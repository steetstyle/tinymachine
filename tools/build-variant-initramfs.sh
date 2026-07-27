#!/bin/bash
# Build variant-specific initramfs with CPython/MicroPython + packages
#
# Usage: ./build-variant-initramfs.sh [--from-source] <variant> [output-dir]
#
# Flags:
#   --from-source  Build MicroPython from git submodule (tools/subprojects/micropython)
#                  instead of downloading release tarball. Requires submodule init:
#                    git submodule update --init tools/subprojects/micropython
#
# Variants:
#   minimal     — MicroPython v1.28.0 (built from source, 2.4MB initrd)
#   numpy       — CPython 3.12.3 (built from source) + numpy (pre-built wheel)
#   tinygrad    — CPython 3.12.3 + tinygrad (from local repo, no numpy)
#   tinygrad-nv — CPython 3.12.3 + tinygrad (from local repo) + GPU firmware
#   pytorch     — CPython 3.12.3 + torch (CPU via pip)
#
# Creates: $OUTPUT_DIR/<variant>-initrd.zst (zstd-compressed cpio archive)
#
# Source builds (no host Python/pip dependency):
#   - CPython 3.12.3: python.org tarball (git repo too large for submodule, ~1.5GB)
#   - MicroPython: github release tarball (default) OR git submodule (--from-source)
#   - pip packages: pip download --only-binary :all: → pre-built manylinux wheels
#
# Cached at: tools/initramfs/cpython/3.12.3/{install,wheels}/
#            tools/initramfs/bin/micropython
#
# Dependencies: wget, curl, cpio, zstd, gcc, make, libssl-dev, libffi-dev
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Parse flags
FROM_SOURCE=false
POSITIONAL=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --from-source)
            FROM_SOURCE=true
            shift
            ;;
        *)
            POSITIONAL+=("$1")
            shift
            ;;
    esac
done

VARIANT="${POSITIONAL[0]:-minimal}"
OUTPUT_DIR="$(realpath -m "${POSITIONAL[1]:-$(dirname "$0")/../tinymachine-fork/templates}")"
mkdir -p "$OUTPUT_DIR"
TEMP_ROOT=$(mktemp -d)

echo "=== TinyMachine Variant Initramfs Builder ==="
echo "Variant:   $VARIANT"
echo "Output:    $OUTPUT_DIR"
echo "Source:    $([ "$FROM_SOURCE" = true ] && echo 'local git submodule' || echo 'download tarball')"
echo "Temp root: $TEMP_ROOT"
echo ""

# Cleanup on exit
cleanup() {
    rm -rf "$TEMP_ROOT"
}
trap cleanup EXIT

# ── Validate variant ──
case "$VARIANT" in
    minimal|numpy|tinygrad|tinygrad-cpu|tinygrad-nv|pytorch|pytorch-cpu|pytorch-nv)
        ;;
    *)
        echo "ERROR: Unknown variant '$VARIANT'"
        echo "Usage: $0 {minimal|numpy|tinygrad|tinygrad-cpu|tinygrad-nv|pytorch|pytorch-cpu|pytorch-nv} [output-dir]"
        exit 1
        ;;
esac

# ── Step 1: Create directory structure ──
mkdir -p "$TEMP_ROOT/bin"
mkdir -p "$TEMP_ROOT/dev"
mkdir -p "$TEMP_ROOT/proc"
mkdir -p "$TEMP_ROOT/sys"
mkdir -p "$TEMP_ROOT/tmp"
mkdir -p "$TEMP_ROOT/usr/lib"
mkdir -p "$TEMP_ROOT/etc"

# ── Step 2: Add busybox (for shell, dd, etc.) ──
BUSYBOX_BIN="$SCRIPT_DIR/initramfs/bin/busybox"
if [ ! -f "$BUSYBOX_BIN" ] || [ ! -s "$BUSYBOX_BIN" ]; then
    # Try host's busybox first (statically linked, works in any initramfs)
    if [ -x /usr/bin/busybox ]; then
        echo "Using host Busybox: /usr/bin/busybox"
        cp /usr/bin/busybox "$BUSYBOX_BIN"
    else
        echo "Downloading static Busybox..."
        BUSYBOX_URL="https://busybox.net/downloads/binaries/1.36.1-x86_64-linux-musl/busybox"
        wget -q -O "$BUSYBOX_BIN" "$BUSYBOX_URL" || {
            echo "WARNING: Could not download Busybox"
        }
    fi
    chmod +x "$BUSYBOX_BIN" 2>/dev/null || true
fi

if [ -x "$BUSYBOX_BIN" ] && [ -s "$BUSYBOX_BIN" ]; then
    cp "$BUSYBOX_BIN" "$TEMP_ROOT/bin/busybox"
    for applet in sh mount umount cat echo dd printf poweroff tr ifconfig route; do
        ln -sf busybox "$TEMP_ROOT/bin/$applet"
    done
else
    echo "ERROR: Busybox required but not available (empty or missing)"
    exit 1
fi

# Copy shared libc and ld-linux for ALL variants (needed by C init binary)
# Minimal variant needs only: libc.so.6 + libm.so.6 + ld-linux-x86-64.so.2
# Only put in lib/, symlink lib64 -> lib for compatibility
mkdir -p "$TEMP_ROOT/lib" "$TEMP_ROOT/usr/lib"
for lib in /lib/x86_64-linux-gnu/libc.so* /lib/x86_64-linux-gnu/libm.so*; do
    if [ -f "$lib" ]; then
        cp -L "$lib" "$TEMP_ROOT/lib/" 2>/dev/null || true
    fi
done
# ld-linux — copy to /lib/ for ld-linux search path
cp -L /lib64/ld-linux-x86-64.so.2 "$TEMP_ROOT/lib/" 2>/dev/null || true
# NO SYMLINK for /lib64 — kernel ELF loader must find ld-linux without
# symlink traversal. The variant-specific section below creates /lib64
# as a real directory with a copy of ld-linux. If that section isn't
# reached (e.g., minimal MicroPython variant), we still create it here.
rm -f "$TEMP_ROOT/lib64" 2>/dev/null || true
mkdir -p "$TEMP_ROOT/lib64"
cp -L /lib64/ld-linux-x86-64.so.2 "$TEMP_ROOT/lib64/" 2>/dev/null || true

# ── Step 3: Python runtime + packages (all variants) ──
# ALL variants now build from source. No host Python is copied.

CPYTHON_VER="3.12.3"
CPYTHON_TARBALL_URL="https://www.python.org/ftp/python/${CPYTHON_VER}/Python-${CPYTHON_VER}.tar.xz"
CPYTHON_CACHE="$SCRIPT_DIR/initramfs/cpython/${CPYTHON_VER}"
PY_VER="${CPYTHON_VER%.*}"

if [ "$VARIANT" = "minimal" ]; then
    # ── Minimal variant: MicroPython (tiny, no stdlib baggage) ──
    MICROPYTHON_BIN="$SCRIPT_DIR/initramfs/bin/micropython"
    MICROPYTHON_SRC_DIR="$SCRIPT_DIR/subprojects/micropython"
    
    if [ -f "$MICROPYTHON_BIN" ]; then
        echo "Using cached MicroPython binary: $MICROPYTHON_BIN"
    else
        mkdir -p "$SCRIPT_DIR/initramfs/bin"
        echo "MicroPython not cached. Building from source..."
        
        if [ "$FROM_SOURCE" = true ]; then
            # Build from git submodule
            if [ ! -f "$MICROPYTHON_SRC_DIR/ports/unix/Makefile" ]; then
                echo "  ERROR: --from-source requested but submodule not found at $MICROPYTHON_SRC_DIR"
                echo "  Run: git submodule update --init tools/subprojects/micropython"
                exit 1
            fi
            echo "  Source: submodule $MICROPYTHON_SRC_DIR (v1.28.0)"
            # Initialize only the submodules needed by unix port (30+ board submodules skipped)
            echo "  Initializing submodule submodules (mbedtls, berkeley-db, axtls, lwip, libffi)..."
            for MP_SUBMOD in lib/berkeley-db-1.xx lib/mbedtls lib/axtls lib/lwip lib/micropython-lib lib/libffi; do
                if [ ! -d "$MICROPYTHON_SRC_DIR/$MP_SUBMOD/include" ] && [ ! -f "$MICROPYTHON_SRC_DIR/$MP_SUBMOD/README.md" ]; then
                    git -C "$MICROPYTHON_SRC_DIR" submodule deinit -f "$MP_SUBMOD" 2>/dev/null || true
                    rm -rf "$MICROPYTHON_SRC_DIR/$MP_SUBMOD"
                    git -C "$MICROPYTHON_SRC_DIR" submodule update --init "$MP_SUBMOD" 2>&1
                fi
            done
            echo "  Building mpy-cross..."
            make -C "$MICROPYTHON_SRC_DIR/mpy-cross" -j$(nproc) -s
            echo "  Building unix port..."
            make -C "$MICROPYTHON_SRC_DIR/ports/unix" -j$(nproc) -s
            cp "$MICROPYTHON_SRC_DIR/ports/unix/build-standard/micropython" "$MICROPYTHON_BIN"
        else
            # Default: download release tarball (includes submodules, no git needed)
            echo "  Source: tarball download"
            MICROPYTHON_VER="v1.28.0"
            MICROPYTHON_TARBALL_URL="https://github.com/micropython/micropython/releases/download/${MICROPYTHON_VER}/micropython-${MICROPYTHON_VER#v}.tar.xz"
            BUILD_DIR=$(mktemp -d)
            cd "$BUILD_DIR"
            echo "  Downloading ${MICROPYTHON_TARBALL_URL}..."
            curl -sL "$MICROPYTHON_TARBALL_URL" | tar xJ
            cd "micropython-${MICROPYTHON_VER#v}"
            echo "  Building mpy-cross..."
            make -C mpy-cross -j$(nproc) -s
            echo "  Building unix port..."
            make -C ports/unix -j$(nproc) -s
            cp "ports/unix/build-standard/micropython" "$MICROPYTHON_BIN"
            cd /tmp
            rm -rf "$BUILD_DIR"
        fi
        
        echo "  Stripping..."
        strip "$MICROPYTHON_BIN" 2>/dev/null || true
        ls -lh "$MICROPYTHON_BIN"
        echo "  MicroPython built and cached at $MICROPYTHON_BIN"
    fi
    mkdir -p "$TEMP_ROOT/bin"
    cp "$MICROPYTHON_BIN" "$TEMP_ROOT/bin/python3"
    ln -sf python3 "$TEMP_ROOT/bin/python" 2>/dev/null || true
    chmod +x "$TEMP_ROOT/bin/python3"
    echo "Using MicroPython for minimal variant ($(du -h "$TEMP_ROOT/bin/python3" | cut -f1))"

else
    # ── Non-minimal variants: CPython from source + pip packages ──
    echo "Building CPython ${CPYTHON_VER} from source for variant '$VARIANT'..."

    # ── Step 3a: Build CPython from source ──
    # Cached at $CPYTHON_CACHE/install/ to avoid rebuilds across variants
    if [ -f "$CPYTHON_CACHE/install/usr/bin/python3" ]; then
        echo "  Using cached CPython build: $CPYTHON_CACHE/install (already built)"
        PYTHON_BIN="$CPYTHON_CACHE/install/usr/bin/python3"
    else
        # Check build dependencies
        MISSING_DEPS=""
        for dep in gcc make pkg-config libssl-dev libffi-dev zlib1g-dev; do
            if ! dpkg -s "$dep" &>/dev/null 2>/dev/null && ! which "$dep" &>/dev/null 2>/dev/null; then
                MISSING_DEPS="$MISSING_DEPS $dep"
            fi
        done
        if [ -n "$MISSING_DEPS" ]; then
            echo "  WARNING: missing build deps:$MISSING_DEPS"
            echo "  Attempting build anyway — some modules may be missing"
        fi

        if [ "$FROM_SOURCE" = true ]; then
            echo "  NOTE: CPython has no submodule (repo too large). Using tarball download."
        fi
        
        # Always download CPython tarball (git repo is 1.5GB+, impractical as submodule)
        BUILD_DIR=$(mktemp -d)
        cd "$BUILD_DIR"
        echo "  Downloading ${CPYTHON_TARBALL_URL}..."
        curl -sL "$CPYTHON_TARBALL_URL" | tar xJ
        cd "Python-${CPYTHON_VER}"
        echo "  Configuring..."
        ./configure --prefix=/usr --with-ensurepip=install --disable-test-modules 2>&1 | tail -3
        echo "  Building (make -j$(nproc))..."
        make -j$(nproc) 2>&1 | tail -3
        echo "  Installing to cache..."
        mkdir -p "$CPYTHON_CACHE/install"
        make install DESTDIR="$CPYTHON_CACHE/install" 2>&1 | tail -3
        PYTHON_BIN="$CPYTHON_CACHE/install/usr/bin/python3"
        cd /tmp
        rm -rf "$BUILD_DIR"
        echo "  CPython ${CPYTHON_VER} built and cached at $CPYTHON_CACHE/install"
    fi
    echo "  CPython version: $($PYTHON_BIN --version 2>&1)"

    # ── Step 3b: Copy CPython to initramfs ──
    cp -a "$CPYTHON_CACHE/install/"* "$TEMP_ROOT/"
    echo "  CPython installed: $(du -sh "$CPYTHON_CACHE/install/usr" | cut -f1)"

    # Fix /usr/bin/python3 symlink (ensure it points to the binary in /usr/bin)
    if [ -f "$TEMP_ROOT/usr/bin/python3" ]; then
        ln -sf /usr/bin/python3 "$TEMP_ROOT/bin/python3" 2>/dev/null || true
    fi
    chmod +x "$TEMP_ROOT/usr/bin/python3" 2>/dev/null || true
    # Ensure bin/python3 exists
    if [ ! -f "$TEMP_ROOT/bin/python3" ]; then
        ln -sf /usr/bin/python3 "$TEMP_ROOT/bin/python3" 2>/dev/null || true
    fi
    # Also provide /usr/bin/python
    ln -sf python3 "$TEMP_ROOT/usr/bin/python" 2>/dev/null || true

    # Copy ld-linux (kernel ELF loader needs it at /lib64/)
    rm -rf "$TEMP_ROOT/lib64" 2>/dev/null || true
    mkdir -p "$TEMP_ROOT/lib64" "$TEMP_ROOT/lib"
    cp -L /lib64/ld-linux-x86-64.so.2 "$TEMP_ROOT/lib64/" 2>/dev/null || true
    cp -L /lib64/ld-linux-x86-64.so.2 "$TEMP_ROOT/lib/" 2>/dev/null || true

    # Copy shared library dependencies for python3 (from the built CPython)
    echo "  Resolving CPython shared library dependencies..."
    for lib in $(ldd "$TEMP_ROOT/usr/bin/python3" 2>/dev/null | grep "=> /" | awk '{print $3}'); do
        libdir=$(dirname "$lib")
        mkdir -p "$TEMP_ROOT/$libdir"
        cp -L "$lib" "$TEMP_ROOT/$libdir/" 2>/dev/null || true
    done
    # Also copy libpython3.12.so (if built as shared)
    find "$CPYTHON_CACHE/install" -name "libpython*.so*" 2>/dev/null | while read lib; do
        libname=$(basename "$lib")
        target="$TEMP_ROOT/usr/lib/$libname"
        if [ ! -f "$target" ]; then
            cp -L "$lib" "$target" 2>/dev/null || true
        fi
    done

    # ── Step 3c: Download + install pip packages ──
    mkdir -p "$TEMP_ROOT/usr/lib/python$PY_VER/dist-packages"
    
    PIP_PACKAGES=""
    PIP_EXTRA=""
    case "$VARIANT" in
        numpy|numpy-cpu)
            PIP_PACKAGES="numpy"
            ;;
        tinygrad|tinygrad-cpu)
            # tinygrad-cpu: tinygrad from local repo, NO numpy, NO GPU deps
            PIP_PACKAGES=""
            TINYGRAD_SRC="$SCRIPT_DIR/../tinygrad"
            ;;
        tinygrad-nv)
            # tinygrad from local repo — NV backend variant
            PIP_PACKAGES=""
            TINYGRAD_SRC="$SCRIPT_DIR/../tinygrad"
            ;;
        pytorch|pytorch-cpu)
            PIP_PACKAGES="torch"
            PIP_EXTRA="--extra-index-url https://download.pytorch.org/whl/cpu"
            ;;
        pytorch-nv)
            PIP_PACKAGES="torch"
            PIP_EXTRA="--extra-index-url https://download.pytorch.org/whl/cu126"
            ;;
    esac
    
    if [ -n "$PIP_PACKAGES" ]; then
        echo "  Downloading pip packages: $PIP_PACKAGES"
        
        # Use the newly built CPython's pip to download wheels
        # --only-binary :all: ensures we don't compile C extensions (use pre-built manylinux wheels)
        # --dest: download to wheel cache, don't install yet
        WHEEL_DIR="$CPYTHON_CACHE/wheels"
        mkdir -p "$WHEEL_DIR"
        
        $PYTHON_BIN -m pip download \
            --only-binary :all: \
            --platform manylinux_2_27_x86_64 \
            --platform manylinux_2_28_x86_64 \
            --platform linux_x86_64 \
            --dest "$WHEEL_DIR" \
            ${PIP_EXTRA:-} \
            $PIP_PACKAGES 2>&1 || {
            echo "  WARNING: pip download failed — will try without platform constraints"
            # Fallback: download without platform constraint (may download source tarballs)
            $PYTHON_BIN -m pip download \
                --dest "$WHEEL_DIR" \
                ${PIP_EXTRA:-} \
                $PIP_PACKAGES 2>&1 || echo "  WARNING: pip download (fallback) also failed"
        }
        
        # Extract wheels to dist-packages
        echo "  Extracting wheels to dist-packages..."
        for wheel in "$WHEEL_DIR"/*.whl; do
            [ -f "$wheel" ] || continue
            echo "    $(basename "$wheel")"
            unzip -qo "$wheel" -d "$TEMP_ROOT/usr/lib/python$PY_VER/dist-packages/" 2>/dev/null || {
                # Fallback: use Python's zipfile module
                $PYTHON_BIN -c "import zipfile, sys; zipfile.ZipFile(sys.argv[1]).extractall('$TEMP_ROOT/usr/lib/python$PY_VER/dist-packages/')" "$wheel"
            }
        done
        
        # Handle torch CPU-specific index (for pytorch variant)
        if [ "$VARIANT" = "pytorch" ] || [ "$VARIANT" = "pytorch-cpu" ]; then
            # If torch wasn't found in standard index, try CPU-only index
            if [ ! -d "$TEMP_ROOT/usr/lib/python$PY_VER/dist-packages/torch" ]; then
                echo "  torch not in standard index, trying CPU-only index..."
                $PYTHON_BIN -m pip download \
                    --only-binary :all: \
                    --platform manylinux_2_27_x86_64 \
                    --platform manylinux_2_28_x86_64 \
                    --platform linux_x86_64 \
                    --extra-index-url https://download.pytorch.org/whl/cpu \
                    --dest "$WHEEL_DIR" \
                    torch 2>&1 || echo "  WARNING: CPU torch download failed"
                for wheel in "$WHEEL_DIR"/torch*.whl; do
                    [ -f "$wheel" ] || continue
                    echo "    $(basename "$wheel") (CPU)"
                    unzip -qo "$wheel" -d "$TEMP_ROOT/usr/lib/python$PY_VER/dist-packages/" 2>/dev/null || true
                done
            fi
        fi
    fi

    # ── Copy tinygrad from local repo ──
    if [ -n "${TINYGRAD_SRC:-}" ]; then
        if [ -d "$TINYGRAD_SRC/tinygrad" ]; then
            echo "  Copying tinygrad from local repo: $TINYGRAD_SRC ($(git -C "$TINYGRAD_SRC" describe --always 2>/dev/null || echo "unknown"))"
            cp -a "$TINYGRAD_SRC/tinygrad" "$TEMP_ROOT/usr/lib/python$PY_VER/dist-packages/tinygrad"
            echo "  tinygrad copied ($(du -sh "$TINYGRAD_SRC/tinygrad" | cut -f1))"
        else
            echo "  WARNING: tinygrad source not found at $TINYGRAD_SRC/tinygrad — installing from pip"
            $PYTHON_BIN -m pip download --only-binary :all: --dest "$WHEEL_DIR" tinygrad 2>&1 || true
            for wheel in "$WHEEL_DIR"/tinygrad*.whl; do
                [ -f "$wheel" ] || continue
                unzip -qo "$wheel" -d "$TEMP_ROOT/usr/lib/python$PY_VER/dist-packages/" 2>/dev/null || true
            done
        fi
    fi

    # ── Step 3d: Copy shared library deps for all .so files ──
    echo "  Resolving shared library dependencies for .so files..."
    find "$TEMP_ROOT" -name "*.so*" -type f 2>/dev/null | while read sofile; do
        for lib in $(ldd "$sofile" 2>/dev/null | grep "=> /" | awk '{print $3}'); do
            libdir=$(dirname "$lib")
            libname=$(basename "$lib")
            target="$TEMP_ROOT/$libdir/$libname"
            if [ ! -f "$target" ]; then
                mkdir -p "$(dirname "$target")"
                cp -L "$lib" "$target" 2>/dev/null || true
            fi
        done
    done

    # ── CUDA support for pytorch variant (CPU-only for now) ──
    if [ "$VARIANT" = "pytorch" ] || [ "$VARIANT" = "pytorch-cpu" ]; then
        echo ""
        echo "=== Pytorch variant: CPU-only torch (CUDA passthrough needs nvidia.ko) ==="
        echo ""
    fi

    # ── Verify installed packages ──
    echo "  Installed packages:"
    if [ -d "$TEMP_ROOT/usr/lib/python$PY_VER/dist-packages" ]; then
        ls -d "$TEMP_ROOT/usr/lib/python$PY_VER/dist-packages/"* 2>/dev/null | head -20
    fi
fi  # end if [ "$VARIANT" = "minimal" ]

# ── Step 3.5: Precompile Python bytecode (optional, skips on error) ──
# Compiles all .py files to .pyc at build time, so Python doesn't need
# to compile at first import in the guest. Saves ~200-500ms on startup.
# If compileall fails (e.g. host Python version mismatch), it's non-fatal:
# the guest will compile at first use as before (just slower).
# PY_VER is set from CPYTHON_VER above for non-minimal variants; for
# minimal (MicroPython), this is empty and the block is skipped.
if [ -d "$TEMP_ROOT/usr/lib/python$PY_VER" ] && [ -n "$PY_VER" ]; then
    echo "Precompiling Python bytecode (compileall)..."
    # Use --invalidation-mode=unchecked-hash so Python always loads .pyc
    # regardless of source mtime (which may differ after rsync/file operations
    # in the build pipeline). Without this, Python rejects .pyc as "stale"
    # when timestamps don't match, falling back to .py compilation (179-599s).
    if "$TEMP_ROOT/bin/python3" -m compileall -f --invalidation-mode=unchecked-hash -q "$TEMP_ROOT/usr/lib/python$PY_VER" 2>/dev/null; then
        # Keep ALL .py files — removing them breaks Python 3.12 early startup
        # (encodings package must be importable during init_fs_encoding before
        # __pycache__ lookup works reliably). Keeping .py alongside .pyc is safe:
        # Python prefers .pyc when available, falling back to .py if .pyc is
        # stale or invalid. This gives us fast imports (from .pyc) with zero
        # risk of breaking Python's own bootstrap.
        #
        # tinygrad's autogen also needs .py to verify sources exist; without
        # them it tries to regenerate from scratch using dpkg/llvm-config.
        echo "  ✅ stdlib .pyc precompiled (__pycache__ format), .py sources KEPT for safety"
    else
        echo "  ⚠️  compileall for stdlib failed — Python will compile at first use (slower)"
    fi
fi

# DO NOT delete __pycache__ directories — they contain the .pyc files we just created!
# (The deletion at line 639/642 was previously removing ALL __pycache__, which
# wiped the precompiled bytecode and caused 179-599s import times.)

# Also precompile tinygrad + dist-packages .py → .pyc so they load faster.
# Without this, importing tinygrad takes 180-600s on a single-core KVM VCPU
# because Python re-parses every .py file from scratch on each import
# (PYTHONDONTWRITEBYTECODE=1 prevents runtime .pyc creation).
PY_DIST="$TEMP_ROOT/usr/lib/python$PY_VER/dist-packages"
if [ -d "$PY_DIST" ]; then
    echo "Precompiling dist-packages bytecode (compileall)..."
    if "$TEMP_ROOT/bin/python3" -m compileall -f --invalidation-mode=unchecked-hash -q "$PY_DIST" 2>/dev/null; then
        echo "  ✅ dist-packages .pyc precompiled (__pycache__ format, tinygrad included)"
    else
        echo "  ⚠️  compileall for dist-packages failed — will use .py at runtime"
    fi
fi

# ── Step 4: Compile C init binary ──
# The C init replaces the old shell init (tools/initramfs/init) with:
#   1. mmap /dev/mem → zero-copy pointer access (was: dd bs=1 = 4080 syscalls)
#   2. Tight compile-time spin loop (was: ash while loop = 80ms/100K iters)
#   3. Direct fork+exec python -c (was: shell pipe overhead)
INIT_C_SRC="$SCRIPT_DIR/initramfs/init.c"
if [ -f "$INIT_C_SRC" ]; then
    echo "Compiling C init (statically linked)..."
    gcc -static -O2 -s -o "$TEMP_ROOT/init" "$INIT_C_SRC" 2>&1 || {
        echo "WARNING: C init compilation failed, falling back to shell init"
        # Fallback to minimal shell init
        cat > "$TEMP_ROOT/init" << 'SHELLINIT'
#!/bin/sh
mount -t devtmpfs none /dev 2>/dev/null || true
mount -t proc none /proc 2>/dev/null || true
while true; do
    CMD=$(dd if=/dev/mem bs=1 skip=516096 count=4080 2>/dev/null | tr -d '\0' || true)
    if [ -n "$CMD" ]; then
        dd if=/dev/zero bs=1 count=4080 2>/dev/null | dd of=/dev/mem bs=1 seek=516096 2>/dev/null || true
        printf '%s\n' "$CMD" | /bin/micropython 2>&1 | dd of=/dev/mem bs=1 seek=520192 count=4080 2>/dev/null || true
    fi
    printf 'READY' | dd of=/dev/mem bs=1 seek=524282 count=5 2>/dev/null || true
    i=0; while [ $i -lt 10000 ]; do : $((i = i + 1)); done
done
SHELLINIT
        chmod +x "$TEMP_ROOT/init"
    }
else
    echo "ERROR: init.c not found at $INIT_C_SRC"
    exit 1
fi

# ── Step 5: Strip debug symbols ──
# Strips .debug_* sections from .so files, ELF binaries, and kernel modules.
# Reduces initramfs size by ~3-5MB (compressed).
# SAFETY: --strip-debug only removes debug info, does not affect code/data.
#          .ko files are relocatable ELF — strip --strip-debug is safe.
echo "Stripping debug symbols..."
STRIP_BEFORE=$(du -sh "$TEMP_ROOT" | cut -f1)
find "$TEMP_ROOT" -type f \( -name "*.so*" -o -name "*.ko" -o -executable \) 2>/dev/null | while read -r f; do
    strip --strip-debug "$f" 2>/dev/null || true
done
STRIP_AFTER=$(du -sh "$TEMP_ROOT" | cut -f1)
echo "Strip: $STRIP_BEFORE → $STRIP_AFTER"

# ── Step 5.5a: Add ldconfig for Python ctypes library discovery ──
# Python's ctypes.util.find_library() runs /sbin/ldconfig -p to locate
# shared libraries by SONAME. Without it, find_library returns None,
# and CDLL(None) loads the python3 binary by mistake, causing
# misleading "undefined symbol" errors.
# ldconfig.real is statically linked (1.1MB, ~466KB compressed).
LDCONFIG_SRC="/sbin/ldconfig.real"
if [ -f "$LDCONFIG_SRC" ]; then
    mkdir -p "$TEMP_ROOT/sbin"
    cp "$LDCONFIG_SRC" "$TEMP_ROOT/sbin/ldconfig" 2>/dev/null && echo "Added ldconfig ($(du -sh "$TEMP_ROOT/sbin/ldconfig" | cut -f1))"
    # Create /etc/ld.so.conf with default library paths
    mkdir -p "$TEMP_ROOT/etc"
    echo "/lib" > "$TEMP_ROOT/etc/ld.so.conf"
    echo "/usr/lib" >> "$TEMP_ROOT/etc/ld.so.conf"
    echo "/usr/local/lib" >> "$TEMP_ROOT/etc/ld.so.conf"

    # Create /etc/profile to set LD_LIBRARY_PATH for login shells.
    # Busybox sh reads this when invoked as a login shell (argv[0][0] == '-').
    # This is a belt-and-suspenders backup to init.c's setenv().
    mkdir -p "$TEMP_ROOT/etc"
    cat > "$TEMP_ROOT/etc/profile" << 'PROFILE'
# TinyOS initramfs profile — set library path for ctypes discovery
export LD_LIBRARY_PATH=/lib:/usr/lib
export PATH=/usr/bin:/bin:/sbin
PROFILE
fi

# ── Step 5.5b: Add libatomic + libgcc_s for tinygrad NV backend ──
# tinygrad's System.atomic_lib does ctypes.CDLL("libatomic.so.1") for
# atomic_thread_fence(). In our minimal initramfs, this library is not
# included by Python pip packages. Add it from the host (~35KB).
ATOMIC_LIB="/lib/x86_64-linux-gnu/libatomic.so.1"
if [ -f "$ATOMIC_LIB" ]; then
    mkdir -p "$TEMP_ROOT/lib"
    cp -L "$ATOMIC_LIB" "$TEMP_ROOT/lib/libatomic.so.1" 2>/dev/null && echo "Added libatomic.so.1 ($(du -sh "$TEMP_ROOT/lib/libatomic.so.1" | cut -f1))"
fi

# libgcc_s.so.1 needed by libtinymesa.so (NAK compiler) → NV backend
GCC_LIB="/lib/x86_64-linux-gnu/libgcc_s.so.1"
if [ -f "$GCC_LIB" ]; then
    mkdir -p "$TEMP_ROOT/lib"
    cp -L "$GCC_LIB" "$TEMP_ROOT/lib/libgcc_s.so.1" 2>/dev/null && echo "Added libgcc_s.so.1 ($(du -sh "$TEMP_ROOT/lib/libgcc_s.so.1" | cut -f1))"
fi

# libffi.so.8 needed by MicroPython (dynamically linked for ctypes module)
FFI_LIB="/lib/x86_64-linux-gnu/libffi.so.8"
if [ -f "$FFI_LIB" ]; then
    cp -L "$FFI_LIB" "$TEMP_ROOT/lib/libffi.so.8" 2>/dev/null && echo "Added libffi.so.8 ($(du -sh "$TEMP_ROOT/lib/libffi.so.8" | cut -f1))"
fi

# ── Step 6: NVIDIA kernel modules + firmware (GPU variants) ──
# For GPU passthrough, the guest needs kernel modules + GSP firmware blobs.
NVIDIA_MODULES_SRC="$SCRIPT_DIR/initramfs/lib/modules"
NVIDIA_FIRMWARE_SRC="$SCRIPT_DIR/initramfs/lib/firmware"
FIRMWARE_DIR="${FIRMWARE_DIR:-/tmp/tinymachine-firmware}"

# GPU variants only: pytorch-nv and tinygrad-nv need NVIDIA firmware + modules.
# CPU variants (numpy, tinygrad, tinygrad-cpu, pytorch, pytorch-cpu, minimal)
# get NO GPU firmware, NO nvidia.ko modules, NO CUDA libs.
if [ "$VARIANT" = "pytorch-nv" ] || [ "$VARIANT" = "tinygrad-nv" ]; then
    if [ -d "$NVIDIA_MODULES_SRC" ]; then
        echo "Copying NVIDIA kernel modules ($(du -sh "$NVIDIA_MODULES_SRC" | cut -f1))..."
        mkdir -p "$TEMP_ROOT/lib/modules"
        cp -r "$NVIDIA_MODULES_SRC/"* "$TEMP_ROOT/lib/modules/"
        echo "  Modules: $(find "$TEMP_ROOT/lib/modules" -name '*.ko' | wc -l) .ko files"
    else
        echo "  (no NVIDIA kernel modules directory — OK for tinygrad NV backend)"
    fi

    # Include GSP firmware blobs for the NV backend.
    #
    # NVIDIA GPU firmware strategy:
    #   For tinygrad-nv (direct ring buffer, no nvidia.ko):
    #     Only AD104 booter_load + bootloader (~93KB) needed for SEC2 GSP boot.
    #     nvidia.ko is NOT loaded; tinygrad accesses GPU via direct BAR MMIO.
    #
    #   For pytorch (RMAPI through nvidia.ko):
    #     Needs full GSP firmware (ga102/gsp-570.144.bin.zst, ~51MB compressed)
    #     AND nvidia.ko kernel module loaded in guest.
    #
    #   We copy from host firmware (/lib/firmware/nvidia/) when available,
    #   or from tools/initramfs/lib/firmware/ as fallback.
    mkdir -p "$TEMP_ROOT/lib/firmware/nvidia"

    # ── GSP firmware (full RMAPI firmware) ──
    # Needed by nvidia.ko RMAPI path (pytorch variant). For tinygrad-nv, the
    # nvidia.ko is NOT loaded, but we still include it as fallback.
    #
    # The actual GSP firmware is shared across GPU families:
    #   ad102/gsp/gsp-570.144.bin.zst → ../../ga102/gsp/gsp-570.144.bin.zst
    #   ga102/gsp/gsp-570.144.bin.zst = ~51MB zstd-compressed
    if [ -f /lib/firmware/nvidia/ga102/gsp/gsp-570.144.bin.zst ]; then
        echo "  Copying GSP firmware from host (ga102/gsp-570.144.bin.zst)..."
        mkdir -p "$TEMP_ROOT/lib/firmware/nvidia/ga102/gsp"
        # Decompress and copy — kernel expects raw .bin, not .zst
        zstd -dc /lib/firmware/nvidia/ga102/gsp/gsp-570.144.bin.zst \
            > "$TEMP_ROOT/lib/firmware/nvidia/ga102/gsp/gsp-570.144.bin" 2>/dev/null
        echo "    -> $(du -h "$TEMP_ROOT/lib/firmware/nvidia/ga102/gsp/gsp-570.144.bin" | cut -f1) (570.144)"
    elif [ -f "$NVIDIA_FIRMWARE_SRC/nvidia/ga102/gsp/gsp-570.144.bin" ]; then
        # Fallback to tools/initramfs/lib/firmware/ (pre-downloaded by download-nv-firmware.sh)
        echo "  Copying GSP firmware from fallback source (tools/initramfs)..."
        mkdir -p "$TEMP_ROOT/lib/firmware/nvidia/ga102/gsp"
        cp "$NVIDIA_FIRMWARE_SRC/nvidia/ga102/gsp/gsp-570.144.bin" \
            "$TEMP_ROOT/lib/firmware/nvidia/ga102/gsp/gsp-570.144.bin"
        echo "    -> $(du -h "$TEMP_ROOT/lib/firmware/nvidia/ga102/gsp/gsp-570.144.bin" | cut -f1)"
    else
        echo "  WARNING: No GSP firmware found on host or tools/initramfs. nvidia.ko RMAPI will fail."
        echo "    Run: tools/download-nv-firmware.sh"
    fi

    # ── AD104 booter/bootloader firmware (tinygrad direct GSP) ──
    # These are small firmware files (~93KB total) that tinygrad's NV backend
    # loads directly into SEC2 Falcon via MMIO to boot the GSP.
    BOOTER_SRC="/lib/firmware/nvidia/ad102/gsp"
    if [ -d "$BOOTER_SRC" ]; then
        echo "  Copying AD104 booter/bootloader firmware from host..."
        mkdir -p "$TEMP_ROOT/lib/firmware/nvidia/ad102/gsp"
        for f in booter_load-570.144.bin.zst bootloader-570.144.bin.zst scrubber-570.144.bin.zst; do
            if [ -f "$BOOTER_SRC/$f" ]; then
                zstd -dc "$BOOTER_SRC/$f" > "$TEMP_ROOT/lib/firmware/nvidia/ad102/gsp/${f%.zst}" 2>/dev/null
            fi
        done
        echo "    -> $(du -sh "$TEMP_ROOT/lib/firmware/nvidia/ad102" | cut -f1)"
    elif [ -d "$NVIDIA_FIRMWARE_SRC/nvidia/ad102" ]; then
        # Fallback to tools/initramfs firmware
        cp -r "$NVIDIA_FIRMWARE_SRC/nvidia/ad102/"* "$TEMP_ROOT/lib/firmware/nvidia/ad102/" 2>/dev/null || true
        echo "  Copying AD104 booter from fallback source"
    fi

    echo "  Firmware: $(find "$TEMP_ROOT/lib/firmware/nvidia" -type f | wc -l) files"
    echo "  Size: $(du -sh "$TEMP_ROOT/lib/firmware" | cut -f1)"

    # ── Step 6.3: CUDA userspace driver libraries (pytorch-nv variant) ──
    # For the pytorch-nv variant with nvidia.ko loaded in guest, we include
    # the host's CUDA driver libraries so that libcuda.so is available.
    # Note: CUDA Toolkit (libcudart, libcublas, libnvrtc) is NOT on the host,
    # so pytorch GPU compute remains CPU-only for now. The driver libraries
    # enable nvidia-smi and basic CUDA driver API calls in the guest.
    if [ "$VARIANT" = "pytorch-nv" ]; then
        CUDA_LIBS_SRC="/usr/lib/x86_64-linux-gnu"
        echo "Adding CUDA driver libraries for pytorch variant..."
        mkdir -p "$TEMP_ROOT/usr/lib/x86_64-linux-gnu"
        for lib_pattern in "libcuda.so*" "libnvidia-ml.so*" "libnvidia-ptxjitcompiler.so*"; do
            for f in $CUDA_LIBS_SRC/$lib_pattern; do
                if [ -f "$f" ] && [ ! -L "$f" ]; then
                    target="$TEMP_ROOT/usr/lib/x86_64-linux-gnu/$(basename "$f")"
                    if [ ! -f "$target" ]; then
                        cp -L "$f" "$target" 2>/dev/null || true
                    fi
                fi
            done
        done
        # Create symlinks (libcuda.so → libcuda.so.1 → libcuda.so.595.84)
        if [ -f "$TEMP_ROOT/usr/lib/x86_64-linux-gnu/libcuda.so.595.84" ]; then
            ln -sf libcuda.so.595.84 "$TEMP_ROOT/usr/lib/x86_64-linux-gnu/libcuda.so.1"
            ln -sf libcuda.so.1 "$TEMP_ROOT/usr/lib/x86_64-linux-gnu/libcuda.so"
        fi
        if [ -f "$TEMP_ROOT/usr/lib/x86_64-linux-gnu/libnvidia-ml.so.595.84" ]; then
            ln -sf libnvidia-ml.so.595.84 "$TEMP_ROOT/usr/lib/x86_64-linux-gnu/libnvidia-ml.so.1"
            ln -sf libnvidia-ml.so.1 "$TEMP_ROOT/usr/lib/x86_64-linux-gnu/libnvidia-ml.so"
        fi
        echo "  CUDA libs: $(du -sh "$TEMP_ROOT/usr/lib/x86_64-linux-gnu" | cut -f1)"
        echo "  $(find "$TEMP_ROOT/usr/lib/x86_64-linux-gnu" -name 'libcuda*' -o -name 'libnvidia*' | wc -l) files"
    fi

    # ── NAK GPU kernel compiler (tinymesa) ──
    # tinygrad's NAKRenderer compiles GPU kernels via the open-source mesa library
    # instead of requiring the proprietary CUDA toolkit (nvcc/nvrtc/nvjitlink).
    # tinyos_nv_patch.py REMOVED — GPU variants use upstream tinygrad code directly,
    # no runtime monkey-patching. The PCIIface/GSP-RM path works from source builds.
    echo "Downloading libtinymesa.so for NAK GPU kernel compilation..."
    TINYMESA_URL="https://github.com/sirhcm/tinymesa/releases/download/v1/libtinymesa-mesa-25.2.7-linux-amd64.so"
    if [ ! -f "$TEMP_ROOT/usr/local/lib/libtinymesa.so" ]; then
        mkdir -p "$TEMP_ROOT/usr/local/lib"
        if wget -q --timeout=30 -O "$TEMP_ROOT/usr/local/lib/libtinymesa.so" "$TINYMESA_URL" 2>/dev/null; then
            echo "  libtinymesa.so: $(du -sh "$TEMP_ROOT/usr/local/lib/libtinymesa.so" | cut -f1)"
        else
            echo "WARNING: libtinymesa download failed — GPU kernel compilation will need CUDA"
        fi
    fi

    # Add libzstd.so.1 needed by libtinymesa.so (for NAK decompression in compilation)
    echo "Adding libzstd.so.1 for libtinymesa..."
    mkdir -p "$TEMP_ROOT/lib/x86_64-linux-gnu"
    if [ -f "$TEMP_ROOT/lib/x86_64-linux-gnu/libzstd.so.1" ]; then
        echo "  libzstd.so.1 already present"
    elif [ -f "/lib/x86_64-linux-gnu/libzstd.so.1" ]; then
        cp /lib/x86_64-linux-gnu/libzstd.so.1 "$TEMP_ROOT/lib/x86_64-linux-gnu/"
        echo "  libzstd.so.1: $(du -sh "$TEMP_ROOT/lib/x86_64-linux-gnu/libzstd.so.1" | cut -f1)"
    else
        echo "WARNING: libzstd.so.1 not found on host — NAK may fail"
    fi
fi

# ── Step 6.5: Add tinygrad PCIIface firmware files (GPU variants only) ──
# These are loaded by tinygrad's NV backend (ops_nv.py → NV_FLCN/NV_GSP)
# for GSP firmware initialization via PCIIface (direct BAR MMIO, no kernel
# module needed). The files are pre-decompressed from .zst to .bin.
#
# CPU variants (minimal, numpy, tinygrad, tinygrad-cpu, pytorch, pytorch-cpu)
# do NOT get GPU firmware — zero GPU-related files.
# GPU variants (tinygrad-nv, pytorch-nv) get GSP firmware for NV backend.

# Helper function (defined OUTSIDE the if block for shell parser correctness)
# Tries source paths in order:
#   1. $1 (host /lib/firmware/nvidia/... as .zst)
#   2. $1 with .zst → .bin (host decompressed)
#   3. $NVIDIA_FIRMWARE_SRC/ equivalent (tools/initramfs fallback)
decompress_fw() {
    local src="$1" dst="$2"
    local fw_src="${NVIDIA_FIRMWARE_SRC:-tools/initramfs/lib/firmware}"
    
    # Try primary source (.zst on host)
    if [ -f "$src" ]; then
        mkdir -p "$(dirname "$dst")"
        if [ -f "$dst" ]; then
            local size=$(stat -c%s "$dst" 2>/dev/null || echo 0)
            echo "  SKIP $(basename "$dst") (already exists, $(numfmt --to=iec $size))"
            return 0
        fi
        zstd -d "$src" -o "$dst" -f -q 2>/dev/null
        if [ -f "$dst" ]; then
            local size=$(stat -c%s "$dst" 2>/dev/null || echo 0)
            echo "  $(basename "$dst"): $(numfmt --to=iec $size) (from host)"
            return 0
        fi
    fi
    
    # Try decompressed path on host (replace .zst with .bin)
    local src_bin="${src%.zst}.bin"
    if [ -f "$src_bin" ] && [ "$src_bin" != "$src" ]; then
        mkdir -p "$(dirname "$dst")"
        cp "$src_bin" "$dst" 2>/dev/null
        if [ -f "$dst" ]; then
            local size=$(stat -c%s "$dst" 2>/dev/null || echo 0)
            echo "  $(basename "$dst"): $(numfmt --to=iec $size) (from host .bin)"
            return 0
        fi
    fi
    
    # Try tools/initramfs fallback (download-nv-firmware.sh output)
    # Derive relative path: strip /lib/firmware/ prefix, prepend fw_src
    local rel="${src#/lib/firmware/}"
    rel="${rel%.zst}.bin"
    local fallback="$fw_src/$rel"
    if [ -f "$fallback" ]; then
        mkdir -p "$(dirname "$dst")"
        cp "$fallback" "$dst" 2>/dev/null
        if [ -f "$dst" ]; then
            local size=$(stat -c%s "$dst" 2>/dev/null || echo 0)
            echo "  $(basename "$dst"): $(numfmt --to=iec $size) (from tools/initramfs fallback)"
            return 0
        fi
    fi
    
    echo "  WARNING: $(basename "$dst") not found (checked host + tools/initramfs)"
    echo "    Run: tools/download-nv-firmware.sh"
    return 1
}

if [ "$VARIANT" = "tinygrad-nv" ] || [ "$VARIANT" = "pytorch-nv" ]; then
    FIRMWARE_BASE="$TEMP_ROOT/lib/firmware/nvidia"
    mkdir -p "$FIRMWARE_BASE/ad102/gsp" "$FIRMWARE_BASE/ga102/gsp"
    decompress_fw "/lib/firmware/nvidia/ad102/gsp/booter_load-570.144.bin.zst" \
        "$FIRMWARE_BASE/ad102/gsp/booter_load-570.144.bin"
    decompress_fw "/lib/firmware/nvidia/ad102/gsp/bootloader-570.144.bin.zst" \
        "$FIRMWARE_BASE/ad102/gsp/bootloader-570.144.bin"
    decompress_fw "/lib/firmware/nvidia/ga102/gsp/gsp-570.144.bin.zst" \
        "$FIRMWARE_BASE/ga102/gsp/gsp-570.144.bin"
fi  # end GPU-only firmware block

# ── Step 6.6: Add /usr/bin/clang stub (GPU variants only) ──
# tinygrad's CStyleLanguage.__init__ creates ClangCompiler (stores arch, no subprocess).
# But some code paths may try `clang` as a subprocess. Without this stub,
# FileNotFoundError propagates. The stub returns exit code 1, which allows
# tinygrad's select_first_inited to catch CalledProcessError and try the next renderer.
# Real clang is not needed: NV GPU compute uses NAKRenderer (libtinymesa.so).
# CPU variants do NOT get this stub — they don't have NAK renderer.
if [ "$VARIANT" = "tinygrad-nv" ] || [ "$VARIANT" = "pytorch-nv" ]; then
mkdir -p "$TEMP_ROOT/usr/bin"
CLANG_STUB="$TEMP_ROOT/usr/bin/clang"
if [ ! -f "$CLANG_STUB" ]; then
    cat > "$CLANG_STUB" << 'CLANG_EOF'
#!/bin/sh
echo "tinymachine clang stub: clang not available in VFIO guest" >&2
exit 1
CLANG_EOF
    chmod +x "$CLANG_STUB"
    echo "Added /usr/bin/clang stub ($(wc -c < "$CLANG_STUB") bytes)"
fi
fi  # end GPU-only clang stub

# ── Step 7: Create device nodes ──
# We need at least /dev/mem for the init script communication protocol
# (devtmpfs handles this at mount time, but we add a static /dev/mem for safety)
# In Linux, /dev/mem is created by devtmpfs automatically

# ── Step 7.5: Initrd size optimization ──
# Removes unnecessary files to reduce initrd size and boot time.
# Measured impact: 348MB → ~210MB uncompressed, 155MB → ~95MB compressed.
echo ""
echo "=== Initrd size optimization ==="
BEFORE=$(du -sh "$TEMP_ROOT" | cut -f1)

# 7.5a: Remove static Python library archives from config-3.12/
# These are only needed for C extension compilation, not at runtime.
# libpython3.12.a (15MB) + libpython3.12-pic.a (13MB) = 28MB saved
CONFIG_DIR="$TEMP_ROOT/usr/lib/python${PY_VER}/config-${PY_VER}-x86_64-linux-gnu"
if [ -d "$CONFIG_DIR" ]; then
    echo "  Removing static Python .a libs..."
    rm -f "$CONFIG_DIR/libpython${PY_VER}.a"
    rm -f "$CONFIG_DIR/libpython${PY_VER}-pic.a"
fi

# 7.5b: Deduplicate libpython3.12.so
# The config dir may have a symlink and /usr/lib/x86_64-linux-gnu/ has 3 copies
# (libpython3.12.so, libpython3.12.so.1, libpython3.12.so.1.0) all same size.
# Keep one real file at libpython3.12.so.1.0, symlink the others.
LIBMAGIC="$TEMP_ROOT/usr/lib/x86_64-linux-gnu/libpython${PY_VER}.so.1.0"
if [ -f "$LIBMAGIC" ]; then
    echo "  Deduplicating libpython${PY_VER}.so..."
    rm -f "$TEMP_ROOT/usr/lib/x86_64-linux-gnu/libpython${PY_VER}.so"
    rm -f "$TEMP_ROOT/usr/lib/x86_64-linux-gnu/libpython${PY_VER}.so.1"
    ln -sf "libpython${PY_VER}.so.1.0" "$TEMP_ROOT/usr/lib/x86_64-linux-gnu/libpython${PY_VER}.so"
    ln -sf "libpython${PY_VER}.so.1.0" "$TEMP_ROOT/usr/lib/x86_64-linux-gnu/libpython${PY_VER}.so.1"
fi

# 7.5c: Remove gsp_tu10x.bin (Turing firmware, not needed for AD104 Ada GPU)
# Saves ~29MB uncompressed. The ga10x firmware is at nvidia/595.71.05/gsp_ga10x.bin.
if [ -f "$TEMP_ROOT/lib/firmware/nvidia/595.71.05/gsp_tu10x.bin" ]; then
    echo "  Removing gsp_tu10x.bin (Turing firmware, not needed for Ada)..."
    rm -f "$TEMP_ROOT/lib/firmware/nvidia/595.71.05/gsp_tu10x.bin"
fi

# 7.5d: Keep gsp-570.144.bin (tinygrad direct GSP firmware, 61MB)
# When using PCIIface path (no kernel module, VFIO passthrough), tinygrad
# loads gsp-570.144.bin directly via SEC2 booter. This firmware is REQUIRED.
# The RMAPI path (nvidia.ko kernel module) uses firmware at 595.71.05/.
# Since we use PCIIface (no RMAPI), we keep the direct GSP firmware.
if [ -d "$TEMP_ROOT/lib/firmware/nvidia/ga102" ]; then
    echo "  Keeping ga102 direct GSP firmware (61MB — needed for PCIIface NV backend)"
fi

# 7.5e: Remove nouveau and unnecessary kernel modules
# Nouveau (3.1MB) is not needed when using nvidia.ko.
# DRM display helpers, WMI, backlight, thermal are for desktop/laptop not GPU compute.
if [ -d "$TEMP_ROOT/lib/modules/6.8.1/drivers" ]; then
    echo "  Removing unnecessary kernel modules..."
    rm -f "$TEMP_ROOT/lib/modules/6.8.1/drivers/gpu/drm/nouveau/nouveau.ko" 2>/dev/null
    # Remove DRM display/ttm helpers (needed by nouveau, not nvidia.ko)
    rm -rf "$TEMP_ROOT/lib/modules/6.8.1/drivers/gpu/drm/display" 2>/dev/null
    rm -f "$TEMP_ROOT/lib/modules/6.8.1/drivers/gpu/drm/drm_ttm_helper.ko" 2>/dev/null
    rm -f "$TEMP_ROOT/lib/modules/6.8.1/drivers/gpu/drm/drm_gpuvm.ko" 2>/dev/null
    rm -f "$TEMP_ROOT/lib/modules/6.8.1/drivers/gpu/drm/drm_exec.ko" 2>/dev/null
    rm -f "$TEMP_ROOT/lib/modules/6.8.1/drivers/gpu/drm/drm_kms_helper.ko" 2>/dev/null
    rm -f "$TEMP_ROOT/lib/modules/6.8.1/drivers/gpu/drm/scheduler/gpu-sched.ko" 2>/dev/null
    rm -f "$TEMP_ROOT/lib/modules/6.8.1/drivers/gpu/drm/i2c/ch7006.ko" 2>/dev/null
    rm -f "$TEMP_ROOT/lib/modules/6.8.1/drivers/gpu/drm/i2c/sil164.ko" 2>/dev/null
    rm -f "$TEMP_ROOT/lib/modules/6.8.1/drivers/gpu/drm/ttm/ttm.ko" 2>/dev/null
    rm -rf "$TEMP_ROOT/lib/modules/6.8.1/drivers/platform" 2>/dev/null
    rm -rf "$TEMP_ROOT/lib/modules/6.8.1/drivers/acpi" 2>/dev/null
    rm -rf "$TEMP_ROOT/lib/modules/6.8.1/drivers/video" 2>/dev/null
    rm -rf "$TEMP_ROOT/lib/modules/6.8.1/drivers/thermal" 2>/dev/null
    rm -rf "$TEMP_ROOT/lib/modules/6.8.1/drivers/i2c" 2>/dev/null
    # Clean up empty driver directories
    find "$TEMP_ROOT/lib/modules/6.8.1/drivers" -type d -empty -delete 2>/dev/null || true
fi

# 7.5f: Remove unittest, test, and doctest from Python stdlib
# These are only needed for development, not for running tinygrad.
# We already exclude test/ during rsync, but some test files may remain in
# dist-packages (from pip) and the stdlib search path.
echo "  Removing Python test modules..."
find "$TEMP_ROOT/usr/lib/python${PY_VER}" -type d -name "test" -exec rm -rf {} + 2>/dev/null || true
find "$TEMP_ROOT/usr/lib/python${PY_VER}" -type d -name "tests" -exec rm -rf {} + 2>/dev/null || true
# KEEP __pycache__ — they contain .pyc files precompiled by the guest Python.
# Deleting them forces Python to recompile at import time (179-599s on single VCPU).

# 7.5h: Strip more aggressively (already done above, but do it again
# for files that were added after the initial strip)
find "$TEMP_ROOT" -type f \( -name "*.so*" -o -executable \) 2>/dev/null | while read -r f; do
    strip --strip-debug "$f" 2>/dev/null || true
done

AFTER=$(du -sh "$TEMP_ROOT" | cut -f1)
echo "  Size: $BEFORE → $AFTER"
echo ""

# ── Step 8: Create cpio archive ──
echo "Creating initramfs cpio archive..."

# Clean up temp files that may have been created during pip install
# (pip temp dirs in $TEMP_ROOT/tmp/ add ~1GB of duplicated torch+numpy libs)
rm -rf "$TEMP_ROOT/tmp" 2>/dev/null || true
mkdir -p "$TEMP_ROOT/tmp"

# tinyos_nv_patch.py REMOVED — all variants use source builds, no runtime patches.
# GPU variants handle NV backend through upstream tinygrad code (PCIIface/GSP-RM),
# not through runtime monkey-patching. See `tools/build-variant-initramfs.sh` for
# the per-variant build logic.

# Remove circular lib/lib -> lib symlink (created by recursive cp -r when lib64 is a symlink)
if [ -L "$TEMP_ROOT/lib/lib" ]; then
    rm -f "$TEMP_ROOT/lib/lib"
    echo "Fixed: removed circular lib/lib -> lib symlink"
fi

cd "$TEMP_ROOT"
find . -print0 | cpio --null -o -H newc --quiet 2>/dev/null | zstd -19 -T0 > "$OUTPUT_DIR/$VARIANT-initrd.zst"

# Also generate .gz version for backward compatibility with tests
zstd -dc "$OUTPUT_DIR/$VARIANT-initrd.zst" 2>/dev/null | gzip -c > "$OUTPUT_DIR/$VARIANT-initrd.gz" 2>/dev/null || true

# Also save to variant-specific template directory for tinymachine template build
TEMPLATE_DIR="$(realpath -m "$OUTPUT_DIR/../templates/python/v1/$VARIANT")"
mkdir -p "$TEMPLATE_DIR"
    cp "$OUTPUT_DIR/$VARIANT-initrd.zst" "$TEMPLATE_DIR/initrd.zst" 2>/dev/null || true
    cp "$OUTPUT_DIR/$VARIANT-initrd.zst" "$TEMPLATE_DIR/initrd" 2>/dev/null || true
    # Also copy .gz version for test backward compat
    cp "$OUTPUT_DIR/$VARIANT-initrd.gz" "$TEMPLATE_DIR/initrd.gz" 2>/dev/null || true

# Also copy to ~/.tinymachine templates directory (CLI default path)
TINYMACHINE_HOME_DIR="$HOME/.tinymachine/templates/python/v1/$VARIANT"
if [ -d "$HOME/.tinymachine" ]; then
    mkdir -p "$TINYMACHINE_HOME_DIR"
    cp "$OUTPUT_DIR/$VARIANT-initrd.zst" "$TINYMACHINE_HOME_DIR/initrd.zst" 2>/dev/null || true
    cp "$OUTPUT_DIR/$VARIANT-initrd.gz" "$TINYMACHINE_HOME_DIR/initrd.gz" 2>/dev/null || true
    echo "Also copied to: $TINYMACHINE_HOME_DIR/initrd.zst + .gz"
fi

echo ""
echo "=== Build complete ==="
echo "Output: $OUTPUT_DIR/$VARIANT-initrd.zst"
echo "Template: $TEMPLATE_DIR/initrd.zst"
SIZE=$(stat -c%s "$OUTPUT_DIR/$VARIANT-initrd.zst" 2>/dev/null || echo "0")
echo "Size:   $SIZE bytes ($(( SIZE / 1024 )) KB)"

# Show contents
echo ""
echo "Top-level contents:"
ls -la "$TEMP_ROOT/" 2>/dev/null
echo ""
echo "Python check:"
if [ -x "$TEMP_ROOT/bin/python3" ]; then
    echo "Python binary: $(stat -c%s "$TEMP_ROOT/bin/python3" 2>/dev/null | numfmt --to=iec 2>/dev/null || echo "$(du -h "$TEMP_ROOT/bin/python3" | cut -f1)")"
    # Try to check version (via chroot simulation)
    if "$TEMP_ROOT/bin/python3" --version 2>/dev/null; then
        echo "✅ Python works"
    else
        echo "⚠️  Python binary may need shared libraries in guest"
        # Check library deps
        ldd "$TEMP_ROOT/bin/python3" 2>/dev/null | grep "not found" || echo "   (all libs satisfied)"
    fi
else
    echo "Python binary not found at expected location"
fi

if [ -d "$TEMP_ROOT/usr/lib/python${PY_VER}/site-packages" ]; then
    PKG_COUNT=$(ls "$TEMP_ROOT/usr/lib/python${PY_VER}/site-packages/" 2>/dev/null | wc -l)
    echo "Packages: $PKG_COUNT items in site-packages"
fi
