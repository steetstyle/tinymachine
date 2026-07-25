#!/bin/bash
# ──────────────────────────────────────────────────────────────────────
# TinyOS NVIDIA Kernel Module Builder
# ──────────────────────────────────────────────────────────────────────
#
# Builds nvidia.ko (and friends) against the TinyOS guest kernel.
# Produces: nvidia.ko, nvidia-uvm.ko, nvidia-modeset.ko,
#           nvidia-drm.ko, nvidia-peermem.ko
#
# Usage:
#   ./build-nvidia-module.sh                              # use defaults
#   ./build-nvidia-module.sh --kernel-dir /path/to/linux  # custom kernel
#   ./build-nvidia-module.sh --nvidia-src /usr/src/nvidia  # custom source
#   ./build-nvidia-module.sh --install                     # build + install into initrd
#   ./build-nvidia-module.sh --install --variant tinygrad-nv # target variant
#   ./build-nvidia-module.sh --help
#
# Dependencies: gcc, make, kernel source (configured + built)
#
# The nvidia kernel module source is expected at one of:
#   /usr/src/nvidia-<version>/   (Ubuntu package)
#   /tmp/nvidia-build/           (copied from above for writable build dir)
#   Specified via --nvidia-src
#
# Kernel source expected at:
#   /tmp/tinyos-kernel-build/linux-{version}/
#   Specified via --kernel-dir
# ──────────────────────────────────────────────────────────────────────
set -euo pipefail

# ─── Config defaults ──────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TINYOS_DIR="${HOME}/.tinyos/templates"
KERNEL_BUILD_DIR="${BUILD_DIR:-/tmp/tinyos-kernel-build}"
KERNEL_VERSION="${KERNEL_VERSION:-7.1.4}"
KERNEL_DIR="${KERNEL_DIR:-${KERNEL_BUILD_DIR}/linux-${KERNEL_VERSION}}"
NVIDIA_BUILD_DIR="/tmp/nvidia-build"
CONFTEST_CACHE_DIR="${NVIDIA_BUILD_DIR}/conftest"
TINYOS_INITRD_DIR="${TINYOS_DIR}/python/v1"

# ─── Colors ──────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; NC='\033[0m'
ok()   { echo -e "${GREEN}✓${NC} $1"; }
warn() { echo -e "${YELLOW}⚠ $1${NC}"; }
err()  { echo -e "${RED}✗ $1${NC}" >&2; }
info() { echo -e "${BLUE}ℹ${NC} $1"; }

# ─── Help ─────────────────────────────────────────────────────────────
usage() {
    cat << 'EOF'
Usage: ./build-nvidia-module.sh [options]

Options:
  --kernel-dir DIR     Kernel source directory (default: /tmp/.../linux-7.1.4)
  --nvidia-src DIR     NVIDIA module source (default: /usr/src/nvidia-* or /tmp/nvidia-build)
  --install            Build and copy modules into a variant's initrd
  --variant NAME       Target initrd variant for --install (default: minimal)
  --clean              Remove old build artifacts before building
  --skip-build         Skip module build, only install (for re-install)
  --help               Show this help

Examples:
  ./build-nvidia-module.sh                              # basic build
  ./build-nvidia-module.sh --install                    # build + install into minimal initrd
  ./build-nvidia-module.sh --install --variant tinygrad-nv
  ./build-nvidia-module.sh --kernel-dir /tmp/linux-6.8.0 --nvidia-src /opt/nvidia
EOF
    exit 0
}

# ─── Parse arguments ─────────────────────────────────────────────────
DO_INSTALL=false
DO_CLEAN=false
SKIP_BUILD=false
VARIANT="minimal"

while [ $# -gt 0 ]; do
    case "$1" in
        --kernel-dir) KERNEL_DIR="$2"; shift 2 ;;
        --nvidia-src) NVIDIA_SRC="$2"; shift 2 ;;
        --install)    DO_INSTALL=true; shift ;;
        --variant)    VARIANT="$2"; shift 2 ;;
        --clean)      DO_CLEAN=true; shift ;;
        --skip-build) SKIP_BUILD=true; shift ;;
        --help|-h)    usage ;;
        *) err "Unknown option: $1"; usage ;;
    esac
done

# ─── Find NVIDIA source ──────────────────────────────────────────────
find_nvidia_src() {
    # Check explicit source first
    if [ -n "${NVIDIA_SRC:-}" ]; then
        if [ -d "$NVIDIA_SRC" ]; then
            echo "$NVIDIA_SRC"
            return 0
        fi
        err "Specified nvidia source not found: $NVIDIA_SRC"
        return 1
    fi

    # Check writable build dir
    if [ -d "$NVIDIA_BUILD_DIR" ] && [ -f "${NVIDIA_BUILD_DIR}/Kbuild" ]; then
        echo "$NVIDIA_BUILD_DIR"
        return 0
    fi

    # Check /usr/src for nvidia packages (Ubuntu)
    for d in /usr/src/nvidia-*; do
        if [ -d "$d" ] && [ -f "${d}/Kbuild" ]; then
            echo "$d"
            return 0
        fi
    done

    err "NVIDIA kernel module source not found."
    echo "  Install: sudo apt-get install nvidia-kernel-source-<ver>"
    echo "  Or copy to: $NVIDIA_BUILD_DIR"
    return 1
}

# ─── Setup writable build directory ──────────────────────────────────
setup_build_dir() {
    local src="$1"
    if [ "$src" = "$NVIDIA_BUILD_DIR" ]; then
        # Already in writable dir
        return 0
    fi

    info "Copying NVIDIA source to writable build dir..."
    rm -rf "$NVIDIA_BUILD_DIR"
    mkdir -p "$NVIDIA_BUILD_DIR"
    cp -a "$src/"* "$NVIDIA_BUILD_DIR/" 2>/dev/null || {
        err "Failed to copy NVIDIA source"
        return 1
    }
    ok "Copied to $NVIDIA_BUILD_DIR"
}

# ─── Check kernel readiness ──────────────────────────────────────────
check_kernel() {
    if [ ! -d "$KERNEL_DIR" ]; then
        err "Kernel source not found at $KERNEL_DIR"
        echo "  Build it: ./build-kernel.sh gpu-nvidia --version $KERNEL_VERSION"
        return 1
    fi
    if [ ! -f "${KERNEL_DIR}/Module.symvers" ]; then
        err "Kernel not built yet — Module.symvers missing"
        echo "  Build it: cd $KERNEL_DIR && make -j\$(nproc)"
        return 1
    fi
    if [ ! -f "${KERNEL_DIR}/vmlinux" ]; then
        warn "vmlinux not found — modules_prepare may be insufficient"
        warn "  Run: make -j\$(nproc) in $KERNEL_DIR"
    fi
    ok "Kernel source OK: $KERNEL_DIR"
}

# ─── Build modules ────────────────────────────────────────────────────
build_modules() {
    info "Building NVIDIA kernel modules against $KERNEL_DIR ..."

    # Clean conftest cache to avoid stale detection
    rm -rf "${NVIDIA_BUILD_DIR}/conftest"

    cd "$NVIDIA_BUILD_DIR"
    if make SYSSRC="$KERNEL_DIR" 2>&1 | tee /tmp/nvidia-build.log | tail -5; then
        ok "All NVIDIA modules built successfully"
        return 0
    fi

    # Check for known build failures
    if grep -q "implicit declaration.*del_timer_sync" /tmp/nvidia-build.log; then
        err "Build failed: kernel removed del_timer_sync"
        err "  Solution: clean conftest cache and rebuild"
        echo "  rm -rf ${NVIDIA_BUILD_DIR}/conftest && make SYSSRC=$KERNEL_DIR"
        return 1
    fi
    if grep -q "drm_fb_helper_set_suspend_unlocked" /tmp/nvidia-build.log; then
        err "Build failed: CONFIG_DRM_FBDEV_EMULATION not set in kernel"
        err "  Solution: enable in kernel config and rebuild kernel"
        echo "  echo CONFIG_DRM_FBDEV_EMULATION=y >> $KERNEL_DIR/.config"
        echo "  make -j\$(nproc) -C $KERNEL_DIR"
        return 1
    fi

    err "Build failed — see /tmp/nvidia-build.log for details"
    return 1
}

# ─── List built modules ──────────────────────────────────────────────
list_modules() {
    local dir="${1:-$NVIDIA_BUILD_DIR}"
    local found=false
    for m in nvidia.ko nvidia-uvm.ko nvidia-modeset.ko nvidia-drm.ko nvidia-peermem.ko; do
        local path="${dir}/${m}"
        if [ -f "$path" ]; then
            local size
            size=$(stat -c%s "$path" 2>/dev/null || echo "0")
            size=$(numfmt --to=iec "$size" 2>/dev/null || echo "${size}B")
            echo "  $m ($size) ✅"
            found=true
        else
            echo "  $m ❌ missing"
        fi
    done
    $found
}

# ─── Pack modules into variant initrd ─────────────────────────────────
install_modules() {
    local variant="$1"
    local initrd_src="${TINYOS_INITRD_DIR}/${variant}/initrd.zst"
    local initrd_dst="${TINYOS_INITRD_DIR}/${variant}/initrd.zst"

    if [ ! -f "$initrd_src" ] && [ "$variant" != "nvidia" ]; then
        # Try build it
        if [ -f "${SCRIPT_DIR}/build-variant-initramfs.sh" ]; then
            info "Building initrd for variant '${variant}'..."
            bash "${SCRIPT_DIR}/build-variant-initramfs.sh" "$variant" || {
                err "Failed to build initrd for variant '${variant}'"
                return 1
            }
        else
            err "Initrd not found at $initrd_src"
            return 1
        fi
    fi

    local tmpdir
    tmpdir=$(mktemp -d)
    info "Extracting initrd: $initrd_src ..."

    # Extract initrd
    if ! zstd -d < "$initrd_src" 2>/dev/null | cpio -id --quiet -D "$tmpdir" 2>/dev/null; then
        err "Failed to extract initrd"
        rm -rf "$tmpdir"
        return 1
    fi

    # Create modules directory
    mkdir -p "$tmpdir/lib/modules/${KERNEL_VERSION}"

    # Copy modules
    local count=0
    for m in nvidia.ko nvidia-uvm.ko nvidia-modeset.ko nvidia-drm.ko nvidia-peermem.ko; do
        if [ -f "${NVIDIA_BUILD_DIR}/${m}" ]; then
            cp "${NVIDIA_BUILD_DIR}/${m}" "$tmpdir/lib/modules/${KERNEL_VERSION}/"
            count=$((count + 1))
        fi
    done

    if [ "$count" -eq 0 ]; then
        err "No nvidia modules found to install"
        rm -rf "$tmpdir"
        return 1
    fi

    # Strip debug symbols from modules
    for f in "$tmpdir/lib/modules/${KERNEL_VERSION}"/*.ko; do
        strip --strip-debug "$f" 2>/dev/null || true
    done

    # Generate modules.dep (simple flat file for modprobe compatibility)
    cat > "$tmpdir/lib/modules/${KERNEL_VERSION}/modules.dep" << 'DEP'
nvidia.ko:
nvidia-uvm.ko: nvidia.ko
nvidia-modeset.ko: nvidia.ko
nvidia-drm.ko: nvidia.ko nvidia-modeset.ko
nvidia-peermem.ko: nvidia.ko
DEP

    # Rebuild initrd
    local out_initrd="/tmp/initrd-nvidia-${variant}.zst"
    cd "$tmpdir"
    find . -print0 | cpio --null -o -H newc --quiet 2>/dev/null | zstd -19 -T0 > "$out_initrd" 2>/dev/null

    # Install to template directory
    cp "$out_initrd" "$initrd_dst"

    local size
    size=$(stat -c%s "$initrd_dst" 2>/dev/null || echo "0")
    size=$(numfmt --to=iec "$size" 2>/dev/null || echo "${size}B")

    rm -rf "$tmpdir"
    ok "Installed $count modules into ${variant} initrd ($size)"
    return 0
}

# ─── Main ─────────────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║      TinyOS NVIDIA Module Builder — kernel ${KERNEL_VERSION}        ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Step 1: Find NVIDIA source
NVIDIA_SRC=$(find_nvidia_src)
ok "NVIDIA source: $NVIDIA_SRC"

# Step 2: Setup writable build dir (if needed)
setup_build_dir "$NVIDIA_SRC"

# Step 3: Check kernel
check_kernel

# Step 4: Clean if requested
if [ "$DO_CLEAN" = true ]; then
    info "Cleaning build artifacts..."
    rm -rf "${NVIDIA_BUILD_DIR}/conftest"
    rm -f "${NVIDIA_BUILD_DIR}"/*.ko "${NVIDIA_BUILD_DIR}"/*.o
    ok "Cleaned"
fi

# Step 5: Build
if [ "$SKIP_BUILD" = false ]; then
    build_modules || exit 1
else
    info "Skipping build (--skip-build)"
fi

# Step 6: Show results
echo ""
info "Built modules:"
list_modules "$NVIDIA_BUILD_DIR"
echo ""

# Step 7: Install into initrd if requested
if [ "$DO_INSTALL" = true ]; then
    install_modules "$VARIANT" || exit 1
fi

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║     ✅ NVIDIA module build complete                          ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
info "Modules:       ${NVIDIA_BUILD_DIR}/nvidia*.ko"
if [ "$DO_INSTALL" = true ]; then
    info "Installed to:  ${TINYOS_INITRD_DIR}/${VARIANT}/initrd.zst"
fi
info "Test command:  ./test-vfio-gpu.sh --variant ${VARIANT}"
echo ""
