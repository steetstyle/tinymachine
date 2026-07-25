#!/bin/bash
# TinyMachine Environment Setup Script
#
# Patches the minimal Python initrd with host shared libraries required
# to run Python3 in the KVM guest.
#
# Usage:
#   bash tools/setup-env.sh
#
# Prerequisites:
#   - ~/.tinyos/templates/python/v1/minimal/initrd.gz (from a prior build)
#   - Kernel image at ~/.tinyos/templates/kernel/vmlinux-base

set -euo pipefail

# ─── Config ─────────────────────────────────────────────────────────────

TINYOS_DIR="${HOME}/.tinyos"
TEMPLATES_DIR="${TINYOS_DIR}/templates"
INITRD="${TEMPLATES_DIR}/python/v1/minimal/initrd.gz"
KERNEL="${TEMPLATES_DIR}/kernel/vmlinux-base"
ZSTD_BIN=$(command -v zstd || true)

log()  { printf "\e[32m[✓]\e[0m %s\n" "$*"; }
warn() { printf "\e[33m[!]\e[0m %s\n" "$*"; }
err()  { printf "\e[31m[✗]\e[0m %s\n" "$*"; }

# ─── Library resolution ────────────────────────────────────────────────

# Resolve a shared library to its real file path.
# Follows symlinks to find the actual .so file (the versioned binary).
resolve_lib_real() {
    local lib="$1"
    local path

    # Try ldconfig first
    path=$(ldconfig -p 2>/dev/null | awk -v lib="$lib" '$1 == lib {print $NF; exit}')
    if [ -n "$path" ]; then
        # Follow symlinks to get the real file
        realpath -f "$path" 2>/dev/null || readlink -f "$path" 2>/dev/null || echo "$path"
        return 0
    fi

    # Fallback: search common paths
    for d in /usr/lib /usr/lib/x86_64-linux-gnu /lib /lib/x86_64-linux-gnu; do
        for f in "$d/$lib"*; do
            if [ -f "$f" ] || [ -L "$f" ]; then
                realpath -f "$f" 2>/dev/null || readlink -f "$f" 2>/dev/null || echo "$f"
                return 0
            fi
        done
    done
    return 1
}

# Get the SONAME of a shared library (the DT_SONAME field).
get_soname() {
    local file="$1"
    objdump -p "$file" 2>/dev/null | awk '/SONAME/ {print $2; exit}' || echo ""
}

# ─── Step 1: Check prerequisites ────────────────────────────────────────

echo "=== TinyMachine Environment Setup ==="
echo ""

if [ ! -f "$KERNEL" ]; then
    warn "Kernel not found at $KERNEL"
    warn "KVM CoW fork (Tier 2) requires a kernel + initrd template."
else
    log "Kernel found: $KERNEL"
fi

if [ ! -f "$INITRD" ]; then
    err "Initrd not found at $INITRD"
    err "A python:minimal template must exist first."
    err "Build from the tinyos repo or use: tools/build-variant-initramfs.sh minimal"
    exit 1
fi
log "Initrd found: $INITRD"

# ─── Step 2: Find all missing libraries ─────────────────────────────────

echo ""
echo "=== Resolving Python3 library dependencies ==="

# Extract the initrd to check what's already there
WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT
zcat "$INITRD" | cpio -idm -D "$WORKDIR" 2>/dev/null
log "Extracted initrd to $WORKDIR"

# Check what the initrd's python3 actually needs
PYTHON_BIN="${WORKDIR}/bin/python3"
if [ ! -f "$PYTHON_BIN" ]; then
    err "No python3 binary found in initrd at $PYTHON_BIN"
    exit 1
fi

# Run ldd in a chroot-like way: set LD_LIBRARY_PATH to the initrd's lib dir
# and see which libs are missing.
MISSING=$(LD_LIBRARY_PATH="${WORKDIR}/lib" ldd "$PYTHON_BIN" 2>&1 | grep "not found" | awk '{print $1}' || true)

if [ -z "$MISSING" ]; then
    echo ""
    log "All Python3 library dependencies already satisfied."
    # Still rebuild if zst is missing
    if [ -n "$ZSTD_BIN" ] && [ ! -f "${INITRD%.gz}.zst" ]; then
        zcat "$INITRD" | zstd -o "${INITRD%.gz}.zst"
        log "Rebuilt missing zstd variant: ${INITRD%.gz}.zst"
    fi
    exit 0
fi

echo "Missing libraries:"
echo "$MISSING" | sed 's/^/  /'

# ─── Step 3: Resolve and add each missing library ───────────────────────

echo ""
echo "=== Adding missing libraries ==="

# For each missing lib, resolve it on the host, copy the real file,
# and create the SONAME symlink.
for lib_name in $MISSING; do
    real_path=$(resolve_lib_real "$lib_name") || true
    if [ -z "$real_path" ] || [ ! -f "$real_path" ]; then
        warn "Could not resolve $lib_name on host system — skipping"
        continue
    fi

    # Get the SONAME from the real file
    soname=$(get_soname "$real_path")
    if [ -z "$soname" ]; then
        # If no SONAME, use the lib name as-is
        soname="$lib_name"
    fi

    # Copy the real file to the initrd's lib dir, named by SONAME.
    # The real file is the fully-resolved non-symlink (e.g., libffi.so.8.1.4).
    # We copy it as the SONAME (e.g., libffi.so.8) so the dynamic linker finds it.
    cp -L "$real_path" "${WORKDIR}/lib/${soname}"
    chmod 755 "${WORKDIR}/lib/${soname}"
    log "Added ${soname} ($(basename "$real_path"))"

    # Create a symlink from the real filename to SONAME (e.g., libffi.so.8.1.4 → libffi.so.8).
    # This is needed if any library has a DT_NEEDED entry for the full versioned name.
    real_basename=$(basename "$real_path")
    if [ "$soname" != "$real_basename" ]; then
        if [ ! -f "${WORKDIR}/lib/${real_basename}" ] && [ ! -L "${WORKDIR}/lib/${real_basename}" ]; then
            ln -sf "$soname" "${WORKDIR}/lib/${real_basename}"
            log "  symlink: ${real_basename} → ${soname}"
        fi
    fi

    # Create linker symlink (e.g., libffi.so → libffi.so.8) for -lffi linker flag
    base_name="${soname%%.so*}"
    if [ "$base_name" != "$soname" ]; then
        linker_name="${base_name}.so"
        if [ ! -f "${WORKDIR}/lib/${linker_name}" ] && [ ! -L "${WORKDIR}/lib/${linker_name}" ]; then
            ln -sf "$soname" "${WORKDIR}/lib/${linker_name}"
            log "  symlink: ${linker_name} → ${soname}"
        fi
    fi
done

# ─── Step 4: Verify all dependencies are satisfied ───────────────────────

echo ""
echo "=== Verifying dependencies ==="
VERIFY=$(LD_LIBRARY_PATH="${WORKDIR}/lib" ldd "$PYTHON_BIN" 2>&1 | grep "not found" || true)
if [ -n "$VERIFY" ]; then
    warn "Still missing after patch:"
    echo "$VERIFY" | sed 's/^/  /'
    # Check if it's worth trying to run anyway
fi

# Run a quick test to confirm the binary works
if LD_LIBRARY_PATH="${WORKDIR}/lib" "$PYTHON_BIN" -c "print('healthcheck:ok')" 2>&1 | grep -q "healthcheck:ok"; then
    log "Python3 healthcheck PASSED"
else
    warn "Python3 healthcheck FAILED — initrd may not work in KVM"
fi

# ─── Step 5: Rebuild initrd ────────────────────────────────────────────

echo ""
echo "=== Rebuilding initrd ==="

cd "$WORKDIR"
find . | cpio -o -H newc 2>/dev/null | gzip -1 > "$INITRD.tmp"
mv "$INITRD.tmp" "$INITRD"
cd "$OLDPWD"

log "Patched initrd: $INITRD ($(stat --format=%s "$INITRD" 2>/dev/null) bytes)"

# Also create .zst variant if zstd is available
if [ -n "$ZSTD_BIN" ]; then
    zcat "$INITRD" | zstd -o "${INITRD%.gz}.zst" 2>&1 || warn "zstd rebuild failed (non-fatal)"
    log "Created zstd variant: ${INITRD%.gz}.zst"
fi

echo ""
log "Environment setup complete. Run tests with: cargo test"
