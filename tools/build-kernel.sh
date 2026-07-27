#!/bin/bash
# ──────────────────────────────────────────────────────────────────────
# TinyMachine Kernel Builder — build vmlinux profiles for KVM sandboxes
# ──────────────────────────────────────────────────────────────────────
#
# Usage:
#   ./build-kernel.sh                         # list profiles + versions
#   ./build-kernel.sh base                    # build vmlinux-base (default version)
#   ./build-kernel.sh base --version 7.1.4    # build specific version
#   ./build-kernel.sh --list                  # show installed versions
#   ./build-kernel.sh --default 7.1.4         # change default version
#
# Each profile produces a stripped vmlinux ELF at:
#   ~/.tinymachine/templates/kernel/v{version}/vmlinux-<profile>
#
# Dependencies: gcc, make, flex, bison, libelf-dev, wget, curl
# ──────────────────────────────────────────────────────────────────────
set -euo pipefail

# ─── Config ───────────────────────────────────────────────────────────

LINUX_VERSION="7.1.4"                       # Upstream version (default)
LINUX_TARBALL="linux-${LINUX_VERSION}.tar.xz"
LINUX_URL="https://cdn.kernel.org/pub/linux/kernel/v7.x/${LINUX_TARBALL}"
BUILD_DIR="${BUILD_DIR:-/tmp/tinymachine-kernel-build}"
TINYMACHINE_KERNEL_DIR="${HOME}/.tinymachine/templates/kernel"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Number of parallel build jobs
JOBS="${JOBS:-$(nproc)}"

# ─── Colors ──────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; NC='\033[0m'
ok()   { echo -e "${GREEN}✓${NC} $1"; }
warn() { echo -e "${YELLOW}⚠ $1${NC}"; }
err()  { echo -e "${RED}✗ $1${NC}" >&2; }
info() { echo -e "${BLUE}ℹ${NC} $1"; }

# ─── Profiles ─────────────────────────────────────────────────────────
declare -A PROFILES
PROFILES["base"]="Base profile (no GPU support) — matches vmlinux-base"
PROFILES["gpu-vfio"]="GPU VFIO passthrough profile — CONFIG_VFIO=y, CONFIG_VFIO_PCI=y, CONFIG_VFIO_IOMMU_TYPE1=y"
PROFILES["gpu-nvidia"]="GPU NVIDIA passthrough profile — ACPI=y + VFIO=y (for nvidia.ko module loading)"
PROFILES["gpu-vk"]="GPU Vulkan profile — CONFIG_DRM=y, CONFIG_DRM_AMDGPU=y (Vulkan support)"

declare -A PROFILE_CONFIGS
# Extra config lines added on top of the base allnoconfig + PCI + BLK + EXT4
PROFILE_CONFIGS["base"]=""
PROFILE_CONFIGS["gpu-vfio"]="
# Enable ACPI for nouveau module symbol dependencies (wmi, video backlight).
# Without CONFIG_ACPI=y, modules like wmi.ko and video.ko can't resolve ACPI
# symbols, and nouveau.ko depends on both — so module loading fails with ENOEXEC.
#
# ACPI boot behavior (no acpi=off in cmdline):
#   - KVM guest has no RSDP/ACPI tables, so acpi_init() sets acpi_disabled=1.
#   - pci_acpi_init() returns -ENODEV (can't find PCI root bridge).
#   - Legacy fallback runs (pcibios_scan_root → pcibios_scan_specific_bus(0)).
#   - PCI devices appear at bus 0 (our VFIO GPU at 00:02.0 is visible).
CONFIG_ACPI=y
CONFIG_VFIO=y
CONFIG_VFIO_IOMMU_TYPE1=y
CONFIG_VFIO_PCI=y
CONFIG_VFIO_PCI_VGA=y
CONFIG_VFIO_NOIOMMU=y
CONFIG_VFIO_VIRQFD=y
CONFIG_VFIO_GROUP=y
CONFIG_VFIO_CONTAINER=y
CONFIG_VFIO_DEVICE_CDEV=y
CONFIG_IOMMU_API=y
CONFIG_IOMMU_SUPPORT=y
CONFIG_IOMMU_IOVA=y

# ─── Nouveau (open-source NVIDIA driver, Ada GSP support since 6.7) ───
# Provides open-source GPU compute support for Ada GPUs (AD103/AD104).
# Uses GSP firmware which may handle DMA initialization differently
# than nvidia.ko's PCIIface/GSP path.
CONFIG_DRM=y
# Built as module (=m) instead of built-in (=y) to avoid MMIO faults
# during kernel boot — see gpu-nvidia profile for full explanation.
CONFIG_DRM_NOUVEAU=m
CONFIG_DRM_NOUVEAU_GSP_DEFAULT=y
"

PROFILE_CONFIGS["gpu-nvidia"]="
# GPU NVIDIA passthrough: ACPI=y + VFIO=y + DMA_SHARED_BUFFER=y
# ACPI is kept enabled (unlike gpu-vfio) because nvidia.ko needs 11 ACPI
# symbols (acpi_evaluate_object, etc.). The kernel is booted WITHOUT
# acpi=off in cmdline; ACPI init fails gracefully (no tables in KVM guest),
# then falls back to legacy PCI scan (pcibios_scan_root).
#
# With CONFIG_ACPI=y and acpi=off in cmdline:
#   pci_acpi_init returns -ENODEV → legacy fallback works? No — on modern
#   kernels, acpi=off skips ACPI init entirely but pci_acpi_init returns
#   success even though no ACPI tables were parsed, so the legacy fallback
#   is skipped. Result: PCI devices invisible.
#
# Solution: compile ACPI=y, boot WITHOUT acpi=off. ACPI init finds no RSDP,
# sets acpi_disabled=1. pci_acpi_init returns -ENODEV. Legacy fallback runs.
CONFIG_VFIO=y
CONFIG_VFIO_IOMMU_TYPE1=y
CONFIG_VFIO_PCI=y
CONFIG_VFIO_PCI_VGA=y
CONFIG_VFIO_NOIOMMU=y
CONFIG_VFIO_VIRQFD=y
CONFIG_VFIO_GROUP=y
CONFIG_VFIO_CONTAINER=y
CONFIG_VFIO_DEVICE_CDEV=y
CONFIG_IOMMU_API=y
CONFIG_IOMMU_SUPPORT=y
CONFIG_IOMMU_IOVA=y
CONFIG_DMA_SHARED_BUFFER=y
CONFIG_DRM=y
CONFIG_FW_LOADER=y

# ─── Nouveau (open-source NVIDIA driver, Ada GSP support since 6.7) ───
# Alternative to nvidia.ko for GPU compute. Uses GSP firmware for Ada GPUs.
# The GSP codepath handles DMA differently than nvidia.ko's PCIIface path,
# potentially avoiding the DMA timeout issue seen with nvidia.ko.
#
# Built as module (=m) NOT built-in (=y) because the driver probes GPU MMIO
# during PCI enumeration at boot time, but KVM hasn't mapped GPU BARs yet
# (map_guest_bar_slots runs after boot). With =m, nouveau can be loaded via
# modprobe after BAR mapping is complete.
CONFIG_DRM_NOUVEAU=m
CONFIG_DRM_NOUVEAU_GSP_DEFAULT=y
"

PROFILE_CONFIGS["gpu-vk"]="
CONFIG_DRM=y
CONFIG_DRM_AMDGPU=y
CONFIG_DRM_AMDGPU_USERPTR=y
CONFIG_DRM_RADEON=y
CONFIG_DRM_NOUVEAU=y
CONFIG_DRM_VIRTIO_GPU=y
CONFIG_HSA_AMD=y
CONFIG_DRM_TTM=y
"

# ─── Output filename ──────────────────────────────────────────────────
profile_filename() {
    echo "vmlinux-${1}"
}

# ─── Registry helpers ─────────────────────────────────────────────────

# Update registry.toml with build info for the given version+profile
update_registry() {
    local version="$1"
    local profile="$2"

    local reg_file="${TINYMACHINE_KERNEL_DIR}/registry.toml"
    mkdir -p "$TINYMACHINE_KERNEL_DIR"

    # Load existing registry or create default
    local default_ver="${version}"
    if [ -f "$reg_file" ]; then
        # Extract existing default_version
        local existing_default
        existing_default=$(grep -oP 'default_version\s*=\s*"\K[^"]*' "$reg_file" 2>/dev/null || echo "$version")
        default_ver="$existing_default"
    fi

    # Compute sha256 hash of the base kernel for this version
    local base_file="${TINYMACHINE_KERNEL_DIR}/v${version}/vmlinux-base"
    local hash=""
    if [ -f "$base_file" ]; then
        hash=$(sha256sum "$base_file" | cut -d' ' -f1)
    else
        # If no base kernel (e.g., only GPU profiles), hash from the current profile
        local profile_file="${TINYMACHINE_KERNEL_DIR}/v${version}/vmlinux-${profile}"
        if [ -f "$profile_file" ]; then
            hash=$(sha256sum "$profile_file" | cut -d' ' -f1)
        fi
    fi

    # Discover all profiles for this version
    local profiles_list=""
    local first=true
    if [ -d "${TINYMACHINE_KERNEL_DIR}/v${version}" ]; then
        for f in "${TINYMACHINE_KERNEL_DIR}/v${version}"/vmlinux-*; do
            [ -f "$f" ] || continue
            local p_name="${f#*vmlinux-}"
            if [ "$first" = true ]; then
                profiles_list="\"${p_name}\""
                first=false
            else
                profiles_list="${profiles_list}, \"${p_name}\""
            fi
        done
    fi
    [ -z "$profiles_list" ] && profiles_list="\"${profile}\""

    # Write registry.toml using a temporary file to avoid partial writes
    local tmp_reg=$(mktemp)
    cat > "$tmp_reg" << REGEOF
# TinyMachine Kernel Registry
# Managed by build-kernel.sh — do not edit manually
default_version = "${default_ver}"

[versions]
[versions."${version}"]
profiles = [${profiles_list}]
hash = "${hash}"
REGEOF

    # Add profile_hashes if we have any
    if [ -d "${TINYMACHINE_KERNEL_DIR}/v${version}" ]; then
        local count=0
        for f in "${TINYMACHINE_KERNEL_DIR}/v${version}"/vmlinux-*; do
            [ -f "$f" ] || continue
            local p_name="${f#*vmlinux-}"
            local p_hash
            p_hash=$(sha256sum "$f" | cut -d' ' -f1)

            if [ "$count" -eq 0 ]; then
                echo "" >> "$tmp_reg"
                echo "[versions.\"${version}\".profile_hashes]" >> "$tmp_reg"
            fi
            echo "\"${p_name}\" = \"${p_hash}\"" >> "$tmp_reg"
            count=$((count + 1))
        done
    fi

    # Move into place atomically
    mv "$tmp_reg" "$reg_file"
    ok "Registry updated: ${reg_file}"
}

# ─── Prerequisites ───────────────────────────────────────────────────
check_prereqs() {
    local missing=0
    for cmd in gcc make flex bison; do
        if ! command -v "$cmd" &>/dev/null; then
            err "Missing: $cmd — install build-essential, flex, bison"
            missing=1
        fi
    done
    if [ ! -f /usr/include/elf.h ]; then
        warn "Missing: libelf-dev — kernel build may fail"
    fi
    return "$missing"
}

# ─── Download kernel source ──────────────────────────────────────────
download_source() {
    local version="$1"
    local tarball="linux-${version}.tar.xz"
    local url=""

    # Determine URL based on version
    local major="${version%%.*}"
    if [ "$major" -ge 7 ]; then
        url="https://cdn.kernel.org/pub/linux/kernel/v${major}.x/${tarball}"
    elif [ "$major" -eq 6 ]; then
        url="https://cdn.kernel.org/pub/linux/kernel/v6.x/${tarball}"
    else
        err "Unknown kernel major version: ${major}"
        return 1
    fi

    if [ -f "${BUILD_DIR}/${tarball}" ] || [ -d "${BUILD_DIR}/linux-${version}" ]; then
        ok "Kernel source already at ${BUILD_DIR}/linux-${version}"
        return 0
    fi

    mkdir -p "$BUILD_DIR"
    info "Downloading Linux ${version} from kernel.org..."
    echo "  URL: ${url}"

    if command -v wget &>/dev/null; then
        wget --no-check-certificate -q --show-progress -O "${BUILD_DIR}/${tarball}" "${url}" || {
            err "Download failed. Trying curl..."
            curl -L -o "${BUILD_DIR}/${tarball}" "${url}" || {
                err "Download failed with both wget and curl"
                return 1
            }
        }
    elif command -v curl &>/dev/null; then
        curl -L -o "${BUILD_DIR}/${tarball}" "${url}" || {
            err "Download failed"
            return 1
        }
    else
        err "Neither wget nor curl available"
        return 1
    fi

    ok "Downloaded: ${BUILD_DIR}/${tarball}"

    info "Extracting kernel source..."
    cd "$BUILD_DIR"
    tar -xf "${tarball}" 2>&1 | tail -5 || {
        err "Extraction failed"
        return 1
    }
    ok "Extracted to ${BUILD_DIR}/linux-${version}"
}

# ─── Configure kernel ────────────────────────────────────────────────
configure_kernel() {
    local profile="$1"
    local version="$2"
    local kernel_dir="${BUILD_DIR}/linux-${version}"

    if [ ! -d "$kernel_dir" ]; then
        err "Kernel source not found at $kernel_dir"
        return 1
    fi

    cd "$kernel_dir"

    # Start from a minimal config with PCI + block + ext4 support
    # This gives us a tiny kernel that boots in KVM
    info "Creating minimal configuration for profile '${profile}' (Linux ${version})..."

    # Use allnoconfig as base, then enable essentials
    make allnoconfig 2>&1 | tail -3

    # Enable minimum required options for a bootable x86_64 KVM guest
    # We use scripts/config to set individual options
    local config_additions="
# ─── Architecture: x86_64 ───
CONFIG_64BIT=y
# CONFIG_32BIT is not set
CONFIG_X86_64=y
CONFIG_X86=y
CONFIG_X86_VERBOSE_BOOTUP=y
CONFIG_X86_64_SMP=y
CONFIG_SMP=y
CONFIG_NR_CPUS=4
CONFIG_PCI=y
CONFIG_PCI_DIRECT=y
CONFIG_PCI_MMCONFIG=y
CONFIG_ACPI=y
CONFIG_ACPI_BUTTON=y
CONFIG_ACPI_PROCESSOR=y

# ─── Block layer ───
CONFIG_BLOCK=y
CONFIG_BLK_DEV_INITRD=y

# ─── Module support (needed for nvidia.ko and other out-of-tree drivers) ───
CONFIG_MODULES=y
CONFIG_MODULE_UNLOAD=y

# ─── Binary formats ───
CONFIG_BINFMT_ELF=y
CONFIG_BINFMT_SCRIPT=y

# ─── Filesystems ───
CONFIG_EXT4_FS=y
CONFIG_EXT4_FS_POSIX_ACL=y
CONFIG_PROC_FS=y
CONFIG_SYSFS=y
CONFIG_TMPFS=y
CONFIG_DEVTMPFS=y
CONFIG_DEVTMPFS_MOUNT=y

# ─── Character devices ───
CONFIG_SERIAL_8250=y
CONFIG_SERIAL_8250_CONSOLE=y
CONFIG_SERIAL_8250_NR_UARTS=4
CONFIG_SERIAL_8250_RUNTIME_UARTS=4
CONFIG_PRINTK=y
CONFIG_EARLY_PRINTK=y

# ─── Networking (minimal) ───
CONFIG_NET=y
CONFIG_INET=y
CONFIG_IPV6=n
CONFIG_VIRTIO_NET=y
CONFIG_NETDEVICES=y
CONFIG_NET_CORE=y
CONFIG_VIRTIO=y
CONFIG_VIRTIO_PCI=y
CONFIG_VIRTIO_PCI_LEGACY=y
CONFIG_VIRTIO_BALLOON=y

# ─── Memory ───
CONFIG_HIGH_RES_TIMERS=y
CONFIG_NO_HZ_IDLE=y
CONFIG_SCHED_MC=y
CONFIG_PAGE_POISONING=n
CONFIG_DEBUG_KERNEL=n

# ─── /dev/mem access (required for init's command buffer protocol) ───
CONFIG_DEVMEM=y
CONFIG_STRICT_DEVMEM=y
# Note: iomem=relaxed kernel cmdline allows access to RAM via /dev/mem

# ─── KVM Guest support ───
CONFIG_HYPERVISOR_GUEST=y
CONFIG_PARAVIRT=y
CONFIG_KVM_GUEST=y
CONFIG_PARAVIRT_SPINLOCKS=y

# ─── Misc essential ───
CONFIG_TTY=y
CONFIG_VT=y
CONFIG_VT_CONSOLE=y
CONFIG_HW_CONSOLE=y
CONFIG_UNIX98_PTYS=y
CONFIG_DEVPTS_MULTIPLE_INSTANCES=y

# ─── PCI hotplug ───
CONFIG_HOTPLUG_PCI=y
CONFIG_HOTPLUG_PCI_PCIE=y

# ─── PCI MSI interrupts (required by nvidia.ko and many PCI drivers) ───
CONFIG_PCI_MSI=y

# ─── UUID / Partitions ───
CONFIG_UNIXWARE_DISKLABEL=y
CONFIG_LBD=y
CONFIG_MSDOS_PARTITION=y
CONFIG_EFI_PARTITION=y
CONFIG_PARTITION_ADVANCED=y
"

    # Write the base config
    echo "$config_additions" > /tmp/kernel-base-config.txt

    # Apply base config via scripts/config
    info "Applying base kernel configuration..."
    while IFS='=' read -r key value; do
        # Skip empty lines and comments
        [[ -z "$key" || "$key" == \#* ]] && continue
        # Handle 'y' / 'n' / 'm' values
        case "$value" in
            y)
                scripts/config --enable "${key#CONFIG_}" 2>/dev/null || true
                ;;
            n)
                scripts/config --disable "${key#CONFIG_}" 2>/dev/null || true
                ;;
            m)
                scripts/config --module "${key#CONFIG_}" 2>/dev/null || true
                ;;
            *)
                # String or int value
                scripts/config --set-val "${key#CONFIG_}" "$value" 2>/dev/null || true
                ;;
        esac
    done < /tmp/kernel-base-config.txt

    # ─── Apply profile-specific config ────────────────────────────────
    local profile_config="${PROFILE_CONFIGS[$profile]:-}"
    if [ -n "$profile_config" ]; then
        info "Applying profile '${profile}' configuration..."
        echo "$profile_config" > /tmp/kernel-profile-config.txt
        while IFS='=' read -r key value; do
            [[ -z "$key" || "$key" == \#* ]] && continue
            case "$value" in
                y) scripts/config --enable "${key#CONFIG_}" 2>/dev/null || true ;;
                n) scripts/config --disable "${key#CONFIG_}" 2>/dev/null || true ;;
                m) scripts/config --module "${key#CONFIG_}" 2>/dev/null || true ;;
                *) scripts/config --set-val "${key#CONFIG_}" "$value" 2>/dev/null || true ;;
            esac
        done < /tmp/kernel-profile-config.txt
    fi

    # Enable namespaces (needed for virtio)
    scripts/config --enable NAMESPACES 2>/dev/null || true
    scripts/config --enable UTS_NS 2>/dev/null || true
    scripts/config --enable IPC_NS 2>/dev/null || true
    scripts/config --enable PID_NS 2>/dev/null || true
    scripts/config --enable NET_NS 2>/dev/null || true
    scripts/config --enable USER_NS 2>/dev/null || true
    scripts/config --enable CGROUPS 2>/dev/null || true

    # Sync and show final config state
    make olddefconfig 2>&1 | tail -3

    # HACK: Ensure virtio-net is enabled (scripts/config --enable doesn't
    # resolve dependency chains; VIRTIO_NET depends on VIRTIO which
    # depends on VIRTIO_MENU, and these must be set explicitly).
    if grep -q "^CONFIG_VIRTIO_NET=y" .config 2>/dev/null; then
        : # Already enabled — good
    else
        # Attempt to force virtio-net via direct .config injection
        # (olddefconfig will disable if deps can't be met, but they should be now)
        echo "CONFIG_VIRTIO_MENU=y" >> .config
        echo "CONFIG_VIRTIO=y" >> .config
        echo "CONFIG_VIRTIO_PCI=y" >> .config
        echo "CONFIG_VIRTIO_PCI_LEGACY=y" >> .config
        echo "CONFIG_VIRTIO_NET=y" >> .config
        make olddefconfig 2>&1 | tail -1
        if grep -q "^CONFIG_VIRTIO_NET=y" .config; then
            info "virtio-net forced enabled via direct .config injection"
        else
            warn "virtio-net could not be enabled (networking will not be available in guest)"
        fi
    fi

    # Show VFIO config if gpu-vfio or gpu-nvidia profile
    if [ "$profile" = "gpu-vfio" ] || [ "$profile" = "gpu-nvidia" ]; then
        info "VFIO config check:"
        grep "^CONFIG_VFIO" .config 2>/dev/null || warn "VFIO options not in config"
    fi

    ok "Kernel configured for profile '${profile}' (Linux ${version})"
}

# ─── Build kernel ─────────────────────────────────────────────────────
build_kernel() {
    local profile="$1"
    local version="$2"
    local kernel_dir="${BUILD_DIR}/linux-${version}"
    local version_dir="${TINYMACHINE_KERNEL_DIR}/v${version}"
    local output_file="${version_dir}/$(profile_filename "$profile")"

    cd "$kernel_dir"

    # Build vmlinux
    info "Building vmlinux (${JOBS} parallel jobs)..."
    make -j"$JOBS" vmlinux 2>&1 | tail -20 || {
        err "Kernel build failed. Check ${kernel_dir}/vmlinux"
        return 1
    }

    # Check the built kernel
    if [ ! -f vmlinux ]; then
        err "vmlinux not found after build!"
        return 1
    fi

    local size_before=$(stat -c%s vmlinux 2>/dev/null || echo "0")
    info "vmlinux built: ${size_before} bytes"

    # Build kernel modules (for profiles with =m drivers like nouveau)
    info "Building kernel modules (${JOBS} parallel jobs)..."
    make -j"$JOBS" modules 2>&1 | tail -10 || {
        warn "Kernel modules build failed (non-fatal for =y builds)"
    }

    # Strip debug symbols
    if command -v strip &>/dev/null; then
        info "Stripping debug symbols..."
        cp vmlinux vmlinux-stripped
        strip --strip-debug vmlinux-stripped 2>/dev/null || true
        local size_after=$(stat -c%s vmlinux-stripped 2>/dev/null || echo "0")
        info "Stripped: ${size_before} → ${size_after} bytes"
        mv vmlinux-stripped vmlinux
    fi

    # Install to TinyMachine templates (versioned directory)
    mkdir -p "$version_dir"
    cp vmlinux "$output_file"
    chmod 644 "$output_file"

    ok "Kernel installed: ${output_file} ($(stat -c%s "$output_file" 2>/dev/null) bytes)"

    # Verify it's a valid ELF
    if file "$output_file" | grep -q "ELF"; then
        ok "ELF verification passed"
    else
        warn "Output does not appear to be an ELF binary"
    fi

    # Install kernel modules to TinyMachine initramfs staging directory
    # (so the initramfs builder picks up nouveau.ko and other =m drivers)
    local modules_staging="${SCRIPT_DIR}/initramfs/lib/modules/${version}"
    if [ -d "${kernel_dir}/drivers" ]; then
        info "Installing kernel modules to initramfs staging..."
        mkdir -p "$modules_staging"
        find "${kernel_dir}" -name "*.ko" -type f 2>/dev/null | while read -r ko; do
            # Determine module path relative to kernel dir
            local rel_path="${ko#${kernel_dir}/}"
            local target="${modules_staging}/${rel_path}"
            mkdir -p "$(dirname "$target")"
            cp "$ko" "$target"
        done
        local ko_count=$(find "$modules_staging" -name "*.ko" -type f 2>/dev/null | wc -l)
        if [ "$ko_count" -gt 0 ]; then
            ok "${ko_count} kernel modules installed to initramfs staging"
        else
            info "No modules to install (all drivers built-in)"
        fi
    fi

    # Update registry after build
    update_registry "$version" "$profile"
}

# ─── List profiles ────────────────────────────────────────────────────
list_profiles() {
    echo ""
    echo "Available kernel profiles:"
    echo "─────────────────────────"
    for profile in "${!PROFILES[@]}"; do
        local filename="$(profile_filename "$profile")"
        local installed=""
        # Check all version directories for this profile
        local found_versions=""
        local first_ver=true
        for vdir in "${TINYMACHINE_KERNEL_DIR}"/v*/; do
            [ -d "$vdir" ] || continue
            local ver_name="$(basename "$vdir")"
            ver_name="${ver_name#v}"
            if [ -f "${vdir}${filename}" ]; then
                local size=$(stat -c%s "${vdir}${filename}" 2>/dev/null || echo "0")
                if [ "$first_ver" = true ]; then
                    found_versions="${GREEN}v${ver_name} ($(numfmt --to=iec $size 2>/dev/null || echo "${size}B"))${NC}"
                    first_ver=false
                else
                    found_versions="${found_versions}, ${GREEN}v${ver_name} ($(numfmt --to=iec $size 2>/dev/null || echo "${size}B"))${NC}"
                fi
            fi
        done
        if [ -z "$found_versions" ]; then
            installed="${YELLOW}(not installed)${NC}"
        else
            installed="${found_versions}"
        fi
        printf "  ${BLUE}%-15s${NC} %s\n" "$profile:" "${PROFILES[$profile]}"
        printf "  %-15s %b\n" "" "$installed"
        echo ""
    done
}

# ─── List installed versions ─────────────────────────────────────────
list_versions() {
    echo ""
    echo "Installed kernel versions:"
    echo "─────────────────────────"

    if [ -f "${TINYMACHINE_KERNEL_DIR}/registry.toml" ]; then
        local default_ver
        default_ver=$(grep -oP 'default_version\s*=\s*"\K[^"]*' "${TINYMACHINE_KERNEL_DIR}/registry.toml" 2>/dev/null || echo "")
        echo "  Registry: ${TINYMACHINE_KERNEL_DIR}/registry.toml"
        [ -n "$default_ver" ] && echo "  Default version: ${BLUE}${default_ver}${NC}"
        echo ""
    fi

    local count=0
    for vdir in "${TINYMACHINE_KERNEL_DIR}"/v*/; do
        [ -d "$vdir" ] || continue
        local ver_name="$(basename "$vdir")"
        ver_name="${ver_name#v}"
        local profiles_in_version=""
        local first=true
        for f in "${vdir}"vmlinux-*; do
            [ -f "$f" ] || continue
            local p_name="${f#*vmlinux-}"
            local p_size=$(stat -c%s "$f" 2>/dev/null || echo "0")
            if [ "$first" = true ]; then
                profiles_in_version="${p_name} ($(numfmt --to=iec $p_size 2>/dev/null || echo "${p_size}B"))"
                first=false
            else
                profiles_in_version="${profiles_in_version}, ${p_name} ($(numfmt --to=iec $p_size 2>/dev/null || echo "${p_size}B"))"
            fi
        done
        if [ -n "$profiles_in_version" ]; then
            echo "  ${GREEN}v${ver_name}${NC}: ${profiles_in_version}"
            count=$((count + 1))
        else
            echo "  ${YELLOW}v${ver_name}${NC}: (empty directory)"
            count=$((count + 1))
        fi
    done

    if [ "$count" -eq 0 ]; then
        echo "  ${YELLOW}(no kernel versions installed)${NC}"
        echo ""
        echo "  Build one: ${BLUE}$0 base${NC}"
    fi
    echo ""
}

# ─── Change default version ─────────────────────────────────────────-
set_default_version() {
    local version="$1"

    if [ ! -d "${TINYMACHINE_KERNEL_DIR}/v${version}" ]; then
        err "Version directory not found: ${TINYMACHINE_KERNEL_DIR}/v${version}"
        exit 1
    fi

    # Create or update registry.toml
    local reg_file="${TINYMACHINE_KERNEL_DIR}/registry.toml"

    if [ -f "$reg_file" ]; then
        # Update existing registry
        local tmp_reg=$(mktemp)
        # Replace or add default_version
        if grep -q '^default_version' "$reg_file"; then
            sed "s/^default_version\s*=.*/default_version = \"${version}\"/" "$reg_file" > "$tmp_reg"
        else
            cp "$reg_file" "$tmp_reg"
            echo "default_version = \"${version}\"" >> "$tmp_reg"
        fi
        mv "$tmp_reg" "$reg_file"
    else
        # Create minimal registry
        cat > "$reg_file" << REGEOF
# TinyMachine Kernel Registry
# Managed by build-kernel.sh — do not edit manually
default_version = "${version}"
REGEOF
    fi

    ok "Default kernel version set to ${version}"
}

# ─── Main ─────────────────────────────────────────────────────────────
main() {
    local profile=""
    local version="$LINUX_VERSION"
    local show_list=false
    local set_default=""
    local positional_args=()

    # Parse arguments
    while [ $# -gt 0 ]; do
        case "$1" in
            --list)
                show_list=true
                shift
                ;;
            --version)
                if [ -z "${2:-}" ]; then
                    err "--version requires a version argument (e.g., 7.1.4)"
                    exit 1
                fi
                version="$2"
                shift 2
                ;;
            --default)
                if [ -z "${2:-}" ]; then
                    err "--default requires a version argument (e.g., 7.1.4)"
                    exit 1
                fi
                set_default="$2"
                shift 2
                ;;
            --help | -h)
                echo "Usage: $0 [profile] [options]"
                echo ""
                echo "Build a kernel profile:"
                echo "  $0 base                    # build vmlinux-base (default)"
                echo "  $0 gpu-vfio                # build vmlinux-gpu-vfio"
                echo ""
                echo "Options:"
                echo "  --version VERSION          # kernel version (default: $LINUX_VERSION)"
                echo "  --list                     # show installed versions"
                echo "  --default VERSION          # change default version"
                echo "  --help                     # show this help"
                echo ""
                echo "Profiles: ${!PROFILES[*]}"
                exit 0
                ;;
            --*)
                err "Unknown option: $1"
                exit 1
                ;;
            *)
                positional_args+=("$1")
                shift
                ;;
        esac
    done

    # Handle --list
    if [ "$show_list" = true ]; then
        list_versions
        list_profiles
        exit 0
    fi

    # Handle --default
    if [ -n "$set_default" ]; then
        set_default_version "$set_default"
        exit 0
    fi

    # Get profile from positional args
    profile="${positional_args[0]:-}"

    # Ensure TinyOS kernel directory exists
    mkdir -p "$TINYMACHINE_KERNEL_DIR"

    # List profiles if no argument
    if [ -z "$profile" ]; then
        echo ""
        echo "TinyMachine Kernel Builder v$(grep -oP 'LINUX_VERSION="\K[^"]*' "$0" 2>/dev/null || echo "$LINUX_VERSION")"
        list_versions
        list_profiles
        echo ""
        echo "Usage: $0 [profile] [options]"
        echo "       $0 base --version 7.1.4"
        echo "       $0 --list"
        echo "       $0 --default 7.1.4"
        echo ""
        echo "Profiles: ${!PROFILES[*]}"
        exit 0
    fi

    # Validate profile
    if [ -z "${PROFILES[$profile]:-}" ]; then
        err "Unknown profile: '${profile}'"
        echo "Available: ${!PROFILES[*]}"
        exit 1
    fi

    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║        TinyMachine Kernel Builder — ${profile} (v${version})                ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""

    check_prereqs || exit 1
    download_source "$version" || exit 1
    configure_kernel "$profile" "$version" || exit 1
    build_kernel "$profile" "$version" || exit 1

    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║     ✅ Kernel build complete: ${profile} v${version}              ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""

    ls -lh "${TINYMACHINE_KERNEL_DIR}/v${version}/$(profile_filename "$profile")"
}

main "$@"
