#!/bin/bash
# TinyOS VM Launcher — QEMU with VFIO GPU + virtio + proper MSI routing
#
# Usage:
#   ./run-vm.sh <variant> [gpu-pci-address]
#
# Variants: minimal, tinygrad, tinygrad-nv, pytorch
#
# Examples:
#   ./run-vm.sh tinygrad-nv                    # auto-detect NVIDIA GPU
#   ./run-vm.sh minimal                         # CPU-only, no GPU
#   ./run-vm.sh tinygrad-nv 0000:01:00.0       # explicit GPU address
#
# Kernel cmdline (MSI-enabled):
#   pci=noearly            ← Skip early PCI probe (prevents SMI hang)
#   acpi_irq_handling=off  ← Don't let ACPI touch GPU IRQs
#   (NO pci=nomsi — MSI enabled for virtio-net/virtio-blk performance)
#
# QEMU MSI routing:
#   kernel_irqchip=split   ← KVM handles VFIO MSI, QEMU handles legacy IRQs
#   x-msix-relocation      ← Relocate MSI-X table for GPU VFIO compatibility
#
set -euo pipefail

# ── Config ──
# Always use /home/roy path (sudo changes HOME to /root)
TINYOS_DIR="/home/roy/.tinyos/templates"
KERNEL_DIR="${TINYOS_DIR}/kernel"
VARIANT="${1:-tinygrad-nv}"
GPU_BDF="${2:-}"

# Validate variant
case "$VARIANT" in
    minimal|tinygrad|tinygrad-nv|pytorch) ;;
    *) echo "Usage: $0 {minimal|tinygrad|tinygrad-nv|pytorch} [gpu-pci-address]"
       exit 1 ;;
esac

# ── Find kernel + initrd ──
# Use bzImage (not vmlinux) — QEMU -kernel needs bzImage format
VMLINUX="${KERNEL_DIR}/bzImage-gpu-nvidia"
INITRD="${TINYOS_DIR}/python/v1/${VARIANT}/initrd.zst"

if [ ! -f "$VMLINUX" ]; then
    echo "ERROR: Kernel not found at $VMLINUX"
    echo "  Build: ./build-kernel.sh gpu-nvidia"
    exit 1
fi

if [ ! -f "$INITRD" ]; then
    echo "ERROR: Initrd not found at $INITRD"
    echo "  Build: ./build-variant-initramfs.sh $VARIANT"
    exit 1
fi

# ── Auto-detect NVIDIA GPU PCI address ──
if [ -z "$GPU_BDF" ] && [ "$VARIANT" != "minimal" ]; then
    # Try to find a VFIO-bound NVIDIA GPU (driver in use = vfio-pci)
    # lspci -D -k shows kernel driver on a separate line; use -B1 to get the BDF line
    GPU_BDF=$(lspci -d 10de: -D -k 2>/dev/null | grep -B2 "vfio-pci" | grep "VGA" | awk '{print $1}' | head -1)
    if [ -z "$GPU_BDF" ]; then
        # Fallback: any NVIDIA GPU not using nvidia driver
        GPU_BDF=$(lspci -d 10de: -D -k 2>/dev/null | grep -B1 "Kernel driver in use:" | grep -v "nvidia" | grep "NVIDIA" | awk '{print $1}' | head -1)
    fi
    if [ -z "$GPU_BDF" ]; then
        echo "ERROR: No NVIDIA GPU found for VFIO passthrough"
        echo "  Ensure the GPU is bound to vfio-pci:"
        echo "    sudo sh -c 'echo vfio-pci > /sys/bus/pci/devices/0000:XX:00.0/driver_override'"
        exit 1
    fi
    echo "Detected GPU: $GPU_BDF"
fi

# ── Kernel cmdline (MSI enabled) ──
CMDLINE="pci=noearly acpi_irq_handling=off console=ttyS0 tinyos.qemu=1"

if [ "$VARIANT" = "minimal" ]; then
    CMDLINE="$CMDLINE console=ttyS0"
fi

# ── QEMU arguments ──
QEMU_ARGS=(
    -machine q35,accel=kvm,kernel_irqchip=split
    -cpu host,kvm=on
    -smp "$(nproc)"
    -m 3G
    -kernel "$VMLINUX"
    -initrd "$INITRD"
    -append "$CMDLINE"
    -nographic
)

# ── VFIO GPU passthrough (skipped for 'minimal') ──
if [ "$VARIANT" != "minimal" ] && [ -n "$GPU_BDF" ]; then
    # GPU function
    QEMU_ARGS+=(-device vfio-pci,host="$GPU_BDF",x-msix-relocation=bar2)

    # GPU audio function (same device, function 1)
    GPU_DOM=$(echo "$GPU_BDF" | cut -d: -f1)
    GPU_BUS=$(echo "$GPU_BDF" | cut -d: -f2)
    GPU_FUNC=$(echo "$GPU_BDF" | cut -d. -f2)
    GPU_AUDIO="${GPU_DOM}:${GPU_BUS}:${GPU_FUNC%.*}.1"
    if lspci -s "$GPU_AUDIO" &>/dev/null 2>&1; then
        QEMU_ARGS+=(-device vfio-pci,host="$GPU_AUDIO")
    fi
fi

# ── VirtIO devices (MSI-X enabled, uses kernel_irqchip for routing) ──
# Network
QEMU_ARGS+=(
    -netdev user,id=net0
    -device virtio-net-pci,netdev=net0
)

# Storage (if disk image exists)
DISK_IMG="${TINYOS_DIR}/disk.img"
if [ -f "$DISK_IMG" ]; then
    QEMU_ARGS+=(
        -drive file="$DISK_IMG",if=virtio,format=raw
    )
fi

# ── Launch ──
echo "=== TinyOS VM ==="
echo "Variant:     $VARIANT"
echo "Kernel:      $VMLINUX"
echo "Initrd:      $INITRD"
echo "GPU:         ${GPU_BDF:-none}"
echo "Cmdline:     $CMDLINE"
echo "MSI routing: kernel_irqchip=split + msix=on"
echo "=================="
echo ""

exec qemu-system-x86_64 "${QEMU_ARGS[@]}"
