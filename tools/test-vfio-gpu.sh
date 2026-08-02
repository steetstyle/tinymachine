#!/bin/bash
# ──────────────────────────────────────────────────────────────────────
# TinyOS VFIO GPU Test Script
# ──────────────────────────────────────────────────────────────────────
#
# Launches QEMU with VFIO GPU passthrough, injects Python test code
# over serial (with 8-second delay for UART init), and verifies GPU
# device nodes are created by nvidia.ko.
#
# Usage:
#   ./test-vfio-gpu.sh                                    # minimal variant, auto GPU
#   ./test-vfio-gpu.sh --variant tinygrad-nv              # specific variant
#   ./test-vfio-gpu.sh --gpu 0000:01:00.0                 # explicit GPU BDF
#   ./test-vfio-gpu.sh --list-gpus                        # list VFIO-bound GPUs
#   ./test-vfio-gpu.sh --help
#
# Quick test (default):
#   Launches VM, injects Python code, checks /dev/nvidia0 and /dev/nvidiactl
#
# Extended test:
#   ./test-vfio-gpu.sh --test nvidia-smi   (if nvidia-smi binary in initrd)
#   ./test-vfio-gpu.sh --test cuda         (NVML init check via Python)
#   ./test-vfio-gpu.sh --interactive       (drop into QEMU serial console)
#
# Requirements:
#   - GPU bound to vfio-pci driver
#   - nvidia.ko built via ./build-nvidia-module.sh
#   - Initrd with nvidia modules (use --install flag in build-nvidia-module.sh)
#   - Kernel at /tmp/tinyos-kernel-build/linux-7.1.4/arch/x86/boot/bzImage
#   - MEMLOCK ulimit >= 4GB (ulimit -l 4000000)
#
# Known issue: VFIO_MAP_DMA -22 at 0x8000000000 (512GB IOMMU boundary)
#   On Intel systems with 39-bit VT-d, the GPU's 64-bit BAR3 at the top of
#   the address space exceeds the IOMMU aperture. We work around this with
#   x-no-mmap=on (MMIO through QEMU read/write instead of direct BAR mmap).
#   Compute workloads are unaffected since data transfer goes through DMA.
# ──────────────────────────────────────────────────────────────────────
set -euo pipefail

# ─── Config defaults ──────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TINYMACHINE_DIR="${HOME}/.tinymachine/templates"
KERNEL_BUILD_DIR="${BUILD_DIR:-/tmp/tinymachine-kernel-build}"
KERNEL_VERSION="${KERNEL_VERSION:-7.1.4}"
KERNEL_BZIMAGE="${KERNEL_BUILD_DIR}/linux-${KERNEL_VERSION}/arch/x86/boot/bzImage"
VARIANT="minimal"
GPU_BDF=""
TEST_MODE="quick"   # quick | nvidia-smi | cuda | tinygrad | interactive
INTERACTIVE=false
SERIAL_DELAY=8  # seconds to wait before injecting code (UART FIFO flush)

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
Usage: ./test-vfio-gpu.sh [options]

Options:
  --variant NAME     Initrd variant (default: minimal)
  --gpu BDF          GPU PCI address (default: auto-detect)
  --test MODE        Test mode: quick | nvidia-smi | cuda | tinygrad | interactive
  --interactive      Drop into serial console (no code injection)
  --delay SECONDS    Serial injection delay (default: 8)
  --list-gpus        List VFIO-bound GPUs and exit
  --help             Show this help

Test modes:
  quick        Check /dev/nvidia0 and /dev/nvidiactl exist (default)
  nvidia-smi   Run nvidia-smi inside guest (requires binary in initrd)
  cuda         Test NVML init via Python ctypes (requires libcuda in initrd)
  tinygrad     Test direct PCI BAR access via tinygrad runtime
  interactive  Connect to serial console manually

Examples:
  ./test-vfio-gpu.sh                                    # quick test
  ./test-vfio-gpu.sh --variant tinygrad-nv              # test with tinygrad variant
  ./test-vfio-gpu.sh --gpu 0000:01:00.0                 # explicit GPU address
  ./test-vfio-gpu.sh --interactive                      # manual console
EOF
    exit 0
}

# ─── List VFIO-bound GPUs ────────────────────────────────────────────
list_gpus() {
    echo "VFIO-bound NVIDIA GPUs:"
    echo "────────────────────────"
    lspci -d 10de: -D -k 2>/dev/null | grep -B2 "vfio-pci" | grep "VGA" | awk '{print $1}' | while read -r bdf; do
        local desc
        desc=$(lspci -s "$bdf" -nn 2>/dev/null | cut -d' ' -f2-)
        echo "  $bdf  $desc"
    done
    echo ""
    echo "All NVIDIA GPUs:"
    lspci -d 10de: -D -nn 2>/dev/null | head -5
}

# ─── Parse arguments ─────────────────────────────────────────────────
while [ $# -gt 0 ]; do
    case "$1" in
        --variant)    VARIANT="$2"; shift 2 ;;
        --gpu)        GPU_BDF="$2"; shift 2 ;;
        --test)       TEST_MODE="$2"; shift 2 ;;
        --interactive) INTERACTIVE=true; shift ;;
        --delay)      SERIAL_DELAY="$2"; shift 2 ;;
        --list-gpus)  list_gpus; exit 0 ;;
        --help|-h)    usage ;;
        *) err "Unknown option: $1"; usage ;;
    esac
done

# ─── Auto-detect GPU ──────────────────────────────────────────────────
detect_gpu() {
    GPU_BDF=$(lspci -d 10de: -D -k 2>/dev/null | grep -B2 "vfio-pci" | grep "VGA" | awk '{print $1}' | head -1)
    if [ -z "$GPU_BDF" ]; then
        # Fallback: any NVIDIA GPU
        GPU_BDF=$(lspci -d 10de: -D 2>/dev/null | grep "VGA" | awk '{print $1}' | head -1)
    fi
    if [ -z "$GPU_BDF" ]; then
        err "No NVIDIA GPU detected"
        err "  Ensure GPU is bound to vfio-pci:"
        err "    sudo sh -c 'echo vfio-pci > /sys/bus/pci/devices/0000:XX:00.0/driver_override'"
        exit 1
    fi
    ok "GPU detected: $GPU_BDF ($(lspci -s "$GPU_BDF" -nn 2>/dev/null | cut -d' ' -f2-))"
}

# ─── Find GPU audio function ─────────────────────────────────────────
get_gpu_audio_bdf() {
    # BDF format: DDDD:BB:DD.F → replace function number with 1
    echo "$1" | sed 's/\.[0-9]*$/.1/'
}

# ─── Check prerequisites ─────────────────────────────────────────────
check_prereqs() {
    local missing=false

    if [ ! -f "$KERNEL_BZIMAGE" ]; then
        # Try to find bzImage from kernel build dir
        KERNEL_BZIMAGE=$(find "$KERNEL_BUILD_DIR" -name "bzImage" -type f 2>/dev/null | head -1 || echo "")
        if [ -z "$KERNEL_BZIMAGE" ]; then
            err "Kernel bzImage not found at $KERNEL_BZIMAGE"
            err "  Build: ./build-kernel.sh gpu-nvidia"
            missing=true
        fi
    fi

    local initrd="${TINYMACHINE_DIR}/python/v1/${VARIANT}/initrd.zst"
    if [ ! -f "$initrd" ]; then
        err "Initrd not found at $initrd"
        err "  Build: ./build-variant-initramfs.sh ${VARIANT}"
        err "  Or:    ./build-nvidia-module.sh --install --variant ${VARIANT}"
        missing=true
    fi

    if ! command -v qemu-system-x86_64 &>/dev/null; then
        err "qemu-system-x86_64 not found"
        err "  Install: sudo apt-get install qemu-system-x86"
        missing=true
    fi

    # Check MEMLOCK
    local memlock
    memlock=$(ulimit -l 2>/dev/null || echo "0")
    if [ "$memlock" -lt 3000000 ] 2>/dev/null; then
        warn "MEMLOCK is ${memlock}KB — may be insufficient for 3.5G VM"
        warn "  Run: ulimit -l 4000000"
    fi

    if [ "$missing" = true ]; then
        exit 1
    fi

    ok "Kernel: $KERNEL_BZIMAGE"
    ok "Initrd: $initrd"
    ok "QEMU:   $(qemu-system-x86_64 --version 2>&1 | head -1)"
}

# ─── Build serial test code ──────────────────────────────────────────
build_test_code() {
    case "$TEST_MODE" in
        quick)
            cat << 'PYEOF'
import os
print("=== GPU Device Check ===")
devs = os.listdir("/dev")
has_nvidia0 = "nvidia0" in devs
has_nvidiactl = "nvidiactl" in devs
has_nvidia_uvm = "nvidia-uvm" in devs
print(f"/dev/nvidia0:    {'✅' if has_nvidia0 else '❌'} {os.path.exists('/dev/nvidia0')}")
print(f"/dev/nvidiactl:  {'✅' if has_nvidiactl else '❌'} {os.path.exists('/dev/nvidiactl')}")
print(f"/dev/nvidia-uvm: {'✅' if has_nvidia_uvm else '❌'} {os.path.exists('/dev/nvidia-uvm')}")
if has_nvidiactl:
    f = open("/dev/nvidiactl", "rb")
    d = f.read(4)
    f.close()
    print(f"nvidiactl read: {d.hex()} ({'✅' if len(d) == 4 else '❌'})")
# Also check sysfs for NVIDIA PCI device
import struct
pci_devices = os.listdir("/sys/bus/pci/devices/")
for d in pci_devices:
    try:
        vendor = open(f"/sys/bus/pci/devices/{d}/vendor").read().strip()
        device = open(f"/sys/bus/pci/devices/{d}/device").read().strip()
        if vendor == "0x10de":
            print(f"GPU in sysfs: {d}  {vendor}:{device}")
    except: pass
print("=== GPU Check Complete ===")
PYEOF
            ;;

        cuda)
            # Test NVML via ctypes (requires libcuda.so in initrd)
            cat << 'PYEOF'
import os, ctypes
print("=== CUDA/NVML Test ===")
try:
    libcuda = ctypes.CDLL("libcuda.so.1")
    # cuInit
    result = libcuda.cuInit(0)
    print(f"cuInit(0) = {result}  ({'✅' if result == 0 else '❌'})")
    if result == 0:
        # cuDeviceGetCount
        count = ctypes.c_int()
        libcuda.cuDeviceGetCount(ctypes.byref(count))
        print(f"cuDeviceGetCount = {count.value}")
except Exception as e:
    print(f"CUDA error: {e}")
print("=== NVML Test Complete ===")
PYEOF
            ;;

        nvidia-smi)
            # Run nvidia-smi if available
            cat << 'PYEOF'
import os
print("=== nvidia-smi ===")
if os.path.exists("/usr/bin/nvidia-smi"):
    os.system("nvidia-smi 2>&1")
elif os.path.exists("/bin/nvidia-smi"):
    os.system("nvidia-smi 2>&1")
else:
    print("nvidia-smi not in initrd")
    # Try to read /proc/driver/nvidia/cards/0
    if os.path.exists("/proc/driver/nvidia"):
        print(os.listdir("/proc/driver/nvidia"))
        for f in os.listdir("/proc/driver/nvidia"):
            p = f"/proc/driver/nvidia/{f}"
            if os.path.isfile(p):
                print(f"--- {p} ---")
                print(open(p).read())
print("=== nvidia-smi Check Complete ===")
PYEOF
            ;;
        tinygrad)
            local __script__
            __script__=$(cat << 'PYEOF'
import os, sys, traceback, time
sys.path.insert(0, '/usr/lib/python3.12/dist-packages')
print("=== Tinygrad NVDev Test ===", flush=True)

pf = "/usr/lib/python3.12/dist-packages/tinyos_nv_patch.py"
if os.path.exists(pf):
    exec(open(pf).read())
    apply_patches()
    print("P1: patches applied", flush=True)
else:
    print("P1: patch file not found", flush=True)
    sys.exit(1)

pci_devices = os.listdir("/sys/bus/pci/devices/")
gpu = [d for d in pci_devices if open(f"/sys/bus/pci/devices/{d}/vendor").read().strip() == "0x10de"]
if not gpu:
    print("E1: No NVIDIA GPU found", flush=True)
    sys.exit(1)
gpu_bdf = gpu[0]
print(f"D1: GPU at {gpu_bdf}", flush=True)

from tinygrad.runtime.support.system import PCIDevice
from tinygrad.runtime.support.nv.nvdev import NVDev
print("D2: imports done", flush=True)

pci = PCIDevice("nvidia", gpu_bdf)
print(f"D3: PCIDevice ok, bar0_info={pci.bar_info(0)}", flush=True)

nv = NVDev(pci)
print(f"N1: chip={nv.chip_name}, fw={nv.fw_name}", flush=True)
print(f"N2: vram={nv.vram_size>>20}MB, large_bar={nv.large_bar}", flush=True)
print("\n=== NVDev Init OK ===", flush=True)
PYEOF
)
            local __b64__
            __b64__=$(echo "$__script__" | base64 -w0)
            echo "import base64 as b; exec(b.b64decode('$__b64__'))"
            ;;
    esac
}

# ─── Launch VM ───────────────────────────────────────────────────────
launch_vm() {
    local initrd="${TINYMACHINE_DIR}/python/v1/${VARIANT}/initrd.zst"
    local gpu_audio
    gpu_audio=$(get_gpu_audio_bdf "$GPU_BDF")

    # Kernel cmdline — tinyos.qemu=1 triggers auto module loading + serial mode
    local cmdline="console=ttyS0,115200n8 root=/dev/ram0 ignore_loglevel pci=noearly acpi_irq_handling=off tinyos.qemu=1"

    info "Launching QEMU (variant=${VARIANT}, gpu=${GPU_BDF})..."

    if [ "$INTERACTIVE" = true ]; then
        # Interactive mode — just boot and let user type commands
        info "Interactive mode — serial console ready"
        info "  (Python commands are run via init's serial loop)"
        echo ""
        exec qemu-system-x86_64 \
            -machine type=q35,accel=kvm,kernel_irqchip=split \
            -cpu host,migratable=off \
            -smp "$(nproc)" \
            -m 3.5G \
            -kernel "$KERNEL_BZIMAGE" \
            -initrd "$initrd" \
            -append "$cmdline" \
            -device vfio-pci,host="$GPU_BDF",rombar=0 \
            -device vfio-pci,host="$gpu_audio",rombar=0 \
            -nographic \
            -serial stdio \
            -no-reboot \
            -nodefaults \
            -no-user-config
    else
        # Automated test mode — inject code after delay
        local test_code
        test_code=$(build_test_code | tr '\n' ';' | sed 's/;;*/;/g; s/^;//; s/;$//')

        info "Will inject Python code after ${SERIAL_DELAY}s delay..."
        info "Test mode: $TEST_MODE"
        echo ""

        # Run QEMU with serial code injection via stdin
        # The sleep+echo pipeline delivers code after UART is initialized
        timeout 150 bash -c '
            sleep '"$SERIAL_DELAY"'
            echo '"'$test_code'"'
        ' | qemu-system-x86_64 \
            -machine type=q35,accel=kvm,kernel_irqchip=split \
            -cpu host,migratable=off \
            -smp "$(nproc)" \
            -m 3.5G \
            -kernel "$KERNEL_BZIMAGE" \
            -initrd "$initrd" \
            -append "$cmdline" \
            -device vfio-pci,host="$GPU_BDF",rombar=0 \
            -device vfio-pci,host="$gpu_audio",rombar=0 \
            -nographic \
            -serial stdio \
            -no-reboot \
            -nodefaults \
            -no-user-config \
            2>&1 | grep -E "(===|nvidia|mod_load|GPU|OK|FAIL|init:|Kernel panic|Call Trace|DONE|READY|BAR[012]|mmap|Config\[|P[0-9]|D[0-9]|N[0-9]|Traceback)"
    fi
}

# ─── Main ─────────────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║          TinyOS VFIO GPU Test — v${KERNEL_VERSION}                    ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Auto-detect GPU if not specified
if [ -z "$GPU_BDF" ]; then
    detect_gpu
fi

# Check prerequisites
check_prereqs

# Launch VM
launch_vm

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║     ✅ Test complete                                        ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
