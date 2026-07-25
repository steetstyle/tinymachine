#!/bin/bash
# test-tgrad-final.sh — INTERACTIVE QEMU+VFIO test with code injection
#
# Tests KVM QEMU + VFIO GPU passthrough end-to-end:
# 1. Checks dma_mask_bits >= 64 (kernel BZ 217237 fix)
# 2. Checks RLIMIT_MEMLOCK is sufficient
# 3. Boots QEMU with KVM + VFIO + VBIOS romfile
# 4. Waits for READY from guest init.c
# 5. Injects Python code via FIFO
# 6. Waits for result
#
# No TCG fallback — if KVM VFIO fails, the error is reported clearly.
#
# Root cause of VFIO_MAP_DMA failures:
#   dma_mask_bits=32: Kernel pci_alloc_dev() sets 32-bit default.
#     VFIO inherits this and rejects DMA >4GB → ENOMEM.
#     Fix: sudo insmod tools/tinyos-dma-fix/tinyos_dma_fix.ko
#   RLIMIT_MEMLOCK: VFIO needs memory pinning permission.
#     Fix: ulimit -l unlimited (or sudo)
#
# Run: sudo bash test-tgrad-final.sh
set -euo pipefail

KERNEL="/home/roy/.tinymachine/templates/kernel/bzImage-gpu-nvidia"
INITRD="/home/roy/.tinymachine/templates/python/v1/minimal/initrd.zst"
VBIOS="/home/roy/.tinymachine/vbios/Asus.RTX4080Mobile.12288.221219.rom"
DMA_FIX_KO="/home/roy/github-projects/tinymachine/tools/tinyos-dma-fix/tinymachine_dma_fix.ko"
CMDLINE="console=ttyS0 tinyos.qemu=1"
LOG="/tmp/tgrad-final.log"
FIFO="/tmp/tgrad-final-in"

trap "pkill -9 qemu-system-x86_64 2>/dev/null; rm -f $FIFO $LOG" EXIT
rm -f "$FIFO" "$LOG"
mkfifo "$FIFO"

echo "=== GPU Diagnostics ==="
BDF="0000:01:00.0"
DMA_MASK=$(cat /sys/bus/pci/devices/$BDF/dma_mask_bits 2>/dev/null || echo "N/A")
DRIVER=$(basename $(readlink /sys/bus/pci/devices/$BDF/driver 2>/dev/null) 2>/dev/null || echo "none")
echo "Device:      $BDF"
echo "dma_mask:    ${DMA_MASK}bit"
echo "Driver:      $DRIVER"
echo ""

# ── Fix 1: dma_mask_bits must be >= 64 for VFIO IOMMU mappings ──
if [ "$DMA_MASK" != "64" ] && [ "$DMA_MASK" != "N/A" ]; then
    echo "⚠️  dma_mask_bits=$DMA_MASK — VFIO will reject DMA >4GB!"
    echo "   Loading tinymachine_dma_fix.ko to set dma_mask=64..."
    if [ -f "$DMA_FIX_KO" ]; then
        sudo insmod "$DMA_FIX_KO" domain=0 bus=1 slot=0 func=0 verbose=1 || {
            echo "❌ Failed to load DMA fix module."
            echo "   Check Secure Boot: the module must be signed."
            echo "   $ /lib/modules/$(uname -r)/build/scripts/sign-file \\"
            echo "       sha512 /var/lib/shim-signed/mok/MOK.priv \\"
            echo "       /var/lib/shim-signed/mok/MOK.der $DMA_FIX_KO"
            exit 1
        }
        echo "   ✅ Module loaded. Verifying..."
        sleep 1
        NEW_MASK=$(cat /sys/bus/pci/devices/$BDF/dma_mask_bits 2>/dev/null || echo "N/A")
        if [ "$NEW_MASK" != "64" ]; then
            echo "   ⚠️  dma_mask still $NEW_MASK — rebinding vfio-pci..."
            echo "$BDF" | sudo tee /sys/bus/pci/drivers/vfio-pci/unbind 2>/dev/null || true
            sleep 0.5
            echo "$BDF" | sudo tee /sys/bus/pci/drivers/vfio-pci/bind 2>/dev/null || true
            sleep 1
            NEW_MASK=$(cat /sys/bus/pci/devices/$BDF/dma_mask_bits 2>/dev/null || echo "N/A")
        fi
        if [ "$NEW_MASK" != "64" ]; then
            echo "❌ Could not set dma_mask_bits to 64. Aborting."
            echo "   Run: sudo dmesg | grep tinymachine-dma-fix"
            exit 1
        fi
        echo "   ✅ dma_mask_bits now ${NEW_MASK}bit"
    else
        echo "❌ DMA fix module not found at $DMA_FIX_KO"
        echo "   Build it: cd tools/tinymachine-dma-fix && make"
        exit 1
    fi
fi

# ── Fix 2: Ensure sufficient RLIMIT_MEMLOCK ──
MEMLOCK=$(ulimit -l)
echo "RLIMIT_MEMLOCK: $MEMLOCK KB"
if [ "$MEMLOCK" != "unlimited" ] && [ "$MEMLOCK" -lt 4194304 ]; then
    echo "⚠️  Memlock too low for 4GB VM. Attempting raise..."
    ulimit -l unlimited 2>/dev/null || {
        echo "   Could not raise memlock (need root). Set it manually:"
        echo "   $ ulimit -l unlimited"
        echo "   Or add to /etc/security/limits.conf:"
        echo "   * soft memlock unlimited"
        echo "   * hard memlock unlimited"
    }
fi
echo ""

echo "=== Boot QEMU (background) ==="
cat "$FIFO" | \
qemu-system-x86_64 \
    -machine q35,accel=kvm,kernel_irqchip=split \
    -cpu host,kvm=on -smp 16 -m 4G -no-reboot \
    -nographic -nodefaults -serial stdio -display none \
    -kernel "$KERNEL" -initrd "$INITRD" -append "$CMDLINE" \
    -device "vfio-pci,host=0000:01:00.0,x-no-mmap=on,romfile=$VBIOS" \
    -device "vfio-pci,host=0000:01:00.1,x-no-mmap=on" \
    -netdev user,id=net0 -device virtio-net-pci,netdev=net0 \
    -vga none 2>&1 | stdbuf -oL tee "$LOG" &

QEMU_PID=$!
echo "QEMU PID: $QEMU_PID"

echo ""
echo "=== Waiting for READY (polling up to 30s) ==="
READY=0
for i in $(seq 1 30); do
    sleep 1
    if grep -q "READY" "$LOG" 2>/dev/null; then
        echo "✅ Got READY at ${i}s!"
        READY=$i
        break
    fi
    if ! kill -0 $QEMU_PID 2>/dev/null; then
        echo "QEMU died at ${i}s"
        wait $QEMU_PID 2>/dev/null || true
        break
    fi
done

if [ $READY -eq 0 ]; then
    echo ""
    echo "========== NO READY =========="
    if [ -s "$LOG" ]; then
        grep -i "vfio\|dma_map\|Cannot allocate\|Invalid argument" "$LOG" | head -10 || echo "(no VFIO errors)"
        echo "--- Last 15 lines ---"
        tail -15 "$LOG"
    else
        echo "(empty log — QEMU may have failed at startup)"
    fi
    kill $QEMU_PID 2>/dev/null || true
    exit 1
fi

echo ""
echo "=== Sending Python code ==="
CODE='import sys; print("=== HELLO FROM GUEST ===", sys.version)'
echo "Code: $CODE"
echo "$CODE" > "$FIFO"
echo ""

echo "=== Waiting for result (up to 15s) ==="
RESULT=0
for i in $(seq 1 15); do
    sleep 1
    if grep -q "=== HELLO FROM GUEST ===" "$LOG" 2>/dev/null; then
        echo "✅ Got result at ${i}s!"
        RESULT=$i
        break
    fi
    if ! kill -0 $QEMU_PID 2>/dev/null; then
        break
    fi
done

echo ""
echo "========== RESULT =========="
if grep -q "=== HELLO FROM GUEST ===" "$LOG" 2>/dev/null; then
    echo "✅ GUEST EXECUTION WORKS! "
    echo ""
    grep -B3 -A3 "HELLO FROM GUEST" "$LOG"
    echo ""
    echo "--- Full log ---"
    cat "$LOG"
elif grep -q "READY" "$LOG" 2>/dev/null; then
    echo "⚠️ Booted (READY) but code didn't execute"
    tail -15 "$LOG"
else
    echo "❌ Failed"
    cat "$LOG"
fi

kill $QEMU_PID 2>/dev/null || true
echo ""
echo "Log: $LOG"
