#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────
# vfio-gpu.sh — VFIO GPU passthrough: setup + launch
# ─────────────────────────────────────────────────────────────────────────
# Tek script, iki mod:
#
#   sudo ./tools/vfio-gpu.sh setup      # VFIO bağla (reboot sonrası 1 kere)
#   sudo ./tools/vfio-gpu.sh launch     # QEMU başlat + Python test
#   sudo ./tools/vfio-gpu.sh reset      # Eski driver'a dön
#
# Çözdüğü sorunlar:
#   1. VFIO_MAP_DMA -22 → pci-hole64-size=64G
#   2. Xid 154 GPU timeout → x-no-mmap=on kaldırıldı
#   3. group not viable → audio fonksiyonu da vfio-pci'ye bağlandı
# ─────────────────────────────────────────────────────────────────────────
set -euo pipefail

GPU_BDF="0000:01:00.0"
AUDIO_BDF="0000:01:00.1"
TINYMACHINE_DIR="${HOME}/.tinymachine/templates"
KERNEL="${TINYMACHINE_DIR}/kernel/v7.1.4/bzImage-gpu-nvidia"
INITRD="${TINYMACHINE_DIR}/python/v1/minimal/initrd.zst"
SERIAL_DELAY=10

# ─── Renkler ──────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; NC='\033[0m'
ok()   { echo -e "${GREEN}*${NC} $1"; }
warn() { echo -e "${YELLOW}*${NC} $1"; }
err()  { echo -e "${RED}*${NC} $1" >&2; }
info() { echo -e "${BLUE}*${NC} $1"; }

# ─── setup ────────────────────────────────────────────────────────────
cmd_setup() {
    echo ""
    echo "╔══════════════════════════════════════════════════╗"
    echo "║   VFIO GPU Passthrough — Setup                  ║"
    echo "╚══════════════════════════════════════════════════╝"
    echo ""

    if [ "$(id -u)" -ne 0 ]; then
        err "sudo ile çalıştır."
        exit 1
    fi

    info "[1] VFIO modülleri yükleniyor..."
    modprobe vfio-pci 2>/dev/null || { err "vfio-pci yüklenemedi"; exit 1; }
    ok "vfio-pci yüklendi"

    info "[2] GPU (VGA) bağlanıyor: $GPU_BDF"
    DRV=$(basename "$(readlink "/sys/bus/pci/devices/$GPU_BDF/driver" 2>/dev/null)" 2>/dev/null || echo "yok")
    if [ "$DRV" != "vfio-pci" ]; then
        echo "vfio-pci" > "/sys/bus/pci/devices/$GPU_BDF/driver_override"
        echo "$GPU_BDF" > "/sys/bus/pci/drivers/vfio-pci/bind" 2>/dev/null || true
    fi
    sleep 0.3
    DRV=$(basename "$(readlink "/sys/bus/pci/devices/$GPU_BDF/driver" 2>/dev/null)" 2>/dev/null || echo "yok")
    [ "$DRV" = "vfio-pci" ] && ok "  GPU → vfio-pci" || err "  GPU hâlâ $DRV"

    info "[3] Audio bağlanıyor: $AUDIO_BDF"
    DRV=$(basename "$(readlink "/sys/bus/pci/devices/$AUDIO_BDF/driver" 2>/dev/null)" 2>/dev/null || echo "yok")
    if [ "$DRV" != "vfio-pci" ]; then
        [ "$DRV" != "yok" ] && echo "$AUDIO_BDF" > "/sys/bus/pci/devices/$AUDIO_BDF/driver/unbind" 2>/dev/null || true
        echo "vfio-pci" > "/sys/bus/pci/devices/$AUDIO_BDF/driver_override"
        echo "$AUDIO_BDF" > "/sys/bus/pci/drivers/vfio-pci/bind" 2>/dev/null || true
    fi
    sleep 0.3
    DRV=$(basename "$(readlink "/sys/bus/pci/devices/$AUDIO_BDF/driver" 2>/dev/null)" 2>/dev/null || echo "yok")
    [ "$DRV" = "vfio-pci" ] && ok "  Audio → vfio-pci" || err "  Audio hâlâ $DRV"

    info "[4] IOMMU grubu kontrolü..."
    GROUP=$(basename "$(readlink -f "/sys/bus/pci/devices/$GPU_BDF/iommu_group" 2>/dev/null)" 2>/dev/null || echo "?")
    ok "IOMMU group $GROUP"
    for d in /sys/kernel/iommu_groups/"$GROUP"/devices/*; do
        bdf=$(basename "$d")
        drv=$(basename "$(readlink "$d/driver" 2>/dev/null)" 2>/dev/null || echo "NONE")
        echo "    $bdf  →  $drv"
    done

    if [ -e "/dev/vfio/$GROUP" ]; then
        ok "VFIO device node: /dev/vfio/$GROUP"
    else
        err "/dev/vfio/$GROUP yok — modprobe sonrası udev bekle"
    fi

    MEMLOCK=$(ulimit -l)
    if [ "$MEMLOCK" -lt 3000000 ]; then
        warn "MEMLOCK = ${MEMLOCK}KB (az). ulimit -l 4000000 yap."
    fi

    echo ""
    ok "Setup tamam. 'launch' ile QEMU başlat."
    echo ""
}

# ─── launch ───────────────────────────────────────────────────────────
cmd_launch() {
    echo ""
    echo "╔══════════════════════════════════════════════════╗"
    echo "║   VFIO GPU Passthrough — QEMU Launch            ║"
    echo "╚══════════════════════════════════════════════════╝"
    echo ""

    # Dosyaları kontrol et
    [ -f "$KERNEL" ] || { err "Kernel yok: $KERNEL"; exit 1; }
    [ -f "$INITRD" ] || { err "Initrd yok: $INITRD"; exit 1; }
    ok "Kernel: $KERNEL"
    ok "Initrd: $INITRD"

    # pci-hole64-size ile 64-bit MMIO penceresi 64 GB'a indirilir.
    # Böylece GPU BAR'ları 512 GB sınırının altında kalır.
    # x-no-mmap=on KULLANILMAZ — direkt BAR mmap hızlıdır.
    QEMU_EXTRA="-global q35-pcihost.pci-hole64-size=64G"

    mkdir -p /tmp/vfio-gpu
    local LOG="/tmp/vfio-gpu/launch-$(date +%s).log"

    # Python kodu — dumped onto the serial console after READY
    PYCODE="exec(open('/root/test_cuda.py').read())"

    timeout $((SERIAL_DELAY + 35)) bash -c '
        sleep '"$SERIAL_DELAY"'
        echo "'"$PYCODE"'"
    ' | timeout $((SERIAL_DELAY + 40)) qemu-system-x86_64 \
        -machine type=q35,accel=kvm \
        -cpu host,migratable=off \
        -smp "$(nproc)" \
        -m 3.5G \
        -kernel "$KERNEL" \
        -initrd "$INITRD" \
        -append "console=ttyS0,115200n8 root=/dev/ram0 tinyos.qemu=1 loglevel=8 CP_BEFORE_RUN_PYTHON=/root/test_cuda.py" \
        $QEMU_EXTRA \
        -device vfio-pci,host="$GPU_BDF",rombar=0 \
        -device vfio-pci,host="$AUDIO_BDF",rombar=0 \
        -nographic -display none -serial stdio \
        -no-reboot -nodefaults -no-user-config \
        2>&1 | tee "$LOG"

    echo ""
    ok "Log: $LOG"
    echo ""
}

# ─── reset ────────────────────────────────────────────────────────────
cmd_reset() {
    echo ""
    info "Cihazlar varsayılan driver'a döndürülüyor..."

    # Audio → snd_hda_intel
    if [ -d "/sys/bus/pci/devices/$AUDIO_BDF" ]; then
        echo "$AUDIO_BDF" > "/sys/bus/pci/devices/$AUDIO_BDF/driver/unbind" 2>/dev/null || true
        echo "" > "/sys/bus/pci/devices/$AUDIO_BDF/driver_override" 2>/dev/null || true
        echo "$AUDIO_BDF" > "/sys/bus/pci/drivers/snd_hda_intel/bind" 2>/dev/null || true
        ok "Audio → snd_hda_intel"
    fi

    # GPU → nvidia (veya boşta bırak)
    if [ -d "/sys/bus/pci/devices/$GPU_BDF" ]; then
        echo "$GPU_BDF" > "/sys/bus/pci/devices/$GPU_BDF/driver/unbind" 2>/dev/null || true
        echo "" > "/sys/bus/pci/devices/$GPU_BDF/driver_override" 2>/dev/null || true
        ok "GPU varsayılana döndü"
    fi

    ok "Reset tamam."
}

# ─── main ─────────────────────────────────────────────────────────────
case "${1:-help}" in
    setup)   cmd_setup ;;
    launch)  cmd_launch ;;
    reset)   cmd_reset ;;
    *)
        echo "Kullanım: sudo ./tools/vfio-gpu.sh {setup|launch|reset}"
        echo ""
        echo "  setup   — VFIO modülleri yükle, GPU+Audio bağla"
        echo "  launch  — QEMU başlat, GPU test et"
        echo "  reset   — Eski driver'lara dön"
        ;;
esac
