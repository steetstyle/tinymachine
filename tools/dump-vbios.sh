#!/bin/bash
# Dump NVIDIA GPU VBIOS Option ROM via VFIO device cdev + iommufd.
#
# Usage: ./tools/dump-vbios.sh [BDF] [output.rom]
#   BDF        — PCI BDF of the GPU (default: 0000:01:00.0)
#   output.rom — output ROM file (default: tools/vbios/<vendor_device>.rom)
#
# The dumped ROM is also copied to ~/.tinymachine/vbios/<vendor_device>.rom
# for FreshBootBackend VBIOS POST.
#
# Requires: gcc (on-the-fly compilation of ioctl helper)
#           /dev/vfio/devices/vfio* and /dev/iommu accessible
#
# How it works:
#   1. Find the VFIO device cdev for the GPU (bound to vfio-pci)
#   2. Open /dev/iommu and bind the device to iommufd
#   3. Query VFIO ROM region info → read via pread
#   4. Verify 0xAA55 signature, parse PCIR header, save to file
set -euo pipefail

# ── Config ──
BDF="${1:-0000:01:00.0}"
OUTPUT="${2:-}"
TOOLS_DIR="$(cd "$(dirname "$0")" && pwd)"

# ── Find VFIO device cdev ──
DEV_CDEV=""
for cdev in /dev/vfio/devices/vfio*; do
    [ -c "$cdev" ] || continue
    DEV_PATH=$(cat "/sys/bus/pci/devices/${BDF}/vfio-dev/vfio0/dev" 2>/dev/null || true)
    if [ -z "$DEV_PATH" ]; then
        # Try to match by looking at the sysfs device link
        CDEV_NUM=$(echo "$cdev" | grep -oP '\d+$' || echo "")
        [ -n "$CDEV_NUM" ] || continue
        # Check if this cdev matches our BDF
        MATCH=$(readlink -f "/sys/class/vfio-dev/vfio${CDEV_NUM}/device" 2>/dev/null || echo "")
        if echo "$MATCH" | grep -q "$BDF$"; then
            DEV_CDEV="$cdev"
            break
        fi
    else
        MAJ=$(echo "$DEV_PATH" | cut -d: -f1)
        MIN=$(echo "$DEV_PATH" | cut -d: -f2)
        # /dev/vfio/devices/vfio{minor}
        OUR_CDEV="/dev/vfio/devices/vfio${MIN}"
        if [ -c "$OUR_CDEV" ]; then
            DEV_CDEV="$OUR_CDEV"
            break
        fi
    fi
done

if [ -z "$DEV_CDEV" ]; then
    echo "ERROR: Cannot find VFIO device cdev for BDF=$BDF"
    echo "  Make sure the GPU is bound to vfio-pci:"
    echo "    lspci -s $BDF -v | grep 'Kernel driver in use'"
    echo "  and VFIO device cdev is enabled:"
    echo "    ls /dev/vfio/devices/"
    exit 1
fi
echo "Using VFIO cdev: $DEV_CDEV for $BDF"

# ── Check /dev/iommu ──
if [ ! -c /dev/iommu ]; then
    echo "ERROR: /dev/iommu not found (requires CONFIG_IOMMUFD)"
    exit 1
fi

# ── Get vendor:device from lspci ──
LSPCI=$(lspci -n -s "$BDF" 2>/dev/null || echo "")
VENDOR_DEV=$(echo "$LSPCI" | grep -oP '(?<=: )[0-9a-f]{4}:[0-9a-f]{4}' | head -1 || echo "10de:0000")
VENDOR_DEV="${VENDOR_DEV//:/_}"
echo "GPU vendor:device: $VENDOR_DEV"

# ── Determine output path ──
if [ -z "$OUTPUT" ]; then
    OUTPUT="$TOOLS_DIR/vbios/${VENDOR_DEV}.rom"
fi
mkdir -p "$(dirname "$OUTPUT")" "$HOME/.tinymachine/vbios"

# ── Check if we already have a valid ROM ──
if [ -f "$OUTPUT" ] && [ -s "$OUTPUT" ]; then
    SIG=$(hexdump -n 2 -v -e '2/1 "%02x"' "$OUTPUT" 2>/dev/null || echo "")
    if [ "$SIG" = "55aa" ] || [ "$SIG" = "aa55" ]; then
        SIZE=$(stat -c%s "$OUTPUT")
        echo "VBIOS ROM already exists at: $OUTPUT ($SIZE bytes, sig=0x$SIG)"
        echo "Use: rm -f '$OUTPUT' to re-dump"
        exit 0
    fi
fi

# ── Build the ioctl helper C program ──
CACHE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/tinymachine"
mkdir -p "$CACHE_DIR"
HELPER="$CACHE_DIR/dump-vbios-helper"

# Only rebuild if source changed
cat > "$CACHE_DIR/dump-vbios-helper.c" << 'CCODE'
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <linux/vfio.h>

int main(int argc, char *argv[]) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <cdev_path> <iommu_path> <output_path>\n", argv[0]);
        return 1;
    }
    const char *cdev_path = argv[1];
    const char *iommu_path = argv[2];
    const char *output_path = argv[3];

    // Open iommufd
    int iommufd = open(iommu_path, O_RDWR);
    if (iommufd < 0) { perror("open iommufd"); return 1; }

    // Open VFIO device cdev
    int dev_fd = open(cdev_path, O_RDWR);
    if (dev_fd < 0) { perror("open cdev"); close(iommufd); return 1; }

    // Bind device to iommufd
    struct vfio_device_bind_iommufd bind = {
        .argsz = sizeof(bind),
        .flags = 0,
        .iommufd = iommufd,
    };
    int ret = ioctl(dev_fd, VFIO_DEVICE_BIND_IOMMUFD, &bind);
    if (ret < 0) { perror("BIND_IOMMUFD"); close(dev_fd); close(iommufd); return 1; }

    // Get device info
    struct vfio_device_info di = {.argsz = sizeof(di)};
    ret = ioctl(dev_fd, VFIO_DEVICE_GET_INFO, &di);
    if (ret < 0) { perror("GET_INFO"); close(dev_fd); close(iommufd); return 1; }
    fprintf(stderr, "Device: %u regions, %u irqs\n", di.num_regions, di.num_irqs);

    // Get ROM region info (index 6)
    struct vfio_region_info ri = {.argsz = sizeof(ri), .index = 6};
    ret = ioctl(dev_fd, VFIO_DEVICE_GET_REGION_INFO, &ri);
    if (ret < 0) {
        perror("ROM REGION_INFO");
        fprintf(stderr, "ROM region not available. "
                "Run 'lspci -s <bdf> -vv' and check for 'Expansion ROM'\n");
        close(dev_fd);
        close(iommufd);
        return 1;
    }

    fprintf(stderr, "ROM region: size=%lu (0x%lx), offset=0x%lx\n",
            (unsigned long)ri.size, (unsigned long)ri.size,
            (unsigned long)ri.offset);

    if (ri.size == 0) {
        fprintf(stderr, "ERROR: ROM region size is 0\n");
        close(dev_fd);
        close(iommufd);
        return 1;
    }

    // Read ROM via pread
    unsigned char *buf = malloc(ri.size);
    if (!buf) { perror("malloc"); close(dev_fd); close(iommufd); return 1; }

    ssize_t n = pread(dev_fd, buf, ri.size, ri.offset);
    if (n <= 0) { perror("pread ROM"); free(buf); close(dev_fd); close(iommufd); return 1; }

    // Verify PCI Option ROM signature
    unsigned short sig = *(unsigned short *)buf;
    fprintf(stderr, "ROM signature: 0x%04x (%s)\n",
            sig, sig == 0xAA55 ? "VALID" : "INVALID");

    if (sig != 0xAA55) {
        // Dump first few bytes for debugging
        fprintf(stderr, "First 16 bytes:");
        for (int i = 0; i < 16 && i < n; i++)
            fprintf(stderr, " %02x", buf[i]);
        fprintf(stderr, "\n");
        free(buf);
        close(dev_fd);
        close(iommufd);
        return 1;
    }

    // Parse PCIR header to determine total ROM size (including all images)
    unsigned short pcir_off = *(unsigned short *)(buf + 0x18);
    unsigned int total_size = 0;
    unsigned int img_start = 0;

    while (img_start < (unsigned int)n) {
        unsigned short img_sig = *(unsigned short *)(buf + img_start);
        if (img_sig != 0xAA55) break;

        if (img_start + pcir_off + 0x12 > (unsigned int)n) break;
        unsigned int p_off = (unsigned int)pcir_off;
        unsigned short img_blocks = *(unsigned short *)(buf + img_start + p_off + 0x10);
        unsigned int img_size = img_blocks * 512;
        unsigned char last = (buf[img_start + p_off + 0x15] >> 7) & 1;

        fprintf(stderr, "  Image at 0x%06x: %u blocks = %u bytes%s\n",
                img_start, img_blocks, img_size, last ? " [LAST]" : "");

        total_size = img_start + img_size;
        if (last) break;
        img_start += img_size;
    }

    if (total_size == 0) total_size = n;
    if (total_size > (unsigned int)n) total_size = n;

    // Write to output file
    FILE *f = fopen(output_path, "wb");
    if (!f) { perror("fopen output"); free(buf); close(dev_fd); close(iommufd); return 1; }
    size_t written = fwrite(buf, 1, total_size, f);
    fclose(f);

    fprintf(stderr, "Saved %zu bytes to %s\n", written, output_path);

    free(buf);
    close(dev_fd);
    close(iommufd);
    return 0;
}
CCODE

if [ ! -x "$HELPER" ] || [ "$CACHE_DIR/dump-vbios-helper.c" -nt "$HELPER" ]; then
    echo "Compiling helper..."
    gcc -O2 -o "$HELPER" "$CACHE_DIR/dump-vbios-helper.c" -std=c11
    echo "Compiled: $HELPER"
fi

# ── Run the helper ──
echo "Dumping VBIOS ROM..."
"$HELPER" "$DEV_CDEV" "/dev/iommu" "$OUTPUT"

# ── Verify and copy ──
if [ -f "$OUTPUT" ] && [ -s "$OUTPUT" ]; then
    SIG=$(hexdump -n 2 -v -e '2/1 "%02x"' "$OUTPUT" 2>/dev/null || echo "")
    SIZE=$(stat -c%s "$OUTPUT")
    echo ""
    echo "=== VBIOS ROM dumped successfully ==="
    echo "  Path:  $OUTPUT"
    echo "  Size:  $SIZE bytes"
    echo "  Sig:   0x$SIG"

    # Copy to ~/.tinymachine/vbios/
    DEST_DIR="$HOME/.tinymachine/vbios"
    mkdir -p "$DEST_DIR"
    BASENAME=$(basename "$OUTPUT")
    cp "$OUTPUT" "$DEST_DIR/$BASENAME"
    echo "  Saved:  $DEST_DIR/$BASENAME"

    # Generate symlink with readable GPU name
    GPU_NAME=$(lspci -s "$BDF" 2>/dev/null | sed 's/.*: //' | tr ' /' '_' || echo "gpu")
    if [ -n "$GPU_NAME" ]; then
        ln -sf "$BASENAME" "$DEST_DIR/${GPU_NAME}.rom" 2>/dev/null || true
        echo "  Alias:  $DEST_DIR/${GPU_NAME}.rom -> $BASENAME"
    fi

    # Detect FreshBoot's expected name from GPU model
    # This maps GPU model names to the hardcoded filenames in fresh_boot.rs
    GPU_MODEL=$(lspci -s "$BDF" 2>/dev/null | sed 's/.*: //' || echo "")
    FB_NAME=""
    if echo "$GPU_MODEL" | grep -qi "RTX 4080"; then
        FB_NAME="Asus.RTX4080Mobile.12288.221219.rom"
    elif echo "$GPU_MODEL" | grep -qi "RTX 4090"; then
        FB_NAME="Asus.RTX4090.16384.221219.rom"
    elif echo "$GPU_MODEL" | grep -qi "RTX 4070\|RTX 4060\|RTX 4050"; then
        FB_NAME="Asus.RTX4070.12288.221219.rom"
    fi
    if [ -n "$FB_NAME" ]; then
        cp "$OUTPUT" "$DEST_DIR/$FB_NAME"
        echo "  FreshBoot:  $DEST_DIR/$FB_NAME -> $BASENAME"
    else
        echo "  Note: Unknown GPU model '$GPU_MODEL', FreshBoot may need config update"
    fi
else
    echo "ERROR: Output file is empty or missing"
    exit 1
fi

echo ""
echo "=== Done ==="
echo "FreshBootBackend will auto-detect this ROM in ~/.tinymachine/vbios/"
echo "Test with: cargo test --test fresh_boot_vbios -- --nocapture"
