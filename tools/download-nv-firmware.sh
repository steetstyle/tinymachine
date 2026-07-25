#!/bin/bash
# Pre-download NVIDIA GSP firmware files for VFIO passthrough NV compute.
#
# TinyOS needs these firmware files inside the KVM guest for tinygrad's
# PCIIface (direct VFIO PCI BAR access). The host's nvidia.ko handles
# firmware loading via the kernel module; but in VFIO, the guest tinygrad
# must load GSP firmware directly from /lib/firmware/.
#
# Usage: ./download-nv-firmware.sh [output-dir]
#   output-dir defaults to $(dirname $0)/initramfs/lib/firmware
#
# Firmware files needed for AD104 (RTX 4080):
#   nvidia/ad102/gsp/booter_load-570.144.bin     (57 KB)
#   nvidia/ad102/gsp/bootloader-570.144.bin      (37 KB)
#   nvidia/ga102/gsp/gsp-570.144.bin             (64 MB)  ← biggest
#
# Source: https://gitlab.com/kernel-firmware/linux-firmware
# Commit: 1e2c15348485939baf1b6d1f5a7a3b799d80703d
set -euo pipefail

FIRMWARE_BASE="https://gitlab.com/kernel-firmware/linux-firmware/-/raw/1e2c15348485939baf1b6d1f5a7a3b799d80703d"
OUTPUT_DIR="${1:-$(cd "$(dirname "$0")" && pwd)/initramfs/lib/firmware}"

# SHA256 hashes (from tinygrad helpers.py fetch_fw calls)
declare -A FW_HASHES
FW_HASHES["nvidia/ad102/gsp/booter_load-570.144.bin"]="8b293e19b637c5e22c87a2428d1c71bb13e0904e8a88ac6b3c6c1f2679c6e37a"
FW_HASHES["nvidia/ad102/gsp/bootloader-570.144.bin"]="65ab2e6b6e0fca95365c4deac79a34582abcfeb15b6ae234138f22e7183118a8"
FW_HASHES["nvidia/ga102/gsp/gsp-570.144.bin"]="a8c3ebeed280323aedb51c061f321e73379cce7a9ae643a33dd03915df027f7f"

echo "=== TinyOS NVIDIA GSP Firmware Downloader ==="
echo "Output: $OUTPUT_DIR"

# First check if host has firmware in /lib/firmware/nvidia/ (much faster copy)
HOST_FW="/lib/firmware/nvidia"
COPIED=0
for rel_path in "${!FW_HASHES[@]}"; do
    name=$(basename "$rel_path")
    dir=$(dirname "$rel_path")
    expected_sha="${FW_HASHES[$rel_path]}"

    mkdir -p "$OUTPUT_DIR/$dir"
    out_file="$OUTPUT_DIR/$rel_path"

    # Check host's .zst file first
    zst_file="$HOST_FW/$dir/$name.zst"
    if [ -f "$zst_file" ]; then
        echo "  Checking host $zst_file ..."
        if command -v zstd &>/dev/null; then
            actual_sha=$(zstd -d --stdout "$zst_file" 2>/dev/null | sha256sum | cut -d' ' -f1)
            if [ "$actual_sha" = "$expected_sha" ]; then
                zstd -d --stdout "$zst_file" > "$out_file"
                echo "  COPIED (from host): $rel_path ($(stat -c%s "$out_file") bytes, sha OK)"
                COPIED=$((COPIED + 1))
                continue
            fi
        fi
    fi

    # Check if we already have the file downloaded
    if [ -f "$out_file" ]; then
        actual_sha=$(sha256sum "$out_file" | cut -d' ' -f1)
        if [ "$actual_sha" = "$expected_sha" ]; then
            echo "  EXISTS: $rel_path ($(stat -c%s "$out_file") bytes, sha OK)"
            COPIED=$((COPIED + 1))
            continue
        fi
    fi

    # Download from linux-firmware gitlab
    url="$FIRMWARE_BASE/$rel_path"
    echo "  Downloading $url ..."
    curl -sL "$url" -o "$out_file" || {
        echo "  ERROR: Failed to download $url"
        exit 1
    }
    actual_sha=$(sha256sum "$out_file" | cut -d' ' -f1)
    if [ "$actual_sha" != "$expected_sha" ]; then
        echo "  ERROR: SHA256 mismatch for $rel_path"
        echo "    Expected: $expected_sha"
        echo "    Actual:   $actual_sha"
        exit 1
    fi
    echo "  DOWNLOADED: $rel_path ($(stat -c%s "$out_file") bytes, sha OK)"
    COPIED=$((COPIED + 1))
done

echo ""
echo "=== Done: $COPIED/${#FW_HASHES[@]} firmware files ready ==="
ls -la "$OUTPUT_DIR/nvidia/"*/gsp/*.bin 2>/dev/null
