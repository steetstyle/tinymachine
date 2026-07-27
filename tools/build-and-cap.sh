#!/bin/bash
# Build, set capabilities, and optionally run build-snapshot with --network.
# Usage: bash tools/build-and-cap.sh [--run]
set -e
cd "$(dirname "$0")/.."
echo "Building..."
cargo build --bin tinymachine --bin build-snapshot "$@"
echo "Setting capabilities..."
sudo setcap cap_net_admin+ep target/debug/tinymachine
sudo setcap cap_net_admin+ep target/debug/build-snapshot
echo "Done."
if [ "${1:-}" = "--run" ]; then
  shift
  RUST_LOG=debug exec cargo run --bin build-snapshot -- --kernel tinymachine-fork/templates/kernel/vmlinux-base --lang python --variant minimal --profile base --network "$@" 2>&1
fi
