#!/usr/bin/env bash
set -euo pipefail

# ─────────────────────────────────────────────────────────────────────────────
# TinyOS Layer Builder
# ─────────────────────────────────────────────────────────────────────────────
# Build a pre-built cpio layer for the Layer Composition System.
#
# Usage:
#   ./build-layer.sh --type pip     --name numpy   --version 1.26.4 [--mode host]
#   ./build-layer.sh --type runtime --name python  --version 3.12.3 [--mode kvm]
#   ./build-layer.sh --type npm     --name express --version 4.19.0
#   ./build-layer.sh --type source  --name myapp   --version 1.0.0 --build-script ./build.sh
#
# Layer types: base, runtime, pip, npm, cargo, apt, source
# Build modes: host (fast, default), kvm (isolated sandbox)
#
# Output: ~/.tinymachine/layers/<type>/<name>/<version>/layer.cpio.zst
# ─────────────────────────────────────────────────────────────────────────────

LAYERS_DIR="${HOME}/.tinymachine/layers"
BUILD_MODE="host"
LAYER_TYPE=""
LAYER_NAME=""
LAYER_VERSION=""
BUILD_SCRIPT=""
VERBOSE=false

# ─── Parse arguments ─────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --type) LAYER_TYPE="$2"; shift 2 ;;
        --name) LAYER_NAME="$2"; shift 2 ;;
        --version) LAYER_VERSION="$2"; shift 2 ;;
        --mode) BUILD_MODE="$2"; shift 2 ;;
        --build-script) BUILD_SCRIPT="$2"; shift 2 ;;
        --verbose|-v) VERBOSE=true; shift ;;
        --help|-h)
            echo "Usage: $0 --type TYPE --name NAME --version VERSION [options]"
            echo ""
            echo "Required:"
            echo "  --type TYPE       Layer type: base, runtime, pip, npm, cargo, apt, source"
            echo "  --name NAME       Layer name (e.g., numpy, python, express)"
            echo "  --version VER     Layer version (e.g., 1.26.4, 3.12.3)"
            echo ""
            echo "Options:"
            echo "  --mode MODE       Build mode: host (default) or kvm"
            echo "  --build-script S  Path to build script (source type only)"
            echo "  --verbose         Verbose output"
            echo "  --help            Show this help"
            exit 0
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# ─── Validate arguments ──────────────────────────────────────────────────────
if [[ -z "$LAYER_TYPE" ]] || [[ -z "$LAYER_NAME" ]] || [[ -z "$LAYER_VERSION" ]]; then
    echo "ERROR: --type, --name, and --version are required"
    echo "Try: $0 --help"
    exit 1
fi

if [[ "$LAYER_TYPE" != "base" ]] && [[ "$LAYER_TYPE" != "runtime" ]] && \
   [[ "$LAYER_TYPE" != "pip" ]] && [[ "$LAYER_TYPE" != "npm" ]] && \
   [[ "$LAYER_TYPE" != "cargo" ]] && [[ "$LAYER_TYPE" != "apt" ]] && \
   [[ "$LAYER_TYPE" != "source" ]]; then
    echo "ERROR: Unknown layer type '$LAYER_TYPE'"
    echo "Valid types: base, runtime, pip, npm, cargo, apt, source"
    exit 1
fi

if [[ "$BUILD_MODE" != "host" ]] && [[ "$BUILD_MODE" != "kvm" ]]; then
    echo "ERROR: Build mode must be 'host' or 'kvm'"
    exit 1
fi

# ─── Setup paths ─────────────────────────────────────────────────────────────
OUTPUT_DIR="${LAYERS_DIR}/${LAYER_TYPE}/${LAYER_NAME}/${LAYER_VERSION}"
OUTPUT_FILE="${OUTPUT_DIR}/layer.cpio.zst"
BUILD_DIR=$(mktemp -d -t "tinymachine-layer-${LAYER_NAME}-${LAYER_VERSION}-XXXXXX")

# Ensure DESTDIR is exported so build scripts can use it
export DESTDIR="${BUILD_DIR}/dest"
mkdir -p "$DESTDIR"

cleanup() {
    if [[ "$VERBOSE" == "true" ]]; then
        echo "Cleaning up build directory: ${BUILD_DIR}"
    fi
    rm -rf "$BUILD_DIR"
}
trap cleanup EXIT

info() {
    echo "[build-layer.sh] $*"
}

# ─── Build functions per type ────────────────────────────────────────────────

build_pip() {
    local pkg="$1"
    local ver="$2"
    info "Installing pip package ${pkg}==${ver} to ${DESTDIR}"
    pip3 install --target="${DESTDIR}/usr/lib/python3/dist-packages" \
        --no-cache-dir \
        "${pkg}==${ver}" 2>&1 | tail -5
    # Strip .pyc files and __pycache__
    find "$DESTDIR" -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true
    find "$DESTDIR" -name '*.pyc' -delete 2>/dev/null || true
    # Strip .dist-info except METADATA
    find "$DESTDIR" -name '*.dist-info' -type d | while read -r d; do
        if [[ -f "$d/METADATA" ]]; then
            mv "$d/METADATA" "${d}/../METADATA.${pkg}" 2>/dev/null || true
        fi
        rm -rf "$d"
    done
}

build_npm() {
    local pkg="$1"
    local ver="$2"
    info "Installing npm package ${pkg}@${ver} to ${DESTDIR}"
    mkdir -p "${BUILD_DIR}/npm_work"
    cd "${BUILD_DIR}/npm_work"
    # Use package.json to install specific version
    cat > package.json <<JSON
{
  "name": "layer-${pkg}",
  "version": "0.0.0",
  "private": true,
  "dependencies": {
    "${pkg}": "${ver}"
  }
}
JSON
    npm install --prefix "$BUILD_DIR/npm_work" 2>&1 | tail -5
    # Copy node_modules to DESTDIR
    if [[ -d "node_modules" ]]; then
        mkdir -p "$DESTDIR/usr/lib/node_modules"
        cp -r "node_modules/${pkg}" "$DESTDIR/usr/lib/node_modules/" 2>/dev/null || true
    fi
    cd /tmp
}

build_cargo() {
    local pkg="$1"
    local ver="$2"
    info "Installing cargo package ${pkg} v${ver} to ${DESTDIR}"
    # Use cargo install with --root
    cargo install "${pkg}" --version "${ver}" --root "$DESTDIR" 2>&1 | tail -5
}

build_runtime() {
    local runtime="$1"
    local ver="$2"
    info "Building runtime ${runtime} ${ver} — checking for build script"

    local script_path=""
    # Look for build script in recipes directory
    local recipe_dir="${HOME}/.tinymachine/layers/recipes/${runtime}/${ver}"
    if [[ -f "${recipe_dir}/build.sh" ]]; then
        script_path="${recipe_dir}/build.sh"
    elif [[ -n "$BUILD_SCRIPT" ]]; then
        script_path="$BUILD_SCRIPT"
    fi

    if [[ -n "$script_path" ]]; then
        info "Using build script: ${script_path}"
        if [[ ! -f "$script_path" ]]; then
            echo "ERROR: Build script not found: ${script_path}"
            exit 1
        fi
        chmod +x "$script_path"
        # Run the build script — it receives DESTDIR as argument
        "$script_path" "$DESTDIR"
    else
        echo "ERROR: No build script found for runtime ${runtime} ${ver}"
        echo "Create a recipe at: ${recipe_dir}/build.sh"
        echo ""
        echo "Example build.sh:"
        echo "  #!/bin/bash"
        echo "  set -euo pipefail"
        echo "  DESTDIR=\"\$1\""
        echo "  curl -sL \"https://python.org/ftp/python/${ver}/Python-${ver}.tar.xz\" | tar xJ"
        echo "  cd \"Python-${ver}\""
        echo "  ./configure --prefix=/usr --disable-test-modules"
        echo "  make -j\$(nproc)"
        echo "  make install DESTDIR=\"\$DESTDIR\""
        exit 1
    fi
}

build_source() {
    info "Building from source script: ${BUILD_SCRIPT}"
    if [[ ! -f "$BUILD_SCRIPT" ]]; then
        echo "ERROR: Build script not found: ${BUILD_SCRIPT}"
        exit 1
    fi
    chmod +x "$BUILD_SCRIPT"
    # Run the build script with DESTDIR as argument
    "$BUILD_SCRIPT" "$DESTDIR"
}

build_apt() {
    local pkg="$1"
    info "Downloading apt package ${pkg} to ${DESTDIR}"
    # Use apt-get download + dpkg -x
    local tmp_deb="${BUILD_DIR}/pkg.deb"
    apt-get download "${pkg}" -o "dir::cache=${BUILD_DIR}" 2>&1 | tail -3 || true
    # Try to extract any downloaded .deb
    find "${BUILD_DIR}" -name '*.deb' -exec dpkg-deb -x {} "$DESTDIR" \; 2>/dev/null || true
}

# ─── Execute build ───────────────────────────────────────────────────────────
info "Building layer: ${LAYER_TYPE}/${LAYER_NAME}@${LAYER_VERSION}"
info "Build mode: ${BUILD_MODE}"
info "Output: ${OUTPUT_FILE}"

case "$LAYER_TYPE" in
    pip)
        build_pip "$LAYER_NAME" "$LAYER_VERSION"
        ;;
    npm)
        build_npm "$LAYER_NAME" "$LAYER_VERSION"
        ;;
    cargo)
        build_cargo "$LAYER_NAME" "$LAYER_VERSION"
        ;;
    runtime)
        build_runtime "$LAYER_NAME" "$LAYER_VERSION"
        ;;
    source)
        if [[ -z "$BUILD_SCRIPT" ]]; then
            echo "ERROR: --build-script is required for source type"
            exit 1
        fi
        build_source
        ;;
    apt)
        build_apt "$LAYER_NAME"
        ;;
    base)
        info "Base layer: nothing to build (kernel + init.c + busybox)"
        # Base layers are pre-built, just create an empty marker
        mkdir -p "${DESTDIR}/etc"
        echo "tinymachine-base-${LAYER_VERSION}" > "${DESTDIR}/etc/tinymachine-layer"
        ;;
esac

# ─── Create cpio archive ─────────────────────────────────────────────────────
if [[ ! -d "$DESTDIR" ]] || [[ -z "$(ls -A "$DESTDIR" 2>/dev/null)" ]]; then
    echo "WARNING: DESTDIR is empty — creating minimal layer"
    mkdir -p "$DESTDIR/etc"
    echo "${LAYER_TYPE}/${LAYER_NAME}@${LAYER_VERSION}" > "${DESTDIR}/etc/tinymachine-layer"
fi

info "Creating cpio archive..."
mkdir -p "$OUTPUT_DIR"
cd "$DESTDIR"

# Create compressed cpio archive
find . -print0 2>/dev/null | cpio -o -0 -H newc --quiet 2>/dev/null | zstd -q -o "$OUTPUT_FILE" 2>/dev/null

if [[ ! -f "$OUTPUT_FILE" ]] || [[ ! -s "$OUTPUT_FILE" ]]; then
    echo "ERROR: Failed to create cpio archive"
    ls -la "$DESTDIR"
    exit 1
fi

# ─── Generate metadata ───────────────────────────────────────────────────────
cd /tmp

# Calculate sizes and hash
COMPRESSED_SIZE=$(stat -c%s "$OUTPUT_FILE" 2>/dev/null || stat -f%z "$OUTPUT_FILE" 2>/dev/null)
HASH=$(sha256sum "$OUTPUT_FILE" | cut -d' ' -f1)
# Estimate uncompressed size (zstd decompress to /dev/null)
UNCOMPRESSED_SIZE=$(zstd -d -c "$OUTPUT_FILE" 2>/dev/null | wc -c || echo "$COMPRESSED_SIZE")

# Determine provides based on layer name (pip packages)
PROVIDES="[\"${LAYER_NAME}\"]"
if [[ "$LAYER_TYPE" == "pip" ]]; then
    case "$LAYER_NAME" in
        numpy)   PROVIDES='["numpy","scipy","pandas","matplotlib"]' ;;
        tinygrad) PROVIDES='["tinygrad","extra"]' ;;
        pytorch) PROVIDES='["torch","torchvision","torchaudio"]' ;;
        requests) PROVIDES='["requests","urllib3"]' ;;
        flask)   PROVIDES='["flask","fastapi"]' ;;
        pillow)  PROVIDES='["pillow","PIL"]' ;;
        transformers) PROVIDES='["transformers","sentencepiece"]' ;;
        jax)     PROVIDES='["jax","flax"]' ;;
    esac
fi

# Determine interpreter
INTERPRETER="null"
INTERPRETER_ARGS="[]"
if [[ "$LAYER_TYPE" == "runtime" ]]; then
    case "$LAYER_NAME" in
        python) INTERPRETER='"/usr/bin/python3"'; INTERPRETER_ARGS='["-c"]' ;;
        node)   INTERPRETER='"/usr/bin/node"';     INTERPRETER_ARGS='["-e"]' ;;
    esac
fi

# Write meta.json
META_FILE="${OUTPUT_DIR}/meta.json"
cat > "$META_FILE" <<JSON
{
  "layer_type": "${LAYER_TYPE}",
  "name": "${LAYER_NAME}",
  "version": "${LAYER_VERSION}",
  "provides": ${PROVIDES},
  "requires_runtime": $( [[ "$LAYER_TYPE" == "pip" || "$LAYER_TYPE" == "npm" ]] && echo "\"${LAYER_NAME}\"" || echo "null" ),
  "size_bytes": ${UNCOMPRESSED_SIZE:-0},
  "compressed_size": ${COMPRESSED_SIZE:-0},
  "hash": "${HASH}",
  "kernel_profile": $( [[ "$LAYER_NAME" == "tinygrad" ]] && echo '"gpu-vk"' || echo 'null' ),
  "memory_mb": $( [[ "$LAYER_NAME" == "pytorch" ]] && echo 3072 || echo 64 ),
  "interpreter": ${INTERPRETER},
  "interpreter_args": ${INTERPRETER_ARGS},
  "default": true
}
JSON

info "✓ Layer built: ${LAYER_TYPE}/${LAYER_NAME}@${LAYER_VERSION}"
info "  Output: ${OUTPUT_FILE}"
info "  Compressed: $(numfmt --to=iec-i ${COMPRESSED_SIZE:-0})B"
info "  Uncompressed: $(numfmt --to=iec-i ${UNCOMPRESSED_SIZE:-0})B"
info "  Hash: ${HASH}"

# Update registry.toml
REGISTRY_FILE="${LAYERS_DIR}/registry.toml"
mkdir -p "$(dirname "$REGISTRY_FILE")"

# Append to registry
cat >> "$REGISTRY_FILE" <<TOML

["${LAYER_TYPE}/${LAYER_NAME}"]
version = "${LAYER_VERSION}"
hash = "${HASH}"
TOML
if [[ "$LAYER_TYPE" == "pip" ]]; then
    echo "provides = ${PROVIDES}" >> "$REGISTRY_FILE"
fi

info "✓ Registry updated: ${REGISTRY_FILE}"
