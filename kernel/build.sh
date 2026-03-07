#!/bin/bash
# =====================================================================
# Garden AI — Custom aarch64 Linux Kernel Build Script
# =====================================================================
# Cross-compiles a minimal Linux kernel for aarch64 with VirtIO-vSock
# compiled built-in (=y). Runs inside a Docker container with the
# aarch64-linux-gnu toolchain.
#
# Usage: ./build.sh [kernel_version]
#   Default kernel version: 6.12.13
#
# Output: ../guest/kernel/kernel (raw uncompressed Image)
# =====================================================================

set -euo pipefail

KERNEL_VERSION="${1:-6.12.13}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUTPUT_DIR="${SCRIPT_DIR}/../guest/kernel"

echo "🌿 Garden AI Kernel Builder"
echo "   Kernel: v${KERNEL_VERSION}"
echo "   Output: ${OUTPUT_DIR}/kernel"
echo ""

# Build inside Docker for reliable cross-compilation
docker run --rm \
    -v "${SCRIPT_DIR}:/build" \
    -v "${OUTPUT_DIR}:/output" \
    -w /src \
    ubuntu:24.04 \
    bash -c "
        set -euo pipefail
        
        echo '📦 Installing cross-compilation toolchain...'
        apt-get update -qq
        apt-get install -y -qq \
            gcc-aarch64-linux-gnu make flex bison libssl-dev bc \
            wget xz-utils > /dev/null 2>&1
        
        echo '⬇️  Downloading Linux ${KERNEL_VERSION} source...'
        wget -q https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-${KERNEL_VERSION}.tar.xz
        tar xf linux-${KERNEL_VERSION}.tar.xz
        cd linux-${KERNEL_VERSION}
        
        echo '⚙️  Generating minimal aarch64 defconfig...'
        make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- defconfig > /dev/null 2>&1
        
        echo '🔧 Applying Garden AI kernel config overrides...'
        # Copy our config overrides
        cat /build/garden.config >> .config
        
        # Resolve any dependency conflicts introduced by our overrides
        make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- olddefconfig > /dev/null 2>&1
        
        echo '🔍 Verifying vSock config...'
        grep -E 'VSOCK|VIRTIO_VSOCK' .config
        
        echo ''
        echo '🔨 Building kernel (this takes ~5-10 minutes)...'
        make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- -j\$(nproc) Image 2>&1 | tail -5
        
        echo ''
        echo '📋 Kernel binary info:'
        ls -lh arch/arm64/boot/Image
        
        cp arch/arm64/boot/Image /output/kernel
        echo ''
        echo '✅ Kernel built and copied to output!'
    "

echo ""
echo "✅ Custom kernel ready at: ${OUTPUT_DIR}/kernel"
ls -lh "${OUTPUT_DIR}/kernel"
