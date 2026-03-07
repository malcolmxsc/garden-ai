# Guest VM Assets

This directory holds the Linux kernel and root filesystem used by Garden AI sandboxes.

## Required Files

| File | Description | How to obtain |
|------|-------------|---------------|
| `kernel/bzImage` | Compiled Linux kernel image | Build from source or download a minimal kernel |
| `rootfs/rootfs.img` | Root filesystem disk image | Build with Alpine Linux or a custom initramfs |

## Building a Minimal Guest Kernel

```bash
# Clone Linux kernel
git clone --depth 1 --branch v6.6 https://github.com/torvalds/linux.git
cd linux

# Use a minimal config for fast boot
make tinyconfig
# Enable required options:
#   CONFIG_VIRTIO=y, CONFIG_VIRTIO_BLK=y, CONFIG_VIRTIO_NET=y,
#   CONFIG_VIRTIO_CONSOLE=y, CONFIG_VIRTIO_FS=y,
#   CONFIG_NET=y, CONFIG_INET=y, CONFIG_EXT4_FS=y

make -j$(nproc) bzImage
cp arch/x86/boot/bzImage ../guest/kernel/  # or arch/arm64/boot/Image for Apple Silicon
```

## Building a Minimal Root FS (Alpine)

```bash
# Create a 512MB disk image
dd if=/dev/zero of=rootfs.img bs=1M count=512
mkfs.ext4 rootfs.img

# Mount and install Alpine
mkdir -p /tmp/rootfs
sudo mount rootfs.img /tmp/rootfs
# ... install Alpine base system ...
sudo umount /tmp/rootfs

cp rootfs.img ../guest/rootfs/
```

## Performance Target

Garden AI aims to boot the guest kernel in **< 200ms** using Apple's Virtualization.framework.
A stripped-down kernel with only VirtIO drivers enabled is essential for this target.
