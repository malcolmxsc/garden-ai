#!/usr/bin/env sh
# An apk file is actually a gzipped tarball, or a concatenated set of them!
# Sometimes there are two gz streams in an apk file.
curl -s -L -o busybox.apk "https://dl-cdn.alpinelinux.org/alpine/v3.19/main/aarch64/busybox-static-1.36.1-r15.apk"
mkdir -p unpack
tar -xzf busybox.apk -C unpack || true
if [ ! -f unpack/bin/busybox.static ]; then
  # Try zcatting the entire combined stream and tar it out
  zcat busybox.apk | tar xf - -C unpack || true
fi
cp unpack/bin/busybox.static guest/initramfs/busybox
chmod +x guest/initramfs/busybox
