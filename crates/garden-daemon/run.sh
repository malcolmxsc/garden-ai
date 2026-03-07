#!/usr/bin/env bash

# Exit immediately if a command exits with a non-zero status
set -e

echo "📦 Building garden-daemon..."
cargo build

echo "🔐 Signing binary with Virtualization Entitlements..."
# We use the built-in macOS `codesign` tool. 
# -s - means "Ad-Hoc Signing" (we don't need a paid Apple Developer certificate for local testing)
# --entitlements points to our XML file.
# --force overwrites any existing signature.
codesign -s - --entitlements entitlements.plist --force ../../target/debug/garden-daemon

echo "🚀 Executing securely signed daemon..."
echo "----------------------------------------------------"
../../target/debug/garden-daemon
