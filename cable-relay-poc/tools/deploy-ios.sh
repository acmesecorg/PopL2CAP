#!/usr/bin/env bash
# Deploy the CableRelay iOS app to a physical device without Xcode's debugger.
#
#   ./tools/deploy-ios.sh iphone
#   ./tools/deploy-ios.sh ipad
#   ./tools/deploy-ios.sh all          # both devices
#   ./tools/deploy-ios.sh iphone --no-launch
#
set -euo pipefail

TARGET="${1:?usage: deploy-ios.sh iphone|ipad|all [--no-launch]}"
LAUNCH=1
[ "${2:-}" = "--no-launch" ] && LAUNCH=0

IPHONE_UDID="2256577C-A96C-5DE5-9F88-73221B992312"
IPAD_UDID="BBD4A84F-89C3-5376-80DF-FE644CC384B2"
BID="com.crainiate.cablerelay"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
APP="$ROOT/build/Build/Products/Debug-iphoneos/CableRelay.app"

build() {
  echo "▸ regenerating xcodeproj…"
  ( cd "$ROOT" && /opt/homebrew/bin/xcodegen generate >/dev/null )

  echo "▸ building (Debug, device)…"
  xcodebuild -project "$ROOT/CableRelay.xcodeproj" -scheme CableRelay \
    -sdk iphoneos -destination 'generic/platform=iOS' ARCHS=arm64 \
    -derivedDataPath "$ROOT/build" -allowProvisioningUpdates build \
    | grep -E "^\*\* BUILD|error:" || true
  [ -d "$APP" ] || { echo "✗ build product missing: $APP"; exit 1; }
}

install_and_launch() {
  local name="$1" udid="$2"
  echo "▸ installing → $name ($udid)"
  xcrun devicectl device install app --device "$udid" "$APP"

  if [ "$LAUNCH" = "1" ]; then
    echo "▸ launching (unattached)…"
    if xcrun devicectl device process launch --device "$udid" "$BID"; then
      echo "✓ $name is running, no debugger attached"
    else
      echo "✗ $name: installed, launch REFUSED (device locked? tap the icon instead)"
    fi
  else
    echo "✓ $name: installed (not launched — --no-launch)"
  fi
}

build

case "$TARGET" in
  iphone) install_and_launch "iPhone" "$IPHONE_UDID" ;;
  ipad)   install_and_launch "iPad" "$IPAD_UDID" ;;
  all)    install_and_launch "iPhone" "$IPHONE_UDID"
          install_and_launch "iPad" "$IPAD_UDID" ;;
  *) echo "target must be iphone|ipad|all"; exit 1 ;;
esac
