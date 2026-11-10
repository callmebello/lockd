#!/bin/bash
# Gera dist/Lockd.app (release), assinado. Uso: scripts/build_app.sh
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/version.sh
IDENTITY="${LOCKD_SIGN_IDENTITY:-Apple Development: Gustavo Henrique Correia Ferreira (44LNP6HYTB)}"

swift build -c release --arch arm64 --jobs 2
BIN="$(swift build -c release --arch arm64 --jobs 2 --show-bin-path)"
APP=dist/Lockd.app
rm -rf "$APP"; mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BIN/Lockd" "$APP/Contents/MacOS/Lockd"
cp "$BIN/lockdctl" "$APP/Contents/MacOS/lockdctl"

# ícone
iconutil -c icns brand-assets/AppIcon.iconset -o "$APP/Contents/Resources/AppIcon.icns"
rm -rf "$APP/Contents/Resources/chrome-extension"; cp -R extension "$APP/Contents/Resources/chrome-extension"
cp brand-assets/lockd-wordmark.png brand-assets/AppIconUI.png "$APP/Contents/Resources/"

cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleIdentifier</key><string>app.lockd.mac</string>
  <key>CFBundleName</key><string>Lockd</string>
  <key>CFBundleDisplayName</key><string>Lockd</string>
  <key>CFBundleExecutable</key><string>Lockd</string>
  <key>CFBundleIconFile</key><string>AppIcon</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>$LOCKD_RESOLVED_VERSION</string>
  <key>CFBundleVersion</key><string>$LOCKD_RESOLVED_BUILD</string>
  <key>LSMinimumSystemVersion</key><string>14.0</string>
  <key>LSUIElement</key><true/>
  <key>NSHighResolutionCapable</key><true/>
  <key>NSDownloadsFolderUsageDescription</key><string>Lockd organizes logos, fonts and credential files you download.</string>
  <key>NSDesktopFolderUsageDescription</key><string>Lockd organizes logos and credential files you save to the Desktop.</string>
</dict></plist>
PLIST

codesign --force --options runtime --timestamp --sign "$IDENTITY" --identifier app.lockd.mac.cli "$APP/Contents/MacOS/lockdctl"
codesign --force --options runtime --timestamp --sign "$IDENTITY" --identifier app.lockd.mac "$APP/Contents/MacOS/Lockd"
codesign --force --options runtime --timestamp --sign "$IDENTITY" "$APP"
codesign --verify --deep --strict --verbose=2 "$APP"
du -sh "$APP"
echo "OK → $(pwd)/$APP"
