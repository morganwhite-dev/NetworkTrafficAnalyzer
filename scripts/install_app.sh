#!/usr/bin/env bash
# Build "Network Traffic Analyzer.app" in ~/Applications so you can start the
# analyzer from Spotlight or the Dock instead of the terminal.
#
#   scripts/install_app.sh            # install or update the app
#   scripts/install_app.sh --remove   # delete it
#
# The app starts live capture on Wi-Fi straight away (set up ChmodBPF first,
# see the README), opens the dashboard, and stops the analyzer when you quit it.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
APP="$HOME/Applications/Network Traffic Analyzer.app"

if [ "$(uname)" != "Darwin" ]; then
  echo "This builds a macOS app, so it only runs on a Mac." >&2
  exit 1
fi
if [ "${1:-}" = "--remove" ]; then
  rm -rf "$APP" && echo "Removed $APP"
  exit 0
fi
if [ ! -x "$ROOT/.venv/bin/python" ]; then
  echo "Run scripts/setup.sh first." >&2
  exit 1
fi

mkdir -p "$HOME/Applications" "$HOME/Library/Logs"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
# Put this repo's location into the launcher (escaped for AppleScript).
esc_root="$(printf '%s' "$ROOT" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g')"
sed "s|__REPO__|$esc_root|" "$ROOT/scripts/macos/launcher.applescript" > "$tmp/launcher.applescript"

rm -rf "$APP"
osacompile -s -o "$APP" "$tmp/launcher.applescript"     # -s: stays open, so Quit stops the analyzer
cp "$ROOT/assets/AppIcon.icns" "$APP/Contents/Resources/applet.icns"
# Newer osacompile also ships an asset catalog whose generic icon would win; drop it.
rm -f "$APP/Contents/Resources/Assets.car"
plutil -remove CFBundleIconName "$APP/Contents/Info.plist" 2>/dev/null || true
plutil -replace CFBundleName -string "Network Traffic Analyzer" "$APP/Contents/Info.plist"
plutil -replace CFBundleIdentifier -string "dev.morganwhite.network-traffic-analyzer" "$APP/Contents/Info.plist"
codesign --force --deep --sign - "$APP" >/dev/null 2>&1 || true   # ad-hoc signature after the edits
touch "$APP"
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f "$APP" 2>/dev/null || true

echo "Installed: $APP"
echo "Open it from Spotlight (Cmd+Space, type \"Network Traffic\") or drag it into your Dock."
echo "Logs go to ~/Library/Logs/NetworkTrafficAnalyzer.log"
