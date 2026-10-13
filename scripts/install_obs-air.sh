#!/bin/bash
set -euo pipefail
finish() {
  local result=$?
  if (( result == 0 )); then
    for seconds in 5 4 3 2 1; do
      printf '\rClosing in %ds...' "$seconds"
      sleep 1
    done
    printf '\n'
  else
    echo "Installation failed. See the error above."
    read -r -p "Press Enter to close." || true
  fi
}
trap finish EXIT
cd "$(dirname "$0")"
if pgrep -x OBS >/dev/null; then
  echo "Exit OBS before installing." >&2
  exit 1
fi
if [[ "$(uname -m)" != arm64 ]]; then
  echo "This package requires Apple Silicon." >&2
  exit 1
fi
if [[ ! -f obs-air.plugin/Contents/MacOS/obs-air ]]; then
  echo "Incomplete package. Extract the entire ZIP." >&2
  exit 1
fi
home_dir="$(cd "$HOME" && pwd -P)"
target="$home_dir/Library/Application Support/obs-studio/plugins"
mkdir -p "$target"
if [[ "$(cd "$target" && pwd -P)" != "$target" || -L "$target/obs-air.plugin" ]]; then
  echo "Installation stopped: the destination is a symbolic link." >&2
  exit 1
fi
# Replace the complete bundle to remove obsolete libraries.
rm -rf -- "$target/obs-air.plugin"
ditto obs-air.plugin "$target/obs-air.plugin"
xattr -dr com.apple.quarantine "$target/obs-air.plugin"
echo "Quarantine attribute removed."
echo "Installed: $target/obs-air.plugin"
echo "Restart OBS 32 or later and add AirPlay (OBS-Air)."
echo "Use Screen Mirroring on a device connected to the same LAN."
echo "Allow OBS local-network access when prompted."
