# OBS-Air

AirPlay screen mirroring and audio for **OBS Studio 32 or later**, on
**Windows x64** and **Apple Silicon macOS arm64**.

Add **AirPlay (OBS-Air)** to Sources. Supports H.264 video, AAC/ALAC/PCM audio,
portrait/landscape rotation, automatic/720p/1080p negotiation, and 30/60 FPS.
Languages: English, Simplified Chinese, and Traditional Chinese.
**Version 2.0.0** is based on a fixed official UxPlay 1.74 experimental commit.

## Install

Download the matching ZIP from [GitHub Releases](https://github.com/iesv/OBS-Air/releases/latest),
extract it completely, and exit OBS.

- **Windows:** run `install_obs-air.bat` as administrator. OBS must be installed
  in its default location. The script allows inbound OBS TCP/UDP on private
  networks from the local subnet; port changes need no firewall updates.
- **macOS:** run `bash install_obs-air.sh` in Terminal. The script removes quarantine
  from the installed bundle. Allow OBS local-network access when prompted.
  The bundle is ad-hoc signed and not notarized.

Successful scripts exit after a five-second countdown. Errors remain visible until dismissed.

Restart OBS, add the source, and select the receiver in **Screen Mirroring**
on a device connected to the same LAN. Use OBS audio monitoring to hear audio locally.
For audio-only playback, select the receiver from the device's AirPlay audio output menu.

To uninstall, exit OBS and delete `%ProgramData%\obs-studio\plugins\obs-air`
on Windows, or `~/Library/Application Support/obs-studio/plugins/obs-air.plugin`
on macOS. Scene settings and Windows firewall rules are retained.

## Settings

- Leave the connection password empty to disable it. Visible ASCII letters,
  digits and keyboard symbols are accepted; whitespace and non-ASCII input are filtered.
  Passwords remain visible and are saved in scene settings.
- Confirm the properties dialog to apply changes. Receiver changes disconnect devices.
  **Restart receiver** uses applied settings and leaves pending edits unapplied.
  A restart shortcut can be assigned under **Settings → Hotkeys**.
  **Follow device volume** is off by default. Enable it to apply AirPlay volume
  and mute commands without changing the OBS mixer volume.
- **Block takeover** is on by default. Disable it to allow a new
  authenticated device to replace the current device.
  Password authentication failures and blocked takeovers are logged once per connection;
  normal password challenges are not failures, and passwords are not logged.
- One receiver and one device are active at a time. Reuse the existing source in other scenes.
  Connection information shows the device and actual received video dimensions.
  Audio-only connections show **Audio streaming** without a video size.
- Base port **P** uses TCP **P/P+100**, UDP **P+11-P+13**, and mDNS UDP **5353**.
  The default is **7800**. Choose unused ports and a distinct name alongside AirServer.

Defaults: automatic resolution, 60 FPS, low latency, and takeover protection.

Automatic resolution preserves received dimensions; it does not guarantee physical
screen resolution. DRM video, HLS, HEVC, Bluetooth discovery and peer-to-peer AirPlay
are unsupported. Windows uses built-in mDNS; macOS uses system Bonjour.
Neither platform requires an additional Bonjour installation.

GPL-3.0-or-later. See [THIRD_PARTY.md](THIRD_PARTY.md) for dependencies.
Packages include the required notices in `THIRD_PARTY_LICENSES.txt`.
