# Third-party components

- **AirPlay core:** [FDH2/UxPlay](https://github.com/FDH2/UxPlay), experimental
  1.74 commit `ec203121355220dd90278a369eeabb0b8ba4f14a` (2026-10-11).
  This is the sole protocol update baseline. OBS-Air retains mirroring/audio
  with bounded requests, per-connection password authentication, session ownership,
  joined media workers, Windows socket support and native timestamp reception.
  HLS player code is omitted. Original GPL/LGPL/MIT notices, including PlayFair
  and llhttp, are preserved. Selected embedding-safety adaptations originate
  from [jerjjj/libuxplay](https://github.com/jerjjj/libuxplay), commit
  `ef191afd1fba1786ac7dc8ee5379472bb72fa7c6`; this is a retained source attribution,
  not a separate runtime dependency or update baseline.
- **libplist 2.7.0:** [libimobiledevice/libplist](https://github.com/libimobiledevice/libplist),
  commit `cf5897a71ea412ea2aeb1e2f6b5ea74d4fabfd8c`, LGPL-2.1-or-later.
  The C API is built statically. Unused C++ wrappers, examples and upstream
  build templates are omitted. Boolean getters use direct typed reads.
- **OBS Studio 32.0.0:** [obsproject/obs-studio](https://github.com/obsproject/obs-studio).
  libobs is provided by the host. Windows statically builds LGPL w32-pthreads;
  macOS uses native pthreads and the host libobs framework.
- **Qt 6.8.3 Core:** official [OBS dependency build](https://github.com/obsproject/obs-deps)
  `2025-08-23`. Qt is provided by OBS and is not packaged.
- **FFmpeg 7, x264 and zlib:** official OBS dependency build `2025-08-23`.
  Required libraries and licenses are packaged. macOS dylibs use private OBS-Air
  names and relative loader paths.
- **OpenSSL 3.5.9:** [openssl/openssl](https://github.com/openssl/openssl),
  Apache-2.0. The static crypto library and its license are included.

Source archives and SDKs are pinned by SHA256 in `scripts/prepare.py`.
Windows supplies mDNS internally; macOS uses system Bonjour.
GStreamer, GLib and a separate Bonjour installation are not required.
Packages combine license texts and required notices in `THIRD_PARTY_LICENSES.txt`.
Source license files remain intact; ordinary maintainer lists are not packaged.
