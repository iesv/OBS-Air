"""Combine the required third-party license texts and notices for a package."""
from pathlib import Path
import argparse

ROOT = Path(__file__).resolve().parents[1]
LICENSE_FILE = "THIRD_PARTY_LICENSES.txt"
COMMON_NOTICES = {
    "UxPlay/LICENSE": "third_party/uxplay/LICENSE",
    "PlayFair/LICENSE.md": "third_party/uxplay/lib/playfair/LICENSE.md",
    "llhttp/LICENSE-MIT": "third_party/uxplay/lib/llhttp/LICENSE-MIT",
    "libplist/COPYING": "third_party/libplist/COPYING",
    "libcnary/COPYING": "third_party/libplist/libcnary/COPYING",
    "OpenSSL/LICENSE.txt": ".deps/openssl/LICENSE.txt",
    "FFmpeg/COPYING.GPLv2": ".deps/obs-deps/licenses/FFmpeg/COPYING.GPLv2",
    "x264/COPYING": ".deps/obs-deps/licenses/x264/COPYING",
    "x264/AUTHORS": ".deps/obs-deps/licenses/x264/AUTHORS",
}
WINDOWS_NOTICES = {
    "zlib/README": ".deps/obs-deps/licenses/zlib/README",
    "w32-pthreads/COPYING": ".deps/obs-studio/deps/w32-pthreads/COPYING",
    "w32-pthreads/COPYING.LIB": ".deps/obs-studio/deps/w32-pthreads/COPYING.LIB",
}


def write_licenses(destination, platform):
    notices = COMMON_NOTICES | (WINDOWS_NOTICES if platform == "windows" else {})
    sections = ["OBS-Air third-party licenses and notices\n"]
    for name, source in notices.items():
        text = (ROOT / source).read_text(encoding="utf-8")
        if name == "zlib/README":
            _, marker, text = text.partition("Copyright notice:")
            if not marker:
                raise ValueError("zlib README is missing its copyright notice")
            text = marker + text.split("\nIf you use the zlib library in a product", 1)[0]
        sections.append(f"\n=== {name} ===\n\n{text.rstrip()}\n")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text("".join(sections), encoding="utf-8", newline="\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("platform", choices=("windows", "macos"))
    parser.add_argument("destination", type=Path)
    arguments = parser.parse_args()
    write_licenses(arguments.destination, arguments.platform)
