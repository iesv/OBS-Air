"""Check installation ZIP content and architecture without unpacking it."""
from pathlib import Path
import plistlib
import struct
import sys
import zipfile
from package_licenses import COMMON_NOTICES, LICENSE_FILE, WINDOWS_NOTICES

ROOT = Path(__file__).resolve().parents[1]


def main():
    platform = "macos-arm64" if sys.platform == "darwin" else "windows-x64"
    import re
    version = re.search(r"project\(OBS-Air VERSION ([0-9.]+)", (ROOT / "CMakeLists.txt").read_text())[1]
    package = ROOT / "dist" / f"OBS-Air-{version}-{platform}.zip"
    with zipfile.ZipFile(package) as archive:
        if archive.testzip():
            raise RuntimeError("Corrupt installation ZIP")
        if any("uninstall_obs-air" in name for name in archive.namelist()):
            raise RuntimeError("Obsolete uninstall script in package")
        if any(name.endswith("install_obs-air.command") for name in archive.namelist()):
            raise RuntimeError("Obsolete macOS installer in package")
        prefix = package.stem + "/"
        notices = archive.read(prefix + LICENSE_FILE).decode("utf-8")
        required = tuple(COMMON_NOTICES) + (tuple(WINDOWS_NOTICES) if sys.platform != "darwin" else ())
        if any(f"=== {name} ===" not in notices for name in required):
            raise RuntimeError("Missing third-party license or copyright notice")
        if any(name.startswith(prefix + "licenses/") for name in archive.namelist()):
            raise RuntimeError("Obsolete separate license directory in package")
        if sys.platform == "darwin":
            bundle = prefix + "obs-air.plugin/Contents/"
            info = plistlib.loads(archive.read(bundle + "Info.plist"))
            if info["CFBundleExecutable"] != "obs-air":
                raise RuntimeError("Wrong bundle executable")
            if info["CFBundleVersion"] != version or info["CFBundleShortVersionString"] != version:
                raise RuntimeError("Wrong bundle version")
            binary = archive.read(bundle + "MacOS/obs-air")
            if struct.unpack_from("<II", binary) != (0xfeedfacf, 0x100000c):
                raise RuntimeError("Plugin is not a native arm64 Mach-O")
            if not archive.getinfo(prefix + "install_obs-air.sh").external_attr >> 16 & 0o111:
                raise RuntimeError("Installer is not executable")
            locale = bundle + "Resources/locale/"
        else:
            binary = archive.read(prefix + "obs-studio/plugins/obs-air/bin/64bit/obs-air.dll")
            offset = struct.unpack_from("<I", binary, 0x3c)[0]
            if binary[offset:offset + 4] != b"PE\0\0" or struct.unpack_from("<H", binary, offset + 4)[0] != 0x8664:
                raise RuntimeError("Plugin is not Windows x64")
            data = archive.read(prefix + "install_obs-air.bat")
            installer = data.decode("ascii")
            if b"\r\r\n" in data or data.count(b"\n") != data.count(b"\r\n"):
                raise RuntimeError("Invalid BAT line endings")
            rules = [line for line in installer.splitlines()
                     if "firewall add rule" in line or "firewall set rule" in line]
            if len(rules) != 2 or any(
                any(option not in rule for option in (
                    'program="%obs_program%"', "dir=in", "action=allow",
                    "profile=private protocol=%~2 localport=any remoteip=LocalSubnet"))
                for rule in rules
            ) or "set /p" in installer.lower():
                raise RuntimeError("Installer firewall scope or unattended setup is incorrect")
            locale = prefix + "obs-studio/plugins/obs-air/data/locale/"
        expected_keys = None
        for language in ("en-US", "zh-CN", "zh-TW"):
            text = archive.read(locale + language + ".ini").decode("utf-8")
            keys = set(re.findall(r"^([A-Za-z]+)=", text, re.M))
            if expected_keys is not None and keys != expected_keys:
                raise RuntimeError(f"Locale key mismatch: {language}")
            expected_keys = keys
            if 'SourceName="AirPlay (OBS-Air)"' not in text or 'haliluya.net' not in text:
                raise RuntimeError(f"Missing source metadata: {language}")
    print(f"Installation ZIP content and architecture passed: {package.name}")


if __name__ == "__main__":
    main()
