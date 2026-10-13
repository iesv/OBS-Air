"""Fetch the pinned build SDKs. Runtime dependencies are packaged by CMake."""
from pathlib import Path, PurePosixPath
import hashlib
import shutil
import subprocess
import sys
import tarfile
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
DEPS = ROOT / ".deps"


def prepare(name, url, digest, destination, marker, strip_root=False, only_prefix=None):
    target = DEPS / destination
    if (target / marker).is_file():
        return
    archive = DEPS / (name + (".tar.xz" if url.endswith(".tar.xz") else ".dmg" if url.endswith(".dmg") else ".zip"))
    if not archive.exists():
        print(f"Downloading {name}", flush=True)
        with urllib.request.urlopen(url, timeout=120) as response, archive.open("wb") as output:
            shutil.copyfileobj(response, output)
    with archive.open("rb") as source:
        actual_digest = hashlib.file_digest(source, "sha256").hexdigest()
    if actual_digest != digest:
        raise RuntimeError(f"SHA256 mismatch: {archive}. Remove this archive and retry.")
    print(f"Extracting {name}", flush=True)
    if url.endswith(".tar.xz"):
        with tarfile.open(archive) as package:
            package.extractall(target, filter="data")
        if not (target / marker).is_file():
            raise RuntimeError(f"Missing SDK file: {target / marker}")
        return
    if url.endswith(".dmg"):
        volume = DEPS / "obs-volume"
        volume.mkdir(exist_ok=True)
        subprocess.run(["hdiutil", "attach", str(archive), "-nobrowse", "-readonly", "-mountpoint", str(volume)], check=True)
        try:
            shutil.copytree(volume / "OBS.app", target / "OBS.app", symlinks=True)
        finally:
            subprocess.run(["hdiutil", "detach", str(volume)], check=True)
        if not (target / marker).is_file():
            raise RuntimeError(f"Missing OBS runtime: {target / marker}")
        return
    with zipfile.ZipFile(archive) as package:
        for entry in package.infolist():
            if only_prefix and not entry.filename.startswith(only_prefix):
                continue
            parts = PurePosixPath(entry.filename).parts
            if strip_root:
                parts = parts[1:]
            if not parts or entry.is_dir():
                continue
            if ".." in parts or PurePosixPath(entry.filename).is_absolute():
                raise RuntimeError("Archive path is outside the dependency directory")
            output = target.joinpath(*parts)
            output.parent.mkdir(parents=True, exist_ok=True)
            with package.open(entry) as source, output.open("wb") as sink:
                shutil.copyfileobj(source, sink)
    if not (target / marker).is_file():
        raise RuntimeError(f"Missing SDK file: {target / marker}")


def main():
    DEPS.mkdir(exist_ok=True)
    base = "https://github.com/obsproject/obs-deps/releases/download/2025-08-23/"
    if sys.platform == "darwin":
        prepare("obs-deps", base + "macos-deps-2025-08-23-arm64.tar.xz",
                "09cbeb3cbf4fbb9e58e4cf4ca030a724fb1be41d2d7851c8b356f476e04544db",
                "obs-deps", "include/libavcodec/avcodec.h")
        prepare("qt-deps", base + "macos-deps-qt6-2025-08-23-arm64.tar.xz",
                "ed70bb04a5ffc4c820d691e7f1d9913462bc4e018383e98c5548876f6dec0304",
                "qt", "lib/cmake/Qt6Core/Qt6CoreConfig.cmake")
        prepare("obs-runtime", "https://github.com/obsproject/obs-studio/releases/download/32.0.0/OBS-Studio-32.0.0-macOS-Apple.dmg",
                "2107f7dae0649afa9190400ae193f57eaec96fab4f8c216ee08138ed2803c680",
                "obs-runtime", "OBS.app/Contents/Frameworks/libobs.framework/libobs")
    elif sys.platform == "win32":
        prepare("obs-deps", base + "windows-deps-2025-08-23-x64.zip",
            "8de229cff6f1981508c0eb646b35e644633a5855787b9f5d3b90ae2aeb87ffc1",
            "obs-deps", "include/libavcodec/avcodec.h")
        prepare("qt-deps", base + "windows-deps-qt6-2025-08-23-x64.zip",
            "c62e82483bc7c0bf199e8ac3220c66a85a6e8a0cd69a05b6d44f873b830e415f",
            "qt", "lib/cmake/Qt6Core/Qt6CoreConfig.cmake")
        prepare("obs-runtime", "https://github.com/obsproject/obs-studio/releases/download/32.0.0/OBS-Studio-32.0.0-Windows-x64.zip",
                "96ebdcc3e5709825303803e5368b5d7ef04dfbd40c2ce6308fe06a6043066fa0",
                "obs-runtime", "bin/64bit/obs.dll")
    else:
        raise RuntimeError("Build on Windows x64 or macOS arm64")
    prepare("obs-sdk", "https://github.com/obsproject/obs-studio/archive/refs/tags/32.0.0.zip",
            "8b91b13f966d018ef2de20d74b85857374bac263f30e13ec1e9acb0212413b94",
            "obs-studio", "libobs/obs.h", strip_root=True)
    crypto = "openssl/lib/libcrypto.a" if sys.platform == "darwin" else "openssl/lib/libcrypto.lib"
    if not (DEPS / crypto).is_file():
        prepare("openssl-source", "https://github.com/openssl/openssl/archive/refs/tags/openssl-3.5.9.zip",
                "e3365bdecdbcd88b2454a89a5ae526f6cc07cc76eca24753034b37680cd271f3",
                "openssl-source", "Configure", strip_root=True)
        if sys.platform == "win32":
            prepare("perl", "https://github.com/StrawberryPerl/Perl-Dist-Strawberry/releases/download/"
                "SP_54231_64bit/strawberry-perl-5.42.3.1-64bit-portable.zip",
                "6a081a811781c30aca51dbc036afd93092af91e3297901f02c17043795a10690",
                "strawberry", "perl/bin/perl.exe", only_prefix="perl/")
            prepare("jom", "https://download.qt.io/official_releases/jom/jom_1_1_7.zip",
                "4c8af345586a9a08fbfd2f613fcac748226d91a75627aa3581b297dd513046fe",
                "jom", "jom.exe")
    license_file = DEPS / "openssl/LICENSE.txt"
    if not license_file.exists():
        license_file.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(DEPS / "openssl-source/LICENSE.txt", license_file)


if __name__ == "__main__":
    main()
