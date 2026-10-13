"""Create the arm64 OBS plugin bundle, embed required dylibs, and sign it."""
from pathlib import Path
import plistlib
import re
import shutil
import subprocess
from package_licenses import LICENSE_FILE, write_licenses

ROOT = Path(__file__).resolve().parents[1]
DEPS = ROOT / ".deps"
VERSION = re.search(r"project\(OBS-Air VERSION ([0-9.]+)", (ROOT / "CMakeLists.txt").read_text())[1]
NAME = f"OBS-Air-{VERSION}-macos-arm64"
STAGE = ROOT / "build/package" / NAME
BUNDLE = STAGE / "obs-air.plugin"
CONTENTS = BUNDLE / "Contents"


def run(*arguments):
    return subprocess.check_output(arguments, text=True).strip()


def dependencies(binary):
    return [line.strip().split(" (", 1)[0] for line in run("otool", "-L", str(binary)).splitlines()[1:]]


def main():
    if STAGE.exists():
        shutil.rmtree(STAGE)
    (CONTENTS / "MacOS").mkdir(parents=True)
    frameworks = CONTENTS / "Frameworks"
    frameworks.mkdir()
    binary = CONTENTS / "MacOS/obs-air"
    shutil.copy2(ROOT / "build/obs-air", binary)
    shutil.copytree(ROOT / "data", CONTENTS / "Resources")
    info = {
        "CFBundleExecutable": "obs-air", "CFBundleIdentifier": "io.github.iesv.obs-air",
        "CFBundleName": "OBS-Air", "CFBundlePackageType": "BNDL",
        "CFBundleVersion": VERSION, "CFBundleShortVersionString": VERSION,
        "LSMinimumSystemVersion": "12.0",
    }
    (CONTENTS / "Info.plist").write_bytes(plistlib.dumps(info))
    pending = [binary]
    embedded = set()
    while pending:
        current = pending.pop()
        for dependency in dependencies(current):
            if Path(dependency).name == current.name:
                continue  # otool also lists a dylib's own install ID.
            if dependency.startswith(("/System/Library/", "/usr/lib/")):
                continue
            if ".framework/" in dependency:
                name = dependency.split("/")[-1]
                if name not in ("QtCore", "libobs"):
                    raise RuntimeError(f"Unexpected non-system framework: {dependency}")
                replacement = f"@rpath/{name}.framework/Versions/A/{name}"
            else:
                name = Path(dependency).name
                candidate = DEPS / "obs-deps/lib" / name
                if not candidate.is_file():
                    raise RuntimeError(f"Missing runtime dependency: {dependency}")
                if name not in embedded:
                    library = frameworks / ("obs-air-" + name)
                    shutil.copy2(candidate, library)
                    library.chmod(0o755)
                    run("install_name_tool", "-id", f"@rpath/obs-air-{name}", str(library))
                    embedded.add(name)
                    pending.append(library)
                replacement = ("@loader_path/../Frameworks/" if current == binary else "@loader_path/") + "obs-air-" + name
            if dependency != replacement:
                run("install_name_tool", "-change", dependency, replacement, str(current))
    for library in frameworks.iterdir():
        if run("lipo", "-archs", str(library)) != "arm64":
            raise RuntimeError(f"Runtime is not arm64: {library}")
        run("codesign", "--force", "--sign", "-", "--timestamp=none", str(library))
    run("codesign", "--force", "--sign", "-", "--timestamp=none", str(BUNDLE))
    run("codesign", "--verify", "--deep", "--strict", str(BUNDLE))
    for name in ("README.md", "LICENSE", "THIRD_PARTY.md"):
        shutil.copy2(ROOT / name, STAGE / name)
    installer = STAGE / "install_obs-air.sh"
    shutil.copy2(ROOT / "scripts" / installer.name, installer)
    installer.chmod(0o755)
    write_licenses(STAGE / LICENSE_FILE, "macos")
    (ROOT / "dist").mkdir(exist_ok=True)
    run("ditto", "-c", "-k", "--sequesterRsrc", "--keepParent", str(STAGE), str(ROOT / "dist" / (NAME + ".zip")))
    print(f"Created dist/{NAME}.zip; embedded {len(embedded)} runtime libraries")


if __name__ == "__main__":
    main()
