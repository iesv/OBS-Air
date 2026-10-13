#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ "$(uname -m)" != arm64 ]]; then
  echo "Use an Apple Silicon arm64 build runner" >&2
  exit 1
fi
python3 scripts/prepare.py
if [[ ! -f .deps/openssl/lib/libcrypto.a ]]; then
  prefix="$PWD/.deps/openssl"
  (
    cd .deps/openssl-source
    CFLAGS="-arch arm64 -mmacosx-version-min=12.0" perl Configure darwin64-arm64-cc \
      no-asm no-shared no-tests no-module "--prefix=$prefix"
    make -j 3 build_libs
    make install_dev
  )
fi
cmake --preset macos-arm64
cmake --build --preset macos-arm64 --parallel 3
ctest --preset macos-arm64
python3 scripts/package_macos.py
python3 scripts/check_package.py
