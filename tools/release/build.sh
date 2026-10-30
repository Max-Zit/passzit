#!/bin/bash
# Builds a release into dist/: the server for Linux (deb, rpm and plain
# program for amd64 and arm64) and Windows, the browser extensions,
# third-party licenses and, with the release key, the signed manifest of
# dist/release-V (the files that go on GitHub).
#   bash tools/release/build.sh 0.5.0 [release-notes.md]
set -euo pipefail
V=${1:?version}
NOTES=${2:-}
KEY=${PASSZIT_RELEASE_KEY:-/c/Users/Mili/Ai/release-keys/passzit-release.key}
cd "$(dirname "$0")/../.."
export GOTMPDIR=$PWD/.gotmp CGO_ENABLED=0
mkdir -p dist "$GOTMPDIR"
# Argon2id for the browser (embedded into the server).
go run ./tools/buildwasm
for arch in amd64 arm64; do
  GOOS=linux GOARCH=$arch go build -trimpath -ldflags "-s -w -X main.version=$V" -o "dist/passzit-server-$V-linux-$arch" ./cmd/passzit-server
done
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w -X main.version=$V" -o "dist/passzit-server-$V-windows-amd64.exe" ./cmd/passzit-server
# The helper that opens RDP, SSH and WinBox for the browser extension.
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w -X main.version=$V" -o "dist/passzit-helper-$V-windows-amd64.exe" ./cmd/passzit-helper
for arch in amd64 arm64; do
  GOOS=linux GOARCH=$arch go build -trimpath -ldflags "-s -w -X main.version=$V" -o "dist/passzit-helper-$V-linux-$arch" ./cmd/passzit-helper
done
# Browser extensions (Chromium browsers and Firefox).
go run ./tools/extpack -version "$V" >/dev/null
# Licenses of everything linked into the programs (fails on an unknown license).
go run ./tools/licenses -out THIRD_PARTY_LICENSES.md "dist/passzit-server-$V-linux-amd64" "dist/passzit-server-$V-linux-arm64" "dist/passzit-server-$V-windows-amd64.exe" "dist/passzit-helper-$V-windows-amd64.exe" ./tools/argon2wasm ./tools/qrwasm
cp THIRD_PARTY_LICENSES.md "dist/THIRD_PARTY_LICENSES-$V.md"

# Linux packages of the server.
NFPM="go run github.com/goreleaser/nfpm/v2/cmd/nfpm@v2.43.0"
export VERSION=$V
for arch in amd64 arm64; do
  rm -rf bin/pkg && mkdir -p bin/pkg
  cp "dist/passzit-server-$V-linux-$arch" bin/pkg/passzit-server
  # programs users download from the console (Launcher page): the PassZit
  # helper for Windows and, when given, the MaxZit Launcher from the
  # WatchZit release (MAXZIT_LAUNCHER=path/to/maxzit-launcher-…-windows-amd64.exe)
  mkdir -p bin/pkg/downloads
  cp "dist/passzit-helper-$V-windows-amd64.exe" bin/pkg/downloads/passzit-helper.exe
  if [ -n "${MAXZIT_LAUNCHER:-}" ]; then cp "$MAXZIT_LAUNCHER" bin/pkg/downloads/maxzit-launcher.exe; fi
  export ARCH=$arch
  rm -f "dist/passzit-server_${V}_$arch.deb" dist/passzit-server-"${V}"-1.*.rpm.$arch
  $NFPM package --config packaging/linux/nfpm-server.yaml --packager deb --target dist/ >/dev/null
  $NFPM package --config packaging/linux/nfpm-server.yaml --packager rpm --target dist/ >/dev/null
done

# What goes on GitHub, with the signed manifest.
R="dist/release-$V"
rm -rf "$R" && mkdir -p "$R"
cp "dist/passzit-server-$V-linux-amd64" "dist/passzit-server-$V-linux-arm64" "dist/passzit-server-$V-windows-amd64.exe" \
   "dist/passzit-server_${V}_amd64.deb" "dist/passzit-server_${V}_arm64.deb" \
   "dist/passzit-server-${V}-1.x86_64.rpm" "dist/passzit-server-${V}-1.aarch64.rpm" \
   "dist/passzit-extension-chromium-$V.zip" "dist/passzit-extension-firefox-$V.zip" \
   "dist/passzit-helper-$V-windows-amd64.exe" "dist/passzit-helper-$V-linux-amd64" "dist/passzit-helper-$V-linux-arm64" \
   "dist/THIRD_PARTY_LICENSES-$V.md" packaging/install.sh "$R/"
(cd "$R" && sha256sum $(ls | grep -v '^SHA256SUMS') > SHA256SUMS)
if [ -f "$KEY" ]; then
  go run ./tools/relsign sign -key "$KEY" -version "$V" -dir "$R" ${NOTES:+-notes "$NOTES"}
else
  echo "note: no release key at $KEY; the release is not signed"
fi
echo "built $V"
