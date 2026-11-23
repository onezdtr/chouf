#!/bin/sh
# Install or update chouf from the latest release, no compiler needed:
#   curl -fsSL https://raw.githubusercontent.com/onezdtr/chouf/main/get.sh | sudo sh
set -eu
REPO=onezdtr/chouf
case $(uname -m) in
x86_64) ARCH=x86_64 ;;
aarch64 | arm64) ARCH=aarch64 ;;
*) echo "no chouf build for $(uname -m) yet: build from source (see README)"; exit 1 ;;
esac
TAG=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n 1)
[ -n "$TAG" ] || { echo "could not find the latest release of $REPO"; exit 1; }
NAME=chouf-$TAG-$ARCH
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
echo "downloading chouf $TAG ($ARCH)"
curl -fsSL -o "$TMP/$NAME.tar.gz" "https://github.com/$REPO/releases/download/$TAG/$NAME.tar.gz"
curl -fsSL -o "$TMP/$NAME.tar.gz.sha256" "https://github.com/$REPO/releases/download/$TAG/$NAME.tar.gz.sha256"
(cd "$TMP" && sha256sum -c --quiet "$NAME.tar.gz.sha256")
tar xzf "$TMP/$NAME.tar.gz" -C "$TMP" --no-same-owner
"$TMP/$NAME/install.sh"
