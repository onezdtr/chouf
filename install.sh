#!/bin/sh
# Install chouf, from a release archive (binaries next to this script) or from the source tree (built first).
#   ./install.sh            chouf only, in ~/.local/bin (no root needed; the kernel tracer is left out)
#   sudo ./install.sh       chouf in /usr/local/bin, and the kernel tracer chouf-trace as a system service
# chouf needs rootless podman. The tracer (root) is optional: it says which program did what, where it connected,
# keeps the sandbox off your local network and proves what left the machine.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
command -v podman >/dev/null || echo "warning: podman is not installed; chouf needs it (apt install podman / dnf install podman)"

if [ ! -x "$HERE/chouf" ]; then # source tree: build, as the invoking user when run with sudo
    BUILD="cargo build --release --workspace"
    if [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_USER:-}" ]; then runuser -u "$SUDO_USER" -- sh -c "cd '$HERE' && $BUILD"; else (cd "$HERE" && $BUILD); fi
    BIN="$HERE/target/release"
    UNIT="$HERE/trace/chouf-trace.service"
else
    BIN="$HERE"
    UNIT="$HERE/chouf-trace.service"
fi

if [ "$(id -u)" -ne 0 ]; then
    mkdir -p "$HOME/.local/bin"
    install -m 755 "$BIN/chouf" "$HOME/.local/bin/chouf"
    echo "chouf installed in ~/.local/bin (make sure it is in your PATH)."
    echo "For the kernel tracer (who did what, network guard, proof of theft): sudo $0"
    exit 0
fi

install -m 755 "$BIN/chouf" /usr/local/bin/chouf
install -m 755 "$BIN/chouf-trace" /usr/local/bin/chouf-trace
install -m 644 "$UNIT" /etc/systemd/system/chouf-trace.service
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload
    systemctl enable chouf-trace.service >/dev/null 2>&1
    systemctl restart chouf-trace.service
fi
echo "chouf and its kernel tracer are installed. Try: chouf run -- sh -c 'cat ~/.ssh/id_ed25519'"
