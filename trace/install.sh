#!/bin/sh
# Build and install chouf-trace as a system service. Run from the repository: sudo ./trace/install.sh
# (it builds as the invoking user first, so cargo does not run as root).
set -eu
cd "$(dirname "$0")/.."
if [ "$(id -u)" -ne 0 ]; then echo "run with sudo: sudo $0"; exit 1; fi
USER_NAME=${SUDO_USER:-root}
runuser -u "$USER_NAME" -- cargo build --release -p chouf-trace
install -m 755 target/release/chouf-trace /usr/local/bin/chouf-trace
install -m 644 trace/chouf-trace.service /etc/systemd/system/chouf-trace.service
systemctl daemon-reload
systemctl enable chouf-trace.service >/dev/null 2>&1
systemctl restart chouf-trace.service
echo "chouf-trace is running: chouf will now say which process did what."
