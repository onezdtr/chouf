# chouf online

A small web front for chouf, invite only: someone gives an install script URL (with optional arguments, like `-y`),
an npm package or a pip package; chouf runs it in its sandbox, one check at a time, and the report is a web page.
Python standard library only.

What a visitor types only reaches the sandbox as arguments (`"$1"`), never as shell code, and only when it is well
formed (`test_chouf_web.py`). Each check is capped: 240 s, 3 GB of memory, 2 processors, 4096 processes, no local
network. Reports are kept 30 days.

## Set up (on a machine where chouf and chouf-trace already run)

Run it as a user of its own, **without sudo**: the code it runs comes from strangers.

```
sudo useradd -m chouf && sudo loginctl enable-linger chouf
sudo install -d /opt/chouf-web && sudo install -m 644 web/chouf_web.py web/index.html web/app.js /opt/chouf-web/
sudo -iu chouf podman build -t localhost/chouf-ubuntu -f - < web/Containerfile
sudo -iu chouf mkdir -p ~chouf/.config/systemd/user ~chouf/.local/share/chouf-web
sudo install -o chouf -m 644 web/chouf-web.service ~chouf/.config/systemd/user/
echo "SOMECODE alice 10" | sudo -u chouf tee ~chouf/.local/share/chouf-web/codes   # code, label, checks a day
sudo -iu chouf systemctl --user enable --now chouf-web
```

It listens on 127.0.0.1:4800: put it on the Internet behind a reverse proxy (for instance
`tailscale funnel --bg --https=8443 http://127.0.0.1:4800`). Every check is logged in `log.jsonl`.
