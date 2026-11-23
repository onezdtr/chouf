#!/usr/bin/env python3
"""chouf online: a small web front for chouf, invite only.

Someone with an invite code gives an install script URL, an npm package or a pip package; chouf runs it in its
sandbox on this machine, one at a time, and the report is served as a page. Standard library only.

  CHOUF_WEB_DATA  where codes, logs and reports live (default ~/.local/share/chouf-web)
  CHOUF_WEB_PORT  port on 127.0.0.1 (default 4800); put it on the Internet with a reverse proxy (Tailscale Funnel)

Invite codes: one per line in $CHOUF_WEB_DATA/codes, "CODE LABEL RUNS_PER_DAY" (# starts a comment).
"""

import datetime
import hmac
import json
import os
import queue
import re
import secrets
import shutil
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

DATA = Path(os.environ.get("CHOUF_WEB_DATA", Path.home() / ".local/share/chouf-web"))
PORT = int(os.environ.get("CHOUF_WEB_PORT", "4800"))
CHOUF = os.environ.get("CHOUF_BIN", "chouf")
HERE = Path(__file__).resolve().parent

# What one run may use on this machine: the sandbox is capped, the whole run too (pull, report, clean-up).
LIMITS = ["--timeout", "240", "--memory", "3g", "--cpus", "2"]
RUN_SECONDS = 420
MAX_WAITING = 8
REPORT_DAYS = 30

# The machines each kind of check runs in. The script one is ubuntu with curl (web/Containerfile, built by install.sh).
IMAGES = {
    "script": "localhost/chouf-ubuntu",
    "npm": "docker.io/library/node:22",
    "pip": "docker.io/library/python:3.12",
}

# Trust boundary: what a visitor types only ever reaches the sandbox as one argument ("$1"), never as shell code.
# (no $ ( ) ' ` in URLs: they never reach a shell anyway, and no install script needs them)
URL = re.compile(r"https://[A-Za-z0-9.-]+(?::\d{1,5})?(?:/[A-Za-z0-9._~!&*+,;=:@%/-]*)?(?:\?[A-Za-z0-9._~!&*+,;=:@%/?-]*)?")
NPM = re.compile(r"(?:@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*(?:@[A-Za-z0-9.^~<>=*|+ -]{1,40})?")
PIP = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*(?:\[[A-Za-z0-9,._-]+\])?(?:(?:==|>=|<=|~=|!=|<|>)[A-Za-z0-9.*+!-]{1,40})?")
JOB_ID = re.compile(r"[A-Za-z0-9_-]{16}")
ARG = re.compile(r"-{0,2}[A-Za-z0-9][A-Za-z0-9=._,:/+@-]{0,60}")


def valid_args(text):
    """The words given to an install script (`| sh -s -- -y`), or None: at most 6 plain options or values."""
    words = (text or "").split()
    if len(words) > 6 or not all(ARG.fullmatch(w) for w in words):
        return None
    return words


def valid(kind, target):
    """The target if it is a well-formed thing of that kind, else None."""
    t = (target or "").strip()
    if not t or len(t) > 300:
        return None
    pattern = {"script": URL, "npm": NPM, "pip": PIP}.get(kind)
    if pattern is None or not pattern.fullmatch(t):
        return None
    if kind == "npm" and len(t.split("@")[0 if not t.startswith("@") else 1]) > 214:
        return None
    return t


def command(kind, target, args=()):
    """The command run inside the sandbox; the target (and a script's words) are arguments, read as "$1", "$@"."""
    if kind == "script":
        return ["bash", "-c", 'url=$1; shift; curl -fsSL --proto =https --max-time 60 -- "$url" | bash -s -- "$@"', "chouf", target, *args]
    if kind == "npm":
        return ["sh", "-c", 'mkdir -p /tmp/project && cd /tmp/project && npm init -y >/dev/null && npm install --no-fund --no-audit -- "$1"', "chouf", target]
    return ["pip", "install", "--no-cache-dir", "--root-user-action=ignore", "--", target]


def chouf_argv(kind, target, lang, args=()):
    return [CHOUF, "run", "--image", IMAGES[kind], "--lang", lang, *LIMITS, "--", *command(kind, target, args)]


def load_codes():
    """{code: (label, runs per day)} from the codes file."""
    codes = {}
    try:
        lines = (DATA / "codes").read_text().splitlines()
    except OSError:
        return codes
    for line in lines:
        parts = line.split("#")[0].split()
        if len(parts) >= 2:
            codes[parts[0]] = (parts[1], int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 10)
    return codes


def check_code(given):
    """The (label, quota) of a code, compared in constant time; None when no code matches."""
    found = None
    for code, info in load_codes().items():
        if hmac.compare_digest(code.encode(), (given or "").encode()):
            found = info
    return found


def log(entry):
    entry["at"] = datetime.datetime.now().isoformat(timespec="seconds")
    with open(DATA / "log.jsonl", "a") as f:
        f.write(json.dumps(entry) + "\n")


def runs_today(label):
    today = datetime.date.today().isoformat()
    try:
        lines = (DATA / "log.jsonl").read_text().splitlines()
    except OSError:
        return 0
    return sum(1 for l in lines if '"queued"' in l and json.loads(l).get("label") == label and json.loads(l)["at"].startswith(today))


class Failures:
    """Wrong invite codes per address: 10 an hour, then refused (guessing codes takes forever)."""

    def __init__(self):
        self.seen = {}
        self.lock = threading.Lock()

    def blocked(self, ip):
        with self.lock:
            now = time.time()
            self.seen[ip] = [t for t in self.seen.get(ip, []) if now - t < 3600]
            return len(self.seen[ip]) >= 10

    def add(self, ip):
        with self.lock:
            self.seen.setdefault(ip, []).append(time.time())


FAILURES = Failures()
JOBS = {}  # id -> {"state": "waiting"|"running"|"done"|"failed", "kind", "target", "exit"}
WAITING = queue.Queue()
LOCK = threading.Lock()


def remove_session(path):
    """A session holds files owned by the sandbox's users: removed from inside the user namespace."""
    subprocess.run(["podman", "unshare", "rm", "-rf", "--", str(path)], stdin=subprocess.DEVNULL, capture_output=True, timeout=120)
    shutil.rmtree(path, ignore_errors=True)


def run_job(job_id):
    job = JOBS[job_id]
    sessions = DATA / "sessions"
    env = dict(os.environ, CHOUF_DATA=str(sessions))
    started = time.time()
    try:
        out = subprocess.run(chouf_argv(job["kind"], job["target"], job["lang"], job["args"]), stdin=subprocess.DEVNULL,
                             capture_output=True, text=True, timeout=RUN_SECONDS, env=env)
        found = re.search(r"^session: (\S+)", out.stdout, re.M)
        session = Path(found.group(1)) if found else None
        if session and (session / "report.html").is_file() and session.resolve().is_relative_to(sessions.resolve()):
            shutil.copy(session / "report.html", DATA / "reports" / f"{job_id}.html")
            shutil.copy(session / "report.json", DATA / "reports" / f"{job_id}.json")
            job.update(state="done", exit=out.returncode)
        else:
            job.update(state="failed", exit=out.returncode, error=(out.stderr or out.stdout)[-300:])
        if session and session.resolve().is_relative_to(sessions.resolve()):
            remove_session(session)
    except subprocess.TimeoutExpired:
        job.update(state="failed", exit=None, error="took too long")
    log({"event": "finished", "job": job_id, "label": job["label"], "state": job["state"], "exit": job.get("exit"),
         "seconds": round(time.time() - started)})


def worker():
    while True:
        job_id = WAITING.get()
        JOBS[job_id]["state"] = "running"
        try:
            run_job(job_id)
        except Exception as e:  # one broken run must not stop the queue
            JOBS[job_id].update(state="failed", error=str(e)[:300])


def clean_old_reports():
    while True:
        limit = time.time() - REPORT_DAYS * 86400
        for f in (DATA / "reports").glob("*"):
            if f.stat().st_mtime < limit:
                f.unlink(missing_ok=True)
        time.sleep(3600)


def position(job_id):
    with WAITING.mutex:
        waiting = list(WAITING.queue)
    return waiting.index(job_id) + 1 if job_id in waiting else 0


class Handler(BaseHTTPRequestHandler):
    server_version = "chouf-web"
    sys_version = ""

    def ip(self):
        # behind the proxy, the visitor is the first address it forwards
        return (self.headers.get("X-Forwarded-For") or self.client_address[0]).split(",")[0].strip()

    def send(self, code, body, ctype="application/json", extra=None):
        data = body if isinstance(body, bytes) else (json.dumps(body) if ctype == "application/json" else body).encode()
        self.send_response(code)
        self.send_header("Content-Type", f"{ctype}; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass  # requests are logged by what they do (log.jsonl), not one line each

    def do_GET(self):
        path = self.path.split("?")[0]
        if path in ("/", "/index.html"):
            page = (HERE / "index.html").read_bytes()
            csp = "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'"
            return self.send(200, page, "text/html", {"Content-Security-Policy": csp})
        if path == "/app.js":
            return self.send(200, (HERE / "app.js").read_bytes(), "text/javascript")
        m = re.fullmatch(r"/api/job/([A-Za-z0-9_-]+)", path)
        if m and JOB_ID.fullmatch(m.group(1)) and m.group(1) in JOBS:
            j = JOBS[m.group(1)]
            return self.send(200, {"state": j["state"], "position": position(m.group(1)), "exit": j.get("exit"), "error": j.get("error")})
        m = re.fullmatch(r"/r/([A-Za-z0-9_-]+)", path)
        if m and JOB_ID.fullmatch(m.group(1)) and (DATA / "reports" / f"{m.group(1)}.html").is_file():
            # the report page escapes everything and carries its own strict CSP; this one forbids any script at all
            csp = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'"
            return self.send(200, (DATA / "reports" / f"{m.group(1)}.html").read_bytes(), "text/html", {"Content-Security-Policy": csp})
        self.send(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/api/run":
            return self.send(404, {"error": "not found"})
        size = int(self.headers.get("Content-Length") or 0)
        if size <= 0 or size > 4096:
            return self.send(400, {"error": "bad request"})
        try:
            req = json.loads(self.rfile.read(size))
            kind, target, code, args = req["kind"], req["target"], req["code"], req.get("args", "")
            assert all(isinstance(x, str) for x in (kind, target, code, args))
        except Exception:
            return self.send(400, {"error": "bad request"})
        ip = self.ip()
        if FAILURES.blocked(ip):
            return self.send(429, {"error": "too many wrong codes, try again in an hour"})
        who = check_code(code)
        if who is None:
            FAILURES.add(ip)
            log({"event": "bad code", "ip": ip})
            return self.send(403, {"error": "unknown invite code"})
        label, quota = who
        target, args = valid(kind, target), valid_args(args) if kind == "script" else []
        if args is None:
            return self.send(400, {"error": "arguments: at most 6 plain words, like -y or --default-toolchain=stable"})
        if target is None:
            return self.send(400, {"error": "not a valid " + {"script": "https:// script address", "npm": "npm package name", "pip": "pip package name"}.get(kind, "kind")})
        with LOCK:
            if runs_today(label) >= quota:
                return self.send(429, {"error": f"this code has used its {quota} runs for today"})
            if WAITING.qsize() >= MAX_WAITING:
                return self.send(503, {"error": "too many checks waiting, try again in a few minutes"})
            job_id = secrets.token_urlsafe(12)
            lang = "fr" if (self.headers.get("Accept-Language") or "").lower().startswith("fr") else "en"
            JOBS[job_id] = {"state": "waiting", "kind": kind, "target": target, "args": args, "label": label, "lang": lang}
            log({"event": "queued", "job": job_id, "label": label, "kind": kind, "target": target, "args": args, "ip": ip})
            WAITING.put(job_id)
        self.send(200, {"job": job_id})


def main():
    for d in ("reports", "sessions"):
        (DATA / d).mkdir(parents=True, exist_ok=True)
    threading.Thread(target=worker, daemon=True).start()
    threading.Thread(target=clean_old_reports, daemon=True).start()
    server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"chouf-web on http://127.0.0.1:{PORT}, data in {DATA}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
