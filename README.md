# chouf

*chouf* (« look » in Darija) runs a program in a throwaway sandbox full of **bait secrets** and tells you, in plain words,
what it really did: which secrets it went after, how it will start again by itself, what it now trusts.

```
$ chouf run --file install-theme.sh -- sh /input/install-theme.sh

Secrets it went after
 ! opened, read ~/.aws/credentials  (AWS access keys)
 ! opened, read ~/.config/google-chrome/Default/Cookies  (Chrome cookies)
 ! listed    ~/.mozilla/firefox/k3x9.default-release  (looked inside the folder of: Firefox cookies)
 ! opened, read ~/.ssh/id_ed25519  (SSH private key)

Ways it will run again by itself
 ! added     /etc/cron.d/theme-update  (scheduled task)
 ! opened, wrote ~/.bashrc  (runs in every new terminal)

What it now trusts
 ! added     /etc/apt/sources.list.d/theme.list  (adds a software source)
```

## How it works

- **A rootless podman container** (Ubuntu 24.04 by default). The program runs as root inside it, so installers behave as
  they would with `sudo`, but only the container's copy of the system is touched. `podman diff` gives every system file
  added, changed or deleted, minus what an empty container does by itself (measured once per image).
- **A fake home full of bait**: SSH and GPG keys, AWS, GitHub, npm, Docker and Kubernetes credentials, Chrome and Firefox
  cookies and passwords, a Bitcoin wallet, a `.env`, a shell history with an API key. None of it is real, and every value
  carries a token unique to the run, so a leaked secret can be traced back to the run that leaked it.
- **inotify from the host**: the fake home is a bind mount, so every open, read, write, create and delete inside it is
  seen from outside, without root, including files written into folders created a microsecond earlier.

## Usage

```
chouf run [--image IMAGE] [--timeout SECS] [--no-net] [--file PATH]... -- COMMAND [ARGS]...
```

Exit code: 0 nothing alarming, 1 secrets / persistence / trust findings, 2 chouf itself failed.
Each run is kept in `~/.local/share/chouf/sessions/<id>/` (`report.json`, `stdout`, `stderr`, the fake home).

## Status

Early. Next: a kernel tracer (eBPF) to know *which process* did what and where it connected, an agent that explores
the program (sub-commands, interactive prompts, waiting for delayed behaviour) and compares what it claims with what it
does.

## Tests

```
cargo test                          # unit tests
cargo test -- --include-ignored     # + real runs through podman
```

## License

GPL-2.0-only
