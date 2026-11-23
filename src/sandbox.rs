//! The throwaway machine: a rootless podman container, the fake home mounted as /root, everything else copy-on-write.
//! `podman diff` then tells which system files the program added, changed or deleted.

use std::collections::BTreeSet;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

pub const OUTPUT_LIMIT: usize = 1 << 20;

/// What a desktop runs: decoy processes (sleep under other names, in a tmpfs that `podman diff` never shows) so a
/// program that counts processes or looks for a desktop session finds one, and a pid 1 called systemd.
const DECOYS: &str = "systemd-journald systemd-udevd dbus-daemon NetworkManager gdm gnome-shell Xwayland pipewire wireplumber pipewire-pulse gvfsd tracker-miner-fs-3 evolution-source-registry gnome-keyring-daemon firefox code cron sshd cupsd udisksd";

/// The keep-alive script of a live sandbox (its pid 1).
pub fn keepalive() -> Vec<String> {
    let script = format!(
        "d=/dev/shm/.session; mkdir -p $d; for n in systemd {DECOYS}; do ln -sf /bin/sleep $d/$n; done; \
         for n in {DECOYS}; do $d/$n 2147483647 & done; exec $d/systemd 2147483647"
    );
    vec!["/bin/sh".into(), "-c".into(), script]
}

pub struct Spec<'a> {
    pub name: String,
    pub image: &'a str,
    pub home: &'a Path,
    pub input: Option<&'a Path>,
    pub cmd: &'a [String],
    pub timeout: Duration,
    pub net: bool,
    /// Caps for the whole machine, as podman takes them ("2g", "1.5"); None: no cap.
    pub memory: Option<&'a str>,
    pub cpus: Option<&'a str>,
}

/// Processes the machine may hold at once: far more than any installer needs, few enough that a fork bomb in the
/// program under test cannot freeze the computer running chouf.
const PIDS_LIMIT: &str = "--pids-limit=4096";

#[derive(Default)]
pub struct Outcome {
    pub exit: Option<i32>,
    pub timed_out: bool,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub elapsed: Duration,
    pub fs: FsDiff,
}

#[derive(Default, Debug, PartialEq)]
pub struct FsDiff {
    pub added: Vec<String>,
    pub changed: Vec<String>,
    pub deleted: Vec<String>,
}

fn podman(args: &[&str]) -> io::Result<Output> {
    let out = Command::new("podman")
        .args(args)
        .stdin(Stdio::null())
        .output()?;
    if !out.status.success() {
        let msg = String::from_utf8_lossy(&out.stderr);
        return Err(io::Error::other(format!(
            "podman {}: {}",
            args[0],
            msg.trim()
        )));
    }
    Ok(out)
}

/// Removes the container whatever happens.
struct Container<'a>(&'a str);

impl Drop for Container<'_> {
    fn drop(&mut self) {
        let _ = Command::new("podman")
            .args(["rm", "--force", "--time", "0", self.0])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

fn capped(mut r: impl Read + Send + 'static) -> thread::JoinHandle<Vec<u8>> {
    thread::spawn(move || {
        let (mut kept, mut buf) = (Vec::new(), [0u8; 8192]);
        while let Ok(n) = r.read(&mut buf) {
            if n == 0 {
                break;
            }
            let room = OUTPUT_LIMIT.saturating_sub(kept.len());
            kept.extend_from_slice(&buf[..n.min(room)]); // past the limit: keep draining so the program never blocks
        }
        kept
    })
}

/// A created, not yet started container. Creating it relabels the mounts (a walk through the whole fake home):
/// start watching only after that, or the walk looks like the program listing every folder.
pub struct Created<'a> {
    spec: &'a Spec<'a>,
    _container: Container<'a>,
}

pub fn create<'a>(spec: &'a Spec<'a>) -> io::Result<Created<'a>> {
    let home = format!("{}:/root:Z", spec.home.display());
    let mut args = vec![
        "create",
        "--name",
        &spec.name,
        "--hostname",
        "workstation",
        "--pull=missing",
        "--volume",
        &home,
        "--workdir",
        "/root",
        "--env",
        "HOME=/root",
        // what a terminal session has, and not the variable podman sets to say "you are in a container"
        "--unsetenv=container",
        "--env",
        "USER=root",
        "--env",
        "LOGNAME=root",
        "--env",
        "SHELL=/bin/bash",
        "--env",
        "LANG=C.UTF-8",
        "--env",
        "TERM=xterm-256color",
        PIDS_LIMIT,
    ];
    let (memory, cpus);
    if let Some(m) = spec.memory {
        memory = format!("--memory={m}");
        args.push(&memory);
    }
    if let Some(c) = spec.cpus {
        cpus = format!("--cpus={c}");
        args.push(&cpus);
    }
    let input;
    if let Some(dir) = spec.input {
        input = format!("{}:/input:ro,Z", dir.display());
        args.extend(["--volume", &input]);
    }
    if !spec.net {
        args.push("--network=none");
    }
    args.push(spec.image);
    args.extend(spec.cmd.iter().map(String::as_str));
    podman(&args)?;
    let container = Container(&spec.name);
    podman(&["init", &spec.name])?; // mounts and relabels now, not at start
    Ok(Created {
        spec,
        _container: container,
    })
}

pub fn run(spec: &Spec) -> io::Result<Outcome> {
    create(spec)?.start()
}

impl Created<'_> {
    pub fn start(self) -> io::Result<Outcome> {
        let spec = self.spec;
        let started = Instant::now();
        let mut child = Command::new("podman")
            .args(["start", "--attach", &spec.name])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let (out, err) = (
            capped(child.stdout.take().unwrap()),
            capped(child.stderr.take().unwrap()),
        );
        let mut timed_out = false;
        while child.try_wait()?.is_none() {
            if started.elapsed() > spec.timeout {
                timed_out = true;
                let _ = podman(&["kill", &spec.name]);
                child.wait()?;
                break;
            }
            thread::sleep(Duration::from_millis(50));
        }
        let elapsed = started.elapsed();
        let code = podman(&["inspect", "--format", "{{.State.ExitCode}}", &spec.name])?;
        let diff = podman(&["diff", "--format", "json", &spec.name])?;
        Ok(Outcome {
            exit: String::from_utf8_lossy(&code.stdout)
                .trim()
                .parse()
                .ok()
                .filter(|_| !timed_out),
            timed_out,
            stdout: out.join().unwrap_or_default(),
            stderr: err.join().unwrap_or_default(),
            elapsed,
            fs: parse_diff(&diff.stdout)?,
        })
    }
}

/// What one command of an exploration did.
#[derive(Default, Debug)]
pub struct Step {
    pub exit: Option<i32>,
    pub timed_out: bool,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// A running container kept alive (its main process sleeps) so several commands can run in the same machine,
/// one after the other, like a person trying a program: everything they do lands in the same traces and diff.
pub struct Live<'a> {
    spec: &'a Spec<'a>,
    _container: Container<'a>,
    started: Instant,
    /// The sandbox's pid 1 as the host sees it: its process tree is chouf's (decoys), not the program's.
    pub init_pid: u32,
}

impl<'a> Created<'a> {
    /// Starts the container's keep-alive process (the spec's cmd must be one, like `sleep infinity`).
    pub fn start_live(self) -> io::Result<Live<'a>> {
        podman(&["start", &self.spec.name])?;
        let pid = podman(&["inspect", "--format", "{{.State.Pid}}", &self.spec.name])?;
        let init_pid = String::from_utf8_lossy(&pid.stdout).trim().parse().unwrap_or(0);
        thread::sleep(Duration::from_millis(300)); // let the decoys come up before the program looks around
        Ok(Live { spec: self.spec, _container: self._container, started: Instant::now(), init_pid })
    }
}

impl Live<'_> {
    /// Runs argv as root in /root, feeding it `stdin`. A command that outlives `timeout` stops the whole machine:
    /// returns with timed_out set, and no further command can run.
    pub fn exec(&self, argv: &[String], stdin: &str, timeout: Duration) -> io::Result<Step> {
        let started = Instant::now();
        let mut child = Command::new("podman")
            .args(["exec", "--interactive", "--workdir", "/root", &self.spec.name])
            .args(argv)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let mut input = child.stdin.take().unwrap();
        let data = stdin.as_bytes().to_vec();
        let feeder = thread::spawn(move || {
            let _ = std::io::Write::write_all(&mut input, &data); // a program that never reads its input is fine
        });
        let (out, err) = (capped(child.stdout.take().unwrap()), capped(child.stderr.take().unwrap()));
        let mut timed_out = false;
        let status = loop {
            if let Some(st) = child.try_wait()? {
                break Some(st);
            }
            if started.elapsed() > timeout {
                timed_out = true;
                let _ = podman(&["kill", &self.spec.name]);
                let _ = child.wait();
                break None;
            }
            thread::sleep(Duration::from_millis(50));
        };
        let _ = feeder.join();
        Ok(Step {
            exit: status.and_then(|s| s.code()),
            timed_out,
            stdout: out.join().unwrap_or_default(),
            stderr: err.join().unwrap_or_default(),
        })
    }

    /// What changed on the system so far, the machine still running.
    pub fn diff_now(&self) -> io::Result<FsDiff> {
        parse_diff(&podman(&["diff", "--format", "json", &self.spec.name])?.stdout)
    }

    /// A small file inside the machine (at most 64 KiB), or None.
    pub fn read_file(&self, path: &str) -> Option<String> {
        let out = Command::new("podman")
            .args(["exec", &self.spec.name, "head", "-c", "65536", path])
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .ok()?;
        out.status.success().then(|| String::from_utf8_lossy(&out.stdout).into_owned())
    }

    /// Copies a folder of the machine into `dest` (same path below it), from outside: nothing runs inside, so the
    /// tracer sees nothing of it. A missing folder is not an error: there is just nothing to copy.
    pub fn copy_out(&self, path: &str, dest: &Path) {
        let to = dest.join(path.trim_start_matches('/'));
        if let Some(parent) = to.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = Command::new("podman")
            .args(["cp", &format!("{}:{path}", self.spec.name), &to.to_string_lossy()])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }

    /// True while the machine still runs (a timed-out command stops it).
    pub fn alive(&self) -> bool {
        podman(&["inspect", "--format", "{{.State.Running}}", &self.spec.name])
            .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "true")
            .unwrap_or(false)
    }

    /// Stops the machine and returns what changed on its system. The container is removed when this is dropped.
    pub fn finish(self) -> io::Result<(FsDiff, Duration)> {
        let elapsed = self.started.elapsed();
        let _ = podman(&["stop", "--time", "1", &self.spec.name]);
        let diff = podman(&["diff", "--format", "json", &self.spec.name])?;
        Ok((parse_diff(&diff.stdout)?, elapsed))
    }
}

pub fn parse_diff(json: &[u8]) -> io::Result<FsDiff> {
    let v: serde_json::Value = serde_json::from_slice(json).map_err(io::Error::other)?;
    let list = |k: &str| -> Vec<String> {
        let mut l: Vec<String> = v[k]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|x| x.as_str().map(String::from))
            .collect();
        l.sort();
        l
    };
    Ok(FsDiff {
        added: list("added"),
        changed: list("changed"),
        deleted: list("deleted"),
    })
}

/// What the program did, minus what any container does by itself (`noise`), minus directories that only "changed"
/// because something inside them did.
pub fn interesting(d: FsDiff, noise: &BTreeSet<String>) -> FsDiff {
    let all: Vec<&String> = d.added.iter().chain(&d.changed).chain(&d.deleted).collect();
    let is_parent = |p: &String| {
        all.iter().any(|q| {
            q.len() > p.len() && q.starts_with(p.as_str()) && q.as_bytes()[p.len()] == b'/'
        })
    };
    let keep = |l: &Vec<String>, drop_parents: bool| -> Vec<String> {
        l.iter()
            .filter(|p| !noise.contains(*p) && !(drop_parents && is_parent(p)))
            .cloned()
            .collect()
    };
    FsDiff {
        added: keep(&d.added, false),
        changed: keep(&d.changed, true),
        deleted: keep(&d.deleted, false),
    }
}

/// The diff of a container that does nothing, once per image (cached).
pub fn noise(image: &str, cache: &Path) -> io::Result<BTreeSet<String>> {
    let file = cache.join(format!("noise-{}.json", image.replace(['/', ':'], "_")));
    if let Ok(body) = fs::read(&file) {
        if let Ok(v) = serde_json::from_slice::<BTreeSet<String>>(&body) {
            return Ok(v);
        }
    }
    let home: PathBuf = cache.join(format!("empty-home-{}", std::process::id()));
    fs::create_dir_all(&home)?;
    let cmd = ["true".to_string()];
    let spec = Spec {
        name: format!("chouf-noise-{}", std::process::id()),
        image,
        home: &home,
        input: None,
        cmd: &cmd,
        timeout: Duration::from_secs(120),
        net: true,
        memory: None,
        cpus: None,
    };
    let out = run(&spec);
    let _ = fs::remove_dir_all(&home);
    let d = out?.fs;
    let set: BTreeSet<String> = d
        .added
        .into_iter()
        .chain(d.changed)
        .chain(d.deleted)
        .collect();
    fs::write(&file, serde_json::to_vec(&set).map_err(io::Error::other)?)?;
    Ok(set)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parent_directories_and_noise_are_dropped() {
        let d = parse_diff(br#"{"changed":["/etc","/usr","/usr/bin","/etc/passwd","/run"],"added":["/usr/bin/malin","/etc/hostname"],"deleted":["/opt/x"]}"#).unwrap();
        let noise: BTreeSet<String> = ["/etc/hostname".to_string(), "/run".to_string()].into();
        let d = interesting(d, &noise);
        assert_eq!(d.added, vec!["/usr/bin/malin"]);
        assert_eq!(d.changed, vec!["/etc/passwd"]); // /etc stays out: /etc/passwd explains it
        assert_eq!(d.deleted, vec!["/opt/x"]);
    }

    #[test]
    fn a_lone_changed_directory_is_kept() {
        // "/usrlocal" is not inside "/usr": prefix matching must stop at a path boundary
        let d = parse_diff(br#"{"changed":["/usr","/var/lib"],"added":["/usrlocal"]}"#).unwrap();
        assert_eq!(
            interesting(d, &BTreeSet::new()).changed,
            vec!["/usr", "/var/lib"]
        );
    }
}
