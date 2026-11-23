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

pub struct Spec<'a> {
    pub name: String,
    pub image: &'a str,
    pub home: &'a Path,
    pub input: Option<&'a Path>,
    pub cmd: &'a [String],
    pub timeout: Duration,
    pub net: bool,
}

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
    ];
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
