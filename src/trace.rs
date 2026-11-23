//! Which process did what, from the kernel: the client side of chouf-trace (a root service, see trace/).
//! chouf asks it to watch the container's cgroup after `podman init` and before `podman start`, so nothing the
//! program does is missed. Without the service, chouf still works; the report only lacks the "who" and the network.

use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::io::{self, BufRead, BufReader, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::Command;
use std::thread;
use std::time::Duration;

pub const SOCK: &str = "/run/chouf-trace.sock";
const MAX_EVENTS: usize = 500_000;

/// The cgroup podman made for a created (or initialized) container: the scope above the container's own cgroup,
/// so whatever the program spawns in sub-cgroups is watched too.
pub fn cgroup_of(container: &str) -> io::Result<PathBuf> {
    let out = Command::new("podman")
        .args(["inspect", "--format", "{{.State.Pid}}", container])
        .output()?;
    let pid = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if pid.is_empty() || pid == "0" {
        return Err(io::Error::other("the container has no process yet"));
    }
    let line = fs::read_to_string(format!("/proc/{pid}/cgroup"))?;
    let rel = line
        .lines()
        .find_map(|l| l.strip_prefix("0::"))
        .ok_or_else(|| io::Error::other("no cgroup v2"))?;
    let dir = PathBuf::from(format!("/sys/fs/cgroup{rel}"));
    Ok(match dir.file_name().and_then(|n| n.to_str()) {
        Some("container") => dir.parent().map(PathBuf::from).unwrap_or(dir),
        _ => dir,
    })
}

pub struct Tracer {
    stream: UnixStream,
    reader: thread::JoinHandle<(Vec<Value>, bool)>,
}

impl Tracer {
    /// Ok(None) when the service is not installed; Err when it refused.
    pub fn start(container: &str) -> io::Result<Option<Tracer>> {
        let sock = std::env::var("CHOUF_TRACE_SOCK").unwrap_or_else(|_| SOCK.to_string());
        let Ok(stream) = UnixStream::connect(sock) else {
            return Ok(None);
        };
        let cg = cgroup_of(container)?;
        let mut w = stream.try_clone()?;
        writeln!(w, "{}", json!({"watch": cg}))?;
        let mut r = BufReader::new(stream.try_clone()?);
        let mut first = String::new();
        r.read_line(&mut first)?;
        let hello: Value = serde_json::from_str(&first).unwrap_or(Value::Null);
        if let Some(e) = hello.get("error").and_then(Value::as_str) {
            return Err(io::Error::other(format!("chouf-trace: {e}")));
        }
        let reader = thread::spawn(move || {
            let (mut events, mut lost) = (Vec::new(), false);
            for line in r.lines().map_while(Result::ok) {
                if events.len() >= MAX_EVENTS {
                    lost = true;
                    continue;
                }
                if let Ok(v) = serde_json::from_str(&line) {
                    events.push(v);
                }
            }
            (events, lost)
        });
        Ok(Some(Tracer { stream, reader }))
    }

    /// Ends the watch and returns everything seen. The short wait lets the last events of the run reach us.
    pub fn stop(self) -> Activity {
        thread::sleep(Duration::from_millis(600));
        let _ = self.stream.shutdown(Shutdown::Write); // the service ends the watch and closes its side
        let (events, lost) = self.reader.join().unwrap_or_default();
        Activity::from_events(&events, lost)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Exec {
    pub t: i64,
    pub file: String,
    pub args: Vec<String>,
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct Proc {
    pub ppid: u32,
    pub comm: String,
    /// Every program this pid became (exec replaces a process in place: bash → sh).
    pub execs: Vec<Exec>,
    pub exit: Option<i64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Open {
    pub t: i64,
    pub pid: u32,
    pub path: String,
    pub writes: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Conn {
    pub pid: u32,
    pub proto: &'static str,
    pub ip: String,
    pub port: u64,
    pub name: Option<String>,
}

#[derive(Debug, Default)]
pub struct Activity {
    pub procs: BTreeMap<u32, Proc>,
    pub opens: Vec<Open>,
    pub conns: Vec<Conn>,
    pub lost: bool,
}

/// How a command line is shown: what ran, short enough for one line.
fn short(args: &[String], file: &str) -> String {
    let s = if args.is_empty() { file.to_string() } else { args.join(" ") };
    let s = s.replace(['\n', '\r', '\t'], " ");
    if s.chars().count() > 90 {
        format!("{}…", s.chars().take(89).collect::<String>())
    } else {
        s
    }
}

impl Activity {
    pub fn from_events(events: &[Value], lost: bool) -> Activity {
        let mut a = Activity { lost, ..Default::default() };
        let mut names: HashMap<String, String> = HashMap::new();
        let mut seen_opens = BTreeSet::new();
        let mut seen_conns = BTreeSet::new();
        for e in events {
            let pid = e["pid"].as_u64().unwrap_or(0) as u32;
            let t = e["t"].as_i64().unwrap_or(0);
            let comm = e["comm"].as_str().unwrap_or("").to_string();
            match e["kind"].as_str() {
                Some("exec") => {
                    let p = a.procs.entry(pid).or_default();
                    p.ppid = e["ppid"].as_u64().unwrap_or(0) as u32;
                    p.comm = comm;
                    p.execs.push(Exec {
                        t,
                        file: e["file"].as_str().unwrap_or("").into(),
                        args: e["args"].as_array().into_iter().flatten().filter_map(|x| x.as_str().map(String::from)).collect(),
                    });
                }
                Some("fork") => {
                    let p = a.procs.entry(pid).or_default();
                    p.ppid = e["ppid"].as_u64().unwrap_or(0) as u32;
                    p.comm = comm;
                }
                Some("exit") => {
                    if let Some(p) = a.procs.get_mut(&pid) {
                        p.exit = e["code"].as_i64();
                    }
                }
                Some("open") => {
                    let path = e["path"].as_str().unwrap_or("").to_string();
                    let writes = e["mode"].as_str() != Some("read") || e["create"].as_bool() == Some(true);
                    // overlayfs checks each open twice (the file shown, then the real one): keep one
                    if !path.is_empty() && seen_opens.insert((pid, path.clone(), writes, t / 50)) {
                        a.opens.push(Open { t, pid, path, writes });
                    }
                }
                Some(k @ ("connect" | "udp")) => {
                    let ip = e["ip"].as_str().unwrap_or("").to_string();
                    let port = e["port"].as_u64().unwrap_or(0);
                    if k == "udp" && port == 53 {
                        continue; // a DNS question: its answer names the next connections instead
                    }
                    if seen_conns.insert((pid, ip.clone(), port, k)) {
                        a.conns.push(Conn { pid, proto: if k == "connect" { "tcp" } else { "udp" }, name: names.get(&ip).cloned(), ip, port });
                    }
                }
                Some("dns") => {
                    for ans in e["answers"].as_array().into_iter().flatten() {
                        if let (Some(ip), Some(n)) = (ans["ip"].as_str(), ans["name"].as_str()) {
                            names.insert(ip.into(), n.into());
                        }
                    }
                }
                _ => {}
            }
        }
        a
    }

    /// The closest ancestor that ran a program of its own (a forked subshell does not: it is its parent's code).
    fn shown_parent(&self, pid: u32) -> Option<u32> {
        let mut cur = self.procs.get(&pid)?.ppid;
        for _ in 0..64 {
            let p = self.procs.get(&cur)?;
            if !p.execs.is_empty() {
                return Some(cur);
            }
            cur = p.ppid;
        }
        None
    }

    /// The program a pid was running at time t, as its command line; a subshell answers as the script it came from.
    pub fn who(&self, pid: u32, t: i64) -> String {
        match self.procs.get(&pid) {
            Some(p) => match p.execs.iter().rev().find(|x| x.t <= t).or(p.execs.first()) {
                Some(x) => short(&x.args, &x.file),
                None => match self.shown_parent(pid) {
                    Some(parent) => self.who(parent, t),
                    None if !p.comm.is_empty() => p.comm.clone(),
                    None => format!("process {pid}"),
                },
            },
            None => format!("process {pid}"),
        }
    }

    /// The programs that opened a path inside the container, and whether any of them wrote.
    pub fn openers(&self, container_path: &str) -> (Vec<String>, bool) {
        let mut who = Vec::new();
        let mut wrote = false;
        for o in self.opens.iter().filter(|o| o.path == container_path) {
            let w = self.who(o.pid, o.t);
            if !who.contains(&w) {
                who.push(w);
            }
            wrote |= o.writes;
        }
        (who, wrote)
    }

    /// The process tree, depth first, as (depth, command line, exit code).
    pub fn tree(&self) -> Vec<(usize, String, Option<i64>)> {
        // only processes that ran a program are shown; forked subshells pass their children up
        let mut kids: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
        let mut roots = Vec::new();
        for (pid, p) in self.procs.iter().filter(|(_, p)| !p.execs.is_empty()) {
            match self.shown_parent(*pid).filter(|pp| pp != pid) {
                Some(pp) => kids.entry(pp).or_default().push(*pid),
                None => roots.push(*pid),
            }
        }
        let mut out = Vec::new();
        let mut stack: Vec<(u32, usize)> = roots.into_iter().rev().map(|p| (p, 0)).collect();
        let mut visited = BTreeSet::new();
        while let Some((pid, depth)) = stack.pop() {
            if !visited.insert(pid) || out.len() >= 400 {
                continue;
            }
            let p = &self.procs[&pid];
            for x in &p.execs {
                out.push((depth, short(&x.args, &x.file), None));
            }
            if let (Some(last), Some(code)) = (out.last_mut(), p.exit) {
                last.2 = Some(code);
            }
            for k in kids.get(&pid).into_iter().flatten().rev() {
                stack.push((*k, depth + 1));
            }
        }
        out
    }

    pub fn json(&self) -> Value {
        json!({
            "programs": self.tree().iter().map(|(d, c, x)| json!({"depth": d, "command": c, "exit": x})).collect::<Vec<_>>(),
            "connections": self.conns.iter().map(|c| json!({"by": self.who(c.pid, i64::MAX), "proto": c.proto, "ip": c.ip, "port": c.port, "name": c.name})).collect::<Vec<_>>(),
            "events_lost": self.lost,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(v: Value) -> Value {
        v
    }

    fn sample() -> Activity {
        let events = vec![
            ev(json!({"kind":"exec","t":1,"pid":10,"ppid":1,"comm":"bash","file":"/usr/bin/bash","args":["bash","-c","x"]})),
            ev(json!({"kind":"exec","t":2,"pid":11,"ppid":10,"comm":"cat","file":"/usr/bin/cat","args":["cat","/root/.ssh/id_ed25519"]})),
            ev(json!({"kind":"open","t":3,"pid":11,"comm":"cat","path":"/root/.ssh/id_ed25519","mode":"read","create":false})),
            ev(json!({"kind":"open","t":3,"pid":11,"comm":"cat","path":"/root/.ssh/id_ed25519","mode":"read","create":false})),
            ev(json!({"kind":"exit","t":4,"pid":11,"comm":"cat","code":0})),
            ev(json!({"kind":"udp","t":5,"pid":12,"comm":"getent","ip":"169.254.1.1","port":53})),
            ev(json!({"kind":"dns","t":6,"answers":[{"ip":"93.184.216.34","name":"example.com"}]})),
            ev(json!({"kind":"connect","t":7,"pid":10,"comm":"bash","ip":"93.184.216.34","port":443})),
            ev(json!({"kind":"connect","t":8,"pid":10,"comm":"bash","ip":"93.184.216.34","port":443})),
            ev(json!({"kind":"open","t":9,"pid":10,"comm":"bash","path":"/root/.bashrc","mode":"write","create":false})),
            ev(json!({"kind":"exec","t":10,"pid":10,"ppid":1,"comm":"sh","file":"/usr/bin/sh","args":["sh","-c","echo bye"]})),
            ev(json!({"kind":"exit","t":11,"pid":10,"comm":"sh","code":3})),
        ];
        Activity::from_events(&events, false)
    }

    #[test]
    fn who_opened_a_bait_once_per_open() {
        let a = sample();
        assert_eq!(a.opens.iter().filter(|o| o.path.ends_with("id_ed25519")).count(), 1);
        assert_eq!(a.openers("/root/.ssh/id_ed25519"), (vec!["cat /root/.ssh/id_ed25519".to_string()], false));
        // the pid was still bash when it wrote .bashrc, sh only after
        assert_eq!(a.openers("/root/.bashrc"), (vec!["bash -c x".to_string()], true));
        assert_eq!(a.openers("/nowhere"), (vec![], false));
    }

    #[test]
    fn connections_are_named_deduplicated_and_dns_questions_dropped() {
        let a = sample();
        assert_eq!(a.conns.len(), 1);
        assert_eq!(a.conns[0].name.as_deref(), Some("example.com"));
        assert_eq!((a.conns[0].proto, a.conns[0].port), ("tcp", 443));
    }

    #[test]
    fn tree_follows_parents_and_execs() {
        let t = sample().tree();
        assert_eq!(
            t,
            vec![
                (0, "bash -c x".to_string(), None),
                (0, "sh -c echo bye".to_string(), Some(3)),
                (1, "cat /root/.ssh/id_ed25519".to_string(), Some(0)),
            ]
        );
    }

    #[test]
    fn a_subshell_is_transparent() {
        let events = vec![
            json!({"kind":"exec","t":1,"pid":10,"ppid":1,"comm":"sh","file":"/bin/sh","args":["sh","install.sh"]}),
            json!({"kind":"fork","t":2,"pid":20,"ppid":10,"comm":"sh"}),
            json!({"kind":"open","t":3,"pid":20,"comm":"sh","path":"/root/.netrc","mode":"read","create":false}),
            json!({"kind":"exec","t":4,"pid":21,"ppid":20,"comm":"cat","file":"/bin/cat","args":["cat","/root/.ssh/id_rsa"]}),
        ];
        let a = Activity::from_events(&events, false);
        assert_eq!(a.tree(), vec![(0, "sh install.sh".to_string(), None), (1, "cat /root/.ssh/id_rsa".to_string(), None)]);
        assert_eq!(a.openers("/root/.netrc").0, vec!["sh install.sh".to_string()]);
    }

    #[test]
    fn long_and_multiline_commands_stay_on_one_line() {
        let s = short(&["sh".into(), "-c".into(), format!("a\nb {}", "x".repeat(200))], "/bin/sh");
        assert!(!s.contains('\n') && s.chars().count() == 90 && s.ends_with('…'));
    }
}
