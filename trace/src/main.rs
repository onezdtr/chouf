//! chouf-trace: the root helper of chouf. It loads the eBPF probes once and, on request, reports what the processes
//! of one cgroup do: programs run (with arguments and parent), files opened, connections, DNS answers.
//!
//! Protocol, on the Unix socket SOCK: the client sends one line `{"watch": "/sys/fs/cgroup/..."}`, then reads JSON
//! lines until it closes the connection, which ends the watch. A client may only watch a cgroup directory it owns
//! (checked with SO_PEERCRED and the directory owner), so a user never sees another user's processes.

mod dns;
mod event;

use anyhow::{bail, Context, Result};
use libbpf_rs::{
    skel::{OpenSkel, Skel, SkelBuilder},
    Link, MapCore, MapFlags, RingBufferBuilder,
};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::mem::MaybeUninit;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender, SyncSender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{fs, thread};

mod bpf {
    include!(concat!(env!("OUT_DIR"), "/trace.skel.rs"));
}
use bpf::*;

pub const SOCK: &str = "/run/chouf-trace.sock";
const CGROUP_ROOT: &str = "/sys/fs/cgroup/";
const MAX_WATCHES_PER_UID: usize = 8;
const QUEUE: usize = 65_536; // events buffered per client before the slowest client starts losing some

static STOP: AtomicBool = AtomicBool::new(false);
extern "C" fn on_signal(_: libc::c_int) {
    STOP.store(true, Ordering::Relaxed);
}

/// Who is at the other end of a Unix socket.
fn peer_uid(s: &UnixStream) -> std::io::Result<u32> {
    let mut cred = libc::ucred { pid: 0, uid: 0, gid: 0 };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: cred and len are valid for the size passed; the kernel fills at most len bytes.
    let r = unsafe {
        libc::getsockopt(s.as_raw_fd(), libc::SOL_SOCKET, libc::SO_PEERCRED, &mut cred as *mut _ as *mut _, &mut len)
    };
    if r != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(cred.uid)
}

/// The cgroup a client may watch: a real directory under /sys/fs/cgroup, owned by the client (or the client is root).
/// Returns its canonical path and its id (the directory's inode number, which is what eBPF sees as the cgroup id).
pub fn allowed(path: &str, uid: u32) -> Result<(PathBuf, u64)> {
    let p = fs::canonicalize(path).context("no such cgroup")?;
    if !p.starts_with(CGROUP_ROOT) || p == Path::new(CGROUP_ROOT) {
        bail!("not a cgroup under {CGROUP_ROOT}");
    }
    let m = fs::metadata(&p)?;
    if !m.is_dir() {
        bail!("not a cgroup directory");
    }
    if uid != 0 && m.uid() != uid {
        bail!("this cgroup belongs to someone else");
    }
    Ok((p, m.ino()))
}

enum Cmd {
    Watch { id: u64, uid: u32, dir: fs::File, guard: bool, find: Vec<Vec<u8>>, tx: SyncSender<Value>, reply: Sender<Result<(), String>> },
    Unwatch { id: u64 },
}

struct Watch {
    uid: u32,
    /// Byte strings to look for in what the sandbox sends (the session's bait marks): only matches are reported.
    find: Vec<Vec<u8>>,
    tx: SyncSender<Value>,
    _links: Vec<Link>,
}

/// The /64 prefixes of the host's global IPv6 addresses (from /proc/net/if_inet6): the home network's own prefix.
/// Link-local, loopback and ULA addresses are already refused by range in the kernel side.
pub fn home_prefixes(if_inet6: &str) -> Vec<[u8; 8]> {
    let mut out: Vec<[u8; 8]> = Vec::new();
    for line in if_inet6.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        // address, ifindex, prefix length, scope (00 = global), flags, name
        if f.len() < 6 || f[3] != "00" || f[0].len() != 32 {
            continue;
        }
        let mut p = [0u8; 8];
        for (i, b) in p.iter_mut().enumerate() {
            *b = u8::from_str_radix(&f[0][2 * i..2 * i + 2], 16).unwrap_or(0);
        }
        if p[0] & 0xfe == 0xfc {
            continue; // ULA: already private
        }
        if !out.contains(&p) && out.len() < 8 {
            out.push(p);
        }
    }
    out
}

fn client(stream: UnixStream, cmds: Sender<Cmd>) -> Result<()> {
    let uid = peer_uid(&stream)?;
    let mut line = String::new();
    BufReader::new(stream.try_clone()?).take(4096).read_line(&mut line)?;
    let mut out = stream.try_clone()?;
    let req: Value = serde_json::from_str(&line).unwrap_or(Value::Null);
    let guard = req.get("guard").and_then(Value::as_bool).unwrap_or(false);
    let find: Vec<Vec<u8>> = req
        .get("find")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .filter(|p| (8..=64).contains(&p.len()))
        .take(16)
        .map(|p| p.as_bytes().to_vec())
        .collect();
    let Some(path) = req.get("watch").and_then(Value::as_str) else {
        writeln!(out, "{}", json!({"error": "expected {\"watch\": \"/sys/fs/cgroup/...\"}"}))?;
        return Ok(());
    };
    let (p, id) = match allowed(path, uid) {
        Ok(x) => x,
        Err(e) => {
            writeln!(out, "{}", json!({"error": format!("{e:#}")}))?;
            return Ok(());
        }
    };
    let (tx, rx): (SyncSender<Value>, Receiver<Value>) = mpsc::sync_channel(QUEUE);
    let (rtx, rrx) = mpsc::channel();
    cmds.send(Cmd::Watch { id, uid, dir: fs::File::open(&p)?, guard, find, tx, reply: rtx })?;
    if let Err(e) = rrx.recv()? {
        writeln!(out, "{}", json!({"error": e}))?;
        return Ok(());
    }
    writeln!(out, "{}", json!({"watching": p, "cgroup": id, "guard": guard}))?;

    // The client ends the watch by closing its side: notice it even when no event flows.
    let closed = Arc::new(AtomicBool::new(false));
    let c2 = closed.clone();
    let mut probe = stream.try_clone()?;
    thread::spawn(move || {
        let mut buf = [0u8; 64];
        while !matches!(std::io::Read::read(&mut probe, &mut buf), Ok(0) | Err(_)) {}
        c2.store(true, Ordering::Relaxed);
    });
    let mut w = std::io::BufWriter::new(out);
    while !closed.load(Ordering::Relaxed) && !STOP.load(Ordering::Relaxed) {
        match rx.recv_timeout(Duration::from_millis(200)) {
            Ok(v) => {
                if writeln!(w, "{v}").is_err() {
                    break;
                }
                // flush once the queue is drained, not per event
                if rx.try_recv().map(|v| writeln!(w, "{v}")).is_err() && w.flush().is_err() {
                    break;
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if w.flush().is_err() {
                    break;
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    let _ = cmds.send(Cmd::Unwatch { id });
    Ok(())
}

fn boot_ms() -> i64 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: ts is a valid timespec to fill.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    let mono = ts.tv_sec as i64 * 1000 + ts.tv_nsec as i64 / 1_000_000;
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as i64 - mono
}

fn main() -> Result<()> {
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        bail!("chouf-trace loads eBPF programs: run it as root (it is meant to run as a system service)");
    }
    let mut obj = MaybeUninit::uninit();
    let mut skel = TraceSkelBuilder::default().open(&mut obj)?.load().context("load BPF programs")?;
    skel.attach().context("attach BPF programs")?;
    let bss = skel.maps.bss_data.take().context("no .bss")?;

    let watches: Arc<Mutex<HashMap<u64, Watch>>> = Arc::default();
    let boot = boot_ms();
    let w2 = watches.clone();
    let mut rb = RingBufferBuilder::new();
    rb.add(&skel.maps.events, move |data| {
        if let Some((cg, mut v, sample)) = event::sent(data, boot) {
            // data the sandbox sends: only what matches its owner's patterns leaves the daemon
            if let Some(w) = w2.lock().unwrap().get(&cg) {
                for (i, excerpt) in event::find(sample, &w.find) {
                    v["kind"] = "leak".into();
                    v["pattern"] = i.into();
                    v["excerpt"] = excerpt.into();
                    let _ = w.tx.try_send(v.clone());
                }
            }
            return 0;
        }
        let routed = if data.len() == event::SIZE {
            event::decode(data, boot)
        } else {
            dns::payload(data).map(|(cg, msg)| {
                let answers: Vec<Value> =
                    dns::answers(msg).into_iter().map(|(ip, name)| json!({"ip": ip.to_string(), "name": name})).collect();
                (cg, json!({"kind": "dns", "answers": answers}))
            })
        };
        if let Some((cg, v)) = routed {
            if let Some(w) = w2.lock().unwrap().get(&cg) {
                let _ = w.tx.try_send(v); // a stuck client loses events, it never blocks the others
            }
        }
        0
    })?;
    let rb = rb.build()?;

    let _ = fs::remove_file(SOCK);
    let listener = UnixListener::bind(SOCK).with_context(|| format!("bind {SOCK}"))?;
    // Anyone may ask; allowed() decides what each asker may see.
    fs::set_permissions(SOCK, fs::Permissions::from_mode(0o666))?;
    let (ctx, crx) = mpsc::channel::<Cmd>();
    thread::spawn(move || {
        for s in listener.incoming().flatten() {
            let c = ctx.clone();
            thread::spawn(move || {
                if let Err(e) = client(s, c) {
                    eprintln!("client: {e:#}");
                }
            });
        }
    });
    for sig in [libc::SIGINT, libc::SIGTERM] {
        // SAFETY: the handler only stores to an atomic, which is async-signal-safe.
        unsafe { libc::signal(sig, on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t) };
    }
    eprintln!("chouf-trace: ready on {SOCK}");

    while !STOP.load(Ordering::Relaxed) {
        let _ = rb.poll(Duration::from_millis(100));
        while let Ok(cmd) = crx.try_recv() {
            let mut ws = watches.lock().unwrap();
            match cmd {
                Cmd::Watch { id, uid, dir, guard, find, tx, reply } => {
                    let res = if ws.contains_key(&id) {
                        Err("this cgroup is already watched".to_string())
                    } else if ws.values().filter(|w| w.uid == uid).count() >= MAX_WATCHES_PER_UID {
                        Err(format!("at most {MAX_WATCHES_PER_UID} sandboxes at once"))
                    } else {
                        skel.maps.watched.update(&id.to_ne_bytes(), &[1], MapFlags::ANY).map_err(|e| e.to_string())
                    };
                    let mut links = Vec::new();
                    if res.is_ok() {
                        links.extend(skel.progs.on_ingress.attach_cgroup(dir.as_raw_fd()).ok());
                    }
                    let res = if res.is_ok() && guard {
                        // the home prefix can change (a new router lease): read it for every guarded watch
                        let prefixes = home_prefixes(&fs::read_to_string("/proc/net/if_inet6").unwrap_or_default());
                        for i in 0..8u32 {
                            let mut v = [0u8; 16];
                            if let Some(p) = prefixes.get(i as usize) {
                                v[..8].copy_from_slice(p);
                                v[8] = 1;
                            }
                            let _ = skel.maps.lan6_prefixes.update(&i.to_ne_bytes(), &v, MapFlags::ANY);
                        }
                        [&skel.progs.guard_connect4, &skel.progs.guard_connect6, &skel.progs.guard_sendmsg4, &skel.progs.guard_sendmsg6]
                            .iter()
                            .map(|p| p.attach_cgroup(dir.as_raw_fd()).map(|l| links.push(l)))
                            .collect::<Result<Vec<_>, _>>()
                            .map(|_| ())
                            .map_err(|e| format!("could not guard the local network: {e}"))
                    } else {
                        res
                    };
                    if res.is_ok() {
                        ws.insert(id, Watch { uid, find, tx, _links: links });
                        bss.watching = ws.len() as u32;
                    } else {
                        let _ = skel.maps.watched.delete(&id.to_ne_bytes());
                    }
                    let _ = reply.send(res);
                }
                Cmd::Unwatch { id } => {
                    ws.remove(&id);
                    let _ = skel.maps.watched.delete(&id.to_ne_bytes());
                    bss.watching = ws.len() as u32;
                }
            }
        }
    }
    let _ = fs::remove_file(SOCK);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_home_prefix_is_read_from_global_addresses_only() {
        let table = "2a01cb080265f00df6f91efffe11c990 02 40 00 00 wlp3s0\n\
                     fe80000000000000a2b3fffffe0c1d2e 02 40 20 80 wlp3s0\n\
                     fd7a115ca1e0000000000000000801ab 05 80 00 80 tailscale0\n\
                     00000000000000000000000000000001 01 80 10 80 lo\n\
                     2a01cb080265f00d0000000000000099 02 80 00 80 wlp3s0\n";
        assert_eq!(home_prefixes(table), vec![[0x2a, 0x01, 0xcb, 0x08, 0x02, 0x65, 0xf0, 0x0d]]);
    }
}

