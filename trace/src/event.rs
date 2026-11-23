//! `struct event` from src/bpf/trace.bpf.c, decoded into JSON for the client.
//! Only bytes the kernel side marks as valid are read: path up to its NUL, args up to the length in `flags`.
//! The rest of each ring buffer slot is not cleared by the kernel side and may hold an older event.

use serde_json::{json, Value};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const SIZE: usize = 584;
const EV_EXEC: u8 = 1;
const EV_OPEN: u8 = 2;
const EV_CONNECT: u8 = 3;
const EV_UDP: u8 = 4;
const EV_EXIT: u8 = 5;
const EV_FORK: u8 = 6;
const AF_INET: u16 = 2;
const O_ACCMODE: u32 = 3;
const O_CREAT: u32 = 0o100;
const O_TRUNC: u32 = 0o1000;
const O_DIRECTORY: u32 = 0o200000;

fn u16_at(b: &[u8], i: usize) -> u16 {
    u16::from_ne_bytes(b[i..i + 2].try_into().unwrap())
}
fn u32_at(b: &[u8], i: usize) -> u32 {
    u32::from_ne_bytes(b[i..i + 4].try_into().unwrap())
}
fn u64_at(b: &[u8], i: usize) -> u64 {
    u64::from_ne_bytes(b[i..i + 8].try_into().unwrap())
}

/// A NUL-terminated string in a fixed field; nothing after the first NUL is looked at.
fn cstr(field: &[u8]) -> String {
    let end = field.iter().position(|&c| c == 0).unwrap_or(field.len());
    String::from_utf8_lossy(&field[..end]).into_owned()
}

fn ip(family: u16, a: &[u8]) -> IpAddr {
    if family == AF_INET {
        IpAddr::V4(Ipv4Addr::new(a[0], a[1], a[2], a[3]))
    } else {
        IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(a).unwrap()))
    }
}

/// (watched cgroup, event as JSON), or None for a sample that is not a known event.
/// `boot_ms` turns kernel monotonic time into wall-clock milliseconds.
pub fn decode(b: &[u8], boot_ms: i64) -> Option<(u64, Value)> {
    if b.len() != SIZE {
        return None;
    }
    let cgroup = u64_at(b, 8);
    let kind = b[36];
    let flags = u32_at(b, 28);
    let mut v = json!({
        "t": boot_ms + (u64_at(b, 0) / 1_000_000) as i64,
        "pid": u32_at(b, 16),
        "uid": u32_at(b, 24),
        "comm": cstr(&b[56..72]),
    });
    let o = v.as_object_mut().unwrap();
    match kind {
        EV_EXEC => {
            let n = (flags as usize).min(256);
            let args: Vec<String> = b[328..328 + n]
                .split(|&c| c == 0)
                .filter(|s| !s.is_empty())
                .map(|s| String::from_utf8_lossy(s).into_owned())
                .collect();
            o.insert("kind".into(), "exec".into());
            o.insert("ppid".into(), u32_at(b, 20).into());
            o.insert("file".into(), cstr(&b[72..328]).into());
            o.insert("args".into(), args.into());
        }
        EV_OPEN => {
            let mode = match flags & O_ACCMODE {
                0 => "read",
                1 => "write",
                _ => "read-write",
            };
            o.insert("kind".into(), "open".into());
            o.insert("path".into(), cstr(&b[72..328]).into());
            o.insert("mode".into(), mode.into());
            o.insert("create".into(), (flags & O_CREAT != 0).into());
            o.insert("truncate".into(), (flags & O_TRUNC != 0).into());
            o.insert("directory".into(), (flags & O_DIRECTORY != 0).into());
        }
        EV_CONNECT | EV_UDP => {
            let family = u16_at(b, 32);
            o.insert("kind".into(), if kind == EV_CONNECT { "connect" } else { "udp" }.into());
            o.insert("ip".into(), ip(family, &b[40..if family == AF_INET { 44 } else { 56 }]).to_string().into());
            o.insert("port".into(), u16_at(b, 34).into());
        }
        EV_FORK => {
            o.insert("kind".into(), "fork".into());
            o.insert("ppid".into(), u32_at(b, 20).into());
        }
        EV_EXIT => {
            o.insert("kind".into(), "exit".into());
            o.insert("code".into(), flags.into());
        }
        _ => return None,
    }
    Some((cgroup, v))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(kind: u8, flags: u32, path: &[u8], args: &[u8]) -> Vec<u8> {
        let mut b = vec![0xAAu8; SIZE]; // stale bytes everywhere: none of them may show up
        b[..36].fill(0);
        b[0..8].copy_from_slice(&5_000_000u64.to_ne_bytes());
        b[8..16].copy_from_slice(&42u64.to_ne_bytes());
        b[16..20].copy_from_slice(&7u32.to_ne_bytes());
        b[20..24].copy_from_slice(&1u32.to_ne_bytes());
        b[28..32].copy_from_slice(&flags.to_ne_bytes());
        b[36] = kind;
        b[56..62].copy_from_slice(b"curl\0\0");
        b[72..72 + path.len()].copy_from_slice(path);
        b[328..328 + args.len()].copy_from_slice(args);
        b
    }

    #[test]
    fn exec_reads_args_only_up_to_their_length() {
        let b = raw(EV_EXEC, 13, b"/usr/bin/curl\0", b"curl\0-s\0x.io\0");
        let (cg, v) = decode(&b, 1000).unwrap();
        assert_eq!(cg, 42);
        assert_eq!(v["t"], 1005);
        assert_eq!(v["file"], "/usr/bin/curl");
        assert_eq!(v["args"], json!(["curl", "-s", "x.io"]));
        assert!(!v.to_string().contains('\u{AA}') && !v.to_string().contains('\u{FFFD}'));
    }

    #[test]
    fn open_modes() {
        let (_, v) = decode(&raw(EV_OPEN, 1 | O_CREAT | O_TRUNC, b"/root/.bashrc\0", b""), 0).unwrap();
        assert_eq!((v["mode"].as_str(), v["create"].as_bool(), v["path"].as_str()), (Some("write"), Some(true), Some("/root/.bashrc")));
        let (_, v) = decode(&raw(EV_OPEN, 0, b"/root/.ssh/id_ed25519\0", b""), 0).unwrap();
        assert_eq!(v["mode"], "read");
    }

    #[test]
    fn connect_ipv4_and_unknown_samples() {
        let mut b = raw(EV_CONNECT, 0, b"\0", b"");
        b[32..34].copy_from_slice(&AF_INET.to_ne_bytes());
        b[34..36].copy_from_slice(&443u16.to_ne_bytes());
        b[40..44].copy_from_slice(&[93, 184, 216, 34]);
        let (_, v) = decode(&b, 0).unwrap();
        assert_eq!((v["ip"].as_str(), v["port"].as_u64()), (Some("93.184.216.34"), Some(443)));
        assert!(decode(&raw(99, 0, b"\0", b""), 0).is_none());
        assert!(decode(&b[..100], 0).is_none());
    }
}
