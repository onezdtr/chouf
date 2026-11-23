//! What the system's package manager installed from a repository. An installer pulling docker-ce and its dependencies
//! adds boot scripts, services and system accounts that belong to those packages, not to the program under test:
//! they are named as the packages' own instead of raising an alarm.
//!
//! A package counts only when the kernel tracer saw it go the repository way: apt's download method wrote the .deb in
//! /var/cache/apt/archives/partial, then dpkg installed that very file. A .deb the program brought itself
//! (`dpkg -i ./x.deb`, `apt install ./x.deb`) is never excused, and a software source the program added stays an alarm.
//! shortcut: Debian/Ubuntu (dpkg) only; rpm-based images keep every alarm, add rpm when chouf runs Fedora images.

use crate::trace::Activity;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

const ARCHIVES: &str = "/var/cache/apt/archives/";
const INFO: &str = "/var/lib/dpkg/info/";
/// System folders copied out of the machine before it stops: the package lists, the enabled services (links) and the
/// software sources.
pub const COPIED: &[&str] = &["/var/lib/dpkg/info", "/etc/systemd/system", "/etc/apt/sources.list.d"];
/// The account files a package's install script changes when it creates its system user.
const ACCOUNTS: &[&str] = &["/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow"];

#[derive(Default, Debug)]
pub struct Packages {
    /// System path → the package it belongs to.
    managed: BTreeMap<String, String>,
    /// A software source file → the addresses it adds.
    pub sources: BTreeMap<String, Vec<String>>,
}

/// "docker-ce_5%3a29.1.1-1~ubuntu.24.04~noble_arm64.deb" or "dbus:arm64" → the package name.
fn name(s: &str) -> &str {
    let s = s.rsplit('/').next().unwrap_or(s);
    let s = s.split('_').next().unwrap_or(s);
    s.split(':').next().unwrap_or(s)
}

/// The packages installed from a repository during the run, as the tracer saw it. apt hands dpkg its downloads
/// through a folder of links (--recursive /tmp/apt-dpkg-install-…): what counts is the file dpkg's own tools
/// (dpkg-split, dpkg-deb) really open, which the kernel names by its real path.
pub fn from_repositories(a: &Activity) -> BTreeSet<String> {
    let ran = |pid: &u32, f: &dyn Fn(&str) -> bool| a.procs.get(pid).is_some_and(|p| p.execs.iter().any(|x| f(&x.file)));
    let downloaded: BTreeSet<&str> = a
        .opens
        .iter()
        .filter(|o| o.writes && ran(&o.pid, &|f| f.starts_with("/usr/lib/apt/methods/")))
        .filter_map(|o| o.path.strip_prefix(ARCHIVES)?.strip_prefix("partial/"))
        .collect();
    let dpkg = |f: &str| ["/usr/bin/dpkg", "/usr/bin/dpkg-deb", "/usr/bin/dpkg-split"].contains(&f);
    let (mut good, mut bad) = (BTreeSet::new(), BTreeSet::new());
    for o in a.opens.iter().filter(|o| o.path.ends_with(".deb") && o.path != "/var/lib/dpkg/reassemble.deb" && ran(&o.pid, &dpkg)) {
        match o.path.strip_prefix(ARCHIVES) {
            Some(file) if !file.contains('/') && downloaded.contains(file) => good.insert(name(file).to_string()),
            _ => bad.insert(name(&o.path).to_string()),
        };
    }
    good.retain(|n| !bad.contains(n));
    good
}

/// The package whose install script (dbus.postinst) a process runs under, if any.
fn script_package(a: &Activity, pid: u32) -> Option<String> {
    let mut cur = pid;
    for _ in 0..64 {
        let p = a.procs.get(&cur)?;
        for x in &p.execs {
            // the script runs directly (file) or through its interpreter (argv[1])
            for f in std::iter::once(&x.file).chain(x.args.get(1)) {
                if let Some(s) = f.strip_prefix(INFO) {
                    if [".preinst", ".postinst", ".prerm", ".postrm"].iter().any(|e| s.ends_with(e)) && !s.contains('/') {
                        return Some(name(s.rsplit_once('.').map_or(s, |(n, _)| n)).to_string());
                    }
                }
            }
        }
        cur = p.ppid;
    }
    None
}

/// "/usr/lib/x" and "/lib/x" are the same file on a merged-/usr system; dpkg lists may use either.
fn twin(p: &str) -> Option<String> {
    match p.strip_prefix("/usr") {
        Some(rest) if ["/lib/", "/bin/", "/sbin/"].iter().any(|d| rest.starts_with(d)) => Some(rest.to_string()),
        _ => ["/lib/", "/bin/", "/sbin/"].iter().any(|d| p.starts_with(d)).then(|| format!("/usr{p}")),
    }
}

/// Joins a link's target to its folder and removes "." and "..", without touching the disk.
fn resolve(link: &str, target: &Path) -> String {
    let mut out = PathBuf::from("/");
    let base = if target.is_absolute() { PathBuf::new() } else { Path::new(link).parent().unwrap_or(Path::new("/")).to_path_buf() };
    for c in base.join(target).components() {
        match c {
            Component::ParentDir => {
                out.pop();
            }
            Component::Normal(n) => out.push(n),
            _ => {}
        }
    }
    out.to_string_lossy().into_owned()
}

fn walk(dir: &Path, inside: &str, out: &mut Vec<(String, PathBuf)>) {
    for e in fs::read_dir(dir).into_iter().flatten().flatten() {
        let (host, path) = (e.path(), format!("{inside}/{}", e.file_name().to_string_lossy()));
        if e.file_type().is_ok_and(|t| t.is_dir()) {
            walk(&host, &path, out);
        }
        out.push((path, host));
    }
}

/// The addresses a software source file adds (one-line "deb URL …" or deb822 "URIs: URL").
pub fn source_urls(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for l in text.lines().map(str::trim) {
        let words: Vec<&str> = if let Some(rest) = l.strip_prefix("deb ").or(l.strip_prefix("deb-src ")) {
            rest.split_whitespace().filter(|w| w.contains("://")).take(1).collect()
        } else if let Some(rest) = l.strip_prefix("URIs:") {
            rest.split_whitespace().collect()
        } else {
            vec![]
        };
        for w in words {
            if !out.iter().any(|o| o == w) {
                out.push(w.to_string());
            }
        }
    }
    out
}

impl Packages {
    /// `copy`: where COPIED was copied (same paths below it). `changed`: the system paths the run added or changed.
    pub fn load(copy: &Path, changed: &[String], a: &Activity) -> Packages {
        let trusted = from_repositories(a);
        let mut managed = BTreeMap::new();
        // files the packages hold, from dpkg's list of each package installed during the run
        for p in changed.iter().filter_map(|p| p.strip_prefix(INFO)?.strip_suffix(".list")) {
            if !trusted.contains(name(p)) {
                continue;
            }
            for f in fs::read_to_string(copy.join(&INFO[1..]).join(format!("{p}.list"))).unwrap_or_default().lines() {
                managed.insert(f.to_string(), name(p).to_string());
            }
        }
        // a service enabled by a link to a packaged unit (multi-user.target.wants/docker.service → docker.service)
        let mut entries = Vec::new();
        walk(&copy.join("etc/systemd/system"), "/etc/systemd/system", &mut entries);
        let owner = |m: &BTreeMap<String, String>, p: &str| m.get(p).or_else(|| twin(p).and_then(|t| m.get(&t))).cloned();
        let mut dirs = Vec::new();
        for (path, host) in &entries {
            if let Ok(target) = fs::read_link(host) {
                if let Some(pkg) = owner(&managed, &resolve(path, &target)) {
                    managed.insert(path.clone(), pkg);
                }
            } else if host.is_dir() {
                dirs.push(path.clone());
            }
        }
        // a folder of such links (getty.target.wants) is the packages' when everything in it is
        dirs.sort_by_key(|d| std::cmp::Reverse(d.len()));
        for d in dirs {
            let inside: Vec<&(String, PathBuf)> = entries.iter().filter(|(p, _)| p.starts_with(&format!("{d}/"))).collect();
            let pkgs: BTreeSet<Option<String>> = inside.iter().map(|(p, _)| managed.get(p).cloned()).collect();
            if !inside.is_empty() && !pkgs.contains(&None) {
                managed.insert(d, pkgs.into_iter().flatten().collect::<Vec<_>>().join(", "));
            }
        }
        // system accounts created by a package's install script (adduser messagebus): every writer must be one
        for p in changed.iter().filter(|p| ACCOUNTS.contains(&p.trim_end_matches(['-', '+']))) {
            let base = p.trim_end_matches(['-', '+']);
            let writers: Vec<Option<String>> = a
                .opens
                .iter()
                .filter(|o| o.writes && o.path.trim_end_matches(['-', '+']) == base)
                .map(|o| script_package(a, o.pid).filter(|n| trusted.contains(n)))
                .collect();
            if !writers.is_empty() && writers.iter().all(Option::is_some) {
                let mut names: Vec<String> = writers.into_iter().flatten().collect();
                names.sort();
                names.dedup();
                managed.insert(p.clone(), names.join(", "));
            }
        }
        let mut sources = BTreeMap::new();
        for p in changed.iter().filter(|p| p.starts_with("/etc/apt/sources.list.d/")) {
            let urls = source_urls(&fs::read_to_string(copy.join(&p[1..])).unwrap_or_default());
            if !urls.is_empty() {
                sources.insert(p.clone(), urls);
            }
        }
        Packages { managed, sources }
    }

    /// The package a system path belongs to.
    pub fn of(&self, path: &str) -> Option<&str> {
        self.managed.get(path).or_else(|| twin(path).and_then(|t| self.managed.get(&t))).map(String::as_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn exec(pid: u32, ppid: u32, file: &str, args: &[&str]) -> serde_json::Value {
        json!({"kind":"exec","t":pid,"pid":pid,"ppid":ppid,"comm":"x","file":file,"args":args})
    }
    fn read(pid: u32, path: &str) -> serde_json::Value {
        json!({"kind":"open","t":200+pid,"pid":pid,"comm":"x","path":path,"mode":"read","create":false})
    }
    fn write(pid: u32, path: &str) -> serde_json::Value {
        json!({"kind":"open","t":100+pid,"pid":pid,"comm":"x","path":path,"mode":"write","create":true})
    }

    #[test]
    fn only_packages_downloaded_by_apt_and_installed_by_dpkg_count() {
        let deb = "docker-ce_5%3a29.1.1-1~ubuntu.24.04~noble_arm64.deb";
        let events = vec![
            exec(10, 1, "/usr/bin/apt-get", &["apt-get", "install", "docker-ce"]),
            exec(11, 10, "/usr/lib/apt/methods/http", &["/usr/lib/apt/methods/http"]),
            write(11, &format!("/var/cache/apt/archives/partial/{deb}")),
            exec(12, 10, "/usr/bin/dpkg", &["/usr/bin/dpkg", "--unpack", "--recursive", "/tmp/apt-dpkg-install-x"]),
            exec(13, 12, "/usr/bin/dpkg-deb", &["dpkg-deb", "--fsys-tarfile", &format!("/tmp/apt-dpkg-install-x/0-{deb}")]),
            read(13, &format!("/var/cache/apt/archives/{deb}")),
            // brought by the program: a local file, or a file it dropped in the cache itself
            exec(14, 1, "/usr/bin/dpkg-deb", &["dpkg-deb", "-x", "/tmp/evil_1.0_arm64.deb"]),
            read(14, "/tmp/evil_1.0_arm64.deb"),
            write(1, "/var/cache/apt/archives/sneaky_1_all.deb"),
            exec(15, 1, "/usr/bin/dpkg-split", &["dpkg-split", "-Qao", "x"]),
            read(15, "/var/cache/apt/archives/sneaky_1_all.deb"),
        ];
        let a = Activity::from_events(&events, false);
        assert_eq!(from_repositories(&a), BTreeSet::from(["docker-ce".to_string()]));
    }

    #[test]
    fn package_files_links_and_accounts_are_the_packages_own() {
        let dir = std::env::temp_dir().join(format!("chouf-pkg-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let info = dir.join("var/lib/dpkg/info");
        let sys = dir.join("etc/systemd/system");
        let src = dir.join("etc/apt/sources.list.d");
        for d in [&info, &sys.join("multi-user.target.wants"), &sys.join("evil.target.wants"), &src] {
            fs::create_dir_all(d).unwrap();
        }
        fs::write(info.join("docker-ce.list"), "/etc/init.d/docker\n/lib/systemd/system/docker.service\n").unwrap();
        fs::write(info.join("dbus:arm64.list"), "/usr/lib/systemd/system/dbus.service\n").unwrap();
        fs::write(info.join("evil.list"), "/etc/init.d/evil\n").unwrap();
        let link = |to: &str, at: &str| std::os::unix::fs::symlink(to, sys.join(at)).unwrap();
        link("/usr/lib/systemd/system/docker.service", "multi-user.target.wants/docker.service");
        link("../../../usr/lib/systemd/system/dbus.service", "dbus-org.freedesktop.dbus.service");
        link("/tmp/payload.service", "evil.target.wants/evil.service");
        fs::write(src.join("docker.list"), "deb [arch=arm64 signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu noble stable\n").unwrap();
        let deb = |n: &str| format!("/var/cache/apt/archives/{n}_1_arm64.deb");
        let events = vec![
            exec(11, 1, "/usr/lib/apt/methods/http", &["http"]),
            write(11, "/var/cache/apt/archives/partial/docker-ce_1_arm64.deb"),
            write(11, "/var/cache/apt/archives/partial/dbus_1_arm64.deb"),
            exec(12, 1, "/usr/bin/dpkg-deb", &["dpkg-deb"]),
            read(12, &deb("docker-ce")),
            read(12, &deb("dbus")),
            exec(13, 12, "/var/lib/dpkg/info/dbus.postinst", &["/bin/sh", "/var/lib/dpkg/info/dbus.postinst", "configure"]),
            exec(14, 13, "/usr/sbin/useradd", &["useradd", "messagebus"]),
            write(14, "/etc/passwd+"),
            write(14, "/etc/shadow+"),
            write(15, "/etc/shadow"), // a process outside any package script
        ];
        let a = Activity::from_events(&events, false);
        let changed: Vec<String> = [
            "/var/lib/dpkg/info/docker-ce.list", "/var/lib/dpkg/info/dbus:arm64.list", "/var/lib/dpkg/info/evil.list",
            "/etc/passwd", "/etc/passwd-", "/etc/shadow", "/etc/apt/sources.list.d/docker.list",
        ].map(String::from).to_vec();
        let p = Packages::load(&dir, &changed, &a);
        assert_eq!(p.of("/etc/init.d/docker"), Some("docker-ce"));
        assert_eq!(p.of("/usr/lib/systemd/system/docker.service"), Some("docker-ce"), "merged /usr");
        assert_eq!(p.of("/etc/systemd/system/multi-user.target.wants/docker.service"), Some("docker-ce"));
        assert_eq!(p.of("/etc/systemd/system/multi-user.target.wants"), Some("docker-ce"));
        assert_eq!(p.of("/etc/systemd/system/dbus-org.freedesktop.dbus.service"), Some("dbus"), "relative link");
        assert_eq!(p.of("/etc/passwd"), Some("dbus"));
        assert_eq!(p.of("/etc/passwd-"), Some("dbus"));
        // never excused: a package not downloaded by apt, a link to a file of no package, a writer outside the scripts
        assert_eq!(p.of("/etc/init.d/evil"), None);
        assert_eq!(p.of("/etc/systemd/system/evil.target.wants/evil.service"), None);
        assert_eq!(p.of("/etc/systemd/system/evil.target.wants"), None);
        assert_eq!(p.of("/etc/shadow"), None);
        assert_eq!(p.sources["/etc/apt/sources.list.d/docker.list"], vec!["https://download.docker.com/linux/ubuntu"]);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn deb822_sources_give_their_addresses() {
        let t = "Types: deb\nURIs: https://repo.example.com/apt https://mirror.example.com/apt\nSuites: stable\n";
        assert_eq!(source_urls(t), vec!["https://repo.example.com/apt", "https://mirror.example.com/apt"]);
    }
}
