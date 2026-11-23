//! Turns raw observations into findings a non-specialist can read.

use crate::canary::Canary;
use crate::sandbox::{FsDiff, Outcome};
use crate::explore::{describe_short, Done, Verdict};
use crate::trace::Activity;
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

pub fn findings(canaries: &[Canary], home: &Touches, sys: &FsDiff) -> Vec<Finding> {
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
            out.push(Finding {
                kind,
                path: p.clone(),
                did: vec![word],
                why: why.to_string(),
                by: vec![],
                group: "",
                count: 1,
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
    let mut groups: BTreeMap<(Kind, String, Vec<&'static str>, String, &'static str), Vec<Finding>> = BTreeMap::new();
    for f in list {
        groups.entry((f.kind, parent(&f.path), f.did.clone(), f.why.clone(), f.group)).or_default().push(f);
    }
    let mut out = Vec::new();
    for ((kind, dir, did, why, group), fs) in groups {
        if fs.len() > FOLD && kind != Kind::Secret {
            let mut by: Vec<String> = fs.iter().flat_map(|f| f.by.iter().cloned()).collect();
            by.sort();
            by.dedup();
            out.push(Finding { kind, path: dir, did, why, by, group, count: fs.len() });
        } else {
            out.extend(fs);
        }
    }
    out.sort_by(|a, b| (a.kind, &a.path).cmp(&(b.kind, &b.path)));
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
pub fn in_short(findings: &[Finding], activity: Option<&Activity>) -> String {
    let secrets: Vec<&Finding> = findings.iter().filter(|f| f.kind == Kind::Secret).collect();
    let persist = findings.iter().filter(|f| f.kind == Kind::Persistence).count();
    let trust = findings.iter().filter(|f| f.kind == Kind::Trust).count();
    let mut groups: Vec<&str> = secrets.iter().map(|f| f.group).filter(|g| !g.is_empty()).collect();
    groups.sort();
    groups.dedup();
    let mut s = String::from("\nIn short\n");
    if secrets.is_empty() && persist == 0 && trust == 0 {
        s += "   Nothing alarming: no secret touched, nothing set to run again, nothing new trusted.\n";
    }
    if !secrets.is_empty() {
        s += &format!("   !! It went through your {}: {} bait file{}.\n", groups.join(", "), secrets.len(), if secrets.len() > 1 { "s" } else { "" });
    }
    if persist > 0 {
        s += &format!("   !! It set itself up to run again on its own ({persist} way{}).\n", if persist > 1 { "s" } else { "" });
    }
    if trust > 0 {
        s += "   !! It changed what the machine trusts (software sources, certificates, admin rights or accounts).\n";
    }
    let own: Vec<&str> = findings.iter().filter(|f| f.why.contains(", read by its own tool: ")).map(|f| f.path.as_str()).collect();
    if !own.is_empty() {
        s += &format!("   It read {} of its own settings ({}): normal, nothing else touched {}.\n", if own.len() > 1 { "some" } else { "one" }, own.join(", "), if own.len() > 1 { "them" } else { "it" });
    }
    if findings.iter().any(|f| ["/var/lib/dpkg/", "/var/lib/rpm/", "/usr/lib/sysimage/rpm/"].iter().any(|p| f.path.starts_with(p))) {
        s += "   It installed software with the system's package manager (normal for an installer).\n";
    }
    if let Some(a) = activity {
        let mut places: Vec<String> = a.conns.iter().map(|c| c.name.clone().unwrap_or_else(|| c.ip.clone())).collect();
        places.sort();
        places.dedup();
        match places.len() {
            0 => s += "   It contacted nothing on the network.\n",
            n => s += &format!("   It contacted {n} place{} on the network: {}.\n", if n > 1 { "s" } else { "" }, places.iter().take(5).cloned().collect::<Vec<_>>().join(", ")),
        }
    }
    if !groups.is_empty() || persist > 0 {
        s += "   If you already ran it on your own machine:\n";
        for g in &groups {
            s += &format!("     - {}\n", advice(g));
        }
        if persist > 0 {
            let where_: Vec<&str> = findings.iter().filter(|f| f.kind == Kind::Persistence).map(|f| f.path.as_str()).take(6).collect();
            s += &format!("     - remove what it set up to come back: {}\n", where_.join(", "));
        }
    }
    s
}

/// Names the programs behind each finding: "~/x" is /root/x inside the sandbox, system paths are themselves.
/// Also clears a bait read only by its own tools (npm reading ~/.npmrc): it becomes an ordinary line that says so.
/// The kernel tracer is what makes this possible; without it, every bait read stays an alarm.
pub fn attribute(findings: &mut [Finding], a: &Activity) {
    for f in findings.iter_mut() {
        let inside = match f.path.strip_prefix('~') {
            Some(rest) => format!("/root{rest}"),
            None => f.path.clone(),
        };
        f.by = a.openers(&inside).0;
        let Some(rel) = f.path.strip_prefix("~/") else { continue };
        if f.kind != Kind::Secret || f.why.starts_with("looked inside") {
            continue;
        }
        let tools = crate::canary::own_tools(rel);
        let readers = a.opener_commands(&inside);
        let own = |cmd: &Option<Vec<String>>| {
            cmd.as_ref().and_then(|c| {
                // the program itself, or the script handed to an interpreter (python3 /usr/local/bin/pip)
                c.iter().take(3).filter_map(|x| x.rsplit('/').next()).find(|n| tools.contains(n)).map(str::to_string)
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
    pub exploration: Option<Exploration<'a>>,
}

impl Report<'_> {
    pub fn json(&self) -> Value {
        let o = self.outcome;
        json!({
            "session": self.id, "image": self.image, "command": self.cmd,
            "exit_code": o.exit, "timed_out": o.timed_out, "seconds": o.elapsed.as_secs_f64(),
            "watch_incomplete": self.incomplete, "temporary_files": self.transient,
            "findings": self.findings.iter().map(|f| json!({"kind": f.kind.tag(), "path": f.path, "did": f.did, "why": f.why, "by": f.by, "group": f.group, "count": f.count})).collect::<Vec<_>>(),
            "activity": match &self.activity { Ok(a) => a.json(), Err(why) => json!({"unavailable": why}) },
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
        s += &in_short(&self.findings, self.activity.as_ref().ok().copied());
        if let Some(x) = &self.exploration {
            s += "\nHow chouf explored it\n";
            for (i, d) in x.steps.iter().enumerate() {
                s += &format!("   [{}] {}\n", i + 1, describe_short(d));
            }
            if let Some(n) = &x.note {
                s += &format!("   ({n})\n");
            }
        }
        if self.findings.is_empty() {
            s += "\nNothing: no bait touched, no file changed.\n";
        }
        let mut last = None;
        let others = self.findings.iter().filter(|f| f.kind == Kind::Other).count();
        let mut shown_others = 0;
        for f in &self.findings {
            if last != Some(f.kind) {
                s += &format!("\n{}\n", f.kind.title());
                last = Some(f.kind);
            }
            // ordinary changes: a short sample in the terminal, all of them in report.json and report.html
            if f.kind == Kind::Other {
                shown_others += 1;
                if shown_others > OTHER_LINES {
                    if shown_others == OTHER_LINES + 1 {
                        s += &format!("   and {} more (report.html has them all)\n", others - OTHER_LINES);
                    }
                    continue;
                }
            }
            let mark = if f.kind == Kind::Other { " " } else { "!" };
            let why = if f.why.is_empty() {
                String::new()
            } else {
                format!("  ({})", f.why)
            };
            let path = if f.count > 1 { format!("{} files in {}", f.count, f.path) } else { f.path.clone() };
            s += &format!(" {mark} {:<9} {}{}\n", f.did.join(", "), path, why);
            // who did it matters for an alarm; for an ordinary change it is noise
            let by: &[String] = if f.kind == Kind::Other { &[] } else { &f.by };
            for b in by.iter().take(3) {
                s += &format!("   {:<9} by {b}\n", "");
            }
            if by.len() > 3 {
                s += &format!("   {:<9} and {} more\n", "", by.len() - 3);
            }
        }
        match &self.activity {
            Ok(a) => {
                if !a.conns.is_empty() {
                    s += "\nWhere it connected\n";
                    for c in a.conns.iter().take(30) {
                        let dest = match &c.name {
                            Some(n) => format!("{n} ({})", c.ip),
                            None => c.ip.clone(),
                        };
                        s += &format!("   {dest} port {} {}  by {}\n", c.port, c.proto, a.who(c.pid, i64::MAX));
                    }
                    if a.conns.len() > 30 {
                        s += &format!("   and {} more\n", a.conns.len() - 30);
                    }
                }
                let tree = a.tree();
                if !tree.is_empty() {
                    s += &format!("\nPrograms it ran ({})\n", tree.len());
                    for (depth, cmd, exit) in tree.iter().take(40) {
                        let code = match exit {
                            Some(0) | None => String::new(),
                            Some(c) => format!("  (exit {c})"),
                        };
                        s += &format!("   {}{cmd}{code}\n", "  ".repeat((*depth).min(8)));
                    }
                    if tree.len() > 40 {
                        s += &format!("   and {} more (report.json has them all)\n", tree.len() - 40);
                    }
                }
                if a.lost {
                    s += "\nWarning: the kernel tracer lost events, the lists above may be incomplete.\n";
                }
            }
            Err(why) => s += &format!("\n({why})\n"),
        }
        if let Some(x) = &self.exploration {
            s += &format!("\nWhat it says vs what it does  (opinion of {}, not a measurement)\n", x.model);
            match &x.verdict {
                Ok(v) => {
                    let mark = match v.level.as_str() {
                        "consistent" => "consistent: it does what it says",
                        "suspicious" => "SUSPICIOUS: it does things it does not explain",
                        _ => "MALICIOUS: it steals, hides or contradicts itself",
                    };
                    s += &format!("   {mark}\n   {}\n", v.summary);
                    for p in &v.points {
                        let sign = match p.assessment.as_str() {
                            "consistent" => "ok",
                            "contradicts" => "!!",
                            _ => " ?",
                        };
                        s += &format!("   {sign} says: {}\n      does: {}\n", p.says, p.does);
                    }
                }
                Err(e) => s += &format!("   ({e})\n"),
            }
        }
        if self.transient > 0 {
            s += &format!(
                "\n({} temporary files or folders created and removed in ~)\n",
                self.transient
            );
        }
        if self.incomplete {
            s += "\nWarning: some file events were lost, this list may be incomplete.\n";
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
                group: crate::canary::PRIVATE,
            },
            Canary {
                path: ".aws/credentials".into(),
                what: "AWS access keys",
                group: crate::canary::DEV,
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
        let f = findings(&canaries, &home, &sys);
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
        let f = |kind, path: &str, group| Finding { kind, path: path.into(), did: vec!["read"], why: String::new(), by: vec![], group, count: 1 };
        let findings = vec![
            f(Kind::Secret, "~/.config/Exodus/exodus.wallet/seed.seco", crate::canary::WALLETS),
            f(Kind::Secret, "~/.config/BraveSoftware/Brave-Browser/Default/Login Data", crate::canary::PASSWORDS),
            f(Kind::Persistence, "/etc/cron.d/x", ""),
        ];
        let s = in_short(&findings, None);
        assert!(s.contains("It went through your crypto wallets, passwords and browser logins: 2 bait files."), "{s}");
        assert!(s.contains("run again on its own (1 way)") && s.contains("new wallet") && s.contains("/etc/cron.d/x"), "{s}");
        assert!(in_short(&[f(Kind::Other, "/tmp/x", "")], None).contains("Nothing alarming"));
    }

    #[test]
    fn the_standard_certificate_bundle_is_not_a_new_trust_but_a_custom_root_is() {
        let mut added: Vec<String> = (0..8).map(|i| format!("/usr/share/ca-certificates/mozilla/Root_{i}.crt")).collect();
        added.extend((0..8).map(|i| format!("/etc/ssl/certs/Root_{i}.pem")));
        added.extend((0..8).map(|i| format!("/etc/ssl/certs/{i:08x}.0")));
        added.push("/etc/ssl/certs/ca-certificates.crt".into());
        added.push("/etc/ssl/certs/Evil_CA.pem".into());
        let sys = FsDiff { added: added.clone(), changed: vec![], deleted: vec![] };
        let f = findings(&[], &Touches::default(), &sys);
        let trust: Vec<&str> = f.iter().filter(|f| f.kind == Kind::Trust).map(|f| f.path.as_str()).collect();
        assert_eq!(trust, vec!["/etc/ssl/certs/Evil_CA.pem"], "only the root that is not Mozilla's stays an alarm");
        // the 17 ordinary links fold into one line, the 8 Mozilla files into another
        let certs = f.iter().find(|f| f.kind == Kind::Other && f.path == "/etc/ssl/certs/").unwrap();
        assert_eq!((certs.count, certs.why.as_str()), (17, "standard root certificates (ca-certificates package)"));
        // a custom root in the local folder: nothing is excused
        let mut sys = sys;
        sys.added.push("/usr/local/share/ca-certificates/corp.crt".into());
        let f = findings(&[], &Touches::default(), &sys);
        let alarms: usize = f.iter().filter(|f| f.kind == Kind::Trust && f.path.starts_with("/etc/ssl/certs/")).map(|f| f.count).sum();
        assert_eq!(alarms, 18, "every certificate is an alarm again: {f:?}");
    }

    #[test]
    fn a_tool_reading_its_own_settings_is_not_a_theft_but_anything_else_is() {
        use serde_json::json;
        let canaries = vec![Canary { path: ".npmrc".into(), what: "npm publish token", group: crate::canary::DEV }];
        let home = touches(&[(".npmrc", &[Op::Open, Op::Read])]);
        let run = |events: Vec<serde_json::Value>| {
            let a = Activity::from_events(&events, false);
            let mut f = findings(&canaries, &home, &FsDiff::default());
            attribute(&mut f, &a);
            f
        };
        let npm = json!({"kind":"exec","t":1,"pid":10,"ppid":1,"comm":"node","file":"/usr/local/bin/node","args":["node","/usr/local/bin/npm","install"]});
        let read = |pid| json!({"kind":"open","t":5,"pid":pid,"comm":"node","path":"/root/.npmrc","mode":"read","create":false});
        let f = run(vec![npm.clone(), read(10)]);
        assert_eq!(f[0].kind, Kind::Other, "{f:?}");
        assert_eq!(f[0].why, "npm publish token, read by its own tool: npm");
        assert!(in_short(&f, None).contains("It read one of its own settings (~/.npmrc)"));
        // the classic attack: an install script, not npm, reads the token
        let postinstall = json!({"kind":"exec","t":2,"pid":11,"ppid":10,"comm":"node","file":"/usr/local/bin/node","args":["node","install.js"]});
        let f = run(vec![npm.clone(), postinstall, read(10), read(11)]);
        assert_eq!(f[0].kind, Kind::Secret, "{f:?}");
        // a program merely named after nothing it owns, or an unknown process: still an alarm
        let f = run(vec![read(99)]);
        assert_eq!(f[0].kind, Kind::Secret);
    }
}
