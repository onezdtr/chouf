//! Turns raw observations into findings a non-specialist can read.

use crate::canary::Canary;
use crate::sandbox::{FsDiff, Outcome};
use crate::watch::{Op, Touches};
use serde_json::{json, Value};
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
        let (kind, why) = if let Some(c) = canaries.iter().find(|c| c.path == rel_s) {
            (Kind::Secret, c.what.to_string())
        } else if let (Some(c), true) = (bait_inside, ops.contains(&Op::List) && !rel_s.is_empty())
        {
            (
                Kind::Secret,
                format!("looked inside the folder of: {}", c.what),
            )
        } else if let (Some(why), true) = (lookup(PERSISTENCE, &path), changing(&ops)) {
            (Kind::Persistence, why.to_string())
        } else if changing(&ops) {
            (Kind::Other, String::new())
        } else {
            continue; // reading ordinary files (a shell reading ~/.bashrc) is not news
        };
        out.push(Finding {
            kind,
            path,
            did,
            why,
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
            });
        }
    }
    out.sort_by(|a, b| (a.kind, &a.path).cmp(&(b.kind, &b.path)));
    out
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

pub struct Report<'a> {
    pub id: &'a str,
    pub image: &'a str,
    pub cmd: &'a [String],
    pub outcome: &'a Outcome,
    pub findings: Vec<Finding>,
    pub incomplete: bool,
    pub transient: usize,
}

impl Report<'_> {
    pub fn json(&self) -> Value {
        let o = self.outcome;
        json!({
            "session": self.id, "image": self.image, "command": self.cmd,
            "exit_code": o.exit, "timed_out": o.timed_out, "seconds": o.elapsed.as_secs_f64(),
            "watch_incomplete": self.incomplete, "temporary_files": self.transient,
            "findings": self.findings.iter().map(|f| json!({"kind": f.kind.tag(), "path": f.path, "did": f.did, "why": f.why})).collect::<Vec<_>>(),
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
        if self.findings.is_empty() {
            s += "\nNothing: no bait touched, no file changed.\n";
        }
        let mut last = None;
        for f in &self.findings {
            if last != Some(f.kind) {
                s += &format!("\n{}\n", f.kind.title());
                last = Some(f.kind);
            }
            let mark = if f.kind == Kind::Other { " " } else { "!" };
            let why = if f.why.is_empty() {
                String::new()
            } else {
                format!("  ({})", f.why)
            };
            s += &format!(" {mark} {:<9} {}{}\n", f.did.join(", "), f.path, why);
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
            },
            Canary {
                path: ".aws/credentials".into(),
                what: "AWS access keys",
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
}
