mod canary;
mod report;
mod sandbox;
mod watch;

use std::env;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

const USAGE: &str = "chouf: run a program in a throwaway sandbox full of bait secrets, and see what it really does.

usage: chouf run [--image IMAGE] [--timeout SECS] [--no-net] [--file PATH]... -- COMMAND [ARGS]...

  --image IMAGE   container image (default ubuntu:24.04)
  --timeout SECS  stop the program after SECS seconds (default 300)
  --no-net        no network at all
  --file PATH     make PATH available read-only as /input/<name> (repeatable)

The program runs as root inside a rootless container: it can change the whole system, only the copy is touched.
Its home (/root) is a fake one, full of bait secrets that exist nowhere else.
Every run is kept in ~/.local/share/chouf/sessions/<id>/ (report.json, stdout, stderr, home).";

struct RunOpts {
    image: String,
    timeout: Duration,
    net: bool,
    files: Vec<PathBuf>,
    cmd: Vec<String>,
}

fn parse_run(args: &[String]) -> Result<RunOpts, String> {
    let mut o = RunOpts {
        image: "docker.io/library/ubuntu:24.04".into(),
        timeout: Duration::from_secs(300),
        net: true,
        files: vec![],
        cmd: vec![],
    };
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut value = |name: &str| it.next().cloned().ok_or(format!("{name} needs a value"));
        match a.as_str() {
            "--image" => o.image = value("--image")?,
            "--timeout" => {
                o.timeout = Duration::from_secs(
                    value("--timeout")?
                        .parse()
                        .map_err(|_| "--timeout: seconds")?,
                )
            }
            "--no-net" => o.net = false,
            "--file" => o.files.push(PathBuf::from(value("--file")?)),
            "--" => {
                o.cmd = it.cloned().collect();
                break;
            }
            other => return Err(format!("unknown option {other}")),
        }
    }
    if o.cmd.is_empty() {
        return Err("nothing to run: put the command after --".into());
    }
    Ok(o)
}

fn data_dir() -> PathBuf {
    env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env::var_os("HOME").unwrap_or_default()).join(".local/share")
        })
        .join("chouf")
}

fn cache_dir() -> PathBuf {
    env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env::var_os("HOME").unwrap_or_default()).join(".cache"))
        .join("chouf")
}

/// "20261123-134502-ab12": sortable, readable, unique enough.
fn session_id(token: &str) -> String {
    let now = unsafe { libc::time(std::ptr::null_mut()) };
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe { libc::localtime_r(&now, &mut tm) };
    format!(
        "{:04}{:02}{:02}-{:02}{:02}{:02}-{}",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec,
        &token[..4]
    )
}

fn run(o: RunOpts) -> io::Result<ExitCode> {
    let token = canary::token()?;
    let id = session_id(&token);
    let dir = data_dir().join("sessions").join(&id);
    let home = dir.join("home");
    fs::create_dir_all(&home)?;
    let canaries = canary::plant(&home, &token)?;
    let input = if o.files.is_empty() {
        None
    } else {
        let d = dir.join("input");
        fs::create_dir_all(&d)?;
        for f in &o.files {
            let name = f
                .file_name()
                .ok_or_else(|| io::Error::other(format!("--file {}: not a file", f.display())))?;
            fs::copy(f, d.join(name))?; // a copy: podman relabels what it mounts, the user's own file stays as it is
        }
        Some(d)
    };
    fs::create_dir_all(cache_dir())?;
    let noise = sandbox::noise(&o.image, &cache_dir())?;

    let spec = sandbox::Spec {
        name: format!("chouf-{id}"),
        image: &o.image,
        home: &home,
        input: input.as_deref(),
        cmd: &o.cmd,
        timeout: o.timeout,
        net: o.net,
    };
    let created = sandbox::create(&spec)?;
    let watcher = watch::Watcher::start(&home)?;
    let outcome = created.start();
    let touches = watcher.stop()?;
    let mut outcome = outcome?;
    let mut noise = noise;
    noise.insert("/input".into()); // our own mount point
    outcome.fs = sandbox::interesting(std::mem::take(&mut outcome.fs), &noise);

    let report = report::Report {
        id: &id,
        image: &o.image,
        cmd: &o.cmd,
        outcome: &outcome,
        findings: report::findings(&canaries, &touches, &outcome.fs),
        transient: report::transient_count(&touches),
        incomplete: touches.incomplete,
    };
    let mut json = report.json();
    json["token"] = token.clone().into();
    fs::write(
        dir.join("report.json"),
        serde_json::to_vec_pretty(&json).map_err(io::Error::other)?,
    )?;
    fs::write(dir.join("stdout"), &outcome.stdout)?;
    fs::write(dir.join("stderr"), &outcome.stderr)?;
    print!("{}", report.text());
    println!("\nsession: {}", dir.display());
    let alarming = report
        .findings
        .iter()
        .any(|f| f.kind != report::Kind::Other);
    Ok(if alarming {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    })
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("run") => match parse_run(&args[1..]) {
            Ok(o) => run(o).unwrap_or_else(|e| {
                eprintln!("chouf: {e}");
                ExitCode::from(2)
            }),
            Err(e) => {
                eprintln!("chouf: {e}\n\n{USAGE}");
                ExitCode::from(2)
            }
        },
        _ => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}
