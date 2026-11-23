mod canary;
mod explore;
mod html;
mod llm;
mod report;
mod sandbox;
mod trace;
mod watch;

use explore::{Action, Done};
use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::thread;
use std::time::Duration;

const USAGE: &str = "chouf: run a program in a throwaway sandbox full of bait secrets, and see what it really does.

usage: chouf run     [OPTIONS] -- COMMAND [ARGS]...
       chouf explore [OPTIONS] [--claim TEXT] [--steps N] -- COMMAND [ARGS]...

  run       runs the command once and reports what it did
  explore   an AI tester drives the program (its options, its questions, what it does later), then compares what it
            says with what it does. Needs a Gemini key: GEMINI_API_KEY or ~/.config/chouf/gemini

  --image IMAGE   container image (default ubuntu:24.04)
  --timeout SECS  stop a command after SECS seconds (default 300)
  --no-net        no network at all
  --allow-lan     let it reach your local network (by default chouf-trace refuses it: router, other machines)
  --file PATH     make PATH available read-only as /input/<name> (repeatable)
  --claim TEXT    explore: what the program is supposed to do (\"installs a GTK theme\")
  --steps N       explore: at most N steps after the first run (default 6)

The program runs as root inside a rootless container: it can change the whole system, only the copy is touched.
Its home (/root) is a fake one, full of bait secrets that exist nowhere else.
Every run is kept in ~/.local/share/chouf/sessions/<id>/ (report.json, stdout, stderr, home).";

struct Opts {
    image: String,
    timeout: Duration,
    net: bool,
    files: Vec<PathBuf>,
    cmd: Vec<String>,
    claim: Option<String>,
    steps: usize,
    allow_lan: bool,
}

fn parse(args: &[String], explore: bool) -> Result<Opts, String> {
    let mut o = Opts {
        image: "docker.io/library/ubuntu:24.04".into(),
        timeout: Duration::from_secs(300),
        net: true,
        files: vec![],
        cmd: vec![],
        claim: None,
        steps: explore::MAX_STEPS,
        allow_lan: false,
    };
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut value = |name: &str| it.next().cloned().ok_or(format!("{name} needs a value"));
        match a.as_str() {
            "--image" => o.image = value("--image")?,
            "--timeout" => o.timeout = Duration::from_secs(value("--timeout")?.parse().map_err(|_| "--timeout: seconds")?),
            "--no-net" => o.net = false,
            "--allow-lan" => o.allow_lan = true,
            "--file" => o.files.push(PathBuf::from(value("--file")?)),
            "--claim" if explore => o.claim = Some(value("--claim")?),
            "--steps" if explore => o.steps = value("--steps")?.parse().map_err(|_| "--steps: a number")?,
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

/// Where sessions are kept: CHOUF_DATA, else $XDG_DATA_HOME/chouf. (Tests set CHOUF_DATA: changing XDG_DATA_HOME
/// would also move podman's image store, and every test would pull its own copy of the image.)
fn data_dir() -> PathBuf {
    if let Some(d) = env::var_os("CHOUF_DATA") {
        return PathBuf::from(d);
    }
    env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env::var_os("HOME").unwrap_or_default()).join(".local/share"))
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

/// Everything a run needs before the sandbox exists: a session folder, a fake home full of baits, the input files.
struct Session {
    id: String,
    token: String,
    dir: PathBuf,
    home: PathBuf,
    input: Option<PathBuf>,
    canaries: Vec<canary::Canary>,
    noise: std::collections::BTreeSet<String>,
}

fn prepare(o: &Opts) -> io::Result<Session> {
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
            let name = f.file_name().ok_or_else(|| io::Error::other(format!("--file {}: not a file", f.display())))?;
            fs::copy(f, d.join(name))?; // a copy: podman relabels what it mounts, the user's own file stays as it is
        }
        Some(d)
    };
    fs::create_dir_all(cache_dir())?;
    let mut noise = sandbox::noise(&o.image, &cache_dir())?;
    noise.insert("/input".into()); // our own mount point
    Ok(Session { id, token, dir, home, input, canaries, noise })
}

fn tracer_result(t: io::Result<Option<trace::Tracer>>) -> Result<trace::Tracer, String> {
    match t {
        Ok(Some(t)) => Ok(t),
        Ok(None) => Err("no kernel tracer: install chouf-trace (sudo ./trace/install.sh) to see which program did what and where it connected, and to keep it off your local network".into()),
        Err(e) => Err(format!("kernel tracer unavailable: {e}")),
    }
}

/// Writes report.json and prints the report; the exit code says whether anything alarming was found.
fn finish(s: &Session, r: &report::Report) -> io::Result<ExitCode> {
    let mut json = r.json();
    json["token"] = s.token.clone().into();
    fs::write(s.dir.join("report.json"), serde_json::to_vec_pretty(&json).map_err(io::Error::other)?)?;
    let short = report::in_short(&r.findings, r.activity.as_ref().ok().copied());
    fs::write(s.dir.join("report.html"), html::page(&json, &short))?;
    print!("{}", r.text());
    println!("\nsession: {}  (report.html to share)", s.dir.display());
    let probed_lan = r.activity.as_ref().is_ok_and(|a| !a.blocked.is_empty());
    let alarming = probed_lan || r.findings.iter().any(|f| f.kind != report::Kind::Other);
    Ok(if alarming { ExitCode::from(1) } else { ExitCode::SUCCESS })
}

fn run(o: Opts) -> io::Result<ExitCode> {
    let s = prepare(&o)?;
    let spec = sandbox::Spec {
        name: format!("chouf-{}", s.id),
        image: &o.image,
        home: &s.home,
        input: s.input.as_deref(),
        cmd: &o.cmd,
        timeout: o.timeout,
        net: o.net,
    };
    let created = sandbox::create(&spec)?;
    // before start: the container's cgroup exists from `podman init`, so the program's first instruction is seen
    let tracer = tracer_result(trace::Tracer::start(&spec.name, o.net && !o.allow_lan));
    let watcher = watch::Watcher::start(&s.home)?;
    let outcome = created.start();
    let touches = watcher.stop()?;
    let activity = tracer.map(trace::Tracer::stop);
    let mut outcome = outcome?;
    outcome.fs = sandbox::interesting(std::mem::take(&mut outcome.fs), &s.noise);
    fs::write(s.dir.join("stdout"), &outcome.stdout)?;
    fs::write(s.dir.join("stderr"), &outcome.stderr)?;

    let mut findings = report::findings(&s.canaries, &touches, &outcome.fs);
    if let Ok(a) = &activity {
        report::attribute(&mut findings, a, &outcome.fs);
    }
    finish(
        &s,
        &report::Report {
            id: &s.id,
            image: &o.image,
            cmd: &o.cmd,
            outcome: &outcome,
            findings,
            transient: report::transient_count(&touches),
            incomplete: touches.incomplete,
            activity: activity.as_ref().map_err(Clone::clone),
            exploration: None,
        },
    )
}

/// Bait files some process opened so far, as "~/.ssh/id_ed25519".
fn baits_opened(a: &trace::Activity, canaries: &[canary::Canary]) -> Vec<String> {
    canaries
        .iter()
        .filter(|c| a.opens.iter().any(|o| o.path == format!("/root/{}", c.path)))
        .map(|c| format!("~/{}", c.path))
        .collect()
}

fn save_step(dir: &Path, n: usize, d: &Done) -> io::Result<()> {
    let steps = dir.join("steps");
    fs::create_dir_all(&steps)?;
    fs::write(steps.join(format!("{n}.stdout")), &d.stdout)?;
    fs::write(steps.join(format!("{n}.stderr")), &d.stderr)
}

fn explore(o: Opts) -> io::Result<ExitCode> {
    let (model, name): (Box<dyn llm::Llm>, String) = if let Some(s) = llm::Scripted::from_env() {
        (Box::new(s), "a scripted model (test)".into())
    } else if let Some(g) = llm::Gemini::from_env() {
        let name = g.model().to_string();
        (Box::new(g), name)
    } else {
        return Err(io::Error::other("explore needs a Gemini key: set GEMINI_API_KEY or write it to ~/.config/chouf/gemini"));
    };
    let s = prepare(&o)?;
    let keepalive = ["sleep".to_string(), "infinity".to_string()];
    let spec = sandbox::Spec {
        name: format!("chouf-{}", s.id),
        image: &o.image,
        home: &s.home,
        input: s.input.as_deref(),
        cmd: &keepalive,
        timeout: o.timeout,
        net: o.net,
    };
    let created = sandbox::create(&spec)?;
    let tracer = tracer_result(trace::Tracer::start(&spec.name, o.net && !o.allow_lan));
    let watcher = watch::Watcher::start(&s.home)?;
    let live = created.start_live()?;

    let mut done: Vec<Done> = Vec::new();
    let mut action = Action::Run { argv: o.cmd.clone(), stdin: String::new(), why: "the command you asked to check".into() };
    let mut note = None;
    loop {
        let (exit, timed_out, stdout, stderr) = match &action {
            Action::Run { argv, stdin, .. } => {
                eprintln!("chouf: [{}] $ {}", done.len() + 1, argv.join(" "));
                let st = live.exec(argv, stdin, o.timeout)?;
                (st.exit, st.timed_out, String::from_utf8_lossy(&st.stdout).into_owned(), String::from_utf8_lossy(&st.stderr).into_owned())
            }
            Action::Wait { .. } => {
                let pause = explore::wait_duration(&action).unwrap();
                eprintln!("chouf: [{}] waiting {} s", done.len() + 1, pause.as_secs());
                thread::sleep(pause);
                (None, false, String::new(), String::new())
            }
            Action::Stop { .. } => break,
        };
        let d = Done { action: action.clone(), exit, timed_out, stdout, stderr };
        save_step(&s.dir, done.len() + 1, &d)?;
        done.push(d);
        if timed_out || !live.alive() || done.len() > o.steps {
            break;
        }
        let a = tracer.as_ref().ok().map(trace::Tracer::snapshot);
        let seen = explore::observed(a.as_ref(), &a.as_ref().map(|a| baits_opened(a, &s.canaries)).unwrap_or_default());
        match explore::next(model.as_ref(), &o.cmd, o.claim.as_deref(), &done, &seen, o.steps + 1 - done.len()) {
            Ok(next) => {
                if let Action::Stop { why } = &next {
                    eprintln!("chouf: the explorer stops: {why}");
                }
                action = next;
            }
            Err(e) => {
                note = Some(format!("the explorer stopped early: {e}"));
                break;
            }
        }
    }

    let (fs_diff, elapsed) = live.finish()?;
    let touches = watcher.stop()?;
    let activity = tracer.map(trace::Tracer::stop);
    let first = done.first();
    let outcome = sandbox::Outcome {
        exit: first.and_then(|d| d.exit),
        timed_out: done.iter().any(|d| d.timed_out),
        stdout: first.map(|d| d.stdout.clone().into_bytes()).unwrap_or_default(),
        stderr: first.map(|d| d.stderr.clone().into_bytes()).unwrap_or_default(),
        elapsed,
        fs: sandbox::interesting(fs_diff, &s.noise),
    };
    let mut findings = report::findings(&s.canaries, &touches, &outcome.fs);
    if let Ok(a) = &activity {
        report::attribute(&mut findings, a, &outcome.fs);
    }
    let seen = explore::observed(activity.as_ref().ok(), &activity.as_ref().map(|a| baits_opened(a, &s.canaries)).unwrap_or_default());
    eprintln!("chouf: judging what it says against what it did ({name})");
    let verdict = explore::judge(model.as_ref(), &o.cmd, o.claim.as_deref(), &done, &findings, &seen)
        .map_err(|e| format!("no verdict: {e}"))
        .and_then(|v| v.ok_or_else(|| "no verdict: the model's answer was unusable".to_string()));
    finish(
        &s,
        &report::Report {
            id: &s.id,
            image: &o.image,
            cmd: &o.cmd,
            outcome: &outcome,
            findings,
            transient: report::transient_count(&touches),
            incomplete: touches.incomplete,
            activity: activity.as_ref().map_err(Clone::clone),
            exploration: Some(report::Exploration { steps: &done, verdict, model: name, note }),
        },
    )
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let (cmd, explore_mode): (fn(Opts) -> io::Result<ExitCode>, bool) = match args.first().map(String::as_str) {
        Some("run") => (run, false),
        Some("explore") => (explore, true),
        _ => {
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    match parse(&args[1..], explore_mode) {
        Ok(o) => cmd(o).unwrap_or_else(|e| {
            eprintln!("chouf: {e}");
            ExitCode::from(2)
        }),
        Err(e) => {
            eprintln!("chouf: {e}\n\n{USAGE}");
            ExitCode::from(2)
        }
    }
}
