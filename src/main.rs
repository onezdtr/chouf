mod canary;
mod explore;
mod html;
mod llm;
mod persist;
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

/// Home files a program changes to come back by itself: the startup files chouf planted (compared with what it
/// wrote), and anything in the folders the desktop and systemd start from.
fn home_ways_back(home: &Path) -> Vec<String> {
    let mut out = Vec::new();
    for rel in [".bashrc", ".zshrc", ".profile", ".bash_profile", ".ssh/rc"] {
        if let Ok(now) = fs::read_to_string(home.join(rel)) {
            if canary::planted(rel) != Some(now.as_str()) {
                out.push(format!("~/{rel}"));
            }
        }
    }
    for dir in [".config/autostart", ".config/systemd/user"] {
        for e in fs::read_dir(home.join(dir)).into_iter().flatten().flatten() {
            out.push(format!("~/{dir}/{}", e.file_name().to_string_lossy()));
        }
    }
    out
}

/// Sets off, once, what the program set up to come back (persist.rs), watched like the rest of the run.
fn set_off(live: &sandbox::Live, s: &Session) -> io::Result<Vec<Done>> {
    if !live.alive() {
        return Ok(vec![]);
    }
    let sys = sandbox::interesting(live.diff_now()?, &s.noise);
    let system: Vec<String> = sys.added.into_iter().chain(sys.changed).collect();
    let read = |p: &str| live.read_file(p);
    let mut done = Vec::new();
    for t in persist::plan(&home_ways_back(&s.home), &system, &read) {
        eprintln!("chouf: setting off what it set up: {}", t.why);
        let st = live.exec(&t.argv, "", Duration::from_secs(persist::TRIGGER_SECONDS + 15))?;
        done.push(Done {
            action: Action::Run { argv: t.argv, stdin: String::new(), why: t.why },
            exit: st.exit,
            timed_out: st.timed_out,
            stdout: String::from_utf8_lossy(&st.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&st.stderr).into_owned(),
        });
        if st.timed_out || !live.alive() {
            break;
        }
    }
    Ok(done)
}

/// The sandbox every run uses: created, watched from its first instruction, then started as a desktop-looking machine
/// that stays up while commands run in it.
struct Machine<'a> {
    live: sandbox::Live<'a>,
    tracer: Result<trace::Tracer, String>,
    watcher: watch::Watcher,
}

fn machine<'a>(o: &Opts, s: &Session, spec: &'a sandbox::Spec<'a>) -> io::Result<Machine<'a>> {
    let created = sandbox::create(spec)?;
    // before start: the container's cgroup exists from `podman init`, so the first instruction is seen
    let tracer = tracer_result(trace::Tracer::start(&spec.name, o.net && !o.allow_lan));
    let watcher = watch::Watcher::start(&s.home)?;
    let live = created.start_live()?;
    Ok(Machine { live, tracer, watcher })
}

fn spec<'a>(o: &'a Opts, s: &'a Session, keepalive: &'a [String]) -> sandbox::Spec<'a> {
    sandbox::Spec {
        name: format!("chouf-{}", s.id),
        image: &o.image,
        home: &s.home,
        input: s.input.as_deref(),
        cmd: keepalive,
        timeout: o.timeout,
        net: o.net,
    }
}

/// Stops the machine and writes the report.
/// `judge` (explore): turns the measured findings into the exploration part of the report, verdict included.
fn conclude<'e>(
    o: &Opts,
    s: &Session,
    m: Machine,
    first: Option<&Done>,
    judge: Option<&dyn Fn(&[report::Finding], &str) -> report::Exploration<'e>>,
    triggered: &[Done],
) -> io::Result<ExitCode> {
    let init = m.live.init_pid;
    let (fs_diff, elapsed) = m.live.finish()?;
    let touches = m.watcher.stop()?;
    let activity = m.tracer.map(|t| t.stop().without_tree(init).without_our_reads());
    let outcome = sandbox::Outcome {
        exit: first.and_then(|d| d.exit),
        timed_out: first.is_some_and(|d| d.timed_out),
        stdout: first.map(|d| d.stdout.clone().into_bytes()).unwrap_or_default(),
        stderr: first.map(|d| d.stderr.clone().into_bytes()).unwrap_or_default(),
        elapsed,
        fs: sandbox::interesting(fs_diff, &s.noise),
    };
    fs::write(s.dir.join("stdout"), &outcome.stdout)?;
    fs::write(s.dir.join("stderr"), &outcome.stderr)?;
    let mut findings = report::findings(&s.canaries, &touches, &outcome.fs);
    if let Ok(a) = &activity {
        report::attribute(&mut findings, a, &outcome.fs);
    }
    let seen = explore::observed(activity.as_ref().ok(), &activity.as_ref().map(|a| baits_opened(a, &s.canaries)).unwrap_or_default());
    let exploration = judge.map(|j| j(&findings, &seen));
    finish(
        s,
        &report::Report {
            id: &s.id,
            image: &o.image,
            cmd: &o.cmd,
            outcome: &outcome,
            findings,
            transient: report::transient_count(&touches),
            incomplete: touches.incomplete,
            activity: activity.as_ref().map_err(Clone::clone),
            exploration,
            triggered,
        },
    )
}

fn run_step(live: &sandbox::Live, argv: &[String], stdin: &str, why: &str, timeout: Duration) -> io::Result<Done> {
    let st = live.exec(argv, stdin, timeout)?;
    Ok(Done {
        action: Action::Run { argv: argv.to_vec(), stdin: stdin.to_string(), why: why.to_string() },
        exit: st.exit,
        timed_out: st.timed_out,
        stdout: String::from_utf8_lossy(&st.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&st.stderr).into_owned(),
    })
}

fn run(o: Opts) -> io::Result<ExitCode> {
    let s = prepare(&o)?;
    let keepalive = sandbox::keepalive();
    let spec = spec(&o, &s, &keepalive);
    let m = machine(&o, &s, &spec)?;
    let first = run_step(&m.live, &o.cmd, "", "the command you asked to check", o.timeout)?;
    let triggered = if first.timed_out { vec![] } else { set_off(&m.live, &s)? };
    conclude(&o, &s, m, Some(&first), None, &triggered)
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
    let (model, name): (Box<dyn llm::Llm>, String) = if let Some(sc) = llm::Scripted::from_env() {
        (Box::new(sc), "a scripted model (test)".into())
    } else if let Some(g) = llm::Gemini::from_env() {
        let name = g.model().to_string();
        (Box::new(g), name)
    } else {
        return Err(io::Error::other("explore needs a Gemini key: set GEMINI_API_KEY or write it to ~/.config/chouf/gemini"));
    };
    let s = prepare(&o)?;
    let keepalive = sandbox::keepalive();
    let spec = spec(&o, &s, &keepalive);
    let m = machine(&o, &s, &spec)?;

    let mut done: Vec<Done> = Vec::new();
    let mut action = Action::Run { argv: o.cmd.clone(), stdin: String::new(), why: "the command you asked to check".into() };
    let mut note = None;
    loop {
        let d = match &action {
            Action::Run { argv, stdin, why } => {
                eprintln!("chouf: [{}] $ {}", done.len() + 1, argv.join(" "));
                run_step(&m.live, argv, stdin, why, o.timeout)?
            }
            Action::Wait { .. } => {
                let pause = explore::wait_duration(&action).unwrap();
                eprintln!("chouf: [{}] waiting {} s", done.len() + 1, pause.as_secs());
                thread::sleep(pause);
                Done { action: action.clone(), exit: None, timed_out: false, stdout: String::new(), stderr: String::new() }
            }
            Action::Stop { .. } => break,
        };
        save_step(&s.dir, done.len() + 1, &d)?;
        let stop = d.timed_out || !m.live.alive();
        done.push(d);
        if stop || done.len() > o.steps {
            break;
        }
        let a = m.tracer.as_ref().ok().map(|t| t.snapshot().without_tree(m.live.init_pid));
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
    let triggered = if done.iter().any(|d| d.timed_out) { vec![] } else { set_off(&m.live, &s)? };
    let first = done.first().cloned();
    let all: Vec<Done> = done.iter().chain(&triggered).cloned().collect();
    let judge = |findings: &[report::Finding], seen: &str| {
        eprintln!("chouf: judging what it says against what it did ({name})");
        let verdict = explore::judge(model.as_ref(), &o.cmd, o.claim.as_deref(), &all, findings, seen)
            .map_err(|e| format!("no verdict: {e}"))
            .and_then(|v| v.ok_or_else(|| "no verdict: the model's answer was unusable".to_string()));
        report::Exploration { steps: &done, verdict, model: name.clone(), note: note.clone() }
    };
    conclude(&o, &s, m, first.as_ref(), Some(&judge), &triggered)
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
