//! The model behind the explorer: Gemini through its REST API, called with curl (no HTTP stack in chouf).
//! The key comes from GEMINI_API_KEY or ~/.config/chouf/gemini and reaches curl through a private header file,
//! never the command line (which every user of the machine can read in the process list).

use serde_json::{json, Value};
use std::env;
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

/// Anything that turns a prompt and a JSON schema into a JSON answer: Gemini, or a script in tests.
pub trait Llm {
    fn ask(&self, prompt: &str, schema: &Value) -> io::Result<Value>;
}

pub struct Gemini {
    key: String,
    model: String,
}

impl Gemini {
    /// None when no key is configured.
    pub fn from_env() -> Option<Gemini> {
        let key = env::var("GEMINI_API_KEY").ok().filter(|k| !k.is_empty()).or_else(|| {
            let home = PathBuf::from(env::var_os("HOME")?);
            fs::read_to_string(home.join(".config/chouf/gemini")).ok().map(|k| k.trim().to_string())
        })?;
        let model = env::var("CHOUF_MODEL").unwrap_or_else(|_| "gemini-3.1-flash-lite".into());
        Some(Gemini { key, model })
    }

    pub fn model(&self) -> &str {
        &self.model
    }

    fn call(&self, body: &Value) -> io::Result<Value> {
        let dir = env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from).unwrap_or_else(env::temp_dir);
        let header = dir.join(format!("chouf-key-{}-{:?}", std::process::id(), thread::current().id()));
        {
            let mut f = fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&header)?;
            writeln!(f, "x-goog-api-key: {}", self.key)?;
        }
        let url = format!("https://generativelanguage.googleapis.com/v1beta/models/{}:generateContent", self.model);
        let out = Command::new("curl")
            .args(["--silent", "--show-error", "--max-time", "120", "--write-out", "\n%{http_code}"])
            .arg("--header")
            .arg(format!("@{}", header.display()))
            .args(["--header", "Content-Type: application/json", "--data-binary", "@-", &url])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .and_then(|mut c| {
                c.stdin.take().unwrap().write_all(body.to_string().as_bytes())?;
                c.wait_with_output()
            });
        let _ = fs::remove_file(&header);
        let out = out?;
        let text = String::from_utf8_lossy(&out.stdout);
        let (payload, code) = text.rsplit_once('\n').unwrap_or((&text, "0"));
        let code = code.trim();
        if code == "000" {
            // no HTTP answer at all: network trouble, worth another try
            return Err(io::Error::other(format!("Gemini unreachable (HTTP 000): {}", String::from_utf8_lossy(&out.stderr).trim())));
        }
        if code != "200" {
            return Err(io::Error::other(format!("Gemini answered HTTP {code}: {}", payload.chars().take(300).collect::<String>())));
        }
        serde_json::from_str(payload).map_err(io::Error::other)
    }
}

impl Llm for Gemini {
    fn ask(&self, prompt: &str, schema: &Value) -> io::Result<Value> {
        let body = json!({
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": {"temperature": 0.2, "responseMimeType": "application/json", "responseSchema": schema},
        });
        let mut last = None;
        for attempt in 0..3 {
            match self.call(&body) {
                Ok(v) => {
                    let text: String = v["candidates"][0]["content"]["parts"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter(|p| p["thought"] != true)
                        .filter_map(|p| p["text"].as_str())
                        .collect();
                    return serde_json::from_str(&text).map_err(|e| io::Error::other(format!("not JSON from the model: {e}")));
                }
                // the free tier often answers 429 or 503 for a moment
                Err(e) if ["HTTP 429", "HTTP 500", "HTTP 503", "HTTP 000"].iter().any(|c| e.to_string().contains(c)) => {
                    last = Some(e);
                    thread::sleep(Duration::from_secs(5 * (attempt + 1)));
                }
                Err(e) => return Err(e),
            }
        }
        Err(last.unwrap())
    }
}

/// A model that replays answers from a file, one JSON value per line (CHOUF_FAKE_LLM): end-to-end tests of the
/// explorer without network or key. Every prompt it gets is appended to the file's ".prompts" sibling.
pub struct Scripted {
    answers: std::sync::Mutex<std::collections::VecDeque<Value>>,
    log: PathBuf,
}

impl Scripted {
    pub fn from_env() -> Option<Scripted> {
        let path = PathBuf::from(env::var_os("CHOUF_FAKE_LLM")?);
        let answers = fs::read_to_string(&path).ok()?.lines().filter_map(|l| serde_json::from_str(l).ok()).collect();
        Some(Scripted { answers: std::sync::Mutex::new(answers), log: path.with_extension("prompts") })
    }
}

impl Llm for Scripted {
    fn ask(&self, prompt: &str, _schema: &Value) -> io::Result<Value> {
        let mut f = fs::OpenOptions::new().create(true).append(true).open(&self.log)?;
        writeln!(f, "=====\n{prompt}")?;
        self.answers.lock().unwrap().pop_front().ok_or_else(|| io::Error::other("the script has no more answers"))
    }
}

