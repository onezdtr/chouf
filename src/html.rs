//! report.html: the same report as a page anyone can open and share. Self-contained (no network, no script).
//! Everything in it that came from the program, the sandbox or the model is escaped: a hostile program cannot
//! write into the page.

use crate::i18n::{t, tf};
use serde_json::Value;

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&#39;")
}

fn text(v: &Value) -> String {
    esc(v.as_str().unwrap_or(""))
}

const STYLE: &str = r#"
:root{--bg:#f7f6f3;--panel:#fff;--line:#e7e4de;--fg:#1c1b19;--muted:#66625b;--bad:#b42318;--warn:#b54708;--ok:#067647;--mono:ui-monospace,"SF Mono",Menlo,monospace}
@media (prefers-color-scheme:dark){:root{--bg:#121211;--panel:#1b1a18;--line:#2d2b28;--fg:#edebe7;--muted:#a19c93;--bad:#f97066;--warn:#fdb022;--ok:#47cd89}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.55 -apple-system,"Inter",system-ui,sans-serif}
main{max-width:860px;margin:0 auto;padding:32px 16px 64px;display:grid;gap:18px}
header h1{font-size:22px;margin:0 0 4px;letter-spacing:-.01em}header p{margin:0;color:var(--muted);font-size:13px}
code,.mono{font-family:var(--mono);font-size:13px}
section{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px 18px}
h2{font-size:13px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin:0 0 10px}
.short p{margin:6px 0}.bad{color:var(--bad);font-weight:600}.warn{color:var(--warn);font-weight:600}.ok{color:var(--ok);font-weight:600}
ul{margin:6px 0;padding-left:20px}li{margin:3px 0}
.f{padding:8px 0;border-top:1px solid var(--line)}.f:first-of-type{border-top:0}
.f .by{color:var(--muted);font-size:13px;overflow-wrap:anywhere}.path{overflow-wrap:anywhere}
.tree div{white-space:pre-wrap;overflow-wrap:anywhere}
.verdict .level{font-size:17px}.note{color:var(--muted);font-size:13px}
"#;

/// The page, from report.json.
pub fn page(r: &Value, in_short: &str) -> String {
    let mut h = String::new();
    let cmd: Vec<String> = r["command"].as_array().into_iter().flatten().filter_map(|a| a.as_str()).map(esc).collect();
    h += &format!(
        "<header><h1>{}</h1><p>chouf session {} · {} · {}</p></header>",
        if crate::i18n::french() { format!("Ce que <code>{}</code> a vraiment fait", cmd.join(" ")) } else { format!("What <code>{}</code> really did", cmd.join(" ")) },
        text(&r["session"]),
        text(&r["image"]),
        match r["exit_code"].as_i64() {
            Some(c) => format!("exit {c}"),
            None if r["timed_out"] == true => "stopped at the time limit".into(),
            None => "no exit code".into(),
        }
    );
    // the plain summary, line by line: "!!" lines are alarms
    h += &format!("<section class=\"short\"><h2>{}</h2>", t("In short"));
    let calm = t("Nothing alarming: no secret touched, nothing set to run again, nothing new trusted.");
    for line in in_short.lines().map(str::trim).filter(|l| !l.is_empty() && *l != t("In short")) {
        if let Some(rest) = line.strip_prefix("!! ") {
            h += &format!("<p class=\"bad\">{}</p>", esc(rest));
        } else if let Some(rest) = line.strip_prefix("- ") {
            h += &format!("<ul><li>{}</li></ul>", esc(rest));
        } else if line == calm {
            h += &format!("<p class=\"ok\">{}</p>", esc(line));
        } else {
            h += &format!("<p>{}</p>", esc(line));
        }
    }
    h += "</section>";

    if let Some(v) = r["exploration"]["verdict"].as_object() {
        let level = v.get("level").and_then(Value::as_str).unwrap_or("");
        let (class, words) = match level {
            "consistent" => ("ok", t("consistent: it does what it says")),
            "suspicious" => ("warn", t("SUSPICIOUS: it does things it does not explain")),
            "malicious" => ("bad", t("MALICIOUS: it steals, hides or contradicts itself")),
            _ => ("note", "—".to_string()),
        };
        h += &format!(
            "<section class=\"verdict\"><h2>{}</h2><p class=\"level {class}\">{words}</p><p>{}</p><ul>",
            t("What it says vs what it does"),
            esc(v.get("summary").and_then(Value::as_str).unwrap_or(""))
        );
        for p in v.get("points").and_then(Value::as_array).into_iter().flatten() {
            let mark = match p["assessment"].as_str() {
                Some("consistent") => "<span class=\"ok\">ok</span>",
                Some("contradicts") => "<span class=\"bad\">contradicts</span>",
                _ => "<span class=\"warn\">unexplained</span>",
            };
            h += &format!("<li>{mark} · {} {} — {} {}</li>", t("says:"), text(&p["says"]), t("does:"), text(&p["does"]));
        }
        h += &format!("</ul><p class=\"note\">{}</p></section>", tf("(opinion of {}, not a measurement)", &[&text(&r["exploration"]["model"])]));
    }

    for (kind, title) in [
        ("secret", "Secrets it went after"),
        ("persistence", "Ways it will run again by itself"),
        ("trust", "What it now trusts"),
        ("other", "Everything else it changed"),
    ] {
        let list: Vec<&Value> = r["findings"].as_array().into_iter().flatten().filter(|f| f["kind"] == kind).collect();
        if list.is_empty() {
            continue;
        }
        h += &format!("<section><h2>{}</h2>", t(title));
        for f in list {
            let did: Vec<String> = f["did"].as_array().into_iter().flatten().filter_map(|d| d.as_str()).map(|d| esc(&t(d))).collect();
            let mut notes: Vec<String> = f["why"].as_str().filter(|w| !w.is_empty()).map(crate::i18n::why).into_iter().collect();
            if let Some(p) = f["package"].as_str().filter(|p| !p.is_empty()) {
                notes.push(tf("package {}", &[p]));
            }
            let why = esc(&notes.join(" · "));
            h += &format!(
                "<div class=\"f\"><span class=\"{}\">{}</span> <span class=\"path mono\">{}</span>{}",
                if kind == "other" { "note" } else { "bad" },
                did.join(", "),
                match f["count"].as_u64() { Some(n) if n > 1 => tf("{} files in {}", &[&n.to_string(), &text(&f["path"])]), _ => text(&f["path"]) },
                if why.is_empty() { String::new() } else { format!(" <span class=\"note\">({why})</span>") }
            );
            for l in f["lines"].as_array().into_iter().flatten().take(4) {
                h += &format!("<div class=\"by mono\">+ {}</div>", text(l));
            }
            for b in f["by"].as_array().into_iter().flatten().take(if kind == "other" { 0 } else { 3 }) {
                h += &format!("<div class=\"by mono\">{} {}</div>", t("by"), text(b));
            }
            h += "</div>";
        }
        h += "</section>";
    }

    let a = &r["activity"];
    if let Some(leaks) = a["leaks"].as_array().filter(|l| !l.is_empty()) {
        h += &format!("<section><h2>{}</h2>", t("What left the machine"));
        for l in leaks.iter().take(20) {
            let dest = l["name"].as_str().map(esc).unwrap_or_else(|| text(&l["ip"]));
            h += &format!("<div class=\"f\"><span class=\"bad\">{} → {dest} (port {})</span><div class=\"by mono\">{} {}</div><div class=\"by mono\">&ldquo;{}&rdquo;</div></div>", l["what"].as_str().map(|w| esc(&t(w))).unwrap_or_else(|| t("one of your secrets")), l["port"], t("by"), text(&l["by"]), text(&l["excerpt"]));
        }
        h += "</section>";
    }
    if let Some(conns) = a["connections"].as_array().filter(|c| !c.is_empty()) {
        h += &format!("<section><h2>{}</h2>", t("Where it connected"));
        for c in conns.iter().take(50) {
            let dest = match c["name"].as_str() {
                Some(n) => format!("{} ({})", esc(n), text(&c["ip"])),
                None => text(&c["ip"]),
            };
            let sent = c["sent"].as_u64().unwrap_or(0);
            let bytes = if sent > 0 { format!(" · sent {sent} bytes") } else { String::new() };
            h += &format!("<div class=\"f\"><span class=\"mono\">{dest} port {}{bytes}</span><div class=\"by mono\">{} {}</div></div>", c["port"], t("by"), text(&c["by"]));
        }
        h += "</section>";
    }
    if let Some(blocked) = a["blocked"].as_array().filter(|b| !b.is_empty()) {
        h += &format!("<section><h2>{}</h2>", t("What chouf refused on your local network"));
        for b in blocked.iter().take(50) {
            h += &format!("<div class=\"f\"><span class=\"bad mono\">{}:{} {}</span><div class=\"by mono\">{} {}</div></div>", text(&b["ip"]), b["port"], text(&b["proto"]), t("by"), text(&b["by"]));
        }
        h += "</section>";
    }
    if let Some(progs) = a["programs"].as_array().filter(|p| !p.is_empty()) {
        h += &format!("<section class=\"tree\"><h2>{} ({})</h2>", t("Programs it ran"), progs.len());
        for p in progs.iter().take(200) {
            let depth = p["depth"].as_u64().unwrap_or(0).min(8) as usize;
            h += &format!("<div class=\"mono\">{}{}</div>", "&nbsp;&nbsp;".repeat(depth), text(&p["command"]));
        }
        h += "</section>";
    }
    if let Some(why) = a["unavailable"].as_str() {
        h += &format!("<p class=\"note\">{}</p>", esc(why));
    }
    format!(
        "<!doctype html><html lang=\"{}\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">\
<title>chouf · {}</title><style>{STYLE}</style></head><body><main>{h}</main></body></html>",
        if crate::i18n::french() { "fr" } else { "en" },
        cmd.join(" ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn nothing_from_the_program_can_write_into_the_page() {
        let evil = "<script>alert(1)</script>\"><img src=x onerror=alert(2)>";
        let r = json!({"command": ["sh", evil], "session": "s", "image": "i", "exit_code": 0,
            "findings": [{"kind": "secret", "path": evil, "did": ["read"], "why": evil, "by": [evil]}],
            "activity": {"connections": [{"name": evil, "ip": "1.2.3.4", "port": 80, "by": evil}], "programs": [{"depth": 0, "command": evil}]},
            "exploration": {"model": evil, "verdict": {"level": "malicious", "summary": evil, "points": [{"says": evil, "does": evil, "assessment": "contradicts"}]}}});
        let p = page(&r, &format!("In short\n   !! {evil}\n"));
        assert!(!p.contains("<script>") && !p.contains("<img"), "unescaped program text");
        assert!(p.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(p.contains("Content-Security-Policy") && p.contains("MALICIOUS"));
    }
}
