//! The bait: a fake home that looks lived-in and is full of secrets that do not exist anywhere else.
//! Every value carries the session token, so a leaked secret can be traced back to the run that leaked it.

use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

pub struct Canary {
    /// Path relative to the home directory.
    pub path: String,
    /// What a thief would believe it is.
    pub what: &'static str,
}

/// A fresh random token (16 hex chars).
pub fn token() -> io::Result<String> {
    let mut b = [0u8; 8];
    io::Read::read_exact(&mut fs::File::open("/dev/urandom")?, &mut b)?;
    Ok(b.iter().map(|x| format!("{x:02x}")).collect())
}

fn baits(t: &str) -> Vec<(&'static str, &'static str, String)> {
    let up = t.to_uppercase();
    vec![
        (".ssh/id_ed25519", "SSH private key",
         format!("-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ{t}chouf\n-----END OPENSSH PRIVATE KEY-----\n")),
        (".aws/credentials", "AWS access keys",
         format!("[default]\naws_access_key_id = AKIA{up}\naws_secret_access_key = {t}{t}chouf/canary\n")),
        (".config/gh/hosts.yml", "GitHub CLI token",
         format!("github.com:\n    user: dev\n    oauth_token: gho_{t}chouf\n    git_protocol: https\n")),
        (".git-credentials", "Git passwords", format!("https://dev:ghp_{t}chouf@github.com\n")),
        (".npmrc", "npm publish token", format!("//registry.npmjs.org/:_authToken=npm_{t}chouf\n")),
        (".docker/config.json", "Docker registry login", format!("{{\"auths\":{{\"https://index.docker.io/v1/\":{{\"auth\":\"{t}chouf\"}}}}}}\n")),
        (".kube/config", "Kubernetes cluster token",
         format!("apiVersion: v1\nkind: Config\nusers:\n- name: admin\n  user:\n    token: {t}chouf\n")),
        (".config/google-chrome/Default/Cookies", "Chrome cookies", format!("SQLite format 3\0chouf {t}\n")),
        (".config/google-chrome/Default/Login Data", "Chrome saved passwords", format!("SQLite format 3\0chouf {t}\n")),
        (".mozilla/firefox/k3x9.default-release/cookies.sqlite", "Firefox cookies", format!("SQLite format 3\0chouf {t}\n")),
        (".mozilla/firefox/k3x9.default-release/logins.json", "Firefox saved passwords",
         format!("{{\"logins\":[{{\"hostname\":\"https://bank.example\",\"encryptedPassword\":\"{t}chouf\"}}]}}\n")),
        (".electrum/wallets/default_wallet", "Bitcoin wallet", format!("{{\"seed\":\"chouf {t}\",\"wallet_type\":\"standard\"}}\n")),
        (".gnupg/private-keys-v1.d/A1B2C3.key", "GPG private key", format!("(private-key (rsa (n #{up}#)))\n")),
        (".bash_history", "Shell history",
         format!("ls\ncd projects/shop\nexport OPENAI_API_KEY=sk-{t}chouf\ngit push\n")),
        ("projects/shop/.env", "App secrets (.env)",
         format!("DATABASE_URL=postgres://shop:{t}@db.internal/shop\nSTRIPE_SECRET_KEY=sk_live_{t}chouf\n")),
    ]
}

/// Ordinary files, so the home looks real. Not bait.
const PLAIN: &[(&str, &str)] = &[
    (".bashrc", "# ~/.bashrc\n[ -z \"$PS1\" ] && return\nalias ll='ls -l'\n"),
    (".profile", "# ~/.profile\n[ -f ~/.bashrc ] && . ~/.bashrc\n"),
    (".ssh/known_hosts", "github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n"),
    (".mozilla/firefox/profiles.ini", "[Profile0]\nName=default-release\nIsRelative=1\nPath=k3x9.default-release\nDefault=1\n"),
    ("projects/shop/README.md", "# shop\n"),
];

/// Writes the fake home and returns the bait list.
pub fn plant(home: &Path, token: &str) -> io::Result<Vec<Canary>> {
    let write = |rel: &str, body: &[u8], mode: u32| -> io::Result<()> {
        let p = home.join(rel);
        fs::create_dir_all(p.parent().unwrap())?;
        fs::write(&p, body)?;
        fs::set_permissions(&p, fs::Permissions::from_mode(mode))
    };
    for (rel, body) in PLAIN {
        write(rel, body.as_bytes(), 0o644)?;
    }
    let mut out = Vec::new();
    for (rel, what, body) in baits(token) {
        write(rel, body.as_bytes(), 0o600)?;
        out.push(Canary {
            path: rel.to_string(),
            what,
        });
    }
    fs::set_permissions(home.join(".ssh"), fs::Permissions::from_mode(0o700))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_bait_carries_the_token_and_tokens_differ() {
        let dir = std::env::temp_dir().join(format!("chouf-canary-{}", std::process::id()));
        let t = token().unwrap();
        assert_eq!(t.len(), 16);
        assert_ne!(t, token().unwrap());
        let baits = plant(&dir, &t).unwrap();
        assert!(baits.len() >= 10);
        for c in &baits {
            let body = fs::read(dir.join(&c.path)).unwrap();
            let s = String::from_utf8_lossy(&body).to_lowercase();
            assert!(s.contains(&t), "{} lacks the token", c.path);
        }
        assert_eq!(
            fs::metadata(dir.join(".ssh/id_ed25519"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        fs::remove_dir_all(dir).unwrap();
    }
}
