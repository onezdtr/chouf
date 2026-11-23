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
    /// The family it belongs to, in words anyone understands: "passwords", "crypto wallets"...
    pub group: &'static str,
}

pub const PASSWORDS: &str = "passwords and browser logins";
pub const WALLETS: &str = "crypto wallets";
pub const DEV: &str = "developer and cloud keys";
pub const CHAT: &str = "messaging accounts";
pub const PRIVATE: &str = "private keys and history";

/// The programs that read a bait as part of their normal job (npm reads ~/.npmrc, git ~/.git-credentials, ssh the
/// SSH keys). Matched on the name of the program run or of the script given to an interpreter (`python3 pip`).
/// A bait read only by its own tools is not a theft; read by anything else, it still is. Browsers, wallets and chat
/// sessions have no installer as their own tool: none listed.
pub fn own_tools(rel: &str) -> &'static [&'static str] {
    const TABLE: &[(&str, &[&str])] = &[
        (".npmrc", &["npm", "npx", "pnpm", "yarn", "corepack"]),
        (".netrc", &["pip", "pip3", "curl", "wget", "git", "git-remote-http", "git-remote-https", "ftp", "uv"]),
        (".pypirc", &["twine", "poetry", "flit", "hatch"]),
        (".git-credentials", &["git", "git-credential-store", "git-remote-http", "git-remote-https"]),
        (".docker/config.json", &["docker", "podman", "buildah", "skopeo", "docker-credential-desktop"]),
        (".kube/config", &["kubectl", "helm", "k9s", "kubectx", "minikube", "kind"]),
        (".config/gh/hosts.yml", &["gh"]),
        (".aws/credentials", &["aws", "aws_completer"]),
        (".cargo/credentials.toml", &["cargo"]),
        (".config/gcloud/", &["gcloud", "gsutil", "bq"]),
        (".azure/", &["az"]),
        (".vault-token", &["vault"]),
        (".terraform.d/", &["terraform", "tofu"]),
        (".pgpass", &["psql", "pg_dump", "pg_restore", "pg_dumpall"]),
        (".config/rclone/", &["rclone"]),
        (".ssh/id_", &["ssh", "scp", "sftp", "ssh-add", "ssh-keygen", "git", "rsync"]),
        (".gnupg/", &["gpg", "gpg2", "gpg-agent", "gpgsm"]),
    ];
    TABLE.iter().find(|(p, _)| rel.starts_with(p)).map(|(_, t)| *t).unwrap_or(&[])
}

/// A fresh random token (16 hex chars).
pub fn token() -> io::Result<String> {
    let mut b = [0u8; 8];
    io::Read::read_exact(&mut fs::File::open("/dev/urandom")?, &mut b)?;
    Ok(b.iter().map(|x| format!("{x:02x}")).collect())
}

fn baits(t: &str) -> Vec<(&'static str, &'static str, &'static str, String)> {
    let up = t.to_uppercase();
    // (path, what it looks like, group, content). Paths are where real info-stealers look on Linux.
    let sqlite = || format!("SQLite format 3\0chouf {t}\n");
    let leveldb = || format!("\0\0chouf leveldb {t}\n");
    vec![
        (".ssh/id_ed25519", "SSH private key", PRIVATE,
         format!("-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ{t}chouf\n-----END OPENSSH PRIVATE KEY-----\n")),
        (".aws/credentials", "AWS access keys", DEV,
         format!("[default]\naws_access_key_id = AKIA{up}\naws_secret_access_key = {t}{t}chouf/canary\n")),
        (".config/gh/hosts.yml", "GitHub CLI token", DEV,
         format!("github.com:\n    user: dev\n    oauth_token: gho_{t}chouf\n    git_protocol: https\n")),
        (".git-credentials", "Git passwords", DEV, format!("https://dev:ghp_{t}chouf@github.com\n")),
        (".npmrc", "npm publish token", DEV, format!("//registry.npmjs.org/:_authToken=npm_{t}chouf\n")),
        (".docker/config.json", "Docker registry login", DEV, format!("{{\"auths\":{{\"https://index.docker.io/v1/\":{{\"auth\":\"{t}chouf\"}}}}}}\n")),
        (".kube/config", "Kubernetes cluster token", DEV,
         format!("apiVersion: v1\nkind: Config\nusers:\n- name: admin\n  user:\n    token: {t}chouf\n")),
        (".config/google-chrome/Default/Cookies", "Chrome cookies", PASSWORDS, sqlite()),
        (".config/google-chrome/Default/Login Data", "Chrome saved passwords", PASSWORDS, sqlite()),
        (".mozilla/firefox/k3x9.default-release/cookies.sqlite", "Firefox cookies", PASSWORDS, sqlite()),
        (".mozilla/firefox/k3x9.default-release/logins.json", "Firefox saved passwords", PASSWORDS,
         format!("{{\"logins\":[{{\"hostname\":\"https://bank.example\",\"encryptedPassword\":\"{t}chouf\"}}]}}\n")),
        (".electrum/wallets/default_wallet", "Bitcoin wallet", WALLETS, format!("{{\"seed\":\"chouf {t}\",\"wallet_type\":\"standard\"}}\n")),
        (".gnupg/private-keys-v1.d/A1B2C3.key", "GPG private key", PRIVATE, format!("(private-key (rsa (n #{up}#)))\n")),
        (".bash_history", "Shell history", PRIVATE,
         format!("ls\ncd projects/shop\nexport OPENAI_API_KEY=sk-{t}chouf\ngit push\n")),
        ("projects/shop/.env", "App secrets (.env)", DEV,
         format!("DATABASE_URL=postgres://shop:{t}@db.internal/shop\nSTRIPE_SECRET_KEY=sk_live_{t}chouf\n")),
        (".ssh/id_rsa", "SSH private key (RSA)", PRIVATE,
         format!("-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA{up}chouf\n-----END RSA PRIVATE KEY-----\n")),
        // other browsers
        (".config/BraveSoftware/Brave-Browser/Default/Login Data", "Brave saved passwords", PASSWORDS, sqlite()),
        (".config/BraveSoftware/Brave-Browser/Default/Cookies", "Brave cookies", PASSWORDS, sqlite()),
        (".config/chromium/Default/Cookies", "Chromium cookies", PASSWORDS, sqlite()),
        (".config/microsoft-edge/Default/Login Data", "Edge saved passwords", PASSWORDS, sqlite()),
        // password managers
        ("Documents/Passwords.kdbx", "KeePass password database", PASSWORDS, format!("\u{3}\u{d9}\u{a2}\u{9a}chouf kdbx {t}\n")),
        (".config/Bitwarden/data.json", "Bitwarden vault", PASSWORDS,
         format!("{{\"global\":{{\"vaultTimeout\":15}},\"user_chouf\":{{\"encryptedKey\":\"{t}\"}}}}\n")),
        // crypto wallets
        (".config/google-chrome/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn/000003.log",
         "MetaMask wallet (browser extension)", WALLETS, leveldb()),
        (".config/Exodus/exodus.wallet/seed.seco", "Exodus wallet seed", WALLETS, format!("SECO chouf {t}\n")),
        (".ethereum/keystore/UTC--2025-03-14T09-12-44.512Z--5e1f", "Ethereum wallet key", WALLETS,
         format!("{{\"address\":\"5e1f{t}\",\"crypto\":{{\"cipher\":\"aes-128-ctr\",\"ciphertext\":\"{t}chouf\"}}}}\n")),
        (".config/solana/id.json", "Solana wallet key", WALLETS, format!("[12,{},chouf,{t}]\n", t.len())),
        // messaging
        (".local/share/TelegramDesktop/tdata/key_datas", "Telegram session", CHAT, format!("TDF$chouf {t}\n")),
        (".config/discord/Local Storage/leveldb/000005.ldb", "Discord login token", CHAT, leveldb()),
        (".config/Slack/Cookies", "Slack session cookies", CHAT, sqlite()),
        // cloud and developer
        (".config/gcloud/application_default_credentials.json", "Google Cloud credentials", DEV,
         format!("{{\"client_id\":\"chouf.apps.googleusercontent.com\",\"refresh_token\":\"1//{t}chouf\",\"type\":\"authorized_user\"}}\n")),
        (".azure/msal_token_cache.json", "Azure login tokens", DEV, format!("{{\"RefreshToken\":{{\"chouf\":{{\"secret\":\"{t}\"}}}}}}\n")),
        (".netrc", "Saved server passwords (.netrc)", DEV, format!("machine ftp.example.com login deploy password {t}chouf\n")),
        (".pypirc", "PyPI upload token", DEV, format!("[pypi]\nusername = __token__\npassword = pypi-{t}chouf\n")),
        (".cargo/credentials.toml", "crates.io publish token", DEV, format!("[registry]\ntoken = \"cio{t}chouf\"\n")),
        (".vault-token", "HashiCorp Vault token", DEV, format!("hvs.{t}chouf\n")),
        (".terraform.d/credentials.tfrc.json", "Terraform Cloud token", DEV,
         format!("{{\"credentials\":{{\"app.terraform.io\":{{\"token\":\"{t}.atlasv1.chouf\"}}}}}}\n")),
        (".pgpass", "PostgreSQL passwords", DEV, format!("db.internal:5432:shop:shop:{t}chouf\n")),
        (".config/rclone/rclone.conf", "Cloud storage logins (rclone)", DEV,
         format!("[drive]\ntype = drive\ntoken = {{\"access_token\":\"ya29.{t}chouf\"}}\n")),
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

/// What chouf wrote at `rel` before the run, for the ordinary (non-bait) files: a file that no longer reads like
/// this was changed by the program.
pub fn planted(rel: &str) -> Option<&'static str> {
    PLAIN.iter().find(|(p, _)| *p == rel).map(|(_, body)| *body)
}

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
    for (rel, what, group, body) in baits(token) {
        write(rel, body.as_bytes(), 0o600)?;
        out.push(Canary {
            path: rel.to_string(),
            what,
            group,
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
        assert!(baits.len() >= 35);
        let mut paths: Vec<&str> = baits.iter().map(|c| c.path.as_str()).collect();
        paths.sort();
        paths.dedup();
        assert_eq!(paths.len(), baits.len(), "two baits at one path");
        for g in [PASSWORDS, WALLETS, DEV, CHAT, PRIVATE] {
            assert!(baits.iter().any(|c| c.group == g), "no bait in {g}");
        }
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
