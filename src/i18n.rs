//! The report in the reader's language: English or French. `report.json` stays in English (it is read by programs);
//! the terminal report and report.html follow `--lang`, else CHOUF_LANG, else the system's LANG.
//! Strings are looked up by their English text: a missing translation shows the English, never nothing.

use std::sync::OnceLock;

static FRENCH: OnceLock<bool> = OnceLock::new();

/// Sets the language once, at startup. `flag`: the --lang value, if given.
pub fn init(flag: Option<&str>) {
    let pick = |v: &str| v.to_lowercase().starts_with("fr");
    let fr = match flag {
        Some(f) => pick(f),
        None => ["CHOUF_LANG", "LC_ALL", "LC_MESSAGES", "LANG"]
            .iter()
            .find_map(|k| std::env::var(k).ok().filter(|v| !v.is_empty()))
            .is_some_and(|v| pick(&v)),
    };
    let _ = FRENCH.set(fr);
}

pub fn french() -> bool {
    *FRENCH.get().unwrap_or(&false)
}

const FR: &[(&str, &str)] = &[
    // section titles
    ("Secrets it went after", "Les secrets qu'il a fouillés"),
    ("Ways it will run again by itself", "Ce qu'il a prévu pour revenir tout seul"),
    ("What it now trusts", "Ce que la machine accepte désormais"),
    ("Everything else it changed", "Tout le reste de ce qu'il a changé"),
    ("In short", "En bref"),
    ("How chouf explored it", "Comment chouf l'a testé"),
    ("What it set up, set off once by chouf", "Ce qu'il a préparé, déclenché une fois par chouf"),
    ("What chouf refused on your local network", "Ce que chouf a bloqué sur ton réseau local"),
    ("What left the machine (bait data seen in what it sent)", "Ce qui est sorti de la machine (faux secrets vus dans ses envois)"),
    ("What left the machine", "Ce qui est sorti de la machine"),
    ("Where it connected", "Où il s'est connecté"),
    ("Programs it ran", "Les programmes qu'il a lancés"),
    ("What it says vs what it does", "Ce qu'il dit, ce qu'il fait"),
    // in short
    ("Nothing alarming: no secret touched, nothing set to run again, nothing new trusted.",
     "Rien d'alarmant : aucun secret touché, rien de prévu pour revenir, rien de nouveau accepté."),
    ("PROOF: a secret left the machine, sent to {}: {}.", "PREUVE : un secret est sorti de la machine, envoyé à {} : {}."),
    ("your {}", "{}"),
    ("one of your secrets", "un de tes secrets"),
    ("{} bytes", "{} octets"),
    ("{} KB", "{} Ko"),
    ("{} MB", "{} Mo"),
    ("It went through your {}: {} bait files.", "Il a fouillé tes {} : {} faux secrets."),
    ("It went through your {}: {} bait file.", "Il a fouillé tes {} : {} faux secret."),
    ("It set itself up to run again on its own ({} ways).", "Il s'est installé pour revenir tout seul ({} façons)."),
    ("It set itself up to run again on its own ({} way).", "Il s'est installé pour revenir tout seul ({} façon)."),
    ("It changed what the machine trusts (software sources, certificates, admin rights or accounts).",
     "Il a changé ce que la machine accepte (sources de logiciels, certificats, droits d'administrateur ou comptes)."),
    ("It read some of its own settings ({}): normal, nothing else touched them.",
     "Il a lu certains de ses propres réglages ({}) : normal, rien d'autre n'y a touché."),
    ("It read one of its own settings ({}): normal, nothing else touched it.",
     "Il a lu un de ses propres réglages ({}) : normal, rien d'autre n'y a touché."),
    ("It was stopped at the time limit: what it would have done next was not seen.",
     "Il a été arrêté à la limite de temps : la suite de ce qu'il aurait fait n'a pas été vue."),
    ("It stopped on an error (exit {}): what it would have done next was not seen.",
     "Il s'est arrêté sur une erreur (exit {}) : la suite de ce qu'il aurait fait n'a pas été vue."),
    ("Its last message: {}", "Son dernier message : {}"),
    ("It added a software source: {}. What comes from there will be installed like the system's own updates.",
     "Il a ajouté une source de logiciels : {}. Ce qui vient de là s'installera comme les mises à jour du système."),
    ("Packages it installed will start with the machine: {} (normal for this kind of software).",
     "Des paquets qu'il a installés démarreront avec la machine : {} (normal pour ce genre de logiciel)."),
    ("It adds {} to your PATH (in {}): normal for an installer of commands.",
     "Il ajoute {} à ton PATH (dans {}) : normal pour un installeur de commandes."),
    ("take out the lines it added to {} (shown below)", "retire les lignes qu'il a ajoutées à {} (montrées plus bas)"),
    ("package {}", "paquet {}"),
    ("(+{} of its own programs)", "(+{} de ses propres programmes)"),
    ("adds to PATH: {}", "ajoute au PATH : {}"),
    ("puts its own commands first in PATH, in place of: {}", "met ses propres commandes en tête du PATH, à la place de : {}"),
    ("It installed software with the system's package manager (normal for an installer).",
     "Il a installé des logiciels avec le gestionnaire de paquets du système (normal pour un installeur)."),
    ("It tried to reach your local network {} times (router, other machines): chouf refused. {}",
     "Il a essayé de joindre ton réseau local {} fois (box, autres machines) : chouf a refusé. {}"),
    ("It tried to reach your local network {} time (router, other machines): chouf refused. {}",
     "Il a essayé de joindre ton réseau local {} fois (box, autres machines) : chouf a refusé. {}"),
    ("After reading your secrets it sent {}.", "Après avoir lu tes secrets, il a envoyé {}."),
    ("{} to {}", "{} à {}"),
    ("It contacted nothing on the network.", "Il n'a rien contacté sur le réseau."),
    ("It contacted {} places on the network: {}.", "Il a contacté {} endroits sur le réseau : {}."),
    ("It contacted {} place on the network: {}.", "Il a contacté {} endroit sur le réseau : {}."),
    ("If you already ran it on your own machine:", "Si tu l'as déjà lancé sur ta vraie machine :"),
    ("remove what it set up to come back: {}", "supprime ce qu'il a installé pour revenir : {}"),
    // advice
    ("change the passwords saved in your browsers and password manager, and log out of every site",
     "change les mots de passe enregistrés dans tes navigateurs et ton gestionnaire de mots de passe, et déconnecte-toi de tous les sites"),
    ("move your crypto to a new wallet: the old one's seed and keys must be considered stolen",
     "déplace tes cryptos vers un nouveau portefeuille : la phrase secrète et les clés de l'ancien sont à considérer comme volées"),
    ("revoke those tokens and keys, then create new ones (cloud, GitHub, npm, PyPI, databases)",
     "révoque ces jetons et ces clés, puis crées-en de nouveaux (cloud, GitHub, npm, PyPI, bases de données)"),
    ("log out of every session in those apps (Telegram, Discord, Slack) from another device",
     "déconnecte toutes les sessions de ces applis (Telegram, Discord, Slack) depuis un autre appareil"),
    ("replace your SSH and GPG keys, and remove the old public keys wherever they are trusted",
     "remplace tes clés SSH et GPG, et retire les anciennes clés publiques partout où elles sont acceptées"),
    // families of baits
    ("passwords and browser logins", "mots de passe et connexions du navigateur"),
    ("crypto wallets", "portefeuilles crypto"),
    ("developer and cloud keys", "clés de développeur et de cloud"),
    ("messaging accounts", "comptes de messagerie"),
    ("private keys and history", "clés privées et historique"),
    // detail lines
    ("Nothing: no bait touched, no file changed.", "Rien : aucun faux secret touché, aucun fichier modifié."),
    ("by", "par"),
    ("and {} more", "et {} autres"),
    ("and {} more (report.html has them all)", "et {} autres (report.html les a tous)"),
    ("and {} more (report.json has them all)", "et {} autres (report.json les a tous)"),
    ("{} files in {}", "{} fichiers dans {}"),
    ("sent {}, received {}", "envoyé {}, reçu {}"),
    ("Warning: some file events were lost, this list may be incomplete.",
     "Attention : des événements de fichiers ont été perdus, cette liste est peut-être incomplète."),
    ("Warning: the kernel tracer lost events, the lists above may be incomplete.",
     "Attention : le traceur noyau a perdu des événements, les listes ci-dessus sont peut-être incomplètes."),
    ("({} temporary files or folders created and removed in ~)", "({} fichiers ou dossiers temporaires créés puis effacés dans ~)"),
    ("(opinion of {}, not a measurement)", "(avis de {}, pas une mesure)"),
    ("consistent: it does what it says", "cohérent : il fait ce qu'il dit"),
    ("SUSPICIOUS: it does things it does not explain", "SUSPECT : il fait des choses qu'il n'explique pas"),
    ("MALICIOUS: it steals, hides or contradicts itself", "MALVEILLANT : il vole, se cache ou se contredit"),
    ("says:", "dit :"),
    ("does:", "fait :"),
    // the baits
    ("SSH private key", "clé privée SSH"),
    ("AWS access keys", "clés d'accès AWS"),
    ("GitHub CLI token", "jeton GitHub CLI"),
    ("Git passwords", "mots de passe Git"),
    ("npm publish token", "jeton de publication npm"),
    ("Docker registry login", "identifiants du registre Docker"),
    ("Kubernetes cluster token", "jeton du cluster Kubernetes"),
    ("Chrome cookies", "cookies Chrome"),
    ("Chrome saved passwords", "mots de passe enregistrés dans Chrome"),
    ("Firefox cookies", "cookies Firefox"),
    ("Firefox saved passwords", "mots de passe enregistrés dans Firefox"),
    ("Bitcoin wallet", "portefeuille Bitcoin"),
    ("GPG private key", "clé privée GPG"),
    ("Shell history", "historique du terminal"),
    ("App secrets (.env)", "secrets d'application (.env)"),
    ("SSH private key (RSA)", "clé privée SSH (RSA)"),
    ("Brave saved passwords", "mots de passe enregistrés dans Brave"),
    ("Brave cookies", "cookies Brave"),
    ("Chromium cookies", "cookies Chromium"),
    ("Edge saved passwords", "mots de passe enregistrés dans Edge"),
    ("KeePass password database", "base de mots de passe KeePass"),
    ("Bitwarden vault", "coffre Bitwarden"),
    ("MetaMask wallet (browser extension)", "portefeuille MetaMask (extension du navigateur)"),
    ("Exodus wallet seed", "phrase secrète du portefeuille Exodus"),
    ("Ethereum wallet key", "clé de portefeuille Ethereum"),
    ("Solana wallet key", "clé de portefeuille Solana"),
    ("Telegram session", "session Telegram"),
    ("Discord login token", "jeton de connexion Discord"),
    ("Slack session cookies", "cookies de session Slack"),
    ("Google Cloud credentials", "identifiants Google Cloud"),
    ("Azure login tokens", "jetons de connexion Azure"),
    ("Saved server passwords (.netrc)", "mots de passe de serveurs (.netrc)"),
    ("PyPI upload token", "jeton d'envoi PyPI"),
    ("crates.io publish token", "jeton de publication crates.io"),
    ("HashiCorp Vault token", "jeton HashiCorp Vault"),
    ("Terraform Cloud token", "jeton Terraform Cloud"),
    ("PostgreSQL passwords", "mots de passe PostgreSQL"),
    ("Cloud storage logins (rclone)", "identifiants de stockage cloud (rclone)"),
    // what it did
    ("opened", "ouvert"),
    ("read", "lu"),
    ("wrote", "écrit"),
    ("created", "créé"),
    ("deleted", "effacé"),
    ("moved", "déplacé"),
    ("listed", "listé"),
    ("added", "ajouté"),
    ("changed", "modifié"),
    // why it matters
    ("runs in every new terminal", "se lance dans chaque nouveau terminal"),
    ("runs at every login", "se lance à chaque connexion"),
    ("starts with the desktop session", "démarre avec le bureau"),
    ("user service", "service utilisateur"),
    ("lets someone log in to this machine", "permet à quelqu'un de se connecter à cette machine"),
    ("runs at every SSH login", "se lance à chaque connexion SSH"),
    ("scheduled task", "tâche planifiée"),
    ("system service", "service système"),
    ("boot script", "script de démarrage"),
    ("runs in every terminal", "se lance dans chaque terminal"),
    ("starts with every desktop session", "démarre avec chaque session de bureau"),
    ("loaded into every program", "chargé dans chaque programme"),
    ("runs when a device is plugged in", "se lance quand on branche un appareil"),
    ("adds a software source", "ajoute une source de logiciels"),
    ("trusts a new signing key", "accepte une nouvelle clé de signature"),
    ("trusts a new root certificate", "accepte un nouveau certificat racine"),
    ("changes who can be admin", "change qui peut être administrateur"),
    ("changes the user accounts", "change les comptes utilisateurs"),
    ("changes the passwords", "change les mots de passe"),
    ("redirects web addresses", "redirige des adresses web"),
    ("standard root certificates (ca-certificates package)", "certificats racine standards (paquet ca-certificates)"),
    ("looked inside the folder of: {}", "a regardé dans le dossier de : {}"),
    ("{}, read by its own tool: {}", "{}, lu par son propre outil : {}"),
];

/// The text in the report's language (English when there is no translation).
pub fn t(en: &str) -> String {
    if french() {
        if let Some((_, fr)) = FR.iter().find(|(e, _)| *e == en) {
            return fr.to_string();
        }
    }
    en.to_string()
}

/// A template with `{}` holes, translated, then filled in order.
pub fn tf(en: &str, args: &[&str]) -> String {
    let mut out = t(en);
    for a in args {
        if let Some(i) = out.find("{}") {
            out.replace_range(i..i + 2, a);
        }
    }
    out
}

/// A "why" from the report, which can be composite ("X, read by its own tool: npm").
pub fn why(w: &str) -> String {
    if let Some(rest) = w.strip_prefix("looked inside the folder of: ") {
        return tf("looked inside the folder of: {}", &[&t(rest)]);
    }
    for prefix in [crate::report::PATH_ONLY, crate::report::TAKES_OVER] {
        if let Some(rest) = w.strip_prefix(prefix) {
            return tf(&format!("{prefix}{{}}"), &[rest]);
        }
    }
    if let Some((what, tools)) = w.split_once(", read by its own tool: ") {
        return tf("{}, read by its own tool: {}", &[&t(what), tools]);
    }
    t(w)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn templates_fill_in_order_and_unknown_text_stays_english() {
        // the language is process-wide: these checks hold in either language
        let s = tf("PROOF: {} left the machine, sent to {}.", &["X", "evil.example"]);
        assert!(s.contains('X') && s.ends_with("evil.example."), "{s}");
        assert_eq!(t("no such sentence"), "no such sentence");
        assert!(FR.iter().all(|(e, f)| e.matches("{}").count() == f.matches("{}").count()), "holes must match");
    }
}
