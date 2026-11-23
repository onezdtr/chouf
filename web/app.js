// chouf online: send a check, follow it in the queue, open its report.
const FR = {
  "sub": "Vois ce qu'un installeur fait vraiment avant de le lancer : il tourne ici, dans un bac à sable rempli de faux secrets.",
  "tab-script": "Script d'installation",
  "label-script": "Adresse du script (celle que tu donnerais à sh)",
  "label-npm": "Paquet npm (nom, ou nom@version)",
  "label-pip": "Paquet pip (nom, ou nom==version)",
  "label-code": "Code d'invitation",
  "label-args": "Arguments du script (facultatif, comme le -y de « sh -s -- -y »)",
  "go": "Vérifier",
  "how1": "Il tourne en root dans un conteneur jetable dont le home contient 38 fausses clés, jetons et portefeuilles.",
  "how2": "Un traceur noyau note ce qu'il ouvre, lance et envoie ; ton rapport le dit simplement.",
  "how3": "Une vérification à la fois, quelques minutes chacune. Les rapports sont gardés 30 jours.",
  "local": "ou lance-le sur ta propre machine Linux",
  "waiting": "En attente : {} avant toi…",
  "running": "En cours dans le bac à sable (1 à 4 minutes)…",
  "sending": "Envoi…",
  "failed": "Échec : {}",
  "network": "Le serveur ne répond pas. Réessaie dans un moment.",
};
const EN = {
  "label-script": "Script address (the URL you would pipe to sh)",
  "label-npm": "npm package (name, or name@version)",
  "label-pip": "pip package (name, or name==version)",
  "waiting": "Waiting: {} ahead of you…",
  "running": "Running in the sandbox (1 to 4 minutes)…",
  "sending": "Sending…",
  "failed": "Failed: {}",
  "network": "The server does not answer. Try again in a moment.",
};
const fr = (navigator.language || "").toLowerCase().startsWith("fr");
const t = (k, v) => ((fr && FR[k]) || EN[k] || k).replace("{}", v ?? "");
const PLACEHOLDER = { script: "https://sh.rustup.rs", npm: "left-pad", pip: "requests" };

if (fr) {
  document.documentElement.lang = "fr";
  document.querySelectorAll("[data-t]").forEach((el) => { if (FR[el.dataset.t]) el.textContent = FR[el.dataset.t]; });
}

const $ = (id) => document.getElementById(id);
let kind = "script";
const store = {
  get: (k) => { try { return localStorage.getItem(k) || ""; } catch { return ""; } },
  set: (k, v) => { try { localStorage.setItem(k, v); } catch { /* private window: the code is just not remembered */ } },
};
$("code").value = store.get("chouf-code");

document.querySelectorAll(".tabs button").forEach((b) => b.addEventListener("click", () => {
  document.querySelectorAll(".tabs button").forEach((x) => x.setAttribute("aria-selected", String(x === b)));
  kind = b.dataset.kind;
  $("target-label").textContent = t("label-" + kind);
  $("target").placeholder = PLACEHOLDER[kind];
  $("target").value = "";
  $("args-box").hidden = kind !== "script";
  $("target").focus();
}));

function status(text, bad) {
  $("status").textContent = text;
  $("status").className = bad ? "bad" : "";
}

async function follow(job) {
  for (;;) {
    await new Promise((r) => setTimeout(r, 2000));
    let j;
    try { j = await (await fetch("api/job/" + job)).json(); } catch { continue; }
    if (j.state === "waiting") status(t("waiting", j.position - 1));
    else if (j.state === "running") status(t("running"));
    else if (j.state === "done") { location.href = "r/" + job; return; }
    else { status(t("failed", j.error || "?"), true); $("go").disabled = false; return; }
  }
}

$("go").addEventListener("click", async () => {
  const target = $("target").value.trim();
  const code = $("code").value.trim();
  if (!target || !code) return;
  store.set("chouf-code", code);
  $("go").disabled = true;
  status(t("sending"));
  try {
    const r = await fetch("api/run", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ kind, target, code, args: kind === "script" ? $("args").value.trim() : "" }) });
    const j = await r.json();
    if (!r.ok) { status(j.error || "?", true); $("go").disabled = false; return; }
    follow(j.job);
  } catch {
    status(t("network"), true);
    $("go").disabled = false;
  }
});
