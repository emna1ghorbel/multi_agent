"""
CTI DASHBOARD — Reads from FULL pipeline data, not just mapped TTPs.

Key fixes vs prior version:
  - Tactics/Kill Chain pulled from BEHAVIORS (real attack flow), not just
    mapped MITRE techniques (which may be incomplete).
  - IOCs categorized by type with stacked bar chart (IPs, URLs, Domains,
    Hashes, CVEs, Malware, Tools).
  - Severity uses behavior severities, falling back to TTP severities.
"""

import io
import os
import base64
from collections import Counter

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec

from langsmith import traceable


PALETTE = {
    "bg": "#ffffff", "panel": "#f5f7fb", "border": "#d0d7de",
    "text": "#1f2328", "subtext": "#57606a",
    "Critical": "#d1242f", "High": "#d97706", "Medium": "#f59e0b",
    "Low": "#2da44e", "Unknown": "#6e7781",
    "accent": "#0969da", "accent2": "#1f6feb", "accent3": "#54aeff",
}


KILL_CHAIN_ORDER = [
    "initial_access", "execution", "persistence", "privilege_escalation",
    "defense_evasion", "credential_access", "discovery", "lateral_movement",
    "collection", "exfiltration", "command_and_control", "impact",
]
KILL_CHAIN_LABELS = [
    "Init.Access", "Execution", "Persistence", "Priv.Esc.", "Def.Evasion",
    "Cred.Access", "Discovery", "Lat.Movement", "Collection",
    "Exfiltration", "C2", "Impact",
]


# Mirror of aggregator/threat_brief category aliases
_CAT_TO_TACTIC = {
    "process_creation":       "execution",
    "process_manipulation":   "execution",
    "registry_modification":  "persistence",
    "persistence_mechanisms": "persistence",
    "network_communication":  "command_and_control",
    "network_activity":       "command_and_control",
    "file_system_activity":   "impact",
    "file_system_operations": "impact",
    "credential_access":      "credential_access",
    "credential_theft":       "credential_access",
    "defense_evasion":        "defense_evasion",
    "discovery":              "discovery",
    "lateral_movement":       "lateral_movement",
    "collection":             "collection",
    "exfiltration":           "exfiltration",
    "initial_access":         "initial_access",
    "privilege_escalation":   "privilege_escalation",
    "impact":                 "impact",
    # Phishing/macro hints from descriptions
    "phishing":               "initial_access",
    "macro":                  "execution",
}


def _norm(x):
    s = str(x or "").strip()
    if not s:
        return "Unknown"
    s = s.replace("_", " ").replace("-", " ")
    return " ".join(w[:1].upper() + w[1:].lower() for w in s.split())


def _sev_name(x):
    n = _norm(x)
    for valid in ("Critical", "High", "Medium", "Low", "Unknown"):
        if n.lower() == valid.lower():
            return valid
    return "Unknown"


def _as_int(v):
    try:
        return int(v)
    except Exception:
        return 0


def _category_to_tactic(category: str, description: str = "") -> str:
    """Map behavior category to ATT&CK tactic (kill chain stage)."""
    cat = (category or "").lower().strip().replace(" ", "_")
    if cat in _CAT_TO_TACTIC:
        return _CAT_TO_TACTIC[cat]

    # Description-based fallback
    desc = (description or "").lower()
    if any(k in desc for k in ("phishing", "spear", "lure", "email attachment")):
        return "initial_access"
    if any(k in desc for k in ("macro", "execute", "powershell", "script")):
        return "execution"
    if any(k in desc for k in ("registry", "scheduled task", "autorun", "persistence")):
        return "persistence"
    if any(k in desc for k in ("c2", "command and control", "outbound", "beacon")):
        return "command_and_control"
    if any(k in desc for k in ("encrypt", "ransom", "destroy", "wipe")):
        return "impact"
    return "unknown"


# ---------------------------------------------------------------------------
#  DATA EXTRACTION — uses behaviors AND mapped TTPs together
# ---------------------------------------------------------------------------

def _collect_behaviors(report):
    """
    Pull behaviors from all available sources in the report.
    Aggregator sometimes embeds these in different paths.
    """
    behaviors = []

    # Try threat_brief.mitre_input.behaviors
    tb = report.get("threat_brief", {})
    if isinstance(tb, dict):
        behaviors.extend(tb.get("mitre_input", {}).get("behaviors", []))

    # Try top-level behaviors (passed by orchestrator)
    behaviors.extend(report.get("behaviors", []) or [])

    # If aggregator stored them in section_4 procedures, extract
    for ttp in report.get("section_4_ttps", []) or []:
        ob = ttp.get("observed_behavior", {})
        if ob and ob.get("category"):
            behaviors.append({
                "category":    ob.get("category", ""),
                "description": ob.get("description", ""),
                "severity":    ttp.get("severity_level", "Unknown"),
            })

    return behaviors


def _tactics_from_all(report):
    """Tactics counter built from BOTH behaviors AND mapped techniques."""
    counter = Counter()

    # 1) From mapped techniques
    for ttp in report.get("section_4_ttps", []) or []:
        if t := ttp.get("tactic"):
            counter[_norm(t)] += 1

    # 2) From behaviors (catches stages that didn't map to ATT&CK)
    for b in _collect_behaviors(report):
        tactic = _category_to_tactic(b.get("category", ""), b.get("description", ""))
        if tactic and tactic != "unknown":
            counter[_norm(tactic)] += 1

    # 3) From kill_chain_stages list (last-resort backstop)
    if not counter:
        for s in (
            report.get("executive_summary", {}).get("kill_chain_stages")
            or report.get("section_2_key_takeaways", {}).get("kill_chain_stages")
            or []
        ):
            counter[_norm(s)] += 1

    return {k: v for k, v in counter.items() if v > 0}


def _killchain_from_all(report):
    """Kill chain coverage from BOTH behaviors AND mapped techniques."""
    active = set()

    for ttp in report.get("section_4_ttps", []) or []:
        if t := ttp.get("tactic"):
            active.add(_norm(t).lower().replace(" ", "_"))

    for b in _collect_behaviors(report):
        tactic = _category_to_tactic(b.get("category", ""), b.get("description", ""))
        if tactic and tactic != "unknown":
            active.add(tactic)

    for s in (
        report.get("executive_summary", {}).get("kill_chain_stages")
        or report.get("section_2_key_takeaways", {}).get("kill_chain_stages")
        or []
    ):
        active.add(str(s).lower().replace(" ", "_").replace("-", "_"))

    return active


def _techniques(report):
    counter = Counter()
    for ttp in report.get("section_4_ttps", []) or []:
        tid = ttp.get("technique_id", "")
        name = ttp.get("technique_name", "")
        label = f"{tid} {name}".strip() or "Unknown"
        counter[label] += 1
    return {k: v for k, v in counter.items() if v > 0}


def _severity(report):
    """Severity from BOTH mapped TTPs AND behaviors."""
    counter = Counter()

    # Mapped TTPs first
    dist = report.get("section_3_severity", {}).get("distribution", {})
    if dist:
        for k, v in dist.items():
            counter[_sev_name(k)] += _as_int(v)

    # Add behavior severities (so phishing/macro show up too)
    for b in _collect_behaviors(report):
        sev = b.get("severity", "Unknown")
        # Behaviors may use lowercase
        counter[_sev_name(sev)] += 1

    return {k: v for k, v in counter.items() if v > 0}


def _iocs_categorized(report):
    """Return ordered dict of IOC type -> count, no inflation."""
    s5 = report.get("section_5_iocs_artifacts", {})
    network = s5.get("network", {})
    files = s5.get("files", {})
    crypto = s5.get("crypto", {})
    ti = s5.get("threat_intelligence", {})

    counts = {
        "IPs":        len(network.get("ips", [])),
        "URLs":       len(network.get("urls", [])),
        "Domains":    len(network.get("domains", [])),
        "Hashes":     (len(files.get("md5", [])) +
                       len(files.get("sha1", [])) +
                       len(files.get("sha256", []))),
        "CVEs":       len(ti.get("cves", [])),
        "Malware":    len(ti.get("malware_names", [])) +
                      len(ti.get("ransomware_groups", [])),
        "Tools":      len(ti.get("tools_abused", [])),
        "APT Groups": len(ti.get("apt_groups", [])),
        "Crypto":     (len(crypto.get("btc", [])) +
                       len(crypto.get("eth", [])) +
                       len(crypto.get("xmr", []))),
    }

    # Drop zero-count categories
    return {k: v for k, v in counts.items() if v > 0}


def _summary(report):
    e = report.get("executive_summary", {})
    s2 = report.get("section_2_key_takeaways", {})

    actor = (
        e.get("threat_actor")
        or s2.get("threat_actor", {}).get("name")
        or "Unknown"
    )

    techniques_count = e.get("total_techniques") or len(report.get("section_4_ttps", []))
    behaviors_count = len(_collect_behaviors(report))
    iocs = _iocs_categorized(report)
    total_iocs = sum(iocs.values())

    return {
        "techniques": techniques_count,
        "behaviors":  behaviors_count,
        "iocs":       total_iocs,
        "actor":      actor,
        "class":      e.get("threat_classification", "N/A"),
    }


# ---------------------------------------------------------------------------
#  RENDERERS
# ---------------------------------------------------------------------------

def _no_data(ax, message, p):
    ax.set_facecolor(p["panel"])
    ax.text(0.5, 0.5, message, ha="center", va="center",
            color=p["subtext"], fontsize=11)
    ax.set_xticks([])
    ax.set_yticks([])


def render_tactics(ax, data, p):
    ax.set_facecolor(p["panel"])
    if not data:
        _no_data(ax, "No tactic data", p)
        return

    items = sorted(data.items(), key=lambda x: x[1])
    labels = [i[0] for i in items]
    values = [i[1] for i in items]

    bars = ax.barh(labels, values, color=p["accent"], edgecolor="white", linewidth=0.8)
    for bar, v in zip(bars, values):
        ax.text(bar.get_width() + 0.05, bar.get_y() + bar.get_height() / 2,
                str(v), va="center", fontsize=9, color=p["text"])

    ax.set_title("ATT&CK Tactics Observed", color=p["text"], fontweight="bold")
    ax.tick_params(colors=p["text"], labelsize=9)
    ax.grid(axis="x", alpha=0.2)
    ax.set_xlim(0, max(values) * 1.15)


def render_severity(ax, data, p):
    ax.set_facecolor(p["panel"])
    order = ["Critical", "High", "Medium", "Low", "Unknown"]
    labels = [k for k in order if data.get(k, 0) > 0]
    sizes = [data[k] for k in labels]

    if not sizes or sum(sizes) <= 0:
        _no_data(ax, "No severity data", p)
        return

    colors = [p.get(k, p["Unknown"]) for k in labels]
    wedges, texts, autotexts = ax.pie(
        sizes, labels=labels, colors=colors,
        autopct=lambda pct: f"{pct:.0f}%\n({int(pct*sum(sizes)/100)})",
        wedgeprops={"edgecolor": "#ffffff", "linewidth": 2},
        textprops={"color": p["text"], "fontsize": 9},
        startangle=90,
    )
    for at in autotexts:
        at.set_color("white")
        at.set_fontweight("bold")
        at.set_fontsize(8)

    ax.set_title("Severity Distribution", color=p["text"], fontweight="bold")


def render_killchain(ax, active_stages, p):
    ax.set_facecolor(p["panel"])

    vals = [1 if stage in active_stages else 0 for stage in KILL_CHAIN_ORDER]
    colors = [p["accent"] if v > 0 else p["border"] for v in vals]

    bars = ax.bar(range(len(vals)), vals, color=colors, edgecolor="white", linewidth=1)

    # Annotate active stages
    for i, (bar, v) in enumerate(zip(bars, vals)):
        if v > 0:
            ax.text(bar.get_x() + bar.get_width() / 2, 1.05,
                    "✓", ha="center", va="bottom",
                    color=p["accent"], fontsize=12, fontweight="bold")

    ax.set_ylim(0, 1.3)
    ax.set_xticks(range(len(KILL_CHAIN_ORDER)))
    ax.set_xticklabels(KILL_CHAIN_LABELS, rotation=45, ha="right", fontsize=7.5)
    ax.set_yticks([])

    n_active = sum(vals)
    ax.set_title(f"Kill Chain Coverage ({n_active}/{len(KILL_CHAIN_ORDER)} stages)",
                 color=p["text"], fontweight="bold")
    ax.tick_params(colors=p["text"])
    ax.grid(axis="y", alpha=0.0)

    # Legend
    ax.text(0.0, -0.15, "■ Detected", color=p["accent"],
        fontsize=8, fontweight="bold", transform=ax.transAxes)
    ax.text(0.25, -0.15, "■ Not observed", color=p["border"],
            fontsize=8, transform=ax.transAxes)


def render_iocs(ax, ioc_data, p):
    """Categorized IOC bar chart — replaces vague 'top techniques'."""
    ax.set_facecolor(p["panel"])
    if not ioc_data:
        _no_data(ax, "No IOCs extracted", p)
        return

    items = sorted(ioc_data.items(), key=lambda x: x[1], reverse=True)
    labels = [i[0] for i in items]
    values = [i[1] for i in items]

    # Color-code by type category
    color_map = {
        "IPs": p["accent"], "URLs": p["accent2"], "Domains": p["accent3"],
        "Hashes": p["High"], "CVEs": p["Critical"], "Malware": p["Critical"],
        "Tools": p["Medium"], "APT Groups": p["Critical"], "Crypto": p["Medium"],
    }
    colors = [color_map.get(l, p["accent"]) for l in labels]

    bars = ax.barh(labels, values, color=colors, edgecolor="white", linewidth=0.8)
    for bar, v in zip(bars, values):
        ax.text(bar.get_width() + 0.05, bar.get_y() + bar.get_height() / 2,
                str(v), va="center", fontsize=9, color=p["text"], fontweight="bold")

    ax.invert_yaxis()
    total = sum(values)
    ax.set_title(f"IOCs by Category (total: {total})",
                 color=p["text"], fontweight="bold")
    ax.tick_params(colors=p["text"], labelsize=9)
    ax.grid(axis="x", alpha=0.2)
    ax.set_xlim(0, max(values) * 1.2)


# ---------------------------------------------------------------------------
#  MAIN ENTRY
# ---------------------------------------------------------------------------

@traceable(name="CTI Dashboard")
def generate_dashboard(report, output="dashboard.png"):
    p = PALETTE

    tactics = _tactics_from_all(report)
    severity = _severity(report)
    killchain_active = _killchain_from_all(report)
    iocs = _iocs_categorized(report)
    summary = _summary(report)

    os.makedirs(os.path.dirname(os.path.abspath(output)) or ".", exist_ok=True)

    fig = plt.figure(figsize=(14, 8), facecolor=p["bg"])
    gs = gridspec.GridSpec(2, 2, figure=fig)

    ax1 = fig.add_subplot(gs[0, 0])
    ax2 = fig.add_subplot(gs[0, 1])
    ax3 = fig.add_subplot(gs[1, 0])
    ax4 = fig.add_subplot(gs[1, 1])

    render_tactics(ax1, tactics, p)
    render_severity(ax2, severity, p)
    render_killchain(ax3, killchain_active, p)
    render_iocs(ax4, iocs, p)

    title = (
        f"CTI DASHBOARD  |  Actor: {summary['actor']}  |  "
        f"{summary['behaviors']} behaviors  |  "
        f"{summary['techniques']} techniques  |  "
        f"{summary['iocs']} IOCs"
    )
    fig.suptitle(title, color=p["text"], fontsize=14, fontweight="bold", y=0.98)

    fig.subplots_adjust(left=0.08, right=0.97, top=0.90, bottom=0.12, hspace=0.45, wspace=0.30)

    plt.savefig(output, dpi=100,facecolor=p["bg"])

    buf = io.BytesIO()
    plt.savefig(buf, format="png", dpi=100,facecolor=p["bg"])
    buf.seek(0)
    b64 = base64.b64encode(buf.read()).decode()
    plt.close(fig)

    return {
        "path": os.path.abspath(output),
        "base64": b64,
        "debug_counts": {
            "tactics": len(tactics),
            "severity": len(severity),
            "killchain_active": len(killchain_active),
            "iocs_categories": len(iocs),
            "behaviors": summary["behaviors"],
            "techniques": summary["techniques"],
        },
    }