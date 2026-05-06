
import os

from reportlab.platypus import Image, PageBreak
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer,
    Table, TableStyle, KeepTogether, Flowable,
)

# ---------------------------------------------------------------------------
#  THEME
# ---------------------------------------------------------------------------

PRIMARY_DARK  = colors.HexColor("#0F172A")
PRIMARY_LIGHT = colors.HexColor("#F8FAFC")
ACCENT        = colors.HexColor("#0EA5E9")
TEXT_MAIN     = colors.HexColor("#334155")
TEXT_MUTED    = colors.HexColor("#64748B")
BORDER        = colors.HexColor("#E2E8F0")
WHITE         = colors.white

_SEV_COLORS = {
    "Critical": colors.HexColor("#DC2626"),
    "High":     colors.HexColor("#EA580C"),
    "Medium":   colors.HexColor("#EAB308"),
    "Low":      colors.HexColor("#16A34A"),
}

_KILL_CHAIN_ORDER = [
    "initial_access", "execution", "persistence", "privilege_escalation",
    "defense_evasion", "credential_access", "discovery", "lateral_movement",
    "collection", "exfiltration", "command_and_control", "impact",
]
_KILL_CHAIN_LABELS = [
    "Init.", "Exec.", "Persist.", "Priv.Esc.", "Def.Ev.",
    "Cred.", "Discov.", "Lat.Mv.", "Collect.", "Exfil.", "C2", "Impact",
]


def _sev_color(level: str):
    return _SEV_COLORS.get(level, TEXT_MUTED)


def _safe(val, maxlen: int = 0) -> str:
    """ReportLab ASCII encoding only. Aggregator is responsible for truncation."""
    subs = {
        "\u2014": "-", "\u2013": "-", "\u2018": "'", "\u2019": "'",
        "\u201c": '"', "\u201d": '"', "\u2026": "...", "\u00b7": "*",
    }
    text = str(val) if val is not None else ""
    result = "".join(subs.get(ch, ch) if ord(ch) < 256 else "?" for ch in text)
    return result[:maxlen - 1] + "..." if maxlen and len(result) > maxlen else result


# ---------------------------------------------------------------------------
#  STYLES
# ---------------------------------------------------------------------------

def _build_styles() -> dict:
    S = ParagraphStyle
    return {
        "subsection":   S("sub",    fontSize=10, textColor=PRIMARY_DARK, fontName="Helvetica-Bold",    leading=14, spaceBefore=8,  spaceAfter=4),
        "body":         S("body",   fontSize=9,  textColor=TEXT_MAIN,    fontName="Helvetica",         leading=14, spaceAfter=4,   alignment=TA_JUSTIFY),
        "kv_key":       S("kv_k",   fontSize=9,  textColor=TEXT_MUTED,   fontName="Helvetica-Bold",    leading=12),
        "kv_val":       S("kv_v",   fontSize=9,  textColor=TEXT_MAIN,    fontName="Helvetica",         leading=12),
        "mono":         S("mono",   fontSize=7.5,textColor=TEXT_MAIN,    fontName="Courier",           leading=10, spaceAfter=2),
        "bullet":       S("blt",    fontSize=9,  textColor=TEXT_MAIN,    fontName="Helvetica",         leading=13, leftIndent=12,  bulletIndent=4, spaceAfter=3),
        "table_hdr":    S("thdr",   fontSize=8,  textColor=WHITE,        fontName="Helvetica-Bold",    leading=10, alignment=TA_CENTER),
        "table_cell":   S("tcell",  fontSize=8,  textColor=TEXT_MAIN,    fontName="Helvetica",         leading=11, alignment=TA_LEFT),
        "table_cell_c": S("tcellc", fontSize=8,  textColor=TEXT_MAIN,    fontName="Helvetica",         leading=11, alignment=TA_CENTER),
        "procedure":    S("proc",   fontSize=8,  textColor=TEXT_MAIN,    fontName="Helvetica-Oblique", leading=11, leftIndent=4),
        "caption":      S("cap",    fontSize=7,  textColor=TEXT_MUTED,   fontName="Helvetica",         leading=9,  alignment=TA_CENTER, spaceAfter=4),
        "raw":          S("raw",    fontSize=7.5,textColor=TEXT_MUTED,   fontName="Courier",           leading=10, backColor=PRIMARY_LIGHT, leftIndent=6, rightIndent=6),
    }


def _table_style() -> TableStyle:
    return TableStyle([
        ("BACKGROUND",    (0, 0), (-1,  0), PRIMARY_DARK),
        ("TEXTCOLOR",     (0, 0), (-1,  0), WHITE),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [WHITE, PRIMARY_LIGHT]),
        ("LINEABOVE",     (0, 0), (-1,  0), 2, ACCENT),
        ("LINEBELOW",     (0, 0), (-1, -1), 0.5, BORDER),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ])


def _render_dashboard(report_data, st):
    dashboard_path = (
        report_data.get("dashboard_path")
        or report_data.get("dashboard", {}).get("path")
    )

    if not dashboard_path or not os.path.exists(dashboard_path):
        return []

    img = Image(dashboard_path)

    iw = img.imageWidth[0] if isinstance(img.imageWidth, list) else img.imageWidth
    ih = img.imageHeight[0] if isinstance(img.imageHeight, list) else img.imageHeight
    
    max_width  = 170 * mm
    max_height = 110 * mm
    aspect = ih / iw
    
    if aspect * max_width <= max_height:
        img.drawWidth  = max_width
        img.drawHeight = max_width * aspect
    else:
        img.drawHeight = max_height
        img.drawWidth  = max_height / aspect
    
    img.hAlign = "CENTER"

    return [
        PageBreak(),
        SectionHeader(6, "CTI Visual Dashboard"),
        Spacer(1, 5 * mm),
        img,
        Spacer(1, 3 * mm),
        Paragraph("Generated from CTI dashboard module.", st["caption"]),
    ]


# ---------------------------------------------------------------------------
#  CUSTOM FLOWABLES
# ---------------------------------------------------------------------------

class SectionHeader(Flowable):
    def __init__(self, number: int, title: str, width: float = 170 * mm):
        super().__init__()
        self.number, self.title = number, title
        self.width, self.height = width, 12 * mm

    def draw(self):
        self.canv.setFillColor(PRIMARY_DARK)
        self.canv.rect(0, 0, self.width, self.height, fill=1, stroke=0)
        self.canv.setFillColor(ACCENT)
        self.canv.rect(0, 0, 4 * mm, self.height, fill=1, stroke=0)
        self.canv.setFillColor(WHITE)
        self.canv.setFont("Helvetica-Bold", 11)
        self.canv.drawString(8 * mm, 4 * mm, f"{self.number}. {_safe(self.title).upper()}")


class SeverityBadge(Flowable):
    def __init__(self, level: str, score: float, width: float = 170 * mm):
        super().__init__()
        self.level, self.score = level, score
        self.width, self.height = width, 14 * mm

    def draw(self):
        c = _sev_color(self.level)
        self.canv.setFillColor(c)
        self.canv.roundRect(0, 0, self.width, self.height, 2, fill=1, stroke=0)
        self.canv.setFillColor(WHITE)
        self.canv.roundRect(self.width - 35 * mm, 2 * mm, 33 * mm, 10 * mm, 2, fill=1, stroke=0)
        self.canv.setFillColor(WHITE)
        self.canv.setFont("Helvetica-Bold", 12)
        self.canv.drawString(6 * mm, 4.5 * mm, f"GLOBAL SEVERITY: {self.level.upper()}")
        self.canv.setFillColor(c)
        self.canv.drawCentredString(self.width - 18.5 * mm, 4.5 * mm, f"{self.score:.1f} / 5.0")


class KillChainBar(Flowable):
    """Renders aggregator-provided active stage names. No normalization here."""
    def __init__(self, active_stages: list, width: float = 170 * mm):
        super().__init__()
        self.active = set(active_stages)   # already normalized by aggregator
        self.width, self.height = width, 16 * mm

    def draw(self):
        w_box = self.width / len(_KILL_CHAIN_ORDER)
        for i, (stage, label) in enumerate(zip(_KILL_CHAIN_ORDER, _KILL_CHAIN_LABELS)):
            active = stage in self.active
            self.canv.setFillColor(ACCENT if active else PRIMARY_LIGHT)
            self.canv.setStrokeColor(WHITE if active else BORDER)
            self.canv.rect(i * w_box, 6 * mm, w_box, 8 * mm, fill=1, stroke=1)
            self.canv.setFillColor(WHITE if active else TEXT_MUTED)
            self.canv.setFont("Helvetica-Bold" if active else "Helvetica", 5.5)
            self.canv.drawCentredString((i * w_box) + (w_box / 2), 8 * mm, label)
        self.canv.setFont("Helvetica", 7)
        self.canv.setFillColor(TEXT_MUTED)
        self.canv.drawString(0, 2 * mm, "Reconnaissance")
        self.canv.drawRightString(self.width, 2 * mm, "Actions on Objectives")


# ---------------------------------------------------------------------------
#  SECTION RENDERERS
# ---------------------------------------------------------------------------
def _render_section_1(data: dict, st: dict) -> list:
    """Raw input — verbatim passthrough, no modification."""
    return [SectionHeader(1, "Raw Input"), Spacer(1, 7 * mm),
            Paragraph(_safe(data.get("raw_input", "No raw input provided."), 2000), st["raw"])]
    
def _render_section_2(data: dict, st: dict) -> list:
    """Executive Summary — reads pre-shaped fields, emits flowables only."""
    s1    = data.get("section_1_summary_context", {})
    s2    = data.get("section_2_key_takeaways", {})
    s3    = data.get("section_3_severity", {})
    ex    = data.get("executive_summary", {})
    actor = s2.get("threat_actor", {})
    env   = s2.get("target_environment", {})

    items = [SectionHeader(2, "Executive Summary"), Spacer(1, 4 * mm),
             Paragraph("Incident Overview", st["subsection"]),
             Paragraph(_safe(s1.get("attack_narrative") or "No narrative available."), st["body"]),
             Paragraph("Key Takeaways", st["subsection"])]

    kv_rows = [
        [Paragraph("Threat Actor",   st["kv_key"]), Paragraph(f"{_safe(actor.get('name', 'Unidentified'))} (Conf: {actor.get('confidence', 0.0):.0%})", st["kv_val"])],
        [Paragraph("Initial Access", st["kv_key"]), Paragraph(_safe(s2.get("initial_access_vector", "Unknown")), st["kv_val"])],
        [Paragraph("Impact",         st["kv_key"]), Paragraph(_safe(s2.get("impact", "Unknown")), st["kv_val"])],
        [Paragraph("OS / Sector",    st["kv_key"]), Paragraph(f"{_safe(env.get('os', 'Unknown').title())} / {_safe(', '.join(env.get('sector', [])) or 'Unknown')}", st["kv_val"])],
        [Paragraph("Classification", st["kv_key"]), Paragraph(_safe(s1.get("threat_classification", "Unknown")), st["kv_val"])],
    ]
    kv = Table(kv_rows, colWidths=[48 * mm, 122 * mm])
    kv.setStyle(_table_style())
    items += [KeepTogether([kv]), Spacer(1, 4 * mm),
              Paragraph("Threat Severity", st["subsection"]),
              SeverityBadge(s3.get("global_level", "Unknown"), s3.get("global_score", 0.0)),
              Spacer(1, 4 * mm),
              Paragraph("Kill Chain Coverage", st["subsection"]),
              KillChainBar(ex.get("kill_chain_stages", []))]
    return items


def _render_section_3(data: dict, st: dict) -> list:
    """TTPs — aggregator pre-sorted by kill chain; procedure_text pre-built."""
    ttps  = data.get("section_4_ttps", [])
    items = [SectionHeader(3, "Tactics, Techniques & Procedures"), Spacer(1, 3 * mm)]

    if not ttps:
        return items + [Paragraph("No TTPs mapped for this threat.", st["body"])]

    rows = [[Paragraph(h, st["table_hdr"]) for h in ("Tactic", "Technique", "Sev.", "Procedure")]]
    prev_tactic = None
    for ttp in ttps:
        tactic  = _safe(ttp.get("tactic", "Unknown"))
        level   = ttp.get("severity_level", "Unknown")
        # FIX 1: hexval() returns "0xRRGGBB" — [2:] strips "0x", giving valid 6-char hex.
        # Original [1:] stripped only "0", leaving "xRRGGBB" which is an invalid color.
        hex_col = _sev_color(level).hexval()[2:]
        rows.append([
            Paragraph(tactic if tactic != prev_tactic else "", st["table_cell"]),
            Paragraph(f"<b>{_safe(ttp.get('technique_name', ''), 40)}</b><br/><font color='#0EA5E9'>{_safe(ttp.get('technique_id', ''))}</font>", st["table_cell"]),
            Paragraph(f"<font color='#{hex_col}'><b>{level[:4]}</b></font>", st["table_cell_c"]),
            Paragraph(_safe(ttp.get("procedure_text", "Behavior observed."), 300), st["procedure"]),
        ])
        prev_tactic = tactic

    tbl = Table(rows, colWidths=[30 * mm, 42 * mm, 14 * mm, 84 * mm], repeatRows=1)
    tbl.setStyle(_table_style())
    return items + [tbl, Spacer(1, 3 * mm),
                    Paragraph("Procedures extracted from source context.", st["caption"])]


def _render_section_4(data: dict, st: dict) -> list:
    """IOCs and CTI entities."""
    s5 = data.get("section_5_iocs_artifacts", {})
    items = [SectionHeader(4, "IOCs & Artifacts"), Spacer(1, 3 * mm)]

    tables = list(s5.get("ioc_tables", []))

    # Also render threat intelligence entities, not only raw network/file IOCs.
    ti = s5.get("threat_intelligence", {})
    label_map = {
        "malware_names": "Malware",
        "ransomware_groups": "Ransomware Group",
        "apt_groups": "APT Group",
        "tools_abused": "Tool",
        "cves": "CVE",
        "campaign_names": "Campaign",
    }

    ti_rows = []
    for key, label in label_map.items():
        for value in ti.get(key, []):
            if isinstance(value, str) and value.strip():
                ti_rows.append((label, value))

    existing_titles = {str(t.get("title", "")).lower() for t in tables}
    if ti_rows and "threat intelligence entities" not in existing_titles:
        tables.append({
            "title": "Threat Intelligence Entities",
            "rows": ti_rows,
        })

    if not tables:
        return items + [
            Paragraph(
                "No concrete network, file, crypto, CVE, malware, or actor indicators "
                "were extracted from this message.",
                st["body"],
            )
        ]

    for group in tables:
        raw_rows = group.get("rows", [])
        if not raw_rows:
            continue

        rows = [[Paragraph("Type", st["table_hdr"]), Paragraph("Indicator", st["table_hdr"])]]
        rows += [
            [
                Paragraph(_safe(k, 24), st["table_cell_c"]),
                Paragraph(_safe(v, 150), st["mono"]),
            ]
            for k, v in raw_rows
        ]

        tbl = Table(rows, colWidths=[35 * mm, 135 * mm], repeatRows=1)
        tbl.setStyle(_table_style())

        items += [
            Paragraph(_safe(group.get("title", "Indicators")), st["subsection"]),
            tbl,
            Spacer(1, 3 * mm),
        ]

    return items


def _render_section_5(data: dict, st: dict) -> list:
    """Mitigations."""
    s6 = data.get("section_6_mitigations", {})

    items = [
        SectionHeader(5, "Mitigation & Remediation"),
        Spacer(1, 3 * mm),
        Paragraph("Top Priority Actions", st["subsection"]),
    ]

    priority_actions = s6.get("priority_actions", [])

    if priority_actions:
        p_rows = [[Paragraph(h, st["table_hdr"]) for h in ("#", "Priority Action", "Standard Ref")]]

        for idx, action in enumerate(priority_actions[:5]):
            if isinstance(action, dict):
                text = action.get("text", "")
                refs = action.get("refs", "Best Practice")
            else:
                text = str(action)
                refs = "Best Practice"

            p_rows.append([
                Paragraph(str(idx + 1), st["table_cell_c"]),
                Paragraph(_safe(text, 300), st["table_cell"]),
                Paragraph(_safe(refs, 60), st["table_cell_c"]),
            ])

        p_tbl = Table(p_rows, colWidths=[8 * mm, 130 * mm, 32 * mm], repeatRows=1)
        p_tbl.setStyle(_table_style())
        items += [p_tbl, Spacer(1, 5 * mm)]
    else:
        items += [
            Paragraph(
                "No Critical/High priority actions were promoted. "
                "See technique-level mitigations below if available.",
                st["body"],
            ),
            Spacer(1, 3 * mm),
        ]

    by_technique = s6.get("by_technique", [])
    if by_technique:
        items += [Paragraph("Mitigations by Technique", st["subsection"])]

        rows = [[
            Paragraph("Technique", st["table_hdr"]),
            Paragraph("Severity", st["table_hdr"]),
            Paragraph("Priority", st["table_hdr"]),
            Paragraph("Recommended Mitigation", st["table_hdr"]),
        ]]

        for tm in by_technique[:8]:
            mitigations = tm.get("mitigations", [])
            mit_text = "; ".join(mitigations[:2]) if mitigations else "No mitigation text returned."

            rows.append([
                Paragraph(
                    f"<b>{_safe(tm.get('technique_id', ''))}</b><br/>{_safe(tm.get('technique_name', ''), 45)}",
                    st["table_cell"],
                ),
                Paragraph(_safe(tm.get("severity_level", "Unknown")), st["table_cell_c"]),
                Paragraph(_safe(tm.get("priority", "short_term")), st["table_cell_c"]),
                Paragraph(_safe(mit_text, 350), st["table_cell"]),
            ])

        tbl = Table(rows, colWidths=[42 * mm, 22 * mm, 26 * mm, 80 * mm], repeatRows=1)
        tbl.setStyle(_table_style())
        items += [tbl, Spacer(1, 5 * mm)]

    recs = s6.get("global_recommendations", [])
    if recs:
        items += [
            Paragraph("Strategic Recommendations", st["subsection"]),
            *[Paragraph(f"&#x2022; {_safe(r)}", st["bullet"]) for r in recs],
        ]

    if not priority_actions and not by_technique and not recs:
        items += [
            Paragraph(
                "No mitigations were generated. This usually means no ATT&CK techniques "
                "were mapped upstream.",
                st["body"],
            )
        ]

    return items




# ---------------------------------------------------------------------------
#  PAGE DECORATORS
# ---------------------------------------------------------------------------

def _on_page(canvas, doc):
    canvas.saveState()
    canvas.setStrokeColor(PRIMARY_DARK)
    canvas.line(15 * mm, A4[1] - 12 * mm, A4[0] - 15 * mm, A4[1] - 12 * mm)
    canvas.setFont("Helvetica-Bold", 9)
    canvas.setFillColor(PRIMARY_DARK)
    canvas.drawString(15 * mm, A4[1] - 10 * mm, "CTI Threat Intelligence Report")
    canvas.setStrokeColor(BORDER)
    canvas.line(15 * mm, 12 * mm, A4[0] - 15 * mm, 12 * mm)
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(TEXT_MUTED)
    canvas.drawCentredString(A4[0] / 2, 8 * mm, f"Page {doc.page}  |  Strictly Confidential")
    canvas.restoreState()


# ---------------------------------------------------------------------------
#  PUBLIC ENTRY POINT
# ---------------------------------------------------------------------------
import copy
def generate_pdf_report(report_data: dict, output_filepath: str) -> None:
    doc = SimpleDocTemplate(output_filepath, pagesize=A4,
                            rightMargin=15 * mm, leftMargin=15 * mm,
                            topMargin=15 * mm, bottomMargin=20 * mm)

    st = _build_styles()
    story = []

    renderers = [
        ("1", _render_section_1),
        ("2", _render_section_2),
        ("3", _render_section_3),
        ("4", _render_section_4),
        ("5", _render_section_5),
        ("dash", _render_dashboard),
    ]

    seen = set()

    for label, r in renderers:
        if r in seen:
            raise RuntimeError(f"Duplicate renderer detected: {r.__name__}")
        seen.add(r)

        story.extend(r(report_data, st))
        story.append(Spacer(1, 10 * mm))

    doc.build(story, onFirstPage=_on_page, onLaterPages=_on_page)
