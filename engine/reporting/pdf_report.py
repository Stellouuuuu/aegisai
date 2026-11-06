"""PDF audit report rendered from the JSON report (requires reportlab)."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    Paragraph,
    Preformatted,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

SEVERITY_COLORS = {
    "critical": colors.HexColor("#b71c1c"),
    "high": colors.HexColor("#e65100"),
    "medium": colors.HexColor("#f9a825"),
    "low": colors.HexColor("#1565c0"),
}
SEVERITY_ORDER = ["critical", "high", "medium", "low"]
CONFIDENCE_LABEL = {"confirmed": "Confirmé", "needs_review": "A vérifier", "rejected": "Rejeté"}
METHODOLOGY = (
    "AegisAI teste l'application en boîte noire, via son API. Chaque scénario d'attaque est "
    "rattaché à l'OWASP Top 10 for LLM Applications 2025 et à MITRE ATLAS. Une faille n'est "
    "déclarée qu'avec une preuve objective (canary token, marqueur d'injection, appel d'outil "
    "interdit), comparée à une réponse de référence et rejouée plusieurs fois pour écarter "
    "les faux positifs. La gravité combine impact, exploitabilité et confiance."
)


def _t(text: object) -> str:
    """Safe text for the built-in PDF fonts (Latin-1 range) and for Paragraph markup."""
    return escape(str(text).encode("cp1252", "replace").decode("cp1252"))


def _pre(text: object, width: int = 95) -> str:
    raw = str(text).encode("cp1252", "replace").decode("cp1252")
    lines: list[str] = []
    for line in raw.splitlines() or [""]:
        lines.extend(line[i : i + width] for i in range(0, max(len(line), 1), width))
    return "\n".join(lines[:25])


def render_pdf(report: dict[str, Any], out_path: str | Path) -> Path:
    base = getSampleStyleSheet()
    h1 = ParagraphStyle("h1", parent=base["Title"], fontSize=22, spaceAfter=6)
    h2 = ParagraphStyle("h2", parent=base["Heading2"], spaceBefore=14, spaceAfter=6)
    h3 = ParagraphStyle("h3", parent=base["Heading3"], spaceBefore=10, spaceAfter=4)
    body = ParagraphStyle("body", parent=base["BodyText"], leading=14)
    small = ParagraphStyle("small", parent=body, fontSize=8, textColor=colors.grey)
    code = ParagraphStyle("code", fontName="Courier", fontSize=7.5, leading=9.5,
                          backColor=colors.HexColor("#f4f4f4"), borderPadding=4)

    doc = SimpleDocTemplate(
        str(out_path), pagesize=A4, title="Rapport d'audit AegisAI",
        leftMargin=2 * cm, rightMargin=2 * cm, topMargin=2 * cm, bottomMargin=2 * cm,
    )
    story: list[Any] = [
        Paragraph("Rapport d'audit de sécurité IA", h1),
        Paragraph("Généré par AegisAI", body),
        Spacer(1, 10),
    ]

    info = [
        ["Cible", _t(report["target"])],
        ["Date", _t(report["generated_at"])],
        ["Durée du scan", f"{report['duration_seconds']} s"],
        ["Requêtes émises", str(report["requests_sent"])],
        ["Profondeur", _t(report["depth"])],
        ["Modules", _t(", ".join(report["modules"]))],
    ]
    t = Table([[Paragraph(f"<b>{k}</b>", body), Paragraph(v, body)] for k, v in info],
              colWidths=[4 * cm, 13 * cm])
    t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.25, colors.lightgrey),
                           ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    story += [t, Paragraph("Méthodologie", h2), Paragraph(_t(METHODOLOGY), body)]

    story.append(Paragraph("Synthèse", h2))
    summary = report["summary"]
    story.append(Paragraph(f"Score de sécurité : <b>{report['security_score']}/100</b>", body))
    counts = [[s.capitalize() for s in SEVERITY_ORDER],
              [str(summary.get(s, 0)) for s in SEVERITY_ORDER]]
    ct = Table(counts, colWidths=[4.25 * cm] * 4)
    style = [("ALIGN", (0, 0), (-1, -1), "CENTER"), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
             ("GRID", (0, 0), (-1, -1), 0.25, colors.lightgrey)]
    for i, s in enumerate(SEVERITY_ORDER):
        style.append(("BACKGROUND", (i, 0), (i, 0), SEVERITY_COLORS[s]))
    ct.setStyle(TableStyle(style))
    story += [Spacer(1, 6), ct]

    story.append(Paragraph("Détail des vulnérabilités", h2))
    if not report["findings"]:
        story.append(Paragraph("Aucune vulnérabilité prouvée par les scénarios exécutés.", body))
    for f in report["findings"]:
        sev = f["severity"]
        head = (f"<font color='{SEVERITY_COLORS[sev].hexval().replace('0x', '#')}'>"
                f"[{sev.upper()}]</font> {_t(f['id'])} : {_t(f['scenario'])}")
        story.append(Paragraph(head, h3))
        meta = (f"OWASP {_t(f['owasp'])} | ATLAS {_t(f.get('atlas') or '-')} | "
                f"Risque {f.get('risk_score')} / 10 | "
                f"{CONFIDENCE_LABEL.get(f['confidence'], f['confidence'])} | "
                f"Rejouable : {'oui' if f['reproducible'] else 'non'}")
        story += [Paragraph(meta, small), Spacer(1, 4)]
        story.append(Paragraph(f"<b>Preuve :</b> {_t(f['evidence'])}", body))
        story.append(Paragraph(f"<b>Règle violée :</b> {_t(f['safety_rule_violated'])}", body))
        story.append(Paragraph("<b>Requête envoyée :</b>", body))
        story.append(Preformatted(_pre(f["request"]), code))
        story.append(Paragraph("<b>Réponse reçue :</b>", body))
        story.append(Preformatted(_pre(f["response"]), code))
        story.append(Paragraph(f"<b>Recommandation :</b> {_t(f['recommendation'])}", body))

    doc.build(story)
    return Path(out_path)
