"""Branded PDF report with the DeployGuard logo, a diagonal watermark, scan history and fix steps."""
import io
from xml.sax.saxutils import escape

from django.conf import settings
from django.utils import timezone
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import KeepTogether, Paragraph, Preformatted, SimpleDocTemplate, Spacer, Table, TableStyle

from .fixes import PLATFORMS, fix_for

ACCENT = colors.HexColor("#3347d6")
INK = colors.HexColor("#1e233c")
MUTE = colors.HexColor("#586489")
SEV = {"critical": "#c4243b", "high": "#b8560a", "medium": "#8a6a00", "low": "#0d6fb0"}
ST = {"new": "#7b3fc4", "recurring": "#c2410c", "unchanged": "#586489", "resolved": "#0b7d55"}


def draw_logo(c, x, y, size, color, width=2.4):
    """Vector shield + check mark (same artwork as the web logo). x,y is the bottom-left corner."""
    c.saveState()
    c.translate(x, y + size)
    k = size / 32.0
    c.scale(k, -k)
    c.setStrokeColor(color)
    c.setLineWidth(width)
    c.setLineJoin(1)
    c.setLineCap(1)
    p = c.beginPath()
    p.moveTo(16, 2); p.lineTo(4, 7); p.lineTo(4, 15)
    p.curveTo(4, 22.5, 9, 28, 16, 30)
    p.curveTo(23, 28, 28, 22.5, 28, 15)
    p.lineTo(28, 7); p.close()
    c.drawPath(p, stroke=1, fill=0)
    q = c.beginPath()
    q.moveTo(10.5, 16); q.lineTo(14.5, 20); q.lineTo(21.5, 12)
    c.drawPath(q, stroke=1, fill=0)
    c.restoreState()


def _chrome(host, generated):
    def draw(c, doc):
        w, h = A4
        c.saveState()
        # watermark: faint centred logo plus diagonal brand text on every page
        c.setStrokeAlpha(0.07); c.setFillAlpha(0.07)
        draw_logo(c, w / 2 - 38 * mm, h / 2 - 38 * mm, 76 * mm, colors.HexColor("#6b7280"), width=1.6)
        c.translate(w / 2, h / 2); c.rotate(45)
        c.setFillColor(colors.HexColor("#3c468c")); c.setFont("Helvetica-Bold", 56)
        c.drawCentredString(0, -20, settings.SITE_NAME)
        c.restoreState()
        c.saveState()
        draw_logo(c, 15 * mm, h - 21 * mm, 11 * mm, ACCENT)
        c.setFillColor(INK); c.setFont("Helvetica-Bold", 14); c.drawString(29 * mm, h - 16.5 * mm, settings.SITE_NAME)
        c.setFillColor(MUTE); c.setFont("Helvetica", 9); c.drawRightString(w - 15 * mm, h - 16.5 * mm, "Security Regression Report")
        c.setStrokeColor(ACCENT); c.setLineWidth(0.8); c.line(15 * mm, h - 24 * mm, w - 15 * mm, h - 24 * mm)
        c.setStrokeColor(colors.HexColor("#d2d8eb")); c.setLineWidth(0.4); c.line(15 * mm, 15 * mm, w - 15 * mm, 15 * mm)
        c.setFillColor(MUTE); c.setFont("Helvetica", 8)
        c.drawString(15 * mm, 10 * mm, f"{settings.SITE_NAME}  |  {host}  |  Generated {generated}")
        c.drawRightString(w - 15 * mm, 10 * mm, f"Page {doc.page}")
        c.restoreState()
    return draw


def build_pdf(scan, platform: str = "nginx") -> bytes:
    host = scan.website.host
    platform = platform if platform in dict(PLATFORMS) else "nginx"
    plat_name = dict(PLATFORMS)[platform]
    history = list(scan.website.scans.order_by("number"))
    prev = scan.previous()
    counts = scan.counts()

    ss = getSampleStyleSheet()
    base = ParagraphStyle("b", parent=ss["Normal"], fontName="Helvetica", fontSize=9.5, leading=13, textColor=INK)
    small = ParagraphStyle("s", parent=base, fontSize=8.5, textColor=MUTE, leading=11)
    h1 = ParagraphStyle("h1", parent=base, fontName="Helvetica-Bold", fontSize=22, leading=26, spaceAfter=4)
    h2 = ParagraphStyle("h2", parent=base, fontName="Helvetica-Bold", fontSize=13, leading=16, spaceBefore=10, spaceAfter=5)
    label = ParagraphStyle("l", parent=base, fontName="Helvetica-Bold", fontSize=8.5, textColor=MUTE, spaceBefore=4, spaceAfter=1)
    code = ParagraphStyle("c", parent=base, fontName="Courier", fontSize=7.8, leading=10, leftIndent=6, backColor=colors.HexColor("#f1f3fa"), borderPadding=4)

    def pre(text):
        return Preformatted(text, code)

    story = [Paragraph("Security Regression Report", h1),
             Paragraph(f'<font color="#3347d6"><b>{escape(host)}</b></font>', ParagraphStyle("hh", parent=base, fontSize=14, leading=18)),
             Paragraph(escape(f"{scan.website.url}   |   Scan {scan.number} of {len(history)}   |   {timezone.localtime(scan.created_at):%d %b %Y, %H:%M}"), small),
             Paragraph(escape(f"Scan mode: {'Demo data' if scan.mode == 'demo' else 'Live scan'}   |   Requested by: {scan.website.owner.username}"), small),
             Spacer(1, 8)]
    delta = f"   ({scan.score - prev.score:+d} since scan {prev.number})" if prev else "   (baseline scan)"
    sc_color = "#0b7d55" if scan.score >= 80 else "#8a6a00" if scan.score >= 55 else "#c4243b"
    story.append(Paragraph(f'<font color="{sc_color}"><b>Security score: {scan.score} / 100{escape(delta)}</b></font>',
                           ParagraphStyle("sc", parent=base, fontSize=13, leading=17)))
    story.append(Paragraph("Summary of changes", h2))

    def grid(data, widths):
        t = Table(data, colWidths=widths, repeatRows=1)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#ecf0fa")), ("FONT", (0, 0), (-1, 0), "Helvetica-Bold", 8.5),
            ("TEXTCOLOR", (0, 0), (-1, 0), MUTE), ("FONT", (0, 1), (-1, -1), "Helvetica", 9), ("TEXTCOLOR", (0, 1), (-1, -1), INK),
            ("LINEBELOW", (0, 0), (-1, -1), 0.4, colors.HexColor("#dce1f0")), ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        return t

    story.append(grid([["New", "Recurring", "Unchanged", "Resolved", "Passed checks"],
                       [counts["new"], counts["recurring"], counts["unchanged"], counts["resolved"], counts["passed"]]], [34 * mm] * 4 + [40 * mm]))
    story.append(Spacer(1, 4))
    story.append(Paragraph("Each finding is compared with the previous scan. Recurring means the issue was fixed earlier and has come back." if prev else
                           "This is the first scan of this website. Every failing check is marked new and becomes the baseline for later comparisons.", small))
    story.append(Paragraph("Scan history", h2))
    rows = [["#", "Date", "Score", "New", "Recurring", "Unchanged", "Resolved"]]
    for h in history:
        k = h.counts()
        rows.append([h.number, f"{timezone.localtime(h.created_at):%d %b %Y}", h.score, k["new"], k["recurring"], k["unchanged"], k["resolved"]])
    story.append(grid(rows, [12 * mm, 36 * mm, 22 * mm, 22 * mm, 28 * mm, 28 * mm, 28 * mm]))
    story.append(Paragraph("Findings and how to fix them", ParagraphStyle("h14", parent=h2, fontSize=15, leading=19, spaceBefore=14)))

    findings = sorted(scan.findings.exclude(status="passed"), key=lambda f: (f.status == "resolved", f.severity_rank))
    if not findings:
        story.append(Paragraph("No findings. Every check passed.", base))
    for f in findings:
        block = [Paragraph(f"<b>{escape(f.title)}</b>", ParagraphStyle("ft", parent=base, fontSize=11.5, leading=15, spaceBefore=8)),
                 Paragraph(f'<font color="{ST["resolved"] if f.status == "resolved" else SEV[f.severity]}"><b>{f.severity.upper()}   |   {f.status.upper()}</b></font>',
                           ParagraphStyle("fm", parent=small, spaceAfter=3))]
        if f.status == "resolved":
            block.append(Paragraph("Fixed. This check passes in the current scan.", ParagraphStyle("ok", parent=base, textColor=colors.HexColor(ST["resolved"]))))
            story.append(KeepTogether(block))
            continue
        fx = fix_for(f.check_id, host)
        block += [Paragraph("Evidence", label), pre(f.evidence), Paragraph("Why it matters", label), Paragraph(escape(f.meta.impact), base),
                  Paragraph("How to fix", label)]
        block += [Paragraph(f"{i}. {escape(s)}", ParagraphStyle("st", parent=base, leftIndent=8)) for i, s in enumerate(fx["steps"], 1)]
        block += [Paragraph(f"Code for {plat_name}", label), pre(fx["code"][platform]), Paragraph("Verify after deploying", label), pre(fx["verify"])]
        ai = f.ai_prompts.first()
        if ai:
            block += [Paragraph("AI explanation", ParagraphStyle("ai", parent=label, textColor=ACCENT)),
                      Paragraph(escape(ai.response[:1200]).replace("\n", "<br/>"), ParagraphStyle("aib", parent=base, leftIndent=6, fontSize=9))]
        story.append(KeepTogether(block[:3]))
        story.extend(block[3:])
    story.append(Spacer(1, 10))
    story.append(Paragraph("Findings come from fixed, repeatable checks. AI text only explains the scanner's evidence and does not add findings.", small))

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=15 * mm, rightMargin=15 * mm, topMargin=32 * mm, bottomMargin=22 * mm,
                            title=f"{settings.SITE_NAME} report for {host}", author=settings.SITE_NAME)
    chrome = _chrome(host, timezone.localtime(timezone.now()).strftime("%d %b %Y"))
    doc.build(story, onFirstPage=chrome, onLaterPages=chrome)
    return buf.getvalue()
