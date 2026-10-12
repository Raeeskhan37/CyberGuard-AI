import json
from datetime import datetime, timezone
import io
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

def generate_json_report(scan_results: list, audit_results: dict, ai_analysis: dict) -> str:
    """
    Generates a structured, valid JSON security report.
    """
    report_dict = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "application": "CyberGuard AI",
        "developer": "Raees Khan",
        "scanner_results": scan_results if scan_results else [],
        "dependency_audit": audit_results if audit_results else {},
        "ai_analysis": ai_analysis if ai_analysis else {}
    }
    return json.dumps(report_dict, indent=4)

def generate_pdf_report(scan_results: list, audit_results: dict, ai_analysis: dict) -> io.BytesIO:
    """
    Generates a professional PDF security report using ReportLab.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
    story = []
    
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'ReportTitle',
        parent=styles['Heading1'],
        fontSize=20,
        textColor=colors.HexColor("#0f172a"),
        spaceAfter=6
    )
    subtitle_style = ParagraphStyle(
        'ReportSubtitle',
        parent=styles['Normal'],
        fontSize=10,
        textColor=colors.HexColor("#64748b"),
        spaceAfter=15
    )
    heading_style = ParagraphStyle(
        'SectionHeading',
        parent=styles['Heading2'],
        fontSize=14,
        textColor=colors.HexColor("#1e293b"),
        spaceBefore=12,
        spaceAfter=6
    )
    body_style = ParagraphStyle(
        'ReportBody',
        parent=styles['Normal'],
        fontSize=10,
        textColor=colors.HexColor("#334155"),
        spaceAfter=8
    )

    # Title & Metadata
    story.append(Paragraph("🛡️ CyberGuard AI — Security Assessment Report", title_style))
    story.append(Paragraph(f"Generated on: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')} | Developed by Raees Khan", subtitle_style))
    story.append(Spacer(1, 10))

    # Executive Summary Section
    story.append(Paragraph("Executive Summary", heading_style))
    if ai_analysis and ai_analysis.get("executive_summary"):
        story.append(Paragraph(ai_analysis.get("executive_summary"), body_style))
    else:
        story.append(Paragraph("No AI executive summary generated. Review raw scanner findings below.", body_style))
    
    story.append(Spacer(1, 10))

    # Bandit Findings Section
    story.append(Paragraph("Static Code Analysis Findings (Bandit)", heading_style))
    if scan_results:
        table_data = [["Severity", "File", "Line", "Test Name", "Description"]]
        for item in scan_results[:25]: # Limit for PDF fit
            table_data.append([
                Paragraph(str(item.get("severity", "LOW")), body_style),
                Paragraph(str(item.get("filename", "")), body_style),
                Paragraph(str(item.get("line_number", "")), body_style),
                Paragraph(str(item.get("test_name", "")), body_style),
                Paragraph(str(item.get("issue_text", ""))[:100], body_style)
            ])
        t = Table(table_data, colWidths=[65, 90, 35, 110, 240])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#f1f5f9")),
            ('TEXTCOLOR', (0,0), (-1,0), colors.HexColor("#0f172a")),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0,0), (-1,0), 6),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
        ]))
        story.append(t)
    else:
        story.append(Paragraph("No code vulnerabilities detected.", body_style))

    story.append(Spacer(1, 10))

    # Remediation Advice Section
    story.append(Paragraph("Remediation & Recommendations", heading_style))
    if ai_analysis and ai_analysis.get("remediation_advice"):
        story.append(Paragraph(ai_analysis.get("remediation_advice"), body_style))
    else:
        story.append(Paragraph("Standard remediation: Ensure secure coding principles, validate all user inputs, and keep dependencies updated.", body_style))

    doc.build(story)
    buffer.seek(0)
    return buffer
