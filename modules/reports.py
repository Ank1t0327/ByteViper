import json
import csv
import io
import os
import time
from modules.db import db_manager

def generate_json_report():
    """Generates a complete JSON dump of packets, alerts, and sessions."""
    report_data = {
        "generated_at": time.time(),
        "packets": db_manager.get_packets(limit=2000),
        "alerts": db_manager.get_alerts(limit=2000),
        "sessions": db_manager.get_sessions(limit=2000)
    }
    return json.dumps(report_data, indent=2)

def generate_alerts_csv():
    """Generates a CSV string representing triggered security alerts."""
    alerts = db_manager.get_alerts(limit=2000)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Timestamp", "Rule Name", "Severity", "Description", "Source IP"])
    for a in alerts:
        writer.writerow([
            a.get("id"),
            a.get("timestamp"),
            a.get("rule_name"),
            a.get("severity"),
            a.get("description"),
            a.get("src_ip")
        ])
    return output.getvalue()

def generate_packets_csv():
    """Generates a CSV string representing captured packets."""
    packets = db_manager.get_packets(limit=2000)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Timestamp", "Length", "Protocol", "Source IP", "Destination IP", "Summary"])
    for p in packets:
        writer.writerow([
            p.get("id"),
            p.get("timestamp"),
            p.get("length"),
            p.get("protocol"),
            p.get("src_ip"),
            p.get("dst_ip"),
            p.get("summary")
        ])
    return output.getvalue()

def generate_pcap_report():
    """Generates a raw PCAP byte stream of captured packets."""
    from web.streamer import streamer
    from scapy.all import wrpcap
    import tempfile
    
    raw_packets = streamer.get_raw_packets()
    
    # Write to a temp file and read back
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
        tmp_name = tmp.name
        
    try:
        wrpcap(tmp_name, raw_packets)
        with open(tmp_name, "rb") as f:
            pcap_bytes = f.read()
    finally:
        if os.path.exists(tmp_name):
            os.remove(tmp_name)
            
    return pcap_bytes

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch

def generate_pdf_report():
    """Generates a professional forensic PDF report of captured traffic and alerts."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=54,
        leftMargin=54,
        topMargin=54,
        bottomMargin=54
    )
    
    styles = getSampleStyleSheet()
    
    # Custom Styles for Premium Look
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=24,
        leading=28,
        textColor=colors.HexColor('#0f172a'),
        spaceAfter=15
    )
    
    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor('#475569'),
        spaceAfter=25
    )

    h1_style = ParagraphStyle(
        'SectionH1',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=14,
        leading=18,
        textColor=colors.HexColor('#0f172a'),
        spaceBefore=15,
        spaceAfter=10,
        keepWithNext=True
    )
    
    body_style = ParagraphStyle(
        'BodyDark',
        parent=styles['BodyText'],
        fontName='Helvetica',
        fontSize=9.5,
        leading=13.5,
        textColor=colors.HexColor('#1e293b')
    )

    code_style = ParagraphStyle(
        'CodeStyle',
        parent=styles['CodeText'],
        fontName='Courier',
        fontSize=8.5,
        leading=11,
        textColor=colors.HexColor('#0f172a')
    )
    
    # Fetch data from DB
    packets = db_manager.get_packets(limit=2000)
    alerts = db_manager.get_alerts(limit=2000)
    sessions = db_manager.get_sessions(limit=2000)

    total_packets = len(packets)
    total_alerts = len(alerts)
    total_sessions = len(sessions)

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for a in alerts:
        sev = a.get("severity", "MEDIUM").upper()
        if sev in severity_counts:
            severity_counts[sev] += 1

    story = []
    
    # Title & Metadata
    story.append(Paragraph("ByteViper NDS Forensic Report", title_style))
    story.append(Paragraph(f"Generated on <b>{time.ctime()}</b> | Target Network Monitoring Session", subtitle_style))
    story.append(Spacer(1, 10))

    # Executive Summary Section
    story.append(Paragraph("1. Executive Summary", h1_style))
    exec_summary_text = (
        "This automated forensic report captures security posture assessment metrics and live network incident "
        "timelines recorded by the ByteViper Network Detection System. The engine conducts deep packet "
        "inspection (DPI) on layer-7 payloads to detect vulnerabilities, protocol non-compliance, credential leaks, "
        "and command-and-control (C2) actions. Over the capture interval, network headers and payloads were "
        "correlated against real-time threat intelligence feeds."
    )
    story.append(Paragraph(exec_summary_text, body_style))
    story.append(Spacer(1, 15))

    # Stats Table
    stats_data = [
        [
            Paragraph("<b>Total Packets Captured:</b>", body_style),
            Paragraph(str(total_packets), body_style),
            Paragraph("<b>Total Flow Sessions:</b>", body_style),
            Paragraph(str(total_sessions), body_style)
        ],
        [
            Paragraph("<b>Total Security Alerts:</b>", body_style),
            Paragraph(f"<font color='red'><b>{total_alerts}</b></font>", body_style),
            Paragraph("<b>Critical / High Alerts:</b>", body_style),
            Paragraph(f"<b>{severity_counts['CRITICAL'] + severity_counts['HIGH']}</b>", body_style)
        ]
    ]
    
    stats_table = Table(stats_data, colWidths=[2.0*inch, 1.25*inch, 2.0*inch, 1.25*inch])
    stats_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f8fafc')),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('TEXTCOLOR', (0,0), (-1,-1), colors.HexColor('#0f172a')),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#cbd5e1')),
        ('TOPPADDING', (0,0), (-1,-1), 8),
        ('BOTTOMPADDING', (0,0), (-1,-1), 8),
    ]))
    story.append(stats_table)
    story.append(Spacer(1, 20))
    
    def add_header_footer(canvas, doc):
        canvas.saveState()
        canvas.setFont('Helvetica', 8)
        canvas.setFillColor(colors.HexColor('#64748b'))
        canvas.drawString(54, 36, "ByteViper Network Detection System | Forensic Report")
        canvas.drawRightString(doc.pagesize[0] - 54, 36, f"Page {doc.page}")
        canvas.setStrokeColor(colors.HexColor('#cbd5e1'))
        canvas.setLineWidth(0.5)
        canvas.line(54, doc.pagesize[1] - 40, doc.pagesize[0] - 54, doc.pagesize[1] - 40)
        canvas.drawString(54, doc.pagesize[1] - 35, "CONFIDENTIAL - CYBERSECURITY EVIDENCE")
        canvas.restoreState()

    doc.build(story, onFirstPage=add_header_footer, onLaterPages=add_header_footer)
    buffer.seek(0)
    return buffer.getvalue()
