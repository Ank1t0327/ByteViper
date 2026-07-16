import json
import csv
import io
import os
import time
from core.db import db_manager

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
    
    story = []
    
    story.append(Paragraph("ByteViper NDS Forensic Report", title_style))
    story.append(Paragraph(f"Generated on {time.ctime()}", subtitle_style))
    story.append(Paragraph("This is a placeholder for the forensic report content.", body_style))
    
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
