import csv
import io
from datetime import datetime, timezone
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle


def make_csv(alerts):
    output = io.StringIO(newline='')
    fields = ['id','timestamp','src_ip','src_port','dst_ip','dst_port','protocol','rule','severity','reason','observed','status']
    writer = csv.DictWriter(output, fieldnames=fields, extrasaction='ignore')
    writer.writeheader()
    writer.writerows(alerts)
    return output.getvalue().encode('utf-8-sig')


def make_pdf(alerts, summary):
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=landscape(A4), rightMargin=14*mm, leftMargin=14*mm, topMargin=13*mm, bottomMargin=13*mm)
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name='SmallCell', parent=styles['BodyText'], fontSize=7, leading=8))
    story = [Paragraph('NIDS / Detection Field Report', styles['Title']),
             Paragraph('Generated: ' + datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC'), styles['Normal']),
             Spacer(1, 5*mm),
             Paragraph(f"Records analyzed: <b>{summary['records']}</b> &nbsp;&nbsp; Alerts: <b>{summary['alerts']}</b> &nbsp;&nbsp; High/Critical: <b>{summary['high']}</b>", styles['Heading2']),
             Spacer(1, 3*mm), Paragraph('Severity summary', styles['Heading3'])]
    sev_data = [['Severity','Count']] + [[s, str(summary['severities'].get(s, 0))] for s in ['Critical','High','Medium','Low']]
    sev = Table(sev_data, colWidths=[35*mm, 25*mm])
    sev.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),colors.HexColor('#173f35')),('TEXTCOLOR',(0,0),(-1,0),colors.white),('GRID',(0,0),(-1,-1),.3,colors.HexColor('#c9d2ca')),('PADDING',(0,0),(-1,-1),5)]))
    story += [sev, Spacer(1, 4*mm), Paragraph('Detected events', styles['Heading3'])]
    data = [['Time','Source','Destination','Protocol','Rule','Severity','Evidence']]
    for a in alerts[:250]:
        data.append([a.get('timestamp','')[:19], f"{a.get('src_ip','')}:{a.get('src_port') or '-'}", f"{a.get('dst_ip','')}:{a.get('dst_port') or '-'}", a.get('protocol',''), a.get('rule',''), a.get('severity',''), a.get('reason','')])
    table = Table([[Paragraph(str(c), styles['SmallCell']) for c in row] for row in data], repeatRows=1,
                  colWidths=[28*mm, 29*mm, 29*mm, 18*mm, 35*mm, 18*mm, 94*mm])
    table.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),colors.HexColor('#173f35')),('TEXTCOLOR',(0,0),(-1,0),colors.white),('GRID',(0,0),(-1,-1),.25,colors.HexColor('#c9d2ca')),('VALIGN',(0,0),(-1,-1),'TOP'),('PADDING',(0,0),(-1,-1),4),('ROWBACKGROUNDS',(0,1),(-1,-1),[colors.white,colors.HexColor('#f4f3ed')])]))
    story.append(table)
    story += [Spacer(1, 4*mm), Paragraph('Interpretation: these are rule-triggered findings, not proof of malicious intent. Validate the surrounding traffic and network context before taking action.', styles['Italic'])]
    doc.build(story)
    return buffer.getvalue()
