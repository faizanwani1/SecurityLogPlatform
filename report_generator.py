
import os

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter

from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle
)

from reportlab.lib.styles import getSampleStyleSheet


def generate_report(incidents, logs):

    output_folder = "final_report"

    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    pdf_path = os.path.join(
        output_folder,
        "Security_Report.pdf"
    )

    doc = SimpleDocTemplate(
        pdf_path,
        pagesize=letter
    )

    styles = getSampleStyleSheet()

    content = []

    content.append(
        Paragraph(
            "Security Log Analysis & Incident Response Report",
            styles['Title']
        )
    )

    content.append(Spacer(1, 20))

    summary_data = [
        ["Metric", "Value"],
        ["Total Logs", str(len(logs))],
        ["Total Incidents", str(len(incidents))]
    ]

    summary_table = Table(summary_data)

    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.grey),
        ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
        ('GRID', (0,0), (-1,-1), 1, colors.black)
    ]))

    content.append(summary_table)

    content.append(Spacer(1,20))

    content.append(
        Paragraph(
            "Incident Summary",
            styles['Heading2']
        )
    )

    for incident in incidents:

        content.append(
            Paragraph(
                f"Incident #{incident.id}: {incident.title}",
                styles['Heading3']
            )
        )

        content.append(
            Paragraph(
                f"Severity: {incident.severity}",
                styles['BodyText']
            )
        )

        content.append(
            Paragraph(
                f"Status: {incident.status}",
                styles['BodyText']
            )
        )

        content.append(Spacer(1,10))

    doc.build(content)

    return pdf_path

