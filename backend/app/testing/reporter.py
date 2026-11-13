"""Generates the QA Report exports offered by the dashboard: PDF, JSON, CSV."""
from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone
from xml.sax.saxutils import escape as xml_escape

from app.testing.collector import ResultCollector
from app.testing.schema_version import SCHEMA_VERSION

_STATUS_HEX = {
    "PASS": "#1a7f37",
    "FAIL": "#c62828",
    "WARNING": "#b7791f",
    "INFO": "#1967d2",
    "ERROR": "#7b1fa2",
}


def _status_of(result) -> str:
    return result.status if isinstance(result.status, str) else result.status.value


def _category_of(result) -> str:
    return result.category if isinstance(result.category, str) else result.category.value


def _p(value: object) -> str:
    """Escape a value for safe embedding in reportlab's XML-like paragraph markup.

    Response bodies/descriptions can contain arbitrary text from the system
    under test (including literal '<' or '&'), so everything dynamic must be
    escaped before being interpolated into a Paragraph's markup string.
    """
    return xml_escape(str(value))


class Reporter:
    def __init__(self, collector: ResultCollector, environment_url: str, scope: str) -> None:
        self.collector = collector
        self.environment_url = environment_url
        self.scope = scope
        self.generated_at = datetime.now(timezone.utc)

    def to_json(self) -> str:
        payload = {
            "schema_version": SCHEMA_VERSION,
            "run_id": self.collector.run_id,
            "environment_url": self.environment_url,
            "scope": self.scope,
            "generated_at": self.generated_at.isoformat(),
            "summary": self.collector.summary(),
            "results": [r.model_dump(mode="json") for r in self.collector.results],
        }
        return json.dumps(payload, indent=2, default=str)

    def to_csv(self) -> str:
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(
            [
                "Test Case ID", "Category", "Name", "Description", "Status",
                "Expected", "Actual", "Status Code", "Duration (ms)", "Recommendation",
            ]
        )
        for r in self.collector.results:
            writer.writerow(
                [
                    r.test_case_id,
                    _category_of(r),
                    r.name,
                    r.description,
                    _status_of(r),
                    r.expected,
                    r.actual,
                    r.response.status_code if r.response else "",
                    round(r.duration_ms, 2),
                    r.recommendation or "",
                ]
            )
        return buffer.getvalue()

    def to_pdf(self) -> bytes:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import LETTER
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=LETTER,
            leftMargin=18 * mm,
            rightMargin=18 * mm,
            topMargin=16 * mm,
            bottomMargin=16 * mm,
            title=f"QA Report - {self.collector.run_id}",
        )
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle("QATitle", parent=styles["Title"], fontSize=18, spaceAfter=4)
        meta_style = ParagraphStyle("QAMeta", parent=styles["Normal"], textColor=colors.HexColor("#555555"))
        h2_style = ParagraphStyle("QAH2", parent=styles["Heading2"], fontSize=11, spaceBefore=14, spaceAfter=4)
        body_style = ParagraphStyle("QABody", parent=styles["Normal"], fontSize=9, leading=12)
        mono_style = ParagraphStyle(
            "QAMono", parent=styles["Code"], fontSize=7.5, leading=10,
            backColor=colors.HexColor("#f4f4f4"), borderPadding=4,
        )

        story: list = []
        story.append(Paragraph("Payment QA Suite &mdash; Test Report", title_style))
        story.append(Paragraph(f"Environment: {_p(self.environment_url)}", meta_style))
        story.append(
            Paragraph(
                f"Scope: {_p(self.scope)} | Generated: {_p(self.generated_at.isoformat())} | "
                f"Run ID: {_p(self.collector.run_id)}",
                meta_style,
            )
        )
        story.append(Spacer(1, 10))

        summary = self.collector.summary()
        summary_data = [
            ["Total", "Passed", "Failed", "Warnings", "Info", "Errors", "Pass Rate"],
            [
                str(summary["total"]), str(summary["passed"]), str(summary["failed"]),
                str(summary["warnings"]), str(summary["info"]), str(summary["errors"]),
                f'{summary["pass_rate"]}%',
            ],
        ]
        summary_table = Table(summary_data, hAlign="LEFT")
        summary_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111827")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d0d0d0")),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                ]
            )
        )
        story.append(summary_table)
        story.append(Spacer(1, 16))

        for result in self.collector.results:
            status_value = _status_of(result)
            category_value = _category_of(result)
            color_hex = _STATUS_HEX.get(status_value, "#000000")

            story.append(
                Paragraph(
                    f'<font color="{color_hex}"><b>[{_p(status_value)}]</b></font> '
                    f'{_p(result.test_case_id)} &mdash; {_p(result.name)} '
                    f'<font size=8 color="#777777">({_p(category_value)})</font>',
                    h2_style,
                )
            )
            story.append(Paragraph(f"<b>Description:</b> {_p(result.description)}", body_style))
            story.append(Paragraph(f"<b>Expected:</b> {_p(result.expected)}", body_style))
            story.append(Paragraph(f"<b>Actual:</b> {_p(result.actual)}", body_style))

            if result.input_parameters:
                story.append(
                    Paragraph(f"<b>Input:</b> {_p(json.dumps(result.input_parameters, default=str))}", mono_style)
                )
            if result.request:
                story.append(
                    Paragraph(f"<b>Request:</b> {_p(result.request.method)} {_p(result.request.url)}", mono_style)
                )
            if result.response:
                summary_line = f"status={result.response.status_code} elapsed={result.response.elapsed_ms}ms"
                if result.response.error:
                    summary_line += f" error={result.response.error}"
                story.append(Paragraph(f"<b>Response:</b> {_p(summary_line)}", mono_style))
            if result.recommendation:
                story.append(Paragraph(f"<b>Recommendation:</b> {_p(result.recommendation)}", body_style))

            story.append(Spacer(1, 8))

        doc.build(story)
        return buffer.getvalue()
