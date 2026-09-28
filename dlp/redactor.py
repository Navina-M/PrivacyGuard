"""
dlp/redactor.py

Text redaction and semantic HTML highlighting engine.
Supports multiple redaction styles (Tags, Masking, Full Block, Minimal, Category-based)
ensuring true irreversible redaction of sensitive values from text outputs.
"""
from typing import List, Dict, Optional
from html import escape
import json

SEVERITY_CSS_CLASS = {
    "CRITICAL": "hl-critical",
    "HIGH": "hl-high",
    "MEDIUM": "hl-medium",
    "LOW": "hl-low",
}


def _non_overlapping(findings: List[Dict]) -> List[Dict]:
    """
    Sort by start index, drop findings that overlap an already-accepted span
    (preserving the highest-confidence / first finding).
    """
    accepted = []
    occupied_until = -1
    for f in sorted(findings, key=lambda x: (x["start"], -(x.get("confidence", 0)))):
        if f["start"] >= occupied_until:
            accepted.append(f)
            occupied_until = f["end"]
    return accepted


def redact_text(
    text: str,
    findings: List[Dict],
    style: str = "TAG",
    custom_replacement: Optional[str] = None
) -> str:
    """
    Redact all identified sensitive spans in `text` with chosen redaction style.
    
    Styles:
      - 'TAG': [REDACTED: <TYPE>]  (e.g. [REDACTED: EMAIL])
      - 'MINIMAL': [REDACTED]
      - 'MASK': Replaces with asterisks or bullets '••••••••'
      - 'BLOCK': Replaces with solid blackout blocks '████████'
      - 'CATEGORY': [REDACTED: <CATEGORY>] (e.g. [REDACTED: Financial Information])
      - 'CUSTOM': Uses custom_replacement string
    """
    spans = _non_overlapping(findings)
    if not spans:
        return text

    out = []
    cursor = 0

    for f in spans:
        out.append(text[cursor:f["start"]])
        span_len = max(f["end"] - f["start"], 4)
        ftype = f.get("type", "SENSITIVE")
        fcat = f.get("category", "Confidential")

        if style == "TAG":
            token = f"[REDACTED - {ftype}]"
        elif style == "MINIMAL":
            token = "[REDACTED]"
        elif style == "MASK":
            token = "•" * span_len
        elif style == "BLOCK":
            token = "█" * min(span_len, 16)
        elif style == "CATEGORY":
            token = f"[{fcat.upper().replace(' ', '_')}]"
        elif style == "CUSTOM" and custom_replacement:
            token = custom_replacement.replace("{type}", ftype).replace("{category}", fcat)
        else:
            token = f"[REDACTED - {ftype}]"

        out.append(token)
        cursor = f["end"]

    out.append(text[cursor:])
    return "".join(out)


def highlight_html(text: str, findings: List[Dict]) -> str:
    """
    Build accessible HTML markup with semantic <mark> tags around sensitive spans.
    Includes data attributes, badges, and tooltip descriptions for the interactive UI.
    """
    spans = _non_overlapping(findings)
    if not spans:
        return escape(text)

    out = []
    cursor = 0
    for f in spans:
        out.append(escape(text[cursor:f["start"]]))
        css_class = SEVERITY_CSS_CLASS.get(f.get("severity", "LOW"), "hl-low")
        ftype = escape(f.get("type", "UNKNOWN"))
        fsev = escape(f.get("severity", "LOW"))
        fcat = escape(f.get("category", "General"))
        fconf = f"{round(f.get('confidence', 0.5) * 100)}%"

        span_text = text[f["start"]:f["end"]]
        tooltip = f"{ftype} | {fsev} Severity | {fcat} ({fconf} confidence)"

        out.append(
            f'<mark class="{css_class}" '
            f'data-type="{ftype}" '
            f'data-severity="{fsev}" '
            f'data-category="{fcat}" '
            f'data-confidence="{fconf}" '
            f'title="{escape(tooltip)}">'
            f'{escape(span_text)}'
            f'<span class="mark-tag">{ftype}</span>'
            f'</mark>'
        )
        cursor = f["end"]

    out.append(escape(text[cursor:]))
    return "".join(out)


def export_findings_csv(findings: List[Dict]) -> str:
    """Generate a clean CSV string of all findings."""
    import csv
    import io
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Type", "Category", "Detected Value", "Severity", "Confidence", "Source", "Start", "End"])
    for f in findings:
        writer.writerow([
            f.get("type", ""),
            f.get("category", ""),
            f.get("value", ""),
            f.get("severity", ""),
            f"{round(f.get('confidence', 0) * 100)}%",
            f.get("source", ""),
            f.get("start", ""),
            f.get("end", "")
        ])
    return output.getvalue()
