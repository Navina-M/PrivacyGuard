"""
dlp/ner.py

spaCy NER wrapper. Falls back cleanly if spaCy or the language model
isn't installed — the rest of the app must keep working on regex-only
detection in that case.
"""
from typing import List, Dict

_NLP = None
_NER_AVAILABLE = False
_UNAVAILABLE_REASON = ""

# Entity types we care about for a DLP context. DATE is excluded by
# default from being auto-flagged — dates alone aren't inherently
# sensitive; PERSON/ORG/GPE/LOC are informative but not auto-critical.
RELEVANT_LABELS = {"PERSON", "ORG", "GPE", "LOC"}

_SEVERITY_BY_LABEL = {
    "PERSON": "LOW",
    "ORG": "LOW",
    "GPE": "LOW",
    "LOC": "LOW",
}

_CATEGORY_BY_LABEL = {
    "PERSON": "Personal Information",
    "ORG": "Business Information",
    "GPE": "Personal Information",
    "LOC": "Personal Information",
}


def _try_load():
    global _NLP, _NER_AVAILABLE, _UNAVAILABLE_REASON
    try:
        import spacy  # noqa: F401
    except ModuleNotFoundError:
        _UNAVAILABLE_REASON = (
            "spaCy is not installed in this environment. "
            "Install with `pip install spacy` and "
            "`python -m spacy download en_core_web_sm` to enable NER."
        )
        _NER_AVAILABLE = False
        return

    try:
        import spacy
        _NLP = spacy.load("en_core_web_sm")
        _NER_AVAILABLE = True
    except OSError:
        _UNAVAILABLE_REASON = (
            "spaCy is installed but the 'en_core_web_sm' model is missing. "
            "Run `python -m spacy download en_core_web_sm`."
        )
        _NER_AVAILABLE = False


_try_load()


def ner_status() -> Dict:
    return {
        "available": _NER_AVAILABLE,
        "reason": None if _NER_AVAILABLE else _UNAVAILABLE_REASON,
    }


def detect_entities(text: str) -> List[Dict]:
    """
    Returns structured findings in the same shape as dlp.detector.detect(),
    so results can be merged directly. Returns [] (never raises) if NER
    is unavailable — callers should treat that as "regex-only mode".
    """
    if not _NER_AVAILABLE or _NLP is None:
        return []

    doc = _NLP(text)
    findings = []
    for ent in doc.ents:
        if ent.label_ not in RELEVANT_LABELS:
            continue
        value = ent.text.strip()
        if not value:
            continue
        findings.append({
            "type": f"NER_{ent.label_}",
            "category": _CATEGORY_BY_LABEL.get(ent.label_, "Personal Information"),
            "value": value,
            "start": ent.start_char,
            "end": ent.end_char,
            "confidence": 0.75,
            "source": "ner",
            "severity": _SEVERITY_BY_LABEL.get(ent.label_, "LOW"),
        })
    return findings
