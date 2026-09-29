"""
dlp/ner.py

spaCy NER wrapper. Falls back cleanly if spaCy or the language model
isn't installed — the rest of the app must keep working on regex-only
detection in that case.
"""
from typing import List, Dict
import re

_NLP = None
_NER_AVAILABLE = False
_UNAVAILABLE_REASON = ""

# Entity types we care about for a DLP context.
# PERSON is the primary PII entity. Generic locations (GPE/LOC) and organizations (ORG)
# are filtered to prevent spamming common nouns and public entity names.
RELEVANT_LABELS = {"PERSON"}

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

# Common non-person words that NER often misidentifies as PERSON entities
_NON_PERSON_WORDS = {
    "monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday",
    "january", "february", "march", "april", "may", "june", "july", "august",
    "september", "october", "november", "december",
    "confidential", "internal", "proprietary", "employee", "patient", "customer",
    "doctor", "summary", "discharge", "form", "application", "document", "report",
    "notes", "diagnosis", "prescription", "hospital", "clinic", "department",
    "status", "total", "subtotal", "tax", "amount", "balance", "invoice", "receipt",
    "date", "time", "year", "month", "day", "name", "title", "subject", "author",
    "manager", "director", "admin", "administrator", "user", "username", "password",
    "system", "server", "database", "python", "javascript", "linux", "windows",
    "google", "microsoft", "amazon", "apple", "github", "facebook", "twitter",
    "india", "united states", "america", "bangalore", "karnataka", "chennai", "mumbai",
    "delhi", "california", "new york", "london", "paris", "tokyo", "singapore",
    "visa", "mastercard", "rupay", "amex", "hdfc", "sbi", "icici", "axis",
    "terms", "conditions", "privacy", "guard", "edge", "test", "sample", "example",
    "strictly", "warning", "caution", "notice", "section", "page", "header", "footer",
    "billing", "payment", "card", "account", "number", "code", "reference", "id"
}


def _is_valid_person_name(name_str: str, text: str, start: int, end: int) -> bool:
    """
    Check whether a candidate PERSON entity looks like an actual person name
    rather than a misclassified header, common word, or label.
    """
    clean = name_str.strip().strip(":,.-_#\"'()")
    if len(clean) < 2 or len(clean) > 50:
        return False

    lower_clean = clean.lower()
    if lower_clean in _NON_PERSON_WORDS:
        return False

    # Check tokens
    tokens = [t for t in re.split(r"[\s\-_]+", lower_clean) if t]
    if not tokens:
        return False

    # If any token is purely numbers or symbols
    if any(re.match(r"^\d+$", t) for t in tokens):
        return False

    # If all tokens are known non-person words
    if all(t in _NON_PERSON_WORDS for t in tokens):
        return False

    # Look for name prefix indicators in preceding context window
    prefix_indicators = ("name", "mr.", "mrs.", "ms.", "dr.", "prof.", "patient", "employee", "author", "contact", "user", "👤", "🧑")
    window_before = text[max(0, start - 40):start].lower()
    has_name_prefix = any(p in window_before for p in prefix_indicators)

    # Valid if preceded by name indicator or is a 2-3 word capitalized proper name not in blacklist
    if has_name_prefix:
        return True

    # Multi-token capitalized name without digits
    if len(tokens) >= 2 and all(len(t) > 1 for t in tokens) and not any(ch.isdigit() for ch in clean):
        # Ensure it's not all uppercase header title (e.g. "PATIENT DISCHARGE SUMMARY")
        if clean.isupper() and len(tokens) > 2:
            return False
        return True

    return False


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
    if not _NER_AVAILABLE or _NLP is None or not text:
        return []

    doc = _NLP(text)
    findings = []
    for ent in doc.ents:
        if ent.label_ not in RELEVANT_LABELS:
            continue
        value = ent.text.strip()
        if not value:
            continue

        if ent.label_ == "PERSON":
            if not _is_valid_person_name(value, text, ent.start_char, ent.end_char):
                continue

        findings.append({
            "type": f"NER_{ent.label_}",
            "category": _CATEGORY_BY_LABEL.get(ent.label_, "Personal Information"),
            "value": value,
            "start": ent.start_char,
            "end": ent.end_char,
            "confidence": 0.85,
            "source": "ner",
            "severity": _SEVERITY_BY_LABEL.get(ent.label_, "LOW"),
        })
    return findings
