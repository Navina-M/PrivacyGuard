"""
dlp/detector.py

High-accuracy sensitive information detector with checksum validation
(Luhn algorithm for cards, Verhoeff algorithm for Aadhaar, PAN structure checks),
context-aware false positive rejection, and privacy-preserving masking.
"""
from dataclasses import dataclass, asdict
from typing import List, Dict, Tuple
import re
from .patterns import compiled_patterns, CONTEXT_SENSITIVE_TYPES

_PATTERNS = compiled_patterns()

# Verhoeff algorithm multiplication and permutation tables for Indian Aadhaar checksum
_VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 6, 7, 8, 9, 0, 1, 2, 3, 4],
    [6, 7, 8, 9, 5, 1, 2, 3, 4, 0],
    [7, 8, 9, 5, 6, 2, 3, 4, 0, 1],
    [8, 9, 5, 6, 7, 3, 4, 0, 1, 2],
    [9, 5, 6, 7, 8, 4, 0, 1, 2, 3],
]

_VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]

_VERHOEFF_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]


def validate_verhoeff(num_str: str) -> bool:
    """Validates Aadhaar 12-digit number using Verhoeff checksum algorithm."""
    clean = re.sub(r"\D", "", num_str)
    if len(clean) != 12:
        return False
    c = 0
    reversed_digits = [int(x) for x in reversed(clean)]
    for i, digit in enumerate(reversed_digits):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][digit]]
    return c == 0


def validate_luhn(card_str: str) -> bool:
    """Validates Credit/Debit card numbers using the standard Luhn (mod 10) algorithm."""
    clean = re.sub(r"\D", "", card_str)
    if not (13 <= len(clean) <= 19):
        return False
    total = 0
    reverse_digits = [int(d) for d in clean[::-1]]
    for i, digit in enumerate(reverse_digits):
        if i % 2 == 1:
            doubled = digit * 2
            total += doubled - 9 if doubled > 9 else doubled
        else:
            total += digit
    return total % 10 == 0


def validate_pan(pan_str: str) -> bool:
    """Validates Indian PAN structure."""
    clean = pan_str.strip().upper()
    if len(clean) != 10:
        return False
    # 4th character must be one of the standard PAN holder status letters:
    # C (Company), P (Person), H (HUF), F (Firm), A (AOP), T (Trust), B (BOI), L (Local), J (Artificial Juridical), G (Govt)
    if clean[3] not in "CPHFATBLJG":
        return False
    return True


@dataclass
class Finding:
    type: str
    category: str
    value: str          # masked for display
    start: int
    end: int
    confidence: float
    source: str          # "regex" | "ner" | "ai"
    severity: str        # LOW | MEDIUM | HIGH | CRITICAL
    raw_preview: str = "" # safe contextual summary if needed

    def to_dict(self) -> Dict:
        return asdict(self)


def mask_value(raw: str, type_name: str = "") -> str:
    """
    Mask a sensitive value for safe presentation in reports and UI tables.
    Preserves structural hints (e.g. domain for email, last 4 for cards)
    while thoroughly hiding the secret.
    """
    raw = raw.strip()
    if not raw:
        return "****"

    if type_name == "EMAIL" and "@" in raw:
        user_part, domain = raw.split("@", 1)
        if len(user_part) <= 2:
            masked_user = user_part[:1] + "*"
        else:
            masked_user = user_part[:1] + "*" * (len(user_part) - 2) + user_part[-1:]
        return f"{masked_user}@{domain}"

    if type_name == "CREDIT_CARD":
        digits = re.sub(r"\D", "", raw)
        if len(digits) >= 4:
            return f"•••• •••• •••• {digits[-4:]}"

    if type_name == "AADHAAR":
        digits = re.sub(r"\D", "", raw)
        if len(digits) == 12:
            return f"•••• •••• {digits[-4:]}"

    if type_name in ("AWS_ACCESS_KEY", "GOOGLE_API_KEY", "OPENAI_API_KEY", "GITHUB_TOKEN"):
        if len(raw) > 8:
            return raw[:4] + "•" * (len(raw) - 8) + raw[-4:]

    if len(raw) <= 4:
        return "*" * len(raw)
    if len(raw) <= 8:
        return raw[:1] + "*" * (len(raw) - 2) + raw[-1:]
    return raw[:2] + "*" * (len(raw) - 4) + raw[-2:]


# Common English uppercase words that should never be misidentified as SWIFT codes
_UPPERCASE_WORD_REJECTIONS = {
    "INTERNAL", "SECURITY", "DOCUMENT", "TRANSFER", "STANDARD", "CUSTOMER",
    "HOSPITAL", "SCHEDULE", "PASSPORT", "EMPLOYEE", "DATABASE", "RESPONSE",
    "CONFIDENTIAL", "DOWNLOAD", "MANAGEMENT", "REPRESENTATIVE", "APPLICATION",
    "RESTRICTED", "DIRECTOR", "ADMINISTRATION", "INFORMATION", "DEPARTMENT",
    "PROPRIETARY", "COMMUNICATION", "DECLARATION", "CERTIFICATE", "OPERATIONS",
    "ELECTRONIC", "INDIVIDUAL", "VALIDATION", "GOVERNMENT", "HEALTHCARE",
    "REGISTERED", "PRODUCTION", "DISCHARGE", "TREATMENT", "DISCLAIMER",
    "STATEMENTS", "DISCLOSURE", "PARTICULAR", "IMPORTANT", "AGREEMENT",
    "REFERENCE", "CONDITIONS", "SUBMISSION", "AUTHORIZED", "COMPLIANCE",
    "ENTERPRISE", "TECHNOLOGY", "COPYRIGHT", "ORIGINAL", "MODIFIED"
}

_DUMMY_SECRET_VALUES = {
    "password", "passwd", "pwd", "secret", "true", "false", "null",
    "undefined", "none", "[redacted]", "********", "your_password",
    "placeholder", "string", "text", "type", "hidden", "default",
    "your_api_key_here", "your_secret_key", "xxxxxxxxxxxxxxxx",
    "abcdefghijklmnopqrstuvwxyz", "1234567890123456", "placeholder_key"
}

# Icon and Context Keyword Catalog
_CONTEXT_KEYWORDS_AND_ICONS = (
    # Unicode / Emoji Icons
    "📞", "📱", "☎️", "📲", "✆", "℡",
    "✉️", "📧", "📨", "📩",
    "💳", "🪙", "🆔", "🪪", "🎂", "👶",
    "📍", "📌", "🏠", "🏢",
    "🔒", "🔑", "🗝️", "🛡️",
    "💰", "💵", "💸", "₹", "$", "€", "£", "¥",
    "🩺", "⚕️", "🏥", "🩸", "👤", "🧑",
    # Contextual keywords
    "account", "a/c", "acct", "card", "aadhaar", "aadhar", "uid", "uidai",
    "pan", "ssn", "social security", "balance", "bank", "routing",
    "beneficiary", "swift", "bic", "ifsc", "customer", "emp", "token", "secret",
    "password", "passwd", "pwd", "salary", "ctc", "stipend", "wage", "remuneration",
    "dob", "birth", "born", "birthday", "mrn", "patient", "doctor", "rx",
    "email", "mail", "phone", "mobile", "tel", "cell", "contact",
    "pin", "pincode", "zip", "zipcode", "address", "voter", "epic", "passport"
)


def _looks_like_context_hit(match_text: str, full_text: str, start: int, end: int) -> Tuple[bool, float]:
    """
    Context check for high-false-positive types.
    Looks for surrounding keywords or icons within ~80 chars before or after the match.
    """
    window_before = full_text[max(0, start - 80):start].lower()
    window_after = full_text[end:min(len(full_text), end + 60)].lower()
    window = f"{window_before} {match_text.lower()} {window_after}"

    has_keyword = any(k.lower() in window for k in _CONTEXT_KEYWORDS_AND_ICONS)
    return has_keyword, (0.92 if has_keyword else 0.35)


def detect(text: str) -> List[Dict]:
    """
    Run all detection patterns with algorithmic checksums, symbol recognition,
    and context validation against `text`. Returns a structured list of verified findings.
    """
    if not text:
        return []

    findings: List[Finding] = []

    for type_name, regex, category, severity in _PATTERNS:
        for m in regex.finditer(text):
            raw_value = m.group(0).strip()
            start, end = m.start(), m.end()
            confidence = 0.95

            # ---------------- Algorithmic and Contextual Validation ----------------
            if type_name == "CREDIT_CARD":
                clean_digits = re.sub(r"\D", "", raw_value)
                if len(clean_digits) < 13 or len(clean_digits) > 19:
                    continue
                # Skip repeated identical digits like 0000000000000000 or 1111111111111111 if invalid
                if len(set(clean_digits)) == 1 and not validate_luhn(clean_digits):
                    continue
                if validate_luhn(clean_digits):
                    confidence = 0.99
                else:
                    has_ctx, _ = _looks_like_context_hit(raw_value, text, start, end)
                    if not has_ctx:
                        continue  # Skip random digit clusters that aren't valid cards
                    confidence = 0.75

            elif type_name == "AADHAAR":
                clean_digits = re.sub(r"\D", "", raw_value)
                if len(clean_digits) != 12:
                    continue
                # Aadhaar cannot start with 0 or 1, or have all repeated digits
                if clean_digits[0] in "01" or len(set(clean_digits)) == 1:
                    continue
                is_verhoeff = validate_verhoeff(clean_digits)
                has_ctx, _ = _looks_like_context_hit(raw_value, text, start, end)
                if is_verhoeff:
                    confidence = 0.98
                elif has_ctx:
                    confidence = 0.85
                else:
                    # 12 random numbers with invalid checksum and no context -> false positive
                    continue

            elif type_name == "PAN":
                clean_pan = raw_value.split()[-1].strip().upper()
                if validate_pan(clean_pan):
                    confidence = 0.98
                else:
                    # Check if surrounded by PAN keywords/icons
                    has_ctx, _ = _looks_like_context_hit(raw_value, text, start, end)
                    if not has_ctx:
                        continue
                    confidence = 0.70

            elif type_name == "SWIFT_BIC":
                upper_val = raw_value.strip().upper()
                # Reject normal English dictionary words
                if upper_val in _UPPERCASE_WORD_REJECTIONS:
                    continue
                # Check for bank/swift context
                has_ctx, _ = _looks_like_context_hit(raw_value, text, start, end)
                if not has_ctx:
                    continue
                confidence = 0.90

            elif type_name == "BANK_ACCOUNT_IN":
                clean_digits = re.sub(r"\D", "", raw_value)
                if len(clean_digits) < 9 or len(clean_digits) > 18:
                    continue
                # Reject all repeated digits (e.g. 000000000, 111111111)
                if len(set(clean_digits)) <= 2:
                    continue
                # Standalone digits require bank/financial context to avoid flagging random timestamps/numbers
                has_ctx, _ = _looks_like_context_hit(raw_value, text, start, end)
                if not has_ctx:
                    continue
                confidence = 0.90

            elif type_name == "PASSWORD_FIELD":
                # Check if the extracted password is just a placeholder/type attribute
                val_check = raw_value.split(":")[-1].split("=")[-1].strip(" \"'").lower()
                if val_check in _DUMMY_SECRET_VALUES or len(val_check) < 3:
                    continue
                confidence = 0.95

            elif type_name == "API_KEY_GENERIC":
                val_check = raw_value.split(":")[-1].split("=")[-1].strip(" \"'").lower()
                if val_check in _DUMMY_SECRET_VALUES:
                    continue
                confidence = 0.90

            elif type_name == "DOB":
                # Ensure date has context of birth or age or cake icon
                birth_indicators = ("dob", "birth", "born", "b'day", "birthday", "🎂", "👶", "age", "date of birth", "d.o.b")
                window_before = text[max(0, start - 50):start].lower()
                window_after = text[end:min(len(text), end + 30)].lower()
                window = f"{window_before} {raw_value.lower()} {window_after}"
                if not any(b in window for b in birth_indicators):
                    continue
                confidence = 0.92


            elif type_name in CONTEXT_SENSITIVE_TYPES:
                has_ctx, ctx_conf = _looks_like_context_hit(raw_value, text, start, end)
                if not has_ctx:
                    continue
                confidence = ctx_conf

            # Only accept findings meeting minimum confidence threshold (filters out noise)
            if confidence < 0.60:
                continue

            findings.append(
                Finding(
                    type=type_name,
                    category=category,
                    value=raw_value,
                    start=start,
                    end=end,
                    confidence=confidence,
                    source="regex",
                    severity=severity,
                )
            )

    return [f.to_dict() for f in findings]


def deduplicate(findings: List[Dict]) -> List[Dict]:
    """
    Collapse exact or overlapping findings, prioritizing higher confidence and severity.
    """
    seen = set()
    out = []
    # Sort findings by start position, then higher confidence
    sorted_findings = sorted(findings, key=lambda f: (f["start"], -f.get("confidence", 0)))
    for f in sorted_findings:
        key = (f["type"], f["start"], f["end"])
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out

