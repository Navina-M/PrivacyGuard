"""
dlp/patterns.py

Comprehensive pattern catalog and rule definitions for PrivacyGuard Edge.
Covers Government Identifiers (Aadhaar, PAN, Passports, SSN, Voter ID, Driving License),
Financial Data (Credit Cards, Bank Accounts, IFSC, UPI, SWIFT, IBAN, Crypto),
Credentials (API Keys, Passwords, Tokens, Private Keys, Database URIs),
Personal Information (Emails, Phones, DOB, Addresses, Health/MRN),
Network Infrastructure (IPv4, IPv6, MAC, URLs), and Business Data.
"""
import re

SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")

CATEGORIES = (
    "Personal Information",
    "Government Identifier",
    "Financial Information",
    "Credentials",
    "Network Information",
    "Business Information",
    "Health Information",
)

# List of tuples: (type_name, regex_pattern, category, severity, description)
PATTERNS = [
    # ---------------- Government Identifiers ----------------
    (
        "AADHAAR",
        r"\b[2-9]\d{3}\s?\d{4}\s?\d{4}\b",
        "Government Identifier",
        "HIGH",
        "Indian 12-digit Unique Identification Number (Aadhaar)",
    ),
    (
        "PAN",
        r"\b[A-Z]{5}[0-9]{4}[A-Z]\b",
        "Government Identifier",
        "HIGH",
        "Indian Permanent Account Number (Income Tax PAN)",
    ),
    (
        "PASSPORT_IN",
        r"\b[A-PR-WYa-pr-wy][1-9]\d\s?\d{4}[1-9]\b",
        "Government Identifier",
        "HIGH",
        "Indian Passport Number",
    ),
    (
        "PASSPORT_GLOBAL",
        r"(?i)\bpassport\s*(?:no|num|number|#)?\s*[:\-]?\s*([A-Z0-9]{6,10})\b",
        "Government Identifier",
        "HIGH",
        "International Passport Identifier",
    ),
    (
        "VOTER_ID_IN",
        r"\b[A-Z]{3}[0-9]{7}\b",
        "Government Identifier",
        "HIGH",
        "Indian Voter ID Card (EPIC)",
    ),
    (
        "DRIVING_LICENSE_IN",
        r"\b[A-Z]{2}[0-9]{2}\s?[0-9]{11}\b",
        "Government Identifier",
        "HIGH",
        "Indian Driving Licence Number",
    ),
    (
        "US_SSN",
        r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b",
        "Government Identifier",
        "CRITICAL",
        "United States Social Security Number (SSN)",
    ),
    (
        "UK_NINO",
        r"\b[A-CEGHJ-PR-TW-Z]{1}[A-CEGHJ-NPR-TW-Z]{1}\s?[0-9]{6}\s?[A-D]{1}\b",
        "Government Identifier",
        "HIGH",
        "UK National Insurance Number (NINO)",
    ),

    # ---------------- Financial Information ----------------
    (
        "CREDIT_CARD",
        r"\b(?:\d[ -]*?){13,19}\b",
        "Financial Information",
        "CRITICAL",
        "Payment Card Number (Visa, Mastercard, Amex, RuPay, Discover)",
    ),
    (
        "BANK_ACCOUNT_IN",
        r"\b\d{9,18}\b",
        "Financial Information",
        "HIGH",
        "Bank Account Number",
    ),
    (
        "IFSC",
        r"\b[A-Z]{4}0[A-Z0-9]{6}\b",
        "Financial Information",
        "HIGH",
        "Indian Financial System Code (IFSC)",
    ),
    (
        "SWIFT_BIC",
        r"\b[A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b",
        "Financial Information",
        "HIGH",
        "SWIFT / BIC Bank Routing Code",
    ),
    (
        "IBAN",
        r"\b[A-Z]{2}\d{2}\s?(?:[A-Z0-9]{4}\s?){3,7}[A-Z0-9]{1,4}\b",
        "Financial Information",
        "HIGH",
        "International Bank Account Number (IBAN)",
    ),
    (
        "UPI_ID",
        r"\b[a-zA-Z0-9.\-_]{2,256}@(?!gmail|yahoo|outlook|hotmail|icloud|proton|live)[a-zA-Z]{2,64}\b",
        "Financial Information",
        "MEDIUM",
        "Unified Payments Interface (UPI VPA)",
    ),
    (
        "CVV_CVC",
        r"(?i)\b(?:cvv|cvc|cvv2|cvc2|security[_\- ]?code)\s*[:=\-]?\s*([0-9]{3,4})\b",
        "Financial Information",
        "CRITICAL",
        "Card Security Verification Value (CVV/CVC)",
    ),
    (
        "SALARY_MENTION",
        r"(?i)\b(?:salary|ctc|remuneration|compensation|take[- ]home|stipend)\s*[:\-]?\s*(?:rs\.?|inr|₹|\$|€|£)?\s*[\d,]+(?:\.\d+)?(?:\s*(?:lpa|k|lakhs?|cr|crores?|p\.a\.|per annum|usd|inr))?\b",
        "Financial Information",
        "MEDIUM",
        "Salary or Compensation Figure",
    ),
    (
        "CRYPTO_WALLET",
        r"\b(?:0x[a-fA-F0-9]{40}|(?:bc1|[13])[a-km-zA-HJ-NP-Z1-9]{25,39}|[1-9A-HJ-NP-Za-km-z]{32,44})\b",
        "Financial Information",
        "HIGH",
        "Cryptocurrency Public Wallet Address (ETH, BTC, SOL)",
    ),

    # ---------------- Credentials & Secrets ----------------
    (
        "PASSWORD_FIELD",
        r"(?i)\b(?:password|passwd|pwd|db_pass|secret_key|master_key)\s*[:=]\s*[\"']?([^\s\"';]{3,})[\"']?",
        "Credentials",
        "CRITICAL",
        "Plaintext Password or Secret Assignment",
    ),
    (
        "AWS_ACCESS_KEY",
        r"\b(AKIA|ASIA|AROA)[0-9A-Z]{16}\b",
        "Credentials",
        "CRITICAL",
        "Amazon Web Services (AWS) Access Key ID",
    ),
    (
        "AWS_SECRET_KEY",
        r"(?i)\baws[_\-]?secret[_\-]?access[_\-]?key\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})[\"']?",
        "Credentials",
        "CRITICAL",
        "AWS Secret Access Key",
    ),
    (
        "GITHUB_TOKEN",
        r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}\b|\bgithub_pat_[A-Za-z0-9_]{82}\b",
        "Credentials",
        "CRITICAL",
        "GitHub Personal Access Token or OAuth Key",
    ),
    (
        "GOOGLE_API_KEY",
        r"\bAIza[0-9A-Za-z\-_]{35}\b",
        "Credentials",
        "CRITICAL",
        "Google Cloud / Maps / Firebase API Key",
    ),
    (
        "OPENAI_API_KEY",
        r"\bsk-[a-zA-Z0-9]{20,}\b|\bsk-proj-[a-zA-Z0-9\-_]{20,}\b",
        "Credentials",
        "CRITICAL",
        "OpenAI API Secret Key",
    ),
    (
        "SLACK_TOKEN",
        r"\bxox[baprs]-[0-9a-zA-Z]{10,48}\b",
        "Credentials",
        "CRITICAL",
        "Slack Bot / App / User Token",
    ),
    (
        "STRIPE_KEY",
        r"\b(?:sk|pk|rk)_(?:live|test)_[0-9a-zA-Z]{24,99}\b",
        "Credentials",
        "CRITICAL",
        "Stripe Payment Secret/Publishable Key",
    ),
    (
        "JWT_TOKEN",
        r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
        "Credentials",
        "CRITICAL",
        "JSON Web Token (JWT)",
    ),
    (
        "PRIVATE_KEY_BLOCK",
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----",
        "Credentials",
        "CRITICAL",
        "Cryptographic Private Key Block",
    ),
    (
        "DATABASE_CONNECTION_URI",
        r"\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp|mssql):\/\/[^\s\"'>]+",
        "Credentials",
        "CRITICAL",
        "Database Connection URI with Credentials",
    ),
    (
        "BEARER_TOKEN",
        r"(?i)\bBearer\s+([A-Za-z0-9\-_=]{20,})\b",
        "Credentials",
        "CRITICAL",
        "Authorization Bearer Token",
    ),
    (
        "API_KEY_GENERIC",
        r"(?i)\b(?:api[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|app[_-]?secret)\s*[:=]\s*[\"']?([A-Za-z0-9\-_]{16,})[\"']?",
        "Credentials",
        "CRITICAL",
        "Generic API Key or Secret Token",
    ),

    # ---------------- Personal Information (PII) ----------------
    (
        "EMAIL",
        r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        "Personal Information",
        "MEDIUM",
        "Electronic Mail Address",
    ),
    (
        "PHONE_IN",
        r"(?<!\d)(?:\+91[\-\s]?)?[6-9]\d{9}(?!\d)",
        "Personal Information",
        "MEDIUM",
        "Indian Mobile / Telephone Number",
    ),
    (
        "PHONE_INTL",
        r"\+(?:[1-9]\d{0,2})[\s\-\.]?(?:\(?\d{2,4}\)?[\s\-\.]?)?\d{3,4}[\s\-\.]?\d{3,4}\b",
        "Personal Information",
        "MEDIUM",
        "International E.164 Phone Number",
    ),
    (
        "DOB",
        r"\b(0?[1-9]|[12]\d|3[01])[\/\-.](0?[1-9]|1[0-2])[\/\-.](19|20)\d{2}\b",
        "Personal Information",
        "MEDIUM",
        "Date of Birth (DD/MM/YYYY or similar)",
    ),
    (
        "PINCODE_IN",
        r"(?i)\b(?:pin|pincode|postal\s*code)\s*[:\-]?\s*([1-9][0-9]{5})\b",
        "Personal Information",
        "LOW",
        "Indian 6-digit Postal Pincode",
    ),
    (
        "US_ZIPCODE",
        r"(?i)\b(?:zip|zipcode)\s*[:\-]?\s*(\d{5}(?:-\d{4})?)\b",
        "Personal Information",
        "LOW",
        "US Postal Zip Code",
    ),

    # ---------------- Health & Medical Information ----------------
    (
        "MEDICAL_RECORD_NUMBER",
        r"(?i)\b(?:mrn|patient[_\- ]?id|medical[_\- ]?record[_\- ]?no|rx[_\- ]?number)\s*[:\-]?\s*([A-Za-z0-9\-]{4,16})\b",
        "Health Information",
        "HIGH",
        "Medical Record Number / Patient Identifier",
    ),
    (
        "BLOOD_GROUP",
        r"(?i)\b(?:blood[_\- ]?(?:group|type))\s*[:\-]?\s*(A|B|AB|O)[+-]\b",
        "Health Information",
        "LOW",
        "Patient Blood Group / Type",
    ),

    # ---------------- Network Information ----------------
    (
        "IPV4",
        r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b",
        "Network Information",
        "LOW",
        "IPv4 Network IP Address",
    ),
    (
        "IPV6",
        r"\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b",
        "Network Information",
        "LOW",
        "IPv6 Network Address",
    ),
    (
        "MAC_ADDRESS",
        r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b",
        "Network Information",
        "LOW",
        "Hardware MAC Address",
    ),
    (
        "URL",
        r"\bhttps?:\/\/[^\s\"'>]+",
        "Network Information",
        "LOW",
        "Web URL / Endpoint",
    ),

    # ---------------- Business Information ----------------
    (
        "EMPLOYEE_ID",
        r"(?i)\bemp(?:loyee)?[_\- ]?id\s*[:\-]?\s*([A-Za-z0-9\-]{3,16})\b",
        "Business Information",
        "MEDIUM",
        "Employee Identifier / Corporate ID",
    ),
    (
        "CUSTOMER_ID",
        r"(?i)\bcustomer[_\- ]?id\s*[:\-]?\s*([A-Za-z0-9\-]{3,16})\b",
        "Business Information",
        "MEDIUM",
        "Customer / Account Identifier",
    ),
    (
        "CONFIDENTIAL_MARKER",
        r"(?i)\b(?:strictly\s+confidential|internal\s+use\s+only|do\s+not\s+distribute|proprietary\s+(?:and\s+confidential)?|trade\s+secret|nda\s+protected)\b",
        "Business Information",
        "MEDIUM",
        "Document Confidentiality / Classification Marker",
    ),
]

# Types that require additional context check if heuristic validation isn't available
CONTEXT_SENSITIVE_TYPES = {"BANK_ACCOUNT_IN", "CREDIT_CARD", "AADHAAR", "SWIFT_BIC"}


def compiled_patterns():
    """Return patterns with compiled regex objects."""
    compiled = []
    for item in PATTERNS:
        type_name = item[0]
        regex_str = item[1]
        category = item[2]
        severity = item[3]
        compiled.append((type_name, re.compile(regex_str), category, severity))
    return compiled
