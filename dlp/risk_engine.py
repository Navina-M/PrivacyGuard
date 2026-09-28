"""
dlp/risk_engine.py

Calculates comprehensive privacy risk scores, evaluates regulatory compliance impact
(GDPR, HIPAA, PCI-DSS, Indian DPDP Act 2023), and provides actionable remediation guidance.
"""
from typing import List, Dict
from collections import Counter

# Points per severity level
SEVERITY_POINTS = {
    "LOW": 5,
    "MEDIUM": 15,
    "HIGH": 35,
    "CRITICAL": 75,
}

# Score thresholds
THRESHOLDS = [
    (0, 45, "LOW"),
    (46, 120, "MEDIUM"),
    (121, 260, "HIGH"),
    (261, float("inf"), "CRITICAL"),
]

RECOMMENDATIONS = {
    "LOW": "Document has minimal sensitive information. Safe to share under standard organizational policies.",
    "MEDIUM": "Moderate sensitivity detected. Review and verify highlighted entries before external transfer or publishing.",
    "HIGH": "High risk detected. Redact sensitive government IDs, financial numbers, or internal markers prior to distribution.",
    "CRITICAL": "CRITICAL RISK: Unencrypted credentials, payment cards, or high-risk identifiers detected. Strictly do not distribute without full automated redaction and security review.",
}

COMPLIANCE_MAP = {
    "Government Identifier": ["DPDP Act 2023", "GDPR Art. 87", "CCPA/CPRA"],
    "Financial Information": ["PCI-DSS v4.0", "RBI Data Localization", "GLBA"],
    "Credentials": ["SOC 2 Security", "ISO/IEC 27001", "NIST CSF"],
    "Personal Information": ["GDPR Art. 6", "DPDP Act 2023", "PIPEDA"],
    "Health Information": ["HIPAA (Protected Health Info)", "GDPR Art. 9 (Special Category)"],
    "Network Information": ["CIS Controls", "Internal Security Baseline"],
    "Business Information": ["Trade Secret Protection", "Confidentiality NDA"],
}


def _level_for_score(score: int) -> str:
    for low, high, level in THRESHOLDS:
        if low <= score <= high:
            return level
    return "CRITICAL"


def assess(findings: List[Dict]) -> Dict:
    """
    Compute comprehensive privacy risk assessment from a list of structured findings.
    """
    if not findings:
        return {
            "score": 0,
            "level": "LOW",
            "reasons": ["No sensitive information detected in the analyzed content."],
            "recommendation": RECOMMENDATIONS["LOW"],
            "counts_by_severity": {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0},
            "counts_by_category": {},
            "compliance_impacts": [],
            "total_findings": 0,
        }

    score = 0
    severity_counts = Counter()
    category_counts = Counter()
    type_counts = Counter()
    impacted_regulations = set()

    for f in findings:
        sev = f.get("severity", "LOW")
        conf = f.get("confidence", 0.5)
        cat = f.get("category", "General")
        ftype = f.get("type", "UNKNOWN")

        category_counts[cat] += 1
        severity_counts[sev] += 1
        type_counts[ftype] += 1

        # Collect compliance impacts
        for reg in COMPLIANCE_MAP.get(cat, []):
            impacted_regulations.add(reg)

        # Diminishing returns calculation
        occurrence_index = type_counts[ftype]
        decay = max(0.35, 1.0 - 0.08 * (occurrence_index - 1))
        score += SEVERITY_POINTS.get(sev, 5) * conf * decay

    # Bonus penalty for co-occurring high risk categories
    distinct_categories = len(category_counts)
    if distinct_categories >= 3:
        score *= 1.2

    score = min(round(score), 999)
    level = _level_for_score(score)

    reasons = []
    if category_counts.get("Credentials"):
        reasons.append(f"{category_counts['Credentials']} credential(s)/secret(s) detected — severe risk of unauthorized system access if shared.")
    if category_counts.get("Government Identifier"):
        reasons.append(f"{category_counts['Government Identifier']} government identifier(s) detected (e.g. Aadhaar, PAN, SSN, Passport).")
    if category_counts.get("Financial Information"):
        reasons.append(f"{category_counts['Financial Information']} financial record(s) detected (e.g. Credit Card, Bank Account, UPI).")
    if category_counts.get("Health Information"):
        reasons.append(f"{category_counts['Health Information']} health/medical identifier(s) detected (protected health data).")
    if category_counts.get("Personal Information"):
        reasons.append(f"{category_counts['Personal Information']} personal information item(s) detected (PII).")
    if category_counts.get("Network Information"):
        reasons.append(f"{category_counts['Network Information']} network/infrastructure parameter(s) identified.")
    if category_counts.get("Business Information"):
        reasons.append(f"{category_counts['Business Information']} business-sensitive classification or employee reference(s) found.")

    if distinct_categories >= 3:
        reasons.append(f"Multiple data categories co-occur ({distinct_categories} categories), significantly increasing correlation risk.")

    if not reasons:
        reasons.append("Low-sensitivity references detected; minimal exposure risk.")

    return {
        "score": score,
        "level": level,
        "reasons": reasons,
        "recommendation": RECOMMENDATIONS[level],
        "counts_by_severity": {
            "LOW": severity_counts.get("LOW", 0),
            "MEDIUM": severity_counts.get("MEDIUM", 0),
            "HIGH": severity_counts.get("HIGH", 0),
            "CRITICAL": severity_counts.get("CRITICAL", 0),
        },
        "counts_by_category": dict(category_counts),
        "compliance_impacts": sorted(list(impacted_regulations)),
        "total_findings": len(findings),
    }


def explain_finding(finding: Dict) -> Dict:
    """
    Build explainability and remediation breakdown for an individual finding.
    """
    source_label = {
        "regex": "Deterministic Pattern Engine + Checksum",
        "ner": "Named Entity Recognition (spaCy)",
        "ai": "Contextual AI Heuristic",
    }.get(finding.get("source"), finding.get("source", "Pattern Matching"))

    conf = finding.get("confidence", 0.5)
    if conf >= 0.85:
        confidence_label = "High"
    elif conf >= 0.55:
        confidence_label = "Medium"
    else:
        confidence_label = "Low"

    ftype = finding.get("type", "SENSITIVE")
    fcat = finding.get("category", "Personal Data")
    fsev = finding.get("severity", "LOW")

    # Specific actionable guidance
    if fcat == "Credentials":
        action = "Immediately revoke or rotate this secret/key. Redact before committing or sharing."
    elif fcat == "Financial Information":
        action = "Redact all account and card numbers. Ensure PCI-DSS compliance."
    elif fcat == "Government Identifier":
        action = "Redact full identifier; preserve at most last 4 digits if required for audit."
    elif fcat == "Health Information":
        action = "Redact patient identifiers in accordance with HIPAA / health privacy guidelines."
    else:
        action = "Review context and redact if sharing outside authorized parties."

    reason = (
        f"This value matched the '{ftype}' pattern associated with "
        f"{fcat.lower()}."
    )
    if confidence_label == "Low":
        reason += " Confidence is low — this may be a false positive; manual review recommended."

    return {
        "type": ftype,
        "category": fcat,
        "reason": reason,
        "detection_method": source_label,
        "confidence": confidence_label,
        "confidence_pct": round(conf * 100),
        "severity": fsev,
        "recommended_action": action,
    }
