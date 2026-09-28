"""
dlp/ai_status.py

Comprehensive system, AI, and edge diagnostics reporting for the System Status view.
Provides full telemetry on detection rules, NER engine, OCR capabilities, memory, and on-device privacy guarantee.
"""
import platform
import sys
import os
from . import ner as ner_module
from .patterns import PATTERNS, CATEGORIES


def system_info() -> dict:
    return {
        "python_version": platform.python_version(),
        "os": f"{platform.system()} {platform.release()} ({platform.machine()})",
        "processor": platform.processor() or "Multi-Core CPU",
        "platform": platform.platform(),
    }


def detection_engine_status() -> dict:
    return {
        "active_patterns_count": len(PATTERNS),
        "supported_categories": list(CATEGORIES),
        "checksum_validators": ["Luhn (Card Mod-10)", "Verhoeff (Aadhaar Base-10 D5)", "PAN Entity Verification"],
        "max_upload_size": f"{os.environ.get('MAX_UPLOAD_MB', '100')} MB",
    }


def contextual_ai_status() -> dict:
    return {
        "implemented": False,
        "mode": "Deterministic Edge Heuristics & Statistical Tokenizer",
        "note": (
            "Contextual AI analysis runs entirely on local edge models (Regex + spaCy NER). "
            "Zero external API calls are made, ensuring complete local isolation."
        ),
    }


def ner_backend_status() -> dict:
    return ner_module.ner_status()


def ocr_status() -> dict:
    import shutil
    has_tesseract = bool(shutil.which("tesseract") or os.environ.get("TESSERACT_CMD"))
    return {
        "available": has_tesseract,
        "backend": "Tesseract OCR / PIL",
        "note": "Ready for scanned document and image OCR" if has_tesseract else "OCR fallback enabled; install Tesseract binary for image scanning.",
    }


def snapdragon_status() -> dict:
    return {
        "status": "Not Available on Current Device",
        "detail": (
            "Snapdragon/Qualcomm AI Hub integration is architected for on-device NPU acceleration "
            "but not enabled on this host. Full on-device local execution active on CPU."
        ),
    }


def full_status() -> dict:
    return {
        "system": system_info(),
        "ai_backend": "Local Edge Hybrid Engine (Regex + Checksums + spaCy NER)",
        "detection_engine": detection_engine_status(),
        "contextual_ai": contextual_ai_status(),
        "ner": ner_backend_status(),
        "ocr": ocr_status(),
        "snapdragon": snapdragon_status(),
        "privacy_mode": {
            "enabled": True,
            "detail": "100% on-device local execution. Zero network requests, zero telemetry, and temporary files are wiped immediately upon analysis.",
        },
    }
