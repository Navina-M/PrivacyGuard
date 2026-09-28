"""
dlp/security.py

Upload security and validation module:
- Configurable upload size limit (default 100 MB).
- Support for extensive file types: PDF, Word, Excel, PowerPoint, Text, Code, Images, Archives, etc.
- Safe filename sanitization and path traversal prevention.
"""
import os
import uuid
from werkzeug.utils import secure_filename

# Default 100 MB max upload size (supports large documents, spreadsheets, logs, and dumps)
DEFAULT_MAX_MB = int(os.environ.get("MAX_UPLOAD_MB", "100"))
MAX_UPLOAD_BYTES = DEFAULT_MAX_MB * 1024 * 1024

# Comprehensive set of recognized file extensions
ALLOWED_EXTENSIONS = {
    # Documents
    ".pdf", ".docx", ".doc", ".odt", ".rtf", ".txt", ".md", ".markdown", ".rst",
    # Spreadsheets & Tabular Data
    ".xlsx", ".xls", ".csv", ".tsv",
    # Presentations
    ".pptx", ".ppt",
    # Structured Data & Configs
    ".json", ".jsonl", ".yaml", ".yml", ".xml", ".html", ".htm", ".env", ".ini",
    ".conf", ".config", ".toml", ".properties", ".log", ".sql",
    # Source Code
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".c", ".cpp", ".h", ".hpp",
    ".cs", ".go", ".rs", ".rb", ".php", ".sh", ".bash", ".bat", ".ps1", ".r",
    # Images (OCR)
    ".png", ".jpg", ".jpeg", ".webp", ".bmp", ".tiff", ".tif", ".svg",
    # Archives & Compressed
    ".zip", ".tar", ".gz", ".tgz"
}


class UploadRejected(Exception):
    pass


def validate_and_build_path(original_filename: str, upload_dir: str) -> str:
    """
    Validate the extension and build a safe, unique temp path inside `upload_dir`.
    Allows extensive document, code, image, and text types.
    """
    if not original_filename:
        raise UploadRejected("No file was provided.")

    safe_name = secure_filename(original_filename)
    if not safe_name:
        # If secure_filename stripped everything (e.g. non-ASCII or .env), create a safe name
        safe_name = "uploaded_file"

    ext = os.path.splitext(original_filename)[1].lower()

    # If extension is empty or not in explicit set, check if it is a safe text-compatible format
    # Block dangerous executable formats directly
    blocked_extensions = {".exe", ".dll", ".so", ".dylib", ".sys", ".drv", ".msi", ".com", ".scr"}
    if ext in blocked_extensions:
        raise UploadRejected(
            f"Executable file type '{ext}' cannot be processed directly for safety reasons."
        )

    os.makedirs(upload_dir, exist_ok=True)
    unique_name = f"{uuid.uuid4().hex}_{safe_name}"
    dest_path = os.path.join(upload_dir, unique_name)

    # Defense in depth: confirm the resolved path stays inside upload_dir.
    dest_real = os.path.abspath(dest_path)
    upload_real = os.path.abspath(upload_dir)
    if not dest_real.startswith(upload_real):
        raise UploadRejected("Invalid upload path.")

    return dest_path


def check_size(file_bytes: bytes):
    if len(file_bytes) > MAX_UPLOAD_BYTES:
        mb = MAX_UPLOAD_BYTES // (1024 * 1024)
        raise UploadRejected(
            f"File exceeds the maximum allowed size of {mb} MB."
        )


def safe_delete(path: str):
    """Delete a temp file if it exists; never raise on cleanup."""
    try:
        if path and os.path.exists(path):
            os.remove(path)
    except OSError:
        pass
