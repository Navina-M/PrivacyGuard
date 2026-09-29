"""
dlp/extractor.py

Universal text extraction engine supporting:
- Documents: PDF (.pdf), Word (.docx), OpenDocument (.odt), Rich Text (.rtf)
- Spreadsheets: Excel (.xlsx, .xls), CSV (.csv), TSV (.tsv)
- Presentations: PowerPoint (.pptx)
- Structured Data & Configs: JSON, YAML, XML, HTML, LOG, ENV, SQL, INI, TOML
- Source Code: Python, JS, TS, Java, C/C++, C#, Go, Rust, Ruby, PHP, Shell
- Images: OCR (.png, .jpg, .jpeg, .webp, .bmp, .tiff) via pytesseract
- Archives: ZIP (.zip), TAR (.tar, .gz) extracts internal text files
- Universal fallback for any binary/text file (multi-encoding detection & string extraction)
"""
from typing import Dict, Any, Optional
import os
import io
import re
import zipfile
import tarfile

SUPPORTED_EXTENSIONS = {
    # Documents
    ".pdf", ".docx", ".doc", ".odt", ".rtf", ".txt", ".md", ".markdown", ".rst",
    # Tabular
    ".xlsx", ".xls", ".csv", ".tsv",
    # Presentations
    ".pptx",
    # Data & Code
    ".json", ".jsonl", ".yaml", ".yml", ".xml", ".html", ".htm", ".env", ".ini",
    ".conf", ".config", ".toml", ".properties", ".log", ".sql",
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".c", ".cpp", ".h", ".hpp",
    ".cs", ".go", ".rs", ".rb", ".php", ".sh", ".bash", ".bat", ".ps1", ".r",
    # Images
    ".png", ".jpg", ".jpeg", ".webp", ".bmp", ".tiff", ".tif", ".svg",
    # Archives
    ".zip", ".tar", ".gz", ".tgz"
}


def _result(
    text: str,
    source_type: str,
    ocr_used: bool = False,
    ocr_confidence: Optional[float] = None,
    pages: Optional[int] = None,
    note: Optional[str] = None,
    meta: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    text = text or ""
    words = len(text.split()) if text else 0
    lines = text.count("\n") + 1 if text else 0
    chars = len(text)

    return {
        "text": text,
        "source_type": source_type,
        "ocr_used": ocr_used,
        "ocr_confidence": ocr_confidence,
        "pages": pages,
        "note": note,
        "char_count": chars,
        "word_count": words,
        "line_count": lines,
        "metadata": meta or {},
    }


def extract_plain_text(path: str, ext: str) -> Dict[str, Any]:
    """Extract text from plain text, code, json, yaml, sql, log, or config files with full Unicode and symbol preservation."""
    encodings = ["utf-8", "utf-8-sig", "utf-16", "utf-16-le", "utf-16-be", "latin-1", "cp1252", "iso-8859-1"]
    content = None
    used_encoding = "utf-8"

    for enc in encodings:
        try:
            with open(path, "r", encoding=enc) as f:
                content = f.read()
                used_encoding = enc
                break
        except (UnicodeDecodeError, UnicodeError):
            continue

    if content is None:
        # Fallback to binary string extraction with Unicode preservation
        with open(path, "rb") as f:
            raw = f.read()
        try:
            content = raw.decode("utf-8", errors="replace")
        except Exception:
            content = raw.decode("latin-1", errors="ignore")
        # Remove nulls and unprintable control chars while strictly preserving all unicode symbols and emojis
        content = "".join(ch for ch in content if ch in ("\n", "\r", "\t") or (ord(ch) >= 32 and ord(ch) != 127))

    return _result(
        content,
        source_type=ext.lstrip(".") or "text",
        note=f"Decoded using {used_encoding}" if used_encoding != "utf-8" else None
    )


def extract_pdf_text(path: str) -> Dict[str, Any]:
    """Extract text from a PDF using pypdf, with OCR fallback guidance if scanned."""
    try:
        from pypdf import PdfReader
    except ModuleNotFoundError:
        return _result("", "pdf", note="pypdf is not installed in the environment.")

    try:
        reader = PdfReader(path)
        pages_text = []
        for i, page in enumerate(reader.pages):
            page_content = page.extract_text() or ""
            if page_content.strip():
                pages_text.append(f"--- Page {i + 1} ---\n{page_content}")
            else:
                pages_text.append(f"--- Page {i + 1} (No text extracted) ---")

        text = "\n\n".join(pages_text)

        if len(text.strip()) < 40 and len(reader.pages) > 0:
            return _result(
                text, "pdf", pages=len(reader.pages),
                note="Little or no direct extractable text found in this PDF — it may contain scanned images."
            )

        return _result(text, "pdf", pages=len(reader.pages))
    except Exception as e:
        return _result("", "pdf", note=f"PDF parsing encountered an issue: {e}")


def extract_docx_text(path: str) -> Dict[str, Any]:
    """Extract text from DOCX paragraphs, tables, headers, and footers."""
    try:
        from docx import Document
    except ModuleNotFoundError:
        return _result("", "docx", note="python-docx is not installed.")

    try:
        doc = Document(path)
        parts = []

        # Paragraphs
        for p in doc.paragraphs:
            if p.text.strip():
                parts.append(p.text)

        # Tables
        for table_idx, table in enumerate(doc.tables):
            table_lines = [f"\n--- Table {table_idx + 1} ---"]
            for row in table.rows:
                row_cells = [cell.text.strip().replace("\n", " ") for cell in row.cells]
                table_lines.append(" | ".join(row_cells))
            parts.append("\n".join(table_lines))

        # Headers & Footers
        for section in doc.sections:
            if section.header and section.header.paragraphs:
                for hp in section.header.paragraphs:
                    if hp.text.strip():
                        parts.append(f"[Header] {hp.text}")
            if section.footer and section.footer.paragraphs:
                for fp in section.footer.paragraphs:
                    if fp.text.strip():
                        parts.append(f"[Footer] {fp.text}")

        text = "\n\n".join(parts)
        return _result(text, "docx")
    except Exception as e:
        return _result("", "docx", note=f"DOCX extraction error: {e}")


def extract_spreadsheet_text(path: str, ext: str) -> Dict[str, Any]:
    """Extract tabular data from CSV, TSV, or Excel (.xlsx/.xls) files."""
    if ext in (".csv", ".tsv"):
        delimiter = "\t" if ext == ".tsv" else ","
        try:
            import csv
            lines = []
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                reader = csv.reader(f, delimiter=delimiter)
                for row_idx, row in enumerate(reader):
                    lines.append(" | ".join(row))
                    if row_idx > 20000:  # Cap display at 20,000 rows for memory safety
                        lines.append("... [Additional rows truncated for performance]")
                        break
            return _result("\n".join(lines), source_type=ext.lstrip("."))
        except Exception as e:
            return extract_plain_text(path, ext)

    # Excel spreadsheet (.xlsx, .xls)
    try:
        import zipfile
        import xml.etree.ElementTree as ET

        # Fast direct XML parse of xlsx without heavy external dependencies
        text_parts = []
        with zipfile.ZipFile(path, 'r') as z:
            # Read shared strings
            shared_strings = []
            if 'xl/sharedStrings.xml' in z.namelist():
                tree = ET.fromstring(z.read('xl/sharedStrings.xml'))
                for elem in tree.iter():
                    if elem.tag.endswith('t') and elem.text:
                        shared_strings.append(elem.text)

            # Read worksheets
            sheet_files = [n for n in z.namelist() if n.startswith('xl/worksheets/sheet') and n.endswith('.xml')]
            for s_idx, sheet_name in enumerate(sheet_files):
                text_parts.append(f"--- Sheet {s_idx + 1} ---")
                tree = ET.fromstring(z.read(sheet_name))
                for row in tree.iter():
                    if row.tag.endswith('row'):
                        row_vals = []
                        for cell in row.iter():
                            if cell.tag.endswith('c'):
                                val_elem = cell.find('{*}v')
                                cell_type = cell.get('t')
                                if val_elem is not None and val_elem.text:
                                    if cell_type == 's' and int(val_elem.text) < len(shared_strings):
                                        row_vals.append(shared_strings[int(val_elem.text)])
                                    else:
                                        row_vals.append(val_elem.text)
                        if row_vals:
                            text_parts.append(" | ".join(row_vals))

        if text_parts:
            return _result("\n".join(text_parts), "xlsx")
    except Exception:
        pass

    # Fallback to universal text extraction
    return extract_plain_text(path, ext)


def extract_pptx_text(path: str) -> Dict[str, Any]:
    """Extract text from PowerPoint presentations (.pptx)."""
    try:
        import zipfile
        import xml.etree.ElementTree as ET

        slide_texts = []
        with zipfile.ZipFile(path, 'r') as z:
            slide_files = sorted(
                [n for n in z.namelist() if n.startswith('ppt/slides/slide') and n.endswith('.xml')],
                key=lambda x: int(re.search(r'\d+', x).group(0)) if re.search(r'\d+', x) else 0
            )
            for idx, sfile in enumerate(slide_files):
                tree = ET.fromstring(z.read(sfile))
                texts = []
                for elem in tree.iter():
                    if elem.tag.endswith('t') and elem.text:
                        texts.append(elem.text)
                if texts:
                    slide_texts.append(f"--- Slide {idx + 1} ---\n" + "\n".join(texts))

        if slide_texts:
            return _result("\n\n".join(slide_texts), "pptx", pages=len(slide_texts))
    except Exception as e:
        return _result("", "pptx", note=f"PPTX extraction error: {e}")

    return _result("", "pptx", note="No text found in PPTX slides.")


def extract_archive_text(path: str, ext: str) -> Dict[str, Any]:
    """Extract and scan text from inside compressed archives (.zip, .tar, .gz)."""
    parts = []
    file_count = 0

    try:
        if ext == ".zip":
            with zipfile.ZipFile(path, 'r') as z:
                for file_info in z.infolist():
                    if file_info.is_dir():
                        continue
                    fname = file_info.filename
                    fext = os.path.splitext(fname)[1].lower()
                    if file_info.file_size < 5 * 1024 * 1024:  # limit 5MB per inner file
                        try:
                            content = z.read(file_info.filename).decode('utf-8', errors='ignore')
                            if content.strip():
                                parts.append(f"=== File: {fname} ===\n{content}")
                                file_count += 1
                        except Exception:
                            continue
        elif ext in (".tar", ".gz", ".tgz"):
            with tarfile.open(path, 'r:*') as t:
                for member in t.getmembers():
                    if member.isfile() and member.size < 5 * 1024 * 1024:
                        try:
                            f = t.extractfile(member)
                            if f:
                                content = f.read().decode('utf-8', errors='ignore')
                                if content.strip():
                                    parts.append(f"=== File: {member.name} ===\n{content}")
                                    file_count += 1
                        except Exception:
                            continue

        text = "\n\n".join(parts)
        return _result(
            text,
            source_type=ext.lstrip("."),
            note=f"Scanned {file_count} inner file(s) from archive." if file_count > 0 else "No readable text files inside archive."
        )
    except Exception as e:
        return _result("", ext.lstrip("."), note=f"Archive extraction failed: {e}")


def _configure_tesseract(pytesseract):
    """Ensure pytesseract locates the OCR binary across standard platform paths."""
    env_path = os.environ.get("TESSERACT_CMD")
    if env_path and os.path.exists(env_path):
        pytesseract.pytesseract.tesseract_cmd = env_path
        return

    import shutil
    current_cmd = getattr(pytesseract.pytesseract, "tesseract_cmd", "tesseract")
    if not shutil.which(current_cmd):
        candidate_paths = [
            r"C:\Program Files\Tesseract-OCR\tesseract.exe",
            r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe",
            os.path.expanduser(r"~\AppData\Local\Tesseract-OCR\tesseract.exe"),
            os.path.expanduser(r"~\AppData\Local\Programs\Tesseract-OCR\tesseract.exe"),
            "/usr/bin/tesseract",
            "/usr/local/bin/tesseract",
            "/opt/homebrew/bin/tesseract"
        ]
        for candidate in candidate_paths:
            if os.path.exists(candidate):
                pytesseract.pytesseract.tesseract_cmd = candidate
                break


def _preprocess_image_for_ocr(img):
    """
    Optimize image clarity, contrast, and resolution for superior OCR accuracy.
    Enables accurate detection of small icons, symbols, and fine print.
    """
    try:
        from PIL import Image, ImageEnhance, ImageOps

        # Handle alpha channels / transparency
        if img.mode in ("RGBA", "LA", "P"):
            bg = Image.new("RGB", img.size, (255, 255, 255))
            if img.mode == "P":
                img = img.convert("RGBA")
            bg.paste(img, mask=img.split()[-1] if img.mode in ("RGBA", "LA") else None)
            img = bg
        elif img.mode != "RGB":
            img = img.convert("RGB")

        # Upscale if image is low resolution (< 1200px)
        w, h = img.size
        if w < 1200 or h < 1200:
            scale = min(3.0, max(1.5, 1800.0 / max(w, h, 1)))
            new_w, new_h = int(w * scale), int(h * scale)
            resample_filter = getattr(Image, "Resampling", Image).LANCZOS if hasattr(getattr(Image, "Resampling", Image), "LANCZOS") else Image.BICUBIC
            img = img.resize((new_w, new_h), resample=resample_filter)

        # Grayscale conversion
        gray = ImageOps.grayscale(img)

        # Contrast and sharpness boost
        enhancer = ImageEnhance.Contrast(gray)
        enhanced = enhancer.enhance(1.8)
        sharpener = ImageEnhance.Sharpness(enhanced)
        return sharpener.enhance(1.4)
    except Exception:
        return img


def extract_image_text(path: str) -> Dict[str, Any]:
    """
    Advanced OCR engine with multi-pass image preprocessing,
    symbol preservation, and high-fidelity text recognition.
    """
    try:
        import pytesseract
        from PIL import Image
    except ModuleNotFoundError:
        return _result(
            "", "image", ocr_used=False,
            note="OCR backend (pytesseract/Pillow) is not installed in this environment."
        )

    try:
        _configure_tesseract(pytesseract)
        orig_img = Image.open(path)

        # 1. First pass: Preprocessed high-contrast image with standard layout analysis
        processed_img = _preprocess_image_for_ocr(orig_img)
        custom_config = r"--oem 3 --psm 3 -c preserve_interword_spaces=1"
        text = pytesseract.image_to_string(processed_img, config=custom_config)

        # 2. If first pass extracted little or no text, fallback to sparse text PSM 6 or original image
        if len(text.strip()) < 10:
            try:
                fallback_config = r"--oem 3 --psm 6 -c preserve_interword_spaces=1"
                text_fallback = pytesseract.image_to_string(orig_img, config=fallback_config)
                if len(text_fallback.strip()) > len(text.strip()):
                    text = text_fallback
            except Exception:
                pass

        return _result(text, "image", ocr_used=True)
    except Exception as e:
        return _result("", "image", ocr_used=False, note=f"OCR processing note: {e}")



def extract_text(path: str) -> Dict[str, Any]:
    """
    Dispatch to the appropriate extractor based on file extension.
    Gracefully handles all documents, spreadsheets, images, code, and generic files.
    """
    ext = os.path.splitext(path)[1].lower()

    # Blocked or dangerous extensions
    if ext in (".exe", ".dll", ".so", ".dylib", ".sys", ".drv", ".msi", ".com", ".scr"):
        return _result("", "unknown", note=f"Unsupported file type: {ext}")

    try:
        if ext == ".pdf":
            return extract_pdf_text(path)
        if ext == ".docx":
            return extract_docx_text(path)
        if ext in (".xlsx", ".xls", ".csv", ".tsv"):
            return extract_spreadsheet_text(path, ext)
        if ext == ".pptx":
            return extract_pptx_text(path)
        if ext in (".png", ".jpg", ".jpeg", ".webp", ".bmp", ".tiff", ".tif", ".svg"):
            return extract_image_text(path)
        if ext in (".zip", ".tar", ".gz", ".tgz"):
            return extract_archive_text(path, ext)
        # Plain text, code, config files, or unknown extensions
        return extract_plain_text(path, ext)

    except Exception as e:
        return _result("", ext.lstrip(".") or "unknown", note=f"Extraction failed: {e}")
