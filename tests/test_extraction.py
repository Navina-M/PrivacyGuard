import os
import tempfile
from dlp import extractor


def test_unsupported_extension_returns_note():
    result = extractor.extract_text("somefile.exe")
    assert result["text"] == ""
    assert "Unsupported" in result["note"]


def test_docx_extraction(tmp_path=None):
    from docx import Document
    doc = Document()
    doc.add_paragraph("This is a test paragraph with sample content.")
    path = os.path.join(tempfile.gettempdir(), "pg_test.docx")
    doc.save(path)

    result = extractor.extract_docx_text(path)
    assert "test paragraph" in result["text"]
    assert result["source_type"] == "docx"
    os.remove(path)


def test_pdf_extraction_handles_missing_file_gracefully():
    result = extractor.extract_text("/nonexistent/path/file.pdf")
    assert result["text"] == ""
    assert result["note"] is not None


def test_image_extraction():
    from PIL import Image, ImageDraw
    img = Image.new("RGB", (200, 60), color=(255, 255, 255))
    d = ImageDraw.Draw(img)
    d.text((10, 10), "SECRET_KEY_123", fill=(0, 0, 0))
    path = os.path.join(tempfile.gettempdir(), "pg_test_ocr.png")
    img.save(path)

    result = extractor.extract_image_text(path)
    assert result["source_type"] == "image"
    if result["ocr_used"]:
        assert "SECRET" in result["text"]
    os.remove(path)

