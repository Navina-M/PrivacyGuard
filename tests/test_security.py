import pytest
import tempfile
from dlp.security import validate_and_build_path, check_size, UploadRejected, MAX_UPLOAD_BYTES


def test_rejects_unsupported_extension():
    with pytest.raises(UploadRejected):
        validate_and_build_path("malware.exe", tempfile.gettempdir())


def test_rejects_empty_filename():
    with pytest.raises(UploadRejected):
        validate_and_build_path("", tempfile.gettempdir())


def test_accepts_pdf_and_builds_safe_path():
    path = validate_and_build_path("report.pdf", tempfile.gettempdir())
    assert path.endswith(".pdf")
    assert tempfile.gettempdir() in path


def test_path_traversal_attempt_is_sanitized():
    path = validate_and_build_path("../../etc/passwd.pdf", tempfile.gettempdir())
    assert ".." not in path
    assert tempfile.gettempdir() in path


def test_oversized_file_rejected():
    big = b"0" * (MAX_UPLOAD_BYTES + 1)
    with pytest.raises(UploadRejected):
        check_size(big)


def test_normal_size_accepted():
    small = b"hello world"
    check_size(small)  # should not raise
