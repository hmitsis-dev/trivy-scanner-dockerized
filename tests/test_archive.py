import io
import tarfile

import pytest
from conftest import build_archive

from trivy_scanner.archive import ArchiveValidationError, safe_extract_tar, safe_filename


def _write(tmp_path, data: bytes):
    path = tmp_path / "a.tar.gz"
    path.write_bytes(data)
    return path


def _archive_with(member: tarfile.TarInfo) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        tar.addfile(member, io.BytesIO(b"x" * member.size) if member.isfile() else None)
    return buffer.getvalue()


def test_extracts_regular_files(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    safe_extract_tar(_write(tmp_path, build_archive()), out)
    assert (out / "project" / "app.py").read_text().startswith("print")


def test_rejects_path_traversal(tmp_path):
    with pytest.raises(ArchiveValidationError, match="unsafe path"):
        safe_extract_tar(_write(tmp_path, build_archive({"../escape.txt": b"x"})), tmp_path / "out")


@pytest.mark.parametrize("kind", [tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE, tarfile.CHRTYPE])
def test_rejects_links_and_special_files(tmp_path, kind):
    member = tarfile.TarInfo("thing")
    member.type = kind
    member.linkname = "/etc/passwd"
    with pytest.raises(ArchiveValidationError):
        safe_extract_tar(_write(tmp_path, _archive_with(member)), tmp_path / "out")


def test_rejects_too_many_members(tmp_path):
    files = {f"f{i}": b"" for i in range(5)}
    with pytest.raises(ArchiveValidationError, match="too many"):
        safe_extract_tar(_write(tmp_path, build_archive(files)), tmp_path / "out", max_members=3)


def test_rejects_decompression_bomb(tmp_path):
    archive = build_archive({"zeros": b"\0" * (2 * 1024 * 1024)})
    with pytest.raises(ArchiveValidationError, match="expands beyond"):
        safe_extract_tar(_write(tmp_path, archive), tmp_path / "out", max_extracted_mb=1)


def test_rejects_garbage(tmp_path):
    with pytest.raises(ArchiveValidationError):
        safe_extract_tar(_write(tmp_path, b"not a tarball"), tmp_path / "out")


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("project.tar.gz", "project.tar.gz"),
        ("../../x.tgz", "x.tgz"),
        ("/abs/y.tar.gz", "y.tar.gz"),
        ("..\\z.tgz", "z.tgz"),
    ],
)
def test_safe_filename(raw, expected):
    assert safe_filename(raw) == expected


@pytest.mark.parametrize("raw", ["", "..", "/"])
def test_safe_filename_rejects_empty(raw):
    with pytest.raises(ArchiveValidationError):
        safe_filename(raw)
