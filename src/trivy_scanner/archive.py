from __future__ import annotations

import tarfile
from collections.abc import Iterable
from pathlib import Path, PurePosixPath
from typing import BinaryIO

_CHUNK_SIZE = 1024 * 1024


class ArchiveValidationError(Exception):
    """Raised when an uploaded archive is invalid."""


def ensure_allowed_extension(filename: str, allowed_extensions: Iterable[str]) -> None:
    allowed = list(allowed_extensions)
    if not any(filename.endswith(ext) for ext in allowed):
        raise ArchiveValidationError(f"Unsupported archive type. Allowed extensions: {', '.join(allowed)}")


def safe_filename(filename: str) -> str:
    """Strip any directory components a client put in the upload filename."""
    name = PurePosixPath(filename.replace("\\", "/")).name
    if not name or name in {".", ".."}:
        raise ArchiveValidationError("Invalid archive filename")
    return name


def copy_with_limit(source: BinaryIO, destination: Path, limit_mb: int) -> None:
    """Stream an upload to disk, aborting as soon as it exceeds the size limit."""
    limit = limit_mb * 1024 * 1024
    written = 0
    with destination.open("wb") as buffer:
        while chunk := source.read(_CHUNK_SIZE):
            written += len(chunk)
            if written > limit:
                raise ArchiveValidationError(f"Archive exceeds size limit of {limit_mb} MB")
            buffer.write(chunk)


def safe_extract_tar(
    archive_path: Path,
    target_dir: Path,
    max_members: int = 10_000,
    max_extracted_mb: int = 1024,
) -> None:
    target_dir = target_dir.resolve()
    max_bytes = max_extracted_mb * 1024 * 1024
    try:
        with tarfile.open(archive_path, "r:gz") as tar:
            members = []
            total = 0
            for member in tar:
                members.append(member)
                if len(members) > max_members:
                    raise ArchiveValidationError(f"Archive contains too many files (>{max_members})")
                if member.issym() or member.islnk():
                    raise ArchiveValidationError(f"Archive contains a link: {member.name}")
                if not (member.isfile() or member.isdir()):
                    raise ArchiveValidationError(f"Archive contains a special file: {member.name}")
                if not (target_dir / member.name).resolve().is_relative_to(target_dir):
                    raise ArchiveValidationError(f"Archive contains unsafe path: {member.name}")
                total += member.size
                if total > max_bytes:
                    raise ArchiveValidationError(f"Archive expands beyond {max_extracted_mb} MB")
            if hasattr(tarfile, "data_filter"):
                tar.extractall(path=target_dir, members=members, filter="data")  # noqa: S202 - members validated above
            else:  # pragma: no cover - Python without PEP 706 backport
                tar.extractall(path=target_dir, members=members)  # noqa: S202 - members validated above
    except (tarfile.TarError, EOFError, OSError) as exc:
        raise ArchiveValidationError(f"Could not read archive: {exc}") from exc
