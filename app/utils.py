import os
import tarfile
from pathlib import Path
from typing import Iterable


class ArchiveValidationError(Exception):
    """Raised when an uploaded archive is invalid."""


def ensure_allowed_extension(filename: str, allowed_extensions: Iterable[str]) -> None:
    if not any(filename.endswith(ext) for ext in allowed_extensions):
        allowed = ", ".join(allowed_extensions)
        raise ArchiveValidationError(f"Unsupported archive type. Allowed extensions: {allowed}")


def safe_extract_tar(archive_path: Path, target_dir: Path, max_members: int = 10_000) -> None:
    with tarfile.open(archive_path, "r:gz") as tar:
        members = tar.getmembers()
        if len(members) > max_members:
            raise ArchiveValidationError(f"Archive contains too many files (>{max_members})")
        for member in members:
            member_path = target_dir / member.name
            if not _is_within_directory(target_dir, member_path):
                raise ArchiveValidationError(f"Archive contains unsafe path: {member.name}")
            if member.issym() or member.islnk():
                raise ArchiveValidationError(f"Archive contains symbolic link: {member.name}")
        tar.extractall(path=target_dir)


def _is_within_directory(directory: Path, target: Path) -> bool:
    directory = directory.resolve()
    target = target.resolve()
    return os.path.commonpath([directory]) == os.path.commonpath([directory, target])


def ensure_file_size_within_limit(file_path: Path, limit_mb: int) -> None:
    size_mb = file_path.stat().st_size / (1024 * 1024)
    if size_mb > limit_mb:
        raise ArchiveValidationError(f"Archive exceeds size limit of {limit_mb} MB (actual: {size_mb:.2f} MB)")
