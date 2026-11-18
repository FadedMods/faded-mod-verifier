"""Portable archive and filesystem checks shared by new isolated install paths."""
from __future__ import annotations

import hashlib
import os
import re
import stat
import unicodedata
import zipfile
from pathlib import Path, PurePosixPath


class PackageSafetyError(ValueError):
    pass


def digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def reject_links(path: Path) -> None:
    for part in (path, *path.parents):
        if part.exists() or part.is_symlink():
            info = part.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                raise PackageSafetyError("Symbolic links and reparse points are not supported.")


def safe_name(name: str) -> str:
    if not isinstance(name, str) or not name or len(name) > 700 or "\\" in name or "\x00" in name:
        raise PackageSafetyError("Unsupported archive path.")
    name = name.removesuffix("/")
    parts = name.split("/")
    for part in parts:
        normalized = unicodedata.normalize("NFKC", part)
        if (not normalized or normalized in (".", "..") or normalized[-1] in " ." or
            any(ord(c) < 32 or c in ':<>"|?*/\\' for c in normalized) or
            re.fullmatch(r"(?i)(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?", normalized)):
            raise PackageSafetyError("Unsafe archive destination.")
    if PurePosixPath(name).is_absolute():
        raise PackageSafetyError("Absolute archive destination.")
    return name


def inspect_archives(paths: list[Path], *, max_bytes=4 * 1024**3,
                     max_entries=50000, max_ratio=250) -> list[dict]:
    """Inspect the combined plan before writing any member, preserving case."""
    destinations = {}
    directory_spellings = {}
    records, total, compressed = [], 0, 0
    for part, path in enumerate(paths):
        reject_links(path)
        try:
            with zipfile.ZipFile(path) as archive:
                for info in archive.infolist():
                    original = info.orig_filename
                    if info.filename != original:
                        raise PackageSafetyError("Truncated archive path.")
                    name = safe_name(original)
                    key = unicodedata.normalize("NFKC", name).casefold()
                    for parent in PurePosixPath(name).parents:
                        if str(parent) == ".":
                            continue
                        parent_name = parent.as_posix()
                        parent_key = unicodedata.normalize("NFKC", parent_name).casefold()
                        if parent_key in directory_spellings and directory_spellings[parent_key] != parent_name:
                            raise PackageSafetyError("Case-colliding implicit archive directory.")
                        directory_spellings[parent_key] = parent_name
                    mode = info.external_attr >> 16
                    kind = stat.S_IFMT(mode)
                    is_dir = info.is_dir()
                    if info.flag_bits & 1 or info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                        raise PackageSafetyError("Encrypted or unsupported archive member.")
                    if kind not in (0, stat.S_IFDIR if is_dir else stat.S_IFREG) or info.external_attr & 0x400:
                        raise PackageSafetyError("Archive links or special objects are not supported.")
                    if key in destinations:
                        prior = destinations[key]
                        if is_dir and prior[0] and prior[1] == name:
                            continue
                        raise PackageSafetyError("Duplicate or case-colliding archive destination.")
                    destinations[key] = (is_dir, name)
                    total += info.file_size
                    compressed += info.compress_size
                    if (len(destinations) > max_entries or total > max_bytes or
                        info.file_size > max_bytes or info.file_size > max(1024**2, info.compress_size * max_ratio)):
                        raise PackageSafetyError("Archive resource limit exceeded.")
                    if not is_dir:
                        records.append(dict(part=part, name=name, size=info.file_size, crc=info.CRC))
        except (zipfile.BadZipFile, NotImplementedError, RuntimeError) as exc:
            raise PackageSafetyError("Archive cannot be completely inspected.") from exc
    if not records or total > max(1024**2, compressed * max_ratio):
        raise PackageSafetyError("Empty archive or compression quota exceeded.")
    for key in destinations:
        for parent in PurePosixPath(key).parents:
            if str(parent) != "." and str(parent) in destinations and not destinations[str(parent)][0]:
                raise PackageSafetyError("Archive file conflicts with a parent directory.")
    return records


def extract_plan(paths: list[Path], destination: Path, records: list[dict]) -> None:
    reject_links(destination)
    destination.mkdir(parents=True, exist_ok=True)
    for part, path in enumerate(paths):
        with zipfile.ZipFile(path) as archive:
            for row in (r for r in records if r["part"] == part):
                target = destination / safe_name(row["name"])
                reject_links(target)
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(row["name"]) as source, target.open("xb") as output:
                    written = 0
                    while chunk := source.read(1024 * 1024):
                        written += len(chunk)
                        if written > row["size"]:
                            raise PackageSafetyError("Archive member exceeded its declared size.")
                        output.write(chunk)
                if written != row["size"]:
                    raise PackageSafetyError("Archive member was truncated.")


def safe_tree(root: Path, maximum=4 * 1024**3) -> int:
    reject_links(root)
    total, count = 0, 0
    if root.exists():
        for directory, folders, files in os.walk(root, followlinks=False):
            for name in [*folders, *files]:
                path = Path(directory) / name
                reject_links(path)
                if not path.is_dir() and not path.is_file():
                    raise PackageSafetyError("Unsupported filesystem object.")
                if path.is_file():
                    total += path.stat().st_size
                count += 1
                if total > maximum or count > 60000:
                    raise PackageSafetyError("Runtime maintenance limit exceeded.")
    return total
