"""Bounded snapshots and comparable file inventories."""
import os
from pathlib import Path
import unicodedata
from zipfile import is_zipfile

from .community_package import is_mod_info, package_layout
from .package_safety import PackageSafetyError, digest_file, extract_plan, inspect_archives, reject_links, safe_name

MAX_EXPANDED = 16 * 1024**3
MAX_ENTRIES = 100_000
CHUNK = 1024**2


def _copy_directory(source: Path, destination: Path):
    def raise_walk_error(error):
        raise error

    total = 0
    names = set()
    for parent, directories, filenames in os.walk(source, followlinks=False, onerror=raise_walk_error):
        for name in sorted(directories + filenames):
            original = Path(parent) / name
            reject_links(original)
            relative = safe_name(original.relative_to(source).as_posix())
            comparable = unicodedata.normalize("NFKC", relative).casefold()
            if comparable in names or len(names) >= MAX_ENTRIES:
                raise PackageSafetyError("The folder has colliding names or exceeds the entry limit.")
            names.add(comparable)
            if original.is_dir():
                continue
            if not original.is_file():
                raise PackageSafetyError("A regular file or directory was expected.")
            before = original.stat()
            total += before.st_size
            if total > MAX_EXPANDED:
                raise PackageSafetyError("The folder exceeds the 16 GiB scan limit.")
            output = destination / relative
            output.parent.mkdir(parents=True, exist_ok=True)
            copied = 0
            with original.open("rb") as incoming, output.open("xb") as outgoing:
                while data := incoming.read(CHUNK):
                    copied += len(data)
                    if copied > before.st_size:
                        raise PackageSafetyError("A file changed during the snapshot.")
                    outgoing.write(data)
            after = original.stat()
            if copied != before.st_size or before.st_mtime_ns != after.st_mtime_ns or after.st_size != copied:
                raise PackageSafetyError("A file changed during the snapshot.")


def capture(source: Path, destination: Path):
    reject_links(source)
    if source.is_dir():
        destination.mkdir()
        _copy_directory(source, destination)
        archive_digest = None
    elif source.is_file() and is_zipfile(source):
        archive_digest = digest_file(source)
        records = inspect_archives([source], max_bytes=MAX_EXPANDED, max_entries=MAX_ENTRIES)
        extract_plan([source], destination, records)
        if digest_file(source) != archive_digest:
            raise PackageSafetyError("The ZIP changed while it was being inspected.")
    else:
        raise PackageSafetyError("Choose a readable ZIP archive or mod directory.")
    files = sorted(path for path in destination.rglob("*") if path.is_file())
    if not files:
        raise PackageSafetyError("The package has no files.")
    return archive_digest, files


def inventory(root: Path, files: list[Path]):
    names = [path.relative_to(root).as_posix() for path in files]
    prefix = ""
    layout = "generic"
    if any(is_mod_info(name.split("/")) for name in names):
        layout = "installed-mod"
    else:
        try:
            folder, wrapper, _ = package_layout([{"name": name} for name in names])
        except PackageSafetyError:
            pass
        else:
            layout = "steam-workshop" if wrapper else "installed-mod"
            prefix = wrapper + folder + "/"
    contents = {
        name[len(prefix):]: {"size": path.stat().st_size, "sha256": digest_file(path)}
        for name, path in zip(names, files) if name.startswith(prefix)
    }
    return layout, contents


def compare(actual, expected):
    missing = sorted(expected.keys() - actual.keys())
    extra = sorted(actual.keys() - expected.keys())
    changed = sorted(name for name in actual.keys() & expected.keys() if actual[name] != expected[name])
    return {"status": "mismatch" if missing or extra or changed else "passed",
            "missing": missing, "extra": extra, "changed": changed}


def scan_targets(root: Path, files: list[Path], nested: Path):
    """Scan each ZIP/JAR member in addition to the containing file."""
    targets = []
    expanded = 0

    def add(path, label, depth):
        nonlocal expanded
        targets.append((path, label))
        if len(targets) > MAX_ENTRIES:
            raise PackageSafetyError("Nested scan coverage exceeds the entry limit.")
        with path.open("rb") as stream:
            magic = stream.read(4)
        if path.suffix.lower() not in (".zip", ".jar") and magic not in (b"PK\x03\x04", b"PK\x05\x06"):
            return
        if depth >= 3:
            raise PackageSafetyError("Nested ZIP/JAR coverage exceeds three levels.")
        records = inspect_archives([path], max_bytes=MAX_EXPANDED - expanded,
                                   max_entries=MAX_ENTRIES - len(targets))
        expanded += sum(record["size"] for record in records)
        unpacked = nested / str(len(targets))
        extract_plan([path], unpacked, records)
        for record in records:
            add(unpacked / record["name"], label + "!" + record["name"], depth + 1)

    for path in files:
        add(path, path.relative_to(root).as_posix(), 0)
    return targets
