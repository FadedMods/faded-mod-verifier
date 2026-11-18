"""Local preflight for community Project Zomboid ZIPs."""
from contextlib import ExitStack
from pathlib import Path
import re
import shutil
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

from .package_safety import PackageSafetyError, digest_file, inspect_archives, reject_links

MAX_DELIVERY_BYTES = 2 * 1024**3
WORKSHOP_CONVERSION = "steam-workshop-v1"


def is_mod_info(parts):
    return parts[-1] == "mod.info" and (
        len(parts) == 1 or (
            len(parts) == 2 and (parts[0] == "common" or re.fullmatch(r"[0-9]+(?:\.[0-9]+)*", parts[0]))
        )
    )


def package_layout(records):
    """Return the installation folder, wrapper, and root/build metadata members."""
    layouts = {}
    for record in records:
        parts = record["name"].split("/")
        if len(parts) >= 2 and is_mod_info(parts[1:]):
            layouts.setdefault((parts[0], ""), []).append(record)
        for offset in (0, 1):
            if parts[offset:offset + 2] == ["Contents", "mods"] and len(parts) >= offset + 4:
                if is_mod_info(parts[offset + 3:]):
                    wrapper = "/".join(parts[:offset + 2]) + "/"
                    layouts.setdefault((parts[offset + 2], wrapper), []).append(record)
    if len(layouts) != 1:
        raise PackageSafetyError("ZIP must contain one mod folder with mod.info at its root or in a build folder.")
    (folder, wrapper), metadata = next(iter(layouts.items()))
    prefix = wrapper + folder + "/"
    workshop_root = wrapper.removesuffix("Contents/mods/")
    steam_metadata = {workshop_root + item for item in ("workshop.txt", "preview.png")} if wrapper else set()
    if any(not row["name"].startswith(prefix) and row["name"] not in steam_metadata for row in records):
        raise PackageSafetyError("ZIP contains files outside its single mod folder.")
    return folder, wrapper, metadata


def package_kind(records):
    has_java = any(row["name"].lower().endswith(".jar") for row in records)
    has_lua = any(row["name"].lower().endswith(".lua") for row in records)
    if has_java:
        return "hybrid" if has_lua else "fjl-java"
    return "lua-assets"


def verify_zip(path):
    records = inspect_archives([path], max_bytes=16 * 1024**3, max_entries=100000)
    folder, wrapper, metadata = package_layout(records)
    if any(row["name"].lower().endswith(".class") for row in records):
        raise PackageSafetyError("Place compiled Java classes in an FJL plugin JAR.")
    ids = set()
    with ZipFile(path) as archive:
        for row in metadata:
            if row["size"] > 65536:
                raise PackageSafetyError("mod.info exceeds the registry's metadata size limit.")
            for line in archive.read(row["name"]).decode("utf-8-sig").splitlines():
                key, separator, value = line.partition("=")
                if separator and key.strip().lower() == "id" and value.strip():
                    ids.add(value.strip())
        if not ids:
            raise PackageSafetyError("Add an internal id to mod.info.")
        damaged = archive.testzip()
        if damaged is not None:
            raise PackageSafetyError("ZIP contains a member with an invalid checksum.")
    return {
        "folder": folder, "wrapper": wrapper, "kind": package_kind(records),
        "mod_ids": sorted(ids), "entries": len(records), "sha256": digest_file(path),
    }


def export_workshop_zip(source: Path, output: Path, expected_sha256: str):
    reject_links(source)
    reject_links(output)
    if digest_file(source) != expected_sha256:
        raise PackageSafetyError("The original ZIP changed. Verify it again before exporting.")
    records = inspect_archives([source], max_bytes=16 * 1024**3, max_entries=100000)
    folder, wrapper, _ = package_layout(records)
    if not wrapper:
        raise PackageSafetyError("This ZIP already uses the installed-mod layout.")
    return write_workshop_zip(source, output, records, folder, wrapper)


def write_workshop_zip(source, output, records, folder, wrapper, *, min_free_bytes=0):
    """Write only the mod files from an already-inspected, stable ZIP."""
    reject_links(source)
    reject_links(output)
    prefix = wrapper + folder + "/"

    class BoundedOutput:
        def __init__(self, stream):
            self.stream = stream

        def __getattr__(self, name):
            return getattr(self.stream, name)

        def write(self, data):
            if self.stream.tell() + len(data) > MAX_DELIVERY_BYTES:
                raise PackageSafetyError("The converted ZIP exceeds the 2 GiB per-part limit.")
            if min_free_bytes and shutil.disk_usage(output.parent).free < min_free_bytes + len(data):
                raise OSError("Insufficient storage for the converted ZIP.")
            return self.stream.write(data)

    with ExitStack() as cleanup:
        with ZipFile(source) as archive, output.open("xb") as stream:
            cleanup.callback(output.unlink, missing_ok=True)
            with ZipFile(BoundedOutput(stream), "w", compression=ZIP_DEFLATED) as target:
                for row in records:
                    name = row["name"]
                    if not name.startswith(prefix):
                        continue
                    member = ZipInfo(name[len(wrapper):])
                    member.compress_type = archive.getinfo(name).compress_type
                    member.file_size = row["size"]
                    member.external_attr = 0o100644 << 16
                    written = 0
                    with archive.open(name) as payload, target.open(member, "w", force_zip64=row["size"] >= 2**31) as dest:
                        while chunk := payload.read(1024 * 1024):
                            written += len(chunk)
                            if written > row["size"]:
                                raise PackageSafetyError("A Workshop file exceeds its declared size.")
                            dest.write(chunk)
                    if written != row["size"]:
                        raise PackageSafetyError("A Workshop file has an incomplete payload.")
        cleanup.pop_all()
    return output
