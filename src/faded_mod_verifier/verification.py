"""Shared verification pipeline for the CLI and desktop app."""
import os
from pathlib import Path
import tempfile
from zipfile import BadZipFile
from zlib import error as CompressionError

from .inspection import capture, compare, inventory, scan_targets
from .package_safety import PackageSafetyError
from .scanning import clamav, yara_scan

INSPECTION_ERRORS = (OSError, ValueError, RuntimeError, BadZipFile, CompressionError)


def absolute(path):
    return Path(os.path.abspath(path.expanduser()))


def verify_mod(source, *, reference=None, expected_sha256=None, inspect_only=False,
               include_inventory=False, clamscan="clamscan", database=None,
               environment=None, yara_rules=None, progress=lambda message: None):
    source = absolute(source)
    with tempfile.TemporaryDirectory(prefix="faded-mod-verifier-") as directory:
        workspace = Path(directory).resolve(strict=True)
        snapshot = workspace / "mod"
        progress("Reading and checking the mod…")
        digest, payload = capture(source, snapshot)
        layout, contents = inventory(snapshot, payload)
        integrity = {"status": "passed", "layout": layout, "sha256": digest, "files": len(payload)}
        hashes = {"status": "reference-required"}
        if expected_sha256:
            if digest is None:
                raise PackageSafetyError("Use a reference ZIP or folder for an installed mod.")
            hashes = {"status": "passed" if digest == expected_sha256 else "mismatch",
                      "expected_sha256": expected_sha256}
        comparison = {"status": "reference-required"}
        if reference:
            progress("Comparing the trusted reference…")
            baseline = workspace / "reference"
            _, reference_files = capture(absolute(reference), baseline)
            _, trusted = inventory(baseline, reference_files)
            comparison = compare(contents, trusted)
        scans = {"clamav": {"status": "skipped"}, "yara": {"status": "skipped"}}
        if not inspect_only:
            try:
                progress("Preparing files and nested archives for scanning…")
                targets = scan_targets(snapshot, payload, workspace / "nested")
            except INSPECTION_ERRORS as exc:
                scans = {engine: {"status": "incomplete", "reason": str(exc)} for engine in scans}
            else:
                progress("Scanning with ClamAV…")
                scans["clamav"] = clamav(targets, workspace, clamscan, database=database, environment=environment)
                progress("Scanning with YARA…")
                scans["yara"] = yara_scan(targets, yara_rules)
        report = {"integrity": integrity, "archive_hash": hashes, "file_comparison": comparison, "scans": scans}
        if include_inventory:
            report["inventory"] = contents
        statuses = {item["status"] for item in (hashes, comparison, *scans.values())}
        if statuses & {"mismatch", "flagged"}:
            return report, 1
        return report, 2 if "incomplete" in statuses else 0
