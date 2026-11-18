"""Command-line interface for local mod verification and Workshop ZIP preparation."""
import argparse
import json
import os
from pathlib import Path
import re
import tempfile
from zipfile import BadZipFile
from zlib import error as CompressionError

from .community_package import export_workshop_zip, verify_zip
from .inspection import capture, compare, inventory, scan_targets
from .package_safety import PackageSafetyError
from .scanning import clamav, yara_scan


def absolute(path):
    return Path(os.path.abspath(path.expanduser()))


def expected_sha256(value):
    if not re.fullmatch(r"[a-fA-F0-9]{64}", value):
        raise argparse.ArgumentTypeError("Enter a 64-character SHA-256 digest.")
    return value.lower()


def verify(arguments):
    source = absolute(arguments.source)
    with tempfile.TemporaryDirectory(prefix="faded-mod-verifier-") as directory:
        workspace = Path(directory).resolve(strict=True)
        snapshot = workspace / "mod"
        digest, payload = capture(source, snapshot)
        layout, contents = inventory(snapshot, payload)
        trusted = None
        if arguments.compare:
            baseline = workspace / "reference"
            _, reference = capture(absolute(arguments.compare), baseline)
            _, trusted = inventory(baseline, reference)
        integrity = {"status": "passed", "layout": layout, "sha256": digest, "files": len(payload)}
        hashes = {"status": "reference-required"}
        if arguments.expected_sha256:
            if digest is None:
                raise PackageSafetyError("Use --compare to verify an installed folder against a reference.")
            hashes = {"status": "passed" if digest == arguments.expected_sha256 else "mismatch",
                      "expected_sha256": arguments.expected_sha256}
        comparison = compare(contents, trusted) if trusted is not None else {"status": "reference-required"}
        scans = {"clamav": {"status": "skipped"}, "yara": {"status": "skipped"}}
        if not arguments.inspect_only:
            try:
                targets = scan_targets(snapshot, payload, workspace / "nested")
            except (OSError, ValueError, RuntimeError, BadZipFile, CompressionError) as exc:
                scans = {engine: {"status": "incomplete", "reason": str(exc)} for engine in scans}
            else:
                scans["clamav"] = clamav(targets, workspace, arguments.clamscan)
                scans["yara"] = yara_scan(targets, arguments.yara_rules)
        report = {"integrity": integrity, "archive_hash": hashes, "file_comparison": comparison, "scans": scans}
        if arguments.inventory:
            report["inventory"] = contents
        statuses = {item["status"] for item in (hashes, comparison, *scans.values())}
        if statuses & {"mismatch", "flagged"}:
            return report, 1
        return report, 2 if "incomplete" in statuses else 0


def main(argv=None):
    parser = argparse.ArgumentParser(prog="faded-mod-verifier", description="Verify local mod ZIPs and folders.")
    parser.add_argument("--version", action="version", version="%(prog)s 0.1.0")
    commands = parser.add_subparsers(dest="command", required=True)
    check = commands.add_parser("verify", help="Check local integrity, malware signatures and optional fidelity.")
    check.add_argument("source", type=Path, help="A ZIP-format download or installed mod folder.")
    check.add_argument("--expected-sha256", type=expected_sha256, help="Compare the ZIP with a trusted SHA-256.")
    check.add_argument("--compare", type=Path, help="Compare the files with a trusted ZIP or mod folder.")
    check.add_argument("--clamscan", default="clamscan", help="ClamAV command or local executable path.")
    check.add_argument("--yara-rules", type=Path, help="Add a locally trusted YARA rule file.")
    check.add_argument("--inspect-only", action="store_true", help="Check structure and fidelity without malware scanning.")
    check.add_argument("--inventory", action="store_true", help="Include file hashes and sizes in the report.")
    check.add_argument("--json", action="store_true", help="Print a JSON report.")
    prepare = commands.add_parser("prepare", help="Convert a single-mod PZ Workshop ZIP to the installer layout.")
    prepare.add_argument("source", type=Path)
    prepare.add_argument("output", type=Path)
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "prepare":
            source = absolute(arguments.source)
            output = absolute(arguments.output)
            report = verify_zip(source)
            export_workshop_zip(source, output, report["sha256"])
            print(f"Prepared {output}")
            print(f"SHA-256  {verify_zip(output)['sha256']}")
            return 0
        report, code = verify(arguments)
    except (OSError, ValueError, RuntimeError, BadZipFile, CompressionError) as exc:
        report, code = {"integrity": {"status": "incomplete", "reason": str(exc)}}, 2
    if getattr(arguments, "json", False):
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        for label, item in report.items():
            if label in ("inventory", "scans"):
                continue
            print(f"{label.replace('_', ' ').capitalize():16} {item['status']}")
            for name, value in item.items():
                if name != "status" and value:
                    print(f"  {name}  {json.dumps(value, ensure_ascii=True)}")
        for engine, item in report.get("scans", {}).items():
            print(f"{engine.upper():16} {item['status']}")
            if item.get("reason"):
                print("  " + item["reason"])
            for finding in item.get("findings", []):
                print("  " + json.dumps(finding, ensure_ascii=True))
        if getattr(arguments, "inventory", False) and "inventory" in report:
            print(json.dumps(report["inventory"], indent=2, sort_keys=True))
    return code
