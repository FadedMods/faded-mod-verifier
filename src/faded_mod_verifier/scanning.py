"""Run local malware scanners on the exact snapshot files."""
from importlib.resources import files
import os
from pathlib import Path
import shutil
import subprocess


def _result(status, **details):
    return {"status": status, **details}


def clamav(targets, directory, executable):
    engine = shutil.which(executable)
    if not engine:
        return _result("incomplete", reason="ClamAV clamscan was not found.")
    if any(path.stat().st_size > 256 * 1024**2 for path, _ in targets):
        return _result("incomplete", reason="A file exceeds ClamAV's 256 MiB coverage limit.")

    # Empty files have no content. ClamAV may report them with a separate
    # status, so count them separately from files requiring scan coverage.
    expected = {os.path.normcase(str(path)): label for path, label in targets if path.stat().st_size}
    if not expected:
        return _result("passed", scanned=0, empty_files=len(targets))
    listing = directory / "clamav-inputs.txt"
    listing.write_text("\n".join(str(path) for path, _ in targets if path.stat().st_size) + "\n", encoding="utf-8")
    try:
        scan = subprocess.run([
            engine, "--stdout", "--no-summary", "--scan-archive=yes",
            "--alert-encrypted=yes", "--alert-exceeds-max=yes", "--max-filesize=256M",
            "--max-scansize=512M", "--max-recursion=8", "--max-files=50000",
            "--file-list=" + str(listing),
        ], capture_output=True, encoding="utf-8", errors="replace", timeout=1200, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return _result("incomplete", reason=str(exc))
    findings = []
    ok = set()
    incomplete = scan.returncode not in (0, 1) or bool(scan.stderr.strip())
    for line in scan.stdout.splitlines():
        name, separator, result = line.rpartition(": ")
        if not separator:
            continue
        key = os.path.normcase(name)
        if key not in expected:
            if result.endswith(" FOUND") or result.endswith(" ERROR"):
                incomplete = True
            continue
        if result == "OK":
            ok.add(key)
        elif result.endswith(" FOUND") and not result.startswith(("Heuristics.Limits.", "Heuristics.Encrypted.")):
            findings.append({"file": expected[key], "signature": result.removesuffix(" FOUND")})
        else:
            incomplete = True
    if findings:
        return _result("flagged", findings=findings)
    if incomplete or scan.returncode or ok != expected.keys():
        return _result("incomplete", scanned=len(ok), expected=len(expected),
                       reason="ClamAV did not report completed coverage. Check its signatures and configuration.")
    return _result("passed", scanned=len(ok), empty_files=len(targets)-len(expected))


def yara_scan(targets, custom_rules: Path | None):
    try:
        import yara
    except ImportError:
        return _result("incomplete", reason="Install the verifier's scan extra to enable YARA.")
    try:
        source = {"baseline": files(__package__).joinpath("baseline.yar").read_text(encoding="utf-8")}
        if custom_rules:
            if custom_rules.stat().st_size > 1024**2:
                return _result("incomplete", reason="Custom rules exceed 1 MiB.")
            source["custom"] = custom_rules.read_text(encoding="utf-8")
        rules = yara.compile(sources=source, includes=False, externals={"lua_file": False})
        findings = []
        for path, label in targets:
            if path.stat().st_size > 256 * 1024**2:
                return _result("incomplete", reason="A file exceeds YARA's 256 MiB coverage limit.")
            for match in rules.match(str(path), timeout=15, externals={"lua_file": path.suffix.lower() == ".lua"}):
                findings.append({"file": label, "rule": match.namespace + ":" + match.rule})
    except (OSError, ValueError, yara.Error) as exc:
        return _result("incomplete", reason=str(exc))
    return _result("flagged" if findings else "passed", scanned=len(targets), findings=findings)
