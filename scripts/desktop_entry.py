"""Entry point for the frozen desktop executable."""
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
from zipfile import ZipFile

from tkinterdnd2 import TkinterDnD

from faded_mod_verifier.desktop import VerifierWindow, main
from faded_mod_verifier.inspection import capture
from faded_mod_verifier.scanning import yara_scan
from faded_mod_verifier.verification import verify_mod


def smoke(report_path):
    """Exercise the frozen Tk/DnD runtime and scan a disposable package."""
    root = TkinterDnD.Tk()
    root.withdraw()
    try:
        app = VerifierWindow(root)
        assert root.tk.call("package", "provide", "tkdnd")
        with tempfile.TemporaryDirectory(prefix="faded-verifier-smoke-") as directory:
            location = Path(directory).resolve()
            archive = location / "Workshop fixture.zip"
            with ZipFile(archive, "w") as package:
                package.writestr("Contents/mods/Example/42/mod.info", "id=Example\n")
                package.writestr("Contents/mods/Example/42/media/lua/shared/example.lua", "local fixture = true\n")
            dropped = root.tk.call("list", str(archive))
            assert app.drop(SimpleNamespace(data=dropped)) == "copy"
            assert app.source == archive
            scanner = app.engine.scanner()
            if scanner:
                app.report, code = verify_mod(archive, clamscan=str(scanner.executable), database=scanner.database,
                                              environment=scanner.environment)
                app.show_report(code)
                assert code == 0, app.report
                result = app.report["scans"]
            else:
                snapshot = location / "scan"
                _, files = capture(archive, snapshot)
                result = {"clamav": {"status": "not-installed"},
                          "yara": yara_scan([(path, path.name) for path in files], None)}
                assert result["yara"]["status"] == "passed", result
        report_path.write_text(json.dumps({"desktop": "passed", "scans": result}), encoding="utf-8")
    finally:
        root.destroy()


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--desktop-smoke":
        try:
            smoke(Path(sys.argv[2]))
        except Exception as error:
            Path(sys.argv[2]).write_text(json.dumps({"desktop": "failed", "reason": str(error)}), encoding="utf-8")
            raise SystemExit(1) from error
    else:
        main()
