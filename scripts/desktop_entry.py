"""Entry point for the frozen desktop executable."""
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
from zipfile import ZipFile

from tkinterdnd2 import TkinterDnD

from faded_mod_verifier.desktop import VerifierWindow, main
from faded_mod_verifier.desktop_clamav import DesktopClamAV
from faded_mod_verifier.inspection import capture
from faded_mod_verifier.scanning import yara_scan
from faded_mod_verifier.verification import verify_mod


def smoke(report_path, engine_root=None):
    """Exercise the frozen Tk/DnD runtime and scan a disposable package."""
    root = TkinterDnD.Tk()
    root.withdraw()
    try:
        engine = DesktopClamAV(engine_root) if engine_root else None
        app = VerifierWindow(root, engine)
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
            installed = location / "Example Folder"
            (installed / "42").mkdir(parents=True)
            (installed / "42" / "mod.info").write_bytes(b"id=Example\n")
            assert app.drop(SimpleNamespace(data=root.tk.call("list", str(installed)))) == "copy"
            assert app.source == installed
            scanner = app.engine.scanner()
            if engine_root:
                assert scanner and scanner.database, "Managed ClamAV engine is unavailable"
            if scanner:
                app.report, code = verify_mod(archive, clamscan=str(scanner.executable), database=scanner.database,
                                              environment=scanner.environment)
                app.show_report(code)
                assert code == 0, app.report
                result = app.report["scans"]
                _, folder_code = verify_mod(installed, clamscan=str(scanner.executable), database=scanner.database,
                                            environment=scanner.environment)
                assert folder_code == 0
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
    if len(sys.argv) in (3, 4) and sys.argv[1] == "--desktop-smoke":
        try:
            smoke(Path(sys.argv[2]), Path(sys.argv[3]).resolve() if len(sys.argv) == 4 else None)
        except Exception as error:
            Path(sys.argv[2]).write_text(json.dumps({"desktop": "failed", "reason": str(error)}), encoding="utf-8")
            raise SystemExit(1) from error
    else:
        main()
