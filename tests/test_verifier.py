import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from zipfile import ZipFile

from faded_mod_verifier.cli import main
from faded_mod_verifier.package_safety import digest_file


class LocalVerification(unittest.TestCase):
    def test_workshop_and_installed_copy_match_and_edits_are_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workshop = root / "workshop.zip"
            data = "id=Example\n"
            with ZipFile(workshop, "w") as archive:
                archive.writestr("Contents/mods/Example/42/mod.info", data)
                archive.writestr("workshop.txt", "title=Example\n")
            target = root / "prepared.zip"
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(["prepare", str(workshop), str(target)]), 0)
            installed = root / "Example"
            (installed / "42").mkdir(parents=True)
            info = installed / "42" / "mod.info"
            info.write_bytes(data.encode())
            args = ["verify", str(installed), "--compare", str(workshop), "--inspect-only", "--json"]
            first = io.StringIO()
            with contextlib.redirect_stdout(first):
                self.assertEqual(main(args), 0)
                self.assertEqual(main(["verify", str(target), "--expected-sha256", digest_file(target),
                                       "--inspect-only"]), 0)
            info.write_text("id=Changed")
            edited = io.StringIO()
            with contextlib.redirect_stdout(edited):
                self.assertEqual(main(args), 1)
            self.assertEqual(json.loads(edited.getvalue())["file_comparison"]["changed"], ["42/mod.info"])

    def test_missing_scan_engine_is_explicit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "mod.info").write_text("id=Example\n")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                result = main(["verify", str(root), "--json", "--clamscan", str(root / "missing")])
            self.assertEqual(result, 2)
            self.assertEqual(json.loads(output.getvalue())["scans"]["clamav"]["status"], "incomplete")
