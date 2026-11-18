"""Per-user ClamAV setup using pinned, official upstream downloads."""
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
from urllib.request import Request, urlopen

from .package_safety import extract_plan, inspect_archives, reject_links

ENGINE_VERSION = "1.5.5"
MIB = 1024**2
ASSETS = {
    "win32": ("win.x64.zip", 225800047, "90169f5e551010bfbd0208b50d9b2fa8988ef396cccbd46b0cc8cae03e22a4a4"),
    "linux": ("linux.x86_64.deb", 107577342, "fff17fb1f8917d1ea1308c9736dabe376077458aba000a5dadcce7193a8c538c"),
}


def app_data():
    if sys.platform == "win32":
        base = Path(os.getenv("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
    else:
        base = Path(os.getenv("XDG_DATA_HOME") or Path.home() / ".local" / "share")
    return base / "FadedMods" / "ModVerifier"


def download_engine(target, progress):
    suffix, expected_size, expected_digest = ASSETS[sys.platform]
    url = (f"https://github.com/Cisco-Talos/clamav/releases/download/clamav-{ENGINE_VERSION}/"
           f"clamav-{ENGINE_VERSION}.{suffix}")
    request = Request(url, headers={"User-Agent": "Faded-Mod-Verifier"})
    digest = hashlib.sha256()
    written = 0
    with urlopen(request, timeout=50) as response, target.open("xb") as stream:
        if not response.geturl().startswith("https://"):
            raise ValueError("ClamAV must be downloaded over HTTPS.")
        while chunk := response.read(MIB):
            written += len(chunk)
            if written > expected_size:
                raise ValueError("The ClamAV download exceeds its published size.")
            digest.update(chunk)
            stream.write(chunk)
            if written // MIB % 8 == 0 or written == expected_size:
                progress(f"Downloading ClamAV… {written // MIB} of {expected_size // MIB} MB")
    if written != expected_size or digest.hexdigest() != expected_digest:
        raise ValueError("The ClamAV download did not match its verified SHA-256.")


def unpack_deb(package, destination):
    """Read the data archive from the verified Debian package without installing it."""
    tar_path = destination.parent / "payload.tar"
    with package.open("rb") as source:
        if source.read(8) != b"!<arch>\n":
            raise ValueError("The ClamAV package format is invalid.")
        while header := source.read(60):
            if len(header) != 60 or header[-2:] != b"\x60\n":
                raise ValueError("An invalid ClamAV package header was found.")
            name = header[:16].decode("ascii").strip().rstrip("/")
            remaining = int(header[48:58])
            if remaining < 0 or source.tell() + remaining > package.stat().st_size:
                raise ValueError("The ClamAV package is incomplete.")
            if name.startswith("data.tar"):
                with tar_path.open("xb") as output:
                    while remaining:
                        chunk = source.read(min(MIB, remaining))
                        if not chunk:
                            raise ValueError("The ClamAV package is incomplete.")
                        output.write(chunk)
                        remaining -= len(chunk)
                break
            source.seek(remaining + remaining % 2, os.SEEK_CUR)
    if not tar_path.is_file():
        raise ValueError("The ClamAV package is missing its data archive.")
    with tarfile.open(tar_path) as archive:
        if sum(member.size for member in archive.getmembers()) > 2 * 1024**3:
            raise ValueError("The ClamAV package exceeds the extraction limit.")
        archive.extractall(destination, filter="data")


def child_environment(library_dirs=()):
    """Restore the host loader environment before running an external engine."""
    environment = os.environ.copy()
    if sys.platform == "linux":
        original = environment.pop("LD_LIBRARY_PATH_ORIG", "")
        if getattr(sys, "frozen", False):
            environment.pop("LD_LIBRARY_PATH", None)
        libraries = [str(path) for path in library_dirs]
        if original:
            libraries.append(original)
        if libraries:
            environment["LD_LIBRARY_PATH"] = os.pathsep.join(libraries)
    return environment


@dataclass(frozen=True)
class Scanner:
    executable: Path
    database: Path | None
    environment: dict


class DesktopClamAV:
    def __init__(self, root=None):
        self.root = root if root is not None else app_data()
        self.engine = self.root / ("clamav-" + ENGINE_VERSION)
        self.database = self.root / "definitions"
        self.suffix = ".exe" if sys.platform == "win32" else ""

    def _binary(self, name):
        return next(self.engine.rglob(name + self.suffix), None)

    def _libraries(self):
        return sorted({path.parent for path in self.engine.rglob("libfreshclam.so*")})

    def _environment(self):
        environment = child_environment(self._libraries())
        certificate = next(self.engine.rglob("clamav.crt"), None)
        if certificate:
            reject_links(certificate)
            environment["CVD_CERTS_DIR"] = str(certificate.parent)
        elif sys.platform == "linux":
            raise ValueError("The portable engine is missing its ClamAV definition certificate.")
        return environment

    def _definitions_ready(self):
        return all(any((self.database / (name + suffix)).is_file() for suffix in (".cvd", ".cld"))
                   for name in ("main", "daily"))

    def scanner(self):
        executable = self._binary("clamscan")
        if executable and self._definitions_ready():
            try:
                return Scanner(executable, self.database, self._environment())
            except (OSError, ValueError):
                pass
        # Distro-managed ClamAV is also available to Linux desktop users.
        system = shutil.which("clamscan") if sys.platform == "linux" else None
        return Scanner(Path(system), None, child_environment()) if system else None

    def status(self):
        scanner = self.scanner()
        if scanner and scanner.database is None:
            return "Using the system ClamAV installation"
        if scanner:
            rules = [path for path in self.database.glob("daily.*") if path.suffix in (".cvd", ".cld")]
            updated = datetime.fromtimestamp(max(path.stat().st_mtime for path in rules)).strftime("%b %d, %Y")
            return f"ClamAV definitions updated {updated}"
        return "ClamAV needs its first-time setup"

    @contextmanager
    def _lock(self):
        with (self.root / "setup.lock").open("a+b") as lock:
            if sys.platform == "win32":
                import msvcrt
                lock.seek(0)
                msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield

    def setup(self, progress):
        reject_links(self.root)
        self.root.mkdir(parents=True, exist_ok=True)
        with self._lock():
            self._setup(progress)

    def _setup(self, progress):
        freshclam = self._binary("freshclam")
        if freshclam is None or self._binary("clamscan") is None:
            with tempfile.TemporaryDirectory(prefix="setup-", dir=self.root) as directory:
                folder = Path(directory)
                package = folder / "clamav"
                progress("Downloading the official ClamAV engine…")
                download_engine(package, progress)
                progress("Preparing the verified ClamAV engine…")
                staging = folder / "engine"
                if sys.platform == "win32":
                    plan = inspect_archives([package], max_bytes=2 * 1024**3)
                    extract_plan([package], staging, plan)
                else:
                    unpack_deb(package, staging)
                if not list(staging.rglob("freshclam" + self.suffix)) or not list(staging.rglob("clamscan" + self.suffix)):
                    raise ValueError("The verified ClamAV package is missing its tools.")
                staging.rename(self.engine)
            freshclam = self._binary("freshclam")
        reject_links(self.database)
        self.database.mkdir(exist_ok=True)
        reject_links(freshclam)
        progress("Downloading current ClamAV malware definitions…")
        with tempfile.TemporaryDirectory(prefix="freshclam-", dir=self.root) as directory:
            config = Path(directory) / "freshclam.conf"
            settings = "DatabaseMirror database.clamav.net\nConnectTimeout 30\nReceiveTimeout 120\nMaxAttempts 2\n"
            if sys.platform == "linux":
                import pwd
                owner = pwd.getpwuid(os.getuid()).pw_name
                if not owner or any(char.isspace() for char in owner):
                    raise ValueError("ClamAV setup needs a valid local account name.")
                settings += f"DatabaseOwner {owner}\n"
            config.write_text(settings, encoding="utf-8")
            result = subprocess.run([
                str(freshclam), "--stdout", "--config-file=" + str(config), "--datadir=" + str(self.database),
            ], cwd=freshclam.parent, env=self._environment(), capture_output=True,
                text=True, encoding="utf-8", errors="replace", timeout=1200,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0), check=False)
        if result.returncode or not self._definitions_ready():
            lines = (result.stdout + "\n" + result.stderr).splitlines()
            errors = [line for line in lines if "error" in line.lower() or "warning" in line.lower()]
            raise ValueError("ClamAV could not finish updating its definitions.\n" + "\n".join(errors[:4])[:650])
