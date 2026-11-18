"""Drag-and-drop desktop interface for the local verifier."""
from pathlib import Path
from queue import Empty, Queue
import re
from threading import Thread
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from urllib.parse import unquote, urlsplit

from tkinterdnd2 import DND_FILES, TkinterDnD

from . import __version__
from .desktop_clamav import DesktopClamAV
from .verification import verify_mod

WINDOW = "#16131d"
PANEL = "#211b2c"
DROP = "#2a2037"
TEXT = "#f7f2ff"
MUTED = "#c1b7d0"
ACCENT = "#c5a0fa"


class VerifierWindow:
    def __init__(self, root, engine=None):
        self.root = root
        self.engine = engine if engine is not None else DesktopClamAV()
        self.events = Queue()
        self.busy = False
        self.source = None
        self.reference = None
        self.report = None

        root.title("Faded Mod Verifier")
        root.configure(background=WINDOW)
        root.geometry("780x670")
        root.minsize(720, 620)
        root.protocol("WM_DELETE_WINDOW", self.close)
        self.source_text = tk.StringVar(value="Drop a ZIP or a Steam mod folder")
        self.reference_text = tk.StringVar(value="No reference selected")
        self.hash_text = tk.StringVar()
        self.status = tk.StringVar(value="Choose a package to start.")
        self.engine_status = tk.StringVar()

        style = ttk.Style(root)
        style.theme_use("clam")
        style.configure("TButton", background=PANEL, foreground=TEXT, padding=(12, 7),
                        bordercolor="#4d405e", focuscolor=ACCENT)
        style.map("TButton", background=[("active", DROP)], foreground=[("disabled", "#96899f")])
        style.configure("Primary.TButton", background=ACCENT, foreground="#20142e")
        style.map("Primary.TButton", background=[("disabled", PANEL), ("active", "#e1c7ff")],
                  foreground=[("disabled", "#96899f")])
        style.configure("TEntry", fieldbackground=PANEL, foreground=TEXT, insertcolor=TEXT)
        style.configure("Horizontal.TProgressbar", troughcolor=PANEL, background=ACCENT)

        outer = tk.Frame(root, background=WINDOW, padx=24, pady=18)
        outer.pack(fill="both", expand=True)
        heading = tk.Frame(outer, background=WINDOW)
        heading.pack(fill="x")
        self.label(heading, "Faded Mod Verifier", size=22, weight="bold").pack(side="left")
        self.label(heading, __version__, color=MUTED).pack(side="right")

        self.drop_zone = tk.Frame(outer, background=DROP, highlightbackground="#805ab0", highlightthickness=1,
                                  padx=16, pady=15)
        self.drop_zone.pack(fill="x", pady=(14, 0))
        drop_title = self.label(self.drop_zone, variable=self.source_text, size=14, background=DROP, weight="bold")
        drop_title.configure(wraplength=640)
        drop_title.pack()
        self.label(self.drop_zone, "Files are scanned locally with ClamAV and YARA.",
                   background=DROP, color=MUTED).pack(pady=(3, 7))
        buttons = tk.Frame(self.drop_zone, background=DROP)
        buttons.pack()
        self.zip_button = ttk.Button(buttons, text="Choose ZIP…", command=lambda: self.pick_source(False))
        self.folder_button = ttk.Button(buttons, text="Choose folder…", command=lambda: self.pick_source(True))
        self.zip_button.pack(side="left", padx=4)
        self.folder_button.pack(side="left", padx=4)
        for target in (root, self.drop_zone, drop_title):
            target.drop_target_register(DND_FILES)
            target.dnd_bind("<<Drop>>", self.drop)

        reference = tk.Frame(outer, background=WINDOW)
        reference.pack(fill="x", pady=(11, 0))
        self.reference_button = ttk.Menubutton(reference, text="Compare a reference")
        menu = tk.Menu(self.reference_button, tearoff=False)
        menu.add_command(label="Choose reference ZIP…", command=lambda: self.pick_reference(False))
        menu.add_command(label="Choose reference folder…", command=lambda: self.pick_reference(True))
        menu.add_command(label="Clear reference", command=lambda: self.set_reference(None))
        self.reference_button.configure(menu=menu)
        self.reference_button.pack(side="left")
        selected_reference = self.label(reference, variable=self.reference_text, color=MUTED)
        selected_reference.configure(wraplength=430)
        selected_reference.pack(side="left", padx=9)

        digest = tk.Frame(outer, background=WINDOW)
        digest.pack(fill="x", pady=(7, 0))
        self.label(digest, "Expected SHA-256 (optional)", color=MUTED).pack(side="left", padx=(0, 8))
        self.hash_entry = ttk.Entry(digest, textvariable=self.hash_text)
        self.hash_entry.pack(side="left", fill="x", expand=True, ipady=3)

        actions = tk.Frame(outer, background=WINDOW)
        actions.pack(fill="x", pady=(15, 0))
        self.setup_button = ttk.Button(actions, command=self.setup)
        self.setup_button.pack(side="left")
        self.label(actions, variable=self.engine_status, color=MUTED).pack(side="left", padx=9)
        self.scan_button = ttk.Button(actions, text="Scan mod", style="Primary.TButton", command=self.scan)
        self.scan_button.pack(side="right")

        self.label(outer, variable=self.status, color=ACCENT).pack(anchor="w", pady=(9, 5))
        self.progress = ttk.Progressbar(outer, mode="indeterminate")
        self.progress.pack(fill="x")
        results = tk.Frame(outer, background=PANEL)
        results.pack(fill="both", expand=True, pady=(11, 0))
        self.results = tk.Text(results, background=PANEL, foreground=TEXT, wrap="word", height=6,
                               font=("Segoe UI" if root.tk.call("tk", "windowingsystem") == "win32" else "TkDefaultFont", 10),
                               padx=12, pady=10, relief="flat", highlightthickness=0, state="disabled")
        scrollbar = ttk.Scrollbar(results, command=self.results.yview)
        self.results.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.results.pack(side="left", fill="both", expand=True)
        self.update_controls()
        self.root.after(80, self.process_events)

    @staticmethod
    def label(parent, text="", *, variable=None, size=10, background=WINDOW, color=TEXT, weight="normal"):
        family = "Segoe UI" if parent.tk.call("tk", "windowingsystem") == "win32" else "TkDefaultFont"
        return tk.Label(parent, text=text, textvariable=variable, background=background, foreground=color,
                        font=(family, size, weight), anchor="w")

    def update_controls(self):
        available = self.engine.scanner()
        self.engine_status.set(self.engine.status())
        self.setup_button.configure(text="Update ClamAV" if available and available.database else "Set up ClamAV")
        for button in (self.setup_button, self.zip_button, self.folder_button, self.reference_button, self.hash_entry):
            button.configure(state="disabled" if self.busy else "normal")
        self.scan_button.configure(state="normal" if self.source and not self.busy else "disabled")

    def browse(self, directory, title):
        return filedialog.askdirectory(title=title) if directory else filedialog.askopenfilename(
            title=title, filetypes=[("ZIP and FMOD packages", "*.zip *.fmod"), ("All files", "*")])

    def pick_source(self, directory):
        filename = self.browse(directory, "Choose a mod")
        if filename:
            self.set_source(Path(filename))

    def pick_reference(self, directory):
        filename = self.browse(directory, "Choose a trusted reference")
        if filename:
            self.set_reference(Path(filename))

    def set_reference(self, path):
        self.reference = path
        self.reference_text.set(path.name if path else "No reference selected")

    def set_source(self, path):
        self.source = path
        self.report = None
        self.source_text.set(path.name)
        self.hash_text.set("")
        self.write_results("")
        self.status.set("Ready to scan.")
        self.update_controls()

    def drop(self, event):
        if self.busy:
            return "refuse_drop"
        paths = self.root.tk.splitlist(event.data)
        if len(paths) != 1:
            self.status.set("Drop one ZIP or mod folder at a time.")
            return "refuse_drop"
        path = paths[0]
        if path.startswith("file:"):
            uri = urlsplit(path)
            if uri.netloc not in ("", "localhost"):
                self.status.set("Choose a local ZIP or mod folder.")
                return "refuse_drop"
            path = unquote(uri.path)
        self.set_source(Path(path))
        return "copy"

    def start(self, kind, action):
        self.busy = True
        self.progress.start(12)
        self.update_controls()

        def run():
            def progress(message):
                self.events.put(("progress", message))
            try:
                self.events.put((kind, action(progress)))
            except Exception as exc:
                self.events.put(("error", str(exc)))
        Thread(target=run, daemon=True).start()

    def setup(self):
        self.status.set("Preparing ClamAV setup…")
        self.start("setup", self.engine.setup)

    def scan(self):
        scanner = self.engine.scanner()
        if scanner is None:
            self.status.set("Select Set up ClamAV to enable scanning.")
            return
        source, reference, expected = self.source, self.reference, self.hash_text.get().strip().lower()
        if expected and not re.fullmatch(r"[a-f0-9]{64}", expected):
            self.status.set("Enter a complete 64-character SHA-256 or clear the field.")
            return
        self.status.set("Preparing the scan…")
        self.write_results("")
        self.start("scan", lambda progress: verify_mod(source, reference=reference, expected_sha256=expected or None,
                   clamscan=str(scanner.executable), database=scanner.database,
                   environment=scanner.environment, progress=progress))

    def process_events(self):
        while True:
            try:
                event, value = self.events.get_nowait()
            except Empty:
                break
            if event == "progress":
                self.status.set(value)
                continue
            self.busy = False
            self.progress.stop()
            if event == "scan":
                self.report, code = value
                self.show_report(code)
            elif event == "setup":
                self.status.set("ClamAV is ready. Choose a mod and select Scan mod.")
            else:
                self.status.set("Operation incomplete.")
                self.write_results(value)
            self.update_controls()
        self.root.after(80, self.process_events)

    def write_results(self, value):
        self.results.configure(state="normal")
        self.results.delete("1.0", "end")
        self.results.insert("1.0", value)
        self.results.configure(state="disabled")

    def show_report(self, code):
        self.status.set({0: "Scan complete. No matches reported.", 1: "Review the findings below.",
                         2: "Scan incomplete."}[code])
        data = self.report
        integrity = data["integrity"]
        lines = [f"Archive integrity  {integrity['status']} · {integrity['files']} files"]
        if integrity["sha256"]:
            lines.append("SHA-256  " + integrity["sha256"])
        for name, field in (("ClamAV", "clamav"), ("YARA", "yara")):
            result = data["scans"][field]
            scanned = f" · {result['scanned']} scanned" if "scanned" in result else ""
            lines.append(f"{name}  {result['status']}{scanned}")
            if result.get("reason"):
                lines.append("  " + result["reason"])
            for finding in result.get("findings", []):
                indicator = finding.get("signature", finding.get("rule", ""))
                lines.append(f"  {finding['file']}  {indicator}")
        if data["archive_hash"]["status"] != "reference-required":
            lines.append("Expected SHA-256  " + data["archive_hash"]["status"])
        comparison = data["file_comparison"]
        if comparison["status"] != "reference-required":
            lines.append("Reference files  " + comparison["status"])
            for label in ("changed", "missing", "extra"):
                names = comparison[label]
                lines.extend(f"  {label.capitalize()}  {name}" for name in names[:100])
                if len(names) > 100:
                    lines.append(f"  {len(names) - 100} more {label} files")
        self.write_results("\n".join(lines))

    def close(self):
        if self.busy:
            messagebox.showinfo("Operation in progress", "Wait for the current operation to finish.")
        else:
            self.root.destroy()


def main():
    root = TkinterDnD.Tk()
    VerifierWindow(root)
    root.mainloop()
