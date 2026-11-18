# Faded Mod Verifier

Verify a downloaded mod ZIP or a mod folder on disk, including a Steam Workshop subscription. The verifier checks archive paths and file integrity, runs ClamAV and YARA locally, and can compare the contents with a reference you trust. It reads the mod as data and scans a temporary copy.

## Install

Use Python 3.10 or newer and install the release with its YARA support.

    python -m pip install "faded-mod-verifier[scan] @ https://github.com/FadedMods/faded-mod-verifier/releases/download/v0.1.0/faded_mod_verifier-0.1.0-py3-none-any.whl"

Install ClamAV and update its signature database. The verifier uses the `clamscan` executable from your PATH. On Windows you can also provide the full path to `clamscan.exe` with `--clamscan`. [ClamAV installation](https://docs.clamav.net/manual/Installing.html) · [Signature updates](https://docs.clamav.net/manual/Usage/SignatureManagement.html)

## Scan a download or Steam mod

    faded-mod-verifier verify "Downloads/ExampleMod.zip"
    faded-mod-verifier verify "steamapps/workshop/content/108600/1234567890"

Run the same checks on a Faded Mods ZIP, a Steam mod folder or a ZIP-format package from another publisher. For a Workshop item that contains several mods, point the verifier at the item folder for a scan or at the specific mod folder for file comparison.

The report separates archive integrity, the expected archive hash, file comparison, ClamAV and YARA. A passed scan means the configured engines found no matching signatures or rules in the inspected files. Updating signatures or using different YARA rules can change the result. The included YARA rule looks for a direct host-process call in Lua, which merits review. Add your own trusted rule file with `--yara-rules`.

The verifier reads ZIP and JAR members within bounded depth and size limits. An interrupted, unsupported or incomplete scan is reported as incomplete. File and folder snapshots use temporary storage, so allow enough disk space for the expanded mod and any reference copy.

## Verify that the files match

Compare a download with the SHA-256 published by a source you trust.

    faded-mod-verifier verify "Downloads/ExampleMod.zip" --expected-sha256 PASTE_TRUSTED_SHA256_HERE

Compare your installed copy with a trusted original ZIP or a known-good folder.

    faded-mod-verifier verify "Zomboid/mods/ExampleMod" --compare "Downloads/ExampleMod.zip"

File comparison reports missing, extra and changed paths. It ignores ZIP compression and timestamps. For a single Project Zomboid mod, it also ignores the Steam wrapper so an original Workshop ZIP can be compared with an installed copy. ClamAV and YARA still see files outside the mod folder, such as Workshop metadata. Steam updates can legitimately change files, so compare the same release.

Use `--inspect-only` for structural and fidelity checks on a machine without the scan engines. It marks both scans as skipped. `--json` and `--inventory` are available for automation.

## Prepare a Project Zomboid Workshop ZIP

    faded-mod-verifier prepare "WorkshopExport.zip" "ExampleMod.zip"

This accepts a single `Contents/mods/ExampleMod` directory with `mod.info` at its root or in a build folder. It produces a new installer-layout ZIP and prints its SHA-256. Use `verify` on the output for a local scan. The Faded Mods registry runs its own complete checks before a release can appear in Community Mods.

For GitHub and HTTPS releases connected to Faded Mods, you can point the release manifest at the original single-mod Workshop ZIP. Use the original ZIP's size and SHA-256 in the manifest, and set the installation folder to the mod folder inside `Contents/mods`. The registry prepares the installer ZIP automatically. [Faded Mods publishing portal](https://fadedmods.com/?page_id=286)

## Automation

- `0` means all requested checks completed without findings or a mismatch. `--inspect-only` counts structure and fidelity only.
- `1` means a scanner flagged a file or the trusted reference differs.
- `2` means a required inspection or scan was incomplete.

Use `python -m faded_mod_verifier` if the command is unavailable on your PATH. From a checkout, install it with `python -m pip install -e ".[scan]"` and run the tests with `python -m unittest discover -s tests`.

## License

MIT. See [LICENSE](LICENSE).
