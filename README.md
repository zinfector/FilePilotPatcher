# File Pilot reverse-engineering project

This repository contains the Ghidra analysis, patcher, regression fixtures, and
research notes for the File Pilot 0.8.2 Open File Location and tab-transport
modifications.

## Repository layout

- `patcher/` - maintained patcher source, payload, build wrapper, and tests.
- `ghidra/project/` - the current Ghidra project and analysis database.
- `ghidra/scripts/` - FilePilot-specific Ghidra automation.
- `binaries/input/` - the unmodified File Pilot 0.8.2 patch input.
- `binaries/regression/` - known builds used by regression tests.
- `binaries/release/` - the current combined patched executable.
- `docs/` - design notes and historical implementation documentation.

Executable files and Ghidra database blobs are stored with Git LFS. After
cloning, run:

```powershell
git lfs pull
```

## Build and test

Install the Python dependencies, build from an x64 Visual Studio toolchain,
and run the regression suite:

```powershell
python -m pip install lief capstone
Set-Location .\patcher
& .\build_patch.ps1
python -m unittest -v .\test_locator.py
```

The default build reads `binaries/input/FPilot-original.exe` and writes
`binaries/release/FPilot-open-location-tab-merge.exe`.

## Ghidra

Open `ghidra/project/FilePilot.gpr` in Ghidra. See `ghidra/README.md` before
committing analysis changes.

## Binary provenance

Expected hashes are recorded in `binaries/SHA256SUMS.txt`. The File Pilot
executables remain subject to their original vendor license; review that
license before distributing a clone or release bundle.
