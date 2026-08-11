# Ghidra workspace

Open `project/FilePilot.gpr` with Ghidra 12.1.2 or a compatible version. The
repository includes the current project database so labels, types, comments,
and decompiler analysis remain available after cloning.

Ghidra database blobs are tracked with Git LFS. Close Ghidra before staging a
project update so its indexes are consistent. Per-user workspace state, lock
files, journals, and backup indexes are ignored.

`scripts/FilePilotTrace.java` contains the FilePilot-specific tracing helper.
Add `ghidra/scripts` to Ghidra's script directories when using it.
