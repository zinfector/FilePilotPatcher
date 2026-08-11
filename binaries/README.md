# Binary artifacts

The binary set is deliberately small and divided by purpose:

- `input/FPilot-original.exe` is the untouched File Pilot 0.8.2 input used by
  the patcher and structural discovery tests.
- `regression/FPilot-patched.exe` is the earlier Open File Location build used
  to validate the legacy tab emitter.
- `regression/FPilot-open-location-tab-relative.exe` is the runtime-tested
  relative-placement reference build.
- `release/FPilot-open-location-tab-merge.exe` is the current combined output.

These files are stored through Git LFS. Confirm their values against
`SHA256SUMS.txt` before debugging a patch or interpreting a regression failure.
