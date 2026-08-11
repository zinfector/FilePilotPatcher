# Binary artifacts

The binary set is deliberately small and divided by purpose:

- `input/FPilot-original.exe` is the untouched File Pilot 0.8.2 input used by
  the patcher and structural discovery tests.
- `regression/FPilot-patched.exe` is the earlier Open File Location build used
  to validate the legacy tab emitter.
- `regression/FPilot-open-location-tab-relative.exe` is the runtime-tested
  relative-placement reference build.
- `release/FPilot-open-location-tab-merge.exe` combines Open File Location and
  the tab patches without Unicode.
- `release/FPilot-all-patches.exe` is the explicit full combined
  build: Open File Location, tab creation/tear-off, cross-window merge, and all
  Unicode support through the fixed D3D-atlas renderer. Its sibling
  `.unicode.json` file records the validated hooks, fixed renderer, and runtime
  telemetry location.

These files are stored through Git LFS. Confirm their values against
`SHA256SUMS.txt` before debugging a patch or interpreting a regression failure.
