# FilePilot tab tear-off relative-position fix

Target: FilePilot 0.8.2 x64 (`FPilot-original.exe` SHA-256
`08826147A90E7C6A1C4E80968AAA927B14CFBCA7271C7D12DB3AF9F24C483646`;
first-stage tear-off input SHA-256
`1480022DBBAE30C4090DB8528EEB5D5D64555380EB27230E87D72A21ADF04DDD`).

## Root causes

1. FilePilot suppresses the new-window path when the source has one tab. The
   first-stage patch removes that branch.
2. The new-window worker originally samples the cursor asynchronously. By the
   time the worker runs, it is no longer guaranteed to be the drag decision
   point.
3. `STARTUPINFO.dwX` and `dwY` are `DWORD` fields. Negative virtual-screen
   coordinates are not honored as signed positions, so Windows cascades the
   child on a positive-coordinate monitor.
4. FilePilot can restore saved geometry in the child after process creation.
   The first-stage patch bypasses restored geometry for a clipboard-launched
   tear-off child.
5. FilePilot queues the child when the tab crosses the detach threshold, before
   button-up. A one-shot position therefore preserves the threshold point, not
   the final drop point during a gradual drag.
6. The previous tooltip candidate let FilePilot position the Drag Image and
   Drag Text HWNDs, then called `SetWindowPos` again after render dispatch. The
   native and injected writers alternated positions in the same frame, causing
   visible flicker.
7. The previous combined build treated job `+0x58/+0x5C` as spare placement
   fields. They are actually the first eight bytes of the inline serialized
   panel JSON. Coordinate writes corrupted the payload, so the child fell back
   to `C:\Users\Zuonik`.
8. The parent published `FPT2` into the same process-global record watched by
   the child apply hook. In a multi-tab source, the parent therefore moved its
   own HWND to the child's target and appeared directly underneath it.

## Implemented behavior

- Drag activation records the exact pointer grip within the dragged tab.
- The parent captures the detach point synchronously into a dedicated
  process-private pending record and sends that signed `FPT2` record in a
  second registered clipboard format alongside the existing panel payload.
- The child consumes `FPT2` before FilePilot empties the clipboard.
- The parent pending record and child inbound record are distinct, so the
  source window cannot trigger the child-only apply hook.
- On child render frames, the child computes `cursor - saved window anchor` and
  calls `SetWindowPos` with signed coordinates. It follows the physical left
  button through the remainder of the drag and performs the final correction
  on release.
- Drag Image and Drag Text points are corrected immediately after each native
  `ClientToScreen` call. Their existing `CreateWindowExW`/`SetWindowPos` path is
  now the only position writer, avoiding the old oscillation.

## Runtime validation

No debugger was attached for the placement tests.

- Gradual cross-monitor drag: source origin `(1048, 285)`, grab point
  `(1348, 304)`, release `(-1280, 576)`, saved anchor `(300, 19)`, expected
  child origin `(-1580, 557)`, actual `(-1580, 557)`.
- Positive-coordinate drag: release `(1800, 650)`, saved anchor `(293, 19)`,
  expected child origin `(1507, 631)`, actual `(1507, 631)`.
- The child resolved `GetAsyncKeyState`, followed while the button was down,
  and cleared the pending `FPT2` state after release.
- A multi-tab combined-build run kept the source fixed at `(-1580,557)` and
  placed the child at `(980,557)` for cursor `(1280,576)` and anchor `(300,19)`.
  The detached window retained the `selection_test` path.
- Static disassembly confirms all five new seams: clipboard publish, clipboard
  consume, child signed placement, Drag Image point correction, and Drag Text
  point correction.

## Artifacts

- `patch-filepilot-tab-relative.ps1` rebuilds from the known first-stage input
  and verifies its SHA-256 before patching.
- `FPilot-tab-relative-fixed.exe` is the rebuilt executable.
  SHA-256: `AF57C29CEC3CC86F19CEE2E960A9D31237F4BDED23C6EB1744FED28083894B3E`.
- The injected `.fpt` section contains code and registered-format strings; the
  `.fpd` section contains per-process drag and placement state.
- The original Authenticode directory is cleared because modifying the image
  invalidates the original signature.
