# FilePilot combined patch

This build combines the existing **Open File Location** shell-selection patch
with the tab tear-off positioning fix.

## Artifacts

- Input (retained): `binaries/regression/FPilot-patched.exe`
- Input SHA-256: `CBFEF161172EC9D56DF6278BB791D693CF34219EB6E66FC2DB3EBAD6702A2BA4`
- Historical output (superseded and not retained): `FPilot-open-location-tab-relative.exe`
- Output SHA-256: `C4661EE3AFFBEF3EB5AE175959D3B3393FA86B8B59F88860F4848BDDB0B16572`
- Historical entry script: `patch-filepilot-combined.ps1` (superseded)
- Maintained emitter: `patcher/tab_relative.py`

The entry script validates the exact input SHA-256 before applying the tab
tear-off patch. It does not overwrite the input binary.

## Combined PE layout

- `.fplt` at RVA `0x277000`, size `0x16000`: pre-existing Open File Location payload
- `.fpt` at RVA `0x28D000`, size `0x1000`: tab tear-off code
- `.fpd` at RVA `0x28E000`, size `0x200`: process-private grip,
  outbound-pending, and inbound-child placement records
- `SizeOfImage`: `0x28F000`

The `.fplt` bytes are identical between the input and combined output. The
certificate directory is cleared because modifying the executable invalidates
the original signature.

The outbound placement record is deliberately separate from the queued job.
The job's JSON begins at `job +0x58`; the previous build used `+0x58/+0x5C`
as coordinates and therefore replaced the first eight JSON bytes. That made the
child reject the two-byte/truncated payload and fall back to the user profile
directory. The child-side placement record is also separate from the parent's
outbound record. Consequently only the child observes the `FPT2` apply marker,
and the source HWND is never repositioned on top of the detached window.

The current call-site hook preserves only volatile argument registers. It no
longer borrows `R13` or patches function prologues/epilogues, avoiding the prior
saved-`R14` stack-slot overwrite.

## Verification

- Multi-tab gradual drag retained anchor `(300,19)`. The source stayed at
  `(-1580,557)` while cursor `(1280,576)` produced child origin `(980,557)`,
  exactly `cursor - anchor`.
- A negative-monitor run produced child origin `(-1580,557)` for cursor
  `(-1280,576)` and the same `(300,19)` anchor.
- The detached child retained the `selection_test` path instead of falling back
  to `C:\Users\Zuonik`.
- Standard `SHOpenFolderAndSelectItems` probe exited `0` and visibly selected
  `SELECT_ME.txt`.
- Chromium-style shell-selection probe returned `0x00000000`, exited `0`, and
  visibly selected `SECOND_TARGET.log`.
- The combined executable remained responsive during both tests.
