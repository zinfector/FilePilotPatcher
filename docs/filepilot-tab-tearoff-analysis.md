# File Pilot folder-tab tear-off analysis

> Historical note: paths under the former `work/` directory refer to temporary
> diagnostics and one-off patch artifacts that were intentionally not retained
> in the organized repository. The maintained implementation is under
> `patcher/`, and retained binaries are documented under `binaries/`.

Target: `FPilot.exe` 0.8.2 x64
SHA-256: `08826147A90E7C6A1C4E80968AAA927B14CFBCA7271C7D12DB3AF9F24C483646`
Image base: `0x140000000`

## Implemented patch

Patched copy: `work/FPilot-tab-tearoff-patched.exe`
Patched SHA-256: `1480022DBBAE30C4090DB8528EEB5D5D64555380EB27230E87D72A21ADF04DDD`

The signed original and the pre-existing `File Pilot/FPilot-patched.exe` were
left untouched. Because the input is Authenticode-signed, this modified copy
necessarily reports a signature hash mismatch.

The reproducible patcher is `work/patch-filepilot-tab-tearoff.ps1`. It validates
the original SHA-256 and expected instruction bytes before making either edit.

Applied changes:

1. `0x14016D382`, file offset `0x16C782`: `76 E7 -> 90 90`, allowing a
   one-tab source to enter the existing close-and-spawn path.
2. `0x1401DEC14`, file offset `0x1DE014`: replace the nine-byte saved-geometry
   test with a jump to a 29-byte stub at `0x140216900` (file offset
   `0x215D00`). The stub skips restored geometry when `[rbp+0x70]`, the
   tear-off clipboard JSON length, is nonzero; otherwise it reproduces the
   original saved-geometry test and control flow.
3. Extend `.text` virtual size from `0x2158F0` to `0x21591D` so the stub in the
   section's zero-filled raw tail is explicitly mapped executable.

### Patched live verification

A one-tab source was dragged outside after applying the patch. Breakpoints
showed `FUN_140113FF0` return `EAX=1`, followed by `TearOffSpawnB` instead of
`SingleTabNoSpawn`. The source process then exited normally.

At process creation, the traced cursor placement was `(666,395)` with
`STARTF_USEPOSITION`. The child window's observed top-left was also exactly
`(666,395)`, rather than the source/saved top-left `(545,558)`. This verifies
both patch components together. The trace is in
`work/tab-tearoff-patched-live.log`.

## Conclusion

The stock executable already implements the intended high-level flow:

```text
folder-tab drag ends outside the current window
    -> queue command 0x58 with source, target, coordinates, and modifier
    -> command 0x58 selects its outside-window branch
    -> serialize the dragged panel/tab into JSON
    -> launch another FPilot.exe process
    -> set STARTF_USEPOSITION to the current cursor coordinates
    -> child process creates the new top-level window
```

Most importantly, both outside-window call sites already pass `1` for the
"position at cursor" argument. Patching those immediates will therefore not
enable behavior that is missing: it is already enabled in this build.

Live breakpoint traces confirmed two separate defects/limitations:

1. A single-tab outside drop reaches command `0x58` and is correctly classified
   as an outside drop, but an explicit tab-count branch suppresses process
   creation when the source contains one tab.
2. A multi-tab outside drop launches correctly and supplies the cursor point in
   `STARTUPINFOW`, but the child replaces it with saved session geometry before
   calling `CreateWindowExW`.

## Live debugging results

### Single-tab source

A controlled drag from `(853,563)` to `(361,344)` produced this breakpoint
sequence:

```text
0x14017912F  EmitCommand58
0x14016CFF2  Command58Handler
0x14016D0BB  DropKindDecision       R14D = 0
0x14016D355  OutsideDrop
0x14016D37F  TabCountReturned       EAX = 1
0x14016D36B  SingleTabNoSpawn
```

No new process appeared. The decisive instructions are:

```asm
14016D37A  call FUN_140113FF0       ; count eligible top-level tabs
14016D37F  cmp  eax,1
14016D382  jbe  14016D36B           ; clear drag state without spawning
```

The `JBE` is at file offset `0x16C782`, with bytes `76 E7`. Removing or
redirecting this branch makes the existing close-old-tab-and-spawn path at
`0x14016D384` available to a one-tab window. A minimal experimental patch is
`76 E7 -> 90 90`; the expected result is that the old one-tab source window
closes while the dragged tab is recreated in the child.

### Multi-tab source

A controlled drag from `(417,560)` to `(725,291)` produced:

```text
0x14017912F  EmitCommand58
0x14016CFF2  Command58Handler
0x14016D0BB  DropKindDecision       R14D = 0
0x14016D355  OutsideDrop
0x14016D3AF  TearOffSpawnB          R8D = 1
0x140203C42  GetCursorPosCall
0x140203C48  GetCursorPosReturn
0x140203F5D  CreateProcessCall
```

At `CreateProcessW`, the traced structure was:

```text
STARTUPINFO.cb       = 104
STARTUPINFO.dwFlags  = 0x4 (STARTF_USEPOSITION)
STARTUPINFO.dwX      = 725
STARTUPINFO.dwY      = 291
```

The new child process nevertheless created its window at rectangle
`(125,541)-(1673,1161)`, exactly the saved/source geometry rather than the
release point. This rules out the drag handler, `GetCursorPos`, and
`CreateProcessW` as the placement failure.

The override is in `entry`:

```asm
1401DEC14  cmp dword ptr [rbp+650h],0 ; saved geometry is present
1401DEC1B  je  1401DEC8B              ; retain CW_USEDEFAULT only if absent
1401DEC1D  ...                         ; load saved X/Y/width/height
1401DEDF0  call CreateWindowExW
```

`0x1401DEC14` is file offset `0x1DE014`; the compare/branch bytes are
`83 BD 50 06 00 00 00 74 6E`. The clipboard tear-off JSON length remains at
`[rbp+0x70]` at this point. A robust patch should skip the saved-geometry block
when `[rbp+0x70] != 0`, while retaining the existing `[rbp+0x650]` test for
ordinary launches. With X/Y left as `CW_USEDEFAULT`, Windows consumes the
already-correct `STARTF_USEPOSITION` coordinates.

Changing only `0x1401DEC1B` from `JE` to `JMP` also proves the placement fix,
but it disables saved initial positioning for every normal File Pilot launch;
it is therefore suitable only as a quick experiment, not the preferred patch.

## Primary functions

| Address | Current Ghidra name | Inferred role | Relevance |
|---|---|---|---|
| `0x140179040` | `FUN_140179040` | Finish/update tab drag and emit semantic command | Primary input seam. On release it queues command `0x58` with the target group/sibling, layout and placement flags, and the copy modifier; the source tab remains in `app+0xEA8`. |
| `0x140165BD0` | `FUN_140165BD0` | Main UI/command dispatcher | Contains the command `0x58` handler. The relevant handler begins at `0x14016CFF2`; the tear-off branch is around `0x14016D355`. |
| `0x140185260` | `FUN_140185260` | Serialize panel and request a new window | Produces JSON shaped as `{ "Panel": ... }` and forwards the cursor-position boolean. |
| `0x14010D7C0` | `FUN_14010D7C0` | Queue asynchronous new-window job | Copies the JSON and stores the cursor-position flag at job offset `+0x50`. |
| `0x140203B70` | `FUN_140203B70` | Publish state and launch a new FPilot process | Writes `FilePilot-OpenWindowFormat` clipboard data, calls `GetCursorPos`, applies `STARTF_USEPOSITION`, then calls `CreateProcessW`. |
| `0x1401DD9E0` | `entry` | Child startup and main-window creation | Selects default or restored X/Y and calls `CreateWindowExW`. This is the strongest secondary patch seam if startup geometry defeats the requested cursor placement. |
| `0x140204DE0` | `FUN_140204DE0` | Apply/update window geometry | May reposition the window after creation through `SetWindowPos`; verify this if the window briefly appears correctly and then moves. |

Suggested analysis names are `FinalizeTabDrag`, `MainFrameCommandDispatcher`,
`SerializePanelAndOpenWindow`, `QueueOpenWindowJob`,
`OpenSerializedPanelInNewProcess`, and `ApplyWindowGeometry` respectively.

## Command 0x58: tab-drop handling

`FUN_140179040` checks the active drag state at application-context offset
`+0xEA8`. While the drag is active it queues command `0x57`; when the release
is observed it queues command `0x58` at `0x14017912F`.

The command contains five meaningful values:

- target group identity, derived through `+0xEB0`;
- optional target sibling-tab identity, derived through `+0xEB8`;
- a split/layout-orientation flag from `+0xEC0`;
- a placement enum from `+0xEC4` (`2` is tab-strip insertion, while `1` and
  `3` select opposite split placements); and
- a copy modifier encoded as `input_state >> 1`.

The dragged tab itself is read from `+0xEA8` by the command handler. Earlier
revisions of this note described `+0xEC0/+0xEC4` as screen coordinates; the
drop-marker write sites prove that they are semantic flags. Cross-window
transport must carry the cursor point separately.

The dispatcher uses a jump table at `0x140172EE4`. Its entry for command
`0x58` leads to `0x14016CFF2`. This code parses the queued arguments, resolves
the dragged tab and drop target, and selects internal reparenting or external
tear-off behavior.

The outside-window path begins near `0x14016D355`. It has two calls to
`FUN_140185260`:

| Instruction | File offset | Meaning |
|---|---:|---|
| `0x14016D35D: MOV R8D,1` | `0x16C75D` | Pass `position_at_cursor = true`. |
| `0x14016D366: CALL 0x140185260` | `0x16C766` | First tear-off spawn variant. |
| `0x14016D3A3: MOV R8D,1` | `0x16C7A3` | Pass `position_at_cursor = true`. |
| `0x14016D3AF: CALL 0x140185260` | `0x16C7AF` | Second tear-off spawn variant. |

For comparison, the ordinary **Duplicate Tab To New Window** action is handled
by `FUN_140087DE0` and calls `FUN_140185260(..., 0)`. This confirms that the
third argument is deliberately specific to drag tear-off rather than normal
window duplication.

## Cursor placement and process launch

In `FUN_140203B70`, the job flag at `+0x50` controls this path:

```c
if (job->position_at_cursor != 0) {
    GetCursorPos(&point);
    startup_info.dwFlags |= STARTF_USEPOSITION;
    startup_info.dwX = point.x;
    startup_info.dwY = point.y;
}
CreateProcessW(..., &startup_info, ...);
```

Key instructions:

- `GetCursorPos` call: `0x140203C42` (file offset `0x203042`)
- `CreateProcessW` call: `0x140203F5D` (file offset `0x20335D`)

The panel JSON is passed through the registered clipboard format
`FilePilot-OpenWindowFormat`, then consumed by the new process.

## Child geometry: likely patch seam

At `entry`, File Pilot initially uses `CW_USEDEFAULT` for X and Y. If startup
state indicates explicit geometry, however, it replaces those defaults with
saved/restored coordinates, validates them against a monitor, and passes the
explicit values to `CreateWindowExW` at `0x1401DEDF0` (file offset
`0x1DE1F0`). `FUN_140204DE0` can subsequently call `SetWindowPos` as well.

Consequently, a robust patch should distinguish a drag-created child from a
normal launch and make that child prefer the tear-off coordinates over restored
geometry. Clipboard-payload presence is already observable through the nonzero
JSON length at entry stack offset `[rbp+0x70]`. Alternatively, the payload could
carry either:

- an explicit `tear_off` marker plus cursor X/Y, or
- an instruction to suppress restored positioning for this launch.

Using explicit coordinates in the child is more reliable than relying only on
`STARTF_USEPOSITION`, because application-supplied `CreateWindowExW` geometry
or a later `SetWindowPos` can supersede the process startup hint.

## Recommended breakpoint sequence

Before changing bytes, trace one failed drag in this order:

1. `0x14017912F` - verify release emits command `0x58`.
2. `0x14016D366` and `0x14016D3AF` - verify the external-drop branch is reached.
3. `0x140203C42` - verify `GetCursorPos` runs and inspect the returned point.
4. `0x140203F5D` - inspect `STARTUPINFOW.dwFlags`, `dwX`, and `dwY` at launch.
5. `0x1401DEDF0` in the child - inspect the actual X/Y given to `CreateWindowExW`.
6. `0x140204DE0` in the child - check for a later geometry override.

If step 1 fails, focus on `FUN_140179040` and its drag-state fields. If step 1
succeeds but step 2 fails, focus on the drop classification in
`0x14016CFF2` through `0x14016D3BE`. If steps 2-4 succeed, patch the child
geometry selection in `entry` and, if needed, `FUN_140204DE0`.

## Lower-priority code

`FUN_1401E8020` ("File Pilot - Drag Image"), `FUN_1401E82C0` ("File Pilot -
Drag Text"), and the main window procedure `FUN_14020ADE0` are not the primary
tear-off implementation. The first two create visual drag helpers; the window
procedure is useful only for tracing raw mouse input before it becomes command
`0x58`.

## Supporting exports

- `work/tabdrag-emitter-decompile.txt` - release/event producer
- `work/tabdrag-core-disasm.txt` - command `0x58` handler and tear-off branch
- `work/tabdrag-decompile-1.txt` - async job and process-launch decompilation
- `work/tabdrag-decompile-2.txt` - panel serialization wrapper
- `work/tabdrag-decompile-3.txt` - ordinary duplicate-to-window comparison
- `work/tabdrag-api-xrefs.txt` - cursor/process API references
- `work/tabdrag-geometry-xrefs.txt` - startup and repositioning API references

The original executable and Ghidra database were not modified. A separate
patched executable was created as documented above.

The relative-placement follow-up is implemented in
`work/FPilot-tab-relative-patched.exe` by
`work/patch-filepilot-tab-relative.ps1`. It preserves the tab grip using the
mouse-down coordinates at input `+0x58/+0x5C`, the tab item rectangle at
`+0x290`, synchronous release capture in `FUN_140185260`, and async-job fields
`+0x54/+0x58/+0x5C`. Its injected `.fpt` code begins at RVA `0x277000`.
Grip state is isolated at `.fpd` RVA `0x278000` instead of repurposing the
tooltip renderer's application `+0xEA0/+0xEA4` viewport-origin fields.
The record also stores raw tab-relative grip X/Y. A hardware watchpoint proved
that tooltip renderer `+0xD4` is a font-height input consumed by `CreateFontW`,
not a rectangle edge; modifying it was the cause of the oversized tooltip.
The final patch leaves all renderer fields native. Its hook at `0x14020518F`
runs after both native drag-helper dispatch calls and moves the existing Drag
Image and Drag Text HWNDs with `SetWindowPos` and `SWP_NOSIZE`. This makes the
grip-relative position the final write in each render frame, placing the image
at `cursor - rawGrip` and the text immediately below it without flicker.

Live logs are in `work/tab-tearoff-singletab.log` and
`work/tab-tearoff-multitab.log`; the final visual comparisons are
`work/tab-tooltip-original-compare-2.png` and
`work/tab-tooltip-patched-finalcompare.png`.
The reusable debugger is in `work/TabTearoffTracer/`.
