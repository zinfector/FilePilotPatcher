# File Pilot 0.8.5: file-operation undo/redo patch design

Status: investigation and implementation design, **not an implemented or runtime-tested patch**.
No application executable was modified. This document distinguishes verified binary facts
from proposed behavior and remaining runtime validation.

## Finding

The correct interception point is File Pilot's native `IFileOperation::PerformOperations`
call, with a small wrapper around its operation worker to supply operation kind and scope.
Use a private completion-based history and new native file-context commands. This allows
Ctrl+Z / Ctrl+Y / Ctrl+Shift+Z without taking text undo away from rename, search, or path inputs.

This is a payload feature, not a one-byte flag fix. The native worker already supplies
`FOF_ALLOWUNDO` except for permanent delete. Simply adding that flag again, or sending
Ctrl+Z to Explorer, would not implement File Pilot's own undo/redo history.

## Verified input and evidence

Program: `ghidra/project/FPilot 0.85.gpr`, `/FPilot.exe`.
Image base: `0x140000000`; file/product version previously verified as 0.8.5.0.
SHA-256: `ab5e7bbfa50872225f24856697ef7341a58e51a5e521435ba0dfeeb8ab3b2676`.
All addresses below are image VAs, not raw file offsets.

Evidence is in `analysis/undo-0.8.5/`:

- `file-engine.txt`: native submitter, operation engine, and Recycle Bin action helper.
- `keybinds.txt`: command registration, shortcut parser, text callbacks, and native worker callers.
- `operations.txt`: initial import investigation and Shell menu verb filtering.
- `seams.json`: raw offsets, expected bytes, decoded instructions, and COM GUID checks.
- `audit_seams.py`: read-only, hash-gated reproduction of 17 instruction-seam checks.

Ghidra was opened with `-process FPilot.exe -noanalysis -readOnly`. The broad discovery
run hit a decompiler timeout in an unrelated large UI function and was stopped; its
`discovery.txt` is partial. Focused exports contain the relevant completed functions.
The headless launcher returned exit code 1 even for those exports and did not emit its
usual final report, so this is not claimed as a clean Ghidra batch run. Independent
PE decoding verifies the key call instructions and interface GUIDs in the original file.

| Verified location | Meaning |
| --- | --- |
| `0x140110410` | `P_PerformFilesOperation`: copies operation input into owned storage and submits work |
| `0x140110ae0` | `P_PerformFilesOperationNT`: executes native operations through Shell COM |
| `0x1401f6970` | Worker thunk; calls the engine, frees job storage, decrements outstanding count |
| `0x140110ba2` | Creates `CLSID_FileOperation`, requests `IID_IFileOperation` |
| `0x140111eed` | `CopyItem`, vtable offset `0x80` |
| `0x140111f18` | `MoveItem`, vtable offset `0x70` |
| `0x140111bc9` | `DeleteItem`, vtable offset `0x90` |
| `0x140111f81` | `SetOperationFlags`, vtable offset `0x28` |
| `0x140111f93` | `PerformOperations`, vtable offset `0xa8`; **preferred completion-tracking hook** |
| `0x140209330` | Recycle Bin context-menu action helper (`undelete` / delete) |
| `0x1401e9310` | Shell context-menu enumeration; compares and filters `undo` / `redo` verbs |
| `0x1400260d0` | Native command registration; allocates `0x48`-byte descriptors |
| `0x140036880` | Parses native keybinding strings into a descriptor |
| `0x14008a900` / `0x14008a840` | Existing text undo / redo callbacks |

The GUID bytes at `0x140235938` and `0x140235908` decode to
`3ad05575-8857-4850-9277-11b85bdb8e09` and
`947aab5f-0a5c-4c13-b4d6-4bf7836fc9f8`, respectively.
This confirms the COM interface independently of inferred vtable signatures.

The engine's operation kinds are:

| Kind | Behavior relevant to this patch |
| --- | --- |
| 0 | Copy |
| 1 | Move |
| 2 | Recyclable delete / Trash |
| 3 | Permanent delete |
| 4 | Rename |
| 8 | Delete selected Recycle Bin items |
| 9 | Empty Recycle Bin |
| 10 | Restore selected Recycle Bin items |
| 11 | Restore all Recycle Bin items |

Kinds 8–11 bypass creation of the normal `IFileOperation` object. These need history
invalidation even though the completion hook will not run for them. New-file/folder
and shortcut paths also exist; their reversal is outside the initial move/delete feature.

At worker entry, RDX points to the native operation descriptor and its first DWORD is
the kind. The engine sets base flags to `0x240` (`FOF_NOCONFIRMMKDIR | FOF_ALLOWUNDO`),
or `0x200` for kind 3. It conditionally adds `0x10000000` for elevation and `0x10` for
confirmation policy. It passes null per-item progress sinks to the queue calls. At
completion it tests the overall HRESULT, which is insufficient to build per-file history.

Microsoft documents Shell undo as user-session state coordinated by Explorer.
That makes a Shell `undo` verb an unsuitable substitute for a private File Pilot stack:
it can affect operations performed by another application.
[SetOperationFlags](https://learn.microsoft.com/en-us/windows/win32/api/shobjidl_core/nf-shobjidl_core-ifileoperation-setoperationflags).

## Proposed binary integration

Add `undo_payload.cpp` and a hash-gated `undo_patch.py` using the repository's existing
payload/build conventions. Keep this feature opt-in until runtime tests pass.

1. Wrap all nine verified direct calls to `0x140110ae0` with the same ABI:
   RCX = native allocator/job context, RDX = operation descriptor. Copy the kind and
   required request metadata before calling the original. Keep a scoped, nestable
   thread-local operation context; do not hold pointers to freed native job storage.
   This is needed because several paths call the worker directly instead of using
   `0x140110410`. Call RVAs are `0x1131a8`, `0x108907`, `0x110a97`, `0x20b1fd`,
   `0x7ea16`, `0x7ec26`, `0x113a2b`, `0x113b1c`, and `0x1f6985`.
   Confirm indirect/address-taken callers at runtime; do not assume these nine prove
   complete coverage of third-party Shell extensions or cross-process drag/drop.

2. Replace the six bytes at **RVA `0x111f93`**:

   ```text
   original: FF 90 A8 00 00 00       call qword ptr [rax+0xa8]
   proposed: E8 <relative32> 90     call HistoryPerform; nop
   ```

   `relative32 = HistoryPerformVA - (0x140111f93 + 5)` and must fit signed 32 bits.
   The original code already loads the `IFileOperation*` into RCX, so use
   `HRESULT WINAPI HistoryPerform(IFileOperation* operation)`. Return the original
   `PerformOperations` HRESULT unchanged. Native result handling starts at `0x140111f99`.
   Do not replace the three-byte `SetOperationFlags` call with a five-byte call.

3. `HistoryPerform` calls `Advise` with a real reference-counted
   `IFileOperationProgressSink`, executes `operation->PerformOperations()` exactly once,
   calls `GetAnyOperationsAborted`, and unadvises using the returned cookie. Attach
   before execution, even though the individual operations have already been queued.
   Finish collection after the operation returns; exception-safe cleanup must keep
   the sink alive until callbacks and `Unadvise` finish. If recording setup fails,
   preserve normal operation behavior, report that it was not recorded, and install
   a history barrier. Never turn a recorder allocation failure into a fabricated undo.

4. Hook the native Trash-command registration call at **RVA `0x27697`** (a complete
   five-byte `call 0x1400260d0`). Call the original registrar, retain its result, then
   register the new file commands using the same allocator, registry, group, and
   file-context mask. Return the original descriptor so the following native code
   still assigns Delete to Trash. Install new commands once per registry instance,
   not just once per process. Supply separate translated/display labels as necessary.

5. Existing payloads may already own shared hooks. Apply this component through the
   maintained patcher using the original-input hash and a composed manifest; reject
   unexpected occupied seams. Do not directly accept arbitrary patched binaries by
   weakening the hash guard. Preserve x64 stack alignment, shadow space, nonvolatile
   registers, unwind metadata, and the established payload relocation policy.

Minimal control flow, not compilable implementation:

```cpp
HistoryWorker(arena, request) {
    ScopedOperation context(copy_request_metadata(request));
    return OriginalWorker(arena, request);
}

HistoryPerform(operation) {
    auto sink = MakeSink(CurrentOperation());
    auto registration = TryAdvise(operation, sink);
    HRESULT result = operation->PerformOperations();
    bool aborted = QueryAbortState(operation);
    registration.Unadvise();
    PublishObservedResults(sink, result, aborted);
    return result;
}
```

The recorder must not retain native request strings, raw unowned COM pointers, or
stack addresses beyond their lifetime. Snapshot UTF-16 paths, Shell PIDLs, and identity
information into payload-owned memory.

## History behavior

Initial scope: process-session history shared by all File Pilot windows, 100 completed
user batches, ordinary filesystem moves and recyclable deletes. One multi-selection
operation is one batch. Older pre-patch operations cannot be reconstructed safely.
Persistent history across restarts is a separate feature needing a durable journal.

Each batch contains an ID, operation kind, completion sequence, affected paths and
parents, per-item result, original location, actual resulting location, source/result
identity, and a reversibility reason. Item state is explicit: applied, undone, skipped,
failed, permanently deleted, or unavailable. A bounded history discards metadata only;
it must never empty the Recycle Bin to enforce its capacity limit.

- **Record facts after completion.** `MoveItem` / `DeleteItem` queue success does not
  mean the filesystem changed. Capture source identity and location in the pre-callback;
  accept a record only after a successful post-callback with an actual result. Interpret
  Shell success-status codes such as skipped/ignored explicitly; `SUCCEEDED(hr)` alone
  is not sufficient. Reconcile uncertain outcomes conservatively.
- **Move undo:** move the recorded resulting object to its original parent and name.
  Redo moves it forward again. Use the actual result from each replay to refresh its
  identity; cross-volume moves may create a new file identity.
- **Delete undo:** use the exact returned Recycle Bin Shell item, identified by a cloned
  absolute PIDL and original location, to restore that one item. Do not search by basename
  or invoke Restore All. Resolve the PIDL into a fresh Shell item on the replay apartment.
  A Shell MoveItem restore to the original directory/name is the preferred implementation
  to prototype; verify metadata cleanup and collision behavior on the target Windows build.
  The native `undelete` helper is useful evidence but lacks per-item outcome tracking.
- **Delete redo:** recycle the restored object again and replace the stored recycle-item
  identity with the new callback result. Never reuse the first delete's stale PIDL.
- **Partial batches:** retain successful reversible items even if other items failed or
  the batch was cancelled. Undo in reverse observed order. On partial undo/redo, keep
  per-item state and block unrelated history traversal until the partial operation is
  resolved or explicitly abandoned; never move the whole batch to the other stack early.
- **New work:** an observed new filesystem mutation clears the redo branch. A cancelled
  operation with no mutations does not. Unsupported mutations create a visible barrier
  instead of letting Ctrl+Z silently jump past them. Replays carry a transaction ID and
  suppress normal recording; callbacks still update their own replay state.
- **Concurrency:** serialize tracked execution and replay through a coordinator. Use
  completion order for history, reject history commands while native work is outstanding,
  and protect reentrant UI/COM callbacks without holding the history mutex during Shell
  calls. Busy status must be visible. Test native scheduler counters and direct worker
  callers so queued earlier operations cannot slip past the busy gate.

Microsoft's post-move callback returns the resulting item and the actual name, including
collision renames; the delete callback returns the recycled item or null if deletion
was permanent. Those are the required facts for dependable reversal.
[PostMoveItem](https://learn.microsoft.com/en-us/windows/win32/api/shobjidl_core/nf-shobjidl_core-ifileoperationprogresssink-postmoveitem),
[PostDeleteItem](https://learn.microsoft.com/en-us/windows/win32/api/shobjidl_core/nf-shobjidl_core-ifileoperationprogresssink-postdeleteitem).

Replay on a dedicated, message-pumped STA initialized for COM. Marshal interfaces or
recreate them from owned identifiers; never pass an apartment-bound `IShellItem*` raw
to another thread. Completion messages update history and refresh affected open panels
on the UI thread. Do not manipulate native panels from a worker callback.

## Collisions and irreversible operations

Before undo or redo, validate the recorded object's identity and source/destination state.
Refuse to act on a different object that has appeared under the same path. Missing objects,
offline volumes, emptied Recycle Bins, and uncertain identity produce an unavailable record
with a reason, not a success. Treat directories, hard links, junctions, network providers,
and archive-backed paths conservatively until their identity semantics are validated.

Never silently overwrite an existing name during replay. A preflight alone has a race;
Shell conflict handling and post-operation verification remain necessary. Replays must not
inherit the native `FOF_NOCONFIRMATION` policy that could accept replacement automatically.

Initial moves that replaced another object or merged directory contents are not fully
reversible from source/destination paths alone. Version one must mark those batches as
unavailable/barriers unless it has proved no replacement/merge occurred. Full support
requires preserving the displaced destination before mutation and journaling the exact
merge effects. If the sink cannot establish whether replacement happened, fail closed on
reversibility. Do not advertise all successful moves as undoable.

**Shift+Delete remains permanent.** Kind 3 and kinds 8/9 do not gain a false undo entry.
If an ordinary Delete on a non-recyclable location permanently deletes an item, the null
recycle result makes that item unavailable too. Making permanent deletion reversible
would require an explicit change to deletion semantics and backup storage; it is not
part of this design. Manual restore/empty-bin operations invalidate affected records;
external Explorer actions are caught by identity validation before replay.

## Native keybinding design

Verified current defaults are `HK_TextUndo = Ctrl+Z` and
`HK_TextRedo = Ctrl+Shift+Z`. Their registration sites use context mask `0x10`.
Trash and Delete use mask `6`; the registrar stores the mask at descriptor `+0x38`
and the callback at `+0x30`. Text callbacks dispatch event `0x17` / `0x18` through
the active context selected by app `+0xc74` and must remain intact.

Add native descriptors with the file-command context mask and the same group as Trash:

| Command | Default | Behavior |
| --- | --- | --- |
| `HK_FileUndo` | Ctrl+Z | Undo newest eligible file batch |
| `HK_FileRedo` | Ctrl+Y | Redo newest undone file batch |
| `HK_FileRedoAlternate` | Ctrl+Shift+Z | Same redo callback; configurable alternate |

Use `0x140036880` with counted key strings and primary-binding offset zero for each
descriptor. This avoids guessing the native secondary-binding format. Descriptors must
survive config loading/reloading and appear under meaningful labels such as “Undo File
Operation” and “Redo File Operation”, rather than untranslated resource keys.

Native file callbacks shown in `keybinds.txt` use `param_3 == 2` as execution, with
other calls checking availability. The new callbacks must preserve that convention:
availability checks do not mutate stacks, and execution queues one replay. Return
disabled/unavailable when history is empty, busy, blocked, or unavailable.

The observed context masks are a candidate for correct routing, not a completed focus
test. Verify them in rename, search, address entry, command palette, native edit controls,
modal dialogs, file lists, split panes, and secondary windows. Add an explicit native
focus check if needed. Text-focused Ctrl+Z / Ctrl+Shift+Z must continue to use text
history even when there is a file batch waiting. Holding a key must not replay a batch
multiple times; use native press semantics and the coordinator's in-flight latch.
Do not install a global Windows hotkey or a GetAsyncKeyState polling loop.

## Implementation and acceptance plan

1. Build a standalone scratch-directory harness for the sink and replay engine. Verify
   exact recycle-item restoration and refreshed redo identities before injecting it.
2. Add native worker/completion hooks in record-only mode; compare batch records against
   actual move/delete outcomes, including cancellation and destination renaming.
3. Add replay, identity/conflict checks, barriers, busy coordination, and partial states.
4. Add native commands and labels; test config persistence and every focus context.
5. Integrate with the existing 0.8.5 patch components and build a separate experimental
   executable with manifest/rollback instructions. Keep the original executable available.

Required runtime matrix (all disposable test files):

| Scenario | Required result |
| --- | --- |
| Single and multi-file move; same and different volumes | One batch; correct undo/redo paths and contents |
| Delete -> undo -> redo -> undo | Exact objects restored; recycle identity refreshed each cycle |
| Cancel before work / cancel midway / access denied | No phantom items; successful subset remains represented |
| Same-name conflict / directory merge / overwrite | No silent loss; unavailable unless full reversal data exists |
| Destination object externally replaced | Refuse to move/delete the replacement |
| Empty Recycle Bin / manual restore / disconnected disk | Clear unavailable reason; no fabricated success |
| Shift+Delete | Remains permanent; cannot be offered as reversible |
| Rename box / search / path editor / modal dialog | Native text undo preserved; file history untouched |
| Two windows, simultaneous jobs, rapid/repeated keys | Shared ordered history; no double replay or deadlock |
| Undo then new successful move/delete | Redo cleared; failed no-op does not clear it |
| Long Unicode names, folders, case-only names | No truncation; correct identity and name handling |
| Drag/drop, cut/paste, menu actions, native commands | Coverage measured; bypasses explicitly identified |
| Archive payload and Shell extensions | Unsupported mutations barred; no temporary archive paths recorded as ordinary files |

Static validation completed: original hash accepted; all 17 recorded instruction seams
and both COM GUIDs match; mutated-code, truncated, and arbitrary inputs rejected.
No sink, restore replay, injected keyboard handler, or patched executable has been
runtime-tested. Those are implementation tasks, not implied by the static checks.

Reproduce the static audit from the `File Pilot` directory:

```powershell
python .\analysis\undo-0.8.5\audit_seams.py .\ghidra\project\FPilot.exe `
  --self-test --output .\analysis\undo-0.8.5\seams.json
```

Reproduce the focused Ghidra evidence using the existing `FilePilotArchiveTrace.java`
script with the same read-only flags and addresses `140233300`, `1402333b0`,
`140232b50`, `140232b18` (file engine), then `only:14008a900`, `only:14008a840`,
`only:1400260d0`, `only:140036880`, `140110ae0`, `140110410` (bindings and callers).
Do not run two headless instances against the same project simultaneously.
