# Preserve the mouse's position within a torn-off tab

## Desired invariant

Let `G` be the point where the user grabbed the source tab, expressed relative
to that tab's top-left. Let `Tnew` be the new child's tab-header top-left in
screen coordinates. The placement invariant is:

```text
releaseCursor = Tnew + G
```

Equivalently, after the child has laid out its tab strip:

```text
windowTopLeft += releaseCursor - (newTabTopLeft + G)
```

This keeps the same part of the tab under the pointer instead of putting the
new window's corner under the pointer.

## Recommended scheme

### 1. Capture the grip when the drag becomes active

The drag becomes active around `0x14016CFD3-0x14016CFDA`; the latter stores the
dragged object at application-state offset `+0xEA8`. At that moment record:

```text
grabX = mouseDownScreenX - draggedTabRectScreenLeft
grabY = mouseDownScreenY - draggedTabRectScreenTop
```

The tab renderer already has the dragged header's rectangle during this pass,
so capture it there rather than reconstructing it at release. Store the grip in
device-independent units, or as fractions of the tab width and height, so a
tear-off onto a monitor with different DPI remains stable.

The existing `+0xEA0/+0xEA4` pair is not the grip. Static and live inspection
showed that it receives the source viewport's screen origin from
`[DAT_140247018+0x10]+8/+0xC`; one trace produced `(192,25)`, matching the
source viewport. It can help convert local tab geometry to screen geometry but
should not be treated as the click offset.

### 2. Capture the release point synchronously

Capture `releaseCursorX/Y` in `FUN_140179040` when command `0x58` is emitted, or
at the start of the outside-drop block `0x14016D355`. Do not leave this to the
asynchronous worker at `FUN_140203B70`.

The live traces showed a measurable interval between mouse release and the
worker's `GetCursorPos`; the cursor can move during that interval. The release
coordinates therefore need to travel with the queued tear-off operation.

### 3. Carry placement metadata with the tear-off

Preferred metadata:

```c
struct TearOffPlacement {
    uint32_t magic;       // e.g. 'FPT1'
    int32_t releaseX;
    int32_t releaseY;
    float   grabU;        // 0..1 across the source tab
    float   grabV;        // 0..1 down the source tab
};
```

Only command `0x58` outside drops create this metadata. The ordinary
**Duplicate Tab To New Window** action continues passing no placement record.

There are two suitable transport choices:

1. Add a `"TearOff"` object alongside `"Panel"` in the existing JSON.
2. Publish a second registered clipboard format, for example
   `FilePilot-TearOffPlacement`, before launching the child.

The second format is less invasive to the panel serializer. The child must read
both formats in `FUN_1401F8BF0` before its existing `EmptyClipboard` call.

Do not place this metadata in the asynchronous job built by
`FUN_14010D7C0`. Runtime inspection proved that its inline serialized JSON
begins at `job +0x58`; `+0x58/+0x5C` are payload bytes, not spare fields.
Overwriting them truncates/corrupts the panel JSON and makes the child fall back
to its default user-profile path.

### 4. Correct placement after the child knows its real tab rectangle

The child should initially create the window hidden at the provisional
`STARTF_USEPOSITION` point. Once its first/dragged tab header has been laid out,
compute:

```text
gripPixelsX = grabU * newTabWidth
gripPixelsY = grabV * newTabHeight

deltaX = releaseX - (newTabScreenLeft + gripPixelsX)
deltaY = releaseY - (newTabScreenTop  + gripPixelsY)

SetWindowPos(hwnd, ..., windowLeft + deltaX, windowTop + deltaY,
             0, 0, SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE)
```

Perform this once, then clear the tear-off placement record. This naturally
handles:

- a source tab in any slot becoming the child's first tab;
- different tab widths caused by title length;
- quick-access/sidebar width differences;
- window-frame and custom-titlebar offsets;
- per-monitor DPI changes.

The existing conditional startup trampoline at `0x1401DEC14` remains useful:
it prevents saved session geometry from overriding the provisional placement.
The one-shot correction can live near `FUN_140204DE0`, which already applies
window geometry, or immediately after the first tab-layout pass.

### 5. Clamp only for visibility

After computing the exact position, intersect the proposed window rectangle
with the destination monitor's work area. Preserve the grip invariant unless
it would leave the entire title/tab strip inaccessible; in that case shift the
minimum amount required to keep a usable strip onscreen.

## Smaller alternative

If a compact patch is preferred over exact behavior, calculate the desired
top-left entirely in the parent:

```text
desiredX = releaseX - (firstTabLocalX + grabX)
desiredY = releaseY - (firstTabLocalY + grabY)
```

Store `desiredX/Y` in a dedicated process-private pending record. The worker
uses that record for provisional startup placement and publishes it in the
registered clipboard format. This preserves the original job layout and JSON.

## Validation matrix

Test at least:

1. one tab, grab near its left edge;
2. one tab, grab near its close button;
3. middle tab from a three-tab window;
4. a long-title tab and a short-title tab;
5. source and destination monitors with different DPI;
6. source near every monitor edge;
7. ordinary duplicate-to-new-window and normal startup, which must retain their
   previous placement behavior.

## Implemented compact scheme

The separate build `FPilot-tab-relative-fixed.exe` implements the
parent-side calculation without hard-coding a complete tab width:

- input-state `+0x58/+0x5C` retains the original mouse-down point;
- the dragged panel's UI item state exposes the full tab rectangle at
  `+0x290/+0x294` through `+0x298/+0x29C`;
- the drag-activation hook at `0x14016CFD3` calculates the grip and translates
  it to the first-tab anchor, including the Windows resize-frame width;
- a private record at `.fpd` RVA `0x278000` holds anchor X, anchor Y, an
  `FPT1` validity value, and the raw tab-relative grip X/Y between activation
  and release;
- the `FUN_140185260` call site samples `GetCursorPos` synchronously immediately
  before the async job is queued and writes a separate outbound pending record;
- `FUN_140203B70` publishes that record as `FPT2` and uses its desired
  coordinates for provisional placement, while retaining the old
  `GetCursorPos` fallback for non-tear-off requests;
- the child copies `FPT2` into a distinct inbound record. The per-frame apply
  hook watches only this child record, so the source HWND cannot be moved;
- no job bytes or nonvolatile-register prologue/epilogue slots are modified.

Injected code lives in an executable/readable `.fpt` section at RVA
`0x277000`; the process-private record lives in a separate readable/writable
`.fpd` section at RVA `0x278000`. Application `+0xEA0/+0xEA4` retain their
native source-viewport origin; the placement patch no longer uses them as grip
storage.

The same raw grip now positions the two native drag-helper windows without
touching renderer geometry. Dynamic watchpoints showed that renderer `+0xD4`
feeds `CreateFontW` in the `File Pilot - Drag Text` path; treating those fields
as rectangle edges caused the oversized tooltip regression. The corrected
hook at `0x14020518F`, immediately after the native Drag Image and Drag Text
dispatch calls, applies `SetWindowPos` with
`SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE`. Applying the correction last
prevents the native render pass and the patch from alternating positions. The
image top-left is `cursor - (rawGripX, rawGripY)`, so the pointer occupies the
same point in the drag image as it did in the source tab. Neither helper's
native width, height, bitmap, nor font is modified.

The existing single-tab and child-geometry patches remain in force. A
per-monitor-DPI-aware no-debugger test grabbed a tab 130 pixels from the
configured tab slot, released at `(1800,650)`, and measured both expected and
actual child outer-window coordinates as `(1475,635)`. Thus the cursor retained
the same `(325,15)` position relative to the outer window.

The final matched live comparison measured the original helper windows as
`120x25` (Drag Image) and `122x25` (Drag Text). The patched executable produced
the same `120x25` and `122x25` sizes. With raw grip `(28,14)` and cursor
`(1280,576)`, the patched image rectangle began at `(1252,562)`, preserving the
grip exactly. On release, window anchor `(151,19)` produced a child outer-window
origin of `(1129,557)`, exactly `release - anchor`.
