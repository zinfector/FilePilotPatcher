# File Pilot Unicode patch

## Outcome

The combined patch makes File Pilot 0.8.2 render ordinary Chinese, Arabic,
Korean, symbol, and monochrome emoji filenames on a stock Windows installation.
DirectWrite provides shaping and system-font fallback. The input hook accepts
UTF-16 surrogate pairs, the two ASCII-only caret clamps are removed, and bounded
copies cannot end in a partial UTF-8 sequence.

The current renderer is carrier-free. It does not install a Direct3D device hook,
a frame hook, a draw-batch hook, a private shader, or a custom command type.

## Native row-resource design

File Pilot already knows how to turn a stable CPU texture descriptor into a
backend resource and emit an ordinary type-0 textured quad. The patch now uses
that contract directly:

1. DirectWrite shapes an extended-text row with the configured File Pilot size
   and Windows font fallback.
2. The shaped runs are rasterized into a tightly bounded, one-channel coverage
   image with a one-pixel transparent gutter.
3. The coverage image is stored in File Pilot's native 0x28-byte texture
   descriptor as an immutable `R8_UNORM` resource.
4. The Unicode render hook constructs the same full-texture image style used by
   File Pilot, copying the caller's native color and preserving its current clip,
   command position, and menu/window transform.
5. The hook calls File Pilot's verified native quad emitter directly with the
   cached row resource and destination rectangle.

The command stream therefore contains only the final native row quad. There is
no second pass through File Pilot's native text renderer, no transparent carrier
to draw, no marker to search for, no deferred overlay to replay, and no
frame-variant packet metadata. Once a row is cached, the resource descriptor and
emitted command bytes remain stable across idle frames, allowing File Pilot's
existing command-hash short circuit to work again.

The caches are deliberately bounded: 128 shaped-run entries, 256 native row
resources, at most 512 UTF-16 units and 512 glyphs per row. Cache misses are
rasterized on demand; repeated folder rows and menu labels are cache hits.

Arabic uses Segoe UI, CJK uses Microsoft YaHei, Korean uses Malgun Gothic, Indic
scripts use Nirmala UI, and symbols/emoji use their Segoe families. File Pilot's
private-use icon ranges remain on its original compact native atlas path.

## Why this removes the menu delay

The previous implementation inserted a native carrier, captured its transformed
geometry, replaced marker instances inside File Pilot's Direct3D batch, and
restored a custom graphics pipeline afterward. Even when a label did not change,
per-frame packet and marker state changed. That defeated the native renderer's
unchanged-command fast path and kept the UI thread and GPU dispatch path active;
right-click menu construction then competed with that work.

The redesigned path stops above the backend boundary. It uses the native texture
descriptor and calls the native quad emitter exactly once, so unchanged Unicode rows are
indistinguishable from stable image commands to the rest of File Pilot.

## Runtime telemetry and validation

`build_patch.ps1 -All` writes a sibling `<output>.unicode.json` manifest with
`renderer: native-row-resource`, `transform: direct-native-emitter`, command type 0,
and the telemetry RVA. Version 8 telemetry records measurement/render calls,
shape and row-cache hits/misses, row builds, submissions, uploaded bytes,
failures, fallback counts, font metrics, and the last DirectWrite/row status.

The development smoke test rendered Chinese, Arabic, Korean, and emoji rows with
zero row failures or backend fallbacks. The frame counter remained unchanged
over a two-second idle interval, confirming that the old continuous dispatch
loop was gone. Across the automated context-menu probes, message dispatch took
12–15 ms versus 12 ms for the untouched executable, and the first menu render
arrived after 14–18 ms. This is a local validation, not a performance guarantee.

## Patched regions

The patcher validates these File Pilot regions and redirects only the hook rows:

| Region | File Pilot 0.8.2 address | Patch |
| --- | ---: | --- |
| Text measurement | `0x1401B78F0` | All 38 direct callers use DirectWrite for extended text |
| Text renderer | `0x1401B82F0` | Its direct dispatch caller submits cached native rows |
| Font atlas wrapper | `0x140216580` | Three callers capture configured font metrics |
| Native font rasterizer | `0x140215C70` | Retained for the isolated `.ttc` compatibility path |
| `WM_CHAR` UTF-16-to-UTF-8 call | `0x14020B59A` | Surrogate pairs are accumulated before conversion |
| Caret clamps | `0x1401D0DBA`, `0x1401D11FD` | ASCII-only conditional moves are removed |
| Native quad emitter | `0x1401B9B50` | Called directly by the Unicode hook; the known call at `0x1401B8F9C` validates its identity and remains unpatched |

The native glyph-range table at `0x140245DC0` is validated but not modified.
There are no patched native-quad, `D3D11CreateDevice`, frame-lifecycle, or draw-batch calls.
The separate shell/tab payload's bounded copy helper also prevents an incomplete
UTF-8 tail.

## Build and verification

From the repository root:

```powershell
python -m pip install lief capstone
& .\patcher\build_patch.ps1 -All
python -m unittest discover -s .\patcher -p 'test_*.py' -v
```

Runtime smoke coverage uses filenames such as:

- `报告-中文.txt`
- `مرحبا-العربية.txt`
- `한국어-파일.txt`
- `emoji-😀.txt`

## Remaining limitations

- A cold row-cache miss still performs DirectWrite shaping and rasterization on
  the calling thread; normal redraws and later menu opens reuse the cached row.
- Missing system fonts can still produce a replacement glyph.
- Emoji are monochrome masks rather than layered color glyphs.
- Configured font-file recognition uses a bounded filename-to-family map; an
  unrecognized custom font currently falls back to Segoe UI.
- Grapheme-aware editing, normalization, locale-sensitive collation, word
  boundaries, and full bidirectional editing retain File Pilot's behavior.
- The native descriptor/quad contract is backend-facing rather than D3D-specific,
  but the current runtime validation was performed with File Pilot's Direct3D
  backend.
