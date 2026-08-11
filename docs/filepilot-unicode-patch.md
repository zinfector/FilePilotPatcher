# File Pilot Unicode patch

## Outcome

The combined patch makes File Pilot 0.8.2 render ordinary Chinese, Arabic,
Korean, symbol, and monochrome emoji filenames on a stock Windows installation.
It keeps measurement and drawing consistent through DirectWrite, accepts UTF-16
surrogate pairs from `WM_CHAR`, removes the two ASCII-only caret clamps, and
prevents a bounded copy from ending in a partial UTF-8 sequence.

The patch does not add grapheme-aware editing, normalization, locale-sensitive
collation, or layered color-emoji composition. Those remain File Pilot or future
renderer concerns.

## Fixed D3D-atlas renderer

The Unicode payload has one production renderer. It has no environment selector
and no alternate runtime arms. Building with `-All` always installs
`d3d-atlas` alongside Open File Location and the tab patches.

DirectWrite shapes visible extended text with system font fallback. The payload
rasterizes each shaped row to ClearType coverage, selects the channel matching
File Pilot's native glyph atlas, uploads an immutable R8 mask, and draws it on
File Pilot's own D3D11 immediate context. A 128-entry shaped-run cache and a
128-entry row-mask cache avoid repeating shaping and upload work.

The renderer captures File Pilot's configured font object, path, and point size
at the native atlas-creation seam. It uses the verified `size * 4/3` DirectWrite
em-size conversion, retains recognized configured families such as Segoe UI and
Consolas, selects deterministic Windows fallback families per script, and aligns
overlay origins to the native integer pixel grid.

Native File Pilot multiplies all color channels by mono-atlas coverage and uses
premultiplied-alpha composition. The injected pixel shader follows the same
order: its source blend is `ONE` and its destination blend is
`INV_SRC_ALPHA`. This avoids the second coverage multiply that produced black
contours on bright selection backgrounds.

File Pilot can submit an identical label several times between presentations
during invalidation and selection transitions. The queue identifies a logical
label by text, rectangle, alignment, height, em size, and family, retains one
packet, and applies the latest color. This prevents redundant edge overdraw and
keeps selection transitions stable.

The D3D device hook restores File Pilot's compact native glyph ranges before
font jobs rasterize them. This removes the 49,088-code-point startup and
folder-open workload. DirectWrite performs shaping and font fallback only for
visible extended rows, and the caches amortize repeat visits.

The Direct3D device calls are wrapped to request
`D3D11_CREATE_DEVICE_BGRA_SUPPORT`. The overlay is inserted at the one verified
File Pilot Direct3D frame call immediately before `IDXGISwapChain::Present`.
On OpenGL, or if the D3D resources cannot be created, the hooks
leave File Pilot's native text enabled and record a backend fallback instead of
hiding labels. A resize releases cached row layouts and the old back-buffer target
before File Pilot calls `ResizeBuffers`.

The renderer is initialized before native text dispatch for a frame. It suppresses
native text only when its pipeline and current render-target view are ready, so
there is no first-frame native-plus-overlay transition. It uses the same
immediate context as File Pilot, and snapshots/restores its render targets,
input assembly, shaders, resource/sampler, blend, depth/stencil, rasterizer, and
scissor state around every overlay batch. File Pilot can replay an identical
label several times between two presentations during invalidation and selection
transitions. The queue now identifies a logical label by text, rectangle,
alignment, height, em size, and family, retains only one packet, and applies the
latest submitted color. Distinct labels and positions are unaffected.

The fixed script policy assigns Segoe UI to
Arabic, Microsoft YaHei to CJK, Malgun Gothic to Korean, Nirmala UI to Indic,
and the Segoe symbol/emoji families to their corresponding ranges. Latin and
the extension retain the configured File Pilot family.

File Pilot's UI icons are deliberately never sent to Segoe UI. Their verified
private-use ranges remain on the native icon-font path.

### Runtime telemetry and validation

`build_patch.ps1 -All` writes a sibling `<output>.unicode.json` manifest that
identifies `d3d-atlas` as the fixed renderer and records the telemetry RVA. The
payload exports readiness, fallback/error, cache, frame, upload, coalescing, and
cumulative shaping/drawing counters. Healthy D3D operation has no backend or
atlas failures, builds one mask per distinct row, converges toward cache hits,
and keeps `D3DAtlasDrawCalls == OverlayDrawn`.

In the four-filename smoke workload, the renderer built four masks, reached
32-36 cache hits, coalesced 160-176 redundant label submissions, and recorded no
backend or atlas failures. In a 120-frame selection probe, the settled final 60
captures were pixel-identical. The transition images were File Pilot's selection
animation; glyph edges no longer darkened or accumulated across those frames.

## Implementation plan and completed work

1. Validate every hook seam against the exact File Pilot 0.8.2 SHA-256 before
   writing an output. The patch fails closed on a different binary.
2. Restore File Pilot's compact glyph ranges before its font jobs start, so
   startup does not rasterize tens of thousands of unused code points.
3. Shape visible extended rows with DirectWrite, system font fallback, and the
   configured File Pilot font metrics.
4. Rasterize and cache R8 glyph masks, then composite them through File Pilot's
   immediate D3D11 context with native-equivalent premultiplied blending.
5. Accumulate high and low UTF-16 surrogates at the one-character `WM_CHAR`
   conversion site before calling File Pilot's UTF-8 codec.
6. Remove the two code-point clamps that forced caret input back into the ASCII
   range, and make bounded UTF-8 copies stop on a code-point boundary.
7. Regression-test exact call-site counts, fixed renderer metadata, icon
   preservation, hook destinations, and the fail-closed profile. Smoke-test
   real filenames in a running patched executable.

All seven steps are implemented. The injected payload has no CRT or new static
DLL dependency; DirectWrite is resolved at runtime.

## Patched regions

The patcher validates and redirects these File Pilot regions:

| Region | File Pilot 0.8.2 address | Patch |
| --- | ---: | --- |
| Glyph lookup | `0x14010AA50` | Five callers routed through the Unicode payload |
| Text measurement | `0x1401B78F0` | All 38 direct callers use the same Arabic transform as drawing |
| Text renderer | `0x1401B82F0` | Its direct dispatch caller is routed through the shaper |
| Font atlas wrapper | `0x140216580` | Three callers capture configured font metrics and retain native fallback support |
| Native font rasterizer | `0x140215C70` | Reused by the isolated `.ttc` path |
| `WM_CHAR` UTF-16-to-UTF-8 call | `0x14020B59A` | Surrogate pairs are accumulated before conversion |
| Glyph range table | `0x140245DC0` | Restored to compact native ranges by the D3D device hook |
| Caret clamps | `0x1401D0DBA`, `0x1401D11FD` | ASCII-only conditional moves are removed |
| `D3D11CreateDevice` calls | `0x14004892B`, `0x14004897A` | Request BGRA interoperability and initialize compact ranges |
| Direct3D frame call | `0x1401EDB49` | D3D-atlas overlay runs after native drawing and before `Present` |

The separate shell/tab payload's bounded copy helper is also corrected so a
truncated filename cannot contain an incomplete UTF-8 sequence.

## Glyph and font coverage

Latin, Cyrillic, arrows, and File Pilot's verified private-use icon ranges stay
on the native path. Arabic-family scripts, CJK, Hangul, Indic scripts, symbols,
and supplementary-plane text use DirectWrite shaping and installed Windows font
fallback on demand. The fixed-size caches bound memory independently of Unicode
block size. Actual glyph availability still depends on installed fonts.

## Build and verification

From the repository root:

```powershell
python -m pip install lief capstone
& .\patcher\build_patch.ps1 -All
python -m unittest discover -s .\patcher -p 'test_*.py' -v
```

Runtime smoke coverage used these filenames:

- `报告-中文.txt`
- `مرحبا-العربية.txt`
- `한국어-파일.txt`
- `emoji-😀.txt`

Chinese, Arabic, Korean, and the monochrome emoji fallback rendered and the
process remained responsive. A synthetic `WM_CHAR` pair for `U+1F600` reached
the hook as one valid surrogate pair. Layered color emoji remain outside this
patch.

## Remaining limitations and follow-up options

- DirectWrite provides shaping and bidirectional layout, but a missing system
  font can still produce a replacement glyph.
- Emoji and other supplementary-plane characters can enter the UTF-8 and
  DirectWrite paths, but the renderer uses monochrome glyph masks rather than
  layered color emoji.
- Configured font-file recognition is still a bounded filename-to-family map.
  An unrecognized custom font file currently falls back to Segoe UI in all
  the fallback renderer.
- Case folding, collation, word boundaries, grapheme-aware cursor movement,
  and normalization retain File Pilot's original behavior.
- The Unicode renderer requires File Pilot's Direct3D backend. OpenGL
  deliberately falls back to File Pilot's native text path.
- File Pilot still animates selection and hover state. Those deliberate
  background-transition frames remain, but glyph edges no longer darken or
  accumulate across them.
