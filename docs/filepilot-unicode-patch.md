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

## Native-inline renderer A/B modes

DirectWrite shapes visible extended text with system font fallback. The payload
captures File Pilot's configured font object, path, and point size at the native
atlas-creation seam and uses the verified `size * 4/3` DirectWrite em-size
conversion. Arabic uses Segoe UI, CJK uses Microsoft YaHei, Korean uses Malgun
Gothic, Indic scripts use Nirmala UI, and symbols/emoji use their Segoe families.
File Pilot's private-use icon ranges stay on its native icon-font path.

The previous renderer replayed all Unicode after File Pilot's frame renderer.
That made background filenames topmost when a popup covered them, and its label
rectangle could not reproduce nested menu/window scissors. The new implementation
hooks both native calls to `FUN_14004A690`, File Pilot's D3D glyph-batch helper.
Unicode now executes at the marker's original command position, after File Pilot
has selected the correct render target and native clip rectangle.

File Pilot also applies menu/window animation while building each native
0x48-byte glyph instance. The payload hooks the verified native quad-emitter call
at `0x1401B8F9C` and turns the invisible carrier into a 4096-pixel transform
probe. File Pilot transforms that known rectangle itself; the payload derives an
anchored affine transform from the four resulting corners and applies it to the
DirectWrite row or glyph quads. This preserves nested translation, scale,
rotation, skew, and mirroring without depending on the private matrix-stack
layout.

The A/B modes are:

- `row-texture` (proposition 1, default): File Pilot emits one transparent native
  carrier glyph. The batch hook replaces it with one cached, DirectWrite-shaped
  R8 row texture.
- `shaped-glyph` (proposition 2): the same carrier selects a shared 2048x2048 R8
  glyph page. DirectWrite glyph IDs, advances, offsets, fallback faces, and bidi
  levels produce individual quads. Baselines are snapped to File Pilot's integer
  pixel grid to prevent filtering shimmer.
- `custom-command` (proposition 4): the payload calls File Pilot's verified native
  command allocator, records the live clip/target IDs, and appends a custom marker
  instance directly. The batch hook draws a row texture when it sees that marker.
  If the frame vector has no spare slot, this mode falls back to the transparent
  native carrier rather than corrupting the list.

Set `FPILOT_UNICODE_NATIVE_MODE` to one of those names before process startup.
Unknown or absent values select `row-texture`.

Animation behavior has an independent A/B selector. `native-probe` is the
default; `legacy` retains the former static-rectangle placement:

```powershell
$env:FPILOT_UNICODE_TRANSFORM_MODE = 'native-probe'
# or: $env:FPILOT_UNICODE_TRANSFORM_MODE = 'legacy'
```

The row cache has 128 entries. The shaped-glyph arm retains the existing
128-entry shape cache and up to 1024 glyph records on its page. Texture and shape
assets remain reusable. Native-probe packets are coalesced only after capture and
only when their complete affine transform and other draw state match, so different
parent animations cannot merge. Every carrier remains in the command stream. The
active native scissor is intersected with the transformed label bounds and viewport.

Native File Pilot multiplies all color channels by mono-atlas coverage and uses
premultiplied-alpha composition. The injected shader matches its `ONE` /
`INV_SRC_ALPHA` blend. The inline draw snapshots and restores render targets,
input assembly, shaders, resources/samplers, blend, depth/stencil, rasterizer,
and scissors. It deliberately keeps the render target selected by File Pilot.

The D3D device hook restores File Pilot's compact native glyph ranges before font
jobs start, eliminating the former 49,088-code-point startup/folder-open workload.
DirectWrite work is limited to visible extended rows. On OpenGL or failed D3D
initialization, the native text path stays enabled and telemetry records a backend
fallback.

### Runtime telemetry and validation

`build_patch.ps1 -All` writes a sibling `<output>.unicode.json` manifest with the
selectors, modes, and telemetry RVA. Version 7 telemetry includes the selected
renderer and transform modes, transform captures/failures, animated draws, probe
markers, validation residual, marker submission/draw counts, native batch splits,
custom-command fallbacks, and shaped-glyph build/hit/draw counters.

`benchmark_unicode_native_modes.ps1` cold-starts the three renderer arms under
both `legacy` and `native-probe` placement against the four multilingual
filenames. Earlier renderer-only samples reached first Unicode drawing in roughly
240-370 ms; results are machine- and cache-dependent.
The native-probe smoke run reported zero transform-capture failures, packets left
undispatched, backend fallbacks, custom-command fallbacks, and atlas failures in
all three renderer arms after transform-aware coalescing. These figures are a
local comparison, not a performance guarantee.

## Implementation plan and completed work

1. Validate every hook seam against the exact File Pilot 0.8.2 SHA-256 before
   writing an output. The patch fails closed on a different binary.
2. Restore File Pilot's compact glyph ranges before its font jobs start, so
   startup does not rasterize tens of thousands of unused code points.
3. Shape visible extended rows with DirectWrite, system font fallback, and the
   configured File Pilot font metrics.
4. Rasterize and cache R8 row/glyph masks, insert a carrier at File Pilot's
   native command position, and composite under the active target and scissor.
5. Capture File Pilot's native carrier transform and apply it to every Unicode
   row/glyph quad so menu and window animation remains native.
6. Accumulate high and low UTF-16 surrogates at the one-character `WM_CHAR`
   conversion site before calling File Pilot's UTF-8 codec.
7. Remove the two code-point clamps that forced caret input back into the ASCII
   range, and make bounded UTF-8 copies stop on a code-point boundary.
8. Regression-test exact call-site counts, A/B metadata, command/draw seams, icon
   preservation, hook destinations, and the fail-closed profile. Smoke-test
   real filenames in a running patched executable.

All eight steps are implemented. The injected payload has no CRT or new static
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
| Native command allocator | `0x1401B99C0` | Proposition 4 appends a clip/target-aware carrier node |
| Native quad-emitter call | `0x1401B8F9C` | Invisible carriers capture File Pilot's exact affine animation transform |
| Native D3D batch calls | `0x140049B30`, `0x140049C37` | Inline markers are replaced at their original draw position |
| Direct3D frame call | `0x1401EDB49` | Initializes resources, handles resize, and retires per-frame packet data |

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
& .\patcher\benchmark_unicode_native_modes.ps1
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
  three native-inline modes.
- Case folding, collation, word boundaries, grapheme-aware cursor movement,
  and normalization retain File Pilot's original behavior.
- The Unicode renderer requires File Pilot's Direct3D backend. OpenGL
  deliberately falls back to File Pilot's native text path.
- File Pilot still animates selection and hover state. Those deliberate
  background-transition frames remain, but glyph edges no longer darken or
  accumulate across them.
