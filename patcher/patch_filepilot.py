"""Discover and apply the File Pilot Open File Location and tab-transport patches.

The locator intentionally fails closed. It uses masked structural signatures and exception-table
function boundaries to find the required native regions, derives their call targets and structure
offsets from disassembly, resolves every Windows API through the target's import table, and
validates cross-references before writing. The tab tear-off extension is additionally gated to an
exact build profile because its hooks depend on register and stack layouts at native instruction
seams. Use --open-location-only to emit only the shell integration.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import lief
from capstone import CS_ARCH_X86, CS_MODE_64, Cs
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG

from tab_relative import SUPPORTED_SHA256 as TAB_SUPPORTED_SHA256, apply_tab_patch


KNOWN_SHA256 = {
    "08826147a90e7c6a1c4e80968aaa927b14cfbca7271c7d12db3af9f24c483646":
        "File Pilot 0.8.2 x64",
}
PAYLOAD_IMAGE_BASE = 0x140270000
PAYLOAD_FIRST_RVA = 0x1000
BINDINGS_MAGIC = 0x53474E4942504C46
BINDINGS_VERSION = 22
BINDINGS_QWORDS = 41
UNICODE_PAYLOAD_FIRST_RVA = 0x1000
UNICODE_BINDINGS_MAGIC = 0x53474E4942555046
UNICODE_BINDINGS_VERSION = 5
UNICODE_BINDINGS_QWORDS = 22
UNICODE_SUPPORTED_SHA256 = {
    "08826147a90e7c6a1c4e80968aaa927b14cfbca7271c7d12db3af9f24c483646":
        "File Pilot 0.8.2 x64 Unicode profile",
}
UNICODE_GLYPH_LOOKUP_RVA = 0x10AA50
UNICODE_MEASURE_TEXT_RVA = 0x1B78F0
UNICODE_RENDER_TEXT_RVA = 0x1B82F0
UNICODE_FONT_CREATE_ATLAS_RVA = 0x216580
UNICODE_FONT_RASTERIZER_RVA = 0x215C70
UNICODE_UTF16_TO_UTF8_RVA = 0x1DD750
UNICODE_INPUT_CONVERSION_CALL_RVA = 0x20B59A
UNICODE_RANGE_TABLE_RVA = 0x245DC0
UNICODE_D3D_CREATE_DEVICE_RVA = 0x2168E4
UNICODE_D3D_RENDER_FRAME_RVA = 0x49350
UNICODE_D3D_RENDER_FRAME_CALL_RVA = 0x1EDB49
UNICODE_D3D_RENDERER_GLOBAL_RVA = 0x2474D8
UNICODE_NATIVE_QUAD_EMITTER_RVA = 0x1B9B50
UNICODE_NATIVE_QUAD_CALL_RVA = 0x1B8F9C
UNICODE_NATIVE_COMMAND_ALLOCATOR_RVA = 0x1B99C0
UNICODE_D3D_DRAW_BATCH_RVA = 0x4A690
UNICODE_D3D_DRAW_BATCH_CALL_RVAS = (0x49B30, 0x49C37)
UNICODE_NATIVE_RENDER_DATA_GLOBAL_RVA = 0x247298
UNICODE_CARET_CLAMPS = {
    0x1D0DBA: bytes.fromhex("0F 47 D0"),
    0x1D11FD: bytes.fromhex("0F 47 D7"),
}
UNICODE_ORIGINAL_RANGES = (
    (0x0020, 0x007F), (0x0080, 0x00FF), (0x0100, 0x017F),
    (0x0180, 0x024F), (0x0370, 0x03FF), (0x0400, 0x04FF),
    (0x0500, 0x052F), (0x2DE0, 0x2DFF), (0xA640, 0xA69F),
    (0x1C80, 0x1C8F), (0x0300, 0x036F), (0x2000, 0x206F),
    (0x2190, 0x2193), (0xE000, 0xE096), (0xE400, 0xE400),
    (0xE800, 0xE801), (0xEC00, 0xEC00),
)
UNICODE_INITIAL_RANGES = (
    (0x0020, 0x03FF), (0x0400, 0x052F), (0x1C80, 0x2DFF),
    (0x0590, 0x08FF), (0x3000, 0x4DBF), (0x4E00, 0x65FF),
    (0x6600, 0x7DFF), (0x7E00, 0x95FF), (0x9600, 0xA69F),
    (0xAC00, 0xC1FF), (0xC200, 0xD7AF), (0xFB50, 0xFEFF),
    (0x2190, 0x2193),
    (0xE000, 0xE096), (0xE400, 0xE400), (0xE800, 0xE801), (0xEC00, 0xEC00),
)
TAB_SURFACE_RENDERER_RVA = 0x1464E0
TAB_SURFACE_CALL_RVAS = (0x1180A9, 0x1187F5, 0x118904)
TAB_HOVER_HELPER_RVA = 0x1D7860
TAB_HOVER_CALL_RVAS = (0x147AD4, 0x147B14)
INPUT_STATE_GLOBAL_RVA = 0x246F80
FRAME_GENERATION_GLOBAL_RVA = 0x247278


# Displacements, stack sizes, member offsets, and rel32 operands are wildcarded. The surrounding
# instruction relationships are deliberately retained, so a code shift or data-layout adjustment
# can be discovered while an unrelated byte sequence cannot silently pass.
STARTUP_SIGNATURE = (
    "48 8D 95 ?? ?? ?? ?? 48 8D 8D ?? ?? ?? ?? 44 89 7E ?? "
    "E8 ?? ?? ?? ?? 33 D2 48 8D 3D ?? ?? ?? ?? 4C 8D 25 ?? ?? ?? ?? "
    "41 B9 00 00 01 00",
    18,
)
FRAME_SIGNATURE = (
    "B8 04 00 00 00 48 8B CE 41 89 06 E8 ?? ?? ?? ?? "
    "0F 10 86 ?? ?? ?? ?? 48 8D 4D ?? 41 C7 06 08 00 00 00",
    11,
)
LIVE_WRAPPER_SIGNATURE = (
    "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 41 56 41 57 "
    "48 81 EC ?? ?? ?? ?? 4C 8B 8A ?? ?? ?? ?? 48 8B E9 "
    "B9 ?? ?? ?? ?? 49 8B F8 BE ?? ?? ?? ?? 48 8B DA 4D 8B 71 ?? "
    "4D 85 F6 0F 44 F1 48 8B CD 49 03 F1",
    0,
)

PANEL_VIEWPORT_SIGNATURE = (
    "48 89 6C 24 10 48 89 74 24 18 57 48 81 EC ?? ?? ?? ?? "
    "4C 8B 4A 78 4C 8D 1D ?? ?? ?? ?? 33 FF 48 8B F2 44 8B D7 48 8B E9 "
    "0F 1F 84 00 00 00 00 00",
    0,
)

# Three renderers construct command 0x31 in this build.  Discovery selects the one whose
# containing function also tests the inspector-child marker before reaching this sequence.
OPEN_COMMAND_SIGNATURE = (
    "BA 31 00 00 00 48 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? "
    "49 8B 56 ?? 48 8D 8D ?? ?? ?? ?? FF 50 20",
    12,
)

ITEM_INTERACTION_SIGNATURE = (
    "4C 89 4C 24 20 4C 89 44 24 18 48 89 4C 24 08 55 53 56 57 "
    "41 54 41 55 41 56 41 57 48 8D AC 24 ?? ?? ?? ?? "
    "48 81 EC ?? ?? ?? ??",
    0,
)

# Native selection callbacks used to commit the shell-requested item after enumeration.
SELECTION_CANCEL_SIGNATURE = (
    "44 89 44 24 ?? 53 56 57 41 55 41 56 48 83 EC ?? 48 8B 1A 48 8B F9 "
    "4C 89 64 24 ?? 48 85 DB 75 ?? 48 8B 99 ?? ?? ?? ?? 33 F6 33 C0 "
    "F0 0F B1 35 ?? ?? ?? ?? 8B 89 ?? ?? ?? ?? FF C1 3B C8",
    0,
)

# The native Ctrl+Shift+Enter handler.  Its two trailing qwords are the split mode
# (2 == right) and reserved flags passed to the shared selected-item opener.
OPEN_RIGHT_SIGNATURE = (
    "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC ?? 48 8B 3A 48 8B F1 "
    "48 85 FF 75 ?? 48 8B B9 ?? ?? ?? ?? 33 DB 39 9F ?? ?? ?? ?? 75 ?? "
    "48 39 9F ?? ?? ?? ?? 0F 94 C3 EB ?? 48 39 9F ?? ?? ?? ?? 0F 96 C3 "
    "84 DB 75 ?? 41 83 F8 02 75 ?? 48 8B D7 E8 ?? ?? ?? ?? 4C 8D 44 24 20 "
    "48 C7 44 24 20 02 00 00 00 48 8B D7 48 C7 44 24 28 00 00 00 00 "
    "48 8B CE E8 ?? ?? ?? ??",
    0,
)


IMPORT_BINDINGS = (
    "GetCommandLineW",
    "CommandLineToArgvW",
    "LocalFree",
    "GetFileAttributesW",
    "PathRemoveFileSpecW",
    "PathFindFileNameW",
    "SHParseDisplayName",
    "WideCharToMultiByte",
    "GetCurrentThreadId",
    "LoadLibraryW",
    "GetProcAddress",
    "InvalidateRect",
    "PostMessageW",
    "CoCreateInstance",
    "CoTaskMemFree",
    "PropVariantClear",
)


def u16(data: bytes | bytearray, off: int) -> int:
    return struct.unpack_from("<H", data, off)[0]


def u32(data: bytes | bytearray, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def u64(data: bytes | bytearray, off: int) -> int:
    return struct.unpack_from("<Q", data, off)[0]


def align(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


@dataclass(frozen=True)
class SectionRecord:
    name: str
    vsize: int
    rva: int
    raw_size: int
    raw: int


def pe_layout(data: bytes | bytearray):
    pe = u32(data, 0x3C)
    if data[pe:pe + 4] != b"PE\0\0":
        raise ValueError("not a PE file")
    coff = pe + 4
    section_count = u16(data, coff + 2)
    optional_size = u16(data, coff + 16)
    optional = coff + 20
    if u16(data, optional) != 0x20B:
        raise ValueError("expected a PE32+ image")
    if u16(data, coff) != 0x8664:
        raise ValueError("expected an AMD64 executable")
    table = optional + optional_size
    records = []
    for index in range(section_count):
        off = table + index * 40
        records.append(SectionRecord(
            bytes(data[off:off + 8]).rstrip(b"\0").decode("ascii", "replace"),
            u32(data, off + 8), u32(data, off + 12),
            u32(data, off + 16), u32(data, off + 20),
        ))
    return pe, coff, optional, table, records


def rva_to_file(records: Iterable[SectionRecord], rva: int) -> int:
    for section in records:
        size = max(section.vsize, section.raw_size)
        if section.rva <= rva < section.rva + size:
            return section.raw + rva - section.rva
    raise ValueError(f"RVA 0x{rva:x} is not file-backed")


def parse_masked_pattern(specification: str) -> tuple[bytes, bytes]:
    values = bytearray()
    mask = bytearray()
    for token in specification.split():
        if token in {"?", "??"}:
            values.append(0)
            mask.append(0)
        else:
            values.append(int(token, 16))
            mask.append(0xFF)
    return bytes(values), bytes(mask)


def longest_fixed_run(mask: bytes) -> tuple[int, int]:
    best_start = best_size = current_start = current_size = 0
    for index, value in enumerate(mask + b"\0"):
        if value:
            if current_size == 0:
                current_start = index
            current_size += 1
        else:
            if current_size > best_size:
                best_start, best_size = current_start, current_size
            current_size = 0
    return best_start, best_size


def find_masked(data: bytes, specification: str) -> list[int]:
    values, mask = parse_masked_pattern(specification)
    anchor_start, anchor_size = longest_fixed_run(mask)
    if anchor_size < 4:
        raise ValueError("signature has no sufficiently long fixed anchor")
    anchor = values[anchor_start:anchor_start + anchor_size]
    matches = []
    cursor = 0
    while True:
        found = data.find(anchor, cursor)
        if found < 0:
            break
        candidate = found - anchor_start
        if 0 <= candidate <= len(data) - len(values):
            if all(not mask[i] or data[candidate + i] == values[i] for i in range(len(values))):
                matches.append(candidate)
        cursor = found + 1
    return matches


class TargetImage:
    def __init__(self, path: Path):
        self.path = path
        self.data = path.read_bytes()
        self.digest = hashlib.sha256(self.data).hexdigest()
        self.pe, self.coff, self.optional, self.table, self.sections = pe_layout(self.data)
        self.image_base = u64(self.data, self.optional + 24)
        self.section_alignment = u32(self.data, self.optional + 32)
        self.text = next((section for section in self.sections if section.name == ".text"), None)
        if not self.text:
            raise ValueError("target has no .text section")
        self.text_data = self.data[self.text.raw:self.text.raw + self.text.raw_size]
        self.text_va = self.image_base + self.text.rva
        self.binary = lief.PE.parse(str(path))
        if self.binary is None:
            raise ValueError("LIEF could not parse the target")
        if any(section.name == ".fplt" for section in self.sections):
            raise ValueError("target already contains a .fplt section")

    def va_to_file(self, va: int) -> int:
        return rva_to_file(self.sections, va - self.image_base)

    def read(self, va: int, size: int) -> bytes:
        off = self.va_to_file(va)
        return self.data[off:off + size]

    def in_text(self, va: int) -> bool:
        return self.text_va <= va < self.text_va + self.text.raw_size

    def decode_call(self, site_va: int) -> int:
        raw = self.read(site_va, 5)
        if len(raw) != 5 or raw[0] != 0xE8:
            raise ValueError(f"0x{site_va:x} is not a direct rel32 call")
        return site_va + 5 + struct.unpack_from("<i", raw, 1)[0]

    def locate_signature(self, label: str, signature: tuple[str, int]) -> int:
        specification, anchor_offset = signature
        matches = find_masked(self.text_data, specification)
        if len(matches) != 1:
            rendered = ", ".join(hex(self.text_va + match) for match in matches) or "none"
            raise ValueError(f"{label} signature expected one match, found {len(matches)}: {rendered}")
        return self.text_va + matches[0] + anchor_offset

    def resolve_import_iat(self, names: Iterable[str]) -> dict[str, int]:
        requested = tuple(names)
        found: dict[str, list[int]] = {name: [] for name in requested}
        for library in self.binary.imports:
            for entry in library.entries:
                if entry.name in found:
                    found[entry.name].append(self.image_base + entry.iat_address)
        result = {}
        for name, addresses in found.items():
            if len(addresses) != 1:
                raise ValueError(f"import {name} expected once, found {len(addresses)}")
            result[name] = addresses[0]
        return result

    def import_iat(self) -> dict[str, int]:
        return self.resolve_import_iat(IMPORT_BINDINGS)

    def instruction_starts(self) -> set[int]:
        ranges = self.runtime_functions()
        decoder = Cs(CS_ARCH_X86, CS_MODE_64)
        starts: set[int] = set()
        for begin, end in ranges:
            for instruction in decoder.disasm(self.read(begin, end - begin), begin):
                starts.add(instruction.address)
        if not starts:
            raise ValueError("could not recover instruction boundaries from .pdata")
        return starts

    def runtime_functions(self) -> list[tuple[int, int]]:
        directory = self.optional + 112 + 3 * 8
        pdata_rva, pdata_size = struct.unpack_from("<II", self.data, directory)
        if not pdata_rva or pdata_size < 12:
            raise ValueError("target has no usable x64 exception directory")
        pdata_file = rva_to_file(self.sections, pdata_rva)
        ranges: list[tuple[int, int]] = []
        for cursor in range(pdata_file, pdata_file + pdata_size - 11, 12):
            begin_rva, end_rva, _ = struct.unpack_from("<III", self.data, cursor)
            if not begin_rva or end_rva <= begin_rva:
                continue
            begin = self.image_base + begin_rva
            end = self.image_base + end_rva
            if not self.in_text(begin) or end > self.text_va + self.text.raw_size:
                continue
            ranges.append((begin, end))
        if not ranges:
            raise ValueError("could not recover runtime functions from .pdata")
        return ranges

    def containing_runtime_function(self, address: int) -> tuple[int, int]:
        matches = [(begin, end) for begin, end in self.runtime_functions()
                   if begin <= address < end]
        if len(matches) != 1:
            raise ValueError(f"address 0x{address:x} belongs to {len(matches)} runtime functions")
        return matches[0]


def register_name(instruction, operand_index: int) -> str | None:
    operand = instruction.operands[operand_index]
    if operand.type != X86_OP_REG:
        return None
    return instruction.reg_name(operand.reg)


def memory_base_and_disp(instruction, operand_index: int) -> tuple[str | None, int] | None:
    operand = instruction.operands[operand_index]
    if operand.type != X86_OP_MEM:
        return None
    return instruction.reg_name(operand.mem.base), operand.mem.disp


def unique_value(values: list[int], label: str) -> int:
    distinct = sorted(set(values))
    if len(distinct) != 1:
        raise ValueError(f"{label} expected one value, found {distinct}")
    return distinct[0]


def immediate_call_target(instruction) -> int | None:
    if (instruction.mnemonic != "call" or not instruction.operands or
            instruction.operands[0].type != X86_OP_IMM):
        return None
    return instruction.operands[0].imm


def discover_runtime_support(target: TargetImage, instruction_starts: set[int]) -> dict:
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True

    item_interaction = target.locate_signature(
        "item interaction", ITEM_INTERACTION_SIGNATURE)
    item_instructions = list(decoder.disasm(
        target.read(item_interaction, 0x1200), item_interaction))
    open_specification, open_call_offset = OPEN_COMMAND_SIGNATURE
    open_matches = [target.text_va + offset
                    for offset in find_masked(target.text_data, open_specification)]
    candidates = [sequence for sequence in open_matches
                  if item_interaction <= sequence < item_interaction + 0x1200]
    if len(candidates) != 1:
        rendered = ", ".join(hex(item) for item in candidates) or "none"
        raise ValueError("selection command path expected one child-aware match, found "
                         f"{len(candidates)}: {rendered}")
    begin_open_site = candidates[0] + open_call_offset
    begin_queued_command = target.decode_call(begin_open_site)
    if not target.in_text(begin_queued_command):
        raise ValueError("queued-command builder is outside .text")

    selection_cancel = target.locate_signature(
        "selection-cancel callback", SELECTION_CANCEL_SIGNATURE)
    toggle_cursor_candidates = []
    runtime_ranges = target.runtime_functions()
    for site in instruction_starts:
        if target.read(site, 1) != b"\xE8" or target.decode_call(site) != begin_queued_command:
            continue
        containing = [index for index, (begin, end) in enumerate(runtime_ranges)
                      if begin <= site < end]
        if len(containing) != 1:
            continue
        root_index = containing[0]
        while (root_index and
               runtime_ranges[root_index - 1][1] == runtime_ranges[root_index][0]):
            root_index -= 1
        begin = runtime_ranges[root_index][0]
        end = runtime_ranges[containing[0]][1]
        if end - begin > 0x1000:
            continue
        callback_instructions = list(decoder.disasm(target.read(begin, end - begin), begin))
        call_index = next((index for index, instruction in enumerate(callback_instructions)
                           if instruction.address == site), None)
        if call_index is None:
            continue
        setup = callback_instructions[max(0, call_index - 5):call_index]
        has_toggle_command = any(
            instruction.mnemonic == "mov" and len(instruction.operands) == 2 and
            register_name(instruction, 0) == "edx" and
            instruction.operands[1].type == X86_OP_IMM and
            instruction.operands[1].imm == 0x2E
            for instruction in setup)
        has_cursor_event = any(
            instruction.mnemonic == "cmp" and len(instruction.operands) == 2 and
            register_name(instruction, 0) == "r8d" and
            instruction.operands[1].type == X86_OP_IMM and
            instruction.operands[1].imm == 2
            for instruction in callback_instructions[:call_index])
        if has_toggle_command and has_cursor_event:
            toggle_cursor_candidates.append(begin)
    toggle_cursor_selection = unique_value(
        toggle_cursor_candidates, "toggle-cursor-selection callback")

    panel_viewport_site = target.locate_signature(
        "panel viewport renderer", PANEL_VIEWPORT_SIGNATURE)
    panel_viewport_renderer, _ = target.containing_runtime_function(panel_viewport_site)
    viewport_instructions = list(decoder.disasm(
        target.read(panel_viewport_renderer, 0x400), panel_viewport_renderer))
    find_window_candidates = []
    for index, instruction in enumerate(viewport_instructions[:-1]):
        called = immediate_call_target(instruction)
        following = viewport_instructions[index + 1]
        if (called is not None and following.mnemonic == "mov" and
                register_name(following, 0) == "rbx" and
                register_name(following, 1) == "rax"):
            find_window_candidates.append(called)
    find_imgui_window = unique_value(find_window_candidates, "ImGui window lookup")

    open_right = target.locate_signature("open in right split", OPEN_RIGHT_SIGNATURE)
    open_right_instructions = []
    for instruction in decoder.disasm(target.read(open_right, 0x100), open_right):
        open_right_instructions.append(instruction)
        if instruction.mnemonic == "ret":
            break
    app_active_panel_offset = unique_value([
        memory_base_and_disp(instruction, 1)[1]
        for instruction in open_right_instructions
        if instruction.mnemonic == "mov" and len(instruction.operands) == 2 and
        register_name(instruction, 0) == "rdi" and
        memory_base_and_disp(instruction, 1) and
        memory_base_and_disp(instruction, 1)[0] == "rcx"
    ], "active panel offset")

    for label, value in (
        ("selection cancel", selection_cancel),
        ("cursor selection toggle", toggle_cursor_selection),
        ("ImGui window lookup", find_imgui_window),
    ):
        if not target.in_text(value):
            raise ValueError(f"discovered {label} 0x{value:x} is outside .text")
    if not 0 <= app_active_panel_offset < 0x2000:
        raise ValueError(
            f"implausible active panel offset: 0x{app_active_panel_offset:x}")
    return {
        "selection_cancel": selection_cancel,
        "toggle_cursor_selection": toggle_cursor_selection,
        "app_active_panel_offset": app_active_panel_offset,
        "find_imgui_window": find_imgui_window,
    }


@dataclass
class TargetLayout:
    digest: str
    known_build: str | None
    image_base: int
    startup_site: int
    original_initializer: int
    frame_site: int
    original_frame: int
    live_wrapper: int
    live_call_sites: list[int]
    selector: int
    selection_cancel: int
    toggle_cursor_selection: int
    selection_state_display_offset: int
    display_mode_offset: int
    display_primary_offset: int
    display_alternate_offset: int
    display_count_offset: int
    app_active_panel_offset: int
    find_imgui_window: int
    imports: dict[str, int]

    def binding_values(self, include_tab: bool = True) -> list[int]:
        values = [BINDINGS_MAGIC, BINDINGS_VERSION, BINDINGS_QWORDS * 8]
        values.extend(self.imports[name] for name in IMPORT_BINDINGS)
        values.extend((
            self.selector, self.original_initializer, self.live_wrapper,
            self.selection_cancel, self.toggle_cursor_selection, self.original_frame,
            self.selection_state_display_offset, self.display_mode_offset,
            self.display_primary_offset, self.display_alternate_offset,
            self.display_count_offset, self.app_active_panel_offset,
            self.find_imgui_window, int(include_tab),
            self.image_base + 0x185550 if include_tab else 0,
            self.image_base + 0x15F750 if include_tab else 0,
            self.image_base + 0x1846C0 if include_tab else 0,
            self.image_base + 0x1925B0 if include_tab else 0,
            self.image_base + TAB_SURFACE_RENDERER_RVA if include_tab else 0,
            self.image_base + INPUT_STATE_GLOBAL_RVA if include_tab else 0,
            self.image_base + FRAME_GENERATION_GLOBAL_RVA if include_tab else 0,
            self.image_base + TAB_HOVER_HELPER_RVA if include_tab else 0,
        ))
        if len(values) != BINDINGS_QWORDS:
            raise AssertionError(f"binding table has {len(values)} values")
        return values

    def report(self) -> dict:
        def address(value: int) -> str:
            return f"0x{value:x}"
        return {
            "sha256": self.digest,
            "known_build": self.known_build,
            "image_base": address(self.image_base),
            "startup_hook_site": address(self.startup_site),
            "original_initializer": address(self.original_initializer),
            "frame_hook_site": address(self.frame_site),
            "original_frame": address(self.original_frame),
            "live_selection_wrapper": address(self.live_wrapper),
            "live_selection_call_sites": [address(site) for site in self.live_call_sites],
            "selector": address(self.selector),
            "selection_cancel": address(self.selection_cancel),
            "toggle_cursor_selection": address(self.toggle_cursor_selection),
            "offsets": {
                "selection_state_display": address(self.selection_state_display_offset),
                "display_mode": address(self.display_mode_offset),
                "display_primary": address(self.display_primary_offset),
                "display_alternate": address(self.display_alternate_offset),
                "display_count": address(self.display_count_offset),
                "app_active_panel": address(self.app_active_panel_offset),
            },
            "tab_support": {
                "find_imgui_window": address(self.find_imgui_window),
            },
            "iat": {name: address(value) for name, value in self.imports.items()},
        }


def discover_layout(target: TargetImage) -> TargetLayout:
    startup_site = target.locate_signature("startup hook", STARTUP_SIGNATURE)
    frame_site = target.locate_signature("frame hook", FRAME_SIGNATURE)
    live_wrapper = target.locate_signature("live-selection wrapper", LIVE_WRAPPER_SIGNATURE)
    original_initializer = target.decode_call(startup_site)
    original_frame = target.decode_call(frame_site)
    for label, address in (("initializer", original_initializer), ("frame", original_frame),
                           ("live-selection wrapper", live_wrapper)):
        if not target.in_text(address):
            raise ValueError(f"discovered {label} 0x{address:x} is outside .text")

    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    instructions = list(decoder.disasm(target.read(live_wrapper, 0x300), live_wrapper))
    if not instructions or instructions[0].address != live_wrapper:
        raise ValueError("could not disassemble live-selection wrapper")

    state_offsets = []
    mode_offsets = []
    primary_offsets = []
    alternate_offsets = []
    count_offsets = []
    selector_candidates = []
    for index, instruction in enumerate(instructions):
        if instruction.mnemonic == "mov" and len(instruction.operands) == 2:
            destination = register_name(instruction, 0)
            memory = memory_base_and_disp(instruction, 1)
            if destination == "r9" and memory and memory[0] == "rdx":
                state_offsets.append(memory[1])
            elif destination == "r14" and memory and memory[0] == "r9":
                mode_offsets.append(memory[1])
            elif destination == "esi" and instruction.operands[1].type == X86_OP_IMM:
                primary_offsets.append(instruction.operands[1].imm)
            elif destination == "ecx" and instruction.operands[1].type == X86_OP_IMM:
                alternate_offsets.append(instruction.operands[1].imm)
        if instruction.mnemonic == "movups" and len(instruction.operands) == 2:
            destination = register_name(instruction, 0)
            memory = memory_base_and_disp(instruction, 1)
            if destination == "xmm1" and memory and memory[0] == "rsi":
                count_offsets.append(memory[1])
        if instruction.mnemonic == "call" and instruction.operands[0].type == X86_OP_IMM:
            following = instructions[index + 1:index + 4]
            if not any(item.mnemonic == "test" and item.op_str == "eax, eax" for item in following):
                continue
            context = {(item.mnemonic, item.op_str) for item in instructions[max(0, index - 24):index]}
            required = {("mov", "r9, r15"), ("mov", "r8, rsi"), ("mov", "rcx, rbx")}
            if required.issubset(context) and any(item.mnemonic == "lea" and
                    item.op_str.startswith("rdx, [rsp") for item in instructions[max(0, index - 24):index]):
                selector_candidates.append(instruction.operands[0].imm)

    selection_state_display_offset = unique_value(state_offsets[:1], "selection-state display offset")
    display_mode_offset = unique_value(mode_offsets[:1], "display-mode offset")
    display_primary_offset = unique_value(primary_offsets[:1], "primary display offset")
    display_alternate_offset = unique_value(alternate_offsets[:1], "alternate display offset")
    display_count_offset = unique_value(count_offsets[:1], "display-count offset")
    selector = unique_value(selector_candidates, "native selector")
    for label, value in (
        ("selection-state display offset", selection_state_display_offset),
        ("display-mode offset", display_mode_offset),
        ("primary display offset", display_primary_offset),
        ("alternate display offset", display_alternate_offset),
        ("display-count offset", display_count_offset),
    ):
        if value < 0 or value >= 0x1000 or value % 8:
            raise ValueError(f"implausible {label}: 0x{value:x}")
    if not target.in_text(selector):
        raise ValueError(f"native selector 0x{selector:x} is outside .text")

    instruction_starts = target.instruction_starts()
    live_call_sites = []
    for site in instruction_starts:
        if target.read(site, 1) == b"\xE8" and target.decode_call(site) == live_wrapper:
            live_call_sites.append(site)
    live_call_sites.sort()
    if not 4 <= len(live_call_sites) <= 32:
        raise ValueError(f"expected 4..32 live-selection call sites, found {len(live_call_sites)}")
    if startup_site in live_call_sites or frame_site in live_call_sites:
        raise ValueError("hook-site cross-reference sets overlap unexpectedly")

    support = discover_runtime_support(target, instruction_starts)

    return TargetLayout(
        target.digest, KNOWN_SHA256.get(target.digest), target.image_base,
        startup_site, original_initializer, frame_site, original_frame, live_wrapper,
        live_call_sites, selector, support["selection_cancel"],
        support["toggle_cursor_selection"], selection_state_display_offset,
        display_mode_offset, display_primary_offset, display_alternate_offset,
        display_count_offset, support["app_active_panel_offset"],
        support["find_imgui_window"], target.import_iat(),
    )


def find_export(payload: bytes, optional: int, sections: list[SectionRecord], wanted: bytes) -> int:
    export_rva = u32(payload, optional + 112)
    export_file = rva_to_file(sections, export_rva)
    number_of_names = u32(payload, export_file + 24)
    functions_file = rva_to_file(sections, u32(payload, export_file + 28))
    names_file = rva_to_file(sections, u32(payload, export_file + 32))
    ordinals_file = rva_to_file(sections, u32(payload, export_file + 36))
    for index in range(number_of_names):
        name_file = rva_to_file(sections, u32(payload, names_file + index * 4))
        end = payload.index(0, name_file)
        if payload[name_file:end] == wanted:
            ordinal = u16(payload, ordinals_file + index * 2)
            return u32(payload, functions_file + ordinal * 4)
    raise ValueError(f"payload export {wanted!r} not found")


def build_payload_image(payload: bytes, target_base: int, section_rva: int,
                        layout: TargetLayout, include_tab: bool = True):
    _, _, optional, _, sections = pe_layout(payload)
    if u64(payload, optional + 24) != PAYLOAD_IMAGE_BASE:
        raise ValueError("payload was linked at the wrong image base")
    exports = {name: find_export(payload, optional, sections, name.encode("ascii"))
               for name in ("Hook", "FrameHook", "LiveSelectionHook",
                             "CrossWindowTryTransfer", "CrossWindowPreviewPulse",
                             "RemoteTabSurfaceHook", "RemoteTabHoverHook", "Bindings")}
    image_size = u32(payload, optional + 56)
    mapped = bytearray(image_size - PAYLOAD_FIRST_RVA)
    for section in sections:
        if section.rva < PAYLOAD_FIRST_RVA or not section.raw_size:
            continue
        relative = section.rva - PAYLOAD_FIRST_RVA
        mapped[relative:relative + section.raw_size] = \
            payload[section.raw:section.raw + section.raw_size]

    delta = (target_base + section_rva) - (PAYLOAD_IMAGE_BASE + PAYLOAD_FIRST_RVA)
    reloc_rva = u32(payload, optional + 112 + 5 * 8)
    reloc_size = u32(payload, optional + 112 + 5 * 8 + 4)
    reloc_file = rva_to_file(sections, reloc_rva)
    cursor = reloc_file
    limit = reloc_file + reloc_size
    while cursor + 8 <= limit:
        page_rva, block_size = struct.unpack_from("<II", payload, cursor)
        if not page_rva or block_size < 8 or cursor + block_size > limit:
            break
        for entry_off in range(cursor + 8, cursor + block_size, 2):
            entry = u16(payload, entry_off)
            kind, offset = entry >> 12, entry & 0xFFF
            if kind == 0:
                continue
            if kind != 10:
                raise ValueError(f"unsupported payload relocation type {kind}")
            mapped_off = page_rva + offset - PAYLOAD_FIRST_RVA
            struct.pack_into("<Q", mapped, mapped_off, u64(mapped, mapped_off) + delta)
        cursor += block_size

    binding_off = exports["Bindings"] - PAYLOAD_FIRST_RVA
    existing = struct.unpack_from("<QQQ", mapped, binding_off)
    expected = (BINDINGS_MAGIC, BINDINGS_VERSION, BINDINGS_QWORDS * 8)
    if existing != expected:
        raise ValueError(f"payload binding header mismatch: {existing!r}")
    struct.pack_into("<" + "Q" * BINDINGS_QWORDS, mapped, binding_off,
                     *layout.binding_values(include_tab))
    return mapped, exports


@dataclass(frozen=True)
class UnicodeLayout:
    glyph_lookup: int
    glyph_lookup_call_sites: tuple[int, ...]
    measure_text: int
    measure_text_call_sites: tuple[int, ...]
    render_text: int
    render_text_call_sites: tuple[int, ...]
    font_create_atlas: int
    font_create_atlas_call_sites: tuple[int, ...]
    font_rasterizer: int
    utf16_to_utf8: int
    input_conversion_call_site: int
    range_table: int
    d3d_create_device: int
    d3d_create_device_call_sites: tuple[int, ...]
    d3d_render_frame: int
    d3d_render_frame_call_site: int
    d3d_renderer_global: int
    native_quad_emitter: int
    native_quad_call_site: int
    native_command_allocator: int
    d3d_draw_batch: int
    d3d_draw_batch_call_sites: tuple[int, ...]
    native_render_data_global: int

    def report(self) -> dict:
        address = lambda value: f"0x{value:x}"
        return {
            "profile": "DirectWrite-shaped native-inline D3D11 A/B renderers",
            "glyph_lookup": address(self.glyph_lookup),
            "glyph_lookup_call_sites": [address(value)
                                        for value in self.glyph_lookup_call_sites],
            "measure_text": address(self.measure_text),
            "measure_text_call_sites": [address(value)
                                         for value in self.measure_text_call_sites],
            "render_text": address(self.render_text),
            "render_text_call_sites": [address(value)
                                        for value in self.render_text_call_sites],
            "font_create_atlas": address(self.font_create_atlas),
            "font_create_atlas_call_sites": [address(value)
                                              for value in self.font_create_atlas_call_sites],
            "font_rasterizer": address(self.font_rasterizer),
            "input_conversion_call_site": address(self.input_conversion_call_site),
            "range_table": address(self.range_table),
            "d3d_create_device_call_sites": [address(value)
                                              for value in self.d3d_create_device_call_sites],
            "d3d_render_frame_call_site": address(self.d3d_render_frame_call_site),
            "d3d_renderer_global": address(self.d3d_renderer_global),
            "native_quad_emitter": address(self.native_quad_emitter),
            "native_quad_call_site": address(self.native_quad_call_site),
            "native_command_allocator": address(self.native_command_allocator),
            "d3d_draw_batch": address(self.d3d_draw_batch),
            "d3d_draw_batch_call_sites": [address(value)
                                            for value in self.d3d_draw_batch_call_sites],
            "native_render_data_global": address(self.native_render_data_global),
            "atlas_policy": "compact native ranges with row and shared-glyph mask caches",
        }


def direct_call_sites(target: TargetImage, instruction_starts: set[int], destination: int) -> tuple[int, ...]:
    return tuple(sorted(
        site for site in instruction_starts
        if target.read(site, 1) == b"\xE8" and target.decode_call(site) == destination
    ))


def discover_unicode_layout(target: TargetImage) -> UnicodeLayout:
    if target.digest not in UNICODE_SUPPORTED_SHA256:
        raise ValueError(
            "Unicode patch has no verified profile for input SHA-256 " + target.digest)
    starts = target.instruction_starts()
    base = target.image_base
    glyph_lookup = base + UNICODE_GLYPH_LOOKUP_RVA
    measure_text = base + UNICODE_MEASURE_TEXT_RVA
    render_text = base + UNICODE_RENDER_TEXT_RVA
    font_create_atlas = base + UNICODE_FONT_CREATE_ATLAS_RVA
    font_rasterizer = base + UNICODE_FONT_RASTERIZER_RVA
    utf16_to_utf8 = base + UNICODE_UTF16_TO_UTF8_RVA
    glyph_calls = direct_call_sites(target, starts, glyph_lookup)
    measure_calls = direct_call_sites(target, starts, measure_text)
    render_calls = direct_call_sites(target, starts, render_text)
    font_calls = direct_call_sites(target, starts, font_create_atlas)
    rasterizer_calls = direct_call_sites(target, starts, font_rasterizer)
    wrapper_rasterizer_calls = tuple(site for site in rasterizer_calls
                                     if font_create_atlas <= site < font_create_atlas + 0xC2)
    if len(wrapper_rasterizer_calls) != 1:
        raise ValueError("Unicode font wrapper no longer has one native rasterizer call")
    expected_counts = {
        "glyph lookup": (len(glyph_calls), 5),
        "text measurement": (len(measure_calls), 38),
        "text renderer": (len(render_calls), 1),
        "font atlas": (len(font_calls), 3),
    }
    for label, (actual, expected) in expected_counts.items():
        if actual != expected:
            raise ValueError(f"Unicode {label} expected {expected} direct calls, found {actual}")
    input_call = base + UNICODE_INPUT_CONVERSION_CALL_RVA
    if target.decode_call(input_call) != utf16_to_utf8:
        raise ValueError("Unicode WM_CHAR conversion seam no longer calls the UTF-16 codec")
    for rva, expected in UNICODE_CARET_CLAMPS.items():
        if target.read(base + rva, len(expected)) != expected:
            raise ValueError(f"Unicode caret clamp changed at 0x{base + rva:x}")
    expected_ranges = b"".join(struct.pack("<II", low, high)
                               for low, high in UNICODE_ORIGINAL_RANGES)
    range_table = base + UNICODE_RANGE_TABLE_RVA
    if target.read(range_table, len(expected_ranges)) != expected_ranges:
        raise ValueError("Unicode glyph range table no longer matches the verified layout")
    d3d_create_device = base + UNICODE_D3D_CREATE_DEVICE_RVA
    d3d_create_calls = direct_call_sites(target, starts, d3d_create_device)
    expected_d3d_calls = (base + 0x4892B, base + 0x4897A)
    if d3d_create_calls != expected_d3d_calls:
        raise ValueError("Unicode renderer expected the two verified D3D11CreateDevice calls")
    d3d_render_frame = base + UNICODE_D3D_RENDER_FRAME_RVA
    d3d_render_call = base + UNICODE_D3D_RENDER_FRAME_CALL_RVA
    if target.decode_call(d3d_render_call) != d3d_render_frame:
        raise ValueError("Unicode renderer D3D pre-Present seam changed")
    native_quad_emitter = base + UNICODE_NATIVE_QUAD_EMITTER_RVA
    native_quad_call = base + UNICODE_NATIVE_QUAD_CALL_RVA
    if target.decode_call(native_quad_call) != native_quad_emitter:
        raise ValueError("Unicode native quad-emitter seam changed")
    d3d_draw_batch = base + UNICODE_D3D_DRAW_BATCH_RVA
    d3d_draw_batch_calls = tuple(base + rva for rva in UNICODE_D3D_DRAW_BATCH_CALL_RVAS)
    for call in d3d_draw_batch_calls:
        if target.decode_call(call) != d3d_draw_batch:
            raise ValueError("Unicode native D3D draw-batch seam changed")
    return UnicodeLayout(
        glyph_lookup, glyph_calls, measure_text, measure_calls, render_text, render_calls,
        font_create_atlas, font_calls, font_rasterizer, utf16_to_utf8, input_call, range_table,
        d3d_create_device, d3d_create_calls, d3d_render_frame, d3d_render_call,
        base + UNICODE_D3D_RENDERER_GLOBAL_RVA,
        native_quad_emitter, native_quad_call,
        base + UNICODE_NATIVE_COMMAND_ALLOCATOR_RVA, d3d_draw_batch,
        d3d_draw_batch_calls, base + UNICODE_NATIVE_RENDER_DATA_GLOBAL_RVA)


def build_unicode_payload_image(payload: bytes, target: TargetImage, section_rva: int,
                                layout: UnicodeLayout):
    _, _, optional, _, sections = pe_layout(payload)
    payload_image_base = u64(payload, optional + 24)
    exports = {name: find_export(payload, optional, sections, name.encode("ascii"))
               for name in ("UnicodeGlyphLookupHook", "UnicodeMeasureTextHook",
                            "UnicodeRenderTextHook", "UnicodeFontCreateAtlasHook",
                            "UnicodeUtf16ToUtf8Hook", "UnicodeD3D11CreateDeviceHook",
                            "UnicodeD3DRenderFrameHook", "UnicodeNativeQuadHook",
                            "UnicodeD3DDrawBatchHook", "UnicodeDebug",
                            "UnicodeExperiment", "Bindings")}
    image_size = u32(payload, optional + 56)
    mapped = bytearray(image_size - UNICODE_PAYLOAD_FIRST_RVA)
    for section in sections:
        if section.rva < UNICODE_PAYLOAD_FIRST_RVA or not section.raw_size:
            continue
        relative = section.rva - UNICODE_PAYLOAD_FIRST_RVA
        mapped[relative:relative + section.raw_size] = \
            payload[section.raw:section.raw + section.raw_size]

    delta = (target.image_base + section_rva) - \
        (payload_image_base + UNICODE_PAYLOAD_FIRST_RVA)
    reloc_rva = u32(payload, optional + 112 + 5 * 8)
    reloc_size = u32(payload, optional + 112 + 5 * 8 + 4)
    cursor = rva_to_file(sections, reloc_rva)
    limit = cursor + reloc_size
    while cursor + 8 <= limit:
        page_rva, block_size = struct.unpack_from("<II", payload, cursor)
        if not page_rva or block_size < 8 or cursor + block_size > limit:
            break
        for entry_off in range(cursor + 8, cursor + block_size, 2):
            entry = u16(payload, entry_off)
            kind, offset = entry >> 12, entry & 0xFFF
            if kind == 0:
                continue
            if kind != 10:
                raise ValueError(f"unsupported Unicode payload relocation type {kind}")
            mapped_off = page_rva + offset - UNICODE_PAYLOAD_FIRST_RVA
            struct.pack_into("<Q", mapped, mapped_off, u64(mapped, mapped_off) + delta)
        cursor += block_size

    imports = target.resolve_import_iat((
        "LoadLibraryW", "GetProcAddress", "GetFileAttributesW", "VirtualAlloc", "VirtualFree",
        "D3D11CreateDevice"))
    binding_values = [
        UNICODE_BINDINGS_MAGIC, UNICODE_BINDINGS_VERSION, UNICODE_BINDINGS_QWORDS * 8,
        imports["LoadLibraryW"], imports["GetProcAddress"], imports["GetFileAttributesW"],
        imports["VirtualAlloc"], imports["VirtualFree"], layout.glyph_lookup,
        layout.measure_text, layout.render_text, layout.font_create_atlas,
        layout.font_rasterizer, layout.utf16_to_utf8, layout.range_table,
        imports["D3D11CreateDevice"], layout.d3d_render_frame, layout.d3d_renderer_global,
        layout.native_quad_emitter, layout.native_command_allocator, layout.d3d_draw_batch,
        layout.native_render_data_global,
    ]
    if len(binding_values) != UNICODE_BINDINGS_QWORDS:
        raise AssertionError("Unicode binding table length changed")
    binding_off = exports["Bindings"] - UNICODE_PAYLOAD_FIRST_RVA
    existing = struct.unpack_from("<QQQ", mapped, binding_off)
    expected = (UNICODE_BINDINGS_MAGIC, UNICODE_BINDINGS_VERSION, UNICODE_BINDINGS_QWORDS * 8)
    if existing != expected:
        raise ValueError(f"Unicode payload binding header mismatch: {existing!r}")
    struct.pack_into("<" + "Q" * UNICODE_BINDINGS_QWORDS, mapped, binding_off, *binding_values)
    return mapped, exports


def patch_call(data: bytearray, target: TargetImage, sections: list[SectionRecord],
               site_va: int, expected_target: int, replacement_target: int, label: str):
    site_file = rva_to_file(sections, site_va - target.image_base)
    original = bytes(data[site_file:site_file + 5])
    if len(original) != 5 or original[0] != 0xE8:
        raise ValueError(f"{label} site 0x{site_va:x} is no longer a direct call")
    decoded = site_va + 5 + struct.unpack_from("<i", original, 1)[0]
    if decoded != expected_target:
        raise ValueError(f"{label} site 0x{site_va:x} changed target "
                         f"from 0x{expected_target:x} to 0x{decoded:x}")
    displacement = replacement_target - (site_va + 5)
    if not -(1 << 31) <= displacement < (1 << 31):
        raise ValueError(f"{label} replacement is outside rel32 range")
    data[site_file:site_file + 5] = b"\xE8" + struct.pack("<i", displacement)


def patch_exact_bytes(data: bytearray, sections: list[SectionRecord], image_base: int,
                      site_va: int, expected: bytes, replacement: bytes, label: str):
    if len(expected) != len(replacement):
        raise ValueError(f"{label} replacement length changed")
    site_file = rva_to_file(sections, site_va - image_base)
    actual = bytes(data[site_file:site_file + len(expected)])
    if actual != expected:
        raise ValueError(f"{label} site 0x{site_va:x} changed: {actual.hex()}")
    data[site_file:site_file + len(replacement)] = replacement


def apply_unicode_patch(output: bytearray, target: TargetImage, sections: list[SectionRecord],
                        layout: UnicodeLayout, payload_va: int, exports: dict[str, int]) -> dict:
    hooks = {
        "glyph lookup": payload_va + exports["UnicodeGlyphLookupHook"],
        "text measurement": payload_va + exports["UnicodeMeasureTextHook"],
        "text renderer": payload_va + exports["UnicodeRenderTextHook"],
        "font atlas": payload_va + exports["UnicodeFontCreateAtlasHook"],
        "WM_CHAR UTF-16 conversion": payload_va + exports["UnicodeUtf16ToUtf8Hook"],
        "D3D11 device creation": payload_va + exports["UnicodeD3D11CreateDeviceHook"],
        "D3D frame lifecycle": payload_va + exports["UnicodeD3DRenderFrameHook"],
        "native quad emitter": payload_va + exports["UnicodeNativeQuadHook"],
        "native D3D draw batch": payload_va + exports["UnicodeD3DDrawBatchHook"],
    }
    for site in layout.glyph_lookup_call_sites:
        patch_call(output, target, sections, site, layout.glyph_lookup,
                   hooks["glyph lookup"], "Unicode glyph lookup")
    for site in layout.measure_text_call_sites:
        patch_call(output, target, sections, site, layout.measure_text,
                   hooks["text measurement"], "Unicode text measurement")
    for site in layout.render_text_call_sites:
        patch_call(output, target, sections, site, layout.render_text,
                   hooks["text renderer"], "Unicode text renderer")
    for site in layout.font_create_atlas_call_sites:
        patch_call(output, target, sections, site, layout.font_create_atlas,
                   hooks["font atlas"], "Unicode font atlas")
    patch_call(output, target, sections, layout.input_conversion_call_site,
               layout.utf16_to_utf8, hooks["WM_CHAR UTF-16 conversion"],
               "Unicode WM_CHAR conversion")
    for site in layout.d3d_create_device_call_sites:
        patch_call(output, target, sections, site, layout.d3d_create_device,
                   hooks["D3D11 device creation"], "Unicode D3D11 device creation")
    patch_call(output, target, sections, layout.d3d_render_frame_call_site,
               layout.d3d_render_frame, hooks["D3D frame lifecycle"],
               "Unicode D3D frame lifecycle")
    patch_call(output, target, sections, layout.native_quad_call_site,
               layout.native_quad_emitter, hooks["native quad emitter"],
               "Unicode native quad emitter")
    for site in layout.d3d_draw_batch_call_sites:
        patch_call(output, target, sections, site, layout.d3d_draw_batch,
                   hooks["native D3D draw batch"], "Unicode native D3D draw batch")

    for rva, expected in UNICODE_CARET_CLAMPS.items():
        patch_exact_bytes(output, sections, target.image_base, target.image_base + rva,
                          expected, b"\x90" * len(expected), "Unicode caret clamp")
    old_ranges = b"".join(struct.pack("<II", low, high)
                          for low, high in UNICODE_ORIGINAL_RANGES)
    new_ranges = b"".join(struct.pack("<II", low, high)
                          for low, high in UNICODE_INITIAL_RANGES)
    patch_exact_bytes(output, sections, target.image_base, layout.range_table,
                      old_ranges, new_ranges, "Unicode glyph range table")
    report = layout.report()
    report["hooks"] = {name: f"0x{address:x}" for name, address in hooks.items()}
    report["caret_ascii_clamps_removed"] = len(UNICODE_CARET_CLAMPS)
    report["renderer"] = "native-inline-d3d-atlas"
    report["renderer_selection"] = "environment"
    report["renderer_selector"] = "FPILOT_UNICODE_NATIVE_MODE"
    report["renderer_default"] = "row-texture"
    report["renderer_modes"] = {
        "row-texture": 1,
        "shaped-glyph": 2,
        "custom-command": 4,
    }
    report["transform_selection"] = "environment"
    report["transform_selector"] = "FPILOT_UNICODE_TRANSFORM_MODE"
    report["transform_default"] = "native-probe"
    report["transform_modes"] = {
        "legacy": 1,
        "native-probe": 2,
    }
    report["telemetry_rva"] = (
        f"0x{payload_va + exports['UnicodeExperiment'] - target.image_base:x}")
    return report


def choose_section_rva(target: TargetImage) -> int:
    end = max(section.rva + max(section.vsize, section.raw_size) for section in target.sections)
    return align(end, target.section_alignment)


def build_profile_name(include_tab: bool, include_unicode: bool) -> str:
    if include_tab and include_unicode:
        return "all"
    if include_tab:
        return "open-location-and-tabs"
    if include_unicode:
        return "open-location-and-unicode"
    return "open-location-only"


def patch(target_path: Path, payload_path: Path, output_path: Path,
          layout_path: Path | None = None, include_tab: bool = True,
          include_unicode: bool = False, unicode_payload_path: Path | None = None):
    target = TargetImage(target_path)
    if include_tab and target.digest not in TAB_SUPPORTED_SHA256:
        raise ValueError(
            "tab tear-off patch has no verified profile for input SHA-256 "
            f"{target.digest}; use --open-location-only for structurally compatible builds")
    layout = discover_layout(target)
    report = layout.report()
    report["build_profile"] = build_profile_name(include_tab, include_unicode)
    report["patches"] = {
        "open_file_location": True,
        "tab_window_creation": include_tab,
        "cross_window_tab_merge": include_tab,
    }
    if include_unicode:
        report["patches"]["unicode_text"] = True
        if unicode_payload_path is None:
            raise ValueError("Unicode patch requires --unicode-payload")
    unicode_layout = discover_unicode_layout(target) if include_unicode else None

    section_rva = choose_section_rva(target)
    mapped, exports = build_payload_image(payload_path.read_bytes(), target.image_base,
                                           section_rva, layout, include_tab)
    binary = lief.PE.parse(str(target_path))
    section = lief.PE.Section(".fplt")
    section.content = list(mapped)
    section.virtual_address = section_rva
    section.characteristics = 0xE0000060
    added = binary.add_section(section)
    if added.virtual_address != section_rva:
        raise ValueError(f"LIEF assigned unexpected payload RVA 0x{added.virtual_address:x}; "
                         f"expected 0x{section_rva:x}")
    unicode_section_rva = 0
    unicode_exports: dict[str, int] = {}
    if unicode_layout is not None and unicode_payload_path is not None:
        unicode_section_rva = align(section_rva + len(mapped), target.section_alignment)
        unicode_mapped, unicode_exports = build_unicode_payload_image(
            unicode_payload_path.read_bytes(), target, unicode_section_rva, unicode_layout)
        unicode_section = lief.PE.Section(".fpu")
        unicode_section.content = list(unicode_mapped)
        unicode_section.virtual_address = unicode_section_rva
        unicode_section.characteristics = 0xE0000060
        unicode_added = binary.add_section(unicode_section)
        if unicode_added.virtual_address != unicode_section_rva:
            raise ValueError(
                f"LIEF assigned unexpected Unicode payload RVA 0x{unicode_added.virtual_address:x}; "
                f"expected 0x{unicode_section_rva:x}")
    # LIEF writes to a private sibling first. A failed tab validation therefore
    # cannot leave a misleading Open-Location-only executable at the requested
    # combined output path.
    with tempfile.NamedTemporaryFile(
            prefix=f".{output_path.stem}-", suffix=".exe", dir=output_path.parent,
            delete=False) as temporary_file:
        temporary_path = Path(temporary_file.name)
    try:
        binary.write(str(temporary_path))
        # LIEF can retain its Windows file handle until the PE object is destroyed. Release it
        # before reading or deleting the sibling, otherwise a fast rebuild intermittently gets
        # ERROR_ACCESS_DENIED even though serialization completed.
        del binary
        output = bytearray(temporary_path.read_bytes())
    finally:
        temporary_path.unlink(missing_ok=True)
    _, _, optional, _, sections = pe_layout(output)
    struct.pack_into("<I", output, optional + 64, 0)  # checksum
    struct.pack_into("<II", output, optional + 112 + 4 * 8, 0, 0)  # Authenticode directory
    payload_va = target.image_base + section_rva - PAYLOAD_FIRST_RVA
    hook_va = payload_va + exports["Hook"]
    frame_hook_va = payload_va + exports["FrameHook"]
    live_hook_va = payload_va + exports["LiveSelectionHook"]
    remote_tab_surface_hook_va = payload_va + exports["RemoteTabSurfaceHook"]
    remote_tab_hover_hook_va = payload_va + exports["RemoteTabHoverHook"]
    cross_window_transfer_rva = (
        payload_va + exports["CrossWindowTryTransfer"] - target.image_base)
    cross_window_preview_rva = (
        payload_va + exports["CrossWindowPreviewPulse"] - target.image_base)
    patch_call(output, target, sections, layout.startup_site, layout.original_initializer,
               hook_va, "startup")
    patch_call(output, target, sections, layout.frame_site, layout.original_frame,
               frame_hook_va, "frame")
    for site in layout.live_call_sites:
        patch_call(output, target, sections, site, layout.live_wrapper,
                   live_hook_va, "live selection")
    if unicode_layout is not None:
        unicode_payload_va = target.image_base + unicode_section_rva - UNICODE_PAYLOAD_FIRST_RVA
        report["unicode"] = apply_unicode_patch(
            output, target, sections, unicode_layout, unicode_payload_va, unicode_exports)
    if include_tab:
        original_tab_surface = target.image_base + TAB_SURFACE_RENDERER_RVA
        for call_rva in TAB_SURFACE_CALL_RVAS:
            patch_call(output, target, sections, target.image_base + call_rva,
                       original_tab_surface, remote_tab_surface_hook_va,
                       "cross-window native tab marker")
        original_tab_hover = target.image_base + TAB_HOVER_HELPER_RVA
        for call_rva in TAB_HOVER_CALL_RVAS:
            patch_call(output, target, sections, target.image_base + call_rva,
                       original_tab_hover, remote_tab_hover_hook_va,
                       "cross-window native tab hover")
        report["cross_window_preview"] = {
            "native_tab_surface_renderer": f"0x{original_tab_surface:x}",
            "call_sites": [f"0x{target.image_base + rva:x}" for rva in TAB_SURFACE_CALL_RVAS],
            "input_state_global": f"0x{target.image_base + INPUT_STATE_GLOBAL_RVA:x}",
            "frame_generation_global":
                f"0x{target.image_base + FRAME_GENERATION_GLOBAL_RVA:x}",
            "native_hover_helper": f"0x{original_tab_hover:x}",
            "hover_call_sites": [
                f"0x{target.image_base + rva:x}" for rva in TAB_HOVER_CALL_RVAS],
        }
        report["tab_tearoff"] = apply_tab_patch(
            output, target.digest, cross_window_transfer_rva,
            cross_window_preview_rva)
    if layout_path:
        layout_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    output_path.write_bytes(output)
    print(f"Wrote {output_path}")
    print(f"SHA-256 {hashlib.sha256(output).hexdigest()}")


def analyze(target_path: Path, layout_path: Path | None = None, include_tab: bool = True,
            include_unicode: bool = False):
    target = TargetImage(target_path)
    if include_tab and target.digest not in TAB_SUPPORTED_SHA256:
        raise ValueError(
            "tab tear-off patch has no verified profile for input SHA-256 "
            f"{target.digest}; use --open-location-only to analyze only the structural patch")
    report = discover_layout(target).report()
    report["build_profile"] = build_profile_name(include_tab, include_unicode)
    report["patches"] = {
        "open_file_location": True,
        "tab_window_creation": include_tab,
        "cross_window_tab_merge": include_tab,
    }
    if include_unicode:
        report["patches"]["unicode_text"] = True
        report["unicode"] = discover_unicode_layout(target).report()
    if include_tab:
        report["tab_tearoff"] = {
            "profile": TAB_SUPPORTED_SHA256[target.digest],
            "validation": "exact SHA-256 plus per-hook byte checks during patch mode",
        }
    rendered = json.dumps(report, indent=2)
    print(rendered)
    if layout_path:
        layout_path.write_text(rendered + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--analyze", action="store_true",
                        help="discover and validate a target without writing an executable")
    parser.add_argument("--layout-json", type=Path,
                        help="write the discovered target layout as JSON")
    parser.add_argument("--open-location-only", action="store_true",
                        help="omit all tab patches and emit only Open File Location integration")
    parser.add_argument(
        "--all", action="store_true",
        help="emit Open File Location, tab creation/merge, and the D3D-atlas Unicode renderer")
    parser.add_argument("--unicode-payload", type=Path,
                        help="compiled unicode_payload.dll used with --all")
    parser.add_argument("input", type=Path, help="unpatched File Pilot executable")
    parser.add_argument("payload", type=Path, nargs="?", help="compiled payload DLL")
    parser.add_argument("output", type=Path, nargs="?", help="patched standalone executable")
    args = parser.parse_args()
    if args.all and args.open_location_only:
        parser.error("--all cannot be combined with --open-location-only")
    include_unicode = args.all
    if args.analyze:
        if args.payload or args.output:
            parser.error("--analyze accepts only the input executable")
        analyze(args.input, args.layout_json, not args.open_location_only, include_unicode)
        return
    if not args.payload or not args.output:
        parser.error("patch mode requires input, payload, and output paths")
    if include_unicode and not args.unicode_payload:
        parser.error("--all requires --unicode-payload")
    patch(args.input, args.payload, args.output, args.layout_json,
          not args.open_location_only, include_unicode, args.unicode_payload)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as error:
        raise SystemExit(f"error: {error}") from None
