"""Discover and apply the File Pilot Open File Location and tab-transport patches.

The locator intentionally fails closed. It uses masked structural signatures and exception-table
function boundaries to find the required native regions, derives their call targets and structure
offsets from disassembly, resolves every Windows API through the target's import table, and
validates cross-references before writing. The tab tear-off extension is additionally gated to an
exact build profile because its hooks depend on register and stack layouts at native instruction
seams. Miller-navigation regions are discovered for compatibility reporting only and are never
patched by this combined emitter. Use --open-location-only to emit only the shell integration.
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
BINDINGS_VERSION = 21
BINDINGS_QWORDS = 82
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

# The folder inspector's synchronization routine.  The fixed instructions describe the flow
# "panel -> inspector state -> selected item -> folder mode -> backing model -> metadata path";
# all structure displacements and the metadata helper call are derived from the match.
INSPECTOR_SYNC_SIGNATURE = (
    "48 8B 8F ?? ?? ?? ?? 45 33 F6 48 8B 99 ?? ?? ?? ?? 48 85 DB "
    "0F 84 ?? ?? ?? ?? 83 B9 ?? ?? ?? ?? 02 0F 85 ?? ?? ?? ?? "
    "48 8B 89 ?? ?? ?? ?? 48 8B D3 0F 29 B4 24 ?? ?? ?? ?? "
    "E8 ?? ?? ?? ?? 44 8B 43 20 48 8B D0 0F 10 70 ??",
    0,
)

# Native Inspector surface renderer.  The ordinary panel surface calls this after computing the
# Inspector width; Inspector child panels bypass that surface to suppress tabs, so Miller invokes
# the same renderer explicitly for recursive children.
INSPECTOR_RENDERER_SIGNATURE = (
    "48 8B C4 55 48 8D A8 ?? ?? ?? ?? 48 81 EC ?? ?? ?? ?? "
    "44 0F 29 48 88 44 0F 29 90 ?? ?? ?? ?? 44 0F 29 98 ?? ?? ?? ?? "
    "48 89 58 18 41 8B D8 48 89 78 E8 45 33 C0 4C 89 68 D8 4C 8B E9",
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

# Native "Cancel selection" callback.  It is used before the cursor-toggle callback so Miller
# navigation keeps exactly one solid selected row in each column.
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

    def import_iat(self) -> dict[str, int]:
        found: dict[str, list[int]] = {name: [] for name in IMPORT_BINDINGS}
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


def discover_miller_layout(target: TargetImage, instruction_starts: set[int]) -> dict:
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    inspector_renderer = target.locate_signature(
        "inspector renderer", INSPECTOR_RENDERER_SIGNATURE)

    item_interaction = target.locate_signature("item interaction", ITEM_INTERACTION_SIGNATURE)
    item_instructions = list(decoder.disasm(target.read(item_interaction, 0x1200),
                                             item_interaction))
    open_specification, open_call_offset = OPEN_COMMAND_SIGNATURE
    open_matches = [target.text_va + offset
                    for offset in find_masked(target.text_data, open_specification)]
    candidates = [sequence for sequence in open_matches
                  if item_interaction <= sequence < item_interaction + 0x1200]
    if len(candidates) != 1:
        rendered = ", ".join(hex(item) for item in candidates) or "none"
        raise ValueError(f"Miller open-command path expected one child-aware match, found "
                         f"{len(candidates)}: {rendered}")

    sequence = candidates[0]
    child_offsets = []
    for instruction in item_instructions:
        if instruction.address >= sequence or instruction.mnemonic != "cmp" or \
                len(instruction.operands) != 2:
            continue
        memory = memory_base_and_disp(instruction, 0)
        immediate = instruction.operands[1]
        if (memory and memory[0] == "r14" and memory[1] >= 0x400 and
                instruction.operands[0].size == 2 and immediate.type == X86_OP_IMM and
                immediate.imm == 0):
            child_offsets.append(memory[1])
    child_flag_offset = unique_value(child_offsets, "inspector-child flag offset")
    begin_open_site = sequence + open_call_offset
    begin_queued_command = target.decode_call(begin_open_site)
    if not target.in_text(begin_queued_command):
        raise ValueError("queued-command builder is outside .text")

    selection_cancel = target.locate_signature(
        "selection-cancel callback", SELECTION_CANCEL_SIGNATURE)
    toggle_cursor_candidates = []
    panel_focused_item_candidates = []
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
        if not has_toggle_command:
            continue
        has_cursor_event = any(
            instruction.mnemonic == "cmp" and len(instruction.operands) == 2 and
            register_name(instruction, 0) == "r8d" and
            instruction.operands[1].type == X86_OP_IMM and
            instruction.operands[1].imm == 2
            for instruction in callback_instructions[:call_index])
        if not has_cursor_event:
            continue
        toggle_cursor_candidates.append(begin)
        panel_focused_item_candidates.extend(
            memory[1]
            for instruction in callback_instructions[:call_index]
            if instruction.mnemonic == "mov" and len(instruction.operands) == 2 and
            register_name(instruction, 0) == "rdx" and
            (memory := memory_base_and_disp(instruction, 1)) is not None and
            memory[0] == "rdi" and 0x100 <= memory[1] < 0x400)
    toggle_cursor_selection = unique_value(
        toggle_cursor_candidates, "toggle-cursor-selection callback")
    panel_focused_item_offset = unique_value(
        panel_focused_item_candidates, "panel focused-item offset")

    open_command_sites = []
    for index, instruction in enumerate(item_instructions):
        if immediate_call_target(instruction) != begin_queued_command:
            continue
        setup = item_instructions[max(0, index - 5):index]
        commands = [candidate.operands[1].imm for candidate in setup
                    if candidate.mnemonic in {"mov", "lea"} and
                    len(candidate.operands) == 2 and
                    register_name(candidate, 0) == "edx" and
                    candidate.operands[1].type == X86_OP_IMM]
        if commands and commands[-1] in {0x30, 0x31}:
            open_command_sites.append((commands[-1], instruction.address))
    directory_open_sites = [site for command, site in open_command_sites if command == 0x30]
    inspector_open_sites = [site for command, site in open_command_sites if command == 0x31]
    if inspector_open_sites != [begin_open_site] or len(directory_open_sites) != 1:
        raise ValueError("expected one standard and one inspector directory-open command site")
    begin_open_call_sites = sorted(directory_open_sites + inspector_open_sites)

    metadata_candidates = []
    for index, instruction in enumerate(item_instructions):
        if not sequence - 0x200 <= instruction.address < sequence:
            continue
        called = immediate_call_target(instruction)
        if called is None or index == 0 or index + 1 >= len(item_instructions):
            continue
        before = item_instructions[index - 1]
        after = item_instructions[index + 1]
        backing = memory_base_and_disp(before, 1) if before.mnemonic == "mov" else None
        flags = memory_base_and_disp(after, 1) if after.mnemonic == "mov" else None
        if (register_name(before, 0) == "rcx" and backing and backing[0] == "r14" and
                register_name(after, 0) == "eax" and flags and flags[0] == "rax"):
            metadata_candidates.append((called, backing[1], flags[1], index))
    if len(metadata_candidates) != 1:
        raise ValueError(f"item metadata call expected once near child activation, found "
                         f"{len(metadata_candidates)}")
    item_metadata, panel_backing_offset, metadata_flags_offset, metadata_call_index = \
        metadata_candidates[0]
    item_flag_values = []
    for instruction in item_instructions[max(0, metadata_call_index - 12):metadata_call_index]:
        if instruction.mnemonic != "mov" or len(instruction.operands) != 2:
            continue
        memory = memory_base_and_disp(instruction, 1)
        if register_name(instruction, 0) == "edx" and memory and memory[0] == "rcx":
            item_flag_values.append(memory[1])
    item_flags_offset = unique_value(item_flag_values, "item flags offset")

    item_interaction_call_sites = []
    for site in instruction_starts:
        if target.read(site, 1) == b"\xE8" and target.decode_call(site) == item_interaction:
            item_interaction_call_sites.append(site)
    item_interaction_call_sites.sort()
    if not 2 <= len(item_interaction_call_sites) <= 24:
        raise ValueError(f"expected 2..24 item-interaction call sites, found "
                         f"{len(item_interaction_call_sites)}")

    sync_site = target.locate_signature("inspector synchronization", INSPECTOR_SYNC_SIGNATURE)
    runtime_functions = target.runtime_functions()
    sync_matches = [index for index, (begin, end) in enumerate(runtime_functions)
                    if begin <= sync_site < end]
    if len(sync_matches) != 1:
        raise ValueError("inspector synchronization site has no unique runtime function")
    sync_index = sync_matches[0]
    while (sync_index and
           runtime_functions[sync_index - 1][1] == runtime_functions[sync_index][0]):
        sync_index -= 1
    inspector_sync = runtime_functions[sync_index][0]
    inspector_sync_call_sites = sorted(
        site for site in instruction_starts
        if target.read(site, 1) == b"\xE8" and target.decode_call(site) == inspector_sync)
    if len(inspector_sync_call_sites) != 1:
        raise ValueError("inspector synchronization entry expected one direct caller")
    inspector_sync_call_site = inspector_sync_call_sites[0]
    inspector_frame, inspector_frame_end = target.containing_runtime_function(
        inspector_sync_call_site)
    inspector_frame_instructions = list(decoder.disasm(
        target.read(inspector_frame, inspector_frame_end - inspector_frame), inspector_frame))
    sync_call_index = next(
        index for index, instruction in enumerate(inspector_frame_instructions)
        if instruction.address == inspector_sync_call_site)
    child_render_calls = [
        instruction for instruction in inspector_frame_instructions[sync_call_index + 1:]
        if immediate_call_target(instruction) is not None]
    if len(child_render_calls) != 1:
        raise ValueError("inspector frame expected one child-render call after synchronization")
    inspector_child_render_site = child_render_calls[0].address
    panel_renderer = immediate_call_target(child_render_calls[0])
    if panel_renderer is None or not target.in_text(panel_renderer):
        raise ValueError("inspector child renderer is outside .text")
    renderer_frame_calls = sorted(
        site for site in instruction_starts
        if target.read(site, 1) == b"\xE8" and target.decode_call(site) == inspector_frame)
    if len(renderer_frame_calls) != 1:
        raise ValueError("panel renderer expected one inspector-frame call")

    inspector_renderer_call_sites = sorted(
        site for site in instruction_starts
        if target.read(site, 1) == b"\xE8" and target.decode_call(site) == inspector_renderer)
    if not 2 <= len(inspector_renderer_call_sites) <= 8:
        raise ValueError("Inspector renderer expected 2..8 direct surface call sites")
    surface_roots = []
    for site in inspector_renderer_call_sites:
        matches = [index for index, (begin, end) in enumerate(runtime_functions)
                   if begin <= site < end]
        if len(matches) != 1:
            raise ValueError("Inspector renderer call has no unique runtime function")
        root_index = matches[0]
        while (root_index and
               runtime_functions[root_index - 1][1] == runtime_functions[root_index][0]):
            root_index -= 1
        surface_roots.append(runtime_functions[root_index][0])
    panel_surface_renderer = unique_value(surface_roots, "panel surface renderer")

    panel_viewport_site = target.locate_signature(
        "panel viewport renderer", PANEL_VIEWPORT_SIGNATURE)
    panel_viewport_renderer, _ = target.containing_runtime_function(panel_viewport_site)
    panel_viewport_call_sites = sorted(
        site for site in instruction_starts
        if target.read(site, 1) == b"\xE8" and
        target.decode_call(site) == panel_viewport_renderer)
    if not 1 <= len(panel_viewport_call_sites) <= 4:
        raise ValueError("panel viewport renderer expected 1..4 direct surface calls")

    surface_instructions = list(decoder.disasm(
        target.read(panel_surface_renderer, 0x1000), panel_surface_renderer))

    # The surface loads the global layout context and immediately reads its 16-bit phase. Derive
    # both values so the payload can distinguish construction from paint without build constants.
    phase_candidates = []
    for index, instruction in enumerate(surface_instructions[:-1]):
        following = surface_instructions[index + 1]
        source = memory_base_and_disp(instruction, 1) \
            if instruction.mnemonic == "mov" and len(instruction.operands) == 2 else None
        phase = memory_base_and_disp(following, 1) \
            if following.mnemonic == "movzx" and len(following.operands) == 2 else None
        if (source and phase and register_name(instruction, 0) == "rcx" and
                source[0] == "rip" and register_name(following, 0) == "eax" and
                phase[0] == "rcx" and
                following.operands[1].size == 2):
            phase_candidates.append((instruction.address + instruction.size + source[1], phase[1]))
    if len(set(phase_candidates)) != 1:
        raise ValueError("panel surface expected one global layout-phase load")
    layout_context_global, layout_phase_offset = phase_candidates[0]

    # Header and slider-canvas calls both occur before the phase-0 and phase-1 viewport calls. The
    # Header renderer is the common call closest to those viewport calls in both passes.
    surface_calls: dict[int, list[int]] = {}
    for instruction in surface_instructions:
        called = immediate_call_target(instruction)
        if called is not None:
            surface_calls.setdefault(called, []).append(instruction.address)
    header_candidates = []
    for called, sites in surface_calls.items():
        if len(sites) != len(panel_viewport_call_sites):
            continue
        ordered = sorted(sites)
        if all(site < viewport and viewport - site < 0x80
               for site, viewport in zip(ordered, panel_viewport_call_sites)):
            header_candidates.append((sum(viewport - site for site, viewport
                                          in zip(ordered, panel_viewport_call_sites)),
                                      called, ordered))
    if not header_candidates:
        raise ValueError("panel Header renderer was not found before both viewport passes")
    header_candidates.sort()
    if len(header_candidates) > 1 and header_candidates[0][0] == header_candidates[1][0]:
        raise ValueError("panel Header renderer ordering is ambiguous")
    _, panel_header_renderer, panel_header_call_sites = header_candidates[0]

    # The phase-0 surface constructs Footer after Header and immediately before Viewport. Unlike
    # Header and Viewport it has no phase-1 call, so identify the sole direct call in that interval.
    # Recursive Miller columns must construct it because the child-content renderer later resolves
    # Panel/Footer/SliderButton to obtain its clipping geometry.
    first_header_site = panel_header_call_sites[0]
    first_viewport_site = panel_viewport_call_sites[0]
    footer_candidates = [
        (called, sites[0]) for called, sites in surface_calls.items()
        if len(sites) == 1 and first_header_site < sites[0] < first_viewport_site
    ]
    if len(footer_candidates) != 1:
        raise ValueError("panel Footer renderer was not uniquely found between Header and Viewport")
    panel_footer_renderer, panel_footer_call_site = footer_candidates[0]

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
    viewport_prefix = viewport_instructions[:12]
    panel_identity_offset = unique_value([
        memory_base_and_disp(instruction, 1)[1]
        for instruction in viewport_prefix
        if instruction.mnemonic == "mov" and len(instruction.operands) == 2 and
        register_name(instruction, 0) == "r9" and
        memory_base_and_disp(instruction, 1) and
        memory_base_and_disp(instruction, 1)[0] == "rdx"
    ], "panel identity offset")

    sync_end = sync_site + 0x500
    sync_instructions = list(decoder.disasm(target.read(sync_site, sync_end - sync_site),
                                             sync_site))
    sync_window = [instruction for instruction in sync_instructions
                   if sync_site <= instruction.address < sync_site + 0x70]

    panel_inspector_offset = unique_value([
        memory_base_and_disp(instruction, 1)[1]
        for instruction in sync_window
        if instruction.mnemonic == "mov" and len(instruction.operands) == 2 and
        register_name(instruction, 0) == "rcx" and
        memory_base_and_disp(instruction, 1) and
        memory_base_and_disp(instruction, 1)[0] == "rdi"
    ], "panel inspector offset")
    inspector_current_item_offset = unique_value([
        memory_base_and_disp(instruction, 1)[1]
        for instruction in sync_window
        if instruction.mnemonic == "mov" and len(instruction.operands) == 2 and
        register_name(instruction, 0) == "rbx" and
        memory_base_and_disp(instruction, 1) and
        memory_base_and_disp(instruction, 1)[0] == "rcx"
    ], "inspector current-item offset")
    inspector_mode_offset = unique_value([
        memory_base_and_disp(instruction, 0)[1]
        for instruction in sync_window
        if instruction.mnemonic == "cmp" and len(instruction.operands) == 2 and
        memory_base_and_disp(instruction, 0) and
        memory_base_and_disp(instruction, 0)[0] == "rcx" and
        memory_base_and_disp(instruction, 0)[1] >= 0x1000 and
        instruction.operands[1].type == X86_OP_IMM and instruction.operands[1].imm == 2
    ], "inspector mode offset")
    inspector_backing_offset = unique_value([
        memory_base_and_disp(instruction, 1)[1]
        for instruction in sync_window
        if instruction.mnemonic == "mov" and len(instruction.operands) == 2 and
        register_name(instruction, 0) == "rcx" and
        memory_base_and_disp(instruction, 1) and
        memory_base_and_disp(instruction, 1)[0] == "rcx" and
        memory_base_and_disp(instruction, 1)[1] >= 0x1000
    ], "inspector backing offset")
    metadata_path_offset = unique_value([
        memory_base_and_disp(instruction, 1)[1]
        for instruction in sync_window
        if instruction.mnemonic == "movups" and len(instruction.operands) == 2 and
        register_name(instruction, 0) == "xmm6" and
        memory_base_and_disp(instruction, 1) and
        memory_base_and_disp(instruction, 1)[0] == "rax"
    ], "metadata path offset")

    child_offsets = []
    owner_offsets = []
    sync_child_flags = []
    panel_view_candidates = []
    view_settings_candidates = []
    navigate_candidates = []
    for index, instruction in enumerate(sync_instructions):
        if not sync_site <= instruction.address < sync_end:
            continue
        if instruction.mnemonic == "mov" and len(instruction.operands) == 2:
            destination_memory = memory_base_and_disp(instruction, 0)
            source_memory = memory_base_and_disp(instruction, 1)
            if register_name(instruction, 0) == "rdx" and source_memory and \
                    source_memory[0] == "rax" and source_memory[1] >= 0x1000:
                child_offsets.append(source_memory[1])
            if destination_memory and destination_memory[0] == "rcx" and \
                    register_name(instruction, 1) == "rdi":
                owner_offsets.append(destination_memory[1])
            if destination_memory and destination_memory[0] == "rcx" and \
                    register_name(instruction, 1) == "r15w" and \
                    instruction.operands[0].size == 2:
                sync_child_flags.append(destination_memory[1])
            if register_name(instruction, 0) == "rax" and source_memory and \
                    source_memory[0] == "rdi" and index + 1 < len(sync_instructions):
                following = sync_instructions[index + 1]
                if following.mnemonic == "add" and register_name(following, 0) == "rax" and \
                        following.operands[1].type == X86_OP_IMM:
                    panel_view_candidates.append(source_memory[1])
                    view_settings_candidates.append(following.operands[1].imm)
        called = immediate_call_target(instruction)
        if called is not None and index >= 2:
            previous = sync_instructions[index - 1]
            earlier = sync_instructions[index - 2]
            previous_memory = memory_base_and_disp(previous, 0) \
                if previous.mnemonic == "mov" else None
            earlier_memory = memory_base_and_disp(earlier, 0) \
                if earlier.mnemonic in {"movdqa", "movaps"} else None
            if (previous_memory and previous_memory[0] == "rsp" and
                    previous_memory[1] == 0x20 and register_name(previous, 1) == "rax" and
                    earlier_memory and earlier_memory[0] == "rsp" and
                    earlier_memory[1] == 0x30):
                navigate_candidates.append(called)

    inspector_child_offset = unique_value(child_offsets, "inspector child offset")
    child_owner_offset = unique_value(owner_offsets, "child owner offset")
    sync_child_flag_offset = unique_value(sync_child_flags, "synchronized child flag offset")
    if sync_child_flag_offset != child_flag_offset:
        raise ValueError("child flag differs between inspector synchronization and item activation")
    panel_view_offset = unique_value(panel_view_candidates, "panel view offset")
    view_settings_offset = unique_value(view_settings_candidates, "view settings offset")
    navigate_panel = unique_value(navigate_candidates, "panel navigation helper")
    if item_metadata != unique_value([
            immediate_call_target(instruction) for instruction in sync_window
            if immediate_call_target(instruction) == item_metadata], "shared metadata helper"):
        raise ValueError("inspector and item renderer use different metadata helpers")

    # These two fields form the stable leading inspector layout block.  Their relationship is
    # validated here and the remaining inspector fields are independently derived above.
    inspector_extent_offset = 0x40
    inspector_ratio_offset = inspector_extent_offset + 4
    inspector_layout_offset = inspector_extent_offset + 8
    inspector_width_offset = inspector_extent_offset + 0x10
    panel_container_offset = child_flag_offset - 0x12
    if panel_container_offset <= 0 or panel_container_offset % 8:
        raise ValueError("panel container is not aligned before child marker")

    inspector_surface_instructions = list(decoder.disasm(
        target.read(inspector_renderer, 0x1000), inspector_renderer))

    # PanelInspector is opened in both layout passes through the same stack-activation helper.
    # The first of those two calls is the phase-0 seam: the node has just been constructed and is
    # current until the native instructions immediately following the call pop it again.
    activation_calls: dict[int, list[int]] = {}
    for instruction in inspector_surface_instructions:
        if instruction.address >= inspector_renderer + 0x600:
            break
        called = immediate_call_target(instruction)
        if called is not None:
            activation_calls.setdefault(called, []).append(instruction.address)
    activation_candidates = [(called, sites) for called, sites in activation_calls.items()
                             if len(sites) == 2]
    if len(activation_candidates) != 1:
        raise ValueError("Inspector layout activation expected one helper called twice in the "
                         f"two-pass prefix, found {len(activation_candidates)}")
    inspector_layout_activate, activation_sites = activation_candidates[0]
    inspector_layout_activate_call_site = activation_sites[0]

    child_surface_candidates = []
    for index, instruction in enumerate(inspector_surface_instructions):
        called = immediate_call_target(instruction)
        if called is None:
            continue
        setup = inspector_surface_instructions[max(0, index - 8):index]
        has_child_load = any(
            candidate.mnemonic == "mov" and len(candidate.operands) == 2 and
            register_name(candidate, 0) == "rdx" and
            (memory := memory_base_and_disp(candidate, 1)) is not None and
            memory[0] == "rdx" and memory[1] == inspector_child_offset
            for candidate in setup)
        has_window_argument = any(
            candidate.mnemonic == "mov" and len(candidate.operands) == 2 and
            register_name(candidate, 0) == "r8" and
            register_name(candidate, 1) == "r14"
            for candidate in setup)
        if has_child_load and has_window_argument:
            child_surface_candidates.append((called, instruction.address))
    inspector_child_surface_renderer = unique_value(
        [candidate[0] for candidate in child_surface_candidates],
        "Inspector child surface renderer")
    inspector_child_surface_site = unique_value(
        [candidate[1] for candidate in child_surface_candidates],
        "Inspector child surface call site")

    # The panel renderer reads the current backing-model path as a StringView.  Validate the
    # stable adjacent pointer/length members before exposing the pointer displacement to the
    # recursive Inspector controller.
    backing_path_offset = 0x168
    # This large renderer is represented by several contiguous unwind regions, so inspect its
    # bounded logical body rather than only the first prologue-sized .pdata entry.
    renderer_instructions = list(decoder.disasm(
        target.read(panel_renderer, 0x1000), panel_renderer))
    has_backing_path_view = any(
        (memory := memory_base_and_disp(instruction, operand_index)) is not None and
        memory[1] == backing_path_offset and instruction.operands[operand_index].size >= 16
        for instruction in renderer_instructions
        for operand_index in range(len(instruction.operands))
    )
    if not has_backing_path_view:
        raise ValueError("panel renderer does not expose the expected backing path StringView")

    navigate_call_sites = sorted(
        site for site in instruction_starts
        if target.read(site, 1) == b"\xE8" and target.decode_call(site) == navigate_panel)
    if not 4 <= len(navigate_call_sites) <= 64:
        raise ValueError(f"expected 4..64 panel-navigation call sites, found "
                         f"{len(navigate_call_sites)}")

    open_right = target.locate_signature("open in right split", OPEN_RIGHT_SIGNATURE)
    open_right_instructions = []
    for instruction in decoder.disasm(target.read(open_right, 0x100), open_right):
        open_right_instructions.append(instruction)
        if instruction.mnemonic == "ret":
            break
    open_right_calls = [immediate_call_target(instruction)
                        for instruction in open_right_instructions
                        if immediate_call_target(instruction) is not None]
    if len(open_right_calls) != 2:
        raise ValueError(f"right-split wrapper expected two direct calls, found "
                         f"{len(open_right_calls)}")
    open_selected_items = open_right_calls[-1]
    app_active_panel_offset = unique_value([
        memory_base_and_disp(instruction, 1)[1]
        for instruction in open_right_instructions
        if instruction.mnemonic == "mov" and len(instruction.operands) == 2 and
        register_name(instruction, 0) == "rdi" and
        memory_base_and_disp(instruction, 1) and
        memory_base_and_disp(instruction, 1)[0] == "rcx"
    ], "active panel offset")

    open_function_matches = [index for index, (begin, end) in enumerate(runtime_functions)
                             if begin <= open_selected_items < end]
    if len(open_function_matches) != 1:
        raise ValueError("selected-item opener has no unique runtime function")
    open_root_index = open_function_matches[0]
    while (open_root_index and
           runtime_functions[open_root_index - 1][1] ==
           runtime_functions[open_root_index][0]):
        open_root_index -= 1
    open_end_index = open_root_index
    while (open_end_index + 1 < len(runtime_functions) and
           runtime_functions[open_end_index][1] == runtime_functions[open_end_index + 1][0]):
        open_end_index += 1
    open_root = runtime_functions[open_root_index][0]
    open_end = runtime_functions[open_end_index][1]
    open_instructions = list(decoder.disasm(target.read(open_root, open_end - open_root),
                                             open_root))
    open_selected_navigate_call_sites = sorted(
        instruction.address for instruction in open_instructions
        if immediate_call_target(instruction) == navigate_panel)
    if not 1 <= len(open_selected_navigate_call_sites) <= 4:
        raise ValueError("right-split opener expected 1..4 navigation call sites, found "
                         f"{len(open_selected_navigate_call_sites)}")

    runtime_functions = target.runtime_functions()
    close_roots = []
    for site in instruction_starts:
        if target.read(site, 1) != b"\xE8" or target.decode_call(site) != begin_queued_command:
            continue
        if site < target.text_va + 5 or target.read(site - 5, 5) != b"\xBA\x55\x00\x00\x00":
            continue
        containing = [index for index, (begin, end) in enumerate(runtime_functions)
                      if begin <= site < end]
        if len(containing) != 1:
            continue
        root_index = containing[0]
        while (root_index and
               runtime_functions[root_index - 1][1] == runtime_functions[root_index][0]):
            root_index -= 1
        root = runtime_functions[root_index][0]
        end_index = root_index
        while (end_index + 1 < len(runtime_functions) and
               runtime_functions[end_index][1] == runtime_functions[end_index + 1][0]):
            end_index += 1
        logical_end = runtime_functions[end_index][1]
        root_instructions = list(decoder.disasm(target.read(root, logical_end - root), root))
        has_event_two = any(
            instruction.mnemonic == "cmp" and len(instruction.operands) == 2 and
            register_name(instruction, 0) in {"r8d", "ebx"} and
            instruction.operands[1].type == X86_OP_IMM and
            instruction.operands[1].imm == 2
            for instruction in root_instructions)
        has_child_marker = any(
            instruction.mnemonic == "cmp" and len(instruction.operands) == 2 and
            memory_base_and_disp(instruction, 0) and
            memory_base_and_disp(instruction, 0)[1] == child_flag_offset and
            instruction.operands[0].size == 2
            for instruction in root_instructions)
        has_active_fallback = any(
            instruction.mnemonic == "mov" and len(instruction.operands) == 2 and
            memory_base_and_disp(instruction, 1) and
            memory_base_and_disp(instruction, 1)[1] == app_active_panel_offset
            for instruction in root_instructions)
        if has_event_two and has_child_marker and has_active_fallback:
            close_roots.append(root)
    close_all_tabs = unique_value(close_roots, "close-all-tabs wrapper")

    values = {
        "item_interaction": item_interaction,
        "item_interaction_call_sites": item_interaction_call_sites,
        "begin_open_site": begin_open_site,
        "begin_open_call_sites": begin_open_call_sites,
        "begin_queued_command": begin_queued_command,
        "selection_cancel": selection_cancel,
        "toggle_cursor_selection": toggle_cursor_selection,
        "open_selected_items": open_selected_items,
        "open_selected_navigate_call_sites": open_selected_navigate_call_sites,
        "close_all_tabs": close_all_tabs,
        "app_active_panel_offset": app_active_panel_offset,
        "item_metadata": item_metadata,
        "inspector_sync": inspector_sync,
        "inspector_sync_call_site": inspector_sync_call_site,
        "inspector_frame": inspector_frame,
        "inspector_renderer": inspector_renderer,
        "inspector_renderer_call_sites": inspector_renderer_call_sites,
        "inspector_child_surface_renderer": inspector_child_surface_renderer,
        "inspector_child_surface_site": inspector_child_surface_site,
        "inspector_layout_activate": inspector_layout_activate,
        "inspector_layout_activate_call_site": inspector_layout_activate_call_site,
        "panel_surface_renderer": panel_surface_renderer,
        "panel_viewport_renderer": panel_viewport_renderer,
        "panel_viewport_call_sites": panel_viewport_call_sites,
        "panel_header_renderer": panel_header_renderer,
        "panel_header_call_sites": panel_header_call_sites,
        "panel_footer_renderer": panel_footer_renderer,
        "panel_footer_call_site": panel_footer_call_site,
        "layout_context_global": layout_context_global,
        "layout_phase_offset": layout_phase_offset,
        "find_imgui_window": find_imgui_window,
        "panel_renderer": panel_renderer,
        "inspector_child_render_site": inspector_child_render_site,
        "navigate_panel": navigate_panel,
        "navigate_call_sites": navigate_call_sites,
        "panel_inspector_offset": panel_inspector_offset,
        "panel_backing_offset": panel_backing_offset,
        "panel_view_offset": panel_view_offset,
        "panel_identity_offset": panel_identity_offset,
        "panel_container_offset": panel_container_offset,
        "child_owner_offset": child_owner_offset,
        "child_flag_offset": child_flag_offset,
        "inspector_extent_offset": inspector_extent_offset,
        "inspector_ratio_offset": inspector_ratio_offset,
        "inspector_layout_offset": inspector_layout_offset,
        "inspector_width_offset": inspector_width_offset,
        "inspector_mode_offset": inspector_mode_offset,
        "inspector_current_item_offset": inspector_current_item_offset,
        "inspector_backing_offset": inspector_backing_offset,
        "inspector_child_offset": inspector_child_offset,
        "view_settings_offset": view_settings_offset,
        "item_flags_offset": item_flags_offset,
        "metadata_path_offset": metadata_path_offset,
        "metadata_flags_offset": metadata_flags_offset,
        "backing_path_offset": backing_path_offset,
        "panel_focused_item_offset": panel_focused_item_offset,
    }
    for label, value in values.items():
        if label.endswith("_call_sites") or label.endswith("_call_site"):
            continue
        if label in {"item_interaction", "begin_open_site", "begin_queued_command",
                      "open_selected_items", "close_all_tabs", "item_metadata",
                      "inspector_sync", "inspector_frame", "inspector_renderer",
                      "inspector_child_surface_renderer", "inspector_child_surface_site",
                      "inspector_layout_activate", "panel_surface_renderer",
                      "panel_viewport_renderer", "panel_header_renderer",
                      "panel_footer_renderer",
                      "find_imgui_window", "panel_renderer",
                      "inspector_child_render_site", "navigate_panel",
                      "selection_cancel", "toggle_cursor_selection"}:
            if not target.in_text(value):
                raise ValueError(f"discovered Miller {label} 0x{value:x} is outside .text")
        elif label == "layout_context_global":
            target.read(value, 8)
        elif value < 0 or value >= 0x2000:
            raise ValueError(f"implausible Miller {label}: 0x{value:x}")
    return values


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
    selection_commit: int
    selection_cancel: int
    toggle_cursor_selection: int
    selection_state_display_offset: int
    display_mode_offset: int
    display_primary_offset: int
    display_alternate_offset: int
    display_count_offset: int
    panel_selection_mode_offset: int
    item_interaction: int
    item_interaction_call_sites: list[int]
    begin_open_site: int
    begin_open_call_sites: list[int]
    begin_queued_command: int
    open_selected_items: int
    open_selected_navigate_call_sites: list[int]
    close_all_tabs: int
    app_active_panel_offset: int
    item_metadata: int
    inspector_sync: int
    inspector_sync_call_site: int
    inspector_frame: int
    inspector_renderer: int
    inspector_renderer_call_sites: list[int]
    inspector_child_surface_renderer: int
    inspector_child_surface_site: int
    inspector_layout_activate: int
    inspector_layout_activate_call_site: int
    panel_surface_renderer: int
    panel_viewport_renderer: int
    panel_viewport_call_sites: list[int]
    panel_header_renderer: int
    panel_header_call_sites: list[int]
    panel_footer_renderer: int
    panel_footer_call_site: int
    layout_context_global: int
    layout_phase_offset: int
    find_imgui_window: int
    panel_renderer: int
    inspector_child_render_site: int
    navigate_panel: int
    navigate_call_sites: list[int]
    panel_inspector_offset: int
    panel_backing_offset: int
    panel_view_offset: int
    panel_identity_offset: int
    panel_container_offset: int
    child_owner_offset: int
    child_flag_offset: int
    inspector_extent_offset: int
    inspector_ratio_offset: int
    inspector_layout_offset: int
    inspector_width_offset: int
    inspector_mode_offset: int
    inspector_current_item_offset: int
    inspector_backing_offset: int
    inspector_child_offset: int
    view_settings_offset: int
    item_flags_offset: int
    metadata_path_offset: int
    metadata_flags_offset: int
    backing_path_offset: int
    panel_focused_item_offset: int
    imports: dict[str, int]

    def binding_values(self, include_tab: bool = True) -> list[int]:
        values = [BINDINGS_MAGIC, BINDINGS_VERSION, BINDINGS_QWORDS * 8]
        values.extend(self.imports[name] for name in IMPORT_BINDINGS)
        values.extend((self.selector, self.original_initializer, self.live_wrapper,
                       self.selection_commit, self.selection_cancel,
                       self.toggle_cursor_selection, self.original_frame,
                       self.selection_state_display_offset,
                       self.display_mode_offset, self.display_primary_offset,
                       self.display_alternate_offset, self.display_count_offset,
                       self.panel_selection_mode_offset,
                       self.item_interaction, self.begin_queued_command,
                        self.item_metadata, self.inspector_sync, self.inspector_frame,
                        self.inspector_renderer, self.inspector_child_surface_renderer,
                        self.panel_surface_renderer, self.panel_viewport_renderer,
                        self.find_imgui_window, self.panel_renderer,
                        self.inspector_layout_activate, self.panel_header_renderer,
                        self.panel_footer_renderer,
                        self.layout_context_global, self.layout_phase_offset,
                        self.navigate_panel,
                       self.open_selected_items, self.close_all_tabs,
                       self.app_active_panel_offset,
                       self.panel_inspector_offset, self.panel_backing_offset,
                       self.panel_view_offset, self.panel_identity_offset,
                       self.panel_container_offset,
                       self.child_owner_offset,
                       self.child_flag_offset, self.inspector_extent_offset,
                       self.inspector_ratio_offset,
                       self.inspector_layout_offset, self.inspector_width_offset,
                       self.inspector_mode_offset,
                       self.inspector_current_item_offset, self.inspector_backing_offset,
                       self.inspector_child_offset, self.view_settings_offset,
                       self.item_flags_offset, self.metadata_path_offset,
                       self.metadata_flags_offset, self.backing_path_offset,
                       self.panel_focused_item_offset,
                       int(include_tab),
                       self.image_base + 0x185550 if include_tab else 0,
                       self.image_base + 0x15F750 if include_tab else 0,
                       self.image_base + 0x1846C0 if include_tab else 0,
                       self.image_base + 0x1925B0 if include_tab else 0,
                       self.image_base + TAB_SURFACE_RENDERER_RVA if include_tab else 0,
                       self.image_base + INPUT_STATE_GLOBAL_RVA if include_tab else 0,
                       self.image_base + FRAME_GENERATION_GLOBAL_RVA if include_tab else 0,
                       self.image_base + TAB_HOVER_HELPER_RVA if include_tab else 0))
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
            "selection_commit": address(self.selection_commit),
            "selection_cancel": address(self.selection_cancel),
            "toggle_cursor_selection": address(self.toggle_cursor_selection),
            "miller": {
                "item_interaction": address(self.item_interaction),
                "item_interaction_call_sites": [address(site)
                                                for site in self.item_interaction_call_sites],
                "begin_open_hook_site": address(self.begin_open_site),
                "begin_open_hook_sites": [address(site)
                                          for site in self.begin_open_call_sites],
                "begin_queued_command": address(self.begin_queued_command),
                "open_selected_items": address(self.open_selected_items),
                "open_selected_navigate_call_sites": [address(site)
                                                       for site in self.open_selected_navigate_call_sites],
                "close_all_tabs": address(self.close_all_tabs),
                "item_metadata": address(self.item_metadata),
                "inspector_sync": address(self.inspector_sync),
                "inspector_sync_call_site": address(self.inspector_sync_call_site),
                "inspector_frame": address(self.inspector_frame),
                "inspector_renderer": address(self.inspector_renderer),
                "inspector_renderer_call_sites": [address(site)
                                                   for site in self.inspector_renderer_call_sites],
                "inspector_child_surface_renderer":
                    address(self.inspector_child_surface_renderer),
                "inspector_child_surface_site": address(self.inspector_child_surface_site),
                "inspector_layout_activate": address(self.inspector_layout_activate),
                "inspector_layout_activate_call_site":
                    address(self.inspector_layout_activate_call_site),
                "panel_surface_renderer": address(self.panel_surface_renderer),
                "panel_viewport_renderer": address(self.panel_viewport_renderer),
                "panel_viewport_call_sites": [address(site)
                                               for site in self.panel_viewport_call_sites],
                "panel_header_renderer": address(self.panel_header_renderer),
                "panel_header_call_sites": [address(site)
                                             for site in self.panel_header_call_sites],
                "panel_footer_renderer": address(self.panel_footer_renderer),
                "panel_footer_call_site": address(self.panel_footer_call_site),
                "layout_context_global": address(self.layout_context_global),
                "layout_phase_offset": address(self.layout_phase_offset),
                "find_imgui_window": address(self.find_imgui_window),
                "panel_renderer": address(self.panel_renderer),
                "inspector_child_render_site": address(self.inspector_child_render_site),
                "navigate_panel": address(self.navigate_panel),
                "navigate_call_sites": [address(site) for site in self.navigate_call_sites],
            },
            "offsets": {
                "selection_state_display": address(self.selection_state_display_offset),
                "display_mode": address(self.display_mode_offset),
                "display_primary": address(self.display_primary_offset),
                "display_alternate": address(self.display_alternate_offset),
                "display_count": address(self.display_count_offset),
                "panel_selection_mode": address(self.panel_selection_mode_offset),
                "panel_inspector": address(self.panel_inspector_offset),
                "panel_backing": address(self.panel_backing_offset),
                "panel_view": address(self.panel_view_offset),
                "panel_identity": address(self.panel_identity_offset),
                "panel_container": address(self.panel_container_offset),
                "child_owner": address(self.child_owner_offset),
                "child_flag": address(self.child_flag_offset),
                "inspector_extent": address(self.inspector_extent_offset),
                "inspector_ratio": address(self.inspector_ratio_offset),
                "inspector_layout": address(self.inspector_layout_offset),
                "inspector_width": address(self.inspector_width_offset),
                "inspector_mode": address(self.inspector_mode_offset),
                "inspector_current_item": address(self.inspector_current_item_offset),
                "inspector_backing": address(self.inspector_backing_offset),
                "inspector_child": address(self.inspector_child_offset),
                "view_settings": address(self.view_settings_offset),
                "item_flags": address(self.item_flags_offset),
                "metadata_path": address(self.metadata_path_offset),
                "metadata_flags": address(self.metadata_flags_offset),
                "backing_path": address(self.backing_path_offset),
                "panel_focused_item": address(self.panel_focused_item_offset),
                "app_active_panel": address(self.app_active_panel_offset),
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
    selector_instructions = list(decoder.disasm(target.read(selector, 0x100), selector))
    panel_selection_mode_offset = unique_value([
        memory_base_and_disp(instruction, 1)[1]
        for index, instruction in enumerate(selector_instructions[:-1])
        if instruction.mnemonic == "mov" and len(instruction.operands) == 2 and
        register_name(instruction, 0) == "eax" and
        memory_base_and_disp(instruction, 1) and
        memory_base_and_disp(instruction, 1)[0] == "rcx" and
        selector_instructions[index + 1].mnemonic == "mov"
    ], "panel selection-mode offset")
    selection_commit_candidates = []
    for index, instruction in enumerate(instructions):
        if (instruction.mnemonic != "call" or not instruction.operands or
                instruction.operands[0].type != X86_OP_IMM or
                instruction.operands[0].imm != selector):
            continue
        for candidate_index in range(index + 1, min(index + 12, len(instructions))):
            candidate = instructions[candidate_index]
            if (candidate.mnemonic != "call" or not candidate.operands or
                    candidate.operands[0].type != X86_OP_IMM):
                continue
            setup = {(item.mnemonic, item.op_str) for item in
                     instructions[max(index + 1, candidate_index - 4):candidate_index]}
            if {("mov", "rdx, rbx"), ("mov", "rcx, rbp")}.issubset(setup):
                selection_commit_candidates.append(candidate.operands[0].imm)
    selection_commit = unique_value(selection_commit_candidates, "selection commit helper")
    for label, value in (
        ("selection-state display offset", selection_state_display_offset),
        ("display-mode offset", display_mode_offset),
        ("primary display offset", display_primary_offset),
        ("alternate display offset", display_alternate_offset),
        ("display-count offset", display_count_offset),
        ("panel selection-mode offset", panel_selection_mode_offset),
    ):
        if value < 0 or value >= 0x1000 or value % 8:
            raise ValueError(f"implausible {label}: 0x{value:x}")
    if not target.in_text(selector):
        raise ValueError(f"native selector 0x{selector:x} is outside .text")
    if not target.in_text(selection_commit):
        raise ValueError(f"selection commit helper 0x{selection_commit:x} is outside .text")

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

    miller = discover_miller_layout(target, instruction_starts)
    if set(miller["item_interaction_call_sites"]) & set(live_call_sites):
        raise ValueError("Miller and live-selection call-site sets overlap unexpectedly")

    return TargetLayout(
        target.digest, KNOWN_SHA256.get(target.digest), target.image_base,
        startup_site, original_initializer, frame_site, original_frame, live_wrapper,
        live_call_sites, selector, selection_commit, miller["selection_cancel"],
        miller["toggle_cursor_selection"], selection_state_display_offset,
        display_mode_offset,
        display_primary_offset, display_alternate_offset, display_count_offset,
        panel_selection_mode_offset,
        miller["item_interaction"], miller["item_interaction_call_sites"],
        miller["begin_open_site"], miller["begin_open_call_sites"],
        miller["begin_queued_command"], miller["open_selected_items"],
        miller["open_selected_navigate_call_sites"], miller["close_all_tabs"],
        miller["app_active_panel_offset"],
        miller["item_metadata"], miller["inspector_sync"],
        miller["inspector_sync_call_site"], miller["inspector_frame"],
        miller["inspector_renderer"], miller["inspector_renderer_call_sites"],
        miller["inspector_child_surface_renderer"],
        miller["inspector_child_surface_site"],
        miller["inspector_layout_activate"],
        miller["inspector_layout_activate_call_site"],
        miller["panel_surface_renderer"], miller["panel_viewport_renderer"],
        miller["panel_viewport_call_sites"], miller["panel_header_renderer"],
        miller["panel_header_call_sites"], miller["panel_footer_renderer"],
        miller["panel_footer_call_site"], miller["layout_context_global"],
        miller["layout_phase_offset"], miller["find_imgui_window"],
        miller["panel_renderer"],
        miller["inspector_child_render_site"],
        miller["navigate_panel"], miller["navigate_call_sites"],
        miller["panel_inspector_offset"], miller["panel_backing_offset"],
        miller["panel_view_offset"], miller["panel_identity_offset"],
        miller["panel_container_offset"],
        miller["child_owner_offset"],
        miller["child_flag_offset"], miller["inspector_extent_offset"],
        miller["inspector_ratio_offset"],
        miller["inspector_layout_offset"], miller["inspector_width_offset"],
        miller["inspector_mode_offset"],
        miller["inspector_current_item_offset"], miller["inspector_backing_offset"],
        miller["inspector_child_offset"], miller["view_settings_offset"],
        miller["item_flags_offset"], miller["metadata_path_offset"],
        miller["metadata_flags_offset"], miller["backing_path_offset"],
        miller["panel_focused_item_offset"],
        target.import_iat(),
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
                             "ItemInteractionHook", "BeginOpenHook",
                              "MillerNavigateHook", "MillerInspectorSyncHook",
                              "RecursiveInspectorRenderHook", "PanelViewportHook",
                              "PanelInspectorSurfaceHook", "InspectorPhase0ActivateHook",
                              "RecursiveInspectorChildSurfaceHook", "PanelHeaderHook",
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


def choose_section_rva(target: TargetImage) -> int:
    end = max(section.rva + max(section.vsize, section.raw_size) for section in target.sections)
    return align(end, target.section_alignment)


def miller_call_sites(layout: TargetLayout) -> list[int]:
    """Return every native call site reserved for the separate Miller experiment."""
    sites = {
        *layout.item_interaction_call_sites,
        *layout.begin_open_call_sites,
        layout.inspector_sync_call_site,
        layout.inspector_child_render_site,
        layout.inspector_layout_activate_call_site,
        layout.inspector_child_surface_site,
        *layout.panel_viewport_call_sites,
        *layout.panel_header_call_sites,
        *layout.inspector_renderer_call_sites,
        *layout.navigate_call_sites,
    }
    return sorted(sites)


def verify_miller_unmodified(output: bytearray, sections: list[SectionRecord],
                             target: TargetImage, layout: TargetLayout) -> int:
    sites = miller_call_sites(layout)
    for site in sites:
        output_file = rva_to_file(sections, site - target.image_base)
        if bytes(output[output_file:output_file + 5]) != target.read(site, 5):
            raise ValueError(f"Miller separation guard detected a modified call at 0x{site:x}")
    return len(sites)


def patch(target_path: Path, payload_path: Path, output_path: Path,
          layout_path: Path | None = None, include_tab: bool = True):
    target = TargetImage(target_path)
    if include_tab and target.digest not in TAB_SUPPORTED_SHA256:
        raise ValueError(
            "tab tear-off patch has no verified profile for input SHA-256 "
            f"{target.digest}; use --open-location-only for structurally compatible builds")
    layout = discover_layout(target)
    report = layout.report()
    report["patches"] = {
        "open_file_location": True,
        "tab_window_creation": include_tab,
        "cross_window_tab_merge": include_tab,
        "miller_navigation": False,
    }

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
    report["miller_separation_guard"] = {
        "modified_call_sites": 0,
        "verified_native_call_sites": verify_miller_unmodified(
            output, sections, target, layout),
    }
    if layout_path:
        layout_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    output_path.write_bytes(output)
    print(f"Wrote {output_path}")
    print(f"SHA-256 {hashlib.sha256(output).hexdigest()}")


def analyze(target_path: Path, layout_path: Path | None = None, include_tab: bool = True):
    target = TargetImage(target_path)
    if include_tab and target.digest not in TAB_SUPPORTED_SHA256:
        raise ValueError(
            "tab tear-off patch has no verified profile for input SHA-256 "
            f"{target.digest}; use --open-location-only to analyze only the structural patch")
    report = discover_layout(target).report()
    report["patches"] = {
        "open_file_location": True,
        "tab_window_creation": include_tab,
        "cross_window_tab_merge": include_tab,
        "miller_navigation": False,
    }
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
    parser.add_argument("input", type=Path, help="unpatched File Pilot executable")
    parser.add_argument("payload", type=Path, nargs="?", help="compiled payload DLL")
    parser.add_argument("output", type=Path, nargs="?", help="patched standalone executable")
    args = parser.parse_args()
    if args.analyze:
        if args.payload or args.output:
            parser.error("--analyze accepts only the input executable")
        analyze(args.input, args.layout_json, not args.open_location_only)
        return
    if not args.payload or not args.output:
        parser.error("patch mode requires input, payload, and output paths")
    patch(args.input, args.payload, args.output, args.layout_json,
          not args.open_location_only)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as error:
        raise SystemExit(f"error: {error}") from None
