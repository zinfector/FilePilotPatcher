"""Fail-closed File Pilot 0.8.2 tab tear-off patch emitter.

The Open File Location payload is discovered structurally by
``patch_filepilot.py``.  The tab tear-off hooks depend on register and stack
layouts at eight native seams, so this module deliberately accepts only the
exact build whose layouts were verified in Ghidra and at runtime.
"""
from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass


SUPPORTED_SHA256 = {
    "08826147a90e7c6a1c4e80968aaa927b14cfbca7271c7d12db3af9f24c483646":
        "File Pilot 0.8.2 x64",
}

GRIP_MAGIC = 0x31545046       # FPT1
PLACEMENT_MAGIC = 0x32545046  # FPT2
PLACEMENT_SIZE = 0x20


def _u16(data: bytes | bytearray, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes | bytearray, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


@dataclass(frozen=True)
class _Section:
    name: str
    vsize: int
    rva: int
    raw_size: int
    raw: int


def _pe_layout(data: bytes | bytearray):
    pe = _u32(data, 0x3C)
    if data[pe:pe + 4] != b"PE\0\0":
        raise ValueError("not a PE file")
    coff = pe + 4
    if _u16(data, coff) != 0x8664:
        raise ValueError("tab patch expects an AMD64 executable")
    optional = coff + 20
    if _u16(data, optional) != 0x20B:
        raise ValueError("tab patch expects a PE32+ executable")
    section_count = _u16(data, coff + 2)
    table = optional + _u16(data, coff + 16)
    sections = []
    for index in range(section_count):
        header = table + index * 40
        sections.append(_Section(
            bytes(data[header:header + 8]).rstrip(b"\0").decode("ascii", "replace"),
            _u32(data, header + 8), _u32(data, header + 12),
            _u32(data, header + 16), _u32(data, header + 20),
        ))
    return pe, coff, optional, table, sections


def _rva_to_file(sections: list[_Section], rva: int) -> int:
    for section in sections:
        if section.rva <= rva < section.rva + max(section.vsize, section.raw_size):
            return section.raw + rva - section.rva
    raise ValueError(f"tab patch RVA 0x{rva:x} is not file-backed")


def _assert_bytes(data: bytearray, sections: list[_Section], rva: int,
                  expected: bytes, label: str) -> int:
    offset = _rva_to_file(sections, rva)
    actual = bytes(data[offset:offset + len(expected)])
    if actual != expected:
        raise ValueError(
            f"{label} at RVA 0x{rva:x} changed: expected {expected.hex(' ')}, "
            f"found {actual.hex(' ')}")
    return offset


class _Emitter:
    def __init__(self, base_rva: int):
        self.base_rva = base_rva
        self.code = bytearray()

    @property
    def rva(self) -> int:
        return self.base_rva + len(self.code)

    def emit(self, value: str | bytes | bytearray):
        if isinstance(value, str):
            self.code.extend(bytes.fromhex(value))
        else:
            self.code.extend(value)

    def i32(self, value: int):
        if not -(1 << 31) <= value < (1 << 31):
            raise ValueError(f"rel32 value is out of range: {value}")
        self.code.extend(struct.pack("<i", value))

    def rel_call(self, target_rva: int):
        start = self.rva
        self.emit(b"\xE8")
        self.i32(target_rva - (start + 5))

    def rel_jump(self, target_rva: int):
        start = self.rva
        self.emit(b"\xE9")
        self.i32(target_rva - (start + 5))

    def rip(self, prefix: str, target_rva: int, instruction_length: int):
        start = self.rva
        self.emit(prefix)
        self.i32(target_rva - (start + instruction_length))

    def patch_rel8(self, index: int, target_index: int):
        delta = target_index - (index + 1)
        if not -128 <= delta <= 127:
            raise ValueError("rel8 is out of range")
        self.code[index] = delta & 0xFF

    def patch_rel32(self, index: int, target_index: int):
        delta = target_index - (index + 4)
        if not -(1 << 31) <= delta < (1 << 31):
            raise ValueError("rel32 is out of range")
        struct.pack_into("<i", self.code, index, delta)


def _rel32(source_rva: int, instruction_length: int, target_rva: int) -> bytes:
    delta = target_rva - (source_rva + instruction_length)
    if not -(1 << 31) <= delta < (1 << 31):
        raise ValueError("relative branch target is out of range")
    return struct.pack("<i", delta)


def _apply_first_stage(data: bytearray, sections: list[_Section]):
    # Allow the native close-old-tab + spawn path when the source has one tab.
    branch_rva = 0x16D382
    branch = _assert_bytes(data, sections, branch_rva, b"\x76\xE7", "single-tab JBE")
    data[branch:branch + 2] = b"\x90\x90"

    # A clipboard-launched child must not restore stale saved geometry over its
    # provisional tear-off coordinates.  Keep this compact verified cave so the
    # Python output remains equivalent to the already runtime-tested build.
    hook_rva = 0x1DEC14
    resume_rva = 0x1DEC1D
    skip_rva = 0x1DEC8B
    cave_rva = 0x216900
    hook = _assert_bytes(
        data, sections, hook_rva,
        bytes.fromhex("83 BD 50 06 00 00 00 74 6E"),
        "startup geometry check")
    cave = _rva_to_file(sections, cave_rva)
    stub = bytearray.fromhex("48 83 7D 70 00 0F 85")
    stub += _rel32(cave_rva + 5, 6, skip_rva)
    stub += bytes.fromhex("83 BD 50 06 00 00 00 0F 84")
    stub += _rel32(cave_rva + 18, 6, skip_rva)
    stub += b"\xE9" + _rel32(cave_rva + 24, 5, resume_rva)
    if any(data[cave:cave + len(stub)]):
        raise ValueError("startup geometry code cave is not empty")
    data[hook:hook + 9] = b"\xE9" + _rel32(hook_rva, 5, cave_rva) + b"\x90" * 4
    data[cave:cave + len(stub)] = stub

    text_index = next((index for index, section in enumerate(sections)
                       if section.name == ".text"), None)
    if text_index is None:
        raise ValueError("tab patch could not find .text")
    _, _, _, table, _ = _pe_layout(data)
    text_header = table + text_index * 40
    required_vsize = cave_rva - sections[text_index].rva + len(stub)
    if required_vsize > sections[text_index].vsize:
        struct.pack_into("<I", data, text_header + 8, required_vsize)


def _build_code(code_rva: int, state_rva: int,
                cross_window_transfer_rva: int | None = None,
                cross_window_preview_rva: int | None = None) -> tuple[bytes, dict[str, int]]:
    e = _Emitter(code_rva)
    grip_anchor_x = state_rva
    grip_anchor_y = state_rva + 4
    grip_valid = state_rva + 8
    grip_raw_x = state_rva + 12
    grip_raw_y = state_rva + 16
    placement = state_rva + 0x20
    placement_size = placement + 4
    placement_desired_x = placement + 8
    placement_desired_y = placement + 12
    placement_raw_x = placement + 16
    placement_raw_y = placement + 20
    placement_anchor_x = placement + 24
    placement_anchor_y = placement + 28
    get_async_key_state_ptr = state_rva + 0x48
    pending = state_rva + 0x60
    pending_size = pending + 4
    pending_desired_x = pending + 8
    pending_desired_y = pending + 12
    pending_raw_x = pending + 16
    pending_raw_y = pending + 20
    pending_anchor_x = pending + 24
    pending_anchor_y = pending + 28
    format_name = code_rva + 0xE00
    user32_name = code_rva + 0xE40
    get_async_key_state_name = code_rva + 0xE60
    stubs: dict[str, int] = {}

    # Capture the tab's window-relative anchor and raw tooltip grip.
    stubs["activation"] = e.rva
    e.emit("49 89 87 A0 0E 00 00 50 51 52 41 50 41 51 41 52 41 53 48 83 EC 30")
    e.rip("C7 05", grip_valid, 10); e.emit("00 00 00 00")
    e.emit("4D 8B 84 24 F0 04 00 00 49 8B 08")
    e.rip("4C 8D 05", 0x229A18, 7); e.emit("BA 04 00 00 00")
    loop1 = len(e.code)
    e.emit("41 0F B6 00 48 6B C9 21 48 01 C1 49 FF C0 FF CA 75 00")
    e.patch_rel8(len(e.code) - 1, loop1)
    e.emit("48 6B C9 21 49 03 4C 24 78")
    e.rip("4C 8D 05", 0x22A854, 7); e.emit("BA 05 00 00 00")
    loop2 = len(e.code)
    e.emit("41 0F B6 00 48 6B C9 21 48 01 C1 49 FF C0 FF CA 75 00")
    e.patch_rel8(len(e.code) - 1, loop2)
    e.rel_call(0x1CAC10)
    e.emit("48 89 44 24 20 B9 20 00 00 00")
    e.rip("FF 15", 0x217650, 6)
    e.emit("89 44 24 28 B9 5C 00 00 00")
    e.rip("FF 15", 0x217650, 6)
    e.emit("44 8B 54 24 28 41 01 C2 4C 8B 5C 24 20")
    e.rip("48 8B 15", 0x246F80, 7)
    e.emit("8B 4A 58 41 2B 8B 90 02 00 00")
    e.rip("89 0D", grip_raw_x, 6)
    e.emit("41 03 8F A0 0E 00 00 44 01 D1 83 E9 05")
    e.rip("89 0D", grip_anchor_x, 6)
    e.emit("8B 4A 5C")
    e.rip("89 0D", grip_anchor_y, 6)
    e.emit("41 2B 8B 94 02 00 00")
    e.rip("89 0D", grip_raw_y, 6)
    e.rip("C7 05", grip_valid, 10); e.i32(GRIP_MAGIC)
    e.emit("48 83 C4 30 41 5B 41 5A 41 59 41 58 5A 59 58 C3")

    # Capture the detach point into parent-private state; never touch the job,
    # whose serialized JSON starts at +0x58.
    stubs["export_call"] = e.rva
    e.emit("F6 C2 01 0F 84 00 00 00 00"); no_tear = len(e.code) - 4
    e.rip("81 3D", grip_valid, 10); e.i32(GRIP_MAGIC)
    e.emit("0F 85 00 00 00 00"); no_grip = len(e.code) - 4
    e.emit("51 52 48 83 EC 30 48 8D 4C 24 20")
    e.rip("C7 05", pending, 10); e.emit("00 00 00 00")
    e.rip("FF 15", 0x217788, 6)
    e.emit("85 C0 0F 84 00 00 00 00"); capture_failed = len(e.code) - 4
    e.emit("8B 44 24 20"); e.rip("2B 05", grip_anchor_x, 6)
    e.rip("89 05", pending_desired_x, 6)
    e.emit("8B 44 24 24"); e.rip("2B 05", grip_anchor_y, 6)
    e.rip("89 05", pending_desired_y, 6)
    e.rip("8B 05", grip_raw_x, 6); e.rip("89 05", pending_raw_x, 6)
    e.rip("8B 05", grip_raw_y, 6); e.rip("89 05", pending_raw_y, 6)
    e.rip("8B 05", grip_anchor_x, 6); e.rip("89 05", pending_anchor_x, 6)
    e.rip("8B 05", grip_anchor_y, 6); e.rip("89 05", pending_anchor_y, 6)
    e.rip("C7 05", pending_size, 10); e.i32(PLACEMENT_SIZE)
    e.rip("C7 05", pending, 10); e.i32(PLACEMENT_MAGIC)
    capture_done = len(e.code); e.patch_rel32(capture_failed, capture_done)
    e.rip("C7 05", grip_valid, 10); e.emit("00 00 00 00")
    e.emit("8B 54 24 30 48 8B 4C 24 38")
    cross_window_handled = None
    if cross_window_transfer_rva is not None:
        e.rel_call(cross_window_transfer_rva)
        e.emit("85 C0 0F 85 00 00 00 00")
        cross_window_handled = len(e.code) - 4
        e.emit("8B 54 24 30 48 8B 4C 24 38")
    e.emit("48 83 C4 40")
    e.rel_call(0x10D7C0); e.rel_jump(0x185511)
    if cross_window_handled is not None:
        handled = len(e.code)
        e.patch_rel32(cross_window_handled, handled)
        e.rip("C7 05", pending, 10); e.emit("00 00 00 00")
        e.emit("48 83 C4 40")
        e.rel_jump(0x185511)
    ordinary_export = len(e.code)
    e.patch_rel32(no_tear, ordinary_export); e.patch_rel32(no_grip, ordinary_export)
    e.rel_call(0x10D7C0); e.rel_jump(0x185511)

    # Use the pending position for STARTUPINFO after publishing it.
    stubs["worker_placement"] = e.rva
    e.rip("81 3D", pending, 10); e.i32(PLACEMENT_MAGIC)
    e.emit("75 00"); worker_fallback = len(e.code) - 1
    e.emit("83 4D CC 04"); e.rip("8B 05", pending_desired_x, 6); e.emit("89 45 B0")
    e.rip("8B 05", pending_desired_y, 6); e.emit("89 45 B4")
    e.rip("C7 05", pending, 10); e.emit("00 00 00 00 C3")
    fallback = len(e.code); e.patch_rel8(worker_fallback, fallback)
    e.emit("48 83 EC 28 48 8D 4D 30 4C 89 7D 30")
    e.rip("FF 15", 0x217788, 6)
    e.emit("48 83 C4 28 8B 45 30 83 4D CC 04 89 45 B0 8B 45 34 89 45 B4 C3")

    # Publish signed placement beside FilePilot's existing panel clipboard data.
    stubs["clipboard_publish"] = e.rva
    e.rip("81 3D", pending, 10); e.i32(PLACEMENT_MAGIC)
    e.emit("0F 85 00 00 00 00"); no_placement = len(e.code) - 4
    e.emit("48 83 EC 38"); e.rip("48 8D 0D", format_name, 7)
    e.rip("FF 15", 0x2176A0, 6)
    e.emit("85 C0 0F 84 00 00 00 00"); no_format = len(e.code) - 4
    e.emit("89 44 24 20"); e.rip("48 8D 0D", pending, 7)
    e.emit("BA 20 00 00 00 45 31 C0"); e.rel_call(0x1E1400)
    e.emit("48 85 C0 0F 84 00 00 00 00"); no_memory = len(e.code) - 4
    e.emit("48 89 44 24 28 48 89 C2 8B 4C 24 20")
    e.rip("FF 15", 0x2176B0, 6)
    e.emit("48 85 C0 0F 85 00 00 00 00"); success = len(e.code) - 4
    e.emit("48 8B 4C 24 28"); e.rip("FF 15", 0x217288, 6)
    publish_cleanup = len(e.code)
    for branch in (no_format, no_memory, success): e.patch_rel32(branch, publish_cleanup)
    e.emit("48 83 C4 38")
    publish_original = len(e.code); e.patch_rel32(no_placement, publish_original)
    e.emit("0F 57 C0 48 89 B4 24 38 01 00 00 C3")

    # Consume FPT2 into a child-only record before EmptyClipboard.
    stubs["clipboard_consume"] = e.rva
    e.emit("48 83 EC 48 89 F9"); e.rip("FF 15", 0x217690, 6)
    e.emit("85 C0 0F 84 00 00 00 00"); no_panel = len(e.code) - 4
    e.rip("48 8D 0D", format_name, 7); e.rip("FF 15", 0x2176A0, 6)
    e.emit("85 C0 0F 84 00 00 00 00"); consume_no_format = len(e.code) - 4
    e.emit("89 44 24 20 89 C1"); e.rip("FF 15", 0x217690, 6)
    e.emit("85 C0 0F 84 00 00 00 00"); unavailable = len(e.code) - 4
    e.emit("8B 4C 24 20"); e.rip("FF 15", 0x2176A8, 6)
    e.emit("48 85 C0 0F 84 00 00 00 00"); no_handle = len(e.code) - 4
    e.emit("48 89 44 24 28 48 89 C1"); e.rip("FF 15", 0x217280, 6)
    e.emit("48 85 C0 0F 84 00 00 00 00"); no_lock = len(e.code) - 4
    e.emit("81 38"); e.i32(PLACEMENT_MAGIC)
    e.emit("0F 85 00 00 00 00"); bad_magic = len(e.code) - 4
    e.emit("83 78 04 20 0F 85 00 00 00 00"); bad_size = len(e.code) - 4
    for source_offset, target_rva in (
        (8, placement_desired_x), (12, placement_desired_y),
        (16, placement_raw_x), (20, placement_raw_y),
        (24, placement_anchor_x), (28, placement_anchor_y),
    ):
        e.emit(f"8B 50 {source_offset:02X}"); e.rip("89 15", target_rva, 6)
    e.rip("C7 05", placement_size, 10); e.i32(PLACEMENT_SIZE)
    e.rip("C7 05", placement, 10); e.i32(PLACEMENT_MAGIC)
    unlock = len(e.code)
    e.patch_rel32(bad_magic, unlock); e.patch_rel32(bad_size, unlock)
    e.emit("48 8B 4C 24 28"); e.rip("FF 15", 0x217278, 6)
    panel_present = len(e.code)
    for branch in (consume_no_format, unavailable, no_handle, no_lock):
        e.patch_rel32(branch, panel_present)
    e.emit("B8 01 00 00 00")
    consume_done = len(e.code); e.patch_rel32(no_panel, consume_done)
    e.emit("48 83 C4 48 C3")

    # Follow the physical left button and apply signed coordinates only in the child.
    stubs["child_apply"] = e.rva
    e.rip("81 3D", placement, 10); e.i32(PLACEMENT_MAGIC)
    e.emit("0F 85 00 00 00 00"); apply_no_placement = len(e.code) - 4
    e.emit("48 8B 8E B8 08 00 00 48 85 C9 0F 84 00 00 00 00")
    apply_no_window = len(e.code) - 4
    e.emit("48 83 EC 58 48 89 4C 24 48 48 8D 4C 24 38")
    e.rip("FF 15", 0x217788, 6)
    e.emit("85 C0 0F 84 00 00 00 00"); apply_no_cursor = len(e.code) - 4
    e.emit("44 8B 44 24 38"); e.rip("44 2B 05", placement_anchor_x, 7)
    e.emit("44 8B 4C 24 3C"); e.rip("44 2B 0D", placement_anchor_y, 7)
    e.rip("44 89 05", placement_desired_x, 7)
    e.rip("44 89 0D", placement_desired_y, 7)
    e.emit("48 8B 4C 24 48 31 D2 C7 44 24 20 00 00 00 00 C7 44 24 28 00 00 00 00 C7 44 24 30 15 00 00 00")
    e.rip("FF 15", 0x2176E0, 6)
    e.rip("48 8B 05", get_async_key_state_ptr, 7)
    e.emit("48 85 C0 75 00"); have_async = len(e.code) - 1
    e.rip("48 8D 0D", user32_name, 7); e.rip("FF 15", 0x217238, 6)
    e.emit("48 85 C0 74 00"); resolve_failed = len(e.code) - 1
    e.emit("48 89 C1"); e.rip("48 8D 15", get_async_key_state_name, 7)
    e.rip("FF 15", 0x217480, 6); e.rip("48 89 05", get_async_key_state_ptr, 7)
    e.emit("48 85 C0 74 00"); resolve_missing = len(e.code) - 1
    have_async_target = len(e.code); e.patch_rel8(have_async, have_async_target)
    e.emit("B9 01 00 00 00 FF D0 66 A9 00 80 75 00")
    still_dragging = len(e.code) - 1
    released = len(e.code)
    e.patch_rel8(resolve_failed, released); e.patch_rel8(resolve_missing, released)
    e.rip("C7 05", placement, 10); e.emit("00 00 00 00")
    apply_cleanup = len(e.code); e.patch_rel8(still_dragging, apply_cleanup)
    e.patch_rel32(apply_no_cursor, apply_cleanup)
    e.emit("48 83 C4 58")
    apply_original = len(e.code)
    e.patch_rel32(apply_no_placement, apply_original)
    e.patch_rel32(apply_no_window, apply_original)
    e.emit("8B 87 A0 01 00 00 C3")

    # Correct each drag helper's POINT before its native HWND-positioning call.
    stubs["drag_image"] = e.rva
    if cross_window_preview_rva is not None:
        e.emit("48 83 EC 28")
        e.rel_call(cross_window_preview_rva)
        e.emit("48 83 C4 28")
    e.rip("81 3D", grip_valid, 10); e.i32(GRIP_MAGIC)
    e.emit("0F 85 00 00 00 00"); image_no_grip = len(e.code) - 4
    e.emit("48 83 EC 28 48 8D 4D 6F"); e.rip("FF 15", 0x217788, 6)
    e.emit("85 C0 74 00"); image_failed = len(e.code) - 1
    e.rip("8B 05", grip_raw_x, 6); e.emit("29 45 6F")
    e.rip("8B 05", grip_raw_y, 6); e.emit("29 45 73")
    image_cleanup = len(e.code); e.patch_rel8(image_failed, image_cleanup)
    e.emit("48 83 C4 28")
    image_original = len(e.code); e.patch_rel32(image_no_grip, image_original)
    e.emit("48 8B 83 40 09 00 00 C3")

    stubs["drag_text"] = e.rva
    e.rip("81 3D", grip_valid, 10); e.i32(GRIP_MAGIC)
    e.emit("0F 85 00 00 00 00"); text_no_grip = len(e.code) - 4
    e.emit("48 83 EC 28 48 8D 4D 67"); e.rip("FF 15", 0x217788, 6)
    e.emit("85 C0 74 00"); text_failed = len(e.code) - 1
    e.rip("8B 05", grip_raw_x, 6); e.emit("29 45 67")
    e.rip("8B 05", grip_raw_y, 6)
    e.emit("29 45 6B 8B 86 7C 09 00 00 01 45 6B")
    text_cleanup = len(e.code); e.patch_rel8(text_failed, text_cleanup)
    e.emit("48 83 C4 28")
    text_original = len(e.code); e.patch_rel32(text_no_grip, text_original)
    e.emit("4C 89 BE 90 0A 00 00 C3")

    if len(e.code) > 0xE00:
        raise ValueError("tab code overlaps its placement format string")
    e.code.extend(b"\0" * (0xE00 - len(e.code)))
    e.code.extend("FilePilot-TearOffPlacementV2\0".encode("utf-16le"))
    if len(e.code) > 0xE40:
        raise ValueError("tab format string overlaps user32.dll")
    e.code.extend(b"\0" * (0xE40 - len(e.code)))
    e.code.extend("user32.dll\0".encode("utf-16le"))
    if len(e.code) > 0xE60:
        raise ValueError("user32.dll overlaps GetAsyncKeyState")
    e.code.extend(b"\0" * (0xE60 - len(e.code)))
    e.code.extend(b"GetAsyncKeyState\0")
    if len(e.code) > 0x1000:
        raise ValueError("tab code exceeds its section")
    e.code.extend(b"\0" * (0x1000 - len(e.code)))
    return bytes(e.code), stubs


def _write_hook(data: bytearray, sections: list[_Section], rva: int,
                expected: bytes, target_rva: int, jump: bool = False):
    offset = _assert_bytes(data, sections, rva, expected, f"tab hook 0x{rva:x}")
    opcode = b"\xE9" if jump else b"\xE8"
    replacement = opcode + _rel32(rva, 5, target_rva)
    data[offset:offset + len(expected)] = replacement + b"\x90" * (len(expected) - 5)


def apply_tab_patch(data: bytearray, original_sha256: str,
                    cross_window_transfer_rva: int | None = None,
                    cross_window_preview_rva: int | None = None) -> dict:
    """Append and hook the verified tear-off patch into an .fplt-patched image."""
    build = SUPPORTED_SHA256.get(original_sha256.lower())
    if not build:
        raise ValueError(
            "tab tear-off patch has no verified profile for input SHA-256 "
            f"{original_sha256}; use --open-location-only for structurally compatible builds")

    _, coff, optional, table, sections = _pe_layout(data)
    names = [section.name for section in sections]
    if ".fplt" not in names:
        raise ValueError("tab patch requires the Open File Location .fplt payload")
    if ".fpt" in names or ".fpd" in names:
        raise ValueError("target already contains tab tear-off sections")
    section_alignment = _u32(data, optional + 0x20)
    file_alignment = _u32(data, optional + 0x24)
    if section_alignment != 0x1000 or file_alignment != 0x200:
        raise ValueError("unexpected PE alignment for tab patch")

    _apply_first_stage(data, sections)
    # Refresh .text metadata after the first-stage VirtualSize extension.
    _, coff, optional, table, sections = _pe_layout(data)
    mapped_end = max(section.rva + max(section.vsize, section.raw_size)
                     for section in sections)
    code_rva = _align(mapped_end, section_alignment)
    state_rva = code_rva + 0x1000
    code_raw = _align(len(data), file_alignment)
    state_raw = code_raw + 0x1000
    final_size = state_raw + 0x200
    data.extend(b"\0" * (final_size - len(data)))

    header = table + len(sections) * 40
    size_of_headers = _u32(data, optional + 0x3C)
    if header + 80 > size_of_headers:
        raise ValueError("no room for tab section headers")

    def write_section(offset: int, name: bytes, vsize: int, rva: int,
                      raw_size: int, raw: int, characteristics: int):
        data[offset:offset + 40] = b"\0" * 40
        data[offset:offset + len(name)] = name
        struct.pack_into("<IIII", data, offset + 8, vsize, rva, raw_size, raw)
        struct.pack_into("<I", data, offset + 36, characteristics)

    write_section(header, b".fpt", 0x1000, code_rva, 0x1000, code_raw, 0x60000020)
    write_section(header + 40, b".fpd", 0x200, state_rva, 0x200, state_raw, 0xC0000040)
    struct.pack_into("<H", data, coff + 2, len(sections) + 2)
    struct.pack_into("<I", data, optional + 0x38,
                     _align(state_rva + 0x200, section_alignment))
    struct.pack_into("<I", data, optional + 0x40, 0)
    struct.pack_into("<II", data, optional + 0x90, 0, 0)

    code, stubs = _build_code(code_rva, state_rva, cross_window_transfer_rva,
                              cross_window_preview_rva)
    data[code_raw:code_raw + len(code)] = code
    _, _, _, _, patched_sections = _pe_layout(data)
    _write_hook(data, patched_sections, 0x16CFD3,
                bytes.fromhex("49 89 87 A0 0E 00 00"), stubs["activation"])
    _write_hook(data, patched_sections, 0x18550C,
                bytes.fromhex("E8 AF 82 F8 FF"), stubs["export_call"], jump=True)
    _write_hook(data, patched_sections, 0x203C3A,
                bytes.fromhex("48 8D 4D 30 4C 89 7D 30 FF 15 40 3B 01 00 8B 45 30 83 4D CC 04 89 45 B0 8B 45 34 89 45 B4"),
                stubs["worker_placement"])
    _write_hook(data, patched_sections, 0x203BF3,
                bytes.fromhex("0F 57 C0 48 89 B4 24 38 01 00 00"),
                stubs["clipboard_publish"])
    _write_hook(data, patched_sections, 0x1F8C22,
                bytes.fromhex("8B CF FF 15 66 EA 01 00"), stubs["clipboard_consume"])
    _write_hook(data, patched_sections, 0x20518F,
                bytes.fromhex("8B 87 A0 01 00 00"), stubs["child_apply"])
    _write_hook(data, patched_sections, 0x1E822D,
                bytes.fromhex("48 8B 83 40 09 00 00"), stubs["drag_image"])
    _write_hook(data, patched_sections, 0x1E84E3,
                bytes.fromhex("4C 89 BE 90 0A 00 00"), stubs["drag_text"])

    report = {
        "profile": build,
        "code_rva": f"0x{code_rva:x}",
        "state_rva": f"0x{state_rva:x}",
        "stubs": {name: f"0x{rva:x}" for name, rva in stubs.items()},
        "sha256": hashlib.sha256(data).hexdigest(),
    }
    if cross_window_transfer_rva is not None:
        report["cross_window_transfer_rva"] = f"0x{cross_window_transfer_rva:x}"
    if cross_window_preview_rva is not None:
        report["cross_window_preview_rva"] = f"0x{cross_window_preview_rva:x}"
    return report
