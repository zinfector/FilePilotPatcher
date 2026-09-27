"""Embed archive support in the executable; no runtime sidecar files."""
from pathlib import Path
import struct
import lief
from archive_profiles import PROFILES

def apply(image: bytes, original_digest: str, engine: Path, bootstrap: Path):
    profile = PROFILES[original_digest]
    binary = lief.PE.parse(list(image))
    boot = lief.PE.parse(str(bootstrap))
    alignment = binary.optional_header.section_alignment
    align = lambda n: (n + alignment - 1) & ~(alignment - 1)
    start = align(max(s.virtual_address + max(s.virtual_size, s.sizeof_raw_data) for s in binary.sections))
    data = bytearray(boot.optional_header.sizeof_image)
    for s in boot.sections:
        data[s.virtual_address:s.virtual_address + len(s.content)] = bytes(s.content)
    exports = {e.name: e.address for e in boot.get_export().entries}
    for relocation in boot.relocations:
        for entry in relocation.entries:
            if int(entry.type) == 10:
                off = relocation.virtual_address + entry.position
                value = struct.unpack_from('<Q', data, off)[0]
                struct.pack_into('<Q', data, off, value - boot.optional_header.imagebase + binary.optional_header.imagebase + start)
    def offset(rva):
        s = next(s for s in binary.sections if s.virtual_address <= rva < s.virtual_address + max(s.virtual_size,s.sizeof_raw_data))
        return s.pointerto_raw_data + rva - s.virtual_address
    call = profile['startup_call_rva']
    previous = call + 5 + struct.unpack_from('<i', image, offset(call)+1)[0]
    imports = {e.name: i.import_address_table_rva + n*8 for i in binary.imports for n,e in enumerate(i.entries)}
    engine_rva = align(start + len(data))
    fields = ('nt_query_pointer_rva', 'open_selection_rva', 'describe_item_rva',
              'open_prologue_bytes', 'panel_model_offset', 'panel_selection_mode_offset',
              'panel_cursor_offset', 'panel_selection_count_offset', 'panel_selection_array_offset',
              'selection_stride', 'item_flags_offset', 'descriptor_path_offset', 'descriptor_length_offset',
              'clipboard_rva', 'clipboard_prologue_bytes', 'clipboard_list_offset',
              'drag_rva', 'drag_prologue_bytes', 'drag_owner_offset', 'drag_active_offset')
    values = (engine_rva, previous, imports['LoadLibraryW'], imports['GetProcAddress'],
              *(profile[name] for name in fields))
    struct.pack_into('<' + 'I' * len(values), data, exports['ArchiveBindings'], *values)
    for name, rva, content, flags in [('.fpab',start,data,0xE0000060),('.fpa',engine_rva,engine.read_bytes(),0x40000040)]:
        s=lief.PE.Section(name);s.virtual_address=rva;s.content=list(content);s.characteristics=flags;binary.add_section(s)
    binary.patch_address(call,[0xE8]+list(struct.pack('<i',start+exports['ArchiveStart']-call-5)))
    binary.optional_header.checksum=0
    binary.data_directories[4].rva=0;binary.data_directories[4].size=0
    # The existing patcher emits a fixed-base executable. Preserve its relocation policy.
    config=lief.PE.Builder.config_t();builder=lief.PE.Builder(binary,config);builder.build()
    return bytes(builder.raw_bytes()), {'profile':profile['name'],'engine_rva':hex(engine_rva),
        'startup_rva':hex(start+exports['ArchiveStart']),'storage':'memory-only',
        'extraction_shortcut':'Ctrl+Shift+E','engine':'7-Zip 26.03',
        'native_open_rva':hex(profile['open_selection_rva']),
        'native_clipboard_rva':hex(profile['clipboard_rva']),
        'native_drag_rva':hex(profile['drag_rva']),
        'external_launch':'read-only managed cache; Ctrl+Shift+K opens cache',
        'shell_transfer':'FILEGROUPDESCRIPTORW and indexed IStream; copy only'}
