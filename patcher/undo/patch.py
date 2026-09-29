"""Embed undo runtime and bootstrap in File Pilot 0.8.5."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import lief

EXPECTED = 'ab5e7bbfa50872225f24856697ef7341a58e51a5e521435ba0dfeeb8ab3b2676'


def apply(image, bootstrap, runtime=None, *, original_digest=None):
    if (original_digest or hashlib.sha256(image).hexdigest()) != EXPECTED:
        raise ValueError('Only the original verified File Pilot 0.8.5 executable is supported')
    pe = lief.PE.parse(list(image))
    dll = lief.PE.parse(str(bootstrap))
    runtime = runtime or Path(bootstrap).with_name('FPilot.Undo.dll')
    engine = lief.PE.parse(str(runtime))
    if engine.data_directories[9].size:
        raise ValueError('Embedded undo runtime must use explicit Windows TLS')
    if any(s.name in ('.fpundo', '.fpuh') for s in pe.sections):
        raise ValueError('Undo payload already embedded')
    if any(list(lib.entries) for lib in dll.imports):
        raise ValueError('Bootstrap must have no imports')
    alignment = pe.optional_header.section_alignment
    start = (max(s.virtual_address + max(s.virtual_size, s.sizeof_raw_data)
                 for s in pe.sections) + alignment - 1) & ~(alignment - 1)
    mapped = bytearray(dll.optional_header.sizeof_image)
    for s in dll.sections:
        mapped[s.virtual_address:s.virtual_address + len(s.content)] = bytes(s.content)
    exports = {e.name:e.address for e in dll.get_export().entries}
    for block in dll.relocations:
        for entry in block.entries:
            if int(entry.type) == 0:
                continue
            if int(entry.type) != 10:
                raise ValueError('Unsupported bootstrap relocation')
            offset = block.virtual_address + entry.position
            value, = struct.unpack_from('<Q', mapped, offset)
            struct.pack_into('<Q', mapped, offset, value - dll.optional_header.imagebase + pe.optional_header.imagebase + start)
    imports = {e.name:e.iat_address for lib in pe.imports for e in lib.entries if e.name}
    original_entry = pe.optional_header.addressof_entrypoint
    engine_rva = (start + len(mapped) + alignment - 1) & ~(alignment - 1)
    struct.pack_into('<4I', mapped, exports['UndoBindings'], engine_rva, original_entry,
                     imports['LoadLibraryW'], imports['GetProcAddress'])
    section = lief.PE.Section('.fpundo')
    section.virtual_address = start
    section.content = list(mapped)
    section.characteristics = 0xE0000060
    pe.add_section(section)
    engine_section = lief.PE.Section('.fpuh')
    engine_section.virtual_address = engine_rva
    engine_section.content = list(runtime.read_bytes())
    engine_section.characteristics = 0x40000040
    pe.add_section(engine_section)
    pe.optional_header.addressof_entrypoint = start + exports['UndoEntry']
    pe.optional_header.dll_characteristics &= ~0x40
    pe.optional_header.checksum = 0
    pe.data_directories[4].rva = pe.data_directories[4].size = 0
    # Bootstrap registers engine unwind data, resolves imports and invokes its CRT entry.
    builder = lief.PE.Builder(pe, lief.PE.Builder.config_t())
    builder.build()
    return bytes(builder.raw_bytes()), {'original_entry_rva':hex(original_entry),
        'entry_rva':hex(pe.optional_header.addressof_entrypoint), 'runtime':'embedded; memory-only',
        'engine_rva':hex(engine_rva),
        'runtime_sha256':hashlib.sha256(runtime.read_bytes()).hexdigest(),
        'history':'100 process-session batches; move and recyclable delete',
        'status':'experimental; desktop keybinding and recycle recovery verification incomplete',
        'keys':{'undo':'Ctrl+Z','redo':['Ctrl+Y','Ctrl+Shift+Z']}}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input',type=Path)
    parser.add_argument('output',type=Path)
    args = parser.parse_args()
    if args.input.resolve() == args.output.resolve():
        parser.error('Output must be a separate executable')
    here = Path(__file__).resolve().parent
    image, report = apply(args.input.read_bytes(),here/'bootstrap.dll')
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_bytes(image)
    report['sha256'] = hashlib.sha256(image).hexdigest()
    report['runtime_sha256'] = hashlib.sha256((here/'FPilot.Undo.dll').read_bytes()).hexdigest()
    args.output.with_suffix('.undo.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(f'Wrote {args.output}')
