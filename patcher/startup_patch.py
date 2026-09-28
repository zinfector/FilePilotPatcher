"""File Pilot 0.8.5 startup/resource payload embedding."""
from pathlib import Path
import struct
import lief
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from native_profiles import SHA256_085


def apply(image: bytes, original_digest: str, payload: Path, *, frame_site: int,
          pending_rva: int = 0, unicode_maintenance: int = 0, menu_maintenance: int = 0,
          worker_limit: int = 4, standby_seconds: int = 90):
    if original_digest != SHA256_085:
        raise ValueError("startup optimization currently supports only the original 0.8.5 build")
    binary = lief.PE.parse(list(image))
    dll = lief.PE.parse(str(payload))
    base = binary.optional_header.imagebase
    alignment = binary.optional_header.section_alignment
    start = (max(s.virtual_address + max(s.virtual_size, s.sizeof_raw_data)
                 for s in binary.sections) + alignment - 1) & ~(alignment - 1)
    mapped = bytearray(dll.optional_header.sizeof_image)
    for section in dll.sections:
        mapped[section.virtual_address:section.virtual_address + len(section.content)] = bytes(section.content)
    exports = {e.name: e.address for e in dll.get_export().entries}
    for relocation in dll.relocations:
        for item in relocation.entries:
            kind = int(item.type)
            if kind == 0:
                continue
            if kind != 10:
                raise ValueError(f"unsupported startup relocation {kind}")
            off = relocation.virtual_address + item.position
            value = struct.unpack_from('<Q', mapped, off)[0]
            struct.pack_into('<Q', mapped, off, value - dll.optional_header.imagebase + base + start)

    def offset(rva):
        section = next(s for s in binary.sections if s.virtual_address <= rva <
                       s.virtual_address + s.sizeof_raw_data)
        return section.pointerto_raw_data + rva - section.virtual_address

    previous_frame = frame_site + 5 + struct.unpack_from('<i', image, offset(frame_site) + 1)[0]
    imports = {e.name: binary.optional_header.imagebase + e.iat_address
               for library in binary.imports for e in library.entries if e.name}
    exception = dll.data_directories[3]
    values = (0x3154524154535046, 1, 22 * 8,
              imports['LoadLibraryW'], imports['GetProcAddress'], imports['GetCommandLineW'],
              base + binary.optional_header.addressof_entrypoint, base + 0x17B7C0,
              base + 0x1FABA0, base + 0x10F460,
              base + previous_frame, base + 0x249240, base + pending_rva if pending_rva else 0,
              unicode_maintenance, menu_maintenance, worker_limit, standby_seconds, 1,
              base + start + exception.rva, exception.size // 12, base + start, imports['ShowWindow'])
    struct.pack_into('<22Q', mapped, exports['StartupSettings'], *values)
    section = lief.PE.Section('.fps')
    section.virtual_address = start
    section.content = list(mapped)
    section.characteristics = 0xE0000060
    binary.add_section(section)
    binary.optional_header.addressof_entrypoint = start + exports['StartupEntry']
    # Existing payloads also use absolute bindings and require their fixed base.
    binary.optional_header.dll_characteristics &= ~0x40
    builder = lief.PE.Builder(binary, lief.PE.Builder.config_t())
    builder.build()
    output = bytearray(builder.raw_bytes())

    def patch_call(rva, destination, expected=None, indirect=False):
        off = offset(rva)
        old = bytes(output[off:off + (6 if indirect else 5)])
        if indirect:
            if old[:2] != b'\xff\x15':
                raise ValueError(f"self-launch seam changed at {rva:x}")
        elif old[0] != 0xe8 or (expected is not None and
                rva + 5 + struct.unpack_from('<i', old, 1)[0] != expected):
            raise ValueError(f"startup call seam changed at {rva:x}")
        output[off:off + len(old)] = b'\xe8' + struct.pack('<i', destination - rva - 5) + (b'\x90' if indirect else b'')

    addr = lambda name: start + exports[name]
    patch_call(0x1E05B6, addr('StartupWorkers'), 0x79B50)
    patch_call(0x1E11CD, addr('StartupClipboard'), 0x1FABA0)
    patch_call(0x1E1310, addr('StartupConfig'), 0x17B7C0)
    patch_call(0x1E1520, addr('StartupCreateWindow'), indirect=True)
    patch_call(0x488DB, addr('StartupD3D'), 0x2181B4)
    patch_call(0x4892A, addr('StartupD3D'), 0x2181B4)
    # FUN_14004A640 has already resolved the texture, shader constants and
    # sampler. Replace only its Map/copy/Unmap/DrawInstanced tail. Keep its
    # prologue, texture lifetime management, draw counter and epilogue intact.
    # At this boundary EBP=count, RSI=vertices; the native stack already has
    # aligned shadow space for the replacement four-argument call.
    upload_begin, upload_end = 0x4A826, 0x4A8C5
    original_upload = bytes.fromhex(
        '488b15a3ec1f004c8d4424404c894424280f57c00f11442440bb00200000'
        'c744242000000000488b4a483beb488b527041b9040000000f42dd4533c0'
        '488b01ff5070488b4c24404c8d04db49c1e003483bce740d4d85c07408'
        '488bd6e8299f1c00488b1542ec1f004533c0488b4a48488b5270488b01'
        'ff5078488b052aec1f004533c9448bc3c744242000000000488b4848'
        '418d5104488b01ff90a8000000')
    off = offset(upload_begin)
    if bytes(output[off:offset(upload_end)]) != original_upload:
        raise ValueError('native renderer upload seam changed')
    upload = bytearray(b'\x48\x8b\x05' + struct.pack('<i', 0x2494D0 - upload_begin - 7))
    upload += bytes.fromhex('48 8b 48 48 48 8b 50 70 44 8b c5 4c 8b ce')
    upload += b'\xe8' + struct.pack('<i', addr('StartupUpload') - (upload_begin + len(upload) + 5))
    upload += b'\xe9' + struct.pack('<i', upload_end - (upload_begin + len(upload) + 5))
    output[off:offset(upload_end)] = upload + b'\x90' * (upload_end - upload_begin - len(upload))
    patch_call(frame_site, addr('StartupFrame'), previous_frame)
    for site in (0x2054B0, 0x205AD1):
        patch_call(site, addr('StartupCreateProcess'), indirect=True)
    # Include the tab patch's emitted trampolines, which now own the export calls.
    queue_calls = []
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    for section in binary.sections:
        if section.name not in ('.text', '.fpt'):
            continue
        raw = bytes(output[section.pointerto_raw_data:section.pointerto_raw_data + section.sizeof_raw_data])
        for insn in decoder.disasm(raw, section.virtual_address):
            if insn.mnemonic == 'call' and insn.op_str == '0x10f460':
                queue_calls.append(insn.address)
    # .text contains embedded tables. Restrict native scanning to the known
    # serializer function as well, rather than relying on linear disassembly.
    raw = bytes(output[offset(0x187540):offset(0x187540) + 738])
    for insn in decoder.disasm(raw, 0x187540):
        if insn.mnemonic == 'call' and insn.op_str == '0x10f460':
            queue_calls.append(insn.address)
    for site in sorted(set(queue_calls)):
        patch_call(site, addr('StartupQueue'), 0x10F460)
    if not queue_calls:
        raise ValueError('no serialized-window dispatch sites remain')
    off = offset(0x1E538C)
    if output[off:off + 6] != bytes.fromhex('41 be 00 00 00 01'):
        raise ValueError('job arena commit policy seam changed')
    output[off:off + 6] = bytes.fromhex('41 be 00 00 10 00')
    return output, {
        'worker_limit': worker_limit, 'job_arena_commit_increment': 1024 * 1024,
        'standby_limit': 1, 'standby_seconds': standby_seconds,
        'standby_stage': 'preloaded D3D11 device and shared DirectWrite font collection, before native entry',
        'renderer_upload': {
            'strategy': 'append using WRITE_NO_OVERWRITE; WRITE_DISCARD only on buffer wrap',
            'buffer_bytes': 589824, 'instance_stride': 72, 'instance_capacity': 8192,
            'native_upload_rva': hex(upload_begin),
            'counters_rva': hex(addr('RenderUploadCounters')),
        },
        'serialized_window_hooks': [hex(rva) for rva in sorted(set(queue_calls))],
        'environment': ['FPILOT_WARM=0|1', 'FPILOT_WORKERS=2..64', 'FPILOT_STANDBY_SECONDS=5..600'],
        'payload_rva': hex(start),
    }
