"""File Pilot 0.8.5 startup/resource payload embedding."""
from pathlib import Path
import struct
import lief
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from native_profiles import SHA256_085


def apply(image: bytes, original_digest: str, payload: Path, *, frame_site: int,
          pending_rva: int = 0, unicode_maintenance: int = 0, menu_maintenance: int = 0,
          worker_limit: int = 4, standby_seconds: int = 30):
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
    values = (0x3154524154535046, 1, 23 * 8,
              imports['LoadLibraryW'], imports['GetProcAddress'], imports['GetCommandLineW'],
              base + binary.optional_header.addressof_entrypoint, base + 0x17B7C0,
              base + 0x1FABA0, base + 0x10F460,
              base + previous_frame, base + 0x249240, base + pending_rva if pending_rva else 0,
              unicode_maintenance, menu_maintenance, worker_limit, standby_seconds, 1,
              base + start + exception.rva, exception.size // 12, base + start, imports['ShowWindow'],
              base + 0x1EF5C0)
    struct.pack_into('<23Q', mapped, exports['StartupSettings'], *values)
    section = lief.PE.Section('.fps')
    section.virtual_address = start
    section.content = list(mapped)
    section.characteristics = 0xE0000060
    binary.add_section(section)
    binary.optional_header.addressof_entrypoint = start + exports['StartupEntry']
    # Existing payloads also use absolute bindings and require their fixed base.
    binary.optional_header.dll_characteristics &= ~0x40
    # Keep the full stack reservation and Windows guard-page growth.
    binary.optional_header.sizeof_stack_commit = 128 * 1024
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
    patch_call(0x1ECA54, addr('StartupWatchZero'), 0x2147E0)
    for site in (0x1ECC90, 0x1ECF78):
        patch_call(site, addr('StartupWatchRead'), indirect=True)
    for site in (0x1ECEFC, 0x1ED7D4, 0x1EDA1B, 0x1EE44A, 0x1EE574, 0x1EE5A6, 0x1EE6AC):
        patch_call(site, addr('StartupWatchQueue'), 0x1EF5C0)
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
    output[off:off + 6] = bytes.fromhex('41 be 00 00 01 00')
    # These are commit quanta, not reservation sizes or array capacities.
    # Preserve the allocator's growth/rounding logic and native object layout.
    pool_sites = (
        (0x61A5A, '41bf00001000', 2),         # directory state arena
        (0x61D3E, '48c7871002000000001000', 7), # directory strings arena
        (0x63851, '48c70700001000', 3),      # alternate directory state constructor
        (0x17B8CB, '48c70100001000', 3),     # first application frame arena
        (0x17B8D7, '48c7878000000000001000', 7), # second application frame arena
    )
    for site, expected, immediate in pool_sites:
        raw = bytes.fromhex(expected)
        off = offset(site)
        if output[off:off + len(raw)] != raw:
            raise ValueError(f'native arena commit seam changed at {site:x}')
        struct.pack_into('<I', output, off + immediate, 64 * 1024)
    return output, {
        'worker_limit': worker_limit, 'job_arena_commit_increment': 64 * 1024,
        'stack_initial_commit': 128 * 1024,
        'stack_reservation': binary.optional_header.sizeof_stack_reserve,
        'native_pool_commit_increment': 64 * 1024,
        'native_pool_sites': [hex(site) for site, _, _ in pool_sites],
        'filesystem_queue': '16 MiB capacity; interior pages decommitted before first read, committed before publishing records; retained until watcher destruction',
        'standby_default': 'disabled; opt in with FPILOT_WARM=1',
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
