"""Only File Pilot-specific seams belong here; the filesystem adapter is version independent."""
PROFILES = {
    "ab5e7bbfa50872225f24856697ef7341a58e51a5e521435ba0dfeeb8ab3b2676": {
        "name": "File Pilot 0.8.5 x64",
        "startup_call_rva": 0x1E15FB,
        "nt_query_pointer_rva": 0x249220,
        "open_selection_rva": 0x5E090,
        "describe_item_rva": 0x67400,
        # Complete position-independent instructions through push rdi.
        "open_prologue_bytes": 15,
        "panel_model_offset": 0x90,
        "panel_selection_mode_offset": 0x120,
        "panel_cursor_offset": 0x128,
        "panel_selection_count_offset": 0x178,
        "panel_selection_array_offset": 0x1B0,
        "selection_stride": 0x10,
        "item_flags_offset": 0x20,
        "descriptor_path_offset": 0x10,
        "descriptor_length_offset": 0x18,
        "clipboard_rva": 0x113700,
        "clipboard_prologue_bytes": 16,
        "clipboard_list_offset": 0x18,
        "drag_rva": 0x1F0530,
        "drag_prologue_bytes": 14,
        "drag_owner_offset": 0x50,
        "drag_active_offset": 0x58,
    },
}
