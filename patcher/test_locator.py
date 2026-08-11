import hashlib
import json
import struct
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
BINARIES = HERE.parent / "binaries"
INPUT_BINARIES = BINARIES / "input"
REGRESSION_BINARIES = BINARIES / "regression"
RELEASE_BINARIES = BINARIES / "release"
sys.path.insert(0, str(HERE))

import patch_filepilot as patcher
import tab_relative


class MaskedPatternTests(unittest.TestCase):
    def test_signature_survives_address_and_offset_changes(self):
        specification, anchor = patcher.FRAME_SIGNATURE
        values, mask = patcher.parse_masked_pattern(specification)
        concrete = bytearray(values)
        wildcard_values = iter(range(1, 256))
        for index, fixed in enumerate(mask):
            if not fixed:
                concrete[index] = next(wildcard_values)
        blob = b"shifted-prefix" * 17 + bytes(concrete) + b"shifted-suffix"
        self.assertEqual(patcher.find_masked(blob, specification), [len(b"shifted-prefix" * 17)])
        self.assertEqual(concrete[anchor], 0xE8)

    def test_fixed_instruction_change_is_rejected(self):
        specification, _ = patcher.FRAME_SIGNATURE
        values, mask = patcher.parse_masked_pattern(specification)
        concrete = bytearray(values)
        fixed_index = next(index for index, fixed in enumerate(mask) if fixed)
        concrete[fixed_index] ^= 0xFF
        self.assertEqual(patcher.find_masked(bytes(concrete), specification), [])


class OriginalBinaryRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = INPUT_BINARIES / "FPilot-original.exe"
        if not cls.original.exists():
            raise unittest.SkipTest("FPilot-original.exe is not present")
        cls.layout = patcher.discover_layout(patcher.TargetImage(cls.original))

    def test_known_regions_are_rediscovered(self):
        self.assertEqual(self.layout.startup_site, 0x1401DEED2)
        self.assertEqual(self.layout.frame_site, 0x14019F465)
        self.assertEqual(self.layout.live_wrapper, 0x14005D610)
        self.assertEqual(self.layout.selector, 0x14004AC90)
        self.assertEqual(self.layout.selection_commit, 0x1401BB250)
        self.assertEqual(len(self.layout.live_call_sites), 8)

    def test_miller_regions_are_rediscovered(self):
        self.assertEqual(self.layout.item_interaction, 0x140116080)
        self.assertEqual(self.layout.item_interaction_call_sites, [
            0x14012923A, 0x14012A1B4, 0x14012BC89,
            0x14012FFCC, 0x140131514, 0x1401325CB,
        ])
        self.assertEqual(self.layout.begin_open_site, 0x140116FF5)
        self.assertEqual(self.layout.begin_open_call_sites, [
            0x140116F80, 0x140116FF5,
        ])
        self.assertEqual(self.layout.begin_queued_command, 0x14015D7D0)
        self.assertEqual(self.layout.open_selected_items, 0x14005DC00)
        self.assertEqual(self.layout.open_selected_navigate_call_sites, [
            0x14005EE16, 0x14005F328,
        ])
        self.assertEqual(self.layout.close_all_tabs, 0x1400871F0)
        self.assertEqual(self.layout.item_metadata, 0x1400668A0)
        self.assertEqual(self.layout.inspector_sync, 0x14008AC20)
        self.assertEqual(self.layout.navigate_panel, 0x14014E850)

    def test_structure_offsets_are_derived(self):
        self.assertEqual(self.layout.selection_state_display_offset, 0x98)
        self.assertEqual(self.layout.display_mode_offset, 0x10)
        self.assertEqual(self.layout.display_primary_offset, 0x20)
        self.assertEqual(self.layout.display_alternate_offset, 0xC8)
        self.assertEqual(self.layout.display_count_offset, 0x68)
        self.assertEqual(self.layout.panel_inspector_offset, 0x6D8)
        self.assertEqual(self.layout.panel_backing_offset, 0x90)
        self.assertEqual(self.layout.panel_view_offset, 0x98)
        self.assertEqual(self.layout.child_owner_offset, 0xC8)
        self.assertEqual(self.layout.child_flag_offset, 0x502)
        self.assertEqual(self.layout.inspector_layout_offset, 0x48)
        self.assertEqual(self.layout.inspector_mode_offset, 0x13D0)
        self.assertEqual(self.layout.inspector_current_item_offset, 0x13E8)
        self.assertEqual(self.layout.inspector_backing_offset, 0x13F0)
        self.assertEqual(self.layout.inspector_child_offset, 0x1480)
        self.assertEqual(self.layout.view_settings_offset, 0x16C)
        self.assertEqual(self.layout.item_flags_offset, 0x20)
        self.assertEqual(self.layout.metadata_path_offset, 0x10)
        self.assertEqual(self.layout.metadata_flags_offset, 0x30)
        self.assertEqual(self.layout.app_active_panel_offset, 0xB30)

    def test_binding_table_is_complete(self):
        values = self.layout.binding_values()
        self.assertEqual(len(values), patcher.BINDINGS_QWORDS)
        self.assertNotIn(0, values[3:])
        self.assertEqual(values[-3], 0x140246F80)
        self.assertEqual(values[-2], 0x140247278)
        self.assertEqual(values[-1], 0x1401D7860)

    def test_native_tab_surface_marker_calls_are_exact(self):
        target = patcher.TargetImage(self.original)
        for call_rva in patcher.TAB_SURFACE_CALL_RVAS:
            call = target.read(target.image_base + call_rva, 5)
            self.assertEqual(call[0], 0xE8)
            destination = target.image_base + call_rva + 5 + struct.unpack_from(
                "<i", call, 1)[0]
            self.assertEqual(destination,
                             target.image_base + patcher.TAB_SURFACE_RENDERER_RVA)

        for call_rva in patcher.TAB_HOVER_CALL_RVAS:
            call = target.read(target.image_base + call_rva, 5)
            self.assertEqual(call[0], 0xE8)
            destination = target.image_base + call_rva + 5 + struct.unpack_from(
                "<i", call, 1)[0]
            self.assertEqual(destination,
                             target.image_base + patcher.TAB_HOVER_HELPER_RVA)


class TabPatchRegressionTests(unittest.TestCase):
    ORIGINAL_SHA256 = "08826147a90e7c6a1c4e80968aaa927b14cfbca7271c7d12db3af9f24c483646"
    COMBINED_SHA256 = "c4661ee3affbef3eb5ae175959d3b3393fa86b8b59f88860f4848bddb0b16572"

    @classmethod
    def setUpClass(cls):
        cls.open_location = REGRESSION_BINARIES / "FPilot-patched.exe"
        cls.combined = REGRESSION_BINARIES / "FPilot-open-location-tab-relative.exe"
        if not cls.open_location.exists() or not cls.combined.exists():
            raise unittest.SkipTest("runtime-tested patch artifacts are not present")

    def test_python_emitter_recreates_runtime_tested_combined_build(self):
        image = bytearray(self.open_location.read_bytes())
        report = tab_relative.apply_tab_patch(image, self.ORIGINAL_SHA256)
        self.assertEqual(hashlib.sha256(image).hexdigest(), self.COMBINED_SHA256)
        self.assertEqual(report["code_rva"], "0x28d000")
        self.assertEqual(report["state_rva"], "0x28e000")

    def test_cross_window_bridge_is_opt_in_and_reported(self):
        image = bytearray(self.open_location.read_bytes())
        bridge_rva = 0x27B5B0
        preview_rva = 0x27B690
        report = tab_relative.apply_tab_patch(
            image, self.ORIGINAL_SHA256, cross_window_transfer_rva=bridge_rva,
            cross_window_preview_rva=preview_rva)
        self.assertEqual(report["cross_window_transfer_rva"], "0x27b5b0")
        self.assertEqual(report["cross_window_preview_rva"], "0x27b690")
        self.assertNotEqual(hashlib.sha256(image).hexdigest(), self.COMBINED_SHA256)
        _, _, _, _, sections = tab_relative._pe_layout(image)
        start_rva = int(report["stubs"]["export_call"], 16)
        end_rva = int(report["stubs"]["worker_placement"], 16)
        start = tab_relative._rva_to_file(sections, start_rva)
        bridge_calls = []
        for index in range(end_rva - start_rva - 4):
            if image[start + index] != 0xE8:
                continue
            displacement = struct.unpack_from("<i", image, start + index + 1)[0]
            bridge_calls.append(start_rva + index + 5 + displacement)
        self.assertIn(bridge_rva, bridge_calls)

        drag_rva = int(report["stubs"]["drag_image"], 16)
        drag_end_rva = int(report["stubs"]["drag_text"], 16)
        drag = tab_relative._rva_to_file(sections, drag_rva)
        preview_calls = []
        for index in range(drag_end_rva - drag_rva - 4):
            if image[drag + index] != 0xE8:
                continue
            displacement = struct.unpack_from("<i", image, drag + index + 1)[0]
            preview_calls.append(drag_rva + index + 5 + displacement)
        self.assertIn(preview_rva, preview_calls)

    def test_unknown_tab_profile_fails_closed(self):
        image = bytearray(self.open_location.read_bytes())
        with self.assertRaisesRegex(ValueError, "no verified profile"):
            tab_relative.apply_tab_patch(image, "0" * 64)


class SeparatedCombinedBuildTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original_path = INPUT_BINARIES / "FPilot-original.exe"
        cls.combined_path = RELEASE_BINARIES / "FPilot-open-location-tab-merge.exe"
        cls.report_path = HERE / "layout-open-location-tab-merge.json"
        if not cls.original_path.exists() or not cls.combined_path.exists():
            raise unittest.SkipTest("separated combined artifact is not present")
        cls.original = patcher.TargetImage(cls.original_path)
        cls.combined_data = cls.combined_path.read_bytes()
        _, _, _, _, cls.combined_sections = patcher.pe_layout(cls.combined_data)
        cls.layout = patcher.discover_layout(cls.original)

    def test_every_miller_call_site_remains_native(self):
        sites = patcher.miller_call_sites(self.layout)
        self.assertEqual(len(sites), 52)
        for site in sites:
            offset = patcher.rva_to_file(
                self.combined_sections, site - self.original.image_base)
            self.assertEqual(self.combined_data[offset:offset + 5], self.original.read(site, 5),
                             f"Miller call changed at 0x{site:x}")

    def test_report_names_only_the_requested_features(self):
        report = json.loads(self.report_path.read_text(encoding="utf-8"))
        self.assertEqual(report["patches"], {
            "open_file_location": True,
            "tab_window_creation": True,
            "cross_window_tab_merge": True,
            "miller_navigation": False,
        })
        self.assertEqual(report["miller_separation_guard"]["modified_call_sites"], 0)


if __name__ == "__main__":
    unittest.main()
