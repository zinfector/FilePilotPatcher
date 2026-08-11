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


class UnicodeRendererSourceTests(unittest.TestCase):
    def test_combined_profile_has_stable_name(self):
        self.assertEqual(patcher.build_profile_name(True, True), "all")

    def test_d3d_atlas_uses_premultiplied_native_blending(self):
        shader = (HERE / "unicode_mask.hlsl").read_text(encoding="utf-8")
        payload = (HERE / "unicode_payload.cpp").read_text(encoding="utf-8")
        self.assertIn("return input.color * glyphMask.Sample", shader)
        self.assertIn(
            "blend.RenderTarget[0].SrcBlend = D3D11_BLEND_ONE;", payload)
        self.assertIn(
            "blend.RenderTarget[0].DestBlend = D3D11_BLEND_INV_SRC_ALPHA;",
            payload)

    def test_native_inline_packets_preserve_command_instances(self):
        payload = (HERE / "unicode_payload.cpp").read_text(encoding="utf-8")
        self.assertIn("7, ExperimentInitialized", payload)
        self.assertIn("static bool EnqueueInlinePacket", payload)
        self.assertIn("UnicodeD3DDrawBatchHook", payload)
        self.assertNotIn("queued.color[component] = candidate.color[component];", payload)

    def test_native_transform_probe_preserves_animation_geometry(self):
        payload = (HERE / "unicode_payload.cpp").read_text(encoding="utf-8")
        self.assertIn("FPILOT_UNICODE_TRANSFORM_MODE", payload)
        self.assertIn("NativeTransformProbe = 2", payload)
        self.assertIn("UnicodeNativeQuadHook", payload)
        self.assertIn("kNativeTransformProbeBasis = 4096", payload)
        self.assertIn("ApplyPacketTransform", payload)
        self.assertIn("CoalesceCapturedPacket", payload)
        self.assertIn("NativeMarkerProbe", payload)

    def test_native_renderer_ab_modes_are_explicit(self):
        payload = (HERE / "unicode_payload.cpp").read_text(encoding="utf-8")
        self.assertNotIn("FPILOT_UNICODE_RENDERER", payload)
        self.assertIn("FPILOT_UNICODE_NATIVE_MODE", payload)
        self.assertIn("NativeRendererRowTexture = 1", payload)
        self.assertIn("NativeRendererShapedGlyphs = 2", payload)
        self.assertIn("NativeRendererCustomCommand = 4", payload)
        self.assertIn("DrawD3DShapedGlyphsInline", payload)
        self.assertIn("SubmitCustomNativeCommand", payload)
        self.assertIn("InlineScissor", payload)
        self.assertNotIn("DrawOverlayQueue", payload)


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
        self.assertEqual(len(self.layout.live_call_sites), 8)

    def test_structure_offsets_are_derived(self):
        self.assertEqual(self.layout.selection_state_display_offset, 0x98)
        self.assertEqual(self.layout.display_mode_offset, 0x10)
        self.assertEqual(self.layout.display_primary_offset, 0x20)
        self.assertEqual(self.layout.display_alternate_offset, 0xC8)
        self.assertEqual(self.layout.display_count_offset, 0x68)
        self.assertEqual(self.layout.app_active_panel_offset, 0xB30)
        self.assertEqual(self.layout.find_imgui_window, 0x1401CAC10)

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


class UnicodePatchRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original_path = INPUT_BINARIES / "FPilot-original.exe"
        if not cls.original_path.exists():
            raise unittest.SkipTest("FPilot-original.exe is not present")
        cls.original = patcher.TargetImage(cls.original_path)
        cls.layout = patcher.discover_unicode_layout(cls.original)

    def test_unicode_hook_seams_are_complete(self):
        self.assertEqual(self.layout.glyph_lookup, 0x14010AA50)
        self.assertEqual(len(self.layout.glyph_lookup_call_sites), 5)
        self.assertEqual(self.layout.measure_text, 0x1401B78F0)
        self.assertEqual(len(self.layout.measure_text_call_sites), 38)
        self.assertEqual(self.layout.render_text_call_sites, (0x1401D50B3,))
        self.assertEqual(len(self.layout.font_create_atlas_call_sites), 3)
        self.assertEqual(self.layout.font_rasterizer, 0x140215C70)
        self.assertEqual(self.layout.input_conversion_call_site, 0x14020B59A)
        self.assertEqual(self.layout.d3d_create_device_call_sites,
                         (0x14004892B, 0x14004897A))
        self.assertEqual(self.layout.d3d_render_frame, 0x140049350)
        self.assertEqual(self.layout.d3d_render_frame_call_site, 0x1401EDB49)
        self.assertEqual(self.layout.d3d_renderer_global, 0x1402474D8)
        self.assertEqual(self.layout.native_quad_emitter, 0x1401B9B50)
        self.assertEqual(self.layout.native_quad_call_site, 0x1401B8F9C)
        self.assertEqual(self.layout.native_command_allocator, 0x1401B99C0)
        self.assertEqual(self.layout.d3d_draw_batch, 0x14004A690)
        self.assertEqual(self.layout.d3d_draw_batch_call_sites,
                         (0x140049B30, 0x140049C37))
        self.assertEqual(self.layout.native_render_data_global, 0x140247298)

    def test_unicode_ranges_cover_requested_scripts_and_preserve_icons(self):
        self.assertEqual(len(patcher.UNICODE_INITIAL_RANGES), 17)
        for codepoint in (0x0627, 0x4E2D, 0x6587, 0xAC00, 0xD55C):
            self.assertTrue(any(low <= codepoint <= high
                                for low, high in patcher.UNICODE_INITIAL_RANGES))
        self.assertEqual(patcher.UNICODE_INITIAL_RANGES[13:],
                         patcher.UNICODE_ORIGINAL_RANGES[13:])

    def test_emitted_unicode_build_has_validated_hooks(self):
        output_path = RELEASE_BINARIES / "FPilot-all-patches.exe"
        if not output_path.exists():
            raise unittest.SkipTest("combined Unicode release has not been built")
        output = output_path.read_bytes()
        _, _, _, _, sections = patcher.pe_layout(output)
        unicode_section = next((section for section in sections if section.name == ".fpu"), None)
        self.assertIsNotNone(unicode_section)
        expected_ranges = b"".join(struct.pack("<II", low, high)
                                   for low, high in patcher.UNICODE_INITIAL_RANGES)
        table_offset = patcher.rva_to_file(
            sections, self.layout.range_table - self.original.image_base)
        self.assertEqual(output[table_offset:table_offset + len(expected_ranges)], expected_ranges)
        for rva, original in patcher.UNICODE_CARET_CLAMPS.items():
            offset = patcher.rva_to_file(sections, rva)
            self.assertEqual(output[offset:offset + len(original)], b"\x90" * len(original))
        for site in (*self.layout.glyph_lookup_call_sites,
                     *self.layout.measure_text_call_sites,
                     *self.layout.render_text_call_sites,
                     *self.layout.font_create_atlas_call_sites,
                     *self.layout.d3d_create_device_call_sites,
                     *self.layout.d3d_draw_batch_call_sites,
                     self.layout.input_conversion_call_site,
                     self.layout.d3d_render_frame_call_site,
                     self.layout.native_quad_call_site):
            offset = patcher.rva_to_file(sections, site - self.original.image_base)
            self.assertEqual(output[offset], 0xE8)
            destination = site + 5 + struct.unpack_from("<i", output, offset + 1)[0]
            self.assertTrue(
                self.original.image_base + unicode_section.rva <= destination <
                self.original.image_base + unicode_section.rva + unicode_section.vsize,
                f"Unicode hook at 0x{site:x} targets 0x{destination:x}")

    def test_emitted_unicode_manifest_describes_native_ab_renderers(self):
        output_path = RELEASE_BINARIES / "FPilot-all-patches.exe"
        manifest_path = Path(str(output_path) + ".unicode.json")
        if not manifest_path.exists():
            raise unittest.SkipTest("combined Unicode manifest has not been built")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(manifest["unicode"]["renderer"], "native-inline-d3d-atlas")
        self.assertEqual(manifest["unicode"]["renderer_selection"], "environment")
        self.assertEqual(manifest["unicode"]["renderer_selector"],
                         "FPILOT_UNICODE_NATIVE_MODE")
        self.assertEqual(manifest["unicode"]["renderer_modes"], {
            "row-texture": 1,
            "shaped-glyph": 2,
            "custom-command": 4,
        })
        self.assertEqual(manifest["unicode"]["transform_selector"],
                         "FPILOT_UNICODE_TRANSFORM_MODE")
        self.assertEqual(manifest["unicode"]["transform_default"], "native-probe")
        self.assertEqual(manifest["unicode"]["transform_modes"], {
            "legacy": 1,
            "native-probe": 2,
        })

    def test_all_release_manifest_has_every_requested_patch(self):
        output_path = RELEASE_BINARIES / "FPilot-all-patches.exe"
        manifest_path = Path(str(output_path) + ".unicode.json")
        if not output_path.exists() or not manifest_path.exists():
            raise unittest.SkipTest("combined release has not been built")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(manifest["build_profile"], "all")
        self.assertEqual(manifest["patches"], {
            "open_file_location": True,
            "tab_window_creation": True,
            "cross_window_tab_merge": True,
            "unicode_text": True,
        })
        output = output_path.read_bytes()
        _, _, _, _, sections = patcher.pe_layout(output)
        self.assertTrue({".fplt", ".fpu", ".fpt", ".fpd"}.issubset(
            {section.name for section in sections}))


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

    def test_report_names_only_the_requested_features(self):
        report = json.loads(self.report_path.read_text(encoding="utf-8"))
        self.assertEqual(report["patches"], {
            "open_file_location": True,
            "tab_window_creation": True,
            "cross_window_tab_merge": True,
        })


if __name__ == "__main__":
    unittest.main()
