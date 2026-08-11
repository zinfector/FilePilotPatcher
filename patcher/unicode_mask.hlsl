// Source for unicode_mask_shaders.h. The payload embeds the compiled bytecode so
// patched executables do not acquire a D3DCompiler runtime dependency.
struct VertexInput {
    float2 position : POSITION;
    float2 uv : TEXCOORD0;
    float4 color : COLOR0;
};

struct PixelInput {
    float4 position : SV_POSITION;
    float2 uv : TEXCOORD0;
    float4 color : COLOR0;
};

PixelInput VsMain(VertexInput input) {
    PixelInput output;
    output.position = float4(input.position, 0.0f, 1.0f);
    output.uv = input.uv;
    output.color = input.color;
    return output;
}

Texture2D glyphMask : register(t0);
SamplerState glyphSampler : register(s0);

float4 PsMain(PixelInput input) : SV_TARGET {
    // Match File Pilot's mono-atlas shader: coverage modulates RGBA before
    // the ordinary source-alpha blend stage.
    return input.color * glyphMask.Sample(glyphSampler, input.uv).r;
}
