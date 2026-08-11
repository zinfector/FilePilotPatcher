param(
    [string]$Exe = (Join-Path $PSScriptRoot '..\binaries\release\FPilot-all-patches.exe'),
    [string]$Folder = (Join-Path $PSScriptRoot '..\..\work\unicode-runtime-test'),
    [string]$OutputCsv = (Join-Path $PSScriptRoot '..\..\work\unicode-native-ab.csv'),
    [ValidateSet('row-texture', 'shaped-glyph', 'custom-command')]
    [string[]]$Mode = @('row-texture', 'shaped-glyph', 'custom-command'),
    [ValidateSet('legacy', 'native-probe')]
    [string[]]$TransformMode = @('legacy', 'native-probe'),
    [int]$SampleMilliseconds = 2500,
    [string]$ScreenshotDirectory
)

$ErrorActionPreference = 'Stop'
$Exe = (Resolve-Path -LiteralPath $Exe).Path
if (-not (Test-Path -LiteralPath $Folder -PathType Container)) {
    throw "Benchmark folder does not exist: $Folder. Pass -Folder with an existing multilingual folder."
}
$Folder = (Resolve-Path -LiteralPath $Folder).Path
$manifestPath = $Exe + '.unicode.json'
if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
    throw "Unicode manifest does not exist: $manifestPath. Rebuild with build_patch.ps1 -All."
}
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
$telemetryRva = [Convert]::ToInt64($manifest.unicode.telemetry_rva.Substring(2), 16)
$outputParent = Split-Path -Parent $OutputCsv
if ($outputParent -and -not (Test-Path -LiteralPath $outputParent)) {
    New-Item -ItemType Directory -Path $outputParent | Out-Null
}
if ($ScreenshotDirectory -and -not (Test-Path -LiteralPath $ScreenshotDirectory)) {
    New-Item -ItemType Directory -Path $ScreenshotDirectory | Out-Null
}

Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class UnicodeNativeMemory {
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr OpenProcess(uint access, bool inherit, int processId);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool ReadProcessMemory(
        IntPtr process, IntPtr address, byte[] buffer, UIntPtr size, out UIntPtr read);
    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr handle);
}
'@

function Get-U64([byte[]]$Bytes, [int]$Offset) {
    [BitConverter]::ToUInt64($Bytes, $Offset)
}

function Read-UnicodeState([Diagnostics.Process]$Process) {
    $Process.Refresh()
    $address = [IntPtr]($Process.MainModule.BaseAddress.ToInt64() + $telemetryRva)
    $handle = [UnicodeNativeMemory]::OpenProcess(0x10, $false, $Process.Id)
    if ($handle -eq [IntPtr]::Zero) { throw "OpenProcess failed for PID $($Process.Id)" }
    try {
        $bytes = New-Object byte[] 352
        $read = [UIntPtr]::Zero
        $ok = [UnicodeNativeMemory]::ReadProcessMemory(
            $handle, $address, $bytes, [UIntPtr]::new([uint64]$bytes.Length), [ref]$read)
        if (-not $ok -or $read.ToUInt64() -ne $bytes.Length) {
            throw "ReadProcessMemory failed for PID $($Process.Id)"
        }
    }
    finally {
        [UnicodeNativeMemory]::CloseHandle($handle) | Out-Null
    }
    [pscustomobject]@{
        Version = [BitConverter]::ToUInt32($bytes, 0)
        Flags = [BitConverter]::ToUInt32($bytes, 4)
        MeasureCalls = Get-U64 $bytes 8
        RenderCalls = Get-U64 $bytes 16
        PacketsQueued = Get-U64 $bytes 24
        PacketsDrawn = Get-U64 $bytes 32
        BackendFallbacks = Get-U64 $bytes 48
        ShapeMicroseconds = Get-U64 $bytes 80
        DrawMicroseconds = Get-U64 $bytes 88
        FrameCalls = Get-U64 $bytes 104
        RowBuilds = Get-U64 $bytes 152
        RowCacheHits = Get-U64 $bytes 160
        AtlasFailures = Get-U64 $bytes 176
        PacketReuses = Get-U64 $bytes 208
        SelectedMode = [BitConverter]::ToUInt32($bytes, 224)
        MarkersSubmitted = Get-U64 $bytes 232
        MarkersDrawn = Get-U64 $bytes 240
        PacketsNotDispatched = Get-U64 $bytes 248
        NativeBatchSplits = Get-U64 $bytes 256
        CustomCommands = Get-U64 $bytes 264
        CustomCommandFallbacks = Get-U64 $bytes 272
        GlyphBuilds = Get-U64 $bytes 280
        GlyphCacheHits = Get-U64 $bytes 288
        GlyphDrawCalls = Get-U64 $bytes 296
        SelectedTransformMode = [BitConverter]::ToUInt32($bytes, 304)
        TransformCaptures = Get-U64 $bytes 312
        TransformFailures = Get-U64 $bytes 320
        AnimatedDraws = Get-U64 $bytes 328
        ProbeMarkers = Get-U64 $bytes 336
        TransformMaxResidual = [BitConverter]::ToSingle($bytes, 344)
    }
}

$rows = foreach ($currentTransformMode in $TransformMode) {
foreach ($currentMode in $Mode) {
    Get-Process -ErrorAction SilentlyContinue |
        Where-Object { $_.Path -eq $Exe } |
        ForEach-Object { $_.Kill(); $_.WaitForExit(10000) | Out-Null }

    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $Exe
    $startInfo.UseShellExecute = $false
    $startInfo.EnvironmentVariables['FPILOT_UNICODE_NATIVE_MODE'] = $currentMode
    $startInfo.EnvironmentVariables['FPILOT_UNICODE_TRANSFORM_MODE'] = $currentTransformMode
    $startInfo.Arguments = '"' + $Folder.Replace('"', '\"') + '"'
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $process = [Diagnostics.Process]::Start($startInfo)
    $inputIdle = $null
    $firstFrame = $null
    $firstUnicode = $null
    try {
        if ($process.WaitForInputIdle(10000)) { $inputIdle = $timer.Elapsed.TotalMilliseconds }
        $deadline = [DateTime]::UtcNow.AddSeconds(10)
        do {
            if ($process.HasExited) {
                throw "File Pilot exited in mode $currentMode with code $($process.ExitCode)"
            }
            try {
                $state = Read-UnicodeState $process
                if ($null -eq $firstFrame -and $state.FrameCalls -gt 0) {
                    $firstFrame = $timer.Elapsed.TotalMilliseconds
                }
                if ($null -eq $firstUnicode -and $state.MarkersDrawn -gt 0) {
                    $firstUnicode = $timer.Elapsed.TotalMilliseconds
                }
            }
            catch {
                $state = $null
            }
            if ($null -ne $firstFrame -and $null -ne $firstUnicode) { break }
            Start-Sleep -Milliseconds 10
        } while ([DateTime]::UtcNow -lt $deadline)
        if ($SampleMilliseconds -gt $timer.ElapsedMilliseconds) {
            Start-Sleep -Milliseconds ($SampleMilliseconds - $timer.ElapsedMilliseconds)
        }
        $state = Read-UnicodeState $process
        $process.Refresh()
        if ($ScreenshotDirectory) {
            $capture = Join-Path $PSScriptRoot 'capture_window.ps1'
            $image = Join-Path $ScreenshotDirectory (
                $currentMode + '-' + $currentTransformMode + '.png')
            & $capture -ProcessId $process.Id -OutputPath $image
        }
        [pscustomobject]@{
            TimestampUtc = [DateTime]::UtcNow.ToString('o')
            Mode = $currentMode
            ModeId = $state.SelectedMode
            TransformMode = $currentTransformMode
            TransformModeId = $state.SelectedTransformMode
            InputIdleMs = [Math]::Round($inputIdle, 3)
            FirstFrameMs = [Math]::Round($firstFrame, 3)
            FirstUnicodeMs = [Math]::Round($firstUnicode, 3)
            WorkingSetMiB = [Math]::Round($process.WorkingSet64 / 1MB, 2)
            CpuMs = [Math]::Round($process.TotalProcessorTime.TotalMilliseconds, 2)
            Frames = $state.FrameCalls
            RenderCalls = $state.RenderCalls
            PacketsQueued = $state.PacketsQueued
            PacketReuses = $state.PacketReuses
            MarkersSubmitted = $state.MarkersSubmitted
            MarkersDrawn = $state.MarkersDrawn
            PacketsNotDispatched = $state.PacketsNotDispatched
            NativeBatchSplits = $state.NativeBatchSplits
            RowBuilds = $state.RowBuilds
            RowCacheHits = $state.RowCacheHits
            GlyphBuilds = $state.GlyphBuilds
            GlyphCacheHits = $state.GlyphCacheHits
            GlyphDrawCalls = $state.GlyphDrawCalls
            CustomCommands = $state.CustomCommands
            CustomCommandFallbacks = $state.CustomCommandFallbacks
            TransformCaptures = $state.TransformCaptures
            TransformFailures = $state.TransformFailures
            AnimatedDraws = $state.AnimatedDraws
            ProbeMarkers = $state.ProbeMarkers
            TransformMaxResidual = $state.TransformMaxResidual
            BackendFallbacks = $state.BackendFallbacks
            AtlasFailures = $state.AtlasFailures
            ShapeMicroseconds = $state.ShapeMicroseconds
            DrawMicroseconds = $state.DrawMicroseconds
            Flags = ('0x{0:x}' -f $state.Flags)
        }
    }
    finally {
        if ($process -and -not $process.HasExited) {
            $process.Kill()
            $process.WaitForExit(10000) | Out-Null
        }
    }
}
}

$rows | Export-Csv -LiteralPath $OutputCsv -NoTypeInformation
$rows | Format-Table -AutoSize
Write-Output "Wrote $OutputCsv"
