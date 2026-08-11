param(
    [Parameter(Mandatory)] [string]$Executable,
    [Parameter(Mandatory)] [string]$BeforeImage,
    [Parameter(Mandatory)] [string]$HoldImage,
    [Parameter(Mandatory)] [UInt64]$DebugAddress
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing
Add-Type @'
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class CrossDragNative {
    [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left, Top, Right, Bottom; }
    [StructLayout(LayoutKind.Sequential)] public struct POINT { public int X, Y; }
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr hwnd, out RECT rect);
    [DllImport("user32.dll")] public static extern bool MoveWindow(IntPtr hwnd, int x, int y, int w, int h, bool repaint);
    [DllImport("user32.dll")] public static extern bool SetWindowPos(IntPtr hwnd, IntPtr after, int x, int y, int w, int h, uint flags);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hwnd);
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hwnd, int command);
    [DllImport("user32.dll")] public static extern bool SetCursorPos(int x, int y);
    [DllImport("user32.dll")] public static extern bool GetCursorPos(out POINT point);
    [DllImport("user32.dll")] public static extern IntPtr WindowFromPoint(POINT point);
    [DllImport("user32.dll")] public static extern IntPtr GetAncestor(IntPtr hwnd, uint flags);
    [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr hwnd, out uint pid);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr hwnd, StringBuilder text, int count);
    [DllImport("user32.dll")] public static extern void mouse_event(uint flags, uint dx, uint dy, uint data, UIntPtr extra);
    [DllImport("kernel32.dll", SetLastError=true)] private static extern bool ReadProcessMemory(IntPtr process, IntPtr address, byte[] buffer, int size, out IntPtr read);
    public static ulong[] ReadDebug(IntPtr process, ulong address) {
        var bytes = new byte[17 * 8]; IntPtr read;
        if (!ReadProcessMemory(process, new IntPtr(unchecked((long)address)), bytes, bytes.Length, out read) || read.ToInt64() != bytes.Length)
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        var values = new ulong[17];
        for (int i = 0; i < values.Length; ++i) values[i] = BitConverter.ToUInt64(bytes, i * 8);
        return values;
    }
}
'@

function Wait-MainWindow([Diagnostics.Process]$Process) {
    $deadline = (Get-Date).AddSeconds(20)
    do { Start-Sleep -Milliseconds 100; $Process.Refresh() }
    while ($Process.MainWindowHandle -eq 0 -and -not $Process.HasExited -and (Get-Date) -lt $deadline)
    if ($Process.HasExited -or $Process.MainWindowHandle -eq 0) { throw "No main window for PID $($Process.Id)" }
}

function Save-Window([Diagnostics.Process]$Process, [string]$Path) {
    $rect = New-Object CrossDragNative+RECT
    [CrossDragNative]::GetWindowRect($Process.MainWindowHandle, [ref]$rect) | Out-Null
    $bitmap = New-Object Drawing.Bitmap ($rect.Right - $rect.Left), ($rect.Bottom - $rect.Top)
    $graphics = [Drawing.Graphics]::FromImage($bitmap)
    try {
        $graphics.CopyFromScreen($rect.Left, $rect.Top, 0, 0, $bitmap.Size)
        $bitmap.Save($Path, [Drawing.Imaging.ImageFormat]::Png)
    } finally { $graphics.Dispose(); $bitmap.Dispose() }
}

$resolved = (Resolve-Path -LiteralPath $Executable).Path
$existing = @(Get-Process -ErrorAction SilentlyContinue | Where-Object Path -eq $resolved | ForEach-Object Id)
$target = Start-Process -FilePath $resolved -PassThru
$source = $null
$released = $true
try {
    Wait-MainWindow $target
    $source = Start-Process -FilePath $resolved -PassThru
    Wait-MainWindow $source
    [CrossDragNative]::ShowWindow($target.MainWindowHandle, 9) | Out-Null
    [CrossDragNative]::ShowWindow($source.MainWindowHandle, 9) | Out-Null
    [CrossDragNative]::MoveWindow($target.MainWindowHandle, 40, 80, 900, 620, $true) | Out-Null
    [CrossDragNative]::MoveWindow($source.MainWindowHandle, 1040, 80, 900, 620, $true) | Out-Null
    [CrossDragNative]::SetWindowPos($target.MainWindowHandle, [IntPtr](-1), 40, 80, 900, 620, 0) | Out-Null
    [CrossDragNative]::SetWindowPos($source.MainWindowHandle, [IntPtr](-1), 1040, 80, 900, 620, 0) | Out-Null
    Start-Sleep -Milliseconds 700

    $targetRect = New-Object CrossDragNative+RECT
    $sourceRect = New-Object CrossDragNative+RECT
    [CrossDragNative]::GetWindowRect($target.MainWindowHandle, [ref]$targetRect) | Out-Null
    [CrossDragNative]::GetWindowRect($source.MainWindowHandle, [ref]$sourceRect) | Out-Null
    "TARGET_PID=$($target.Id) SOURCE_PID=$($source.Id) TARGET_RECT=$($targetRect.Left),$($targetRect.Top),$($targetRect.Right),$($targetRect.Bottom) SOURCE_RECT=$($sourceRect.Left),$($sourceRect.Top),$($sourceRect.Right),$($sourceRect.Bottom)"

    # Expose multiple draggable tabs in the source window.
    [CrossDragNative]::SetForegroundWindow($source.MainWindowHandle) | Out-Null
    for ($index = 0; $index -lt 2; ++$index) {
        [CrossDragNative]::SetCursorPos(1447, 99) | Out-Null
        [CrossDragNative]::mouse_event(2, 0, 0, 0, [UIntPtr]::Zero)
        [CrossDragNative]::mouse_event(4, 0, 0, 0, [UIntPtr]::Zero)
        Start-Sleep -Milliseconds 300
    }
    Start-Sleep -Milliseconds 700
    Save-Window $target $BeforeImage

    $startX = 1340; $startY = 99
    $holdX = 250; $holdY = 99
    [CrossDragNative]::SetCursorPos($startX, $startY) | Out-Null
    [CrossDragNative]::mouse_event(2, 0, 0, 0, [UIntPtr]::Zero)
    [CrossDragNative]::mouse_event(4, 0, 0, 0, [UIntPtr]::Zero)
    Start-Sleep -Milliseconds 20
    [CrossDragNative]::mouse_event(2, 0, 0, 0, [UIntPtr]::Zero)
    $released = $false
    for ($step = 1; $step -le 32; ++$step) {
        $x = [int]($startX + (($holdX - $startX) * $step / 32.0))
        [CrossDragNative]::SetCursorPos($x, $holdY) | Out-Null
        Start-Sleep -Milliseconds 20
    }
    Start-Sleep -Milliseconds 120
    $actual = New-Object CrossDragNative+POINT
    [CrossDragNative]::GetCursorPos([ref]$actual) | Out-Null
    $direct = [CrossDragNative]::GetAncestor([CrossDragNative]::WindowFromPoint($actual), 2)
    $directPid = 0
    [CrossDragNative]::GetWindowThreadProcessId($direct, [ref]$directPid) | Out-Null
    $directClass = New-Object Text.StringBuilder 128
    [CrossDragNative]::GetClassNameW($direct, $directClass, $directClass.Capacity) | Out-Null
    "CURSOR=$($actual.X),$($actual.Y) DIRECT=0x$($direct.ToInt64().ToString('x')) PID=$directPid CLASS=$directClass"
    Save-Window $target $HoldImage
    $target.Refresh(); $source.Refresh()
    "HOLD_TARGET_ALIVE=$(-not $target.HasExited) HOLD_SOURCE_ALIVE=$(-not $source.HasExited)"
    if (-not $target.HasExited) { "TARGET_DEBUG=$([string]::Join(',', [CrossDragNative]::ReadDebug($target.Handle, $DebugAddress)))" }
    if (-not $source.HasExited) { "SOURCE_DEBUG=$([string]::Join(',', [CrossDragNative]::ReadDebug($source.Handle, $DebugAddress)))" }
    [CrossDragNative]::mouse_event(4, 0, 0, 0, [UIntPtr]::Zero)
    $released = $true
    Start-Sleep -Milliseconds 800
    $target.Refresh(); $source.Refresh()
    "TARGET_ALIVE=$(-not $target.HasExited) SOURCE_ALIVE=$(-not $source.HasExited)"
    if (-not $target.HasExited) {
        $afterImage = Join-Path ([IO.Path]::GetDirectoryName($HoldImage)) `
            (([IO.Path]::GetFileNameWithoutExtension($HoldImage)) + '-after.png')
        Save-Window $target $afterImage
        "TARGET_AFTER_DEBUG=$([string]::Join(',', [CrossDragNative]::ReadDebug($target.Handle, $DebugAddress)))"
        "AFTER_IMAGE=$afterImage"
    }
} finally {
    if (-not $released) { [CrossDragNative]::mouse_event(4, 0, 0, 0, [UIntPtr]::Zero) }
    Get-Process -ErrorAction SilentlyContinue |
        Where-Object { $_.Id -notin $existing -and $_.Path -eq $resolved } |
        Stop-Process -Force -ErrorAction SilentlyContinue
}
