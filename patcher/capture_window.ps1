param([int]$ProcessId, [string]$OutputPath)
Add-Type -AssemblyName System.Drawing
Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class NativeCapture {
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int L,T,R,B; }
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr h, IntPtr dc, uint flags);
}
'@
$p = Get-Process -Id $ProcessId
$h = $p.MainWindowHandle
$r = New-Object NativeCapture+RECT
[NativeCapture]::GetWindowRect($h, [ref]$r) | Out-Null
$bmp = New-Object Drawing.Bitmap ($r.R-$r.L),($r.B-$r.T)
$g = [Drawing.Graphics]::FromImage($bmp)
$dc = $g.GetHdc()
[NativeCapture]::PrintWindow($h, $dc, 2) | Out-Null
$g.ReleaseHdc($dc)
$g.Dispose()
$bmp.Save($OutputPath, [Drawing.Imaging.ImageFormat]::Png)
$bmp.Dispose()
