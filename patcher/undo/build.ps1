param(
    [string]$InputExe = (Join-Path $PSScriptRoot '..\..\ghidra\project\FPilot.exe'),
    [string]$OutputExe = (Join-Path $PSScriptRoot '..\..\binaries\release\undo-0.8.5\FPilot.Undo.exe'),
    [switch]$PayloadOnly
)
$ErrorActionPreference = 'Stop'
$vswhere = 'C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe'
$vsInstall = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
$vsDev = Join-Path $vsInstall 'VC\Auxiliary\Build\vcvars64.bat'
if (-not (Test-Path -LiteralPath $vsDev)) { throw 'Visual Studio x64 tools required' }
$compile = 'call "{0}" >nul && cl /nologo /std:c++17 /O2 /EHsc /MD /W4 /LD history.cpp /link /out:FPilot.Undo.dll ole32.lib shell32.lib user32.lib uuid.lib advapi32.lib && cl /nologo /O2 /GS- /GR- /EHs-c- /Zl /c bootstrap.cpp /Fobootstrap.obj && link /nologo /dll /nodefaultlib /entry:DllMain /base:0x140300000 /fixed:no /dynamicbase:no /out:bootstrap.dll bootstrap.obj' -f $vsDev
Push-Location $PSScriptRoot
try {
    cmd.exe /d /c $compile
    if ($LASTEXITCODE -ne 0) { throw 'Undo payload build failed' }
    if (-not $PayloadOnly) {
        python .\patch.py $InputExe $OutputExe
        if ($LASTEXITCODE -ne 0) { throw 'Undo executable build failed' }
    }
} finally { Pop-Location }
