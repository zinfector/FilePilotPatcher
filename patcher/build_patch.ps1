param(
    [string]$InputExe = (Join-Path $PSScriptRoot '..\binaries\input\FPilot-original.exe'),
    [string]$OutputExe = (Join-Path $PSScriptRoot '..\binaries\release\FPilot-open-location-tab-merge.exe'),
    [string]$PythonExe,
    [string]$UnicodeReport,
    [switch]$OpenLocationOnly,
    [switch]$All
)

$ErrorActionPreference = 'Stop'
$includeUnicode = $All
if ($All -and $OpenLocationOnly) {
    throw '-All cannot be combined with -OpenLocationOnly'
}
if ($All -and -not $PSBoundParameters.ContainsKey('OutputExe')) {
    $OutputExe = Join-Path $PSScriptRoot '..\binaries\release\FPilot-all-patches.exe'
}
$invocationDirectory = (Get-Location).Path
if (-not [System.IO.Path]::IsPathRooted($InputExe)) {
    $InputExe = Join-Path $invocationDirectory $InputExe
}
if (-not [System.IO.Path]::IsPathRooted($OutputExe)) {
    $OutputExe = Join-Path $invocationDirectory $OutputExe
}
if ($includeUnicode -and -not $UnicodeReport) { $UnicodeReport = $OutputExe + '.unicode.json' }
if ($UnicodeReport -and -not [System.IO.Path]::IsPathRooted($UnicodeReport)) {
    $UnicodeReport = Join-Path $invocationDirectory $UnicodeReport
}
$vswhere = 'C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe'
$vsDev = $null
if (Test-Path -LiteralPath $vswhere) {
    $vsInstall = & $vswhere -latest -products * `
        -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if ($vsInstall) {
        $candidate = Join-Path $vsInstall 'VC\Auxiliary\Build\vcvars64.bat'
        if (Test-Path -LiteralPath $candidate) { $vsDev = $candidate }
    }
}
if (-not $vsDev) {
    $candidate = 'C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat'
    if (Test-Path -LiteralPath $candidate) { $vsDev = $candidate }
}
if (-not $vsDev -or -not (Test-Path -LiteralPath $vsDev)) {
    throw 'A Visual Studio x64 C++ build environment was not found'
}

if (-not $PythonExe) {
    $pythonCandidates = @()
    $pythonCommand = Get-Command python.exe -ErrorAction SilentlyContinue
    if ($pythonCommand -and $pythonCommand.Source -notlike '*\WindowsApps\*') {
        $pythonCandidates += $pythonCommand.Source
    }
    $userProfile = [Environment]::GetFolderPath('UserProfile')
    $pythonCandidates += Join-Path $userProfile `
        '.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe'
    $PythonExe = $pythonCandidates |
        Where-Object { $_ -and (Test-Path -LiteralPath $_) } |
        Select-Object -First 1
}
if (-not $PythonExe -or -not (Test-Path -LiteralPath $PythonExe)) {
    throw 'Python was not found; pass -PythonExe with a Python executable path'
}
$PythonExe = (Resolve-Path -LiteralPath $PythonExe).Path

& $PythonExe -c 'import lief, capstone' 2>$null
if ($LASTEXITCODE -ne 0) {
    throw 'Python packages lief and capstone are required: python -m pip install lief capstone'
}

$compile = 'call "{0}" >nul && cl /nologo /c /O2 /GS- /GR- /EHs-c- /Zl /W4 /DUNICODE /D_UNICODE /Brepro payload.cpp /Fopayload.obj && link /nologo /Brepro /dll /nodefaultlib /entry:DllMain /base:0x140270000 /fixed:no /dynamicbase:no /machine:x64 /out:payload.dll payload.obj' -f $vsDev
$compileUnicode = 'call "{0}" >nul && cl /nologo /c /O2 /GS- /GR- /EHs-c- /Zl /W4 /DUNICODE /D_UNICODE /Brepro unicode_payload.cpp /Founicode_payload.obj && link /nologo /Brepro /dll /nodefaultlib /entry:DllMain /base:0x1402A0000 /fixed:no /dynamicbase:no /machine:x64 /out:unicode_payload.dll unicode_payload.obj' -f $vsDev
Push-Location $PSScriptRoot
try {
    cmd.exe /d /c $compile
    if ($LASTEXITCODE -ne 0) { throw "Payload build failed with exit code $LASTEXITCODE" }
    if ($includeUnicode) {
        cmd.exe /d /c $compileUnicode
        if ($LASTEXITCODE -ne 0) { throw "Unicode payload build failed with exit code $LASTEXITCODE" }
    }

    $patchArguments = @('.\patch_filepilot.py', $InputExe, '.\payload.dll', $OutputExe)
    if ($OpenLocationOnly) { $patchArguments = @('.\patch_filepilot.py', '--open-location-only', $InputExe, '.\payload.dll', $OutputExe) }
    if ($includeUnicode) {
        $patchArguments = @($patchArguments[0], '--all', '--unicode-payload',
            '.\unicode_payload.dll', '--layout-json', $UnicodeReport) +
            $patchArguments[1..($patchArguments.Length - 1)]
    }
    & $PythonExe @patchArguments
    if ($LASTEXITCODE -ne 0) { throw "Patch failed with exit code $LASTEXITCODE" }
}
finally {
    Pop-Location
}
