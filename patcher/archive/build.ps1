param([string]$VsDev)
$ErrorActionPreference='Stop'
$patcher=Split-Path $PSScriptRoot
$vendor=Join-Path $patcher 'vendor\7zip'
if (!(Test-Path "$vendor\CPP\7zip\Archive\IArchive.h")) {
    git clone --depth 1 --branch 26.03 https://github.com/ip7z/7zip.git $vendor
    if ($LASTEXITCODE) { throw '7-Zip source download failed' }
}
$bundle=Join-Path $vendor 'CPP\7zip\Bundles\Format7zF'
Push-Location $bundle
try {
    cmd /d /c "call `"$VsDev`" >nul && nmake /nologo PLATFORM=x64"
    if ($LASTEXITCODE) { throw '7-Zip build failed' }
} finally { Pop-Location }
Push-Location $patcher
try {
    $compile='call "{0}" >nul && rc /nologo /fo archive_licenses.res archive\licenses.rc && cl /nologo /c /std:c++17 /O2 /MT /EHsc /GS- /Zc:threadSafeInit- /DUNICODE /D_UNICODE archive\backend.cpp archive\winfs.cpp archive\shell_transfer.cpp && link /nologo /dll /incremental:no /opt:ref /opt:icf /out:archive_payload.dll backend.obj winfs.obj shell_transfer.obj archive_licenses.res "{1}\x64\*.obj" "{1}\x64\resource.res" kernel32.lib user32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib comdlg32.lib shlwapi.lib uuid.lib' -f $VsDev,$bundle
    cmd /d /c $compile
    if ($LASTEXITCODE) { throw 'Archive runtime build failed' }
    $compile='call "{0}" >nul && cl /nologo /c /O2 /GS- /GR- /EHs-c- /Zl archive\bootstrap.cpp /Foarchive_bootstrap.obj && link /nologo /dll /nodefaultlib /entry:DllMain /fixed:no /out:archive_bootstrap.dll archive_bootstrap.obj' -f $VsDev
    cmd /d /c $compile
    if ($LASTEXITCODE) { throw 'Archive bootstrap build failed' }
} finally { Pop-Location }
