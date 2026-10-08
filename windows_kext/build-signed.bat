@echo off
REM Builds and signs portmaster-kext.sys.
REM
REM rc.exe, link.exe and signtool must be on PATH -
REM that is what vcvarsall.bat sets up. Running the script outside that
REM environment fails with "cannot find path".
setlocal

set VCVARS=C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvarsall.bat
if not exist "%VCVARS%" (
    echo Could not find vcvarsall.bat at "%VCVARS%"
    exit /b 1
)

cd /d "%~dp0"

echo === cargo build --release ===
pushd driver
cargo build --release %*
if errorlevel 1 (
    popd
    exit /b 1
)
popd

echo === link + sign ===
call "%VCVARS%" x64 >nul
if errorlevel 1 (
    echo vcvarsall failed
    exit /b 1
)

REM Render a private resource; leave the release template unchanged.
set "VERSION_RC=%~dp0driver\target\x86_64-pc-windows-msvc\release\portmaster-kext-version.rc"
set "VERSION_RES=%~dp0driver\target\x86_64-pc-windows-msvc\release\portmaster-kext-version.res"

echo === version resource ===
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "$ErrorActionPreference = 'Stop';" ^
    "$version = Get-Content -LiteralPath '%~dp0kextinterface\version.txt' -Raw | ConvertFrom-Json;" ^
    "if ($version -isnot [array] -or $version.Count -ne 4) { throw 'Driver version must contain four byte-sized integers.' };" ^
    "foreach ($part in $version) { if ($part -isnot [int] -or $part -lt 0 -or $part -gt 255) { throw 'Driver version must contain four byte-sized integers.' } };" ^
    "$metadata = Get-Content -LiteralPath '%~dp0release\templates\version.rc' -Raw;" ^
    "$metadata = $metadata.Replace('{{version}}', ($version -join ', ')).Replace('{{version_str}}', ($version -join '.'));" ^
    "$metadata = $metadata.Replace('Portmaster Windows Kernel Extension Driver', 'WFP Callout Driver').Replace('PortmasterKext64.sys', 'portmaster-kext.sys');" ^
    "Set-Content -LiteralPath '%VERSION_RC%' -Value $metadata -Encoding ASCII"
if errorlevel 1 exit /b 1

rc.exe /nologo /fo "%VERSION_RES%" "%VERSION_RC%"
if errorlevel 1 exit /b 1

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0link-dev.ps1" -VersionResource "%VERSION_RES%"
exit /b %ERRORLEVEL%
