@echo off
REM Builds and signs portmaster-kext.sys.
REM
REM dojob.ps1 calls link.exe and signtool directly, so both must be on PATH -
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
cargo build --release
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

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0link-dev.ps1"
exit /b %ERRORLEVEL%
