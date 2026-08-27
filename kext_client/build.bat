@echo off
setlocal
set VCVARS=C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvars64.bat
call "%VCVARS%" >nul 2>&1
cd /d "%~dp0"
if not exist build mkdir build
cd build
cmake -G Ninja -DCMAKE_BUILD_TYPE=Release .. 2>&1 || cmake .. 2>&1
cmake --build . --config Release 2>&1
