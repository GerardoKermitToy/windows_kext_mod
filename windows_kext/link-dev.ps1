# Example script for creating debug builds. Libraries may change depending on the version of the WDK that is installed.

Remove-Item -Path "portmaster-kext.sys"  -ErrorAction SilentlyContinue
$SDK_Version = "10.0.28000.0"

link.exe /OUT:portmaster-kext.sys `
/MANIFEST:NO /PROFILE /Driver `
"C:\Program Files (x86)\Windows Kits\10\lib\$SDK_Version\km\x64\wdmsec.lib" `
"C:\Program Files (x86)\Windows Kits\10\lib\$SDK_Version\km\x64\ndis.lib" `
"C:\Program Files (x86)\Windows Kits\10\lib\$SDK_Version\km\x64\fwpkclnt.lib" `
"C:\Program Files (x86)\Windows Kits\10\lib\$SDK_Version\km\x64\BufferOverflowK.lib" `
"C:\Program Files (x86)\Windows Kits\10\lib\$SDK_Version\km\x64\ntoskrnl.lib" `
"C:\Program Files (x86)\Windows Kits\10\lib\$SDK_Version\km\x64\hal.lib" `
"C:\Program Files (x86)\Windows Kits\10\lib\$SDK_Version\km\x64\wmilib.lib" `
"C:\Program Files (x86)\Windows Kits\10\lib\wdf\kmdf\x64\1.15\WdfLdr.lib" `
"C:\Program Files (x86)\Windows Kits\10\lib\wdf\kmdf\x64\1.15\WdfDriverEntry.lib" `
"driver\target\x86_64-pc-windows-msvc\release\driver.lib" `
/RELEASE /INTEGRITYCHECK /VERSION:"10.0" /DEBUG /MACHINE:X64 /ENTRY:"FxDriverEntry" /OPT:REF /INCREMENTAL:NO /SUBSYSTEM:NATIVE",6.01" /OPT:ICF /ERRORREPORT:PROMPT /MERGE:"_TEXT=.text;_PAGE=PAGE" /NOLOGO /NODEFAULTLIB /SECTION:"INIT,d"

signtool sign /v /s My /n "MyCompany Code Signing" /tr http://timestamp.digicert.com /td SHA256 /fd SHA256 portmaster-kext.sys


if(!$?) {
    Exit $LASTEXITCODE
}
