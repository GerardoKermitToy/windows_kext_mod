# Kernel-only windows-link adapter

`windows-sys` 0.61.2 uses `windows-link` 0.2.1 to declare Windows APIs. The
upstream macro synthesizes raw-DLL imports on Windows. Some exported names are
shared by user-mode DLLs and WDK kernel libraries, so those imports can silently
bind a kernel driver to `ntdll.dll`, `fwpuclnt.dll`, or `iphlpapi.dll` even when
the project declares a kernel-specific FFI signature itself.

This patch preserves the macro's declaration syntax but leaves each symbol
unresolved for the final driver link against the WDK import libraries. It is
scoped to the `driver` and standalone `wdk` Cargo roots. It must not be used for
user-mode programs, and must be reviewed together with `windows-sys` and
`windows-link` upgrades. Both SYS-linking scripts reject user-mode DLL imports.
The kernel's byte-sized `BOOLEAN` values must also not be assumed to be valid
Rust `bool` values; see `wdk/src/ffi.rs` and `driver/src/address_monitor.rs`.
