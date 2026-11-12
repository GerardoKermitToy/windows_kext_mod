//! Kernel-only replacement for windows-link 0.2.1.
//!
//! `windows-sys` uses this macro to declare FFI functions. Its upstream
//! implementation synthesizes raw-dylib imports, including user-mode DLLs
//! that export names also provided by the WDK's kernel import libraries.
//! Leave symbols unresolved here so the final driver link resolves them from
//! the WDK libraries instead. Do not use this crate for user-mode binaries.

#![no_std]

#[macro_export]
macro_rules! link {
    ($library:literal $abi:literal $($link_name:literal)? fn $($function:tt)*) => {
        extern $abi {
            $(#[link_name = $link_name])?
            pub fn $($function)*;
        }
    };
}
