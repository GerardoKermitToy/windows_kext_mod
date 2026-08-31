use core::ffi::c_void;
use crate::{
    alloc::borrow::ToOwned,
    driver::Driver,
    ffi::{pm_GetDeviceObject, pm_InitDriverObject, WdfIrpPreprocessCallback},
    utils::check_ntstatus,
};
use alloc::ffi::CString;
use alloc::format;
use alloc::string::String;
use widestring::U16CString;
use windows_sys::{
    Wdk::{
        Foundation::DRIVER_OBJECT,
        System::SystemServices::DbgPrint,
    },
    Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE, UNICODE_STRING},
};

// Debug
pub fn dbg_print(str: String) {
    if let Ok(c_str) = CString::new(str) {
        unsafe {
            DbgPrint(c_str.as_ptr() as _);
        }
    }
}

pub fn init_driver_object(
    driver_object: *mut DRIVER_OBJECT,
    registry_path: *mut UNICODE_STRING,
    driver_name: &str,
    wdf_driver_unload: unsafe extern "system" fn(HANDLE),
    create_callback: WdfIrpPreprocessCallback,
    cleanup_callback: WdfIrpPreprocessCallback,
    close_callback: WdfIrpPreprocessCallback,
    read_callback: WdfIrpPreprocessCallback,
    write_callback: WdfIrpPreprocessCallback,
    device_control_callback: WdfIrpPreprocessCallback,
) -> Result<Driver, String> {
    let win_driver_path = format!("\\Device\\{}", driver_name);
    let dos_driver_path = format!("\\??\\{}", driver_name);

    let mut wdf_driver_handle = INVALID_HANDLE_VALUE;
    let mut wdf_device_handle = INVALID_HANDLE_VALUE;

    let Ok(win_driver) = U16CString::from_str(win_driver_path) else {
        return Err("Invalid argument win_driver_path".to_owned());
    };
    let Ok(dos_driver) = U16CString::from_str(dos_driver_path) else {
        return Err("Invalid argument dos_driver_path".to_owned());
    };

    unsafe {
        let status = pm_InitDriverObject(
            driver_object,
            registry_path,
            &mut wdf_driver_handle,
            &mut wdf_device_handle,
            win_driver.as_ptr(),
            dos_driver.as_ptr(),
            wdf_driver_unload,
            create_callback,
            cleanup_callback,
            close_callback,
            read_callback,
            write_callback,
            device_control_callback,
        );

        check_ntstatus(status)?;
        if wdf_driver_handle.is_null()
            || wdf_driver_handle == INVALID_HANDLE_VALUE
            || wdf_device_handle.is_null()
            || wdf_device_handle == INVALID_HANDLE_VALUE
        {
            return Err("KMDF returned an invalid driver or device handle".to_owned());
        }

        return Ok(Driver::new(wdf_driver_handle, wdf_device_handle));
    }
}

pub(crate) fn wdf_device_wdm_get_device_object(wdf_device: HANDLE) -> *mut c_void {
    unsafe {
        return pm_GetDeviceObject(wdf_device);
    }
}
