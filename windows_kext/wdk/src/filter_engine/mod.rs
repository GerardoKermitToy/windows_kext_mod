use core::ffi::c_void;

use crate::alloc::borrow::ToOwned;
use crate::driver::Driver;
use crate::ffi::FWPS_FILTER2;
use crate::filter_engine::transaction::Transaction;
use crate::{dbg, info};
use alloc::boxed::Box;
use alloc::string::String;
use alloc::{format, vec::Vec};
use windows_sys::Wdk::Foundation::DEVICE_OBJECT;
use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};

use self::callout::{Callout, FilterType};
use self::callout_data::CalloutData;
use self::classify::ClassifyOut;
use self::layer::IncomingValues;
use self::metadata::FwpsIncomingMetadataValues;

pub mod callout;
pub mod callout_data;
pub(crate) mod classify;
#[allow(dead_code)]
pub mod ffi;
pub mod flow;
pub mod layer;
pub(crate) mod metadata;
pub mod net_buffer;
pub mod packet;
pub mod stream_data;
pub mod transaction;
// Helper functions for ALE Readirect layers. Not needed for the current implementation.
// pub mod connect_request;

pub struct FilterEngine {
    device_object: *mut DEVICE_OBJECT,
    handle: HANDLE,
    sublayer_guid: u128,
    committed: bool,
    callouts: Option<Vec<Box<Callout>>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnregisterCalloutsResult {
    /// All runtime callouts are gone and the dynamic FWPM session is closed.
    Complete,
    /// At least one callout still owns a WFP flow context.
    Busy,
}

impl FilterEngine {
    pub fn new(driver: &Driver, layer_guid: u128) -> Result<Self, String> {
        let filter_engine_handle: HANDLE;
        match ffi::create_filter_engine() {
            Ok(handle) => {
                filter_engine_handle = handle;
            }
            Err(code) => {
                return Err(format!("failed to initialize filter engine {}", code).to_owned());
            }
        }
        Ok(Self {
            device_object: driver.get_device_object(),
            handle: filter_engine_handle,
            sublayer_guid: layer_guid,
            committed: false,
            callouts: None,
        })
    }

    pub fn commit(&mut self, callouts: Vec<Callout>) -> Result<(), String> {
        if self.committed || self.callouts.is_some() {
            return Err("filter engine is already initialized".to_owned());
        }
        if self.handle.is_null() || self.handle == INVALID_HANDLE_VALUE {
            return Err("filter engine session is closed".to_owned());
        }

        // Runtime FWPS registrations are outside the FWPM transaction. Publish
        // each Box before its first fallible registration so rollback always has
        // both the runtime ID and the callback's backing allocation.
        self.callouts = Some(Vec::new());
        let result = self.commit_inner(callouts);
        if let Err(err) = result {
            // commit_inner has returned, so its Transaction guard has already
            // aborted the FWPM transaction. Runtime registrations must be
            // removed separately before their Boxes can be released.
            self.rollback_until_clean();
            self.callouts = None;
            return Err(err);
        }

        self.committed = true;
        info!("transaction committed");
        Ok(())
    }

    fn commit_inner(&mut self, callouts: Vec<Callout>) -> Result<(), String> {
        let mut filter_engine = Transaction::begin_write(self)?;
        filter_engine
            .register_sublayer()
            .map_err(|err| format!("filter_engine: {}", err))?;

        dbg!("Callouts count: {}", callouts.len());
        let device_object = filter_engine.device_object;
        let filter_engine_handle = filter_engine.handle;
        let sublayer_guid = filter_engine.sublayer_guid;

        for callout in callouts {
            let mut callout = Box::new(callout);
            callout.address = callout.as_ref() as *const Callout as u64;

            let callouts = filter_engine
                .callouts
                .as_mut()
                .ok_or_else(|| "callout storage was not initialized".to_owned())?;
            callouts.push(callout);
            let callout = callouts
                .last_mut()
                .ok_or_else(|| "newly inserted callout is missing".to_owned())?;

            callout.register_runtime_callout(device_object, catch_all_callout)?;
            callout.register_management_callout(filter_engine_handle)?;
            callout.register_filter(filter_engine_handle, sublayer_guid)?;

            dbg!(
                "registering callout: {} -> {}",
                callout.name,
                callout.filter_id
            );
        }

        filter_engine.commit()
    }

    /// Recreates resettable filters and forces WFP to reauthorize existing flows.
    ///
    /// This calls the WFP management API and must run at PASSIVE_LEVEL. Callers
    /// must also serialize mutable access without using a lock that raises IRQL.
    pub fn reset_all_filters(&mut self) -> Result<(), String> {
        // Begin to write transaction. This is also a lock guard. It will abort if transaction is not committed.
        let mut filter_engine = match Transaction::begin_write(self) {
            Ok(transaction) => transaction,
            Err(err) => {
                return Err(err);
            }
        };
        let filter_engine_handle = filter_engine.handle;
        let sublayer_guid = filter_engine.sublayer_guid;
        if let Some(callouts) = &mut filter_engine.callouts {
            for callout in callouts {
                if let FilterType::Resettable = callout.filter_type {
                    if callout.filter_id != 0 {
                        // Remove old filter.
                        if let Err(err) =
                            ffi::unregister_filter(filter_engine_handle, callout.filter_id)
                        {
                            return Err(format!("filter_engine: {}", err));
                        }
                        callout.filter_id = 0;
                    }
                    // Create new filter.
                    if let Err(err) = callout.register_filter(filter_engine_handle, sublayer_guid) {
                        return Err(format!("filter_engine: {}", err));
                    }
                }
            }
        }
        // Commit transaction.
        filter_engine.commit()?;
        return Ok(());
    }

    fn register_sublayer(&self) -> Result<(), String> {
        let result = ffi::register_sublayer(
            self.handle,
            "PortmasterSublayer",
            "The Portmaster sublayer holds all it's filters.",
            self.sublayer_guid,
        );
        if let Err(code) = result {
            return Err(format!("failed to register sublayer: {}", code));
        }

        Ok(())
    }

    fn unregister_runtime_callouts(&mut self) -> Result<UnregisterCalloutsResult, String> {
        let Some(callouts) = self.callouts.as_mut() else {
            return Ok(UnregisterCalloutsResult::Complete);
        };

        for callout in callouts.iter_mut() {
            if !callout.registered {
                continue;
            }

            match ffi::unregister_callout(callout.id)
                .map_err(|err| format!("failed to unregister callout {}: {}", callout.name, err))?
            {
                ffi::UnregisterCalloutResult::Removed => {
                    // Retain the ID and Box after every failure. Clear them only
                    // once WFP confirms that this runtime registration is gone.
                    callout.registered = false;
                    callout.id = 0;
                }
                ffi::UnregisterCalloutResult::Busy => {
                    return Ok(UnregisterCalloutsResult::Busy);
                }
            }
        }

        Ok(UnregisterCalloutsResult::Complete)
    }

    fn close_dynamic_session(&mut self) -> Result<(), String> {
        if self.handle.is_null() || self.handle == INVALID_HANDLE_VALUE {
            return Ok(());
        }

        // The session is dynamic, so a successful close synchronously removes
        // its filters, management callouts, and sublayer. Runtime FWPS callouts
        // were removed above because they are not owned by this session.
        ffi::filter_engine_close(self.handle)
            .map_err(|err| format!("failed to close filter engine: {}", err))?;
        self.handle = INVALID_HANDLE_VALUE;
        self.committed = false;

        if let Some(callouts) = self.callouts.as_mut() {
            for callout in callouts {
                callout.filter_id = 0;
            }
        }

        Ok(())
    }

    /// Unregisters all runtime callouts and closes the dynamic FWPM session.
    ///
    /// `STATUS_DEVICE_BUSY` is retryable after the owner removes all associated
    /// flow contexts. Until WFP confirms removal, every runtime ID and backing
    /// Callout Box remains live. The caller must run at PASSIVE_LEVEL.
    pub fn unregister_all(&mut self) -> Result<UnregisterCalloutsResult, String> {
        let result = self.unregister_runtime_callouts()?;
        if result == UnregisterCalloutsResult::Busy {
            return Ok(result);
        }

        self.close_dynamic_session()?;
        Ok(UnregisterCalloutsResult::Complete)
    }

    /// Last-resort cleanup for construction failures and destructor paths.
    /// Returning while a runtime callout still points into this driver would be
    /// unsafe, so retry rather than freeing its ID or backing allocation.
    fn rollback_until_clean(&mut self) {
        loop {
            match self.unregister_all() {
                Ok(UnregisterCalloutsResult::Complete) => return,
                Ok(UnregisterCalloutsResult::Busy) => {
                    dbg!("callout cleanup is waiting for WFP flow contexts");
                }
                Err(err) => {
                    dbg!("callout cleanup failed: {}", err);
                }
            }
            crate::utils::sleep_ms(1);
        }
    }
}

impl Drop for FilterEngine {
    fn drop(&mut self) {
        dbg!("Unregistering callouts");
        self.rollback_until_clean();
    }
}

#[no_mangle]
unsafe extern "C" fn catch_all_callout(
    fixed_values: *const IncomingValues,
    meta_values: *const FwpsIncomingMetadataValues,
    layer_data: *mut c_void,
    _context: *mut c_void,
    filter: *const FWPS_FILTER2,
    flow_context: u64,
    classify_out: *mut ClassifyOut,
) {
    // This must be acquired before touching `filter.context`: the Callout box
    // containing that context is owned by Device and is freed during unload.
    // A callback that arrives after admission closes is from a WFP teardown race;
    // leave the classify result untouched and, most importantly, do not
    // dereference memory owned by the retiring Device.
    let Some(_callback_guard) = crate::callback_barrier::CALLBACK_BARRIER.enter_classify() else {
        return;
    };

    let filter = &(*filter);
    // Filter context is the address of the callout.
    let callout = filter.context as *mut Callout;

    if let Some(callout) = callout.as_ref() {
        // Setup callout data.
        let array = core::slice::from_raw_parts(
            (*fixed_values).incoming_value_array,
            (*fixed_values).value_count as usize,
        );
        let data = CalloutData {
            layer: callout.layer,
            layer_id: (*fixed_values).layer_id,
            callout_id: callout.id,
            flow_context,
            values: array,
            metadata: meta_values,
            classify_out,
            layer_data,
        };
        // Call the defined function.
        (callout.callout_fn)(data);
    }
}
