//! Opt-in, nonpaged TraceLogging instrumentation for xperf/WPA.
//!
//! No allocations, packet inspection, locks, or floating-point operations. The
//! driver must register before callback admission and unregister after rundown,
//! including destruction of the injection handles. See perf/XPERF.md.

use core::{
    ffi::c_void,
    mem::{offset_of, size_of},
    sync::atomic::{AtomicU64, Ordering},
};
use windows_sys::core::GUID;
use windows_sys::Wdk::System::SystemServices::KeQueryPerformanceCounter;

const TIMING: u64 = 0x1;
const REQUESTS: u64 = 0x2;
const EVERY_EVENT: u64 = 0x4;
const SAMPLE_EVERY: u64 = 64;
const LAYER_SLOTS: usize = 128;
const CPU_SLOTS: usize = 64;
const SLOT_COUNT: usize = LAYER_SLOTS + 4;

// Keep this GUID stable: xperf enables an unloaded driver by GUID, not by name.
const PROVIDER_ID: GUID = GUID::from_u128(0x5af3e2b6_6a7b_4d89_98b5_5e7da86c328d);
const PROVIDER_NAME: &[u8] = b"Portmaster.Kext.Performance\0";
const PROVIDER_TRAITS: [u8; PROVIDER_NAME.len() + 2] = metadata(PROVIDER_NAME, false);

// TraceLogging wire format documented in the WDK's TraceLoggingProvider.h.
// Channel 11 and descriptor types 2/1 make the ETL self-describing; no manifest
// or machine-local decoding resources are required.
#[repr(C)]
struct EventDescriptor {
    id: u16,
    version: u8,
    channel: u8,
    level: u8,
    opcode: u8,
    task: u16,
    keyword: u64,
}

impl EventDescriptor {
    const fn new(keyword: u64) -> Self {
        Self {
            id: 0,
            version: 0,
            channel: 11,
            level: 4,
            opcode: 0,
            task: 0,
            keyword,
        }
    }
}

#[repr(C)]
struct DataDescriptor {
    ptr: u64,
    size: u32,
    kind: u32,
}

impl DataDescriptor {
    fn new(ptr: *const u8, size: usize, kind: u32) -> Self {
        Self {
            ptr: ptr as u64,
            size: size as u32,
            kind,
        }
    }
}

const _: () = {
    assert!(size_of::<EventDescriptor>() == 16);
    assert!(offset_of!(EventDescriptor, keyword) == 8);
    assert!(size_of::<DataDescriptor>() == 16);
    assert!(offset_of!(DataDescriptor, size) == 8);
    assert!(offset_of!(DataDescriptor, kind) == 12);
    assert!(SAMPLE_EVERY.is_power_of_two());
};

type EnableCallback =
    unsafe extern "system" fn(*const GUID, u32, u8, u64, u64, *const c_void, *mut c_void);

// Kernel APIs, deliberately not the user-mode EventRegister/EventWrite imports.
extern "system" {
    fn EtwRegister(
        provider: *const GUID,
        callback: Option<EnableCallback>,
        context: *mut c_void,
        handle: *mut u64,
    ) -> i32;
    fn EtwSetInformation(handle: u64, class: i32, data: *const c_void, size: u32) -> i32;
    fn EtwUnregister(handle: u64) -> i32;
    fn EtwEventEnabled(handle: u64, event: *const EventDescriptor) -> u8;
    fn EtwWrite(
        handle: u64,
        event: *const EventDescriptor,
        activity: *const GUID,
        count: u32,
        data: *mut DataDescriptor,
    ) -> i32;
    fn KeGetCurrentProcessorNumberEx(number: *mut c_void) -> u32;
}

const fn metadata<const N: usize>(body: &[u8], event: bool) -> [u8; N] {
    let prefix = if event { 3 } else { 2 };
    assert!(N == body.len() + prefix && N <= u16::MAX as usize);
    assert!(!body.is_empty() && body[body.len() - 1] == 0 || event);
    let mut bytes = [0; N];
    bytes[0] = N as u8;
    bytes[1] = (N >> 8) as u8;
    // bytes[2] is the event's zero-tag extension, if present.
    let mut index = 0;
    while index < body.len() {
        bytes[prefix + index] = body[index];
        index += 1;
    }
    bytes
}

macro_rules! event_metadata {
    ($name:literal, $($field:literal),+ $(,)?) => {{
        // Every payload field is a tightly packed UINT64 (TlgInUINT64 = 10).
        const BODY: &[u8] = concat!($name, "\0", $($field, "\0", "\x0a",)+).as_bytes();
        metadata::<{ BODY.len() + 3 }>(BODY, true)
    }};
}

const TIMING_EVENT: EventDescriptor = EventDescriptor::new(TIMING);
const REQUEST_EVENT: EventDescriptor = EventDescriptor::new(REQUESTS);
const FULL_EVENT: EventDescriptor = EventDescriptor::new(EVERY_EVENT);
const STATE_EVENT: EventDescriptor = EventDescriptor::new(TIMING | REQUESTS);
const DURATION_METADATA: &[u8] = &event_metadata!(
    "Duration",
    "Operation",
    "Detail",
    "StartQpc",
    "DurationNs",
    "Result",
    "Flags",
    "SampleEvery",
    "Epoch"
);
const REQUEST_METADATA: &[u8] = &event_metadata!(
    "RequestRoundTrip",
    "RequestId",
    "OwnerPid",
    "Protocol",
    "IpVersion",
    "Verdict",
    "StartQpc",
    "DurationNs",
    "SampleEvery",
    "Epoch"
);
const STATE_METADATA: &[u8] = &event_metadata!(
    "ProviderState",
    "SchemaVersion",
    "Phase",
    "QpcFrequency",
    "SampleEvery",
    "EnabledKeywords",
    "WriteFailures",
    "Epoch"
);
const COUNTER_METADATA: &[u8] =
    &event_metadata!("Counter", "Operation", "Detail", "Calls", "Epoch");

static HANDLE: AtomicU64 = AtomicU64::new(0);
static ENABLED: AtomicU64 = AtomicU64::new(0);
static FREQUENCY: AtomicU64 = AtomicU64::new(0);
static EPOCH: AtomicU64 = AtomicU64::new(1);
static WRITE_FAILURES: AtomicU64 = AtomicU64::new(0);

// Shard hot counters by processor to avoid a system-wide fetch_add hotspot.
// On >64 logical processors, slots are shared, but counts remain exact. No
// processor-local unsynchronized state: callbacks can be preempted/migrated.
#[repr(align(64))]
struct CpuCounters([AtomicU64; SLOT_COUNT]);
static COUNTERS: [CpuCounters; CPU_SLOTS] =
    [const { CpuCounters([const { AtomicU64::new(0) }; SLOT_COUNT]) }; CPU_SLOTS];

#[repr(u64)]
#[derive(Clone, Copy)]
pub enum Operation {
    Classify = 1,
    Verdict = 2,
    Read = 3,
    Cleanup = 4,
    Inject = 5,
}

impl Operation {
    fn slot(self, detail: u64) -> Option<usize> {
        match self {
            Self::Classify => (detail < LAYER_SLOTS as u64).then_some(detail as usize),
            _ => Some(LAYER_SLOTS + self as usize - 2),
        }
    }
}

fn qpc() -> u64 {
    // SAFETY: QPC is callable at any IRQL; the frequency output is optional.
    unsafe { KeQueryPerformanceCounter(core::ptr::null_mut()) as u64 }
}

fn duration_ns(start: u64, end: u64) -> u64 {
    let frequency = FREQUENCY.load(Ordering::Relaxed);
    if frequency == 0 {
        return 0;
    }
    // Integer-only conversion, without overflow for a long pending request.
    ((end.saturating_sub(start) as u128 * 1_000_000_000) / frequency as u128).min(u64::MAX as u128)
        as u64
}

fn write(event: &EventDescriptor, metadata: &[u8], payload: &[u64]) {
    let handle = HANDLE.load(Ordering::Acquire);
    if handle == 0 {
        return;
    }
    let mut data = [
        DataDescriptor::new(PROVIDER_TRAITS.as_ptr(), PROVIDER_TRAITS.len(), 2),
        DataDescriptor::new(metadata.as_ptr(), metadata.len(), 1),
        DataDescriptor::new(payload.as_ptr().cast(), core::mem::size_of_val(payload), 0),
    ];
    // SAFETY: all metadata and nonpaged stack payloads remain valid until EtwWrite
    // returns. EtwWrite is synchronous with respect to its buffers, may run at
    // DISPATCH_LEVEL, and does not retain these pointers.
    let status = unsafe {
        EtwWrite(
            handle,
            event,
            core::ptr::null(),
            data.len() as u32,
            data.as_mut_ptr(),
        )
    };
    if status < 0 {
        WRITE_FAILURES.fetch_add(1, Ordering::Relaxed);
    }
}

fn refresh_enabled() {
    let handle = HANDLE.load(Ordering::Acquire);
    let mut mask = 0;
    if handle != 0 {
        for event in [&TIMING_EVENT, &REQUEST_EVENT, &FULL_EVENT] {
            // SAFETY: the registered handle is live through callback rundown.
            if unsafe { EtwEventEnabled(handle, event) } != 0 {
                mask |= event.keyword;
            }
        }
    }
    ENABLED.store(mask, Ordering::Release);
}

fn snapshot(phase: u64) {
    let enabled = ENABLED.load(Ordering::Acquire);
    if enabled & (TIMING | REQUESTS) == 0 {
        return;
    }
    write(
        &STATE_EVENT,
        STATE_METADATA,
        &[
            1,
            phase,
            FREQUENCY.load(Ordering::Relaxed),
            SAMPLE_EVERY,
            enabled,
            WRITE_FAILURES.load(Ordering::Relaxed),
            EPOCH.load(Ordering::Relaxed),
        ],
    );
    if enabled & TIMING == 0 {
        return;
    }
    for slot in 0..SLOT_COUNT {
        let calls = COUNTERS
            .iter()
            .map(|cpu| cpu.0[slot].load(Ordering::Relaxed))
            .sum::<u64>();
        if calls == 0 {
            continue;
        }
        let (operation, detail) = if slot < LAYER_SLOTS {
            (Operation::Classify as u64, slot as u64)
        } else {
            ((slot - LAYER_SLOTS + 2) as u64, 0)
        };
        write(
            &TIMING_EVENT,
            COUNTER_METADATA,
            &[operation, detail, calls, EPOCH.load(Ordering::Relaxed)],
        );
    }
}

unsafe extern "system" fn enable_callback(
    _source: *const GUID,
    control: u32,
    _level: u8,
    _any: u64,
    _all: u64,
    _filter: *const c_void,
    _context: *mut c_void,
) {
    // ETW invokes this at PASSIVE_LEVEL. Only static storage is accessed; no
    // Device pointer is used, including while DriverEntry or unload is running.
    match control {
        0 => {
            ENABLED.store(0, Ordering::Release);
            EPOCH.fetch_add(1, Ordering::AcqRel);
        }
        1 => {
            EPOCH.fetch_add(1, Ordering::AcqRel);
            refresh_enabled();
            snapshot(1);
        }
        2 => snapshot(3), // EVENT_CONTROL_CODE_CAPTURE_STATE
        _ => {}
    }
}

/// Call once at PASSIVE_LEVEL before opening classify/I/O admission.
pub fn register() -> Result<(), i32> {
    let mut frequency = 0;
    // SAFETY: the output points to a live LARGE_INTEGER-sized stack value.
    unsafe { KeQueryPerformanceCounter(&mut frequency) };
    FREQUENCY.store(frequency as u64, Ordering::Relaxed);
    let mut handle = 0;
    // SAFETY: GUID and callback have static lifetime; handle is a valid output.
    let status = unsafe {
        EtwRegister(
            &PROVIDER_ID,
            Some(enable_callback),
            core::ptr::null_mut(),
            &mut handle,
        )
    };
    if status < 0 {
        return Err(status);
    }
    // SAFETY: class 2 is EventProviderSetTraits. Setting it enables metadata
    // descriptor types and gives the provider its UTF-8 name.
    let status = unsafe {
        EtwSetInformation(
            handle,
            2,
            PROVIDER_TRAITS.as_ptr().cast(),
            PROVIDER_TRAITS.len() as u32,
        )
    };
    if status < 0 {
        // SAFETY: this handle was registered above and has not been published.
        unsafe { EtwUnregister(handle) };
        return Err(status);
    }
    HANDLE.store(handle, Ordering::Release);
    // Registration may synchronously invoke enable_callback before HANDLE was
    // published, if xperf started before the driver loaded.
    refresh_enabled();
    snapshot(1);
    Ok(())
}

/// Call at PASSIVE_LEVEL after all emitters, including injection completions, drain.
pub fn unregister() {
    snapshot(2);
    ENABLED.store(0, Ordering::Release);
    EPOCH.fetch_add(1, Ordering::AcqRel);
    let handle = HANDLE.swap(0, Ordering::AcqRel);
    if handle != 0 {
        // SAFETY: driver callback rundown has completed; EtwUnregister drains
        // the remaining ETW enable callbacks before the image can be unloaded.
        unsafe { EtwUnregister(handle) };
    }
}

/// Measures elapsed wall time, not scheduled CPU time. Created before acquiring
/// operation locks so Drop emits only after their guards have been released.
pub struct Span {
    operation: Operation,
    detail: u64,
    start: u64,
    sample_every: u64,
    epoch: u64,
    result: u64,
    flags: u64,
}

impl Span {
    #[inline]
    pub fn new(operation: Operation, detail: u64) -> Self {
        let mut span = Self {
            operation,
            detail,
            start: 0,
            sample_every: SAMPLE_EVERY,
            epoch: 0,
            result: 0,
            flags: 0,
        };
        let enabled = ENABLED.load(Ordering::Acquire);
        if enabled & TIMING == 0 {
            return span;
        }
        let Some(slot) = operation.slot(detail) else {
            return span;
        };
        // SAFETY: callable at any IRQL with an optional output. The return value is
        // a system-wide processor index; modulo CPU_SLOTS maps processors whose
        // indices differ by a multiple of CPU_SLOTS to the same atomic slot.
        let cpu =
            unsafe { KeGetCurrentProcessorNumberEx(core::ptr::null_mut()) as usize } % CPU_SLOTS;
        let count = COUNTERS[cpu].0[slot].fetch_add(1, Ordering::Relaxed);
        if enabled & EVERY_EVENT != 0 || matches!(operation, Operation::Cleanup) {
            span.sample_every = 1;
        }
        if count & (span.sample_every - 1) == 0 {
            span.epoch = EPOCH.load(Ordering::Acquire);
            span.start = qpc();
        }
        span
    }

    pub fn set_result(&mut self, result: u64, flags: u64) {
        self.result = result;
        self.flags = flags;
    }
}

impl Drop for Span {
    fn drop(&mut self) {
        if self.start == 0 {
            return;
        }
        // Read the end before formatting or writing the event, excluding that
        // part of the observer's overhead from this operation's duration.
        let end = qpc();
        if self.epoch != EPOCH.load(Ordering::Acquire) {
            return;
        }
        write(
            &TIMING_EVENT,
            DURATION_METADATA,
            &[
                self.operation as u64,
                self.detail,
                self.start,
                duration_ns(self.start, end),
                self.result,
                self.flags,
                self.sample_every,
                self.epoch,
            ],
        );
    }
}

#[derive(Clone, Copy, Default)]
pub struct RequestStamp {
    start: u64,
    epoch: u64,
    owner_pid: u64,
    sample_every: u64,
}

fn sampled_request(id: u64) -> bool {
    // Stable hashing avoids always selecting the same phase of a periodic
    // connection workload. No RNG or contended global sampling counter.
    let mut hash = id;
    hash = (hash ^ (hash >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    hash = (hash ^ (hash >> 27)).wrapping_mul(0x94d049bb133111eb);
    (hash ^ (hash >> 31)) & (SAMPLE_EVERY - 1) == 0
}

/// Timestamp before Info construction/publication. Sampling never reads the NBL.
pub fn request_queued(id: u64, owner_pid: u64) -> RequestStamp {
    let enabled = ENABLED.load(Ordering::Acquire);
    if enabled & REQUESTS == 0 {
        return RequestStamp::default();
    }
    let full = enabled & EVERY_EVENT != 0;
    if !full && !sampled_request(id) {
        return RequestStamp::default();
    }
    RequestStamp {
        epoch: EPOCH.load(Ordering::Acquire),
        start: qpc(),
        owner_pid,
        sample_every: if full { 1 } else { SAMPLE_EVERY },
    }
}

/// Call after claiming the pending request and releasing the packet-cache lock.
/// Includes queueing, ReadFile, userspace scheduling/policy, WriteFile and claim;
/// deliberately ends before verdict application and asynchronous reinjection.
pub fn request_received(id: u64, stamp: RequestStamp, protocol: u8, ip_version: u8, verdict: u8) {
    if stamp.start == 0 {
        return;
    }
    let end = qpc();
    if stamp.epoch != EPOCH.load(Ordering::Acquire) {
        return;
    }
    write(
        &REQUEST_EVENT,
        REQUEST_METADATA,
        &[
            id,
            stamp.owner_pid,
            protocol as u64,
            ip_version as u64,
            verdict as u64,
            stamp.start,
            duration_ns(stamp.start, end),
            stamp.sample_every,
            stamp.epoch,
        ],
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event_fields(bytes: &[u8]) -> usize {
        assert_eq!(
            u16::from_le_bytes([bytes[0], bytes[1]]) as usize,
            bytes.len()
        );
        assert_eq!(bytes[2], 0);
        let mut rest = &bytes[3..];
        let name_end = rest.iter().position(|byte| *byte == 0).unwrap();
        assert!(name_end > 0);
        rest = &rest[name_end + 1..];
        let mut fields = 0;
        while !rest.is_empty() {
            let end = rest.iter().position(|byte| *byte == 0).unwrap();
            assert!(end > 0);
            assert_eq!(rest[end + 1], 10);
            fields += 1;
            rest = &rest[end + 2..];
        }
        fields
    }

    #[test]
    fn self_describing_metadata_matches_payloads() {
        assert_eq!(
            u16::from_le_bytes([PROVIDER_TRAITS[0], PROVIDER_TRAITS[1]]) as usize,
            PROVIDER_TRAITS.len()
        );
        assert_eq!(&PROVIDER_TRAITS[2..], PROVIDER_NAME);
        assert_eq!(event_fields(DURATION_METADATA), 8);
        assert_eq!(event_fields(REQUEST_METADATA), 9);
        assert_eq!(event_fields(STATE_METADATA), 7);
        assert_eq!(event_fields(COUNTER_METADATA), 4);
    }

    #[test]
    fn timing_slots_are_distinct_and_bounded() {
        assert_eq!(Operation::Classify.slot(0), Some(0));
        assert_eq!(Operation::Classify.slot(127), Some(127));
        assert_eq!(Operation::Classify.slot(128), None);
        assert_eq!(Operation::Verdict.slot(0), Some(128));
        assert_eq!(Operation::Read.slot(0), Some(129));
        assert_eq!(Operation::Cleanup.slot(0), Some(130));
        assert_eq!(Operation::Inject.slot(0), Some(SLOT_COUNT - 1));
    }

    #[test]
    fn request_sampling_is_sparse() {
        let count = (1..=65536).filter(|id| sampled_request(*id)).count();
        assert!((800..=1300).contains(&count));
    }
}
