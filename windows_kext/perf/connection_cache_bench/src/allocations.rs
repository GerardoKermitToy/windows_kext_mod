use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

#[derive(Clone, Copy, Default, Debug)]
pub struct Stats {
    pub calls: u64,
    pub live: usize,
    pub peak: usize,
}

thread_local! {
    static COUNTERS: Cell<Option<Stats>> = const { Cell::new(None) };
}

struct Allocator;

#[global_allocator]
static ALLOCATOR: Allocator = Allocator;

fn change(add: usize, remove: usize, call: bool) {
    let _ = COUNTERS.try_with(|counter| {
        if let Some(mut stats) = counter.get() {
            stats.live = stats.live.checked_sub(remove).unwrap() + add;
            stats.peak = stats.peak.max(stats.live);
            stats.calls += u64::from(call);
            counter.set(Some(stats));
        }
    });
}

unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            change(layout.size(), 0, true);
        }
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            change(layout.size(), 0, true);
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        change(0, layout.size(), false);
        unsafe { System.dealloc(pointer, layout) };
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let result = unsafe { System.realloc(pointer, layout, size) };
        if !result.is_null() {
            change(size, layout.size(), true);
        }
        result
    }
}

pub fn start() {
    COUNTERS.with(|counter| {
        assert!(counter.get().is_none());
        counter.set(Some(Stats::default()));
    });
}

pub fn snapshot() -> Stats {
    COUNTERS.with(|counter| counter.get().expect("allocation tracking enabled"))
}

pub fn finish() {
    let stats = COUNTERS.with(|counter| counter.replace(None).unwrap());
    assert_eq!(stats.live, 0, "cache allocations must be released on drop");
}
