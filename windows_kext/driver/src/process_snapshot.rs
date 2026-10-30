//! PID-only process inventory. Kernel callbacks and session transitions serialize
//! access externally; the bootstrap journal closes the enumeration/notify race.

use alloc::{collections::BTreeMap, vec::Vec};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProcessChange {
    Created { pid: u64, parent_pid: u64 },
    Terminated { pid: u64 },
}

pub(crate) struct ProcessSnapshot {
    active: bool,
    processes: BTreeMap<u64, u64>,
    bootstrap: Option<Vec<ProcessChange>>,
}

impl ProcessSnapshot {
    pub(crate) fn new() -> Self {
        Self {
            active: false,
            processes: BTreeMap::new(),
            bootstrap: None,
        }
    }

    pub(crate) fn begin(&mut self) {
        self.clear();
        self.active = true;
        self.bootstrap = Some(Vec::new());
    }

    /// Returns a live change to publish, or journals it until enumeration ends.
    pub(crate) fn record(&mut self, change: ProcessChange) -> Option<ProcessChange> {
        if !self.active {
            return None;
        }
        if let Some(bootstrap) = &mut self.bootstrap {
            bootstrap.push(change);
            return None;
        }
        self.apply(change);
        Some(change)
    }

    /// Publish the baseline followed by the journal while still holding the same
    /// lock used by record(). Replaying in order preserves short-lived processes
    /// and PID reuse, including exits which raced the system enumeration.
    pub(crate) fn finish(
        &mut self,
        seed: Vec<(u64, u64)>,
    ) -> Option<(Vec<(u64, u64)>, Vec<ProcessChange>)> {
        let changes = self.bootstrap.take()?;
        self.processes.extend(seed);
        let baseline = self
            .processes
            .iter()
            .map(|(&pid, &parent)| (pid, parent))
            .collect();
        for &change in &changes {
            self.apply(change);
        }
        Some((baseline, changes))
    }

    fn apply(&mut self, change: ProcessChange) {
        match change {
            ProcessChange::Created { pid, parent_pid } => {
                self.processes.insert(pid, parent_pid);
            }
            ProcessChange::Terminated { pid } => {
                self.processes.remove(&pid);
            }
        }
    }

    pub(crate) fn clear(&mut self) {
        *self = Self::new();
    }
}

// SYSTEM_PROCESS_INFORMATION's fixed prefix on 64-bit Windows. Names and the
// variable thread array are intentionally ignored; NextEntryOffset bounds each
// record. This is the query ABI, not an EPROCESS layout.
#[repr(C)]
struct SystemProcessHeader {
    next_entry_offset: u32,
    number_of_threads: u32,
    reserved: [u8; 48],
    image_name: [u64; 2],
    base_priority: i32,
    padding: u32,
    pid: u64,
    parent_pid: u64,
}

const _: () = {
    assert!(core::mem::size_of::<SystemProcessHeader>() == 96);
    assert!(core::mem::offset_of!(SystemProcessHeader, pid) == 80);
    assert!(core::mem::offset_of!(SystemProcessHeader, parent_pid) == 88);
};

pub(crate) fn parse_system_processes(buffer: &[u8]) -> Result<Vec<(u64, u64)>, &'static str> {
    let mut remaining = buffer;
    let mut processes = Vec::new();
    loop {
        if remaining.len() < core::mem::size_of::<SystemProcessHeader>() {
            return Err("truncated system process header");
        }
        let next = u32::from_le_bytes(remaining[..4].try_into().unwrap()) as usize;
        let pid = u64::from_le_bytes(remaining[80..88].try_into().unwrap());
        let parent = u64::from_le_bytes(remaining[88..96].try_into().unwrap());
        processes.push((pid, parent));
        if next == 0 {
            return Ok(processes);
        }
        if next < core::mem::size_of::<SystemProcessHeader>() || next % 8 != 0 {
            return Err("invalid system process record offset");
        }
        remaining = remaining
            .get(next..)
            .ok_or("system process offset exceeds buffer")?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn created(pid: u64, parent_pid: u64) -> ProcessChange {
        ProcessChange::Created { pid, parent_pid }
    }

    fn ended(pid: u64) -> ProcessChange {
        ProcessChange::Terminated { pid }
    }

    #[test]
    fn system_query_walker_uses_offsets_not_thread_counts_or_names() {
        let mut buffer = vec![0u8; 352];
        buffer[..4].copy_from_slice(&256u32.to_le_bytes());
        buffer[4..8].copy_from_slice(&100_000u32.to_le_bytes());
        buffer[80..88].copy_from_slice(&4u64.to_le_bytes());
        buffer[256 + 80..256 + 88].copy_from_slice(&0x0102_0304_0506_0708u64.to_le_bytes());
        buffer[256 + 88..256 + 96].copy_from_slice(&4u64.to_le_bytes());
        assert_eq!(
            parse_system_processes(&buffer),
            Ok(vec![(4, 0), (0x0102_0304_0506_0708, 4)])
        );
    }

    #[test]
    fn system_query_walker_rejects_bad_offsets_and_truncation() {
        assert!(parse_system_processes(&[]).is_err());
        assert!(parse_system_processes(&[0; 95]).is_err());
        for offset in [8u32, 95, 97, 192, u32::MAX] {
            let mut buffer = vec![0u8; 192];
            buffer[..4].copy_from_slice(&offset.to_le_bytes());
            assert!(parse_system_processes(&buffer).is_err(), "offset {offset}");
        }
    }

    #[test]
    fn no_inventory_or_history_before_connection() {
        let mut snapshot = ProcessSnapshot::new();
        assert_eq!(snapshot.record(created(12, 4)), None);
        assert_eq!(snapshot.record(ended(12)), None);
        assert!(snapshot.processes.is_empty());
        assert!(snapshot.bootstrap.is_none());
    }

    #[test]
    fn seeds_existing_system_and_idle_processes_without_paths() {
        let mut snapshot = ProcessSnapshot::new();
        snapshot.begin();
        let (baseline, changes) = snapshot.finish(vec![(4, 0), (0, 0), (80, 4)]).unwrap();
        assert_eq!(baseline, [(0, 0), (4, 0), (80, 4)]);
        assert!(changes.is_empty());
        assert_eq!(snapshot.processes.len(), 3);
    }

    #[test]
    fn replay_does_not_resurrect_an_exit_seen_during_enumeration() {
        let mut snapshot = ProcessSnapshot::new();
        snapshot.begin();
        snapshot.record(ended(80));
        snapshot.record(created(81, 4));
        let (baseline, changes) = snapshot.finish(vec![(4, 0), (80, 4)]).unwrap();
        assert_eq!(baseline, [(4, 0), (80, 4)]);
        assert_eq!(changes, [ended(80), created(81, 4)]);
        assert_eq!(snapshot.processes, BTreeMap::from([(4, 0), (81, 4)]));
    }

    #[test]
    fn bootstrap_preserves_short_lifetimes_and_pid_reuse_order() {
        let mut snapshot = ProcessSnapshot::new();
        snapshot.begin();
        let changes = [
            created(80, 4),
            ended(80),
            created(80, 20),
            created(90, 80),
            ended(90),
        ];
        for &change in &changes {
            assert_eq!(snapshot.record(change), None);
        }
        let (baseline, replay) = snapshot.finish(vec![(4, 0), (80, 20)]).unwrap();
        assert_eq!(replay, changes);
        assert_eq!(snapshot.processes.get(&80), Some(&20));
        assert!(!snapshot.processes.contains_key(&90));

        let mut consumer = ProcessSnapshot::new();
        consumer.begin();
        consumer.finish(baseline).unwrap();
        for change in replay {
            consumer.record(change);
        }
        assert_eq!(consumer.processes, snapshot.processes);
    }

    #[test]
    fn parent_exit_does_not_delete_or_reparent_live_children() {
        let mut snapshot = ProcessSnapshot::new();
        snapshot.begin();
        snapshot.finish(vec![(4, 0), (80, 4), (81, 80)]).unwrap();
        assert_eq!(snapshot.record(ended(80)), Some(ended(80)));
        assert!(!snapshot.processes.contains_key(&80));
        assert_eq!(snapshot.processes.get(&81), Some(&80));
        assert_eq!(snapshot.record(created(80, 4)), Some(created(80, 4)));
        assert_eq!(snapshot.processes.len(), 3);
    }

    #[test]
    fn disconnect_discards_inventory_and_bootstrap_for_next_session() {
        let mut snapshot = ProcessSnapshot::new();
        snapshot.begin();
        snapshot.record(created(80, 4));
        snapshot.clear();
        assert_eq!(snapshot.record(created(81, 4)), None);
        assert!(snapshot.processes.is_empty());
        snapshot.begin();
        let (baseline, changes) = snapshot.finish(vec![(4, 0), (82, 4)]).unwrap();
        assert_eq!(baseline, [(4, 0), (82, 4)]);
        assert!(changes.is_empty());
    }

    #[test]
    fn restart_rebuilds_from_scratch_and_journals_only_new_bootstrap_events() {
        let mut snapshot = ProcessSnapshot::new();
        snapshot.begin();
        snapshot.finish(vec![(4, 0), (80, 4)]).unwrap();
        snapshot.record(created(81, 80));
        snapshot.begin();
        snapshot.record(created(91, 4));
        let (baseline, changes) = snapshot.finish(vec![(4, 0), (90, 4)]).unwrap();
        assert_eq!(baseline, [(4, 0), (90, 4)]);
        assert_eq!(changes, [created(91, 4)]);
        assert_eq!(
            snapshot.processes,
            BTreeMap::from([(4, 0), (90, 4), (91, 4)])
        );

        snapshot.begin();
        snapshot.record(created(100, 4));
        snapshot.begin();
        let (baseline, changes) = snapshot.finish(vec![(4, 0)]).unwrap();
        assert_eq!(baseline, [(4, 0)]);
        assert!(changes.is_empty());
    }

    #[test]
    fn repeated_churn_retains_only_live_pids() {
        let mut snapshot = ProcessSnapshot::new();
        snapshot.begin();
        snapshot.finish(vec![(0, 0), (4, 0)]).unwrap();
        for pid in 100..10_000 {
            snapshot.record(created(pid, 4));
            snapshot.record(ended(pid));
        }
        assert_eq!(snapshot.processes, BTreeMap::from([(0, 0), (4, 0)]));
        assert!(snapshot.bootstrap.is_none());
    }
}
