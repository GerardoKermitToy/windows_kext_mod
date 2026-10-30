use alloc::vec::Vec;

#[repr(u8)]
#[derive(Clone, Copy)]
enum InfoType {
    LogLine = 0,
    // Values 1 and 2 are reserved for the legacy connection format.
    ConnectionIpv4 = 7,
    ConnectionIpv6 = 8,
    ConnectionEndEventV4 = 3,
    ConnectionEndEventV6 = 4,
    BandwidthStatsV4 = 5,
    BandwidthStatsV6 = 6,
    ProcessCreated = 9,
    ProcessTerminated = 10,
}

// Fallow this pattern when adding new packets: [InfoType: u8, data_size_in_bytes: u32, data: ...]

trait PushBytes {
    fn push(self, vec: &mut Vec<u8>);
}

impl PushBytes for u8 {
    fn push(self, vec: &mut Vec<u8>) {
        vec.push(self);
    }
}

impl PushBytes for InfoType {
    fn push(self, vec: &mut Vec<u8>) {
        vec.push(self as u8);
    }
}

impl PushBytes for u16 {
    fn push(self, vec: &mut Vec<u8>) {
        vec.extend_from_slice(&u16::to_le_bytes(self));
    }
}

impl PushBytes for u32 {
    fn push(self, vec: &mut Vec<u8>) {
        vec.extend_from_slice(&u32::to_le_bytes(self));
    }
}

impl PushBytes for u64 {
    fn push(self, vec: &mut Vec<u8>) {
        vec.extend_from_slice(&u64::to_le_bytes(self));
    }
}

impl PushBytes for usize {
    fn push(self, vec: &mut Vec<u8>) {
        vec.extend_from_slice(&usize::to_le_bytes(self));
    }
}

impl PushBytes for [u8; 4] {
    fn push(self, vec: &mut Vec<u8>) {
        vec.extend_from_slice(&self);
    }
}

impl PushBytes for [u8; 16] {
    fn push(self, vec: &mut Vec<u8>) {
        vec.extend_from_slice(&self);
    }
}

impl PushBytes for &[u8] {
    fn push(self, vec: &mut Vec<u8>) {
        vec.extend_from_slice(self);
    }
}

macro_rules! push_bytes {
    ($vec:expr,$value:expr) => {
        PushBytes::push($value, $vec);
    };
}

macro_rules! get_combined_size{
    ($($a:expr),*)=>{{0 $(+core::mem::size_of_val(&$a))*}}
}

pub struct Info(Vec<u8>);

impl Info {
    fn new(info_type: InfoType, size: usize) -> Self {
        let mut vec = Vec::with_capacity(size + 5); // +1 for the info type +4 for the size.
        push_bytes!(&mut vec, info_type);
        push_bytes!(&mut vec, size as u32);
        Self(vec)
    }

    fn with_capacity(info_type: InfoType, capacity: usize) -> Self {
        let mut vec = Vec::with_capacity(capacity + 5); // +1 for the info type + 4 for the size.
        push_bytes!(&mut vec, info_type);
        push_bytes!(&mut vec, 0 as u32);
        Self(vec)
    }

    #[cfg(test)]
    fn assert_size(&self) {
        let size = u32::from_le_bytes([self.0[1], self.0[2], self.0[3], self.0[4]]) as usize;
        assert_eq!(size, self.0.len() - 5);
    }

    fn update_size(&mut self) {
        let size = self.0.len() - 5;
        let bytes = &mut self.0;
        bytes[1] = size as u8;
        bytes[2] = (size >> 8) as u8;
        bytes[3] = (size >> 16) as u8;
        bytes[4] = (size >> 24) as u8;
    }

    pub fn as_bytes(&self) -> &[u8] {
        return self.0.as_slice();
    }
}

impl core::fmt::Write for Info {
    fn write_str(&mut self, s: &str) -> Result<(), core::fmt::Error> {
        const MAX_CAPACITY: usize = 500;

        let space_left = self.0.capacity() - self.0.len();
        if s.len() > space_left {
            if self.0.capacity() < MAX_CAPACITY {
                self.0.reserve(MAX_CAPACITY);
            } else {
                return Ok(());
            }
        }

        self.0.extend_from_slice(s.as_bytes());
        self.update_size();
        Ok(())
    }
}

pub fn connection_info_v4(
    id: u64,
    process_id: u64,
    tid: u64,
    compartment_id: u32,
    interface_index: u32,
    sub_interface_index: u32,
    direction: u8,
    protocol: u8,
    local_ip: [u8; 4],
    remote_ip: [u8; 4],
    local_port: u16,
    remote_port: u16,
    payload_layer: u8,
    payload: &[u8],
) -> Info {
    let mut size = get_combined_size!(
        id,
        process_id,
        tid,
        compartment_id,
        interface_index,
        sub_interface_index,
        direction,
        protocol,
        local_ip,
        remote_ip,
        local_port,
        remote_port,
        payload_layer,
        payload.len() as u32
    );
    size += payload.len();

    let mut info = Info::new(InfoType::ConnectionIpv4, size);
    let vec = &mut info.0;
    push_bytes!(vec, id);
    push_bytes!(vec, process_id);
    push_bytes!(vec, tid);
    push_bytes!(vec, compartment_id);
    push_bytes!(vec, interface_index);
    push_bytes!(vec, sub_interface_index);
    push_bytes!(vec, direction);
    push_bytes!(vec, protocol);
    push_bytes!(vec, local_ip);
    push_bytes!(vec, remote_ip);
    push_bytes!(vec, local_port);
    push_bytes!(vec, remote_port);
    push_bytes!(vec, payload_layer);
    push_bytes!(vec, payload.len() as u32);
    push_bytes!(vec, payload);
    info
}

pub fn connection_info_v6(
    id: u64,
    process_id: u64,
    tid: u64,
    compartment_id: u32,
    interface_index: u32,
    sub_interface_index: u32,
    direction: u8,
    protocol: u8,
    local_ip: [u8; 16],
    remote_ip: [u8; 16],
    local_port: u16,
    remote_port: u16,
    payload_layer: u8,
    payload: &[u8],
) -> Info {
    let mut size = get_combined_size!(
        id,
        process_id,
        tid,
        compartment_id,
        interface_index,
        sub_interface_index,
        direction,
        protocol,
        local_ip,
        remote_ip,
        local_port,
        remote_port,
        payload_layer,
        payload.len() as u32
    );
    size += payload.len();
    let mut info = Info::new(InfoType::ConnectionIpv6, size);
    let vec = &mut info.0;
    push_bytes!(vec, id);
    push_bytes!(vec, process_id);
    push_bytes!(vec, tid);
    push_bytes!(vec, compartment_id);
    push_bytes!(vec, interface_index);
    push_bytes!(vec, sub_interface_index);
    push_bytes!(vec, direction);
    push_bytes!(vec, protocol);
    push_bytes!(vec, local_ip);
    push_bytes!(vec, remote_ip);
    push_bytes!(vec, local_port);
    push_bytes!(vec, remote_port);
    push_bytes!(vec, payload_layer);
    push_bytes!(vec, payload.len() as u32);
    if !payload.is_empty() {
        push_bytes!(vec, payload);
    }
    info
}

pub fn connection_end_event_v4_info(
    process_id: u64,
    direction: u8,
    protocol: u8,
    local_ip: [u8; 4],
    remote_ip: [u8; 4],
    local_port: u16,
    remote_port: u16,
) -> Info {
    let size = get_combined_size!(
        process_id,
        direction,
        protocol,
        local_ip,
        remote_ip,
        local_port,
        remote_port
    );
    let mut info = Info::new(InfoType::ConnectionEndEventV4, size);
    let vec = &mut info.0;
    push_bytes!(vec, process_id);
    push_bytes!(vec, direction);
    push_bytes!(vec, protocol);
    push_bytes!(vec, local_ip);
    push_bytes!(vec, remote_ip);
    push_bytes!(vec, local_port);
    push_bytes!(vec, remote_port);
    info
}

pub fn connection_end_event_v6_info(
    process_id: u64,
    direction: u8,
    protocol: u8,
    local_ip: [u8; 16],
    remote_ip: [u8; 16],
    local_port: u16,
    remote_port: u16,
) -> Info {
    let size = get_combined_size!(
        process_id,
        direction,
        protocol,
        local_ip,
        remote_ip,
        local_port,
        remote_port
    );
    let mut info = Info::new(InfoType::ConnectionEndEventV6, size);
    let vec = &mut info.0;
    push_bytes!(vec, process_id);
    push_bytes!(vec, direction);
    push_bytes!(vec, protocol);
    push_bytes!(vec, local_ip);
    push_bytes!(vec, remote_ip);
    push_bytes!(vec, local_port);
    push_bytes!(vec, remote_port);
    info
}

/// Initial snapshot entries and subsequent process creations share this format.
/// The payload size determines the number of (PID, parent PID) pairs.
pub fn process_created_info<I>(processes: I) -> Info
where
    I: IntoIterator<Item = (u64, u64)>,
    I::IntoIter: ExactSizeIterator,
{
    let processes = processes.into_iter();
    let mut info = Info::new(InfoType::ProcessCreated, processes.len() * 16);
    for (pid, parent_pid) in processes {
        push_bytes!(&mut info.0, pid);
        push_bytes!(&mut info.0, parent_pid);
    }
    info
}

/// The payload is a packed array of terminated PIDs, without a count field.
pub fn process_terminated_info<I>(processes: I) -> Info
where
    I: IntoIterator<Item = u64>,
    I::IntoIter: ExactSizeIterator,
{
    let processes = processes.into_iter();
    let mut info = Info::new(InfoType::ProcessTerminated, processes.len() * 8);
    for pid in processes {
        push_bytes!(&mut info.0, pid);
    }
    info
}

#[repr(u8)]
#[derive(Clone, Copy)]
pub enum Severity {
    Trace = 1,
    Debug = 2,
    Info = 3,
    Warning = 4,
    Error = 5,
    Critical = 6,
    Disabled = 7,
}

// pub fn log_line(severity: Severity, prefix: String, line: String) -> Info {
//     let mut size = get_combined_size!(severity);
//     size += prefix.len() + line.len();

//     let mut info = Info::new(InfoType::LogLine, size);
//     let vec = &mut info.0;
//     push_bytes!(vec, severity as u8);
//     push_bytes!(vec, prefix.as_bytes());
//     push_bytes!(vec, line.as_bytes());
//     info
// }

pub fn log_line(severity: Severity, capacity: usize) -> Info {
    let mut info = Info::with_capacity(InfoType::LogLine, capacity);
    let vec = &mut info.0;
    push_bytes!(vec, severity as u8);
    info
}

// Special struct for Bandwidth stats
pub struct BandwidthValueV4 {
    pub local_ip: [u8; 4],
    pub local_port: u16,
    pub remote_ip: [u8; 4],
    pub remote_port: u16,
    pub transmitted_bytes: u64,
    pub received_bytes: u64,
}

impl BandwidthValueV4 {
    const SERIALIZED_SIZE: usize = 2 * core::mem::size_of::<[u8; 4]>()
        + 2 * core::mem::size_of::<u16>()
        + 2 * core::mem::size_of::<u64>();
}

impl PushBytes for BandwidthValueV4 {
    fn push(self, vec: &mut Vec<u8>) {
        push_bytes!(vec, self.local_ip);
        push_bytes!(vec, self.local_port);
        push_bytes!(vec, self.remote_ip);
        push_bytes!(vec, self.remote_port);
        push_bytes!(vec, self.transmitted_bytes);
        push_bytes!(vec, self.received_bytes);
    }
}

pub struct BandwidthValueV6 {
    pub local_ip: [u8; 16],
    pub local_port: u16,
    pub remote_ip: [u8; 16],
    pub remote_port: u16,
    pub transmitted_bytes: u64,
    pub received_bytes: u64,
}

impl BandwidthValueV6 {
    const SERIALIZED_SIZE: usize = 2 * core::mem::size_of::<[u8; 16]>()
        + 2 * core::mem::size_of::<u16>()
        + 2 * core::mem::size_of::<u64>();
}

impl PushBytes for BandwidthValueV6 {
    fn push(self, vec: &mut Vec<u8>) {
        push_bytes!(vec, self.local_ip);
        push_bytes!(vec, self.local_port);
        push_bytes!(vec, self.remote_ip);
        push_bytes!(vec, self.remote_port);
        push_bytes!(vec, self.transmitted_bytes);
        push_bytes!(vec, self.received_bytes);
    }
}

pub fn bandiwth_stats_array_v4<I>(protocol: u8, values: I) -> Info
where
    I: IntoIterator<Item = BandwidthValueV4>,
    I::IntoIter: ExactSizeIterator,
{
    let values = values.into_iter();
    let count = values.len();
    let size =
        get_combined_size!(protocol, count as u32) + BandwidthValueV4::SERIALIZED_SIZE * count;

    let mut info = Info::new(InfoType::BandwidthStatsV4, size);
    let vec = &mut info.0;
    push_bytes!(vec, protocol);
    push_bytes!(vec, count as u32);
    for v in values {
        push_bytes!(vec, v);
    }
    info
}

pub fn bandiwth_stats_array_v6<I>(protocol: u8, values: I) -> Info
where
    I: IntoIterator<Item = BandwidthValueV6>,
    I::IntoIter: ExactSizeIterator,
{
    let values = values.into_iter();
    let count = values.len();
    let size =
        get_combined_size!(protocol, count as u32) + BandwidthValueV6::SERIALIZED_SIZE * count;

    let mut info = Info::new(InfoType::BandwidthStatsV6, size);
    let vec = &mut info.0;
    push_bytes!(vec, protocol);
    push_bytes!(vec, count as u32);
    for v in values {
        push_bytes!(vec, v);
    }
    info
}

#[cfg(test)]
mod tests {
    use super::{
        bandiwth_stats_array_v4, bandiwth_stats_array_v6, connection_info_v4, connection_info_v6,
        BandwidthValueV4, BandwidthValueV6,
    };
    use alloc::{collections::BTreeMap, vec};
    use core::cell::Cell;

    #[test]
    fn connection_v4_preserves_metadata_order_and_little_endian() {
        let info = connection_info_v4(
            0x0102_0304_0506_0708,
            0x1112_1314_1516_1718,
            0x2122_2324_2526_2728,
            0x3132_3334,
            0x4142_4344,
            0x5152_5354,
            1,
            17,
            [1, 2, 3, 4],
            [5, 6, 7, 8],
            0x6162,
            0x7172,
            3,
            &[0xaa, 0xbb, 0xcc],
        );
        assert_eq!(
            info.as_bytes(),
            &[
                7, 58, 0, 0, 0, 8, 7, 6, 5, 4, 3, 2, 1, 0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12,
                0x11, 0x28, 0x27, 0x26, 0x25, 0x24, 0x23, 0x22, 0x21, 0x34, 0x33, 0x32, 0x31, 0x44,
                0x43, 0x42, 0x41, 0x54, 0x53, 0x52, 0x51, 1, 17, 1, 2, 3, 4, 5, 6, 7, 8, 0x62,
                0x61, 0x72, 0x71, 3, 3, 0, 0, 0, 0xaa, 0xbb, 0xcc,
            ]
        );
        info.assert_size();
    }

    #[test]
    fn connection_v6_preserves_metadata_order_and_little_endian() {
        let info = connection_info_v6(
            0x0102_0304_0506_0708,
            0x1112_1314_1516_1718,
            0x2122_2324_2526_2728,
            0x3132_3334,
            0x4142_4344,
            0x5152_5354,
            1,
            17,
            core::array::from_fn(|i| i as u8 + 1),
            core::array::from_fn(|i| i as u8 + 17),
            0x6162,
            0x7172,
            4,
            &[0xaa, 0xbb, 0xcc],
        );
        let mut expected = vec![
            8, 82, 0, 0, 0, 8, 7, 6, 5, 4, 3, 2, 1, 0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11,
            0x28, 0x27, 0x26, 0x25, 0x24, 0x23, 0x22, 0x21, 0x34, 0x33, 0x32, 0x31, 0x44, 0x43,
            0x42, 0x41, 0x54, 0x53, 0x52, 0x51, 1, 17,
        ];
        expected.extend(1..=16);
        expected.extend(17..=32);
        expected.extend_from_slice(&[0x62, 0x61, 0x72, 0x71, 4, 3, 0, 0, 0, 0xaa, 0xbb, 0xcc]);
        assert_eq!(info.as_bytes(), expected.as_slice());
        info.assert_size();
    }

    #[test]
    fn connection_without_metadata_or_payload_keeps_fixed_fields() {
        let v4 = connection_info_v4(1, 2, 0, 0, 0, 0, 0, 6, [1; 4], [2; 4], 3, 4, 4, &[]);
        let v6 = connection_info_v6(1, 2, 0, 0, 0, 0, 0, 6, [1; 16], [2; 16], 3, 4, 4, &[]);
        for (info, info_type, size) in [(v4, 7, 55), (v6, 8, 79)] {
            let bytes = info.as_bytes();
            assert_eq!(&bytes[..5], &[info_type, size, 0, 0, 0]);
            assert_eq!(bytes.len(), size as usize + 5);
            assert_eq!(&bytes[21..41], &[0; 20]);
            assert_eq!(&bytes[41..43], &[0, 6]);
            assert_eq!(&bytes[bytes.len() - 4..], &[0; 4]);
            info.assert_size();
        }
    }

    #[test]
    fn empty_bandwidth_iterators_preserve_wire_headers() {
        let v4 = bandiwth_stats_array_v4(17, core::iter::empty::<BandwidthValueV4>());
        let v6 = bandiwth_stats_array_v6(6, core::iter::empty::<BandwidthValueV6>());

        assert_eq!(v4.as_bytes(), &[5, 5, 0, 0, 0, 17, 0, 0, 0, 0]);
        assert_eq!(v6.as_bytes(), &[6, 5, 0, 0, 0, 6, 0, 0, 0, 0]);
    }

    #[test]
    fn bandwidth_v4_iterator_preserves_field_order_and_little_endian() {
        let info = bandiwth_stats_array_v4(
            17,
            [BandwidthValueV4 {
                local_ip: [1, 2, 3, 4],
                local_port: 0x1234,
                remote_ip: [5, 6, 7, 8],
                remote_port: 0x5678,
                transmitted_bytes: 0x0102_0304_0506_0708,
                received_bytes: 0x1112_1314_1516_1718,
            }],
        );

        assert_eq!(
            info.as_bytes(),
            &[
                5, 33, 0, 0, 0, 17, 1, 0, 0, 0, 1, 2, 3, 4, 0x34, 0x12, 5, 6, 7, 8, 0x78, 0x56, 8,
                7, 6, 5, 4, 3, 2, 1, 0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11,
            ]
        );
        info.assert_size();
    }

    #[test]
    fn bandwidth_v6_vec_preserves_field_order_and_little_endian() {
        let info = bandiwth_stats_array_v6(
            6,
            vec![BandwidthValueV6 {
                local_ip: [1; 16],
                local_port: 0x1234,
                remote_ip: [2; 16],
                remote_port: 0x5678,
                transmitted_bytes: 0x0102_0304_0506_0708,
                received_bytes: 0x1112_1314_1516_1718,
            }],
        );
        let mut expected = vec![6, 57, 0, 0, 0, 6, 1, 0, 0, 0];
        expected.extend_from_slice(&[1; 16]);
        expected.extend_from_slice(&[0x34, 0x12]);
        expected.extend_from_slice(&[2; 16]);
        expected.extend_from_slice(&[0x78, 0x56]);
        expected.extend_from_slice(&[8, 7, 6, 5, 4, 3, 2, 1]);
        expected.extend_from_slice(&[0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11]);

        assert_eq!(info.as_bytes(), expected.as_slice());
        info.assert_size();
    }

    #[test]
    fn bandwidth_serializes_owned_map_once_in_key_order() {
        let stats = BTreeMap::from([(2u8, 20u64), (1, 10)]);
        let visited = Cell::new(0);
        let values = stats.into_iter().map(|(id, bytes)| {
            visited.set(visited.get() + 1);
            BandwidthValueV4 {
                local_ip: [id; 4],
                local_port: 0,
                remote_ip: [0; 4],
                remote_port: 0,
                transmitted_bytes: bytes,
                received_bytes: 0,
            }
        });
        assert_eq!(visited.get(), 0);

        let info = bandiwth_stats_array_v4(6, values);
        let bytes = info.as_bytes();
        assert_eq!(visited.get(), 2);
        assert_eq!(bytes.len(), 10 + 28 * 2);
        assert_eq!(&bytes[..10], &[5, 61, 0, 0, 0, 6, 2, 0, 0, 0]);
        assert_eq!(&bytes[10..14], &[1; 4]);
        assert_eq!(&bytes[38..42], &[2; 4]);
        assert_eq!(&bytes[22..30], &10u64.to_le_bytes());
        assert_eq!(&bytes[50..58], &20u64.to_le_bytes());
        info.assert_size();
    }

    #[test]
    fn process_batches_have_no_count_and_preserve_full_width_pids() {
        let created =
            super::process_created_info([(0, 0), (0x0102_0304_0506_0708, 0x1112_1314_1516_1718)]);
        let mut expected = vec![9, 32, 0, 0, 0];
        expected.extend_from_slice(&[0; 16]);
        expected.extend_from_slice(&[8, 7, 6, 5, 4, 3, 2, 1]);
        expected.extend_from_slice(&[0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11]);
        assert_eq!(created.as_bytes(), expected);
        created.assert_size();

        let terminated = super::process_terminated_info([0, 0x0102_0304_0506_0708]);
        assert_eq!(
            terminated.as_bytes(),
            &[10, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 7, 6, 5, 4, 3, 2, 1]
        );
        terminated.assert_size();
    }

    #[test]
    fn empty_process_batches_and_large_payload_headers_are_exact() {
        assert_eq!(super::process_created_info([]).as_bytes(), &[9, 0, 0, 0, 0]);
        assert_eq!(
            super::process_terminated_info([]).as_bytes(),
            &[10, 0, 0, 0, 0]
        );
        let created = super::process_created_info((0..300usize).map(|pid| (pid as u64, 4)));
        assert_eq!(&created.as_bytes()[..5], &[9, 0xc0, 0x12, 0, 0]);
        assert_eq!(created.as_bytes().len(), 5 + 300 * 16);
        created.assert_size();
    }

    #[test]
    fn bandwidth_v6_iterator_serializes_full_u32_count() {
        let count = 300;
        let values = (0..count).map(|_| BandwidthValueV6 {
            local_ip: [0; 16],
            local_port: 0,
            remote_ip: [0; 16],
            remote_port: 0,
            transmitted_bytes: 0,
            received_bytes: 0,
        });
        let info = bandiwth_stats_array_v6(17, values);

        assert_eq!(info.as_bytes().len(), 10 + 52 * count);
        assert_eq!(&info.as_bytes()[6..10], &(count as u32).to_le_bytes());
        info.assert_size();
    }
}

#[cfg(test)]
use std::fs::File;
#[cfg(test)]
use std::io::Write;

#[cfg(test)]
use rand::seq::SliceRandom;

#[test]
fn generate_test_info_file() -> Result<(), std::io::Error> {
    let mut file = File::create("../kextinterface/testdata/rust_info_test.bin")?;
    let enums = [
        InfoType::LogLine,
        InfoType::ConnectionIpv4,
        InfoType::ConnectionIpv6,
        InfoType::ConnectionEndEventV4,
        InfoType::ConnectionEndEventV6,
        InfoType::BandwidthStatsV4,
        InfoType::BandwidthStatsV6,
        InfoType::ProcessCreated,
        InfoType::ProcessTerminated,
    ];

    let mut selected: Vec<InfoType> = Vec::with_capacity(1000);
    let mut rng = rand::thread_rng();
    for _ in 0..selected.capacity() {
        selected.push(enums.choose(&mut rng).unwrap().clone());
    }
    // Write wrong size data. To make sure that mismatches between kext and portmaster are handled properly.
    let mut info = connection_info_v6(
        1,
        2,
        9,
        10,
        11,
        12,
        3,
        4,
        [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
        [2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17],
        5,
        6,
        7,
        &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
    );
    info.assert_size();
    info.0[0] = InfoType::ConnectionIpv4 as u8;
    file.write_all(&info.0)?;

    for value in selected {
        file.write_all(&match value {
            InfoType::LogLine => {
                let mut info = log_line(Severity::Trace, 5);
                use std::fmt::Write;
                _ = write!(info, "prefix: test log");
                info.assert_size();
                info.0
            }
            InfoType::ConnectionIpv4 => {
                let info = connection_info_v4(
                    1,
                    2,
                    9,
                    10,
                    11,
                    12,
                    3,
                    4,
                    [1, 2, 3, 4],
                    [2, 3, 4, 5],
                    5,
                    6,
                    7,
                    &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
                );
                info.assert_size();
                info.0
            }

            InfoType::ConnectionIpv6 => {
                let info = connection_info_v6(
                    1,
                    2,
                    9,
                    10,
                    11,
                    12,
                    3,
                    4,
                    [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
                    [2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17],
                    5,
                    6,
                    7,
                    &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
                );
                info.assert_size();
                info.0
            }
            InfoType::ConnectionEndEventV4 => {
                let info = connection_end_event_v4_info(1, 2, 3, [1, 2, 3, 4], [2, 3, 4, 5], 4, 5);
                info.assert_size();
                info.0
            }
            InfoType::ConnectionEndEventV6 => {
                let info = connection_end_event_v6_info(
                    1,
                    2,
                    3,
                    [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
                    [2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17],
                    4,
                    5,
                );
                info.assert_size();
                info.0
            }
            InfoType::BandwidthStatsV4 => {
                let mut vec = Vec::new();
                vec.push(BandwidthValueV4 {
                    local_ip: [1, 2, 3, 4],
                    local_port: 1,
                    remote_ip: [2, 3, 4, 5],
                    remote_port: 2,
                    transmitted_bytes: 3,
                    received_bytes: 4,
                });
                vec.push(BandwidthValueV4 {
                    local_ip: [1, 2, 3, 4],
                    local_port: 5,
                    remote_ip: [2, 3, 4, 5],
                    remote_port: 6,
                    transmitted_bytes: 7,
                    received_bytes: 8,
                });
                let info = bandiwth_stats_array_v4(1, vec);
                info.assert_size();
                info.0
            }
            InfoType::BandwidthStatsV6 => {
                let mut vec = Vec::new();
                vec.push(BandwidthValueV6 {
                    local_ip: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
                    local_port: 1,
                    remote_ip: [2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17],
                    remote_port: 2,
                    transmitted_bytes: 3,
                    received_bytes: 4,
                });
                vec.push(BandwidthValueV6 {
                    local_ip: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
                    local_port: 5,
                    remote_ip: [2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17],
                    remote_port: 6,
                    transmitted_bytes: 7,
                    received_bytes: 8,
                });
                let info = bandiwth_stats_array_v6(1, vec);
                info.assert_size();
                info.0
            }
            InfoType::ProcessCreated => {
                let info = process_created_info([(1, 0), (2, 1)]);
                info.assert_size();
                info.0
            }
            InfoType::ProcessTerminated => {
                let info = process_terminated_info([1, 2]);
                info.assert_size();
                info.0
            }
        })?;
    }

    return Ok(());
}
