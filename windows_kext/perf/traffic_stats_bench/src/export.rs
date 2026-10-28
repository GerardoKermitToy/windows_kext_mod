use super::*;

pub(super) trait WireKey: Copy + Ord {
    const FAMILY: usize;
    fn encode(self, out: &mut Vec<u8>);
}

macro_rules! wire_key {
    ($key:ty, $family:expr) => {
        impl WireKey for $key {
            const FAMILY: usize = $family;
            fn encode(self, out: &mut Vec<u8>) {
                out.extend_from_slice(&self.local_ip);
                out.extend_from_slice(&self.local_port.to_le_bytes());
                out.extend_from_slice(&self.remote_ip);
                out.extend_from_slice(&self.remote_port.to_le_bytes());
            }
        }
    };
}
wire_key!(Key4, 4);
wire_key!(Key6, 16);

pub(super) fn serialize<K: WireKey, M: StatsMap<K>>(map: M, protocol: u8) -> Option<Vec<u8>> {
    let count = map.len();
    if count == 0 {
        return None;
    }
    let size = 5 + count * (2 * K::FAMILY + 20);
    assert!(size <= u32::MAX as usize);
    let mut out = Vec::with_capacity(size + 5);
    out.push(if K::FAMILY == 4 { 5 } else { 6 });
    out.extend_from_slice(&(size as u32).to_le_bytes());
    out.push(protocol);
    out.extend_from_slice(&(count as u32).to_le_bytes());
    let mut emit = |(key, value): (K, Counter)| {
        key.encode(&mut out);
        out.extend_from_slice(&value.transmitted_bytes.to_le_bytes());
        out.extend_from_slice(&value.received_bytes.to_le_bytes());
    };
    if ORDERED_OUTPUT.load(Ordering::Relaxed) != 0 && !M::SORTED {
        let mut pairs: Vec<_> = map.into_pairs().collect();
        pairs.sort_unstable_by_key(|entry| entry.0);
        pairs.into_iter().for_each(&mut emit);
    } else {
        map.into_pairs().for_each(&mut emit);
    }
    Some(out)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(super) struct CanonicalKey {
    info_type: u8,
    protocol: u8,
    tuple: [u8; 36],
}

pub(super) type Rows = Vec<(CanonicalKey, Counter)>;

pub(super) fn reference(events: &[Event]) -> Rows {
    let mut map = BTreeMap::<_, Counter>::new();
    for event in events {
        let mut bytes = Vec::with_capacity(36);
        let info_type = match event.key {
            EventKey::V4(key) => {
                key.encode(&mut bytes);
                5
            }
            EventKey::V6(key) => {
                key.encode(&mut bytes);
                6
            }
        };
        let mut tuple = [0; 36];
        tuple[..bytes.len()].copy_from_slice(&bytes);
        let protocol = if matches!(event.class, Class::TcpV4 | Class::TcpV6) {
            6
        } else {
            17
        };
        let key = CanonicalKey {
            info_type,
            protocol,
            tuple,
        };
        map.entry(key).or_default().add(event.outbound, event.bytes);
    }
    map.into_iter().collect()
}

pub(super) fn decode(packets: &[Vec<u8>]) -> Rows {
    let mut map = BTreeMap::new();
    for packet in packets {
        assert!(packet.len() >= 10);
        assert_eq!(
            u32::from_le_bytes(packet[1..5].try_into().unwrap()) as usize,
            packet.len() - 5
        );
        let tuple_size = match packet[0] {
            5 => 12,
            6 => 36,
            _ => panic!("invalid family"),
        };
        assert!(packet[5] == 6 || packet[5] == 17);
        let count = u32::from_le_bytes(packet[6..10].try_into().unwrap()) as usize;
        assert_eq!(packet.len(), 10 + count * (tuple_size + 16));
        for row in packet[10..].chunks_exact(tuple_size + 16) {
            let mut tuple = [0; 36];
            tuple[..tuple_size].copy_from_slice(&row[..tuple_size]);
            let key = CanonicalKey {
                info_type: packet[0],
                protocol: packet[5],
                tuple,
            };
            let value = Counter {
                transmitted_bytes: u64::from_le_bytes(
                    row[tuple_size..tuple_size + 8].try_into().unwrap(),
                ),
                received_bytes: u64::from_le_bytes(
                    row[tuple_size + 8..tuple_size + 16].try_into().unwrap(),
                ),
            };
            assert!(map.insert(key, value).is_none(), "duplicate aggregate key");
        }
    }
    map.into_iter().collect()
}
