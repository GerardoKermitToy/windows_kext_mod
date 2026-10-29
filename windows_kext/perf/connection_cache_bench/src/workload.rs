use crate::connection::{Connection, ConnectionV4, ConnectionV6, Direction, Verdict};
use crate::connection_map::Key;
use smoltcp::wire::{IpAddress, IpProtocol, Ipv4Address, Ipv6Address};
use std::collections::BTreeSet;

pub const CONNECTIONS: usize = 50_000;
pub const REQUESTS: usize = 1_000_000;
pub const HITS: usize = 700_000;
pub const SEED: u64 = 0x2026_1029_7047_5000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PacketInfo {
    verdict: u8,
    process_id: u64,
    direction: u8,
    pub instance_id: u64,
}

impl PacketInfo {
    pub fn checksum(self) -> u64 {
        self.process_id.wrapping_mul(31)
            ^ self.instance_id.rotate_left(17)
            ^ (u64::from(self.verdict) << 8)
            ^ u64::from(self.direction)
    }
}

pub fn snapshot<T: Connection>(connection: &T) -> Option<PacketInfo> {
    Some(PacketInfo {
        verdict: connection.get_verdict() as u8,
        process_id: connection.get_process_id(),
        direction: connection.get_direction() as u8,
        instance_id: connection.get_instance_id(),
    })
}

pub trait Family: Connection + Clone {
    const NAME: &'static str;
    fn make(key: &Key, ordinal: usize) -> Self;
}

macro_rules! family {
    ($ty:ty, $name:literal) => {
        impl Family for $ty {
            const NAME: &'static str = $name;
            fn make(key: &Key, ordinal: usize) -> Self {
                let direction = if ordinal % 3 == 0 {
                    Direction::Inbound
                } else {
                    Direction::Outbound
                };
                let mut connection = Self::from_key(key, 1000 + ordinal as u64, direction).unwrap();
                connection.thread_id = 5000 + ordinal as u64;
                connection.verdict = match ordinal % 10 {
                    0 => Verdict::PermanentBlock,
                    1 => Verdict::PermanentDrop,
                    _ => Verdict::PermanentAccept,
                };
                connection
            }
        }
    };
}
family!(ConnectionV4, "v4");
family!(ConnectionV6, "v6");

#[derive(Clone, Copy)]
pub enum Shape {
    Client,
    Listener,
    Mixed,
}

impl Shape {
    pub fn name(self) -> &'static str {
        match self {
            Self::Client => "client",
            Self::Listener => "listener",
            Self::Mixed => "mixed",
        }
    }
}

#[derive(Clone, Copy)]
pub struct Query {
    pub key: Key,
    pub direction: Direction,
}

pub struct Workload<T> {
    pub name: String,
    pub connections: Vec<T>,
    pub queries: Vec<Query>,
    pub expected: Vec<Option<PacketInfo>>,
    pub ports: Vec<(IpProtocol, u16)>,
    pub checksum: u64,
}

pub struct Rng(u64);
impl Rng {
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }
    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    pub fn shuffle<T>(&mut self, values: &mut [T]) {
        for index in (1..values.len()).rev() {
            values.swap(index, self.next() as usize % (index + 1));
        }
    }
}

fn tuple<T: Family>(index: usize, shape: Shape) -> Key {
    let (protocol, local_port) = match shape {
        Shape::Listener => (IpProtocol::Udp, 443),
        Shape::Client => (
            if index % 2 == 0 {
                IpProtocol::Tcp
            } else {
                IpProtocol::Udp
            },
            10_000 + (index / 2) as u16,
        ),
        Shape::Mixed if index < 40_000 => (
            if index % 2 == 0 {
                IpProtocol::Tcp
            } else {
                IpProtocol::Udp
            },
            10_000 + (index / 2) as u16,
        ),
        Shape::Mixed => (
            if index % 2 == 0 {
                IpProtocol::Tcp
            } else {
                IpProtocol::Udp
            },
            2000 + (index % 16) as u16,
        ),
    };
    let remote = 0xc612_0000u32 + index as u32;
    let (local_address, remote_address) = if T::NAME == "v4" {
        (
            IpAddress::Ipv4(Ipv4Address::new(10, 0, 0, 1 + (index % 4) as u8)),
            IpAddress::Ipv4(Ipv4Address::from_bytes(&remote.to_be_bytes())),
        )
    } else {
        let mut remote = [0u8; 16];
        remote[..4].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8]);
        remote[8..].copy_from_slice(&(index as u64 + 1).to_be_bytes());
        (
            IpAddress::Ipv6(Ipv6Address::new(
                0x2001,
                0xdb8,
                1,
                0,
                0,
                0,
                0,
                1 + (index % 4) as u16,
            )),
            IpAddress::Ipv6(Ipv6Address::from_bytes(&remote)),
        )
    };
    Key {
        protocol,
        local_address,
        local_port,
        remote_address,
        remote_port: 1024 + ((index as u64 * 104_729) % 64_511) as u16,
    }
}

fn miss(mut key: Key, kind: usize, index: usize) -> Key {
    match kind {
        0 => match &mut key.remote_address {
            IpAddress::Ipv4(address) => address.0[0] = 203,
            IpAddress::Ipv6(address) => address.0[3] = 0xb9,
        },
        1 => match &mut key.local_address {
            IpAddress::Ipv4(address) => address.0[1] = 254,
            IpAddress::Ipv6(address) => address.0[3] = 0xba,
        },
        2 => key.local_port = 60_000 + (index % 4096) as u16,
        _ => unreachable!(),
    }
    key
}

impl<T: Family> Workload<T> {
    pub fn new(shape: Shape, burst: bool) -> Self {
        let mut rng = Rng::new(SEED);
        let mut connections: Vec<_> = (0..CONNECTIONS)
            .map(|index| T::make(&tuple::<T>(index, shape), index))
            .collect();
        rng.shuffle(&mut connections);
        let keys: BTreeSet<_> = connections.iter().map(Connection::get_key).collect();
        assert_eq!(keys.len(), CONNECTIONS, "distinct complete tuples required");
        let ports = keys
            .iter()
            .map(Key::small)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let mut requests = Vec::with_capacity(REQUESTS);
        if burst {
            for block in 0..REQUESTS / 10 {
                let connection = &connections[rng.next() as usize % CONNECTIONS];
                let mut kinds = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
                rng.shuffle(&mut kinds);
                for kind in kinds {
                    let key = if kind < 7 {
                        connection.get_key()
                    } else {
                        miss(connection.get_key(), kind - 7, block)
                    };
                    requests.push((
                        Query {
                            key,
                            direction: direction(rng.next()),
                        },
                        if kind < 7 { snapshot(connection) } else { None },
                    ));
                }
            }
        } else {
            for index in 0..REQUESTS {
                let connection = &connections[rng.next() as usize % CONNECTIONS];
                let hit = index < HITS;
                let key = if hit {
                    connection.get_key()
                } else {
                    miss(connection.get_key(), (index - HITS) / 100_000, index)
                };
                requests.push((
                    Query {
                        key,
                        direction: direction(rng.next()),
                    },
                    if hit { snapshot(connection) } else { None },
                ));
            }
            rng.shuffle(&mut requests);
        }
        assert_eq!(requests.len(), REQUESTS);
        assert_eq!(
            requests
                .iter()
                .filter(|(_, result)| result.is_some())
                .count(),
            HITS
        );
        for (query, result) in &requests {
            assert_eq!(
                keys.contains(&query.key),
                result.is_some(),
                "miss accidentally hit a stored tuple"
            );
        }
        let checksum = requests
            .iter()
            .filter_map(|(_, result)| *result)
            .fold(0u64, |sum, value| sum.wrapping_add(value.checksum()));
        let (queries, expected) = requests.into_iter().unzip();
        Self {
            name: format!(
                "{}-{}-{}",
                T::NAME,
                shape.name(),
                if burst { "burst" } else { "uniform" }
            ),
            connections,
            queries,
            expected,
            ports,
            checksum,
        }
    }
}

fn direction(random: u64) -> Direction {
    if random & 1 == 0 {
        Direction::Inbound
    } else {
        Direction::Outbound
    }
}

#[test]
fn required_workloads_have_exactly_seventy_percent_hits() {
    for shape in [Shape::Client, Shape::Listener, Shape::Mixed] {
        let workload = Workload::<ConnectionV4>::new(shape, false);
        assert_eq!(workload.expected.iter().flatten().count(), HITS);
    }
    let workload = Workload::<ConnectionV6>::new(Shape::Mixed, true);
    assert_eq!(workload.expected.iter().flatten().count(), HITS);
}
