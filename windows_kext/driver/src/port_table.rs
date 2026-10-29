use alloc::{collections::BTreeMap, vec, vec::Vec};
use smoltcp::wire::IpProtocol;

type PortKey = (IpProtocol, u16);

const PORT_COUNT: usize = u16::MAX as usize + 1;

/// Direct TCP/UDP port directory pointing into densely stored local-port groups.
///
/// The directory is allocated on the heap, never on the kernel stack. Zero means
/// absent; other cells contain a slot index plus one. There are at most 2 * 65,536
/// TCP/UDP groups, so u32 indices cannot overflow. This bounds only the port key
/// space, not the number of connections or retained generations in each value.
/// Other IP protocols keep the full key space through a fallback B-tree.
pub(crate) struct PortTable<V> {
    directory: Vec<u32>,
    slots: Vec<(PortKey, V)>,
    other: BTreeMap<PortKey, V>,
}

pub(crate) struct Entry<'a, V> {
    table: &'a mut PortTable<V>,
    key: PortKey,
}

impl<V> Default for PortTable<V> {
    fn default() -> Self {
        Self {
            directory: vec![0; 2 * PORT_COUNT],
            slots: Vec::new(),
            other: BTreeMap::new(),
        }
    }
}

impl<V> PortTable<V> {
    #[inline]
    fn offset(key: &PortKey) -> Option<usize> {
        match key.0 {
            IpProtocol::Tcp => Some(usize::from(key.1)),
            IpProtocol::Udp => Some(PORT_COUNT + usize::from(key.1)),
            _ => None,
        }
    }

    pub(crate) fn entry(&mut self, key: PortKey) -> Entry<'_, V> {
        Entry { table: self, key }
    }

    #[inline]
    pub(crate) fn get(&self, key: &PortKey) -> Option<&V> {
        match Self::offset(key) {
            Some(offset) => self.directory[offset]
                .checked_sub(1)
                .map(|index| &self.slots[index as usize].1),
            None => self.other.get(key),
        }
    }

    #[inline]
    pub(crate) fn get_mut(&mut self, key: &PortKey) -> Option<&mut V> {
        match Self::offset(key) {
            Some(offset) => self.directory[offset]
                .checked_sub(1)
                .map(|index| &mut self.slots[index as usize].1),
            None => self.other.get_mut(key),
        }
    }

    pub(crate) fn values(&self) -> impl Iterator<Item = &V> {
        self.slots
            .iter()
            .map(|(_, value)| value)
            .chain(self.other.values())
    }

    pub(crate) fn values_mut(&mut self) -> impl Iterator<Item = &mut V> {
        self.slots
            .iter_mut()
            .map(|(_, value)| value)
            .chain(self.other.values_mut())
    }

    pub(crate) fn retain(&mut self, mut keep: impl FnMut(&PortKey, &mut V) -> bool) {
        let mut index = 0;
        while index < self.slots.len() {
            let (key, value) = &mut self.slots[index];
            if keep(key, value) {
                index += 1;
                continue;
            }
            self.directory[Self::offset(key).expect("TCP/UDP slot")] = 0;
            self.slots.swap_remove(index);
            if let Some((moved_key, _)) = self.slots.get(index) {
                self.directory[Self::offset(moved_key).expect("TCP/UDP slot")] = (index + 1) as u32;
            }
        }
        self.other.retain(keep);
        if self.slots.capacity() > 64 && self.slots.len() < self.slots.capacity() / 4 {
            self.slots.shrink_to_fit();
        }
    }

    pub(crate) fn clear(&mut self) {
        self.directory.fill(0);
        self.slots = Vec::new();
        self.other.clear();
    }
}

impl<'a, V> Entry<'a, V> {
    pub(crate) fn or_insert_with(self, create: impl FnOnce() -> V) -> &'a mut V {
        let Some(offset) = PortTable::<V>::offset(&self.key) else {
            return self.table.other.entry(self.key).or_insert_with(create);
        };
        if self.table.directory[offset] == 0 {
            self.table.slots.push((self.key, create()));
            self.table.directory[offset] = self.table.slots.len() as u32;
        }
        let index = self.table.directory[offset] as usize - 1;
        &mut self.table.slots[index].1
    }
}

#[cfg(test)]
mod tests {
    use super::PortTable;
    use smoltcp::wire::IpProtocol;

    #[test]
    fn every_tcp_and_udp_port_can_be_occupied_at_once() {
        let mut table = PortTable::default();
        for (protocol, base) in [(IpProtocol::Tcp, 0), (IpProtocol::Udp, 65_536)] {
            for port in 0..=u16::MAX {
                let value = base + u32::from(port);
                assert_eq!(
                    *table.entry((protocol, port)).or_insert_with(|| value),
                    value
                );
            }
        }
        assert_eq!(table.values().count(), 2 * 65_536);
        for (protocol, base) in [(IpProtocol::Tcp, 0), (IpProtocol::Udp, 65_536)] {
            for port in 0..=u16::MAX {
                assert_eq!(
                    table.get(&(protocol, port)),
                    Some(&(base + u32::from(port)))
                );
                let value = table
                    .entry((protocol, port))
                    .or_insert_with(|| panic!("existing port"));
                *value += 1;
            }
        }
        table.retain(|(_, port), value| {
            *value += 10;
            *port % 257 == 0
        });
        for (protocol, base) in [(IpProtocol::Tcp, 0), (IpProtocol::Udp, 65_536)] {
            for port in 0..=u16::MAX {
                let expected = (port % 257 == 0).then_some(base + u32::from(port) + 11);
                assert_eq!(table.get(&(protocol, port)), expected.as_ref());
                if expected.is_none() {
                    *table.entry((protocol, port)).or_insert_with(|| 0) = base + u32::from(port);
                }
            }
        }
        assert_eq!(table.values().count(), 2 * 65_536);
        table.retain(|_, _| false);
        assert_eq!(table.values().count(), 0);
        assert_eq!(table.slots.capacity(), 0);
        assert!(table.directory.iter().all(|index| *index == 0));
    }

    #[test]
    fn directory_matches_btree_through_repeated_churn() {
        let mut table = PortTable::default();
        let mut expected = alloc::collections::BTreeMap::new();
        let mut random = 0x2026_1029_1310_7200u64;
        for step in 0..20_000u32 {
            random ^= random << 13;
            random ^= random >> 7;
            random ^= random << 17;
            let protocol = match random % 3 {
                0 => IpProtocol::Tcp,
                1 => IpProtocol::Udp,
                _ => IpProtocol::Unknown(253),
            };
            let key = (protocol, (random >> 32) as u16);
            *table.entry(key).or_insert_with(|| 0) = step;
            expected.insert(key, step);
            if step % 127 == 0 {
                table.retain(|(_, port), value| {
                    *value += 1;
                    port % 5 == 0
                });
                expected.retain(|(_, port), value| {
                    *value += 1;
                    port % 5 == 0
                });
            }
            assert_eq!(table.values().count(), expected.len());
            assert_eq!(table.get(&key), expected.get(&key));
            assert_eq!(table.get_mut(&key), expected.get_mut(&key));
        }
        for (key, value) in expected {
            assert_eq!(table.get(&key), Some(&value));
        }
    }

    #[test]
    fn directory_repairs_moved_slots_and_handles_all_protocols_and_ports() {
        let mut table = PortTable::default();
        for protocol in [IpProtocol::Tcp, IpProtocol::Udp, IpProtocol::Unknown(253)] {
            for port in [0, 1, 443, u16::MAX] {
                *table.entry((protocol, port)).or_insert_with(|| 0) = port;
            }
        }
        table.retain(|(_, port), _| *port != 1 && *port != 443);
        assert_eq!(table.values().count(), 6);
        for protocol in [IpProtocol::Tcp, IpProtocol::Udp, IpProtocol::Unknown(253)] {
            assert_eq!(table.get(&(protocol, 0)), Some(&0));
            assert_eq!(table.get(&(protocol, u16::MAX)), Some(&u16::MAX));
            assert_eq!(table.get(&(protocol, 1)), None);
            assert_eq!(table.get(&(protocol, 443)), None);
            *table.entry((protocol, 1)).or_insert_with(|| 999) = 7;
            assert_eq!(table.get(&(protocol, 1)), Some(&7));
        }
        table.clear();
        assert_eq!(table.values().count(), 0);
        assert!(table.slots.is_empty());
        assert_eq!(table.slots.capacity(), 0);
        assert!(table.other.is_empty());
        assert_eq!(table.get(&(IpProtocol::Udp, 1)), None);
        *table.entry((IpProtocol::Udp, 1)).or_insert_with(|| 42) = 43;
        assert_eq!(table.get(&(IpProtocol::Udp, 1)), Some(&43));
    }
}
