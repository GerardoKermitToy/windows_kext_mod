//! Canonical complement of local destination addresses for WFP connection policies.
//!
//! WFP does not reliably support multiple independent NOT_EQUAL conditions for
//! the same field. Each permitted interval is represented by a separate policy
//! with one remote-address range condition instead. This work runs only when the
//! address inventory changes, never on the packet/connection classify path.

use alloc::vec::Vec;
use windows_sys::Win32::Foundation::{NTSTATUS, STATUS_INSUFFICIENT_RESOURCES};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AddressRange {
    pub first: u128,
    pub last: u128,
}

#[derive(Debug, PartialEq, Eq)]
pub struct AddressRanges {
    pub ipv4: Vec<AddressRange>,
    pub ipv6: Vec<AddressRange>,
}

impl AddressRanges {
    /// IPv4 inputs are in WFP's host-order representation (e.g. 127.0.0.1 is
    /// 0x7f000001); IPv6 inputs are in network byte order.
    pub fn new(ipv4: &[u32], ipv6: &[[u8; 16]]) -> Result<Self, NTSTATUS> {
        let mut v4 = Vec::new();
        v4.try_reserve_exact(ipv4.len().saturating_add(1))
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        v4.push(AddressRange {
            first: 0x7f00_0000,
            last: 0x7fff_ffff,
        });
        v4.extend(ipv4.iter().map(|&ip| AddressRange {
            first: ip as u128,
            last: ip as u128,
        }));

        let mut v6 = Vec::new();
        v6.try_reserve_exact(ipv6.len().saturating_add(1))
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        v6.push(AddressRange { first: 1, last: 1 });
        v6.extend(ipv6.iter().map(|&ip| {
            let ip = u128::from_be_bytes(ip);
            AddressRange {
                first: ip,
                last: ip,
            }
        }));
        Ok(Self {
            ipv4: complement(v4, u32::MAX as u128)?,
            ipv6: complement(v6, u128::MAX)?,
        })
    }
}

fn complement(mut excluded: Vec<AddressRange>, max: u128) -> Result<Vec<AddressRange>, NTSTATUS> {
    excluded.sort_unstable_by_key(|range| (range.first, range.last));
    let mut permitted = Vec::new();
    permitted
        .try_reserve_exact(excluded.len().saturating_add(1))
        .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    let mut next = Some(0u128);
    for range in excluded {
        let Some(first) = next else { break };
        if range.last < first {
            continue;
        }
        if range.first > first {
            permitted.push(AddressRange {
                first,
                last: range.first - 1,
            });
        }
        next = if range.last == max {
            None
        } else {
            Some(range.last + 1)
        };
    }
    if let Some(first) = next {
        permitted.push(AddressRange { first, last: max });
    }
    Ok(permitted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn contains(ranges: &[AddressRange], value: u128) -> bool {
        ranges
            .iter()
            .any(|range| range.first <= value && value <= range.last)
    }

    #[test]
    fn loopback_is_always_excluded_and_boundaries_are_preserved() {
        let ranges = AddressRanges::new(&[], &[]).unwrap();
        for ip in [0x7f00_0000, 0x7f00_0001, 0x7f00_0002, 0x7fff_ffff] {
            assert!(!contains(&ranges.ipv4, ip));
        }
        for ip in [0, 0x7eff_ffff, 0x8000_0000, u32::MAX as u128] {
            assert!(contains(&ranges.ipv4, ip));
        }
        assert!(contains(&ranges.ipv6, 0));
        assert!(!contains(&ranges.ipv6, 1));
        assert!(contains(&ranges.ipv6, 2));
        assert!(contains(&ranges.ipv6, u128::MAX));
    }

    #[test]
    fn duplicate_unsorted_adjacent_and_extreme_addresses_are_canonical() {
        let ip6 = |n: u128| n.to_be_bytes();
        let a = AddressRanges::new(
            &[0, 3, 2, 2, 0x7f00_0002, u32::MAX],
            &[ip6(3), ip6(u128::MAX), ip6(0), ip6(3)],
        )
        .unwrap();
        let b =
            AddressRanges::new(&[u32::MAX, 2, 3, 0], &[ip6(0), ip6(3), ip6(u128::MAX)]).unwrap();
        assert_eq!(a, b);
        assert_eq!(
            a.ipv4,
            vec![
                AddressRange { first: 1, last: 1 },
                AddressRange {
                    first: 4,
                    last: 0x7eff_ffff
                },
                AddressRange {
                    first: 0x8000_0000,
                    last: 0xffff_fffe
                },
            ]
        );
        assert_eq!(
            a.ipv6,
            vec![
                AddressRange { first: 2, last: 2 },
                AddressRange {
                    first: 4,
                    last: u128::MAX - 1
                },
            ]
        );
    }

    #[test]
    fn complement_matches_brute_force_for_overlapping_intervals() {
        let mut seed = 0x95f3_8b21u32;
        for _ in 0..256 {
            let mut excluded = Vec::new();
            for _ in 0..12 {
                seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                let a = (seed >> 24) as u128;
                seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                let b = (seed >> 24) as u128;
                excluded.push(AddressRange {
                    first: a.min(b),
                    last: a.max(b),
                });
            }
            let allowed = complement(excluded.clone(), 255).unwrap();
            for value in 0..=255 {
                assert_eq!(contains(&allowed, value), !contains(&excluded, value));
            }
            assert!(allowed
                .windows(2)
                .all(|pair| pair[0].last + 1 < pair[1].first));
        }
    }

    #[test]
    fn covering_the_entire_address_space_yields_no_permitted_range() {
        assert!(complement(
            vec![AddressRange {
                first: 0,
                last: u128::MAX
            }],
            u128::MAX
        )
        .unwrap()
        .is_empty());
        assert!(complement(
            vec![AddressRange {
                first: 0,
                last: u32::MAX as u128
            }],
            u32::MAX as u128
        )
        .unwrap()
        .is_empty());
    }
}
