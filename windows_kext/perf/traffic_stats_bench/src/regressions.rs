use super::*;

fn check_candidate<C: Candidate>() {
    let events = generate_workload(20_000, 777, WORKLOAD_SEED);
    let expected = export::reference(&events);
    let mut candidate = C::new();
    for event in &events {
        candidate.update(event);
    }
    assert_eq!(export::decode(&candidate.drain_wire()), expected);
}

#[test]
fn btree_exact_totals_and_wire() {
    check_candidate::<BTreeCandidate>();
}
#[test]
fn swiss_fx_exact_totals_and_wire() {
    check_candidate::<FastHashCandidate>();
}
#[test]
fn swiss_sip_exact_totals_and_wire() {
    check_candidate::<SipHashCandidate>();
}
#[test]
fn linear_exact_totals_and_wire() {
    check_candidate::<OpenCandidate>();
}
#[test]
fn sorted_vec_exact_totals_and_wire() {
    check_candidate::<SortedCandidate>();
}
#[test]
fn dense_index_exact_totals_and_wire() {
    check_candidate::<DenseCandidate>();
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct CollisionKey(u64);
impl Hash for CollisionKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_u64(0);
    }
}

fn collision_check<M: Default + StatsMap<CollisionKey>>() {
    let mut map = M::default();
    for key in 0..500 {
        map.update(CollisionKey(key), true, key + 1);
        map.update(CollisionKey(key), false, 2 * key + 3);
    }
    assert_eq!(map.len(), 500);
    let output: BTreeMap<_, _> = map.into_pairs().collect();
    assert_eq!(output.len(), 500);
    for key in 0..500 {
        assert_eq!(
            output[&CollisionKey(key)],
            Counter {
                transmitted_bytes: key + 1,
                received_bytes: 2 * key + 3
            }
        );
    }
}

#[test]
fn distinct_keys_with_identical_hashes_are_not_merged() {
    collision_check::<HashBrownStore<CollisionKey, FastBuildHasher>>();
    collision_check::<HashBrownStore<CollisionKey, SipBuildHasher>>();
    collision_check::<OpenAddressMap<CollisionKey>>();
    collision_check::<alternatives::DenseStore<CollisionKey>>();
}

#[test]
fn empty_drains_produce_no_packets() {
    assert!(BTreeCandidate::new().drain_wire().is_empty());
    assert!(FastHashCandidate::new().drain_wire().is_empty());
    assert!(SipHashCandidate::new().drain_wire().is_empty());
    assert!(OpenCandidate::new().drain_wire().is_empty());
    assert!(SortedCandidate::new().drain_wire().is_empty());
    assert!(DenseCandidate::new().drain_wire().is_empty());
}

#[test]
fn detached_snapshots_and_later_updates_do_not_overlap() {
    let events = generate_workload(10_000, 200, WORKLOAD_SEED);
    let mut active = FastHashCandidate::new();
    for event in &events[..5000] {
        active.update(event);
    }
    let detached = mem::replace(&mut active, FastHashCandidate::new());
    for event in &events[5000..] {
        active.update(event);
    }
    assert_eq!(
        export::decode(&detached.drain_wire()),
        export::reference(&events[..5000])
    );
    assert_eq!(
        export::decode(&active.drain_wire()),
        export::reference(&events[5000..])
    );
}

#[test]
fn v4_wire_header_and_counter_endianness() {
    let key = Key4 {
        local_ip: [192, 0, 2, 1],
        local_port: 0x1234,
        remote_ip: [198, 51, 100, 2],
        remote_port: 0x5678,
    };
    let mut map = BTreeStore::default();
    map.update(key, true, 0x0102030405060708);
    map.update(key, false, 0x1112131415161718);
    let bytes = export::serialize(map, 6).unwrap();
    assert_eq!(&bytes[..10], &[5, 33, 0, 0, 0, 6, 1, 0, 0, 0]);
    assert_eq!(
        &bytes[10..22],
        &[192, 0, 2, 1, 0x34, 0x12, 198, 51, 100, 2, 0x78, 0x56]
    );
    assert_eq!(&bytes[22..30], &[8, 7, 6, 5, 4, 3, 2, 1]);
    assert_eq!(
        &bytes[30..38],
        &[0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11]
    );
}

#[test]
fn v6_wire_uses_full_u32_count() {
    let mut map = HashBrownStore::<Key6, FastBuildHasher>::default();
    let mut rng = Rng::new(WORKLOAD_SEED);
    for id in 0..66_000 {
        map.update(make_v6_key(id, true, &mut rng), true, 1);
    }
    let bytes = export::serialize(map, 6).unwrap();
    assert_eq!(u32::from_le_bytes(bytes[6..10].try_into().unwrap()), 66_000);
    assert_eq!(bytes.len(), 10 + 66_000 * 52);
}

#[test]
fn linear_updates_at_growth_threshold_do_not_reallocate() {
    let mut map = OpenAddressMap::<CollisionKey>::default();
    for id in 0..10 {
        map.update(CollisionKey(id), true, 1);
    }
    let capacity = map.capacity();
    for _ in 0..100 {
        map.update(CollisionKey(0), true, 1);
    }
    assert_eq!(map.capacity(), capacity);
    assert_eq!(map.len(), 10);
}

#[test]
#[should_panic]
fn malformed_wire_count_is_rejected() {
    export::decode(&[vec![5, 5, 0, 0, 0, 6, 1, 0, 0, 0]]);
}
