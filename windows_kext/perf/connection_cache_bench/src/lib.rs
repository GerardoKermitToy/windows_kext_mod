#![cfg(test)]
#![allow(dead_code, unused_imports)]
#![deny(unsafe_op_in_unsafe_fn)]

extern crate alloc;

mod allocations;
mod bench;
#[path = "../../../driver/src/connection.rs"]
mod connection;
#[path = "../../../driver/src/connection_map.rs"]
mod connection_map;
#[path = "../../../driver/src/port_table.rs"]
mod port_table;
mod workload;

use siphasher::sip::SipHasher13;
use std::hash::BuildHasher;

#[derive(Default)]
struct SipBuild;

impl BuildHasher for SipBuild {
    type Hasher = SipHasher13;

    fn build_hasher(&self) -> Self::Hasher {
        // Fixed for reproducibility only. A keyed kernel deployment needs an
        // unpredictable per-load key obtained before packet classification.
        SipHasher13::new_with_keys(0x6148_c9e7_f03b_285d, 0x94ad_7136_0ec2_5bf8)
    }
}

mod tree_tree {
    include!(concat!(env!("OUT_DIR"), "/tree_tree.rs"));
}
mod hash_tree {
    include!(concat!(env!("OUT_DIR"), "/hash_tree.rs"));
}
mod tree_hash {
    include!(concat!(env!("OUT_DIR"), "/tree_hash.rs"));
}
mod hash_hash {
    include!(concat!(env!("OUT_DIR"), "/hash_hash.rs"));
}
mod directory_tree {
    include!(concat!(env!("OUT_DIR"), "/directory_tree.rs"));
}
mod sip_sip {
    include!(concat!(env!("OUT_DIR"), "/sip_sip.rs"));
}
mod directory_sip {
    include!(concat!(env!("OUT_DIR"), "/directory_sip.rs"));
}
