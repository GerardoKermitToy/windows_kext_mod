use std::{env, fs, path::PathBuf};

fn replace_once(source: &mut String, from: &str, to: &str) {
    assert_eq!(
        source.matches(from).count(),
        1,
        "source anchor changed: {from}"
    );
    *source = source.replacen(from, to, 1);
}

fn main() {
    let path = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap())
        .join("../../driver/src/connection_map.rs");
    println!("cargo:rerun-if-changed={}", path.display());
    let original = fs::read_to_string(path).unwrap();
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());

    for (name, outer, inner, keyed) in [
        ("tree_tree", "tree", "tree", false),
        ("hash_tree", "hash", "tree", false),
        ("tree_hash", "tree", "hash", false),
        ("hash_hash", "hash", "hash", false),
        ("directory_tree", "directory", "tree", false),
        ("sip_sip", "hash", "hash", true),
        ("directory_sip", "directory", "hash", true),
    ] {
        let mut source = original.clone();
        // Share the production Key and Connection types, not lookalike records.
        let start = source
            .find("#[derive(Clone, Copy, PartialEq, PartialOrd, Eq, Ord)]")
            .unwrap();
        let end = source
            .find("/// Compact family-specific key for one remote endpoint.")
            .unwrap();
        source.replace_range(start..end, "use crate::connection_map::Key;\n\n");
        source.insert_str(0, "use alloc::collections::BTreeMap;\n");
        if keyed {
            replace_once(
                &mut source,
                "type FxBuildHasher = BuildHasherDefault<FxHasher>;",
                "type FxBuildHasher = crate::SipBuild;",
            );
        }
        if inner == "tree" {
            replace_once(
                &mut source,
                "    hash_map::{Entry, Values, ValuesMut},",
                "    hash_map,",
            );
            source.insert_str(
                0,
                "use alloc::collections::btree_map::{Entry, Values, ValuesMut};\n",
            );
            replace_once(
                &mut source,
                "type RemoteMap<T> = HashMap<\n    RemoteEndpoint<<T as Connection>::RemoteAddressKey>,\n    ConnectionBucket<T>,\n    FxBuildHasher,\n>;",
                "type RemoteMap<T> = BTreeMap<RemoteEndpoint<<T as Connection>::RemoteAddressKey>, ConnectionBucket<T>>;",
            );
            replace_once(
                &mut source,
                "                if connections.capacity() > 64 && connections.len() < connections.capacity() / 4 {\n                    connections.shrink_to_fit();\n                }\n",
                "",
            );
        }
        let outer_type = match outer {
            "tree" => "BTreeMap<(IpProtocol, u16), RemoteConnections<T>>",
            "hash" => "HashMap<(IpProtocol, u16), RemoteConnections<T>, FxBuildHasher>",
            "directory" => "PortTable<RemoteConnections<T>>",
            _ => unreachable!(),
        };
        replace_once(
            &mut source,
            "(PortTable<RemoteConnections<T>>);",
            &format!("({outer_type});"),
        );
        replace_once(
            &mut source,
            "Self(PortTable::default())",
            "Self(Default::default())",
        );
        if outer == "hash" {
            replace_once(&mut source,
                "        self.0.retain(|_, connections| !connections.is_empty());",
                "        self.0.retain(|_, connections| !connections.is_empty());\n        if self.0.capacity() > 64 && self.0.len() < self.0.capacity() / 4 {\n            self.0.shrink_to_fit();\n        }");
            replace_once(
                &mut source,
                "        self.0.clear();",
                "        self.0 = Default::default();",
            );
        }
        // UDP donor selection is explicit in production and does not depend on
        // index iteration order. Every candidate retains the same regression tests.
        fs::write(out.join(format!("{name}.rs")), source).unwrap();
    }
}
