//! Byte-exact conformance for IdentityChain::derive against the
//! harness JSON vectors.

use nip41::IdentityChain;
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Deserialize)]
struct Vectors {
    root_secret: String,
    chain_length: usize,
    generations: Vec<Generation>,
}

#[derive(Deserialize)]
struct Generation {
    index: usize,
    internal_key: String,
    npub: String,
    nsec: String,
}

fn load() -> Vectors {
    let path: PathBuf = [
        env!("CARGO_MANIFEST_DIR"),
        "..",
        "harness",
        "vectors",
        "nip41-test-vectors.json",
    ]
    .iter()
    .collect();
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("could not read {}: {e}", path.display()));
    serde_json::from_str(&raw).expect("vectors JSON well-formed")
}

#[test]
fn derive_matches_json_vectors() {
    let v = load();
    let mut root = [0u8; 32];
    hex::decode_to_slice(&v.root_secret, &mut root).unwrap();

    let chain = IdentityChain::derive(&root, v.chain_length).unwrap();
    assert_eq!(chain.length(), v.chain_length);

    for g in &v.generations {
        assert_eq!(chain.npub(g.index), g.npub, "npub[{}]", g.index);
        assert_eq!(
            chain.internal_xonly(g.index),
            g.internal_key,
            "internal_key[{}]",
            g.index
        );

        let exported = chain.export_nsec(g.index).unwrap();
        assert_eq!(hex::encode(exported.as_ref()), g.nsec, "nsec[{}]", g.index);
    }
}
