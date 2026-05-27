//! Criterion benchmark for the backward chain build at the spec-pinned
//! length of 1024. Single bench group; add more entries if a need emerges.
//!
//!   cargo bench --bench chain

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use nip41::IdentityChain;

fn derive_chain_1024(c: &mut Criterion) {
    let root = [0x42u8; 32];
    c.bench_function("derive(root, 1024)", |b| {
        b.iter(|| {
            let chain = IdentityChain::derive(black_box(&root), black_box(1024)).unwrap();
            black_box(chain);
        })
    });
}

criterion_group!(benches, derive_chain_1024);
criterion_main!(benches);
