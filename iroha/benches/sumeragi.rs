use criterion::*;
use iroha::{crypto::KeyPair, peer::PeerId, sumeragi::NetworkTopology};

const N_PEERS: usize = 255;

fn get_n_peers(n: usize) -> Vec<PeerId> {
    (0..n)
        .map(|i| PeerId {
            address: format!("127.0.0.{}", i),
            public_key: KeyPair::generate()
                .expect("Failed to generate KeyPair.")
                .public_key,
        })
        .collect()
}

fn sort_peers(criterion: &mut Criterion) {
    let mut network_topology = NetworkTopology::new(&get_n_peers(N_PEERS), None, 1)
        .init()
        .expect("Failed to initialize topology.");
    criterion.bench_function("sort_peers", |b| {
        b.iter(|| network_topology.sort_peers(Some([0u8; 32])));
    });
}

criterion_group!(benches, sort_peers);
criterion_main!(benches);
