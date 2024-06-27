use iroha_data_model::{
    domain::{Domain, DomainId},
    isi::Register,
};
use test_network::{wait_for_genesis_committed, NetworkBuilder};

#[test]
fn all_peers_submit_genesis() {
    multiple_genesis_peers(4, 4, 13_800);
}

#[test]
fn multiple_genesis_4_peers_3_genesis() {
    multiple_genesis_peers(4, 3, 13_820);
}

#[test]
fn multiple_genesis_4_peers_2_genesis() {
    multiple_genesis_peers(4, 2, 13_840);
}

fn multiple_genesis_peers(n_peers: u32, n_genesis_peers: u32, port: u16) {
    let (_rt, network, client) = NetworkBuilder::new(n_peers, Some(port))
        .with_genesis_peers(n_genesis_peers)
        .create_with_runtime();
    wait_for_genesis_committed(&network.clients(), 0);

    let domain_id: DomainId = "foo".parse().expect("Valid");
    let create_domain = Register::domain(Domain::new(domain_id));
    client
        .submit_blocking(create_domain)
        .expect("Failed to register domain");
}
