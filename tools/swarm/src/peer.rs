//! Peer utils.

pub type PeerInfo = (PeerName, P2pApiPorts, ExposedKeyPair);
pub type PeerName = String;
pub type P2pApiPorts = [u16; 2];
pub type ExposedKeyPair = (iroha_crypto::PublicKey, iroha_crypto::ExposedPrivateKey);

pub const SERVICE_NAME: &str = "irohad";

pub fn generate_key_pair(base_seed: Option<&[u8]>, extra_seed: &[u8]) -> iroha_crypto::KeyPair {
    base_seed.map_or_else(iroha_crypto::KeyPair::random, |base| {
        let seed = base.iter().chain(extra_seed).copied().collect::<Vec<_>>();
        iroha_crypto::KeyPair::from_seed(seed, iroha_crypto::Algorithm::default())
    })
}

pub fn generate_peers(
    count: u16,
    key_seed: Option<&[u8]>,
) -> std::collections::BTreeMap<u16, PeerInfo> {
    (0..count)
        .map(|nth| {
            let (public_key, private_key) =
                generate_key_pair(key_seed, &nth.to_be_bytes()).into_parts();
            (
                nth,
                (
                    format!("{SERVICE_NAME}{nth}"),
                    [super::BASE_PORT_P2P + nth, super::BASE_PORT_API + nth],
                    (public_key, iroha_crypto::ExposedPrivateKey(private_key)),
                ),
            )
        })
        .collect()
}

#[allow(single_use_lifetimes)]
pub fn get_trusted_peers<'a>(
    peers: impl Iterator<Item = &'a PeerInfo>,
) -> std::collections::BTreeSet<iroha_data_model::peer::PeerId> {
    peers
        .map(|(service_name, [port_p2p, _], (public_key, _))| {
            iroha_data_model::peer::PeerId::new(
                iroha_primitives::addr::SocketAddrHost {
                    host: service_name.clone().into(),
                    port: *port_p2p,
                }
                .into(),
                public_key.clone(),
            )
        })
        .collect()
}
