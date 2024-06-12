//! Peer utils.

pub type PeerInfo = (PeerName, P2pApiPorts, ExposedKeyPair);
pub type PeerName = String;
pub type P2pApiPorts = [u16; 2];
pub type ExposedKeyPair = (iroha_crypto::PublicKey, iroha_crypto::ExposedPrivateKey);

pub const SERVICE_NAME: &str = "irohad";

pub fn generate_key_pair(base_seed: Option<&[u8]>, extra_seed: &[u8]) -> ExposedKeyPair {
    let (public_key, private_key) = base_seed
        .map_or_else(iroha_crypto::KeyPair::random, |seed| {
            iroha_crypto::KeyPair::from_seed(
                seed.iter().chain(extra_seed).copied().collect::<Vec<_>>(),
                iroha_crypto::Algorithm::default(),
            )
        })
        .into_parts();
    (public_key, iroha_crypto::ExposedPrivateKey(private_key))
}

pub fn generate_peers(
    count: u16,
    key_seed: Option<&[u8]>,
) -> std::collections::BTreeMap<u16, PeerInfo> {
    (0..count)
        .map(|nth| {
            let name = format!("{SERVICE_NAME}{nth}");
            let ports = [super::BASE_PORT_P2P + nth, super::BASE_PORT_API + nth];
            let key_pair = generate_key_pair(key_seed, &nth.to_be_bytes());
            (nth, (name, ports, key_pair))
        })
        .collect()
}

pub fn chain() -> iroha_data_model::ChainId {
    iroha_data_model::ChainId::from(crate::CHAIN_ID)
}

pub fn peer_id(
    name: &str,
    port: u16,
    public_key: iroha_crypto::PublicKey,
) -> iroha_data_model::peer::PeerId {
    iroha_data_model::peer::PeerId::new(
        iroha_primitives::addr::SocketAddrHost {
            host: name.to_owned().into(),
            port,
        }
        .into(),
        public_key,
    )
}

#[allow(single_use_lifetimes)]
pub fn get_trusted_peers<'a>(
    peers: impl Iterator<Item = &'a PeerInfo>,
) -> std::collections::BTreeSet<iroha_data_model::peer::PeerId> {
    peers
        .map(|(service_name, [port_p2p, _], (public_key, _))| {
            peer_id(service_name, *port_p2p, public_key.clone())
        })
        .collect()
}
