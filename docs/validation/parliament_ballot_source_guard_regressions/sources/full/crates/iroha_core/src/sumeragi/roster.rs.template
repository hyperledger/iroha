//! The initial validator roster: the authenticated subset of the configured trusted peers.

use iroha_model_base::peer::PeerId;
use std::collections::BTreeSet;

/// Build the initial validator topology as the authenticated subset of trusted peers.
///
/// Every returned validator is a trusted peer with a BLS-normal key and an
/// explicit, valid proof of possession. An empty PoP map therefore yields an
/// empty validator roster, while PoPs for keys outside the trusted-peer set are
/// ignored. The result is deduplicated and canonically ordered by [`PeerId`].
pub fn filter_validators_from_trusted(
    tp: &iroha_config::parameters::actual::TrustedPeers,
) -> Vec<PeerId> {
    let mut baseline: BTreeSet<PeerId> = BTreeSet::new();
    let iter = std::iter::once(tp.myself.clone()).chain(tp.others.clone());
    for peer in iter {
        let pk = peer.id().public_key();
        if !crate::crypto_util::is_bls_normal_public_key(pk) {
            iroha_logger::warn!(?pk, "excluding peer: validator identity must be BLS-normal");
            continue;
        }
        baseline.insert(PeerId::new(pk.clone()));
    }
    let mut validators = BTreeSet::new();
    let mut missing = 0usize;
    for peer_id in &baseline {
        let pk = peer_id.public_key();
        let Some(pop) = tp.pops.get(pk) else {
            missing = missing.saturating_add(1);
            continue;
        };
        if let Err(error) = iroha_crypto::bls_normal_pop_verify(pk, pop) {
            iroha_logger::warn!(?pk, ?error, "invalid PoP; excluding peer from consensus");
            continue;
        }
        validators.insert(peer_id.clone());
    }
    if missing > 0 {
        iroha_logger::info!(
            missing,
            baseline = baseline.len(),
            pops = tp.pops.len(),
            validators = validators.len(),
            "excluding trusted peers without validator PoPs from consensus roster"
        );
    }
    iroha_logger::info!(
        validators = validators.len(),
        configured_peers = tp.others.len().saturating_add(1),
        pops = tp.pops.len(),
        "resolved validator roster from trusted peers"
    );
    validators.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::filter_validators_from_trusted;
    use iroha_config::parameters::actual::TrustedPeers;
    use iroha_crypto::{Algorithm, KeyPair, PublicKey, bls_normal_pop_prove};
    use iroha_data_model::peer::Peer;
    use iroha_model_base::peer::PeerId;
    use std::collections::BTreeMap;

    fn bls_key(seed: &[u8]) -> KeyPair {
        KeyPair::try_from_seed(seed.to_vec(), Algorithm::BlsNormal)
            .expect("derive BLS validator fixture")
    }

    fn peer(key: &KeyPair, port: u16) -> Peer {
        Peer::new(
            format!("127.0.0.1:{port}")
                .parse()
                .expect("fixture peer address"),
            key.public_key().clone(),
        )
    }

    fn trusted_peers(
        myself: &KeyPair,
        others: &[&KeyPair],
        pops: BTreeMap<PublicKey, Vec<u8>>,
    ) -> TrustedPeers {
        TrustedPeers {
            myself: peer(myself, 21_000),
            others: others
                .iter()
                .enumerate()
                .map(|(index, key)| {
                    peer(
                        key,
                        21_001_u16
                            .checked_add(u16::try_from(index).expect("fixture peer index"))
                            .expect("fixture peer port"),
                    )
                })
                .collect(),
            pops,
        }
    }

    #[test]
    fn validator_filter_requires_explicit_pops_even_when_map_is_empty() {
        let local = bls_key(b"validator-filter-empty-local");
        let other = bls_key(b"validator-filter-empty-other");
        let trusted = trusted_peers(&local, &[&other], BTreeMap::new());

        assert!(filter_validators_from_trusted(&trusted).is_empty());
    }

    #[test]
    fn validator_filter_returns_only_trusted_bls_peers_with_valid_pops() {
        let local = bls_key(b"validator-filter-valid-local");
        let eligible = bls_key(b"validator-filter-valid-other");
        let missing = bls_key(b"validator-filter-missing-pop");
        let invalid = bls_key(b"validator-filter-invalid-pop");
        let observer = KeyPair::try_from_seed(
            b"validator-filter-ed25519-observer".to_vec(),
            Algorithm::Ed25519,
        )
        .expect("derive non-validator fixture");
        let pop_only = bls_key(b"validator-filter-pop-only");
        let pops = BTreeMap::from([
            (
                local.public_key().clone(),
                bls_normal_pop_prove(local.private_key()).expect("local validator PoP"),
            ),
            (
                eligible.public_key().clone(),
                bls_normal_pop_prove(eligible.private_key()).expect("other validator PoP"),
            ),
            (invalid.public_key().clone(), Vec::new()),
            (
                pop_only.public_key().clone(),
                bls_normal_pop_prove(pop_only.private_key()).expect("untrusted key PoP"),
            ),
        ]);
        let trusted = trusted_peers(&local, &[&eligible, &missing, &invalid, &observer], pops);
        let mut expected = vec![
            PeerId::new(local.public_key().clone()),
            PeerId::new(eligible.public_key().clone()),
        ];
        expected.sort();

        assert_eq!(filter_validators_from_trusted(&trusted), expected);
    }

    #[test]
    fn validator_filter_never_synthesizes_pop_only_keys() {
        let local = bls_key(b"validator-filter-uncredentialed-local");
        let pop_only = bls_key(b"validator-filter-untrusted-pop");
        let trusted = trusted_peers(
            &local,
            &[],
            BTreeMap::from([(
                pop_only.public_key().clone(),
                bls_normal_pop_prove(pop_only.private_key()).expect("untrusted key PoP"),
            )]),
        );

        assert!(filter_validators_from_trusted(&trusted).is_empty());
    }
}
