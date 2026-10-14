//! One signed-genesis native consensus-configuration fingerprint.
//!
//! This commits native protocol, complete initial epoch authority and explicit signed chain
//! parameters. It does not claim to fingerprint local queues, resource budgets or transport.

use iroha_crypto::Hash;
use iroha_data_model::block::SignedBlock;

/// Authenticate signed genesis and fingerprint the exact native consensus configuration.
///
/// # Errors
/// Rejects invalid signed genesis, omitted/duplicated explicit chain parameters or invalid
/// native parameter geometry. No retired adapter configuration or implicit fallback is used.
pub fn consensus_configuration_fingerprint(
    genesis: &SignedBlock,
) -> Result<Hash, crate::execution_attempt::ExecutionAttemptError<String>> {
    iroha_data_model::sumeragi_finality::consensus_configuration_fingerprint(genesis).map_err(
        |error| {
            crate::execution_attempt::genesis_read_attempt_error(error, |error| error.to_string())
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn actual_signed_genesis_fingerprint_changes_with_source_and_rejects_tampering() {
        use crate::sumeragi::test_chain::{CertifiedTestChain, TestChainConfig};
        let mut a =
            CertifiedTestChain::start(TestChainConfig::new(crate::state::World::new(), 1_000))
                .unwrap();
        let b = CertifiedTestChain::start(TestChainConfig::new(crate::state::World::new(), 2_000))
            .unwrap();
        let genesis = a.committed(1);
        assert_eq!(
            consensus_configuration_fingerprint(genesis.block()).unwrap(),
            iroha_data_model::sumeragi_finality::consensus_configuration_fingerprint(
                genesis.block()
            )
            .unwrap(),
        );
        assert_ne!(
            consensus_configuration_fingerprint(genesis.block()).unwrap(),
            consensus_configuration_fingerprint(b.committed(1).block()).unwrap()
        );
        a.commit(Vec::new());
        assert!(consensus_configuration_fingerprint(a.committed(2).block()).is_err());
        let mut tampered = genesis.block().as_ref().clone();
        let foreign =
            iroha_crypto::KeyPair::from_seed(vec![0xC9; 32], iroha_crypto::Algorithm::Ed25519);
        let signature = iroha_data_model::block::BlockSignature::new(
            0,
            iroha_crypto::SignatureOf::new(foreign.private_key(), &tampered.header()),
        );
        tampered
            .replace_signatures(
                iroha_data_model::block::BlockSignatures::try_from_iter([signature])
                    .expect("at most 31 block signatures"),
            )
            .unwrap();
        assert!(consensus_configuration_fingerprint(&tampered).is_err());
    }
}
