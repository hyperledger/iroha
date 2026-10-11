//! Genesis generation, materialization, validation, and signing commands.
use crate::{Outcome, RunArgs};
use clap::Subcommand;
use color_eyre::eyre::eyre;
use iroha_genesis::RawGenesisTransaction;
use std::io::{BufWriter, Write};

/// Check the signed scheduling parameters against the manifest's consensus mode.
///
/// # Errors
/// Returns an error when NPoS parameters disagree with the consensus mode or the initial epoch
/// cannot contain its committed beacon anchor and pulse.
pub fn ensure_genesis_schedule_matches_consensus(
    manifest: &RawGenesisTransaction,
) -> color_eyre::Result<()> {
    manifest.validate_mode_specific_consensus_parameters()
}

/// Check that a nonempty genesis topology is an exact supported committee.
///
/// The ordered BLS roster of this topology is validator generation zero.
///
/// # Errors
/// Returns an error when the topology is not an exact `3f + 1` committee or repeats a peer.
pub fn ensure_genesis_topology_is_generation_zero(
    manifest: &RawGenesisTransaction,
) -> color_eyre::Result<()> {
    manifest.validate_genesis_topology()
}

#[cfg(test)]
fn complete_test_genesis_builder(
    builder: iroha_genesis::GenesisBuilder,
) -> iroha_genesis::GenesisBuilder {
    builder.with_sumeragi_context_parameters(
        iroha_data_model::block::consensus::SumeragiGenesisContextParameters::recommended(),
    )
}

#[cfg(test)]
/// Complete test genesis builders with the required signed Sumeragi context.
pub trait CompleteTestGenesisBuilder {
    /// Install the required signed context for a deterministic fixture.
    fn complete_for_test(self) -> Self;
    /// Install the supplied topology and the required signed context.
    fn set_topology_for_test(self, topology: Vec<iroha_genesis::GenesisTopologyEntry>) -> Self;
}

#[cfg(test)]
impl CompleteTestGenesisBuilder for iroha_genesis::GenesisBuilder {
    fn complete_for_test(self) -> Self {
        complete_test_genesis_builder(self)
    }

    fn set_topology_for_test(self, topology: Vec<iroha_genesis::GenesisTopologyEntry>) -> Self {
        complete_test_genesis_builder(self.set_topology(topology))
    }
}

#[cfg(test)]
mod authority_tests {
    use super::*;
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_data_model::parameter::{
        Parameter,
        system::{SumeragiConsensusMode, SumeragiNposParameters},
    };
    use iroha_genesis::{GenesisBuilder, GenesisTopologyEntry};
    use iroha_model_base::chain::ChainId;
    use iroha_model_base::peer::PeerId;
    use std::{num::NonZeroU64, path::PathBuf};

    fn test_topology(seed_prefix: u8, count: u8) -> Vec<GenesisTopologyEntry> {
        let mut topology = (0_u8..count)
            .map(|index| {
                let key = KeyPair::try_from_seed(
                    vec![seed_prefix.wrapping_add(index); 32],
                    Algorithm::BlsNormal,
                )
                .expect("derive deterministic genesis test validator");
                let pop = iroha_crypto::bls_normal_pop_prove(key.private_key())
                    .expect("derive deterministic genesis test PoP");
                GenesisTopologyEntry::new(PeerId::new(key.public_key().clone()), pop)
            })
            .collect::<Vec<_>>();
        topology.sort_by(|left, right| left.peer.cmp(&right.peer));
        topology
    }

    #[test]
    fn genesis_topology_is_generation_zero_only_as_an_exact_committee() {
        let manifest = GenesisBuilder::new_without_executor(
            ChainId::from("generation-zero-topology"),
            PathBuf::from("."),
        )
        .set_topology_for_test(test_topology(0x30, 4))
        .build_raw()
        .expect("complete generation-zero manifest");
        ensure_genesis_topology_is_generation_zero(&manifest)
            .expect("an exact 3f+1 topology is generation zero");
        let short = GenesisBuilder::new_without_executor(
            ChainId::from("generation-zero-short-topology"),
            PathBuf::from("."),
        )
        .set_topology_for_test(test_topology(0x30, 3))
        .build_raw()
        .expect("complete short manifest");
        assert!(ensure_genesis_topology_is_generation_zero(&short).is_err());
    }

    #[test]
    fn genesis_epoch_requires_room_for_committed_beacon_authority() {
        for length in [1, 2, 3] {
            let npos_parameters = SumeragiNposParameters {
                epoch_length_blocks: NonZeroU64::new(length).unwrap(),
                evidence_horizon_blocks: length,
                slashing_delay_blocks: length,
                ..SumeragiNposParameters::default()
            };
            let manifest = GenesisBuilder::new_without_executor(
                ChainId::from("initial-beacon-window"),
                PathBuf::from("."),
            )
            .append_parameter(Parameter::Custom(npos_parameters.into_custom_parameter()))
            .append_parameter(Parameter::Sumeragi(
                iroha_data_model::parameter::system::SumeragiParameter::EpochLengthBlocks(
                    NonZeroU64::new(length).unwrap(),
                ),
            ))
            .set_topology_for_test(test_topology(0x70, 4))
            .build_raw()
            .expect("complete schedule manifest")
            .with_consensus_mode(SumeragiConsensusMode::Npos);
            let result = ensure_genesis_schedule_matches_consensus(&manifest);
            if length < 3 {
                assert!(
                    result
                        .expect_err("missing committed beacon anchor")
                        .to_string()
                        .contains("epoch_length_blocks >= 3")
                );
            } else {
                result.expect("the initial epoch reserves its committed beacon anchor");
            }
        }
    }
}
mod embed_pop;
mod generate;
mod materialize;
mod normalize;
mod npos;
mod prepared;
pub mod profile;
mod sign;
#[cfg(test)]
pub use iroha_deploy::genesis::staging::bind_and_sign_staged_sumeragi_context;
pub use iroha_deploy::genesis::staging::staged_signed_sumeragi_context_hashes;
#[cfg(test)]
pub use sign::{prepared_native_test_chain, tests::native_genesis_fixture_with_instructions};
mod validate;
#[cfg(test)]
pub use iroha_deploy::genesis::generate_default;
pub use iroha_deploy::genesis::{ConsensusPolicy, validate_consensus_mode};
pub use npos::ensure_npos_parameters;
pub use profile::{
    GenesisProfile, PUBLIC_NEXUS_CHAIN_ID, PUBLIC_XOR_ALIAS, ProfileDefaults,
    TAIRA_XOR_ASSET_DEFINITION_ID, parse_vrf_seed_hex, profile_defaults, profile_requires_npos,
    profile_uses_public_xor, reject_retired_public_chain_id, resolve_vrf_seed,
};
fn require_native_wire_protocol(manifest: &RawGenesisTransaction) -> color_eyre::Result<()> {
    let expected = u32::from(iroha_data_model::sumeragi::PROTOCOL_VERSION);
    if manifest.wire_protocol_version() != expected {
        return Err(eyre!(
            "fresh genesis must advertise wire_protocol_version = {expected}; legacy plural and downgrade protocol shapes are prohibited"
        ));
    }
    Ok(())
}
#[derive(Subcommand)]
pub enum Args {
    Sign(sign::Args),
    Generate(generate::Args),
    /// Materialize an incomplete source template with its explicit NPoS XOR selection
    Materialize(materialize::Args),
    /// Validate a genesis JSON file and report invalid identifiers
    Validate(validate::Args),
    /// Verify one exact bound-manifest/signed-genesis/signer/hash bundle
    ValidatePrepared(prepared::Args),
    /// Embed one or more PoPs into a genesis JSON manifest (inline `topology` entries carrying `pop_hex`)
    EmbedPop(embed_pop::Args),
    /// Expand a genesis manifest and show the final ordered transactions
    Normalize(normalize::Args),
}
impl<T: Write> RunArgs<T> for Args {
    fn run(self, writer: &mut BufWriter<T>) -> Outcome {
        match self {
            Args::Sign(args) => args.run(writer),
            Args::Generate(args) => args.run(writer),
            Args::Materialize(args) => args.run(writer),
            Args::Validate(args) => args.run(writer),
            Args::ValidatePrepared(args) => args.run(writer),
            Args::EmbedPop(args) => args.run(writer),
            Args::Normalize(args) => args.run(writer),
        }
    }
}
