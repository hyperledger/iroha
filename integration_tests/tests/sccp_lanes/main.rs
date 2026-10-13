//! Native SCCP on four production validator processes, with a closed Parliament launch gate.
//!
//! Genuine NPoS registrations precede initialization. An ordinary transaction reaches
//! finality, every peer exposes the same genesis-bound certified SCCP result, and even an
//! authorized proposer cannot substitute a missing qualified Parliament ballot.

use std::{num::NonZeroU64, time::Duration};

use eyre::{Result, ensure, eyre};
use integration_tests::sandbox;
use iroha::{
    client::sccp::SccpFinalityAt,
    crypto::{Algorithm, KeyPair},
    data_model::{
        isi::{governance::ProposeSccpRouteGovernance, sccp::InitializeSccpV1},
        parameter::system::SumeragiNposParameters,
        prelude::*,
        sccp::{
            governance::{
                SccpGovernanceActionV1, SccpGovernanceProposalV1, SccpGovernanceSubjectV1,
                SccpSetParametersActionV1,
            },
            params::SccpParametersV1,
        },
        sumeragi_finality::authenticated_genesis,
        transaction::FeePaymentIntent,
    },
};
use iroha_executor_data_model::permission::sccp::CanProposeSccpRouteGovernance;
use iroha_sccp::v1::{committee::committee_root, finality::verify_certificate};
use iroha_test_network::{NetworkBuilder, init_instruction_registry};
use iroha_test_samples::ALICE_ID;

fn builder() -> NetworkBuilder {
    let epoch = NonZeroU64::new(3_600).unwrap();
    let npos = SumeragiNposParameters {
        epoch_length_blocks: epoch,
        max_validators: 4,
        ..SumeragiNposParameters::default()
    };
    let proposal_permission: Permission = CanProposeSccpRouteGovernance.into();
    NetworkBuilder::new()
        .with_peers(4)
        .with_auto_populated_trusted_peers()
        .with_npos_consensus()
        .with_npos_genesis_bootstrap(1_000_u64.into())
        .with_block_cadence(Duration::from_secs(1))
        .with_genesis_instruction(SetParameter::new(Parameter::Sumeragi(
            SumeragiParameter::EpochLengthBlocks(epoch),
        )))
        .with_genesis_instruction(SetParameter::new(Parameter::Custom(
            npos.into_custom_parameter(),
        )))
        .with_genesis_post_bootstrap_isi(vec![
            InitializeSccpV1 {
                parameters: SccpParametersV1::taira_default(),
                reset_nonce: [0x59; 32],
            }
            .into(),
            Grant::account_permission(proposal_permission, ALICE_ID.clone()).into(),
        ])
        .with_config_layer(|layer| {
            layer
                .write(
                    ["nexus", "storage", "local_budget_bytes"],
                    1_073_741_824_i64,
                )
                .write(
                    ["nexus", "staking", "unbonding_delay_ms"],
                    1_814_400_000_i64,
                )
                .write(["nexus", "staking", "max_slash_bps"], 1_i64)
                .write(["nexus", "fees", "base_fee"], "0")
                .write(["nexus", "fees", "per_byte_fee"], "0")
                .write(["nexus", "fees", "per_instruction_fee"], "0")
                .write(["nexus", "fees", "per_gas_unit_fee"], "0");
        })
}

#[test]
fn four_validators_publish_native_sccp_finality_and_refuse_unqualified_launch() -> Result<()> {
    init_instruction_registry();
    let (network, runtime) = sandbox::start_network_blocking_or_skip(
        builder(),
        stringify!(four_validators_publish_native_sccp_finality_and_refuse_unqualified_launch),
    )?
    .ok_or_else(|| eyre!("native SCCP qualification requires four actual validator processes"))?;
    let result = (|| -> Result<()> {
        runtime.block_on(network.ensure_blocks(1))?;
        ensure!(network.peers().len() == 4);
        let genesis = network.genesis();
        let (epoch, _) = authenticated_genesis(&genesis.0)?.into_parts();
        let keys = epoch
            .committee
            .iter()
            .map(|member| {
                let (algorithm, bytes) = member.validator.public_key().try_to_bytes()?;
                ensure!(algorithm == Algorithm::BlsNormal);
                <[u8; 48]>::try_from(bytes).map_err(|_| eyre!("genesis key width"))
            })
            .collect::<Result<Vec<_>>>()?;
        ensure!(keys.len() == 4);
        let root = committee_root(&keys).ok_or_else(|| eyre!("invalid signed committee"))?;
        let instance = iroha_sumeragi::preimage::instance_id(
            &iroha_core::sumeragi::crypto::BlsCrypto::new(),
            &iroha_sumeragi::types::Hash32(*epoch.network_id.as_bytes()),
            network.chain_id().as_str().as_bytes(),
            iroha_sumeragi::preimage::InstanceKind::Global,
            0,
        )
        .0;
        let client = network.peers()[0].client();
        let before = client.client().get_sumeragi_status()?.committed_height;
        let account = AccountId::new(
            KeyPair::try_from_seed(vec![0x77; 32], Algorithm::Ed25519)?
                .public_key()
                .clone(),
        );
        client.submit(
            Register::account(Account::new(account)),
            FeePaymentIntent::authority(Vec::new(), None),
        )?;
        let after = client.client().get_sumeragi_status()?.committed_height;
        ensure!(
            after > before,
            "ordinary registration must commit a successor"
        );
        runtime.block_on(network.ensure_blocks(after))?;
        let mut original = None;
        for peer in network.peers() {
            let client = peer.client();
            let capabilities = client.sccp().capabilities()?;
            ensure!(capabilities.network_id == *epoch.network_id.as_bytes());
            ensure!(capabilities.consensus_instance == instance);
            ensure!(capabilities.parameters == Some(SccpParametersV1::taira_default()));
            ensure!(!capabilities.parliament_binding_ballot_available);
            let holds = client.sccp().forgery_hold(Default::default())?;
            ensure!(holds.revisions.is_empty() && holds.next.is_none());
            let generation = client.sccp().committee(1)?;
            ensure!(generation.committee_root == root && generation.keys == keys);
            ensure!(
                generation.members.len() == 4 && generation.members.iter().all(Option::is_some)
            );
            ensure!(generation.liable && generation.start_height == 1);
            let certificate = client
                .sccp()
                .finality(SccpFinalityAt::Height(NonZeroU64::new(after).unwrap()))?;
            ensure!(certificate.committee == keys);
            let verified = verify_certificate(
                &instance,
                &certificate.qc,
                &certificate.header,
                &certificate.aggregate_signature,
                &keys,
            )?;
            ensure!(verified.header.height() == after && verified.header.is_active());
            ensure!(verified.header.generation() == 1 && verified.header.committee_root() == root);
            ensure!(verified.qc.signers.count_ones() == 3);
            let certified_result = (certificate.header, verified.qc.block_hash, verified.result);
            if let Some(expected) = &original {
                ensure!(
                    &certified_result == expected,
                    "all peers must certify the same retained block and result"
                );
            } else {
                original = Some(certified_result);
            }
        }
        let rejection = client
            .submit(
                ProposeSccpRouteGovernance {
                    proposal: SccpGovernanceProposalV1 {
                        network_id: epoch.network_id,
                        base_revisions: vec![(SccpGovernanceSubjectV1::Parameters, 0).into()],
                        actions: vec![SccpGovernanceActionV1::SetParameters(
                            SccpSetParametersActionV1 {
                                next: SccpParametersV1::taira_default(),
                            },
                        )],
                    },
                },
                FeePaymentIntent::authority(Vec::new(), None),
            )
            .expect_err("a proposer permission cannot supply the qualified Parliament ballot");
        ensure!(
            format!("{rejection:?}").contains("ParliamentBallotUnavailable"),
            "unexpected rejection: {rejection:?}"
        );
        for peer in network.peers() {
            ensure!(peer.client().sccp().governance_proposals()?.is_empty());
        }
        Ok(())
    })();
    runtime.block_on(network.shutdown());
    result
}
