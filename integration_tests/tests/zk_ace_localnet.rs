//! Taira-shaped local-node fail-closed coverage for the disabled ZK-ACE
//! privacy-transfer candidate.
#![cfg(feature = "zk-stark")]
use eyre::{Result, WrapErr as _, ensure, eyre};
use integration_tests::sandbox;
use iroha::{
    client::Client,
    data_model::{
        asset::AssetBalanceScope,
        prelude::{AssetDefinitionId, QueryBuilderExt},
        privacy::{
            PRIVACY_ZK_ACE_POLICY_INITIAL_EPOCH_V1, PrivacyCompiledProfileResultV1,
            PrivacyCompiledProfileUnavailableReasonV1, PrivacyPolicyDigestV1, PrivacyPolicyIdV1,
            PrivacyProtocolIdV1, PrivacyZkAcePolicyLifecycleV1, PrivacyZkAcePolicyRecordV1,
        },
        query::block::prelude::FindBlocks,
        transaction::FeePaymentIntent,
    },
};
use iroha_core_privacy::privacy_profiles::{
    CompiledPrivacyProfileErrorV1, compiled_privacy_profile_snapshot_result_v1,
    compiled_privacy_profile_v1,
};
use iroha_model_base::domain::DomainId;
use iroha_model_base::metadata::Metadata;
use iroha_test_network::{NetworkBuilder, init_instruction_registry};
use iroha_test_samples::{ALICE_ID, ALICE_KEYPAIR, BOB_ID};
use std::{
    num::NonZeroU32,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use zk_ace_prover::{
    ZkAcePrivacyActionBuildErrorV1, ZkAcePrivacyActionTransactionContextV1, ZkAcePrivacyTransferV1,
    ZkAcePrivacyWitnessV1, build_signed_zk_ace_privacy_transfer_v1,
};

const TEST_NAME: &str = "zk_ace_privacy_transfer_fails_closed_taira_localnet";
const PROTOCOL: PrivacyProtocolIdV1 = PrivacyProtocolIdV1::ZkAcePqAuthorizationV1;

fn no_fee() -> FeePaymentIntent {
    FeePaymentIntent::authority(Vec::new(), None)
}

fn require_test_network_feature(feature: &str) -> Result<()> {
    let enabled = std::env::var("TEST_NETWORK_IROHAD_FEATURES")
        .ok()
        .is_some_and(|value| {
            value
                .split([',', ' ', '\t', '\n'])
                .any(|item| item.trim() == feature)
        });
    ensure!(
        enabled,
        "{TEST_NAME}: TEST_NETWORK_IROHAD_FEATURES must include `{feature}`"
    );
    Ok(())
}

fn asset_definition_id() -> AssetDefinitionId {
    AssetDefinitionId::derive_from_components(
        DomainId::try_new("wonderland", "universal").expect("default domain"),
        "zkace_typed".parse().expect("asset name"),
    )
}

fn canonical_genesis_hash(client: &Client) -> Result<[u8; 32]> {
    let blocks = client
        .query(FindBlocks)
        .execute_all()
        .wrap_err("query canonical genesis block")?;
    let genesis = blocks
        .iter()
        .filter(|block| block.header().prev_block_hash().is_none())
        .collect::<Vec<_>>();
    ensure!(
        genesis.len() == 1,
        "expected exactly one genesis block, got {}",
        genesis.len()
    );
    let hash = *genesis[0].header().hash().as_ref();
    ensure!(hash != [0; 32], "canonical genesis hash is zero");
    Ok(hash)
}

fn witness(seed: u8) -> ZkAcePrivacyWitnessV1 {
    ZkAcePrivacyWitnessV1::try_new(
        [seed; 32],
        [seed.wrapping_add(1); 32],
        [seed.wrapping_add(2); 32],
    )
    .expect("valid localnet witness")
}

fn policy(witness: &ZkAcePrivacyWitnessV1) -> PrivacyZkAcePolicyRecordV1 {
    PrivacyZkAcePolicyRecordV1::new(
        PrivacyPolicyIdV1::new([0x41; 32]),
        witness.identity_commitment_v1(),
        PrivacyPolicyDigestV1::new([0x42; 32]),
        PRIVACY_ZK_ACE_POLICY_INITIAL_EPOCH_V1,
        asset_definition_id(),
        vec![ALICE_ID.clone()],
        PrivacyZkAcePolicyLifecycleV1::Active,
    )
    .expect("valid governed policy")
}

#[test]
fn zk_ace_privacy_transfer_fails_closed_taira_localnet() -> Result<()> {
    require_test_network_feature("zk-stark")?;
    init_instruction_registry();

    ensure!(
        compiled_privacy_profile_v1(PROTOCOL)
            == Err(CompiledPrivacyProfileErrorV1::EngineUnavailable {
                protocol_id: PROTOCOL,
            }),
        "ZK-ACE unexpectedly became governance-available"
    );
    ensure!(
        compiled_privacy_profile_snapshot_result_v1(PROTOCOL)
            == PrivacyCompiledProfileResultV1::Unavailable(
                PrivacyCompiledProfileUnavailableReasonV1::EngineUnavailable,
            ),
        "local ZK-ACE capability result is not the exact fail-closed status"
    );

    let builder = NetworkBuilder::new()
        .with_peers(4)
        .with_auto_populated_trusted_peers()
        .with_permissioned_consensus();
    let Some((network, _runtime)) = sandbox::start_network_blocking_or_skip(builder, TEST_NAME)?
    else {
        return Ok(());
    };
    let mut client_builder = network.client().client().to_builder();
    client_builder.add_transaction_nonce = true;
    let client = client_builder.build()?;

    let row = client
        .get_privacy_capabilities()
        .wrap_err("query fail-closed ZK-ACE capability")?
        .protocols
        .into_iter()
        .find(|row| row.protocol_id == PROTOCOL)
        .ok_or_else(|| eyre!("ZK-ACE capability row missing"))?;
    ensure!(
        row.compiled_profile
            == PrivacyCompiledProfileResultV1::Unavailable(
                PrivacyCompiledProfileUnavailableReasonV1::EngineUnavailable,
            ),
        "network exposed an unexpected ZK-ACE compiled profile: {:?}",
        row.compiled_profile
    );
    ensure!(
        row.activation.is_none(),
        "unavailable ZK-ACE unexpectedly has an activation: {:?}",
        row.activation
    );

    let witness = witness(0x11);
    let transfer = ZkAcePrivacyTransferV1::try_new(
        policy(&witness),
        ALICE_ID.clone(),
        BOB_ID.clone(),
        AssetBalanceScope::Global,
        19,
    )
    .wrap_err("construct governed ZK-ACE transfer")?;
    let creation_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .wrap_err("system clock before Unix epoch")?;
    let genesis_hash = canonical_genesis_hash(&client)?;
    let build_error = match build_signed_zk_ace_privacy_transfer_v1(
        ZkAcePrivacyActionTransactionContextV1 {
            network_id: *client.network_id(),
            authority: ALICE_ID.clone(),
            creation_time,
            time_to_live: Some(Duration::from_secs(3_600)),
            nonce: NonZeroU32::new(1),
            fee_payment: no_fee(),
            metadata: Metadata::default(),
        },
        transfer,
        witness,
        genesis_hash,
        ALICE_KEYPAIR.private_key(),
    ) {
        Ok(_) => {
            return Err(eyre!(
                "disabled ZK-ACE production builder admitted a transfer"
            ));
        }
        Err(error) => error,
    };
    ensure!(
        matches!(
            &build_error,
            ZkAcePrivacyActionBuildErrorV1::CompiledProfileUnavailable
        ),
        "ZK-ACE builder rejected for the wrong reason: {build_error:?}"
    );
    Ok(())
}
