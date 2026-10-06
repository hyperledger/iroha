#![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]
//! Torii handler test for zk vote tally convenience endpoint.
#![cfg(all(
    feature = "halo2-dev-tests",
    any(feature = "zk-halo2", feature = "zk-halo2-ipa")
))]
use axum::{extract::State, response::IntoResponse};
use http_body_util::BodyExt as _;
use iroha_core::{
    kura::Kura,
    query::store::LiveQueryStore,
    state::{State as CoreState, World, WorldReadOnly as _},
};
use iroha_core_zk::{hash_vk, test_utils::halo2_fixture_envelope};
use iroha_data_model::prelude::*;
use iroha_data_model::{
    confidential::ConfidentialStatus,
    isi::Grant,
    isi::verifying_keys,
    permission::Permission,
    proof::{VerifyingKeyId, VerifyingKeyRecord},
    zk::BackendTag,
};
use iroha_primitives::json::Json;
use iroha_torii::{NoritoJson, ZkVoteGetTallyRequestDto, handle_v1_zk_vote_tally};
use nonzero_ext::nonzero;
use std::{sync::Arc, time::Duration};
const ACCOUNT_SIGNATORY: &str =
    "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03";
const TALLY_FIXTURE_BACKEND: &str = "halo2/ipa";
const TALLY_FIXTURE_CIRCUIT_ID: &str = "halo2/ipa:tiny-add2inst-public";
#[tokio::test]
async fn vote_tally_handler_returns_finalized_tally() {
    // Build minimal state
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    let mut core_state = CoreState::new_for_testing(World::new(), kura, query);
    core_state
        .edit_zk_for_testing(|zk| zk.halo2.enabled = true)
        .expect("fixture ZK settings install");
    core_state
        .edit_zk_for_testing(|zk| zk.verify_timeout = Duration::ZERO)
        .expect("fixture ZK settings install");
    let mut state = Arc::new(core_state);
    // Seed one finalized election via ISIs
    let header = iroha_data_model::block::BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction();
    let eid = "election-alpha".to_string();
    let owner = AccountId::new(ACCOUNT_SIGNATORY.parse().expect("public key"));
    stx.world
        .executor()
        .clone()
        .execute_instruction(
            &mut stx,
            &owner,
            InstructionBox::from(Register::account(Account::new(owner.clone()))),
        )
        .expect("register owner account");
    let fixture_seed = halo2_fixture_envelope(TALLY_FIXTURE_CIRCUIT_ID, [0; 32]);
    let vk_box = fixture_seed
        .vk_box(TALLY_FIXTURE_BACKEND)
        .expect("vote tally fixture must include VK bytes");
    let vk_commitment = hash_vk(&vk_box);
    let fixture = halo2_fixture_envelope(TALLY_FIXTURE_CIRCUIT_ID, vk_commitment);
    let vk_id = VerifyingKeyId::new(TALLY_FIXTURE_BACKEND, "tally_current");
    let mut vk_record = VerifyingKeyRecord::new(
        1,
        TALLY_FIXTURE_CIRCUIT_ID,
        BackendTag::Halo2IpaPasta,
        "pallas",
        fixture.schema_hash,
        vk_commitment,
    );
    vk_record.vk_len = u32::try_from(vk_box.bytes.len()).expect("VK length fits u32");
    vk_record.max_proof_bytes =
        u32::try_from(fixture.proof_bytes.len()).expect("proof length fits u32");
    vk_record.gas_schedule_id = Some("halo2_default".into());
    vk_record.key = Some(vk_box.clone());
    vk_record.status = ConfidentialStatus::Active;
    let proof_box = fixture.proof_box(TALLY_FIXTURE_BACKEND);
    stx.world
        .executor()
        .clone()
        .execute_instruction(
            &mut stx,
            &owner,
            InstructionBox::from(Grant::account_permission(
                Permission::new(
                    "CanManageParliament".parse().expect("permission id"),
                    Json::new(()),
                ),
                owner.clone(),
            )),
        )
        .expect("grant CanManageParliament");
    stx.world
        .executor()
        .clone()
        .execute_instruction(
            &mut stx,
            &owner,
            InstructionBox::from(Grant::account_permission(
                Permission::new(
                    "CanEnactGovernance".parse().expect("permission id"),
                    Json::new(()),
                ),
                owner.clone(),
            )),
        )
        .expect("grant CanEnactGovernance");
    let report =
        iroha_core_zk::verify_backend_with_timing(TALLY_FIXTURE_BACKEND, &proof_box, Some(&vk_box));
    assert!(report.ok, "vote tally proof must verify: {report:?}");
    stx.world
        .executor()
        .clone()
        .execute_instruction(
            &mut stx,
            &owner,
            InstructionBox::from(Grant::account_permission(
                Permission::new(
                    "CanManageVerifyingKeys"
                        .parse()
                        .expect("manage vk permission id"),
                    Json::new(()),
                ),
                owner.clone(),
            )),
        )
        .expect("grant CanManageVerifyingKeys");
    stx.world
        .executor()
        .clone()
        .execute_instruction(
            &mut stx,
            &owner,
            verifying_keys::RegisterVerifyingKey {
                id: vk_id.clone(),
                record: vk_record,
            }
            .into(),
        )
        .expect("register vote/tally verifying key");
    let create = iroha_data_model::isi::zk::CreateElection {
        election_id: eid.clone(),
        options: 2,
        eligible_root: [0u8; 32],
        start_ts: 0,
        end_ts: 0,
        vk_ballot: vk_id.clone(),
        vk_tally: vk_id.clone(),
        domain_tag: "ballot-domain".to_string(),
    };
    stx.world
        .executor()
        .clone()
        .execute_instruction(&mut stx, &owner, InstructionBox::from(create))
        .unwrap();
    let finalize = iroha_data_model::isi::zk::FinalizeElection {
        election_id: eid.clone(),
        tally: vec![5, 8],
        tally_proof: iroha_data_model::proof::ProofAttachment::new_ref(
            TALLY_FIXTURE_BACKEND.into(),
            proof_box,
            vk_id.clone(),
        ),
    };
    stx.world
        .executor()
        .clone()
        .execute_instruction(&mut stx, &owner, InstructionBox::from(finalize))
        .unwrap();
    stx.apply();
    block
        .commit_world_overlay_for_testing()
        .expect("seed directly verified tally query fixture");
    let source = Arc::get_mut(&mut state).expect("unique tally fixture state");
    let mut config = iroha_core::sumeragi::test_chain::TestChainConfig::new(
        std::mem::take(&mut source.world),
        1,
    );
    config.zk = Some(source.zk_snapshot());
    let chain = iroha_core::sumeragi::test_chain::CertifiedTestChain::start(config)
        .expect("original tally query genesis");
    let state = chain.state().clone();
    let expected_view = state.view();
    let expected_height = u64::try_from(expected_view.height()).expect("height fits u64");
    let expected_hash = expected_view
        .latest_block_hash()
        .map(|hash| hex::encode(hash.as_ref()))
        .expect("committed block hash");
    drop(expected_view);
    // Call Torii handler directly
    let req = ZkVoteGetTallyRequestDto {
        election_id: eid.clone(),
    };
    let resp = handle_v1_zk_vote_tally(State(state.clone()), None, NoritoJson(req))
        .await
        .expect("handler ok")
        .into_response();
    let body = resp
        .into_body()
        .collect()
        .await
        .expect("read body")
        .to_bytes();
    // Parse using Norito JSON
    let v: norito::json::Value = norito::json::from_slice(&body).expect("json parse");
    assert_eq!(
        v.get("finalized").and_then(norito::json::Value::as_bool),
        Some(true)
    );
    assert_eq!(
        v.get("evaluated_block_height")
            .and_then(norito::json::Value::as_u64),
        Some(expected_height)
    );
    assert_eq!(
        v.get("evaluated_block_hash")
            .and_then(norito::json::Value::as_str),
        Some(expected_hash.as_str())
    );
    let tally = v
        .get("tally")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();
    let ints: Vec<u64> = tally.into_iter().filter_map(|x| x.as_u64()).collect();
    assert_eq!(ints, vec![5, 8]);
    let norito_response = handle_v1_zk_vote_tally(
        State(state),
        Some(http::HeaderValue::from_static("application/x-norito")),
        NoritoJson(ZkVoteGetTallyRequestDto { election_id: eid }),
    )
    .await
    .expect("Norito handler response")
    .into_response();
    assert_eq!(
        norito_response.headers().get(http::header::CONTENT_TYPE),
        Some(&http::HeaderValue::from_static("application/x-norito"))
    );
    let bytes = norito_response
        .into_body()
        .collect()
        .await
        .expect("read Norito body")
        .to_bytes();
    let decoded: iroha_torii::ZkVoteGetTallyResponseDto =
        norito::decode_from_bytes(&bytes).expect("decode Norito tally response");
    assert_eq!(decoded.evaluated_block_height, expected_height);
    assert_eq!(decoded.evaluated_block_hash, expected_hash);
    assert!(decoded.finalized);
    assert_eq!(decoded.tally, vec![5, 8]);
}
