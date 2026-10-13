//! Async signed approval proof reads bind exact private roots, bodies and bounded responses.

use super::*;
use crate::{
    client::evidence_http_tests::{client_with_base_url, mark_data_model_compatible},
    http::{HttpTransport, TransportFuture, TransportRequest},
    http_default::DefaultHttpTransport,
};
use iroha_data_model::{
    asset::{AssetBalanceScope, AssetId},
    permission::Permissions,
    sumeragi_amx::{AmxDebitApprovalProofV1, AmxDebitApprovalV1},
    sumeragi_finality::{
        WorldStateElementKindV1, WorldStateSnapshotEntryV1, WorldStateSnapshotV1,
        test_fixtures::NativeFinalityFixture, world_state_value_hash_v1,
    },
};
use std::sync::{Arc, Mutex};

#[derive(Debug)]
struct Transport {
    response: Mutex<Option<Response<Vec<u8>>>>,
    requests: Mutex<Vec<TransportRequest>>,
}
impl HttpTransport for Transport {
    fn send_blocking(&self, _: TransportRequest) -> Result<Response<Vec<u8>>> {
        panic!("approval proof reader must use the owned async transport")
    }
    fn send(&self, request: TransportRequest) -> TransportFuture<'_> {
        Box::pin(async move {
            self.requests.lock().unwrap().push(request);
            self.response
                .lock()
                .unwrap()
                .take()
                .ok_or_else(|| eyre!("unexpected repeated proof read"))
        })
    }
}

#[tokio::test(flavor = "current_thread")]
async fn amx_approval_async_read_authenticates_exact_body_and_rejects_stale_or_wrong_terms() {
    let mut client = client_with_base_url("http://approval.invalid/provider/v1/".parse().unwrap());
    let parent = client.network_id;
    let ds = iroha_model_base::topology::DataSpaceId::new(7);
    let mut native = NativeFinalityFixture::start_with_scope(
        "sdk-amx-bank",
        iroha_data_model::block::consensus::SumeragiRootScope::Dataspace {
            parent_network_id: parent,
            dataspace_id: ds,
        },
    );
    client.network_id = native.network_id();
    client.chain = native.chain_id().parse().unwrap();
    let owner = AccountId::new(
        KeyPair::from_seed(vec![99; 32], Algorithm::Ed25519)
            .public_key()
            .clone(),
    );
    let approval = AmxDebitApprovalV1 {
        global_network: parent,
        participant_network: native.network_id(),
        participant_instance: native.verifier().instance().0,
        dataspace: ds,
        transaction_id: [87; 32],
        debited_asset: AssetId::with_scope(
            "6TEAJqbb8oEPmLncoNiMRbLEK6tw".parse().unwrap(),
            owner.clone(),
            AssetBalanceScope::Dataspace(ds),
        ),
    };
    let permissions = Permissions::from([approval.permission().unwrap()]);
    let mut entries = vec![];
    for account in [&owner, &client.account] {
        entries.push(WorldStateSnapshotEntryV1 {
            field_id: "world.accounts".into(),
            kind: WorldStateElementKindV1::Table,
            key_hash: Some(world_state_value_hash_v1(account).unwrap()),
            value_hash: Hash::new(b"synthetic account original"),
        });
    }
    entries.push(WorldStateSnapshotEntryV1 {
        field_id: "world.asset_definitions".into(),
        kind: WorldStateElementKindV1::Table,
        key_hash: Some(world_state_value_hash_v1(approval.debited_asset.definition()).unwrap()),
        value_hash: Hash::new(b"synthetic asset original"),
    });
    entries.push(WorldStateSnapshotEntryV1 {
        field_id: "world.account_permissions".into(),
        kind: WorldStateElementKindV1::Table,
        key_hash: Some(world_state_value_hash_v1(&client.account).unwrap()),
        value_hash: world_state_value_hash_v1(&permissions).unwrap(),
    });
    entries
        .sort_by(|a, b| (&a.field_id, a.kind, a.key_hash).cmp(&(&b.field_id, b.kind, b.key_hash)));
    let schema = Hash::new(b"independently qualified AMX schema");
    let proof = AmxDebitApprovalProofV1 {
        world: WorldStateSnapshotV1 {
            schema_hash: schema,
            entries,
        },
        relay_permissions: permissions,
    };
    let block = native.block_with_submitted_work(native.next_header());
    let certificate = native.certify_with_world_root(block, proof.world.root().unwrap());
    let verified = native
        .verifier()
        .verify_retained_decision(&certificate)
        .unwrap();
    let block = native.block_with_submitted_work(native.next_header());
    let later_certificate = native.certify_with_world_root(block, Hash::new(b"later bank cut"));
    let later = native
        .verifier()
        .verify_retained_decision(&later_certificate)
        .unwrap();
    for (code, media, wrong_terms, stale_proof, success) in [
        (200, APPLICATION_NORITO, false, false, true),
        (200, APPLICATION_NORITO, true, false, false),
        (200, APPLICATION_NORITO, false, true, false),
        (404, APPLICATION_NORITO, false, false, false),
        (200, APPLICATION_JSON, false, false, false),
    ] {
        let transport = Arc::new(Transport {
            response: Mutex::new(Some(
                Response::builder()
                    .status(code)
                    .header("content-type", media)
                    .body(norito::encode_canonical(&proof).unwrap())
                    .unwrap(),
            )),
            requests: Mutex::new(vec![]),
        });
        let client = client
            .clone()
            .with_test_http_transport(DefaultHttpTransport::from_shared(transport.clone()));
        mark_data_model_compatible(&client);
        let mut selected = approval.clone();
        if wrong_terms {
            selected.transaction_id[0] ^= 1;
        }
        let selected_block = if stale_proof { &later } else { &verified };
        let result = client
            .get_amx_debit_approval_state_async(&selected, &client.account, schema, selected_block)
            .await;
        assert_eq!(result.is_ok(), success);
        let requests = transport.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        let request = &requests[0];
        assert_eq!(request.method, HttpMethod::POST);
        assert_eq!(
            request.url.path(),
            format!(
                "/provider/v1/amx/debit-approval/{}",
                selected_block.height()
            )
        );
        assert_eq!(request.body, norito::encode_canonical(&selected).unwrap());
        assert_eq!(
            request.max_response_bytes,
            iroha_data_model::sumeragi_amx::approval_proof::MAX_AMX_DEBIT_APPROVAL_PROOF_BYTES_V1
        );
        for name in [
            "x-iroha-account",
            "x-iroha-signature",
            "x-iroha-timestamp-ms",
            "x-iroha-nonce",
        ] {
            assert!(
                request.headers.iter().any(
                    |(key, value)| key.as_str().eq_ignore_ascii_case(name) && !value.is_empty()
                )
            );
        }
    }
}
