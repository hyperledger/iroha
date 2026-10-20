//! Real Core scheduled invocations and Commit-QC proof authentication.
//! Compiled fixed-argument contract callbacks have separate Core execution tests.

use super::*;
use iroha_core::{
    state::World,
    sumeragi::{
        finality::{build_checkpoint, build_proof},
        test_chain::{CertifiedTestChain, TestChainConfig},
    },
};
use iroha_data_model::{Registrable, isi::Unregister, trigger::action::TimeTriggerRetryPolicy};
use iroha_version::EncodeVersioned;

struct Fixture {
    chain: CertifiedTestChain,
    original: SignedTransaction,
    checkpoint: SumeragiFinalityCheckpoint,
    proofs: Vec<SumeragiFinalityProof>,
}

impl Fixture {
    fn new(reject: bool) -> Self {
        let key = KeyPair::from_seed(vec![0x51; 32], Algorithm::Ed25519);
        let authority = AccountId::new(key.public_key().clone());
        let world = World::with([], [Account::new(authority.clone()).build(&authority)], []);
        let mut chain = CertifiedTestChain::start(TestChainConfig::new(world, 1_000)).unwrap();
        chain.commit_at(1_001, vec![]);
        let checkpoint = build_checkpoint(&chain.state().view(), 2).unwrap();
        let body: InstructionBox = if reject {
            Unregister::domain(
                iroha_model_base::domain::DomainId::try_new("absent_scheduled", "universal").unwrap(),
            ).into()
        } else {
            Log::new(iroha_data_model::Level::INFO, "actual scheduled execution".into()).into()
        };
        let action = TriggerAction::new(
            vec![body], Repeats::Exactly(1), authority,
            TimeEventFilter::new(ExecutionTime::Schedule(
                TimeSchedule::starting_at(Duration::from_millis(1_003))
                    .with_period(Duration::from_millis(5)),
            )),
        ).unwrap().with_retry_policy(TimeTriggerRetryPolicy {
            max_retries: NonZeroU32::new(1).unwrap(),
            retry_after_ms: NonZeroU64::new(5).unwrap(),
        }).unwrap();
        let original = chain.sign(&key, [Register::trigger(Trigger::new("fixture".parse().unwrap(), action)).into()], 1_002);
        assert_eq!(chain.commit_at(1_002, vec![original.clone()]), vec![true]);
        chain.commit_at(1_003, vec![]);
        if reject {
            chain.commit_at(1_007, vec![]);
            chain.commit_at(1_008, vec![]);
        }
        let last = if reject { 6 } else { 4 };
        let proofs = (2..=last).map(|height| build_proof(&chain.state().view(), height).unwrap()).collect();
        Self { chain, original, checkpoint, proofs }
    }

    fn verify(&self, original: &[u8], id: &str, proofs: &[SumeragiFinalityProof]) -> PyResult<json::Value> {
        let (projection, _) = authenticate(
            original, id, &json::to_json(proofs).unwrap(), self.chain.network_id(),
            self.checkpoint.chain_id(), &self.checkpoint.encode_canonical().unwrap(),
        )?;
        json::from_json(&projection).map_err(refusal)
    }

    fn result(&self) -> json::Value {
        self.verify(&self.original.encode_versioned(), "fixture", &self.proofs).unwrap()
    }
}

#[test]
fn genuine_scheduled_output_binds_original_activation_authority_and_internal_route() {
    let fixture = Fixture::new(false);
    let result = fixture.result();
    assert_eq!(result["proof_kind"].as_str(), Some("scheduled-time-v1"));
    assert_eq!(result["terminal"].as_str(), Some("applied"));
    assert_eq!(result["registered_at_height"].as_u64(), Some(3));
    assert_eq!(result["registered_at_ms"].as_u64(), Some(1_002));
    assert_eq!(result["authority"], json::to_value(fixture.original.authority()).unwrap());
    assert_eq!(result["execution_route"], norito::json!({
        "kind": "internal", "root_scope": "Global", "dataspace_id": 0, "lane_id": null,
    }));
    assert!(result.get("transaction_hash").is_none());
    let rows = result["outcomes"].as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["block_height"].as_u64(), Some(4));
    assert_eq!(rows[0]["result_ok"].as_bool(), Some(true));
    assert_eq!(rows[0]["output"]["kind"].as_str(), Some("time"));
}

#[test]
fn genuine_retry_chain_is_complete_and_exhausts_only_its_native_budget() {
    let fixture = Fixture::new(true);
    let result = fixture.result();
    assert_eq!(result["terminal"].as_str(), Some("exhausted"));
    let rows = result["outcomes"].as_array().unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0]["block_height"].as_u64(), Some(4));
    assert_eq!(rows[1]["block_height"].as_u64(), Some(6));
    assert!(rows.iter().all(|row| row["result_ok"].as_bool() == Some(false)));
    assert_ne!(rows[0]["execution_call_hash"], rows[1]["execution_call_hash"]);
    let pending = fixture.verify(&fixture.original.encode_versioned(), "fixture", &fixture.proofs[..2]).unwrap();
    assert_eq!(pending["terminal"].as_str(), Some("pending"));
    assert!(pending["outcomes"].as_array().unwrap().is_empty());
}

#[test]
fn scheduled_proof_rejects_foreign_original_id_mutation_replay_and_missing_prefix() {
    let fixture = Fixture::new(true);
    let bytes = fixture.original.encode_versioned();
    assert!(fixture.verify(&bytes, "foreign", &fixture.proofs).is_err());
    let mut altered = bytes.clone();
    altered[0] ^= 1;
    assert!(fixture.verify(&altered, "fixture", &fixture.proofs).is_err());
    let mut extra = bytes.clone();
    extra.push(0);
    assert!(fixture.verify(&extra, "fixture", &fixture.proofs).is_err());
    let mut gap = fixture.proofs.clone();
    gap.remove(2);
    assert!(fixture.verify(&bytes, "fixture", &gap).is_err());
    let mut duplicate = fixture.proofs.clone();
    duplicate.insert(3, duplicate[2].clone());
    assert!(fixture.verify(&bytes, "fixture", &duplicate).is_err());
    let mut substituted = fixture.proofs.clone();
    let last = substituted.last_mut().unwrap();
    let index = last.block_wire.len() / 2;
    last.block_wire[index] ^= 1;
    assert!(fixture.verify(&bytes, "fixture", &substituted).is_err());
    let late = build_checkpoint(&fixture.chain.state().view(), 4).unwrap();
    assert!(authenticate(
        &bytes, "fixture", &json::to_json(&fixture.proofs[2..]).unwrap(), fixture.chain.network_id(),
        late.chain_id(), &late.encode_canonical().unwrap(),
    ).is_err(), "a later trusted tip cannot replace original activation and retry history");
}
