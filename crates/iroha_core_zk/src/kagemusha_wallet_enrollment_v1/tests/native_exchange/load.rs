//! Native BLS evidence for an actual funded Load with exact retained-output recovery.
//! TODO: Run the pinned StateExecutor capture and installed-wallet qualification.
use super::*;
use crate::kagemusha_wallet_artifacts_v1::producer_inventory::{
    QualifiedReceiptSourceV1, open_pinned_engineering_finality_sources,
};
use crate::kagemusha_wallet_registration_v1::verify_finalized_kagemusha_wallet_registration_v1;
use iroha_crypto::{Algorithm, Hash, HashOf, MerkleProof};
use iroha_data_model::{
    events::EventBox,
    isi::kagemusha_wallet::load_finality::verify_finalized_kagemusha_wallet_load_event_v1,
    sumeragi_finality::{
        SumeragiCommitCertificateV1, SumeragiFinalityProof, VerifiedSumeragiBlock,
    },
};
use iroha_fs::{PrivateDirectory, PublishMode};
use std::collections::{BTreeMap, BTreeSet};

#[path = "load/activation_retention.rs"]
mod activation_retention;
#[path = "load/campaign_tests.rs"]
mod campaign_tests;

const CAPTURE_MAX: usize = 16 << 20;
const ORIGINAL_MAX: usize = 16 << 20;
const HISTORY_MAX: u64 = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CampaignHeights {
    registration: u64,
    activation: u64,
    load: u64,
}

// Both StateExecutor and four-peer owners retain one exact canonical receipt and
// the entire certified prefix. The receipt selects three consecutive wallet stages;
// native verification below authenticates their actual instructions and event.
fn campaign_heights(load: u64) -> CampaignHeights {
    assert!((5..=HISTORY_MAX).contains(&load));
    CampaignHeights {
        registration: load - 2,
        activation: load - 1,
        load,
    }
}

fn capture_heights(rows: &[norito::json::Value], heights: CampaignHeights) {
    assert_eq!(rows.len(), usize::try_from(heights.load - 1).unwrap());
    for (row, height) in rows.iter().zip(2..=heights.load) {
        assert_eq!(row["height"].as_u64(), Some(height));
    }
}

fn fixed<const N: usize>(value: &norito::json::Value) -> [u8; N] {
    let original = value.as_str().unwrap();
    let bytes: [u8; N] = hex::decode(original).unwrap().try_into().unwrap();
    assert_eq!(hex::encode(bytes), original);
    bytes
}
fn raw(value: &norito::json::Value) -> Vec<u8> {
    let original = value.as_str().unwrap();
    let bytes = hex::decode(original).unwrap();
    assert_eq!(hex::encode(&bytes), original);
    bytes
}
fn pinned(path: &Path, maximum: usize, expected: &str) -> Vec<u8> {
    let directory = PrivateDirectory::open_exact(path.parent().unwrap()).unwrap();
    let bytes = directory
        .read(path.file_name().unwrap(), maximum)
        .unwrap()
        .to_vec();
    assert_eq!(sha(&bytes), expected);
    bytes
}
fn selected_json(name: &str, maximum: usize) -> (PathBuf, Vec<u8>, norito::json::Value) {
    let path = selected_path(name);
    let bytes = pinned(&path, maximum, &env_pin(&format!("{name}_SHA256")));
    let json = norito::json::from_slice(&bytes).unwrap();
    (path, bytes, json)
}
fn originals(
    root: &Path,
    manifest: &norito::json::Value,
    field: &str,
    names: &[(String, usize)],
) -> BTreeMap<String, Vec<u8>> {
    let rows = manifest[field].as_array().unwrap();
    assert_eq!(rows.len(), names.len());
    let mut values = BTreeMap::new();
    for row in rows {
        let name = row["name"].as_str().unwrap();
        let maximum = names
            .iter()
            .find(|(candidate, _)| candidate == name)
            .unwrap()
            .1;
        let length = row["bytes"].as_u64().unwrap();
        assert!(length > 0 && length <= maximum as u64);
        let digest = fixed::<32>(&row["sha256"]);
        let bytes = pinned(&root.join(name), maximum, &hex::encode(digest));
        assert_eq!(bytes.len() as u64, length);
        assert!(values.insert(name.to_owned(), bytes).is_none());
    }
    assert_eq!(
        values.keys().collect::<BTreeSet<_>>(),
        names.iter().map(|(name, _)| name).collect()
    );
    values
}
fn shape(names: &[(&str, usize)]) -> Vec<(String, usize)> {
    names
        .iter()
        .map(|(name, bound)| ((*name).to_owned(), *bound))
        .collect()
}

// Missing siblings and exhausted padding have exactly one canonical representation.
fn event_path(
    count: u64,
    index: u32,
    siblings: &[[u8; 32]; 32],
) -> Result<MerkleProof<EventBox>, ()> {
    if count == 0 || count > 1u64 << 32 || u64::from(index) >= count {
        return Err(());
    }
    let (mut width, mut position, mut path) = (count, index, Vec::new());
    for sibling in siblings {
        if width <= 1 {
            if *sibling != [0; 32] {
                return Err(());
            }
            continue;
        }
        if (u64::from(position) ^ 1) < width {
            let hash = Hash::from_marked_bytes(*sibling).ok_or(())?;
            path.push(Some(HashOf::from_untyped_unchecked(hash)));
        } else {
            if *sibling != [0; 32] {
                return Err(());
            }
            path.push(None);
        }
        position >>= 1;
        width = (width >> 1) + (width & 1);
    }
    if width != 1 || position != 0 {
        return Err(());
    }
    Ok(MerkleProof::from_audit_path(index, path))
}
fn require_block(row: &norito::json::Value, block: &VerifiedSumeragiBlock) {
    let certificate = block.block().commit_certificate().unwrap();
    let qc: iroha_sumeragi::message::Qc = decode(certificate.commit_qc());
    let schedule = &block.commitment().schedule;
    assert!(schedule.boundary.is_none());
    assert!(row["authenticated_schedule"]["boundary"].is_null());
    assert_eq!(
        fixed::<32>(&row["authenticated_schedule"]["current"]["context_id_hex"]),
        schedule.current.context_id().unwrap()
    );
    assert_eq!(row["height"].as_u64(), Some(block.height()));
    assert_eq!(
        raw(&row["result_preimage_hex"]),
        certificate.result_preimage()
    );
    assert_eq!(fixed::<32>(&row["result_hash_hex"]), block.result().0);
    assert_eq!(raw(&row["commit_vote_preimage_hex"]), qc.preimage());
    assert_eq!(raw(&row["qc_bitmap_hex"]), qc.signers.as_bytes());
    assert_eq!(
        fixed::<96>(&row["qc_aggregate_signature_hex"]),
        qc.agg_sig.0
    );
    let keys = row["committee_public_keys_hex"].as_array().unwrap();
    let pops = row["committee_proofs_of_possession_hex"]
        .as_array()
        .unwrap();
    assert_eq!(keys.len(), schedule.current.committee.len());
    assert_eq!(pops.len(), keys.len());
    for ((member, key), pop) in schedule.current.committee.iter().zip(keys).zip(pops) {
        let (algorithm, bytes) = member.validator.public_key().try_to_bytes().unwrap();
        assert_eq!(algorithm, Algorithm::BlsNormal);
        assert_eq!(raw(key), bytes);
        assert_eq!(raw(pop), member.proof_of_possession);
    }
}

// Reconstruct input/output membership only from the already verified original.
// A unique direct Register for the installed scheme must have actually succeeded;
// a reported JSON receipt or a second producer-specific original adds no authority.
fn require_registration(
    verified: &VerifiedSumeragiBlock,
    genesis: &SumeragiFinalityVerifier,
    scheme_id: [u8; 32],
    asset: &KagemushaWalletAssetScopeV1,
    reserve: &AccountId,
) {
    use iroha_data_model::{
        query::CommittedTransaction,
        transaction::{Executable, TransactionEntrypoint},
    };
    let block = verified.block();
    let mut selected = None;
    for (input_index, entrypoint) in block.network_entrypoints().enumerate() {
        let TransactionEntrypoint::External(transaction) = entrypoint else {
            continue;
        };
        let Executable::Instructions(instructions) = transaction.instructions() else {
            continue;
        };
        for (instruction_index, instruction) in instructions.iter().enumerate() {
            let Some(instruction) = instruction
                .as_any()
                .downcast_ref::<KagemushaWalletLedgerV1>()
            else {
                continue;
            };
            let KagemushaWalletLedgerActionV1::Register { scheme, .. } = &instruction.action else {
                continue;
            };
            if instruction.scheme != scheme_id {
                continue;
            }
            let scheme = KagemushaWalletSchemeV1::decode_canonical(scheme, &scheme_id).unwrap();
            assert!(
                selected
                    .replace((input_index, instruction_index, scheme))
                    .is_none(),
                "ambiguous matching registration"
            );
        }
    }
    let (input_index, instruction_index, scheme) = selected.expect("actual direct registration");
    let entrypoint = block.network_entrypoint_at(input_index).unwrap().clone();
    let input_index = u32::try_from(input_index).unwrap();
    let (output_index, _) = block.network_output_at(input_index).unwrap();
    let output = block.execution_outputs()[output_index as usize].clone();
    let committed = CommittedTransaction {
        block_hash: block.hash(),
        entrypoint_hash: entrypoint.hash(),
        entrypoint_proof: block.network_input_proof(input_index).unwrap(),
        entrypoint,
        output_hash: HashOf::new(&output),
        output_proof: block.output_proof(output_index).unwrap(),
        output,
    };
    let finalized = verify_finalized_kagemusha_wallet_registration_v1(
        verified,
        &committed,
        genesis.initial_epoch().network_id,
        genesis.chain_id(),
        &scheme,
        asset.asset_digest(),
        instruction_index,
    )
    .unwrap();
    assert_eq!(finalized.height(), verified.height());
    assert_eq!(finalized.asset(), asset);
    assert_eq!(finalized.reserve(), reserve);
}

struct Inputs {
    heights: CampaignHeights,
    receipt: KagemushaWalletLoadReceiptV1,
    receipt_bytes: Vec<u8>,
    blocks: Vec<VerifiedSumeragiBlock>,
    activation_bytes: Vec<u8>,
    event: MerkleProof<EventBox>,
    capture_sha256: String,
    target_sha256: String,
    setup_sha256: String,
}
fn inputs(genesis: &SumeragiFinalityVerifier, installation: InstallationV1) -> Inputs {
    let (setup_path, setup_bytes, setup) =
        selected_json("KAGEMUSHA_NATIVE_LEDGER_SETUP", TARGET_MAX);
    assert_eq!(
        setup["schema"].as_str(),
        Some("iroha.kagemusha.executed-ledger-setup.v1")
    );
    assert_eq!(setup["chain_id"].as_str(), Some(genesis.chain_id()));
    assert_eq!(setup["registration_height"].as_u64(), Some(1));
    assert_eq!(setup["certified_height"].as_u64(), Some(2));
    let setup_originals = originals(
        setup_path.parent().unwrap(),
        &setup,
        "originals",
        &shape(&[
            ("account.norito", 4096),
            ("account-b.norito", 4096),
            ("account-c.norito", 4096),
            ("reserve.norito", 4096),
            ("asset.norito", 4096),
            ("signed-genesis.wire", ORIGINAL_MAX),
            ("genesis-manifest.json", ORIGINAL_MAX),
            ("registration-proof.norito", ORIGINAL_MAX),
            ("capture.json", 1 << 20),
        ]),
    );
    assert_eq!(
        sha(&setup_originals["capture.json"]),
        env_pin("KAGEMUSHA_SIGNED_GENESIS_FIXTURE_SHA256")
    );
    let source: norito::json::Value =
        norito::json::from_slice(&setup_originals["capture.json"]).unwrap();
    let initial: [SumeragiFinalityProof; 2] = decode(&setup_originals["registration-proof.norito"]);
    let (capture_path, capture_bytes, capture) =
        selected_json("KAGEMUSHA_EXECUTED_LOAD_CAPTURE", CAPTURE_MAX);
    for field in ["version", "chain_id", "signed_genesis_wire_hex"] {
        assert_eq!(capture[field], source[field], "{field}");
    }
    assert_eq!(
        raw(&capture["signed_genesis_wire_hex"]),
        setup_originals["signed-genesis.wire"]
    );
    let receipt_bytes = pinned(
        &capture_path.parent().unwrap().join("receipt.norito"),
        KAGEMUSHA_WALLET_LOAD_RECEIPT_MAX_BYTES_V1,
        &env_pin("KAGEMUSHA_EXECUTED_LOAD_RECEIPT_SHA256"),
    );
    let receipt = KagemushaWalletLoadReceiptV1::decode_canonical(&receipt_bytes).unwrap();
    let heights = campaign_heights(receipt.block_height);
    let names = (1..=heights.load)
        .flat_map(|height| {
            [
                (format!("block-{height}.wire"), ORIGINAL_MAX),
                (format!("native-proof-{height}.norito"), ORIGINAL_MAX),
            ]
        })
        .chain([(
            "receipt.norito".to_owned(),
            KAGEMUSHA_WALLET_LOAD_RECEIPT_MAX_BYTES_V1,
        )])
        .collect::<Vec<_>>();
    let frames = originals(
        capture_path.parent().unwrap(),
        &capture,
        "originals",
        &names,
    );
    assert_eq!(frames["receipt.norito"], receipt_bytes);
    let (target_path, target_bytes, target) =
        selected_json("KAGEMUSHA_NATIVE_LOAD_TARGET", TARGET_MAX);
    assert_eq!(target["schema"].as_str(), Some(TARGET_SCHEMA));
    assert_eq!(target["source_pins"], source_pins());
    assert_eq!(
        fixed::<32>(&target["executed_ledger_setup_sha256"]),
        <[u8; 32]>::from(Sha256::digest(&setup_bytes))
    );
    assert_eq!(target["native_chain_id"].as_str(), Some(genesis.chain_id()));
    assert_eq!(
        fixed::<32>(&target["native_instance"]),
        genesis.instance().0
    );
    assert_eq!(
        fixed::<32>(&target["native_initial_epoch_sha256"]),
        <[u8; 32]>::from(Sha256::digest(
            norito::encode_canonical(genesis.initial_epoch()).unwrap()
        ))
    );
    assert_eq!(
        fixed::<32>(&capture["native_target_sha256"]),
        <[u8; 32]>::from(Sha256::digest(&target_bytes))
    );
    assert_eq!(fixed::<32>(&target["scheme_id"]), installation.scheme_id);
    assert_eq!(
        fixed::<32>(&target["manifest_digest"]),
        installation.manifest_digest
    );
    let target_originals = originals(
        target_path.parent().unwrap(),
        &target,
        "files",
        &shape(&[
            ("account.norito", 4096),
            ("asset.norito", 4096),
            (
                "credential.norito",
                KAGEMUSHA_WALLET_CREDENTIAL_MAX_BYTES_V1,
            ),
            ("certificates.norito", 32768),
            ("bootstrap.norito", KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1),
            (
                "activation.norito",
                KAGEMUSHA_WALLET_ACTIVATION_MAX_BYTES_V1,
            ),
            ("issue-load.norito", 4096),
        ]),
    );
    for name in ["account.norito", "asset.norito"] {
        assert_eq!(target_originals[name], setup_originals[name]);
    }
    let account: AccountId = decode(&target_originals["account.norito"]);
    let asset: KagemushaWalletAssetScopeV1 = decode(&target_originals["asset.norito"]);
    let activation = KagemushaWalletActivationV1::decode_canonical(
        &target_originals["activation.norito"],
        &installation.scheme_id,
    )
    .unwrap();
    assert_eq!(activation.asset, asset);
    assert_eq!(
        activation.credential.body.account_digest,
        kagemusha_wallet_account_digest_v1(&account).unwrap()
    );
    assert_eq!(
        activation.credential.to_canonical_bytes().unwrap(),
        target_originals["credential.norito"]
    );
    assert_eq!(
        norito::encode_canonical(&activation.certificates).unwrap(),
        target_originals["certificates.norito"]
    );
    assert_eq!(
        norito::encode_canonical(&activation.bootstrap).unwrap(),
        target_originals["bootstrap.norito"]
    );
    let action: KagemushaWalletLedgerV1 = decode(&target_originals["issue-load.norito"]);
    assert_eq!(
        action,
        KagemushaWalletLedgerV1::new(
            installation.scheme_id,
            KagemushaWalletLedgerActionV1::IssueLoad {
                wallet: activation.credential.body.wallet_id,
                asset: asset.asset_digest(),
                ordinal: 0,
                request_id: LOAD_ID,
                amount: LOAD_AMOUNT,
                charge: None
            }
        )
    );
    assert_eq!(receipt.scheme_id, installation.scheme_id);
    assert_eq!(receipt.wallet_id, activation.credential.body.wallet_id);
    assert_eq!(receipt.asset_digest, asset.asset_digest());
    assert_eq!(
        receipt.payer_account_digest,
        activation.credential.body.account_digest
    );
    assert_eq!(
        (
            receipt.request_id,
            receipt.ordinal,
            receipt.amount,
            receipt.online_charge,
            receipt.charge_quote
        ),
        (LOAD_ID, 0, LOAD_AMOUNT, 0, [0; 32])
    );
    for (name, expected) in [
        ("wallet_id", receipt.wallet_id),
        ("asset_digest", receipt.asset_digest),
        ("payer_account_digest", receipt.payer_account_digest),
        ("request_id", receipt.request_id),
        ("charge_quote", receipt.charge_quote),
    ] {
        assert_eq!(fixed::<32>(&target[name]), expected);
    }
    for (name, expected) in [("ordinal", "0"), ("amount", "100"), ("online_charge", "0")] {
        assert_eq!(target[name].as_str(), Some(expected));
    }
    let rows = capture["blocks"].as_array().unwrap();
    capture_heights(rows, heights);
    let mut native = genesis.clone();
    let mut blocks = Vec::new();
    for height in 1..=heights.load {
        let original = &frames[&format!("native-proof-{height}.norito")];
        let proof: SumeragiFinalityProof = decode(original);
        assert_eq!(proof.height(), height);
        assert_eq!(proof.block_wire, frames[&format!("block-{height}.wire")]);
        if height <= 2 {
            assert_eq!(
                *original,
                norito::encode_canonical(&initial[height as usize - 1]).unwrap()
            );
        }
        let block = native.verify(&proof).unwrap();
        if height == heights.registration {
            require_registration(
                &block,
                genesis,
                installation.scheme_id,
                &asset,
                &decode::<AccountId>(&setup_originals["reserve.norito"]),
            );
        }
        if height == 1 {
            // H1's result attachment differs from the original signed proposal. Native
            // verification above still authenticates the entire executed wire and result;
            // the next proof binds that result through its parent commitment.
            let signed_original = &setup_originals["signed-genesis.wire"];
            let signed =
                iroha_data_model::block::decode_framed_signed_block(signed_original).unwrap();
            assert!(signed.header().is_genesis() && signed.is_resultless_proposal());
            assert_eq!(signed.encode_wire().unwrap(), *signed_original);
            assert_eq!(block.block().hash(), signed.hash());
            assert_eq!(
                block
                    .block()
                    .canonical_resultless_proposal()
                    .unwrap()
                    .encode_wire()
                    .unwrap(),
                *signed_original
            );
        } else {
            require_block(&rows[height as usize - 2], &block);
            blocks.push(block);
        }
    }
    let terminal = blocks.last().unwrap();
    let row = &capture["load"];
    assert_eq!(raw(&row["receipt_frame_hex"]), receipt_bytes);
    assert_eq!(
        raw(&row["receipt_transcript_hex"]),
        receipt.transcript().unwrap()
    );
    assert_eq!(
        fixed::<32>(&row["receipt_digest_hex"]),
        receipt.receipt_digest().unwrap()
    );
    assert_eq!(
        raw(&row["result_preimage_hex"]),
        terminal
            .block()
            .commit_certificate()
            .unwrap()
            .result_preimage()
    );
    let commitment = terminal.execution().event_commitment.as_ref().unwrap();
    assert_eq!(
        fixed::<32>(&row["event_commitment_root_hex"]),
        *commitment.root().as_ref()
    );
    let count = row["event_commitment_count"].as_u64().unwrap();
    assert_eq!(count, commitment.leaf_count().get());
    let index = u32::try_from(row["event_index"].as_u64().unwrap()).unwrap();
    let siblings: [[u8; 32]; 32] = row["event_siblings_hex"]
        .as_array()
        .unwrap()
        .iter()
        .map(fixed::<32>)
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    let event = event_path(count, index, &siblings).unwrap();
    verify_finalized_kagemusha_wallet_load_event_v1(
        terminal,
        &event,
        genesis.initial_epoch().network_id,
        genesis.chain_id(),
        &receipt,
    )
    .unwrap();
    Inputs {
        heights,
        receipt,
        receipt_bytes,
        blocks,
        activation_bytes: target_originals["activation.norito"].clone(),
        event,
        capture_sha256: sha(&capture_bytes),
        target_sha256: sha(&target_bytes),
        setup_sha256: sha(&setup_bytes),
    }
}

fn activation_signed_wire<'a, I>(
    transactions: I,
    scheme: &[u8; 32],
    account_digest: &[u8; 32],
    original: &[u8],
) -> Vec<u8>
where
    I: Iterator<Item = &'a iroha_data_model::transaction::SignedTransaction>,
{
    use iroha_data_model::transaction::Executable;

    let mut selected = None;
    for transaction in transactions {
        let Executable::Instructions(instructions) = transaction.instructions() else {
            continue;
        };
        let [instruction] = instructions.as_ref() else {
            continue;
        };
        let Some(instruction) = instruction
            .as_any()
            .downcast_ref::<KagemushaWalletLedgerV1>()
        else {
            continue;
        };
        if instruction.scheme != *scheme
            || !matches!(&instruction.action, KagemushaWalletLedgerActionV1::Activate(bytes) if bytes == original)
            || kagemusha_wallet_account_digest_v1(transaction.authority()).unwrap()
                != *account_digest
        {
            continue;
        }
        assert!(
            selected.replace(transaction).is_none(),
            "ambiguous exact retained Activate attempts"
        );
    }
    // Select an existing signed original from the already verified block. Native
    // intake still verifies its exact account authority, signature, network, inner
    // bytes and successful certified execution. Installation may precede this block.
    selected
        .expect("exact retained sole-instruction Activate is absent")
        .encode_wire_v1()
        .unwrap()
}

#[test]
fn activation_wire_selects_exact_original_without_block_shape_assumptions() {
    use iroha_data_model::{
        isi::InstructionBox,
        transaction::{FeePaymentIntent, TransactionBuilder},
    };
    let network = iroha_data_model::NetworkId::from_genesis_hash(
        iroha_crypto::HashOf::from_untyped_unchecked(iroha_crypto::Hash::new(
            b"activation wire test",
        )),
    );
    let sign = |seed: u8, at: u64, instructions: Vec<InstructionBox>| {
        let keys =
            iroha_crypto::KeyPair::from_seed(vec![seed; 32], iroha_crypto::Algorithm::Ed25519);
        let authority = iroha_data_model::account::AccountId::new(keys.public_key().clone());
        let mut builder = TransactionBuilder::new(
            network.clone(),
            authority,
            FeePaymentIntent::authority(Vec::new(), None),
        );
        builder.set_creation_time(std::time::Duration::from_millis(at));
        builder
            .with_instructions(instructions)
            .sign(keys.private_key())
    };
    // Typed inner DATA exercises selection only. Real signatures are retained;
    // genuine activation originals and finality remain mandatory in the native owner.
    let scheme = [1; 32];
    let original = vec![5];
    let install = KagemushaWalletLedgerV1::new(
        scheme,
        KagemushaWalletLedgerActionV1::InstallVerifierPack {
            asset: [2; 32],
            manifest_digest: [3; 32],
            pack: vec![4],
        },
    );
    let activate = KagemushaWalletLedgerV1::new(
        scheme,
        KagemushaWalletLedgerActionV1::Activate(original.clone()),
    );
    let installation = sign(95, 1, vec![install.clone().into()]);
    let activation = sign(41, 1, vec![activate.clone().into()]);
    let account = kagemusha_wallet_account_digest_v1(activation.authority()).unwrap();
    let fresh_attempt = sign(41, 2, vec![activate.clone().into()]);
    assert_ne!(
        activation.encode_wire_v1().unwrap(),
        fresh_attempt.encode_wire_v1().unwrap()
    );
    let foreign = sign(
        41,
        1,
        vec![
            iroha_data_model::isi::Log::new(
                iroha_data_model::Level::INFO,
                "foreign instruction".into(),
            )
            .into(),
        ],
    );
    let combined = sign(41, 1, vec![install.into(), activate.clone().into()]);
    let wrong_scheme = sign(
        41,
        1,
        vec![
            KagemushaWalletLedgerV1::new(
                [9; 32],
                KagemushaWalletLedgerActionV1::Activate(original.clone()),
            )
            .into(),
        ],
    );
    let wrong_original = sign(
        41,
        1,
        vec![
            KagemushaWalletLedgerV1::new(scheme, KagemushaWalletLedgerActionV1::Activate(vec![6]))
                .into(),
        ],
    );
    let wrong_owner = sign(42, 1, vec![activate.into()]);
    for accepted in [
        vec![&activation],
        vec![&installation, &activation],
        vec![&activation, &installation],
        vec![&foreign, &installation, &activation, &foreign],
        vec![&wrong_scheme, &wrong_original, &wrong_owner, &activation],
    ] {
        assert_eq!(
            activation_signed_wire(accepted.into_iter(), &scheme, &account, &original),
            activation.encode_wire_v1().unwrap()
        );
    }
    for rejected in [
        vec![],
        vec![&installation],
        vec![&foreign],
        vec![&wrong_scheme],
        vec![&wrong_original],
        vec![&wrong_owner],
        vec![&combined],
        vec![&installation, &foreign],
        vec![&activation, &activation],
        vec![&activation, &fresh_attempt],
    ] {
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| activation_signed_wire(
                rejected.into_iter(),
                &scheme,
                &account,
                &original,
            )))
            .is_err()
        );
    }
}

// Confirm the exact already-executed Activate before the first native Load. No
// transaction, activation proof, ledger result or finality certificate is synthesized.
pub(super) fn confirm_existing_activation(
    wallet: &mut Wallet,
    sources: &Sources,
) -> (Vec<u8>, state::LedgerCommitV1) {
    use state::{LedgerAttemptIngestV1 as Ingest, LedgerAttemptOutcomeV1 as Outcome};

    let (scheme_id, manifest_digest) = sources.qualified.installation();
    let input = inputs(
        &sources.genesis,
        InstallationV1 {
            scheme_id,
            manifest_digest,
        },
    );
    let activation = input
        .blocks
        .iter()
        .find(|block| block.height() == input.heights.activation)
        .unwrap();
    // The actual certified prefix establishes installation before Activate. Select
    // the retained target original without assuming a transaction count or position.
    // Native intake still authenticates authority, signature and successful execution.
    let signed = activation_signed_wire(
        activation.block().external_transactions(),
        &input.receipt.scheme_id,
        &input.receipt.payer_account_digest,
        &input.activation_bytes,
    );
    let transaction = activation
        .block()
        .external_transactions()
        .find(|transaction| transaction.encode_wire_v1().unwrap() == signed)
        .unwrap();
    let entrypoint = *transaction.hash_as_entrypoint().as_ref();
    assert_eq!(
        wallet.retain_activation_attempt(&signed).unwrap(),
        Outcome::Awaiting { entrypoint }
    );
    // One original, whatever the height: the block's own certificate and membership.
    let finality = ledger_finality_original(activation, transaction);
    let Ingest::Outcome(Outcome::Confirmed(confirmed)) = wallet
        .ingest_activation_finality(&signed, &finality)
        .unwrap()
    else {
        panic!("the certified Activate confirms the wallet from one original");
    };
    assert_eq!(confirmed.height, input.heights.activation);
    assert_eq!(confirmed.commit_hash, activation.core_hash().0);
    assert_eq!(
        wallet
            .ingest_activation_finality(&signed, &finality)
            .unwrap(),
        Ingest::Outcome(Outcome::Confirmed(confirmed))
    );
    assert_eq!(
        wallet.activation_attempt_outcome(&signed).unwrap(),
        Outcome::Confirmed(confirmed)
    );
    (signed, confirmed)
}

fn verify_output(
    graph: &QualifiedReceiptSourceV1,
    receipt: &KagemushaWalletLoadReceiptV1,
    bytes: &[u8],
) {
    let retained = KagemushaWalletLoadFinalityV1::decode_canonical(bytes).unwrap();
    assert_eq!(retained.receipt_digest, receipt.receipt_digest().unwrap());
    retained.verify(graph.verifier(), receipt).unwrap();
}
fn put_exact(directory: &PrivateDirectory, name: &str, bytes: &[u8], maximum: usize) {
    assert!(!bytes.is_empty() && bytes.len() <= maximum);
    match directory.read_optional(name, maximum).unwrap() {
        Some(original) => assert_eq!(
            original.as_slice(),
            bytes,
            "retained output differs: {name}"
        ),
        None => directory
            .write_atomic(name, bytes, PublishMode::CreateNew)
            .unwrap(),
    }
}
fn run(resume: bool) {
    let output_path = selected_path("KAGEMUSHA_NATIVE_LOAD_EVIDENCE_OUTPUT");
    if !resume {
        private_dir(&output_path);
    }
    let output = PrivateDirectory::open_exact(&output_path).unwrap();
    // Every invocation independently authenticates the selected native trust root.
    let admission = selected_path("KAGEMUSHA_NATIVE_LOAD_ADMISSION_OUTPUT");
    let (_installed, graph, genesis, _originals) =
        open_pinned_engineering_finality_sources(&admission);
    let installation = InstallationV1 {
        scheme_id: graph.installation().0,
        manifest_digest: graph.installation().1,
    };
    let input = inputs(&genesis, installation);
    let selection = norito::json::to_vec(&norito::json!({
        "schema": "iroha.kagemusha.selected-native-load-production.v1",
        "capture_sha256": (input.capture_sha256), "target_sha256": (input.target_sha256),
        "setup_sha256": (input.setup_sha256), "receipt_sha256": (sha(&input.receipt_bytes)),
        "source_pins": (source_pins()),
    }))
    .unwrap();
    if resume {
        // A missing selected job is lost custody, never an opportunity to adopt new inputs.
        assert_eq!(
            output
                .read("selection.json", TARGET_MAX)
                .unwrap()
                .as_slice(),
            selection
        );
    } else {
        output
            .write_atomic("selection.json", &selection, PublishMode::CreateNew)
            .unwrap();
    }
    let terminal = input.blocks.last().unwrap();
    assert_eq!(terminal.height(), input.heights.load);
    assert_eq!(terminal.height(), input.receipt.block_height);
    let evidence = KagemushaWalletLoadFinalityV1 {
        version: 1,
        receipt_digest: input.receipt.receipt_digest().unwrap(),
        certificate: SumeragiCommitCertificateV1::from_verified(terminal).unwrap(),
        event_proof: input.event,
    };
    let proof = evidence.to_canonical_bytes().unwrap();
    verify_output(&graph, &input.receipt, &proof);
    put_exact(
        &output,
        "receipt.norito",
        &input.receipt_bytes,
        KAGEMUSHA_WALLET_LOAD_RECEIPT_MAX_BYTES_V1,
    );
    put_exact(
        &output,
        "load-finality.norito",
        &proof,
        KAGEMUSHA_WALLET_LOAD_FINALITY_MAX_BYTES_V1,
    );
    let result = norito::json!({
        "schema":"iroha.kagemusha.generated-native-load-finality.v1",
        "scope":"Actual complete native certified prefix through the observed funded Load, successful registration, direct BLS receipt admission and exact evidence recovery. Explicit simulated wallet hardware; no ABC, settlement, deployment or phone qualification.",
        "capture_sha256":(input.capture_sha256),"target_sha256":(input.target_sha256),"setup_sha256":(input.setup_sha256),
        "receipt_sha256":(sha(&input.receipt_bytes)),"receipt_bytes":(input.receipt_bytes.len()),
        "finality_sha256":(sha(&proof)),"finality_bytes":(proof.len()),"source_pins":(source_pins()),
        "registration_height":(input.heights.registration),"activation_height":(input.heights.activation),
        "receipt_height":(input.heights.load),"native_bls_finality":true,"existing_only_recovery":true,
    });
    // Deterministic completion bytes also survive replay; any existing discrepancy refuses.
    put_exact(
        &output,
        "generated.json",
        &norito::json::to_vec(&result).unwrap(),
        TARGET_MAX,
    );
    output.sync().unwrap();
    eprintln!(
        "GENUINE_LOAD_FINALITY receipt_sha256={} finality_sha256={} exact_reopen=true",
        sha(&input.receipt_bytes),
        sha(&proof)
    );
}

#[test]
#[ignore = "requires actual signed catalog and independently pinned StateExecutor funded Load capture"]
fn export_native_load_finality_from_executed_history() {
    run(false);
}
#[test]
#[ignore = "requires same pinned capture and existing selected evidence custody"]
fn resume_native_load_finality_from_executed_history() {
    run(true);
}

#[test]
fn captured_block_requires_original_native_result_envelope() {
    use iroha_data_model::sumeragi_finality::test_fixtures::NativeFinalityFixture;

    let fixture = NativeFinalityFixture::new();
    let block = fixture
        .verifier()
        .verify_retained_decision(fixture.latest())
        .unwrap();
    let certificate = block.block().commit_certificate().unwrap();
    let qc: iroha_sumeragi::message::Qc = decode(certificate.commit_qc());
    let schedule = &block.commitment().schedule;
    let keys: Vec<_> = schedule
        .current
        .committee
        .iter()
        .map(|member| hex::encode(member.validator.public_key().try_to_bytes().unwrap().1))
        .collect();
    let pops: Vec<_> = schedule
        .current
        .committee
        .iter()
        .map(|member| hex::encode(&member.proof_of_possession))
        .collect();
    let mut row = norito::json!({
        "height": (block.height()),
        "result_preimage_hex": (hex::encode(certificate.result_preimage())),
        "result_hash_hex": (hex::encode(block.result().0)),
        "commit_vote_preimage_hex": (hex::encode(qc.preimage())),
        "qc_bitmap_hex": (hex::encode(qc.signers.as_bytes())),
        "qc_aggregate_signature_hex": (hex::encode(qc.agg_sig.0)),
        "committee_public_keys_hex": keys,
        "committee_proofs_of_possession_hex": pops,
        "authenticated_schedule": {
            "current": {"context_id_hex": (hex::encode(schedule.current.context_id().unwrap()))},
            "boundary": (norito::json::Value::Null),
        },
    });
    require_block(&row, &block);
    row.as_object_mut().unwrap().insert(
        "result_preimage_hex".into(),
        hex::encode(block.commitment().preimage().unwrap()).into(),
    );
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| require_block(&row, &block)))
            .is_err()
    );
}

#[test]
fn event_path_refuses_out_of_range_missing_and_noncanonical_padding() {
    let zero = [[0u8; 32]; 32];
    assert!(event_path(1, 0, &zero).is_ok());
    assert!(event_path(0, 0, &zero).is_err());
    assert!(event_path((1u64 << 32) + 1, 0, &zero).is_err());
    assert!(event_path(1, 1, &zero).is_err());
    assert!(event_path(2, 0, &zero).is_err());
    let mut noncanonical = zero;
    noncanonical[31] = *Hash::new(b"unused padding").as_ref();
    assert!(event_path(1, 0, &noncanonical).is_err());
    let mut odd = zero;
    odd[1] = *Hash::new(b"real sibling").as_ref();
    assert!(event_path(3, 2, &odd).is_ok());
    odd[0] = *Hash::new(b"absent odd sibling").as_ref();
    assert!(event_path(3, 2, &odd).is_err());
}
#[test]
fn exact_output_publication_replays_and_refuses_substitution() {
    let root = qualification_root().join("genuine-load-output-tests");
    fs::create_dir_all(&root).unwrap();
    let temp = tempfile::tempdir_in(&root).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    }
    let directory = PrivateDirectory::open_exact(temp.path()).unwrap();
    put_exact(&directory, "receipt.norito", b"exact bounded DATA", 64);
    put_exact(&directory, "receipt.norito", b"exact bounded DATA", 64);
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| put_exact(
            &directory,
            "receipt.norito",
            b"changed DATA",
            64
        )))
        .is_err()
    );
    assert_eq!(
        directory.read("receipt.norito", 64).unwrap().as_slice(),
        b"exact bounded DATA"
    );
}

#[test]
fn original_manifest_refuses_role_length_pin_and_duplicate_changes() {
    let root = qualification_root().join("genuine-load-manifest-tests");
    fs::create_dir_all(&root).unwrap();
    let temp = tempfile::tempdir_in(&root).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    }
    let directory = PrivateDirectory::open_exact(temp.path()).unwrap();
    put_exact(&directory, "receipt.norito", b"exact", 64);
    let row = norito::json!({"name":"receipt.norito","bytes":5,"sha256":(sha(b"exact"))});
    let manifest = norito::json!({"originals":(vec![row.clone()])});
    let names = shape(&[("receipt.norito", 64)]);
    assert_eq!(
        originals(temp.path(), &manifest, "originals", &names)["receipt.norito"],
        b"exact"
    );
    for (field, value) in [
        ("name", norito::json!("foreign.norito")),
        ("bytes", norito::json!(65)),
        ("bytes", norito::json!(4)),
        ("sha256", norito::json!(hex::encode([7u8; 32]))),
    ] {
        let mut altered = row.clone();
        altered.as_object_mut().unwrap().insert(field.into(), value);
        let value = norito::json!({"originals":(vec![altered])});
        assert!(
            std::panic::catch_unwind(|| originals(temp.path(), &value, "originals", &names))
                .is_err()
        );
    }
    let duplicate = norito::json!({"originals":(vec![row.clone(),row])});
    let twice = shape(&[("receipt.norito", 64), ("other.norito", 64)]);
    assert!(
        std::panic::catch_unwind(|| originals(temp.path(), &duplicate, "originals", &twice))
            .is_err()
    );
}
