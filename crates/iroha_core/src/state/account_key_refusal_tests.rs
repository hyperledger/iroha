//! Real Core upload and governance DTO readers preserve canonical account/table refusal.

use std::fmt::Debug;

use super::{
    GovernanceLockCustody, GovernanceLockRecord, GovernanceLocksForReferendum,
    GovernanceSlashEntry, GovernanceSlashLedger, SmartContractCodeUploadKey,
};
use iroha_allocation::AllocationBudget;
use iroha_crypto::Hash;
use iroha_data_model::{
    account::AccountId, asset::AssetDefinitionId, smart_contract::ContractArtifactId,
};
use iroha_model_base::{domain::DomainId, topology::DataSpaceId};
use iroha_test_samples::ALICE_ID;
use norito::{
    DecodeLimits,
    core::{
        DecodeAttemptErrorKind, DecodeBudgetContext, DecodeResourceError, classify_decode_attempt,
        reserve_decode_btree_allocation, with_decode_limits_measured,
    },
    json::{self, JsonKeyCodec as _, JsonObjectKeyOwned as _},
};

fn limits(bytes: usize) -> DecodeLimits {
    DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, bytes, usize::MAX)
}

fn check_original_refusal<T: Debug>(
    source: &str,
    literal: &str,
    read: impl Fn(&str) -> Result<T, json::Error>,
    check_value: impl Fn(&T),
    preceding_admissions: impl Fn() -> Result<(), norito::Error>,
    first_admission: impl Fn() -> Result<(), norito::Error>,
    invalid_context: &str,
) {
    let pointer = source.as_ptr();
    let (complete, usage) = with_decode_limits_measured(limits(usize::MAX), || read(source));
    check_value(&complete.expect("complete genuine Core JSON reader"));
    let complete_demand = usage.total_allocated_bytes();
    assert!(complete_demand > 0);
    // Admit only the measured canonical planning prefix before the selected
    // table/key checkpoint. The complete operation still uses its real DTO reader.
    let (prefix_result, prefix_usage) =
        with_decode_limits_measured(limits(usize::MAX), &preceding_admissions);
    prefix_result.expect("genuine canonical prefix before the selected admission");
    let prefix = prefix_usage.total_allocated_bytes();
    assert!(prefix < complete_demand);
    let (expected, _) = with_decode_limits_measured(limits(prefix), || {
        preceding_admissions()?;
        first_admission()
    });
    let expected = expected.unwrap_err().decode_resource_error().unwrap();
    let DecodeResourceError::TotalAllocationExceeded { attempted, limit } = expected else {
        panic!("canonical selected admission must report its exact quota demand");
    };
    assert_eq!(limit, u64::try_from(prefix).unwrap());
    assert!(attempted > limit);
    let malformed = source.replacen(literal, "not-an-I105-account", 1);
    let (invalid, invalid_usage) =
        with_decode_limits_measured(limits(usize::MAX), || read(&malformed));
    let invalid = invalid.unwrap_err();
    assert!(matches!(invalid, json::Error::Message(_)));
    assert!(!invalid.is_decode_resource_limit());
    let context_limit = complete_demand
        .checked_add(usize::try_from(attempted).unwrap())
        .unwrap()
        .checked_add(invalid_usage.total_allocated_bytes())
        .unwrap();
    let pool = AllocationBudget::new(DecodeBudgetContext::allocation_layout().size());
    let original = DecodeBudgetContext::try_new_owned(limits(context_limit), &pool).unwrap();
    let baseline = pool.reserved_bytes();
    // The original pool owns this decode counter owner. Ordinary map return graphs
    // are not claimed to have physical admission by these JSON decoder controls.
    let before = original.consumed_allocated_bytes();
    let mut observed = None;
    let refusal=original.with(||norito::with_decode_limits_scope(limits(prefix),||{
        classify_decode_attempt(||{
            let error=read(source).expect_err("original finite Core operation must refuse");
            let json::Error::ScopedDecodeResource(origin)=&error else {
                panic!("Core account-key reader must preserve its original scoped refusal: {error:?}");
            };
            observed=Some(origin.clone());
            Err::<(),_>(error.into_core_error())
        })
    })).unwrap_err();
    assert_eq!(refusal.kind(), DecodeAttemptErrorKind::EnclosingLimit);
    let error = refusal.into_error();
    assert_eq!(error.decode_resource_error(), Some(expected));
    let norito::Error::ScopedDecodeResource(returned) = error else {
        panic!("same Core operation must return its original observer");
    };
    assert_eq!(returned, observed.unwrap());
    drop(returned);
    assert_eq!(pool.reserved_bytes(), baseline);
    let after_refusal = original.consumed_allocated_bytes();
    // Canonical counters charge the outer owner before the narrow inner refusal.
    assert_eq!(after_refusal - before, attempted);
    let retry = original
        .with(|| read(source))
        .expect("same source and original context retry");
    check_value(&retry);
    assert_eq!(
        original.consumed_allocated_bytes() - after_refusal,
        u64::try_from(complete_demand).unwrap()
    );
    drop(retry);
    assert_eq!(pool.reserved_bytes(), baseline);
    let (raw, _) = with_decode_limits_measured(limits(prefix), || read(source));
    let raw = raw.unwrap_err().into_core_error();
    assert_eq!(
        raw.decode_resource_error(),
        Some(expected),
        "Core account-key reader must preserve original unscoped refusal fields"
    );
    assert!(!matches!(raw, norito::Error::ScopedDecodeResource(_)));
    let invalid = original
        .with(|| {
            classify_decode_attempt(|| {
                Err::<(), _>(read(&malformed).unwrap_err().into_core_error())
            })
        })
        .unwrap_err();
    assert_eq!(invalid.kind(), DecodeAttemptErrorKind::Invalid);
    assert!(invalid.into_error().to_string().contains(invalid_context));
    assert_eq!(source.as_ptr(), pointer);
    drop(original);
    assert_eq!(pool.reserved_bytes(), 0);
}

// This is checkpoint calibration using the same canonical object/entry owners,
// not an alternate DTO decoder. Neither visitor consumes a returned record.
fn governance_prefix<V>(
    source: &str,
    field: &str,
    include_table: bool,
) -> Result<(), norito::Error> {
    let mut parser = json::Parser::new(source);
    parser
        .preflight_document()
        .map_err(json::Error::into_core_error)?;
    let mut outer = json::MapVisitor::new(&mut parser).map_err(json::Error::into_core_error)?;
    assert_eq!(outer.total_entries(), 1);
    let key = outer
        .next_key()
        .map_err(json::Error::into_core_error)?
        .unwrap();
    assert_eq!(key.as_str(), field);
    let inner = json::MapVisitor::new(outer.parser()).map_err(json::Error::into_core_error)?;
    assert_eq!(inner.total_entries(), 1);
    if include_table {
        reserve_decode_btree_allocation::<AccountId, V>(inner.total_entries())?;
    }
    Ok(())
}

fn lock_record(account: &AccountId) -> GovernanceLockRecord {
    GovernanceLockRecord {
        owner: account.clone(),
        amount: 0_u64.into(),
        slashed: 0_u64.into(),
        expiry_height: 17,
        direction: 0,
        duration_blocks: 3,
        custody: GovernanceLockCustody {
            escrowed: true,
            asset_definition_id: AssetDefinitionId::derive_from_components(
                DomainId::try_new("refusal", "universal").unwrap(),
                "bond".parse().unwrap(),
            ),
            bond_escrow_account: account.clone(),
            slash_receiver_account: account.clone(),
        },
    }
}

#[test]
fn upload_account_key_preserves_original_refusal_fields_scope_and_same_source_retry() {
    let account = ALICE_ID.clone();
    let literal = account.canonical_i105().unwrap();
    let artifact = ContractArtifactId::new(DataSpaceId::UNIVERSAL, Hash::prehashed([0x31; 32]));
    let expected = SmartContractCodeUploadKey::new(account, artifact);
    let source = format!("{literal}|0|{}", hex::encode(artifact.code_hash.as_ref()));
    check_original_refusal(
        &source,
        &literal,
        SmartContractCodeUploadKey::decode_json_key,
        |decoded| assert_eq!(*decoded, expected),
        || Ok(()),
        || {
            AccountId::from_json_key_text(&literal)
                .map(|_| ())
                .map_err(json::Error::into_core_error)
        },
        "invalid upload owner",
    );
}

#[test]
fn governance_lock_account_key_preserves_original_refusal_fields_scope_and_same_source_retry() {
    let account = ALICE_ID.clone();
    let literal = account.canonical_i105().unwrap();
    let record = lock_record(&account);
    let expected = GovernanceLocksForReferendum {
        locks: std::collections::BTreeMap::from([(account.clone(), record)]),
    };
    let source = json::to_json(&expected).unwrap();
    check_original_refusal(
        &source,
        &literal,
        json::from_json::<GovernanceLocksForReferendum>,
        |decoded| {
            assert_eq!(decoded.locks.len(), 1);
            let actual = decoded.locks.get(&account).unwrap();
            let record = expected.locks.get(&account).unwrap();
            assert_eq!(actual.owner, record.owner);
            assert_eq!(actual.amount, record.amount);
            assert_eq!(actual.slashed, record.slashed);
            assert_eq!(actual.expiry_height, record.expiry_height);
            assert_eq!(actual.direction, record.direction);
            assert_eq!(actual.duration_blocks, record.duration_blocks);
            assert_eq!(actual.custody, record.custody);
        },
        || governance_prefix::<GovernanceLockRecord>(&source, "locks", false),
        || reserve_decode_btree_allocation::<AccountId, GovernanceLockRecord>(1),
        "invalid I105",
    );
    check_original_refusal(
        &source,
        &literal,
        json::from_json::<GovernanceLocksForReferendum>,
        |decoded| {
            assert_eq!(decoded.locks.len(), 1);
            let actual = decoded.locks.get(&account).unwrap();
            let record = expected.locks.get(&account).unwrap();
            assert_eq!(actual.owner, record.owner);
            assert_eq!(actual.amount, record.amount);
            assert_eq!(actual.slashed, record.slashed);
            assert_eq!(actual.expiry_height, record.expiry_height);
            assert_eq!(actual.direction, record.direction);
            assert_eq!(actual.duration_blocks, record.duration_blocks);
            assert_eq!(actual.custody, record.custody);
        },
        || governance_prefix::<GovernanceLockRecord>(&source, "locks", true),
        || {
            AccountId::from_json_key_text(&literal)
                .map(|_| ())
                .map_err(json::Error::into_core_error)
        },
        "invalid I105",
    );
}

#[test]
fn governance_slash_account_key_preserves_original_refusal_fields_scope_and_same_source_retry() {
    let account = ALICE_ID.clone();
    let literal = account.canonical_i105().unwrap();
    let record = GovernanceSlashEntry {
        last_height: 19,
        ..GovernanceSlashEntry::default()
    };
    let expected = GovernanceSlashLedger {
        slashes: std::collections::BTreeMap::from([(account.clone(), record)]),
    };
    let source = json::to_json(&expected).unwrap();
    check_original_refusal(
        &source,
        &literal,
        json::from_json::<GovernanceSlashLedger>,
        |decoded| {
            assert_eq!(decoded.slashes.len(), 1);
            let actual = decoded.slashes.get(&account).unwrap();
            let record = expected.slashes.get(&account).unwrap();
            assert_eq!(actual.total_slashed, record.total_slashed);
            assert_eq!(actual.total_restituted, record.total_restituted);
            assert_eq!(actual.last_reason, record.last_reason);
            assert_eq!(actual.last_height, record.last_height);
        },
        || governance_prefix::<GovernanceSlashEntry>(&source, "slashes", false),
        || reserve_decode_btree_allocation::<AccountId, GovernanceSlashEntry>(1),
        "invalid I105",
    );
    check_original_refusal(
        &source,
        &literal,
        json::from_json::<GovernanceSlashLedger>,
        |decoded| {
            assert_eq!(decoded.slashes.len(), 1);
            let actual = decoded.slashes.get(&account).unwrap();
            let record = expected.slashes.get(&account).unwrap();
            assert_eq!(actual.total_slashed, record.total_slashed);
            assert_eq!(actual.total_restituted, record.total_restituted);
            assert_eq!(actual.last_reason, record.last_reason);
            assert_eq!(actual.last_height, record.last_height);
        },
        || governance_prefix::<GovernanceSlashEntry>(&source, "slashes", true),
        || {
            AccountId::from_json_key_text(&literal)
                .map(|_| ())
                .map_err(json::Error::into_core_error)
        },
        "invalid I105",
    );
}

#[test]
fn governance_locks_dto_keeps_exact_json_layout_and_rejects_duplicate_account_keys() {
    let account = ALICE_ID.clone();
    let literal = account.canonical_i105().unwrap();
    let record = lock_record(&account);
    let record_text = json::to_json(&record).unwrap();
    let key = json::to_json(&literal).unwrap();
    let expected = GovernanceLocksForReferendum {
        locks: std::collections::BTreeMap::from([(account.clone(), record)]),
    };
    let source = format!("{{\"locks\":{{{key}:{record_text}}}}}");
    assert_eq!(json::to_json(&expected).unwrap(), source);
    let decoded = json::from_json::<GovernanceLocksForReferendum>(&source).unwrap();
    assert_eq!(json::to_json(&decoded).unwrap(), source);
    let mut canonical = Vec::new();
    norito::core::write_canonical_to_writer(&expected, &mut canonical).unwrap();
    let restored = norito::decode_canonical::<GovernanceLocksForReferendum>(&canonical).unwrap();
    assert_eq!(json::to_json(&restored).unwrap(), source);
    let duplicate = format!("{{\"locks\":{{{key}:{record_text},{key}:{record_text}}}}}");
    let error = json::from_json::<GovernanceLocksForReferendum>(&duplicate).unwrap_err();
    assert!(matches!(error,json::Error::DuplicateField{field} if field==literal));
}

#[test]
fn governance_slash_dto_keeps_exact_json_layout_and_rejects_duplicate_account_keys() {
    let account = ALICE_ID.clone();
    let literal = account.canonical_i105().unwrap();
    let record = GovernanceSlashEntry {
        last_height: 19,
        ..GovernanceSlashEntry::default()
    };
    let record_text = json::to_json(&record).unwrap();
    let key = json::to_json(&literal).unwrap();
    let expected = GovernanceSlashLedger {
        slashes: std::collections::BTreeMap::from([(account.clone(), record)]),
    };
    let source = format!("{{\"slashes\":{{{key}:{record_text}}}}}");
    assert_eq!(json::to_json(&expected).unwrap(), source);
    let decoded = json::from_json::<GovernanceSlashLedger>(&source).unwrap();
    assert_eq!(json::to_json(&decoded).unwrap(), source);
    let mut canonical = Vec::new();
    norito::core::write_canonical_to_writer(&expected, &mut canonical).unwrap();
    let restored = norito::decode_canonical::<GovernanceSlashLedger>(&canonical).unwrap();
    assert_eq!(json::to_json(&restored).unwrap(), source);
    let duplicate = format!("{{\"slashes\":{{{key}:{record_text},{key}:{record_text}}}}}");
    let error = json::from_json::<GovernanceSlashLedger>(&duplicate).unwrap_err();
    assert!(matches!(error,json::Error::DuplicateField{field} if field==literal));
}
