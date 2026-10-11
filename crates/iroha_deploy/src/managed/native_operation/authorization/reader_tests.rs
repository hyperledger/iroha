//! Actual private epoch/claim reads exercise lexical metadata reuse and canonical refusals.
//! These retained local records never grant a live Lease, native finality or permission to sign.

use super::*;
use crate::managed::native_operation::encode;
use iroha_data_model::{asset::AssetDefinitionId, transaction::FeePaymentIntent};
use iroha_fs::PublishMode;
use iroha_primitives::numeric::Quantity;
use iroha_wallet::operations::BoundedTransactionOptions;
use std::{collections::BTreeMap, time::Duration};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Counts {
    reads: usize,
    decodes: usize,
    digests: usize,
    names: usize,
}
thread_local! {
    static COUNTS: Cell<Counts> = const { Cell::new(Counts { reads: 0, decodes: 0, digests: 0, names: 0 }) };
}
pub(super) fn record_read() {
    COUNTS.with(|counts| {
        let mut value = counts.get();
        value.reads += 1;
        counts.set(value);
    });
}
pub(super) fn record_decoded() {
    COUNTS.with(|counts| {
        let mut value = counts.get();
        value.decodes += 1;
        counts.set(value);
    });
}
pub(super) fn digest_computed() {
    COUNTS.with(|counts| {
        let mut value = counts.get();
        value.digests += 1;
        counts.set(value);
    });
}
pub(super) fn namespace_read() {
    COUNTS.with(|counts| {
        let mut value = counts.get();
        value.names += 1;
        counts.set(value);
    });
}
fn counts() -> Counts {
    COUNTS.with(Cell::get)
}
fn reset_counts() {
    COUNTS.with(|counts| counts.set(Counts::default()));
}
impl EpochReader {
    /// Measure only real epoch source reads, canonical decodes, digests and namespaces.
    pub(in crate::managed) fn test_epoch_work<T>(
        action: impl FnOnce() -> T,
    ) -> (T, (usize, usize, usize, usize)) {
        struct Restore(Counts);
        impl Drop for Restore {
            fn drop(&mut self) {
                COUNTS.with(|state| state.set(self.0));
            }
        }
        let _restore = Restore(COUNTS.with(|state| state.replace(Counts::default())));
        let value = action();
        let counts = counts();
        (
            value,
            (counts.reads, counts.decodes, counts.digests, counts.names),
        )
    }
}

struct Fixture {
    _temporary: tempfile::TempDir,
    parent: PrivateDirectory,
    epochs: PrivateDirectory,
    fees: Fees,
    scope: Scope,
    provider: ProviderId,
    intent: [u8; 32],
    first: Epoch,
    second: Epoch,
    claim: Replacement,
    origin: Origin,
}
impl Fixture {
    fn new() -> Self {
        let temporary = tempfile::tempdir().unwrap();
        let parent = PrivateDirectory::open_or_create(temporary.path().join("intent")).unwrap();
        let epochs = parent.create_child("epochs").unwrap();
        let asset = AssetDefinitionId::parse_address_literal(
            crate::genesis::profile::TAIRA_XOR_ASSET_DEFINITION_ID,
        )
        .unwrap();
        let fees = Fees::from_options(&BoundedTransactionOptions {
            fee_payment: FeePaymentIntent::authority(Vec::new(), None),
            max_total_fees: BTreeMap::from([(asset, Quantity::from(1_000u64))]),
            deadline: Instant::now() + Duration::from_secs(60),
        })
        .unwrap();
        let provider = ProviderId::new([7; 32]);
        let scope = Scope::Renewal {
            provider,
            sequence: 2,
        };
        let intent = [1; 32];
        // Historical metadata is intentionally not a current wall-clock authorization.
        let first = Epoch {
            ordinal: 1,
            previous: None,
            parent_intent: intent,
            issued_at_unix_ms: 1,
            terms: Terms {
                requested_deadline_unix_ms: 20_000,
                signing_deadline_unix_ms: 10_000,
                fees: fees.clone(),
            },
        };
        let second = Epoch {
            ordinal: 2,
            previous: Some(digest(&first).unwrap()),
            ..first.clone()
        };
        let claim = Replacement {
            epoch: digest(&first).unwrap(),
            purpose: Purpose::CustodyRenewal {
                provider,
                sequence: 2,
            },
            target: ReplacementTarget::EnrollmentBody {
                outer_intent: intent,
                previous_body: [2; 32],
                successor_selection: [3; 32],
            },
        };
        attempts::write_record(&epochs, "0001.nrt", &first).unwrap();
        attempts::write_record(&epochs, "0002.nrt", &second).unwrap();
        attempts::write_record(&epochs, "0001-replacement.nrt", &claim).unwrap();
        let origin = Origin::Generated {
            ordinal: 2,
            epoch: digest(&second).unwrap(),
            parent_intent: intent,
        };
        Self {
            _temporary: temporary,
            parent,
            epochs,
            fees,
            scope,
            provider,
            intent,
            first,
            second,
            claim,
            origin,
        }
    }
    fn validate(&self, reader: &mut EpochReader) -> Result<()> {
        reader.validate_references(
            &self.parent,
            self.intent,
            &self.fees,
            self.scope,
            std::iter::once(&self.origin),
        )
    }
    fn replace<T: norito::NoritoSerialize>(&self, name: &str, value: &T) {
        self.epochs
            .write_atomic(
                name,
                &encode(value, attempts::MAX_RECORD_BYTES).unwrap(),
                PublishMode::Replace,
            )
            .unwrap();
    }
}

#[test]
fn immutable_images_decode_once_but_keep_all_three_complete_fresh_censuses() {
    let fixture = Fixture::new();
    let mut reader = EpochReader::default();
    reset_counts();
    reader
        .validate_retained(
            &fixture.parent,
            fixture.intent,
            &fixture.fees,
            fixture.scope,
        )
        .unwrap();
    let first_bytes = reader.records[0].epoch.bytes.as_ptr();
    let claim_bytes = reader.records[0].claim.as_ref().unwrap().bytes.as_ptr();
    fixture.validate(&mut reader).unwrap();
    fixture.validate(&mut reader).unwrap();
    assert_eq!(first_bytes, reader.records[0].epoch.bytes.as_ptr());
    assert_eq!(
        claim_bytes,
        reader.records[0].claim.as_ref().unwrap().bytes.as_ptr()
    );
    assert_eq!(
        counts(),
        Counts {
            reads: 15,
            decodes: 3,
            digests: 2,
            names: 6
        }
    );
    assert!(reader.records[0].epoch.value == fixture.first);
    assert!(reader.records[1].epoch.value == fixture.second);
    // A separate reader must authenticate the same original source independently.
    reset_counts();
    let mut independent = EpochReader::default();
    fixture.validate(&mut independent).unwrap();
    assert_ne!(first_bytes, independent.records[0].epoch.bytes.as_ptr());
    assert_eq!(
        counts(),
        Counts {
            reads: 5,
            decodes: 3,
            digests: 2,
            names: 2
        }
    );
}

#[test]
fn fresh_changed_epoch_bytes_preserve_canonical_and_semantic_refusal_then_retry() {
    let fixture = Fixture::new();
    let mut reader = EpochReader::default();
    fixture.validate(&mut reader).unwrap();
    let original = fixture
        .epochs
        .read("0002.nrt", attempts::MAX_RECORD_BYTES)
        .unwrap();
    let names = fixture.epochs.entries(MAX_EPOCHS * 2).unwrap();
    let mut mutations = Vec::new();
    let mut changed = fixture.second.clone();
    changed.ordinal = 1;
    mutations.push(encode(&changed, attempts::MAX_RECORD_BYTES).unwrap());
    changed = fixture.second.clone();
    changed.parent_intent[0] ^= 1;
    mutations.push(encode(&changed, attempts::MAX_RECORD_BYTES).unwrap());
    changed = fixture.second.clone();
    changed.previous = Some([0x99; 32]);
    mutations.push(encode(&changed, attempts::MAX_RECORD_BYTES).unwrap());
    changed = fixture.second.clone();
    changed.issued_at_unix_ms = 0;
    mutations.push(encode(&changed, attempts::MAX_RECORD_BYTES).unwrap());
    changed = fixture.second.clone();
    changed.terms.signing_deadline_unix_ms = 0;
    mutations.push(encode(&changed, attempts::MAX_RECORD_BYTES).unwrap());
    changed = fixture.second.clone();
    changed
        .terms
        .fees
        .max_total_fees
        .values_mut()
        .for_each(|quantity| *quantity = Quantity::from(1u64));
    mutations.push(encode(&changed, attempts::MAX_RECORD_BYTES).unwrap());
    mutations.push(original.iter().copied().chain([0]).collect());
    mutations.push(vec![0xAB; attempts::MAX_RECORD_BYTES + 1]);
    for changed in mutations {
        fixture
            .epochs
            .write_atomic("0002.nrt", &changed, PublishMode::Replace)
            .unwrap();
        let retained_error = fixture.validate(&mut reader).unwrap_err();
        let fresh_error = fixture.validate(&mut EpochReader::default()).unwrap_err();
        assert_eq!(retained_error.to_string(), fresh_error.to_string());
        assert_eq!(
            fixture
                .epochs
                .read("0002.nrt", changed.len())
                .unwrap()
                .as_slice(),
            changed
        );
        assert_eq!(fixture.epochs.entries(MAX_EPOCHS * 2).unwrap(), names);
        fixture
            .epochs
            .write_atomic("0002.nrt", &original, PublishMode::Replace)
            .unwrap();
        fixture.validate(&mut reader).unwrap();
        assert!(reader.records[1].epoch.value == fixture.second);
    }
    // Cached images still compare exact current fees and parent at each census.
    let mut fees = fixture.fees.clone();
    fees.max_total_fees
        .values_mut()
        .for_each(|quantity| *quantity = Quantity::from(1u64));
    assert!(
        reader
            .validate_retained(&fixture.parent, fixture.intent, &fees, fixture.scope)
            .is_err()
    );
    assert!(
        reader
            .validate_retained(&fixture.parent, [9; 32], &fixture.fees, fixture.scope)
            .is_err()
    );
    fixture.validate(&mut reader).unwrap();
}

#[test]
fn optional_claims_gaps_names_and_current_scope_never_use_an_earlier_source_verdict() {
    let fixture = Fixture::new();
    let mut reader = EpochReader::default();
    fixture.validate(&mut reader).unwrap();
    for changed in [
        Replacement {
            epoch: [9; 32],
            ..fixture.claim.clone()
        },
        Replacement {
            purpose: Purpose::CustodyRenewal {
                provider: fixture.provider,
                sequence: 3,
            },
            ..fixture.claim.clone()
        },
        Replacement {
            target: ReplacementTarget::EnrollmentBody {
                outer_intent: fixture.intent,
                previous_body: [2; 32],
                successor_selection: [2; 32],
            },
            ..fixture.claim.clone()
        },
    ] {
        fixture.replace("0001-replacement.nrt", &changed);
        assert_eq!(
            fixture.validate(&mut reader).unwrap_err().to_string(),
            fixture
                .validate(&mut EpochReader::default())
                .unwrap_err()
                .to_string()
        );
        fixture.replace("0001-replacement.nrt", &fixture.claim);
        fixture.validate(&mut reader).unwrap();
    }
    assert!(
        reader
            .validate_retained(
                &fixture.parent,
                fixture.intent,
                &fixture.fees,
                Scope::Bootstrap([fixture.provider; 3])
            )
            .is_err()
    );
    std::fs::remove_file(fixture.epochs.path().join("0001.nrt")).unwrap();
    assert!(fixture.validate(&mut reader).is_err());
    attempts::write_record(&fixture.epochs, "0001.nrt", &fixture.first).unwrap();
    fixture.validate(&mut reader).unwrap();
    fixture
        .epochs
        .write_atomic("unknown.nrt", b"foreign", PublishMode::CreateNew)
        .unwrap();
    assert!(fixture.validate(&mut reader).is_err());
    std::fs::remove_file(fixture.epochs.path().join("unknown.nrt")).unwrap();
    fixture.validate(&mut reader).unwrap();
    // Removing an optional claim is legal if the actual current namespace agrees. An old
    // Some cannot replace the freshly observed absence or be resurrected by a cached DTO.
    std::fs::remove_file(fixture.epochs.path().join("0001-replacement.nrt")).unwrap();
    fixture.validate(&mut reader).unwrap();
    assert!(reader.records[0].claim.is_none());
    attempts::write_record(&fixture.epochs, "0001-replacement.nrt", &fixture.claim).unwrap();
    fixture.validate(&mut reader).unwrap();
    assert!(reader.records[0].claim.is_some());
}

#[test]
fn another_decoder_scope_must_admit_even_identical_source_and_append_then_retry_fresh() {
    let fixture = Fixture::new();
    let mut reader = EpochReader::default();
    fixture.validate(&mut reader).unwrap();
    let first_bytes = fixture
        .epochs
        .read("0001.nrt", attempts::MAX_RECORD_BYTES)
        .unwrap();
    let second_bytes = fixture
        .epochs
        .read("0002.nrt", attempts::MAX_RECORD_BYTES)
        .unwrap();
    let original_names = fixture.epochs.entries(MAX_EPOCHS * 2).unwrap();
    let no_allocations = norito::DecodeLimits::new(
        attempts::MAX_RECORD_BYTES,
        attempts::MAX_RECORD_BYTES,
        attempts::MAX_RECORD_BYTES,
        0,
        32,
    );
    // Previously admitted bytes cannot exempt another caller's narrower decoder scope.
    // The sole original codec must refuse with the same error as a fresh independent import.
    let cached_error =
        norito::core::with_decode_limits_scope(no_allocations, || fixture.validate(&mut reader))
            .unwrap_err();
    let fresh_error = norito::core::with_decode_limits_scope(no_allocations, || {
        fixture.validate(&mut EpochReader::default())
    })
    .unwrap_err();
    assert_eq!(cached_error.to_string(), fresh_error.to_string());
    assert!(reader.records.is_empty());
    assert_eq!(
        fixture
            .epochs
            .read("0001.nrt", attempts::MAX_RECORD_BYTES)
            .unwrap(),
        first_bytes
    );
    assert_eq!(
        fixture
            .epochs
            .read("0002.nrt", attempts::MAX_RECORD_BYTES)
            .unwrap(),
        second_bytes
    );
    assert_eq!(
        fixture.epochs.entries(MAX_EPOCHS * 2).unwrap(),
        original_names
    );
    fixture.validate(&mut reader).unwrap();
    let no_fields = norito::DecodeLimits::new(
        attempts::MAX_RECORD_BYTES,
        0,
        attempts::MAX_RECORD_BYTES,
        attempts::MAX_RECORD_BYTES * 8,
        32,
    );
    assert_eq!(
        norito::core::with_decode_limits_scope(no_fields, || fixture.validate(&mut reader))
            .unwrap_err()
            .to_string(),
        norito::core::with_decode_limits_scope(no_fields, || fixture
            .validate(&mut EpochReader::default()))
        .unwrap_err()
        .to_string()
    );
    fixture.validate(&mut reader).unwrap();
    let full_admission = norito::DecodeLimits::new(
        attempts::MAX_RECORD_BYTES,
        attempts::MAX_RECORD_BYTES,
        attempts::MAX_RECORD_BYTES,
        attempts::MAX_RECORD_BYTES * 8,
        32,
    );
    reset_counts();
    norito::core::with_decode_limits_scope(full_admission, || {
        fixture.validate(&mut reader)?;
        fixture.validate(&mut reader)
    })
    .unwrap();
    assert_eq!(
        counts(),
        Counts {
            reads: 10,
            decodes: 6,
            digests: 4,
            names: 4
        }
    );
    let third = Epoch {
        ordinal: 3,
        previous: Some(digest(&fixture.second).unwrap()),
        ..fixture.second.clone()
    };
    attempts::write_record(&fixture.epochs, "0003.nrt", &third).unwrap();
    let bytes = fixture
        .epochs
        .read("0003.nrt", attempts::MAX_RECORD_BYTES)
        .unwrap();
    let names = fixture.epochs.entries(MAX_EPOCHS * 2).unwrap();
    assert_eq!(names.len(), original_names.len() + 1);
    assert!(
        norito::core::with_decode_limits_scope(no_allocations, || fixture.validate(&mut reader))
            .is_err()
    );
    // Refusal drops partial metadata; no extra old graph or successful source verdict is kept.
    assert!(reader.records.is_empty());
    assert_eq!(
        fixture
            .epochs
            .read("0003.nrt", attempts::MAX_RECORD_BYTES)
            .unwrap(),
        bytes
    );
    assert_eq!(fixture.epochs.entries(MAX_EPOCHS * 2).unwrap(), names);
    fixture.validate(&mut reader).unwrap();
    assert_eq!(reader.records.len(), 3);
    assert!(reader.records[2].epoch.value == third);
    let third_origin = Origin::Generated {
        ordinal: 3,
        epoch: digest(&third).unwrap(),
        parent_intent: fixture.intent,
    };
    reader
        .validate_references(
            &fixture.parent,
            fixture.intent,
            &fixture.fees,
            fixture.scope,
            std::iter::once(&third_origin),
        )
        .unwrap();
    // Fresh absent-to-present claims also pass through the same canonical decoder.
    let new_claim = Replacement {
        epoch: digest(&fixture.second).unwrap(),
        ..fixture.claim.clone()
    };
    attempts::write_record(&fixture.epochs, "0002-replacement.nrt", &new_claim).unwrap();
    reset_counts();
    fixture.validate(&mut reader).unwrap();
    assert_eq!(counts().decodes, 1);
    assert!(reader.records[1].claim.as_ref().unwrap().value == new_claim);
    fixture
        .epochs
        .write_atomic("0065.nrt", &bytes, PublishMode::CreateNew)
        .unwrap();
    assert!(fixture.validate(&mut reader).is_err());
    std::fs::remove_file(fixture.epochs.path().join("0065.nrt")).unwrap();
    // This independent retry has no reader from the failed call and re-admits all real sources.
    fixture.validate(&mut EpochReader::default()).unwrap();
}

#[test]
fn full_epoch_bound_keeps_original_images_and_reads_every_claim_and_namespace_again() {
    let fixture = Fixture::new();
    let mut previous = fixture.second.clone();
    for ordinal in 3..=MAX_EPOCHS {
        let epoch = Epoch {
            ordinal: u8::try_from(ordinal).unwrap(),
            previous: Some(digest(&previous).unwrap()),
            ..fixture.second.clone()
        };
        attempts::write_record(&fixture.epochs, &format!("{ordinal:04}.nrt"), &epoch).unwrap();
        previous = epoch;
    }
    let origin = Origin::Generated {
        ordinal: u8::try_from(MAX_EPOCHS).unwrap(),
        epoch: digest(&previous).unwrap(),
        parent_intent: fixture.intent,
    };
    let mut reader = EpochReader::default();
    reset_counts();
    reader
        .validate_retained(
            &fixture.parent,
            fixture.intent,
            &fixture.fees,
            fixture.scope,
        )
        .unwrap();
    let original_buffers = reader
        .records
        .iter()
        .map(|entry| entry.epoch.bytes.as_ptr())
        .collect::<Vec<_>>();
    for _ in 0..2 {
        reader
            .validate_references(
                &fixture.parent,
                fixture.intent,
                &fixture.fees,
                fixture.scope,
                std::iter::once(&origin),
            )
            .unwrap();
        assert_eq!(reader.records.len(), MAX_EPOCHS);
        assert_eq!(
            reader
                .records
                .iter()
                .map(|entry| entry.epoch.bytes.as_ptr())
                .collect::<Vec<_>>(),
            original_buffers
        );
    }
    assert_eq!(
        counts(),
        Counts {
            reads: 3 * MAX_EPOCHS * 2,
            decodes: MAX_EPOCHS + 1,
            digests: MAX_EPOCHS,
            names: 6,
        }
    );
}

#[cfg(unix)]
#[test]
fn equal_cached_bytes_still_require_private_single_link_regular_file_custody() {
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    let fixture = Fixture::new();
    let mut reader = EpochReader::default();
    fixture.validate(&mut reader).unwrap();
    let source = fixture.epochs.path().join("0002.nrt");
    let original = fixture
        .epochs
        .read("0002.nrt", attempts::MAX_RECORD_BYTES)
        .unwrap();
    let names = fixture.epochs.entries(MAX_EPOCHS * 2).unwrap();
    let permissions = std::fs::metadata(&source).unwrap().permissions();
    std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(
        fixture.validate(&mut reader).unwrap_err().to_string(),
        fixture
            .validate(&mut EpochReader::default())
            .unwrap_err()
            .to_string()
    );
    assert_eq!(
        std::fs::read(&source).unwrap().as_slice(),
        original.as_slice()
    );
    std::fs::set_permissions(&source, permissions).unwrap();
    fixture.validate(&mut reader).unwrap();

    let other_link = fixture.parent.path().join("only-test-owned-link");
    std::fs::hard_link(&source, &other_link).unwrap();
    assert_eq!(
        fixture.validate(&mut reader).unwrap_err().to_string(),
        fixture
            .validate(&mut EpochReader::default())
            .unwrap_err()
            .to_string()
    );
    std::fs::remove_file(&other_link).unwrap();
    fixture.validate(&mut reader).unwrap();

    std::fs::remove_file(&source).unwrap();
    symlink(fixture.epochs.path().join("0001.nrt"), &source).unwrap();
    assert_eq!(
        fixture.validate(&mut reader).unwrap_err().to_string(),
        fixture
            .validate(&mut EpochReader::default())
            .unwrap_err()
            .to_string()
    );
    std::fs::remove_file(&source).unwrap();
    fixture
        .epochs
        .write_atomic("0002.nrt", &original, PublishMode::CreateNew)
        .unwrap();
    fixture.validate(&mut reader).unwrap();
    assert_eq!(fixture.epochs.entries(MAX_EPOCHS * 2).unwrap(), names);
    assert_eq!(
        fixture
            .epochs
            .read("0002.nrt", attempts::MAX_RECORD_BYTES)
            .unwrap(),
        original
    );
}

#[test]
fn freshly_validated_images_do_not_relax_exact_origin_ordinal_hash_or_parent_binding() {
    let fixture = Fixture::new();
    let mut reader = EpochReader::default();
    fixture.validate(&mut reader).unwrap();
    let digest = digest(&fixture.second).unwrap();
    for origin in [
        Origin::Generated {
            ordinal: 0,
            epoch: digest,
            parent_intent: fixture.intent,
        },
        Origin::Generated {
            ordinal: 3,
            epoch: digest,
            parent_intent: fixture.intent,
        },
        Origin::Generated {
            ordinal: 2,
            epoch: [9; 32],
            parent_intent: fixture.intent,
        },
        Origin::Generated {
            ordinal: 2,
            epoch: digest,
            parent_intent: [9; 32],
        },
    ] {
        let validate = |reader: &mut EpochReader| {
            reader.validate_references(
                &fixture.parent,
                fixture.intent,
                &fixture.fees,
                fixture.scope,
                std::iter::once(&origin),
            )
        };
        assert_eq!(
            validate(&mut reader).unwrap_err().to_string(),
            validate(&mut EpochReader::default())
                .unwrap_err()
                .to_string()
        );
        fixture.validate(&mut reader).unwrap();
    }
    // A valid explicit historical origin has no generated-epoch binding, as before.
    reader
        .validate_references(
            &fixture.parent,
            fixture.intent,
            &fixture.fees,
            fixture.scope,
            std::iter::once(&Origin::Explicit),
        )
        .unwrap();
}

#[test]
fn definite_initial_epoch_absence_keeps_explicit_history_and_requires_generated_references() {
    let fixture = Fixture::new();
    let mut reader = EpochReader::default();
    fixture.validate(&mut reader).unwrap();
    let absent = fixture.parent.create_child("without-epochs").unwrap();
    reader
        .validate_references(
            &absent,
            fixture.intent,
            &fixture.fees,
            fixture.scope,
            std::iter::once(&Origin::Explicit),
        )
        .unwrap();
    assert!(reader.records.is_empty());
    assert!(
        reader
            .validate_references(
                &absent,
                fixture.intent,
                &fixture.fees,
                fixture.scope,
                std::iter::once(&fixture.origin)
            )
            .is_err()
    );
    fixture.validate(&mut reader).unwrap();
    assert_eq!(reader.records.len(), 2);
}

#[cfg(unix)]
#[test]
fn epoch_explicit_reference_refuses_parent_loss_and_replacement_then_original_retry() {
    let fixture = Fixture::new();
    let mut reader = EpochReader::default();
    fixture.validate(&mut reader).unwrap();
    let original = fixture.parent.path().to_owned();
    let displaced = original.with_file_name("displaced");
    std::fs::rename(&original, &displaced).unwrap();
    assert!(
        reader
            .validate_references(
                &fixture.parent,
                fixture.intent,
                &fixture.fees,
                fixture.scope,
                std::iter::once(&Origin::Explicit)
            )
            .is_err()
    );
    let replacement = PrivateDirectory::open_or_create(&original).unwrap();
    assert!(
        reader
            .validate_references(
                &fixture.parent,
                fixture.intent,
                &fixture.fees,
                fixture.scope,
                std::iter::once(&Origin::Explicit)
            )
            .is_err()
    );
    assert!(replacement.entries(1).unwrap().is_empty());
    drop(replacement);
    std::fs::remove_dir(&original).unwrap();
    std::fs::rename(&displaced, &original).unwrap();
    fixture.validate(&mut reader).unwrap();
    assert_eq!(reader.records.len(), 2);
}
