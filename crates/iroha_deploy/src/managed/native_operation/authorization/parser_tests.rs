//! Actual private epoch files exercise exact lexical ownership and selected-record freshness.
//! Historical canonical metadata here is never a live Lease or a native signing permission.

use super::*;
use iroha_data_model::{asset::AssetDefinitionId, transaction::FeePaymentIntent};
use iroha_fs::PublishMode;
use iroha_primitives::numeric::Quantity;
use iroha_wallet::operations::BoundedTransactionOptions;
use std::{collections::BTreeMap, time::Duration};

thread_local! {
    static ORIGINAL_RECIPE: Cell<bool> = const { Cell::new(false) };
}
pub(super) fn original_recipe() -> bool {
    ORIGINAL_RECIPE.with(Cell::get)
}
impl EpochReader {
    /// Run the original per-body census recipe against genuine parser inputs in tests.
    pub(in crate::managed) fn test_original_body_censuses<T>(action: impl FnOnce() -> T) -> T {
        struct Restore(bool);
        impl Drop for Restore {
            fn drop(&mut self) {
                ORIGINAL_RECIPE.with(|state| state.set(self.0));
            }
        }
        let _restore = Restore(ORIGINAL_RECIPE.with(|state| state.replace(true)));
        action()
    }
}

struct Fixture {
    parent: Arc<PrivateDirectory>,
    epochs: PrivateDirectory,
    fees: Fees,
    scope: Scope,
    intent: [u8; 32],
    values: Vec<Epoch>,
    // Directory owners close before the temporary tree is removed on Windows.
    _temporary: tempfile::TempDir,
}
impl Fixture {
    fn new(count: usize) -> Self {
        let temporary = tempfile::tempdir().unwrap();
        let parent =
            Arc::new(PrivateDirectory::open_or_create(temporary.path().join("intent")).unwrap());
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
        let scope = Scope::Renewal {
            provider: ProviderId::new([7; 32]),
            sequence: 2,
        };
        let intent = [1; 32];
        let mut values: Vec<Epoch> = Vec::new();
        for index in 1..=count {
            let value = Epoch {
                ordinal: u8::try_from(index).unwrap(),
                previous: values.last().map(digest).transpose().unwrap(),
                parent_intent: intent,
                issued_at_unix_ms: 1,
                terms: Terms {
                    requested_deadline_unix_ms: 20_000,
                    signing_deadline_unix_ms: 10_000,
                    fees: fees.clone(),
                },
            };
            attempts::write_record(&epochs, &format!("{index:04}.nrt"), &value).unwrap();
            values.push(value);
        }
        Self {
            _temporary: temporary,
            parent,
            epochs,
            fees,
            scope,
            intent,
            values,
        }
    }
    fn context(&self) -> BodyParserEpochContext {
        BodyParserEpochContext {
            parent: Arc::clone(&self.parent),
            parent_intent: self.intent,
            fees: self.fees.clone(),
            scope: self.scope,
        }
    }
    fn origin(&self, index: usize) -> Origin {
        Origin::Generated {
            ordinal: u8::try_from(index).unwrap(),
            epoch: digest(&self.values[index - 1]).unwrap(),
            parent_intent: self.intent,
        }
    }
    fn claim(&self, index: usize) -> Replacement {
        let Scope::Renewal { provider, sequence } = self.scope else {
            unreachable!()
        };
        Replacement {
            epoch: digest(&self.values[index - 1]).unwrap(),
            purpose: Purpose::CustodyRenewal { provider, sequence },
            target: ReplacementTarget::EnrollmentBody {
                outer_intent: self.intent,
                previous_body: [2; 32],
                successor_selection: [3; 32],
            },
        }
    }
    fn initial(&self, reader: &mut EpochReader) {
        reader
            .validate_retained(&self.parent, self.intent, &self.fees, self.scope)
            .unwrap();
    }
    fn enter(&self, reader: &mut EpochReader) {
        let source = reader.open_parser_source(self.context()).unwrap();
        assert!(reader.parser_source.replace(source).is_none());
    }
    fn selected(&self, reader: &mut EpochReader, index: usize) -> Result<()> {
        reader.validate_references(
            &self.parent,
            self.intent,
            &self.fees,
            self.scope,
            std::iter::once(&self.origin(index)),
        )
    }
    fn close(&self, reader: &mut EpochReader) -> Result<()> {
        let source = reader.parser_source.take().unwrap();
        let result = reader.close_parser_source(&source);
        assert!(
            reader.parser_source.is_none(),
            "ordinary failures cannot leave coverage armed"
        );
        result
    }
}

#[test]
fn bound_uses_three_complete_censuses_and_selected_sources_without_copying_original_images() {
    let fixture = Fixture::new(MAX_EPOCHS);
    let claim = fixture.claim(1);
    attempts::write_record(&fixture.epochs, "0001-replacement.nrt", &claim).unwrap();
    let mut reader = EpochReader::default();
    let ((), counts) = EpochReader::test_epoch_work(|| {
        fixture.initial(&mut reader);
        let images = reader
            .records
            .iter()
            .map(|entry| entry.epoch.bytes.as_ptr())
            .collect::<Vec<_>>();
        let claim_image = reader.records[0].claim.as_ref().unwrap().bytes.as_ptr();
        fixture.enter(&mut reader);
        for index in 1..=MAX_EPOCHS {
            fixture.selected(&mut reader, index).unwrap();
        }
        fixture.close(&mut reader).unwrap();
        assert_eq!(
            images,
            reader
                .records
                .iter()
                .map(|entry| entry.epoch.bytes.as_ptr())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            claim_image,
            reader.records[0].claim.as_ref().unwrap().bytes.as_ptr()
        );
        assert_eq!(reader.records.len(), MAX_EPOCHS);
    });
    assert_eq!(
        counts,
        (
            3 * MAX_EPOCHS * 2 + MAX_EPOCHS * 2,
            MAX_EPOCHS + 1,
            MAX_EPOCHS,
            6
        )
    );
    // These are actual leaf reads, including every optional claim. No 65th epoch read
    // exists at the canonical bound; a namespace overflow still refuses at exact exit.
    fixture.enter(&mut reader);
    attempts::write_record(&fixture.epochs, "0065.nrt", &fixture.values[0]).unwrap();
    assert!(fixture.close(&mut reader).is_err());
    std::fs::remove_file(fixture.epochs.path().join("0065.nrt")).unwrap();
    fixture.initial(&mut reader);
}

#[test]
fn exact_exit_refuses_changed_removed_and_new_images_before_decoder_replacement() {
    let fixture = Fixture::new(2);
    let claim = fixture.claim(1);
    attempts::write_record(&fixture.epochs, "0001-replacement.nrt", &claim).unwrap();
    let original = fixture
        .epochs
        .read("0002.nrt", attempts::MAX_RECORD_BYTES)
        .unwrap();
    for mutation in 0..5 {
        let mut reader = EpochReader::default();
        fixture.enter(&mut reader);
        match mutation {
            0 => {
                fixture
                    .epochs
                    .write_atomic("0002.nrt", b"changed", PublishMode::Replace)
                    .unwrap();
            }
            1 => {
                std::fs::remove_file(fixture.epochs.path().join("0002.nrt")).unwrap();
            }
            2 => {
                std::fs::remove_file(fixture.epochs.path().join("0001-replacement.nrt")).unwrap();
            }
            3 => {
                attempts::write_record(&fixture.epochs, "0002-replacement.nrt", &fixture.claim(2))
                    .unwrap();
            }
            4 => {
                let third = Epoch {
                    ordinal: 3,
                    previous: Some(digest(&fixture.values[1]).unwrap()),
                    ..fixture.values[1].clone()
                };
                attempts::write_record(&fixture.epochs, "0003.nrt", &third).unwrap();
            }
            _ => unreachable!(),
        }
        let (result, counts) = EpochReader::test_epoch_work(|| fixture.close(&mut reader));
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("original epoch parser image changed")
        );
        assert_eq!(
            counts.1, 0,
            "no changed/new image replaces the original canonical image"
        );
        assert!(reader.records.is_empty());
        match mutation {
            0 | 1 => {
                fixture
                    .epochs
                    .write_atomic("0002.nrt", &original, PublishMode::Replace)
                    .unwrap();
            }
            2 => {
                attempts::write_record(&fixture.epochs, "0001-replacement.nrt", &claim).unwrap();
            }
            3 => {
                std::fs::remove_file(fixture.epochs.path().join("0002-replacement.nrt")).unwrap();
            }
            4 => {
                std::fs::remove_file(fixture.epochs.path().join("0003.nrt")).unwrap();
            }
            _ => unreachable!(),
        }
        fixture.initial(&mut reader);
        assert_eq!(reader.records.len(), 2);
    }
    // A valid append or optional claim already present BEFORE entry is ordinary fresh input.
    attempts::write_record(&fixture.epochs, "0002-replacement.nrt", &fixture.claim(2)).unwrap();
    let mut reader = EpochReader::default();
    fixture.enter(&mut reader);
    fixture.selected(&mut reader, 2).unwrap();
    fixture.close(&mut reader).unwrap();
    assert!(reader.records[1].claim.is_some());
}

#[test]
fn selected_epoch_claim_and_exact_parent_ownership_require_current_admission() {
    let fixture = Fixture::new(2);
    let mut reader = EpochReader::default();
    fixture.enter(&mut reader);
    let pointer = reader.records[1].epoch.bytes.as_ptr();
    let (result, counts) = EpochReader::test_epoch_work(|| fixture.selected(&mut reader, 2));
    result.unwrap();
    assert_eq!(counts, (2, 0, 1, 0));
    // Equal paths and bytes do not identify the original Arc-owned parent. Foreign
    // calls use a separate ordinary full reader and cannot overwrite the source images.
    let foreign = PrivateDirectory::open_or_create(fixture.parent.path()).unwrap();
    let (result, counts) = EpochReader::test_epoch_work(|| {
        reader.validate_references(
            &foreign,
            fixture.intent,
            &fixture.fees,
            fixture.scope,
            std::iter::once(&fixture.origin(2)),
        )
    });
    result.unwrap();
    assert_eq!(counts, (5, 2, 2, 2));
    assert_eq!(pointer, reader.records[1].epoch.bytes.as_ptr());
    let wrong_scope = Scope::Renewal {
        provider: ProviderId::new([7; 32]),
        sequence: 3,
    };
    let (result, counts) = EpochReader::test_epoch_work(|| {
        reader.validate_references(
            &fixture.parent,
            fixture.intent,
            &fixture.fees,
            wrong_scope,
            std::iter::once(&fixture.origin(2)),
        )
    });
    result.unwrap();
    assert_eq!(counts, (5, 2, 2, 2));
    let no_allocation = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 32);
    let (actual, actual_usage) = norito::core::with_decode_limits_measured(no_allocation, || {
        fixture.selected(&mut reader, 2)
    });
    let (ordinary, ordinary_usage) =
        norito::core::with_decode_limits_measured(no_allocation, || {
            fixture.selected(&mut EpochReader::default(), 2)
        });
    assert_eq!(
        actual.unwrap_err().to_string(),
        ordinary.unwrap_err().to_string()
    );
    assert_eq!(actual_usage, ordinary_usage);
    assert_eq!(pointer, reader.records[1].epoch.bytes.as_ptr());
    for name in ["0002.nrt", "0002-replacement.nrt"] {
        let before = fixture
            .epochs
            .read_optional(name, attempts::MAX_RECORD_BYTES)
            .unwrap();
        fixture
            .epochs
            .write_atomic(name, b"changed", PublishMode::Replace)
            .unwrap();
        assert!(
            fixture
                .selected(&mut reader, 2)
                .unwrap_err()
                .to_string()
                .contains("original epoch parser image changed")
        );
        match before {
            Some(bytes) => {
                fixture
                    .epochs
                    .write_atomic(name, &bytes, PublishMode::Replace)
                    .unwrap();
            }
            None => {
                std::fs::remove_file(fixture.epochs.path().join(name)).unwrap();
            }
        }
    }
    let Origin::Generated {
        ordinal,
        epoch,
        parent_intent,
    } = fixture.origin(2)
    else {
        unreachable!()
    };
    for changed in [
        Origin::Generated {
            ordinal: 0,
            epoch,
            parent_intent,
        },
        Origin::Generated {
            ordinal: 3,
            epoch,
            parent_intent,
        },
        Origin::Generated {
            ordinal,
            epoch: [99; 32],
            parent_intent,
        },
        Origin::Generated {
            ordinal,
            epoch,
            parent_intent: [99; 32],
        },
    ] {
        assert!(
            reader
                .validate_references(
                    &fixture.parent,
                    fixture.intent,
                    &fixture.fees,
                    fixture.scope,
                    std::iter::once(&changed)
                )
                .is_err()
        );
    }
    fixture.close(&mut reader).unwrap();
}

#[test]
fn full_entry_and_original_absence_are_required_before_and_after_body_inspection() {
    let fixture = Fixture::new(2);
    let mut reader = EpochReader::default();
    fixture
        .epochs
        .write_atomic("unknown.nrt", b"unknown", PublishMode::CreateNew)
        .unwrap();
    assert!(reader.open_parser_source(fixture.context()).is_err());
    assert!(reader.parser_source.is_none());
    std::fs::remove_file(fixture.epochs.path().join("unknown.nrt")).unwrap();
    fixture.enter(&mut reader);
    fixture.close(&mut reader).unwrap();
    // Start from a parent whose epochs child has never existed. Do not delete a live
    // PrivateDirectory: Windows intentionally denies deleting its retained handle.
    let parent = Arc::new(
        PrivateDirectory::open_or_create(fixture._temporary.path().join("absent-intent")).unwrap(),
    );
    let context = || BodyParserEpochContext {
        parent: Arc::clone(&parent),
        parent_intent: fixture.intent,
        fees: fixture.fees.clone(),
        scope: fixture.scope,
    };
    let mut reader = EpochReader::default();
    let source = reader.open_parser_source(context()).unwrap();
    parent.create_child("epochs").unwrap();
    assert!(
        reader
            .close_parser_source(&source)
            .unwrap_err()
            .to_string()
            .contains("original epoch absence changed")
    );
    drop(source);
    let source = reader.open_parser_source(context()).unwrap();
    reader.close_parser_source(&source).unwrap();
}

#[cfg(unix)]
#[test]
fn original_directory_and_equal_leaf_bytes_still_require_native_custody() {
    use std::os::unix::fs::{PermissionsExt as _, symlink};
    let fixture = Fixture::new(2);
    let mut reader = EpochReader::default();
    fixture.enter(&mut reader);
    let path = fixture.epochs.path().join("0002.nrt");
    let original = fixture
        .epochs
        .read("0002.nrt", attempts::MAX_RECORD_BYTES)
        .unwrap();
    let permissions = std::fs::metadata(&path).unwrap().permissions();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(fixture.selected(&mut reader, 2).is_err());
    assert!(fixture.close(&mut reader).is_err());
    std::fs::set_permissions(&path, permissions).unwrap();
    fixture.enter(&mut reader);
    let link = fixture.parent.path().join("test-owned-link");
    std::fs::hard_link(&path, &link).unwrap();
    assert!(fixture.selected(&mut reader, 2).is_err());
    assert!(fixture.close(&mut reader).is_err());
    std::fs::remove_file(link).unwrap();
    fixture.enter(&mut reader);
    std::fs::remove_file(&path).unwrap();
    symlink(fixture.epochs.path().join("0001.nrt"), &path).unwrap();
    assert!(fixture.selected(&mut reader, 2).is_err());
    assert!(fixture.close(&mut reader).is_err());
    std::fs::remove_file(&path).unwrap();
    fixture
        .epochs
        .write_atomic("0002.nrt", &original, PublishMode::CreateNew)
        .unwrap();
    fixture.enter(&mut reader);
    let held = fixture.parent.path().join("test-original-epochs");
    std::fs::rename(fixture.epochs.path(), &held).unwrap();
    fixture.parent.create_child("epochs").unwrap();
    assert!(fixture.selected(&mut reader, 2).is_err());
    assert!(fixture.close(&mut reader).is_err());
    std::fs::remove_dir(fixture.epochs.path()).unwrap();
    std::fs::rename(held, fixture.epochs.path()).unwrap();
    fixture.enter(&mut reader);
    fixture.close(&mut reader).unwrap();
}
