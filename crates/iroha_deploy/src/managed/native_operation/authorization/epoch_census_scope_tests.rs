//! Genuine complete epoch censuses retain every leaf while sharing only original ancestry.

use super::*;
use iroha_fs::CustodyWorkV1;
use std::cell::RefCell;

type AfterImage = Box<dyn FnOnce(&str) -> Result<()>>;
thread_local! {
    static ORIGINAL_RECIPE: Cell<bool> = const { Cell::new(false) };
    static AFTER_IMAGE: RefCell<Option<AfterImage>> = const { RefCell::new(None) };
}
pub(in crate::managed) fn original_recipe() -> bool {
    ORIGINAL_RECIPE.with(Cell::get)
}
pub(in crate::managed) fn after_image(name: &str) -> Result<()> {
    let hook = AFTER_IMAGE.with(RefCell::take);
    hook.map_or(Ok(()), |hook| hook(name))
}
fn observe<T>(original: bool, hook: Option<AfterImage>, read: impl FnOnce() -> T) -> T {
    struct Restore(bool, Option<AfterImage>);
    impl Drop for Restore {
        fn drop(&mut self) {
            ORIGINAL_RECIPE.with(|value| value.set(self.0));
            AFTER_IMAGE.with(|value| value.replace(self.1.take()));
        }
    }
    let _restore = Restore(
        ORIGINAL_RECIPE.with(|value| value.replace(original)),
        AFTER_IMAGE.with(|value| value.replace(hook)),
    );
    read()
}
fn read(fixture: &Fixture) -> Result<Vec<RetainedEpoch>> {
    read_epochs(
        &fixture.epochs,
        fixture.intent,
        &fixture.fees,
        fixture.scope,
        Vec::new(),
    )
}
fn measure<T>(read: impl FnOnce() -> T) -> (T, CustodyWorkV1, Counts) {
    reset_counts();
    let before = CustodyWorkV1::current_thread();
    let result = read();
    (
        result,
        CustodyWorkV1::current_thread().since(before),
        counts(),
    )
}

#[test]
fn complete_sixty_four_epoch_census_keeps_every_leaf_and_only_two_ancestry_walks() {
    let fixture = Fixture::new();
    let mut previous = fixture.second.clone();
    for ordinal in 3..=MAX_EPOCHS {
        let value = Epoch {
            ordinal: u8::try_from(ordinal).unwrap(),
            previous: Some(digest(&previous).unwrap()),
            ..previous.clone()
        };
        attempts::write_record(&fixture.epochs, &format!("{ordinal:04}.nrt"), &value).unwrap();
        previous = value;
    }
    let before = CustodyWorkV1::current_thread();
    fixture.epochs.revalidate().unwrap();
    let one_walk = CustodyWorkV1::current_thread().since(before);
    assert_eq!(one_walk.ancestry_walks, 1);
    let (original, original_work, original_counts) =
        measure(|| observe(true, None, || read(&fixture)));
    let (scoped, scoped_work, scoped_counts) = measure(|| read(&fixture));
    let original = original.unwrap();
    let scoped = scoped.unwrap();
    assert_eq!(original.len(), MAX_EPOCHS);
    assert_eq!(scoped.len(), MAX_EPOCHS);
    for (original, scoped) in original.iter().zip(&scoped) {
        assert_eq!(original.epoch.bytes, scoped.epoch.bytes);
        assert!(original.epoch.value == scoped.epoch.value);
        assert_eq!(
            original.claim.as_ref().map(|v| &v.bytes),
            scoped.claim.as_ref().map(|v| &v.bytes)
        );
    }
    assert_eq!(original_counts, scoped_counts);
    assert_eq!(scoped_counts.reads, 2 * MAX_EPOCHS);
    assert_eq!(scoped_counts.names, 2);
    assert_eq!(scoped_counts.decodes, MAX_EPOCHS + 1);
    assert_eq!(scoped_work.ancestry_walks, 2);
    assert_eq!(scoped_work.ancestry_opens, 2 * one_walk.ancestry_opens);
    assert_eq!(original_work.ancestry_walks, (4 * MAX_EPOCHS + 4) as u64);
    assert_eq!(
        original_work.ancestry_opens,
        original_work.ancestry_walks * one_walk.ancestry_opens
    );
}

#[test]
fn inherited_and_late_decoder_owners_keep_original_epoch_reads_and_refusals() {
    let fixture = Fixture::new();
    for allocations in [0, 1, attempts::MAX_RECORD_BYTES * 8] {
        let limits = norito::DecodeLimits::new(
            attempts::MAX_RECORD_BYTES,
            attempts::MAX_RECORD_BYTES,
            attempts::MAX_RECORD_BYTES,
            allocations,
            32,
        );
        let run = |original| {
            measure(|| {
                observe(original, None, || {
                    norito::core::with_decode_limits_scope(limits, || read(&fixture))
                })
            })
        };
        let (old, old_work, old_counts) = run(true);
        let (new, new_work, new_counts) = run(false);
        assert_eq!(old.is_ok(), new.is_ok());
        assert_eq!(
            old.as_ref().err().map(ToString::to_string),
            new.as_ref().err().map(ToString::to_string)
        );
        assert_eq!(old_work, new_work);
        assert_eq!(old_counts, new_counts);
    }
    // A scope selected before an inherited owner appears cannot waive its physical recipe.
    fixture
        .epochs
        .read_scope(|reader| {
            let mut source = EpochCensusRead {
                root: &fixture.epochs,
                reader: Some(reader),
            };
            let limits = norito::DecodeLimits::new(
                attempts::MAX_RECORD_BYTES,
                attempts::MAX_RECORD_BYTES,
                attempts::MAX_RECORD_BYTES,
                0,
                32,
            );
            let (late, late_work, late_counts) = measure(|| {
                norito::core::with_decode_limits_scope(limits, || {
                    read_epochs_inner(
                        &mut source,
                        fixture.intent,
                        &fixture.fees,
                        fixture.scope,
                        Vec::new(),
                        false,
                    )
                })
            });
            let (plain, plain_work, plain_counts) = measure(|| {
                observe(true, None, || {
                    norito::core::with_decode_limits_scope(limits, || read(&fixture))
                })
            });
            assert_eq!(
                late.err().expect("late decoder must refuse").to_string(),
                plain
                    .err()
                    .expect("original decoder must refuse")
                    .to_string()
            );
            assert_eq!(late_work, plain_work);
            assert_eq!(late_counts, plain_counts);
            Ok::<_, crate::managed::Error>(())
        })
        .unwrap();
    assert_eq!(read(&fixture).unwrap().len(), 2);
}

#[cfg(unix)]
#[test]
fn epoch_census_exit_keeps_original_owner_and_overrides_success_or_inner_refusal() {
    use std::os::unix::fs::PermissionsExt as _;
    for attack in ["permissions", "missing", "replacement"] {
        for inner_error in [false, true] {
            let fixture = Fixture::new();
            let path = fixture.epochs.path().to_path_buf();
            let displaced = fixture.parent.path().join("displaced-epochs");
            let mutate_path = path.clone();
            let mutate_displaced = displaced.clone();
            let result = observe(
                false,
                Some(Box::new(move |name| {
                    assert_eq!(name, "0001.nrt");
                    match attack {
                        "permissions" => std::fs::set_permissions(
                            &mutate_path,
                            std::fs::Permissions::from_mode(0o755),
                        )
                        .unwrap(),
                        "missing" => std::fs::rename(&mutate_path, &mutate_displaced).unwrap(),
                        "replacement" => {
                            std::fs::rename(&mutate_path, &mutate_displaced).unwrap();
                            std::fs::create_dir(&mutate_path).unwrap();
                            std::fs::set_permissions(
                                &mutate_path,
                                std::fs::Permissions::from_mode(0o700),
                            )
                            .unwrap();
                        }
                        _ => unreachable!(),
                    }
                    if inner_error {
                        Err(invalid("original epoch semantic refusal"))
                    } else {
                        Ok(())
                    }
                })),
                || read(&fixture),
            );
            let error = result.err().expect("original epoch owner must close");
            let native = fixture.epochs.revalidate().unwrap_err();
            assert_eq!(
                error.to_string(),
                crate::managed::Error::from(native).to_string()
            );
            assert_ne!(error.to_string(), "original epoch semantic refusal");
            match attack {
                "permissions" => {
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap()
                }
                "missing" => std::fs::rename(&displaced, &path).unwrap(),
                "replacement" => {
                    std::fs::remove_dir(&path).unwrap();
                    std::fs::rename(&displaced, &path).unwrap();
                }
                _ => unreachable!(),
            }
            assert_eq!(read(&fixture).unwrap().len(), 2);
        }
    }
}

#[test]
fn scoped_epoch_images_preserve_optional_absence_exact_exit_and_first_refusal_order() {
    let fixture = Fixture::new();
    let retained = read(&fixture).unwrap();
    let first = retained[0].epoch.bytes.as_ptr();
    let retained = read_epochs_using(
        &fixture.epochs,
        fixture.intent,
        &fixture.fees,
        fixture.scope,
        retained,
        true,
    )
    .unwrap();
    assert_eq!(retained[0].epoch.bytes.as_ptr(), first);
    let claim = Replacement {
        epoch: digest(&fixture.second).unwrap(),
        ..fixture.claim.clone()
    };
    fixture.replace("0002-replacement.nrt", &claim);
    let error = read_epochs_using(
        &fixture.epochs,
        fixture.intent,
        &fixture.fees,
        fixture.scope,
        retained,
        true,
    )
    .err()
    .unwrap();
    assert_eq!(
        error.to_string(),
        invalid("original epoch parser image changed").to_string()
    );
    std::fs::remove_file(fixture.epochs.path().join("0002-replacement.nrt")).unwrap();
    let (failure, _, counts) = measure(|| {
        observe(
            false,
            Some(Box::new(|_| Err(invalid("first epoch semantic refusal")))),
            || read(&fixture),
        )
    });
    assert_eq!(
        failure.err().unwrap().to_string(),
        invalid("first epoch semantic refusal").to_string()
    );
    assert_eq!((counts.reads, counts.decodes, counts.names), (1, 0, 1));
    assert_eq!(read(&fixture).unwrap().len(), 2);
}
