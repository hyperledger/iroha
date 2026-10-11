//! Exact verifying-key circuit/version inverse for current and predecessor WSV cuts.

use super::*;
use crate::state::verifying_key_index_validation::{self as relation, Work};

pub(super) fn validate_verifying_key_index(world: &World) -> Result<(), StateRestoreError> {
    let invalid = |message: String| json::Error::InvalidField {
        field: "world.verifying_keys_by_circuit".to_owned(),
        message,
    };
    let read_failure = |error| StateRestoreError::StateRead(StateViewError::from(error));
    // Retain the exact persisted pair. Validation never repairs a corrupt inverse or
    // replaces its physical current/undo maps. Startup work admission remains separate.
    let keys = world
        .verifying_keys
        .try_committed_view_nonblocking()
        .map_err(read_failure)?;
    let index = world
        .verifying_keys_by_circuit
        .try_committed_view_nonblocking()
        .map_err(read_failure)?;
    let result = relation::validate(&keys, &index, &mut Work::startup());
    let keys_current = keys.try_matches_current(&world.verifying_keys);
    let index_current = index.try_matches_current(&world.verifying_keys_by_circuit);
    if !keys_current.map_err(read_failure)? || !index_current.map_err(read_failure)? {
        return Err(StateRestoreError::StateRead(StateViewError::Changed));
    }
    result.map_err(|error| {
        StateRestoreError::Serialization(match error {
            relation::Error::WorkLimit => {
                invalid("verifier-key startup work admission unavailable".into())
            }
            relation::Error::Index { image, missing } => invalid(format!(
                "{} verifier-key index: {}",
                match image {
                    relation::Image::Current => "current",
                    relation::Image::Predecessor => "predecessor",
                },
                if missing {
                    "registry row lacks its exact circuit/version inverse"
                } else {
                    "circuit index contains a foreign row"
                }
            )),
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_data_model::{
        proof::{VerifyingKeyId, VerifyingKeyRecord},
        zk::BackendTag,
    };

    fn encoded<K: mv::Key + norito::codec::Encode, V: mv::Value + norito::codec::Encode>(
        store: &mv::storage::Storage<K, V>,
    ) -> String {
        let mut output = String::new();
        crate::state::snapshot_storage::serialize(store, &mut output);
        output
    }

    fn id(sequence: u8) -> VerifyingKeyId {
        VerifyingKeyId::new("halo2/ipa", format!("key-{sequence}"))
    }

    fn record(version: u32, circuit: &str) -> VerifyingKeyRecord {
        VerifyingKeyRecord::new(
            version,
            circuit,
            BackendTag::NativePipaRPasta,
            "pasta",
            [1; 32],
            [2; 32],
        )
    }

    fn valid_world() -> World {
        let world = World::default();
        let mut block = world.block();
        block.verifying_keys.insert(id(1), record(2, "circuit"));
        block
            .verifying_keys_by_circuit
            .insert(("circuit".to_owned(), 2), id(1));
        block.commit();
        world
    }

    #[test]
    fn current_cut_rejects_missing_foreign_and_ambiguous_inverse_rows() {
        validate_verifying_key_index(&valid_world()).unwrap();
        for mutation in 0..5 {
            let world = valid_world();
            let mut block = world.block();
            match mutation {
                0 => {
                    block
                        .verifying_keys_by_circuit
                        .remove(("circuit".to_owned(), 2));
                }
                1 => {
                    block
                        .verifying_keys_by_circuit
                        .insert(("circuit".to_owned(), 2), id(2));
                }
                2 => {
                    block
                        .verifying_keys_by_circuit
                        .insert(("other".to_owned(), 2), id(1));
                }
                3 => {
                    block.verifying_keys.insert(id(1), record(3, "circuit"));
                }
                4 => {
                    block.verifying_keys.insert(id(2), record(2, "circuit"));
                }
                _ => unreachable!(),
            }
            block.commit();
            let error = validate_verifying_key_index(&world).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("world.verifying_keys_by_circuit"),
                "{error}"
            );
        }
    }

    #[test]
    fn predecessor_cut_cannot_hide_an_unindexed_verifying_key() {
        let world = World::default();
        {
            let mut block = world.block();
            block.verifying_keys.insert(id(1), record(2, "circuit"));
            block.commit();
        }
        {
            let mut block = world.block();
            block
                .verifying_keys_by_circuit
                .insert(("circuit".to_owned(), 2), id(1));
            block.commit();
        }
        let error = validate_verifying_key_index(&world).unwrap_err();
        assert!(error.to_string().contains("predecessor"), "{error}");
    }

    #[test]
    fn shared_restore_validator_preserves_exact_current_and_undo_for_version_and_status_touches() {
        use crate::state::verifying_key_index_validation::test_support as fixture;
        use iroha_data_model::confidential::ConfidentialStatus;
        let world = fixture::world();
        {
            let mut block = world.block();
            let mut value = fixture::record();
            value.version = 2;
            value.status = ConfidentialStatus::Withdrawn;
            value.key = None;
            value.vk_len = 0;
            block.verifying_keys.insert(fixture::id(), value);
            block
                .verifying_keys_by_circuit
                .remove(("circuit".into(), 1));
            block
                .verifying_keys_by_circuit
                .insert(("circuit".into(), 2), fixture::id());
            block
                .verifying_keys
                .remove(VerifyingKeyId::new("absent", "key"));
            block.verifying_keys_by_circuit.remove(("absent".into(), 0));
            block.commit();
        }
        let before = (
            encoded(&world.verifying_keys),
            encoded(&world.verifying_keys_by_circuit),
        );
        validate_verifying_key_index(&world).unwrap();
        assert_eq!(
            (
                encoded(&world.verifying_keys),
                encoded(&world.verifying_keys_by_circuit)
            ),
            before
        );
        world.block_and_revert().commit();
        validate_verifying_key_index(&world).unwrap();
        assert_eq!(
            world
                .verifying_keys
                .view()
                .get(&fixture::id())
                .unwrap()
                .version,
            1
        );
        assert_eq!(
            world
                .verifying_keys_by_circuit
                .view()
                .get(&("circuit".into(), 1)),
            Some(&fixture::id())
        );
        {
            let mut block = world.block();
            let mut value = fixture::record();
            value.status = ConfidentialStatus::Withdrawn;
            block.verifying_keys.insert(fixture::id(), value);
            block
                .verifying_keys_by_circuit
                .remove(("circuit".into(), 1));
            block
                .verifying_keys_by_circuit
                .insert(("circuit".into(), 1), fixture::id());
            block.commit();
        }
        let before = (
            encoded(&world.verifying_keys),
            encoded(&world.verifying_keys_by_circuit),
        );
        validate_verifying_key_index(&world).unwrap();
        assert_eq!(
            (
                encoded(&world.verifying_keys),
                encoded(&world.verifying_keys_by_circuit)
            ),
            before
        );
    }

    #[test]
    fn failed_restore_never_repairs_or_discards_either_persisted_image() {
        use crate::state::verifying_key_index_validation::test_support as fixture;
        for prior in [false, true] {
            let world = fixture::world();
            {
                let mut index = world.verifying_keys_by_circuit.block();
                index.remove(("circuit".into(), 1));
                index.commit();
            }
            if prior {
                fixture::repair_current(&world, &[]);
            }
            let before = (
                encoded(&world.verifying_keys),
                encoded(&world.verifying_keys_by_circuit),
            );
            let error = validate_verifying_key_index(&world).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains(if prior { "predecessor" } else { "current" })
            );
            assert_eq!(
                (
                    encoded(&world.verifying_keys),
                    encoded(&world.verifying_keys_by_circuit)
                ),
                before
            );
        }
    }

    #[test]
    fn restore_keeps_each_original_registry_publication_refusal_until_actual_release() {
        use std::{
            future::Future,
            task::{Context, Poll, Waker},
        };
        let world = valid_world();
        let release_budget = iroha_allocation::AllocationBudget::new(4096);
        let mut registration = crate::unit_test_support::release_registration(&release_budget);
        let context = &mut Context::from_waker(Waker::noop());
        macro_rules! check {
            ($source:expr) => {{
                let source = &$source;
                let journal = source
                    .block()
                    .try_detach(|_| Ok::<_, std::convert::Infallible>(()))
                    .unwrap_or_else(|_| panic!("prepare original unchanged registry journal"));
                let prepared = journal
                    .try_prepare_publication(source, |_, _| Ok::<_, std::convert::Infallible>(()))
                    .unwrap_or_else(|_| panic!("hold actual original registry publication"));
                let Err(mv::PublicationPreparationError::Busy(original)) =
                    source.try_committed_view_nonblocking()
                else {
                    panic!("the held publication must refuse its exact original reader");
                };
                let error = validate_verifying_key_index(&world).unwrap_err();
                assert!(
                    std::error::Error::source(&error)
                        .unwrap()
                        .downcast_ref::<StateViewError>()
                        .is_some()
                );
                let error = crate::snapshot::TryReadError::from(error);
                assert!(
                    std::error::Error::source(&error)
                        .unwrap()
                        .downcast_ref::<StateViewError>()
                        .is_some()
                );
                let crate::snapshot::TryReadError::StateRead(StateViewError::Busy(wait)) = error
                else {
                    panic!(
                        "local registry contention must not invalidate snapshot bytes: {error:?}"
                    );
                };
                assert_eq!(wait, original);
                let mut pending = std::pin::pin!(wait.wait_for_release(&mut registration));
                assert_eq!(pending.as_mut().poll(context), Poll::Pending);
                let foreign = valid_world();
                foreign.verifying_keys.block().commit();
                assert_eq!(pending.as_mut().poll(context), Poll::Pending);
                drop(prepared);
                assert_eq!(pending.as_mut().poll(context), Poll::Ready(()));
                validate_verifying_key_index(&world).unwrap();
            }};
        }
        check!(world.verifying_keys);
        check!(world.verifying_keys_by_circuit);
    }
}
