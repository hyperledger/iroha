//! Fail-closed admission of the complete State authority inventory.
//!
//! The registry describes every physical owner, but a description with a
//! `Required` schema is not a complete commitment schema. Admission checks only
//! schema metadata; it never grants captured-row, publication or finality authority.
//! Derived dependencies must terminate in canonical values or authenticated
//! history; an owner container or a node-local cache cannot supply authority.
//! TODO: fund and consume this check in the State/Kura publication capsule.

use super::leaf::{CanonicalTableLeafSet, CanonicalTablePairedSnapshot, LeafError, LeafLimits};
use super::{Canonical, DerivationCheck, Disclosure, Field, Role, STATE_FIELDS, Schema, V1_LAYOUT};
use crate::state::{State, is_stable_state_view_generation};
use mv::storage::StorageReadOnly;

const BLOCK_HISTORY_SOURCE: &str = "Canonical SignedBlockWire/finality history in height order";
const BLOCK_HISTORY_AUTHENTICATION: &str =
    "Kura authenticated recovery prefix; State block-hash publication owner";
// These exact descriptors audit classification only; the opaque native execution
// owner and verified restore prefix remain the source of execution authority.
const NATIVE_EXECUTION_HISTORY_SOURCE: &str = "Original native height, Iroha hash, core header hash and execution result; current and undo cuts outside World";
const NATIVE_EXECUTION_HISTORY_AUTHENTICATION: &str = "Original worker verified exact quorum and output seal, or original signed-genesis execution; restore verifies the actual certified native prefix and configured chain/network before accepting snapshot claims";
const NATIVE_WORLD_CUT_HISTORY_SOURCE: &str = "Original pre-tail World root, count and native journal differences bound to the execution tip and publication generation";
const NATIVE_WORLD_CUT_HISTORY_AUTHENTICATION: &str = "Original completed executor captures R; frozen publication reconstructs that exact root and count from the complete native tail journal; restoration must replay original execution rather than decode a caller-supplied cut";
#[path = "complete/native_capture.rs"]
mod native_capture;
pub(crate) use native_capture::{
    capture_account_alias_table_once, capture_accounts_table_once, capture_domains_table_once,
};

#[path = "complete/frozen_verifying_keys.rs"]
pub(in crate::state) mod frozen_verifying_keys;

#[path = "complete/frozen_proofs.rs"]
pub(in crate::state) mod frozen_proofs;

#[path = "complete/frozen_domain_ownership.rs"]
pub(in crate::state) mod frozen_domain_ownership;

#[path = "complete/frozen_account_identity.rs"]
pub(in crate::state) mod frozen_account_identity;

#[path = "complete/frozen_account_aliases.rs"]
pub(in crate::state) mod frozen_account_aliases;

#[path = "complete/frozen_contract_subjects.rs"]
pub(in crate::state) mod frozen_contract_subjects;

mod frozen_account_rekeys;
#[path = "complete/frozen_escrows.rs"]
pub(in crate::state) mod frozen_escrows;
#[path = "complete/frozen_nfts_rwas.rs"]
mod frozen_nfts_rwas;
mod frozen_repo_agreements;
#[path = "complete/frozen_trigger_actions.rs"]
mod frozen_trigger_actions;
#[path = "complete/frozen_trigger_contracts.rs"]
mod frozen_trigger_contracts;

#[path = "complete/frozen_assets.rs"]
pub(in crate::state) mod frozen_assets;

#[path = "complete/frozen_asset_definitions.rs"]
pub(in crate::state) mod frozen_asset_definitions;

#[path = "complete/frozen_contract_aliases.rs"]
pub(in crate::state) mod frozen_contract_aliases;

#[path = "complete/frozen_validation_fee_proposals.rs"]
pub(in crate::state) mod frozen_validation_fee_proposals;

#[path = "complete/grouped_capture.rs"]
mod grouped_capture;
pub(crate) use grouped_capture::{
    capture_account_rekey_records_once, capture_asset_definitions_once, capture_assets_once,
    capture_contract_alias_bindings_once, capture_contract_subject_bindings_once,
    capture_escrows_once, capture_governance_proposals_once, capture_nfts_once,
    capture_proofs_once, capture_repo_agreements_once, capture_rwas_once,
    capture_verifying_keys_once,
};

/// A field that cannot yet participate in a complete State commitment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum CompleteInventoryError {
    /// Stable field identities must be unique across nested owners.
    #[error("duplicate State authority identity: {0}")]
    DuplicateIdentity(&'static str),
    /// An unfinished semantic projection blocks complete-root publication.
    #[error("State authority has no complete V1 schema: {0}")]
    RequiredSchema(&'static str),
    /// Only the fixed first-release Norito layout can be committed.
    #[error("State authority uses a non-V1 layout: {0}")]
    NonV1Layout(&'static str),
    /// Empty identities or reconstruction procedures cannot identify authority.
    #[error("State authority descriptor is incomplete: {0}")]
    IncompleteDescriptor(&'static str),
    /// A secondary index names authority that is absent from this inventory.
    #[error("State derivation names an unknown or ambiguous source: {0}")]
    UnknownSource(&'static str),
    /// A derived index cannot obtain authority from a local field or owner container.
    #[error("State derivation depends on a non-authoritative source: {0}")]
    NonAuthoritySource(&'static str),
    /// A circular derivation has no independently authenticated base.
    #[error("State derivation contains a cycle: {0}")]
    DerivationCycle(&'static str),
    /// Historical authority must use an exact reviewed source and owner descriptor.
    #[error("State history authority has an unrecognized field or descriptor: {0}")]
    HistoryDescriptorMismatch(&'static str),
    /// Disclosure policy must agree with the classified role.
    #[error("State authority disclosure policy differs from its role: {0}")]
    DisclosureMismatch(&'static str),
}

fn visit(fields: &'static [Field], action: &mut dyn FnMut(&'static Field)) {
    for field in fields {
        action(field);
        if let Role::Canonical(Canonical::Owner(children)) = field.role {
            visit(children, action);
        }
    }
}

fn count_identity(fields: &'static [Field], identity: &str) -> usize {
    let mut count = 0;
    visit(fields, &mut |field| {
        if field.id == identity {
            count += 1;
        }
    });
    count
}

fn find_identity(fields: &'static [Field], identity: &str) -> Option<&'static Field> {
    let mut found = None;
    visit(fields, &mut |field| {
        if field.id == identity {
            found = Some(field);
        }
    });
    found
}

fn check_history_field(
    field: &'static Field,
    source: &str,
    authentication: &str,
) -> Result<(), CompleteInventoryError> {
    if source.is_empty() || authentication.is_empty() {
        return Err(CompleteInventoryError::IncompleteDescriptor(field.id));
    }
    let expected = match field.id {
        "state.block_hashes" => (BLOCK_HISTORY_SOURCE, BLOCK_HISTORY_AUTHENTICATION),
        "state.native_execution_tip" => (
            NATIVE_EXECUTION_HISTORY_SOURCE,
            NATIVE_EXECUTION_HISTORY_AUTHENTICATION,
        ),
        "state.native_world_cut" => (
            NATIVE_WORLD_CUT_HISTORY_SOURCE,
            NATIVE_WORLD_CUT_HISTORY_AUTHENTICATION,
        ),
        _ => return Err(CompleteInventoryError::HistoryDescriptorMismatch(field.id)),
    };
    if (source, authentication) == expected {
        Ok(())
    } else {
        Err(CompleteInventoryError::HistoryDescriptorMismatch(field.id))
    }
}

mod derivation_path;
use derivation_path::DerivationPath;

fn check_derivation_source(
    fields: &'static [Field],
    source: &'static str,
    active: &DerivationPath<'_>,
) -> Result<(), CompleteInventoryError> {
    if count_identity(fields, source) != 1 {
        return Err(CompleteInventoryError::UnknownSource(source));
    }
    if active.contains(source) {
        return Err(CompleteInventoryError::DerivationCycle(source));
    }
    let field = find_identity(fields, source).expect("unique derivation source remains registered");
    match field.role {
        Role::Canonical(Canonical::Table { .. } | Canonical::Cell(_)) => Ok(()),
        Role::History {
            source,
            authentication,
        } => check_history_field(field, source, authentication),
        Role::Canonical(Canonical::Owner(_)) | Role::Local(_) => {
            Err(CompleteInventoryError::NonAuthoritySource(source))
        }
        Role::Derived { sources, .. } => {
            let next = active.child(source);
            sources
                .iter()
                .try_for_each(|source| check_derivation_source(fields, source, &next))
        }
    }
}

fn check_schema(field: &'static Field, schema: Schema) -> Result<(), CompleteInventoryError> {
    match schema {
        Schema::Norito {
            nominal_name,
            layout,
        } => {
            if layout != V1_LAYOUT {
                return Err(CompleteInventoryError::NonV1Layout(field.id));
            }
            if nominal_name().is_empty() {
                return Err(CompleteInventoryError::IncompleteDescriptor(field.id));
            }
        }
        Schema::Semantic {
            identity,
            encoder,
            layout,
        } => {
            if layout != V1_LAYOUT {
                return Err(CompleteInventoryError::NonV1Layout(field.id));
            }
            if identity.is_empty() || encoder.is_empty() {
                return Err(CompleteInventoryError::IncompleteDescriptor(field.id));
            }
        }
        Schema::Required { .. } => {
            return Err(CompleteInventoryError::RequiredSchema(field.id));
        }
    }
    Ok(())
}

fn check_field(
    fields: &'static [Field],
    field: &'static Field,
) -> Result<(), CompleteInventoryError> {
    if field.id.is_empty() {
        return Err(CompleteInventoryError::IncompleteDescriptor(field.id));
    }
    let expected_disclosure = if matches!(field.role, Role::Local(_)) {
        Disclosure::NotApplicable
    } else {
        Disclosure::CommitmentOnly
    };
    if field.disclosure != expected_disclosure {
        return Err(CompleteInventoryError::DisclosureMismatch(field.id));
    }
    match field.role {
        Role::Canonical(Canonical::Table { key, value }) => {
            check_schema(field, key)?;
            check_schema(field, value)?;
        }
        Role::Canonical(Canonical::Cell(schema)) => check_schema(field, schema)?,
        Role::Canonical(Canonical::Owner(children)) => {
            if children.is_empty() {
                return Err(CompleteInventoryError::IncompleteDescriptor(field.id));
            }
        }
        Role::Derived { sources, check } => {
            let (DerivationCheck::Rebuild(procedure) | DerivationCheck::Commitment(procedure)) =
                check;
            if sources.is_empty()
                || sources.iter().any(|source| source.is_empty())
                || procedure.is_empty()
            {
                return Err(CompleteInventoryError::IncompleteDescriptor(field.id));
            }
            match check {
                DerivationCheck::Rebuild(_) => {
                    let active = DerivationPath::root(field.id);
                    sources
                        .iter()
                        .try_for_each(|source| check_derivation_source(fields, source, &active))?;
                }
                // A commitment derives from whole owners: their canonical descendants.
                DerivationCheck::Commitment(_) => {
                    for &source in sources {
                        if count_identity(fields, source) != 1 {
                            return Err(CompleteInventoryError::UnknownSource(source));
                        }
                        let owner = find_identity(fields, source)
                            .expect("unique commitment source remains registered");
                        if !matches!(owner.role, Role::Canonical(Canonical::Owner(_))) {
                            return Err(CompleteInventoryError::NonAuthoritySource(source));
                        }
                    }
                }
            }
        }
        Role::History {
            source,
            authentication,
        } => check_history_field(field, source, authentication)?,
        Role::Local(reason) => {
            if reason.is_empty() {
                return Err(CompleteInventoryError::IncompleteDescriptor(field.id));
            }
        }
    }
    Ok(())
}

/// Admit a fully described V1 inventory, including all nested World/trigger owners.
///
/// This checks schema and classification only. A successful result does not
/// prove complete row traversal, derived-index reconstruction, durable root
/// custody, or finality.
pub(crate) fn require_complete_inventory(
    fields: &'static [Field],
) -> Result<(), CompleteInventoryError> {
    let mut result = Ok(());
    visit(fields, &mut |field| {
        if result.is_err() {
            return;
        }
        result = if count_identity(fields, field.id) != 1 {
            Err(CompleteInventoryError::DuplicateIdentity(field.id))
        } else {
            check_field(fields, field)
        };
    });
    result
}

/// Admit the actual typed inventory's schema metadata, without capturing State authority.
pub(crate) fn require_complete_state_inventory() -> Result<(), CompleteInventoryError> {
    require_complete_inventory(STATE_FIELDS)
}

mod composition;
pub(in crate::state) mod table_capture;

#[cfg(test)]
#[path = "complete/native_history_tests.rs"]
mod native_history_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::authority_registry::schema;
    use crate::{kura::Kura, query::store::LiveQueryStore, state::World};
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_data_model::{
        Registrable,
        account::{Account, AccountId, rekey::AccountAlias},
    };
    use iroha_model_base::topology::DataSpaceId;

    fn alias_limits() -> LeafLimits {
        LeafLimits {
            max_tables: 1,
            max_rows: 8,
            max_payload_bytes: 4 * 1024,
            max_ordered_table_bytes: 32 * 1024,
            max_streamed_value_bytes: 8 * 1024 * 1024,
        }
    }

    #[test]
    fn actual_world_alias_rows_are_captured_once_per_stable_state_generation() {
        let first_owner = AccountId::new(
            KeyPair::from_seed(b"complete-state-first-account".to_vec(), Algorithm::Ed25519)
                .public_key()
                .clone(),
        );
        let second_owner = AccountId::new(
            KeyPair::from_seed(
                b"complete-state-second-account".to_vec(),
                Algorithm::Ed25519,
            )
            .public_key()
            .clone(),
        );
        let first_alias = AccountAlias::domainless(
            "first".parse().expect("alias label"),
            DataSpaceId::UNIVERSAL,
        );
        let second_alias = AccountAlias::domainless(
            "second".parse().expect("alias label"),
            DataSpaceId::UNIVERSAL,
        );
        let mut world = World::with(
            [],
            [
                Account::new(first_owner.clone()).build(&first_owner),
                Account::new(second_owner.clone()).build(&second_owner),
            ],
            [],
        );
        world
            .account_aliases
            .insert(first_alias.clone(), first_owner.clone());
        world
            .account_aliases
            .insert(second_alias.clone(), second_owner.clone());
        world.rebuild_account_alias_index().unwrap();
        let mut state = State::new_for_testing(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let limits = alias_limits();
        let captured = capture_account_alias_table_once(&state, limits)
            .expect("bounded table")
            .expect("stable generation");
        let same = capture_account_alias_table_once(&state, limits)
            .expect("bounded table")
            .expect("stable generation");
        assert_eq!(captured.root(), same.root());
        let first_proof = captured
            .prove_lookup("world.account_aliases", &first_alias)
            .expect("included alias");
        assert!(
            CanonicalTableLeafSet::verify_paired_lookup(
                "world.account_aliases",
                limits,
                &captured.root(),
                &captured.ordered_root(),
                &first_alias,
                &first_proof,
            )
            .expect("authentic alias path")
            .is_some()
        );
        let mut canonical_rows = vec![
            (
                norito::codec::encode_adaptive(&first_alias),
                norito::codec::encode_adaptive(&first_owner),
            ),
            (
                norito::codec::encode_adaptive(&second_alias),
                norito::codec::encode_adaptive(&second_owner),
            ),
        ];
        canonical_rows.sort_unstable_by(|left, right| left.0.cmp(&right.0));
        let range = captured
            .prove_raw_range(&canonical_rows[0].0, &canonical_rows[1].0, 1, 8 * 1024)
            .expect("bounded exact raw-key interval");
        let verified = CanonicalTableLeafSet::verify_paired_raw_range(
            "world.account_aliases",
            limits,
            &captured.root(),
            &captured.lookup_root(),
            &captured.ordered_root(),
            &canonical_rows[0].0,
            &canonical_rows[1].0,
            1,
            8 * 1024,
            &range,
        )
        .expect("complete scoped interval");
        assert_eq!(
            verified
                .rows()
                .map(|(key, _)| key.to_vec())
                .collect::<Vec<_>>(),
            vec![canonical_rows[0].0.clone()]
        );
        let expected_owner = if canonical_rows[0].0 == norito::codec::encode_adaptive(&first_alias)
        {
            &first_owner
        } else {
            &second_owner
        };
        CanonicalTableLeafSet::verify_paired_value_preimage(
            "world.account_aliases",
            limits,
            &verified,
            &canonical_rows[0].0,
            expected_owner,
        )
        .expect("complete canonical alias value preimage");
        let omitted = CanonicalTableLeafSet::paired_table_from_rows(
            "world.account_aliases",
            limits,
            &state
                .pipeline_ivm_prepared_cache
                .read()
                .execution_budget()
                .clone(),
            [(&first_alias, &first_owner)],
        )
        .expect("bounded omitted-row control");
        assert_ne!(captured.root(), omitted.root(), "omitted authoritative row");

        let mut publication = state.state_view_publication();
        let guard = publication.begin();
        assert!(
            capture_account_alias_table_once(&state, limits)
                .expect("busy generation is a local retry")
                .is_none(),
            "publication generation must never yield a scoped root"
        );
        drop(guard);
        drop(publication);

        state
            .world
            .account_aliases
            .insert(first_alias.clone(), second_owner);
        state.world.rebuild_account_alias_index().unwrap();
        let substituted = capture_account_alias_table_once(&state, limits)
            .expect("bounded substituted table")
            .expect("stable generation");
        assert_ne!(
            captured.root(),
            substituted.root(),
            "same-key value substitution"
        );
    }

    #[test]
    fn every_current_derived_source_resolves_to_one_actual_inventory_identity() {
        let mut checked = 0;
        visit(STATE_FIELDS, &mut |field| {
            if let Role::Derived { sources, check } = field.role {
                for source in sources {
                    assert_eq!(
                        count_identity(STATE_FIELDS, source),
                        1,
                        "{} names unclassified derivation source {}",
                        field.id,
                        source
                    );
                    if let DerivationCheck::Commitment(_) = check {
                        // A commitment derives from a whole owner's canonical values.
                        assert!(
                            matches!(
                                find_identity(STATE_FIELDS, source).map(|owner| owner.role),
                                Some(Role::Canonical(Canonical::Owner(_)))
                            ),
                            "{} commits to a non-owner {source}",
                            field.id
                        );
                        checked += 1;
                        continue;
                    }
                    check_derivation_source(STATE_FIELDS, source, &DerivationPath::root(field.id))
                        .unwrap_or_else(|error| {
                            panic!(
                                "{} has an unauthenticated derivation chain: {error}",
                                field.id
                            )
                        });
                    checked += 1;
                }
            }
        });
        assert!(
            checked > 40,
            "expected to audit the nested State/World links"
        );
    }

    #[test]
    fn historical_derivation_base_is_closed_and_bound_to_its_state_field() {
        for id in [
            "state.block_hashes",
            "state.native_execution_tip",
            "state.native_world_cut",
        ] {
            let field = find_identity(STATE_FIELDS, id).expect("actual history owner");
            let Role::History {
                source,
                authentication,
            } = field.role
            else {
                panic!("{id} must retain its historical authority class");
            };
            assert_eq!(check_history_field(field, source, authentication), Ok(()));
        }

        const WRONG_HISTORY_FIELD: &[Field] = &[Field::new(
            "test.forged_history",
            Role::History {
                source: BLOCK_HISTORY_SOURCE,
                authentication: BLOCK_HISTORY_AUTHENTICATION,
            },
        )];
        assert_eq!(
            require_complete_inventory(WRONG_HISTORY_FIELD),
            Err(CompleteInventoryError::HistoryDescriptorMismatch(
                "test.forged_history"
            ))
        );
        const DERIVED_FROM_WRONG_HISTORY: &[Field] = &[
            Field::new(
                "test.derived",
                Role::Derived {
                    sources: &["test.forged_history"],
                    check: DerivationCheck::Rebuild("rebuild"),
                },
            ),
            Field::new(
                "test.forged_history",
                Role::History {
                    source: BLOCK_HISTORY_SOURCE,
                    authentication: BLOCK_HISTORY_AUTHENTICATION,
                },
            ),
        ];
        assert_eq!(
            require_complete_inventory(DERIVED_FROM_WRONG_HISTORY),
            Err(CompleteInventoryError::HistoryDescriptorMismatch(
                "test.forged_history"
            ))
        );

        const WRONG_SOURCE: &[Field] = &[Field::new(
            "state.block_hashes",
            Role::History {
                source: "arbitrary history",
                authentication: BLOCK_HISTORY_AUTHENTICATION,
            },
        )];
        assert_eq!(
            require_complete_inventory(WRONG_SOURCE),
            Err(CompleteInventoryError::HistoryDescriptorMismatch(
                "state.block_hashes"
            ))
        );
        const WRONG_OWNER: &[Field] = &[Field::new(
            "state.block_hashes",
            Role::History {
                source: BLOCK_HISTORY_SOURCE,
                authentication: "unverified owner",
            },
        )];
        assert_eq!(
            require_complete_inventory(WRONG_OWNER),
            Err(CompleteInventoryError::HistoryDescriptorMismatch(
                "state.block_hashes"
            ))
        );
        const EMPTY_SOURCE: &[Field] = &[Field::new(
            "state.block_hashes",
            Role::History {
                source: "",
                authentication: BLOCK_HISTORY_AUTHENTICATION,
            },
        )];
        assert_eq!(
            require_complete_inventory(EMPTY_SOURCE),
            Err(CompleteInventoryError::IncompleteDescriptor(
                "state.block_hashes"
            ))
        );
    }

    #[test]
    fn nested_inventory_checks_schema_uniqueness_and_classification() {
        const GOOD_CHILD: &[Field] = &[Field::new(
            "test.rows",
            Role::Canonical(Canonical::Table {
                key: schema::<u64>(),
                value: schema::<u64>(),
            }),
        )];
        const GOOD: &[Field] = &[Field::new(
            "test.owner",
            Role::Canonical(Canonical::Owner(GOOD_CHILD)),
        )];
        assert_eq!(require_complete_inventory(GOOD), Ok(()));
        const DUPLICATE: &[Field] = &[
            Field::new("test.same", Role::Local("first")),
            Field::new("test.same", Role::Local("second")),
        ];
        assert_eq!(
            require_complete_inventory(DUPLICATE),
            Err(CompleteInventoryError::DuplicateIdentity("test.same"))
        );
        const REQUIRED: &[Field] = &[Field::new(
            "test.required",
            Role::Canonical(Canonical::Cell(Schema::Required {
                identity: "test:required:v1",
                obligation: "TODO: implement the canonical projection",
            })),
        )];
        assert_eq!(
            require_complete_inventory(REQUIRED),
            Err(CompleteInventoryError::RequiredSchema("test.required"))
        );
        const WRONG_LAYOUT: &[Field] = &[Field::new(
            "test.old_layout",
            Role::Canonical(Canonical::Cell(Schema::Semantic {
                identity: "test:old-layout:v1",
                encoder: "test encoder",
                layout: super::super::CanonicalLayout {
                    major: 0,
                    minor: 0,
                    flags: 0,
                },
            })),
        )];
        assert_eq!(
            require_complete_inventory(WRONG_LAYOUT),
            Err(CompleteInventoryError::NonV1Layout("test.old_layout"))
        );
        const MISSING_SOURCE: &[Field] = &[Field::new(
            "test.derived",
            Role::Derived {
                sources: &[],
                check: DerivationCheck::Rebuild("rebuild"),
            },
        )];
        assert_eq!(
            require_complete_inventory(MISSING_SOURCE),
            Err(CompleteInventoryError::IncompleteDescriptor("test.derived"))
        );
        const UNKNOWN_SOURCE: &[Field] = &[Field::new(
            "test.derived",
            Role::Derived {
                sources: &["test.missing"],
                check: DerivationCheck::Rebuild("rebuild"),
            },
        )];
        assert_eq!(
            require_complete_inventory(UNKNOWN_SOURCE),
            Err(CompleteInventoryError::UnknownSource("test.missing"))
        );
        const LOCAL_SOURCE: &[Field] = &[
            Field::new("test.local", Role::Local("physical cache")),
            Field::new(
                "test.derived",
                Role::Derived {
                    sources: &["test.local"],
                    check: DerivationCheck::Rebuild("rebuild"),
                },
            ),
        ];
        assert_eq!(
            require_complete_inventory(LOCAL_SOURCE),
            Err(CompleteInventoryError::NonAuthoritySource("test.local"))
        );
        const OWNER_SOURCE: &[Field] = &[
            Field::new("test.owner", Role::Canonical(Canonical::Owner(GOOD_CHILD))),
            Field::new(
                "test.derived",
                Role::Derived {
                    sources: &["test.owner"],
                    check: DerivationCheck::Rebuild("rebuild"),
                },
            ),
        ];
        assert_eq!(
            require_complete_inventory(OWNER_SOURCE),
            Err(CompleteInventoryError::NonAuthoritySource("test.owner"))
        );
        const INDIRECT_LOCAL_SOURCE: &[Field] = &[
            Field::new(
                "test.outer",
                Role::Derived {
                    sources: &["test.middle"],
                    check: DerivationCheck::Rebuild("outer"),
                },
            ),
            Field::new(
                "test.middle",
                Role::Derived {
                    sources: &["test.local"],
                    check: DerivationCheck::Rebuild("middle"),
                },
            ),
            Field::new("test.local", Role::Local("physical cache")),
        ];
        assert_eq!(
            require_complete_inventory(INDIRECT_LOCAL_SOURCE),
            Err(CompleteInventoryError::NonAuthoritySource("test.local"))
        );
        const DERIVATION_CYCLE: &[Field] = &[
            Field::new(
                "test.first",
                Role::Derived {
                    sources: &["test.second"],
                    check: DerivationCheck::Rebuild("first"),
                },
            ),
            Field::new(
                "test.second",
                Role::Derived {
                    sources: &["test.first"],
                    check: DerivationCheck::Rebuild("second"),
                },
            ),
        ];
        assert_eq!(
            require_complete_inventory(DERIVATION_CYCLE),
            Err(CompleteInventoryError::DerivationCycle("test.first"))
        );
        const VALID_DERIVATION: &[Field] = &[
            Field::new(
                "test.rows",
                Role::Canonical(Canonical::Table {
                    key: schema::<u64>(),
                    value: schema::<u64>(),
                }),
            ),
            Field::new(
                "test.middle",
                Role::Derived {
                    sources: &["test.rows"],
                    check: DerivationCheck::Rebuild("middle"),
                },
            ),
            Field::new(
                "test.outer",
                Role::Derived {
                    sources: &["test.middle"],
                    check: DerivationCheck::Rebuild("outer"),
                },
            ),
        ];
        assert_eq!(require_complete_inventory(VALID_DERIVATION), Ok(()));
        const INVALID_DISCLOSURE: &[Field] = &[Field {
            id: "test.rows",
            role: Role::Canonical(Canonical::Cell(schema::<u64>())),
            disclosure: Disclosure::NotApplicable,
        }];
        assert_eq!(
            require_complete_inventory(INVALID_DISCLOSURE),
            Err(CompleteInventoryError::DisclosureMismatch("test.rows"))
        );
    }
}

// The grouped catalog retains both roots with the same-writer frontier and surface.
// TODO: consume that owner through complete State/Kura publication and recovery.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "TODO: complete State publication must consume the retained membership frontier"
    )
)]
#[path = "complete/transaction_membership.rs"]
mod transaction_membership;
