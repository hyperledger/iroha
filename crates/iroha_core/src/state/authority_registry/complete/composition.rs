//! Exact, non-authorizing composition of the declared canonical State leaves.
//!
//! This draft accepts caller-supplied digests and cannot attest their row owners,
//! a finalized predecessor, Kura custody, or recovery. The complete publisher
//! must supply those proofs before this fold can become a State commitment.
//! Historical authority is rejected until that publisher has an authenticated
//! history handle. In particular this digest is never a finalized State root.
//! TODO: replace supplied digests with State-owned retained node handles, bind
//! verified Kura history and one predecessor, and publish/recover atomically.

use super::{CompleteInventoryError, require_complete_inventory, visit};
use crate::state::authority_registry::{
    Canonical, CanonicalLayout, DerivationCheck, Disclosure, Field, Role, Schema,
};
use iroha_crypto::Hash;

const START: &[u8] = b"iroha:state-canonical-composition-draft:start:v1\0";
const SCHEMA: &[u8] = b"iroha:state-canonical-composition-draft:schema:v1\0";
const FIELD: &[u8] = b"iroha:state-canonical-composition-draft:field:v1\0";
const FINISH: &[u8] = b"iroha:state-canonical-composition-draft:finish:v1\0";
const DESCRIPTOR_START: &[u8] = b"iroha:state-canonical-composition-draft:descriptor-start:v1\0";
const DESCRIPTOR_FIELD: &[u8] = b"iroha:state-canonical-composition-draft:descriptor-field:v1\0";
const DESCRIPTOR_FINISH: &[u8] = b"iroha:state-canonical-composition-draft:descriptor-finish:v1\0";
const TEXT: &[u8] = b"iroha:state-canonical-composition-draft:text:v1\0";

/// One untrusted input, in the exact declaration order of canonical leaves.
#[derive(Clone, Copy)]
pub(super) struct CanonicalLeafDigest<'a> {
    pub(super) id: &'a str,
    pub(super) digest: Hash,
}

/// A schema-bound draft only; possession conveys no State/finality authority.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct CanonicalCompositionDraft {
    digest: Hash,
    leaf_count: u64,
}

/// Refusal before any draft digest can be returned.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub(super) enum CompositionError {
    /// The declared owner inventory itself is incomplete.
    #[error(transparent)]
    Inventory(#[from] CompleteInventoryError),
    /// History has no authenticated State/Kura publication handle yet.
    #[error("State history has no authenticated composition handle: {0}")]
    UnboundHistory(&'static str),
    /// A derived row cannot inherit authority from local or unchecked derived state.
    #[error("State derivation {field} has no checked authoritative source: {table_source}")]
    UnboundDerivedSource {
        /// Identity of the derived field.
        field: &'static str,
        /// Identity of its unauthenticated source.
        table_source: &'static str,
    },
    /// A declared canonical leaf was omitted or displaced.
    #[error("State canonical composition is missing or out of order at {0}")]
    MissingOrDisplacedLeaf(&'static str),
    /// A caller added an undeclared or duplicate canonical leaf.
    #[error("State canonical composition has extra supplied leaves")]
    ExtraLeaf,
    /// A platform-size or schema length cannot enter the V1 transcript.
    #[error("State canonical composition length exceeds u64")]
    LengthOverflow,
}

fn text_digest(value: &str) -> Result<Hash, CompositionError> {
    let length = u64::try_from(value.len()).map_err(|_| CompositionError::LengthOverflow)?;
    Ok(Hash::new_from_chunks(&[
        TEXT,
        &length.to_le_bytes(),
        value.as_bytes(),
    ]))
}

fn schema_digest(field: &'static str, schema: Schema) -> Result<Hash, CompositionError> {
    let (tag, identity, encoder, layout): (
        u8,
        std::borrow::Cow<'static, str>,
        &str,
        CanonicalLayout,
    ) = match schema {
        Schema::Norito {
            nominal_name,
            layout,
        } => (0, nominal_name(), "", layout),
        Schema::Semantic {
            identity,
            encoder,
            layout,
        } => (1, std::borrow::Cow::Borrowed(identity), encoder, layout),
        Schema::Required { .. } => {
            // require_complete_inventory rejects this before composition.
            return Err(CompositionError::Inventory(
                CompleteInventoryError::RequiredSchema(field),
            ));
        }
    };
    let identity = text_digest(&identity)?;
    let encoder = text_digest(encoder)?;
    Ok(Hash::new_from_chunks(&[
        SCHEMA,
        &[tag, layout.major, layout.minor, layout.flags],
        identity.as_ref(),
        encoder.as_ref(),
    ]))
}

fn field_schema_digest(field: &'static Field) -> Result<Option<Hash>, CompositionError> {
    let role = field.role;
    match role {
        Role::Canonical(Canonical::Table { key, value }) => {
            let key = schema_digest(field.id, key)?;
            let value = schema_digest(field.id, value)?;
            Ok(Some(Hash::new_from_chunks(&[
                SCHEMA,
                &[0],
                key.as_ref(),
                value.as_ref(),
            ])))
        }
        Role::Canonical(Canonical::Cell(value)) => {
            let value = schema_digest(field.id, value)?;
            Ok(Some(Hash::new_from_chunks(&[SCHEMA, &[1], value.as_ref()])))
        }
        Role::Canonical(Canonical::Owner(_))
        | Role::Derived { .. }
        | Role::History { .. }
        | Role::Local(_) => Ok(None),
    }
}

fn field_descriptor_digest(field: &'static Field) -> Result<Hash, CompositionError> {
    let id = text_digest(field.id)?;
    let disclosure_tag = match field.disclosure {
        Disclosure::CommitmentOnly => 0,
        Disclosure::NotApplicable => 1,
    };
    let (role_tag, payload) = match field.role {
        Role::Canonical(Canonical::Table { key, value }) => {
            let key = schema_digest(field.id, key)?;
            let value = schema_digest(field.id, value)?;
            (
                0,
                Hash::new_from_chunks(&[SCHEMA, key.as_ref(), value.as_ref()]),
            )
        }
        Role::Canonical(Canonical::Cell(value)) => (1, schema_digest(field.id, value)?),
        Role::Canonical(Canonical::Owner(children)) => (2, inventory_descriptor_digest(children)?),
        Role::Derived { sources, check } => {
            let mut source_fold = Hash::new(DESCRIPTOR_START);
            for source in sources {
                let source = text_digest(source)?;
                source_fold = Hash::new_from_chunks(&[
                    DESCRIPTOR_FIELD,
                    source_fold.as_ref(),
                    source.as_ref(),
                ]);
            }
            let source_count =
                u64::try_from(sources.len()).map_err(|_| CompositionError::LengthOverflow)?;
            let (tag, procedure) = match check {
                DerivationCheck::Rebuild(procedure) => (3, procedure),
                DerivationCheck::Commitment(procedure) => (6, procedure),
            };
            let procedure = text_digest(procedure)?;
            (
                tag,
                Hash::new_from_chunks(&[
                    DESCRIPTOR_FINISH,
                    source_fold.as_ref(),
                    &source_count.to_le_bytes(),
                    procedure.as_ref(),
                ]),
            )
        }
        Role::History {
            source,
            authentication,
        } => {
            let source = text_digest(source)?;
            let authentication = text_digest(authentication)?;
            (
                4,
                Hash::new_from_chunks(&[
                    DESCRIPTOR_FINISH,
                    source.as_ref(),
                    authentication.as_ref(),
                ]),
            )
        }
        Role::Local(reason) => (5, text_digest(reason)?),
    };
    Ok(Hash::new_from_chunks(&[
        DESCRIPTOR_FIELD,
        id.as_ref(),
        &[role_tag, disclosure_tag],
        payload.as_ref(),
    ]))
}

fn inventory_descriptor_digest(fields: &'static [Field]) -> Result<Hash, CompositionError> {
    let mut fold = Hash::new(DESCRIPTOR_START);
    for field in fields {
        let descriptor = field_descriptor_digest(field)?;
        fold = Hash::new_from_chunks(&[DESCRIPTOR_FIELD, fold.as_ref(), descriptor.as_ref()]);
    }
    let count = u64::try_from(fields.len()).map_err(|_| CompositionError::LengthOverflow)?;
    Ok(Hash::new_from_chunks(&[
        DESCRIPTOR_FINISH,
        fold.as_ref(),
        &count.to_le_bytes(),
    ]))
}

fn role_for_id(fields: &'static [Field], id: &str) -> Option<Role> {
    let mut found = None;
    visit(fields, &mut |field| {
        if field.id == id {
            found = Some(field.role);
        }
    });
    found
}

fn reject_unbound_derived_sources(fields: &'static [Field]) -> Result<(), CompositionError> {
    let mut error = None;
    visit(fields, &mut |field| {
        if error.is_some() {
            return;
        }
        if let Role::Derived { sources, .. } = field.role {
            for source in sources {
                // Existence and uniqueness were checked by require_complete_inventory.
                // A textual Rebuild descriptor does not establish that another
                // derived source has actually been reconstructed and checked.
                if !matches!(
                    role_for_id(fields, source),
                    Some(Role::Canonical(_) | Role::History { .. })
                ) {
                    error = Some(CompositionError::UnboundDerivedSource {
                        field: field.id,
                        table_source: source,
                    });
                    break;
                }
            }
        }
    });
    error.map_or(Ok(()), Err)
}

/// Fold every declared canonical table/cell exactly once in declaration order.
///
/// This checks only the inventory and supplied digest identities. The actual
/// State inventory still fails closed on unbound derived sources and history.
/// Even a synthetic successful draft does not authenticate the supplied roots.
fn compose_canonical_draft(
    fields: &'static [Field],
    leaves: &[CanonicalLeafDigest<'_>],
) -> Result<CanonicalCompositionDraft, CompositionError> {
    require_complete_inventory(fields)?;
    reject_unbound_derived_sources(fields)?;
    let descriptor = inventory_descriptor_digest(fields)?;
    let mut history = None;
    visit(fields, &mut |field| {
        if history.is_none() && matches!(field.role, Role::History { .. }) {
            history = Some(field.id);
        }
    });
    if let Some(field) = history {
        return Err(CompositionError::UnboundHistory(field));
    }

    let mut digest = Hash::new(START);
    let mut count = 0_usize;
    let mut error = None;
    visit(fields, &mut |field| {
        if error.is_some() {
            return;
        }
        let schema = match field_schema_digest(field) {
            Ok(Some(schema)) => schema,
            Ok(None) => return,
            Err(failure) => {
                error = Some(failure);
                return;
            }
        };
        let Some(input) = leaves.get(count) else {
            error = Some(CompositionError::MissingOrDisplacedLeaf(field.id));
            return;
        };
        if input.id != field.id {
            error = Some(CompositionError::MissingOrDisplacedLeaf(field.id));
            return;
        }
        let (Ok(id_len), Some(next_count)) = (u64::try_from(field.id.len()), count.checked_add(1))
        else {
            error = Some(CompositionError::LengthOverflow);
            return;
        };
        digest = Hash::new_from_chunks(&[
            FIELD,
            digest.as_ref(),
            &id_len.to_le_bytes(),
            field.id.as_bytes(),
            schema.as_ref(),
            input.digest.as_ref(),
        ]);
        count = next_count;
    });
    if let Some(error) = error {
        return Err(error);
    }
    if count != leaves.len() {
        return Err(CompositionError::ExtraLeaf);
    }
    let leaf_count = u64::try_from(count).map_err(|_| CompositionError::LengthOverflow)?;
    Ok(CanonicalCompositionDraft {
        digest: Hash::new_from_chunks(&[
            FINISH,
            descriptor.as_ref(),
            digest.as_ref(),
            &leaf_count.to_le_bytes(),
        ]),
        leaf_count,
    })
}

/// Non-authorizing actual-State probe, pinned to the exhaustive typed inventory.
///
/// Inventory metadata admission does not bind derived sources or Kura history,
/// so this cannot return a digest. Synthetic inventories remain test-only.
#[cfg(test)]
fn compose_actual_state_draft(
    leaves: &[CanonicalLeafDigest<'_>],
) -> Result<CanonicalCompositionDraft, CompositionError> {
    compose_canonical_draft(super::super::STATE_FIELDS, leaves)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::authority_registry::schema;

    const CHILDREN: &[Field] = &[
        Field::new(
            "test.rows",
            Role::Canonical(Canonical::Table {
                key: schema::<u64>(),
                value: schema::<u64>(),
            }),
        ),
        Field::new(
            "test.cell",
            Role::Canonical(Canonical::Cell(Schema::Semantic {
                identity: "test:cell:v1",
                encoder: "test_cell_encoder",
                layout: crate::state::authority_registry::V1_LAYOUT,
            })),
        ),
    ];
    const FIELDS: &[Field] = &[
        Field::new("test.owner", Role::Canonical(Canonical::Owner(CHILDREN))),
        Field::new(
            "test.derived",
            Role::Derived {
                sources: &["test.rows"],
                check: DerivationCheck::Rebuild("rebuild_test_index"),
            },
        ),
        Field::new("test.local", Role::Local("transient worker")),
    ];
    const OTHER_CHILDREN: &[Field] = &[
        CHILDREN[0],
        Field::new(
            "test.cell",
            Role::Canonical(Canonical::Cell(Schema::Semantic {
                identity: "test:other-cell:v1",
                encoder: "test_cell_encoder",
                layout: crate::state::authority_registry::V1_LAYOUT,
            })),
        ),
    ];
    const OTHER_FIELDS: &[Field] = &[Field::new(
        "test.owner",
        Role::Canonical(Canonical::Owner(OTHER_CHILDREN)),
    )];
    const REWRAPPED_CHILDREN: &[Field] = &[Field::new(
        "test.nested-owner",
        Role::Canonical(Canonical::Owner(CHILDREN)),
    )];
    const REWRAPPED_FIELDS: &[Field] = &[
        Field::new(
            "test.owner",
            Role::Canonical(Canonical::Owner(REWRAPPED_CHILDREN)),
        ),
        FIELDS[1],
        FIELDS[2],
    ];
    const RENAMED_OWNER_FIELDS: &[Field] = &[
        Field::new(
            "test.renamed-owner",
            Role::Canonical(Canonical::Owner(CHILDREN)),
        ),
        FIELDS[1],
        FIELDS[2],
    ];
    const OTHER_ENCODER_CHILDREN: &[Field] = &[
        CHILDREN[0],
        Field::new(
            "test.cell",
            Role::Canonical(Canonical::Cell(Schema::Semantic {
                identity: "test:cell:v1",
                encoder: "other_test_cell_encoder",
                layout: crate::state::authority_registry::V1_LAYOUT,
            })),
        ),
    ];
    const OTHER_ENCODER_FIELDS: &[Field] = &[
        Field::new(
            "test.owner",
            Role::Canonical(Canonical::Owner(OTHER_ENCODER_CHILDREN)),
        ),
        FIELDS[1],
        FIELDS[2],
    ];
    const OTHER_DERIVATION_SOURCE_FIELDS: &[Field] = &[
        FIELDS[0],
        Field::new(
            "test.derived",
            Role::Derived {
                sources: &["test.cell"],
                check: DerivationCheck::Rebuild("rebuild_test_index"),
            },
        ),
        FIELDS[2],
    ];
    const OTHER_DERIVATION_CHECK_FIELDS: &[Field] = &[
        FIELDS[0],
        Field::new(
            "test.derived",
            Role::Derived {
                sources: &["test.rows"],
                check: DerivationCheck::Rebuild("rebuild_other_test_index"),
            },
        ),
        FIELDS[2],
    ];
    const ORDERED_DERIVATION_SOURCES: &[Field] = &[
        FIELDS[0],
        Field::new(
            "test.derived",
            Role::Derived {
                sources: &["test.rows", "test.cell"],
                check: DerivationCheck::Rebuild("rebuild_test_index"),
            },
        ),
        FIELDS[2],
    ];
    const REVERSED_DERIVATION_SOURCES: &[Field] = &[
        FIELDS[0],
        Field::new(
            "test.derived",
            Role::Derived {
                sources: &["test.cell", "test.rows"],
                check: DerivationCheck::Rebuild("rebuild_test_index"),
            },
        ),
        FIELDS[2],
    ];
    const OTHER_LOCAL_FIELDS: &[Field] = &[
        FIELDS[0],
        FIELDS[1],
        Field::new("test.local", Role::Local("different transient worker")),
    ];

    fn leaves() -> [CanonicalLeafDigest<'static>; 2] {
        [
            CanonicalLeafDigest {
                id: "test.rows",
                digest: Hash::new(b"rows"),
            },
            CanonicalLeafDigest {
                id: "test.cell",
                digest: Hash::new(b"cell"),
            },
        ]
    }

    #[test]
    fn nested_canonical_draft_rejects_omission_reorder_duplicate_and_extra() {
        let exact = leaves();
        let draft = compose_canonical_draft(FIELDS, &exact).expect("complete synthetic draft");
        assert_eq!(draft.leaf_count, 2);
        assert_eq!(
            compose_canonical_draft(FIELDS, &exact[..1]),
            Err(CompositionError::MissingOrDisplacedLeaf("test.cell"))
        );
        assert_eq!(
            compose_canonical_draft(FIELDS, &[exact[1], exact[0]]),
            Err(CompositionError::MissingOrDisplacedLeaf("test.rows"))
        );
        assert_eq!(
            compose_canonical_draft(FIELDS, &[exact[0], exact[0]]),
            Err(CompositionError::MissingOrDisplacedLeaf("test.cell"))
        );
        assert_eq!(
            compose_canonical_draft(FIELDS, &[exact[0], exact[1], exact[0]]),
            Err(CompositionError::ExtraLeaf)
        );
    }

    #[test]
    fn draft_binds_field_schema_and_supplied_digest_without_certifying_it() {
        let exact = leaves();
        let original = compose_canonical_draft(FIELDS, &exact).unwrap();
        let mut changed = exact;
        changed[1].digest = Hash::new(b"substituted cell");
        assert_ne!(original, compose_canonical_draft(FIELDS, &changed).unwrap());
        assert_ne!(
            original,
            compose_canonical_draft(OTHER_FIELDS, &exact).unwrap(),
            "same leaf bytes under a different semantic schema"
        );
    }

    #[test]
    fn draft_binds_owner_hierarchy_and_all_noncanonical_descriptors() {
        let exact = leaves();
        let original = compose_canonical_draft(FIELDS, &exact).unwrap();
        for changed in [
            REWRAPPED_FIELDS,
            RENAMED_OWNER_FIELDS,
            OTHER_ENCODER_FIELDS,
            OTHER_DERIVATION_SOURCE_FIELDS,
            OTHER_DERIVATION_CHECK_FIELDS,
            OTHER_LOCAL_FIELDS,
        ] {
            assert_ne!(
                original,
                compose_canonical_draft(changed, &exact).unwrap(),
                "same leaf digests must bind the complete declared inventory"
            );
        }
        assert_ne!(
            compose_canonical_draft(ORDERED_DERIVATION_SOURCES, &exact).unwrap(),
            compose_canonical_draft(REVERSED_DERIVATION_SOURCES, &exact).unwrap(),
            "declared reconstruction source order must be bound"
        );
    }

    #[test]
    fn descriptor_binds_history_tags_and_authentication_even_while_history_is_unbound() {
        const ORIGINAL: &[Field] = &[Field::new(
            "test.history",
            Role::History {
                source: "finalized source",
                authentication: "Kura owner",
            },
        )];
        const CHANGED_AUTHENTICATION: &[Field] = &[Field::new(
            "test.history",
            Role::History {
                source: "finalized source",
                authentication: "different Kura owner",
            },
        )];
        const CHANGED_SOURCE: &[Field] = &[Field::new(
            "test.history",
            Role::History {
                source: "different finalized source",
                authentication: "Kura owner",
            },
        )];
        const CHANGED_ROLE: &[Field] = &[Field::new("test.history", Role::Local("runtime cursor"))];
        assert_ne!(
            inventory_descriptor_digest(ORIGINAL).unwrap(),
            inventory_descriptor_digest(CHANGED_AUTHENTICATION).unwrap()
        );
        assert_ne!(
            inventory_descriptor_digest(ORIGINAL).unwrap(),
            inventory_descriptor_digest(CHANGED_SOURCE).unwrap()
        );
        assert_ne!(
            inventory_descriptor_digest(ORIGINAL).unwrap(),
            inventory_descriptor_digest(CHANGED_ROLE).unwrap()
        );
        assert_eq!(
            compose_canonical_draft(ORIGINAL, &[]),
            Err(CompositionError::Inventory(
                CompleteInventoryError::HistoryDescriptorMismatch("test.history")
            ))
        );
    }

    #[test]
    fn derived_sources_cannot_resolve_to_local_or_unchecked_derived_state() {
        const LOCAL_SOURCE: &[Field] = &[
            Field::new("test.local", Role::Local("runtime cache")),
            Field::new(
                "test.derived",
                Role::Derived {
                    sources: &["test.local"],
                    check: DerivationCheck::Rebuild("rebuild_index"),
                },
            ),
        ];
        const DERIVED_SOURCE: &[Field] = &[
            Field::new(
                "test.cell",
                Role::Canonical(Canonical::Cell(schema::<u64>())),
            ),
            Field::new(
                "test.first-derived",
                Role::Derived {
                    sources: &["test.cell"],
                    check: DerivationCheck::Rebuild("rebuild_first"),
                },
            ),
            Field::new(
                "test.second-derived",
                Role::Derived {
                    sources: &["test.first-derived"],
                    check: DerivationCheck::Rebuild("rebuild_second"),
                },
            ),
        ];
        assert_eq!(
            compose_canonical_draft(LOCAL_SOURCE, &[]),
            Err(CompositionError::Inventory(
                CompleteInventoryError::NonAuthoritySource("test.local")
            ))
        );
        assert_eq!(
            compose_canonical_draft(DERIVED_SOURCE, &[]),
            Err(CompositionError::UnboundDerivedSource {
                field: "test.second-derived",
                table_source: "test.first-derived",
            })
        );
    }

    #[test]
    fn history_and_actual_state_remain_unbound_after_schema_admission() {
        const HISTORY: &[Field] = &[
            Field::new(
                "test.cell",
                Role::Canonical(Canonical::Cell(schema::<u64>())),
            ),
            Field::new(
                "state.block_hashes",
                Role::History {
                    source: "Canonical SignedBlockWire/finality history in height order",
                    authentication: "Kura authenticated recovery prefix; State block-hash publication owner",
                },
            ),
        ];
        let leaf = [CanonicalLeafDigest {
            id: "test.cell",
            digest: Hash::new(b"cell"),
        }];
        assert_eq!(
            compose_canonical_draft(HISTORY, &leaf),
            Err(CompositionError::UnboundHistory("state.block_hashes"))
        );
        assert_eq!(super::super::require_complete_state_inventory(), Ok(()));
        // Even a caller supplying every canonical identity and a digest for each
        // cannot substitute for checked source ownership or authenticated history.
        let mut supplied = Vec::new();
        visit(super::super::super::STATE_FIELDS, &mut |field| {
            if matches!(
                field.role,
                Role::Canonical(Canonical::Cell(_) | Canonical::Table { .. })
            ) {
                supplied.push(CanonicalLeafDigest {
                    id: field.id,
                    digest: Hash::new(field.id.as_bytes()),
                });
            }
        });
        assert_eq!(
            compose_actual_state_draft(&supplied),
            Err(CompositionError::UnboundDerivedSource {
                field: "world.account_scope_directory",
                table_source: "world.uaid_dataspaces",
            })
        );
    }

    #[test]
    fn inventory_disclosure_violation_precedes_digest_composition() {
        const INVALID: &[Field] = &[Field {
            id: "test.cell",
            role: Role::Canonical(Canonical::Cell(schema::<u64>())),
            disclosure: Disclosure::NotApplicable,
        }];
        let leaf = [CanonicalLeafDigest {
            id: "test.cell",
            digest: Hash::new(b"cell"),
        }];
        assert_eq!(
            compose_canonical_draft(INVALID, &leaf),
            Err(CompositionError::Inventory(
                CompleteInventoryError::DisclosureMismatch("test.cell")
            ))
        );
    }
}
