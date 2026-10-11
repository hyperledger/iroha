//! Controls for exhaustive authority declarations and fail-closed disclosure.

use super::*;
use std::collections::{BTreeMap, BTreeSet};

fn flatten(fields: &'static [Field], result: &mut BTreeMap<&'static str, &'static Field>) {
    for field in fields {
        assert!(
            result.insert(field.id, field).is_none(),
            "duplicate {}",
            field.id
        );
        if let Role::Canonical(Canonical::Owner(children)) = field.role {
            flatten(children, result);
        }
    }
}

fn fields() -> BTreeMap<&'static str, &'static Field> {
    let mut result = BTreeMap::new();
    flatten(STATE_FIELDS, &mut result);
    result
}

fn check_schema(schema: Schema) {
    match schema {
        Schema::Norito {
            nominal_name,
            layout,
        } => {
            assert!(!nominal_name().is_empty());
            assert_eq!(layout, V1_LAYOUT);
        }
        Schema::Semantic {
            identity,
            encoder,
            layout,
        } => {
            assert!(identity.starts_with("iroha:state:"));
            assert!(!encoder.is_empty());
            assert_eq!(layout, V1_LAYOUT);
        }
        Schema::Required {
            identity,
            obligation,
        } => {
            assert!(identity.starts_with("iroha:state:"));
            assert!(obligation.starts_with("TODO:"));
        }
    }
}

#[test]
fn authority_registry_declares_every_owner_and_typed_canonical_schema() {
    // The declaration macro also emits a no-`..` typed destructure. Adding an
    // actual field without a role fails Rust compilation before this test runs.
    assert_eq!(WORLD_FIELDS.len(), 315);
    let Role::Canonical(Canonical::Cell(Schema::Norito { nominal_name, .. })) =
        fields()["world.sumeragi_amx_participant"].role
    else {
        panic!("original native AMX participant must retain its typed canonical owner");
    };
    assert_eq!(
        nominal_name(),
        norito::schema::identity::nominal_name::<crate::sumeragi::amx::RetainedNativeAmx>(),
    );
    assert_eq!(super::runtime::RUNTIME_FIELDS.len(), 10);
    assert_eq!(
        STATE_FIELDS.len(),
        64 + usize::from(cfg!(feature = "telemetry"))
    );
    assert_eq!(
        crate::smartcontracts::isi::triggers::set::AUTHORITY_FIELDS.len(),
        10
    );
    assert_eq!(V1_LAYOUT.major, 0);
    assert_eq!(V1_LAYOUT.minor, 0);
    assert_eq!(V1_LAYOUT.flags, norito::core::header_flags::COMPACT_LEN);
    assert!(matches!(
        fields()["state.ivm_execution_budget"].role,
        Role::Local(_)
    ));
    for field in fields().values() {
        assert!(field.id.contains('.'));
        match field.role {
            Role::Canonical(Canonical::Table { key, value }) => {
                check_schema(key);
                check_schema(value);
            }
            Role::Canonical(Canonical::Cell(value)) => check_schema(value),
            Role::Canonical(Canonical::Owner(children)) => assert!(!children.is_empty()),
            Role::Derived { sources, check } => {
                assert!(!sources.is_empty());
                let (DerivationCheck::Rebuild(owner) | DerivationCheck::Commitment(owner)) = check;
                assert!(!owner.is_empty());
            }
            Role::History {
                source,
                authentication,
            } => {
                assert!(!source.is_empty());
                assert!(!authentication.is_empty());
            }
            Role::Local(reason) => assert!(!reason.is_empty()),
        }
    }
}

#[test]
fn derivations_have_real_sources_and_cannot_form_an_authority_cycle() {
    fn visit<'a>(id: &'a str, fields: &BTreeMap<&str, &Field>, stack: &mut BTreeSet<&'a str>) {
        assert!(stack.insert(id), "authority cycle at {id}");
        let field = fields
            .get(id)
            .unwrap_or_else(|| panic!("unclassified source {id}"));
        assert!(
            !matches!(field.role, Role::Local(_)),
            "derivation depends on physical field {id}"
        );
        if let Role::Derived { sources, .. } = field.role {
            for source in sources {
                visit(source, fields, stack);
            }
        }
        stack.remove(id);
    }
    let fields = fields();
    for field in fields.values() {
        if let Role::Derived { sources, .. } = field.role {
            for source in sources {
                visit(source, &fields, &mut BTreeSet::new());
            }
        }
    }
}

#[test]
fn semantic_cursors_and_mixed_configuration_are_not_physical_caches() {
    let fields = fields();
    let Role::Canonical(Canonical::Owner(children)) = fields["state.transactions"].role else {
        panic!("transaction membership must expose both complete cuts");
    };
    assert_eq!(children.len(), 3);
    assert!(matches!(
        fields["state.transactions.frontier"].role,
        Role::Canonical(Canonical::Cell(Schema::Norito { .. }))
    ));
    for id in ["state.transactions.current", "state.transactions.rollback"] {
        assert!(matches!(
            fields[id].role,
            Role::Canonical(Canonical::Table {
                key: Schema::Norito { .. },
                value: Schema::Norito { .. },
            })
        ));
    }
    for id in [
        "world.account_aliases",
        "world.da_pin_intents_by_alias",
        "world.proof_tags",
        "world.consensus_keys_by_pk",
        "world.domain_endorsements_by_domain",
        "world.twitter_bindings_by_uaid",
        "world.musubi_resolver_index_checkpoints",
        "world.musubi_resolver_index_revision",
        "world.sccp_light_clients",
        "world.sumeragi_lanes",
        "state.transactions",
        "state.canonical_runtime",
        "state.pipeline",
        "state.oracle",
        "state.crypto",
        "state.zk",
        "state.nexus",
        "state.gov",
        "state.content",
        "state.settlement",
        "state.lane_compliance",
    ] {
        assert!(matches!(fields[id].role, Role::Canonical(_)), "{id}");
    }
    for id in [
        "world.domains_by_owner",
        "world.private_settlement_recipient_index",
        "world.asset_definition_aliases",
        "world.proofs_by_tag",
        "triggers.ids",
        "triggers.active_time",
    ] {
        assert!(matches!(fields[id].role, Role::Derived { .. }), "{id}");
    }
    assert!(matches!(
        fields["state.da_pin_intents"].role,
        Role::Derived {
            sources: &[
                "world.da_pin_intents_by_ticket",
                "world.da_pin_intents_by_alias"
            ],
            check: DerivationCheck::Rebuild(_),
        }
    ));
    assert!(matches!(
        fields["world.sccp_pending_counts"].role,
        Role::Canonical(Canonical::Table { .. })
    ));
    assert!(matches!(
        fields["world.proofs_by_tag"].role,
        Role::Derived {
            sources: &["world.proof_tags"],
            check: DerivationCheck::Rebuild(_),
        }
    ));
    assert!(matches!(
        fields["world.verifying_keys_by_circuit"].role,
        Role::Derived {
            sources: &["world.verifying_keys"],
            check: DerivationCheck::Rebuild(_),
        }
    ));
    for id in [
        "world.musubi_maintainer_directory",
        "world.musubi_archive_reverse_references",
        "world.musubi_replication_shortfall_releases",
    ] {
        assert!(matches!(
            fields[id].role,
            Role::Derived {
                check: DerivationCheck::Rebuild(_),
                ..
            }
        ));
    }
    assert!(matches!(
        fields["state.lane_privacy_registry"].role,
        Role::Derived {
            check: DerivationCheck::Rebuild(_),
            ..
        }
    ));
    assert!(matches!(
        fields["state.settlement_engine"].role,
        Role::Derived {
            sources: &["state.settlement"],
            check: DerivationCheck::Rebuild(_),
        }
    ));
    for id in [
        "world.external_event_buf",
        "state.trigger_ivm_cache",
        "state.native_pending_evidence",
        "state.view_generation",
    ] {
        assert!(matches!(fields[id].role, Role::Local(_)), "{id}");
    }
}

#[test]
fn native_execution_tip_is_authenticated_history_without_a_snapshot_decoder() {
    let fields = fields();
    let tip = fields["state.native_execution_tip"];
    let Role::History {
        source,
        authentication,
    } = tip.role
    else {
        panic!("native execution tip must remain outside the World commitment");
    };
    assert!(source.contains("current and undo"));
    assert!(authentication.contains("output seal"));
    assert!(authentication.contains("configured chain/network"));
    assert_eq!(tip.disclosure, Disclosure::CommitmentOnly);
    assert!(!fields.contains_key("state.lane_consensus_contexts"));
    assert!(!fields.contains_key("state.merge_admission"));
    let witness = fields["state.native_world_cut"];
    let Role::History {
        source,
        authentication,
    } = witness.role
    else {
        panic!("retained native journal custody cannot become independent snapshot authority");
    };
    assert!(source.starts_with("Original pre-tail World"));
    assert!(source.contains("native journal"));
    assert!(authentication.contains("restoration must replay original execution"));
    assert!(authentication.contains("rather than decode a caller-supplied cut"));
    assert_eq!(witness.disclosure, Disclosure::CommitmentOnly);
}

#[test]
fn original_world_cut_retention_has_no_decoded_or_independent_authority() {
    let fields = fields();
    let cut = fields["state.native_world_cut"];
    let Role::History {
        source,
        authentication,
    } = cut.role
    else {
        panic!("original journal retention cannot add a canonical State row");
    };
    assert!(source.contains("execution tip and publication generation"));
    assert!(authentication.contains("exact root and count"));
    assert!(authentication.contains("restoration must replay original execution"));
    assert!(authentication.contains("rather than decode a caller-supplied cut"));
    assert_eq!(cut.disclosure, Disclosure::CommitmentOnly);
}

#[test]
fn authority_metadata_never_grants_raw_row_disclosure_or_completed_projection() {
    let fields = fields();
    for field in fields.values() {
        assert_eq!(
            field.disclosure,
            if matches!(field.role, Role::Local(_)) {
                Disclosure::NotApplicable
            } else {
                Disclosure::CommitmentOnly
            }
        );
    }
    assert!(matches!(
        fields["state.canonical_runtime"].role,
        Role::Canonical(Canonical::Owner(_))
    ));
    assert!(matches!(
        fields["runtime.lanes"].role,
        Role::Canonical(Canonical::Cell(Schema::Semantic { .. }))
    ));
    for id in [
        "runtime.owner_policy",
        "runtime.lane_incarnation_lineage",
        "runtime.autoscale_sample_history",
    ] {
        assert!(
            matches!(
                fields[id].role,
                Role::Canonical(Canonical::Cell(Schema::Norito { .. }))
            ),
            "{id}"
        );
    }
    for id in [
        "world.consensus_keys_by_pk",
        "world.domain_endorsements_by_domain",
        "world.twitter_bindings_by_uaid",
    ] {
        assert!(matches!(
            fields[id].role,
            Role::Canonical(Canonical::Table {
                key: Schema::Norito { .. },
                value: Schema::Norito { .. },
            })
        ));
    }
    assert!(matches!(
        fields["triggers.contracts"].role,
        Role::Canonical(Canonical::Table {
            value: Schema::Semantic { .. },
            ..
        })
    ));
    assert!(matches!(
        fields["world.musubi_archive_availability"].role,
        Role::Canonical(Canonical::Table {
            key: Schema::Norito { .. },
            value: Schema::Semantic { .. },
        })
    ));
    assert!(matches!(
        fields["state.content"].role,
        Role::Canonical(Canonical::Cell(Schema::Semantic { .. }))
    ));
    assert!(matches!(
        fields["state.crypto"].role,
        Role::Canonical(Canonical::Cell(Schema::Semantic { .. }))
    ));
    assert!(matches!(
        fields["state.oracle"].role,
        Role::Canonical(Canonical::Cell(Schema::Semantic { .. }))
    ));
    assert!(matches!(
        fields["state.pipeline"].role,
        Role::Canonical(Canonical::Cell(Schema::Semantic { .. }))
    ));
    assert!(matches!(
        fields["state.gov"].role,
        Role::Canonical(Canonical::Cell(Schema::Semantic { .. }))
    ));
    assert!(matches!(
        fields["state.zk"].role,
        Role::Canonical(Canonical::Cell(Schema::Semantic { .. }))
    ));
    assert!(matches!(
        fields["state.settlement"].role,
        Role::Canonical(Canonical::Cell(Schema::Semantic { .. }))
    ));
    assert!(matches!(
        fields["state.lane_compliance"].role,
        Role::Canonical(Canonical::Cell(Schema::Semantic { .. }))
    ));
}

#[test]
fn ordered_consensus_key_and_endorsement_vectors_bind_their_observable_order() {
    use iroha_crypto::{Hash, HashOf};
    use iroha_data_model::{
        consensus::{ConsensusKeyId, ConsensusKeyRole},
        nexus::DomainEndorsement,
    };

    let keys = vec![
        ConsensusKeyId::new(ConsensusKeyRole::Validator, "first"),
        ConsensusKeyId::new(ConsensusKeyRole::Validator, "second"),
    ];
    let mut reverse_keys = keys.clone();
    reverse_keys.reverse();
    assert_ne!(
        norito::encode_canonical(&keys).unwrap(),
        norito::encode_canonical(&reverse_keys).unwrap()
    );
    assert_eq!(
        norito::decode_canonical::<Vec<ConsensusKeyId>>(&norito::encode_canonical(&keys).unwrap())
            .unwrap(),
        keys
    );

    let endorsements = vec![
        HashOf::<DomainEndorsement>::from_untyped_unchecked(Hash::new(b"first")),
        HashOf::<DomainEndorsement>::from_untyped_unchecked(Hash::new(b"second")),
    ];
    let mut reverse_endorsements = endorsements.clone();
    reverse_endorsements.reverse();
    assert_ne!(
        norito::encode_canonical(&endorsements).unwrap(),
        norito::encode_canonical(&reverse_endorsements).unwrap()
    );
    assert_eq!(
        norito::decode_canonical::<Vec<HashOf<DomainEndorsement>>>(
            &norito::encode_canonical(&endorsements).unwrap()
        )
        .unwrap(),
        endorsements
    );

    let binding_digests = vec![Hash::new(b"binding first"), Hash::new(b"binding second")];
    let mut reverse_digests = binding_digests.clone();
    reverse_digests.reverse();
    assert_ne!(
        norito::encode_canonical(&binding_digests).unwrap(),
        norito::encode_canonical(&reverse_digests).unwrap()
    );
    assert_eq!(
        norito::decode_canonical::<Vec<Hash>>(&norito::encode_canonical(&binding_digests).unwrap())
            .unwrap(),
        binding_digests
    );
}
