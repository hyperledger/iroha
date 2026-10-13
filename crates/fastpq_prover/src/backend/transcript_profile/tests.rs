//! Identity, record and constant tests of the frozen q77 transcript profile.
//!
//! The pinned identities are goldens: a change of any descriptor parameter
//! changes them, and the pins, the workloads record and every measurement
//! that names the previous identity are then replaced in the same change.

use fastpq_isi::semantic_profile::{
    SemanticProfileKindV1, SemanticProfileOwnedValueV1 as Owned, SemanticProfileV1,
};

use super::{
    super::{
        air::q77,
        compact_model_statement::candidate_artifact::{
            execution_effect_profile_id, quantity_diagnostic_profile_id,
        },
        compact_public_columns::LAYOUT_ID,
        frozen_record::{as_u64, field, list, optional, profile_entry, record, text},
    },
    *,
};

/// SHA3-256 identity of the frozen transcript profile descriptor.
const IDENTITY: &str = "b1b3be0bc1b548e32fa6f949500c0de43c8f7412a5586623c4d3f1ca705f945b";
/// Exact length of the canonical descriptor frame.
const FRAME_BYTES: usize = 3_871;
/// `FastpqCompactProfileIdV1` of the AXT quantity artifact descriptor.
const QUANTITY_ARTIFACT_PROFILE: &str =
    "4f0ece59b3f42d1c318f597b0df2f5af8b8db41bc95dfbb11974ddb285f20b0b";
/// `FastpqCompactProfileIdV1` of the ordinary execution-effect artifact descriptor.
const EXECUTION_EFFECT_ARTIFACT_PROFILE: &str =
    "e4b83c36dca6915f908d6509ef43511ae6da1b8254cb2724b2b6fe00918779b8";

fn value_of(key: &str) -> Owned {
    profile()
        .parameters()
        .into_iter()
        .find(|(candidate, _)| candidate == key)
        .unwrap_or_else(|| panic!("descriptor has no `{key}` parameter"))
        .1
}

fn count(key: &str) -> usize {
    let Owned::U64(number) = value_of(key) else {
        panic!("`{key}` is not an integer");
    };
    usize::try_from(number).unwrap()
}

fn counts(key: &str) -> Vec<usize> {
    let Owned::U64List(values) = value_of(key) else {
        panic!("`{key}` is not a list");
    };
    values
        .into_iter()
        .map(|value| usize::try_from(value).unwrap())
        .collect()
}

#[test]
fn frozen_identity_frame_and_artifact_profile_ids_are_pinned() {
    let profile = profile();
    assert_eq!(profile.kind(), SemanticProfileKindV1::Transcript);
    assert_eq!(profile.name(), NAME);
    assert_eq!(profile.as_bytes().len(), FRAME_BYTES);
    assert_eq!(profile.id().to_string(), IDENTITY);
    // The public accessor returns the same descriptor the transcript absorbs.
    assert!(core::ptr::eq(q77::transcript_profile(), profile));
    // The descriptor is canonical and stable across decode and re-encode.
    let (decoded, parameters) = SemanticProfileV1::decode(profile.as_bytes()).unwrap();
    assert_eq!(&decoded, profile);
    assert_eq!(parameters, profile.parameters());
    // The artifact wire digests embed the same descriptor bytes and are pinned.
    eprintln!(
        "quantity_artifact_profile={} execution_effect_artifact_profile={}",
        hex::encode(quantity_diagnostic_profile_id().0),
        hex::encode(execution_effect_profile_id().0)
    );
    assert_eq!(
        hex::encode(quantity_diagnostic_profile_id().0),
        QUANTITY_ARTIFACT_PROFILE
    );
    assert_eq!(
        hex::encode(execution_effect_profile_id().0),
        EXECUTION_EFFECT_ARTIFACT_PROFILE
    );
    for flags in [0, norito::core::header_flags::COMPACT_LEN] {
        let _flags = norito::core::DecodeFlagsGuard::enter(flags);
        assert_eq!(
            hex::encode(quantity_diagnostic_profile_id().0),
            QUANTITY_ARTIFACT_PROFILE
        );
    }
}

#[test]
fn descriptor_reads_the_engine_constants() {
    let engine = q77::PROFILE;
    assert_eq!(count("trace_rows"), engine.trace_rows);
    assert_eq!(count("columns"), engine.columns);
    assert_eq!(count("committed_columns"), engine.committed_columns);
    assert_eq!(count("public_columns"), engine.public_columns);
    assert_eq!(
        count("columns"),
        count("committed_columns") + count("public_columns")
    );
    assert_eq!(count("constraints"), engine.constraints);
    assert_eq!(count("evaluation_rows"), engine.evaluation_rows);
    assert_eq!(counts("fri_arities"), engine.fri_arities);
    assert_eq!(counts("fri_lengths"), engine.fri_lengths);
    assert_eq!(counts("fri_degree_bounds"), engine.fri_degree_bounds);
    assert_eq!(count("queries"), engine.queries);
    assert_eq!(count("query_candidates"), engine.query_candidates);
    assert_eq!(
        count("trace_mask_coefficients"),
        engine.trace_mask_coefficients
    );
    assert_eq!(
        count("quotient_mask_coefficients"),
        engine.quotient_mask_coefficients
    );
    assert_eq!(count("max_frame_bytes"), engine.max_frame_bytes);
    assert_eq!(
        count("max_relation_identity_bytes"),
        crate::air::MAX_RELATION_IDENTITY_BYTES
    );
    assert_eq!(
        count("max_statement_bytes"),
        crate::air::MAX_STATEMENT_BYTES
    );
    // Derived relations between the bound numbers.
    assert_eq!(count("ood_answers"), 2 * count("committed_columns") + 2);
    assert_eq!(count("deep_components"), 2 * count("committed_columns") + 4);
    assert_eq!(count("terminal_values"), counts("fri_lengths")[5]);
    assert_eq!(
        count("terminal_degree_bound"),
        counts("fri_degree_bounds")[5]
    );
    assert_eq!(
        count("composition_mask_coefficients"),
        counts("fri_degree_bounds")[0]
    );
    assert_eq!(count("extension_bytes"), 8 * count("extension_degree"));
    assert_eq!(count("commitment_bytes"), 32);
    assert_eq!(
        count("max_merkle_path_levels"),
        count("evaluation_rows").ilog2() as usize
    );
    assert_eq!(count("max_fri_layers"), counts("fri_lengths").len());
    assert_eq!(
        count("max_fiber_values"),
        counts("fri_arities").into_iter().max().unwrap()
    );
    assert_eq!(
        count("structural_work_charge"),
        q77::VerifierLimits::exact(0).work.max_work_units
    );
    assert_eq!(
        count("max_decode_allocation_charges"),
        q77::VerifierLimits::exact(0).max_decode_allocation_charges
    );
    let tapes = counts("tape_bytes");
    assert_eq!(tapes.len(), 10);
    assert_eq!(tapes.iter().sum::<usize>(), 30_920);
    assert_eq!(tapes[1], 8 * (4 * count("constraints") + 6));
    assert_eq!(tapes[9], 8 * count("query_raw_words"));
    assert_eq!(count("grinding_bits"), 0);
    assert_eq!(value_of("grinding_nonce"), Owned::Text("none".to_owned()));
    assert_eq!(
        value_of("construction"),
        Owned::Text(CONSTRUCTION.to_owned())
    );
    assert_eq!(count("framing_version"), usize::from(FRAMING_VERSION));
    // The roots generate the domains the descriptor names.
    let Owned::U64(trace_root) = value_of("trace_root") else {
        panic!("trace root");
    };
    let Owned::U64(evaluation_root) = value_of("evaluation_root") else {
        panic!("evaluation root");
    };
    let blowup = (count("evaluation_rows") / count("trace_rows")) as u64;
    assert_eq!(super::super::field_pow(evaluation_root, blowup), trace_root);
    assert_eq!(
        super::super::field_pow(trace_root, count("trace_rows") as u64),
        1
    );
}

#[test]
fn descriptor_holds_semantic_data_only() {
    // No parameter is a source, build or binary digest, a measurement, a
    // qualification status or a caller ceiling: no key names one, and the
    // descriptor carries no opaque digest at all.
    for (key, value) in profile().parameters() {
        for token in key.split('_') {
            assert!(
                ![
                    "source",
                    "build",
                    "binary",
                    "revision",
                    "toolchain",
                    "commit",
                    "git",
                    "measurement",
                    "measured",
                    "qualification",
                    "review",
                    "caller",
                    "policy",
                    "sha256",
                    "digest",
                ]
                .contains(&token),
                "parameter `{key}` names evidence metadata or policy"
            );
        }
        assert!(
            !matches!(value, Owned::Bytes(_)),
            "parameter `{key}` is an opaque digest"
        );
    }
    // The statement-bound data stays in the context, not in the descriptor.
    for (key, value) in profile().parameters() {
        assert_ne!(key, "relation");
        assert_ne!(key, "statement");
        assert_ne!(value, Owned::Text(LAYOUT_ID.to_owned()));
    }
}

#[test]
fn workloads_record_names_this_descriptor_and_every_dependent_measurement() {
    let profile = profile();
    let entry = profile_entry(NAME);
    assert_eq!(text(entry, "kind"), profile.kind().label());
    assert_eq!(text(entry, "status"), "frozen");
    assert_eq!(text(entry, "identity"), profile.id().to_string());
    // The recorded parameter list is this descriptor, in order and by type.
    let recorded: Vec<(String, Owned)> = list(entry, "parameters")
        .iter()
        .map(|parameter| {
            let value = field(parameter, "value");
            let value = match text(parameter, "type") {
                "u64" => Owned::U64(as_u64(value)),
                "text" => Owned::Text(value.as_str().unwrap().to_owned()),
                "bytes" => Owned::Bytes(hex::decode(value.as_str().unwrap()).unwrap()),
                "u64-list" => {
                    Owned::U64List(value.as_array().unwrap().iter().map(as_u64).collect())
                }
                other => panic!("unknown recorded value type `{other}`"),
            };
            (text(parameter, "key").to_owned(), value)
        })
        .collect();
    assert_eq!(recorded, profile.parameters());

    let section = field(record(), "semantic_profiles");
    let shared = field(section, "shared_transcript");
    assert_eq!(text(shared, "profile"), NAME);
    assert_eq!(text(shared, "construction"), CONSTRUCTION);
    assert_eq!(
        as_u64(field(field(shared, "grinding"), "bits")),
        GRINDING_BITS
    );
    let ids = field(field(shared, "goldens"), "artifact_profile_ids");
    assert_eq!(text(ids, "quantity_axt"), QUANTITY_ARTIFACT_PROFILE);
    assert_eq!(
        text(ids, "execution_effect"),
        EXECUTION_EFFECT_ARTIFACT_PROFILE
    );

    // Every shared-backend workload depends on this profile, and every
    // measurement that names the profile names the current identity. A
    // measurement taken under another identity does not describe this profile.
    let workloads = field(record(), "workloads");
    let mut dependent = 0;
    let mut bound = 0;
    for workload in list(workloads, "definitions") {
        let names: Vec<_> = list(workload, "profiles")
            .iter()
            .map(|name| name.as_str().unwrap())
            .collect();
        if text(workload, "kind") == "shared-backend" {
            assert!(
                names.contains(&NAME),
                "workload {} does not name the transcript profile",
                text(workload, "id")
            );
            dependent += 1;
        }
        let Some(measurements) = optional(workload, "exploratory_measurements") else {
            continue;
        };
        for measurement in measurements.as_array().unwrap() {
            let identities = field(measurement, "profile_identities")
                .as_object()
                .unwrap();
            if let Some(identity) = identities.get(NAME) {
                assert_eq!(
                    identity.as_str().unwrap(),
                    IDENTITY,
                    "measurement {} was taken under another transcript identity and is inapplicable",
                    text(measurement, "id")
                );
                assert!(names.contains(&NAME));
                bound += 1;
            }
        }
    }
    assert!(dependent >= 13, "shared-backend workloads: {dependent}");
    assert!(
        bound >= 1,
        "no recorded measurement names the frozen identity"
    );
}
