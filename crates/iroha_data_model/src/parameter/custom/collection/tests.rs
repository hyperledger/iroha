//! Canonical map identity, fallible authoring and retained lifetime regressions.

use super::*;
use iroha_primitives::json::Json;
use norito::codec::Encode as _;

fn parameter(id: &str, value: u32) -> CustomParameter {
    CustomParameter::new(id.parse().unwrap(), Json::new(value))
}

fn source() -> CustomParameters {
    CustomParameters::try_from_iter([
        parameter("alpha_parameter_identity_longer_than_inline_storage", 1),
        parameter("zeta_parameter_identity_longer_than_inline_storage", 2),
    ])
    .unwrap()
}

fn structural_bytes(source: &CustomParameters) -> usize {
    let id_layouts: Vec<_> = source
        .values()
        .filter_map(|parameter| parameter.id.name().admission_clone_layout())
        .collect();
    Layout::array::<CustomParameter>(source.len())
        .unwrap()
        .size()
        + Layout::array::<AllocationCharge>(id_layouts.len())
            .unwrap()
            .size()
        + id_layouts.iter().map(Layout::size).sum::<usize>()
}

#[test]
fn authored_replacements_keep_one_sorted_identity_and_read_api() {
    let mut parameters = CustomParameters::new();
    assert!(parameters.is_empty());
    assert!(
        parameters
            .try_insert(parameter("zeta", 1))
            .unwrap()
            .is_none()
    );
    assert!(
        parameters
            .try_insert(parameter("alpha", 2))
            .unwrap()
            .is_none()
    );
    assert_eq!(
        parameters.insert(parameter("zeta", 3)).unwrap().payload,
        Json::new(1_u32)
    );
    assert_eq!(parameters.len(), 2);
    let alpha = "alpha".parse().unwrap();
    assert!(parameters.contains_key(&alpha));
    assert_eq!(parameters[&alpha].payload, Json::new(2_u32));
    assert_eq!(
        parameters
            .keys()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        ["alpha", "zeta"]
    );
    assert_eq!((&parameters).into_iter().count(), parameters.values().len());
    assert_eq!(parameters.try_remove(&alpha).unwrap().unwrap().id, alpha);
    assert!(parameters.remove(&alpha).is_none());
    let rebuilt: CustomParameters = [parameter("zeta", 2), parameter("zeta", 3)]
        .into_iter()
        .collect();
    assert_eq!(rebuilt, parameters);
    assert_eq!(parameters, parameters.clone());
    assert_eq!(parameters.partial_cmp(&rebuilt), Some(Ordering::Equal));
    assert!(format!("{parameters:?}").contains("zeta"));
}

#[test]
fn framed_binary_json_and_schema_have_one_map_owner() {
    let parameters = source();
    let bytes = norito::encode_canonical(&parameters).unwrap();
    assert_eq!(
        norito::decode_canonical::<CustomParameters>(&bytes).unwrap(),
        parameters
    );
    let json = json::to_json(&parameters).unwrap();
    assert_eq!(
        json::from_str::<CustomParameters>(&json).unwrap(),
        parameters
    );
    assert_eq!(
        super::super::json_helpers::from_value(json::from_str(&json).unwrap()).unwrap(),
        parameters
    );
    let bounded = json::to_json(&parameters).unwrap();
    let mut plain = String::new();
    parameters.json_serialize(&mut plain);
    assert_eq!(bounded, plain);
    assert_eq!(
        <CustomParameters as iroha_schema::TypeId>::id(),
        "CustomParameters"
    );
    assert_eq!(
        <CustomParameters as norito::NoritoSchema>::nominal_name(),
        "iroha_data_model::parameter::CustomParameters"
    );
    let mut map = iroha_schema::MetaMap::new();
    <CustomParameters as iroha_schema::IntoSchema>::update_schema_map(&mut map);
    assert!(map.contains_key::<CustomParameters>());
    assert!(map.contains_key::<CustomParameter>());
}

#[test]
fn json_rejects_duplicate_reversed_mismatched_and_ambiguous_records() {
    for invalid in [
        r#"{"alpha":{"id":"alpha","payload":1},"alpha":{"id":"alpha","payload":2}}"#,
        r#"{"zeta":{"id":"zeta","payload":1},"alpha":{"id":"alpha","payload":2}}"#,
        r#"{"alpha":{"id":"zeta","payload":1}}"#,
        r#"{"alpha":{"id":"alpha","id":"alpha","payload":1}}"#,
        r#"{"alpha":{"id":"alpha","payload":1,"payload":2}}"#,
        r#"{"alpha":{"id":"alpha","payload":1,"unknown":2}}"#,
        r#"{"alpha":{"payload":1}}"#,
        r#"{"alpha":{"id":"alpha"}}"#,
    ] {
        assert!(
            json::from_str::<CustomParameters>(invalid).is_err(),
            "{invalid}"
        );
    }
}

// Deliberately build hostile entries using the same fixed V1 prefixes and leaf
// encoders, bypassing only the collection writer's strict-order assertion.
fn hostile_map(entries: &[(CustomParameterId, CustomParameter)]) -> Vec<u8> {
    let flags = core::default_encode_flags();
    let mut bytes = (entries.len() as u64).to_le_bytes().to_vec();
    for (key, value) in entries {
        for field in [key.encode(), value.encode()] {
            core::write_len_to_vec_with_flags(&mut bytes, field.len() as u64, flags);
            bytes.extend_from_slice(&field);
        }
    }
    bytes
}

#[test]
fn binary_rejects_duplicate_reversed_and_mismatched_identity() {
    let alpha = parameter("alpha", 1);
    let zeta = parameter("zeta", 2);
    for entries in [
        vec![
            (alpha.id.clone(), alpha.clone()),
            (alpha.id.clone(), alpha.clone()),
        ],
        vec![
            (zeta.id.clone(), zeta.clone()),
            (alpha.id.clone(), alpha.clone()),
        ],
        vec![(alpha.id.clone(), zeta.clone())],
    ] {
        let bytes = hostile_map(&entries);
        let _context =
            core::PayloadCtxGuard::enter_with_flags(&bytes, core::default_encode_flags());
        assert!(matches!(
            CustomParameters::decode_from_slice(&bytes),
            Err(norito::Error::LengthMismatch)
        ));
    }
    let bytes = hostile_map(&[
        (alpha.id.clone(), alpha.clone()),
        (zeta.id.clone(), zeta.clone()),
    ]);
    let _context = core::PayloadCtxGuard::enter_with_flags(&bytes, core::default_encode_flags());
    let (decoded, used) = CustomParameters::decode_from_slice(&bytes).unwrap();
    assert_eq!(used, bytes.len());
    assert_eq!(decoded, [alpha, zeta].into_iter().collect());
}

#[test]
fn zero_and_partial_graph_refusals_refund_then_retry_exact_source() {
    let source = source();
    let bytes = source.encode();
    let pool = AllocationBudget::new(0);
    assert!(matches!(
        source.try_retain_in(&pool),
        Err(CustomParametersAdmissionError::Admission(_))
    ));
    assert_eq!(pool.reserved_bytes(), 0);
    // Fund the whole structure and only the first JSON leaf. The second leaf
    // fails after real partial construction and must refund every earlier owner.
    let probe = AllocationBudget::new(1 << 20);
    let first_leaf = source
        .values()
        .next()
        .unwrap()
        .payload
        .try_retain_in(&probe)
        .unwrap();
    let first_leaf_bytes = probe.reserved_bytes();
    drop(first_leaf);
    pool.set_limit_bytes(structural_bytes(&source) + first_leaf_bytes);
    assert!(matches!(
        source.try_retain_in(&pool),
        Err(CustomParametersAdmissionError::Json(_))
    ));
    assert_eq!(pool.reserved_bytes(), 0);
    assert_eq!(source.encode(), bytes);
    pool.set_limit_bytes(1 << 20);
    let retained = source.try_retain_in(&pool).unwrap();
    let exact = pool.reserved_bytes();
    assert!(retained.belongs_to(&pool));
    assert_eq!(retained, source);
    drop(retained);
    assert_eq!(pool.reserved_bytes(), 0);
    pool.set_limit_bytes(exact - 1);
    assert!(source.try_retain_in(&pool).is_err());
    assert_eq!(pool.reserved_bytes(), 0);
    pool.set_limit_bytes(exact);
    drop(source.try_retain_in(&pool).unwrap());
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn fallible_authoring_refuses_array_growth_and_copy_before_mutation() {
    let source = source();
    let before = source.encode();
    let mut empty = CustomParameters::new();
    let next = parameter("new", 3);
    let zero = norito::DecodeLimits::new(0, 0, 0, 0, 0);
    let insert = core::DecodeBudgetContext::new(zero).with(|| empty.try_insert(next));
    assert!(
        matches!(insert, Err(CustomParametersAdmissionError::Codec(error)) if error.is_decode_resource_limit())
    );
    assert!(empty.is_empty());
    let copy = core::DecodeBudgetContext::new(zero).with(|| source.try_clone_for_authoring());
    assert!(
        matches!(copy, Err(CustomParametersAdmissionError::Codec(error)) if error.is_decode_resource_limit())
    );
    assert_eq!(source.encode(), before);
    assert_eq!(source.try_clone_for_authoring().unwrap(), source);
}

#[test]
fn escaped_json_and_same_pool_siblings_retain_original_backing_until_last_drop() {
    let source = source();
    let pool = AllocationBudget::new(1 << 20);
    let first = source.try_retain_in(&pool).unwrap();
    let first_total = pool.reserved_bytes();
    let escaped = first.values().next().unwrap().payload.clone();
    let second = first.try_retain_in(&pool).unwrap();
    assert_eq!(
        pool.reserved_bytes(),
        first_total + structural_bytes(&source)
    );
    assert!(Json::ptr_eq(
        &first.values().next().unwrap().payload,
        &second.values().next().unwrap().payload
    ));
    drop(first);
    assert_eq!(pool.reserved_bytes(), first_total);
    drop(second);
    assert!(pool.reserved_bytes() > 0);
    assert!(escaped.belongs_to(&pool));
    drop(escaped);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn foreign_pool_cannot_claim_original_custody_and_authoring_clone_has_no_authority() {
    let pool = AllocationBudget::new(1 << 20);
    let foreign = AllocationBudget::new(1 << 20);
    let retained = source().try_retain_in(&pool).unwrap();
    assert!(!retained.belongs_to(&foreign));
    let copied = retained.try_retain_in(&foreign).unwrap();
    assert!(copied.belongs_to(&foreign));
    assert!(!Json::ptr_eq(
        &retained.values().next().unwrap().payload,
        &copied.values().next().unwrap().payload
    ));
    let mut authored = retained.try_clone_for_authoring().unwrap();
    assert!(!authored.belongs_to(&pool));
    assert!(!retained.clone().belongs_to(&pool));
    authored.try_insert(parameter("new", 3)).unwrap();
    drop(authored);
    drop(retained);
    assert_eq!(pool.reserved_bytes(), 0);
    assert!(foreign.reserved_bytes() > 0);
    drop(copied);
    assert_eq!(foreign.reserved_bytes(), 0);
}

#[test]
fn retained_mutation_refuses_before_touching_bytes_and_empty_pool_is_identity_bound() {
    let pool = AllocationBudget::new(1 << 20);
    let mut retained = source().try_retain_in(&pool).unwrap();
    let before = retained.encode();
    let charge = pool.reserved_bytes();
    let id = retained.keys().next().unwrap().clone();
    for parameter in [
        parameter("new", 3),
        CustomParameter::new(id.clone(), Json::new(4_u32)),
    ] {
        assert!(matches!(
            retained.try_insert(parameter),
            Err(CustomParametersAdmissionError::RetainedMutation)
        ));
    }
    assert!(matches!(
        retained.try_remove(&id),
        Err(CustomParametersAdmissionError::RetainedMutation)
    ));
    assert_eq!(retained.encode(), before);
    assert_eq!(pool.reserved_bytes(), charge);
    let zero = AllocationBudget::new(0);
    let foreign = AllocationBudget::new(0);
    let empty = CustomParameters::new().try_retain_in(&zero).unwrap();
    assert!(empty.belongs_to(&zero));
    assert!(!empty.belongs_to(&foreign));
    assert!(!CustomParameters::default().belongs_to(&zero));
}

#[test]
fn borrowed_update_keeps_sorted_insert_replace_remove_without_source_mutation() {
    let pool = AllocationBudget::new(1 << 20);
    let source: CustomParameters = [parameter("bravo", 2), parameter("delta", 4)]
        .into_iter()
        .collect();
    let source = source.try_retain_in(&pool).unwrap();
    let original = source.encode();
    for replacement in [
        parameter("alpha", 1),
        parameter("charlie", 3),
        parameter("echo", 5),
        parameter("bravo", 22),
    ] {
        let updated = source
            .try_with_update(&replacement.id, Some(&replacement), &pool)
            .unwrap();
        let mut expected = source.try_clone_for_authoring().unwrap();
        expected.insert(replacement.clone());
        assert_eq!(updated, expected);
        assert!(updated.belongs_to(&pool));
        assert_eq!(source.encode(), original);
        assert!(source.belongs_to(&pool));
    }
    for id in ["alpha", "bravo", "delta", "echo"] {
        let id = id.parse().unwrap();
        let updated = source.try_with_update(&id, None, &pool).unwrap();
        let mut expected = source.try_clone_for_authoring().unwrap();
        expected.remove(&id);
        assert_eq!(updated, expected);
        assert!(updated.belongs_to(&pool));
        assert_eq!(source.encode(), original);
    }
    let one: CustomParameters = [parameter("alpha", 1)].into_iter().collect();
    let empty = one
        .try_with_update(&"alpha".parse().unwrap(), None, &pool)
        .unwrap();
    assert!(empty.is_empty() && empty.belongs_to(&pool));
    drop((source, empty));
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn borrowed_update_mismatch_and_every_partial_refusal_preserve_predecessor() {
    let pool = AllocationBudget::new(1 << 20);
    let source = source().try_retain_in(&pool).unwrap();
    let original = source.encode();
    let baseline = pool.reserved_bytes();
    let replacement = parameter("middle_parameter_identity_longer_than_inline_storage", 3);
    let id = "different".parse().unwrap();
    pool.set_limit_bytes(baseline);
    assert!(matches!(
        source.try_with_update(&id, Some(&replacement), &pool),
        Err(CustomParametersAdmissionError::KeyValueMismatch)
    ));
    assert_eq!(pool.reserved_bytes(), baseline);
    let (refused, requests) = crate::amx_prepare_streaming_allocations::measured(|| {
        source.try_with_update(&replacement.id, Some(&replacement), &pool)
    });
    assert!(matches!(
        refused,
        Err(CustomParametersAdmissionError::Admission(_))
    ));
    assert_eq!(
        requests,
        [0, 0, 0],
        "no ordinary draft is copied before admission"
    );
    let mut failures = 0;
    let mut success = false;
    for extra in (0..8192).step_by(17) {
        pool.set_limit_bytes(baseline + extra);
        match source.try_with_update(&replacement.id, Some(&replacement), &pool) {
            Err(CustomParametersAdmissionError::Admission(_))
            | Err(CustomParametersAdmissionError::Json(JsonRetentionError::Admission(_))) => {
                failures += 1
            }
            Err(error) => panic!("unexpected finite-pool update cause: {error:?}"),
            Ok(updated) => {
                assert!(updated.belongs_to(&pool));
                assert_eq!(updated[&replacement.id], replacement);
                drop(updated);
                success = true;
                break;
            }
        }
        assert_eq!(source.encode(), original);
        assert_eq!(pool.reserved_bytes(), baseline);
    }
    assert!(failures > 2 && success);
    assert_eq!(pool.reserved_bytes(), baseline);
    assert_eq!(source.encode(), original);
    drop(source);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn borrowed_same_pool_update_shares_json_and_foreign_update_copies_custody() {
    let pool = AllocationBudget::new(1 << 20);
    let foreign = AllocationBudget::new(1 << 20);
    let source = source().try_retain_in(&pool).unwrap();
    let first = source.values().next().unwrap();
    let same = source
        .try_with_update(&first.id, Some(first), &pool)
        .unwrap();
    assert!(same.belongs_to(&pool));
    assert_eq!(&same, &source);
    assert_eq!(
        same[&first.id].payload.get().as_ptr(),
        first.payload.get().as_ptr()
    );
    let other = source
        .try_with_update(&first.id, Some(first), &foreign)
        .unwrap();
    assert!(other.belongs_to(&foreign));
    assert!(!other.belongs_to(&pool));
    assert_ne!(
        other[&first.id].payload.get().as_ptr(),
        first.payload.get().as_ptr()
    );
    let escaped = same[&first.id].payload.clone();
    drop((same, source));
    assert!(pool.reserved_bytes() > 0);
    drop(escaped);
    assert_eq!(pool.reserved_bytes(), 0);
    assert!(foreign.reserved_bytes() > 0);
    drop(other);
    assert_eq!(foreign.reserved_bytes(), 0);
}
