//! Tests for compute economics governance bounds and sponsor caps.
use iroha_config::parameters::{actual::ComputeEconomics, defaults, user};
use iroha_config_base::{read::ConfigReader, toml::TomlSource};
use iroha_data_model::compute::{
    ComputeGovernanceError, ComputePriceDeltaBounds, ComputePriceRiskClass, ComputePriceWeights,
    ComputeSponsorPolicy,
};
use iroha_model_base::name::Name;
use std::{
    collections::BTreeMap,
    num::{NonZeroU16, NonZeroU64},
    str::FromStr,
};
fn default_price_families() -> BTreeMap<Name, ComputePriceWeights> {
    defaults::compute::price_families()
}
fn default_economics() -> ComputeEconomics {
    ComputeEconomics {
        max_cu_per_call: defaults::compute::max_cu_per_call(),
        max_amplification_ratio: defaults::compute::max_amplification_ratio(),
        fee_split: defaults::compute::fee_split(),
        sponsor_policy: defaults::compute::sponsor_policy(),
        price_bounds: defaults::compute::price_bounds(),
        price_risk_classes: defaults::compute::price_risk_classes(),
        price_family_baseline: default_price_families(),
        price_amplifiers: defaults::compute::price_amplifiers(),
    }
}
#[test]
fn price_bounds_read_risk_class_object_keys() {
    let table = r"
[price_bounds.Low]
max_cycles_delta_bps = 500
max_egress_delta_bps = 600
[price_bounds.Balanced]
max_cycles_delta_bps = 1500
max_egress_delta_bps = 1600
[price_bounds.High]
max_cycles_delta_bps = 2500
max_egress_delta_bps = 2600
"
    .parse()
    .expect("price bounds TOML");
    let economics = ConfigReader::new()
        .with_toml_source(TomlSource::inline(table))
        .read_and_complete::<user::ComputeEconomics>()
        .expect("risk class keys must deserialize through ConfigReader");
    assert_eq!(economics.price_bounds.len(), 3);
    for (class, cycles, egress) in [
        (ComputePriceRiskClass::Low, 500, 600),
        (ComputePriceRiskClass::Balanced, 1500, 1600),
        (ComputePriceRiskClass::High, 2500, 2600),
    ] {
        let bounds = &economics.price_bounds[&class];
        assert_eq!(bounds.max_cycles_delta_bps.get(), cycles);
        assert_eq!(bounds.max_egress_delta_bps.get(), egress);
    }
}
#[test]
fn price_bounds_reject_noncanonical_risk_class_object_keys() {
    for key in ["Unknown", "low", "balanced", "high", "LOW", " Low", "Low "] {
        let table = format!(
            r#"
[price_bounds."{key}"]
max_cycles_delta_bps = 500
max_egress_delta_bps = 600
"#
        )
        .parse()
        .expect("price bounds TOML");
        let error = ConfigReader::new()
            .with_toml_source(TomlSource::inline(table))
            .read_and_complete::<user::ComputeEconomics>()
            .expect_err("noncanonical risk class keys must fail");
        assert!(format!("{error:?}").contains("price_bounds"), "key {key:?}");
    }
}
#[test]
fn price_update_respects_bounds() {
    let mut families = default_price_families();
    let economics = default_economics();
    let family = Name::from_str("default").expect("family");
    // Within the balanced bounds (15%).
    let ok_weights = ComputePriceWeights {
        cycles_per_unit: NonZeroU64::new(1_100_000).expect("cycles"),
        egress_bytes_per_unit: NonZeroU64::new(1100).expect("egress"),
        unit_label: "cu".to_string(),
    };
    economics
        .apply_price_update(&family, ok_weights.clone(), &mut families)
        .expect("within bounds");
    assert_eq!(Some(&ok_weights), families.get(&family));
    // Exceeds the balanced bounds for cycles.
    let err = economics
        .apply_price_update(
            &family,
            ComputePriceWeights {
                cycles_per_unit: NonZeroU64::new(2_000_000).expect("cycles"),
                egress_bytes_per_unit: NonZeroU64::new(1024).expect("egress"),
                unit_label: "cu".to_string(),
            },
            &mut families,
        )
        .expect_err("delta should be rejected");
    assert!(matches!(
        err,
        ComputeGovernanceError::CyclesDeltaExceeded { .. }
    ));
}
#[test]
fn sponsor_caps_enforced() {
    let economics = default_economics();
    economics
        .validate_sponsor_allocation(5_000)
        .expect("under cap");
    let err = economics
        .validate_sponsor_allocation(20_000)
        .expect_err("over cap");
    assert!(matches!(
        err,
        ComputeGovernanceError::SponsorCapExceeded {
            requested: 20_000,
            limit: 10_000,
        }
    ));
}

#[test]
fn ivm_compute_defaults_have_only_current_resource_and_sandbox_fields() {
    let config = ConfigReader::new()
        .read_and_complete::<user::Compute>()
        .expect("default compute config");
    assert_eq!(
        config.resource_profiles,
        defaults::compute::resource_profiles()
    );
    assert_eq!(config.sandbox, defaults::compute::sandbox_rules());
    let profiles = norito::json::to_value(&config.resource_profiles).unwrap();
    for profile in profiles.as_object().unwrap().values() {
        assert_eq!(profile.as_object().unwrap().len(), 6);
        assert!(profile.get("max_stack_bytes").is_some());
        assert!(profile.get("allow_wasi").is_none());
    }
    let sandbox = norito::json::to_value(&config.sandbox).unwrap();
    assert_eq!(sandbox.as_object().unwrap().len(), 5);
    assert!(sandbox.get("mode").is_none());
    assert!(config.sandbox.deny_nondeterministic_syscalls);
}

#[test]
fn ivm_compute_config_rejects_removed_resource_allowance() {
    for value in [false, true] {
        let table = format!(
            r"[resource_profiles.cpu-small]
max_cycles = 5000000
max_memory_bytes = 134217728
max_stack_bytes = 2097152
max_io_bytes = 16777216
max_egress_bytes = 8388608
allow_gpu_hints = false
allow_wasi = {value}
"
        )
        .parse()
        .expect("syntactically valid removed profile field");
        let error = ConfigReader::new()
            .with_toml_source(TomlSource::inline(table))
            .read_and_complete::<user::Compute>()
            .expect_err("removed resource allowance must fail configuration parsing");
        let report = format!("{error:?}");
        assert!(report.contains("allow_wasi"), "{report}");
    }
}

#[test]
fn ivm_compute_config_rejects_every_removed_sandbox_mode() {
    for mode in ["IvmOnly", "WasiLite"] {
        let table = format!(
            r#"[sandbox]
randomness = "SeededFromRequest"
storage = "ReadOnly"
deny_nondeterministic_syscalls = true
allow_gpu_hints = false
allow_tee_hints = false
mode = {{ mode = "{mode}" }}
"#
        )
        .parse()
        .expect("syntactically valid removed sandbox selector");
        let error = ConfigReader::new()
            .with_toml_source(TomlSource::inline(table))
            .read_and_complete::<user::Compute>()
            .expect_err("even the former IVM selector must fail configuration parsing");
        let report = format!("{error:?}");
        assert!(report.contains("unknown field `mode`"), "{report}");
    }
}

#[test]
fn ivm_compute_config_accepts_explicit_current_guardrails() {
    let table = r#"
[sandbox]
randomness = "SeededFromRequest"
storage = "ReadOnly"
deny_nondeterministic_syscalls = true
allow_gpu_hints = false
allow_tee_hints = false
[resource_profiles.cpu-small]
max_cycles = 5000000
max_memory_bytes = 134217728
max_stack_bytes = 2097152
max_io_bytes = 16777216
max_egress_bytes = 8388608
allow_gpu_hints = false
"#
    .parse()
    .expect("current IVM guardrails TOML");
    let config = ConfigReader::new()
        .with_toml_source(TomlSource::inline(table))
        .read_and_complete::<user::Compute>()
        .expect("current IVM resource and sandbox overrides");
    assert_eq!(config.sandbox, defaults::compute::sandbox_rules());
    assert_eq!(config.resource_profiles.len(), 1);
    let profile = defaults::compute::default_resource_profile();
    assert_eq!(
        config.resource_profiles[&profile],
        defaults::compute::resource_profiles()[&profile]
    );
}

#[test]
fn ivm_compute_config_accepts_all_current_policy_strings() {
    for randomness in ["None", "SeededFromRequest"] {
        for storage in ["ReadOnly", "ReadWrite"] {
            for auth in ["PublicOnly", "AuthenticatedOnly", "Either"] {
                let table = format!(
                    r#"auth_policy = "{auth}"
[sandbox]
randomness = "{randomness}"
storage = "{storage}"
deny_nondeterministic_syscalls = true
allow_gpu_hints = false
allow_tee_hints = false
"#
                )
                .parse()
                .expect("canonical policy strings");
                let config = ConfigReader::new()
                    .with_toml_source(TomlSource::inline(table))
                    .read_and_complete::<user::Compute>()
                    .expect("all current unit policy variants must work in TOML");
                assert_eq!(
                    norito::json::to_value(&config.auth_policy)
                        .unwrap()
                        .as_str(),
                    Some(auth)
                );
                assert_eq!(
                    norito::json::to_value(&config.sandbox.randomness)
                        .unwrap()
                        .as_str(),
                    Some(randomness)
                );
                assert_eq!(
                    norito::json::to_value(&config.sandbox.storage)
                        .unwrap()
                        .as_str(),
                    Some(storage)
                );
            }
        }
    }
    for (name, expected) in [
        ("Low", ComputePriceRiskClass::Low),
        ("Balanced", ComputePriceRiskClass::Balanced),
        ("High", ComputePriceRiskClass::High),
    ] {
        let table = format!(
            r#"[price_risk_classes]
default = "{name}"
"#
        )
        .parse()
        .expect("canonical risk class string");
        let economics = ConfigReader::new()
            .with_toml_source(TomlSource::inline(table))
            .read_and_complete::<user::ComputeEconomics>()
            .expect("all risk class values must work in TOML");
        assert_eq!(
            economics.price_risk_classes[&Name::from_str("default").unwrap()],
            expected
        );
    }
}

#[test]
fn ivm_compute_config_rejects_object_valued_unit_policies() {
    for source in [
        r#"auth_policy = { mode = "Either" }"#,
        r#"[sandbox]
randomness = { randomness = "SeededFromRequest" }
storage = "ReadOnly"
deny_nondeterministic_syscalls = true
allow_gpu_hints = false
allow_tee_hints = false
"#,
        r#"[sandbox]
randomness = "SeededFromRequest"
storage = { storage = "ReadOnly" }
deny_nondeterministic_syscalls = true
allow_gpu_hints = false
allow_tee_hints = false
"#,
    ] {
        let table = source
            .parse()
            .expect("syntactically valid removed policy envelope");
        let error = ConfigReader::new()
            .with_toml_source(TomlSource::inline(table))
            .read_and_complete::<user::Compute>()
            .expect_err("unit policy envelopes must be rejected");
        let report = format!("{error:?}");
        assert!(!report.contains("missing field"), "{report}");
    }
    let table = r#"[price_risk_classes]
default = { class = "Balanced" }
"#
    .parse()
    .expect("syntactically valid removed risk class envelope");
    let error = ConfigReader::new()
        .with_toml_source(TomlSource::inline(table))
        .read_and_complete::<user::ComputeEconomics>()
        .expect_err("object-valued risk classes must be rejected");
    assert!(!format!("{error:?}").contains("missing field"));
}

#[test]
fn price_update_keeps_full_width_bounds_and_original_family_on_refusal() {
    let family: Name = "default".parse().unwrap();
    let cases: [(u64, u64, u16, Option<u128>); 12] = [
        (1, 4_097, 1_500, Some(40_960_000)),
        (1, 4_097, u16::MAX, Some(40_960_000)),
        (
            1,
            u64::MAX,
            u16::MAX,
            Some((u128::from(u64::MAX) - 1) * 10_000),
        ),
        (u64::MAX / 2, u64::MAX, 1_500, Some(10_000)),
        (u64::MAX, 1, 9_998, Some(9_999)),
        (u64::MAX, 1, 9_999, None),
        (u64::MAX - 1, u64::MAX, 1, None),
        (10_000, 11_500, 1_500, None),
        (10_000, 11_501, 1_500, Some(1_501)),
        (10_000, 75_535, u16::MAX, None),
        (10_000, 75_536, u16::MAX, Some(65_536)),
        (u64::MAX, u64::MAX, 1, None),
    ];
    for component in ["cycles", "egress"] {
        for &(original, proposed, maximum, rejected_delta) in &cases {
            let current = ComputePriceWeights {
                cycles_per_unit: NonZeroU64::new(original).unwrap(),
                egress_bytes_per_unit: NonZeroU64::new(original).unwrap(),
                unit_label: "cu".to_owned(),
            };
            let mut updated = current.clone();
            match component {
                "cycles" => updated.cycles_per_unit = NonZeroU64::new(proposed).unwrap(),
                "egress" => updated.egress_bytes_per_unit = NonZeroU64::new(proposed).unwrap(),
                _ => unreachable!("fixed components"),
            }
            let bounds = ComputePriceDeltaBounds {
                max_cycles_delta_bps: NonZeroU16::new(maximum).unwrap(),
                max_egress_delta_bps: NonZeroU16::new(maximum).unwrap(),
            };
            let expected = rejected_delta.map_or(Ok(()), |delta_bps| {
                Err(match component {
                    "cycles" => ComputeGovernanceError::CyclesDeltaExceeded {
                        family: family.clone(),
                        delta_bps,
                        max_bps: maximum,
                    },
                    "egress" => ComputeGovernanceError::EgressDeltaExceeded {
                        family: family.clone(),
                        delta_bps,
                        max_bps: maximum,
                    },
                    _ => unreachable!("fixed components"),
                })
            });
            let mut economics = default_economics();
            economics.price_family_baseline = BTreeMap::from([(family.clone(), current.clone())]);
            economics.price_risk_classes =
                BTreeMap::from([(family.clone(), ComputePriceRiskClass::Balanced)]);
            economics.price_bounds = BTreeMap::from([(ComputePriceRiskClass::Balanced, bounds)]);
            let mut families = BTreeMap::from([(family.clone(), current)]);
            let original_families = families.clone();
            assert_eq!(
                economics.apply_price_update(&family, updated.clone(), &mut families),
                expected,
                "configuration must retain the full-width {component} bound for {original} -> {proposed}",
            );
            if rejected_delta.is_some() {
                assert_eq!(
                    families, original_families,
                    "refusal must not replace any original family"
                );
            } else {
                assert_eq!(families, BTreeMap::from([(family.clone(), updated)]));
            }
        }
    }
}

#[test]
fn price_update_refusals_keep_lookup_and_label_precedence() {
    let family: Name = "default".parse().unwrap();
    let absent: Name = "absent".parse().unwrap();
    let mut economics = default_economics();
    let mut families = default_price_families();
    let original = families.clone();
    let mut updated = ComputePriceWeights {
        cycles_per_unit: NonZeroU64::MAX,
        egress_bytes_per_unit: NonZeroU64::MAX,
        unit_label: "changed".to_owned(),
    };
    assert_eq!(
        economics.apply_price_update(&absent, updated.clone(), &mut families),
        Err(ComputeGovernanceError::UnknownPriceFamily { family: absent }),
    );
    assert_eq!(families, original);
    economics.price_risk_classes.clear();
    assert_eq!(
        economics.apply_price_update(&family, updated.clone(), &mut families),
        Err(ComputeGovernanceError::MissingRiskClass {
            family: family.clone()
        }),
    );
    assert_eq!(families, original);
    economics
        .price_risk_classes
        .insert(family.clone(), ComputePriceRiskClass::Balanced);
    economics.price_bounds.clear();
    assert_eq!(
        economics.apply_price_update(&family, updated.clone(), &mut families),
        Err(ComputeGovernanceError::MissingRiskBounds {
            class: ComputePriceRiskClass::Balanced
        }),
    );
    assert_eq!(families, original);
    economics.price_bounds.insert(
        ComputePriceRiskClass::Balanced,
        ComputePriceDeltaBounds {
            max_cycles_delta_bps: NonZeroU16::MAX,
            max_egress_delta_bps: NonZeroU16::MAX,
        },
    );
    assert_eq!(
        economics.apply_price_update(&family, updated.clone(), &mut families),
        Err(ComputeGovernanceError::UnitLabelChanged {
            family: family.clone(),
            from: original[&family].unit_label.clone(),
            to: updated.unit_label.clone(),
        }),
    );
    assert_eq!(families, original);
    updated.unit_label = original[&family].unit_label.clone();
    assert!(matches!(
        economics.apply_price_update(&family, updated, &mut families),
        Err(ComputeGovernanceError::CyclesDeltaExceeded { .. }),
    ));
    assert_eq!(families, original);
}

#[test]
fn sponsor_caps_keep_exact_daily_total_and_per_call_precedence() {
    let cases = [
        (u64::MAX, u64::MAX, 0, u64::MAX, None),
        (u64::MAX, u64::MAX, 1, u64::MAX - 1, None),
        (
            u64::MAX,
            u64::MAX,
            1,
            u64::MAX,
            Some((u128::from(u64::MAX) + 1, u64::MAX)),
        ),
        (
            u64::MAX,
            u64::MAX,
            u64::MAX,
            u64::MAX,
            Some((2 * u128::from(u64::MAX), u64::MAX)),
        ),
        (2, u64::MAX, 3, u64::MAX, Some((3, 2))),
        (10, 20, 8, 12, None),
        (10, 20, 8, 13, Some((21, 20))),
    ];
    for (per_call, daily, requested, consumed, refused) in cases {
        let policy = ComputeSponsorPolicy {
            max_cu_per_call: NonZeroU64::new(per_call).unwrap(),
            max_daily_cu: NonZeroU64::new(daily).unwrap(),
        };
        let expected = refused.map_or(Ok(()), |(requested, limit)| {
            Err(ComputeGovernanceError::SponsorCapExceeded { requested, limit })
        });
        let mut economics = default_economics();
        economics.sponsor_policy = policy;
        assert_eq!(
            economics.validate_sponsor_allocation_with_usage(requested, consumed),
            expected,
            "configuration must enforce the same exact sponsor sum"
        );
    }
}
