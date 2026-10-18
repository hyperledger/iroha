//! Independent census, singular-factor and extension-polynomial controls.

use super::*;
use crate::privacy_engines::transparent_stark::{GOLDILOCKS_MODULUS_V1, GoldilocksFp4V1 as E};

fn active_time(index: usize, certificates: usize, entries: usize) -> bool {
    match index {
        0..=2 => index < certificates,
        3..=5 => index - 3 < certificates,
        6..=7 => true,
        _ => index - 8 < entries,
    }
}

fn challenges() -> [[F; 12]; LOOKUP_LANES_V1] {
    // Lane zero deliberately makes every timestamp event singular. Other
    // lanes bind the domain, identity and value with nonzero factors.
    let mut lanes = core::array::from_fn(|lane| {
        core::array::from_fn(|column| F((lane * (column + 1) * 17) as u64))
    });
    lanes[0][0] = F::ZERO.sub(F(TIMESTAMP_DOMAIN_V1).inv().unwrap());
    lanes
}

fn events(certificates: usize, entries: usize) -> Vec<NumericLookupEventV1<F>> {
    let certificate_two = F((certificates - 2) as u64);
    let mut events = Vec::new();
    for index in 0..TEMPORAL_SLOTS_V1 {
        if active_time(index, certificates, entries) {
            let slot = temporal_slot_v1(index).unwrap();
            events.push(NumericLookupEventV1 {
                source: F::ONE,
                query: F::ZERO,
                multiplicity: slot.numeric_multiplicity_v1(F(entries as u64)),
                tuple: timestamp_tuple_v1(
                    slot.identity_v1(certificate_two),
                    F(1000 + index as u64),
                ),
            });
        }
    }
    for index in 0..RELATION_SLOTS_V1 {
        let slot = relation_slot_v1(index).unwrap();
        let active = match slot.activity {
            NumericActivityV1::Required => true,
            NumericActivityV1::CertificateTwo => certificates == 3,
            NumericActivityV1::Entry(entry) => usize::from(entry) < entries,
        };
        if !active {
            continue;
        }
        for operand in [slot.left, slot.right] {
            if let NumericOperandV1::Time { slot, add_seconds } = operand {
                let source_index = (0..TEMPORAL_SLOTS_V1)
                    .find(|index| temporal_slot_v1(*index) == Some(slot))
                    .unwrap();
                let tuple = operand
                    .timestamp_tuple_v1(
                        certificate_two,
                        F(1000 + source_index as u64 + u64::from(add_seconds)),
                    )
                    .unwrap();
                events.push(NumericLookupEventV1 {
                    source: F::ZERO,
                    query: F::ONE,
                    multiplicity: F::ZERO,
                    tuple,
                });
            }
        }
    }
    // Public padding rows have canonical zero witnesses for each inverse lane.
    events.push(NumericLookupEventV1 {
        source: F::ZERO,
        query: F::ZERO,
        multiplicity: F::ZERO,
        tuple: [F::ZERO; 12],
    });
    events
}

fn rows(events: &[NumericLookupEventV1<F>]) -> Vec<NumericLookupRowV1<F>> {
    let mut sum = [F::ZERO; LOOKUP_LANES_V1];
    let mut zero_sum = sum;
    events
        .iter()
        .map(|event| {
            let mut inverse = [F::ZERO; LOOKUP_LANES_V1];
            let mut zero = inverse;
            let weight = event.source.mul(event.multiplicity).sub(event.query);
            if event.source.add(event.query) != F::ZERO {
                for (lane, challenge) in challenges().into_iter().enumerate() {
                    let factor = event
                        .tuple
                        .into_iter()
                        .zip(challenge)
                        .fold(F::ONE, |sum, (value, challenge)| {
                            sum.add(value.mul(challenge))
                        });
                    match factor.inv() {
                        Some(value) => inverse[lane] = value,
                        None => zero[lane] = F::ONE,
                    }
                }
            }
            let row = NumericLookupRowV1 {
                inverse,
                zero,
                sum,
                zero_sum,
            };
            for lane in 0..LOOKUP_LANES_V1 {
                sum[lane] = sum[lane].add(weight.mul(inverse[lane]));
                zero_sum[lane] = zero_sum[lane].add(weight.mul(zero[lane]));
            }
            row
        })
        .collect()
}

fn valid(events: &[NumericLookupEventV1<F>], rows: &[NumericLookupRowV1<F>]) -> bool {
    events.iter().enumerate().all(|(index, event)| {
        let residues = lookup_residues_v1(
            event,
            &rows[index],
            &rows[(index + 1) % rows.len()],
            F(u64::from(index == 0)),
            F(u64::from(index + 1 != rows.len())),
            F(u64::from(index + 1 == rows.len())),
            &challenges(),
        );
        assert_eq!(residues.len(), LOOKUP_RESIDUES_V1);
        residues.into_iter().all(|value| value == F::ZERO)
    })
}

#[test]
fn fixed_slot_census_matches_every_private_operand_and_only_one_strict_relation() {
    assert_eq!(TEMPORAL_SLOTS_V1 * DECIMAL_ROWS_PER_TIME_V1, 1080);
    assert_eq!(TEMPORAL_SLOTS_V1 * CALENDAR_PHASES_V1, 504);
    assert_eq!(RELATION_SLOTS_V1 * RELATION_PHASES_V1, 146);
    assert_eq!(RELATION_SLOTS_V1 * RANGE_BYTES_PER_RELATION_V1, 584);
    assert!(temporal_slot_v1(72).is_none());
    assert!(relation_slot_v1(73).is_none());
    for certificates in [2, 3] {
        for entries in [0, 1, 64] {
            let events = events(certificates, entries);
            let mut source_counts = std::collections::BTreeMap::new();
            let mut query_counts = std::collections::BTreeMap::new();
            for event in &events {
                let key = event.tuple.map(F::value);
                if event.source == F::ONE {
                    assert!(
                        source_counts
                            .insert(key, event.multiplicity.value())
                            .is_none()
                    );
                } else if event.query == F::ONE {
                    *query_counts.entry(key).or_insert(0) += 1;
                }
            }
            assert_eq!(source_counts.len(), 2 * certificates + 2 + entries);
            assert_eq!(source_counts, query_counts);
            assert!(valid(&events, &rows(&events)));
        }
    }
    for index in 0..RELATION_SLOTS_V1 {
        let slot = relation_slot_v1(index).unwrap();
        assert_eq!(slot.strict, index == 7);
        if index >= 9 {
            assert_eq!(slot.relation, 7);
            assert_eq!(usize::from(slot.instance), index - 9);
        }
    }
    let cert2 = F::ONE;
    let identities = (0..TEMPORAL_SLOTS_V1)
        .map(|index| {
            temporal_slot_v1(index)
                .unwrap()
                .identity_v1(cert2)
                .map(F::value)
        })
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(identities.len(), 72);
    for index in 0..3 {
        // assign_certificate_provenance_v1 authenticates certificate date
        // role_instance as the document index, rather than always zero.
        for slot in [index, index + 3] {
            let identity = temporal_slot_v1(slot).unwrap().identity_v1(cert2);
            assert_eq!(identity[2], F(index as u64));
        }
        assert_eq!(
            temporal_slot_v1(index).unwrap().identity_v1(cert2)[0],
            F(index as u64)
        );
        assert_eq!(
            temporal_slot_v1(index + 3).unwrap().identity_v1(cert2)[0],
            F(index as u64)
        );
    }
    for index in 6..72 {
        assert_eq!(
            temporal_slot_v1(index).unwrap().identity_v1(F::ZERO)[0],
            F(2)
        );
        assert_eq!(
            temporal_slot_v1(index).unwrap().identity_v1(F::ONE)[0],
            F(3)
        );
    }
}

#[test]
fn singular_inverse_prefix_and_event_mutations_are_rejected() {
    let honest = events(3, 64);
    assert!(valid(&honest, &rows(&honest)));
    for column in 1..=4 {
        let mut altered = events(3, 64);
        let query = altered
            .iter_mut()
            .find(|event| event.query == F::ONE)
            .unwrap();
        query.tuple[column] = query.tuple[column].add(F::ONE);
        assert!(
            !valid(&altered, &rows(&altered)),
            "identity/value column {column}"
        );
    }
    for removed in [0, 6, 71, honest.len() - 2] {
        let mut altered = events(3, 64);
        altered.remove(removed);
        assert!(!valid(&altered, &rows(&altered)), "omitted event {removed}");
    }
    let mut altered = events(3, 64);
    altered[6].multiplicity = altered[6].multiplicity.add(F::ONE);
    assert!(!valid(&altered, &rows(&altered)));
    let mut witnesses = rows(&honest);
    assert_eq!(witnesses[0].zero[0], F::ONE);
    witnesses[0].inverse[0] = F::ONE;
    assert!(!valid(&honest, &witnesses), "singular inverse must be zero");
    for lane in 0..LOOKUP_LANES_V1 {
        let mut witnesses = rows(&honest);
        witnesses[honest.len() / 2].sum[lane] = F(999);
        assert!(!valid(&honest, &witnesses));
        let mut witnesses = rows(&honest);
        witnesses[honest.len() - 1].zero_sum[lane] = F::ONE;
        assert!(!valid(&honest, &witnesses));
    }
    let mut altered = events(3, 64);
    altered[0].query = F::ONE;
    assert!(
        !valid(&altered, &rows(&altered)),
        "source and query are disjoint"
    );
}

#[test]
fn exact_der_identity_and_public_window_bounds_are_not_host_ordinals() {
    let identity = TemporalSlotV1::CrlEntry(63).identity_v1(F::ONE);
    let tuple = time_node_tuple_v1(identity, F(123), F(24), F(200), F(215));
    assert_eq!(
        tuple.map(F::value),
        [
            100,
            3,
            ZkX509Rfc5280GrammarRoleV1::CrlEntryTime as u64,
            63,
            123,
            24,
            200,
            215,
            0,
            0,
            0,
            0
        ]
    );
    assert_eq!(validate_window_v1(0, MAXIMUM_TIMESTAMP_V1), Ok(()));
    assert!(validate_window_v1(1, 0).is_err());
    assert!(validate_window_v1(0, MAXIMUM_TIMESTAMP_V1 + 1).is_err());
    assert!(validate_window_v1(0, GOLDILOCKS_MODULUS_V1 - 1).is_err());
    const { assert!(MAXIMUM_TIMESTAMP_V1 + 300 < 1 << SLACK_BITS_V1) };
    const { assert!(2 * (1_u64 << SLACK_BITS_V1) < GOLDILOCKS_MODULUS_V1) };
    assert!(
        NumericOperandV1::WindowStart
            .timestamp_tuple_v1(F::ZERO, F(123))
            .is_none()
    );
    let operand = NumericOperandV1::Time {
        slot: TemporalSlotV1::CrlThisUpdate,
        add_seconds: 300,
    };
    assert_eq!(
        operand.timestamp_tuple_v1(F::ONE, F(1300)).unwrap(),
        timestamp_tuple_v1(TemporalSlotV1::CrlThisUpdate.identity_v1(F::ONE), F(1000))
    );
}

fn polynomial_input<A: PolynomialAirFieldV1>(x: A) -> Vec<A> {
    let cell = |index: usize| {
        A::from_base(F((index * 13 + 7) as u64))
            .add(x.mul(A::from_base(F((index * 5 + 3) as u64))))
            .add(x.mul(x).mul(A::from_base(F((index % 7 + 1) as u64))))
            .add(
                x.mul(x)
                    .mul(x)
                    .mul(A::from_base(F((index % 11 + 2) as u64))),
            )
    };
    let event = NumericLookupEventV1 {
        source: cell(0),
        query: cell(1),
        multiplicity: cell(2),
        tuple: core::array::from_fn(|index| cell(3 + index)),
    };
    let row = |offset| NumericLookupRowV1 {
        inverse: core::array::from_fn(|index| cell(offset + index)),
        zero: core::array::from_fn(|index| cell(offset + 4 + index)),
        sum: core::array::from_fn(|index| cell(offset + 8 + index)),
        zero_sum: core::array::from_fn(|index| cell(offset + 12 + index)),
    };
    lookup_residues_v1(
        &event,
        &row(15),
        &row(31),
        cell(47),
        cell(48),
        cell(49),
        &challenges(),
    )
}

#[test]
fn all_lookup_residues_match_independent_extension_lifting_at_degree_four() {
    // Cubic substitution into degree-four AIR has degree at most12. Thirteen
    // independent base samples determine its extension evaluation uniquely.
    let samples = (0..13)
        .map(|index| polynomial_input(F(index)))
        .collect::<Vec<_>>();
    let x = E::canonical([19, 7, 11, 5]).unwrap();
    let actual = polynomial_input(x);
    assert_eq!(actual.len(), 51);
    assert!(actual.iter().any(|value| {
        value.coefficients()[1..]
            .iter()
            .any(|coefficient| *coefficient != F::ZERO)
    }));
    for residue in 0..actual.len() {
        let mut expected = E::ZERO;
        for (index, sample) in samples.iter().enumerate() {
            let mut numerator = E::ONE;
            let mut denominator = F::ONE;
            for other in 0..samples.len() {
                if other != index {
                    numerator = numerator.mul(x.sub(E::from_base(F(other as u64))));
                    denominator = denominator.mul(F(index as u64).sub(F(other as u64)));
                }
            }
            expected =
                expected.add(numerator.mul_base(sample[residue].mul(denominator.inv().unwrap())));
        }
        assert_eq!(actual[residue], expected, "residue {residue}");
    }
    for index in 0..13 {
        assert_eq!(
            polynomial_input(E::from_base(F(index))),
            polynomial_input(F(index))
                .into_iter()
                .map(E::from_base)
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn affine_factor_prevents_projective_tuple_and_multiplicity_aliases() {
    let challenge = core::array::from_fn(|index| F((index + 7) as u64));
    let tuple = |domain| {
        let mut values = [F::ZERO; 12];
        values[0] = F(domain);
        values[1] = F(domain * 3);
        values
    };
    let first = tuple(100);
    let doubled = tuple(200);
    let homogeneous = |values: [F; 12]| {
        values
            .into_iter()
            .zip(challenge)
            .fold(F::ZERO, |sum, (value, challenge)| {
                sum.add(value.mul(challenge))
            })
    };
    // One source and two consumers with proportional homogeneous tuples can
    // cancel as rational functions despite different multiplicities.
    assert_eq!(
        homogeneous(first).inv().unwrap(),
        homogeneous(doubled).inv().unwrap().mul(F(2))
    );
    assert_ne!(
        lookup_factor_v1(first, challenge).inv().unwrap(),
        lookup_factor_v1(doubled, challenge)
            .inv()
            .unwrap()
            .mul(F(2))
    );
    for column in 0..12 {
        let mut changed = first;
        changed[column] = changed[column].add(F::ONE);
        assert_ne!(
            lookup_factor_v1(first, challenge),
            lookup_factor_v1(changed, challenge)
        );
    }
}

#[test]
fn weighted_prefix_transition_attains_degree_four_including_fixed_selector() {
    let mut values = (0..6)
        .map(|value| {
            let x = F(value);
            let event = NumericLookupEventV1 {
                source: x,
                query: F::ZERO,
                multiplicity: x,
                tuple: [F::ZERO; 12],
            };
            let current = NumericLookupRowV1 {
                inverse: [x; LOOKUP_LANES_V1],
                zero: [F::ZERO; LOOKUP_LANES_V1],
                sum: [F::ZERO; LOOKUP_LANES_V1],
                zero_sum: [F::ZERO; LOOKUP_LANES_V1],
            };
            let residues = lookup_residues_v1(
                &event,
                &current,
                &current,
                F::ZERO,
                x,
                F::ZERO,
                &challenges(),
            );
            // Three event checks precede twelve checks per lane; transition
            // position eight is -continue * source * multiplicity * inverse.
            assert_eq!(residues[11], F::ZERO.sub(x.pow(4)));
            residues[11]
        })
        .collect::<Vec<_>>();
    for order in 1..=5 {
        values = values.windows(2).map(|pair| pair[1].sub(pair[0])).collect();
        if order == 4 {
            assert!(values.iter().all(|value| *value == F::ZERO.sub(F(24))));
        }
    }
    assert_eq!(values, [F::ZERO]);
}

/// Integer meaning of the verifier-fixed relation-slot schedule: every active
/// slot is `left = right + slack` with a 38-bit slack that is nonzero when the
/// slot is strict. Operands come only from the public window and the
/// authenticated DER time slots.
fn slot_schedule_admits_v1(
    certificates: &[(u64, u64)],
    crl: (u64, u64),
    entries: &[u64],
    start: u64,
    end: u64,
) -> bool {
    (0..RELATION_SLOTS_V1).all(|index| {
        let slot = relation_slot_v1(index).unwrap();
        let active = match slot.activity {
            NumericActivityV1::Required => true,
            NumericActivityV1::CertificateTwo => certificates.len() == 3,
            NumericActivityV1::Entry(entry) => usize::from(entry) < entries.len(),
        };
        if !active {
            return true;
        }
        let value = |operand: NumericOperandV1| match operand {
            NumericOperandV1::WindowStart => start,
            NumericOperandV1::WindowEnd => end,
            NumericOperandV1::Time { slot, add_seconds } => {
                u64::from(add_seconds)
                    + match slot {
                        TemporalSlotV1::CertificateNotBefore(certificate) => {
                            certificates[usize::from(certificate)].0
                        }
                        TemporalSlotV1::CertificateNotAfter(certificate) => {
                            certificates[usize::from(certificate)].1
                        }
                        TemporalSlotV1::CrlThisUpdate => crl.0,
                        TemporalSlotV1::CrlNextUpdate => crl.1,
                        TemporalSlotV1::CrlEntry(entry) => entries[usize::from(entry)],
                    }
            }
        };
        value(slot.left)
            .checked_sub(value(slot.right))
            .is_some_and(|slack| slack < 1 << SLACK_BITS_V1 && (!slot.strict || slack != 0))
    })
}

/// The in-relation temporal predicate is the canonical data-model interval
/// definition: each certificate is bound on both sides by its own slots, so the
/// binding upper bound is the earliest `notAfter` at any path position, and the
/// CRL `nextUpdate` slot is the only strict one.
#[test]
fn relation_slot_schedule_is_the_canonical_presentation_interval_predicate() {
    use iroha_data_model::privacy::{
        PrivacyZkX509CertificateValidityV1, PrivacyZkX509CrlUpdateIntervalV1,
        PrivacyZkX509PresentationWindowV1, ZK_X509_MAX_CRL_AGE_SECONDS_V1,
        ZK_X509_MAX_UNIX_SECONDS_V1, validate_zk_x509_presentation_interval_v1,
    };

    // The schedule has one lower and one upper slot per certificate, three CRL
    // slots, and the canonical age and calendar ceilings.
    for certificate in 0..3_u8 {
        let lower = relation_slot_v1(usize::from(certificate) * 2).unwrap();
        assert_eq!(
            (lower.relation, lower.instance),
            (1, u16::from(certificate))
        );
        assert_eq!(lower.left, NumericOperandV1::WindowStart);
        assert_eq!(
            lower.right,
            NumericOperandV1::Time {
                slot: TemporalSlotV1::CertificateNotBefore(certificate),
                add_seconds: 0,
            }
        );
        let upper = relation_slot_v1(usize::from(certificate) * 2 + 1).unwrap();
        assert_eq!(
            (upper.relation, upper.instance),
            (2, u16::from(certificate))
        );
        assert_eq!(
            upper.left,
            NumericOperandV1::Time {
                slot: TemporalSlotV1::CertificateNotAfter(certificate),
                add_seconds: 0,
            }
        );
        assert_eq!(upper.right, NumericOperandV1::WindowEnd);
        let expected_activity = if certificate == 2 {
            NumericActivityV1::CertificateTwo
        } else {
            NumericActivityV1::Required
        };
        assert_eq!(lower.activity, expected_activity);
        assert_eq!(upper.activity, expected_activity);
        assert!(!lower.strict && !upper.strict);
    }
    let fresh = relation_slot_v1(8).unwrap();
    assert_eq!(
        fresh.left,
        NumericOperandV1::Time {
            slot: TemporalSlotV1::CrlThisUpdate,
            add_seconds: u16::try_from(ZK_X509_MAX_CRL_AGE_SECONDS_V1).unwrap(),
        }
    );
    assert_eq!(
        u64::from(CRL_AGE_SECONDS_V1),
        ZK_X509_MAX_CRL_AGE_SECONDS_V1
    );
    assert_eq!(MAXIMUM_TIMESTAMP_V1, ZK_X509_MAX_UNIX_SECONDS_V1);
    let next_update = relation_slot_v1(7).unwrap();
    assert!(next_update.strict);
    assert_eq!(
        next_update.left,
        NumericOperandV1::Time {
            slot: TemporalSlotV1::CrlNextUpdate,
            add_seconds: 0,
        }
    );
    assert_eq!(next_update.right, NumericOperandV1::WindowEnd);

    // Exhaustive boundary grid around the CRL freshness horizon.
    const T: u64 = 1_672_531_200;
    let mut validities = Vec::new();
    for not_before in [T - 2, T, T + 2] {
        for not_after in [T + 297, T + 299, T + 300, T + 302] {
            validities.push((not_before, not_after));
        }
    }
    let crls = [
        (T - 1, T + 299),
        (T, T + 300),
        (T, T + 301),
        (T, T + 305),
        (T + 1, T + 303),
    ];
    let mut admitted = 0_u64;
    let mut rejected = 0_u64;
    let mut check = |certificates: &[(u64, u64)]| {
        let canonical_certificates: Vec<_> = certificates
            .iter()
            .map(|(not_before, not_after)| {
                PrivacyZkX509CertificateValidityV1::new(*not_before, *not_after)
            })
            .collect();
        for crl in crls {
            for start in (T - 3)..=(T + 3) {
                for end in (T + 295)..=(T + 304) {
                    let window = PrivacyZkX509PresentationWindowV1::new(start, end);
                    let in_relation = window.validate().is_ok()
                        && validate_window_v1(start, end).is_ok()
                        && slot_schedule_admits_v1(certificates, crl, &[], start, end);
                    let canonical = validate_zk_x509_presentation_interval_v1(
                        &canonical_certificates,
                        PrivacyZkX509CrlUpdateIntervalV1::new(crl.0, crl.1),
                        window,
                    )
                    .is_ok();
                    assert_eq!(
                        in_relation, canonical,
                        "window [{start}, {end}], path {certificates:?}, CRL {crl:?}"
                    );
                    if canonical {
                        admitted += 1;
                    } else {
                        rejected += 1;
                    }
                }
            }
        }
    };
    for leaf in &validities {
        for root in &validities {
            check(&[*leaf, *root]);
            for intermediate in &validities {
                check(&[*leaf, *intermediate, *root]);
            }
        }
    }
    assert!(admitted > 1_000 && rejected > 100_000);

    // Earliest expiry at the leaf, the intermediate and the root: equality is
    // admitted, one second later has no non-negative slack.
    let earliest = T + 150;
    let later = T + 86_400;
    for position in 0..3 {
        let mut certificates = [(T - 3_600, later); 3];
        certificates[position].1 = earliest;
        let crl = (T, T + 301);
        assert!(slot_schedule_admits_v1(
            &certificates,
            crl,
            &[],
            T,
            earliest
        ));
        assert!(!slot_schedule_admits_v1(
            &certificates,
            crl,
            &[],
            T,
            earliest + 1
        ));
        // The latest-expiry window is inside the CRL and the other certificates.
        assert!(!slot_schedule_admits_v1(
            &certificates,
            crl,
            &[],
            T,
            T + 300
        ));
        let mut all_later = certificates;
        all_later[position].1 = later;
        assert!(slot_schedule_admits_v1(&all_later, crl, &[], T, T + 300));
    }
    // CRL nextUpdate is strict; thisUpdate is inclusive; the age cap is 300.
    let certificates = [(T - 3_600, later); 2];
    assert!(slot_schedule_admits_v1(
        &certificates,
        (T, T + 200),
        &[],
        T,
        T + 199
    ));
    assert!(!slot_schedule_admits_v1(
        &certificates,
        (T, T + 200),
        &[],
        T,
        T + 200
    ));
    assert!(!slot_schedule_admits_v1(
        &certificates,
        (T, T + 200),
        &[],
        T - 1,
        T + 199
    ));
    assert!(slot_schedule_admits_v1(
        &certificates,
        (T, T + 900),
        &[],
        T + 1,
        T + 300
    ));
    assert!(!slot_schedule_admits_v1(
        &certificates,
        (T, T + 900),
        &[],
        T + 1,
        T + 301
    ));
    // Revocation-entry slots are unchanged: no entry postdates thisUpdate.
    assert!(slot_schedule_admits_v1(
        &certificates,
        (T, T + 301),
        &[T, T - 1],
        T,
        T + 300
    ));
    assert!(!slot_schedule_admits_v1(
        &certificates,
        (T, T + 301),
        &[T + 1],
        T,
        T + 300
    ));
}
