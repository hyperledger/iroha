// Constraint-level controls for the presentation-interval relation slots.
//
// The witness builders refuse to construct rows for a window outside a signed
// interval, so a test that only calls them shows prover-side host behaviour.
// These tests evaluate the actual challenge-independent AIR residues over
// rows a cheating prover could commit against a forged public window, on
// genuinely signed paths whose earliest expiry sits at the leaf, the
// intermediate and the root.
//
// A relation slot enforces `left = right + slack` over the field. Its public
// operand is bound to a verifier-owned fixed cell; its slack is copied to
// eight range bytes that bound it below 2^38. A window end one second past
// the earliest expiry therefore leaves the prover three choices on the
// binding slot, and each one leaves a non-zero residue or breaks the copy:
// keep the honest operand (it no longer equals the fixed cell), keep the
// honest slack (the sum no longer holds), or take the field-wrapped slack
// `-1` (its bytes exceed the range bound, and the honest bytes no longer
// carry it).

/// 2023-01-01T00:00:00Z, the `thisUpdate` of the interval fixtures.
const PRESENTATION_INTERVAL_T: u64 = 1_672_531_200;
/// Relation code of `notAfter_i >= end`; slot index `2 * i + 1`.
const PRESENTATION_INTERVAL_UPPER_RELATION: u16 = 2;
/// Slot of `nextUpdate > end` (strict) and of `thisUpdate + 300 >= end`.
const PRESENTATION_INTERVAL_NEXT_UPDATE_SLOT: usize = 7;
const PRESENTATION_INTERVAL_CRL_AGE_SLOT: usize = 8;

/// Base material of one genuinely signed path and CRL, presented with an
/// admitted window, and the verifier-owned schedule of the same statement
/// with a forged window end.
struct PresentationIntervalMaterialV1 {
    material: ZkX509Rfc5280StarkBaseMaterialV1,
    forged: ZkX509Rfc5280StarkFixedScheduleV1,
    forged_end: u64,
}

impl PresentationIntervalMaterialV1 {
    fn new(
        certificates: &[iroha_data_model::privacy::PrivacyZkX509CertificateValidityV1],
        crl: iroha_data_model::privacy::PrivacyZkX509CrlUpdateIntervalV1,
        admitted: iroha_data_model::privacy::PrivacyZkX509PresentationWindowV1,
        forged_end: u64,
    ) -> Self {
        use crate::privacy_engines::zk_x509::{
            relation::release_fixture::build_zk_x509_interval_fixture_v1,
            verifier_profile::rfc_statement_with_crl_number_v1,
        };
        use iroha_data_model::privacy::validate_zk_x509_presentation_interval_v1;

        // The admitted window is admitted and the forged end is not, by the
        // canonical definition.
        assert_eq!(
            validate_zk_x509_presentation_interval_v1(certificates, crl, admitted),
            Ok(())
        );
        let mut rejected = admitted;
        rejected.not_after_unix_seconds = forged_end;
        assert!(rejected.validate().is_ok());
        assert!(validate_zk_x509_presentation_interval_v1(certificates, crl, rejected).is_err());

        let fixture = build_zk_x509_interval_fixture_v1(certificates, crl, admitted)
            .expect("genuinely signed interval fixture");
        let trace = build_zk_x509_rfc5280_trace_v1(
            &fixture.witness.certificate_chain_der,
            &fixture.witness.crl_der,
            rfc_statement_with_crl_number_v1(
                &fixture.statement,
                fixture.authoritative_state.crl_record().crl_number,
            ),
        )
        .expect("admitted window trace");
        let material = build_zk_x509_rfc5280_stark_base_material_v1(&trace)
            .expect("admitted window base material");
        // The verifier compiles its fixed columns from the public statement
        // alone; only the public end differs.
        let mut forged_shape = material.schedule.shape;
        assert_eq!(
            forged_shape.presentation_not_after_unix_seconds,
            admitted.not_after_unix_seconds
        );
        forged_shape.presentation_not_after_unix_seconds = forged_end;
        let forged = compile_zk_x509_rfc5280_stark_fixed_schedule_v1(forged_shape)
            .expect("the forged window is a well-shaped public statement");
        assert_eq!(forged.starts, material.schedule.starts);
        assert_eq!(forged.counts, material.schedule.counts);
        Self {
            material,
            forged,
            forged_end,
        }
    }

    fn relation_first(&self, slot: usize) -> usize {
        self.material.schedule.starts[ZkX509Rfc5280StarkFamilyV1::Relation as usize]
            + slot * numeric::RELATION_PHASES_V1
    }

    fn range_first(&self, slot: usize) -> usize {
        self.material.schedule.starts[ZkX509Rfc5280StarkFamilyV1::RangeByte as usize]
            + slot * numeric::RANGE_BYTES_PER_RELATION_V1
    }

    /// Rows `first..=first + count` as a prover commits them against
    /// `schedule`, after `forge` edits the row at each offset. The last row is
    /// only the successor of the final transition.
    fn commit(
        &self,
        schedule: &ZkX509Rfc5280StarkFixedScheduleV1,
        first: usize,
        count: usize,
        forge: impl Fn(usize, &mut ZkX509Rfc5280StarkBaseRowV1),
    ) -> Vec<ZkX509Rfc5280StarkBaseRowV1> {
        (0..=count)
            .map(|offset| {
                let mut row = self.material.base_row(first + offset).unwrap();
                if offset < count {
                    forge(offset, &mut row);
                }
                // The prover derives every helper column from the row it commits.
                populate_degree_normalization_helpers_v1(
                    &mut row,
                    &schedule.fixed_row(first + offset).unwrap(),
                );
                row
            })
            .collect()
    }

    /// The two relation rows of one slot with the right operand moved to the
    /// forged end and the given slack and strict-inverse.
    fn forged_relation(
        &self,
        slot: usize,
        slack: F,
        inverse: F,
    ) -> Vec<ZkX509Rfc5280StarkBaseRowV1> {
        let forged_end = F(self.forged_end);
        self.commit(
            &self.forged,
            self.relation_first(slot),
            numeric::RELATION_PHASES_V1,
            |phase, row| {
                row[BASE_B] = forged_end;
                row[BASE_C] = slack;
                row[BASE_INVERSE] = inverse;
                if phase == 1 {
                    // The right operand is the public window end.
                    row[BASE_G] = forged_end;
                }
            },
        )
    }

    /// The eight range rows of one slot re-committed to the big-endian bytes
    /// of `slack`, with a consistent accumulator chain.
    fn forged_range(&self, slot: usize, slack: F) -> Vec<ZkX509Rfc5280StarkBaseRowV1> {
        let bytes = slack.0.to_be_bytes();
        self.commit(
            &self.forged,
            self.range_first(slot),
            numeric::RANGE_BYTES_PER_RELATION_V1,
            |offset, row| {
                let before = bytes[..offset]
                    .iter()
                    .fold(0_u64, |state, byte| state * 256 + u64::from(*byte));
                row[BASE_VALUE] = F(u64::from(bytes[offset]));
                write_u8_bits_v1(row, BASE_BYTE_BITS, bytes[offset]);
                row[BASE_STATE_BEFORE] = F(before);
                row[BASE_STATE_AFTER] = F(before * 256 + u64::from(bytes[offset]));
            },
        )
    }
}

/// Whether each transition of consecutive committed rows leaves a non-zero
/// challenge-independent residue under the verifier's fixed rows.
fn presentation_interval_violations_v1(
    rows: &[ZkX509Rfc5280StarkBaseRowV1],
    schedule: &ZkX509Rfc5280StarkFixedScheduleV1,
    first: usize,
) -> Vec<bool> {
    let unused = [F::ZERO; ZK_X509_RFC5280_STARK_AUX_WIDTH_V1];
    let base_residues = RFC5280_RESIDUE_SECTIONS_V1[..12]
        .iter()
        .map(|(_, count)| count)
        .sum::<usize>();
    rows.windows(2)
        .enumerate()
        .map(|(offset, pair)| {
            let residues = evaluate_zk_x509_rfc5280_stark_residues_v1(
                &pair[0],
                &pair[1],
                &unused,
                &unused,
                &schedule.fixed_row(first + offset).unwrap(),
                der_challenges_v1(),
                &challenges_v1(),
                ZkX509Rfc5280StarkTerminalClaimsV1::canonical_identity_v1(),
            )
            .unwrap();
            residues[..base_residues]
                .iter()
                .any(|residue| *residue != F::ZERO)
        })
        .collect()
}

/// The copy-bus tuple that ties a relation slack to its range terminal.
fn presentation_interval_copy_tuple_v1(row: &ZkX509Rfc5280StarkBaseRowV1) -> [F; 4] {
    [
        row[BASE_COPY_DOMAIN],
        row[BASE_COPY_KEY_1],
        row[BASE_COPY_KEY_2],
        row[BASE_COPY_VALUE],
    ]
}

/// The honest rows of one slot satisfy every base constraint, carry the
/// expected operands, and publish their slack to the range terminal.
fn assert_presentation_interval_slot_is_honest_v1(
    case: &PresentationIntervalMaterialV1,
    slot: usize,
    left: u64,
    right: u64,
) {
    let honest = &case.material.schedule;
    let relation = case.commit(
        honest,
        case.relation_first(slot),
        numeric::RELATION_PHASES_V1,
        |_, _| {},
    );
    assert_eq!(
        presentation_interval_violations_v1(&relation, honest, case.relation_first(slot)),
        [false, false],
        "slot {slot}: honest relation rows"
    );
    for row in &relation[..numeric::RELATION_PHASES_V1] {
        assert_eq!(row[BASE_ACTIVE], F::ONE, "slot {slot} is active");
        assert_eq!(row[BASE_A], F(left), "slot {slot}: left operand");
        assert_eq!(row[BASE_B], F(right), "slot {slot}: right operand");
        assert_eq!(row[BASE_C], F(left - right), "slot {slot}: slack");
    }
    assert_eq!(relation[1][BASE_G], F(right), "slot {slot}: public operand");
    let range = case.commit(
        honest,
        case.range_first(slot),
        numeric::RANGE_BYTES_PER_RELATION_V1,
        |_, _| {},
    );
    assert_eq!(
        presentation_interval_violations_v1(&range, honest, case.range_first(slot)),
        [false; numeric::RANGE_BYTES_PER_RELATION_V1],
        "slot {slot}: honest range rows"
    );
    let terminal = &range[numeric::RANGE_BYTES_PER_RELATION_V1 - 1];
    assert_eq!(terminal[BASE_STATE_AFTER], F(left - right));
    assert_eq!(relation[1][BASE_COPY_SOURCE_ACTIVE], F::ONE);
    assert_eq!(terminal[BASE_COPY_CONSUMER_ACTIVE], F::ONE);
    assert_eq!(
        presentation_interval_copy_tuple_v1(&relation[1]),
        presentation_interval_copy_tuple_v1(terminal),
        "slot {slot}: the slack is copied to its range terminal"
    );
}

/// Every way to commit the binding slot against the forged public end fails.
///
/// `left` is the signed bound and `honest_right` the admitted public end, so
/// the forged end needs the slack `left - forged_end`, one below the admitted
/// slack.
fn assert_presentation_interval_binding_slot_rejects_v1(
    case: &PresentationIntervalMaterialV1,
    slot: usize,
    left: u64,
    honest_right: u64,
) {
    let descriptor = numeric::relation_slot_v1(slot).unwrap();
    let relation_first = case.relation_first(slot);
    let range_first = case.range_first(slot);
    let honest_slack = F(left - honest_right);
    let honest_inverse = if descriptor.strict {
        honest_slack.inv().expect("strict slack is non-zero")
    } else {
        F::ZERO
    };
    // 1. The honest rows against the forged schedule: the public operand no
    //    longer equals the verifier's fixed cell.
    let stale = case.commit(
        &case.forged,
        relation_first,
        numeric::RELATION_PHASES_V1,
        |_, _| {},
    );
    assert_eq!(
        presentation_interval_violations_v1(&stale, &case.forged, relation_first),
        [false, true],
        "slot {slot}: the admitted end is not the forged public end"
    );
    // 2. The operand moved to the forged end with the honest slack: the sum
    //    `left = right + slack` fails on both phases.
    let shifted = case.forged_relation(slot, honest_slack, honest_inverse);
    assert_eq!(
        presentation_interval_violations_v1(&shifted, &case.forged, relation_first),
        [true, true],
        "slot {slot}: the honest slack does not reach the forged end"
    );
    // 3. The slack repaired in the field.
    let repaired_slack = F(left).sub(F(case.forged_end));
    assert_eq!(repaired_slack, honest_slack.sub(F::ONE));
    if descriptor.strict && repaired_slack == F::ZERO {
        // A strict slot needs a non-zero slack: no inverse satisfies
        // `slack * inverse = 1`, whatever the prover commits.
        for inverse in [F::ZERO, F::ONE, honest_inverse] {
            let repaired = case.forged_relation(slot, repaired_slack, inverse);
            assert_eq!(
                presentation_interval_violations_v1(&repaired, &case.forged, relation_first),
                [true, true],
                "slot {slot}: equality with the strict bound"
            );
        }
        return;
    }
    // Otherwise the admitted slack was zero and the repaired slack is the
    // field-wrapped `-1`: the relation rows alone are satisfied.
    assert_eq!(honest_slack, F::ZERO, "slot {slot} binds with equality");
    assert_eq!(repaired_slack, F::ZERO.sub(F::ONE));
    let repaired = case.forged_relation(slot, repaired_slack, F::ZERO);
    assert_eq!(
        presentation_interval_violations_v1(&repaired, &case.forged, relation_first),
        [false, false],
        "slot {slot}: the wrapped slack satisfies the relation rows alone"
    );
    // 3a. The honest range rows are still valid rows, but they carry slack
    //     zero: the copy bus no longer matches the wrapped slack.
    let honest_range = case.commit(
        &case.forged,
        range_first,
        numeric::RANGE_BYTES_PER_RELATION_V1,
        |_, _| {},
    );
    assert_eq!(
        presentation_interval_violations_v1(&honest_range, &case.forged, range_first),
        [false; numeric::RANGE_BYTES_PER_RELATION_V1]
    );
    assert_ne!(
        presentation_interval_copy_tuple_v1(&repaired[1]),
        presentation_interval_copy_tuple_v1(
            &honest_range[numeric::RANGE_BYTES_PER_RELATION_V1 - 1]
        ),
        "slot {slot}: the honest range bytes do not carry the wrapped slack"
    );
    // 3b. Range rows re-committed to the wrapped slack do carry it, and its
    //     leading bytes violate the 38-bit bound.
    let wrapped_range = case.forged_range(slot, repaired_slack);
    assert_eq!(
        presentation_interval_copy_tuple_v1(&repaired[1]),
        presentation_interval_copy_tuple_v1(
            &wrapped_range[numeric::RANGE_BYTES_PER_RELATION_V1 - 1]
        )
    );
    // The wrapped slack is `p - 1 = 0xFFFF_FFFF_0000_0000`: its three leading
    // bytes must be zero and the top two bits of its fourth byte must be
    // clear. The four low bytes are zero and violate nothing, so the
    // rejection is exactly the range bound.
    assert_eq!(
        repaired_slack.0.to_be_bytes(),
        [0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0]
    );
    assert_eq!(
        presentation_interval_violations_v1(&wrapped_range, &case.forged, range_first),
        [true, true, true, true, false, false, false, false],
        "slot {slot}: the wrapped slack exceeds the 38-bit range"
    );
}

/// A slot whose signed bound still covers the forged end is satisfiable: the
/// rejection comes from the binding slot alone.
fn assert_presentation_interval_slack_slot_still_holds_v1(
    case: &PresentationIntervalMaterialV1,
    slot: usize,
    left: u64,
) {
    assert!(left > case.forged_end);
    let slack = F(left - case.forged_end);
    let inverse = if numeric::relation_slot_v1(slot).unwrap().strict {
        slack.inv().expect("strict slack is non-zero")
    } else {
        F::ZERO
    };
    let relation = case.forged_relation(slot, slack, inverse);
    assert_eq!(
        presentation_interval_violations_v1(&relation, &case.forged, case.relation_first(slot)),
        [false, false],
        "slot {slot}: a later signed bound covers the forged end"
    );
    let range = case.forged_range(slot, slack);
    assert_eq!(
        presentation_interval_violations_v1(&range, &case.forged, case.range_first(slot)),
        [false; numeric::RANGE_BYTES_PER_RELATION_V1]
    );
    assert_eq!(
        presentation_interval_copy_tuple_v1(&relation[1]),
        presentation_interval_copy_tuple_v1(&range[numeric::RANGE_BYTES_PER_RELATION_V1 - 1])
    );
}

#[test]
fn forged_window_end_past_the_earliest_expiry_violates_the_air_at_each_path_position() {
    use iroha_data_model::privacy::{
        PrivacyZkX509CertificateValidityV1, PrivacyZkX509CrlUpdateIntervalV1,
        PrivacyZkX509PresentationWindowV1,
    };
    const T: u64 = PRESENTATION_INTERVAL_T;
    let earliest_expiry = T + 150;
    let later_expiry = T + 86_400;
    let crl = PrivacyZkX509CrlUpdateIntervalV1::new(T, T + 301);
    for position in 0..3 {
        let mut expiries = [later_expiry, later_expiry + 3_600, 1_893_456_000];
        expiries[position] = earliest_expiry;
        let certificates = [
            PrivacyZkX509CertificateValidityV1::new(T - 3_600, expiries[0]),
            PrivacyZkX509CertificateValidityV1::new(T - 7_200, expiries[1]),
            PrivacyZkX509CertificateValidityV1::new(1_640_995_200, expiries[2]),
        ];
        // The forged end is one second past the earliest expiry while the
        // other certificates and the CRL still cover it.
        let case = PresentationIntervalMaterialV1::new(
            &certificates,
            crl,
            PrivacyZkX509PresentationWindowV1::new(T, earliest_expiry),
            earliest_expiry + 1,
        );
        for (certificate, expiry) in expiries.into_iter().enumerate() {
            let slot = 2 * certificate + 1;
            let descriptor = numeric::relation_slot_v1(slot).unwrap();
            assert_eq!(descriptor.relation, PRESENTATION_INTERVAL_UPPER_RELATION);
            assert_eq!(usize::from(descriptor.instance), certificate);
            assert!(!descriptor.strict);
            assert_eq!(descriptor.right, numeric::NumericOperandV1::WindowEnd);
            assert_presentation_interval_slot_is_honest_v1(&case, slot, expiry, earliest_expiry);
            if certificate == position {
                assert_presentation_interval_binding_slot_rejects_v1(
                    &case,
                    slot,
                    expiry,
                    earliest_expiry,
                );
            } else {
                assert_presentation_interval_slack_slot_still_holds_v1(&case, slot, expiry);
            }
        }
        // The two CRL upper slots still cover the forged end as well.
        assert_presentation_interval_slack_slot_still_holds_v1(
            &case,
            PRESENTATION_INTERVAL_NEXT_UPDATE_SLOT,
            crl.next_update_unix_seconds,
        );
        assert_presentation_interval_slack_slot_still_holds_v1(
            &case,
            PRESENTATION_INTERVAL_CRL_AGE_SLOT,
            T + 300,
        );
    }
}

#[test]
fn forged_window_end_at_next_update_or_past_the_crl_age_violates_the_air() {
    use iroha_data_model::privacy::{
        PrivacyZkX509CertificateValidityV1, PrivacyZkX509CrlUpdateIntervalV1,
        PrivacyZkX509PresentationWindowV1,
    };
    const T: u64 = PRESENTATION_INTERVAL_T;
    let wide = PrivacyZkX509CertificateValidityV1::new(1_640_995_200, 1_893_456_000);
    let certificates = [wide, wide];
    // nextUpdate is exclusive: the admitted end is nextUpdate - 1 with strict
    // slack one, and the forged end equals nextUpdate.
    let next_update = T + 200;
    let case = PresentationIntervalMaterialV1::new(
        &certificates,
        PrivacyZkX509CrlUpdateIntervalV1::new(T, next_update),
        PrivacyZkX509PresentationWindowV1::new(T, next_update - 1),
        next_update,
    );
    let descriptor = numeric::relation_slot_v1(PRESENTATION_INTERVAL_NEXT_UPDATE_SLOT).unwrap();
    assert!(descriptor.strict);
    assert_eq!(descriptor.right, numeric::NumericOperandV1::WindowEnd);
    assert_presentation_interval_slot_is_honest_v1(
        &case,
        PRESENTATION_INTERVAL_NEXT_UPDATE_SLOT,
        next_update,
        next_update - 1,
    );
    assert_presentation_interval_binding_slot_rejects_v1(
        &case,
        PRESENTATION_INTERVAL_NEXT_UPDATE_SLOT,
        next_update,
        next_update - 1,
    );
    // The CRL-age slot and both certificate slots still cover that end.
    assert_presentation_interval_slack_slot_still_holds_v1(
        &case,
        PRESENTATION_INTERVAL_CRL_AGE_SLOT,
        T + 300,
    );
    for slot in [1, 3] {
        assert_presentation_interval_slack_slot_still_holds_v1(
            &case,
            slot,
            wide.not_after_unix_seconds(),
        );
    }
    // The age cap: the admitted end is thisUpdate + 300 and the forged end is
    // one second later, while nextUpdate is an hour away.
    let case = PresentationIntervalMaterialV1::new(
        &certificates,
        PrivacyZkX509CrlUpdateIntervalV1::new(T, T + 3_600),
        PrivacyZkX509PresentationWindowV1::new(T + 1, T + 300),
        T + 301,
    );
    let descriptor = numeric::relation_slot_v1(PRESENTATION_INTERVAL_CRL_AGE_SLOT).unwrap();
    assert!(!descriptor.strict);
    assert_eq!(descriptor.right, numeric::NumericOperandV1::WindowEnd);
    assert_presentation_interval_slot_is_honest_v1(
        &case,
        PRESENTATION_INTERVAL_CRL_AGE_SLOT,
        T + 300,
        T + 300,
    );
    assert_presentation_interval_binding_slot_rejects_v1(
        &case,
        PRESENTATION_INTERVAL_CRL_AGE_SLOT,
        T + 300,
        T + 300,
    );
    assert_presentation_interval_slack_slot_still_holds_v1(
        &case,
        PRESENTATION_INTERVAL_NEXT_UPDATE_SLOT,
        T + 3_600,
    );
}
