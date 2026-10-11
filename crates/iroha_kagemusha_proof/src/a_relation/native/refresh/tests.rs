//! Native Refresh artifact and exact-original rejection coverage.

use super::*;

#[test]
fn fixed_refresh_schedules_require_each_owner_exactly_once() {
    for (v, n) in [
        (Variant::RefreshCredential, 4),
        (Variant::RefreshSchemePolicy, 4),
        (Variant::RefreshBlacklist, 4),
        (Variant::RefreshQuotaShare, 7),
        (Variant::RefreshTimeAnchor, 4),
    ] {
        let schedule = crate::a_relation::schedule::compiled::OperationSchedule::for_variant(v);
        let partition = schedule.q_partitions().to_vec();
        let tasks = schedule.tasks().to_vec();
        assert_eq!(partition.len(), n);
        assert_eq!(tasks.len(), n);
        if v == Variant::RefreshQuotaShare {
            assert_eq!(
                partition,
                [vec![], vec![], vec![], vec![0], vec![1], vec![2], vec![]]
            );
            assert_eq!(
                tasks[0],
                [
                    OperationTask::RefreshEffects,
                    OperationTask::RefreshQuotaPreviousRoot
                ]
            );
            assert_eq!(tasks[1], [OperationTask::RefreshQuotaWindowRoot]);
            assert_eq!(tasks[2], [OperationTask::RefreshQuotaUsageRoot]);
            assert_eq!(tasks[6], [OperationTask::RefreshQuotaMerge]);
        } else {
            assert_eq!(partition[..4], [vec![], vec![0], vec![1], vec![2]]);
        }
        OperationTask::validate(v, &tasks).unwrap();
        for i in 0..tasks.len() {
            if !tasks[i].is_empty() {
                let mut missing = tasks.clone();
                missing[i].pop();
                assert!(OperationTask::validate(v, &missing).is_err());
            }
        }
    }
    assert!(object_kinds(Variant::Load).is_err());
}

fn original() -> Inputs {
    let state = StateWitness {
        core: [Fp::ZERO; 33],
        rest: [Fp::ZERO; 8],
        lineage: [Fp::ZERO; 18],
    };
    let state = RefreshWitness {
        predecessor: state,
        successor: state,
        statement: [Fp::ZERO; 26],
        update: crate::admin_sigma::RefreshUpdateWitness {
            kind: crate::admin_sigma::RefreshKind::Credential,
            digest: Fp::ZERO,
            scheme: [Fp::ZERO; 2],
            asset: [Fp::ZERO; 2],
            wallet: [Fp::ZERO; 2],
            counter: Fp::ZERO,
            issued_at_ms: Fp::ZERO,
            expires_at_ms: Fp::ZERO,
            root: Fp::ZERO,
            controls: Fp::ZERO,
            fee_schedule: Fp::ZERO,
        },
    };
    let sigma = (0..64).collect::<Vec<u8>>();
    let mut raw = u32::try_from(sigma.len()).unwrap().to_le_bytes().to_vec();
    raw.extend(&sigma);
    let statement = hash_with_domain(
        iroha_plonk_gadgets::statement::STATEMENT_DOMAIN,
        &state.statement,
    );
    let mut bounded = vec![Fq::from_repr(statement.to_repr()).unwrap()];
    bounded.extend(raw.chunks(31).map(|chunk| le_value::<Fq>(chunk).unwrap()));
    bounded.extend([Fq::ONE; K]);
    Inputs {
        state,
        sigma,
        objects: core::array::from_fn(|_| vec![]),
        blacklist: None,
        quota: None,
        q: [
            QInput {
                proof: vec![],
                instances: vec![
                    bounded,
                    vec![],
                    vec![Fq::from(14)],
                    vec![Fq::ONE],
                    vec![Fq::from(12)],
                ],
            },
            QInput {
                proof: vec![],
                instances: vec![],
            },
            QInput {
                proof: vec![],
                instances: vec![],
            },
        ],
        predecessor: PredecessorInput {
            proof: vec![],
            pallas: [0; 544],
            vesta: [0; 544],
        },
    }
}

#[test]
fn exact_refresh_sigma_tape_statement_length_and_selector_are_bound() {
    let source = original();
    assert_eq!(
        check_sigma_tape(&source, Variant::RefreshCredential),
        Ok(())
    );
    for mutation in 0..6 {
        let mut bad = source.clone();
        match mutation {
            0 => bad.sigma[40] ^= 1,
            1 => bad.sigma.push(7),
            2 => bad.q[0].instances[0][1] += Fq::ONE,
            3 => bad.q[0].instances[2][0] = Fq::ZERO,
            4 => bad.q[0].instances[2][0] = Fq::from(2),
            _ => bad.state.statement[20] += Fp::ONE,
        }
        assert_eq!(
            check_sigma_tape(&bad, Variant::RefreshCredential),
            Err(Error::Input),
            "mutation{mutation}"
        );
    }
}

#[test]
fn refresh_q_sigma_normalization_rejects_wrong_selector_source_or_scalar_alias() {
    let mut input = original().q[0].clone();
    let point = iroha_plonk::transcript::decode_point::<Eq>(
        &iroha_plonk_recursion::VESTA_TRIVIAL_GENERATOR,
    )
    .unwrap();
    let (x, y) = Option::<(Fq, Fq)>::from(point.coordinates()).unwrap();
    input.instances[1] = vec![x, y];
    let n = input.instances[0].len();
    input.instances[0][n - K..n - K + 4].fill(Fq::ZERO);
    assert!(q_sigma_part(&input, 12, Variant::RefreshCredential).is_ok());
    for mutation in 0..6 {
        let mut bad = input.clone();
        match mutation {
            0 => bad.instances[0][n - K] = Fq::ONE,
            1 => bad.instances[0][n - 1] = Fq::ZERO,
            2 => bad.instances[1] = vec![Fq::ZERO, Fq::ZERO],
            3 => bad.instances[3][0] = Fq::ZERO,
            4 => bad.instances[4][0] = Fq::from(16),
            _ => bad.instances[2][0] = Fq::ZERO,
        }
        assert!(
            q_sigma_part(&bad, 12, Variant::RefreshCredential).is_err(),
            "mutation{mutation}"
        );
    }
    let p = [
        0x992d_30ed_0000_0001_u64,
        0x2246_98fc_094c_f91b,
        0,
        0x4000_0000_0000_0000,
    ];
    let mut repr = [0; 32];
    for (to, word) in repr.chunks_exact_mut(8).zip(p) {
        to.copy_from_slice(&word.to_le_bytes());
    }
    let mut alias = input;
    alias.instances[0][n - 1] = Fq::from_repr(repr).unwrap();
    assert!(q_sigma_part(&alias, 12, Variant::RefreshCredential).is_err());
}

#[test]
fn all_five_signed_originals_bind_body_and_each_raw_signature_limb() {
    assert_eq!(
        object_kinds(Variant::RefreshCredential).unwrap(),
        [
            ObjectKind::Certificate,
            ObjectKind::Credential,
            ObjectKind::Receipt,
            ObjectKind::Certificate,
            ObjectKind::Credential
        ]
    );
    for kind in object_kinds(Variant::RefreshQuotaShare).unwrap() {
        let raw = (0..kind.body_len() + 64)
            .map(|i| u8::try_from(i % 256).unwrap())
            .collect::<Vec<_>>();
        let digest = object_digest(kind, &raw).unwrap();
        for index in [
            0,
            kind.body_len() - 1,
            kind.body_len(),
            kind.body_len() + 16,
            kind.body_len() + 32,
            kind.body_len() + 48,
        ] {
            let mut changed = raw.clone();
            changed[index] ^= 1;
            assert_ne!(object_digest(kind, &changed).unwrap(), digest);
        }
        assert!(object_digest(kind, &raw[..raw.len() - 1]).is_err());
    }
}

#[test]
fn final_digest_has_exact52_fields_and_keeps_high_foreign_challenge_limbs() {
    let ep = iroha_plonk::transcript::decode_point::<Ep>(
        &iroha_plonk_recursion::PALLAS_TRIVIAL_GENERATOR,
    )
    .unwrap();
    let eq = iroha_plonk::transcript::decode_point::<Eq>(
        &iroha_plonk_recursion::VESTA_TRIVIAL_GENERATOR,
    )
    .unwrap();
    let mut challenges = [Fq::ONE; K];
    challenges[15] = Fq::from(2).pow_vartime([200]);
    let pallas = FoldInput::from_normalized(ep, 16, challenges).unwrap();
    let fields = core::array::from_fn(|i| Fp::from(u64::try_from(i).unwrap() + 1));
    let digest = terminal_digest(&fields, &pallas).unwrap();
    let (x, y) = Option::<(Fp, Fp)>::from(ep.coordinates()).unwrap();
    let mut expected = fields.to_vec();
    expected.extend([x, y]);
    for challenge in challenges {
        let repr = challenge.to_repr();
        expected.push(Fp::from_u128(u128::from_le_bytes(
            repr[..16].try_into().unwrap(),
        )));
        expected.push(Fp::from_u128(u128::from_le_bytes(
            repr[16..].try_into().unwrap(),
        )));
    }
    assert_eq!(expected.len(), 52);
    assert_eq!(
        digest,
        hash_with_domain(super::super::super::LINEAGE_DOMAIN, &expected)
    );
    challenges[15] = Fq::ONE;
    assert_ne!(
        digest,
        terminal_digest(
            &fields,
            &FoldInput::from_normalized(ep, 16, challenges).unwrap()
        )
        .unwrap()
    );
    let part = FoldInput::from_normalized(eq, 16, [Fp::ONE; K]).unwrap();
    let public = internal_public(digest, &part).unwrap();
    assert_eq!(public.len(), 69);
    assert_eq!(&public[62..65], &[Fp::ZERO, Fp::ONE, Fp::ZERO]);
    assert_eq!(&public[22..42], &public[42..62]);
    assert_eq!(&public[65..69], &public[22..26]);
}

#[test]
fn refresh_uses_one_shared_sigma_selector_and_rejects_unrelated_variants() {
    for variant in [
        Variant::RefreshCredential,
        Variant::RefreshSchemePolicy,
        Variant::RefreshBlacklist,
        Variant::RefreshQuotaShare,
        Variant::RefreshTimeAnchor,
    ] {
        assert_eq!(check_sigma_tape(&original(), variant), Ok(()));
        assert_eq!(sigma_selector(variant), Ok(Fq::from(14)));
    }
    assert_eq!(
        check_sigma_tape(&original(), Variant::Load),
        Err(Error::Artifact)
    );
}

#[test]
fn quota_native_proposals_commit_all_array_boundaries_and_signed_fields() {
    let mut value = QuotaInput {
        old: core::array::from_fn(|i| {
            core::array::from_fn(|j| Fp::from(u64::try_from(i * 4 + j + 1).unwrap()))
        }),
        windows: core::array::from_fn(|i| {
            core::array::from_fn(|j| Fp::from(u64::try_from(i * 4 + j + 257).unwrap()))
        }),
        used: core::array::from_fn(|i| Fp::from(u64::try_from(i + 513).unwrap())),
        issued: Fp::from(577),
        window_count: Fp::from(578),
    };
    let original = value.commitments();
    assert_eq!(&original[3..], &[Fp::from(577), Fp::from(578)]);
    for i in [0, 63] {
        let mut changed = value.clone();
        changed.old[i][3] += Fp::ONE;
        assert_ne!(changed.commitments()[0], original[0]);
        assert_eq!(&changed.commitments()[1..], &original[1..]);
        let mut changed = value.clone();
        changed.windows[i][3] += Fp::ONE;
        assert_ne!(changed.commitments()[1], original[1]);
        let mut changed = value.clone();
        changed.used[i] += Fp::ONE;
        assert_ne!(changed.commitments()[2], original[2]);
    }
    value.windows = value.old;
    assert_ne!(
        value.commitments()[0],
        value.commitments()[1],
        "different typed array tags"
    );
    value.issued += Fp::ONE;
    value.window_count += Fp::ONE;
    assert_ne!(&value.commitments()[3..], &original[3..]);
}

#[test]
fn fixed_union_projection_rejects_wrong_kind_each_field_and_original_signature() {
    use crate::admin_sigma::{RefreshKind, RefreshUpdateWitness};
    for (variant, kind, typed) in [
        (
            Variant::RefreshCredential,
            ObjectKind::Credential,
            RefreshKind::Credential,
        ),
        (
            Variant::RefreshSchemePolicy,
            ObjectKind::SchemePolicy,
            RefreshKind::SchemePolicy,
        ),
        (
            Variant::RefreshBlacklist,
            ObjectKind::Blacklist,
            RefreshKind::Blacklist,
        ),
        (
            Variant::RefreshQuotaShare,
            ObjectKind::QuotaShare,
            RefreshKind::QuotaShare,
        ),
        (
            Variant::RefreshTimeAnchor,
            ObjectKind::TimeAnchor,
            RefreshKind::TimeAnchor,
        ),
    ] {
        // Projection parsing only: this counting specimen is never authenticated,
        // passed to native Advance, proved, or treated as an admitted signed object.
        let mut raw = vec![0; kind.body_len() + 64];
        raw[0] = 1;
        let expected = RefreshUpdateWitness {
            kind: typed,
            digest: object_digest(kind, &raw).unwrap(),
            scheme: [Fp::ZERO; 2],
            asset: [Fp::ZERO; 2],
            wallet: [Fp::ZERO; 2],
            counter: Fp::ZERO,
            issued_at_ms: Fp::ZERO,
            expires_at_ms: Fp::ZERO,
            root: Fp::ZERO,
            controls: Fp::ZERO,
            fee_schedule: Fp::ZERO,
        };
        assert_eq!(check_update_projection(variant, &expected, &raw), Ok(()));
        for changed in 0..14 {
            let mut altered = expected;
            match changed {
                0 => {
                    altered.kind = if typed == RefreshKind::Credential {
                        RefreshKind::TimeAnchor
                    } else {
                        RefreshKind::Credential
                    }
                }
                1 => altered.digest += Fp::ONE,
                2..=3 => altered.scheme[changed - 2] += Fp::ONE,
                4..=5 => altered.asset[changed - 4] += Fp::ONE,
                6..=7 => altered.wallet[changed - 6] += Fp::ONE,
                8 => altered.counter += Fp::ONE,
                9 => altered.issued_at_ms += Fp::ONE,
                10 => altered.expires_at_ms += Fp::ONE,
                11 => altered.root += Fp::ONE,
                12 => altered.controls += Fp::ONE,
                _ => altered.fee_schedule += Fp::ONE,
            }
            assert_eq!(
                check_update_projection(variant, &altered, &raw),
                Err(Error::Input)
            );
        }
        raw[kind.body_len() + 48] ^= 1;
        assert_eq!(
            check_update_projection(variant, &expected, &raw),
            Err(Error::Input)
        );
        assert_eq!(
            check_update_projection(variant, &expected, &raw[..raw.len() - 1]),
            Err(Error::Input)
        );
    }
}

#[test]
fn typed_refresh_context_schema_rejects_foreign_operations_and_cross_kind_updates() {
    for variant in [
        Variant::RefreshCredential,
        Variant::RefreshSchemePolicy,
        Variant::RefreshBlacklist,
        Variant::RefreshQuotaShare,
        Variant::RefreshTimeAnchor,
    ] {
        let schema = RefreshObjects::context_specs(variant).unwrap();
        assert_eq!(
            schema[..5].iter().map(|spec| spec.tag).collect::<Vec<_>>(),
            [1, 2, 3, 4, 5]
        );
        assert_eq!(
            schema.len(),
            if variant == Variant::RefreshQuotaShare {
                6
            } else {
                5
            }
        );
        if variant == Variant::RefreshQuotaShare {
            assert_eq!(schema[5].tag, 6);
            assert_eq!(schema[5].capacity, 160);
        }
        let lengths = object_kinds(variant)
            .unwrap()
            .map(|kind| u32::try_from(kind.body_len() + 64).unwrap());
        assert_eq!(
            schema[..5]
                .iter()
                .map(|spec| spec.capacity)
                .collect::<Vec<_>>(),
            lengths
        );
    }
    let renewal = RefreshObjects::context_specs(Variant::RefreshCredential).unwrap();
    for variant in [
        Variant::RefreshSchemePolicy,
        Variant::RefreshBlacklist,
        Variant::RefreshQuotaShare,
        Variant::RefreshTimeAnchor,
    ] {
        assert_ne!(
            RefreshObjects::context_specs(variant).unwrap()[1],
            renewal[1]
        );
    }
    for variant in [
        Variant::Bootstrap,
        Variant::Load,
        Variant::Send,
        Variant::Receive,
        Variant::ArchiveReceive,
        Variant::ArchiveStatus,
        Variant::Unload,
        Variant::Retiring,
    ] {
        assert_eq!(
            RefreshObjects::context_specs(variant),
            Err(LayoutError::Synthesis)
        );
    }
}
