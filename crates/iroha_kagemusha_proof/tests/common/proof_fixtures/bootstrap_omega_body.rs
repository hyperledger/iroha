// Shared genuine builder items. Registered tests remain in the integration harness.
use ff::{Field, PrimeField};
use iroha_kagemusha_proof::omega::{OmegaCircuit, OmegaPlan, OmegaWitness};
use iroha_pasta::{Ep, Eq, Fp, Fq, PastaAffine, msm::MemoryBudget};
use iroha_plonk::{
    Protocol, ProverConfig, ProverRandomness, Witness,
    check::{CheckMode, check},
    create_proof_owned_with_claim,
    cs::{
        CircuitDescriptorV1, CircuitDescriptorV2, CurveV1, DescriptorConfig, InstanceModeV1,
        ProofSuffixV1, TranscriptV1, TranscriptV2,
    },
    frontend::synthesize,
    keys::{KeygenConfigV2, keygen_pk_v2},
    pcs::ipa::PinnedParams,
    verifier::accumulate_generator,
};
use iroha_plonk_recursion::{AccumulatorT, FoldConfig, create_fold, verifier::CompactSpans};

// Greedy structural projection with actual retained-primary top locations.
// This does not assign constraints or establish a production schedule.
fn secondary_aligned_projection(
    widths: &[usize],
    segments: &[(bool, usize, usize)],
) -> (usize, std::collections::BTreeMap<usize, usize>, bool) {
    let mut target = std::collections::BTreeMap::<usize, usize>::new();
    for bits in widths {
        *target.entry(*bits).or_default() += 1;
    }
    // A forced secondary step must not read a next-state port owned by
    // another lane. Conservatively exclude every eligible-segment end.
    let forbidden_tops = segments
        .iter()
        .filter(|(_, _, length)| *length > 0)
        .map(|(_, start, length)| start + length - 1)
        .collect::<std::collections::BTreeSet<_>>();
    let mut previous = usize::MAX;
    for _ in 0..64 {
        let mut discard = target.clone();
        let mut pattern = vec![0_u8; 300_000];
        let mut primary_end = 16;
        for bits in widths {
            if let Some(count) = discard.get_mut(bits)
                && *count > 0
            {
                *count -= 1;
                continue;
            }
            let rows = bits.div_ceil(15);
            if !matches!(bits % 15, 1 | 2) {
                while forbidden_tops.contains(&(primary_end + rows - 1)) {
                    primary_end += 1;
                }
            }
            pattern[primary_end..primary_end + rows - 1].fill(1);
            pattern[primary_end + rows - 1] = if bits % 15 == 1 {
                3
            } else if bits % 15 == 2 {
                4
            } else {
                2
            };
            primary_end += rows;
        }
        let mut remaining = target.clone();
        let mut placed = std::collections::BTreeMap::<usize, usize>::new();
        for (pow, start, length) in segments {
            let end = start + length;
            let mut row = *start;
            let order: &[usize] = if *pow {
                &[128, 87, 81]
            } else {
                &[93, 81, 128, 87]
            };
            while row < end {
                let candidate = order
                    .iter()
                    .find(|bits| {
                        let count = remaining.get(bits).copied().unwrap_or(0);
                        let rows = bits.div_ceil(if *pow { 15 } else { 12 });
                        count > 0 && row + rows <= end && pattern[row + rows - 1] != 2
                    })
                    .copied();
                if let Some(bits) = candidate {
                    row += bits.div_ceil(if *pow { 15 } else { 12 });
                    *remaining.get_mut(&bits).unwrap() -= 1;
                    *placed.entry(bits).or_default() += 1;
                } else {
                    row += 1;
                }
            }
        }
        let count = placed.values().sum::<usize>();
        if count == previous {
            return (primary_end, placed, true);
        }
        previous = count;
        target = placed;
    }
    let saved = target
        .iter()
        .map(|(bits, count)| bits.div_ceil(15) * count)
        .sum::<usize>();
    (
        16 + widths.iter().map(|bits| bits.div_ceil(15)).sum::<usize>() - saved,
        target,
        false,
    )
}

/// Checks the complete compact predicate and reports its exact row/byte gates.
pub(crate) fn compact_diagnostic(circuit: &OmegaCircuit, public: &[Vec<Fq>]) {
    let _ = compact_layout(circuit, public, true);
}

pub(crate) fn compact_layout(
    circuit: &OmegaCircuit,
    public: &[Vec<Fq>],
    prove: bool,
) -> Option<(
    CompactSpans,
    iroha_plonk_gadgets::range::secondary::SecondaryPlan,
)> {
    let mut selected_layout = None;
    // Explicitly diagnostic only. All output descriptors below still use k16.
    let spans = CompactSpans::new(32_768, 131_072, 262_138).unwrap();
    let diagnostic = circuit.clone().with_compact_layout(spans);
    let assigned = synthesize(&diagnostic, 18, Some(public)).unwrap();
    let report = check(&assigned.cs, &assigned.tables, CheckMode::Strict).unwrap();
    assert!(report.is_satisfied(), "{:?}", report.failures().first());
    let assigned_rows = assigned.tables.advice_assigned();
    let used = |start: usize, end: usize| {
        assigned_rows[..10]
            .iter()
            .filter_map(|column| column[start..end].iter().rposition(|v| *v).map(|r| r + 1))
            .max()
            .unwrap_or(0)
    };
    let sponge = used(0, 32_768).div_ceil(37) * 37;
    let arithmetic = used(32_768, 131_072);
    let curve = used(131_072, 262_138);
    let range = assigned_rows[10]
        .iter()
        .rposition(|v| *v)
        .map_or(0, |r| r + 1);
    // The compact profile allocates eight phase columns, then
    // two tuple-table columns, top width and range pattern. Audit the actual fixed tape,
    // not a count extrapolated from the host interpreter's operations.
    let fixed = assigned.tables.fixed();
    assert_eq!(fixed.len(), 12);
    let pattern = &fixed[11];
    let widths_column = &fixed[10];
    let mut widths = std::collections::BTreeMap::<usize, (usize, usize)>::new();
    let mut event_widths = Vec::new();
    let mut row = 16;
    while row < range {
        let start = row;
        while pattern[row] == Fq::ONE {
            row += 1;
        }
        let steps = row - start;
        let top = if pattern[row] == Fq::from(3) {
            1
        } else if pattern[row] == Fq::from(4) {
            2
        } else {
            assert_eq!(pattern[row], Fq::from(2));
            (3..=15)
                .find(|bits| widths_column[row] == Fq::from(*bits as u64))
                .unwrap()
        };
        row += 1;
        event_widths.push(15 * steps + top);
        let entry = widths.entry(15 * steps + top).or_default();
        entry.0 += 1;
        entry.1 += row - start;
    }
    assert_eq!(widths.values().map(|v| v.1).sum::<usize>() + 16, range);
    eprintln!("AUTHENTICATED_SOURCE_COMPACT_RANGE widths_count_rows={widths:?}");
    let pure_glue = (32_768..32_768 + arithmetic)
        .filter(|row| fixed[0][*row] == Fq::ZERO && fixed[1][*row] == Fq::ZERO)
        .count();
    let mut kernels = std::collections::BTreeMap::<&str, usize>::new();
    for (row, phase) in fixed[0].iter().enumerate().skip(32_768).take(arithmetic) {
        if *phase != Fq::ONE || fixed[1][row] != Fq::ZERO {
            continue;
        }
        for (name, active) in [
            ("mul", fixed[7][row] == Fq::from(3)),
            ("div", fixed[7][row] == Fq::from(4)),
            ("proper_finish", fixed[7][row] == Fq::from(5)),
            (
                "wide_finish",
                fixed[4][row] == Fq::from(4) && fixed[5][row] == Fq::ZERO,
            ),
            (
                "narrow_finish",
                fixed[4][row] == Fq::from(4) && fixed[5][row] == Fq::from(3),
            ),
        ] {
            if active {
                *kernels.entry(name).or_default() += 1;
            }
        }
    }
    eprintln!("AUTHENTICATED_SOURCE_COMPACT_KERNELS counts={kernels:?}");
    let sponge_spare = (16..sponge)
        .filter(|row| {
            fixed[1][*row] == Fq::ONE
                && [0, 1, 2, 4, 5, 9]
                    .iter()
                    .all(|col| !assigned_rows[*col][*row])
        })
        .count();
    eprintln!(
        "AUTHENTICATED_SOURCE_COMPACT_SPARE pure_glue_rows={pure_glue} staged_ff_rows={} sponge_six_spare_rows={sponge_spare} optimistic_87bit_secondary_checks={} secondary_not_implemented=true",
        arithmetic - pure_glue,
        pure_glue / 8 + sponge_spare / 6
    );

    // Structural component placement estimate. Only wholly unused state/digit
    // ports count; no query, cell or phase is overwritten by this diagnostic.
    let mut segments = Vec::<(bool, usize, usize)>::new();
    let mut segment_start = 0;
    let mut current = None;
    let mut length = 0;
    for (packed_row, row) in (0..sponge).chain(32_768..32_768 + arithmetic).enumerate() {
        let phase = if fixed[1][row] == Fq::ONE
            && [0, 1, 2, 4, 5, 9]
                .iter()
                .all(|column| !assigned_rows[*column][row])
        {
            Some(true)
        } else if fixed[0][row] == Fq::ZERO
            && fixed[1][row] == Fq::ZERO
            && [4, 5, 6, 7, 8, 9]
                .iter()
                .all(|column| !assigned_rows[*column][row])
        {
            Some(false)
        } else {
            None
        };
        if phase == current && phase.is_some() {
            length += 1;
        } else {
            if let Some(previous) = current {
                segments.push((previous, segment_start, length));
            }
            current = phase;
            segment_start = packed_row;
            length = usize::from(phase.is_some());
        }
    }
    if let Some(previous) = current {
        segments.push((previous, segment_start, length));
    }
    let mut pool = widths
        .iter()
        .map(|(bits, (count, _))| (*bits, *count))
        .collect::<std::collections::BTreeMap<_, _>>();
    let mut saved = 0;
    let mut used_secondary = 0;
    let mut selected = std::collections::BTreeMap::<usize, usize>::new();
    let mut available = [0_usize; 2];
    for (is_sponge, _, length) in &segments {
        available[usize::from(*is_sponge)] += length;
        let mut remaining = *length;
        let order: &[usize] = if *is_sponge {
            &[128, 87, 81]
        } else {
            &[93, 81, 128, 87]
        };
        for bits in order {
            let rows = bits.div_ceil(if *is_sponge { 15 } else { 12 });
            let Some(count) = pool.get_mut(bits) else {
                continue;
            };
            let chosen = (*count).min(remaining / rows);
            *count -= chosen;
            remaining -= chosen * rows;
            used_secondary += chosen * rows;
            saved += chosen * bits.div_ceil(15);
            *selected.entry(*bits).or_default() += chosen;
        }
    }
    eprintln!(
        "AUTHENTICATED_SOURCE_SECONDARY_PLACEMENT eligible_glue_pow={available:?} segments={} selected={selected:?} secondary_rows={used_secondary} optimistic_saved_primary={saved} remaining_primary={} primary_top_alignment_not_yet_applied=true",
        segments.len(),
        range - saved
    );

    let total = sponge + arithmetic + curve;
    // Reserve37 rows for the real public-prefix/Poseidon separation. The
    // remainder may become an explicit empty-Glue span in the candidate.
    let padding = 65_530_usize.saturating_sub(total + 37);
    let mut padded = segments
        .iter()
        .map(|(pow, start, len)| (*pow, start + 37, *len))
        .collect::<Vec<_>>();
    padded.push((false, sponge + arithmetic + 37, padding));
    let aligned = secondary_aligned_projection(&event_widths, &padded);
    eprintln!(
        "AUTHENTICATED_SOURCE_SECONDARY_ALIGNED primary_remaining={} selected={:?} fixed_point={} padding_glue={padding} source_trace_only=true checked_replay_follows=true",
        aligned.0, aligned.1, aligned.2
    );
    // Executable replay candidate. Its immutable plan is built solely from
    // this fixed tape and spare-port occupancy, then checked by guards during
    // both actual and unknown synthesis.
    if aligned.2 && aligned.0 <= 65_530 && total + 37 <= 65_530 {
        use iroha_plonk_gadgets::range::secondary::{SecondaryPhase, SecondaryPlan};
        let mut phases = vec![None; 65_530];
        for (packed_row, row) in (0..sponge).chain(32_768..32_768 + arithmetic).enumerate() {
            let high = fixed[1][row] == Fq::ONE;
            let low = fixed[0][row] == Fq::ONE;
            let active = assigned.tables.fixed_assigned()[0][row]
                && assigned.tables.fixed_assigned()[1][row];
            let ports: &[usize] = if high {
                &[0, 1, 2, 4, 5, 9]
            } else {
                &[4, 5, 6, 7, 8, 9]
            };
            let free = ports
                .iter()
                .all(|column| !assigned_rows[*column][row] || row < 16 && *column < 3);
            if active && (high || !low) {
                assert!(
                    ports
                        .iter()
                        .all(|column| !assigned_rows[*column][row] || row < 16 && *column < 3),
                    "live secondary digit row {row}"
                );
            }
            if free && (high || !low) {
                phases[packed_row + 37] = Some(if high {
                    if low {
                        SecondaryPhase::PairedPoseidon
                    } else {
                        SecondaryPhase::Poseidon
                    }
                } else {
                    SecondaryPhase::Glue
                });
            }
        }
        phases[sponge + arithmetic + 37..sponge + arithmetic + 37 + padding]
            .fill(Some(SecondaryPhase::Glue));
        let plan = match SecondaryPlan::new(event_widths.clone(), phases.clone()) {
            Ok(plan) => plan,
            Err(error) => {
                phases.resize(262_138, None);
                let expanded = SecondaryPlan::new(event_widths.clone(), phases).unwrap();
                panic!(
                    "secondary plan {error:?}: exact range {}, hard limit65530",
                    expanded.primary_end()
                );
            }
        };
        eprintln!(
            "AUTHENTICATED_SECONDARY_REPLAY_PLAN events={} range={}",
            plan.event_count(),
            plan.primary_end()
        );
        let spans =
            CompactSpans::new(sponge + 37, sponge + arithmetic + 37 + padding, 65_530).unwrap();
        let candidate = circuit.clone().with_secondary_layout(spans, plan.clone());
        selected_layout = Some((spans, plan));
        let compiled = synthesize(&candidate, 16, Some(public)).unwrap();
        let checked = check(&compiled.cs, &compiled.tables, CheckMode::Strict).unwrap();
        assert!(
            checked.is_satisfied(),
            "secondary replay: {:?}",
            checked.failures().first()
        );
        let unknown = synthesize(
            &iroha_plonk::frontend::Circuit::without_witnesses(&candidate),
            16,
            None,
        )
        .unwrap();
        assert_eq!(compiled.tables.fixed(), unknown.tables.fixed());
        assert_eq!(
            compiled.tables.advice_assigned(),
            unknown.tables.advice_assigned()
        );
        assert_eq!(compiled.tables.permutation(), unknown.tables.permutation());
        eprintln!(
            "AUTHENTICATED_SECONDARY_REPLAY_PREDICATE_PASS known_unknown_equal=true actual_outer_proof=false"
        );
        drop(compiled);
        drop(unknown);
        if prove {
            let params = PinnedParams::<Ep>::derive(16).unwrap();
            let mut key_config = KeygenConfigV2::pipa_r(OmegaPlan::instance_types().to_vec());
            key_config.compress_selectors = false;
            let key = keygen_pk_v2(&params, &candidate, &key_config).unwrap();
            let protocol = Protocol::new(key.binding().descriptor()).unwrap();
            assert_eq!(protocol.shape().degree, 9);
            assert_eq!(protocol.shape().lookups, 1);
            assert_eq!(protocol.proof_length() + 1088, 4800);
            let output = create_proof_owned_with_claim(
                &params,
                &key,
                Witness::from_circuit(&key, &candidate, public).unwrap(),
                ProverRandomness::os(),
                ProverConfig::default(),
            )
            .unwrap();
            let proof = output.proof;
            assert_eq!(proof.len(), protocol.proof_length());
            iroha_plonk::verify_full(
                &params,
                key.binding(),
                key.vk(),
                public,
                &proof,
                MemoryBudget::DEFAULT,
            )
            .unwrap();
            output
                .opening
                .decide(&params, MemoryBudget::DEFAULT)
                .unwrap();
            eprintln!(
                "AUTHENTICATED_SECONDARY_ACTUAL_PROOF bytes={} transport={} full_catalog=false lineage_rebound=false",
                proof.len(),
                proof.len() + 1088
            );
        }
    }
    let finalized = assigned
        .cs
        .finalize(assigned.tables.selectors(), true)
        .unwrap();
    let layout = CircuitDescriptorV1::from_constraint_system(
        &finalized,
        DescriptorConfig {
            curve: CurveV1::Pallas,
            k: 16,
            transcript: TranscriptV1::Blake2bChallenge255,
            instance_mode: InstanceModeV1::Direct,
            proof_suffix: ProofSuffixV1::FoldedGenerator,
        },
    )
    .unwrap();
    let descriptor = CircuitDescriptorV2::from_layout(
        layout,
        TranscriptV2::KagemushaPoseidonRp57Base,
        OmegaPlan::instance_types().to_vec(),
    )
    .unwrap();
    let protocol = Protocol::new(&descriptor).unwrap();
    eprintln!(
        "AUTHENTICATED_SOURCE_COMPACT_OMEGA sponge={sponge} arithmetic={arithmetic} curve={curve} shared_total={total} range={range} shape={:?} descriptor_transport={} actual_outer_proof=false actual_authenticated_terminal_A=true production_k16_fit={}",
        protocol.shape(),
        protocol.proof_length() + 1088,
        total <= protocol.shape().usable_rows && range <= protocol.shape().usable_rows
    );
    drop(assigned.tables);
    let packed = circuit
        .clone()
        .with_compact_layout(CompactSpans::new(sponge, sponge + arithmetic, total).unwrap());
    if total > protocol.shape().usable_rows || range > protocol.shape().usable_rows {
        assert!(synthesize(&packed, 16, Some(public)).is_err());
    }
    selected_layout
}

fn wrapper(
    bootstrap: &bootstrap_chain::AuthenticatedBootstrap,
) -> (OmegaCircuit, Vec<Vec<Fq>>, AccumulatorT<Eq>) {
    let params = PinnedParams::<Eq>::derive(16).unwrap();
    let trivial = AccumulatorT::trivial(&params, MemoryBudget::DEFAULT).unwrap();
    let (fold, output) = create_fold(
        &params,
        &[
            bootstrap.vesta_part.as_input(),
            bootstrap.opening.clone(),
            trivial.as_input(),
            trivial.as_input(),
        ],
        Fq::from(101).to_repr(),
        &FoldConfig::default(),
    )
    .unwrap();
    output.decide(&params, MemoryBudget::DEFAULT).unwrap();
    let (x, y) = output.g().coordinates().unwrap();
    let public = vec![
        vec![Fq::from_repr(bootstrap.instances[0].to_repr()).unwrap()],
        vec![x, y],
        output
            .challenges()
            .iter()
            .map(|v| Fq::from_repr(v.to_repr()).unwrap())
            .collect(),
    ];
    let digest = bootstrap.key.kagemusha_digest(&bootstrap.binding).unwrap();
    let plan = OmegaPlan::new(bootstrap.binding.clone(), params, vec![digest]).unwrap();
    let source_bytes = bootstrap.proof.len();
    let circuit = OmegaCircuit::new(
        plan,
        OmegaWitness {
            key: bootstrap.key.clone(),
            instances: bootstrap.instances.clone(),
            length: u32::try_from(source_bytes).unwrap(),
            proof: bootstrap.proof.clone(),
            fold: fold.to_bytes(),
        },
    )
    .unwrap();
    (circuit, public, output)
}

/// Genuine rooted Bootstrap outer artifact for following-operation tests.
/// The fixed catalog currently contains Bootstrap only; full catalog and byte
/// qualification remain open and changing that catalog requires rebinding.
#[allow(dead_code)]
pub struct RootedBootstrapOmega {
    pub(crate) source: bootstrap_chain::AuthenticatedBootstrap,
    pub(crate) key: iroha_plonk::VerifyingKey<Ep>,
    pub(crate) binding: iroha_plonk::DescriptorBinding,
    pub(crate) proof: Vec<u8>,
    pub(crate) instances: Vec<Vec<Fq>>,
    pub(crate) opening: iroha_plonk_recursion::FoldInput<Ep>,
    pub(crate) vesta: AccumulatorT<Eq>,
}

/// Rebuilds all authenticated witnesses against the actual immutable outer key.
pub(crate) fn rooted_bootstrap_omega(diagnostics: bool) -> RootedBootstrapOmega {
    rooted_bootstrap_omega_with_layout(diagnostics, 0)
}

/// Rooted component with an explicit common source profile. Shared-range
/// profiles disable Omega selector compression so catalog size cannot alter
/// the predecessor descriptor before the terminal keys are constructed.
pub(crate) fn rooted_bootstrap_omega_with_layout(
    diagnostics: bool,
    source_buses: usize,
) -> RootedBootstrapOmega {
    rooted_bootstrap_omega_with_q_layout(diagnostics, source_buses, None)
}

/// Explicit candidate Q/source profile, identically used before and after rebinding.
pub(crate) fn rooted_bootstrap_omega_with_q_layout(
    diagnostics: bool,
    source_buses: usize,
    q_buses: Option<usize>,
) -> RootedBootstrapOmega {
    rooted_bootstrap_omega_with_profile(
        diagnostics,
        bootstrap_chain::SourceProfile::ordinary(source_buses),
        q_buses,
    )
}

/// Named source profile, identically used before and after immutable-key rebinding.
pub(crate) fn rooted_bootstrap_omega_with_profile(
    diagnostics: bool,
    profile: bootstrap_chain::SourceProfile,
    q_buses: Option<usize>,
) -> RootedBootstrapOmega {
    rooted_bootstrap_omega_with_identity(
        diagnostics,
        profile,
        q_buses,
        bootstrap_chain::BootstrapIdentity::Payer,
    )
}

/// Root the same Bootstrap key with a separately enrolled receiver identity.
pub(crate) fn rooted_bootstrap_omega_with_identity(
    diagnostics: bool,
    profile: bootstrap_chain::SourceProfile,
    q_buses: Option<usize>,
    identity: bootstrap_chain::BootstrapIdentity,
) -> RootedBootstrapOmega {
    let first = bootstrap_chain::authenticated_bootstrap_with_identity(
        false,
        Fp::from(91),
        profile,
        q_buses,
        identity,
    );
    let (first_circuit, _, _) = wrapper(&first);
    let params = PinnedParams::<Ep>::derive(16).unwrap();
    let mut config = KeygenConfigV2::pipa_r(OmegaPlan::instance_types().to_vec());
    config.compress_selectors = profile == bootstrap_chain::SourceProfile::Generic;
    let first_key = keygen_pk_v2(&params, &first_circuit, &config).unwrap();
    let omega_digest = first_key
        .vk()
        .kagemusha_digest(first_key.binding())
        .unwrap();
    let first_binding = first_key.binding().clone();
    let first_vk = first_key.vk().clone();
    drop(first_key);
    // Rebuild every signed object and proof with the actual admitted Omega key
    // digest, then prove that neither A nor Omega key depends on that witness.
    let bootstrap = bootstrap_chain::authenticated_bootstrap_with_identity(
        false,
        omega_digest,
        profile,
        q_buses,
        identity,
    );
    assert_eq!(first.binding, bootstrap.binding);
    assert_eq!(
        first.key.kagemusha_digest(&first.binding).unwrap(),
        bootstrap.key.kagemusha_digest(&bootstrap.binding).unwrap()
    );
    eprintln!(
        "AUTHENTICATED_BOOTSTRAP_A_SOURCE shape={:?}",
        Protocol::new(bootstrap.binding.descriptor())
            .unwrap()
            .shape()
    );
    let source_bytes = bootstrap.proof.len();
    let (circuit, public, vesta) = wrapper(&bootstrap);
    if diagnostics {
        compact_diagnostic(&circuit, &public);
    }
    let assigned = synthesize(&circuit, 16, Some(&public)).unwrap();
    let report = check(&assigned.cs, &assigned.tables, CheckMode::Strict).unwrap();
    assert!(report.is_satisfied(), "{:?}", report.failures().first());
    let lanes: Vec<_> = assigned
        .tables
        .advice_assigned()
        .iter()
        .map(|column| column.iter().rposition(|v| *v).map_or(0, |r| r + 1))
        .collect();
    drop(assigned);
    let key = keygen_pk_v2(&params, &circuit, &config).unwrap();
    assert_eq!(key.binding(), &first_binding);
    assert_eq!(key.vk().to_bytes(), first_vk.to_bytes());
    let witness = Witness::from_circuit(&key, &circuit, &public).unwrap();
    let proof = create_proof_owned_with_claim(
        &params,
        &key,
        witness,
        ProverRandomness::os(),
        ProverConfig::default(),
    )
    .unwrap();
    let verified = accumulate_generator(
        &params,
        key.binding(),
        key.vk(),
        &public,
        &proof.proof,
        MemoryBudget::DEFAULT,
    )
    .unwrap();
    verified.decide(&params, MemoryBudget::DEFAULT).unwrap();
    eprintln!(
        "AUTHENTICATED_BOOTSTRAP_OMEGA source_A2_bytes={source_bytes} lanes={lanes:?} actual_proof_bytes={} transport_bytes={} source_operation_authenticated=true actual_omega_key_bound=true production_size_pass={} release_qualified=false",
        proof.proof.len(),
        proof.proof.len() + 1088,
        proof.proof.len() + 1088 <= 4821
    );
    RootedBootstrapOmega {
        source: bootstrap,
        key: key.vk().clone(),
        binding: key.binding().clone(),
        proof: proof.proof,
        instances: public,
        opening: iroha_plonk_recursion::FoldInput::from_opening(
            *verified.g(),
            verified.challenges(),
        )
        .unwrap(),
        vesta,
    }
}

fn serialized_foreign_inventory(range_buses: usize) {
    let bootstrap = bootstrap_chain::authenticated_bootstrap_with_layout(
        false,
        iroha_pasta::Fp::from(91),
        range_buses,
    );
    source_outer_inventory(&bootstrap, range_buses);
}

fn source_outer_inventory(bootstrap: &bootstrap_chain::AuthenticatedBootstrap, range_buses: usize) {
    let source = Protocol::new(bootstrap.binding.descriptor()).unwrap();
    eprintln!(
        "SERIALIZED_FF_BOOTSTRAP_A_SOURCE total_buses={range_buses} shape={:?} actual_proof_bytes={}",
        source.shape(),
        bootstrap.proof.len()
    );
    let (circuit, public, _) = wrapper(bootstrap);
    compact_diagnostic(&circuit, &public);
    let pinned = circuit
        .clone()
        .with_key_catalog(vec![bootstrap.key.clone()])
        .unwrap();
    eprintln!("AUTHENTICATED_BOOTSTRAP_PINNED_KEY_CATALOG entries=1 full_catalog=false");
    compact_diagnostic(&pinned, &public);
}
