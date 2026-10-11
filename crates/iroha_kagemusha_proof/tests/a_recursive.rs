//! Recursive obligation ownership, with genuine Bootstrap state and signed-object
//! composition through sigma, Q, A1, W and A2. Send tests still isolate its frame.

#[path = "common/bootstrap.rs"]
mod bootstrap;
#[path = "common/bootstrap_objects.rs"]
#[allow(dead_code)] // Shared payer/receiver helpers are consumed by distinct test binaries.
mod bootstrap_objects;
mod common;
#[path = "common/native_source_factory_checks.rs"]
mod native_source_factory_checks;
use iroha_kagemusha_proof::a_relation::AFramePlan;

include!("common/proof_fixtures/a_recursive_body.rs");

#[test]
#[ignore = "actual k16 Q proof composed into A; run optimized with --include-ignored"]
fn bootstrap_frame_hard_verifies_real_q_and_keeps_its_opening() {
    let Fixture {
        circuit, values, ..
    } = fixture();
    assert_eq!(values[0].len(), AFramePlan::instance_length());
    let honest = check_circuit(&circuit, 16, &values, CheckMode::Strict).unwrap_or_else(|error| {
        let diagnostic = synthesize(&circuit, 17, Some(&values)).expect("diagnostic layout");
        let rows = diagnostic
            .tables
            .advice_assigned()
            .iter()
            .map(|column| column.iter().rposition(|v| *v).map_or(0, |r| r + 1))
            .collect::<Vec<_>>();
        let report =
            iroha_plonk::check::check(&diagnostic.cs, &diagnostic.tables, CheckMode::Strict)
                .unwrap();
        panic!(
            "k16 capacity failure {error:?}; diagnostic k17 rows={rows:?} predicate_pass={}",
            report.is_satisfied()
        );
    });
    assert!(
        honest.is_satisfied(),
        "{:?}",
        &honest.failures()[..honest.failures().len().min(8)]
    );
    let known = synthesize(&circuit, 16, Some(&values)).unwrap();
    let unknown = synthesize(&circuit.without_witnesses(), 16, None).unwrap();
    assert_eq!(known.tables.fixed(), unknown.tables.fixed());
    assert_eq!(
        known.tables.advice_assigned(),
        unknown.tables.advice_assigned()
    );
    let rows = known
        .tables
        .advice_assigned()
        .iter()
        .filter_map(|column| column.iter().rposition(|v| *v).map(|r| r + 1))
        .max()
        .unwrap();
    let lanes = known
        .tables
        .advice_assigned()
        .iter()
        .map(|c| c.iter().rposition(|v| *v).map_or(0, |r| r + 1))
        .collect::<Vec<_>>();
    println!("A actualQ Bootstrap frame rows={rows} lanes={lanes:?}");
    for route in [1, 2] {
        let mut bad = circuit.clone();
        bad.route = route;
        assert!(!satisfied(&bad, &values));
    }
    let mut bad = circuit.clone();
    bad.q_length -= 1;
    assert!(!satisfied(&bad, &values));
    let mut bad = circuit.clone();
    bad.q[100] ^= 1;
    assert!(!satisfied(&bad, &values));
    let mut bad = circuit.clone();
    bad.sigma[100] ^= 1;
    assert!(!satisfied(&bad, &values));
    let mut bad = circuit;
    bad.statement[3] += Fp::ONE;
    assert!(!satisfied(&bad, &values));
}

#[test]
#[ignore = "actual predecessor and Q proofs with hard Pallas fold; run optimized"]
fn send_frame_binds_predecessor_key_and_both_generator_obligations() {
    let mut base = fixture();
    let trivial = AccumulatorT::trivial(&base.params, MemoryBudget::DEFAULT)
        .unwrap()
        .as_input();
    let vparams = common::vesta_params(16);
    let vtrivial = AccumulatorT::trivial(&vparams, MemoryBudget::DEFAULT).unwrap();
    let (x, y) = vtrivial.g().coordinates().unwrap();
    let mut predecessor = OmegaFrame {
        instances: vec![vec![Fq::ZERO], vec![x, y], vec![Fq::ONE; 16]],
        known: true,
    };
    let config = KeygenConfigV2::pipa_r(vec![
        InstanceType::Bounded,
        InstanceType::Field,
        InstanceType::Bounded,
    ]);
    let key = keygen_pk_v2(&base.params, &predecessor, &config).unwrap();
    let key_digest = key.vk().kagemusha_digest(key.binding()).unwrap();
    base.circuit.fields[17] = key_digest;
    let mut fields = base.circuit.fields;
    fields[5] += Fp::ONE;
    predecessor.instances[0][0] = Fq::from_repr(digest(&fields, &trivial).to_repr()).unwrap();
    let witness = Witness::from_circuit(&key, &predecessor, &predecessor.instances).unwrap();
    let proof = create_proof_owned_with_claim(
        &base.params,
        &key,
        witness,
        common::recovery(73),
        ProverConfig::default(),
    )
    .unwrap();
    let opening = FoldInput::from_opening(*proof.opening.g(), proof.opening.challenges()).unwrap();
    let inputs = [trivial.clone(), opening, base.q_opening];
    let (fold, output) = create_fold(
        &base.params,
        &inputs,
        Fp::from(29).to_repr(),
        &FoldConfig::default(),
    )
    .unwrap();
    output.decide(&base.params, MemoryBudget::DEFAULT).unwrap();
    let omega = VerifierPlan::new(key.binding().clone(), base.params.clone()).unwrap();
    base.circuit.plan = AProofPlan::new(
        Variant::Send,
        base.sigma_plan,
        vec![base.q_plan],
        Some(omega),
        &base.params,
    )
    .unwrap();
    base.circuit.predecessor = Some(Predecessor {
        key: key.vk().clone(),
        fields,
        pallas: trivial,
        proof: proof.proof.clone(),
        length: u32::try_from(proof.proof.len()).unwrap(),
        fold: fold.to_bytes().to_vec(),
        fold_length: 1120,
    });
    let values = [public(&base.circuit.fields, &output.as_input(), &base.part)];
    let honest =
        check_circuit(&base.circuit, 16, &values, CheckMode::Strict).unwrap_or_else(|error| {
            let diagnostic =
                synthesize(&base.circuit, 18, Some(&values)).expect("diagnostic Send layout");
            let lanes = diagnostic
                .tables
                .advice_assigned()
                .iter()
                .map(|c| c.iter().rposition(|v| *v).map_or(0, |r| r + 1))
                .collect::<Vec<_>>();
            let report =
                iroha_plonk::check::check(&diagnostic.cs, &diagnostic.tables, CheckMode::Strict)
                    .unwrap();
            panic!(
                "Send k16 capacity failure {error:?}; diagnostic lanes={lanes:?} predicate_pass={}",
                report.is_satisfied()
            );
        });
    assert!(
        honest.is_satisfied(),
        "{:?}",
        &honest.failures()[..honest.failures().len().min(8)]
    );
    for mutation in 0..6 {
        let mut bad = base.circuit.clone();
        match mutation {
            0 => bad.predecessor = None,
            1 => bad.fields[17] += Fp::ONE,
            2 => bad.predecessor.as_mut().unwrap().fields[17] += Fp::ONE,
            3 => bad.predecessor.as_mut().unwrap().proof[100] ^= 1,
            4 => bad.predecessor.as_mut().unwrap().fold[100] ^= 1,
            _ => bad.predecessor.as_mut().unwrap().length -= 1,
        }
        assert!(!satisfied(&bad, &values), "mutation {mutation}");
    }
}

#[test]
#[ignore = "context schema over actual Q metadata; run optimized"]
fn split_context_rebinds_state_statement_all_q_fields_and_original_tape() {
    let circuit = context_fixture(fixture());
    let values = [vec![circuit.digest()]];
    let report = check_circuit(&circuit, 16, &values, CheckMode::Strict).unwrap();
    assert!(
        report.is_satisfied(),
        "{:?}",
        &report.failures()[..report.failures().len().min(5)]
    );
    let known = synthesize(&circuit, 16, Some(&values)).unwrap();
    let unknown = synthesize(&circuit.without_witnesses(), 16, None).unwrap();
    assert_eq!(known.tables.fixed(), unknown.tables.fixed());
    assert_eq!(
        known.tables.advice_assigned(),
        unknown.tables.advice_assigned()
    );
    for kind in 0..9 {
        let mut bad = circuit.clone();
        match kind {
            0 => bad.statement[17] += Fp::ONE,
            1 => bad.core[8] += Fp::ONE,
            2 => bad.rest[7] += Fp::ONE,
            3 => bad.public[17] += Fp::ONE,
            4 => bad.q[0][0][0] += Fq::ONE,
            5 => bad.object[0] ^= 1,
            6 => bad.object[35] ^= 1,
            7 => bad.object_digest += Fp::ONE,
            _ => bad.wrong_order = true,
        }
        assert!(
            !check_circuit(&bad, 16, &values, CheckMode::Strict).is_ok_and(|r| r.is_satisfied()),
            "context group {kind}"
        );
    }
    let mut different_domain = values.clone();
    different_domain[0][0] = hash_with_domain(LINEAGE_DOMAIN, &[circuit.digest()]);
    assert!(
        !check_circuit(&circuit, 16, &different_domain, CheckMode::Strict)
            .unwrap()
            .is_satisfied()
    );
}

#[test]
#[ignore = "actual Bootstrap sigma/Q, A1/W/A2 and authenticated 2V1F objects; run optimized"]
fn actual_split_chain_retains_context_wrapper_and_final_claims() {
    let _ = authenticated_bootstrap(true);
}

#[test]
#[ignore = "two actual scheme-distinct Bootstrap chains plus signed foreign-scheme rejection"]
fn bootstrap_keys_are_scheme_independent_and_signed_foreign_scope_rejects() {
    let run = |scheme, certificate_scheme| {
        authenticated_bootstrap_for_schemes(
            false,
            Fp::from(91),
            SourceProfile::Tagged {
                buses: iroha_kagemusha_proof::a_relation::native::bootstrap::SOURCE_RANGE_BUSES,
            },
            None,
            BootstrapIdentity::Payer,
            scheme,
            certificate_scheme,
        )
    };
    let first = run([1, 2], [1, 2]).unwrap();
    let second = run([101, 102], [101, 102]).unwrap();
    assert_ne!(first.state.core[1..3], second.state.core[1..3]);
    assert_ne!(first.state.lineage[5], second.state.lineage[5]);
    assert_eq!(first.binding, second.binding);
    assert_eq!(
        first.source_keys, second.source_keys,
        "carried SchemeID must not change sigma/Q/A/W original keys"
    );
    assert!(run([1, 2], [101, 102]).is_none());
    eprintln!(
        "BOOTSTRAP_SCHEME_KEYS actual_chains=2 exact_source_keys=6 foreign_signed_scope_rejected=true full_catalog=false"
    );
}

#[test]
#[ignore = "genuine common-Q2/Tagged3 production A1/W/A2, source mutation and artifact differential"]
fn production_native_bootstrap_stages_preserve_the_genuine_installed_relation() {
    let _ = authenticated_bootstrap_with_profile(
        true,
        Fp::from(91),
        SourceProfile::Tagged {
            buses: iroha_kagemusha_proof::a_relation::native::bootstrap::SOURCE_RANGE_BUSES,
        },
        Some(2),
    );
}
