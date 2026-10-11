//! Genuine monetary Load inputs following direct native receipt authentication.
//! The exact receipt is never relabeled; Load binds its terms and signed Advance.

use super::{bootstrap, bootstrap_objects, common, load_chain, load_objects};
use ff::{Field, PrimeField};
use iroha_kagemusha_proof::{
    a_relation::{
        AProofPlan, QProofPlan,
        native::load::{A_STAGE_COUNT, Inputs, Plan, PredecessorInput, QInput},
        schedule::sigma_selector,
        split::WKey,
    },
    admin_sigma::{LoadCircuit, LoadWitness, StateWitness},
    operation_relation::map_effects::LOAD_DOMAIN,
    q_sigma::{QSigmaPlan, SigmaClass, SigmaSlotWitness, native::QSigmaProver},
    q_signature::QSignaturePlan,
    tree::{IndexedInsert, IndexedTree},
    witness::core_index as core,
};
use iroha_pasta::{Ep, Eq, Fp, Fq, msm::MemoryBudget, poseidon::hash_with_domain};
use iroha_plonk::{
    ProverConfig, Witness, create_proof_owned_with_claim,
    cs::InstanceType,
    keys::{CosetCachePolicy, KeygenConfigV2, keygen_pk_v2, pk::artifact::ReadConfig},
    pcs::ipa::PinnedParams,
};
use iroha_plonk_recursion::{FoldConfig, obligation::ledger::Variant, verifier::VerifierPlan};
use std::{fs, path::Path};

fn monetary(
    before: &iroha_kagemusha_proof::admin_sigma::BootstrapWitness,
    receipt: &[u8; 282],
) -> (LoadWitness, IndexedInsert<Fp>) {
    assert_eq!(&receipt[..2], &1_u16.to_le_bytes());
    for (offset, field) in [(2, core::SCHEME), (34, core::ASSET), (66, core::WALLET)] {
        assert_eq!(
            &receipt[offset..offset + 32],
            bootstrap_objects::id(before.core[field], before.core[field + 1])
        );
    }
    let word = |offset| {
        Fp::from_u128(u128::from_le_bytes(
            receipt[offset..offset + 16].try_into().unwrap(),
        ))
    };
    let ordinal = word(130);
    let amount = word(146);
    let charge = word(162);
    assert_eq!(ordinal, before.core[core::NEXT_LOAD]);
    let receipt = load_objects::OrdinaryReceipt { bytes: *receipt };
    let mut after = *before;
    after.core[core::BALANCE] += amount;
    after.core[core::NEXT_LOAD] += Fp::ONE;
    after.core[core::SEQUENCE] += Fp::ONE;
    after.core[core::STATE_NONCE] += Fp::ONE;
    let mut tree = IndexedTree::new();
    assert_eq!(tree.root(), before.core[core::LOAD_REDEEM_ROOT]);
    let insertion = tree
        .insert(
            Fp::from(2).pow_vartime([128]) + ordinal,
            hash_with_domain(LOAD_DOMAIN, &[ordinal, receipt.digest(), amount]),
        )
        .unwrap();
    after.core[core::LOAD_REDEEM_ROOT] = tree.root();
    bootstrap::rebind(&mut after);
    let mut statement = after.statement;
    statement[14] = before.lineage[5];
    statement[16] = Fp::from(2);
    statement[17..].fill(Fp::ZERO);
    statement[17..21].copy_from_slice(&[receipt.digest(), ordinal, amount, charge]);
    (
        LoadWitness {
            predecessor: StateWitness::from(before),
            successor: StateWitness::from(&after),
            statement,
        },
        insertion,
    )
}

/// Build from a real rooted predecessor and a natively authenticated receipt.
/// The monetary relation verifies receipt binding, authorization and the state transition.
pub fn build(
    rooted: &load_chain::bootstrap_outer::RootedBootstrapOmega,
    receipt: &[u8; 282],
    directory: &Path,
) -> load_chain::InstalledLoad {
    match fs::symlink_metadata(directory) {
        Ok(metadata) => assert!(metadata.file_type().is_dir()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(directory).unwrap()
        }
        Err(error) => panic!("unavailable Load original directory: {error}"),
    }
    let (state, insertion) = monetary(&rooted.source.state, receipt);
    let pallas = PinnedParams::<Ep>::derive(16).unwrap();
    let vesta = PinnedParams::<Eq>::derive(16).unwrap();
    let sigma_params = PinnedParams::<Eq>::derive(12).unwrap();
    let sigma = LoadCircuit::new(&state);
    let sigma_instances = sigma.instances();
    let sigma_key = keygen_pk_v2(
        &sigma_params,
        &sigma,
        &KeygenConfigV2::pipa_r(LoadCircuit::instance_types().to_vec()),
    )
    .unwrap();
    let sigma_proof = create_proof_owned_with_claim(
        &sigma_params,
        &sigma_key,
        Witness::from_circuit(&sigma_key, &sigma, &sigma_instances).unwrap(),
        common::recovery(191),
        ProverConfig::default(),
    )
    .unwrap();
    let sigma_plan = QSigmaPlan::new(
        SigmaClass::new(
            VerifierPlan::new(sigma_key.binding().clone(), sigma_params).unwrap(),
            vec![(
                sigma_selector(2, 0).unwrap(),
                sigma_key
                    .vk()
                    .kagemusha_digest(sigma_key.binding())
                    .unwrap(),
            )],
        )
        .unwrap(),
        None,
        &vesta,
    )
    .unwrap();
    let prepared = sigma_plan
        .prepare(
            SigmaSlotWitness {
                key: sigma_key.vk().clone(),
                statement: sigma_instances[0][0],
                length: u32::try_from(sigma_proof.proof.len()).unwrap(),
                proof: sigma_proof.proof.clone(),
            },
            None,
            &vesta,
            Fq::from(193),
            &FoldConfig::default(),
        )
        .unwrap();
    drop(sigma_key);
    let q_sigma = QSigmaProver::keygen_serialized_foreign(&prepared, pallas.clone(), 2).unwrap();
    let sigma_q_proof = q_sigma
        .prove(&prepared, common::recovery(194), ProverConfig::default())
        .unwrap();
    let mut q_plans = vec![
        QProofPlan::new(
            VerifierPlan::new(q_sigma.binding().clone(), pallas.clone()).unwrap(),
            q_sigma.verifying_key().clone(),
        )
        .unwrap(),
    ];
    let mut q_inputs = vec![QInput {
        proof: sigma_q_proof.bytes,
        instances: sigma_q_proof.instances,
    }];
    drop(q_sigma);
    let mut signed_state = bootstrap_objects::enrollment();
    signed_state.0.lineage[17] = rooted.source.state.lineage[17];
    assert_eq!(signed_state.0.core, rooted.source.state.core);
    assert_eq!(signed_state.0.rest, rooted.source.state.rest);
    assert_eq!(signed_state.0.lineage, rooted.source.state.lineage);
    let (_, certificate, credential) = signed_state;
    let own = load_objects::receipt(&state, &sigma_proof.proof);
    let signatures = [
        load_objects::own_signature(own.signature),
        load_objects::current_signatures(&[credential.signature, certificate.signature]),
    ];
    let signature_plans: [QSignaturePlan; 2] =
        std::array::from_fn(|i| signatures[i].0.plan().clone());
    for (index, (circuit, instances)) in signatures.iter().enumerate() {
        let key = keygen_pk_v2(
            &pallas,
            circuit,
            &KeygenConfigV2::pipa_r(QSignaturePlan::instance_types().to_vec()),
        )
        .unwrap();
        let proof = create_proof_owned_with_claim(
            &pallas,
            &key,
            Witness::from_circuit(&key, circuit, instances).unwrap(),
            common::recovery(u8::try_from(195 + index).unwrap()),
            ProverConfig::default(),
        )
        .unwrap();
        q_plans.push(
            QProofPlan::new(
                VerifierPlan::new(key.binding().clone(), pallas.clone()).unwrap(),
                key.vk().clone(),
            )
            .unwrap(),
        );
        q_inputs.push(QInput {
            proof: proof.proof,
            instances: instances.to_vec(),
        });
    }
    let operation = AProofPlan::new(
        Variant::Load,
        sigma_plan,
        q_plans,
        Some(VerifierPlan::new(rooted.binding.clone(), pallas.clone()).unwrap()),
        &pallas,
    )
    .unwrap();
    let plan = Plan::new(
        operation,
        load_objects::policy(),
        signature_plans,
        rooted.key.clone(),
        pallas.clone(),
        vesta.clone(),
    )
    .unwrap();
    let inputs = Inputs {
        state,
        sigma: sigma_proof.proof,
        receipt: *receipt,
        objects: [own.bytes, certificate.bytes, credential.bytes],
        insertion,
        q: q_inputs.try_into().unwrap(),
        predecessor: PredecessorInput {
            proof: rooted.proof.clone(),
            pallas: rooted.source.pallas.to_bytes(),
            vesta: rooted.vesta.to_bytes(),
        },
    };
    let _prepared = plan.prepare(inputs.clone(), MemoryBudget::DEFAULT).unwrap();
    let mut a = Vec::new();
    let mut w = Vec::new();
    let mut previous = None;
    let mut config = KeygenConfigV2::pipa_r(vec![InstanceType::Bounded]);
    config.compress_selectors = false;
    for stage in 0..A_STAGE_COUNT {
        let source = plan.source_circuit(stage, previous.take()).unwrap();
        let key = keygen_pk_v2(&vesta, &source, &config).unwrap();
        let binding = key.binding().clone();
        let vk = key.vk().clone();
        a.push(load_chain::Original::persist(
            &directory.join(format!("a{stage}.pk")),
            binding.encoded().to_vec(),
            vk.to_bytes().to_vec(),
            key.artifact_bytes_v2().unwrap(),
        ));
        drop(key);
        if stage + 1 < A_STAGE_COUNT {
            let source = plan.wrapper_source(stage, &binding, &vk).unwrap();
            let (fixed, key) = WKey::keygen(&source, &pallas).unwrap();
            w.push(load_chain::Original::persist(
                &directory.join(format!("w{stage}.pk")),
                key.binding().encoded().to_vec(),
                key.vk().to_bytes().to_vec(),
                key.artifact_bytes_v2().unwrap(),
            ));
            drop(key);
            previous = Some(fixed);
        }
        eprintln!(
            "ORDINARY_LOAD_ARTIFACT stage={} complete4A3W=false",
            stage + 1
        );
    }
    load_chain::InstalledLoad {
        plan,
        a: a.try_into().ok().unwrap(),
        w: w.try_into().ok().unwrap(),
        inputs,
        read: ReadConfig {
            maximum_bytes: 256 << 20,
            maximum_rows: 1 << 16,
            coset_cache: CosetCachePolicy::OnDemand,
            msm_budget: MemoryBudget::DEFAULT,
        },
    }
}

/// Check exact first-Load identities/terms and the actual local sigma constraints.
pub fn check_first_capture(capture: &str) {
    let json: norito::json::Value = norito::json::from_str(capture).unwrap();
    let text = json
        .get("receipt_transcript_hex")
        .unwrap()
        .as_str()
        .unwrap();
    assert_eq!(text.len(), 564);
    let receipt: [u8; 282] = (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    let (before, _, _) = bootstrap_objects::enrollment();
    let (state, insertion) = monetary(&before, &receipt);
    assert_eq!(state.statement[18..21], [Fp::ZERO, Fp::from(100), Fp::ZERO]);
    assert_eq!(state.successor.core[core::BALANCE], Fp::from(100));
    assert!(insertion.slot > 0);
    let circuit = LoadCircuit::new(&state);
    let report = iroha_plonk::check::check_circuit(
        &circuit,
        12,
        &circuit.instances(),
        iroha_plonk::check::CheckMode::Strict,
    )
    .unwrap();
    assert!(report.is_satisfied());
    for offset in [2, 34, 66, 130] {
        let mut changed = receipt;
        changed[offset] ^= 1;
        assert!(std::panic::catch_unwind(|| monetary(&before, &changed)).is_err());
    }
}
