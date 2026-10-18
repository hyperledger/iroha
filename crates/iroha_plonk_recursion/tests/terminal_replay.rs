//! Retained terminal-fold replay against genuine proofs of one fixed public frame.
//!
//! This isolates the closed native terminal owner: the two k16 A-frame proofs are
//! genuine PIPA-R proofs, but their relation only fixes 69 public words. They are
//! not operation A proofs, an installed catalog, an Omega proof or C12 qualification.

use ff::{Field, PrimeField};
use iroha_pasta::{CancellationToken, Eq, Fp, msm::MemoryBudget};
use iroha_plonk::{
    ProverConfig, ProverRandomness, VerificationCounts, Witness, create_proof_owned_with_claim,
    cs::{Column, ConstraintSystem, Instance, InstanceType},
    frontend::{Circuit, Error, Layouter, SimpleFloorPlanner},
    keys::{KeygenConfigV2, keygen_pk_v2},
    pcs::ipa::PinnedParams,
    verifier::{accumulate_frame_cancellable, verify_full_opening_cancellable},
};
use iroha_plonk_gadgets::{GlueChip, GlueConfig, statement::foreign_limbs};
use iroha_plonk_recursion::{
    AccumulatorT, FoldConfig, FoldInput, FoldTape, FoldWitness,
    terminal::{Error as TerminalError, TerminalPlan},
};

/// Fixed-frame isolation, matching the existing Omega component fixture's relation.
#[derive(Clone)]
struct Frame(Vec<Fp>);

impl Circuit<Fp> for Frame {
    type Config = (GlueConfig, Column<Instance>);
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();

    fn without_witnesses(&self) -> Self {
        self.clone()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let columns = core::array::from_fn(|_| meta.advice_column());
        let constants = meta.fixed_column();
        let glue = GlueConfig::configure(meta, columns, constants);
        let public = meta.instance_column(69);
        meta.enable_equality(public);
        (glue, public)
    }

    fn synthesize(
        &self,
        (config, public): Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let mut glue = GlueChip::new(config);
        let words = layouter.assign_region(
            || "fixed terminal frame isolation",
            |mut region| {
                self.0
                    .iter()
                    .map(|value| glue.constant(&mut region, *value))
                    .collect::<Result<Vec<_>, _>>()
            },
        )?;
        for (row, word) in words.into_iter().enumerate() {
            layouter.constrain_instance(word.cell(), public, row)?;
        }
        Ok(())
    }
}

fn coordinates(claim: &FoldInput<Eq>) -> Vec<Fp> {
    let (x, y) = iroha_plonk::transcript::generator_coordinates::<Eq>(claim.g());
    foreign_limbs(&x)
        .into_iter()
        .chain(foreign_limbs(&y))
        .map(Fp::from_u128)
        .collect()
}

fn frame(trivial: &FoldInput<Eq>) -> Vec<Fp> {
    let mut words = vec![Fp::from(17), Fp::from(16)];
    // Part, predecessor and incoming are independently named, deciding slots.
    // Equal bytes do not collapse these obligations. Slot one is the A opening.
    for _ in 0..3 {
        words.extend(coordinates(trivial));
        words.extend(trivial.challenges());
    }
    words.extend([Fp::ZERO, Fp::ONE, Fp::ZERO]);
    words.extend(coordinates(trivial));
    assert_eq!(words.len(), 69);
    words
}

fn public_fixture_tape() -> FoldTape<Eq> {
    // Public deterministic algebraic DATA; never producer entropy.
    let mut coin = 19_u64;
    FoldTape::try_fill::<core::convert::Infallible>(|destination| {
        *destination = Fp::from(coin);
        coin += 1;
        Ok(())
    })
    .unwrap()
}

#[test]
#[ignore = "two genuine k16 PIPA-R proofs and one native fold; run with --release --ignored"]
fn retained_terminal_fold_replays_only_with_its_exact_valid_source() {
    let params = PinnedParams::<Eq>::derive(16).unwrap();
    let budget = MemoryBudget::DEFAULT;
    let config = FoldConfig::default();
    let trivial = AccumulatorT::trivial(&params, budget).unwrap();
    trivial.decide(&params, budget).unwrap();
    let values = frame(&trivial.as_input());
    let public = [values.clone()];
    let circuit = Frame(values);
    let mut key_config = KeygenConfigV2::pipa_r(vec![InstanceType::Bounded]);
    key_config.compress_selectors = false;
    let key = keygen_pk_v2(&params, &circuit, &key_config).unwrap();
    let descriptor_original = key.binding().encoded().to_vec();
    let key_original = key.vk().to_bytes().to_vec();
    let public_original = public.clone();
    let proofs: [_; 2] = core::array::from_fn(|_| {
        let witness = Witness::from_circuit(&key, &circuit, &public).unwrap();
        create_proof_owned_with_claim(
            &params,
            &key,
            witness,
            ProverRandomness::os(),
            ProverConfig::default(),
        )
        .unwrap()
    });
    assert_ne!(proofs[0].proof, proofs[1].proof, "fresh proof originals");
    let proof_originals = [proofs[0].proof.clone(), proofs[1].proof.clone()];
    let before = VerificationCounts::current_thread();
    for proof in &proofs {
        // Genuine full acceptance precedes every splice assertion; a malformed
        // second proof or an undecided succinct parse cannot make this test pass.
        let opening = verify_full_opening_cancellable(
            &params,
            key.binding(),
            key.vk(),
            &public,
            &proof.proof,
            budget,
            None,
        )
        .unwrap();
        assert_eq!(opening.g(), proof.opening.g());
        assert_eq!(opening.challenges(), proof.opening.challenges());
    }
    let verified = VerificationCounts::current_thread().since(before);
    assert_eq!(verified.verify_full, 2);
    assert_eq!(verified.reused_verifications, 0);
    let parsed: [_; 2] = core::array::from_fn(|index| {
        accumulate_frame_cancellable(
            &params,
            key.binding(),
            key.vk(),
            &public,
            &proofs[index].proof,
            budget,
            None,
        )
        .unwrap()
    });
    assert_eq!(parsed[0].instances(), parsed[1].instances());
    assert_eq!(parsed[0].binding(), parsed[1].binding());
    assert_ne!(parsed[0].first_raw(), parsed[1].first_raw());
    assert_ne!(
        parsed[0].own_claim().challenges(),
        parsed[1].own_claim().challenges(),
        "same frame/key still has distinct proof-owned openings"
    );
    let plan = TerminalPlan::new(
        &descriptor_original,
        std::slice::from_ref(&key_original),
        params.clone(),
    )
    .unwrap();
    let (fold, output) = plan
        .read(0, &public, &proofs[0].proof, &config)
        .unwrap()
        .create(public_fixture_tape(), &config)
        .unwrap();
    output.decide(&params, budget).unwrap();
    let retained = fold.to_private_bytes();
    let restored = FoldWitness::<Eq>::from_private_bytes(&retained).unwrap();
    assert_eq!(&*restored.to_private_bytes(), &*retained);

    // Reparse the exact original and restore its canonical private bytes. No
    // fresh tape is supplied to either replay API.
    let original_frame = plan.read(0, &public, &proofs[0].proof, &config).unwrap();
    let replay = original_frame.verify(&restored, &config).unwrap();
    assert_eq!(replay, output);
    replay.decide(&params, budget).unwrap();
    let other_frame = plan.read(0, &public, &proofs[1].proof, &config).unwrap();
    assert!(matches!(
        other_frame.verify(&restored, &config),
        Err(TerminalError::Fold(
            iroha_plonk_recursion::Error::FoldEquation
        ))
    ));
    // The failed splice must not poison subsequent exact replay.
    assert_eq!(original_frame.verify(&restored, &config).unwrap(), output);

    let cancellation = CancellationToken::new();
    cancellation.cancel();
    let cancelled = FoldConfig {
        cancellation: Some(cancellation),
        ..config.clone()
    };
    let error = plan
        .read(0, &public, &proofs[0].proof, &cancelled)
        .unwrap_err();
    assert!(error.is_cancelled(), "cancelled parse has no proof verdict");
    let error = original_frame.verify(&restored, &cancelled).unwrap_err();
    assert!(error.is_cancelled(), "cancelled replay has no fold verdict");
    let final_reparse = plan.read(0, &public, &proofs[0].proof, &config).unwrap();
    let final_replay = final_reparse.verify(&restored, &config).unwrap();
    assert_eq!(final_replay, output);
    final_replay.decide(&params, budget).unwrap();
    assert!(matches!(
        other_frame.verify(&restored, &config),
        Err(TerminalError::Fold(
            iroha_plonk_recursion::Error::FoldEquation
        ))
    ));

    assert_eq!(&*fold.to_private_bytes(), &*retained);
    assert_eq!(&*restored.to_private_bytes(), &*retained);
    assert_eq!(proofs[0].proof, proof_originals[0]);
    assert_eq!(proofs[1].proof, proof_originals[1]);
    assert_eq!(public, public_original);
    assert_eq!(key.binding().encoded(), descriptor_original);
    assert_eq!(key.vk().to_bytes(), key_original);
    println!(
        "TERMINAL_REPLAY full_verified_A_frames=2 reused_full_verdicts=0 same_key=true same_public_frame=true exact_fold_restore=true cross_proof_refusals=2 cancellation_refusals=2 exact_replay_after_refusal=true operation_relation=false production_catalog=false outer_Omega_proof=false"
    );
}
