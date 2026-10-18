//! D6b retention rules that need no proof: the key separates every durable input it names,
//! including the Send mask; the durable prefix is byte-exact; a foreign slot value is the cold
//! path; σ from fresh coins is never retained; and the retained state holds durable payload
//! identities, never a copy of a durable payload (Z1).
//! These are predicate-level checks. The genuine warm/cold chain checks run with the release
//! native exchange suites, whose fold helper asserts them on every turn and drives one changed
//! key through the genuine worker's same-call cold path.

use iroha_plonk_recursion::obligation::ledger::Variant;

use super::*;

fn key() -> RetentionKeyV1 {
    RetentionKeyV1 {
        installation: ([1; 32], [2; 32]),
        wallet: [3; 32],
        route: OperationRoute {
            variant: Variant::Receive,
            own: 6,
            incoming: Some(2),
        },
        sequence: 4,
        capsule: [5; 32],
        predecessor: [6; 32],
        sources: [[7; 32], [8; 32], [9; 32]],
        pending: [10; 32],
        credits: [11; 32],
    }
}

/// Deploy-pipeline §7.4 tests 4 and 11 and review T4 at the predicate: a changed route or
/// mask, predecessor, capsule, source record or preparation, root, installation or wallet
/// never resumes. The Send mask is checked alone, on a Send-route key whose only change is
/// the own selector.
#[test]
fn every_key_input_separates_retained_state() {
    let base = key();
    let durable = [[21; 32], [22; 32]];
    let mutations: [(&str, fn(&mut RetentionKeyV1)); 15] = [
        ("scheme", |k| k.installation.0[0] ^= 1),
        ("verifier manifest", |k| k.installation.1[0] ^= 1),
        ("wallet", |k| k.wallet[0] ^= 1),
        ("route variant", |k| {
            k.route.variant = Variant::ReceiveRenewed
        }),
        ("incoming selector", |k| k.route.incoming = Some(3)),
        ("no incoming slot", |k| k.route.incoming = None),
        ("sequence", |k| k.sequence += 1),
        ("capsule", |k| k.capsule[0] ^= 1),
        ("predecessor Ω", |k| k.predecessor[0] ^= 1),
        ("predecessor source record", |k| k.sources[0][0] ^= 1),
        ("successor source record", |k| k.sources[1][0] ^= 1),
        ("retained preparation", |k| k.sources[2][0] ^= 1),
        ("pending-map root", |k| k.pending[0] ^= 1),
        ("credit-tree root", |k| k.credits[0] ^= 1),
        ("another operation family", |k| {
            k.route = OperationRoute {
                variant: Variant::Send,
                own: 3,
                incoming: None,
            }
        }),
    ];
    assert!(resumable(&base, &durable[..1], &key(), &durable));
    for (label, mutate) in mutations {
        let mut changed = key();
        mutate(&mut changed);
        assert_ne!(changed, base, "{label}");
        assert!(
            !resumable(&changed, &durable[..1], &base, &durable),
            "{label}: the cold path"
        );
    }
    // The Send mask alone: Send routes select own σ key 2 + mask, with no incoming slot.
    let send = || RetentionKeyV1 {
        route: OperationRoute {
            variant: Variant::Send,
            own: 2,
            incoming: None,
        },
        ..key()
    };
    assert!(resumable(&send(), &durable[..1], &send(), &durable));
    for own in [3, 5] {
        let mut masked = send();
        masked.route.own = own;
        assert_ne!(masked, send(), "Send mask {own}");
        assert!(
            !resumable(&masked, &durable[..1], &send(), &durable),
            "Send mask {own}: the cold path"
        );
    }
}

/// Review G3/K4 and deploy-pipeline §7.4 test 3: retained restores resume only over a
/// byte-exact prefix of the durable list; one changed durable byte, a reorder or a shorter
/// list sends the sub-proof down the cold path, where the strict restore refuses the change.
#[test]
fn the_retained_prefix_must_be_byte_exact() {
    let payloads: Vec<PrivateArchiveBytes> = (0..3_u8)
        .map(|stage| PrivateArchiveBytes::copy_from(&[stage; 64]).unwrap())
        .collect();
    let durable: Vec<[u8; 32]> = payloads.iter().map(payload_digest).collect();
    let k = key();
    for held in 0..=durable.len() {
        assert!(resumable(&k, &durable[..held], &k, &durable), "{held}");
    }
    let mut changed = payloads[0].as_slice().to_vec();
    changed[63] ^= 1;
    let changed = PrivateArchiveBytes::copy_from(&changed).unwrap();
    let mut tampered = durable.clone();
    tampered[0] = payload_digest(&changed);
    for held in 1..=durable.len() {
        assert!(!resumable(&k, &durable[..held], &k, &tampered), "{held}");
    }
    assert!(
        resumable(&k, &[], &k, &tampered),
        "nothing retained, nothing to compare"
    );
    assert!(
        !resumable(&k, &durable, &k, &durable[..2]),
        "a longer retained list"
    );
    let reordered = [durable[1], durable[0], durable[2]];
    assert!(!resumable(&k, &durable[..2], &k, &reordered));
    assert_ne!(payload_digest(&payloads[0]), payload_digest(&payloads[1]));
}

/// Review K1: a slot value the native owner did not create is absent, never a panic.
#[test]
fn a_foreign_slot_value_is_the_cold_path() {
    assert!(
        FoldRetentionV1::new(7_u64)
            .downcast::<RetainedFoldV1>()
            .is_none()
    );
    assert!(
        FoldRetentionV1::new(key())
            .downcast::<RetainedFoldV1>()
            .is_none()
    );
}

/// Review G4/K6: a σ preparation is retained only from `NoIncoming` or from the private
/// fold of durable checkpoint 0, never from fresh coins.
#[test]
fn a_sigma_from_fresh_coins_is_never_retained() {
    assert!(q::sigma_in_restore_form(false, false), "no incoming slot");
    assert!(q::sigma_in_restore_form(false, true), "no incoming slot");
    assert!(
        q::sigma_in_restore_form(true, true),
        "the private fold of durable checkpoint 0"
    );
    assert!(!q::sigma_in_restore_form(true, false), "fresh coins");
}

/// Countersign Z1(4): exhaustive destructurings with explicit field types, of `RetainedFoldV1`
/// and the Q sources here and, one level down, of the Q chain (`q::q_state_fields`) and of
/// every family state (`stages::family_state_fields`), whose fields are private to those
/// modules. A new field at any of these levels, or a durable payload held as bytes instead of
/// its identity, fails to compile. The family sessions and checkpoints, the σ preparation, the
/// σ and signature witnesses, the owner credential and the fold fields are opaque types of
/// other modules: what they hold is stated below, not checked here.
///
/// Z1(1)–(3) as these types show them. A durable payload is held only as its identity (`held`).
/// Every other value keeps its in-call type and is moved, never cloned. The σ private fold and
/// the private folds of the restored Q originals stay in `PrivateFoldBytes`, which clears on its
/// last drop. The plain `Vec<u8>` that remain are freed but not cleared when the state is
/// dropped, and the retention copies none of them:
/// - the proof bytes the strict restores decoded into the restored Q originals
///   (`q_checkpoint::Original::proof`) and A/W checkpoints;
/// - the step's originals and Q proofs inside the family session's verified preparation;
/// - the σ proofs in the Q sources and in the σ preparation, which copies them in the call, as
///   the cold path does today.
///
/// `AuthenticatedCredentialV1`, `Fields` and `QSourcesV1` are plain in-call types, freed on
/// drop but not zeroized, with no new copy.
fn retained_fold_fields(retained: RetainedFoldV1) {
    let RetainedFoldV1 {
        key,
        held,
        public,
        stage,
    } = retained;
    let _: RetentionKeyV1 = key;
    let _: Vec<[u8; 32]> = held;
    let _: KagemushaWalletLineagePublicV1 = public;
    match stage {
        RetainedStageV1::Q(retained) => {
            let RetainedQV1 {
                owner,
                fields,
                q_sources,
                q,
            } = *retained;
            let _: AuthenticatedCredentialV1 = owner;
            let _: Fields = fields;
            let q::QSourcesV1 {
                own,
                incoming,
                signatures,
            } = q_sources;
            let _: Option<iroha_kagemusha_proof::q_sigma::SigmaSlotWitness> = own;
            let _: Option<iroha_kagemusha_proof::q_sigma::native::IncomingSigma> = incoming;
            let _: Vec<Vec<iroha_kagemusha_proof::q_signature::SignatureWitness>> = signatures;
            let q: Option<Box<q::QStateV1>> = q;
            if let Some(state) = q {
                q::q_state_fields(*state);
            }
        }
        RetainedStageV1::Chain(chain) => {
            let RetainedChainV1 {
                public_fields,
                family,
            } = *chain;
            let _: [Fp; 18] = public_fields;
            stages::family_state_fields(family);
        }
    }
}

#[test]
fn retained_state_holds_payload_identities_never_a_payload_copy() {
    // The scheduler slot owns it across threads and fold calls.
    fn owned<T: Send + 'static>() {}
    owned::<RetainedFoldV1>();
    let _: fn(RetainedFoldV1) = retained_fold_fields;
}

/// The release suites' key perturbation changes only a retained fold state; any other slot
/// value is declined unchanged.
#[test]
fn the_key_perturbation_declines_a_foreign_value() {
    let mut value = FoldRetentionV1::new(7_u64);
    assert!(!perturb_retained_key_for_test(&mut value));
    assert_eq!(value.downcast::<u64>(), Some(7));
}

/// Review G1: the retained state and its slot value are move-only, so a retained session
/// resumes at most once. Resolves only when neither type implements `Clone`.
#[test]
fn retained_fold_state_is_move_only() {
    trait AmbiguousIfClone<A> {
        fn check() {}
    }
    impl<T: ?Sized> AmbiguousIfClone<()> for T {}
    #[allow(dead_code)]
    struct IsClone;
    impl<T: ?Sized + Clone> AmbiguousIfClone<IsClone> for T {}
    let _ = <RetainedFoldV1 as AmbiguousIfClone<_>>::check;
    let _ = <FoldRetentionV1 as AmbiguousIfClone<_>>::check;
}
