//! Prover-instance binding for retained native sessions (DP §7.4 test 8).
//!
//! These checks use plain values. The genuine per-family resume checks run in
//! the optimized installed-producer suites with real sessions.

use super::*;

#[test]
fn bound_state_resumes_only_on_the_instance_that_bound_it() {
    let owner = ProverInstanceV1::fresh();
    let other = ProverInstanceV1::fresh();
    let refused = other.admit(owner.bind(vec![7_u8, 8, 9]));
    let bound = match refused {
        Ok(_) => panic!("another prover instance admitted retained state"),
        Err(bound) => bound,
    };
    assert_eq!(owner.admit(bound).ok(), Some(vec![7_u8, 8, 9]));
}

#[test]
fn a_cloned_prover_identity_is_another_instance() {
    let owner = ProverInstanceV1::fresh();
    let clone = owner.clone();
    assert!(clone.admit(owner.bind(1_u8)).is_err());
    assert!(owner.admit(clone.bind(2_u8)).is_err());
    assert_eq!(owner.admit(owner.bind(3_u8)).ok(), Some(3));
    assert_eq!(clone.admit(clone.bind(4_u8)).ok(), Some(4));
}

#[test]
fn retained_state_keeps_its_identity_after_the_prover_is_dropped() {
    let owner = ProverInstanceV1::fresh();
    let mut bound = owner.bind(5_u8);
    drop(owner);
    // The bound value keeps the dropped owner's allocation alive, so no later
    // instance can be placed at that address and admit it.
    for _ in 0..4096 {
        let later = ProverInstanceV1::fresh();
        bound = match later.admit(bound) {
            Ok(_) => panic!("a later prover instance admitted retained state"),
            Err(bound) => bound,
        };
    }
}

#[test]
fn binding_moves_the_value_and_a_refusal_hands_it_back_for_dropping() {
    let owner = ProverInstanceV1::fresh();
    let other = ProverInstanceV1::fresh();
    let value = Arc::new(());
    let bound = owner.bind(Arc::clone(&value));
    assert_eq!(Arc::strong_count(&value), 2, "binding copies nothing");
    let refused = other.admit(bound);
    assert_eq!(
        Arc::strong_count(&value),
        2,
        "refusal returns the same value"
    );
    drop(refused);
    assert_eq!(
        Arc::strong_count(&value),
        1,
        "a dropped refusal releases it"
    );
    let resumed = owner.admit(owner.bind(Arc::clone(&value)));
    assert!(resumed.is_ok_and(|resumed| Arc::ptr_eq(&resumed, &value)));
}

#[test]
fn retained_sessions_are_owned_move_only_state() {
    // A retention slot stores the state as owned `Send` data across fold calls.
    fn owned<T: Send + 'static>(_: core::marker::PhantomData<T>) {}
    macro_rules! move_only {
        ($($retained:ty),+ $(,)?) => {$({
            trait AmbiguousIfClone<A> {
                fn check() {}
            }
            impl<T: ?Sized> AmbiguousIfClone<()> for T {}
            #[allow(dead_code)]
            struct IsClone;
            impl<T: ?Sized + Clone> AmbiguousIfClone<IsClone> for T {}
            // Resolves only when `$retained` does not implement `Clone`.
            let _ = <$retained as AmbiguousIfClone<_>>::check;
            owned(core::marker::PhantomData::<$retained>);
        })+};
    }
    move_only!(
        super::super::bootstrap::RetainedSession,
        super::super::load::RetainedSession,
        super::super::send::RetainedSession,
        super::super::receive::RetainedSession,
        super::super::archive::RetainedSession,
        super::super::consuming::RetainedSession,
        super::super::refresh::RetainedSession,
    );
}
