//! Exact initial state, administrative value changes and unchanged-field tests.

use super::*;
use iroha_kagemusha_proof::{
    operation_relation::administrative::NULLIFIER_DOMAIN,
    tree::{IndexedTree, QuotaUsageTree, QuotaWindowTree},
};

fn initial() -> StateCircuit {
    let mut state = basic();
    let empty = IndexedTree::<Fp>::new().root();
    state.core[core::CONSUMED_CREDIT_ROOT..=core::FEE_CLAIM_ROOT].fill(empty);
    state.core[core::QUOTA_USAGE_ROOT] =
        QuotaUsageTree::<Fp>::new(&QuotaWindowTree::new(&[]).expect("windows")).root();
    state.rest[rest::BLACKLIST_HISTORY] = empty;
    state.lineage[14] = Fp::ZERO;
    state.lineage[15] = empty;
    state.lineage[16] = empty;
    state.rebind();
    state
}

fn rebind(c: &mut StatementCircuit) {
    let (mut before, mut after) = c.states.take().expect("states");
    if let Some(before) = &mut before {
        before.rebind();
    }
    after.rebind();
    *c = bind_statement(c.clone(), before, after);
}

fn fixture(variant: Variant) -> StatementCircuit {
    let mut c = statement(variant);
    c.administrative_effects = true;
    if variant == Variant::Bootstrap {
        return bind_statement(c, None, initial());
    }
    let mut before = initial();
    before.core[core::BALANCE] = Fp::from(100);
    before.core[core::NEXT_LOAD] = Fp::from(3);
    before.core[core::NEXT_REDEEM] = Fp::from(7);
    before.lineage[14] = Fp::from(11);
    before.lineage[15] = Fp::from(12345);
    before.rebind();
    let mut after = before.clone();
    after.core[core::SEQUENCE] += Fp::ONE;
    after.core[core::STATE_NONCE] += Fp::ONE;
    if variant == Variant::Load {
        c.fields[18] = Fp::from(3);
        c.fields[19] = Fp::from(20);
        after.core[core::BALANCE] += Fp::from(20);
        after.core[core::NEXT_LOAD] += Fp::ONE;
        after.core[core::LOAD_REDEEM_ROOT] = Fp::from(55);
    } else {
        after.core[core::BURNED_TOTAL] = before.lineage[14];
        after.core[core::PENDING_OUTGOING_ROOT] = before.lineage[15];
        if variant == Variant::Unload {
            c.fields[18] = before.core[core::NEXT_REDEEM];
            c.fields[17] = hash_with_domain(
                NULLIFIER_DOMAIN,
                &[
                    before.core[core::SCHEME],
                    before.core[core::SCHEME + 1],
                    before.core[core::WALLET],
                    before.core[core::WALLET + 1],
                    c.fields[18],
                ],
            );
            c.fields[19] = Fp::from(20);
            after.core[core::BALANCE] -= Fp::from(20);
            after.core[core::NEXT_REDEEM] += Fp::ONE;
            after.core[core::LOAD_REDEEM_ROOT] = Fp::from(55);
        } else {
            after.core[core::LIFECYCLE] = Fp::from(2);
        }
    }
    after.rebind();
    bind_statement(c, Some(before), after)
}

#[test]
fn bootstrap_rejects_preloaded_value_and_nonempty_maps() {
    let c = fixture(Variant::Bootstrap);
    assert!(c.accepts());
    for index in core::BALANCE..=core::BLACKLIST_ISSUED_AT {
        let mut wrong = c.clone();
        wrong.states.as_mut().unwrap().1.core[index] += Fp::ONE;
        rebind(&mut wrong);
        assert!(!wrong.accepts(), "core {index}");
    }
    for index in [core::POLICY_EPOCH, core::TIME_FLOOR] {
        let mut wrong = c.clone();
        wrong.states.as_mut().unwrap().1.core[index] += Fp::ONE;
        rebind(&mut wrong);
        assert!(!wrong.accepts());
    }
    for index in 1..8 {
        let mut wrong = c.clone();
        wrong.states.as_mut().unwrap().1.rest[index] += Fp::ONE;
        rebind(&mut wrong);
        assert!(!wrong.accepts(), "rest {index}");
    }
    for index in [14, 15, 16] {
        let mut wrong = c.clone();
        wrong.states.as_mut().unwrap().1.lineage[index] += Fp::ONE;
        assert!(!wrong.accepts());
    }
}

#[test]
fn administrative_arithmetic_continuity_and_exact_field_changes() {
    for variant in [Variant::Load, Variant::Unload, Variant::Retiring] {
        let c = fixture(variant);
        assert!(c.accepts(), "{variant:?}");
        for index in 0..CORE_FIELDS {
            // Nonce is fresh; recovery map is separately authenticated in A.
            if index == core::STATE_NONCE
                || (index == core::LOAD_REDEEM_ROOT && variant != Variant::Retiring)
            {
                continue;
            }
            let mut wrong = c.clone();
            wrong.states.as_mut().unwrap().1.core[index] += Fp::ONE;
            rebind(&mut wrong);
            assert!(!wrong.accepts(), "{variant:?} core{index}");
        }
        for index in 0..REST_FIELDS {
            let mut wrong = c.clone();
            wrong.states.as_mut().unwrap().1.rest[index] += Fp::ONE;
            rebind(&mut wrong);
            assert!(!wrong.accepts(), "{variant:?} rest{index}");
        }
        for index in [14, 15, 16] {
            let mut wrong = c.clone();
            wrong.states.as_mut().unwrap().1.lineage[index] += Fp::ONE;
            assert!(!wrong.accepts());
        }
        let known = synthesize(&c, 12, Some(&[c.public()])).expect("known");
        let unknown = synthesize(&c.without_witnesses(), 12, None).expect("unknown");
        assert_eq!(known.tables.fixed(), unknown.tables.fixed());
        assert_eq!(known.tables.permutation(), unknown.tables.permutation());
    }
    let mut load = fixture(Variant::Load);
    let (before, after) = load.states.as_mut().unwrap();
    before.as_mut().unwrap().core[core::BALANCE] = Fp::from_u128(u128::MAX);
    after.core[core::BALANCE] = Fp::from(19);
    rebind(&mut load);
    assert!(!load.accepts());
    let mut unload = fixture(Variant::Unload);
    unload.fields[19] = Fp::from(90);
    unload.states.as_mut().unwrap().1.core[core::BALANCE] = Fp::from(10);
    rebind(&mut unload);
    assert!(!unload.accepts(), "must leave adjusted burned value");
    let mut forged = fixture(Variant::Unload);
    forged.fields[17] += Fp::ONE;
    assert!(!forged.accepts());
    let mut retired = fixture(Variant::Retiring);
    retired.states.as_mut().unwrap().0.as_mut().unwrap().core[core::LIFECYCLE] = Fp::from(2);
    rebind(&mut retired);
    assert!(!retired.accepts());
}
