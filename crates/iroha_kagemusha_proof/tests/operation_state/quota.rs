//! Fixed-array quota rebuild, deterministic matching and quota-reset attacks.

use super::*;
use iroha_kagemusha_proof::{
    operation_relation::quota_refresh::{self, QUOTA_WITNESS_WORDS, QuotaRebuildCells, QuotaRoot},
    tree::{QUOTA_NODE_DOMAIN, QUOTA_USAGE_DOMAIN, QUOTA_USAGE_NODE_DOMAIN, QUOTA_WINDOW_DOMAIN},
};

#[derive(Clone, Copy)]
enum Scope {
    Combined,
    Root(QuotaRoot),
    Semantics,
}

#[derive(Clone)]
pub(super) struct Fixture {
    scope: Scope,
    old: Vec<[Fp; 4]>,
    windows: Vec<[Fp; 4]>,
    used: Vec<Fp>,
    issued: Fp,
    count_override: Option<u64>,
}

impl Fixture {
    pub(super) fn erase_usage(&mut self) {
        self.used[0] = Fp::ZERO;
    }
    pub(super) fn constrain(
        &self,
        uint: &mut UintChip<'_, Fp>,
        sponge: &mut impl iroha_plonk_gadgets::WordHasher<Fp>,
        region: &mut Region<'_, Fp>,
        transition: &MapTransition<'_>,
        known: bool,
    ) -> Result<(), Error> {
        let count = Fp::from(self.count_override.unwrap_or_else(|| {
            u64::try_from(self.windows.iter().filter(|w| w[0] != Fp::ZERO).count()).expect("count")
        }));
        let values: Vec<_> = self
            .old
            .iter()
            .flatten()
            .chain(self.windows.iter().flatten())
            .chain(&self.used)
            .chain([&self.issued, &count])
            .map(|v| {
                if known {
                    Value::known(*v)
                } else {
                    Value::unknown()
                }
            })
            .collect();
        let w = uint.glue().witnesses(region, &values)?;
        let old = ::core::array::from_fn(|i| ::core::array::from_fn(|j| w[4 * i + j].clone()));
        let windows =
            ::core::array::from_fn(|i| ::core::array::from_fn(|j| w[256 + 4 * i + j].clone()));
        let used = ::core::array::from_fn(|i| w[512 + i].clone());
        let witness = QuotaRebuildCells {
            old,
            windows,
            used,
            issued: w[576].clone(),
            window_count: w[577].clone(),
        };
        let committed = witness.commitment_words();
        assert_eq!(committed.len(), QUOTA_WITNESS_WORDS);
        assert_eq!(
            committed
                .iter()
                .map(iroha_plonk_gadgets::Word::cell)
                .collect::<Vec<_>>(),
            w.iter()
                .map(iroha_plonk_gadgets::Word::cell)
                .collect::<Vec<_>>(),
            "fixed quota commitment preserves every assigned word in order"
        );
        match self.scope {
            Scope::Combined => quota_refresh::constrain(uint, sponge, region, transition, &witness),
            Scope::Root(root) => {
                quota_refresh::constrain_root(sponge, region, transition, &witness, root)
            }
            Scope::Semantics => {
                quota_refresh::constrain_semantics(uint, region, transition, &witness)
            }
        }
    }
    fn roots(&self) -> [Fp; 3] {
        fn root(leaves: &[[Fp; 4]], leaf_domain: u64, node_domain: u64) -> Fp {
            let mut nodes: Vec<_> = leaves
                .iter()
                .map(|leaf| hash_with_domain(leaf_domain, leaf))
                .collect();
            while nodes.len() > 1 {
                nodes = nodes
                    .chunks_exact(2)
                    .map(|pair| hash_with_domain(node_domain, pair))
                    .collect();
            }
            nodes[0]
        }
        let new: Vec<_> = self
            .windows
            .iter()
            .zip(&self.used)
            .map(|(w, used)| [w[0], w[1], w[2], *used])
            .collect();
        [
            root(&self.old, QUOTA_USAGE_DOMAIN, QUOTA_USAGE_NODE_DOMAIN),
            root(&self.windows, QUOTA_WINDOW_DOMAIN, QUOTA_NODE_DOMAIN),
            root(&new, QUOTA_USAGE_DOMAIN, QUOTA_USAGE_NODE_DOMAIN),
        ]
    }
}

fn row(kind: u64, start: u64, end: u64, amount: u64) -> [Fp; 4] {
    [kind, start, end, amount].map(Fp::from)
}

fn rebuild_roots(c: &mut RefreshCircuit) {
    let roots = c.quota.as_ref().expect("quota").roots();
    let (before, after) = c.statement.states.as_mut().expect("states");
    before.as_mut().expect("before").core[core::QUOTA_USAGE_ROOT] = roots[0];
    after.core[core::QUOTA_WINDOWS_ROOT] = roots[1];
    after.core[core::QUOTA_USAGE_ROOT] = roots[2];
    c.facts[10] = roots[1];
    c.rebind();
}

pub(super) fn sample() -> RefreshCircuit {
    let mut c = fixture(Variant::RefreshQuotaShare);
    let before = c
        .statement
        .states
        .as_mut()
        .expect("states")
        .0
        .as_mut()
        .expect("before");
    before.rest[rest::QUOTA_SHARE] = Fp::from(70);
    before.rest[rest::QUOTA_SHARE_ID] = Fp::ONE;
    before.core[core::QUOTA_WINDOWS_ROOT] = Fp::from(71);
    before.core[core::QUOTA_SHARE_EXPIRY] = Fp::from(100);
    let mut q = Fixture {
        scope: Scope::Combined,
        count_override: None,
        old: vec![[Fp::ZERO; 4]; 64],
        windows: vec![[Fp::ZERO; 4]; 64],
        used: vec![Fp::ZERO; 64],
        issued: Fp::from(40),
    };
    q.old[0] = row(1, 40, 60, 10);
    q.windows[0] = row(1, 40, 60, 5); // A lower replacement limit must not erase usage.
    q.windows[1] = row(2, 50, 80, 4);
    q.used[0] = Fp::from(10);
    c.quota = Some(q);
    rebuild_roots(&mut c);
    c
}

#[test]
fn quota_rebuild_preserves_charges_and_has_witness_independent_layout() {
    let c = sample();
    assert!(c.accepts());
    let known = synthesize(&c, 16, Some(&[c.statement.public()])).expect("known");
    let unknown = synthesize(&c.without_witnesses(), 16, None).expect("unknown");
    assert_eq!(known.tables.fixed(), unknown.tables.fixed());
    assert_eq!(known.tables.selectors(), unknown.tables.selectors());
    assert_eq!(known.tables.permutation(), unknown.tables.permutation());
    assert_eq!(
        known.tables.advice_assigned(),
        unknown.tables.advice_assigned()
    );
    let rows: Vec<_> = known
        .tables
        .advice_assigned()
        .iter()
        .map(|c| c.iter().rposition(|used| *used).map_or(0, |i| i + 1))
        .collect();
    eprintln!("production quota rebuild rows={rows:?}");
    let mut all = sample();
    let q = all.quota.as_mut().expect("quota");
    q.issued = Fp::from(40);
    for i in 0_u64..64 {
        let index = usize::try_from(i).expect("slot");
        q.old[index] = row(1, 40 + 10 * i, 50 + 10 * i, i);
        q.windows[index] = row(1, 40 + 10 * i, 50 + 10 * i, 100);
        q.used[index] = Fp::from(i);
    }
    all.facts[9] = Fp::from(1000);
    all.statement.states.as_mut().expect("states").1.core[core::QUOTA_SHARE_EXPIRY] =
        Fp::from(1000);
    rebuild_roots(&mut all);
    assert!(all.accepts(), "all 64 matched, no padding");
}

#[test]
fn quota_rebuild_rejects_reset_changed_end_and_live_drop_even_with_rehashed_roots() {
    for attack in 0..14 {
        let mut c = sample();
        let q = c.quota.as_mut().expect("quota");
        match attack {
            0 => q.used[0] = Fp::ZERO,
            1 => q.windows[0][2] += Fp::ONE,
            2 => {
                q.windows[0] = q.windows[1];
                q.windows[1] = [Fp::ZERO; 4];
                q.used[0] = Fp::ZERO;
            }
            3 => q.used[1] = Fp::ONE,
            4 => q.windows[1][1] = Fp::from(39),
            5 => q.windows[1] = q.windows[0],
            6 => {
                q.windows[2] = q.windows[1];
                q.windows[1] = [Fp::ZERO; 4];
            }
            7 => q.windows[1][2] = Fp::from(55),
            8 => q.windows[1][0] = Fp::from(3),
            9 => q.old[2][3] = Fp::ONE,
            10 => q.count_override = Some(0),
            11 => q.count_override = Some(1),
            12 => q.count_override = Some(3),
            13 => q.count_override = Some(65),
            _ => unreachable!(),
        }
        rebuild_roots(&mut c);
        assert!(!c.accepts(), "quota attack {attack}");
    }
}

#[test]
fn quota_first_share_and_expired_or_unused_drops_follow_exact_floor_rules() {
    let mut first = sample();
    let before = first
        .statement
        .states
        .as_mut()
        .expect("states")
        .0
        .as_mut()
        .expect("before");
    before.rest[rest::QUOTA_SHARE] = Fp::ZERO;
    before.rest[rest::QUOTA_SHARE_ID] = Fp::ZERO;
    before.core[core::QUOTA_WINDOWS_ROOT] = Fp::ZERO;
    before.core[core::QUOTA_SHARE_EXPIRY] = Fp::ZERO;
    before.core[core::TIME_FLOOR] = Fp::from(45);
    first.statement.states.as_mut().expect("states").1.core[core::TIME_FLOOR] = Fp::from(45);
    first.statement.fields[19] = Fp::from(45);
    let q = first.quota.as_mut().expect("quota");
    q.old.fill([Fp::ZERO; 4]);
    q.used.fill(Fp::ZERO);
    rebuild_roots(&mut first);
    assert!(first.accepts(), "first share starts before accepted floor");
    let mut fake_first = first.clone();
    fake_first.quota.as_mut().expect("quota").old[0] = row(1, 40, 60, 1);
    rebuild_roots(&mut fake_first);
    assert!(!fake_first.accepts());
    for unused in [false, true] {
        let mut c = sample();
        let q = c.quota.as_mut().expect("quota");
        if unused {
            q.old[0][3] = Fp::ZERO;
        } else {
            c.statement
                .states
                .as_mut()
                .expect("states")
                .0
                .as_mut()
                .expect("before")
                .core[core::TIME_FLOOR] = Fp::from(60);
            c.statement.states.as_mut().expect("states").1.core[core::TIME_FLOOR] = Fp::from(60);
            c.statement.fields[19] = Fp::from(60);
        }
        // Drop the old key and install a future window; a signed share is nonempty.
        q.windows.fill([Fp::ZERO; 4]);
        q.windows[0] = row(2, 60, 80, 4);
        q.used.fill(Fp::ZERO);
        rebuild_roots(&mut c);
        assert!(c.accepts(), "drop unused={unused}");
        c.quota.as_mut().expect("quota").windows.fill([Fp::ZERO; 4]);
        rebuild_roots(&mut c);
        assert!(!c.accepts(), "signed share cannot contain zero windows");
    }
}

#[test]
fn split_quota_roots_reject_changed_preimages_and_preserve_fixed_layout() {
    for root in [
        QuotaRoot::PreviousUsage,
        QuotaRoot::ReplacementWindows,
        QuotaRoot::ReplacementUsage,
    ] {
        let mut c = sample();
        c.quota.as_mut().expect("quota").scope = Scope::Root(root);
        assert!(c.accepts(), "root {root:?}");
        let known = synthesize(&c, 16, Some(&[c.statement.public()])).expect("known");
        let unknown = synthesize(&c.without_witnesses(), 16, None).expect("unknown");
        assert_eq!(known.tables.fixed(), unknown.tables.fixed());
        assert_eq!(known.tables.permutation(), unknown.tables.permutation());
        assert_eq!(
            known.tables.advice_assigned(),
            unknown.tables.advice_assigned()
        );
        let q = c.quota.as_mut().expect("quota");
        match root {
            QuotaRoot::PreviousUsage => q.old[0][3] += Fp::ONE,
            QuotaRoot::ReplacementWindows => q.windows[0][3] += Fp::ONE,
            QuotaRoot::ReplacementUsage => q.used[0] += Fp::ONE,
        }
        assert!(!c.accepts(), "changed exact {root:?} preimage");
    }
}

#[test]
fn split_quota_semantics_reject_reset_with_consistently_rehashed_roots() {
    let mut c = sample();
    c.quota.as_mut().expect("quota").scope = Scope::Semantics;
    assert!(c.accepts());
    c.quota.as_mut().expect("quota").used[0] = Fp::ZERO;
    rebuild_roots(&mut c);
    assert!(
        !c.accepts(),
        "matching usage cannot reset even with rebound roots"
    );
}
