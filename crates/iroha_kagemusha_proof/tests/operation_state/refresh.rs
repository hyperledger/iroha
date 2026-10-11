//! Refresh state-effect constraints; signed-object authentication is composed separately.

use super::*;
use iroha_kagemusha_proof::operation_relation::{
    map_effects::{MapState, MapTransition},
    refresh::{self, RefreshUpdate},
};

#[path = "quota.rs"]
mod quota;

const RK: u32 = 13;
const VARIANTS: [Variant; 5] = [
    Variant::RefreshCredential,
    Variant::RefreshSchemePolicy,
    Variant::RefreshBlacklist,
    Variant::RefreshQuotaShare,
    Variant::RefreshTimeAnchor,
];

#[derive(Clone)]
struct RefreshCircuit {
    statement: StatementCircuit,
    // Variant-fixed canonical object fields, not an authenticated object fixture.
    facts: Vec<Fp>,
    quota: Option<quota::Fixture>,
}

impl Circuit<Fp> for RefreshCircuit {
    type Config = Config;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();
    fn without_witnesses(&self) -> Self {
        Self {
            statement: self.statement.without_witnesses(),
            ..self.clone()
        }
    }
    fn configure(meta: &mut ConstraintSystem<Fp>) -> Config {
        configure_columns(meta, 27)
    }
    fn synthesize(&self, config: Config, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
        let mut glue = GlueChip::new(config.glue);
        let mut range = RunningSumChip::new(config.range);
        let mut sponge = SpongeChip::new(config.sponge);
        range.load_table(&mut layouter)?;
        let output = layouter.assign_region(
            || "refresh",
            |mut region| self.assign(&mut glue, &mut range, &mut sponge, &mut region),
        )?;
        for (i, word) in output.iter().enumerate() {
            layouter.constrain_instance(word.cell(), config.public, i)?;
        }
        Ok(())
    }
}

impl RefreshCircuit {
    fn assign(
        &self,
        glue: &mut GlueChip<Fp>,
        range: &mut RunningSumChip<Fp>,
        sponge: &mut impl iroha_plonk_gadgets::WordHasher<Fp>,
        region: &mut Region<'_, Fp>,
    ) -> Result<Vec<iroha_plonk_gadgets::Word<Fp>>, Error> {
        let value = |v: &Fp| {
            if self.statement.known {
                Value::known(*v)
            } else {
                Value::unknown()
            }
        };
        let fields = glue.witnesses(
            region,
            &self.statement.fields.iter().map(value).collect::<Vec<_>>(),
        )?;
        let facts = glue.witnesses(region, &self.facts.iter().map(value).collect::<Vec<_>>())?;
        let mut uint = UintChip::new(glue, range);
        let statement = StatementCells::constrain(
            &mut uint,
            sponge,
            region,
            self.statement.variant,
            &::core::array::from_fn(|i| fields[i].clone()),
        )?;
        let (before, after) = self.statement.states.as_ref().expect("states");
        let (before, previous) = assign_state(
            &mut uint,
            sponge,
            region,
            before.as_ref().expect("before"),
            self.statement.known,
        )?;
        let (after, lineage) =
            assign_state(&mut uint, sponge, region, after, self.statement.known)?;
        let pair = |i: usize| ::core::array::from_fn(|j| facts[i + j].clone());
        let scheme = if facts.len() >= 5 { pair(1) } else { pair(0) };
        let asset = if facts.len() >= 8 { pair(3) } else { pair(0) };
        let wallet = if facts.len() == 11 {
            pair(5)
        } else if facts.len() == 6 {
            pair(3)
        } else {
            pair(0)
        };
        let update = match self.statement.variant {
            Variant::RefreshCredential => RefreshUpdate::Credential {
                digest: &facts[0],
                issued: &facts[1],
                lease: &facts[2],
            },
            Variant::RefreshSchemePolicy => RefreshUpdate::SchemePolicy {
                digest: &facts[0],
                scheme: &scheme,
                asset: &asset,
                epoch: &facts[5],
                controls: &facts[6],
                fee: &facts[7],
            },
            Variant::RefreshBlacklist => RefreshUpdate::Blacklist {
                digest: &facts[0],
                scheme: &scheme,
                version: &facts[3],
                root: &facts[4],
                issued: &facts[5],
            },
            Variant::RefreshQuotaShare => RefreshUpdate::QuotaShare {
                digest: &facts[0],
                scheme: &scheme,
                asset: &asset,
                wallet: &wallet,
                id: &facts[7],
                issued: &facts[8],
                expires: &facts[9],
                windows: &facts[10],
            },
            Variant::RefreshTimeAnchor => RefreshUpdate::TimeAnchor {
                digest: &facts[0],
                scheme: &scheme,
                wallet: &wallet,
                issued: &facts[5],
            },
            _ => return Err(Error::Synthesis),
        };
        refresh::constrain(
            &mut uint,
            region,
            &MapTransition {
                statement: &statement,
                predecessor: MapState {
                    state: &before,
                    lineage: &previous,
                },
                successor: MapState {
                    state: &after,
                    lineage: &lineage,
                },
            },
            update,
        )?;
        if let Some(quota) = &self.quota {
            quota.constrain(
                &mut uint,
                sponge,
                region,
                &MapTransition {
                    statement: &statement,
                    predecessor: MapState {
                        state: &before,
                        lineage: &previous,
                    },
                    successor: MapState {
                        state: &after,
                        lineage: &lineage,
                    },
                },
                self.statement.known,
            )?;
        }
        let mut output = statement.fields().to_vec();
        output.push(statement.digest().clone());
        Ok(output)
    }
    fn accepts(&self) -> bool {
        check_circuit(
            self,
            if self.quota.is_some() { 16 } else { RK },
            &[self.statement.public()],
            CheckMode::Strict,
        )
        .is_ok_and(|r| r.is_satisfied())
    }
    fn rebind(&mut self) {
        let (before, mut after) = self.statement.states.take().expect("states");
        let mut before = before.expect("predecessor");
        before.rebind();
        after.rebind();
        self.statement = bind_statement(self.statement.clone(), Some(before), after);
    }
}

fn fixture(variant: Variant) -> RefreshCircuit {
    let mut before = basic();
    before.core[core::BALANCE] = Fp::from(100);
    before.core[core::TIME_FLOOR] = Fp::from(30);
    before.core[core::TIME_ANCHOR_MAX_RESPONSE] = Fp::from(5);
    before.core[core::LEASE_EXPIRY] = Fp::from(1000);
    before.rest[rest::PERMITTED] = Fp::from(5);
    before.rebind();
    let mut after = before.clone();
    after.core[core::SEQUENCE] += Fp::ONE;
    after.core[core::STATE_NONCE] += Fp::ONE;
    let f = Fp::from;
    let facts = match variant {
        Variant::RefreshCredential => {
            after.core[core::CREDENTIAL] = f(80);
            after.core[core::LEASE_EXPIRY] = f(2000);
            after.core[core::TIME_FLOOR] = f(40);
            vec![f(80), f(40), f(2000)]
        }
        Variant::RefreshSchemePolicy => {
            after.core[core::POLICY_EPOCH] = f(2);
            after.core[core::ENABLED_CONTROLS] = f(5);
            after.rest[rest::SCHEME_POLICY] = f(80);
            after.rest[rest::FEE_SCHEDULE] = f(90);
            vec![f(80), f(1), f(2), f(3), f(4), f(2), f(7), f(90)]
        }
        Variant::RefreshBlacklist => {
            after.core[core::BLACKLIST_VERSION] = f(2);
            after.core[core::BLACKLIST_ROOT] = f(89);
            after.core[core::BLACKLIST_ISSUED_AT] = f(40);
            after.core[core::TIME_FLOOR] = f(40);
            after.rest[rest::BLACKLIST] = f(80);
            vec![f(80), f(1), f(2), f(2), f(89), f(40)]
        }
        Variant::RefreshQuotaShare => {
            after.rest[rest::QUOTA_SHARE] = f(80);
            after.rest[rest::QUOTA_SHARE_ID] = f(2);
            after.core[core::QUOTA_WINDOWS_ROOT] = f(89);
            after.core[core::QUOTA_SHARE_EXPIRY] = f(100);
            after.core[core::TIME_FLOOR] = f(40);
            vec![
                f(80),
                f(1),
                f(2),
                f(3),
                f(4),
                f(5),
                f(6),
                f(2),
                f(40),
                f(100),
                f(89),
            ]
        }
        Variant::RefreshTimeAnchor => {
            after.rest[rest::TIME_ANCHOR] = f(80);
            after.core[core::TIME_FLOOR] = f(40);
            vec![f(80), f(1), f(2), f(5), f(6), f(40)]
        }
        _ => unreachable!(),
    };
    after.rebind();
    let mut stmt = statement(variant);
    stmt.fields[18] = f(80);
    stmt.fields[19] = after.core[core::TIME_FLOOR];
    RefreshCircuit {
        statement: bind_statement(stmt, Some(before), after),
        facts,
        quota: None,
    }
}

#[test]
fn five_refresh_state_effects_and_every_unrelated_field_are_constrained() {
    for variant in VARIANTS {
        let c = fixture(variant);
        assert!(c.accepts(), "{variant:?}");
        for i in 0..CORE_FIELDS + REST_FIELDS {
            if i == core::STATE_NONCE
                || (variant == Variant::RefreshQuotaShare && i == core::QUOTA_USAGE_ROOT)
                || (variant == Variant::RefreshBlacklist
                    && i == CORE_FIELDS + rest::BLACKLIST_HISTORY)
            {
                continue;
            }
            let mut bad = c.clone();
            let after = &mut bad.statement.states.as_mut().expect("states").1;
            if i < CORE_FIELDS {
                after.core[i] += Fp::ONE;
            } else {
                after.rest[i - CORE_FIELDS] += Fp::ONE;
            }
            bad.rebind();
            assert!(!bad.accepts(), "{variant:?} field {i}");
        }
        for i in [14, 15, 16] {
            let mut bad = c.clone();
            bad.statement.states.as_mut().expect("states").1.lineage[i] += Fp::ONE;
            bad.rebind();
            assert!(!bad.accepts(), "lineage {i}");
        }
        let known = synthesize(&c, RK, Some(&[c.statement.public()])).expect("known");
        let unknown = synthesize(&c.without_witnesses(), RK, None).expect("unknown");
        assert_eq!(known.tables.fixed(), unknown.tables.fixed());
        assert_eq!(known.tables.selectors(), unknown.tables.selectors());
        assert_eq!(known.tables.permutation(), unknown.tables.permutation());
        assert_eq!(
            known.tables.advice_assigned(),
            unknown.tables.advice_assigned()
        );
    }
}

#[test]
fn refresh_rejects_stale_counters_wrong_objects_and_repeated_anchors() {
    for (variant, at) in [
        (Variant::RefreshSchemePolicy, 5),
        (Variant::RefreshBlacklist, 3),
        (Variant::RefreshQuotaShare, 7),
    ] {
        let mut stale = fixture(variant);
        stale.facts[at] = Fp::ZERO;
        assert!(!stale.accepts());
        stale.facts[at] = Fp::from_u128(1 << 64);
        assert!(!stale.accepts());
    }
    for variant in VARIANTS {
        let mut bad = fixture(variant);
        bad.facts[0] += Fp::ONE;
        assert!(!bad.accepts(), "digest {variant:?}");
        if variant != Variant::RefreshCredential {
            for index in [1, 2] {
                let mut bad = fixture(variant);
                bad.facts[index] += Fp::ONE;
                assert!(!bad.accepts(), "scheme {variant:?}");
            }
        }
    }
    let mut repeated = fixture(Variant::RefreshTimeAnchor);
    repeated
        .statement
        .states
        .as_mut()
        .expect("states")
        .0
        .as_mut()
        .expect("before")
        .rest[rest::TIME_ANCHOR] = Fp::from(80);
    repeated.rebind();
    assert!(!repeated.accepts());
    let mut backwards = fixture(Variant::RefreshTimeAnchor);
    backwards.facts[5] = Fp::from(20);
    let after = &mut backwards.statement.states.as_mut().expect("states").1;
    after.core[core::TIME_FLOOR] = Fp::from(30);
    backwards.statement.fields[19] = Fp::from(30);
    backwards.rebind();
    assert!(backwards.accepts(), "older anchor keeps monotone floor");
    let mut too_short = fixture(Variant::RefreshQuotaShare);
    too_short.facts[9] = Fp::from(40);
    too_short.statement.states.as_mut().expect("states").1.core[core::QUOTA_SHARE_EXPIRY] =
        Fp::from(40);
    too_short.rebind();
    assert!(!too_short.accepts());
}

#[derive(Clone)]
struct SharedRefresh(RefreshCircuit);

#[derive(Clone, Debug)]
struct SharedConfig {
    verifier: iroha_plonk_recursion::verifier::VerifierConfig<iroha_pasta::Ep>,
    public: Column<Instance>,
}

impl Circuit<Fp> for SharedRefresh {
    type Config = SharedConfig;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();
    fn without_witnesses(&self) -> Self {
        Self(self.0.without_witnesses())
    }
    fn configure(meta: &mut ConstraintSystem<Fp>) -> SharedConfig {
        let verifier = iroha_plonk_recursion::verifier::VerifierConfig::configure(meta);
        let public = meta.instance_column(27);
        meta.enable_equality(public);
        SharedConfig { verifier, public }
    }
    fn synthesize(
        &self,
        config: SharedConfig,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let mut chip = iroha_plonk_recursion::verifier::VerifierChip::new(config.verifier);
        chip.load_tables(&mut layouter)?;
        let output = layouter.assign_region(
            || "shared quota and verifier lane",
            |mut region| {
                let lanes = chip.operation_lanes()?;
                let words = self
                    .0
                    .assign(lanes.glue, lanes.range, lanes.hash, &mut region)?;
                // Both the direct interpreter API and generic operation hasher
                // continue after the entire fixed-array rebuild without a reset.
                let repeated = chip.hash_words(&mut region, STATEMENT_DOMAIN, &words[..26])?;
                GlueChip::assert_equal(&mut region, &repeated, &words[26])?;
                let lanes = chip.operation_lanes()?;
                // Borrowing a non-clear transcript is rejected, rather than reset.
                lanes.hash.absorb_constant(Fp::ONE);
                assert!(chip.operation_lanes().is_err());
                assert!(chip.hash_words(&mut region, 0, &[]).is_err());
                Ok(words)
            },
        )?;
        for (i, word) in output.iter().enumerate() {
            layouter.constrain_instance(word.cell(), config.public, i)?;
        }
        Ok(())
    }
}

#[test]
fn operation_hashes_share_recursive_lane_without_resetting_it() {
    let source = quota::sample();
    let c = SharedRefresh(source.clone());
    let report =
        check_circuit(&c, 16, &[source.statement.public()], CheckMode::Strict).expect("shared");
    assert!(report.is_satisfied(), "{report:?}");
    let known = synthesize(&c, 16, Some(&[source.statement.public()])).expect("known");
    let unknown = synthesize(&c.without_witnesses(), 16, None).expect("unknown");
    assert_eq!(known.tables.fixed(), unknown.tables.fixed());
    assert_eq!(known.tables.selectors(), unknown.tables.selectors());
    assert_eq!(known.tables.permutation(), unknown.tables.permutation());
    let mut bad = source;
    bad.quota.as_mut().expect("quota").erase_usage();
    assert!(
        !check_circuit(
            &SharedRefresh(bad.clone()),
            16,
            &[bad.statement.public()],
            CheckMode::Strict
        )
        .expect("forged")
        .is_satisfied()
    );
}
