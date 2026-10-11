//! Canonical G1 state openings, control consistency and public lineage bindings.

#[path = "operation_state/incoming.rs"]
mod incoming;

#[path = "operation_state/administrative.rs"]
mod administrative;
#[path = "operation_state/maps.rs"]
mod maps;
#[path = "operation_state/refresh.rs"]
mod refresh;

use ff::{Field, PrimeField};
use iroha_kagemusha_proof::{
    a_relation::LineagePublicCells,
    operation_relation::{
        state::{StateCells, rest_index as rest},
        statement::StatementCells,
    },
    witness::{CORE_DOMAIN, CORE_FIELDS, REST_DOMAIN, REST_FIELDS, core_index as core},
};
use iroha_pasta::{Fp, poseidon::hash_with_domain};
use iroha_plonk::{
    check::{CheckMode, check_circuit},
    cs::{Column, ConstraintSystem, Instance},
    frontend::{Circuit, Error, Layouter, Region, SimpleFloorPlanner, Value, synthesize},
};
use iroha_plonk_gadgets::statement::STATEMENT_DOMAIN;
use iroha_plonk_gadgets::{
    GlueChip, GlueConfig, LimbBits, Pow5Columns, RoundConstantColumns, RunningSumChip,
    RunningSumConfig, SpongeChip, SpongeConfig, UintChip,
};
use iroha_plonk_recursion::obligation::ledger::Variant;
use norito::json::Value as Json;

const K: u32 = 11;

#[derive(Clone)]
struct StateCircuit {
    core: [Fp; CORE_FIELDS],
    rest: [Fp; REST_FIELDS],
    lineage: [Fp; 18],
    known: bool,
}

#[derive(Clone, Debug)]
struct Config {
    glue: GlueConfig,
    range: RunningSumConfig,
    sponge: SpongeConfig<Fp>,
    public: Column<Instance>,
}

fn configure_columns(meta: &mut ConstraintSystem<Fp>, public_count: usize) -> Config {
    let advice = ::core::array::from_fn(|_| meta.advice_column());
    let constants = meta.fixed_column();
    let glue = GlueConfig::configure(meta, advice, constants);
    let range_column = meta.advice_column();
    let range = RunningSumConfig::configure(meta, range_column, LimbBits::new(9).expect("limbs"));
    let columns = Pow5Columns::allocate(meta);
    let rounds = RoundConstantColumns::allocate(meta);
    let sponge = SpongeConfig::configure(
        meta,
        columns,
        rounds,
        &[(CORE_DOMAIN, 34), (REST_DOMAIN, 8)],
    );
    let public = meta.instance_column(public_count);
    meta.enable_equality(public);
    Config {
        glue,
        range,
        sponge,
        public,
    }
}

impl Circuit<Fp> for StateCircuit {
    type Config = Config;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();
    fn without_witnesses(&self) -> Self {
        Self {
            known: false,
            ..self.clone()
        }
    }
    fn configure(meta: &mut ConstraintSystem<Fp>) -> Config {
        configure_columns(meta, 20)
    }
    fn synthesize(&self, config: Config, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
        let mut glue = GlueChip::new(config.glue);
        let mut range = RunningSumChip::new(config.range);
        let mut sponge = SpongeChip::new(config.sponge);
        range.load_table(&mut layouter)?;
        let outputs = layouter.assign_region(
            || "state opening",
            |mut region| {
                let values: Vec<_> = self
                    .core
                    .iter()
                    .chain(&self.rest)
                    .chain(&self.lineage)
                    .map(|value| {
                        if self.known {
                            Value::known(*value)
                        } else {
                            Value::unknown()
                        }
                    })
                    .collect();
                let words = glue.witnesses(&mut region, &values)?;
                let mut uint = UintChip::new(&mut glue, &mut range);
                let state = StateCells::constrain(
                    &mut uint,
                    &mut sponge,
                    &mut region,
                    &::core::array::from_fn(|i| words[i].clone()),
                    &::core::array::from_fn(|i| words[CORE_FIELDS + i].clone()),
                )?;
                let lineage = LineagePublicCells::constrain(
                    &mut uint,
                    &mut region,
                    &::core::array::from_fn(|i| words[CORE_FIELDS + REST_FIELDS + i].clone()),
                )?;
                state.bind_lineage(&mut uint, &mut region, &lineage)?;
                let mut outputs = vec![state.rest_digest().clone(), state.commitment().clone()];
                outputs.extend_from_slice(lineage.fields());
                Ok(outputs)
            },
        )?;
        for (index, word) in outputs.iter().enumerate() {
            layouter.constrain_instance(word.cell(), config.public, index)?;
        }
        Ok(())
    }
}

impl StateCircuit {
    fn new(core: &[Fp; CORE_FIELDS], rest: [Fp; REST_FIELDS]) -> Self {
        let mut result = Self {
            core: *core,
            rest,
            lineage: [Fp::ONE; 18],
            known: true,
        };
        result.rebind();
        result
    }
    fn rebind(&mut self) {
        let fields = &mut self.lineage;
        fields[0] = Fp::ONE;
        fields[1] = self.core[core::SCHEME];
        fields[2] = self.core[core::SCHEME + 1];
        fields[5] = {
            let mut preimage = self.core.to_vec();
            preimage.push(hash_with_domain(REST_DOMAIN, &self.rest));
            hash_with_domain(CORE_DOMAIN, &preimage)
        };
        fields[6] = self.core[core::WALLET];
        fields[7] = self.core[core::WALLET + 1];
        fields[8] = self.core[core::CREDENTIAL];
        fields[13] = self.core[core::LIFECYCLE]
            + Fp::from(256) * self.core[core::POLICY_EPOCH]
            + Fp::from_u128(1 << 72) * self.core[core::ENABLED_CONTROLS];
    }
    fn public(&self) -> Vec<Fp> {
        let rest = hash_with_domain(REST_DOMAIN, &self.rest);
        let mut preimage = self.core.to_vec();
        preimage.push(rest);
        let head = hash_with_domain(CORE_DOMAIN, &preimage);
        let mut public = vec![rest, head];
        public.extend(self.lineage);
        public
    }
    fn accepts(&self) -> bool {
        check_circuit(self, K, &[self.public()], CheckMode::Strict).is_ok_and(|r| r.is_satisfied())
    }
    fn reject_rebound(&mut self) {
        self.rebind();
        assert!(!self.accepts());
    }
}

fn basic() -> StateCircuit {
    let mut core = [Fp::ZERO; CORE_FIELDS];
    core[core::LIFECYCLE] = Fp::ONE;
    for (index, field) in core.iter_mut().enumerate().take(8).skip(1) {
        *field = Fp::from(index as u64);
    }
    for (index, field) in core.iter_mut().enumerate().take(21).skip(16) {
        *field = Fp::from(index as u64);
    }
    core[core::STATE_NONCE] = Fp::from(77);
    let mut rest = [Fp::ZERO; REST_FIELDS];
    rest[rest::BLACKLIST_HISTORY] = Fp::from(88);
    StateCircuit::new(&core, rest)
}

fn field(value: &Json) -> Fp {
    let s = value.as_str().expect("hex");
    let bytes =
        ::core::array::from_fn(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("byte"));
    iroha_plonk_gadgets::statement::canonical_field(&bytes).expect("canonical")
}

#[test]
fn shared_core_rest_vectors_and_keygen_layout_match() {
    let fixture: Json = norito::json::from_str(include_str!(
        "../../../fixtures/kagemusha/wallet_v1_vectors.json"
    ))
    .expect("fixture");
    for name in ["controlled_state", "receive_successor_state"] {
        let object = &fixture["field_encodings"][name];
        let core = object["core_items"]
            .as_array()
            .expect("core")
            .iter()
            .map(field)
            .collect::<Vec<_>>()
            .try_into()
            .expect("33");
        let rest = object["rest_items"]
            .as_array()
            .expect("rest")
            .iter()
            .map(field)
            .collect::<Vec<_>>()
            .try_into()
            .expect("8");
        let c = StateCircuit::new(&core, rest);
        assert!(c.accepts(), "{name}");
        assert_eq!(c.public()[1], field(&object["commitment_hex"]));
        let public = [c.public()];
        let known = synthesize(&c, K, Some(&public)).expect("known");
        let unknown = synthesize(&c.without_witnesses(), K, None).expect("unknown");
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
fn integer_ranges_lifecycle_and_nonzero_state_facts() {
    assert!(basic().accepts());
    for index in [core::SCHEME, core::ASSET, core::WALLET] {
        let mut c = basic();
        c.core[index] = Fp::ZERO;
        c.core[index + 1] = Fp::ZERO;
        c.reject_rebound();
    }
    for index in [
        core::CREDENTIAL,
        core::CONSUMED_CREDIT_ROOT,
        core::PENDING_OUTGOING_ROOT,
        core::LOAD_REDEEM_ROOT,
        core::FEE_CLAIM_ROOT,
        core::QUOTA_USAGE_ROOT,
        core::STATE_NONCE,
    ] {
        let mut c = basic();
        c.core[index] = Fp::ZERO;
        c.reject_rebound();
    }
    for index in (core::SCHEME..core::CREDENTIAL).chain(core::BALANCE..=core::NEXT_REDEEM) {
        let mut c = basic();
        c.core[index] = Fp::from_u128(1 << 127).double();
        c.reject_rebound();
    }
    for index in [
        core::QUOTA_SHARE_EXPIRY,
        core::BLACKLIST_VERSION,
        core::BLACKLIST_ISSUED_AT,
        core::BLACKLIST_MAX_AGE,
        core::TIME_ANCHOR_MAX_RESPONSE,
        core::LEASE_EXPIRY,
        core::POLICY_EPOCH,
        core::TIME_FLOOR,
    ] {
        let mut c = basic();
        c.core[index] = Fp::from_u128(1 << 64);
        c.reject_rebound();
    }
    let mut c = basic();
    c.rest[rest::QUOTA_SHARE_ID] = Fp::from_u128(1 << 64);
    c.reject_rebound();
    let mut c = basic();
    c.rest[rest::BLACKLIST_HISTORY] = Fp::ZERO;
    c.reject_rebound();
    for tag in [0, 3] {
        let mut c = basic();
        c.core[core::LIFECYCLE] = Fp::from(tag);
        c.reject_rebound();
    }
    let mut retiring = basic();
    retiring.core[core::LIFECYCLE] = Fp::from(2);
    retiring.rebind();
    assert!(retiring.accepts());
}

#[test]
fn exact_control_mask_policy_and_held_object_consistency() {
    for permitted in 0..8_u64 {
        for enabled in 0..8_u64 {
            let mut c = basic();
            c.rest[rest::PERMITTED] = Fp::from(permitted);
            c.core[core::ENABLED_CONTROLS] = Fp::from(enabled);
            c.core[core::POLICY_EPOCH] = Fp::ONE;
            c.rest[rest::SCHEME_POLICY] = Fp::ONE;
            if permitted & 6 != 0 {
                c.core[core::TIME_ANCHOR_MAX_RESPONSE] = Fp::from(17);
            }
            if permitted & 4 != 0 {
                c.core[core::LEASE_EXPIRY] = Fp::from(33);
            }
            c.rebind();
            assert_eq!(
                c.accepts(),
                enabled & !permitted == 0,
                "{permitted}/{enabled}"
            );
        }
    }
    let mut c = basic();
    c.rest[rest::PERMITTED] = Fp::from(8);
    c.reject_rebound();
    let mut c = basic();
    c.core[core::ENABLED_CONTROLS] = Fp::from(8);
    c.reject_rebound();
    for index in [
        rest::SCHEME_POLICY,
        rest::FEE_SCHEDULE,
        rest::BLACKLIST,
        rest::QUOTA_SHARE,
        rest::QUOTA_SHARE_ID,
    ] {
        let mut c = basic();
        c.rest[index] = Fp::ONE;
        c.reject_rebound();
    }
    for index in [
        core::POLICY_EPOCH,
        core::BLACKLIST_VERSION,
        core::BLACKLIST_ROOT,
        core::BLACKLIST_ISSUED_AT,
        core::QUOTA_WINDOWS_ROOT,
        core::QUOTA_SHARE_EXPIRY,
        core::BLACKLIST_MAX_AGE,
        core::TIME_ANCHOR_MAX_RESPONSE,
        core::LEASE_EXPIRY,
    ] {
        let mut c = basic();
        c.core[index] = Fp::ONE;
        c.reject_rebound();
    }
    let mut c = basic();
    c.rest[rest::PERMITTED] = Fp::ONE;
    c.core[core::BLACKLIST_MAX_AGE] = Fp::from(9);
    c.core[core::TIME_ANCHOR_MAX_RESPONSE] = Fp::from(10);
    c.core[core::BLACKLIST_VERSION] = Fp::ONE;
    c.core[core::BLACKLIST_ROOT] = Fp::from(20);
    c.rest[rest::BLACKLIST] = Fp::from(30);
    c.rest[rest::QUOTA_SHARE_ID] = Fp::ONE;
    c.rest[rest::QUOTA_SHARE] = Fp::from(40);
    c.core[core::QUOTA_WINDOWS_ROOT] = Fp::from(50);
    c.core[core::QUOTA_SHARE_EXPIRY] = Fp::from(60);
    c.rebind();
    assert!(
        c.accepts(),
        "holding a share does not imply its control is enabled"
    );
    c.core[core::TIME_ANCHOR_MAX_RESPONSE] = Fp::ZERO;
    c.reject_rebound();
}

#[test]
fn lineage_head_identity_and_packed_facts_are_bound() {
    for index in [0, 1, 2, 5, 6, 7, 8, 13] {
        let mut c = basic();
        c.lineage[index] += Fp::ONE;
        assert!(!c.accepts(), "lineage field {index}");
    }
    for index in [1, 2, 3, 4, 6, 7, 9, 10, 11, 12, 14] {
        let mut c = basic();
        c.lineage[index] = Fp::from_u128(1 << 127).double();
        assert!(!c.accepts());
    }
    // Lineage-adjusted values differ from the committed core; the owning
    // operation must constrain their transitions, not this state opening.
    let mut c = basic();
    c.lineage[14] = Fp::from(42);
    c.lineage[15] = Fp::from(43);
    c.lineage[16] = Fp::from(44);
    assert!(c.accepts());
}

#[derive(Clone)]
struct StatementCircuit {
    variant: Variant,
    fields: [Fp; 26],
    states: Option<(Option<StateCircuit>, StateCircuit)>,
    known: bool,
    administrative_effects: bool,
}

fn assign_state(
    uint: &mut UintChip<'_, Fp>,
    sponge: &mut impl iroha_plonk_gadgets::WordHasher<Fp>,
    region: &mut Region<'_, Fp>,
    source: &StateCircuit,
    known: bool,
) -> Result<(StateCells, LineagePublicCells), Error> {
    let values: Vec<_> = source
        .core
        .iter()
        .chain(&source.rest)
        .chain(&source.lineage)
        .map(|f| {
            if known {
                Value::known(*f)
            } else {
                Value::unknown()
            }
        })
        .collect();
    let words = uint.glue().witnesses(region, &values)?;
    let state = StateCells::constrain(
        uint,
        sponge,
        region,
        &::core::array::from_fn(|i| words[i].clone()),
        &::core::array::from_fn(|i| words[CORE_FIELDS + i].clone()),
    )?;
    let lineage = LineagePublicCells::constrain(
        uint,
        region,
        &::core::array::from_fn(|i| words[CORE_FIELDS + REST_FIELDS + i].clone()),
    )?;
    Ok((state, lineage))
}

impl Circuit<Fp> for StatementCircuit {
    type Config = Config;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();
    fn without_witnesses(&self) -> Self {
        Self {
            known: false,
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
            || "statement",
            |mut region| {
                let values = self.fields.map(|f| {
                    if self.known {
                        Value::known(f)
                    } else {
                        Value::unknown()
                    }
                });
                let words = glue.witnesses(&mut region, &values)?;
                let mut uint = UintChip::new(&mut glue, &mut range);
                let statement = StatementCells::constrain(
                    &mut uint,
                    &mut sponge,
                    &mut region,
                    self.variant,
                    &::core::array::from_fn(|i| words[i].clone()),
                )?;
                assert_eq!(statement.variant(), self.variant);
                if let Some((before, after)) = &self.states {
                    let predecessor = before
                        .as_ref()
                        .map(|s| assign_state(&mut uint, &mut sponge, &mut region, s, self.known))
                        .transpose()?;
                    let (successor, lineage) =
                        assign_state(&mut uint, &mut sponge, &mut region, after, self.known)?;
                    statement.bind_states(
                        &mut uint,
                        &mut region,
                        predecessor.as_ref().map(|(s, l)| (s, l)),
                        &successor,
                        &lineage,
                    )?;
                    if self.administrative_effects {
                        use iroha_kagemusha_proof::operation_relation::{
                            administrative,
                            map_effects::{MapState, MapTransition},
                        };
                        if let Some((before, previous)) = &predecessor {
                            administrative::monetary(
                                &mut uint,
                                &mut sponge,
                                &mut region,
                                &MapTransition {
                                    statement: &statement,
                                    predecessor: MapState {
                                        state: before,
                                        lineage: previous,
                                    },
                                    successor: MapState {
                                        state: &successor,
                                        lineage: &lineage,
                                    },
                                },
                            )?;
                        } else {
                            administrative::bootstrap(
                                &mut uint,
                                &mut region,
                                &statement,
                                &successor,
                                &lineage,
                            )?;
                        }
                    }
                }
                let mut output = statement.fields().to_vec();
                output.push(statement.digest().clone());
                Ok(output)
            },
        )?;
        for (i, word) in output.iter().enumerate() {
            layouter.constrain_instance(word.cell(), config.public, i)?;
        }
        Ok(())
    }
}

impl StatementCircuit {
    fn public(&self) -> Vec<Fp> {
        let mut public = self.fields.to_vec();
        public.push(hash_with_domain(STATEMENT_DOMAIN, &self.fields));
        public
    }
    fn accepts(&self) -> bool {
        check_circuit(self, 12, &[self.public()], CheckMode::Strict).is_ok_and(|r| r.is_satisfied())
    }
}

fn statement(variant: Variant) -> StatementCircuit {
    let mut fields = [Fp::ONE; 26];
    fields[11] = Fp::ZERO;
    fields[12] = Fp::ZERO;
    fields[13] = if matches!(variant, Variant::Send | Variant::Unload | Variant::Retiring) {
        Fp::from(77)
    } else {
        Fp::ZERO
    };
    fields[17..].fill(Fp::ZERO);
    let (tag, values): (u64, Vec<u64>) = match variant {
        Variant::Bootstrap => {
            for i in [9, 10, 11, 14] {
                fields[i] = Fp::ZERO;
            }
            (1, vec![1, 2, 3, 4])
        }
        Variant::Load => {
            fields[10] = Fp::from(4);
            (2, vec![1, 3, 4, 0])
        }
        Variant::Send => (3, vec![1, 2, 3, 4, 5, 6, 7, 8, 9]),
        Variant::Receive | Variant::ReceiveRenewed => (4, vec![1, 2, 3, 4]),
        Variant::ArchiveReceive | Variant::ArchiveStatus => (5, vec![1, 2]),
        Variant::Unload => (6, vec![1, 2, 3, 0, 0]),
        Variant::Retiring => {
            fields[8] = Fp::from(2);
            (8, vec![])
        }
        Variant::RefreshCredential => (7, vec![1, 1, 0]),
        Variant::RefreshSchemePolicy => (7, vec![2, 1, 0]),
        Variant::RefreshBlacklist => (7, vec![3, 1, 0]),
        Variant::RefreshQuotaShare => (7, vec![4, 1, 0]),
        Variant::RefreshTimeAnchor => (7, vec![5, 1, 0]),
    };
    fields[16] = Fp::from(tag);
    for (i, value) in values.into_iter().enumerate() {
        fields[17 + i] = Fp::from(value);
    }
    StatementCircuit {
        variant,
        fields,
        states: None,
        known: true,
        administrative_effects: false,
    }
}

#[test]
fn all_operation_statement_variants_and_consistent_forgeries() {
    for variant in Variant::ALL {
        let c = statement(variant);
        assert!(c.accepts(), "{variant:?}");
        for index in [0, 16] {
            let mut wrong = c.clone();
            wrong.fields[index] += Fp::ONE;
            assert!(!wrong.accepts());
        }
        if variant != Variant::Send {
            let mut padding = c.clone();
            padding.fields[25] = Fp::ONE;
            assert!(!padding.accepts());
        }
        for index in [1, 2, 3, 4, 5, 6, 9, 10, 12] {
            let mut wide = c.clone();
            wide.fields[index] = Fp::from_u128(1 << 127).double();
            assert!(!wide.accepts());
        }
        for index in [7, 15] {
            let mut zero = c.clone();
            zero.fields[index] = Fp::ZERO;
            assert!(!zero.accepts());
        }
        for pair in [1, 3, 5] {
            let mut zero = c.clone();
            zero.fields[pair] = Fp::ZERO;
            zero.fields[pair + 1] = Fp::ZERO;
            assert!(!zero.accepts());
        }
        let mut wrong = c.clone();
        wrong.fields[11] = Fp::from(8);
        assert!(!wrong.accepts());
        let mut wrong = c.clone();
        wrong.fields[8] = Fp::from(3);
        assert!(!wrong.accepts());
        let mut lineage = c.clone();
        lineage.fields[13] = if c.fields[13] == Fp::ZERO {
            Fp::ONE
        } else {
            Fp::ZERO
        };
        assert!(!lineage.accepts());
    }
    for (variant, index, value) in [
        (Variant::Bootstrap, 9, Fp::ONE),
        (Variant::Bootstrap, 14, Fp::ONE),
        (Variant::Send, 21, Fp::ZERO),
        (Variant::Send, 21, Fp::from_u128(u128::MAX)),
        (Variant::Send, 24, Fp::from(10)),
        (Variant::Send, 23, Fp::ZERO),
        (Variant::Receive, 20, Fp::ZERO),
        (Variant::Receive, 17, Fp::ZERO),
        (Variant::ArchiveStatus, 18, Fp::ZERO),
        (Variant::Unload, 19, Fp::ZERO),
        (Variant::Unload, 20, Fp::from(4)),
        (Variant::Unload, 21, Fp::ONE),
        (Variant::Load, 10, Fp::from(3)),
        (Variant::RefreshCredential, 18, Fp::from(2)),
        (Variant::RefreshBlacklist, 17, Fp::from(2)),
        (Variant::Retiring, 8, Fp::ONE),
    ] {
        let mut c = statement(variant);
        c.fields[index] = value;
        assert!(!c.accepts(), "{variant:?} field{index}");
    }
}

#[test]
fn actual_sigma_statement_vectors_match() {
    let fixture: Json = norito::json::from_str(include_str!(
        "../../../fixtures/kagemusha/wallet_v1_vectors.json"
    ))
    .expect("fixture");
    for (name, variant) in [
        ("send_statement", Variant::Send),
        ("receive_statement", Variant::Receive),
    ] {
        let object = &fixture["field_encodings"][name];
        let fields = object["items"]
            .as_array()
            .expect("items")
            .iter()
            .map(field)
            .collect::<Vec<_>>()
            .try_into()
            .expect("26");
        let c = StatementCircuit {
            variant,
            fields,
            states: None,
            known: true,
            administrative_effects: false,
        };
        assert!(c.accepts());
        assert_eq!(c.public()[26], field(&object["digest_hex"]));
    }
}

fn bind_statement(
    mut statement: StatementCircuit,
    before: Option<StateCircuit>,
    after: StateCircuit,
) -> StatementCircuit {
    let f = &mut statement.fields;
    f[1] = after.lineage[3];
    f[2] = after.lineage[4];
    for (i, j) in [
        (3, core::SCHEME),
        (4, core::SCHEME + 1),
        (5, core::ASSET),
        (6, core::ASSET + 1),
        (7, core::CREDENTIAL),
        (8, core::LIFECYCLE),
        (9, core::SEQUENCE),
        (10, core::NEXT_LOAD),
    ] {
        f[i] = after.core[j];
    }
    f[15] = after.lineage[5];
    if let Some(ref before) = before {
        f[14] = before.lineage[5];
        f[11] = before.core[core::ENABLED_CONTROLS];
        if matches!(
            statement.variant,
            Variant::Send | Variant::Unload | Variant::Retiring
        ) {
            f[12] = before.lineage[14];
            f[13] = before.lineage[15];
        }
    }
    statement.states = Some((before, after));
    statement
}

#[test]
fn statement_headers_bind_actual_state_openings_and_one_sequence_advance() {
    let before = basic();
    let mut after = basic();
    after.core[core::SEQUENCE] = Fp::ONE;
    after.core[core::STATE_NONCE] += Fp::ONE;
    after.rebind();
    let c = bind_statement(
        statement(Variant::Send),
        Some(before.clone()),
        after.clone(),
    );
    assert!(c.accepts());
    for index in [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15] {
        let mut wrong = c.clone();
        wrong.fields[index] += Fp::ONE;
        assert!(!wrong.accepts(), "header{index}");
    }
    let mut wrong_state = after.clone();
    wrong_state.core[core::SEQUENCE] = Fp::from(2);
    wrong_state.rebind();
    assert!(!bind_statement(statement(Variant::Send), Some(before.clone()), wrong_state).accepts());
    for index in [3, 4, 9, 10, 11, 12, 17] {
        let mut wrong = after.clone();
        wrong.lineage[index] += Fp::ONE;
        assert!(
            !bind_statement(statement(Variant::Send), Some(before.clone()), wrong).accepts(),
            "continuity{index}"
        );
    }
    let mut alien = after;
    alien.core[core::WALLET] += Fp::ONE;
    alien.rebind();
    assert!(!bind_statement(statement(Variant::Send), Some(before), alien).accepts());
    let bootstrap = bind_statement(statement(Variant::Bootstrap), None, basic());
    assert!(bootstrap.accepts());
    let mut extra = bootstrap.clone();
    extra.states.as_mut().unwrap().0 = Some(basic());
    assert!(!extra.accepts());
    let mut missing = c.clone();
    missing.states.as_mut().unwrap().0 = None;
    assert!(!missing.accepts());
    let known = synthesize(&c, 12, Some(&[c.public()])).expect("known");
    let unknown = synthesize(&c.without_witnesses(), 12, None).expect("unknown");
    assert_eq!(known.tables.fixed(), unknown.tables.fixed());
    assert_eq!(known.tables.selectors(), unknown.tables.selectors());
    assert_eq!(known.tables.permutation(), unknown.tables.permutation());
    assert_eq!(
        known.tables.advice_assigned(),
        unknown.tables.advice_assigned()
    );
}
