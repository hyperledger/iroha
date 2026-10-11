//! Send ownership and the exact policy/fee terms opened from its held state.

use super::{
    semantics::{credential, parse, policy_set, request_credit, request_set},
    *,
};
use iroha_kagemusha_proof::{
    operation_relation::{
        objects::{credential::CredentialCells, fee, policy::PolicyCells, request::RequestCells},
        state::{StateCells, rest_index as rest},
        statement::StatementCells,
    },
    witness::{CORE_FIELDS, REST_FIELDS, core_index as core},
};
use iroha_plonk_recursion::obligation::ledger::Variant;

#[derive(Clone)]
struct Send {
    request: ObjectCircuit,
    payer: ObjectCircuit,
    schedule: ObjectCircuit,
    core: [Fp; CORE_FIELDS],
    rest: [Fp; REST_FIELDS],
    statement: [Fp; 26],
    valid: bool,
}
impl Circuit<Fp> for Send {
    type Config = Config;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();
    fn without_witnesses(&self) -> Self {
        Self {
            request: self.request.without_witnesses(),
            payer: self.payer.without_witnesses(),
            schedule: self.schedule.without_witnesses(),
            ..self.clone()
        }
    }
    fn configure(meta: &mut ConstraintSystem<Fp>) -> Config {
        ObjectCircuit::configure(meta)
    }
    fn synthesize(&self, c: Config, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
        let mut glue = GlueChip::new(c.glue);
        let mut range = RunningSumChip::new(c.range);
        let mut hash = SpongeChip::new(c.hash);
        let mut bytes = BytesChip::new(c.bytes);
        range.load_table(&mut layouter)?;
        bytes.load_table(&mut layouter)?;
        let valid = layouter.assign_region(
            || "Send object bindings",
            |mut region| {
                let mut uint = UintChip::new(&mut glue, &mut range);
                let request = parse(&self.request, &mut bytes, &mut uint, &mut hash, &mut region)?;
                let payer = parse(&self.payer, &mut bytes, &mut uint, &mut hash, &mut region)?;
                let schedule = parse(
                    &self.schedule,
                    &mut bytes,
                    &mut uint,
                    &mut hash,
                    &mut region,
                )?;
                let request = RequestCells::check(&mut uint, &mut hash, &mut region, &request)?;
                let payer = CredentialCells::check(&mut uint, &mut region, &payer)?;
                let schedule = PolicyCells::check(&mut uint, &mut region, &schedule)?;
                let value = |v: &Fp| {
                    if self.request.known {
                        Value::known(*v)
                    } else {
                        Value::unknown()
                    }
                };
                let words = uint.glue().witnesses(
                    &mut region,
                    &self
                        .core
                        .iter()
                        .chain(&self.rest)
                        .chain(&self.statement)
                        .map(value)
                        .collect::<Vec<_>>(),
                )?;
                let state = StateCells::constrain(
                    &mut uint,
                    &mut hash,
                    &mut region,
                    &::core::array::from_fn(|i| words[i].clone()),
                    &::core::array::from_fn(|i| words[CORE_FIELDS + i].clone()),
                )?;
                let statement = StatementCells::constrain(
                    &mut uint,
                    &mut hash,
                    &mut region,
                    Variant::Send,
                    &::core::array::from_fn(|i| words[CORE_FIELDS + REST_FIELDS + i].clone()),
                )?;
                let ownership = request.bind_send(&mut uint, &mut region, &statement, &payer)?;
                let fee = fee::bind_send(&mut uint, &mut region, &request, &state, &schedule)?;
                uint.glue().and(&mut region, &ownership, &fee)
            },
        )?;
        layouter.constrain_instance(valid.word().cell(), c.public, 0)
    }
}
impl Send {
    fn public(&self) -> Vec<Fp> {
        let mut public = vec![Fp::ZERO; 8];
        public[0] = Fp::from(u64::from(self.valid));
        public
    }
    fn accepts(&self) -> bool {
        check_circuit(self, 13, &[self.public()], CheckMode::Strict).is_ok_and(|r| r.is_satisfied())
    }
    fn reject(mut self, reason: &str) {
        self.valid = false;
        assert!(self.accepts(), "total rejection: {reason}");
        self.valid = true;
        assert!(!self.accepts(), "forged acceptance: {reason}");
    }
    fn rebind_request(&mut self) {
        self.statement[17] = request_credit(&self.request);
        self.statement[23] = self.request.public(Fp::ZERO)[1];
        self.statement[7] = self.payer.public(Fp::ZERO)[1];
    }
}
fn words<const N: usize>(v: &Json) -> [Fp; N] {
    v.as_array()
        .expect("words")
        .iter()
        .map(|v| field(v.as_str().expect("hex")))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap_or_else(|_| panic!("{N} words"))
}
fn base() -> Send {
    let find = |kind| {
        cases()
            .into_iter()
            .find(|(c, ..)| c.kind == kind)
            .expect("object")
            .0
    };
    let j = fixture();
    let request = find(ObjectKind::Request);
    let schedule = find(ObjectKind::FeeSchedule);
    let mut c = Send {
        request,
        payer: credential(),
        schedule,
        core: words(&j["field_encodings"]["controlled_state"]["core_items"]),
        rest: words(&j["field_encodings"]["controlled_state"]["rest_items"]),
        statement: words(&j["field_encodings"]["send_statement"]["items"]),
        valid: true,
    };
    // The component opens a valid predecessor and checks its held policy. Its
    // authentication/state transition is covered by the operation relation.
    c.core[core::POLICY_EPOCH] = Fp::ONE;
    c.rest[rest::SCHEME_POLICY] = Fp::from_repr(
        c.request.bytes[314..346]
            .try_into()
            .expect("Request policy digest"),
    )
    .into_option()
    .expect("canonical digest");
    c.rest[rest::FEE_SCHEDULE] = c.schedule.public(Fp::ZERO)[1];
    c.rebind_request();
    c
}

#[test]
fn send_binds_payer_and_head_held_fees_with_no_receiver_signature_obligation() {
    let c = base();
    assert!(c.accepts(), "native vector terms");
    for offset in [2, 34, 66, 98] {
        let mut wrong = c.clone();
        wrong.payer.bytes[offset] ^= 1;
        wrong.rebind_request();
        wrong.reject("payer scope/wallet/account");
    }
    for i in [3, 4, 5, 6, 7, 17, 18, 19, 20, 21, 22, 23] {
        let mut wrong = c.clone();
        wrong.statement[i] += Fp::ONE;
        wrong.reject("statement field substitution");
    }
    let mut wrong = c.clone();
    // Rebind the exact Request and statement, so its changed fee cannot be
    // rejected merely for a stale Request digest.
    request_set(&mut wrong.request, 11, 7);
    wrong.statement[22] = Fp::from(7);
    wrong.rebind_request();
    wrong.reject("incorrect exact fee");
    for index in [10, 13] {
        let mut wrong = c.clone();
        request_set(&mut wrong.request, index, 1);
        wrong.rebind_request();
        wrong.reject("foreign fee schedule or same-epoch policy");
    }
    let mut future = c.clone();
    request_set(&mut future.request, 12, 2);
    future.rebind_request();
    future.reject("future policy epoch");
    let mut prior = c.clone();
    prior.core[core::POLICY_EPOCH] = Fp::from(2);
    prior.rest[rest::SCHEME_POLICY] += Fp::ONE;
    assert!(
        prior.accepts(),
        "older Request survives policy epoch advancement"
    );
    for (index, value) in [(1, 1), (2, 1), (5, 10_001), (9, 3)] {
        let mut wrong = c.clone();
        policy_set(&mut wrong.schedule, index, value);
        let digest = wrong.schedule.public(Fp::ZERO)[1];
        wrong.rest[rest::FEE_SCHEDULE] = digest;
        wrong.request.bytes[258..290].copy_from_slice(&digest.to_repr());
        wrong.rebind_request();
        wrong.reject("held fee object scope/body");
    }
    let known = synthesize(&c, 13, None).expect("known");
    let unknown = synthesize(&c.without_witnesses(), 13, None).expect("unknown");
    assert_eq!(known.tables.fixed(), unknown.tables.fixed());
    assert_eq!(known.tables.permutation(), unknown.tables.permutation());
}

#[test]
fn absent_fee_policy_forces_zero_and_ignores_malformed_unused_slot() {
    let mut c = base();
    c.core[core::POLICY_EPOCH] = Fp::ZERO;
    c.core[core::ENABLED_CONTROLS] = Fp::ZERO;
    c.rest[rest::SCHEME_POLICY] = Fp::ZERO;
    c.rest[rest::FEE_SCHEDULE] = Fp::ZERO;
    for index in [10, 11, 12, 13] {
        request_set(&mut c.request, index, 0);
    }
    c.statement[22] = Fp::ZERO;
    c.schedule.bytes[0] = 9;
    policy_set(&mut c.schedule, 5, u128::from(u32::MAX));
    c.rebind_request();
    assert!(c.accepts());
    request_set(&mut c.request, 10, 1);
    request_set(&mut c.request, 11, 1);
    c.statement[22] = Fp::ONE;
    c.rebind_request();
    c.reject("fee introduced without held schedule");
}
