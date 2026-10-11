//! Total credential predicates and exact provider-receipt derived fields.

use super::*;
use iroha_kagemusha_proof::operation_relation::{
    incoming_statement::{DynamicStatementCells, IncomingStatementCells},
    objects::{
        credential::CredentialCells,
        receipt::{self, ReceiptContext},
    },
};
use iroha_plonk::frontend::Region;
use iroha_plonk_gadgets::Word;
use iroha_plonk_recursion::obligation::ledger::Variant;

const CREDENTIAL_WIDTHS: [usize; 29] = [
    2, 32, 32, 32, 32, 65, 32, 1, 32, 8, 4, 4, 4, 4, 32, 8, 4, 4, 4, 4, 32, 4, 8, 8, 32, 8, 4, 8,
    32,
];
fn set(c: &mut ObjectCircuit, index: usize, value: u64) {
    let start: usize = CREDENTIAL_WIDTHS[..index].iter().sum();
    let length = CREDENTIAL_WIDTHS[index];
    c.bytes[start..start + length].fill(0);
    let n = length.min(8);
    c.bytes[start..start + n].copy_from_slice(&value.to_le_bytes()[..n]);
}
pub fn credential() -> ObjectCircuit {
    let mut c = cases()
        .into_iter()
        .find(|(c, ..)| c.kind == ObjectKind::Credential)
        .expect("credential")
        .0;
    c.soft = true;
    c.body_check = BodyCheck::Semantic;
    c
}
fn invalid(mut c: ObjectCircuit, message: &str) {
    c.valid = false;
    assert!(c.accepts(Fp::ZERO), "total false: {message}");
    c.valid = true;
    assert!(!c.accepts(Fp::ZERO), "forged true: {message}");
}
#[test]
fn credential_evidence_and_policy_rules_return_total_verdicts() {
    let c = credential();
    assert!(c.accepts(Fp::ZERO));
    for (index, value, reason) in [
        (7, 0, "missing evidence kind"),
        (7, 4, "foreign evidence kind"),
        (7, 2, "StrongBox kind without its fact"),
        (7, 3, "Apple kind with Android facts"),
        (10, 1087, "TEE claiming StrongBox"),
        (10, 1084, "missing hardware fact"),
        (10, 1085 | (1 << 6), "Android claiming Apple"),
        (10, 1085 | (1 << 12), "undefined fact"),
        (16, 1 << 31, "undefined fresh fact"),
        (15, 1, "fresh time before enrollment"),
        (16, 0, "first credential fresh record differs"),
        (21, 8, "undefined control"),
        (22, 1, "age without blacklist"),
        (23, 1, "response with no time rule"),
        (27, 1, "lease without permission"),
        (21, 2, "quota without response"),
        (21, 4, "lease without response/expiry"),
    ] {
        let mut wrong = c.clone();
        set(&mut wrong, index, value);
        invalid(wrong, reason);
    }
    for index in [1, 2, 3, 4, 8, 14, 20, 24, 28] {
        let mut wrong = c.clone();
        set(&mut wrong, index, 0);
        invalid(wrong, "zero binding");
    }
    let mut renewed = c.clone();
    set(&mut renewed, 26, 1);
    set(&mut renewed, 16, 0); // Required enrollment facts are not invented for fresh evidence.
    assert!(renewed.accepts(Fp::ZERO));
    let mut controlled = c.clone();
    for (index, value) in [(21, 7), (22, 100), (23, 5), (27, 1000)] {
        set(&mut controlled, index, value);
    }
    assert!(controlled.accepts(Fp::ZERO));
    let mut strongbox = c.clone();
    set(&mut strongbox, 7, 2);
    set(&mut strongbox, 10, 1087);
    set(&mut strongbox, 16, 1087);
    assert!(strongbox.accepts(Fp::ZERO));
    let mut apple = c.clone();
    for (index, value) in [
        (7, 3),
        (10, 192),
        (16, 192),
        (11, 0),
        (12, 0),
        (13, 0),
        (17, 0),
        (18, 0),
        (19, 0),
    ] {
        set(&mut apple, index, value);
    }
    assert!(apple.accepts(Fp::ZERO));
    set(&mut apple, 18, 1);
    invalid(apple, "Apple patch claim");
    let known = synthesize(&c, 12, Some(&[c.public(Fp::ZERO)])).expect("known");
    let unknown = synthesize(&c.without_witnesses(), 12, None).expect("unknown");
    assert_eq!(known.tables.fixed(), unknown.tables.fixed());
    assert_eq!(known.tables.permutation(), unknown.tables.permutation());
}

pub fn parse(
    c: &ObjectCircuit,
    bytes: &mut BytesChip<Fp>,
    uint: &mut UintChip<'_, Fp>,
    hash: &mut SpongeChip<Fp>,
    region: &mut Region<'_, Fp>,
) -> Result<SignedObjectCells, Error> {
    let values = c
        .bytes
        .iter()
        .map(|b| {
            if c.known {
                Value::known(*b)
            } else {
                Value::unknown()
            }
        })
        .collect::<Vec<_>>();
    let run = bytes.run(
        region,
        &values,
        &c.kind.primary_segments(),
        &c.kind.secondary_segments(),
    )?;
    SignedObjectCells::decode_soft(uint, hash, region, c.kind, &run).map(|(object, _)| object)
}

#[derive(Clone)]
struct Renewal {
    before: ObjectCircuit,
    after: ObjectCircuit,
    valid: bool,
}
impl Circuit<Fp> for Renewal {
    type Config = Config;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();
    fn without_witnesses(&self) -> Self {
        Self {
            before: self.before.without_witnesses(),
            after: self.after.without_witnesses(),
            valid: self.valid,
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
            || "renewal",
            |mut region| {
                let mut uint = UintChip::new(&mut glue, &mut range);
                let before = parse(&self.before, &mut bytes, &mut uint, &mut hash, &mut region)?;
                let after = parse(&self.after, &mut bytes, &mut uint, &mut hash, &mut region)?;
                let before = CredentialCells::check(&mut uint, &mut region, &before)?;
                let after = CredentialCells::check(&mut uint, &mut region, &after)?;
                after.replacement_of(&mut uint, &mut region, &before)
            },
        )?;
        layouter.constrain_instance(valid.word().cell(), c.public, 0)
    }
}
impl Renewal {
    fn public(&self) -> Vec<Fp> {
        let mut p = vec![Fp::ZERO; 8];
        p[0] = Fp::from(u64::from(self.valid));
        p
    }
    fn accepts(&self) -> bool {
        check_circuit(self, 13, &[self.public()], CheckMode::Strict).is_ok_and(|r| r.is_satisfied())
    }
}
#[test]
fn renewal_keeps_every_immutable_field_and_cannot_wrap_counter() {
    let before = credential();
    let mut after = before.clone();
    set(&mut after, 26, 1);
    let c = Renewal {
        before,
        after,
        valid: true,
    };
    assert!(c.accepts());
    for index in [1, 2, 3, 4, 5, 6, 8, 9, 11, 12, 13, 20, 24] {
        let mut wrong = c.clone();
        let start: usize = CREDENTIAL_WIDTHS[..index].iter().sum();
        wrong.after.bytes[start + usize::from(index == 5)] ^= 1;
        wrong.valid = false;
        assert!(wrong.accepts(), "total replacement mismatch {index}");
        wrong.valid = true;
        assert!(!wrong.accepts(), "replacement mismatch {index}");
    }
    let mut changed = c.clone();
    for (index, value) in [
        (14, 9),
        (15, 1_790_000_001_000),
        (16, 0),
        (25, 1_790_000_002_000),
        (28, 10),
    ] {
        set(&mut changed.after, index, value);
    }
    assert!(changed.accepts());
    let mut wrapped = c.clone();
    set(&mut wrapped.before, 26, u64::from(u32::MAX));
    set(&mut wrapped.after, 26, 0);
    wrapped.valid = false;
    assert!(wrapped.accepts());
    wrapped.valid = true;
    assert!(!wrapped.accepts());
}

#[derive(Clone)]
struct Receipt {
    object: ObjectCircuit,
    variant: Variant,
    statement: [Fp; 26],
    context: [Fp; 6], // wallet2, provider2, proof, Payment
    valid: bool,
    dynamic: bool,
}
impl Circuit<Fp> for Receipt {
    type Config = Config;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();
    fn without_witnesses(&self) -> Self {
        Self {
            object: self.object.without_witnesses(),
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
            || "receipt",
            |mut region| {
                let mut uint = UintChip::new(&mut glue, &mut range);
                let object = parse(&self.object, &mut bytes, &mut uint, &mut hash, &mut region)?;
                let value = |v: &Fp| {
                    if self.object.known {
                        Value::known(*v)
                    } else {
                        Value::unknown()
                    }
                };
                let fields: [Word<Fp>; 26] = uint
                    .glue()
                    .witnesses(
                        &mut region,
                        &self.statement.iter().map(value).collect::<Vec<_>>(),
                    )?
                    .try_into()
                    .map_err(|_| Error::Synthesis)?;
                let context = uint.glue().witnesses(
                    &mut region,
                    &self.context.iter().map(value).collect::<Vec<_>>(),
                )?;
                if self.dynamic {
                    let statement = DynamicStatementCells::constrain(
                        &mut uint,
                        &mut hash,
                        &mut region,
                        &fields,
                    )?;
                    return receipt::bind_dynamic(
                        &mut uint,
                        &mut hash,
                        &mut region,
                        &object,
                        &ReceiptContext {
                            wallet: &[context[0].clone(), context[1].clone()],
                            provider: &[context[2].clone(), context[3].clone()],
                            statement: &statement,
                            proof_digest: &context[4],
                            payment_digest: &context[5],
                        },
                    );
                }
                let statement = IncomingStatementCells::constrain(
                    &mut uint,
                    &mut hash,
                    &mut region,
                    self.variant,
                    &fields,
                )?;
                receipt::bind(
                    &mut uint,
                    &mut hash,
                    &mut region,
                    &object,
                    &ReceiptContext {
                        wallet: &[context[0].clone(), context[1].clone()],
                        provider: &[context[2].clone(), context[3].clone()],
                        statement: &statement,
                        proof_digest: &context[4],
                        payment_digest: &context[5],
                    },
                )
            },
        )?;
        layouter.constrain_instance(valid.word().cell(), c.public, 0)
    }
}
impl Receipt {
    fn accepts(&self) -> bool {
        let mut p = vec![Fp::ZERO; 8];
        p[0] = Fp::from(u64::from(self.valid));
        check_circuit(
            self,
            if self.dynamic { 13 } else { 12 },
            &[p],
            CheckMode::Strict,
        )
        .is_ok_and(|r| r.is_satisfied())
    }
}

#[test]
fn status_receipt_projects_every_head_kind_without_witness_dependent_layout() {
    let object = cases()
        .into_iter()
        .find(|(_, _, name, _)| name == "Send receipt")
        .expect("receipt")
        .0;
    let statement: [Fp; 26] = fixture()["field_encodings"]["send_statement"]["items"]
        .as_array()
        .expect("fields")
        .iter()
        .map(|v| field(v.as_str().expect("hex")))
        .collect::<Vec<_>>()
        .try_into()
        .expect("26");
    let half = |offset| {
        Fp::from_u128(u128::from_le_bytes(
            object.bytes[offset..offset + 16].try_into().expect("half"),
        ))
    };
    let context = [
        half(34),
        half(50),
        half(66),
        half(82),
        Fp::from(99),
        Fp::ZERO,
    ];
    let base = Receipt {
        object,
        statement,
        context,
        variant: Variant::Send,
        valid: true,
        dynamic: true,
    };
    let mut layout = None;
    for variant in Variant::ALL {
        let mut c = base.clone();
        c.variant = variant;
        let f = &mut c.statement;
        if !matches!(variant, Variant::Send | Variant::Unload | Variant::Retiring) {
            f[12..14].fill(Fp::ZERO);
        }
        if variant == Variant::Bootstrap {
            for i in [9, 10, 11, 14] {
                f[i] = Fp::ZERO;
            }
        }
        f[16..].fill(Fp::ZERO);
        let (tag, effect): (u64, Vec<Fp>) = match variant {
            Variant::Bootstrap => (1, vec![1, 2, 3, 4].into_iter().map(Fp::from).collect()),
            Variant::Load => {
                f[10] = Fp::from(3);
                (2, vec![10, 2, 4, 5].into_iter().map(Fp::from).collect())
            }
            Variant::Send => (
                3,
                vec![10, 20, 30, 4, 100, 2, 40, 1000, 1001]
                    .into_iter()
                    .map(Fp::from)
                    .collect(),
            ),
            Variant::Receive | Variant::ReceiveRenewed => {
                (4, vec![10, 20, 30, 100].into_iter().map(Fp::from).collect())
            }
            Variant::ArchiveReceive | Variant::ArchiveStatus => {
                (5, vec![10, 20].into_iter().map(Fp::from).collect())
            }
            Variant::Unload => (6, vec![10, 2, 4, 1, 20].into_iter().map(Fp::from).collect()),
            Variant::Retiring => {
                f[8] = Fp::from(2);
                (8, vec![])
            }
            _ => {
                let kind = match variant {
                    Variant::RefreshCredential => 1,
                    Variant::RefreshSchemePolicy => 2,
                    Variant::RefreshBlacklist => 3,
                    Variant::RefreshQuotaShare => 4,
                    Variant::RefreshTimeAnchor => 5,
                    _ => unreachable!(),
                };
                (
                    7,
                    vec![
                        Fp::from(kind),
                        if kind == 1 { f[7] } else { Fp::from(20) },
                        Fp::from(2),
                    ],
                )
            }
        };
        f[16] = Fp::from(tag);
        f[17..17 + effect.len()].copy_from_slice(&effect);
        c.context[5] = if tag == 4 { Fp::from(77) } else { Fp::ZERO };
        let mut operation = c.context[..2].to_vec();
        operation.push(f[16]);
        match tag {
            1 => operation.extend_from_slice(&f[17..19]),
            5 | 7 => operation.push(f[18]),
            8 => operation.push(Fp::ZERO),
            _ => operation.push(f[17]),
        }
        let operation = hash_with_domain(u64::from_le_bytes(*b"kgwopid1"), &operation);
        for (offset, value) in [
            (114, operation),
            (146, f[14]),
            (178, f[15]),
            (210, hash_with_domain(u64::from_le_bytes(*b"kgwstmt1"), f)),
            (242, c.context[4]),
            (306, c.context[5]),
        ] {
            c.object.bytes[offset..offset + 32].copy_from_slice(&value.to_repr());
        }
        c.object.bytes[98..114].copy_from_slice(&f[9].to_repr()[..16]);
        assert!(c.accepts(), "dynamic receipt {variant:?}");
        let known = synthesize(&c, 13, None).expect("known");
        if let Some((fixed, copies)) = &layout {
            assert_eq!(known.tables.fixed(), fixed);
            assert_eq!(known.tables.permutation(), copies);
        } else {
            layout = Some((
                known.tables.fixed().to_vec(),
                known.tables.permutation().clone(),
            ));
        }
        for offset in [114, 210, 306] {
            let mut wrong = c.clone();
            wrong.object.bytes[offset] ^= 1;
            wrong.valid = false;
            assert!(
                wrong.accepts(),
                "total dynamic receipt {variant:?} {offset}"
            );
            wrong.valid = true;
            assert!(!wrong.accepts());
        }
        let mut wrong = c.clone();
        wrong.statement[16] = Fp::from(99);
        wrong.object.bytes[210..242].copy_from_slice(
            &hash_with_domain(u64::from_le_bytes(*b"kgwstmt1"), &wrong.statement).to_repr(),
        );
        wrong.valid = false;
        assert!(wrong.accepts());
        wrong.valid = true;
        assert!(!wrong.accepts());
    }
}
#[test]
fn receipt_bindings_match_send_and_receive_vectors_and_reject_every_substitution() {
    for (name, variant, statement_name) in [
        ("Send receipt", Variant::Send, "send_statement"),
        (
            "Receive receipt binding the Payment digest",
            Variant::Receive,
            "receive_statement",
        ),
    ] {
        let object = cases()
            .into_iter()
            .find(|(_, _, object, _)| object == name)
            .expect("receipt")
            .0;
        let j = fixture();
        let statement = j["field_encodings"][statement_name]["items"]
            .as_array()
            .expect("items")
            .iter()
            .map(|v| field(v.as_str().expect("field")))
            .collect::<Vec<_>>()
            .try_into()
            .expect("26");
        let half = |start| {
            Fp::from_u128(u128::from_le_bytes(
                object.bytes[start..start + 16].try_into().expect("half"),
            ))
        };
        let canonical = |start| {
            Fp::from_repr(object.bytes[start..start + 32].try_into().expect("32"))
                .into_option()
                .expect("canonical")
        };
        let context = [
            half(34),
            half(50),
            half(66),
            half(82),
            canonical(242),
            canonical(306),
        ];
        let c = Receipt {
            object,
            variant,
            statement,
            context,
            valid: true,
            dynamic: false,
        };
        assert!(c.accepts(), "{name}");
        // First byte of each derived field; capsule and proof special cases below.
        for offset in [0, 2, 34, 66, 98, 114, 146, 178, 210, 242, 306] {
            let mut wrong = c.clone();
            wrong.object.bytes[offset] ^= 1;
            wrong.valid = false;
            assert!(wrong.accepts(), "total {name} {offset}");
            wrong.valid = true;
            assert!(!wrong.accepts(), "forged {name} {offset}");
        }
        let mut zero = c.clone();
        zero.object.bytes[274..306].fill(0);
        zero.valid = false;
        assert!(zero.accepts());
        zero.valid = true;
        assert!(!zero.accepts());
        for i in 0..6 {
            let mut wrong = c.clone();
            wrong.context[i] += Fp::ONE;
            wrong.valid = false;
            assert!(wrong.accepts());
            wrong.valid = true;
            assert!(!wrong.accepts());
        }
        // Semantic and width failures in an incoming statement must remain
        // provable as false, so the corrected-claim burn/no-op branch can run.
        for i in [0, 1, 8, 9, 11, 16, 19] {
            let mut wrong = c.clone();
            wrong.statement[i] = -Fp::ONE;
            wrong.valid = false;
            assert!(wrong.accepts(), "soft incoming {name} field{i}");
            wrong.valid = true;
            assert!(!wrong.accepts(), "forged incoming {name} field{i}");
        }
        for i in [0, 8, 11, 25] {
            let mut wrong = c.clone();
            wrong.statement[i] = -Fp::ONE;
            // Keep every derived receipt field consistent with the malformed
            // statement; only its own mandatory semantic verdict rejects it.
            let digest = hash_with_domain(u64::from_le_bytes(*b"kgwstmt1"), &wrong.statement);
            wrong.object.bytes[210..242].copy_from_slice(&digest.to_repr());
            wrong.valid = false;
            assert!(
                wrong.accepts(),
                "consistent malformed receipt {name} field{i}"
            );
            wrong.valid = true;
            assert!(
                !wrong.accepts(),
                "omitted statement verdict {name} field{i}"
            );
        }
    }
}

const REQUEST_WIDTHS: [usize; 19] = [
    2, 32, 32, 32, 32, 32, 32, 16, 32, 16, 32, 16, 8, 32, 8, 8, 32, 32, 32,
];
pub fn request_set(c: &mut ObjectCircuit, index: usize, value: u128) {
    let offset: usize = REQUEST_WIDTHS[..index].iter().sum();
    let n = REQUEST_WIDTHS[index];
    c.bytes[offset..offset + n].fill(0);
    let written = n.min(16);
    c.bytes[offset..offset + written].copy_from_slice(&value.to_le_bytes()[..written]);
}
pub fn request_credit(c: &ObjectCircuit) -> Fp {
    let mut offset = 0;
    let mut words = Vec::new();
    for (index, n) in REQUEST_WIDTHS.into_iter().enumerate() {
        let b = &c.bytes[offset..offset + n];
        if [8, 10, 13, 16, 17].contains(&index) {
            words.push(
                Fp::from_repr(b.try_into().expect("field"))
                    .into_option()
                    .unwrap_or(Fp::ZERO),
            );
        } else if n == 32 {
            words.push(Fp::from_u128(u128::from_le_bytes(
                b[..16].try_into().expect("lo"),
            )));
            words.push(Fp::from_u128(u128::from_le_bytes(
                b[16..].try_into().expect("hi"),
            )));
        } else {
            let mut integer = [0_u8; 16];
            integer[..n].copy_from_slice(b);
            words.push(Fp::from_u128(u128::from_le_bytes(integer)));
        }
        offset += n;
    }
    hash_with_domain(u64::from_le_bytes(*b"kgwcrdt1"), &words)
}
#[test]
fn request_body_overflow_pairs_and_identity_checks_are_total() {
    let mut c = cases()
        .into_iter()
        .find(|(c, ..)| c.kind == ObjectKind::Request)
        .expect("request")
        .0;
    c.soft = true;
    c.body_check = BodyCheck::Semantic;
    assert!(c.accepts(request_credit(&c)));
    for index in [1, 2, 3, 4, 5, 6, 8, 9, 17, 18] {
        let mut wrong = c.clone();
        request_set(&mut wrong, index, 0);
        wrong.valid = false;
        assert!(wrong.accepts(request_credit(&wrong)), "total zero {index}");
        wrong.valid = true;
        assert!(
            !wrong.accepts(request_credit(&wrong)),
            "forged zero {index}"
        );
    }
    for changes in [
        vec![(10, 0), (11, 1)],
        vec![(12, 0), (13, 1)],
        vec![(12, 1), (13, 0)],
        vec![(15, 0), (16, 1)],
        vec![(15, 1), (16, 0)],
        vec![(9, u128::MAX), (11, 1)],
    ] {
        let mut wrong = c.clone();
        for (i, v) in changes {
            request_set(&mut wrong, i, v);
        }
        wrong.valid = false;
        assert!(wrong.accepts(request_credit(&wrong)));
        wrong.valid = true;
        assert!(!wrong.accepts(request_credit(&wrong)));
    }
    let mut same = c.clone();
    let payer: usize = REQUEST_WIDTHS[..3].iter().sum();
    let receiver: usize = REQUEST_WIDTHS[..5].iter().sum();
    let source = same.bytes[payer..payer + 32].to_vec();
    same.bytes[receiver..receiver + 32].copy_from_slice(&source);
    same.valid = false;
    assert!(same.accepts(request_credit(&same)));
    same.valid = true;
    assert!(!same.accepts(request_credit(&same)));
    for max in [u128::MAX, u128::MAX - 1] {
        let mut boundary = c.clone();
        request_set(&mut boundary, 9, max);
        request_set(&mut boundary, 11, u128::MAX - max);
        assert!(boundary.accepts(request_credit(&boundary)));
    }
    let mut free = c.clone();
    for i in [10, 11, 12, 13, 15, 16] {
        request_set(&mut free, i, 0);
    }
    assert!(free.accepts(request_credit(&free)));
}

pub fn policy_set(c: &mut ObjectCircuit, index: usize, value: u128) {
    let widths: &[usize] = match c.kind {
        ObjectKind::SchemePolicy => &[2, 32, 32, 8, 4, 32, 32],
        ObjectKind::FeeSchedule => &[2, 32, 32, 8, 32, 4, 16, 16, 16, 1, 32],
        ObjectKind::Blacklist => &[2, 32, 8, 8, 4, 32, 32],
        ObjectKind::QuotaShare => &[2, 32, 32, 32, 8, 8, 8, 32, 4, 32],
        ObjectKind::TimeAnchor => &[2, 32, 32, 32, 8, 32],
        ObjectKind::ChargeQuote => &[2, 32, 32, 32, 1, 16, 16, 16, 32, 8, 32],
        _ => panic!("fixed policy"),
    };
    let offset: usize = widths[..index].iter().sum();
    let n = widths[index];
    c.bytes[offset..offset + n].fill(0);
    let written = n.min(16);
    c.bytes[offset..offset + written].copy_from_slice(&value.to_le_bytes()[..written]);
}
#[test]
fn issuer_body_rules_match_native_bounds_and_have_total_false_paths() {
    for (mut c, _, name, _) in cases() {
        if matches!(
            c.kind,
            ObjectKind::Certificate
                | ObjectKind::Credential
                | ObjectKind::Receipt
                | ObjectKind::Request
        ) {
            continue;
        }
        c.soft = true;
        c.body_check = BodyCheck::Semantic;
        assert!(c.accepts(Fp::ZERO), "{name}");
        let attacks: &[(usize, u128)] = match c.kind {
            ObjectKind::SchemePolicy => &[(1, 0), (2, 0), (3, 0), (4, 8), (6, 0)],
            ObjectKind::FeeSchedule => &[
                (1, 0),
                (2, 0),
                (4, 0),
                (5, 10_001),
                (7, u128::MAX),
                (9, 0),
                (9, 3),
                (10, 0),
            ],
            ObjectKind::Blacklist => &[(1, 0), (2, 0), (4, 65_536), (5, 0), (6, 0)],
            ObjectKind::QuotaShare => &[
                (1, 0),
                (2, 0),
                (3, 0),
                (4, 0),
                (6, 0),
                (7, 0),
                (8, 0),
                (8, 65),
                (9, 0),
            ],
            ObjectKind::TimeAnchor => &[(1, 0), (2, 0), (3, 0), (5, 0)],
            ObjectKind::ChargeQuote => &[
                (1, 0),
                (2, 0),
                (3, 0),
                (4, 0),
                (4, 3),
                (6, u128::MAX),
                (7, 0),
                (8, 0),
                (10, 0),
            ],
            _ => unreachable!(),
        };
        for (index, value) in attacks {
            let mut wrong = c.clone();
            policy_set(&mut wrong, *index, *value);
            invalid(wrong, &format!("{name} field{index}"));
        }
        if c.kind == ObjectKind::ChargeQuote {
            let mut unload = c.clone();
            policy_set(&mut unload, 4, 2);
            policy_set(&mut unload, 6, 10);
            policy_set(&mut unload, 7, 10);
            assert!(unload.accepts(Fp::ZERO));
            policy_set(&mut unload, 7, 11);
            invalid(unload, "quote exceeds redemption");
        }
    }
}

#[derive(Clone)]
struct Fee {
    object: ObjectCircuit,
    amount: u128,
    expected: u128,
    valid: bool,
}
impl Circuit<Fp> for Fee {
    type Config = Config;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();
    fn without_witnesses(&self) -> Self {
        Self {
            object: self.object.without_witnesses(),
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
        let output = layouter.assign_region(
            || "fee",
            |mut region| {
                let mut uint = UintChip::new(&mut glue, &mut range);
                let object = parse(&self.object, &mut bytes, &mut uint, &mut hash, &mut region)?;
                let policy =
                    iroha_kagemusha_proof::operation_relation::objects::policy::PolicyCells::check(
                        &mut uint,
                        &mut region,
                        &object,
                    )?;
                let amount = uint.assign::<128>(
                    &mut region,
                    if self.object.known {
                        Value::known(self.amount)
                    } else {
                        Value::unknown()
                    },
                )?;
                let fee =
                    iroha_kagemusha_proof::operation_relation::objects::fee::FeeCells::compute(
                        &mut uint,
                        &mut region,
                        &policy,
                        amount.word(),
                    )?;
                Ok([
                    amount.word().clone(),
                    fee.amount().clone(),
                    fee.valid().word().clone(),
                ])
            },
        )?;
        for (i, word) in output.iter().enumerate() {
            layouter.constrain_instance(word.cell(), c.public, i)?;
        }
        Ok(())
    }
}
impl Fee {
    fn public(&self) -> Vec<Fp> {
        let mut p = vec![Fp::ZERO; 8];
        p[0] = Fp::from_u128(self.amount);
        p[1] = Fp::from_u128(self.expected);
        p[2] = Fp::from(u64::from(self.valid));
        p
    }
    fn accepts(&self) -> bool {
        check_circuit(self, 12, &[self.public()], CheckMode::Strict).is_ok_and(|r| r.is_satisfied())
    }
}
#[test]
fn exact_fee_rounding_clamps_and_preclamp_overflow_are_bound() {
    let object = cases()
        .into_iter()
        .find(|(c, ..)| c.kind == ObjectKind::FeeSchedule)
        .expect("fee")
        .0;
    for (amount, bp, fixed, min, max, rounding, expected, valid) in [
        (100, 300, 2, 0, u128::MAX, 1, 5, true),
        (1, 1, 0, 0, u128::MAX, 1, 0, true),
        (1, 1, 0, 0, u128::MAX, 2, 1, true),
        (99_999, 3333, 7, 0, u128::MAX, 1, 33_336, true),
        (99_999, 3333, 7, 0, u128::MAX, 2, 33_337, true),
        (100, 0, 0, 3, 7, 1, 3, true),
        (100, 10_000, 0, 3, 7, 1, 7, true),
        (u128::MAX, 10_000, 0, 0, u128::MAX, 2, u128::MAX, true),
        (u128::MAX, 10_000, 1, 0, 0, 1, 0, false),
        (u128::MAX, 10_001, 0, 0, u128::MAX, 1, 0, false),
    ] {
        let mut c = Fee {
            object: object.clone(),
            amount,
            expected,
            valid,
        };
        for (i, v) in [(5, bp), (6, fixed), (7, min), (8, max), (9, rounding)] {
            policy_set(&mut c.object, i, v);
        }
        assert!(
            c.accepts(),
            "fee {amount} {bp} {rounding} {expected} {valid}"
        );
        let mut wrong = c.clone();
        wrong.expected ^= 1;
        assert!(!wrong.accepts(), "substitutefee");
        wrong = c.clone();
        wrong.valid = !valid;
        assert!(!wrong.accepts(), "substitutestatus");
        let known = synthesize(&c, 12, Some(&[c.public()])).expect("known");
        let unknown = synthesize(&c.without_witnesses(), 12, None).expect("unknown");
        assert_eq!(known.tables.fixed(), unknown.tables.fixed());
        assert_eq!(known.tables.permutation(), unknown.tables.permutation());
    }
}
