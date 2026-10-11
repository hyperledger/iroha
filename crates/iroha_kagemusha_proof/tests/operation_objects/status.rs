//! Delivery transcript vectors and folded-head identity/substitution cases.

use super::{
    semantics::{credential, parse},
    *,
};
use iroha_kagemusha_proof::{
    a_relation::LineagePublicCells,
    operation_relation::{
        incoming_statement::{DynamicStatementCells, IncomingStatementCells},
        objects::{
            credential::CredentialCells,
            credit_opening::CreditOpeningCells,
            request::RequestCells,
            status::{
                CreditedCells, EvidenceKind, ReceiveEvidenceCells, ReceiveEvidenceInputs,
                StatusCells, StatusInputs,
            },
        },
    },
    tree::{INDEXED_LEAF_DOMAIN, INDEXED_NODE_DOMAIN, path_root},
};

#[derive(Clone)]
struct Credited {
    tape: Vec<u8>,
    kind: EvidenceKind,
    expected: [Fp; 3],
    valid: bool,
    known: bool,
}
impl Circuit<Fp> for Credited {
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
        ObjectCircuit::configure(meta)
    }
    fn synthesize(&self, c: Config, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
        let mut glue = GlueChip::new(c.glue);
        let mut range = RunningSumChip::new(c.range);
        let mut hash = SpongeChip::new(c.hash);
        let mut bytes = BytesChip::new(c.bytes);
        range.load_table(&mut layouter)?;
        bytes.load_table(&mut layouter)?;
        let result = layouter.assign_region(
            || "Credited transcript",
            |mut region| {
                let run = bytes.run(
                    &mut region,
                    &self
                        .tape
                        .iter()
                        .map(|b| value(self.known, *b))
                        .collect::<Vec<_>>(),
                    &CreditedCells::primary_segments(),
                    &CreditedCells::secondary_segments(),
                )?;
                let expected = glue
                    .witnesses(
                        &mut region,
                        &self
                            .expected
                            .iter()
                            .map(|f| value(self.known, *f))
                            .collect::<Vec<_>>(),
                    )?
                    .try_into()
                    .map_err(|_| Error::Synthesis)?;
                let credited = CreditedCells::from_run(
                    &mut UintChip::new(&mut glue, &mut range),
                    &mut hash,
                    &mut region,
                    &run,
                    self.kind,
                    &expected,
                )?;
                Ok([credited.digest().clone(), credited.valid().word().clone()])
            },
        )?;
        for (i, word) in result.iter().enumerate() {
            layouter.constrain_instance(word.cell(), c.public, i)?;
        }
        Ok(())
    }
}
fn value<T: Copy>(known: bool, v: T) -> Value<T> {
    if known {
        Value::known(v)
    } else {
        Value::unknown()
    }
}
fn field_at(tape: &[u8], offset: usize) -> Fp {
    Fp::from_repr(tape[offset..offset + 32].try_into().expect("field"))
        .into_option()
        .expect("canonical")
}
fn half_at(tape: &[u8], offset: usize) -> Fp {
    Fp::from_u128(u128::from_le_bytes(
        tape[offset..offset + 16].try_into().expect("half"),
    ))
}
impl Credited {
    fn public(&self) -> Vec<Fp> {
        let mut out = vec![Fp::ZERO; 8];
        out[0] = p_bytes_native(u64::from_le_bytes(*b"kgwcrdd1"), &self.tape);
        out[1] = Fp::from(u64::from(self.valid));
        out
    }
    fn accepts(&self) -> bool {
        check_circuit(self, 12, &[self.public()], CheckMode::Strict).is_ok_and(|r| r.is_satisfied())
    }
    fn rejects(mut self) {
        self.valid = false;
        assert!(self.accepts());
        self.valid = true;
        assert!(!self.accepts());
    }
    fn rejects_preimage(mut self) {
        for verdict in [false, true] {
            self.valid = verdict;
            assert!(
                !self.accepts(),
                "a substituted preimage cannot choose {verdict}"
            );
        }
    }
}
#[test]
fn credited_forms_match_native_vectors_and_bind_every_original_byte() {
    for row in fixture()["poseidon"]["large_input_digests"]
        .as_array()
        .expect("digests")
        .iter()
        .filter(|r| r["domain"].as_str() == Some("kgwcrdd1"))
    {
        let tape = decode(row["body_hex"].as_str().expect("bytes"));
        let c = Credited {
            expected: [field_at(&tape, 3), field_at(&tape, 35), field_at(&tape, 67)],
            kind: if tape[2] == 1 {
                EvidenceKind::Receive
            } else {
                EvidenceKind::Status
            },
            tape,
            valid: true,
            known: true,
        };
        assert_eq!(
            c.public()[0],
            field(row["digest_hex"].as_str().expect("digest"))
        );
        assert!(c.accepts());
        for i in 0..CreditedCells::BYTES {
            let mut wrong = c.clone();
            wrong.tape[i] ^= 1;
            let start = if i < 67 { 35 } else { 67 };
            if i >= 35
                && bool::from(
                    Fp::from_repr(wrong.tape[start..start + 32].try_into().unwrap()).is_some(),
                )
            {
                wrong.rejects_preimage();
            } else {
                wrong.rejects();
            }
        }
        for i in 0..3 {
            let mut wrong = c.clone();
            wrong.expected[i] += Fp::ONE;
            if i == 0 {
                wrong.rejects();
            } else {
                wrong.rejects_preimage();
            }
        }
        for at in [3, 35, 67] {
            let mut wrong = c.clone();
            wrong.tape[at..at + 32].fill(255);
            wrong.rejects();
        }
        let known = synthesize(&c, 12, None).expect("known");
        let unknown = synthesize(&c.without_witnesses(), 12, None).expect("unknown");
        assert_eq!(known.tables.fixed(), unknown.tables.fixed());
        assert_eq!(known.tables.permutation(), unknown.tables.permutation());
    }
}

#[derive(Clone)]
struct Status {
    request: ObjectCircuit,
    receiver: ObjectCircuit,
    receipt: ObjectCircuit,
    statement: [Fp; 26],
    head: [Fp; 18],
    opening: Vec<u8>,
    tape: Vec<u8>,
    context: [Fp; 7], // provider halves, proof, lineage-byte digest, Payment, expected relation halves
    valid: bool,
    receive: bool,
    decode_carried_proof: bool,
}
impl Circuit<Fp> for Status {
    type Config = Config;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();
    fn without_witnesses(&self) -> Self {
        Self {
            request: self.request.without_witnesses(),
            receiver: self.receiver.without_witnesses(),
            receipt: self.receipt.without_witnesses(),
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
        let result = layouter.assign_region(
            || "CreditStatus exact components",
            |mut region| {
                let known = self.request.known;
                let opening = bytes.run(
                    &mut region,
                    &self
                        .opening
                        .iter()
                        .map(|b| value(known, *b))
                        .collect::<Vec<_>>(),
                    &CreditOpeningCells::primary_segments(),
                    &CreditOpeningCells::secondary_segments(),
                )?;
                let opening = CreditOpeningCells::from_run(
                    &mut glue,
                    &mut range,
                    &mut hash,
                    &mut region,
                    &opening,
                )?;
                let mut uint = UintChip::new(&mut glue, &mut range);
                let request = parse(&self.request, &mut bytes, &mut uint, &mut hash, &mut region)?;
                let receiver = parse(
                    &self.receiver,
                    &mut bytes,
                    &mut uint,
                    &mut hash,
                    &mut region,
                )?;
                let receipt = parse(&self.receipt, &mut bytes, &mut uint, &mut hash, &mut region)?;
                let request = RequestCells::check(&mut uint, &mut hash, &mut region, &request)?;
                let receiver = CredentialCells::check(&mut uint, &mut region, &receiver)?;
                let fields = uint
                    .glue()
                    .witnesses(
                        &mut region,
                        &self
                            .statement
                            .iter()
                            .map(|f| value(known, *f))
                            .collect::<Vec<_>>(),
                    )?
                    .try_into()
                    .map_err(|_| Error::Synthesis)?;
                let statement =
                    DynamicStatementCells::constrain(&mut uint, &mut hash, &mut region, &fields)?;
                let head = uint
                    .glue()
                    .witnesses(
                        &mut region,
                        &self
                            .head
                            .iter()
                            .map(|f| value(known, *f))
                            .collect::<Vec<_>>(),
                    )?
                    .try_into()
                    .map_err(|_| Error::Synthesis)?;
                let head = LineagePublicCells::constrain(&mut uint, &mut region, &head)?;
                let context = uint.glue().witnesses(
                    &mut region,
                    &self
                        .context
                        .iter()
                        .map(|f| value(known, *f))
                        .collect::<Vec<_>>(),
                )?;
                if self.receive {
                    let statement = IncomingStatementCells::constrain(
                        &mut uint,
                        &mut hash,
                        &mut region,
                        iroha_plonk_recursion::obligation::ledger::Variant::Receive,
                        &fields,
                    )?;
                    let evidence = ReceiveEvidenceCells::bind(
                        &mut uint,
                        &mut hash,
                        &mut region,
                        &ReceiveEvidenceInputs {
                            statement: &statement,
                            receipt: &receipt,
                            request: &request,
                            receiver: &receiver,
                            relation: context[5..7].try_into().map_err(|_| Error::Synthesis)?,
                            provider: &[context[0].clone(), context[1].clone()],
                            payment_digest: &context[4],
                            proof_digest: &context[2],
                        },
                    )?;
                    return Ok([evidence.digest().clone(), evidence.valid().word().clone()]);
                }
                let tape = bytes.run(
                    &mut region,
                    &self
                        .tape
                        .iter()
                        .map(|b| value(known, *b))
                        .collect::<Vec<_>>(),
                    &StatusCells::primary_segments(),
                    &StatusCells::secondary_segments(),
                )?;
                let carried = if self.decode_carried_proof {
                    StatusCells::carried_proof_digest(&mut uint, &mut region, &tape)?
                } else {
                    context[2].clone()
                };
                let status = StatusCells::from_run(
                    &mut uint,
                    &mut hash,
                    &mut region,
                    &tape,
                    &StatusInputs {
                        statement: &statement,
                        receipt: &receipt,
                        lineage: &head,
                        lineage_digest: &context[3],
                        proof_digest: &carried,
                        opening: &opening,
                        provider: &[context[0].clone(), context[1].clone()],
                        relation: &[context[5].clone(), context[6].clone()],
                        request: &request,
                        receiver: &receiver,
                        payment_digest: &context[4],
                    },
                )?;
                Ok([status.digest().clone(), status.valid().word().clone()])
            },
        )?;
        for (i, word) in result.iter().enumerate() {
            layouter.constrain_instance(word.cell(), c.public, i)?;
        }
        Ok(())
    }
}
impl Status {
    fn public(&self) -> Vec<Fp> {
        let mut out = vec![Fp::ZERO; 8];
        out[0] = if self.receive {
            hash_with_domain(
                u64::from_le_bytes(*b"kgwpkg_1"),
                &[
                    hash_with_domain(u64::from_le_bytes(*b"kgwstmt1"), &self.statement),
                    self.context[2],
                    self.receipt.public(Fp::ZERO)[1],
                ],
            )
        } else {
            p_bytes_native(u64::from_le_bytes(*b"kgwcsts1"), &self.tape)
        };
        out[1] = Fp::from(u64::from(self.valid));
        out
    }
    fn accepts(&self) -> bool {
        check_circuit(self, 14, &[self.public()], CheckMode::Strict).is_ok_and(|r| r.is_satisfied())
    }
    fn rejects(mut self, reason: &str) {
        self.valid = false;
        assert!(self.accepts(), "total {reason}");
        self.valid = true;
        assert!(!self.accepts(), "forged {reason}");
    }
    fn rejects_preimage(mut self, reason: &str) {
        for verdict in [false, true] {
            self.valid = verdict;
            assert!(!self.accepts(), "preimage {reason}, verdict={verdict}");
        }
    }
    fn rebuild_transcript(&mut self) {
        self.tape = 1u16.to_le_bytes().to_vec();
        for word in [
            hash_with_domain(u64::from_le_bytes(*b"kgwstmt1"), &self.statement),
            self.context[2],
            self.receipt.public(Fp::ZERO)[1],
            self.context[3],
            p_bytes_native(u64::from_le_bytes(*b"kgwcopn1"), &self.opening),
        ] {
            self.tape.extend_from_slice(&word.to_repr());
        }
    }
    fn opening_root(&self) -> Fp {
        let value = hash_with_domain(
            u64::from_le_bytes(*b"kgwcdig1"),
            &[
                field_at(&self.opening, 0),
                field_at(&self.opening, 32),
                Fp::from(u64::from(self.opening[64])),
            ],
        );
        let leaf = hash_with_domain(
            INDEXED_LEAF_DOMAIN,
            &[
                field_at(&self.opening, 0),
                value,
                field_at(&self.opening, 65),
            ],
        );
        let slot = u32::from_le_bytes(self.opening[97..101].try_into().expect("slot"));
        let siblings = (0..32)
            .map(|i| field_at(&self.opening, 101 + 32 * i))
            .collect::<Vec<_>>();
        path_root(INDEXED_NODE_DOMAIN, leaf, u64::from(slot), &siblings)
    }
}
fn status() -> Status {
    let j = fixture();
    let mut request = cases()
        .into_iter()
        .find(|(c, ..)| c.kind == ObjectKind::Request)
        .expect("Request")
        .0;
    let mut receiver = credential();
    receiver.bytes[66..130].copy_from_slice(&request.bytes[130..194]);
    let receiver_digest = receiver.public(Fp::ZERO)[1];
    request.bytes[210..242].copy_from_slice(&receiver_digest.to_repr());
    // The certificate-set digest is a different Request field. Replacing it
    // with the credential digest would hide a wrong circuit field index.
    assert_ne!(field_at(&request.bytes, 394), receiver_digest);
    let mut request_words = j["poseidon"]["credit_id"]["poseidon"]["items"]
        .as_array()
        .expect("request fields")
        .iter()
        .map(|v| field(v.as_str().expect("hex")))
        .collect::<Vec<_>>();
    request_words[14] = receiver_digest;
    let credit = hash_with_domain(u64::from_le_bytes(*b"kgwcrdt1"), &request_words);
    let mut receipt = cases()
        .into_iter()
        .find(|(_, _, name, _)| name == "Receive receipt binding the Payment digest")
        .expect("receipt")
        .0;
    let mut statement: [Fp; 26] = j["field_encodings"]["receive_statement"]["items"]
        .as_array()
        .expect("statement")
        .iter()
        .map(|v| field(v.as_str().expect("field")))
        .collect::<Vec<_>>()
        .try_into()
        .expect("26");
    statement[17] = credit;
    let operation = hash_with_domain(
        u64::from_le_bytes(*b"kgwopid1"),
        &[request_words[9], request_words[10], Fp::from(4), credit],
    );
    receipt.bytes[114..146].copy_from_slice(&operation.to_repr());
    receipt.bytes[210..242]
        .copy_from_slice(&hash_with_domain(u64::from_le_bytes(*b"kgwstmt1"), &statement).to_repr());
    let mut opening = decode(
        j["poseidon"]["credit_digest_opening"]["credit_opening_hex"]
            .as_str()
            .expect("opening"),
    );
    opening[..32].copy_from_slice(&credit.to_repr());
    opening[65..97].fill(0);
    let mut head = [Fp::ZERO; 18];
    head[0] = Fp::ONE;
    head[1..3].copy_from_slice(&statement[3..5]);
    head[3..5].copy_from_slice(&statement[1..3]);
    head[5] = statement[15];
    head[6..8].copy_from_slice(&request_words[9..11]);
    head[8] = statement[7];
    for (i, offset) in [147, 131, 179, 163].into_iter().enumerate() {
        head[9 + i] = Fp::from_u128(u128::from_be_bytes(
            receiver.bytes[offset..offset + 16]
                .try_into()
                .expect("key half"),
        ));
    }
    head[13] = statement[8] + Fp::from(256);
    head[15] = Fp::ONE;
    head[17] = Fp::ONE;
    let context = [
        half_at(&receipt.bytes, 66),
        half_at(&receipt.bytes, 82),
        field_at(&receipt.bytes, 242),
        Fp::from(77),
        field_at(&opening, 32),
        statement[1],
        statement[2],
    ];
    let mut c = Status {
        request,
        receiver,
        receipt,
        statement,
        head,
        opening,
        tape: vec![],
        context,
        valid: true,
        receive: false,
        decode_carried_proof: false,
    };
    c.head[16] = c.opening_root();
    c.rebuild_transcript();
    c
}
#[test]
fn receive_evidence_binds_retained_credit_amount_relation_and_exact_payment() {
    let mut c = status();
    c.receive = true;
    assert!(c.accepts());
    for i in 0..26 {
        let mut wrong = c.clone();
        wrong.statement[i] += Fp::ONE;
        wrong.rejects(&format!("Receive statement field{i}"));
    }
    for i in [0, 1, 2, 4, 5, 6] {
        let mut wrong = c.clone();
        wrong.context[i] += Fp::ONE;
        wrong.rejects(&format!("Receive context{i}"));
    }
    for offset in [2, 34, 66, 98, 114, 146, 178, 210, 242, 306] {
        let mut wrong = c.clone();
        wrong.receipt.bytes[offset] ^= 1;
        wrong.rejects(&format!("receipt field at{offset}"));
    }
    let mut wrong = c.clone();
    wrong.request.bytes[210] ^= 1;
    wrong.rejects("foreign quoted credential");
    let mut renewed = c.clone();
    renewed.statement[7] += Fp::ONE;
    renewed.receipt.bytes[210..242].copy_from_slice(
        &hash_with_domain(u64::from_le_bytes(*b"kgwstmt1"), &renewed.statement).to_repr(),
    );
    assert!(
        renewed.accepts(),
        "Receive permits renewed receiver credential"
    );
    let mut malformed = c.clone();
    malformed.statement[20] = -Fp::ONE;
    malformed.receipt.bytes[210..242].copy_from_slice(
        &hash_with_domain(u64::from_le_bytes(*b"kgwstmt1"), &malformed.statement).to_repr(),
    );
    malformed.rejects("malformed amount with rebound statement digest");
    let known = synthesize(&c, 14, None).expect("known");
    let unknown = synthesize(&c.without_witnesses(), 14, None).expect("unknown");
    assert_eq!(known.tables.fixed(), unknown.tables.fixed());
    assert_eq!(known.tables.permutation(), unknown.tables.permutation());
}
#[test]
fn status_binds_folded_head_retained_payment_and_receiver_renewal_identity() {
    let c = status();
    assert!(c.accepts());
    for i in 0..StatusCells::BYTES {
        let mut wrong = c.clone();
        wrong.tape[i] ^= 1;
        let start = 2 + i.saturating_sub(2) / 32 * 32;
        if i >= 2
            && bool::from(
                Fp::from_repr(wrong.tape[start..start + 32].try_into().unwrap()).is_some(),
            )
        {
            wrong.rejects_preimage(&format!("transcript byte{i}"));
        } else {
            wrong.rejects(&format!("transcript byte{i}"));
        }
    }
    for i in [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 16] {
        let mut wrong = c.clone();
        wrong.head[i] += Fp::ONE;
        wrong.rejects(&format!("head field{i}"));
    }
    for i in [0, 1, 2, 4, 5, 6] {
        let mut wrong = c.clone();
        wrong.context[i] += Fp::ONE;
        wrong.rebuild_transcript();
        wrong.rejects(&format!("rebound context{i}"));
    }
    let mut wrong = c.clone();
    wrong.context[3] += Fp::ONE;
    wrong.rejects_preimage("foreign exact-lineage byte digest");
    let mut foreign = c.clone();
    foreign.statement[1] += Fp::ONE;
    foreign.head[3] = foreign.statement[1];
    foreign.receipt.bytes[210..242].copy_from_slice(
        &hash_with_domain(u64::from_le_bytes(*b"kgwstmt1"), &foreign.statement).to_repr(),
    );
    foreign.rebuild_transcript();
    foreign.rejects("foreign relation despite rebound statement, head and receipt");
    let mut wrong = c.clone();
    wrong.receipt.bytes[306] ^= 1;
    wrong.rebuild_transcript();
    // A status receipt binds its own Payment, which may describe a later Receive.
    assert!(
        wrong.accepts(),
        "head receipt need not describe this older credit"
    );
    let mut wrong = c.clone();
    wrong.opening[32] ^= 1;
    wrong.head[16] = wrong.opening_root();
    wrong.rebuild_transcript();
    wrong.rejects("foreign Payment despite rebound root");
    let mut burned = c.clone();
    burned.opening[64] = 1;
    burned.head[16] = burned.opening_root();
    burned.rebuild_transcript();
    assert!(burned.accepts());
    let mut renewed = c.clone();
    renewed.head[8] += Fp::ONE;
    renewed.statement[7] = renewed.head[8];
    renewed.receipt.bytes[210..242].copy_from_slice(
        &hash_with_domain(u64::from_le_bytes(*b"kgwstmt1"), &renewed.statement).to_repr(),
    );
    renewed.rebuild_transcript();
    assert!(
        renewed.accepts(),
        "renewed head credential differs while wallet/key remain equal"
    );
    let known = synthesize(&c, 14, None).expect("known");
    let unknown = synthesize(&c.without_witnesses(), 14, None).expect("unknown");
    assert_eq!(known.tables.fixed(), unknown.tables.fixed());
    assert_eq!(known.tables.permutation(), unknown.tables.permutation());
}

#[test]
fn original_status_addresses_cannot_be_replaced_to_manufacture_noop() {
    let c = status();
    for component in 0..5 {
        let mut changed = c.clone();
        match component {
            0 => changed.statement[1] += Fp::ONE,
            1 => changed.context[2] += Fp::ONE,
            2 => changed.receipt.bytes[ObjectKind::Receipt.body_len()] ^= 1,
            3 => changed.context[3] += Fp::ONE,
            _ => changed.opening[101] ^= 1,
        }
        // Keep the original transcript. Neither false nor true can excuse a
        // different preimage of a canonical source address.
        changed.rejects_preimage(&format!("component {component}"));
    }
    for component in 0..5 {
        let mut malformed = c.clone();
        let start = 2 + 32 * component;
        malformed.tape[start..start + 32].fill(255);
        malformed.rejects(&format!("noncanonical original address {component}"));
    }
}

#[test]
fn original_carried_status_proof_digest_remains_total_when_receipt_disagrees() {
    let mut c = status();
    c.decode_carried_proof = true;
    assert!(c.accepts());
    let mut wrong = c.clone();
    let digest = field_at(&wrong.tape, 34) + Fp::ONE;
    wrong.tape[34..66].copy_from_slice(&digest.to_repr());
    wrong.rejects("original carried proof digest differs from receipt");
    let mut malformed = c.clone();
    malformed.tape[34..66].fill(255);
    malformed.rejects("noncanonical original carried proof digest");
    let known = synthesize(&c, 14, None).unwrap();
    let unknown = synthesize(&c.without_witnesses(), 14, None).unwrap();
    assert_eq!(known.tables.fixed(), unknown.tables.fixed());
    assert_eq!(known.tables.permutation(), unknown.tables.permutation());
}
