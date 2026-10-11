//! Mandatory Payment content addresses and total bound incoming predicates.

use super::{
    semantics::{credential, parse},
    *,
};
use iroha_kagemusha_proof::a_relation::{
    IncomingLineageCells, LineagePublicCells, own::ConsumingProofCells,
};
use iroha_kagemusha_proof::operation_relation::{
    incoming_statement::IncomingStatementCells,
    objects::{
        credential::CredentialCells,
        payment::{IncomingPaymentCells, PaymentCells, PaymentInputs},
        request::RequestCells,
    },
};
use iroha_plonk_recursion::obligation::ledger::Variant;

#[derive(Clone)]
struct Payment {
    request: ObjectCircuit,
    payer: ObjectCircuit,
    receipt: ObjectCircuit,
    statement: [Fp; 26],
    transcript: Vec<u8>,
    proof: Fp,
    provider: [Fp; 2],
    valid: bool,
    consumer: Option<Consumer>,
}

#[derive(Clone)]
struct Consumer {
    predecessor: Vec<u8>,
    receiver: [Fp; 18],
    selector: u64,
}
impl Circuit<Fp> for Payment {
    type Config = Config;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();
    fn without_witnesses(&self) -> Self {
        Self {
            request: self.request.without_witnesses(),
            payer: self.payer.without_witnesses(),
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
        let output = layouter.assign_region(
            || "Payment transcript",
            |mut region| {
                let mut uint = UintChip::new(&mut glue, &mut range);
                let request = parse(&self.request, &mut bytes, &mut uint, &mut hash, &mut region)?;
                let payer = parse(&self.payer, &mut bytes, &mut uint, &mut hash, &mut region)?;
                let receipt = parse(&self.receipt, &mut bytes, &mut uint, &mut hash, &mut region)?;
                let request = RequestCells::check(&mut uint, &mut hash, &mut region, &request)?;
                let payer = CredentialCells::check(&mut uint, &mut region, &payer)?;
                let value = |v: &Fp| {
                    if self.request.known {
                        Value::known(*v)
                    } else {
                        Value::unknown()
                    }
                };
                let fields = uint
                    .glue()
                    .witnesses(
                        &mut region,
                        &self.statement.iter().map(value).collect::<Vec<_>>(),
                    )?
                    .try_into()
                    .map_err(|_| Error::Synthesis)?;
                let statement = IncomingStatementCells::constrain(
                    &mut uint,
                    &mut hash,
                    &mut region,
                    Variant::Send,
                    &fields,
                )?;
                let proof = uint.glue().witness(&mut region, value(&self.proof))?;
                let provider = uint
                    .glue()
                    .witnesses(
                        &mut region,
                        &self.provider.iter().map(value).collect::<Vec<_>>(),
                    )?
                    .try_into()
                    .map_err(|_| Error::Synthesis)?;
                let tape = self
                    .transcript
                    .iter()
                    .map(|b| {
                        if self.request.known {
                            Value::known(*b)
                        } else {
                            Value::unknown()
                        }
                    })
                    .collect::<Vec<_>>();
                let run = bytes.run(
                    &mut region,
                    &tape,
                    &PaymentCells::primary_segments(),
                    &PaymentCells::secondary_segments(),
                )?;
                let inputs = PaymentInputs {
                    request: &request,
                    payer: &payer,
                    statement: &statement,
                    receipt: &receipt,
                    provider: &provider,
                    proof_digest: &proof,
                };
                let (payment, selector) = if let Some(consumer) = &self.consumer {
                    let tape = consumer
                        .predecessor
                        .iter()
                        .map(|b| {
                            if self.request.known {
                                Value::known(*b)
                            } else {
                                Value::unknown()
                            }
                        })
                        .collect::<Vec<_>>();
                    let pred_run = bytes.run(
                        &mut region,
                        &tape,
                        &iroha_plonk_gadgets::bytes::chunk_segments(0, tape.len()),
                        &ConsumingProofCells::omega_segments(32)?,
                    )?;
                    let key = uint.glue().constant(&mut region, Fp::from(77))?;
                    let predecessor = IncomingLineageCells::from_run(
                        &mut uint,
                        &mut region,
                        &pred_run,
                        32,
                        &key,
                    )?;
                    let fields = uint
                        .glue()
                        .witnesses(
                            &mut region,
                            &consumer.receiver.iter().map(value).collect::<Vec<_>>(),
                        )?
                        .try_into()
                        .map_err(|_| Error::Synthesis)?;
                    let receiver = LineagePublicCells::constrain(&mut uint, &mut region, &fields)?;
                    let bound = IncomingPaymentCells::from_run(
                        &mut uint,
                        &mut hash,
                        &mut region,
                        &run,
                        &inputs,
                        &predecessor,
                        &receiver,
                    )?;
                    (bound.payment().clone(), bound.sigma_index().clone())
                } else {
                    let payment =
                        PaymentCells::from_run(&mut uint, &mut hash, &mut region, &run, &inputs)?;
                    (payment, uint.glue().constant(&mut region, Fp::ZERO)?)
                };
                Ok([
                    payment.digest().clone(),
                    payment.package_digest().clone(),
                    payment.valid().word().clone(),
                    selector,
                ])
            },
        )?;
        for (i, word) in output.iter().enumerate() {
            layouter.constrain_instance(word.cell(), c.public, i)?;
        }
        Ok(())
    }
}
impl Payment {
    fn public(&self) -> Vec<Fp> {
        let mut p = vec![Fp::ZERO; 8];
        p[0] = p_bytes_native(u64::from_le_bytes(*b"kgwpay_1"), &self.transcript);
        p[1] = hash_with_domain(
            u64::from_le_bytes(*b"kgwpkg_1"),
            &[
                hash_with_domain(u64::from_le_bytes(*b"kgwstmt1"), &self.statement),
                self.proof,
                self.receipt.public(Fp::ZERO)[1],
            ],
        );
        p[2] = Fp::from(u64::from(self.valid));
        p[3] = Fp::from(self.consumer.as_ref().map_or(0, |c| c.selector));
        p
    }
    fn accepts(&self) -> bool {
        check_circuit(self, 13, &[self.public()], CheckMode::Strict).is_ok_and(|r| r.is_satisfied())
    }
    fn reject(mut self, reason: &str) {
        self.valid = false;
        assert!(self.accepts(), "total {reason}");
        self.valid = true;
        assert!(!self.accepts(), "forged {reason}");
    }
    fn reject_substitution(mut self, original: &Self, reason: &str) {
        assert_eq!(
            self.transcript, original.transcript,
            "fixed Payment: {reason}"
        );
        for valid in [false, true] {
            self.valid = valid;
            assert!(!self.accepts(), "hard preimage binding ({valid}): {reason}");
        }
    }
    fn rebind_components(&mut self) {
        self.transcript[2..34].copy_from_slice(&self.request.public(Fp::ZERO)[1].to_repr());
        self.transcript[99..131].copy_from_slice(&self.payer.public(Fp::ZERO)[1].to_repr());
        let package = self.public()[1];
        self.transcript[131..163].copy_from_slice(&package.to_repr());
    }
}
fn base() -> Payment {
    let request = cases()
        .into_iter()
        .find(|(c, ..)| c.kind == ObjectKind::Request)
        .expect("Request")
        .0;
    let receipt = cases()
        .into_iter()
        .find(|(_, _, name, _)| name == "Send receipt")
        .expect("receipt")
        .0;
    let j = fixture();
    let transcript = j["poseidon"]["large_input_digests"]
        .as_array()
        .expect("digests")
        .iter()
        .find(|v| v["domain"].as_str() == Some("kgwpay_1"))
        .expect("Payment");
    let provider = ::core::array::from_fn(|i| {
        Fp::from_u128(u128::from_le_bytes(
            receipt.bytes[66 + i * 16..82 + i * 16]
                .try_into()
                .expect("half"),
        ))
    });
    let proof = Fp::from_repr(receipt.bytes[242..274].try_into().expect("proof"))
        .into_option()
        .expect("canonical");
    let c = Payment {
        request,
        payer: credential(),
        receipt,
        provider,
        proof,
        statement: j["field_encodings"]["send_statement"]["items"]
            .as_array()
            .expect("statement")
            .iter()
            .map(|v| field(v.as_str().expect("hex")))
            .collect::<Vec<_>>()
            .try_into()
            .expect("26"),
        transcript: decode(transcript["body_hex"].as_str().expect("hex")),
        valid: true,
        consumer: None,
    };
    assert_eq!(
        c.public()[0],
        field(transcript["digest_hex"].as_str().expect("digest"))
    );
    assert_eq!(
        c.public()[1],
        field(
            j["poseidon"]["package"]["digest_hex"]
                .as_str()
                .expect("package")
        )
    );
    c
}

fn halves(bytes: &[u8]) -> [Fp; 2] {
    core::array::from_fn(|i| {
        Fp::from_u128(u128::from_le_bytes(
            bytes[16 * i..16 * i + 16].try_into().expect("half"),
        ))
    })
}

fn incoming() -> Payment {
    let mut c = base();
    let mut body = Vec::new();
    body.extend_from_slice(&1u16.to_le_bytes());
    for pair in [&c.statement[3..5], &c.statement[1..3]] {
        for half in pair {
            body.extend_from_slice(&half.to_repr()[..16]);
        }
    }
    body.extend_from_slice(&c.statement[14].to_repr());
    body.extend_from_slice(&c.request.bytes[66..98]);
    body.extend_from_slice(&c.statement[7].to_repr());
    body.extend_from_slice(&c.payer.bytes[130..195]);
    body.push(1);
    body.extend_from_slice(&c.request.bytes[306..314]);
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&c.statement[12].to_repr()[..16]);
    body.extend_from_slice(&c.statement[13].to_repr());
    body.extend_from_slice(&Fp::from(42).to_repr());
    assert_eq!(body.len(), ConsumingProofCells::PUBLIC_BYTES);
    // Explicit decoder-only fixture: proof and accumulator authentication is
    // separate. No stand-in byte string is used as a verified proof here.
    body.resize(
        body.len() + 32 + 2 * iroha_plonk_recursion::ACCUMULATOR_BYTES,
        0,
    );
    let mut predecessor = u32::try_from(body.len())
        .expect("length")
        .to_le_bytes()
        .to_vec();
    predecessor.extend(body);
    let mut receiver = [Fp::ZERO; 18];
    receiver[0] = Fp::ONE;
    receiver[1..3].copy_from_slice(&c.statement[3..5]);
    receiver[3..5].copy_from_slice(&c.statement[1..3]);
    receiver[6..8].copy_from_slice(&halves(&c.request.bytes[130..162]));
    let j = fixture();
    let key = j["keys"]
        .as_array()
        .expect("keys")
        .iter()
        .find(|k| k["name"].as_str() == Some("receiver_payment"))
        .expect("key");
    let key = decode(key["public_key_hex"].as_str().expect("SEC1"));
    for (i, index) in [10, 9, 12, 11].into_iter().enumerate() {
        receiver[index] = Fp::from_u128(u128::from_be_bytes(
            key[1 + 16 * i..17 + 16 * i].try_into().expect("half"),
        ));
    }
    receiver[13] = Fp::ONE;
    c.consumer = Some(Consumer {
        predecessor,
        receiver,
        selector: 2,
    });
    c
}

impl Payment {
    fn rebind_statement(&mut self) {
        let digest = hash_with_domain(u64::from_le_bytes(*b"kgwstmt1"), &self.statement);
        self.receipt.bytes[210..242].copy_from_slice(&digest.to_repr());
        let package = self.public()[1];
        self.transcript[131..163].copy_from_slice(&package.to_repr());
    }

    fn native_send(&self) -> bool {
        use iroha_kagemusha_proof::{
            check_send,
            consumer::LineageView,
            witness::{RequestBody, RequestTerms},
        };
        use iroha_plonk_gadgets::statement::{StatementV1, StepRelation};
        let Some(consumer) = &self.consumer else {
            return false;
        };
        let raw = &consumer.predecessor[4..];
        let request = &self.request.bytes;
        let b = |offset| {
            request[offset..offset + 32]
                .try_into()
                .expect("body digest")
        };
        let u =
            |offset| u128::from_le_bytes(request[offset..offset + 16].try_into().expect("u128"));
        let v = |offset| u64::from_le_bytes(request[offset..offset + 8].try_into().expect("u64"));
        let request = RequestBody {
            scheme_id: b(2),
            asset_digest: b(34),
            payer_wallet: b(66),
            payer_account: b(98),
            receiver_wallet: b(130),
            receiver_account: b(162),
            send_ordinal: u(194),
            receiver_credential_digest: b(210),
            terms: RequestTerms {
                amount: u(242),
                fee: u(290),
                fee_schedule: b(258),
                policy_epoch: v(306),
                scheme_policy: b(314),
                request_time: v(346),
                receiver_blacklist_version: v(354),
                receiver_blacklist_root: b(362),
                certificates: b(394),
                nonce: b(426),
            },
        };
        let field = |offset| {
            Fp::from_repr(raw[offset..offset + 32].try_into().expect("field")).into_option()
        };
        let Some(head) = field(66) else {
            return false;
        };
        let Some(pending) = field(256) else {
            return false;
        };
        let view = LineageView {
            head,
            scheme_id: raw[2..34].try_into().expect("scheme"),
            relation_id: raw[34..66].try_into().expect("relation"),
            wallet_id: raw[98..130].try_into().expect("wallet"),
            credential_digest: raw[130..162].try_into().expect("credential"),
            lifecycle: raw[227],
            enabled_controls: u32::from_le_bytes(raw[236..240].try_into().expect("controls")),
            burned_total: u128::from_le_bytes(raw[240..256].try_into().expect("burned")),
            pending_outgoing_root: pending,
        };
        let f = &self.statement;
        let pair = |index: usize| {
            let mut out = [0; 32];
            out[..16].copy_from_slice(&f[index].to_repr()[..16]);
            out[16..].copy_from_slice(&f[index + 1].to_repr()[..16]);
            out
        };
        let integer = |index: usize| {
            u128::from_le_bytes(f[index].to_repr()[..16].try_into().expect("integer"))
        };
        let statement = StatementV1 {
            relation_id: pair(1),
            step: StepRelation::Send,
            scheme_id: pair(3),
            asset_digest: pair(5),
            credential_digest: f[7].to_repr(),
            lifecycle: u8::try_from(integer(8)).expect("lifecycle"),
            sequence: integer(9),
            next_load: integer(10),
            enabled_controls: u32::try_from(integer(11)).expect("mask"),
            lineage_burned_total: integer(12),
            lineage_pending_outgoing_root: f[13],
            predecessor: f[14],
            successor: f[15],
            effect: f[17..].to_vec(),
        };
        check_send(&view, &request, &statement).is_ok()
    }
}

#[test]
fn incoming_send_consumer_binds_lineage_and_total_policy_time_rules() {
    let c = incoming();
    assert!(c.native_send());
    assert!(c.accepts());
    // Native consumer parity: these are every lineage input check_send binds.
    for offset in [2, 18, 34, 50, 66, 98, 114, 130, 227, 236, 240, 256] {
        let mut wrong = c.clone();
        wrong.consumer.as_mut().expect("consumer").predecessor[4 + offset] ^= 1;
        assert!(!wrong.native_send(), "native field {offset}");
        if offset == 236 {
            wrong.consumer.as_mut().expect("consumer").selector = 3;
        }
        wrong.reject(&format!("predecessor field{offset}"));
    }
    for lifecycle in [1, 2] {
        for mask in 0..8 {
            let mut valid = c.clone();
            valid.statement[8] = Fp::from(lifecycle);
            valid.statement[11] = Fp::from(mask);
            let consumer = valid.consumer.as_mut().expect("consumer");
            consumer.predecessor[4 + 227] = u8::try_from(lifecycle).expect("lifecycle");
            consumer.predecessor[4 + 236..4 + 240]
                .copy_from_slice(&u32::try_from(mask).expect("mask").to_le_bytes());
            consumer.selector = 2 + mask;
            valid.rebind_statement();
            assert!(valid.native_send());
            assert!(valid.accepts(), "lifecycle{lifecycle}/mask{mask}");
        }
    }
    // A coherent unsupported control/lifecycle still gives false, never an
    // impossible range check that prevents the protocol's burn/no-op branch.
    for (lifecycle, mask) in [(0, 0), (3, 0), (255, 0), (1, 8), (1, u32::MAX)] {
        let mut wrong = c.clone();
        wrong.statement[8] = Fp::from(lifecycle);
        wrong.statement[11] = Fp::from(u64::from(mask));
        let consumer = wrong.consumer.as_mut().expect("consumer");
        consumer.predecessor[4 + 227] = u8::try_from(lifecycle).expect("lifecycle");
        consumer.predecessor[4 + 236..4 + 240].copy_from_slice(&mask.to_le_bytes());
        consumer.selector = if mask < 8 { 2 + u64::from(mask) } else { 2 };
        wrong.rebind_statement();
        wrong.reject("unsupported coherent lifecycle/control");
    }
    for index in [1, 2, 3, 4, 6, 7] {
        let mut wrong = c.clone();
        wrong.consumer.as_mut().expect("consumer").receiver[index] += Fp::ONE;
        wrong.reject("receiver scope/wallet substitution");
    }
    let mut wrong = c.clone();
    wrong.statement[1] += Fp::ONE;
    wrong.consumer.as_mut().expect("consumer").predecessor[4 + 34..4 + 50]
        .copy_from_slice(&wrong.statement[1].to_repr()[..16]);
    wrong.rebind_statement();
    assert!(
        wrong.native_send(),
        "coherent foreign relation passes local native consumer"
    );
    wrong.reject("coherent foreign relation differs from current receiver");
    for offset in [163, 179, 195, 211] {
        let mut wrong = c.clone();
        wrong.consumer.as_mut().expect("consumer").predecessor[4 + offset] ^= 1;
        wrong.reject("payer credential key differs from incoming lineage");
    }
    let mut wrong = c.clone();
    let key = &wrong.payer.bytes[130..195];
    let receiver = &mut wrong.consumer.as_mut().expect("consumer").receiver;
    for (i, index) in [10, 9, 12, 11].into_iter().enumerate() {
        receiver[index] = Fp::from_u128(u128::from_be_bytes(
            key[1 + 16 * i..17 + 16 * i].try_into().expect("half"),
        ));
    }
    wrong.reject("payer equals receiver payment key");
    let epoch = u64::from_le_bytes(c.request.bytes[306..314].try_into().expect("epoch"));
    let mut wrong = c.clone();
    wrong.consumer.as_mut().expect("consumer").predecessor[4 + 228..4 + 236]
        .copy_from_slice(&(epoch - 1).to_le_bytes());
    wrong.reject("stale payer policy epoch");
    let mut valid = c.clone();
    valid.consumer.as_mut().expect("consumer").predecessor[4 + 228..4 + 236]
        .copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(
        valid.accepts(),
        "newer payer policy retains earlier Request"
    );
    let time = u64::from_le_bytes(c.request.bytes[346..354].try_into().expect("time"));
    let mut valid = c.clone();
    valid.statement[24] = Fp::from(time);
    valid.rebind_statement();
    assert!(valid.accepts(), "accepted lower endpoint is inclusive");
    for lower in [Fp::from(time - 1), -Fp::ONE] {
        let mut wrong = c.clone();
        wrong.statement[24] = lower;
        wrong.rebind_statement();
        wrong.reject("early/oversized accepted lower bound");
    }
    for offset in [0, 4, 4 + 162] {
        let mut wrong = c.clone();
        wrong.consumer.as_mut().expect("consumer").predecessor[offset] ^= 1;
        wrong.reject("original lineage length/version/SEC1 failure");
    }
    let mut wrong = c.clone();
    wrong.consumer.as_mut().expect("consumer").predecessor[4 + 130..4 + 162].fill(255);
    wrong.reject("noncanonical original credential digest");
    let known = synthesize(&c, 13, None).expect("known");
    let unknown = synthesize(&c.without_witnesses(), 13, None).expect("unknown");
    assert_eq!(known.tables.fixed(), unknown.tables.fixed());
    assert_eq!(known.tables.permutation(), unknown.tables.permutation());
}

#[test]
fn native_payment_transcript_binds_every_byte_and_each_nested_component() {
    let c = base();
    assert!(c.accepts());
    for i in 0..PaymentCells::BYTES {
        let mut wrong = c.clone();
        wrong.transcript[i] ^= 1;
        if (2..34).contains(&i) || (99..163).contains(&i) {
            for valid in [false, true] {
                wrong.valid = valid;
                assert!(!wrong.accepts(), "content address byte{i}, verdict{valid}");
            }
        } else {
            wrong.reject(&format!("Payment byte{i}"));
        }
    }
    for i in [
        2, 34, 66, 98, 130, 162, 194, 210, 242, 258, 290, 306, 314, 346, 354, 362, 394, 426, 458,
    ] {
        let mut wrong = c.clone();
        wrong.request.bytes[i] ^= 1;
        wrong.reject_substitution(&c, "nested Request");
    }
    for i in [2, 34, 66, 98, 130, 195, 227, 260, 300, 350, 444, 476] {
        let mut wrong = c.clone();
        wrong.payer.bytes[i] ^= 1;
        wrong.reject_substitution(&c, "nested payer credential");
    }
    for i in [0, 2, 34, 66, 98, 114, 146, 178, 210, 242, 274, 306, 338] {
        let mut wrong = c.clone();
        wrong.receipt.bytes[i] ^= 1;
        wrong.reject_substitution(&c, "nested receipt");
    }
    for i in 0..26 {
        let mut wrong = c.clone();
        wrong.statement[i] = -Fp::ONE;
        wrong.reject_substitution(&c, "nested incoming statement");
    }
    let mut wrong = c.clone();
    wrong.proof += Fp::ONE;
    wrong.reject_substitution(&c, "different proof tape digest");
    for i in 0..2 {
        let mut wrong = c.clone();
        wrong.provider[i] += Fp::ONE;
        wrong.reject("different provider");
    }
    let known = synthesize(&c, 13, None).expect("known");
    let unknown = synthesize(&c.without_witnesses(), 13, None).expect("unknown");
    assert_eq!(known.tables.fixed(), unknown.tables.fixed());
    assert_eq!(known.tables.permutation(), unknown.tables.permutation());
}

#[test]
fn committed_malformed_components_remain_total_after_exact_content_rebinding() {
    let c = base();
    // These are genuinely different, committed Payments. Their bad original
    // payloads stay total; an arbitrary alternative preimage of c cannot burn.
    for object in 0..3 {
        let mut malformed = c.clone();
        match object {
            0 => malformed.request.bytes[0] ^= 1,
            1 => malformed.payer.bytes[0] ^= 1,
            _ => malformed.receipt.bytes[0] ^= 1,
        }
        malformed.rebind_components();
        assert_ne!(malformed.transcript, c.transcript);
        malformed.reject("committed wrong object version");
    }
    let mut malformed = c.clone();
    malformed.statement[24] = -Fp::ONE;
    malformed.rebind_statement();
    malformed.reject("committed oversized incoming statement");
}
