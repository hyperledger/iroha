//! In-circuit digests against the native Poseidon and the shared G1
//! vectors:
//!
//! - the native reference (`iroha_pasta::poseidon::hash_with_domain`)
//!   reproduces every `kagemusha_v1_poseidon` vector of
//!   `fixtures/native_prover/kats_v1.json` on both fields;
//! - spec section 3.2 shared vectors: the domains, the 32-element core and
//!   13-element rest (also of the `controlled_state` vector, whose elements
//!   are all distinct and named), the rest digest and head commitment,
//!   `credit_id` over
//!   the 24-element Request body, both chain appends and the 28-element
//!   statements that the G1 data model publishes in
//!   `fixtures/kagemusha/wallet_v1_vectors.json` are reproduced by this
//!   crate's native encodings, and its circuits compute the same
//!   commitment, `credit_id` and chain values in circuit;
//! - every digest the relation computes in circuit (predecessor, successor,
//!   credit identifier, chain, statement) equals the native reference, for
//!   many witnesses, every relation shape and both fields, and does not
//!   depend on the prefix mode or the lane count;
//! - the statement digest equals the gadgets' `StatementV1::digest`;
//! - pinned known answers guard the encoding against drift.

mod common;

use common::{RELATIONS, folded, in_circuit_digests, relation_shapes, repo_root, smallest_shape};
use ff::PrimeField;
use iroha_kagemusha_proof::{
    Controls, CoreState, Identity, MapRoots, Mutation, PrefixMode, ReceiveInputs, RelationShape,
    RequestBody, RequestTerms, SendInputs, SigmaParams, SigmaRelation, SigmaShape, StateRest,
    StateV1, StepInputs, StepRelation, StepWitness, limb_bits_for, sample_witness,
    witness::{
        CORE_DOMAIN, CORE_FIELDS, CREDIT_DOMAIN, LineageInputs, RECEIVE_CHAIN_DOMAIN,
        REQUEST_FIELDS, REST_DOMAIN, REST_FIELDS, SEND_CHAIN_DOMAIN,
    },
};
use iroha_pasta::{
    Fp, Fq,
    poseidon::{PoseidonField, hash_with_domain},
};
use iroha_plonk_gadgets::statement::{STATEMENT_DOMAIN, STATEMENT_FIELDS};
use norito::json::Value;

fn hex_decode(text: &str) -> [u8; 32] {
    assert_eq!(text.len(), 64, "32-byte hex");
    let bytes = (0..32)
        .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).expect("hex digit"))
        .collect::<Vec<_>>();
    bytes.try_into().expect("32 bytes")
}

fn scalar<F: PrimeField<Repr = [u8; 32]>>(text: &str) -> F {
    Option::from(F::from_repr(hex_decode(text))).expect("canonical scalar")
}

fn hex<F: PrimeField<Repr = [u8; 32]>>(value: &F) -> String {
    use core::fmt::Write as _;
    value.to_repr().iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

fn shared_vectors<F: PoseidonField>(parity: &str) -> usize {
    let path = repo_root().join("fixtures/native_prover/kats_v1.json");
    let text = std::fs::read_to_string(&path).expect("read kats_v1.json");
    let fixture = norito::json::parse_value(&text).expect("parse kats_v1.json");
    let vectors = fixture
        .get("kagemusha_v1_poseidon")
        .and_then(|section| section.get(parity))
        .and_then(|section| section.get("vectors"))
        .and_then(Value::as_array)
        .expect("kagemusha_v1_poseidon vectors");
    for vector in vectors {
        let text = |key: &str| vector.get(key).and_then(Value::as_str).expect("string");
        let label = text("domain");
        let domain = u64::from_le_bytes(label.as_bytes().try_into().expect("8-byte domain"));
        let inputs = vector
            .get("inputs")
            .and_then(Value::as_array)
            .expect("inputs")
            .iter()
            .map(|input| scalar::<F>(input.as_str().expect("hex")))
            .collect::<Vec<F>>();
        assert_eq!(
            hash_with_domain(domain, &inputs),
            scalar::<F>(text("output")),
            "{parity} {label}"
        );
    }
    vectors.len()
}

#[test]
fn the_native_reference_reproduces_the_shared_vectors() {
    assert_eq!(shared_vectors::<Fp>("fp"), 12);
    assert_eq!(shared_vectors::<Fq>("fq"), 12);
}

// ---------------------------------------------------------------------------
// The G1 vectors of `fixtures/kagemusha/wallet_v1_vectors.json`
// ---------------------------------------------------------------------------

/// The parsed G1 wallet vectors.
fn wallet_vectors() -> Value {
    let path = repo_root().join("fixtures/kagemusha/wallet_v1_vectors.json");
    let text = std::fs::read_to_string(&path).expect("read wallet_v1_vectors.json");
    norito::json::parse_value(&text).expect("parse wallet_v1_vectors.json")
}

/// The value at `path` (object keys).
fn at<'v>(value: &'v Value, path: &[&str]) -> &'v Value {
    path.iter().fold(value, |value, key| {
        value
            .get(*key)
            .unwrap_or_else(|| panic!("missing {key} in {path:?}"))
    })
}

/// A 32-byte hex string at `path`.
fn bytes_at(value: &Value, path: &[&str]) -> [u8; 32] {
    hex_decode(at(value, path).as_str().expect("hex string"))
}

/// The 32-byte element list at `path`.
fn items_at(value: &Value, path: &[&str]) -> Vec<[u8; 32]> {
    at(value, path)
        .as_array()
        .expect("item list")
        .iter()
        .map(|item| hex_decode(item.as_str().expect("item hex")))
        .collect()
}

/// Typed reads of a G1 element list (the element rule of the wire record:
/// an integer is one element, a digest two `u128` limbs low half first, a
/// `P` value one element).
struct Items<'a>(&'a [[u8; 32]]);

impl Items<'_> {
    /// The integer element at `index` (below `2^128`).
    fn integer(&self, index: usize) -> u128 {
        let item = &self.0[index];
        assert_eq!(item[16..], [0; 16], "element {index} is an integer");
        u128::from_le_bytes(item[..16].try_into().expect("16 bytes"))
    }

    /// The `u64` element at `index`.
    fn u64(&self, index: usize) -> u64 {
        u64::try_from(self.integer(index)).expect("u64 element")
    }

    /// The `u32` element at `index`.
    fn u32(&self, index: usize) -> u32 {
        u32::try_from(self.integer(index)).expect("u32 element")
    }

    /// The 32-byte digest whose limbs are the elements `index` and
    /// `index + 1`.
    fn digest(&self, index: usize) -> [u8; 32] {
        let lo = self.integer(index).to_le_bytes();
        let hi = self.integer(index + 1).to_le_bytes();
        let mut digest = [0_u8; 32];
        digest[..16].copy_from_slice(&lo);
        digest[16..].copy_from_slice(&hi);
        digest
    }

    /// The `P` value element at `index`.
    fn field(&self, index: usize) -> Fp {
        Option::from(Fp::from_repr(self.0[index])).expect("canonical element")
    }
}

/// Canonical encodings of field elements.
fn encode(fields: &[Fp]) -> Vec<[u8; 32]> {
    fields.iter().map(PrimeField::to_repr).collect()
}

/// The G1 core of `items` (core element order).
fn core_of(items: &Items<'_>) -> CoreState<Fp> {
    CoreState {
        lifecycle: u8::try_from(items.integer(0)).expect("lifecycle tag"),
        identity: Identity {
            scheme_id: items.digest(1),
            asset_digest: items.digest(3),
            wallet_id: items.digest(5),
            credential_digest: items.digest(7),
        },
        balance: items.integer(9),
        burned_total: items.integer(10),
        sequence: items.integer(11),
        next_send: items.integer(12),
        next_load: items.integer(13),
        next_redeem: items.integer(14),
        send_chain: items.field(15),
        recv_chain: items.field(16),
        roots: MapRoots {
            consumed_credit: items.field(17),
            pending_outgoing: items.field(18),
            load_redeem_recovery: items.field(19),
            fee_claim_recovery: items.field(20),
            quota_usage: items.field(21),
        },
        controls: Controls {
            enabled: items.u32(22),
            quota_windows_root: items.field(23),
            blacklist_version: items.u64(24),
            blacklist_root: items.field(25),
            blacklist_issued_at_ms: items.u64(26),
            blacklist_max_age_ms: items.u64(27),
            lease_expires_at_ms: items.u64(28),
        },
        policy_epoch: items.u64(29),
        accepted_time_floor_ms: items.u64(30),
        state_nonce: items.field(31),
    }
}

/// The G1 rest of `items` (rest element order).
fn rest_of(items: &Items<'_>) -> StateRest {
    StateRest {
        permitted_controls: items.u32(0),
        time_anchor_max_response_ms: items.u64(1),
        scheme_policy: items.digest(2),
        fee_schedule: items.digest(4),
        blacklist: items.digest(6),
        quota_share: items.digest(8),
        quota_share_id: items.u64(10),
        time_anchor: items.digest(11),
    }
}

/// The Request body of the `credit_id` items (request-body order).
fn request_of(items: &Items<'_>) -> RequestBody {
    assert_eq!(items.integer(0), 1, "request version");
    RequestBody {
        scheme_id: items.digest(1),
        asset_digest: items.digest(3),
        payer_wallet: items.digest(5),
        receiver_wallet: items.digest(7),
        send_ordinal: items.integer(9),
        receiver_credential_digest: items.digest(10),
        terms: RequestTerms {
            amount: items.integer(12),
            fee_schedule: items.digest(13),
            fee: items.integer(15),
            policy_epoch: items.u64(16),
            scheme_policy: items.digest(17),
            request_time: items.u64(19),
            certificates: items.digest(20),
            nonce: items.digest(22),
        },
    }
}

/// The fixture values a witness is built from.
struct G1Vectors {
    state: StateV1<Fp>,
    commitment: Fp,
    rest_digest: Fp,
    core_items: Vec<[u8; 32]>,
    rest_items: Vec<[u8; 32]>,
    request: RequestBody,
    request_items: Vec<[u8; 32]>,
    credit_id: Fp,
    send_statement: Vec<[u8; 32]>,
    send_statement_digest: Fp,
    receive_statement: Vec<[u8; 32]>,
    receive_statement_digest: Fp,
    send_append: Vec<[u8; 32]>,
    send_chain: Fp,
    recv_append: Vec<[u8; 32]>,
    recv_chain: Fp,
}

fn g1_vectors() -> G1Vectors {
    let fixture = wallet_vectors();
    let encodings = at(&fixture, &["field_encodings"]);
    let core_items = items_at(encodings, &["receive_successor_state", "core_items"]);
    let rest_items = items_at(encodings, &["receive_successor_state", "rest_items"]);
    let request_items = items_at(&fixture, &["poseidon", "credit_id", "poseidon", "items"]);
    assert_eq!(core_items.len(), CORE_FIELDS);
    assert_eq!(rest_items.len(), REST_FIELDS);
    assert_eq!(request_items.len(), REQUEST_FIELDS);
    let field = |path: &[&str]| -> Fp {
        Option::from(Fp::from_repr(bytes_at(encodings, path))).expect("canonical value")
    };
    G1Vectors {
        state: StateV1 {
            core: core_of(&Items(&core_items)),
            rest: rest_of(&Items(&rest_items)),
        },
        commitment: field(&["receive_successor_state", "commitment_hex"]),
        rest_digest: field(&["receive_successor_state", "rest_digest_hex"]),
        request: request_of(&Items(&request_items)),
        credit_id: Option::from(Fp::from_repr(bytes_at(
            &fixture,
            &["poseidon", "credit_id", "poseidon", "digest_hex"],
        )))
        .expect("canonical credit_id"),
        send_statement: items_at(encodings, &["send_statement", "items"]),
        send_statement_digest: field(&["send_statement", "digest_hex"]),
        receive_statement: items_at(encodings, &["receive_statement", "items"]),
        receive_statement_digest: field(&["receive_statement", "digest_hex"]),
        send_append: items_at(encodings, &["send_chain_append_from_empty"]),
        send_chain: field(&["send_chain_append_from_empty_hex"]),
        recv_append: items_at(encodings, &["recv_chain_append"]),
        recv_chain: field(&["recv_chain_append_hex"]),
        core_items,
        rest_items,
        request_items,
    }
}

/// The receiver's `sigma_recv` witness of the fixture: its predecessor is
/// the fixture state (the Request's receiver), its Request the fixture's.
fn receive_witness(vectors: &G1Vectors) -> StepWitness<Fp> {
    let statement = Items(&vectors.receive_statement);
    let request = &vectors.request;
    StepWitness {
        relation_id: statement.digest(1),
        predecessor: vectors.state,
        successor_nonce: Fp::from(9_u64),
        inputs: StepInputs::Receive(Box::new(ReceiveInputs {
            payer_wallet: request.payer_wallet,
            send_ordinal: request.send_ordinal,
            receiver_credential_digest: request.receiver_credential_digest,
            request: request.terms,
            successor_consumed_credit: Fp::from(7_u64),
        })),
    }
}

/// The payer's `sigma_send` witness of the fixture: a payer state with the
/// send statement's identity and sequence, an empty send chain, the
/// Request's send ordinal, and the statement's lineage inputs, Request
/// digest and accepted interval.
fn send_witness(vectors: &G1Vectors) -> StepWitness<Fp> {
    let statement = Items(&vectors.send_statement);
    let request = &vectors.request;
    let mut core = vectors.state.core;
    core.identity = Identity {
        scheme_id: statement.digest(3),
        asset_digest: statement.digest(5),
        wallet_id: request.payer_wallet,
        credential_digest: statement.digest(7),
    };
    core.balance = 1 << 100;
    core.burned_total = 0;
    core.sequence = statement.integer(10) - 1;
    core.next_send = request.send_ordinal;
    core.next_load = statement.integer(11);
    core.send_chain = Fp::from(0_u64);
    core.controls.enabled = statement.u32(12);
    core.policy_epoch = request.terms.policy_epoch;
    core.accepted_time_floor_ms = 0;
    StepWitness {
        relation_id: statement.digest(1),
        predecessor: StateV1 {
            core,
            rest: vectors.state.rest,
        },
        successor_nonce: Fp::from(11_u64),
        inputs: StepInputs::Send(Box::new(SendInputs {
            receiver_wallet: request.receiver_wallet,
            receiver_credential_digest: request.receiver_credential_digest,
            request: request.terms,
            request_digest: statement.digest(24),
            accepted_lower: statement.u64(26),
            accepted_upper: statement.u64(27),
            lineage: LineageInputs {
                burned_total: statement.integer(13),
                pending_outgoing_root: statement.field(14),
            },
            successor_pending_outgoing: Fp::from(13_u64),
            successor_fee_claim: Fp::from(15_u64),
        })),
    }
}

/// The statement items of `witness` match the vector `expected` except the
/// two commitments (indices 15 and 16, the vector's stand-in heads); with
/// the vector's commitments substituted the digest is the vector's.
fn statement_matches(
    witness: &StepWitness<Fp>,
    relation: SigmaRelation,
    expected: &[[u8; 32]],
    digest: Fp,
) {
    let mut statement = witness.statement(relation).expect("honest statement");
    let encoded = encode(&statement.encode().expect("encoding"));
    assert_eq!(expected.len(), STATEMENT_FIELDS);
    for (index, (item, vector)) in encoded.iter().zip(expected).enumerate() {
        if index != 15 && index != 16 {
            assert_eq!(item, vector, "{relation:?} statement element {index}");
        }
    }
    let items = Items(expected);
    statement.predecessor = items.field(15);
    statement.successor = items.field(16);
    assert_eq!(
        encode(&statement.encode().expect("encoding")),
        expected.to_vec()
    );
    assert_eq!(statement.digest(), Some(digest), "{relation:?}");
}

#[test]
fn the_domains_are_the_g1_domains() {
    let fixture = wallet_vectors();
    let domains = at(&fixture, &["field_encodings", "domains"])
        .as_array()
        .expect("domains");
    let domain = |name: &str| -> u64 {
        let ascii = domains
            .iter()
            .find(|row| row.get("use").and_then(Value::as_str) == Some(name))
            .and_then(|row| row.get("ascii"))
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("domain {name}"));
        u64::from_le_bytes(ascii.as_bytes().try_into().expect("8 ASCII bytes"))
    };
    assert_eq!(domain("core"), CORE_DOMAIN);
    assert_eq!(domain("rest"), REST_DOMAIN);
    assert_eq!(domain("statement"), STATEMENT_DOMAIN);
    assert_eq!(domain("credit_id"), CREDIT_DOMAIN);
    assert_eq!(domain("send_chain"), SEND_CHAIN_DOMAIN);
    assert_eq!(domain("recv_chain"), RECEIVE_CHAIN_DOMAIN);
    // No prototype `kgsp*` domain survives.
    for row in domains {
        let ascii = row.get("ascii").and_then(Value::as_str).expect("ascii");
        assert!(ascii.starts_with("kgw"), "{ascii}");
    }
}

/// The native encodings reproduce every G1 element list and digest the
/// step relations use.
#[test]
fn native_encodings_reproduce_the_g1_vectors() {
    let vectors = g1_vectors();
    // The core and rest element lists, the rest digest and the commitment.
    let state = vectors.state;
    assert_eq!(encode(&state.core.fields()), vectors.core_items);
    assert_eq!(encode(&state.rest.fields::<Fp>()), vectors.rest_items);
    assert_eq!(state.rest.digest::<Fp>(), vectors.rest_digest);
    assert_eq!(state.commitment(), vectors.commitment);
    // credit_id over the 24 Request elements: one element.
    assert_eq!(
        encode(&vectors.request.fields::<Fp>()),
        vectors.request_items
    );
    assert_eq!(vectors.request.credit_id::<Fp>(), vectors.credit_id);
    // The receiver's witness: its Request is the vector's.
    let receive = receive_witness(&vectors);
    assert_eq!(receive.request_body(), vectors.request);
    let native = receive.evaluate(SigmaRelation::RECEIVE);
    assert!(native.is_honest(), "{:?}", native.violations);
    assert_eq!(native.digests.predecessor, vectors.commitment);
    assert_eq!(native.digests.credit, vectors.credit_id);
    // The vector's statement is the Receive that reached the fixture state
    // (sequence 5), so its predecessor had sequence 4.
    let mut earlier = receive.clone();
    earlier.predecessor.core.sequence -= 1;
    statement_matches(
        &earlier,
        SigmaRelation::RECEIVE,
        &vectors.receive_statement,
        vectors.receive_statement_digest,
    );
    // The receive chain append from the vector's chain.
    let mut appended = receive.clone();
    appended.predecessor.core.recv_chain = Items(&vectors.recv_append).field(0);
    let native = appended.evaluate(SigmaRelation::RECEIVE);
    assert_eq!(encode(&native.chain_entry), vectors.recv_append);
    assert_eq!(native.digests.chain, vectors.recv_chain);
    // The payer's witness: the send chain append from empty and the send
    // statement.
    let send = send_witness(&vectors);
    assert_eq!(send.request_body(), vectors.request);
    let native = send.evaluate(SigmaRelation::SEND);
    assert!(native.is_honest(), "{:?}", native.violations);
    assert_eq!(native.digests.credit, vectors.credit_id);
    assert_eq!(encode(&native.chain_entry), vectors.send_append);
    assert_eq!(native.digests.chain, vectors.send_chain);
    statement_matches(
        &send,
        SigmaRelation::SEND,
        &vectors.send_statement,
        vectors.send_statement_digest,
    );
}

/// The circuits compute the G1 commitment, `credit_id` and chain values in
/// circuit (every hash is also compared with the native reference during
/// synthesis), on every prefix mode.
#[test]
fn in_circuit_values_reproduce_the_g1_vectors() {
    let vectors = g1_vectors();
    for prefix in [PrefixMode::Folded, PrefixMode::Absorbed] {
        let receive_shape = smallest_shape(RelationShape::new(SigmaRelation::RECEIVE, prefix));
        let receive = receive_witness(&vectors);
        let digests = in_circuit_digests(&receive_shape, &receive);
        assert_eq!(digests.predecessor, vectors.commitment, "{prefix:?}");
        assert_eq!(digests.credit, vectors.credit_id, "{prefix:?}");
        let mut appended = receive;
        appended.predecessor.core.recv_chain = Items(&vectors.recv_append).field(0);
        assert_eq!(
            in_circuit_digests(&receive_shape, &appended).chain,
            vectors.recv_chain,
            "{prefix:?}"
        );
        let send_shape = smallest_shape(RelationShape::new(SigmaRelation::SEND, prefix));
        let digests = in_circuit_digests(&send_shape, &send_witness(&vectors));
        assert_eq!(digests.credit, vectors.credit_id, "{prefix:?}");
        assert_eq!(digests.chain, vectors.send_chain, "{prefix:?}");
    }
}

/// The named decimal integer `name` of a `controlled_state` field object.
fn named_int(fields: &Value, name: &str) -> u128 {
    at(fields, &[name])
        .as_str()
        .expect("decimal string")
        .parse()
        .unwrap_or_else(|_| panic!("decimal {name}"))
}

/// The named 32-byte value `name` of a `controlled_state` field object.
fn named_bytes(fields: &Value, name: &str) -> [u8; 32] {
    bytes_at(fields, &[name])
}

/// The named σ-field value `name` of a `controlled_state` field object.
fn named_field(fields: &Value, name: &str) -> Fp {
    Option::from(Fp::from_repr(named_bytes(fields, name))).expect("canonical value")
}

/// The G1 `controlled_state` vector built from its named fields: every core
/// and rest element is distinct, so the vector binds each position of the
/// commitment preimage to its field (owner answers Q3, Q4, Q5 and Q10).
fn controlled_state() -> (StateV1<Fp>, Value) {
    let fixture = wallet_vectors();
    let vector = at(&fixture, &["field_encodings", "controlled_state"]).clone();
    let core = at(&vector, &["core_fields"]);
    let rest = at(&vector, &["rest_fields"]);
    let u64_of = |name: &str| u64::try_from(named_int(core, name)).expect("u64 field");
    let state = StateV1 {
        core: CoreState {
            lifecycle: u8::try_from(named_int(core, "lifecycle")).expect("tag"),
            identity: Identity {
                scheme_id: named_bytes(core, "scheme_id"),
                asset_digest: named_bytes(core, "asset_digest"),
                wallet_id: named_bytes(core, "wallet_id"),
                credential_digest: named_bytes(core, "credential_digest"),
            },
            balance: named_int(core, "balance"),
            burned_total: named_int(core, "burned_total"),
            sequence: named_int(core, "sequence"),
            next_send: named_int(core, "next_send"),
            next_load: named_int(core, "next_load"),
            next_redeem: named_int(core, "next_redeem"),
            send_chain: named_field(core, "send_chain"),
            recv_chain: named_field(core, "recv_chain"),
            roots: MapRoots {
                consumed_credit: named_field(core, "consumed_credit_root"),
                pending_outgoing: named_field(core, "pending_outgoing_root"),
                load_redeem_recovery: named_field(core, "load_redeem_recovery_root"),
                fee_claim_recovery: named_field(core, "fee_claim_root"),
                quota_usage: named_field(core, "quota_usage_root"),
            },
            controls: Controls {
                enabled: u32::try_from(named_int(core, "enabled_controls")).expect("mask"),
                quota_windows_root: named_field(core, "quota_windows_root"),
                blacklist_version: u64_of("blacklist_version"),
                blacklist_root: named_field(core, "blacklist_root"),
                blacklist_issued_at_ms: u64_of("blacklist_issued_at_ms"),
                blacklist_max_age_ms: u64_of("blacklist_max_age_ms"),
                lease_expires_at_ms: u64_of("lease_expires_at_ms"),
            },
            policy_epoch: u64_of("policy_epoch"),
            accepted_time_floor_ms: u64_of("accepted_time_floor_ms"),
            state_nonce: named_field(core, "state_nonce"),
        },
        rest: StateRest {
            permitted_controls: u32::try_from(named_int(rest, "permitted_controls")).expect("mask"),
            time_anchor_max_response_ms: u64::try_from(named_int(
                rest,
                "time_anchor_max_response_ms",
            ))
            .expect("u64 field"),
            scheme_policy: named_bytes(rest, "scheme_policy"),
            fee_schedule: named_bytes(rest, "fee_schedule"),
            blacklist: named_bytes(rest, "blacklist"),
            quota_share: named_bytes(rest, "quota_share"),
            quota_share_id: u64::try_from(named_int(rest, "quota_share_id")).expect("u64 field"),
            time_anchor: named_bytes(rest, "time_anchor"),
        },
    };
    (state, vector)
}

/// Every core and rest position of the G1 commitment preimage holds the
/// field this crate's encoding puts there, natively and in circuit: the
/// controlled vector has no two equal elements, so a swapped, dropped or
/// shifted field (for example the blacklist issue time and maximum age, the
/// one load/redeem recovery root, or scheme and asset) changes the
/// commitment.
#[test]
fn the_controlled_state_pins_every_commitment_position() {
    let (state, vector) = controlled_state();
    let core_items = items_at(&vector, &["core_items"]);
    let rest_items = items_at(&vector, &["rest_items"]);
    assert_eq!(encode(&state.core.fields()), core_items);
    assert_eq!(encode(&state.rest.fields::<Fp>()), rest_items);
    let distinct = core_items.iter().collect::<std::collections::BTreeSet<_>>();
    assert_eq!(distinct.len(), CORE_FIELDS, "distinct core elements");
    let distinct = rest_items.iter().collect::<std::collections::BTreeSet<_>>();
    assert_eq!(distinct.len(), REST_FIELDS, "distinct rest elements");
    let field = |key: &str| -> Fp {
        Option::from(Fp::from_repr(bytes_at(&vector, &[key]))).expect("canonical value")
    };
    assert_eq!(state.rest.digest::<Fp>(), field("rest_digest_hex"));
    let commitment = field("commitment_hex");
    assert_eq!(state.commitment(), commitment);

    // The circuits open the same commitment: a `sigma_recv` from the
    // controlled state (Retiring, every control enabled) under a Request
    // quoted with another receiver credential digest (owner answer Q8).
    let identity = state.core.identity;
    let terms = RequestTerms {
        amount: 5,
        fee_schedule: [0x5c; 32],
        fee: 1,
        policy_epoch: 3,
        scheme_policy: [0x5d; 32],
        request_time: 4,
        certificates: [0x5e; 32],
        nonce: [0x5f; 32],
    };
    let witness = StepWitness {
        relation_id: [0x42; 32],
        predecessor: state,
        successor_nonce: Fp::from(17_u64),
        inputs: StepInputs::Receive(Box::new(ReceiveInputs {
            payer_wallet: [0x5a; 32],
            send_ordinal: 9,
            receiver_credential_digest: [0x5b; 32],
            request: terms,
            successor_consumed_credit: Fp::from(19_u64),
        })),
    };
    assert_ne!(
        witness.request_body().receiver_credential_digest,
        identity.credential_digest
    );
    assert_eq!(witness.request_body().receiver_wallet, identity.wallet_id);
    let native = witness.evaluate(SigmaRelation::RECEIVE);
    assert!(native.is_honest(), "{:?}", native.violations);
    assert_eq!(native.digests.predecessor, commitment);
    for prefix in [PrefixMode::Folded, PrefixMode::Absorbed] {
        let shape = smallest_shape(RelationShape::new(SigmaRelation::RECEIVE, prefix));
        assert_eq!(
            in_circuit_digests(&shape, &witness).predecessor,
            commitment,
            "{prefix:?}"
        );
    }
}

/// Bytes of a hex string of any even length.
fn hex_bytes(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0, "even hex length");
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).expect("hex digit"))
        .collect()
}

/// The domain word of an 8-byte ASCII label.
fn domain_of(label: &str) -> u64 {
    u64::from_le_bytes(label.as_bytes().try_into().expect("8-byte domain"))
}

/// The G1 `P_bytes` element list (wire record section 1): the byte length as
/// one element, then the 31-byte little-endian chunks, the last zero-filled.
fn packed(bytes: &[u8]) -> Vec<Fp> {
    let mut items = vec![Fp::from(u64::try_from(bytes.len()).expect("length"))];
    for chunk in bytes.chunks(31) {
        let mut repr = [0_u8; 32];
        repr[..chunk.len()].copy_from_slice(chunk);
        items.push(Option::from(Fp::from_repr(repr)).expect("a chunk is below 2^248"));
    }
    items
}

/// The `iroha_pasta` Poseidon reproduces every G1 domain's known answer, the
/// `P_bytes` packing rule at the empty input and the 31-byte chunk
/// boundaries, and both `proof_digest` domains and the Payment digest over
/// their vectored bodies (owner answers Q2 and Q9): the hash, domains and
/// packing a lineage relation recomputes are the data model's.
#[test]
fn the_packing_rule_and_large_input_digests_reproduce_the_g1_vectors() {
    let fixture = wallet_vectors();
    let poseidon = at(&fixture, &["poseidon"]);
    let kats = at(poseidon, &["kats"]).as_array().expect("kats");
    assert_eq!(kats.len(), 22);
    let one_two_three = [1_u64, 2, 3].map(Fp::from).to_vec();
    for kat in kats {
        let label = at(kat, &["domain"]).as_str().expect("domain");
        assert!(label.starts_with("kgw"), "{label}");
        assert_eq!(encode(&one_two_three), items_at(kat, &["items"]), "{label}");
        assert_eq!(
            hash_with_domain(domain_of(label), &one_two_three).to_repr(),
            bytes_at(kat, &["digest_hex"]),
            "{label}"
        );
    }
    let packing = at(poseidon, &["packing"]).as_array().expect("packing");
    let lengths: Vec<u64> = packing
        .iter()
        .map(|vector| at(vector, &["len"]).as_u64().expect("len"))
        .collect();
    assert_eq!(lengths, [0, 1, 30, 31, 32, 62, 63]);
    for vector in packing {
        let bytes = hex_bytes(at(vector, &["bytes_hex"]).as_str().expect("bytes"));
        let digest = at(vector, &["poseidon"]);
        let items = packed(&bytes);
        assert_eq!(
            encode(&items),
            items_at(digest, &["items"]),
            "{}",
            bytes.len()
        );
        let label = at(digest, &["domain"]).as_str().expect("domain");
        assert_eq!(
            hash_with_domain(domain_of(label), &items).to_repr(),
            bytes_at(digest, &["digest_hex"]),
            "{}",
            bytes.len()
        );
    }
    let mut large = at(poseidon, &["proof_digests"])
        .as_array()
        .expect("proof digests")
        .clone();
    large.push(at(poseidon, &["payment_digest"]).clone());
    let mut labels = Vec::new();
    for vector in &large {
        let body = hex_bytes(at(vector, &["body_hex"]).as_str().expect("body"));
        let items = packed(&body);
        let elements = at(vector, &["elements"]).as_u64().expect("elements");
        assert_eq!(u64::try_from(items.len()).expect("count"), elements);
        let label = at(vector, &["domain"]).as_str().expect("domain");
        assert_eq!(
            hash_with_domain(domain_of(label), &items).to_repr(),
            bytes_at(vector, &["digest_hex"]),
            "{label}"
        );
        labels.push(label.to_owned());
    }
    assert_eq!(labels, ["kgwprf_1", "kgwstep1", "kgwpay_1"]);
}

fn parity_on<F: PoseidonField>(seeds: core::ops::Range<u64>) -> usize {
    let mut checked = 0;
    for relation in relation_shapes() {
        let shape = smallest_shape(relation);
        for seed in seeds.clone() {
            for mutation in [Mutation::None, Mutation::Overdraft, Mutation::Overflow] {
                let witness = sample_witness::<F>(seed, relation.relation, mutation);
                let native = witness.evaluate(relation.relation);
                assert_eq!(
                    in_circuit_digests(&shape, &witness),
                    native.digests,
                    "{} seed {seed} {mutation:?}",
                    relation.label()
                );
                checked += 1;
            }
        }
    }
    checked
}

#[test]
fn in_circuit_digests_equal_the_native_reference_on_both_fields() {
    assert_eq!(parity_on::<Fp>(0..2), 6 * 2 * 3);
    assert_eq!(parity_on::<Fq>(2..3), 6 * 3);
}

#[test]
#[ignore = "more witnesses; run in release"]
fn in_circuit_digests_equal_the_native_reference_on_many_witnesses() {
    assert_eq!(parity_on::<Fp>(0..16), 6 * 16 * 3);
    assert_eq!(parity_on::<Fq>(0..16), 6 * 16 * 3);
}

#[test]
fn digests_do_not_depend_on_the_prefix_mode_or_the_lanes() {
    for relation in RELATIONS {
        let witness = sample_witness::<Fp>(21, relation, Mutation::None);
        let mut seen = None;
        for prefix in [PrefixMode::Folded, PrefixMode::Absorbed] {
            for lanes in 1..=3 {
                let shape = RelationShape::new(relation, prefix);
                let params = SigmaParams::new(shape, lanes, limb_bits_for(12)).expect("params");
                let digests = in_circuit_digests(&SigmaShape::new(params, 12), &witness);
                assert_eq!(*seen.get_or_insert(digests), digests, "{prefix:?} {lanes}");
            }
        }
    }
}

#[test]
fn statement_digests_equal_the_gadget_encoding() {
    for relation in relation_shapes() {
        let shape = smallest_shape(relation);
        let witness = sample_witness::<Fp>(5, relation.relation, Mutation::None);
        let statement = witness
            .statement(relation.relation)
            .expect("honest statement");
        assert_eq!(statement.relation_id, witness.relation_id);
        assert_eq!(
            statement.enabled_controls,
            relation.relation.enabled_controls()
        );
        assert_eq!(
            Some(in_circuit_digests(&shape, &witness).statement),
            statement.digest(),
            "{}",
            relation.label()
        );
    }
    assert_eq!(folded(SigmaRelation::RECEIVE).step(), StepRelation::Receive);
}

/// Known answers of seed 0 on `Fp` (a change here is a change of the
/// measured relation).
#[test]
fn pinned_known_answers() {
    let answers = RELATIONS.map(|relation| {
        let native = sample_witness::<Fp>(0, relation, Mutation::None).evaluate(relation);
        println!(
            "KAT relation={} statement={} credit={}",
            relation.label(),
            hex(&native.digests.statement),
            hex(&native.digests.credit)
        );
        (hex(&native.digests.statement), hex(&native.digests.credit))
    });
    for ((statement, credit), (pinned_statement, pinned_credit)) in answers.iter().zip(PINNED) {
        assert_eq!(statement, pinned_statement);
        assert_eq!(credit, pinned_credit);
    }
}

/// The pinned statement digests and credit identifiers of
/// [`pinned_known_answers`], in [`RELATIONS`] order.
const PINNED: [(&str, &str); 3] = [
    (
        "c8fbc690290a2b326e62400d0d6c8a9215143af778bc27352e0fc1ee260e003b",
        "f590cb60d749732105fcc2e51ab2e31877b2f0833498228827f0789c0e2b8e18",
    ),
    (
        "3b036c87bcb6ee46a0b40691818774cef68927d03cdb1cf712748e1c09bf0320",
        "f590cb60d749732105fcc2e51ab2e31877b2f0833498228827f0789c0e2b8e18",
    ),
    (
        "01c39b5df374bc1db6b10c6b5a87b8e6446ebb3658a288754186a84fdadfd224",
        "b740c90bfa2f07fb35f41da7d3638fe81f37cb976cf2b6acc2edcc4ec31c971c",
    ),
];
