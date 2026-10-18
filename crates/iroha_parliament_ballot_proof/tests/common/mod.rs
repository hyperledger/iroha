//! Shared test support: the prototype's deterministic fixtures and the vector
//! file reader. The fixture inputs are opaque test byte strings, not Norito
//! encodings.
#![allow(dead_code)]

use std::collections::HashMap;

use iroha_parliament_ballot_proof::{
    credential::{
        CredentialSecret, RegistrationContext, body_digest, policy_hash, proposal_digest,
        scope_digest,
    },
    framing::{BodyContext, Commitment, Digest64, OpaqueField},
    profile::{Profile, Row},
    registration::RegistrationStatement,
    sealed_list::SealedList,
    vote::{Vote, VoteStatement},
};
use sha3::digest::{ExtendableOutput, Update, XofReader};

/// `Enc(body_context)` of the fixtures.
pub const ENC_BODY: &[u8] = b"enc:body_context:fixture-body-1";
/// The six other opaque inputs of the fixtures, in `m_reg` order.
pub const ENCS: [&[u8]; 6] = [
    b"enc:network_id:fixture-net",
    b"enc:authority:fixture-authority",
    b"enc:assignment_id:0001",
    b"enc:governance_attempt_id:0007",
    b"enc:election_attempt_id:0003",
    b"enc:body_role:member",
];
/// `Enc(canonical_proposal_content)` of the fixtures.
pub const ENC_PROPOSAL: &[u8] = b"enc:canonical_proposal_content:fixture-proposal";
/// `Enc(body_instance_id)` of the fixtures.
pub const ENC_BODY_INSTANCE: &[u8] = b"enc:body_instance_id:fixture-instance";
/// `Enc(complete_frozen_policy)` of the fixtures.
pub const ENC_POLICY: &[u8] = b"enc:complete_frozen_policy:fixture-policy";

/// SHAKE256 of the concatenation of `parts`, `len` bytes.
pub fn shake256(parts: &[&[u8]], len: usize) -> Vec<u8> {
    let mut sponge = sha3::Shake256::default();
    for part in parts {
        sponge.update(part);
    }
    let mut out = vec![0u8; len];
    sponge.finalize_xof().read(&mut out);
    out
}

/// The 64-byte SHAKE256 digest the vector files use.
pub fn shake256_64(data: &[u8]) -> Vec<u8> {
    shake256(&[data], 64)
}

/// The prototype's fixture derivation: SHAKE256 of a labelled string.
pub fn fx(label: &str, len: usize) -> Vec<u8> {
    shake256(&[b"PARL-ballot-proto/fixture/v1/", label.as_bytes()], len)
}

/// Decode a hexadecimal string.
pub fn hex(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2), "odd hex length");
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).expect("hex digits"))
        .collect()
}

/// A vector file: `name = hex` lines.
pub struct Vector(HashMap<String, Vec<u8>>);

impl Vector {
    /// Parse the text of a vector file.
    pub fn parse(text: &str) -> Self {
        let mut map = HashMap::new();
        for line in text.lines() {
            if line.starts_with('#') || line.trim().is_empty() {
                continue;
            }
            let (name, value) = line.split_once(" = ").expect("name = hex");
            assert!(
                map.insert(name.to_owned(), hex(value.trim())).is_none(),
                "duplicate {name}"
            );
        }
        Self(map)
    }

    /// The bytes of `name`.
    pub fn get(&self, name: &str) -> &[u8] {
        self.0
            .get(name)
            .unwrap_or_else(|| panic!("the vector has no {name}"))
    }

    /// A little-endian integer field.
    pub fn int(&self, name: &str) -> usize {
        self.get(name)
            .iter()
            .rev()
            .fold(0usize, |acc, byte| (acc << 8) | usize::from(*byte))
    }

    /// Whether the vector has `name`.
    pub fn has(&self, name: &str) -> bool {
        self.0.contains_key(name)
    }
}

/// The prototype's name of a row.
pub fn row_label(row: Row) -> &'static str {
    match row {
        Row::Candidate => "fast",
        #[cfg(feature = "diagnostics")]
        Row::Comparator => "comparator",
    }
}

/// Copy a slice into an array.
pub fn array<const N: usize>(bytes: &[u8]) -> [u8; N] {
    <[u8; N]>::try_from(bytes).expect("exact length")
}

/// An opaque field of the fixtures.
pub fn opaque(bytes: &[u8]) -> OpaqueField {
    OpaqueField::new(bytes).expect("within the bound")
}

/// The body context of the fixtures.
pub fn body_context() -> BodyContext {
    BodyContext::new(ENC_BODY).expect("within the bound")
}

/// The registration context built from six opaque strings.
pub fn context_of(encs: [&[u8]; 6]) -> RegistrationContext {
    RegistrationContext {
        network_id: opaque(encs[0]),
        authority: opaque(encs[1]),
        assignment_id: opaque(encs[2]),
        governance_attempt_id: opaque(encs[3]),
        election_attempt_id: opaque(encs[4]),
        body_role: opaque(encs[5]),
    }
}

/// The secret bytes of fixture member `j`.
pub fn member_secret(j: usize) -> [u8; 48] {
    array(&fx(&format!("member-sk-{j}"), 48))
}

/// The secret that is no member's.
pub fn other_secret() -> [u8; 48] {
    array(&fx("other-sk", 48))
}

/// A credential secret from bytes.
pub fn secret(bytes: &[u8; 48]) -> CredentialSecret {
    CredentialSecret::from_bytes(bytes)
}

/// `B` of the fixtures.
pub fn fixture_body_digest() -> Digest64 {
    body_digest(&body_context()).expect("frame")
}

/// A registration fixture.
pub struct RegCase {
    /// The row.
    pub row: Row,
    /// The statement of member 0.
    pub statement: RegistrationStatement,
    /// The secret of member 0.
    pub secret: [u8; 48],
    /// The proving tape.
    pub tape: [u8; 112],
}

/// The prototype's `reg_case(row)`.
pub fn reg_case(row: Row) -> RegCase {
    let profile = Profile::new(row).expect("tables");
    let secret_bytes = member_secret(0);
    let statement = RegistrationStatement::for_secret(
        &profile,
        &secret(&secret_bytes),
        body_context(),
        context_of(ENCS),
    )
    .expect("statement");
    RegCase {
        row,
        statement,
        secret: secret_bytes,
        tape: array(&fx(&format!("tape/reg/{}", row_label(row)), 112)),
    }
}

/// The prototype's `member_list(s)`: the sorted commitments of members
/// `0 .. s` and their secrets in list order.
pub fn member_list(size: usize) -> (SealedList, Vec<[u8; 48]>) {
    let body = fixture_body_digest();
    let mut pairs: Vec<(Commitment, [u8; 48])> = (0..size)
        .map(|j| {
            let bytes = member_secret(j);
            (secret(&bytes).commitment(&body), bytes)
        })
        .collect();
    pairs.sort_unstable();
    let list = SealedList::new(pairs.iter().map(|(entry, _)| *entry).collect()).expect("sealed");
    (list, pairs.into_iter().map(|(_, bytes)| bytes).collect())
}

/// `scope` of the fixtures for the proposal encoding `proposal`.
pub fn scope_for(proposal: &[u8]) -> Digest64 {
    scope_digest(
        &opaque(ENCS[0]),
        &proposal_digest(proposal).expect("frame"),
        &opaque(ENCS[3]),
        &opaque(ENC_BODY_INSTANCE),
    )
    .expect("frame")
}

/// A vote fixture.
pub struct VoteCase {
    /// The row.
    pub row: Row,
    /// The statement of the member at `index`.
    pub statement: VoteStatement,
    /// The sealed list.
    pub list: SealedList,
    /// The members' secrets in list order.
    pub secrets: Vec<[u8; 48]>,
    /// The voter's secret.
    pub secret: [u8; 48],
    /// The voter's list position.
    pub index: usize,
    /// The proving tape.
    pub tape: [u8; 112],
}

/// The prototype's `vote_case(row, s, pos)` with vote 0.
pub fn vote_case(row: Row, size: usize, index: usize) -> VoteCase {
    let (list, secrets) = member_list(size);
    let voter = secrets[index];
    let scope = scope_for(ENC_PROPOSAL);
    let statement = VoteStatement::for_secret(
        &Profile::new(row).expect("profile"),
        &secret(&voter),
        fixture_body_digest(),
        scope,
        &list,
        Vote::Aye,
        policy_hash(ENC_POLICY).expect("frame"),
    )
    .expect("statement");
    VoteCase {
        row,
        statement,
        list,
        secrets,
        secret: voter,
        index,
        tape: array(&fx(
            &format!("tape/vote/{size}/{index}/{}", row_label(row)),
            112,
        )),
    }
}

/// Flip bit `bit` of a byte string.
pub fn flip(bytes: &mut [u8], bit: usize) {
    bytes[bit / 8] ^= 1 << (bit % 8);
}

// ---------------------------------------------------------------------------
// Invalid witnesses: the semantic faults of the prototype's self-test, each with
// the statement the cheating prover and the verifier agree on and the exact set
// of constraint blocks it must violate (written from the relation, not from the
// evaluator's output).

use std::collections::BTreeSet;

use iroha_parliament_ballot_proof::{
    layout::{
        BlockKind, PERMUTATION_OFFSETS, Permutation, SELECTOR_A_OFFSET, block_of, constraint_blocks,
    },
    profile::Role,
    registration::{self, RegistrationInstance, RegistrationRelation},
    vote::{self, VoteInstance, VoteRelation},
};
use iroha_zkp_vole::{field::Gf256, quicksilver::violated_constraints};

/// A semantic fault.
pub struct Fault<S> {
    /// The prototype's name of the fault.
    pub name: &'static str,
    /// The (possibly false) statement.
    pub statement: S,
    /// The invalid extended witness.
    pub witness: Vec<u8>,
    /// The blocks it must violate, exactly.
    pub expected: BTreeSet<BlockKind>,
}

/// The transition block of `permutation`, group `group`.
pub fn transition(permutation: Permutation, group: u8) -> BlockKind {
    BlockKind::Transition { permutation, group }
}

/// The output block of `permutation`.
pub fn output(permutation: Permutation) -> BlockKind {
    BlockKind::Output { permutation }
}

fn set(kinds: &[BlockKind]) -> BTreeSet<BlockKind> {
    kinds.iter().copied().collect()
}

/// Replace the committed state `(permutation index, group)` of `witness` by the
/// one of `donor`.
pub fn splice_state(witness: &mut [u8], donor: &[u8], permutation: usize, group: usize) {
    let start = PERMUTATION_OFFSETS[permutation] / 8 + 200 * (group - 1);
    witness[start..start + 200].copy_from_slice(&donor[start..start + 200]);
}

/// Overwrite the selector words of a vote witness.
pub fn set_selectors(witness: &mut [u8], a: u32, b: u32) {
    let start = SELECTOR_A_OFFSET / 8;
    witness[start..start + 4].copy_from_slice(&a.to_le_bytes());
    witness[start + 4..start + 8].copy_from_slice(&b.to_le_bytes());
}

/// The blocks `witness` violates in the registration relation.
pub fn registration_violations(
    instance: &RegistrationInstance,
    witness: &[u8],
) -> BTreeSet<BlockKind> {
    let blocks = constraint_blocks(Role::Registration);
    violated_constraints::<Gf256, _>(&RegistrationRelation, instance.public(), witness)
        .expect("well-formed relation")
        .into_iter()
        .map(|index| block_of(&blocks, index).expect("inside the stream"))
        .collect()
}

/// The blocks `witness` violates in the vote relation.
pub fn vote_violations(instance: &VoteInstance, witness: &[u8]) -> BTreeSet<BlockKind> {
    let blocks = constraint_blocks(Role::Vote);
    violated_constraints::<Gf256, _>(&VoteRelation, instance.public(), witness)
        .expect("well-formed relation")
        .into_iter()
        .map(|index| block_of(&blocks, index).expect("inside the stream"))
        .collect()
}

/// The pad of a case's tape.
pub fn pad_of(tape: &[u8; 112]) -> [u8; 32] {
    array(&tape[48..80])
}

/// The registration faults of the prototype's self-test.
pub fn registration_faults(case: &RegCase) -> Vec<Fault<RegistrationStatement>> {
    use Permutation::{Authorization, Commitment};
    let profile = Profile::new(case.row).expect("tables");
    let pad = pad_of(&case.tape);
    let own = secret(&case.secret);
    let other = secret(&other_secret());
    let body = fixture_body_digest();
    let instance_of =
        |statement: &RegistrationStatement| statement.instance(&profile).expect("valid statement");
    let honest_instance = instance_of(&case.statement);
    let witness_for = |instance: &RegistrationInstance, who: &CredentialSecret| {
        registration::witness(instance.public(), who, &pad).to_vec()
    };
    let honest = witness_for(&honest_instance, &own);
    let foreign = witness_for(&honest_instance, &other);
    let mut out = Vec::new();

    out.push(Fault {
        name: "wrong sk",
        statement: case.statement.clone(),
        witness: foreign.clone(),
        expected: set(&[output(Commitment), output(Authorization)]),
    });

    // The public C of another member; D_reg and auth recomputed by the cheater
    // with its own secret.
    let other_commitment = secret(&member_secret(1)).commitment(&body);
    let digest = iroha_parliament_ballot_proof::credential::registration_digest(
        profile.descriptor_digest(),
        &body_context(),
        &context_of(ENCS),
        &body,
        &other_commitment,
    )
    .expect("frame");
    let statement = RegistrationStatement::new(
        body_context(),
        context_of(ENCS),
        other_commitment,
        own.authorization(&digest),
    )
    .expect("statement");
    out.push(Fault {
        name: "right sk, public C of another member",
        witness: witness_for(&instance_of(&statement), &own),
        statement,
        expected: set(&[output(Commitment)]),
    });

    // auth computed for the D_reg of another network id.
    let mut other_encs = ENCS;
    other_encs[0] = b"enc:network_id:other-net";
    let other_statement =
        RegistrationStatement::for_secret(&profile, &own, body_context(), context_of(other_encs))
            .expect("statement");
    let statement = RegistrationStatement::new(
        body_context(),
        context_of(ENCS),
        *case.statement.commitment(),
        *other_statement.auth(),
    )
    .expect("statement");
    out.push(Fault {
        name: "auth for another D_reg (states of the statement's D_reg)",
        witness: witness_for(&instance_of(&statement), &own),
        statement: statement.clone(),
        expected: set(&[output(Authorization)]),
    });
    out.push(Fault {
        name: "auth for another D_reg (states of the other D_reg)",
        witness: witness_for(&instance_of(&other_statement), &own),
        statement,
        expected: set(&[transition(Authorization, 1)]),
    });

    let mut witness = honest.clone();
    splice_state(&mut witness, &foreign, 1, 11);
    out.push(Fault {
        name: "intermediate state A_A^(22) from a different message",
        statement: case.statement.clone(),
        witness,
        expected: set(&[transition(Authorization, 11), output(Authorization)]),
    });
    let mut witness = honest;
    splice_state(&mut witness, &foreign, 0, 6);
    out.push(Fault {
        name: "intermediate state A_C^(12) from a different message",
        statement: case.statement.clone(),
        witness,
        expected: set(&[transition(Commitment, 6), transition(Commitment, 7)]),
    });
    out
}

/// The vote faults of the prototype's self-test.
pub fn vote_faults(case: &VoteCase) -> Vec<Fault<VoteStatement>> {
    use BlockKind::{PrefixA, PrefixB, Range, SumA, SumB};
    use Permutation::{Commitment, Nullifier, VoteAuthorization};
    let profile = Profile::new(case.row).expect("tables");
    let pad = pad_of(&case.tape);
    let own = secret(&case.secret);
    let other = secret(&other_secret());
    let size = case.list.size();
    let index = u16::try_from(case.index).expect("small");
    let instance_of =
        |statement: &VoteStatement| statement.instance(&profile).expect("valid statement");
    let honest_instance = instance_of(&case.statement);
    let witness_at = |instance: &VoteInstance, who: &CredentialSecret, position: u16| {
        vote::witness(instance.public(), who, position, &pad).to_vec()
    };
    let honest = witness_at(&honest_instance, &own, index);
    let foreign = witness_at(&honest_instance, &other, index);
    let (a0, b0) = (1u32 << (case.index / 32), 1u32 << (case.index % 32));
    let mut out = Vec::new();
    let mut same_statement = |name, witness, expected: &[BlockKind]| {
        out.push(Fault {
            name,
            statement: case.statement.clone(),
            witness,
            expected: set(expected),
        });
    };

    same_statement(
        "wrong sk",
        foreign.clone(),
        &[
            output(Commitment),
            output(Nullifier),
            output(VoteAuthorization),
        ],
    );
    same_statement(
        "right sk, selectors on another member",
        witness_at(
            &honest_instance,
            &own,
            u16::try_from((case.index + 1) % size).expect("small"),
        ),
        &[output(Commitment)],
    );
    same_statement(
        "index i = S encoded in the selectors",
        witness_at(&honest_instance, &own, u16::try_from(size).expect("small")),
        &[Range, output(Commitment)],
    );
    same_statement(
        "index i = 1023 encoded in the selectors",
        witness_at(&honest_instance, &own, 1023),
        &[Range, output(Commitment)],
    );
    let with_selectors = |a: u32, b: u32| {
        let mut witness = honest.clone();
        set_selectors(&mut witness, a, b);
        witness
    };
    same_statement(
        "two a bits set",
        with_selectors(a0 | (a0 << 1), b0),
        &[PrefixA, SumA],
    );
    same_statement(
        "three a bits set",
        with_selectors(a0 | (a0 << 1) | (a0 << 2), b0),
        &[PrefixA],
    );
    same_statement(
        "two b bits set",
        with_selectors(a0, b0 | (b0 << 5)),
        &[PrefixB, SumB],
    );
    same_statement(
        "three b bits set",
        with_selectors(a0, b0 | (b0 << 5) | (b0 << 9)),
        &[PrefixB],
    );
    same_statement(
        "no selector bit set",
        with_selectors(0, 0),
        &[SumA, SumB, Range, output(Commitment)],
    );

    // The same voter under another scope.
    let other_scope = scope_for(b"enc:another proposal");
    let mut other_statement = case.statement.clone();
    other_statement.scope = other_scope;
    other_statement.nullifier = own.nullifier(&other_scope);
    let other_scope_witness = witness_at(&instance_of(&other_statement), &own, index);
    let mut nullifier_only = honest.clone();
    for group in 1..=11 {
        splice_state(&mut nullifier_only, &other_scope_witness, 1, group);
    }
    same_statement(
        "nullifier states of another scope",
        nullifier_only,
        &[transition(Nullifier, 1), output(Nullifier)],
    );
    let mut witness = honest.clone();
    splice_state(&mut witness, &foreign, 0, 6);
    same_statement(
        "intermediate state A_C^(12) from a different message",
        witness,
        &[transition(Commitment, 6), transition(Commitment, 7)],
    );
    let mut witness = honest.clone();
    splice_state(&mut witness, &foreign, 1, 11);
    same_statement(
        "intermediate state A_N^(22) from a different message",
        witness,
        &[transition(Nullifier, 11), output(Nullifier)],
    );

    // The statement's scope with the nullifier of the other scope.
    let mut statement = case.statement.clone();
    statement.nullifier = own.nullifier(&other_scope);
    statement.auth_v =
        own.vote_authorization(&statement.authorization_digest(&profile).expect("D_v"));
    let corrected_auth = witness_at(&instance_of(&statement), &own, index);
    out.push(Fault {
        name: "public nf of another scope (states of the statement's scope)",
        statement: statement.clone(),
        witness: corrected_auth.clone(),
        expected: set(&[output(Nullifier)]),
    });
    out.push(Fault {
        name: "public nf of another scope (states of the other scope)",
        statement,
        witness: {
            let mut witness = corrected_auth;
            for group in 1..=11 {
                splice_state(&mut witness, &other_scope_witness, 1, group);
            }
            witness
        },
        expected: set(&[transition(Nullifier, 1)]),
    });
    // Complete output coverage: each half must be enforced even when every
    // other statement value and witness state is honestly recomputed.
    for (name, auth, start, len) in [
        ("wrong low half of auth_v", true, 0, 32),
        ("wrong high half of auth_v", true, 32, 32),
        ("wrong low half of nf with recomputed auth_v", false, 0, 64),
        (
            "wrong high half of nf with recomputed auth_v",
            false,
            64,
            64,
        ),
    ] {
        let mut statement = case.statement.clone();
        if auth {
            for byte in &mut statement.auth_v.0[start..start + len] {
                *byte ^= 0xff;
            }
        } else {
            for byte in &mut statement.nullifier.0[start..start + len] {
                *byte ^= 0xff;
            }
            statement.auth_v =
                own.vote_authorization(&statement.authorization_digest(&profile).expect("D_v"));
        }
        let witness = witness_at(&instance_of(&statement), &own, index);
        out.push(Fault {
            name,
            statement,
            witness,
            expected: set(&[output(if auth { VoteAuthorization } else { Nullifier })]),
        });
    }
    out
}
