//! Actual signed Bootstrap objects for the recursive composition tests.

use ff::{Field, PrimeField};
use iroha_kagemusha_proof::{
    a_relation::bootstrap::BootstrapPolicy,
    admin_sigma::BootstrapWitness,
    operation_relation::objects::ObjectKind,
    q_signature::{
        QSignatureCircuit, QSignaturePlan, SignatureKey, SignatureSlot, SignatureWitness,
    },
};
use iroha_pasta::{Fp, Fq, poseidon::hash_with_domain};
use iroha_plonk_gadgets::{
    bytes::p_bytes_native,
    p256::{
        VerifyMode,
        native::{self, Affine, HALF_N, ORDER},
    },
    sha256::native::sha256_of_digest,
};

#[derive(Clone)]
pub struct Signed {
    pub kind: ObjectKind,
    pub bytes: Vec<u8>,
    pub signature: SignatureWitness,
}
impl Signed {
    pub fn digest(&self) -> Fp {
        let end = self.kind.body_len();
        let mut fields = vec![p_bytes_native(
            self.kind.signing_domain(),
            &self.bytes[..end],
        )];
        for offset in [16, 0, 48, 32] {
            fields.push(Fp::from_u128(u128::from_be_bytes(
                self.bytes[end + offset..end + offset + 16]
                    .try_into()
                    .unwrap(),
            )));
        }
        hash_with_domain(self.kind.object_domain(), &fields)
    }
}
fn halves(value: [u64; 4]) -> [Fp; 2] {
    [
        Fp::from_u128(u128::from(value[0]) + (u128::from(value[1]) << 64)),
        Fp::from_u128(u128::from(value[2]) + (u128::from(value[3]) << 64)),
    ]
}
fn be(value: [u64; 4]) -> [u8; 32] {
    let mut out = [0; 32];
    for (dst, word) in out.chunks_exact_mut(8).zip(value.into_iter().rev()) {
        dst.copy_from_slice(&word.to_be_bytes());
    }
    out
}
pub fn key(secret: u64) -> Affine {
    native::mul(&Affine::GENERATOR, &[secret, 0, 0, 0]).unwrap()
}
pub fn sec1(point: Affine) -> Vec<u8> {
    [vec![4], be(point.x).to_vec(), be(point.y).to_vec()].concat()
}
pub fn id(a: Fp, b: Fp) -> Vec<u8> {
    let mut out = a.to_repr()[..16].to_vec();
    out.extend_from_slice(&b.to_repr()[..16]);
    out
}
pub fn small_id(a: u64, b: u64) -> Vec<u8> {
    id(Fp::from(a), Fp::from(b))
}
pub fn sign(kind: ObjectKind, mut body: Vec<u8>, secret: u64, nonce: u64) -> Signed {
    assert_eq!(body.len(), kind.body_len());
    let digest = p_bytes_native(kind.signing_domain(), &body);
    let message_bytes = sha256_of_digest(&digest);
    let message = core::array::from_fn(|i| {
        u64::from_be_bytes(message_bytes[(3 - i) * 8..(4 - i) * 8].try_into().unwrap())
    });
    let secret = [secret, 0, 0, 0];
    let nonce = [nonce, 0, 0, 0];
    let point = native::mul(&Affine::GENERATOR, &secret).unwrap();
    let r = ORDER.reduce_once(&native::mul(&Affine::GENERATOR, &nonce).unwrap().x);
    let mut s = ORDER.mul(
        &ORDER.inverse(&nonce),
        &ORDER.add(&ORDER.reduce_once(&message), &ORDER.mul(&r, &secret)),
    );
    if native::words_cmp(&s, &HALF_N).is_gt() {
        s = ORDER.neg(&s);
    }
    assert!(native::verify_prehashed(&message, &r, &s, &point));
    body.extend(be(r));
    body.extend(be(s));
    Signed {
        kind,
        bytes: body,
        signature: SignatureWitness {
            digest,
            key: [point.x, point.y],
            signature: [r, s],
        },
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Identity {
    #[default]
    Payer,
    Receiver,
}
impl Identity {
    pub const fn secret(self) -> u64 {
        match self {
            Self::Payer => 29,
            Self::Receiver => 43,
        }
    }
}
pub fn enrollment() -> (BootstrapWitness, Signed, Signed) {
    enrollment_for(Identity::Payer)
}
pub fn enrollment_for(identity: Identity) -> (BootstrapWitness, Signed, Signed) {
    enrollment_for_schemes(identity, [1, 2], [1, 2])
}
/// Signed test inputs; a differing certificate scope is deliberately invalid authorization.
pub fn enrollment_for_schemes(
    identity: Identity,
    scheme: [u128; 2],
    certificate_scheme: [u128; 2],
) -> (BootstrapWitness, Signed, Signed) {
    let mut w = super::bootstrap::witness();
    w.core[1..3].copy_from_slice(&scheme.map(Fp::from_u128));
    super::bootstrap::rebind(&mut w);
    let (account, nonce) = match identity {
        Identity::Payer => (small_id(9, 10), 37),
        Identity::Receiver => {
            w.core[5] = Fp::from(71);
            w.core[6] = Fp::from(72);
            (small_id(73, 74), 53)
        }
    };
    let mut body = 1u16.to_le_bytes().to_vec();
    body.extend(id(
        Fp::from_u128(certificate_scheme[0]),
        Fp::from_u128(certificate_scheme[1]),
    ));
    body.push(1);
    body.extend(sec1(key(17)));
    body.extend(1u64.to_le_bytes());
    let certificate = sign(ObjectKind::Certificate, body, 23, 31);
    let mut body = 1u16.to_le_bytes().to_vec();
    for offset in [1, 3, 5] {
        body.extend(id(w.core[offset], w.core[offset + 1]));
    }
    body.extend(account);
    body.extend(sec1(key(identity.secret())));
    body.extend(small_id(31, 32));
    body.push(1); // Android TEE; the issuer attests evidence identities.
    for _ in 0..2 {
        body.extend(small_id(41, 42));
        body.extend(100u64.to_le_bytes());
        for field in [1085u32, 0, 0, 0] {
            body.extend(field.to_le_bytes());
        }
    }
    body.extend(small_id(51, 52));
    body.extend(0u32.to_le_bytes());
    body.extend(0u64.to_le_bytes());
    body.extend(0u64.to_le_bytes());
    body.extend(id(w.statement[17], w.statement[18]));
    body.extend(101u64.to_le_bytes());
    body.extend(0u32.to_le_bytes());
    body.extend(0u64.to_le_bytes());
    body.extend(certificate.digest().to_repr());
    let credential = sign(ObjectKind::Credential, body, 17, nonce);
    w.core[7] = credential.digest();
    w.lineage[9..11].copy_from_slice(&halves(key(identity.secret()).x));
    w.lineage[11..13].copy_from_slice(&halves(key(identity.secret()).y));
    super::bootstrap::rebind(&mut w);
    (w, certificate, credential)
}
pub fn receipt(w: &BootstrapWitness, sigma: &[u8]) -> Signed {
    receipt_for(w, sigma, Identity::Payer)
}
pub fn receipt_for(w: &BootstrapWitness, sigma: &[u8], identity: Identity) -> Signed {
    let mut tape = u32::try_from(sigma.len()).unwrap().to_le_bytes().to_vec();
    tape.extend_from_slice(sigma);
    let proof_digest = p_bytes_native(u64::from_le_bytes(*b"kgwstep1"), &tape);
    let operation = hash_with_domain(
        u64::from_le_bytes(*b"kgwopid1"),
        &[
            w.core[5],
            w.core[6],
            Fp::ONE,
            w.statement[17],
            w.statement[18],
        ],
    );
    let statement = hash_with_domain(
        iroha_plonk_gadgets::statement::STATEMENT_DOMAIN,
        &w.statement,
    );
    let mut body = 1u16.to_le_bytes().to_vec();
    body.extend(id(w.core[1], w.core[2]));
    body.extend(id(w.core[5], w.core[6]));
    body.extend(small_id(31, 32));
    body.extend(0u128.to_le_bytes());
    for v in [operation, Fp::ZERO, w.lineage[5], statement, proof_digest] {
        body.extend(v.to_repr());
    }
    body.extend(small_id(101, 102));
    body.extend(Fp::ZERO.to_repr());
    sign(ObjectKind::Receipt, body, identity.secret(), 41)
}
pub fn policy() -> BootstrapPolicy {
    BootstrapPolicy::new([31, 32], key(23)).unwrap()
}
pub fn signatures(objects: &[Signed; 3]) -> (QSignatureCircuit, [Vec<Fq>; 1]) {
    let slots = vec![
        SignatureSlot {
            mode: VerifyMode::Hard,
            key: SignatureKey::Variable,
        },
        SignatureSlot {
            mode: VerifyMode::Hard,
            key: SignatureKey::Variable,
        },
        SignatureSlot {
            mode: VerifyMode::Hard,
            key: SignatureKey::Fixed(key(23)),
        },
    ];
    let witnesses = [2, 1, 0].map(|i| objects[i].signature).to_vec();
    let c = QSignatureCircuit::new(QSignaturePlan::new(slots).unwrap(), witnesses).unwrap();
    let instances = c.instances(&[true; 3]).unwrap();
    (c, instances)
}
