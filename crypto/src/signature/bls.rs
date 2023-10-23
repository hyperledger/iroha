#![allow(unused)]

/// Implements
/// https://eprint.iacr.org/2018/483 and
/// https://crypto.stanford.edu/~dabo/pubs/papers/BLSmultisig.html
use amcl_wrapper::{
    constants::{GroupG1_SIZE, MODBYTES},
    extension_field_gt::GT,
    field_elem::FieldElement,
    group_elem::GroupElement,
    group_elem_g1::G1,
    group_elem_g2::G2,
    types_g2::GroupG2_SIZE,
};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::Error;
// use keys::{KeyGenOption, PrivateKey as UrsaPrivateKey, PublicKey as UrsaPublicKey};
// use crate::{PublicKey, PrivateKey};
use crate::KeyGenOption;

pub const PRIVATE_KEY_SIZE: usize = MODBYTES;
/// This is a simple alias so the consumer can just use PrivateKey::random() to generate a new one
/// instead of wrapping it as a private field
pub type PrivateKey = FieldElement;

macro_rules! bls_impl {
    ($pk_size:expr, $sig_size:expr, $pk_group:ident, $sig_group:ident, $ate_2_pairing_is_one:ident, $set_pairs:ident) => {
        pub const PUBLIC_KEY_SIZE: usize = $pk_size;
        pub const SIGNATURE_SIZE: usize = $sig_size;

        pub const MESSAGE_CONTEXT: &[u8; 20] = b"for signing messages";
        pub const PUBLICKEY_CONTEXT: &[u8; 47] = b"for signing public keys for proof of possession";

        pub type Generator = $pk_group;
        pub type SignatureGroup = $sig_group;

        /// Creates a new BLS key pair
        pub fn generate(g: &Generator) -> (PublicKey, PrivateKey) {
            let sk = PrivateKey::random();
            let pk = PublicKey::new(&sk, g);
            (pk, sk)
        }

        fn hash_msg<A: AsRef<[u8]>>(message: A, context: Option<&'static [u8]>) -> SignatureGroup {
            let ctx: &[u8] = context.unwrap_or(MESSAGE_CONTEXT);
            hash_to_point(message, ctx)
        }

        fn hash_key(pk: &PublicKey, context: Option<&'static [u8]>) -> SignatureGroup {
            let ctx: &[u8] = context.unwrap_or(PUBLICKEY_CONTEXT);
            hash_to_point(pk.to_bytes(), ctx)
        }

        fn hash_to_point<A: AsRef<[u8]>>(v: A, ctx: &[u8]) -> SignatureGroup {
            let mut value = Vec::new();
            value.extend_from_slice(ctx);
            value.extend_from_slice(v.as_ref());
            SignatureGroup::from_msg_hash(value.as_slice())
        }

        pub struct Bls;

        impl Bls {
            fn new() -> Self {
                Bls
            }

            fn keypair(
                &self,
                options: Option<KeyGenOption>,
            ) -> Result<(PublicKey, PrivateKey), Error> {
                let (public_key, private_key) = match options {
                    Some(option) => match option {
                        // Follows https://datatracker.ietf.org/doc/draft-irtf-cfrg-bls-signature/?include_text=1
                        KeyGenOption::UseSeed(ref seed) => {
                            let salt = b"BLS-SIG-KEYGEN-SALT-";
                            let info = [0u8, PRIVATE_KEY_SIZE as u8]; // key_info || I2OSP(L, 2)
                            let mut ikm = vec![0u8; seed.len() + 1];
                            ikm[..seed.len()].copy_from_slice(seed); // IKM || I2OSP(0, 1)
                            let mut okm = [0u8; PRIVATE_KEY_SIZE];
                            let h = hkdf::Hkdf::<Sha256>::new(Some(&salt[..]), &ikm);
                            h.expand(&info[..], &mut okm).map_err(|err| {
                                Error::KeyGenError(format!("Failed to generate keypair: {}", err))
                            })?;
                            let private_key: PrivateKey = PrivateKey::from(&okm);
                            (
                                PublicKey::new(&private_key, &Generator::generator()),
                                private_key,
                            )
                        }
                        KeyGenOption::FromPrivateKey(ref key) => {
                            // iroha_crypto doesn't use this I think?
                            // also, we probably have to assert that the key type is BLS I think?
                            todo!()

                            // let private_key =
                            //     PrivateKey::from_bytes(key.as_ref()).map_err(|_| {
                            //         Error::ParseError(
                            //             "Failed to parse private key.".to_string(),
                            //         )
                            //     })?;
                            // (
                            //     PublicKey::new(&private_key, &Generator::generator()),
                            //     private_key,
                            // )
                        }
                    },
                    None => generate(&Generator::generator()),
                };
                Ok((public_key, private_key))
            }

            fn sign(&self, message: &[u8], sk: &PrivateKey) -> Result<Vec<u8>, Error> {
                Ok(Signature::new(message, None, sk).to_bytes())
            }

            fn verify(
                &self,
                message: &[u8],
                signature: &[u8],
                pk: &PublicKey,
            ) -> Result<bool, Error> {
                Ok(Signature::from_bytes(signature)
                    .map_err(|_| Error::ParseError("Failed to parse signature.".to_string()))?
                    .verify(message, None, pk, &Generator::generator()))
            }

            fn signature_size() -> usize {
                SIGNATURE_SIZE
            }

            fn private_key_size() -> usize {
                PRIVATE_KEY_SIZE
            }

            fn public_key_size() -> usize {
                PUBLIC_KEY_SIZE
            }
        }

        #[derive(Debug, Clone, Serialize, Deserialize)]
        pub struct PublicKey(Generator);

        impl PublicKey {
            pub fn new(sk: &PrivateKey, g: &Generator) -> Self {
                PublicKey(g * sk)
            }

            // Create an combined public key without rogue key mitigation
            pub fn combine(&mut self, pks: &[PublicKey]) {
                for pk in pks {
                    self.0 += &pk.0;
                }
            }

            pub fn to_bytes(&self) -> Vec<u8> {
                self.0.to_bytes(false)
            }

            pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
                Ok(PublicKey(
                    Generator::from_bytes(bytes)
                        .map_err(|e| Error::ParseError(format!("{:?}", e)))?,
                ))
            }
        }

        /// Represents an aggregated BLS public key that mitigates the rogue key attack
        /// for verifying aggregated signatures.
        #[derive(Debug, Clone, Serialize, Deserialize)]
        pub struct AggregatedPublicKey(Generator);

        impl From<&[PublicKey]> for AggregatedPublicKey {
            fn from(keys: &[PublicKey]) -> Self {
                // To combat the rogue key attack,
                // compute (t_1,…,t_n)←H1(pk_1,…,pk_n) ∈ R_n
                // output the aggregated public key
                // as described in section 3.1 from https://eprint.iacr.org/2018/483
                let mut bytes = Vec::new();
                for k in keys {
                    bytes.extend_from_slice(k.to_bytes().as_slice());
                }
                AggregatedPublicKey(keys.iter().fold(Generator::identity(), |apk, k| {
                    // The position of the ith public key in the byte array
                    // of the hash doesn't matter as much as its included twice.
                    // For convenience, its appended to the end
                    let mut h = bytes.clone();
                    h.extend_from_slice(k.0.to_bytes(false).as_slice());
                    apk + &k.0 * &FieldElement::from_msg_hash(h.as_slice())
                }))
            }
        }

        impl AggregatedPublicKey {
            pub fn new(keys: &[PublicKey]) -> Self {
                keys.into()
            }

            pub fn to_bytes(&self) -> Vec<u8> {
                self.0.to_bytes(false)
            }

            pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
                Ok(AggregatedPublicKey(
                    Generator::from_bytes(bytes)
                        .map_err(|e| Error::ParseError(format!("{:?}", e)))?,
                ))
            }
        }

        /// Signature over a message. One gotcha for BLS signatures
        /// is the need to mitigate rogue key attacks. There are two methods to achieve
        /// this: compute additional work to make each message distinct
        /// in a signature for each `PublicKey` or
        /// use `ProofOfPossession`. `Signature` and `ProofOfPossession` MUST
        /// use domain separation values that are different
        /// to avoid certain types of attacks and make `Signature`
        /// distinct from `ProofOfPossession`. If `ProofOfPossession`
        /// and `Signature` use the same value for `context` they are effectively the same.
        /// Don't do this. You have been warned.
        ///
        /// To make messages distinct, use `new_with_rk_mitigation`. If using
        /// proof of possession mitigation, use `new`.
        #[derive(Debug, Clone, Serialize, Deserialize)]
        pub struct Signature(SignatureGroup);

        impl Signature {
            pub fn new<A: AsRef<[u8]>>(
                message: A,
                context: Option<&'static [u8]>,
                sk: &PrivateKey,
            ) -> Self {
                Signature(hash_msg(message, context) * sk)
            }

            pub fn new_with_rk_mitigation<A: AsRef<[u8]>>(
                message: A,
                context: Option<&'static [u8]>,
                sk: &PrivateKey,
                pk_index: usize,
                pks: &[PublicKey],
            ) -> Self {
                let hash = hash_msg(message, context);
                // To combat the rogue key attack,
                // compute (t_1,…,t_n)←H1(pk_1,…,pk_n) ∈ R_n
                // output the aggregated public key
                // as described in section 3.1 from https://eprint.iacr.org/2018/483
                let mut bytes = Vec::new();
                for k in pks {
                    bytes.extend_from_slice(k.to_bytes().as_slice());
                }
                bytes.extend_from_slice(pks[pk_index].to_bytes().as_slice());
                let a = FieldElement::from_msg_hash(bytes.as_slice());
                Signature(hash * sk * &a)
            }

            // Collects multiple signatures into a single signature
            // Verified by using `verify_multi`. This method does not
            // directly mitigate the rogue key attack. It is expected the caller
            // handles this using other techniques like proof of possession
            pub fn combine(&mut self, signatures: &[Signature]) {
                for sig in signatures {
                    self.0 += &sig.0;
                }
            }

            // Verify a signature generated by `new`
            pub fn verify<A: AsRef<[u8]>>(
                &self,
                message: A,
                context: Option<&'static [u8]>,
                pk: &PublicKey,
                g: &Generator,
            ) -> bool {
                let hash = hash_msg(message, context);
                $ate_2_pairing_is_one(&g, &self.0, &pk.0, &hash)
            }

            // Caller should aggregate all signatures into `self` by using `combine`.
            // Messages must be distinct
            // `inputs` is a slice of message - public key tuples
            // Multisignature verification
            pub fn verify_multi(
                &self,
                inputs: &[(&[u8], &PublicKey)],
                context: Option<&'static [u8]>,
                g: &Generator,
            ) -> bool {
                let mut msg_check = ::std::collections::HashSet::new();
                let mut pairs = Vec::new();
                for (msg, pk) in inputs {
                    let hash = hash_msg(msg, context);
                    if msg_check.contains(&hash) {
                        return false;
                    }
                    pairs.push((pk.0.clone(), hash.clone()));
                    msg_check.insert(hash);
                }

                pairs.push((-g, self.0.clone()));
                let ate_pairs = pairs.iter().map($set_pairs).collect();
                GT::ate_multi_pairing(ate_pairs).is_one()
            }

            pub fn batch_verify(
                inputs: &[(&[u8], &Signature, &PublicKey)],
                context: Option<&'static [u8]>,
                g: &Generator,
            ) -> bool {
                // To avoid rogue key attacks, you must use proof of possession or `AggregateSignature::batch_verify`
                // This function just avoids checking for distinct messages and
                // uses batch verification as described in the end of section 3.1 from https://eprint.iacr.org/2018/483
                let mut pairs = Vec::new();
                let mut sig = SignatureGroup::identity();
                for (msg, asg, apk) in inputs {
                    let random_exponent = FieldElement::random();
                    let hash = hash_msg(msg, context);
                    sig += &asg.0 * &random_exponent;
                    pairs.push((&apk.0 * &random_exponent, hash));
                }

                pairs.push((-g, sig));

                let ate_pairs = pairs.iter().map($set_pairs).collect();
                GT::ate_multi_pairing(ate_pairs).is_one()
            }

            pub fn to_bytes(&self) -> Vec<u8> {
                self.0.to_bytes(false)
            }

            pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
                Ok(Signature(
                    SignatureGroup::from_bytes(bytes)
                        .map_err(|e| Error::ParseError(format!("{:?}", e)))?,
                ))
            }
        }

        /// Proof of possession for BLS verification key.
        /// Used as another form of rogue key mitigation
        /// where signers are known entities in a group.
        /// Virtually identical to a signature but should
        /// use a different domain separation than `Signature`.
        #[derive(Debug, Clone, Serialize, Deserialize)]
        pub struct ProofOfPossession(SignatureGroup);

        impl ProofOfPossession {
            pub fn new(pk: &PublicKey, context: Option<&'static [u8]>, sk: &PrivateKey) -> Self {
                ProofOfPossession(hash_key(pk, context) * sk)
            }

            pub fn to_bytes(&self) -> Vec<u8> {
                self.0.to_bytes(false)
            }

            pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
                Ok(ProofOfPossession(
                    SignatureGroup::from_bytes(bytes)
                        .map_err(|e| Error::ParseError(format!("{:?}", e)))?,
                ))
            }

            pub fn verify(
                &self,
                context: Option<&'static [u8]>,
                pk: &PublicKey,
                g: &Generator,
            ) -> bool {
                let hash = hash_key(pk, context);
                $ate_2_pairing_is_one(&g, &self.0, &pk.0, &hash)
            }
        }

        #[derive(Debug, Clone, Serialize, Deserialize)]
        pub struct AggregatedSignature(SignatureGroup);

        impl AggregatedSignature {
            // `Signature` should be generated by calling `Signature::new_with_rk_mitigation`
            // to avoid rogue key attacks. If using proof of possession mitigation
            // then `Signature` can be generated by calling `Signature::new`
            pub fn new(signatures: &[Signature]) -> Self {
                AggregatedSignature(
                    signatures
                        .iter()
                        .fold(SignatureGroup::identity(), |sig, s| sig + &s.0),
                )
            }

            // Verify with rogue key attack mitigation.
            pub fn verify<A: AsRef<[u8]>>(
                &self,
                message: A,
                context: Option<&'static [u8]>,
                pk: &AggregatedPublicKey,
                g: &Generator,
            ) -> bool {
                let hash = hash_msg(message, context);
                $ate_2_pairing_is_one(&g, &self.0, &pk.0, &hash)
            }

            // Verify without rogue key mitigation. Assumes caller has handled
            // rogue key mitigation some other way like proof of possession.
            // This practice is discouraged in favor of the other method
            // but there are use cases where proof of possession is better suited
            pub fn verify_no_rk<A: AsRef<[u8]>>(
                &self,
                message: A,
                context: Option<&'static [u8]>,
                pks: &[PublicKey],
                g: &Generator,
            ) -> bool {
                let apk = pks.iter().fold(Generator::identity(), |a, p| a + &p.0);
                let hash = hash_msg(message, context);
                $ate_2_pairing_is_one(&g, &self.0, &apk, &hash)
            }

            /// This should be used to verify quickly multiple BLS aggregated signatures by batching
            /// versus verifying them one by one as it reduces the number of computed pairings
            pub fn batch_verify(
                inputs: &[(
                    &[u8], /* message */
                    &AggregatedSignature,
                    &AggregatedPublicKey,
                )],
                context: Option<&'static [u8]>,
                g: &Generator,
            ) -> bool {
                // To combat the rogue key attack and avoid checking for distinct messages
                // use batch verification as described in the end of section 3.1 from https://eprint.iacr.org/2018/483
                let mut pairs = Vec::new();
                let mut sig = SignatureGroup::identity();
                for (msg, asg, apk) in inputs {
                    let random_exponent = FieldElement::random();
                    let hash = hash_msg(msg, context);
                    sig += &asg.0 * &random_exponent;
                    pairs.push((&apk.0 * &random_exponent, hash));
                }

                pairs.push((-g, sig));

                let ate_pairs = pairs.iter().map($set_pairs).collect();
                GT::ate_multi_pairing(ate_pairs).is_one()
            }

            pub fn to_bytes(&self) -> Vec<u8> {
                self.0.to_bytes(false)
            }

            pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
                Ok(AggregatedSignature(
                    SignatureGroup::from_bytes(bytes)
                        .map_err(|e| Error::ParseError(format!("{:?}", e)))?,
                ))
            }
        }
    };
}

macro_rules! bls_tests_impl {
    () => {
        #[cfg(test)]
        mod tests {
            use super::*;

            const MESSAGE_1: &[u8; 22] = b"This is a test message";
            const MESSAGE_2: &[u8; 20] = b"Another test message";
            const SEED: &[u8; 10] = &[1u8; 10];

            #[test]
            fn signature_generation_from_seed() {
                let keypair_1 = Bls
                    .keypair(Some(KeyGenOption::UseSeed(SEED.to_vec())))
                    .unwrap();
                let keypair_2 = Bls
                    .keypair(Some(KeyGenOption::UseSeed(SEED.to_vec())))
                    .unwrap();
                assert_eq!(keypair_1, keypair_2);
            }

            #[test]
            fn signature_verification() {
                let g = Generator::generator();
                let (pk, sk) = generate(&g);

                let signature_1 = Signature::new(&MESSAGE_1[..], None, &sk);
                assert!(signature_1.verify(&MESSAGE_1[..], None, &pk, &g));

                let signature_2 = Signature::new(&MESSAGE_2[..], Some(MESSAGE_CONTEXT), &sk);
                assert!(signature_2.verify(&MESSAGE_2[..], Some(MESSAGE_CONTEXT), &pk, &g));

                // Should fail for different messages
                assert!(!signature_1.verify(&MESSAGE_2[..], Some(MESSAGE_CONTEXT), &pk, &g));
                assert!(!signature_2.verify(&MESSAGE_1[..], None, &pk, &g));
            }

            #[test]
            fn proof_of_possession() {
                let g = Generator::generator();
                let (pk, sk) = generate(&g);

                let proof_of_possession_1 = ProofOfPossession::new(&pk, None, &sk);
                assert!(proof_of_possession_1.verify(None, &pk, &g));

                let ctx = b"another domain separator";
                let proof_of_possession_2 = ProofOfPossession::new(&pk, Some(ctx), &sk);
                assert!(!proof_of_possession_2.verify(None, &pk, &g));
                assert!(proof_of_possession_2.verify(Some(ctx), &pk, &g));
            }

            #[test]
            fn aggregate_signature_verification_rk() {
                const KEY_COUNT: usize = 10;

                let g = Generator::from_msg_hash(b"nothing up my sleeve for this generator");
                let mut pks = Vec::new();
                let mut sks = Vec::new();
                let mut asigs = Vec::new();
                for _ in 0..KEY_COUNT {
                    let (pk, sk) = generate(&g);

                    pks.push(pk);
                    sks.push(sk);
                }

                for i in 0..KEY_COUNT {
                    let sig = Signature::new_with_rk_mitigation(
                        &MESSAGE_1[..],
                        Some(MESSAGE_CONTEXT),
                        &sks[i],
                        i,
                        pks.as_slice(),
                    );
                    asigs.push(sig);
                }

                let apk = AggregatedPublicKey::new(pks.as_slice());
                let asg = AggregatedSignature::new(asigs.as_slice());
                assert!(asg.verify(&MESSAGE_1[..], Some(MESSAGE_CONTEXT), &apk, &g));

                // Can't verify individually because of rogue key mitigation
                for i in 0..KEY_COUNT {
                    assert!(!asigs[i].verify(&MESSAGE_1[..], Some(MESSAGE_CONTEXT), &pks[i], &g));
                }
            }

            #[test]
            fn aggregate_signature_verification_no_rk() {
                const KEY_COUNT: usize = 10;

                let g = Generator::generator();
                let mut pks = Vec::new();
                let mut sks = Vec::new();
                let mut sigs = Vec::new();
                for _ in 0..KEY_COUNT {
                    let (pk, sk) = generate(&g);

                    pks.push(pk);
                    sks.push(sk);
                }

                for i in 0..KEY_COUNT {
                    let sig = Signature::new(&MESSAGE_1[..], Some(MESSAGE_CONTEXT), &sks[i]);
                    sigs.push(sig);
                }

                let asg = AggregatedSignature::new(sigs.as_slice());
                assert!(asg.verify_no_rk(
                    &MESSAGE_1[..],
                    Some(MESSAGE_CONTEXT),
                    pks.as_slice(),
                    &g
                ));

                // Check that simple aggregation without rogue key mitigation fails
                let apk = AggregatedPublicKey::new(pks.as_slice());
                assert!(!asg.verify(&MESSAGE_1[..], Some(MESSAGE_CONTEXT), &apk, &g));

                // Can verify individually because of no rogue key mitigation
                for i in 0..KEY_COUNT {
                    assert!(sigs[i].verify(&MESSAGE_1[..], Some(MESSAGE_CONTEXT), &pks[i], &g));
                }
            }

            #[test]
            fn batch_signature_verification() {
                const KEY_COUNT: usize = 10;
                const SIG_COUNT: usize = 5;

                // First batch verification with rogue key mitigation
                let g = Generator::generator();
                let mut groups_1 = Vec::new();
                for _ in 0..SIG_COUNT {
                    let mut sks = Vec::new();
                    let mut pks = Vec::new();
                    let mut sigs = Vec::new();
                    let msg = FieldElement::random();
                    for _ in 0..KEY_COUNT {
                        let (pk, sk) = generate(&g);
                        pks.push(pk);
                        sks.push(sk);
                    }

                    for i in 0..KEY_COUNT {
                        let sig = Signature::new_with_rk_mitigation(
                            msg.to_bytes().as_slice(),
                            Some(MESSAGE_CONTEXT),
                            &sks[i],
                            i,
                            pks.as_slice(),
                        );
                        sigs.push(sig);
                    }

                    let asg = AggregatedSignature::new(sigs.as_slice());
                    let apk = AggregatedPublicKey::new(pks.as_slice());
                    //sanity check
                    assert!(asg.verify(msg.to_bytes().as_slice(), Some(MESSAGE_CONTEXT), &apk, &g));
                    groups_1.push((msg.to_bytes(), asg, apk));
                }

                let refs = groups_1
                    .iter()
                    .map(|(m, s, p)| (m.as_slice(), s, p))
                    .collect::<Vec<(&[u8], &AggregatedSignature, &AggregatedPublicKey)>>();
                assert!(AggregatedSignature::batch_verify(
                    refs.as_slice(),
                    Some(MESSAGE_CONTEXT),
                    &g
                ));

                // Second batch verification without rogue key mitigation
                let mut groups_2 = Vec::new();
                for _ in 0..SIG_COUNT {
                    let mut sks = Vec::new();
                    let mut pks = Vec::new();
                    let mut sigs = Vec::new();
                    let msg = FieldElement::random();
                    for _ in 0..KEY_COUNT {
                        let (pk, sk) = generate(&g);
                        pks.push(pk);
                        sks.push(sk);
                    }

                    for i in 0..KEY_COUNT {
                        let sig = Signature::new(
                            msg.to_bytes().as_slice(),
                            Some(MESSAGE_CONTEXT),
                            &sks[i],
                        );
                        sigs.push(sig);
                    }

                    let mut asg = sigs[0].clone();
                    asg.combine(&sigs[1..]);

                    let mut apk = pks[0].clone();
                    apk.combine(&pks[1..]);

                    //sanity check
                    assert!(asg.verify(msg.to_bytes().as_slice(), Some(MESSAGE_CONTEXT), &apk, &g));
                    groups_2.push((msg.to_bytes(), asg, apk));
                }

                let refs = groups_2
                    .iter()
                    .map(|(m, s, p)| (m.as_slice(), s, p))
                    .collect::<Vec<(&[u8], &Signature, &PublicKey)>>();
                assert!(Signature::batch_verify(
                    refs.as_slice(),
                    Some(MESSAGE_CONTEXT),
                    &g
                ));
            }

            #[test]
            fn multi_signature_verification() {
                const KEY_COUNT: usize = 10;

                let g = Generator::generator();
                let mut pks = Vec::new();
                let mut sks = Vec::new();
                let mut sigs = Vec::new();
                let mut msgs = Vec::new();
                for _ in 0..KEY_COUNT {
                    let (pk, sk) = generate(&g);

                    let msg = FieldElement::random();
                    let sig = Signature::new(msg.to_bytes().as_slice(), None, &sk);

                    pks.push(pk);
                    sks.push(sk);
                    sigs.push(sig);
                    msgs.push(msg.to_bytes());
                }
                let mut sig = sigs[0].clone();
                sig.combine(&sigs[1..]);
                let inputs = msgs
                    .iter()
                    .zip(pks.iter())
                    .map(|(msg, pk)| (msg.as_slice(), pk))
                    .collect::<Vec<(&[u8], &PublicKey)>>();

                assert!(sig.verify_multi(inputs.as_slice(), None, &g));
                msgs[0] = msgs[1].clone();
                let inputs = msgs
                    .iter()
                    .zip(pks.iter())
                    .map(|(msg, pk)| (msg.as_slice(), pk))
                    .collect::<Vec<(&[u8], &PublicKey)>>();
                assert!(!sig.verify_multi(inputs.as_slice(), None, &g));
            }
        }
    };
}

pub mod prelude {
    pub use super::{
        normal::*,
        small::{
            generate as small_generate, AggregatedPublicKey as SmallAggregatedPublicKey,
            AggregatedSignature as SmallAggregatedSignature, Generator as SmallGenerator,
            ProofOfPossession as SmallProofOfPossession, PublicKey as SmallPublicKey,
            Signature as SmallSignature, SignatureGroup as SmallSignatureGroup,
        },
        PrivateKey,
    };
}

/// This version is the small BLS signature scheme
/// with the public key group in G1 and signature group in G2.
/// 192 byte signatures and 97 byte public keys
pub mod normal {
    use super::*;

    bls_impl!(
        GroupG1_SIZE,
        GroupG2_SIZE,
        G1,
        G2,
        ate_2_pairing_g1_g2_is_one,
        set_pairs_g1_g2
    );

    bls_tests_impl!();
}

/// This version is the small BLS signature scheme
/// with the public key group in G2 and signature group in G1.
/// 97 bytes signatures and 192 byte public keys
///
/// This results in smaller signatures but slower operations and bigger public key.
/// This is good for situations where space is a consideration and verification is infrequent
pub mod small {
    use super::*;

    bls_impl!(
        GroupG2_SIZE,
        GroupG1_SIZE,
        G2,
        G1,
        ate_2_pairing_g2_g1_is_one,
        set_pairs_g2_g1
    );

    bls_tests_impl!();
}

#[inline(always)]
fn ate_2_pairing_g1_g2_is_one(p1: &G1, g1: &G2, p2: &G1, g2: &G2) -> bool {
    GT::ate_2_pairing(&-p1, g1, p2, g2).is_one()
}

#[inline(always)]
fn set_pairs_g1_g2(t: &(G1, G2)) -> (&G1, &G2) {
    (&t.0, &t.1)
}

#[inline(always)]
fn ate_2_pairing_g2_g1_is_one(p1: &G2, g1: &G1, p2: &G2, g2: &G1) -> bool {
    GT::ate_2_pairing(g1, &-p1, g2, p2).is_one()
}

#[inline(always)]
fn set_pairs_g2_g1(t: &(G2, G1)) -> (&G1, &G2) {
    (&t.1, &t.0)
}

#[cfg(test)]
mod tests {
    use amcl_wrapper::{
        constants::{GroupG1_SIZE, MODBYTES},
        field_elem::FieldElement,
        group_elem::GroupElement,
        types_g2::GroupG2_SIZE,
    };

    use super::{
        normal::{
            generate as normal_generate, Generator as NormalGenerator, Signature as NormalSignature,
        },
        small::{
            generate as small_generate, Generator as SmallGenerator, Signature as SmallSignature,
        },
    };

    #[test]
    fn size_check() {
        let msg = FieldElement::random();
        let g = NormalGenerator::generator();
        let (pk, sk) = normal_generate(&g);
        assert_eq!(sk.to_bytes().len(), MODBYTES);
        assert_eq!(pk.to_bytes().len(), GroupG1_SIZE);
        let sig = NormalSignature::new(msg.to_bytes().as_slice(), None, &sk);
        assert_eq!(sig.to_bytes().len(), GroupG2_SIZE);

        let g = SmallGenerator::generator();
        let (pk, sk) = small_generate(&g);
        assert_eq!(sk.to_bytes().len(), MODBYTES);
        assert_eq!(pk.to_bytes().len(), GroupG2_SIZE);
        let sig = SmallSignature::new(msg.to_bytes().as_slice(), None, &sk);
        assert_eq!(sig.to_bytes().len(), GroupG1_SIZE);
    }
}
