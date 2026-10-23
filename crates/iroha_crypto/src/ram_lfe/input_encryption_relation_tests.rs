//! Offline composition of the existing RAM-LFE input and BGV equation oracles.
//! This does not create a client proof, input commitment or admission route.
use super::RamLfeReferenceInputV1;
use iroha_fhe::bgv::{
    BgvParameters, BgvProfile, Plaintext, SlotEncoding,
    fixtures::{self, FixtureEntropy},
};
use zeroize::Zeroizing;

fn profile() -> BgvProfile {
    BgvProfile::new(BgvParameters::derive(8, 257, (40, 3), (41, 2), 2).expect("parameters"))
        .expect("profile")
}

// Test composition only: scalar-subalgebra validation comes from SlotEncoding,
// and all 64 input constraints come from the canonical RAM-LFE input owner.
fn is_input(encoding: &SlotEncoding, plaintext: &Plaintext) -> bool {
    let Ok(slots) = encoding.decode(plaintext) else {
        return false;
    };
    if slots.len() != 128 || slots[64..].iter().any(|&x| x != 0) {
        return false;
    }
    let mut input = Zeroizing::new([0_u16; 64]);
    for (to, &from) in input.iter_mut().zip(&slots[..64]) {
        let Ok(value) = u16::try_from(from) else {
            return false;
        };
        *to = value;
    }
    RamLfeReferenceInputV1::from_slots(&*input).is_ok()
}

#[test]
fn empty_and_maximum_byte_inputs_bind_all_slots_and_fresh_encryption() {
    let p = profile();
    let encoding = SlotEncoding::new(&p).expect("encoding");
    assert_eq!(encoding.slots(), 128);
    assert_eq!(encoding.stride(), 2);
    let secret = fixtures::secret_key(&p, &mut FixtureEntropy::new([11; 64])).expect("secret");
    let key = fixtures::public_key(&p, &secret, &mut FixtureEntropy::new([12; 64])).expect("key");
    let limit = fixtures::encryption_witness_working_bytes(&p).expect("limit");
    for bytes in [&[][..], &[255_u8; 63][..]] {
        let input = RamLfeReferenceInputV1::from_bytes(bytes).expect("input");
        let mut slots = Zeroizing::new([0_u64; 128]);
        for (to, &from) in slots.iter_mut().zip(input.slots()) {
            *to = u64::from(from);
        }
        let plaintext = encoding.encode(&p, &*slots).expect("plaintext");
        assert!(is_input(&encoding, &plaintext));
        assert_eq!(&*encoding.decode(&plaintext).expect("decoded"), &*slots);
        let (ciphertext, witness) = fixtures::encrypt_with_witness(
            &p,
            &key,
            &plaintext,
            &mut FixtureEntropy::new([13; 64]),
            limit,
        )
        .expect("witness");
        witness
            .check(&p, &key, &plaintext, &ciphertext, limit)
            .expect("exact relation");
        let opened = secret.decrypt(&p, &ciphertext).expect("opened");
        assert_eq!(opened.profile_identity(), plaintext.profile_identity());
        assert_eq!(opened.coefficients(), plaintext.coefficients());
        assert_eq!(&*encoding.decode(&opened).expect("opened slots"), &*slots);
        // Decryption returns the conservative whole-ring bound. The original
        // sparse encoding's tighter public bound is not ciphertext plaintext.
        assert_eq!(opened.bound(), Plaintext::worst_case_bound(&p));
        assert_eq!(plaintext.bound(), encoding.vector_bound());
    }
}

#[test]
fn input_relation_rejects_invalid_length_bytes_padding_and_extension_coefficients() {
    let p = profile();
    let encoding = SlotEncoding::new(&p).expect("encoding");
    assert!(RamLfeReferenceInputV1::from_bytes(&[0; 64]).is_err());
    for (length, index, value) in [
        (1, 1, 256),
        (64, 0, 64),
        (0, 1, 1),
        (1, 2, 1),
        (0, 64, 1),
        (0, 127, 1),
    ] {
        let mut slots = Zeroizing::new([0_u64; 128]);
        slots[0] = length;
        slots[index] = value;
        let plaintext = encoding.encode(&p, &*slots).expect("canonical field slots");
        assert!(
            !is_input(&encoding, &plaintext),
            "invalid case {length}/{index}/{value}"
        );
    }
    let mut coefficients = vec![0; 256];
    coefficients[1] = 1;
    let extension = Plaintext::new(&p, coefficients).expect("valid ring element");
    assert!(!is_input(&encoding, &extension));
    let mut noncanonical = Zeroizing::new([0_u64; 128]);
    noncanonical[1] = 257;
    assert!(encoding.encode(&p, &*noncanonical).is_err());
}
