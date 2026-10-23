//! Shared strict I105 prefix, radix, checksum and controller validity controls.

use super::*;
use crate::account::prepared_decode::{AccountJsonAdmissionError, ChargedAccount};
use iroha_allocation::AllocationBudget;
use iroha_crypto::KeyPair;

fn single() -> AccountId {
    AccountId::new(
        KeyPair::try_from_seed(vec![0x71; 32], Algorithm::Ed25519)
            .unwrap()
            .public_key()
            .clone(),
    )
}
fn direct(
    literal: &str,
    pool: &AllocationBudget,
) -> Result<ChargedAccount, AccountJsonAdmissionError> {
    let source = json::to_json(literal).unwrap();
    let mut parser = json::Parser::new(&source);
    ChargedAccount::try_decode_json(&mut parser, pool)
}
fn refuse(literal: &str, pool: &AllocationBudget) {
    assert!(
        AccountId::parse_encoded(literal).is_err(),
        "ordinary accepted {literal:?}"
    );
    assert!(
        direct(literal, pool).is_err(),
        "admitted accepted {literal:?}"
    );
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn strict_literal_rejects_alternate_envelopes_padding_checksum_and_wrong_chain() {
    let _chain = ChainDiscriminantGuard::enter(753);
    let expected = single();
    let literal = expected.canonical_i105().unwrap();
    let bytes = expected
        .to_account_address()
        .unwrap()
        .canonical_bytes()
        .unwrap();
    let pool = AllocationBudget::new(1 << 20);
    let mut checksum = literal.clone();
    let final_start = checksum.char_indices().last().unwrap().0;
    let replacement = if &checksum[final_start..] == "1" {
        "2"
    } else {
        "1"
    };
    checksum.replace_range(final_start.., replacement);
    for invalid in [
        "".into(),
        " ".into(),
        "merchant@paynet".into(),
        expected.try_signatory().unwrap().to_string(),
        format!("0x{}", hex::encode(&bytes)),
        format!(" {literal}"),
        format!("{literal} "),
        literal.replacen("sora", "ｓｏｒａ", 1),
        format!("sora1{}", literal.strip_prefix("sora").unwrap()),
        checksum,
        format!("{literal}!"),
        encode_i105_literal(369, &bytes).unwrap(),
        encode_i105_literal(42, &bytes).unwrap(),
    ] {
        refuse(&invalid, &pool);
    }
}

#[test]
fn numeric_prefix_candidates_and_explicit_none_share_address_semantics() {
    let expected = single();
    let bytes = expected
        .to_account_address()
        .unwrap()
        .canonical_bytes()
        .unwrap();
    let pool = AllocationBudget::new(1 << 20);
    for chain in [1, 12, 123, 1234, 12345, 65535, 0, 369, 753] {
        let literal = encode_i105_literal(chain, &bytes).unwrap();
        let _local = ChainDiscriminantGuard::enter(753);
        let owner = ChargedAccount::try_from_encoded(&literal, None, &pool).unwrap();
        assert_eq!(owner.get(), &expected);
        assert!(owner.belongs_to(&pool));
        assert_eq!(
            AccountAddress::parse_encoded(&literal, None)
                .unwrap()
                .to_account_id()
                .unwrap(),
            expected
        );
        drop(owner);
        assert_eq!(pool.reserved_bytes(), 0);
        let owner = ChargedAccount::try_from_encoded(&literal, Some(chain), &pool).unwrap();
        assert_eq!(owner.get(), &expected);
        drop(owner);
        let wrong = chain.wrapping_add(1);
        assert!(
            matches!(ChargedAccount::try_from_encoded(&literal,Some(wrong),&pool),Err(crate::account::AccountLiteralAdmissionError::Address(AccountAddressError::UnexpectedNetworkPrefix{expected:actual,found})) if actual==wrong&&found==chain)
        );
        assert_eq!(pool.reserved_bytes(), 0);
        if literal.starts_with('n') {
            assert!(
                ChargedAccount::try_from_encoded(&literal.replacen('n', "n0", 1), None, &pool)
                    .is_err()
            );
            assert_eq!(pool.reserved_bytes(), 0);
        }
    }
}

#[test]
fn header_controller_and_multisig_canonicality_share_the_direct_destination() {
    let _chain = ChainDiscriminantGuard::enter(753);
    let pool = AllocationBudget::new(1 << 20);
    let canonical = single()
        .to_account_address()
        .unwrap()
        .canonical_bytes()
        .unwrap();
    let mut invalids = Vec::new();
    for header in [0, 3, 0x0a, 0x22, 0x12] {
        let mut bytes = canonical.clone();
        bytes[0] = header;
        invalids.push(bytes);
    }
    let mut trailing = canonical.clone();
    trailing.push(0);
    invalids.push(trailing);
    let mut extended = vec![
        canonical[0],
        CONTROLLER_SINGLE_KEY_EXTENDED_TAG,
        canonical[2],
        0,
        canonical[3],
    ];
    extended.extend_from_slice(&canonical[4..]);
    invalids.push(extended);
    let members = [0x72, 0x73]
        .into_iter()
        .map(|seed| {
            MultisigMember::new(
                KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
                    .unwrap()
                    .public_key()
                    .clone(),
                1,
            )
            .unwrap()
        })
        .collect();
    let expected = AccountId::new_multisig(MultisigPolicy::new(2, members).unwrap());
    let multi = expected
        .to_account_address()
        .unwrap()
        .canonical_bytes()
        .unwrap();
    invalids.push([&multi[..7], &multi[44..], &multi[7..44]].concat());
    invalids.push([&multi[..7], &multi[7..44], &multi[7..44]].concat());
    for (offset, value) in [(2, 2), (4, 0), (4, 3), (9, 0)] {
        let mut bytes = multi.clone();
        bytes[offset] = value;
        invalids.push(bytes);
    }
    for bytes in invalids {
        refuse(&encode_i105_literal(753, &bytes).unwrap(), &pool);
    }
    let literal = encode_i105_literal(753, &multi).unwrap();
    assert_eq!(direct(&literal, &pool).unwrap().get(), &expected);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn unsupported_key_implementation_retains_its_actual_fixed_cause() {
    let _chain = ChainDiscriminantGuard::enter(753);
    let pool = AllocationBudget::new(1 << 20);
    let algorithm = Algorithm::Gost3410_2012_256ParamSetA;
    let mut bytes = vec![0x02, 0, CurveId::from_algorithm(algorithm).as_u8(), 64];
    bytes.extend(
        hex::decode(
            include_str!("../../../../../../fixtures/account/gost256a_public_key.hex").trim(),
        )
        .unwrap(),
    );
    let literal = encode_i105_literal(753, &bytes).unwrap();
    match AccountId::parse_encoded(&literal) {
        Ok(expected) => {
            assert_eq!(direct(&literal, &pool).unwrap().get(), &expected);
        }
        Err(crate::account::AccountIdParseError::Address(
            AccountAddressError::UnsupportedImplementation(original),
        )) => {
            assert_eq!(original.algorithm, algorithm);
            assert!(
                matches!(direct(&literal,&pool),Err(AccountJsonAdmissionError::Json(json::Error::UnsupportedFeature(actual))) if actual==algorithm.as_static_str())
            );
            assert!(
                matches!(ChargedAccount::try_from_encoded(&literal,None,&pool),Err(crate::account::AccountLiteralAdmissionError::Address(AccountAddressError::UnsupportedImplementation(actual))) if actual==original)
            );
        }
        Err(error) => panic!("unexpected actual GOST owner: {error:?}"),
    }
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn shared_radix_capacity_covers_every_supported_base_and_leading_zero() {
    for base in 2..=256 {
        for source in [
            vec![0],
            vec![0, 0, 1],
            vec![255; 17],
            (0..64).collect::<Vec<u8>>(),
        ] {
            let encoded = super::encode_base_n(&source, base, &Ordinary).unwrap();
            let decoded = super::decode_base_n(&encoded, base, &Ordinary).unwrap();
            assert_eq!(&*decoded, source.as_slice(), "base {base}");
        }
    }
}

#[test]
fn zero_member_weight_precedes_later_key_and_complete_policy_validation() {
    let _chain = ChainDiscriminantGuard::enter(753);
    let members = [0x74, 0x75]
        .into_iter()
        .map(|seed| {
            MultisigMember::new(
                KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
                    .unwrap()
                    .public_key()
                    .clone(),
                1,
            )
            .unwrap()
        })
        .collect();
    let expected = AccountId::new_multisig(MultisigPolicy::new(2, members).unwrap());
    let canonical = expected
        .to_account_address()
        .unwrap()
        .canonical_bytes()
        .unwrap();
    let pool = AllocationBudget::new(1 << 20);
    // Header(2), version(1), threshold(2), count(2), then fixed member header(5)
    // and 32 Ed25519 bytes. Length preflight still passes for the short later key.
    assert_eq!(canonical.len(), 7 + 2 * (5 + 32));
    for faults in [1u8, 2, 4, 7] {
        let mut bytes = canonical.clone();
        bytes[8..10].copy_from_slice(&0u16.to_be_bytes());
        if faults & 1 != 0 {
            bytes[2] = 2;
        }
        if faults & 2 != 0 {
            bytes[3..5].copy_from_slice(&0u16.to_be_bytes());
        }
        if faults & 4 != 0 {
            bytes[47..49].copy_from_slice(&31u16.to_be_bytes());
            bytes.pop();
        }
        let literal = encode_i105_literal(753, &bytes).unwrap();
        assert!(matches!(
            AccountAddress::parse_encoded(&literal, None),
            Err(AccountAddressError::InvalidMultisigPolicy(
                MultisigPolicyError::MemberWeightZero
            ))
        ));
        assert!(matches!(
            AccountId::parse_encoded(&literal),
            Err(crate::account::AccountIdParseError::Address(
                AccountAddressError::InvalidMultisigPolicy(MultisigPolicyError::MemberWeightZero)
            ))
        ));
        assert!(matches!(
            ChargedAccount::try_from_encoded(&literal, None, &pool),
            Err(crate::account::AccountLiteralAdmissionError::Address(
                AccountAddressError::InvalidMultisigPolicy(MultisigPolicyError::MemberWeightZero)
            ))
        ));
        assert_eq!(pool.reserved_bytes(), 0);
        // Restoring the first weight exposes the distinct later fault; the earlier
        // result cannot have come from an unrelated final validation failure.
        bytes[8..10].copy_from_slice(&1u16.to_be_bytes());
        let later = encode_i105_literal(753, &bytes).unwrap();
        let error = AccountAddress::parse_encoded(&later, None).unwrap_err();
        assert!(!matches!(
            error,
            AccountAddressError::InvalidMultisigPolicy(MultisigPolicyError::MemberWeightZero)
        ));
    }
}
