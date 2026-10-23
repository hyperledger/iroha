//! Fresh canonical account fixtures for every SDK's complete-controller encoder.

use iroha_crypto::{Algorithm, KeyPair, PublicKey};
use iroha_data_model::account::{
    AccountId, MultisigMember, MultisigPolicy, address::ChainDiscriminantGuard, curve::CurveId,
};
use norito::{codec::Encode, json::Value};

#[derive(Clone, norito::Encode)]
struct PolicyFields {
    version: u8,
    threshold: u16,
    members: Vec<MemberFields>,
}
#[derive(Clone, norito::Encode)]
struct MemberFields {
    public_key: PublicKey,
    weight: u16,
}
#[derive(norito::Encode)]
enum ControllerFields {
    Single(PublicKey),
    Multisig(PolicyFields),
}

fn object<const N: usize>(entries: [(&str, Value); N]) -> Value {
    Value::Object(
        entries
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    )
}
fn text(value: impl Into<String>) -> Value {
    Value::String(value.into())
}
fn key(algorithm: Algorithm, index: u32) -> PublicKey {
    let mut seed = vec![0xA5; 32];
    seed[..4].copy_from_slice(&index.to_le_bytes());
    KeyPair::try_from_seed(seed, algorithm)
        .expect("public deterministic fixture key")
        .into_parts()
        .0
}
fn member(key: PublicKey, weight: u16) -> MultisigMember {
    MultisigMember::new(key, weight).unwrap()
}
fn account_case(name: &str, account: &AccountId) -> Value {
    let canonical = norito::encode_canonical(account).unwrap();
    assert_eq!(
        norito::decode_canonical::<AccountId>(&canonical).unwrap(),
        *account
    );
    let literal = account.canonical_i105().unwrap();
    assert_eq!(AccountId::parse_encoded(&literal).unwrap(), *account);
    let (raw, flags) = norito::codec::encode_with_header_flags(account);
    assert_eq!(
        flags, 0x02,
        "fixture advertises the canonical compact-field layout"
    );
    let policy = account.multisig_policy().map_or(Value::Null, |policy| {
        object([
            ("version", u64::from(policy.version()).into()),
            ("threshold", u64::from(policy.threshold()).into()),
            (
                "members",
                Value::Array(
                    policy
                        .members()
                        .iter()
                        .map(|member| {
                            let (algorithm, payload) = member.public_key().try_to_bytes().unwrap();
                            object([
                                ("algorithm", text(algorithm.as_static_str())),
                                (
                                    "curve_id",
                                    u64::from(CurveId::from_algorithm(algorithm).as_u8()).into(),
                                ),
                                ("public_key_hex", text(hex::encode(payload))),
                                ("weight", u64::from(member.weight()).into()),
                            ])
                        })
                        .collect(),
                ),
            ),
        ])
    });
    object([
        ("name", text(name)),
        ("i105", text(literal)),
        (
            "canonical_address_hex",
            text(account.to_canonical_hex().unwrap().trim_start_matches("0x")),
        ),
        ("account_id_payload_hex", text(hex::encode(raw))),
        ("account_id_frame_hex", text(hex::encode(canonical))),
        ("layout_flags", u64::from(flags).into()),
        ("policy", policy),
    ])
}

/// Emit checked positives and malformed external policy payloads as Norito JSON.
pub fn emit() {
    let _chain = ChainDiscriminantGuard::enter(753);
    let _layout = norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    let algorithms = [
        Algorithm::Ed25519,
        Algorithm::Secp256k1,
        Algorithm::BlsNormal,
        Algorithm::BlsSmall,
        Algorithm::MlDsa,
        Algorithm::Gost3410_2012_256ParamSetA,
        Algorithm::Gost3410_2012_256ParamSetB,
        Algorithm::Gost3410_2012_256ParamSetC,
        Algorithm::Gost3410_2012_512ParamSetA,
        Algorithm::Gost3410_2012_512ParamSetB,
        Algorithm::Sm2,
    ];
    let keys: Vec<_> = algorithms
        .into_iter()
        .enumerate()
        .map(|(index, algorithm)| {
            key(
                algorithm,
                u32::try_from(index).expect("fixture algorithm index fits u32"),
            )
        })
        .collect();
    let mut positives = Vec::new();
    for public_key in &keys {
        let algorithm = public_key.try_algorithm().unwrap();
        let account = AccountId::new(public_key.clone());
        assert_eq!(
            ControllerFields::Single(public_key.clone()).encode(),
            account.encode()
        );
        positives.push(account_case(algorithm.as_static_str(), &account));
    }
    let base = MultisigPolicy::new(
        2,
        vec![
            member(key(Algorithm::Ed25519, 11), 1),
            member(key(Algorithm::Ed25519, 22), 2),
        ],
    )
    .unwrap();
    positives.push(account_case(
        "weighted-two",
        &AccountId::new_multisig(base.clone()),
    ));
    positives.push(account_case(
        "threshold-three",
        &AccountId::new_multisig(MultisigPolicy::new(3, base.members().to_vec()).unwrap()),
    ));
    positives.push(account_case(
        "weights-swapped",
        &AccountId::new_multisig(
            MultisigPolicy::new(
                2,
                base.members()
                    .iter()
                    .map(|m| member(m.public_key().clone(), 3 - m.weight()))
                    .collect(),
            )
            .unwrap(),
        ),
    ));
    positives.push(account_case(
        "all-eleven-algorithms",
        &AccountId::new_multisig(
            MultisigPolicy::new(
                11,
                keys.into_iter()
                    .enumerate()
                    .map(|(index, key)| {
                        member(
                            key,
                            u16::try_from(index + 1).expect("fixture member weight fits u16"),
                        )
                    })
                    .collect(),
            )
            .unwrap(),
        ),
    ));
    positives.push(account_case(
        "members-256",
        &AccountId::new_multisig(
            MultisigPolicy::new(
                256,
                (0..256)
                    .map(|index| member(key(Algorithm::Ed25519, 1000 + index), 1))
                    .collect(),
            )
            .unwrap(),
        ),
    ));

    let fields = PolicyFields {
        version: 1,
        threshold: 2,
        members: base
            .members()
            .iter()
            .map(|m| MemberFields {
                public_key: m.public_key().clone(),
                weight: m.weight(),
            })
            .collect(),
    };
    assert_eq!(
        ControllerFields::Multisig(fields.clone()).encode(),
        AccountId::new_multisig(base).encode()
    );
    let mut malformed = Vec::new();
    let mut p = fields.clone();
    p.members.reverse();
    malformed.push(("reordered", p));
    let mut p = fields.clone();
    p.members[1] = p.members[0].clone();
    p.members[1].weight = 2;
    malformed.push(("duplicate-key-different-weight", p));
    let mut p = fields.clone();
    p.version = 2;
    malformed.push(("version-two", p));
    let mut p = fields.clone();
    p.threshold = 0;
    malformed.push(("zero-threshold", p));
    let mut p = fields.clone();
    p.threshold = 4;
    malformed.push(("unreachable-threshold", p));
    let mut p = fields.clone();
    p.members[0].weight = 0;
    malformed.push(("zero-member-weight", p));
    let mut p = fields;
    p.members.clear();
    malformed.push(("empty-members", p));
    let negatives = malformed
        .into_iter()
        .map(|(name, fields)| {
            let (raw, flags) =
                norito::codec::encode_with_header_flags(&ControllerFields::Multisig(fields));
            assert_eq!(
                flags, 0x02,
                "negative fixture retains the canonical declared layout"
            );
            let framed =
                norito::core::frame_bare_with_header_flags::<AccountId>(&raw, flags).unwrap();
            assert!(
                norito::decode_canonical::<AccountId>(&framed).is_err(),
                "{name}"
            );
            object([
                ("name", text(name)),
                ("account_id_payload_hex", text(hex::encode(raw))),
                ("account_id_frame_hex", text(hex::encode(framed))),
                ("layout_flags", u64::from(flags).into()),
            ])
        })
        .collect();
    let fixture = object([
        ("schema", text("iroha.account.multisig-wire.v1")),
        ("chain_discriminant", 753u64.into()),
        ("positive", Value::Array(positives)),
        ("negative", Value::Array(negatives)),
    ]);
    println!("{}", norito::json::to_json(&fixture).unwrap());
}
