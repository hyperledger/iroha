use super::*;
use crate::vega::{
    MaskedRelaxedRandomErrorV1, MaskedRelaxedRandomSourceV1, derive_t256_generators_v1,
    sponge::keccak256,
    zk_ams::mkhe::{
        active::ZkAmsMkheActivePartySecretV1, manifest::ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1,
        packing::ZkAmsT256RotationDirectionV1,
    },
};

const ORACLE_RELEASE_MODULI_V1: [u64; 38] = [
    1_152_921_504_606_584_833,
    1_152_921_504_598_720_513,
    1_152_921_504_592_429_057,
    1_152_921_504_581_419_009,
    1_152_921_504_580_894_721,
    1_152_921_504_578_273_281,
    1_152_921_504_577_748_993,
    1_152_921_504_577_486_849,
    1_152_921_504_568_836_097,
    1_152_921_504_565_166_081,
    1_152_921_504_563_331_073,
    1_152_921_504_556_515_329,
    1_152_921_504_555_466_753,
    1_152_921_504_554_156_033,
    1_152_921_504_552_583_169,
    1_152_921_504_542_883_841,
    1_152_921_504_538_951_681,
    1_152_921_504_537_378_817,
    1_152_921_504_531_873_793,
    1_152_921_504_521_650_177,
    1_152_921_504_509_853_697,
    1_152_921_504_508_280_833,
    1_152_921_504_506_970_113,
    1_152_921_504_495_697_921,
    1_152_921_504_491_241_473,
    1_152_921_504_488_620_033,
    1_152_921_504_479_444_993,
    1_152_921_504_470_794_241,
    1_152_921_504_468_172_801,
    1_152_921_504_462_929_921,
    1_152_921_504_462_667_777,
    1_152_921_504_455_589_889,
    1_152_921_504_447_987_713,
    1_152_921_504_442_482_689,
    1_152_921_504_436_191_233,
    1_152_921_504_427_278_337,
    1_152_921_504_419_414_017,
    1_152_921_504_409_190_401,
];
const ORACLE_STATEMENT_DIGEST_V1: [u8; 32] = [
    0x0a, 0x36, 0xb1, 0xad, 0xc8, 0xec, 0x36, 0xbf, 0xcd, 0xdd, 0x02, 0x41, 0x1f, 0xc8, 0x2f, 0xe6,
    0xf8, 0xaf, 0xa0, 0xb7, 0x6b, 0xae, 0x9b, 0x9a, 0x49, 0xfa, 0x43, 0x2e, 0xdc, 0x97, 0x52, 0x0c,
];
const ORACLE_AUTHORITY_DIGEST_V1: [u8; 32] = [
    0xcd, 0x6d, 0xbe, 0xb0, 0x87, 0xca, 0x5e, 0xb0, 0x58, 0x48, 0xb9, 0x6b, 0x42, 0xea, 0x56, 0xf1,
    0x91, 0x28, 0x58, 0xbf, 0x05, 0xff, 0x1d, 0x7c, 0x3e, 0x8a, 0x46, 0x8a, 0x13, 0xdf, 0x3c, 0x04,
];
const ORACLE_SCHEDULE_DIGEST_V1: [u8; 32] = [
    0x14, 0x4c, 0x6d, 0x54, 0xf0, 0x63, 0xb8, 0x48, 0x8c, 0xe6, 0x96, 0xef, 0xc8, 0x3d, 0x79, 0x46,
    0x91, 0xfb, 0xac, 0x4b, 0x22, 0xca, 0x68, 0x5d, 0xdc, 0xfa, 0xa3, 0x3a, 0x80, 0xe8, 0x52, 0x9d,
];
const ORACLE_CONTEXT_HEX_V1: &str = concat!(
    "0101",
    "0101010101010101010101010101010101010101010101010101010101010101",
    "0202020202020202020202020202020202020202020202020202020202020202",
    "0303030303030303030303030303030303030303030303030303030303030303",
    "0404040404040404040404040404040404040404040404040404040404040404",
    "0000000000000005",
    "0606060606060606060606060606060606060606060606060606060606060606",
    "0707070707070707070707070707070707070707070707070707070707070707",
    "0808080808080808080808080808080808080808080808080808080808080808",
    "020109",
    "00000005",
    "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a",
    "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
);

fn axes_fixture() -> DirectGaloisTargetAAxesV1 {
    DirectGaloisTargetAAxesV1 {
        profile_digest: [1; 32],
        context_digest: [2; 32],
        roster_digest: [3; 32],
        key_material_digest: [4; 32],
        epoch: 5,
        transcript_digest: [6; 32],
        collective_public_key_digest: [7; 32],
        secret_lineage_root: [8; 32],
        target_tag: 2,
        evaluated_key_ordinal: 1,
        digit_index: 9,
        galois_exponent: 5,
        target_a_seed: [10; 32],
        initial_round_digest: [11; 32],
    }
}

fn oracle_context_frame(axes: &DirectGaloisTargetAAxesV1) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.push(1);
    bytes.push(1);
    bytes.extend_from_slice(&axes.profile_digest);
    bytes.extend_from_slice(&axes.context_digest);
    bytes.extend_from_slice(&axes.roster_digest);
    bytes.extend_from_slice(&axes.key_material_digest);
    bytes.extend_from_slice(&axes.epoch.to_be_bytes());
    bytes.extend_from_slice(&axes.transcript_digest);
    bytes.extend_from_slice(&axes.collective_public_key_digest);
    bytes.extend_from_slice(&axes.secret_lineage_root);
    bytes.push(axes.target_tag);
    bytes.push(axes.evaluated_key_ordinal);
    bytes.push(axes.digit_index);
    bytes.extend_from_slice(&axes.galois_exponent.to_be_bytes());
    bytes.extend_from_slice(&axes.target_a_seed);
    bytes.extend_from_slice(&axes.initial_round_digest);
    bytes
}

fn oracle_sampler_frame(axes: &DirectGaloisTargetAAxesV1, limb: u16, modulus: u64) -> Vec<u8> {
    let context = oracle_context_frame(axes);
    let mut frame = Vec::new();
    frame.extend_from_slice(b"iroha.zk-ams.v1.mkhe.direct-collective-galois-target-a-limb");
    frame.push(1);
    frame.push(1);
    frame.extend_from_slice(&(context.len() as u32).to_be_bytes());
    frame.extend_from_slice(&context);
    frame.extend_from_slice(&limb.to_be_bytes());
    frame.extend_from_slice(&modulus.to_be_bytes());
    frame.extend_from_slice(&131_072_u32.to_be_bytes());
    frame
}

fn oracle_residues(frame: &[u8], modulus: u64, count: usize) -> Vec<u64> {
    let zone = u64::MAX - u64::MAX % modulus;
    let mut stream = Shake256Reader::new(frame);
    let mut output = Vec::new();
    for _ in 0..count {
        let mut accepted = None;
        for _ in 0..128 {
            let mut bytes = [0_u8; 8];
            stream.read(&mut bytes);
            let candidate = u64::from_le_bytes(bytes);
            if candidate < zone {
                accepted = Some(candidate % modulus);
                break;
            }
        }
        output.push(accepted.expect("oracle sample must terminate"));
    }
    output
}

fn oracle_statement_digest(axes: &DirectGaloisTargetAAxesV1) -> [u8; 32] {
    let context = oracle_context_frame(axes);
    let mut hash = Keccak256::new();
    hash.update(b"iroha.zk-ams.v1.mkhe.direct-collective-galois-target-a-statement");
    hash.update(&[1, 1]);
    hash.update(&(context.len() as u32).to_be_bytes());
    hash.update(&context);
    hash.update(&131_072_u32.to_be_bytes());
    hash.update(&38_u16.to_be_bytes());
    for (limb, modulus) in ORACLE_RELEASE_MODULI_V1.iter().copied().enumerate() {
        let residues = oracle_residues(
            &oracle_sampler_frame(axes, limb as u16, modulus),
            modulus,
            131_072,
        );
        hash.update(&(limb as u16).to_be_bytes());
        hash.update(&modulus.to_be_bytes());
        hash.update(&131_072_u32.to_be_bytes());
        for residue in residues {
            hash.update(&residue.to_be_bytes());
        }
    }
    hash.finalize()
}

fn oracle_authority_digest(
    axes: &DirectGaloisTargetAAxesV1,
    statement_digest: [u8; 32],
) -> [u8; 32] {
    let context = oracle_context_frame(axes);
    let mut hash = Keccak256::new();
    hash.update(b"iroha.zk-ams.v1.mkhe.direct-collective-galois-target-a-authority");
    hash.update(&[1, 1]);
    hash.update(&(context.len() as u32).to_be_bytes());
    hash.update(&context);
    hash.update(&statement_digest);
    hash.finalize()
}

struct FixtureRandomV1 {
    seed: Vec<u8>,
    counter: u64,
}
impl FixtureRandomV1 {
    fn new(seed: &[u8]) -> Self {
        Self {
            seed: seed.to_vec(),
            counter: 0,
        }
    }
}
impl MaskedRelaxedRandomSourceV1 for FixtureRandomV1 {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), MaskedRelaxedRandomErrorV1> {
        let mut written = 0;
        while written < destination.len() {
            let mut frame = self.seed.clone();
            frame.extend_from_slice(&self.counter.to_be_bytes());
            let block = keccak256(&frame);
            let take = (destination.len() - written).min(block.len());
            destination[written..written + take].copy_from_slice(&block[..take]);
            written += take;
            self.counter = self.counter.wrapping_add(1);
        }
        Ok(())
    }
}

fn sealed_cpk_fixture_v1() -> (
    ZkAmsMkheGovernedActiveRosterV1,
    VerifiedPersistentWitnessBindingSetV1,
) {
    let mut random = FixtureRandomV1::new(b"direct-galois-target-a-roster");
    let mut secrets = (0..ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1)
        .map(|_| ZkAmsMkheActivePartySecretV1::generate(&mut random).unwrap())
        .collect::<Vec<_>>();
    secrets.sort_by_key(|secret| secret.party().unwrap());
    let secret_refs: [&ZkAmsMkheActivePartySecretV1; ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1] =
        secrets.iter().collect::<Vec<_>>().try_into().unwrap();
    let roster = ZkAmsMkheGovernedActiveRosterV1::new(77, secret_refs, &mut random).unwrap();
    let security = keccak256(b"direct-galois-target-a-security");
    let transcript = keccak256(b"direct-galois-target-a-cpk-transcript");
    let collective_key = keccak256(b"direct-galois-target-a-collective-key");
    let shares: [[u8; 32]; ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1] = core::array::from_fn(|index| {
        keccak256(&[
            b'g',
            b'a',
            b'l',
            b'o',
            b'i',
            b's',
            b'-',
            b's',
            b'h',
            b'a',
            b'r',
            b'e',
            index as u8,
        ])
    });
    let bindings = (0..ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1)
        .map(|index| {
            let mut label = b"direct-galois-target-a-party-".to_vec();
            label.push(index as u8);
            let commitments =
                derive_t256_generators_v1(&label, super::super::PERSISTENT_COMMITMENT_CHUNKS_V1)
                    .unwrap()
                    .try_into()
                    .unwrap();
            super::super::mint_test_state_owned_collective_secret_binding_v1(
                &roster,
                security,
                transcript,
                index,
                shares[index],
                commitments,
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    let binding_refs: [&super::super::VerifiedPersistentWitnessBindingV1;
        ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1] =
        bindings.iter().collect::<Vec<_>>().try_into().unwrap();
    let set = VerifiedPersistentWitnessBindingSetV1::new(
        &roster,
        transcript,
        collective_key,
        shares,
        binding_refs,
    )
    .unwrap();
    (roster, set)
}

#[test]
fn independent_oracle_pins_exact_context_schedule_and_selected_residues() {
    let axes = axes_fixture();
    let encoded = axes.encode();
    assert_eq!(encoded.as_slice(), oracle_context_frame(&axes));
    assert_eq!(encoded.len(), 305);
    assert_eq!(hex::encode(encoded), ORACLE_CONTEXT_HEX_V1);
    assert_eq!(ORACLE_CONTEXT_HEX_V1.len(), 610);

    let profile = release_profile_v1();
    assert_eq!(profile.moduli, ORACLE_RELEASE_MODULI_V1.as_slice());
    let schedule = zk_ams_t256_galois_key_schedule_v1().unwrap();
    validate_zk_ams_t256_galois_key_schedule_v1(&schedule).unwrap();
    assert_eq!(schedule.digest, ORACLE_SCHEDULE_DIGEST_V1);
    assert_eq!(
        ZK_AMS_T256_GALOIS_KEY_SCHEDULE_DIGEST_V1,
        ORACLE_SCHEDULE_DIGEST_V1
    );
    assert_eq!(
        schedule.entries[0].direction,
        ZkAmsT256RotationDirectionV1::Forward
    );
    assert_eq!(schedule.entries[0].steps, 1);
    assert_eq!(schedule.entries[0].exponent, 5);

    for limb in [0_usize, 1, 37] {
        let modulus = ORACLE_RELEASE_MODULI_V1[limb];
        let production = sampler_frame(encoded, limb as u16, modulus).unwrap();
        let oracle = oracle_sampler_frame(&axes, limb as u16, modulus);
        assert_eq!(production, oracle);
        assert_eq!(production.len(), 384);
        let expected = oracle_residues(&oracle, modulus, 4);
        let pinned: &[u64] = match limb {
            0 => &[
                535_880_340_495_844_301,
                907_819_324_993_073_828,
                328_886_067_524_583_230,
                927_505_125_797_312_203,
            ],
            1 => &[
                112_235_523_962_569_957,
                158_788_962_019_970_346,
                1_085_903_826_194_902_432,
                726_616_220_969_712_971,
            ],
            37 => &[
                411_976_486_004_721_017,
                188_848_428_455_258_017,
                575_779_727_480_523_852,
                574_405_957_684_603_671,
            ],
            _ => unreachable!(),
        };
        assert_eq!(expected, pinned);
        let mut stream = Shake256Reader::new(&production);
        let zone = u64::MAX - u64::MAX % modulus;
        let mut budget = 4 * 128;
        let observed = (0..4)
            .map(|_| {
                sample_residue(modulus, zone, &mut budget, |bytes| stream.read(bytes)).unwrap()
            })
            .collect::<Vec<_>>();
        assert_eq!(observed, expected);
    }
}

#[test]
fn independent_oracle_pins_complete_statement_and_authority_digests() {
    let axes = axes_fixture();
    let expected = oracle_statement_digest(&axes);
    let expected_authority = oracle_authority_digest(&axes, expected);
    let mut stream = DirectGaloisTargetAStatementStreamV1::begin_for_test(axes).unwrap();
    let mut workspace = vec![0_u64; 131_072];
    for _ in 0..38 {
        stream.derive_next_limb_into(&mut workspace).unwrap();
    }
    let authority = stream.finish().unwrap();
    assert_eq!(authority.statement_digest, expected);
    assert_eq!(expected, ORACLE_STATEMENT_DIGEST_V1);
    assert_eq!(authority.authority_digest, expected_authority);
    assert_eq!(expected_authority, ORACLE_AUTHORITY_DIGEST_V1);
}

#[test]
fn sealed_cpk_mint_and_poisoned_replay_are_end_to_end_typed() {
    let (roster, set) = sealed_cpk_fixture_v1();
    let target = ZkAmsMkheDirectEvaluatedKeyTargetV1::Galois { schedule_index: 0 };
    let context =
        ZkAmsMkheDirectCeremonyContextV1::from_verified_binding_set(&roster, &set, target, 9)
            .unwrap();
    let contribution = keccak256(b"direct-galois-target-a-b-statement");
    let proof_transcript = keccak256(b"direct-galois-target-a-proof-commitments");
    let selector =
        mint_galois_selector_v1(&roster, &set, context, contribution, proof_transcript).unwrap();
    assert_eq!(selector.relation, PersistentDirectRelationV1::Galois);
    assert_eq!(selector.context_digest, context.digest());
    assert_eq!(selector.prior_round_digest, context.initial_round_digest());
    assert_eq!(
        selector.evaluated_key_ordinal,
        context.evaluated_key_ordinal()
    );
    assert_eq!(selector.digit_index, context.digit_index());
    assert_eq!(selector.galois_exponent, context.galois_exponent());
    assert_eq!(selector.common_a_statement_digest, [0; 32]);
    assert_ne!(selector.target_a_statement_digest, [0; 32]);
    assert_eq!(selector.aggregate_h0_statement_digest, [0; 32]);
    assert_eq!(selector.aggregate_h1_statement_digest, [0; 32]);
    assert_eq!(selector.contribution_statement_digest, contribution);
    assert_eq!(
        selector.proof_commitment_transcript_digest,
        proof_transcript
    );

    let raw_mismatch = ZkAmsMkheDirectCeremonyContextV1::new(
        &roster,
        keccak256(b"direct-galois-target-a-wrong-transcript"),
        set.collective_public_key_digest(),
        *set.identity_digests(),
        target,
        9,
    )
    .unwrap();
    assert!(matches!(
        derive_verified_direct_galois_target_a_statement_v1(&roster, &set, raw_mismatch),
        Err(ZkAmsMkheErrorV1::InvalidKeyMaterial)
    ));

    let capability = set
        .bind_direct_relation_use(&roster, 0, None, selector)
        .unwrap();
    let other_context =
        ZkAmsMkheDirectCeremonyContextV1::from_verified_binding_set(&roster, &set, target, 8)
            .unwrap();
    assert!(DirectGaloisTargetAReplayV1::begin(other_context, &capability).is_err());
    assert_eq!(
        DirectGaloisTargetAReplayV1::begin(context, &capability)
            .unwrap()
            .finish()
            .map(|_| ()),
        Err(ZkAmsMkheErrorV1::InvalidPolynomial)
    );

    let mut workspace = vec![0_u64; ZK_AMS_MKHE_RELEASE_RING_DEGREE_V1];
    let mut poisoned = DirectGaloisTargetAReplayV1::begin(context, &capability).unwrap();
    assert_eq!(
        poisoned.derive_next_limb_into(&mut [0_u64; 1]),
        Err(ZkAmsMkheErrorV1::InvalidPolynomial)
    );
    assert_eq!(
        poisoned.derive_next_limb_into(&mut workspace),
        Err(ZkAmsMkheErrorV1::InvalidPolynomial)
    );
    assert_eq!(
        poisoned.finish().map(|_| ()),
        Err(ZkAmsMkheErrorV1::InvalidPolynomial)
    );

    let mut unwind = DirectGaloisTargetAReplayV1::begin(context, &capability).unwrap();
    unwind.inject_unwind_on_next_derive_for_test();
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        unwind.derive_next_limb_into(&mut workspace).unwrap();
    }));
    assert!(caught.is_err());
    assert_eq!(
        unwind.derive_next_limb_into(&mut workspace),
        Err(ZkAmsMkheErrorV1::InvalidPolynomial)
    );
    assert_eq!(
        unwind.finish().map(|_| ()),
        Err(ZkAmsMkheErrorV1::InvalidPolynomial)
    );

    let mut replay = DirectGaloisTargetAReplayV1::begin(context, &capability).unwrap();
    for _ in 0..DIRECT_GALOIS_TARGET_A_RELEASE_LIMBS_V1 {
        replay.derive_next_limb_into(&mut workspace).unwrap();
    }
    replay.finish().unwrap();
}

#[test]
fn every_authority_axis_is_visible_and_no_party_axis_exists() {
    let baseline = axes_fixture().encode();
    macro_rules! changed_axis {
        ($field:ident, $value:expr) => {{
            let mut axes = axes_fixture();
            axes.$field = $value;
            assert_ne!(axes.encode(), baseline);
        }};
    }
    changed_axis!(profile_digest, [21; 32]);
    changed_axis!(context_digest, [22; 32]);
    changed_axis!(roster_digest, [23; 32]);
    changed_axis!(key_material_digest, [24; 32]);
    changed_axis!(epoch, 25);
    changed_axis!(transcript_digest, [26; 32]);
    changed_axis!(collective_public_key_digest, [27; 32]);
    changed_axis!(secret_lineage_root, [28; 32]);
    changed_axis!(target_tag, 1);
    changed_axis!(evaluated_key_ordinal, 2);
    changed_axis!(digit_index, 29);
    changed_axis!(galois_exponent, 25);
    changed_axis!(target_a_seed, [30; 32]);
    changed_axis!(initial_round_digest, [31; 32]);

    let source = include_str!("direct_galois_target_a_v1.rs");
    let axes_source = source
        .split("struct DirectGaloisTargetAAxesV1")
        .nth(1)
        .unwrap()
        .split("impl DirectGaloisTargetAAxesV1")
        .next()
        .unwrap();
    assert!(!axes_source.contains("party"));
}

#[test]
fn rejection_budget_poisoning_and_resource_arithmetic_are_exact() {
    assert_eq!(DIRECT_GALOIS_TARGET_A_RESIDUES_V1, 4_980_736);
    assert_eq!(
        DIRECT_GALOIS_TARGET_A_CANONICAL_RESIDUE_BYTES_V1,
        39_845_888
    );
    assert_eq!(DIRECT_GALOIS_TARGET_A_LIMB_WORKSPACE_BYTES_V1, 1_048_576);
    assert_eq!(DIRECT_GALOIS_TARGET_A_MAX_CANDIDATES_V1, 637_534_208);
    assert_eq!(DIRECT_GALOIS_TARGET_A_SAMPLER_FRAME_BYTES_V1, 384);

    let modulus = 17;
    let zone = u64::MAX - u64::MAX % modulus;
    let mut candidates = vec![u64::MAX; 127];
    candidates.push(5);
    let mut cursor = 0;
    let mut budget = 128;
    assert_eq!(
        sample_residue(modulus, zone, &mut budget, |bytes| {
            *bytes = candidates[cursor].to_le_bytes();
            cursor += 1;
        }),
        Ok(5)
    );
    assert_eq!(cursor, 128);
    assert_eq!(budget, 0);

    let mut exhausted = 128;
    assert_eq!(
        sample_residue(modulus, zone, &mut exhausted, |bytes| {
            *bytes = u64::MAX.to_le_bytes();
        }),
        Err(ZkAmsMkheErrorV1::InvalidProfile)
    );
    assert_eq!(exhausted, 0);
    let mut empty = 0;
    assert_eq!(
        sample_residue(modulus, zone, &mut empty, |_| {}),
        Err(ZkAmsMkheErrorV1::ResourceCeilingExceeded)
    );

    let encoded = axes_fixture().encode();
    let first_modulus = release_profile_v1().moduli[0];
    assert_eq!(
        sampler_frame(encoded, 1, first_modulus),
        Err(ZkAmsMkheErrorV1::InvalidPolynomial)
    );
    assert_eq!(
        sampler_frame(encoded, 38, first_modulus),
        Err(ZkAmsMkheErrorV1::InvalidPolynomial)
    );
    let mut poisoned =
        DirectGaloisTargetAStatementStreamV1::begin_for_test(axes_fixture()).unwrap();
    assert_eq!(
        poisoned.derive_next_limb_into(&mut [0_u64; 1]),
        Err(ZkAmsMkheErrorV1::InvalidPolynomial)
    );
    let mut exact = vec![0_u64; ZK_AMS_MKHE_RELEASE_RING_DEGREE_V1];
    assert_eq!(
        poisoned.derive_next_limb_into(&mut exact),
        Err(ZkAmsMkheErrorV1::InvalidPolynomial)
    );
    assert_eq!(
        poisoned.finish().map(|_| ()),
        Err(ZkAmsMkheErrorV1::InvalidPolynomial)
    );

    let mut unwind = DirectGaloisTargetAStatementStreamV1::begin_for_test(axes_fixture()).unwrap();
    unwind.inject_unwind_on_next_derive = true;
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        unwind.derive_next_limb_into(&mut exact).unwrap();
    }));
    assert!(caught.is_err());
    assert_eq!(
        unwind.derive_next_limb_into(&mut exact),
        Err(ZkAmsMkheErrorV1::InvalidPolynomial)
    );
    assert_eq!(
        unwind.finish().map(|_| ()),
        Err(ZkAmsMkheErrorV1::InvalidPolynomial)
    );

    let source = include_str!("direct_galois_target_a_v1.rs");
    let derive = source
        .split("fn derive_next_limb_into(&mut self")
        .nth(1)
        .unwrap()
        .split("fn derive_next_limb_inner")
        .next()
        .unwrap();
    assert!(
        derive.find("self.failed = true;").unwrap()
            < derive.find("derive_next_limb_inner(output)").unwrap()
    );
    let authority = source
        .split("fn derive_verified_direct_galois_target_a_statement_v1")
        .nth(1)
        .unwrap()
        .split("fn new_galois_selector_v1")
        .next()
        .unwrap();
    assert!(authority.contains("try_reserve_exact(ZK_AMS_MKHE_RELEASE_RING_DEGREE_V1)"));
    assert!(authority.contains("workspace.resize(ZK_AMS_MKHE_RELEASE_RING_DEGREE_V1, 0_u64)"));
    assert!(!authority.contains("DIRECT_GALOIS_TARGET_A_RESIDUES_V1"));
}

#[test]
fn sealed_cpk_authority_selector_and_replay_stay_opaque_and_move_only() {
    let source = include_str!("direct_galois_target_a_v1.rs");
    let authority = source
        .split("fn derive_verified_direct_galois_target_a_statement_v1")
        .nth(1)
        .unwrap()
        .split("fn new_galois_selector_v1")
        .next()
        .unwrap();
    let validate = authority
        .find("bindings.validate_for_consumer(roster, PersistentWitnessConsumerV1::Galois)?;")
        .unwrap();
    let reconstruct = authority
        .find("ZkAmsMkheDirectCeremonyContextV1::from_verified_binding_set(")
        .unwrap();
    let equality = authority.find("if expected != context").unwrap();
    let allocate = authority.find("let mut workspace = Vec::new();").unwrap();
    assert!(validate < reconstruct && reconstruct < equality && equality < allocate);
    assert!(authority.contains("usize::from(context.digit_index())"));
    assert!(!authority.contains("identity_digests()"));
    assert!(!authority.contains("target_a_seed()"));

    let selector = source
        .split("fn new_galois_selector_v1")
        .nth(1)
        .unwrap()
        .split("/// Mint the only production Galois selector")
        .next()
        .unwrap();
    assert!(selector.contains("target_a: VerifiedDirectGaloisTargetAStatementV1"));
    assert!(selector.contains("prior_round_digest: context.initial_round_digest()"));
    assert!(selector.contains("relation: PersistentDirectRelationV1::Galois"));
    assert!(selector.contains("common_a_statement_digest: [0; 32]"));
    assert!(selector.contains("aggregate_h0_statement_digest: [0; 32]"));
    assert!(selector.contains("aggregate_h1_statement_digest: [0; 32]"));
    assert!(!selector.contains("target_a_statement_digest: [u8; 32]"));

    let mint = source
        .split("pub(super) fn mint_galois_selector_v1")
        .nth(1)
        .unwrap()
        .split("fn sampler_frame")
        .next()
        .unwrap();
    let mint_signature = mint.split('{').next().unwrap();
    assert!(!mint_signature.contains("prior_round_digest"));
    assert!(!mint_signature.contains("target_a_statement_digest"));
    assert!(!mint_signature.contains("target_a_seed"));
    assert!(!mint_signature.contains("evaluated_key_ordinal"));
    assert!(!mint_signature.contains("digit_index"));
    assert!(!mint_signature.contains("galois_exponent"));
    assert!(mint_signature.contains("Result<PersistentDirectRelationUseSelectorV1"));
    assert!(mint.contains("derive_verified_direct_galois_target_a_statement_v1("));
    assert!(mint.contains("new_galois_selector_v1("));

    let replay = source
        .split("pub(super) struct DirectGaloisTargetAReplayV1")
        .nth(1)
        .unwrap()
        .split("/// Derive target `a` only")
        .next()
        .unwrap();
    assert!(replay.contains("expected_statement_digest: [u8; 32]"));
    assert!(replay.contains("capability.validate()?;"));
    assert!(replay.contains("PersistentDirectRelationV1::Galois"));
    assert!(replay.contains("selector.prior_round_digest != context.initial_round_digest()"));
    assert!(replay.contains("selector.context_digest != context.digest()"));
    assert!(replay.contains("selector.evaluated_key_ordinal != context.evaluated_key_ordinal()"));
    assert!(replay.contains("selector.digit_index != context.digit_index()"));
    assert!(replay.contains("selector.galois_exponent != context.galois_exponent()"));
    assert!(replay.contains("capability.ephemeral_commitments.is_some()"));
    assert!(replay.contains("DirectGaloisTargetAStatementStreamV1::begin(context)?"));
    assert!(replay.contains("self.stream.finish()?.statement_digest_for(self.context)?"));
    assert!(replay.contains("observed != self.expected_statement_digest"));
    assert!(replay.contains("inject_unwind_on_next_derive_for_test"));

    let completion = source
        .split("struct DirectGaloisTargetACompletionSealV1")
        .nth(1)
        .unwrap()
        .split("impl DirectGaloisTargetAReplayV1")
        .next()
        .unwrap();
    assert!(completion.contains("_non_copy: Vec<core::convert::Infallible>"));
    assert!(completion.contains("_seal: DirectGaloisTargetACompletionSealV1"));
    assert!(!source.contains("pub(super) struct DirectGaloisTargetACompletionSealV1"));
    assert!(core::mem::needs_drop::<DirectGaloisTargetACompletionSealV1>());
    assert!(core::mem::needs_drop::<CompletedDirectGaloisTargetAReplayV1>());

    assert!(!source.contains("derive(Clone"));
    assert!(!source.contains("impl Clone"));
    assert!(!source.contains("impl Copy"));
    assert!(!source.contains("Deref"));
    assert!(!source.contains("callback"));
    assert!(!source.contains("to_bytes"));
    assert!(!source.contains("from_bytes"));
    assert!(!source.contains("pub(super) struct VerifiedDirectGaloisTargetAStatementV1"));
    assert!(!source.contains("pub(super) fn statement_digest_for"));
    assert!(!source.contains("pub(super) fn authority_digest"));
    assert!(!source.contains("VerifiedDirectRelationProofReceiptV1"));
    assert!(!source.contains("bind_direct_relation_use"));
    assert!(!source.contains("EvaluatedKeySetAdmissionV1"));
}

#[test]
fn parent_visibility_and_all_release_receipt_gates_remain_closed() {
    let active = include_str!("../active_exact_binding.rs");
    assert!(active.contains("mod direct_galois_target_a_v1;"));
    assert!(!active.contains("pub(super) mod direct_galois_target_a_v1;"));
    let parent_mint = active
        .split("pub(super) fn mint_galois_selector_v1")
        .nth(1)
        .unwrap()
        .split("/// Non-serializable, single-use authorization")
        .next()
        .unwrap();
    let parent_signature = parent_mint.split('{').next().unwrap();
    assert!(parent_signature.contains("Result<PersistentDirectRelationUseSelectorV1"));
    assert!(!parent_signature.contains("prior_round_digest"));
    assert!(!parent_signature.contains("target_a_statement_digest"));
    assert!(!parent_signature.contains("target_a_seed"));
    assert!(!parent_signature.contains("evaluated_key_ordinal"));
    assert!(!parent_signature.contains("digit_index"));
    assert!(!parent_signature.contains("galois_exponent"));
    assert!(parent_mint.contains("direct_galois_target_a_v1::mint_galois_selector_v1("));
    assert!(!parent_mint.contains("VerifiedDirectGaloisTargetAStatementV1"));

    let verifier = active
        .split("pub(super) fn verify_and_consume_direct_relation_use_v1")
        .nth(1)
        .unwrap()
        .split("/// Sole production minting boundary")
        .next()
        .unwrap();
    assert!(verifier.contains("capability.validate()?;"));
    assert!(verifier.contains("Err(ZkAmsMkheErrorV1::ReleaseUnavailable)"));
    assert!(!verifier.contains("DirectGaloisTargetAReplayV1"));

    let audit = super::super::exact_binding_audit_v1(&release_profile_v1()).unwrap();
    assert_eq!(audit.blocker_mask, 0xfd);
    assert!(!audit.canonical_complete_wire_certified);
    assert!(!audit.chunked_workspace_certified);
    assert!(!audit.sampler_wired_to_runtime);
    assert!(!audit.persistent_graph_wired_to_runtime);
    assert!(!audit.split_decryption_wide_relation_certified);
    assert!(!audit.release_kat_pinned);
    assert!(!audit.release_available);

    let receipt = include_str!("../receipt_capability_audit.rs");
    let production = receipt
        .split("pub(super) fn zk_ams_mkhe_receipt_capability_audit_v1")
        .nth(1)
        .unwrap()
        .split("pub(super) fn require_zk_ams_mkhe_receipt_capability_v1")
        .next()
        .unwrap();
    assert!(production.contains("native_bgv_opening_receipt_sealed: false"));
    assert!(production.contains("rns_link_algebraic_receipt_complete: false"));
    assert!(production.contains("terminal_materialization_receipt_enforced: false"));
    assert!(production.contains("split_decryption_receipts_enforced: false"));
    assert!(production.contains("release_available: false"));
    let receipt_enforcement = receipt
        .split("pub(super) fn require_zk_ams_mkhe_receipt_capability_v1")
        .nth(1)
        .unwrap()
        .split("fn receipt_capability_blocker_mask_v1")
        .next()
        .unwrap();
    assert!(receipt_enforcement.contains("Err(ZkAmsMkheErrorV1::ReleaseUnavailable)"));

    let manifest = include_str!("../manifest.rs");
    let readiness = manifest
        .split("let active_exact_binding_gate")
        .nth(1)
        .unwrap()
        .split("Ok(ZkAmsMkheReadinessV1 {")
        .next()
        .unwrap();
    assert!(readiness.contains("active_exact_binding.blocker_mask == 0"));
    assert!(readiness.contains("receipt_capability.blocker_mask == 0"));
    assert!(readiness.contains("manifest.receipt_capability_blocker_mask == 0"));
    assert!(manifest.contains("return Err(ZkAmsMkheErrorV1::ReleaseUnavailable);"));
}
