#[rustfmt::skip]
use super::super::super::super::{PERSISTENT_COMMITMENT_CHUNKS_V1, PersistentDirectRelationUseSelectorV1, PersistentDirectRelationV1, VerifiedPersistentWitnessDirectRelationUseV1, persistent_commitment_set_digest, persistent_direct_relation_use_digest};
#[rustfmt::skip]
use super::super::{DirectPolynomialObjectV1, DirectRelationPublicObjectsV1, GaloisBObjectRoleV1};
use super::*;
#[rustfmt::skip]
use crate::vega::{
    MaskedRelaxedRandomErrorV1, MaskedRelaxedRandomSourceV1, VegaT256PointV1,
    derive_t256_generators_v1,
    sponge::{Keccak256, keccak256},
    zk_ams::mkhe::{ZkAmsMkheErrorV1, ZkAmsMkhePartyIdV1, active::{ZkAmsMkheActivePartySecretV1, ZkAmsMkheGovernedActiveRosterV1}, direct_collective_eval_ceremony::{DIRECT_POLYNOMIAL_STREAM_DOMAIN_V1, ZkAmsMkheDirectCeremonyContextV1, ZkAmsMkheDirectCeremonyRoundV1, ZkAmsMkheDirectEvaluatedKeyTargetV1, ZkAmsMkheDirectPolynomialRoleV1, direct_relation_contribution_statement_from_polynomials_v1}, direct_object_transport::{ZkAmsMkheDirectObjectKindV1, ZkAmsMkheDirectObjectPointerV1, ZkAmsMkheDirectObjectReadAtProviderV1}, manifest::{RELEASE_MODULI_V1, ZK_AMS_MKHE_RELEASE_RING_DEGREE_V1, ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1}},
};

const ZERO_POLYNOMIAL_BLAKE3_V1: [u8; 32] = [
    0xa0, 0xbd, 0x92, 0x4f, 0xd5, 0x6e, 0x8c, 0xf2, 0x26, 0x7c, 0x52, 0xbc, 0xe9, 0x67, 0x3d, 0x81,
    0x2d, 0x59, 0x44, 0x22, 0x24, 0x02, 0x8f, 0x9e, 0xd0, 0xaf, 0xea, 0x98, 0x18, 0x1d, 0x57, 0xfa,
];
const ZERO_GALOIS_B_STATEMENT_KECCAK_V1: [u8; 32] = [
    0x3c, 0xcb, 0x18, 0xc8, 0x90, 0x5e, 0xeb, 0xba, 0x4f, 0x70, 0xed, 0x16, 0x2d, 0x05, 0xa9, 0x81,
    0x88, 0xa9, 0x51, 0xa2, 0xf9, 0xe5, 0xff, 0x5c, 0xab, 0x0e, 0x0f, 0xdc, 0x8d, 0xfc, 0x58, 0xff,
];

struct DeterministicRandomV1(u64);
impl MaskedRelaxedRandomSourceV1 for DeterministicRandomV1 {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), MaskedRelaxedRandomErrorV1> {
        for chunk in destination.chunks_mut(32) {
            let block = keccak256(&self.0.to_be_bytes());
            chunk.copy_from_slice(&block[..chunk.len()]);
            self.0 = self.0.wrapping_add(1);
        }
        Ok(())
    }
}

struct ProceduralZeroProviderV1 {
    provider_identity: [u8; 32],
    snapshot_identity: [u8; 32],
    snapshot_calls: usize,
    snapshot_drift_at: Option<usize>,
    wrong_object_len: bool,
    short_read_at: Option<usize>,
    over_read_at: Option<usize>,
    panic_read_at: Option<usize>,
    corrupt_read_at: Option<usize>,
    invalid_residue_at: Option<usize>,
    read_calls: usize,
    max_read_bytes: usize,
    next_offset: u64,
}
impl ProceduralZeroProviderV1 {
    fn canonical() -> Self {
        Self {
            provider_identity: [0x91; 32],
            snapshot_identity: [0x92; 32],
            snapshot_calls: 0,
            snapshot_drift_at: None,
            wrong_object_len: false,
            short_read_at: None,
            over_read_at: None,
            panic_read_at: None,
            corrupt_read_at: None,
            invalid_residue_at: None,
            read_calls: 0,
            max_read_bytes: 0,
            next_offset: 0,
        }
    }
}
#[rustfmt::skip]
impl ZkAmsMkheDirectObjectReadAtProviderV1 for ProceduralZeroProviderV1 {
    fn provider_identity(&mut self) -> Result<[u8; 32], ZkAmsMkheErrorV1> { Ok(self.provider_identity) }
    fn snapshot_identity(&mut self) -> Result<[u8; 32], ZkAmsMkheErrorV1> {
        let call = self.snapshot_calls; self.snapshot_calls += 1;
        Ok(if self.snapshot_drift_at == Some(call) { [0x93; 32] } else { self.snapshot_identity })
    }
    fn object_len(&mut self, pointer: ZkAmsMkheDirectObjectPointerV1) -> Result<u64, ZkAmsMkheErrorV1> {
        Ok(pointer.payload_bytes() - if self.wrong_object_len { 1 } else { 0 })
    }
    fn read_at(&mut self, pointer: ZkAmsMkheDirectObjectPointerV1, absolute_offset: u64, destination: &mut [u8]) -> Result<usize, ZkAmsMkheErrorV1> {
        if pointer.kind() != ZkAmsMkheDirectObjectKindV1::GaloisB || absolute_offset != self.next_offset {
            return Err(ZkAmsMkheErrorV1::InvalidWireEncoding);
        }
        let call = self.read_calls; self.read_calls += 1;
        self.max_read_bytes = self.max_read_bytes.max(destination.len());
        if self.panic_read_at == Some(call) { panic!("procedural provider panic"); }
        destination.fill(0);
        if self.invalid_residue_at == Some(call) {
            let limb_bytes = (ZK_AMS_MKHE_RELEASE_RING_DEGREE_V1 * 8) as u64;
            let limb = usize::try_from(absolute_offset / limb_bytes).unwrap();
            destination[..8].copy_from_slice(&RELEASE_MODULI_V1[limb].to_be_bytes());
        }
        if self.corrupt_read_at == Some(call) { destination[7] = 1; }
        if self.short_read_at == Some(call) { return Ok(destination.len() - 1); }
        if self.over_read_at == Some(call) { return Ok(destination.len() + 1); }
        self.next_offset += destination.len() as u64;
        Ok(destination.len())
    }
}

struct ReplayFixtureV1 {
    context: ZkAmsMkheDirectCeremonyContextV1,
    capability: VerifiedPersistentWitnessDirectRelationUseV1,
    objects: DirectRelationPublicObjectsV1,
    provider: ProceduralZeroProviderV1,
}
impl ReplayFixtureV1 {
    fn begin(&mut self) -> Result<DirectGaloisBStatementReplayV1, ZkAmsMkheErrorV1> {
        DirectGaloisBStatementReplayV1::begin(
            self.context,
            &self.capability,
            self.objects,
            &mut self.provider,
        )
    }
}

fn governed_roster() -> ZkAmsMkheGovernedActiveRosterV1 {
    let mut random = DeterministicRandomV1(1);
    let mut secrets: [ZkAmsMkheActivePartySecretV1; ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1] =
        core::array::from_fn(|_| ZkAmsMkheActivePartySecretV1::generate(&mut random).unwrap());
    secrets.sort_by_key(|secret| secret.party().unwrap());
    let references = core::array::from_fn(|index| &secrets[index]);
    ZkAmsMkheGovernedActiveRosterV1::new(77, references, &mut random).unwrap()
}

fn manual_zero_polynomial_digest(
    context_digest: [u8; 32],
    party_index: u8,
    party: ZkAmsMkhePartyIdV1,
    round: ZkAmsMkheDirectCeremonyRoundV1,
    role: ZkAmsMkheDirectPolynomialRoleV1,
) -> [u8; 32] {
    let mut hash = Keccak256::new();
    hash.update(DIRECT_POLYNOMIAL_STREAM_DOMAIN_V1);
    hash.update(&context_digest);
    hash.update(&[round as u8, role as u8, party_index]);
    hash.update(&party.to_bytes());
    hash.update(&(ZK_AMS_MKHE_RELEASE_RING_DEGREE_V1 as u32).to_be_bytes());
    hash.update(&[RELEASE_MODULI_V1.len() as u8]);
    let zeroes = [0_u8; ZK_AMS_MKHE_DIRECT_OBJECT_READ_BYTES_V1];
    for (limb, modulus) in RELEASE_MODULI_V1.iter().enumerate() {
        hash.update(&[limb as u8]);
        hash.update(&modulus.to_be_bytes());
        for _ in 0..READ_CALLS_PER_LIMB_V1 {
            hash.update(&zeroes);
        }
    }
    hash.finalize()
}

fn pointer(kind: ZkAmsMkheDirectObjectKindV1) -> ZkAmsMkheDirectObjectPointerV1 {
    ZkAmsMkheDirectObjectPointerV1::new(
        kind,
        EXACT_POLYNOMIAL_BYTES_V1 as u64,
        ZERO_POLYNOMIAL_BLAKE3_V1,
    )
    .unwrap()
}
fn commitments(label: &[u8]) -> [VegaT256PointV1; PERSISTENT_COMMITMENT_CHUNKS_V1] {
    derive_t256_generators_v1(label, PERSISTENT_COMMITMENT_CHUNKS_V1)
        .unwrap()
        .try_into()
        .unwrap()
}

#[rustfmt::skip]
fn fixture(statement_digest_tweak: bool) -> ReplayFixtureV1 {
    let roster = governed_roster();
    let lineages = core::array::from_fn(|index| keccak256(&[0x51, index as u8]));
    let context = ZkAmsMkheDirectCeremonyContextV1::new(&roster, [0x61; 32], [0x62; 32], lineages, ZkAmsMkheDirectEvaluatedKeyTargetV1::Galois { schedule_index: 7 }, 3).unwrap();
    let party = roster.participants()[0].party();
    let mut b_digest = ZERO_GALOIS_B_STATEMENT_KECCAK_V1;
    if statement_digest_tweak { b_digest[0] ^= 1; }
    let objects = DirectRelationPublicObjectsV1::Galois { b: DirectPolynomialObjectV1::<GaloisBObjectRoleV1>::new(b_digest, pointer(ZkAmsMkheDirectObjectKindV1::GaloisB)).unwrap() };
    let prior = context.initial_round_digest();
    let contribution = direct_relation_contribution_statement_from_polynomials_v1(context, ZkAmsMkheDirectCeremonyRoundV1::Galois, prior, 0, party, &[b_digest]).unwrap();
    let selector = PersistentDirectRelationUseSelectorV1::new(PersistentDirectRelationV1::Galois, context.digest(), prior, context.evaluated_key_ordinal(), context.digit_index(), context.galois_exponent(), [0; 32], [0x64; 32], [0; 32], [0; 32], contribution, [0x65; 32]).unwrap();
    let secret_basis = [0x66; 32];
    let secret_commitments = commitments(b"galois-b-replay-secret");
    let mut capability = VerifiedPersistentWitnessDirectRelationUseV1 {
        binding_set_root: context.secret_lineage_root(), collective_public_key_digest: context.collective_public_key_digest(), party_index: 0, party,
        secret_identity_digest: lineages[0], secret_generator_basis_digest: secret_basis,
        secret_commitment_set_digest: persistent_commitment_set_digest(secret_basis, &secret_commitments).unwrap(), secret_commitments,
        ephemeral_identity_digest: [0; 32], ephemeral_commitment_set_digest: [0; 32], ephemeral_source_context_digest: [0; 32], ephemeral_source_statement_digest: [0; 32], ephemeral_record_index: 0, ephemeral_commitments: None,
        selector, use_digest: [0; 32],
    };
    capability.use_digest = persistent_direct_relation_use_digest(&capability).unwrap();
    capability.validate().unwrap();
    ReplayFixtureV1 { context, capability, objects, provider: ProceduralZeroProviderV1::canonical() }
}

macro_rules! assert_error {
    ($result:expr, $expected:expr) => {
        match $result {
            Ok(_) => panic!("expected failure"),
            Err(error) => assert_eq!(error, $expected),
        }
    };
}
fn replay_all(fixture: &mut ReplayFixtureV1) -> Result<(), ZkAmsMkheErrorV1> {
    let mut replay = fixture.begin()?;
    let mut limb = vec![0_u64; ZK_AMS_MKHE_RELEASE_RING_DEGREE_V1];
    for _ in 0..RELEASE_RNS_LIMBS_V1 {
        replay.replay_next_limb_into(&mut fixture.provider, &mut limb)?;
    }
    replay.finish(&mut fixture.provider)?;
    Ok(())
}

#[test]
fn full_zero_kat_is_role_separated_and_exactly_accounted() {
    let mut blake3 = norito::streaming::Blake3Hasher::new();
    let zeroes = [0_u8; ZK_AMS_MKHE_DIRECT_OBJECT_READ_BYTES_V1];
    for _ in 0..READ_CALLS_PER_OBJECT_V1 {
        blake3.update(&zeroes);
    }
    assert_eq!(blake3.finalize(), ZERO_POLYNOMIAL_BLAKE3_V1);
    let mut fixture = fixture(false);
    let party = fixture.capability.party;
    let galois = manual_zero_polynomial_digest(
        fixture.context.digest(),
        0,
        party,
        ZkAmsMkheDirectCeremonyRoundV1::Galois,
        ZkAmsMkheDirectPolynomialRoleV1::GaloisB,
    );
    let rkg = manual_zero_polynomial_digest(
        fixture.context.digest(),
        0,
        party,
        ZkAmsMkheDirectCeremonyRoundV1::RkgRoundOne,
        ZkAmsMkheDirectPolynomialRoleV1::RkgH0,
    );
    assert_eq!(galois, ZERO_GALOIS_B_STATEMENT_KECCAK_V1);
    assert_ne!(galois, rkg);
    replay_all(&mut fixture).unwrap();
    assert_eq!(fixture.provider.read_calls, 4_864);
    assert_eq!(fixture.provider.max_read_bytes, 8_192);
    assert_eq!(fixture.provider.next_offset, 39_845_888);
    assert_eq!(REPLAY_LIVE_PAYLOAD_BYTES_V1, 1_056_768);
}

#[test]
fn sealed_relation_context_object_and_lineage_splices_fail_before_io() {
    let mut object = fixture(false);
    let DirectRelationPublicObjectsV1::Galois { mut b } = object.objects else {
        unreachable!()
    };
    b.statement_digest[0] ^= 1;
    object.objects = DirectRelationPublicObjectsV1::Galois { b };
    assert_error!(object.begin(), ZkAmsMkheErrorV1::InvalidKeyMaterial);
    assert_eq!(
        (object.provider.snapshot_calls, object.provider.read_calls),
        (0, 0)
    );

    let mut context = fixture(false);
    context.capability.selector.context_digest[0] ^= 1;
    context.capability.use_digest =
        persistent_direct_relation_use_digest(&context.capability).unwrap();
    assert_error!(context.begin(), ZkAmsMkheErrorV1::InvalidKeyMaterial);
    assert_eq!(context.provider.read_calls, 0);

    let mut lineage = fixture(false);
    lineage.capability.secret_identity_digest[0] ^= 1;
    lineage.capability.use_digest =
        persistent_direct_relation_use_digest(&lineage.capability).unwrap();
    assert_error!(lineage.begin(), ZkAmsMkheErrorV1::InvalidKeyMaterial);
    assert_eq!(lineage.provider.read_calls, 0);

    let mut kind = fixture(false);
    let DirectRelationPublicObjectsV1::Galois { mut b } = kind.objects else {
        unreachable!()
    };
    b.pointer = pointer(ZkAmsMkheDirectObjectKindV1::RkgH0);
    kind.objects = DirectRelationPublicObjectsV1::Galois { b };
    assert_error!(kind.begin(), ZkAmsMkheErrorV1::InvalidWireEncoding);
    assert_eq!(kind.provider.read_calls, 0);
}

#[test]
fn workspace_residue_partial_and_extra_states_are_poisoned() {
    let mut width = fixture(false);
    let mut replay = width.begin().unwrap();
    let mut short = vec![0_u64; ZK_AMS_MKHE_RELEASE_RING_DEGREE_V1 - 1];
    let mut full = vec![0_u64; ZK_AMS_MKHE_RELEASE_RING_DEGREE_V1];
    assert_eq!(
        replay.replay_next_limb_into(&mut width.provider, &mut short),
        Err(ZkAmsMkheErrorV1::InvalidPolynomial)
    );
    assert_eq!(
        replay.replay_next_limb_into(&mut width.provider, &mut full),
        Err(ZkAmsMkheErrorV1::InvalidPolynomial)
    );

    let mut residue = fixture(false);
    residue.provider.invalid_residue_at = Some(0);
    let mut replay = residue.begin().unwrap();
    assert_eq!(
        replay.replay_next_limb_into(&mut residue.provider, &mut full),
        Err(ZkAmsMkheErrorV1::InvalidPolynomial)
    );
    assert_eq!(
        replay.replay_next_limb_into(&mut residue.provider, &mut full),
        Err(ZkAmsMkheErrorV1::InvalidPolynomial)
    );

    let mut partial = fixture(false);
    let replay = partial.begin().unwrap();
    assert_error!(
        replay.finish(&mut partial.provider),
        ZkAmsMkheErrorV1::InvalidPolynomial
    );

    let mut extra = fixture(false);
    let mut replay = extra.begin().unwrap();
    for _ in 0..RELEASE_RNS_LIMBS_V1 {
        replay
            .replay_next_limb_into(&mut extra.provider, &mut full)
            .unwrap();
    }
    assert_eq!(
        replay.replay_next_limb_into(&mut extra.provider, &mut full),
        Err(ZkAmsMkheErrorV1::InvalidPolynomial)
    );
}

#[test]
fn provider_length_read_snapshot_and_identity_failures_are_exact() {
    for failure in 0..6 {
        let mut fixture = fixture(false);
        match failure {
            0 => fixture.provider.wrong_object_len = true,
            1 => fixture.provider.short_read_at = Some(0),
            2 => fixture.provider.over_read_at = Some(0),
            3 => fixture.provider.snapshot_drift_at = Some(2),
            4 => fixture.provider.provider_identity = [0; 32],
            _ => fixture.provider.snapshot_identity = [0; 32],
        }
        if matches!(failure, 0 | 4 | 5) {
            assert_error!(fixture.begin(), ZkAmsMkheErrorV1::InvalidKeyMaterial);
            continue;
        }
        let mut replay = fixture.begin().unwrap();
        let mut limb = vec![0_u64; ZK_AMS_MKHE_RELEASE_RING_DEGREE_V1];
        let expected = if failure == 3 {
            ZkAmsMkheErrorV1::InvalidKeyMaterial
        } else {
            ZkAmsMkheErrorV1::InvalidWireEncoding
        };
        assert_eq!(
            replay.replay_next_limb_into(&mut fixture.provider, &mut limb),
            Err(expected)
        );
        assert_eq!(
            replay.replay_next_limb_into(&mut fixture.provider, &mut limb),
            Err(ZkAmsMkheErrorV1::InvalidPolynomial)
        );
    }
}

#[test]
fn statement_digest_and_content_address_are_independently_required() {
    let mut statement = fixture(true);
    assert_eq!(
        replay_all(&mut statement),
        Err(ZkAmsMkheErrorV1::InvalidKeyMaterial)
    );
    let mut content = fixture(false);
    content.provider.corrupt_read_at = Some(0);
    assert_eq!(
        replay_all(&mut content),
        Err(ZkAmsMkheErrorV1::InvalidWireEncoding)
    );
}

#[test]
fn caught_provider_unwind_cannot_resume_the_replay() {
    let mut fixture = fixture(false);
    fixture.provider.panic_read_at = Some(0);
    let mut replay = fixture.begin().unwrap();
    let mut limb = vec![0_u64; ZK_AMS_MKHE_RELEASE_RING_DEGREE_V1];
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = replay.replay_next_limb_into(&mut fixture.provider, &mut limb);
    }));
    assert!(caught.is_err());
    assert_eq!(
        replay.replay_next_limb_into(&mut fixture.provider, &mut limb),
        Err(ZkAmsMkheErrorV1::InvalidPolynomial)
    );
    assert_eq!(fixture.provider.read_calls, 1);
}

#[test]
fn replay_surface_is_opaque_bounded_and_fail_closed() {
    let source = include_str!("galois_b_replay_v1.rs");
    for forbidden in "Vec<|Vec::|derive(Clone|derive(Copy|impl Clone|impl Copy|Deref|AsRef|callback|decode|pub fn pointer|pub fn digest|pub fn bytes|pub fn receipt|pub fn snapshot".split('|') {
        assert!(!source.contains(forbidden), "forbidden surface: {forbidden}");
    }
    assert!(source.contains("[0_u8; ZK_AMS_MKHE_DIRECT_OBJECT_READ_BYTES_V1]"));
    assert!(source.contains("self.poisoned = true;"));
    assert!(source.contains("ExpectedDirectRelationStatementV1::new("));
    assert!(source.contains("u64::from_be_bytes"));
    assert!(source.contains("if value >= modulus"));
    assert!(source.contains("_read_receipt: ZkAmsMkheDirectObjectReadReceiptV1"));
    assert!(!source.contains("VerifiedDirectRelationProofReceiptV1"));
    assert!(source.contains("ZkAmsMkheDirectCeremonyRoundV1::Galois as u8"));
    assert!(source.contains("ZkAmsMkheDirectPolynomialRoleV1::GaloisB as u8"));
    let active = include_str!("../../../active_exact_binding.rs");
    assert!(active.contains("let canonical_complete_wire_certified = false;"));
    assert!(!active.contains("canonical_complete_wire_certified = true"));
    let verifier = active
        .split("pub(super) fn verify_and_consume_direct_relation_use_v1")
        .nth(1)
        .and_then(|tail| tail.split("/// Sole production minting boundary").next())
        .unwrap();
    assert!(verifier.contains("Err(ZkAmsMkheErrorV1::ReleaseUnavailable)"));
    assert!(!verifier.contains("DirectGaloisBStatementReplayV1"));
    let transport = include_str!("../../../direct_object_transport.rs");
    assert!(transport.contains("ZK_AMS_MKHE_DIRECT_OBJECT_ADMISSION_GATE_V1: bool = false"));
    assert!(transport.contains("ZK_AMS_MKHE_DIRECT_OBJECT_RELEASE_GATE_V1: bool = false"));
}
