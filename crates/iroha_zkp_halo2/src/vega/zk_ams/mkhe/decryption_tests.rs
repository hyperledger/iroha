// Test body included from the parent module to keep its production source budget bounded.
use super::super::super::MaskedRelaxedRandomErrorV1;
use super::super::collective::{
    generate_zk_ams_mkhe_collective_party_state_with_prepared_public_a_v1,
    prepare_zk_ams_mkhe_collective_public_a_v1,
    validate_collective_public_key_share_for_verified_cpk_compact_v1,
};
use super::super::sample_uniform_rns;
use super::*;
const TEST_MODULI: [u64; 2] = [2_013_265_921, 1_811_939_329];
const TEST_ROOTS: [u64; 2] = [1_400_279_418, 677_356_115];
const TEST_SMUDGE_BITS: usize = 8;
const TEST_FINAL_RESIDUAL_BITS: usize = 24;
const BUFFERED_DECRYPTION_SPARSE_CHALLENGE_DOMAIN_V1: &[u8] =
    b"iroha.zk-ams.v1.mkhe.decryption-proof-sparse-challenge";
fn test_profile() -> BgvProfile {
    BgvProfile {
        profile_id: [0xd8; 32],
        ring_degree: 8,
        moduli: &TEST_MODULI,
        negacyclic_roots: &TEST_ROOTS,
        plaintext_modulus: PlaintextModulus::Tiny(17),
        error_eta: 2,
        hybrid_rns_decomposition: false,
        gadget_base_log: 8,
        gadget_digits: 8,
        max_ciphertext_bytes: 1 << 20,
        max_evaluated_key_bytes: 16 << 20,
        max_round_bytes: 16 << 20,
        max_share_bytes: 4 << 20,
        max_workspace_bytes: 16 << 20,
        max_work_units: 1 << 20,
    }
}
fn sparse_challenge_frame_reference(
    ring_degree: usize,
    weight: usize,
    challenge_seed: [u8; 32],
) -> [u8; BUFFERED_DECRYPTION_SPARSE_CHALLENGE_DOMAIN_V1.len() + 40] {
    let mut frame = [0_u8; BUFFERED_DECRYPTION_SPARSE_CHALLENGE_DOMAIN_V1.len() + 40];
    let domain_end = BUFFERED_DECRYPTION_SPARSE_CHALLENGE_DOMAIN_V1.len();
    frame[..domain_end].copy_from_slice(BUFFERED_DECRYPTION_SPARSE_CHALLENGE_DOMAIN_V1);
    frame[domain_end..domain_end + 32].copy_from_slice(&challenge_seed);
    frame[domain_end + 32..domain_end + 36]
        .copy_from_slice(&u32::try_from(ring_degree).unwrap().to_be_bytes());
    frame[domain_end + 36..].copy_from_slice(&u32::try_from(weight).unwrap().to_be_bytes());
    frame
}
fn buffered_sparse_challenge_terms_reference(
    ring_degree: usize,
    challenge_seed: [u8; 32],
) -> Vec<(usize, i8)> {
    assert!(ring_degree >= 2 && ring_degree.is_power_of_two());
    let weight = DECRYPTION_RELEASE_CHALLENGE_WEIGHT_V1.min((ring_degree / 2).max(1));
    let frame = sparse_challenge_frame_reference(ring_degree, weight, challenge_seed);
    let stream_bytes = weight * MAX_RANDOM_REJECTION_ATTEMPTS_V1 * 8;
    let buffered = shake256(&frame, stream_bytes);
    let mask = u64::try_from(ring_degree - 1).unwrap();
    let mut terms = Vec::with_capacity(weight);
    for candidate in buffered.chunks_exact(8) {
        let word = u64::from_le_bytes(candidate.try_into().unwrap());
        let position = usize::try_from(word & mask).unwrap();
        if terms.iter().any(|(selected, _)| *selected == position) {
            continue;
        }
        terms.push((position, if word >> 63 == 0 { -1 } else { 1 }));
        if terms.len() == weight {
            break;
        }
    }
    assert_eq!(terms.len(), weight);
    terms.sort_unstable_by_key(|(position, _)| *position);
    terms
}
struct KatRandom {
    state: [u8; 32],
    counter: u64,
}
impl KatRandom {
    fn new(label: &[u8]) -> Self {
        Self {
            state: keccak256(label),
            counter: 0,
        }
    }
}
impl MaskedRelaxedRandomSourceV1 for KatRandom {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), MaskedRelaxedRandomErrorV1> {
        let mut cursor = 0;
        while cursor < destination.len() {
            let mut frame = Vec::with_capacity(40);
            frame.extend_from_slice(&self.state);
            frame.extend_from_slice(&self.counter.to_be_bytes());
            let block = shake256(&frame, 64);
            let take = (destination.len() - cursor).min(block.len());
            destination[cursor..cursor + take].copy_from_slice(&block[..take]);
            cursor += take;
            self.counter = self.counter.wrapping_add(1);
        }
        Ok(())
    }
}
struct FailingRandom;
impl MaskedRelaxedRandomSourceV1 for FailingRandom {
    fn fill_bytes(&mut self, _destination: &mut [u8]) -> Result<(), MaskedRelaxedRandomErrorV1> {
        Err(MaskedRelaxedRandomErrorV1::Unavailable)
    }
}
struct PartiallyFailingRandom;
impl MaskedRelaxedRandomSourceV1 for PartiallyFailingRandom {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), MaskedRelaxedRandomErrorV1> {
        destination.fill(0xa5);
        Err(MaskedRelaxedRandomErrorV1::Unavailable)
    }
}
struct ConstantRandom(u8);
impl MaskedRelaxedRandomSourceV1 for ConstantRandom {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), MaskedRelaxedRandomErrorV1> {
        destination.fill(self.0);
        Ok(())
    }
}
struct FastDeterministicRandom(u64);
impl FastDeterministicRandom {
    fn new(label: &[u8]) -> Self {
        let digest = keccak256(label);
        Self(u64::from_be_bytes(digest[..8].try_into().unwrap()))
    }
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut value = self.0;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^ (value >> 31)
    }
}
impl MaskedRelaxedRandomSourceV1 for FastDeterministicRandom {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), MaskedRelaxedRandomErrorV1> {
        for chunk in destination.chunks_mut(8) {
            let block = self.next_u64().to_be_bytes();
            chunk.copy_from_slice(&block[..chunk.len()]);
        }
        Ok(())
    }
}
struct Fixture {
    profile: BgvProfile,
    parties: super::super::PartySet,
    authentication: Vec<AuthenticationSecret>,
    relations: Vec<DecryptionPublicRelationV1>,
    secrets: Vec<SecretPolynomial>,
    errors: Vec<SecretPolynomial>,
    ciphertext: ZkAmsMkheCollectiveCiphertextV1,
    message: Vec<u64>,
}
fn fixture(label: &[u8]) -> Fixture {
    let profile = test_profile();
    profile.validate().unwrap();
    let mut random = KatRandom::new(label);
    let mut authentication = (0..ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1)
        .map(|_| AuthenticationSecret::generate(&mut random).unwrap())
        .collect::<Vec<_>>();
    authentication.sort_by_key(|secret| secret.party_id().unwrap());
    let parties = super::super::PartySet::new(
        authentication
            .iter()
            .map(|secret| secret.party_id().unwrap())
            .collect(),
    )
    .unwrap();
    let common_a = sample_uniform_rns(&profile, &mut random).unwrap();
    let mut secrets = Vec::with_capacity(ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1);
    let mut errors = Vec::with_capacity(ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1);
    let mut party_bs = Vec::with_capacity(ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1);
    let mut collective_b = RnsPolynomial::zero(&profile);
    for _ in 0..ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1 {
        let secret = SecretPolynomial::sample_ternary(&profile, &mut random).unwrap();
        let error = SecretPolynomial::sample_error(&profile, &mut random).unwrap();
        let party_b = common_a
            .mul(&secret.as_rns(&profile).unwrap(), &profile)
            .unwrap()
            .negate(&profile)
            .unwrap()
            .add(
                &error
                    .as_rns(&profile)
                    .unwrap()
                    .scale_plaintext_modulus(&profile)
                    .unwrap(),
                &profile,
            )
            .unwrap();
        collective_b = collective_b.add(&party_b, &profile).unwrap();
        secrets.push(secret);
        errors.push(error);
        party_bs.push(party_b);
    }
    let message = vec![0, 1, 2, 3, 8, 9, 15, 16];
    let message_rns = RnsPolynomial::from_test_plaintext(&profile, &message).unwrap();
    let ephemeral = SecretPolynomial::sample_ternary(&profile, &mut random).unwrap();
    let error_zero = SecretPolynomial::sample_error(&profile, &mut random).unwrap();
    let error_one = SecretPolynomial::sample_error(&profile, &mut random).unwrap();
    let ephemeral_rns = ephemeral.as_rns(&profile).unwrap();
    let constant = collective_b
        .mul(&ephemeral_rns, &profile)
        .unwrap()
        .add(
            &error_zero
                .as_rns(&profile)
                .unwrap()
                .scale_plaintext_modulus(&profile)
                .unwrap(),
            &profile,
        )
        .unwrap()
        .add(&message_rns, &profile)
        .unwrap();
    let linear = common_a
        .mul(&ephemeral_rns, &profile)
        .unwrap()
        .add(
            &error_one
                .as_rns(&profile)
                .unwrap()
                .scale_plaintext_modulus(&profile)
                .unwrap(),
            &profile,
        )
        .unwrap();
    let transcript_digest = keccak256(&[label, b".transcript"].concat());
    let epoch = 41;
    let ciphertext = ZkAmsMkheCollectiveCiphertextV1::new(
        &profile,
        &parties,
        epoch,
        transcript_digest,
        73,
        1,
        constant,
        linear,
    )
    .unwrap();
    let roster_digest = ciphertext.roster_digest();
    // Make the digest available to every exact per-party binding.
    let ciphertext_digest = ciphertext.digest();
    let key_context_digest = keccak256(&[label, b".key-context"].concat());
    let statement_binding_digest = keccak256(&[label, b".statement-binding"].concat());
    let mut relations = Vec::with_capacity(ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1);
    for (index, party_b) in party_bs.into_iter().enumerate() {
        let binding = DecryptionBindingV1 {
            profile_digest: profile.digest().unwrap(),
            roster_digest,
            epoch: ciphertext.epoch(),
            transcript_digest,
            ciphertext_digest,
            key_context_digest,
            statement_binding_digest,
            ciphertext_record_index: 0,
            sample_index: ciphertext.sample_index(),
            party_index: u8::try_from(index).unwrap(),
            party: parties.parties[index],
            level: ciphertext.level(),
        };
        relations.push(DecryptionPublicRelationV1 {
            binding: binding.clone(),
            common_a: Arc::new(common_a.clone()),
            party_b,
        });
    }
    ciphertext.validate(&profile, &parties).unwrap();
    Fixture {
        profile,
        parties,
        authentication,
        relations,
        secrets,
        errors,
        ciphertext,
        message,
    }
}
fn make_shares(fixture: &Fixture, label: &[u8]) -> Vec<AuthenticatedDecryptionShareV1> {
    let mut random = KatRandom::new(label);
    (0..ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1)
        .map(|index| {
            let witness = DecryptionPartyWitnessV1 {
                binding: fixture.relations[index].binding.clone(),
                secret: &fixture.secrets[index],
                public_key_error: &fixture.errors[index],
            };
            create_authenticated_decryption_share(
                &fixture.profile,
                &fixture.parties,
                &fixture.relations[index],
                &witness,
                &fixture.ciphertext,
                &fixture.authentication[index],
                TEST_SMUDGE_BITS,
                &mut random,
            )
            .unwrap()
        })
        .collect()
}
#[test]
fn release_tests_do_not_retain_full_roster_public_key_material() {
    let source = include_str!("decryption_tests.rs");
    for forbidden in [
        ["PublicRelease", "ProvingFixture"].concat(),
        ["public_release_proving_", "fixture"].concat(),
        ["std::sync::Once", "Lock"].concat(),
        ["aggregate_", "zk_ams_mkhe_collective_public_key_v1"].concat(),
    ] {
        assert!(
            !source.contains(&forbidden),
            "release tests must not restore the retained {forbidden} corridor",
        );
    }
    let evidence =
        super::super::cpk_ceremony::zk_ams_mkhe_cpk_ceremony_residency_evidence_v1().unwrap();
    assert_eq!(evidence.live_party_state_retained_point_bytes, 264);
    assert_eq!(
        evidence.maximum_prior_admitted_state_retained_point_bytes,
        1_848
    );
    assert_eq!(evidence.state_owned_secret_narrowing_bytes, 131_072);
    assert!(!evidence.state_owned_secret_membership_prover_workspace_enumerated);
    assert_eq!(evidence.final_native_collective_key_bytes, 79_691_776);
    assert_eq!(evidence.streaming_key_publication_scratch_bytes, 8_192);
    assert_eq!(evidence.streaming_key_authority_heap_bytes, 59_584);
    assert_eq!(evidence.streaming_key_publication_peak_bytes, 79_759_552);
    assert_eq!(evidence.enumerated_ceremony_peak_bytes, 115_516_304);
    assert!(evidence.enumerated_ceremony_peak_bytes <= 160 * 1024 * 1024);
    assert!(!evidence.cas_backend_residency_enumerated);
    assert_eq!(evidence.authenticated_peak_residency_digest, [0; 32]);
    assert!(!evidence.release_certified);
}
#[test]
fn production_zeroizing_vector_owners_are_exact_before_secret_fill() {
    let decryption = include_str!("decryption.rs");
    for (
        name,
        implementation_start,
        implementation_end,
        constructor_start,
        constructor_end,
        exact,
    ) in [
        (
            "byte vector",
            "impl ZeroizingByteVectorV1 {",
            "impl Drop for ZeroizingByteVectorV1",
            "fn zeroed(len: usize) -> Result<Self, ZkAmsMkheErrorV1> {",
            "\n    fn as_slice",
            "try_exact_capacity_vec_v1(len)",
        ),
        (
            "i64 vector",
            "impl ZeroizingI64VectorV1 {",
            "impl Drop for ZeroizingI64VectorV1",
            "fn with_capacity(capacity: usize) -> Result<Self, ZkAmsMkheErrorV1> {",
            "\n    #[cfg(test)]\n    fn from_vec",
            "try_exact_capacity_vec_v1(capacity)",
        ),
        (
            "signed-wide vector",
            "impl ZeroizingSignedWideVectorV1 {",
            "impl Drop for ZeroizingSignedWideVectorV1",
            "fn with_capacity(capacity: usize) -> Result<Self, ZkAmsMkheErrorV1> {",
            "\n    #[cfg(test)]\n    fn from_vec",
            "try_exact_capacity_vec_v1(capacity)",
        ),
    ] {
        assert_eq!(
            decryption.matches(implementation_start).count(),
            1,
            "{name}"
        );
        let implementation = decryption
            .split(implementation_start)
            .nth(1)
            .unwrap_or_else(|| panic!("missing {name} implementation"))
            .split(implementation_end)
            .next()
            .unwrap_or_else(|| panic!("missing {name} implementation boundary"));
        let constructor = implementation
            .split(constructor_start)
            .nth(1)
            .unwrap_or_else(|| panic!("missing {name} constructor"))
            .split(constructor_end)
            .next()
            .unwrap_or_else(|| panic!("missing {name} constructor boundary"));
        assert_eq!(constructor.matches("try_exact_capacity_vec_v1(").count(), 1);
        assert!(constructor.contains(exact));
        assert_eq!(
            constructor
                .matches("ZkAmsMkheErrorV1::ResourceCeilingExceeded")
                .count(),
            1
        );
        assert!(!constructor.contains("try_reserve_exact"));
    }
    let byte_constructor = decryption
        .split("impl ZeroizingByteVectorV1 {")
        .nth(1)
        .expect("byte-vector implementation")
        .split("impl Drop for ZeroizingByteVectorV1")
        .next()
        .expect("byte-vector implementation boundary");
    assert!(byte_constructor.contains("bytes.resize(len, 0);"));

    let streaming = include_str!("decryption_streaming.rs");
    let staged = streaming
        .split("pub fn prove_zk_ams_mkhe_decryption_share_staged_v1")
        .nth(1)
        .expect("release staged prover")
        .split("/// Zero-copy canonical view")
        .next()
        .expect("release staged prover boundary");
    let outer_owner = staged
        .find(
            "let mut smudge = super::ZeroizingSignedWideVectorV1::with_capacity(profile.ring_degree)?;",
        )
        .expect("outer smudge owner");
    let first_secret_fill = staged
        .find("smudge.push(sample_signed_wide(&smudge_bound, &mut bounded_random)?);")
        .expect("outer smudge RNG fill");
    assert!(outer_owner < first_secret_fill);
}
#[test]
fn streamed_sparse_challenge_matches_independent_buffered_reference() {
    for (ring_degree, challenge_seed) in [
        (2, [0x11; 32]),
        (8, [0x22; 32]),
        (64, [0x33; 32]),
        (1_024, [0x44; 32]),
        (4_096, [0x55; 32]),
    ] {
        let dense = derive_sparse_challenge(ring_degree, challenge_seed).unwrap();
        assert_eq!(dense.capacity(), ring_degree);
        let actual = dense
            .iter()
            .copied()
            .enumerate()
            .filter(|(_, sign)| *sign != 0)
            .collect::<Vec<_>>();
        assert_eq!(
            actual,
            buffered_sparse_challenge_terms_reference(ring_degree, challenge_seed)
        );
    }

    let ring_degree = release_profile_v1().ring_degree;
    let challenge_seed = [0xa5; 32];
    let weight = DECRYPTION_RELEASE_CHALLENGE_WEIGHT_V1.min((ring_degree / 2).max(1));
    let stream_bytes = weight * MAX_RANDOM_REJECTION_ATTEMPTS_V1 * 8;
    assert_eq!(ring_degree, 131_072);
    assert_eq!(weight, 20);
    assert_eq!(stream_bytes, 20_480);
    assert_eq!(stream_bytes / 8, 2_560);
    assert_eq!(
        DECRYPTION_SPARSE_CHALLENGE_DOMAIN_V1,
        BUFFERED_DECRYPTION_SPARSE_CHALLENGE_DOMAIN_V1
    );
    assert_eq!(DECRYPTION_SPARSE_CHALLENGE_DOMAIN_V1.len() + 40, 94);
    let frame = sparse_challenge_frame_reference(ring_degree, weight, challenge_seed);
    let expected = buffered_sparse_challenge_terms_reference(ring_degree, challenge_seed);
    let mask = u64::try_from(ring_degree - 1).unwrap();
    let mut reader = Shake256Reader::new(&frame);
    let mut actual: Vec<(usize, i8)> = Vec::with_capacity(weight);
    for _ in 0..stream_bytes / 8 {
        let mut candidate = [0_u8; 8];
        reader.read(&mut candidate);
        let word = u64::from_le_bytes(candidate);
        let position = usize::try_from(word & mask).unwrap();
        if actual.iter().any(|(selected, _)| *selected == position) {
            continue;
        }
        actual.push((position, if word >> 63 == 0 { -1 } else { 1 }));
        if actual.len() == weight {
            break;
        }
    }
    actual.sort_unstable_by_key(|(position, _)| *position);
    assert_eq!(actual, expected);
}
#[test]
fn production_sparse_challenge_is_stack_framed_streamed_and_exact() {
    let decryption = include_str!("decryption.rs");
    assert_eq!(decryption.matches("fn derive_sparse_challenge(").count(), 1);
    let challenge = decryption
        .split("fn derive_sparse_challenge(")
        .nth(1)
        .expect("production sparse challenge")
        .split("#[derive(Clone, Debug, PartialEq, Eq)]\nstruct DecryptionBindingV1")
        .next()
        .expect("production sparse-challenge boundary");
    let mut prior_end = 0;
    for marker in [
        "let weight = wide_relation_challenge_weight(ring_degree)?;",
        "let mut frame = [0_u8; DECRYPTION_SPARSE_CHALLENGE_DOMAIN_V1.len() + 40];",
        "copy_from_slice(DECRYPTION_SPARSE_CHALLENGE_DOMAIN_V1);",
        ".copy_from_slice(&challenge_seed);",
        "u32::try_from(ring_degree)",
        "u32::try_from(weight)",
        "let stream_bytes = weight",
        "let mut stream = Shake256Reader::new(&frame);",
        "let mut challenge = try_exact_capacity_vec_v1(ring_degree)",
        "challenge.resize(ring_degree, 0_i8);",
        "for _ in 0..stream_bytes / 8",
        "stream.read(&mut candidate);",
        "let word = u64::from_le_bytes(candidate);",
        "if challenge[position] != 0",
        "if word >> 63 == 0 { -1 } else { 1 }",
        "if selected == weight",
        "return Ok(challenge);",
    ] {
        let next = challenge[prior_end..]
            .find(marker)
            .unwrap_or_else(|| panic!("missing ordered sparse-challenge marker: {marker}"));
        prior_end += next + marker.len();
    }
    assert_eq!(challenge.matches("try_exact_capacity_vec_v1(").count(), 1);
    assert!(!challenge.contains("let mut frame = Vec"));
    assert!(!challenge.contains("Vec::with_capacity"));
    assert!(!challenge.contains("shake256("));
    assert!(!challenge.contains("vec!["));
    assert!(!challenge.contains("try_reserve_exact"));
}
#[test]
fn fixed_manifest_encoder_is_exact_ordered_and_deterministic() {
    let decryption = include_str!("decryption.rs");
    let encoder = decryption
        .split("impl ZkAmsMkheDecryptionTransportManifestV1 {")
        .nth(1)
        .expect("transport manifest implementation")
        .split("pub fn encode(&self) -> Result<Vec<u8>, ZkAmsMkheErrorV1> {")
        .nth(1)
        .expect("transport manifest encoder")
        .split("/// Decode, authenticate, and bind one exact manifest")
        .next()
        .expect("transport manifest encoder boundary");
    let mut prior_end = 0;
    for marker in [
        "self.validate_structural()?;",
        "try_exact_capacity_vec_v1(ZK_AMS_MKHE_DECRYPTION_SPLIT_MANIFEST_BYTES_V1)",
        ".map_err(|_| ZkAmsMkheErrorV1::ResourceCeilingExceeded)?;",
        "bytes.extend_from_slice(&DECRYPTION_SPLIT_MANIFEST_TAG_V1);",
        "bytes.push(MKHE_VERSION_V1);",
        "bytes.extend_from_slice(&self.binding.profile_digest);",
        "bytes.extend_from_slice(&self.binding.roster_digest);",
        "bytes.extend_from_slice(&self.binding.epoch.to_be_bytes());",
        "bytes.extend_from_slice(&self.binding.transcript_digest);",
        "bytes.extend_from_slice(&self.binding.ciphertext_digest);",
        "bytes.extend_from_slice(&self.binding.key_context_digest);",
        "bytes.extend_from_slice(&self.binding.statement_binding_digest);",
        "bytes.extend_from_slice(&self.binding.ciphertext_record_index.to_be_bytes());",
        "bytes.extend_from_slice(&self.binding.sample_index.to_be_bytes());",
        "bytes.push(self.binding.party_index);",
        "bytes.extend_from_slice(&self.binding.party.to_bytes());",
        "bytes.push(self.binding.level);",
        "bytes.push(DECRYPTION_SPLIT_COMPONENT_COUNT_V1 as u8);",
        "write_decryption_transport_pointer(&mut bytes, 0, self.polynomial);",
        "write_decryption_transport_pointer(&mut bytes, 1, self.proof);",
        "bytes.extend_from_slice(&self.manifest_digest);",
        "bytes.extend_from_slice(&self.authentication.party.to_bytes());",
        "bytes.extend_from_slice(&self.authentication.public_key);",
        "bytes.extend_from_slice(&self.authentication.signature);",
        "if bytes.len() != ZK_AMS_MKHE_DECRYPTION_SPLIT_MANIFEST_BYTES_V1",
        "if bytes.capacity() != ZK_AMS_MKHE_DECRYPTION_SPLIT_MANIFEST_BYTES_V1",
        "Ok(bytes)",
    ] {
        let next = encoder[prior_end..]
            .find(marker)
            .unwrap_or_else(|| panic!("missing ordered manifest-encoder marker: {marker}"));
        prior_end += next + marker.len();
    }
    assert_eq!(encoder.matches("try_exact_capacity_vec_v1(").count(), 1);
    assert!(!encoder.contains("Vec::with_capacity"));
    assert!(!encoder.contains("try_reserve_exact"));

    let mut random = KatRandom::new(b"fixed-manifest-capacity");
    let secret = AuthenticationSecret::generate(&mut random).unwrap();
    let party = secret.party_id().unwrap();
    let evidence = derive_decryption_resource_evidence(&release_profile_v1()).unwrap();
    let binding = DecryptionBindingV1 {
        profile_digest: [0x11; 32],
        roster_digest: [0x22; 32],
        epoch: 7,
        transcript_digest: [0x33; 32],
        ciphertext_digest: [0x44; 32],
        key_context_digest: [0x55; 32],
        statement_binding_digest: [0x66; 32],
        ciphertext_record_index: 9,
        sample_index: 11,
        party_index: 0,
        party,
        level: 1,
    };
    let polynomial = ZkAmsMkheDecryptionTransportPointerV1 {
        kind: ZkAmsMkheDecryptionTransportComponentKindV1::SharePolynomial,
        payload_bytes: evidence.split_polynomial_object_bytes,
        payload_blake3: [0x77; 32],
    };
    let proof = ZkAmsMkheDecryptionTransportPointerV1 {
        kind: ZkAmsMkheDecryptionTransportComponentKindV1::ProofEnvelope,
        payload_bytes: evidence.split_proof_envelope_bytes,
        payload_blake3: [0x88; 32],
    };
    let digest = decryption_split_manifest_digest(&binding, polynomial, proof).unwrap();
    let authentication = ArtifactAuthentication::sign(
        DECRYPTION_SPLIT_MANIFEST_AUTH_DOMAIN_V1,
        digest,
        &secret,
        &mut random,
    )
    .unwrap();
    let manifest =
        ZkAmsMkheDecryptionTransportManifestV1::new(binding, polynomial, proof, authentication)
            .unwrap();
    let encoded = manifest.encode().unwrap();
    assert_eq!(
        encoded.len(),
        ZK_AMS_MKHE_DECRYPTION_SPLIT_MANIFEST_BYTES_V1
    );
    assert_eq!(
        encoded.capacity(),
        ZK_AMS_MKHE_DECRYPTION_SPLIT_MANIFEST_BYTES_V1
    );
    assert_eq!(manifest.encode().unwrap(), encoded);
}
#[test]
fn release_plaintext_decoder_uses_exact_output_and_stack_crt_scratch() {
    let decryption = include_str!("decryption.rs");
    let decoder = decryption
        .split("fn decode_centered_plaintext(")
        .nth(1)
        .expect("centered plaintext decoder")
        .split("#[path = \"decryption_streaming.rs\"]")
        .next()
        .expect("centered plaintext decoder boundary");
    assert_eq!(decoder.matches("PlaintextModulus::T256 => {").count(), 1);
    let t256 = decoder
        .split("PlaintextModulus::T256 => {")
        .nth(1)
        .expect("release T256 decoder");
    let mut prior_end = 0;
    for marker in [
        "try_exact_capacity_vec_v1(profile.ring_degree)",
        ".map_err(|_| ZkAmsMkheErrorV1::ResourceCeilingExceeded)?;",
        "let plaintext_allocation = plaintext.as_ptr();",
        "let mut residue_scratch = [0_u64; super::MAX_RNS_LIMBS_V1];",
        "let residues = &mut residue_scratch[..profile.moduli.len()];",
        "for coefficient in 0..profile.ring_degree",
        "for (limb, residue) in residues.iter_mut().enumerate()",
        "*residue = polynomial.limb(profile, limb)[coefficient];",
        "let centered = centered_crt(residues, profile.moduli, ciphertext_modulus)?;",
        "plaintext.push(canonical);",
        "if plaintext.len() != profile.ring_degree",
        "|| plaintext.capacity() != profile.ring_degree",
        "|| plaintext.as_ptr() != plaintext_allocation",
        "DecryptedPlaintextV1::T256(plaintext)",
    ] {
        let next = t256[prior_end..]
            .find(marker)
            .unwrap_or_else(|| panic!("missing ordered T256 decoder marker: {marker}"));
        prior_end += next + marker.len();
    }
    assert_eq!(t256.matches("try_exact_capacity_vec_v1(").count(), 1);
    assert!(!t256.contains("Vec::with_capacity"));
    assert!(!t256.contains("collect::<Vec"));
    assert!(!t256.contains("try_reserve_exact"));

    let profile = release_profile_v1();
    assert_eq!(profile.ring_degree, 131_072);
    assert_eq!(profile.moduli.len(), 38);
    assert_eq!(profile.ring_degree * size_of::<[u8; 32]>(), 4_194_304);
    assert_eq!(core::mem::size_of_val(profile.moduli), 304);
    assert_eq!(super::super::MAX_RNS_LIMBS_V1 * size_of::<u64>(), 512);
}
#[test]
fn native_full_roster_compatibility_is_test_only_and_not_facaded() {
    let decryption = include_str!("decryption.rs");
    for required in [
        "#[cfg(test)]\n#[derive(Clone, Copy)]\npub struct ZkAmsMkheDecryptionStatementV1",
        "#[cfg(test)]\n#[derive(Clone, PartialEq, Eq)]\npub struct ZkAmsMkheDecryptionProofV1",
        "#[cfg(test)]\n#[derive(Clone, PartialEq, Eq)]\npub struct ZkAmsMkheAuthenticatedDecryptionShareV1",
        "#[cfg(test)]\npub struct ZkAmsMkheDecryptionSplitTransportV1",
    ] {
        assert!(
            decryption.contains(required),
            "native full-roster compatibility must remain test-only: {required}",
        );
    }
    for marker in [
        "pub fn split_zk_ams_mkhe_decryption_share_v1(",
        "pub fn reconstruct_zk_ams_mkhe_decryption_share_v1(",
        "pub fn prove_zk_ams_mkhe_decryption_share_v1<",
        "pub fn verify_zk_ams_mkhe_decryption_share_v1(",
        "pub fn verify_combine_decode_zk_ams_mkhe_decryption_v1(",
    ] {
        assert_eq!(
            decryption.matches(marker).count(),
            1,
            "native compatibility item"
        );
        let position = decryption.find(marker).expect("native compatibility item");
        let item_start = decryption[..position]
            .rfind("\n\n")
            .map_or(0, |boundary| boundary + 2);
        assert!(
            decryption[item_start..position]
                .lines()
                .any(|line| line.trim() == "#[cfg(test)]"),
            "native full-roster compatibility must remain test-only: {marker}",
        );
    }
    let facades = [
        include_str!("../mkhe.rs"),
        include_str!("../../zk_ams.rs"),
        include_str!("../../../vega.rs"),
    ];
    for forbidden in [
        "ZkAmsMkheDecryptionStatementV1",
        "ZkAmsMkheDecryptionProofV1",
        "ZkAmsMkheAuthenticatedDecryptionShareV1",
        "ZkAmsMkheDecryptionSplitTransportV1",
        "split_zk_ams_mkhe_decryption_share_v1",
        "reconstruct_zk_ams_mkhe_decryption_share_v1",
        "prove_zk_ams_mkhe_decryption_share_v1",
        "verify_zk_ams_mkhe_decryption_share_v1",
        "verify_combine_decode_zk_ams_mkhe_decryption_v1",
    ] {
        assert!(
            facades.iter().all(|source| !source.contains(forbidden)),
            "production facade must omit test-only native surface: {forbidden}",
        );
    }
    for owner in [
        "ZkAmsMkheCollectiveCiphertextV1",
        "ZkAmsMkheCollectiveLevelOneV1",
        "ZkAmsMkheCollectivePublicKeyV1",
    ] {
        for source in facades {
            assert_eq!(
                source.matches(owner).count(),
                1,
                "native facade owner {owner}"
            );
            let position = source.find(owner).expect("native facade owner");
            let gate = source[..position]
                .rfind("#[cfg(test)]")
                .expect("native facade owner cfg(test)");
            let gated_use = &source[gate..position];
            assert!(gated_use.contains("pub use "));
            assert!(gated_use.len() < 256, "detached cfg(test) for {owner}");
        }
    }
    // The streamed collective owners have no production consumer yet, so their
    // facade re-exports stay parked behind `cfg(test)` together with the owners.
    for parked in [
        "ZkAmsMkheCollectivePartyStateV1",
        "ZkAmsMkheCollectivePublicKeyShareV1",
        "ZkAmsMkhePreparedCollectivePublicAV1",
        "ZkAmsMkheStreamingCollectiveCiphertextV1",
    ] {
        for source in facades {
            let position = source.find(parked).expect("parked collective facade owner");
            let use_start = source[..position]
                .rfind("pub use ")
                .expect("parked collective facade pub use");
            let preceding_line = source[..use_start]
                .lines()
                .rev()
                .find(|line| !line.trim().is_empty())
                .map(str::trim);
            assert_eq!(
                preceding_line,
                Some("#[cfg(test)]"),
                "parked collective facade must stay test-only: {parked}",
            );
        }
    }
}
#[test]
fn materialized_collective_key_compatibility_is_test_only_outside_cpk_finalization() {
    let evaluated_keys = include_str!("collective_eval_keys.rs");
    let production_import = evaluated_keys
        .split_once("use super::{")
        .expect("collective evaluated-key production import")
        .1
        .split_once("};")
        .expect("collective evaluated-key production import end")
        .0;
    for forbidden in [
        "ZkAmsMkheCollectivePublicKeyV1",
        "ZkAmsMkheCollectivePublicKeyShareV1",
    ] {
        assert!(
            !production_import.contains(forbidden),
            "production evaluated-key import retained materialized key owner: {forbidden}",
        );
    }
    for required in [
        "#[cfg(test)]\n    pub fn from_verified_collective_key_and_shares(",
        "#[cfg(test)]\nfn validate_evidence_collective_context(",
    ] {
        assert!(
            evaluated_keys.contains(required),
            "materialized collective-key compatibility must remain test-only: {required}",
        );
    }
    let cks_stream = include_str!("collective_eval_keys/cks_stream.rs");
    assert!(
        cks_stream
            .contains("#[cfg(test)]\npub(super) fn trusted_context_from_verified_key_and_shares(")
    );
    assert!(evaluated_keys.contains("pub(super) fn from_staged_verified_digests("));
}
#[test]
fn prepared_collective_batch_api_is_public_through_vega() {
    type Prepare = fn(
        &crate::vega::ZkAmsMkheGovernedActiveRosterV1,
        [u8; 32],
    ) -> Result<
        crate::vega::ZkAmsMkhePreparedCollectivePublicAV1,
        crate::vega::ZkAmsMkheErrorV1,
    >;
    let _: Prepare = crate::vega::prepare_zk_ams_mkhe_collective_public_a_v1;
    type Generate = fn(
        &crate::vega::ZkAmsMkheGovernedActiveRosterV1,
        &crate::vega::ZkAmsMkhePreparedCollectivePublicAV1,
        usize,
        &crate::vega::ZkAmsMkheActivePartySecretV1,
        &mut FastDeterministicRandom,
    ) -> Result<
        (
            crate::vega::ZkAmsMkheCollectivePartyStateV1,
            crate::vega::ZkAmsMkheCollectivePublicKeyShareV1,
        ),
        crate::vega::ZkAmsMkheErrorV1,
    >;
    let _: Generate =
        crate::vega::generate_zk_ams_mkhe_collective_party_state_with_prepared_public_a_v1::<
            FastDeterministicRandom,
        >;
}
#[test]
fn exact_wide_sign_magnitude_boundaries_are_canonical_and_no_wrap() {
    let maximum = WideMagnitudeV1::max_for_bits(1_855).unwrap();
    assert_eq!(maximum.bit_len(), 1_855);
    for value in [
        SignedWideV1::zero(),
        SignedWideV1::new(false, maximum.clone()).unwrap(),
        SignedWideV1::new(true, maximum.clone()).unwrap(),
    ] {
        let encoded = value.encode_fixed(232).unwrap();
        assert_eq!(encoded.len(), 232);
        assert_eq!(SignedWideV1::decode_fixed(&encoded).unwrap(), value);
        for modulus in TEST_MODULI {
            assert!(value.mod_u64(modulus) < modulus);
        }
    }
    let mut negative_zero = vec![0_u8; 232];
    negative_zero[0] = 0x80;
    assert_eq!(
        SignedWideV1::decode_fixed(&negative_zero),
        Err(ZkAmsMkheErrorV1::InvalidWireEncoding)
    );
    let overflow = SignedWideV1::new(false, WideMagnitudeV1::max_for_bits(1_856).unwrap()).unwrap();
    assert_eq!(
        overflow.encode_fixed(232),
        Err(ZkAmsMkheErrorV1::InvalidWireEncoding)
    );
}
#[test]
fn t256_wide_reduction_and_centering_boundaries_are_exact() {
    let modulus = wide_from_be(&super::super::VEGA_T256_SCALAR_MODULUS_BE_V1).unwrap();
    let one = wide_from_u64(1);
    let modulus_minus_one = modulus.checked_sub(one).unwrap();
    let modulus_plus_one = wide_checked_add(modulus, one).unwrap();
    let twice_modulus = wide_checked_add(modulus, modulus).unwrap();
    assert_eq!(reduce_wide_mod_t256(WideUint::zero()), [0; 32]);
    let mut one_be = [0_u8; 32];
    one_be[31] = 1;
    assert_eq!(reduce_wide_mod_t256(one), one_be);
    assert_eq!(
        reduce_wide_mod_t256(modulus_minus_one),
        t256_subtract_modulus(one_be).unwrap()
    );
    assert_eq!(reduce_wide_mod_t256(modulus), [0; 32]);
    assert_eq!(reduce_wide_mod_t256(modulus_plus_one), one_be);
    assert_eq!(reduce_wide_mod_t256(twice_modulus), [0; 32]);
    let negative_one = SignedCrtV1::normalized(true, one);
    let canonical = t256_subtract_modulus(one_be).unwrap();
    let reduced = reduce_wide_mod_t256(negative_one.magnitude);
    assert_eq!(t256_subtract_modulus(reduced).unwrap(), canonical);
    assert!(canonical > super::super::T256_CENTERED_MAX_BE_V1);
}
#[test]
fn unavailable_zero_and_constant_random_sources_fail_closed() {
    assert_eq!(
        validate_wide_relation_random_health(&mut FailingRandom),
        Err(ZkAmsMkheErrorV1::RandomUnavailable)
    );
    assert_eq!(
        validate_wide_relation_random_health(&mut ConstantRandom(0)),
        Err(ZkAmsMkheErrorV1::RandomUnavailable)
    );
    assert_eq!(
        validate_wide_relation_random_health(&mut ConstantRandom(0xa5)),
        Err(ZkAmsMkheErrorV1::RandomUnavailable)
    );
    let bound = WideMagnitudeV1::max_for_bits(TEST_SMUDGE_BITS).unwrap();
    assert_eq!(
        sample_signed_wide(&bound, &mut FailingRandom),
        Err(ZkAmsMkheErrorV1::RandomUnavailable)
    );
}
#[test]
fn transient_secret_owners_zeroize_after_partial_rng_error_and_unwind() {
    reset_decryption_transient_zeroized_drop_count_v1();
    assert_eq!(
        validate_wide_relation_random_health(&mut PartiallyFailingRandom),
        Err(ZkAmsMkheErrorV1::RandomUnavailable)
    );
    assert_eq!(decryption_transient_zeroized_drop_count_v1(), 1);
    let bound = WideMagnitudeV1::max_for_bits(TEST_SMUDGE_BITS).unwrap();
    assert_eq!(
        sample_signed_wide(&bound, &mut PartiallyFailingRandom),
        Err(ZkAmsMkheErrorV1::RandomUnavailable)
    );
    assert_eq!(decryption_transient_zeroized_drop_count_v1(), 2);
    let profile = test_profile();
    let unwind = std::panic::catch_unwind(|| {
        let mut small = ZeroizingI64VectorV1::with_capacity(2).unwrap();
        small.push(7);
        let mut wide = ZeroizingSignedWideVectorV1::with_capacity(1).unwrap();
        wide.push(SignedWideV1::from_i64(-9));
        let _candidate = ZeroizingWideMagnitudeCandidateV1::new(bound.clone());
        let _rns = ZeroizingDecryptionRnsV1::new(
            RnsPolynomial::from_signed(&profile, &[1, -1, 0, 1, 0, -1, 1, 0]).unwrap(),
        );
        panic!("exercise zeroizing unwind owners");
    });
    assert!(unwind.is_err());
    assert_eq!(decryption_transient_zeroized_drop_count_v1(), 6);
}
#[test]
fn compact_cpk_share_validation_rejects_moved_two_party_proof_substitution() {
    let mut roster_random =
        FastDeterministicRandom::new(b"decryption-two-share-substitution-roster");
    let mut party_secrets = (0..ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1)
        .map(|_| ZkAmsMkheActivePartySecretV1::generate(&mut roster_random).unwrap())
        .collect::<Vec<_>>();
    party_secrets.sort_by_key(|secret| secret.party().unwrap());
    let ordered_secrets: [&ZkAmsMkheActivePartySecretV1; ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1] =
        std::array::from_fn(|index| &party_secrets[index]);
    let governed_roster = super::super::active::ZkAmsMkheGovernedActiveRosterV1::new(
        0xdec0_de02,
        ordered_secrets,
        &mut roster_random,
    )
    .unwrap();
    let transcript_digest = keccak256(b"decryption-two-share-substitution.transcript");
    let prepared_public_a =
        prepare_zk_ams_mkhe_collective_public_a_v1(&governed_roster, transcript_digest).unwrap();
    let mut party_zero_random =
        FastDeterministicRandom::new(b"decryption-two-share-substitution-party-0");
    let (party_zero_state, baseline) =
        generate_zk_ams_mkhe_collective_party_state_with_prepared_public_a_v1(
            &governed_roster,
            &prepared_public_a,
            0,
            &party_secrets[0],
            &mut party_zero_random,
        )
        .unwrap();
    drop(party_zero_state);
    let mut party_one_random =
        FastDeterministicRandom::new(b"decryption-two-share-substitution-party-1");
    let (party_one_state, proof_donor) =
        generate_zk_ams_mkhe_collective_party_state_with_prepared_public_a_v1(
            &governed_roster,
            &prepared_public_a,
            1,
            &party_secrets[1],
            &mut party_one_random,
        )
        .unwrap();
    drop(party_one_state);
    assert_eq!(
        validate_collective_public_key_share_for_verified_cpk_compact_v1(
            &governed_roster,
            transcript_digest,
            0,
            &baseline,
        ),
        Ok(baseline.digest())
    );
    // Move the baseline instead of cloning its release-sized polynomial/proof
    // owners. At most the shared A and two party B/proof payloads coexist.
    let mut substitution = baseline;
    substitution
        .splice_active_proof_for_test(&proof_donor)
        .expect("hostile purpose fixture has a recomputed legacy share digest");
    assert_eq!(
        validate_collective_public_key_share_for_verified_cpk_compact_v1(
            &governed_roster,
            transcript_digest,
            0,
            &substitution,
        ),
        Err(ZkAmsMkheErrorV1::InvalidKeyMaterial),
        "a structurally valid proof/authentication substitution must not inherit active admission",
    );
}
#[test]
fn complete_eight_party_native_decryption_kat_recovers_plaintext() {
    let fixture = fixture(b"decryption-positive-kat");
    let shares = make_shares(&fixture, b"decryption-positive-shares");
    let result = aggregate_and_decrypt_full_roster(
        &fixture.profile,
        &fixture.parties,
        &fixture.relations,
        &fixture.ciphertext,
        &shares,
        TEST_SMUDGE_BITS,
        TEST_FINAL_RESIDUAL_BITS,
    )
    .unwrap();
    assert_eq!(
        result.plaintext,
        DecryptedPlaintextV1::Tiny(fixture.message)
    );
    assert_eq!(
        result.ordered_share_set_digest,
        [
            0xef, 0x1e, 0xa0, 0x77, 0xdf, 0x84, 0xd3, 0xca, 0x0a, 0x83, 0xf3, 0xd0, 0x9b, 0x25,
            0x2b, 0xe9, 0x92, 0x93, 0xb7, 0xcc, 0x3e, 0x8e, 0x87, 0x28, 0x68, 0x16, 0xff, 0x83,
            0xfb, 0x00, 0xef, 0x35,
        ]
    );
    assert!(result.maximum_residual_bits <= TEST_FINAL_RESIDUAL_BITS as u16);
    assert_ne!(result.ordered_share_set_digest, [0; 32]);
}
#[test]
fn canonical_share_wire_roundtrip_rehashes_and_reverifies_every_relation() {
    let fixture = fixture(b"decryption-wire-kat");
    let shares = make_shares(&fixture, b"decryption-wire-shares");
    for (index, share) in shares.iter().enumerate() {
        let encoded = share.encode(&fixture.profile, TEST_SMUDGE_BITS).unwrap();
        if index == 0 {
            assert_eq!(
                keccak256(&encoded),
                [
                    0x0e, 0x2a, 0xc6, 0x55, 0x1f, 0x30, 0x64, 0xfd, 0x9d, 0xf1, 0xc2, 0x93, 0x20,
                    0x14, 0x26, 0xe8, 0x07, 0x7e, 0x83, 0x27, 0xa8, 0x73, 0x13, 0x3c, 0x19, 0x4c,
                    0xd1, 0x8d, 0x69, 0x88, 0xbc, 0xbf,
                ]
            );
        }
        let decoded = AuthenticatedDecryptionShareV1::decode_exact(
            &encoded,
            &fixture.profile,
            &fixture.parties,
            &fixture.relations[index].binding,
            TEST_SMUDGE_BITS,
        )
        .unwrap();
        assert_eq!(decoded, *share);
        assert_eq!(
            decoded.encode(&fixture.profile, TEST_SMUDGE_BITS).unwrap(),
            encoded
        );
        verify_authenticated_share(
            &fixture.profile,
            &fixture.parties,
            &fixture.relations[index],
            &fixture.ciphertext,
            &fixture.relations[index].binding,
            &decoded,
            TEST_SMUDGE_BITS,
        )
        .unwrap();
    }
}
#[test]
fn release_resource_evidence_is_exact_for_split_transport() {
    let evidence = zk_ams_mkhe_decryption_resource_evidence_v1().unwrap();
    evidence.validate().unwrap();
    assert_eq!(evidence.ring_degree, 131_072);
    assert_eq!(evidence.rns_limb_count, 38);
    assert_eq!(evidence.roster_size, 8);
    assert_eq!(evidence.smudge_quotient_bits, 1_855);
    assert_eq!(evidence.challenge_weight, 20);
    assert_eq!(evidence.challenge_space_lower_bound_bits, 260);
    assert_eq!(evidence.statistical_security_bits, 128);
    assert_eq!(evidence.mask_slack_log2, 24);
    assert_eq!(evidence.wide_response_coefficient_bytes, 236);
    assert_eq!(evidence.share_polynomial_bytes, 39_845_892);
    assert_eq!(
        evidence.secret_response_bytes,
        131_072 * DECRYPTION_SIGNED_SMALL_BYTES_V1 as u64
    );
    assert_eq!(
        evidence.public_key_error_response_bytes,
        evidence.secret_response_bytes
    );
    assert_eq!(evidence.smudge_response_bytes, 30_932_992);
    assert_eq!(evidence.proof_header_bytes, 55);
    assert_eq!(evidence.proof_payload_bytes, 33_030_199);
    assert_eq!(
        evidence.governed_proof_payload_ceiling_bytes,
        32 * 1024 * 1024
    );
    assert_eq!(evidence.proof_payload_headroom_bytes, 524_233);
    assert!(evidence.proof_payload_ceiling_met);
    assert_eq!(evidence.split_polynomial_object_bytes, 39_845_892);
    assert_eq!(evidence.split_proof_envelope_bytes, 33_030_199);
    assert_eq!(evidence.split_manifest_bytes, 498);
    assert_eq!(evidence.split_polynomial_headroom_bytes, 27_262_972);
    assert_eq!(evidence.split_proof_headroom_bytes, 524_233);
    assert!(evidence.split_component_ceilings_met);
    assert_eq!(
        evidence.native_combine_relation_residency_lower_bound_bytes,
        358_612_992
    );
    assert_eq!(
        evidence.governed_native_workspace_ceiling_bytes,
        160 * 1024 * 1024
    );
    assert!(
        evidence.native_combine_relation_residency_lower_bound_bytes
            > evidence.governed_native_workspace_ceiling_bytes
    );
    assert_eq!(
        evidence.native_peak_residency_certificate_digest,
        ZK_AMS_MKHE_DECRYPTION_NATIVE_RESIDENCY_CERTIFICATE_DIGEST_V1
    );
    assert_eq!(evidence.native_peak_residency_certificate_digest, [0; 32]);
    assert!(!evidence.native_peak_residency_certified);
    assert_eq!(
        evidence.split_release_kat_digest,
        ZK_AMS_MKHE_DECRYPTION_SPLIT_RELEASE_KAT_DIGEST_V1
    );
    assert_eq!(evidence.split_release_kat_digest, [0; 32]);
    assert!(!evidence.split_transport_ready);
    assert_eq!(evidence.record_overhead_bytes, 432);
    assert_eq!(evidence.total_share_record_bytes, 72_876_523);
    assert_eq!(evidence.governed_share_ceiling_bytes, 64 * 1024 * 1024);
    assert!(!evidence.share_ceiling_met);
    assert_eq!(evidence.ceiling_shortfall_bytes, 5_767_659);
    assert_eq!(
        evidence.minimum_sound_share_ceiling_bytes,
        evidence.total_share_record_bytes
    );
    assert_ne!(evidence.evidence_digest, [0; 32]);
    let mut forged_native_ready = evidence;
    forged_native_ready.native_peak_residency_certified = true;
    forged_native_ready.split_transport_ready = true;
    forged_native_ready.evidence_digest = decryption_resource_evidence_digest(forged_native_ready);
    assert_eq!(
        forged_native_ready.validate(),
        Err(ZkAmsMkheErrorV1::InvalidProfile)
    );
}
#[test]
fn release_split_objects_have_exact_canonical_sizes_and_preflight() {
    let profile = release_profile_v1();
    let evidence = zk_ams_mkhe_decryption_resource_evidence_v1().unwrap();
    let polynomial = RnsPolynomial::zero(&profile);
    let polynomial_object = encode_decryption_polynomial_object(&profile, &polynomial).unwrap();
    assert_eq!(polynomial_object.len(), 39_845_892);
    assert!(polynomial_object.len() <= profile.max_share_bytes);
    assert_eq!(
        decode_decryption_polynomial_object(&polynomial_object).unwrap(),
        polynomial
    );
    assert!(
        decode_decryption_polynomial_object(&polynomial_object[..polynomial_object.len() - 1])
            .is_err()
    );
    let mut extended_polynomial = polynomial_object.clone();
    extended_polynomial.push(0);
    assert!(decode_decryption_polynomial_object(&extended_polynomial).is_err());
    drop(extended_polynomial);
    let mut wrong_polynomial_count = polynomial_object.clone();
    wrong_polynomial_count[..4].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(decode_decryption_polynomial_object(&wrong_polynomial_count).is_err());
    drop(wrong_polynomial_count);
    let mut noncanonical_polynomial = polynomial_object.clone();
    noncanonical_polynomial[4..12].copy_from_slice(&profile.moduli[0].to_be_bytes());
    assert!(decode_decryption_polynomial_object(&noncanonical_polynomial).is_err());
    drop(noncanonical_polynomial);
    let proof = DecryptionRelationProofV1 {
        wide_response_bytes: evidence.wide_response_coefficient_bytes,
        challenge_seed: [0x5a; 32],
        secret_response: vec![0; profile.ring_degree],
        public_key_error_response: vec![0; profile.ring_degree],
        smudge_response: vec![SignedWideV1::zero(); profile.ring_degree],
    };
    let proof_envelope = proof.encode().unwrap();
    assert_eq!(proof_envelope.len(), 33_030_199);
    assert!(proof_envelope.len() <= ZK_AMS_MKHE_MAX_PROOF_BYTES_V1);
    let decoded = ZkAmsMkheDecryptionProofV1::decode_release_exact(&proof_envelope).unwrap();
    assert_eq!(decoded, proof);
    assert!(matches!(
        ZkAmsMkheDecryptionProofV1::decode_release_exact(
            &proof_envelope[..proof_envelope.len() - 1]
        ),
        Err(ZkAmsMkheErrorV1::InvalidWireEncoding)
    ));
    let mut extended_proof = proof_envelope.clone();
    extended_proof.push(0);
    assert!(ZkAmsMkheDecryptionProofV1::decode_release_exact(&extended_proof).is_err());
    drop(extended_proof);
    for offset in [
        0_usize, // tag
        4,       // version
        5,       // fixed wide-response width
        7,       // ring degree
        43,      // secret-response count
        47,      // public-error-response count
        51,      // smudge-response count
    ] {
        let mut malformed = proof_envelope.clone();
        malformed[offset] ^= 1;
        assert!(
            ZkAmsMkheDecryptionProofV1::decode_release_exact(&malformed).is_err(),
            "proof header mutation offset {offset} must reject"
        );
    }
    let mut negative_zero = proof_envelope.clone();
    let first_wide_response = DECRYPTION_PROOF_HEADER_BYTES_V1
        + profile.ring_degree * 2 * DECRYPTION_SIGNED_SMALL_BYTES_V1;
    negative_zero
        [first_wide_response..first_wide_response + usize::from(proof.wide_response_bytes)]
        .fill(0);
    negative_zero[first_wide_response] = 0x80;
    assert!(ZkAmsMkheDecryptionProofV1::decode_release_exact(&negative_zero).is_err());
    let polynomial_pointer = ZkAmsMkheDecryptionTransportPointerV1::from_payload(
        ZkAmsMkheDecryptionTransportComponentKindV1::SharePolynomial,
        &polynomial_object,
    )
    .unwrap();
    let proof_pointer = ZkAmsMkheDecryptionTransportPointerV1::from_payload(
        ZkAmsMkheDecryptionTransportComponentKindV1::ProofEnvelope,
        &proof_envelope,
    )
    .unwrap();
    assert_eq!(polynomial_pointer.payload_bytes(), 39_845_892);
    assert_eq!(proof_pointer.payload_bytes(), 33_030_199);
    assert_ne!(polynomial_pointer.payload_blake3(), [0; 32]);
    assert_ne!(proof_pointer.payload_blake3(), [0; 32]);
}
#[test]
fn sound_share_ceiling_boundary_is_exact_to_one_byte() {
    let baseline = zk_ams_mkhe_decryption_resource_evidence_v1().unwrap();
    let mut one_short = release_profile_v1();
    one_short.max_share_bytes = usize::try_from(
        baseline
            .minimum_sound_share_ceiling_bytes
            .checked_sub(1)
            .unwrap(),
    )
    .unwrap();
    let short = derive_decryption_resource_evidence(&one_short).unwrap();
    assert!(!short.share_ceiling_met);
    assert_eq!(short.ceiling_shortfall_bytes, 1);
    let mut exact = release_profile_v1();
    exact.max_share_bytes = usize::try_from(baseline.minimum_sound_share_ceiling_bytes).unwrap();
    let exact = derive_decryption_resource_evidence(&exact).unwrap();
    assert!(exact.share_ceiling_met);
    assert_eq!(exact.ceiling_shortfall_bytes, 0);
    assert_eq!(
        production_decryption_share_record_bytes(
            &release_profile_v1(),
            usize::from(baseline.smudge_quotient_bits),
        )
        .unwrap()
        .1,
        usize::try_from(baseline.minimum_sound_share_ceiling_bytes).unwrap()
    );
}
#[test]
fn missing_excess_duplicate_and_reordered_sets_identify_first_slot() {
    let fixture = fixture(b"decryption-set-negative");
    let shares = make_shares(&fixture, b"decryption-set-negative-shares");
    let missing = aggregate_and_decrypt_full_roster(
        &fixture.profile,
        &fixture.parties,
        &fixture.relations,
        &fixture.ciphertext,
        &shares[..7],
        TEST_SMUDGE_BITS,
        TEST_FINAL_RESIDUAL_BITS,
    )
    .unwrap_err();
    assert_eq!(missing.reason, DecryptionAbortReasonV1::MissingShare);
    assert_eq!(missing.party_index, 7);
    let mut excess = shares.clone();
    excess.push(shares[0].clone());
    assert_eq!(
        aggregate_and_decrypt_full_roster(
            &fixture.profile,
            &fixture.parties,
            &fixture.relations,
            &fixture.ciphertext,
            &excess,
            TEST_SMUDGE_BITS,
            TEST_FINAL_RESIDUAL_BITS,
        )
        .unwrap_err()
        .reason,
        DecryptionAbortReasonV1::ExcessShare
    );
    for mutation in [
        {
            let mut values = shares.clone();
            values[1] = values[0].clone();
            values
        },
        {
            let mut values = shares.clone();
            values.swap(2, 3);
            values
        },
    ] {
        let abort = aggregate_and_decrypt_full_roster(
            &fixture.profile,
            &fixture.parties,
            &fixture.relations,
            &fixture.ciphertext,
            &mutation,
            TEST_SMUDGE_BITS,
            TEST_FINAL_RESIDUAL_BITS,
        )
        .unwrap_err();
        assert_eq!(
            abort.reason,
            DecryptionAbortReasonV1::ReorderedOrDuplicateShare
        );
        assert_ne!(abort.evidence_digest, [0; 32]);
    }
}
#[test]
fn every_binding_axis_and_replay_axis_fails_closed() {
    let fixture = fixture(b"decryption-binding-negative");
    let shares = make_shares(&fixture, b"decryption-binding-negative-shares");
    for axis in 0..12 {
        let mut mutation = shares[3].clone();
        match axis {
            0 => mutation.binding.profile_digest[0] ^= 1,
            1 => mutation.binding.roster_digest[0] ^= 1,
            2 => mutation.binding.epoch += 1,
            3 => mutation.binding.transcript_digest[0] ^= 1,
            4 => mutation.binding.ciphertext_digest[0] ^= 1,
            5 => mutation.binding.key_context_digest[0] ^= 1,
            6 => mutation.binding.statement_binding_digest[0] ^= 1,
            7 => mutation.binding.ciphertext_record_index += 1,
            8 => mutation.binding.sample_index += 1,
            9 => mutation.binding.party_index = 4,
            10 => mutation.binding.party = fixture.parties.parties[4],
            11 => mutation.binding.level = 0,
            _ => unreachable!(),
        }
        assert!(
            verify_authenticated_share(
                &fixture.profile,
                &fixture.parties,
                &fixture.relations[3],
                &fixture.ciphertext,
                &fixture.relations[3].binding,
                &mutation,
                TEST_SMUDGE_BITS,
            )
            .is_err(),
            "binding axis {axis} must reject"
        );
    }
    let other_fixture = self::fixture(b"decryption-binding-other-session");
    assert!(
        verify_authenticated_share(
            &other_fixture.profile,
            &other_fixture.parties,
            &other_fixture.relations[3],
            &other_fixture.ciphertext,
            &other_fixture.relations[3].binding,
            &shares[3],
            TEST_SMUDGE_BITS,
        )
        .is_err()
    );
}
#[test]
fn polynomial_public_key_proof_and_authentication_mutations_are_rejected() {
    let fixture = fixture(b"decryption-proof-negative");
    let shares = make_shares(&fixture, b"decryption-proof-negative-shares");
    let mut share_poly = shares[2].clone();
    share_poly.share.coefficients[0] =
        (share_poly.share.coefficients[0] + 1) % fixture.profile.moduli[0];
    assert_eq!(
        verify_authenticated_share(
            &fixture.profile,
            &fixture.parties,
            &fixture.relations[2],
            &fixture.ciphertext,
            &fixture.relations[2].binding,
            &share_poly,
            TEST_SMUDGE_BITS,
        ),
        Err(ZkAmsMkheErrorV1::InvalidAuthentication)
    );
    let mut bad_relation = fixture.relations[2].clone();
    bad_relation.party_b.coefficients[0] =
        (bad_relation.party_b.coefficients[0] + 1) % fixture.profile.moduli[0];
    assert!(
        verify_authenticated_share(
            &fixture.profile,
            &fixture.parties,
            &bad_relation,
            &fixture.ciphertext,
            &fixture.relations[2].binding,
            &shares[2],
            TEST_SMUDGE_BITS,
        )
        .is_err()
    );
    for mutation in 0..4 {
        let mut proof = shares[2].clone();
        match mutation {
            0 => proof.proof.challenge_seed[0] ^= 1,
            1 => proof.proof.secret_response[0] += 1,
            2 => proof.proof.public_key_error_response[0] += 1,
            3 => {
                proof.proof.smudge_response[0] = proof.proof.smudge_response[0]
                    .checked_add(&SignedWideV1::from_i64(1))
                    .unwrap();
            }
            _ => unreachable!(),
        }
        assert!(
            verify_decryption_relation(
                &fixture.profile,
                &fixture.parties,
                &fixture.relations[2],
                &fixture.ciphertext,
                &proof.share,
                TEST_SMUDGE_BITS,
                &proof.proof,
            )
            .is_err(),
            "proof mutation {mutation} must reject"
        );
    }
    assert!(
        verify_decryption_relation(
            &fixture.profile,
            &fixture.parties,
            &fixture.relations[2],
            &fixture.ciphertext,
            &shares[2].share,
            TEST_SMUDGE_BITS + 1,
            &shares[2].proof,
        )
        .is_err(),
        "a proof must not replay under another smudging bound"
    );
    let mut signature = shares[2].clone();
    signature.authentication.signature[64] ^= 1;
    assert_eq!(
        verify_authenticated_share(
            &fixture.profile,
            &fixture.parties,
            &fixture.relations[2],
            &fixture.ciphertext,
            &fixture.relations[2].binding,
            &signature,
            TEST_SMUDGE_BITS,
        ),
        Err(ZkAmsMkheErrorV1::InvalidAuthentication)
    );
}
#[test]
fn cross_party_relation_proof_authentication_and_ciphertext_splices_fail() {
    let fixture = fixture(b"decryption-splice-negative");
    let shares = make_shares(&fixture, b"decryption-splice-negative-shares");
    let index = 4;
    let mut proof_splice = shares[index].clone();
    proof_splice.proof = shares[index + 1].proof.clone();
    assert!(
        verify_decryption_relation(
            &fixture.profile,
            &fixture.parties,
            &fixture.relations[index],
            &fixture.ciphertext,
            &proof_splice.share,
            TEST_SMUDGE_BITS,
            &proof_splice.proof,
        )
        .is_err()
    );
    let mut authentication_splice = shares[index].clone();
    authentication_splice.authentication = shares[index + 1].authentication.clone();
    assert!(
        verify_authenticated_share(
            &fixture.profile,
            &fixture.parties,
            &fixture.relations[index],
            &fixture.ciphertext,
            &fixture.relations[index].binding,
            &authentication_splice,
            TEST_SMUDGE_BITS,
        )
        .is_err()
    );
    assert!(
        verify_authenticated_share(
            &fixture.profile,
            &fixture.parties,
            &fixture.relations[index + 1],
            &fixture.ciphertext,
            &fixture.relations[index].binding,
            &shares[index],
            TEST_SMUDGE_BITS,
        )
        .is_err()
    );
    for mutate_constant in [false, true] {
        let mut constant = fixture.ciphertext.constant().clone();
        let mut linear = fixture.ciphertext.linear().clone();
        let polynomial = if mutate_constant {
            &mut constant
        } else {
            &mut linear
        };
        polynomial.coefficients[0] = (polynomial.coefficients[0] + 1) % fixture.profile.moduli[0];
        let ciphertext = ZkAmsMkheCollectiveCiphertextV1::new(
            &fixture.profile,
            &fixture.parties,
            fixture.ciphertext.epoch(),
            fixture.ciphertext.transcript_digest(),
            fixture.ciphertext.sample_index(),
            fixture.ciphertext.level(),
            constant,
            linear,
        )
        .unwrap();
        assert!(
            verify_authenticated_share(
                &fixture.profile,
                &fixture.parties,
                &fixture.relations[index],
                &ciphertext,
                &fixture.relations[index].binding,
                &shares[index],
                TEST_SMUDGE_BITS,
            )
            .is_err()
        );
    }
    let mut wrong_profile = fixture.profile.clone();
    wrong_profile.profile_id[0] ^= 1;
    assert!(
        verify_authenticated_share(
            &wrong_profile,
            &fixture.parties,
            &fixture.relations[index],
            &fixture.ciphertext,
            &fixture.relations[index].binding,
            &shares[index],
            TEST_SMUDGE_BITS,
        )
        .is_err()
    );
}
#[test]
fn response_bounds_reject_one_step_over_every_family() {
    let fixture = fixture(b"decryption-response-bound-negative");
    let share = make_shares(&fixture, b"decryption-response-bound-shares").remove(0);
    let weight = wide_relation_challenge_weight(fixture.profile.ring_degree).unwrap();
    let (_, secret_limit) = small_response_parameters(1, weight, &fixture.profile).unwrap();
    let (_, error_limit) = small_response_parameters(
        i64::from(fixture.profile.error_eta),
        weight,
        &fixture.profile,
    )
    .unwrap();
    let (_, wide_limit, _) = wide_response_parameters(TEST_SMUDGE_BITS, weight).unwrap();
    let mut secret = share.proof.clone();
    secret.secret_response[0] = secret_limit + 1;
    let mut error = share.proof.clone();
    error.public_key_error_response[0] = error_limit + 1;
    let mut wide = share.proof.clone();
    wide.smudge_response[0] = SignedWideV1::new(
        false,
        wide_limit
            .checked_add(&WideMagnitudeV1 {
                limbs: {
                    let mut limbs = [0_u64; DECRYPTION_MAX_WIDE_LIMBS_V1];
                    limbs[0] = 1;
                    limbs
                },
            })
            .unwrap(),
    )
    .unwrap();
    for proof in [secret, error, wide] {
        assert_eq!(
            verify_decryption_relation(
                &fixture.profile,
                &fixture.parties,
                &fixture.relations[0],
                &fixture.ciphertext,
                &share.share,
                TEST_SMUDGE_BITS,
                &proof,
            ),
            Err(ZkAmsMkheErrorV1::InvalidShareProof)
        );
    }
}
#[test]
fn decoder_preflights_truncation_extension_counts_residues_and_negative_zero() {
    let fixture = fixture(b"decryption-wire-negative");
    let share = make_shares(&fixture, b"decryption-wire-negative-shares").remove(0);
    let encoded = share.encode(&fixture.profile, TEST_SMUDGE_BITS).unwrap();
    for malformed in [
        encoded[..encoded.len() - 1].to_vec(),
        {
            let mut value = encoded.clone();
            value.push(0);
            value
        },
        {
            let mut value = encoded.clone();
            // Residue count begins immediately before the proof length.
            let offset = TEST_DECRYPTION_SHARE_HEADER_BYTES_V1 - 4;
            value[offset..offset + 4].copy_from_slice(&u32::MAX.to_be_bytes());
            value
        },
    ] {
        assert!(
            AuthenticatedDecryptionShareV1::decode_exact(
                &malformed,
                &fixture.profile,
                &fixture.parties,
                &fixture.relations[0].binding,
                TEST_SMUDGE_BITS,
            )
            .is_err()
        );
    }
    let polynomial_offset = TEST_DECRYPTION_SHARE_HEADER_BYTES_V1 + 4;
    let mut noncanonical = encoded.clone();
    noncanonical[polynomial_offset..polynomial_offset + 8]
        .copy_from_slice(&fixture.profile.moduli[0].to_be_bytes());
    assert!(
        AuthenticatedDecryptionShareV1::decode_exact(
            &noncanonical,
            &fixture.profile,
            &fixture.parties,
            &fixture.relations[0].binding,
            TEST_SMUDGE_BITS,
        )
        .is_err()
    );
    let proof_offset = TEST_DECRYPTION_SHARE_HEADER_BYTES_V1
        + checked_rns_polynomial_bytes(&fixture.profile).unwrap();
    let wide_bytes = usize::from(share.proof.wide_response_bytes);
    let wide_offset =
        proof_offset + DECRYPTION_PROOF_HEADER_BYTES_V1 + fixture.profile.ring_degree * 16;
    let mut negative_zero = encoded.clone();
    negative_zero[wide_offset..wide_offset + wide_bytes].fill(0);
    negative_zero[wide_offset] = 0x80;
    assert!(
        AuthenticatedDecryptionShareV1::decode_exact(
            &negative_zero,
            &fixture.profile,
            &fixture.parties,
            &fixture.relations[0].binding,
            TEST_SMUDGE_BITS,
        )
        .is_err()
    );
}
#[test]
fn final_centered_correctness_bound_is_enforced_after_all_proofs() {
    let fixture = fixture(b"decryption-bound-negative");
    let shares = make_shares(&fixture, b"decryption-bound-negative-shares");
    let abort = aggregate_and_decrypt_full_roster(
        &fixture.profile,
        &fixture.parties,
        &fixture.relations,
        &fixture.ciphertext,
        &shares,
        TEST_SMUDGE_BITS,
        1,
    )
    .unwrap_err();
    assert_eq!(
        abort.reason,
        DecryptionAbortReasonV1::CorrectnessBoundExceeded
    );
}
