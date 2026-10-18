//! Native authority, canonical transport and complete-claim mutation regressions.

use super::*;
use iroha_crypto::Hash;
use iroha_pasta::PastaAffine;
use p256::ecdsa::{Signature, SigningKey, signature::Signer};

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes((&[seed; 32]).into()).unwrap()
}

fn public(key: &SigningKey) -> KagemushaDevicePublicKeyV1 {
    KagemushaDevicePublicKeyV1::from_sec1_bytes(
        key.verifying_key().to_encoded_point(false).as_bytes(),
    )
    .unwrap()
}

fn sign(key: &SigningKey, message: &[u8]) -> KagemushaWalletSignerOutputV1<'static> {
    let signature: Signature = key.sign(message);
    KagemushaWalletSignerOutputV1::Raw(signature.to_bytes().into())
}

struct Authority {
    scheme: KagemushaWalletSchemeV1,
    signer: KagemushaWalletSignerCertificateV1,
    manifest: KagemushaWalletArtifactManifestV1,
    runtime: RuntimeBindings,
    allowlist: KagemushaWalletVerifyingKeyAllowlistV1,
}

fn fixture() -> Authority {
    // These proof-length/key placeholders exercise authority rejection only; they never
    // construct an admitted ArtifactSet or claim a genuine operation proof.
    let allowlist = KagemushaWalletVerifyingKeyAllowlistV1 {
        version: 1,
        steps: KagemushaWalletOperationKindV1::ALL
            .iter()
            .map(|kind| KagemushaWalletVerifyingKeyEntryV1 {
                kind: *kind,
                enabled_controls: 0,
                verifying_key_digest: [kind.tag() + 1; 32],
                proof_bytes: 1,
            })
            .collect(),
        lineage_verifying_key_digest: [9; 32],
        lineage_proof_bytes: 1,
    };
    let runtime = RuntimeBindings {
        eq_protocol_digest: [21; 32],
        ep_protocol_digest: [22; 32],
        native_profile_digest: [23; 32],
        artifact_inventory_digest: [24; 32],
    };
    let root = key(7);
    let artifact = key(8);
    let scheme = KagemushaWalletSchemeV1 {
        version: 1,
        network_id: *Hash::new(b"wallet-native-artifact-test").as_ref(),
        scheme_root_key: public(&root),
        relation_id: kagemusha_wallet_relation_id_v1(
            &runtime.eq_protocol_digest,
            &runtime.ep_protocol_digest,
            &runtime.native_profile_digest,
            &allowlist.verifying_key_set_digest().unwrap(),
            &runtime.artifact_inventory_digest,
        ),
        provider_contract: kagemusha_wallet_provider_contract_v1(),
    };
    let certificate = KagemushaWalletSignerCertificateBodyV1 {
        version: 1,
        scheme_id: scheme.scheme_id(),
        role: KagemushaWalletSignerRoleV1::Artifact,
        key: public(&artifact),
        serial: 1,
    };
    let signer = KagemushaWalletSignerCertificateV1::sign(
        certificate,
        &scheme,
        sign(&root, &certificate.signing_message()),
    )
    .unwrap();
    let body = KagemushaWalletArtifactManifestBodyV1 {
        version: 1,
        network_id: scheme.network_id,
        relation_id: scheme.relation_id,
        eq_protocol_digest: runtime.eq_protocol_digest,
        ep_protocol_digest: runtime.ep_protocol_digest,
        native_profile_digest: runtime.native_profile_digest,
        verifying_key_set_digest: allowlist.verifying_key_set_digest().unwrap(),
        artifact_inventory_digest: runtime.artifact_inventory_digest,
        provider_contract: scheme.provider_contract,
        signer_certificate: signer.certificate_digest(),
    };
    let manifest = KagemushaWalletArtifactManifestV1::sign(
        body,
        &signer,
        sign(&artifact, &body.signing_message()),
    )
    .unwrap();
    Authority {
        scheme,
        signer,
        manifest,
        runtime,
        allowlist,
    }
}

fn load(f: &Authority, expected: [u8; 32], runtime: RuntimeBindings) -> Result<ArtifactSet, Error> {
    ArtifactSet::authenticate(
        f.scheme,
        &f.signer,
        &f.manifest,
        expected,
        runtime,
        f.allowlist.clone(),
        &[],
        LineageArtifact {
            descriptor: b"missing",
            verifying_key: b"missing",
        },
    )
}

#[test]
fn signed_manifest_never_admits_an_incomplete_catalog() {
    let f = fixture();
    assert_eq!(
        load(&f, f.manifest.manifest_digest(), f.runtime).err(),
        Some(Error::Inventory)
    );
    assert_eq!(
        load(&f, [0; 32], f.runtime).err(),
        Some(Error::RuntimeBinding)
    );
    assert_eq!(
        load(&f, [99; 32], f.runtime).err(),
        Some(Error::RuntimeBinding)
    );
    let mut wrong = f;
    wrong.scheme.network_id = *Hash::new(b"another-network").as_ref();
    assert_eq!(
        load(&wrong, wrong.manifest.manifest_digest(), wrong.runtime).err(),
        Some(Error::Authority)
    );
}

#[test]
fn every_native_runtime_binding_is_required_independently() {
    let f = fixture();
    assert_eq!(f.runtime.require(&f.manifest), Ok(()));
    for index in 0..4 {
        for substituted in [[0; 32], [88; 32]] {
            let mut runtime = f.runtime;
            match index {
                0 => runtime.eq_protocol_digest = substituted,
                1 => runtime.ep_protocol_digest = substituted,
                2 => runtime.native_profile_digest = substituted,
                _ => runtime.artifact_inventory_digest = substituted,
            }
            assert_eq!(
                load(&f, f.manifest.manifest_digest(), runtime).err(),
                Some(Error::RuntimeBinding)
            );
        }
    }
}

#[test]
fn inventory_bounds_reject_empty_and_oversized_material_before_decoding() {
    assert_eq!(inventory_size([(&b"descriptor"[..], &b"key"[..])]), Ok(()));
    assert_eq!(
        inventory_size([(&[][..], &b"key"[..])]),
        Err(Error::Inventory)
    );
    assert_eq!(
        inventory_size([(&b"descriptor"[..], &[][..])]),
        Err(Error::Inventory)
    );
    let large = vec![1; DESCRIPTOR_MAX + 1];
    assert_eq!(
        inventory_size([(&large[..], &b"key"[..])]),
        Err(Error::Inventory)
    );
    let large = vec![1; KEY_MAX + 1];
    assert_eq!(
        inventory_size([(&b"descriptor"[..], &large[..])]),
        Err(Error::Inventory)
    );
    let descriptor = vec![1; DESCRIPTOR_MAX];
    let key = vec![1; KEY_MAX];
    assert_eq!(
        inventory_size((0..17).map(|_| (&descriptor[..], &key[..]))),
        Err(Error::Inventory)
    );
    assert_eq!(
        binding(b"not a V2 descriptor", CurveV1::Pallas, true).err(),
        Some(Error::Profile)
    );
}

#[test]
fn transport_requires_exact_proof_and_two_canonical_finite_claims() {
    assert!(decode_transport(&[], 0).is_err());
    assert!(decode_transport(&[1; 5], usize::MAX).is_err());
    let bytes = vec![0; 1 + 2 * ACCUMULATOR_BYTES];
    assert!(
        decode_transport(&bytes, 1).is_err(),
        "identity/zero claim rejected"
    );
    assert!(decode_transport(&bytes[..bytes.len() - 1], 1).is_err());
    let mut extended = bytes;
    extended.push(0);
    assert!(
        decode_transport(&extended, 1).is_err(),
        "extension is not an alternate frame"
    );
}

#[test]
fn foreign_challenge_limbs_preserve_all_256_bits_without_reduction() {
    let bytes = std::array::from_fn(|i| i as u8);
    let [low, high] = limbs(&bytes);
    assert_eq!(&low[..16], &bytes[..16]);
    assert_eq!(&high[..16], &bytes[16..]);
    assert_eq!(&low[16..], &[0; 16]);
    assert_eq!(&high[16..], &[0; 16]);
}

#[test]
fn lineage_digest_matches_independent_integer_rp57_endian_and_order_vector() {
    // Reproduce this vector with fixtures/native_prover/lineage_digest_vector.py,
    // which uses the independent Python integer RP57 sponge and checks the Fp table pin.
    // The fixed finite point (-1,2) and challenges1..16 are only an encoding vector;
    // no accumulator decide or monetary acceptance is asserted for this claim.
    let point = Option::<iroha_pasta::EpAffine>::from(iroha_pasta::EpAffine::from_xy(
        -Fp::from(1),
        Fp::from(2),
    ))
    .unwrap();
    let claim =
        AccumulatorT::<Ep>::new(point, std::array::from_fn(|i| Fq::from(i as u64 + 1))).unwrap();
    let key = hex::decode(concat!(
        "04",
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
    ))
    .unwrap();
    let public = KagemushaWalletLineagePublicV1 {
        version: 1,
        scheme_id: std::array::from_fn(|i| i as u8),
        relation_id: std::array::from_fn(|i| (31 - i) as u8),
        head: KagemushaWalletStateCommitmentV1 {
            value: Fp::from(3).to_repr(),
        },
        wallet_id: [0x42; 32],
        credential_digest: Fp::from(5).to_repr(),
        payment_key: KagemushaDevicePublicKeyV1::from_sec1_bytes(&key).unwrap(),
        lifecycle: KagemushaWalletLifecycleV1::Active,
        policy_epoch: 0x0102_0304_0506_0708,
        enabled_controls: KAGEMUSHA_WALLET_CONTROLS_DEFINED_MASK_V1,
        burned_total: 0x1122_3344_5566_7788_99aa_bbcc_ddee_ff00,
        pending_outgoing_root: Fp::from(9).to_repr(),
        credit_digest_root: Fp::from(10).to_repr(),
    };
    assert_eq!(
        public.enabled_controls, 3,
        "the two-control vector is fixed"
    );
    assert_eq!(
        hex::encode(lineage_digest(&public, Fp::from(11).to_repr(), &claim).unwrap()),
        "4501dca8d1da0168c8000e3bcb18c2178e5258e5bff684a07a6bc1fed852780f",
    );
    // The independent producer also reproduces the old raw mask-7 digest. That is
    // an encoding control only: the retired control bit cannot enter native verification.
    let mut retired = public;
    retired.enabled_controls = 7;
    assert_eq!(
        lineage_digest(&retired, Fp::from(11).to_repr(), &claim),
        Err(Error::Authority),
    );
}

fn lineage_public() -> KagemushaWalletLineagePublicV1 {
    KagemushaWalletLineagePublicV1 {
        version: 1,
        scheme_id: [1; 32],
        relation_id: [2; 32],
        head: KagemushaWalletStateCommitmentV1 {
            value: Fp::from(3).to_repr(),
        },
        wallet_id: [4; 32],
        credential_digest: Fp::from(5).to_repr(),
        payment_key: public(&key(6)),
        lifecycle: KagemushaWalletLifecycleV1::Active,
        policy_epoch: 7,
        enabled_controls: 0,
        burned_total: 8,
        pending_outgoing_root: Fp::from(9).to_repr(),
        credit_digest_root: Fp::from(10).to_repr(),
    }
}

#[test]
#[ignore = "complete k16 transparent params and native accumulator decides; run optimized"]
fn lineage_digest_binds_every_field_and_both_claims_decide_independently() {
    let ep = PinnedParams::<Ep>::derive(16).unwrap();
    let eq = PinnedParams::<Eq>::derive(16).unwrap();
    let pallas = AccumulatorT::trivial(&ep, MemoryBudget::DEFAULT).unwrap();
    let vesta = AccumulatorT::trivial(&eq, MemoryBudget::DEFAULT).unwrap();
    let public = lineage_public();
    let key_digest = Fp::from(11).to_repr();
    let original = lineage_digest(&public, key_digest, &pallas).unwrap();
    for field in 0..12 {
        let mut changed = public;
        match field {
            0 => changed.scheme_id[0] ^= 1,
            1 => changed.relation_id[0] ^= 1,
            2 => changed.head.value = Fp::from(12).to_repr(),
            3 => changed.wallet_id[0] ^= 1,
            4 => changed.credential_digest = Fp::from(13).to_repr(),
            5 => changed.payment_key = super::tests::public(&key(14)),
            6 => changed.lifecycle = KagemushaWalletLifecycleV1::Retiring,
            7 => changed.policy_epoch += 1,
            8 => changed.enabled_controls = 1,
            9 => changed.burned_total += 1,
            10 => changed.pending_outgoing_root = Fp::from(15).to_repr(),
            _ => changed.credit_digest_root = Fp::from(16).to_repr(),
        }
        assert_ne!(
            lineage_digest(&changed, key_digest, &pallas).unwrap(),
            original,
            "public field {field}"
        );
    }
    assert_ne!(
        lineage_digest(&public, Fp::from(17).to_repr(), &pallas).unwrap(),
        original
    );
    let mut challenges = *pallas.challenges();
    challenges[15] = Fq::from(2);
    let poisoned = AccumulatorT::<Ep>::new(*pallas.g(), challenges).unwrap();
    assert_ne!(
        lineage_digest(&public, key_digest, &poisoned).unwrap(),
        original
    );
    assert!(poisoned.decide(&ep, MemoryBudget::DEFAULT).is_err());
    let mut challenges = *vesta.challenges();
    challenges[0] = Fp::from(2);
    let poisoned_vesta = AccumulatorT::<Eq>::new(*vesta.g(), challenges).unwrap();
    assert!(poisoned_vesta.decide(&eq, MemoryBudget::DEFAULT).is_err());
    assert_eq!(vesta.decide(&eq, MemoryBudget::DEFAULT), Ok(()));
    assert_eq!(pallas.decide(&ep, MemoryBudget::DEFAULT), Ok(()));
    let mut transport = vec![7; 32];
    transport.extend(pallas.to_bytes());
    transport.extend(vesta.to_bytes());
    let (proof, p, v) = decode_transport(&transport, 32).unwrap();
    assert_eq!(proof, &[7; 32]);
    assert_eq!(p, pallas);
    assert_eq!(v, vesta);
    transport.push(0);
    assert!(decode_transport(&transport, 32).is_err());
}

// These are DATA-only context controls over the maintained canonical wire fixture. Its
// sigma/Omega bytes are labelled stand-ins and are never admitted into an ArtifactSet.
fn capsule_data_fixture<T>(name: &str) -> T
where
    T: norito::NoritoSerialize,
    for<'de> T: norito::NoritoDeserialize<'de>,
{
    let vectors: norito::json::Value = norito::json::from_str(include_str!(
        "../../../../fixtures/kagemusha/wallet_v1_vectors.json"
    ))
    .expect("maintained wallet vectors");
    let row = vectors["objects"]
        .as_array()
        .expect("objects")
        .iter()
        .find(|row| row["type"].as_str() == Some(name))
        .expect("canonical object");
    let bytes = hex::decode(row["canonical_hex"].as_str().expect("hex")).expect("hex");
    norito::decode_canonical_with_limits(&bytes, norito::canonical_decode_limits(bytes.len()))
        .expect("exact canonical fixture")
}

fn receive_capsule_data() -> (
    KagemushaWalletSchemeV1,
    KagemushaWalletRecoveryBodyV1,
    KagemushaWalletCredentialV1,
) {
    let scheme = capsule_data_fixture("KagemushaWalletSchemeV1");
    let capsule = capsule_data_fixture::<KagemushaWalletRecoveryCapsuleV1>(
        "KagemushaWalletRecoveryCapsuleV1",
    )
    .body()
    .clone();
    let request = retained_request(&capsule).expect("exact retained Request");
    (scheme, capsule, request.receiver_credential)
}

fn request_original(capsule: &mut KagemushaWalletRecoveryBodyV1) -> &mut Vec<u8> {
    &mut capsule
        .retained_inputs
        .iter_mut()
        .find(|input| input.role == KagemushaWalletRetainedInputRoleV1::Request)
        .expect("retained Request")
        .bytes
}

// Recompute the capsule's actual own public bindings after a DATA context mutation. This
// makes the negative controls reach the new context join rather than only shape rejection.
fn rebind_capsule_data(capsule: &mut KagemushaWalletRecoveryBodyV1) {
    capsule.operation_id = capsule
        .statement
        .operation_id(&capsule.wallet_id)
        .expect("operation identity");
    capsule.output = KagemushaWalletOutputDescriptorV1::for_transition(
        &capsule.statement,
        &capsule.proof_digest().expect("proof digest"),
        &capsule.payment_digest,
    )
    .expect("receipt-free output descriptor");
    capsule.validate().expect("structurally valid capsule");
}

#[test]
fn receipt_free_context_uses_retained_request_without_mutating_originals() {
    let (scheme, capsule, credential) = receive_capsule_data();
    let original = capsule.clone();
    retained_request(&capsule).expect("held Request");
    // Receive has one key: its selector reads no list recorded by the Request.
    assert_eq!(
        capsule_selector(&scheme, &capsule, &credential),
        Ok((KagemushaWalletOperationKindV1::Receive, 0))
    );
    assert_eq!(
        capsule, original,
        "all retained canonical bytes remain exact"
    );
}

#[test]
fn receive_package_selects_its_one_key_from_the_package_alone() {
    // Package verification takes no Request: Receive's key is mask 0 whatever controls the
    // receiver's predecessor carries in the statement.
    let mut package: KagemushaWalletPackageV1 = capsule_data_fixture("KagemushaWalletPackageV1");
    assert_eq!(
        package.statement.effect.kind(),
        KagemushaWalletOperationKindV1::Receive
    );
    for controls in 0..=KAGEMUSHA_WALLET_CONTROLS_DEFINED_MASK_V1 {
        package.statement.enabled_controls = controls;
        assert_eq!(
            package.verifying_key_selector(),
            (KagemushaWalletOperationKindV1::Receive, 0)
        );
    }
}

#[test]
fn receipt_free_context_rejects_missing_or_duplicate_held_request() {
    let (scheme, capsule, credential) = receive_capsule_data();
    let mut missing = capsule.clone();
    missing
        .retained_inputs
        .retain(|input| input.role != KagemushaWalletRetainedInputRoleV1::Request);
    assert_eq!(
        capsule_selector(&scheme, &missing, &credential),
        Err(Error::Authority)
    );
    let mut duplicate = capsule;
    let request = duplicate
        .retained_inputs
        .iter()
        .find(|input| input.role == KagemushaWalletRetainedInputRoleV1::Request)
        .expect("Request")
        .clone();
    duplicate.retained_inputs.push(request);
    duplicate
        .validate()
        .expect("G1 permits repeated roles structurally");
    assert_eq!(
        capsule_selector(&scheme, &duplicate, &credential),
        Err(Error::Authority),
        "even identical duplicate Request originals are ambiguous"
    );
}

#[test]
fn receipt_free_context_rejects_noncanonical_or_oversized_request_before_decode() {
    let (scheme, capsule, credential) = receive_capsule_data();
    for bytes in [
        Vec::new(),
        vec![0; KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1 + 1],
        {
            let mut bytes = request_original(&mut capsule.clone()).clone();
            bytes.push(0);
            bytes
        },
    ] {
        let mut changed = capsule.clone();
        *request_original(&mut changed) = bytes;
        assert_eq!(
            capsule_selector(&scheme, &changed, &credential),
            Err(Error::Authority)
        );
    }
}

#[test]
fn receipt_free_receive_context_binds_credit_payer_and_amount_to_request() {
    let (scheme, capsule, credential) = receive_capsule_data();
    for field in 0..3 {
        let mut changed = capsule.clone();
        let KagemushaWalletEffectV1::Receive {
            credit_id,
            payer_wallet_id,
            amount,
        } = &mut changed.statement.effect
        else {
            panic!("Receive fixture")
        };
        match field {
            0 => *credit_id = Fp::from(99).to_repr(),
            1 => *payer_wallet_id = [99; 32],
            _ => *amount = amount.checked_add(1).expect("amount"),
        }
        rebind_capsule_data(&mut changed);
        assert_eq!(
            capsule_selector(&scheme, &changed, &credential),
            Err(Error::Authority),
            "mismatching Receive context field{field}"
        );
    }
}

#[test]
fn receipt_free_context_rejects_another_installed_scheme_or_current_credential() {
    let (scheme, capsule, credential) = receive_capsule_data();
    let mut other_scheme = scheme;
    other_scheme.network_id = *Hash::new(b"another-capsule-installation").as_ref();
    assert_eq!(
        capsule_selector(&other_scheme, &capsule, &credential),
        Err(Error::Authority)
    );
    // The retained incoming credential is the payer, while this capsule belongs to the
    // held Request's receiver. Both are actual fixture originals, not dummy owners.
    let original = capsule
        .retained_inputs
        .iter()
        .find(|input| input.role == KagemushaWalletRetainedInputRoleV1::Credential)
        .expect("retained payer credential");
    let payer: KagemushaWalletCredentialV1 = norito::decode_canonical_with_limits(
        &original.bytes,
        norito::canonical_decode_limits(original.bytes.len()),
    )
    .expect("exact retained payer credential");
    assert_ne!(payer.body.wallet_id, credential.body.wallet_id);
    assert_eq!(
        capsule_selector(&scheme, &capsule, &payer),
        Err(Error::Authority)
    );
}

#[test]
fn receipt_free_context_preserves_soft_incoming_original_for_receive_relation() {
    let (scheme, mut capsule, credential) = receive_capsule_data();
    let expected = capsule_selector(&scheme, &capsule, &credential).expect("Request context");
    let incoming = capsule
        .retained_inputs
        .iter_mut()
        .find(|input| input.role == KagemushaWalletRetainedInputRoleV1::Payment)
        .expect("incoming Payment original");
    incoming.bytes = vec![0xff];
    let original = capsule.clone();
    capsule
        .validate()
        .expect("G1 retains bytes without deciding soft validity");
    assert_eq!(
        capsule_selector(&scheme, &capsule, &credential),
        Ok(expected)
    );
    assert_eq!(capsule, original);
    // This is only a context precheck. No stand-in sigma is verified, no ArtifactSet or
    // NativeProofs owner is constructed, and no incoming validity/burn verdict is asserted.
}

// Reuse the maintained signed Request, payer credential, Send statement and labelled proof
// originals. Only the unsigned capsule/state DATA is rebound. This is not a successor
// produced by the Send relation, an authenticated ArtifactSet, or proof acceptance evidence.
fn send_capsule_data() -> (
    KagemushaWalletSchemeV1,
    KagemushaWalletRecoveryBodyV1,
    KagemushaWalletCredentialV1,
) {
    let (scheme, mut capsule, _) = receive_capsule_data();
    let request = retained_request(&capsule).expect("original signed Request");
    request.verify(&scheme).expect("actual Request authority");
    let original = capsule
        .retained_inputs
        .iter()
        .find(|input| input.role == KagemushaWalletRetainedInputRoleV1::Credential)
        .expect("retained payer credential");
    let payer: KagemushaWalletCredentialV1 = norito::decode_canonical_with_limits(
        &original.bytes,
        norito::canonical_decode_limits(original.bytes.len()),
    )
    .expect("exact canonical payer credential");
    payer.validate().expect("maintained payer credential");
    let payment: KagemushaWalletPaymentV1 = capsule_data_fixture("KagemushaWalletPaymentV1");
    assert_eq!(payment.signed_request().unwrap(), request.signed());
    assert_eq!(
        payment.send.lineage.lineage().unwrap().public.payment_key,
        payer.body.payment_key
    );
    assert_eq!(
        payment
            .send
            .lineage
            .lineage()
            .unwrap()
            .public
            .credential_digest,
        payer.credential_digest()
    );
    assert_eq!(request.body.payer_wallet_id, payer.body.wallet_id);
    assert_eq!(request.body.payer_account_digest, payer.body.account_digest);
    assert_eq!(request.body.asset_digest, payer.body.asset_digest);

    capsule.wallet_id = payer.body.wallet_id;
    capsule.kind = KagemushaWalletOperationKindV1::Send;
    capsule.statement = payment.send.statement;
    capsule.predecessor_lineage = payment.send.lineage;
    capsule.step_proof = payment.send.step_proof;
    capsule.payment_digest = [0; 32];
    capsule.map_openings.clear();
    capsule
        .retained_inputs
        .retain(|input| input.role == KagemushaWalletRetainedInputRoleV1::Request);

    let state = &mut capsule.successor_state;
    state.core.scheme_id = payer.body.scheme_id;
    state.core.wallet_id = payer.body.wallet_id;
    state.core.asset_digest = payer.body.asset_digest;
    state.core.credential_digest = payer.credential_digest();
    state.core.lifecycle = capsule.statement.lifecycle;
    state.core.sequence = capsule.statement.sequence;
    state.core.next_load = capsule.statement.next_load;
    state.core.burned_total = capsule.statement.lineage_burned_total;
    state.core.enabled_controls = capsule.statement.enabled_controls;
    state.core.policy_epoch = capsule
        .predecessor_lineage
        .lineage()
        .expect("actual Send predecessor lineage")
        .public
        .policy_epoch;
    state.rest.scheme_policy = request.body.scheme_policy;
    state.rest.fee_schedule = request.body.fee_schedule;
    state.rest.permitted_controls = payer.body.regulatory_policy.permitted_controls;
    state.core.time_anchor_max_response_ms =
        payer.body.regulatory_policy.time_anchor_max_response_ms;
    state.core.lease_expires_at_ms = payer.body.lease_expires_at_ms;
    state
        .validate_for_credential(&payer)
        .expect("payer-bound unsigned state DATA");
    capsule.statement.successor = state.commitment().expect("DATA successor binding");
    rebind_capsule_data(&mut capsule);
    (scheme, capsule, payer)
}

#[test]
fn receipt_free_send_context_uses_original_request_payer_and_control_selector() {
    let (scheme, capsule, payer) = send_capsule_data();
    let original = capsule.clone();
    let (_, receive, _) = receive_capsule_data();
    let request = retained_request(&capsule).expect("retained Request");
    request.verify(&scheme).expect("unchanged signed Request");
    let mut held = capsule.clone();
    let mut source = receive;
    assert_eq!(request_original(&mut held), request_original(&mut source));
    let payment: KagemushaWalletPaymentV1 = capsule_data_fixture("KagemushaWalletPaymentV1");
    assert_eq!(capsule.predecessor_lineage, payment.send.lineage);
    assert_eq!(capsule.step_proof, payment.send.step_proof);
    assert_eq!(
        capsule_selector(&scheme, &capsule, &payer),
        Ok((
            KagemushaWalletOperationKindV1::Send,
            payment.send.statement.enabled_controls,
        ))
    );
    assert_eq!(capsule, original, "context checks retain exact originals");
    // Only the context precheck runs; the fixture sigma/Omega stand-ins are not verified.
}

#[test]
fn receipt_free_send_context_binds_every_request_effect_field() {
    let (scheme, capsule, payer) = send_capsule_data();
    let request = retained_request(&capsule).expect("original Request");
    for field in 0..7 {
        let mut changed = capsule.clone();
        let KagemushaWalletEffectV1::Send {
            credit_id,
            receiver_wallet_id,
            send_ordinal,
            amount,
            fee,
            request: request_digest,
            accepted_lower_ms,
            ..
        } = &mut changed.statement.effect
        else {
            panic!("Send DATA fixture")
        };
        match field {
            0 => *credit_id = Fp::from(99).to_repr(),
            1 => *receiver_wallet_id = [99; 32],
            2 => *send_ordinal = send_ordinal.checked_add(1).expect("send ordinal"),
            3 => *amount = amount.checked_add(1).expect("amount"),
            4 => *fee = fee.checked_add(1).expect("fee"),
            5 => *request_digest = Fp::from(99).to_repr(),
            _ => {
                *accepted_lower_ms = request
                    .body
                    .receiver_accepted_time_ms
                    .checked_sub(1)
                    .expect("maintained nonzero accepted time")
            }
        }
        rebind_capsule_data(&mut changed);
        let mut retained = changed.clone();
        let mut original = capsule.clone();
        assert_eq!(
            request_original(&mut retained),
            request_original(&mut original)
        );
        assert_eq!(
            retained_request(&changed),
            Ok(request.clone()),
            "effect mutation preserves the genuine signed Request"
        );
        assert_eq!(
            capsule_selector(&scheme, &changed, &payer),
            Err(Error::Authority),
            "mismatching Send context field {field} must fail beyond valid capsule shape"
        );
    }
}

#[test]
fn receipt_free_send_context_refuses_missing_or_ambiguous_request_originals() {
    let (scheme, capsule, payer) = send_capsule_data();
    let mut missing = capsule.clone();
    missing.retained_inputs.clear();
    assert_eq!(
        capsule_selector(&scheme, &missing, &payer),
        Err(Error::Authority)
    );
    let mut duplicate = capsule;
    let request = duplicate.retained_inputs[0].clone();
    duplicate.retained_inputs.push(request);
    duplicate
        .validate()
        .expect("repeated roles are structurally allowed");
    assert_eq!(
        capsule_selector(&scheme, &duplicate, &payer),
        Err(Error::Authority),
        "identical duplicate originals cannot select Send's Request context"
    );
}

#[test]
#[ignore = "genuine signed k12/k16 verifier inventory; run optimized"]
fn cancelled_verification_never_reports_acceptance_or_invalidity() {
    use crate::kagemusha_wallet_artifacts_v1::{InstalledVerifierPackV1, engineering_fixture};
    let (pack, installation) = engineering_fixture::signed_inventory();
    let installed =
        InstalledVerifierPackV1::load(&pack.to_canonical_bytes().unwrap(), installation).unwrap();
    let verifier = installed.verifier();
    // Parameter ownership is installation-scoped, not a runtime generator cache.
    for key in verifier.steps.values() {
        let parameters = verifier.vesta_parameters(key.params.params().k()).unwrap();
        assert!(Arc::ptr_eq(parameters, &key.params));
    }
    assert!(Arc::ptr_eq(
        verifier.vesta_parameters(16).unwrap(),
        &verifier.vesta
    ));
    assert!(Arc::ptr_eq(
        verifier.pallas_parameters(),
        &verifier.lineage.params
    ));
    assert!(matches!(verifier.vesta_parameters(1), Err(Error::Profile)));
    // These are unadmitted DATA originals from another scheme. This test proves only
    // cancellation precedence; none of their placeholder proof bytes is accepted.
    let (_, capsule, credential) = receive_capsule_data();
    let frozen: KagemushaWalletRecoveryCapsuleV1 =
        capsule_data_fixture("KagemushaWalletRecoveryCapsuleV1");
    assert_eq!(frozen.body(), &capsule);
    let payment: KagemushaWalletPaymentV1 = capsule_data_fixture("KagemushaWalletPaymentV1");
    let lineage = payment.send.lineage.lineage().unwrap();
    let token = iroha_pasta::CancellationToken::new();
    token.cancel();
    let budget = MemoryBudget::DEFAULT;
    let work = KagemushaWalletVerificationCountsV1::current_thread();
    assert_eq!(
        verifier.verify_package_proofs_cancellable(&payment.send, budget, Some(&token)),
        Err(Error::Cancelled)
    );
    assert_eq!(
        verifier.verify_capsule_proofs_cancellable(&frozen, &credential, budget, Some(&token)),
        Err(Error::Cancelled)
    );
    assert_eq!(
        verifier.verify_body_proofs_cancellable(&capsule, &credential, budget, Some(&token)),
        Err(Error::Cancelled)
    );
    assert_eq!(
        verifier.verify_step_proof_cancellable(
            &capsule.statement,
            &capsule.step_proof,
            KagemushaWalletOperationKindV1::Receive,
            0,
            budget,
            Some(&token)
        ),
        Err(Error::Cancelled)
    );
    assert_eq!(
        verifier.verify_lineage_cancellable(lineage, budget, Some(&token)),
        Err(Error::Cancelled)
    );
    // A fresh operation has no inherited signal and performs actual authority checks.
    assert_eq!(
        verifier.verify_package_proofs(&payment.send, budget),
        Err(Error::Authority)
    );
    // Only the direct lineage call started; refusals before it ran no proof work.
    assert_eq!(
        KagemushaWalletVerificationCountsV1::current_thread().since(work),
        KagemushaWalletVerificationCountsV1 {
            verify_lineage: 1,
            proofs: iroha_plonk::VerificationCounts::default(),
        }
    );
}

#[test]
fn retained_request_read_preserves_original_refusal_and_exact_retry() {
    let (scheme, mut capsule, payer) = send_capsule_data();
    let before = capsule.clone();
    let expected = retained_request(&capsule).unwrap();
    let limits = norito::DecodeLimits::new(usize::MAX, 0, usize::MAX, usize::MAX, 64);
    for error in [
        norito::with_decode_limits_scope(limits, || retained_request(&capsule)).unwrap_err(),
        norito::with_decode_limits_scope(limits, || capsule_selector(&scheme, &capsule, &payer))
            .unwrap_err(),
    ] {
        assert!(matches!(error, Error::DecodeResource(ref cause)
            if cause.kind() == norito::core::DecodeLocalRefusalKind::EnclosingLimit));
    }
    assert_eq!(capsule, before);
    assert_eq!(retained_request(&capsule).unwrap(), expected);
    assert!(capsule_selector(&scheme, &capsule, &payer).is_ok());
    *request_original(&mut capsule) = vec![0];
    assert_eq!(retained_request(&capsule), Err(Error::Authority));
}

#[test]
fn generator_identity_transport_is_canonical_data_and_uses_zero_coordinates() {
    use ff::Field;
    use iroha_plonk::transcript::decode_generator;
    let p =
        AccumulatorT::<Ep>::new(decode_generator::<Ep>(&[0; 32]).unwrap(), [Fq::ONE; K]).unwrap();
    let v =
        AccumulatorT::<Eq>::new(decode_generator::<Eq>(&[0; 32]).unwrap(), [Fp::ONE; K]).unwrap();
    assert_eq!(generator_coordinates::<Ep>(p.g()), (Fp::ZERO, Fp::ZERO));
    assert_eq!(generator_coordinates::<Eq>(v.g()), (Fq::ZERO, Fq::ZERO));
    let mut transport = vec![7; 32];
    transport.extend(p.to_bytes());
    transport.extend(v.to_bytes());
    let (opening, decoded_p, decoded_v) = decode_transport(&transport, 32).unwrap();
    assert_eq!(opening, &[7; 32]);
    assert_eq!(decoded_p, p);
    assert_eq!(decoded_v, v);
    // Transport syntax and the digest confer no deciding or proof authority.
    let public = lineage_public();
    let key = Fp::from(11).to_repr();
    let mut words = lineage_public_fields(&public, key)
        .unwrap()
        .map(|v| v.to_repr())
        .to_vec();
    words.extend([Fp::ZERO.to_repr(); 2]);
    for _ in 0..K {
        words.extend([Fp::ONE.to_repr(), Fp::ZERO.to_repr()]);
    }
    assert_eq!(
        lineage_digest(&public, key, &p).unwrap(),
        kagemusha_wallet_poseidon_v1(u64::from_le_bytes(*b"kgwomg_1"), &words).unwrap()
    );
    transport[32..64].fill(255);
    assert!(decode_transport(&transport, 32).is_err());
}

#[test]
fn model_admission_and_recursive_input_tapes_share_role_capacities() {
    use iroha_kagemusha_proof::a_relation::receive::{
        MAX_OMEGA_RAW_BYTES, MAX_SEND_PROOF_BYTES, MAX_SIGMA_RAW_BYTES, OMEGA_TRANSPORT_CAP,
        PAYMENT_PROOF_BUDGET, PAYMENT_RAW_PROOF_BUDGET,
    };
    assert_eq!(
        PAYMENT_PROOF_BUDGET,
        KAGEMUSHA_WALLET_PAYMENT_PROOF_BUDGET_V1
    );
    assert_eq!(MAX_SEND_PROOF_BYTES, KAGEMUSHA_WALLET_SIGMA_PROOF_CAP_V1);
    assert_eq!(MAX_SIGMA_RAW_BYTES, KAGEMUSHA_WALLET_SIGMA_PROOF_CAP_V1);
    assert_eq!(OMEGA_TRANSPORT_CAP, KAGEMUSHA_WALLET_OMEGA_PROOF_CAP_V1);
    // The internal Omega tape adds the public prefix; it does not gain proof capacity.
    assert_eq!(MAX_OMEGA_RAW_BYTES - OMEGA_TRANSPORT_CAP, 320);
    assert_eq!(PAYMENT_RAW_PROOF_BUDGET - PAYMENT_PROOF_BUDGET, 320);
    assert_eq!(
        MAX_OMEGA_RAW_BYTES + MAX_SIGMA_RAW_BYTES,
        PAYMENT_RAW_PROOF_BUDGET
    );
    assert!(OMEGA_TRANSPORT_CAP <= KAGEMUSHA_WALLET_LINEAGE_PROOF_CAP_V1);
}

/// A genuine k16 Pallas PIPA-R key in the installed Omega profile whose only relation copies
/// its three public columns into advice (a selector-gated equality, so blinding rows stay
/// free), and every canonical instance has a real proof. The
/// wallet's Omega relation cannot be proved under an installed scheme here (its public outputs
/// bind that scheme), so this relation stands in for it: the installed verifier's complete
/// lineage boundary then runs on real proof bytes, namely the exact transport split, D_A over
/// the public fields and acc_P, the instances that bind acc_V, full verification and both
/// decides on the shared owners. It is never a wallet relation or a catalog member.
#[derive(Clone)]
struct TransportRelation {
    instances: Option<Vec<Vec<Fq>>>,
}

impl iroha_plonk::Circuit<Fq> for TransportRelation {
    type Config = (
        iroha_plonk::cs::Selector,
        iroha_plonk::cs::Column<iroha_plonk::cs::Advice>,
        iroha_plonk::cs::Column<iroha_plonk::cs::Advice>,
        Vec<iroha_plonk::cs::Column<iroha_plonk::cs::Instance>>,
    );
    type FloorPlanner = iroha_plonk::SimpleFloorPlanner;
    type Params = ();

    fn without_witnesses(&self) -> Self {
        Self { instances: None }
    }

    fn configure(meta: &mut iroha_plonk::cs::ConstraintSystem<Fq>) -> Self::Config {
        let enabled = meta.selector();
        let copied = meta.advice_column();
        let mirror = meta.advice_column();
        meta.enable_equality(copied);
        let columns = [1, 2, K]
            .into_iter()
            .map(|length| {
                let column = meta.instance_column(length);
                meta.enable_equality(column);
                column
            })
            .collect();
        meta.create_gate("copied public value", |cells| {
            let enabled = cells.query_selector(enabled);
            vec![
                enabled
                    * (cells.query_advice(copied, iroha_plonk::cs::Rotation::cur())
                        - cells.query_advice(mirror, iroha_plonk::cs::Rotation::cur())),
            ]
        });
        (enabled, copied, mirror, columns)
    }

    fn synthesize(
        &self,
        (enabled, copied, mirror, columns): Self::Config,
        mut layouter: impl iroha_plonk::Layouter<Fq>,
    ) -> Result<(), iroha_plonk::Error> {
        let lengths = [1, 2, K];
        let cells = layouter.assign_region(
            || "public copies",
            |mut region| {
                let mut cells = Vec::new();
                for (column, length) in lengths.iter().enumerate() {
                    for index in 0..*length {
                        let value = self
                            .instances
                            .as_ref()
                            .map_or_else(iroha_plonk::Value::unknown, |all| {
                                iroha_plonk::Value::known(all[column][index])
                            });
                        let row = cells.len();
                        region.enable_selector(|| "copied public value", &enabled, row)?;
                        region.assign_advice(mirror, row, value)?;
                        cells.push(region.assign_advice(copied, row, value)?.cell());
                    }
                }
                Ok(cells)
            },
        )?;
        let mut cells = cells.into_iter();
        for (column, length) in columns.iter().zip(lengths) {
            for row in 0..length {
                let cell = cells.next().ok_or(iroha_plonk::Error::Synthesis)?;
                layouter.constrain_instance(cell, *column, row)?;
            }
        }
        Ok(())
    }
}

/// An honest accumulator `(<s(u), g>, u)` of 16 explicit challenges on `params`.
fn honest_claim<C: PastaCurve>(params: &PinnedParams<C>, first: u64) -> AccumulatorT<C> {
    let challenges = core::array::from_fn(|index| C::ScalarExt::from(first + index as u64));
    let g = params
        .folded_generator_cancellable(&challenges, MemoryBudget::DEFAULT, None)
        .unwrap();
    AccumulatorT::new(g, challenges).unwrap()
}

/// Verify-once evidence at the installed verifier boundary (M1). Warm the installed verifier's
/// shared Pallas and Vesta owners with a real transport, then present every mutation of that
/// transport and of each public field: each verdict equals the verdict of freshly derived
/// owners, no mutation is answered from the memo, nothing negative is retained, and the exact
/// transport is still accepted (from the memo) after every refusal and after cancellation.
#[test]
#[ignore = "genuine k16 Pallas transport proof and repeated installed-verifier derivation; run optimized"]
fn installed_lineage_memo_matches_fresh_owners_for_every_transport_mutation() {
    use crate::kagemusha_wallet_artifacts_v1::{
        ArtifactOriginalV1, InstalledVerifierPackV1, engineering_fixture,
    };
    use iroha_plonk::{
        ProverConfig, ProverRandomness,
        keys::{CosetCachePolicy, KeygenConfigV2, keygen_pk_v2},
        prover::{Witness, create_proof_owned},
        transcript::encode_point,
    };

    let budget = MemoryBudget::DEFAULT;
    let pallas = PinnedParams::<Ep>::derive(16).unwrap();
    let vesta = PinnedParams::<Eq>::derive(16).unwrap();
    let mut config = KeygenConfigV2::pipa_r(vec![
        InstanceType::Bounded,
        InstanceType::Field,
        InstanceType::Bounded,
    ]);
    config.coset_cache = CosetCachePolicy::OnDemand;
    let proving_key =
        keygen_pk_v2(&pallas, &TransportRelation { instances: None }, &config).unwrap();
    let (pack, installation) =
        engineering_fixture::signed_inventory_with_lineage(ArtifactOriginalV1 {
            descriptor: proving_key.binding().encoded().to_vec(),
            verifying_key: proving_key.vk().to_bytes().to_vec(),
        });
    let original = pack.to_canonical_bytes().unwrap();
    let fresh = || InstalledVerifierPackV1::load(&original, installation).unwrap();
    let warm = fresh();
    let verifier = warm.verifier();
    let proof_bytes = verifier.lineage.proof_bytes;

    // The exact transport: public outputs under the installed scheme, honest acc_P and acc_V,
    // and a real proof of the instances verify_lineage derives from them.
    let mut outputs = lineage_public();
    outputs.scheme_id = verifier.scheme.scheme_id();
    outputs.relation_id = verifier.scheme.relation_id;
    let acc_p = honest_claim(&pallas, 21);
    let acc_v = honest_claim(&vesta, 41);
    let digest = lineage_digest(
        &outputs,
        verifier.allowlist.lineage_verifying_key_digest,
        &acc_p,
    )
    .unwrap();
    let (x, y) = generator_coordinates::<Eq>(acc_v.g());
    let instances = vec![
        vec![Fq::from_repr(digest).unwrap()],
        vec![x, y],
        acc_v
            .challenges()
            .iter()
            .map(|challenge| Fq::from_repr(challenge.to_repr()).unwrap())
            .collect(),
    ];
    let relation = TransportRelation {
        instances: Some(instances.clone()),
    };
    let proof = create_proof_owned(
        &pallas,
        &proving_key,
        Witness::from_circuit(&proving_key, &relation, &instances).unwrap(),
        ProverRandomness::hedged(),
        ProverConfig::default(),
    )
    .unwrap();
    assert_eq!(
        verify_full_cancellable(
            &pallas,
            proving_key.binding(),
            proving_key.vk(),
            &instances,
            &proof,
            budget,
            None,
        ),
        Ok(()),
        "the stand-in proof verifies under its own key"
    );
    drop(proving_key);
    assert_eq!(proof.len(), proof_bytes);
    let mut transport = proof;
    transport.extend_from_slice(&acc_p.to_bytes());
    transport.extend_from_slice(&acc_v.to_bytes());
    let exact = KagemushaWalletLineageV1 {
        public: outputs,
        proof: transport.clone(),
    };

    let counted = |verifier: &ArtifactSet,
                   lineage: &KagemushaWalletLineageV1,
                   token: Option<&iroha_pasta::CancellationToken>| {
        let start = KagemushaWalletVerificationCountsV1::current_thread();
        let verdict = verifier.verify_lineage_cancellable(lineage, budget, token);
        (
            verdict,
            KagemushaWalletVerificationCountsV1::current_thread().since(start),
        )
    };
    // Cold: the exact transport computes Omega's generator and both decides.
    let (verdict, cold) = counted(verifier, &exact, None);
    assert_eq!(verdict, Ok(()));
    assert_eq!(
        (
            cold.verify_lineage,
            cold.proofs.verify_full,
            cold.proofs.reused_verifications,
            cold.proofs.decides,
            cold.proofs.generator_msms,
        ),
        (1, 1, 0, 2, 3)
    );
    // Warm: the same bytes are answered from the shared owners' memos.
    let warm_reuse = |verifier: &ArtifactSet, label: &str| {
        let (verdict, reuse) = counted(verifier, &exact, None);
        assert_eq!(verdict, Ok(()), "exact transport after {label}");
        assert_eq!(
            (
                reuse.proofs.verify_full,
                reuse.proofs.reused_verifications,
                reuse.proofs.decides,
                reuse.proofs.reused_generators,
                reuse.proofs.generator_msms,
            ),
            (1, 1, 2, 2, 0),
            "exact transport after {label}"
        );
    };
    warm_reuse(verifier, "warming");
    // A cancelled call on the warm owners has no verdict.
    let token = iroha_pasta::CancellationToken::new();
    token.cancel();
    assert_eq!(
        counted(verifier, &exact, Some(&token)).0,
        Err(Error::Cancelled)
    );
    warm_reuse(verifier, "cancellation");

    // Every mutation: canonical foreign P and V, decidable but unbound P and V, a changed P
    // challenge, proof bit flips at the start, middle and end, length +-1, each public field.
    let p_at = proof_bytes;
    let v_at = proof_bytes + ACCUMULATOR_BYTES;
    let mut mutations: Vec<(String, KagemushaWalletLineageV1)> = Vec::new();
    let mut transport_case = |label: &str, changed: Vec<u8>| {
        mutations.push((
            label.to_owned(),
            KagemushaWalletLineageV1 {
                public: outputs,
                proof: changed,
            },
        ));
    };
    for (label, at, point) in [
        (
            "foreign canonical P",
            p_at,
            encode_point::<Ep>(&(-*acc_p.g())),
        ),
        (
            "foreign canonical V",
            v_at,
            encode_point::<Eq>(&(-*acc_v.g())),
        ),
    ] {
        let mut changed = transport.clone();
        assert_ne!(&changed[at..at + 32], point.as_slice());
        changed[at..at + 32].copy_from_slice(&point);
        transport_case(label, changed);
    }
    let other_p = honest_claim(&pallas, 61);
    let other_v = honest_claim(&vesta, 81);
    assert_eq!(other_p.decide(&pallas, budget), Ok(()));
    assert_eq!(other_v.decide(&vesta, budget), Ok(()));
    for (label, at, bytes) in [
        ("decidable unbound P", p_at, other_p.to_bytes()),
        ("decidable unbound V", v_at, other_v.to_bytes()),
    ] {
        let mut changed = transport.clone();
        changed[at..at + ACCUMULATOR_BYTES].copy_from_slice(&bytes);
        transport_case(label, changed);
    }
    let mut changed = transport.clone();
    changed[p_at + 32..p_at + 64].copy_from_slice(&Fq::from(2).to_repr());
    transport_case("changed P challenge", changed);
    for (label, index) in [
        ("proof bit at start", 0),
        ("proof bit in middle", proof_bytes / 2),
        ("proof bit at end", proof_bytes - 1),
    ] {
        let mut changed = transport.clone();
        changed[index] ^= 1;
        transport_case(label, changed);
    }
    let mut longer = transport.clone();
    longer.push(0);
    transport_case("length + 1", longer);
    transport_case("length - 1", transport[..transport.len() - 1].to_vec());
    for field in 0..13 {
        let mut changed = outputs;
        let label = match field {
            0 => {
                changed.version = 2;
                "public version"
            }
            1 => {
                changed.scheme_id[0] ^= 1;
                "public scheme"
            }
            2 => {
                changed.relation_id[0] ^= 1;
                "public relation"
            }
            3 => {
                changed.head.value = Fp::from(12).to_repr();
                "public head"
            }
            4 => {
                changed.wallet_id[0] ^= 1;
                "public wallet"
            }
            5 => {
                changed.credential_digest = Fp::from(13).to_repr();
                "public credential"
            }
            6 => {
                changed.payment_key = public(&key(14));
                "public payment key"
            }
            7 => {
                changed.lifecycle = KagemushaWalletLifecycleV1::Retiring;
                "public lifecycle"
            }
            8 => {
                changed.policy_epoch += 1;
                "public policy epoch"
            }
            9 => {
                changed.enabled_controls = 1;
                "public controls"
            }
            10 => {
                changed.burned_total += 1;
                "public burned total"
            }
            11 => {
                changed.pending_outgoing_root = Fp::from(15).to_repr();
                "public pending root"
            }
            _ => {
                changed.credit_digest_root = Fp::from(16).to_repr();
                "public credit root"
            }
        };
        mutations.push((
            label.to_owned(),
            KagemushaWalletLineageV1 {
                public: changed,
                proof: transport.clone(),
            },
        ));
    }
    assert_eq!(mutations.len(), 23);

    let mut verdicts = Vec::with_capacity(mutations.len());
    for (label, lineage) in &mutations {
        let (on_warm, work) = counted(verifier, lineage, None);
        let independent = fresh();
        let on_fresh = independent
            .verifier()
            .verify_lineage_cancellable(lineage, budget, None);
        assert!(on_warm.is_err(), "{label} must be refused");
        assert_eq!(on_warm, on_fresh, "{label}: warm and fresh owners disagree");
        assert_eq!(
            work.proofs.reused_verifications, 0,
            "{label} was answered from the memo"
        );
        warm_reuse(verifier, label);
        verdicts.push(format!("{label}={on_warm:?}"));
    }
    // A fresh owner accepts the exact transport from nothing; the warm owner still reuses it.
    let (verdict, again) = counted(fresh().verifier(), &exact, None);
    assert_eq!(verdict, Ok(()));
    assert_eq!(again.proofs.reused_verifications, 0);
    warm_reuse(verifier, "every mutation");
    eprintln!(
        "INSTALLED_LINEAGE_MEMO_PARITY mutations={} warm_equals_fresh=true exact_reused_after_each=true \
         omega_relation=transport_stand_in verdicts=[{}]",
        mutations.len(),
        verdicts.join(", ")
    );
}

/// A valid outer proof must not hide a failed transported Pallas or Vesta obligation.
/// These are genuine proofs of `TransportRelation`, which permits every canonical public
/// tuple; they are not proofs of a wallet operation or members of its production catalog.
/// Unlike mutations of an existing proof's instances, each poisoned claim is bound by a
/// newly proved statement whose complete outer verification succeeds before native refusal.
#[test]
#[ignore = "three genuine k16 transport stand-in proofs and fresh installed owners; run optimized"]
fn installed_lineage_rejects_bound_nondeciding_claims() {
    use crate::kagemusha_wallet_artifacts_v1::{
        ArtifactOriginalV1, InstalledVerifierPackV1, engineering_fixture,
    };
    use iroha_plonk::{
        ProverConfig, ProverRandomness,
        keys::{CosetCachePolicy, KeygenConfigV2, keygen_pk_v2},
        prover::{Witness, create_proof_owned},
    };

    let budget = MemoryBudget::DEFAULT;
    let pallas = PinnedParams::<Ep>::derive(16).unwrap();
    let vesta = PinnedParams::<Eq>::derive(16).unwrap();
    let mut config = KeygenConfigV2::pipa_r(vec![
        InstanceType::Bounded,
        InstanceType::Field,
        InstanceType::Bounded,
    ]);
    config.coset_cache = CosetCachePolicy::OnDemand;
    let proving_key =
        keygen_pk_v2(&pallas, &TransportRelation { instances: None }, &config).unwrap();
    let (pack, installation) =
        engineering_fixture::signed_inventory_with_lineage(ArtifactOriginalV1 {
            descriptor: proving_key.binding().encoded().to_vec(),
            verifying_key: proving_key.vk().to_bytes().to_vec(),
        });
    let original = pack.to_canonical_bytes().unwrap();
    let fresh = || InstalledVerifierPackV1::load(&original, installation).unwrap();
    let warm = fresh();
    let verifier = warm.verifier();
    let mut outputs = lineage_public();
    outputs.scheme_id = verifier.scheme.scheme_id();
    outputs.relation_id = verifier.scheme.relation_id;

    let acc_p = honest_claim(&pallas, 21);
    let acc_v = honest_claim(&vesta, 41);
    assert_eq!(acc_p.decide(&pallas, budget), Ok(()));
    assert_eq!(acc_v.decide(&vesta, budget), Ok(()));
    let poisoned_p = AccumulatorT::<Ep>::new(-*acc_p.g(), *acc_p.challenges()).unwrap();
    let poisoned_v = AccumulatorT::<Eq>::new(-*acc_v.g(), *acc_v.challenges()).unwrap();
    assert_ne!(poisoned_p.g(), acc_p.g());
    assert_ne!(poisoned_v.g(), acc_v.g());
    assert_eq!(
        AccumulatorT::<Ep>::from_bytes(&poisoned_p.to_bytes()),
        Ok(poisoned_p.clone())
    );
    assert_eq!(
        AccumulatorT::<Eq>::from_bytes(&poisoned_v.to_bytes()),
        Ok(poisoned_v.clone())
    );
    assert_eq!(
        poisoned_p.decide(&pallas, budget),
        Err(iroha_plonk_recursion::Error::Undecidable)
    );
    assert_eq!(
        poisoned_v.decide(&vesta, budget),
        Err(iroha_plonk_recursion::Error::Undecidable)
    );

    let prove_transport = |p: &AccumulatorT<Ep>, v: &AccumulatorT<Eq>| {
        let digest =
            lineage_digest(&outputs, verifier.allowlist.lineage_verifying_key_digest, p).unwrap();
        let (x, y) = generator_coordinates::<Eq>(v.g());
        let instances = vec![
            vec![Fq::from_repr(digest).unwrap()],
            vec![x, y],
            v.challenges()
                .iter()
                .map(|challenge| Fq::from_repr(challenge.to_repr()).unwrap())
                .collect(),
        ];
        let relation = TransportRelation {
            instances: Some(instances.clone()),
        };
        let mut proof = create_proof_owned(
            &pallas,
            &proving_key,
            Witness::from_circuit(&proving_key, &relation, &instances).unwrap(),
            ProverRandomness::hedged(),
            ProverConfig::default(),
        )
        .unwrap();
        assert_eq!(proof.len(), verifier.lineage.proof_bytes);
        // Check the exact installed key and derived instances independently.
        // The separate parameter owner does not warm the installed owners.
        assert_eq!(
            verify_full_cancellable(
                &pallas,
                &verifier.lineage.binding,
                &verifier.lineage.vk,
                &instances,
                &proof,
                budget,
                None,
            ),
            Ok(()),
            "bound stand-in proof must pass full verification before accumulator decisions"
        );
        proof.extend_from_slice(&p.to_bytes());
        proof.extend_from_slice(&v.to_bytes());
        KagemushaWalletLineageV1 {
            public: outputs,
            proof,
        }
    };
    let exact = prove_transport(&acc_p, &acc_v);
    let cases = [
        ("Pallas", prove_transport(&poisoned_p, &acc_v), 1),
        ("Vesta", prove_transport(&acc_p, &poisoned_v), 2),
    ];
    assert_eq!(verifier.verify_lineage(&exact, budget), Ok(()));
    let counted = |owner: &ArtifactSet, lineage: &KagemushaWalletLineageV1| {
        let start = KagemushaWalletVerificationCountsV1::current_thread();
        let verdict = owner.verify_lineage(lineage, budget);
        (
            verdict,
            KagemushaWalletVerificationCountsV1::current_thread().since(start),
        )
    };
    for (claim, lineage, expected_decisions) in cases {
        let independent = fresh();
        for (state, owner) in [("warm", verifier), ("fresh", independent.verifier())] {
            for repeat in 0..2 {
                let (verdict, work) = counted(owner, &lineage);
                assert_eq!(
                    verdict,
                    Err(Error::Proof),
                    "{claim}: {state}, repeat {repeat}"
                );
                assert_eq!(work.verify_lineage, 1);
                assert_eq!(work.proofs.verify_full, 1);
                assert_eq!(work.proofs.decides, expected_decisions, "{claim}: {state}");
                // The full outer proof may be remembered after its acceptance,
                // although the lineage was refused. Its hit must still execute
                // and propagate the failed transported obligation every time.
                assert_eq!(work.proofs.reused_verifications, repeat);
                let (replay, replay_work) = counted(owner, &exact);
                assert_eq!(
                    replay,
                    Ok(()),
                    "healthy exact replay after {claim}: {state}"
                );
                assert_eq!(replay_work.proofs.verify_full, 1);
                assert_eq!(replay_work.proofs.decides, 2);
            }
        }
    }
    eprintln!(
        "INSTALLED_LINEAGE_BOUND_CLAIMS independent_outer_full_checks=3 poisoned_claims=2 \
         boundary_refusals=8 healthy_replays=8 warm_equals_fresh=true \
         omega_relation=transport_stand_in production_catalog=false"
    );
}
