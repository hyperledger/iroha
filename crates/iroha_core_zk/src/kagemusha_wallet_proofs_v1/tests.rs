//! Native authority, canonical transport and complete-claim mutation regressions.

use super::*;
use iroha_crypto::Hash;
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
    // The known answer was computed with an independent Python modular-integer
    // implementation of the 8/57 RP57 permutation and pinned Fp constant table.
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
        enabled_controls: 7,
        burned_total: 0x1122_3344_5566_7788_99aa_bbcc_ddee_ff00,
        pending_outgoing_root: Fp::from(9).to_repr(),
        credit_digest_root: Fp::from(10).to_repr(),
    };
    assert_eq!(
        hex::encode(lineage_digest(&public, Fp::from(11).to_repr(), &claim).unwrap()),
        "9570139378353ed3bfd6a661281cbc42989a3f5493be973914a21c94a04fc407",
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
    KagemushaWalletRecoveryCapsuleV1,
    KagemushaWalletCredentialV1,
) {
    let scheme = capsule_data_fixture("KagemushaWalletSchemeV1");
    let capsule = capsule_data_fixture("KagemushaWalletRecoveryCapsuleV1");
    let request = retained_request(&capsule).expect("exact retained Request");
    (scheme, capsule, request.receiver_credential)
}

fn request_original(capsule: &mut KagemushaWalletRecoveryCapsuleV1) -> &mut Vec<u8> {
    &mut capsule
        .retained_inputs
        .iter_mut()
        .find(|input| input.role == KagemushaWalletRetainedInputRoleV1::Request)
        .expect("retained Request")
        .bytes
}

// Recompute the capsule's actual own public bindings after a DATA context mutation. This
// makes the negative controls reach the new context join rather than only shape rejection.
fn rebind_capsule_data(capsule: &mut KagemushaWalletRecoveryCapsuleV1) {
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
    let request = retained_request(&capsule).expect("held Request");
    let expected_mask = if request.body.receiver_blacklist_version == 0 {
        0
    } else {
        KAGEMUSHA_WALLET_CONTROL_BLACKLIST_V1
    };
    assert_eq!(
        capsule_selector(&scheme, &capsule, &credential),
        Ok((KagemushaWalletOperationKindV1::Receive, expected_mask))
    );
    assert_eq!(
        capsule, original,
        "all retained canonical bytes remain exact"
    );
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
fn receipt_free_context_cannot_change_historical_selector_without_request_signature() {
    let (scheme, mut capsule, credential) = receive_capsule_data();
    let mut request = retained_request(&capsule).expect("Request");
    request.body.receiver_blacklist_version = request
        .body
        .receiver_blacklist_version
        .checked_add(1)
        .expect("historical version");
    if request.body.receiver_blacklist_root == [0; 32] {
        request.body.receiver_blacklist_root = Fp::from(99).to_repr();
    }
    request
        .body
        .validate()
        .expect("structurally valid changed Request body");
    *request_original(&mut capsule) =
        norito::encode_canonical(&request).expect("canonical mutation");
    capsule
        .validate()
        .expect("the capsule does not authenticate Request by shape");
    assert_eq!(
        capsule_selector(&scheme, &capsule, &credential),
        Err(Error::Authority),
        "a canonical but unauthenticated historical version cannot choose another key"
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
    KagemushaWalletRecoveryCapsuleV1,
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
    assert_eq!(payment.request, request.signed());
    assert_eq!(payment.payer_payment_key, payer.body.payment_key);
    assert_eq!(payment.payer_credential_digest, payer.credential_digest());
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
    state.core.blacklist_max_age_ms = payer.body.regulatory_policy.blacklist_max_age_ms;
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
    let payment: KagemushaWalletPaymentV1 = capsule_data_fixture("KagemushaWalletPaymentV1");
    let lineage = payment.send.lineage.lineage().unwrap();
    let token = iroha_pasta::CancellationToken::new();
    token.cancel();
    let budget = MemoryBudget::DEFAULT;
    assert_eq!(
        verifier.verify_package_proofs_cancellable(&payment.send, None, budget, Some(&token)),
        Err(Error::Cancelled)
    );
    assert_eq!(
        verifier.verify_capsule_proofs_cancellable(&capsule, &credential, budget, Some(&token)),
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
        verifier.verify_package_proofs(&payment.send, None, budget),
        Err(Error::Authority)
    );
}
