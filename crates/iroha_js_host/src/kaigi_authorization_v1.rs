//! Native construction of the final context-bound Kaigi authorization proof.

use iroha_data_model::{
    kaigi::{KaigiId, authorization::KaigiAuthorizationIdentitiesV1},
    proof::VerifyingKeyBox,
};
use iroha_model_base::domain::DomainId;
use iroha_model_base::name::Name;
use kaigi_zk::authorization_v1::{
    KaigiAuthorizationActionV1, KaigiAuthorizationContextV1, KaigiAuthorizationWitnessV1,
    compute_authorization_v1,
};
use napi::{
    Env,
    bindgen_prelude::{BigInt, Buffer, Uint8Array, Uint8ArraySlice},
};
use napi_derive::napi;
use std::str::FromStr as _;

use super::kaigi_proof_v1::{consume_blinding, encode_verified_envelope, failure, invalid};

/// Exact field outputs and canonical proof for one Kaigi authorization action.
#[napi(object)]
pub struct JsKaigiAuthorizationProofV1 {
    /// Canonical raw Pasta Fp commitment, without Iroha hash-marker mutation.
    pub commitment: Buffer,
    /// Canonical raw Pasta Fp action nullifier.
    pub nullifier: Buffer,
    /// Canonical raw Pasta Fp authorization binding the action and pre-state.
    pub authorization: Buffer,
    /// Exact 32-byte pre-state root supplied to the relation.
    pub pre_roster_root: Buffer,
    /// Canonical Norito `OpenVerifyEnvelope` for the final V1 circuit.
    pub proof: Buffer,
}

/// Decode exact native identities and sequence values for the typed N-API context.
#[allow(clippy::too_many_arguments)] // Fixed context fields mirror the typed N-API boundary.
pub fn parse_context(
    network: &[u8],
    domain: &str,
    call_name: &str,
    host: &str,
    subject: &str,
    sequence: &BigInt,
    action: &str,
    pre_root: &[u8],
) -> napi::Result<KaigiAuthorizationContextV1> {
    let network = super::parse_transaction_network_id_bytes(network)?;
    let domain_id = DomainId::parse_fully_qualified(domain).map_err(invalid)?;
    let name = Name::from_str(call_name).map_err(invalid)?;
    if domain_id.to_string() != domain || name.as_ref() != call_name {
        return Err(invalid(
            "callId must use canonical domain and call-name text",
        ));
    }
    if host.trim() != host || subject.trim() != subject {
        return Err(invalid(
            "account identities must not contain surrounding whitespace",
        ));
    }
    let _chain_guard = super::scoped_chain_discriminant_for_literal(host)?;
    let host = super::parse_account_id(host, "Kaigi host")?;
    let subject = super::parse_account_id(subject, "Kaigi subject")?;
    let identities = KaigiAuthorizationIdentitiesV1::new(
        network,
        &KaigiId::new(domain_id, name),
        &host,
        &subject,
    )
    .map_err(invalid)?;
    let (negative, sequence, lossless) = sequence.get_u64();
    if negative || !lossless {
        return Err(invalid(
            "participationSequence must be an exact unsigned 64-bit bigint",
        ));
    }
    let action = match action {
        "hostCreate" => KaigiAuthorizationActionV1::HostCreate,
        "join" => KaigiAuthorizationActionV1::Join,
        "leave" => KaigiAuthorizationActionV1::Leave,
        "hostEnd" => KaigiAuthorizationActionV1::HostEnd,
        _ => return Err(invalid("unknown Kaigi authorization action")),
    };
    let context = KaigiAuthorizationContextV1 {
        network_id: *identities.network_id.as_bytes(),
        call_id: identities.call_id.words(),
        host_id: identities.host_id.words(),
        subject_id: identities.subject_id.words(),
        participation_sequence: sequence,
        action,
        pre_roster_root: pre_root
            .try_into()
            .map_err(|_| invalid("preRosterRoot must contain exactly 32 bytes"))?,
    };
    context.validate().map_err(invalid)?;
    Ok(context)
}

fn produce(
    context: KaigiAuthorizationContextV1,
    witness: KaigiAuthorizationWitnessV1,
) -> napi::Result<(JsKaigiAuthorizationProofV1, VerifyingKeyBox)> {
    let outputs = compute_authorization_v1(&context, &witness).map_err(invalid)?;
    let key = iroha_core_zk::native_pipa_r::kaigi_verifying_key(
        kaigi_zk::native::NativeRelationV1::Authorization,
    )
    .map_err(failure)?;
    let envelope = iroha_core_zk::native_pipa_r::prove_kaigi_authorization(context, witness)
        .map_err(failure)?;
    let proof = encode_verified_envelope(&envelope, &key)?;
    let [commitment, nullifier, authorization] = outputs.canonical_bytes();
    Ok((
        JsKaigiAuthorizationProofV1 {
            commitment: commitment.to_vec().into(),
            nullifier: nullifier.to_vec().into(),
            authorization: authorization.to_vec().into(),
            pre_roster_root: context.pre_roster_root.to_vec().into(),
            proof: proof.into(),
        },
        key,
    ))
}

/// Consume a nonzero full-field blinding and prove one complete Kaigi V1 action.
///
/// Accepted blinding buffers are cleared before context parsing, including on
/// failure. The native prover consumes the witness and releases its advice buffers.
#[napi(js_name = "buildKaigiAuthorizationProofV1")]
#[allow(clippy::too_many_arguments)] // Keep each final V1 field typed across N-API.
pub fn build_kaigi_authorization_proof_v1(
    env: Env,
    network_id: Uint8Array,
    domain_id: String,
    call_name: String,
    host_id: String,
    subject_id: String,
    participation_sequence: BigInt,
    action: String,
    pre_roster_root: Uint8Array,
    mut blinding: Uint8ArraySlice<'_>,
) -> napi::Result<JsKaigiAuthorizationProofV1> {
    // Public byte views may share JS backing storage with the consumed view.
    // Snapshot exact-size values without allocating from an untrusted length.
    let network: Result<[u8; 32], _> = network_id.as_ref().try_into();
    let root: Result<[u8; 32], _> = pre_roster_root.as_ref().try_into();
    let witness = consume_blinding(env, &mut blinding)?;
    let network = network.map_err(|_| invalid("networkId must contain exactly 32 bytes"))?;
    let root = root.map_err(|_| invalid("preRosterRoot must contain exactly 32 bytes"))?;
    let context = parse_context(
        &network,
        &domain_id,
        &call_name,
        &host_id,
        &subject_id,
        &participation_sequence,
        &action,
        &root,
    )?;
    produce(context, witness).map(|(artifacts, _)| artifacts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kaigi_proof_v1::{VK_BACKEND, take_witness};
    use iroha_core_zk::hash_vk;
    use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair};
    use iroha_data_model::{
        NetworkId,
        account::AccountId,
        proof::ProofBox,
        zk::{BackendTag, OpenVerifyEnvelope},
    };
    use kaigi_zk::authorization_v1::{
        KAIGI_AUTHORIZATION_CIRCUIT_ID_V1, KAIGI_AUTHORIZATION_PUBLIC_INPUTS_SCHEMA_V1,
    };

    fn account(seed: u8) -> AccountId {
        let key = KeyPair::from_seed(vec![seed; 32], Algorithm::Ed25519);
        AccountId::new(key.public_key().clone())
    }

    fn fixture_context() -> KaigiAuthorizationContextV1 {
        let network =
            NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new([3; 32])));
        let domain = DomainId::try_new("kaigi", "universal").unwrap();
        parse_context(
            network.as_bytes(),
            &domain.to_string(),
            "native-proof",
            &account(1).to_string(),
            &account(2).to_string(),
            &BigInt::from(1_u64),
            "join",
            &[0x35; 32],
        )
        .unwrap()
    }

    #[test]
    fn explicit_host_selects_context_and_rejects_a_subject_from_another_network() {
        use iroha_data_model::account::address::{ChainDiscriminantGuard, chain_discriminant};
        let _outer = ChainDiscriminantGuard::enter(753);
        let network =
            NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new([3; 32])));
        let mut first = None;
        for prefix in [369, 42] {
            let host = account(1).to_i105_for_discriminant(prefix).unwrap();
            let subject = account(2).to_i105_for_discriminant(prefix).unwrap();
            let parse = |subject: &str| {
                parse_context(
                    network.as_bytes(),
                    "kaigi.universal",
                    "native-proof",
                    &host,
                    subject,
                    &BigInt::from(1_u64),
                    "join",
                    &[0x35; 32],
                )
            };
            let context = parse(&subject).unwrap();
            assert_eq!(chain_discriminant(), 753);
            if let Some(first) = first {
                assert_eq!(context, first);
            } else {
                first = Some(context);
            }
            assert!(parse(&account(2).to_i105_for_discriminant(753).unwrap()).is_err());
            assert_eq!(chain_discriminant(), 753);
        }
    }

    #[test]
    fn generated_envelope_verification_fails_closed_without_returning_bytes() {
        let key = VerifyingKeyBox::new(VK_BACKEND.to_owned(), Vec::new());
        let envelope = OpenVerifyEnvelope {
            backend: BackendTag::NativePipaRPasta,
            circuit_id: KAIGI_AUTHORIZATION_CIRCUIT_ID_V1.to_owned(),
            vk_hash: hash_vk(&key),
            public_inputs: KAIGI_AUTHORIZATION_PUBLIC_INPUTS_SCHEMA_V1.to_vec(),
            proof_bytes: Vec::new(),
            aux: Vec::new(),
        };
        let error = encode_verified_envelope(&envelope, &key).unwrap_err();
        assert_eq!(error.status, napi::Status::GenericFailure);
        assert!(
            error
                .reason
                .contains("failed canonical native verification")
        );
    }

    #[test]
    fn witness_consumption_clears_valid_invalid_and_wrong_length_buffers() {
        let mut valid = [0; 32];
        valid[0] = 1;
        let witness = take_witness(&mut valid).unwrap();
        assert_eq!(valid, [0; 32]);
        assert!(!format!("{witness:?}").contains("[1,"));
        for mut invalid in [vec![0; 32], vec![0xff; 32], vec![1; 31], vec![1; 33]] {
            assert!(take_witness(&mut invalid).is_err());
            assert!(invalid.iter().all(|&byte| byte == 0));
        }
    }

    #[test]
    fn canonical_context_rejects_lossy_sequence_and_wrong_roles_and_binds_all_identities() {
        use iroha_data_model::account::{MultisigMember, MultisigPolicy};

        let base = fixture_context();
        let network =
            NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new([3; 32])));
        let domain = DomainId::try_new("kaigi", "universal").unwrap().to_string();
        let host = account(1).to_string();
        let subject = account(2).to_string();
        let context = |sequence: BigInt, action: &str, subject: &str| {
            parse_context(
                network.as_bytes(),
                &domain,
                "native-proof",
                &host,
                subject,
                &sequence,
                action,
                &[0x35; 32],
            )
        };
        assert_eq!(
            context(BigInt::from(1_u64), "join", &subject).unwrap(),
            base
        );
        assert!(
            context(
                BigInt {
                    sign_bit: true,
                    words: vec![1]
                },
                "join",
                &subject
            )
            .is_err()
        );
        assert!(
            context(
                BigInt {
                    sign_bit: false,
                    words: vec![0, 1]
                },
                "join",
                &subject
            )
            .is_err()
        );
        assert!(context(BigInt::from(0_u64), "join", &subject).is_err());
        assert!(context(BigInt::from(1_u64), "hostEnd", &host).is_err());
        assert!(context(BigInt::from(1_u64), "join", &host).is_err());
        assert!(context(BigInt::from(0_u64), "hostCreate", &subject).is_err());
        assert!(context(BigInt::from(1_u64), "JOIN", &subject).is_err());
        let maximum = context(BigInt::from(u64::MAX), "leave", &subject).unwrap();
        assert_eq!(maximum.participation_sequence, u64::MAX);
        let other = context(BigInt::from(1_u64), "join", &account(4).to_string()).unwrap();
        assert_ne!(other.subject_id, base.subject_id);
        let members: Vec<_> = (1..=24)
            .map(|seed| {
                MultisigMember::new(account(seed).expect_single_signatory().clone(), 1).unwrap()
            })
            .collect();
        let policy = MultisigPolicy::new(2, members).unwrap();
        let original = AccountId::new_multisig(policy.clone());
        let original_text = original.canonical_i105().unwrap();
        assert_eq!(AccountId::parse_encoded(&original_text).unwrap(), original);
        let original_context = context(BigInt::from(1_u64), "join", &original_text).unwrap();
        let mut changed_members = policy.members().to_vec();
        let last = changed_members.last_mut().unwrap();
        *last = MultisigMember::new(last.public_key().clone(), 2).unwrap();
        let changed = AccountId::new_multisig(MultisigPolicy::new(2, changed_members).unwrap());
        let changed_context = context(
            BigInt::from(1_u64),
            "join",
            &changed.canonical_i105().unwrap(),
        )
        .unwrap();
        assert_ne!(original_context.subject_id, changed_context.subject_id);
        assert!(
            parse_context(
                &[0; 32],
                &domain,
                "native-proof",
                &host,
                &subject,
                &BigInt::from(1_u64),
                "join",
                &[0x35; 32]
            )
            .is_err()
        );
        assert!(
            parse_context(
                network.as_bytes(),
                &domain,
                "native-proof",
                &host,
                &subject,
                &BigInt::from(1_u64),
                "join",
                &[0x35; 31]
            )
            .is_err()
        );
    }

    #[test]
    fn final_native_proof_verifies_and_rejects_mutated_context_owner_and_outputs() {
        let context = fixture_context();
        assert!(std::ptr::eq(
            kaigi_zk::native::NativeRelationV1::Authorization
                .prover()
                .unwrap(),
            kaigi_zk::native::NativeRelationV1::Authorization
                .prover()
                .unwrap()
        ));
        let mut secret = [0x11; 32];
        let (artifacts, key) = produce(context, take_witness(&mut secret).unwrap()).unwrap();
        assert_eq!(secret, [0; 32]);
        for output in [
            &artifacts.commitment,
            &artifacts.nullifier,
            &artifacts.authorization,
        ] {
            assert!(
                iroha_data_model::kaigi::scalar::KaigiAuthorizationScalarV1::from_le_bytes(
                    output.as_ref().try_into().unwrap()
                )
                .is_some()
            );
        }
        assert_eq!(artifacts.pre_roster_root.as_ref(), context.pre_roster_root);
        let envelope: OpenVerifyEnvelope =
            norito::decode_canonical(artifacts.proof.as_ref()).unwrap();
        assert_eq!(envelope.circuit_id, KAIGI_AUTHORIZATION_CIRCUIT_ID_V1);
        assert_eq!(
            envelope.public_inputs,
            KAIGI_AUTHORIZATION_PUBLIC_INPUTS_SCHEMA_V1
        );
        assert_eq!(envelope.vk_hash, hash_vk(&key));
        assert!(envelope.aux.is_empty());
        let proof = ProofBox::new(VK_BACKEND.to_owned(), artifacts.proof.as_ref().to_vec());
        assert!(iroha_core_zk::verify_backend(
            VK_BACKEND,
            &proof,
            Some(&key)
        ));
        for row in 0..31 {
            let mut changed = envelope.clone();
            let mut inner: iroha_data_model::zk::NativePipaRProofV1 =
                norito::decode_canonical(&changed.proof_bytes).unwrap();
            assert_eq!(inner.public_inputs.len(), 31);
            let bytes = &mut inner.public_inputs[row];
            let zero = bytes.iter().all(|byte| *byte == 0);
            bytes.fill(0);
            if zero {
                bytes[0] = 1;
            }
            changed.proof_bytes = norito::encode_canonical(&inner).unwrap();
            let proof = ProofBox::new(
                VK_BACKEND.to_owned(),
                norito::encode_canonical(&changed).unwrap(),
            );
            assert!(
                !iroha_core_zk::verify_backend(VK_BACKEND, &proof, Some(&key)),
                "modified row {row}"
            );
        }
    }
}
