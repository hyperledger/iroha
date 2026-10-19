use super::*;
use crate::{
    Domain, Level,
    account::{MultisigMember, MultisigPolicy},
    prelude::{Log, Register, TriggerId},
    privacy::{
        IROHA_JINDO_FIELD_ELEMENT_BYTES_V1, IROHA_JINDO_LATTICE_COMMITMENT_BYTES_V1,
        IrohaIvmPrivateNoteStarkStatementV1, IrohaJindoPolynomialCommitmentStatementV1,
        PrivacyActionDigestV1, PrivacyChallengeV1, PrivacyCommitmentV1,
        PrivacyCredentialDocumentTypeV1, PrivacyEngineManifestDigestV1, PrivacyIssuerIdV1,
        PrivacyJindoFieldElementV1, PrivacyJindoLatticeCommitmentV1, PrivacyNullifierV1,
        PrivacyP256PointV1, PrivacyParameterDigestV1, PrivacyParameterIdV1, PrivacyPolicyDigestV1,
        PrivacyPolicyIdV1, PrivacyPoolIdV1, PrivacyProgramIdV1, PrivacyProofBytesV1,
        PrivacyProofEnvelopeV1, PrivacyProofSystemIdV1, PrivacyProofV1, PrivacyProtocolIdV1,
        PrivacyRootV1, PrivacySessionTranscriptDigestV1, PrivacyStatementContextV1,
        PrivacyStatementDigestV1, PrivacyStatementSchemaDigestV1, PrivacyStatementV1,
        PrivacyTransactionIntentDigestV1, PrivacyValueBalanceV1,
        PrivacyVegaDeviceAuthenticationDigestV1, PrivacyVegaIssuerRecordDigestV1,
        PrivacyVegaMdlDateV1, PrivacyVegaMdlDigestAlgorithmV1, PrivacyVegaMdlNamespaceV1,
        PrivacyVegaMdlSignatureAlgorithmV1, PrivacyVerifierDigestV1,
        PrivacyZkAceIdentityCommitmentV1, PrivacyZkAceReplayNullifierV1,
        VegaExistingCredentialStatementV1, ZkAcePqAuthorizationStatementV1,
    },
    transaction::{
        ExecutableBatchItem,
        executable::{ContractInvocation, IvmProved},
    },
    trigger::DataTriggerSequence,
};
use iroha_model_base::domain::DomainId;
use iroha_model_base::metadata::Metadata;
use iroha_version::{
    DecodeAll,
    codec::{DecodeVersioned, EncodeVersioned},
};
use norito::core::DecodeFromSlice;
fn sample_signed_transaction() -> SignedTransaction {
    let chain = test_network_id(0x11);
    let public_key: iroha_crypto::PublicKey =
        "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03"
            .parse()
            .unwrap();
    let authority = AccountId::new(public_key);
    let private_key: iroha_crypto::PrivateKey =
        "802620CCF31D85E3B32A4BEA59987CE0C78E3B8E2DB93881468AB2435FE45D5C9DCD53"
            .parse()
            .unwrap();
    TransactionBuilder::new(
        chain,
        authority,
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([Log::new(Level::INFO, "exact slice".into())])
    .sign(&private_key)
}

#[test]
fn fallible_external_hash_is_exact_original_intent_under_inherited_scope() {
    let signed = sample_signed_transaction();
    let expected = signed.hash_as_entrypoint();
    assert_eq!(Hash::from(signed.hash()), Hash::from(expected));
    let limits = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 64);
    let actual =
        norito::with_decode_limits_scope(limits, || signed.try_hash_as_entrypoint()).unwrap();
    assert_eq!(actual, expected);
    let prehash = HashOf::try_new(signed.payload()).unwrap();
    let signatory = signed.authority().try_signatory().unwrap();
    assert!(
        iroha_crypto::verify_signature_borrowed(&signed.signature().0, signatory, prehash.as_ref())
            .is_ok()
    );
    signed.verify_signature().unwrap();
}
fn split_default_norito_fields(bytes: &[u8], count: usize) -> Vec<Vec<u8>> {
    let flags = norito::core::default_encode_flags();
    let mut offset = 0usize;
    let mut fields = Vec::with_capacity(count);
    for _ in 0..count {
        let (len, prefix) = norito::core::read_len_from_slice_with_flags(
            bytes.get(offset..).expect("Norito field prefix"),
            flags,
        )
        .expect("Norito field length");
        let start = offset.checked_add(prefix).expect("Norito field start");
        let end = start.checked_add(len).expect("Norito field end");
        fields.push(
            bytes
                .get(start..end)
                .expect("complete Norito field")
                .to_vec(),
        );
        offset = end;
    }
    assert_eq!(offset, bytes.len(), "unexpected trailing Norito fields");
    fields
}
fn encode_default_norito_fields(fields: &[Vec<u8>]) -> Vec<u8> {
    let flags = norito::core::default_encode_flags();
    let mut encoded = Vec::new();
    for field in fields {
        norito::core::write_len_to_vec_with_flags(
            &mut encoded,
            u64::try_from(field.len()).expect("Norito field length fits u64"),
            flags,
        );
        encoded.extend_from_slice(field);
    }
    encoded
}
fn signed_transaction_with_log_type_name_alias(canonical: &[u8]) -> Vec<u8> {
    assert_eq!(canonical.first(), Some(&1), "signed transaction V1 prefix");
    let mut signed = split_default_norito_fields(&canonical[1..], 3);
    let mut payload = split_default_norito_fields(&signed[1], 9);

    assert_eq!(&payload[3][..4], &0_u32.to_le_bytes());
    let executable_fields = split_default_norito_fields(&payload[3][4..], 1);
    let sequence = &executable_fields[0];
    assert_eq!(&sequence[..8], &1_u64.to_le_bytes());
    let sequence_fields = split_default_norito_fields(&sequence[8..], 1);
    let mut instruction = split_default_norito_fields(&sequence_fields[0], 2);
    let wire_id = split_default_norito_fields(&instruction[0], 1);
    assert_eq!(wire_id[0], b"iroha.log");

    instruction[0] =
        encode_default_norito_fields(&[std::any::type_name::<Log>().as_bytes().to_vec()]);
    let mut sequence = 1_u64.to_le_bytes().to_vec();
    sequence.extend_from_slice(&encode_default_norito_fields(&[
        encode_default_norito_fields(&instruction),
    ]));
    let mut executable = 0_u32.to_le_bytes().to_vec();
    executable.extend_from_slice(&encode_default_norito_fields(&[sequence]));
    payload[3] = executable;
    signed[1] = encode_default_norito_fields(&payload);

    let mut alternate = vec![1];
    alternate.extend_from_slice(&encode_default_norito_fields(&signed));
    alternate
}
fn external_entrypoint_wire(signed_transaction_wire: &[u8]) -> Vec<u8> {
    assert_eq!(
        signed_transaction_wire.first(),
        Some(&1),
        "nested signed transaction V1 prefix"
    );
    let mut wire = vec![1];
    wire.extend_from_slice(&0_u32.to_le_bytes());
    wire.extend_from_slice(&encode_default_norito_fields(&[signed_transaction_wire
        [1..]
        .to_vec()]));
    wire
}

fn assert_exact_json<T: norito::json::JsonSerialize>(value: &T) {
    let legacy = norito::json::to_json(value).expect("serialize legacy JSON");
    assert_eq!(
        norito::json::to_json_bounded(value, legacy.len()).expect("serialize at exact bound"),
        legacy
    );
    assert_eq!(
        norito::json::to_json_bounded(value, legacy.len() - 1),
        Err(norito::json::BoundedJsonError::BodyTooLarge)
    );
}

#[test]
fn transaction_manual_json_families_have_exact_checked_bounds() {
    assert_exact_json(&TransactionEntrypoint::External(sample_signed_transaction()));
    assert_exact_json(&TransactionResult::new(Ok(DataTriggerSequence::default())));
    assert_exact_json(&ExecutionStep(ConstVec::from(vec![InstructionBox::from(
        Log::new(Level::INFO, "checked execution step".to_owned()),
    )])));
}
#[test]
fn transaction_domain_network_and_genesis_wire_are_disjoint_and_pinned() {
    let network_id = test_network_id(0x35);
    let network = TransactionDomain::Network(network_id);
    let network_payload = norito::codec::Encode::encode(&network);
    let mut expected_network = vec![
        0,
        0,
        0,
        0,
        u8::try_from(Hash::LENGTH).expect("hash byte length fits the wire prefix"),
    ];
    expected_network.extend_from_slice(network_id.as_bytes());
    assert_eq!(network_payload, expected_network);
    let network_bytes =
        norito::encode_canonical(&network).expect("encode network transaction domain");
    assert_eq!(
        norito::decode_canonical::<TransactionDomain>(&network_bytes)
            .expect("decode pinned network transaction domain"),
        network
    );
    let genesis = TransactionDomain::Genesis;
    let genesis_payload = norito::codec::Encode::encode(&genesis);
    assert_eq!(genesis_payload, [1, 0, 0, 0]);
    let genesis_bytes =
        norito::encode_canonical(&genesis).expect("encode genesis transaction domain");
    assert_eq!(
        norito::decode_canonical::<TransactionDomain>(&genesis_bytes)
            .expect("decode pinned genesis transaction domain"),
        genesis
    );
    assert_ne!(network_bytes, genesis_bytes);
    assert!(
        <TransactionDomain as norito::codec::Decode>::decode(&mut &[2, 0, 0, 0][..]).is_err(),
        "the closed transaction-domain enum must reject unknown discriminants"
    );
}

#[test]
fn transaction_domain_json_is_closed_and_rejects_legacy_identity_keys() {
    let network_id = test_network_id(0x35);
    let network = TransactionDomain::Network(network_id);
    let network_id_json =
        norito::json::to_json(&network_id).expect("serialize canonical network id");
    let expected_network = format!(r#"{{"kind":"network","value":{network_id_json}}}"#);
    assert_eq!(
        norito::json::to_json(&network).expect("serialize network transaction domain"),
        expected_network
    );
    assert_eq!(
        norito::json::from_str::<TransactionDomain>(&expected_network)
            .expect("decode canonical network transaction domain"),
        network
    );
    assert_eq!(
        norito::json::to_json(&TransactionDomain::Genesis)
            .expect("serialize genesis transaction domain"),
        r#"{"kind":"genesis","value":null}"#
    );
    for rejected in [
        format!(r#"{{"kind":"network","content":{network_id_json}}}"#),
        format!(r#"{{"network_id":{network_id_json}}}"#),
        r#"{"chain":"legacy"}"#.to_owned(),
        r#"{"chainId":"legacy"}"#.to_owned(),
        r#"{"chain_id":"legacy"}"#.to_owned(),
        format!(r#"{{"kind":"network","value":{network_id_json},"chain":"legacy"}}"#),
        r#"{"kind":"genesis","chain":"legacy"}"#.to_owned(),
        format!(r#"{{"kind":"genesis","value":{network_id_json}}}"#),
    ] {
        assert!(
            norito::json::from_str::<TransactionDomain>(&rejected).is_err(),
            "legacy, flat, or non-canonical transaction domain must be rejected: {rejected}"
        );
    }
}

#[test]
fn transaction_payload_json_rejects_retired_identity_keys_and_unknown_fields() {
    let transaction = sample_signed_transaction();
    let payload = transaction.payload();
    let exact_json = norito::json::to_json(payload).expect("serialize transaction payload");
    let expected_json = format!(
        "{{\"domain\":{domain},\"authority\":{authority},\"creation_time_ms\":{creation_time_ms},\"instructions\":{instructions},\"time_to_live_ms\":{time_to_live_ms},\"nonce\":{nonce},\"fee_payment\":{fee_payment},\"metadata\":{metadata},\"attachments\":null}}",
        domain = norito::json::to_json(&payload.domain).expect("serialize transaction domain"),
        authority =
            norito::json::to_json(&payload.authority).expect("serialize transaction authority"),
        creation_time_ms = payload.creation_time_ms,
        instructions =
            norito::json::to_json(&payload.instructions).expect("serialize transaction executable"),
        time_to_live_ms = norito::json::to_json(&payload.time_to_live_ms)
            .expect("serialize transaction lifetime"),
        nonce = norito::json::to_json(&payload.nonce).expect("serialize transaction nonce"),
        fee_payment =
            norito::json::to_json(&payload.fee_payment).expect("serialize transaction fee intent"),
        metadata =
            norito::json::to_json(&payload.metadata).expect("serialize transaction metadata"),
    );
    assert_eq!(exact_json, expected_json);
    assert_eq!(
        norito::json::from_str::<TransactionPayload>(&exact_json)
            .expect("deserialize exact transaction payload JSON"),
        payload.clone()
    );
    let canonical = norito::json::to_value(transaction.payload())
        .expect("serialize canonical transaction payload");
    assert!(
        norito::json::from_value::<TransactionPayload>(canonical.clone()).is_ok(),
        "the canonical transaction payload must round-trip"
    );
    let canonical_object = canonical
        .as_object()
        .expect("transaction payload serializes as an object");
    assert!(canonical_object.contains_key("domain"));
    for retired in [
        "chain",
        "chain_id",
        "chainId",
        "admission_intent",
        "admissionIntent",
    ] {
        assert!(!canonical_object.contains_key(retired));
        let mut hostile = canonical.clone();
        hostile
            .as_object_mut()
            .expect("transaction payload object")
            .insert(
                retired.to_owned(),
                norito::json::Value::String("legacy".to_owned()),
            );
        assert!(
            norito::json::from_value::<TransactionPayload>(hostile).is_err(),
            "retired transaction identity key `{retired}` must be rejected"
        );
    }
    let mut unknown = canonical.clone();
    unknown
        .as_object_mut()
        .expect("transaction payload object")
        .insert(
            "future_identity".to_owned(),
            norito::json::Value::String("forbidden".to_owned()),
        );
    assert!(
        norito::json::from_value::<TransactionPayload>(unknown).is_err(),
        "unknown transaction payload fields must fail closed"
    );
    assert_eq!(
        canonical
            .as_object()
            .expect("transaction payload object")
            .get("attachments"),
        Some(&norito::json::Value::Null),
        "absent attachments must be represented by an explicit null"
    );
    let mut missing_attachments = canonical.clone();
    missing_attachments
        .as_object_mut()
        .expect("transaction payload object")
        .remove("attachments");
    assert!(
        norito::json::from_value::<TransactionPayload>(missing_attachments).is_err(),
        "transaction payload attachments are mandatory even when null"
    );
    let mut missing_domain = canonical;
    missing_domain
        .as_object_mut()
        .expect("transaction payload object")
        .remove("domain");
    assert!(
        norito::json::from_value::<TransactionPayload>(missing_domain).is_err(),
        "transaction payload domain is mandatory"
    );
}
fn sample_fee_asset() -> AssetDefinitionId {
    AssetDefinitionId::derive_from_components(
        DomainId::try_new("fees", "universal").expect("valid fee domain"),
        "xor".parse().expect("valid fee asset name"),
    )
}

#[test]
fn fee_payment_json_requires_explicit_nullable_gas_and_closed_objects() {
    let mut unknown_kind =
        norito::json::to_value(&FeeChargeKind::Nexus).expect("serialize fee charge kind");
    unknown_kind
        .as_object_mut()
        .expect("fee charge kind JSON object")
        .insert("pre_release_field".to_owned(), norito::json::Value::Null);
    assert!(
        norito::json::from_value::<FeeChargeKind>(unknown_kind).is_err(),
        "fee charge kind unknown fields must fail closed"
    );

    let authority = AuthorityFeePayment {
        charge_limits: Vec::new(),
        gas_limit: None,
    };
    let authority_json =
        norito::json::to_json(&authority).expect("serialize authority fee payment with absent gas");
    assert_eq!(authority_json, r#"{"charge_limits":[],"gas_limit":null}"#);
    assert_eq!(
        norito::json::from_str::<AuthorityFeePayment>(&authority_json)
            .expect("deserialize exact authority fee-payment JSON"),
        authority
    );

    let sponsor = SponsorFeePayment {
        program_id: FeeSponsorProgramId::new(
            sample_signed_transaction().authority().clone(),
            "wallet".parse().expect("program name"),
        ),
        program_revision: 1,
        charge_limits: Vec::new(),
        gas_limit: None,
    };
    let sponsor_json =
        norito::json::to_json(&sponsor).expect("serialize sponsor fee payment with absent gas");
    let expected_sponsor_json = format!(
        "{{\"program_id\":{program_id},\"program_revision\":1,\"charge_limits\":[],\"gas_limit\":null}}",
        program_id =
            norito::json::to_json(&sponsor.program_id).expect("serialize sponsor program id")
    );
    assert_eq!(sponsor_json, expected_sponsor_json);
    assert_eq!(
        norito::json::from_str::<SponsorFeePayment>(&sponsor_json)
            .expect("deserialize exact sponsor fee-payment JSON"),
        sponsor
    );

    for (label, canonical) in [
        (
            "authority",
            norito::json::to_value(&authority).expect("serialize authority fee payment"),
        ),
        (
            "sponsor",
            norito::json::to_value(&sponsor).expect("serialize sponsor fee payment"),
        ),
    ] {
        let mut missing = canonical.clone();
        assert!(
            missing
                .as_object_mut()
                .expect("fee-payment JSON object")
                .remove("gas_limit")
                .is_some()
        );
        let missing_rejected = if label == "authority" {
            norito::json::from_value::<AuthorityFeePayment>(missing).is_err()
        } else {
            norito::json::from_value::<SponsorFeePayment>(missing).is_err()
        };
        assert!(missing_rejected, "{label} gas_limit omission must fail");

        let mut unknown = canonical;
        unknown
            .as_object_mut()
            .expect("fee-payment JSON object")
            .insert("pre_release_field".to_owned(), norito::json::Value::Null);
        let unknown_rejected = if label == "authority" {
            norito::json::from_value::<AuthorityFeePayment>(unknown).is_err()
        } else {
            norito::json::from_value::<SponsorFeePayment>(unknown).is_err()
        };
        assert!(unknown_rejected, "{label} unknown fields must fail closed");
    }
}
#[test]
fn transaction_v1_rejects_pre_release_binary_layouts_without_nullable_fields() {
    #[derive(Encode)]
    struct PreReleaseAuthorityFeePayment {
        charge_limits: Vec<FeeChargeLimit>,
    }
    #[derive(Encode)]
    struct PreReleaseSponsorFeePayment {
        program_id: FeeSponsorProgramId,
        program_revision: u64,
        charge_limits: Vec<FeeChargeLimit>,
    }
    #[derive(Encode)]
    struct PreReleaseTransactionPayload {
        domain: TransactionDomain,
        authority: AccountId,
        creation_time_ms: u64,
        instructions: Executable,
        time_to_live_ms: Option<NonZeroU64>,
        nonce: Option<NonZeroU32>,
        fee_payment: FeePaymentIntent,
        metadata: Metadata,
    }

    let authority_bytes = PreReleaseAuthorityFeePayment {
        charge_limits: Vec::new(),
    }
    .encode();
    assert!(
        AuthorityFeePayment::decode(&mut authority_bytes.as_slice()).is_err(),
        "the first-release authority fee payment must require the nullable gas slot"
    );

    let sponsor_bytes = PreReleaseSponsorFeePayment {
        program_id: FeeSponsorProgramId::new(
            sample_signed_transaction().authority().clone(),
            "wallet".parse().expect("program name"),
        ),
        program_revision: 1,
        charge_limits: Vec::new(),
    }
    .encode();
    assert!(
        SponsorFeePayment::decode(&mut sponsor_bytes.as_slice()).is_err(),
        "the first-release sponsor fee payment must require the nullable gas slot"
    );

    let payload = sample_signed_transaction().payload().clone();
    let payload_bytes = PreReleaseTransactionPayload {
        domain: payload.domain,
        authority: payload.authority,
        creation_time_ms: payload.creation_time_ms,
        instructions: payload.instructions,
        time_to_live_ms: payload.time_to_live_ms,
        nonce: payload.nonce,
        fee_payment: payload.fee_payment,
        metadata: payload.metadata,
    }
    .encode();
    assert!(
        TransactionPayload::decode(&mut payload_bytes.as_slice()).is_err(),
        "the first-release transaction payload must require the nullable attachments slot"
    );
}
fn privacy_test_authority() -> AccountId {
    let public_key: iroha_crypto::PublicKey =
        "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03"
            .parse()
            .expect("test public key");
    AccountId::new(public_key)
}
fn privacy_test_private_key() -> iroha_crypto::PrivateKey {
    "802620CCF31D85E3B32A4BEA59987CE0C78E3B8E2DB93881468AB2435FE45D5C9DCD53"
        .parse()
        .expect("test private key")
}
const fn privacy_test_bytes(seed: u8) -> [u8; 32] {
    [seed; 32]
}
fn draft_privacy_submission() -> SubmitPrivacyProofV1 {
    let protocol_id = PrivacyProtocolIdV1::IrohaJindoPolynomialCommitmentV1;
    let parameter_id = PrivacyParameterIdV1::new(privacy_test_bytes(1));
    let parameter_digest = PrivacyParameterDigestV1::new(privacy_test_bytes(2));
    let verifier_digest = PrivacyVerifierDigestV1::new(privacy_test_bytes(3));
    let statement_schema_digest = PrivacyStatementSchemaDigestV1::new(privacy_test_bytes(4));
    let engine_manifest_digest = PrivacyEngineManifestDigestV1::new(privacy_test_bytes(5));
    let statement = PrivacyStatementV1::IrohaJindoPolynomialCommitmentV1(
        IrohaJindoPolynomialCommitmentStatementV1 {
            context: PrivacyStatementContextV1 {
                network_id: test_network_id(0x30),
                action_index: 0,
                parameter_id,
                parameter_digest,
                verifier_digest,
                statement_schema_digest,
                engine_manifest_digest,
                transaction_intent_digest: PrivacyTransactionIntentDigestV1::new([0; 32]),
            },
            polynomial_commitments: (6_i32..10)
                .map(|coefficient| {
                    let mut encoding = vec![0; IROHA_JINDO_LATTICE_COMMITMENT_BYTES_V1];
                    encoding[..4].copy_from_slice(&coefficient.to_le_bytes());
                    PrivacyJindoLatticeCommitmentV1::new(encoding)
                })
                .collect(),
            evaluation_point: PrivacyJindoFieldElementV1::new(
                [7; IROHA_JINDO_FIELD_ELEMENT_BYTES_V1],
            ),
            claimed_evaluations: (8_u8..12)
                .map(|value| {
                    let mut encoding = [0; IROHA_JINDO_FIELD_ELEMENT_BYTES_V1];
                    encoding[0] = value;
                    PrivacyJindoFieldElementV1::new(encoding)
                })
                .collect(),
        },
    );
    SubmitPrivacyProofV1::new(PrivacyProofEnvelopeV1 {
        wire_magic: crate::privacy::PrivacyProofWireMagicV1::default(),
        catalog_commitment: crate::privacy::PrivacyExact12CatalogCommitmentV1::default(),
        protocol_id,
        proof_system_id: PrivacyProofSystemIdV1::JindoPolynomialCommitment,
        engine_id: protocol_id.expected_engine(),
        parameter_id,
        parameter_digest,
        verifier_digest,
        statement_schema_digest,
        engine_manifest_digest,
        statement_digest: PrivacyStatementDigestV1::new([0; 32]),
        statement,
        proof: PrivacyProofV1::IrohaJindoPolynomialCommitmentV1(PrivacyProofBytesV1::new(vec![
            0xA5, 0x5A, 1,
        ])),
    })
}
fn privacy_payload_with_executable(executable: Executable) -> TransactionPayload {
    TransactionBuilder::new_with_time(
        TransactionDomain::Network(test_network_id(0x30)),
        privacy_test_authority(),
        1_725_000_000_000,
        FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_executable(executable)
    .into_payload()
    .expect("valid test payload")
}
fn draft_privacy_payload() -> TransactionPayload {
    privacy_payload_with_executable(vec![InstructionBox::from(draft_privacy_submission())].into())
}
fn draft_zk_ace_privacy_payload() -> TransactionPayload {
    let mut payload = draft_privacy_payload();
    mutate_direct_privacy_submission(&mut payload, |submission| {
        let context = *submission.envelope.statement.context();
        let authority = privacy_test_authority();
        submission.envelope.protocol_id = PrivacyProtocolIdV1::ZkAcePqAuthorizationV1;
        submission.envelope.proof_system_id = PrivacyProofSystemIdV1::StarkFriSha3_384Goldilocks;
        submission.envelope.engine_id =
            PrivacyProtocolIdV1::ZkAcePqAuthorizationV1.expected_engine();
        submission.envelope.statement =
            PrivacyStatementV1::ZkAcePqAuthorizationV1(ZkAcePqAuthorizationStatementV1 {
                context,
                identity_commitment: PrivacyZkAceIdentityCommitmentV1::new([0x71; 6])
                    .expect("small fixture words are canonical"),
                policy_id: PrivacyPolicyIdV1::new(privacy_test_bytes(0x72)),
                policy_digest: PrivacyPolicyDigestV1::new(privacy_test_bytes(0x73)),
                source: authority.clone(),
                destination: authority,
                asset_definition_id: sample_fee_asset(),
                public_balance_scope: crate::asset::AssetBalanceScope::Global,
                amount: 7,
                authorization_epoch: 1,
                replay_nullifier: PrivacyZkAceReplayNullifierV1::new([0x74; 6])
                    .expect("small fixture words are canonical"),
            });
        submission.envelope.statement_digest = PrivacyStatementDigestV1::new([0; 32]);
        submission.envelope.proof =
            PrivacyProofV1::ZkAcePqAuthorizationV1(PrivacyProofBytesV1::new(vec![0xA5, 0x5A]));
    });
    payload
}
fn draft_vega_privacy_payload() -> TransactionPayload {
    let mut payload = draft_privacy_payload();
    mutate_direct_privacy_submission(&mut payload, |submission| {
        let context = *submission.envelope.statement.context();
        let protocol_id = PrivacyProtocolIdV1::VegaExistingCredentialZkV1;
        submission.envelope.protocol_id = protocol_id;
        submission.envelope.proof_system_id =
            PrivacyProofSystemIdV1::VegaNeutronNovaSpartanHyraxT256;
        submission.envelope.engine_id = protocol_id.expected_engine();
        submission.envelope.statement =
            PrivacyStatementV1::VegaExistingCredentialZkV1(VegaExistingCredentialStatementV1 {
                context,
                issuer_id: PrivacyIssuerIdV1::new(privacy_test_bytes(0x81)),
                issuer_record_epoch: 1,
                issuer_record_digest: PrivacyVegaIssuerRecordDigestV1::new(privacy_test_bytes(
                    0x82,
                )),
                document_type: PrivacyCredentialDocumentTypeV1::Iso18013_5Mdl,
                namespace: PrivacyVegaMdlNamespaceV1::OrgIso18013_5_1,
                digest_algorithm: PrivacyVegaMdlDigestAlgorithmV1::Sha256,
                issuer_authentication_algorithm: PrivacyVegaMdlSignatureAlgorithmV1::CoseSign1Es256,
                device_authentication_algorithm: PrivacyVegaMdlSignatureAlgorithmV1::CoseSign1Es256,
                issuer_public_key: PrivacyP256PointV1::new([
                    0x02, 0x6f, 0xf0, 0x3b, 0x94, 0x92, 0x41, 0xce, 0x1d, 0xad, 0xd4, 0x35, 0x19,
                    0xe6, 0x96, 0x0e, 0x0a, 0x85, 0xb4, 0x1a, 0x69, 0xa0, 0x5c, 0x32, 0x81, 0x03,
                    0xaa, 0x2b, 0xce, 0x15, 0x94, 0xca, 0x16,
                ]),
                device_authentication_digest: PrivacyVegaDeviceAuthenticationDigestV1::new(
                    privacy_test_bytes(0x83),
                ),
                presentation_date: PrivacyVegaMdlDateV1 {
                    year: 2026,
                    month: 7,
                    day: 28,
                },
                minimum_age_years: 18,
                reader_challenge: PrivacyChallengeV1::new(privacy_test_bytes(0x84)),
                session_transcript_digest: PrivacySessionTranscriptDigestV1::new(
                    privacy_test_bytes(0x85),
                ),
            });
        submission.envelope.statement_digest = PrivacyStatementDigestV1::new([0; 32]);
        submission.envelope.proof =
            PrivacyProofV1::VegaExistingCredentialZkV1(PrivacyProofBytesV1::new(vec![0xA5, 0x5A]));
    });
    payload
}
fn draft_ivm_private_note_privacy_payload() -> TransactionPayload {
    let mut payload = draft_privacy_payload();
    mutate_direct_privacy_submission(&mut payload, |submission| {
        let context = *submission.envelope.statement.context();
        let protocol_id = PrivacyProtocolIdV1::IrohaIvmPrivateNoteStarkV1;
        submission.envelope.protocol_id = protocol_id;
        submission.envelope.proof_system_id = PrivacyProofSystemIdV1::StarkFriSha3_384Goldilocks;
        submission.envelope.engine_id = protocol_id.expected_engine();
        let mut statement = IrohaIvmPrivateNoteStarkStatementV1 {
            context,
            asset_definition_id: sample_fee_asset(),
            public_balance_scope: crate::asset::AssetBalanceScope::Global,
            pool_id: PrivacyPoolIdV1::new(privacy_test_bytes(0x91)),
            program_id: PrivacyProgramIdV1::new(privacy_test_bytes(0x92)),
            action_digest: PrivacyActionDigestV1::new([0; 32]),
            state_root: PrivacyRootV1::new(privacy_test_bytes(0x93)),
            root_epoch: 7,
            nullifiers: vec![PrivacyNullifierV1::new(privacy_test_bytes(0x94))],
            output_commitments: vec![PrivacyCommitmentV1::new(privacy_test_bytes(0x95))],
            encrypted_outputs: Vec::new(),
            value_balance: PrivacyValueBalanceV1::balanced(),
            execution_epoch: 7,
        };
        statement.action_digest = statement
            .computed_action_digest()
            .expect("draft IVM action digest");
        submission.envelope.statement = PrivacyStatementV1::IrohaIvmPrivateNoteStarkV1(statement);
        submission.envelope.statement_digest = PrivacyStatementDigestV1::new([0; 32]);
        submission.envelope.proof =
            PrivacyProofV1::IrohaIvmPrivateNoteStarkV1(PrivacyProofBytesV1::new(vec![0xA5, 0x5A]));
    });
    payload
}
fn mutate_direct_privacy_submission(
    payload: &mut TransactionPayload,
    mutate: impl FnOnce(&mut SubmitPrivacyProofV1),
) {
    let submitted = match &payload.instructions {
        Executable::Instructions(instructions) => instructions
            .iter()
            .find_map(|instruction| instruction.as_any().downcast_ref::<SubmitPrivacyProofV1>()),
        Executable::Batch(items) => items.iter().find_map(|item| match item {
            ExecutableBatchItem::Instruction(instruction) => {
                instruction.as_any().downcast_ref::<SubmitPrivacyProofV1>()
            }
            ExecutableBatchItem::ContractCall(_) => None,
        }),
        _ => None,
    };
    let mut submission = submitted
        .expect("test payload has a direct privacy submission")
        .clone();
    mutate(&mut submission);
    payload.instructions = match &payload.instructions {
        Executable::Instructions(instructions) => Executable::Instructions(
            instructions
                .iter()
                .map(|instruction| {
                    if instruction.as_any().is::<SubmitPrivacyProofV1>() {
                        submission.clone().into()
                    } else {
                        instruction.clone()
                    }
                })
                .collect::<Vec<_>>()
                .into(),
        ),
        Executable::Batch(items) => Executable::Batch(
            items
                .iter()
                .map(|item| match item {
                    ExecutableBatchItem::Instruction(instruction)
                        if instruction.as_any().is::<SubmitPrivacyProofV1>() =>
                    {
                        ExecutableBatchItem::Instruction(submission.clone().into())
                    }
                    _ => item.clone(),
                })
                .collect::<Vec<_>>()
                .into(),
        ),
        _ => panic!("test helper requires a direct native privacy member"),
    };
}
fn finalized_privacy_payload() -> TransactionPayload {
    let mut payload = draft_privacy_payload();
    let intent = payload
        .privacy_transaction_intent_digest_v1()
        .expect("draft derives a canonical intent");
    mutate_direct_privacy_submission(&mut payload, |submission| {
        submission
            .envelope
            .statement
            .context_mut()
            .transaction_intent_digest = intent;
        submission.envelope.statement_digest = submission
            .envelope
            .statement
            .digest()
            .expect("final statement digest");
    });
    assert_eq!(
        payload
            .validate_privacy_transaction_intent_binding_v1()
            .expect("final payload binding"),
        intent
    );
    payload
}

#[test]
fn privacy_intent_rejects_foreign_network_even_after_digest_refinalization() {
    for domain in [
        TransactionDomain::Network(test_network_id(0x31)),
        TransactionDomain::Genesis,
    ] {
        let mut payload = finalized_privacy_payload();
        payload.domain = domain;
        assert_eq!(
            payload.validate_privacy_transaction_intent_binding_v1(),
            Err(PrivacyTransactionIntentErrorV1::NetworkDomainMismatch)
        );
        let intent = payload
            .privacy_transaction_intent_digest_v1()
            .expect("projection can be computed for the adversarial payload");
        mutate_direct_privacy_submission(&mut payload, |submission| {
            submission
                .envelope
                .statement
                .context_mut()
                .transaction_intent_digest = intent;
            submission.envelope.statement_digest = submission
                .envelope
                .statement
                .digest()
                .expect("refinalized adversarial statement");
        });
        assert_eq!(
            payload.validate_privacy_transaction_intent_binding_v1(),
            Err(PrivacyTransactionIntentErrorV1::NetworkDomainMismatch),
            "consistent hashes cannot authorize a foreign-network or genesis privacy proof"
        );
    }
}

fn privacy_test_contract_call() -> ContractInvocation {
    ContractInvocation {
        contract_address: crate::smart_contract::ContractAddress::derive(
            &test_network_id(0x30),
            &privacy_test_authority(),
            0,
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
        )
        .expect("test contract address"),
        expected_code_hash: Hash::new(b"privacy intent test contract"),
        entrypoint: "run".to_owned(),
        arguments: None,
    }
}
fn legacy_proof_only_privacy_intent_digest(
    payload: &TransactionPayload,
) -> PrivacyTransactionIntentDigestV1 {
    let mut normalized = payload.clone();
    mutate_direct_privacy_submission(&mut normalized, |submission| {
        submission.envelope.proof.bytes_mut().bytes.clear();
    });
    let encoded = norito::to_bytes(&normalized).expect("legacy projection encodes");
    let mut hasher = blake3::Hasher::new();
    hasher.update(PRIVACY_TRANSACTION_INTENT_DIGEST_DOMAIN_V1);
    hasher.update(
        &u64::try_from(encoded.len())
            .expect("test payload length fits u64")
            .to_le_bytes(),
    );
    hasher.update(&encoded);
    PrivacyTransactionIntentDigestV1::new(*hasher.finalize().as_bytes())
}
fn assert_privacy_binding_absent(payload: &TransactionPayload, message: &str) {
    assert!(
        payload
            .privacy_transaction_intent_binding_if_present_v1()
            .expect(message)
            .is_none()
    );
}
fn assert_privacy_digest_rejects_path(
    payload: &TransactionPayload,
    path: PrivacyTransactionIntentUnsupportedPathV1,
    message: &str,
) {
    assert_eq!(
        payload
            .privacy_transaction_intent_digest_v1()
            .expect_err(message),
        PrivacyTransactionIntentErrorV1::UnsupportedPath { path }
    );
}
fn assert_privacy_binding_rejects_path(
    payload: &TransactionPayload,
    path: PrivacyTransactionIntentUnsupportedPathV1,
    message: &str,
) {
    assert_eq!(
        payload
            .privacy_transaction_intent_binding_if_present_v1()
            .expect_err(message),
        PrivacyTransactionIntentErrorV1::UnsupportedPath { path }
    );
}
fn assert_privacy_ivm_paths_rejected() {
    let raw_ivm =
        privacy_payload_with_executable(Executable::Ivm(IvmBytecode::from_compiled(vec![1])));
    assert_privacy_digest_rejects_path(
        &raw_ivm,
        PrivacyTransactionIntentUnsupportedPathV1::Ivm,
        "raw IVM is not a direct typed submission",
    );
    assert_privacy_binding_absent(
        &raw_ivm,
        "an ordinary IVM transaction has no privacy binding",
    );
    let ordinary_proved = privacy_payload_with_executable(Executable::IvmProved(IvmProved {
        bytecode: IvmBytecode::from_compiled(vec![2]),
        overlay: vec![InstructionBox::from(Log::new(
            Level::INFO,
            "ordinary proved overlay".into(),
        ))]
        .into(),
        events_commitment: Hash::new(b"ordinary events"),
        gas_policy_commitment: Hash::new(b"ordinary gas"),
    }));
    assert_privacy_binding_absent(
        &ordinary_proved,
        "an ordinary proved transaction has no privacy binding",
    );
    let proved = privacy_payload_with_executable(Executable::IvmProved(IvmProved {
        bytecode: IvmBytecode::from_compiled(vec![2]),
        overlay: vec![InstructionBox::from(draft_privacy_submission())].into(),
        events_commitment: Hash::new(b"events"),
        gas_policy_commitment: Hash::new(b"gas"),
    }));
    assert_privacy_binding_rejects_path(
        &proved,
        PrivacyTransactionIntentUnsupportedPathV1::IvmProved,
        "proved overlays cannot carry a V1 privacy submission",
    );
}
fn assert_privacy_dynamic_dispatch_paths_rejected() {
    let contract =
        privacy_payload_with_executable(Executable::ContractCall(privacy_test_contract_call()));
    assert_privacy_digest_rejects_path(
        &contract,
        PrivacyTransactionIntentUnsupportedPathV1::ContractCall,
        "contract call is opaque to the V1 projection",
    );
    assert_privacy_binding_absent(
        &contract,
        "an ordinary contract transaction has no privacy binding",
    );
    let ordinary_contract_batch = privacy_payload_with_executable(Executable::Batch(
        vec![ExecutableBatchItem::ContractCall(
            privacy_test_contract_call(),
        )]
        .into(),
    ));
    assert_privacy_binding_absent(
        &ordinary_contract_batch,
        "an ordinary contract batch has no privacy binding",
    );
    let custom = privacy_payload_with_executable(
        vec![
            InstructionBox::from(draft_privacy_submission()),
            InstructionBox::from(CustomInstruction::new(Json::new("opaque executor"))),
        ]
        .into(),
    );
    assert_privacy_binding_rejects_path(
        &custom,
        PrivacyTransactionIntentUnsupportedPathV1::CustomInstruction,
        "custom executor path",
    );
    let ordinary_custom = privacy_payload_with_executable(
        vec![InstructionBox::from(CustomInstruction::new(Json::new(
            "ordinary executor",
        )))]
        .into(),
    );
    assert_privacy_binding_absent(
        &ordinary_custom,
        "an ordinary custom instruction has no privacy binding",
    );
    let trigger = privacy_payload_with_executable(
        vec![
            InstructionBox::from(draft_privacy_submission()),
            InstructionBox::from(ExecuteTrigger::new(
                TriggerId::from_str("privacy_dynamic").expect("trigger id"),
            )),
        ]
        .into(),
    );
    assert_privacy_binding_rejects_path(
        &trigger,
        PrivacyTransactionIntentUnsupportedPathV1::ExecuteTrigger,
        "by-call trigger path",
    );
    let ordinary_trigger = privacy_payload_with_executable(
        vec![InstructionBox::from(ExecuteTrigger::new(
            TriggerId::from_str("ordinary_dynamic").expect("trigger id"),
        ))]
        .into(),
    );
    assert_privacy_binding_absent(
        &ordinary_trigger,
        "an ordinary trigger instruction has no privacy binding",
    );
}
fn assert_canonical_privacy_intent_kat(
    payload: &TransactionPayload,
    expected: PrivacyTransactionIntentDigestV1,
) {
    let mut normalized = payload.clone();
    normalized.instructions = normalize_privacy_executable_for_intent_v1(&normalized.instructions)
        .expect("canonical normalized executable");
    let normalized_bytes =
        norito::encode_canonical(&normalized).expect("canonical normalized payload");
    assert_eq!(
        normalized_bytes,
        payload
            .privacy_transaction_intent_projection_bytes_v1()
            .expect("production canonical projection"),
        "manual normalization must match the production canonical projection"
    );
    assert_eq!(
        normalized_bytes.len(),
        50_259,
        "the canonical fixture wire length is part of the cross-SDK KAT"
    );
    // Final V1 includes the eight-byte wire marker and 48-byte catalog
    // commitment, each with its canonical field-length prefix.
    assert_eq!(
        hex::encode(expected.as_bytes()),
        "52756936c8e625cec56483d94eda82a3a9f5e8749922239622d78b37ab9009bc",
        "canonical privacy transaction-intent V1 digest"
    );
}
fn assert_privacy_proof_bytes_are_projected_out(
    payload: &TransactionPayload,
    expected: PrivacyTransactionIntentDigestV1,
) {
    let mut changed_proof = payload.clone();
    mutate_direct_privacy_submission(&mut changed_proof, |submission| {
        submission.envelope.proof.bytes_mut().bytes = vec![9, 8, 7, 6, 5];
    });
    assert_eq!(
        changed_proof
            .privacy_transaction_intent_digest_v1()
            .expect("proof bytes are projected out"),
        expected
    );
    changed_proof
        .validate_privacy_transaction_intent_binding_v1()
        .expect("proof bytes do not alter either derived digest");
}
fn assert_stored_privacy_digests_are_checked(
    payload: &TransactionPayload,
    expected: PrivacyTransactionIntentDigestV1,
) {
    let mut stale_intent = payload.clone();
    mutate_direct_privacy_submission(&mut stale_intent, |submission| {
        submission
            .envelope
            .statement
            .context_mut()
            .transaction_intent_digest =
            PrivacyTransactionIntentDigestV1::new(privacy_test_bytes(0xD1));
    });
    assert_eq!(
        stale_intent
            .privacy_transaction_intent_digest_v1()
            .expect("the derived intent field is projected out"),
        expected
    );
    assert!(matches!(
        stale_intent
            .validate_privacy_transaction_intent_binding_v1()
            .expect_err("stored intent is independently checked"),
        PrivacyTransactionIntentErrorV1::IntentDigestMismatch { .. }
    ));
    let mut zero_intent = payload.clone();
    mutate_direct_privacy_submission(&mut zero_intent, |submission| {
        submission
            .envelope
            .statement
            .context_mut()
            .transaction_intent_digest = PrivacyTransactionIntentDigestV1::new([0; 32]);
    });
    assert_eq!(
        zero_intent
            .validate_privacy_transaction_intent_binding_v1()
            .expect_err("zero stored intent"),
        PrivacyTransactionIntentErrorV1::ZeroIntentDigest
    );
    let mut stale_statement = payload.clone();
    mutate_direct_privacy_submission(&mut stale_statement, |submission| {
        submission.envelope.statement_digest =
            PrivacyStatementDigestV1::new(privacy_test_bytes(0xD2));
    });
    assert_eq!(
        stale_statement
            .privacy_transaction_intent_digest_v1()
            .expect("the derived statement digest is projected out"),
        expected
    );
    assert!(matches!(
        stale_statement
            .validate_privacy_transaction_intent_binding_v1()
            .expect_err("stored statement digest is independently checked"),
        PrivacyTransactionIntentErrorV1::StatementDigestMismatch { .. }
    ));
    let mut zero_statement = payload.clone();
    mutate_direct_privacy_submission(&mut zero_statement, |submission| {
        submission.envelope.statement_digest = PrivacyStatementDigestV1::new([0; 32]);
    });
    assert_eq!(
        zero_statement
            .validate_privacy_transaction_intent_binding_v1()
            .expect_err("zero stored statement digest"),
        PrivacyTransactionIntentErrorV1::ZeroStatementDigest
    );
}
fn assert_legacy_privacy_digest_cycle_is_broken(expected: PrivacyTransactionIntentDigestV1) {
    let draft = draft_privacy_payload();
    let first_legacy = legacy_proof_only_privacy_intent_digest(&draft);
    let mut inserted = draft;
    mutate_direct_privacy_submission(&mut inserted, |submission| {
        submission
            .envelope
            .statement
            .context_mut()
            .transaction_intent_digest = first_legacy;
        submission.envelope.statement_digest = submission
            .envelope
            .statement
            .digest()
            .expect("legacy-cycle statement digest");
    });
    let second_legacy = legacy_proof_only_privacy_intent_digest(&inserted);
    assert_ne!(
        first_legacy, second_legacy,
        "the old proof-only projection changes after inserting its own result and cannot construct the stored value"
    );
    assert_eq!(
        inserted
            .privacy_transaction_intent_digest_v1()
            .expect("canonical projection removes both derived fields"),
        expected
    );
}
#[test]
fn transaction_payload_exposes_execution_identity_ttl_and_network() {
    let chain = test_network_id(0x12);
    let public_key: iroha_crypto::PublicKey =
        "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03"
            .parse()
            .expect("public key");
    let authority = AccountId::new(public_key);
    let instructions: Executable = vec![InstructionBox::from(Log::new(
        Level::INFO,
        "payload".into(),
    ))]
    .into();
    let time_to_live = Duration::from_secs(42);
    let mut builder = TransactionBuilder::new(
        chain,
        authority.clone(),
        FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_executable(instructions.clone());
    builder.set_ttl(time_to_live);
    let payload = builder.payload();
    assert_eq!(payload.instructions(), &instructions);
    assert_eq!(payload.authority(), &authority);
    assert_eq!(payload.time_to_live(), Some(time_to_live));
    assert_eq!(payload.network_id(), Some(&chain));
}
#[test]
fn privacy_transaction_intent_requires_one_direct_typed_submission() {
    let ordinary = privacy_payload_with_executable(
        vec![InstructionBox::from(Log::new(
            Level::INFO,
            "ordinary".into(),
        ))]
        .into(),
    );
    assert_eq!(
        ordinary
            .privacy_transaction_intent_digest_v1()
            .expect_err("zero submissions"),
        PrivacyTransactionIntentErrorV1::MissingSubmission
    );
    assert!(
        ordinary
            .privacy_transaction_intent_binding_if_present_v1()
            .expect("ordinary payload is not a privacy transaction")
            .is_none()
    );
    let duplicate = draft_privacy_submission();
    let duplicate_payload = privacy_payload_with_executable(
        vec![
            InstructionBox::from(duplicate.clone()),
            InstructionBox::from(duplicate),
        ]
        .into(),
    );
    assert_eq!(
        duplicate_payload
            .privacy_transaction_intent_digest_v1()
            .expect_err("two direct submissions"),
        PrivacyTransactionIntentErrorV1::MultipleSubmissions { count: 2 }
    );
    assert_eq!(
        duplicate_payload
            .privacy_transaction_intent_binding_if_present_v1()
            .expect_err("runtime must reject multiple direct submissions"),
        PrivacyTransactionIntentErrorV1::MultipleSubmissions { count: 2 }
    );
}
#[test]
fn privacy_mixed_batch_binds_exact_direct_member_and_contract_order() {
    let call = privacy_test_contract_call();
    let mut payload = privacy_payload_with_executable(Executable::Batch(
        vec![
            ExecutableBatchItem::ContractCall(call.clone()),
            ExecutableBatchItem::Instruction(draft_privacy_submission().into()),
            ExecutableBatchItem::ContractCall(call),
        ]
        .into(),
    ));
    let intent = payload
        .privacy_transaction_intent_digest_v1()
        .expect("mixed intent");
    mutate_direct_privacy_submission(&mut payload, |submission| {
        submission
            .envelope
            .statement
            .context_mut()
            .transaction_intent_digest = intent;
        submission.envelope.statement_digest = submission.envelope.statement.digest().unwrap();
    });
    let (bound, submission) = payload
        .privacy_transaction_intent_binding_if_present_v1()
        .expect("mixed binding")
        .expect("direct submission");
    assert_eq!(bound, intent);
    assert_eq!(submission.envelope.statement.context().action_index, 0);
    let Executable::Batch(items) = &payload.instructions else {
        unreachable!()
    };
    for index in [0, 2] {
        let mut changed = items.clone().into_vec();
        let ExecutableBatchItem::ContractCall(call) = &mut changed[index] else {
            unreachable!()
        };
        call.expected_code_hash = Hash::new(b"changed contract binding");
        let mut tampered = payload.clone();
        tampered.instructions = Executable::Batch(changed.into());
        assert_ne!(
            tampered.privacy_transaction_intent_digest_v1().unwrap(),
            intent
        );
        assert!(
            tampered
                .validate_privacy_transaction_intent_binding_v1()
                .is_err()
        );
    }
    let mut reordered = items.clone().into_vec();
    reordered.swap(0, 1);
    let mut tampered = payload.clone();
    tampered.instructions = Executable::Batch(reordered.into());
    assert_ne!(
        tampered.privacy_transaction_intent_digest_v1().unwrap(),
        intent
    );
    assert!(
        tampered
            .validate_privacy_transaction_intent_binding_v1()
            .is_err()
    );
}

#[test]
fn privacy_transaction_intent_rejects_dynamic_paths() {
    assert_privacy_ivm_paths_rejected();
    assert_privacy_dynamic_dispatch_paths_rejected();
}
#[test]
fn privacy_transaction_intent_projection_breaks_the_derived_digest_cycle_exactly() {
    let payload = finalized_privacy_payload();
    let canonical_projection = payload
        .privacy_transaction_intent_projection_bytes_v1()
        .expect("canonical finalized projection bytes");
    let expected = payload
        .privacy_transaction_intent_digest_v1()
        .expect("canonical finalized projection");
    {
        let alternate_flags =
            norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
        let _ambient = norito::core::DecodeFlagsGuard::enter(alternate_flags);
        assert_eq!(
            payload
                .privacy_transaction_intent_projection_bytes_v1()
                .expect("ambient layout flags cannot alter the canonical projection"),
            canonical_projection
        );
        assert_eq!(
            payload
                .privacy_transaction_intent_digest_v1()
                .expect("ambient layout flags cannot alter the canonical intent"),
            expected
        );
    }
    assert_canonical_privacy_intent_kat(&payload, expected);
    assert_privacy_proof_bytes_are_projected_out(&payload, expected);
    assert_stored_privacy_digests_are_checked(&payload, expected);
    assert_legacy_privacy_digest_cycle_is_broken(expected);
}
#[test]
fn zk_ace_intent_projection_zeroes_the_derived_nullifier_and_binds_action_fields() {
    let payload = draft_zk_ace_privacy_payload();
    let expected = payload
        .privacy_transaction_intent_digest_v1()
        .expect("derive ZK-ACE draft intent");
    let mut changed_nullifier = payload.clone();
    mutate_direct_privacy_submission(&mut changed_nullifier, |submission| {
        let PrivacyStatementV1::ZkAcePqAuthorizationV1(statement) =
            &mut submission.envelope.statement
        else {
            panic!("ZK-ACE fixture statement");
        };
        statement.replay_nullifier = PrivacyZkAceReplayNullifierV1::new([0x75; 6])
            .expect("small fixture words are canonical");
    });
    assert_eq!(
        changed_nullifier
            .privacy_transaction_intent_digest_v1()
            .expect("derived replay nullifier is projected out"),
        expected
    );
    let mut changed_amount = payload.clone();
    mutate_direct_privacy_submission(&mut changed_amount, |submission| {
        let PrivacyStatementV1::ZkAcePqAuthorizationV1(statement) =
            &mut submission.envelope.statement
        else {
            panic!("ZK-ACE fixture statement");
        };
        statement.amount += 1;
    });
    assert_ne!(
        changed_amount
            .privacy_transaction_intent_digest_v1()
            .expect("independent action amount remains bound"),
        expected
    );
    let mut changed_scope = payload.clone();
    mutate_direct_privacy_submission(&mut changed_scope, |submission| {
        let PrivacyStatementV1::ZkAcePqAuthorizationV1(statement) =
            &mut submission.envelope.statement
        else {
            panic!("ZK-ACE fixture statement");
        };
        statement.public_balance_scope = crate::asset::AssetBalanceScope::Dataspace(
            iroha_model_base::topology::DataSpaceId::new(7),
        );
    });
    assert_ne!(
        changed_scope
            .privacy_transaction_intent_digest_v1()
            .expect("exact public balance scope remains bound"),
        expected
    );
    let mut finalized = payload;
    mutate_direct_privacy_submission(&mut finalized, |submission| {
        submission
            .envelope
            .statement
            .context_mut()
            .transaction_intent_digest = expected;
        submission.envelope.statement_digest = submission
            .envelope
            .statement
            .digest()
            .expect("final ZK-ACE statement digest");
    });
    assert_eq!(
        finalized
            .validate_privacy_transaction_intent_binding_v1()
            .expect("final ZK-ACE intent binding"),
        expected
    );
}
#[test]
fn vega_intent_projection_zeroes_only_the_derived_hdev_and_breaks_its_cycle() {
    let payload = draft_vega_privacy_payload();
    let expected = payload
        .privacy_transaction_intent_digest_v1()
        .expect("derive Vega draft intent");
    assert_eq!(
        hex::encode(expected.as_bytes()),
        "3d3928fdee164c3e9efc55c9a90bdd491380b62c94723b076cf95ddc81bb232b",
        "canonical Vega two-phase transaction-intent projection KAT"
    );
    let mut changed_hdev = payload.clone();
    mutate_direct_privacy_submission(&mut changed_hdev, |submission| {
        let PrivacyStatementV1::VegaExistingCredentialZkV1(statement) =
            &mut submission.envelope.statement
        else {
            panic!("Vega fixture statement");
        };
        statement.device_authentication_digest =
            PrivacyVegaDeviceAuthenticationDigestV1::new(privacy_test_bytes(0x86));
    });
    assert_eq!(
        changed_hdev
            .privacy_transaction_intent_digest_v1()
            .expect("derived H_dev is projected out"),
        expected
    );
    let independent_mutations: [fn(&mut VegaExistingCredentialStatementV1); 3] = [
        |statement: &mut VegaExistingCredentialStatementV1| {
            statement.reader_challenge.0[0] ^= 1;
        },
        |statement: &mut VegaExistingCredentialStatementV1| {
            statement.issuer_record_digest.0[0] ^= 1;
        },
        |statement: &mut VegaExistingCredentialStatementV1| {
            statement.presentation_date.day += 1;
        },
    ];
    for mutate in independent_mutations {
        let mut changed = payload.clone();
        mutate_direct_privacy_submission(&mut changed, |submission| {
            let PrivacyStatementV1::VegaExistingCredentialZkV1(statement) =
                &mut submission.envelope.statement
            else {
                panic!("Vega fixture statement");
            };
            mutate(statement);
        });
        assert_ne!(
            changed
                .privacy_transaction_intent_digest_v1()
                .expect("independent Vega statement field remains bound"),
            expected
        );
    }
    let mut finalized = payload;
    mutate_direct_privacy_submission(&mut finalized, |submission| {
        let PrivacyStatementV1::VegaExistingCredentialZkV1(statement) =
            &mut submission.envelope.statement
        else {
            panic!("Vega fixture statement");
        };
        statement.context.transaction_intent_digest = expected;
        statement.device_authentication_digest =
            PrivacyVegaDeviceAuthenticationDigestV1::new(privacy_test_bytes(0x87));
        submission.envelope.statement_digest = submission
            .envelope
            .statement
            .digest()
            .expect("final Vega statement digest");
    });
    assert_eq!(
        finalized
            .validate_privacy_transaction_intent_binding_v1()
            .expect("final intent-bound Vega payload"),
        expected
    );
}
#[test]
fn ivm_private_note_intent_projection_breaks_the_action_digest_fixed_point() {
    let payload = draft_ivm_private_note_privacy_payload();
    let expected = payload
        .privacy_transaction_intent_digest_v1()
        .expect("derive IVM private-note draft intent");
    let mut changed_action_digest = payload.clone();
    mutate_direct_privacy_submission(&mut changed_action_digest, |submission| {
        let PrivacyStatementV1::IrohaIvmPrivateNoteStarkV1(statement) =
            &mut submission.envelope.statement
        else {
            panic!("IVM private-note fixture statement");
        };
        statement.action_digest = PrivacyActionDigestV1::new(privacy_test_bytes(0x96));
    });
    assert_eq!(
        changed_action_digest
            .privacy_transaction_intent_digest_v1()
            .expect("derived IVM action digest is projected out"),
        expected
    );
    let independent_mutations: [fn(&mut IrohaIvmPrivateNoteStarkStatementV1); 4] = [
        |statement: &mut IrohaIvmPrivateNoteStarkStatementV1| {
            statement.state_root.0[0] ^= 1;
        },
        |statement: &mut IrohaIvmPrivateNoteStarkStatementV1| {
            statement.execution_epoch += 1;
        },
        |statement: &mut IrohaIvmPrivateNoteStarkStatementV1| {
            statement.output_commitments[0].0[0] ^= 1;
        },
        |statement: &mut IrohaIvmPrivateNoteStarkStatementV1| {
            statement.public_balance_scope = crate::asset::AssetBalanceScope::Dataspace(
                iroha_model_base::topology::DataSpaceId::new(7),
            );
        },
    ];
    for mutate in independent_mutations {
        let mut changed = payload.clone();
        mutate_direct_privacy_submission(&mut changed, |submission| {
            let PrivacyStatementV1::IrohaIvmPrivateNoteStarkV1(statement) =
                &mut submission.envelope.statement
            else {
                panic!("IVM private-note fixture statement");
            };
            mutate(statement);
        });
        assert_ne!(
            changed
                .privacy_transaction_intent_digest_v1()
                .expect("independent IVM statement field remains bound"),
            expected
        );
    }
    let mut finalized = payload;
    mutate_direct_privacy_submission(&mut finalized, |submission| {
        let PrivacyStatementV1::IrohaIvmPrivateNoteStarkV1(statement) =
            &mut submission.envelope.statement
        else {
            panic!("IVM private-note fixture statement");
        };
        statement.context.transaction_intent_digest = expected;
        statement.action_digest = PrivacyActionDigestV1::new([0; 32]);
        statement.action_digest = statement
            .computed_action_digest()
            .expect("intent-bound IVM action digest");
        assert!(!statement.action_digest.is_zero());
        assert_eq!(
            statement
                .computed_action_digest()
                .expect("stable IVM action digest"),
            statement.action_digest,
            "canonical two-phase construction reaches a stable action digest"
        );
        submission.envelope.statement_digest = submission
            .envelope
            .statement
            .digest()
            .expect("final IVM statement digest");
    });
    assert_eq!(
        finalized
            .validate_privacy_transaction_intent_binding_v1()
            .expect("final IVM intent binding"),
        expected
    );
    let mut stale_action_digest = finalized;
    mutate_direct_privacy_submission(&mut stale_action_digest, |submission| {
        let PrivacyStatementV1::IrohaIvmPrivateNoteStarkV1(statement) =
            &mut submission.envelope.statement
        else {
            panic!("IVM private-note fixture statement");
        };
        statement.action_digest.0[0] ^= 1;
        assert_ne!(
            statement
                .computed_action_digest()
                .expect("recompute adversarial IVM action digest"),
            statement.action_digest,
            "an independently drifted action digest cannot authenticate its statement"
        );
    });
}
#[test]
#[ignore = "operator-only KAT regeneration after an intentional intent projection change"]
fn print_transaction_intent_projection_kats() {
    let payload = finalized_privacy_payload();
    let projection = payload
        .privacy_transaction_intent_projection_bytes_v1()
        .expect("privacy intent projection");
    let digest = payload
        .privacy_transaction_intent_digest_v1()
        .expect("privacy intent projection digest");
    eprintln!(
        "PRIVACY_TRANSACTION_INTENT_PROJECTION_LEN_V1={}",
        projection.len()
    );
    eprintln!(
        "PRIVACY_TRANSACTION_INTENT_PROJECTION_KAT_V1={}",
        hex::encode(digest.as_bytes())
    );
    eprintln!(
        "PRIVACY_TRANSACTION_INTENT_PROJECTION_HEX_V1={}",
        hex::encode(&projection)
    );
    let vega = draft_vega_privacy_payload();
    let vega_projection = vega
        .privacy_transaction_intent_projection_bytes_v1()
        .expect("Vega projection bytes");
    let vega_digest = vega
        .privacy_transaction_intent_digest_v1()
        .expect("Vega intent projection");
    eprintln!(
        "VEGA_TRANSACTION_INTENT_PROJECTION_HEX_V1={}",
        hex::encode(&vega_projection)
    );
    eprintln!(
        "VEGA_TRANSACTION_INTENT_PROJECTION_KAT_V1={}",
        hex::encode(vega_digest.as_bytes())
    );
}
#[test]
#[allow(clippy::too_many_lines)]
fn privacy_transaction_intent_binds_every_independent_payload_field() {
    let payload = finalized_privacy_payload();
    let expected = payload
        .privacy_transaction_intent_digest_v1()
        .expect("base intent");
    macro_rules! assert_bound {
        ($name:literal, $mutate:expr) => {{
            let mut changed = payload.clone();
            ($mutate)(&mut changed);
            assert_ne!(
                changed
                    .privacy_transaction_intent_digest_v1()
                    .expect(concat!("derive changed ", $name)),
                expected,
                "{} must remain in the intent projection",
                $name
            );
        }};
    }
    assert_bound!("payload network", |changed: &mut TransactionPayload| {
        changed.domain = TransactionDomain::Network(test_network_id(0xFE));
    });
    assert_bound!("payload authority", |changed: &mut TransactionPayload| {
        let key: iroha_crypto::PublicKey =
            "ed012004FF5B81046DDCCF19E2E451C45DFB6F53759D4EB30FA2EFA807284D1CC33016"
                .parse()
                .expect("alternate key");
        changed.authority = AccountId::new(key);
    });
    assert_bound!("creation time", |changed: &mut TransactionPayload| {
        changed.creation_time_ms += 1;
    });
    assert_bound!("time to live", |changed: &mut TransactionPayload| {
        changed.time_to_live_ms = NonZeroU64::new(10);
    });
    assert_bound!("nonce", |changed: &mut TransactionPayload| {
        changed.nonce = NonZeroU32::new(7);
    });
    assert_bound!("fee intent", |changed: &mut TransactionPayload| {
        changed.fee_payment = FeePaymentIntent::authority(Vec::new(), NonZeroU64::new(11));
    });
    assert_bound!("metadata", |changed: &mut TransactionPayload| {
        changed.metadata.insert(
            Name::from_str("privacy_mutation").expect("metadata name"),
            Json::new(1_u32),
        );
    });
    assert_bound!("instruction ordinal", |changed: &mut TransactionPayload| {
        let Executable::Instructions(instructions) = &changed.instructions else {
            unreachable!()
        };
        let mut instructions = instructions.clone().into_vec();
        instructions.insert(0, Log::new(Level::INFO, "before privacy".into()).into());
        changed.instructions = Executable::Instructions(instructions.into());
    });
    macro_rules! assert_submission_bound {
        ($name:literal, $mutate:expr) => {
            assert_bound!($name, |changed: &mut TransactionPayload| {
                mutate_direct_privacy_submission(changed, $mutate);
            });
        };
    }
    assert_submission_bound!("protocol tag", |submission: &mut SubmitPrivacyProofV1| {
        submission.envelope.protocol_id = PrivacyProtocolIdV1::ZkAcePqAuthorizationV1;
    });
    assert_submission_bound!(
        "proof-system tag",
        |submission: &mut SubmitPrivacyProofV1| {
            submission.envelope.proof_system_id =
                PrivacyProofSystemIdV1::StarkFriSha3_384Goldilocks;
        }
    );
    assert_submission_bound!("engine tag", |submission: &mut SubmitPrivacyProofV1| {
        submission.envelope.engine_id =
            PrivacyProtocolIdV1::ZkAcePqAuthorizationV1.expected_engine();
    });
    assert_submission_bound!(
        "envelope parameter id",
        |submission: &mut SubmitPrivacyProofV1| {
            submission.envelope.parameter_id = PrivacyParameterIdV1::new(privacy_test_bytes(0x21));
        }
    );
    assert_submission_bound!(
        "envelope parameter digest",
        |submission: &mut SubmitPrivacyProofV1| {
            submission.envelope.parameter_digest =
                PrivacyParameterDigestV1::new(privacy_test_bytes(0x22));
        }
    );
    assert_submission_bound!(
        "envelope verifier digest",
        |submission: &mut SubmitPrivacyProofV1| {
            submission.envelope.verifier_digest =
                PrivacyVerifierDigestV1::new(privacy_test_bytes(0x23));
        }
    );
    assert_submission_bound!(
        "envelope schema digest",
        |submission: &mut SubmitPrivacyProofV1| {
            submission.envelope.statement_schema_digest =
                PrivacyStatementSchemaDigestV1::new(privacy_test_bytes(0x24));
        }
    );
    assert_submission_bound!(
        "envelope engine-manifest digest",
        |submission: &mut SubmitPrivacyProofV1| {
            submission.envelope.engine_manifest_digest =
                PrivacyEngineManifestDigestV1::new(privacy_test_bytes(0x25));
        }
    );
    assert_submission_bound!(
        "proof variant tag",
        |submission: &mut SubmitPrivacyProofV1| {
            submission.envelope.proof =
                PrivacyProofV1::ZkAcePqAuthorizationV1(PrivacyProofBytesV1::new(vec![0xA5]));
        }
    );
    assert_submission_bound!(
        "context network",
        |submission: &mut SubmitPrivacyProofV1| {
            submission.envelope.statement.context_mut().network_id = test_network_id(0x31);
        }
    );
    assert_submission_bound!("action index", |submission: &mut SubmitPrivacyProofV1| {
        submission.envelope.statement.context_mut().action_index = 1;
    });
    assert_submission_bound!(
        "context parameter id",
        |submission: &mut SubmitPrivacyProofV1| {
            submission.envelope.statement.context_mut().parameter_id =
                PrivacyParameterIdV1::new(privacy_test_bytes(0x31));
        }
    );
    assert_submission_bound!(
        "context parameter digest",
        |submission: &mut SubmitPrivacyProofV1| {
            submission.envelope.statement.context_mut().parameter_digest =
                PrivacyParameterDigestV1::new(privacy_test_bytes(0x32));
        }
    );
    assert_submission_bound!(
        "context verifier digest",
        |submission: &mut SubmitPrivacyProofV1| {
            submission.envelope.statement.context_mut().verifier_digest =
                PrivacyVerifierDigestV1::new(privacy_test_bytes(0x33));
        }
    );
    assert_submission_bound!(
        "context schema digest",
        |submission: &mut SubmitPrivacyProofV1| {
            submission
                .envelope
                .statement
                .context_mut()
                .statement_schema_digest =
                PrivacyStatementSchemaDigestV1::new(privacy_test_bytes(0x34));
        }
    );
    assert_submission_bound!(
        "context engine-manifest digest",
        |submission: &mut SubmitPrivacyProofV1| {
            submission
                .envelope
                .statement
                .context_mut()
                .engine_manifest_digest =
                PrivacyEngineManifestDigestV1::new(privacy_test_bytes(0x35));
        }
    );
    assert_submission_bound!(
        "statement polynomial commitment",
        |submission: &mut SubmitPrivacyProofV1| {
            let PrivacyStatementV1::IrohaJindoPolynomialCommitmentV1(statement) =
                &mut submission.envelope.statement
            else {
                unreachable!()
            };
            statement.polynomial_commitments[0].encoding[0] ^= 1;
        }
    );
    assert_submission_bound!(
        "statement query point",
        |submission: &mut SubmitPrivacyProofV1| {
            let PrivacyStatementV1::IrohaJindoPolynomialCommitmentV1(statement) =
                &mut submission.envelope.statement
            else {
                unreachable!()
            };
            statement.evaluation_point.encoding[0] ^= 1;
        }
    );
    assert_submission_bound!(
        "statement claimed evaluation",
        |submission: &mut SubmitPrivacyProofV1| {
            let PrivacyStatementV1::IrohaJindoPolynomialCommitmentV1(statement) =
                &mut submission.envelope.statement
            else {
                unreachable!()
            };
            statement.claimed_evaluations[0].encoding[0] ^= 1;
        }
    );
}
#[test]
fn privacy_intent_is_independent_of_the_complete_signed_transaction_hash() {
    let payload = finalized_privacy_payload();
    let transaction = TransactionBuilder::from_payload(payload)
        .expect("valid final payload")
        .sign(&privacy_test_private_key());
    let expected_intent = transaction
        .privacy_transaction_intent_digest_v1()
        .expect("signed transaction intent");
    let mut altered_signature = transaction.clone();
    altered_signature.signature = sample_signed_transaction().signature().clone();
    assert_eq!(
        altered_signature.hash(),
        transaction.hash(),
        "transaction identity must exclude replaceable authorization proof"
    );
    assert_eq!(
        altered_signature
            .privacy_transaction_intent_digest_v1()
            .expect("intent depends only on unsigned payload"),
        expected_intent
    );
}
#[test]
fn fee_payment_intent_requires_canonical_positive_component_limits() {
    let asset = sample_fee_asset();
    let nexus = FeeChargeLimit::new(FeeChargeKind::Nexus, asset.clone(), Quantity::from(10_u32));
    assert_eq!(nexus.kind(), FeeChargeKind::Nexus);
    assert_eq!(nexus.asset_definition_id(), &asset);
    assert_eq!(nexus.max_amount(), &Quantity::from(10_u32));
    let pipeline = FeeChargeLimit::new(
        FeeChargeKind::PipelineGas,
        asset.clone(),
        Quantity::from(20_u32),
    );
    FeePaymentIntent::authority(vec![nexus.clone(), pipeline.clone()], None)
        .validate()
        .expect("ordered positive fee limits are valid");
    let err = FeePaymentIntent::authority(vec![pipeline, nexus.clone()], None)
        .validate()
        .expect_err("reversed component order must fail");
    assert_eq!(err, FeePaymentIntentError::NonCanonicalChargeLimitOrder);
    let err = FeePaymentIntent::authority(vec![nexus.clone(), nexus], None)
        .validate()
        .expect_err("duplicate component must fail");
    assert_eq!(
        err,
        FeePaymentIntentError::DuplicateChargeKind(FeeChargeKind::Nexus)
    );
    let err = FeePaymentIntent::authority(
        vec![FeeChargeLimit::new(
            FeeChargeKind::Nexus,
            asset.clone(),
            Quantity::zero(),
        )],
        None,
    )
    .validate()
    .expect_err("zero maximum must fail");
    assert_eq!(
        err,
        FeePaymentIntentError::ZeroChargeLimit {
            kind: FeeChargeKind::Nexus,
            asset_definition_id: asset,
        }
    );
}
#[test]
fn fee_quote_selection_comparison_binds_payer_revision_and_gas() {
    let authority = FeePaymentIntent::authority(Vec::new(), NonZeroU64::new(100));
    assert!(
        authority.has_same_payer_and_gas_bound(&FeePaymentIntent::authority(
            vec![FeeChargeLimit::new(
                FeeChargeKind::Nexus,
                sample_fee_asset(),
                Quantity::from(1_u32),
            )],
            NonZeroU64::new(100),
        ))
    );
    assert!(
        !authority.has_same_payer_and_gas_bound(&FeePaymentIntent::authority(
            Vec::new(),
            NonZeroU64::new(101),
        ))
    );
    let sponsor = sample_signed_transaction().authority().clone();
    let first = FeePaymentIntent::sponsor(
        FeeSponsorProgramId::new(sponsor.clone(), "wallet".parse().expect("program name")),
        1,
        Vec::new(),
        None,
    );
    let same = FeePaymentIntent::sponsor(
        FeeSponsorProgramId::new(sponsor.clone(), "wallet".parse().expect("program name")),
        1,
        Vec::new(),
        None,
    );
    let other_revision = FeePaymentIntent::sponsor(
        FeeSponsorProgramId::new(sponsor, "wallet".parse().expect("program name")),
        2,
        Vec::new(),
        None,
    );
    assert!(first.has_same_payer_and_gas_bound(&same));
    assert!(!first.has_same_payer_and_gas_bound(&other_revision));
    assert!(!first.has_same_payer_and_gas_bound(&authority));
}
#[test]
fn legacy_fee_metadata_is_rejected_before_signing() {
    let mut metadata = Metadata::default();
    metadata.insert(
        "fee_sponsor".parse().expect("valid metadata key"),
        Json::new("legacy".to_owned()),
    );
    let err = FeePaymentIntent::validate_metadata(&metadata)
        .expect_err("legacy fee metadata must fail closed");
    assert_eq!(
        err,
        FeePaymentIntentError::LegacyMetadataKey("fee_sponsor".to_owned())
    );
}
#[test]
fn transaction_payload_validates_typed_and_legacy_fee_invariants_together() {
    let mut payload = sample_signed_transaction().payload().clone();
    payload.fee_payment = FeePaymentIntent::authority(
        vec![FeeChargeLimit::new(
            FeeChargeKind::Nexus,
            sample_fee_asset(),
            Quantity::zero(),
        )],
        None,
    );
    assert!(matches!(
        payload.validate_fee_payment_intent(),
        Err(FeePaymentIntentError::ZeroChargeLimit { .. })
    ));
    payload.fee_payment = FeePaymentIntent::authority(Vec::new(), None);
    payload.metadata.insert(
        "gas_limit".parse().expect("valid metadata key"),
        Json::new(1_u64),
    );
    assert_eq!(
        payload
            .validate_fee_payment_intent()
            .expect_err("retired metadata must fail the combined validation"),
        FeePaymentIntentError::LegacyMetadataKey("gas_limit".to_owned())
    );
}
#[test]
fn signed_transaction_exposes_signature_bound_fee_intent() {
    let transaction = sample_signed_transaction();
    assert_eq!(
        transaction.fee_payment_intent(),
        &FeePaymentIntent::authority(Vec::new(), None)
    );
    assert_eq!(
        transaction.payload().fee_payment_intent(),
        transaction.fee_payment_intent()
    );
    transaction
        .verify_signature()
        .expect("the signed fee intent must verify with the payload");
}
#[test]
fn signed_contract_invocation_arguments_and_code_hash_are_signature_bound() {
    let network_id = test_network_id(0x13);
    let public_key: iroha_crypto::PublicKey =
        "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03"
            .parse()
            .expect("public key");
    let authority = AccountId::new(public_key);
    let private_key: iroha_crypto::PrivateKey =
        "802620CCF31D85E3B32A4BEA59987CE0C78E3B8E2DB93881468AB2435FE45D5C9DCD53"
            .parse()
            .expect("private key");
    let contract_address = crate::smart_contract::ContractAddress::derive(
        &network_id,
        &authority,
        0,
        iroha_model_base::topology::DataSpaceId::UNIVERSAL,
    )
    .expect("contract address");
    let arguments = crate::transaction::executable::ContractArgumentRecord::try_new(vec![
        0x4b, 0x4f, 0x54, 0x4f,
    ])
    .expect("bounded argument record");
    let mut transaction = TransactionBuilder::new(
        network_id,
        authority,
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_executable(Executable::ContractCall(
        crate::transaction::executable::ContractInvocation {
            contract_address,
            expected_code_hash: iroha_crypto::Hash::new(b"signed-contract-code"),
            entrypoint: "call".to_owned(),
            arguments: Some(arguments),
        },
    ))
    .sign(&private_key);
    let signed_hash = transaction.hash();
    transaction
        .verify_signature()
        .expect("original signature verifies");
    let Executable::ContractCall(invocation) = &mut transaction.payload_mut().instructions else {
        panic!("contract call executable");
    };
    invocation
        .arguments
        .as_mut()
        .expect("argument record")
        .as_mut_bytes()[0] ^= 0x01;
    assert_ne!(transaction.hash(), signed_hash);
    transaction
        .verify_signature()
        .expect_err("mutating signed arguments must invalidate the signature");
    let Executable::ContractCall(invocation) = &mut transaction.payload_mut().instructions else {
        panic!("contract call executable");
    };
    invocation
        .arguments
        .as_mut()
        .expect("argument record")
        .as_mut_bytes()[0] ^= 0x01;
    transaction
        .verify_signature()
        .expect("restoring signed arguments restores the original signature");
    let Executable::ContractCall(invocation) = &mut transaction.payload_mut().instructions else {
        panic!("contract call executable");
    };
    invocation.expected_code_hash = iroha_crypto::Hash::new(b"rebound-contract-code");
    assert_ne!(transaction.hash(), signed_hash);
    transaction
        .verify_signature()
        .expect_err("mutating the expected code hash must invalidate the signature");
}
#[test]
fn verify_proof_instruction_signed_tx_versioned_roundtrip() {
    let chain = test_network_id(0x14);
    let public_key: iroha_crypto::PublicKey =
        "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03"
            .parse()
            .unwrap();
    let authority = AccountId::new(public_key);
    let private_key: iroha_crypto::PrivateKey =
        "802620CCF31D85E3B32A4BEA59987CE0C78E3B8E2DB93881468AB2435FE45D5C9DCD53"
            .parse()
            .unwrap();
    let proof_bytes = b"open-verify-envelope".to_vec();
    let mut attachment = crate::proof::ProofAttachment::new_ref(
        "halo2/ipa".into(),
        crate::proof::ProofBox::new("halo2/ipa".into(), proof_bytes.clone()),
        crate::proof::VerifyingKeyId::new("halo2/ipa", "component_verify_v1"),
    );
    attachment.envelope_hash = Some(iroha_crypto::Hash::new(&proof_bytes).into());
    let instruction: InstructionBox = crate::isi::zk::VerifyProof::new(attachment).into();
    let tx = TransactionBuilder::new(
        chain,
        authority,
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([instruction])
    .sign(&private_key);
    let bytes = tx.encode_versioned();
    let decoded = SignedTransaction::decode_all_versioned(&bytes)
        .expect("versioned VerifyProof transaction must decode");
    assert_eq!(decoded.hash(), tx.hash());
    decoded
        .verify_signature()
        .expect("decoded VerifyProof transaction signature must verify");
}
fn checked_random_keypair() -> iroha_crypto::KeyPair {
    iroha_crypto::KeyPair::try_random().expect("test fixture random key generation should succeed")
}
fn checked_random_keypair_with_algorithm(algorithm: Algorithm) -> iroha_crypto::KeyPair {
    iroha_crypto::KeyPair::try_random_with_algorithm(algorithm).unwrap_or_else(|err| {
        panic!("{algorithm:?} transaction fixture key generation should succeed: {err}")
    })
}
const SMALL_ORDER_ED25519_SIGNATURE_R: [u8; 32] = [
    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];
const NONCANONICAL_ED25519_SIGNATURE_R: [u8; 32] = [
    0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
];
fn signature_of_with_malformed_ed25519_r<T>(
    signature: &SignatureOf<T>,
    replacement_r: &[u8; 32],
) -> SignatureOf<T> {
    let mut payload = signature.payload().to_vec();
    payload[..replacement_r.len()].copy_from_slice(replacement_r);
    SignatureOf::from_signature(iroha_crypto::Signature::from_bytes(&payload))
}
#[test]
fn with_instructions_accepts_instruction_box() {
    let chain = test_network_id(0x15);
    let _domain: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
    // Pre-boxed instruction
    let instruction: InstructionBox = Register::domain(Domain::new(
        DomainId::try_new("wonderland", "universal").unwrap(),
    ))
    .into();
    let expected_id = crate::isi::Instruction::id(&*instruction);
    // Use a known matching keypair (values from project samples)
    let public_key: iroha_crypto::PublicKey =
        "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03"
            .parse()
            .unwrap();
    let private_key: iroha_crypto::PrivateKey =
        "802620CCF31D85E3B32A4BEA59987CE0C78E3B8E2DB93881468AB2435FE45D5C9DCD53"
            .parse()
            .unwrap();
    let key_pair = iroha_crypto::KeyPair::new(public_key.clone(), private_key).unwrap();
    let authority = AccountId::new(public_key.clone());
    let tx = TransactionBuilder::new(
        chain,
        authority.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions(core::iter::once(instruction))
    .with_metadata(Metadata::default())
    .sign(key_pair.private_key());
    assert_eq!(
        tx.authority().expect_single_signatory(),
        key_pair.public_key()
    );
    if let Executable::Instructions(v) = tx.instructions() {
        assert_eq!(v.len(), 1);
        // Ensure the inner instruction wasn't double-boxed by verifying its type id.
        let instruction_id = crate::isi::Instruction::id(&*v[0]);
        assert_eq!(instruction_id, expected_id);
        assert_ne!(instruction_id, "iroha_data_model::isi::InstructionBox");
    } else {
        panic!("expected Instructions variant");
    }
}
#[test]
fn with_executable_batch_preserves_mixed_item_order() {
    let key_pair = checked_random_keypair_with_algorithm(Algorithm::Ed25519);
    let authority = AccountId::new(key_pair.public_key().clone());
    let invocation = crate::transaction::executable::ContractInvocation {
        contract_address: "irohac1qyqqqqqqqqqqqqputuv64zhf0a0a4hhlqdj2lhnwuzq4xjq3qexfh"
            .parse()
            .expect("contract address"),
        expected_code_hash: Hash::new(b"builder-batch-contract"),
        entrypoint: "run".to_owned(),
        arguments: None,
    };
    let items = vec![
        crate::transaction::ExecutableBatchItem::Instruction(
            Log::new(Level::INFO, "before".into()).into(),
        ),
        crate::transaction::ExecutableBatchItem::ContractCall(invocation),
        crate::transaction::ExecutableBatchItem::Instruction(
            Log::new(Level::INFO, "after".into()).into(),
        ),
    ];
    let tx = TransactionBuilder::new(
        test_network_id(0x31),
        authority,
        FeePaymentIntent::authority(
            Vec::new(),
            Some(NonZeroU64::new(100_000).expect("nonzero gas limit")),
        ),
    )
    .with_executable_batch(items)
    .sign(key_pair.private_key());
    let Executable::Batch(items) = tx.instructions() else {
        panic!("expected mixed executable batch");
    };
    assert!(matches!(
        items[0],
        crate::transaction::ExecutableBatchItem::Instruction(_)
    ));
    assert!(matches!(
        items[1],
        crate::transaction::ExecutableBatchItem::ContractCall(_)
    ));
    assert!(matches!(
        items[2],
        crate::transaction::ExecutableBatchItem::Instruction(_)
    ));
}
#[test]
fn transaction_builder_exports_signable_payload_and_accepts_external_signature() {
    let chain = test_network_id(0x16);
    let key_pair = checked_random_keypair_with_algorithm(Algorithm::Ed25519);
    let authority = AccountId::new(key_pair.public_key().clone());
    let builder = TransactionBuilder::new(
        chain,
        authority,
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([Log::new(Level::INFO, "external signature".into())]);
    let payload_bytes = builder.encode_payload();
    let payload_hash = builder.payload_hash();
    assert_eq!(payload_hash, Hash::new(&payload_bytes));
    let payload_hash_bytes = builder.payload_hash_bytes();
    let signature = Signature::try_new(key_pair.private_key(), &payload_hash_bytes)
        .expect("checked external transaction fixture signature");
    signature
        .verify(key_pair.public_key(), &payload_hash_bytes)
        .expect("checked external transaction fixture signature verifies prehash");
    let signed = builder.build_with_signature(signature);
    assert!(signed.verify_signature().is_ok());
}
#[test]
fn prepared_external_identity_matches_signed_identity_and_binds_exact_intent() {
    let key_pair = checked_random_keypair_with_algorithm(Algorithm::Ed25519);
    let mut builder = TransactionBuilder::new(
        test_network_id(0x26),
        AccountId::new(key_pair.public_key().clone()),
        FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([Log::new(Level::INFO, "prepared external identity".into())]);
    builder.set_creation_time(Duration::from_millis(42));
    builder.set_nonce(NonZeroU32::new(7).unwrap());
    let prepared_hash = builder.hash_as_entrypoint();
    let decoded = TransactionBuilder::decode_payload(&builder.encode_payload()).unwrap();
    assert_eq!(decoded.hash_as_entrypoint(), prepared_hash);
    assert_ne!(Hash::from(prepared_hash), builder.payload_hash());
    let signed = builder.clone().sign(key_pair.private_key());
    assert_eq!(signed.hash_as_entrypoint(), prepared_hash);
    assert_eq!(
        TransactionEntrypoint::External(signed.clone()).hash(),
        prepared_hash
    );
    let mut replaced_authorization = signed;
    replaced_authorization.signature = sample_signed_transaction().signature().clone();
    assert_eq!(replaced_authorization.hash_as_entrypoint(), prepared_hash);
    let mut different_nonce = builder.clone();
    different_nonce.set_nonce(NonZeroU32::new(8).unwrap());
    assert_ne!(different_nonce.hash_as_entrypoint(), prepared_hash);
    let mut different_lifetime = builder.clone();
    different_lifetime.set_ttl(Duration::from_secs(10));
    assert_ne!(different_lifetime.hash_as_entrypoint(), prepared_hash);
    let different_action =
        builder.with_instructions([Log::new(Level::INFO, "another action".into())]);
    assert_ne!(different_action.hash_as_entrypoint(), prepared_hash);
}

#[test]
fn transaction_builder_decodes_exact_external_signing_payload() {
    let chain = test_network_id(0x17);
    let key_pair = checked_random_keypair_with_algorithm(Algorithm::Ed25519);
    let authority = AccountId::new(key_pair.public_key().clone());
    let mut builder = TransactionBuilder::new(
        chain,
        authority,
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([Log::new(Level::INFO, "decode payload".into())]);
    builder.set_creation_time(Duration::from_millis(42));
    builder.set_nonce(NonZeroU32::new(7).unwrap());
    let encoded = builder.encode_payload();
    let decoded = TransactionBuilder::decode_payload(&encoded).unwrap();
    assert_eq!(decoded.encode_payload(), encoded);
    assert_eq!(decoded.payload_hash_bytes(), builder.payload_hash_bytes());
    let mut with_trailing = encoded;
    with_trailing.push(0);
    assert!(TransactionBuilder::decode_payload(&with_trailing).is_err());
    assert!(TransactionBuilder::decode_payload(&[]).is_err());
    let canonical = builder.encode_payload();
    assert!(
        canonical[0] < 0x80,
        "fixture starts with a compact field length"
    );
    let mut overlong = Vec::with_capacity(canonical.len() + 1);
    overlong.push(canonical[0] | 0x80);
    overlong.push(0);
    overlong.extend_from_slice(&canonical[1..]);
    assert!(TransactionBuilder::decode_payload(&overlong).is_err());
}
#[test]
fn transaction_builder_payload_roundtrip_preserves_quote_to_sign_preimage() {
    let chain = test_network_id(0x18);
    let key_pair = checked_random_keypair_with_algorithm(Algorithm::Ed25519);
    let authority = AccountId::new(key_pair.public_key().clone());
    let intent = FeePaymentIntent::authority(
        vec![FeeChargeLimit::new(
            FeeChargeKind::Nexus,
            sample_fee_asset(),
            Quantity::from(10_u32),
        )],
        None,
    );
    let mut builder = TransactionBuilder::new(chain, authority, intent)
        .with_instructions([Log::new(Level::INFO, "quote then sign".into())]);
    builder.set_creation_time(Duration::from_millis(42));
    let payload = builder.into_payload().expect("valid unsigned payload");
    let expected = norito::codec::encode_adaptive(&payload);
    let rebuilt = TransactionBuilder::from_payload(payload.clone())
        .expect("quoted payload reconstructs a builder");
    assert_eq!(rebuilt.encode_payload(), expected);
    let signed = rebuilt
        .try_sign(key_pair.private_key())
        .expect("exact quoted payload signs");
    assert_eq!(signed.payload(), &payload);
    signed.verify_signature().expect("signature verifies");
}
#[test]
fn transaction_builder_from_payload_rejects_retired_fee_metadata() {
    let chain = test_network_id(0x19);
    let key_pair = checked_random_keypair_with_algorithm(Algorithm::Ed25519);
    let authority = AccountId::new(key_pair.public_key().clone());
    let mut payload = TransactionBuilder::new(
        chain,
        authority,
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .into_payload()
    .expect("default payload is structurally valid");
    payload.metadata.insert(
        "gas_limit".parse().expect("metadata key"),
        Json::new(10_u64),
    );
    let error = TransactionBuilder::from_payload(payload)
        .expect_err("retired fee metadata must fail before signing");
    assert!(matches!(
        error,
        TransactionSignatureError::InvalidFeePaymentIntent(_)
    ));
}
#[test]
fn transaction_builder_try_sign_matches_compatibility_sign() {
    let chain = test_network_id(0x1A);
    let key_pair = checked_random_keypair_with_algorithm(Algorithm::Ed25519);
    let authority = AccountId::new(key_pair.public_key().clone());
    let make_builder = || {
        let mut builder = TransactionBuilder::new(
            chain,
            authority.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(Level::INFO, "fallible tx signing".into())])
        .with_metadata(Metadata::default());
        builder.set_creation_time(Duration::from_millis(1_234));
        builder
    };
    let fallible = make_builder()
        .try_sign(key_pair.private_key())
        .expect("transaction signing should succeed");
    let compatibility = make_builder().sign(key_pair.private_key());
    assert_eq!(
        norito::to_bytes(&fallible).expect("encode fallible signed transaction"),
        norito::to_bytes(&compatibility).expect("encode compatibility signed transaction")
    );
    fallible
        .verify_signature()
        .expect("fallible signed transaction must verify");
}
#[test]
fn transaction_signature_decode_from_slice_roundtrip() {
    let chain = test_network_id(0x1B);
    let _domain: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
    let public_key: iroha_crypto::PublicKey =
        "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03"
            .parse()
            .unwrap();
    let authority = AccountId::new(public_key.clone());
    let private_key: iroha_crypto::PrivateKey =
        "802620CCF31D85E3B32A4BEA59987CE0C78E3B8E2DB93881468AB2435FE45D5C9DCD53"
            .parse()
            .unwrap();
    let signed_tx = TransactionBuilder::new(
        chain,
        authority,
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .sign(&private_key);
    let signature = signed_tx.signature().clone();
    let encoded = norito::to_bytes(&signature).expect("encode signature");
    let decoded: TransactionSignature =
        norito::core::decode_from_bytes(&encoded).expect("decode signature");
    assert_eq!(decoded, signature);
    let inner = signature.0.clone();
    let inner_encoded = norito::to_bytes(&inner).expect("encode inner signature");
    let decoded_inner: iroha_crypto::SignatureOf<TransactionPayload> =
        norito::core::decode_from_bytes(&inner_encoded).expect("decode inner signature");
    assert_eq!(decoded_inner, inner);
}
#[test]
fn transaction_signature_decode_rejects_empty_signature_material() {
    let signature = TransactionSignature(SignatureOf::from_signature(
        iroha_crypto::Signature::from_bytes(&[]),
    ));
    let encoded = norito::to_bytes(&signature).expect("encode invalid transaction signature");
    let err = norito::core::decode_from_bytes::<TransactionSignature>(&encoded)
        .expect_err("empty transaction signature must fail closed");
    let message = err.to_string();
    assert!(
        message.contains("empty") || message.contains("length mismatch"),
        "unexpected transaction signature decode error: {message}"
    );
}
#[test]
fn transaction_signature_decode_rejects_all_zero_signature_material() {
    let signature = TransactionSignature(SignatureOf::from_signature(
        iroha_crypto::Signature::from_bytes(&[0_u8; 64]),
    ));
    let encoded = norito::to_bytes(&signature).expect("encode invalid transaction signature");
    let err = norito::core::decode_from_bytes::<TransactionSignature>(&encoded)
        .expect_err("all-zero transaction signature must fail closed");
    let message = err.to_string();
    assert!(
        message.contains("all zero"),
        "unexpected transaction signature decode error: {message}"
    );
}
#[test]
fn signed_transaction_decode_from_slice_rejects_trailing_bytes() {
    let signed_tx = sample_signed_transaction();
    let mut bytes = norito::codec::encode_adaptive(&signed_tx);
    bytes.push(0);
    let err = SignedTransaction::decode_from_slice(&bytes)
        .expect_err("signed transaction slice decoder must reject trailing bytes");
    assert!(matches!(err, norito::core::Error::LengthMismatch));
}
#[test]
fn execution_step_decode_from_slice_rejects_trailing_bytes() {
    let step = ExecutionStep(ConstVec::from(vec![InstructionBox::from(Log::new(
        Level::INFO,
        "exact execution step".into(),
    ))]));
    let mut bytes = norito::codec::encode_adaptive(&step);
    bytes.push(0);
    let err = ExecutionStep::decode_from_slice(&bytes)
        .expect_err("execution step slice decoder must reject trailing bytes");
    assert!(matches!(err, norito::core::Error::LengthMismatch));
}
#[test]
fn execution_step_decode_from_slice_roundtrips_instruction_vector() {
    let step = ExecutionStep(ConstVec::from(vec![
        InstructionBox::from(Log::new(Level::INFO, "first execution step".into())),
        InstructionBox::from(Log::new(Level::WARN, "second execution step".into())),
    ]));
    let bytes = norito::codec::encode_adaptive(&step);
    let (decoded, used) =
        ExecutionStep::decode_from_slice(&bytes).expect("decode exact execution step");
    assert_eq!(used, bytes.len());
    assert_eq!(decoded, step);
}
#[test]
fn signed_transaction_versioned_decode_rejects_trailing_bytes() {
    let signed_tx = sample_signed_transaction();
    let mut bytes = signed_tx.encode_versioned();
    bytes.push(0);
    let err = SignedTransaction::decode_all_versioned(&bytes)
        .expect_err("versioned signed transaction decoder must reject trailing bytes");
    assert!(matches!(err, iroha_version::error::Error::NoritoCodec(_)));
}
#[test]
fn signed_transaction_versioned_roundtrip() {
    let signed_tx = sample_signed_transaction();
    let bytes = signed_tx.encode_versioned();
    assert_eq!(
        signed_tx
            .encode_wire_v1()
            .expect("fixed V1 transaction wire must encode"),
        bytes,
        "the inherent fixed-V1 encoder must remain byte-identical to EncodeVersioned"
    );
    let decoded = SignedTransaction::decode_all_versioned(&bytes)
        .expect("versioned signed transaction must decode");
    assert_eq!(decoded, signed_tx);
}
#[test]
fn signed_transaction_versioned_decode_rejects_instruction_type_name_alias() {
    let signed_tx = sample_signed_transaction();
    let canonical = signed_tx.encode_versioned();
    let alternate = signed_transaction_with_log_type_name_alias(&canonical);
    assert_ne!(alternate, canonical);
    let error = SignedTransaction::decode_all_versioned(&alternate)
        .expect_err("concrete Rust type names are not canonical V1 instruction wire ids");
    assert!(matches!(error, iroha_version::error::Error::NoritoCodec(_)));
}
#[test]
fn signed_transaction_fixed_v1_wire_binds_full_authorization_proof() {
    let signer_a = checked_random_keypair();
    let signer_b = checked_random_keypair();
    let policy = MultisigPolicy::new(
        1,
        vec![
            MultisigMember::new(signer_a.public_key().clone(), 1).expect("first multisig member"),
            MultisigMember::new(signer_b.public_key().clone(), 1).expect("second multisig member"),
        ],
    )
    .expect("one-of-two multisig policy");
    let builder = TransactionBuilder::new(
        test_network_id(0x32),
        AccountId::new_multisig(policy),
        FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([Log::new(Level::INFO, "authorization-sensitive wire".into())]);
    let first_proof = builder.clone().sign_multisig([signer_a.private_key()]);
    let second_proof = builder.sign_multisig([signer_b.private_key()]);
    first_proof
        .verify_signature()
        .expect("first proof is valid");
    second_proof
        .verify_signature()
        .expect("second proof is valid");
    assert_eq!(
        first_proof.hash(),
        second_proof.hash(),
        "the transaction identity intentionally hashes only the shared payload"
    );
    let wire_a = first_proof
        .encode_wire_v1()
        .expect("first fixed V1 wire must encode");
    let wire_b = second_proof
        .encode_wire_v1()
        .expect("second fixed V1 wire must encode");
    assert_eq!(wire_a, first_proof.encode_versioned());
    assert_eq!(wire_b, second_proof.encode_versioned());
    assert_ne!(
        wire_a, wire_b,
        "different valid authorization proofs must produce different complete wire bytes"
    );
}
#[test]
fn signed_transaction_versioned_decode_rejects_empty_payload_without_body_decode() {
    let err = SignedTransaction::decode_all_versioned(&[])
        .expect_err("empty signed transaction payload must be rejected");
    assert!(matches!(err, iroha_version::error::Error::NotVersioned));
    assert!(
        !err.to_string().contains("panic during decode"),
        "empty payloads should not surface as decode panics: {err}"
    );
}
#[test]
fn signed_transaction_versioned_decode_rejects_version_only_payload_without_decode_panic() {
    let err = SignedTransaction::decode_all_versioned(&[1])
        .expect_err("version-only signed transaction payload must be rejected");
    assert!(matches!(err, iroha_version::error::Error::NoritoCodec(_)));
    assert!(
        !err.to_string().contains("panic during decode"),
        "truncated payloads should not surface as decode panics: {err}"
    );
}
#[test]
fn signed_transaction_versioned_decode_rejects_unsupported_version_without_body_decode() {
    let signed_tx = sample_signed_transaction();
    let mut bytes = signed_tx.encode_versioned();
    bytes[0] = 2;
    let err = SignedTransaction::decode_all_versioned(&bytes)
        .expect_err("unsupported signed transaction version must be rejected");
    assert!(matches!(
        err,
        iroha_version::error::Error::UnsupportedVersion(_)
    ));
    assert!(
        !err.to_string().contains("panic during decode"),
        "unsupported versions should not surface as decode panics: {err}"
    );
}
#[test]
fn signed_transaction_decode_rejects_empty_signature_without_decode_panic() {
    let mut invalid_tx = sample_signed_transaction();
    invalid_tx.signature = TransactionSignature(iroha_crypto::SignatureOf::from_signature(
        iroha_crypto::Signature::from_bytes(&[]),
    ));
    let encoded = norito::to_bytes(&invalid_tx).expect("encode invalid transaction fixture");
    let err = norito::core::decode_from_bytes::<SignedTransaction>(&encoded)
        .expect_err("empty signed transaction signature must fail closed");
    let message = err.to_string();
    assert!(
        message.contains("empty") || message.contains("length mismatch"),
        "unexpected signed transaction decode error: {message}"
    );
    let err = SignedTransaction::decode_all_versioned(&invalid_tx.encode_versioned())
        .expect_err("empty signed transaction signature must be rejected");
    let message = err.to_string();
    assert!(
        message.contains("empty") || message.contains("length mismatch"),
        "unexpected versioned signed transaction decode error: {message}"
    );
    assert!(
        !message.contains("panic during decode"),
        "empty signatures should not surface as decode panics: {message}"
    );
}
#[test]
fn signed_transaction_decode_rejects_all_zero_signature_without_decode_panic() {
    let mut invalid_tx = sample_signed_transaction();
    invalid_tx.signature = TransactionSignature(iroha_crypto::SignatureOf::from_signature(
        iroha_crypto::Signature::from_bytes(&[0_u8; 64]),
    ));
    let encoded = norito::to_bytes(&invalid_tx).expect("encode invalid transaction fixture");
    let err = norito::core::decode_from_bytes::<SignedTransaction>(&encoded)
        .expect_err("all-zero signed transaction signature must fail closed");
    let message = err.to_string();
    assert!(
        message.contains("all zero"),
        "unexpected signed transaction decode error: {message}"
    );
    let err = SignedTransaction::decode_all_versioned(&invalid_tx.encode_versioned())
        .expect_err("all-zero signed transaction signature must be rejected");
    let message = err.to_string();
    assert!(
        message.contains("all zero"),
        "unexpected versioned signed transaction decode error: {message}"
    );
    assert!(
        !message.contains("panic during decode"),
        "all-zero signatures should not surface as decode panics: {message}"
    );
}
#[test]
fn signed_transaction_versioned_decode_preserves_invalid_signature_for_validation() {
    let mut invalid_tx = sample_signed_transaction();
    let mut signature = invalid_tx.signature().0.payload().to_vec();
    let last = signature
        .last_mut()
        .expect("test signature payload is non-empty");
    *last ^= 0xFF;
    invalid_tx.signature = TransactionSignature(iroha_crypto::SignatureOf::from_signature(
        iroha_crypto::Signature::try_from_bytes(&signature)
            .expect("tampered transaction signature remains structurally admissible"),
    ));
    let decoded = SignedTransaction::decode_all_versioned(&invalid_tx.encode_versioned())
        .expect("well-formed transaction with invalid signature must still decode");
    let err = decoded
        .verify_signature()
        .expect_err("invalid transaction signature must fail verification");
    assert!(matches!(err, TransactionSignatureError::CryptoError(_)));
}
#[test]
fn signed_transaction_rejects_malformed_ed25519_signature_r() {
    let tx = sample_signed_transaction();
    for (label, replacement_r) in [
        ("small-order", SMALL_ORDER_ED25519_SIGNATURE_R),
        ("noncanonical", NONCANONICAL_ED25519_SIGNATURE_R),
    ] {
        let mut invalid_tx = tx.clone();
        invalid_tx.signature = TransactionSignature(signature_of_with_malformed_ed25519_r(
            &tx.signature.0,
            &replacement_r,
        ));
        let err = invalid_tx
            .verify_signature()
            .expect_err("malformed Ed25519 transaction signature R must fail admission");
        assert_eq!(
            err,
            TransactionSignatureError::CryptoError("Signature verification failed".to_owned()),
            "{label} transaction signature R was not rejected"
        );
    }
}
#[test]
fn signed_transaction_rejects_malformed_mldsa_signature_lengths() {
    let key_pair = checked_random_keypair_with_algorithm(Algorithm::MlDsa);
    let chain = test_network_id(0x1C);
    let authority = AccountId::new(key_pair.public_key().clone());
    let tx = TransactionBuilder::new(
        chain,
        authority,
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([Log::new(Level::INFO, "mldsa tx".into())])
    .sign(key_pair.private_key());
    tx.verify_signature()
        .expect("valid ML-DSA transaction signature verifies");
    let valid_signature = tx.signature.0.payload().to_vec();
    for (label, replacement_signature) in [
        (
            "short",
            valid_signature[..valid_signature.len() - 1].to_vec(),
        ),
        ("overlong", {
            let mut payload = valid_signature.clone();
            payload.push(0x5A);
            payload
        }),
    ] {
        let mut invalid_tx = tx.clone();
        invalid_tx.signature = TransactionSignature(SignatureOf::from_signature(
            Signature::from_bytes(&replacement_signature),
        ));
        let err = invalid_tx
            .verify_signature()
            .expect_err("malformed ML-DSA transaction signature length must fail admission");
        assert!(
            matches!(err, TransactionSignatureError::CryptoError(_)),
            "{label} ML-DSA transaction signature length failed with unexpected error: {err:?}"
        );
    }
}
#[test]
fn transaction_entrypoint_versioned_decode_rejects_trailing_bytes() {
    let entrypoint = TransactionEntrypoint::from(sample_signed_transaction());
    let mut bytes = entrypoint.encode_versioned();
    bytes.push(0);
    let err = TransactionEntrypoint::decode_all_versioned(&bytes)
        .expect_err("versioned transaction entrypoint decoder must reject trailing bytes");
    assert!(matches!(err, iroha_version::error::Error::NoritoCodec(_)));
}
#[test]
fn transaction_entrypoint_versioned_roundtrip_matches_fixed_v1_wire() {
    let entrypoint = TransactionEntrypoint::from(sample_signed_transaction());
    let versioned = entrypoint.encode_versioned();
    assert_eq!(
        entrypoint
            .encode_wire_v1()
            .expect("fixed V1 entrypoint wire must encode"),
        versioned,
        "the inherent fixed-V1 entrypoint encoder must match EncodeVersioned"
    );
    let decoded = TransactionEntrypoint::decode_all_versioned(&versioned)
        .expect("versioned transaction entrypoint must decode");
    assert_eq!(decoded, entrypoint);
}
#[test]
fn transaction_entrypoint_versioned_decode_rejects_nested_instruction_type_name_alias() {
    let signed_tx = sample_signed_transaction();
    let canonical_signed = signed_tx.encode_versioned();
    let canonical_entrypoint = TransactionEntrypoint::from(signed_tx).encode_versioned();
    assert_eq!(
        external_entrypoint_wire(&canonical_signed),
        canonical_entrypoint,
        "test fixture must reproduce the canonical external-entrypoint wire"
    );
    let alternate_signed = signed_transaction_with_log_type_name_alias(&canonical_signed);
    let alternate_entrypoint = external_entrypoint_wire(&alternate_signed);
    let error = TransactionEntrypoint::decode_all_versioned(&alternate_entrypoint)
        .expect_err("nested instruction aliases are not canonical V1 entrypoint wires");
    assert!(matches!(error, iroha_version::error::Error::NoritoCodec(_)));
}
#[test]
fn signed_transaction_roundtrip_preserves_instruction_order() {
    use crate::parameter::{Parameter, system::SumeragiParameter};
    let chain = test_network_id(0x1D);
    let public_key: iroha_crypto::PublicKey =
        "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03"
            .parse()
            .unwrap();
    let authority = AccountId::new(public_key.clone());
    let private_key: iroha_crypto::PrivateKey =
        "802620CCF31D85E3B32A4BEA59987CE0C78E3B8E2DB93881468AB2435FE45D5C9DCD53"
            .parse()
            .unwrap();
    let ordered = vec![
        InstructionBox::from(crate::isi::SetParameter::new(Parameter::Sumeragi(
            SumeragiParameter::MaxClockDriftMs(667),
        ))),
        InstructionBox::from(crate::isi::SetParameter::new(Parameter::Transaction(
            crate::parameter::TransactionParameter::RequireHeightTtl(true),
        ))),
        InstructionBox::from(crate::isi::SetParameter::new(Parameter::Transaction(
            crate::parameter::TransactionParameter::RequireSequence(true),
        ))),
        InstructionBox::from(crate::isi::SetParameter::new(Parameter::Block(
            crate::parameter::BlockParameter::MaxTransactions(
                core::num::NonZeroU64::new(10_000).unwrap(),
            ),
        ))),
    ];
    let tx = TransactionBuilder::new(
        chain,
        authority,
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions(ordered.clone())
    .sign(&private_key);
    let bytes = norito::codec::encode_adaptive(&tx);
    let (decoded, used): (SignedTransaction, usize) =
        SignedTransaction::decode_from_slice(&bytes).expect("decode signed transaction");
    assert_eq!(
        used,
        bytes.len(),
        "signed transaction must consume full buffer"
    );
    let Executable::Instructions(actual) = decoded.instructions() else {
        panic!("expected instruction executable after roundtrip");
    };
    let actual = actual.iter().cloned().collect::<Vec<_>>();
    assert_eq!(
        actual, ordered,
        "instruction order must survive signed transaction roundtrip"
    );
}
#[test]
fn sign_rejects_mismatched_signatory_without_rewriting_payload() {
    let chain = test_network_id(0x1E);
    let _domain: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
    let stored_public_key: iroha_crypto::PublicKey =
        "ed012004FF5B81046DDCCF19E2E451C45DFB6F53759D4EB30FA2EFA807284D1CC33016"
            .parse()
            .unwrap();
    let private_key: iroha_crypto::PrivateKey =
        "802620CCF31D85E3B32A4BEA59987CE0C78E3B8E2DB93881468AB2435FE45D5C9DCD53"
            .parse()
            .unwrap();
    let key_pair = iroha_crypto::KeyPair::from_private_key(private_key).unwrap();
    let authority = AccountId::new(stored_public_key.clone());
    assert_ne!(authority.expect_single_signatory(), key_pair.public_key());
    let error = TransactionBuilder::new(
        chain,
        authority.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .try_sign(key_pair.private_key())
    .expect_err("signing must preserve and reject a mismatched authority");
    assert_eq!(error, TransactionSignatureError::AuthorityKeyMismatch);
    assert_eq!(authority.expect_single_signatory(), &stored_public_key);
}
#[test]
fn entrypoint_hashes_match_direct_encoding() {
    let chain = test_network_id(0x1F);
    let _domain: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
    let public_key: iroha_crypto::PublicKey =
        "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03"
            .parse()
            .unwrap();
    let authority = AccountId::new(public_key);
    let private_key: iroha_crypto::PrivateKey =
        "802620CCF31D85E3B32A4BEA59987CE0C78E3B8E2DB93881468AB2435FE45D5C9DCD53"
            .parse()
            .unwrap();
    let tx = TransactionBuilder::new(
        chain,
        authority.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .sign(&private_key);
    let entry = TransactionEntrypoint::External(tx.clone());
    assert_ne!(
        HashOf::new(&entry),
        entry.hash(),
        "raw envelope hashing must not define external transaction identity"
    );
    assert_eq!(tx.hash_as_entrypoint(), entry.hash());
    assert_eq!(Hash::from(tx.hash()), Hash::from(tx.hash_as_entrypoint()));
    assert!(
        TransactionEntrypoint::decode_all(&mut [3_u8, 0, 0, 0].as_slice()).is_err(),
        "retired synthetic Time tag must fail network decoding"
    );
}

#[test]
fn transaction_result_hash_matches_inner() {
    let ok_inner = DataTriggerSequence::default();
    let result_ok = TransactionResult::new(Ok(ok_inner.clone()));
    assert_eq!(HashOf::new(&result_ok), result_ok.hash());
    assert_eq!(
        result_ok.hash(),
        TransactionResult::hash_from_inner(&Ok(ok_inner))
    );
    let err_reason = error::TransactionRejectionReason::LimitCheck(error::TransactionLimitError {
        reason: "limit exceeded".into(),
    });
    let err_inner: TransactionResultInner = Err(err_reason.clone());
    let result_err = TransactionResult::new(err_inner.clone());
    assert_eq!(HashOf::new(&result_err), result_err.hash());
    assert_eq!(
        result_err.hash(),
        TransactionResult::hash_from_inner(&err_inner)
    );
}
#[path = "signed/sealed_commitment_tests.rs"]
mod sealed_commitment_tests;
include!("signed/genesis_domain_test.rs");
include!("signed/result_json_test.rs");

#[test]
fn native_transaction_payload_has_nine_fields_and_rejects_retired_admission_slots() {
    let payload = sample_signed_transaction().payload().clone();
    let canonical = payload.encode();
    let fields = split_default_norito_fields(&canonical, 9);
    let decoded = TransactionPayload::decode_all(&mut canonical.as_slice())
        .expect("native payload roundtrip");
    assert_eq!(decoded, payload);
    for retired_tag in [0_u32, 1_u32] {
        let mut old_fields = fields.clone();
        old_fields.insert(7, retired_tag.to_le_bytes().to_vec());
        let old_wire = encode_default_norito_fields(&old_fields);
        assert!(
            TransactionPayload::decode_all(&mut old_wire.as_slice()).is_err(),
            "retired admission slot must never be decoded as the native layout"
        );
    }
}

#[test]
#[ignore = "explicit canonical transaction-intent KAT capture after an intentional wire change"]
fn capture_current_privacy_transaction_intent_kats() {
    for (name, payload) in [
        ("privacy", finalized_privacy_payload()),
        ("vega", draft_vega_privacy_payload()),
    ] {
        let projection = payload
            .privacy_transaction_intent_projection_bytes_v1()
            .unwrap();
        let digest = payload.privacy_transaction_intent_digest_v1().unwrap();
        println!(
            "PRIVACY_INTENT_KAT={name}\t{}\t{}",
            projection.len(),
            hex::encode(digest.as_bytes())
        );
    }
}

#[test]
fn entrypoint_identity_is_memoized_without_reaching_wire_or_equality() {
    let fresh = |tx: &SignedTransaction| {
        HashOf::<TransactionEntrypoint>::from_untyped_unchecked(Hash::from(HashOf::new(
            &ExternalEntrypointRef(tx.payload()),
        )))
    };
    let signed = sample_signed_transaction();
    let wire_before = norito::encode_canonical(&signed).expect("encode signed transaction");
    let expected = fresh(&signed);
    assert!(signed.entrypoint_hash.0.get().is_none());
    assert_eq!(signed.hash_as_entrypoint(), expected);
    assert_eq!(signed.entrypoint_hash.0.get(), Some(&expected));
    assert_eq!(signed.try_hash_as_entrypoint().unwrap(), expected);
    assert_eq!(
        norito::encode_canonical(&signed).expect("encode memoized transaction"),
        wire_before,
        "the memo never reaches the wire"
    );
    let decoded: SignedTransaction =
        norito::decode_canonical(&wire_before).expect("decode signed transaction");
    assert!(decoded.entrypoint_hash.0.get().is_none());
    assert_eq!(decoded, signed, "equality ignores the memo");
    assert_eq!(decoded.hash_as_entrypoint(), expected);
    assert_eq!(format!("{decoded:?}"), format!("{signed:?}"));
    let cloned = signed.clone();
    assert_eq!(cloned.entrypoint_hash.0.get(), Some(&expected));
    let other = iroha_crypto::KeyPair::try_from_seed(vec![7; 32], iroha_crypto::Algorithm::Ed25519)
        .expect("fixture key");
    let reattributed = cloned.with_authority(AccountId::new(other.public_key().clone()));
    assert!(
        reattributed.entrypoint_hash.0.get().is_none(),
        "replacing payload content resets the memo"
    );
    assert_eq!(reattributed.hash_as_entrypoint(), fresh(&reattributed));
    assert_ne!(reattributed.hash_as_entrypoint(), expected);
}
