//! Complete canonical envelope measurements for the fixed first-release proof ceiling.
//!
//! These are transport-shape fixtures, not valid proofs or privacy admission evidence.

use std::{num::NonZeroU64, time::Duration};

use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::{
    account::{AccountId, MultisigMember, MultisigPolicy},
    isi::privacy::SubmitPrivacyProofV1,
    parameter::Parameters,
    privacy::{
        IrohaZkAmsProofV1, PrivacyConsensusLimitsV1, PrivacyProofBytesV1, PrivacyProofV1,
        PrivacyStatementV1, PrivacyStatementValidationError, TAIRA_PRIVACY_MAX_ACTION_BYTES_V1,
        TAIRA_PRIVACY_MAX_PROOF_BYTES_PER_ACTION_V1,
        TAIRA_PRIVACY_PROOF_ENVELOPE_METADATA_ALLOWANCE_BYTES_V1,
        privacy_exact12_fixture_bundle_v1,
    },
    transaction::{FeePaymentIntent, SignedTransaction, TransactionBuilder},
};

/// Both closed ZK-AMS action variants add the same nested proof tag and field length.
#[test]
fn zk_ams_action_variants_have_the_same_proof_frame_size() {
    let bytes = PrivacyProofBytesV1::new(vec![
        0x5a;
        TAIRA_PRIVACY_MAX_PROOF_BYTES_PER_ACTION_V1 as usize
    ]);
    let batch = PrivacyProofV1::IrohaZkAmsV1(
        IrohaZkAmsProofV1::MaskedRelaxedSpartanBatchAdmission(bytes.clone()),
    );
    let provision =
        PrivacyProofV1::IrohaZkAmsV1(IrohaZkAmsProofV1::Ristretto255LsagProvisionAccount(bytes));
    assert_eq!(
        norito::canonical_frame_len(&batch).expect("batch proof frame"),
        norito::canonical_frame_len(&provision).expect("provision proof frame"),
    );
}

/// Measure every signature algorithm with sixteen members and sixteen signatures.
///
/// This is not the maximum legal authority or metadata: account policies can contain more
/// non-signing members, and the complete transaction cap independently bounds all such context.
#[test]
fn ceiling_proof_complete_envelopes_fit_the_fixed_transaction_cap() {
    let parameters = Parameters::default();
    let proof_bytes = TAIRA_PRIVACY_MAX_PROOF_BYTES_PER_ACTION_V1 as usize;
    assert_eq!(proof_bytes, 9_437_184);
    let transaction_cap = usize::try_from(parameters.transaction().max_tx_bytes().get())
        .expect("transaction ceiling fits usize");
    assert_eq!(transaction_cap, 10_485_760);
    let algorithms: Vec<_> = (0..=u8::MAX)
        .filter_map(|tag| Algorithm::try_from(tag).ok())
        .collect();
    let largest = *algorithms
        .iter()
        .max_by_key(|algorithm| algorithm.signature_payload_len())
        .expect("at least one supported signature algorithm");
    assert_eq!(largest, Algorithm::MlDsa);
    let count = usize::try_from(parameters.transaction().max_signatures().get())
        .expect("signature ceiling fits usize");
    let fixtures = privacy_exact12_fixture_bundle_v1().expect("typed fixtures");
    assert_eq!(fixtures.rows.len(), 12);
    for algorithm in algorithms {
        let keys: Vec<_> = (0..count)
            .map(|index| {
                KeyPair::from_seed(
                    vec![u8::try_from(index + 1).expect("sixteen distinct signer seeds"); 32],
                    algorithm,
                )
            })
            .collect();
        let policy = MultisigPolicy::new(
            u16::try_from(count).expect("sixteen-member signature threshold"),
            keys.iter()
                .map(|key| MultisigMember::new(key.public_key().clone(), 1).expect("member"))
                .collect(),
        )
        .expect("sixteen-member signature policy");
        let authority = AccountId::new_multisig(policy);
        for row in &fixtures.rows {
            let instruction: SubmitPrivacyProofV1 =
                norito::decode_canonical(&row.submit_proof_instruction_norito)
                    .expect("fixture instruction");
            let mut envelope = instruction.envelope().clone();
            envelope.proof.bytes_mut().bytes = vec![0x5a; proof_bytes];
            let statement_bytes = norito::canonical_frame_len(&envelope.statement)
                .expect("canonical statement frame");
            let envelope_bytes =
                norito::canonical_frame_len(&envelope).expect("canonical envelope frame");
            // This declared allowance covers metadata and framing, never extra proof bytes.
            // Also account for the statement field prefix growing to the full 256 KiB budget,
            // even when this protocol's valid statement shapes cannot reach that ceiling.
            let flags = norito::core::default_encode_flags();
            let maximum_statement_bytes = PrivacyConsensusLimitsV1::taira_default()
                .max_statement_and_encrypted_output_bytes_per_transaction
                as usize;
            let statement_payload_bytes = {
                let _canonical = norito::core::DecodeFlagsGuard::enter(flags);
                norito::core::encoded_payload_len(&envelope.statement)
                    .expect("canonical statement payload")
            };
            let statement_header_bytes = statement_bytes - statement_payload_bytes;
            let statement_prefix_growth =
                norito::core::len_prefix_len_with_flags(
                    maximum_statement_bytes - statement_header_bytes,
                    flags,
                ) - norito::core::len_prefix_len_with_flags(statement_payload_bytes, flags);
            let metadata_bytes = envelope_bytes - proof_bytes - statement_bytes;
            assert!(
                metadata_bytes + statement_prefix_growth
                    <= TAIRA_PRIVACY_PROOF_ENVELOPE_METADATA_ALLOWANCE_BYTES_V1 as usize
            );
            assert!(envelope_bytes <= TAIRA_PRIVACY_MAX_ACTION_BYTES_V1 as usize);
            envelope
                .validate_with_limits(&PrivacyConsensusLimitsV1::taira_default())
                .expect("intrinsic envelope bounds and bindings, not native proof validity");
            let instruction = SubmitPrivacyProofV1::new(envelope);
            let action_bytes = norito::encode_canonical(&instruction)
                .expect("complete action frame")
                .len();
            assert_eq!(
                action_bytes - envelope_bytes,
                4,
                "one canonical compact V1 field length"
            );
            let mut builder = TransactionBuilder::new(
                instruction.envelope().statement.context().network_id,
                authority.clone(),
                FeePaymentIntent::authority(Vec::new(), NonZeroU64::new(10_000)),
            )
            .with_instructions([instruction]);
            builder.set_creation_time(Duration::from_millis(1_725_000_000_000));
            let signed = builder
                .try_sign_multisig(keys.iter().map(KeyPair::private_key))
                .expect("sign maximum bundle");
            signed
                .verify_signature()
                .expect("actual signature verification");
            assert_eq!(signed.signature_count(), count);
            let canonical =
                norito::encode_canonical(&signed).expect("canonical signed transaction");
            assert!(canonical.len() <= transaction_cap, "{:?}", row.protocol_id);
            let decoded: SignedTransaction =
                norito::decode_canonical(&canonical).expect("canonical transaction roundtrip");
            assert_eq!(decoded, signed);
            println!(
                "MAXIMUM_PROOF_ENVELOPE protocol={:?} algorithm={} signatures={} proof={} action={} transaction={} remaining={}",
                row.protocol_id,
                algorithm.as_static_str(),
                count,
                proof_bytes,
                action_bytes,
                canonical.len(),
                transaction_cap - canonical.len(),
            );
            println!(
                "PROOF_CONTEXT_FRAMING protocol={:?} statement={} envelope={} submit={} wrapper={}",
                row.protocol_id,
                statement_bytes,
                envelope_bytes,
                action_bytes,
                action_bytes - envelope_bytes,
            );
            assert!(action_bytes <= SubmitPrivacyProofV1::canonical_frame_byte_limit_v1());
        }
    }
}

/// Saturate the intrinsically validated statement frame, including its encrypted output.
///
/// PQ-MASP's typed statement validator permits a nonempty, nonzero ciphertext up to the
/// aggregate statement cap. This synthetic transport shape is not a native-valid ciphertext
/// or a valid proof; native proving and admission remain separate qualification boundaries.
#[test]
fn maximum_statement_and_proof_fit_with_sixteen_mldsa_signatures() {
    let limits = PrivacyConsensusLimitsV1::taira_default();
    let statement_cap = limits.max_statement_and_encrypted_output_bytes_per_transaction as usize;
    assert_eq!(statement_cap, 262_144);
    let fixtures = privacy_exact12_fixture_bundle_v1().expect("typed fixtures");
    let mut envelope = fixtures
        .rows
        .iter()
        .find_map(|row| {
            let instruction: SubmitPrivacyProofV1 =
                norito::decode_canonical(&row.submit_proof_instruction_norito).expect("fixture");
            matches!(
                instruction.envelope().statement,
                PrivacyStatementV1::PqMaspStarkV1(_)
            )
            .then(|| instruction.envelope().clone())
        })
        .expect("PQ-MASP fixture");
    let PrivacyStatementV1::PqMaspStarkV1(statement) = &mut envelope.statement else {
        unreachable!("selected exact statement variant")
    };
    statement.encrypted_outputs[0].ciphertext = vec![0x5a; statement_cap];
    let oversized = norito::canonical_frame_len(&envelope.statement).expect("statement frame");
    let ciphertext_len = statement_cap - (oversized - statement_cap);
    let PrivacyStatementV1::PqMaspStarkV1(statement) = &mut envelope.statement else {
        unreachable!("selected exact statement variant")
    };
    statement.encrypted_outputs[0]
        .ciphertext
        .truncate(ciphertext_len);
    assert_eq!(
        norito::canonical_frame_len(&envelope.statement).unwrap(),
        statement_cap
    );
    assert_eq!(envelope.statement.validate(&limits), Ok(()));

    let mut one_over = envelope.statement.clone();
    let PrivacyStatementV1::PqMaspStarkV1(statement) = &mut one_over else {
        unreachable!("selected exact statement variant")
    };
    statement.encrypted_outputs[0].ciphertext.push(0x5a);
    assert_eq!(
        norito::canonical_frame_len(&one_over).unwrap(),
        statement_cap + 1
    );
    assert_eq!(
        one_over.validate(&limits),
        Err(
            PrivacyStatementValidationError::StatementAndEncryptedOutputsTooLarge {
                bytes: statement_cap as u64 + 1,
                max: u32::try_from(statement_cap).expect("statement ceiling fits u32"),
            }
        )
    );

    envelope.statement_digest = envelope
        .statement
        .digest()
        .expect("updated statement digest");
    envelope.proof.bytes_mut().bytes = vec![0x5a; limits.max_proof_bytes_per_action as usize];
    let envelope_bytes = norito::canonical_frame_len(&envelope).expect("envelope frame");
    assert!(envelope_bytes <= TAIRA_PRIVACY_MAX_ACTION_BYTES_V1 as usize);
    envelope
        .validate_with_limits(&limits)
        .expect("intrinsic maximum envelope, not native proof validity");
    let instruction = SubmitPrivacyProofV1::new(envelope);
    let submit_bytes = norito::canonical_frame_len(&instruction).expect("submit frame");
    assert_eq!(submit_bytes - envelope_bytes, 4);
    let parameters = Parameters::default();
    let count = usize::try_from(parameters.transaction().max_signatures().get())
        .expect("signature ceiling fits usize");
    assert_eq!(count, 16);
    let keys: Vec<_> = (0..count)
        .map(|index| {
            KeyPair::from_seed(
                vec![u8::try_from(index + 1).expect("sixteen distinct signer seeds"); 32],
                Algorithm::MlDsa,
            )
        })
        .collect();
    let policy = MultisigPolicy::new(
        u16::try_from(count).expect("sixteen-member signature threshold"),
        keys.iter()
            .map(|key| MultisigMember::new(key.public_key().clone(), 1).expect("member"))
            .collect(),
    )
    .expect("sixteen-member policy");
    let mut builder = TransactionBuilder::new(
        instruction.envelope().statement.context().network_id,
        AccountId::new_multisig(policy),
        FeePaymentIntent::authority(Vec::new(), NonZeroU64::new(10_000)),
    )
    .with_instructions([instruction]);
    builder.set_creation_time(Duration::from_millis(1_725_000_000_000));
    let signed = builder
        .try_sign_multisig(keys.iter().map(KeyPair::private_key))
        .expect("sign sixteen-member bundle");
    signed
        .verify_signature()
        .expect("actual signature verification");
    let canonical = norito::encode_canonical(&signed).expect("signed transaction frame");
    assert_eq!(signed.signature_count(), count);
    let decoded: SignedTransaction = norito::decode_canonical(&canonical).expect("roundtrip");
    assert_eq!(decoded, signed);
    let transaction_cap = usize::try_from(parameters.transaction().max_tx_bytes().get())
        .expect("transaction ceiling fits usize");
    assert!(canonical.len() <= transaction_cap);
    println!(
        "MAXIMUM_STATEMENT_ENVELOPE statement={} ciphertext={} proof={} envelope={} submit={} wrapper={} transaction={} remaining={} authority_members={} signatures={}",
        statement_cap,
        ciphertext_len,
        limits.max_proof_bytes_per_action,
        envelope_bytes,
        submit_bytes,
        submit_bytes - envelope_bytes,
        canonical.len(),
        transaction_cap - canonical.len(),
        count,
        count,
    );
}
