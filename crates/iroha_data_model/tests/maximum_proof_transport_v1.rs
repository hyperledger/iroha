//! Complete canonical envelope measurements for the fixed first-release proof ceiling.
//!
//! The 9,437,184-byte proof ceiling and the 10,485,760-byte signed-transaction cap are the
//! first-release defaults. The remaining 1 MiB must hold the required context of a ceiling-proof
//! transaction: up to the committed `max_signatures` signers of any supported algorithm with
//! their multisig authority, the whole statement including its encrypted outputs (at most
//! 262,144 bytes), the fixed 512-byte envelope allowance, the authority fee intent with its
//! Nexus and `PipelineGas` charge limits at their largest amounts and an executable gas bound,
//! the lifetime and nonce, the `tx_sequence` and `expires_at_height` metadata that the governed
//! `require_sequence` and `require_height_ttl` flags make mandatory (both at `u64::MAX`, so the
//! guarantee holds whatever the flags say), and the Submit and transaction framing. Larger
//! multisig member sets and other transaction metadata are not required context; they share the
//! same transaction cap with no promise that a ceiling proof still fits. Committed parameters
//! keep this guarantee:
//! coherence (`validate_privacy_action_context`) refuses any transaction cap, signature cap or
//! privacy profile under which one maximal action and this context no longer fit, using the
//! per-signer and framing bytes that `maximal_action_context_constants_are_the_measured_worst_case`
//! derives here from actual signed transactions. When last measured, the largest required context
//! at the defaults (the full statement with sixteen ML-DSA signers and the largest admissible fee
//! intent and the flag-required metadata) made a 9,938,306-byte transaction, 547,454 bytes below
//! the cap. The tests print every
//! measurement (`MAXIMUM_PROOF_ENVELOPE`, `MAXIMUM_STATEMENT_ENVELOPE`, `ACTION_CONTEXT`) and
//! assert the caps and the derived constants.
//!
//! These are transport-shape fixtures: synthetic proof bytes and the current Exact12 fixture
//! statements. They are not valid proofs, privacy admission evidence or the widths of any native
//! proof catalog; a change to a native statement width changes the measured transport sizes,
//! never the fixed caps.

use std::{
    num::{NonZeroU32, NonZeroU64},
    time::Duration,
};

use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::{
    account::{AccountId, MultisigMember, MultisigPolicy},
    asset::AssetDefinitionId,
    isi::privacy::SubmitPrivacyProofV1,
    parameter::{
        Parameters,
        system::resource_coherence::{
            MAX_TRANSACTION_SIGNER_BYTES, MAXIMAL_ACTION_TRANSACTION_FRAMING_BYTES,
            maximal_action_transaction_bytes,
        },
    },
    privacy::{
        IrohaZkAmsProofV1, PrivacyConsensusLimitsV1, PrivacyProofBytesV1, PrivacyProofEnvelopeV1,
        PrivacyProofV1, PrivacyStatementV1, PrivacyStatementValidationError,
        TAIRA_PRIVACY_MAX_ACTION_BYTES_V1, TAIRA_PRIVACY_MAX_PROOF_BYTES_PER_ACTION_V1,
        TAIRA_PRIVACY_PROOF_ENVELOPE_METADATA_ALLOWANCE_BYTES_V1,
        privacy_exact12_fixture_bundle_v1,
    },
    transaction::{
        FeeChargeKind, FeeChargeLimit, FeePaymentIntent, SignedTransaction, TransactionBuilder,
    },
};
use iroha_model_base::metadata::Metadata;
use iroha_primitives::{json::Json, numeric::Quantity};

/// The metadata that the governed `require_sequence` and `require_height_ttl` admission flags
/// make mandatory, at its largest encoding: `tx_sequence` and `expires_at_height` at `u64::MAX`.
fn flag_required_metadata() -> Metadata {
    let mut metadata = Metadata::default();
    for key in ["tx_sequence", "expires_at_height"] {
        metadata.insert(key.parse().expect("metadata key"), Json::new(u64::MAX));
    }
    metadata
}

/// The flag-required entries read back exactly as admission parses them.
fn assert_flag_required_metadata(signed: &SignedTransaction) {
    assert_eq!(signed.tx_sequence().expect("u64 sequence"), Some(u64::MAX));
    assert_eq!(
        signed.expires_at_height().expect("u64 height"),
        Some(u64::MAX)
    );
}

/// The admissible authority fee intent with its largest encoding: the Nexus and `PipelineGas`
/// charge limits admission requires, in canonical order, each at the largest representable
/// amount (a limit at or above the charged bound is admissible), and a gas bound. Asset
/// definition identifiers and the gas bound have one fixed width.
fn maximal_fee_intent() -> FeePaymentIntent {
    let asset = AssetDefinitionId::from_uuid_bytes([
        0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x4a, 0x5a, 0x9a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
        0x5a,
    ])
    .expect("canonical UUIDv4 asset definition");
    // The largest mantissa a quantity admits: 512-bit two's complement, non-negative.
    let amount: Quantity = (num_bigint_max_mantissa())
        .parse()
        .expect("largest admissible quantity");
    let intent = FeePaymentIntent::authority(
        vec![
            FeeChargeLimit::new(FeeChargeKind::Nexus, asset.clone(), amount.clone()),
            FeeChargeLimit::new(FeeChargeKind::PipelineGas, asset, amount),
        ],
        Some(NonZeroU64::MAX),
    );
    intent
        .validate()
        .expect("structurally admissible fee intent");
    intent
}

/// The longest lifetime admission accepts under the committed defaults. Lifetimes have one
/// fixed width, so every admissible lifetime encodes to the same length.
fn admissible_ttl() -> Duration {
    Duration::from_millis(
        Parameters::default()
            .transaction()
            .max_time_to_live_ms()
            .get(),
    )
}

/// Decimal text of `2^511 - 1`, the largest non-negative 512-bit two's-complement mantissa.
fn num_bigint_max_mantissa() -> String {
    // Repeated doubling in decimal keeps this independent of a big-integer dependency.
    let mut digits = vec![1_u8];
    for _ in 0..511 {
        let mut carry = 0;
        for digit in &mut digits {
            let doubled = *digit * 2 + carry;
            *digit = doubled % 10;
            carry = doubled / 10;
        }
        if carry > 0 {
            digits.push(carry);
        }
    }
    // Subtract one: `2^511` ends in 8, never 0.
    digits[0] -= 1;
    digits
        .iter()
        .rev()
        .map(|digit| char::from(b'0' + digit))
        .collect()
}

/// A complete signed transaction carrying `envelope` from `count` signers of `algorithm`,
/// with the maximal admissible fee intent, lifetime and nonce.
fn signed_with_required_context(
    envelope: &PrivacyProofEnvelopeV1,
    algorithm: Algorithm,
    count: usize,
) -> SignedTransaction {
    let keys: Vec<_> = (0..count)
        .map(|index| {
            let seed = u16::try_from(index + 1).expect("signer seed");
            KeyPair::from_seed(
                [seed.to_le_bytes().as_slice(), &[0x7a; 30]].concat(),
                algorithm,
            )
        })
        .collect();
    let policy = MultisigPolicy::new(
        u16::try_from(count).expect("signature threshold"),
        keys.iter()
            .map(|key| MultisigMember::new(key.public_key().clone(), 1).expect("member"))
            .collect(),
    )
    .expect("signature policy");
    let instruction = SubmitPrivacyProofV1::new(envelope.clone());
    let mut builder = TransactionBuilder::new(
        instruction.envelope().statement.context().network_id,
        AccountId::new_multisig(policy),
        maximal_fee_intent(),
    )
    .with_instructions([instruction])
    .with_metadata(flag_required_metadata());
    builder.set_creation_time(Duration::from_millis(1_725_000_000_000));
    builder.set_nonce(NonZeroU32::MAX);
    builder.set_ttl(admissible_ttl());
    let signed = builder
        .try_sign_multisig(keys.iter().map(KeyPair::private_key))
        .expect("sign the measured transaction");
    signed
        .verify_signature()
        .expect("actual signature verification");
    assert_eq!(signed.signature_count(), count);
    assert_flag_required_metadata(&signed);
    signed
}

/// A complete signed transaction carrying `envelope` from a single-key authority of `algorithm`,
/// with the maximal admissible fee intent, lifetime and nonce.
fn signed_by_single_key(
    envelope: &PrivacyProofEnvelopeV1,
    algorithm: Algorithm,
) -> SignedTransaction {
    let key = KeyPair::from_seed(
        [0x01, 0x00].iter().copied().chain([0x7a; 30]).collect(),
        algorithm,
    );
    let instruction = SubmitPrivacyProofV1::new(envelope.clone());
    let mut builder = TransactionBuilder::new(
        instruction.envelope().statement.context().network_id,
        AccountId::new(key.public_key().clone()),
        maximal_fee_intent(),
    )
    .with_instructions([instruction])
    .with_metadata(flag_required_metadata());
    builder.set_creation_time(Duration::from_millis(1_725_000_000_000));
    builder.set_nonce(NonZeroU32::MAX);
    builder.set_ttl(admissible_ttl());
    let signed = builder
        .try_sign(key.private_key())
        .expect("sign the single-key transaction");
    signed
        .verify_signature()
        .expect("actual signature verification");
    assert_eq!(signed.signature_count(), 1);
    assert_flag_required_metadata(&signed);
    signed
}

/// The PQ-MASP fixture envelope with its statement saturated to the aggregate statement cap.
fn full_statement_envelope(limits: &PrivacyConsensusLimitsV1) -> PrivacyProofEnvelopeV1 {
    let statement_cap = limits.max_statement_and_encrypted_output_bytes_per_transaction as usize;
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
    envelope.statement_digest = envelope
        .statement
        .digest()
        .expect("updated statement digest");
    envelope
}

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
                maximal_fee_intent(),
            )
            .with_instructions([instruction])
            .with_metadata(flag_required_metadata());
            builder.set_creation_time(Duration::from_millis(1_725_000_000_000));
            builder.set_nonce(NonZeroU32::MAX);
            builder.set_ttl(admissible_ttl());
            let signed = builder
                .try_sign_multisig(keys.iter().map(KeyPair::private_key))
                .expect("sign maximum bundle");
            signed
                .verify_signature()
                .expect("actual signature verification");
            assert_eq!(signed.signature_count(), count);
            assert_flag_required_metadata(&signed);
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
        maximal_fee_intent(),
    )
    .with_instructions([instruction])
    .with_metadata(flag_required_metadata());
    builder.set_creation_time(Duration::from_millis(1_725_000_000_000));
    builder.set_nonce(NonZeroU32::MAX);
    builder.set_ttl(admissible_ttl());
    let signed = builder
        .try_sign_multisig(keys.iter().map(KeyPair::private_key))
        .expect("sign sixteen-member bundle");
    signed
        .verify_signature()
        .expect("actual signature verification");
    let canonical = norito::encode_canonical(&signed).expect("signed transaction frame");
    assert_eq!(signed.signature_count(), count);
    assert_flag_required_metadata(&signed);
    let decoded: SignedTransaction = norito::decode_canonical(&canonical).expect("roundtrip");
    assert_eq!(decoded, signed);
    let transaction_cap = usize::try_from(parameters.transaction().max_tx_bytes().get())
        .expect("transaction ceiling fits usize");
    assert!(canonical.len() <= transaction_cap);
    // The governed relation's bound covers this transaction at the committed signature cap.
    let bound = maximal_action_transaction_bytes(
        limits.max_action_bytes,
        parameters.transaction().max_signatures(),
    )
    .expect("representable required context");
    assert!(
        u64::try_from(canonical.len()).unwrap() <= bound
            && bound <= u64::try_from(transaction_cap).unwrap(),
        "{} <= {bound} <= {transaction_cap}",
        canonical.len()
    );
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

/// Derive the per-signer and framing terms of the required-context relation from actual signed
/// transactions of every supported algorithm, and check its bound against them.
///
/// `R(algorithm, n)` is a transaction's canonical length beyond its action envelope; every
/// measured transaction carries the maximal admissible fee intent, lifetime and nonce and the
/// flag-required `tx_sequence` and `expires_at_height` metadata at `u64::MAX`. At the
/// ceiling size (four-byte outer length prefixes, the largest a transaction within the protocol
/// transport limit has) the largest one-signer remainder and the largest per-signer step pin
/// `MAXIMAL_ACTION_TRANSACTION_FRAMING_BYTES + MAX_TRANSACTION_SIGNER_BYTES` and
/// `MAX_TRANSACTION_SIGNER_BYTES` exactly. Every measured remainder, also across signer counts
/// whose vector length prefixes grow, stays within `framing + n * signer`. A single-key authority
/// carries one signature and no bundle, while a one-member multisig transaction repeats its
/// bundle entry as the primary signature, so the single-key remainder stays within the one-signer
/// bound too.
#[test]
fn maximal_action_context_constants_are_the_measured_worst_case() {
    let limits = PrivacyConsensusLimitsV1::taira_default();
    let mut ceiling = full_statement_envelope(&limits);
    ceiling.proof.bytes_mut().bytes = vec![0x5a; limits.max_proof_bytes_per_action as usize];
    let mut small = ceiling.clone();
    small.proof.bytes_mut().bytes = vec![0x5a];
    let remainder = |envelope: &PrivacyProofEnvelopeV1, algorithm: Algorithm, count: usize| {
        let signed = signed_with_required_context(envelope, algorithm, count);
        let total = norito::encode_canonical(&signed)
            .expect("canonical transaction")
            .len();
        u64::try_from(total - norito::canonical_frame_len(envelope).expect("envelope frame"))
            .expect("remainder fits u64")
    };
    let signer = MAX_TRANSACTION_SIGNER_BYTES;
    let framing = MAXIMAL_ACTION_TRANSACTION_FRAMING_BYTES;
    let algorithms: Vec<_> = (0..=u8::MAX)
        .filter_map(|tag| Algorithm::try_from(tag).ok())
        .collect();
    let (mut largest_step, mut largest_first) = (0, 0);
    for &algorithm in &algorithms {
        let first = remainder(&ceiling, algorithm, 1);
        let second = remainder(&ceiling, algorithm, 2);
        largest_step = largest_step.max(second - first);
        largest_first = largest_first.max(first);
        let single = {
            let transaction = signed_by_single_key(&ceiling, algorithm);
            let total = norito::encode_canonical(&transaction)
                .expect("canonical transaction")
                .len();
            u64::try_from(total - norito::canonical_frame_len(&ceiling).expect("envelope frame"))
                .expect("remainder fits u64")
        };
        assert!(
            single <= framing + signer,
            "{algorithm} single-key authority: {single} context bytes"
        );
        println!(
            "ACTION_CONTEXT algorithm={} one_signer={first} step={} single_key={single}",
            algorithm.as_static_str(),
            second - first
        );
        // Consecutive counts with the small envelope; ML-DSA also crosses the larger
        // length-prefix boundaries of its signer vectors and of the whole transaction.
        let counts: Vec<usize> = if algorithm == Algorithm::MlDsa {
            (1..=6).chain([16, 17, 64, 128, 200]).collect()
        } else {
            (1..=6).chain([16, 17]).collect()
        };
        let mut previous: Option<(usize, u64)> = None;
        for count in counts {
            let measured = remainder(&small, algorithm, count);
            assert!(
                measured <= framing + u64::try_from(count).unwrap() * signer,
                "{algorithm} with {count} signers: {measured} context bytes"
            );
            if let Some((last, before)) = previous
                && last + 1 == count
            {
                largest_step = largest_step.max(measured - before);
            }
            previous = Some((count, measured));
        }
    }
    assert_eq!(largest_step, signer, "the measured worst per-signer bytes");
    assert_eq!(
        largest_first - signer,
        framing,
        "the measured worst framing bytes"
    );
    // The relation at the committed defaults: one maximal action with sixteen signers fits.
    let defaults = Parameters::default();
    let required = maximal_action_transaction_bytes(
        limits.max_action_bytes,
        defaults.transaction().max_signatures(),
    )
    .unwrap();
    assert!(required <= defaults.transaction().max_tx_bytes().get());
    println!(
        "ACTION_CONTEXT signer={signer} framing={framing} required_at_defaults={required} transaction_cap={}",
        defaults.transaction().max_tx_bytes()
    );
}
