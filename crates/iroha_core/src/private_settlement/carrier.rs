//! Exact signed-transaction binding for the global private-settlement carrier.
//!
//! A receipt instruction reached through a trigger, contract, custom executor,
//! proved overlay, or mixed batch must not finalize state. Admission derives a
//! one-shot binding only for one exact direct instruction whose signer and fee
//! intent match the certified manifest.

use iroha_crypto::Hash;
use iroha_data_model::{
    ValidationFail,
    isi::private_settlement::{
        AbortAtomicPrivateSettlementV1, FinalizeAtomicPrivateSettlementV1,
        RegisterAtomicPrivateSettlementPrepareV1,
    },
    nexus::PrivateSettlementCommitBundleV1,
    transaction::{Executable, SignedTransaction},
};
use thiserror::Error;

const COMMIT_BUNDLE_DIGEST_DOMAIN_V1: &[u8] = b"iroha:nexus:private-settlement:commit-bundle:v1\0";
const CARRIER_INSTRUCTION_DIGEST_DOMAIN_V1: &[u8] =
    b"iroha:nexus:private-settlement:carrier-instruction:v1\0";
const ABORT_CARRIER_INSTRUCTION_DIGEST_DOMAIN_V1: &[u8] =
    b"iroha:nexus:private-settlement:abort-carrier-instruction:v1\0";
const PREPARE_LOCK_CARRIER_INSTRUCTION_DIGEST_DOMAIN_V1: &[u8] =
    b"iroha:nexus:private-settlement:prepare-lock-carrier-instruction:v1\0";

fn canonical_digest_v1<T: norito::NoritoSerialize>(
    domain: &[u8],
    value: &T,
) -> Result<Hash, norito::Error> {
    let encoded = norito::encode_canonical(value)?;
    let encoded_len = u64::try_from(encoded.len())
        .map_err(|_| norito::Error::Io(std::io::Error::other("canonical value is too large")))?;
    Ok(Hash::new_from_chunks(&[
        domain,
        &encoded_len.to_le_bytes(),
        encoded.as_slice(),
    ]))
}

/// Hash one exact pre-finality committee-certified bundle.
pub(crate) fn private_settlement_commit_bundle_digest_v1(
    bundle: &PrivateSettlementCommitBundleV1,
) -> Result<Hash, norito::Error> {
    canonical_digest_v1(COMMIT_BUNDLE_DIGEST_DOMAIN_V1, bundle)
}

/// Hash the exact direct carrier instruction authorized by the sponsor.
pub(crate) fn private_settlement_carrier_instruction_digest_v1(
    instruction: &FinalizeAtomicPrivateSettlementV1,
) -> Result<Hash, norito::Error> {
    canonical_digest_v1(CARRIER_INSTRUCTION_DIGEST_DOMAIN_V1, instruction)
}

/// Hash the exact direct abort carrier instruction authorized by the sponsor.
pub(crate) fn private_settlement_abort_carrier_instruction_digest_v1(
    instruction: &AbortAtomicPrivateSettlementV1,
) -> Result<Hash, norito::Error> {
    canonical_digest_v1(ABORT_CARRIER_INSTRUCTION_DIGEST_DOMAIN_V1, instruction)
}

/// Hash the exact direct all-Prepare control-lock carrier instruction.
pub(crate) fn private_settlement_prepare_lock_carrier_instruction_digest_v1(
    instruction: &RegisterAtomicPrivateSettlementPrepareV1,
) -> Result<Hash, norito::Error> {
    canonical_digest_v1(
        PREPARE_LOCK_CARRIER_INSTRUCTION_DIGEST_DOMAIN_V1,
        instruction,
    )
}

/// One-shot identity installed from an exact signed carrier transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PrivateSettlementCarrierBindingV1 {
    payload_digest: Hash,
    instruction_digest: Hash,
    signed_transaction_bytes: u64,
    consumed: bool,
}

impl PrivateSettlementCarrierBindingV1 {
    fn new(payload_digest: Hash, instruction_digest: Hash, signed_transaction_bytes: u64) -> Self {
        Self {
            payload_digest,
            instruction_digest,
            signed_transaction_bytes,
            consumed: false,
        }
    }

    /// Consume the exact carrier once after all comparisons succeed.
    pub(crate) fn consume(
        &mut self,
        payload_digest: Hash,
        instruction_digest: Hash,
        max_signed_transaction_bytes: u64,
    ) -> Result<(), PrivateSettlementCarrierBindingErrorV1> {
        if self.payload_digest != payload_digest {
            return Err(PrivateSettlementCarrierBindingErrorV1::PayloadMismatch);
        }
        if self.instruction_digest != instruction_digest {
            return Err(PrivateSettlementCarrierBindingErrorV1::InstructionMismatch);
        }
        if max_signed_transaction_bytes == 0
            || self.signed_transaction_bytes > max_signed_transaction_bytes
        {
            return Err(PrivateSettlementCarrierBindingErrorV1::CarrierTooLarge);
        }
        if self.consumed {
            return Err(PrivateSettlementCarrierBindingErrorV1::AlreadyConsumed);
        }
        self.consumed = true;
        Ok(())
    }
}

/// Derive the optional one-shot carrier identity from a signed transaction.
///
/// Ordinary transactions return `Ok(None)`. If a carrier is present, the
/// executable must contain that carrier and nothing else, the signed authority
/// must be the manifest sponsor, and the signed fee intent must be byte-for-byte
/// equal to the manifest fee intent.
pub(crate) fn signed_private_settlement_carrier_binding_v1(
    transaction: &SignedTransaction,
) -> Result<Option<PrivateSettlementCarrierBindingV1>, ValidationFail> {
    let explicit_carrier_count = transaction
        .instructions()
        .explicit_instructions()
        .filter(|instruction| {
            let instruction = instruction.as_any();
            instruction
                .downcast_ref::<FinalizeAtomicPrivateSettlementV1>()
                .is_some()
                || instruction
                    .downcast_ref::<RegisterAtomicPrivateSettlementPrepareV1>()
                    .is_some()
                || instruction
                    .downcast_ref::<AbortAtomicPrivateSettlementV1>()
                    .is_some()
        })
        .count();
    if explicit_carrier_count == 0 {
        return Ok(None);
    }

    let Executable::Instructions(instructions) = transaction.instructions() else {
        return Err(not_permitted());
    };
    if instructions.len() != 1 || explicit_carrier_count != 1 {
        return Err(not_permitted());
    }
    let instruction = instructions[0].as_any();
    let (manifest, payload_digest, instruction_digest) = if let Some(carrier) =
        instruction.downcast_ref::<FinalizeAtomicPrivateSettlementV1>()
    {
        let manifest = &carrier.commit_bundle.manifest;
        let structural_receipt = carrier
            .commit_bundle
            .clone()
            .into_receipt(manifest.authority_context_height);
        structural_receipt
            .validate_shape()
            .map_err(|_| not_permitted())?;
        let payload_digest = private_settlement_commit_bundle_digest_v1(&carrier.commit_bundle)
            .map_err(|error| {
                ValidationFail::InternalError(format!(
                    "failed to encode private-settlement commit bundle: {error}"
                ))
            })?;
        let instruction_digest = private_settlement_carrier_instruction_digest_v1(carrier)
            .map_err(|error| {
                ValidationFail::InternalError(format!(
                    "failed to encode private-settlement carrier: {error}"
                ))
            })?;
        (manifest, payload_digest, instruction_digest)
    } else if let Some(carrier) =
        instruction.downcast_ref::<RegisterAtomicPrivateSettlementPrepareV1>()
    {
        carrier
            .barrier
            .validate_shape()
            .map_err(|_| not_permitted())?;
        let instruction_digest = private_settlement_prepare_lock_carrier_instruction_digest_v1(
            carrier,
        )
        .map_err(|error| {
            ValidationFail::InternalError(format!(
                "failed to encode private-settlement Prepare-lock carrier: {error}"
            ))
        })?;
        (
            &carrier.barrier.manifest,
            carrier.barrier.prepared_bundle_digest,
            instruction_digest,
        )
    } else if let Some(carrier) = instruction.downcast_ref::<AbortAtomicPrivateSettlementV1>() {
        carrier.manifest.validate().map_err(|_| not_permitted())?;
        let payload_digest = carrier.manifest.manifest_digest().map_err(|error| {
            ValidationFail::InternalError(format!(
                "failed to encode private-settlement abort manifest: {error}"
            ))
        })?;
        let instruction_digest = private_settlement_abort_carrier_instruction_digest_v1(carrier)
            .map_err(|error| {
                ValidationFail::InternalError(format!(
                    "failed to encode private-settlement abort carrier: {error}"
                ))
            })?;
        (&carrier.manifest, payload_digest, instruction_digest)
    } else {
        return Err(not_permitted());
    };
    if transaction.authority() != &manifest.sponsor
        || transaction.fee_payment_intent() != &manifest.public_fee_intent
    {
        return Err(not_permitted());
    }
    let encoded_transaction = transaction.encode_wire_v1().map_err(|error| {
        ValidationFail::InternalError(format!(
            "failed to encode private-settlement carrier transaction: {error}"
        ))
    })?;
    let signed_transaction_bytes = u64::try_from(encoded_transaction.len()).map_err(|_| {
        ValidationFail::InternalError(
            "private-settlement carrier transaction is too large".to_owned(),
        )
    })?;
    Ok(Some(PrivateSettlementCarrierBindingV1::new(
        payload_digest,
        instruction_digest,
        signed_transaction_bytes,
    )))
}

fn not_permitted() -> ValidationFail {
    ValidationFail::NotPermitted(
        "private-settlement control/finality requires one exact sponsor-signed direct carrier with the committed fee intent"
            .to_owned(),
    )
}

/// Closed failure while consuming a transaction-scoped carrier binding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub(crate) enum PrivateSettlementCarrierBindingErrorV1 {
    /// No exact direct carrier was installed from the current signed payload.
    #[error("the current signed transaction has no bound private-settlement carrier")]
    MissingBinding,
    /// The certified bundle or abort manifest differs from the exact signed carrier.
    #[error("private-settlement payload differs from the signed carrier")]
    PayloadMismatch,
    /// The complete instruction differs from the exact signed carrier.
    #[error("private-settlement instruction differs from the signed carrier")]
    InstructionMismatch,
    /// The complete sponsor-signed transaction exceeds the governed carrier limit.
    #[error("private-settlement signed carrier exceeds the governed byte limit")]
    CarrierTooLarge,
    /// A nested or repeated execution attempted to replay the carrier.
    #[error("private-settlement carrier was already consumed")]
    AlreadyConsumed,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::private_settlement::coordinator::tests::certified_commit_bundle_fixture;
    use iroha_crypto::{Algorithm, HashOf, KeyPair};
    use iroha_data_model::{
        NetworkId, account::AccountId, block::BlockHeader, nexus::AtomicPrivateSettlementV1,
        transaction::TransactionBuilder,
    };
    use std::num::{NonZeroU32, NonZeroU64};

    #[test]
    fn one_shot_binding_rejects_substitution_and_replay() {
        let bundle_digest = Hash::new(b"bundle-a");
        let instruction_digest = Hash::new(b"instruction-a");
        let mut binding =
            PrivateSettlementCarrierBindingV1::new(bundle_digest, instruction_digest, 1024);

        assert_eq!(
            binding.consume(Hash::new(b"bundle-b"), instruction_digest, 1024),
            Err(PrivateSettlementCarrierBindingErrorV1::PayloadMismatch)
        );
        assert_eq!(
            binding.consume(bundle_digest, Hash::new(b"instruction-b"), 1024),
            Err(PrivateSettlementCarrierBindingErrorV1::InstructionMismatch)
        );
        assert_eq!(
            binding.consume(bundle_digest, instruction_digest, 1023),
            Err(PrivateSettlementCarrierBindingErrorV1::CarrierTooLarge)
        );
        assert_eq!(
            binding.consume(bundle_digest, instruction_digest, 1024),
            Ok(())
        );
        assert_eq!(
            binding.consume(bundle_digest, instruction_digest, 1024),
            Err(PrivateSettlementCarrierBindingErrorV1::AlreadyConsumed)
        );
    }

    #[test]
    fn signed_carrier_limit_uses_the_complete_fixed_v1_transaction_wire() {
        let (bundle, sponsor_key) = certified_commit_bundle_fixture();
        let instruction = FinalizeAtomicPrivateSettlementV1::new(bundle.clone());
        let direct_instruction_bytes = u64::try_from(
            bundle
                .canonical_carrier_bytes_len()
                .expect("carrier instruction encodes"),
        )
        .expect("fixture instruction length fits u64");
        let mut builder = TransactionBuilder::new(
            bundle.manifest.network_id,
            bundle.manifest.sponsor.clone(),
            bundle.manifest.public_fee_intent.clone(),
        )
        .with_instructions([instruction.clone()]);
        builder.set_nonce(NonZeroU32::new(7).expect("non-zero fixture nonce"));
        let transaction = builder.sign(sponsor_key.private_key());
        let exact_signed_bytes = u64::try_from(
            transaction
                .encode_wire_v1()
                .expect("fixed V1 signed transaction encodes")
                .len(),
        )
        .expect("fixture signed transaction length fits u64");
        assert!(
            exact_signed_bytes > direct_instruction_bytes,
            "the signed envelope and authorization proof must contribute to the limit"
        );

        let mut binding = signed_private_settlement_carrier_binding_v1(&transaction)
            .expect("carrier binding derives")
            .expect("fixture contains one direct carrier");
        assert_eq!(binding.signed_transaction_bytes, exact_signed_bytes);
        let bundle_digest = private_settlement_commit_bundle_digest_v1(&bundle)
            .expect("fixture bundle digest encodes");
        let instruction_digest = private_settlement_carrier_instruction_digest_v1(&instruction)
            .expect("fixture instruction digest encodes");
        assert_eq!(
            binding.consume(bundle_digest, instruction_digest, exact_signed_bytes - 1,),
            Err(PrivateSettlementCarrierBindingErrorV1::CarrierTooLarge)
        );
        assert_eq!(
            binding.consume(bundle_digest, instruction_digest, exact_signed_bytes),
            Ok(())
        );
    }

    #[test]
    fn signed_prepare_registration_binds_barrier_fee_and_complete_transaction() {
        use iroha_data_model::nexus::PrivateSettlementPrepareBarrierV1;

        let (bundle, sponsor_key) = certified_commit_bundle_fixture();
        let barrier = PrivateSettlementPrepareBarrierV1 {
            version: bundle.version,
            manifest: bundle.manifest.clone(),
            authority_catalog: bundle.authority_catalog.clone(),
            deltas: bundle.legs.iter().map(|leg| leg.delta.clone()).collect(),
            prepare_certificates: bundle.legs.iter().map(|leg| leg.prepare.clone()).collect(),
            prepared_bundle_digest: bundle.legs[0].commit.body.prepared_bundle_digest,
        };
        barrier.validate_shape().expect("fixture Prepare barrier");
        let instruction = RegisterAtomicPrivateSettlementPrepareV1::new(barrier.clone());
        let transaction = TransactionBuilder::new(
            barrier.manifest.network_id,
            barrier.manifest.sponsor.clone(),
            barrier.manifest.public_fee_intent.clone(),
        )
        .with_instructions([instruction.clone()])
        .sign(sponsor_key.private_key());
        let exact_signed_bytes = u64::try_from(
            transaction
                .encode_wire_v1()
                .expect("fixed V1 signed registration transaction encodes")
                .len(),
        )
        .expect("fixture signed transaction length fits u64");
        let mut binding = signed_private_settlement_carrier_binding_v1(&transaction)
            .expect("registration binding derives")
            .expect("fixture contains one direct registration carrier");
        let instruction_digest =
            private_settlement_prepare_lock_carrier_instruction_digest_v1(&instruction)
                .expect("registration instruction digest encodes");
        assert_eq!(binding.signed_transaction_bytes, exact_signed_bytes);
        assert_eq!(
            binding.consume(
                barrier.prepared_bundle_digest,
                instruction_digest,
                exact_signed_bytes - 1,
            ),
            Err(PrivateSettlementCarrierBindingErrorV1::CarrierTooLarge)
        );
        assert_eq!(
            binding.consume(
                barrier.prepared_bundle_digest,
                instruction_digest,
                exact_signed_bytes,
            ),
            Ok(())
        );
    }

    #[test]
    fn signed_abort_carrier_binds_manifest_reason_and_complete_transaction() {
        use iroha_data_model::nexus::PrivateSettlementAbortReasonV1;

        let (bundle, sponsor_key) = certified_commit_bundle_fixture();
        let manifest = bundle.manifest;
        let instruction = AbortAtomicPrivateSettlementV1::new(
            manifest.clone(),
            PrivateSettlementAbortReasonV1::ParticipantRejected,
        );
        let transaction = TransactionBuilder::new(
            manifest.network_id,
            manifest.sponsor.clone(),
            manifest.public_fee_intent.clone(),
        )
        .with_instructions([instruction.clone()])
        .sign(sponsor_key.private_key());
        let exact_signed_bytes = u64::try_from(
            transaction
                .encode_wire_v1()
                .expect("fixed V1 signed abort transaction encodes")
                .len(),
        )
        .expect("fixture signed transaction length fits u64");
        let mut binding = signed_private_settlement_carrier_binding_v1(&transaction)
            .expect("abort carrier binding derives")
            .expect("fixture contains one direct abort carrier");
        assert_eq!(binding.signed_transaction_bytes, exact_signed_bytes);

        let manifest_digest = manifest.manifest_digest().expect("manifest digest encodes");
        let substituted =
            AbortAtomicPrivateSettlementV1::new(manifest, PrivateSettlementAbortReasonV1::Expired);
        let substituted_digest =
            private_settlement_abort_carrier_instruction_digest_v1(&substituted)
                .expect("substituted instruction digest encodes");
        assert_eq!(
            binding.consume(manifest_digest, substituted_digest, exact_signed_bytes),
            Err(PrivateSettlementCarrierBindingErrorV1::InstructionMismatch)
        );
        let instruction_digest =
            private_settlement_abort_carrier_instruction_digest_v1(&instruction)
                .expect("abort instruction digest encodes");
        assert_eq!(
            binding.consume(manifest_digest, instruction_digest, exact_signed_bytes),
            Ok(())
        );
    }

    #[test]
    fn mixed_terminal_carriers_are_rejected_before_execution() {
        use iroha_data_model::{isi::InstructionBox, nexus::PrivateSettlementAbortReasonV1};

        let (bundle, sponsor_key) = certified_commit_bundle_fixture();
        let manifest = bundle.manifest.clone();
        let instructions = vec![
            InstructionBox::from(FinalizeAtomicPrivateSettlementV1::new(bundle)),
            InstructionBox::from(AbortAtomicPrivateSettlementV1::new(
                manifest.clone(),
                PrivateSettlementAbortReasonV1::ParticipantRejected,
            )),
        ];
        let transaction = TransactionBuilder::new(
            manifest.network_id,
            manifest.sponsor,
            manifest.public_fee_intent,
        )
        .with_instructions(instructions)
        .sign(sponsor_key.private_key());
        assert!(matches!(
            signed_private_settlement_carrier_binding_v1(&transaction),
            Err(ValidationFail::NotPermitted(_))
        ));
    }

    #[test]
    fn abort_carrier_rejects_substituted_sponsor_and_fee_intent() {
        use iroha_data_model::{
            nexus::PrivateSettlementAbortReasonV1, transaction::FeePaymentIntent,
        };

        let (bundle, sponsor_key) = certified_commit_bundle_fixture();
        let manifest = bundle.manifest;
        let instruction = AbortAtomicPrivateSettlementV1::new(
            manifest.clone(),
            PrivateSettlementAbortReasonV1::ParticipantRejected,
        );
        let outsider_key = KeyPair::from_seed(vec![0xA9; 32], Algorithm::Ed25519);
        let outsider = AccountId::new(outsider_key.public_key().clone());
        let wrong_sponsor = TransactionBuilder::new(
            manifest.network_id,
            outsider,
            manifest.public_fee_intent.clone(),
        )
        .with_instructions([instruction.clone()])
        .sign(outsider_key.private_key());
        assert!(matches!(
            signed_private_settlement_carrier_binding_v1(&wrong_sponsor),
            Err(ValidationFail::NotPermitted(_))
        ));

        let wrong_fee = TransactionBuilder::new(
            manifest.network_id,
            manifest.sponsor,
            FeePaymentIntent::authority(Vec::new(), NonZeroU64::new(1)),
        )
        .with_instructions([instruction])
        .sign(sponsor_key.private_key());
        assert!(matches!(
            signed_private_settlement_carrier_binding_v1(&wrong_fee),
            Err(ValidationFail::NotPermitted(_))
        ));
    }

    #[test]
    fn commit_bundle_digest_is_domain_separated_and_deterministic() {
        let bundle = PrivateSettlementCommitBundleV1 {
            version: 1,
            manifest: AtomicPrivateSettlementV1 {
                version: 1,
                network_id: NetworkId::from_genesis_hash(
                    HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(b"network")),
                ),
                bundle_id: Hash::new(b"invalid-fixture-bundle"),
                authority_context_height: 1,
                expiry_height: 2,
                sponsor: AccountId::new(
                    KeyPair::from_seed(vec![0x51; 32], Algorithm::Ed25519)
                        .public_key()
                        .clone(),
                ),
                public_fee_intent: iroha_data_model::transaction::FeePaymentIntent::authority(
                    Vec::new(),
                    None,
                ),
                fee_intent_digest: Hash::new(b"fee"),
                reimbursement_terms_commitment: Hash::new(b"reimbursement"),
                reimbursement_leg_ordinal: 0,
                legs: Vec::new(),
            },
            authority_catalog:
                iroha_data_model::nexus::PrivateSettlementAuthorityCatalogV1::default(),
            legs: Vec::new(),
        };
        let first = private_settlement_commit_bundle_digest_v1(&bundle)
            .expect("fixture encodes canonically");
        let second = private_settlement_commit_bundle_digest_v1(&bundle)
            .expect("fixture encodes canonically");
        assert_eq!(first, second);
        assert_ne!(
            first,
            Hash::new(&norito::encode_canonical(&bundle).unwrap())
        );
    }
}
