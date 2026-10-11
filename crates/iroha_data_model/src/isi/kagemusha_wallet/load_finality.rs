//! Exact successful Load instructions authenticated by native global-chain finality.
//!
//! The caller selects its network, chain, payer and complete Load instruction independently
//! of the response. Only the native verifier can supply the finalized block capability.

use super::{KagemushaWalletLedgerActionV1, KagemushaWalletLedgerV1};
use crate::kagemusha::kagemusha_wallet_v1::{decode_frame_v1, encode_frame_v1};
use crate::{
    Decode, DeriveJsonDeserialize, DeriveJsonSerialize, Encode, NetworkId,
    account::AccountId,
    block::BlockHeader,
    events::{
        EventBox,
        data::{DataEvent, kagemusha::KagemushaLoadCommittedV1},
    },
    kagemusha::{
        KagemushaWalletChargeKindV1, KagemushaWalletChargeQuoteV1,
        KagemushaWalletValidationErrorV1, kagemusha_wallet_account_digest_v1,
        kagemusha_wallet_is_canonical_field_v1, kagemusha_wallet_poseidon_bytes_v1,
    },
    query::CommittedTransaction,
    sumeragi_finality::{FinalityError, VerifiedSumeragiBlock},
    transaction::{Executable, SignedTransaction, signed::TransactionEntrypoint},
};
use iroha_crypto::{HashOf, MerkleProof};

/// Maximum complete canonical original receipt, including its fixed payer account digest.
pub const KAGEMUSHA_WALLET_LOAD_RECEIPT_MAX_BYTES_V1: usize = 512;

pub use crate::kagemusha::KAGEMUSHA_WALLET_LOAD_RECEIPT_DOMAIN_V1;
/// Exact fixed transcript width: version, four identities, three amounts, quote, transaction,
/// height, and canonical payer account digest.
pub const KAGEMUSHA_WALLET_LOAD_RECEIPT_TRANSCRIPT_BYTES_V1: usize = 2 + 7 * 32 + 3 * 16 + 8;

/// Original receipt of an ordinary successful Load transaction.
///
/// This serializable record is data, not proof of execution. Authenticate it through
/// [`verify_finalized_kagemusha_wallet_load_v1`] before accepting its historical terms.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Encode,
    Decode,
    norito::NoritoSchema,
    iroha_schema::IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[repr(align(16))]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha_data_model::isi::kagemusha_wallet::KagemushaWalletLoadReceiptV1")]
pub struct KagemushaWalletLoadReceiptV1 {
    /// First-release receipt version, exactly one.
    pub version: u16,
    /// Registered scheme identity.
    pub scheme_id: [u8; 32],
    /// Exact registered asset digest.
    pub asset_digest: [u8; 32],
    /// Wallet incarnation funded by this Load.
    pub wallet_id: [u8; 32],
    /// Stable nonzero original request identity.
    pub request_id: [u8; 32],
    /// Exact successive ordinal accepted by ledger execution.
    pub ordinal: u128,
    /// Net offline amount in registered atomic units.
    pub amount: u128,
    /// Additional displayed charge debited online.
    pub online_charge: u128,
    /// Canonical charge quote digest, zero exactly when there is no charge.
    pub charge_quote: [u8; 32],
    /// Hash of the original signed transaction.
    pub transaction_hash: [u8; 32],
    /// Height of the successful execution, after genesis.
    pub block_height: u64,
    /// Canonical account digest of the authenticated transaction authority that funded the Load.
    pub payer_account_digest: [u8; 32],
}

impl KagemushaWalletLoadReceiptV1 {
    /// Validate the receipt's data shape without conferring finality or spend authority.
    ///
    /// # Errors
    /// Rejects another version, missing identities, zero amount, a genesis height,
    /// inconsistent charge fields, an exhausted ordinal or an overflowing total online debit.
    pub fn validate(&self) -> Result<(), KagemushaWalletValidationErrorV1> {
        use KagemushaWalletValidationErrorV1 as Error;
        if self.version != 1 {
            return Err(Error::UnsupportedVersion {
                field: "load_receipt.version",
                version: self.version,
            });
        }
        for (field, value) in [
            ("load_receipt.scheme_id", &self.scheme_id),
            ("load_receipt.asset_digest", &self.asset_digest),
            ("load_receipt.wallet_id", &self.wallet_id),
            ("load_receipt.request_id", &self.request_id),
            ("load_receipt.transaction_hash", &self.transaction_hash),
            (
                "load_receipt.payer_account_digest",
                &self.payer_account_digest,
            ),
        ] {
            if *value == [0; 32] {
                return Err(Error::InvalidField { field });
            }
        }
        if self.amount == 0 {
            return Err(Error::InvalidField {
                field: "load_receipt.amount",
            });
        }
        if self.block_height < 2 {
            return Err(Error::InvalidField {
                field: "load_receipt.block_height",
            });
        }
        if !kagemusha_wallet_is_canonical_field_v1(&self.charge_quote)
            || (self.online_charge == 0) != (self.charge_quote == [0; 32])
        {
            return Err(Error::InvalidField {
                field: "load_receipt.charge_quote",
            });
        }
        self.ordinal
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow {
                field: "load_receipt.next_ordinal",
            })?;
        self.amount
            .checked_add(self.online_charge)
            .ok_or(Error::ArithmeticOverflow {
                field: "load_receipt.online_debit",
            })?;
        Ok(())
    }

    /// Check the independently retained charge quote against this receipt's exact terms.
    /// This validates data consistency only; it does not authenticate execution or the quote.
    ///
    /// # Errors
    /// Rejects missing, unexpected or mismatched charge terms and invalid quote data.
    pub fn require_charge_quote(
        &self,
        quote: Option<&KagemushaWalletChargeQuoteV1>,
    ) -> Result<(), KagemushaWalletValidationErrorV1> {
        use KagemushaWalletValidationErrorV1 as Error;
        self.validate()?;
        match (self.charge_quote == [0; 32], quote) {
            (true, None) => Ok(()),
            (true, Some(_)) | (false, None) => Err(Error::InvalidField {
                field: "load_receipt.charge_quote",
            }),
            (false, Some(quote)) => {
                quote.validate()?;
                if quote.charge_quote_digest() != self.charge_quote {
                    return Err(Error::InvalidField {
                        field: "load_receipt.charge_quote",
                    });
                }
                if quote.body.scheme_id != self.scheme_id {
                    return Err(Error::SchemeMismatch {
                        field: "charge_quote.scheme_id",
                    });
                }
                if quote.body.asset_digest != self.asset_digest {
                    return Err(Error::InvalidField {
                        field: "charge_quote.asset_digest",
                    });
                }
                quote.require_terms(
                    KagemushaWalletChargeKindV1::Load,
                    &self.wallet_id,
                    self.ordinal,
                    self.amount,
                    self.online_charge,
                )
            }
        }
    }

    /// Check that this receipt describes the next ordinal of the supplied wallet state.
    /// This is a data binding check; finality remains a separate proof obligation.
    ///
    /// # Errors
    /// Rejects invalid data or another scheme, asset, wallet or next ordinal.
    pub fn require_next_for(
        &self,
        state: &crate::kagemusha::KagemushaWalletStateV1,
    ) -> Result<(), KagemushaWalletValidationErrorV1> {
        use KagemushaWalletValidationErrorV1 as Error;
        self.validate()?;
        state.validate()?;
        if self.scheme_id != state.core.scheme_id {
            return Err(Error::SchemeMismatch {
                field: "load_receipt.scheme_id",
            });
        }
        for (field, valid) in [
            (
                "load_receipt.asset_digest",
                self.asset_digest == state.core.asset_digest,
            ),
            (
                "load_receipt.wallet_id",
                self.wallet_id == state.core.wallet_id,
            ),
            ("load_receipt.ordinal", self.ordinal == state.core.next_load),
        ] {
            if !valid {
                return Err(Error::InvalidField { field });
            }
        }
        Ok(())
    }

    /// Derive the public Load effect without granting authority to apply it.
    ///
    /// # Errors
    /// Rejects invalid receipt data.
    pub fn load_effect(
        &self,
    ) -> Result<crate::kagemusha::KagemushaWalletEffectV1, KagemushaWalletValidationErrorV1> {
        Ok(crate::kagemusha::KagemushaWalletEffectV1::Load {
            receipt_digest: self.receipt_digest()?,
            load_ordinal: self.ordinal,
            amount: self.amount,
            online_charge: self.online_charge,
        })
    }

    /// Exact checked total debit represented by this receipt, including its online charge.
    ///
    /// # Errors
    /// Rejects invalid receipt fields or an overflowing debit.
    pub fn ledger_debit(&self) -> Result<u128, KagemushaWalletValidationErrorV1> {
        self.validate()?;
        self.amount.checked_add(self.online_charge).ok_or(
            KagemushaWalletValidationErrorV1::ArithmeticOverflow {
                field: "load_receipt.online_debit",
            },
        )
    }

    /// Encode the validated receipt as one complete canonical Norito frame.
    ///
    /// # Errors
    /// Returns structural validation or canonical encoding errors.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, KagemushaWalletValidationErrorV1> {
        self.validate()?;
        encode_frame_v1(self, KAGEMUSHA_WALLET_LOAD_RECEIPT_MAX_BYTES_V1)
    }

    /// Decode one complete bounded canonical receipt frame; this grants no finality authority.
    ///
    /// # Errors
    /// Rejects oversized, noncanonical or structurally invalid receipt data.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, KagemushaWalletValidationErrorV1> {
        let receipt: Self = decode_frame_v1(bytes, KAGEMUSHA_WALLET_LOAD_RECEIPT_MAX_BYTES_V1)?;
        receipt.validate()?;
        Ok(receipt)
    }

    /// Exact fixed transcript, with integers in little-endian order and the canonical
    /// payer account digest.
    ///
    /// # Errors
    /// Returns structural validation errors.
    pub fn transcript(
        &self,
    ) -> Result<
        [u8; KAGEMUSHA_WALLET_LOAD_RECEIPT_TRANSCRIPT_BYTES_V1],
        KagemushaWalletValidationErrorV1,
    > {
        self.validate()?;
        let mut bytes = [0; KAGEMUSHA_WALLET_LOAD_RECEIPT_TRANSCRIPT_BYTES_V1];
        let mut offset = 0;
        for field in [
            self.version.to_le_bytes().as_slice(),
            &self.scheme_id,
            &self.asset_digest,
            &self.wallet_id,
            &self.request_id,
            self.ordinal.to_le_bytes().as_slice(),
            self.amount.to_le_bytes().as_slice(),
            self.online_charge.to_le_bytes().as_slice(),
            &self.charge_quote,
            &self.transaction_hash,
            self.block_height.to_le_bytes().as_slice(),
            &self.payer_account_digest,
        ] {
            bytes[offset..offset + field.len()].copy_from_slice(field);
            offset += field.len();
        }
        Ok(bytes)
    }

    /// Stable canonical σ-field identity `P_bytes(kgwolod1, transcript)` of the receipt.
    ///
    /// This digest is an identity only; it is not an offline Load proof.
    ///
    /// # Errors
    /// Returns structural validation errors.
    pub fn receipt_digest(&self) -> Result<[u8; 32], KagemushaWalletValidationErrorV1> {
        Ok(kagemusha_wallet_poseidon_bytes_v1(
            KAGEMUSHA_WALLET_LOAD_RECEIPT_DOMAIN_V1,
            &self.transcript()?,
        ))
    }
}

/// Immutable evidence for one exact Load instruction in successful finalized execution.
///
/// Fields are private and no decoder or unchecked constructor exists. This capability proves
/// a historical execution event, not the wallet's current state or an additional credit.
#[derive(Debug, Clone)]
pub struct VerifiedKagemushaWalletLoadV1 {
    network: NetworkId,
    receipt: KagemushaWalletLoadReceiptV1,
    payer: AccountId,
    instruction: KagemushaWalletLedgerV1,
    instruction_index: usize,
    transaction_hash: HashOf<SignedTransaction>,
    entrypoint_hash: HashOf<TransactionEntrypoint>,
    block_hash: HashOf<BlockHeader>,
    height: u64,
}

impl VerifiedKagemushaWalletLoadV1 {
    /// Exact original receipt derived from the authenticated successful instruction.
    #[must_use]
    pub fn receipt(&self) -> &KagemushaWalletLoadReceiptV1 {
        &self.receipt
    }

    /// Independently selected network authenticated by the global certificate.
    #[must_use]
    pub const fn network(&self) -> NetworkId {
        self.network
    }

    /// Exact payer authenticated by the transaction signature and successful execution.
    #[must_use]
    pub fn payer(&self) -> &AccountId {
        &self.payer
    }

    /// Complete immutable instruction, including scheme, asset, ordinal and charge terms.
    #[must_use]
    pub fn instruction(&self) -> &KagemushaWalletLedgerV1 {
        &self.instruction
    }

    /// Zero-based position of the direct instruction in the signed transaction.
    #[must_use]
    pub const fn instruction_index(&self) -> usize {
        self.instruction_index
    }

    /// Hash of the exact signed transaction that successfully executed the Load.
    #[must_use]
    pub const fn transaction_hash(&self) -> HashOf<SignedTransaction> {
        self.transaction_hash
    }

    /// Hash of the exact external network input authenticated by the block.
    #[must_use]
    pub const fn entrypoint_hash(&self) -> HashOf<TransactionEntrypoint> {
        self.entrypoint_hash
    }

    /// Authenticated finalized block header hash.
    #[must_use]
    pub const fn block_hash(&self) -> HashOf<BlockHeader> {
        self.block_hash
    }

    /// One-based height of the block that finalized the successful Load.
    #[must_use]
    pub const fn height(&self) -> u64 {
        self.height
    }
}

/// Why a candidate finalized Load cannot authenticate the caller's exact request.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KagemushaWalletLoadFinalityErrorV1 {
    /// Native global scope, transaction signature, inclusion or successful execution failed.
    #[error(transparent)]
    Finality(#[from] FinalityError),
    /// The supplied index does not select a direct Load instruction.
    #[error("finalized input does not contain the selected direct Load instruction")]
    WrongInstruction,
    /// The signed payer differs from the independently selected account.
    #[error("finalized Load payer differs from the approved account")]
    WrongPayer,
    /// Any instruction term differs from the independently selected Load request.
    #[error("finalized Load terms differ from the approved request")]
    WrongTerms,
    /// The committed terms cannot form a canonical Load receipt.
    #[error("finalized Load receipt is malformed: {0}")]
    InvalidReceipt(String),
    /// The exact Load event does not occur in the certified ordered event commitment.
    #[error("Load event differs from the certified receipt, height or ordered inclusion")]
    WrongEvent,
}

/// A receipt authenticated by exact system-event inclusion in a certified global result.
/// No decoder or unchecked constructor can manufacture this capability.
#[derive(Debug, Clone)]
pub struct VerifiedKagemushaWalletLoadEventV1 {
    receipt: KagemushaWalletLoadReceiptV1,
    network: NetworkId,
    block_hash: HashOf<BlockHeader>,
    event_index: u32,
}

impl VerifiedKagemushaWalletLoadEventV1 {
    /// The complete original receipt authenticated through its canonical transcript digest.
    #[must_use]
    pub fn receipt(&self) -> &KagemushaWalletLoadReceiptV1 {
        &self.receipt
    }
    /// Independently selected network authenticated by the global certificate.
    #[must_use]
    pub const fn network(&self) -> NetworkId {
        self.network
    }
    /// Authenticated result-bearing block header hash.
    #[must_use]
    pub const fn block_hash(&self) -> HashOf<BlockHeader> {
        self.block_hash
    }
    /// Exact zero-based position in the certified emitted-event stream.
    #[must_use]
    pub const fn event_index(&self) -> u32 {
        self.event_index
    }
    /// Authenticated original execution height.
    #[must_use]
    pub const fn height(&self) -> u64 {
        self.receipt.block_height
    }
}

/// Authenticate an exact original Load receipt through its system execution event.
///
/// The caller independently selects the receipt terms, network and chain. The
/// receipt transcript is validated and hashed, and its exact canonical `EventBox`
/// must occur at the supplied position in the authenticated result's root-and-count
/// commitment. Finality comes exclusively from `verified`, never from event naming,
/// a signer added to the Load protocol, or a host success flag.
///
/// # Errors
/// A malformed receipt, different height/scope, absent event stream, substituted
/// digest, invalid proof geometry or missing event inclusion is rejected.
pub fn verify_finalized_kagemusha_wallet_load_event_v1(
    verified: &VerifiedSumeragiBlock,
    proof: &MerkleProof<EventBox>,
    expected_network: NetworkId,
    expected_chain: &str,
    expected_receipt: &KagemushaWalletLoadReceiptV1,
) -> Result<VerifiedKagemushaWalletLoadEventV1, KagemushaWalletLoadFinalityErrorV1> {
    use KagemushaWalletLoadFinalityErrorV1 as Error;
    verified.verify_global_scope(expected_network, expected_chain)?;
    let event = KagemushaLoadCommittedV1::from_receipt(expected_receipt)
        .map_err(|error| Error::InvalidReceipt(error.to_string()))?;
    if expected_receipt.block_height != verified.height() {
        return Err(Error::WrongEvent);
    }
    let commitment = verified
        .execution()
        .event_commitment
        .as_ref()
        .ok_or(Error::WrongEvent)?;
    let boxed = EventBox::Data(DataEvent::KagemushaLoadCommitted(event).into());
    if !proof.verify(&HashOf::new(&boxed), commitment) {
        return Err(Error::WrongEvent);
    }
    Ok(VerifiedKagemushaWalletLoadEventV1 {
        receipt: *expected_receipt,
        network: expected_network,
        block_hash: verified.header().hash(),
        event_index: proof.leaf_index(),
    })
}

/// Authenticate one exact direct Load instruction in a successful external transaction.
///
/// `verified` must come from a native finality verifier rooted in independently selected
/// genesis or a trusted checkpoint. The expected network, chain, payer and complete
/// instruction must come from the caller's original request, not the candidate response.
/// The entire instruction is compared, including charge bytes and beneficiary. Nested
/// batches and VM effects are not interpreted as direct Load instructions. Ledger execution
/// rejects request reuse by a different transaction or height, so a successful original
/// instruction cannot be substituted with a later no-op retry. Lost responses are recovered
/// through the original receipt query.
///
/// # Errors
/// Refuses another global scope, private-root authority, unsuccessful or substituted
/// execution, an invalid signature, a wrong payer/index, or any changed Load term.
pub fn verify_finalized_kagemusha_wallet_load_v1(
    verified: &VerifiedSumeragiBlock,
    committed: &CommittedTransaction,
    expected_network: NetworkId,
    expected_chain: &str,
    instruction_index: usize,
    expected_instruction: &KagemushaWalletLedgerV1,
    expected_payer: &AccountId,
) -> Result<VerifiedKagemushaWalletLoadV1, KagemushaWalletLoadFinalityErrorV1> {
    use KagemushaWalletLoadFinalityErrorV1 as Error;

    verified.verify_global_scope(expected_network, expected_chain)?;
    verified.verify_committed_transaction(&expected_network, committed)?;
    let TransactionEntrypoint::External(transaction) = committed.entrypoint() else {
        return Err(Error::WrongInstruction);
    };
    if transaction.authority() != expected_payer {
        return Err(Error::WrongPayer);
    }
    let Executable::Instructions(instructions) = transaction.instructions() else {
        return Err(Error::WrongInstruction);
    };
    let instruction = instructions
        .get(instruction_index)
        .and_then(|instruction| {
            instruction
                .as_any()
                .downcast_ref::<KagemushaWalletLedgerV1>()
        })
        .ok_or(Error::WrongInstruction)?;
    if !matches!(
        instruction.action,
        KagemushaWalletLedgerActionV1::IssueLoad { .. }
    ) || !matches!(
        expected_instruction.action,
        KagemushaWalletLedgerActionV1::IssueLoad { .. }
    ) {
        return Err(Error::WrongInstruction);
    }
    if instruction != expected_instruction {
        return Err(Error::WrongTerms);
    }
    let receipt = receipt_from_instruction(instruction, transaction, verified.height())
        .map_err(|error| Error::InvalidReceipt(error.to_string()))?;
    Ok(VerifiedKagemushaWalletLoadV1 {
        receipt,
        network: expected_network,
        payer: transaction.authority().clone(),
        instruction: instruction.clone(),
        instruction_index,
        transaction_hash: transaction.hash(),
        entrypoint_hash: *committed.entrypoint_hash(),
        block_hash: *committed.block_hash(),
        height: verified.height(),
    })
}

fn receipt_from_instruction(
    instruction: &KagemushaWalletLedgerV1,
    transaction: &SignedTransaction,
    block_height: u64,
) -> Result<KagemushaWalletLoadReceiptV1, KagemushaWalletValidationErrorV1> {
    use KagemushaWalletValidationErrorV1 as Error;
    let KagemushaWalletLedgerActionV1::IssueLoad {
        wallet,
        asset,
        ordinal,
        request_id,
        amount,
        charge,
    } = &instruction.action
    else {
        return Err(Error::InvalidField {
            field: "load_receipt.instruction",
        });
    };
    let (online_charge, charge_quote) = match charge {
        None => (0, [0; 32]),
        Some(charge) => {
            let quote =
                KagemushaWalletChargeQuoteV1::decode_canonical(&charge.quote, &instruction.scheme)?;
            if quote.body.asset_digest != *asset {
                return Err(Error::InvalidField {
                    field: "load_receipt.asset_digest",
                });
            }
            quote.require_terms(
                KagemushaWalletChargeKindV1::Load,
                wallet,
                *ordinal,
                *amount,
                quote.body.online_charge,
            )?;
            if quote.body.beneficiary_account_digest
                != kagemusha_wallet_account_digest_v1(&charge.beneficiary)?
            {
                return Err(Error::InvalidField {
                    field: "load_receipt.beneficiary",
                });
            }
            (quote.body.online_charge, quote.charge_quote_digest())
        }
    };
    let receipt = KagemushaWalletLoadReceiptV1 {
        version: 1,
        scheme_id: instruction.scheme,
        asset_digest: *asset,
        wallet_id: *wallet,
        request_id: *request_id,
        ordinal: *ordinal,
        amount: *amount,
        online_charge,
        charge_quote,
        transaction_hash: *transaction.hash().as_ref(),
        block_height,
        payer_account_digest: kagemusha_wallet_account_digest_v1(transaction.authority())?,
    };
    receipt.validate()?;
    Ok(receipt)
}

#[cfg(test)]
mod tests;
