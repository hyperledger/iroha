//! Direct ledger finality outcomes of signed Activate and Unload attempts.
//!
//! Each attempt is confirmed from one bounded original: the inclusion block's original
//! `CommitQC` certificate with the membership of the exact entrypoint and its joined Network
//! output. It is verified on a private clone of the epoch reader that the protected manifest
//! selected, rooted in the installed signed genesis. Nothing walks or replays blocks or imports
//! a checkpoint, and an absent, refused or unavailable original is never a verdict. The first
//! authenticated outcome of each attempt is retained immutably together with its exact original.
use super::*;
use crate::kagemusha_wallet_state_v1::{
    decode_attempt_error, finality_read_error, read_model_original,
};
use iroha_data_model::transaction::SignedTransaction;
use iroha_version::codec::DecodeVersioned;

/// BLS-certified native consensus identity of an inclusion block. It is not the Iroha
/// block-header hash, which a compact certificate does not authenticate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LedgerCommitV1 {
    /// Certified inclusion height.
    pub height: u64,
    /// Native consensus block identity named by the quorum certificate.
    pub commit_hash: [u8; 32],
}

/// Native-retained outcome of one exact signed Activate or Unload attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LedgerAttemptOutcomeV1 {
    /// No authenticated outcome is retained. Only this natively derived entrypoint hash of
    /// the retained signed wire selects the attempt's finality route; it is not authority.
    Awaiting {
        /// Entrypoint hash recomputed from the retained signed wire.
        entrypoint: [u8; 32],
    },
    /// Certified rejected execution of this attempt only. It never changes offline value,
    /// the retained claim or any other attempt.
    Rejected(LedgerCommitV1),
    /// Certified successful execution. For Activate this is the wallet's activation; it does
    /// not assert that every other attempt executed successfully.
    Confirmed(LedgerCommitV1),
}

/// Result of offering one ledger finality original for an attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LedgerAttemptIngestV1 {
    /// The attempt's retained outcome after this original.
    Outcome(LedgerAttemptOutcomeV1),
    /// The original names an epoch this wallet has not selected. This is DATA: nothing was
    /// verified or written. Synchronize epoch boundaries until they cover `target_height`,
    /// then offer the same original again.
    EpochRequired {
        /// Untrusted certificate height; it selects synchronization work, never authority.
        target_height: u64,
    },
}

/// Immutable first authenticated outcome of one attempt and the archive address of its
/// exact finality original. Its fields are rechecked against that original on every read.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, norito::Encode, norito::Decode, norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_core_zk::kagemusha_wallet_state_v1::LedgerOutcomeV1")]
pub(super) struct LedgerOutcome {
    version: u16,
    entrypoint: [u8; 32],
    accepted: bool,
    height: u64,
    commit_hash: [u8; 32],
    finality: [u8; 32],
}

impl LedgerOutcome {
    pub(super) const fn accepted(&self) -> bool {
        self.accepted
    }
    pub(super) const fn commit(&self) -> LedgerCommitV1 {
        LedgerCommitV1 {
            height: self.height,
            commit_hash: self.commit_hash,
        }
    }
    pub(super) const fn attempt(&self) -> LedgerAttemptOutcomeV1 {
        if self.accepted {
            LedgerAttemptOutcomeV1::Confirmed(self.commit())
        } else {
            LedgerAttemptOutcomeV1::Rejected(self.commit())
        }
    }
    /// Finite field bindings of a retained record; the original is checked separately.
    pub(super) fn require(&self) -> Result<(), Error> {
        if self.version != 1
            || self.entrypoint == [0; 32]
            || self.height < 2
            || self.commit_hash == [0; 32]
            || self.finality == [0; 32]
        {
            return Err(Error::WitnessLost("ledger outcome binding"));
        }
        Ok(())
    }
    fn same(&self, verified: &VerifiedKagemushaLedgerOutcomeV1) -> bool {
        (
            self.entrypoint,
            self.height,
            self.commit_hash,
            self.accepted,
        ) == (
            verified.entrypoint(),
            verified.height(),
            verified.commit_hash(),
            verified.accepted(),
        )
    }
}

/// Recompute the attempt key, the entrypoint hash, from one exact retained signed wire.
/// The caller-supplied or HTTP transaction hash is never an attempt key.
pub(super) fn entrypoint(signed: &SignedTransaction) -> Result<[u8; 32], Error> {
    let hash = norito::core::classify_decode_attempt(|| signed.try_hash_as_entrypoint()).map_err(
        |error| decode_attempt_error(error, Error::Invalid("ledger attempt entrypoint")),
    )?;
    Ok(*hash.as_ref())
}

/// Decode one exact canonical signed wire. Authority, network and instruction checks belong
/// to the caller's intake; this only binds a retained original to its entrypoint hash.
pub(super) fn signed_original(bytes: &[u8]) -> Result<SignedTransaction, Error> {
    if bytes.is_empty() || bytes.len() > LEDGER_INSTRUCTION_MAX_BYTES_V1 {
        return Err(Error::Invalid("ledger signed transaction bound"));
    }
    let transaction =
        norito::with_decode_limits_scope(norito::canonical_decode_limits(bytes.len()), || {
            SignedTransaction::decode_all_versioned(bytes)
        })
        .map_err(|error| match error {
            iroha_version::error::Error::NoritoResourceLimit(original) => decode_attempt_error(
                original,
                Error::Invalid("ledger signed transaction encoding"),
            ),
            _ => Error::Invalid("ledger signed transaction encoding"),
        })?;
    let canonical = norito::core::classify_decode_attempt(|| transaction.encode_wire_v1())
        .map_err(|error| decode_attempt_error(error, Error::Invalid("ledger signed wire")))?;
    if canonical != bytes {
        return Err(Error::Invalid("ledger signed wire"));
    }
    Ok(transaction)
}

/// Recompute the entrypoint hash of an exact retained signed wire. A retained original that no
/// longer decodes canonically is lost custody, never invalid caller input.
pub(super) fn retained_entrypoint(wire: &[u8]) -> Result<[u8; 32], Error> {
    let lost = |error| match error {
        Error::Invalid(_) => Error::WitnessLost("ledger attempt signed original"),
        other => other,
    };
    entrypoint(&signed_original(wire).map_err(lost)?).map_err(lost)
}

/// One offered original, verified but not yet retained.
pub(super) enum OfferedOutcome {
    /// Authenticated under an epoch the protected manifest selected; nothing is written yet.
    Verified(VerifiedKagemushaLedgerOutcomeV1),
    /// The certificate names an unselected epoch; nothing was verified or written.
    EpochRequired(u64),
}

impl<C: Custody, A: ArchiveStore, N: NativeProofs> Coordinator<C, A, N> {
    /// The installed signed genesis is the global root of this wallet's ledger scope.
    pub(super) fn require_ledger_root(
        &self,
        genesis: &SumeragiFinalityVerifier,
    ) -> Result<(), Error> {
        let (scheme, chain) = self.proofs.ledger_scope()?;
        if scheme.scheme_id() != self.scheme_id
            || chain != genesis.chain_id()
            || genesis.initial_epoch().network_id.as_bytes() != &scheme.network_id
            || genesis.root_scope() != iroha_data_model::block::consensus::SumeragiRootScope::Global
        {
            return Err(Error::Proof("ledger outcome root scope"));
        }
        Ok(())
    }

    /// Verify one original for the exact `signed` attempt under the epoch authority that the
    /// protected manifest selected. Nothing is written. Only the selected index supplies an
    /// epoch; the certificate's own boundary successor is discarded with the private reader.
    pub(super) fn verify_ledger_original(
        &mut self,
        manifest: &manifest::Manifest,
        genesis: &SumeragiFinalityVerifier,
        signed: &SignedTransaction,
        bytes: &[u8],
    ) -> Result<OfferedOutcome, Error> {
        if bytes.is_empty() || bytes.len() > KAGEMUSHA_WALLET_LEDGER_FINALITY_MAX_BYTES_V1 {
            return Err(Error::Invalid("ledger finality original bound"));
        }
        let original = read_model_original(
            || KagemushaWalletLedgerFinalityV1::decode_canonical(bytes),
            Error::Invalid("ledger finality canonical original"),
        )?;
        let (epoch, height) = original.selectors().map_err(|error| {
            finality_read_error(error, Error::Invalid("ledger finality selectors"))
        })?;
        let initial = genesis.initial_epoch().authorization.epoch;
        if epoch > manifest.finality_epoch.unwrap_or(initial) {
            return Ok(OfferedOutcome::EpochRequired(height));
        }
        let (reader, _) = self.selected_commit_epoch(manifest, genesis, epoch)?;
        let verified = original
            .verify(&reader, genesis.chain_id(), signed)
            .map_err(|error| {
                finality_read_error(error, Error::Proof("ledger finality original"))
            })?;
        Ok(OfferedOutcome::Verified(verified))
    }

    /// Write the exact verified original. The caller selects it and its outcome record in
    /// one fenced manifest publication; an unselected written object grants nothing.
    pub(super) fn write_ledger_original(
        &mut self,
        verified: &VerifiedKagemushaLedgerOutcomeV1,
        bytes: &[u8],
    ) -> Result<LedgerOutcome, Error> {
        let outcome = LedgerOutcome {
            version: 1,
            entrypoint: verified.entrypoint(),
            accepted: verified.accepted(),
            height: verified.height(),
            commit_hash: verified.commit_hash(),
            finality: self
                .archive
                .write_object(bytes, KAGEMUSHA_WALLET_LEDGER_FINALITY_MAX_BYTES_V1)?,
        };
        outcome.require()?;
        Ok(outcome)
    }

    /// Recheck every custody binding of a retained outcome against its exact original, with
    /// no BLS: the archive digest, the canonical frame, the entrypoint recomputed by the caller
    /// from its retained wire, the decoded height and `CommitQC` block hash, the joined row's
    /// result and the shared leaf index. Any difference is lost custody, never an outcome.
    pub(super) fn retained_ledger_original(
        &mut self,
        outcome: &LedgerOutcome,
        entrypoint: &[u8; 32],
    ) -> Result<(), Error> {
        outcome.require()?;
        let bytes = self.archive.read_object(
            &outcome.finality,
            KAGEMUSHA_WALLET_LEDGER_FINALITY_MAX_BYTES_V1,
        )?;
        let original = read_model_original(
            || KagemushaWalletLedgerFinalityV1::decode_canonical(&bytes),
            Error::WitnessLost("ledger outcome original"),
        )?;
        let bindings = original.custody_bindings().map_err(|error| {
            finality_read_error(error, Error::WitnessLost("ledger outcome original"))
        })?;
        if outcome.entrypoint != *entrypoint
            || *original.entrypoint_hash.as_ref() != outcome.entrypoint
            || bindings.height != outcome.height
            || bindings.qc_block_hash != outcome.commit_hash
            || bindings.accepted != outcome.accepted
        {
            return Err(Error::WitnessLost("ledger outcome binding"));
        }
        Ok(())
    }

    /// Offer another original for an attempt whose first outcome is retained. Its exact
    /// original is idempotent without verification. A different original must verify to the
    /// same entrypoint, height, commit hash and result (honest peers may hold different exact
    /// quorum certificates for one block); it is never written and never replaces the first.
    pub(super) fn reconcile_ledger_original(
        &mut self,
        manifest: &manifest::Manifest,
        genesis: &SumeragiFinalityVerifier,
        retained: &LedgerOutcome,
        signed: &SignedTransaction,
        bytes: &[u8],
    ) -> Result<LedgerAttemptOutcomeV1, Error> {
        if crate::kagemusha_wallet_advance_v1::kagemusha_wallet_archive_object_digest_v1(bytes)
            == retained.finality
        {
            return Ok(retained.attempt());
        }
        match self.verify_ledger_original(manifest, genesis, signed, bytes)? {
            OfferedOutcome::Verified(verified) if retained.same(&verified) => {
                Ok(retained.attempt())
            }
            OfferedOutcome::Verified(_) => {
                Err(Error::Proof("conflicting authenticated ledger outcome"))
            }
            // The retained block's epoch is selected, so an unselected one is another block.
            OfferedOutcome::EpochRequired(_) => {
                Err(Error::Invalid("ledger finality original of another block"))
            }
        }
    }
}

#[cfg(test)]
impl LedgerOutcome {
    /// A copy with one custody binding changed; production never constructs one.
    pub(super) fn tampered(&self, binding: u8) -> Self {
        let mut value = *self;
        match binding {
            0 => value.accepted = !value.accepted,
            1 => value.height += 1,
            2 => value.commit_hash[0] ^= 1,
            3 => value.entrypoint[0] ^= 1,
            4 => value.finality[0] ^= 1,
            5 => value.version = 2,
            _ => value.height = 1,
        }
        value
    }
}

#[cfg(test)]
pub(super) mod tests;
