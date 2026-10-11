//! Source-selected ownership and fold progress; a snapshot grants no operation permission.

use super::*;
use crate::kagemusha_wallet_advance_v1::kagemusha_wallet_archive_checkpoint_digest_v1;

/// Exact last indexed Ω, verified against its own retained head and the wallet incarnation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotFold {
    /// Sequence covered by this source-selected fold.
    pub sequence: u128,
    /// Exact covered head commitment.
    pub head: [u8; 32],
    /// Credential selected by that head; renewal may change the current credential digest.
    pub credential_digest: [u8; 32],
    /// Cumulative P4 burns verified by this fold.
    pub burned_total: u128,
}

/// Source-retained ownership and local proof progress (§PC/P1a/P1b/P4).
///
/// Owned value is current gross value minus known burns. An unfinished Receive fold may
/// discover a P4 burn, increasing known burns without changing the selected state head.
/// `folded_balance` is present only when Ω covers this exact current head. Even then, it
/// grants no Send/Unload/Request readiness: lifecycle, controls, authentication and each
/// native operation's rules remain authoritative. Retiring is not an automatic spend ban.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Snapshot {
    /// Native-selected scheme.
    pub scheme_id: [u8; 32],
    /// Native-selected wallet incarnation.
    pub wallet_id: [u8; 32],
    /// Exact current retained head commitment.
    pub head: [u8; 32],
    /// Exact current retained credential digest.
    pub credential_digest: [u8; 32],
    /// Current retained head sequence.
    pub sequence: u128,
    /// Current state lifecycle, including Retiring remaining-value custody.
    pub lifecycle: KagemushaWalletLifecycleV1,
    /// Gross value from the retained state; lineage burns are accounted separately.
    pub balance: u128,
    /// Burn total last resynchronized into this retained state core.
    pub core_burned_total: u128,
    /// Last verified fold's cumulative burns, or the actual retained core value before Ω.
    pub known_burned_total: u128,
    /// Gross value minus known burns, computed with checked arithmetic in Native only.
    pub owned_balance: u128,
    /// Value with Ω of this exact current head; absent while any head remains unfolded.
    pub folded_balance: Option<u128>,
    /// Number of released heads still needing local folds, including Bootstrap when unproved.
    pub fold_backlog: u128,
    /// Exact source-indexed verified fold; absent only when the source manifest has none.
    pub verified_fold: Option<SnapshotFold>,
}

impl<C: Custody, A: ArchiveStore, N: NativeProofs> Coordinator<C, A, N> {
    /// Read current retained ownership and exact source-indexed fold progress.
    ///
    /// Only the current and last-folded indexed heads are read. Recovery may index an
    /// interrupted unindexed tail through the existing bounded streaming path; permanent
    /// history is never scanned or accumulated. Full marker and original manifest selection
    /// are rechecked after witness/proof reads, including metadata-only generation changes.
    ///
    /// # Errors
    /// Pending, unavailable/uncertain custody, no released head, missing witnesses, invalid
    /// proof, source changes and underflow return errors without any monetary projection.
    pub fn snapshot(&mut self) -> Result<Snapshot, Error> {
        let (manifest_digest, manifest) = self.sync_manifest()?;
        let status = self.status()?;
        let SlotStatus::Released(marker) = &status else {
            return Err(if matches!(status, SlotStatus::Pending(_)) {
                Error::Pending
            } else {
                Error::NoHead
            });
        };
        let original_manifest = self
            .custody
            .archive_checkpoint()?
            .ok_or(Error::WitnessLost("snapshot manifest"))?;
        if original_manifest.1.len()
            > crate::kagemusha_wallet_advance_v1::KAGEMUSHA_WALLET_ARCHIVE_MANIFEST_MAX_BYTES_V1
            || original_manifest.0 != manifest_digest
            || kagemusha_wallet_archive_checkpoint_digest_v1(&original_manifest.1)
                != manifest_digest
            || original_manifest.1 != archive::encode(&manifest)?
            || marker.archive_checkpoint() != manifest_digest
        {
            return Err(Error::WitnessLost("snapshot source manifest"));
        }
        let (sequence, operation, capsule_digest) = marker.head().ok_or(Error::NoHead)?;
        if manifest.indexed != Some(sequence) || manifest.capsule != capsule_digest {
            return Err(Error::WitnessLost("snapshot selected index"));
        }
        let current = self.indexed_step(&manifest, sequence)?;
        let capsule = &current.frozen.capsule;
        let head = match marker.marker().state {
            KagemushaWalletMarkerStateV1::Head { head, .. } => head.value,
            _ => return Err(Error::NoHead),
        };
        if capsule.statement.successor.value != head
            || current.retained.operation_id != operation
            || marker.selected_generation() != Some(current.retained.selected_generation)
            || marker.completion_digest() != Some(current.retained.completion_digest)
            || marker.payment_key() != &current.frozen.credential.body.payment_key
        {
            return Err(Error::WitnessLost("snapshot selected head"));
        }
        let state = &capsule.successor_state;
        let core = &state.core;
        let (verified_fold, known_burned_total, folded_balance, fold_backlog) =
            if let Some(folded_sequence) = manifest.folded {
                if folded_sequence > sequence {
                    return Err(Error::WitnessLost("snapshot future fold"));
                }
                let folded_step = if folded_sequence == sequence {
                    current.clone()
                } else {
                    self.indexed_step(&manifest, folded_sequence)?
                };
                let a = &folded_step.frozen.credential.body;
                let b = &current.frozen.credential.body;
                if a.scheme_id != b.scheme_id
                    || a.asset_digest != b.asset_digest
                    || a.wallet_id != b.wallet_id
                    || a.account_digest != b.account_digest
                    || a.payment_key != b.payment_key
                    || a.provider_contract != b.provider_contract
                    || a.enrollment_id != b.enrollment_id
                {
                    return Err(Error::WitnessLost("snapshot fold incarnation"));
                }
                let fold = self
                    .read_fold(&folded_step)?
                    .ok_or(Error::WitnessLost("snapshot indexed fold"))?;
                let public = &fold.record.lineage.public;
                let folded_core = &folded_step.frozen.capsule.successor_state.core;
                if public.burned_total < folded_core.burned_total
                    || public.burned_total < core.burned_total
                {
                    return Err(Error::WitnessLost("snapshot burn regression"));
                }
                // This also authenticates the exact folded head/wallet/credential and rejects
                // burns above that head's own gross balance, even for an indexed ancestor.
                let covered_balance = valid(
                    folded_step
                        .frozen
                        .capsule
                        .successor_state
                        .spendable_with(public),
                )?;
                let snapshot_fold = SnapshotFold {
                    sequence: folded_sequence,
                    head: public.head.value,
                    credential_digest: public.credential_digest,
                    burned_total: public.burned_total,
                };
                (
                    Some(snapshot_fold),
                    public.burned_total,
                    (folded_sequence == sequence).then_some(covered_balance),
                    sequence
                        .checked_sub(folded_sequence)
                        .ok_or(Error::Invalid("snapshot backlog"))?,
                )
            } else {
                (
                    None,
                    core.burned_total,
                    None,
                    sequence
                        .checked_add(1)
                        .ok_or(Error::Invalid("snapshot backlog overflow"))?,
                )
            };
        let owned_balance = core
            .balance
            .checked_sub(known_burned_total)
            .ok_or(Error::Invalid("snapshot owned balance"))?;
        let snapshot = Snapshot {
            scheme_id: self.scheme_id,
            wallet_id: self.wallet_id,
            head,
            credential_digest: core.credential_digest,
            sequence,
            lifecycle: core.lifecycle,
            balance: core.balance,
            core_burned_total: core.burned_total,
            known_burned_total,
            owned_balance,
            folded_balance,
            fold_backlog,
            verified_fold,
        };
        // Neither a protected-data error nor a different source selection is an empty wallet.
        if self.status()? != status {
            return Err(Error::WitnessLost("snapshot source marker changed"));
        }
        let (final_digest, _) = self.manifest()?;
        let final_manifest = self
            .custody
            .archive_checkpoint()?
            .ok_or(Error::WitnessLost("snapshot manifest changed"))?;
        if final_digest != manifest_digest
            || final_manifest.1.len()
                > crate::kagemusha_wallet_advance_v1::KAGEMUSHA_WALLET_ARCHIVE_MANIFEST_MAX_BYTES_V1
            || final_manifest != original_manifest
        {
            return Err(Error::WitnessLost("snapshot source manifest changed"));
        }
        // A metadata read may itself cross a storage lock or custody generation boundary.
        if self.status()? != status {
            return Err(Error::WitnessLost("snapshot source marker changed"));
        }
        Ok(snapshot)
    }
}
