//! Transaction-bound ordinary finality custody, independent of the wallet's global tip.
use super::*;
use crate::kagemusha_wallet_state_v1::finality_read_error;
use iroha_data_model::sumeragi_finality::{
    SumeragiCheckpointAdvanceError, SumeragiFinalityCheckpoint, SumeragiFinalityProof,
};
const SESSION_MAX: usize = MAX_FINALITY_CHECKPOINT_BYTES + 1024;

#[derive(norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core_zk::kagemusha_wallet_state_v1::UnloadProofSessionV1")]
struct Session {
    transaction: [u8; 32],
    original_digest: [u8; 32],
    checkpoint: Vec<u8>,
}

impl Session {
    fn restore(
        &self,
        genesis: &SumeragiFinalityVerifier,
        transaction: &[u8; 32],
        original_digest: &[u8; 32],
    ) -> Result<(SumeragiFinalityVerifier, SumeragiFinalityCheckpoint), Error> {
        if self.transaction != *transaction || self.original_digest != *original_digest {
            return Err(Error::OperationConflict);
        }
        let checkpoint =
            SumeragiFinalityCheckpoint::decode_canonical(&self.checkpoint).map_err(|error| {
                finality_read_error(error, Error::WitnessLost("Unload cursor checkpoint"))
            })?;
        let verifier = SumeragiFinalityVerifier::from_trusted_checkpoint(
            &checkpoint,
            &genesis.initial_epoch().network_id,
            genesis.chain_id(),
        )
        .map_err(|error| {
            finality_read_error(
                error,
                Error::WitnessLost("Unload cursor checkpoint verification"),
            )
        })?;
        if verifier.initial_epoch() != genesis.initial_epoch()
            || verifier.instance() != genesis.instance()
        {
            return Err(Error::WitnessLost("Unload cursor genesis binding"));
        }
        Ok((verifier, checkpoint))
    }
}
fn next_checkpoint(
    verifier: SumeragiFinalityVerifier,
    previous: Option<&SumeragiFinalityCheckpoint>,
    candidate: &SumeragiFinalityProof,
) -> Result<(SumeragiFinalityCheckpoint, VerifiedSumeragiBlock, bool), Error> {
    if let Some(previous) = previous {
        if candidate.height() == previous.height() {
            let decision = verifier
                .verify_retained_decision(candidate)
                .map_err(|error| {
                    finality_read_error(error, Error::Proof("Unload cursor retry decision"))
                })?;
            return Ok((previous.clone(), decision, false));
        }
        if previous.height().checked_add(1) != Some(candidate.height()) {
            return Err(Error::Invalid("Unload cursor next height"));
        }
    } else if candidate.height() != 1 {
        return Err(Error::Invalid("Unload cursor requires genesis"));
    }
    let needs_contiguous_verification = if previous.is_some() {
        true
    } else {
        match verifier.verify_retained_decision(candidate) {
            Ok(_) => false,
            Err(iroha_data_model::sumeragi_finality::FinalityReadError::Invalid(_)) => true,
            Err(original) => {
                return Err(finality_read_error(
                    original,
                    Error::Proof("Unload cursor initial decision"),
                ));
            }
        }
    };
    let (checkpoint, decision) = if needs_contiguous_verification {
        // One exact native producer owns the candidate through continuity and bounded export.
        // Active cumulative decoder owners retain the original two-attempt admission recipe.
        verifier
            .advance_checkpoint_with_tip(candidate)
            .map_err(|error| match error {
                SumeragiCheckpointAdvanceError::Verify(original) => {
                    finality_read_error(original, Error::Proof("Unload cursor continuity"))
                }
                SumeragiCheckpointAdvanceError::Export(original) => {
                    finality_read_error(original, Error::Proof("Unload cursor checkpoint"))
                }
            })?
    } else {
        verifier
            .export_checkpoint_with_tip(candidate)
            .map_err(|error| finality_read_error(error, Error::Proof("Unload cursor checkpoint")))?
    };
    Ok((checkpoint, decision, true))
}

struct UnloadInclusion<'a> {
    scheme: [u8; 32],
    transaction: &'a [u8; 32],
    digest: &'a [u8; 32],
    original: &'a [u8],
}
impl UnloadInclusion<'_> {
    fn retain(
        &self,
        archive: &mut impl index::ObjectStore,
        confirmations: &mut index::IndexRoot,
        genesis: &SumeragiFinalityVerifier,
        decision: &VerifiedSumeragiBlock,
    ) -> Result<bool, Error> {
        if retained_unload_confirmation(archive, confirmations, self.transaction, self.digest)?
            .is_some()
        {
            return Ok(false);
        }
        // The cursor producer returns the exact native decision it has already verified.
        // Keep that opaque capability inside this call instead of rebuilding the same
        // checkpoint and verifying its tip twice more. Every supplied candidate still
        // passes native finality, and inclusion below still binds the exact claim bytes.
        if !contains_successful_unload(
            decision,
            &genesis.initial_epoch().network_id,
            self.scheme,
            self.transaction,
            self.original,
        )? {
            return Ok(false);
        }
        let confirmed = UnloadConfirmation {
            original_digest: *self.digest,
            height: decision.height(),
            block_hash: *decision.block().hash().as_ref(),
        };
        *confirmations =
            confirmations.set(archive, *self.transaction, &archive::encode(&confirmed)?)?;
        Ok(true)
    }
}

impl<F: KagemushaWalletFsV1, P: KagemushaWalletPlatformV1, S: OriginalSourceV1 + Send>
    Coordinator<AdvanceHandle<F, P>, ProviderArchive<F, P>, NativeWalletProofsV1<F, P, S>>
{
    pub(super) fn unload_original_digest(
        &self,
        transaction: &[u8; 32],
        original: &[u8],
    ) -> Result<[u8; 32], Error> {
        if *transaction == [0; 32]
            || original.is_empty()
            || original.len() > LEDGER_INSTRUCTION_MAX_BYTES_V1
        {
            return Err(Error::Invalid("Unload cursor input bound"));
        }
        let claim = read_model_original(
            || KagemushaWalletUnloadClaimV1::decode_canonical(original, &self.scheme_id),
            Error::Invalid("G1 validation"),
        )?;
        if claim.credential.body.wallet_id != self.wallet_id
            || claim.credential.body.account_digest != self.proofs.enrollment.body.account_digest
        {
            return Err(Error::Invalid("Unload cursor wallet scope"));
        }
        Ok(*iroha_crypto::Hash::new(original).as_ref())
    }
    pub(super) fn selected_unload_cursor(
        &mut self,
        manifest: &manifest::Manifest,
        transaction: &[u8; 32],
        original_digest: &[u8; 32],
    ) -> Result<(SumeragiFinalityVerifier, Option<SumeragiFinalityCheckpoint>), Error> {
        let genesis = &self.proofs.genesis;
        let (scheme, chain) = self.proofs.ledger_scope()?;
        if scheme.scheme_id() != self.scheme_id
            || chain != genesis.chain_id()
            || genesis.initial_epoch().network_id.as_bytes() != &scheme.network_id
            || genesis.root_scope() != iroha_data_model::block::consensus::SumeragiRootScope::Global
        {
            return Err(Error::Proof("Unload cursor root scope"));
        }
        let Some(address) = manifest
            .ledger_unload_proofs
            .get(&mut self.archive, transaction)?
        else {
            return Ok(((**genesis).clone(), None));
        };
        let address = address
            .try_into()
            .map_err(|_| Error::WitnessLost("Unload cursor index"))?;
        if manifest.ledger_unload_retired == Some((*transaction, address)) {
            return Err(Error::WitnessLost("Unload cursor selected retired object"));
        }
        let session: Session = archive::decode(&self.archive.read_object(&address, SESSION_MAX)?)?;
        let (verifier, checkpoint) = session.restore(genesis, transaction, original_digest)?;
        Ok((verifier, Some(checkpoint)))
    }
    fn clean_unload_cursor(&mut self) -> Result<(), Error> {
        let (selected, mut manifest) = self.sync_manifest()?;
        if let Some((transaction, address)) = manifest.ledger_unload_retired {
            if manifest
                .ledger_unload_proofs
                .get(&mut self.archive, &transaction)?
                .as_deref()
                == Some(address.as_slice())
            {
                return Err(Error::WitnessLost("Unload cleanup selects current cursor"));
            }
            self.archive.remove(ArchiveKey::Object(address))?;
            manifest.ledger_unload_retired = None;
            self.publish_manifest(selected, &manifest)?;
        }
        Ok(())
    }
    /// Read this exact transaction and claim's selected confirmation or ordinary finality cursor.
    /// Only an absent confirmation yields progress; malformed or mismatched retained DATA fails.
    /// # Errors
    /// Foreign/changed claim, missing checkpoint custody or invalid selected genesis.
    pub fn unload_finality_progress(
        &mut self,
        transaction: [u8; 32],
        original: &[u8],
    ) -> Result<UnloadFinalityProgressV1, Error> {
        let digest = self.unload_original_digest(&transaction, original)?;
        let (_, manifest) = self.sync_manifest()?;
        if let Some(confirmed) = retained_unload_confirmation(
            &mut self.archive,
            &manifest.ledger_unload_confirmations,
            &transaction,
            &digest,
        )? {
            return Ok(UnloadFinalityProgressV1::Confirmed(confirmed));
        }
        let (_, checkpoint) = self.selected_unload_cursor(&manifest, &transaction, &digest)?;
        Ok(checkpoint
            .as_ref()
            .map_or(UnloadFinalityProgressV1::NotStarted, |checkpoint| {
                UnloadFinalityProgressV1::Verifying(ledger::progress(checkpoint))
            }))
    }
    /// Verify and persist one exact next ordinary block for this Unload's own cursor.
    /// No caller height, HTTP status or proposed transaction supplies inclusion authority.
    /// # Errors
    /// Invalid prefix, changed original, unavailable custody or failed durable publication.
    pub fn ingest_unload_finality(
        &mut self,
        transaction: [u8; 32],
        original: &[u8],
        finality: &[u8],
    ) -> Result<LedgerProgressV1, Error> {
        let digest = self.unload_original_digest(&transaction, original)?;
        let candidate = ledger::proof_original(finality)?;
        self.clean_unload_cursor()?;
        let (selected, mut manifest) = self.sync_manifest()?;
        let (verifier, previous) = self.selected_unload_cursor(&manifest, &transaction, &digest)?;
        let (checkpoint, decision, changed) =
            next_checkpoint(verifier, previous.as_ref(), &candidate)?;
        // The returned checkpoint owns its exact tip; the input wire copies are
        // no longer needed during inclusion, encoding or durable publication.
        drop(candidate);
        drop(previous);
        // The HTTP locator may be later than the actual transaction. Retain inclusion
        // atomically with this prefix so a later cursor can never discard its evidence.
        // unload_original_digest already validated the claim and its owner scope.
        let confirmed = UnloadInclusion {
            scheme: self.scheme_id,
            transaction: &transaction,
            digest: &digest,
            original,
        }
        .retain(
            &mut self.archive,
            &mut manifest.ledger_unload_confirmations,
            &self.proofs.genesis,
            &decision,
        )?;
        // Inclusion retained only compact confirmation data. Release the decoded
        // block before checkpoint encoding, archive writes and manifest publication.
        drop(decision);
        if !changed {
            if confirmed {
                self.publish_manifest(selected, &manifest)?;
            }
            return Ok(ledger::progress(&checkpoint));
        }
        let session = Session {
            transaction,
            original_digest: digest,
            checkpoint: checkpoint
                .encode_canonical()
                .map_err(|_| Error::Proof("Unload checkpoint encoding"))?,
        };
        let bytes = archive::encode(&session)?;
        let address = self.archive.write_object(&bytes, SESSION_MAX)?;
        let old = manifest
            .ledger_unload_proofs
            .get(&mut self.archive, &transaction)?
            .map(|bytes| {
                bytes
                    .try_into()
                    .map_err(|_| Error::WitnessLost("Unload previous cursor"))
            })
            .transpose()?;
        manifest.ledger_unload_proofs =
            manifest
                .ledger_unload_proofs
                .set(&mut self.archive, transaction, &address)?;
        manifest.ledger_unload_retired = old
            .filter(|old| *old != address)
            .map(|old| (transaction, old));
        self.publish_manifest(selected, &manifest)?;
        self.clean_unload_cursor()?;
        Ok(ledger::progress(&checkpoint))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_data_model::sumeragi_finality::test_fixtures::NativeFinalityFixture;

    impl UnloadInclusion<'_> {
        // Tests which start from an independently selected checkpoint use the same full
        // importer and consume its authenticated tip without a second tip verification.
        fn retain_checkpoint_fixture(
            &self,
            archive: &mut impl index::ObjectStore,
            confirmations: &mut index::IndexRoot,
            genesis: &SumeragiFinalityVerifier,
            checkpoint: &SumeragiFinalityCheckpoint,
        ) -> Result<bool, Error> {
            let (_, decision) = SumeragiFinalityVerifier::from_trusted_checkpoint_with_tip(
                checkpoint,
                &genesis.initial_epoch().network_id,
                genesis.chain_id(),
            )
            .map_err(|error| finality_read_error(error, Error::Proof("Unload selected prefix")))?;
            self.retain(archive, confirmations, genesis, &decision)
        }
    }

    #[test]
    fn unload_cursor_returns_the_exact_authenticated_candidate_for_inclusion() {
        let mut native = NativeFinalityFixture::start("unload-verified-candidate-reuse");
        let genesis = native.verifier();
        let previous = native.checkpoint();
        let block = native.block_with_submitted_work(native.next_header());
        let candidate = native.certify(block);
        let (checkpoint, decision, changed) =
            next_checkpoint(genesis, Some(&previous), &candidate).unwrap();
        assert!(changed);
        assert_eq!(decision.height(), candidate.height());
        assert_eq!(
            decision.block().encode_wire().unwrap(),
            candidate.block_wire
        );
        assert_eq!(checkpoint.tip(), &candidate);
        let verifier = SumeragiFinalityVerifier::from_trusted_checkpoint(
            &checkpoint,
            &native.network_id(),
            native.chain_id(),
        )
        .unwrap();
        let (retry, decision, changed) =
            next_checkpoint(verifier.clone(), Some(&checkpoint), &candidate).unwrap();
        assert!(!changed);
        assert_eq!(
            retry.encode_canonical().unwrap(),
            checkpoint.encode_canonical().unwrap()
        );
        assert_eq!(
            decision.block().encode_wire().unwrap(),
            candidate.block_wire
        );
        let mut changed = candidate;
        changed.committee[0].proof_of_possession[0] ^= 1;
        assert!(next_checkpoint(verifier, Some(&checkpoint), &changed).is_err());
    }

    #[test]
    fn unload_cursor_advance_preserves_refusal_category_and_exact_retry() {
        let mut native = NativeFinalityFixture::start("unload-advance-refusal");
        let genesis = native.verifier();
        let previous = native.checkpoint();
        let block = native.block_with_submitted_work(native.next_header());
        let candidate = native.certify(block);
        let original = norito::encode_canonical(&candidate).unwrap();
        let expected = native.checkpoint();
        let limits = norito::DecodeLimits::new(usize::MAX, 0, usize::MAX, usize::MAX, 64);
        let refused = norito::with_decode_limits_scope(limits, || {
            next_checkpoint(genesis.clone(), Some(&previous), &candidate)
        });
        assert!(matches!(refused, Err(Error::DecodeResource(ref cause))
            if cause.kind() == norito::core::DecodeLocalRefusalKind::EnclosingLimit));
        let mut invalid = candidate.clone();
        invalid.committee[0].proof_of_possession[0] ^= 1;
        assert!(matches!(
            next_checkpoint(genesis.clone(), Some(&previous), &invalid),
            Err(Error::Proof("Unload cursor continuity"))
        ));
        assert_eq!(norito::encode_canonical(&candidate).unwrap(), original);
        let (retried, decision, changed) =
            next_checkpoint(genesis, Some(&previous), &candidate).unwrap();
        assert!(changed);
        assert_eq!(retried, expected);
        assert_eq!(
            decision.block().encode_wire().unwrap(),
            candidate.block_wire
        );
    }

    /// Host diagnostic for the removed redundant native-finality work; no device SLA claim.
    #[test]
    #[ignore = "host timing diagnostic; run explicitly with --ignored --nocapture"]
    fn unload_finality_inclusion_reuse_timing() {
        use crate::kagemusha_wallet_state_v1::tests::MemoryArchive;
        use std::time::{Duration, Instant};
        let mut native = NativeFinalityFixture::start("unload-inclusion-reuse-timing");
        let genesis = native.verifier();
        let previous = native.checkpoint();
        let block = native.block_with_submitted_work(native.next_header());
        let candidate = native.certify(block);
        let inclusion = UnloadInclusion {
            scheme: [1; 32],
            transaction: &[2; 32],
            digest: &[3; 32],
            original: b"absent transaction claim",
        };
        let mut baseline = Duration::ZERO;
        let mut optimized = Duration::ZERO;
        for sample in 0..6 {
            for old_path in [true, false] {
                let start = Instant::now();
                let (checkpoint, decision, _) =
                    next_checkpoint(genesis.clone(), Some(&previous), &candidate).unwrap();
                let decision = if old_path {
                    // Reproduce the original caller's full checkpoint import followed by
                    // a separate tip verification, with exactly the same genuine BLS input.
                    drop(decision);
                    let restored = SumeragiFinalityVerifier::from_trusted_checkpoint(
                        &checkpoint,
                        &native.network_id(),
                        native.chain_id(),
                    )
                    .unwrap();
                    restored.verify_retained_decision(checkpoint.tip()).unwrap()
                } else {
                    decision
                };
                assert!(
                    !inclusion
                        .retain(
                            &mut MemoryArchive::new(),
                            &mut index::IndexRoot::default(),
                            &genesis,
                            &decision,
                        )
                        .unwrap()
                );
                if sample != 0 {
                    if old_path {
                        baseline += start.elapsed();
                    } else {
                        optimized += start.elapsed();
                    }
                }
            }
        }
        eprintln!(
            "UNLOAD_FINALITY_REUSE samples=5 block_bytes={} duplicated_ms={:.3} reused_ms={:.3} speedup={:.3}",
            candidate.block_wire.len(),
            baseline.as_secs_f64() * 200.0,
            optimized.as_secs_f64() * 200.0,
            baseline.as_secs_f64() / optimized.as_secs_f64(),
        );
    }

    #[test]
    fn selected_unload_decision_preserves_actual_read_refusal_and_exact_retry() {
        // Actual native BLS decisions; this is a read/refusal control, not a ledger
        // Unload execution fixture. The public settlement continuations cover inclusion.
        let mut native = NativeFinalityFixture::start("selected-unload-decision-refusal");
        let block = native.block_with_submitted_work(native.next_header());
        native.certify(block);
        let verifier = native.verifier();
        let checkpoint = native.checkpoint();
        let tip = checkpoint.tip();
        let original = norito::encode_canonical(tip).unwrap();
        let expected = selected_unload_decision(&verifier, tip).unwrap();
        for limits in [
            norito::DecodeLimits::new(usize::MAX, 0, usize::MAX, usize::MAX, 64),
            norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 64),
        ] {
            let refused = norito::with_decode_limits_scope(limits, || {
                selected_unload_decision(&verifier, tip)
            });
            assert!(matches!(refused, Err(Error::DecodeResource(ref cause))
                if cause.kind() == norito::core::DecodeLocalRefusalKind::EnclosingLimit));
            assert_eq!(norito::encode_canonical(tip).unwrap(), original);
            assert_eq!(
                selected_unload_decision(&verifier, tip)
                    .unwrap()
                    .block()
                    .hash(),
                expected.block().hash()
            );
        }
        let mut malformed = tip.clone();
        malformed.block_wire = vec![0];
        assert!(matches!(
            selected_unload_decision(&verifier, &malformed),
            Err(Error::Proof("Unload selected native decision"))
        ));
        assert_eq!(
            selected_unload_decision(&verifier, tip)
                .unwrap()
                .block()
                .hash(),
            expected.block().hash()
        );
    }

    #[test]
    fn unload_cursor_read_refusal_keeps_exact_checkpoint_for_retry() {
        let native = NativeFinalityFixture::start("unload-cursor-read-refusal");
        let genesis = native.verifier();
        let session = Session {
            transaction: [1; 32],
            original_digest: [2; 32],
            checkpoint: native.checkpoint().encode_canonical().unwrap(),
        };
        let original = session.checkpoint.clone();
        let limits = norito::DecodeLimits::new(usize::MAX, 0, usize::MAX, usize::MAX, 64);
        let refused = norito::with_decode_limits_scope(limits, || {
            session.restore(&genesis, &[1; 32], &[2; 32])
        });
        assert!(matches!(refused, Err(Error::DecodeResource(ref cause))
            if cause.kind() == norito::core::DecodeLocalRefusalKind::EnclosingLimit));
        assert_eq!(session.checkpoint, original);
        let (_, checkpoint) = session.restore(&genesis, &[1; 32], &[2; 32]).unwrap();
        assert_eq!(checkpoint.encode_canonical().unwrap(), original);
        let broken = Session {
            checkpoint: vec![0],
            ..session
        };
        assert!(matches!(
            broken.restore(&genesis, &[1; 32], &[2; 32]),
            Err(Error::WitnessLost(_))
        ));
    }

    #[test]
    fn unload_checkpoint_initial_and_retry_refusals_do_not_become_proof_verdicts() {
        let native = NativeFinalityFixture::start("unload-checkpoint-refusal");
        let genesis = native.verifier();
        let candidate = native.genesis_proof();
        let original = norito::encode_canonical(candidate).unwrap();
        let (checkpoint, _, changed) = next_checkpoint(genesis.clone(), None, candidate).unwrap();
        assert!(changed);
        let limits = norito::DecodeLimits::new(usize::MAX, 0, usize::MAX, usize::MAX, 64);
        for previous in [None, Some(&checkpoint)] {
            let refused = norito::with_decode_limits_scope(limits, || {
                next_checkpoint(genesis.clone(), previous, candidate)
            });
            assert!(matches!(refused, Err(Error::DecodeResource(ref cause))
                if cause.kind() == norito::core::DecodeLocalRefusalKind::EnclosingLimit));
            assert_eq!(norito::encode_canonical(candidate).unwrap(), original);
            let (retried, _, changed) =
                next_checkpoint(genesis.clone(), previous, candidate).unwrap();
            assert_eq!(changed, previous.is_none());
            assert_eq!(
                retried.encode_canonical().unwrap(),
                checkpoint.encode_canonical().unwrap()
            );
        }
    }

    #[test]
    fn unload_settlement_read_distinguishes_absence_from_corrupt_or_foreign_confirmation() {
        use crate::kagemusha_wallet_state_v1::tests::MemoryArchive;

        let mut archive = MemoryArchive::new();
        let mut confirmations = index::IndexRoot::default();
        let transaction = [41; 32];
        let digest = [42; 32];
        assert_eq!(
            retained_unload_confirmation(&mut archive, &confirmations, &transaction, &digest)
                .unwrap(),
            None
        );
        let original = archive::encode(&UnloadConfirmation {
            original_digest: digest,
            height: 2,
            block_hash: [43; 32],
        })
        .unwrap();
        confirmations = confirmations
            .set(&mut archive, transaction, &original)
            .unwrap();
        let selected = archive::encode(&confirmations).unwrap();
        let restored = archive::decode(&selected).unwrap();
        let expected = Some(LedgerProgressV1 {
            height: 2,
            block_hash: [43; 32],
        });
        assert_eq!(
            retained_unload_confirmation(&mut archive, &restored, &transaction, &digest).unwrap(),
            expected
        );
        assert!(
            retained_unload_confirmation(&mut archive, &restored, &transaction, &[44; 32]).is_err()
        );
        assert_eq!(
            retained_unload_confirmation(&mut archive, &restored, &[45; 32], &digest).unwrap(),
            None
        );
        for invalid in [
            vec![0xff],
            archive::encode(&UnloadConfirmation {
                original_digest: digest,
                height: 1,
                block_hash: [43; 32],
            })
            .unwrap(),
            archive::encode(&UnloadConfirmation {
                original_digest: digest,
                height: 2,
                block_hash: [0; 32],
            })
            .unwrap(),
        ] {
            let corrupt = confirmations
                .set(&mut archive, transaction, &invalid)
                .unwrap();
            assert!(
                retained_unload_confirmation(&mut archive, &corrupt, &transaction, &digest)
                    .is_err()
            );
            assert_eq!(
                confirmations.get(&mut archive, &transaction).unwrap(),
                Some(original.clone())
            );
        }
    }

    #[test]
    fn unload_confirmation_survives_overshooting_locator_with_genuine_certificates() {
        use crate::kagemusha_wallet_state_v1::tests::MemoryArchive;
        use iroha_crypto::{Algorithm, KeyPair};
        use iroha_data_model::{
            account::AccountId,
            block::{BlockSignatures, builder::BlockBuilder},
            transaction::{FeePaymentIntent, TransactionBuilder},
        };
        // Structural inclusion/custody test: model-valid claim with stand-in wallet proofs,
        // genuine signatures/native certificates, and explicitly synthetic execution outputs.
        // This does not execute a World Unload; it checks relayed exact-byte inclusion.
        let mut native = NativeFinalityFixture::start("unload-overshooting-locator");
        let genesis = native.verifier();
        let previous = native.checkpoint();
        let signer = KeyPair::from_seed(vec![79; 32], Algorithm::Ed25519);
        let account = AccountId::new(signer.public_key().clone());
        let claim: KagemushaWalletUnloadClaimV1 =
            crate::kagemusha_wallet_state_v1::tests::fixture("KagemushaWalletUnloadClaimV1");
        assert_ne!(
            claim.account, account,
            "the submitter only relays this claim"
        );
        let scheme = claim.credential.body.scheme_id;
        let original_bytes = claim.to_canonical_bytes().unwrap();
        let original = original_bytes.as_slice();
        let digest = *iroha_crypto::Hash::new(original).as_ref();
        let header = native.next_header();
        let mut tx = TransactionBuilder::new(
            native.network_id(),
            account.clone(),
            FeePaymentIntent::authority(vec![], None),
        );
        tx.set_creation_time(std::time::Duration::from_millis(
            header.creation_time_ms - 1,
        ));
        let tx = tx
            .with_instructions([KagemushaWalletLedgerV1 {
                scheme,
                action: KagemushaWalletLedgerActionV1::Unload(original.to_vec()),
            }])
            .sign(signer.private_key());
        let mut builder = BlockBuilder::new(header);
        builder.push_transaction(tx);
        let mut block = builder.build(BlockSignatures::default());
        NativeFinalityFixture::install_network_results(&mut block, vec![Ok(Vec::new())]);
        let transaction = *block.network_entrypoint_at(0).unwrap().hash().as_ref();
        native.certify(block);
        let two = native.checkpoint();
        let (exported, verified, changed) =
            next_checkpoint(genesis.clone(), Some(&previous), two.tip()).unwrap();
        assert!(changed);
        assert_eq!(exported, two);
        let inclusion = UnloadInclusion {
            scheme,
            transaction: &transaction,
            digest: &digest,
            original,
        };
        let mut archive = MemoryArchive::new();
        let mut confirmations = index::IndexRoot::default();
        let unchanged = confirmations;
        let limits = norito::DecodeLimits::new(usize::MAX, 0, usize::MAX, usize::MAX, 64);
        let refused = norito::with_decode_limits_scope(limits, || {
            inclusion.retain_checkpoint_fixture(&mut archive, &mut confirmations, &genesis, &two)
        });
        assert!(matches!(refused, Err(Error::DecodeResource(ref cause))
            if cause.kind() == norito::core::DecodeLocalRefusalKind::EnclosingLimit));
        assert_eq!(confirmations, unchanged);
        assert!(
            inclusion
                .retain(&mut archive, &mut confirmations, &genesis, &verified)
                .unwrap()
        );
        let selected = archive::encode(&confirmations).unwrap();
        let exact = confirmations
            .get(&mut archive, &transaction)
            .unwrap()
            .unwrap();
        assert!(
            contains_successful_unload(
                &verified,
                &native.network_id(),
                scheme,
                &transaction,
                b"substituted claim"
            )
            .is_err()
        );
        assert!(
            contains_successful_unload(
                &verified,
                &native.network_id(),
                [92; 32],
                &transaction,
                original
            )
            .is_err()
        );
        assert!(
            !contains_successful_unload(
                &verified,
                &native.network_id(),
                scheme,
                &[93; 32],
                original
            )
            .unwrap()
        );
        // Relaying never authorizes changing the claim's paid account. Canonical claim
        // validation still binds it to the credential, and inclusion requires exact bytes.
        let mut changed_account = claim.clone();
        changed_account.account = account.clone();
        let changed_account = archive::encode(&changed_account).unwrap();
        assert!(KagemushaWalletUnloadClaimV1::decode_canonical(&changed_account, &scheme).is_err());
        assert!(
            contains_successful_unload(
                &verified,
                &native.network_id(),
                scheme,
                &transaction,
                &changed_account
            )
            .is_err()
        );
        let mut changed_claim = claim.clone();
        changed_claim.version = 2;
        let changed_claim = archive::encode(&changed_claim).unwrap();
        assert!(KagemushaWalletUnloadClaimV1::decode_canonical(&changed_claim, &scheme).is_err());
        assert!(
            contains_successful_unload(
                &verified,
                &native.network_id(),
                scheme,
                &transaction,
                &changed_claim
            )
            .is_err()
        );
        assert!(
            contains_successful_unload(
                &verified,
                &native.network_id(),
                scheme,
                &transaction,
                original
            )
            .unwrap()
        );
        let block = native.block_with_submitted_work(native.next_header());
        native.certify(block);
        let three = native.checkpoint();
        assert!(
            !contains_successful_unload(
                &native
                    .verifier()
                    .verify_retained_decision(three.tip())
                    .unwrap(),
                &native.network_id(),
                scheme,
                &transaction,
                original
            )
            .unwrap()
        );
        // Simulated restart restores the selected immutable index, then processes the
        // later HTTP-located block. The exact earlier confirmation remains unchanged.
        let mut confirmations: index::IndexRoot = archive::decode(&selected).unwrap();
        assert!(
            !inclusion
                .retain_checkpoint_fixture(&mut archive, &mut confirmations, &genesis, &three)
                .unwrap()
        );
        assert_eq!(
            confirmations
                .get(&mut archive, &transaction)
                .unwrap()
                .unwrap(),
            exact
        );
        let confirmation: UnloadConfirmation = archive::decode(&exact).unwrap();
        assert_eq!(confirmation.height, 2);
        assert_eq!(confirmation.block_hash, ledger::progress(&two).block_hash);
        assert_eq!(
            retained_unload_confirmation(&mut archive, &confirmations, &transaction, &digest)
                .unwrap(),
            Some(ledger::progress(&two))
        );
        let changed = UnloadInclusion {
            digest: &[94; 32],
            ..inclusion
        };
        assert!(
            changed
                .retain_checkpoint_fixture(&mut archive, &mut confirmations, &genesis, &three)
                .is_err()
        );
        // Even a certified rejected output never earns a successful confirmation.
        let before_rejected = native.verifier();
        let header = native.next_header();
        let mut tx = TransactionBuilder::new(
            native.network_id(),
            account.clone(),
            FeePaymentIntent::authority(vec![], None),
        );
        tx.set_creation_time(std::time::Duration::from_millis(
            header.creation_time_ms - 1,
        ));
        let tx = tx
            .with_instructions([KagemushaWalletLedgerV1 {
                scheme,
                action: KagemushaWalletLedgerActionV1::Unload(original.to_vec()),
            }])
            .sign(signer.private_key());
        let mut builder = BlockBuilder::new(header);
        builder.push_transaction(tx);
        let mut block = builder.build(BlockSignatures::default());
        NativeFinalityFixture::install_network_results(
            &mut block,
            vec![Err(
                iroha_data_model::transaction::error::TransactionRejectionReason::LimitCheck(
                    iroha_data_model::transaction::error::TransactionLimitError {
                        reason: "explicit synthetic rejection".into(),
                    },
                ),
            )],
        );
        let rejected = *block.network_entrypoint_at(0).unwrap().hash().as_ref();
        native.certify(block);
        let rejected_checkpoint = native.checkpoint();
        let (_, rejected_decision, changed) =
            next_checkpoint(before_rejected, Some(&three), rejected_checkpoint.tip()).unwrap();
        assert!(changed);
        let rejected = UnloadInclusion {
            transaction: &rejected,
            digest: &digest,
            original,
            scheme,
        };
        let before = confirmations;
        assert!(
            rejected
                .retain(
                    &mut archive,
                    &mut confirmations,
                    &genesis,
                    &rejected_decision
                )
                .is_err()
        );
        assert_eq!(confirmations, before);
    }

    #[test]
    fn unload_cursor_restores_exact_older_history_with_genuine_certificates() {
        let mut native = NativeFinalityFixture::start("unload-independent-cursor");
        let genesis = native.verifier();
        let (one, _, changed) =
            next_checkpoint(genesis.clone(), None, native.genesis_proof()).unwrap();
        assert!(changed);
        let mut verifier = SumeragiFinalityVerifier::from_trusted_checkpoint(
            &one,
            &native.network_id(),
            native.chain_id(),
        )
        .unwrap();
        let block = native.block_with_submitted_work(native.next_header());
        let two = native.certify(block);
        let (two_checkpoint, _, _) = next_checkpoint(verifier.clone(), Some(&one), &two).unwrap();
        let session = Session {
            transaction: [1; 32],
            original_digest: [2; 32],
            checkpoint: two_checkpoint.encode_canonical().unwrap(),
        };
        let block = native.block_with_submitted_work(native.next_header());
        let three = native.certify(block);
        // Another consumer advanced its independent history. This retained original still
        // authenticates the older target, and exact retry cannot move or recreate it.
        verifier.verify(&two).unwrap();
        verifier.verify(&three).unwrap();
        let (older, restored) = session.restore(&genesis, &[1; 32], &[2; 32]).unwrap();
        assert_eq!(restored.height(), 2);
        assert!(older.verify_retained_decision(&two).is_ok());
        assert!(!next_checkpoint(older, Some(&restored), &two).unwrap().2);
        assert!(session.restore(&genesis, &[3; 32], &[2; 32]).is_err());
        assert!(session.restore(&genesis, &[1; 32], &[3; 32]).is_err());
        let foreign = NativeFinalityFixture::start("foreign-unload-cursor");
        assert!(
            session
                .restore(&foreign.verifier(), &[1; 32], &[2; 32])
                .is_err()
        );
        assert!(next_checkpoint(genesis.clone(), None, &two).is_err());
        assert!(next_checkpoint(genesis, Some(&one), &three).is_err());
        let mut broken = two;
        broken.block_wire[0] ^= 1;
        let (older, restored) = session
            .restore(&native.verifier(), &[1; 32], &[2; 32])
            .unwrap();
        assert!(next_checkpoint(older, Some(&restored), &broken).is_err());
    }
}
