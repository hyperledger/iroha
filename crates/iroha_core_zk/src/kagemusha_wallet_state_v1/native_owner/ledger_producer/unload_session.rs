//! Transaction-bound ordinary finality custody, independent of the wallet's global tip.
use super::*;
use iroha_data_model::sumeragi_finality::{SumeragiFinalityCheckpoint, SumeragiFinalityProof};
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
        let checkpoint = SumeragiFinalityCheckpoint::decode_canonical(&self.checkpoint)
            .map_err(|_| Error::WitnessLost("Unload cursor checkpoint"))?;
        let verifier = SumeragiFinalityVerifier::from_trusted_checkpoint(
            &checkpoint,
            &genesis.initial_epoch().network_id,
            &genesis.chain_id(),
        )
        .map_err(|_| Error::WitnessLost("Unload cursor checkpoint verification"))?;
        if verifier.initial_epoch() != genesis.initial_epoch()
            || verifier.instance() != genesis.instance()
        {
            return Err(Error::WitnessLost("Unload cursor genesis binding"));
        }
        Ok((verifier, checkpoint))
    }
}
fn next_checkpoint(
    mut verifier: SumeragiFinalityVerifier,
    previous: Option<&SumeragiFinalityCheckpoint>,
    candidate: &SumeragiFinalityProof,
) -> Result<(SumeragiFinalityCheckpoint, bool), Error> {
    if let Some(previous) = previous {
        if candidate.height() == previous.height() {
            verifier
                .verify_retained_decision(candidate)
                .map_err(|_| Error::Proof("Unload cursor retry decision"))?;
            return Ok((previous.clone(), false));
        }
        if previous.height().checked_add(1) != Some(candidate.height()) {
            return Err(Error::Invalid("Unload cursor next height"));
        }
    } else if candidate.height() != 1 {
        return Err(Error::Invalid("Unload cursor requires genesis"));
    }
    if previous.is_some() || verifier.verify_retained_decision(candidate).is_err() {
        verifier
            .verify(candidate)
            .map_err(|_| Error::Proof("Unload cursor continuity"))?;
    }
    let checkpoint = verifier
        .export_checkpoint(candidate)
        .map_err(|_| Error::Proof("Unload cursor checkpoint"))?;
    Ok((checkpoint, true))
}

struct UnloadInclusion<'a> {
    scheme: [u8; 32],
    account: &'a iroha_data_model::account::AccountId,
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
        checkpoint: &SumeragiFinalityCheckpoint,
    ) -> Result<bool, Error> {
        if retained_unload_confirmation(archive, confirmations, self.transaction, self.digest)?
            .is_some()
        {
            return Ok(false);
        }
        let verifier = SumeragiFinalityVerifier::from_trusted_checkpoint(
            checkpoint,
            &genesis.initial_epoch().network_id,
            &genesis.chain_id(),
        )
        .map_err(|_| Error::Proof("Unload selected prefix"))?;
        let verified = verifier
            .verify_retained_decision(checkpoint.tip())
            .map_err(|_| Error::Proof("Unload selected native decision"))?;
        if !contains_successful_unload(
            &verified,
            &genesis.initial_epoch().network_id,
            self.scheme,
            self.account,
            self.transaction,
            self.original,
        )? {
            return Ok(false);
        }
        let progress = ledger::progress(checkpoint);
        let confirmed = UnloadConfirmation {
            original_digest: *self.digest,
            height: progress.height,
            block_hash: progress.block_hash,
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
        let claim = valid(KagemushaWalletUnloadClaimV1::decode_canonical(
            original,
            &self.scheme_id,
        ))?;
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
        let _payment = self.scheduler.payment();
        let digest = self.unload_original_digest(&transaction, original)?;
        let candidate = ledger::proof_original(finality)?;
        self.clean_unload_cursor()?;
        let (selected, mut manifest) = self.sync_manifest()?;
        let (verifier, previous) = self.selected_unload_cursor(&manifest, &transaction, &digest)?;
        let (checkpoint, changed) = next_checkpoint(verifier, previous.as_ref(), &candidate)?;
        // The HTTP locator may be later than the actual transaction. Retain inclusion
        // atomically with this prefix so a later cursor can never discard its evidence.
        let claim = valid(KagemushaWalletUnloadClaimV1::decode_canonical(
            original,
            &self.scheme_id,
        ))?;
        let confirmed = UnloadInclusion {
            scheme: self.scheme_id,
            account: &claim.account,
            transaction: &transaction,
            digest: &digest,
            original,
        }
        .retain(
            &mut self.archive,
            &mut manifest.ledger_unload_confirmations,
            &self.proofs.genesis,
            &checkpoint,
        )?;
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
        // Structural inclusion/custody test: genuine signatures and native certificates,
        // explicitly synthetic execution outputs; this does not execute a World Unload.
        let mut native = NativeFinalityFixture::start("unload-overshooting-locator");
        let genesis = native.verifier();
        let signer = KeyPair::from_seed(vec![79; 32], Algorithm::Ed25519);
        let account = AccountId::new(signer.public_key().clone());
        let scheme = [91; 32];
        let original = b"exact original used only by this inclusion fixture";
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
        let inclusion = UnloadInclusion {
            scheme,
            account: &account,
            transaction: &transaction,
            digest: &digest,
            original,
        };
        let mut archive = MemoryArchive::new();
        let mut confirmations = index::IndexRoot::default();
        assert!(
            inclusion
                .retain(&mut archive, &mut confirmations, &genesis, &two)
                .unwrap()
        );
        let selected = archive::encode(&confirmations).unwrap();
        let exact = confirmations
            .get(&mut archive, &transaction)
            .unwrap()
            .unwrap();
        let verified = native
            .verifier()
            .verify_retained_decision(two.tip())
            .unwrap();
        assert!(
            contains_successful_unload(
                &verified,
                &native.network_id(),
                scheme,
                &account,
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
                &account,
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
                &account,
                &[93; 32],
                original
            )
            .unwrap()
        );
        let foreign = AccountId::new(
            KeyPair::from_seed(vec![80; 32], Algorithm::Ed25519)
                .public_key()
                .clone(),
        );
        assert!(
            contains_successful_unload(
                &verified,
                &native.network_id(),
                scheme,
                &foreign,
                &transaction,
                original
            )
            .is_err()
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
                &account,
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
                .retain(&mut archive, &mut confirmations, &genesis, &three)
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
                .retain(&mut archive, &mut confirmations, &genesis, &three)
                .is_err()
        );
        // Even a certified rejected output never earns a successful confirmation.
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
        let rejected = UnloadInclusion {
            transaction: &rejected,
            digest: &digest,
            original,
            scheme,
            account: &account,
        };
        let before = confirmations;
        assert!(
            rejected
                .retain(
                    &mut archive,
                    &mut confirmations,
                    &genesis,
                    &native.checkpoint()
                )
                .is_err()
        );
        assert_eq!(confirmations, before);
    }

    #[test]
    fn unload_cursor_restores_exact_older_history_with_genuine_certificates() {
        let mut native = NativeFinalityFixture::start("unload-independent-cursor");
        let genesis = native.verifier();
        let (one, changed) =
            next_checkpoint(genesis.clone(), None, native.genesis_proof()).unwrap();
        assert!(changed);
        let mut verifier = SumeragiFinalityVerifier::from_trusted_checkpoint(
            &one,
            &native.network_id(),
            &native.chain_id(),
        )
        .unwrap();
        let block = native.block_with_submitted_work(native.next_header());
        let two = native.certify(block);
        let (two_checkpoint, _) = next_checkpoint(verifier.clone(), Some(&one), &two).unwrap();
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
        assert!(!next_checkpoint(older, Some(&restored), &two).unwrap().1);
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
