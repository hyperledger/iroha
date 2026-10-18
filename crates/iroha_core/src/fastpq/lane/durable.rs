//! Source-bound producer progress in Kura's sole bounded artifact store.
//!
//! The immutable record at each complete statement position is the disk cursor.
//! There is no mutable high-water mark that can skip a missing or invalid artifact.
//! A file is only an advertisement: recovery authenticates the complete source and
//! verifies the exact artifact afresh before advancing the retained in-memory index.

use super::*;
use iroha_crypto::Hash;

#[derive(norito::Encode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::fastpq::ProducerPositionV1")]
struct Position {
    carrier: HashOf<BlockHeader>,
    result: [u8; 32],
    manifest: iroha_data_model::fastpq::FastpqOrdinarySourceStatementManifestV1,
    leaf: iroha_data_model::fastpq::FastpqOrdinarySourceStatementLeafV1,
}

/// Original producer refusal. Invalid source/proof/record failures remain terminal.
#[derive(Debug, thiserror::Error)]
pub(super) enum DurableError {
    #[error(transparent)]
    Source(#[from] source::SourceWorkError),
    #[error(transparent)]
    Storage(#[from] crate::kura::Error),
    #[error(transparent)]
    Codec(#[from] norito::Error),
    #[error(transparent)]
    Verification(#[from] offline_compact::VerificationError),
    #[error("FASTPQ producer record: {0}")]
    Identity(&'static str),
}

fn position(job: &FastpqWitnessJob) -> Result<Hash, DurableError> {
    let native = job.source.native().committed();
    let leaf = job
        .source
        .leaves()
        .get(job.next_statement)
        .ok_or(DurableError::Identity("cursor is outside complete source"))?;
    if usize::try_from(leaf.statement_index).ok() != Some(job.next_statement)
        || leaf.source != job.source.manifest().source
    {
        return Err(DurableError::Identity("original source position differs"));
    }
    let bytes = norito::encode_canonical(&Position {
        carrier: native.block_hash(),
        result: native.result().0,
        manifest: *job.source.manifest(),
        leaf: *leaf,
    })?;
    Ok(Hash::new(bytes))
}

impl FastpqCompletedEntry {
    /// Persist exact produced bytes at their source-position key atomically. Every failure
    /// returns the same source/artifact owner; queue delivery alone never advances it.
    pub(super) fn persist(self, kura: &Kura) -> Result<FastpqWitnessJob, (Self, DurableError)> {
        let result = self.persist_ref(kura);
        match result {
            Ok(()) => {
                let mut job = self.job;
                job.next_statement += 1; // bounded by the original source leaf slice
                Ok(job)
            }
            Err(error) => Err((self, error)),
        }
    }

    fn persist_ref(&self, kura: &Kura) -> Result<(), DurableError> {
        let verified = self.verified().ok_or(DurableError::Identity(
            "component output is not a genuine verified producer artifact",
        ))?;
        let identity = verified.identity();
        if identity.artifact_bytes != self.bytes().len() as u64 {
            return Err(DurableError::Identity(
                "verified complete artifact length differs",
            ));
        }
        let key = position(&self.job)?;
        // Record and artifact are ONE immutable object. A crash or full store
        // cannot leave a cursor referring to an absent second file, nor consume
        // artifact quota while permanently losing space for its cursor metadata.
        // The source-bound key is derived from the complete authenticated position;
        // restart still verifies these raw bytes against independent expectations.
        let receipt = kura.persist_fastpq_producer_record(key, self.bytes())?;
        if !receipt.is_from(kura)
            || receipt.reference().digest() != *Hash::new(self.bytes()).as_ref()
            || receipt.reference().byte_len() != self.bytes().len() as u64
        {
            return Err(DurableError::Identity(
                "producer receipt differs from exact artifact",
            ));
        }
        Ok(())
    }
}

impl FastpqWitnessJob {
    /// Consume at most one advertised position. Absence leaves this same source/index
    /// ready for production; malformed or invalid evidence never becomes absence.
    pub(super) fn recover_next(
        &mut self,
        kura: &Kura,
        proving: ProvingLimits,
        verification: &ExecutionEffectVerificationLimits,
    ) -> Result<bool, DurableError> {
        if self.next_statement == self.source.leaves().len() {
            return Ok(false);
        }
        let key = position(self)?;
        let Some(artifact) = kura.read_fastpq_producer_record(key)? else {
            return Ok(false);
        };
        let mut prepared = source::prepare_for_verification(
            &self.source,
            self.next_statement,
            proving,
            verification,
        )?;
        let verified = offline_compact::verify_quantity_ordinary_artifact(
            &artifact,
            ExpectedExecutionEffects {
                source: prepared.original.leaf(),
                statement: prepared.expectations,
            },
            verification,
            prepared.original.pool(),
            &mut prepared.reservation,
        )?;
        if verified.identity().artifact_bytes != artifact.len() as u64 {
            return Err(DurableError::Identity(
                "fresh verifier length differs from retained object",
            ));
        }
        self.next_statement += 1;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_primitives::numeric::Quantity;
    use std::num::{NonZeroU64, NonZeroUsize};

    fn source() -> (
        crate::sumeragi::test_chain::CertifiedTestChain,
        FastpqWitnessJob,
    ) {
        let (chain, source) = crate::fastpq::finalized_source::test_fixture::original_source(
            Quantity::from(100_u32),
            &[3],
        );
        chain
            .state()
            .ivm_execution_budget()
            .set_limit_bytes(2 * 1024 * 1024 * 1024);
        let job = match FastpqWitnessJob::from_finalized(source) {
            Ok(job) => job,
            Err((_, error)) => panic!("genuine source refused: {error}"),
        };
        (chain, job)
    }
    fn store(maximum: usize) -> Arc<Kura> {
        Kura::blank_with_fastpq_artifact_policy_for_testing(
            iroha_config::parameters::actual::KuraFastpqArtifactPolicy {
                max_artifact_bytes: NonZeroUsize::new(maximum).unwrap(),
                max_artifacts: NonZeroUsize::new(4).unwrap(),
                max_total_bytes: NonZeroU64::new(maximum as u64 * 4).unwrap(),
            },
        )
    }

    #[test]
    fn raw_advertisement_never_advances_authenticated_statement_cursor() {
        let (_chain, mut job) = source();
        let original = std::ptr::from_ref(job.source.entry(0).unwrap().effects());
        let key = position(&job).unwrap();
        let kura = store(1024);
        assert!(
            !job.recover_next(
                &kura,
                ProvingLimits::default(),
                &ExecutionEffectVerificationLimits::default()
            )
            .unwrap()
        );
        assert_eq!(job.next_statement, 0);
        kura.persist_fastpq_producer_record(key, b"not a verified proof")
            .unwrap();
        assert!(matches!(
            job.recover_next(
                &kura,
                ProvingLimits::default(),
                &ExecutionEffectVerificationLimits::default()
            ),
            Err(DurableError::Verification(_))
        ));
        assert_eq!(job.next_statement, 0);
        assert_eq!(
            std::ptr::from_ref(job.source.entry(0).unwrap().effects()),
            original
        );
    }

    #[test]
    fn actual_verified_producer_artifact_survives_refusal_and_fresh_cursor_recovery() {
        let (chain, job) = source();
        let source_hash = job.block_hash();
        let key = position(&job).unwrap();
        let original = std::ptr::from_ref(job.source.entry(0).unwrap().effects());
        let engine: Arc<dyn FastpqProofEngine> = Arc::new(RealProofEngine {
            proving: ProvingLimits::default(),
            verification: ExecutionEffectVerificationLimits::default(),
        });
        let output = prove_entry(&engine, &job).expect("actual canonical full-effect producer");
        let completed = FastpqCompletedEntry {
            job,
            output,
            generation: 0,
        };
        assert!(completed.verified().is_some());
        let proof_hash = Hash::new(completed.bytes());
        let proof_len = completed.bytes().len();
        let short = store(proof_len - 1);
        let (completed, _) = completed
            .persist(&short)
            .err()
            .expect("real immutable object limit");
        assert_eq!(completed.job.next_statement, 0);
        assert_eq!(
            std::ptr::from_ref(completed.job.source.entry(0).unwrap().effects()),
            original
        );
        assert_eq!(Hash::new(completed.bytes()), proof_hash);
        let kura = store(proof_len);
        let job = completed
            .persist(&kura)
            .unwrap_or_else(|(_, error)| panic!("exact durable barrier: {error}"));
        assert_eq!(job.next_statement, 1);
        assert_eq!(
            Hash::new(kura.read_fastpq_producer_record(key).unwrap().unwrap()),
            proof_hash
        );
        drop(job);

        // Restart source identity comes from an independent authenticated native read,
        // not the old in-memory cursor, file presence, or the offered proof identity.
        let pool = AllocationBudget::new(2 * 1024 * 1024 * 1024);
        let native = crate::sumeragi::certified_chain::CertifiedChain::new(&chain.state().view())
            .unwrap()
            .authenticated_execution(2)
            .unwrap();
        let mut read =
            crate::query::native_context_archive::fastpq_source::NativeFastpqSourceRead::new(
                Arc::clone(chain.kura()),
                native,
                pool.clone(),
                crate::query::native_context_archive::fastpq_source::SourceReadLimits {
                    max_entries: 64,
                    max_statements: 64,
                    max_effects_per_statement: 128,
                },
            );
        let mut recovered = (0..256)
            .find_map(|_| read.poll().unwrap())
            .map(FastpqWitnessJob::from_recovered)
            .expect("finite genuine source read");
        assert_eq!(recovered.next_statement, 0);
        assert_eq!(recovered.block_hash(), source_hash);
        assert_eq!(position(&recovered).unwrap(), key);
        assert!(
            recovered
                .recover_next(
                    &kura,
                    ProvingLimits::default(),
                    &ExecutionEffectVerificationLimits::default()
                )
                .unwrap()
        );
        assert_eq!(recovered.next_statement, 1);
        assert!(
            !recovered
                .recover_next(
                    &kura,
                    ProvingLimits::default(),
                    &ExecutionEffectVerificationLimits::default()
                )
                .unwrap()
        );
    }
}
