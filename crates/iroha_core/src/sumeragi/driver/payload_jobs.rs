//! Retained availability work executed off the consensus loop.

use iroha_allocation::{AllocationBudget, ChargedBuffer};
use iroha_primitives::erasure::rs16::compact::{CodecAllocationError, Encoded, encode_funded};
use iroha_sumeragi::{
    availability::{
        AcquisitionError, AuthoredBody, AuthoringError, AvailabilityError, AvailabilitySource,
        AvailableBody, PayloadAcquisition, PayloadAuthoring, PayloadBytes, RowBytes,
        verify_manifest,
    },
    crypto::{Crypto, Signer},
    message::{BlockHeader, ByteAdmissionError, PayloadChunk, PayloadManifest},
    types::{HeightConfig, PublicKey},
};

/// An original author request, retaining every completed encoding/signing phase on refusal.
pub struct AuthorJob {
    /// Exact Core request; Core independently rejects obsolete completion.
    pub req: u64,
    config: HeightConfig,
    instance: iroha_sumeragi::types::Hash32,
    job: Option<PayloadAuthoring>,
}

impl AuthorJob {
    /// Retain the original Core statement and admitted application payload.
    pub fn new(req: u64, config: HeightConfig, header: BlockHeader, payload: PayloadBytes) -> Self {
        Self {
            req,
            config,
            instance: header.instance,
            job: Some(PayloadAuthoring::new(header, payload)),
        }
    }

    /// Complete only with the exact configured proposer signer and original pool.
    ///
    /// # Errors
    /// Refusal retains the same job. A consumed job cannot run a second time.
    pub fn poll(
        &mut self,
        budget: &AllocationBudget,
        crypto: &dyn Crypto,
        signer: &dyn Signer,
    ) -> Result<AuthoredBody, AuthoringError> {
        let job = self
            .job
            .take()
            .ok_or(AuthoringError::Invalid(AvailabilityError::Source))?;
        match job.complete(self.instance, &self.config, budget, crypto, signer) {
            Ok(body) => Ok(body),
            Err((job, error)) => {
                self.job = Some(job);
                Err(error)
            }
        }
    }
}

/// A bounded incoming acquisition with one retained refused original relay chunk.
pub struct NetworkAcquisition {
    job: Option<PayloadAcquisition>,
    pending: Option<(PublicKey, PayloadChunk)>,
    audit_id: u64,
    accepted_rows: u32,
}

impl NetworkAcquisition {
    /// An independently selected source and an untrusted exact manifest carrier.
    pub fn new(source: AvailabilitySource, manifest: PayloadManifest, audit_id: u64) -> Self {
        Self {
            job: Some(PayloadAcquisition::new(source, manifest)),
            pending: None,
            audit_id,
            accepted_rows: 0,
        }
    }

    /// Duplicate requests must keep this original job rather than reset received rows.
    pub fn matches(&self, source: &AvailabilitySource, manifest: &PayloadManifest) -> bool {
        self.job
            .as_ref()
            .is_some_and(|job| job.source() == source && job.manifest() == manifest)
    }

    /// The exact carrier is used only when a failure disproves its original authorization.
    pub fn manifest(&self) -> Option<&PayloadManifest> {
        self.job.as_ref().map(PayloadAcquisition::manifest)
    }

    /// Accept one actual row. If the retained retry slot is occupied, return the incoming
    /// original owner to the bounded caller; never replace the refused owner.
    ///
    /// # Errors
    /// Returns the incoming chunk unchanged while a previous chunk is pending or the
    /// acquisition has already completed.
    #[allow(
        clippy::result_large_err,
        reason = "return exact incoming relay owner under backpressure"
    )]
    pub fn receive(&mut self, from: PublicKey, chunk: PayloadChunk) -> Result<(), PayloadChunk> {
        if self.pending.is_some() || self.job.is_none() {
            return Err(chunk);
        }
        self.pending = Some((from, chunk));
        Ok(())
    }

    /// Process-local acquisition identity and count of actually admitted distinct rows.
    pub fn audit(&self) -> (u64, u32) {
        (self.audit_id, self.accepted_rows)
    }

    /// Progress actual row admission and reconstruction, preserving every original phase.
    ///
    /// # Errors
    /// Incomplete and invalid relay rows are not manifest faults. Only
    /// `AcquisitionError::rejects_manifest` permits the Core rejection event.
    pub fn poll(
        &mut self,
        budget: &AllocationBudget,
        crypto: &dyn Crypto,
    ) -> Result<AvailableBody, AcquisitionError> {
        let job = self.job.as_mut().ok_or(AcquisitionError::Incomplete)?;
        if let Some((from, chunk)) = self.pending.take() {
            let index = chunk.index;
            match job.push(chunk, budget, crypto) {
                Ok(true) => {
                    self.accepted_rows += 1;
                    iroha_logger::info!(
                        process_id = std::process::id(),
                        acquisition = self.audit_id,
                        instance = %job.source().instance(),
                        height = job.source().height(),
                        block = %job.source().block_hash(),
                        availability_digest = %job.manifest().header.availability_digest,
                        index,
                        from = %super::audit::Hex(from.as_bytes()),
                        "sumeragi payload row admitted"
                    );
                }
                Ok(false) => {}
                Err((chunk, error)) => {
                    if error.is_local_refusal() {
                        self.pending = Some((from, chunk));
                    }
                    return Err(error);
                }
            }
        }
        let job = self.job.take().expect("original acquisition");
        match job.complete(budget, crypto) {
            Ok(body) => Ok(body),
            Err((job, error)) => {
                self.job = Some(job);
                Err(error)
            }
        }
    }
}

/// A source-bound outgoing stream. Exact original signatures are never regenerated.
pub struct PayloadDissemination {
    source: AvailabilitySource,
    body: AvailableBody,
    codeword: Option<Encoded>,
    row: Option<(usize, ChargedBuffer<u8>)>,
    verified: bool,
}

/// Outgoing resource refusal versus a source/codeword defect.
#[derive(Debug)]
pub enum DisseminationError {
    /// Immutable source, payload or codeword does not match the original authorization.
    Invalid(AvailabilityError),
    /// Original-pool RS16 encoding refusal.
    Codec(CodecAllocationError),
    /// Original-pool row backing or shared-control refusal.
    Bytes(ByteAdmissionError),
}

impl DisseminationError {
    /// Whether the same outgoing stream can resume when resources return.
    pub fn is_local_refusal(&self) -> bool {
        match self {
            Self::Bytes(error) => error.is_local_refusal(),
            Self::Codec(
                CodecAllocationError::Admission(_) | CodecAllocationError::Allocation(_),
            ) => true,
            _ => false,
        }
    }
}

impl PayloadDissemination {
    /// Use the author's original funded codeword when held, or derive it once from restored
    /// custody. Authority always comes from the preserved complete original signature table.
    pub fn new(source: AvailabilitySource, body: AvailableBody, codeword: Option<Encoded>) -> Self {
        Self {
            source,
            body,
            codeword,
            row: None,
            verified: false,
        }
    }

    /// Exact mandatory manifest; publishing it alone supplies no reconstructed custody.
    pub fn manifest(&self) -> PayloadManifest {
        PayloadManifest {
            header: self.body.header().clone(),
            availability: self.body.availability().clone(),
        }
    }

    /// Index whose original backing awaits shared-control admission, if any.
    pub fn pending_index(&self) -> Option<usize> {
        self.row.as_ref().map(|(index, _)| *index)
    }

    /// Materialize an indexed original signed row from the single retained funded codeword.
    /// A refused row keeps its exact backing and index until that same index is retried.
    ///
    /// # Errors
    /// Source/codeword defects remain distinct from temporary local memory refusal.
    pub fn chunk(
        &mut self,
        index: usize,
        budget: &AllocationBudget,
        crypto: &dyn Crypto,
    ) -> Result<Option<PayloadChunk>, DisseminationError> {
        let invalid = DisseminationError::Invalid;
        if self.body.source() != &self.source {
            return Err(invalid(AvailabilityError::Source));
        }
        if !self.body.admitted_to(budget) {
            return Err(invalid(AvailabilityError::ForeignBudget));
        }
        let header = self.body.header();
        if !self.verified
            && (header.instance != self.source.instance()
                || header.height != self.source.height()
                || header.hash(crypto) != self.source.block_hash())
        {
            return Err(invalid(AvailabilityError::Source));
        }
        let shape = self
            .source
            .config()
            .epoch
            .da_layout
            .shape(u64::from(header.payload_len))
            .map_err(|_| invalid(AvailabilityError::Shape))?;
        if self.codeword.is_none() {
            self.codeword = Some(
                encode_funded(shape, self.body.payload().as_slice(), budget)
                    .map_err(DisseminationError::Codec)?,
            );
        }
        let codeword = self.codeword.as_ref().expect("retained funded codeword");
        if codeword.shape() != shape || !codeword.belongs_to(budget) {
            return Err(invalid(AvailabilityError::Source));
        }
        if !self.verified {
            let verified = verify_manifest(
                self.source.instance(),
                self.source.config(),
                header,
                self.body.availability(),
                budget,
                crypto,
            )
            .map_err(invalid)?;
            for index in 0..shape.chunk_count() {
                let range = shape.chunk_range(index).expect("bounded original codeword");
                if !verified.accepts_row(index, &codeword.codeword()[range], crypto) {
                    return Err(invalid(AvailabilityError::Digest));
                }
            }
            self.verified = true;
        }
        if index >= shape.chunk_count() {
            return Ok(None);
        }
        if self.pending_index().is_some_and(|pending| pending != index) {
            return Err(invalid(AvailabilityError::Source));
        }
        if self.row.is_none() {
            let range = shape.chunk_range(index).expect("bounded outgoing row");
            let mut row = ChargedBuffer::new(range.len(), budget)
                .map_err(|e| DisseminationError::Bytes(ByteAdmissionError::Buffer(e)))?;
            row.append(&codeword.codeword()[range])
                .expect("exact funded row capacity");
            self.row = Some((index, row));
        }
        let (_, row) = self.row.take().expect("retained row backing");
        match RowBytes::from_charged(row, budget) {
            Ok(bytes) => {
                let chunk = PayloadChunk {
                    instance: self.source.instance(),
                    height: self.source.height(),
                    block_hash: self.source.block_hash(),
                    index: index as u32,
                    bytes,
                };
                Ok(Some(chunk))
            }
            Err((row, error)) => {
                self.row = Some((index, row));
                Err(DisseminationError::Bytes(error))
            }
        }
    }
}

#[cfg(test)]
mod indexed_tests {
    use super::*;
    use crate::sumeragi::{crypto::BlsCrypto, driver::payload_worker_tests::Fixture};
    #[test]
    fn refused_indexed_row_retains_exact_backing_until_same_index_retry() {
        let f = Fixture::new();
        let crypto = BlsCrypto::new();
        let mut stream = PayloadDissemination::new(f.source.clone(), f.body.clone(), None);
        let first = stream.chunk(0, &f.budget, &crypto).unwrap().unwrap();
        let width = first.bytes.as_slice().len();
        drop(first);
        let hold = f
            .budget
            .try_reserve_bytes((1 << 25) - f.budget.reserved_bytes() - width)
            .unwrap();
        let error = stream.chunk(1, &f.budget, &crypto).unwrap_err();
        assert!(error.is_local_refusal());
        assert_eq!(stream.pending_index(), Some(1));
        let pointer = stream.row.as_ref().unwrap().1.as_slice().as_ptr();
        let held = f.budget.reserved_bytes();
        assert!(matches!(
            stream.chunk(2, &f.budget, &crypto),
            Err(DisseminationError::Invalid(AvailabilityError::Source))
        ));
        assert_eq!(stream.pending_index(), Some(1));
        assert_eq!(f.budget.reserved_bytes(), held);
        drop(hold);
        let retried = stream.chunk(1, &f.budget, &crypto).unwrap().unwrap();
        assert_eq!(retried.index, 1);
        assert_eq!(retried.bytes.as_slice().as_ptr(), pointer);
        assert_eq!(stream.pending_index(), None);
    }
}
