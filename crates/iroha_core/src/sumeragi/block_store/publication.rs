//! Exact source-bound publication without copying the executed proposal or complete payload.
use super::*;
use crate::execution_attempt::ExecutionAttemptError as Attempt;
use committed_read::certified_source;

impl KuraBlockStore {
    pub(super) fn write(&self, body: &AvailableBody, qc: &Qc) -> Result<(), Attempt<io::Error>> {
        if !body.admitted_to(&self.execution_budget) {
            return Err(invalid("publication uses another allocation pool").into());
        }
        let height = body.header().height;
        let source = certified_source(&*self.schedule, &*self.hasher, height, body.header(), qc)?;
        if body.source() != &source {
            return Err(invalid("body custody uses another historical authority").into());
        }
        let tip = self.height();
        if height <= tip {
            let (stored, original_qc) = self
                .committed_body(height)?
                .ok_or_else(|| invalid("committed retry has no original frame"))?;
            if stored != *body || original_qc != *qc {
                return Err(invalid("another committed decision is already stored").into());
            }
            return Ok(());
        }
        if tip.checked_add(1) != Some(height) {
            return Err(invalid("publication would leave a committed height gap").into());
        }
        let staged = self
            .staging
            .get(&qc.block_hash)
            .ok_or_else(|| invalid("no original executed frame staged for commit"))?;
        let executed = &staged.executed;
        if !executed.belongs_to(&self.execution_budget) {
            return Err(invalid("staged block control uses another allocation pool").into());
        }
        if executed.header().height().get() != height || !executed.has_results() {
            return Err(invalid("staged frame has another height or no execution result").into());
        }
        let certificate = executed
            .commit_certificate()
            .ok_or_else(|| invalid("staged frame has no commit certificate"))?;
        if !certificate.admitted_to(&self.execution_budget) {
            return Err(invalid("staged certificate uses another allocation pool").into());
        }
        norito::verify_exact_canonical_frame(body.header(), certificate.consensus_header())
            .map_err(codec)?;
        norito::verify_exact_canonical_frame(qc, certificate.commit_qc()).map_err(codec)?;
        norito::verify_exact_canonical_frame(body.availability(), certificate.availability())
            .map_err(codec)?;
        if result_of_preimage(certificate.result_preimage()) != qc.result {
            return Err(invalid("staged result preimage differs from the certified result").into());
        }
        super::execution::validate(executed)?;
        if !matches_payload(executed, body.payload().as_slice())? {
            return Err(invalid("staged proposal differs from the original signed payload").into());
        }
        self.kura
            .store_block(executed.clone())
            .map_err(|error| io::Error::other(error).into())
    }
}
fn codec(error: norito::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}
pub(super) fn matches_payload(block: &SignedBlock, payload: &[u8]) -> io::Result<bool> {
    struct Compare<'a> {
        expected: &'a [u8],
        position: usize,
        equal: bool,
    }
    impl io::Write for Compare<'_> {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let end = self
                .position
                .checked_add(bytes.len())
                .ok_or_else(|| invalid("proposal comparison offset overflow"))?;
            self.equal &= self.expected.get(self.position..end) == Some(bytes);
            self.position = end;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut compare = Compare {
        expected: payload,
        position: 0,
        equal: true,
    };
    block
        .write_resultless_proposal_wire(&mut compare)
        .map_err(codec)?;
    Ok(compare.equal && compare.position == payload.len())
}
