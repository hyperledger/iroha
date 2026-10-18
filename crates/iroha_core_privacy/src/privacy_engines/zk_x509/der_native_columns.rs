//! Bounded DER column projection through the original native row constructors.
//!
//! The caller owns the already admitted column buffers. Reconstruct each row
//! once per public batch without retaining another private matrix or changing
//! canonical inactive rows, carried terminals or field-validation boundaries.

use super::*;
use crate::privacy_engines::aggregate_stark::MASKED_TRACE_LDE_COLUMN_BATCH_V1;
use zeroize::Zeroizing;

type Error = ZkX509DerStarkErrorV1;

struct ColumnBatchGuardV1<'a, 'b> {
    targets: &'a mut [&'b mut [F]],
    complete: bool,
}

impl Drop for ColumnBatchGuardV1<'_, '_> {
    fn drop(&mut self) {
        if !self.complete {
            for target in self.targets.iter_mut() {
                super::super::private_table::zeroize_fields_v1(target);
            }
        }
    }
}

fn project_rows_v1<const WIDTH: usize>(
    row_count: usize,
    first: usize,
    targets: &mut [&mut [F]],
    mut row_at: impl FnMut(usize) -> Result<[F; WIDTH], Error>,
) -> Result<(), Error> {
    // Public extent refusals precede source access and leave targets untouched.
    if row_count == 0
        || targets.is_empty()
        || targets.len() > MASKED_TRACE_LDE_COLUMN_BATCH_V1
        || first
            .checked_add(targets.len())
            .is_none_or(|end| end > WIDTH)
        || targets.iter().any(|target| target.len() != row_count)
    {
        return Err(Error::Resource);
    }
    let mut guard = ColumnBatchGuardV1 {
        targets,
        complete: false,
    };
    for index in 0..row_count {
        let row = Zeroizing::new(row_at(index)?);
        for (offset, target) in guard.targets.iter_mut().enumerate() {
            // Preserve exact fields; MAIN's existing native-column admission
            // performs canonicality checks before mask sampling as before.
            target[index] = row[first + offset];
        }
    }
    guard.complete = true;
    Ok(())
}

/// Fill up to eight adjacent base columns without allocating private backing.
pub fn fill_zk_x509_der_stark_native_base_columns_v1(
    base: &ZkX509DerStarkBaseV1,
    first: usize,
    targets: &mut [&mut [F]],
) -> Result<(), Error> {
    project_rows_v1(ZK_X509_DER_STARK_TRACE_SIZE_V1, first, targets, |index| {
        zk_x509_der_stark_aggregate_base_row_v1(base, index)
    })
}

/// Fill up to eight adjacent auxiliary columns, retaining original padding checks.
pub fn fill_zk_x509_der_stark_native_aux_columns_v1(
    trace: &ZkX509DerStarkTraceV1,
    first: usize,
    targets: &mut [&mut [F]],
) -> Result<(), Error> {
    project_rows_v1(ZK_X509_DER_STARK_TRACE_SIZE_V1, first, targets, |index| {
        zk_x509_der_stark_aggregate_aux_row_v1(trace, index)
    })
}

#[cfg(test)]
#[path = "der_native_columns_tests.rs"]
mod tests;
