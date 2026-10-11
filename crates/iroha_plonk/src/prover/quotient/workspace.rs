//! Bounded, caller-owned storage reused by quotient evaluations.

use core::{fmt, mem::size_of_val};

use iroha_pasta::PastaField;

/// A quotient workspace could not admit its field buffers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkspaceError {
    /// The requested buffers exceed the caller's explicit byte ceiling.
    Limit {
        /// Bytes required by the current key and protocol shape.
        required: usize,
        /// The caller's byte ceiling.
        limit: usize,
    },
    /// The allocator could not provide the admitted buffer.
    Allocation,
}

impl fmt::Display for WorkspaceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Limit { required, limit } => {
                write!(
                    f,
                    "quotient workspace requires {required} bytes, limit is {limit}"
                )
            }
            Self::Allocation => f.write_str("quotient workspace allocation failed"),
        }
    }
}

impl std::error::Error for WorkspaceError {}

/// Reusable quotient coset buffers, owned exclusively by the proving caller.
///
/// The explicit ceiling bounds the retained field storage, independently of
/// the process-wide MSM scratch budget. It excludes allocator bookkeeping,
/// column-reference metadata, proving keys, inputs and the quotient output.
/// Same-sized columns keep their allocations across proofs; changing the row
/// count clears the old shape before admitting replacements.
/// The storage carries no key identity or cached evaluations: every lease is
/// zeroized on success, error and unwind, and all columns are overwritten for
/// the next proof. No process-global cache or platform allocator hook is used.
pub struct QuotientWorkspace<F: PastaField> {
    maximum_bytes: usize,
    rows: usize,
    columns: Vec<Box<[F]>>,
}

impl<F: PastaField> fmt::Debug for QuotientWorkspace<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QuotientWorkspace")
            .field("maximum_bytes", &self.maximum_bytes)
            .field("allocated_bytes", &self.allocated_bytes())
            .finish_non_exhaustive()
    }
}

impl<F: PastaField> QuotientWorkspace<F> {
    /// Creates empty storage with an explicit maximum field-buffer byte count.
    #[must_use]
    pub fn new(maximum_bytes: usize) -> Self {
        Self {
            maximum_bytes,
            rows: 0,
            columns: Vec::new(),
        }
    }

    /// The immutable caller-selected field-buffer ceiling.
    #[must_use]
    pub fn maximum_bytes(&self) -> usize {
        self.maximum_bytes
    }

    /// Field storage currently retained for reuse, including unused columns.
    #[must_use]
    pub fn allocated_bytes(&self) -> usize {
        self.columns
            .iter()
            .map(|column| size_of_val(column.as_ref()))
            .sum()
    }

    /// Zeroizes and releases the retained storage. The ceiling is unchanged.
    pub fn clear(&mut self) {
        for column in &mut self.columns {
            wipe(column);
        }
        self.columns.clear();
        self.rows = 0;
    }

    #[cfg(test)]
    pub(in crate::prover) fn is_zeroized(&self) -> bool {
        self.columns
            .iter()
            .flat_map(|column| column.iter())
            .all(|value| *value == F::ZERO)
    }

    pub(in crate::prover) fn check(&self, bytes: usize) -> Result<(), WorkspaceError> {
        if bytes > self.maximum_bytes {
            Err(WorkspaceError::Limit {
                required: bytes,
                limit: self.maximum_bytes,
            })
        } else {
            Ok(())
        }
    }

    pub(super) fn lease(
        &mut self,
        rows: usize,
        count: usize,
    ) -> Result<Lease<'_, F>, WorkspaceError> {
        let bytes = rows
            .checked_mul(count)
            .and_then(|elements| elements.checked_mul(size_of::<F>()))
            .ok_or(WorkspaceError::Limit {
                required: usize::MAX,
                limit: self.maximum_bytes,
            })?;
        self.check(bytes)?;
        if self.rows != rows {
            // Never retain old and replacement row shapes together.
            self.clear();
            self.rows = rows;
        }
        if self.columns.len() < count {
            self.columns
                .try_reserve_exact(count - self.columns.len())
                .map_err(|_| WorkspaceError::Allocation)?;
            while self.columns.len() < count {
                let mut values = Vec::new();
                values
                    .try_reserve_exact(rows)
                    .map_err(|_| WorkspaceError::Allocation)?;
                values.resize(rows, F::ZERO);
                self.columns.push(values.into_boxed_slice());
            }
        }
        Ok(Lease {
            columns: &mut self.columns,
        })
    }
}

impl<F: PastaField> Drop for QuotientWorkspace<F> {
    fn drop(&mut self) {
        for column in &mut self.columns {
            wipe(column);
        }
    }
}

fn wipe<F: PastaField>(values: &mut [F]) {
    for value in values {
        value.zeroize();
    }
}

pub(super) struct Lease<'a, F: PastaField> {
    pub(super) columns: &'a mut [Box<[F]>],
}

impl<F: PastaField> Drop for Lease<'_, F> {
    fn drop(&mut self) {
        for column in &mut *self.columns {
            wipe(column);
        }
    }
}

#[cfg(test)]
mod tests {
    use iroha_pasta::{Fp, Fq};

    use super::*;

    fn check<F: PastaField>() {
        let mut workspace = QuotientWorkspace::<F>::new(8 * size_of::<F>());
        assert_eq!(workspace.maximum_bytes(), 8 * size_of::<F>());
        assert_eq!(workspace.allocated_bytes(), 0);
        let addresses = {
            let lease = workspace.lease(2, 2).unwrap();
            for column in &mut *lease.columns {
                column.fill(F::ONE);
            }
            lease
                .columns
                .iter()
                .map(|column| column.as_ptr())
                .collect::<Vec<_>>()
        };
        assert!(workspace.is_zeroized());
        {
            let lease = workspace.lease(2, 1).unwrap();
            for (column, address) in lease.columns.iter_mut().zip(&addresses) {
                assert_eq!(column.as_ptr(), *address);
                column.fill(F::ONE);
            }
        }
        assert_eq!(workspace.allocated_bytes(), 4 * size_of::<F>());
        assert!(workspace.is_zeroized());
        assert!(matches!(
            workspace.lease(2, 5),
            Err(WorkspaceError::Limit { .. })
        ));
        assert_eq!(workspace.columns[0].as_ptr(), addresses[0]);
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let lease = workspace.lease(2, 4).unwrap();
                for (column, address) in lease.columns.iter().zip(&addresses) {
                    assert_eq!(column.as_ptr(), *address);
                }
                for column in &mut *lease.columns {
                    column.fill(F::ONE);
                }
                panic!("injected evaluator failure");
            }))
            .is_err()
        );
        assert!(workspace.is_zeroized());
        assert_eq!(workspace.allocated_bytes(), workspace.maximum_bytes());
        assert!(workspace.lease(usize::MAX, 2).is_err());
        assert!(workspace.lease(1, usize::MAX).is_err());
        {
            let lease = workspace.lease(4, 2).unwrap();
            assert_eq!(lease.columns.len(), 2);
            assert!(lease.columns.iter().all(|column| column.len() == 4));
            for column in &mut *lease.columns {
                column.fill(F::ONE);
            }
        }
        assert!(workspace.is_zeroized());
        assert_eq!(workspace.allocated_bytes(), 8 * size_of::<F>());
        workspace.lease(1, 3).unwrap();
        assert_eq!(workspace.allocated_bytes(), 3 * size_of::<F>());
        assert!(workspace.is_zeroized());
        workspace.clear();
        assert_eq!(workspace.allocated_bytes(), 0);
        workspace.lease(8, 1).unwrap();
    }

    #[test]
    fn bound_reuse_zeroization_growth_and_unwind_both_fields() {
        check::<Fp>();
        check::<Fq>();
    }
}
