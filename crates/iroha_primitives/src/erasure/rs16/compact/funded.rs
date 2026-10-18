//! Exact original-pool backing for compact codec jobs; no protocol admission or scheduling.
//! Inputs and the shared RS16 field tables have separate existing owners.
use super::CompactShape;
use crate::erasure::rs16::Rs16Error;
use iroha_allocation::{AllocationBudget, AllocationRefusal, ChargedBuffer, PrepaidBufferError};
use std::alloc::Layout;
/// A resource refusal or an invalid RS16 input encountered by a funded codec job.
#[derive(Debug)]
pub enum CodecAllocationError {
    /// The original pool cannot reserve the exact job backing.
    Admission(AllocationRefusal),
    /// Allocation of already reserved backing failed.
    Allocation(PrepaidBufferError),
    /// The input geometry, shards, or reconstructed codeword is invalid.
    Codec(Rs16Error),
}
impl std::fmt::Display for CodecAllocationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Admission(error) => error.fmt(f),
            Self::Allocation(error) => error.fmt(f),
            Self::Codec(_) => f.write_str("invalid compact RS16 codeword"),
        }
    }
}
impl std::error::Error for CodecAllocationError {}
/// Move-only encoded bytes retaining their original pool charge.
pub struct Encoded {
    shape: CompactShape,
    codeword: ChargedBuffer<u8>,
}
impl Encoded {
    /// Exact checked geometry of this job.
    pub fn shape(&self) -> CompactShape {
        self.shape
    }
    /// Original encoded bytes in canonical stripe and row order.
    pub fn codeword(&self) -> &[u8] {
        self.codeword.as_slice()
    }
    /// Whether every retained output is charged to this exact pool.
    pub fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        self.codeword.belongs_to(budget)
    }
}
/// Verified reconstructed job outputs; no safe backing extraction or growth.
pub struct Reconstructed {
    shape: CompactShape,
    payload: ChargedBuffer<u8>,
    codeword: ChargedBuffer<u8>,
}
impl Reconstructed {
    /// Move verified payload backing unchanged, dropping the no-longer-needed codeword.
    pub fn into_payload(self) -> ChargedBuffer<u8> {
        self.payload
    }
    /// Exact checked geometry of this job.
    pub fn shape(&self) -> CompactShape {
        self.shape
    }
    /// Reconstructed original payload without padding.
    pub fn payload(&self) -> &[u8] {
        self.payload.as_slice()
    }
    /// Original encoded bytes in canonical stripe and row order.
    pub fn codeword(&self) -> &[u8] {
        self.codeword.as_slice()
    }
    /// Whether every retained output is charged to this exact pool.
    pub fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        self.payload.belongs_to(budget) && self.codeword.belongs_to(budget)
    }
}
fn layout<T>(count: usize) -> Result<Layout, CodecAllocationError> {
    Layout::array::<T>(count)
        .map_err(|_| CodecAllocationError::Admission(AllocationRefusal::DemandOverflow))
}
/// Total exact requested backing bytes, excluding the input and existing process tables.
///
/// # Errors
/// Returns [`CodecAllocationError::Admission`] if a buffer layout or the sum of
/// all required layouts exceeds the host's address space.
pub fn required_backing_bytes(
    shape: CompactShape,
    reconstruct: bool,
) -> Result<usize, CodecAllocationError> {
    [
        layout::<u8>(shape.encoded_bytes())?,
        layout::<u8>(if reconstruct {
            shape.payload_bytes()
        } else {
            0
        })?,
        layout::<u16>(shape.workspace_words())?,
    ]
    .into_iter()
    .try_fold(0usize, |n, v| {
        n.checked_add(v.size())
            .ok_or(CodecAllocationError::Admission(
                AllocationRefusal::DemandOverflow,
            ))
    })
}
type JobBuffers = (ChargedBuffer<u8>, ChargedBuffer<u8>, ChargedBuffer<u16>);

fn buffers(
    shape: CompactShape,
    reconstruct: bool,
    budget: &AllocationBudget,
) -> Result<JobBuffers, CodecAllocationError> {
    let mut reservation = budget
        .try_reserve_bytes(required_backing_bytes(shape, reconstruct)?)
        .map_err(CodecAllocationError::Admission)?;
    let mut codeword = ChargedBuffer::from_reservation(shape.encoded_bytes(), &mut reservation)
        .map_err(CodecAllocationError::Allocation)?;
    let mut payload = ChargedBuffer::from_reservation(
        if reconstruct {
            shape.payload_bytes()
        } else {
            0
        },
        &mut reservation,
    )
    .map_err(CodecAllocationError::Allocation)?;
    let mut workspace = ChargedBuffer::from_reservation(shape.workspace_words(), &mut reservation)
        .map_err(CodecAllocationError::Allocation)?;
    fill_zeroed(&mut codeword, &ZERO_BYTES);
    fill_zeroed(&mut payload, &ZERO_BYTES);
    fill_zeroed(&mut workspace, &ZERO_WORDS);
    Ok((codeword, payload, workspace))
}
/// Elements copied per bulk append while zero-initializing job backing.
const ZERO_BLOCK: usize = 4096;
static ZERO_BYTES: [u8; ZERO_BLOCK] = [0; ZERO_BLOCK];
static ZERO_WORDS: [u16; ZERO_BLOCK] = [0; ZERO_BLOCK];
/// Initialize every admitted element of a fresh buffer from `zeros` in bulk copies. Appends
/// never grow, replace or recharge the backing, so its original exact charge is unchanged.
fn fill_zeroed<T: Copy>(buffer: &mut ChargedBuffer<T>, zeros: &[T; ZERO_BLOCK]) {
    loop {
        let remaining = buffer.capacity() - buffer.as_slice().len();
        if remaining == 0 {
            return;
        }
        buffer
            .append(&zeros[..remaining.min(zeros.len())])
            .expect("bulk zeroing stays within the admitted capacity");
    }
}
/// Encode into one original-funded move-only byte owner; scratch drops before return.
///
/// # Errors
/// Returns a resource error when the exact backing cannot be reserved or allocated,
/// or [`CodecAllocationError::Codec`] when the payload does not fit the shape or
/// the encoding matrix cannot be inverted.
pub fn encode_funded(
    shape: CompactShape,
    payload: &[u8],
    budget: &AllocationBudget,
) -> Result<Encoded, CodecAllocationError> {
    let (mut codeword, _, mut workspace) = buffers(shape, false, budget)?;
    shape
        .encode_into(payload, codeword.as_mut_slice(), workspace.as_mut_slice())
        .map_err(CodecAllocationError::Codec)?;
    Ok(Encoded { shape, codeword })
}
/// Recover, compare all original chunk commitments and canonical padding before exposing owners.
///
/// # Errors
/// Returns a resource error when the exact backing cannot be reserved or allocated,
/// or [`CodecAllocationError::Codec`] when rows are missing, malformed, inconsistent,
/// rejected by the commitment predicate, or reconstruct noncanonical padding.
pub fn reconstruct_funded(
    shape: CompactShape,
    received: &[Option<&[u8]>],
    budget: &AllocationBudget,
    verify_original_row: impl FnMut(usize, &[u8]) -> bool,
) -> Result<Reconstructed, CodecAllocationError> {
    let (mut codeword, mut payload, mut workspace) = buffers(shape, true, budget)?;
    shape
        .reconstruct_into(
            received,
            payload.as_mut_slice(),
            codeword.as_mut_slice(),
            workspace.as_mut_slice(),
            verify_original_row,
        )
        .map_err(CodecAllocationError::Codec)?;
    Ok(Reconstructed {
        shape,
        payload,
        codeword,
    })
}

#[cfg(test)]
mod tests {
    use super::super::super::reference;
    use super::*;
    use crate::erasure::rs16::compact::encode_funded;

    /// Bulk zeroing initializes exactly the admitted capacity under the original charge,
    /// across block boundaries and for empty buffers.
    #[test]
    fn fill_zeroed_initializes_exact_capacity_without_recharging() {
        for capacity in [
            0usize,
            1,
            ZERO_BLOCK - 1,
            ZERO_BLOCK,
            ZERO_BLOCK + 1,
            3 * ZERO_BLOCK + 7,
        ] {
            let budget = AllocationBudget::new(capacity * 3);
            let mut bytes = ChargedBuffer::<u8>::new(capacity, &budget).unwrap();
            let mut words = ChargedBuffer::<u16>::new(capacity, &budget).unwrap();
            assert_eq!(budget.reserved_bytes(), capacity * 3);
            fill_zeroed(&mut bytes, &ZERO_BYTES);
            fill_zeroed(&mut words, &ZERO_WORDS);
            assert_eq!(bytes.as_slice().len(), capacity);
            assert_eq!(words.as_slice().len(), capacity);
            assert!(bytes.as_slice().iter().all(|byte| *byte == 0));
            assert!(words.as_slice().iter().all(|word| *word == 0));
            assert_eq!(budget.reserved_bytes(), capacity * 3);
            assert!(bytes.belongs_to(&budget) && words.belongs_to(&budget));
            fill_zeroed(&mut bytes, &ZERO_BYTES);
            assert_eq!(bytes.as_slice().len(), capacity);
            drop((bytes, words));
            assert_eq!(budget.reserved_bytes(), 0);
        }
    }

    /// Funded jobs reserve exactly the shape's backing once, retain only their outputs'
    /// charges, refund everything on codec rejection, and match the reference codeword.
    #[test]
    fn funded_jobs_charge_exact_backing_and_match_reference() {
        for (k, m, row, len) in [
            (4, 2, 256 * 1024, 1_048_579),
            (3, 3, 64, 1000),
            (1, 1, 2, 1),
        ] {
            let payload = reference::bytes(0xF00D ^ len as u64, len);
            let shape = CompactShape::new(len, k, m, row).unwrap();
            let expected = reference::compact_encode(&payload, k, m, row);
            let encode_bytes = required_backing_bytes(shape, false).unwrap();
            assert_eq!(
                encode_bytes,
                shape.encoded_bytes() + 2 * shape.workspace_words()
            );
            let budget = AllocationBudget::new(encode_bytes);
            let encoded = encode_funded(shape, &payload, &budget).unwrap();
            assert!(encoded.codeword() == expected.as_slice());
            assert!(encoded.belongs_to(&budget));
            assert_eq!(encoded.shape(), shape);
            assert_eq!(budget.peak_reserved_bytes(), encode_bytes);
            assert_eq!(budget.reserved_bytes(), shape.encoded_bytes());
            drop(encoded);
            assert_eq!(budget.reserved_bytes(), 0);
            let short = AllocationBudget::new(encode_bytes - 1);
            assert!(matches!(
                encode_funded(shape, &payload, &short),
                Err(CodecAllocationError::Admission(_))
            ));
            assert_eq!(short.reserved_bytes(), 0);

            let reconstruct_bytes = required_backing_bytes(shape, true).unwrap();
            assert_eq!(reconstruct_bytes, encode_bytes + len);
            let budget = AllocationBudget::new(reconstruct_bytes);
            let row_of = |index: usize| &expected[shape.chunk_range(index).unwrap()];
            let received = (0..shape.chunk_count())
                .map(|index| (index % (k + m) != 0).then(|| row_of(index)))
                .collect::<Vec<_>>();
            let restored =
                reconstruct_funded(shape, &received, &budget, |index, row| row == row_of(index))
                    .unwrap();
            assert!(restored.payload() == payload.as_slice());
            assert!(restored.codeword() == expected.as_slice());
            assert!(restored.belongs_to(&budget));
            assert_eq!(restored.shape(), shape);
            assert_eq!(budget.peak_reserved_bytes(), reconstruct_bytes);
            assert_eq!(budget.reserved_bytes(), shape.encoded_bytes() + len);
            let owner = restored.into_payload();
            assert_eq!(budget.reserved_bytes(), len);
            assert!(owner.as_slice() == payload.as_slice());
            drop(owner);
            assert_eq!(budget.reserved_bytes(), 0);
            assert!(matches!(
                reconstruct_funded(shape, &received, &budget, |_, _| false),
                Err(CodecAllocationError::Codec(_))
            ));
            assert_eq!(budget.reserved_bytes(), 0);
            let short = AllocationBudget::new(reconstruct_bytes - 1);
            assert!(matches!(
                reconstruct_funded(shape, &received, &short, |_, _| true),
                Err(CodecAllocationError::Admission(_))
            ));
        }
    }
}
