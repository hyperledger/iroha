//! Completed, clearing Metal execution of exact SHA3 absorbed-state continuations.
use super::*;
use crate::keccak_batch::{self, Job};
use zeroize::Zeroizing;
const KERNEL: &str = "fastpq_sha3_256_continuations";
static CONTEXT: OnceLock<MetalResult<Context>> = OnceLock::new();
struct Context {
    device: Device,
    queues: QueuePool,
    pipeline: ComputePipelineState,
    quarantine: Mutex<Option<Vec<(PooledBuffer, Buffer)>>>,
}
struct Layout {
    jobs: u32,
    words: [usize; 5],
    payload_bytes: usize,
}
fn layout(count: usize, bytes: usize) -> MetalResult<Layout> {
    if count == 0 || count > keccak_batch::MAX_JOBS || bytes > count * keccak_batch::MAX_BODY_BYTES
    {
        return Err(GpuError::InvalidInput(
            "SHA3 continuation geometry exceeds fixed bounds",
        ));
    }
    Ok(Layout {
        jobs: u32::try_from(count).map_err(|_| GpuError::InvalidInput("SHA3 count exceeds u32"))?,
        words: [
            26 * count,
            2 * count,
            bytes.max(1).div_ceil(8),
            4 * count,
            60 * count,
        ],
        payload_bytes: bytes,
    })
}
fn build_context() -> MetalResult<Context> {
    let device = select_metal_device().ok_or(GpuError::Unsupported(GpuBackend::Metal))?;
    register_metal_device_hints(&device);
    let library = load_metal_library(&device)?;
    let pipeline = load_pipeline(&device, &library, KERNEL)?;
    let queues = QueuePool::new(&device, resolve_queue_policy(&device))?;
    Ok(Context {
        device,
        queues,
        pipeline,
        quarantine: Mutex::new(None),
    })
}
pub fn hash(jobs: &[Job<'_>], output: &mut [[u8; 32]]) -> MetalResult<()> {
    let _drain = DrainScope::enter(METAL_COMMAND_TIMEOUT);
    ensure_backend_available()?;
    let bytes = keccak_batch::validate(jobs, output.len())
        .map_err(|_| GpuError::InvalidInput("SHA3 exact batch admission failed"))?;
    let shape = layout(jobs.len(), bytes)?;
    let context = CONTEXT
        .get_or_init(build_context)
        .as_ref()
        .map_err(Clone::clone)?;
    let mut quarantine = context.quarantine.lock().map_err(|_| GpuError::Execution {
        backend: GpuBackend::Metal,
        message: "SHA3 dispatch lock poisoned".into(),
    })?;
    if quarantine.is_some() {
        return Err(GpuError::CompletionUncertain {
            backend: GpuBackend::Metal,
        });
    }
    for words in shape.words {
        validate_metal_pooled_word_len(&context.device, words)?;
    }
    let pools = stage(jobs, &shape)?;
    let mut buffers = Vec::new();
    buffers
        .try_reserve_exact(5)
        .map_err(|_| GpuError::InvalidInput("SHA3 buffer owner allocation failed"))?;
    for mut pool in pools {
        let buffer = shared_pooled_buffer(&context.device, &mut pool)?;
        buffers.push((pool, buffer));
    }
    let (queue, index) = context.queues.select(shape.jobs, 0);
    let ticket = submit_compute(
        queue,
        index,
        &context.pipeline,
        u64::from(shape.jobs),
        None,
        false,
        |encoder| {
            for (binding, storage) in [0, 2, 1, 3, 4].iter().enumerate() {
                encoder.set_buffer(binding as u64, Some(&buffers[*storage].1), 0);
            }
            encoder.set_bytes(
                5,
                size_of::<u32>() as u64,
                ptr::from_ref(&shape.jobs).cast(),
            );
        },
    )?;
    finish(wait_for_ticket(ticket), buffers, &mut quarantine, output)
}
fn finish(
    completion: MetalResult<()>,
    buffers: Vec<(PooledBuffer, Buffer)>,
    quarantine: &mut Option<Vec<(PooledBuffer, Buffer)>>,
    output: &mut [[u8; 32]],
) -> MetalResult<()> {
    if let Err(error) = completion {
        if matches!(error, GpuError::CompletionUncertain { .. }) {
            *quarantine = Some(buffers);
        }
        return Err(error);
    }
    let buffer = buffers
        .get(3)
        .ok_or(GpuError::InvalidInput("SHA3 output owner missing"))?;
    collect(&buffer.0, output)
}
fn stage(jobs: &[Job<'_>], shape: &Layout) -> MetalResult<Vec<PooledBuffer>> {
    if jobs.len() != shape.jobs as usize {
        return Err(GpuError::InvalidInput(
            "SHA3 stage count changed after admission",
        ));
    }
    let mut pools = Vec::new();
    pools
        .try_reserve_exact(5)
        .map_err(|_| GpuError::InvalidInput("SHA3 pool owner allocation failed"))?;
    for words in shape.words {
        pools.push(PooledBuffer::sensitive_zeroed(words)?);
    }
    let mut offset = 0;
    for (index, job) in jobs.iter().enumerate() {
        let mut prefix = Zeroizing::new([0u64; 26]);
        job.prefix().with_absorbed_state_v1(|words, position| {
            prefix[..25].copy_from_slice(words);
            prefix[25] = position as u64;
        });
        pools[0].copy_from_slice_at(index * 26, &prefix[..]);
        pools[1].copy_from_slice_at(index * 2, &[offset as u64, job.body().len() as u64]);
        copy_bytes(&mut pools[2], offset, job.body())?;
        offset += job.body().len();
    }
    if offset != shape.payload_bytes {
        return Err(GpuError::InvalidInput(
            "SHA3 staged extent changed after admission",
        ));
    }
    Ok(pools)
}
fn copy_bytes(pool: &mut PooledBuffer, offset: usize, bytes: &[u8]) -> MetalResult<()> {
    let bound = pool
        .len()
        .checked_mul(8)
        .ok_or(GpuError::InvalidInput("SHA3 shared extent overflow"))?;
    if offset
        .checked_add(bytes.len())
        .is_none_or(|end| end > bound)
    {
        return Err(GpuError::InvalidInput(
            "SHA3 byte range exceeds shared extent",
        ));
    }
    let backing = Arc::get_mut(&mut pool.backing).ok_or(GpuError::InvalidInput(
        "SHA3 cannot mutate retained storage",
    ))?;
    for (index, &byte) in bytes.iter().enumerate() {
        let position = offset + index;
        let word_index = position / 8;
        let shift = (position % 8) * 8;
        let word = &mut backing.pages[word_index / METAL_BUFFER_PAGE_WORDS].words
            [word_index % METAL_BUFFER_PAGE_WORDS];
        *word = (*word & !(0xffu64 << shift)) | (u64::from(byte) << shift);
    }
    Ok(())
}
fn collect(buffer: &PooledBuffer, output: &mut [[u8; 32]]) -> MetalResult<()> {
    let expected = output
        .len()
        .checked_mul(4)
        .ok_or(GpuError::InvalidInput("SHA3 output extent overflow"))?;
    if buffer.len() != expected {
        return Err(GpuError::InvalidInput(
            "SHA3 completed output count differs",
        ));
    }
    for (index, out) in output.iter_mut().enumerate() {
        let mut words = Zeroizing::new([0; 4]);
        buffer.copy_range_to_slice(index * 4, &mut words[..]);
        for byte in 0..32 {
            out[byte] = words[byte / 8].to_le_bytes()[byte % 8];
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use fastpq_isi::keccak256::Sha3_256V1;
    #[test]
    fn layout_and_staging_cover_exact_unaligned_bytes_and_sensitive_owners() {
        assert!(layout(0, 0).is_err());
        assert!(layout(1025, 0).is_err());
        assert!(layout(1, 8193).is_err());
        let mut prefix = Sha3_256V1::new();
        prefix.update(&[7; 137]);
        let bodies = [vec![11; 7], vec![13; 8192], vec![], vec![17; 3]];
        let jobs = bodies
            .iter()
            .map(|body| Job::new(&prefix, body))
            .collect::<Vec<_>>();
        let shape = layout(jobs.len(), bodies.iter().map(Vec::len).sum()).unwrap();
        let mut pools = stage(&jobs, &shape).unwrap();
        assert_eq!(pools.len(), 5);
        assert!(pools.iter().all(|p| p.backing.sensitive));
        let actual = pools[2]
            .to_vec()
            .unwrap()
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect::<Vec<_>>();
        let expected = bodies.concat();
        assert_eq!(&actual[..expected.len()], expected);
        assert!(actual[expected.len()..].iter().all(|b| *b == 0));
        assert!(copy_bytes(&mut pools[2], usize::MAX, &[1]).is_err());
        let retained = pools[2].backing();
        assert!(copy_bytes(&mut pools[2], 0, &[1]).is_err());
        drop(retained);
        for pool in &mut pools {
            let backing = Arc::get_mut(&mut pool.backing).unwrap();
            backing.wipe_sensitive_pages();
            assert!(
                backing
                    .pages
                    .iter()
                    .flat_map(|p| p.words.iter())
                    .all(|&v| v == 0)
            );
        }
    }
    #[test]
    fn uncertain_completion_retains_owners_without_output_access() {
        let mut quarantine = None;
        let mut output = [[0xA7; 32]; 1];
        let error = GpuError::CompletionUncertain {
            backend: GpuBackend::Metal,
        };
        assert!(finish(Err(error), Vec::new(), &mut quarantine, &mut output).is_err());
        assert!(quarantine.is_some());
        assert_eq!(output, [[0xA7; 32]; 1]);
    }
    #[test]
    fn completed_error_has_no_quarantine_or_output_access() {
        let mut quarantine = None;
        let mut output = [[0xA7; 32]; 1];
        let error = GpuError::InvalidInput("completed injected failure");
        assert!(finish(Err(error), Vec::new(), &mut quarantine, &mut output).is_err());
        assert!(quarantine.is_none());
        assert_eq!(output, [[0xA7; 32]; 1]);
    }
    #[test]
    fn completed_output_is_opaque_little_endian_and_exact() {
        let words = [u64::MAX, 0, 0x0123_4567_89ab_cdef, 0x8000_0000_0000_0000];
        let buffer = PooledBuffer::from_slice(&words).unwrap();
        let mut output = [[0; 32]; 1];
        collect(&buffer, &mut output).unwrap();
        assert_eq!(
            output[0].to_vec(),
            words
                .into_iter()
                .flat_map(u64::to_le_bytes)
                .collect::<Vec<_>>()
        );
        assert!(collect(&buffer, &mut []).is_err());
    }
}
