//! Bounded exact-root FFT with independent tiles and globally ordered stages.
//!
//! Caller columns are published only after the entire command completes. The
//! sole private copy uses the existing clearing, Arc-backed shared allocation;
//! the existing dispatch ticket drains or quarantines it on error and unwind.

use super::*;

const LANES: u64 = 256;
const LOCAL_LOG: u32 = 8;
const BUTTERFLIES_PER_GROUP: u64 = 2048;
pub(super) const BIT_REVERSE_KERNEL: &str = "exact_root_bit_reverse_v1";
pub(super) const LOCAL_TILES_KERNEL: &str = "exact_root_local_tiles_v1";
pub(super) const GLOBAL_STAGE_KERNEL: &str = "exact_root_global_stage_v1";

#[derive(Clone, Copy)]
#[repr(C)]
struct ExactRootFftArgs {
    column_len: u64,
    normalization: u64,
    log_len: u32,
    column_count: u32,
    stage: u32,
    padding: u32,
}

/// The public exact-root facade validates canonicality and root order first.
pub fn transform(
    columns: &mut [Vec<u64>],
    log_size: u32,
    root: u64,
    inverse: bool,
) -> MetalResult<()> {
    let _drain_scope = DrainScope::enter(METAL_COMMAND_TIMEOUT);
    ensure_backend_available()?;
    let extent = goldilocks_domain_len(log_size)?;
    if log_size == 0
        || columns.is_empty()
        || columns.len() > crate::goldilocks_transform::MAX_GOLDILOCKS_TRANSFORM_COLUMNS_V1
        || columns.iter().any(|column| column.len() != extent)
    {
        return Err(GpuError::InvalidInput(
            "invalid bounded exact-root FFT shape",
        ));
    }
    let column_count = u32::try_from(columns.len())
        .map_err(|_| GpuError::InvalidInput("exact-root FFT column count exceeds u32"))?;
    let words = extent
        .checked_mul(columns.len())
        .ok_or(GpuError::InvalidInput(
            "exact-root FFT staging extent exceeds platform limits",
        ))?;
    let context = metal_context()?;
    for pipeline in [
        &context.exact_root_bit_reverse,
        &context.exact_root_local_tiles,
        &context.exact_root_global_stage,
    ] {
        if pipeline.max_total_threads_per_threadgroup() < LANES {
            return Err(GpuError::Unsupported(GpuBackend::Metal));
        }
    }
    validate_metal_pooled_word_len(&context.device, words)?;
    let twiddles = context.factorized_root_twiddle_buffer(log_size, root, inverse)?;
    let args = ExactRootFftArgs {
        column_len: extent as u64,
        normalization: if inverse {
            goldilocks_inv(extent as u64)
        } else {
            1
        },
        log_len: log_size,
        column_count,
        stage: 0,
        padding: 0,
    };
    let mut buffer = flatten_with_stats(columns, ColumnStagingPhase::Fft)?;
    let metal_buffer = shared_pooled_buffer(&context.device, &mut buffer)?;
    let ticket = submit(context, &metal_buffer, &twiddles, args)?;
    // Reuse the production wait/copy owner and its failure injection. This is
    // one batch covering all columns: no partial caller mutation precedes wait.
    ColumnBatchTicket {
        range: 0..columns.len(),
        buffer,
        metal_buffer,
        tickets: smallvec::smallvec![ticket],
    }
    .wait(columns, extent, true)
}

fn submit(
    context: &MetalPipelines,
    columns: &Buffer,
    twiddles: &Buffer,
    mut args: ExactRootFftArgs,
) -> MetalResult<DispatchTicket> {
    let (queue, queue_index) = context.queues.select(args.column_count, 0);
    let mut permit = CommandPermit::try_new(queue_index)?;
    autoreleasepool(|| {
        let command = try_command_buffer(queue)?;
        let encoder = try_compute_encoder(&command)?;
        encoder.set_buffer(0, Some(columns), 0);
        encoder.set_buffer(1, Some(twiddles), 0);
        let encode = |pipeline: &ComputePipelineState, groups: u64, args: &ExactRootFftArgs| {
            encoder.set_compute_pipeline_state(pipeline);
            encoder.set_bytes(
                2,
                mem::size_of::<ExactRootFftArgs>() as u64,
                ptr::from_ref(args).cast(),
            );
            encoder.dispatch_thread_groups(
                MTLSize::new(groups, u64::from(args.column_count), 1),
                MTLSize::new(LANES, 1, 1),
            );
            // A resource barrier orders writes across *all* groups. It also
            // separates bit reversal from tiles and tiles from global stages.
            // A shader threadgroup barrier cannot establish those dependencies.
            encoder.memory_barrier_with_resources(&[columns]);
        };
        encode(
            &context.exact_root_bit_reverse,
            args.column_len.div_ceil(LANES),
            &args,
        );
        encode(
            &context.exact_root_local_tiles,
            args.column_len >> args.log_len.min(LOCAL_LOG),
            &args,
        );
        for stage in LOCAL_LOG..args.log_len {
            args.stage = stage;
            encode(
                &context.exact_root_global_stage,
                (args.column_len / 2).div_ceil(BUTTERFLIES_PER_GROUP),
                &args,
            );
        }
        encoder.end_encoding();
        let completion = permit.completion();
        let completion_handler = ConcreteBlock::new(move |_| completion.complete()).copy();
        command.add_completed_handler(&completion_handler);
        permit.mark_launched();
        command.commit();
        Ok(DispatchTicket {
            command,
            trace_label: None,
            timing_start: None,
            kernel_context: None,
            permit,
            adaptive_sample: None,
            drain_budget: ticket_lifetime::ticket_budget(METAL_COMMAND_TIMEOUT),
            completion_checked: false,
        })
    })
}

#[cfg(test)]
#[path = "metal_exact_root_tests.rs"]
mod tests;
