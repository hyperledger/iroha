//! Explicit same-process arithmetic diagnostic on SHA-pinned native public columns.

use std::{collections::BTreeMap, path::PathBuf, time::Instant};

use super::*;
use ff::Field;
use group::{Curve, GroupEncoding};
use iroha_pasta::Ep;

use crate::pcs::ipa::commit::{
    Secrecy, commit_lagrange_cancellable, test_observation::CommitmentProbe,
};

type Scalar = <Ep as PastaCurve>::ScalarExt;
type Point = <Ep as PastaCurve>::AffineExt;
type Fixture = (u32, Vec<[u8; 32]>, Vec<Vec<[u8; 32]>>);
type Columns = (Vec<Point>, Vec<Vec<Scalar>>);

fn read_case(directory: &std::path::Path, slots: usize) -> Columns {
    let path = directory.join(format!("load-signature-{slots}.norito"));
    assert!(path.metadata().unwrap().len() <= 512 << 20);
    let encoded = std::fs::read(path).unwrap();
    let expected = std::env::var(format!("IROHA_PUBLIC_COLUMN_FIXTURE_{slots}_SHA256")).unwrap();
    assert_eq!(format!("{:x}", Sha256::digest(&encoded)), expected);
    // The hash-pinned diagnostic includes every canonical byte of two large
    // native public tables; keep its larger decode allowance local and finite.
    let limits = norito::DecodeLimits::new(1 << 20, 512 << 20, 1 << 28, 1 << 30, 16);
    let previous_archive_limit = norito::core::max_archive_len();
    norito::core::set_max_archive_len(512 << 20);
    let decoded = norito::decode_from_bytes_with_limits(&encoded, limits);
    norito::core::set_max_archive_len(previous_archive_limit);
    let (k, points, columns): Fixture = decoded.unwrap();
    assert_eq!(k, 16);
    assert!(!columns.is_empty() && columns.len() <= 256);
    assert_eq!(points.len(), columns.len());
    let columns = columns
        .into_iter()
        .map(|column| {
            assert_eq!(column.len(), 1 << k);
            column
                .into_iter()
                .map(|bytes| Scalar::from_repr(bytes).into_option().unwrap())
                .collect()
        })
        .collect();
    let points = points
        .into_iter()
        .map(|bytes| Point::from_bytes(&bytes).into_option().unwrap())
        .collect();
    (points, columns)
}

fn monolithic(owner: &PinnedParams<Ep>, cases: &[Columns], trial: usize) {
    // This is the previous computation path, with its identical whole-column
    // digest/reuse. The two fixture cases cannot reach the 8,192-entry bound.
    let mut whole = BTreeMap::new();
    for (case, (expected, columns)) in cases.iter().enumerate() {
        let probe = CommitmentProbe::start();
        let started = Instant::now();
        for (point, values) in expected.iter().zip(columns) {
            let digest = super::super::column_digest(values, None).unwrap();
            let actual = *whole.entry(digest).or_insert_with(|| {
                commit_lagrange_cancellable(
                    owner.params(),
                    values,
                    &Scalar::from(DEFAULT_BLIND),
                    Secrecy::Public,
                    MemoryBudget::DEFAULT,
                    None,
                )
                .unwrap()
                .to_affine()
            });
            assert_eq!(actual, *point);
        }
        assert!(whole.len() < super::super::MAX_COLUMNS);
        println!(
            "PUBLIC_COLUMN_ARITHMETIC trial={trial} path=monolithic case={case} columns={} milliseconds={} whole_misses={}",
            columns.len(),
            started.elapsed().as_millis(),
            probe.calls()
        );
    }
}

fn partial(owner: &PinnedParams<Ep>, cases: &[Columns], trial: usize) {
    // Clear only this diagnostic's optional computed memo between cold trials.
    *owner.public_columns.lock().unwrap() = super::super::PublicColumnCache::default();
    for (case, (expected, columns)) in cases.iter().enumerate() {
        let full = CommitmentProbe::start();
        let blocks = CommitmentProbe::start_partial();
        let started = Instant::now();
        for (point, values) in expected.iter().zip(columns) {
            assert_eq!(
                owner
                    .commit_public_column_cancellable(values, MemoryBudget::DEFAULT, None)
                    .unwrap(),
                *point
            );
        }
        let elapsed = started.elapsed().as_millis();
        let cache = owner.public_columns.lock().unwrap();
        assert!(cache.blocks.points.len() <= MAX_BLOCKS);
        println!(
            "PUBLIC_COLUMN_ARITHMETIC trial={trial} path=partial case={case} columns={} milliseconds={elapsed} whole_misses={} partial_msms={} retained_partials={} point_bytes={} digest_bytes=32 fifo_digest_bytes=32",
            columns.len(),
            full.calls(),
            blocks.calls(),
            cache.blocks.points.len(),
            std::mem::size_of::<Ep>()
        );
    }
}

#[test]
#[ignore = "requires SHA-pinned fixtures exported by the genuine k16 Load Q native test; explicit arithmetic diagnostic"]
fn actual_native_columns_compare_monolithic_and_partial_cold_and_nearby_reuse() {
    let directory = PathBuf::from(std::env::var_os("IROHA_PUBLIC_COLUMN_FIXTURE_DIR").unwrap());
    let cases = [read_case(&directory, 1), read_case(&directory, 2)];
    let owner = PinnedParams::<Ep>::derive(16).unwrap();
    println!(
        "PUBLIC_COLUMN_ARITHMETIC_SCOPE native_k16_load_signature_columns=true authority=false phone_timing=false full_admission=false rayon_threads={}",
        rayon::current_num_threads()
    );
    for trial in 0..3 {
        if trial % 2 == 0 {
            monolithic(&owner, &cases, trial);
            partial(&owner, &cases, trial);
        } else {
            partial(&owner, &cases, trial);
            monolithic(&owner, &cases, trial);
        }
    }
}

// Ignored diagnostic: compare bounded within-column scheduling on exact
// SHA-pinned native columns before considering any production scheduler change.

use group::Group;
use std::sync::atomic::{AtomicUsize, Ordering};

fn bounded_wave_column(
    owner: &PinnedParams<Ep>,
    values: &[Scalar],
    wave: usize,
    shared: &SharedMemoryBudget,
    cancellation: Option<&CancellationToken>,
    whole_misses: &mut usize,
    partial_calls: &AtomicUsize,
) -> Result<Point, MsmError> {
    assert!(matches!(wave, 1 | 2 | 4 | 8));
    CancellationToken::checkpoint(cancellation)?;
    let bases = owner.params().g_lagrange();
    if values.len() > bases.len() {
        return Err(MsmError::LengthMismatch(iroha_pasta::LengthMismatch {
            left: values.len(),
            right: bases.len(),
        }));
    }
    let whole_digest = super::super::column_digest(values, cancellation)?;
    if let Some(point) = owner
        .public_columns
        .lock()
        .ok()
        .and_then(|cache| cache.points.get(&whole_digest).copied())
    {
        CancellationToken::checkpoint(cancellation)?;
        return Ok(point);
    }
    *whole_misses += 1;
    let mut sum = Ep::identity();
    // Each wave owns at most eight borrowed block views and eight computed
    // points. No scalar/base copies or whole-column work lists are allocated.
    for (wave_index, wave_values) in values.chunks(BLOCK_ROWS * wave).enumerate() {
        let mut work = Vec::with_capacity(wave);
        for (index, block) in wave_values.chunks(BLOCK_ROWS).enumerate() {
            let offset = (wave_index * wave + index) * BLOCK_ROWS;
            let Some(digest) = block_digest(offset, block, cancellation)? else {
                continue;
            };
            let cached = owner
                .public_columns
                .lock()
                .ok()
                .and_then(|cache| cache.blocks.points.get(&digest).copied());
            work.push((offset, digest, block, cached));
        }
        // The existing kernels retain their ordinary plan, shared 64 MiB
        // admission, cancellation and allocation-free contention fallback.
        // Indexed collection joins every worker and preserves row-offset order.
        let completed: Vec<Result<([u8; 32], Ep, bool), MsmError>> = work
            .into_par_iter()
            .map(|(offset, digest, block, cached)| {
                CancellationToken::checkpoint(cancellation)?;
                if let Some(point) = cached {
                    return Ok((digest, point, false));
                }
                partial_calls.fetch_add(1, Ordering::Relaxed);
                let point = msm_public_cancellable::<Ep>(
                    block,
                    &bases[offset..offset + block.len()],
                    MemoryBudget::DEFAULT,
                    shared,
                    cancellation,
                )?;
                CancellationToken::checkpoint(cancellation)?;
                Ok((digest, point, true))
            })
            .collect();
        CancellationToken::checkpoint(cancellation)?;
        for result in completed {
            let (digest, point, computed) = result?;
            CancellationToken::checkpoint(cancellation)?;
            if computed {
                if let Ok(mut cache) = owner.public_columns.lock() {
                    cache.blocks.insert(digest, point);
                }
            }
            sum += point;
        }
    }
    sum += owner.params().w().to_curve() * Scalar::from(DEFAULT_BLIND);
    CancellationToken::checkpoint(cancellation)?;
    let point = sum.to_affine();
    if let Ok(mut cache) = owner.public_columns.lock() {
        cache.insert(whole_digest, point);
    }
    CancellationToken::checkpoint(cancellation)?;
    Ok(point)
}

fn bounded_waves(owner: &PinnedParams<Ep>, cases: &[Columns], trial: usize, wave: usize) {
    *owner.public_columns.lock().unwrap() = super::super::PublicColumnCache::default();
    let shared = SharedMemoryBudget::new(64 << 20);
    for (case, (expected, columns)) in cases.iter().enumerate() {
        let mut whole_misses = 0;
        let partial_calls = AtomicUsize::new(0);
        let started = Instant::now();
        for (point, values) in expected.iter().zip(columns) {
            assert_eq!(
                bounded_wave_column(
                    owner,
                    values,
                    wave,
                    &shared,
                    None,
                    &mut whole_misses,
                    &partial_calls,
                )
                .unwrap(),
                *point,
            );
        }
        let elapsed = started.elapsed().as_millis();
        assert_eq!(shared.in_use_bytes(), 0);
        assert!(shared.peak_bytes() <= 64 << 20);
        let cache = owner.public_columns.lock().unwrap();
        assert!(cache.points.len() <= super::super::MAX_COLUMNS);
        assert!(cache.blocks.points.len() <= MAX_BLOCKS);
        println!(
            "PUBLIC_COLUMN_WAVE_ARITHMETIC trial={trial} wave={wave} case={case} columns={} milliseconds={elapsed} whole_misses={whole_misses} partial_msms={} retained_partials={} scratch_peak_bytes={} point_bytes={}",
            columns.len(),
            partial_calls.load(Ordering::Relaxed),
            cache.blocks.points.len(),
            shared.peak_bytes(),
            std::mem::size_of::<Ep>(),
        );
    }
}

#[test]
#[ignore = "explicit SHA-pinned native-column scheduling diagnostic only; no production scheduler changes"]
fn actual_native_columns_compare_bounded_waves() {
    let directory = PathBuf::from(std::env::var_os("IROHA_PUBLIC_COLUMN_FIXTURE_DIR").unwrap());
    let cases = [read_case(&directory, 1), read_case(&directory, 2)];
    let owner = PinnedParams::<Ep>::derive(16).unwrap();
    println!(
        "PUBLIC_COLUMN_WAVE_SCOPE native_k16_load_signature_columns=true authority=false phone_timing=false full_admission=false rayon_threads={} waves=1,2,4,8 scratch_ceiling_bytes={}",
        rayon::current_num_threads(),
        64 << 20,
    );
    for trial in 0..3 {
        if trial % 2 == 0 {
            monolithic(&owner, &cases, trial);
        }
        let mut waves = [1, 2, 4, 8];
        waves.rotate_left(trial);
        for wave in waves {
            bounded_waves(&owner, &cases, trial, wave);
        }
        if trial % 2 == 1 {
            monolithic(&owner, &cases, trial);
        }
    }
}

// Ignored scalar-suffix hashing diagnostic; production hashing is unchanged.
// Scalar-suffix hash diagnostic on retained actual native tables. The fixture
// lacks original descriptor/copy/selector prefix; this is NOT an original
// fingerprint or admission test. Production prefix parity needs genuine tests.

type SourceAndColumns = ([u8; 32], Vec<[u8; 32]>);

#[derive(Clone, Copy)]
enum HashSchedule {
    TwoPass,
    FusedScalars,
    FusedBatches,
}

fn diagnostic_source_prefix() -> Sha256 {
    let mut source = Sha256::new();
    source.update(b"iroha:diagnostic:actual-public-scalar-suffix:v1\0");
    source
}

fn actual_table_hashes(
    columns: &[Vec<Scalar>],
    schedule: HashSchedule,
    cancellation: Option<&CancellationToken>,
) -> Result<SourceAndColumns, MsmError> {
    CancellationToken::checkpoint(cancellation)?;
    let mut source = diagnostic_source_prefix();
    let mut digests = Vec::with_capacity(columns.len());
    if matches!(schedule, HashSchedule::TwoPass) {
        for column in columns {
            for (row, value) in column.iter().enumerate() {
                if row % 1024 == 0 {
                    CancellationToken::checkpoint(cancellation)?;
                }
                source.update(value.to_repr());
            }
        }
        for column in columns {
            digests.push(super::super::column_digest(column, cancellation)?);
        }
    } else {
        let mut buffer = [0_u8; 256 * 32];
        for column in columns {
            let mut hash = Sha256::new();
            hash.update(super::super::COLUMN_DOMAIN);
            hash.update(DEFAULT_BLIND.to_le_bytes());
            hash.update((column.len() as u64).to_le_bytes());
            if matches!(schedule, HashSchedule::FusedScalars) {
                for (row, value) in column.iter().enumerate() {
                    if row % 1024 == 0 {
                        CancellationToken::checkpoint(cancellation)?;
                    }
                    let canonical = value.to_repr();
                    source.update(canonical);
                    hash.update(canonical);
                }
            } else {
                for chunk in column.chunks(256) {
                    CancellationToken::checkpoint(cancellation)?;
                    for (value, slot) in chunk.iter().zip(buffer.chunks_exact_mut(32)) {
                        slot.copy_from_slice(&value.to_repr());
                    }
                    let canonical = &buffer[..chunk.len() * 32];
                    source.update(canonical);
                    hash.update(canonical);
                }
            }
            CancellationToken::checkpoint(cancellation)?;
            digests.push(hash.finalize().into());
        }
    }
    CancellationToken::checkpoint(cancellation)?;
    Ok((source.finalize().into(), digests))
}

#[test]
#[ignore = "explicit actual-native scalar-suffix hashing diagnostic only; no source authority or production changes"]
fn actual_native_columns_compare_two_pass_and_fused_canonicalization() {
    let directory = PathBuf::from(std::env::var_os("IROHA_PUBLIC_COLUMN_FIXTURE_DIR").unwrap());
    let cases = [read_case(&directory, 1), read_case(&directory, 2)];
    println!(
        "PUBLIC_SCALAR_HASH_SCOPE native_k16_load_signature_columns=true source_prefix=diagnostic_only original_fingerprint=false authority=false phone_timing=false"
    );
    for (case, (_, columns)) in cases.iter().enumerate() {
        let expected = actual_table_hashes(columns, HashSchedule::TwoPass, None).unwrap();
        let rows: usize = columns.iter().map(Vec::len).sum();
        for trial in 0..5 {
            let mut schedules = [
                HashSchedule::TwoPass,
                HashSchedule::FusedScalars,
                HashSchedule::FusedBatches,
            ];
            schedules.rotate_left(trial % 3);
            for schedule in schedules {
                let (name, canonicalizations, stack_bytes) = match schedule {
                    HashSchedule::TwoPass => ("two_pass", rows * 2, 0),
                    HashSchedule::FusedScalars => ("fused_scalars", rows, 0),
                    HashSchedule::FusedBatches => ("fused_batches", rows, 8192),
                };
                let started = Instant::now();
                let actual =
                    actual_table_hashes(std::hint::black_box(columns), schedule, None).unwrap();
                let elapsed = started.elapsed().as_micros();
                assert_eq!(actual, expected);
                println!(
                    "PUBLIC_SCALAR_HASH trial={trial} case={case} schedule={name} microseconds={elapsed} rows={rows} canonicalizations={canonicalizations} extra_stack_bytes={stack_bytes} column_hashes={}",
                    columns.len()
                );
            }
        }
    }
}

// Only this explicitly ignored diagnostic tests representation reuse. The
// production constructor remains the reference and does not use either shortcut.
#[derive(Clone, Copy)]
enum ReprSchedule {
    CurrentFused,
    LastValue,
    ZeroOne,
    LastValueZeroOne,
}

const ZERO_REPR: [u8; 32] = [0; 32];
const ONE_REPR: [u8; 32] = {
    let mut bytes = [0; 32];
    bytes[0] = 1;
    bytes
};

fn reused_repr_hashes<const LAST: bool, const ZERO_ONE: bool>(
    columns: &[Vec<Scalar>],
    cancellation: Option<&CancellationToken>,
) -> Result<SourceAndColumns, MsmError> {
    CancellationToken::checkpoint(cancellation)?;
    let mut source = diagnostic_source_prefix();
    let mut digests = Vec::with_capacity(columns.len());
    for column in columns {
        let mut hash = Sha256::new();
        hash.update(super::super::COLUMN_DOMAIN);
        hash.update(DEFAULT_BLIND.to_le_bytes());
        hash.update((column.len() as u64).to_le_bytes());
        // At most one native scalar, one canonical repr and one initialized bit.
        // Reuse is determined solely by equality with the actual native scalar.
        let mut previous = Scalar::ZERO;
        let mut canonical = ZERO_REPR;
        let mut initialized = false;
        for (row, value) in column.iter().enumerate() {
            if row % 1024 == 0 {
                CancellationToken::checkpoint(cancellation)?;
            }
            if !LAST || !initialized || *value != previous {
                canonical = if ZERO_ONE && *value == Scalar::ZERO {
                    ZERO_REPR
                } else if ZERO_ONE && *value == Scalar::ONE {
                    ONE_REPR
                } else {
                    value.to_repr()
                };
                if LAST {
                    previous = *value;
                    initialized = true;
                }
            }
            // Match production order, framing, row order and update granularity.
            hash.update(canonical);
            source.update(canonical);
        }
        CancellationToken::checkpoint(cancellation)?;
        digests.push(hash.finalize().into());
    }
    CancellationToken::checkpoint(cancellation)?;
    Ok((source.finalize().into(), digests))
}

fn repr_table_hashes(
    columns: &[Vec<Scalar>],
    schedule: ReprSchedule,
    cancellation: Option<&CancellationToken>,
) -> Result<SourceAndColumns, MsmError> {
    match schedule {
        ReprSchedule::CurrentFused => {
            CancellationToken::checkpoint(cancellation)?;
            let mut source = diagnostic_source_prefix();
            let mut digests = Vec::with_capacity(columns.len());
            for column in columns {
                let handle = super::super::HashedPublicColumn::with_canonical_sink(
                    column,
                    |bytes| source.update(bytes),
                    cancellation,
                )?;
                digests.push(handle.digest);
            }
            CancellationToken::checkpoint(cancellation)?;
            Ok((source.finalize().into(), digests))
        }
        ReprSchedule::LastValue => reused_repr_hashes::<true, false>(columns, cancellation),
        ReprSchedule::ZeroOne => reused_repr_hashes::<false, true>(columns, cancellation),
        ReprSchedule::LastValueZeroOne => reused_repr_hashes::<true, true>(columns, cancellation),
    }
}

#[test]
#[ignore = "explicit actual-native scalar representation diagnostic only; production canonicalization unchanged"]
fn actual_native_columns_compare_bounded_repr_reuse() {
    assert_eq!(Scalar::ZERO.to_repr(), ZERO_REPR);
    assert_eq!(Scalar::ONE.to_repr(), ONE_REPR);
    let schedules = [
        ReprSchedule::CurrentFused,
        ReprSchedule::LastValue,
        ReprSchedule::ZeroOne,
        ReprSchedule::LastValueZeroOne,
    ];
    let small = vec![
        vec![],
        vec![Scalar::ZERO; 5],
        vec![Scalar::ONE; 5],
        vec![Scalar::from(17); 5],
        vec![Scalar::ZERO, Scalar::ONE, Scalar::ZERO, -Scalar::ONE],
    ];
    let expected = repr_table_hashes(&small, ReprSchedule::CurrentFused, None).unwrap();
    let cancelled = CancellationToken::new();
    cancelled.cancel();
    for schedule in schedules {
        assert_eq!(repr_table_hashes(&small, schedule, None).unwrap(), expected);
        assert_eq!(
            repr_table_hashes(&small, schedule, Some(&cancelled)),
            Err(MsmError::Cancelled)
        );
    }
    let directory = PathBuf::from(std::env::var_os("IROHA_PUBLIC_COLUMN_FIXTURE_DIR").unwrap());
    let cases = [read_case(&directory, 1), read_case(&directory, 2)];
    println!(
        "PUBLIC_REPR_SCOPE native_k16_load_signature_columns=true source_prefix=diagnostic_only original_fingerprint=false authority=false phone_timing=false production_changed=false reuse_resets_each_column=true max_reuse_state_bytes={}",
        std::mem::size_of::<Scalar>() + std::mem::size_of::<[u8; 32]>() + 1,
    );
    for (case, (_, columns)) in cases.iter().enumerate() {
        let expected = repr_table_hashes(columns, ReprSchedule::CurrentFused, None).unwrap();
        // All frequencies and implied conversion counts are outside timed loops.
        let mut rows = 0_usize;
        let mut zero = 0_usize;
        let mut one = 0_usize;
        let mut consecutive_equal = 0_usize;
        let mut changed_nonzero_nonone = 0_usize;
        for column in columns {
            let mut previous = None;
            for value in column {
                rows += 1;
                zero += usize::from(*value == Scalar::ZERO);
                one += usize::from(*value == Scalar::ONE);
                let equal = previous == Some(*value);
                consecutive_equal += usize::from(equal);
                changed_nonzero_nonone +=
                    usize::from(!equal && *value != Scalar::ZERO && *value != Scalar::ONE);
                previous = Some(*value);
            }
        }
        println!(
            "PUBLIC_REPR_COUNTS case={case} rows={rows} columns={} consecutive_equal={consecutive_equal} zero={zero} one={one} changed_nonzero_nonone={changed_nonzero_nonone}",
            columns.len(),
        );
        for trial in 0..5 {
            let mut order = schedules;
            order.rotate_left(trial % schedules.len());
            if trial % 2 == 1 {
                order.reverse();
            }
            for schedule in order {
                let (name, conversions) = match schedule {
                    ReprSchedule::CurrentFused => ("current_fused", rows),
                    ReprSchedule::LastValue => ("last_value", rows - consecutive_equal),
                    ReprSchedule::ZeroOne => ("zero_one", rows - zero - one),
                    ReprSchedule::LastValueZeroOne => {
                        ("last_value_zero_one", changed_nonzero_nonone)
                    }
                };
                let started = Instant::now();
                let actual =
                    repr_table_hashes(std::hint::black_box(columns), schedule, None).unwrap();
                let elapsed = started.elapsed().as_micros();
                assert_eq!(actual, expected, "every column and source-suffix hash");
                println!(
                    "PUBLIC_REPR trial={trial} case={case} schedule={name} microseconds={elapsed} rows={rows} canonicalizations={conversions} column_hashes={}",
                    columns.len(),
                );
            }
        }
    }
}

// Separate bounded experiment: avoid a per-scalar reuse branch on ordinary
// varied columns, and bulk-update SHA only for proven equal native chunks.
fn constant_chunk_hashes(
    columns: &[Vec<Scalar>],
    cancellation: Option<&CancellationToken>,
) -> Result<SourceAndColumns, MsmError> {
    CancellationToken::checkpoint(cancellation)?;
    let mut source = diagnostic_source_prefix();
    let mut digests = Vec::with_capacity(columns.len());
    let mut repeated = [0_u8; 256 * 32];
    let mut buffered_repr = ZERO_REPR;
    for column in columns {
        let mut hash = Sha256::new();
        hash.update(super::super::COLUMN_DOMAIN);
        hash.update(DEFAULT_BLIND.to_le_bytes());
        hash.update((column.len() as u64).to_le_bytes());
        for chunk in column.chunks(256) {
            CancellationToken::checkpoint(cancellation)?;
            let first = chunk.first().expect("chunks are nonempty");
            if chunk.iter().skip(1).all(|value| value == first) {
                let canonical = first.to_repr();
                if canonical != buffered_repr {
                    for slot in repeated.chunks_exact_mut(32) {
                        slot.copy_from_slice(&canonical);
                    }
                    buffered_repr = canonical;
                }
                let bytes = &repeated[..chunk.len() * 32];
                hash.update(bytes);
                source.update(bytes);
            } else {
                for value in chunk {
                    let canonical = value.to_repr();
                    hash.update(canonical);
                    source.update(canonical);
                }
            }
        }
        CancellationToken::checkpoint(cancellation)?;
        digests.push(hash.finalize().into());
    }
    CancellationToken::checkpoint(cancellation)?;
    Ok((source.finalize().into(), digests))
}

#[test]
#[ignore = "explicit constant-native-chunk hashing diagnostic only; production canonicalization unchanged"]
fn actual_native_columns_compare_constant_chunk_canonicalization() {
    assert_eq!(Scalar::ZERO.to_repr(), ZERO_REPR);
    let small = vec![
        vec![],
        vec![Scalar::ZERO; 257],
        vec![Scalar::ONE; 513],
        vec![Scalar::from(17); 255],
        vec![-Scalar::ONE; 256],
        vec![Scalar::ZERO, Scalar::ONE, Scalar::ZERO, -Scalar::ONE],
    ];
    assert_eq!(
        constant_chunk_hashes(&small, None).unwrap(),
        repr_table_hashes(&small, ReprSchedule::CurrentFused, None).unwrap()
    );
    let cancelled = CancellationToken::new();
    cancelled.cancel();
    assert_eq!(
        constant_chunk_hashes(&small, Some(&cancelled)),
        Err(MsmError::Cancelled)
    );
    let directory = PathBuf::from(std::env::var_os("IROHA_PUBLIC_COLUMN_FIXTURE_DIR").unwrap());
    let cases = [read_case(&directory, 1), read_case(&directory, 2)];
    println!(
        "PUBLIC_CONSTANT_CHUNK_SCOPE native_k16_load_signature_columns=true source_prefix=diagnostic_only original_fingerprint=false authority=false phone_timing=false production_changed=false chunk_rows=256 buffer_bytes=8192"
    );
    for (case, (_, columns)) in cases.iter().enumerate() {
        let expected = repr_table_hashes(columns, ReprSchedule::CurrentFused, None).unwrap();
        let rows: usize = columns.iter().map(Vec::len).sum();
        let mut chunks = 0_usize;
        let mut constant_chunks = 0_usize;
        let mut constant_rows = 0_usize;
        let mut zero_chunks = 0_usize;
        let mut one_chunks = 0_usize;
        // Frequencies and implied to_repr calls are measured outside timing.
        for chunk in columns.iter().flat_map(|column| column.chunks(256)) {
            chunks += 1;
            let first = chunk.first().unwrap();
            if chunk.iter().skip(1).all(|value| value == first) {
                constant_chunks += 1;
                constant_rows += chunk.len();
                zero_chunks += usize::from(*first == Scalar::ZERO);
                one_chunks += usize::from(*first == Scalar::ONE);
            }
        }
        println!(
            "PUBLIC_CONSTANT_CHUNK_COUNTS case={case} rows={rows} columns={} chunks={chunks} constant_chunks={constant_chunks} constant_rows={constant_rows} zero_chunks={zero_chunks} one_chunks={one_chunks}",
            columns.len(),
        );
        for trial in 0..5 {
            let order = if trial % 2 == 0 {
                [false, true]
            } else {
                [true, false]
            };
            for chunked in order {
                let started = Instant::now();
                let actual = if chunked {
                    constant_chunk_hashes(std::hint::black_box(columns), None).unwrap()
                } else {
                    repr_table_hashes(
                        std::hint::black_box(columns),
                        ReprSchedule::CurrentFused,
                        None,
                    )
                    .unwrap()
                };
                let elapsed = started.elapsed().as_micros();
                assert_eq!(actual, expected, "every column and source-suffix hash");
                let schedule = if chunked {
                    "constant_chunks"
                } else {
                    "current_fused"
                };
                let conversions = if chunked {
                    rows - constant_rows + constant_chunks
                } else {
                    rows
                };
                println!(
                    "PUBLIC_CONSTANT_CHUNK trial={trial} case={case} schedule={schedule} microseconds={elapsed} canonicalizations={conversions} column_hashes={}",
                    columns.len(),
                );
            }
        }
    }
}
