//! Design §5.3 runtime capacity check.
//!
//! Before an operation proves its step, and again before it commits, the wallet checks the
//! phone it is running on, at that moment. Free bytes in its no-backup custody storage must
//! cover the operation's commit, recovery and output reservation plus the fold witnesses the
//! step adds until a durable Ω covers it. Memory currently available to the app must cover the
//! peak proving memory of the relations that prove the step and fold it; one prover runs at a
//! time, so the largest of them bounds the operation.
//!
//! Each relation has two bounds ([`KagemushaWalletProvingMemoryV1`]): the fused quotient, which
//! transforms every coset column at once and is the fastest, and the lean quotient, which
//! evaluates the same terms in passes of at most [`KAGEMUSHA_WALLET_LEAN_QUOTIENT_COLUMNS_V1`]
//! columns and costs extra coset FFTs. Admission requires the lean bound, so a phone with less
//! memory still pays offline. Each proof of a fold proves fused whenever the memory available
//! when the fold started covers its own relation's fused bound, so small relations stay fused
//! while a larger one needs passes; below that bound, every column's worth of memory above the
//! relation's lean bound widens the passes by one column, so more memory means fewer passes
//! and fewer FFTs ([`kagemusha_wallet_quotient_columns_v1`]). Both plans write identical proof
//! bytes.
//!
//! Both bounds come from the installed, authenticated relation descriptors and checkpoint
//! layouts, never from a phone model, device class, roster or published per-model budget. The
//! check adds no field to the artifact manifest, verifier pack, producer inventory or
//! transport. A failed check refuses the operation before commit with a typed
//! `NotEnoughStorage` or `NotEnoughMemory` result, never a device verdict: nothing is debited
//! or credited and the holder retries after freeing storage or memory. A measured peak above
//! the computed bound is a defect in [`iroha_plonk::prover::peak_proving_columns`], fixed in
//! code.

use iroha_pasta::msm::PROCESS_MSM_SCRATCH_BYTES;
use iroha_plonk::{
    cs::ProtocolDescriptor,
    prover::{bounded_quotient_columns, peak_proving_columns},
};

/// Bytes of one scalar-field element in a proving vector.
const FIELD_BYTES: u64 = 32;
/// Bytes of one affine generator in the pinned parameters.
const POINT_BYTES: u64 = 64;
/// Resident wallet-core baseline outside the prover (`specs/kagemusha_lambda_omega_v1.md` §6).
pub const KAGEMUSHA_WALLET_CORE_BASELINE_BYTES_V1: u64 = 50 << 20;
/// Coset columns a lean proof's quotient transforms at once.
pub const KAGEMUSHA_WALLET_LEAN_QUOTIENT_COLUMNS_V1: usize = 16;

/// What one operation needs on this phone before it may prove or commit.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct KagemushaWalletRuntimeCapacityV1 {
    /// Free no-backup custody bytes.
    pub storage_bytes: u64,
    /// Memory available to the app.
    pub memory_bytes: u64,
}

/// What this phone has at the moment of the check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KagemushaWalletRuntimeResourcesV1 {
    /// Free bytes of the no-backup custody storage.
    pub storage_bytes: u64,
    /// Memory currently available to the app, or `None` when the OS gives no answer.
    ///
    /// An unanswered memory probe never becomes a refusal: the holder could not free memory to
    /// change it. Proving then runs as it would without the check, and an OS memory kill is
    /// ordinary process death recovered at the next start (design §1.2, §5.3). The storage
    /// bound is always evaluated.
    pub memory_bytes: Option<u64>,
}

/// The bound a phone did not meet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KagemushaWalletCapacityShortfallV1 {
    /// Free custody storage is below the operation's reservation.
    Storage,
    /// Available memory is below the operation's peak proving memory.
    Memory,
}

/// Peak proving memory under both quotient plans (see the module documentation).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct KagemushaWalletProvingMemoryV1 {
    /// Every coset column transformed at once: the fastest plan.
    pub fused_bytes: u64,
    /// Passes of at most [`KAGEMUSHA_WALLET_LEAN_QUOTIENT_COLUMNS_V1`] coset columns; never
    /// above `fused_bytes`.
    pub lean_bytes: u64,
    /// What one more quotient column adds to the lean bound: one domain vector of the largest
    /// domain, with the bound's 15% margin.
    pub column_bytes: u64,
}

impl KagemushaWalletProvingMemoryV1 {
    /// The bounds of a relation that always proves fused, such as a σ step.
    #[must_use]
    pub fn fused_only(self) -> Self {
        Self {
            lean_bytes: self.fused_bytes,
            ..self
        }
    }

    /// Larger of both bounds of `self` and `other`.
    #[must_use]
    pub fn max(self, other: Self) -> Self {
        Self {
            fused_bytes: self.fused_bytes.max(other.fused_bytes),
            lean_bytes: self.lean_bytes.max(other.lean_bytes),
            column_bytes: self.column_bytes.max(other.column_bytes),
        }
    }

    /// The prover's quotient columns for a proof with `available` bytes: `None`, the fused
    /// plan, when they cover the fused bound or the OS gives no answer; otherwise the lean
    /// width plus one column per `column_bytes` above the lean bound. Each lean bound counts
    /// passes at least the lean width, and a plan `x` columns wider holds passes at most `x`
    /// columns wider, so the extra memory stays within the extra columns paid for.
    #[must_use]
    pub fn quotient_columns(&self, available: Option<u64>) -> Option<usize> {
        match available {
            Some(available) if available < self.fused_bytes => {
                let extra = available
                    .saturating_sub(self.lean_bytes)
                    .checked_div(self.column_bytes)
                    .unwrap_or(0);
                Some(
                    KAGEMUSHA_WALLET_LEAN_QUOTIENT_COLUMNS_V1
                        .saturating_add(usize::try_from(extra).unwrap_or(usize::MAX)),
                )
            }
            _ => None,
        }
    }
}

impl KagemushaWalletRuntimeCapacityV1 {
    /// Larger of both bounds of `self` and `other`.
    #[must_use]
    pub fn max(self, other: Self) -> Self {
        Self {
            storage_bytes: self.storage_bytes.max(other.storage_bytes),
            memory_bytes: self.memory_bytes.max(other.memory_bytes),
        }
    }

    /// Check `available` against this requirement; storage first.
    ///
    /// # Errors
    ///
    /// The first bound `available` does not meet.
    pub fn check(
        &self,
        available: &KagemushaWalletRuntimeResourcesV1,
    ) -> Result<(), KagemushaWalletCapacityShortfallV1> {
        if available.storage_bytes < self.storage_bytes {
            return Err(KagemushaWalletCapacityShortfallV1::Storage);
        }
        match available.memory_bytes {
            Some(memory) if memory < self.memory_bytes => {
                Err(KagemushaWalletCapacityShortfallV1::Memory)
            }
            _ => Ok(()),
        }
    }
}

/// Conservative peak proving memory of `columns` field columns of `2^k` rows, in bytes: the
/// columns with a 15% margin, the pinned `g` and `g_lagrange` parameters (`2·64·2^k` bytes),
/// the process-wide 64 MiB MSM scratch cap and the 50 MiB wallet-core baseline. `None` on
/// overflow.
fn peak_bytes(k: u8, columns: usize) -> Option<u64> {
    let n = 1_u64.checked_shl(u32::from(k))?;
    let margined = u64::try_from(columns)
        .ok()?
        .checked_mul(FIELD_BYTES)?
        .checked_mul(n)?
        .checked_mul(115)?
        .div_ceil(100);
    margined
        .checked_add(POINT_BYTES.checked_mul(2)?.checked_mul(n)?)?
        .checked_add(u64::try_from(PROCESS_MSM_SCRATCH_BYTES).ok()?)?
        .checked_add(KAGEMUSHA_WALLET_CORE_BASELINE_BYTES_V1)
}

/// Both quotient plans' peak proving memory of one installed relation descriptor.
///
/// The prover counts the field columns one proof holds at its peak, key included
/// ([`iroha_plonk::prover::peak_proving_columns`]); a measured peak above that count is a defect
/// there, fixed in code. The lean bound counts passes at least
/// [`KAGEMUSHA_WALLET_LEAN_QUOTIENT_COLUMNS_V1`] columns wide, so a plan `x` columns wider holds
/// at most `x` more columns. `None` for a descriptor whose columns cannot be counted.
#[must_use]
pub fn kagemusha_wallet_relation_proving_memory_v1(
    descriptor: &ProtocolDescriptor,
) -> Option<KagemushaWalletProvingMemoryV1> {
    let width = KAGEMUSHA_WALLET_LEAN_QUOTIENT_COLUMNS_V1;
    let fused = peak_proving_columns(descriptor, None).ok()?.total();
    // The coset powers, instance columns and lookup numerators come on top of the passes.
    let floor = width
        .checked_add(1)?
        .checked_add(descriptor.instance_lengths.len())?
        .checked_add(descriptor.lookups.len())?;
    let workspace = bounded_quotient_columns(descriptor, width).ok()?;
    let lean = peak_proving_columns(descriptor, Some(width))
        .ok()?
        .total()
        .checked_add(floor.saturating_sub(workspace))?
        .min(fused);
    let n = 1_u64.checked_shl(u32::from(descriptor.k))?;
    Some(KagemushaWalletProvingMemoryV1 {
        fused_bytes: peak_bytes(descriptor.k, fused)?,
        lean_bytes: peak_bytes(descriptor.k, lean)?,
        column_bytes: FIELD_BYTES.checked_mul(n)?.checked_mul(115)?.div_ceil(100),
    })
}

/// The quotient plan of one proof of `descriptor` with `available` bytes: that relation's own
/// [`KagemushaWalletProvingMemoryV1::quotient_columns`], so a relation whose fused bound fits
/// proves fused while a larger one needs passes. `None`, the fused plan, also for a descriptor
/// whose bound cannot be computed; admission computed every installed one.
#[must_use]
pub fn kagemusha_wallet_quotient_columns_v1(
    descriptor: &ProtocolDescriptor,
    available: Option<u64>,
) -> Option<usize> {
    kagemusha_wallet_relation_proving_memory_v1(descriptor)?.quotient_columns(available)
}

/// `MemAvailable` of one `/proc/meminfo` text, in bytes; `None` when absent or malformed.
#[must_use]
pub fn kagemusha_wallet_meminfo_available_v1(text: &str) -> Option<u64> {
    let line = text
        .lines()
        .find_map(|line| line.strip_prefix("MemAvailable:"))?;
    let mut parts = line.split_whitespace();
    let kib: u64 = parts.next()?.parse().ok()?;
    if parts.next()? != "kB" || parts.next().is_some() {
        return None;
    }
    kib.checked_mul(1024)
}

/// Memory currently available to this process from the OS, or `None` without an answer.
///
/// Linux and Android read the kernel's `MemAvailable` estimate from `/proc/meminfo`, which
/// every Android app can read. Apple adapters answer with `os_proc_available_memory()` through
/// their platform owner instead; other hosts give no answer.
#[must_use]
pub fn kagemusha_wallet_native_available_memory_v1() -> Option<u64> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        std::fs::read_to_string("/proc/meminfo")
            .ok()
            .and_then(|text| kagemusha_wallet_meminfo_available_v1(&text))
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peak_bytes_add_margin_parameters_scratch_and_baseline() {
        // 133 columns of 2 MiB, +15%, + 8 MiB parameters + 64 MiB MSM + 50 MiB core.
        assert_eq!(
            peak_bytes(16, 133),
            Some(320_759_399 + (8 << 20) + (64 << 20) + (50 << 20))
        );
        assert!(peak_bytes(16, 134) > peak_bytes(16, 133));
        assert!(peak_bytes(17, 133) > peak_bytes(16, 133));
        assert_eq!(peak_bytes(64, 1), None);
        assert_eq!(peak_bytes(16, usize::MAX), None);
    }

    fn installed_descriptors() -> Vec<iroha_plonk::keys::DescriptorBinding> {
        let (pack, _) =
            crate::kagemusha_wallet_artifacts_v1::engineering_fixture::signed_inventory();
        pack.steps
            .iter()
            .map(|step| step.artifact.descriptor.as_slice())
            .chain([pack.lineage.descriptor.as_slice()])
            .map(|bytes| iroha_plonk::keys::DescriptorBinding::decode_v2(bytes).unwrap())
            .collect()
    }

    #[test]
    fn bounds_count_the_provers_peak_columns_of_installed_descriptors() {
        let width = KAGEMUSHA_WALLET_LEAN_QUOTIENT_COLUMNS_V1;
        let bindings = installed_descriptors();
        for binding in &bindings {
            let descriptor = binding.descriptor();
            let memory = kagemusha_wallet_relation_proving_memory_v1(descriptor).unwrap();
            let fused = peak_proving_columns(descriptor, None).unwrap();
            let lean = peak_proving_columns(descriptor, Some(width)).unwrap();
            assert_eq!(fused.key, lean.key);
            assert_eq!(
                Some(memory.fused_bytes),
                peak_bytes(descriptor.k, fused.total())
            );
            // The lean count, with passes counted at least the lean width, never above fused.
            let floor = width + 1 + descriptor.instance_lengths.len() + descriptor.lookups.len();
            let workspace = bounded_quotient_columns(descriptor, width).unwrap();
            let columns = (lean.total() + floor.saturating_sub(workspace)).min(fused.total());
            assert_eq!(Some(memory.lean_bytes), peak_bytes(descriptor.k, columns));
            assert!(memory.lean_bytes <= memory.fused_bytes);
            assert_eq!(
                memory.column_bytes,
                ((32_u64 << descriptor.k) * 115).div_ceil(100)
            );
            // A plan `x` columns wider than the lean width holds at most `x` more columns.
            for extra in [1, 4, 16, 64] {
                let wider = peak_proving_columns(descriptor, Some(width + extra))
                    .unwrap()
                    .total()
                    .min(fused.total());
                assert!(
                    wider <= columns + extra,
                    "{extra}: {wider} > {columns} + {extra}"
                );
            }
            // Never below the fixed parameter, MSM and wallet-core terms.
            let floor = 128_u64 << descriptor.k;
            assert!(
                memory.lean_bytes > floor + (64 << 20) + KAGEMUSHA_WALLET_CORE_BASELINE_BYTES_V1
            );
        }
        assert!(!bindings.is_empty());
    }

    #[test]
    fn quotient_columns_widen_with_memory_and_prove_fused_when_it_covers_it() {
        let memory = KagemushaWalletProvingMemoryV1 {
            fused_bytes: 100,
            lean_bytes: 60,
            column_bytes: 10,
        };
        let lean = KAGEMUSHA_WALLET_LEAN_QUOTIENT_COLUMNS_V1;
        assert_eq!(
            memory.quotient_columns(None),
            None,
            "no answer proves fused"
        );
        assert_eq!(memory.quotient_columns(Some(100)), None);
        assert_eq!(memory.quotient_columns(Some(99)), Some(lean + 3));
        assert_eq!(memory.quotient_columns(Some(70)), Some(lean + 1));
        assert_eq!(memory.quotient_columns(Some(69)), Some(lean));
        assert_eq!(memory.quotient_columns(Some(60)), Some(lean));
        assert_eq!(memory.quotient_columns(Some(0)), Some(lean));
        assert_eq!(
            memory.fused_only(),
            KagemushaWalletProvingMemoryV1 {
                lean_bytes: 100,
                ..memory
            }
        );
        let no_column = KagemushaWalletProvingMemoryV1 {
            column_bytes: 0,
            ..memory
        };
        assert_eq!(no_column.quotient_columns(Some(99)), Some(lean));
        let other = KagemushaWalletProvingMemoryV1 {
            fused_bytes: 90,
            lean_bytes: 80,
            column_bytes: 20,
        };
        assert_eq!(
            memory.max(other),
            KagemushaWalletProvingMemoryV1 {
                fused_bytes: 100,
                lean_bytes: 80,
                column_bytes: 20
            }
        );
    }

    #[test]
    fn check_refuses_storage_first_and_memory_only_with_an_answer() {
        let need = KagemushaWalletRuntimeCapacityV1 {
            storage_bytes: 10,
            memory_bytes: 20,
        };
        let have = |storage_bytes, memory_bytes| KagemushaWalletRuntimeResourcesV1 {
            storage_bytes,
            memory_bytes,
        };
        assert_eq!(need.check(&have(10, Some(20))), Ok(()));
        assert_eq!(
            need.check(&have(9, Some(20))),
            Err(KagemushaWalletCapacityShortfallV1::Storage)
        );
        assert_eq!(
            need.check(&have(9, Some(0))),
            Err(KagemushaWalletCapacityShortfallV1::Storage)
        );
        assert_eq!(
            need.check(&have(10, Some(19))),
            Err(KagemushaWalletCapacityShortfallV1::Memory)
        );
        // No OS answer evaluates storage only.
        assert_eq!(need.check(&have(10, None)), Ok(()));
        assert_eq!(
            need.check(&have(0, None)),
            Err(KagemushaWalletCapacityShortfallV1::Storage)
        );
        let other = KagemushaWalletRuntimeCapacityV1 {
            storage_bytes: 30,
            memory_bytes: 5,
        };
        assert_eq!(
            need.max(other),
            KagemushaWalletRuntimeCapacityV1 {
                storage_bytes: 30,
                memory_bytes: 20
            }
        );
    }

    #[test]
    fn meminfo_reads_only_a_well_formed_mem_available_line() {
        let text = "MemTotal:        7834512 kB\nMemFree:          301234 kB\nMemAvailable:    2048000 kB\nBuffers:           1234 kB\n";
        assert_eq!(
            kagemusha_wallet_meminfo_available_v1(text),
            Some(2_048_000 * 1024)
        );
        for malformed in [
            "MemTotal: 7834512 kB\nMemFree: 301234 kB\n",
            "MemAvailable: 2048000\n",
            "MemAvailable: 2048000 MB\n",
            "MemAvailable: -1 kB\n",
            "MemAvailable: 2048000 kB extra\n",
            "MemAvailable: 18446744073709551615 kB\n",
            "",
        ] {
            assert_eq!(
                kagemusha_wallet_meminfo_available_v1(malformed),
                None,
                "{malformed:?}"
            );
        }
    }

    #[test]
    fn each_proof_chooses_its_plan_from_its_own_relation() {
        let (pack, _) =
            crate::kagemusha_wallet_artifacts_v1::engineering_fixture::signed_inventory();
        let bindings: Vec<_> = pack
            .steps
            .iter()
            .map(|step| step.artifact.descriptor.as_slice())
            .chain([pack.lineage.descriptor.as_slice()])
            .map(|bytes| iroha_plonk::keys::DescriptorBinding::decode_v2(bytes).unwrap())
            .collect();
        let memory: Vec<_> = bindings
            .iter()
            .map(|binding| kagemusha_wallet_relation_proving_memory_v1(binding.descriptor()))
            .collect::<Option<_>>()
            .unwrap();
        let lean = KAGEMUSHA_WALLET_LEAN_QUOTIENT_COLUMNS_V1;
        for (binding, memory) in bindings.iter().zip(&memory) {
            let columns =
                |available| kagemusha_wallet_quotient_columns_v1(binding.descriptor(), available);
            assert_eq!(columns(None), None);
            assert_eq!(columns(Some(memory.fused_bytes)), None);
            if memory.lean_bytes < memory.fused_bytes {
                assert_eq!(columns(Some(memory.lean_bytes)), Some(lean));
                assert!(columns(Some(memory.fused_bytes - 1)).is_some_and(|wide| wide >= lean));
            }
        }
        // Memory that covers the smallest relation's fused bound but not the largest one's:
        // the small proof stays fused while the large proof takes passes.
        let (small, large) = (
            (0..memory.len())
                .min_by_key(|&index| memory[index].fused_bytes)
                .unwrap(),
            (0..memory.len())
                .max_by_key(|&index| memory[index].fused_bytes)
                .unwrap(),
        );
        let available = Some(memory[small].fused_bytes);
        assert_eq!(
            kagemusha_wallet_quotient_columns_v1(bindings[small].descriptor(), available),
            None
        );
        if memory[small].fused_bytes < memory[large].fused_bytes {
            assert!(
                kagemusha_wallet_quotient_columns_v1(bindings[large].descriptor(), available)
                    .is_some()
            );
        }
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn native_probe_answers_on_linux_kernels() {
        assert!(kagemusha_wallet_native_available_memory_v1().is_some_and(|bytes| bytes > 0));
    }
}
