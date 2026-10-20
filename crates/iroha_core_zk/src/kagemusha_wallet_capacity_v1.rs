//! Design §5.3 runtime capacity check.
//!
//! Before an operation proves its step, and again before it commits, the wallet checks the
//! phone it is running on, at that moment. Free bytes in its no-backup custody storage must
//! cover the operation's commit, recovery and output reservation plus the fold witnesses the
//! step adds until a durable Ω covers it. Memory currently available to the app must cover the
//! peak proving memory of the relations that prove the step and fold it; one prover runs at a
//! time, so the largest of them bounds the operation.
//!
//! Both bounds come from the installed, authenticated relation descriptors and checkpoint
//! layouts, never from a phone model, device class, roster or published per-model budget. The
//! check adds no field to the artifact manifest, verifier pack, producer inventory or
//! transport. A failed check refuses the operation before commit with a typed
//! `NotEnoughStorage` or `NotEnoughMemory` result, never a device verdict: nothing is debited
//! or credited and the holder retries after freeing storage or memory. A measured peak above
//! the computed bound is a defect in [`KagemushaWalletRelationShapeV1::peak_proving_bytes`],
//! fixed in code.

use iroha_pasta::msm::PROCESS_MSM_SCRATCH_BYTES;
use iroha_plonk::cs::ProtocolDescriptor;

/// Bytes of one scalar-field element in a proving vector.
const FIELD_BYTES: u64 = 32;
/// Bytes of one affine generator in the pinned parameters.
const POINT_BYTES: u64 = 64;
/// Resident wallet-core baseline outside the prover (`specs/kagemusha_lambda_omega_v1.md` §6).
pub const KAGEMUSHA_WALLET_CORE_BASELINE_BYTES_V1: u64 = 50 << 20;

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

/// Proving shape of one relation, read from its authenticated descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KagemushaWalletRelationShapeV1 {
    /// `log2` of the domain size.
    pub k: u8,
    /// Circuit degree `d`.
    pub degree: u8,
    /// Fixed columns `F` after selector substitution.
    pub fixed: u32,
    /// Advice columns `n_a`.
    pub advice: u32,
    /// Equality columns `m`.
    pub equality: u32,
    /// Columns per permutation product, `d - 2`.
    pub permutation_chunk: u8,
    /// Lookup arguments `n_l`.
    pub lookups: u32,
}

impl KagemushaWalletRelationShapeV1 {
    /// Shape of one installed descriptor; `None` for counts outside `u32`.
    #[must_use]
    pub fn of(descriptor: &ProtocolDescriptor) -> Option<Self> {
        Some(Self {
            k: descriptor.k,
            degree: descriptor.degree,
            fixed: descriptor.num_fixed_columns,
            advice: descriptor.num_advice_columns,
            equality: u32::try_from(descriptor.permutation.len()).ok()?,
            permutation_chunk: descriptor.permutation_chunk_len,
            lookups: u32::try_from(descriptor.lookups.len()).ok()?,
        })
    }

    /// Conservative peak proving memory of this relation, in bytes.
    ///
    /// The quotient phase is the peak (`specs/kagemusha_lambda_omega_v1.md` §6 RAM plan). It holds
    /// `PK[2(F + m) + 6] + witness[2·n_a + 8·n_l + 2·n_z] + coset[n_a + F + m + n_z + 3·n_l + 4] + 2(d − 1)`
    /// domain vectors of `32·2^k` bytes, with the owned-witness copy factor 2 and
    /// `n_z = ⌈m / (d − 2)⌉` permutation products. The bound adds 15% to those vectors, then the
    /// pinned `g` and `g_lagrange` parameters (`2·64·2^k` bytes), the process-wide 64 MiB MSM
    /// scratch cap and the 50 MiB wallet-core baseline. `None` for an inconsistent shape.
    #[must_use]
    pub fn peak_proving_bytes(&self) -> Option<u64> {
        let n = 1_u64.checked_shl(u32::from(self.k))?;
        let degree = u64::from(self.degree);
        let chunk = u64::from(self.permutation_chunk);
        if degree < 3 || chunk == 0 {
            return None;
        }
        let fixed = u64::from(self.fixed);
        let advice = u64::from(self.advice);
        let equality = u64::from(self.equality);
        let lookups = u64::from(self.lookups);
        let products = equality.div_ceil(chunk);
        let proving_key = 2 * (fixed + equality) + 6;
        let witness = 2 * advice + 8 * lookups + 2 * products;
        let coset = advice + fixed + equality + products + 3 * lookups + 4;
        let quotient = 2 * (degree - 1);
        let vectors = proving_key + witness + coset + quotient;
        let vector_bytes = vectors.checked_mul(FIELD_BYTES)?.checked_mul(n)?;
        let margined = vector_bytes.checked_mul(115)?.div_ceil(100);
        let parameters = POINT_BYTES.checked_mul(2)?.checked_mul(n)?;
        margined
            .checked_add(parameters)?
            .checked_add(u64::try_from(PROCESS_MSM_SCRATCH_BYTES).ok()?)?
            .checked_add(KAGEMUSHA_WALLET_CORE_BASELINE_BYTES_V1)
    }
}

/// Conservative peak proving memory of one installed relation descriptor.
#[must_use]
pub fn kagemusha_wallet_relation_peak_memory_v1(descriptor: &ProtocolDescriptor) -> Option<u64> {
    KagemushaWalletRelationShapeV1::of(descriptor)?.peak_proving_bytes()
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

    fn shape(
        advice: u32,
        fixed: u32,
        equality: u32,
        lookups: u32,
    ) -> KagemushaWalletRelationShapeV1 {
        KagemushaWalletRelationShapeV1 {
            k: 16,
            degree: 6,
            fixed,
            advice,
            equality,
            permutation_chunk: 4,
            lookups,
        }
    }

    fn gib_hundredths(bytes: u64) -> u64 {
        // Round to the two decimals the RAM plan publishes.
        (bytes * 100 + (1 << 29)) >> 30
    }

    #[test]
    fn peak_reproduces_the_published_owned_witness_estimates() {
        // specs/kagemusha_lambda_omega_v1.md §6, owned estimate (c = 2): A 0.84, Q 0.67,
        // Ω/W 0.42 GiB.
        let a = shape(32, 44, 10, 3).peak_proving_bytes().unwrap();
        let q = shape(22, 32, 8, 3).peak_proving_bytes().unwrap();
        let omega = shape(11, 18, 4, 1).peak_proving_bytes().unwrap();
        assert_eq!(gib_hundredths(a), 84);
        assert_eq!(gib_hundredths(q), 67);
        assert_eq!(gib_hundredths(omega), 42);
        // 133 vectors of 2 MiB, +15%, + 8 MiB parameters + 64 MiB MSM + 50 MiB core.
        assert_eq!(omega, 320_759_399 + (8 << 20) + (64 << 20) + (50 << 20));
    }

    #[test]
    fn peak_grows_with_every_descriptor_count_and_rejects_inconsistent_shapes() {
        let base = shape(11, 18, 4, 1);
        let peak = base.peak_proving_bytes().unwrap();
        for changed in [
            KagemushaWalletRelationShapeV1 { advice: 12, ..base },
            KagemushaWalletRelationShapeV1 { fixed: 19, ..base },
            KagemushaWalletRelationShapeV1 {
                equality: 5,
                ..base
            },
            KagemushaWalletRelationShapeV1 { lookups: 2, ..base },
            KagemushaWalletRelationShapeV1 { degree: 7, ..base },
            KagemushaWalletRelationShapeV1 { k: 17, ..base },
        ] {
            assert!(changed.peak_proving_bytes().unwrap() > peak, "{changed:?}");
        }
        let smaller = KagemushaWalletRelationShapeV1 { k: 12, ..base };
        assert!(smaller.peak_proving_bytes().unwrap() < peak);
        for invalid in [
            KagemushaWalletRelationShapeV1 { degree: 2, ..base },
            KagemushaWalletRelationShapeV1 {
                permutation_chunk: 0,
                ..base
            },
            KagemushaWalletRelationShapeV1 { k: 64, ..base },
        ] {
            assert_eq!(invalid.peak_proving_bytes(), None, "{invalid:?}");
        }
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
    fn shapes_are_read_from_authenticated_installed_descriptors() {
        let (pack, _) =
            crate::kagemusha_wallet_artifacts_v1::engineering_fixture::signed_inventory();
        let descriptors = pack
            .steps
            .iter()
            .map(|step| step.artifact.descriptor.as_slice())
            .chain([pack.lineage.descriptor.as_slice()]);
        let mut checked = 0;
        for bytes in descriptors {
            let binding = iroha_plonk::keys::DescriptorBinding::decode_v2(bytes).unwrap();
            let descriptor = binding.descriptor();
            let shape = KagemushaWalletRelationShapeV1::of(descriptor).unwrap();
            assert_eq!(shape.k, descriptor.k);
            assert_eq!(shape.degree, descriptor.degree);
            assert_eq!(shape.fixed, descriptor.num_fixed_columns);
            assert_eq!(shape.advice, descriptor.num_advice_columns);
            assert_eq!(shape.equality as usize, descriptor.permutation.len());
            assert_eq!(shape.permutation_chunk, descriptor.permutation_chunk_len);
            assert_eq!(shape.lookups as usize, descriptor.lookups.len());
            let peak = kagemusha_wallet_relation_peak_memory_v1(descriptor).unwrap();
            assert_eq!(Some(peak), shape.peak_proving_bytes());
            // Never below the fixed parameter, MSM and wallet-core terms.
            let floor = 128_u64 << descriptor.k;
            assert!(peak > floor + (64 << 20) + KAGEMUSHA_WALLET_CORE_BASELINE_BYTES_V1);
            checked += 1;
        }
        assert_eq!(checked, pack.steps.len() + 1);
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn native_probe_answers_on_linux_kernels() {
        assert!(kagemusha_wallet_native_available_memory_v1().is_some_and(|bytes| bytes > 0));
    }
}
