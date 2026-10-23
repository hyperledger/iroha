//! Canonical source capacity and checked bootstrap sizing for FASTPQ execution.
//!
//! These nominal values belong to an agreed genesis policy, never node-local
//! prover settings. Construction and sizing do not authenticate an execution,
//! reserve State capacity, bound non-source mandatory work, or enable proof admission.
//! The bootstrap profile is carried by `BlockParameters`; Core owns authenticated
//! genesis installation, frozen block snapshots and complete reservation lifecycles.

use super::ExecutionOutputPolicyV1;
use iroha_crypto::Hash;

/// Six exact source dimensions for complete logical execution entries.
///
/// E/T/D/I/S add across distinct entries; M takes their maximum. One entry's
/// original occurrences share one statement frame, so its M equals its S.
/// Empty/rejected execution calls still contribute E=1 and may have no source.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    norito::Encode,
    norito::Decode,
    norito::NoritoSchema,
    iroha_schema::IntoSchema,
    norito::derive::JsonSerialize,
)]
#[norito_schema(
    name = "iroha_data_model::parameter::fastpq_source::FastpqSourceLimitsV1",
    frame = "iroha_data_model::parameter::FastpqSourceLimitsV1"
)]
#[norito(deny_unknown_fields)]
pub struct FastpqSourceLimitsV1 {
    /// E: complete logical entry count, including calls without transfers.
    pub max_executed_entries: u32,
    /// T: original nonempty transcript occurrence count.
    pub max_transcripts: u32,
    /// D: original transfer delta count; participant rows require twice this count.
    pub max_deltas: u32,
    /// I: sum of complete canonical original transcript frames, including paths.
    pub max_input_transcript_bytes: u64,
    /// M: largest complete logical-entry public statement frame.
    pub max_statement_bytes: u64,
    /// S: sum of complete statement frames for distinct entries.
    pub max_total_statement_bytes: u64,
}

impl FastpqSourceLimitsV1 {
    /// Empty aggregate usage, not an unlimited or selectable bootstrap policy.
    pub const ZERO: Self = Self {
        max_executed_entries: 0,
        max_transcripts: 0,
        max_deltas: 0,
        max_input_transcript_bytes: 0,
        max_statement_bytes: 0,
        max_total_statement_bytes: 0,
    };

    /// Add complete disjoint entry contributions, retaining M as a maximum.
    ///
    /// This never combines separately measured fragments of the same entry.
    /// # Errors
    /// Rejects any count/byte overflow; no partial aggregate is returned.
    pub fn checked_add_entries(self, other: Self) -> Result<Self, String> {
        Ok(Self {
            max_executed_entries: self
                .max_executed_entries
                .checked_add(other.max_executed_entries)
                .ok_or("FASTPQ source entry aggregate overflows u32")?,
            max_transcripts: self
                .max_transcripts
                .checked_add(other.max_transcripts)
                .ok_or("FASTPQ transcript aggregate overflows u32")?,
            max_deltas: self
                .max_deltas
                .checked_add(other.max_deltas)
                .ok_or("FASTPQ delta aggregate overflows u32")?,
            max_input_transcript_bytes: self
                .max_input_transcript_bytes
                .checked_add(other.max_input_transcript_bytes)
                .ok_or("FASTPQ transcript byte aggregate overflows u64")?,
            max_statement_bytes: self.max_statement_bytes.max(other.max_statement_bytes),
            max_total_statement_bytes: self
                .max_total_statement_bytes
                .checked_add(other.max_total_statement_bytes)
                .ok_or("FASTPQ statement byte aggregate overflows u64")?,
        })
    }

    /// Reserve the same complete entry bound for a finite number of distinct entries.
    /// # Errors
    /// Rejects count/byte overflow. Zero repetitions produce empty usage.
    pub fn checked_repeat_entries(self, count: u32) -> Result<Self, String> {
        if count == 0 {
            return Ok(Self::ZERO);
        }
        Ok(Self {
            max_executed_entries: self
                .max_executed_entries
                .checked_mul(count)
                .ok_or("FASTPQ source entry product overflows u32")?,
            max_transcripts: self
                .max_transcripts
                .checked_mul(count)
                .ok_or("FASTPQ transcript product overflows u32")?,
            max_deltas: self
                .max_deltas
                .checked_mul(count)
                .ok_or("FASTPQ delta product overflows u32")?,
            max_input_transcript_bytes: self
                .max_input_transcript_bytes
                .checked_mul(u64::from(count))
                .ok_or("FASTPQ transcript byte product overflows u64")?,
            max_statement_bytes: self.max_statement_bytes,
            max_total_statement_bytes: self
                .max_total_statement_bytes
                .checked_mul(u64::from(count))
                .ok_or("FASTPQ statement byte product overflows u64")?,
        })
    }

    /// Whether every source dimension fits its inclusive ceiling.
    #[must_use]
    pub const fn fits_within(self, ceiling: Self) -> bool {
        self.max_executed_entries <= ceiling.max_executed_entries
            && self.max_transcripts <= ceiling.max_transcripts
            && self.max_deltas <= ceiling.max_deltas
            && self.max_input_transcript_bytes <= ceiling.max_input_transcript_bytes
            && self.max_statement_bytes <= ceiling.max_statement_bytes
            && self.max_total_statement_bytes <= ceiling.max_total_statement_bytes
    }

    fn validate_nonempty(self) -> Result<(), String> {
        if self.max_executed_entries == 0
            || self.max_transcripts == 0
            || self.max_deltas < self.max_transcripts
            || self.max_input_transcript_bytes == 0
            || self.max_statement_bytes == 0
            || self.max_total_statement_bytes < self.max_statement_bytes
        {
            return Err("FASTPQ source policy needs ordered positive finite dimensions".into());
        }
        Ok(())
    }

    fn validate_single_entry(self) -> Result<(), String> {
        self.validate_nonempty()?;
        if self.max_executed_entries != 1
            || self.max_deltas.checked_mul(2).is_none()
            || self.max_statement_bytes != self.max_total_statement_bytes
        {
            return Err(
                "FASTPQ intrinsic source bound needs E=1, M=S and u32 participant rows".into(),
            );
        }
        Ok(())
    }
}

/// Global retained-obligation source allowance, independent of expiry buckets.
///
/// A zero/failed obligation remains in the retained count even if it emits no
/// source entry. Core must reserve before custody changes, replace atomically,
/// preserve failed retries, and release only when the obligation disappears.
/// This profile does not bound traversal, audit/event bytes or other non-source work.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    norito::Encode,
    norito::Decode,
    norito::NoritoSchema,
    iroha_schema::IntoSchema,
    norito::derive::JsonSerialize,
)]
#[norito_schema(
    name = "iroha_data_model::parameter::fastpq_source::FastpqMandatorySourcePolicyV1",
    frame = "iroha_data_model::parameter::FastpqMandatorySourcePolicyV1"
)]
#[norito(deny_unknown_fields)]
pub struct FastpqMandatorySourcePolicyV1 {
    /// Maximum globally retained obligations, including zero and failed obligations.
    pub max_retained_obligations: u32,
    /// Finite source ceiling for one complete future protocol-purpose entry.
    pub per_obligation: FastpqSourceLimitsV1,
}

impl FastpqMandatorySourcePolicyV1 {
    /// Reserve all retained obligations, so accumulated overdue retries fit too.
    /// # Errors
    /// Rejects an empty policy, malformed per-entry limits or aggregate overflow.
    pub fn reservation(self) -> Result<FastpqSourceLimitsV1, String> {
        if self.max_retained_obligations == 0 {
            return Err("FASTPQ mandatory source policy needs a positive obligation count".into());
        }
        self.per_obligation.validate_single_entry()?;
        self.per_obligation
            .checked_repeat_entries(self.max_retained_obligations)
    }
}

/// Nominal consensus source profile for one immutable first-release genesis policy.
///
/// Intrinsic entry ceilings include every retained business/penalty/fee fragment.
/// Block ceilings include separately reserved native and mandatory source pools. No local
/// construction budget or verifier setting can substitute for this policy.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    norito::Encode,
    norito::Decode,
    norito::NoritoSchema,
    iroha_schema::IntoSchema,
    norito::derive::JsonSerialize,
)]
#[norito_schema(
    name = "iroha_data_model::parameter::fastpq_source::FastpqSourcePolicyV1",
    frame = "iroha_data_model::parameter::FastpqSourcePolicyV1"
)]
#[norito(deny_unknown_fields)]
pub struct FastpqSourcePolicyV1 {
    /// Exact finite per-logical-entry source ceilings.
    pub intrinsic: FastpqSourceLimitsV1,
    /// Exact finite total block source ceilings, including native and mandatory pools.
    pub block: FastpqSourceLimitsV1,
    /// Separately reserved optional native-maintenance entries per block.
    /// Each entry uses the intrinsic limits and cannot borrow trigger or governance capacity.
    pub max_native_maintenance_invocations: u32,
    /// Reserved source capacity for every retained mandatory obligation.
    pub mandatory: FastpqMandatorySourcePolicyV1,
}

impl FastpqSourcePolicyV1 {
    /// Shared bounded native pool for SNS auto-renewal and retail idle settlement.
    /// Retail selects at most half, alternating the odd slot by block height;
    /// unused capacity remains available to the later SNS sweep.
    pub const NATIVE_MAINTENANCE_INVOCATIONS: u32 = 64;
    /// Supported bootstrap Network count, including generated four-validator
    /// genesis with its optional executor and committee-key transaction groups.
    /// This is a finite supported corpus, not a universal genesis size bound.
    pub const BOOTSTRAP_NETWORK_INPUTS: u32 = 11;

    /// Finite first-release corpus ceiling under the bootstrap output envelope.
    ///
    /// Eleven full Network plans reserve 256 Pipeline invocations per input
    /// plus the final Pipeline group and 512 Time invocations, along with 64
    /// globally retained mandatory obligations and 64 separately reserved native
    /// maintenance entries. Intrinsic byte ceilings
    /// cover the measured sixteen-singleton ML-DSA entry and the measured
    /// sixteen-member ML-DSA singleton, with maximum legal quantities and the
    /// empty original paths emitted by execution. These are supported corpus
    /// bounds, not universal bounds on account identities. Larger identities,
    /// additional fragments and supplied paths must pass exact source admission.
    /// This logical reservation does not establish wire, prover or host capacity.
    pub const fn bootstrap() -> Self {
        Self {
            intrinsic: FastpqSourceLimitsV1 {
                max_executed_entries: 1,
                max_transcripts: 16,
                max_deltas: 16,
                max_input_transcript_bytes: 137_200,
                max_statement_bytes: 272_175,
                max_total_statement_bytes: 272_175,
            },
            block: FastpqSourceLimitsV1 {
                max_executed_entries: 3_723,
                max_transcripts: 58_608,
                max_deltas: 58_608,
                max_input_transcript_bytes: 510_095_248,
                max_statement_bytes: 272_175,
                max_total_statement_bytes: 1_012_055_813,
            },
            max_native_maintenance_invocations: Self::NATIVE_MAINTENANCE_INVOCATIONS,
            mandatory: FastpqMandatorySourcePolicyV1 {
                max_retained_obligations: 64,
                per_obligation: FastpqSourceLimitsV1 {
                    max_executed_entries: 1,
                    max_transcripts: 1,
                    max_deltas: 1,
                    max_input_transcript_bytes: 126_257,
                    max_statement_bytes: 252_617,
                    max_total_statement_bytes: 252_617,
                },
            },
        }
    }

    /// Derive a finite candidate from explicit measured entry bounds and output policy.
    ///
    /// This is a sizing owner, not an authenticated installation or reservation.
    /// Inputs must describe the supported corpus, not a universal identity bound.
    /// Registry and Time maxima come from the agreed output envelope; every
    /// potential invocation conservatively reserves the complete intrinsic bound.
    /// # Errors
    /// Rejects malformed input, arithmetic overflow or an infeasible terminal plan.
    pub fn from_sizing(
        output: ExecutionOutputPolicyV1,
        intrinsic: FastpqSourceLimitsV1,
        mandatory: FastpqMandatorySourcePolicyV1,
        network_inputs: u32,
    ) -> Result<Self, String> {
        intrinsic.validate_single_entry()?;
        let reserve = mandatory.reservation()?;
        if !mandatory.per_obligation.fits_within(intrinsic)
            || network_inputs == 0
            || network_inputs > output.maximum_terminal_network_inputs()?
        {
            return Err("FASTPQ sizing needs an intrinsic-covered mandatory entry and feasible Network input".into());
        }
        let count = invocation_count(output, network_inputs)?
            .checked_add(Self::NATIVE_MAINTENANCE_INVOCATIONS)
            .ok_or("FASTPQ native invocation count overflows u32")?;
        let block = intrinsic
            .checked_repeat_entries(count)?
            .checked_add_entries(reserve)?;
        let profile = Self {
            intrinsic,
            block,
            max_native_maintenance_invocations: Self::NATIVE_MAINTENANCE_INVOCATIONS,
            mandatory,
        };
        profile.validate(output)?;
        Ok(profile)
    }

    /// Check all source ceilings and one-input feasibility under the output envelope.
    /// # Errors
    /// Rejects incoherent/overflowing profiles or profiles that strand one full input plan.
    pub fn validate(self, output: ExecutionOutputPolicyV1) -> Result<(), String> {
        if self.maximum_network_inputs(output)? == 0 {
            return Err(
                "FASTPQ source policy cannot reserve one complete Network input plan".into(),
            );
        }
        Ok(())
    }

    /// Conservative Network count fitting source and canonical terminal envelopes.
    ///
    /// This is pure policy arithmetic. It does not let a validator truncate a
    /// committed input set or establish full wire/host/mandatory-work admission.
    /// # Errors
    /// Rejects malformed policy, overflow or a base internal/mandatory pool that cannot fit.
    pub fn maximum_network_inputs(self, output: ExecutionOutputPolicyV1) -> Result<u32, String> {
        self.intrinsic.validate_single_entry()?;
        self.block.validate_nonempty()?;
        let reserve = self.mandatory.reservation()?;
        if !self.intrinsic.fits_within(self.block)
            || !self.mandatory.per_obligation.fits_within(self.intrinsic)
        {
            return Err("FASTPQ source policy does not cover intrinsic/mandatory entries".into());
        }
        let terminal = output.maximum_terminal_network_inputs()?;
        let native = self.native_maintenance_reservation()?;
        let base = self
            .intrinsic
            .checked_repeat_entries(invocation_count(output, 0)?)?
            .checked_add_entries(reserve)?
            .checked_add_entries(native)?;
        if !base.fits_within(self.block) {
            return Err("FASTPQ block source capacity omits its internal/mandatory base".into());
        }
        let slope = self.intrinsic.checked_repeat_entries(
            output
                .max_pipeline_triggers
                .checked_add(1)
                .ok_or("FASTPQ per-input invocation count overflows u32")?,
        )?;
        let pairs = [
            (
                u64::from(self.block.max_executed_entries - base.max_executed_entries),
                u64::from(slope.max_executed_entries),
            ),
            (
                u64::from(self.block.max_transcripts - base.max_transcripts),
                u64::from(slope.max_transcripts),
            ),
            (
                u64::from(self.block.max_deltas - base.max_deltas),
                u64::from(slope.max_deltas),
            ),
            (
                self.block.max_input_transcript_bytes - base.max_input_transcript_bytes,
                slope.max_input_transcript_bytes,
            ),
            (
                self.block.max_total_statement_bytes - base.max_total_statement_bytes,
                slope.max_total_statement_bytes,
            ),
        ];
        let maximum = pairs
            .into_iter()
            .fold(u64::from(terminal), |count, (remaining, per_input)| {
                count.min(remaining / per_input)
            });
        u32::try_from(maximum).map_err(|_| "FASTPQ admissible Network count exceeds u32".into())
    }

    /// Canonical nominal profile digest; callers must authenticate the containing state.
    /// # Errors
    /// Rejects malformed/infeasible policy or canonical encoding failure.
    pub fn digest(self, output: ExecutionOutputPolicyV1) -> Result<Hash, String> {
        self.validate(output)?;
        let frame = norito::encode_canonical(&self).map_err(|error| error.to_string())?;
        Ok(Hash::new(frame))
    }

    /// Exact disjoint native-maintenance reservation under this committed policy.
    /// # Errors
    /// Rejects zero or overflowing native capacity before execution.
    pub fn native_maintenance_reservation(self) -> Result<FastpqSourceLimitsV1, String> {
        self.intrinsic.validate_single_entry()?;
        if self.max_native_maintenance_invocations == 0 {
            return Err("FASTPQ native maintenance capacity must be positive".into());
        }
        self.intrinsic
            .checked_repeat_entries(self.max_native_maintenance_invocations)
    }
}

fn invocation_count(output: ExecutionOutputPolicyV1, network: u32) -> Result<u32, String> {
    network
        .checked_add(1)
        .and_then(|events| events.checked_mul(output.max_pipeline_triggers))
        .and_then(|pipeline| pipeline.checked_add(network))
        .and_then(|calls| calls.checked_add(output.max_time_invocations))
        .ok_or_else(|| "FASTPQ complete invocation count overflows u32".into())
}

impl core::fmt::Display for FastpqSourcePolicyV1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{:?},{:?},{},{:?}_FASTPQ_SOURCE",
            self.intrinsic, self.block, self.max_native_maintenance_invocations, self.mandatory
        )
    }
}

#[cfg(test)]
#[path = "fastpq_source/tests.rs"]
mod tests;

impl norito::json::JsonDeserialize for FastpqSourceLimitsV1 {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        super::system::parameters_json::decode_fastpq_limits(parser)
    }
}

impl norito::json::JsonDeserialize for FastpqMandatorySourcePolicyV1 {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        super::system::parameters_json::decode_fastpq_mandatory(parser)
    }
}

impl norito::json::JsonDeserialize for FastpqSourcePolicyV1 {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        super::system::parameters_json::decode_fastpq_source(parser)
    }
}
