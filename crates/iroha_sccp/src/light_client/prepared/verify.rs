//! Shared native dispatch over originally admitted canonical input and output owners.

use super::*;
use crate::light_client::{
    SccpVerifierWorkV1, bsc, ethereum,
    profile::*,
    proof::SccpLcSegmentV1,
    state::{
        SccpLcStateView,
        admitted::{SccpLcAdmittedDeltaV1, SccpLcDeltaBuilderV1, SccpLcDeltaCapacityV1},
    },
    ton,
};
use iroha_data_model::bridge::SccpNetworkV1;
use iroha_data_model::sccp::light_client::{
    SCCP_LC_BOOTSTRAP_MAX_BYTES_V1, SccpLcFreezeReasonV1, SccpLcInitExpectationV1,
    SccpLightClientParamsV1, SccpLightClientV1,
};

/// Verified initialization metadata and the original owner of its retained set bytes.
#[derive(Debug)]
pub struct SccpAdmittedInitialV1 {
    /// Scalar light-client state to install.
    pub light_client: SccpLightClientV1,
    /// Authenticated purge policy; surviving Parliament checkpoints are checked already.
    pub purge: crate::light_client::state::SccpLcPurgeV1,
    /// Originally admitted learned set, checkpoint and supersession rows.
    pub delta: SccpLcAdmittedDeltaV1,
}

impl PreparedLcFrameV1<SccpLcBootstrapDataV1> {
    /// Work performed by the already admitted bootstrap; no second decode is needed.
    #[must_use]
    pub fn work(&self) -> SccpVerifierWorkV1 {
        let (native_headers, native_header_bytes) = match &self.value {
            SccpLcBootstrapDataV1::Ethereum(_) => (0, 0),
            SccpLcBootstrapDataV1::Bsc(value) => (
                2,
                (value.checkpoint_header.len() as u64)
                    .saturating_add(value.previous_checkpoint_header.len() as u64),
            ),
            SccpLcBootstrapDataV1::Ton(value) => (
                2,
                (value.header_proof.len() as u64).saturating_add(value.config_proof.len() as u64),
            ),
        };
        SccpVerifierWorkV1 {
            native_headers,
            native_header_bytes,
            ..Default::default()
        }
        .with_frame_bytes(self.encoded_len)
    }

    /// Verify the governance expectation, bootstrap and retained conflicts in the same pool.
    ///
    /// # Errors
    /// Returns a protocol rejection or the actual original local refusal.
    pub fn verify_initialization<V: SccpLcStateView + ?Sized>(
        &self,
        profiles: &SccpChainProfilesV1,
        view: &V,
        network: SccpNetworkV1,
        expected: SccpLcInitExpectationV1,
        params: &SccpLightClientParamsV1,
        now: u64,
    ) -> Result<SccpAdmittedInitialV1, SccpLcAttemptErrorV1> {
        super::super::check_frame_len(
            "bootstrap",
            self.encoded_len,
            SCCP_LC_BOOTSTRAP_MAX_BYTES_V1,
        )?;
        let mut output = SccpLcDeltaBuilderV1::new(
            SccpLcDeltaCapacityV1 {
                new_sets: 1,
                superseded_sets: 1,
                checkpoints: usize::from(network != SccpNetworkV1::TonMainnet),
                set_bytes: self.maximum,
            },
            &self.budget,
        )?;
        let metadata = super::super::initial::initialize_into(
            profiles,
            view,
            super::super::initial::InitialRequest {
                network,
                expected,
                params,
                decoded: &self.value,
            },
            now,
            &LcMemory::admitted(&self.budget, self.maximum),
            &mut output,
        )?;
        Ok(SccpAdmittedInitialV1 {
            light_client: metadata.light_client,
            purge: metadata.purge,
            delta: output.finish(None),
        })
    }
}

/// Both exact signed evidence slices and their same-pool decoded graphs.
#[derive(Debug)]
pub struct PreparedLcEvidencePairV1<'a> {
    first_bytes: &'a [u8],
    second_bytes: &'a [u8],
    first: PreparedLcFrameV1<SccpLcEvidenceV1>,
    second: PreparedLcFrameV1<SccpLcEvidenceV1>,
}

impl<'a> PreparedLcEvidencePairV1<'a> {
    /// Admit both canonical records from one original finite allocation pool.
    ///
    /// # Errors
    /// Returns canonical rejection or an original local refusal; partial ownership is dropped.
    pub fn new(
        first: &'a [u8],
        second: &'a [u8],
        maximum: usize,
        budget: &AllocationBudget,
    ) -> Result<Self, SccpLcAttemptErrorV1> {
        Ok(Self {
            first_bytes: first,
            second_bytes: second,
            first: PreparedLcFrameV1::evidence(first, maximum, budget)?,
            second: PreparedLcFrameV1::evidence(second, maximum, budget)?,
        })
    }

    /// Sum the actual work of both admitted canonical records.
    ///
    /// # Errors
    /// Rejects an unrepresentable counter sum before verifier execution.
    pub fn work(&self) -> Result<SccpVerifierWorkV1, SccpLcAttemptErrorV1> {
        let one = |frame: &PreparedLcFrameV1<SccpLcEvidenceV1>| {
            match frame.get() {
                SccpLcEvidenceV1::Ethereum(value) => ethereum::evidence_work(value),
                SccpLcEvidenceV1::Bsc(value) => bsc::evidence_work(value),
                SccpLcEvidenceV1::Ton(value) => ton::evidence_work(value),
            }
            .with_frame_bytes(frame.encoded_len)
        };
        one(&self.first)
            .checked_add(&one(&self.second))
            .ok_or_else(|| SccpLcError::MalformedFrame("evidence work overflows").into())
    }

    /// Verify the original pair, preserving exact signed evidence hashes and allocation source.
    ///
    /// # Errors
    /// Returns protocol rejection or the original physical refusal.
    pub fn verify<V: SccpLcStateView + ?Sized>(
        &self,
        profiles: &SccpChainProfilesV1,
        view: &V,
        network: SccpNetworkV1,
        now: u64,
    ) -> Result<SccpLcFreezeReasonV1, SccpLcAttemptErrorV1> {
        super::super::ensure_supported(network)?;
        let lc = view
            .light_client(network)
            .ok_or(SccpLcError::NotInstalled(network))?;
        self.first.value.expect_network(network)?;
        self.second.value.expect_network(network)?;
        let memory = LcMemory::admitted(&self.first.budget, self.first.maximum);
        match (&self.first.value, &self.second.value) {
            (SccpLcEvidenceV1::Ethereum(a), SccpLcEvidenceV1::Ethereum(b)) => {
                ethereum::verify_equivocation_native(
                    &profiles.ethereum,
                    view,
                    &lc,
                    (a, self.first_bytes),
                    (b, self.second_bytes),
                    now,
                    &memory,
                )
            }
            (SccpLcEvidenceV1::Bsc(a), SccpLcEvidenceV1::Bsc(b)) => {
                bsc::verify_equivocation_native(
                    &profiles.bsc,
                    view,
                    &lc,
                    (a, self.first_bytes),
                    (b, self.second_bytes),
                    now,
                    &memory,
                )
            }
            (SccpLcEvidenceV1::Ton(a), SccpLcEvidenceV1::Ton(b)) => {
                ton::verify_equivocation_native(
                    &profiles.ton,
                    view,
                    (a, self.first_bytes),
                    (b, self.second_bytes),
                    now,
                    &memory,
                )
            }
            (a, b) => Err(SccpLcError::NetworkMismatch {
                expected: a.network(),
                found: b.network(),
            }
            .into()),
        }
    }
}

impl PreparedLcFrameV1<SccpLcAdvanceV1> {
    /// Exact work categories from this already admitted frame. Reserve transaction and block
    /// totals against the committed policy before invoking [`Self::verify_advance`].
    #[must_use]
    pub fn work(&self) -> SccpVerifierWorkV1 {
        match self.get() {
            SccpLcAdvanceV1::Ethereum(value) => ethereum::advance_work(value),
            SccpLcAdvanceV1::Bsc(value) => bsc::advance_work(value),
            SccpLcAdvanceV1::Ton(value) => ton::advance_work(value),
            SccpLcAdvanceV1::Backfill {
                segment: SccpLcSegmentV1::Ethereum(value),
            } => ethereum::segment_work(value),
            SccpLcAdvanceV1::Backfill {
                segment: SccpLcSegmentV1::Bsc(value),
            } => bsc::segment_work(value),
        }
        .with_frame_bytes(self.encoded_len)
    }

    /// Verify against the borrowed original state/overlay and retain every output in this
    /// frame's original finite pool. There is no replacement-budget parameter.
    ///
    /// # Errors
    /// Returns the first protocol failure or the original local physical refusal.
    pub fn verify_advance<V: SccpLcStateView + ?Sized>(
        &self,
        profiles: &SccpChainProfilesV1,
        view: &V,
        network: SccpNetworkV1,
        now: u64,
    ) -> Result<SccpLcAdmittedDeltaV1, SccpLcAttemptErrorV1> {
        super::super::ensure_supported(network)?;
        let lc = super::super::usable_light_client(view, network)?;
        super::super::check_frame_len(
            "advance",
            self.encoded_len,
            super::super::u32_bound(lc.params.max_advance_bytes),
        )?;
        self.value.expect_network(network)?;
        let (sets, checkpoints) = match &self.value {
            SccpLcAdvanceV1::Ethereum(value) => {
                let count = value.updates.len().min(ETHEREUM_MAX_UPDATES_PER_ADVANCE);
                (count, count)
            }
            SccpLcAdvanceV1::Bsc(value) => {
                let count = value.steps.len().min(BSC_MAX_STEPS_PER_ADVANCE);
                (count, 3 * count)
            }
            SccpLcAdvanceV1::Ton(value) => (value.hops.len().min(TON_MAX_HOPS_PER_ADVANCE), 0),
            SccpLcAdvanceV1::Backfill { .. } => (0, 1),
        };
        let mut output = SccpLcDeltaBuilderV1::new(
            SccpLcDeltaCapacityV1 {
                new_sets: sets,
                superseded_sets: sets,
                checkpoints,
                set_bytes: self.maximum,
            },
            &self.budget,
        )?;
        let memory = LcMemory::admitted(&self.budget, self.maximum);
        let head = match &self.value {
            SccpLcAdvanceV1::Ethereum(value) => ethereum::apply_advance_into(
                &profiles.ethereum,
                view,
                &lc,
                value,
                now,
                &memory,
                &mut output,
            )?,
            SccpLcAdvanceV1::Bsc(value) => {
                bsc::apply_advance_into(&profiles.bsc, view, &lc, value, now, &memory, &mut output)?
            }
            SccpLcAdvanceV1::Ton(value) => {
                ton::apply_advance_into(&profiles.ton, view, &lc, value, now, &memory, &mut output)?
            }
            SccpLcAdvanceV1::Backfill {
                segment: SccpLcSegmentV1::Ethereum(value),
            } => {
                ethereum::apply_backfill_into(view, &lc, value, now, &mut output)?;
                None
            }
            SccpLcAdvanceV1::Backfill {
                segment: SccpLcSegmentV1::Bsc(value),
            } => {
                bsc::apply_backfill_into(
                    &profiles.bsc,
                    view,
                    &lc,
                    value,
                    now,
                    &memory,
                    &mut output,
                )?;
                None
            }
        };
        Ok(output.finish(head))
    }
}

/// Verified fixed event fields and originally admitted proof checkpoints.
#[derive(Debug)]
pub struct SccpAdmittedProofV1 {
    /// Authenticated source event; payload data never escapes its original proof owner.
    pub event: SccpNativeEventV1,
    /// Borrow-only checkpoint output with original allocation custody.
    pub checkpoints: SccpLcAdmittedDeltaV1,
}

impl PreparedLcFrameV1<SccpSourceProofV1> {
    /// Exact work categories for reserving committed transaction and block policy totals.
    #[must_use]
    pub fn work(&self) -> SccpVerifierWorkV1 {
        match self.get() {
            SccpSourceProofV1::Ethereum(value) => ethereum::proof_work(value),
            SccpSourceProofV1::Bsc(value) => bsc::proof_work(value),
            SccpSourceProofV1::Ton(value) => ton::proof_work(value),
        }
        .with_frame_bytes(self.encoded_len)
    }

    /// Verify a proof against its immutable source/overlay with scratch and outputs charged
    /// to the same original pool that admitted this frame.
    ///
    /// # Errors
    /// Returns a protocol rejection or the original local physical refusal.
    pub fn verify_proof<V: SccpLcStateView + ?Sized>(
        &self,
        profiles: &SccpChainProfilesV1,
        view: &V,
        network: SccpNetworkV1,
        now: u64,
    ) -> Result<SccpAdmittedProofV1, SccpLcAttemptErrorV1> {
        super::super::ensure_supported(network)?;
        let lc = super::super::usable_light_client(view, network)?;
        super::super::check_frame_len(
            "source proof",
            self.encoded_len,
            super::super::u32_bound(lc.params.max_proof_bytes),
        )?;
        self.value.expect_network(network)?;
        let mut output = SccpLcDeltaBuilderV1::new(
            SccpLcDeltaCapacityV1 {
                new_sets: 0,
                superseded_sets: 0,
                checkpoints: if matches!(self.value, SccpSourceProofV1::Ton(_)) {
                    0
                } else {
                    2
                },
                set_bytes: 0,
            },
            &self.budget,
        )?;
        let memory = LcMemory::admitted(&self.budget, self.maximum);
        let event = match &self.value {
            SccpSourceProofV1::Ethereum(value) => ethereum::verify_proof_native(
                &profiles.ethereum,
                view,
                &lc,
                value,
                now,
                &memory,
                &mut output,
            )?,
            SccpSourceProofV1::Bsc(value) => bsc::verify_proof_native(
                &profiles.bsc,
                view,
                &lc,
                value,
                now,
                &memory,
                &mut output,
            )?,
            SccpSourceProofV1::Ton(value) => {
                ton::verify_proof_native(&profiles.ton, view, value, now, &memory)?
            }
        };
        Ok(SccpAdmittedProofV1 {
            event,
            checkpoints: output.finish(None),
        })
    }
}
