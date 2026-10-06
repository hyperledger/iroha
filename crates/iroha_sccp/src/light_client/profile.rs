//! Compiled source-chain profiles of the running release (`specs/sccp.md` §4.13.2, §4.13.3).
//!
//! A profile holds everything about a source chain that is fixed by the chain itself rather than
//! by Taira governance: genesis identity, slot timing, the hard-fork schedule with its fork
//! versions, and `supported_until`, the last epoch this release's verifier supports. None of it
//! is stored in light-client `params`: a source-chain hard fork needs a Taira release that extends
//! the profile, and the same light client then continues with no Parliament action.
//!
//! [`policy_hash_contribution`] commits to every compiled profile and to the verifier's fixed
//! bounds, so peers running releases with different profiles cannot silently diverge once it is
//! bound into the consensus policy hash.

use crate::{
    ethereum_native::{
        EthereumLightClientError, FINALITY_PARTICIPANT_THRESHOLD, ForkActivation, ForkSchedule,
        SLOTS_PER_EPOCH, SLOTS_PER_SYNC_COMMITTEE_PERIOD,
    },
    v1::hashes::keccak256,
};

/// Ethereum mainnet beacon genesis time (seconds).
pub const ETHEREUM_MAINNET_GENESIS_TIME_S: u64 = 1_606_824_023;
/// Ethereum slot duration (seconds).
pub const ETHEREUM_SECONDS_PER_SLOT: u64 = 12;
/// Ethereum mainnet genesis validators root.
pub const ETHEREUM_MAINNET_GENESIS_VALIDATORS_ROOT: [u8; 32] = [
    0x4b, 0x36, 0x3d, 0xb9, 0x4e, 0x28, 0x61, 0x20, 0xd7, 0x6e, 0xb9, 0x05, 0x34, 0x0f, 0xdd, 0x4e,
    0x54, 0xbf, 0xe9, 0xf0, 0x6b, 0xf3, 0x3f, 0xf6, 0xcf, 0x5a, 0xd2, 0x7f, 0x51, 0x1b, 0xfe, 0x95,
];
/// Ethereum mainnet Altair-through-Fulu activation epochs and fork versions.
pub const ETHEREUM_MAINNET_FORKS: [ForkActivation; 6] = [
    ForkActivation::new(74_240, [0x01, 0, 0, 0]),
    ForkActivation::new(144_896, [0x02, 0, 0, 0]),
    ForkActivation::new(194_048, [0x03, 0, 0, 0]),
    ForkActivation::new(269_568, [0x04, 0, 0, 0]),
    ForkActivation::new(364_032, [0x05, 0, 0, 0]),
    ForkActivation::new(411_392, [0x06, 0, 0, 0]),
];
/// Last Ethereum epoch this release supports (2027-06-30T00:00:00Z).
///
/// No fork after Fulu is compiled. Each release moves this bound to the epoch before the next
/// scheduled fork, or to its own support horizon while none is scheduled; wallets stop burning
/// seven days before it (§7.2).
pub const ETHEREUM_MAINNET_SUPPORTED_UNTIL_EPOCH: u64 = 540_337;
/// EIP-2935 history storage contract.
pub const ETHEREUM_HISTORY_STORAGE_ADDRESS: [u8; 20] = [
    0x00, 0x00, 0xf9, 0x08, 0x27, 0xf1, 0xc5, 0x3a, 0x10, 0xcb, 0x7a, 0x02, 0x33, 0x5b, 0x17, 0x53,
    0x20, 0x00, 0x29, 0x35,
];
/// Keccak-256 of the EIP-2935 history storage contract code on mainnet.
pub const ETHEREUM_HISTORY_STORAGE_CODE_HASH: [u8; 32] = [
    0x6e, 0x49, 0xe6, 0x67, 0x82, 0x03, 0x7c, 0x05, 0x55, 0x89, 0x78, 0x70, 0xe2, 0x9f, 0xa5, 0xe5,
    0x52, 0xda, 0xf4, 0x71, 0x95, 0x52, 0x13, 0x1a, 0x0a, 0xbc, 0xe7, 0x79, 0xda, 0xec, 0x0a, 0x5d,
];
/// EIP-2935 `HISTORY_SERVE_WINDOW`: `1 <= E - B <= 8191` for a `HistoryContract` proof.
pub const ETHEREUM_HISTORY_SERVE_WINDOW: u64 = 8_191;
/// Hard bound on `LightClientUpdate`s in one advance (§4.13.3).
pub const ETHEREUM_MAX_UPDATES_PER_ADVANCE: usize = 16;
/// Hard bound on parent-linked headers in one `HeaderChain` ancestry.
pub const ETHEREUM_MAX_ANCESTRY_HEADERS: usize = 256;
/// Hard bound on headers in one `Backfill` segment.
pub const ETHEREUM_MAX_BACKFILL_HEADERS: usize = 256;
/// Largest amount by which a source slot may lead the Taira block time.
pub const MAX_SOURCE_FUTURE_MS: u64 = 60_000;

/// Compiled Ethereum chain profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EthereumChainProfileV1 {
    /// Beacon genesis time (seconds).
    pub genesis_time_s: u64,
    /// Slot duration (seconds).
    pub seconds_per_slot: u64,
    /// Genesis validators root bound into every signing domain.
    pub genesis_validators_root: [u8; 32],
    /// Altair-through-Fulu activations.
    pub forks: [ForkActivation; 6],
    /// Last supported epoch; anything signed or finalized later fails closed.
    pub supported_until_epoch: u64,
    /// EIP-2935 history storage contract.
    pub history_storage_address: [u8; 20],
    /// Code hash of the history storage contract.
    pub history_storage_code_hash: [u8; 32],
    /// EIP-2935 ring size.
    pub history_serve_window: u64,
}

/// Ethereum mainnet profile compiled into this release.
pub const ETHEREUM_MAINNET: EthereumChainProfileV1 = EthereumChainProfileV1 {
    genesis_time_s: ETHEREUM_MAINNET_GENESIS_TIME_S,
    seconds_per_slot: ETHEREUM_SECONDS_PER_SLOT,
    genesis_validators_root: ETHEREUM_MAINNET_GENESIS_VALIDATORS_ROOT,
    forks: ETHEREUM_MAINNET_FORKS,
    supported_until_epoch: ETHEREUM_MAINNET_SUPPORTED_UNTIL_EPOCH,
    history_storage_address: ETHEREUM_HISTORY_STORAGE_ADDRESS,
    history_storage_code_hash: ETHEREUM_HISTORY_STORAGE_CODE_HASH,
    history_serve_window: ETHEREUM_HISTORY_SERVE_WINDOW,
};

impl EthereumChainProfileV1 {
    /// The validated fork schedule.
    ///
    /// # Errors
    ///
    /// Returns the schedule error of a malformed profile (never for [`ETHEREUM_MAINNET`]).
    pub fn schedule(&self) -> Result<ForkSchedule, EthereumLightClientError> {
        ForkSchedule::new(self.genesis_validators_root, self.forks)
    }

    /// The same profile with another `supported_until` epoch (a release extending the profile).
    #[must_use]
    pub const fn with_supported_until_epoch(mut self, epoch: u64) -> Self {
        self.supported_until_epoch = epoch;
        self
    }

    /// Unix time of the start of `slot` in milliseconds, or `None` on overflow.
    #[must_use]
    pub const fn slot_start_ms(&self, slot: u64) -> Option<u64> {
        let Some(offset) = slot.checked_mul(self.seconds_per_slot) else {
            return None;
        };
        let Some(seconds) = self.genesis_time_s.checked_add(offset) else {
            return None;
        };
        seconds.checked_mul(1_000)
    }

    /// The slot in progress at unix time `unix_ms` (slot 0 before genesis).
    #[must_use]
    pub const fn slot_at_ms(&self, unix_ms: u64) -> u64 {
        let seconds = unix_ms / 1_000;
        if seconds < self.genesis_time_s || self.seconds_per_slot == 0 {
            return 0;
        }
        (seconds - self.genesis_time_s) / self.seconds_per_slot
    }

    /// First slot of a sync-committee period, or `None` on overflow.
    #[must_use]
    pub const fn period_start_slot(period: u64) -> Option<u64> {
        period.checked_mul(SLOTS_PER_SYNC_COMMITTEE_PERIOD)
    }

    /// Unix time at which `period` starts, in milliseconds.
    #[must_use]
    pub const fn period_start_ms(&self, period: u64) -> Option<u64> {
        match Self::period_start_slot(period) {
            Some(slot) => self.slot_start_ms(slot),
            None => None,
        }
    }

    /// Unix time at which the committee of `period` is superseded (the next period starts).
    #[must_use]
    pub const fn period_end_ms(&self, period: u64) -> Option<u64> {
        match period.checked_add(1) {
            Some(next) => self.period_start_ms(next),
            None => None,
        }
    }

    /// Whether `slot` lies at or before the supported epoch bound.
    #[must_use]
    pub const fn supports_slot(&self, slot: u64) -> bool {
        slot / SLOTS_PER_EPOCH <= self.supported_until_epoch
    }

    /// Unix time (ms) of the first slot beyond `supported_until`: evidence signed from then on
    /// fails closed until a release extends the profile. Wallets stop burning seven days before
    /// it (§7.2).
    #[must_use]
    pub const fn supported_until_ms(&self) -> Option<u64> {
        match self.supported_until_epoch.checked_add(1) {
            Some(epoch) => match epoch.checked_mul(SLOTS_PER_EPOCH) {
                Some(slot) => self.slot_start_ms(slot),
                None => None,
            },
            None => None,
        }
    }

    /// Unix time at which the EIP-2935 history contract became active (the Electra/Prague
    /// activation), in milliseconds.
    #[must_use]
    pub const fn history_contract_active_from_ms(&self) -> Option<u64> {
        match self.forks[4].epoch().checked_mul(SLOTS_PER_EPOCH) {
            Some(slot) => self.slot_start_ms(slot),
            None => None,
        }
    }

    /// Canonical fixed-layout bytes committed by the policy hash.
    #[must_use]
    pub fn policy_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        out.extend_from_slice(b"SCCP/LC/PROFILE/ETHEREUM/V1");
        out.extend_from_slice(&self.genesis_time_s.to_be_bytes());
        out.extend_from_slice(&self.seconds_per_slot.to_be_bytes());
        out.extend_from_slice(&self.genesis_validators_root);
        for activation in self.forks {
            out.extend_from_slice(&activation.epoch().to_be_bytes());
            out.extend_from_slice(&activation.version());
        }
        out.extend_from_slice(&self.supported_until_epoch.to_be_bytes());
        out.extend_from_slice(&self.history_storage_address);
        out.extend_from_slice(&self.history_storage_code_hash);
        out.extend_from_slice(&self.history_serve_window.to_be_bytes());
        for bound in [
            FINALITY_PARTICIPANT_THRESHOLD,
            ETHEREUM_MAX_UPDATES_PER_ADVANCE,
            ETHEREUM_MAX_ANCESTRY_HEADERS,
            ETHEREUM_MAX_BACKFILL_HEADERS,
        ] {
            out.extend_from_slice(&u64::try_from(bound).unwrap_or(u64::MAX).to_be_bytes());
        }
        out.extend_from_slice(&MAX_SOURCE_FUTURE_MS.to_be_bytes());
        out
    }
}

/// BNB Smart Chain mainnet EIP-155 chain id.
pub const BSC_MAINNET_CHAIN_ID: u64 = 56;
/// Parlia epoch length after Maxwell (blocks between validator-set checkpoints).
pub const BSC_EPOCH_LENGTH: u64 = 1_000;
/// Mainnet time (ms) at which Osaka and Mendel activate together: the first supported header
/// layout (21 fields, millisecond timestamps in the mix digest).
pub const BSC_MAINNET_SUPPORTED_FROM_MS: u64 = 1_777_343_400_000;
/// Last BSC mainnet time (ms) this release supports (2027-06-30T00:00:00Z).
///
/// No fork after Mendel is compiled. Each release moves this bound to the last block before the
/// next scheduled fork, or to its own support horizon while none is scheduled; wallets stop
/// burning seven days before it (§7.2).
pub const BSC_MAINNET_SUPPORTED_UNTIL_MS: u64 = 1_814_313_600_000;
/// Hard bound on steps in one BSC advance (§4.13.3).
pub const BSC_MAX_STEPS_PER_ADVANCE: usize = 16;
/// Hard bound on parent-linked headers in one BSC step, proof ancestry or backfill.
pub const BSC_MAX_SEGMENT_HEADERS: usize = 256;
/// Largest Parlia validator set (the vote bitmap is a `u64`).
pub const BSC_MAX_VALIDATORS: usize = 64;

/// Compiled BSC chain profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BscChainProfileV1 {
    /// EIP-155 chain id.
    pub chain_id: u64,
    /// Parlia epoch length.
    pub epoch_length: u64,
    /// First supported header time (ms); earlier headers fail closed.
    pub supported_from_ms: u64,
    /// Last supported header time (ms); later headers fail closed.
    pub supported_until_ms: u64,
}

/// BSC mainnet profile compiled into this release.
pub const BSC_MAINNET: BscChainProfileV1 = BscChainProfileV1 {
    chain_id: BSC_MAINNET_CHAIN_ID,
    epoch_length: BSC_EPOCH_LENGTH,
    supported_from_ms: BSC_MAINNET_SUPPORTED_FROM_MS,
    supported_until_ms: BSC_MAINNET_SUPPORTED_UNTIL_MS,
};

impl BscChainProfileV1 {
    /// The same profile with another `supported_until` time (a release extending the profile).
    #[must_use]
    pub const fn with_supported_until_ms(mut self, until_ms: u64) -> Self {
        self.supported_until_ms = until_ms;
        self
    }

    /// The same profile with another first supported time (synthetic test chains).
    #[must_use]
    pub const fn with_supported_from_ms(mut self, from_ms: u64) -> Self {
        self.supported_from_ms = from_ms;
        self
    }

    /// Whether a header timestamped `time_ms` lies in the supported fork window.
    #[must_use]
    pub const fn supports_time(&self, time_ms: u64) -> bool {
        self.supported_from_ms <= time_ms && time_ms <= self.supported_until_ms
    }

    /// Whether `height` is an epoch checkpoint.
    #[must_use]
    pub const fn is_epoch_checkpoint(&self, height: u64) -> bool {
        self.epoch_length != 0 && height.is_multiple_of(self.epoch_length)
    }

    /// Canonical fixed-layout bytes committed by the policy hash.
    #[must_use]
    pub fn policy_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(96);
        out.extend_from_slice(b"SCCP/LC/PROFILE/BSC/V1");
        for value in [
            self.chain_id,
            self.epoch_length,
            self.supported_from_ms,
            self.supported_until_ms,
        ] {
            out.extend_from_slice(&value.to_be_bytes());
        }
        for bound in [
            BSC_MAX_STEPS_PER_ADVANCE,
            BSC_MAX_SEGMENT_HEADERS,
            BSC_MAX_VALIDATORS,
        ] {
            out.extend_from_slice(&u64::try_from(bound).unwrap_or(u64::MAX).to_be_bytes());
        }
        out.extend_from_slice(&MAX_SOURCE_FUTURE_MS.to_be_bytes());
        out
    }
}

/// TRON maintenance interval (ms): the active witness set is re-elected every six hours.
pub const TRON_MAINTENANCE_INTERVAL_MS: u64 = 21_600_000;
/// Offset of the TRON maintenance grid from the Unix epoch (ms). java-tron advances
/// `nextMaintenanceTime` from zero in whole intervals, so maintenances fall at 00:00, 06:00,
/// 12:00 and 18:00 UTC and `T_p = p · 21 600 000`. The builders check it against
/// `/wallet/getnextmaintenancetime` and fail closed on a mismatch.
pub const TRON_MAINTENANCE_ORIGIN_MS: u64 = 0;
/// TRON block interval (ms).
pub const TRON_BLOCK_INTERVAL_MS: u64 = 3_000;
/// Slots skipped after a maintenance block.
pub const TRON_MAINTENANCE_SKIP_SLOTS: u64 = 2;
/// Active witnesses (super representatives) per maintenance period.
pub const TRON_ACTIVE_WITNESSES: usize = 27;
/// Distinct active witnesses that must build on a block for it to be solid (70 % of 27).
pub const TRON_SOLID_THRESHOLD: usize = 19;
/// Last TRON mainnet time (ms) this release supports (2027-06-30T00:00:00Z).
pub const TRON_MAINNET_SUPPORTED_UNTIL_MS: u64 = 1_814_313_600_000;
/// Hard bound on segments in one TRON advance.
pub const TRON_MAX_SEGMENTS_PER_ADVANCE: usize = 16;
/// Hard bound on signed headers in one TRON segment (§4.13.3).
pub const TRON_MAX_SEGMENT_HEADERS: usize = 128;
/// Hard bound on unsigned `raw_data` headers from an event block to a stored checkpoint.
pub const TRON_MAX_ANCESTRY_HEADERS: usize = 1_200;

/// Compiled TRON chain profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TronChainProfileV1 {
    /// Maintenance interval (ms).
    pub maintenance_interval_ms: u64,
    /// Maintenance grid origin (ms).
    pub maintenance_origin_ms: u64,
    /// Block interval (ms).
    pub block_interval_ms: u64,
    /// Slots skipped after a maintenance block.
    pub maintenance_skip_slots: u64,
    /// Last supported header time (ms); later headers fail closed.
    pub supported_until_ms: u64,
}

/// TRON mainnet profile compiled into this release.
pub const TRON_MAINNET: TronChainProfileV1 = TronChainProfileV1 {
    maintenance_interval_ms: TRON_MAINTENANCE_INTERVAL_MS,
    maintenance_origin_ms: TRON_MAINTENANCE_ORIGIN_MS,
    block_interval_ms: TRON_BLOCK_INTERVAL_MS,
    maintenance_skip_slots: TRON_MAINTENANCE_SKIP_SLOTS,
    supported_until_ms: TRON_MAINNET_SUPPORTED_UNTIL_MS,
};

impl TronChainProfileV1 {
    /// The same profile with another `supported_until` time.
    #[must_use]
    pub const fn with_supported_until_ms(mut self, until_ms: u64) -> Self {
        self.supported_until_ms = until_ms;
        self
    }

    /// The maintenance period a header timestamped `time_ms` belongs to (`0` before the origin).
    #[must_use]
    pub const fn period_at(&self, time_ms: u64) -> u64 {
        if time_ms < self.maintenance_origin_ms || self.maintenance_interval_ms == 0 {
            return 0;
        }
        (time_ms - self.maintenance_origin_ms) / self.maintenance_interval_ms
    }

    /// Start of maintenance period `period` (ms), or `None` on overflow.
    #[must_use]
    pub const fn period_start_ms(&self, period: u64) -> Option<u64> {
        match period.checked_mul(self.maintenance_interval_ms) {
            Some(offset) => self.maintenance_origin_ms.checked_add(offset),
            None => None,
        }
    }

    /// End of maintenance period `period` (the next period's start, ms).
    #[must_use]
    pub const fn period_end_ms(&self, period: u64) -> Option<u64> {
        match period.checked_add(1) {
            Some(next) => self.period_start_ms(next),
            None => None,
        }
    }

    /// Length of the witness-learning window after a maintenance block (ms): the first 27
    /// production slots plus the skipped slots.
    #[must_use]
    pub const fn learning_window_ms(&self) -> u64 {
        (TRON_ACTIVE_WITNESSES as u64 + self.maintenance_skip_slots) * self.block_interval_ms
    }

    /// Canonical fixed-layout bytes committed by the policy hash.
    #[must_use]
    pub fn policy_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(128);
        out.extend_from_slice(b"SCCP/LC/PROFILE/TRON/V1");
        for value in [
            self.maintenance_interval_ms,
            self.maintenance_origin_ms,
            self.block_interval_ms,
            self.maintenance_skip_slots,
            self.supported_until_ms,
        ] {
            out.extend_from_slice(&value.to_be_bytes());
        }
        for bound in [
            TRON_ACTIVE_WITNESSES,
            TRON_SOLID_THRESHOLD,
            TRON_MAX_SEGMENTS_PER_ADVANCE,
            TRON_MAX_SEGMENT_HEADERS,
            TRON_MAX_ANCESTRY_HEADERS,
        ] {
            out.extend_from_slice(&u64::try_from(bound).unwrap_or(u64::MAX).to_be_bytes());
        }
        out.extend_from_slice(&MAX_SOURCE_FUTURE_MS.to_be_bytes());
        out
    }
}

/// Margin subtracted from a TON epoch's `utime_until + stake_held_for` (ms): one hour.
pub const TON_FRESHNESS_MARGIN_MS: u64 = 3_600_000;
/// Last TON mainnet time (ms) this release supports (2027-06-30T00:00:00Z).
pub const TON_MAINNET_SUPPORTED_UNTIL_MS: u64 = 1_814_313_600_000;
/// Hard bound on key-block hops in one TON advance.
pub const TON_MAX_HOPS_PER_ADVANCE: usize = 16;
/// Hard bound on shard blocks walked in one TON proof.
pub const TON_MAX_SHARD_LINKS: usize = 32;

/// Compiled TON chain profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TonChainProfileV1 {
    /// Margin subtracted from an epoch's end of stake lock (ms).
    pub freshness_margin_ms: u64,
    /// Last supported block time (ms); later blocks fail closed.
    pub supported_until_ms: u64,
}

/// TON mainnet profile compiled into this release (global id −239 and the TL-B layouts are fixed
/// by `ton_native`).
pub const TON_MAINNET: TonChainProfileV1 = TonChainProfileV1 {
    freshness_margin_ms: TON_FRESHNESS_MARGIN_MS,
    supported_until_ms: TON_MAINNET_SUPPORTED_UNTIL_MS,
};

impl TonChainProfileV1 {
    /// The same profile with another `supported_until` time.
    #[must_use]
    pub const fn with_supported_until_ms(mut self, until_ms: u64) -> Self {
        self.supported_until_ms = until_ms;
        self
    }

    /// Canonical fixed-layout bytes committed by the policy hash.
    #[must_use]
    pub fn policy_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        out.extend_from_slice(b"SCCP/LC/PROFILE/TON/V1");
        for value in [self.freshness_margin_ms, self.supported_until_ms] {
            out.extend_from_slice(&value.to_be_bytes());
        }
        for bound in [TON_MAX_HOPS_PER_ADVANCE, TON_MAX_SHARD_LINKS] {
            out.extend_from_slice(&u64::try_from(bound).unwrap_or(u64::MAX).to_be_bytes());
        }
        out.extend_from_slice(&MAX_SOURCE_FUTURE_MS.to_be_bytes());
        out
    }
}

/// Every compiled source-chain profile of the running release.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SccpChainProfilesV1 {
    /// Ethereum mainnet.
    pub ethereum: EthereumChainProfileV1,
    /// BSC mainnet.
    pub bsc: BscChainProfileV1,
    /// TRON mainnet.
    pub tron: TronChainProfileV1,
    /// TON mainnet.
    pub ton: TonChainProfileV1,
}

/// The profiles compiled into this release.
pub const COMPILED_PROFILES: SccpChainProfilesV1 = SccpChainProfilesV1 {
    ethereum: ETHEREUM_MAINNET,
    bsc: BSC_MAINNET,
    tron: TRON_MAINNET,
    ton: TON_MAINNET,
};

impl SccpChainProfilesV1 {
    /// The profiles compiled into this release.
    #[must_use]
    pub const fn compiled() -> &'static Self {
        &COMPILED_PROFILES
    }

    /// The same profiles with another Ethereum profile.
    #[must_use]
    pub const fn with_ethereum(mut self, ethereum: EthereumChainProfileV1) -> Self {
        self.ethereum = ethereum;
        self
    }

    /// The same profiles with another BSC profile.
    #[must_use]
    pub const fn with_bsc(mut self, bsc: BscChainProfileV1) -> Self {
        self.bsc = bsc;
        self
    }

    /// The same profiles with another TRON profile.
    #[must_use]
    pub const fn with_tron(mut self, tron: TronChainProfileV1) -> Self {
        self.tron = tron;
        self
    }

    /// The same profiles with another TON profile.
    #[must_use]
    pub const fn with_ton(mut self, ton: TonChainProfileV1) -> Self {
        self.ton = ton;
        self
    }

    /// Keccak-256 commitment to every profile, in network order.
    #[must_use]
    pub fn policy_hash(&self) -> [u8; 32] {
        let profiles = [
            self.ethereum.policy_bytes(),
            self.bsc.policy_bytes(),
            self.tron.policy_bytes(),
            self.ton.policy_bytes(),
        ];
        let lengths: Vec<[u8; 4]> = profiles
            .iter()
            .map(|bytes| u32::try_from(bytes.len()).unwrap_or(u32::MAX).to_be_bytes())
            .collect();
        let mut parts: Vec<&[u8]> = vec![b"SCCP/LC/PROFILES/V1"];
        for (length, bytes) in lengths.iter().zip(&profiles) {
            parts.push(length);
            parts.push(bytes);
        }
        keccak256(&parts)
    }
}

/// Keccak-256 commitment to the compiled chain profiles and verifier bounds.
///
/// Core binds it into the consensus policy hash next to the committed `sccp` limits of the ZK validity policy.
#[must_use]
pub fn policy_hash_contribution() -> [u8; 32] {
    SccpChainProfilesV1::compiled().policy_hash()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ethereum_native::EthereumFork;

    #[test]
    fn mainnet_schedule_matches_the_consensus_config() {
        let schedule = ETHEREUM_MAINNET.schedule().expect("valid mainnet schedule");
        assert_eq!(
            schedule.genesis_validators_root(),
            ETHEREUM_MAINNET_GENESIS_VALIDATORS_ROOT
        );
        // Fulu activated at 2025-12-03T21:49:11Z.
        assert_eq!(
            ETHEREUM_MAINNET.slot_start_ms(411_392 * 32),
            Some(1_764_798_551_000)
        );
        assert_eq!(
            schedule.fork_at_slot(411_392 * 32).map(|(fork, _)| fork),
            Ok(EthereumFork::Fulu)
        );
        assert_eq!(
            schedule
                .fork_at_slot(411_392 * 32 - 1)
                .map(|(fork, _)| fork),
            Ok(EthereumFork::Electra)
        );
        assert_eq!(
            ETHEREUM_MAINNET.history_contract_active_from_ms(),
            Some(1_746_612_311_000)
        );
    }

    #[test]
    fn slot_and_period_timing_is_exact() {
        let profile = ETHEREUM_MAINNET;
        assert_eq!(profile.slot_start_ms(0), Some(1_606_824_023_000));
        assert_eq!(profile.slot_at_ms(1_606_824_023_000), 0);
        assert_eq!(profile.slot_at_ms(1_606_824_034_999), 0);
        assert_eq!(profile.slot_at_ms(1_606_824_035_000), 1);
        assert_eq!(profile.slot_at_ms(0), 0);
        assert_eq!(EthereumChainProfileV1::period_start_slot(2), Some(16_384));
        assert_eq!(
            profile.period_end_ms(0),
            profile.slot_start_ms(8_192),
            "period 0 ends when period 1 starts"
        );
        assert_eq!(profile.period_start_ms(1), profile.period_end_ms(0));
        assert_eq!(profile.slot_start_ms(u64::MAX), None);
        assert_eq!(profile.period_end_ms(u64::MAX), None);
    }

    #[test]
    fn supported_until_is_an_inclusive_epoch_bound() {
        let profile = ETHEREUM_MAINNET.with_supported_until_epoch(10);
        assert_eq!(profile.supported_until_ms(), profile.slot_start_ms(11 * 32));
        // 2027-06-30T00:00:00Z falls inside the last supported epoch.
        let until = ETHEREUM_MAINNET.supported_until_ms().expect("time");
        assert!(until > 1_814_313_600_000 && until <= 1_814_313_600_000 + 384_000);
        assert_eq!(
            ETHEREUM_MAINNET
                .with_supported_until_epoch(u64::MAX)
                .supported_until_ms(),
            None
        );
        assert!(profile.supports_slot(10 * 32 + 31));
        assert!(!profile.supports_slot(11 * 32));
        assert!(ETHEREUM_MAINNET.supports_slot(478_462 * 32));
        assert!(!ETHEREUM_MAINNET.supports_slot((ETHEREUM_MAINNET_SUPPORTED_UNTIL_EPOCH + 1) * 32));
    }

    #[test]
    fn bsc_window_and_epochs_are_inclusive() {
        let profile = BSC_MAINNET;
        assert!(profile.supports_time(BSC_MAINNET_SUPPORTED_FROM_MS));
        assert!(!profile.supports_time(BSC_MAINNET_SUPPORTED_FROM_MS - 1));
        assert!(profile.supports_time(BSC_MAINNET_SUPPORTED_UNTIL_MS));
        assert!(!profile.supports_time(BSC_MAINNET_SUPPORTED_UNTIL_MS + 1));
        assert!(profile.with_supported_from_ms(0).supports_time(0));
        assert!(profile.is_epoch_checkpoint(52_000_000));
        assert!(!profile.is_epoch_checkpoint(52_000_001));
        assert!(
            profile
                .policy_bytes()
                .starts_with(b"SCCP/LC/PROFILE/BSC/V1")
        );
    }

    #[test]
    fn tron_periods_follow_the_utc_maintenance_grid() {
        let profile = TRON_MAINNET;
        // Mainnet `getnextmaintenancetime` returned 2026-09-28T12:00:00Z.
        let maintenance = 1_790_596_800_000;
        let period = profile.period_at(maintenance);
        assert_eq!(profile.period_start_ms(period), Some(maintenance));
        assert_eq!(profile.period_at(maintenance - 1), period - 1);
        assert_eq!(
            profile.period_end_ms(period),
            Some(maintenance + TRON_MAINTENANCE_INTERVAL_MS)
        );
        assert_eq!(profile.period_at(0), 0);
        assert_eq!(profile.learning_window_ms(), 87_000);
        assert!(
            profile
                .policy_bytes()
                .starts_with(b"SCCP/LC/PROFILE/TRON/V1")
        );
    }

    #[test]
    fn policy_hash_binds_every_profile_field() {
        let compiled = *SccpChainProfilesV1::compiled();
        assert_eq!(policy_hash_contribution(), compiled.policy_hash());
        let extended = compiled.with_ethereum(ETHEREUM_MAINNET.with_supported_until_epoch(600_000));
        assert_ne!(extended.policy_hash(), compiled.policy_hash());
        let mut other_root = compiled;
        other_root.ethereum.genesis_validators_root[0] ^= 1;
        assert_ne!(other_root.policy_hash(), compiled.policy_hash());
        let later = compiled.with_bsc(BSC_MAINNET.with_supported_until_ms(1));
        assert_ne!(later.policy_hash(), compiled.policy_hash());
        let later = compiled.with_ton(TON_MAINNET.with_supported_until_ms(1));
        assert_ne!(later.policy_hash(), compiled.policy_hash());
        let later = compiled.with_tron(TRON_MAINNET.with_supported_until_ms(1));
        assert_ne!(later.policy_hash(), compiled.policy_hash());
    }
}
