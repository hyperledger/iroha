//! Compiled source-chain profiles of the running release (`specs/sccp.md` §4.13.2, §4.13.3).
//!
//! A profile holds everything about a source chain that is fixed by the chain itself rather than
//! by Taira governance: genesis identity, slot timing, the hard-fork schedule with its fork
//! versions, and `supported_until`, the last epoch or time the verifier supports. None of it is
//! stored in light-client `params`.
//!
//! **Versions.** Each network's profiles are append-only and numbered from 1: version `v` is
//! element `v − 1` of [`ETHEREUM_MAINNET_VERSIONS`], [`BSC_MAINNET_VERSIONS`] or
//! [`TON_MAINNET_VERSIONS`], and a release only ever appends a version, never edits one.
//! Version 1 ([`GENESIS_PROFILE_VERSION`]) is active from genesis. A later version (a
//! source-chain hard fork or a `supported_until` extension) becomes active only when the
//! Parliament enacts `ActivateLightClientProfile` with its
//! [`profile hash`](EthereumChainProfileV1::profile_hash); world state then records the version,
//! its hash and the Taira height it is active from.
//!
//! [`SccpLcActiveProfilesV1`] is the active version and hash of every network.
//! [`SccpLcActiveProfilesV1::policy_hash`] commits to it and is bound into every block's
//! confidential feature digest, so a release that only appends a version not yet activated keeps
//! the same digest. [`SccpLcProfileCatalogV1::resolve`] returns the compiled profiles of an
//! active selection, or [`SccpLcProfileUnavailableV1`] when the running release does not compile
//! an active version (or compiles other content under it); Taira then fails closed instead of
//! verifying under different rules.

use core::fmt;

use iroha_data_model::bridge::SccpNetworkV1;

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
/// Last Ethereum epoch profile version 1 supports (2027-06-30T00:00:00Z).
///
/// No fork after Fulu is compiled. A later release appends a profile version whose bound is the
/// epoch before the next scheduled fork (or its own support horizon while none is scheduled), and
/// the Parliament activates it; wallets stop burning seven days before the active bound (§7.2).
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

/// Ethereum mainnet profile version 1 (active from genesis).
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

/// Ethereum mainnet profile versions compiled into this release, append-only: version `v` is
/// element `v − 1`.
pub const ETHEREUM_MAINNET_VERSIONS: &[EthereumChainProfileV1] = &[ETHEREUM_MAINNET];

impl EthereumChainProfileV1 {
    /// The validated fork schedule.
    ///
    /// # Errors
    ///
    /// Returns the schedule error of a malformed profile (never for [`ETHEREUM_MAINNET`]).
    pub fn schedule(&self) -> Result<ForkSchedule, EthereumLightClientError> {
        ForkSchedule::new(self.genesis_validators_root, self.forks)
    }

    /// The same profile with another `supported_until` epoch (a later profile version).
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
    /// fails closed until the Parliament activates a profile version that extends the bound.
    /// Wallets stop burning seven days before it (§7.2).
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

    /// Keccak-256 of [`Self::policy_bytes`]: the hash an `ActivateLightClientProfile` names and
    /// world state records for this version (§4.13.2).
    #[must_use]
    pub fn profile_hash(&self) -> [u8; 32] {
        keccak256(&[&self.policy_bytes()])
    }
}

/// BNB Smart Chain mainnet EIP-155 chain id.
pub const BSC_MAINNET_CHAIN_ID: u64 = 56;
/// Parlia epoch length after Maxwell (blocks between validator-set checkpoints).
pub const BSC_EPOCH_LENGTH: u64 = 1_000;
/// Mainnet time (ms) at which Osaka and Mendel activate together: the first supported header
/// layout (21 fields, millisecond timestamps in the mix digest).
pub const BSC_MAINNET_SUPPORTED_FROM_MS: u64 = 1_777_343_400_000;
/// Last BSC mainnet time (ms) profile version 1 supports (2027-06-30T00:00:00Z).
///
/// No fork after Mendel is compiled. A later release appends a profile version whose bound is the
/// last block before the next scheduled fork (or its own support horizon while none is
/// scheduled), and the Parliament activates it; wallets stop burning seven days before the active
/// bound (§7.2).
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

/// BSC mainnet profile version 1 (active from genesis).
pub const BSC_MAINNET: BscChainProfileV1 = BscChainProfileV1 {
    chain_id: BSC_MAINNET_CHAIN_ID,
    epoch_length: BSC_EPOCH_LENGTH,
    supported_from_ms: BSC_MAINNET_SUPPORTED_FROM_MS,
    supported_until_ms: BSC_MAINNET_SUPPORTED_UNTIL_MS,
};

/// BSC mainnet profile versions compiled into this release, append-only: version `v` is element
/// `v − 1`.
pub const BSC_MAINNET_VERSIONS: &[BscChainProfileV1] = &[BSC_MAINNET];

impl BscChainProfileV1 {
    /// The same profile with another `supported_until` time (a later profile version).
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

    /// Keccak-256 of [`Self::policy_bytes`]: the hash an `ActivateLightClientProfile` names and
    /// world state records for this version (§4.13.2).
    #[must_use]
    pub fn profile_hash(&self) -> [u8; 32] {
        keccak256(&[&self.policy_bytes()])
    }
}

/// Margin subtracted from a TON epoch's `utime_until + stake_held_for` (ms): one hour.
pub const TON_FRESHNESS_MARGIN_MS: u64 = 3_600_000;
/// Last TON mainnet time (ms) profile version 1 supports (2027-06-30T00:00:00Z).
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

/// TON mainnet profile version 1, active from genesis (global id −239 and the TL-B layouts are
/// fixed by `ton_native`).
pub const TON_MAINNET: TonChainProfileV1 = TonChainProfileV1 {
    freshness_margin_ms: TON_FRESHNESS_MARGIN_MS,
    supported_until_ms: TON_MAINNET_SUPPORTED_UNTIL_MS,
};

/// TON mainnet profile versions compiled into this release, append-only: version `v` is element
/// `v − 1`.
pub const TON_MAINNET_VERSIONS: &[TonChainProfileV1] = &[TON_MAINNET];

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

    /// Keccak-256 of [`Self::policy_bytes`]: the hash an `ActivateLightClientProfile` names and
    /// world state records for this version (§4.13.2).
    #[must_use]
    pub fn profile_hash(&self) -> [u8; 32] {
        keccak256(&[&self.policy_bytes()])
    }
}

/// One profile per source chain: the profiles a verifier call runs under.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SccpChainProfilesV1 {
    /// Ethereum mainnet.
    pub ethereum: EthereumChainProfileV1,
    /// BSC mainnet.
    pub bsc: BscChainProfileV1,
    /// TON mainnet.
    pub ton: TonChainProfileV1,
}

/// Version 1 of every network: the profiles active from genesis.
pub const GENESIS_PROFILES: SccpChainProfilesV1 = SccpChainProfilesV1 {
    ethereum: ETHEREUM_MAINNET_VERSIONS[0],
    bsc: BSC_MAINNET_VERSIONS[0],
    ton: TON_MAINNET_VERSIONS[0],
};

/// The newest compiled version of every network.
pub const LATEST_PROFILES: SccpChainProfilesV1 = SccpChainProfilesV1 {
    ethereum: ETHEREUM_MAINNET_VERSIONS[ETHEREUM_MAINNET_VERSIONS.len() - 1],
    bsc: BSC_MAINNET_VERSIONS[BSC_MAINNET_VERSIONS.len() - 1],
    ton: TON_MAINNET_VERSIONS[TON_MAINNET_VERSIONS.len() - 1],
};

impl SccpChainProfilesV1 {
    /// Version 1 of every network ([`GENESIS_PROFILES`]).
    #[must_use]
    pub const fn genesis() -> &'static Self {
        &GENESIS_PROFILES
    }

    /// The newest compiled version of every network ([`LATEST_PROFILES`]). Off-chain tools
    /// (builders, wallets) use it; Taira execution resolves the versions active in world state
    /// instead ([`SccpLcProfileCatalogV1::resolve`]).
    #[must_use]
    pub const fn latest() -> &'static Self {
        &LATEST_PROFILES
    }

    /// Unix time (ms) from which source evidence of `network` lies beyond its profile's
    /// `supported_until` (`None` for Taira or on overflow).
    #[must_use]
    pub const fn supported_until_ms(&self, network: SccpNetworkV1) -> Option<u64> {
        match network {
            SccpNetworkV1::EthereumMainnet => self.ethereum.supported_until_ms(),
            SccpNetworkV1::BscMainnet => self.bsc.supported_until_ms.checked_add(1),
            SccpNetworkV1::TonMainnet => self.ton.supported_until_ms.checked_add(1),
            SccpNetworkV1::SoraTaira => None,
        }
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

    /// The same profiles with another TON profile.
    #[must_use]
    pub const fn with_ton(mut self, ton: TonChainProfileV1) -> Self {
        self.ton = ton;
        self
    }
}

/// Version of every network's profile before any activation.
pub const GENESIS_PROFILE_VERSION: u32 =
    iroha_data_model::sccp::light_client::SCCP_LC_GENESIS_PROFILE_VERSION_V1;

/// The compiled profile versions of every network, append-only: version `v` of a network is
/// element `v − 1` of its slice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SccpLcProfileCatalogV1<'a> {
    /// Ethereum mainnet versions.
    pub ethereum: &'a [EthereumChainProfileV1],
    /// BSC mainnet versions.
    pub bsc: &'a [BscChainProfileV1],
    /// TON mainnet versions.
    pub ton: &'a [TonChainProfileV1],
}

/// The profile versions compiled into this release.
pub const COMPILED_CATALOG: SccpLcProfileCatalogV1<'static> = SccpLcProfileCatalogV1 {
    ethereum: ETHEREUM_MAINNET_VERSIONS,
    bsc: BSC_MAINNET_VERSIONS,
    ton: TON_MAINNET_VERSIONS,
};

/// Element `version − 1` of `versions` (`None` for version 0 or an uncompiled version).
fn at_version<T: Copy>(versions: &[T], version: u32) -> Option<T> {
    let index = usize::try_from(version.checked_sub(1)?).ok()?;
    versions.get(index).copied()
}

/// Number of compiled versions as a version number (saturating; catalogs are tiny).
fn newest(len: usize) -> u32 {
    u32::try_from(len).unwrap_or(u32::MAX)
}

impl SccpLcProfileCatalogV1<'_> {
    /// The profile versions compiled into this release ([`COMPILED_CATALOG`]).
    #[must_use]
    pub const fn compiled() -> SccpLcProfileCatalogV1<'static> {
        COMPILED_CATALOG
    }

    /// The newest compiled version of `network`, or 0 for a network with no profile (Taira).
    #[must_use]
    pub fn latest_version(&self, network: SccpNetworkV1) -> u32 {
        match network {
            SccpNetworkV1::EthereumMainnet => newest(self.ethereum.len()),
            SccpNetworkV1::BscMainnet => newest(self.bsc.len()),
            SccpNetworkV1::TonMainnet => newest(self.ton.len()),
            SccpNetworkV1::SoraTaira => 0,
        }
    }

    /// Profile hash of compiled version `version` of `network`, or `None` when this catalog does
    /// not compile it.
    #[must_use]
    pub fn profile_hash(&self, network: SccpNetworkV1, version: u32) -> Option<[u8; 32]> {
        match network {
            SccpNetworkV1::EthereumMainnet => {
                at_version(self.ethereum, version).map(|profile| profile.profile_hash())
            }
            SccpNetworkV1::BscMainnet => {
                at_version(self.bsc, version).map(|profile| profile.profile_hash())
            }
            SccpNetworkV1::TonMainnet => {
                at_version(self.ton, version).map(|profile| profile.profile_hash())
            }
            SccpNetworkV1::SoraTaira => None,
        }
    }

    /// Version 1 of every network with its hash: the active selection of a state that records
    /// no activation. A catalog without version 1 of a network yields a zero hash, which
    /// [`Self::resolve`] refuses.
    #[must_use]
    pub fn genesis(&self) -> SccpLcActiveProfilesV1 {
        let genesis = |network| SccpLcProfileRefV1 {
            version: GENESIS_PROFILE_VERSION,
            profile_hash: self
                .profile_hash(network, GENESIS_PROFILE_VERSION)
                .unwrap_or([0; 32]),
        };
        SccpLcActiveProfilesV1 {
            ethereum: genesis(SccpNetworkV1::EthereumMainnet),
            bsc: genesis(SccpNetworkV1::BscMainnet),
            ton: genesis(SccpNetworkV1::TonMainnet),
        }
    }

    /// Check that this catalog compiles `profile` of `network` with exactly its hash.
    ///
    /// # Errors
    ///
    /// Returns [`SccpLcProfileUnavailableV1::NotCompiled`] or
    /// [`SccpLcProfileUnavailableV1::HashMismatch`].
    pub fn check(
        &self,
        network: SccpNetworkV1,
        profile: SccpLcProfileRefV1,
    ) -> Result<(), SccpLcProfileUnavailableV1> {
        let version = profile.version;
        match self.profile_hash(network, version) {
            None => Err(SccpLcProfileUnavailableV1::NotCompiled { network, version }),
            Some(hash) if hash != profile.profile_hash => {
                Err(SccpLcProfileUnavailableV1::HashMismatch { network, version })
            }
            Some(_) => Ok(()),
        }
    }

    /// The compiled profiles of an active selection.
    ///
    /// # Errors
    ///
    /// Returns the first network, in network order, whose active version this catalog does not
    /// compile or compiles with another hash. Taira fails closed on it (§4.13.2).
    pub fn resolve(
        &self,
        active: &SccpLcActiveProfilesV1,
    ) -> Result<SccpChainProfilesV1, SccpLcProfileUnavailableV1> {
        fn pick<T: Copy>(
            versions: &[T],
            network: SccpNetworkV1,
            profile: SccpLcProfileRefV1,
            hash: fn(&T) -> [u8; 32],
        ) -> Result<T, SccpLcProfileUnavailableV1> {
            let version = profile.version;
            let compiled = at_version(versions, version)
                .ok_or(SccpLcProfileUnavailableV1::NotCompiled { network, version })?;
            if hash(&compiled) == profile.profile_hash {
                Ok(compiled)
            } else {
                Err(SccpLcProfileUnavailableV1::HashMismatch { network, version })
            }
        }
        Ok(SccpChainProfilesV1 {
            ethereum: pick(
                self.ethereum,
                SccpNetworkV1::EthereumMainnet,
                active.ethereum,
                EthereumChainProfileV1::profile_hash,
            )?,
            bsc: pick(
                self.bsc,
                SccpNetworkV1::BscMainnet,
                active.bsc,
                BscChainProfileV1::profile_hash,
            )?,
            ton: pick(
                self.ton,
                SccpNetworkV1::TonMainnet,
                active.ton,
                TonChainProfileV1::profile_hash,
            )?,
        })
    }
}

/// The external networks that carry a light-client profile, in the order the active-profile
/// hash commits them.
pub const SCCP_LC_PROFILE_NETWORKS_V1: [SccpNetworkV1; 3] = [
    SccpNetworkV1::EthereumMainnet,
    SccpNetworkV1::BscMainnet,
    SccpNetworkV1::TonMainnet,
];

/// One network's active profile: its version and the hash world state recorded for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SccpLcProfileRefV1 {
    /// Profile version.
    pub version: u32,
    /// Keccak-256 of the version's policy bytes.
    pub profile_hash: [u8; 32],
}

/// The active profile of every network at one Taira height (§4.13.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SccpLcActiveProfilesV1 {
    /// Ethereum mainnet.
    pub ethereum: SccpLcProfileRefV1,
    /// BSC mainnet.
    pub bsc: SccpLcProfileRefV1,
    /// TON mainnet.
    pub ton: SccpLcProfileRefV1,
}

impl SccpLcActiveProfilesV1 {
    /// The active profile of `network` (`None` for Taira, which has none).
    #[must_use]
    pub const fn get(&self, network: SccpNetworkV1) -> Option<SccpLcProfileRefV1> {
        match network {
            SccpNetworkV1::EthereumMainnet => Some(self.ethereum),
            SccpNetworkV1::BscMainnet => Some(self.bsc),
            SccpNetworkV1::TonMainnet => Some(self.ton),
            SccpNetworkV1::SoraTaira => None,
        }
    }

    /// The same selection with `profile` active for `network` (Taira is left unchanged).
    #[must_use]
    pub const fn with(mut self, network: SccpNetworkV1, profile: SccpLcProfileRefV1) -> Self {
        match network {
            SccpNetworkV1::EthereumMainnet => self.ethereum = profile,
            SccpNetworkV1::BscMainnet => self.bsc = profile,
            SccpNetworkV1::TonMainnet => self.ton = profile,
            SccpNetworkV1::SoraTaira => {}
        }
        self
    }

    /// Keccak-256 commitment to the active version and profile hash of every network, in
    /// network order: the SCCP light-client input of the confidential feature digest.
    ///
    /// It depends only on the selection, so compiling a version that is not active leaves it
    /// unchanged.
    #[must_use]
    pub fn policy_hash(&self) -> [u8; 32] {
        let mut bytes = Vec::with_capacity(SCCP_LC_PROFILE_NETWORKS_V1.len() * 36);
        for network in SCCP_LC_PROFILE_NETWORKS_V1 {
            if let Some(profile) = self.get(network) {
                bytes.extend_from_slice(&profile.version.to_be_bytes());
                bytes.extend_from_slice(&profile.profile_hash);
            }
        }
        keccak256(&[b"SCCP/LC/ACTIVE_PROFILES/V1", &bytes])
    }
}

/// The running release cannot verify under an active profile version (§4.13.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SccpLcProfileUnavailableV1 {
    /// The release does not compile this version.
    NotCompiled {
        /// Network of the version.
        network: SccpNetworkV1,
        /// Active version.
        version: u32,
    },
    /// The release compiles this version with other content than world state recorded.
    HashMismatch {
        /// Network of the version.
        network: SccpNetworkV1,
        /// Active version.
        version: u32,
    },
}

impl fmt::Display for SccpLcProfileUnavailableV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotCompiled { network, version } => write!(
                formatter,
                "this release does not compile {} light-client profile version {version}",
                network.profile_key()
            ),
            Self::HashMismatch { network, version } => write!(
                formatter,
                "this release compiles {} light-client profile version {version} with another \
                 profile hash",
                network.profile_key()
            ),
        }
    }
}

impl std::error::Error for SccpLcProfileUnavailableV1 {}

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
    fn profile_hash_binds_every_profile_field() {
        let genesis = *SccpChainProfilesV1::genesis();
        assert_eq!(
            genesis.ethereum.profile_hash(),
            keccak256(&[&genesis.ethereum.policy_bytes()])
        );
        let extended = ETHEREUM_MAINNET.with_supported_until_epoch(600_000);
        assert_ne!(extended.profile_hash(), ETHEREUM_MAINNET.profile_hash());
        let mut other_root = ETHEREUM_MAINNET;
        other_root.genesis_validators_root[0] ^= 1;
        assert_ne!(other_root.profile_hash(), ETHEREUM_MAINNET.profile_hash());
        assert_ne!(
            BSC_MAINNET.with_supported_until_ms(1).profile_hash(),
            BSC_MAINNET.profile_hash()
        );
        assert_ne!(
            TON_MAINNET.with_supported_until_ms(1).profile_hash(),
            TON_MAINNET.profile_hash()
        );
    }

    /// Ethereum versions of a later release that appends version 2.
    const EXTENDED_ETHEREUM: [EthereumChainProfileV1; 2] = [
        ETHEREUM_MAINNET,
        ETHEREUM_MAINNET.with_supported_until_epoch(ETHEREUM_MAINNET_SUPPORTED_UNTIL_EPOCH + 1),
    ];
    /// BSC versions of a later release that appends version 2.
    const EXTENDED_BSC: [BscChainProfileV1; 2] = [
        BSC_MAINNET,
        BSC_MAINNET.with_supported_until_ms(BSC_MAINNET_SUPPORTED_UNTIL_MS + 1),
    ];
    /// TON versions of a later release that appends version 2.
    const EXTENDED_TON: [TonChainProfileV1; 2] = [
        TON_MAINNET,
        TON_MAINNET.with_supported_until_ms(TON_MAINNET_SUPPORTED_UNTIL_MS + 1),
    ];
    /// A later release: version 2 of every network appended to the compiled versions.
    const EXTENDED: SccpLcProfileCatalogV1<'static> = SccpLcProfileCatalogV1 {
        ethereum: &EXTENDED_ETHEREUM,
        bsc: &EXTENDED_BSC,
        ton: &EXTENDED_TON,
    };

    #[test]
    fn supported_until_is_the_first_unsupported_instant_per_network() {
        let genesis = *SccpChainProfilesV1::genesis();
        assert_eq!(
            genesis.supported_until_ms(SccpNetworkV1::EthereumMainnet),
            ETHEREUM_MAINNET.supported_until_ms()
        );
        for (network, inclusive) in [
            (SccpNetworkV1::BscMainnet, BSC_MAINNET_SUPPORTED_UNTIL_MS),
            (SccpNetworkV1::TonMainnet, TON_MAINNET_SUPPORTED_UNTIL_MS),
        ] {
            assert_eq!(genesis.supported_until_ms(network), Some(inclusive + 1));
        }
        assert_eq!(genesis.supported_until_ms(SccpNetworkV1::SoraTaira), None);
        assert_eq!(
            genesis
                .with_ton(TON_MAINNET.with_supported_until_ms(u64::MAX))
                .supported_until_ms(SccpNetworkV1::TonMainnet),
            None
        );
    }

    #[test]
    fn versions_are_append_only_and_numbered_from_one() {
        let compiled = SccpLcProfileCatalogV1::compiled();
        assert_eq!(compiled, COMPILED_CATALOG);
        for network in SCCP_LC_PROFILE_NETWORKS_V1 {
            assert!(compiled.latest_version(network) >= GENESIS_PROFILE_VERSION);
            assert_eq!(compiled.profile_hash(network, 0), None);
            let beyond = compiled.latest_version(network) + 1;
            assert_eq!(compiled.profile_hash(network, beyond), None);
        }
        assert_eq!(compiled.latest_version(SccpNetworkV1::SoraTaira), 0);
        assert_eq!(compiled.profile_hash(SccpNetworkV1::SoraTaira, 1), None);
        assert_eq!(
            compiled.profile_hash(SccpNetworkV1::EthereumMainnet, 1),
            Some(ETHEREUM_MAINNET.profile_hash())
        );
        assert_eq!(
            GENESIS_PROFILES, LATEST_PROFILES,
            "one version per network today"
        );
        assert_eq!(*SccpChainProfilesV1::latest(), LATEST_PROFILES);
        assert_eq!(compiled.resolve(&compiled.genesis()), Ok(GENESIS_PROFILES));

        let extended = EXTENDED;
        for network in SCCP_LC_PROFILE_NETWORKS_V1 {
            assert_eq!(extended.latest_version(network), 2);
            assert_eq!(
                extended.profile_hash(network, 1),
                compiled.profile_hash(network, 1),
                "appending a version never changes an earlier one"
            );
        }
    }

    #[test]
    fn an_appended_version_leaves_the_active_hash_unchanged_until_activated() {
        let compiled = SccpLcProfileCatalogV1::compiled();
        let extended = EXTENDED;
        assert_eq!(extended.genesis(), compiled.genesis());
        assert_eq!(
            extended.genesis().policy_hash(),
            compiled.genesis().policy_hash()
        );
        let v2 = SccpLcProfileRefV1 {
            version: 2,
            profile_hash: EXTENDED_ETHEREUM[1].profile_hash(),
        };
        let activated = extended.genesis().with(SccpNetworkV1::EthereumMainnet, v2);
        assert_ne!(activated.policy_hash(), extended.genesis().policy_hash());
        assert_eq!(activated.get(SccpNetworkV1::EthereumMainnet), Some(v2));
        assert_eq!(activated.get(SccpNetworkV1::SoraTaira), None);
        assert_eq!(
            activated.with(SccpNetworkV1::SoraTaira, v2),
            activated,
            "Taira has no profile"
        );
        let resolved = extended.resolve(&activated).expect("version 2 is compiled");
        assert_eq!(resolved.ethereum, EXTENDED_ETHEREUM[1]);
        assert_eq!(resolved.bsc, BSC_MAINNET);
        // The hash binds the version number as well as the content.
        let renumbered = activated.with(
            SccpNetworkV1::EthereumMainnet,
            SccpLcProfileRefV1 { version: 3, ..v2 },
        );
        assert_ne!(renumbered.policy_hash(), activated.policy_hash());
    }

    #[test]
    fn resolution_fails_closed_on_an_uncompiled_or_different_version() {
        let compiled = SccpLcProfileCatalogV1::compiled();
        let v2 = SccpLcProfileRefV1 {
            version: 2,
            profile_hash: EXTENDED_ETHEREUM[1].profile_hash(),
        };
        let activated = compiled.genesis().with(SccpNetworkV1::EthereumMainnet, v2);
        let missing = SccpLcProfileUnavailableV1::NotCompiled {
            network: SccpNetworkV1::EthereumMainnet,
            version: 2,
        };
        assert_eq!(compiled.resolve(&activated), Err(missing));
        assert_eq!(
            compiled.check(SccpNetworkV1::EthereumMainnet, v2),
            Err(missing)
        );
        assert!(missing.to_string().contains("ethereum-mainnet"));
        let forged = SccpLcProfileRefV1 {
            version: 1,
            profile_hash: [7; 32],
        };
        let mismatch = SccpLcProfileUnavailableV1::HashMismatch {
            network: SccpNetworkV1::TonMainnet,
            version: 1,
        };
        assert_eq!(
            compiled.resolve(&compiled.genesis().with(SccpNetworkV1::TonMainnet, forged)),
            Err(mismatch)
        );
        assert_eq!(
            compiled.check(SccpNetworkV1::TonMainnet, forged),
            Err(mismatch)
        );
        assert!(mismatch.to_string().contains("another profile hash"));
        assert_eq!(
            compiled.check(SccpNetworkV1::SoraTaira, compiled.genesis().ton),
            Err(SccpLcProfileUnavailableV1::NotCompiled {
                network: SccpNetworkV1::SoraTaira,
                version: 1,
            })
        );
        let empty = SccpLcProfileCatalogV1 {
            ethereum: &[],
            ..compiled
        };
        assert_eq!(empty.genesis().ethereum.profile_hash, [0; 32]);
        assert!(empty.resolve(&empty.genesis()).is_err());
    }
}
