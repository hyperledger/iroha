//! Canonical epoch-bearing height slots and atomic boundary schedule results.

use super::{ChainParamsRecord, ScheduleError, consensus_key, global_committee};
use crate::{
    parameter::system::ConsensusMode,
    sumeragi::epoch::{ValidatorEpochBoundaryV1, ValidatorEpochContextV1},
};
use iroha_sumeragi::types::{
    AppliedConfig, ConfigSlot, EpochConfig, EpochId, Hash32, HeightConfig,
};
use norito::{
    NoritoDeserialize, NoritoSerialize,
    derive::{JsonDeserialize, JsonSerialize},
};

/// Complete authorized configuration of one height.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    NoritoSerialize,
    NoritoDeserialize,
    JsonSerialize,
    JsonDeserialize,
    norito::NoritoSchema,
    iroha_schema::IntoSchema,
)]
#[norito_schema(name = "iroha_data_model::sumeragi_finality::ScheduledConfig")]
pub struct ScheduledConfig {
    /// Exact height this configuration governs.
    pub height: u64,
    /// Full authenticated scheduling epoch and original generation credentials.
    pub epoch: ValidatorEpochContextV1,
    /// Ordinary lag-two chain parameters, independent of authority-generation lifetime.
    pub params: ChainParamsRecord,
}
impl ScheduledConfig {
    /// Check complete context and exact containment before building a generic core config.
    ///
    /// # Errors
    /// Rejects malformed epoch authority, a height outside that epoch, invalid parameters
    /// or committee keys, or a configuration exceeding the transport bounds.
    pub fn height_config(&self) -> Result<HeightConfig, ScheduleError> {
        self.height_config_with_validation(&mut EpochValidationScope::new())
    }
    /// Validate this exact height with pure epoch work retained by one enclosing operation.
    ///
    /// # Errors
    /// Rejects the same malformed epochs, containment, parameters and transport bounds as
    /// [`Self::height_config`]. Reuse never authenticates an authority or a certificate.
    pub fn height_config_with_validation(
        &self,
        validation: &mut EpochValidationScope,
    ) -> Result<HeightConfig, ScheduleError> {
        let epoch = validation.core_epoch(&self.epoch)?;
        if self.height < self.epoch.authorization.first_height
            || self.height > self.epoch.authorization.last_height
        {
            return Err(ScheduleError::Epoch(
                "scheduled height is outside its authenticated epoch".into(),
            ));
        }
        self.params.validate().map_err(ScheduleError::Params)?;
        let committee = global_committee(
            self.epoch
                .committee
                .iter()
                .map(|member| consensus_key(&member.validator))
                .collect::<Result<Vec<_>, _>>()?,
        )?;
        let config = HeightConfig {
            epoch: Box::new(epoch),
            committee,
            params: self.params.to_core(),
        };
        iroha_sumeragi::pacemaker::validate_height(&config, super::CHAIN_TRANSPORT_FRAME_LIMIT)
            .map_err(ScheduleError::Params)?;
        Ok(config)
    }
}

/// Exact signed epoch identity passed to generic core signatures and safety records.
///
/// # Errors
/// Rejects invalid epoch authority or failure to derive its canonical context or authority identity.
pub fn core_epoch(context: &ValidatorEpochContextV1) -> Result<EpochConfig, ScheduleError> {
    EpochValidationScope::new().core_epoch(context)
}

/// Bounded pure epoch validation work for one operation or source-bound proof walk.
///
/// At most two complete, immutable, fully validated contexts are retained. A hit requires
/// exact value equality, never a caller-provided hash or epoch number. This has no certificate,
/// source, freshness or authority verdict; consumers must still authenticate each current
/// source and its signatures. One operation may borrow it for independently selected checkpoint
/// imports; it must be dropped when that operation returns. Do not retain it in State views.
/// It cannot be serialized, cloned or populated with an unchecked decoded context.
pub struct EpochValidationScope {
    entries: [Option<ValidatedEpoch>; 2],
    #[cfg(test)]
    validations: usize,
}
struct ValidatedEpoch {
    context: ValidatorEpochContextV1,
    core: EpochConfig,
}
impl Default for EpochValidationScope {
    fn default() -> Self {
        Self::new()
    }
}
impl EpochValidationScope {
    /// Start an empty workspace; it contains no trusted authority or proof evidence.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: [None, None],
            #[cfg(test)]
            validations: 0,
        }
    }
    /// Validate the full exact context once and derive its canonical core projection.
    ///
    /// # Errors
    /// Rejects malformed committee credentials, authority/authorization bindings, geometry,
    /// network, availability layout or encoding, just as the unscoped epoch entrypoint does.
    pub fn core_epoch(
        &mut self,
        context: &ValidatorEpochContextV1,
    ) -> Result<EpochConfig, ScheduleError> {
        self.validated_epoch(context).map_err(ScheduleError::Epoch)
    }
    // The signed-genesis producer already authenticated and reconstructed this value.
    // Reuse only an exact previously validated context. A miss performs its original
    // validation-only work: no context hash, canonical admission or optional insertion.
    pub(super) fn validate_known_or_fresh(
        &self,
        context: &ValidatorEpochContextV1,
    ) -> Result<(), String> {
        if self
            .entries
            .iter()
            .flatten()
            .any(|entry| entry.context == *context)
        {
            Ok(())
        } else {
            context.validate()
        }
    }
    fn validated_epoch(
        &mut self,
        context: &ValidatorEpochContextV1,
    ) -> Result<EpochConfig, String> {
        if let Some(entry) = self
            .entries
            .iter()
            .flatten()
            .find(|entry| entry.context == *context)
        {
            return Ok(entry.core);
        }
        // context_id validates every original BLS proof and the authorized generation first.
        // Invalid inputs never enter retained ownership. A native roundtrip admits the exact
        // frame and every decoded allocation under the caller's original cumulative context;
        // an ordinary graph clone would allocate outside that owner.
        let context_id = context.context_id()?;
        let core = EpochConfig {
            da_layout: context.da_layout,
            id: EpochId {
                epoch: context.authorization.epoch,
                context: Hash32(context_id),
            },
            // Full context validation already proved this exact validator generation identity.
            authority_generation: Hash32(context.authorization.authority_id),
            first_height: context.authorization.first_height,
            last_height: context.authorization.last_height,
            leader_seed: Hash32(context.leader_seed),
        };
        // This cache is optional pure validation reuse. Capacity refusal declines insertion;
        // it never changes the validated epoch, tip, signatures or consensus identity.
        let encoded = norito::core::to_bytes_bounded(context, usize::MAX);
        if let Ok(encoded) = encoded
            && let Ok(context) = norito::decode_canonical::<ValidatorEpochContextV1>(&encoded)
        {
            self.entries[0] = self.entries[1].take();
            self.entries[1] = Some(ValidatedEpoch { context, core });
        }
        #[cfg(test)]
        {
            self.validations += 1;
        }
        Ok(core)
    }
}

/// One scheduled height; a pending boundary has parameters but grants no signing authority.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    NoritoSerialize,
    NoritoDeserialize,
    JsonSerialize,
    JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::sumeragi_finality::ScheduledSlot")]
#[norito(tag = "kind", content = "value", rename_all = "snake_case")]
#[expect(
    clippy::large_enum_variant,
    reason = "canonical slots retain inline geometry in prepaid flat storage"
)]
pub enum ScheduledSlot {
    /// Configuration authorized by signed genesis or the incumbent-certified boundary.
    Ready(ScheduledConfig),
    /// Await publication of the exact predecessor boundary before signing this height.
    PendingBoundary {
        /// Height whose authority remains unavailable.
        height: u64,
        /// Incumbent boundary that must certify the successor.
        boundary_height: u64,
        /// Complete predecessor epoch identity, never a local QC signer subset.
        predecessor_context_id: [u8; 32],
        /// Lag-two parameters already fixed for this height.
        params: ChainParamsRecord,
    },
}
// Schema-only projection of the named variant; the canonical codec remains ScheduledSlot.
struct PendingBoundarySchema;
impl iroha_schema::TypeId for PendingBoundarySchema {
    fn id() -> iroha_schema::Ident {
        "SumeragiPendingBoundary".into()
    }
}
impl iroha_schema::IntoSchema for PendingBoundarySchema {
    fn type_name() -> iroha_schema::Ident {
        "SumeragiPendingBoundary".into()
    }
    fn update_schema_map(map: &mut iroha_schema::MetaMap) {
        use iroha_schema::{Declaration, Metadata, NamedFieldsMeta};
        if map.contains_key::<Self>() {
            return;
        }
        u64::update_schema_map(map);
        <[u8; 32]>::update_schema_map(map);
        ChainParamsRecord::update_schema_map(map);
        map.insert::<Self>(Metadata::Struct(NamedFieldsMeta {
            declarations: vec![
                Declaration {
                    name: "height".into(),
                    ty: core::any::TypeId::of::<u64>(),
                },
                Declaration {
                    name: "boundary_height".into(),
                    ty: core::any::TypeId::of::<u64>(),
                },
                Declaration {
                    name: "predecessor_context_id".into(),
                    ty: core::any::TypeId::of::<[u8; 32]>(),
                },
                Declaration {
                    name: "params".into(),
                    ty: core::any::TypeId::of::<ChainParamsRecord>(),
                },
            ],
        }));
    }
}
impl iroha_schema::TypeId for ScheduledSlot {
    fn id() -> iroha_schema::Ident {
        "ScheduledSlot".into()
    }
}
impl iroha_schema::IntoSchema for ScheduledSlot {
    fn type_name() -> iroha_schema::Ident {
        "ScheduledSlot".into()
    }
    fn update_schema_map(map: &mut iroha_schema::MetaMap) {
        use iroha_schema::{EnumMeta, EnumVariant, Metadata};
        if map.contains_key::<Self>() {
            return;
        }
        ScheduledConfig::update_schema_map(map);
        PendingBoundarySchema::update_schema_map(map);
        map.insert::<Self>(Metadata::Enum(EnumMeta {
            variants: vec![
                EnumVariant {
                    tag: "ready".into(),
                    discriminant: 0,
                    ty: Some(core::any::TypeId::of::<ScheduledConfig>()),
                },
                EnumVariant {
                    tag: "pending_boundary".into(),
                    discriminant: 1,
                    ty: Some(core::any::TypeId::of::<PendingBoundarySchema>()),
                },
            ],
        }));
    }
}
impl ScheduledSlot {
    /// Exact slot height.
    pub const fn height(&self) -> u64 {
        match self {
            Self::Ready(config) => config.height,
            Self::PendingBoundary { height, .. } => *height,
        }
    }
    /// Exact parameter projection, including an unauthenticated authority slot.
    pub const fn params(&self) -> &ChainParamsRecord {
        match self {
            Self::Ready(config) => &config.params,
            Self::PendingBoundary { params, .. } => params,
        }
    }
    /// Map only an authorized slot to signing authority; a pending slot remains explicit.
    ///
    /// # Errors
    /// Rejects a slot inconsistent with the current epoch, or invalid ready-slot configuration.
    pub fn to_core(&self, current: &ValidatorEpochContextV1) -> Result<ConfigSlot, ScheduleError> {
        self.to_core_with_validation(current, &mut EpochValidationScope::new())
    }
    fn to_core_with_validation(
        &self,
        current: &ValidatorEpochContextV1,
        validation: &mut EpochValidationScope,
    ) -> Result<ConfigSlot, ScheduleError> {
        self.validate_against(current, validation)?;
        match self {
            Self::Ready(config) => Ok(ConfigSlot::Ready(
                config.height_config_with_validation(validation)?,
            )),
            Self::PendingBoundary {
                boundary_height,
                predecessor_context_id,
                ..
            } => Ok(ConfigSlot::PendingBoundary {
                boundary_height: *boundary_height,
                predecessor: EpochId {
                    epoch: current.authorization.epoch,
                    context: Hash32(*predecessor_context_id),
                },
            }),
        }
    }
    fn validate_against(
        &self,
        current: &ValidatorEpochContextV1,
        validation: &mut EpochValidationScope,
    ) -> Result<(), ScheduleError> {
        self.params().validate().map_err(ScheduleError::Params)?;
        match self {
            Self::Ready(config) => {
                validation.core_epoch(&config.epoch)?;
                if config.epoch != *current
                    || config.height < current.authorization.first_height
                    || config.height > current.authorization.last_height
                {
                    return Err(ScheduleError::Epoch(
                        "ready slot changes its authorized epoch".into(),
                    ));
                }
            }
            Self::PendingBoundary {
                height,
                boundary_height,
                predecessor_context_id,
                ..
            } => {
                if current.mode != ConsensusMode::Npos
                    || *boundary_height != current.authorization.last_height
                    || *height <= *boundary_height
                    || *predecessor_context_id != validation.core_epoch(current)?.id.context.0
                {
                    return Err(ScheduleError::Epoch(
                        "pending slot differs from its exact incumbent boundary".into(),
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Complete authority/scheduling effect committed in the incumbent's exact execution result.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    NoritoSerialize,
    NoritoDeserialize,
    JsonSerialize,
    JsonDeserialize,
    norito::NoritoSchema,
    iroha_schema::IntoSchema,
)]
#[norito_schema(name = "iroha_data_model::sumeragi_finality::ScheduleOutcome")]
pub struct ScheduleOutcome {
    /// Original execution height.
    pub height: u64,
    /// Exact incumbent context governing the block, including its complete signing generation.
    pub current: ValidatorEpochContextV1,
    /// Mandatory exactly at an `NPoS` boundary; carries next authorization and E+2 preparation.
    pub boundary: Option<ValidatorEpochBoundaryV1>,
    /// Height h+1, ready only when already authorized or installed by this exact boundary.
    pub next: ScheduledSlot,
    /// Height h+2, with original lag-two parameters and an explicit boundary barrier if needed.
    pub after_next: ScheduledSlot,
}
impl ScheduleOutcome {
    /// Validate the next certified result against this result's original successor slots.
    ///
    /// # Errors
    /// A height gap, changed incumbent, changed lag-two parameters or misplaced boundary.
    pub fn validate_successor(&self, next: &Self) -> Result<(), ScheduleError> {
        self.validate_successor_with_validation(next, &mut EpochValidationScope::new())
    }

    pub(super) fn validate_successor_with_validation(
        &self,
        next: &Self,
        validation: &mut EpochValidationScope,
    ) -> Result<(), ScheduleError> {
        self.validate_with_validation(validation)?;
        next.validate_with_validation(validation)?;
        self.validate_successor_relation(next)
    }

    // The sole cross-result relationship rule. Ordinary verification validates both complete
    // endpoints before this pure comparison; the opaque receipt join already owns those
    // original validations and additionally binds each height to its authenticated block.
    pub(super) fn validate_successor_relation(&self, next: &Self) -> Result<(), ScheduleError> {
        let ScheduledSlot::Ready(incumbent) = &self.next else {
            return Err(ScheduleError::Epoch(
                "next height lacks certified authority".into(),
            ));
        };
        if self.height.checked_add(1) != Some(next.height)
            || incumbent.epoch != next.current
            || self.after_next.params() != next.next.params()
            || (next.boundary.is_none() && self.after_next != next.next)
            || (next.boundary.is_some()
                && !matches!(self.after_next, ScheduledSlot::PendingBoundary { .. }))
        {
            return Err(ScheduleError::Epoch(
                "successor changes its authenticated epoch or parameter slots".into(),
            ));
        }
        Ok(())
    }
    /// Validate all canonical context, slot, boundary-presence and height relationships.
    ///
    /// # Errors
    /// Rejects invalid epoch context, nonconsecutive heights, absent or invented boundaries,
    /// or successor slots inconsistent with the authenticated current or successor epoch.
    pub fn validate(&self) -> Result<(), ScheduleError> {
        self.validate_with_validation(&mut EpochValidationScope::new())
    }
    /// Validate all graph relationships while reusing only exact epoch shape work.
    ///
    /// # Errors
    /// Rejects the same malformed contexts, boundaries and successor relationships as
    /// [`Self::validate`]; a hit is not a finality or authority verdict.
    pub fn validate_with_validation(
        &self,
        validation: &mut EpochValidationScope,
    ) -> Result<(), ScheduleError> {
        validation.core_epoch(&self.current)?;
        let current = &self.current.authorization;
        if self.height < current.first_height
            || self.height > current.last_height
            || self.height.checked_add(1) != Some(self.next.height())
            || self.height.checked_add(2) != Some(self.after_next.height())
        {
            return Err(ScheduleError::Epoch(
                "schedule result has nonconsecutive or foreign heights".into(),
            ));
        }
        let is_boundary =
            self.current.mode == ConsensusMode::Npos && self.height == current.last_height;
        if is_boundary != self.boundary.is_some() {
            return Err(ScheduleError::Epoch(
                "schedule result omits or invents an epoch boundary".into(),
            ));
        }
        let authorized = if let Some(boundary) = &self.boundary {
            boundary
                .validate_against_with_context_validation(&self.current, &mut |context| {
                    validation
                        .validated_epoch(context)
                        .map(|epoch| epoch.id.context.0)
                })
                .map_err(ScheduleError::Epoch)?;
            if boundary.height != self.height {
                return Err(ScheduleError::Epoch(
                    "schedule result carries a future boundary".into(),
                ));
            }
            &boundary.next
        } else {
            &self.current
        };
        self.next.validate_against(authorized, validation)?;
        self.after_next.validate_against(authorized, validation)?;
        if is_boundary
            && (!matches!(&self.next, ScheduledSlot::Ready(_))
                || !matches!(&self.after_next, ScheduledSlot::Ready(_)))
        {
            return Err(ScheduleError::Epoch(
                "boundary must atomically authorize both successor slots".into(),
            ));
        }
        Ok(())
    }
    /// Generic core event released only after this original boundary's successful publication.
    ///
    /// # Errors
    /// Rejects an invalid schedule result or unavailable or malformed successor configuration.
    pub fn applied_config(&self) -> Result<AppliedConfig, ScheduleError> {
        let validation = &mut EpochValidationScope::new();
        self.validate_with_validation(validation)?;
        if self.boundary.is_some() {
            let (ScheduledSlot::Ready(next), ScheduledSlot::Ready(after_next)) =
                (&self.next, &self.after_next)
            else {
                return Err(ScheduleError::Epoch(
                    "boundary successor authority is unavailable".into(),
                ));
            };
            Ok(AppliedConfig::Boundary {
                next: next.height_config_with_validation(validation)?,
                after_next: after_next.height_config_with_validation(validation)?,
            })
        } else {
            Ok(AppliedConfig::Continuation {
                after_next: self
                    .after_next
                    .to_core_with_validation(&self.current, validation)?,
            })
        }
    }
}

/// Canonical retained window after one applied execution. Pending slots carry no authority.
/// These pure decoded-value methods validate the graph; production construction separately
/// admits and retains each owned canonical allocation from the original execution pool.
#[derive(
    Clone,
    Debug,
    Default,
    PartialEq,
    Eq,
    NoritoSerialize,
    NoritoDeserialize,
    JsonSerialize,
    JsonDeserialize,
    norito::NoritoSchema,
    iroha_schema::IntoSchema,
)]
#[norito_schema(name = "iroha_data_model::sumeragi_finality::ConsensusSchedule")]
pub struct ConsensusSchedule {
    entries: Vec<ScheduledSlot>,
}
impl ConsensusSchedule {
    /// Construct the pre-genesis empty schedule.
    pub const fn empty() -> Self {
        Self {
            entries: Vec::new(),
        }
    }
    /// Adopt and validate a complete canonical slot window.
    ///
    /// # Errors
    /// Rejects a window that is neither empty nor three consecutive correctly authorized slots.
    pub fn from_owned_entries(entries: Vec<ScheduledSlot>) -> Result<Self, ScheduleError> {
        let result = Self { entries };
        result.validate()?;
        Ok(result)
    }
    /// Oldest to newest canonical slots.
    pub fn entries(&self) -> &[ScheduledSlot] {
        &self.entries
    }
    /// The applied cut represented by the window.
    pub fn tip(&self) -> Option<u64> {
        self.entries.first().map(ScheduledSlot::height)
    }
    /// Look up a slot without treating a boundary barrier as signing authority.
    pub fn get(&self, height: u64) -> Option<&ScheduledSlot> {
        self.entries.iter().find(|entry| entry.height() == height)
    }
    /// Obtain an already authenticated configuration, refusing a pending boundary.
    ///
    /// # Errors
    /// Rejects absent heights and heights awaiting their certified predecessor boundary.
    pub fn ready(&self, height: u64) -> Result<&ScheduledConfig, ScheduleError> {
        match self.get(height) {
            Some(ScheduledSlot::Ready(config)) => Ok(config),
            Some(ScheduledSlot::PendingBoundary { .. }) => Err(ScheduleError::Epoch(
                "height awaits its exact certified predecessor boundary".into(),
            )),
            None => Err(ScheduleError::Malformed),
        }
    }
    /// The window is empty before genesis or contains three consecutive valid slots.
    pub fn is_well_formed(&self) -> bool {
        self.validate().is_ok()
    }
    fn validate(&self) -> Result<(), ScheduleError> {
        self.validate_with_validation(&mut EpochValidationScope::new())
    }
    fn validate_with_validation(
        &self,
        validation: &mut EpochValidationScope,
    ) -> Result<(), ScheduleError> {
        if self.entries.is_empty() {
            return Ok(());
        }
        if self.entries.len() != 3
            || self
                .entries
                .windows(2)
                .any(|pair| pair[0].height().checked_add(1) != Some(pair[1].height()))
        {
            return Err(ScheduleError::Malformed);
        }
        let ScheduledSlot::Ready(first) = &self.entries[0] else {
            return Err(ScheduleError::Malformed);
        };
        first.height_config_with_validation(validation)?;
        let mut context = &first.epoch;
        for slot in &self.entries[1..] {
            if let ScheduledSlot::Ready(config) = slot {
                // A window straddles the applied boundary only at its first height.
                if config.epoch != *context {
                    if first.height != first.epoch.authorization.last_height
                        || first.epoch.mode != ConsensusMode::Npos
                        || first.height.checked_add(1) != Some(config.height)
                        || config.epoch.authorization.epoch
                            != first
                                .epoch
                                .authorization
                                .epoch
                                .checked_add(1)
                                .ok_or(ScheduleError::HeightOverflow)?
                        || config.epoch.authorization.previous_authorization_id
                            != first
                                .epoch
                                .authorization
                                .authorization_id()
                                .map_err(|error| ScheduleError::Epoch(error.to_string()))?
                        || config.epoch.authorization.first_height != config.height
                    {
                        return Err(ScheduleError::Epoch(
                            "stored window changes authority away from its applied boundary".into(),
                        ));
                    }
                    config
                        .epoch
                        .authorization
                        .validate_successor(&first.epoch.authorization)
                        .map_err(|error| ScheduleError::Epoch(error.to_string()))?;
                    if config.epoch.network_id != first.epoch.network_id
                        || config.epoch.mode != first.epoch.mode
                    {
                        return Err(ScheduleError::Epoch(
                            "stored successor changes its network or mode".into(),
                        ));
                    }
                    if matches!(
                        config.epoch.authorization.decision,
                        crate::sumeragi::epoch::ValidatorEpochDecisionV1::Retain
                            | crate::sumeragi::epoch::ValidatorEpochDecisionV1::RetainAndCancel
                    ) && config.epoch.committee != first.epoch.committee
                    {
                        return Err(ScheduleError::Epoch(
                            "retained window replaces original authority credentials".into(),
                        ));
                    }
                    context = &config.epoch;
                }
            }
            slot.validate_against(context, validation)?;
        }
        Ok(())
    }
    /// Build the first window from independently authenticated signed genesis authority.
    ///
    /// # Errors
    /// Rejects invalid authority or parameters, an epoch not beginning at height one and epoch
    /// zero, or successor slots outside the signed genesis epoch.
    pub fn from_genesis(
        epoch: ValidatorEpochContextV1,
        params: ChainParamsRecord,
    ) -> Result<Self, ScheduleError> {
        Self::from_genesis_with_validation(epoch, params, &mut EpochValidationScope::new())
    }
    /// Run [`Self::from_genesis`] with bounded exact-context work owned by the enclosing operation.
    ///
    /// # Errors
    /// The same context, height and graph failures as [`Self::from_genesis`]; no source or proof
    /// authentication is supplied by this pure validation workspace.
    pub fn from_genesis_with_validation(
        epoch: ValidatorEpochContextV1,
        params: ChainParamsRecord,
        validation: &mut EpochValidationScope,
    ) -> Result<Self, ScheduleError> {
        validation.core_epoch(&epoch)?;
        if epoch.authorization.epoch != 0 || epoch.authorization.first_height != 1 {
            return Err(ScheduleError::Epoch(
                "genesis schedule does not begin at native epoch zero".into(),
            ));
        }
        params.validate().map_err(ScheduleError::Params)?;
        let entries = vec![
            ScheduledSlot::Ready(ScheduledConfig {
                height: 1,
                epoch: epoch.clone(),
                params,
            }),
            ScheduledSlot::Ready(ScheduledConfig {
                height: 2,
                epoch: epoch.clone(),
                params,
            }),
            ScheduledSlot::Ready(ScheduledConfig {
                height: 3,
                epoch,
                params,
            }),
        ];
        let result = Self { entries };
        result.validate_with_validation(validation)?;
        Ok(result)
    }
    /// Check a genesis result against a separately reconstructed signed genesis context.
    /// The caller must compare the resulting context with that independent root before trust.
    ///
    /// # Errors
    /// Rejects malformed or non-genesis outcomes and successor slots that differ from the
    /// independently reconstructed genesis schedule.
    pub fn from_genesis_outcome(outcome: &ScheduleOutcome) -> Result<Self, ScheduleError> {
        Self::from_genesis_outcome_with_validation(outcome, &mut EpochValidationScope::new())
    }
    /// Run [`Self::from_genesis_outcome`] with bounded exact-context work owned by the enclosing operation.
    ///
    /// # Errors
    /// The same context, height and graph failures as [`Self::from_genesis_outcome`]; no source or proof
    /// authentication is supplied by this pure validation workspace.
    pub fn from_genesis_outcome_with_validation(
        outcome: &ScheduleOutcome,
        validation: &mut EpochValidationScope,
    ) -> Result<Self, ScheduleError> {
        outcome.validate_with_validation(validation)?;
        if outcome.height != 1
            || outcome.boundary.is_some()
            || outcome.current.authorization.epoch != 0
            || outcome.current.authorization.first_height != 1
        {
            return Err(ScheduleError::Epoch(
                "non-genesis result cannot seed native authority".into(),
            ));
        }
        if outcome.next.params() != outcome.after_next.params() {
            return Err(ScheduleError::Epoch(
                "genesis successor parameters differ".into(),
            ));
        }
        let result = Self::from_genesis_with_validation(
            outcome.current.clone(),
            *outcome.next.params(),
            validation,
        )?;
        if result.entries[1] != outcome.next || result.entries[2] != outcome.after_next {
            return Err(ScheduleError::Epoch(
                "genesis successor authority differs".into(),
            ));
        }
        Ok(result)
    }
    /// Advance one genuinely certified result. At B only, its boundary replaces the B+1
    /// authority barrier; already fixed B+1 parameters remain unchanged. Ordinary authority
    /// cannot change through candidacy or decoded result data outside this certified graph.
    ///
    /// # Errors
    /// Rejects malformed schedules or outcomes, nonconsecutive height, changed incumbent or
    /// lag-two parameters, or a boundary that does not replace its exact pending slot.
    pub fn advanced(&self, outcome: &ScheduleOutcome) -> Result<Self, ScheduleError> {
        self.advanced_with_validation(outcome, &mut EpochValidationScope::new())
    }
    /// Run [`Self::advanced`] with bounded exact-context work owned by the enclosing operation.
    ///
    /// # Errors
    /// The same context, height and graph failures as [`Self::advanced`]; no source or proof
    /// authentication is supplied by this pure validation workspace.
    pub fn advanced_with_validation(
        &self,
        outcome: &ScheduleOutcome,
        validation: &mut EpochValidationScope,
    ) -> Result<Self, ScheduleError> {
        self.validate_with_validation(validation)?;
        outcome.validate_with_validation(validation)?;
        if self.tip().and_then(|tip| tip.checked_add(1)) != Some(outcome.height) {
            return Err(ScheduleError::NotConsecutive {
                height: outcome.height,
                last_scheduled: self.entries.last().map(ScheduledSlot::height),
            });
        }
        let incumbent = self.ready(outcome.height)?;
        if incumbent.epoch != outcome.current {
            return Err(ScheduleError::Epoch(
                "certified result changes its signing incumbent".into(),
            ));
        }
        let retained_next = self
            .get(outcome.next.height())
            .ok_or(ScheduleError::Malformed)?;
        if retained_next.params() != outcome.next.params() {
            return Err(ScheduleError::Epoch(
                "boundary changes already scheduled parameters".into(),
            ));
        }
        if outcome.boundary.is_none() && retained_next != &outcome.next {
            return Err(ScheduleError::Epoch(
                "ordinary result changes already authorized next slot".into(),
            ));
        }
        if outcome.boundary.is_some()
            && !matches!(retained_next, ScheduledSlot::PendingBoundary { .. })
        {
            return Err(ScheduleError::Epoch(
                "boundary did not replace its exact pending successor".into(),
            ));
        }
        let result = Self {
            entries: vec![
                ScheduledSlot::Ready(incumbent.clone()),
                outcome.next.clone(),
                outcome.after_next.clone(),
            ],
        };
        result.validate_with_validation(validation)?;
        Ok(result)
    }
    /// Restore the actual ready/pending slots without guessing post-boundary authority.
    ///
    /// # Errors
    /// Rejects malformed or empty schedules and invalid ready or pending configurations.
    pub fn init_configs(
        &self,
        genesis_height: u64,
    ) -> Result<Vec<(u64, ConfigSlot)>, ScheduleError> {
        let validation = &mut EpochValidationScope::new();
        self.validate_with_validation(validation)?;
        let ScheduledSlot::Ready(first) = self.entries.first().ok_or(ScheduleError::Malformed)?
        else {
            return Err(ScheduleError::Malformed);
        };
        let mut current = &first.epoch;
        let mut result = Vec::with_capacity(3);
        for entry in &self.entries {
            if let ScheduledSlot::Ready(config) = entry {
                current = &config.epoch;
            }
            if entry.height() != genesis_height {
                result.push((
                    entry.height(),
                    entry.to_core_with_validation(current, validation)?,
                ));
            }
        }
        Ok(result)
    }
}

#[cfg(test)]
mod validation_tests;
