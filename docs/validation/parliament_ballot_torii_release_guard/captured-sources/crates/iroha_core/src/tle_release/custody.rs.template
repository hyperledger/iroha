//! Runtime-only multi-session custody for Parliament TLE release shares.

use std::{collections::BTreeMap, sync::RwLock};

use iroha_data_model::governance::types::TleKeySessionId;
#[cfg(test)]
use mv::storage::StorageReadOnly as _;
use thiserror::Error;
use zeroize::Zeroizing;

#[cfg(test)]
use crate::state::{StateReadOnly, WorldReadOnly as _};
use crate::tle_release::{
    AuthorizedTleReleaseContextV1, InMemoryTlePartialReleaseSignerV1, TleKeySessionPublicStateV1,
    TlePartialReleaseCapabilityAttestationV1, TlePartialReleaseCapabilityErrorV1,
    TlePartialReleaseShareV1, TlePartialReleaseSignerV1, TleProjectedPartialReleaseSignerV1,
    ValidatedTleKeySessionV1, ValidatedTleReleaseProjectionV1,
};

/// Process-local, zeroizing owner for active and retiring TLE release shares.
///
/// The registry deliberately has no `Clone`, `Debug`, serialization, key-list,
/// or participant-list surface. A deployment-owned authenticated runtime broker
/// may import a validated software share, or inject an independent
/// [`TleProjectedPartialReleaseSignerV1`] instead of using this type. An
/// in-process provider may inject [`TlePartialReleaseSignerV1`] directly. Import
/// and retirement are never exposed as ledger instructions or public Torii
/// calls.
///
/// Each signing request selects a share only by the exact key-session identifier
/// in an opaque [`AuthorizedTleReleaseContextV1`]. A read guard pins the entry
/// until signing completes, so concurrent retirement cannot destroy scalar
/// material while it is in use. Removing an entry drops its
/// [`InMemoryTlePartialReleaseSignerV1`]; its underlying adaptive share stores
/// all scalars in `Zeroizing` memory.
pub struct RuntimeTleReleaseShareCustodyV1 {
    sessions: RwLock<BTreeMap<TleKeySessionId, InMemoryTlePartialReleaseSignerV1>>,
}

impl RuntimeTleReleaseShareCustodyV1 {
    /// Construct an empty, fail-closed runtime custody registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            sessions: RwLock::new(BTreeMap::new()),
        }
    }

    /// Import one already-validated software share into this process.
    ///
    /// The caller must be the deployment's authenticated runtime-custody
    /// boundary. Duplicate key sessions fail closed; replacing a live share is
    /// never implicit. The rejected incoming share is dropped and zeroized.
    ///
    /// # Errors
    ///
    /// Returns a closed error if custody is unavailable or the exact key
    /// session is already present.
    pub fn insert_validated_share(
        &self,
        signer: InMemoryTlePartialReleaseSignerV1,
    ) -> Result<(), TleReleaseShareCustodyErrorV1> {
        let key_session_id = signer.key_session_id();
        let mut sessions = self
            .sessions
            .write()
            .map_err(|_| TleReleaseShareCustodyErrorV1::CustodyUnavailable)?;
        match sessions.entry(key_session_id) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(signer);
                Ok(())
            }
            std::collections::btree_map::Entry::Occupied(_) => {
                Err(TleReleaseShareCustodyErrorV1::SessionAlreadyPresent)
            }
        }
    }

    /// Validate and import one zeroizing scalar triple for a public DKG session.
    ///
    /// Construction replays the complete public transcript, verifies the
    /// imported scalars against the frozen participant commitment, and consumes
    /// the `Zeroizing` input. No byte-export operation is provided.
    ///
    /// # Errors
    ///
    /// Returns a closed error for malformed public state, a mismatched share,
    /// duplicate custody, or an unavailable registry lock.
    pub fn import_components(
        &self,
        public_state: TleKeySessionPublicStateV1,
        participant_index: u16,
        components: Zeroizing<[[u8; 32]; 3]>,
    ) -> Result<(), TleReleaseShareCustodyErrorV1> {
        let signer = InMemoryTlePartialReleaseSignerV1::from_components(
            public_state,
            participant_index,
            components,
        )
        .map_err(|_| TleReleaseShareCustodyErrorV1::InvalidShare)?;
        self.insert_validated_share(signer)
    }

    #[cfg(test)]
    /// Import a scalar triple against the exact committed public transcript.
    ///
    /// This is the preferred software-custody entry point once the node has a
    /// committed state view: the authenticated runtime broker supplies only
    /// the public key-session identifier, participant seat, and zeroizing share
    /// buffer. Custody obtains the public transcript from consensus state, so a
    /// caller cannot substitute generators, verification shares, or a DKG
    /// qualification record during import.
    ///
    /// # Errors
    ///
    /// Returns a closed error when the public session is not committed, the
    /// share does not match it, the session is already held, or custody is
    /// unavailable.
    pub fn import_committed_components(
        &self,
        state: &impl StateReadOnly,
        key_session_id: TleKeySessionId,
        participant_index: u16,
        components: Zeroizing<[[u8; 32]; 3]>,
    ) -> Result<(), TleReleaseShareCustodyErrorV1> {
        let public_state = state
            .world()
            .tle_key_sessions()
            .get(&key_session_id)
            .cloned()
            .ok_or(TleReleaseShareCustodyErrorV1::SessionNotCommitted)?;
        self.import_components(public_state, participant_index, components)
    }

    #[cfg(test)]
    /// Retire and zeroize one share after every committed reference is expired.
    ///
    /// The deployment's authenticated rotation coordinator must first make the
    /// session ineligible for new ballots through the consensus key-session
    /// lifecycle. This method then reads the exact derived maximum opening
    /// deadline across all ballots and retries that reference `key_session_id`.
    /// Retirement is allowed only when the committed height is strictly greater
    /// than that maximum. A `u64::MAX` deadline is deliberately unretirable.
    ///
    /// Removing the map entry synchronously drops the non-cloneable signer and
    /// zeroizes its scalar buffers before this method returns.
    ///
    /// # Errors
    ///
    /// Returns a closed error when state validation fails, a reference remains
    /// live through the current height, the session is absent, or custody is
    /// unavailable.
    pub fn retire_session(
        &self,
        state: &impl StateReadOnly,
        key_session_id: TleKeySessionId,
    ) -> Result<(), TleReleaseShareCustodyErrorV1> {
        let world = state.world();
        let committed_public_state = world
            .tle_key_sessions()
            .get(&key_session_id)
            .cloned()
            .ok_or(TleReleaseShareCustodyErrorV1::SessionNotCommitted)?;
        let committed_height = u64::try_from(state.height())
            .map_err(|_| TleReleaseShareCustodyErrorV1::InvalidCommittedState)?;
        let next_height = committed_height.checked_add(1).unwrap_or(committed_height);
        if world.tle_key_session_eligible_for_new_ballots(key_session_id, next_height) {
            return Err(TleReleaseShareCustodyErrorV1::SessionStillRequired);
        }
        committed_public_state
            .validate()
            .map_err(|_| TleReleaseShareCustodyErrorV1::InvalidCommittedState)?;
        let retain_through = world.tle_key_session_retention_deadline_v1(key_session_id);
        if retain_through
            .is_some_and(|deadline| deadline == u64::MAX || committed_height <= deadline)
        {
            return Err(TleReleaseShareCustodyErrorV1::SessionStillRequired);
        }

        let retired = self
            .sessions
            .write()
            .map_err(|_| TleReleaseShareCustodyErrorV1::CustodyUnavailable)?
            .remove(&key_session_id)
            .ok_or(TleReleaseShareCustodyErrorV1::SessionNotPresent)?;
        drop(retired);
        Ok(())
    }
}

impl Default for RuntimeTleReleaseShareCustodyV1 {
    fn default() -> Self {
        Self::new()
    }
}

impl TlePartialReleaseSignerV1 for RuntimeTleReleaseShareCustodyV1 {
    fn attest_partial_release_capability(
        &self,
        session: &ValidatedTleKeySessionV1,
        expected_participant_index: u16,
    ) -> Result<TlePartialReleaseCapabilityAttestationV1, TlePartialReleaseCapabilityErrorV1> {
        let sessions = self
            .sessions
            .read()
            .map_err(|_| TlePartialReleaseCapabilityErrorV1::Unavailable)?;
        let signer = sessions
            .get(&session.public_state().key_session_id)
            .ok_or(TlePartialReleaseCapabilityErrorV1::NotOwned)?;
        signer.attest_partial_release_capability(session, expected_participant_index)
    }

    fn sign_partial_release(
        &self,
        context: &AuthorizedTleReleaseContextV1,
    ) -> Result<TlePartialReleaseShareV1, String> {
        let sessions = self
            .sessions
            .read()
            .map_err(|_| "Parliament TLE release custody is unavailable".to_owned())?;
        let signer = sessions
            .get(&context.session().public_state().key_session_id)
            .ok_or_else(|| "Parliament TLE release share is unavailable".to_owned())?;
        signer.sign_partial_release(context)
    }
}

impl TleProjectedPartialReleaseSignerV1 for RuntimeTleReleaseShareCustodyV1 {
    fn sign_projected_partial_release(
        &self,
        projection: &ValidatedTleReleaseProjectionV1,
    ) -> Result<TlePartialReleaseShareV1, String> {
        let sessions = self
            .sessions
            .read()
            .map_err(|_| "Parliament TLE release custody is unavailable".to_owned())?;
        let signer = sessions
            .get(&projection.session().public_state().key_session_id)
            .ok_or_else(|| "Parliament TLE release share is unavailable".to_owned())?;
        signer.sign_projected_partial_release(projection)
    }
}

/// Closed failure classes for runtime TLE release-share custody.
///
/// The enum contains no session identifier, participant seat, provider handle,
/// scalar bytes, or free-form provider diagnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum TleReleaseShareCustodyErrorV1 {
    /// The runtime custody lock was unavailable.
    #[error("Parliament TLE release custody is unavailable")]
    CustodyUnavailable,
    /// The imported scalar share or its public transcript was invalid.
    #[error("Parliament TLE release share is invalid")]
    InvalidShare,
    /// The exact key session is already held and cannot be implicitly replaced.
    #[error("Parliament TLE release session is already present")]
    SessionAlreadyPresent,
    /// The exact key session is not held by this process.
    #[error("Parliament TLE release session is not present")]
    SessionNotPresent,
    /// Consensus state does not contain the requested public key session.
    #[error("Parliament TLE public key session is not committed")]
    SessionNotCommitted,
    /// Committed Parliament state was malformed or its height was unsupported.
    #[error("committed Parliament state is invalid for TLE share retirement")]
    InvalidCommittedState,
    /// At least one committed ballot deadline still requires this share.
    #[error("Parliament TLE release session is still required")]
    SessionStillRequired,
}
