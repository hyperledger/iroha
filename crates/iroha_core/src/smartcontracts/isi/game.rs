//! Native, permissionless session lifecycle with wallet-bound funding and proof-only payouts.
use super::{Error, Execute};
use crate::state::{StateReadOnly, StateTransaction, WorldReadOnly};
use iroha_crypto::{Algorithm, Hash, Signature, derive_non_signing_ed25519_public_key};
use iroha_data_model::{
    IntoKeyValue, NetworkId,
    account::{Account, AccountId},
    asset::{AssetDefinitionId, AssetId},
    execution_proofs::{ExecutionProofEnvelopeV1, ExecutionProofVerificationV1},
    game::*,
    isi::game::*,
};
use iroha_model_base::metadata::Metadata;
use iroha_primitives::numeric::{MAX_DECIMAL_SCALE, Numeric, Quantity, RoundingMode};
use mv::storage::StorageReadOnly;
use norito::codec::Encode;
#[path = "game_items.rs"]
pub(crate) mod items;
#[path = "game_resources.rs"]
pub(crate) mod resources;

/// Exact one-shot capability produced only after native session admission.
pub(in crate::smartcontracts::isi) struct VerifiedGameMovement {
    session_id: Hash,
    authority: AccountId,
    purpose: VerifiedGameMovementPurpose,
    legs: Vec<(AssetId, AssetId, Quantity)>,
}
/// Closed native purposes; only initial settlement may defer an inadmissible transfer.
pub(in crate::smartcontracts::isi) enum VerifiedGameMovementPurpose {
    Funding,
    Settlement,
    Claim { slot: u8 },
}
impl VerifiedGameMovement {
    pub(in crate::smartcontracts::isi) fn into_parts(
        self,
    ) -> (
        Hash,
        AccountId,
        VerifiedGameMovementPurpose,
        Vec<(AssetId, AssetId, Quantity)>,
    ) {
        (self.session_id, self.authority, self.purpose, self.legs)
    }
}
fn invalid(message: impl Into<String>) -> Error {
    Error::InvariantViolation(message.into().into())
}
/// Derive custody without ever deriving a signing scalar.
pub fn game_custody_account_v1(
    network: &NetworkId,
    session: &Hash,
    asset: &AssetDefinitionId,
) -> AccountId {
    AccountId::new(derive_non_signing_ed25519_public_key(
        b"iroha:game:custody:v1",
        &[
            network.as_bytes(),
            session.as_ref(),
            asset.to_string().as_bytes(),
        ],
    ))
}
/// Check one exact custody key or funded-wallet reference count.
pub(crate) fn retained_game_account(world: &impl WorldReadOnly, account: &AccountId) -> bool {
    world.game_custody_by_account().get(account).is_some()
        || world
            .game_account_references()
            .get(account)
            .is_some_and(|count| *count != 0)
}
/// Check one exact funded-asset reference count.
pub(crate) fn retained_game_asset(world: &impl WorldReadOnly, asset: &AssetDefinitionId) -> bool {
    world
        .game_asset_references()
        .get(asset)
        .is_some_and(|count| *count != 0)
}
fn get(st: &StateTransaction<'_, '_>, id: &Hash) -> Result<GameSessionRecordV1, Error> {
    st.world
        .game_sessions
        .get(id)
        .cloned()
        .ok_or_else(|| invalid("session does not exist"))
}
fn next_deadline(st: &StateTransaction<'_, '_>, blocks: u64) -> Result<u64, Error> {
    st.block_height()
        .checked_add(blocks)
        .ok_or_else(|| invalid("session deadline height overflow"))
}
fn active_slots(session: &GameSessionRecordV1) -> Vec<usize> {
    session
        .participants
        .iter()
        .enumerate()
        .filter_map(|(i, p)| p.dnf_at_tick.is_none().then_some(i))
        .collect()
}
fn verify_signature(
    key: &iroha_crypto::PublicKey,
    signature: &Signature,
    hash: &Hash,
) -> Result<(), Error> {
    if key.algorithm() != Algorithm::Ed25519 || signature.payload().len() != 64 {
        return Err(invalid("session signatures require canonical Ed25519"));
    }
    signature
        .verify(key, hash.as_ref())
        .map_err(|_| invalid("invalid session gameplay signature"))
}
fn verify_joint(
    session: &GameSessionRecordV1,
    signatures: &[GameSlotSignatureV1],
    hash: &Hash,
) -> Result<(), Error> {
    // Removed participants may still own a winning claim. Their signature remains
    // necessary for optional checkpoints; forced progress never needs it.
    let slots = (0..session.participants.len()).collect::<Vec<_>>();
    if signatures.len() != slots.len() || slots.is_empty() {
        return Err(invalid(
            "session certificate requires every original participant",
        ));
    }
    for (signature, slot) in signatures.iter().zip(slots) {
        if usize::from(signature.slot) != slot {
            return Err(invalid(
                "session certificate slots must be unique and ordered",
            ));
        }
        verify_signature(
            &session.participants[slot].input_key,
            &signature.signature,
            hash,
        )?;
    }
    Ok(())
}
/// Hash the exact chain-selected history, not a relayer-provided projection.
pub fn game_dispute_root_v1(session: &GameSessionRecordV1) -> Hash {
    game_message_hash_v1(
        &session.network_id,
        "dispute-history",
        &(
            session.session_id,
            session.epoch,
            session.checkpoint.as_ref().map(|c| c.checkpoint),
            session.transcript_anchors.clone(),
            session.forced_batches.clone(),
        ),
    )
}
fn changed_reference_count(current: Option<&u32>, add: bool) -> Result<u32, Error> {
    let current = current.copied().unwrap_or_default();
    if add {
        current.checked_add(1)
    } else {
        current.checked_sub(1)
    }
    .ok_or_else(|| invalid("game retention reference count overflow or underflow"))
}
pub(crate) fn referenced_game_wallets(session: &GameSessionRecordV1) -> Vec<AccountId> {
    if (!session.item_stakes.is_empty() || !session.resources.is_empty())
        && !matches!(session.phase, GamePhaseV1::Settled | GamePhaseV1::Cancelled)
    {
        return session
            .participants
            .iter()
            .map(|participant| participant.account.clone())
            .collect();
    }
    if session.liability.is_zero() {
        return Vec::new();
    }
    if matches!(session.phase, GamePhaseV1::Settled | GamePhaseV1::Cancelled) {
        session
            .payout_claims
            .iter()
            .filter(|claim| !claim.remaining.is_zero())
            .filter_map(|claim| session.participants.get(usize::from(claim.slot)))
            .map(|participant| participant.account.clone())
            .collect()
    } else {
        session
            .participants
            .iter()
            .map(|participant| participant.account.clone())
            .collect()
    }
}
/// Update only the at-most-32 participant keys affected by this transition.
fn update_session_indexes(
    st: &mut StateTransaction<'_, '_>,
    session: &GameSessionRecordV1,
) -> Result<(), Error> {
    let old = st.world.game_sessions.get(&session.session_id);
    if old.is_some_and(|old| {
        old.custody != session.custody || old.asset_definition != session.asset_definition
    }) {
        return Err(invalid("game custody and asset identity are immutable"));
    }
    if old.is_some_and(|old| {
        old.phase != GamePhaseV1::Lobby
            && (!items::same_staked_items(&old.item_stakes, &session.item_stakes)
                || !resources::same_reserved_resources(&old.resources, &session.resources))
    }) {
        return Err(invalid("started game item stakes are immutable"));
    }
    if old.is_some_and(|old| {
        matches!(old.phase, GamePhaseV1::Settled | GamePhaseV1::Cancelled)
            && (old.phase != session.phase
                || old.item_stakes != session.item_stakes
                || old.resources != session.resources
                || old.terminal_at_height != session.terminal_at_height
                || old.result != session.result
                || old.payout_claims.len() != session.payout_claims.len()
                || old
                    .payout_claims
                    .iter()
                    .zip(&session.payout_claims)
                    .any(|(before, after)| {
                        before.slot != after.slot
                            || before.amount != after.amount
                            || after.remaining > before.remaining
                    }))
    }) {
        return Err(invalid(
            "closed game awards are immutable and claims cannot increase",
        ));
    }
    if st
        .world
        .game_custody_by_account
        .get(&session.custody)
        .is_some_and(|id| *id != session.session_id)
    {
        return Err(invalid("game custody is already reserved"));
    }
    let old_funded = old.is_some_and(|old| !old.liability.is_zero());
    let new_funded = !session.liability.is_zero();
    let old_accounts = old.map_or_else(Vec::new, referenced_game_wallets);
    let new_accounts = referenced_game_wallets(session);
    let mut changes = Vec::new();
    for account in &old_accounts {
        if !new_accounts.contains(account) {
            changes.push((
                account.clone(),
                changed_reference_count(st.world.game_account_references.get(account), false)?,
            ));
        }
    }
    for account in &new_accounts {
        if !old_accounts.contains(account) {
            changes.push((
                account.clone(),
                changed_reference_count(st.world.game_account_references.get(account), true)?,
            ));
        }
    }
    let asset_change = if old_funded == new_funded {
        None
    } else {
        Some(changed_reference_count(
            st.world
                .game_asset_references
                .get(&session.asset_definition),
            new_funded,
        )?)
    };
    st.world
        .game_custody_by_account
        .insert(session.custody.clone(), session.session_id);
    for (account, count) in changes {
        if count == 0 {
            st.world.game_account_references.remove(account);
        } else {
            st.world.game_account_references.insert(account, count);
        }
    }
    if let Some(count) = asset_change {
        if count == 0 {
            st.world
                .game_asset_references
                .remove(session.asset_definition.clone());
        } else {
            st.world
                .game_asset_references
                .insert(session.asset_definition.clone(), count);
        }
    }
    Ok(())
}
fn save(st: &mut StateTransaction<'_, '_>, mut session: GameSessionRecordV1) -> Result<(), Error> {
    session.revision = session
        .revision
        .checked_add(1)
        .ok_or_else(|| invalid("session revision overflow"))?;
    session.dispute_root = game_dispute_root_v1(&session);
    update_session_indexes(st, &session)?;
    st.world.emit_events(Some(
        iroha_data_model::events::data::game::GameSessionEventV1 {
            session_id: session.session_id,
            revision: session.revision,
            phase: session.phase as u8,
            dispute_root: session.dispute_root,
            payout_claims: session.payout_claims.clone(),
            item_stakes: session.item_stakes.clone(),
            resources: session.resources.clone(),
            terminal_at_height: session.terminal_at_height,
        },
    ));
    st.world.game_sessions.insert(session.session_id, session);
    Ok(())
}
fn validate_checkpoint(
    session: &GameSessionRecordV1,
    checkpoint: &SignedGameCheckpointV1,
) -> Result<(), Error> {
    let cp = &checkpoint.checkpoint;
    let tick_in_range = (session.next_tick..=session.manifest.max_ticks).contains(&cp.tick);
    if cp.session_id != session.session_id
        || cp.epoch != session.epoch
        || !tick_in_range
        || (!cp.terminal
            && !cp
                .tick
                .is_multiple_of(u32::from(session.manifest.batch_ticks)))
    {
        return Err(invalid(
            "session checkpoint has wrong epoch or stale/noncanonical tick",
        ));
    }
    if let Some(old) = &session.checkpoint {
        if cp.tick == old.checkpoint.tick && cp != &old.checkpoint {
            return Err(invalid("conflicting session checkpoint at same tick"));
        }
    }
    verify_joint(
        session,
        &checkpoint.signatures,
        &game_message_hash_v1(&session.network_id, "checkpoint", cp),
    )
}
fn validate_frontier(
    session: &GameSessionRecordV1,
    checkpoint: &GameCheckpointV1,
    frontier: &GameCommitmentSetV1,
) -> Result<(), Error> {
    if frontier.session_id != session.session_id
        || frontier.epoch != session.epoch
        || (frontier.start_tick, &frontier.parent_transcript_root)
            != (checkpoint.tick, &checkpoint.transcript_root)
        || frontier.commitments.len() != session.participants.len()
        || checkpoint.terminal
    {
        return Err(invalid(
            "session commitment frontier does not extend exact checkpoint",
        ));
    }
    verify_joint(
        session,
        &frontier.signatures,
        &game_commitment_set_hash_v1(&session.network_id, frontier),
    )
}
fn validate_invitation(
    session: &GameSessionRecordV1,
    wallet: &AccountId,
    input_key: &iroha_crypto::PublicKey,
    application_data: &[u8],
    invitation: Option<&Signature>,
) -> Result<(), Error> {
    match (&session.manifest.access, invitation) {
        (GameAccessV1::Public, None) => Ok(()),
        (GameAccessV1::Invite(key), Some(signature)) => verify_signature(
            key,
            signature,
            &game_invitation_hash_v1(
                &session.network_id,
                session.session_id,
                wallet,
                input_key,
                application_data,
            ),
        ),
        _ => Err(invalid("session invitation missing or not applicable")),
    }
}
impl Execute for OpenGameSessionV1 {
    fn execute(
        self,
        authority: &AccountId,
        st: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        if self.manifest.version != 1
            || !(1..=GAME_MAX_PARTICIPANTS_V1)
                .contains(&usize::from(self.manifest.max_participants))
            || self.manifest.min_participants == 0
            || self.manifest.min_participants > self.manifest.max_participants
            || self.manifest.batch_ticks == 0
            || self.manifest.batch_ticks > 256
            || self.manifest.max_ticks == 0
            || self.manifest.max_ticks > 1_000_000
            || !self
                .manifest
                .max_ticks
                .is_multiple_of(u32::from(self.manifest.batch_ticks))
            || self.manifest.max_ticks / u32::from(self.manifest.batch_ticks) > 4096
            || u64::from(self.manifest.max_ticks / u32::from(self.manifest.batch_ticks))
                * u64::from(self.manifest.max_participants)
                * u64::from(self.manifest.max_input_bytes)
                > 4_194_304
            || self.manifest.max_input_bytes == 0
            || self.manifest.max_input_bytes > 4096
            || self.manifest.max_participant_data_bytes > 4096
            || self.manifest.application_parameters.len() > 65536
            || (self.manifest.payout_policy == GamePayoutPolicyV1::NoPayout
                && !self.stake.is_zero())
            || self.join_deadline_height <= st.block_height()
            || self.join_deadline_height > next_deadline(st, 300)?
        {
            return Err(invalid(
                "invalid session rules, positive stake, or bounded join deadline",
            ));
        }
        if st.world.game_sessions.get(&self.session_id).is_some() {
            return Err(invalid("session id already used"));
        }
        if let GameAccessV1::Invite(key) = &self.manifest.access {
            if key.algorithm() != Algorithm::Ed25519 {
                return Err(invalid("session invitation key must use Ed25519"));
            }
        }
        st.world.account(authority)?;
        crate::execution_proofs::validate_game_manifest_v1(&self.manifest)
            .map_err(|e| invalid(format!("compiled game manifest rejected: {e}")))?;
        let payout_scale = if self.stake.is_zero() {
            0
        } else {
            if st
                .world
                .asset_definition(&self.asset_definition)?
                .balance_scope_policy()
                != iroha_data_model::asset::AssetBalancePolicy::Global
            {
                return Err(invalid("V1 game stakes require a globally scoped asset"));
            }
            let spec = st.numeric_spec_for(&self.asset_definition)?;
            super::asset::isi::assert_numeric_spec_with(self.stake.as_numeric(), spec)?;
            let scale = spec.scale().unwrap_or(MAX_DECIMAL_SCALE);
            validate_payout_capacity(&self.stake, self.manifest.max_participants, scale)?;
            scale
        };
        let network = st.network_id().clone();
        let custody = game_custody_account_v1(&network, &self.session_id, &self.asset_definition);
        if st.world.assets_in_account_iter(&custody).next().is_some() {
            return Err(invalid(
                "game custody must be empty before session creation",
            ));
        }
        register_compiled_profile(st, self.manifest.profile_id)?;
        if st.world.account(&custody).is_err() {
            let (id, value) = Account {
                id: custody.clone(),
                metadata: Metadata::default(),
                label: None,
                uaid: None,
                opaque_ids: Vec::new(),
            }
            .into_key_value();
            st.world.accounts.insert(id, value);
        }
        let session = GameSessionRecordV1 {
            version: 1,
            network_id: network.clone(),
            session_id: self.session_id,
            profile_id: self.manifest.profile_id,
            manifest_hash: game_message_hash_v1(&network, "session-manifest", &self.manifest),
            manifest: self.manifest,
            asset_definition: self.asset_definition,
            stake: self.stake,
            payout_scale,
            custody,
            liability: Quantity::zero(),
            payout_claims: Vec::new(),
            item_stakes: Vec::new(),
            resources: Vec::new(),
            participants: Vec::new(),
            roster_hash: Hash::new([]),
            phase: GamePhaseV1::Lobby,
            revision: 0,
            epoch: 0,
            deadline_height: self.join_deadline_height,
            checkpoint: None,
            pending_certificate: None,
            next_tick: 0,
            input_commitments: Vec::new(),
            input_reveals: Vec::new(),
            transcript_anchors: Vec::new(),
            forced_batches: Vec::new(),
            dispute_root: Hash::new([]),
            verification_id: None,
            terminal_at_height: None,
            result: None,
        };
        save(st, session)
    }
}
impl Execute for JoinGameSessionV1 {
    fn execute(
        self,
        authority: &AccountId,
        st: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let mut session = get(st, &self.session_id)?;
        // The endpoint that displays a lobby cannot authorize a different debit.
        // Compare the wallet-signed terms before all admission and funding work.
        if self.expected_manifest_hash != session.manifest_hash
            || self.expected_asset_definition != session.asset_definition
            || self.expected_stake != session.stake
        {
            return Err(invalid(
                "wallet-approved game entry terms do not match the session",
            ));
        }
        if !session.stake.is_zero()
            && st
                .world
                .asset_definition(&session.asset_definition)?
                .balance_scope_policy()
                != iroha_data_model::asset::AssetBalancePolicy::Global
        {
            return Err(invalid("V1 game stakes require a globally scoped asset"));
        }
        let profile =
            crate::execution_proofs::compiled_execution_profile_v1(&session.profile_id)
                .ok_or_else(|| invalid("execution profile is not compiled in this runtime"))?;
        if (!session.stake.is_zero() || !self.resources.is_empty()) && !profile.qualified {
            return Err(invalid(
                "execution proof profile has not passed qualification; funding disabled",
            ));
        }
        if session.phase != GamePhaseV1::Lobby
            || *authority == session.custody
            || st.block_height() > session.deadline_height
            || session.participants.len() >= usize::from(session.manifest.max_participants)
            || self.application_data.len()
                > usize::from(session.manifest.max_participant_data_bytes)
            || self.input_key.algorithm() != Algorithm::Ed25519
            || session
                .participants
                .iter()
                .any(|p| p.account == *authority || p.input_key == self.input_key)
        {
            return Err(invalid(
                "session seat, wallet or input key is not admissible",
            ));
        }
        // Free sessions bypass numeric funding admission, so validate their
        // authority here as well; every roster entry must name a retained account.
        st.world.account(authority)?;
        validate_invitation(
            &session,
            authority,
            &self.input_key,
            &self.application_data,
            self.invitation.as_ref(),
        )?;
        let participant = GameParticipantV1 {
            account: authority.clone(),
            input_key: self.input_key,
            application_data: self.application_data,
            dnf_at_tick: None,
        };
        let equipment = resources::prepare_admission(st, &session, &participant, &self.resources)?;
        let liability = session
            .liability
            .checked_add(&session.stake)
            .map_err(|_| invalid("session stake liability overflow"))?;
        let movement = VerifiedGameMovement {
            session_id: session.session_id,
            authority: authority.clone(),
            purpose: VerifiedGameMovementPurpose::Funding,
            legs: vec![(
                AssetId::new(session.asset_definition.clone(), authority.clone()),
                AssetId::new(session.asset_definition.clone(), session.custody.clone()),
                session.stake.clone(),
            )],
        };
        if !session.stake.is_zero() {
            super::asset::isi::execute_verified_game_movement(st, movement)?;
        }
        resources::apply_admission(st, &mut session, equipment);
        session.liability = liability;
        session.participants.push(participant);
        save(st, session)
    }
}
impl Execute for StartGameSessionV1 {
    fn execute(
        self,
        _authority: &AccountId,
        st: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let mut session = get(st, &self.session_id)?;
        if session.phase != GamePhaseV1::Lobby
            || session.participants.len() < usize::from(session.manifest.min_participants)
            || (session.participants.len() < usize::from(session.manifest.max_participants)
                && st.block_height() <= session.deadline_height)
        {
            return Err(invalid(
                "session starts when its participant limit is reached or join deadline has passed",
            ));
        }
        let admission = GameAdmissionBodyV1::from_session(&session);
        admission.validate().map_err(invalid)?;
        session.roster_hash =
            game_roster_hash_v1(&session.network_id, &session.session_id, &admission);
        let state_root = crate::execution_proofs::initial_game_state_root_v1(
            &session.network_id,
            &session.manifest,
            u8::try_from(session.participants.len())
                .map_err(|_| invalid("game participant count exceeds its wire bound"))?,
        )
        .map_err(|e| invalid(format!("initial game state rejected: {e}")))?;
        let transcript_root = game_message_hash_v1(
            &session.network_id,
            "input-transcript",
            &GameTranscriptV1 {
                batches: Vec::new(),
                dnf_events: Vec::new(),
            },
        );
        session.checkpoint = Some(SignedGameCheckpointV1 {
            checkpoint: GameCheckpointV1 {
                session_id: session.session_id,
                epoch: session.epoch,
                tick: 0,
                transcript_root,
                state_root,
                terminal: false,
            },
            signatures: Vec::new(),
        });
        session.phase = GamePhaseV1::Playing;
        session.deadline_height = next_deadline(st, 300)?;
        session.input_commitments = vec![None; session.participants.len()];
        session.input_reveals = vec![None; session.participants.len()];
        save(st, session)
    }
}
impl Execute for CommitGameCheckpointV1 {
    fn execute(
        self,
        _authority: &AccountId,
        st: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let mut session = get(st, &self.session_id)?;
        if !matches!(
            session.phase,
            GamePhaseV1::Playing | GamePhaseV1::SelectingCheckpoint | GamePhaseV1::ForcedCommit
        ) || (session.phase == GamePhaseV1::SelectingCheckpoint
            && st.block_height() > session.deadline_height)
        {
            return Err(invalid("session checkpoint phase is sealed"));
        }
        if session.phase == GamePhaseV1::ForcedCommit {
            // Resumption must certify newly resolved controls in a new epoch. A
            // pre-dispute certificate must never restart the same deadline cycle.
            let tick = self.checkpoint.checkpoint.tick;
            if tick != session.next_tick
                || !session.forced_batches.last().is_some_and(|batch| {
                    batch
                        .start_tick
                        .checked_add(u32::from(session.manifest.batch_ticks))
                        == Some(tick)
                        && batch.epoch.checked_add(1) == Some(session.epoch)
                })
                || session
                    .checkpoint
                    .as_ref()
                    .is_some_and(|old| tick <= old.checkpoint.tick)
                || session.input_commitments.iter().any(Option::is_some)
            {
                return Err(invalid(
                    "session resumption must certify a newly completed forced batch",
                ));
            }
        }
        validate_checkpoint(&session, &self.checkpoint)?;
        if let Some(frontier) = &self.frontier {
            validate_frontier(&session, &self.checkpoint.checkpoint, frontier)?;
        }
        if let Some(old) = &session.pending_certificate {
            if self.checkpoint.checkpoint.tick == old.start_tick
                && self.frontier.as_ref() != Some(old)
            {
                return Err(invalid(
                    "certified pending controls cannot be discarded or replaced",
                ));
            }
        }
        session.next_tick = self.checkpoint.checkpoint.tick;
        session.checkpoint = Some(self.checkpoint);
        session.pending_certificate = self.frontier;
        if session.phase == GamePhaseV1::ForcedCommit {
            session.phase = GamePhaseV1::Playing;
            session.deadline_height = next_deadline(st, 300)?;
        }
        // A challenge window always remains fixed even when a terminal certificate arrives.
        if session.phase == GamePhaseV1::Playing
            && session
                .checkpoint
                .as_ref()
                .is_some_and(|c| c.checkpoint.terminal)
        {
            session.phase = GamePhaseV1::AwaitingProof;
        }
        save(st, session)
    }
}
impl Execute for ChallengeGameSessionV1 {
    fn execute(
        self,
        _authority: &AccountId,
        st: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let mut session = get(st, &self.session_id)?;
        if session.phase != GamePhaseV1::Playing || self.epoch != session.epoch {
            return Err(invalid("session challenge is stale or already active"));
        }
        let participant = session
            .participants
            .get(usize::from(self.slot))
            .ok_or_else(|| invalid("unknown session challenger slot"))?;
        if participant.dnf_at_tick.is_some() {
            return Err(invalid("DNF participant cannot restart play"));
        }
        verify_signature(
            &participant.input_key,
            &self.signature,
            &game_message_hash_v1(
                &session.network_id,
                "challenge",
                &(session.session_id, session.epoch, self.slot),
            ),
        )?;
        session.phase = GamePhaseV1::SelectingCheckpoint;
        session.deadline_height = next_deadline(st, GAME_CHECKPOINT_WINDOW_BLOCKS_V1)?;
        save(st, session)
    }
}
impl Execute for CommitGameInputsV1 {
    fn execute(
        self,
        _authority: &AccountId,
        st: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let input = self.input;
        let mut session = get(st, &input.session_id)?;
        if session.phase != GamePhaseV1::ForcedCommit
            || st.block_height() > session.deadline_height
            || input.epoch != session.epoch
            || input.start_tick != session.next_tick
        {
            return Err(invalid(
                "session input commitment is stale or outside its phase",
            ));
        }
        let slot = usize::from(input.slot);
        let participant = session
            .participants
            .get(slot)
            .ok_or_else(|| invalid("unknown input slot"))?;
        if participant.dnf_at_tick.is_some() {
            return Err(invalid("DNF slot has no gameplay authority"));
        }
        verify_signature(
            &participant.input_key,
            &input.signature,
            &game_input_message_hash_v1(&session.network_id, &input),
        )?;
        if session.input_commitments[slot].is_some_and(|old| old != input.commitment) {
            return Err(invalid("session input commitment cannot be replaced"));
        }
        session.input_commitments[slot] = Some(input.commitment);
        if active_slots(&session)
            .iter()
            .all(|slot| session.input_commitments[*slot].is_some())
        {
            session.phase = GamePhaseV1::ForcedReveal;
            session.deadline_height = next_deadline(st, GAME_INPUT_WINDOW_BLOCKS_V1)?;
        }
        save(st, session)
    }
}
impl Execute for RevealGameInputsV1 {
    fn execute(
        self,
        _authority: &AccountId,
        st: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let input = self.reveal;
        let mut session = get(st, &input.session_id)?;
        if session.phase != GamePhaseV1::ForcedReveal
            || st.block_height() > session.deadline_height
            || input.epoch != session.epoch
            || input.start_tick != session.next_tick
            || input.payload.len() > usize::from(session.manifest.max_input_bytes)
        {
            return Err(invalid(
                "session input reveal is stale, oversized or malformed",
            ));
        }
        crate::execution_proofs::validate_game_input_v1(&session.manifest, &input.payload)
            .map_err(|e| invalid(format!("game input payload rejected: {e}")))?;
        let slot = usize::from(input.slot);
        if slot >= session.participants.len()
            || session.participants[slot].dnf_at_tick.is_some()
            || session.input_commitments[slot]
                != Some(game_input_commitment_v1(&session.network_id, &input))
        {
            return Err(invalid(
                "session reveal does not match exact retained commitment",
            ));
        }
        if session.input_reveals[slot]
            .as_ref()
            .is_some_and(|old| old != &input.payload)
        {
            return Err(invalid("session reveal conflicts with retained controls"));
        }
        session.input_reveals[slot] = Some(input.payload);
        if active_slots(&session)
            .iter()
            .all(|slot| session.input_reveals[*slot].is_some())
        {
            advance_batch(st, &mut session, false)?;
        }
        save(st, session)
    }
}
fn advance_batch(
    st: &StateTransaction<'_, '_>,
    session: &mut GameSessionRecordV1,
    expired: bool,
) -> Result<(), Error> {
    let mut dnf_slots = Vec::new();
    for slot in active_slots(session) {
        if session.input_reveals[slot].is_none() {
            if !expired {
                return Err(invalid("session batch lacks required reveal"));
            }
            session.participants[slot].dnf_at_tick = Some(session.next_tick);
            dnf_slots.push(
                u8::try_from(slot).map_err(|_| invalid("game DNF slot exceeds its wire bound"))?,
            );
        }
    }
    if !dnf_slots.is_empty() {
        if let Some(checkpoint) = &session.checkpoint {
            let anchor = GameTranscriptAnchorV1 {
                tick: checkpoint.checkpoint.tick,
                transcript_root: checkpoint.checkpoint.transcript_root,
            };
            if session.transcript_anchors.last() != Some(&anchor) {
                if session.transcript_anchors.len() >= GAME_MAX_PARTICIPANTS_V1 {
                    return Err(invalid("session authority-shrink anchor bound exceeded"));
                }
                session.transcript_anchors.push(anchor);
            }
        }
    }
    session.forced_batches.push(GameForcedBatchV1 {
        epoch: session.epoch,
        start_tick: session.next_tick,
        inputs: session
            .input_reveals
            .iter()
            .map(|controls| controls.clone().unwrap_or_default())
            .collect(),
        dnf_slots,
    });
    session.next_tick = session
        .next_tick
        .checked_add(u32::from(session.manifest.batch_ticks))
        .ok_or_else(|| invalid("session tick overflow"))?;
    session.epoch = session
        .epoch
        .checked_add(1)
        .ok_or_else(|| invalid("session epoch overflow"))?;
    session.pending_certificate = None;
    session.input_commitments.fill(None);
    session.input_reveals.fill(None);
    session.phase = if session.next_tick >= session.manifest.max_ticks
        || active_slots(session).len() < usize::from(session.manifest.min_participants)
    {
        GamePhaseV1::AwaitingProof
    } else {
        GamePhaseV1::ForcedCommit
    };
    session.deadline_height = next_deadline(st, GAME_INPUT_WINDOW_BLOCKS_V1)?;
    Ok(())
}
impl Execute for AdvanceGameDeadlineV1 {
    fn execute(
        self,
        _authority: &AccountId,
        st: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let mut session = get(st, &self.session_id)?;
        if st.block_height() <= session.deadline_height {
            return Err(invalid("session deadline has not expired"));
        }
        match session.phase {
            GamePhaseV1::Playing => {
                session.phase = GamePhaseV1::SelectingCheckpoint;
                session.deadline_height = next_deadline(st, GAME_CHECKPOINT_WINDOW_BLOCKS_V1)?;
            }
            GamePhaseV1::SelectingCheckpoint => {
                if session
                    .checkpoint
                    .as_ref()
                    .is_some_and(|c| c.checkpoint.terminal)
                {
                    session.phase = GamePhaseV1::AwaitingProof;
                } else if let Some(frontier) = &session.pending_certificate {
                    session.input_commitments =
                        frontier.commitments.iter().copied().map(Some).collect();
                    session.phase = GamePhaseV1::ForcedReveal;
                    session.deadline_height = next_deadline(st, GAME_INPUT_WINDOW_BLOCKS_V1)?;
                } else {
                    session.phase = GamePhaseV1::ForcedCommit;
                    session.deadline_height = next_deadline(st, GAME_INPUT_WINDOW_BLOCKS_V1)?;
                }
            }
            GamePhaseV1::ForcedCommit => {
                session.phase = GamePhaseV1::ForcedReveal;
                session.deadline_height = next_deadline(st, GAME_INPUT_WINDOW_BLOCKS_V1)?;
            }
            GamePhaseV1::ForcedReveal => advance_batch(st, &mut session, true)?,
            _ => return Err(invalid("session has no advanceable deadline")),
        }
        save(st, session)
    }
}
/// Divide at the immutable quantum, awarding at most one extra unit per ordered winner.
fn winner_amounts(
    pool: &Quantity,
    recipient_count: usize,
    scale: u32,
) -> Result<Vec<Quantity>, Error> {
    if recipient_count == 0
        || recipient_count > GAME_MAX_PARTICIPANTS_V1
        || scale > MAX_DECIMAL_SCALE
        || pool.scale() > scale
    {
        return Err(invalid(
            "session payout recipient count or precision is invalid",
        ));
    }
    if recipient_count == 1 {
        return Ok(vec![pool.clone()]);
    }
    let share = pool
        .try_mul_div_decimal_round(
            &Numeric::one(),
            &Numeric::from(recipient_count as u64),
            scale,
            RoundingMode::Floor,
        )
        .map_err(|_| invalid("session payout division overflow"))?;
    let quantum = Quantity::try_from_numeric(
        Numeric::try_new(1_u32, scale)
            .map_err(|_| invalid("session payout quantum cannot be represented"))?,
    )
    .map_err(|_| invalid("session payout quantum cannot be represented"))?;
    let mut remaining = pool.clone();
    let mut amounts = vec![share; recipient_count];
    for amount in &amounts {
        remaining = remaining
            .checked_sub(amount)
            .map_err(|_| invalid("session payout liability underflow"))?;
    }
    for amount in &mut amounts {
        if remaining.is_zero() {
            break;
        }
        remaining = remaining
            .checked_sub(&quantum)
            .map_err(|_| invalid("session payout remainder is below its frozen quantum"))?;
        *amount = amount
            .checked_add(&quantum)
            .map_err(|_| invalid("session payout residual unit overflow"))?;
    }
    if !remaining.is_zero() {
        return Err(invalid(
            "session payout remainder exceeds one unit per winner",
        ));
    }
    Ok(amounts)
}
/// Reject otherwise legal large stakes whose fractional winnings cannot be represented.
/// This bounded admission check runs before custody can receive any entry funds.
fn validate_payout_capacity(
    stake: &Quantity,
    max_participants: u8,
    scale: u32,
) -> Result<(), Error> {
    let mut pool = Quantity::zero();
    for participants in 1..=usize::from(max_participants) {
        pool = pool
            .checked_add(stake)
            .map_err(|_| invalid("maximum session pool cannot be represented"))?;
        for winners in 1..=participants {
            winner_amounts(&pool, winners, scale)?;
        }
    }
    Ok(())
}
fn refund_amounts(stake: &Quantity, pool: &Quantity, count: usize) -> Result<Vec<Quantity>, Error> {
    let mut remaining = pool.clone();
    let mut amounts = Vec::with_capacity(count);
    for _ in 0..count {
        remaining = remaining
            .checked_sub(stake)
            .map_err(|_| invalid("session refund exceeds liability"))?;
        amounts.push(stake.clone());
    }
    if !remaining.is_zero() {
        return Err(invalid(
            "session refund liability differs from exact original stakes",
        ));
    }
    Ok(amounts)
}
/// Recompute immutable closed-session awards when rebuilding skipped custody guards.
pub(crate) fn expected_game_awards_v1(
    session: &GameSessionRecordV1,
) -> Result<Vec<(u8, Quantity)>, Error> {
    let refund = match session.phase {
        GamePhaseV1::Cancelled => true,
        GamePhaseV1::Settled => session
            .result
            .as_ref()
            .ok_or_else(|| invalid("settled game has no proved outcome"))?
            .winner_slots
            .is_empty(),
        _ => return Err(invalid("game awards require a closed session")),
    };
    let slots = if refund {
        (0..session.participants.len())
            .map(|slot| {
                u8::try_from(slot).map_err(|_| invalid("game refund slot exceeds its wire bound"))
            })
            .collect::<Result<Vec<_>, _>>()?
    } else {
        session
            .result
            .as_ref()
            .expect("settled outcome checked")
            .winner_slots
            .clone()
    };
    if slots
        .iter()
        .any(|slot| usize::from(*slot) >= session.participants.len())
        || slots.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(invalid("closed game awards have invalid owner slots"));
    }
    let mut pool = Quantity::zero();
    for _ in &session.participants {
        pool = pool
            .checked_add(&session.stake)
            .map_err(|_| invalid("game award pool overflow"))?;
    }
    if pool.is_zero() {
        return Ok(Vec::new());
    }
    let amounts = if refund {
        refund_amounts(&session.stake, &pool, slots.len())?
    } else {
        winner_amounts(&pool, slots.len(), session.payout_scale)?
    };
    Ok(slots
        .into_iter()
        .zip(amounts)
        .filter(|(_, amount)| !amount.is_zero())
        .collect())
}
fn payout(
    st: &mut StateTransaction<'_, '_>,
    session: &mut GameSessionRecordV1,
    recipients: &[usize],
    refund: bool,
) -> Result<(), Error> {
    if session.liability.is_zero() {
        return Ok(());
    }
    if recipients.is_empty()
        || recipients
            .iter()
            .any(|slot| *slot >= session.participants.len())
        || recipients.windows(2).any(|pair| pair[0] >= pair[1])
        || (refund && recipients != (0..session.participants.len()).collect::<Vec<_>>())
    {
        return Err(invalid("session payout recipients absent or noncanonical"));
    }
    let amounts = if refund {
        refund_amounts(&session.stake, &session.liability, recipients.len())?
    } else {
        winner_amounts(&session.liability, recipients.len(), session.payout_scale)?
    };
    let mut legs = Vec::new();
    let mut claims = Vec::with_capacity(recipients.len());
    for (slot, amount) in recipients.iter().zip(amounts) {
        if !amount.is_zero() {
            claims.push(GamePayoutClaimV1 {
                slot: u8::try_from(*slot)
                    .map_err(|_| invalid("game payout slot exceeds its wire bound"))?,
                amount: amount.clone(),
                remaining: amount.clone(),
            });
            legs.push((
                AssetId::new(session.asset_definition.clone(), session.custody.clone()),
                AssetId::new(
                    session.asset_definition.clone(),
                    session.participants[*slot].account.clone(),
                ),
                amount,
            ));
        }
    }
    let paid = super::asset::isi::execute_verified_game_movement(
        st,
        VerifiedGameMovement {
            session_id: session.session_id,
            authority: session.custody.clone(),
            purpose: VerifiedGameMovementPurpose::Settlement,
            legs,
        },
    )?;
    if paid {
        for claim in &mut claims {
            claim.remaining = Quantity::zero();
        }
        session.liability = Quantity::zero();
    }
    session.payout_claims = claims;
    Ok(())
}
fn validate_statement(
    session: &GameSessionRecordV1,
    proof: &ExecutionProofEnvelopeV1,
    outcome: &GameOutcomeV1,
) -> Result<(), Error> {
    let statement = &proof.statement;
    let admission = GameAdmissionBodyV1::from_session(session);
    admission.validate().map_err(invalid)?;
    if session.roster_hash
        != game_roster_hash_v1(&session.network_id, &session.session_id, &admission)
    {
        return Err(invalid(
            "proof roster differs from immutable native admission",
        ));
    }
    if proof.version != 1
        || proof.profile_id != session.profile_id
        || statement.network_id != session.network_id
        || statement.session_id != session.session_id
        || statement.roster_hash != session.roster_hash
        || statement.manifest_hash != session.manifest_hash
        || statement.dispute_root != session.dispute_root
        || statement.outcome_hash
            != game_message_hash_v1(&session.network_id, "session-outcome", outcome)
        || outcome.terminal_tick > session.manifest.max_ticks
        || outcome.result.len() > 65536
        || outcome
            .winner_slots
            .iter()
            .any(|slot| usize::from(*slot) >= session.participants.len())
        || outcome
            .winner_slots
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
    {
        return Err(invalid(
            "proof statement or outcome differs from exact native session",
        ));
    }
    if session.forced_batches.is_empty() {
        let checkpoint = session
            .checkpoint
            .as_ref()
            .ok_or_else(|| invalid("session has no terminal certificate"))?;
        if !checkpoint.checkpoint.terminal
            || statement.transcript_root != checkpoint.checkpoint.transcript_root
            || outcome.terminal_tick != checkpoint.checkpoint.tick
        {
            return Err(invalid("proof differs from terminal certified transcript"));
        }
    }
    Ok(())
}
impl Execute for SettleGameSessionV1 {
    fn execute(
        self,
        _authority: &AccountId,
        st: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let mut session = get(st, &self.session_id)?;
        if !matches!(
            session.phase,
            GamePhaseV1::AwaitingProof | GamePhaseV1::ForcedCommit | GamePhaseV1::ForcedReveal
        ) {
            return Err(invalid(
                "session history selection is not sealed for terminal proof",
            ));
        }
        validate_statement(&session, &self.proof, &self.outcome)?;
        crate::execution_proofs::verify_game_proof_for_history_v1(
            &self.proof,
            &session.manifest,
            &self.outcome,
            session.checkpoint.as_ref().map(|c| &c.checkpoint),
            &session.transcript_anchors,
            &session.forced_batches,
            &session.participants,
            session.epoch,
        )
        .map_err(|e| invalid(format!("execution proof rejected: {e}")))?;
        let recipients = if self.outcome.winner_slots.is_empty() {
            (0..session.participants.len()).collect::<Vec<_>>()
        } else {
            self.outcome
                .winner_slots
                .iter()
                .map(|s| usize::from(*s))
                .collect()
        };
        let item_payouts = items::prepare_item_payouts(st, &session, &self.outcome.winner_slots)?;
        let verification_id = retain_execution_verification(st, &self.proof);
        payout(
            st,
            &mut session,
            &recipients,
            self.outcome.winner_slots.is_empty(),
        )?;
        items::apply_item_payouts(st, &mut session, item_payouts);
        session.verification_id = Some(verification_id);
        session.terminal_at_height = Some(st.block_height());
        session.phase = GamePhaseV1::Settled;
        session.result = Some(self.outcome);
        save(st, session)
    }
}
fn register_compiled_profile(st: &mut StateTransaction<'_, '_>, id: Hash) -> Result<(), Error> {
    let profile = crate::execution_proofs::compiled_execution_profile_v1(&id)
        .ok_or_else(|| invalid("profile is not a compiled immutable execution relation"))?;
    if let Some(existing) = st.world.execution_proof_profiles.get(&id) {
        if existing != &profile {
            return Err(invalid("registered execution profile is immutable"));
        }
    } else {
        st.world.execution_proof_profiles.insert(id, profile);
    }
    Ok(())
}
impl Execute for RegisterExecutionProofProfileV1 {
    fn execute(
        self,
        _authority: &AccountId,
        st: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        register_compiled_profile(st, self.profile_id)
    }
}
/// Retain one compact reference per verified statement. The envelope remains in the block.
fn retain_execution_verification(
    st: &mut StateTransaction<'_, '_>,
    proof: &ExecutionProofEnvelopeV1,
) -> Hash {
    let statement_hash =
        game_message_hash_v1(st.network_id(), "execution-statement", &proof.statement);
    let receipt_id = game_message_hash_v1(
        st.network_id(),
        "execution-proof-verification",
        &(proof.profile_id, statement_hash),
    );
    if st
        .world
        .execution_proof_verifications
        .get(&receipt_id)
        .is_none()
    {
        st.world.execution_proof_verifications.insert(
            receipt_id,
            ExecutionProofVerificationV1 {
                profile_id: proof.profile_id,
                statement_hash,
                proof_hash: Hash::new(proof.encode()),
                verified_at_height: st.block_height(),
            },
        );
    }
    receipt_id
}
impl Execute for VerifyExecutionProofV1 {
    fn execute(
        self,
        _authority: &AccountId,
        st: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        if self.proof.statement.network_id != *st.network_id() {
            return Err(invalid("execution proof belongs to another network"));
        }
        crate::execution_proofs::verify_execution_proof_v1(&self.proof)
            .map_err(|e| invalid(format!("execution proof rejected: {e}")))?;
        register_compiled_profile(st, self.proof.profile_id)?;
        retain_execution_verification(st, &self.proof);
        Ok(())
    }
}
impl Execute for ExpireGameSessionV1 {
    fn execute(
        self,
        _authority: &AccountId,
        st: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let mut session = get(st, &self.session_id)?;
        if session.phase != GamePhaseV1::Lobby
            || st.block_height() <= session.deadline_height
            || session.participants.len() >= usize::from(session.manifest.min_participants)
        {
            return Err(invalid("only expired unstartable session lobbies refund"));
        }
        let item_payouts = items::prepare_item_payouts(st, &session, &[])?;
        if !session.participants.is_empty() {
            let recipients = (0..session.participants.len()).collect::<Vec<_>>();
            payout(st, &mut session, &recipients, true)?;
        }
        items::apply_item_payouts(st, &mut session, item_payouts);
        session.phase = GamePhaseV1::Cancelled;
        session.terminal_at_height = Some(st.block_height());
        let admission = GameAdmissionBodyV1::from_session(&session);
        admission.validate().map_err(invalid)?;
        session.roster_hash =
            game_roster_hash_v1(&session.network_id, &session.session_id, &admission);
        save(st, session)
    }
}

impl Execute for ClaimGamePayoutV1 {
    fn execute(
        self,
        authority: &AccountId,
        st: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let mut session = get(st, &self.session_id)?;
        let owner = session
            .participants
            .get(usize::from(self.slot))
            .ok_or_else(|| invalid("unknown payout owner slot"))?;
        let claim_index = session
            .payout_claims
            .iter()
            .position(|claim| claim.slot == self.slot)
            .ok_or_else(|| invalid("session has no payout claim for this slot"))?;
        if !matches!(session.phase, GamePhaseV1::Settled | GamePhaseV1::Cancelled)
            || self.destination == session.custody
            || (self.destination != owner.account && *authority != owner.account)
            || self.amount.is_zero()
            || self.amount > session.payout_claims[claim_index].remaining
        {
            return Err(invalid(
                "payout claim exceeds its remaining amount or wallet authorization",
            ));
        }
        let remaining = session.payout_claims[claim_index]
            .remaining
            .checked_sub(&self.amount)
            .map_err(|_| invalid("payout claim remainder underflow"))?;
        let liability = session
            .liability
            .checked_sub(&self.amount)
            .map_err(|_| invalid("payout claim liability underflow"))?;
        super::asset::isi::execute_verified_game_movement(
            st,
            VerifiedGameMovement {
                session_id: session.session_id,
                authority: authority.clone(),
                purpose: VerifiedGameMovementPurpose::Claim { slot: self.slot },
                legs: vec![(
                    AssetId::new(session.asset_definition.clone(), session.custody.clone()),
                    AssetId::new(session.asset_definition.clone(), self.destination),
                    self.amount,
                )],
            },
        )?;
        session.payout_claims[claim_index].remaining = remaining;
        session.liability = liability;
        save(st, session)
    }
}

impl crate::prelude::ValidSingularQuery for iroha_data_model::query::game::FindGameSessionById {
    fn execute(
        &self,
        state: &impl StateReadOnly,
    ) -> Result<GameSessionRecordV1, iroha_data_model::query::error::QueryExecutionFail> {
        state
            .world()
            .game_sessions()
            .get(&self.session_id)
            .ok_or_else(|| {
                iroha_data_model::query::error::QueryExecutionFail::Find(
                    iroha_data_model::query::error::FindError::GameSession(self.session_id),
                )
            })
            .and_then(crate::smartcontracts::isi::query::own_singular_query_value)
    }
}

impl crate::prelude::ValidSingularQuery
    for iroha_data_model::query::game::FindExecutionProofVerificationById
{
    fn execute(
        &self,
        state: &impl StateReadOnly,
    ) -> Result<ExecutionProofVerificationV1, iroha_data_model::query::error::QueryExecutionFail>
    {
        state
            .world()
            .execution_proof_verifications()
            .get(&self.verification_id)
            .ok_or_else(|| {
                iroha_data_model::query::error::QueryExecutionFail::Find(
                    iroha_data_model::query::error::FindError::ExecutionProofVerification(
                        self.verification_id,
                    ),
                )
            })
            .and_then(crate::smartcontracts::isi::query::own_singular_query_value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        kura::Kura,
        query::store::LiveQueryStore,
        state::{State, World},
    };
    use iroha_crypto::{HashOf, KeyPair};
    use iroha_data_model::Registrable;
    use iroha_data_model::{block::BlockHeader, execution_proofs::RaceTrackV1};
    use iroha_model_base::domain::DomainId;

    pub(super) fn seed_session(st: &mut StateTransaction<'_, '_>, session: GameSessionRecordV1) {
        update_session_indexes(st, &session).unwrap();
        st.world.game_sessions.insert(session.session_id, session);
    }
    pub(super) fn key(slot: u8) -> KeyPair {
        KeyPair::try_from_seed(vec![slot + 1; 32], Algorithm::Ed25519).unwrap()
    }
    fn fixture() -> GameSessionRecordV1 {
        let network = NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
            Hash::prehashed([3; 32]),
        ));
        let session_id = Hash::new(b"session-protocol-adversarial-fixture");
        let asset_definition = AssetDefinitionId::derive_from_components(
            DomainId::try_new("session", "universal").unwrap(),
            "xor".parse().unwrap(),
        );
        let custody = game_custody_account_v1(&network, &session_id, &asset_definition);
        let participants = (0..2)
            .map(|slot| GameParticipantV1 {
                account: AccountId::new(key(slot + 10).public_key().clone()),
                input_key: key(slot).public_key().clone(),
                application_data: vec![slot],
                dnf_at_tick: None,
            })
            .collect::<Vec<_>>();
        let mut session = GameSessionRecordV1 {
            version: 1,
            network_id: network,
            session_id,
            manifest: GameManifestV1 {
                version: 1,
                application_id: Hash::new(b"generic-session-test-application"),
                profile_id: crate::execution_proofs::race_profile_id_v1(),
                application_parameters: RaceTrackV1::NeonTokyo.encode(),
                min_participants: 2,
                max_participants: 2,
                batch_ticks: 6,
                max_ticks: 5400,
                max_input_bytes: 12,
                max_participant_data_bytes: 1,
                access: GameAccessV1::Public,
                payout_policy: GamePayoutPolicyV1::EqualWinnersOrRefund,
            },
            profile_id: crate::execution_proofs::race_profile_id_v1(),
            manifest_hash: Hash::new(b"manifest-fixture"),
            asset_definition,
            stake: Quantity::one(),
            payout_scale: MAX_DECIMAL_SCALE,
            custody,
            liability: Quantity::from(2_u32),
            payout_claims: Vec::new(),
            item_stakes: Vec::new(),
            resources: Vec::new(),
            participants,
            roster_hash: Hash::new(b"roster"),
            phase: GamePhaseV1::Playing,
            revision: 0,
            epoch: 0,
            deadline_height: 30,
            checkpoint: None,
            pending_certificate: None,
            next_tick: 0,
            input_commitments: vec![None; 2],
            input_reveals: vec![None; 2],
            transcript_anchors: vec![],
            forced_batches: vec![],
            dispute_root: Hash::new([]),
            verification_id: None,
            terminal_at_height: None,
            result: None,
        };
        refresh_fixture_admission(&mut session);
        session
    }
    fn refresh_fixture_admission(session: &mut GameSessionRecordV1) {
        session.manifest_hash =
            game_message_hash_v1(&session.network_id, "session-manifest", &session.manifest);
        session.roster_hash = game_roster_hash_v1(
            &session.network_id,
            &session.session_id,
            &GameAdmissionBodyV1::from_session(session),
        );
    }
    fn state() -> State {
        State::new_for_testing(
            World::default(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        )
    }
    pub(super) fn payout_state(first_balance: Quantity) -> (State, GameSessionRecordV1, AccountId) {
        payout_state_with_domain(first_balance, None)
    }
    fn payout_state_with_domain(
        first_balance: Quantity,
        owning_domain: Option<DomainId>,
    ) -> (State, GameSessionRecordV1, AccountId) {
        use iroha_data_model::{
            asset::{Asset, AssetBalancePolicy, AssetDefinition},
            domain::Domain,
        };
        let mut session = fixture();
        session.participants.push(GameParticipantV1 {
            account: AccountId::new(key(12).public_key().clone()),
            input_key: key(2).public_key().clone(),
            application_data: vec![2],
            dnf_at_tick: None,
        });
        session.manifest.max_participants = 3;
        refresh_fixture_admission(&mut session);
        session.liability = Quantity::from(3_u32);
        session.phase = GamePhaseV1::AwaitingProof;
        let owner = session.participants[0].account.clone();
        let redirect = AccountId::new(key(30).public_key().clone());
        let accounts = session
            .participants
            .iter()
            .map(|participant| Account::new(participant.account.clone()).build(&owner))
            .chain(std::iter::once(
                Account::new(redirect.clone()).build(&owner),
            ))
            .collect::<Vec<_>>();
        let definition = AssetDefinition::numeric(
            session.asset_definition.clone(),
            "Game claim asset".to_owned(),
            AssetBalancePolicy::Global,
            owning_domain,
        )
        .build(&owner);
        let world = World::with_assets(
            [Domain::new(DomainId::try_new("session", "universal").unwrap()).build(&owner)],
            accounts,
            [definition],
            [Asset::new(
                AssetId::of(session.asset_definition.clone(), owner),
                first_balance,
            )],
            [],
        );
        (
            State::new_for_testing(
                world,
                Kura::blank_kura_for_testing(),
                LiveQueryStore::start_test(),
            ),
            session,
            redirect,
        )
    }
    /// Retain the original bounded claim invocation before borrowing fixture State.
    pub(super) fn payout_transaction<'block, 'state>(
        block: &'block mut crate::state::StateBlock<'state>,
    ) -> StateTransaction<'block, 'state> {
        block.transaction_for_fastpq_testing(Hash::new(b"native-game-claim-fixture"))
    }
    pub(super) fn fund_payout_fixture(
        st: &mut StateTransaction<'_, '_>,
        session: &mut GameSessionRecordV1,
    ) {
        session.network_id = *st.network_id();
        session.custody = game_custody_account_v1(
            st.network_id(),
            &session.session_id,
            &session.asset_definition,
        );
        let (id, value) = Account::new(session.custody.clone())
            .build(&session.participants[0].account)
            .into_key_value();
        st.world.accounts.insert(id, value);
        super::super::asset::isi::seed_numeric_asset_balance_for_test(
            &mut st.world,
            &AssetId::of(session.asset_definition.clone(), session.custody.clone()),
            &session.liability,
        )
        .unwrap();
        refresh_fixture_admission(session);
        seed_session(st, session.clone());
        st.tx_call_hash = Some(Hash::new(b"native-game-claim-fixture"));
    }
    fn fix_test_awards(st: &mut StateTransaction<'_, '_>, session: &mut GameSessionRecordV1) {
        // Exercise the exact post-verification payout stage independently from
        // the costly native proof tests. No unverified proof is admitted here.
        payout(st, session, &[0, 1], false).unwrap();
        session.phase = GamePhaseV1::Settled;
        session.terminal_at_height = Some(st.block_height());
        session.result = Some(GameOutcomeV1 {
            terminal_tick: 5400,
            winner_slots: vec![0, 1],
            result: Vec::new(),
        });
        save(st, session.clone()).unwrap();
    }
    fn assert_domain_cannot_consume_game_reserve(
        st: &mut StateTransaction<'_, '_>,
        session: &GameSessionRecordV1,
        domain: &DomainId,
    ) {
        let before = get(st, &session.session_id).unwrap();
        let assets = st
            .world
            .assets
            .iter()
            .map(|(id, value)| (id.clone(), value.clone()))
            .collect::<Vec<_>>();
        let definition = st
            .world
            .asset_definitions
            .get(&session.asset_definition)
            .unwrap()
            .clone();
        let domain_before = st.world.domains.get(domain).unwrap().clone();
        assert!(
            st.world
                .domain_asset_definitions
                .get(&((domain).clone(), session.asset_definition.clone()))
                .is_some(),
            "the test must exercise actual domain cascade membership"
        );
        let error = iroha_data_model::isi::Unregister::domain(domain.clone())
            .execute(&session.participants[0].account, st)
            .expect_err("domain owner cannot destroy a funded game reserve");
        assert!(
            error
                .to_string()
                .contains("outstanding native game stake or payout claim")
        );
        assert_eq!(get(st, &session.session_id).unwrap(), before);
        assert_eq!(st.world.domains.get(domain), Some(&domain_before));
        assert_eq!(
            st.world.asset_definitions.get(&session.asset_definition),
            Some(&definition)
        );
        assert_eq!(
            st.world
                .assets
                .iter()
                .map(|(id, value)| (id.clone(), value.clone()))
                .collect::<Vec<_>>(),
            assets,
            "the rejection must precede every balance mutation"
        );
        assert!(retained_game_asset(&st.world, &session.asset_definition));
    }
    #[test]
    fn domain_cascade_cannot_destroy_active_game_stakes() {
        let domain = DomainId::try_new("session", "universal").unwrap();
        let (state, mut session, _) =
            payout_state_with_domain(Quantity::one(), Some(domain.clone()));
        session.phase = GamePhaseV1::Playing;
        let mut block = state.block(header());
        let mut st = payout_transaction(&mut block);
        fund_payout_fixture(&mut st, &mut session);
        assert_domain_cannot_consume_game_reserve(&mut st, &session, &domain);
    }
    #[test]
    fn domain_cascade_cannot_destroy_closed_game_payout_claims() {
        let domain = DomainId::try_new("session", "universal").unwrap();
        let huge: Quantity = format!("1{}", "0".repeat(153)).parse().unwrap();
        let (state, mut session, relayer) = payout_state_with_domain(huge, Some(domain.clone()));
        let mut block = state.block(header());
        let mut st = payout_transaction(&mut block);
        fund_payout_fixture(&mut st, &mut session);
        fix_test_awards(&mut st, &mut session);
        let retained = get(&st, &session.session_id).unwrap();
        assert_eq!(retained.phase, GamePhaseV1::Settled);
        assert_eq!(retained.liability, Quantity::from(3_u32));
        assert!(
            retained
                .payout_claims
                .iter()
                .all(|claim| !claim.remaining.is_zero())
        );
        assert_domain_cannot_consume_game_reserve(&mut st, &session, &domain);
        // Rejected domain deletion cannot poison the surviving independent claim.
        ClaimGamePayoutV1::new(
            session.session_id,
            1,
            session.participants[1].account.clone(),
            "1.5".parse().unwrap(),
        )
        .execute(&relayer, &mut st)
        .unwrap();
        assert_eq!(
            get(&st, &session.session_id).unwrap().liability,
            "1.5".parse().unwrap()
        );
        assert_domain_cannot_consume_game_reserve(&mut st, &session, &domain);
    }
    #[test]
    fn rejected_transaction_rolls_back_prior_game_claim_balances_awards_and_events() {
        use crate::{smartcontracts::ivm::cache::IvmCache, tx::AcceptedTransaction};
        use iroha_data_model::{
            events::EventBox,
            prelude::{Json, TransactionBuilder, TransactionParameters},
            transaction::FeePaymentIntent,
        };
        use iroha_primitives::time::TimeSource;

        let huge: Quantity = format!("1{}", "0".repeat(153)).parse().unwrap();
        let (pristine, mut session, relayer) = payout_state(huge);
        let state = crate::pipeline::overlay::test_support::state_after_genesis(pristine.world);
        let next_header = BlockHeader::new(
            nonzero_ext::nonzero!(2_u64),
            state.view().latest_block_hash(),
            None,
            0,
            0,
        );
        let mut block = state.block(next_header);
        {
            // Construct an existing backed award after the proof stage. The
            // transaction below exercises real claim admission and execution;
            // this fixture is not a proof-to-funded-settlement qualification.
            let mut st = payout_transaction(&mut block);
            fund_payout_fixture(&mut st, &mut session);
            fix_test_awards(&mut st, &mut session);
            st.apply();
        }
        let before = block
            .world
            .game_sessions
            .get(&session.session_id)
            .unwrap()
            .clone();
        let balances_before = block
            .world
            .assets
            .iter()
            .map(|(id, value)| (id.clone(), value.clone()))
            .collect::<Vec<_>>();
        let wallets_before = block
            .world
            .game_account_references
            .iter()
            .map(|(account, count)| (account.clone(), *count))
            .collect::<Vec<_>>();
        // Drain fixture events once; no failed execution overlay is manually
        // reverted by this test. The component execution fixture owns rollback.
        assert!(!block.world.take_external_events().is_empty());
        let claim = ClaimGamePayoutV1::new(
            session.session_id,
            1,
            session.participants[1].account.clone(),
            "1.5".parse().unwrap(),
        );
        // Keep signing and admission on one clock so concurrent NTS tests cannot
        // reject the transaction before it reaches the game rollback path.
        let (_clock, time_source) = TimeSource::new_mock(std::time::Duration::from_secs(1));
        let accept = |instructions: Vec<ClaimGamePayoutV1>| {
            let mut metadata = Metadata::default();
            metadata.insert("expires_at_height".parse().unwrap(), Json::new(100_u64));
            metadata.insert("tx_sequence".parse().unwrap(), Json::new(1_u64));
            let signed = TransactionBuilder::new_with_time_source(
                session.network_id,
                relayer.clone(),
                &time_source,
                FeePaymentIntent::authority(Vec::new(), core::num::NonZeroU64::new(50_000_000)),
            )
            .with_metadata(metadata)
            .with_instructions(instructions)
            .sign(key(30).private_key());
            AcceptedTransaction::accept_with_time_source(
                signed,
                &session.network_id,
                std::time::Duration::from_secs(1),
                TransactionParameters::default(),
                &iroha_data_model::crypto_admission_policy::CryptoAdmissionPolicyV1::new(vec![
                    iroha_crypto::Algorithm::Ed25519,
                    iroha_crypto::Algorithm::Secp256k1,
                ])
                .expect("this stateless fixture explicitly selects Ed25519 and Secp256k1"),
                &time_source,
            )
            .expect("canonical signed claim transaction must pass stateless admission")
        };
        let mut cache = IvmCache::new();
        let result = crate::tx::execute_component_transaction_for_testing(
            &mut block,
            accept(vec![claim.clone(), claim.clone()]),
            &mut cache,
            None,
        );
        let error = result.expect_err("the second claim must exceed its now-zero entitlement");
        assert_eq!(
            error,
            iroha_data_model::transaction::error::TransactionRejectionReason::Validation(
                iroha_data_model::ValidationFail::InstructionFailed(invalid(
                    "payout claim exceeds its remaining amount or wallet authorization",
                )),
            ),
            "must reach the later claim after the first changed balances and awards"
        );
        assert_eq!(
            block.world.game_sessions.get(&session.session_id),
            Some(&before)
        );
        assert_eq!(
            block
                .world
                .assets
                .iter()
                .map(|(id, value)| (id.clone(), value.clone()))
                .collect::<Vec<_>>(),
            balances_before
        );
        assert_eq!(
            block
                .world
                .game_account_references
                .iter()
                .map(|(account, count)| (account.clone(), *count))
                .collect::<Vec<_>>(),
            wallets_before
        );
        assert!(block.world.tx_sequences.get(&relayer).is_none());
        assert!(
            block.world.take_external_events().is_empty(),
            "rejected transfer and game-award events must not escape the overlay"
        );

        // The exact same sequence succeeds with only the first claim. This
        // proves the failed transaction neither consumed the award nor merely
        // failed at an unrelated admission gate before reaching the movement.
        let retry = crate::tx::execute_component_transaction_for_testing(
            &mut block,
            accept(vec![claim]),
            &mut cache,
            None,
        );
        retry.expect("the rolled-back award must remain independently payable");
        let paid = block.world.game_sessions.get(&session.session_id).unwrap();
        assert_eq!(paid.liability, "1.5".parse().unwrap());
        assert!(paid.payout_claims[1].remaining.is_zero());
        assert_eq!(paid.payout_claims[1].amount, before.payout_claims[1].amount);
        assert_eq!(block.world.tx_sequences.get(&relayer), Some(&1));
        for account in [&session.custody, &session.participants[1].account] {
            assert_eq!(
                block
                    .world
                    .assets
                    .get(&AssetId::of(
                        session.asset_definition.clone(),
                        account.clone()
                    ))
                    .unwrap()
                    .as_ref(),
                &"1.5".parse::<Quantity>().unwrap()
            );
        }
        assert!(
            block
                .world
                .take_external_events()
                .iter()
                .any(|event| matches!(event, EventBox::Data(_))),
            "the successful claim must actually publish its data events"
        );
    }
    #[test]
    fn destination_overflow_fixes_backed_awards_and_allows_independent_partial_claims() {
        let huge: Quantity = format!("1{}", "0".repeat(153)).parse().unwrap();
        let prize: Quantity = "1.5".parse().unwrap();
        assert!(
            huge.checked_add(&prize).is_err(),
            "the checked 512-bit overflow must be real"
        );
        let (state, mut session, redirect) = payout_state(huge.clone());
        let mut block = state.block(header());
        let mut st = payout_transaction(&mut block);
        fund_payout_fixture(&mut st, &mut session);
        fix_test_awards(&mut st, &mut session);
        let settled = get(&st, &session.session_id).unwrap();
        assert_eq!(settled.phase, GamePhaseV1::Settled);
        assert_eq!(settled.liability, Quantity::from(3_u32));
        assert_eq!(
            settled
                .payout_claims
                .iter()
                .map(|claim| claim.remaining.clone())
                .collect::<Vec<_>>(),
            vec![prize.clone(); 2]
        );
        let first = session.participants[0].account.clone();
        let second = session.participants[1].account.clone();
        let before = settled.clone();
        assert!(
            ClaimGamePayoutV1::new(session.session_id, 0, redirect.clone(), prize.clone())
                .execute(&second, &mut st)
                .is_err()
        );
        assert_eq!(get(&st, &session.session_id).unwrap(), before);
        // Anyone can pay another winner's original wallet even while the first
        // winner's existing balance cannot represent its fractional prize.
        ClaimGamePayoutV1::new(session.session_id, 1, second.clone(), prize.clone())
            .execute(&redirect, &mut st)
            .unwrap();
        assert_eq!(get(&st, &session.session_id).unwrap().liability, prize);
        ClaimGamePayoutV1::new(
            session.session_id,
            0,
            redirect.clone(),
            "0.5".parse().unwrap(),
        )
        .execute(&first, &mut st)
        .unwrap();
        assert_eq!(
            get(&st, &session.session_id).unwrap().payout_claims[0].remaining,
            Quantity::one()
        );
        ClaimGamePayoutV1::new(session.session_id, 0, redirect.clone(), Quantity::one())
            .execute(&first, &mut st)
            .unwrap();
        let paid = get(&st, &session.session_id).unwrap();
        assert!(paid.liability.is_zero());
        assert!(
            paid.payout_claims
                .iter()
                .all(|claim| claim.remaining.is_zero() && claim.amount == "1.5".parse().unwrap())
        );
        assert!(
            ClaimGamePayoutV1::new(session.session_id, 0, redirect.clone(), Quantity::one())
                .execute(&first, &mut st)
                .is_err()
        );
        assert_eq!(
            st.world
                .assets
                .get(&AssetId::of(
                    session.asset_definition.clone(),
                    first.clone()
                ))
                .unwrap()
                .as_ref(),
            &huge
        );
        for wallet in [&second, &redirect] {
            assert_eq!(
                st.world
                    .assets
                    .get(&AssetId::of(
                        session.asset_definition.clone(),
                        wallet.clone()
                    ))
                    .unwrap()
                    .as_ref(),
                &"1.5".parse::<Quantity>().unwrap()
            );
        }
        assert!(!retained_game_account(&st.world, &first));
        assert!(!retained_game_asset(&st.world, &session.asset_definition));
        assert!(retained_game_account(&st.world, &session.custody));
    }
    #[test]
    fn issuer_freezes_defer_payment_without_vetoing_awards_or_releasing_reserves() {
        use iroha_data_model::{
            asset::AssetTransferAvailability::{Disabled, Enabled},
            isi::asset_transfer_control::{
                SetAssetTransferAvailability, SetAssetTransferBlacklist,
            },
        };
        let (state, mut session, relayer) = payout_state(Quantity::one());
        let mut block = state.block(header());
        let mut st = payout_transaction(&mut block);
        fund_payout_fixture(&mut st, &mut session);
        let issuer = session.participants[0].account.clone();
        let second = session.participants[1].account.clone();
        SetAssetTransferAvailability::new(
            session.custody.clone(),
            session.asset_definition.clone(),
            0,
            Enabled,
            Disabled,
            None,
        )
        .execute(&issuer, &mut st)
        .unwrap();
        SetAssetTransferBlacklist::new(
            session.custody.clone(),
            session.asset_definition.clone(),
            true,
        )
        .execute(&issuer, &mut st)
        .unwrap();
        SetAssetTransferAvailability::new(
            second.clone(),
            session.asset_definition.clone(),
            0,
            Disabled,
            Enabled,
            None,
        )
        .execute(&issuer, &mut st)
        .unwrap();
        fix_test_awards(&mut st, &mut session);
        let owed = get(&st, &session.session_id).unwrap();
        assert_eq!(owed.liability, Quantity::from(3_u32));
        assert!(retained_game_account(&st.world, &issuer));
        assert!(retained_game_asset(&st.world, &session.asset_definition));
        SetAssetTransferAvailability::new(
            session.custody.clone(),
            session.asset_definition.clone(),
            1,
            Enabled,
            Enabled,
            None,
        )
        .execute(&issuer, &mut st)
        .unwrap();
        assert!(
            ClaimGamePayoutV1::new(
                session.session_id,
                0,
                issuer.clone(),
                "1.5".parse().unwrap()
            )
            .execute(&relayer, &mut st)
            .is_err(),
            "custody blacklist still applies"
        );
        assert_eq!(get(&st, &session.session_id).unwrap(), owed);
        SetAssetTransferBlacklist::new(
            session.custody.clone(),
            session.asset_definition.clone(),
            false,
        )
        .execute(&issuer, &mut st)
        .unwrap();
        ClaimGamePayoutV1::new(
            session.session_id,
            0,
            issuer.clone(),
            "1.5".parse().unwrap(),
        )
        .execute(&relayer, &mut st)
        .unwrap();
        let remaining = get(&st, &session.session_id).unwrap();
        assert_eq!(remaining.liability, "1.5".parse().unwrap());
        assert!(
            ClaimGamePayoutV1::new(
                session.session_id,
                1,
                second.clone(),
                "1.5".parse().unwrap()
            )
            .execute(&relayer, &mut st)
            .is_err(),
            "recipient incoming restriction still applies"
        );
        assert_eq!(get(&st, &session.session_id).unwrap(), remaining);
        SetAssetTransferAvailability::new(
            second.clone(),
            session.asset_definition.clone(),
            1,
            Enabled,
            Enabled,
            None,
        )
        .execute(&issuer, &mut st)
        .unwrap();
        ClaimGamePayoutV1::new(session.session_id, 1, second, "1.5".parse().unwrap())
            .execute(&relayer, &mut st)
            .unwrap();
        assert!(get(&st, &session.session_id).unwrap().liability.is_zero());
    }
    pub(super) fn header() -> BlockHeader {
        BlockHeader::new(nonzero_ext::nonzero!(1_u64), None, None, 1_000, 0)
    }
    fn signed_checkpoint(
        session: &GameSessionRecordV1,
        tick: u32,
        terminal: bool,
    ) -> SignedGameCheckpointV1 {
        let checkpoint = GameCheckpointV1 {
            session_id: session.session_id,
            epoch: session.epoch,
            tick,
            transcript_root: Hash::new(b"inputs"),
            state_root: Hash::new(b"state"),
            terminal,
        };
        let digest = game_message_hash_v1(&session.network_id, "checkpoint", &checkpoint);
        let signatures = active_slots(session)
            .into_iter()
            .map(|slot| GameSlotSignatureV1 {
                slot: u8::try_from(slot).expect("fixture value fits u8"),
                signature: Signature::new(
                    key(u8::try_from(slot).expect("fixture value fits u8")).private_key(),
                    digest.as_ref(),
                ),
            })
            .collect();
        SignedGameCheckpointV1 {
            checkpoint,
            signatures,
        }
    }
    #[test]
    fn joint_checkpoint_rejects_missing_duplicate_wrong_domain_and_stale_signature() {
        let mut session = fixture();
        let valid = signed_checkpoint(&session, 6, false);
        validate_checkpoint(&session, &valid).unwrap();
        let mut missing = valid.clone();
        missing.signatures.pop();
        assert!(validate_checkpoint(&session, &missing).is_err());
        let mut duplicate = valid.clone();
        duplicate.signatures[1] = duplicate.signatures[0].clone();
        assert!(validate_checkpoint(&session, &duplicate).is_err());
        let mut wrong = valid.clone();
        wrong.signatures[0].signature = Signature::new(
            key(0).private_key(),
            game_message_hash_v1(&session.network_id, "challenge", &wrong.checkpoint).as_ref(),
        );
        assert!(validate_checkpoint(&session, &wrong).is_err());
        session.epoch = 1;
        assert!(validate_checkpoint(&session, &valid).is_err());
        session.epoch = 0;
        session.next_tick = 12;
        assert!(validate_checkpoint(&session, &valid).is_err());
    }
    #[test]
    fn certified_input_frontier_cannot_be_discarded_after_reveal() {
        let state = state();
        let mut block = state.block(header());
        let mut st = block.transaction();
        let mut session = fixture();
        let checkpoint = signed_checkpoint(&session, 0, false);
        let mut frontier = GameCommitmentSetV1 {
            session_id: session.session_id,
            epoch: 0,
            start_tick: 0,
            parent_transcript_root: checkpoint.checkpoint.transcript_root,
            commitments: vec![Hash::new(b"a"), Hash::new(b"b")],
            signatures: vec![],
        };
        let digest = game_commitment_set_hash_v1(&session.network_id, &frontier);
        frontier.signatures = (0..2)
            .map(|slot| GameSlotSignatureV1 {
                slot,
                signature: Signature::new(key(slot).private_key(), digest.as_ref()),
            })
            .collect();
        session.pending_certificate = Some(frontier.clone());
        session.checkpoint = Some(checkpoint.clone());
        seed_session(&mut st, session.clone());
        let authority = AccountId::new(key(20).public_key().clone());
        assert!(
            CommitGameCheckpointV1 {
                session_id: session.session_id,
                checkpoint: checkpoint.clone(),
                frontier: None
            }
            .execute(&authority, &mut st)
            .is_err()
        );
        assert_eq!(
            get(&st, &session.session_id).unwrap().pending_certificate,
            Some(frontier.clone())
        );
        CommitGameCheckpointV1 {
            session_id: session.session_id,
            checkpoint,
            frontier: Some(frontier),
        }
        .execute(&authority, &mut st)
        .unwrap();
    }
    #[test]
    fn absent_peer_is_removed_only_by_expired_consensus_deadline_and_replay_is_deterministic() {
        let mut roots = Vec::new();
        for _ in 0..4 {
            let state = state();
            let mut block = state.block(header());
            let mut st = block.transaction();
            let mut session = fixture();
            session.phase = GamePhaseV1::ForcedReveal;
            session.deadline_height = 0;
            session.input_reveals[0] = Some([1_u8, 0].repeat(6));
            let authority = AccountId::new(key(20).public_key().clone());
            seed_session(&mut st, session.clone());
            AdvanceGameDeadlineV1 {
                session_id: session.session_id,
            }
            .execute(&authority, &mut st)
            .unwrap();
            let resolved = get(&st, &session.session_id).unwrap();
            assert_eq!(resolved.participants[0].dnf_at_tick, None);
            assert_eq!(resolved.participants[1].dnf_at_tick, Some(0));
            assert_eq!(resolved.next_tick, 6);
            assert_eq!(resolved.epoch, 1);
            assert_eq!(resolved.phase, GamePhaseV1::AwaitingProof);
            assert_eq!(resolved.forced_batches[0].dnf_slots, vec![1]);
            assert_eq!(
                resolved.forced_batches[0].inputs,
                vec![[1_u8, 0].repeat(6), vec![]]
            );
            assert!(
                AdvanceGameDeadlineV1 {
                    session_id: session.session_id
                }
                .execute(&authority, &mut st)
                .is_err()
            );
            roots.push(resolved.encode());
        }
        assert!(
            roots.windows(2).all(|pair| pair[0] == pair[1]),
            "four independent state replicas must select identical history"
        );
    }
    #[test]
    fn gameplay_key_cannot_change_wallet_or_custody_and_closed_custody_remains_reserved() {
        let state = state();
        let mut block = state.block(header());
        let mut st = block.transaction();
        let session = fixture();
        seed_session(&mut st, session.clone());
        assert!(retained_game_account(
            &st.world,
            &session.participants[0].account
        ));
        assert!(retained_game_asset(&st.world, &session.asset_definition));
        assert!(super::super::escrow::is_protocol_escrow_custody_account(
            &st,
            &session.custody
        ));
        let mut closed = session.clone();
        closed.liability = Quantity::zero();
        closed.phase = GamePhaseV1::Settled;
        seed_session(&mut st, closed);
        assert!(!retained_game_account(
            &st.world,
            &session.participants[0].account
        ));
        assert!(retained_game_account(&st.world, &session.custody));
        assert!(!retained_game_asset(&st.world, &session.asset_definition));
        assert_ne!(
            session.custody,
            game_custody_account_v1(
                &session.network_id,
                &Hash::new(b"other-session"),
                &session.asset_definition
            )
        );
    }
    #[test]
    fn challenge_is_relayable_once_but_cannot_extend_its_deadline() {
        let state = state();
        let mut block = state.block(header());
        let mut st = block.transaction();
        let session = fixture();
        seed_session(&mut st, session.clone());
        let hash = game_message_hash_v1(
            &session.network_id,
            "challenge",
            &(session.session_id, session.epoch, 0_u8),
        );
        let challenge = ChallengeGameSessionV1 {
            session_id: session.session_id,
            epoch: 0,
            slot: 0,
            signature: Signature::new(key(0).private_key(), hash.as_ref()),
        };
        let relayer = AccountId::new(key(20).public_key().clone());
        challenge.clone().execute(&relayer, &mut st).unwrap();
        let first = get(&st, &session.session_id).unwrap();
        assert_eq!(first.phase, GamePhaseV1::SelectingCheckpoint);
        assert!(challenge.execute(&relayer, &mut st).is_err());
        assert_eq!(get(&st, &session.session_id).unwrap(), first);
    }
    #[test]
    fn old_checkpoint_cannot_restart_a_forced_deadline_cycle() {
        let state = state();
        let mut block = state.block(header());
        let mut st = block.transaction();
        let mut session = fixture();
        let checkpoint = signed_checkpoint(&session, 0, false);
        session.phase = GamePhaseV1::ForcedCommit;
        session.checkpoint = Some(checkpoint.clone());
        seed_session(&mut st, session.clone());
        let relayer = AccountId::new(key(20).public_key().clone());
        assert!(
            CommitGameCheckpointV1 {
                session_id: session.session_id,
                checkpoint,
                frontier: None
            }
            .execute(&relayer, &mut st)
            .is_err()
        );
        assert_eq!(get(&st, &session.session_id).unwrap(), session);
    }
    #[test]
    fn join_rejects_each_unapproved_entry_term_before_any_mutation() {
        let (state, mut session, entrant) = payout_state(Quantity::from(10_u32));
        session.participants.truncate(1);
        session.liability = session.stake.clone();
        session.phase = GamePhaseV1::Lobby;
        let mut block = state.block(header());
        let mut st = payout_transaction(&mut block);
        fund_payout_fixture(&mut st, &mut session);
        st.world.take_external_events();
        let balances = st
            .world
            .assets
            .iter()
            .map(|(id, value)| (id.clone(), value.clone()))
            .collect::<Vec<_>>();
        let wallets = st
            .world
            .game_account_references
            .iter()
            .map(|(id, count)| (id.clone(), *count))
            .collect::<Vec<_>>();
        let assets = st
            .world
            .game_asset_references
            .iter()
            .map(|(id, count)| (id.clone(), *count))
            .collect::<Vec<_>>();
        let custody = st
            .world
            .game_custody_by_account
            .iter()
            .map(|(id, value)| (id.clone(), *value))
            .collect::<Vec<_>>();
        for wrong_term in 0..3 {
            let mut join = JoinGameSessionV1 {
                session_id: session.session_id,
                input_key: key(30).public_key().clone(),
                application_data: vec![0],
                resources: Vec::new(),
                invitation: None,
                expected_manifest_hash: session.manifest_hash,
                expected_asset_definition: session.asset_definition.clone(),
                expected_stake: session.stake.clone(),
            };
            match wrong_term {
                0 => join.expected_manifest_hash = Hash::new(b"endpoint-substituted-manifest"),
                1 => {
                    join.expected_asset_definition = AssetDefinitionId::derive_from_components(
                        DomainId::try_new("session", "universal").unwrap(),
                        "different_asset".parse().unwrap(),
                    )
                }
                2 => join.expected_stake = Quantity::zero(),
                _ => unreachable!(),
            }
            let error = join.execute(&entrant, &mut st).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("wallet-approved game entry terms"),
                "{error}"
            );
            assert_eq!(get(&st, &session.session_id).unwrap(), session);
            assert_eq!(
                st.world
                    .assets
                    .iter()
                    .map(|(id, value)| (id.clone(), value.clone()))
                    .collect::<Vec<_>>(),
                balances
            );
            assert_eq!(
                st.world
                    .game_account_references
                    .iter()
                    .map(|(id, count)| (id.clone(), *count))
                    .collect::<Vec<_>>(),
                wallets
            );
            assert_eq!(
                st.world
                    .game_asset_references
                    .iter()
                    .map(|(id, count)| (id.clone(), *count))
                    .collect::<Vec<_>>(),
                assets
            );
            assert_eq!(
                st.world
                    .game_custody_by_account
                    .iter()
                    .map(|(id, value)| (id.clone(), *value))
                    .collect::<Vec<_>>(),
                custody
            );
            assert!(st.world.take_external_events().is_empty());
        }
    }
    #[test]
    fn unqualified_proof_profile_never_debits_a_wallet() {
        if crate::execution_proofs::compiled_race_profile_v1().qualified {
            return;
        }
        let mut session = fixture();
        session.phase = GamePhaseV1::Lobby;
        let state = State::new_for_testing(
            index_world_with_policy(
                &session,
                iroha_data_model::asset::AssetBalancePolicy::Global,
            ),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let mut block = state.block(header());
        let mut st = block.transaction();
        seed_session(&mut st, session.clone());
        let authority = AccountId::new(key(20).public_key().clone());
        let error = JoinGameSessionV1 {
            session_id: session.session_id,
            input_key: key(21).public_key().clone(),
            application_data: vec![0],
            resources: Vec::new(),
            invitation: None,
            expected_manifest_hash: session.manifest_hash,
            expected_asset_definition: session.asset_definition.clone(),
            expected_stake: session.stake.clone(),
        }
        .execute(&authority, &mut st)
        .unwrap_err();
        assert!(error.to_string().contains("funding disabled"), "{error:?}");
        assert_eq!(get(&st, &session.session_id).unwrap(), session);
    }
    #[test]
    fn invitation_is_bound_to_exact_wallet_input_key_and_session() {
        let mut session = fixture();
        session.manifest.access = GameAccessV1::Invite(key(30).public_key().clone());
        let wallet = session.participants[0].account.clone();
        let input = key(0).public_key().clone();
        let digest = game_invitation_hash_v1(
            &session.network_id,
            session.session_id,
            &wallet,
            &input,
            &[0],
        );
        let signature = Signature::new(key(30).private_key(), digest.as_ref());
        validate_invitation(&session, &wallet, &input, &[0], Some(&signature)).unwrap();
        assert!(validate_invitation(&session, &wallet, &input, &[0], None).is_err());
        assert!(
            validate_invitation(
                &session,
                &session.participants[1].account,
                &input,
                &[0],
                Some(&signature)
            )
            .is_err()
        );
        assert!(
            validate_invitation(
                &session,
                &wallet,
                key(1).public_key(),
                &[0],
                Some(&signature)
            )
            .is_err()
        );
        session.session_id = Hash::new(b"another-invite-session");
        assert!(validate_invitation(&session, &wallet, &input, &[0], Some(&signature)).is_err());
    }
    #[test]
    fn removed_participant_cannot_be_excluded_from_optional_checkpoint_authority() {
        let mut session = fixture();
        session.participants[1].dnf_at_tick = Some(0);
        session.epoch = 1;
        session.next_tick = 6;
        let reduced = signed_checkpoint(&session, 6, false);
        assert_eq!(reduced.signatures.len(), 1);
        assert!(
            validate_checkpoint(&session, &reduced).is_err(),
            "active survivor must not pin an unprovable checkpoint over a departed winner"
        );
        let mut full = reduced;
        let digest = game_message_hash_v1(&session.network_id, "checkpoint", &full.checkpoint);
        full.signatures.push(GameSlotSignatureV1 {
            slot: 1,
            signature: Signature::new(key(1).private_key(), digest.as_ref()),
        });
        validate_checkpoint(&session, &full).unwrap();
    }
    #[test]
    fn authority_shrink_retains_authenticated_transcript_prefix() {
        let state = state();
        let mut block = state.block(header());
        let mut st = block.transaction();
        let mut session = fixture();
        session.phase = GamePhaseV1::ForcedReveal;
        session.deadline_height = 0;
        let checkpoint = signed_checkpoint(&session, 0, false);
        session.checkpoint = Some(checkpoint.clone());
        session.input_reveals[0] = Some([1_u8, 0].repeat(6));
        seed_session(&mut st, session.clone());
        let relayer = AccountId::new(key(20).public_key().clone());
        AdvanceGameDeadlineV1 {
            session_id: session.session_id,
        }
        .execute(&relayer, &mut st)
        .unwrap();
        let resolved = get(&st, &session.session_id).unwrap();
        assert_eq!(
            resolved.transcript_anchors,
            vec![GameTranscriptAnchorV1 {
                tick: 0,
                transcript_root: checkpoint.checkpoint.transcript_root
            }]
        );
        let mut rewritten = resolved.clone();
        rewritten.transcript_anchors.clear();
        assert_ne!(
            game_dispute_root_v1(&resolved),
            game_dispute_root_v1(&rewritten)
        );
    }
    #[test]
    fn arbitrary_uploaded_profile_identifiers_cannot_register() {
        let state = state();
        let mut block = state.block(header());
        let mut st = block.transaction();
        let relayer = AccountId::new(key(20).public_key().clone());
        let profile_id = Hash::new(b"uncompiled-execution-profile");
        assert!(
            RegisterExecutionProofProfileV1 { profile_id }
                .execute(&relayer, &mut st)
                .is_err()
        );
        assert!(st.world.execution_proof_profiles.get(&profile_id).is_none());
    }
    #[test]
    fn expired_lobby_refunds_exact_stake_once_and_closed_custody_cannot_be_spent() {
        use iroha_data_model::{
            asset::{Asset, AssetBalancePolicy, AssetDefinition},
            domain::Domain,
            isi::{Burn, Transfer, escrow::OpenAssetEscrow},
        };
        let mut session = fixture();
        session.participants.truncate(1);
        session.liability = Quantity::one();
        session.phase = GamePhaseV1::Lobby;
        session.deadline_height = 0;
        let wallet = session.participants[0].account.clone();
        let definition = AssetDefinition::numeric(
            session.asset_definition.clone(),
            "Game stake".to_owned(),
            AssetBalancePolicy::Global,
            None,
        )
        .build(&wallet);
        let world = World::with_assets(
            [Domain::new(DomainId::try_new("session", "universal").unwrap()).build(&wallet)],
            [Account::new(wallet.clone()).build(&wallet)],
            [definition],
            [Asset::new(
                AssetId::of(session.asset_definition.clone(), wallet.clone()),
                Quantity::from(5_u32),
            )],
            [],
        );
        let state = State::new_for_testing(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let mut block = state.block(header());
        let mut st = block.transaction_for_fastpq_testing(Hash::new(b"native-game-refund-call"));
        session.network_id = *st.network_id();
        session.custody = game_custody_account_v1(
            &session.network_id,
            &session.session_id,
            &session.asset_definition,
        );
        let (id, value) = Account::new(session.custody.clone())
            .build(&wallet)
            .into_key_value();
        st.world.accounts.insert(id, value);
        let custody_asset = AssetId::of(session.asset_definition.clone(), session.custody.clone());
        super::super::asset::isi::seed_numeric_asset_balance_for_test(
            &mut st.world,
            &custody_asset,
            &Quantity::one(),
        )
        .unwrap();
        seed_session(&mut st, session.clone());
        st.tx_call_hash = Some(Hash::new(b"native-game-refund-call"));
        ExpireGameSessionV1 {
            session_id: session.session_id,
        }
        .execute(&wallet, &mut st)
        .unwrap();
        let wallet_asset = AssetId::of(session.asset_definition.clone(), wallet.clone());
        assert_eq!(
            st.world.assets.get(&wallet_asset).unwrap().as_ref(),
            &Quantity::from(6_u32)
        );
        assert!(
            st.world
                .assets
                .get(&custody_asset)
                .is_none_or(|amount| amount.as_ref().is_zero())
        );
        assert_eq!(
            get(&st, &session.session_id).unwrap().phase,
            GamePhaseV1::Cancelled
        );
        assert!(
            ExpireGameSessionV1 {
                session_id: session.session_id
            }
            .execute(&wallet, &mut st)
            .is_err()
        );
        // Corrupt the fixture directly: every ordinary custody credit is now rejected.
        let (id, value) = Asset::new(custody_asset.clone(), Quantity::one()).into_key_value();
        st.world.assets.insert(id, value);
        let error = Transfer::asset_quantity(custody_asset.clone(), Quantity::one(), wallet)
            .execute(&session.custody, &mut st)
            .unwrap_err();
        assert!(error.to_string().contains("custody"), "{error}");
        let error = Burn::asset_quantity(Quantity::one(), custody_asset.clone())
            .execute(&session.custody, &mut st)
            .unwrap_err();
        assert!(error.to_string().contains("custody"), "{error}");
        let escrow_id = iroha_data_model::escrow::EscrowId::new(Hash::new(b"game-custody-bypass"));
        let error =
            OpenAssetEscrow::new(escrow_id, session.asset_definition.clone(), Quantity::one())
                .execute(&session.custody, &mut st)
                .unwrap_err();
        assert!(error.to_string().contains("custody"), "{error}");
        assert!(st.world.asset_escrows.get(&escrow_id).is_none());
        assert_eq!(
            st.world.assets.get(&custody_asset).unwrap().as_ref(),
            &Quantity::one(),
            "every rejected debit must retain the entire unexpected residual balance"
        );
    }
    #[test]
    fn free_sessions_register_manifest_join_and_start_with_adapter_defined_genesis() {
        use iroha_data_model::domain::Domain;
        let fixture = fixture();
        let first = fixture.participants[0].account.clone();
        let second = fixture.participants[1].account.clone();
        let world = World::with_assets(
            [Domain::new(DomainId::try_new("session", "universal").unwrap()).build(&first)],
            [
                Account::new(first.clone()).build(&first),
                Account::new(second.clone()).build(&second),
            ],
            [],
            [],
            [],
        );
        let state = State::new_for_testing(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let mut block = state.block(header());
        let mut st = block.transaction();
        let mut manifest = fixture.manifest.clone();
        manifest.payout_policy = GamePayoutPolicyV1::NoPayout;
        OpenGameSessionV1 {
            session_id: fixture.session_id,
            manifest: manifest.clone(),
            asset_definition: fixture.asset_definition.clone(),
            stake: Quantity::zero(),
            join_deadline_height: 10,
        }
        .execute(&first, &mut st)
        .unwrap();
        let opened = get(&st, &fixture.session_id).unwrap();
        for forbidden_authority in [
            opened.custody.clone(),
            AccountId::new(key(7).public_key().clone()),
        ] {
            assert!(
                JoinGameSessionV1 {
                    session_id: fixture.session_id,
                    input_key: key(7).public_key().clone(),
                    application_data: vec![0],
                    resources: Vec::new(),
                    invitation: None,
                    expected_manifest_hash: opened.manifest_hash,
                    expected_asset_definition: opened.asset_definition.clone(),
                    expected_stake: opened.stake.clone(),
                }
                .execute(&forbidden_authority, &mut st)
                .is_err(),
                "free enrollment must reject custody and absent account authorities"
            );
            assert_eq!(get(&st, &fixture.session_id).unwrap(), opened);
        }
        JoinGameSessionV1 {
            session_id: fixture.session_id,
            input_key: key(0).public_key().clone(),
            application_data: vec![0],
            resources: Vec::new(),
            invitation: None,
            expected_manifest_hash: opened.manifest_hash,
            expected_asset_definition: opened.asset_definition.clone(),
            expected_stake: opened.stake.clone(),
        }
        .execute(&first, &mut st)
        .unwrap();
        assert!(
            JoinGameSessionV1 {
                session_id: fixture.session_id,
                input_key: key(0).public_key().clone(),
                application_data: vec![0],
                resources: Vec::new(),
                invitation: None,
                expected_manifest_hash: opened.manifest_hash,
                expected_asset_definition: opened.asset_definition.clone(),
                expected_stake: opened.stake.clone(),
            }
            .execute(&first, &mut st)
            .is_err()
        );
        JoinGameSessionV1 {
            session_id: fixture.session_id,
            input_key: key(1).public_key().clone(),
            application_data: vec![1],
            resources: Vec::new(),
            invitation: None,
            expected_manifest_hash: opened.manifest_hash,
            expected_asset_definition: opened.asset_definition.clone(),
            expected_stake: opened.stake.clone(),
        }
        .execute(&second, &mut st)
        .unwrap();
        StartGameSessionV1 {
            session_id: fixture.session_id,
        }
        .execute(&first, &mut st)
        .unwrap();
        let session = get(&st, &fixture.session_id).unwrap();
        assert_eq!(session.phase, GamePhaseV1::Playing);
        assert!(session.liability.is_zero());
        assert_eq!(session.participants.len(), 2);
        assert_eq!(
            session.manifest_hash,
            game_message_hash_v1(st.network_id(), "session-manifest", &manifest)
        );
        let checkpoint = session.checkpoint.unwrap();
        assert_eq!(checkpoint.checkpoint.tick, 0);
        assert!(checkpoint.signatures.is_empty());
        assert_eq!(
            checkpoint.checkpoint.state_root,
            crate::execution_proofs::initial_game_state_root_v1(st.network_id(), &manifest, 2)
                .unwrap()
        );
        assert_eq!(
            checkpoint.checkpoint.transcript_root,
            game_message_hash_v1(
                st.network_id(),
                "input-transcript",
                &GameTranscriptV1 {
                    batches: vec![],
                    dnf_events: vec![]
                }
            )
        );
        assert!(
            st.world
                .execution_proof_profiles
                .get(&manifest.profile_id)
                .is_some()
        );
        assert!(
            st.world.assets.iter().next().is_none(),
            "free session never mints or debits a stake balance"
        );
    }
    #[test]
    fn opaque_input_reveals_require_adapter_validity_and_exact_retained_commitment() {
        let state = state();
        let mut block = state.block(header());
        let mut st = block.transaction();
        let mut session = fixture();
        session.phase = GamePhaseV1::ForcedReveal;
        let reveal = GameInputRevealV1 {
            session_id: session.session_id,
            epoch: 0,
            start_tick: 0,
            slot: 0,
            payload: [1_u8, 0].repeat(6),
            salt: Hash::new(b"input-salt"),
        };
        session.input_commitments[0] = Some(game_input_commitment_v1(&session.network_id, &reveal));
        seed_session(&mut st, session.clone());
        let relayer = AccountId::new(key(20).public_key().clone());
        let mut substituted = reveal.clone();
        substituted.payload[0] = 2;
        assert!(
            RevealGameInputsV1 {
                reveal: substituted
            }
            .execute(&relayer, &mut st)
            .is_err()
        );
        let mut malformed = reveal.clone();
        malformed.payload[0] = 255;
        assert!(
            RevealGameInputsV1 { reveal: malformed }
                .execute(&relayer, &mut st)
                .is_err()
        );
        assert_eq!(get(&st, &session.session_id).unwrap(), session);
        RevealGameInputsV1 {
            reveal: reveal.clone(),
        }
        .execute(&relayer, &mut st)
        .unwrap();
        assert_eq!(
            get(&st, &session.session_id).unwrap().input_reveals[0],
            Some(reveal.payload)
        );
    }
    #[test]
    fn exact_refunds_preserve_unrestricted_twenty_eight_digit_stakes() {
        let stake: Quantity = "0.1234567890123456789012345678".parse().unwrap();
        let pool = stake
            .checked_add(&stake)
            .unwrap()
            .checked_add(&stake)
            .unwrap();
        let amounts = refund_amounts(&stake, &pool, 3).unwrap();
        assert_eq!(amounts, vec![stake.clone(); 3]);
        assert_eq!(
            amounts
                .iter()
                .try_fold(Quantity::zero(), |sum, value| sum.checked_add(value))
                .unwrap(),
            pool
        );
        assert!(refund_amounts(&stake, &pool, 2).is_err());
        assert!(refund_amounts(&stake, &pool, 4).is_err());
    }
    #[test]
    fn tied_payouts_conserve_pool_and_assign_one_extra_unit_per_ordered_winner() {
        let pool: Quantity = "1".parse().unwrap();
        let amounts = winner_amounts(&pool, 3, 2).unwrap();
        assert_eq!(
            amounts,
            vec![
                "0.34".parse().unwrap(),
                "0.33".parse().unwrap(),
                "0.33".parse().unwrap()
            ]
        );
        let fine = winner_amounts(&pool, 3, MAX_DECIMAL_SCALE).unwrap();
        assert_eq!(fine[0], "0.3333333333333333333333333334".parse().unwrap());
        assert_eq!(fine[2], "0.3333333333333333333333333333".parse().unwrap());
        assert_eq!(
            fine.iter()
                .try_fold(Quantity::zero(), |sum, value| sum.checked_add(value))
                .unwrap(),
            pool
        );
        assert!(winner_amounts(&pool, 0, 2).is_err());
        assert!(winner_amounts(&pool, 3, MAX_DECIMAL_SCALE + 1).is_err());
        assert!(winner_amounts(&"0.001".parse().unwrap(), 3, 2).is_err());
        for count in [3, 7] {
            for scale in [0, 2, MAX_DECIMAL_SCALE] {
                let quantum = Quantity::try_from_numeric(Numeric::new(1_u32, scale)).unwrap();
                for pool in [
                    Quantity::one(),
                    Quantity::from(5_u32),
                    Quantity::from(22_u32),
                ] {
                    let amounts = winner_amounts(&pool, count, scale).unwrap();
                    assert_eq!(
                        amounts
                            .iter()
                            .try_fold(Quantity::zero(), |sum, amount| sum.checked_add(amount))
                            .unwrap(),
                        pool,
                    );
                    let gap = amounts
                        .iter()
                        .max()
                        .unwrap()
                        .checked_sub(amounts.iter().min().unwrap())
                        .unwrap();
                    assert!(
                        gap <= quantum,
                        "every tied prize differs by at most one frozen unit"
                    );
                    assert!(
                        amounts.windows(2).all(|pair| pair[0] >= pair[1]),
                        "residual units follow permanent slot order"
                    );
                }
            }
        }
        assert_eq!(
            winner_amounts(&"1".parse().unwrap(), 7, 2).unwrap(),
            vec![
                "0.15".parse().unwrap(),
                "0.15".parse().unwrap(),
                "0.14".parse().unwrap(),
                "0.14".parse().unwrap(),
                "0.14".parse().unwrap(),
                "0.14".parse().unwrap(),
                "0.14".parse().unwrap()
            ]
        );
    }
    #[test]
    fn custody_admission_rejects_stakes_with_unrepresentable_fractional_winnings() {
        let stake: Quantity = format!("1{}", "0".repeat(150)).parse().unwrap();
        assert!(validate_payout_capacity(&stake, 8, MAX_DECIMAL_SCALE).is_err());
        assert!(validate_payout_capacity(&Quantity::one(), 32, MAX_DECIMAL_SCALE).is_ok());
        let tiny: Quantity = "0.0000000000000000000000000001".parse().unwrap();
        assert!(validate_payout_capacity(&tiny, 32, MAX_DECIMAL_SCALE).is_ok());
    }
    #[test]
    fn session_record_retains_payout_precision_and_receipt_in_canonical_roundtrip() {
        use norito::codec::Decode;
        let mut session = fixture();
        session.verification_id = Some(Hash::new(b"verified-execution-reference"));
        session.terminal_at_height = Some(123);
        crate::private_settlement::global_state::tests::assert_private_settlement_frame_v1(
            &session,
            "iroha_data_model::game::GameSessionRecordV1",
        );
        let bytes = session.encode();
        let decoded = GameSessionRecordV1::decode(&mut bytes.as_slice()).unwrap();
        assert_eq!(decoded, session);
    }
    #[test]
    fn compact_verification_reference_is_idempotent_and_queryable_without_proof_duplication() {
        use crate::prelude::ValidSingularQuery;
        use iroha_data_model::execution_proofs::ExecutionPublicInputsV1;
        let state = state();
        let mut block = state.block(header());
        let mut st = block.transaction();
        let session = fixture();
        // This tests receipt storage only; the public instruction verifies before calling it.
        let proof = ExecutionProofEnvelopeV1 {
            version: 1,
            profile_id: session.profile_id,
            statement: ExecutionPublicInputsV1 {
                network_id: *st.network_id(),
                session_id: session.session_id,
                manifest_hash: session.manifest_hash,
                roster_hash: session.roster_hash,
                transcript_root: Hash::new(b"receipt-test-transcript"),
                dispute_root: session.dispute_root,
                outcome_hash: Hash::new(b"receipt-test-outcome"),
            },
            proof_bytes: vec![1, 2, 3],
        };
        let id = retain_execution_verification(&mut st, &proof);
        let receipt = iroha_data_model::query::game::FindExecutionProofVerificationById {
            verification_id: id,
        }
        .execute(&st)
        .unwrap();
        assert_eq!(receipt.proof_hash, Hash::new(proof.encode()));
        assert_eq!(receipt.verified_at_height, st.block_height());
        assert_eq!(
            receipt.statement_hash,
            game_message_hash_v1(st.network_id(), "execution-statement", &proof.statement)
        );
        let mut alternative = proof.clone();
        alternative.proof_bytes.push(4);
        assert_eq!(retain_execution_verification(&mut st, &alternative), id);
        assert_eq!(
            st.world.execution_proof_verifications.get(&id),
            Some(&receipt)
        );
        assert_eq!(st.world.execution_proof_verifications.iter().count(), 1);
    }
    #[test]
    fn game_retention_counters_preserve_overlapping_sessions_and_permanent_custody() {
        let state = state();
        let mut block = state.block(header());
        let mut st = block.transaction();
        let mut first = fixture();
        let mut second = first.clone();
        second.session_id = Hash::new(b"second-outstanding-session");
        second.custody = game_custody_account_v1(
            &second.network_id,
            &second.session_id,
            &second.asset_definition,
        );
        seed_session(&mut st, first.clone());
        seed_session(&mut st, second.clone());
        assert_eq!(
            st.world
                .game_account_references
                .get(&first.participants[0].account),
            Some(&2)
        );
        assert_eq!(
            st.world.game_asset_references.get(&first.asset_definition),
            Some(&2)
        );
        first.liability = Quantity::zero();
        first.phase = GamePhaseV1::Settled;
        seed_session(&mut st, first.clone());
        assert_eq!(
            st.world
                .game_account_references
                .get(&first.participants[0].account),
            Some(&1)
        );
        second.liability = Quantity::zero();
        second.phase = GamePhaseV1::Settled;
        seed_session(&mut st, second.clone());
        assert!(
            st.world
                .game_account_references
                .get(&first.participants[0].account)
                .is_none()
        );
        assert!(
            st.world
                .game_asset_references
                .get(&first.asset_definition)
                .is_none()
        );
        assert_eq!(st.world.game_custody_by_account.iter().count(), 2);
        assert!(retained_game_account(&st.world, &first.custody));
        assert!(retained_game_account(&st.world, &second.custody));
    }
    fn index_world(session: &GameSessionRecordV1) -> World {
        index_world_with_policy(session, iroha_data_model::asset::AssetBalancePolicy::Global)
    }
    #[test]
    fn full_wsv_hash_covers_game_awards_assets_receipts_and_nft_reserves() {
        use iroha_data_model::nft_market::{NftCustodyPurposeV1, NftCustodyRecordV1};

        let session = fixture();
        let world = || {
            let mut world = index_world(&session);
            world.game_sessions = [(session.session_id, session.clone())]
                .into_iter()
                .collect();
            world
        };
        let hash = |world| {
            let mut state = State::new_for_testing(
                World::default(),
                Kura::blank_kura_for_testing(),
                LiveQueryStore::start_test(),
            );
            // Deliberately mutate the raw committed surface after fixture startup: this test
            // checks that corruption changes the checkpoint, not that restore admits it.
            state.world = world;
            crate::snapshot::canonical_state_snapshot_hash(&state)
                .expect("stable valid fixture snapshot")
        };
        let baseline = hash(world());
        assert_eq!(
            baseline,
            hash(world()),
            "local filesystem paths are excluded"
        );

        let mut changed = world();
        let mut award = session.clone();
        award.payout_claims.push(GamePayoutClaimV1 {
            slot: 0,
            amount: Quantity::one(),
            remaining: Quantity::one(),
        });
        changed.game_sessions = [(session.session_id, award)].into_iter().collect();
        assert_ne!(
            baseline,
            hash(changed),
            "claim entitlement must affect the full WSV hash"
        );

        let mut reserve = session.clone();
        reserve.liability = Quantity::from(3_u32);
        let mut changed = index_world(&reserve);
        changed.game_sessions = [(session.session_id, session.clone())]
            .into_iter()
            .collect();
        assert_ne!(
            baseline,
            hash(changed),
            "independent custody balance changes must be visible"
        );

        let mut changed = world();
        changed.execution_proof_verifications = [(
            Hash::new(b"receipt"),
            ExecutionProofVerificationV1 {
                profile_id: session.profile_id,
                statement_hash: Hash::new(b"statement"),
                proof_hash: Hash::new(b"canonical-proof"),
                verified_at_height: 1,
            },
        )]
        .into_iter()
        .collect();
        assert_ne!(
            baseline,
            hash(changed),
            "proof receipts must affect the full WSV hash"
        );

        let mut changed = world();
        changed.nft_custody_records = [(
            session.custody.clone(),
            NftCustodyRecordV1 {
                version: 1,
                network_id: session.network_id,
                reservation_id: session.session_id,
                purpose: NftCustodyPurposeV1::GameWager,
                nft_id: "skin$session.universal".parse().unwrap(),
                custody: session.custody.clone(),
                original_owner: session.participants[0].account.clone(),
                metadata_hash: Hash::new(b"immutable-skin"),
                released_to: None,
            },
        )]
        .into_iter()
        .collect();
        assert_ne!(
            baseline,
            hash(changed),
            "retained NFT reservations must affect the full WSV hash"
        );
    }
    fn index_world_with_policy(
        session: &GameSessionRecordV1,
        policy: iroha_data_model::asset::AssetBalancePolicy,
    ) -> World {
        use iroha_data_model::{
            asset::{Asset, AssetDefinition},
            domain::Domain,
        };
        let owner = &session.participants[0].account;
        World::with_assets(
            [Domain::new(DomainId::try_new("session", "universal").unwrap()).build(owner)],
            session
                .participants
                .iter()
                .map(|participant| Account::new(participant.account.clone()).build(owner))
                .chain(std::iter::once(
                    Account::new(session.custody.clone()).build(owner),
                )),
            [AssetDefinition::numeric(
                session.asset_definition.clone(),
                "Game index asset".to_owned(),
                policy,
                Some(DomainId::try_new("session", "universal").unwrap()),
            )
            .build(owner)],
            if policy == iroha_data_model::asset::AssetBalancePolicy::Global {
                vec![Asset::new(
                    AssetId::of(session.asset_definition.clone(), session.custody.clone()),
                    session.liability.clone(),
                )]
            } else {
                Vec::new()
            },
            [],
        )
    }
    #[test]
    fn scoped_stakes_are_rejected_at_creation_join_and_restore() {
        let session = fixture();
        let mut world = index_world_with_policy(
            &session,
            iroha_data_model::asset::AssetBalancePolicy::DataspaceRestricted,
        );
        world.game_sessions = [(session.session_id, session.clone())]
            .into_iter()
            .collect();
        assert!(
            world
                .rebuild_game_session_indexes()
                .unwrap_err()
                .contains("globally scoped")
        );
        let state = State::new_for_testing(
            index_world_with_policy(
                &session,
                iroha_data_model::asset::AssetBalancePolicy::DataspaceRestricted,
            ),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let mut block = state.block(header());
        let mut st = block.transaction();
        let owner = &session.participants[0].account;
        let error = OpenGameSessionV1::new(
            session.session_id,
            session.manifest.clone(),
            session.asset_definition.clone(),
            Quantity::one(),
            10,
        )
        .execute(owner, &mut st)
        .unwrap_err();
        assert!(error.to_string().contains("globally scoped"), "{error}");
        assert!(st.world.game_sessions.get(&session.session_id).is_none());
        seed_session(&mut st, session.clone());
        let error = JoinGameSessionV1 {
            session_id: session.session_id,
            input_key: key(3).public_key().clone(),
            application_data: vec![3],
            resources: Vec::new(),
            invitation: None,
            expected_manifest_hash: session.manifest_hash,
            expected_asset_definition: session.asset_definition.clone(),
            expected_stake: session.stake.clone(),
        }
        .execute(owner, &mut st)
        .unwrap_err();
        assert!(error.to_string().contains("globally scoped"), "{error}");
        assert_eq!(get(&st, &session.session_id).unwrap(), session);
    }
    #[test]
    fn only_exact_native_entry_funding_can_credit_reserved_custody() {
        use iroha_data_model::isi::{Mint, Transfer};
        let (state, mut session, entrant) = payout_state(Quantity::from(10_u32));
        session.participants.truncate(1);
        session.liability = Quantity::one();
        session.phase = GamePhaseV1::Lobby;
        let owner = session.participants[0].account.clone();
        let mut block = state.block(header());
        let mut st = payout_transaction(&mut block);
        fund_payout_fixture(&mut st, &mut session);
        let source = AssetId::of(session.asset_definition.clone(), owner.clone());
        let custody_asset = AssetId::of(session.asset_definition.clone(), session.custody.clone());
        Transfer::asset_quantity(source.clone(), Quantity::one(), entrant.clone())
            .execute(&owner, &mut st)
            .unwrap();
        for error in [
            Transfer::asset_quantity(source.clone(), Quantity::one(), session.custody.clone())
                .execute(&owner, &mut st)
                .unwrap_err(),
            Mint::asset_quantity(Quantity::one(), custody_asset.clone())
                .execute(&owner, &mut st)
                .unwrap_err(),
            st.world
                .precheck_numeric_asset_credit_exact(&custody_asset, &Quantity::one())
                .unwrap_err(),
        ] {
            assert!(error.to_string().contains("custody"), "{error}");
        }
        assert_eq!(
            st.world.assets.get(&custody_asset).unwrap().as_ref(),
            &Quantity::one()
        );
        assert_eq!(
            st.world.assets.get(&source).unwrap().as_ref(),
            &Quantity::from(9_u32)
        );
        // This internal capability test exercises admission's exact transfer;
        // the public Join qualification gate is never disabled.
        assert!(
            super::super::asset::isi::execute_verified_game_movement(
                &mut st,
                VerifiedGameMovement {
                    session_id: session.session_id,
                    authority: entrant.clone(),
                    purpose: VerifiedGameMovementPurpose::Funding,
                    legs: vec![(
                        AssetId::of(session.asset_definition.clone(), entrant.clone()),
                        custody_asset.clone(),
                        Quantity::one()
                    )],
                }
            )
            .unwrap()
        );
        assert_eq!(
            st.world.assets.get(&custody_asset).unwrap().as_ref(),
            &Quantity::from(2_u32)
        );
        session.participants.push(GameParticipantV1 {
            account: entrant,
            input_key: key(30).public_key().clone(),
            application_data: vec![0],
            dnf_at_tick: None,
        });
        session.liability = Quantity::from(2_u32);
        save(&mut st, session).unwrap();
    }
    #[test]
    fn prefunded_custody_cannot_be_adopted_by_a_new_session() {
        let (state, mut session, _) = payout_state(Quantity::from(10_u32));
        let owner = session.participants[0].account.clone();
        let mut block = state.block(header());
        let mut st = block.transaction();
        session.network_id = *st.network_id();
        session.custody = game_custody_account_v1(
            st.network_id(),
            &session.session_id,
            &session.asset_definition,
        );
        let (id, value) = Account::new(session.custody.clone())
            .build(&owner)
            .into_key_value();
        st.world.accounts.insert(id, value);
        super::super::asset::isi::seed_numeric_asset_balance_for_test(
            &mut st.world,
            &AssetId::of(session.asset_definition.clone(), session.custody),
            &Quantity::one(),
        )
        .unwrap();
        let error = OpenGameSessionV1::new(
            session.session_id,
            session.manifest,
            session.asset_definition,
            Quantity::one(),
            10,
        )
        .execute(&owner, &mut st)
        .unwrap_err();
        assert!(error.to_string().contains("must be empty"), "{error}");
        assert!(st.world.game_sessions.get(&session.session_id).is_none());
    }
    #[test]
    fn skipped_game_indexes_rebuild_from_authoritative_records_and_reject_wrong_custody() {
        let session = fixture();
        let mut world = index_world(&session);
        world.game_sessions = [(session.session_id, session.clone())]
            .into_iter()
            .collect();
        world.rebuild_game_session_indexes().unwrap();
        assert_eq!(
            world.game_custody_by_account.view().get(&session.custody),
            Some(&session.session_id)
        );
        assert_eq!(
            world
                .game_account_references
                .view()
                .get(&session.participants[0].account),
            Some(&1)
        );
        assert_eq!(
            world
                .game_asset_references
                .view()
                .get(&session.asset_definition),
            Some(&1)
        );
        let mut altered = session.clone();
        altered.custody = session.participants[0].account.clone();
        world.game_sessions = [(session.session_id, altered)].into_iter().collect();
        assert!(world.rebuild_game_session_indexes().is_err());
    }
    #[test]
    fn restore_rejects_phase_impossible_rosters_even_with_recomputed_commitments() {
        for case in 0..3 {
            let mut session = fixture();
            session.stake = Quantity::zero();
            session.liability = Quantity::zero();
            match case {
                0 => session.participants.truncate(1),
                1 => {
                    session.phase = GamePhaseV1::Lobby;
                    session.manifest.max_participants = 8;
                    session.participants = (0..9_u8)
                        .map(|slot| GameParticipantV1 {
                            account: AccountId::new(key(slot + 40).public_key().clone()),
                            input_key: key(slot + 60).public_key().clone(),
                            application_data: vec![slot % 6],
                            dnf_at_tick: None,
                        })
                        .collect();
                }
                _ => {
                    session.phase = GamePhaseV1::Cancelled;
                    session.terminal_at_height = Some(1);
                }
            }
            refresh_fixture_admission(&mut session);
            GameAdmissionBodyV1::from_session(&session)
                .validate()
                .unwrap();
            let mut world = index_world(&session);
            world.game_sessions = [(session.session_id, session)].into_iter().collect();
            let error = world.rebuild_game_session_indexes().unwrap_err();
            assert!(
                error.contains("roster is impossible"),
                "case {case}: {error}"
            );
        }
    }
    #[test]
    fn restore_rejects_missing_custody_and_retained_wallets() {
        let session = fixture();
        for missing in [&session.custody, &session.participants[1].account] {
            let mut world = index_world(&session);
            world.game_sessions = [(session.session_id, session.clone())]
                .into_iter()
                .collect();
            world.rebuild_game_session_indexes().unwrap();
            let surviving = world
                .accounts
                .view()
                .iter()
                .filter(|(id, _)| *id != missing)
                .map(|(id, value)| (id.clone(), value.clone()))
                .collect::<Vec<_>>();
            world.accounts = surviving.into_iter().collect();
            assert!(world.rebuild_game_session_indexes().is_err());
            assert_eq!(
                world
                    .game_account_references
                    .view()
                    .get(&session.participants[1].account),
                Some(&1)
            );
        }
    }
    #[test]
    fn outstanding_claims_rebuild_exact_reserves_and_reject_award_mutation() {
        let mut session = fixture();
        session.phase = GamePhaseV1::Settled;
        session.terminal_at_height = Some(1);
        session.result = Some(GameOutcomeV1 {
            terminal_tick: 5400,
            winner_slots: vec![0, 1],
            result: Vec::new(),
        });
        session.payout_claims = (0..2)
            .map(|slot| GamePayoutClaimV1 {
                slot,
                amount: Quantity::one(),
                remaining: Quantity::one(),
            })
            .collect();
        let mut world = index_world(&session);
        world.game_sessions = [(session.session_id, session.clone())]
            .into_iter()
            .collect();
        world.rebuild_game_session_indexes().unwrap();
        assert_eq!(
            world
                .game_asset_references
                .view()
                .get(&session.asset_definition),
            Some(&1)
        );
        session.payout_claims[0].remaining = Quantity::zero();
        session.liability = Quantity::one();
        world.assets = [iroha_data_model::asset::Asset::new(
            AssetId::of(session.asset_definition.clone(), session.custody.clone()),
            session.liability.clone(),
        )
        .into_key_value()]
        .into_iter()
        .collect();

        world.game_sessions = [(session.session_id, session.clone())]
            .into_iter()
            .collect();
        world.rebuild_game_session_indexes().unwrap();
        assert!(
            world
                .game_account_references
                .view()
                .get(&session.participants[0].account)
                .is_none()
        );
        assert_eq!(
            world
                .game_account_references
                .view()
                .get(&session.participants[1].account),
            Some(&1)
        );
        for mutation in 0..5 {
            let mut altered = session.clone();
            match mutation {
                0 => altered.payout_claims[0].amount = Quantity::from(2_u32),
                1 => altered.payout_claims[1].remaining = Quantity::from(2_u32),
                2 => altered.payout_claims[1].slot = 0,
                3 => altered.liability = Quantity::zero(),
                4 => altered.result = None,
                _ => unreachable!(),
            }
            world.game_sessions = [(altered.session_id, altered)].into_iter().collect();
            assert!(world.rebuild_game_session_indexes().is_err());
            assert_eq!(
                world
                    .game_account_references
                    .view()
                    .get(&session.participants[1].account),
                Some(&1)
            );
            assert_eq!(
                world
                    .game_asset_references
                    .view()
                    .get(&session.asset_definition),
                Some(&1)
            );
        }
    }
    #[test]
    fn restored_game_indexes_reject_bad_liabilities_and_duplicate_authorities_atomically() {
        let valid = fixture();
        let mut world = index_world(&valid);
        world.game_sessions = [(valid.session_id, valid.clone())].into_iter().collect();
        world.rebuild_game_session_indexes().unwrap();

        let mut variants = Vec::new();
        for mutation in 0..5 {
            let mut altered = valid.clone();
            match mutation {
                0 => altered.roster_hash = Hash::new(b"wrong immutable admission"),
                1 => altered.manifest_hash = Hash::new(b"wrong manifest"),
                2 => altered.terminal_at_height = Some(1),
                3 => altered.participants[0].application_data = vec![255],
                _ => {
                    altered.phase = GamePhaseV1::Cancelled;
                    altered.terminal_at_height = Some(0);
                }
            }
            variants.push(altered);
        }
        let mut altered = valid.clone();
        altered.liability = Quantity::one();
        variants.push(altered);
        let mut altered = valid.clone();
        altered.phase = GamePhaseV1::Settled;
        variants.push(altered);
        let mut altered = valid.clone();
        altered.participants[1].account = altered.participants[0].account.clone();
        variants.push(altered);
        let mut altered = valid.clone();
        altered.participants[1].input_key = altered.participants[0].input_key.clone();
        variants.push(altered);
        let mut altered = valid.clone();
        altered.stake = Quantity::zero();
        altered.liability = Quantity::zero();
        altered.participants[1].input_key = altered.participants[0].input_key.clone();
        variants.push(altered);
        let mut altered = valid.clone();
        altered.participants[0].account = altered.custody.clone();
        variants.push(altered);
        let mut altered = valid.clone();
        altered.payout_scale = MAX_DECIMAL_SCALE + 1;
        variants.push(altered);

        for altered in variants {
            world.game_sessions = [(altered.session_id, altered)].into_iter().collect();
            assert!(world.rebuild_game_session_indexes().is_err());
            assert_eq!(
                world
                    .game_account_references
                    .view()
                    .get(&valid.participants[0].account),
                Some(&1),
                "a rejected rebuild must preserve the previous complete index"
            );
            assert_eq!(
                world.game_custody_by_account.view().get(&valid.custody),
                Some(&valid.session_id)
            );
        }
        let mut closed = valid.clone();
        closed.liability = Quantity::zero();
        closed.phase = GamePhaseV1::Settled;
        closed.terminal_at_height = Some(1);
        closed.result = Some(GameOutcomeV1 {
            terminal_tick: 5400,
            winner_slots: vec![0],
            result: Vec::new(),
        });
        closed.payout_claims = vec![GamePayoutClaimV1 {
            slot: 0,
            amount: Quantity::from(2_u32),
            remaining: Quantity::zero(),
        }];
        world.assets = mv::storage::Storage::default();
        world.game_sessions = [(closed.session_id, closed)].into_iter().collect();
        world.rebuild_game_session_indexes().unwrap();
        assert!(world.game_account_references.view().iter().next().is_none());
        assert!(world.game_asset_references.view().iter().next().is_none());
        assert_eq!(
            world.game_custody_by_account.view().get(&valid.custody),
            Some(&valid.session_id)
        );
    }
    #[test]
    fn game_retention_overflow_does_not_partially_publish_custody_or_references() {
        let state = state();
        let mut block = state.block(header());
        let mut st = block.transaction();
        let session = fixture();
        st.world
            .game_account_references
            .insert(session.participants[1].account.clone(), u32::MAX);
        assert!(update_session_indexes(&mut st, &session).is_err());
        assert!(
            st.world
                .game_custody_by_account
                .get(&session.custody)
                .is_none()
        );
        assert!(
            st.world
                .game_asset_references
                .get(&session.asset_definition)
                .is_none()
        );
        assert!(
            st.world
                .game_account_references
                .get(&session.participants[0].account)
                .is_none()
        );
        assert_eq!(
            st.world
                .game_account_references
                .get(&session.participants[1].account),
            Some(&u32::MAX)
        );
        st.world
            .game_account_references
            .remove(session.participants[1].account.clone());
        seed_session(&mut st, session.clone());
        st.world
            .game_asset_references
            .remove(session.asset_definition.clone());
        let mut closed = session.clone();
        closed.phase = GamePhaseV1::Settled;
        closed.terminal_at_height = Some(1);
        closed.result = Some(GameOutcomeV1 {
            terminal_tick: 5400,
            winner_slots: vec![0],
            result: vec![],
        });
        closed.payout_claims = vec![GamePayoutClaimV1 {
            slot: 0,
            amount: Quantity::from(2_u32),
            remaining: Quantity::zero(),
        }];
        closed.liability = Quantity::zero();
        assert!(update_session_indexes(&mut st, &closed).is_err());
        assert_eq!(
            st.world
                .game_account_references
                .get(&session.participants[0].account),
            Some(&1),
            "asset reference underflow must not partially release retained wallets"
        );
    }
}
