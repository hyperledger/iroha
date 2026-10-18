//! Proof admission against authenticated retained native game history, without registration.
use super::super::error::ExecutionProofErrorV1;
use super::{
    admission::{
        classed_race_state_root_v1, classed_race_transcript_root_v1, outcome, validate_payload,
    },
    proof::{
        ClassedRaceProofPayloadV1, classed_race_profile_id_v1, decode_payload,
        verify_classed_race_proof_v1,
    },
    reference::{classed_race_is_terminal_v1, initial_classed_race_state_v1},
    rules::{BATCH_TICKS, MAX_TICKS},
};
use iroha_crypto::Hash;
use iroha_data_model::{
    classed_race_v1::{ClassedRaceDnfEventV1, ClassedRaceReplayV1},
    execution_proofs::{ExecutionProofEnvelopeV1, ExecutionPublicInputsV1},
    game::{
        GameAdmissionBodyV1, GameOutcomeV1, GamePhaseV1, GameSessionRecordV1, game_message_hash_v1,
        game_roster_hash_v1,
    },
};

/// Exact generic native history commitment. This hash is recomputed from the retained record;
/// it never substitutes for authenticating that record's finalized consensus inclusion.
#[must_use]
pub fn classed_race_dispute_root_v1(session: &GameSessionRecordV1) -> Hash {
    game_message_hash_v1(
        &session.network_id,
        "dispute-history",
        &(
            session.session_id,
            session.epoch,
            session.checkpoint.as_ref().map(|signed| signed.checkpoint),
            session.transcript_anchors.clone(),
            session.forced_batches.clone(),
        ),
    )
}

fn prefix(replay: &ClassedRaceReplayV1, tick: u32) -> ClassedRaceReplayV1 {
    ClassedRaceReplayV1 {
        version: 1,
        class_id: replay.class_id,
        track: replay.track,
        player_count: replay.player_count,
        frames: replay.frames[..tick as usize].to_vec(),
        // Checkpoints certify the state before a removal at this same boundary.
        dnf_events: replay
            .dnf_events
            .iter()
            .filter(|event| event.tick < tick)
            .cloned()
            .collect(),
    }
}

pub(super) fn validate_history(
    session: &GameSessionRecordV1,
    claimed: &GameOutcomeV1,
    statement: &ExecutionPublicInputsV1,
    payload: &ClassedRaceProofPayloadV1,
) -> Result<(), ExecutionProofErrorV1> {
    let invalid = || ExecutionProofErrorV1::History;
    // Cardinalities precede cloning/hash projection of any retained history.
    if session.version != 1
        || !(2..=8).contains(&session.participants.len())
        || session.resources.len() != session.participants.len()
        || session.item_stakes.len() > 8
        || session.transcript_anchors.len() > 8
        || session.forced_batches.len() > MAX_TICKS as usize / BATCH_TICKS as usize
        || session.epoch != session.forced_batches.len() as u64
        || !matches!(
            session.phase,
            GamePhaseV1::AwaitingProof
                | GamePhaseV1::ForcedCommit
                | GamePhaseV1::ForcedReveal
                | GamePhaseV1::Settled
        )
        || session
            .checkpoint
            .as_ref()
            .is_some_and(|signed| signed.signatures.len() > session.participants.len())
        || session.forced_batches.iter().any(|batch| {
            batch.inputs.len() != session.participants.len()
                || batch.inputs.iter().any(|input| input.len() > 12)
                || batch.dnf_slots.len() > session.participants.len()
        })
    {
        return Err(invalid());
    }
    validate_payload(statement, payload)?;
    let admission = GameAdmissionBodyV1::from_session(session);
    admission.validate().map_err(|_| invalid())?;
    if session.manifest != payload.manifest
        || admission != payload.admission
        || session.profile_id != classed_race_profile_id_v1()
        || session.manifest.profile_id != session.profile_id
        || session.manifest_hash
            != game_message_hash_v1(&session.network_id, "session-manifest", &session.manifest)
        || session.roster_hash
            != game_roster_hash_v1(&session.network_id, &session.session_id, &admission)
        || session.dispute_root != classed_race_dispute_root_v1(session)
        || &outcome(&payload.result) != claimed
        || session
            .result
            .as_ref()
            .is_some_and(|result| result != claimed)
        || session.resources.iter().any(|resource| {
            session
                .participants
                .get(usize::from(resource.slot))
                .is_none_or(|participant| resource.original_owner != participant.account)
        })
    {
        return Err(invalid());
    }
    let expected = ExecutionPublicInputsV1 {
        network_id: session.network_id,
        session_id: session.session_id,
        manifest_hash: session.manifest_hash,
        roster_hash: session.roster_hash,
        dispute_root: session.dispute_root,
        transcript_root: classed_race_transcript_root_v1(&session.network_id, &payload.replay)?,
        outcome_hash: game_message_hash_v1(&session.network_id, "session-outcome", claimed),
    };
    if statement != &expected {
        return Err(invalid());
    }
    let replay = &payload.replay;
    let terminal = payload.final_state.tick;
    let mut removals = std::collections::BTreeMap::<u32, Vec<u8>>::new();
    for (slot, participant) in session.participants.iter().enumerate() {
        if let Some(tick) = participant.dnf_at_tick {
            // No later consensus disqualification may be silently discarded by ending early.
            if tick > terminal || tick % BATCH_TICKS != 0 {
                return Err(invalid());
            }
            removals.entry(tick).or_default().push(slot as u8);
        }
    }
    if replay.dnf_events
        != removals
            .iter()
            .map(|(tick, slots)| ClassedRaceDnfEventV1 {
                tick: *tick,
                slots: slots.clone(),
            })
            .collect::<Vec<_>>()
    {
        return Err(invalid());
    }
    let mut tail = 0;
    match (&session.checkpoint, &payload.checkpoint_state) {
        (Some(signed), Some(state)) => {
            let checkpoint = &signed.checkpoint;
            if checkpoint.session_id != session.session_id
                || checkpoint.epoch > session.epoch
                || checkpoint.tick > terminal
                || checkpoint.tick % BATCH_TICKS != 0
                || state.tick != checkpoint.tick
                || checkpoint.state_root != classed_race_state_root_v1(&session.network_id, state)
                || checkpoint.transcript_root
                    != classed_race_transcript_root_v1(
                        &session.network_id,
                        &prefix(replay, checkpoint.tick),
                    )?
                || checkpoint.terminal
                    != classed_race_is_terminal_v1(state).map_err(|_| invalid())?
            {
                return Err(invalid());
            }
            if checkpoint.tick == 0 && signed.signatures.is_empty() {
                if checkpoint.epoch != 0
                    || checkpoint.terminal
                    || state
                        != &initial_classed_race_state_v1(
                            replay.class_id,
                            replay.track,
                            replay.player_count,
                        )
                        .map_err(|_| invalid())?
                {
                    return Err(invalid());
                }
            } else {
                if signed.signatures.len() != session.participants.len() {
                    return Err(invalid());
                }
                let hash = game_message_hash_v1(&session.network_id, "checkpoint", checkpoint);
                for (slot, (signature, participant)) in signed
                    .signatures
                    .iter()
                    .zip(&session.participants)
                    .enumerate()
                {
                    if usize::from(signature.slot) != slot
                        || signature.signature.payload().len() != 64
                        || signature
                            .signature
                            .verify(&participant.input_key, hash.as_ref())
                            .is_err()
                    {
                        return Err(invalid());
                    }
                }
            }
            tail = checkpoint.tick;
        }
        (None, None) => {}
        _ => return Err(invalid()),
    }
    if session
        .transcript_anchors
        .windows(2)
        .any(|pair| pair[0].tick >= pair[1].tick)
    {
        return Err(invalid());
    }
    for anchor in &session.transcript_anchors {
        if anchor.tick > tail
            || anchor.tick % BATCH_TICKS != 0
            || anchor.transcript_root
                != classed_race_transcript_root_v1(
                    &session.network_id,
                    &prefix(replay, anchor.tick),
                )?
        {
            return Err(invalid());
        }
    }
    let mut previous_end = 0;
    for (epoch, batch) in session.forced_batches.iter().enumerate() {
        if batch.epoch != epoch as u64
            || batch.start_tick % BATCH_TICKS != 0
            || batch.start_tick > terminal
            || batch.start_tick < previous_end
            || batch.dnf_slots.windows(2).any(|slots| slots[0] >= slots[1])
            || batch.dnf_slots != removals.get(&batch.start_tick).cloned().unwrap_or_default()
        {
            return Err(invalid());
        }
        let end = batch
            .start_tick
            .checked_add(BATCH_TICKS)
            .ok_or_else(invalid)?;
        if end > MAX_TICKS {
            return Err(invalid());
        }
        if let Some(signed) = &session.checkpoint {
            if (batch.epoch < signed.checkpoint.epoch && end > signed.checkpoint.tick)
                || (batch.epoch >= signed.checkpoint.epoch
                    && batch.start_tick < signed.checkpoint.tick)
            {
                return Err(invalid());
            }
        }
        for (slot, input) in batch.inputs.iter().enumerate() {
            let removed = session.participants[slot]
                .dnf_at_tick
                .is_some_and(|tick| tick <= batch.start_tick);
            if removed {
                if !input.is_empty() {
                    return Err(invalid());
                }
            } else if input.len() != 12
                || input
                    .chunks_exact(2)
                    .any(|pair| u16::from_le_bytes([pair[0], pair[1]]) & !63 != 0)
            {
                return Err(invalid());
            }
            for offset in 0..BATCH_TICKS {
                if let Some(frame) = replay.frames.get((batch.start_tick + offset) as usize) {
                    let control = if removed {
                        0
                    } else {
                        u16::from_le_bytes([
                            input[offset as usize * 2],
                            input[offset as usize * 2 + 1],
                        ])
                    };
                    if frame.controls[slot] != control {
                        return Err(invalid());
                    }
                }
            }
        }
        // One forced removal at the terminal boundary may end the race before its six
        // following controls execute. A later batch or later DNF is never ignored.
        if batch.start_tick == terminal && batch.dnf_slots.is_empty() {
            return Err(invalid());
        }
        if batch.start_tick >= tail {
            if batch.start_tick != tail {
                return Err(invalid());
            }
            tail = end;
        }
        previous_end = end;
    }
    if tail < terminal
        || session.next_tick != tail
        || removals.keys().any(|tick| {
            !session
                .forced_batches
                .iter()
                .any(|batch| batch.start_tick == *tick)
        })
    {
        return Err(invalid());
    }
    if session.forced_batches.is_empty()
        && !session
            .checkpoint
            .as_ref()
            .is_some_and(|signed| signed.checkpoint.terminal && signed.checkpoint.tick == terminal)
    {
        return Err(invalid());
    }
    Ok(())
}

/// Verify complete Touring computation and its exact authenticated native session history.
/// The supplied session must come from consensus state or independently verified finalized
/// inclusion. This function checks its retained checkpoint certificates and every forced input;
/// it does not establish ledger finality, NFT collection eligibility or custody on its own.
///
/// # Errors
/// Rejects malformed proof envelopes, inconsistent retained session history,
/// checkpoint signature or forced-input mismatches, and any underlying statement,
/// replay or cryptographic verification failure.
pub fn verify_classed_race_proof_for_session_v1(
    session: &GameSessionRecordV1,
    claimed: &GameOutcomeV1,
    envelope: &ExecutionProofEnvelopeV1,
) -> Result<iroha_data_model::classed_race_v1::ClassedRaceResultV1, ExecutionProofErrorV1> {
    let payload = decode_payload(envelope)?;
    validate_history(session, claimed, &envelope.statement, &payload)?;
    verify_classed_race_proof_v1(&envelope.statement, envelope)
}
