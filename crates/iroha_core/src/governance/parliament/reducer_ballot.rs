impl ParliamentAttemptStateV1 {
    /// Register a fresh private OVN ballot attempt for a body at `Vote`.
    ///
    /// A retry is accepted only after the preceding ballot reached `NoResult`.
    /// The old attempt is superseded and the new attempt must use the exact next
    /// sequence. No plaintext ballot input exists in this reducer API.
    ///
    /// # Errors
    /// Returns an error for a public-finding body, wrong stage/bindings, duplicate
    /// identifier, sequence mismatch, or an old ballot not in `NoResult`.
    #[expect(
        clippy::too_many_arguments,
        reason = "the ballot-specific TLE identity and target are immutable at registration"
    )]
    pub fn register_ballot_attempt(
        &mut self,
        governance_attempt_id: GovernanceAttemptId,
        body_instance_id: BodyInstanceId,
        ballot_attempt_id: BallotAttemptId,
        sequence: u32,
        tle_session_id: TleSessionId,
        tle_key_session_id: TleKeySessionId,
        release_beacon_session_id: BeaconSessionId,
        registered_at_height: u64,
        timed_ovn_policy: ParliamentTimedOvn,
        release_height: u64,
    ) -> Result<(), ParliamentReducerErrorV1> {
        self.ensure_active(governance_attempt_id)?;
        if ballot_attempt_id.as_bytes().iter().all(|byte| *byte == 0)
            || self.ballots.contains_key(&ballot_attempt_id)
        {
            return Err(ParliamentReducerErrorV1::DuplicateOrZeroIdentifier(
                ParliamentReducerEntityV1::BallotAttempt,
            ));
        }
        if tle_session_id.as_bytes().iter().all(|byte| *byte == 0)
            || tle_key_session_id.as_bytes().iter().all(|byte| *byte == 0)
            || release_beacon_session_id
                .as_bytes()
                .iter()
                .all(|byte| *byte == 0)
        {
            return Err(ParliamentReducerErrorV1::DuplicateOrZeroIdentifier(
                ParliamentReducerEntityV1::BallotAttempt,
            ));
        }
        let (
            registration_close_height,
            survivor_freeze_height,
            commitment_close_height,
            expected_release_height,
            opening_deadline_height,
        ) = timed_ballot_schedule(registered_at_height, timed_ovn_policy)?;
        // The frozen release slot creates no consensus obligation: consensus produces only
        // its native boundary pulses. The ballot opens only if a native pulse happens to be
        // committed at exactly `release_height`; otherwise it ends
        // `ReleasePulseUnavailable` through `fail_ballot_no_result`, governance-locally.
        // TODO: retire with the timed-OVN ballot path
        // (specs/parliament_private_ballot_design.md 12.2 step 4).
        if release_height != expected_release_height {
            return Err(ParliamentReducerErrorV1::InvalidBallotSchedule);
        }
        if sequence > timed_ovn_policy.max_ballot_retries {
            return Err(ParliamentReducerErrorV1::BallotRetryLimitExceeded);
        }
        self.ensure_ballot_redraw_available_v1(sequence)?;
        if self
            .ballots
            .values()
            .next()
            .is_some_and(|ballot| !ballot_policy_matches(ballot, timed_ovn_policy))
        {
            return Err(ParliamentReducerErrorV1::InvalidBallotSchedule);
        }
        if self.used_tle_sessions.contains_key(&tle_session_id) {
            return Err(ParliamentReducerErrorV1::TleSessionAlreadyConsumed);
        }
        if ballot_attempt_id != BallotAttemptId::derive_v1(body_instance_id, sequence)
            || tle_session_id
                != TleSessionId::derive_v1(
                    ballot_attempt_id,
                    tle_key_session_id,
                    release_beacon_session_id,
                    release_height,
                )
        {
            return Err(ParliamentReducerErrorV1::ImmutableBindingMismatch);
        }
        if self
            .used_pulse_slots
            .contains_key(&ParliamentPulseSlotV1::new(
                release_beacon_session_id,
                release_height,
            ))
        {
            return Err(ParliamentReducerErrorV1::BeaconPulseAlreadyConsumed);
        }
        let body =
            self.bodies
                .get(&body_instance_id)
                .ok_or(ParliamentReducerErrorV1::UnknownEntity(
                    ParliamentReducerEntityV1::BodyInstance,
                ))?;
        let body_role = body.instance.body;
        let requirement = self.ensure_current_body(body_role)?;
        if requirement.decision_mode != ParliamentDecisionModeV1::HiddenBindingBallot {
            return Err(ParliamentReducerErrorV1::DecisionModeMismatch);
        }
        if body.instance.governance_attempt_id != governance_attempt_id {
            return Err(ParliamentReducerErrorV1::ImmutableBindingMismatch);
        }
        let election = self
            .elections
            .get(&body.instance.election_attempt_id)
            .ok_or(ParliamentReducerErrorV1::ImmutableBindingMismatch)?;
        if election
            .invitation_close_height
            .is_none_or(|close_height| registered_at_height <= close_height)
        {
            return Err(ParliamentReducerErrorV1::InvalidBallotSchedule);
        }
        let original_seats = body.instance.original_seats;
        if timed_ovn_policy.max_corpus_entries < original_seats {
            return Err(ParliamentReducerErrorV1::InvalidBallotSchedule);
        }
        let predecessor = self.active_ballots.get(&body_instance_id).copied();
        match predecessor {
            None => {
                if sequence != 0
                    || body.instance.status
                        != BodyInstanceStatusV1::Deliberating(DeliberationPhaseV1::Vote)
                {
                    return Err(ParliamentReducerErrorV1::RetrySequenceMismatch);
                }
            }
            Some(previous_id) => {
                let previous = self.ballots.get(&previous_id).ok_or(
                    ParliamentReducerErrorV1::UnknownEntity(
                        ParliamentReducerEntityV1::BallotAttempt,
                    ),
                )?;
                if previous.attempt.status != BallotAttemptStatusV1::NoResult
                    || body.instance.status != BodyInstanceStatusV1::NoResult
                {
                    return Err(ParliamentReducerErrorV1::InvalidLifecycleTransition(
                        ParliamentReducerEntityV1::BallotAttempt,
                    ));
                }
                if sequence != previous.attempt.sequence.saturating_add(1) {
                    return Err(ParliamentReducerErrorV1::RetrySequenceMismatch);
                }
                if previous
                    .failure_height
                    .is_none_or(|failure_height| registered_at_height < failure_height)
                {
                    return Err(ParliamentReducerErrorV1::InvalidBallotSchedule);
                }
            }
        }
        if let Some(previous_id) = predecessor {
            self.ballots
                .get_mut(&previous_id)
                .expect("predecessor checked above")
                .attempt
                .status = BallotAttemptStatusV1::Superseded;
        }
        self.bodies
            .get_mut(&body_instance_id)
            .expect("body checked above")
            .instance
            .status = BodyInstanceStatusV1::Balloting;
        self.active_ballots
            .insert(body_instance_id, ballot_attempt_id);
        self.ballots.insert(
            ballot_attempt_id,
            ParliamentBallotStateV1 {
                attempt: ParliamentBallotAttemptV1 {
                    id: ballot_attempt_id,
                    body_instance_id,
                    sequence,
                    original_seats,
                    status: BallotAttemptStatusV1::Registration,
                },
                registration_root: None,
                registered_voters: None,
                corpus_root: None,
                accepted_ballots: None,
                dropout_root: None,
                survivor_root: None,
                survivors: None,
                no_recovery_root: None,
                tle_session_id: Some(tle_session_id),
                tle_key_session_id: Some(tle_key_session_id),
                release_beacon_session_id: Some(release_beacon_session_id),
                registered_at_height,
                registration_phase_blocks: timed_ovn_policy.registration_phase_blocks,
                survivor_freeze_phase_blocks: timed_ovn_policy.survivor_freeze_phase_blocks,
                commitment_phase_blocks: timed_ovn_policy.commitment_phase_blocks,
                release_delay_blocks: timed_ovn_policy.release_delay_blocks,
                opening_phase_blocks: timed_ovn_policy.opening_phase_blocks,
                max_ballot_retries: timed_ovn_policy.max_ballot_retries,
                max_corpus_entries: timed_ovn_policy.max_corpus_entries,
                registration_close_height,
                survivor_freeze_height,
                commitment_close_height,
                registration_closed_at_height: None,
                survivors_frozen_at_height: None,
                commitment_closed_at_height: None,
                timed_commitment_root: None,
                release_height: Some(release_height),
                opening_deadline_height,
                release_pulse_id: None,
                opening_height: None,
                opening_root: None,
                tally: None,
                outcome: None,
                failure_root: None,
                failure_kind: None,
                failure_height: None,
                eligible_confirmation_candidates: None,
            },
        );
        self.used_tle_sessions
            .insert(tle_session_id, ballot_attempt_id);
        Ok(())
    }

    /// Cheaply authorize the registration-close checkpoint before corpus replay.
    ///
    /// This checks only reducer-owned scalar state and bindings. Callers must
    /// still replay and validate the complete timed-OVN registration corpus
    /// after this succeeds.
    ///
    /// # Errors
    /// Returns an error for an inactive attempt, wrong ballot/body binding,
    /// replayed phase, or a containing height other than the frozen deadline.
    pub(crate) fn precheck_close_ballot_registration(
        &self,
        governance_attempt_id: GovernanceAttemptId,
        ballot_attempt_id: BallotAttemptId,
        current_height: u64,
    ) -> Result<&ParliamentBallotStateV1, ParliamentReducerErrorV1> {
        self.precheck_ballot_checkpoint(
            governance_attempt_id,
            ballot_attempt_id,
            BallotAttemptStatusV1::Registration,
            |ballot| current_height == ballot.registration_close_height,
        )
    }

    /// Cheaply authorize the survivor-freeze checkpoint before corpus replay.
    ///
    /// # Errors
    /// Returns an error for an inactive attempt, wrong ballot/body binding,
    /// replayed phase, or a containing height other than the frozen deadline.
    pub(crate) fn precheck_freeze_ballot_survivors(
        &self,
        governance_attempt_id: GovernanceAttemptId,
        ballot_attempt_id: BallotAttemptId,
        current_height: u64,
    ) -> Result<&ParliamentBallotStateV1, ParliamentReducerErrorV1> {
        self.precheck_ballot_checkpoint(
            governance_attempt_id,
            ballot_attempt_id,
            BallotAttemptStatusV1::SurvivorFreeze,
            |ballot| {
                current_height == ballot.survivor_freeze_height
                    && ballot.registration_closed_at_height
                        == Some(ballot.registration_close_height)
            },
        )
    }

    /// Cheaply authorize one bounded corpus append during the commitment window.
    ///
    /// # Errors
    /// Returns an error for an inactive attempt, wrong ballot/body binding,
    /// replayed phase, or a containing height outside the frozen window.
    pub(crate) fn precheck_freeze_timed_ovn_corpus(
        &self,
        governance_attempt_id: GovernanceAttemptId,
        ballot_attempt_id: BallotAttemptId,
        current_height: u64,
    ) -> Result<&ParliamentBallotStateV1, ParliamentReducerErrorV1> {
        self.precheck_ballot_checkpoint(
            governance_attempt_id,
            ballot_attempt_id,
            BallotAttemptStatusV1::TimedCommitment,
            |ballot| {
                timed_commitment_height_is_in_window(ballot, current_height)
                    && ballot.survivors_frozen_at_height == Some(ballot.survivor_freeze_height)
            },
        )
    }

    fn precheck_ballot_checkpoint(
        &self,
        governance_attempt_id: GovernanceAttemptId,
        ballot_attempt_id: BallotAttemptId,
        expected_status: BallotAttemptStatusV1,
        height_is_exact: impl FnOnce(&ParliamentBallotStateV1) -> bool,
    ) -> Result<&ParliamentBallotStateV1, ParliamentReducerErrorV1> {
        self.ensure_active(governance_attempt_id)?;
        let ballot =
            self.ballots
                .get(&ballot_attempt_id)
                .ok_or(ParliamentReducerErrorV1::UnknownEntity(
                    ParliamentReducerEntityV1::BallotAttempt,
                ))?;
        if ballot.attempt.status != expected_status {
            return Err(ParliamentReducerErrorV1::InvalidLifecycleTransition(
                ParliamentReducerEntityV1::BallotAttempt,
            ));
        }
        if !height_is_exact(ballot) {
            return Err(ParliamentReducerErrorV1::WrongBallotPhaseHeight);
        }
        let body = self.bodies.get(&ballot.attempt.body_instance_id).ok_or(
            ParliamentReducerErrorV1::UnknownEntity(ParliamentReducerEntityV1::BodyInstance),
        )?;
        if body.instance.governance_attempt_id != governance_attempt_id
            || self.active_ballots.get(&body.instance.id) != Some(&ballot_attempt_id)
        {
            return Err(ParliamentReducerErrorV1::ImmutableBindingMismatch);
        }
        Ok(ballot)
    }

    /// Close private registration and enter canonical survivor freezing.
    ///
    /// # Errors
    /// Returns an error for replay, zero root, wrong attempt, or a registered
    /// voter count exceeding nonabsent seats. The original-seat quorum is unchanged.
    pub fn close_ballot_registration(
        &mut self,
        governance_attempt_id: GovernanceAttemptId,
        ballot_attempt_id: BallotAttemptId,
        registration_root: [u8; 32],
        registered_voters: u32,
        current_height: u64,
    ) -> Result<(), ParliamentReducerErrorV1> {
        self.ensure_active(governance_attempt_id)?;
        if root_is_zero(&registration_root) {
            return Err(ParliamentReducerErrorV1::ZeroCommitmentRoot);
        }
        let ballot = self.precheck_close_ballot_registration(
            governance_attempt_id,
            ballot_attempt_id,
            current_height,
        )?;
        let body = self
            .bodies
            .get(&ballot.attempt.body_instance_id)
            .expect("checkpoint precheck verified the body");
        let excluded = u32::try_from(body.excluded_assignments.len())
            .map_err(|_| ParliamentReducerErrorV1::InvalidBallotCount)?;
        let eligible = ballot.attempt.original_seats.saturating_sub(excluded);
        if registered_voters > eligible || registered_voters > ballot.max_corpus_entries {
            return Err(ParliamentReducerErrorV1::InvalidBallotCount);
        }
        let ballot = self
            .ballots
            .get_mut(&ballot_attempt_id)
            .expect("ballot checked above");
        ballot.registration_root = Some(registration_root);
        ballot.registered_voters = Some(registered_voters);
        ballot.registration_closed_at_height = Some(current_height);
        ballot.attempt.status = BallotAttemptStatusV1::SurvivorFreeze;
        Ok(())
    }

    /// Freeze a canonical survivor roster meeting the V1 anonymity floor.
    ///
    /// # Errors
    /// Returns an error for replay, zero roots, wrong attempt, a sub-floor
    /// survivor set, or a survivor count exceeding the frozen registration.
    pub fn freeze_ballot_survivors(
        &mut self,
        governance_attempt_id: GovernanceAttemptId,
        ballot_attempt_id: BallotAttemptId,
        dropout_root: [u8; 32],
        survivor_root: [u8; 32],
        survivors: u32,
        no_recovery_root: [u8; 32],
        current_height: u64,
    ) -> Result<(), ParliamentReducerErrorV1> {
        self.ensure_active(governance_attempt_id)?;
        if root_is_zero(&dropout_root)
            || root_is_zero(&survivor_root)
            || root_is_zero(&no_recovery_root)
        {
            return Err(ParliamentReducerErrorV1::ZeroCommitmentRoot);
        }
        let ballot = self.precheck_freeze_ballot_survivors(
            governance_attempt_id,
            ballot_attempt_id,
            current_height,
        )?;
        let registered = ballot
            .registered_voters
            .ok_or(ParliamentReducerErrorV1::ImmutableBindingMismatch)?;
        if survivors < MIN_PARLIAMENT_HIDDEN_BALLOT_ANONYMITY_V1
            || survivors > registered
            || survivors > ballot.max_corpus_entries
        {
            return Err(ParliamentReducerErrorV1::InvalidBallotCount);
        }
        let ballot = self
            .ballots
            .get_mut(&ballot_attempt_id)
            .expect("ballot checked above");
        ballot.dropout_root = Some(dropout_root);
        ballot.survivor_root = Some(survivor_root);
        ballot.survivors = Some(survivors);
        ballot.no_recovery_root = Some(no_recovery_root);
        ballot.survivors_frozen_at_height = Some(current_height);
        ballot.attempt.status = BallotAttemptStatusV1::TimedCommitment;
        Ok(())
    }

    /// Freeze the complete intrinsic timed-OVN ciphertext and one-hot-proof corpus.
    ///
    /// # Errors
    /// Returns an error for replay, survivor-root mutation, a missing survivor
    /// ballot, zero roots, unknown ballot, a completion outside the commitment
    /// window, or wrong attempt.
    pub fn freeze_timed_ovn_corpus(
        &mut self,
        governance_attempt_id: GovernanceAttemptId,
        ballot_attempt_id: BallotAttemptId,
        corpus_root: [u8; 32],
        survivor_root: [u8; 32],
        accepted_ballots: u32,
        timed_commitment_root: [u8; 32],
        current_height: u64,
    ) -> Result<(), ParliamentReducerErrorV1> {
        self.ensure_active(governance_attempt_id)?;
        if root_is_zero(&corpus_root)
            || root_is_zero(&survivor_root)
            || root_is_zero(&timed_commitment_root)
        {
            return Err(ParliamentReducerErrorV1::ZeroCommitmentRoot);
        }
        let ballot = self.precheck_freeze_timed_ovn_corpus(
            governance_attempt_id,
            ballot_attempt_id,
            current_height,
        )?;
        if ballot.survivor_root != Some(survivor_root) {
            return Err(ParliamentReducerErrorV1::AcceptedCorpusMutation);
        }
        if ballot.survivors != Some(accepted_ballots)
            || accepted_ballots < MIN_PARLIAMENT_HIDDEN_BALLOT_ANONYMITY_V1
            || accepted_ballots > ballot.max_corpus_entries
        {
            return Err(ParliamentReducerErrorV1::InvalidBallotCount);
        }
        let ballot = self
            .ballots
            .get_mut(&ballot_attempt_id)
            .expect("ballot checked above");
        ballot.corpus_root = Some(corpus_root);
        ballot.accepted_ballots = Some(accepted_ballots);
        ballot.timed_commitment_root = Some(timed_commitment_root);
        ballot.commitment_closed_at_height = Some(current_height);
        ballot.attempt.status = BallotAttemptStatusV1::AwaitingRelease;
        Ok(())
    }

    /// Consume one finalized pulse for an exact canonical batch of timed openings.
    ///
    /// All awaiting ballots for the supplied session-height slot must be listed
    /// in strict identifier order. This permits legitimate simultaneous opening
    /// while rejecting subset, later, and cross-batch pulse reuse.
    ///
    /// # Errors
    /// Returns an error for an incomplete/noncanonical batch, early release,
    /// wrong binding, pulse reuse, wrong attempt, or replay.
    pub fn begin_ballot_opening_batch(
        &mut self,
        governance_attempt_id: GovernanceAttemptId,
        ballot_attempt_ids: Vec<BallotAttemptId>,
        release_beacon_session_id: BeaconSessionId,
        release_height: u64,
        at_height: u64,
        pulse_id: BeaconPulseId,
    ) -> Result<(), ParliamentReducerErrorV1> {
        self.ensure_active(governance_attempt_id)?;
        if ballot_attempt_ids.is_empty()
            || !ballot_attempt_ids.windows(2).all(|pair| pair[0] < pair[1])
        {
            return Err(ParliamentReducerErrorV1::PulseBindingMismatch);
        }
        if pulse_id.as_bytes().iter().all(|byte| *byte == 0) {
            return Err(ParliamentReducerErrorV1::DuplicateOrZeroIdentifier(
                ParliamentReducerEntityV1::BallotAttempt,
            ));
        }
        if at_height < release_height {
            return Err(ParliamentReducerErrorV1::ReleaseHeightNotReached);
        }
        let expected: Vec<_> = self
            .ballots
            .values()
            .filter(|ballot| {
                ballot.attempt.status == BallotAttemptStatusV1::AwaitingRelease
                    && ballot.release_beacon_session_id == Some(release_beacon_session_id)
                    && ballot.release_height == Some(release_height)
            })
            .map(|ballot| ballot.attempt.id)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        if ballot_attempt_ids != expected {
            return Err(ParliamentReducerErrorV1::PulseBindingMismatch);
        }
        for ballot_id in &ballot_attempt_ids {
            let ballot =
                self.ballots
                    .get(ballot_id)
                    .ok_or(ParliamentReducerErrorV1::UnknownEntity(
                        ParliamentReducerEntityV1::BallotAttempt,
                    ))?;
            let body = self.bodies.get(&ballot.attempt.body_instance_id).ok_or(
                ParliamentReducerErrorV1::UnknownEntity(ParliamentReducerEntityV1::BodyInstance),
            )?;
            if body.instance.governance_attempt_id != governance_attempt_id
                || ballot.attempt.status != BallotAttemptStatusV1::AwaitingRelease
                || ballot.release_beacon_session_id != Some(release_beacon_session_id)
                || ballot.release_height != Some(release_height)
                || ballot
                    .accepted_ballots
                    .is_none_or(|accepted| accepted < MIN_PARLIAMENT_HIDDEN_BALLOT_ANONYMITY_V1)
                || at_height > ballot.opening_deadline_height
                || !timed_commitment_completed_in_window(ballot)
            {
                return Err(ParliamentReducerErrorV1::PulseBindingMismatch);
            }
        }
        if self.used_pulse_ids.contains_key(&pulse_id)
            || self
                .used_pulse_slots
                .contains_key(&ParliamentPulseSlotV1::new(
                    release_beacon_session_id,
                    release_height,
                ))
        {
            return Err(ParliamentReducerErrorV1::BeaconPulseAlreadyConsumed);
        }
        for ballot_id in &ballot_attempt_ids {
            let ballot = self
                .ballots
                .get_mut(ballot_id)
                .expect("ballot batch checked above");
            ballot.release_pulse_id = Some(pulse_id);
            ballot.opening_height = Some(at_height);
            ballot.attempt.status = BallotAttemptStatusV1::Opening;
        }
        self.used_pulse_ids.insert(
            pulse_id,
            ParliamentPulseConsumerV1::BallotBatch(ballot_attempt_ids),
        );
        self.used_pulse_slots.insert(
            ParliamentPulseSlotV1::new(release_beacon_session_id, release_height),
            pulse_id,
        );
        Ok(())
    }

    /// Mark an objectively expired ballot phase as `NoResult`.
    ///
    /// There is no manual or plaintext fallback. A retry must register a fresh
    /// ballot attempt and, if it reaches timed sealing, a fresh TLE session.
    ///
    /// # Errors
    /// Returns an error for an unknown/wrong attempt or a terminal/replayed
    /// ballot transition.
    pub fn fail_ballot_no_result(
        &mut self,
        governance_attempt_id: GovernanceAttemptId,
        ballot_attempt_id: BallotAttemptId,
        release_pulse_available: bool,
        current_height: u64,
    ) -> Result<(), ParliamentReducerErrorV1> {
        self.ensure_active(governance_attempt_id)?;
        let proposal_redraw_budget_exhausted =
            self.randomness_redraws_used_v1()? == MAX_PARLIAMENT_RANDOMNESS_REDRAWS_V1;
        let ballot =
            self.ballots
                .get(&ballot_attempt_id)
                .ok_or(ParliamentReducerErrorV1::UnknownEntity(
                    ParliamentReducerEntityV1::BallotAttempt,
                ))?;
        if matches!(
            ballot.attempt.status,
            BallotAttemptStatusV1::Finalized
                | BallotAttemptStatusV1::NoResult
                | BallotAttemptStatusV1::Superseded
        ) {
            return Err(ParliamentReducerErrorV1::InvalidLifecycleTransition(
                ParliamentReducerEntityV1::BallotAttempt,
            ));
        }
        let failure_kind = classify_ballot_failure(ballot, release_pulse_available, current_height)
            .ok_or(ParliamentReducerErrorV1::BallotFailureKindMismatch)?;
        let failure_root = parliament_ballot_failure_root_v1(
            governance_attempt_id,
            ballot_attempt_id,
            failure_kind,
            current_height,
        );
        let body_id = ballot.attempt.body_instance_id;
        let body = self
            .bodies
            .get(&body_id)
            .ok_or(ParliamentReducerErrorV1::UnknownEntity(
                ParliamentReducerEntityV1::BodyInstance,
            ))?;
        if body.instance.governance_attempt_id != governance_attempt_id
            || self.active_ballots.get(&body_id) != Some(&ballot_attempt_id)
        {
            return Err(ParliamentReducerErrorV1::ImmutableBindingMismatch);
        }
        let ballot = self
            .ballots
            .get_mut(&ballot_attempt_id)
            .expect("ballot checked above");
        let retry_budget_exhausted = ballot.attempt.sequence == ballot.max_ballot_retries;
        ballot.failure_root = Some(failure_root);
        ballot.failure_kind = Some(failure_kind);
        ballot.failure_height = Some(current_height);
        ballot.attempt.status = BallotAttemptStatusV1::NoResult;
        self.bodies
            .get_mut(&body_id)
            .expect("body checked above")
            .instance
            .status = BodyInstanceStatusV1::NoResult;
        if retry_budget_exhausted || proposal_redraw_budget_exhausted {
            self.attempt.status = GovernanceAttemptStatusV1::Rejected;
        }
        Ok(())
    }
}

impl ParliamentAttemptStateV1 {
    /// Finalize a cryptographically opened aggregate and its body result.
    ///
    /// The accepted corpus root/count, recovery root, TLE session, original-seat
    /// denominator, and complete survivor opening are rechecked. An approved
    /// Policy Jury with a strictly sub-five-percent decisive margin dynamically
    /// requires a fresh, disjoint Confirmation Jury. Exactly five percent does
    /// not trigger confirmation. A narrow result is not committed when fewer
    /// than the V1 anonymity floor of eligible fresh Confirmation candidates remain or when its
    /// required fresh draw would exceed the proposal-wide redraw budget; the
    /// verified opening instead becomes an objective terminal `NoResult`.
    ///
    /// # Errors
    /// Returns an error for replay, wrong bindings, a mutated corpus, incomplete
    /// opening, malformed tally, zero roots, or wrong attempt/stage.
    #[expect(
        clippy::too_many_arguments,
        reason = "every final private-ballot binding is rechecked explicitly"
    )]
    pub fn finalize_opened_ballot(
        &mut self,
        governance_attempt_id: GovernanceAttemptId,
        ballot_attempt_id: BallotAttemptId,
        corpus_root: [u8; 32],
        no_recovery_root: [u8; 32],
        tle_session_id: TleSessionId,
        opening_root: [u8; 32],
        opened_survivors: u32,
        tally: ParliamentAggregateTallyV1,
        eligible_confirmation_candidates: u32,
        result_height: u64,
    ) -> Result<ParliamentAggregateOutcomeV1, ParliamentReducerErrorV1> {
        self.ensure_active(governance_attempt_id)?;
        if root_is_zero(&opening_root) {
            return Err(ParliamentReducerErrorV1::ZeroCommitmentRoot);
        }
        let ballot =
            self.ballots
                .get(&ballot_attempt_id)
                .ok_or(ParliamentReducerErrorV1::UnknownEntity(
                    ParliamentReducerEntityV1::BallotAttempt,
                ))?;
        if ballot.attempt.status != BallotAttemptStatusV1::Opening
            || ballot.release_pulse_id.is_none()
            || ballot.opening_height.is_none()
        {
            return Err(ParliamentReducerErrorV1::InvalidLifecycleTransition(
                ParliamentReducerEntityV1::BallotAttempt,
            ));
        }
        if ballot.corpus_root != Some(corpus_root)
            || ballot.no_recovery_root != Some(no_recovery_root)
            || ballot.tle_session_id != Some(tle_session_id)
            || tally.accepted_ballots != ballot.accepted_ballots.unwrap_or(u32::MAX)
        {
            return Err(ParliamentReducerErrorV1::AcceptedCorpusMutation);
        }
        if tally.original_seats != ballot.attempt.original_seats {
            return Err(ParliamentReducerErrorV1::InvalidBallotCount);
        }
        if ballot.survivors != Some(opened_survivors) {
            return Err(ParliamentReducerErrorV1::IncompleteOpening);
        }
        if opened_survivors < MIN_PARLIAMENT_HIDDEN_BALLOT_ANONYMITY_V1
            || tally.accepted_ballots < MIN_PARLIAMENT_HIDDEN_BALLOT_ANONYMITY_V1
        {
            return Err(ParliamentReducerErrorV1::InvalidBallotCount);
        }
        let opening_height = ballot
            .opening_height
            .ok_or(ParliamentReducerErrorV1::IncompleteOpening)?;
        let registration_root = ballot
            .registration_root
            .ok_or(ParliamentReducerErrorV1::IncompleteCertificate)?;
        let dropout_root = ballot
            .dropout_root
            .ok_or(ParliamentReducerErrorV1::IncompleteCertificate)?;
        let survivor_root = ballot
            .survivor_root
            .ok_or(ParliamentReducerErrorV1::IncompleteCertificate)?;
        let timed_commitment_root = ballot
            .timed_commitment_root
            .ok_or(ParliamentReducerErrorV1::IncompleteCertificate)?;
        let release_beacon_session_id = ballot
            .release_beacon_session_id
            .ok_or(ParliamentReducerErrorV1::IncompleteCertificate)?;
        let tle_key_session_id = ballot
            .tle_key_session_id
            .ok_or(ParliamentReducerErrorV1::IncompleteCertificate)?;
        let release_height = ballot
            .release_height
            .ok_or(ParliamentReducerErrorV1::IncompleteCertificate)?;
        let opening_deadline_height = ballot.opening_deadline_height;
        let release_pulse_id = ballot
            .release_pulse_id
            .ok_or(ParliamentReducerErrorV1::IncompleteCertificate)?;
        let ballot_attempt_sequence = ballot.attempt.sequence;
        let registered_at_height = ballot.registered_at_height;
        let registration_close_height = ballot.registration_close_height;
        let survivor_freeze_height = ballot.survivor_freeze_height;
        let commitment_close_height = ballot.commitment_close_height;
        let registration_closed_at_height = ballot
            .registration_closed_at_height
            .ok_or(ParliamentReducerErrorV1::IncompleteCertificate)?;
        let survivors_frozen_at_height = ballot
            .survivors_frozen_at_height
            .ok_or(ParliamentReducerErrorV1::IncompleteCertificate)?;
        let commitment_closed_at_height = ballot
            .commitment_closed_at_height
            .ok_or(ParliamentReducerErrorV1::IncompleteCertificate)?;
        let max_ballot_retries = ballot.max_ballot_retries;
        let max_corpus_entries = ballot.max_corpus_entries;
        if opening_height < release_height
            || opening_height > opening_deadline_height
            || result_height < opening_height
            || result_height > opening_deadline_height
        {
            return Err(ParliamentReducerErrorV1::InvalidCertificateHeight);
        }
        tally
            .validate()
            .map_err(|_| ParliamentReducerErrorV1::InvalidTally)?;
        let body_instance_id = ballot.attempt.body_instance_id;
        let body =
            self.bodies
                .get(&body_instance_id)
                .ok_or(ParliamentReducerErrorV1::UnknownEntity(
                    ParliamentReducerEntityV1::BodyInstance,
                ))?;
        let body_role = body.instance.body;
        self.ensure_current_body(body_role)?;
        if body.instance.governance_attempt_id != governance_attempt_id
            || body.instance.status != BodyInstanceStatusV1::Balloting
            || self.active_ballots.get(&body_instance_id) != Some(&ballot_attempt_id)
            || self.body_bindings.contains_key(&body_role)
        {
            return Err(ParliamentReducerErrorV1::ImmutableBindingMismatch);
        }
        let mut outcome = tally
            .decision()
            .map_err(|_| ParliamentReducerErrorV1::InvalidTally)?;
        if self.attempt.risk_tier == RiskTierV1::Emergency
            && body_role == ParliamentBody::PolicyJury
            && outcome == ParliamentAggregateOutcomeV1::Approved
            && tally.aye < parliament_quorum_seats_v1(tally.original_seats)
        {
            outcome = ParliamentAggregateOutcomeV1::Rejected;
        }
        let result_root = parliament_ballot_result_root_v1(
            governance_attempt_id,
            body_instance_id,
            ballot_attempt_id,
            opening_root,
            tally,
            outcome,
            result_height,
        );
        if root_is_zero(&result_root) {
            return Err(ParliamentReducerErrorV1::ZeroCommitmentRoot);
        }
        let election = self
            .elections
            .get(&body.instance.election_attempt_id)
            .ok_or(ParliamentReducerErrorV1::UnknownEntity(
                ParliamentReducerEntityV1::BodyElection,
            ))?;
        if result_height <= election.attempt.request.pulse_height {
            return Err(ParliamentReducerErrorV1::InvalidCertificateHeight);
        }
        let requires_confirmation = outcome == ParliamentAggregateOutcomeV1::Approved
            && body_role == ParliamentBody::PolicyJury
            && tally
                .requires_confirmation()
                .map_err(|_| ParliamentReducerErrorV1::InvalidTally)?;
        if requires_confirmation
            && self
                .required_bodies
                .iter()
                .any(|entry| entry.body == ParliamentBody::ConfirmationJury)
        {
            return Err(ParliamentReducerErrorV1::InvalidRequiredBodyPipeline);
        }
        let confirmation_failure_kind = if requires_confirmation
            && eligible_confirmation_candidates < MIN_PARLIAMENT_HIDDEN_BALLOT_ANONYMITY_V1
        {
            Some(ParliamentBallotFailureKindV1::ConfirmationJuryCapacityUnavailable)
        } else if requires_confirmation
            && self.randomness_redraws_used_v1()? == MAX_PARLIAMENT_RANDOMNESS_REDRAWS_V1
        {
            Some(ParliamentBallotFailureKindV1::RandomnessRedrawBudgetExhausted)
        } else {
            None
        };
        if let Some(failure_kind) = confirmation_failure_kind {
            let failure_root = parliament_ballot_failure_root_v1(
                governance_attempt_id,
                ballot_attempt_id,
                failure_kind,
                result_height,
            );
            let ballot = self
                .ballots
                .get_mut(&ballot_attempt_id)
                .expect("ballot checked above");
            ballot.opening_root = Some(opening_root);
            ballot.tally = Some(tally);
            ballot.outcome = Some(outcome);
            ballot.failure_root = Some(failure_root);
            ballot.failure_kind = Some(failure_kind);
            ballot.failure_height = Some(result_height);
            ballot.eligible_confirmation_candidates = Some(eligible_confirmation_candidates);
            ballot.attempt.status = BallotAttemptStatusV1::NoResult;
            self.bodies
                .get_mut(&body_instance_id)
                .expect("body checked above")
                .instance
                .status = BodyInstanceStatusV1::NoResult;
            self.attempt.status = GovernanceAttemptStatusV1::Rejected;
            return Ok(ParliamentAggregateOutcomeV1::NoResult);
        }
        {
            let ballot = self
                .ballots
                .get_mut(&ballot_attempt_id)
                .expect("ballot checked above");
            ballot.opening_root = Some(opening_root);
            ballot.tally = Some(tally);
            ballot.outcome = Some(outcome);
            ballot.attempt.status = BallotAttemptStatusV1::Finalized;
        }
        let ballot_binding = ParliamentBallotCertificateBindingV1 {
            ballot_attempt_id,
            ballot_attempt_sequence,
            tle_session_id,
            tle_key_session_id,
            registration_root,
            dropout_root,
            survivor_root,
            corpus_root,
            no_recovery_root,
            timed_commitment_root,
            release_beacon_session_id,
            registered_at_height,
            registration_close_height,
            survivor_freeze_height,
            commitment_close_height,
            registration_closed_at_height,
            survivors_frozen_at_height,
            commitment_closed_at_height,
            max_ballot_retries,
            max_corpus_entries,
            release_height,
            opening_deadline_height,
            release_pulse_id,
            opening_height,
            opening_root,
            tally,
            outcome,
        };
        {
            let body = self
                .bodies
                .get_mut(&body_instance_id)
                .expect("body checked above");
            body.result_root = Some(result_root);
            body.result_height = Some(result_height);
            body.ballot_binding = Some(ballot_binding);
            body.instance.status = match outcome {
                ParliamentAggregateOutcomeV1::Approved => BodyInstanceStatusV1::Approved,
                ParliamentAggregateOutcomeV1::Rejected => BodyInstanceStatusV1::Rejected,
                ParliamentAggregateOutcomeV1::NoQuorum => BodyInstanceStatusV1::NoQuorum,
                ParliamentAggregateOutcomeV1::NoResult => BodyInstanceStatusV1::NoResult,
            };
        }
        let binding = self.build_body_binding(body_instance_id)?;
        self.body_bindings.insert(body_role, binding);

        match outcome {
            ParliamentAggregateOutcomeV1::Approved => {
                if requires_confirmation {
                    self.required_bodies.push(RequiredParliamentBodyV1 {
                        body: ParliamentBody::ConfirmationJury,
                        decision_mode: ParliamentDecisionModeV1::HiddenBindingBallot,
                    });
                }
                self.advance_after_body(body_role)?;
            }
            ParliamentAggregateOutcomeV1::Rejected
            | ParliamentAggregateOutcomeV1::NoQuorum
            | ParliamentAggregateOutcomeV1::NoResult => {
                self.attempt.status = GovernanceAttemptStatusV1::Rejected;
            }
        }
        Ok(outcome)
    }

    /// Construct and freeze the complete automatic governance certificate.
    ///
    /// The reducer supplies the exact ordered body bindings; callers cannot
    /// substitute a roster, pulse, corpus, TLE session, result root, proposal,
    /// policy, effect, or compare-and-set head.
    ///
    /// # Errors
    /// Returns an error unless every required body has a final consistent
    /// binding, certification is atomic with the final body result, and
    /// enactment is strictly later than certification.
    pub fn construct_certificate(
        &mut self,
        governance_attempt_id: GovernanceAttemptId,
        certified_at_height: u64,
        enact_at_height: u64,
    ) -> Result<GovernanceCertificateV1, ParliamentReducerErrorV1> {
        self.ensure_active(governance_attempt_id)?;
        self.ensure_stage(GovernanceStageV1::Certification)?;
        if certified_at_height == 0 || enact_at_height <= certified_at_height {
            return Err(ParliamentReducerErrorV1::InvalidCertificateHeight);
        }
        if self.certificate.is_some() || self.body_bindings.len() != self.required_bodies.len() {
            return Err(ParliamentReducerErrorV1::IncompleteCertificate);
        }
        let mut body_bindings = Vec::with_capacity(self.required_bodies.len());
        for requirement in &self.required_bodies {
            let binding = self
                .body_bindings
                .get(&requirement.body)
                .cloned()
                .ok_or(ParliamentReducerErrorV1::IncompleteCertificate)?;
            if binding.body != requirement.body {
                return Err(ParliamentReducerErrorV1::CertificateBindingMismatch);
            }
            match requirement.decision_mode {
                ParliamentDecisionModeV1::PublicFinding
                    if binding.public_finding.is_none() || binding.ballot.is_some() =>
                {
                    return Err(ParliamentReducerErrorV1::CertificateBindingMismatch);
                }
                ParliamentDecisionModeV1::HiddenBindingBallot
                    if binding.public_finding.is_some() || binding.ballot.is_none() =>
                {
                    return Err(ParliamentReducerErrorV1::IncompleteCertificate);
                }
                _ => {}
            }
            let rebuilt = self.build_body_binding(binding.body_instance_id)?;
            if rebuilt != binding {
                return Err(ParliamentReducerErrorV1::CertificateBindingMismatch);
            }
            body_bindings.push(binding);
        }
        let final_result_height = body_bindings
            .iter()
            .map(|binding| binding.result_height)
            .max()
            .ok_or(ParliamentReducerErrorV1::IncompleteCertificate)?;
        if certified_at_height != final_result_height {
            return Err(ParliamentReducerErrorV1::InvalidCertificateHeight);
        }
        let certificate = GovernanceCertificateV1 {
            proposal_content_id: self.attempt.proposal_content_id,
            governance_attempt_id,
            governance_attempt_sequence: self.attempt.sequence,
            risk_tier: self.attempt.risk_tier,
            body_bindings,
            policy_version: self.policy_version,
            effect_preimage_hash: self.effect_preimage_hash,
            expected_head: self.expected_head,
            certified_at_height,
            enact_at_height,
        };
        certificate
            .validate()
            .map_err(|_| ParliamentReducerErrorV1::CertificateBindingMismatch)?;
        self.certificate = Some(certificate.clone());
        self.attempt.stage = GovernanceStageV1::Enactment;
        self.attempt.status = GovernanceAttemptStatusV1::Certified;
        Ok(certificate)
    }

    fn ensure_certified_for_execution(
        &self,
        governance_attempt_id: GovernanceAttemptId,
        at_height: u64,
    ) -> Result<&GovernanceCertificateV1, ParliamentReducerErrorV1> {
        self.ensure_attempt(governance_attempt_id)?;
        if self.attempt.status != GovernanceAttemptStatusV1::Certified
            || self.attempt.stage != GovernanceStageV1::Enactment
        {
            return Err(ParliamentReducerErrorV1::InvalidLifecycleTransition(
                ParliamentReducerEntityV1::Certificate,
            ));
        }
        let certificate = self
            .certificate
            .as_ref()
            .ok_or(ParliamentReducerErrorV1::IncompleteCertificate)?;
        if at_height != certificate.enact_at_height {
            return Err(ParliamentReducerErrorV1::WrongEnactmentHeight);
        }
        Ok(certificate)
    }

    /// Mark a due certified effect enacted.
    ///
    /// # Errors
    /// Returns an error before the exact due height, for a wrong attempt, or for
    /// any replay/noncertified transition.
    pub fn mark_enacted(
        &mut self,
        governance_attempt_id: GovernanceAttemptId,
        at_height: u64,
    ) -> Result<(), ParliamentReducerErrorV1> {
        self.ensure_certified_for_execution(governance_attempt_id, at_height)?;
        self.attempt.status = GovernanceAttemptStatusV1::Enacted;
        self.terminal_height = Some(at_height);
        Ok(())
    }

    /// Mark a due certificate superseded by a different compare-and-set head.
    ///
    /// # Errors
    /// Returns an error for an unchanged, malformed, or cross-subject head,
    /// early execution, a wrong attempt, or any replay/noncertified transition.
    pub fn mark_superseded(
        &mut self,
        governance_attempt_id: GovernanceAttemptId,
        at_height: u64,
        observed_head: GovernanceExpectedHeadV1,
    ) -> Result<(), ParliamentReducerErrorV1> {
        let certificate = self.ensure_certified_for_execution(governance_attempt_id, at_height)?;
        if observed_head == certificate.expected_head {
            return Err(ParliamentReducerErrorV1::ExpectedHeadUnchanged);
        }
        if !expected_head_is_valid(observed_head)
            || expected_head_subject(observed_head)
                != expected_head_subject(certificate.expected_head)
        {
            return Err(ParliamentReducerErrorV1::InvalidSupersedingHead);
        }
        self.attempt.status = GovernanceAttemptStatusV1::Superseded;
        self.terminal_height = Some(at_height);
        self.superseding_head = Some(observed_head);
        Ok(())
    }

    /// Mark deterministic execution failure for the exact due certificate.
    ///
    /// The failure transcript root is derived entirely from the retained
    /// certificate and its immutable enactment height. Callers cannot supply
    /// either an effect binding or a failure root.
    ///
    /// # Errors
    /// Returns an error before or after the exact due height, for a wrong
    /// attempt, or for any replay/noncertified transition.
    pub fn mark_execution_failed(
        &mut self,
        governance_attempt_id: GovernanceAttemptId,
        at_height: u64,
    ) -> Result<[u8; 32], ParliamentReducerErrorV1> {
        let certificate = self.ensure_certified_for_execution(governance_attempt_id, at_height)?;
        let failure_root = parliament_execution_failure_root_v1(certificate, at_height);
        self.attempt.status = GovernanceAttemptStatusV1::ExecutionFailed;
        self.terminal_height = Some(at_height);
        self.execution_failure_root = Some(failure_root);
        Ok(failure_root)
    }
}
