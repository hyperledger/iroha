impl ParliamentAttemptStateV1 {
    /// Validate only the exact canonical framed size of this attempt state.
    ///
    /// This deliberately performs no semantic replay so snapshot restore can
    /// enforce the authoritative byte bound even in emergency-fast mode.
    ///
    /// # Errors
    /// Returns a fail-closed size error when canonical counting serialization
    /// fails or the frame exceeds the V1 protocol maximum.
    pub(crate) fn validate_encoded_size_v1(&self) -> Result<(), ParliamentReducerErrorV1> {
        let encoded_frame_len = norito::core::encoded_frame_len(self)
            .map_err(|_| ParliamentReducerErrorV1::AttemptStateSizeLimitExceeded)?;
        if encoded_frame_len > MAX_PARLIAMENT_ATTEMPT_STATE_BYTES_V1 {
            return Err(ParliamentReducerErrorV1::AttemptStateSizeLimitExceeded);
        }
        Ok(())
    }

    fn expected_completed_body_count_v1(&self) -> Result<usize, ParliamentReducerErrorV1> {
        let body_index = || {
            self.required_bodies
                .iter()
                .position(|required| stage_for_body(required.body) == self.attempt.stage)
                .ok_or(ParliamentReducerErrorV1::InvalidRequiredBodyPipeline)
        };
        match self.attempt.status {
            GovernanceAttemptStatusV1::Active => match self.attempt.stage {
                GovernanceStageV1::Qualification => Ok(0),
                GovernanceStageV1::Certification | GovernanceStageV1::Enactment => {
                    Ok(self.required_bodies.len())
                }
                _ => body_index(),
            },
            GovernanceAttemptStatusV1::Rejected => {
                let index = body_index()?;
                let body_role = self.required_bodies[index].body;
                let proposal_redraw_budget_exhausted =
                    self.randomness_redraws_used_v1()? == MAX_PARLIAMENT_RANDOMNESS_REDRAWS_V1;
                if let Some(current_body) = self.sealed_body_for_role(body_role) {
                    match current_body.instance.status {
                        BodyInstanceStatusV1::NoResult => return Ok(index),
                        BodyInstanceStatusV1::Approved
                        | BodyInstanceStatusV1::Rejected
                        | BodyInstanceStatusV1::NoQuorum => return Ok(index + 1),
                        // A live current-stage body: an exhausted sortition rejected the attempt.
                        _ => {}
                    }
                }
                // Bodies are drawn together, so the body whose sortition exhausted may serve a
                // later stage than the current one; neither it nor the current body completed.
                let exhausted_sortition = self.required_bodies[index..].iter().any(|required| {
                    let exhausted_sortition_election = self
                        .active_elections
                        .get(&required.body)
                        .and_then(|id| self.elections.get(id))
                        .is_some_and(|election| {
                            election.attempt.status == BodyElectionAttemptStatusV1::NoRoster
                                && (election.attempt.sequence
                                    == MAX_PARLIAMENT_SORTITION_RETRIES_V1
                                    || proposal_redraw_budget_exhausted)
                                && election.failure_kind.is_some()
                                && election.failure_height.is_some()
                        });
                    let exhausted_sortition_capacity = self
                        .active_sortition_capacity_failures
                        .get(&required.body)
                        .and_then(|id| self.sortition_capacity_failures.get(id))
                        .is_some_and(|failure| {
                            failure.status == BodyElectionAttemptStatusV1::NoRoster
                                && (failure.sequence == MAX_PARLIAMENT_SORTITION_RETRIES_V1
                                    || proposal_redraw_budget_exhausted)
                        });
                    exhausted_sortition_election || exhausted_sortition_capacity
                });
                exhausted_sortition
                    .then_some(index)
                    .ok_or(ParliamentReducerErrorV1::IncompleteCertificate)
            }
            GovernanceAttemptStatusV1::Certified
            | GovernanceAttemptStatusV1::Enacted
            | GovernanceAttemptStatusV1::Superseded
            | GovernanceAttemptStatusV1::ExecutionFailed => {
                if self.attempt.stage != GovernanceStageV1::Enactment {
                    return Err(ParliamentReducerErrorV1::IncompleteCertificate);
                }
                Ok(self.required_bodies.len())
            }
        }
    }

    /// Validate all cross-object bindings after decoding persisted reducer state.
    ///
    /// This audit is intentionally stricter than individual transition checks:
    /// it proves map keys, immutable identifiers, roots, lifecycle-dependent
    /// fields, consumed pulse batches, TLE ownership, roster denominators, body
    /// bindings, and any certificate are mutually consistent.
    ///
    /// # Errors
    /// Returns the first fail-closed invariant violation found.
    pub fn validate(&self) -> Result<(), ParliamentReducerErrorV1> {
        self.validate_encoded_size_v1()?;
        if self.attempt.id.as_bytes().iter().all(|byte| *byte == 0)
            || self
                .attempt
                .proposal_content_id
                .as_bytes()
                .iter()
                .all(|byte| *byte == 0)
            || root_is_zero(&self.effect_preimage_hash)
            || !expected_head_is_valid(self.expected_head)
            || !self.attempt.has_canonical_id()
        {
            return Err(ParliamentReducerErrorV1::ImmutableBindingMismatch);
        }
        if self.policy_version != PARLIAMENT_GOVERNANCE_POLICY_VERSION_V1 {
            return Err(ParliamentReducerErrorV1::UnsupportedPolicyVersion);
        }
        if self.attempt.sequence > MAX_PARLIAMENT_GOVERNANCE_ATTEMPT_RETRIES_V1 {
            return Err(ParliamentReducerErrorV1::GovernanceAttemptRetryLimitExceeded);
        }
        let proposal_redraw_budget_exhausted =
            self.randomness_redraws_used_v1()? == MAX_PARLIAMENT_RANDOMNESS_REDRAWS_V1;
        if self.sortition_pulse_delay_blocks == 0
            || self.sortition_pulse_epoch_length_blocks
                < MIN_PARLIAMENT_SORTITION_PULSE_EPOCH_LENGTH_BLOCKS_V1
        {
            return Err(ParliamentReducerErrorV1::InvalidSortitionPulseSchedule);
        }
        // Exact recheck of every generation slot from frozen attempt fields only.
        let invalid_sortition_generation_slots = self.invalid_sortition_generation_slots_v1();
        if !persisted_pipeline_is_canonical(&self.required_bodies) {
            return Err(ParliamentReducerErrorV1::InvalidRequiredBodyPipeline);
        }
        let expected_completed_bodies = self.expected_completed_body_count_v1()?;
        if self.body_bindings.len() != expected_completed_bodies
            || self.required_bodies[..expected_completed_bodies]
                .iter()
                .any(|required| !self.body_bindings.contains_key(&required.body))
        {
            return Err(ParliamentReducerErrorV1::IncompleteCertificate);
        }
        let confirmation_required = self
            .required_bodies
            .last()
            .is_some_and(|entry| entry.body == ParliamentBody::ConfirmationJury);
        let policy_sortition_started = self
            .elections
            .values()
            .any(|election| election.attempt.request.body == ParliamentBody::PolicyJury)
            || self
                .sortition_capacity_failures
                .values()
                .any(|failure| failure.body == ParliamentBody::PolicyJury);
        if self.risk_locked != policy_sortition_started {
            return Err(ParliamentReducerErrorV1::ImmutableBindingMismatch);
        }
        let active_exhausted_election = self.active_elections.values().any(|id| {
            self.elections.get(id).is_some_and(|election| {
                election.attempt.status == BodyElectionAttemptStatusV1::NoRoster
                    && (election.attempt.sequence == MAX_PARLIAMENT_SORTITION_RETRIES_V1
                        || proposal_redraw_budget_exhausted)
            })
        });
        let active_exhausted_capacity =
            self.active_sortition_capacity_failures.values().any(|id| {
                self.sortition_capacity_failures
                    .get(id)
                    .is_some_and(|failure| {
                        failure.status == BodyElectionAttemptStatusV1::NoRoster
                            && (failure.sequence == MAX_PARLIAMENT_SORTITION_RETRIES_V1
                                || proposal_redraw_budget_exhausted)
                    })
            });
        if self.attempt.status == GovernanceAttemptStatusV1::Active
            && (active_exhausted_election || active_exhausted_capacity)
        {
            return Err(ParliamentReducerErrorV1::SortitionRetryLimitExceeded);
        }
        let mut unique_candidate_snapshots = BTreeSet::new();
        if self.candidate_snapshots.iter().any(|snapshot| {
            snapshot.is_empty()
                || !candidate_snapshot_fits_resource_bounds_v1(snapshot)
                || !snapshot.windows(2).all(|pair| pair[0] < pair[1])
                || !unique_candidate_snapshots.insert(snapshot)
        }) {
            return Err(ParliamentReducerErrorV1::InvalidCandidateSnapshot);
        }

        let mut request_ids = BTreeSet::new();
        let mut referenced_candidate_snapshots = BTreeSet::new();
        let mut sortition_sequences =
            BTreeMap::<ParliamentBody, BTreeMap<u32, (BodyElectionAttemptId, bool)>>::new();
        for (id, failure) in &self.sortition_capacity_failures {
            let candidate_count = u32::try_from(failure.candidate_snapshot.len())
                .map_err(|_| ParliamentReducerErrorV1::InvalidCandidateSnapshot)?;
            let request_intent = SortitionRequestV1 {
                id: failure.request_intent_id,
                governance_attempt_id: self.attempt.id,
                body_election_attempt_id: failure.body_election_attempt_id,
                body: failure.body,
                candidate_root: failure.candidate_root,
                candidate_count,
                target_seats: failure.target_seats,
                request_height: failure.request_height,
                pulse_height: failure.pulse_height,
                beacon_session_id: failure.beacon_session_id,
            };
            let requirement = self.requirement_for_body(failure.body)?;
            if *id != failure.body_election_attempt_id
                || *id
                    != BodyElectionAttemptId::derive_v1(
                        self.attempt.id,
                        failure.body,
                        failure.sequence,
                    )
                || failure.sequence > MAX_PARLIAMENT_SORTITION_RETRIES_V1
                || hidden_ballot_population_meets_anonymity_floor_v1(
                    failure.candidate_snapshot.len(),
                )
                || !candidate_snapshot_fits_resource_bounds_v1(&failure.candidate_snapshot)
                || !failure
                    .candidate_snapshot
                    .windows(2)
                    .all(|pair| pair[0] < pair[1])
                || root_is_zero(&failure.candidate_root)
                || failure.candidate_root
                    != parliament_candidate_root_v1(
                        self.attempt.id,
                        failure.body,
                        &failure.candidate_snapshot,
                    )
                || failure.request_intent_id != request_intent.canonical_id()
                || failure.target_seats == 0
                || failure.target_seats > MAX_PARLIAMENT_BODY_TARGET_SEATS_V1
                || (requirement.decision_mode == ParliamentDecisionModeV1::HiddenBindingBallot
                    && failure.target_seats < MIN_PARLIAMENT_HIDDEN_BALLOT_ANONYMITY_V1)
                || failure
                    .beacon_session_id
                    .as_bytes()
                    .iter()
                    .all(|byte| *byte == 0)
                || failure.failure_height != failure.request_height
                || !matches!(
                    failure.status,
                    BodyElectionAttemptStatusV1::NoRoster | BodyElectionAttemptStatusV1::Superseded
                )
                || !request_ids.insert(failure.request_intent_id)
            {
                return Err(ParliamentReducerErrorV1::InvalidCandidateSnapshot);
            }
            if invalid_sortition_generation_slots.contains(&ParliamentPulseSlotV1::new(
                failure.beacon_session_id,
                failure.pulse_height,
            )) {
                return Err(ParliamentReducerErrorV1::InvalidSortitionPulseSchedule);
            }
            if failure.body == ParliamentBody::ConfirmationJury {
                let policy_result_height = self
                    .body_bindings
                    .get(&ParliamentBody::PolicyJury)
                    .map(|binding| binding.result_height)
                    .ok_or(ParliamentReducerErrorV1::ConfirmationJuryNotFresh)?;
                let policy_members = self
                    .sealed_body_for_role(ParliamentBody::PolicyJury)
                    .ok_or(ParliamentReducerErrorV1::ConfirmationJuryNotFresh)?
                    .assignments
                    .iter()
                    .map(|assignment| assignment.member.clone())
                    .collect::<BTreeSet<_>>();
                if failure.request_height < policy_result_height
                    || (failure.sequence == 0 && failure.request_height != policy_result_height)
                    || failure
                        .candidate_snapshot
                        .iter()
                        .any(|candidate| policy_members.contains(candidate))
                {
                    return Err(ParliamentReducerErrorV1::ConfirmationJuryNotFresh);
                }
            }
            if sortition_sequences
                .entry(failure.body)
                .or_default()
                .insert(failure.sequence, (*id, true))
                .is_some()
            {
                return Err(ParliamentReducerErrorV1::RetrySequenceMismatch);
            }
        }
        for (id, election) in &self.elections {
            let request = election.attempt.request;
            let candidate_snapshot_index = usize::try_from(election.candidate_snapshot_index)
                .map_err(|_| ParliamentReducerErrorV1::InvalidCandidateSnapshot)?;
            let candidate_snapshot = self
                .candidate_snapshots
                .get(candidate_snapshot_index)
                .ok_or(ParliamentReducerErrorV1::InvalidCandidateSnapshot)?;
            referenced_candidate_snapshots.insert(candidate_snapshot_index);
            if *id != election.attempt.id
                || *id
                    != BodyElectionAttemptId::derive_v1(
                        self.attempt.id,
                        request.body,
                        election.attempt.sequence,
                    )
                || request.body_election_attempt_id != *id
                || request.governance_attempt_id != self.attempt.id
                || election.attempt.governance_attempt_id != self.attempt.id
                || election.attempt.sequence > MAX_PARLIAMENT_SORTITION_RETRIES_V1
                || !request_ids.insert(request.id)
                || root_is_zero(&request.candidate_root)
                || u32::try_from(candidate_snapshot.len()).ok() != Some(request.candidate_count)
                || request.candidate_root
                    != parliament_candidate_root_v1(
                        self.attempt.id,
                        request.body,
                        candidate_snapshot,
                    )
            {
                return Err(ParliamentReducerErrorV1::InvalidCandidateSnapshot);
            }
            if sortition_sequences
                .entry(request.body)
                .or_default()
                .insert(election.attempt.sequence, (*id, false))
                .is_some()
            {
                return Err(ParliamentReducerErrorV1::RetrySequenceMismatch);
            }
            request
                .validate(None)
                .map_err(|_| ParliamentReducerErrorV1::ImmutableBindingMismatch)?;
            if invalid_sortition_generation_slots.contains(&ParliamentPulseSlotV1::new(
                request.beacon_session_id,
                request.pulse_height,
            )) {
                return Err(ParliamentReducerErrorV1::InvalidSortitionPulseSchedule);
            }
            let requirement = self.requirement_for_body(request.body)?;
            if requirement.decision_mode == ParliamentDecisionModeV1::HiddenBindingBallot {
                if request.target_seats < MIN_PARLIAMENT_HIDDEN_BALLOT_ANONYMITY_V1 {
                    return Err(ParliamentReducerErrorV1::InvalidAssignmentPlan);
                }
                if !hidden_ballot_population_meets_anonymity_floor_v1(candidate_snapshot.len()) {
                    return Err(ParliamentReducerErrorV1::InvalidCandidateSnapshot);
                }
            }
            if request.body == ParliamentBody::ConfirmationJury {
                let policy_result_height = self
                    .body_bindings
                    .get(&ParliamentBody::PolicyJury)
                    .map(|binding| binding.result_height)
                    .ok_or(ParliamentReducerErrorV1::ConfirmationJuryNotFresh)?;
                let policy_members = self
                    .sealed_body_for_role(ParliamentBody::PolicyJury)
                    .ok_or(ParliamentReducerErrorV1::ConfirmationJuryNotFresh)?
                    .assignments
                    .iter()
                    .map(|assignment| assignment.member.clone())
                    .collect::<BTreeSet<_>>();
                if request.request_height < policy_result_height
                    || (election.attempt.sequence == 0
                        && request.request_height != policy_result_height)
                    || candidate_snapshot
                        .iter()
                        .any(|candidate| policy_members.contains(candidate))
                {
                    return Err(ParliamentReducerErrorV1::ConfirmationJuryNotFresh);
                }
            }

            let invited_assignments: Vec<_> = election
                .primary_assignments
                .iter()
                .chain(&election.alternate_assignments)
                .collect();
            let invited_ids: BTreeSet<_> = invited_assignments
                .iter()
                .map(|assignment| assignment.assignment_id)
                .collect();
            let invited_members: BTreeSet<_> = invited_assignments
                .iter()
                .map(|assignment| assignment.member.clone())
                .collect();
            let responses_are_valid = election
                .accepted_assignments
                .is_disjoint(&election.declined_assignments)
                && election.accepted_assignments.is_subset(&invited_ids)
                && election.declined_assignments.is_subset(&invited_ids);
            let assignment_plan_is_valid = election
                .cross_body_assignment_cap
                .is_some_and(|cap| cap > 0)
                && !election.primary_assignments.is_empty()
                && u32::try_from(election.primary_assignments.len()).ok()
                    == Some(request.target_seats.min(request.candidate_count))
                && invited_ids.len() == invited_assignments.len()
                && invited_members.len() == invited_assignments.len()
                && invited_assignments.iter().all(|assignment| {
                    candidate_snapshot.binary_search(&assignment.member).is_ok()
                        && assignment.assignment_id
                            == AssignmentId::derive_v1(*id, &assignment.member)
                })
                && election.assignment_root.is_some_and(|assignment_root| {
                    !root_is_zero(&assignment_root)
                        && election.cross_body_assignment_cap.is_some_and(|cap| {
                            assignment_root
                                == parliament_assignment_plan_root_v1(
                                    *id,
                                    &election.primary_assignments,
                                    &election.alternate_assignments,
                                    cap,
                                )
                        })
                })
                && responses_are_valid;
            let invitation_window_is_valid = matches!(
                (
                    election.invitation_opened_at_height,
                    election.invitation_close_height,
                ),
                (Some(opened), Some(close)) if opened >= request.pulse_height && close >= opened
            );
            match election.attempt.status {
                BodyElectionAttemptStatusV1::AwaitingPulse => {
                    if !election_awaiting_pulse_shape_is_empty(election)
                        || election.failure_kind.is_some()
                        || election.failure_height.is_some()
                    {
                        return Err(ParliamentReducerErrorV1::ImmutableBindingMismatch);
                    }
                }
                BodyElectionAttemptStatusV1::Drawing => {
                    if election.pulse_id.is_none()
                        || election.pulse_output.is_none()
                        || !assignment_plan_is_valid
                        || election.invitation_opened_at_height.is_some()
                        || election.invitation_close_height.is_some()
                        || !election.accepted_assignments.is_empty()
                        || !election.declined_assignments.is_empty()
                        || election.failure_kind.is_some()
                        || election.failure_height.is_some()
                    {
                        return Err(ParliamentReducerErrorV1::InvalidAssignmentPlan);
                    }
                }
                BodyElectionAttemptStatusV1::AcceptingInvitations
                | BodyElectionAttemptStatusV1::Sealed => {
                    if election.pulse_id.is_none()
                        || election.pulse_output.is_none()
                        || !assignment_plan_is_valid
                        || !invitation_window_is_valid
                        || election.failure_kind.is_some()
                        || election.failure_height.is_some()
                    {
                        return Err(ParliamentReducerErrorV1::InvalidAssignmentPlan);
                    }
                    if election.attempt.status == BodyElectionAttemptStatusV1::Sealed {
                        let roster = accepted_roster(election)?;
                        if roster.is_empty()
                            || (requirement.decision_mode
                                == ParliamentDecisionModeV1::HiddenBindingBallot
                                && !hidden_ballot_population_meets_anonymity_floor_v1(roster.len()))
                        {
                            return Err(ParliamentReducerErrorV1::InvalidRoster);
                        }
                    }
                }
                BodyElectionAttemptStatusV1::NoRoster | BodyElectionAttemptStatusV1::Superseded => {
                    // A terminal election always consumed the pulse of its exact slot and
                    // closed its invitation window: no missing-pulse terminal shape exists.
                    let accepted_roster_len = accepted_roster(election)?.len();
                    let drawn_empty_terminal = election.pulse_id.is_some()
                        && election.pulse_output.is_some()
                        && assignment_plan_is_valid
                        && invitation_window_is_valid
                        && accepted_roster_len == 0;
                    let drawn_insufficient_hidden_terminal = election.pulse_id.is_some()
                        && election.pulse_output.is_some()
                        && assignment_plan_is_valid
                        && invitation_window_is_valid
                        && requirement.decision_mode
                            == ParliamentDecisionModeV1::HiddenBindingBallot
                        && accepted_roster_len > 0
                        && !hidden_ballot_population_meets_anonymity_floor_v1(accepted_roster_len);
                    let failure_is_valid = match (election.failure_kind, election.failure_height) {
                        (
                            Some(ParliamentElectionFailureKindV1::EmptyAcceptedRoster),
                            Some(height),
                        ) => {
                            drawn_empty_terminal
                                && election
                                    .invitation_close_height
                                    .is_some_and(|close| height > close)
                        }
                        (
                            Some(ParliamentElectionFailureKindV1::InsufficientHiddenBallotRoster),
                            Some(height),
                        ) => {
                            drawn_insufficient_hidden_terminal
                                && election
                                    .invitation_close_height
                                    .is_some_and(|close| height > close)
                        }
                        _ => false,
                    };
                    if !failure_is_valid {
                        return Err(ParliamentReducerErrorV1::InvalidAssignmentPlan);
                    }
                }
            }
            if let Some(pulse_id) = election.pulse_id {
                let consumer = self
                    .used_pulse_ids
                    .get(&pulse_id)
                    .ok_or(ParliamentReducerErrorV1::PulseBindingMismatch)?;
                if !matches!(consumer, ParliamentPulseConsumerV1::SortitionBatch(batch) if batch.binary_search(&request.id).is_ok())
                    || self.used_pulse_slots.get(&ParliamentPulseSlotV1::new(
                        request.beacon_session_id,
                        request.pulse_height,
                    )) != Some(&pulse_id)
                {
                    return Err(ParliamentReducerErrorV1::PulseBindingMismatch);
                }
            }
        }
        if referenced_candidate_snapshots.len() != self.candidate_snapshots.len() {
            return Err(ParliamentReducerErrorV1::InvalidCandidateSnapshot);
        }
        // `consume_sortition_pulse_batch` draws every request awaiting one slot from a single
        // snapshot, so a slot whose awaiting requests froze different snapshots could never
        // be consumed.
        let mut awaiting_slot_snapshots = BTreeMap::new();
        for election in self
            .elections
            .values()
            .filter(|election| election.attempt.status == BodyElectionAttemptStatusV1::AwaitingPulse)
        {
            let request = election.attempt.request;
            let slot = ParliamentPulseSlotV1::new(request.beacon_session_id, request.pulse_height);
            if *awaiting_slot_snapshots
                .entry(slot)
                .or_insert(election.candidate_snapshot_index)
                != election.candidate_snapshot_index
            {
                return Err(ParliamentReducerErrorV1::InvalidCandidateSnapshot);
            }
        }
        if confirmation_required
            && sortition_sequences
                .get(&ParliamentBody::ConfirmationJury)
                .and_then(|sequences| sequences.get(&0))
                .is_none()
        {
            return Err(ParliamentReducerErrorV1::ConfirmationJuryNotFresh);
        }
        let initial_required_bodies: BTreeSet<_> = self
            .required_bodies
            .iter()
            .filter_map(|requirement| {
                (requirement.body != ParliamentBody::ConfirmationJury).then_some(requirement.body)
            })
            .collect();
        // A public body records capacity evidence only within a generation that a hidden
        // body's sub-floor electorate blocked: before the first drawn pulse, the complete
        // initial generation; after it, a retry generation of every failed body (whose
        // sequences may differ), which therefore includes the blocking hidden body.
        let first_drawn_pulse_height = self
            .elections
            .values()
            .filter(|election| election.pulse_id.is_some())
            .map(|election| election.attempt.request.pulse_height)
            .min();
        for failure in self.sortition_capacity_failures.values() {
            let requirement = self.requirement_for_body(failure.body)?;
            if requirement.decision_mode != ParliamentDecisionModeV1::HiddenBindingBallot {
                let after_first_draw =
                    first_drawn_pulse_height.is_some_and(|height| height < failure.pulse_height);
                let same_generation_bodies = self
                    .sortition_capacity_failures
                    .values()
                    .filter(|other| {
                        (after_first_draw || other.sequence == failure.sequence)
                            && other.request_height == failure.request_height
                            && other.pulse_height == failure.pulse_height
                            && other.beacon_session_id == failure.beacon_session_id
                            && other.candidate_snapshot == failure.candidate_snapshot
                    })
                    .map(|other| other.body)
                    .collect::<BTreeSet<_>>();
                let blocked_by_hidden_body = if after_first_draw {
                    same_generation_bodies.iter().any(|body| {
                        self.requirement_for_body(*body).is_ok_and(|required| {
                            required.decision_mode == ParliamentDecisionModeV1::HiddenBindingBallot
                        })
                    })
                } else {
                    same_generation_bodies == initial_required_bodies
                };
                if !blocked_by_hidden_body {
                    return Err(ParliamentReducerErrorV1::InvalidAssignmentPlan);
                }
            }
        }
        let initial_elections: Vec<_> = self
            .elections
            .values()
            .filter(|election| {
                election.attempt.sequence == 0
                    && election.attempt.request.body != ParliamentBody::ConfirmationJury
            })
            .collect();
        let initial_capacity_failures: Vec<_> = self
            .sortition_capacity_failures
            .values()
            .filter(|failure| {
                failure.sequence == 0 && failure.body != ParliamentBody::ConfirmationJury
            })
            .collect();
        if !initial_elections.is_empty() && !initial_capacity_failures.is_empty() {
            return Err(ParliamentReducerErrorV1::InvalidAssignmentPlan);
        }
        if let Some(first) = initial_elections.first() {
            let registered_bodies: BTreeSet<_> = initial_elections
                .iter()
                .map(|election| election.attempt.request.body)
                .collect();
            if registered_bodies != initial_required_bodies
                || initial_elections.iter().any(|election| {
                    election.attempt.request.request_height != first.attempt.request.request_height
                        || election.attempt.request.beacon_session_id
                            != first.attempt.request.beacon_session_id
                        || election.attempt.request.pulse_height
                            != first.attempt.request.pulse_height
                        || election.candidate_snapshot_index != first.candidate_snapshot_index
                })
            {
                return Err(ParliamentReducerErrorV1::InvalidAssignmentPlan);
            }
        }
        if let Some(first) = initial_capacity_failures.first() {
            let failed_bodies: BTreeSet<_> = initial_capacity_failures
                .iter()
                .map(|failure| failure.body)
                .collect();
            if failed_bodies != initial_required_bodies
                || initial_capacity_failures.iter().any(|failure| {
                    failure.request_height != first.request_height
                        || failure.beacon_session_id != first.beacon_session_id
                        || failure.pulse_height != first.pulse_height
                        || failure.candidate_snapshot != first.candidate_snapshot
                })
            {
                return Err(ParliamentReducerErrorV1::InvalidAssignmentPlan);
            }
        }
        let initial_drawn: Vec<_> = initial_elections
            .iter()
            .copied()
            .filter(|election| election.pulse_id.is_some())
            .collect();
        if let Some(first) = initial_drawn.first() {
            let drawn_bodies: BTreeSet<_> = initial_drawn
                .iter()
                .map(|election| election.attempt.request.body)
                .collect();
            if drawn_bodies != initial_required_bodies
                || initial_drawn.iter().any(|election| {
                    election.pulse_id != first.pulse_id
                        || election.pulse_output != first.pulse_output
                        || election.attempt.request.beacon_session_id
                            != first.attempt.request.beacon_session_id
                        || election.attempt.request.pulse_height
                            != first.attempt.request.pulse_height
                        || election.cross_body_assignment_cap != first.cross_body_assignment_cap
                        || election.candidate_snapshot_index != first.candidate_snapshot_index
                })
            {
                return Err(ParliamentReducerErrorV1::InvalidAssignmentPlan);
            }
        }
        if !self
            .active_elections
            .keys()
            .all(|body| !self.active_sortition_capacity_failures.contains_key(body))
            || self.active_elections.len() + self.active_sortition_capacity_failures.len()
                != sortition_sequences.len()
        {
            return Err(ParliamentReducerErrorV1::ImmutableBindingMismatch);
        }
        for (body, sequences) in &sortition_sequences {
            if sequences
                .keys()
                .copied()
                .ne(0..u32::try_from(sequences.len())
                    .map_err(|_| ParliamentReducerErrorV1::RetrySequenceMismatch)?)
            {
                return Err(ParliamentReducerErrorV1::RetrySequenceMismatch);
            }
            let latest_id = sequences
                .last_key_value()
                .map(|(_, generation)| *generation)
                .ok_or(ParliamentReducerErrorV1::RetrySequenceMismatch)?;
            let active_matches = if latest_id.1 {
                self.active_sortition_capacity_failures.get(body) == Some(&latest_id.0)
            } else {
                self.active_elections.get(body) == Some(&latest_id.0)
            };
            if !active_matches {
                return Err(ParliamentReducerErrorV1::ImmutableBindingMismatch);
            }
            let mut previous_failure_height = None;
            let mut previous_was_capacity_failure = false;
            for (sequence, (id, is_capacity_failure)) in sequences {
                let (status, persisted_sequence, request_height, failure_height) =
                    if *is_capacity_failure {
                        let failure = self
                            .sortition_capacity_failures
                            .get(id)
                            .ok_or(ParliamentReducerErrorV1::RetrySequenceMismatch)?;
                        (
                            failure.status,
                            failure.sequence,
                            failure.request_height,
                            Some(failure.failure_height),
                        )
                    } else {
                        let election = self
                            .elections
                            .get(id)
                            .ok_or(ParliamentReducerErrorV1::RetrySequenceMismatch)?;
                        (
                            election.attempt.status,
                            election.attempt.sequence,
                            election.attempt.request.request_height,
                            election.failure_height,
                        )
                    };
                let is_latest = (*id, *is_capacity_failure) == latest_id;
                let request_precedes_failure = previous_failure_height.is_some_and(|height| {
                    if previous_was_capacity_failure {
                        request_height <= height
                    } else {
                        request_height < height
                    }
                });
                if (is_latest && status == BodyElectionAttemptStatusV1::Superseded)
                    || (!is_latest && status != BodyElectionAttemptStatusV1::Superseded)
                    || *sequence != persisted_sequence
                    || request_precedes_failure
                {
                    return Err(ParliamentReducerErrorV1::RetrySequenceMismatch);
                }
                previous_failure_height = failure_height;
                previous_was_capacity_failure = *is_capacity_failure;
            }
        }
        for (body, active_id) in &self.active_elections {
            let active =
                self.elections
                    .get(active_id)
                    .ok_or(ParliamentReducerErrorV1::UnknownEntity(
                        ParliamentReducerEntityV1::BodyElection,
                    ))?;
            if active.attempt.request.body != *body
                || active.attempt.status == BodyElectionAttemptStatusV1::Superseded
            {
                return Err(ParliamentReducerErrorV1::ImmutableBindingMismatch);
            }
        }
        for (body, active_id) in &self.active_sortition_capacity_failures {
            let active = self.sortition_capacity_failures.get(active_id).ok_or(
                ParliamentReducerErrorV1::UnknownEntity(ParliamentReducerEntityV1::BodyElection),
            )?;
            if active.body != *body || active.status == BodyElectionAttemptStatusV1::Superseded {
                return Err(ParliamentReducerErrorV1::ImmutableBindingMismatch);
            }
        }
        if self.used_pulse_ids.is_empty()
            && !self.active_elections.is_empty()
            && !self.active_sortition_capacity_failures.is_empty()
        {
            return Err(ParliamentReducerErrorV1::InvalidAssignmentPlan);
        }
        if self.used_pulse_ids.is_empty() && !self.active_elections.is_empty() {
            let active_initial: Vec<_> = initial_required_bodies
                .iter()
                .map(|body| {
                    self.active_elections
                        .get(body)
                        .and_then(|id| self.elections.get(id))
                        .ok_or(ParliamentReducerErrorV1::InvalidAssignmentPlan)
                })
                .collect::<Result<_, _>>()?;
            let first = active_initial
                .first()
                .ok_or(ParliamentReducerErrorV1::InvalidAssignmentPlan)?;
            if active_initial.iter().any(|election| {
                election.attempt.sequence != first.attempt.sequence
                    || election.attempt.request.request_height
                        != first.attempt.request.request_height
                    || election.attempt.request.beacon_session_id
                        != first.attempt.request.beacon_session_id
                    || election.attempt.request.pulse_height != first.attempt.request.pulse_height
                    || election.candidate_snapshot_index != first.candidate_snapshot_index
            }) {
                return Err(ParliamentReducerErrorV1::InvalidAssignmentPlan);
            }
        }
        if self.used_pulse_ids.is_empty() && !self.active_sortition_capacity_failures.is_empty() {
            let active_initial: Vec<_> = initial_required_bodies
                .iter()
                .map(|body| {
                    self.active_sortition_capacity_failures
                        .get(body)
                        .and_then(|id| self.sortition_capacity_failures.get(id))
                        .ok_or(ParliamentReducerErrorV1::InvalidAssignmentPlan)
                })
                .collect::<Result<_, _>>()?;
            let first = active_initial
                .first()
                .ok_or(ParliamentReducerErrorV1::InvalidAssignmentPlan)?;
            if active_initial.iter().any(|failure| {
                failure.sequence != first.sequence
                    || failure.request_height != first.request_height
                    || failure.beacon_session_id != first.beacon_session_id
                    || failure.pulse_height != first.pulse_height
                    || failure.candidate_snapshot != first.candidate_snapshot
            }) {
                return Err(ParliamentReducerErrorV1::InvalidAssignmentPlan);
            }
        }

        if self
            .elections
            .values()
            .filter(|election| election.attempt.status == BodyElectionAttemptStatusV1::Sealed)
            .count()
            != self.bodies.len()
        {
            return Err(ParliamentReducerErrorV1::ImmutableBindingMismatch);
        }

        let mut all_members_by_body = BTreeMap::<ParliamentBody, BTreeSet<AccountId>>::new();
        for (id, body) in &self.bodies {
            if *id != body.instance.id
                || *id
                    != BodyInstanceId::derive_v1(
                        body.instance.election_attempt_id,
                        body.roster_root,
                    )
                || body.instance.governance_attempt_id != self.attempt.id
                || root_is_zero(&body.roster_root)
                || body.roster_root
                    != parliament_roster_root_v1(
                        body.instance.election_attempt_id,
                        &body.assignments,
                    )
                || usize::try_from(body.instance.original_seats).ok()
                    != Some(body.assignments.len())
                || body.instance.original_seats == 0
                || body.instance.original_seats > body.instance.target_seats
                || !body
                    .assignments
                    .windows(2)
                    .all(|pair| pair[0].assignment_id < pair[1].assignment_id)
            {
                return Err(ParliamentReducerErrorV1::InvalidRoster);
            }
            if body.assignments.iter().any(|seat| {
                seat.assignment_id
                    != AssignmentId::derive_v1(body.instance.election_attempt_id, &seat.member)
            }) {
                return Err(ParliamentReducerErrorV1::InvalidRoster);
            }
            let members: BTreeSet<_> = body
                .assignments
                .iter()
                .map(|seat| seat.member.clone())
                .collect();
            if members.len() != body.assignments.len()
                || !body.excluded_assignments.iter().all(|excluded| {
                    body.assignments
                        .iter()
                        .any(|seat| seat.assignment_id == *excluded)
                })
            {
                return Err(ParliamentReducerErrorV1::InvalidRoster);
            }
            let decision_mode = self
                .required_bodies
                .iter()
                .find(|required| required.body == body.instance.body)
                .map(|required| required.decision_mode)
                .ok_or(ParliamentReducerErrorV1::InvalidRequiredBodyPipeline)?;
            if matches!(
                body.instance.status,
                BodyInstanceStatusV1::AwaitingSortition
                    | BodyInstanceStatusV1::AcceptingInvitations
                    | BodyInstanceStatusV1::Superseded
            ) {
                return Err(ParliamentReducerErrorV1::InvalidLifecycleTransition(
                    ParliamentReducerEntityV1::BodyInstance,
                ));
            }
            if decision_mode == ParliamentDecisionModeV1::PublicFinding
                && matches!(
                    body.instance.status,
                    BodyInstanceStatusV1::Deliberating(DeliberationPhaseV1::Vote)
                        | BodyInstanceStatusV1::Balloting
                )
            {
                return Err(ParliamentReducerErrorV1::DecisionModeMismatch);
            }
            let result_requires_binding = matches!(
                body.instance.status,
                BodyInstanceStatusV1::Approved
                    | BodyInstanceStatusV1::Rejected
                    | BodyInstanceStatusV1::NoQuorum
            );
            if self.body_bindings.contains_key(&body.instance.body) != result_requires_binding {
                return Err(ParliamentReducerErrorV1::IncompleteCertificate);
            }
            if body
                .public_finding_endorsements
                .iter()
                .any(|(assignment_id, result_root)| {
                    root_is_zero(result_root)
                        || body.excluded_assignments.contains(assignment_id)
                        || !body
                            .assignments
                            .iter()
                            .any(|assignment| assignment.assignment_id == *assignment_id)
                })
            {
                return Err(ParliamentReducerErrorV1::InvalidRoster);
            }
            match decision_mode {
                ParliamentDecisionModeV1::HiddenBindingBallot => {
                    if !body.public_finding_endorsements.is_empty()
                        || body.public_finding_binding.is_some()
                        || body.public_finding_opened_at_height.is_some()
                        || body.public_finding_phase_blocks.is_some()
                        || body.public_finding_deadline_height.is_some()
                        || body.public_finding_no_result_kind.is_some()
                        || body.public_finding_no_result_height.is_some()
                    {
                        return Err(ParliamentReducerErrorV1::CertificateBindingMismatch);
                    }
                }
                ParliamentDecisionModeV1::PublicFinding => {
                    if body.ballot_binding.is_some() {
                        return Err(ParliamentReducerErrorV1::CertificateBindingMismatch);
                    }
                    let quorum = parliament_quorum_seats_v1(body.instance.original_seats);
                    let quorum_usize = usize::try_from(quorum)
                        .map_err(|_| ParliamentReducerErrorV1::InvalidRoster)?;
                    let mut endorsements_by_root = BTreeMap::<[u8; 32], Vec<AssignmentId>>::new();
                    for (assignment_id, result_root) in &body.public_finding_endorsements {
                        endorsements_by_root
                            .entry(*result_root)
                            .or_default()
                            .push(*assignment_id);
                    }
                    match body.public_finding_binding.as_ref() {
                        None => {
                            if endorsements_by_root
                                .values()
                                .any(|endorsers| endorsers.len() >= quorum_usize)
                                || body.result_root.is_some()
                                || body.result_height.is_some()
                            {
                                return Err(ParliamentReducerErrorV1::IncompleteCertificate);
                            }
                            let quorum_unreachable = public_finding_quorum_is_unreachable(body)?;
                            match body.public_finding_no_result_kind {
                                Some(ParliamentNoResultKindV1::PublicFindingQuorumUnreachable) => {
                                    if !quorum_unreachable
                                        || body.instance.status != BodyInstanceStatusV1::NoResult
                                        || self.attempt.status
                                            != GovernanceAttemptStatusV1::Rejected
                                        || body.public_finding_no_result_height.is_none()
                                    {
                                        return Err(
                                            ParliamentReducerErrorV1::PublicFindingFailureKindMismatch,
                                        );
                                    }
                                }
                                Some(ParliamentNoResultKindV1::PublicFindingDeadlineExpired) => {
                                    if quorum_unreachable
                                        || body.instance.status != BodyInstanceStatusV1::NoResult
                                        || self.attempt.status
                                            != GovernanceAttemptStatusV1::Rejected
                                        || body.public_finding_no_result_height.is_none()
                                    {
                                        return Err(
                                            ParliamentReducerErrorV1::PublicFindingFailureKindMismatch,
                                        );
                                    }
                                }
                                Some(_) => {
                                    return Err(
                                        ParliamentReducerErrorV1::PublicFindingFailureKindMismatch,
                                    );
                                }
                                None => {
                                    if quorum_unreachable
                                        || body.instance.status == BodyInstanceStatusV1::NoResult
                                        || body.public_finding_no_result_height.is_some()
                                    {
                                        return Err(
                                            ParliamentReducerErrorV1::PublicFindingFailureKindMismatch,
                                        );
                                    }
                                }
                            }
                        }
                        Some(binding) => {
                            let result_root = body
                                .result_root
                                .ok_or(ParliamentReducerErrorV1::IncompleteCertificate)?;
                            let endorsers = endorsements_by_root
                                .get(&result_root)
                                .ok_or(ParliamentReducerErrorV1::CertificateBindingMismatch)?;
                            let endorsements = u32::try_from(endorsers.len())
                                .map_err(|_| ParliamentReducerErrorV1::InvalidRoster)?;
                            if body.instance.status != BodyInstanceStatusV1::Approved
                                || binding.quorum != quorum
                                || binding.endorsements != endorsements
                                || endorsements != quorum
                                || binding.endorsing_assignments.as_slice() != endorsers.as_slice()
                                || body.public_finding_no_result_kind.is_some()
                                || body.public_finding_no_result_height.is_some()
                                || binding.endorsement_root
                                    != parliament_public_finding_endorsement_root_v1(
                                        self.attempt.id,
                                        body.instance.id,
                                        result_root,
                                        endorsers,
                                    )
                            {
                                return Err(ParliamentReducerErrorV1::CertificateBindingMismatch);
                            }
                        }
                    }
                }
            }
            let election = self
                .elections
                .get(&body.instance.election_attempt_id)
                .ok_or(ParliamentReducerErrorV1::ImmutableBindingMismatch)?;
            if election.attempt.status != BodyElectionAttemptStatusV1::Sealed
                || election.attempt.request.body != body.instance.body
                || election.attempt.request.target_seats != body.instance.target_seats
                || accepted_roster(election)? != body.assignments
            {
                return Err(ParliamentReducerErrorV1::ImmutableBindingMismatch);
            }
            if decision_mode == ParliamentDecisionModeV1::PublicFinding {
                if body
                    .public_finding_no_result_height
                    .is_some_and(|height| height <= election.attempt.request.pulse_height)
                {
                    return Err(ParliamentReducerErrorV1::InvalidPublicFindingSchedule);
                }
                let schedule = match (
                    body.public_finding_opened_at_height,
                    body.public_finding_phase_blocks,
                    body.public_finding_deadline_height,
                ) {
                    (None, None, None) => None,
                    (Some(opened_at), Some(phase_blocks), Some(deadline))
                        if phase_blocks != 0
                            && opened_at > election.attempt.request.pulse_height
                            && opened_at.checked_add(phase_blocks) == Some(deadline) =>
                    {
                        Some((opened_at, deadline))
                    }
                    _ => return Err(ParliamentReducerErrorV1::InvalidPublicFindingSchedule),
                };
                let schedule_required = !body.public_finding_endorsements.is_empty()
                    || body.public_finding_binding.is_some()
                    || body.instance.status
                        == BodyInstanceStatusV1::Deliberating(DeliberationPhaseV1::Reflection)
                    || body.public_finding_no_result_kind
                        == Some(ParliamentNoResultKindV1::PublicFindingDeadlineExpired);
                if schedule_required && schedule.is_none() {
                    return Err(ParliamentReducerErrorV1::InvalidPublicFindingSchedule);
                }
                if schedule.is_some()
                    && !matches!(
                        body.instance.status,
                        BodyInstanceStatusV1::Deliberating(DeliberationPhaseV1::Reflection)
                            | BodyInstanceStatusV1::Approved
                            | BodyInstanceStatusV1::NoResult
                    )
                {
                    return Err(ParliamentReducerErrorV1::InvalidPublicFindingSchedule);
                }
                if let Some((opened_at, deadline)) = schedule {
                    if body
                        .result_height
                        .is_some_and(|height| height < opened_at || height > deadline)
                    {
                        return Err(ParliamentReducerErrorV1::InvalidCertificateHeight);
                    }
                    match body.public_finding_no_result_kind {
                        Some(ParliamentNoResultKindV1::PublicFindingDeadlineExpired)
                            if body
                                .public_finding_no_result_height
                                .is_none_or(|height| height <= deadline) =>
                        {
                            return Err(ParliamentReducerErrorV1::PublicFindingFailureKindMismatch);
                        }
                        Some(ParliamentNoResultKindV1::PublicFindingQuorumUnreachable)
                            if body
                                .public_finding_no_result_height
                                .is_none_or(|height| height < opened_at || height > deadline) =>
                        {
                            return Err(ParliamentReducerErrorV1::PublicFindingFailureKindMismatch);
                        }
                        _ => {}
                    }
                }
            }
            if body.result_root.is_some() != body.result_height.is_some()
                || body
                    .result_height
                    .is_some_and(|height| height <= election.attempt.request.pulse_height)
            {
                return Err(ParliamentReducerErrorV1::InvalidCertificateHeight);
            }
            match body.instance.status {
                BodyInstanceStatusV1::Approved
                | BodyInstanceStatusV1::Rejected
                | BodyInstanceStatusV1::NoQuorum => {
                    if body.result_root.is_none() || body.result_height.is_none() {
                        return Err(ParliamentReducerErrorV1::IncompleteCertificate);
                    }
                }
                BodyInstanceStatusV1::AwaitingSortition
                | BodyInstanceStatusV1::AcceptingInvitations
                | BodyInstanceStatusV1::RosterSealed
                | BodyInstanceStatusV1::Deliberating(_)
                | BodyInstanceStatusV1::Balloting
                | BodyInstanceStatusV1::NoResult
                | BodyInstanceStatusV1::Superseded => {
                    if body.result_root.is_some() || body.result_height.is_some() {
                        return Err(ParliamentReducerErrorV1::ImmutableBindingMismatch);
                    }
                }
            }
            if all_members_by_body
                .insert(body.instance.body, members)
                .is_some()
            {
                return Err(ParliamentReducerErrorV1::InvalidRoster);
            }
        }
        if confirmation_required {
            let policy = all_members_by_body
                .get(&ParliamentBody::PolicyJury)
                .ok_or(ParliamentReducerErrorV1::ConfirmationJuryNotFresh)?;
            if let Some(confirmation) = all_members_by_body.get(&ParliamentBody::ConfirmationJury)
                && !policy.is_disjoint(confirmation)
            {
                return Err(ParliamentReducerErrorV1::ConfirmationJuryNotFresh);
            }
        }
        if self.active_bodies.len() != self.bodies.len() {
            return Err(ParliamentReducerErrorV1::ImmutableBindingMismatch);
        }
        for (body_role, active_id) in &self.active_bodies {
            let body =
                self.bodies
                    .get(active_id)
                    .ok_or(ParliamentReducerErrorV1::UnknownEntity(
                        ParliamentReducerEntityV1::BodyInstance,
                    ))?;
            if body.instance.body != *body_role {
                return Err(ParliamentReducerErrorV1::ImmutableBindingMismatch);
            }
        }

        let mut ballot_sequences =
            BTreeMap::<BodyInstanceId, BTreeMap<u32, BallotAttemptId>>::new();
        let mut frozen_ballot_policy = None;
        for (id, ballot) in &self.ballots {
            if *id != ballot.attempt.id
                || *id
                    != BallotAttemptId::derive_v1(
                        ballot.attempt.body_instance_id,
                        ballot.attempt.sequence,
                    )
            {
                return Err(ParliamentReducerErrorV1::ImmutableBindingMismatch);
            }
            if ballot_sequences
                .entry(ballot.attempt.body_instance_id)
                .or_default()
                .insert(ballot.attempt.sequence, *id)
                .is_some()
            {
                return Err(ParliamentReducerErrorV1::RetrySequenceMismatch);
            }
            let policy = ballot_policy(ballot);
            if frozen_ballot_policy.is_some_and(|expected| expected != policy) {
                return Err(ParliamentReducerErrorV1::InvalidBallotSchedule);
            }
            frozen_ballot_policy = Some(policy);
            let (
                registration_close_height,
                survivor_freeze_height,
                commitment_close_height,
                expected_release_height,
                opening_deadline_height,
            ) = timed_ballot_schedule(ballot.registered_at_height, policy)?;
            if ballot.registration_close_height != registration_close_height
                || ballot.survivor_freeze_height != survivor_freeze_height
                || ballot.commitment_close_height != commitment_close_height
                || ballot.release_height != Some(expected_release_height)
                || ballot.opening_deadline_height != opening_deadline_height
            {
                return Err(ParliamentReducerErrorV1::InvalidBallotSchedule);
            }
            if ballot.attempt.sequence > ballot.max_ballot_retries {
                return Err(ParliamentReducerErrorV1::BallotRetryLimitExceeded);
            }
            let body = self
                .bodies
                .get(&ballot.attempt.body_instance_id)
                .ok_or(ParliamentReducerErrorV1::ImmutableBindingMismatch)?;
            if ballot.attempt.original_seats != body.instance.original_seats
                || ballot.max_corpus_entries < ballot.attempt.original_seats
            {
                return Err(ParliamentReducerErrorV1::InvalidBallotCount);
            }
            let election = self
                .elections
                .get(&body.instance.election_attempt_id)
                .ok_or(ParliamentReducerErrorV1::ImmutableBindingMismatch)?;
            if election
                .invitation_close_height
                .is_none_or(|close_height| ballot.registered_at_height <= close_height)
            {
                return Err(ParliamentReducerErrorV1::InvalidBallotSchedule);
            }
            let tle_session_id = ballot
                .tle_session_id
                .ok_or(ParliamentReducerErrorV1::TleSessionAlreadyConsumed)?;
            let tle_key_session_id = ballot
                .tle_key_session_id
                .ok_or(ParliamentReducerErrorV1::ImmutableBindingMismatch)?;
            let release_beacon_session_id = ballot
                .release_beacon_session_id
                .ok_or(ParliamentReducerErrorV1::ImmutableBindingMismatch)?;
            let release_height = ballot
                .release_height
                .ok_or(ParliamentReducerErrorV1::ImmutableBindingMismatch)?;
            if ballot.registered_at_height == 0
                || release_height <= ballot.registered_at_height
                || tle_session_id
                    != TleSessionId::derive_v1(
                        *id,
                        tle_key_session_id,
                        release_beacon_session_id,
                        release_height,
                    )
            {
                return Err(ParliamentReducerErrorV1::ImmutableBindingMismatch);
            }
            if [
                ballot.registration_root,
                ballot.corpus_root,
                ballot.dropout_root,
                ballot.survivor_root,
                ballot.no_recovery_root,
                ballot.timed_commitment_root,
                ballot.opening_root,
                ballot.failure_root,
            ]
            .into_iter()
            .flatten()
            .any(|root| root_is_zero(&root))
            {
                return Err(ParliamentReducerErrorV1::ZeroCommitmentRoot);
            }
            if let Some(registered) = ballot.registered_voters {
                let excluded = u32::try_from(body.excluded_assignments.len())
                    .map_err(|_| ParliamentReducerErrorV1::InvalidBallotCount)?;
                if registered > ballot.attempt.original_seats.saturating_sub(excluded)
                    || registered > ballot.max_corpus_entries
                {
                    return Err(ParliamentReducerErrorV1::InvalidBallotCount);
                }
            }
            if let Some(survivors) = ballot.survivors
                && (survivors < MIN_PARLIAMENT_HIDDEN_BALLOT_ANONYMITY_V1
                    || survivors > ballot.registered_voters.unwrap_or(0)
                    || survivors > ballot.max_corpus_entries)
            {
                return Err(ParliamentReducerErrorV1::InvalidBallotCount);
            }
            if let Some(accepted) = ballot.accepted_ballots {
                if accepted < MIN_PARLIAMENT_HIDDEN_BALLOT_ANONYMITY_V1
                    || accepted > ballot.registered_voters.unwrap_or(0)
                    || accepted > ballot.max_corpus_entries
                    || ballot.survivors != Some(accepted)
                {
                    return Err(ParliamentReducerErrorV1::InvalidBallotCount);
                }
            }
            let terminal_failure = matches!(
                ballot.attempt.status,
                BallotAttemptStatusV1::NoResult | BallotAttemptStatusV1::Superseded
            );
            if terminal_failure {
                if matches!(
                    ballot.failure_kind,
                    Some(
                        ParliamentBallotFailureKindV1::ConfirmationJuryCapacityUnavailable
                            | ParliamentBallotFailureKindV1::RandomnessRedrawBudgetExhausted
                    )
                ) && (ballot.attempt.status != BallotAttemptStatusV1::NoResult
                    || self.attempt.status != GovernanceAttemptStatusV1::Rejected)
                {
                    return Err(ParliamentReducerErrorV1::BallotFailureKindMismatch);
                }
                if ballot.failure_kind
                    == Some(ParliamentBallotFailureKindV1::RandomnessRedrawBudgetExhausted)
                    && !proposal_redraw_budget_exhausted
                {
                    return Err(ParliamentReducerErrorV1::BallotFailureKindMismatch);
                }
                if !ballot_failure_matches_state(self.attempt.id, *id, ballot, body.instance.body) {
                    return Err(ParliamentReducerErrorV1::BallotFailureKindMismatch);
                }
            } else if ballot.failure_root.is_some()
                || ballot.failure_kind.is_some()
                || ballot.failure_height.is_some()
                || ballot.eligible_confirmation_candidates.is_some()
            {
                return Err(ParliamentReducerErrorV1::ImmutableBindingMismatch);
            }
            if self.used_tle_sessions.get(&tle_session_id) != Some(id) {
                return Err(ParliamentReducerErrorV1::TleSessionAlreadyConsumed);
            }
            if let Some(pulse_id) = ballot.release_pulse_id {
                let consumer = self
                    .used_pulse_ids
                    .get(&pulse_id)
                    .ok_or(ParliamentReducerErrorV1::PulseBindingMismatch)?;
                if !matches!(consumer, ParliamentPulseConsumerV1::BallotBatch(batch) if batch.binary_search(id).is_ok())
                {
                    return Err(ParliamentReducerErrorV1::PulseBindingMismatch);
                }
                let session = ballot
                    .release_beacon_session_id
                    .ok_or(ParliamentReducerErrorV1::PulseBindingMismatch)?;
                let height = ballot
                    .release_height
                    .ok_or(ParliamentReducerErrorV1::PulseBindingMismatch)?;
                if self
                    .used_pulse_slots
                    .get(&ParliamentPulseSlotV1::new(session, height))
                    != Some(&pulse_id)
                {
                    return Err(ParliamentReducerErrorV1::PulseBindingMismatch);
                }
            }
            if matches!(
                ballot.attempt.status,
                BallotAttemptStatusV1::AwaitingRelease
                    | BallotAttemptStatusV1::Opening
                    | BallotAttemptStatusV1::Finalized
            ) && (ballot.registration_root.is_none()
                || ballot.registered_voters.is_none()
                || ballot.dropout_root.is_none()
                || ballot.survivor_root.is_none()
                || ballot.survivors.is_none()
                || ballot.no_recovery_root.is_none()
                || ballot.corpus_root.is_none()
                || ballot.accepted_ballots.is_none()
                || ballot.timed_commitment_root.is_none()
                || ballot.tle_session_id.is_none()
                || ballot.tle_key_session_id.is_none()
                || ballot.release_beacon_session_id.is_none()
                || ballot.release_height.is_none())
            {
                return Err(ParliamentReducerErrorV1::ImmutableBindingMismatch);
            }
            let terminal_confirmation_failure = ballot.attempt.status
                == BallotAttemptStatusV1::NoResult
                && matches!(
                    ballot.failure_kind,
                    Some(
                        ParliamentBallotFailureKindV1::ConfirmationJuryCapacityUnavailable
                            | ParliamentBallotFailureKindV1::RandomnessRedrawBudgetExhausted
                    )
                );
            if ballot.attempt.status != BallotAttemptStatusV1::Finalized
                && !terminal_confirmation_failure
                && (ballot.tally.is_some() || ballot.outcome.is_some())
            {
                return Err(ParliamentReducerErrorV1::ImmutableBindingMismatch);
            }
            match ballot.attempt.status {
                BallotAttemptStatusV1::Registration => {
                    if ballot.tle_session_id.is_none()
                        || ballot.tle_key_session_id.is_none()
                        || ballot.release_beacon_session_id.is_none()
                        || ballot.release_height.is_none()
                        || ballot.registration_closed_at_height.is_some()
                        || ballot.survivors_frozen_at_height.is_some()
                        || ballot.commitment_closed_at_height.is_some()
                        || ballot.registration_root.is_some()
                        || ballot.registered_voters.is_some()
                        || ballot.dropout_root.is_some()
                        || ballot.survivor_root.is_some()
                        || ballot.survivors.is_some()
                        || ballot.no_recovery_root.is_some()
                        || ballot.corpus_root.is_some()
                        || ballot.accepted_ballots.is_some()
                        || ballot.timed_commitment_root.is_some()
                        || ballot.release_pulse_id.is_some()
                        || ballot.opening_height.is_some()
                        || ballot.opening_root.is_some()
                    {
                        return Err(ParliamentReducerErrorV1::ImmutableBindingMismatch);
                    }
                }
                BallotAttemptStatusV1::SurvivorFreeze => {
                    if ballot.registration_closed_at_height
                        != Some(ballot.registration_close_height)
                        || ballot.survivors_frozen_at_height.is_some()
                        || ballot.commitment_closed_at_height.is_some()
                        || ballot.registration_root.is_none()
                        || ballot.registered_voters.is_none()
                        || ballot.dropout_root.is_some()
                        || ballot.survivor_root.is_some()
                        || ballot.survivors.is_some()
                        || ballot.no_recovery_root.is_some()
                        || ballot.corpus_root.is_some()
                        || ballot.accepted_ballots.is_some()
                        || ballot.timed_commitment_root.is_some()
                        || ballot.release_pulse_id.is_some()
                        || ballot.opening_height.is_some()
                        || ballot.opening_root.is_some()
                    {
                        return Err(ParliamentReducerErrorV1::ImmutableBindingMismatch);
                    }
                }
                BallotAttemptStatusV1::TimedCommitment => {
                    if ballot.registration_closed_at_height
                        != Some(ballot.registration_close_height)
                        || ballot.survivors_frozen_at_height != Some(ballot.survivor_freeze_height)
                        || ballot.commitment_closed_at_height.is_some()
                        || ballot.registration_root.is_none()
                        || ballot.registered_voters.is_none()
                        || ballot.dropout_root.is_none()
                        || ballot.survivor_root.is_none()
                        || ballot.survivors.is_none()
                        || ballot.survivors.is_none_or(|survivors| {
                            survivors < MIN_PARLIAMENT_HIDDEN_BALLOT_ANONYMITY_V1
                        })
                        || ballot.no_recovery_root.is_none()
                        || ballot.corpus_root.is_some()
                        || ballot.accepted_ballots.is_some()
                        || ballot.timed_commitment_root.is_some()
                        || ballot.release_pulse_id.is_some()
                        || ballot.opening_height.is_some()
                        || ballot.opening_root.is_some()
                    {
                        return Err(ParliamentReducerErrorV1::ImmutableBindingMismatch);
                    }
                }
                BallotAttemptStatusV1::AwaitingRelease => {
                    if ballot.registration_closed_at_height
                        != Some(ballot.registration_close_height)
                        || ballot.survivors_frozen_at_height != Some(ballot.survivor_freeze_height)
                        || !timed_commitment_completed_in_window(ballot)
                        || ballot.corpus_root.is_none()
                        || ballot.accepted_ballots.is_none()
                        || ballot.timed_commitment_root.is_none()
                        || ballot.tle_session_id.is_none()
                        || ballot.tle_key_session_id.is_none()
                        || ballot.release_height.is_none()
                        || ballot.release_beacon_session_id.is_none()
                        || ballot.release_pulse_id.is_some()
                        || ballot.opening_height.is_some()
                        || ballot.opening_root.is_some()
                    {
                        return Err(ParliamentReducerErrorV1::ImmutableBindingMismatch);
                    }
                }
                BallotAttemptStatusV1::Opening => {
                    if ballot.registration_closed_at_height
                        != Some(ballot.registration_close_height)
                        || ballot.survivors_frozen_at_height != Some(ballot.survivor_freeze_height)
                        || !timed_commitment_completed_in_window(ballot)
                        || ballot.release_pulse_id.is_none()
                        || ballot.opening_height.is_none()
                        || ballot.opening_height < ballot.release_height
                        || ballot.opening_height > Some(ballot.opening_deadline_height)
                        || ballot.opening_root.is_some()
                    {
                        return Err(ParliamentReducerErrorV1::ImmutableBindingMismatch);
                    }
                }
                BallotAttemptStatusV1::Finalized => {
                    if ballot.registration_closed_at_height
                        != Some(ballot.registration_close_height)
                        || ballot.survivors_frozen_at_height != Some(ballot.survivor_freeze_height)
                        || !timed_commitment_completed_in_window(ballot)
                        || ballot.opening_root.is_none()
                        || ballot.opening_height.is_none()
                        || ballot.opening_height < ballot.release_height
                        || ballot.opening_height > Some(ballot.opening_deadline_height)
                        || body.ballot_binding.is_none()
                        || ballot.tally.is_none()
                        || ballot.outcome.is_none()
                        || body.result_height.is_none_or(|height| {
                            ballot
                                .opening_height
                                .is_none_or(|opening_height| height < opening_height)
                        })
                        || body
                            .result_height
                            .is_none_or(|height| height > ballot.opening_deadline_height)
                    {
                        return Err(ParliamentReducerErrorV1::IncompleteCertificate);
                    }
                    let tally = ballot
                        .tally
                        .ok_or(ParliamentReducerErrorV1::IncompleteCertificate)?;
                    let outcome = ballot
                        .outcome
                        .ok_or(ParliamentReducerErrorV1::IncompleteCertificate)?;
                    let opening_root = ballot
                        .opening_root
                        .ok_or(ParliamentReducerErrorV1::IncompleteCertificate)?;
                    let result_height = body
                        .result_height
                        .ok_or(ParliamentReducerErrorV1::IncompleteCertificate)?;
                    let mut expected_outcome = tally
                        .decision()
                        .map_err(|_| ParliamentReducerErrorV1::InvalidTally)?;
                    if self.attempt.risk_tier == RiskTierV1::Emergency
                        && body.instance.body == ParliamentBody::PolicyJury
                        && expected_outcome == ParliamentAggregateOutcomeV1::Approved
                        && tally.aye < parliament_quorum_seats_v1(tally.original_seats)
                    {
                        expected_outcome = ParliamentAggregateOutcomeV1::Rejected;
                    }
                    if expected_outcome != outcome
                        || body.result_root
                            != Some(parliament_ballot_result_root_v1(
                                self.attempt.id,
                                body.instance.id,
                                *id,
                                opening_root,
                                tally,
                                outcome,
                                result_height,
                            ))
                        || self.build_ballot_binding(*id)?
                            != body
                                .ballot_binding
                                .ok_or(ParliamentReducerErrorV1::IncompleteCertificate)?
                    {
                        return Err(ParliamentReducerErrorV1::CertificateBindingMismatch);
                    }
                }
                BallotAttemptStatusV1::NoResult => {
                    // The exact terminal phase and frozen field set were checked above.
                }
                BallotAttemptStatusV1::Superseded => {
                    // Supersession preserves the exact validated no-result transcript.
                }
            }
        }
        if self.active_ballots.len() != ballot_sequences.len()
            || self.used_tle_sessions.len() != self.ballots.len()
        {
            return Err(ParliamentReducerErrorV1::ImmutableBindingMismatch);
        }
        for (body_id, sequences) in &ballot_sequences {
            if sequences
                .keys()
                .copied()
                .ne(0..u32::try_from(sequences.len())
                    .map_err(|_| ParliamentReducerErrorV1::RetrySequenceMismatch)?)
            {
                return Err(ParliamentReducerErrorV1::RetrySequenceMismatch);
            }
            let latest_id = sequences
                .last_key_value()
                .map(|(_, id)| *id)
                .ok_or(ParliamentReducerErrorV1::RetrySequenceMismatch)?;
            if self.active_ballots.get(body_id) != Some(&latest_id) {
                return Err(ParliamentReducerErrorV1::ImmutableBindingMismatch);
            }
            let mut previous_failure_height = None;
            for id in sequences.values() {
                let ballot = self
                    .ballots
                    .get(id)
                    .ok_or(ParliamentReducerErrorV1::RetrySequenceMismatch)?;
                let status = ballot.attempt.status;
                if (*id == latest_id && status == BallotAttemptStatusV1::Superseded)
                    || (*id != latest_id && status != BallotAttemptStatusV1::Superseded)
                    || previous_failure_height
                        .is_some_and(|failure_height| ballot.registered_at_height < failure_height)
                {
                    return Err(ParliamentReducerErrorV1::RetrySequenceMismatch);
                }
                previous_failure_height = ballot.failure_height;
            }
            let latest = self
                .ballots
                .get(&latest_id)
                .ok_or(ParliamentReducerErrorV1::RetrySequenceMismatch)?;
            if latest.attempt.status == BallotAttemptStatusV1::NoResult {
                let retry_budget_exhausted = latest.attempt.sequence == latest.max_ballot_retries;
                let objectively_terminal = matches!(
                    latest.failure_kind,
                    Some(
                        ParliamentBallotFailureKindV1::ConfirmationJuryCapacityUnavailable
                            | ParliamentBallotFailureKindV1::RandomnessRedrawBudgetExhausted
                    )
                );
                if (retry_budget_exhausted
                    || objectively_terminal
                    || proposal_redraw_budget_exhausted)
                    != (self.attempt.status == GovernanceAttemptStatusV1::Rejected)
                {
                    return Err(ParliamentReducerErrorV1::RetrySequenceMismatch);
                }
            }
        }
        for (body_id, active_id) in &self.active_ballots {
            let ballot =
                self.ballots
                    .get(active_id)
                    .ok_or(ParliamentReducerErrorV1::UnknownEntity(
                        ParliamentReducerEntityV1::BallotAttempt,
                    ))?;
            if ballot.attempt.body_instance_id != *body_id
                || ballot.attempt.status == BallotAttemptStatusV1::Superseded
            {
                return Err(ParliamentReducerErrorV1::ImmutableBindingMismatch);
            }
        }
        for (body_id, body) in &self.bodies {
            let decision_mode = self.requirement_for_body(body.instance.body)?.decision_mode;
            let active_ballot = self
                .active_ballots
                .get(body_id)
                .and_then(|ballot_id| self.ballots.get(ballot_id));
            match decision_mode {
                ParliamentDecisionModeV1::PublicFinding => {
                    if active_ballot.is_some() {
                        return Err(ParliamentReducerErrorV1::DecisionModeMismatch);
                    }
                }
                ParliamentDecisionModeV1::HiddenBindingBallot => match body.instance.status {
                    BodyInstanceStatusV1::RosterSealed | BodyInstanceStatusV1::Deliberating(_) => {
                        if active_ballot.is_some() || body.ballot_binding.is_some() {
                            return Err(ParliamentReducerErrorV1::InvalidLifecycleTransition(
                                ParliamentReducerEntityV1::BodyInstance,
                            ));
                        }
                    }
                    BodyInstanceStatusV1::Balloting => {
                        if active_ballot.is_none_or(|ballot| {
                            !matches!(
                                ballot.attempt.status,
                                BallotAttemptStatusV1::Registration
                                    | BallotAttemptStatusV1::SurvivorFreeze
                                    | BallotAttemptStatusV1::TimedCommitment
                                    | BallotAttemptStatusV1::AwaitingRelease
                                    | BallotAttemptStatusV1::Opening
                            )
                        }) || body.ballot_binding.is_some()
                        {
                            return Err(ParliamentReducerErrorV1::InvalidLifecycleTransition(
                                ParliamentReducerEntityV1::BodyInstance,
                            ));
                        }
                    }
                    BodyInstanceStatusV1::Approved
                    | BodyInstanceStatusV1::Rejected
                    | BodyInstanceStatusV1::NoQuorum => {
                        let expected_outcome = match body.instance.status {
                            BodyInstanceStatusV1::Approved => {
                                ParliamentAggregateOutcomeV1::Approved
                            }
                            BodyInstanceStatusV1::Rejected => {
                                ParliamentAggregateOutcomeV1::Rejected
                            }
                            BodyInstanceStatusV1::NoQuorum => {
                                ParliamentAggregateOutcomeV1::NoQuorum
                            }
                            _ => unreachable!("matched completed hidden-body status"),
                        };
                        if active_ballot.is_none_or(|ballot| {
                            ballot.attempt.status != BallotAttemptStatusV1::Finalized
                                || ballot.outcome != Some(expected_outcome)
                        }) || body.ballot_binding.is_none()
                        {
                            return Err(ParliamentReducerErrorV1::CertificateBindingMismatch);
                        }
                    }
                    BodyInstanceStatusV1::NoResult => {
                        if active_ballot.is_none_or(|ballot| {
                            ballot.attempt.status != BallotAttemptStatusV1::NoResult
                        }) || body.ballot_binding.is_some()
                        {
                            return Err(ParliamentReducerErrorV1::InvalidLifecycleTransition(
                                ParliamentReducerEntityV1::BodyInstance,
                            ));
                        }
                    }
                    BodyInstanceStatusV1::AwaitingSortition
                    | BodyInstanceStatusV1::AcceptingInvitations
                    | BodyInstanceStatusV1::Superseded => {
                        return Err(ParliamentReducerErrorV1::InvalidLifecycleTransition(
                            ParliamentReducerEntityV1::BodyInstance,
                        ));
                    }
                },
            }
        }
        for (tle_session_id, ballot_id) in &self.used_tle_sessions {
            let ballot =
                self.ballots
                    .get(ballot_id)
                    .ok_or(ParliamentReducerErrorV1::UnknownEntity(
                        ParliamentReducerEntityV1::BallotAttempt,
                    ))?;
            if ballot.tle_session_id != Some(*tle_session_id) {
                return Err(ParliamentReducerErrorV1::TleSessionAlreadyConsumed);
            }
        }
        let unique_slot_pulses: BTreeSet<_> = self.used_pulse_slots.values().copied().collect();
        if self.used_pulse_ids.len() != self.used_pulse_slots.len()
            || unique_slot_pulses.len() != self.used_pulse_slots.len()
        {
            return Err(ParliamentReducerErrorV1::PulseBindingMismatch);
        }
        for (pulse_id, consumer) in &self.used_pulse_ids {
            if pulse_id.as_bytes().iter().all(|byte| *byte == 0) {
                return Err(ParliamentReducerErrorV1::PulseBindingMismatch);
            }
            match consumer {
                ParliamentPulseConsumerV1::SortitionBatch(request_ids) => {
                    if request_ids.is_empty()
                        || !request_ids.windows(2).all(|pair| pair[0] < pair[1])
                    {
                        return Err(ParliamentReducerErrorV1::PulseBindingMismatch);
                    }
                    let mut slot = None;
                    let mut output = None;
                    let mut assignment_cap = None;
                    let mut candidate_snapshot_index = None;
                    for request_id in request_ids {
                        let election = self
                            .elections
                            .values()
                            .find(|election| election.attempt.request.id == *request_id)
                            .ok_or(ParliamentReducerErrorV1::PulseBindingMismatch)?;
                        if election.pulse_id != Some(*pulse_id) {
                            return Err(ParliamentReducerErrorV1::PulseBindingMismatch);
                        }
                        let request_slot = ParliamentPulseSlotV1::new(
                            election.attempt.request.beacon_session_id,
                            election.attempt.request.pulse_height,
                        );
                        if slot.is_some_and(|expected| expected != request_slot) {
                            return Err(ParliamentReducerErrorV1::PulseBindingMismatch);
                        }
                        if output.is_some_and(|expected| election.pulse_output != Some(expected))
                            || assignment_cap.is_some_and(|expected| {
                                election.cross_body_assignment_cap != Some(expected)
                            })
                            || candidate_snapshot_index.is_some_and(|expected| {
                                election.candidate_snapshot_index != expected
                            })
                        {
                            return Err(ParliamentReducerErrorV1::InvalidAssignmentPlan);
                        }
                        slot = Some(request_slot);
                        output = election.pulse_output;
                        assignment_cap = election.cross_body_assignment_cap;
                        candidate_snapshot_index = Some(election.candidate_snapshot_index);
                    }
                    if slot.is_none_or(|slot| self.used_pulse_slots.get(&slot) != Some(pulse_id))
                        || output.is_none()
                        || assignment_cap.is_none()
                        || candidate_snapshot_index
                            .and_then(|index| usize::try_from(index).ok())
                            .is_none_or(|index| self.candidate_snapshots.get(index).is_none())
                    {
                        return Err(ParliamentReducerErrorV1::PulseBindingMismatch);
                    }
                }
                ParliamentPulseConsumerV1::BallotBatch(ballot_ids) => {
                    if ballot_ids.is_empty() || !ballot_ids.windows(2).all(|pair| pair[0] < pair[1])
                    {
                        return Err(ParliamentReducerErrorV1::PulseBindingMismatch);
                    }
                    let mut slot = None;
                    for ballot_id in ballot_ids {
                        let ballot = self
                            .ballots
                            .get(ballot_id)
                            .ok_or(ParliamentReducerErrorV1::PulseBindingMismatch)?;
                        if ballot.release_pulse_id != Some(*pulse_id) {
                            return Err(ParliamentReducerErrorV1::PulseBindingMismatch);
                        }
                        let ballot_slot = ParliamentPulseSlotV1::new(
                            ballot
                                .release_beacon_session_id
                                .ok_or(ParliamentReducerErrorV1::PulseBindingMismatch)?,
                            ballot
                                .release_height
                                .ok_or(ParliamentReducerErrorV1::PulseBindingMismatch)?,
                        );
                        if slot.is_some_and(|expected| expected != ballot_slot) {
                            return Err(ParliamentReducerErrorV1::PulseBindingMismatch);
                        }
                        slot = Some(ballot_slot);
                    }
                    if slot.is_none_or(|slot| self.used_pulse_slots.get(&slot) != Some(pulse_id)) {
                        return Err(ParliamentReducerErrorV1::PulseBindingMismatch);
                    }
                }
            }
        }
        for pulse_id in self.used_pulse_slots.values() {
            if !self.used_pulse_ids.contains_key(pulse_id) {
                return Err(ParliamentReducerErrorV1::PulseBindingMismatch);
            }
        }

        for (body_role, binding) in &self.body_bindings {
            let rebuilt = self.build_body_binding(binding.body_instance_id)?;
            if binding.body != *body_role || &rebuilt != binding {
                return Err(ParliamentReducerErrorV1::CertificateBindingMismatch);
            }
        }
        let policy_binding = self.body_bindings.get(&ParliamentBody::PolicyJury);
        let requires_confirmation = policy_binding
            .and_then(|binding| binding.ballot)
            .map(|policy_ballot| {
                policy_ballot
                    .tally
                    .requires_confirmation()
                    .map_err(|_| ParliamentReducerErrorV1::InvalidTally)
            })
            .transpose()?
            .unwrap_or(false);
        if requires_confirmation != confirmation_required {
            return Err(ParliamentReducerErrorV1::IncompleteCertificate);
        }
        if let Some(certificate) = &self.certificate {
            certificate
                .validate()
                .map_err(|_| ParliamentReducerErrorV1::CertificateBindingMismatch)?;
            if certificate.proposal_content_id != self.attempt.proposal_content_id
                || certificate.governance_attempt_id != self.attempt.id
                || certificate.governance_attempt_sequence != self.attempt.sequence
                || certificate.risk_tier != self.attempt.risk_tier
                || certificate.policy_version != self.policy_version
                || certificate.effect_preimage_hash != self.effect_preimage_hash
                || certificate.expected_head != self.expected_head
                || certificate.certified_at_height == 0
                || certificate.enact_at_height <= certificate.certified_at_height
                || certificate.body_bindings.len() != self.required_bodies.len()
                || self.attempt.stage != GovernanceStageV1::Enactment
                || !matches!(
                    self.attempt.status,
                    GovernanceAttemptStatusV1::Certified
                        | GovernanceAttemptStatusV1::Enacted
                        | GovernanceAttemptStatusV1::Superseded
                        | GovernanceAttemptStatusV1::ExecutionFailed
                )
            {
                return Err(ParliamentReducerErrorV1::CertificateBindingMismatch);
            }
            for (requirement, binding) in
                self.required_bodies.iter().zip(&certificate.body_bindings)
            {
                if binding.body != requirement.body
                    || self.body_bindings.get(&requirement.body) != Some(binding)
                {
                    return Err(ParliamentReducerErrorV1::CertificateBindingMismatch);
                }
            }
            match self.attempt.status {
                GovernanceAttemptStatusV1::Certified => {
                    if self.terminal_height.is_some()
                        || self.superseding_head.is_some()
                        || self.execution_failure_root.is_some()
                    {
                        return Err(ParliamentReducerErrorV1::CertificateBindingMismatch);
                    }
                }
                GovernanceAttemptStatusV1::Enacted => {
                    if self.terminal_height != Some(certificate.enact_at_height)
                        || self.superseding_head.is_some()
                        || self.execution_failure_root.is_some()
                    {
                        return Err(ParliamentReducerErrorV1::CertificateBindingMismatch);
                    }
                }
                GovernanceAttemptStatusV1::Superseded => {
                    if self.terminal_height != Some(certificate.enact_at_height)
                        || self.superseding_head.is_none_or(|head| {
                            head == certificate.expected_head
                                || !expected_head_is_valid(head)
                                || expected_head_subject(head)
                                    != expected_head_subject(certificate.expected_head)
                        })
                        || self.execution_failure_root.is_some()
                    {
                        return Err(ParliamentReducerErrorV1::CertificateBindingMismatch);
                    }
                }
                GovernanceAttemptStatusV1::ExecutionFailed => {
                    if self.terminal_height != Some(certificate.enact_at_height)
                        || self.superseding_head.is_some()
                        || self.execution_failure_root
                            != Some(parliament_execution_failure_root_v1(
                                certificate,
                                certificate.enact_at_height,
                            ))
                    {
                        return Err(ParliamentReducerErrorV1::CertificateBindingMismatch);
                    }
                }
                GovernanceAttemptStatusV1::Active | GovernanceAttemptStatusV1::Rejected => {
                    return Err(ParliamentReducerErrorV1::CertificateBindingMismatch);
                }
            }
        } else if matches!(
            self.attempt.status,
            GovernanceAttemptStatusV1::Certified
                | GovernanceAttemptStatusV1::Enacted
                | GovernanceAttemptStatusV1::Superseded
                | GovernanceAttemptStatusV1::ExecutionFailed
        ) {
            return Err(ParliamentReducerErrorV1::IncompleteCertificate);
        } else if self.terminal_height.is_some()
            || self.superseding_head.is_some()
            || self.execution_failure_root.is_some()
        {
            return Err(ParliamentReducerErrorV1::CertificateBindingMismatch);
        }
        Ok(())
    }
}
