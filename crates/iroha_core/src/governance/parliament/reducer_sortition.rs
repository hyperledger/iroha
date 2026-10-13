impl ParliamentAttemptStateV1 {
    fn validate_sortition_registration_batch_v1(
        &self,
        governance_attempt_id: GovernanceAttemptId,
        registrations: &[ParliamentSortitionRequestRegistrationV1],
    ) -> Result<(), ParliamentReducerErrorV1> {
        self.ensure_active(governance_attempt_id)?;
        if registrations.is_empty()
            || !registrations
                .windows(2)
                .all(|pair| pair[0].request.body < pair[1].request.body)
        {
            return Err(ParliamentReducerErrorV1::InvalidAssignmentPlan);
        }

        let first = registrations
            .first()
            .expect("nonempty sortition registration batch checked above");
        if registrations.iter().any(|entry| {
            entry.request.governance_attempt_id != governance_attempt_id
                || entry.request.request_height != first.request.request_height
                || entry.request.pulse_height != first.request.pulse_height
                || entry.request.beacon_session_id != first.request.beacon_session_id
                || entry.request.candidate_count != first.request.candidate_count
        }) {
            return Err(ParliamentReducerErrorV1::PulseBindingMismatch);
        }

        let initial_bodies: Vec<_> = self
            .required_bodies
            .iter()
            .filter_map(|required| {
                (required.body != ParliamentBody::ConfirmationJury).then_some(required.body)
            })
            .collect();
        if self.used_pulse_ids.is_empty() {
            let registered_bodies: Vec<_> = registrations
                .iter()
                .map(|entry| entry.request.body)
                .collect();
            if registered_bodies != initial_bodies {
                return Err(ParliamentReducerErrorV1::InvalidAssignmentPlan);
            }
            let has_predecessors = initial_bodies.iter().any(|body| {
                self.active_elections.contains_key(body)
                    || self.active_sortition_capacity_failures.contains_key(body)
            });
            if !has_predecessors && registrations.iter().any(|entry| entry.sequence != 0) {
                return Err(ParliamentReducerErrorV1::RetrySequenceMismatch);
            }
            // Before any pulse is consumed no election can have failed (an election
            // leaves its pulse wait only by consuming the pulse of its exact slot), so
            // the only retryable predecessor is a hidden-capacity failure of the
            // complete initial generation. A pending election is never superseded.
            if has_predecessors
                && initial_bodies.iter().any(|body| {
                    !self
                        .active_sortition_capacity_failures
                        .get(body)
                        .and_then(|id| self.sortition_capacity_failures.get(id))
                        .is_some_and(|failure| {
                            failure.status == BodyElectionAttemptStatusV1::NoRoster
                        })
                })
            {
                return Err(ParliamentReducerErrorV1::InvalidLifecycleTransition(
                    ParliamentReducerEntityV1::BodyElection,
                ));
            }
        } else {
            // One fresh slot retries every failed body together: a single-body retry could
            // spend the last proposal-wide redraw unit and strand another failed body that no
            // later block could afford to redraw. Without a failed body, the batch is the one
            // newly required body.
            let failed_bodies: Vec<_> = self
                .no_roster_sortition_generations_v1()
                .into_keys()
                .collect();
            let registered_bodies: Vec<_> = registrations
                .iter()
                .map(|entry| entry.request.body)
                .collect();
            if (failed_bodies.is_empty() && registrations.len() != 1)
                || (!failed_bodies.is_empty() && registered_bodies != failed_bodies)
            {
                return Err(ParliamentReducerErrorV1::InvalidAssignmentPlan);
            }
        }
        // Every generation owns a fresh pulse slot. A batch joining a slot that an earlier
        // batch registered could freeze a different snapshot for the same pulse, and the
        // pulse batch, which draws every request of a slot from one snapshot, could then
        // never consume it.
        if self
            .sortition_generation_slots_v1()
            .contains(&ParliamentPulseSlotV1::new(
                first.request.beacon_session_id,
                first.request.pulse_height,
            ))
        {
            return Err(ParliamentReducerErrorV1::InvalidSortitionPulseSchedule);
        }
        Ok(())
    }

    /// Return every body whose active sortition generation ended `NoRoster`, with that
    /// generation's sequence, in body order.
    fn no_roster_sortition_generations_v1(&self) -> BTreeMap<ParliamentBody, u32> {
        let elections = self.active_elections.iter().filter_map(|(body, id)| {
            self.elections
                .get(id)
                .filter(|election| election.attempt.status == BodyElectionAttemptStatusV1::NoRoster)
                .map(|election| (*body, election.attempt.sequence))
        });
        let capacity_failures =
            self.active_sortition_capacity_failures
                .iter()
                .filter_map(|(body, id)| {
                    self.sortition_capacity_failures
                        .get(id)
                        .filter(|failure| failure.status == BodyElectionAttemptStatusV1::NoRoster)
                        .map(|failure| (*body, failure.sequence))
                });
        elections.chain(capacity_failures).collect()
    }

    /// Derive the exact next sortition generation a block at `request_height` registers for
    /// every body whose active generation ended `NoRoster`, with its candidate snapshot.
    ///
    /// Every field is fixed by committed state: each failed body's next sequence, the shared
    /// pulse slot [`Self::next_sortition_generation_pulse_height_v1`] derives on
    /// `beacon_session_id` (the first consensus-native pulse height at or after
    /// `request_height` plus the frozen delay and above every earlier generation slot),
    /// the configured body size, and the canonical snapshot of `eligible_candidates` (less
    /// the sealed Policy Jury for a Confirmation Jury retry). Returns `None` when no body
    /// awaits a retry or the generation cannot be expressed. Admission still decides whether
    /// the generation is accepted and whether a sub-floor hidden electorate turns it into
    /// capacity evidence.
    pub(crate) fn next_sortition_retry_v1(
        &self,
        request_height: u64,
        beacon_session_id: BeaconSessionId,
        governance: &Governance,
        eligible_candidates: Vec<AccountId>,
    ) -> Option<(
        Vec<ParliamentSortitionRequestRegistrationV1>,
        Vec<AccountId>,
    )> {
        let failed = self.no_roster_sortition_generations_v1();
        let candidate_snapshot = if failed.contains_key(&ParliamentBody::ConfirmationJury) {
            if failed.len() != 1 {
                return None;
            }
            let policy_members: BTreeSet<_> = self
                .sealed_body_for_role(ParliamentBody::PolicyJury)?
                .assignments
                .iter()
                .map(|assignment| &assignment.member)
                .collect();
            eligible_candidates
                .into_iter()
                .filter(|candidate| !policy_members.contains(candidate))
                .collect()
        } else {
            eligible_candidates
        };
        let pulse_height =
            self.next_sortition_generation_pulse_height_v1(request_height, beacon_session_id)?;
        let candidate_count = u32::try_from(candidate_snapshot.len()).ok()?;
        let registrations = failed
            .into_iter()
            .map(|(body, failed_sequence)| {
                let sequence = failed_sequence.checked_add(1)?;
                // An empty snapshot is capacity intent, which admission records as typed
                // evidence; `try_new_canonical` would refuse it.
                let mut request = SortitionRequestV1 {
                    id: SortitionRequestId::new([0; 32]),
                    governance_attempt_id: self.attempt.id,
                    body_election_attempt_id: BodyElectionAttemptId::derive_v1(
                        self.attempt.id,
                        body,
                        sequence,
                    ),
                    body,
                    candidate_root: parliament_candidate_root_v1(
                        self.attempt.id,
                        body,
                        &candidate_snapshot,
                    ),
                    candidate_count,
                    target_seats: u32::try_from(body_committee_size(governance, body)).ok()?,
                    request_height,
                    pulse_height,
                    beacon_session_id,
                };
                request.id = request.canonical_id();
                Some(ParliamentSortitionRequestRegistrationV1 { sequence, request })
            })
            .collect::<Option<Vec<_>>>()?;
        (!registrations.is_empty()).then_some((registrations, candidate_snapshot))
    }

    /// Atomically register one canonical future-pulse request batch.
    ///
    /// The first batch must contain every initially required body exactly once,
    /// in body order, and freezes one shared candidate snapshot. Before any pulse
    /// is consumed, only a hidden-capacity failure of that complete initial
    /// generation is retried, atomically; a generation awaiting its pulse is never
    /// retried, redrawn or superseded.
    /// After any pulse is consumed, a no-roster retry contains exactly every body
    /// whose active generation ended `NoRoster`, and a dynamically required
    /// Confirmation Jury uses a one-request batch; either may freeze a fresh
    /// snapshot. Mutation is committed only after every request validates.
    ///
    /// # Errors
    /// Returns an error for an empty, partial, mixed-slot, noncanonical, or
    /// otherwise invalid batch without modifying the reducer.
    pub fn register_sortition_request_batch(
        &mut self,
        governance_attempt_id: GovernanceAttemptId,
        registrations: Vec<ParliamentSortitionRequestRegistrationV1>,
        candidate_snapshot: Vec<AccountId>,
    ) -> Result<(), ParliamentReducerErrorV1> {
        self.validate_sortition_registration_batch_v1(governance_attempt_id, &registrations)?;

        let mut next = self.clone();
        for entry in registrations {
            next.register_sortition_request(
                governance_attempt_id,
                entry.sequence,
                entry.request,
                candidate_snapshot.clone(),
            )?;
        }
        *self = next;
        Ok(())
    }

    /// Record an objective sub-anonymity-floor electorate before a hidden-body
    /// future-pulse request can be created.
    ///
    /// The submitted batch remains the request intent and must retain every
    /// ordinary immutable binding. Core persists separate typed evidence for
    /// every body of the generation, consumes no pulse slot, and makes the exact
    /// next generation eligible in a later block. The final permitted generation
    /// rejects the governance attempt with the ordinary sortition-exhaustion result.
    ///
    /// # Errors
    /// Returns an error unless the batch is the exact initial generation or the
    /// exact retry generation of every failed body and includes a hidden body, the
    /// live snapshot is canonically ordered and has fewer than the V1 anonymity
    /// floor, and every non-candidate request binding is valid.
    pub fn record_hidden_sortition_capacity_failure_batch(
        &mut self,
        governance_attempt_id: GovernanceAttemptId,
        registrations: Vec<ParliamentSortitionRequestRegistrationV1>,
        candidate_snapshot: Vec<AccountId>,
    ) -> Result<(), ParliamentReducerErrorV1> {
        self.validate_sortition_registration_batch_v1(governance_attempt_id, &registrations)?;
        if hidden_ballot_population_meets_anonymity_floor_v1(candidate_snapshot.len())
            || !candidate_snapshot_fits_resource_bounds_v1(&candidate_snapshot)
            || !candidate_snapshot.windows(2).all(|pair| pair[0] < pair[1])
            || !registrations.iter().any(|entry| {
                self.required_bodies.iter().any(|required| {
                    required.body == entry.request.body
                        && required.decision_mode == ParliamentDecisionModeV1::HiddenBindingBallot
                })
            })
        {
            return Err(ParliamentReducerErrorV1::InvalidCandidateSnapshot);
        }

        let mut next = self.clone();
        let mut retry_budget_exhausted = false;
        for entry in registrations {
            retry_budget_exhausted |= entry.sequence == MAX_PARLIAMENT_SORTITION_RETRIES_V1;
            next.record_hidden_sortition_capacity_failure(
                governance_attempt_id,
                entry.sequence,
                entry.request,
                candidate_snapshot.clone(),
            )?;
        }
        if retry_budget_exhausted
            || next.randomness_redraws_used_v1()? == MAX_PARLIAMENT_RANDOMNESS_REDRAWS_V1
        {
            next.attempt.status = GovernanceAttemptStatusV1::Rejected;
        }
        *self = next;
        Ok(())
    }

    fn record_hidden_sortition_capacity_failure(
        &mut self,
        governance_attempt_id: GovernanceAttemptId,
        sequence: u32,
        request_intent: SortitionRequestV1,
        candidate_snapshot: Vec<AccountId>,
    ) -> Result<(), ParliamentReducerErrorV1> {
        self.ensure_active(governance_attempt_id)?;
        let requirement = self.ensure_draw_eligible_body(request_intent.body)?;
        if sequence > MAX_PARLIAMENT_SORTITION_RETRIES_V1 {
            return Err(ParliamentReducerErrorV1::SortitionRetryLimitExceeded);
        }
        let candidate_count = u32::try_from(candidate_snapshot.len())
            .map_err(|_| ParliamentReducerErrorV1::InvalidCandidateSnapshot)?;
        if candidate_count >= MIN_PARLIAMENT_HIDDEN_BALLOT_ANONYMITY_V1
            || !candidate_snapshot_fits_resource_bounds_v1(&candidate_snapshot)
            || !candidate_snapshot.windows(2).all(|pair| pair[0] < pair[1])
            || request_intent.governance_attempt_id != governance_attempt_id
            || request_intent.body_election_attempt_id
                != BodyElectionAttemptId::derive_v1(
                    governance_attempt_id,
                    request_intent.body,
                    sequence,
                )
            || request_intent.id != request_intent.canonical_id()
            || request_intent.candidate_count != candidate_count
            || request_intent.candidate_root
                != parliament_candidate_root_v1(
                    governance_attempt_id,
                    request_intent.body,
                    &candidate_snapshot,
                )
        {
            return Err(ParliamentReducerErrorV1::InvalidCandidateSnapshot);
        }
        if request_intent.id.as_bytes().iter().all(|byte| *byte == 0)
            || request_intent
                .body_election_attempt_id
                .as_bytes()
                .iter()
                .all(|byte| *byte == 0)
            || request_intent
                .beacon_session_id
                .as_bytes()
                .iter()
                .all(|byte| *byte == 0)
        {
            return Err(ParliamentReducerErrorV1::DuplicateOrZeroIdentifier(
                ParliamentReducerEntityV1::SortitionRequest,
            ));
        }
        if root_is_zero(&request_intent.candidate_root) {
            return Err(ParliamentReducerErrorV1::ZeroCommitmentRoot);
        }
        if request_intent.target_seats == 0
            || request_intent.target_seats > MAX_PARLIAMENT_BODY_TARGET_SEATS_V1
            || (requirement.decision_mode == ParliamentDecisionModeV1::HiddenBindingBallot
                && request_intent.target_seats < MIN_PARLIAMENT_HIDDEN_BALLOT_ANONYMITY_V1)
        {
            return Err(ParliamentReducerErrorV1::InvalidAssignmentPlan);
        }
        self.ensure_sortition_generation_pulse_height_v1(
            request_intent.request_height,
            request_intent.pulse_height,
            request_intent.beacon_session_id,
        )?;
        let last_consumed = self
            .used_pulse_slots
            .keys()
            .filter_map(|slot| {
                (slot.beacon_session_id == request_intent.beacon_session_id).then_some(slot.height)
            })
            .max();
        if last_consumed.is_some_and(|height| request_intent.pulse_height <= height)
            || self
                .used_pulse_slots
                .contains_key(&ParliamentPulseSlotV1::new(
                    request_intent.beacon_session_id,
                    request_intent.pulse_height,
                ))
        {
            return Err(ParliamentReducerErrorV1::BeaconPulseAlreadyConsumed);
        }
        if request_intent.body == ParliamentBody::ConfirmationJury {
            let policy_result_height = self
                .body_bindings
                .get(&ParliamentBody::PolicyJury)
                .map(|binding| binding.result_height)
                .ok_or(ParliamentReducerErrorV1::ConfirmationJuryNotFresh)?;
            if request_intent.request_height < policy_result_height
                || (sequence == 0 && request_intent.request_height != policy_result_height)
            {
                return Err(ParliamentReducerErrorV1::ConfirmationJuryNotFresh);
            }
            let policy_members = self
                .sealed_body_for_role(ParliamentBody::PolicyJury)
                .ok_or(ParliamentReducerErrorV1::ConfirmationJuryNotFresh)?
                .assignments
                .iter()
                .map(|assignment| assignment.member.clone())
                .collect::<BTreeSet<_>>();
            if candidate_snapshot
                .iter()
                .any(|candidate| policy_members.contains(candidate))
            {
                return Err(ParliamentReducerErrorV1::ConfirmationJuryNotFresh);
            }
        }
        if self
            .elections
            .values()
            .any(|election| election.attempt.request.id == request_intent.id)
            || self
                .sortition_capacity_failures
                .values()
                .any(|failure| failure.request_intent_id == request_intent.id)
            || self
                .elections
                .contains_key(&request_intent.body_election_attempt_id)
            || self
                .sortition_capacity_failures
                .contains_key(&request_intent.body_election_attempt_id)
        {
            return Err(ParliamentReducerErrorV1::DuplicateOrZeroIdentifier(
                ParliamentReducerEntityV1::BodyElection,
            ));
        }
        self.ensure_sortition_generation_redraw_available_v1(
            request_intent.beacon_session_id,
            request_intent.pulse_height,
        )?;

        let election_predecessor = self.active_elections.get(&request_intent.body).copied();
        let capacity_predecessor = self
            .active_sortition_capacity_failures
            .get(&request_intent.body)
            .copied();
        if election_predecessor.is_some() && capacity_predecessor.is_some() {
            return Err(ParliamentReducerErrorV1::ImmutableBindingMismatch);
        }
        match (election_predecessor, capacity_predecessor) {
            (None, None) if sequence != 0 => {
                return Err(ParliamentReducerErrorV1::RetrySequenceMismatch);
            }
            (Some(previous_id), None) => {
                let previous = self.elections.get(&previous_id).ok_or(
                    ParliamentReducerErrorV1::UnknownEntity(
                        ParliamentReducerEntityV1::BodyElection,
                    ),
                )?;
                if previous.attempt.status != BodyElectionAttemptStatusV1::NoRoster {
                    return Err(ParliamentReducerErrorV1::InvalidLifecycleTransition(
                        ParliamentReducerEntityV1::BodyElection,
                    ));
                }
                if previous
                    .failure_height
                    .is_none_or(|failure_height| request_intent.request_height < failure_height)
                {
                    return Err(ParliamentReducerErrorV1::InvalidSortitionPulseSchedule);
                }
                if previous.attempt.sequence >= MAX_PARLIAMENT_SORTITION_RETRIES_V1 {
                    return Err(ParliamentReducerErrorV1::SortitionRetryLimitExceeded);
                }
                if sequence != previous.attempt.sequence.saturating_add(1) {
                    return Err(ParliamentReducerErrorV1::RetrySequenceMismatch);
                }
            }
            (None, Some(previous_id)) => {
                let previous = self.sortition_capacity_failures.get(&previous_id).ok_or(
                    ParliamentReducerErrorV1::UnknownEntity(
                        ParliamentReducerEntityV1::BodyElection,
                    ),
                )?;
                if previous.status != BodyElectionAttemptStatusV1::NoRoster {
                    return Err(ParliamentReducerErrorV1::InvalidLifecycleTransition(
                        ParliamentReducerEntityV1::BodyElection,
                    ));
                }
                if request_intent.request_height <= previous.failure_height {
                    return Err(ParliamentReducerErrorV1::InvalidSortitionPulseSchedule);
                }
                if previous.sequence >= MAX_PARLIAMENT_SORTITION_RETRIES_V1 {
                    return Err(ParliamentReducerErrorV1::SortitionRetryLimitExceeded);
                }
                if sequence != previous.sequence.saturating_add(1) {
                    return Err(ParliamentReducerErrorV1::RetrySequenceMismatch);
                }
            }
            (None, None) => {}
            (Some(_), Some(_)) => unreachable!("dual active generation rejected above"),
        }

        if let Some(previous_id) = election_predecessor {
            self.elections
                .get_mut(&previous_id)
                .expect("predecessor checked above")
                .attempt
                .status = BodyElectionAttemptStatusV1::Superseded;
            self.active_elections.remove(&request_intent.body);
        }
        if let Some(previous_id) = capacity_predecessor {
            self.sortition_capacity_failures
                .get_mut(&previous_id)
                .expect("predecessor checked above")
                .status = BodyElectionAttemptStatusV1::Superseded;
        }
        if request_intent.body == ParliamentBody::PolicyJury {
            self.risk_locked = true;
        }
        let failure = ParliamentSortitionCapacityFailureV1 {
            body_election_attempt_id: request_intent.body_election_attempt_id,
            body: request_intent.body,
            sequence,
            request_intent_id: request_intent.id,
            candidate_snapshot,
            candidate_root: request_intent.candidate_root,
            target_seats: request_intent.target_seats,
            request_height: request_intent.request_height,
            pulse_height: request_intent.pulse_height,
            beacon_session_id: request_intent.beacon_session_id,
            status: BodyElectionAttemptStatusV1::NoRoster,
            failure_height: request_intent.request_height,
        };
        self.active_sortition_capacity_failures
            .insert(request_intent.body, request_intent.body_election_attempt_id);
        self.sortition_capacity_failures
            .insert(request_intent.body_election_attempt_id, failure);
        Ok(())
    }

    /// Register an immutable body-election attempt and future-pulse request.
    ///
    /// A retry is accepted only after the prior election reached `NoRoster`,
    /// uses sequence `previous + 1`, and supersedes that prior attempt.
    ///
    /// # Errors
    /// Returns an error for wrong bindings, invalid request bounds, duplicate
    /// identifiers, wrong stage/body, pulse reuse, or a noncanonical retry.
    pub(crate) fn register_sortition_request(
        &mut self,
        governance_attempt_id: GovernanceAttemptId,
        sequence: u32,
        request: SortitionRequestV1,
        candidate_snapshot: Vec<AccountId>,
    ) -> Result<(), ParliamentReducerErrorV1> {
        self.ensure_active(governance_attempt_id)?;
        let requirement = self.ensure_draw_eligible_body(request.body)?;
        if sequence > MAX_PARLIAMENT_SORTITION_RETRIES_V1 {
            return Err(ParliamentReducerErrorV1::SortitionRetryLimitExceeded);
        }
        if request.governance_attempt_id != governance_attempt_id {
            return Err(ParliamentReducerErrorV1::ImmutableBindingMismatch);
        }
        if request.id.as_bytes().iter().all(|byte| *byte == 0)
            || request
                .body_election_attempt_id
                .as_bytes()
                .iter()
                .all(|byte| *byte == 0)
        {
            return Err(ParliamentReducerErrorV1::DuplicateOrZeroIdentifier(
                ParliamentReducerEntityV1::SortitionRequest,
            ));
        }
        if root_is_zero(&request.candidate_root) {
            return Err(ParliamentReducerErrorV1::ZeroCommitmentRoot);
        }
        if requirement.decision_mode == ParliamentDecisionModeV1::HiddenBindingBallot
            && request.target_seats < MIN_PARLIAMENT_HIDDEN_BALLOT_ANONYMITY_V1
        {
            return Err(ParliamentReducerErrorV1::InvalidAssignmentPlan);
        }
        if candidate_snapshot.is_empty()
            || !candidate_snapshot_fits_resource_bounds_v1(&candidate_snapshot)
            || (requirement.decision_mode == ParliamentDecisionModeV1::HiddenBindingBallot
                && !hidden_ballot_population_meets_anonymity_floor_v1(candidate_snapshot.len()))
            || !candidate_snapshot.windows(2).all(|pair| pair[0] < pair[1])
            || u32::try_from(candidate_snapshot.len()).ok() != Some(request.candidate_count)
            || request.candidate_root
                != parliament_candidate_root_v1(
                    governance_attempt_id,
                    request.body,
                    &candidate_snapshot,
                )
        {
            return Err(ParliamentReducerErrorV1::InvalidCandidateSnapshot);
        }
        if self
            .elections
            .values()
            .any(|election| election.attempt.request.id == request.id)
            || self
                .sortition_capacity_failures
                .values()
                .any(|failure| failure.request_intent_id == request.id)
            || self
                .elections
                .contains_key(&request.body_election_attempt_id)
            || self
                .sortition_capacity_failures
                .contains_key(&request.body_election_attempt_id)
        {
            return Err(ParliamentReducerErrorV1::DuplicateOrZeroIdentifier(
                ParliamentReducerEntityV1::BodyElection,
            ));
        }
        self.ensure_sortition_generation_redraw_available_v1(
            request.beacon_session_id,
            request.pulse_height,
        )?;
        let last_consumed = self
            .used_pulse_slots
            .keys()
            .filter_map(|slot| {
                (slot.beacon_session_id == request.beacon_session_id).then_some(slot.height)
            })
            .max();
        request
            .validate(last_consumed)
            .map_err(|_| ParliamentReducerErrorV1::ImmutableBindingMismatch)?;
        self.ensure_sortition_generation_pulse_height_v1(
            request.request_height,
            request.pulse_height,
            request.beacon_session_id,
        )?;
        if request.body == ParliamentBody::ConfirmationJury {
            let policy_result_height = self
                .body_bindings
                .get(&ParliamentBody::PolicyJury)
                .map(|binding| binding.result_height)
                .ok_or(ParliamentReducerErrorV1::ConfirmationJuryNotFresh)?;
            if request.request_height < policy_result_height
                || (sequence == 0 && request.request_height != policy_result_height)
            {
                return Err(ParliamentReducerErrorV1::ConfirmationJuryNotFresh);
            }
            let policy_members: BTreeSet<_> = self
                .bodies
                .values()
                .find(|body| body.instance.body == ParliamentBody::PolicyJury)
                .ok_or(ParliamentReducerErrorV1::ConfirmationJuryNotFresh)?
                .assignments
                .iter()
                .map(|assignment| assignment.member.clone())
                .collect();
            if candidate_snapshot
                .iter()
                .any(|candidate| policy_members.contains(candidate))
            {
                return Err(ParliamentReducerErrorV1::ConfirmationJuryNotFresh);
            }
        }
        if self
            .used_pulse_slots
            .contains_key(&ParliamentPulseSlotV1::new(
                request.beacon_session_id,
                request.pulse_height,
            ))
        {
            return Err(ParliamentReducerErrorV1::BeaconPulseAlreadyConsumed);
        }

        let election_predecessor = self.active_elections.get(&request.body).copied();
        let capacity_predecessor = self
            .active_sortition_capacity_failures
            .get(&request.body)
            .copied();
        if election_predecessor.is_some() && capacity_predecessor.is_some() {
            return Err(ParliamentReducerErrorV1::ImmutableBindingMismatch);
        }
        match (election_predecessor, capacity_predecessor) {
            (None, None) if sequence != 0 => {
                return Err(ParliamentReducerErrorV1::RetrySequenceMismatch);
            }
            (Some(previous_id), None) => {
                let previous = self.elections.get(&previous_id).ok_or(
                    ParliamentReducerErrorV1::UnknownEntity(
                        ParliamentReducerEntityV1::BodyElection,
                    ),
                )?;
                if previous.attempt.status != BodyElectionAttemptStatusV1::NoRoster {
                    return Err(ParliamentReducerErrorV1::InvalidLifecycleTransition(
                        ParliamentReducerEntityV1::BodyElection,
                    ));
                }
                if previous
                    .failure_height
                    .is_none_or(|failure_height| request.request_height < failure_height)
                {
                    return Err(ParliamentReducerErrorV1::InvalidSortitionPulseSchedule);
                }
                if previous.attempt.sequence >= MAX_PARLIAMENT_SORTITION_RETRIES_V1 {
                    return Err(ParliamentReducerErrorV1::SortitionRetryLimitExceeded);
                }
                if sequence != previous.attempt.sequence.saturating_add(1) {
                    return Err(ParliamentReducerErrorV1::RetrySequenceMismatch);
                }
            }
            (None, Some(previous_id)) => {
                let previous = self.sortition_capacity_failures.get(&previous_id).ok_or(
                    ParliamentReducerErrorV1::UnknownEntity(
                        ParliamentReducerEntityV1::BodyElection,
                    ),
                )?;
                if previous.status != BodyElectionAttemptStatusV1::NoRoster {
                    return Err(ParliamentReducerErrorV1::InvalidLifecycleTransition(
                        ParliamentReducerEntityV1::BodyElection,
                    ));
                }
                if request.request_height <= previous.failure_height {
                    return Err(ParliamentReducerErrorV1::InvalidSortitionPulseSchedule);
                }
                if previous.sequence >= MAX_PARLIAMENT_SORTITION_RETRIES_V1 {
                    return Err(ParliamentReducerErrorV1::SortitionRetryLimitExceeded);
                }
                if sequence != previous.sequence.saturating_add(1) {
                    return Err(ParliamentReducerErrorV1::RetrySequenceMismatch);
                }
            }
            (None, None) => {}
            (Some(_), Some(_)) => unreachable!("dual active generation rejected above"),
        }

        let attempt = iroha_data_model::governance::types::BodyElectionAttemptV1::try_new(
            request.body_election_attempt_id,
            governance_attempt_id,
            sequence,
            request,
            BodyElectionAttemptStatusV1::AwaitingPulse,
        )
        .map_err(|_| ParliamentReducerErrorV1::ImmutableBindingMismatch)?;

        let candidate_snapshot_index = match self
            .candidate_snapshots
            .iter()
            .position(|persisted| persisted == &candidate_snapshot)
        {
            Some(index) => u32::try_from(index)
                .map_err(|_| ParliamentReducerErrorV1::InvalidCandidateSnapshot)?,
            None => {
                let index = u32::try_from(self.candidate_snapshots.len())
                    .map_err(|_| ParliamentReducerErrorV1::InvalidCandidateSnapshot)?;
                self.candidate_snapshots.push(candidate_snapshot);
                index
            }
        };

        if let Some(previous_id) = election_predecessor {
            self.elections
                .get_mut(&previous_id)
                .expect("predecessor checked above")
                .attempt
                .status = BodyElectionAttemptStatusV1::Superseded;
        }
        if let Some(previous_id) = capacity_predecessor {
            self.sortition_capacity_failures
                .get_mut(&previous_id)
                .expect("predecessor checked above")
                .status = BodyElectionAttemptStatusV1::Superseded;
            self.active_sortition_capacity_failures
                .remove(&request.body);
        }
        if request.body == ParliamentBody::PolicyJury {
            self.risk_locked = true;
        }
        self.active_elections
            .insert(request.body, request.body_election_attempt_id);
        self.elections.insert(
            request.body_election_attempt_id,
            ParliamentElectionStateV1 {
                attempt,
                candidate_snapshot_index,
                pulse_id: None,
                pulse_output: None,
                assignment_root: None,
                primary_assignments: Vec::new(),
                alternate_assignments: Vec::new(),
                cross_body_assignment_cap: None,
                invitation_opened_at_height: None,
                invitation_close_height: None,
                accepted_assignments: BTreeSet::new(),
                declined_assignments: BTreeSet::new(),
                failure_kind: None,
                failure_height: None,
            },
        );
        Ok(())
    }

    /// Consume one finalized future pulse and derive its complete assignment plans.
    ///
    /// The first consumed pulse must cover every initially required body in one
    /// simultaneous batch, so a trigger cannot evade cross-body concentration
    /// limits by splitting the draw. Later no-roster retries and a dynamically
    /// required Confirmation Jury may use fresh dedicated pulse slots.
    ///
    /// # Errors
    /// Returns an error for replay, a wrong request/session/height binding, a
    /// duplicate pulse identifier or session-height slot, or a wrong attempt.
    pub fn consume_sortition_pulse_batch(
        &mut self,
        governance_attempt_id: GovernanceAttemptId,
        request_ids: Vec<SortitionRequestId>,
        beacon_session_id: BeaconSessionId,
        pulse_height: u64,
        pulse_id: BeaconPulseId,
        pulse_output: [u8; 32],
        network_id: &NetworkId,
        governance: &Governance,
    ) -> Result<(), ParliamentReducerErrorV1> {
        struct DerivedElectionPlan {
            election_id: BodyElectionAttemptId,
            primary: Vec<ParliamentSeatAssignmentV1>,
            alternates: Vec<ParliamentSeatAssignmentV1>,
            assignment_root: [u8; 32],
        }
        self.ensure_active(governance_attempt_id)?;
        if pulse_id.as_bytes().iter().all(|byte| *byte == 0) {
            return Err(ParliamentReducerErrorV1::DuplicateOrZeroIdentifier(
                ParliamentReducerEntityV1::SortitionRequest,
            ));
        }
        if request_ids.is_empty() || !request_ids.windows(2).all(|pair| pair[0] < pair[1]) {
            return Err(ParliamentReducerErrorV1::PulseBindingMismatch);
        }
        let expected_request_ids: Vec<_> = self
            .elections
            .values()
            .filter(|election| {
                election.attempt.status == BodyElectionAttemptStatusV1::AwaitingPulse
                    && election.attempt.request.beacon_session_id == beacon_session_id
                    && election.attempt.request.pulse_height == pulse_height
            })
            .map(|election| election.attempt.request.id)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        if request_ids != expected_request_ids {
            return Err(ParliamentReducerErrorV1::PulseBindingMismatch);
        }
        let mut election_ids = Vec::with_capacity(request_ids.len());
        let mut bodies = Vec::with_capacity(request_ids.len());
        let mut shared_candidate_snapshot_index = None;
        for request_id in &request_ids {
            let (election_id, election) = self
                .elections
                .iter()
                .find(|(_, state)| state.attempt.request.id == *request_id)
                .ok_or(ParliamentReducerErrorV1::UnknownEntity(
                    ParliamentReducerEntityV1::SortitionRequest,
                ))?;
            let request = election.attempt.request;
            self.ensure_draw_eligible_body(request.body)?;
            if election.attempt.status != BodyElectionAttemptStatusV1::AwaitingPulse {
                return Err(ParliamentReducerErrorV1::InvalidLifecycleTransition(
                    ParliamentReducerEntityV1::BodyElection,
                ));
            }
            if request.governance_attempt_id != governance_attempt_id
                || request.beacon_session_id != beacon_session_id
                || request.pulse_height != pulse_height
            {
                return Err(ParliamentReducerErrorV1::PulseBindingMismatch);
            }
            let configured_target = u32::try_from(body_committee_size(governance, request.body))
                .map_err(|_| ParliamentReducerErrorV1::InvalidAssignmentPlan)?;
            if request.target_seats != configured_target {
                return Err(ParliamentReducerErrorV1::InvalidAssignmentPlan);
            }
            match shared_candidate_snapshot_index {
                None => shared_candidate_snapshot_index = Some(election.candidate_snapshot_index),
                Some(expected) if expected == election.candidate_snapshot_index => {}
                Some(_) => return Err(ParliamentReducerErrorV1::InvalidCandidateSnapshot),
            }
            election_ids.push(*election_id);
            bodies.push(request.body);
        }
        if self.used_pulse_ids.contains_key(&pulse_id)
            || self
                .used_pulse_slots
                .contains_key(&ParliamentPulseSlotV1::new(beacon_session_id, pulse_height))
        {
            return Err(ParliamentReducerErrorV1::BeaconPulseAlreadyConsumed);
        }
        bodies.sort_unstable();
        bodies.dedup();
        if bodies.len() != election_ids.len() {
            return Err(ParliamentReducerErrorV1::InvalidAssignmentPlan);
        }
        if self.used_pulse_ids.is_empty() {
            let mut expected_initial_bodies: Vec<_> = self
                .required_bodies
                .iter()
                .filter_map(|requirement| {
                    (requirement.body != ParliamentBody::ConfirmationJury)
                        .then_some(requirement.body)
                })
                .collect();
            expected_initial_bodies.sort_unstable();
            if bodies != expected_initial_bodies {
                return Err(ParliamentReducerErrorV1::InvalidAssignmentPlan);
            }
        }
        let candidate_snapshot = shared_candidate_snapshot_index
            .and_then(|index| usize::try_from(index).ok())
            .and_then(|index| self.candidate_snapshots.get(index))
            .map(Vec::as_slice)
            .ok_or(ParliamentReducerErrorV1::InvalidCandidateSnapshot)?;
        let plan = derive_attempt_body_plan_v1(
            governance,
            network_id,
            pulse_height,
            &pulse_output,
            candidate_snapshot,
            &bodies,
        );
        if plan.assignment_cap == 0 || plan.rosters.len() != bodies.len() {
            return Err(ParliamentReducerErrorV1::InvalidAssignmentPlan);
        }

        let mut derived = Vec::with_capacity(election_ids.len());
        for election_id in &election_ids {
            let election = self
                .elections
                .get(election_id)
                .expect("election id came from this map");
            let request = election.attempt.request;
            let roster = plan
                .rosters
                .get(&request.body)
                .ok_or(ParliamentReducerErrorV1::InvalidAssignmentPlan)?;
            if roster.body != request.body
                || roster.pulse_height != pulse_height
                || roster.candidate_count != request.candidate_count
                || roster.members.is_empty()
                || u32::try_from(roster.members.len()).ok()
                    != Some(request.target_seats.min(request.candidate_count))
            {
                return Err(ParliamentReducerErrorV1::InvalidAssignmentPlan);
            }
            let primary: Vec<_> = roster
                .members
                .iter()
                .cloned()
                .map(|member| ParliamentSeatAssignmentV1 {
                    assignment_id: AssignmentId::derive_v1(*election_id, &member),
                    member,
                })
                .collect();
            let alternates: Vec<_> = roster
                .alternates
                .iter()
                .cloned()
                .map(|member| ParliamentSeatAssignmentV1 {
                    assignment_id: AssignmentId::derive_v1(*election_id, &member),
                    member,
                })
                .collect();
            let invited: BTreeSet<_> = primary
                .iter()
                .chain(&alternates)
                .map(|assignment| assignment.member.clone())
                .collect();
            if invited.len() != primary.len() + alternates.len() {
                return Err(ParliamentReducerErrorV1::InvalidAssignmentPlan);
            }
            let assignment_root = parliament_assignment_plan_root_v1(
                *election_id,
                &primary,
                &alternates,
                plan.assignment_cap,
            );
            if root_is_zero(&assignment_root) {
                return Err(ParliamentReducerErrorV1::InvalidAssignmentPlan);
            }
            derived.push(DerivedElectionPlan {
                election_id: *election_id,
                primary,
                alternates,
                assignment_root,
            });
        }

        for derived_election in derived {
            let election = self
                .elections
                .get_mut(&derived_election.election_id)
                .expect("election id came from this map");
            election.attempt.status = BodyElectionAttemptStatusV1::Drawing;
            election.pulse_id = Some(pulse_id);
            election.pulse_output = Some(pulse_output);
            election.assignment_root = Some(derived_election.assignment_root);
            election.primary_assignments = derived_election.primary;
            election.alternate_assignments = derived_election.alternates;
            election.cross_body_assignment_cap = Some(plan.assignment_cap);
        }
        self.used_pulse_ids.insert(
            pulse_id,
            ParliamentPulseConsumerV1::SortitionBatch(request_ids),
        );
        self.used_pulse_slots.insert(
            ParliamentPulseSlotV1::new(beacon_session_id, pulse_height),
            pulse_id,
        );
        Ok(())
    }

    /// Open the immutable block-height window for invitation responses.
    ///
    /// # Errors
    /// Returns an error for a wrong attempt, unknown election, invalid height
    /// window, or any transition other than `Drawing -> AcceptingInvitations`.
    pub fn begin_invitation_acceptance(
        &mut self,
        governance_attempt_id: GovernanceAttemptId,
        election_attempt_id: BodyElectionAttemptId,
        opened_at_height: u64,
        response_phase_blocks: u64,
    ) -> Result<(), ParliamentReducerErrorV1> {
        self.ensure_active(governance_attempt_id)?;
        let invitation_close_height = opened_at_height
            .checked_add(
                response_phase_blocks
                    .checked_sub(1)
                    .ok_or(ParliamentReducerErrorV1::InvalidInvitationWindow)?,
            )
            .ok_or(ParliamentReducerErrorV1::InvalidInvitationWindow)?;
        let election = self.elections.get(&election_attempt_id).ok_or(
            ParliamentReducerErrorV1::UnknownEntity(ParliamentReducerEntityV1::BodyElection),
        )?;
        self.ensure_draw_eligible_body(election.attempt.request.body)?;
        if election.attempt.governance_attempt_id != governance_attempt_id {
            return Err(ParliamentReducerErrorV1::ImmutableBindingMismatch);
        }
        if election.attempt.status != BodyElectionAttemptStatusV1::Drawing
            || election.pulse_id.is_none()
            || election.pulse_output.is_none()
            || election.assignment_root.is_none()
            || election.primary_assignments.is_empty()
            || election.cross_body_assignment_cap.is_none()
            || opened_at_height < election.attempt.request.pulse_height
        {
            return Err(ParliamentReducerErrorV1::InvalidLifecycleTransition(
                ParliamentReducerEntityV1::BodyElection,
            ));
        }
        let election = self
            .elections
            .get_mut(&election_attempt_id)
            .expect("election checked above");
        election.invitation_opened_at_height = Some(opened_at_height);
        election.invitation_close_height = Some(invitation_close_height);
        election.attempt.status = BodyElectionAttemptStatusV1::AcceptingInvitations;
        Ok(())
    }

    /// Record one selected citizen's immutable invitation decision.
    ///
    /// The transaction authority is passed as `member`; callers cannot choose
    /// another assignment identifier. Both primaries and alternates respond up
    /// front so the final roster is a pure function of the ranked draw and the
    /// response transcript.
    ///
    /// # Errors
    /// Returns an error for a wrong attempt, unknown invitation, replay, wrong
    /// lifecycle, or a response after the committed close height.
    pub fn record_invitation_response(
        &mut self,
        governance_attempt_id: GovernanceAttemptId,
        election_attempt_id: BodyElectionAttemptId,
        member: &AccountId,
        accept: bool,
        current_height: u64,
    ) -> Result<(), ParliamentReducerErrorV1> {
        self.ensure_active(governance_attempt_id)?;
        let election = self.elections.get(&election_attempt_id).ok_or(
            ParliamentReducerErrorV1::UnknownEntity(ParliamentReducerEntityV1::BodyElection),
        )?;
        self.ensure_draw_eligible_body(election.attempt.request.body)?;
        if election.attempt.governance_attempt_id != governance_attempt_id
            || election.attempt.status != BodyElectionAttemptStatusV1::AcceptingInvitations
        {
            return Err(ParliamentReducerErrorV1::InvalidLifecycleTransition(
                ParliamentReducerEntityV1::BodyElection,
            ));
        }
        let opened_at_height = election
            .invitation_opened_at_height
            .ok_or(ParliamentReducerErrorV1::InvalidInvitationWindow)?;
        let close_height = election
            .invitation_close_height
            .ok_or(ParliamentReducerErrorV1::InvalidInvitationWindow)?;
        if current_height < opened_at_height {
            return Err(ParliamentReducerErrorV1::InvalidInvitationWindow);
        }
        if current_height > close_height {
            return Err(ParliamentReducerErrorV1::InvitationWindowClosed);
        }
        let assignment_id = election
            .primary_assignments
            .iter()
            .chain(&election.alternate_assignments)
            .find_map(|assignment| {
                (&assignment.member == member).then_some(assignment.assignment_id)
            })
            .ok_or(ParliamentReducerErrorV1::UnknownInvitation)?;
        if election.accepted_assignments.contains(&assignment_id)
            || election.declined_assignments.contains(&assignment_id)
        {
            return Err(ParliamentReducerErrorV1::InvitationResponseReplay);
        }
        let election = self
            .elections
            .get_mut(&election_attempt_id)
            .expect("election checked above");
        if accept {
            election.accepted_assignments.insert(assignment_id);
        } else {
            election.declined_assignments.insert(assignment_id);
        }
        Ok(())
    }

    /// Mark an election whose invitation window closed without a viable roster.
    ///
    /// Only an election in invitation acceptance can fail here, and only for an
    /// objective roster fact: no accepted member, or a hidden-ballot roster below
    /// the anonymity floor. An election awaiting its pulse is never failed,
    /// retried or redrawn: it leaves `AwaitingPulse` only through
    /// [`Self::consume_sortition_pulse_batch`] with the pulse of exactly its
    /// frozen slot, and otherwise waits indefinitely.
    ///
    /// # Errors
    /// Returns an error for a wrong attempt, unknown election, any state other
    /// than invitation acceptance (including a pulse wait at any height), an
    /// open invitation window, or a roster that can still be sealed.
    pub fn fail_body_election_no_roster(
        &mut self,
        governance_attempt_id: GovernanceAttemptId,
        election_attempt_id: BodyElectionAttemptId,
        current_height: u64,
    ) -> Result<(), ParliamentReducerErrorV1> {
        self.ensure_active(governance_attempt_id)?;
        let proposal_redraw_budget_exhausted =
            self.randomness_redraws_used_v1()? == MAX_PARLIAMENT_RANDOMNESS_REDRAWS_V1;
        let election = self.elections.get(&election_attempt_id).ok_or(
            ParliamentReducerErrorV1::UnknownEntity(ParliamentReducerEntityV1::BodyElection),
        )?;
        let requirement = self.ensure_draw_eligible_body(election.attempt.request.body)?;
        if election.attempt.status != BodyElectionAttemptStatusV1::AcceptingInvitations {
            return Err(ParliamentReducerErrorV1::InvalidLifecycleTransition(
                ParliamentReducerEntityV1::BodyElection,
            ));
        }
        if election
            .invitation_close_height
            .is_none_or(|close_height| current_height <= close_height)
        {
            return Err(ParliamentReducerErrorV1::InvitationWindowStillOpen);
        }
        let accepted_roster = accepted_roster(election)?;
        let failure_kind = if accepted_roster.is_empty() {
            ParliamentElectionFailureKindV1::EmptyAcceptedRoster
        } else if requirement.decision_mode == ParliamentDecisionModeV1::HiddenBindingBallot
            && !hidden_ballot_population_meets_anonymity_floor_v1(accepted_roster.len())
        {
            ParliamentElectionFailureKindV1::InsufficientHiddenBallotRoster
        } else {
            return Err(ParliamentReducerErrorV1::InvalidRoster);
        };
        let election = self
            .elections
            .get_mut(&election_attempt_id)
            .expect("election checked above");
        election.attempt.status = BodyElectionAttemptStatusV1::NoRoster;
        election.failure_kind = Some(failure_kind);
        election.failure_height = Some(current_height);
        if election.attempt.sequence == MAX_PARLIAMENT_SORTITION_RETRIES_V1
            || proposal_redraw_budget_exhausted
        {
            self.attempt.status = GovernanceAttemptStatusV1::Rejected;
        }
        Ok(())
    }

    /// Seal a canonical roster into a new body instance.
    ///
    /// Hidden-ballot rosters require the V1 anonymity floor. Confirmation members
    /// must also be disjoint from the completed Policy Jury.
    /// The sealed seat count becomes the immutable quorum denominator; later
    /// absence never changes it.
    ///
    /// # Errors
    /// Returns an error for wrong bindings or lifecycle, a malformed roster,
    /// duplicate identifiers, zero roots, or nonfresh confirmation membership.
    pub fn seal_body_roster(
        &mut self,
        governance_attempt_id: GovernanceAttemptId,
        election_attempt_id: BodyElectionAttemptId,
        current_height: u64,
    ) -> Result<BodyInstanceId, ParliamentReducerErrorV1> {
        self.ensure_active(governance_attempt_id)?;
        let election = self.elections.get(&election_attempt_id).ok_or(
            ParliamentReducerErrorV1::UnknownEntity(ParliamentReducerEntityV1::BodyElection),
        )?;
        let request = election.attempt.request;
        let requirement = self.ensure_draw_eligible_body(request.body)?;
        if election.attempt.governance_attempt_id != governance_attempt_id
            || election.attempt.status != BodyElectionAttemptStatusV1::AcceptingInvitations
            || election.assignment_root.is_none()
            || self.active_elections.get(&request.body) != Some(&election_attempt_id)
        {
            return Err(ParliamentReducerErrorV1::InvalidLifecycleTransition(
                ParliamentReducerEntityV1::BodyElection,
            ));
        }
        if election
            .invitation_close_height
            .is_none_or(|close_height| current_height <= close_height)
        {
            return Err(ParliamentReducerErrorV1::InvitationWindowStillOpen);
        }
        let assignments = accepted_roster(election)?;
        let assignment_count = u32::try_from(assignments.len())
            .map_err(|_| ParliamentReducerErrorV1::InvalidRoster)?;
        if assignment_count == 0
            || assignment_count > request.target_seats
            || (requirement.decision_mode == ParliamentDecisionModeV1::HiddenBindingBallot
                && assignment_count < MIN_PARLIAMENT_HIDDEN_BALLOT_ANONYMITY_V1)
        {
            return Err(ParliamentReducerErrorV1::InvalidRoster);
        }
        if assignments.iter().any(|seat| {
            seat.assignment_id != AssignmentId::derive_v1(election_attempt_id, &seat.member)
        }) {
            return Err(ParliamentReducerErrorV1::InvalidRoster);
        }
        let roster_root = parliament_roster_root_v1(election_attempt_id, &assignments);
        let body_instance_id = BodyInstanceId::derive_v1(election_attempt_id, roster_root);
        if root_is_zero(&roster_root)
            || body_instance_id.as_bytes().iter().all(|byte| *byte == 0)
            || self.bodies.contains_key(&body_instance_id)
        {
            return Err(ParliamentReducerErrorV1::DuplicateOrZeroIdentifier(
                ParliamentReducerEntityV1::BodyInstance,
            ));
        }
        let unique_members: BTreeSet<_> =
            assignments.iter().map(|seat| seat.member.clone()).collect();
        if unique_members.len() != assignments.len() {
            return Err(ParliamentReducerErrorV1::InvalidRoster);
        }
        if request.body == ParliamentBody::ConfirmationJury {
            let policy_members: BTreeSet<_> = self
                .bodies
                .values()
                .find(|body| body.instance.body == ParliamentBody::PolicyJury)
                .ok_or(ParliamentReducerErrorV1::ConfirmationJuryNotFresh)?
                .assignments
                .iter()
                .map(|seat| seat.member.clone())
                .collect();
            if !unique_members.is_disjoint(&policy_members) {
                return Err(ParliamentReducerErrorV1::ConfirmationJuryNotFresh);
            }
        }

        let body = ParliamentBodyInstanceV1 {
            id: body_instance_id,
            governance_attempt_id,
            election_attempt_id,
            body: request.body,
            target_seats: request.target_seats,
            original_seats: assignment_count,
            status: BodyInstanceStatusV1::RosterSealed,
        };
        self.elections
            .get_mut(&election_attempt_id)
            .expect("election checked above")
            .attempt
            .status = BodyElectionAttemptStatusV1::Sealed;
        self.active_bodies.insert(request.body, body_instance_id);
        self.bodies.insert(
            body_instance_id,
            ParliamentBodyStateV1 {
                instance: body,
                roster_root,
                assignments,
                excluded_assignments: BTreeSet::new(),
                public_finding_endorsements: BTreeMap::new(),
                public_finding_opened_at_height: None,
                public_finding_phase_blocks: None,
                public_finding_deadline_height: None,
                public_finding_no_result_kind: None,
                public_finding_no_result_height: None,
                public_finding_binding: None,
                result_root: None,
                result_height: None,
                ballot_binding: None,
            },
        );
        Ok(body_instance_id)
    }
}
