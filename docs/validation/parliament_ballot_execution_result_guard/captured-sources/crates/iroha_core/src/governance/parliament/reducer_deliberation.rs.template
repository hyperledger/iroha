impl ParliamentAttemptStateV1 {
    /// Advance a sealed body by exactly one deliberation phase.
    ///
    /// Public-finding bodies stop at reflection. Binding bodies alone may enter
    /// `Vote`, which can only be followed by private ballot registration.
    ///
    /// # Errors
    /// Returns an error for a wrong attempt/body/stage, an unknown instance,
    /// replay, phase skipping, phase reversal, or a decision-mode mismatch.
    pub fn advance_body_phase(
        &mut self,
        governance_attempt_id: GovernanceAttemptId,
        body_instance_id: BodyInstanceId,
        target: DeliberationPhaseV1,
        current_height: u64,
        public_finding_phase_blocks: u64,
    ) -> Result<(), ParliamentReducerErrorV1> {
        self.ensure_active(governance_attempt_id)?;
        let body =
            self.bodies
                .get(&body_instance_id)
                .ok_or(ParliamentReducerErrorV1::UnknownEntity(
                    ParliamentReducerEntityV1::BodyInstance,
                ))?;
        let decision_mode = self.ensure_current_body(body.instance.body)?.decision_mode;
        if body.instance.governance_attempt_id != governance_attempt_id
            || self.active_bodies.get(&body.instance.body) != Some(&body_instance_id)
        {
            return Err(ParliamentReducerErrorV1::ImmutableBindingMismatch);
        }
        let election = self
            .elections
            .get(&body.instance.election_attempt_id)
            .ok_or(ParliamentReducerErrorV1::ImmutableBindingMismatch)?;
        if current_height <= election.attempt.request.pulse_height {
            return Err(ParliamentReducerErrorV1::InvalidPublicFindingSchedule);
        }
        let expected = match body.instance.status {
            BodyInstanceStatusV1::RosterSealed => DeliberationPhaseV1::Orientation,
            BodyInstanceStatusV1::Deliberating(current) => next_deliberation_phase(current).ok_or(
                ParliamentReducerErrorV1::InvalidLifecycleTransition(
                    ParliamentReducerEntityV1::BodyInstance,
                ),
            )?,
            _ => {
                return Err(ParliamentReducerErrorV1::InvalidLifecycleTransition(
                    ParliamentReducerEntityV1::BodyInstance,
                ));
            }
        };
        if target != expected {
            return Err(ParliamentReducerErrorV1::InvalidLifecycleTransition(
                ParliamentReducerEntityV1::BodyInstance,
            ));
        }
        if target == DeliberationPhaseV1::Vote
            && decision_mode != ParliamentDecisionModeV1::HiddenBindingBallot
        {
            return Err(ParliamentReducerErrorV1::DecisionModeMismatch);
        }
        let body = self
            .bodies
            .get_mut(&body_instance_id)
            .expect("body checked above");
        if target == DeliberationPhaseV1::Reflection
            && decision_mode == ParliamentDecisionModeV1::PublicFinding
        {
            let deadline = current_height
                .checked_add(public_finding_phase_blocks)
                .filter(|_| public_finding_phase_blocks != 0)
                .ok_or(ParliamentReducerErrorV1::InvalidPublicFindingSchedule)?;
            if body.public_finding_opened_at_height.is_some()
                || body.public_finding_phase_blocks.is_some()
                || body.public_finding_deadline_height.is_some()
            {
                return Err(ParliamentReducerErrorV1::InvalidLifecycleTransition(
                    ParliamentReducerEntityV1::BodyInstance,
                ));
            }
            body.public_finding_opened_at_height = Some(current_height);
            body.public_finding_phase_blocks = Some(public_finding_phase_blocks);
            body.public_finding_deadline_height = Some(deadline);
        }
        body.instance.status = BodyInstanceStatusV1::Deliberating(target);
        Ok(())
    }

    /// Record a member-authenticated absence without changing the quorum denominator.
    ///
    /// The reducer records no slash, cooldown, or future-selection penalty. The
    /// same assignment cannot be excluded twice, and an exclusion cannot be
    /// introduced after balloting starts. `member` must own the exact named
    /// assignment, preventing a manager or another member from fabricating it.
    /// A public-finding body is marked `NoResult` and the governance attempt is
    /// rejected as soon as the remaining nonexcluded seats can no longer reach
    /// its immutable original-seat quorum.
    ///
    /// # Errors
    /// Returns an error for wrong bindings, an unknown assignment, an authority
    /// that does not own it, replay, or a body that has already entered or
    /// completed balloting.
    pub fn record_attempt_absence(
        &mut self,
        governance_attempt_id: GovernanceAttemptId,
        body_instance_id: BodyInstanceId,
        assignment_id: AssignmentId,
        member: &AccountId,
        current_height: u64,
    ) -> Result<(), ParliamentReducerErrorV1> {
        self.ensure_active(governance_attempt_id)?;
        let body =
            self.bodies
                .get(&body_instance_id)
                .ok_or(ParliamentReducerErrorV1::UnknownEntity(
                    ParliamentReducerEntityV1::BodyInstance,
                ))?;
        let decision_mode = self.ensure_current_body(body.instance.body)?.decision_mode;
        if body.instance.governance_attempt_id != governance_attempt_id {
            return Err(ParliamentReducerErrorV1::ImmutableBindingMismatch);
        }
        let election = self
            .elections
            .get(&body.instance.election_attempt_id)
            .ok_or(ParliamentReducerErrorV1::ImmutableBindingMismatch)?;
        if current_height <= election.attempt.request.pulse_height {
            return Err(ParliamentReducerErrorV1::InvalidPublicFindingSchedule);
        }
        if decision_mode == ParliamentDecisionModeV1::PublicFinding
            && body
                .public_finding_deadline_height
                .is_some_and(|deadline| current_height > deadline)
        {
            return Err(ParliamentReducerErrorV1::PublicFindingWindowClosed);
        }
        let assignment = body
            .assignments
            .iter()
            .find(|seat| seat.assignment_id == assignment_id)
            .ok_or(ParliamentReducerErrorV1::ImmutableBindingMismatch)?;
        if &assignment.member != member {
            return Err(ParliamentReducerErrorV1::UnauthorizedBodyMember);
        }
        if !matches!(
            body.instance.status,
            BodyInstanceStatusV1::RosterSealed | BodyInstanceStatusV1::Deliberating(_)
        ) || !body.public_finding_endorsements.is_empty()
        {
            return Err(ParliamentReducerErrorV1::InvalidLifecycleTransition(
                ParliamentReducerEntityV1::BodyInstance,
            ));
        }
        let body = self
            .bodies
            .get_mut(&body_instance_id)
            .expect("body checked above");
        if !body.excluded_assignments.insert(assignment_id) {
            return Err(ParliamentReducerErrorV1::InvalidLifecycleTransition(
                ParliamentReducerEntityV1::BodyInstance,
            ));
        }
        if decision_mode == ParliamentDecisionModeV1::PublicFinding
            && public_finding_quorum_is_unreachable(body)?
        {
            body.instance.status = BodyInstanceStatusV1::NoResult;
            body.public_finding_no_result_kind =
                Some(ParliamentNoResultKindV1::PublicFindingQuorumUnreachable);
            body.public_finding_no_result_height = Some(current_height);
            self.attempt.status = GovernanceAttemptStatusV1::Rejected;
        }
        Ok(())
    }

    fn build_ballot_binding(
        &self,
        ballot_attempt_id: BallotAttemptId,
    ) -> Result<ParliamentBallotCertificateBindingV1, ParliamentReducerErrorV1> {
        let ballot =
            self.ballots
                .get(&ballot_attempt_id)
                .ok_or(ParliamentReducerErrorV1::UnknownEntity(
                    ParliamentReducerEntityV1::BallotAttempt,
                ))?;
        if ballot.attempt.status != BallotAttemptStatusV1::Finalized {
            return Err(ParliamentReducerErrorV1::IncompleteCertificate);
        }
        Ok(ParliamentBallotCertificateBindingV1 {
            ballot_attempt_id,
            ballot_attempt_sequence: ballot.attempt.sequence,
            tle_session_id: ballot
                .tle_session_id
                .ok_or(ParliamentReducerErrorV1::IncompleteCertificate)?,
            tle_key_session_id: ballot
                .tle_key_session_id
                .ok_or(ParliamentReducerErrorV1::IncompleteCertificate)?,
            registration_root: ballot
                .registration_root
                .ok_or(ParliamentReducerErrorV1::IncompleteCertificate)?,
            dropout_root: ballot
                .dropout_root
                .ok_or(ParliamentReducerErrorV1::IncompleteCertificate)?,
            survivor_root: ballot
                .survivor_root
                .ok_or(ParliamentReducerErrorV1::IncompleteCertificate)?,
            corpus_root: ballot
                .corpus_root
                .ok_or(ParliamentReducerErrorV1::IncompleteCertificate)?,
            no_recovery_root: ballot
                .no_recovery_root
                .ok_or(ParliamentReducerErrorV1::IncompleteCertificate)?,
            timed_commitment_root: ballot
                .timed_commitment_root
                .ok_or(ParliamentReducerErrorV1::IncompleteCertificate)?,
            release_beacon_session_id: ballot
                .release_beacon_session_id
                .ok_or(ParliamentReducerErrorV1::IncompleteCertificate)?,
            registered_at_height: ballot.registered_at_height,
            registration_close_height: ballot.registration_close_height,
            survivor_freeze_height: ballot.survivor_freeze_height,
            commitment_close_height: ballot.commitment_close_height,
            registration_closed_at_height: ballot
                .registration_closed_at_height
                .ok_or(ParliamentReducerErrorV1::IncompleteCertificate)?,
            survivors_frozen_at_height: ballot
                .survivors_frozen_at_height
                .ok_or(ParliamentReducerErrorV1::IncompleteCertificate)?,
            commitment_closed_at_height: ballot
                .commitment_closed_at_height
                .ok_or(ParliamentReducerErrorV1::IncompleteCertificate)?,
            max_ballot_retries: ballot.max_ballot_retries,
            max_corpus_entries: ballot.max_corpus_entries,
            release_height: ballot
                .release_height
                .ok_or(ParliamentReducerErrorV1::IncompleteCertificate)?,
            opening_deadline_height: ballot.opening_deadline_height,
            release_pulse_id: ballot
                .release_pulse_id
                .ok_or(ParliamentReducerErrorV1::IncompleteCertificate)?,
            opening_height: ballot
                .opening_height
                .ok_or(ParliamentReducerErrorV1::IncompleteCertificate)?,
            opening_root: ballot
                .opening_root
                .ok_or(ParliamentReducerErrorV1::IncompleteCertificate)?,
            tally: ballot
                .tally
                .ok_or(ParliamentReducerErrorV1::IncompleteCertificate)?,
            outcome: ballot
                .outcome
                .ok_or(ParliamentReducerErrorV1::IncompleteCertificate)?,
        })
    }

    fn build_body_binding(
        &self,
        body_instance_id: BodyInstanceId,
    ) -> Result<ParliamentBodyCertificateBindingV1, ParliamentReducerErrorV1> {
        let body =
            self.bodies
                .get(&body_instance_id)
                .ok_or(ParliamentReducerErrorV1::UnknownEntity(
                    ParliamentReducerEntityV1::BodyInstance,
                ))?;
        let election = self
            .elections
            .get(&body.instance.election_attempt_id)
            .ok_or(ParliamentReducerErrorV1::UnknownEntity(
                ParliamentReducerEntityV1::BodyElection,
            ))?;
        if election.attempt.status != BodyElectionAttemptStatusV1::Sealed
            || election.attempt.governance_attempt_id != self.attempt.id
            || election.attempt.request.governance_attempt_id != self.attempt.id
            || election.attempt.request.body != body.instance.body
        {
            return Err(ParliamentReducerErrorV1::ImmutableBindingMismatch);
        }
        let beacon_pulse_id = election
            .pulse_id
            .ok_or(ParliamentReducerErrorV1::IncompleteCertificate)?;
        let assignment_root = election
            .assignment_root
            .ok_or(ParliamentReducerErrorV1::IncompleteCertificate)?;
        let result_root = body
            .result_root
            .ok_or(ParliamentReducerErrorV1::IncompleteCertificate)?;
        let result_height = body
            .result_height
            .ok_or(ParliamentReducerErrorV1::IncompleteCertificate)?;
        let ballot = self
            .active_ballots
            .get(&body_instance_id)
            .copied()
            .map(|ballot_id| self.build_ballot_binding(ballot_id))
            .transpose()?;
        if body.ballot_binding != ballot {
            return Err(ParliamentReducerErrorV1::CertificateBindingMismatch);
        }
        Ok(ParliamentBodyCertificateBindingV1 {
            body_instance_id,
            election_attempt_id: body.instance.election_attempt_id,
            election_attempt_sequence: election.attempt.sequence,
            sortition_request_id: election.attempt.request.id,
            sortition_request: election.attempt.request,
            body: body.instance.body,
            original_seats: body.instance.original_seats,
            beacon_session_id: election.attempt.request.beacon_session_id,
            beacon_pulse_id,
            roster_root: body.roster_root,
            assignment_root,
            result_root,
            result_height,
            public_finding: body.public_finding_binding.clone(),
            ballot,
        })
    }

    /// Record one seated member's endorsement of a public, nonbinding finding.
    ///
    /// Each assignment may endorse exactly one result root. The body result
    /// finalizes automatically once one root reaches the immutable two-thirds
    /// original-seat quorum, so a manager cannot invent or select the finding.
    /// If immutable endorsements split so that no root can reach quorum even if
    /// every remaining eligible assignment joins it, the body becomes
    /// `NoResult` and the governance attempt is rejected deterministically.
    ///
    /// # Errors
    /// Returns an error for a binding body, wrong stage/bindings, zero result
    /// root, a nonmember/excluded authority, replay, or a body that has not
    /// completed reflection. Returns whether this endorsement finalized the body.
    pub fn endorse_public_finding(
        &mut self,
        governance_attempt_id: GovernanceAttemptId,
        body_instance_id: BodyInstanceId,
        result_root: [u8; 32],
        member: &AccountId,
        result_height: u64,
    ) -> Result<bool, ParliamentReducerErrorV1> {
        self.ensure_active(governance_attempt_id)?;
        if root_is_zero(&result_root) {
            return Err(ParliamentReducerErrorV1::ZeroCommitmentRoot);
        }
        let body =
            self.bodies
                .get(&body_instance_id)
                .ok_or(ParliamentReducerErrorV1::UnknownEntity(
                    ParliamentReducerEntityV1::BodyInstance,
                ))?;
        let body_role = body.instance.body;
        let requirement = self.ensure_current_body(body_role)?;
        if requirement.decision_mode != ParliamentDecisionModeV1::PublicFinding {
            return Err(ParliamentReducerErrorV1::DecisionModeMismatch);
        }
        if body.instance.governance_attempt_id != governance_attempt_id
            || body.instance.status
                != BodyInstanceStatusV1::Deliberating(DeliberationPhaseV1::Reflection)
        {
            return Err(ParliamentReducerErrorV1::InvalidLifecycleTransition(
                ParliamentReducerEntityV1::BodyInstance,
            ));
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
        let opened_at_height = body
            .public_finding_opened_at_height
            .ok_or(ParliamentReducerErrorV1::InvalidPublicFindingSchedule)?;
        let deadline_height = body
            .public_finding_deadline_height
            .ok_or(ParliamentReducerErrorV1::InvalidPublicFindingSchedule)?;
        if result_height < opened_at_height || result_height > deadline_height {
            return Err(ParliamentReducerErrorV1::PublicFindingWindowClosed);
        }
        let assignment = body
            .assignments
            .iter()
            .find(|assignment| &assignment.member == member)
            .ok_or(ParliamentReducerErrorV1::UnauthorizedBodyMember)?;
        if body
            .excluded_assignments
            .contains(&assignment.assignment_id)
            || body
                .public_finding_endorsements
                .contains_key(&assignment.assignment_id)
        {
            return Err(ParliamentReducerErrorV1::InvalidLifecycleTransition(
                ParliamentReducerEntityV1::BodyInstance,
            ));
        }
        let assignment_id = assignment.assignment_id;
        let quorum = parliament_quorum_seats_v1(body.instance.original_seats);
        {
            let body = self
                .bodies
                .get_mut(&body_instance_id)
                .expect("body checked above");
            body.public_finding_endorsements
                .insert(assignment_id, result_root);
        }
        let endorsing_assignments = self
            .bodies
            .get(&body_instance_id)
            .expect("body checked above")
            .public_finding_endorsements
            .iter()
            .filter_map(|(assignment_id, endorsed_root)| {
                (*endorsed_root == result_root).then_some(*assignment_id)
            })
            .collect::<Vec<_>>();
        let endorsements = u32::try_from(endorsing_assignments.len())
            .map_err(|_| ParliamentReducerErrorV1::InvalidRoster)?;
        if endorsements < quorum {
            let body = self
                .bodies
                .get_mut(&body_instance_id)
                .expect("body checked above");
            if public_finding_quorum_is_unreachable(body)? {
                body.instance.status = BodyInstanceStatusV1::NoResult;
                body.public_finding_no_result_kind =
                    Some(ParliamentNoResultKindV1::PublicFindingQuorumUnreachable);
                body.public_finding_no_result_height = Some(result_height);
                self.attempt.status = GovernanceAttemptStatusV1::Rejected;
            }
            return Ok(false);
        }
        let endorsement_root = parliament_public_finding_endorsement_root_v1(
            governance_attempt_id,
            body_instance_id,
            result_root,
            &endorsing_assignments,
        );
        if root_is_zero(&endorsement_root) {
            return Err(ParliamentReducerErrorV1::ZeroCommitmentRoot);
        }
        {
            let body = self
                .bodies
                .get_mut(&body_instance_id)
                .expect("body checked above");
            body.instance.status = BodyInstanceStatusV1::Approved;
            body.result_root = Some(result_root);
            body.result_height = Some(result_height);
            body.public_finding_binding = Some(ParliamentPublicFindingCertificateBindingV1 {
                endorsement_root,
                endorsing_assignments,
                endorsements,
                quorum,
            });
        }
        let binding = self.build_body_binding(body_instance_id)?;
        if self.body_bindings.insert(body_role, binding).is_some() {
            return Err(ParliamentReducerErrorV1::InvalidLifecycleTransition(
                ParliamentReducerEntityV1::BodyInstance,
            ));
        }
        self.advance_after_body(body_role)?;
        Ok(true)
    }

    /// Terminally reject a public-finding body after its frozen endorsement deadline.
    ///
    /// The caller supplies only the body identifier. Core derives the schedule,
    /// verifies that no finding was finalized, and records the containing height
    /// as objective no-result evidence.
    ///
    /// # Errors
    /// Returns an error for a wrong attempt/body/mode, a replay, a body outside
    /// Reflection, or a trigger submitted no later than the inclusive deadline.
    pub fn fail_public_finding_no_result(
        &mut self,
        governance_attempt_id: GovernanceAttemptId,
        body_instance_id: BodyInstanceId,
        current_height: u64,
    ) -> Result<(), ParliamentReducerErrorV1> {
        self.ensure_active(governance_attempt_id)?;
        let body =
            self.bodies
                .get(&body_instance_id)
                .ok_or(ParliamentReducerErrorV1::UnknownEntity(
                    ParliamentReducerEntityV1::BodyInstance,
                ))?;
        let decision_mode = self.ensure_current_body(body.instance.body)?.decision_mode;
        if decision_mode != ParliamentDecisionModeV1::PublicFinding {
            return Err(ParliamentReducerErrorV1::DecisionModeMismatch);
        }
        if body.instance.governance_attempt_id != governance_attempt_id
            || body.instance.status
                != BodyInstanceStatusV1::Deliberating(DeliberationPhaseV1::Reflection)
            || body.public_finding_binding.is_some()
            || body.public_finding_no_result_kind.is_some()
            || body.public_finding_no_result_height.is_some()
        {
            return Err(ParliamentReducerErrorV1::InvalidLifecycleTransition(
                ParliamentReducerEntityV1::BodyInstance,
            ));
        }
        let deadline_height = body
            .public_finding_deadline_height
            .ok_or(ParliamentReducerErrorV1::InvalidPublicFindingSchedule)?;
        if current_height <= deadline_height {
            return Err(ParliamentReducerErrorV1::PublicFindingWindowStillOpen);
        }
        let body = self
            .bodies
            .get_mut(&body_instance_id)
            .expect("body checked above");
        body.instance.status = BodyInstanceStatusV1::NoResult;
        body.public_finding_no_result_kind =
            Some(ParliamentNoResultKindV1::PublicFindingDeadlineExpired);
        body.public_finding_no_result_height = Some(current_height);
        self.attempt.status = GovernanceAttemptStatusV1::Rejected;
        Ok(())
    }
}
