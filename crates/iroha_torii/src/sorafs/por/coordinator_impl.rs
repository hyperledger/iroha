// Chain-authoritative PoR coordinator implementation.
impl PorCoordinator {
    /// Construct an empty coordinator.
    #[must_use]
    pub fn new() -> Self {
        Self::with_record_limit(MAX_POR_COORDINATOR_RECORDS)
    }
    /// Construct an empty coordinator with the exact shared configured limit.
    #[must_use]
    pub(crate) fn with_record_limit(record_limit: usize) -> Self {
        Self {
            record_limit: record_limit.clamp(1, MAX_POR_COORDINATOR_RECORDS),
            #[cfg(test)]
            records: Arc::new(DashMap::new()),
            authoritative_projection: Arc::new(RwLock::new(None)),
            #[cfg(test)]
            status_indexes: Arc::new(RwLock::new(PorStatusIndexes::default())),
            #[cfg(test)]
            forced_providers: Arc::new(RwLock::new(HashMap::new())),
            prepared_weekly_report: Arc::new(RwLock::new(None)),
            persistence: None,
            persistence_fault: Arc::new(RwLock::new(None)),
            mutation_lock: Arc::new(Mutex::new(())),
            pipeline_lock: Arc::new(tokio::sync::Mutex::new(())),
            #[cfg(test)]
            weekly_report_projection_lookups: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            #[cfg(test)]
            status_page_projection_lookups: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }
    /// Construct a coordinator backed by on-disk persistence.
    ///
    /// # Errors
    ///
    /// Returns [`PorPersistenceError`] if the existing persistence records cannot
    /// be loaded from disk.
    pub fn with_persistence<P: Into<PathBuf>>(path: P) -> Result<Self, PorPersistenceError> {
        Self::with_persistence_and_record_limit(path, MAX_POR_COORDINATOR_RECORDS)
    }
    /// Load durable report state with the exact shared configured record limit.
    pub(crate) fn with_persistence_and_record_limit<P: Into<PathBuf>>(
        path: P,
        record_limit: usize,
    ) -> Result<Self, PorPersistenceError> {
        let persistence = Arc::new(PorPersistence::new(path.into()));
        let LoadedPorCoordinatorState {
            records,
            forced,
            prepared_weekly_report,
            status_generation,
        } = persistence.load()?;
        let record_limit = record_limit.clamp(1, MAX_POR_COORDINATOR_RECORDS);
        if records.len() > record_limit {
            return Err(PorPersistenceError::Decode(format!(
                "persisted PoR lifecycle count {} exceeds configured limit {record_limit}",
                records.len()
            )));
        }
        #[cfg(test)]
        let status_indexes = {
            let status_indexes = PorStatusIndexes::from_records(&records, status_generation);
            status_indexes
                .validate_against_records(&records)
                .map_err(PorPersistenceError::Decode)?;
            status_indexes
        };
        #[cfg(not(test))]
        let _retired_lifecycle_state = (records, forced, status_generation);
        Ok(Self {
            record_limit,
            #[cfg(test)]
            records,
            authoritative_projection: Arc::new(RwLock::new(None)),
            #[cfg(test)]
            status_indexes: Arc::new(RwLock::new(status_indexes)),
            #[cfg(test)]
            forced_providers: forced,
            prepared_weekly_report,
            persistence: Some(persistence),
            persistence_fault: Arc::new(RwLock::new(None)),
            mutation_lock: Arc::new(Mutex::new(())),
            pipeline_lock: Arc::new(tokio::sync::Mutex::new(())),
            #[cfg(test)]
            weekly_report_projection_lookups: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            #[cfg(test)]
            status_page_projection_lookups: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        })
    }
    #[cfg(test)]
    fn next_status_generation(&self) -> Result<u64, PorCoordinatorError> {
        self.status_indexes
            .read()
            .generation
            .checked_add(1)
            .ok_or(PorCoordinatorError::StatusGenerationExhausted)
    }
    fn ensure_persistence_healthy(&self) -> Result<(), PorCoordinatorError> {
        if let Some(reason) = self.persistence_fault.read().clone() {
            return Err(PorCoordinatorError::PersistenceFaultLatched { reason });
        }
        Ok(())
    }
    fn require_authoritative_projection(
        &self,
    ) -> Result<MappedRwLockReadGuard<'_, AuthoritativePorProjectionV1>, PorCoordinatorError> {
        RwLockReadGuard::try_map(self.authoritative_projection.read(), Option::as_ref)
            .map_err(|_| PorCoordinatorError::AuthoritativeProjectionUnavailable)
    }
    fn commit_uncertain_reason(error: &PorCoordinatorError) -> Option<&str> {
        match error {
            PorCoordinatorError::Persistence(PorPersistenceError::CommitUncertain(reason)) => {
                Some(reason)
            }
            _ => None,
        }
    }
    fn latch_commit_uncertain(&self, error: &PorCoordinatorError) {
        let Some(reason) = Self::commit_uncertain_reason(error) else {
            return;
        };
        let mut fault = self.persistence_fault.write();
        if fault.is_none() {
            *fault = Some(reason.to_owned());
        }
    }
    #[cfg(test)]
    fn inject_persistence_commit_uncertain_once(&self) {
        self.persistence
            .as_ref()
            .expect("test coordinator must use persistence")
            .fail_after_publication_once
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }
    /// Serialize node-authoritative mutation and projection refresh.
    pub(crate) async fn lock_pipeline(&self) -> tokio::sync::OwnedMutexGuard<()> {
        Arc::clone(&self.pipeline_lock).lock_owned().await
    }
    /// Atomically replace the Torii status projection from the authoritative
    /// storage-node checkpoint.
    ///
    /// # Errors
    ///
    /// Returns an error when the snapshot is malformed.
    pub(crate) fn install_authoritative_projection(
        &self,
        snapshot: PorStatusAuthoritySnapshotV1,
    ) -> Result<(), PorCoordinatorError> {
        // Snapshot reconciliation is a mutation, not merely validation. Hold
        // the same fence as incremental deltas from the first generation
        // check through publication so a concurrent delta cannot be silently
        // overwritten by a stale startup/recovery snapshot.
        let _mutation = self.mutation_lock.lock();
        if snapshot.generation == 0 {
            return Err(PorCoordinatorError::InvalidAuthoritativeProjection(
                "status generation must be non-zero".to_owned(),
            ));
        }
        if snapshot.statuses.len() > self.record_limit {
            return Err(PorCoordinatorError::InvalidAuthoritativeProjection(
                format!(
                    "status count {} exceeds limit {}",
                    snapshot.statuses.len(),
                    self.record_limit
                ),
            ));
        }
        let minimum_generation = u64::try_from(snapshot.statuses.len())
            .ok()
            .and_then(|count| count.checked_add(1))
            .ok_or(PorCoordinatorError::StatusGenerationExhausted)?;
        if snapshot.generation < minimum_generation {
            return Err(PorCoordinatorError::InvalidAuthoritativeProjection(
                format!(
                    "status generation {} is below minimum {minimum_generation}",
                    snapshot.generation
                ),
            ));
        }
        let mut statuses = BTreeMap::new();
        let mut previous = None;
        let mut forced = HashMap::<[u8; 32], BTreeMap<u64, usize>>::new();
        for status in snapshot.statuses {
            status.validate().map_err(|error| {
                PorCoordinatorError::InvalidAuthoritativeProjection(error.to_string())
            })?;
            if previous.is_some_and(|challenge_id| challenge_id >= status.challenge_id) {
                return Err(PorCoordinatorError::InvalidAuthoritativeProjection(
                    "statuses must be strictly ordered by challenge id".to_owned(),
                ));
            }
            previous = Some(status.challenge_id);
            if status.forced {
                let count = forced
                    .entry(status.provider_id)
                    .or_default()
                    .entry(status.epoch_id)
                    .or_default();
                *count = count.checked_add(1).ok_or(
                    PorCoordinatorError::InvalidAuthoritativeProjection(
                        "forced-provider provenance count overflowed".to_owned(),
                    ),
                )?;
            }
            statuses.insert(status.challenge_id, status);
        }
        let indexes = PorStatusIndexes::from_statuses(&statuses, snapshot.generation);
        let projection = AuthoritativePorProjectionV1 {
            statuses,
            indexes,
            forced_providers: forced,
        };
        let mut installed = self.authoritative_projection.write();
        if let Some(current) = installed.as_ref() {
            match snapshot.generation.cmp(&current.indexes.generation) {
                Ordering::Less => {
                    return Err(PorCoordinatorError::InvalidAuthoritativeProjection(
                        format!(
                            "snapshot generation {} would roll back installed generation {}",
                            snapshot.generation, current.indexes.generation
                        ),
                    ));
                }
                Ordering::Equal if current.statuses == projection.statuses => return Ok(()),
                Ordering::Equal => {
                    return Err(PorCoordinatorError::InvalidAuthoritativeProjection(
                        "same-generation snapshot conflicts with installed authority".to_owned(),
                    ));
                }
                Ordering::Greater => {}
            }
        }
        *installed = Some(projection);
        #[cfg(test)]
        self.records.clear();
        Ok(())
    }
    /// Apply one exact node-authoritative lifecycle update in logarithmic time.
    ///
    /// The currently installed generation must either equal the update generation for an exact
    /// replay or immediately precede it for one insert or forward lifecycle transition. Any
    /// rollback, gap, identity change, or conflicting replay invalidates the rebuildable projection
    /// so reads fail closed until startup reconciliation installs a complete checkpoint.
    pub(crate) fn apply_authoritative_update(
        &self,
        update: PorStatusAuthorityUpdateV1,
    ) -> Result<(), PorCoordinatorError> {
        let validation_error = if update.generation == 0 {
            Some("status generation must be non-zero".to_owned())
        } else {
            update
                .status
                .validate()
                .err()
                .map(|error| error.to_string())
        };
        let _mutation = self.mutation_lock.lock();
        let mut installed = self.authoritative_projection.write();
        if let Some(reason) = validation_error {
            *installed = None;
            return Err(PorCoordinatorError::InvalidAuthoritativeProjection(reason));
        }
        let Some(current) = installed.as_ref() else {
            return Err(PorCoordinatorError::AuthoritativeProjectionUnavailable);
        };
        let challenge_id = update.status.challenge_id;
        if update.removed_challenge_ids.len() > 1
            || update
                .removed_challenge_ids
                .windows(2)
                .any(|ids| ids[0] >= ids[1])
            || update
                .removed_challenge_ids
                .iter()
                .any(|removed| *removed == [0; 32] || *removed == challenge_id)
        {
            *installed = None;
            return Err(PorCoordinatorError::InvalidAuthoritativeProjection(
                "status update removals are not one canonical bounded set".to_owned(),
            ));
        }
        let action = (|| {
            let current_generation = current.indexes.generation;
            if update.generation == current_generation {
                let removals_already_absent = update
                    .removed_challenge_ids
                    .iter()
                    .all(|removed| !current.statuses.contains_key(removed));
                let status_is_exact_or_archived = match current.statuses.get(&challenge_id) {
                    Some(retained) => retained == &update.status,
                    None => {
                        update.removed_challenge_ids.is_empty()
                            && !matches!(
                                update.status.status,
                                PorChallengeOutcome::AwaitingProof
                                    | PorChallengeOutcome::ProofSubmitted
                            )
                    }
                };
                return if removals_already_absent && status_is_exact_or_archived {
                    // The node may authenticate an exact replay from its
                    // checkpoint-pinned archive after rolling retention has
                    // already removed that terminal from this projection.
                    Ok(None)
                } else {
                    Err(
                        "same-generation status update conflicts with retained or archived authority"
                            .to_owned(),
                    )
                };
            }
            if current_generation.checked_add(1) != Some(update.generation) {
                return Err(format!(
                    "status update generation {} does not immediately follow installed generation {current_generation}",
                    update.generation
                ));
            }
            for removed in &update.removed_challenge_ids {
                let status = current.statuses.get(removed).ok_or_else(|| {
                    "status update removes an identity absent from the installed checkpoint"
                        .to_owned()
                })?;
                if matches!(
                    status.status,
                    PorChallengeOutcome::AwaitingProof | PorChallengeOutcome::ProofSubmitted
                ) {
                    return Err(
                        "status update may retire only archived terminal identities".to_owned()
                    );
                }
            }
            let action = if let Some(previous) = current.statuses.get(&challenge_id) {
                if !update.removed_challenge_ids.is_empty() {
                    return Err(
                        "lifecycle replacement cannot retire an unrelated status".to_owned()
                    );
                }
                if !por_status_identity_is_unchanged(previous, &update.status)
                    || !por_status_lifecycle_advances(previous, &update.status)
                {
                    return Err(
                        "status update changes immutable challenge identity or regresses lifecycle state"
                            .to_owned(),
                    );
                }
                AuthoritativeUpdateAction::Replace
            } else {
                if !update.removed_challenge_ids.is_empty()
                    && current.statuses.len() < self.record_limit
                {
                    return Err(
                        "status retention may roll only when admitting at the configured bound"
                            .to_owned(),
                    );
                }
                if current
                    .statuses
                    .len()
                    .saturating_sub(update.removed_challenge_ids.len())
                    >= self.record_limit
                {
                    return Err(format!(
                        "status count would exceed limit {}",
                        self.record_limit
                    ));
                }
                AuthoritativeUpdateAction::Insert
            };
            let prospective_len = current
                .statuses
                .len()
                .checked_sub(update.removed_challenge_ids.len())
                .and_then(|count| {
                    count.checked_add(usize::from(matches!(
                        action,
                        AuthoritativeUpdateAction::Insert
                    )))
                })
                .ok_or_else(|| "status update projected length overflowed".to_owned())?;
            let minimum_generation = u64::try_from(prospective_len)
                .ok()
                .and_then(|count| count.checked_add(1))
                .ok_or_else(|| "status generation floor overflowed".to_owned())?;
            if update.generation < minimum_generation {
                return Err(format!(
                    "status update generation {} is below minimum {minimum_generation}",
                    update.generation
                ));
            }
            Ok(Some(action))
        })();
        let action = match action {
            Ok(Some(action)) => action,
            Ok(None) => return Ok(()),
            Err(reason) => {
                *installed = None;
                return Err(PorCoordinatorError::InvalidAuthoritativeProjection(reason));
            }
        };
        let projection = installed
            .as_mut()
            .expect("installed projection was checked before mutation");
        for removed in &update.removed_challenge_ids {
            let removed_status = projection
                .statuses
                .remove(removed)
                .expect("validated status removal must remain installed");
            projection.indexes.remove_status(&removed_status);
            remove_forced_status(&mut projection.forced_providers, &removed_status);
        }
        let previous = projection
            .statuses
            .insert(challenge_id, update.status.clone());
        if let Some(previous) = previous {
            debug_assert_eq!(action, AuthoritativeUpdateAction::Replace);
            projection.indexes.remove_status(&previous);
            projection.indexes.insert_status(&update.status);
            remove_forced_status(&mut projection.forced_providers, &previous);
        } else {
            debug_assert_eq!(action, AuthoritativeUpdateAction::Insert);
            projection.indexes.insert_status(&update.status);
        }
        projection.indexes.publish_generation(update.generation);
        insert_forced_status(&mut projection.forced_providers, &update.status);
        Ok(())
    }
    /// Drop the rebuildable projection after an uncertain node mutation.
    pub(crate) fn invalidate_authoritative_projection(&self) {
        let _mutation = self.mutation_lock.lock();
        *self.authoritative_projection.write() = None;
    }
    /// Remove retired lifecycle records from coordinator persistence while
    /// retaining any exact weekly-report publication state.
    ///
    /// # Errors
    ///
    /// Returns an error if report-state persistence cannot be updated.
    pub(crate) fn retire_lifecycle_persistence(&self) -> Result<(), PorCoordinatorError> {
        let _mutation = self.mutation_lock.lock();
        if self.authoritative_projection.read().is_none() {
            return Err(PorCoordinatorError::InvalidAuthoritativeProjection(
                "authoritative projection must be installed before retiring lifecycle state"
                    .to_owned(),
            ));
        }
        self.persist()
    }
    /// Record a governance-issued challenge.
    ///
    /// # Errors
    ///
    /// Returns [`PorCoordinatorError::InvalidChallenge`] when validation fails,
    /// [`PorCoordinatorError::DuplicateChallenge`] for an exact replay,
    /// [`PorCoordinatorError::ChallengeConflict`] if a different challenge is
    /// already recorded under the same identifier, or
    /// [`PorCoordinatorError::Persistence`] when persistence updates fail.
    #[cfg(test)]
    pub(crate) fn record_challenge(
        &self,
        challenge: &PorChallengeV1,
    ) -> Result<(), PorCoordinatorError> {
        challenge
            .validate()
            .map_err(PorCoordinatorError::InvalidChallenge)?;
        let _mutation = self.mutation_lock.lock();
        self.ensure_persistence_healthy()?;
        if let Some(existing) = self.records.get(&challenge.challenge_id) {
            if existing.challenge != *challenge {
                return Err(PorCoordinatorError::ChallengeConflict {
                    challenge_id: challenge.challenge_id,
                    challenge_id_hex: hex::encode(challenge.challenge_id),
                });
            }
            return Err(PorCoordinatorError::DuplicateChallenge {
                challenge_id: challenge.challenge_id,
                challenge_id_hex: hex::encode(challenge.challenge_id),
            });
        }
        if self.records.len() >= self.record_limit {
            return Err(PorCoordinatorError::RetentionExhausted {
                limit: self.record_limit,
            });
        }
        let next_status_generation = self.next_status_generation()?;
        let record = ChallengeRecord::from_challenge(challenge.clone());
        if record.challenge.forced {
            self.track_forced(&record.challenge.provider_id, record.challenge.epoch_id);
        }
        let status = record.to_status();
        self.records.insert(challenge.challenge_id, record);
        if let Err(error) = self.persist_with_status_generation(next_status_generation) {
            if Self::commit_uncertain_reason(&error).is_some() {
                self.status_indexes
                    .write()
                    .commit_insert(&status, next_status_generation);
                self.latch_commit_uncertain(&error);
            } else {
                self.records.remove(&challenge.challenge_id);
                if challenge.forced {
                    self.untrack_forced(&challenge.provider_id, challenge.epoch_id);
                }
            }
            return Err(error);
        }
        self.status_indexes
            .write()
            .commit_insert(&status, next_status_generation);
        Ok(())
    }
    /// Record a provider proof submission.
    ///
    /// # Errors
    ///
    /// Returns [`PorCoordinatorError::InvalidProof`] if validation fails,
    /// [`PorCoordinatorError::DuplicateProof`] for any replay,
    /// [`PorCoordinatorError::UnknownChallenge`] when the challenge cannot be found, or
    /// [`PorCoordinatorError::Persistence`] if persisting updates fails.
    #[cfg(test)]
    pub(crate) fn record_proof(
        &self,
        proof: &sorafs_manifest::por::PorProofV1,
        admitted_provider_key: &[u8],
    ) -> Result<(), PorCoordinatorError> {
        proof
            .validate()
            .map_err(PorCoordinatorError::InvalidProof)?;
        proof
            .verify_signature_for_provider(admitted_provider_key)
            .map_err(PorCoordinatorError::InvalidProofSignature)?;
        let _mutation = self.mutation_lock.lock();
        self.ensure_persistence_healthy()?;
        let digest = proof.proof_digest();
        let (previous, previous_status, current_status, next_status_generation) = {
            let mut entry = self.records.get_mut(&proof.challenge_id).ok_or_else(|| {
                PorCoordinatorError::UnknownChallenge {
                    challenge_id: proof.challenge_id,
                    challenge_id_hex: hex::encode(proof.challenge_id),
                }
            })?;
            entry.ensure_consistency(proof.manifest_digest, proof.provider_id)?;
            if !proof
                .samples
                .iter()
                .map(|sample| sample.sample_index)
                .eq(entry.challenge.sample_indices.iter().copied())
            {
                return Err(PorCoordinatorError::SampleIndicesMismatch {
                    challenge_id: proof.challenge_id,
                    challenge_id_hex: hex::encode(proof.challenge_id),
                });
            }
            if proof.submitted_at < entry.challenge.issued_at
                || proof.submitted_at > entry.challenge.deadline_at
            {
                return Err(PorCoordinatorError::ProofOutsideChallengeWindow {
                    submitted_at: proof.submitted_at,
                    issued_at: entry.challenge.issued_at,
                    deadline_at: entry.challenge.deadline_at,
                });
            }
            if entry.proof_digest.is_some() {
                return Err(PorCoordinatorError::DuplicateProof {
                    challenge_id: proof.challenge_id,
                    challenge_id_hex: hex::encode(proof.challenge_id),
                });
            }
            let next_status_generation = self.next_status_generation()?;
            let previous = entry.clone();
            let previous_status = previous.to_status();
            entry.proof_digest = Some(digest);
            entry.proof_submitted_at = Some(proof.submitted_at);
            entry.responded_at = Some(proof.submitted_at);
            let current_status = entry.to_status();
            (
                previous,
                previous_status,
                current_status,
                next_status_generation,
            )
        };
        if let Err(error) = self.persist_with_status_generation(next_status_generation) {
            if Self::commit_uncertain_reason(&error).is_some() {
                self.status_indexes.write().commit_replace(
                    &previous_status,
                    &current_status,
                    next_status_generation,
                );
                self.latch_commit_uncertain(&error);
            } else {
                self.records.insert(proof.challenge_id, previous);
            }
            return Err(error);
        }
        self.status_indexes.write().commit_replace(
            &previous_status,
            &current_status,
            next_status_generation,
        );
        Ok(())
    }
    /// Roll back a just-recorded proof after the node-side commit failed.
    #[cfg(test)]
    pub(crate) fn rollback_proof(
        &self,
        proof: &sorafs_manifest::por::PorProofV1,
    ) -> Result<(), PorCoordinatorError> {
        let _mutation = self.mutation_lock.lock();
        self.ensure_persistence_healthy()?;
        let digest = proof.proof_digest();
        let (previous, previous_status, current_status, next_status_generation) = {
            let mut entry = self.records.get_mut(&proof.challenge_id).ok_or_else(|| {
                PorCoordinatorError::UnknownChallenge {
                    challenge_id: proof.challenge_id,
                    challenge_id_hex: hex::encode(proof.challenge_id),
                }
            })?;
            if entry.proof_digest != Some(digest) || entry.verdict.is_some() {
                return Err(PorCoordinatorError::RollbackConflict {
                    challenge_id: proof.challenge_id,
                    challenge_id_hex: hex::encode(proof.challenge_id),
                });
            }
            let next_status_generation = self.next_status_generation()?;
            let previous = entry.clone();
            let previous_status = previous.to_status();
            entry.proof_digest = None;
            entry.proof_submitted_at = None;
            entry.responded_at = None;
            let current_status = entry.to_status();
            (
                previous,
                previous_status,
                current_status,
                next_status_generation,
            )
        };
        if let Err(error) = self.persist_with_status_generation(next_status_generation) {
            if Self::commit_uncertain_reason(&error).is_some() {
                self.status_indexes.write().commit_replace(
                    &previous_status,
                    &current_status,
                    next_status_generation,
                );
                self.latch_commit_uncertain(&error);
            } else {
                self.records.insert(proof.challenge_id, previous);
            }
            return Err(error);
        }
        self.status_indexes.write().commit_replace(
            &previous_status,
            &current_status,
            next_status_generation,
        );
        Ok(())
    }
    /// Roll back a just-recorded verdict after the node-side commit failed.
    #[cfg(test)]
    pub(crate) fn rollback_verdict(
        &self,
        verdict: &AuditVerdictV1,
    ) -> Result<(), PorCoordinatorError> {
        let canonical_digest = RecordedVerdict::from_verdict(verdict)?.canonical_digest;
        let _mutation = self.mutation_lock.lock();
        self.ensure_persistence_healthy()?;
        let (previous, previous_status, current_status, next_status_generation) = {
            let mut entry = self.records.get_mut(&verdict.challenge_id).ok_or_else(|| {
                PorCoordinatorError::UnknownChallenge {
                    challenge_id: verdict.challenge_id,
                    challenge_id_hex: hex::encode(verdict.challenge_id),
                }
            })?;
            if entry
                .verdict
                .as_ref()
                .is_none_or(|recorded| recorded.canonical_digest != canonical_digest)
            {
                return Err(PorCoordinatorError::RollbackConflict {
                    challenge_id: verdict.challenge_id,
                    challenge_id_hex: hex::encode(verdict.challenge_id),
                });
            }
            let next_status_generation = self.next_status_generation()?;
            let previous = entry.clone();
            let previous_status = previous.to_status();
            entry.verdict = None;
            entry.repair_task_id = None;
            entry.responded_at = entry.proof_submitted_at;
            let current_status = entry.to_status();
            (
                previous,
                previous_status,
                current_status,
                next_status_generation,
            )
        };
        if let Err(error) = self.persist_with_status_generation(next_status_generation) {
            if Self::commit_uncertain_reason(&error).is_some() {
                self.status_indexes.write().commit_replace(
                    &previous_status,
                    &current_status,
                    next_status_generation,
                );
                self.latch_commit_uncertain(&error);
            } else {
                self.records.insert(verdict.challenge_id, previous);
            }
            return Err(error);
        }
        self.status_indexes.write().commit_replace(
            &previous_status,
            &current_status,
            next_status_generation,
        );
        Ok(())
    }
    /// Commit a previously validated audit verdict.
    ///
    /// Exact replays return [`PorCoordinatorVerdictOutcome::Existing`].
    #[cfg(test)]
    pub(crate) fn record_verdict(
        &self,
        verdict: &AuditVerdictV1,
        trusted_auditor_keys: &[Vec<u8>],
        auditor_threshold: usize,
    ) -> Result<PorCoordinatorVerdictOutcome, PorCoordinatorError> {
        verdict
            .validate()
            .map_err(PorCoordinatorError::InvalidVerdict)?;
        verdict
            .verify_signatures_with_policy(trusted_auditor_keys, auditor_threshold)
            .map_err(PorCoordinatorError::InvalidVerdictSignature)?;
        let recorded_verdict = RecordedVerdict::from_verdict(verdict)?;
        let repair_task_id = (verdict.outcome == AuditOutcomeV1::Failed)
            .then(|| sorafs_repair_task_id_v1(por_repair_source_identity_v1(verdict.challenge_id)));
        let _mutation = self.mutation_lock.lock();
        self.ensure_persistence_healthy()?;
        let (previous, previous_status, current_status, next_status_generation) = {
            let mut entry = self.records.get_mut(&verdict.challenge_id).ok_or_else(|| {
                PorCoordinatorError::UnknownChallenge {
                    challenge_id: verdict.challenge_id,
                    challenge_id_hex: hex::encode(verdict.challenge_id),
                }
            })?;
            entry.ensure_consistency(verdict.manifest_digest, verdict.provider_id)?;
            if let Some(existing) = &entry.verdict {
                if existing.canonical_digest == recorded_verdict.canonical_digest
                    && entry.repair_task_id == repair_task_id
                {
                    return Ok(PorCoordinatorVerdictOutcome::Existing);
                }
                return Err(PorCoordinatorError::VerdictConflict {
                    challenge_id: verdict.challenge_id,
                    challenge_id_hex: hex::encode(verdict.challenge_id),
                });
            }
            entry.validate_verdict_transition(verdict)?;
            let next_status_generation = self.next_status_generation()?;
            let previous = entry.clone();
            let previous_status = previous.to_status();
            entry.verdict = Some(recorded_verdict);
            entry.repair_task_id = repair_task_id;
            let current_status = entry.to_status();
            (
                previous,
                previous_status,
                current_status,
                next_status_generation,
            )
        };
        if let Err(error) = self.persist_with_status_generation(next_status_generation) {
            if Self::commit_uncertain_reason(&error).is_some() {
                self.status_indexes.write().commit_replace(
                    &previous_status,
                    &current_status,
                    next_status_generation,
                );
                self.latch_commit_uncertain(&error);
            } else {
                self.records.insert(verdict.challenge_id, previous);
            }
            return Err(error);
        }
        self.status_indexes.write().commit_replace(
            &previous_status,
            &current_status,
            next_status_generation,
        );
        Ok(PorCoordinatorVerdictOutcome::Inserted)
    }
    /// Return one indexed, record-and-byte-bounded status page.
    ///
    /// # Errors
    ///
    /// Returns [`PorCoordinatorError`] when a continuation cursor is invalid, belongs to another
    /// filter or generation, or one record cannot fit the explicit canonical-byte budget.
    pub(crate) fn query_status_page(
        &self,
        filter: &PorStatusFilter,
        limits: PorStatusPageLimits,
        cursor: PorStatusPageCursor,
    ) -> Result<PorStatusPageV1, PorCoordinatorError> {
        let _mutation = self.mutation_lock.lock();
        self.ensure_persistence_healthy()?;
        let authoritative_guard = self.authoritative_projection.read();
        let authoritative = authoritative_guard.as_ref();
        #[cfg(not(test))]
        let authoritative =
            authoritative.ok_or(PorCoordinatorError::AuthoritativeProjectionUnavailable)?;
        #[cfg(test)]
        let legacy_indexes = authoritative.is_none().then(|| self.status_indexes.read());
        #[cfg(not(test))]
        let indexes = &authoritative.indexes;
        #[cfg(not(test))]
        let authoritative = Some(authoritative);
        #[cfg(test)]
        let indexes = authoritative
            .map(|projection| &projection.indexes)
            .unwrap_or_else(|| {
                legacy_indexes
                    .as_deref()
                    .expect("legacy PoR indexes exist without an authoritative projection")
            });
        let selection_digest = por_status_selection_digest(filter);
        let after_anchor =
            Self::validate_page_cursor(cursor, indexes.generation, selection_digest)?;
        if let Some(anchor) = after_anchor {
            let status = self.status_for_indexed_id(authoritative, anchor.challenge_id)?;
            if status.epoch_id != anchor.epoch_id || status.issued_at != anchor.issued_at {
                return Err(PorCoordinatorError::PageCursorAnchorMismatch {
                    challenge_id: anchor.challenge_id,
                });
            }
        }
        let after = after_anchor.map(PorStatusCursorAnchor::status_order_key);
        let candidates = Self::smallest_status_index(indexes, filter);
        if let Some(after) = after
            && !candidates.is_some_and(|candidates| candidates.contains(&after))
        {
            return Err(PorCoordinatorError::PageCursorAnchorSelectionMismatch);
        }
        let mut page = PorStatusPageAccumulator::new(indexes.generation, selection_digest, limits);
        if let Some(candidates) = candidates {
            let lower = after.map_or(Bound::Unbounded, Bound::Excluded);
            let mut candidates = candidates.range((lower, Bound::Unbounded)).peekable();
            while page.inspected_candidates < POR_STATUS_PAGE_MAX_INSPECTED_CANDIDATES_V1
                && !page.record_limit_reached()
            {
                let Some((_, challenge_id)) = candidates.next() else {
                    break;
                };
                #[cfg(test)]
                self.status_page_projection_lookups
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let status = self.status_for_indexed_id(authoritative, *challenge_id)?;
                page.note_inspected_candidate()?;
                if filter.matches(&status) && !page.accept(status.clone())? {
                    break;
                }
                page.consume_candidate(&status);
            }
            if candidates.peek().is_some() {
                page.mark_has_more();
            }
        }
        page.finish()
    }
    #[cfg(test)]
    fn query_statuses(
        &self,
        filter: &PorStatusFilter,
        limit: Option<usize>,
        page_token: Option<[u8; 32]>,
    ) -> Vec<PorChallengeStatusV1> {
        let records = limit.unwrap_or(POR_CHALLENGE_STATUS_PAGE_MAX_RECORDS_V1);
        let limits = PorStatusPageLimits::new(records, POR_STATUS_PAGE_MAX_CANONICAL_BYTES_V1)
            .expect("test PoR status limits are valid");
        let cursor = page_token.map_or(PorStatusPageCursor::First, |challenge_id| {
            let (status, snapshot_generation) = {
                let authoritative = self.authoritative_projection.read();
                let status = self
                    .status_for_indexed_id(authoritative.as_ref(), challenge_id)
                    .expect("test PoR page token must identify a retained challenge");
                let snapshot_generation = authoritative.as_ref().map_or_else(
                    || self.status_indexes.read().generation,
                    |projection| projection.indexes.generation,
                );
                (status, snapshot_generation)
            };
            PorStatusPageCursor::After {
                snapshot_generation,
                selection_digest: por_status_selection_digest(filter),
                last_epoch_id: status.epoch_id,
                last_issued_at: status.issued_at,
                challenge_id,
            }
        });
        self.query_status_page(filter, limits, cursor)
            .expect("test PoR status page is valid")
            .statuses
    }
    /// Return one indexed bounded page of an optional inclusive epoch range.
    ///
    /// This replaces the retired synchronous full-history export. Epoch-range
    /// pages use `(epoch, issued_at, challenge_id)` ordering and the same exact
    /// generation, record, and canonical-byte bounds as ordinary status pages.
    ///
    /// # Errors
    ///
    /// Returns [`PorCoordinatorError`] for an invalid range or cursor, a stale
    /// generation, an index inconsistency, or an undersized byte budget.
    pub(crate) fn export_status_page(
        &self,
        range: Option<(u64, u64)>,
        limits: PorStatusPageLimits,
        cursor: PorStatusPageCursor,
    ) -> Result<PorStatusExportPageV1, PorCoordinatorError> {
        if range.is_some_and(|(start, end)| start > end) {
            let (start, end) = range.expect("checked Some epoch range");
            return Err(PorCoordinatorError::InvalidEpochRange { start, end });
        }
        let _mutation = self.mutation_lock.lock();
        self.ensure_persistence_healthy()?;
        let authoritative_guard = self.authoritative_projection.read();
        let authoritative = authoritative_guard.as_ref();
        #[cfg(not(test))]
        let authoritative =
            authoritative.ok_or(PorCoordinatorError::AuthoritativeProjectionUnavailable)?;
        #[cfg(test)]
        let legacy_indexes = authoritative.is_none().then(|| self.status_indexes.read());
        #[cfg(not(test))]
        let indexes = &authoritative.indexes;
        #[cfg(not(test))]
        let authoritative = Some(authoritative);
        #[cfg(test)]
        let indexes = authoritative
            .map(|projection| &projection.indexes)
            .unwrap_or_else(|| {
                legacy_indexes
                    .as_deref()
                    .expect("legacy PoR indexes exist without an authoritative projection")
            });
        let selection_digest = por_export_selection_digest(range);
        let after_anchor =
            Self::validate_page_cursor(cursor, indexes.generation, selection_digest)?;
        if let (Some((start, end)), Some(anchor)) = (range, after_anchor)
            && !(start..=end).contains(&anchor.epoch_id)
        {
            return Err(PorCoordinatorError::PageCursorAnchorSelectionMismatch);
        }
        if let Some(anchor) = after_anchor {
            let status = self.status_for_indexed_id(authoritative, anchor.challenge_id)?;
            if status.epoch_id != anchor.epoch_id || status.issued_at != anchor.issued_at {
                return Err(PorCoordinatorError::PageCursorAnchorMismatch {
                    challenge_id: anchor.challenge_id,
                });
            }
            let anchor_is_indexed = match range {
                None => indexes.canonical.contains(&anchor.status_order_key()),
                Some(_) => indexes.epoch_order.contains(&anchor.epoch_order_key()),
            };
            if !anchor_is_indexed {
                return Err(PorCoordinatorError::PageCursorAnchorMismatch {
                    challenge_id: anchor.challenge_id,
                });
            }
        }
        let mut page = PorStatusPageAccumulator::new(indexes.generation, selection_digest, limits);
        match range {
            None => {
                let lower = after_anchor
                    .map(PorStatusCursorAnchor::status_order_key)
                    .map_or(Bound::Unbounded, Bound::Excluded);
                let mut candidates = indexes
                    .canonical
                    .range((lower, Bound::Unbounded))
                    .peekable();
                while page.inspected_candidates < POR_STATUS_PAGE_MAX_INSPECTED_CANDIDATES_V1
                    && !page.record_limit_reached()
                {
                    let Some((_, challenge_id)) = candidates.next() else {
                        break;
                    };
                    let status = self.status_for_indexed_id(authoritative, *challenge_id)?;
                    page.note_inspected_candidate()?;
                    if !page.accept(status.clone())? {
                        break;
                    }
                    page.consume_candidate(&status);
                }
                if candidates.peek().is_some() {
                    page.mark_has_more();
                }
            }
            Some((start, end)) => {
                let lower = after_anchor.map_or(Bound::Included((start, 0, [0; 32])), |status| {
                    Bound::Excluded(status.epoch_order_key())
                });
                let upper = Bound::Included((end, u64::MAX, [u8::MAX; 32]));
                let mut candidates = indexes.epoch_order.range((lower, upper)).peekable();
                while page.inspected_candidates < POR_STATUS_PAGE_MAX_INSPECTED_CANDIDATES_V1
                    && !page.record_limit_reached()
                {
                    let Some((_, _, challenge_id)) = candidates.next() else {
                        break;
                    };
                    let status = self.status_for_indexed_id(authoritative, *challenge_id)?;
                    page.note_inspected_candidate()?;
                    if !page.accept(status.clone())? {
                        break;
                    }
                    page.consume_candidate(&status);
                }
                if candidates.peek().is_some() {
                    page.mark_has_more();
                }
            }
        }
        Ok(PorStatusExportPageV1 {
            version: POR_STATUS_EXPORT_PAGE_VERSION_V1,
            start_epoch: range.map(|(start, _)| start),
            end_epoch: range.map(|(_, end)| end),
            page: page.finish()?,
        })
    }
    fn validate_page_cursor(
        cursor: PorStatusPageCursor,
        current_generation: u64,
        expected_selection_digest: [u8; 32],
    ) -> Result<Option<PorStatusCursorAnchor>, PorCoordinatorError> {
        match cursor {
            PorStatusPageCursor::First => Ok(None),
            PorStatusPageCursor::After {
                snapshot_generation,
                selection_digest,
                last_epoch_id,
                last_issued_at,
                challenge_id,
            } => {
                if selection_digest != expected_selection_digest {
                    return Err(PorCoordinatorError::PageCursorSelectionMismatch);
                }
                if snapshot_generation != current_generation {
                    return Err(PorCoordinatorError::StalePageGeneration {
                        expected: snapshot_generation,
                        current: current_generation,
                    });
                }
                Ok(Some(PorStatusCursorAnchor {
                    epoch_id: last_epoch_id,
                    issued_at: last_issued_at,
                    challenge_id,
                }))
            }
        }
    }
    fn smallest_status_index<'a>(
        indexes: &'a PorStatusIndexes,
        filter: &PorStatusFilter,
    ) -> Option<&'a BTreeSet<PorStatusOrderKey>> {
        let mut selected = &indexes.canonical;
        for candidate in [
            filter.manifest.map(|key| indexes.by_manifest.get(&key)),
            filter.provider.map(|key| indexes.by_provider.get(&key)),
            filter.epoch.map(|key| indexes.by_epoch.get(&key)),
            filter
                .status
                .map(|key| indexes.by_outcome.get(&(key as u8))),
        ]
        .into_iter()
        .flatten()
        {
            let candidate = candidate?;
            if candidate.len() < selected.len() {
                selected = candidate;
            }
        }
        Some(selected)
    }
    #[cfg_attr(
        not(test),
        expect(
            clippy::unused_self,
            reason = "test fixtures read the retained local record projection"
        )
    )]
    fn status_for_indexed_id(
        &self,
        authoritative: Option<&AuthoritativePorProjectionV1>,
        challenge_id: [u8; 32],
    ) -> Result<PorChallengeStatusV1, PorCoordinatorError> {
        if let Some(projection) = authoritative {
            return projection
                .statuses
                .get(&challenge_id)
                .cloned()
                .ok_or(PorCoordinatorError::StatusIndexCorrupt { challenge_id });
        }
        #[cfg(not(test))]
        return Err(PorCoordinatorError::AuthoritativeProjectionUnavailable);
        #[cfg(test)]
        self.records
            .get(&challenge_id)
            .map(|record| record.to_status())
            .ok_or(PorCoordinatorError::StatusIndexCorrupt { challenge_id })
    }
    /// Generate a weekly report for the supplied ISO week.
    ///
    /// # Errors
    ///
    /// Returns [`PorCoordinatorError`] if the week is invalid, data cannot be
    /// aggregated, or the report fails validation.
    pub fn weekly_report(
        &self,
        cycle: PorReportIsoWeek,
    ) -> Result<PorWeeklyReportV1, PorCoordinatorError> {
        let _mutation = self.mutation_lock.lock();
        self.ensure_persistence_healthy()?;
        #[cfg(not(test))]
        let authoritative = self.require_authoritative_projection()?;
        if let Some(prepared) = self.prepared_weekly_report.read().as_ref()
            && prepared.report.cycle == cycle
        {
            return Ok(prepared.report.clone());
        }
        let generated_at = canonical_weekly_report_generated_at(cycle)?;
        #[cfg(not(test))]
        drop(authoritative);
        self.weekly_report_at(cycle, generated_at)
    }
    /// Prepare and durably retain the exact report bytes before publication.
    ///
    /// Exact retries for the same cycle return the retained report even if
    /// coordinator history changes after the first preparation. A pending
    /// report must be marked published before the next cycle can be prepared.
    /// Catch-up advances one ISO week per call so outages cannot skip cycles.
    fn prepare_weekly_report(
        &self,
        cycle: PorReportIsoWeek,
    ) -> Result<PreparedWeeklyReportV1, PorCoordinatorError> {
        cycle
            .validate()
            .map_err(PorCoordinatorError::InvalidIsoWeek)?;
        let _mutation = self.mutation_lock.lock();
        self.ensure_persistence_healthy()?;
        #[cfg(not(test))]
        let authoritative = self.require_authoritative_projection()?;
        let requested_marker = iso_week_marker(cycle);
        if let Some(existing) = self.prepared_weekly_report.read().as_ref() {
            let existing_marker = iso_week_marker(existing.report.cycle);
            if existing_marker == requested_marker {
                return Ok(existing.clone());
            }
            if existing_marker > requested_marker {
                return Err(PorCoordinatorError::WeeklyReportCycleRollback {
                    prepared: existing.report.cycle,
                    requested: cycle,
                });
            }
            if !existing.published {
                return Err(PorCoordinatorError::WeeklyReportPublicationPending {
                    prepared: existing.report.cycle,
                    requested: cycle,
                });
            }
        }
        let cycle = self
            .prepared_weekly_report
            .read()
            .as_ref()
            .map_or(Ok(cycle), |existing| {
                next_iso_week(existing.report.cycle).and_then(|next| {
                    if iso_week_marker(next) <= requested_marker {
                        Ok(next)
                    } else {
                        Err(PorCoordinatorError::WeeklyReportCycleRollback {
                            prepared: existing.report.cycle,
                            requested: cycle,
                        })
                    }
                })
            })?;
        let generated_at = canonical_weekly_report_generated_at(cycle)?;
        #[cfg(not(test))]
        drop(authoritative);
        let prepared_report = PreparedWeeklyReportV1 {
            report: self.weekly_report_at(cycle, generated_at)?,
            published: false,
        };
        let previous = {
            let mut prepared = self.prepared_weekly_report.write();
            prepared.replace(prepared_report.clone())
        };
        if let Err(error) = self.persist() {
            if Self::commit_uncertain_reason(&error).is_some() {
                self.latch_commit_uncertain(&error);
            } else {
                *self.prepared_weekly_report.write() = previous;
            }
            return Err(error);
        }
        Ok(prepared_report)
    }
    /// Persist the publication acknowledgement for an exact prepared report.
    fn mark_weekly_report_published(
        &self,
        report: &PorWeeklyReportV1,
    ) -> Result<(), PorCoordinatorError> {
        let _mutation = self.mutation_lock.lock();
        self.ensure_persistence_healthy()?;
        let previous = {
            let mut prepared = self.prepared_weekly_report.write();
            let Some(current) = prepared.as_mut() else {
                return Err(PorCoordinatorError::WeeklyReportPreparationConflict {
                    cycle: report.cycle,
                });
            };
            if current.report != *report {
                return Err(PorCoordinatorError::WeeklyReportPreparationConflict {
                    cycle: report.cycle,
                });
            }
            if current.published {
                return Ok(());
            }
            let previous = current.clone();
            current.published = true;
            previous
        };
        if let Err(error) = self.persist() {
            if Self::commit_uncertain_reason(&error).is_some() {
                self.latch_commit_uncertain(&error);
            } else {
                *self.prepared_weekly_report.write() = Some(previous);
            }
            return Err(error);
        }
        Ok(())
    }
    fn weekly_report_at(
        &self,
        cycle: PorReportIsoWeek,
        generated_at: u64,
    ) -> Result<PorWeeklyReportV1, PorCoordinatorError> {
        cycle
            .validate()
            .map_err(PorCoordinatorError::InvalidIsoWeek)?;
        let (start, end) = iso_week_bounds(cycle)?;
        let start_issued_at = u64::try_from(start.unix_timestamp()).unwrap_or(0);
        let end_issued_at = u64::try_from(end.unix_timestamp()).unwrap_or(0);
        let authoritative_guard = self.authoritative_projection.read();
        let authoritative = authoritative_guard.as_ref();
        #[cfg(not(test))]
        let authoritative =
            authoritative.ok_or(PorCoordinatorError::AuthoritativeProjectionUnavailable)?;
        #[cfg(test)]
        let legacy_indexes = authoritative.is_none().then(|| self.status_indexes.read());
        #[cfg(not(test))]
        let indexes = &authoritative.indexes;
        #[cfg(not(test))]
        let authoritative = Some(authoritative);
        #[cfg(test)]
        let indexes = authoritative
            .map(|projection| &projection.indexes)
            .unwrap_or_else(|| {
                legacy_indexes
                    .as_deref()
                    .expect("legacy PoR indexes exist without an authoritative projection")
            });
        let status_keys = indexes
            .canonical
            .range((
                Bound::Included((start_issued_at, [0; 32])),
                Bound::Excluded((end_issued_at, [0; 32])),
            ))
            .copied()
            .collect::<Vec<_>>();
        let mut statuses = Vec::with_capacity(status_keys.len());
        for (_, challenge_id) in status_keys {
            #[cfg(test)]
            self.weekly_report_projection_lookups
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            statuses.push(self.status_for_indexed_id(authoritative, challenge_id)?);
        }
        let challenges_total = statuses.len() as u32;
        let challenges_verified = statuses
            .iter()
            .filter(|s| matches!(s.status, PorChallengeOutcome::Verified))
            .count() as u32;
        let challenges_failed = statuses
            .iter()
            .filter(|s| {
                matches!(
                    s.status,
                    PorChallengeOutcome::Failed | PorChallengeOutcome::Repaired
                )
            })
            .count() as u32;
        let forced_challenges = statuses.iter().filter(|s| s.forced).count() as u32;
        let mut provider_map: BTreeMap<[u8; 32], ProviderStats> = BTreeMap::new();
        for status in &statuses {
            let entry = provider_map.entry(status.provider_id).or_default();
            entry.manifests.insert(status.manifest_digest);
            entry.challenges += 1;
            entry.forced += u32::from(status.forced);
            match status.status {
                PorChallengeOutcome::Verified => entry.successes += 1,
                PorChallengeOutcome::Failed | PorChallengeOutcome::Repaired => {
                    entry.failures += 1;
                    if entry.first_failure_at.is_none() {
                        entry.first_failure_at =
                            Some(status.responded_at.unwrap_or(status.issued_at));
                    }
                }
                PorChallengeOutcome::AwaitingProof | PorChallengeOutcome::ProofSubmitted => {}
            }
        }
        let providers_missing_vrf = provider_map
            .iter()
            .filter(|(_, stats)| stats.forced > 0)
            .map(|(provider, _)| *provider)
            .collect::<Vec<_>>();
        if let Some(projection) = authoritative {
            debug_assert!(
                providers_missing_vrf
                    .iter()
                    .all(|provider| projection.forced_providers.contains_key(provider))
            );
        }
        let mut top_offenders: Vec<PorProviderSummaryV1> = provider_map
            .iter()
            .filter_map(|(provider_id, stats)| {
                if stats.failures == 0 && stats.forced == 0 {
                    return None;
                }
                let challenges = stats.challenges;
                let successes = stats.successes;
                let failures = stats.failures;
                let forced = stats.forced;
                let success_rate_bps = if challenges == 0 {
                    10_000
                } else {
                    u16::try_from((u64::from(successes) * 10_000_u64) / u64::from(challenges))
                        .unwrap_or(10_000)
                };
                Some(PorProviderSummaryV1 {
                    provider_id: *provider_id,
                    manifest_count: stats.manifests.len() as u32,
                    challenges,
                    successes,
                    failures,
                    forced,
                    success_rate_bps,
                    first_failure_at: stats.first_failure_at,
                    last_success_latency_ms_p95: None,
                    repair_dispatched: failures > 0,
                    pending_repairs: 0,
                    ticket_id: None,
                })
            })
            .collect();
        top_offenders.sort_by(|left, right| match right.failures.cmp(&left.failures) {
            Ordering::Equal => match right.forced.cmp(&left.forced) {
                Ordering::Equal => left.provider_id.cmp(&right.provider_id),
                other => other,
            },
            other => other,
        });
        if top_offenders.len() > 10 {
            top_offenders.truncate(10);
        }
        let report = PorWeeklyReportV1 {
            version: POR_WEEKLY_REPORT_VERSION_V1,
            cycle,
            generated_at,
            challenges_total,
            challenges_verified,
            challenges_failed,
            forced_challenges,
            repairs_enqueued: 0,
            repairs_completed: 0,
            mean_latency_ms: None,
            p95_latency_ms: None,
            slashing_events: Vec::new(),
            providers_missing_vrf,
            top_offenders,
            notes: None,
        };
        report
            .validate()
            .map_err(PorCoordinatorError::InvalidWeeklyReport)?;
        Ok(report)
    }
    /// Persist coordinator state to the configured backing store, if present.
    ///
    /// # Errors
    ///
    /// Returns [`PorCoordinatorError::Persistence`] when the persistence layer
    /// encounters a failure.
    fn persist(&self) -> Result<(), PorCoordinatorError> {
        #[cfg(not(test))]
        let status_generation = self.require_authoritative_projection()?.indexes.generation;
        #[cfg(test)]
        let status_generation = self.authoritative_projection.read().as_ref().map_or_else(
            || self.status_indexes.read().generation,
            |projection| projection.indexes.generation,
        );
        self.persist_with_status_generation(status_generation)
    }
    /// Persist coordinator state with the generation that will be published
    /// with the corresponding status indexes.
    fn persist_with_status_generation(
        &self,
        status_generation: u64,
    ) -> Result<(), PorCoordinatorError> {
        debug_assert_ne!(status_generation, 0);
        if let Some(persistence) = &self.persistence {
            #[cfg(not(test))]
            {
                let _authoritative = self.require_authoritative_projection()?;
                let prepared_weekly_report = self.prepared_weekly_report.read().clone();
                persistence.store(1, &[], &[], prepared_weekly_report.as_ref())?;
                return Ok(());
            }
            #[cfg(test)]
            if self.authoritative_projection.read().is_some() {
                let prepared_weekly_report = self.prepared_weekly_report.read().clone();
                persistence.store(1, &[], &[], prepared_weekly_report.as_ref())?;
                return Ok(());
            }
            #[cfg(test)]
            let mut records: Vec<_> = self
                .records
                .iter()
                .map(|entry| entry.value().clone())
                .collect();
            #[cfg(test)]
            records.sort_by(|left, right| {
                left.challenge
                    .challenge_id
                    .cmp(&right.challenge.challenge_id)
            });
            #[cfg(test)]
            let forced_guard = self.forced_providers.read();
            #[cfg(test)]
            let mut forced: Vec<_> = forced_guard
                .iter()
                .map(|(provider, epochs)| (*provider, epochs.iter().copied().collect::<Vec<_>>()))
                .collect();
            #[cfg(test)]
            forced.sort_by(|left, right| left.0.cmp(&right.0));
            #[cfg(test)]
            drop(forced_guard);
            #[cfg(test)]
            let prepared_weekly_report = self.prepared_weekly_report.read().clone();
            #[cfg(test)]
            persistence.store(
                status_generation,
                &records,
                &forced,
                prepared_weekly_report.as_ref(),
            )?;
        }
        Ok(())
    }
    #[cfg(test)]
    fn track_forced(&self, provider_id: &[u8; 32], epoch: u64) {
        let mut guard = self.forced_providers.write();
        guard.entry(*provider_id).or_default().insert(epoch);
    }
    #[cfg(test)]
    fn untrack_forced(&self, provider_id: &[u8; 32], epoch: u64) {
        let mut guard = self.forced_providers.write();
        if let Some(epochs) = guard.get_mut(provider_id) {
            epochs.remove(&epoch);
            if epochs.is_empty() {
                guard.remove(provider_id);
            }
        }
    }
}
