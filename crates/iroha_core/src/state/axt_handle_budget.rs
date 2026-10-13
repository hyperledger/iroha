// Permanent AXT counter and policy-boundary helpers.
/// Failure to reserve both permanent replay identities for one verified spend.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ThisError)]
pub(crate) enum AxtSpendReplayReservationErrorV1 {
    /// The signed issuer nonce identity is malformed.
    #[error("AXT spend has an invalid issuer nonce replay identity")]
    InvalidIssuerNonce,
    /// The claimed finalized source coordinate is malformed.
    #[error("AXT spend has an invalid source transfer replay identity")]
    InvalidSourceTransfer,
    /// A zero consensus slot cannot record application.
    #[error("AXT spend replay reservation requires a positive consensus slot")]
    ZeroSlot,
    /// Issuer context and source coordinate refer to different networks or dataspaces.
    #[error("AXT spend issuer and source replay identities disagree")]
    IdentityMismatch,
    /// This issuer nonce was already consumed by an earlier envelope.
    #[error("AXT spend issuer nonce has already been consumed")]
    IssuerNonceConsumed,
    /// This physical source transfer was already consumed by an earlier envelope.
    #[error("AXT source transfer has already been consumed")]
    SourceTransferConsumed,
}

#[allow(single_use_lifetimes)]
impl WorldTransaction<'_, '_> {
    /// Reserve one issuer nonce and one physical source transfer in the same transaction.
    ///
    /// The caller must first verify finalized State, successful source execution,
    /// the exact transfer, current issuer authority, and the signed spend. This
    /// ledger operation itself does not grant remote-spend admission.
    ///
    /// # Errors
    /// Rejects malformed identities, mismatched source/issuer scope, a zero slot,
    /// or reuse of either permanent replay identity.
    // TODO: Connect only after the complete finalized-State source resolver and
    // issuer authorization gate exist; remote spends remain fail-closed.
    #[allow(dead_code)]
    pub(crate) fn reserve_verified_axt_spend_replay(
        &mut self,
        issuer_nonce: AxtAnchoredSpendReplayKeyV1,
        source_transfer: AxtSourceTransferReplayKeyV1,
        consumed_slot: u64,
    ) -> Result<(), AxtSpendReplayReservationErrorV1> {
        issuer_nonce
            .validate()
            .map_err(|_| AxtSpendReplayReservationErrorV1::InvalidIssuerNonce)?;
        source_transfer
            .validate()
            .map_err(|_| AxtSpendReplayReservationErrorV1::InvalidSourceTransfer)?;
        if consumed_slot == 0 {
            return Err(AxtSpendReplayReservationErrorV1::ZeroSlot);
        }
        if source_transfer.network_id != issuer_nonce.issuer_context.network_id
            || source_transfer.dataspace_id != issuer_nonce.issuer_context.asset_dsid
        {
            return Err(AxtSpendReplayReservationErrorV1::IdentityMismatch);
        }
        if self.axt_spend_nonce_ledger.get(&issuer_nonce).is_some() {
            return Err(AxtSpendReplayReservationErrorV1::IssuerNonceConsumed);
        }
        if self
            .axt_source_transfer_replay_ledger
            .get(&source_transfer)
            .is_some()
        {
            return Err(AxtSpendReplayReservationErrorV1::SourceTransferConsumed);
        }
        self.axt_spend_nonce_ledger
            .insert(issuer_nonce, consumed_slot);
        self.axt_source_transfer_replay_ledger.insert(
            source_transfer,
            AxtSourceTransferReplayRecordV1 {
                issuer_nonce,
                consumed_slot,
            },
        );
        Ok(())
    }
}

fn axt_policy_identity_matches(left: &AxtPolicyEntry, right: &AxtPolicyEntry) -> bool {
    left.manifest_root == right.manifest_root && left.target_lane == right.target_lane
}

fn axt_policy_is_active(policy: &AxtPolicyEntry) -> bool {
    policy.manifest_root != [0; 32]
}

fn axt_policy_identity_changed(
    previous: Option<&AxtPolicyEntry>,
    next: Option<&AxtPolicyEntry>,
) -> bool {
    match (previous, next) {
        (Some(previous), Some(next)) => !axt_policy_identity_matches(previous, next),
        (Some(_), None) | (None, Some(_)) => true,
        (None, None) => false,
    }
}

pub(crate) fn axt_counter_after_block_boundary(
    previous_policy: Option<&AxtPolicyEntry>,
    next_policy: Option<&AxtPolicyEntry>,
    minimum_generation: u64,
    authorization_identity_changed: bool,
    counter_before_block: Option<AxtHandleCounterRecord>,
    current_counter: Option<AxtHandleCounterRecord>,
) -> Result<Option<AxtHandleCounterRecord>, AxtHandleCounterError> {
    let previous_was_active = previous_policy.is_some_and(axt_policy_is_active);
    let next_is_active = next_policy.is_some_and(axt_policy_is_active);
    let mut counter = current_counter
        .or(counter_before_block)
        .or_else(|| {
            previous_policy.and_then(|policy| {
                (policy.next_handle_counter != 0)
                    .then_some((policy.next_handle_counter, policy.active_handle_era))
                    .and_then(|(next, generation)| {
                        AxtHandleCounterRecord::try_from_parts(next, generation).ok()
                    })
            })
        })
        .or_else(|| {
            next_policy
                .filter(|policy| axt_policy_is_active(policy))
                .map(|_| AxtHandleCounterRecord::initial(minimum_generation))
        });
    let revokes_authority = previous_was_active || counter_before_block.is_some() && next_is_active;
    let raises_generation_floor = counter
        .as_ref()
        .is_some_and(|counter| minimum_generation > counter.authorization_generation());
    if revokes_authority && (authorization_identity_changed || raises_generation_floor) {
        counter
            .as_mut()
            .expect("an authorized AXT policy must retain its permanent counter")
            .try_revoke_for_policy_transition(minimum_generation)?;
    }
    Ok(counter)
}

pub(crate) fn axt_policy_generation_minimum(
    world: &(impl WorldReadOnly + ?Sized),
    dataspace: DataSpaceId,
    policy: Option<&AxtPolicyEntry>,
) -> u64 {
    let Some(policy) = policy.filter(|policy| axt_policy_is_active(policy)) else {
        return 0;
    };
    world
        .space_directory_manifests()
        .iter()
        .filter_map(|(_, set)| set.get(&dataspace))
        .filter(|record| {
            record.is_active() && record.manifest_hash.as_ref() == policy.manifest_root.as_slice()
        })
        .map(|record| {
            record
                .lifecycle
                .activated_epoch
                .unwrap_or(record.manifest.activation_epoch)
        })
        .max()
        .unwrap_or(policy.active_handle_era)
}

fn axt_lane_map_from_lane_config(lane_config: &LaneConfig) -> BTreeMap<DataSpaceId, LaneId> {
    let mut lane_for_dataspace = BTreeMap::new();
    for entry in lane_config.entries() {
        lane_for_dataspace
            .entry(entry.dataspace_id)
            .or_insert(entry.lane_id);
    }
    lane_for_dataspace
}
