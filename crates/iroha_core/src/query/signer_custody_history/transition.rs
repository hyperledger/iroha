//! Staged generic control transitions; operation invalidation stays with receipt authority.
use super::*;
use sorafs_manifest::signer::{
    custody::{
        SignerCustodyActiveHeadV1, SignerCustodyEnrollmentContextV1,
        verify_signer_custody_enrollment_v1,
    },
    custody_control::{
        SignerCustodyPolicyTransitionErrorV1, SignerCustodyPolicyV1,
        configure_signer_custody_policy_v1,
    },
};

#[derive(Clone, Copy)]
pub(crate) enum ControlAction<'a> {
    Configure(&'a [u8]),
    Enroll(&'a [u8]),
    Revoke { signer: bool, attester: bool },
}
pub(crate) struct ControlTransition<'a> {
    pub(crate) deployment: &'a str,
    pub(crate) expected_revision: u64,
    pub(crate) expected_digest: [u8; 32],
    pub(crate) request_digest: [u8; 32],
    pub(crate) action: ControlAction<'a>,
}

fn prepare_keys<P: CustodyPurpose>(
    world: &impl WorldReadOnly,
    deployment: &str,
    current: Option<&NativeControl<P>>,
    next: &SignerCustodyPolicyV1,
) -> Result<Vec<StatePath>, HistoryError> {
    let mut paths = Vec::with_capacity(2);
    for (signer, key, old_key) in [
        (
            true,
            &next.binding.public_key,
            current.map(|row| &row.state.policy.binding.public_key),
        ),
        (
            false,
            &next.attester_public_key,
            current.map(|row| &row.state.policy.attester_public_key),
        ),
    ] {
        let path = key_path::<P>(deployment, signer, key)?;
        if old_key == Some(key) {
            let first: ControlIndexV1 = decode(
                world
                    .smart_contract_state()
                    .get(&path)
                    .ok_or(HistoryError::CorruptHistory)?,
            )?;
            if first.revision == 0
                || first.revision > current.ok_or(HistoryError::CorruptHistory)?.index.revision
            {
                return Err(HistoryError::CorruptHistory);
            }
        } else {
            if world.smart_contract_state().get(&path).is_some() {
                return Err(HistoryError::Generation);
            }
            paths.push(path);
        }
    }
    Ok(paths)
}
/// Check finite revision capacity before additional purpose-owned admission work.
pub(crate) fn control_revision<P: CustodyPurpose>(
    transition: &ControlTransition<'_>,
) -> Result<u64, HistoryError> {
    let revision = transition
        .expected_revision
        .checked_add(1)
        .ok_or(HistoryError::Capacity)?;
    if revision > P::MAX_REVISIONS
        || (!matches!(transition.action, ControlAction::Revoke { .. })
            && revision > P::NORMAL_REVISIONS)
    {
        return Err(HistoryError::Capacity);
    }
    Ok(revision)
}

/// Prepare an entire control transition without publishing any native state.
pub(crate) fn prepare_control<P: CustodyPurpose>(
    tx: &StateTransaction<'_, '_>,
    authority: &AccountId,
    current: Option<&NativeControl<P>>,
    transition: ControlTransition<'_>,
) -> Result<Vec<(StatePath, Vec<u8>)>, HistoryError> {
    if !valid_deployment::<P>(transition.deployment) || transition.request_digest == [0; 32] {
        return Err(HistoryError::Invalid);
    }
    if current.map_or(0, |value| value.index.revision) != transition.expected_revision
        || current.map_or([0; 32], |value| value.index.digest) != transition.expected_digest
    {
        return Err(HistoryError::Conflict);
    }
    if let Some(current) = current {
        validate_binding::<P>(tx, &current.state.policy.binding, transition.deployment)?;
    }
    let mut writes = Vec::new();
    let revision = control_revision::<P>(&transition)?;
    let execution = execution(
        tx,
        authority,
        current.map(|row| P::record_view(&row.record).execution),
    )?;
    let mut keys = Vec::new();
    let (state, enrollment) = match transition.action {
        ControlAction::Configure(bytes) => {
            let policy: SignerCustodyPolicyV1 = decode(bytes)?;
            validate_binding::<P>(tx, &policy.binding, transition.deployment)?;
            let next =
                configure_signer_custody_policy_v1(current.map(|value| &value.state), policy)
                    .map_err(|error| match error {
                        SignerCustodyPolicyTransitionErrorV1::Invalid => HistoryError::Invalid,
                        SignerCustodyPolicyTransitionErrorV1::Unchanged => HistoryError::Conflict,
                        SignerCustodyPolicyTransitionErrorV1::BindingMismatch => {
                            HistoryError::BindingMismatch
                        }
                        SignerCustodyPolicyTransitionErrorV1::Generation => {
                            HistoryError::Generation
                        }
                    })?;
            keys = prepare_keys::<P>(tx.world(), transition.deployment, current, &next.policy)?;
            (next, None)
        }
        ControlAction::Enroll(bytes) => {
            let current = current.ok_or(HistoryError::Conflict)?;
            let anchor = committed_control::<P>(tx, current)?;
            let verified = verify_signer_custody_enrollment_v1(
                bytes,
                &current.state.policy.binding,
                &current.state.policy.custody_trust(),
                &SignerCustodyEnrollmentContextV1 {
                    now_unix_ms: execution.view().recorded_at_unix_ms,
                    anchor_observed_at_unix_ms: execution.view().recorded_at_unix_ms,
                    current_anchor: anchor,
                    next_sequence: current.state.next_sequence,
                    predecessor_digest: current.state.predecessor_digest,
                    signer_revoked: current.state.signer_revoked,
                    attester_revoked: current.state.attester_revoked,
                },
            )
            .map_err(|_| HistoryError::Custody)?;
            let mut next = current.state.clone();
            next.next_sequence = next
                .next_sequence
                .checked_add(1)
                .ok_or(HistoryError::Capacity)?;
            next.predecessor_digest = verified.record_digest();
            next.active_head = Some(SignerCustodyActiveHeadV1 {
                record_digest: verified.record_digest(),
                sequence: verified.statement().sequence,
                approved_anchor: anchor,
                key_revision: next.policy.binding.key_revision,
                policy_revision: next.policy.binding.policy_revision,
                policy_digest: next.policy.binding.policy_digest,
            });
            (next, Some(bytes.to_vec()))
        }
        ControlAction::Revoke { signer, attester } => {
            let current = current.ok_or(HistoryError::Conflict)?;
            let mut next = current.state.clone();
            if (next.attester_revoked || !attester) && (next.signer_revoked || !signer) {
                return Err(HistoryError::Conflict);
            }
            next.signer_revoked |= signer;
            next.attester_revoked |= attester;
            (
                next,
                P::record_view(&current.record)
                    .enrollment
                    .map(<[u8]>::to_vec),
            )
        }
    };
    state.validate().map_err(|_| HistoryError::Invalid)?;
    validate_binding::<P>(tx, &state.policy.binding, transition.deployment)?;
    let record = P::build_record(ControlRecordParts {
        deployment: transition.deployment.to_owned(),
        revision,
        predecessor_digest: transition.expected_digest,
        request_digest: transition.request_digest,
        execution,
        control_state: encode(&state)?,
        enrollment,
    });
    let index = ControlIndexV1 {
        revision,
        digest: control_digest::<P>(&record)?,
        height: P::record_view(&record).execution.view().height,
        ordinal: P::record_view(&record).execution.view().ordinal,
    };
    let index_bytes = encode(&index)?;
    immutable(
        tx.world(),
        &mut writes,
        control_record_key::<P>(transition.deployment, revision)?,
        encode(&record)?,
    )?;
    immutable(
        tx.world(),
        &mut writes,
        control_height_key::<P>(transition.deployment, index.height, index.ordinal)?,
        index_bytes.clone(),
    )?;
    for key in keys {
        immutable(tx.world(), &mut writes, key, index_bytes.clone())?;
    }
    writes.push((control_head_key::<P>(transition.deployment)?, index_bytes));
    Ok(writes)
}
