//! Borrowed execution drafts; every owned graph is allocated only after original admission.

use super::*;
use iroha_data_model::sccp::fast_pause::{SCCP_PAUSE_PANEL_MAX_DRAWN_V1, SccpPassPositionV1};

/// Scalar fast-pause effect and its borrowed canonical destination parts.
#[derive(Debug, Clone, Copy)]
pub(crate) struct FastPauseDraft<'a> {
    pub(crate) certificate_id: [u8; 32],
    pub(crate) effect_hash: [u8; 32],
    pub(crate) panel_id: [u8; 32],
    pub(crate) enacted_at: SccpPassPositionV1,
    pub(crate) enacted_at_ms: u64,
    pub(crate) until_ms: u64,
    pub(crate) taira: bool,
    pub(crate) revisions: &'a [u32],
}

/// Original draw and sorted acceptances; neither borrowed slice owns an AccountId graph.
#[derive(Debug, Clone, Copy)]
pub(crate) struct PausePanelDraft<'a> {
    pub(crate) panel_seq: u64,
    pub(crate) pulse_id: [u8; 32],
    pub(crate) seated_height: u64,
    pub(crate) seated_at_ms: u64,
    pub(crate) accept_until_ms: u64,
    pub(crate) term_ends_at_ms: u64,
    pub(crate) drawn: &'a [&'a AccountId],
    pub(crate) accepted: &'a [&'a AccountId],
    pub(crate) primary_id: [u8; 32],
    pub(crate) backup_id: [u8; 32],
}

/// Borrowed sorted endorsements, including former holders until the current-seat recheck.
#[derive(Debug, Clone, Copy)]
pub(crate) struct FastPauseRoundDraft<'a> {
    pub(crate) panel_id: [u8; 32],
    pub(crate) panel_seq: u64,
    pub(crate) head: u64,
    pub(crate) opened_at_ms: u64,
    pub(crate) closes_at_ms: u64,
    pub(crate) endorsers: &'a [(&'a AccountId, SccpFastPauseEndorsementV1)],
    pub(crate) certify_due: bool,
}

impl RetainedSccpFastPause {
    fn draft_demand(source: &FastPauseDraft<'_>) -> Result<Demand, PauseRecordError> {
        if source.certificate_id == [0; 32]
            || source.effect_hash == [0; 32]
            || source.panel_id == [0; 32]
            || source.enacted_at.height == 0
            || source.until_ms <= source.enacted_at_ms
            || (!source.taira && source.revisions.is_empty())
            || source
                .revisions
                .first()
                .is_some_and(|revision| *revision == 0)
            || !source.revisions.windows(2).all(|pair| pair[0] < pair[1])
        {
            return Err(PauseRecordError::Invalid("fast-pause structure"));
        }
        let mut demand = Demand::default();
        demand.array::<u32>(source.revisions.len())?;
        Ok(demand)
    }

    /// Exact original-pool demand without constructing an intermediate owned DTO.
    pub(crate) fn draft_admission_demand(
        source: &FastPauseDraft<'_>,
    ) -> Result<usize, PauseRecordError> {
        Self::draft_demand(source)?.total_bytes::<SccpFastPauseV1>()
    }

    /// Admit the borrowed effect graph under its original execution budget.
    pub(crate) fn admit_draft(
        source: &FastPauseDraft<'_>,
        budget: &AllocationBudget,
    ) -> Result<Self, PauseRecordError> {
        let mut prepaid = budget.try_reserve_bytes(Self::draft_admission_demand(source)?)?;
        Self::admit_draft_prepaid(source, budget, &mut prepaid)
    }

    /// Consume the exact partition of the original complete effect reservation.
    pub(crate) fn admit_draft_prepaid(
        source: &FastPauseDraft<'_>,
        budget: &AllocationBudget,
        prepaid: &mut AllocationReservation,
    ) -> Result<Self, PauseRecordError> {
        let body = SccpFastPauseV1 {
            certificate_id: source.certificate_id,
            effect_hash: source.effect_hash,
            panel_id: source.panel_id,
            enacted_at: source.enacted_at,
            enacted_at_ms: source.enacted_at_ms,
            until_ms: source.until_ms,
            taira: source.taira,
            revisions: Vec::new(),
        };
        let mut construction =
            Construction::new_prepaid(Self::draft_demand(source)?, budget, prepaid, body)?;
        let mut revisions =
            ChargedBuffer::from_reservation(source.revisions.len(), &mut construction.reservation)
                .map_err(prepaid_error)?;
        for revision in source.revisions {
            revisions
                .try_push(*revision)
                .map_err(|_| PauseRecordError::Invalid("revision count changed"))?;
        }
        construction.body.revisions = construction.vector(revisions)?;
        Ok(Self(publish(construction)?))
    }
}

impl RetainedSccpPausePanel {
    fn draft_demand(source: &PausePanelDraft<'_>) -> Result<Demand, PauseRecordError> {
        if source.panel_seq == 0
            || source.pulse_id == [0; 32]
            || source.seated_height == 0
            || source.accept_until_ms <= source.seated_at_ms
            || source.term_ends_at_ms <= source.accept_until_ms
            || !(10..=SCCP_PAUSE_PANEL_MAX_DRAWN_V1).contains(&source.drawn.len())
            || source.accepted.len() > source.drawn.len()
            || source.primary_id == [0; 32]
            || source.backup_id == [0; 32]
            || source.primary_id == source.backup_id
            || !source
                .drawn
                .iter()
                .enumerate()
                .all(|(index, member)| !source.drawn[..index].contains(member))
            || !source.accepted.windows(2).all(|pair| pair[0] < pair[1])
            || !source
                .accepted
                .iter()
                .all(|member| source.drawn.contains(member))
        {
            return Err(PauseRecordError::Invalid("panel structure"));
        }
        let mut demand = Demand::default();
        demand.array::<AccountId>(source.drawn.len())?;
        demand.array::<AccountId>(source.accepted.len())?;
        for account in source.drawn.iter().chain(source.accepted.iter()) {
            account_demand(&mut demand, account)?;
        }
        Ok(demand)
    }

    /// Exact complete graph demand from borrowed scalar and account references.
    pub(crate) fn draft_admission_demand(
        source: &PausePanelDraft<'_>,
    ) -> Result<usize, PauseRecordError> {
        Self::draft_demand(source)?.total_bytes::<PausePanelBody>()
    }

    /// Reserve the original graph demand before copying even one drawn account.
    pub(crate) fn admit_draft(
        source: &PausePanelDraft<'_>,
        budget: &AllocationBudget,
    ) -> Result<Self, PauseRecordError> {
        let mut prepaid = budget.try_reserve_bytes(Self::draft_admission_demand(source)?)?;
        Self::admit_draft_prepaid(source, budget, &mut prepaid)
    }

    /// Consume a panel's partition of the original complete snapshot or effect reservation.
    pub(crate) fn admit_draft_prepaid(
        source: &PausePanelDraft<'_>,
        budget: &AllocationBudget,
        prepaid: &mut AllocationReservation,
    ) -> Result<Self, PauseRecordError> {
        let body = PausePanelBody {
            panel_seq: source.panel_seq,
            pulse_id: source.pulse_id,
            seated_height: source.seated_height,
            seated_at_ms: source.seated_at_ms,
            accept_until_ms: source.accept_until_ms,
            term_ends_at_ms: source.term_ends_at_ms,
            drawn: Vec::new(),
            accepted: Vec::new(),
            primary_id: source.primary_id,
            backup_id: source.backup_id,
        };
        let mut construction =
            Construction::new_prepaid(Self::draft_demand(source)?, budget, prepaid, body)?;
        construction.body.drawn =
            construction.accounts(source.drawn.len(), source.drawn.iter().copied())?;
        construction.body.accepted =
            construction.accounts(source.accepted.len(), source.accepted.iter().copied())?;
        Ok(Self(publish(construction)?))
    }
}

impl RetainedSccpFastPauseRound {
    fn draft_demand(source: &FastPauseRoundDraft<'_>) -> Result<Demand, PauseRecordError> {
        // Endorsements persist through lazy seat changes. The current-seat quorum is checked
        // by Core; the retained round can name any of the at most 27 drawn accounts.
        if source.panel_id == [0; 32]
            || source.panel_seq == 0
            || source.closes_at_ms <= source.opened_at_ms
            || source.endorsers.is_empty()
            || source.endorsers.len() > SCCP_PAUSE_PANEL_MAX_DRAWN_V1
            || !source
                .endorsers
                .windows(2)
                .all(|pair| pair[0].0 < pair[1].0)
            || !source
                .endorsers
                .iter()
                .all(|(_, value)| value.incident_digest != [0; 32] && value.recorded_at_height != 0)
        {
            return Err(PauseRecordError::Invalid("round structure"));
        }
        let mut demand = Demand::default();
        demand.array::<(AccountId, SccpFastPauseEndorsementV1)>(source.endorsers.len())?;
        for (account, _) in source.endorsers {
            account_demand(&mut demand, account)?;
        }
        Ok(demand)
    }

    /// Exact endorsement graph demand over the original borrowed accounts.
    pub(crate) fn draft_admission_demand(
        source: &FastPauseRoundDraft<'_>,
    ) -> Result<usize, PauseRecordError> {
        Self::draft_demand(source)?.total_bytes::<FastPauseRoundBody>()
    }

    /// Reserve before cloning the original endorsed account graph.
    pub(crate) fn admit_draft(
        source: &FastPauseRoundDraft<'_>,
        budget: &AllocationBudget,
    ) -> Result<Self, PauseRecordError> {
        let mut prepaid = budget.try_reserve_bytes(Self::draft_admission_demand(source)?)?;
        Self::admit_draft_prepaid(source, budget, &mut prepaid)
    }

    /// Consume the exact graph partition of a larger original effect reservation.
    pub(crate) fn admit_draft_prepaid(
        source: &FastPauseRoundDraft<'_>,
        budget: &AllocationBudget,
        prepaid: &mut AllocationReservation,
    ) -> Result<Self, PauseRecordError> {
        let body = FastPauseRoundBody {
            panel_id: source.panel_id,
            panel_seq: source.panel_seq,
            head: source.head,
            opened_at_ms: source.opened_at_ms,
            closes_at_ms: source.closes_at_ms,
            endorsers: Vec::new(),
            certify_due: source.certify_due,
        };
        let mut construction =
            Construction::new_prepaid(Self::draft_demand(source)?, budget, prepaid, body)?;
        let mut entries =
            ChargedBuffer::from_reservation(source.endorsers.len(), &mut construction.reservation)
                .map_err(prepaid_error)?;
        for (account, value) in source.endorsers {
            entries
                .try_push((construction.account(account)?, *value))
                .map_err(|_| PauseRecordError::Invalid("endorser count changed"))?;
        }
        construction.body.endorsers = construction.vector(entries)?;
        Ok(Self(publish(construction)?))
    }
}

#[cfg(test)]
mod tests;
