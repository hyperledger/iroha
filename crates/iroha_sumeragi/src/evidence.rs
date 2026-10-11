//! Independent attribution of native signed evidence against authenticated chain inputs.
//!
//! The application supplies original authenticated configurations, the parent tip and the
//! complete demotion window. Decoding an evidence record supplies none of that authority.
//! A verified report identifies accountable signers; committing a monetary penalty remains
//! an application decision. Conflicting Commit certificates across views establish a safety
//! violation without attributing their intersection (§3.6).

use std::borrow::Borrow;

use crate::{
    api::CommittedTip,
    crypto::{CertError, Crypto, Verifier},
    message::{BlockHeader, Defect, Evidence, Proposal, VoteKind},
    topology::{Topology, committee_permutation, demoted_set, demotion_window},
    types::{Bitmap, Hash32, HeightConfig},
};

/// Independently authenticated inputs for the subject height of one native evidence report.
///
/// These borrowed inputs must come from the original committed history owner. An embedded
/// evidence context or a node-local record is not an authentication source.
pub struct EvidenceContext<'a, Header: Borrow<BlockHeader> = BlockHeader> {
    /// Application-derived exact native instance, including its network and lane identity.
    pub instance: Hash32,
    /// Height whose authority is being supplied.
    pub height: u64,
    /// Complete authenticated epoch, generation, committee and lagged chain parameters.
    pub config: &'a HeightConfig,
    /// Genesis height of this exact instance.
    pub genesis_height: u64,
    /// Parent tip authenticated by the same original chain history.
    pub parent: &'a CommittedTip,
    /// Parent's exact configuration, required after the genesis parent.
    pub parent_config: Option<&'a HeightConfig>,
    /// Demotion window fixed by signed genesis for this instance.
    pub demotion_window: u64,
    /// Every committed header of the exact demotion interval, in ascending height order.
    /// Borrowing preserves each caller's original immutable allocation owner; wrappers grant
    /// no authority and undergo the identical count, order, instance and topology checks.
    pub demotion_headers: &'a [Header],
}

/// Verified attribution, without conferring authorization to change stake or balances.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidenceAttribution {
    /// Subject height, checked against the independently authenticated configuration.
    height: u64,
    /// Exact committee bitmap of signers directly proven accountable by this report.
    offenders: Bitmap,
    /// The report proves two conflicting Commit certificates and requires a safety halt.
    safety_violation: bool,
}

impl EvidenceAttribution {
    /// Subject height under the independently supplied native authority.
    pub const fn height(&self) -> u64 {
        self.height
    }
    /// Exact directly accountable signer set; empty for cross-view safety violations.
    pub fn offenders(&self) -> &Bitmap {
        &self.offenders
    }
    /// Whether two conflicting Commit certificates establish a safety violation.
    pub const fn safety_violation(&self) -> bool {
        self.safety_violation
    }
}

/// A report or its independent authority is insufficient for attribution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvidenceError {
    /// Missing or inconsistent authenticated height, parent or exact committee geometry.
    Context,
    /// The original complete demotion window was not supplied.
    DemotionHistory,
    /// Signed artifacts do not describe the same native subject or do not conflict.
    NotConflicting,
    /// The declared signed-content defect does not reproduce from committed chain inputs.
    DefectMismatch,
    /// A native signature or certificate did not verify.
    Signature(CertError),
}

impl core::fmt::Display for EvidenceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Context => f.write_str("invalid native evidence authority context"),
            Self::DemotionHistory => f.write_str("incomplete native evidence demotion history"),
            Self::NotConflicting => f.write_str("native evidence does not prove a signed conflict"),
            Self::DefectMismatch => f.write_str("native proposal defect does not reproduce"),
            Self::Signature(error) => write!(f, "invalid native evidence signature: {error:?}"),
        }
    }
}
impl std::error::Error for EvidenceError {}
impl From<CertError> for EvidenceError {
    fn from(error: CertError) -> Self {
        Self::Signature(error)
    }
}

impl<Header: Borrow<BlockHeader>> EvidenceContext<'_, Header> {
    fn validate(&self) -> Result<(), EvidenceError> {
        let committee = &self.config.committee;
        if self.height <= self.genesis_height
            || self.parent.height.checked_add(1) != Some(self.height)
            || !self.config.epoch.contains(self.height)
            || committee.n() < 4
            || committee.n() != committee.f() * 3 + 1
            || committee.q() != committee.f() * 2 + 1
        {
            return Err(EvidenceError::Context);
        }
        if self.parent.height > self.genesis_height {
            let parent = self.parent_config.ok_or(EvidenceError::Context)?;
            if !parent.epoch.contains(self.parent.height) {
                return Err(EvidenceError::Context);
            }
        }
        Ok(())
    }

    fn topology(&self, crypto: &dyn Crypto) -> Result<Topology, EvidenceError> {
        let expected = demotion_window(self.height, self.genesis_height, self.demotion_window);
        match expected {
            None if !self.demotion_headers.is_empty() => {
                return Err(EvidenceError::DemotionHistory);
            }
            Some((first, last)) => {
                let count = last.checked_sub(first).and_then(|n| n.checked_add(1));
                if count != u64::try_from(self.demotion_headers.len()).ok()
                    || (first..=last)
                        .zip(self.demotion_headers.iter().map(Borrow::borrow))
                        .any(|(height, header)| {
                            header.height != height || header.instance != self.instance
                        })
                {
                    return Err(EvidenceError::DemotionHistory);
                }
            }
            None => {}
        }
        let demoted = demoted_set(
            &self.config.committee,
            self.height,
            self.genesis_height,
            self.demotion_window,
            self.demotion_headers.iter().map(Borrow::borrow),
        );
        Topology::from_parts(
            committee_permutation(
                crypto,
                &self.instance,
                &self.config.epoch,
                &self.config.committee,
            ),
            &demoted,
            self.height,
        )
        .ok_or(EvidenceError::Context)
    }
}

/// Reverify and attribute all five native evidence variants using original signed artifacts.
///
/// Same-view certificate conflicts attribute only the exact signer intersection. Different-view
/// conflicting Commit certificates return an empty offender set and a safety violation. A signed
/// proposal with poison execution, an unsigned payload substitution, or a relay's altered
/// signature cannot implicate an honest validator.
///
/// # Errors
/// Rejects incomplete authority, wrong epoch/generation context or instance, absent conflicts,
/// incorrect defect labels, and invalid signatures. Caller-owned decode/admission byte limits
/// must be enforced before constructing the input graph.
pub fn verify_evidence<Header: Borrow<BlockHeader>>(
    crypto: &dyn Crypto,
    context: &EvidenceContext<'_, Header>,
    evidence: &Evidence,
) -> Result<EvidenceAttribution, EvidenceError> {
    context.validate()?;
    let config = context.config;
    let epoch = &config.epoch.id;
    let committee = &config.committee;
    let verifier = Verifier::new(crypto, &context.instance, epoch, committee);
    let mut offenders = Vec::new();
    let mut safety_violation = false;
    match evidence {
        Evidence::ProposalEquivocation(first, second) => {
            if first.height != context.height
                || second.height != context.height
                || first.view != second.view
            {
                return Err(EvidenceError::NotConflicting);
            }
            let topology = context.topology(crypto)?;
            let leader = topology.leader(first.view);
            let first_value = verifier.verify_proposal_signature(leader, first)?;
            let second_value = verifier.verify_proposal_signature(leader, second)?;
            if first_value == second_value {
                return Err(EvidenceError::NotConflicting);
            }
            offenders.push(leader);
        }
        Evidence::VoteEquivocation(first, second) => {
            if first.height != context.height
                || second.height != context.height
                || first.view != second.view
                || first.kind != second.kind
                || first.signer != second.signer
                || (first.block_hash == second.block_hash && first.result == second.result)
            {
                return Err(EvidenceError::NotConflicting);
            }
            // Each distinct vote value must carry its signer's valid signature.
            verifier.verify_vote(first)?;
            verifier.verify_vote(second)?;
            offenders.push(first.signer);
        }
        Evidence::TimeoutEquivocation(first, second) => {
            if first.height != context.height
                || second.height != context.height
                || first.view != second.view
                || first.signer != second.signer
                || first.hq() == second.hq()
            {
                return Err(EvidenceError::NotConflicting);
            }
            verifier.verify_timeout(first)?;
            verifier.verify_timeout(second)?;
            offenders.push(first.signer);
        }
        Evidence::InvalidProposal { proposal, defect } => {
            if proposal.height != context.height {
                return Err(EvidenceError::Context);
            }
            let topology = context.topology(crypto)?;
            let leader = topology.leader(proposal.view);
            let (hash, _) = verifier.verify_proposal_signature(leader, proposal)?;
            if proposal_defect(crypto, context, &topology, proposal, hash) != Some(*defect) {
                return Err(EvidenceError::DefectMismatch);
            }
            offenders.push(leader);
        }
        Evidence::ConflictingCertificates(first, second) => {
            if first.kind != VoteKind::Commit
                || second.kind != VoteKind::Commit
                || first.height != context.height
                || second.height != context.height
                || first.value() == second.value()
            {
                return Err(EvidenceError::NotConflicting);
            }
            // As in the native safety monitor (§7.6), the exact quorum of authenticated
            // Commit signatures establishes this safety violation.
            verifier.verify_qc(first)?;
            verifier.verify_qc(second)?;
            safety_violation = true;
            if first.view == second.view {
                offenders.extend(
                    first
                        .signers
                        .ones()
                        .filter(|index| second.signers.ones().any(|other| other == *index)),
                );
            }
        }
    }
    Ok(EvidenceAttribution {
        height: context.height,
        offenders: Bitmap::from_indices(committee.n(), offenders).ok_or(EvidenceError::Context)?,
        safety_violation,
    })
}

fn proposal_defect<Header: Borrow<BlockHeader>>(
    crypto: &dyn Crypto,
    context: &EvidenceContext<'_, Header>,
    topology: &Topology,
    proposal: &Proposal,
    block_hash: Hash32,
) -> Option<Defect> {
    let config = context.config;
    if let Some(defect) = proposal.justify_defect(context.height, |tc| {
        crate::crypto::Verifier::new(
            crypto,
            &context.instance,
            &config.epoch.id,
            &config.committee,
        )
        .verify_tc(tc)
        .is_ok()
    }) {
        return Some(defect);
    }
    if let Some(defect) = proposal.parent_defect(
        context.parent.height == context.genesis_height,
        context.parent.height,
        (context.parent.block_hash, context.parent.result),
        |qc| {
            context.parent_config.is_some_and(|parent| {
                crate::crypto::Verifier::new(
                    crypto,
                    &context.instance,
                    &parent.epoch.id,
                    &parent.committee,
                )
                .verify_qc(qc)
                .is_ok()
            })
        },
    ) {
        return Some(defect);
    }
    proposal.header_defect(
        context.instance,
        context.height,
        (context.parent.block_hash, context.parent.result),
        config,
        topology,
        block_hash,
        |_| true,
    )
}

#[cfg(test)]
mod tests;
