//! Deterministic future-beacon sortition utilities for on-chain bodies.
use crate::governance::sortition;
use iroha_config::parameters::actual::Governance;
use iroha_crypto::blake2::{Blake2b512, Digest as _};
use iroha_data_model::{NetworkId, account::AccountId, governance::types::ParliamentBody};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
/// Bodies selected before a narrow Policy Jury result can trigger a fresh Confirmation Jury.
#[cfg(test)]
const PRIMARY_PARLIAMENT_BODIES_V1: [ParliamentBody; 9] = [
    ParliamentBody::RulesCommittee,
    ParliamentBody::AgendaCouncil,
    ParliamentBody::InterestPanel,
    ParliamentBody::ReviewPanel,
    ParliamentBody::CoordinationCouncil,
    ParliamentBody::MpcCommittee,
    ParliamentBody::FmaCommittee,
    ParliamentBody::OversightCommittee,
    ParliamentBody::PolicyJury,
];
/// Deterministic simultaneous body assignment and its binding concentration cap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ParliamentDrawPlan {
    /// Rosters derived from the committed candidate snapshot and future pulse.
    pub(crate) rosters: BTreeMap<ParliamentBody, ParliamentDrawRoster>,
    /// Smallest allocator-feasible maximum body invitations assigned to one citizen.
    pub(crate) assignment_cap: u32,
}
/// One attempt-local roster derived from a committed candidate snapshot and future pulse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ParliamentDrawRoster {
    /// Body this roster belongs to.
    pub(crate) body: ParliamentBody,
    /// Finalized future-pulse height used for the draw.
    pub(crate) pulse_height: u64,
    /// Number of candidates in the committed snapshot.
    pub(crate) candidate_count: u32,
    /// Deterministically ordered primary members.
    pub(crate) members: Vec<AccountId>,
    /// Deterministically ordered alternates.
    pub(crate) alternates: Vec<AccountId>,
}
fn scored_output(seed: &[u8; 64], input_domain: &[u8], account_id: &AccountId) -> [u8; 32] {
    let input = sortition::build_input(input_domain, seed, account_id);
    let digest = Blake2b512::digest(input);
    let mut output = [0u8; 32];
    output.copy_from_slice(&digest[..32]);
    output
}
/// Derive an attempt-local body plan from an exact precommitted candidate snapshot.
///
/// `pulse_height` and `future_beacon` must come from the finalized pulse named by
/// the corresponding sortition requests. The caller is responsible for checking
/// that `candidates` is the exact strictly ordered snapshot committed by every
/// request in `bodies`; this function defensively deduplicates without using the
/// caller's ordering as entropy.
#[must_use]
pub(crate) fn derive_attempt_body_plan_v1(
    gov_cfg: &Governance,
    network_id: &NetworkId,
    pulse_height: u64,
    future_beacon: &[u8; 32],
    candidates: &[AccountId],
    bodies: &[ParliamentBody],
) -> ParliamentDrawPlan {
    let candidates: Vec<_> = candidates
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    derive_body_plan(
        gov_cfg,
        network_id,
        pulse_height,
        future_beacon,
        &candidates,
        bodies,
    )
}

/// Return the smallest feasible simultaneous assignment cap for `bodies`.
#[must_use]
fn smallest_feasible_assignment_cap(
    gov_cfg: &Governance,
    candidate_count: usize,
    bodies: &[ParliamentBody],
    alternates_per_body: usize,
) -> u32 {
    if candidate_count == 0 || bodies.is_empty() {
        return 0;
    }
    let required_invitations = bodies.iter().fold(0usize, |total, body| {
        let primary = body_committee_size(gov_cfg, *body).min(candidate_count);
        let alternates = alternates_per_body.min(candidate_count.saturating_sub(primary));
        total.saturating_add(primary.saturating_add(alternates))
    });
    let cap = required_invitations
        .div_ceil(candidate_count)
        .min(bodies.len());
    u32::try_from(cap).unwrap_or(u32::MAX)
}

#[allow(clippy::too_many_arguments)]
fn derive_body_plan(
    gov_cfg: &Governance,
    network_id: &NetworkId,
    epoch: u64,
    beacon: &[u8; 32],
    candidates: &[AccountId],
    bodies: &[ParliamentBody],
) -> ParliamentDrawPlan {
    let candidate_count = u32::try_from(candidates.len()).unwrap_or(u32::MAX);
    let alternates_per_body = gov_cfg.parliament_alternate_size;
    let mut rankings = BTreeMap::new();
    for body in bodies {
        rankings.insert(
            *body,
            ranked_body_candidates(network_id, epoch, beacon, candidates, *body),
        );
    }
    let minimum_cap =
        smallest_feasible_assignment_cap(gov_cfg, candidates.len(), bodies, alternates_per_body);
    let maximum_cap = u32::try_from(bodies.len()).unwrap_or(u32::MAX);
    for assignment_cap in minimum_cap..=maximum_cap {
        if let Some(plan) = try_derive_body_plan_with_cap(
            gov_cfg,
            candidates,
            bodies,
            &rankings,
            epoch,
            alternates_per_body,
            candidate_count,
            assignment_cap,
        ) {
            return plan;
        }
    }
    unreachable!("a per-body invitation cap must admit every duplicate-free body plan")
}

#[allow(clippy::too_many_arguments)]
fn try_derive_body_plan_with_cap(
    gov_cfg: &Governance,
    candidates: &[AccountId],
    bodies: &[ParliamentBody],
    rankings: &BTreeMap<ParliamentBody, Vec<AccountId>>,
    pulse_height: u64,
    alternates_per_body: usize,
    candidate_count: u32,
    assignment_cap: u32,
) -> Option<ParliamentDrawPlan> {
    let mut loads: BTreeMap<AccountId, u32> = candidates
        .iter()
        .cloned()
        .map(|candidate| (candidate, 0))
        .collect();
    let mut selected: BTreeMap<ParliamentBody, Vec<AccountId>> = BTreeMap::new();
    for body in bodies {
        let target = body_committee_size(gov_cfg, *body).min(candidates.len());
        let ranked = rankings.get(body)?;
        let mut eligible: Vec<_> = ranked
            .iter()
            .enumerate()
            .filter_map(|(rank, candidate)| {
                let load = loads.get(candidate).copied().unwrap_or(0);
                (load < assignment_cap).then_some((
                    load,
                    same_matter_overlap(*body, candidate, &selected),
                    rank,
                    candidate.clone(),
                ))
            })
            .collect();
        eligible.sort_by(|left, right| {
            (left.0, left.1, left.2, &left.3).cmp(&(right.0, right.1, right.2, &right.3))
        });
        let chosen_set: BTreeSet<_> = eligible
            .into_iter()
            .take(target)
            .map(|(_, _, _, candidate)| candidate)
            .collect();
        let members: Vec<_> = ranked
            .iter()
            .filter(|candidate| chosen_set.contains(*candidate))
            .cloned()
            .collect();
        if members.len() != target {
            return None;
        }
        for member in &members {
            let load = loads
                .get_mut(member)
                .expect("selected candidates originate in the frozen snapshot");
            *load = load.saturating_add(1);
        }
        selected.insert(*body, members);
    }

    let alternates = derive_alternates_with_cap(
        candidates,
        bodies,
        rankings,
        &selected,
        &loads,
        alternates_per_body,
        assignment_cap,
    )?;
    let mut rosters = BTreeMap::new();
    for body in bodies {
        let members = selected.remove(body).unwrap_or_default();
        let alternates = alternates.get(body)?.clone();
        rosters.insert(
            *body,
            ParliamentDrawRoster {
                body: *body,
                pulse_height,
                members,
                alternates,
                candidate_count,
            },
        );
    }
    Some(ParliamentDrawPlan {
        rosters,
        assignment_cap,
    })
}

/// Reserve a capacity-bounded, duplicate-free alternate matching.
///
/// Greedy selection alone can strand a later body even when the requested cap
/// is feasible. The deterministic alternating-path search below reassigns an
/// earlier reservation when necessary. Final vectors are restored to their
/// body-local beacon ranking before they are committed.
#[allow(clippy::too_many_arguments)]
fn derive_alternates_with_cap(
    candidates: &[AccountId],
    bodies: &[ParliamentBody],
    rankings: &BTreeMap<ParliamentBody, Vec<AccountId>>,
    primary: &BTreeMap<ParliamentBody, Vec<AccountId>>,
    primary_loads: &BTreeMap<AccountId, u32>,
    alternates_per_body: usize,
    assignment_cap: u32,
) -> Option<BTreeMap<ParliamentBody, Vec<AccountId>>> {
    let candidate_indices: BTreeMap<_, _> = candidates
        .iter()
        .cloned()
        .enumerate()
        .map(|(index, candidate)| (candidate, index))
        .collect();
    let mut ranked_indices = Vec::with_capacity(bodies.len());
    let mut primary_indices = Vec::with_capacity(bodies.len());
    let mut alternate_targets = Vec::with_capacity(bodies.len());
    for body in bodies {
        let ranked = rankings.get(body)?;
        let ranked = ranked
            .iter()
            .map(|candidate| candidate_indices.get(candidate).copied())
            .collect::<Option<Vec<_>>>()?;
        let members = primary.get(body)?;
        let member_indices = members
            .iter()
            .map(|candidate| candidate_indices.get(candidate).copied())
            .collect::<Option<BTreeSet<_>>>()?;
        alternate_targets
            .push(alternates_per_body.min(candidates.len().saturating_sub(member_indices.len())));
        ranked_indices.push(ranked);
        primary_indices.push(member_indices);
    }

    let mut capacities = Vec::with_capacity(candidates.len());
    let mut total_loads = Vec::with_capacity(candidates.len());
    for candidate in candidates {
        let primary_load = primary_loads.get(candidate).copied().unwrap_or(0);
        capacities.push(assignment_cap.saturating_sub(primary_load) as usize);
        total_loads.push(primary_load as usize);
    }
    let mut matching = vec![BTreeSet::<usize>::new(); bodies.len()];
    for (body_index, target) in alternate_targets.into_iter().enumerate() {
        while matching[body_index].len() < target {
            if !augment_alternate_matching(
                body_index,
                &ranked_indices,
                &primary_indices,
                &capacities,
                &mut total_loads,
                &mut matching,
            ) {
                return None;
            }
        }
    }

    let mut result = BTreeMap::new();
    for (body_index, body) in bodies.iter().copied().enumerate() {
        let alternates = ranked_indices[body_index]
            .iter()
            .filter(|candidate| matching[body_index].contains(candidate))
            .map(|candidate| candidates[*candidate].clone())
            .collect();
        result.insert(body, alternates);
    }
    Some(result)
}

/// Add one alternate reservation through a deterministic alternating path.
fn augment_alternate_matching(
    root_body: usize,
    ranked_indices: &[Vec<usize>],
    primary_indices: &[BTreeSet<usize>],
    capacities: &[usize],
    total_loads: &mut [usize],
    matching: &mut [BTreeSet<usize>],
) -> bool {
    let body_count = matching.len();
    let mut parents = vec![None; body_count.saturating_add(capacities.len())];
    parents[root_body] = Some(root_body);
    let mut queue = VecDeque::from([root_body]);
    let mut terminal_candidate = None;

    while let Some(node) = queue.pop_front() {
        if node < body_count {
            let mut eligible = ranked_indices[node]
                .iter()
                .enumerate()
                .filter(|(_, candidate)| {
                    !primary_indices[node].contains(candidate)
                        && !matching[node].contains(candidate)
                })
                .map(|(rank, candidate)| (total_loads[*candidate], rank, *candidate))
                .collect::<Vec<_>>();
            eligible.sort_unstable();
            for (_, _, candidate) in eligible {
                let candidate_node = body_count + candidate;
                if capacities[candidate] == 0 || parents[candidate_node].is_some() {
                    continue;
                }
                parents[candidate_node] = Some(node);
                let alternate_load = matching
                    .iter()
                    .filter(|assignments| assignments.contains(&candidate))
                    .count();
                if alternate_load < capacities[candidate] {
                    terminal_candidate = Some(candidate_node);
                    break;
                }
                queue.push_back(candidate_node);
            }
            if terminal_candidate.is_some() {
                break;
            }
        } else {
            let candidate = node - body_count;
            for (owner_body, assignments) in matching.iter().enumerate() {
                if assignments.contains(&candidate) && parents[owner_body].is_none() {
                    parents[owner_body] = Some(node);
                    queue.push_back(owner_body);
                }
            }
        }
    }

    let Some(mut candidate_node) = terminal_candidate else {
        return false;
    };
    loop {
        let body = parents[candidate_node].expect("candidate on an alternating path has a parent");
        let candidate = candidate_node - body_count;
        if body != root_body {
            let previous_candidate_node =
                parents[body].expect("intermediate body on an alternating path has a parent");
            let previous_candidate = previous_candidate_node - body_count;
            assert!(matching[body].remove(&previous_candidate));
            total_loads[previous_candidate] = total_loads[previous_candidate]
                .checked_sub(1)
                .expect("matched alternate contributes one candidate load");
            candidate_node = previous_candidate_node;
        }
        assert!(matching[body].insert(candidate));
        total_loads[candidate] = total_loads[candidate].saturating_add(1);
        if body == root_body {
            break;
        }
    }
    true
}

fn same_matter_overlap(
    body: ParliamentBody,
    candidate: &AccountId,
    selected: &BTreeMap<ParliamentBody, Vec<AccountId>>,
) -> u8 {
    let related: &[ParliamentBody] = match body {
        ParliamentBody::CoordinationCouncil => &[ParliamentBody::ReviewPanel],
        ParliamentBody::MpcCommittee | ParliamentBody::FmaCommittee => &[
            ParliamentBody::ReviewPanel,
            ParliamentBody::CoordinationCouncil,
        ],
        ParliamentBody::OversightCommittee => &[
            ParliamentBody::ReviewPanel,
            ParliamentBody::CoordinationCouncil,
            ParliamentBody::MpcCommittee,
            ParliamentBody::FmaCommittee,
        ],
        ParliamentBody::PolicyJury => &[
            ParliamentBody::ReviewPanel,
            ParliamentBody::CoordinationCouncil,
            ParliamentBody::MpcCommittee,
            ParliamentBody::FmaCommittee,
            ParliamentBody::OversightCommittee,
        ],
        ParliamentBody::ConfirmationJury => &[ParliamentBody::PolicyJury],
        ParliamentBody::RulesCommittee
        | ParliamentBody::AgendaCouncil
        | ParliamentBody::InterestPanel
        | ParliamentBody::ReviewPanel => &[],
    };
    related.iter().fold(0u8, |overlap, related_body| {
        overlap.saturating_add(u8::from(
            selected
                .get(related_body)
                .is_some_and(|members| members.contains(candidate)),
        ))
    })
}
pub(crate) fn body_committee_size(cfg: &Governance, body: ParliamentBody) -> usize {
    match body {
        ParliamentBody::RulesCommittee => cfg.rules_committee_size,
        ParliamentBody::AgendaCouncil => cfg.agenda_council_size,
        ParliamentBody::InterestPanel => cfg.interest_panel_size,
        ParliamentBody::ReviewPanel => cfg.review_panel_size,
        ParliamentBody::CoordinationCouncil => cfg.coordination_council_size,
        ParliamentBody::MpcCommittee => cfg.mpc_committee_size,
        ParliamentBody::FmaCommittee => cfg.fma_committee_size,
        ParliamentBody::OversightCommittee => cfg.oversight_committee_size,
        ParliamentBody::PolicyJury => cfg.policy_jury_size,
        ParliamentBody::ConfirmationJury => cfg.confirmation_jury_size,
    }
}
fn body_seed_domain(body: ParliamentBody) -> &'static [u8] {
    match body {
        ParliamentBody::RulesCommittee => b"gov:parliament:body:rules:v1",
        ParliamentBody::AgendaCouncil => b"gov:parliament:body:agenda:v1",
        ParliamentBody::InterestPanel => b"gov:parliament:body:interest:v1",
        ParliamentBody::ReviewPanel => b"gov:parliament:body:review:v1",
        ParliamentBody::CoordinationCouncil => b"gov:parliament:body:coordination:v1",
        ParliamentBody::MpcCommittee => b"gov:parliament:body:mpc:v1",
        ParliamentBody::FmaCommittee => b"gov:parliament:body:fma:v1",
        ParliamentBody::OversightCommittee => b"gov:parliament:body:oversight:v1",
        ParliamentBody::PolicyJury => b"gov:parliament:body:policy_jury:v1",
        ParliamentBody::ConfirmationJury => b"gov:parliament:body:confirmation_jury:v1",
    }
}
fn body_input_domain(body: ParliamentBody) -> &'static [u8] {
    match body {
        ParliamentBody::RulesCommittee => b"iroha:beacon-sortition:v1:parliament:rules|",
        ParliamentBody::AgendaCouncil => b"iroha:beacon-sortition:v1:parliament:agenda|",
        ParliamentBody::InterestPanel => b"iroha:beacon-sortition:v1:parliament:interest|",
        ParliamentBody::ReviewPanel => b"iroha:beacon-sortition:v1:parliament:review|",
        ParliamentBody::CoordinationCouncil => {
            b"iroha:beacon-sortition:v1:parliament:coordination|"
        }
        ParliamentBody::MpcCommittee => b"iroha:beacon-sortition:v1:parliament:mpc|",
        ParliamentBody::FmaCommittee => b"iroha:beacon-sortition:v1:parliament:fma|",
        ParliamentBody::OversightCommittee => b"iroha:beacon-sortition:v1:parliament:oversight|",
        ParliamentBody::PolicyJury => b"iroha:beacon-sortition:v1:parliament:policy_jury|",
        ParliamentBody::ConfirmationJury => {
            b"iroha:beacon-sortition:v1:parliament:confirmation_jury|"
        }
    }
}
fn ranked_body_candidates(
    network_id: &NetworkId,
    epoch: u64,
    beacon: &[u8; 32],
    candidates: &[AccountId],
    body: ParliamentBody,
) -> Vec<AccountId> {
    // The seed binds the network, the pulse (height and output) and the body role only.
    // Requests of different governance attempts that share a pulse, candidate snapshot, body
    // set and sizing configuration therefore receive identical rankings, and slot alignment
    // makes every request of one epoch window share one pulse.
    // TODO: open selection-policy decision (owner decision pending): binding
    // `governance_attempt_id` into this seed would remove the correlated capture across the
    // proposals of one epoch window, at the price of a proposal-multiplicity grinding
    // channel (submit many proposals, keep the favourable draw). Unchanged until decided.
    let seed = sortition::compute_seed(network_id, epoch, beacon, body_seed_domain(body));
    let mut scored: Vec<([u8; 32], AccountId)> = Vec::new();
    for account_id in candidates {
        let output = scored_output(&seed, body_input_domain(body), account_id);
        scored.push((output, account_id.clone()));
    }
    scored.sort_by(|a, b| {
        use core::cmp::Ordering;
        match b.0.cmp(&a.0) {
            Ordering::Equal => a.1.cmp(&b.1),
            other => other,
        }
    });
    scored.dedup_by(|a, b| a.1 == b.1);
    scored
        .into_iter()
        .map(|(_, account_id)| account_id)
        .collect()
}
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair};
    use iroha_data_model::{
        NetworkId, account::AccountId, block::BlockHeader, governance::types::ParliamentBody,
    };
    use std::collections::BTreeSet;
    fn mk_account(seed: u8) -> AccountId {
        let keypair = KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
            .expect("derive governance draw fixture account key");
        let (public_key, _) = keypair.into_parts();
        AccountId::new(public_key)
    }
    fn network_id(label: &[u8]) -> NetworkId {
        NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(
            label,
        )))
    }
    #[test]
    fn mk_account_uses_checked_seed_derivation() {
        let account = mk_account(1);
        let expected = AccountId::new(
            KeyPair::try_from_seed(vec![1; 32], Algorithm::Ed25519)
                .expect("derive expected governance draw fixture account key")
                .public_key()
                .clone(),
        );
        assert_eq!(account, expected);
    }
    #[test]
    fn simultaneous_primary_draw_uses_the_smallest_feasible_overlap_cap() {
        let network_id = network_id(b"body-cap-demo");
        let beacon = [0xD4; 32];
        let accounts: Vec<_> = (1..=3).map(mk_account).collect();
        let cfg = Governance {
            rules_committee_size: 2,
            agenda_council_size: 2,
            interest_panel_size: 2,
            review_panel_size: 2,
            coordination_council_size: 2,
            mpc_committee_size: 2,
            fma_committee_size: 2,
            oversight_committee_size: 2,
            policy_jury_size: 2,
            parliament_alternate_size: 0,
            ..Governance::default()
        };
        let plan = derive_body_plan(
            &cfg,
            &network_id,
            19,
            &beacon,
            &accounts,
            &PRIMARY_PARLIAMENT_BODIES_V1,
        );
        assert_eq!(plan.assignment_cap, 6);
        let mut loads: BTreeMap<AccountId, u32> = BTreeMap::new();
        for roster in plan.rosters.values() {
            assert_eq!(roster.members.len(), 2);
            for member in &roster.members {
                *loads.entry(member.clone()).or_default() += 1;
            }
        }
        assert_eq!(loads.values().copied().max(), Some(plan.assignment_cap));
        assert_eq!(loads.values().copied().min(), Some(plan.assignment_cap));
    }

    #[test]
    fn requests_sharing_pulse_snapshot_bodies_and_sizing_receive_identical_draws() {
        // The draw takes no governance-attempt input, so nothing at this level can tell two
        // attempts apart: the cross-attempt equality (two distinct attempt ids consuming one
        // pulse) is asserted where attempts exist, in
        // `governance::parliament::tests::attempts_consuming_the_same_pulse_over_the_same_snapshot_receive_identical_rosters`.
        // This test pins the inputs the draw does depend on: the plan is drawn from exactly
        // the candidate snapshot, and another pulse output or pulse height changes both the
        // per-body rankings and the plan.
        // See the TODO at the seed derivation for the open selection-policy decision.
        let network_id = network_id(b"correlated-draw-demo");
        let accounts: Vec<_> = (1..=12).map(mk_account).collect();
        let cfg = Governance {
            rules_committee_size: 3,
            policy_jury_size: 3,
            parliament_alternate_size: 2,
            ..Governance::default()
        };
        let bodies = [ParliamentBody::RulesCommittee, ParliamentBody::PolicyJury];
        let pulse = [0xC3; 32];
        let first_attempt =
            derive_attempt_body_plan_v1(&cfg, &network_id, 29, &pulse, &accounts, &bodies);
        let snapshot: BTreeSet<_> = accounts.iter().cloned().collect();
        for body in bodies {
            let ranking = ranked_body_candidates(&network_id, 29, &pulse, &accounts, body);
            assert_eq!(ranking.len(), accounts.len());
            assert_eq!(ranking.iter().cloned().collect::<BTreeSet<_>>(), snapshot);
            let roster = first_attempt.rosters.get(&body).expect("planned body");
            assert_eq!(roster.members.len(), 3);
            assert!(
                roster
                    .members
                    .iter()
                    .all(|member| snapshot.contains(member))
            );
        }

        let other_output =
            derive_attempt_body_plan_v1(&cfg, &network_id, 29, &[0xC4; 32], &accounts, &bodies);
        let other_height =
            derive_attempt_body_plan_v1(&cfg, &network_id, 32, &pulse, &accounts, &bodies);
        assert_ne!(first_attempt, other_output);
        assert_ne!(first_attempt, other_height);
        for body in bodies {
            let ranking = ranked_body_candidates(&network_id, 29, &pulse, &accounts, body);
            assert_ne!(
                ranking,
                ranked_body_candidates(&network_id, 29, &[0xC4; 32], &accounts, body)
            );
            assert_ne!(
                ranking,
                ranked_body_candidates(&network_id, 32, &pulse, &accounts, body)
            );
        }
    }

    #[test]
    fn attempt_body_plan_uses_only_snapshot_set_and_finalized_pulse() {
        let network_id = network_id(b"attempt-body-plan-demo");
        let accounts: Vec<_> = (1..=8).map(mk_account).collect();
        let mut reordered_with_duplicate = accounts.iter().rev().cloned().collect::<Vec<_>>();
        reordered_with_duplicate.push(accounts[3].clone());
        let cfg = Governance {
            rules_committee_size: 3,
            agenda_council_size: 3,
            parliament_alternate_size: 2,
            ..Governance::default()
        };
        let bodies = [
            ParliamentBody::RulesCommittee,
            ParliamentBody::AgendaCouncil,
        ];
        let expected =
            derive_attempt_body_plan_v1(&cfg, &network_id, 31, &[0xA7; 32], &accounts, &bodies);
        let reordered = derive_attempt_body_plan_v1(
            &cfg,
            &network_id,
            31,
            &[0xA7; 32],
            &reordered_with_duplicate,
            &bodies,
        );
        assert!(
            expected
                .rosters
                .values()
                .all(|roster| roster.pulse_height == 31)
        );
        assert_eq!(expected, reordered);
        assert_ne!(
            expected,
            derive_attempt_body_plan_v1(&cfg, &network_id, 32, &[0xA8; 32], &accounts, &bodies,)
        );
    }

    #[test]
    fn enough_citizens_make_all_primary_assignments_disjoint() {
        let network_id = network_id(b"body-disjoint-demo");
        let beacon = [0xE5; 32];
        let accounts: Vec<_> = (1..=18).map(mk_account).collect();
        let cfg = Governance {
            rules_committee_size: 2,
            agenda_council_size: 2,
            interest_panel_size: 2,
            review_panel_size: 2,
            coordination_council_size: 2,
            mpc_committee_size: 2,
            fma_committee_size: 2,
            oversight_committee_size: 2,
            policy_jury_size: 2,
            parliament_alternate_size: 0,
            ..Governance::default()
        };
        let plan = derive_body_plan(
            &cfg,
            &network_id,
            20,
            &beacon,
            &accounts,
            &PRIMARY_PARLIAMENT_BODIES_V1,
        );
        assert_eq!(plan.assignment_cap, 1);
        let members: Vec<_> = plan
            .rosters
            .values()
            .flat_map(|roster| roster.members.iter())
            .collect();
        let unique: BTreeSet<_> = members.iter().copied().collect();
        assert_eq!(members.len(), unique.len());
    }

    #[test]
    fn alternate_matching_reassigns_an_earlier_reservation() {
        let ranked = vec![vec![0, 1], vec![0, 1]];
        let primary = vec![BTreeSet::new(), BTreeSet::from([1])];
        let capacities = [1, 1];
        let mut loads = [0, 0];
        let mut matching = vec![BTreeSet::new(), BTreeSet::new()];

        assert!(augment_alternate_matching(
            0,
            &ranked,
            &primary,
            &capacities,
            &mut loads,
            &mut matching,
        ));
        assert_eq!(matching[0], BTreeSet::from([0]));
        assert!(augment_alternate_matching(
            1,
            &ranked,
            &primary,
            &capacities,
            &mut loads,
            &mut matching,
        ));
        assert_eq!(matching[0], BTreeSet::from([1]));
        assert_eq!(matching[1], BTreeSet::from([0]));
        assert_eq!(loads, [1, 1]);
    }

    #[test]
    fn exact_primary_fill_reserves_ranked_alternates_within_the_persisted_cap() {
        let network_id = network_id(b"body-alternate-cap-demo");
        let beacon = [0xE6; 32];
        let accounts: Vec<_> = (1..=18).map(mk_account).collect();
        let cfg = Governance {
            rules_committee_size: 2,
            agenda_council_size: 2,
            interest_panel_size: 2,
            review_panel_size: 2,
            coordination_council_size: 2,
            mpc_committee_size: 2,
            fma_committee_size: 2,
            oversight_committee_size: 2,
            policy_jury_size: 2,
            parliament_alternate_size: 2,
            ..Governance::default()
        };
        let plan = derive_body_plan(
            &cfg,
            &network_id,
            21,
            &beacon,
            &accounts,
            &PRIMARY_PARLIAMENT_BODIES_V1,
        );
        let repeated = derive_body_plan(
            &cfg,
            &network_id,
            21,
            &beacon,
            &accounts,
            &PRIMARY_PARLIAMENT_BODIES_V1,
        );

        assert_eq!(plan, repeated);
        assert_eq!(plan.assignment_cap, 2);
        let mut invitation_loads = BTreeMap::<AccountId, u32>::new();
        for roster in plan.rosters.values() {
            assert_eq!(roster.members.len(), 2);
            assert_eq!(roster.alternates.len(), 2);
            let invited = roster
                .members
                .iter()
                .chain(&roster.alternates)
                .collect::<BTreeSet<_>>();
            assert_eq!(invited.len(), 4);
            for invited in roster.members.iter().chain(&roster.alternates) {
                *invitation_loads.entry(invited.clone()).or_default() += 1;
            }
        }
        assert_eq!(invitation_loads.len(), accounts.len());
        assert!(
            invitation_loads
                .values()
                .all(|load| *load <= plan.assignment_cap)
        );
    }
}
