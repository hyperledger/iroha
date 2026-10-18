//! Deterministic sample witnesses (the M7 witness distributions of
//! `m7_step`, extended to the G1 core and the controls) and the relation
//! mutations, for tests and measurements.
//!
//! [`sample_witness`] is a pure function of the seed (a `SplitMix64` stream),
//! so every test and measurement can name its witness by `(seed, relation,
//! mutation)`. The values follow M7: a balance near `2^100` (or at the
//! mutation's boundary), amounts below `2^56`, fees below `2^24`, `u64`
//! sequence and ordinals, policy epochs from 256 and accepted times in a
//! 600-second window above the floor. A `sigma_send` takes a lineage
//! `burned_total` below `2^49` that is at least the core's. The core's
//! enabled-controls mask is the relation's.
//!
//! A relation with a control gets consistent control state:
//!
//! - attestation lease: an expiry after the accepted upper time;
//! - quotas: consecutive daily windows around the accepted interval and one
//!   monthly window covering it, their window-tree root in the core, a
//!   usage map holding the monthly window's usage (so its charge is an
//!   update) and an earlier day's (the touched days are insertions), and
//!   the segments and charges of the Send. An even seed puts the interval
//!   inside one day, an odd seed across a day boundary (two daily charges).

use iroha_pasta::{PastaField, poseidon::PoseidonField};
use iroha_plonk_gadgets::statement::StepRelation;

use crate::{
    controls::{QuotaCharge, QuotaWitness, WindowSegment, WindowSlot},
    tree::{QuotaUsageTree, QuotaWindow, QuotaWindowTree, WINDOW_DAILY, WINDOW_MONTHLY},
    witness::{
        CONTROL_ATTESTATION_LEASE, CONTROL_QUOTAS, Controls, CoreState, Identity, LIFECYCLE_ACTIVE,
        LineageInputs, MapRoots, ReceiveInputs, RequestTerms, SendInputs, SigmaRelation, StateRest,
        StateV1, StepInputs, StepWitness,
    },
};

/// A relation mutation (each must be rejected by the relation it targets;
/// the other relations stay honest).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Mutation {
    /// The honest witness.
    #[default]
    None,
    /// The balance is one below `amount + fee` (an overdraft for
    /// `sigma_send`).
    Overdraft,
    /// The balance is `2^128 - amount`, so `balance + amount = 2^128` (an
    /// overflow for `sigma_recv`).
    Overflow,
    /// `sigma_send`: the Request policy epoch is one newer than the
    /// payer's.
    StaleEpoch,
    /// `sigma_send`: the accepted lower time (and the Request time) is one
    /// below the floor.
    EarlyTime,
    /// `sigma_send`: the balance covers `amount + fee` exactly, but the
    /// lineage `burned_total` (at least 1) leaves less spendable.
    Burned,
    /// The counterparty wallet is the wallet's own (payer = receiver).
    SelfPayment,
    /// `sigma_send`: the core's enabled-controls mask differs from the
    /// relation's in the quota bit; `sigma_recv`: the core's mask has an
    /// undefined bit.
    ControlsMismatch,
    /// `sigma_send` with the lease control: the lease expires at the
    /// accepted upper time.
    LeaseExpired,
    /// `sigma_send` with the quota control: the first touched daily window's
    /// limit is one below the gross debit.
    QuotaExceeded,
    /// `sigma_send` with the quota control: the monthly window ended ten
    /// days before the accepted interval, so a defined kind is untouched.
    QuotaUntouched,
}

impl Mutation {
    /// Every mutation, honest first.
    pub const ALL: [Self; 11] = [
        Self::None,
        Self::Overdraft,
        Self::Overflow,
        Self::StaleEpoch,
        Self::EarlyTime,
        Self::Burned,
        Self::SelfPayment,
        Self::ControlsMismatch,
        Self::LeaseExpired,
        Self::QuotaExceeded,
        Self::QuotaUntouched,
    ];
}

/// The `SplitMix64` stream (Steele, Lea and Flood), the M7 sampler.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SplitMix64(u64);

impl SplitMix64 {
    /// A stream seeded with `seed`.
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self(seed)
    }

    /// The next word.
    pub const fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// The next 128-bit value.
    pub const fn next_u128(&mut self) -> u128 {
        let high = self.next_u64() as u128;
        let low = self.next_u64() as u128;
        (high << 64) | low
    }

    /// The next 32 bytes.
    pub fn next_bytes(&mut self) -> [u8; 32] {
        let mut bytes = [0_u8; 32];
        for chunk in bytes.chunks_exact_mut(8) {
            chunk.copy_from_slice(&self.next_u64().to_le_bytes());
        }
        bytes
    }

    /// Canonical field bytes below both Pasta moduli, for carried Poseidon digests.
    pub fn next_digest(&mut self) -> [u8; 32] {
        let mut bytes = self.next_bytes();
        bytes[31] &= 0x3f;
        bytes
    }

    /// The next field element (a 256-bit word reduced modulo the field).
    pub fn next_field<F: PastaField>(&mut self) -> F {
        F::from_raw_reduced([
            self.next_u64(),
            self.next_u64(),
            self.next_u64(),
            self.next_u64(),
        ])
    }
}

/// The relation identity of the sample witnesses (a scheme-level value).
pub const SAMPLE_RELATION_ID: [u8; 32] = *b"kagemusha-sample-relation-id-v1!";

/// One day in milliseconds.
pub const DAY_MS: u64 = 86_400_000;

/// The quota state of a sample Send over `[lower, upper]` with gross
/// `gross`: the windows root, the usage root before and the witness.
fn sample_quota<F: PoseidonField>(
    rng: &mut SplitMix64,
    seed: u64,
    lower: u64,
    upper: u64,
    gross: u128,
    mutation: Mutation,
) -> (F, F, QuotaWitness<F>) {
    // The start of the first touched day: a day boundary inside `(lower,
    // upper]` for an odd seed, else a day that holds the whole interval.
    let boundary = lower + 1 + rng.next_u64() % (upper - lower).max(1);
    let inside = lower.saturating_sub(rng.next_u64() % (DAY_MS - (upper - lower) - 1));
    let first = if seed & 1 == 1 {
        boundary.checked_sub(DAY_MS).unwrap_or(inside)
    } else {
        inside
    };
    let slack = u128::from(rng.next_u64() >> 40);
    let daily_limit = |used: u128| used + gross + slack;
    let mut windows = Vec::new();
    if first >= DAY_MS {
        windows.push(QuotaWindow {
            kind: WINDOW_DAILY,
            start_ms: first - DAY_MS,
            end_ms: first,
            limit: daily_limit(0),
        });
    }
    for day in 0..3 {
        windows.push(QuotaWindow {
            kind: WINDOW_DAILY,
            start_ms: first + day * DAY_MS,
            end_ms: first + (day + 1) * DAY_MS,
            limit: if mutation == Mutation::QuotaExceeded && day == 0 {
                gross - 1
            } else {
                daily_limit(0)
            },
        });
    }
    let monthly_used = u128::from(rng.next_u64() >> 44);
    let monthly = if mutation == Mutation::QuotaUntouched {
        QuotaWindow {
            kind: WINDOW_MONTHLY,
            start_ms: lower.saturating_sub(40 * DAY_MS),
            end_ms: lower.saturating_sub(10 * DAY_MS).max(1),
            limit: monthly_used + gross + slack,
        }
    } else {
        QuotaWindow {
            kind: WINDOW_MONTHLY,
            start_ms: lower.saturating_sub(10 * DAY_MS),
            end_ms: lower + 20 * DAY_MS,
            limit: monthly_used + gross + slack,
        }
    };
    windows.push(monthly);
    let tree = QuotaWindowTree::new(&windows).unwrap_or_else(|| unreachable!("sorted windows"));
    let daily_count = windows.len() - 1;
    let touched_first = daily_count - 3;
    // Each usage leaf exists at its window slot, even before the first charge.
    let mut usage = QuotaUsageTree::<F>::new(&tree);
    if touched_first == 1 {
        let _ = usage.set(0, 3);
    }
    let _ = usage.set(daily_count, monthly_used);
    let usage_root = usage.root();
    let slot = |index: usize| WindowSlot {
        window: tree.slot(index),
        siblings: tree.siblings(index),
    };
    let segment = |base: usize| WindowSegment {
        base: u8::try_from(base).unwrap_or_else(|_| unreachable!("a base below 64")),
        slots: core::array::from_fn(|position| {
            (base + position)
                .checked_sub(1)
                .map_or_else(WindowSlot::unused, slot)
        }),
    };
    let segments = [segment(touched_first), segment(daily_count)];
    // The charges, in window order.
    let mut charges = [QuotaCharge::unused(); 4];
    for (charge, index) in [(0, touched_first), (1, touched_first + 1), (2, daily_count)] {
        let window = windows[index];
        if !window.touches(lower, upper) {
            continue;
        }
        let used = if index == daily_count {
            monthly_used
        } else {
            0
        };
        charges[charge] = QuotaCharge {
            slot: u8::try_from(index).unwrap_or(0),
            siblings: usage
                .siblings(index)
                .unwrap_or([F::ZERO; crate::tree::QUOTA_DEPTH]),
            used,
        };
        let _ = usage.set(index, used + gross);
    }
    (tree.root(), usage_root, QuotaWitness { segments, charges })
}

/// The sample witness of `relation` for `seed`, with `mutation` applied.
#[must_use]
#[allow(
    clippy::too_many_lines,
    reason = "one straight-line sampler of every witness field, in core order"
)]
pub fn sample_witness<F: PoseidonField>(
    seed: u64,
    relation: SigmaRelation,
    mutation: Mutation,
) -> StepWitness<F> {
    let mut rng = SplitMix64::new(seed ^ 0x6b67_6d73_6967_6d61);
    let amount = u128::from(rng.next_u64() >> 8).saturating_add(1);
    let fee = u128::from(rng.next_u64() >> 40);
    let core_burned = u128::from(rng.next_u64() >> 17);
    let lineage_burned = match mutation {
        Mutation::Burned => core_burned.saturating_add(1),
        _ => core_burned.saturating_add(u128::from(rng.next_u64() >> 17)),
    };
    let debit = amount.saturating_add(fee);
    let balance = match mutation {
        Mutation::Overdraft => debit.saturating_sub(1),
        Mutation::Burned => debit,
        Mutation::Overflow => (u128::MAX - amount).saturating_add(1),
        _ => (1_u128 << 100) | (rng.next_u128() >> 30),
    };
    let policy_epoch = (rng.next_u64() >> 24).saturating_add(256);
    let accepted_time_floor = (rng.next_u64() >> 24).saturating_add(1);
    let identity = Identity {
        scheme_id: rng.next_bytes(),
        asset_digest: rng.next_bytes(),
        wallet_id: rng.next_bytes(),
        credential_digest: rng.next_digest(),
    };
    let request_policy_epoch = match mutation {
        Mutation::StaleEpoch => policy_epoch.saturating_add(1),
        _ => policy_epoch.saturating_sub(rng.next_u64() & 0xff),
    };
    let request_time = match mutation {
        // Below the floor, so the early accepted time breaks only the floor.
        Mutation::EarlyTime => accepted_time_floor.saturating_sub(1),
        _ => accepted_time_floor.saturating_add(rng.next_u64() & 0xffff),
    };
    let accepted_lower = match mutation {
        Mutation::EarlyTime => accepted_time_floor.saturating_sub(1),
        _ => request_time.saturating_add(rng.next_u64() & 0xffff),
    };
    let accepted_upper = accepted_lower.saturating_add(600_000);
    let enabled = match (mutation, relation.step()) {
        (Mutation::ControlsMismatch, StepRelation::Send) => relation.enabled_controls() ^ 1,
        // Receive has no relation mask; an undefined core bit is the mismatch.
        (Mutation::ControlsMismatch, StepRelation::Receive) => 1 << 2,
        _ => relation.enabled_controls(),
    };
    let lease_expires_at_ms = match mutation {
        Mutation::LeaseExpired => accepted_upper,
        _ => accepted_upper.saturating_add(1 + (rng.next_u64() >> 24)),
    };
    let mut core: CoreState<F> = CoreState {
        lifecycle: LIFECYCLE_ACTIVE,
        identity,
        balance,
        burned_total: core_burned,
        sequence: u128::from(rng.next_u64()),
        next_send: u128::from(rng.next_u64()),
        next_load: u128::from(rng.next_u64()),
        next_redeem: u128::from(rng.next_u64() >> 32),
        send_chain: rng.next_field(),
        recv_chain: rng.next_field(),
        roots: MapRoots {
            consumed_credit: rng.next_field(),
            pending_outgoing: rng.next_field(),
            load_redeem_recovery: rng.next_field(),
            fee_claim_recovery: rng.next_field(),
            quota_usage: rng.next_field(),
        },
        controls: Controls {
            enabled,
            quota_windows_root: rng.next_field(),
            quota_share_expires_at_ms: accepted_upper.saturating_add(DAY_MS),
            time_anchor_max_response_ms: 600_000,
            lease_expires_at_ms,
        },
        policy_epoch,
        accepted_time_floor_ms: accepted_time_floor,
        state_nonce: rng.next_field(),
    };
    let rest = StateRest {
        permitted_controls: u32::try_from(rng.next_u64() & 3).unwrap_or(0),
        scheme_policy: rng.next_digest(),
        fee_schedule: rng.next_digest(),
        quota_share: rng.next_digest(),
        quota_share_id: rng.next_u64() >> 32,
        time_anchor: rng.next_digest(),
    };
    let request = RequestTerms {
        amount,
        fee,
        fee_schedule: rng.next_digest(),
        policy_epoch: request_policy_epoch,
        scheme_policy: rng.next_digest(),
        request_time,
        certificates: rng.next_digest(),
        nonce: rng.next_bytes(),
    };
    let counterparty = if mutation == Mutation::SelfPayment {
        identity.wallet_id
    } else {
        rng.next_bytes()
    };
    let own_account = rng.next_bytes();
    let counterparty_account = rng.next_bytes();
    let quota = if relation.enforces(CONTROL_QUOTAS) && relation.step() == StepRelation::Send {
        let (windows_root, usage_root, quota) = sample_quota(
            &mut rng,
            seed,
            accepted_lower,
            accepted_upper,
            debit,
            mutation,
        );
        core.controls.quota_windows_root = windows_root;
        core.roots.quota_usage = usage_root;
        quota
    } else {
        QuotaWitness::unused()
    };
    debug_assert!(
        relation.enforces(CONTROL_ATTESTATION_LEASE) || core.controls.lease_expires_at_ms != 0
    );
    let inputs = match relation.step() {
        StepRelation::Send => StepInputs::Send(Box::new(SendInputs {
            payer_account_digest: own_account,
            receiver_wallet: counterparty,
            receiver_account_digest: counterparty_account,
            receiver_credential_digest: rng.next_digest(),
            request,
            // A stand-in Request digest derived from the nonce.
            request_digest: rng.next_digest(),
            accepted_lower,
            accepted_upper,
            lineage: LineageInputs {
                burned_total: lineage_burned,
                pending_outgoing_root: rng.next_field(),
            },
            successor_pending_outgoing: rng.next_field(),
            successor_fee_claim: rng.next_field(),
            quota: Box::new(quota),
        })),
        StepRelation::Receive => StepInputs::Receive(Box::new(ReceiveInputs {
            payer_wallet: counterparty,
            payer_account_digest: counterparty_account,
            receiver_account_digest: own_account,
            send_ordinal: u128::from(rng.next_u64()),
            // The Request was quoted under the receiver's current credential.
            receiver_credential_digest: identity.credential_digest,
            request,
            successor_consumed_credit: rng.next_field(),
        })),
    };
    StepWitness {
        relation_id: SAMPLE_RELATION_ID,
        predecessor: StateV1 { core, rest },
        successor_nonce: rng.next_field(),
        inputs,
    }
}

#[cfg(test)]
mod tests {
    use iroha_pasta::{Fp, Fq};

    use super::*;
    use crate::witness::{CONTROLS_DEFINED, Violation};

    #[test]
    fn splitmix_matches_the_reference_stream() {
        // Reference values of SplitMix64 seeded with 0 (Vigna's C code).
        let mut rng = SplitMix64::new(0);
        assert_eq!(rng.next_u64(), 0xe220_a839_7b1d_cdaf);
        assert_eq!(rng.next_u64(), 0x6e78_9e6a_a1b9_65f4);
        let mut rng = SplitMix64::new(0);
        assert_eq!(rng.next_u128(), 0xe220_a839_7b1d_cdaf_6e78_9e6a_a1b9_65f4);
        let bytes = SplitMix64::new(0).next_bytes();
        assert_eq!(bytes[..8], 0xe220_a839_7b1d_cdaf_u64.to_le_bytes());
        let field: Fq = SplitMix64::new(0).next_field();
        assert_eq!(
            field,
            Fq::from_raw_reduced([
                0xe220_a839_7b1d_cdaf,
                0x6e78_9e6a_a1b9_65f4,
                0x06c4_5d18_8009_454f,
                0xf88b_b8a8_724c_81ec,
            ])
        );
    }

    /// The relations the samples cover.
    const RELATIONS: [SigmaRelation; 5] = [
        SigmaRelation::SEND,
        SigmaRelation::send(CONTROL_ATTESTATION_LEASE),
        SigmaRelation::send(CONTROL_QUOTAS),
        SigmaRelation::send(CONTROLS_DEFINED),
        SigmaRelation::RECEIVE,
    ];

    #[test]
    fn samples_are_deterministic_and_honest() {
        for relation in RELATIONS {
            for seed in 0..8 {
                let witness = sample_witness::<Fp>(seed, relation, Mutation::None);
                assert_eq!(
                    witness,
                    sample_witness::<Fp>(seed, relation, Mutation::None)
                );
                assert_eq!(witness.relation(), relation.step());
                assert_eq!(witness.relation_id, SAMPLE_RELATION_ID);
                assert!(witness.evaluate(relation).is_honest(), "seed {seed}");
                let controls = witness.predecessor.core.controls;
                assert_eq!(controls.enabled, relation.enabled_controls());
            }
        }
        assert_ne!(
            sample_witness::<Fp>(1, SigmaRelation::SEND, Mutation::None),
            sample_witness::<Fp>(2, SigmaRelation::SEND, Mutation::None)
        );
    }

    #[test]
    fn mutations_hit_their_boundaries() {
        let send = |mutation| sample_witness::<Fp>(4, SigmaRelation::SEND, mutation);
        let StepInputs::Send(inputs) = send(Mutation::Overdraft).inputs else {
            panic!("send");
        };
        assert_eq!(
            send(Mutation::Overdraft).predecessor.core.balance + 1,
            inputs.request.amount + inputs.request.fee
        );
        // Burned: the balance alone covers the debit, the lineage
        // burned_total does not leave enough.
        let burned = send(Mutation::Burned);
        let StepInputs::Send(inputs) = &burned.inputs else {
            panic!("send");
        };
        assert_eq!(
            burned.predecessor.core.balance,
            inputs.request.amount + inputs.request.fee
        );
        assert!(inputs.lineage.burned_total >= 1);
        assert!(inputs.lineage.burned_total >= burned.predecessor.core.burned_total);
        let receive = sample_witness::<Fp>(4, SigmaRelation::RECEIVE, Mutation::Overflow);
        assert_eq!(
            receive
                .predecessor
                .core
                .balance
                .checked_add(receive.inputs.amount() - 1),
            Some(u128::MAX)
        );
        // The send-only mutations leave a receive honest.
        for mutation in [
            Mutation::Overdraft,
            Mutation::StaleEpoch,
            Mutation::EarlyTime,
            Mutation::Burned,
        ] {
            let receive = sample_witness::<Fp>(4, SigmaRelation::RECEIVE, mutation);
            assert!(
                receive.evaluate(SigmaRelation::RECEIVE).is_honest(),
                "{mutation:?}"
            );
        }
        // A balance of `2^128 - amount` affords a send.
        assert!(
            sample_witness::<Fp>(4, SigmaRelation::SEND, Mutation::Overflow)
                .evaluate(SigmaRelation::SEND)
                .is_honest()
        );
        assert_eq!(
            send(Mutation::Overdraft)
                .evaluate(SigmaRelation::SEND)
                .violations,
            vec![Violation::Overdraft]
        );
        for relation in RELATIONS {
            assert_eq!(
                sample_witness::<Fp>(4, relation, Mutation::SelfPayment)
                    .evaluate(relation)
                    .violations,
                vec![Violation::SelfPayment]
            );
        }
        assert_eq!(Mutation::ALL.len(), 11);
        assert_eq!(Mutation::default(), Mutation::None);
    }
}
