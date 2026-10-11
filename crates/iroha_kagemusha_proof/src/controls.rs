//! The regulatory controls the step relations enforce (proposal sections
//! 3.2 and 7; wire record `specs/kagemusha_wallet_wire_v1.md` sections 3.3
//! and 3.4): their witnesses and their native reference evaluation, which
//! computes exactly the field values and verdicts of the circuit
//! (`crate::control_circuit`).
//!
//! # Blacklist
//!
//! A Send enforces the payer's current committed list while its BLACKLIST
//! control is enabled and it holds a list (`blacklist_version != 0`).
//! A Receive enforces the receiver's list recorded in the Request, with
//! its relation selected by that recorded version. Current list or mask
//! changes do not invalidate an already issued Request. Absence is one gap
//! opening ([`BlacklistGap`]) with `lower < account < upper` in limb order
//! against the corresponding root. Send also checks maximum list age.
//!
//! # Attestation lease
//!
//! With the lease control, `sigma_send` requires the accepted upper time
//! below the lease expiry (`U < lease_expires_at_ms`).
//!
//! # Quotas
//!
//! With the quota control, `sigma_send` charges the gross `amount + fee`
//! against every window of the head-committed quota-window tree that the
//! accepted interval `[L, U]` touches (`start <= U` and `L < end`), requires
//! `used + gross <= limit` in each and a touched window of every defined
//! kind, and updates the fixed 64-slot quota-usage array. Each usage leaf
//! is aligned to the same slot as its window and commits that window's
//! kind and start, including zero usage for initially unused windows.
//! Charges run in window order (Daily before Monthly, ascending start).
//!
//! Per window kind the witness is a [`WindowSegment`]: four consecutive
//! slots of the window tree, where slot `-1` and slots from 64 are virtual
//! boundaries. Positions 1 and 2 are the charged candidates; position 0
//! shows that no earlier window of the kind is touched (a lower kind, the
//! start boundary, or a window of the kind that ends at or before `L`), and
//! position 3 that no later one is (a higher kind, an empty slot, the end
//! boundary, or a window of the kind that starts after `U`). Because the
//! committed tree is a valid signed share (windows sorted by `(kind,
//! start)`, non-overlapping per kind, then empty slots), the charged set is
//! exactly the touched set. A kind with no window is shown by position 0
//! below it and position 1 above it.
//!
//! At most [`QUOTA_CHARGES_PER_KIND`] windows of one kind can be touched by
//! one Send. The core's authenticated maximum response span bounds `U - L`
//! (B8), and installed windows are longer than that span. The core also
//! authenticates the quota-share expiry, enforced as `U < expires_at_ms`
//! (B7). Those two rules are checked by `crate::witness` and
//! `crate::relation` alongside the other Send arithmetic.

use iroha_pasta::poseidon::PoseidonField;

use crate::tree::{
    BlacklistGap, QUOTA_DEPTH, QUOTA_NODE_DOMAIN, QUOTA_USAGE_NODE_DOMAIN, QuotaWindow,
    WINDOW_DAILY, WINDOW_KINDS, WINDOW_MONTHLY, path_root,
};

/// Positions of a window segment.
pub const SEGMENT_POSITIONS: usize = 4;
/// The most windows of one kind a Send can charge.
pub const QUOTA_CHARGES_PER_KIND: usize = 2;
/// Quota charges of a Send: two per window kind, in window order.
pub const QUOTA_CHARGES: usize = QUOTA_CHARGES_PER_KIND * WINDOW_KINDS.len();
/// The largest segment base: position 0 at slot 63.
pub const SEGMENT_BASE_MAX: u8 = 64;

/// One opened slot of the quota-window tree: the window (or the empty slot)
/// and its six siblings. A virtual position's slot is ignored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WindowSlot<F> {
    /// The window at the slot.
    pub window: QuotaWindow,
    /// The siblings, height 0 first.
    pub siblings: [F; QUOTA_DEPTH],
}

impl<F: PoseidonField> WindowSlot<F> {
    /// An unused slot (all zero).
    #[must_use]
    pub fn unused() -> Self {
        Self {
            window: QuotaWindow::EMPTY,
            siblings: [F::ZERO; QUOTA_DEPTH],
        }
    }

    /// The root this slot opening recomputes at `slot`.
    #[must_use]
    pub fn root(&self, slot: u64) -> F {
        path_root(QUOTA_NODE_DOMAIN, self.window.leaf(), slot, &self.siblings)
    }
}

/// Four consecutive slots `base - 1 ..= base + 2` of the quota-window tree
/// for one window kind; slot `-1` and slots from 64 are virtual.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WindowSegment<F> {
    /// The slot of position 1 (`0..=64`); position `i` is slot `base - 1 +
    /// i`.
    pub base: u8,
    /// The opened slots, position 0 first.
    pub slots: [WindowSlot<F>; SEGMENT_POSITIONS],
}

impl<F: PoseidonField> WindowSegment<F> {
    /// An unused segment.
    #[must_use]
    pub fn unused() -> Self {
        Self {
            base: 0,
            slots: [WindowSlot::unused(); SEGMENT_POSITIONS],
        }
    }

    /// Whether position `position` is a real slot (as the circuit derives
    /// it from the base: `base != 0`, `base != 64`, `base < 63`, `base <
    /// 62`).
    #[must_use]
    pub const fn present(&self, position: usize) -> bool {
        match position {
            0 => self.base != 0,
            1 => self.base != SEGMENT_BASE_MAX,
            2 => self.base < SEGMENT_BASE_MAX - 1,
            _ => self.base < SEGMENT_BASE_MAX - 2,
        }
    }

    /// The slot of a present position (`base - 1 + position`), else 0.
    #[must_use]
    pub fn slot(&self, position: usize) -> u64 {
        if self.present(position) {
            (u64::from(self.base) + position as u64).saturating_sub(1)
        } else {
            0
        }
    }
}

/// One quota charge: the aligned usage-array opening and prior usage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuotaCharge<F> {
    /// Array slot, equal to the charged window slot.
    pub slot: u8,
    /// Siblings against the running usage root.
    pub siblings: [F; QUOTA_DEPTH],
    /// The usage before the charge.
    pub used: u128,
}

impl<F: PoseidonField> QuotaCharge<F> {
    /// A charge that is not taken (all zero).
    #[must_use]
    pub fn unused() -> Self {
        Self {
            slot: 0,
            siblings: [F::ZERO; QUOTA_DEPTH],
            used: 0,
        }
    }
}

/// The quota witness of a `sigma_send`: one segment per window kind and
/// the four charge candidates (Daily positions 1 and 2, then Monthly).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuotaWitness<F> {
    /// The Daily and Monthly segments.
    pub segments: [WindowSegment<F>; 2],
    /// The charge candidates, in window order.
    pub charges: [QuotaCharge<F>; QUOTA_CHARGES],
}

impl<F: PoseidonField> QuotaWitness<F> {
    /// The witness of a relation without the quota control.
    #[must_use]
    pub fn unused() -> Self {
        Self {
            segments: [WindowSegment::unused(); 2],
            charges: [QuotaCharge::unused(); QUOTA_CHARGES],
        }
    }
}

/// Why the controls reject a witness (mapped onto `crate::Violation`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ControlViolation {
    /// The gap opening does not prove the counterparty absent from the
    /// committed list.
    BlacklistListed,
    /// The accepted upper time reached the lease expiry.
    LeaseExpired,
    /// A segment's base or a window opening is invalid.
    QuotaWindowOpening,
    /// A segment does not show that no touched window lies outside it.
    QuotaWindowSkipped,
    /// A window kind the share defines has no touched window.
    QuotaKindUntouched,
    /// An aligned usage-array opening or update does not verify.
    QuotaUsageOpening,
    /// A touched window's usage exceeds its limit (or overflows).
    QuotaExceeded,
}

/// Whether `gap` shows `account` absent from the list `root`, under an
/// enforced list (`version != 0`); always true otherwise.
#[must_use]
pub fn blacklist_holds<F: PoseidonField>(
    version: u64,
    root: &F,
    gap: &BlacklistGap<F>,
    account: &[u8; 32],
) -> bool {
    version == 0 || gap.proves_absent(root, account)
}

/// The facts the circuit derives about one segment position (one bit
/// each, as in circuit).
#[derive(Clone, Copy, Debug)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "the five bits the circuit derives per position, mirrored one to one"
)]
struct PositionFacts {
    present: bool,
    /// `present` and kind 1 / kind 2 / the empty slot.
    kind1: bool,
    kind2: bool,
    empty: bool,
    /// `present`, of the segment's kind, and touched.
    touched: bool,
}

/// The result of the quota rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuotaOutcome<F> {
    /// The quota-usage root after the charges (the circuit's value, also
    /// for a violating witness).
    pub usage_root: F,
    /// The rules the witness breaks.
    pub violations: Vec<ControlViolation>,
}

/// The values of the Send the quota rule reads.
#[derive(Clone, Copy, Debug)]
pub struct QuotaSend<F> {
    /// The committed quota-window root.
    pub windows_root: F,
    /// The committed quota-usage root.
    pub usage_root: F,
    /// The accepted lower time `L`.
    pub lower: u64,
    /// The accepted upper time `U`.
    pub upper: u64,
    /// The gross `amount + fee` as the circuit's field sum.
    pub gross: F,
    /// The gross as an integer (`None` when `amount + fee` overflows).
    pub gross_integer: Option<u128>,
}

/// Whether a field value is below `2^bits` (`bits < 256`).
#[cfg(test)]
fn fits<F: PoseidonField>(value: &F, bits: usize) -> bool {
    let limbs = value.to_canonical_limbs();
    limbs.iter().enumerate().all(|(index, limb)| {
        let low = index * 64;
        if low >= bits {
            *limb == 0
        } else if low + 64 <= bits {
            true
        } else {
            limb >> (bits - low) == 0
        }
    })
}

/// The quota rule of a `sigma_send` (native reference of the circuit).
#[must_use]
pub fn evaluate_quota<F: PoseidonField>(
    witness: &QuotaWitness<F>,
    send: &QuotaSend<F>,
) -> QuotaOutcome<F> {
    let mut violations = Vec::new();
    let mut root = send.usage_root;
    for (segment_index, (segment, kind)) in witness.segments.iter().zip(WINDOW_KINDS).enumerate() {
        if segment.base > SEGMENT_BASE_MAX {
            violations.push(ControlViolation::QuotaWindowOpening);
        }
        let facts: [PositionFacts; SEGMENT_POSITIONS] = core::array::from_fn(|position| {
            let present = segment.present(position);
            let slot = &segment.slots[position];
            let window = &slot.window;
            // The kind range is checked at every position, the opening only
            // at a present one.
            if window.kind > WINDOW_MONTHLY
                || (present && slot.root(segment.slot(position)) != send.windows_root)
            {
                violations.push(ControlViolation::QuotaWindowOpening);
            }
            PositionFacts {
                present,
                kind1: present && window.kind == WINDOW_DAILY,
                kind2: present && window.kind == WINDOW_MONTHLY,
                empty: present && window.kind == 0,
                touched: present && window.kind == kind && window.touches(send.lower, send.upper),
            }
        });
        let [first, second, _, last] = facts;
        // Position 0: below the kind, or of the kind and ended by `L`.
        let below = if kind == WINDOW_DAILY {
            !first.present
        } else {
            !first.present || first.kind1
        };
        let first_window = segment.slots[0].window;
        let first_of_kind = if kind == WINDOW_DAILY {
            first.kind1
        } else {
            first.kind2
        };
        let pre = below || (first_of_kind && first_window.end_ms <= send.lower);
        // Position 3: above the kind, or of the kind and starting after `U`.
        let above = |facts: &PositionFacts| {
            let after = !facts.present;
            if kind == WINDOW_DAILY {
                facts.kind2 || facts.empty || after
            } else {
                facts.empty || after
            }
        };
        let last_window = segment.slots[3].window;
        let last_of_kind = if kind == WINDOW_DAILY {
            last.kind1
        } else {
            last.kind2
        };
        let post = above(&last) || (last_of_kind && last_window.start_ms > send.upper);
        if !(pre && post) {
            violations.push(ControlViolation::QuotaWindowSkipped);
        }
        let covered = second.touched || facts[2].touched || (below && above(&second));
        if !covered {
            violations.push(ControlViolation::QuotaKindUntouched);
        }
        // Positions 1 and 2 are the charge candidates, in window order.
        let candidates = facts.iter().zip(&segment.slots).skip(1);
        let charges = witness.charges[segment_index * QUOTA_CHARGES_PER_KIND..]
            .iter()
            .take(QUOTA_CHARGES_PER_KIND);
        for (offset, ((fact, slot), charge)) in candidates.zip(charges).enumerate() {
            let window = QuotaWindow {
                kind,
                ..slot.window
            };
            let (next_root, charge_violations) = evaluate_charge(
                charge,
                &window,
                segment.slot(offset + 1),
                fact.touched,
                root,
                send,
            );
            root = next_root;
            violations.extend(charge_violations);
        }
    }
    violations.sort_unstable();
    violations.dedup();
    QuotaOutcome {
        usage_root: root,
        violations,
    }
}

/// One charge of the window `window` (with the segment's kind) against the
/// usage root `root`, taken iff `taken`: the root after it and its
/// violations.
fn evaluate_charge<F: PoseidonField>(
    charge: &QuotaCharge<F>,
    window: &QuotaWindow,
    slot: u64,
    taken: bool,
    root: F,
    send: &QuotaSend<F>,
) -> (F, Vec<ControlViolation>) {
    let mut violations = Vec::new();
    let used_before = F::from_u128(charge.used);
    let used_after = used_before + send.gross;
    let sum = send
        .gross_integer
        .and_then(|gross| charge.used.checked_add(gross));
    // The circuit range-checks every candidate's sum, even an unused one.
    if sum.is_none() {
        violations.push(ControlViolation::QuotaExceeded);
    }
    if charge.slot >= 64 {
        violations.push(ControlViolation::QuotaUsageOpening);
    }
    let opened = path_root(
        QUOTA_USAGE_NODE_DOMAIN,
        window.usage_value(used_before),
        u64::from(charge.slot),
        &charge.siblings,
    );
    let after = path_root(
        QUOTA_USAGE_NODE_DOMAIN,
        window.usage_value(used_after),
        u64::from(charge.slot),
        &charge.siblings,
    );
    if taken {
        if sum.is_none_or(|sum| sum > window.limit)
            && !violations.contains(&ControlViolation::QuotaExceeded)
        {
            violations.push(ControlViolation::QuotaExceeded);
        }
        if u64::from(charge.slot) != slot || charge.slot >= 64 || opened != root {
            violations.push(ControlViolation::QuotaUsageOpening);
        }
        (after, violations)
    } else {
        (root, violations)
    }
}

/// The attestation-lease rule: `U < lease_expires_at_ms`.
#[must_use]
pub const fn lease_holds(upper: u64, lease_expires_at_ms: u64) -> bool {
    upper < lease_expires_at_ms
}

#[cfg(test)]
mod tests {
    use ff::PrimeField;
    use iroha_pasta::Fp;

    use super::*;
    use crate::tree::{QuotaUsageTree, QuotaWindowTree};

    #[test]
    fn segment_positions_follow_the_base() {
        let mut segment = WindowSegment::<Fp>::unused();
        assert!(!segment.present(0) && segment.present(1) && segment.present(3));
        assert_eq!(segment.slot(1), 0);
        assert_eq!(segment.slot(0), 0);
        segment.base = 64;
        assert!(segment.present(0) && !segment.present(1) && !segment.present(2));
        assert_eq!(segment.slot(0), 63);
        segment.base = 62;
        assert!(segment.present(2) && !segment.present(3));
        assert_eq!(segment.slot(2), 63);
        assert!(fits(&Fp::from_u128(u128::MAX), 128));
        assert!(!fits(&(Fp::from_u128(u128::MAX) + Fp::from(1_u64)), 128));
        assert!(fits(&(Fp::from_u128(u128::MAX) + Fp::from(1_u64)), 130));
        assert!(!fits(&-Fp::from(1_u64), 130));
    }

    /// A share with three daily windows and one monthly window, and the
    /// witness of a Send at `[lower, upper]` inside the middle day.
    fn sample() -> (QuotaWitness<Fp>, QuotaSend<Fp>, QuotaUsageTree<Fp>) {
        let day = 86_400_000_u64;
        let windows = [
            QuotaWindow {
                kind: 1,
                start_ms: 0,
                end_ms: day,
                limit: 100,
            },
            QuotaWindow {
                kind: 1,
                start_ms: day,
                end_ms: 2 * day,
                limit: 100,
            },
            QuotaWindow {
                kind: 1,
                start_ms: 2 * day,
                end_ms: 3 * day,
                limit: 100,
            },
            QuotaWindow {
                kind: 2,
                start_ms: 0,
                end_ms: 30 * day,
                limit: 1_000,
            },
        ];
        let tree = QuotaWindowTree::new(&windows).expect("tree");
        let slot = |slot: usize| WindowSlot {
            window: tree.slot(slot),
            siblings: tree.siblings(slot),
        };
        let mut usage = QuotaUsageTree::<Fp>::new(&tree);
        assert!(usage.set(3, 7));
        let usage_root = usage.root();
        let gross = 10_u128;
        let daily = usage.siblings(1).expect("slot");
        assert!(usage.set(1, 10));
        let monthly = usage.siblings(3).expect("slot");
        assert!(usage.set(3, 17));
        let witness = QuotaWitness {
            segments: [
                WindowSegment {
                    base: 1,
                    slots: [slot(0), slot(1), slot(2), slot(3)],
                },
                WindowSegment {
                    base: 3,
                    slots: [slot(2), slot(3), slot(4), slot(5)],
                },
            ],
            charges: [
                QuotaCharge {
                    slot: 1,
                    siblings: daily,
                    used: 0,
                },
                QuotaCharge::unused(),
                QuotaCharge {
                    slot: 3,
                    siblings: monthly,
                    used: 7,
                },
                QuotaCharge::unused(),
            ],
        };
        let send = QuotaSend {
            windows_root: tree.root(),
            usage_root,
            lower: day + 5,
            upper: day + 600_005,
            gross: Fp::from_u128(gross),
            gross_integer: Some(gross),
        };
        (witness, send, usage)
    }

    #[test]
    fn an_honest_quota_witness_charges_every_touched_window() {
        let (witness, send, usage) = sample();
        let outcome = evaluate_quota(&witness, &send);
        assert_eq!(outcome.violations, Vec::new());
        assert_eq!(outcome.usage_root, usage.root());
    }

    #[test]
    fn quota_violations_are_reported() {
        let (honest, send, _) = sample();
        // Over the daily limit.
        let mut over = send;
        over.gross = Fp::from(101_u64);
        over.gross_integer = Some(101);
        assert!(
            evaluate_quota(&honest, &over)
                .violations
                .contains(&ControlViolation::QuotaExceeded)
        );
        // A daily segment that starts after the touched window.
        let mut skipped = honest.clone();
        skipped.segments[0].base = 2;
        skipped.segments[0].slots = [
            honest.segments[0].slots[1],
            honest.segments[0].slots[2],
            honest.segments[0].slots[3],
            honest.segments[1].slots[2],
        ];
        let violations = evaluate_quota(&skipped, &send).violations;
        assert!(
            violations.contains(&ControlViolation::QuotaWindowSkipped)
                || violations.contains(&ControlViolation::QuotaKindUntouched),
            "{violations:?}"
        );
        // A forged window opening.
        let mut forged = honest.clone();
        forged.segments[1].slots[1].window.limit += 1;
        assert!(
            evaluate_quota(&forged, &send)
                .violations
                .contains(&ControlViolation::QuotaWindowOpening)
        );
        // An insertion claimed for a present key.
        let mut present = honest;
        present.charges[2].slot = present.charges[0].slot;
        assert!(
            evaluate_quota(&present, &send)
                .violations
                .contains(&ControlViolation::QuotaUsageOpening)
        );
        assert!(lease_holds(9, 10) && !lease_holds(10, 10));
        let gap = BlacklistGap::<Fp>::unused();
        assert!(blacklist_holds(0, &Fp::from(1_u64), &gap, &[1; 32]));
        assert!(!blacklist_holds(1, &Fp::from(1_u64), &gap, &[1; 32]));
    }
}
