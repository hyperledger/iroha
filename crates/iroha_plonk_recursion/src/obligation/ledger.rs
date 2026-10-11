//! Circuit-fixed obligation routes for the unsplit Lambda variants.
//!
//! These schedules are construction metadata, never a prover-supplied list.
//! They identify every claimed opening and accumulator separately, including
//! the hard forwarded sigma part. Claim values and all forwarding equalities
//! must still be bound by the consuming circuits.

use core::{fmt, num::NonZeroU16};

/// An unsplit operation relation, including every policy-refresh variant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Variant {
    /// The unique zero-state base relation, without a predecessor.
    Bootstrap,
    /// Finalized reserve-backed load.
    Load,
    /// Irreversible outgoing payment.
    Send,
    /// Incoming Payment, with a credential shared with the Request.
    Receive,
    /// Incoming Payment whose receiver credential has been renewed.
    ReceiveRenewed,
    /// Credited evidence consisting of a Receive step proof and receipt.
    ArchiveReceive,
    /// Credited evidence against a folded head and its credit-digest tree.
    ArchiveStatus,
    /// Reserve redemption.
    Unload,
    /// Stop accepting new loads.
    Retiring,
    /// Lease/credential renewal.
    RefreshCredential,
    /// Scheme policy replacement.
    RefreshSchemePolicy,
    /// Blacklist history insertion.
    RefreshBlacklist,
    /// Fixed 64-slot quota usage rebuild.
    RefreshQuotaShare,
    /// Accepted-time anchor update.
    RefreshTimeAnchor,
}

impl Variant {
    /// Every unsplit variant; A-split context relations need their own ledger.
    pub const ALL: [Self; 14] = [
        Self::Bootstrap,
        Self::Load,
        Self::Send,
        Self::Receive,
        Self::ReceiveRenewed,
        Self::ArchiveReceive,
        Self::ArchiveStatus,
        Self::Unload,
        Self::Retiring,
        Self::RefreshCredential,
        Self::RefreshSchemePolicy,
        Self::RefreshBlacklist,
        Self::RefreshQuotaShare,
        Self::RefreshTimeAnchor,
    ];
}

/// A distinct source obligation; equal byte values never merge identities.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Obligation {
    /// The own sigma verifier's deferred opening.
    OwnSigma,
    /// The incoming Send/Receive sigma verifier's deferred opening.
    IncomingSigma,
    /// `Q_sigma`'s folded or source-k-preserving forwarded output.
    SigmaPart,
    /// One Q leaf's deferred opening, in descriptor order.
    QOpening(u16),
    /// Predecessor Omega's Pallas accumulator.
    PredecessorPallas,
    /// Predecessor Omega's own deferred opening.
    PredecessorOpening,
    /// Predecessor Omega's Vesta accumulator.
    PredecessorVesta,
    /// Incoming Omega's Pallas accumulator.
    IncomingPallas,
    /// Incoming Omega's own deferred opening.
    IncomingOpening,
    /// Incoming Omega's Vesta accumulator.
    IncomingVesta,
    /// A's deferred opening, created in Omega.
    AggregatorOpening,
}

/// The proof or forwarding equality that consumes a slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Destination {
    /// `F_V^Q`, including the explicit pinned full-length padding input.
    SigmaFold,
    /// Exactly one sigma opening is copied into the part with its source k.
    SigmaForward,
    /// `F_P` in A.
    PallasFold,
    /// Bootstrap's single Q opening is copied into `acc_P`.
    PallasForward,
    /// `F_V^Omega` in Omega.
    VestaFold,
}

/// A ledger input, distinguishing genuine obligations from explicit padding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// An obligation whose identity must occur exactly once in the schedule.
    Claim(Obligation),
    /// The pinned Vesta `ACC_TRIV`: the full-length sigma padding input,
    /// or an explicitly absent predecessor/incoming slot of the uniform
    /// four-input Omega fold. Destination and position fix its role.
    VestaTrivial,
}

/// One circuit-fixed input slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Slot {
    /// Identity or explicit full-length padding constant.
    pub source: Source,
    /// Consuming fold or authenticated forwarding equality.
    pub destination: Destination,
    /// Original source prefix length, bound to the source descriptor.
    /// A gated Trivial replacement uses k16; the mode selector must constrain
    /// that selected fold-input k separately from this original source k.
    pub source_k: u8,
    /// Only incoming claims may use the modes in the parent module.
    pub gated: bool,
}

/// An invalid fixed plan or a consumer that omits, reorders or adds a slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LedgerError {
    /// Sigma descriptors must have one of the implemented k12/k14 shapes.
    SigmaShape,
    /// The variant and presence of an incoming sigma descriptor disagree.
    IncomingShape,
    /// The ordered consumer bindings differ from the fixed schedule.
    Bindings,
}

impl fmt::Display for LedgerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::SigmaShape => "sigma source k must be 12 or 14",
            Self::IncomingShape => "incoming sigma does not match the variant",
            Self::Bindings => "obligation bindings do not match the fixed schedule",
        })
    }
}

impl std::error::Error for LedgerError {}

/// A fixed construction plan, derived from authenticated circuit descriptors.
///
/// It is not an authorization token. Operation circuits must implement its
/// routes and copy the claim values and modes into each named slot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ledger {
    slots: Vec<Slot>,
}

impl Ledger {
    /// Builds the Lambda §2.3 ledger in canonical fold-input order.
    /// Descriptor-derived k values and Q count are fixed at key generation.
    ///
    /// # Errors
    /// A variant/descriptor mismatch or unsupported sigma shape.
    /// Conditional A-split contexts are deliberately separate plans.
    pub fn new(
        variant: Variant,
        q_leaves: NonZeroU16,
        own_sigma_k: u8,
        incoming_sigma_k: Option<u8>,
    ) -> Result<Self, LedgerError> {
        if !matches!(own_sigma_k, 12 | 14)
            || incoming_sigma_k.is_some_and(|k| !matches!(k, 12 | 14))
        {
            return Err(LedgerError::SigmaShape);
        }
        let incoming_sigma = matches!(
            variant,
            Variant::Receive | Variant::ReceiveRenewed | Variant::ArchiveReceive
        );
        let incoming_omega = matches!(
            variant,
            Variant::Receive | Variant::ReceiveRenewed | Variant::ArchiveStatus
        );
        if incoming_sigma != incoming_sigma_k.is_some() {
            return Err(LedgerError::IncomingShape);
        }
        let base = variant == Variant::Bootstrap;
        let mut slots = Vec::new();
        let mut claim = |id, destination, source_k, gated| {
            slots.push(Slot {
                source: Source::Claim(id),
                destination,
                source_k,
                gated,
            });
        };
        let sigma_destination = if incoming_sigma {
            Destination::SigmaFold
        } else {
            Destination::SigmaForward
        };
        claim(Obligation::OwnSigma, sigma_destination, own_sigma_k, false);
        if let Some(k) = incoming_sigma_k {
            claim(Obligation::IncomingSigma, Destination::SigmaFold, k, true);
        }
        // F_P order follows §2.2: predecessor, incoming, then ordered Qs.
        if !base {
            claim(
                Obligation::PredecessorPallas,
                Destination::PallasFold,
                16,
                false,
            );
            claim(
                Obligation::PredecessorOpening,
                Destination::PallasFold,
                16,
                false,
            );
        }
        if incoming_omega {
            claim(
                Obligation::IncomingPallas,
                Destination::PallasFold,
                16,
                true,
            );
            claim(
                Obligation::IncomingOpening,
                Destination::PallasFold,
                16,
                true,
            );
        }
        for index in 0..q_leaves.get() {
            claim(
                Obligation::QOpening(index),
                if base && q_leaves.get() == 1 {
                    Destination::PallasForward
                } else {
                    Destination::PallasFold
                },
                16,
                false,
            );
        }
        claim(
            Obligation::SigmaPart,
            Destination::VestaFold,
            if incoming_sigma { 16 } else { own_sigma_k },
            false,
        );
        claim(
            Obligation::AggregatorOpening,
            Destination::VestaFold,
            16,
            false,
        );
        if !base {
            claim(
                Obligation::PredecessorVesta,
                Destination::VestaFold,
                16,
                false,
            );
        }
        if incoming_omega {
            claim(Obligation::IncomingVesta, Destination::VestaFold, 16, true);
        }
        // One Omega descriptor/key consumes four slots for every variant:
        // part, A opening, predecessor, incoming. Absent claims are explicit
        // pinned constants, not witness-selected omissions.
        for absent in [base, !incoming_omega] {
            if absent {
                slots.push(Slot {
                    source: Source::VestaTrivial,
                    destination: Destination::VestaFold,
                    source_k: 16,
                    gated: false,
                });
            }
        }
        if incoming_sigma {
            // Filtering by destination places this after the two short
            // source openings. It is not a substitute for either obligation.
            slots.push(Slot {
                source: Source::VestaTrivial,
                destination: Destination::SigmaFold,
                source_k: 16,
                gated: false,
            });
        }
        Ok(Self { slots })
    }

    /// Every slot in the fixed ledger; destination-local order is canonical.
    pub fn slots(&self) -> &[Slot] {
        &self.slots
    }

    /// Exact destination-local input order, including explicit padding.
    pub fn inputs(&self, destination: Destination) -> impl Iterator<Item = &Slot> {
        self.slots
            .iter()
            .filter(move |slot| slot.destination == destination)
    }

    /// Checks the consumer's complete ordered schedule against this plan.
    ///
    /// # Errors
    /// Any omitted, duplicated, moved, relabeled, gated or reshaped slot.
    pub fn check_bindings(&self, bindings: &[Slot]) -> Result<(), LedgerError> {
        if bindings == self.slots {
            Ok(())
        } else {
            Err(LedgerError::Bindings)
        }
    }
}
