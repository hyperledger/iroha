//! Independent prepared snapshot banks for the commitments and deliveries phases.

use super::*;
use crate::beacon::GlobalThresholdBeaconDkgSnapshotV1;
use common::*;
use finish::Ledger;
use inline::InlineValue;
use iroha_data_model::consensus::GlobalThresholdBeaconDkgSessionV1;
use rows::{Acceptance, Dealer, Edge, Recipient};
use sequence::Rows;

#[derive(Clone, Copy)]
pub(super) enum SnapshotPhase {
    Commitments,
    Deliveries,
    SinglePublication { seat: u16 },
    LocalDeliveries { seat: u16 },
    LocalAcceptances { seat: u16 },
}

/// Field declaration order preserves payload/backing retirement before its ledger.
pub(super) struct Snapshot {
    session: GlobalThresholdBeaconDkgSessionV1,
    generator_h: [u8; 96],
    generator_v: [u8; 96],
    recipients: Rows<Recipient>,
    dealers: Rows<Dealer>,
    edges: Rows<Edge>,
    acceptances: Rows<Acceptance>,
    height: u64,
    ledger: Ledger,
    budget: AllocationBudget,
    ready: bool,
    canonical: bool,
}
impl Snapshot {
    /// Called with the same already authenticated roster/session as the local
    /// prepared seat. Each phase owns independent actual nested storage.
    pub(super) fn new(
        session: GlobalThresholdBeaconDkgSessionV1,
        roster: &[PeerId],
        phase: SnapshotPhase,
        budget: &AllocationBudget,
    ) -> Result<Self, crate::beacon::GlobalThresholdBeaconSessionError> {
        crate::beacon::validate_dkg_session(&session)?;
        let n = usize::from(session.committee_size);
        if n != roster.len()
            || roster
                .iter()
                .any(|peer| peer.public_key().algorithm() != iroha_crypto::Algorithm::BlsNormal)
            || crate::beacon::global_threshold_beacon_roster_hash_v1(roster) != session.roster_hash
        {
            return Err(crate::beacon::GlobalThresholdBeaconError::InvalidDkgSession.into());
        }
        let (rows, first) = match phase {
            SnapshotPhase::SinglePublication { seat } => {
                if seat == 0 || usize::from(seat) > n {
                    return Err(crate::beacon::GlobalThresholdBeaconError::InvalidDkgSession.into());
                }
                (1, usize::from(seat - 1))
            }
            SnapshotPhase::LocalDeliveries { seat } | SnapshotPhase::LocalAcceptances { seat } => {
                if seat == 0 || usize::from(seat) > n {
                    return Err(crate::beacon::GlobalThresholdBeaconError::InvalidDkgSession.into());
                }
                (n, 0)
            }
            SnapshotPhase::Commitments | SnapshotPhase::Deliveries => (n, 0),
        };
        let edges = match phase {
            SnapshotPhase::Commitments => 0,
            SnapshotPhase::SinglePublication { .. } => 0,
            SnapshotPhase::LocalDeliveries { .. } => n,
            SnapshotPhase::Deliveries | SnapshotPhase::LocalAcceptances { .. } => {
                n.checked_mul(n).ok_or(AllocationRefusal::DemandOverflow)?
            }
        };
        let acceptance_count = match phase {
            SnapshotPhase::LocalAcceptances { .. } => n,
            _ => 0,
        };
        let entries = 4usize
            .checked_add(
                rows.checked_mul(5)
                    .ok_or(AllocationRefusal::DemandOverflow)?,
            )
            .and_then(|value| value.checked_add(edges.checked_mul(3)?))
            .and_then(|value| value.checked_add(acceptance_count))
            .ok_or(AllocationRefusal::DemandOverflow)?;
        let recipients = Rows::new(rows, budget, |index| {
            Recipient::new(roster[first + index].public_key(), budget)
        })?;
        let dealers = Rows::new(rows, budget, |_| Dealer::new(session.threshold, budget))?;
        let edges = Rows::new(edges, budget, |_| Edge::new(budget))?;
        let acceptances = Rows::new(acceptance_count, budget, |_| Acceptance::new(budget))?;
        let ledger = Ledger::new(entries, budget)?;
        Ok(Self {
            session,
            generator_h: [0; 96],
            generator_v: [0; 96],
            recipients,
            dealers,
            edges,
            acceptances,
            height: 0,
            ledger,
            budget: budget.clone(),
            ready: false,
            canonical: false,
        })
    }
    #[cfg(test)]
    pub(super) fn extraction_scaffolding_bytes(&self) -> usize {
        self.recipients.extraction_scaffolding_bytes()
            + self.dealers.extraction_scaffolding_bytes()
            + self.edges.extraction_scaffolding_bytes()
            + self.acceptances.extraction_scaffolding_bytes()
            + self
                .dealers
                .destinations
                .as_slice()
                .iter()
                .map(|dealer| {
                    dealer
                        .coefficient_commitments
                        .extraction_scaffolding_bytes()
                })
                .sum::<usize>()
    }
    pub(super) fn decode(
        &mut self,
        workspace: &mut norito::core::PreparedDecodeWorkspace,
        bytes: &[u8],
        limits: norito::DecodeLimits,
    ) -> Result<(), norito::core::PreparedDecodeError<DestinationError>> {
        self.canonical = false;
        workspace.decode_canonical_into::<GlobalThresholdBeaconDkgSnapshotV1, Self>(
            bytes, limits, self,
        )?;
        self.canonical = true;
        Ok(())
    }

    /// Consumes only the complete frame-validated bank. Authentication of each
    /// signed relation remains the existing live local-seat/reducer obligation.
    pub(super) fn finish(
        self,
    ) -> Result<RetainedPayload<GlobalThresholdBeaconDkgSnapshotV1>, Self> {
        if !self.canonical
            || !self.ready
            || !self.recipients.ready()
            || !self.dealers.ready()
            || !self.edges.ready()
            || !self.acceptances.ready()
        {
            return Err(self);
        }
        // The ledger local precedes every extracted canonical field. On unwind
        // those fields retire first, and the ledger conservatively keeps credits.
        let mut ledger = self.ledger;
        let payload = GlobalThresholdBeaconDkgSnapshotV1 {
            session: self.session,
            generator_h: self.generator_h,
            generator_v: self.generator_v,
            recipient_keys: self.recipients.finish(&mut ledger),
            dealer_commitments: self.dealers.finish(&mut ledger),
            encrypted_shares: self.edges.finish(&mut ledger),
            share_acceptances: self.acceptances.finish(&mut ledger),
            last_updated_height: self.height,
        };
        Ok(ledger.finish(payload, &self.budget))
    }
}
impl FieldDestination for Snapshot {
    type Error = DestinationError;
}
macro_rules! scalar {
    ($index:literal, $name:ident, [u8; $length:expr]) => {
        impl DecodeField<$index, [u8; $length]> for Snapshot {
            type Value = ();
            fn decode_field(
                &mut self,
                field: CanonicalField<'_, [u8; $length]>,
            ) -> DecodeResult<()> {
                self.$name = field.decode_owned()?;
                Ok(())
            }
        }
    };
    ($index:literal, $name:ident, $ty:ty) => {
        impl DecodeField<$index, $ty> for Snapshot {
            type Value = ();
            fn decode_field(&mut self, field: CanonicalField<'_, $ty>) -> DecodeResult<()> {
                self.$name = field.with_payload(<$ty as InlineValue>::decode_payload)?;
                Ok(())
            }
        }
    };
}
scalar!(0, session, GlobalThresholdBeaconDkgSessionV1);
scalar!(1, generator_h, [u8; 96]);
scalar!(2, generator_v, [u8; 96]);
macro_rules! sequence {
    ($index:literal, $name:ident, $ty:ty) => {
        impl DecodeField<$index, Vec<$ty>> for Snapshot {
            type Value = ();
            fn decode_field(&mut self, field: CanonicalField<'_, Vec<$ty>>) -> DecodeResult<()> {
                field.with_payload(|bytes| self.$name.decode(bytes))
            }
        }
    };
}
sequence!(3, recipients, GlobalThresholdBeaconDkgRecipientKeyV1);
sequence!(4, dealers, GlobalThresholdBeaconDkgDealerCommitmentV1);
sequence!(5, edges, GlobalThresholdBeaconDkgEncryptedShareV1);
sequence!(6, acceptances, GlobalThresholdBeaconDkgShareAcceptanceV1);
impl DecodeField<7, u64> for Snapshot {
    type Value = ();
    fn decode_field(&mut self, field: CanonicalField<'_, u64>) -> DecodeResult<()> {
        self.height = field.with_payload(u64::decode_payload)?;
        self.ready = true;
        Ok(())
    }
}
impl PreparedRecordDestination<GlobalThresholdBeaconDkgSnapshotV1> for Snapshot {
    fn reset(&mut self) {
        self.canonical = false;
        self.ready = false;
        self.recipients.reset();
        self.dealers.reset();
        self.edges.reset();
        self.acceptances.reset();
    }
}
impl SerializePayload for Snapshot {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), norito::Error> {
        #[derive(norito::NoritoSerialize)]
        struct View<'a> {
            session: PayloadRef<'a, GlobalThresholdBeaconDkgSessionV1>,
            generator_h: [u8; 96],
            generator_v: [u8; 96],
            recipients: PayloadRef<'a, Rows<Recipient>>,
            dealers: PayloadRef<'a, Rows<Dealer>>,
            edges: PayloadRef<'a, Rows<Edge>>,
            acceptances: PayloadRef<'a, Rows<Acceptance>>,
            height: u64,
        }
        if !self.ready {
            return Err(norito::Error::InvalidValue {
                context: "unfinished prepared DKG snapshot",
            });
        }
        View {
            session: PayloadRef(&self.session),
            generator_h: self.generator_h,
            generator_v: self.generator_v,
            recipients: PayloadRef(&self.recipients),
            dealers: PayloadRef(&self.dealers),
            edges: PayloadRef(&self.edges),
            acceptances: PayloadRef(&self.acceptances),
            height: self.height,
        }
        .serialize(writer)
    }
}

#[cfg(test)]
mod tests;
