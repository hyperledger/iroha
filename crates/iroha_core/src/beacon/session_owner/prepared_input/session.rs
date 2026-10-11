//! Final session destination with every transcript row and output vector prepared.

use super::*;
use common::*;
use finish::Ledger;
use inline::InlineValue;
use iroha_data_model::{consensus::GlobalThresholdBeaconDkgSessionV1, id::NetworkId};
use rows::{Acceptance, Dealer, Edge, Recipient};
use sequence::Rows;

/// The nested transcript has its own generated canonical record traversal.
struct Transcript {
    session: GlobalThresholdBeaconDkgSessionV1,
    generator_h: [u8; 96],
    generator_v: [u8; 96],
    dealers: Rows<Dealer>,
    recipients: Rows<Recipient>,
    edges: Rows<Edge>,
    acceptances: Rows<Acceptance>,
    qualified: CopySequence<u16>,
    event_hash: [u8; 32],
    height: u64,
    ready: bool,
}
impl Transcript {
    fn new(
        session: GlobalThresholdBeaconDkgSessionV1,
        roster: &[PeerId],
        budget: &AllocationBudget,
    ) -> Result<Self, SessionGraphError> {
        let n = usize::from(session.committee_size);
        let edges = n.checked_mul(n).ok_or(AllocationRefusal::DemandOverflow)?;
        Ok(Self {
            session,
            generator_h: [0; 96],
            generator_v: [0; 96],
            dealers: Rows::new(n, budget, |_| Dealer::new(session.threshold, budget))?,
            recipients: Rows::new(n, budget, |index| {
                Recipient::new(roster[index].public_key(), budget)
            })?,
            edges: Rows::new(edges, budget, |_| Edge::new(budget))?,
            acceptances: Rows::new(edges, budget, |_| Acceptance::new(budget))?,
            qualified: CopySequence::new(n, 0, budget)?,
            event_hash: [0; 32],
            height: 0,
            ready: false,
        })
    }
    fn decode(&mut self, bytes: &[u8]) -> DecodeResult<()> {
        self.reset();
        let (_, used) = GlobalThresholdBeaconDkgTranscriptV1::decode_fields(bytes, self)?;
        complete(used, bytes)?;
        self.ready = true;
        Ok(())
    }
    fn reset(&mut self) {
        self.ready = false;
        self.dealers.reset();
        self.recipients.reset();
        self.edges.reset();
        self.acceptances.reset();
        self.qualified.reset();
    }
    fn ready(&self) -> bool {
        self.ready
            && self.dealers.ready()
            && self.recipients.ready()
            && self.edges.ready()
            && self.acceptances.ready()
            && self.qualified.ready()
    }
    fn finish(self, ledger: &mut Ledger) -> GlobalThresholdBeaconDkgTranscriptV1 {
        GlobalThresholdBeaconDkgTranscriptV1 {
            session: self.session,
            generator_h: self.generator_h,
            generator_v: self.generator_v,
            dealer_commitments: self.dealers.finish(ledger),
            recipient_keys: self.recipients.finish(ledger),
            encrypted_shares: self.edges.finish(ledger),
            share_acceptances: self.acceptances.finish(ledger),
            qualified_dealers: ledger.vector(self.qualified.values),
            event_hash: self.event_hash,
            finalized_at_height: self.height,
        }
    }
}
impl FieldDestination for Transcript {
    type Error = DestinationError;
}
macro_rules! scalar {
    ($owner:ty, $index:literal, $name:ident, [u8; $length:expr]) => {
        impl DecodeField<$index, [u8; $length]> for $owner {
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
    ($owner:ty, $index:literal, $name:ident, $ty:ty) => {
        impl DecodeField<$index, $ty> for $owner {
            type Value = ();
            fn decode_field(&mut self, field: CanonicalField<'_, $ty>) -> DecodeResult<()> {
                self.$name = field.with_payload(<$ty as InlineValue>::decode_payload)?;
                Ok(())
            }
        }
    };
}
macro_rules! sequence {
    ($owner:ty, $index:literal, $name:ident, $ty:ty) => {
        impl DecodeField<$index, Vec<$ty>> for $owner {
            type Value = ();
            fn decode_field(&mut self, field: CanonicalField<'_, Vec<$ty>>) -> DecodeResult<()> {
                field.with_payload(|bytes| self.$name.decode(bytes))
            }
        }
    };
}
scalar!(Transcript, 0, session, GlobalThresholdBeaconDkgSessionV1);
scalar!(Transcript, 1, generator_h, [u8; 96]);
scalar!(Transcript, 2, generator_v, [u8; 96]);
sequence!(
    Transcript,
    3,
    dealers,
    GlobalThresholdBeaconDkgDealerCommitmentV1
);
sequence!(
    Transcript,
    4,
    recipients,
    GlobalThresholdBeaconDkgRecipientKeyV1
);
sequence!(
    Transcript,
    5,
    edges,
    GlobalThresholdBeaconDkgEncryptedShareV1
);
sequence!(
    Transcript,
    6,
    acceptances,
    GlobalThresholdBeaconDkgShareAcceptanceV1
);
sequence!(Transcript, 7, qualified, u16);
scalar!(Transcript, 8, event_hash, [u8; 32]);
scalar!(Transcript, 9, height, u64);
impl SerializePayload for Transcript {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), norito::Error> {
        #[derive(norito::NoritoSerialize)]
        struct View<'a> {
            session: PayloadRef<'a, GlobalThresholdBeaconDkgSessionV1>,
            generator_h: [u8; 96],
            generator_v: [u8; 96],
            dealers: PayloadRef<'a, Rows<Dealer>>,
            recipients: PayloadRef<'a, Rows<Recipient>>,
            edges: PayloadRef<'a, Rows<Edge>>,
            acceptances: PayloadRef<'a, Rows<Acceptance>>,
            qualified: PayloadRef<'a, CopySequence<u16>>,
            event_hash: [u8; 32],
            height: u64,
        }
        if !self.ready() {
            return Err(norito::Error::InvalidValue {
                context: "unfinished prepared DKG transcript",
            });
        }
        View {
            session: PayloadRef(&self.session),
            generator_h: self.generator_h,
            generator_v: self.generator_v,
            dealers: PayloadRef(&self.dealers),
            recipients: PayloadRef(&self.recipients),
            edges: PayloadRef(&self.edges),
            acceptances: PayloadRef(&self.acceptances),
            qualified: PayloadRef(&self.qualified),
            event_hash: self.event_hash,
            height: self.height,
        }
        .serialize(writer)
    }
}

/// One independently prepared final public graph. Ledger follows the payload fields.
pub(super) struct Session {
    version: u16,
    network_id: NetworkId,
    session_id: [u8; 32],
    roster_hash: [u8; 32],
    committee_size: u16,
    threshold: u16,
    group_public_key: [u8; 96],
    shares: CopySequence<GlobalThresholdBeaconPublicShareV1>,
    transcript: Transcript,
    dkg_contribution_hash: [u8; 32],
    transcript_hash: [u8; 32],
    ledger: Ledger,
    budget: AllocationBudget,
    ready: bool,
    canonical: bool,
}
impl Session {
    pub(super) fn new(
        session: GlobalThresholdBeaconDkgSessionV1,
        roster: &[PeerId],
        budget: &AllocationBudget,
    ) -> Result<Self, crate::beacon::GlobalThresholdBeaconSessionError> {
        crate::beacon::validate_dkg_session(&session)?;
        let n = usize::from(session.committee_size);
        if roster.len() != n
            || roster
                .iter()
                .any(|peer| peer.public_key().algorithm() != iroha_crypto::Algorithm::BlsNormal)
            || crate::beacon::global_threshold_beacon_roster_hash_v1(roster) != session.roster_hash
        {
            return Err(crate::beacon::GlobalThresholdBeaconError::InvalidDkgSession.into());
        }
        // Six output vectors; five leaf charges per seat; three ciphertext and
        // one acceptance-signature charge per ordered all-seat edge.
        let edges = n.checked_mul(n).ok_or(AllocationRefusal::DemandOverflow)?;
        let entries = 6usize
            .checked_add(n.checked_mul(5).ok_or(AllocationRefusal::DemandOverflow)?)
            .and_then(|count| count.checked_add(edges.checked_mul(4)?))
            .ok_or(AllocationRefusal::DemandOverflow)?;
        Ok(Self {
            version: 0,
            network_id: session.network_id,
            session_id: [0; 32],
            roster_hash: [0; 32],
            committee_size: 0,
            threshold: 0,
            group_public_key: [0; 96],
            shares: CopySequence::new(
                n,
                GlobalThresholdBeaconPublicShareV1 {
                    index: 0,
                    participant_seat_binding: [0; 32],
                    public_key_share: [0; 96],
                },
                budget,
            )?,
            transcript: Transcript::new(session, roster, budget)?,
            dkg_contribution_hash: [0; 32],
            transcript_hash: [0; 32],
            ledger: Ledger::new(entries, budget)?,
            budget: budget.clone(),
            ready: false,
            canonical: false,
        })
    }
    /// Exact temporary row and sequence layouts retired by this original bank's finish.
    #[cfg(test)]
    pub(super) fn extraction_scaffolding_bytes(&self) -> usize {
        self.shares.extraction_scaffolding_bytes()
            + self.transcript.dealers.extraction_scaffolding_bytes()
            + self.transcript.recipients.extraction_scaffolding_bytes()
            + self.transcript.edges.extraction_scaffolding_bytes()
            + self.transcript.acceptances.extraction_scaffolding_bytes()
            + self.transcript.qualified.extraction_scaffolding_bytes()
            + self
                .transcript
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
        workspace.decode_canonical_into::<GlobalThresholdBeaconKeySessionV1, Self>(
            bytes, limits, self,
        )?;
        self.canonical = true;
        Ok(())
    }
    pub(super) fn finish(self) -> Result<RetainedPayload<GlobalThresholdBeaconKeySessionV1>, Self> {
        if !self.canonical || !self.ready || !self.shares.ready() || !self.transcript.ready() {
            return Err(self);
        }
        let mut ledger = self.ledger;
        let payload = GlobalThresholdBeaconKeySessionV1 {
            version: self.version,
            network_id: self.network_id,
            session_id: self.session_id,
            roster_hash: self.roster_hash,
            committee_size: self.committee_size,
            threshold: self.threshold,
            group_public_key: self.group_public_key,
            public_shares: ledger.vector(self.shares.values),
            adaptive_dkg: self.transcript.finish(&mut ledger),
            dkg_contribution_hash: self.dkg_contribution_hash,
            transcript_hash: self.transcript_hash,
        };
        Ok(ledger.finish(payload, &self.budget))
    }
}
impl FieldDestination for Session {
    type Error = DestinationError;
}
scalar!(Session, 0, version, u16);
scalar!(Session, 1, network_id, NetworkId);
scalar!(Session, 2, session_id, [u8; 32]);
scalar!(Session, 3, roster_hash, [u8; 32]);
scalar!(Session, 4, committee_size, u16);
scalar!(Session, 5, threshold, u16);
scalar!(Session, 6, group_public_key, [u8; 96]);
sequence!(Session, 7, shares, GlobalThresholdBeaconPublicShareV1);
impl DecodeField<8, GlobalThresholdBeaconDkgTranscriptV1> for Session {
    type Value = ();
    fn decode_field(
        &mut self,
        field: CanonicalField<'_, GlobalThresholdBeaconDkgTranscriptV1>,
    ) -> DecodeResult<()> {
        field.with_payload(|bytes| self.transcript.decode(bytes))
    }
}
scalar!(Session, 9, dkg_contribution_hash, [u8; 32]);
impl DecodeField<10, [u8; 32]> for Session {
    type Value = ();
    fn decode_field(&mut self, field: CanonicalField<'_, [u8; 32]>) -> DecodeResult<()> {
        self.transcript_hash = field.decode_owned()?;
        self.ready = true;
        Ok(())
    }
}
impl PreparedRecordDestination<GlobalThresholdBeaconKeySessionV1> for Session {
    fn reset(&mut self) {
        self.ready = false;
        self.canonical = false;
        self.shares.reset();
        self.transcript.reset();
    }
}
impl SerializePayload for Session {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), norito::Error> {
        #[derive(norito::NoritoSerialize)]
        struct View<'a> {
            version: u16,
            network_id: NetworkId,
            session_id: [u8; 32],
            roster_hash: [u8; 32],
            committee_size: u16,
            threshold: u16,
            group_public_key: [u8; 96],
            shares: PayloadRef<'a, CopySequence<GlobalThresholdBeaconPublicShareV1>>,
            transcript: PayloadRef<'a, Transcript>,
            dkg_contribution_hash: [u8; 32],
            transcript_hash: [u8; 32],
        }
        if !self.ready {
            return Err(norito::Error::InvalidValue {
                context: "unfinished prepared DKG key session",
            });
        }
        View {
            version: self.version,
            network_id: self.network_id,
            session_id: self.session_id,
            roster_hash: self.roster_hash,
            committee_size: self.committee_size,
            threshold: self.threshold,
            group_public_key: self.group_public_key,
            shares: PayloadRef(&self.shares),
            transcript: PayloadRef(&self.transcript),
            dkg_contribution_hash: self.dkg_contribution_hash,
            transcript_hash: self.transcript_hash,
        }
        .serialize(writer)
    }
}
