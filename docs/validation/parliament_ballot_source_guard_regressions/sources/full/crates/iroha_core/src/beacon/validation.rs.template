//! Borrowed validation of canonical DKG snapshots and finalized transcripts.

use super::*;

/// Borrowed non-byte elements encoded by the canonical Vec element-sequence codec.
pub(super) struct ElementSequence<'a, T>(pub(super) &'a [T]);

impl<T: norito::core::SerializePayload> norito::core::SerializePayload for ElementSequence<'_, T> {
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), norito::Error> {
        norito::core::write_element_sequence::<T, _>(writer, self.0.iter())
    }
}

/// Repeatable borrowed roster projection encoded by the canonical sequence owner.
pub(super) struct RosterIter<I>(pub(super) I);

impl<'a, I> norito::core::SerializePayload for RosterIter<I>
where
    I: ExactSizeIterator<Item = &'a PeerId> + Clone,
{
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), norito::Error> {
        norito::core::write_element_sequence::<PeerId, _>(writer, self.0.clone())
    }
}

struct RecipientRoster<'a>(&'a [GlobalThresholdBeaconDkgRecipientKeyV1]);

impl norito::core::SerializePayload for RecipientRoster<'_> {
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), norito::Error> {
        norito::core::write_element_sequence::<PeerId, _>(
            writer,
            self.0.iter().map(|key| &key.validator),
        )
    }
}

/// Exact event-hash preimage streamed from its original transcript graph.
pub(super) struct DkgEventPreimage<'a> {
    pub(super) session: &'a GlobalThresholdBeaconDkgSessionV1,
    pub(super) generator_h: &'a [u8; 96],
    pub(super) generator_v: &'a [u8; 96],
    pub(super) recipient_keys: &'a [GlobalThresholdBeaconDkgRecipientKeyV1],
    pub(super) dealer_commitments: &'a [GlobalThresholdBeaconDkgDealerCommitmentV1],
    pub(super) encrypted_shares: &'a [GlobalThresholdBeaconDkgEncryptedShareV1],
    pub(super) share_acceptances: &'a [GlobalThresholdBeaconDkgShareAcceptanceV1],
    pub(super) qualified_dealers: &'a [u16],
    pub(super) finalized_at_height: u64,
}

impl norito::core::SerializePayload for DkgEventPreimage<'_> {
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), norito::Error> {
        use norito::codec::encode_adaptive_into;

        writer.write_all(b"iroha.global-threshold-beacon.dkg-events.v1\0")?;
        encode_adaptive_into(self.session, writer)?;
        writer.write_all(self.generator_h)?;
        writer.write_all(self.generator_v)?;
        encode_adaptive_into(&ElementSequence(self.recipient_keys), writer)?;
        encode_adaptive_into(&ElementSequence(self.dealer_commitments), writer)?;
        encode_adaptive_into(&ElementSequence(self.encrypted_shares), writer)?;
        encode_adaptive_into(&ElementSequence(self.share_acceptances), writer)?;
        encode_adaptive_into(&ElementSequence(self.qualified_dealers), writer)?;
        writer.write_all(&self.finalized_at_height.to_be_bytes())?;
        Ok(())
    }
}

/// Domain/session/record hash input with no materialized encoded copies.
pub(super) struct DkgRecordPreimage<'a, T> {
    pub(super) domain: &'static [u8],
    pub(super) session: &'a GlobalThresholdBeaconDkgSessionV1,
    pub(super) record: &'a T,
}

impl<T: norito::core::SerializePayload> norito::core::SerializePayload
    for DkgRecordPreimage<'_, T>
{
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), norito::Error> {
        writer.write_all(self.domain)?;
        norito::codec::encode_adaptive_into(self.session, writer)?;
        norito::codec::encode_adaptive_into(self.record, writer)?;
        Ok(())
    }
}

/// Exact signed/AAD byte sequences borrowing their source fields.
pub(super) enum DkgSignaturePreimage<'a> {
    RecipientKey(
        &'a GlobalThresholdBeaconDkgSessionV1,
        &'a GlobalThresholdBeaconDkgRecipientKeyV1,
    ),
    DealerCommitment(
        &'a GlobalThresholdBeaconDkgSessionV1,
        &'a GlobalThresholdBeaconDkgDealerCommitmentV1,
    ),
    PrivateEdgeAad(
        &'a GlobalThresholdBeaconDkgSessionV1,
        &'a GlobalThresholdBeaconDkgEncryptedShareV1,
    ),
    EncryptedShare(
        &'a GlobalThresholdBeaconDkgSessionV1,
        &'a GlobalThresholdBeaconDkgEncryptedShareV1,
    ),
    ShareAcceptance(
        &'a GlobalThresholdBeaconDkgSessionV1,
        &'a GlobalThresholdBeaconDkgShareAcceptanceV1,
    ),
}

impl DkgSignaturePreimage<'_> {
    /// One exactly sized output owner; field encodings stream into that backing.
    pub(super) fn encode_exact(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.encoded_len());
        self.encode_to(&mut out);
        out
    }
}

impl norito::core::SerializePayload for DkgSignaturePreimage<'_> {
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), norito::Error> {
        use norito::codec::encode_adaptive_into;
        match self {
            Self::RecipientKey(session, key) => {
                writer.write_all(b"iroha.global-threshold-beacon.dkg-recipient-key.v1\0")?;
                encode_adaptive_into(*session, writer)?;
                writer.write_all(&key.recipient_index.to_be_bytes())?;
                encode_adaptive_into(&key.validator, writer)?;
                writer.write_all(&key.x25519_public_key)?;
                encode_adaptive_into(&key.mlkem768_public_key, writer)?;
            }
            Self::DealerCommitment(session, commitment) => {
                writer.write_all(b"iroha.global-threshold-beacon.dkg-dealer-commitment.v1\0")?;
                encode_adaptive_into(*session, writer)?;
                writer.write_all(&commitment.dealer_index.to_be_bytes())?;
                encode_adaptive_into(&commitment.coefficient_commitments, writer)?;
                encode_adaptive_into(&commitment.constant_term_proof, writer)?;
            }
            Self::PrivateEdgeAad(session, edge) | Self::EncryptedShare(session, edge) => {
                writer.write_all(b"iroha.global-threshold-beacon.dkg-private-edge.v1\0")?;
                encode_adaptive_into(*session, writer)?;
                writer.write_all(&edge.dealer_index.to_be_bytes())?;
                writer.write_all(&edge.recipient_index.to_be_bytes())?;
                writer.write_all(&edge.dealer_commitment_hash)?;
                writer.write_all(&edge.recipient_key_hash)?;
                writer.write_all(&edge.delivery_height.to_be_bytes())?;
                if matches!(self, Self::EncryptedShare(..)) {
                    writer.write_all(&edge.ephemeral_x25519_public_key)?;
                    encode_adaptive_into(&edge.mlkem768_ciphertext, writer)?;
                    encode_adaptive_into(&edge.encrypted_share, writer)?;
                }
            }
            Self::ShareAcceptance(session, acceptance) => {
                writer.write_all(b"iroha.global-threshold-beacon.dkg-share-acceptance.v1\0")?;
                encode_adaptive_into(*session, writer)?;
                writer.write_all(&acceptance.dealer_index.to_be_bytes())?;
                writer.write_all(&acceptance.recipient_index.to_be_bytes())?;
                writer.write_all(&acceptance.dealer_commitment_hash)?;
                writer.write_all(&acceptance.encrypted_share_hash)?;
                writer.write_all(&acceptance.accepted_height.to_be_bytes())?;
            }
        }
        Ok(())
    }
}

/// One signature-verification kernel, with explicit ownership of its exact message bytes.
pub(super) trait DkgSignatureVerifier {
    type Resource;
    fn verify(
        &mut self,
        preimage: DkgSignaturePreimage<'_>,
        signature: &iroha_crypto::Signature,
        key: &iroha_crypto::PublicKey,
    ) -> Result<bool, Self::Resource>;
}

/// Existing standalone DKG operations emit an actual ephemeral signed preimage.
/// Session sealing uses the original prepaid workspace through the same verifier kernel.
pub(super) struct AllocatingSignatureVerifier<'a, F>(&'a mut F);
impl<'a, F> AllocatingSignatureVerifier<'a, F> {
    pub(super) fn new(admit: &'a mut F) -> Self {
        Self(admit)
    }
}
impl<F, E> DkgSignatureVerifier for AllocatingSignatureVerifier<'_, F>
where
    F: FnMut(usize) -> Result<(), E>,
{
    type Resource = E;
    fn verify(
        &mut self,
        preimage: DkgSignaturePreimage<'_>,
        signature: &iroha_crypto::Signature,
        key: &iroha_crypto::PublicKey,
    ) -> Result<bool, E> {
        (self.0)(preimage.encoded_len())?;
        Ok(
            iroha_crypto::verify_signature_borrowed(signature, key, &preimage.encode_exact())
                .is_ok(),
        )
    }
}

/// One borrowed view of either a partial snapshot or a finalized transcript.
pub(super) struct DkgSnapshotRef<'a> {
    session: &'a GlobalThresholdBeaconDkgSessionV1,
    generator_h: &'a [u8; 96],
    generator_v: &'a [u8; 96],
    recipient_keys: &'a [GlobalThresholdBeaconDkgRecipientKeyV1],
    dealer_commitments: &'a [GlobalThresholdBeaconDkgDealerCommitmentV1],
    encrypted_shares: &'a [GlobalThresholdBeaconDkgEncryptedShareV1],
    share_acceptances: &'a [GlobalThresholdBeaconDkgShareAcceptanceV1],
    last_updated_height: u64,
}

impl<'a> From<&'a GlobalThresholdBeaconDkgSnapshotV1> for DkgSnapshotRef<'a> {
    fn from(value: &'a GlobalThresholdBeaconDkgSnapshotV1) -> Self {
        Self {
            session: &value.session,
            generator_h: &value.generator_h,
            generator_v: &value.generator_v,
            recipient_keys: &value.recipient_keys,
            dealer_commitments: &value.dealer_commitments,
            encrypted_shares: &value.encrypted_shares,
            share_acceptances: &value.share_acceptances,
            last_updated_height: value.last_updated_height,
        }
    }
}

impl<'a> From<&'a GlobalThresholdBeaconDkgTranscriptV1> for DkgSnapshotRef<'a> {
    fn from(value: &'a GlobalThresholdBeaconDkgTranscriptV1) -> Self {
        Self {
            session: &value.session,
            generator_h: &value.generator_h,
            generator_v: &value.generator_v,
            recipient_keys: &value.recipient_keys,
            dealer_commitments: &value.dealer_commitments,
            encrypted_shares: &value.encrypted_shares,
            share_acceptances: &value.share_acceptances,
            last_updated_height: value.finalized_at_height,
        }
    }
}

/// Project only a verifier whose resource callback cannot fail.
pub(super) fn unbudgeted<T>(
    result: Result<T, GlobalThresholdBeaconVerificationError<std::convert::Infallible>>,
) -> Result<T, GlobalThresholdBeaconError> {
    result.map_err(|error| match error {
        GlobalThresholdBeaconVerificationError::Invalid(error) => error,
        GlobalThresholdBeaconVerificationError::Resource(never) => match never {},
    })
}

impl DkgSnapshotRef<'_> {
    /// Borrow the exact commitments phase without copying its public rows.
    pub(super) fn commitments<'a>(
        session: &'a GlobalThresholdBeaconDkgSessionV1,
        generator_h: &'a [u8; 96],
        generator_v: &'a [u8; 96],
        recipient_keys: &'a [GlobalThresholdBeaconDkgRecipientKeyV1],
        dealer_commitments: &'a [GlobalThresholdBeaconDkgDealerCommitmentV1],
    ) -> DkgSnapshotRef<'a> {
        DkgSnapshotRef {
            session,
            generator_h,
            generator_v,
            recipient_keys,
            dealer_commitments,
            encrypted_shares: &[],
            share_acceptances: &[],
            last_updated_height: session.start_height,
        }
    }
    /// Refuse protocol-sized shapes before encoding or cryptographic parsing.
    pub(super) fn validate_bounds(&self) -> Result<(), GlobalThresholdBeaconError> {
        validate_dkg_session(self.session)?;
        let seats = usize::from(self.session.committee_size);
        let edges = seats
            .checked_mul(seats)
            .ok_or(GlobalThresholdBeaconError::InvalidDkgSession)?;
        let signature_bytes = Algorithm::BlsNormal.signature_payload_len();
        let kem = soranet_pq::MlKemSuite::MlKem768;
        if self.recipient_keys.len() > seats
            || self.recipient_keys.iter().any(|key| {
                key.validator.public_key().algorithm() != Algorithm::BlsNormal
                    || key.mlkem768_public_key.len() != kem.public_key_len()
                    || key.signature.payload().len() != signature_bytes
            })
        {
            return Err(GlobalThresholdBeaconError::InvalidDkgRecipientKey);
        }
        if self.dealer_commitments.len() > seats
            || self.dealer_commitments.iter().any(|dealer| {
                dealer.coefficient_commitments.len() != usize::from(self.session.threshold)
                    || dealer.signature.payload().len() != signature_bytes
            })
        {
            return Err(GlobalThresholdBeaconError::DealerCommitmentEquivocation);
        }
        if self.encrypted_shares.len() > edges
            || self.encrypted_shares.iter().any(|edge| {
                edge.mlkem768_ciphertext.len() != kem.ciphertext_len()
                    || edge.encrypted_share.len() != 12 + 96 + 16
                    || edge.signature.payload().len() != signature_bytes
            })
        {
            return Err(GlobalThresholdBeaconError::InvalidDkgEncryptedShare);
        }
        if self.share_acceptances.len() > edges
            || self
                .share_acceptances
                .iter()
                .any(|acceptance| acceptance.signature.payload().len() != signature_bytes)
        {
            return Err(GlobalThresholdBeaconError::InvalidDkgShareAcceptance);
        }
        Ok(())
    }

    /// Validate the original borrowed graph without snapshot or lookup-map copies.
    pub(super) fn validate(&self) -> Result<(), GlobalThresholdBeaconError> {
        unbudgeted(self.validate_with_admission(&mut |_| Ok::<(), std::convert::Infallible>(())))
    }

    /// Use the caller's same cumulative allocation owner for the borrowed graph.
    pub(super) fn validate_with_admission<E>(
        &self,
        admit: &mut impl FnMut(usize) -> Result<(), E>,
    ) -> Result<(), GlobalThresholdBeaconVerificationError<E>> {
        self.validate_with_verifier(&mut AllocatingSignatureVerifier::new(admit))
    }

    /// The same shape, order, signature and event checks with caller-owned message scratch.
    pub(super) fn validate_with_verifier<V: DkgSignatureVerifier>(
        &self,
        verifier: &mut V,
    ) -> Result<(), GlobalThresholdBeaconVerificationError<V::Resource>> {
        self.validate_bounds()?;
        validate_dkg_generators(self.session, self.generator_h, self.generator_v)?;
        if self
            .recipient_keys
            .windows(2)
            .any(|pair| pair[0].recipient_index >= pair[1].recipient_index)
        {
            return Err(GlobalThresholdBeaconError::InvalidDkgRecipientKey.into());
        }
        for (position, key) in self.recipient_keys.iter().enumerate() {
            verify_global_threshold_beacon_dkg_recipient_key_v1_with(self.session, key, verifier)?;
            if self.recipient_keys[..position].iter().any(|existing| {
                existing.validator == key.validator
                    || (existing.x25519_public_key == key.x25519_public_key
                        && existing.mlkem768_public_key == key.mlkem768_public_key)
            }) {
                return Err(GlobalThresholdBeaconError::InvalidDkgRecipientKey.into());
            }
        }
        if self.recipient_keys.len() == usize::from(self.session.committee_size)
            && *iroha_crypto::HashOf::new(&RecipientRoster(self.recipient_keys)).as_ref()
                != self.session.roster_hash
        {
            return Err(GlobalThresholdBeaconError::InvalidDkgRecipientKey.into());
        }
        if self
            .dealer_commitments
            .windows(2)
            .any(|pair| pair[0].dealer_index >= pair[1].dealer_index)
        {
            return Err(GlobalThresholdBeaconError::DealerCommitmentEquivocation.into());
        }
        for dealer in self.dealer_commitments {
            validate_participant(self.session, dealer.dealer_index)?;
            let key = self
                .recipient_keys
                .binary_search_by_key(&dealer.dealer_index, |key| key.recipient_index)
                .map(|index| &self.recipient_keys[index])
                .map_err(|_| GlobalThresholdBeaconError::DealerCommitmentEquivocation)?;
            verify_global_threshold_beacon_dkg_dealer_commitment_signature_v1_with(
                self.session,
                key,
                dealer,
                verifier,
            )?;
        }
        if self.encrypted_shares.windows(2).any(|pair| {
            (pair[0].dealer_index, pair[0].recipient_index)
                >= (pair[1].dealer_index, pair[1].recipient_index)
        }) {
            return Err(GlobalThresholdBeaconError::InvalidDkgEncryptedShare.into());
        }
        for edge in self.encrypted_shares {
            let dealer = self
                .dealer_commitments
                .binary_search_by_key(&edge.dealer_index, |dealer| dealer.dealer_index)
                .map(|index| &self.dealer_commitments[index])
                .map_err(|_| GlobalThresholdBeaconError::InvalidDkgEncryptedShare)?;
            let dealer_key = self
                .recipient_keys
                .binary_search_by_key(&edge.dealer_index, |key| key.recipient_index)
                .map(|index| &self.recipient_keys[index])
                .map_err(|_| GlobalThresholdBeaconError::InvalidDkgEncryptedShare)?;
            let recipient_key = self
                .recipient_keys
                .binary_search_by_key(&edge.recipient_index, |key| key.recipient_index)
                .map(|index| &self.recipient_keys[index])
                .map_err(|_| GlobalThresholdBeaconError::InvalidDkgEncryptedShare)?;
            verify_global_threshold_beacon_dkg_encrypted_share_v1_with(
                self.session,
                dealer,
                dealer_key,
                recipient_key,
                edge,
                verifier,
            )?;
            if edge.delivery_height > self.last_updated_height {
                return Err(GlobalThresholdBeaconError::InvalidDkgEncryptedShare.into());
            }
        }
        if self.share_acceptances.windows(2).any(|pair| {
            (pair[0].dealer_index, pair[0].recipient_index)
                >= (pair[1].dealer_index, pair[1].recipient_index)
        }) {
            return Err(GlobalThresholdBeaconError::InvalidDkgShareAcceptance.into());
        }
        for acceptance in self.share_acceptances {
            let dealer = self
                .dealer_commitments
                .binary_search_by_key(&acceptance.dealer_index, |dealer| dealer.dealer_index)
                .map(|index| &self.dealer_commitments[index])
                .map_err(|_| GlobalThresholdBeaconError::InvalidDkgShareAcceptance)?;
            let recipient = self
                .recipient_keys
                .binary_search_by_key(&acceptance.recipient_index, |key| key.recipient_index)
                .map(|index| &self.recipient_keys[index])
                .map_err(|_| GlobalThresholdBeaconError::InvalidDkgShareAcceptance)?;
            let edge = self
                .encrypted_shares
                .binary_search_by_key(
                    &(acceptance.dealer_index, acceptance.recipient_index),
                    |edge| (edge.dealer_index, edge.recipient_index),
                )
                .map(|index| &self.encrypted_shares[index])
                .map_err(|_| GlobalThresholdBeaconError::InvalidDkgShareAcceptance)?;
            if acceptance.encrypted_share_hash
                != global_threshold_beacon_dkg_encrypted_share_hash_v1(self.session, edge)
                || acceptance.accepted_height > self.last_updated_height
            {
                return Err(GlobalThresholdBeaconError::InvalidDkgShareAcceptance.into());
            }
            verify_global_threshold_beacon_dkg_share_acceptance_v1_with(
                self.session,
                dealer,
                recipient,
                acceptance,
                verifier,
            )?;
        }
        if ((!self.recipient_keys.is_empty() || !self.dealer_commitments.is_empty())
            && self.last_updated_height < self.session.start_height)
            || (!self.encrypted_shares.is_empty()
                && self.last_updated_height < self.session.commitments_end_height)
            || (!self.share_acceptances.is_empty()
                && self.last_updated_height < self.session.deliveries_end_height)
        {
            return Err(GlobalThresholdBeaconError::NonMonotonicDkgState.into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::beacon::fixtures::adaptive_beacon_fixture;

    #[test]
    fn beacon_verification_reserves_exact_buffers_and_refuses_before_unfunded_work() {
        use crate::{
            beacon::GlobalThresholdBeaconSessionError, test_allocations::allocations_during,
        };
        use iroha_allocation::{AllocationBudget, AllocationRefusal};

        let fixture = adaptive_beacon_fixture();
        let source = fixture.session.record();
        let empty = AllocationBudget::new(0);
        let error = validate_global_threshold_beacon_session_v1(source, &fixture.binding, &empty)
            .unwrap_err();
        let GlobalThresholdBeaconSessionError::Admission(AllocationRefusal::ExceedsLimit {
            requested_bytes: total,
            limit_bytes: 0,
        }) = error
        else {
            panic!("actual complete original-pool demand")
        };
        let pool = AllocationBudget::new(total);
        let mut short = pool.try_reserve_bytes(total - 1).unwrap();
        let mut result = None;
        assert_eq!(
            allocations_during(|| {
                result = Some(
                    validate_global_threshold_beacon_session_from_reservation_v1(
                        source,
                        &fixture.binding,
                        &pool,
                        &mut short,
                    ),
                );
            }),
            0,
            "no verifier, graph or control may allocate before complete admission"
        );
        assert!(
            matches!(result.unwrap(), Err(GlobalThresholdBeaconSessionError::Reservation(iroha_allocation::InsufficientReservation { requested_bytes, remaining_bytes })) if requested_bytes == total && remaining_bytes == total - 1)
        );
        assert_eq!(short.remaining_bytes(), total - 1);
        assert_eq!(pool.reserved_bytes(), total - 1);
        drop(short);
        let mut exact = pool.try_reserve_bytes(total).unwrap();
        let verified = validate_global_threshold_beacon_session_from_reservation_v1(
            source,
            &fixture.binding,
            &pool,
            &mut exact,
        )
        .expect("same source and exact original physical admission");
        assert_eq!(exact.remaining_bytes(), 0);
        assert!(verified.belongs_to(&pool));
        assert_eq!(verified.record(), source);
        assert_eq!(pool.reserved_bytes(), verified.retained_allocation_bytes());
        drop(verified);
        assert_eq!(pool.reserved_bytes(), 0);
    }

    fn snapshot(
        transcript: &GlobalThresholdBeaconDkgTranscriptV1,
    ) -> GlobalThresholdBeaconDkgSnapshotV1 {
        GlobalThresholdBeaconDkgSnapshotV1 {
            session: transcript.session,
            generator_h: transcript.generator_h,
            generator_v: transcript.generator_v,
            recipient_keys: transcript.recipient_keys.clone(),
            dealer_commitments: transcript.dealer_commitments.clone(),
            encrypted_shares: transcript.encrypted_shares.clone(),
            share_acceptances: transcript.share_acceptances.clone(),
            last_updated_height: transcript.finalized_at_height,
        }
    }

    #[test]
    fn snapshot_and_transcript_views_borrow_the_original_graph() {
        let fixture = adaptive_beacon_fixture();
        let transcript = &fixture.session.record().adaptive_dkg;
        let view = DkgSnapshotRef::from(transcript);
        assert!(core::ptr::eq(
            view.recipient_keys,
            transcript.recipient_keys.as_slice()
        ));
        assert!(core::ptr::eq(
            view.encrypted_shares,
            transcript.encrypted_shares.as_slice()
        ));
        view.validate().expect("original signed transcript");
        let owned = snapshot(transcript);
        let view = DkgSnapshotRef::from(&owned);
        assert!(core::ptr::eq(
            view.dealer_commitments,
            owned.dealer_commitments.as_slice()
        ));
        assert!(core::ptr::eq(
            view.share_acceptances,
            owned.share_acceptances.as_slice()
        ));
        view.validate().expect("same authenticated snapshot");
    }

    #[test]
    fn snapshot_bounds_precede_preimages_and_generator_verification() {
        let fixture = adaptive_beacon_fixture();
        let original = snapshot(&fixture.session.record().adaptive_dkg);
        original.validate().expect("original signed graph");
        let mut invalid = original.clone();
        invalid.generator_h = [0; 96];
        invalid.encrypted_shares[0].mlkem768_ciphertext.push(0);
        assert_eq!(
            invalid.validate(),
            Err(GlobalThresholdBeaconError::InvalidDkgEncryptedShare)
        );
        let mut invalid = original.clone();
        invalid.recipient_keys[0].mlkem768_public_key.push(0);
        assert_eq!(
            invalid.validate(),
            Err(GlobalThresholdBeaconError::InvalidDkgRecipientKey)
        );
        let mut invalid = original.clone();
        invalid.dealer_commitments[0]
            .coefficient_commitments
            .push([0; 96]);
        assert_eq!(
            invalid.validate(),
            Err(GlobalThresholdBeaconError::DealerCommitmentEquivocation)
        );
        let mut invalid = original.clone();
        invalid.encrypted_shares[0].encrypted_share.push(0);
        assert_eq!(
            invalid.validate(),
            Err(GlobalThresholdBeaconError::InvalidDkgEncryptedShare)
        );
        let mut invalid = original;
        invalid
            .share_acceptances
            .push(invalid.share_acceptances[0].clone());
        assert_eq!(
            invalid.validate(),
            Err(GlobalThresholdBeaconError::InvalidDkgShareAcceptance)
        );
    }

    #[test]
    fn borrowed_snapshot_lookup_rejects_reordering_duplicates_and_missing_sources() {
        let fixture = adaptive_beacon_fixture();
        let original = snapshot(&fixture.session.record().adaptive_dkg);
        let mut invalid = original.clone();
        invalid.recipient_keys.swap(0, 1);
        assert_eq!(
            invalid.validate(),
            Err(GlobalThresholdBeaconError::InvalidDkgRecipientKey)
        );
        let mut invalid = original.clone();
        invalid.dealer_commitments.swap(0, 1);
        assert_eq!(
            invalid.validate(),
            Err(GlobalThresholdBeaconError::DealerCommitmentEquivocation)
        );
        let mut invalid = original.clone();
        invalid.encrypted_shares.swap(0, 1);
        assert_eq!(
            invalid.validate(),
            Err(GlobalThresholdBeaconError::InvalidDkgEncryptedShare)
        );
        let mut invalid = original.clone();
        invalid.share_acceptances.swap(0, 1);
        assert_eq!(
            invalid.validate(),
            Err(GlobalThresholdBeaconError::InvalidDkgShareAcceptance)
        );
        let mut invalid = original.clone();
        invalid.encrypted_shares[1] = invalid.encrypted_shares[0].clone();
        assert_eq!(
            invalid.validate(),
            Err(GlobalThresholdBeaconError::InvalidDkgEncryptedShare)
        );
        let mut invalid = original;
        invalid.encrypted_shares.remove(0);
        assert_eq!(
            invalid.validate(),
            Err(GlobalThresholdBeaconError::InvalidDkgShareAcceptance)
        );
    }

    #[test]
    fn sharing_verified_session_preserves_its_original_record_buffers() {
        let fixture = adaptive_beacon_fixture();
        let before = fixture.session.record();
        let expected = before.clone();
        let recipients = before.adaptive_dkg.recipient_keys.as_ptr();
        let edges = before.adaptive_dkg.encrypted_shares.as_ptr();
        let public_shares = before.public_shares.as_ptr();
        let reader = fixture.session.clone();
        assert!(reader.ptr_eq(&fixture.session));
        drop(fixture.session);
        let record = reader.record();
        assert_eq!(record, &expected);
        assert_eq!(record.adaptive_dkg.recipient_keys.as_ptr(), recipients);
        assert_eq!(record.adaptive_dkg.encrypted_shares.as_ptr(), edges);
        assert_eq!(record.public_shares.as_ptr(), public_shares);
    }

    #[test]
    fn borrowed_dkg_signatures_preserve_valid_and_forged_verdicts() {
        let fixture = adaptive_beacon_fixture();
        let transcript = &fixture.session.record().adaptive_dkg;
        let session = &transcript.session;
        let key = &transcript.recipient_keys[0];
        let dealer = &transcript.dealer_commitments[0];
        let edge = &transcript.encrypted_shares[0];
        let acceptance = &transcript.share_acceptances[0];
        assert_eq!(
            (dealer.dealer_index, edge.dealer_index, edge.recipient_index),
            (1, 1, 1)
        );
        assert_eq!(
            (acceptance.dealer_index, acceptance.recipient_index),
            (1, 1)
        );
        // Warm the ordinary positive cache, then exercise the borrowed boundary
        // against the same canonical preimages and independently signed substitutions.
        for (signature, preimage) in [
            (
                &key.signature,
                global_threshold_beacon_dkg_recipient_key_preimage_v1(session, key),
            ),
            (
                &dealer.signature,
                global_threshold_beacon_dkg_dealer_commitment_preimage_v1(session, dealer),
            ),
            (
                &edge.signature,
                global_threshold_beacon_dkg_encrypted_share_preimage_v1(session, edge),
            ),
            (
                &acceptance.signature,
                global_threshold_beacon_dkg_share_acceptance_preimage_v1(session, acceptance),
            ),
        ] {
            signature
                .verify(key.validator.public_key(), &preimage)
                .expect("ordinary signed preimage");
            iroha_crypto::verify_signature_borrowed(
                signature,
                key.validator.public_key(),
                &preimage,
            )
            .expect("same uncached canonical relation");
        }
        verify_global_threshold_beacon_dkg_recipient_key_v1(session, key)
            .expect("signed recipient");
        verify_global_threshold_beacon_dkg_dealer_commitment_signature_v1(session, key, dealer)
            .expect("signed commitment");
        verify_global_threshold_beacon_dkg_encrypted_share_v1(session, dealer, key, key, edge)
            .expect("signed edge");
        verify_global_threshold_beacon_dkg_share_acceptance_v1(session, dealer, key, acceptance)
            .expect("signed acceptance");
        let mut forged = key.clone();
        forged.signature = transcript.recipient_keys[1].signature.clone();
        assert_eq!(
            verify_global_threshold_beacon_dkg_recipient_key_v1(session, &forged),
            Err(GlobalThresholdBeaconError::InvalidDkgRecipientKey)
        );
        let mut forged = dealer.clone();
        forged.signature = transcript.dealer_commitments[1].signature.clone();
        assert_eq!(
            verify_global_threshold_beacon_dkg_dealer_commitment_signature_v1(
                session, key, &forged
            ),
            Err(GlobalThresholdBeaconError::DealerCommitmentEquivocation)
        );
        let mut forged = edge.clone();
        forged.signature = transcript.encrypted_shares[1].signature.clone();
        assert_eq!(
            verify_global_threshold_beacon_dkg_encrypted_share_v1(
                session, dealer, key, key, &forged
            ),
            Err(GlobalThresholdBeaconError::InvalidDkgEncryptedShare)
        );
        let mut forged = acceptance.clone();
        forged.signature = transcript.share_acceptances[1].signature.clone();
        assert_eq!(
            verify_global_threshold_beacon_dkg_share_acceptance_v1(session, dealer, key, &forged),
            Err(GlobalThresholdBeaconError::InvalidDkgShareAcceptance)
        );
    }

    #[test]
    fn streamed_dkg_records_and_exact_signature_buffers_preserve_original_bytes() {
        let fixture = adaptive_beacon_fixture();
        let transcript = &fixture.session.record().adaptive_dkg;
        let session = &transcript.session;
        let key = &transcript.recipient_keys[0];
        let dealer = &transcript.dealer_commitments[0];
        let edge = &transcript.encrypted_shares[0];
        let acceptance = &transcript.share_acceptances[0];
        for (domain, original, hash) in [
            (
                b"iroha.global-threshold-beacon.dkg-recipient-key-hash.v1\0".as_slice(),
                key.encode(),
                global_threshold_beacon_dkg_recipient_key_hash_v1(session, key),
            ),
            (
                b"iroha.global-threshold-beacon.dkg-dealer.v1\0".as_slice(),
                dealer.encode(),
                global_threshold_beacon_dkg_dealer_commitment_hash_v1(session, dealer),
            ),
            (
                b"iroha.global-threshold-beacon.dkg-encrypted-share-hash.v1\0".as_slice(),
                edge.encode(),
                global_threshold_beacon_dkg_encrypted_share_hash_v1(session, edge),
            ),
        ] {
            assert_eq!(
                hash,
                *Hash::new_from_chunks(&[domain, &session.encode(), &original]).as_ref()
            );
        }
        let mut recipient = b"iroha.global-threshold-beacon.dkg-recipient-key.v1\0".to_vec();
        recipient.extend_from_slice(&session.encode());
        recipient.extend_from_slice(&key.recipient_index.to_be_bytes());
        recipient.extend_from_slice(&key.validator.encode());
        recipient.extend_from_slice(&key.x25519_public_key);
        recipient.extend_from_slice(&key.mlkem768_public_key.encode());
        let mut commitment = b"iroha.global-threshold-beacon.dkg-dealer-commitment.v1\0".to_vec();
        commitment.extend_from_slice(&session.encode());
        commitment.extend_from_slice(&dealer.dealer_index.to_be_bytes());
        commitment.extend_from_slice(&dealer.coefficient_commitments.encode());
        commitment.extend_from_slice(&dealer.constant_term_proof.encode());
        let mut aad = b"iroha.global-threshold-beacon.dkg-private-edge.v1\0".to_vec();
        aad.extend_from_slice(&session.encode());
        aad.extend_from_slice(&edge.dealer_index.to_be_bytes());
        aad.extend_from_slice(&edge.recipient_index.to_be_bytes());
        aad.extend_from_slice(&edge.dealer_commitment_hash);
        aad.extend_from_slice(&edge.recipient_key_hash);
        aad.extend_from_slice(&edge.delivery_height.to_be_bytes());
        let mut encrypted = aad.clone();
        encrypted.extend_from_slice(&edge.ephemeral_x25519_public_key);
        encrypted.extend_from_slice(&edge.mlkem768_ciphertext.encode());
        encrypted.extend_from_slice(&edge.encrypted_share.encode());
        let mut accepted = b"iroha.global-threshold-beacon.dkg-share-acceptance.v1\0".to_vec();
        accepted.extend_from_slice(&session.encode());
        accepted.extend_from_slice(&acceptance.dealer_index.to_be_bytes());
        accepted.extend_from_slice(&acceptance.recipient_index.to_be_bytes());
        accepted.extend_from_slice(&acceptance.dealer_commitment_hash);
        accepted.extend_from_slice(&acceptance.encrypted_share_hash);
        accepted.extend_from_slice(&acceptance.accepted_height.to_be_bytes());
        for (actual, expected) in [
            (
                global_threshold_beacon_dkg_recipient_key_preimage_v1(session, key),
                recipient,
            ),
            (
                global_threshold_beacon_dkg_dealer_commitment_preimage_v1(session, dealer),
                commitment,
            ),
            (
                global_threshold_beacon_dkg_private_edge_aad_v1(session, edge),
                aad,
            ),
            (
                global_threshold_beacon_dkg_encrypted_share_preimage_v1(session, edge),
                encrypted,
            ),
            (
                global_threshold_beacon_dkg_share_acceptance_preimage_v1(session, acceptance),
                accepted,
            ),
        ] {
            assert_eq!(actual, expected);
            assert_eq!(
                actual.capacity(),
                actual.len(),
                "only one exact output backing"
            );
        }
    }

    #[test]
    fn streamed_beacon_hashes_preserve_every_canonical_preimage_byte() {
        let fixture = adaptive_beacon_fixture();
        let transcript = &fixture.session.record().adaptive_dkg;
        let owned_roster = transcript
            .recipient_keys
            .iter()
            .map(|key| key.validator.clone())
            .collect::<Vec<_>>();
        assert_eq!(
            ElementSequence(&owned_roster).encode(),
            owned_roster.encode()
        );
        assert_eq!(
            RecipientRoster(&transcript.recipient_keys).encode(),
            owned_roster.encode()
        );
        assert_eq!(
            global_threshold_beacon_roster_hash_v1(&owned_roster),
            *iroha_crypto::HashOf::new(&owned_roster).as_ref()
        );
        let projected = transcript.recipient_keys.iter().map(|key| &key.validator);
        assert_eq!(
            RosterIter(projected.clone()).encode(),
            owned_roster.encode()
        );
        assert_eq!(
            global_threshold_beacon_roster_hash_iter_v1(projected),
            global_threshold_beacon_roster_hash_v1(&owned_roster)
        );
        let empty: Vec<PeerId> = Vec::new();
        assert_eq!(ElementSequence(&empty).encode(), empty.encode());
        assert_eq!(
            global_threshold_beacon_roster_hash_iter_v1(empty.iter()),
            global_threshold_beacon_roster_hash_v1(&empty)
        );
        let borrowed = DkgEventPreimage {
            session: &transcript.session,
            generator_h: &transcript.generator_h,
            generator_v: &transcript.generator_v,
            recipient_keys: &transcript.recipient_keys,
            dealer_commitments: &transcript.dealer_commitments,
            encrypted_shares: &transcript.encrypted_shares,
            share_acceptances: &transcript.share_acceptances,
            qualified_dealers: &transcript.qualified_dealers,
            finalized_at_height: transcript.finalized_at_height,
        };
        // Reproduce the specified concatenation independently of the streaming adapter.
        let mut expected = b"iroha.global-threshold-beacon.dkg-events.v1\0".to_vec();
        expected.extend_from_slice(&transcript.session.encode());
        expected.extend_from_slice(&transcript.generator_h);
        expected.extend_from_slice(&transcript.generator_v);
        expected.extend_from_slice(&transcript.recipient_keys.encode());
        expected.extend_from_slice(&transcript.dealer_commitments.encode());
        expected.extend_from_slice(&transcript.encrypted_shares.encode());
        expected.extend_from_slice(&transcript.share_acceptances.encode());
        expected.extend_from_slice(&transcript.qualified_dealers.encode());
        expected.extend_from_slice(&transcript.finalized_at_height.to_be_bytes());
        assert_eq!(borrowed.encode(), expected);
        assert_eq!(
            *iroha_crypto::HashOf::new(&borrowed).as_ref(),
            *Hash::new(&expected).as_ref()
        );
        assert_eq!(*Hash::new(&expected).as_ref(), transcript.event_hash);
    }
}

#[cfg(test)]
#[path = "validation/hybrid_borrow_tests.rs"]
mod hybrid_borrow_tests;
