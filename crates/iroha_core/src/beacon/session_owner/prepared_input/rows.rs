//! Prepared canonical row destinations; no nested owner is extracted during decoding.

use super::*;
use common::*;

macro_rules! inline_field {
    ($owner:ty, $index:literal, $field:ident, [u8; $length:expr]) => {
        impl DecodeField<$index, [u8; $length]> for $owner {
            type Value = ();
            fn decode_field(
                &mut self,
                field: CanonicalField<'_, [u8; $length]>,
            ) -> DecodeResult<()> {
                self.$field = field.decode_owned()?;
                Ok(())
            }
        }
    };
    ($owner:ty, $index:literal, $field:ident, $ty:ty) => {
        impl DecodeField<$index, $ty> for $owner {
            type Value = ();
            fn decode_field(&mut self, field: CanonicalField<'_, $ty>) -> DecodeResult<()> {
                self.$field = field.with_payload(<$ty as inline::InlineValue>::decode_payload)?;
                Ok(())
            }
        }
    };
}
macro_rules! bytes_field {
    ($owner:ty, $index:literal, $field:ident) => {
        impl DecodeField<$index, Vec<u8>> for $owner {
            type Value = ();
            fn decode_field(&mut self, field: CanonicalField<'_, Vec<u8>>) -> DecodeResult<()> {
                field.with_payload(|bytes| self.$field.decode(bytes))
            }
        }
    };
}
macro_rules! signature_field {
    ($owner:ty, $index:literal) => {
        impl DecodeField<$index, Signature> for $owner {
            type Value = ();
            fn decode_field(&mut self, field: CanonicalField<'_, Signature>) -> DecodeResult<()> {
                field.with_payload(|bytes| {
                    self.signature.decode_payload(bytes).map_err(|error| {
                        crypto_error(
                            error,
                            iroha_crypto::Algorithm::BlsNormal.signature_payload_len(),
                        )
                    })
                })
            }
        }
    };
}

pub(super) trait Row: SerializePayload + Sized {
    type Wire: SerializePayload + for<'de> norito::DeserializePayload<'de>;
    fn decode(&mut self, bytes: &[u8]) -> DecodeResult<()>;
    fn reset(&mut self);
    fn ready(&self) -> bool;
}

pub(super) struct Peer {
    pub(super) key: PreparedPublicKeyDecode,
    width: usize,
    ready: bool,
}
impl Peer {
    fn new(source: &PublicKey, budget: &AllocationBudget) -> Result<Self, SessionGraphError> {
        Ok(Self {
            key: public_key(source, budget)?,
            width: source.retained_allocation_layout().size(),
            ready: false,
        })
    }
    fn decode(&mut self, bytes: &[u8]) -> DecodeResult<()> {
        self.reset();
        let (_, used) = PeerId::decode_fields(bytes, self)?;
        complete(used, bytes)?;
        self.ready = true;
        Ok(())
    }
    fn reset(&mut self) {
        self.ready = false;
        self.key.reset();
    }
}
impl FieldDestination for Peer {
    type Error = DestinationError;
}
impl DecodeField<0, PublicKey> for Peer {
    type Value = ();
    fn decode_field(&mut self, field: CanonicalField<'_, PublicKey>) -> DecodeResult<()> {
        field.with_payload(|bytes| {
            self.key
                .decode_payload(bytes)
                .map_err(|error| crypto_error(error, self.width))
        })?;
        let bytes = self
            .key
            .decoded_compact()
            .ok_or(DecodeIntoError::Destination(DestinationError::PlanChanged))?;
        if bytes
            .first()
            .copied()
            .and_then(|tag| iroha_crypto::Algorithm::try_from(tag).ok())
            != Some(iroha_crypto::Algorithm::BlsNormal)
        {
            return Err(norito::Error::InvalidValue {
                context: "DKG seat requires a canonical BLS normal key",
            }
            .into());
        }
        Ok(())
    }
}
impl SerializePayload for Peer {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), norito::Error> {
        #[derive(norito::NoritoSerialize)]
        struct View<'a> {
            public_key: PayloadRef<'a, PreparedPublicKeyDecode>,
        }
        if !self.ready {
            return Err(norito::Error::InvalidValue {
                context: "unfinished prepared DKG peer",
            });
        }
        View {
            public_key: PayloadRef(&self.key),
        }
        .serialize(writer)
    }
}

pub(super) struct Recipient {
    pub(super) recipient_index: u16,
    pub(super) validator: Peer,
    pub(super) x25519_public_key: [u8; 32],
    pub(super) mlkem768_public_key: Bytes,
    pub(super) signature: PreparedSignatureDecode,
    ready: bool,
}
impl Recipient {
    pub(super) fn new(
        source: &PublicKey,
        budget: &AllocationBudget,
    ) -> Result<Self, SessionGraphError> {
        Ok(Self {
            recipient_index: 0,
            validator: Peer::new(source, budget)?,
            x25519_public_key: [0; 32],
            mlkem768_public_key: Bytes::new(
                soranet_pq::MlKemSuite::MlKem768.public_key_len(),
                budget,
            )?,
            signature: signature(budget)?,
            ready: false,
        })
    }
}
impl FieldDestination for Recipient {
    type Error = DestinationError;
}
inline_field!(Recipient, 0, recipient_index, u16);
impl DecodeField<1, PeerId> for Recipient {
    type Value = ();
    fn decode_field(&mut self, field: CanonicalField<'_, PeerId>) -> DecodeResult<()> {
        field.with_payload(|bytes| self.validator.decode(bytes))
    }
}
inline_field!(Recipient, 2, x25519_public_key, [u8; 32]);
bytes_field!(Recipient, 3, mlkem768_public_key);
signature_field!(Recipient, 4);
impl Row for Recipient {
    type Wire = GlobalThresholdBeaconDkgRecipientKeyV1;
    fn decode(&mut self, bytes: &[u8]) -> DecodeResult<()> {
        self.reset();
        let (_, used) = GlobalThresholdBeaconDkgRecipientKeyV1::decode_fields(bytes, self)?;
        complete(used, bytes)?;
        self.ready = true;
        Ok(())
    }
    fn reset(&mut self) {
        self.ready = false;
        self.validator.reset();
        self.mlkem768_public_key.reset();
        self.signature.reset();
    }
    fn ready(&self) -> bool {
        self.ready
    }
}
impl SerializePayload for Recipient {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), norito::Error> {
        #[derive(norito::NoritoSerialize)]
        struct View<'a> {
            recipient_index: u16,
            validator: PayloadRef<'a, Peer>,
            x25519_public_key: [u8; 32],
            mlkem768_public_key: PayloadRef<'a, Bytes>,
            signature: PayloadRef<'a, PreparedSignatureDecode>,
        }
        if !self.ready {
            return Err(norito::Error::InvalidValue {
                context: "unfinished prepared DKG row",
            });
        }
        View {
            recipient_index: self.recipient_index,
            validator: PayloadRef(&self.validator),
            x25519_public_key: self.x25519_public_key,
            mlkem768_public_key: PayloadRef(&self.mlkem768_public_key),
            signature: PayloadRef(&self.signature),
        }
        .serialize(writer)
    }
}

pub(super) struct Dealer {
    pub(super) dealer_index: u16,
    pub(super) coefficient_commitments: CopySequence<[u8; 96]>,
    pub(super) constant_term_proof: GlobalThresholdBeaconDkgConstantProofV1,
    pub(super) signature: PreparedSignatureDecode,
    ready: bool,
}
impl Dealer {
    pub(super) fn new(
        threshold: u16,
        budget: &AllocationBudget,
    ) -> Result<Self, SessionGraphError> {
        Ok(Self {
            dealer_index: 0,
            coefficient_commitments: CopySequence::new(usize::from(threshold), [0; 96], budget)?,
            constant_term_proof: GlobalThresholdBeaconDkgConstantProofV1 {
                commitment: [0; 96],
                response: [0; 32],
            },
            signature: signature(budget)?,
            ready: false,
        })
    }
}
impl FieldDestination for Dealer {
    type Error = DestinationError;
}
inline_field!(Dealer, 0, dealer_index, u16);
impl DecodeField<1, Vec<[u8; 96]>> for Dealer {
    type Value = ();
    fn decode_field(&mut self, field: CanonicalField<'_, Vec<[u8; 96]>>) -> DecodeResult<()> {
        field.with_payload(|bytes| self.coefficient_commitments.decode(bytes))
    }
}
inline_field!(
    Dealer,
    2,
    constant_term_proof,
    GlobalThresholdBeaconDkgConstantProofV1
);
signature_field!(Dealer, 3);
impl Row for Dealer {
    type Wire = GlobalThresholdBeaconDkgDealerCommitmentV1;
    fn decode(&mut self, bytes: &[u8]) -> DecodeResult<()> {
        self.reset();
        let (_, used) = GlobalThresholdBeaconDkgDealerCommitmentV1::decode_fields(bytes, self)?;
        complete(used, bytes)?;
        self.ready = true;
        Ok(())
    }
    fn reset(&mut self) {
        self.ready = false;
        self.coefficient_commitments.reset();
        self.signature.reset();
    }
    fn ready(&self) -> bool {
        self.ready
    }
}
impl SerializePayload for Dealer {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), norito::Error> {
        #[derive(norito::NoritoSerialize)]
        struct View<'a> {
            dealer_index: u16,
            coefficient_commitments: PayloadRef<'a, CopySequence<[u8; 96]>>,
            constant_term_proof: GlobalThresholdBeaconDkgConstantProofV1,
            signature: PayloadRef<'a, PreparedSignatureDecode>,
        }
        if !self.ready {
            return Err(norito::Error::InvalidValue {
                context: "unfinished prepared DKG row",
            });
        }
        View {
            dealer_index: self.dealer_index,
            coefficient_commitments: PayloadRef(&self.coefficient_commitments),
            constant_term_proof: self.constant_term_proof,
            signature: PayloadRef(&self.signature),
        }
        .serialize(writer)
    }
}

pub(super) struct Edge {
    pub(super) dealer_index: u16,
    pub(super) recipient_index: u16,
    pub(super) dealer_commitment_hash: [u8; 32],
    pub(super) recipient_key_hash: [u8; 32],
    pub(super) delivery_height: u64,
    pub(super) ephemeral_x25519_public_key: [u8; 32],
    pub(super) mlkem768_ciphertext: Bytes,
    pub(super) encrypted_share: Bytes,
    pub(super) signature: PreparedSignatureDecode,
    ready: bool,
}
impl Edge {
    pub(super) fn new(budget: &AllocationBudget) -> Result<Self, SessionGraphError> {
        Ok(Self {
            dealer_index: 0,
            recipient_index: 0,
            dealer_commitment_hash: [0; 32],
            recipient_key_hash: [0; 32],
            delivery_height: 0,
            ephemeral_x25519_public_key: [0; 32],
            mlkem768_ciphertext: Bytes::new(
                soranet_pq::MlKemSuite::MlKem768.ciphertext_len(),
                budget,
            )?,
            encrypted_share: Bytes::new(
                iroha_crypto::threshold_bls::DAS_REN_PRIVATE_SHARE_CIPHERTEXT_BYTES_V1,
                budget,
            )?,
            signature: signature(budget)?,
            ready: false,
        })
    }
}
impl FieldDestination for Edge {
    type Error = DestinationError;
}
inline_field!(Edge, 0, dealer_index, u16);
inline_field!(Edge, 1, recipient_index, u16);
inline_field!(Edge, 2, dealer_commitment_hash, [u8; 32]);
inline_field!(Edge, 3, recipient_key_hash, [u8; 32]);
inline_field!(Edge, 4, delivery_height, u64);
inline_field!(Edge, 5, ephemeral_x25519_public_key, [u8; 32]);
bytes_field!(Edge, 6, mlkem768_ciphertext);
bytes_field!(Edge, 7, encrypted_share);
signature_field!(Edge, 8);
impl Row for Edge {
    type Wire = GlobalThresholdBeaconDkgEncryptedShareV1;
    fn decode(&mut self, bytes: &[u8]) -> DecodeResult<()> {
        self.reset();
        let (_, used) = GlobalThresholdBeaconDkgEncryptedShareV1::decode_fields(bytes, self)?;
        complete(used, bytes)?;
        self.ready = true;
        Ok(())
    }
    fn reset(&mut self) {
        self.ready = false;
        self.mlkem768_ciphertext.reset();
        self.encrypted_share.reset();
        self.signature.reset();
    }
    fn ready(&self) -> bool {
        self.ready
    }
}
impl SerializePayload for Edge {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), norito::Error> {
        #[derive(norito::NoritoSerialize)]
        struct View<'a> {
            dealer_index: u16,
            recipient_index: u16,
            dealer_commitment_hash: [u8; 32],
            recipient_key_hash: [u8; 32],
            delivery_height: u64,
            ephemeral_x25519_public_key: [u8; 32],
            mlkem768_ciphertext: PayloadRef<'a, Bytes>,
            encrypted_share: PayloadRef<'a, Bytes>,
            signature: PayloadRef<'a, PreparedSignatureDecode>,
        }
        if !self.ready {
            return Err(norito::Error::InvalidValue {
                context: "unfinished prepared DKG row",
            });
        }
        View {
            dealer_index: self.dealer_index,
            recipient_index: self.recipient_index,
            dealer_commitment_hash: self.dealer_commitment_hash,
            recipient_key_hash: self.recipient_key_hash,
            delivery_height: self.delivery_height,
            ephemeral_x25519_public_key: self.ephemeral_x25519_public_key,
            mlkem768_ciphertext: PayloadRef(&self.mlkem768_ciphertext),
            encrypted_share: PayloadRef(&self.encrypted_share),
            signature: PayloadRef(&self.signature),
        }
        .serialize(writer)
    }
}

pub(super) struct Acceptance {
    pub(super) dealer_index: u16,
    pub(super) recipient_index: u16,
    pub(super) dealer_commitment_hash: [u8; 32],
    pub(super) encrypted_share_hash: [u8; 32],
    pub(super) accepted_height: u64,
    pub(super) signature: PreparedSignatureDecode,
    ready: bool,
}
impl Acceptance {
    pub(super) fn new(budget: &AllocationBudget) -> Result<Self, SessionGraphError> {
        Ok(Self {
            dealer_index: 0,
            recipient_index: 0,
            dealer_commitment_hash: [0; 32],
            encrypted_share_hash: [0; 32],
            accepted_height: 0,
            signature: signature(budget)?,
            ready: false,
        })
    }
}
impl FieldDestination for Acceptance {
    type Error = DestinationError;
}
inline_field!(Acceptance, 0, dealer_index, u16);
inline_field!(Acceptance, 1, recipient_index, u16);
inline_field!(Acceptance, 2, dealer_commitment_hash, [u8; 32]);
inline_field!(Acceptance, 3, encrypted_share_hash, [u8; 32]);
inline_field!(Acceptance, 4, accepted_height, u64);
signature_field!(Acceptance, 5);
impl Row for Acceptance {
    type Wire = GlobalThresholdBeaconDkgShareAcceptanceV1;
    fn decode(&mut self, bytes: &[u8]) -> DecodeResult<()> {
        self.reset();
        let (_, used) = GlobalThresholdBeaconDkgShareAcceptanceV1::decode_fields(bytes, self)?;
        complete(used, bytes)?;
        self.ready = true;
        Ok(())
    }
    fn reset(&mut self) {
        self.ready = false;
        self.signature.reset();
    }
    fn ready(&self) -> bool {
        self.ready
    }
}
impl SerializePayload for Acceptance {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), norito::Error> {
        #[derive(norito::NoritoSerialize)]
        struct View<'a> {
            dealer_index: u16,
            recipient_index: u16,
            dealer_commitment_hash: [u8; 32],
            encrypted_share_hash: [u8; 32],
            accepted_height: u64,
            signature: PayloadRef<'a, PreparedSignatureDecode>,
        }
        if !self.ready {
            return Err(norito::Error::InvalidValue {
                context: "unfinished prepared DKG row",
            });
        }
        View {
            dealer_index: self.dealer_index,
            recipient_index: self.recipient_index,
            dealer_commitment_hash: self.dealer_commitment_hash,
            encrypted_share_hash: self.encrypted_share_hash,
            accepted_height: self.accepted_height,
            signature: PayloadRef(&self.signature),
        }
        .serialize(writer)
    }
}

#[cfg(test)]
mod tests;
