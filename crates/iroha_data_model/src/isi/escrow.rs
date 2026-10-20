use super::*;
isi! {
    /// Open a ledger-managed numeric asset escrow.
    #[norito_schema(name = "iroha_data_model::isi::escrow::OpenAssetEscrow")]
    pub struct OpenAssetEscrow {
        /// Caller-selected escrow identifier.
        pub escrow_id: crate::escrow::EscrowId,
        /// Asset definition to lock.
        pub asset_definition: crate::asset::AssetDefinitionId,
        /// Amount to lock.
        pub amount: iroha_primitives::numeric::Quantity,
        /// Evidence hashes attached when opening the escrow.
        #[norito (default)]
        pub evidence_hashes: Vec<iroha_crypto::Hash>,
    }
}
impl OpenAssetEscrow {
    /// Construct an escrow-opening instruction without initial evidence.
    #[must_use]
    pub fn new(
        escrow_id: crate::escrow::EscrowId,
        asset_definition: crate::asset::AssetDefinitionId,
        amount: impl Into<iroha_primitives::numeric::Quantity>,
    ) -> Self {
        Self {
            escrow_id,
            asset_definition,
            amount: amount.into(),
            evidence_hashes: Vec::new(),
        }
    }
    /// Construct an escrow-opening instruction with evidence hashes attached.
    #[must_use]
    pub fn with_evidence_hashes(
        escrow_id: crate::escrow::EscrowId,
        asset_definition: crate::asset::AssetDefinitionId,
        amount: impl Into<iroha_primitives::numeric::Quantity>,
        evidence_hashes: Vec<iroha_crypto::Hash>,
    ) -> Self {
        Self {
            escrow_id,
            asset_definition,
            amount: amount.into(),
            evidence_hashes,
        }
    }
}
isi! {
    /// Accept an open asset escrow as its buyer.
    #[norito_schema(name = "iroha_data_model::isi::escrow::AcceptAssetEscrow")]
    pub struct AcceptAssetEscrow {
        /// Escrow to accept.
        pub escrow_id: crate::escrow::EscrowId,
    }
}
impl AcceptAssetEscrow {
    /// Construct an escrow-acceptance instruction.
    #[must_use]
    pub const fn new(escrow_id: crate::escrow::EscrowId) -> Self {
        Self { escrow_id }
    }
}
isi! {
    /// Mark an accepted asset escrow as paid off-chain.
    #[norito_schema(name = "iroha_data_model::isi::escrow::MarkEscrowPaymentSent")]
    pub struct MarkEscrowPaymentSent {
        /// Escrow whose payment has been sent.
        pub escrow_id: crate::escrow::EscrowId,
    }
}
impl MarkEscrowPaymentSent {
    /// Construct an instruction that marks off-chain payment as sent.
    #[must_use]
    pub const fn new(escrow_id: crate::escrow::EscrowId) -> Self {
        Self { escrow_id }
    }
}
isi! {
    /// Release a paid escrow to its accepted buyer.
    #[norito_schema(name = "iroha_data_model::isi::escrow::ReleaseAssetEscrow")]
    pub struct ReleaseAssetEscrow {
        /// Escrow to release.
        pub escrow_id: crate::escrow::EscrowId,
    }
}
impl ReleaseAssetEscrow {
    /// Construct an instruction that releases escrowed funds to the buyer.
    #[must_use]
    pub const fn new(escrow_id: crate::escrow::EscrowId) -> Self {
        Self { escrow_id }
    }
}
isi! {
    /// Cancel an open or accepted escrow before payment is marked.
    #[norito_schema(name = "iroha_data_model::isi::escrow::CancelAssetEscrow")]
    pub struct CancelAssetEscrow {
        /// Escrow to cancel.
        pub escrow_id: crate::escrow::EscrowId,
    }
}
impl CancelAssetEscrow {
    /// Construct an instruction that refunds an escrow before payment is marked.
    #[must_use]
    pub const fn new(escrow_id: crate::escrow::EscrowId) -> Self {
        Self { escrow_id }
    }
}
isi! {
    /// Open a dispute for court moderation.
    #[norito_schema(name = "iroha_data_model::isi::escrow::OpenEscrowDispute")]
    pub struct OpenEscrowDispute {
        /// Escrow to dispute.
        pub escrow_id: crate::escrow::EscrowId,
        /// Evidence hashes attached by the disputing party.
        #[norito (default)]
        pub evidence_hashes: Vec<iroha_crypto::Hash>,
    }
}
impl OpenEscrowDispute {
    /// Construct an instruction that opens an escrow dispute without new evidence.
    #[must_use]
    pub fn new(escrow_id: crate::escrow::EscrowId) -> Self {
        Self {
            escrow_id,
            evidence_hashes: Vec::new(),
        }
    }
    /// Construct an instruction that opens an escrow dispute with evidence hashes.
    #[must_use]
    pub fn with_evidence_hashes(
        escrow_id: crate::escrow::EscrowId,
        evidence_hashes: Vec<iroha_crypto::Hash>,
    ) -> Self {
        Self {
            escrow_id,
            evidence_hashes,
        }
    }
}
isi! {
    /// Resolve a disputed escrow by splitting funds between buyer and seller.
    #[norito_schema(name = "iroha_data_model::isi::escrow::ResolveEscrowDispute")]
    pub struct ResolveEscrowDispute {
        /// Escrow to resolve.
        pub escrow_id: crate::escrow::EscrowId,
        /// Amount released to the accepted buyer.
        pub buyer_amount: iroha_primitives::numeric::Quantity,
        /// Amount refunded to the seller.
        pub seller_amount: iroha_primitives::numeric::Quantity,
        /// Evidence or judgement hashes attached by the resolver.
        #[norito (default)]
        pub evidence_hashes: Vec<iroha_crypto::Hash>,
    }
}
impl ResolveEscrowDispute {
    /// Construct a dispute-resolution instruction without additional evidence.
    #[must_use]
    pub fn new(
        escrow_id: crate::escrow::EscrowId,
        buyer_amount: impl Into<iroha_primitives::numeric::Quantity>,
        seller_amount: impl Into<iroha_primitives::numeric::Quantity>,
    ) -> Self {
        Self {
            escrow_id,
            buyer_amount: buyer_amount.into(),
            seller_amount: seller_amount.into(),
            evidence_hashes: Vec::new(),
        }
    }
    /// Construct a dispute-resolution instruction with evidence or judgement hashes.
    #[must_use]
    pub fn with_evidence_hashes(
        escrow_id: crate::escrow::EscrowId,
        buyer_amount: impl Into<iroha_primitives::numeric::Quantity>,
        seller_amount: impl Into<iroha_primitives::numeric::Quantity>,
        evidence_hashes: Vec<iroha_crypto::Hash>,
    ) -> Self {
        Self {
            escrow_id,
            buyer_amount: buyer_amount.into(),
            seller_amount: seller_amount.into(),
            evidence_hashes,
        }
    }
}
isi! {
    /// Open a generic ledger-managed asset lock.
    #[derive (crate :: DeriveJsonSerialize , crate :: DeriveJsonDeserialize)]
    #[norito_schema(name = "iroha_data_model::isi::escrow::OpenAssetLock")]
    pub struct OpenAssetLock {
        /// Caller-selected lock identifier.
        pub escrow_id: crate::escrow::EscrowId,
        /// Asset definition to lock.
        pub asset_definition: crate::asset::AssetDefinitionId,
        /// Account that receives drawdowns from the lock.
        pub destination: crate::account::AccountId,
        /// Amount to lock.
        pub amount: iroha_primitives::numeric::Quantity,
        /// Optional account required to draw down this lock.
        #[norito (skip_serializing_if = "Option::is_none")]
        pub release_authority: Option<crate::account::AccountId>,
        /// Optional Unix timestamp (milliseconds) after which the lock may expire.
        #[norito (skip_serializing_if = "Option::is_none")]
        pub expires_at_ms: Option<u64>,
        /// Evidence hashes attached when opening the lock.
        #[norito (default)]
        pub evidence_hashes: Vec<iroha_crypto::Hash>,
    }
}
impl OpenAssetLock {
    /// Construct a generic asset lock without initial evidence.
    #[must_use]
    pub fn new(
        escrow_id: crate::escrow::EscrowId,
        asset_definition: crate::asset::AssetDefinitionId,
        destination: crate::account::AccountId,
        amount: impl Into<iroha_primitives::numeric::Quantity>,
    ) -> Self {
        Self {
            escrow_id,
            asset_definition,
            destination,
            amount: amount.into(),
            release_authority: None,
            expires_at_ms: None,
            evidence_hashes: Vec::new(),
        }
    }
    /// Construct a generic asset lock with optional authority, expiry, and evidence.
    #[must_use]
    pub fn with_options(
        escrow_id: crate::escrow::EscrowId,
        asset_definition: crate::asset::AssetDefinitionId,
        destination: crate::account::AccountId,
        amount: impl Into<iroha_primitives::numeric::Quantity>,
        release_authority: Option<crate::account::AccountId>,
        expires_at_ms: Option<u64>,
        evidence_hashes: Vec<iroha_crypto::Hash>,
    ) -> Self {
        Self {
            escrow_id,
            asset_definition,
            destination,
            amount: amount.into(),
            release_authority,
            expires_at_ms,
            evidence_hashes,
        }
    }
}
isi! {
    /// Open an attestor-bound conditional escrow with ordered all-of release semantics.
    #[derive (crate :: DeriveJsonSerialize , crate :: DeriveJsonDeserialize)]
    #[norito_schema(name = "iroha_data_model::isi::escrow::OpenConditionalEscrow")]
    pub struct OpenConditionalEscrow {
        /// Caller-selected escrow identifier.
        pub escrow_id: crate::escrow::EscrowId,
        /// Asset definition to lock in protocol custody.
        pub asset_definition: crate::asset::AssetDefinitionId,
        /// Account that receives the full amount after every condition passes.
        pub beneficiary: crate::account::AccountId,
        /// Amount to lock.
        pub amount: iroha_primitives::numeric::Quantity,
        /// Immutable typed predicates and optional ledger-time window.
        pub conditions: Vec<crate::escrow::ConditionalEscrowCondition>,
        /// Absolute Unix timestamp (milliseconds) at or after which anyone may trigger refund.
        pub expires_at_ms: u64,
        /// Evidence hashes attached when opening the escrow.
        #[norito (default)]
        pub evidence_hashes: Vec<iroha_crypto::Hash>,
    }
}
impl OpenConditionalEscrow {
    /// Construct a native ordered all-of conditional escrow.
    #[must_use]
    pub fn new(
        escrow_id: crate::escrow::EscrowId,
        asset_definition: crate::asset::AssetDefinitionId,
        beneficiary: crate::account::AccountId,
        amount: impl Into<iroha_primitives::numeric::Quantity>,
        conditions: Vec<crate::escrow::ConditionalEscrowCondition>,
        expires_at_ms: u64,
    ) -> Self {
        Self {
            escrow_id,
            asset_definition,
            beneficiary,
            amount: amount.into(),
            conditions,
            expires_at_ms,
            evidence_hashes: Vec::new(),
        }
    }
    /// Construct a native conditional escrow with opening evidence.
    #[must_use]
    pub fn with_evidence_hashes(
        escrow_id: crate::escrow::EscrowId,
        asset_definition: crate::asset::AssetDefinitionId,
        beneficiary: crate::account::AccountId,
        amount: impl Into<iroha_primitives::numeric::Quantity>,
        conditions: Vec<crate::escrow::ConditionalEscrowCondition>,
        expires_at_ms: u64,
        evidence_hashes: Vec<iroha_crypto::Hash>,
    ) -> Self {
        Self {
            escrow_id,
            asset_definition,
            beneficiary,
            amount: amount.into(),
            conditions,
            expires_at_ms,
            evidence_hashes,
        }
    }
}
isi! {
    /// Attest the next ordered predicate of one native conditional escrow.
    #[derive (crate :: DeriveJsonSerialize , crate :: DeriveJsonDeserialize)]
    #[norito_schema(name = "iroha_data_model::isi::escrow::AttestEscrowCondition")]
    pub struct AttestEscrowCondition {
        /// Conditional escrow to update.
        pub escrow_id: crate::escrow::EscrowId,
        /// Exact immutable condition identifier.
        pub condition_id: iroha_model_base::name::Name,
        /// Typed value evaluated by the ledger.
        pub value: crate::escrow::ConditionalEscrowValue,
        /// Optional external evidence digest.
        pub evidence_hash: Option<iroha_crypto::Hash>,
    }
}
impl AttestEscrowCondition {
    /// Construct an ordered conditional-escrow attestation.
    #[must_use]
    pub const fn new(
        escrow_id: crate::escrow::EscrowId,
        condition_id: iroha_model_base::name::Name,
        value: crate::escrow::ConditionalEscrowValue,
        evidence_hash: Option<iroha_crypto::Hash>,
    ) -> Self {
        Self {
            escrow_id,
            condition_id,
            value,
            evidence_hash,
        }
    }
}
isi! {
    /// Refund a native conditional escrow whose authoritative deadline has passed.
    #[derive (crate :: DeriveJsonSerialize , crate :: DeriveJsonDeserialize)]
    #[norito_schema(name = "iroha_data_model::isi::escrow::ExpireConditionalEscrow")]
    pub struct ExpireConditionalEscrow {
        /// Conditional escrow to expire.
        pub escrow_id: crate::escrow::EscrowId,
    }
}
impl ExpireConditionalEscrow {
    /// Construct a conditional-escrow expiry instruction.
    #[must_use]
    pub const fn new(escrow_id: crate::escrow::EscrowId) -> Self {
        Self { escrow_id }
    }
}
isi! {
    /// Draw down funds from an active generic asset lock.
    #[derive (crate :: DeriveJsonSerialize , crate :: DeriveJsonDeserialize)]
    #[norito_schema(name = "iroha_data_model::isi::escrow::DrawdownAssetLock")]
    pub struct DrawdownAssetLock {
        /// Lock to draw down.
        pub escrow_id: crate::escrow::EscrowId,
        /// Amount to release to the lock destination.
        pub amount: iroha_primitives::numeric::Quantity,
        /// Exact authoritative remaining amount observed before this drawdown.
        ///
        /// The ledger rejects the instruction if another transaction changed the lock first. This
        /// optimistic precondition makes independently submitted retries economically exactly-once.
        pub expected_remaining_amount: iroha_primitives::numeric::Quantity,
    }
}
impl DrawdownAssetLock {
    /// Construct a generic asset lock drawdown instruction.
    #[must_use]
    pub fn new(
        escrow_id: crate::escrow::EscrowId,
        amount: impl Into<iroha_primitives::numeric::Quantity>,
        expected_remaining_amount: impl Into<iroha_primitives::numeric::Quantity>,
    ) -> Self {
        Self {
            escrow_id,
            amount: amount.into(),
            expected_remaining_amount: expected_remaining_amount.into(),
        }
    }
}
isi! {
    /// Cancel an active generic asset lock and refund remaining custody.
    #[derive (crate :: DeriveJsonSerialize , crate :: DeriveJsonDeserialize)]
    #[norito_schema(name = "iroha_data_model::isi::escrow::CancelAssetLock")]
    pub struct CancelAssetLock {
        /// Lock to cancel.
        pub escrow_id: crate::escrow::EscrowId,
        /// Exact authoritative remaining amount observed before cancellation.
        ///
        /// The ledger rejects the instruction if another transaction changed
        /// the lock first, preventing a stale cancellation from refunding a
        /// different amount than the signer authorized.
        pub expected_remaining_amount: iroha_primitives::numeric::Quantity,
    }
}
impl CancelAssetLock {
    /// Construct a generic asset lock cancellation with an exact remaining-amount precondition.
    #[must_use]
    pub fn new(
        escrow_id: crate::escrow::EscrowId,
        expected_remaining_amount: impl Into<iroha_primitives::numeric::Quantity>,
    ) -> Self {
        Self {
            escrow_id,
            expected_remaining_amount: expected_remaining_amount.into(),
        }
    }
}
isi! {
    /// Expire a generic asset lock whose deadline has passed.
    #[derive (crate :: DeriveJsonSerialize , crate :: DeriveJsonDeserialize)]
    #[norito_schema(name = "iroha_data_model::isi::escrow::ExpireAssetLock")]
    pub struct ExpireAssetLock {
        /// Lock to expire.
        pub escrow_id: crate::escrow::EscrowId,
    }
}
impl ExpireAssetLock {
    /// Construct a generic asset lock expiry instruction.
    #[must_use]
    pub const fn new(escrow_id: crate::escrow::EscrowId) -> Self {
        Self { escrow_id }
    }
}
impl crate::seal::Instruction for OpenAssetEscrow {}
impl crate::seal::Instruction for AcceptAssetEscrow {}
impl crate::seal::Instruction for MarkEscrowPaymentSent {}
impl crate::seal::Instruction for ReleaseAssetEscrow {}
impl crate::seal::Instruction for CancelAssetEscrow {}
impl crate::seal::Instruction for OpenEscrowDispute {}
impl crate::seal::Instruction for ResolveEscrowDispute {}
impl crate::seal::Instruction for OpenAssetLock {}
impl crate::seal::Instruction for OpenConditionalEscrow {}
impl crate::seal::Instruction for AttestEscrowCondition {}
impl crate::seal::Instruction for ExpireConditionalEscrow {}
impl crate::seal::Instruction for DrawdownAssetLock {}
impl crate::seal::Instruction for CancelAssetLock {}
impl crate::seal::Instruction for ExpireAssetLock {}
fn escrow_decode_flags() -> u8 {
    norito::core::effective_decode_flags().unwrap_or_else(norito::core::default_encode_flags)
}
macro_rules! impl_escrow_decode_from_slice {
    ($ty:ty { $($field:ident : $field_ty:ty),+ $(,)? }) => {
        impl<'a> norito::core::DecodeFromSlice<'a> for $ty {
            fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
                let flags = escrow_decode_flags();
                let mut offset = 0usize;
                $(
                    let $field = super::decode_aos_canonical_field::<$field_ty>(
                        super::read_aos_field(bytes, &mut offset, flags)?,
                        flags,
                    )?;
                )+
                if offset != bytes.len() {
                    return Err(norito::core::Error::LengthMismatch);
                }
                norito::core::note_payload_access(bytes, offset);
                Ok((Self { $($field),+ }, offset))
            }
        }
    };
}
impl_escrow_decode_from_slice!(OpenAssetEscrow {
    escrow_id: crate::escrow::EscrowId,
    asset_definition: crate::asset::AssetDefinitionId,
    amount: iroha_primitives::numeric::Quantity,
    evidence_hashes: Vec<iroha_crypto::Hash>,
});
impl_escrow_decode_from_slice!(AcceptAssetEscrow {
    escrow_id: crate::escrow::EscrowId,
});
impl_escrow_decode_from_slice!(MarkEscrowPaymentSent {
    escrow_id: crate::escrow::EscrowId,
});
impl_escrow_decode_from_slice!(ReleaseAssetEscrow {
    escrow_id: crate::escrow::EscrowId,
});
impl_escrow_decode_from_slice!(CancelAssetEscrow {
    escrow_id: crate::escrow::EscrowId,
});
impl_escrow_decode_from_slice!(OpenEscrowDispute {
    escrow_id: crate::escrow::EscrowId,
    evidence_hashes: Vec<iroha_crypto::Hash>,
});
impl_escrow_decode_from_slice!(ResolveEscrowDispute {
    escrow_id: crate::escrow::EscrowId,
    buyer_amount: iroha_primitives::numeric::Quantity,
    seller_amount: iroha_primitives::numeric::Quantity,
    evidence_hashes: Vec<iroha_crypto::Hash>,
});
impl_escrow_decode_from_slice!(OpenAssetLock {
    escrow_id: crate::escrow::EscrowId,
    asset_definition: crate::asset::AssetDefinitionId,
    destination: crate::account::AccountId,
    amount: iroha_primitives::numeric::Quantity,
    release_authority: Option<crate::account::AccountId>,
    expires_at_ms: Option<u64>,
    evidence_hashes: Vec<iroha_crypto::Hash>,
});
impl_escrow_decode_from_slice!(OpenConditionalEscrow {
    escrow_id: crate::escrow::EscrowId,
    asset_definition: crate::asset::AssetDefinitionId,
    beneficiary: crate::account::AccountId,
    amount: iroha_primitives::numeric::Quantity,
    conditions: Vec<crate::escrow::ConditionalEscrowCondition>,
    expires_at_ms: u64,
    evidence_hashes: Vec<iroha_crypto::Hash>,
});
impl_escrow_decode_from_slice!(AttestEscrowCondition {
    escrow_id: crate::escrow::EscrowId,
    condition_id: iroha_model_base::name::Name,
    value: crate::escrow::ConditionalEscrowValue,
    evidence_hash: Option<iroha_crypto::Hash>,
});
impl_escrow_decode_from_slice!(ExpireConditionalEscrow {
    escrow_id: crate::escrow::EscrowId,
});
impl_escrow_decode_from_slice!(DrawdownAssetLock {
    escrow_id: crate::escrow::EscrowId,
    amount: iroha_primitives::numeric::Quantity,
    expected_remaining_amount: iroha_primitives::numeric::Quantity,
});
impl_escrow_decode_from_slice!(CancelAssetLock {
    escrow_id: crate::escrow::EscrowId,
    expected_remaining_amount: iroha_primitives::numeric::Quantity,
});
impl_escrow_decode_from_slice!(ExpireAssetLock {
    escrow_id: crate::escrow::EscrowId,
});
#[cfg(test)]
mod tests {
    use super::*;
    use crate::isi::test_support::{
        assert_registry_decodes_registered_type as assert_registry_decodes, assert_slice_roundtrip,
    };
    use core::num::{NonZeroU32, NonZeroU64};
    use iroha_crypto::{Algorithm, Hash, KeyPair};
    use iroha_model_base::domain::DomainId;
    use iroha_model_base::name::Name;
    use iroha_primitives::numeric::{Numeric, Quantity};
    use norito::{codec::Encode, core::DecodeFromSlice};
    #[derive(Encode)]
    struct ForgedOpenAssetEscrow {
        escrow_id: crate::escrow::EscrowId,
        asset_definition: crate::asset::AssetDefinitionId,
        amount: Numeric,
        evidence_hashes: Vec<iroha_crypto::Hash>,
    }
    fn escrow_id() -> crate::escrow::EscrowId {
        crate::escrow::EscrowId::new(Hash::new("escrow-slice"))
    }
    fn asset_definition_id() -> crate::asset::AssetDefinitionId {
        crate::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "xor".parse::<Name>().unwrap(),
        )
    }
    fn account(seed: u8) -> crate::account::AccountId {
        let key_pair = KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
            .expect("derive checked escrow fixture account keypair");
        crate::account::AccountId::new(key_pair.public_key().clone())
    }
    fn evidence_hashes() -> Vec<Hash> {
        vec![Hash::new("escrow-slice-evidence")]
    }
    fn conditional_conditions(
        attestor: crate::account::AccountId,
    ) -> Vec<crate::escrow::ConditionalEscrowCondition> {
        vec![
            crate::escrow::ConditionalEscrowCondition::Oracle(
                crate::escrow::ConditionalEscrowOracleCondition {
                    id: "delivery_confirmed".parse().expect("condition id"),
                    attestor,
                    predicate: crate::escrow::ConditionalEscrowPredicate::Equals(
                        crate::escrow::ConditionalEscrowValue::Bool(true),
                    ),
                    sequence: NonZeroU32::new(1).expect("non-zero sequence"),
                },
            ),
            crate::escrow::ConditionalEscrowCondition::Within(
                crate::escrow::ConditionalEscrowWithinCondition {
                    id: "delivery_window".parse().expect("condition id"),
                    duration_ms: NonZeroU64::new(60_000).expect("non-zero duration"),
                },
            ),
        ]
    }
    #[test]
    #[allow(clippy::too_many_lines)]
    fn escrow_instruction_constructors_fill_expected_fields() {
        let escrow_id = crate::escrow::EscrowId::new(Hash::new("escrow-ctor"));
        let asset_definition = crate::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "xor".parse::<Name>().unwrap(),
        );
        let evidence = vec![Hash::new("evidence")];
        let destination = account(0xA1);
        let release_authority = account(0xA2);
        assert_eq!(
            OpenAssetEscrow::new(escrow_id, asset_definition.clone(), Quantity::from(10_u64)),
            OpenAssetEscrow {
                escrow_id,
                asset_definition: asset_definition.clone(),
                amount: Quantity::from(10_u64),
                evidence_hashes: Vec::new(),
            }
        );
        assert_eq!(
            OpenAssetEscrow::with_evidence_hashes(
                escrow_id,
                asset_definition.clone(),
                Quantity::from(10_u64),
                evidence.clone(),
            )
            .evidence_hashes,
            evidence
        );
        assert_eq!(AcceptAssetEscrow::new(escrow_id).escrow_id, escrow_id);
        assert_eq!(MarkEscrowPaymentSent::new(escrow_id).escrow_id, escrow_id);
        assert_eq!(ReleaseAssetEscrow::new(escrow_id).escrow_id, escrow_id);
        assert_eq!(CancelAssetEscrow::new(escrow_id).escrow_id, escrow_id);
        assert_eq!(
            OpenEscrowDispute::new(escrow_id).evidence_hashes,
            Vec::new()
        );
        assert_eq!(
            OpenEscrowDispute::with_evidence_hashes(escrow_id, evidence.clone()).evidence_hashes,
            evidence
        );
        assert_eq!(
            ResolveEscrowDispute::new(escrow_id, Quantity::from(7_u64), Quantity::from(3_u64))
                .seller_amount,
            Quantity::from(3_u64)
        );
        assert_eq!(
            ResolveEscrowDispute::with_evidence_hashes(
                escrow_id,
                Quantity::from(7_u64),
                Quantity::from(3_u64),
                evidence.clone(),
            )
            .evidence_hashes,
            evidence
        );
        assert_eq!(
            OpenAssetLock::new(
                escrow_id,
                asset_definition.clone(),
                destination.clone(),
                Quantity::from(20_u64),
            ),
            OpenAssetLock {
                escrow_id,
                asset_definition: asset_definition.clone(),
                destination: destination.clone(),
                amount: Quantity::from(20_u64),
                release_authority: None,
                expires_at_ms: None,
                evidence_hashes: Vec::new(),
            }
        );
        let lock_with_options = OpenAssetLock::with_options(
            escrow_id,
            asset_definition.clone(),
            destination.clone(),
            Quantity::from(20_u64),
            Some(release_authority.clone()),
            Some(12_345),
            evidence.clone(),
        );
        assert_eq!(lock_with_options.release_authority, Some(release_authority));
        assert_eq!(lock_with_options.expires_at_ms, Some(12_345));
        assert_eq!(lock_with_options.evidence_hashes, evidence.clone());
        assert_eq!(
            DrawdownAssetLock::new(escrow_id, Quantity::from(5_u64), Quantity::from(20_u64),)
                .amount,
            Quantity::from(5_u64)
        );
        let cancel = CancelAssetLock::new(escrow_id, Quantity::from(20_u64));
        assert_eq!(cancel.escrow_id, escrow_id);
        assert_eq!(cancel.expected_remaining_amount, Quantity::from(20_u64));
        assert_eq!(ExpireAssetLock::new(escrow_id).escrow_id, escrow_id);
    }
    #[test]
    #[allow(clippy::too_many_lines)]
    fn escrow_decode_from_slice_roundtrips() {
        let escrow_id = escrow_id();
        let asset_definition = asset_definition_id();
        let evidence = evidence_hashes();
        let destination = account(0xB1);
        let release_authority = account(0xB2);
        assert_slice_roundtrip(OpenAssetEscrow::with_evidence_hashes(
            escrow_id,
            asset_definition.clone(),
            Quantity::from(10_u64),
            evidence.clone(),
        ));
        assert_slice_roundtrip(AcceptAssetEscrow::new(escrow_id));
        assert_slice_roundtrip(MarkEscrowPaymentSent::new(escrow_id));
        assert_slice_roundtrip(ReleaseAssetEscrow::new(escrow_id));
        assert_slice_roundtrip(CancelAssetEscrow::new(escrow_id));
        assert_slice_roundtrip(OpenEscrowDispute::with_evidence_hashes(
            escrow_id,
            evidence.clone(),
        ));
        assert_slice_roundtrip(ResolveEscrowDispute::with_evidence_hashes(
            escrow_id,
            Quantity::from(7_u64),
            Quantity::from(3_u64),
            evidence.clone(),
        ));
        assert_slice_roundtrip(OpenAssetLock::with_options(
            escrow_id,
            asset_definition.clone(),
            destination.clone(),
            Quantity::from(20_u64),
            Some(release_authority.clone()),
            Some(12_345),
            evidence.clone(),
        ));
        assert_slice_roundtrip(DrawdownAssetLock::new(
            escrow_id,
            Quantity::from(5_u64),
            Quantity::from(20_u64),
        ));
        assert_slice_roundtrip(CancelAssetLock::new(escrow_id, Quantity::from(20_u64)));
        assert_slice_roundtrip(ExpireAssetLock::new(escrow_id));
    }

    #[test]
    fn cancel_asset_lock_v1_fixtures_enforce_the_two_field_hard_cut() {
        let fixture_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/sorafs_manifest/appeal_finance");
        let read = |relative: &str| {
            std::fs::read(fixture_root.join(relative)).unwrap_or_else(|error| {
                panic!("read CancelAssetLock fixture `{relative}`: {error}")
            })
        };
        let canonical_json = read("cancel_asset_lock_v1.json");
        let canonical_from_json: CancelAssetLock = norito::json::from_slice(&canonical_json)
            .expect("canonical CancelAssetLock JSON must decode");
        assert_eq!(
            canonical_from_json.expected_remaining_amount,
            Quantity::from(20_u64)
        );
        assert_eq!(
            format!(
                "{}\n",
                norito::json::to_json_pretty(&canonical_from_json)
                    .expect("serialize canonical CancelAssetLock JSON")
            )
            .as_bytes(),
            canonical_json
        );
        let canonical_norito = read("cancel_asset_lock_v1.to");
        let canonical_from_norito: CancelAssetLock = norito::decode_from_bytes(&canonical_norito)
            .expect("canonical CancelAssetLock Norito must decode");
        assert_eq!(canonical_from_norito, canonical_from_json);
        assert_eq!(
            norito::to_bytes(&canonical_from_norito)
                .expect("serialize canonical CancelAssetLock Norito"),
            canonical_norito
        );
        for path in [
            "negative/cancel_asset_lock_legacy_missing_expected_v1.json",
            "negative/cancel_asset_lock_noncanonical_quantity_v1.json",
        ] {
            assert!(
                norito::json::from_slice::<CancelAssetLock>(&read(path)).is_err(),
                "noncanonical CancelAssetLock JSON fixture `{path}` must be rejected"
            );
        }
        for path in [
            "negative/cancel_asset_lock_legacy_missing_expected_v1.to",
            "negative/cancel_asset_lock_nested_escrow_id_v1.to",
        ] {
            assert!(
                norito::decode_from_bytes::<CancelAssetLock>(&read(path)).is_err(),
                "noncanonical CancelAssetLock Norito fixture `{path}` must be rejected"
            );
        }
        let zero_json: CancelAssetLock =
            norito::json::from_slice(&read("negative/cancel_asset_lock_zero_expected_v1.json"))
                .expect("zero expected amount remains structurally valid JSON");
        let zero_norito: CancelAssetLock =
            norito::decode_from_bytes(&read("negative/cancel_asset_lock_zero_expected_v1.to"))
                .expect("zero expected amount remains structurally valid Norito");
        assert_eq!(zero_json, zero_norito);
        assert!(
            zero_norito.expected_remaining_amount.is_zero(),
            "the native execution boundary, not the codec, rejects zero"
        );
    }
    #[test]
    fn negative_numeric_payload_cannot_decode_as_native_escrow_instruction_quantity() {
        let forged = ForgedOpenAssetEscrow {
            escrow_id: escrow_id(),
            asset_definition: asset_definition_id(),
            amount: Numeric::new(-1_i32, 0),
            evidence_hashes: Vec::new(),
        };
        assert!(
            OpenAssetEscrow::decode_from_slice(&forged.encode()).is_err(),
            "a negative signed payload must not decode as a native escrow instruction"
        );
    }
    #[test]
    fn conditional_escrow_instructions_roundtrip_and_decode_from_default_registry() {
        let registry = crate::isi::registry::default();
        let escrow_id = escrow_id();
        let open = OpenConditionalEscrow::with_evidence_hashes(
            escrow_id,
            asset_definition_id(),
            account(0xC3),
            Quantity::from(25_u64),
            conditional_conditions(account(0xC4)),
            120_000,
            evidence_hashes(),
        );
        let attest = AttestEscrowCondition::new(
            escrow_id,
            "delivery_confirmed".parse().expect("condition id"),
            crate::escrow::ConditionalEscrowValue::Bool(true),
            Some(Hash::new("signed-delivery-evidence")),
        );
        let expire = ExpireConditionalEscrow::new(escrow_id);
        assert_slice_roundtrip(open.clone());
        assert_slice_roundtrip(attest.clone());
        assert_slice_roundtrip(expire.clone());
        assert_registry_decodes(&registry, open);
        assert_registry_decodes(&registry, attest);
        assert_registry_decodes(&registry, expire);
    }

    #[test]
    fn conditional_escrow_json_preserves_typed_conditions() {
        let open = OpenConditionalEscrow::new(
            escrow_id(),
            asset_definition_id(),
            account(0xC5),
            Quantity::from(25_u64),
            conditional_conditions(account(0xC6)),
            120_000,
        );
        let json = norito::json::to_json(&open).expect("serialize conditional escrow");
        let decoded: OpenConditionalEscrow =
            norito::json::from_str(&json).expect("deserialize conditional escrow");
        assert_eq!(decoded, open);
        assert!(matches!(
            decoded.conditions[0],
            crate::escrow::ConditionalEscrowCondition::Oracle(_)
        ));
        assert!(matches!(
            decoded.conditions[1],
            crate::escrow::ConditionalEscrowCondition::Within(_)
        ));
    }
    #[test]
    #[allow(clippy::too_many_lines)]
    fn escrow_default_registry_decodes_canonical_wire_ids() {
        let registry = crate::isi::registry::default();
        let escrow_id = escrow_id();
        let asset_definition = asset_definition_id();
        let evidence = evidence_hashes();
        let destination = account(0xC1);
        let release_authority = account(0xC2);
        assert_registry_decodes(
            &registry,
            OpenAssetEscrow::with_evidence_hashes(
                escrow_id,
                asset_definition.clone(),
                Quantity::from(10_u64),
                evidence.clone(),
            ),
        );
        assert_registry_decodes(&registry, AcceptAssetEscrow::new(escrow_id));
        assert_registry_decodes(&registry, MarkEscrowPaymentSent::new(escrow_id));
        assert_registry_decodes(&registry, ReleaseAssetEscrow::new(escrow_id));
        assert_registry_decodes(&registry, CancelAssetEscrow::new(escrow_id));
        assert_registry_decodes(
            &registry,
            OpenEscrowDispute::with_evidence_hashes(escrow_id, evidence.clone()),
        );
        assert_registry_decodes(
            &registry,
            ResolveEscrowDispute::with_evidence_hashes(
                escrow_id,
                Quantity::from(7_u64),
                Quantity::from(3_u64),
                evidence.clone(),
            ),
        );
        assert_registry_decodes(
            &registry,
            OpenAssetLock::with_options(
                escrow_id,
                asset_definition.clone(),
                destination,
                Quantity::from(20_u64),
                Some(release_authority),
                Some(12_345),
                evidence.clone(),
            ),
        );
        assert_registry_decodes(
            &registry,
            DrawdownAssetLock::new(escrow_id, Quantity::from(5_u64), Quantity::from(20_u64)),
        );
        assert_registry_decodes(
            &registry,
            CancelAssetLock::new(escrow_id, Quantity::from(20_u64)),
        );
        assert_registry_decodes(&registry, ExpireAssetLock::new(escrow_id));
    }
}
