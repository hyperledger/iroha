//! Contract-controlled native locks with the original payer retained as owner.
//!
//! These instructions require authenticated contract execution. Merely supplying
//! a controller address never grants authority. The native executor must bind
//! that address to the active frame and verify the source transfer permission.

use super::*;
use crate::{
    account::AccountId,
    escrow::control::{AssetLockControlV1, AssetLockWaterfallSettlementV1},
    isi::escrow::{CancelAssetLock, DrawdownAssetLock, ExpireAssetLock, OpenAssetLock},
};

isi! {
    /// Fund a native lock from an explicitly authorized payer under immutable contract control.
    #[derive(crate::DeriveJsonSerialize, crate::DeriveJsonDeserialize)]
    #[norito_schema(name = "iroha_data_model::isi::escrow_control::OpenControlledAssetLockV1")]
    pub struct OpenControlledAssetLockV1 {
        /// Actual funding owner, retained as the native record's seller.
        pub source: AccountId,
        /// Exact opaque application key, nonempty and at most 4,096 bytes.
        ///
        /// Native admission derives the reserved lock ID from the authenticated
        /// controller and these bytes, preventing another contract from opening it.
        pub key: Vec<u8>,
        /// Native lock identity, beneficiary, amount and expiry.
        ///
        /// The release authority must equal the controller's immutable subject.
        pub lock: OpenAssetLock,
        /// Immutable controller and independent claim/cancellation deadlines.
        pub control: AssetLockControlV1,
    }
}

isi! {
    /// Draw from a controlled native lock through its authenticated controller.
    #[derive(crate::DeriveJsonSerialize, crate::DeriveJsonDeserialize)]
    #[norito_schema(name = "iroha_data_model::isi::escrow_control::DrawdownControlledAssetLockV1")]
    pub struct DrawdownControlledAssetLockV1 {
        /// Native lock drawdown, including exact expected remainder.
        pub drawdown: DrawdownAssetLock,
        /// Explicit owner-consented native overflow settlement with exact revision pins.
        /// Absence preserves ordinary controlled-lock settlement.
        pub waterfall: Option<AssetLockWaterfallSettlementV1>,
    }
}

isi! {
    /// Cancel a controlled native lock through its authenticated controller.
    #[derive(crate::DeriveJsonSerialize, crate::DeriveJsonDeserialize)]
    #[norito_schema(name = "iroha_data_model::isi::escrow_control::CancelControlledAssetLockV1")]
    pub struct CancelControlledAssetLockV1 {
        /// Native lock cancellation, including exact expected remainder.
        pub cancel: CancelAssetLock,
        /// Explicit owner-consented native overflow settlement with exact revision pins.
        /// Absence preserves ordinary controlled-lock settlement.
        pub waterfall: Option<AssetLockWaterfallSettlementV1>,
    }
}

isi! {
    /// Expire a controlled native lock through its authenticated controller.
    #[derive(crate::DeriveJsonSerialize, crate::DeriveJsonDeserialize)]
    #[norito_schema(name = "iroha_data_model::isi::escrow_control::ExpireControlledAssetLockV1")]
    pub struct ExpireControlledAssetLockV1 {
        /// Native lock expiry; the retained record determines owner and remainder.
        pub expiry: ExpireAssetLock,
        /// Explicit owner-consented native overflow settlement with exact revision pins.
        /// Absence preserves ordinary controlled-lock settlement.
        pub waterfall: Option<AssetLockWaterfallSettlementV1>,
    }
}

macro_rules! controlled_lock_instruction {
    ($ty:ident, $wire:literal, {$($field:ident : $field_ty:ty),+ $(,)?}) => {
        impl $ty {
            /// Stable additive instruction wire identity.
            pub const WIRE_ID: &'static str = $wire;
        }
        impl crate::seal::Instruction for $ty {}
        impl<'a> norito::core::DecodeFromSlice<'a> for $ty {
            fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
                let flags = norito::core::effective_decode_flags()
                    .unwrap_or_else(norito::core::default_encode_flags);
                let mut offset = 0usize;
                $(
                    let $field = super::decode_aos_canonical_field::<$field_ty>(
                        super::read_aos_field(bytes, &mut offset, flags)?, flags,
                    )?;
                )+
                if offset != bytes.len() {
                    return Err(norito::core::Error::LengthMismatch);
                }
                norito::core::note_payload_access(bytes, offset);
                Ok((Self { $($field,)+ }, offset))
            }
        }
    };
}

controlled_lock_instruction!(
    OpenControlledAssetLockV1, "iroha.asset.lock.controlled.open.v1",
    { source: AccountId, key: Vec<u8>, lock: OpenAssetLock, control: AssetLockControlV1 }
);
controlled_lock_instruction!(
    DrawdownControlledAssetLockV1, "iroha.asset.lock.controlled.drawdown.v1",
    { drawdown: DrawdownAssetLock, waterfall: Option<AssetLockWaterfallSettlementV1> }
);
controlled_lock_instruction!(
    CancelControlledAssetLockV1, "iroha.asset.lock.controlled.cancel.v1",
    { cancel: CancelAssetLock, waterfall: Option<AssetLockWaterfallSettlementV1> }
);
controlled_lock_instruction!(
    ExpireControlledAssetLockV1, "iroha.asset.lock.controlled.expire.v1",
    { expiry: ExpireAssetLock, waterfall: Option<AssetLockWaterfallSettlementV1> }
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        NetworkId, asset::AssetDefinitionId, block::BlockHeader,
        escrow::control::controlled_asset_lock_id, smart_contract::ContractAddress,
    };
    use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair};
    use iroha_model_base::{domain::DomainId, topology::DataSpaceId};

    #[test]
    fn controlled_instructions_keep_payer_controller_and_native_terms_through_registry() {
        let key = KeyPair::try_from_seed(vec![91; 32], Algorithm::Ed25519).expect("fixed test key");
        let source = AccountId::new(key.public_key().clone());
        let network = NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
            Hash::new(b"controlled-lock-test"),
        ));
        let controller = ContractAddress::derive(&network, &source, 1, DataSpaceId::UNIVERSAL)
            .expect("test contract");
        let asset = AssetDefinitionId::derive_from_components(
            DomainId::try_new("escrow", "universal").expect("test domain"),
            "ds".parse().expect("test asset name"),
        );
        let application_key = b"test-lock".to_vec();
        let escrow_id = controlled_asset_lock_id(&controller, &application_key);
        let opening = OpenControlledAssetLockV1 {
            source: source.clone(),
            key: application_key,
            lock: OpenAssetLock::with_options(
                escrow_id,
                asset,
                source.clone(),
                100_u32,
                Some(controller.subject_id()),
                Some(701),
                vec![],
            ),
            control: AssetLockControlV1 {
                controller,
                release_until_ms: core::num::NonZeroU64::new(300),
                cancel_not_before_ms: core::num::NonZeroU64::new(701),
            },
        };
        assert_ne!(opening.source, opening.control.controller.subject_id());
        let bytes = norito::encode_canonical(&opening).expect("encode opening");
        let decoded: OpenControlledAssetLockV1 =
            norito::decode_canonical(&bytes).expect("decode opening");
        assert_eq!(decoded, opening);
        let json = norito::json::to_json(&opening).expect("encode JSON opening");
        let decoded: OpenControlledAssetLockV1 =
            norito::json::from_str(&json).expect("decode JSON opening");
        assert_eq!(decoded.key, b"test-lock");
        assert_eq!(decoded, opening);
        let registry = crate::isi::registry::default();
        for (instruction, expected_id) in [
            (
                InstructionBox::from(opening),
                OpenControlledAssetLockV1::WIRE_ID,
            ),
            (
                InstructionBox::from(DrawdownControlledAssetLockV1 {
                    drawdown: DrawdownAssetLock::new(escrow_id, 20_u32, 100_u32),
                    waterfall: None,
                }),
                DrawdownControlledAssetLockV1::WIRE_ID,
            ),
            (
                InstructionBox::from(CancelControlledAssetLockV1 {
                    cancel: CancelAssetLock::new(escrow_id, 80_u32),
                    waterfall: None,
                }),
                CancelControlledAssetLockV1::WIRE_ID,
            ),
            (
                InstructionBox::from(ExpireControlledAssetLockV1 {
                    expiry: ExpireAssetLock::new(escrow_id),
                    waterfall: None,
                }),
                ExpireControlledAssetLockV1::WIRE_ID,
            ),
        ] {
            let (wire_id, payload) = super::super::encoded_instruction_pair_payload(&instruction)
                .expect("encode instruction pair");
            assert_eq!(wire_id, expected_id);
            let decoded = registry
                .decode(wire_id, &payload)
                .expect("decode registry payload")
                .expect("registered instruction");
            assert_eq!(decoded, instruction);
        }
    }

    #[test]
    fn controlled_settlement_modes_roundtrip_without_losing_revision_pins() {
        let id = crate::escrow::EscrowId::new(Hash::new("controlled-waterfall-wire"));
        let registry = crate::isi::registry::default();
        macro_rules! roundtrip {
            ($value:expr, $ty:ty) => {{
                let value: $ty = $value;
                let binary = norito::encode_canonical(&value).unwrap();
                assert_eq!(norito::decode_canonical::<$ty>(&binary).unwrap(), value);
                let json = norito::json::to_json(&value).unwrap();
                assert_eq!(norito::json::from_str::<$ty>(&json).unwrap(), value);
                let instruction = InstructionBox::from(value);
                let (wire, payload) =
                    super::super::encoded_instruction_pair_payload(&instruction).unwrap();
                let decoded = registry
                    .decode(wire, &payload)
                    .expect("registered controlled settlement instruction")
                    .expect("decode controlled settlement instruction");
                assert_eq!(decoded, instruction);
            }};
        }
        for waterfall in [
            None,
            Some(AssetLockWaterfallSettlementV1 {
                expected_policy_revision: u64::MAX,
                expected_link_revision: u64::MAX - 1,
            }),
        ] {
            roundtrip!(
                DrawdownControlledAssetLockV1 {
                    drawdown: DrawdownAssetLock::new(id, 5_u32, 13_u32),
                    waterfall,
                },
                DrawdownControlledAssetLockV1
            );
            roundtrip!(
                CancelControlledAssetLockV1 {
                    cancel: CancelAssetLock::new(id, 13_u32),
                    waterfall,
                },
                CancelControlledAssetLockV1
            );
            roundtrip!(
                ExpireControlledAssetLockV1 {
                    expiry: ExpireAssetLock::new(id),
                    waterfall,
                },
                ExpireControlledAssetLockV1
            );
        }
    }
}
