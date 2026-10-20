//! Native FI registration, attested links, owner consent and derived off-ramps.

use super::*;
use crate::asset::fi_link::{AssetFiLinkAttestationV1, AssetFiLinkV1, AssetFiV1};
use iroha_primitives::numeric::Quantity;

isi! {
    /// Register or revoke an exact FI settlement account as the asset owner.
    #[derive(crate::DeriveJsonSerialize, crate::DeriveJsonDeserialize)]
    #[norito_schema(name = "iroha_data_model::isi::asset_fi::SetAssetFiV1")]
    pub struct SetAssetFiV1 {
        /// Complete eligibility record with the next revision.
        pub fi: AssetFiV1,
    }
}

isi! {
    /// Authenticate or revoke one opaque checking-account reference as the FI.
    #[derive(crate::DeriveJsonSerialize, crate::DeriveJsonDeserialize)]
    #[norito_schema(name = "iroha_data_model::isi::asset_fi::SetAssetFiLinkAttestationV1")]
    pub struct SetAssetFiLinkAttestationV1 {
        /// Exact FI-attested reference; no wallet capability is changed.
        pub attestation: AssetFiLinkAttestationV1,
    }
}

isi! {
    /// Activate, revise or revoke a link through exact wallet-owner authorization.
    #[derive(crate::DeriveJsonSerialize, crate::DeriveJsonDeserialize)]
    #[norito_schema(name = "iroha_data_model::isi::asset_fi::SetAssetFiLinkV1")]
    pub struct SetAssetFiLinkV1 {
        /// Exact destination, attestation and capabilities approved by the owner.
        pub link: AssetFiLinkV1,
        /// Exact current UID policy revision reviewed with this approval.
        pub expected_policy_revision: u64,
    }
}

isi! {
    /// Defund to the current owner-approved FI without treating that off-ramp as spending.
    ///
    /// The native executor derives the destination from the retained link. A
    /// contract requires the exact approved controller frame and may transfer
    /// only existing beneficial excess under an enabled waterfall capability.
    /// Gross outgoing ceilings and ordinary balance/status controls still apply.
    #[derive(crate::DeriveJsonSerialize, crate::DeriveJsonDeserialize)]
    #[norito_schema(name = "iroha_data_model::isi::asset_fi::TransferToLinkedFiV1")]
    pub struct TransferToLinkedFiV1 {
        /// Exact globally scoped asset.
        pub asset_definition_id: AssetDefinitionId,
        /// Wallet whose owner-approved link supplies the destination.
        pub account_id: AccountId,
        /// Positive amount; no caller-supplied destination or exemption flag.
        pub amount: Quantity,
        /// Exact owner-approved link revision.
        pub expected_link_revision: u64,
        /// Exact current UID policy revision.
        pub expected_policy_revision: u64,
    }
}

macro_rules! link_instruction {
    ($ty:ident, $wire:literal, {$($field:ident : $field_ty:ty),+ $(,)?}) => {
        impl $ty {
            /// Canonical first-release instruction wire identity.
            pub const WIRE_ID: &'static str = $wire;
        }
        impl crate::seal::Instruction for $ty {}
        impl<'a> norito::core::DecodeFromSlice<'a> for $ty {
            fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
                let flags = norito::core::effective_decode_flags()
                    .unwrap_or_else(norito::core::default_encode_flags);
                let mut offset = 0usize;
                $(let $field = super::decode_aos_canonical_field::<$field_ty>(
                    super::read_aos_field(bytes, &mut offset, flags)?, flags,
                )?;)+
                if offset != bytes.len() { return Err(norito::core::Error::LengthMismatch); }
                norito::core::note_payload_access(bytes, offset);
                Ok((Self { $($field,)+ }, offset))
            }
        }
    };
}

link_instruction!(SetAssetFiV1, "iroha.asset.fi.set.v1", { fi: AssetFiV1 });
link_instruction!(SetAssetFiLinkAttestationV1, "iroha.asset.fi.link.attestation.set.v1",
    { attestation: AssetFiLinkAttestationV1 });
link_instruction!(SetAssetFiLinkV1, "iroha.asset.fi.link.set.v1",
    { link: AssetFiLinkV1, expected_policy_revision: u64 });
link_instruction!(TransferToLinkedFiV1, "iroha.asset.fi.link.transfer.v1",
    { asset_definition_id: AssetDefinitionId, account_id: AccountId, amount: Quantity,
      expected_link_revision: u64, expected_policy_revision: u64 });

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isi::test_support::{assert_registry_decodes, assert_slice_roundtrip};
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_model_base::domain::DomainId;

    #[test]
    fn fi_links_preserve_distinct_issuer_owner_reference_and_revisions() {
        let account = |seed| {
            AccountId::new(
                KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
                    .unwrap()
                    .public_key()
                    .clone(),
            )
        };
        let wallet = account(91);
        let fi_account = account(92);
        let asset = AssetDefinitionId::derive_from_components(
            DomainId::try_new("links", "universal").unwrap(),
            "ds".parse().unwrap(),
        );
        let fi = SetAssetFiV1 {
            fi: AssetFiV1 {
                asset_definition_id: asset.clone(),
                fi_account_id: fi_account.clone(),
                revision: 2,
                enabled: true,
            },
        };
        let attestation = SetAssetFiLinkAttestationV1 {
            attestation: AssetFiLinkAttestationV1 {
                asset_definition_id: asset.clone(),
                account_id: wallet.clone(),
                fi_account_id: fi_account.clone(),
                reference_digest: [37; 32],
                revision: 3,
                enabled: true,
            },
        };
        let link = SetAssetFiLinkV1 {
            link: AssetFiLinkV1 {
                asset_definition_id: asset.clone(),
                account_id: wallet.clone(),
                fi_account_id: fi_account,
                reference_digest: [37; 32],
                fi_revision: 2,
                attestation_revision: 3,
                revision: 4,
                enabled: true,
                controller: None,
                waterfall: false,
                reverse_waterfall: false,
            },
            expected_policy_revision: 5,
        };
        let transfer = TransferToLinkedFiV1 {
            asset_definition_id: asset,
            account_id: wallet,
            amount: 11_u32.into(),
            expected_link_revision: 4,
            expected_policy_revision: 5,
        };
        assert_slice_roundtrip(fi.clone());
        assert_slice_roundtrip(attestation.clone());
        assert_slice_roundtrip(link.clone());
        assert_slice_roundtrip(transfer.clone());
        let registry = crate::isi::registry::default();
        assert_registry_decodes(&registry, SetAssetFiV1::WIRE_ID, fi);
        assert_registry_decodes(&registry, SetAssetFiLinkAttestationV1::WIRE_ID, attestation);
        assert_registry_decodes(&registry, SetAssetFiLinkV1::WIRE_ID, link.clone());
        assert_registry_decodes(&registry, TransferToLinkedFiV1::WIRE_ID, transfer);
        let json = norito::json::to_json(&link).unwrap();
        assert_eq!(
            norito::json::from_str::<SetAssetFiLinkV1>(&json).unwrap(),
            link
        );
    }
}
