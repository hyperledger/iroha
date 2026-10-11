use super::*;
isi! {
    /// Open a ledger-managed `SoraNet` VPN lease from one operator-signed quote.
    #[norito_schema(name = "iroha_data_model::isi::vpn::OpenVpnLeaseEscrow")]
    pub struct OpenVpnLeaseEscrow {
        /// Complete operator-authored policy and its canonical signature.
        pub quote: crate::soranet::vpn::VpnSignedQuoteV1,
    }
}
impl OpenVpnLeaseEscrow {
    /// Construct a VPN lease escrow opening instruction.
    #[must_use]
    pub fn new(quote: crate::soranet::vpn::VpnSignedQuoteV1) -> Self {
        Self { quote }
    }
}
isi! {
    /// Settle a `SoraNet` VPN lease with a relay receipt and client voucher.
    #[norito_schema(name = "iroha_data_model::isi::vpn::SettleVpnLease")]
    pub struct SettleVpnLease {
        /// Lease identifier opened by [`OpenVpnLeaseEscrow`].
        #[norito (json = "crate::json_helpers::fixed_bytes")]
        pub lease_id: [u8; 32],
        /// Relay receipt describing final session counters.
        pub relay_receipt: crate::soranet::vpn::VpnSignedSessionReceiptV1,
        /// Highest cumulative usage voucher signed by the client.
        pub client_voucher: crate::soranet::vpn::VpnUsageVoucherV1,
    }
}
impl SettleVpnLease {
    /// Construct a VPN lease settlement instruction.
    #[must_use]
    pub fn new(
        lease_id: [u8; 32],
        relay_receipt: crate::soranet::vpn::VpnSignedSessionReceiptV1,
        client_voucher: crate::soranet::vpn::VpnUsageVoucherV1,
    ) -> Self {
        Self {
            lease_id,
            relay_receipt,
            client_voucher,
        }
    }
}
isi! {
    /// Refund an expired `SoraNet` VPN lease after the relay settlement grace window.
    #[norito_schema(name = "iroha_data_model::isi::vpn::RefundExpiredVpnLease")]
    pub struct RefundExpiredVpnLease {
        /// Lease identifier opened by [`OpenVpnLeaseEscrow`].
        #[norito (json = "crate::json_helpers::fixed_bytes")]
        pub lease_id: [u8; 32],
    }
}
impl RefundExpiredVpnLease {
    /// Construct an expired VPN lease refund instruction.
    #[must_use]
    pub const fn new(lease_id: [u8; 32]) -> Self {
        Self { lease_id }
    }
}
impl crate::seal::Instruction for OpenVpnLeaseEscrow {}
impl crate::seal::Instruction for SettleVpnLease {}
impl crate::seal::Instruction for RefundExpiredVpnLease {}
fn vpn_decode_flags() -> u8 {
    norito::core::effective_decode_flags().unwrap_or_else(norito::core::default_encode_flags)
}
impl<'a> norito::core::DecodeFromSlice<'a> for OpenVpnLeaseEscrow {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        let flags = vpn_decode_flags();
        let mut offset = 0usize;
        let quote = super::decode_aos_canonical_field::<crate::soranet::vpn::VpnSignedQuoteV1>(
            super::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        if offset != bytes.len() {
            return Err(norito::core::Error::LengthMismatch);
        }
        norito::core::note_payload_access(bytes, offset);
        Ok((Self { quote }, offset))
    }
}
impl<'a> norito::core::DecodeFromSlice<'a> for SettleVpnLease {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        let flags = vpn_decode_flags();
        let mut offset = 0usize;
        let lease_id = super::decode_aos_byte_array_field::<32>(bytes, &mut offset, flags)?;
        let relay_receipt = super::decode_aos_canonical_field::<
            crate::soranet::vpn::VpnSignedSessionReceiptV1,
        >(super::read_aos_field(bytes, &mut offset, flags)?, flags)?;
        let client_voucher = super::decode_aos_canonical_field::<
            crate::soranet::vpn::VpnUsageVoucherV1,
        >(super::read_aos_field(bytes, &mut offset, flags)?, flags)?;
        if offset != bytes.len() {
            return Err(norito::core::Error::LengthMismatch);
        }
        norito::core::note_payload_access(bytes, offset);
        Ok((
            Self {
                lease_id,
                relay_receipt,
                client_voucher,
            },
            offset,
        ))
    }
}
impl<'a> norito::core::DecodeFromSlice<'a> for RefundExpiredVpnLease {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        let flags = vpn_decode_flags();
        let mut offset = 0usize;
        let lease_id = super::decode_aos_byte_array_field::<32>(bytes, &mut offset, flags)?;
        if offset != bytes.len() {
            return Err(norito::core::Error::LengthMismatch);
        }
        norito::core::note_payload_access(bytes, offset);
        Ok((Self { lease_id }, offset))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::isi::test_support::{
        assert_registry_decodes_registered_type as assert_registry_decodes, assert_slice_roundtrip,
    };
    use crate::{
        account::AccountId,
        asset::AssetDefinitionId,
        soranet::vpn::{
            VpnAddressSlotV1, VpnExitClassV1, VpnQuoteBodyV1, VpnQuotePolicyV1,
            VpnSessionReceiptV1, VpnSignedQuoteV1, VpnSignedSessionReceiptV1, VpnTariffV1,
            VpnUsageVoucherBodyV1, VpnUsageVoucherV1, derive_vpn_address_plan_v1,
            derive_vpn_lease_id_v1, derive_vpn_session_id_v1,
        },
    };
    use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair, Signature};
    use iroha_model_base::domain::DomainId;
    use iroha_primitives::numeric::{Numeric, Quantity};
    use norito::core::DecodeFromSlice;
    fn account(seed: u8) -> AccountId {
        let key_pair = KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
            .expect("derive checked VPN fixture account keypair");
        AccountId::new(key_pair.public_key().clone())
    }
    fn public_key(seed: u8) -> iroha_crypto::PublicKey {
        let key_pair = KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
            .expect("derive checked VPN fixture public keypair");
        key_pair.public_key().clone()
    }
    fn key_pair(seed: u8) -> KeyPair {
        KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
            .expect("derive checked VPN fixture keypair")
    }
    fn test_network_id(seed: u8) -> crate::NetworkId {
        crate::NetworkId::from_genesis_hash(
            HashOf::<crate::block::BlockHeader>::from_untyped_unchecked(Hash::prehashed(
                [seed; Hash::LENGTH],
            )),
        )
    }
    fn asset_definition() -> AssetDefinitionId {
        AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").expect("domain id"),
            "xor".parse().expect("asset name"),
        )
    }
    fn quantity_nanos(value: u64) -> Quantity {
        Quantity::from_canonical_numeric(Numeric::new(value, 9))
            .expect("u64 nano-XOR fixture fits Quantity")
    }
    fn tariff() -> VpnTariffV1 {
        VpnTariffV1 {
            lease_fee: quantity_nanos(10_000),
            active_fee_per_minute: quantity_nanos(60),
            ingress_fee_per_mib: quantity_nanos(100),
            egress_fee_per_mib: quantity_nanos(200),
        }
    }
    fn quote_policy(account_id: &AccountId, slot: VpnAddressSlotV1) -> VpnQuotePolicyV1 {
        VpnQuotePolicyV1 {
            exit_class: VpnExitClassV1::Standard,
            relay_endpoint: "/dns/relay.example/udp/9443/quic".to_owned(),
            relay_id: [0x11; 32],
            relay_mldsa65_public_key: [0x12;
                crate::soranet::vpn::VPN_RELAY_MLDSA65_PUBLIC_KEY_BYTES_V1],
            descriptor_commit: [0x22; 32],
            tls_server_name: "relay.example".to_owned(),
            relay_tls_spki_sha256: [0xAB; 32],
            relay_certificate_sha256: [0x33; 32],
            directory_snapshot_digest: [0x44; 32],
            relay_trust_valid_until_ms: u64::MAX,
            lease_secs: 600,
            meter_family: "soranet.vpn.standard".to_owned(),
            fee_asset_id: "xor#universal.universal".to_owned(),
            escrow_account_id: account_id.clone(),
            route_pushes: vec!["0.0.0.0/0".to_owned()],
            excluded_routes: Vec::new(),
            dns_servers: vec!["1.1.1.1".to_owned()],
            tunnel_addresses: derive_vpn_address_plan_v1(slot).client_tunnel_addresses,
            mtu_bytes: 1_280,
            flow_label_bits: 24,
            padding_budget_ms: 15,
        }
    }
    fn signed_quote() -> VpnSignedQuoteV1 {
        let network_id = test_network_id(0x31);
        let quote_id = [0x22; 32];
        let client_account_id = account(0x41);
        let operator = key_pair(0x42);
        let operator_account_id = AccountId::new(operator.public_key().clone());
        let address_slot = VpnAddressSlotV1::new(7).expect("fixture slot");
        let body = VpnQuoteBodyV1 {
            lease_id: derive_vpn_lease_id_v1(&network_id, quote_id, &client_account_id),
            session_id: derive_vpn_session_id_v1(
                &network_id,
                quote_id,
                &client_account_id,
                address_slot,
            ),
            network_id,
            quote_id,
            address_slot,
            client_account_id,
            operator_account_id: operator_account_id.clone(),
            metering_public_key: public_key(0x43),
            asset_definition: asset_definition(),
            tariff: tariff(),
            policy: quote_policy(&operator_account_id, address_slot),
            valid_after_ms: 1_700_000_000_000,
            expires_at_ms: 1_700_000_600_000,
            settlement_grace_ms: 60_000,
        };
        VpnSignedQuoteV1::try_sign(body, operator.private_key()).expect("sign VPN quote fixture")
    }
    #[derive(norito::codec::Encode)]
    struct ForgedVpnTariff {
        lease_fee: Numeric,
        active_fee_per_minute: Quantity,
        ingress_fee_per_mib: Quantity,
        egress_fee_per_mib: Quantity,
    }
    #[derive(norito::codec::Encode)]
    struct ForgedVpnQuoteBody {
        network_id: crate::NetworkId,
        quote_id: [u8; 32],
        lease_id: [u8; 32],
        session_id: [u8; 16],
        address_slot: VpnAddressSlotV1,
        client_account_id: AccountId,
        operator_account_id: AccountId,
        metering_public_key: iroha_crypto::PublicKey,
        asset_definition: AssetDefinitionId,
        tariff: ForgedVpnTariff,
        policy: VpnQuotePolicyV1,
        valid_after_ms: u64,
        expires_at_ms: u64,
        settlement_grace_ms: u64,
    }
    #[derive(norito::codec::Encode)]
    struct ForgedVpnSignedQuote {
        body: ForgedVpnQuoteBody,
        signature: Signature,
    }
    #[derive(norito::codec::Encode)]
    struct ForgedOpenVpnLeaseEscrow {
        quote: ForgedVpnSignedQuote,
    }
    #[test]
    fn open_vpn_lease_rejects_forged_negative_quantity() {
        let valid = signed_quote();
        let body = valid.body;
        let forged = ForgedOpenVpnLeaseEscrow {
            quote: ForgedVpnSignedQuote {
                body: ForgedVpnQuoteBody {
                    network_id: body.network_id,
                    quote_id: body.quote_id,
                    lease_id: body.lease_id,
                    session_id: body.session_id,
                    address_slot: body.address_slot,
                    client_account_id: body.client_account_id,
                    operator_account_id: body.operator_account_id,
                    metering_public_key: body.metering_public_key,
                    asset_definition: body.asset_definition,
                    tariff: ForgedVpnTariff {
                        lease_fee: Numeric::new(-1_i32, 0),
                        active_fee_per_minute: body.tariff.active_fee_per_minute,
                        ingress_fee_per_mib: body.tariff.ingress_fee_per_mib,
                        egress_fee_per_mib: body.tariff.egress_fee_per_mib,
                    },
                    policy: body.policy,
                    valid_after_ms: body.valid_after_ms,
                    expires_at_ms: body.expires_at_ms,
                    settlement_grace_ms: body.settlement_grace_ms,
                },
                signature: valid.signature,
            },
        };
        assert!(
            OpenVpnLeaseEscrow::decode_from_slice(&forged.encode()).is_err(),
            "VPN escrow instruction decoding must reject a forged negative lease quantity"
        );
    }
    fn relay_keypair() -> KeyPair {
        KeyPair::try_from_seed(vec![0x44; 32], Algorithm::Ed25519)
            .expect("derive checked VPN relay-receipt fixture keypair")
    }
    fn usage_voucher() -> VpnUsageVoucherV1 {
        let key_pair = KeyPair::try_from_seed(vec![0x43; 32], Algorithm::Ed25519)
            .expect("derive checked VPN usage-voucher fixture keypair");
        let relay_key = relay_keypair();
        let (_, relay_public_key) = relay_key
            .public_key()
            .try_to_bytes()
            .expect("checked VPN relay fixture public key");
        let mut relay_id = [0_u8; 32];
        relay_id.copy_from_slice(relay_public_key);
        let body = VpnUsageVoucherBodyV1 {
            session_id: [0x11; 16],
            quote_id: [0x22; 32],
            relay_id,
            sequence: 7,
            ingress_bytes: 128,
            egress_bytes: 256,
            active_ms: 1_500,
            issued_at_ms: 1_700_000_000_000,
        };
        VpnUsageVoucherV1::try_sign(body, key_pair.private_key())
            .expect("checked VPN usage-voucher ISI fixture signature")
    }
    fn session_receipt(voucher: &VpnUsageVoucherV1) -> VpnSignedSessionReceiptV1 {
        let receipt = VpnSessionReceiptV1 {
            session_id: [0x11; 16],
            quote_id: [0x22; 32],
            payment_tx_hash: [0x44; 32],
            account_hash: [0x55; 32],
            relay_id: voucher.body.relay_id,
            ingress_bytes: 128,
            egress_bytes: 256,
            cover_bytes: 64,
            uptime_secs: 90,
            started_at_ms: 1_700_000_000_000,
            ended_at_ms: 1_700_000_090_000,
            exit_class: VpnExitClassV1::Standard,
            meter_hash: [0x66; 32],
            earned_fee: tariff()
                .fee_ceiling(&voucher.body)
                .expect("bounded VPN fee"),
            highest_voucher_sequence: voucher.body.sequence,
            client_voucher_hash: voucher.hash(),
        };
        VpnSignedSessionReceiptV1::try_sign(receipt, relay_keypair().private_key())
            .expect("checked VPN relay-receipt ISI fixture signature")
    }
    #[test]
    fn vpn_decode_from_slice_roundtrips() {
        let voucher = usage_voucher();
        assert_slice_roundtrip(OpenVpnLeaseEscrow::new(signed_quote()));
        assert_slice_roundtrip(SettleVpnLease::new(
            [0xAA; 32],
            session_receipt(&voucher),
            voucher,
        ));
        assert_slice_roundtrip(RefundExpiredVpnLease::new([0xAA; 32]));
    }
    #[test]
    fn vpn_registry_decodes_canonical_wire_ids() {
        let voucher = usage_voucher();
        let registry = crate::isi::InstructionRegistry::new()
            .register_with_id_slice::<OpenVpnLeaseEscrow>(
                "iroha.instruction.v1::vpn::OpenVpnLeaseEscrow",
            )
            .register_with_id_slice::<SettleVpnLease>("iroha.instruction.v1::vpn::SettleVpnLease")
            .register_with_id_slice::<RefundExpiredVpnLease>(
                "iroha.instruction.v1::vpn::RefundExpiredVpnLease",
            );
        assert_registry_decodes(&registry, OpenVpnLeaseEscrow::new(signed_quote()));
        assert_registry_decodes(
            &registry,
            SettleVpnLease::new([0xAA; 32], session_receipt(&voucher), voucher),
        );
        assert_registry_decodes(&registry, RefundExpiredVpnLease::new([0xAA; 32]));
    }
}
