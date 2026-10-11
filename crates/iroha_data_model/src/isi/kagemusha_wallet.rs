//! Closed KAGEMUSHA ledger instructions. Embedded objects retain their existing canonical
//! G1 frames; Core authenticates them and verifies complete native proofs before monetary effects.
use super::*;
use crate::{DeriveJsonDeserialize, DeriveJsonSerialize, asset::AssetBalanceScope};

/// Authenticated successful Load transactions on the selected global chain.
pub mod load_finality;
/// Native-finality authentication of actual successful Global asset registration.
pub mod registration_finality;

pub use load_finality::KagemushaWalletLoadReceiptV1;

/// Displayed online load charge, separate from the net offline amount.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    norito::NoritoSchema,
    iroha_schema::IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito_schema(name = "iroha_data_model::isi::kagemusha_wallet::KagemushaWalletLoadChargeV1")]
pub struct KagemushaWalletLoadChargeV1 {
    /// Canonical `KagemushaWalletChargeQuoteV1` frame.
    pub quote: Vec<u8>,
    /// Exact account bound by the signed quote.
    pub beneficiary: AccountId,
}

/// Closed operation set; arbitrary method names and proof verdicts are not accepted.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    norito::NoritoSchema,
    iroha_schema::IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito_schema(name = "iroha_data_model::isi::kagemusha_wallet::KagemushaWalletLedgerActionV1")]
#[norito(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
// Keep the direct u128 variant root identical on 32-bit and 64-bit targets.
#[repr(align(16))]
pub enum KagemushaWalletLedgerActionV1 {
    /// Permanently segregate the consenting reserve account's exact balance bucket.
    Register {
        /// Canonical `KagemushaWalletSchemeV1` frame.
        scheme: Vec<u8>,
        /// Canonical `KagemushaWalletAssetScopeV1` frame.
        asset: Vec<u8>,
        /// Account submitting its consent; must hold the dedicated asset permission.
        reserve: AccountId,
        /// Exact immutable balance partition.
        balance_scope: AssetBalanceScope,
    },
    /// Install one immutable complete verifier pack under the registered reserve
    /// account and its exact asset governance permission. No producer/open readiness.
    InstallVerifierPack {
        /// Registered asset whose consenting reserve authorizes this scheme install.
        asset: [u8; 32],
        /// Exact independently selected signed `ArtifactManifest` identity.
        manifest_digest: [u8; 32],
        /// Canonical complete native `VerifierPackV1` original bytes.
        pack: Vec<u8>,
    },
    /// Complete canonical activation frame; native Bootstrap verification is mandatory.
    Activate(Vec<u8>),
    /// Canonical signed unused-enrollment abandonment frame.
    Abandon(Vec<u8>),
    /// Complete canonical Retiring/later committed package proving the closing ordinal.
    CloseLoads(Vec<u8>),
    /// Debit the authenticated payer and record the requested successive Load atomically.
    IssueLoad {
        /// Wallet incarnation.
        wallet: [u8; 32],
        /// Exact registered asset digest approved for this deposit.
        asset: [u8; 32],
        /// Expected next Load ordinal; execution rejects a stale value atomically.
        ordinal: u128,
        /// Stable nonzero retry identity.
        request_id: [u8; 32],
        /// Net offline amount in registered atomic units.
        amount: u128,
        /// Optional exact displayed online charge.
        charge: Option<KagemushaWalletLoadChargeV1>,
    },
    /// Complete canonical Unload claim, paying its bound account at most once.
    Unload(Vec<u8>),
    /// Complete canonical fee claim, paying only its fixed historical beneficiary.
    ClaimFee(Vec<u8>),
    /// Retain a root-authenticated historical signer certificate.
    RetainCertificate {
        /// Registered asset binding.
        asset: [u8; 32],
        /// Canonical signer certificate frame.
        certificate: Vec<u8>,
    },
    /// Retain an issuer-authenticated credential and exact certificate set.
    RetainCredential {
        /// Canonical credential frame.
        credential: Vec<u8>,
        /// Canonical certificate-set frame.
        certificates: Vec<u8>,
    },
    /// Retain the complete signed Request and historical fee terms by their digests.
    RetainRequest(Vec<u8>),
}

isi! {
    /// One exact KAGEMUSHA ledger operation under a registered scheme.
    #[derive(DeriveJsonSerialize, DeriveJsonDeserialize)]
    #[norito_schema(name = "iroha_data_model::isi::kagemusha_wallet::KagemushaWalletLedgerV1")]
    #[repr(align(16))]
    pub struct KagemushaWalletLedgerV1 {
        /// Exact scheme identity; embedded objects must match.
        pub scheme: [u8; 32],
        /// Closed operation payload.
        pub action: KagemushaWalletLedgerActionV1,
    }
}
// Shipping assertions: these current u128 roots retain the frozen eight padding bytes
// after the 40-byte header on ARM32 as well as 64-bit hosts. This changes no field encoding.
const _: () = {
    let action = norito::core::archived_payload_align::<KagemushaWalletLedgerActionV1>();
    let ledger = norito::core::archived_payload_align::<KagemushaWalletLedgerV1>();
    assert!(action == 16 && ledger == 16);
    assert!(norito::core::Header::SIZE == 40);
    assert!((action - norito::core::Header::SIZE % action) % action == 8);
    assert!((ledger - norito::core::Header::SIZE % ledger) % ledger == 8);
};

impl crate::seal::Instruction for KagemushaWalletLedgerV1 {}
impl KagemushaWalletLedgerV1 {
    /// Canonical first-release instruction wire identity.
    pub const WIRE_ID: &'static str = "iroha.kagemusha.wallet.ledger.v1";
    /// Construct a typed instruction. Core performs bounded object decoding and authorization.
    #[must_use]
    pub const fn new(scheme: [u8; 32], action: KagemushaWalletLedgerActionV1) -> Self {
        Self { scheme, action }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn verifier_install_instruction_preserves_pin_asset_and_original_frame() {
        let action = KagemushaWalletLedgerActionV1::InstallVerifierPack {
            asset: [2; 32],
            manifest_digest: [3; 32],
            pack: vec![4, 5, 6, 0, 255],
        };
        let original = KagemushaWalletLedgerV1::new([1; 32], action);
        let bytes = norito::to_bytes(&original).unwrap();
        let recovered: KagemushaWalletLedgerV1 = norito::decode_canonical_with_limits(
            &bytes,
            norito::canonical_decode_limits(bytes.len()),
        )
        .unwrap();
        assert_eq!(recovered, original);
        let json = norito::json::to_json(&original).unwrap();
        let from_json: KagemushaWalletLedgerV1 = norito::json::from_str(&json).unwrap();
        assert_eq!(from_json, original);
    }
    #[test]
    #[ignore = "explicit maintenance capture of the current KAGEMUSHA ledger instruction"]
    fn print_ledger_identity_capture() {
        let value = KagemushaWalletLedgerV1::new(
            [1; 32],
            KagemushaWalletLedgerActionV1::IssueLoad {
                wallet: [2; 32],
                asset: [4; 32],
                ordinal: 0,
                request_id: [3; 32],
                amount: 7,
                charge: None,
            },
        );
        let row = super::super::generated_record_identity_tests::capture(value);
        println!(
            "KAGEMUSHA_LEDGER_IDENTITY={}",
            norito::json::to_json(&row).unwrap()
        );
    }
    #[test]
    fn ledger_instruction_roundtrips_through_canonical_registry_and_json() {
        let value = KagemushaWalletLedgerV1::new(
            [1; 32],
            KagemushaWalletLedgerActionV1::IssueLoad {
                wallet: [2; 32],
                asset: [4; 32],
                ordinal: 0,
                request_id: [3; 32],
                amount: 7,
                charge: None,
            },
        );
        let bytes = norito::to_bytes(&value).unwrap();
        assert_eq!(
            norito::decode_from_bytes::<KagemushaWalletLedgerV1>(&bytes).unwrap(),
            value
        );
        let json = norito::json::to_json(&value).unwrap();
        assert_eq!(
            norito::json::from_str::<KagemushaWalletLedgerV1>(&json).unwrap(),
            value
        );
        let registry = super::super::registry::default();
        let boxed: InstructionBox = value.clone().into();
        assert_eq!(
            boxed.as_any().downcast_ref::<KagemushaWalletLedgerV1>(),
            Some(&value)
        );
        assert_eq!(
            registry.wire_id(core::any::type_name::<KagemushaWalletLedgerV1>()),
            Some(KagemushaWalletLedgerV1::WIRE_ID)
        );
        assert_eq!(
            registry
                .decode(KagemushaWalletLedgerV1::WIRE_ID, &bytes)
                .unwrap()
                .unwrap()
                .as_any()
                .downcast_ref::<KagemushaWalletLedgerV1>(),
            Some(&value)
        );
    }
}
