// Native account-custody instruction, included by the canonical sorafs ISI module.
use crate::sorafs::final_promotion_account_custody::FinalPromotionAccountCustodyActionV1;
isi! {
    /// Govern or check the independent final-promotion account custody under exact control CAS.
    #[derive(crate::DeriveJsonSerialize, crate::DeriveJsonDeserialize)]
    #[norito_schema(name = "iroha_data_model::isi::sorafs::MutateSorafsFinalPromotionAccountCustody")]
    #[norito(deny_unknown_fields)]
    pub struct MutateSorafsFinalPromotionAccountCustody {
        /// Stable deployment matching the account-signing purpose, independent of key rotation.
        pub deployment_id: String,
        /// Exact account-custody revision; zero only before the first configuration.
        pub expected_control_revision: u64,
        /// Exact account-custody record digest; zero only before the first configuration.
        #[norito(json = "crate::json_helpers::fixed_bytes")]
        pub expected_control_digest: [u8; 32],
        /// Governed control or no-write current eligibility check, never a receipt operation.
        pub action: FinalPromotionAccountCustodyActionV1,
    }
}
impl crate::seal::Instruction for MutateSorafsFinalPromotionAccountCustody {}
impl_aos_decode_from_slice!(MutateSorafsFinalPromotionAccountCustody {
    deployment_id: String,
    expected_control_revision: u64,
    expected_control_digest: [u8; 32],
    action: FinalPromotionAccountCustodyActionV1,
});
