// Native final-promotion authority instruction, included by the canonical sorafs ISI module.
use crate::sorafs::final_promotion_authority::FinalPromotionAuthorityActionV1;
isi! {
    /// Mutate or check final promotion authority under exact deployment control CAS.
    #[norito_schema(name = "iroha_data_model::isi::sorafs::MutateSorafsFinalPromotionAuthority")]
    #[norito(deny_unknown_fields)]
    pub struct MutateSorafsFinalPromotionAuthority {
        /// Stable deployment identifier matching the sole role-14 purpose binding.
        pub deployment_id: String,
        /// Exact current custody revision; zero only before first configuration.
        pub expected_control_revision: u64,
        /// Exact current native custody record digest; zero only before first configuration.
        #[norito(json = "crate::json_helpers::fixed_bytes")]
        pub expected_control_digest: [u8; 32],
        /// Canonical governed control, exclusive signing operation or no-write eligibility check.
        pub action: FinalPromotionAuthorityActionV1,
    }
}
impl crate::seal::Instruction for MutateSorafsFinalPromotionAuthority {}
impl_aos_decode_from_slice!(MutateSorafsFinalPromotionAuthority {
    deployment_id: String,
    expected_control_revision: u64,
    expected_control_digest: [u8; 32],
    action: FinalPromotionAuthorityActionV1,
});
