// Native StreamToken custody instruction, included in the existing sorafs ISI module.
use crate::sorafs::stream_token_custody::SorafsStreamTokenCustodyActionV1;
isi! {
    /// Mutate one provider's governed `StreamToken` role control using exact predecessor CAS.
    #[norito_schema(name = "iroha_data_model::isi::sorafs::MutateSorafsStreamTokenCustody")]
    pub struct MutateSorafsStreamTokenCustody {
        /// Registered provider governed by this mutation.
        pub provider_id: ProviderId,
        /// Exact current revision; zero only for first configuration.
        pub expected_revision: u64,
        /// Exact current canonical native control digest; zero only before first configuration.
        #[norito(json = "crate::json_helpers::fixed_bytes")]
        pub expected_digest: [u8; 32],
        /// Sole canonical configure, full enrollment or terminal revocation action.
        pub action: SorafsStreamTokenCustodyActionV1,
    }
}
impl crate::seal::Instruction for MutateSorafsStreamTokenCustody {}
impl_aos_decode_from_slice!(MutateSorafsStreamTokenCustody {
    provider_id: ProviderId,
    expected_revision: u64,
    expected_digest: [u8; 32],
    action: SorafsStreamTokenCustodyActionV1,
});
