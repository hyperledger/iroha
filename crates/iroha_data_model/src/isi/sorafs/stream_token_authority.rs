// Canonical native role-11 request; admission is owned by the matching Core Execute path.
use crate::sorafs::stream_token_authority::StreamTokenAuthorityRequestV1;

isi! {
    /// Reserve, complete, expire or challenge one provider-scoped stream-token operation.
    #[norito_schema(name = "iroha_data_model::isi::sorafs::MutateSorafsStreamTokenAuthority")]
    pub struct MutateSorafsStreamTokenAuthority {
        /// Exact V1 network, provider, control CAS and purpose-owned action.
        pub request: StreamTokenAuthorityRequestV1,
    }
}
impl crate::seal::Instruction for MutateSorafsStreamTokenAuthority {}
impl_aos_decode_from_slice!(MutateSorafsStreamTokenAuthority {
    request: StreamTokenAuthorityRequestV1,
});
