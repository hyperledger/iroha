// Canonical native gateway mutation; authority belongs to the matching Core Execute path.
use crate::sorafs::stream_token_gateway::native::StreamTokenGatewayRequestV1;

isi! {
    /// Configure one gateway or mutate its quota, lease and ordered callback state.
    #[norito_schema(name = "iroha_data_model::isi::sorafs::MutateSorafsStreamTokenGateway")]
    pub struct MutateSorafsStreamTokenGateway {
        /// Exact V1 network, gateway, current-policy CAS and bounded action.
        pub request: StreamTokenGatewayRequestV1,
    }
}
impl crate::seal::Instruction for MutateSorafsStreamTokenGateway {}
impl_aos_decode_from_slice!(MutateSorafsStreamTokenGateway {
    request: StreamTokenGatewayRequestV1,
});
