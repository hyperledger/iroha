// Canonical role-16 topology transition instruction. Core execution remains explicitly closed.
use crate::sorafs::topology_authority::TopologyTransitionV1;

isi! {
    /// Carry one typed topology authority transition under its dedicated V1 wire identity.
    ///
    /// Decoding this instruction does not grant permission, signer custody, execution or finality.
    /// TODO: connect the purpose-owned Core adapter and finalized Check proof before admission.
    #[norito_schema(name = "iroha_data_model::isi::sorafs::MutateSorafsTopologyAuthority")]
    #[norito(deny_unknown_fields)]
    pub struct MutateSorafsTopologyAuthority {
        /// Exact deployment, control/operation heads and sole intended action.
        pub transition: TopologyTransitionV1,
    }
}
impl crate::seal::Instruction for MutateSorafsTopologyAuthority {}
impl_aos_decode_from_slice!(MutateSorafsTopologyAuthority {
    transition: TopologyTransitionV1,
});
