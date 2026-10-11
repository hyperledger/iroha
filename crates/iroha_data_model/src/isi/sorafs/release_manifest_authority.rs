// Native release-manifest authority instruction, included by the canonical SoraFS ISI module.
use crate::sorafs::release_manifest_authority::ReleaseManifestActionV1;

/// Maximum complete canonical role-13 instruction, including its Norito header.
pub const RELEASE_MANIFEST_INSTRUCTION_MAX_BYTES_V1: usize = 64 * 1024;

isi! {
    /// Propose a governed release-manifest authority transition or a no-write Check.
    ///
    /// This V1 instruction is registered for canonical decoding but Core rejects execution
    /// until purpose-owned finalized custody, operation history and Check proof exist.
    #[derive(crate::DeriveJsonSerialize, crate::DeriveJsonDeserialize)]
    #[norito_schema(name = "iroha_data_model::isi::sorafs::MutateSorafsReleaseManifestAuthority")]
    #[norito(deny_unknown_fields)]
    pub struct MutateSorafsReleaseManifestAuthority {
        /// Stable deployment matching only the role-13 release-manifest purpose.
        pub deployment_id: String,
        /// Exact current custody revision; zero only before configuration.
        pub expected_control_revision: u64,
        /// Exact current custody record digest; zero only before configuration.
        #[norito(json = "crate::json_helpers::fixed_bytes")]
        pub expected_control_digest: [u8; 32],
        /// Canonical governed control, operation or challenged Check claim.
        pub action: ReleaseManifestActionV1,
    }
}
impl crate::seal::Instruction for MutateSorafsReleaseManifestAuthority {}
impl_aos_decode_from_slice!(MutateSorafsReleaseManifestAuthority {
    deployment_id: String,
    expected_control_revision: u64,
    expected_control_digest: [u8; 32],
    action: ReleaseManifestActionV1,
});
