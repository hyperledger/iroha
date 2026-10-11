//! Source-bound identity shared by running validators and local release preparation.

use iroha_crypto::{Hash, PublicKey};
use iroha_data_model::parameter::system::ConsensusHandshakeMetadata;

/// Unvalidated immutable build metadata supplied by the owning executable.
///
/// Capture this value in a thin executable and pass it to runtime libraries, so
/// source revisions never become compilation inputs of those libraries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompiledBuildMetadata {
    version: &'static str,
    source_commit: Option<&'static str>,
    sealed_source_commit: Option<&'static str>,
    dpn_validator_release_commit: Option<&'static str>,
    cargo_features: Option<&'static str>,
    target_triple: Option<&'static str>,
}

impl CompiledBuildMetadata {
    /// Capture immutable parts compiled into the owning executable.
    #[must_use]
    pub const fn from_compiled_parts(
        version: &'static str,
        source_commit: Option<&'static str>,
        sealed_source_commit: Option<&'static str>,
        dpn_validator_release_commit: Option<&'static str>,
        cargo_features: Option<&'static str>,
        target_triple: Option<&'static str>,
    ) -> Self {
        Self {
            version,
            source_commit,
            sealed_source_commit,
            dpn_validator_release_commit,
            cargo_features,
            target_triple,
        }
    }

    /// Validate this executable's identity at the runtime admission boundary.
    ///
    /// # Errors
    /// Rejects absent, malformed, or contradictory source metadata.
    pub fn identity(self) -> Result<BuildIdentity, BuildIdentityError> {
        BuildIdentity::from_compiled_parts(
            self.version,
            self.source_commit,
            self.sealed_source_commit,
            self.dpn_validator_release_commit,
            self.cargo_features,
            self.target_triple,
        )
    }

    /// Package version compiled into the owning executable.
    #[must_use]
    pub const fn version(self) -> &'static str {
        self.version
    }

    /// Canonical source label used in executable diagnostics.
    #[must_use]
    pub const fn source_commit_label(self) -> &'static str {
        match self.source_commit {
            Some(value) => value,
            None => "unknown",
        }
    }

    /// Executable feature label used in diagnostics.
    #[must_use]
    pub const fn cargo_features_label(self) -> &'static str {
        match self.cargo_features {
            Some(value) => value,
            None => "unknown",
        }
    }

    /// Optional sealed source marker compiled into the executable.
    #[must_use]
    pub const fn sealed_source_commit(self) -> Option<&'static str> {
        self.sealed_source_commit
    }
}

/// Immutable build metadata supplied by the executable that owns a runtime.
///
/// Shared libraries never inspect environment variables or Git to construct this
/// value. It has no runtime configuration, deserialization, mutation, or default
/// path. An explicit development label is never valid release provenance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuildIdentity {
    version: &'static str,
    source_commit: &'static str,
    dpn_validator_release_commit: Option<&'static str>,
    cargo_features: Option<&'static str>,
    target_triple: Option<&'static str>,
}

/// Invalid metadata compiled into an executable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BuildIdentityError {
    /// The executable lacks a canonical source revision or package version.
    #[error(
        "executable identity requires a version and an exact lowercase 40-digit source commit or local-fast-build"
    )]
    InvalidSource,
    /// The sealed source marker contradicts the canonical executable revision.
    #[error("sealed source metadata must equal the executable's exact source commit")]
    ConflictingSealedSource,
    /// Development metadata cannot authorize a release operation.
    #[error("release admission requires an exact lowercase 40-digit source commit")]
    DevelopmentSource,
}

impl BuildIdentity {
    /// Validate immutable metadata compiled into the owning executable.
    ///
    /// The canonical source is `VERGEN_GIT_SHA`; `IROHA_GIT_COMMIT_HASH` is
    /// an optional matching sealed artifact marker, never a fallback. Local
    /// builds explicitly select `local-fast-build` without a sealed marker.
    ///
    /// # Errors
    /// Returns an error for absent, malformed or contradictory source metadata.
    /// Valid syntax alone does not establish authenticated release provenance.
    pub fn from_compiled_parts(
        version: &'static str,
        source_commit: Option<&'static str>,
        sealed_source_commit: Option<&'static str>,
        dpn_validator_release_commit: Option<&'static str>,
        cargo_features: Option<&'static str>,
        target_triple: Option<&'static str>,
    ) -> Result<Self, BuildIdentityError> {
        let source_commit = source_commit.ok_or(BuildIdentityError::InvalidSource)?;
        let exact_commit = is_exact_commit(source_commit);
        if version.is_empty()
            || version.trim() != version
            || (!exact_commit && source_commit != "local-fast-build")
        {
            return Err(BuildIdentityError::InvalidSource);
        }
        if sealed_source_commit.is_some_and(|sealed| !exact_commit || sealed != source_commit) {
            return Err(BuildIdentityError::ConflictingSealedSource);
        }
        Ok(Self {
            version,
            source_commit,
            dpn_validator_release_commit,
            cargo_features,
            target_triple,
        })
    }

    /// Package version compiled into the executable.
    #[must_use]
    pub const fn version(self) -> &'static str {
        self.version
    }

    /// Canonical source revision compiled into the executable.
    #[must_use]
    pub const fn source_commit(self) -> &'static str {
        self.source_commit
    }

    /// Require the exact source commit needed by release admission.
    ///
    /// # Errors
    /// Rejects explicit development identity. Callers must additionally verify
    /// the signed source, signer and immutable artifact closure.
    pub fn release_source_commit(self) -> Result<&'static str, BuildIdentityError> {
        if is_exact_commit(self.source_commit) {
            Ok(self.source_commit)
        } else {
            Err(BuildIdentityError::DevelopmentSource)
        }
    }

    /// Source-bound fingerprint published by the Sumeragi adapter.
    ///
    /// Its preimage remains the package version immediately followed by the
    /// exact source revision. Features and target do not change this identity.
    #[must_use]
    pub fn build_fingerprint(self) -> Hash {
        let mut bytes = self.version.as_bytes().to_vec();
        bytes.extend_from_slice(self.source_commit.as_bytes());
        Hash::new(bytes)
    }

    /// Public executable metadata in the canonical Torii status schema.
    #[must_use]
    pub fn status(self) -> iroha_torii_shared::status::BuildStatus {
        iroha_torii_shared::status::BuildStatus {
            version: self.version.to_owned(),
            git_commit_sha: self.source_commit.to_owned(),
            dpn_validator_release_commit: self
                .dpn_validator_release_commit
                .unwrap_or("unknown")
                .to_owned(),
            cargo_features: self.cargo_features.unwrap_or("unknown").to_owned(),
            target_triple: self.target_triple.unwrap_or("unknown").to_owned(),
            wire_schema_hash: hex::encode(wire_schema_hash()),
        }
    }
}

/// Wire-schema identity compiled into this binary.
///
/// Hashes the compiled schemas of the covered wire roots, in order the block wire
/// ([`SignedBlock`](iroha_data_model::block::SignedBlock)), the consensus wire
/// ([`WireMessage`](iroha_sumeragi::message::WireMessage) plus native
/// [`Evidence`](iroha_sumeragi::message::Evidence) frames), and the canonical
/// [`ExecutionResultCommitment`](iroha_data_model::sumeragi_finality::ExecutionResultCommitment)
/// payload carried inside result witnesses, with the IVM ABI hash of
/// the sole first-release syscall policy through
/// [`wire_schema_hash_of`](iroha_data_model::wire_schema::wire_schema_hash_of). Each
/// root is rendered against its own types because the wires describe different
/// types under the same schema identifiers (both define a `BlockHeader`). Opaque
/// consensus byte domains (control
/// witnesses, availability tables, rows) are described as length-prefixed byte
/// sequences named with the lengths their decoders admit; the formats inside them are
/// not part of the schema. The value is independent of the compilation target but not
/// of the enabled features (the crypto `Algorithm` schema lists feature-gated
/// variants), so release tooling reads it from a native build of the same commit with
/// the release feature set.
#[must_use]
pub fn wire_schema_hash() -> [u8; 32] {
    static HASH: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();
    *HASH.get_or_init(|| {
        let [block, consensus, execution] = covered_wire_roots();
        iroha_data_model::wire_schema::wire_schema_hash_of(
            &[&block, &consensus, &execution],
            ivm::syscalls::compute_abi_hash(ivm::SyscallPolicy::AbiV1),
        )
    })
}

/// Compiled wire roots in identity order: block, consensus and canonical execution result.
fn covered_wire_roots() -> [iroha_schema::MetaMap; 3] {
    use iroha_schema::IntoSchema;

    let mut consensus = iroha_sumeragi::message::WireMessage::schema();
    // Blocks admit canonical native Evidence frames inside opaque byte fields.
    // Include their actual derived layouts and every referenced type in the identity.
    iroha_sumeragi::message::Evidence::update_schema_map(&mut consensus);
    [
        iroha_data_model::wire_schema::covered_wire_schema(),
        consensus,
        iroha_data_model::sumeragi_finality::ExecutionResultCommitment::schema(),
    ]
}

/// Capture build metadata in the executable invoking this macro.
///
/// Expand only in executable crates, then pass this immutable value to runtime
/// libraries. Expansion occurs in the caller, keeping source revisions out of
/// library compilation inputs.
#[macro_export]
macro_rules! compiled_build_metadata {
    () => {
        $crate::release_identity::CompiledBuildMetadata::from_compiled_parts(
            env!("CARGO_PKG_VERSION"),
            option_env!("VERGEN_GIT_SHA"),
            option_env!("IROHA_GIT_COMMIT_HASH"),
            option_env!("IROHA_DPN_VALIDATOR_RELEASE_COMMIT"),
            option_env!("VERGEN_CARGO_FEATURES"),
            option_env!("VERGEN_CARGO_TARGET_TRIPLE"),
        )
    };
}

/// Capture and validate the canonical identity in the invoking executable.
///
/// Runtime libraries receive [`CompiledBuildMetadata`] from their executable
/// instead of invoking this macro themselves.
#[macro_export]
macro_rules! compiled_build_identity {
    () => {
        $crate::compiled_build_metadata!().identity()
    };
}

fn is_exact_commit(source: &str) -> bool {
    source.len() == 40
        && source
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Verify canonical signed genesis bytes against the explicitly selected genesis key.
/// Returns the actual block hash and its validated signed consensus metadata.
pub fn genesis_identity(
    bytes: &[u8],
    public_key: &PublicKey,
) -> eyre::Result<(Hash, ConsensusHandshakeMetadata)> {
    let block = iroha_genesis::decode_signed_genesis(bytes)?;
    if !block.header().is_genesis() || block.encode_wire()?.as_slice() != bytes {
        eyre::bail!("release genesis is not canonical framed Norito");
    }
    crate::validate_genesis_block(
        &block,
        &iroha_data_model::account::AccountId::new(public_key.clone()),
    )?;
    let metadata = iroha_genesis::signed_genesis_consensus_metadata(&block)?;
    Ok((Hash::from(block.hash()), metadata))
}

#[cfg(test)]
mod tests {
    use iroha_data_model::wire_schema::{wire_root_defects, wire_schema_hash_of};

    use super::*;
    const SOURCE: &str = "1234567890abcdef1234567890abcdef12345678";
    const OTHER: &str = "2234567890abcdef1234567890abcdef12345678";

    #[test]
    fn captured_build_metadata_preserves_validation_and_labels() {
        for (version, source, sealed) in [
            ("3.0.0", Some(SOURCE), Some(SOURCE)),
            ("3.0.0", Some("local-fast-build"), None),
            ("3.0.0", None, None),
            ("", Some(SOURCE), None),
            ("3.0.0", Some("unknown"), None),
            ("3.0.0", Some(SOURCE), Some(OTHER)),
        ] {
            let build = CompiledBuildMetadata::from_compiled_parts(
                version,
                source,
                sealed,
                Some(OTHER),
                Some("daemon"),
                Some("target"),
            );
            assert_eq!(
                build.identity(),
                BuildIdentity::from_compiled_parts(
                    version,
                    source,
                    sealed,
                    Some(OTHER),
                    Some("daemon"),
                    Some("target"),
                )
            );
            assert_eq!(build.version(), version);
            assert_eq!(build.source_commit_label(), source.unwrap_or("unknown"));
            assert_eq!(build.cargo_features_label(), "daemon");
            assert_eq!(build.sealed_source_commit(), sealed);
        }
        let build =
            CompiledBuildMetadata::from_compiled_parts("3.0.0", None, None, None, None, None);
        assert_eq!(build.source_commit_label(), "unknown");
        assert_eq!(build.cargo_features_label(), "unknown");
        assert_eq!(build.sealed_source_commit(), None);
        let build = CompiledBuildMetadata::from_compiled_parts(
            "3.0.0",
            Some("local-fast-build"),
            None,
            None,
            None,
            None,
        );
        assert_eq!(
            build.identity().unwrap().release_source_commit(),
            Err(BuildIdentityError::DevelopmentSource)
        );
    }

    #[test]
    fn executable_identity_rejects_missing_malformed_and_conflicting_source() {
        for source in [
            None,
            Some(""),
            Some("unknown"),
            Some(" HEAD "),
            Some("test-build"),
            Some("1234567890abcdef1234567890abcdef1234567"),
            Some("1234567890ABCDEF1234567890abcdef12345678"),
            Some("1234567890abcdef1234567890abcdef12345678\n"),
        ] {
            assert_eq!(
                BuildIdentity::from_compiled_parts("3.0.0", source, None, None, None, None),
                Err(BuildIdentityError::InvalidSource)
            );
        }
        for version in ["", " 3.0.0", "3.0.0\n"] {
            assert_eq!(
                BuildIdentity::from_compiled_parts(version, Some(SOURCE), None, None, None, None),
                Err(BuildIdentityError::InvalidSource)
            );
        }
        assert_eq!(
            BuildIdentity::from_compiled_parts("3.0.0", None, Some(SOURCE), None, None, None),
            Err(BuildIdentityError::InvalidSource)
        );
        for (source, sealed) in [
            (SOURCE, OTHER),
            (SOURCE, ""),
            ("local-fast-build", SOURCE),
            ("local-fast-build", "local-fast-build"),
        ] {
            assert_eq!(
                BuildIdentity::from_compiled_parts(
                    "3.0.0",
                    Some(source),
                    Some(sealed),
                    None,
                    None,
                    None
                ),
                Err(BuildIdentityError::ConflictingSealedSource)
            );
        }
    }

    #[test]
    fn development_identity_cannot_admit_a_release() {
        let development = BuildIdentity::from_compiled_parts(
            "3.0.0",
            Some("local-fast-build"),
            None,
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(
            development.release_source_commit(),
            Err(BuildIdentityError::DevelopmentSource)
        );
        let release = BuildIdentity::from_compiled_parts(
            "3.0.0",
            Some(SOURCE),
            Some(SOURCE),
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(release.release_source_commit(), Ok(SOURCE));
        assert_ne!(release.build_fingerprint(), development.build_fingerprint());
    }

    #[test]
    fn executable_profiles_share_exact_source_fingerprint_and_report_owned_metadata() {
        let daemon = BuildIdentity::from_compiled_parts(
            "3.0.0",
            Some(SOURCE),
            Some(SOURCE),
            Some(OTHER),
            Some("telemetry"),
            Some("aarch64-apple-darwin"),
        )
        .unwrap();
        let cli = BuildIdentity::from_compiled_parts(
            "3.0.0",
            Some(SOURCE),
            Some(SOURCE),
            None,
            Some("cli"),
            Some("aarch64-apple-darwin"),
        )
        .unwrap();
        let pk2 = BuildIdentity::from_compiled_parts(
            "3.0.0",
            Some(SOURCE),
            Some(SOURCE),
            None,
            Some("dev-tools"),
            Some("aarch64-unknown-linux-gnu"),
        )
        .unwrap();
        assert_eq!(daemon.build_fingerprint(), cli.build_fingerprint());
        assert_eq!(daemon.build_fingerprint(), pk2.build_fingerprint());
        assert_eq!(
            daemon.build_fingerprint(),
            Hash::new(b"3.0.01234567890abcdef1234567890abcdef12345678")
        );
        for changed in [
            BuildIdentity::from_compiled_parts("3.0.1", Some(SOURCE), None, None, None, None)
                .unwrap(),
            BuildIdentity::from_compiled_parts("3.0.0", Some(OTHER), None, None, None, None)
                .unwrap(),
        ] {
            assert_ne!(daemon.build_fingerprint(), changed.build_fingerprint());
        }
        let status = daemon.status();
        assert_eq!(status.version, daemon.version());
        assert_eq!(status.git_commit_sha, SOURCE);
        assert_eq!(status.dpn_validator_release_commit, OTHER);
        assert_eq!(status.cargo_features, "telemetry");
        assert_eq!(status.target_triple, "aarch64-apple-darwin");
        assert_eq!(status.wire_schema_hash, hex::encode(wire_schema_hash()));
    }

    #[test]
    fn wire_schema_hash_binds_compiled_wire_and_ivm_abi_v1() {
        let abi = ivm::syscalls::compute_abi_hash(ivm::SyscallPolicy::AbiV1);
        let [block, consensus, execution] = covered_wire_roots();
        let combined = wire_schema_hash_of(&[&block, &consensus, &execution], abi);
        assert_eq!(wire_schema_hash(), combined);
        assert_eq!(
            wire_schema_hash(),
            wire_schema_hash(),
            "cached value is stable"
        );
        let [block, consensus, execution] = covered_wire_roots();
        assert_eq!(
            wire_schema_hash_of(&[&block, &consensus, &execution], abi),
            combined,
            "rebuilt schemas hash identically"
        );
        let mut other_abi = abi;
        other_abi[0] ^= 1;
        assert_ne!(
            wire_schema_hash_of(&[&block, &consensus, &execution], other_abi),
            combined
        );
        assert_eq!(hex::encode(wire_schema_hash()).len(), 64);
    }

    /// All roots are closed and unambiguous, so every type a consensus frame reaches is
    /// described, and the schema's message discriminants are the canonical Norito tags.
    #[test]
    fn consensus_wire_root_is_closed_and_matches_the_codec_tags() {
        use iroha_schema::Metadata;
        use iroha_sumeragi::{
            message::{PayloadRequest, SyncRequest, WireMessage},
            types::Hash32,
        };

        let [block, consensus, execution] = covered_wire_roots();
        for root in [&block, &consensus, &execution] {
            let defects = wire_root_defects(root);
            assert!(defects.is_empty(), "{defects:?}");
        }
        let Some(Metadata::Enum(message)) = consensus.get::<WireMessage>() else {
            panic!("the consensus root describes the wire message enum");
        };
        for (index, variant) in message.variants.iter().enumerate() {
            assert_eq!(
                usize::try_from(variant.discriminant).ok(),
                Some(index),
                "{} keeps its declaration-order tag",
                variant.tag
            );
            assert!(variant.ty.is_some(), "{} carries a payload", variant.tag);
        }
        let tag = |name: &str| {
            message
                .variants
                .iter()
                .find(|variant| variant.tag == name)
                .map(|variant| variant.discriminant)
        };
        let instance = Hash32([7; 32]);
        let sync = WireMessage::SyncRequest(SyncRequest {
            instance,
            from_height: 1,
            max_count: 1,
            max_bytes: 1,
        });
        let payload = WireMessage::PayloadRequest(PayloadRequest {
            instance,
            height: 1,
            block_hash: instance,
        });
        assert_eq!(tag("SyncRequest"), Some(sync.wire_tag()));
        assert_eq!(tag("PayloadRequest"), Some(payload.wire_tag()));
    }

    /// Dropping the consensus root or changing the type of one consensus field changes the
    /// identity; the root order is bound.
    #[test]
    fn wire_schema_hash_covers_the_consensus_wire() {
        use iroha_schema::{Metadata, NamedFieldsMeta};
        use iroha_sumeragi::message::Vote;

        let abi = ivm::syscalls::compute_abi_hash(ivm::SyscallPolicy::AbiV1);
        let [block, consensus, execution] = covered_wire_roots();
        let combined = wire_schema_hash_of(&[&block, &consensus, &execution], abi);
        assert_ne!(
            wire_schema_hash_of(&[&block, &execution], abi),
            combined,
            "the consensus root is covered"
        );
        assert_ne!(
            wire_schema_hash_of(&[&consensus, &block, &execution], abi),
            combined,
            "the roots are hashed in identity order"
        );

        let Some(Metadata::Struct(vote)) = consensus.get::<Vote>().cloned() else {
            panic!("a vote is a named-field structure");
        };
        let mut declarations = vote.declarations;
        let view = declarations
            .iter_mut()
            .find(|field| field.name == "view")
            .expect("a vote names its view");
        view.ty = core::any::TypeId::of::<u32>();
        let mut changed = consensus.clone();
        changed.insert::<Vote>(Metadata::Struct(NamedFieldsMeta { declarations }));
        let defects = wire_root_defects(&changed);
        assert!(defects.is_empty(), "{defects:?}");
        assert_ne!(
            wire_schema_hash_of(&[&block, &changed, &execution], abi),
            combined,
            "changing a consensus field type changes the identity"
        );
    }

    /// Native evidence in block effects remains covered despite its opaque outer byte field.
    #[test]
    fn wire_schema_hash_covers_native_evidence_fields_and_defects() {
        use iroha_schema::{EnumVariantPayload, Metadata};
        use iroha_sumeragi::message::{Defect, Evidence};

        let [block, consensus, execution] = covered_wire_roots();
        assert!(wire_root_defects(&consensus).is_empty());
        let Some(Metadata::Enum(evidence)) = consensus.get::<Evidence>() else {
            panic!("native evidence enum");
        };
        assert_eq!(evidence.variants.len(), 5);
        let Some(Metadata::Struct(invalid)) = consensus.get::<EnumVariantPayload<Evidence, 3>>()
        else {
            panic!("native signed-content defect fields");
        };
        assert_eq!(invalid.declarations[1].name, "defect");
        assert_eq!(
            invalid.declarations[1].ty,
            core::any::TypeId::of::<Defect>()
        );
        let abi = ivm::syscalls::compute_abi_hash(ivm::SyscallPolicy::AbiV1);
        let original = wire_schema_hash_of(&[&block, &consensus, &execution], abi);
        let Some(Metadata::Enum(mut defects)) = consensus.get::<Defect>().cloned() else {
            panic!("native defect enum");
        };
        defects.variants[0].discriminant = 99;
        let mut changed = consensus.clone();
        changed.insert::<Defect>(Metadata::Enum(defects));
        assert_ne!(
            wire_schema_hash_of(&[&block, &changed, &execution], abi),
            original
        );
        let Some(Metadata::Tuple(mut votes)) =
            consensus.get::<EnumVariantPayload<Evidence, 1>>().cloned()
        else {
            panic!("two original signed votes");
        };
        votes.types[1] = core::any::TypeId::of::<u32>();
        let mut changed = consensus;
        changed.insert::<EnumVariantPayload<Evidence, 1>>(Metadata::Tuple(votes));
        assert_ne!(
            wire_schema_hash_of(&[&block, &changed, &execution], abi),
            original
        );
    }

    /// The canonical result payload remains covered inside opaque consensus witnesses.
    #[test]
    fn wire_schema_hash_covers_canonical_execution_result_fields() {
        use iroha_data_model::sumeragi_finality::ExecutionResultCommitment;
        use iroha_schema::{IntoSchema, Metadata};

        let [block, consensus, execution] = covered_wire_roots();
        assert!(wire_root_defects(&execution).is_empty());
        let abi = ivm::syscalls::compute_abi_hash(ivm::SyscallPolicy::AbiV1);
        let original = wire_schema_hash_of(&[&block, &consensus, &execution], abi);
        assert_ne!(wire_schema_hash_of(&[&block, &consensus], abi), original);
        let Some(Metadata::Struct(mut result)) =
            execution.get::<ExecutionResultCommitment>().cloned()
        else {
            panic!("canonical execution result fields");
        };
        let height = result
            .declarations
            .iter_mut()
            .find(|field| field.name == "height")
            .expect("the result binds its exact executed height");
        height.ty = core::any::TypeId::of::<u32>();
        let mut changed = execution;
        u32::update_schema_map(&mut changed);
        changed.insert::<ExecutionResultCommitment>(Metadata::Struct(result));
        assert!(wire_root_defects(&changed).is_empty());
        assert_ne!(
            wire_schema_hash_of(&[&block, &consensus, &changed], abi),
            original
        );
    }

    /// The consensus root describes each bounded byte domain a frame carries as its codec: a
    /// length-prefixed byte sequence under the domain's frame identifier, named with the lengths
    /// its decoder admits, so a changed domain or bound changes the identity.
    #[test]
    fn consensus_byte_domains_are_described_as_their_codec() {
        use iroha_schema::{IntoSchema, MetaMap, Metadata, VecMeta};
        use iroha_sumeragi::{
            availability::{
                AvailabilityFrame, MAX_AVAILABILITY_FRAME_BYTES, MAX_DA_CHUNK_SIZE_BYTES, RowBytes,
            },
            types::{ControlWitness, MAX_CONTROL_WITNESS_BYTES},
        };
        use norito::codec::Encode as _;

        /// The schema identifier, name and description of `T` in `root`.
        fn described<T: IntoSchema>(root: &MetaMap) -> (String, String, Option<Metadata>) {
            (T::id(), T::type_name(), root.get::<T>().cloned())
        }
        let [_, consensus, _] = covered_wire_roots();
        let bytes = Metadata::Vec(VecMeta {
            ty: core::any::TypeId::of::<u8>(),
        });
        // A domain is named after the last segment of its frame path.
        let domain = |frame: &str, min: usize, max: usize| {
            let name = frame.rsplit("::").next().unwrap_or(frame);
            let frame = format!("iroha_sumeragi::{frame}");
            (frame, format!("{name}<{min}..={max}>"), Some(bytes.clone()))
        };
        let max_row = usize::try_from(MAX_DA_CHUNK_SIZE_BYTES).expect("row bound fits usize");
        let actual = [
            described::<ControlWitness>(&consensus),
            described::<AvailabilityFrame>(&consensus),
            described::<RowBytes>(&consensus),
        ];
        let expected = [
            domain("ControlWitness", 0, MAX_CONTROL_WITNESS_BYTES),
            domain(
                "availability::AvailabilityFrame",
                0,
                MAX_AVAILABILITY_FRAME_BYTES,
            ),
            domain("availability::RowBytes", 2, max_row),
        ];
        assert_eq!(actual, expected);

        let raw = vec![1_u8, 2, 3];
        for encoded in [
            ControlWitness::try_from_slice(&raw).unwrap().encode(),
            AvailabilityFrame::from_untrusted(raw.clone())
                .unwrap()
                .encode(),
            RowBytes::from_untrusted(raw.clone()).unwrap().encode(),
        ] {
            assert_eq!(
                encoded,
                raw.encode(),
                "a byte domain encodes as a byte sequence"
            );
        }
    }
}
