//! Hardened launcher and offline administrator CLI for the `SoraFS` software signer.
#[cfg(not(unix))]
fn main() {
    eprintln!("SoraFS external software signer requires authenticated Unix peer credentials");
    std::process::exit(2);
}
#[cfg(unix)]
mod unix_main {
    use clap::{Args, Parser, Subcommand};
    use irohad::external_software_signer::{
        ExternalSoftwareSignerBackendsV1, ExternalSoftwareSignerBillingStatementAdapterV1,
        ExternalSoftwareSignerEvidenceViewerAdapterV1,
        ExternalSoftwareSignerGovernanceDagAdapterV1, ExternalSoftwareSignerNativeAdapterV1,
        ExternalSoftwareSignerPotrGatewayAdapterV1, ExternalSoftwareSignerPotrProviderAdapterV1,
        RuntimeConsensusThresholdSignerBackendsV1, SignerKeyAlgorithmV1, SignerPurposeBindingV1,
        SignerRoleV1, SoftwareSignerAdministratorClientV1, SoftwareSignerClientV1,
        SoftwareSignerEndpointPolicyV1, SoftwareSignerLiveProvenanceV1,
        SoftwareSignerProvisioningV1, SoftwareSignerPublicBindingV1,
        SoftwareSignerRotationRequestV1, SoftwareSignerServerV1, SoftwareSignerServiceV1,
        SoftwareSignerSignatureReceiptV1, SoftwareSignerWrappingKeyV1,
        load_software_signer_wrapping_key_from_credential_v1,
        load_software_signer_wrapping_key_from_fd_v1,
    };
    use irohad::{
        IrohaRuntimeProviderBindingsV1, IrohaRuntimeProviderSlotV1,
        RuntimeProviderBrokerExecutableArgsV1, RuntimeProviderBrokerExecutableV1,
        load_runtime_provider_broker_catalog_file_v1, load_runtime_provider_broker_policy_file_v1,
    };
    use norito::{NoritoDeserialize, NoritoSerialize};
    use std::{
        env,
        ffi::{OsStr, OsString},
        fs::{self, File},
        io::{Read as _, Write as _},
        os::{fd::OwnedFd, unix::fs::MetadataExt as _},
        path::{Component, Path, PathBuf},
        process,
        sync::Arc,
    };
    const MAX_PUBLIC_ARTIFACT_BYTES_V1: usize = 64 * 1024;
    const MAX_SIGNING_PAYLOAD_BYTES_V1: usize = 32 * 1024 * 1024;
    #[derive(Debug, Parser)]
    #[command(
        name = "sorafs_external_software_signer",
        about = "Operate one role-isolated SoraFS external software signer",
        disable_help_subcommand = true
    )]
    struct Cli {
        #[command(subcommand)]
        command: Command,
    }
    #[derive(Debug, Subcommand)]
    enum Command {
        /// Generate one encrypted key envelope and immutable genesis audit record.
        Provision(ProvisionArgs),
        /// Open an encrypted envelope and serve authenticated local peers.
        Serve(ServeArgs),
        /// Probe and export signed live public provenance.
        Qualify(QualifyArgs),
        /// Sign exact role-scoped bytes and export a raw detached signature.
        Sign(SignArgs),
        /// Verify a public signature receipt entirely offline.
        VerifyReceipt(VerifyReceiptArgs),
        /// Export administrator-authenticated live state.
        Status(AdminStatusArgs),
        /// Rotate to a predecessor-bound monotonic successor key and policy.
        Rotate(RotateArgs),
        /// Irreversibly revoke the active key generation.
        Revoke(RevokeArgs),
    }
    #[derive(Debug, Args)]
    struct WrappingKeySourceArgs {
        /// Inherited descriptor containing exactly 32 wrapping-key bytes.
        #[arg(long, value_name = "FD", conflicts_with = "systemd_credential")]
        wrapping_key_fd: Option<i32>,
        /// Name beneath systemd's `CREDENTIALS_DIRECTORY`; never a path or key value.
        #[arg(long, value_name = "NAME", conflicts_with = "wrapping_key_fd")]
        systemd_credential: Option<String>,
    }
    impl WrappingKeySourceArgs {
        fn load(self) -> Result<SoftwareSignerWrappingKeyV1, CliError> {
            match (self.wrapping_key_fd, self.systemd_credential) {
                (Some(descriptor), None) if descriptor > 2 => {
                    let descriptor = open_inherited_descriptor(descriptor)?;
                    load_software_signer_wrapping_key_from_fd_v1(descriptor)
                        .map_err(|_| CliError::Credential)
                }
                (None, Some(name)) if valid_credential_name(&name) => {
                    let directory = env::var_os("CREDENTIALS_DIRECTORY")
                        .map(PathBuf::from)
                        .ok_or(CliError::Credential)?;
                    load_software_signer_wrapping_key_from_credential_v1(&directory.join(name))
                        .map_err(|_| CliError::Credential)
                }
                _ => Err(CliError::Credential),
            }
        }
    }
    fn open_inherited_descriptor(descriptor: i32) -> Result<OwnedFd, CliError> {
        let namespace = if cfg!(target_os = "linux") {
            "/proc/self/fd"
        } else {
            "/dev/fd"
        };
        File::open(format!("{namespace}/{descriptor}"))
            .map(OwnedFd::from)
            .map_err(|_| CliError::Credential)
    }
    #[derive(Debug, Args)]
    struct ProvisionArgs {
        /// New absolute mode-0700 signer state directory.
        #[arg(long, value_name = "ABSOLUTE_PATH")]
        state_directory: PathBuf,
        /// New absolute public-binding output; never overwritten.
        #[arg(long, value_name = "ABSOLUTE_PATH")]
        binding_out: PathBuf,
        /// Stable production runtime-provider handle.
        #[arg(long)]
        handle: String,
        /// Stable service operator identity.
        #[arg(long)]
        service_id: String,
        /// Stable independently administered identity.
        #[arg(long)]
        administrator_id: String,
        /// Exact signer service UID.
        #[arg(long)]
        service_uid: u32,
        /// Exact irohad/broker client UID.
        #[arg(long)]
        client_uid: u32,
        /// Exact independent administrator UID.
        #[arg(long)]
        administrator_uid: u32,
        /// Isolated signing role.
        #[arg(long)]
        role: SignerRoleV1,
        /// Lowercase-hex Governance DAG publisher peer ID (Governance only).
        #[arg(long, value_name = "LOWER_HEX")]
        governance_publisher_peer_id_hex: Option<String>,
        /// Lowercase-hex 32-byte `PoTR` signer identity (`PoTR` only).
        #[arg(long, value_name = "LOWER_HEX_64")]
        potr_signer_id_hex: Option<String>,
        /// Lowercase-hex 32-byte `PoTR` provider identity (provider role only).
        #[arg(long, value_name = "LOWER_HEX_64")]
        potr_provider_id_hex: Option<String>,
        /// Governed textual billing signer identity (billing only).
        #[arg(long)]
        billing_signer_id: Option<String>,
        /// Governed textual `PoP` issuer identity (`PoP` only).
        #[arg(long)]
        pop_issuer_id: Option<String>,
        /// Ed25519 or ML-DSA-65; promotion permits Ed25519 only.
        #[arg(long)]
        algorithm: SignerKeyAlgorithmV1,
        /// Initial positive monotonic key revision.
        #[arg(long)]
        key_revision: u64,
        /// Initial positive monotonic policy revision.
        #[arg(long)]
        policy_revision: u64,
        /// SHA-256 of the exact reviewed public policy bytes.
        #[arg(long, value_name = "LOWER_HEX_64")]
        policy_digest_sha256: String,
        /// Maximum admitted request payload bytes.
        #[arg(long)]
        max_request_bytes: u32,
        #[command(flatten)]
        wrapping_key: WrappingKeySourceArgs,
    }
    #[derive(Debug, Args)]
    struct ServeArgs {
        #[arg(long, value_name = "ABSOLUTE_PATH")]
        state_directory: PathBuf,
        /// Reviewed canonical public binding; startup requires an exact match.
        #[arg(long, value_name = "ABSOLUTE_PATH")]
        binding: PathBuf,
        #[arg(long, value_name = "ABSOLUTE_PATH")]
        request_socket: PathBuf,
        #[arg(long, value_name = "ABSOLUTE_PATH")]
        administrator_socket: PathBuf,
        #[command(flatten)]
        wrapping_key: WrappingKeySourceArgs,
    }
    #[derive(Debug, Args)]
    struct ClientEndpointArgs {
        #[arg(long, value_name = "ABSOLUTE_PATH")]
        binding: PathBuf,
        #[arg(long, value_name = "ABSOLUTE_PATH")]
        request_socket: PathBuf,
        #[arg(long, value_name = "ABSOLUTE_PATH")]
        administrator_socket: PathBuf,
    }
    impl ClientEndpointArgs {
        fn load_policy(&self) -> Result<SoftwareSignerEndpointPolicyV1, CliError> {
            let binding = read_canonical(&self.binding, MAX_PUBLIC_ARTIFACT_BYTES_V1)?;
            SoftwareSignerEndpointPolicyV1::try_new(
                self.request_socket.clone(),
                self.administrator_socket.clone(),
                binding,
            )
            .map_err(|_| CliError::Binding)
        }
    }
    #[derive(Debug, Args)]
    struct QualifyArgs {
        #[command(flatten)]
        endpoint: ClientEndpointArgs,
        #[arg(long, value_name = "ABSOLUTE_PATH")]
        provenance_out: PathBuf,
    }
    #[derive(Debug, Args)]
    struct SignArgs {
        #[command(flatten)]
        endpoint: ClientEndpointArgs,
        /// Stable non-zero idempotency key; a conflicting reuse is rejected.
        #[arg(long, value_name = "LOWER_HEX_64")]
        operation_id: String,
        /// Regular file containing the exact bytes to sign.
        #[arg(long, value_name = "ABSOLUTE_PATH")]
        payload: PathBuf,
        /// New file receiving only the raw detached signature bytes.
        #[arg(long, value_name = "ABSOLUTE_PATH")]
        signature_out: PathBuf,
        /// New canonical public receipt file with software-key provenance.
        #[arg(long, value_name = "ABSOLUTE_PATH")]
        receipt_out: PathBuf,
    }
    #[derive(Debug, Args)]
    struct VerifyReceiptArgs {
        /// Exact reviewed canonical public binding.
        #[arg(long, value_name = "ABSOLUTE_PATH")]
        binding: PathBuf,
        /// Regular file containing the exact signed payload bytes.
        #[arg(long, value_name = "ABSOLUTE_PATH")]
        payload: PathBuf,
        /// Regular file containing only the raw detached signature bytes.
        #[arg(long, value_name = "ABSOLUTE_PATH")]
        signature: PathBuf,
        /// Canonical public signature-receipt JSON from `sign`.
        #[arg(long, value_name = "ABSOLUTE_PATH")]
        receipt: PathBuf,
        /// Exact caller-selected operation identifier.
        #[arg(long, value_name = "LOWER_HEX_64")]
        expected_operation_id: String,
        /// New payload-free canonical JSON validation artifact.
        #[arg(long, value_name = "ABSOLUTE_PATH")]
        validation_out: PathBuf,
    }
    #[derive(Debug, Args)]
    struct AdminStatusArgs {
        #[command(flatten)]
        endpoint: ClientEndpointArgs,
        #[arg(long, value_name = "ABSOLUTE_PATH")]
        provenance_out: PathBuf,
    }
    #[derive(Debug, Args)]
    struct RotateArgs {
        #[command(flatten)]
        endpoint: ClientEndpointArgs,
        #[arg(long, value_name = "LOWER_HEX_64")]
        operation_id: String,
        #[arg(long, value_name = "LOWER_HEX_64")]
        expected_audit_head: String,
        #[arg(long)]
        expected_key_revision: u64,
        #[arg(long)]
        new_key_revision: u64,
        #[arg(long)]
        new_policy_revision: u64,
        /// SHA-256 of the exact reviewed successor public policy bytes.
        #[arg(long, value_name = "LOWER_HEX_64")]
        new_policy_digest_sha256: String,
        #[arg(long)]
        algorithm: SignerKeyAlgorithmV1,
        /// New successor binding file; the reviewed predecessor is preserved.
        #[arg(long, value_name = "ABSOLUTE_PATH")]
        binding_out: PathBuf,
        #[arg(long, value_name = "ABSOLUTE_PATH")]
        provenance_out: PathBuf,
    }
    #[derive(Debug, Args)]
    struct RevokeArgs {
        #[command(flatten)]
        endpoint: ClientEndpointArgs,
        #[arg(long, value_name = "LOWER_HEX_64")]
        operation_id: String,
        #[arg(long, value_name = "LOWER_HEX_64")]
        expected_audit_head: String,
        #[arg(long)]
        expected_key_revision: u64,
        #[arg(long, value_name = "LOWER_HEX_64")]
        reason_digest: String,
        #[arg(long, value_name = "ABSOLUTE_PATH")]
        provenance_out: PathBuf,
    }
    #[derive(Debug, norito::JsonDeserialize)]
    #[norito(deny_unknown_fields)]
    struct SignatureReceiptJsonV1 {
        schema: String,
        protocol_version: u16,
        digest_contract: String,
        operation_id_hex: String,
        request_digest_blake3_hex: String,
        payload_digest_blake3_hex: String,
        payload_length: u64,
        signature_hex: String,
        commit_sequence: u64,
        commit_audit_head_blake3_hex: String,
        replayed: bool,
        binding: SignatureReceiptBindingJsonV1,
        provenance: SignatureReceiptProvenanceJsonV1,
        response_digest_blake3_hex: String,
        response_attestation_hex: String,
    }
    #[derive(Debug, norito::JsonDeserialize)]
    #[norito(deny_unknown_fields)]
    struct SignatureReceiptBindingJsonV1 {
        handle: String,
        service_id: String,
        administrator_id: String,
        service_uid: u32,
        client_uid: u32,
        administrator_uid: u32,
        role: String,
        domain: String,
        signature_algorithm: String,
        key_revision: u64,
        policy_revision: u64,
        policy_digest_sha256: String,
        public_key_hex: String,
        public_key_digest_blake3_hex: String,
        binding_digest_blake3_hex: String,
        audit_genesis_digest_blake3_hex: String,
        max_request_bytes: u32,
    }
    #[derive(Debug, norito::JsonDeserialize)]
    #[norito(deny_unknown_fields)]
    struct SignatureReceiptProvenanceJsonV1 {
        audit_sequence: u64,
        audit_head_blake3_hex: String,
        revoked: bool,
        attestation_hex: String,
    }
    #[derive(Clone, Copy, Debug)]
    enum CliError {
        Credential,
        Binding,
        Input,
        Output,
        Service,
        Client,
    }
    impl CliError {
        const fn message(self) -> &'static str {
            match self {
                Self::Credential => "runtime secret credential was rejected",
                Self::Binding => "public software-signer binding was rejected",
                Self::Input => "bounded canonical input was rejected",
                Self::Output => "new output artifact could not be committed",
                Self::Service => "software signer service failed closed",
                Self::Client => "authenticated signer operation failed closed",
            }
        }
    }
    /// Terminal launcher error retains credential decoder provenance until reporting.
    #[derive(Debug)]
    enum LauncherError {
        Operation(CliError),
        ThresholdCredential(
            irohad::external_software_signer::RuntimeConsensusThresholdSignerCredentialErrorV1,
        ),
    }
    impl From<CliError> for LauncherError {
        fn from(error: CliError) -> Self {
            Self::Operation(error)
        }
    }
    impl LauncherError {
        fn message(&self) -> &'static str {
            match self {
                Self::Operation(error) => error.message(),
                Self::ThresholdCredential(error) => match error {
                    irohad::external_software_signer::RuntimeConsensusThresholdSignerCredentialErrorV1::Unavailable
                    | irohad::external_software_signer::RuntimeConsensusThresholdSignerCredentialErrorV1::Session(_)
                    | irohad::external_software_signer::RuntimeConsensusThresholdSignerCredentialErrorV1::DecodeResource(_)
                    | irohad::external_software_signer::RuntimeConsensusThresholdSignerCredentialErrorV1::ParliamentFunding(_) => "runtime secret credential is locally unavailable",
                    _ => "runtime secret credential was rejected",
                },
            }
        }
    }
    impl std::fmt::Display for LauncherError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(self.message())
        }
    }
    impl std::error::Error for LauncherError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            match self {
                Self::ThresholdCredential(error) => Some(error),
                Self::Operation(_) => None,
            }
        }
    }
    pub fn main() {
        let result = if is_standard_broker_argv0(env::args_os().next().as_deref()) {
            run_standard_runtime_provider_broker()
        } else {
            run(Cli::parse()).map_err(LauncherError::from)
        };
        if let Err(error) = result {
            eprintln!("{}", error.message());
            process::exit(1);
        }
    }
    fn run(cli: Cli) -> Result<(), CliError> {
        match cli.command {
            Command::Provision(args) => provision(args),
            Command::Serve(args) => serve(args),
            Command::Qualify(args) => qualify(&args),
            Command::Sign(args) => sign(&args),
            Command::VerifyReceipt(args) => verify_receipt(&args),
            Command::Status(args) => status(&args),
            Command::Rotate(args) => rotate(&args),
            Command::Revoke(args) => revoke(&args),
        }
    }
    fn provision(args: ProvisionArgs) -> Result<(), CliError> {
        let policy_digest = parse_digest(&args.policy_digest_sha256)?;
        let purpose_binding = purpose_binding_from_args(&args)?;
        let wrapping_key = args.wrapping_key.load()?;
        let service = SoftwareSignerServiceV1::provision(
            args.state_directory,
            SoftwareSignerProvisioningV1 {
                handle: args.handle,
                service_id: args.service_id,
                administrator_id: args.administrator_id,
                service_uid: args.service_uid,
                client_uid: args.client_uid,
                administrator_uid: args.administrator_uid,
                role: args.role,
                purpose_binding,
                algorithm: args.algorithm,
                key_revision: args.key_revision,
                policy_revision: args.policy_revision,
                policy_digest,
                max_request_bytes: args.max_request_bytes,
            },
            wrapping_key,
        )
        .map_err(|_| CliError::Service)?;
        write_canonical_new(
            &args.binding_out,
            &service.public_binding().map_err(|_| CliError::Service)?,
            0o644,
        )
    }
    fn purpose_binding_from_args(args: &ProvisionArgs) -> Result<SignerPurposeBindingV1, CliError> {
        let no_peer = args.governance_publisher_peer_id_hex.is_none();
        let no_signer = args.potr_signer_id_hex.is_none();
        let no_provider = args.potr_provider_id_hex.is_none();
        let no_billing = args.billing_signer_id.is_none();
        let no_issuer = args.pop_issuer_id.is_none();
        let no_context = no_peer && no_signer && no_provider && no_billing && no_issuer;
        match args.role {
            SignerRoleV1::ProofOutcome
            | SignerRoleV1::Repair
            | SignerRoleV1::Reserve
            | SignerRoleV1::Orderbook
            | SignerRoleV1::Promotion
                if no_context =>
            {
                Ok(SignerPurposeBindingV1::NativeOrPromotion)
            }
            SignerRoleV1::GovernanceDag if no_signer && no_provider && no_billing && no_issuer => {
                let encoded = args
                    .governance_publisher_peer_id_hex
                    .as_deref()
                    .ok_or(CliError::Input)?;
                let publisher_peer_id = parse_lower_hex_bytes(
                    encoded,
                    sorafs_manifest::GOVERNANCE_DAG_PUBLISHER_PEER_ID_MAX_BYTES_V1,
                )?;
                if publisher_peer_id.is_empty() {
                    return Err(CliError::Input);
                }
                Ok(SignerPurposeBindingV1::GovernanceDag { publisher_peer_id })
            }
            SignerRoleV1::PotrGateway if no_peer && no_provider && no_billing && no_issuer => {
                Ok(SignerPurposeBindingV1::PotrGateway {
                    signer_id: parse_digest(
                        args.potr_signer_id_hex.as_deref().ok_or(CliError::Input)?,
                    )?,
                })
            }
            SignerRoleV1::PotrProvider if no_peer && no_billing && no_issuer => {
                Ok(SignerPurposeBindingV1::PotrProvider {
                    signer_id: parse_digest(
                        args.potr_signer_id_hex.as_deref().ok_or(CliError::Input)?,
                    )?,
                    provider_id: parse_digest(
                        args.potr_provider_id_hex
                            .as_deref()
                            .ok_or(CliError::Input)?,
                    )?,
                })
            }
            SignerRoleV1::BillingStatement if no_peer && no_signer && no_provider && no_issuer => {
                Ok(SignerPurposeBindingV1::BillingStatement {
                    signer_id: args.billing_signer_id.clone().ok_or(CliError::Input)?,
                })
            }
            SignerRoleV1::EvidenceViewer if no_context => {
                Ok(SignerPurposeBindingV1::EvidenceViewer)
            }
            SignerRoleV1::PopCredentials if no_peer && no_signer && no_provider && no_billing => {
                Ok(SignerPurposeBindingV1::PopCredentials {
                    issuer_id: args.pop_issuer_id.clone().ok_or(CliError::Input)?,
                })
            }
            _ => Err(CliError::Input),
        }
    }
    fn serve(args: ServeArgs) -> Result<(), CliError> {
        let expected: SoftwareSignerPublicBindingV1 =
            read_canonical(&args.binding, MAX_PUBLIC_ARTIFACT_BYTES_V1)?;
        let wrapping_key = args.wrapping_key.load()?;
        let service = Arc::new(
            SoftwareSignerServiceV1::open(args.state_directory, wrapping_key)
                .map_err(|_| CliError::Service)?,
        );
        if service.public_binding().map_err(|_| CliError::Service)? != expected {
            return Err(CliError::Binding);
        }
        let policy = SoftwareSignerEndpointPolicyV1::try_new(
            args.request_socket,
            args.administrator_socket,
            expected,
        )
        .map_err(|_| CliError::Binding)?;
        SoftwareSignerServerV1::try_new(service, policy)
            .and_then(SoftwareSignerServerV1::serve)
            .map_err(|_| CliError::Service)
    }
    fn qualify(args: &QualifyArgs) -> Result<(), CliError> {
        let client = SoftwareSignerClientV1::new(args.endpoint.load_policy()?);
        let provenance = client.qualify().map_err(|_| CliError::Client)?;
        write_canonical_new(&args.provenance_out, &provenance, 0o644)
    }
    fn sign(args: &SignArgs) -> Result<(), CliError> {
        let operation_id = parse_digest(&args.operation_id)?;
        let payload = read_bounded_regular(&args.payload, MAX_SIGNING_PAYLOAD_BYTES_V1)?;
        let client = SoftwareSignerClientV1::new(args.endpoint.load_policy()?);
        let receipt = client
            .sign(operation_id, &payload)
            .map_err(|_| CliError::Client)?;
        write_signature_receipt_json_new(&args.receipt_out, &receipt)?;
        write_new(&args.signature_out, &receipt.signature, 0o644)
    }
    fn verify_receipt(args: &VerifyReceiptArgs) -> Result<(), CliError> {
        let binding: SoftwareSignerPublicBindingV1 =
            read_canonical(&args.binding, MAX_PUBLIC_ARTIFACT_BYTES_V1)?;
        let payload = read_bounded_regular(&args.payload, MAX_SIGNING_PAYLOAD_BYTES_V1)?;
        let signature = read_bounded_regular(&args.signature, MAX_PUBLIC_ARTIFACT_BYTES_V1)?;
        let expected_operation_id = parse_digest(&args.expected_operation_id)?;
        let receipt = read_signature_receipt_json(&args.receipt, &binding)?;
        receipt
            .verify_offline(&binding, expected_operation_id, &payload, &signature)
            .map_err(|_| CliError::Client)?;
        write_receipt_validation_json_new(&args.validation_out, &receipt, &signature, &binding)
    }
    fn status(args: &AdminStatusArgs) -> Result<(), CliError> {
        let client = SoftwareSignerAdministratorClientV1::new(args.endpoint.load_policy()?);
        let provenance = client.status().map_err(|_| CliError::Client)?;
        write_canonical_new(&args.provenance_out, &provenance, 0o644)
    }
    fn rotate(args: &RotateArgs) -> Result<(), CliError> {
        let client = SoftwareSignerAdministratorClientV1::new(args.endpoint.load_policy()?);
        let provenance = client
            .rotate(SoftwareSignerRotationRequestV1 {
                operation_id: parse_digest(&args.operation_id)?,
                expected_audit_head: parse_digest(&args.expected_audit_head)?,
                expected_key_revision: args.expected_key_revision,
                new_key_revision: args.new_key_revision,
                new_policy_revision: args.new_policy_revision,
                new_policy_digest: parse_digest(&args.new_policy_digest_sha256)?,
                algorithm: args.algorithm,
            })
            .map_err(|_| CliError::Client)?;
        write_canonical_new(&args.binding_out, &provenance.binding, 0o644)?;
        write_canonical_new(&args.provenance_out, &provenance, 0o644)
    }
    fn revoke(args: &RevokeArgs) -> Result<(), CliError> {
        let client = SoftwareSignerAdministratorClientV1::new(args.endpoint.load_policy()?);
        let provenance = client
            .revoke(
                parse_digest(&args.operation_id)?,
                parse_digest(&args.expected_audit_head)?,
                args.expected_key_revision,
                parse_digest(&args.reason_digest)?,
            )
            .map_err(|_| CliError::Client)?;
        write_canonical_new(&args.provenance_out, &provenance, 0o644)
    }
    fn is_standard_broker_argv0(value: Option<&OsStr>) -> bool {
        value
            .map(Path::new)
            .and_then(Path::file_name)
            .is_some_and(|name| name == "iroha-runtime-provider-broker-v1")
    }
    #[cfg(any(test, target_os = "macos"))]
    fn launchd_threshold_bundle_fifo_metadata_is_exact_v1(
        file_type: rustix::fs::FileType,
        owner_uid: u32,
        link_count: u64,
        mode: u32,
    ) -> bool {
        file_type == rustix::fs::FileType::Fifo
            && owner_uid == 0
            && link_count == 1
            && mode & 0o7777 == 0o600
    }
    #[cfg(target_os = "macos")]
    fn validate_launchd_threshold_bundle_stdin_v1(stdin: &std::io::Stdin) -> Result<(), CliError> {
        use std::os::fd::AsFd as _;

        let metadata = rustix::fs::fstat(stdin.as_fd()).map_err(|_| CliError::Credential)?;
        let owner_uid = metadata.st_uid;
        let link_count = u64::from(metadata.st_nlink);
        if !launchd_threshold_bundle_fifo_metadata_is_exact_v1(
            rustix::fs::FileType::from_raw_mode(metadata.st_mode),
            owner_uid,
            link_count,
            u32::from(metadata.st_mode),
        ) {
            return Err(CliError::Credential);
        }
        Ok(())
    }
    /// Admit one original pool from the parsed policy before any credential input.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn standard_broker_credential_budget_v1(
        catalog: &IrohaRuntimeProviderBindingsV1,
        broker_policy: &iroha_config::parameters::actual::RuntimeProviderBroker,
    ) -> Result<iroha_core::state::AllocationBudget, CliError> {
        catalog
            .validate_credential_memory_policy_v1(broker_policy)
            .map_err(|_| CliError::Binding)?;
        Ok(iroha_core::state::AllocationBudget::new(
            broker_policy.credential_max_memory_bytes.get(),
        ))
    }
    /// Import both platform handoffs through the one already admitted pool.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn load_standard_threshold_signers_v1(
        catalog: &IrohaRuntimeProviderBindingsV1,
        broker_policy: &iroha_config::parameters::actual::RuntimeProviderBroker,
    ) -> Result<RuntimeConsensusThresholdSignerBackendsV1, LauncherError> {
        let credential_budget = standard_broker_credential_budget_v1(catalog, broker_policy)?;
        #[cfg(target_os = "linux")]
        let threshold_signers = {
            let credential_directory = env::var_os("CREDENTIALS_DIRECTORY").map(PathBuf::from);
            RuntimeConsensusThresholdSignerBackendsV1::load_from_credential_directory_v1(
                catalog,
                credential_directory.as_deref(),
                &credential_budget,
            )
            .map_err(LauncherError::ThresholdCredential)?
        };
        #[cfg(target_os = "macos")]
        let threshold_signers = {
            let stdin = std::io::stdin();
            validate_launchd_threshold_bundle_stdin_v1(&stdin)?;
            let mut credential_bundle = stdin.lock();
            RuntimeConsensusThresholdSignerBackendsV1::load_from_launchd_credential_bundle_v1(
                catalog,
                &mut credential_bundle,
                &credential_budget,
            )
            .map_err(LauncherError::ThresholdCredential)?
        };
        Ok(threshold_signers)
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn run_standard_runtime_provider_broker() -> Result<(), LauncherError> {
        let args = RuntimeProviderBrokerExecutableArgsV1::parse();
        let broker_policy = load_runtime_provider_broker_policy_file_v1(args.broker_policy_path())
            .map_err(|_| CliError::Binding)?;
        let catalog = load_runtime_provider_broker_catalog_file_v1(args.catalog_path())
            .map_err(|_| CliError::Binding)?;
        let threshold_signers = load_standard_threshold_signers_v1(&catalog, &broker_policy)?;
        let mut signers =
            ExternalSoftwareSignerBackendsV1::new().with_base_registry(Arc::new(threshold_signers));
        for configured in catalog.iter() {
            if matches!(
                configured.slot(),
                IrohaRuntimeProviderSlotV1::GlobalBeaconPartialSigner
                    | IrohaRuntimeProviderSlotV1::ParliamentTlePartialReleaseSigner
            ) {
                continue;
            }
            let role_name = fixed_catalog_signer_role_name(configured)?;
            let (binding_path, request_socket, administrator_socket) =
                fixed_signer_paths(role_name);
            let binding: SoftwareSignerPublicBindingV1 =
                read_canonical(&binding_path, MAX_PUBLIC_ARTIFACT_BYTES_V1)?;
            let policy = SoftwareSignerEndpointPolicyV1::try_new(
                request_socket,
                administrator_socket,
                binding.clone(),
            )
            .map_err(|_| CliError::Binding)?;
            let client = SoftwareSignerClientV1::new(policy);
            match configured.slot() {
                IrohaRuntimeProviderSlotV1::ProofOutcomeTransactionSigner
                | IrohaRuntimeProviderSlotV1::RepairTransactionSigner
                | IrohaRuntimeProviderSlotV1::ReserveTransactionSigner
                | IrohaRuntimeProviderSlotV1::OrderbookTransactionSigner => {
                    signers.insert_native(Arc::new(
                        ExternalSoftwareSignerNativeAdapterV1::try_new(client)
                            .map_err(|_| CliError::Client)?,
                    ))
                }
                IrohaRuntimeProviderSlotV1::GovernanceDagSigner => {
                    let SignerPurposeBindingV1::GovernanceDag { publisher_peer_id } =
                        binding.purpose_binding
                    else {
                        return Err(CliError::Binding.into());
                    };
                    signers.insert_governance_dag(Arc::new(
                        ExternalSoftwareSignerGovernanceDagAdapterV1::try_new(
                            client,
                            publisher_peer_id,
                        )
                        .map_err(|_| CliError::Client)?,
                    ))
                }
                IrohaRuntimeProviderSlotV1::PotrGatewaySigner => {
                    let SignerPurposeBindingV1::PotrGateway { signer_id } = binding.purpose_binding
                    else {
                        return Err(CliError::Binding.into());
                    };
                    signers.insert_potr_gateway(Arc::new(
                        ExternalSoftwareSignerPotrGatewayAdapterV1::try_new(client, signer_id)
                            .map_err(|_| CliError::Client)?,
                    ))
                }
                IrohaRuntimeProviderSlotV1::PotrProviderSigner => {
                    let SignerPurposeBindingV1::PotrProvider {
                        signer_id,
                        provider_id,
                    } = binding.purpose_binding
                    else {
                        return Err(CliError::Binding.into());
                    };
                    signers.insert_potr_provider(Arc::new(
                        ExternalSoftwareSignerPotrProviderAdapterV1::try_new(
                            client,
                            signer_id,
                            provider_id,
                        )
                        .map_err(|_| CliError::Client)?,
                    ))
                }
                IrohaRuntimeProviderSlotV1::BillingStatementSigner => {
                    let SignerPurposeBindingV1::BillingStatement { signer_id } =
                        binding.purpose_binding
                    else {
                        return Err(CliError::Binding.into());
                    };
                    signers.insert_billing_statement(Arc::new(
                        ExternalSoftwareSignerBillingStatementAdapterV1::try_new(client, signer_id)
                            .map_err(|_| CliError::Client)?,
                    ))
                }
                IrohaRuntimeProviderSlotV1::EvidenceViewerReceiptSigner => signers
                    .insert_evidence_viewer(Arc::new(
                        ExternalSoftwareSignerEvidenceViewerAdapterV1::try_new(client)
                            .map_err(|_| CliError::Client)?,
                    )),
                _ => return Err(CliError::Binding.into()),
            }
            .map_err(|_| CliError::Binding)?;
        }
        let executable = RuntimeProviderBrokerExecutableV1::try_from_catalog_v1(
            catalog,
            broker_policy,
            &signers,
        )
        .map_err(|_| CliError::Binding)?;
        #[cfg(target_os = "linux")]
        {
            executable
                .serve_until_shutdown_signal_with_systemd_notify()
                .map_err(|_| LauncherError::Operation(CliError::Service))
        }
        #[cfg(target_os = "macos")]
        {
            executable
                .serve_until_shutdown_signal(|| {})
                .map_err(|_| LauncherError::Operation(CliError::Service))
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    fn run_standard_runtime_provider_broker() -> Result<(), LauncherError> {
        Err(CliError::Service.into())
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn fixed_catalog_signer_role_name(
        configured: &irohad::IrohaRuntimeProviderBindingV1,
    ) -> Result<&'static str, CliError> {
        Ok(match configured.slot() {
            IrohaRuntimeProviderSlotV1::ProofOutcomeTransactionSigner => "proof-outcome",
            IrohaRuntimeProviderSlotV1::RepairTransactionSigner => "repair",
            IrohaRuntimeProviderSlotV1::ReserveTransactionSigner => "reserve",
            IrohaRuntimeProviderSlotV1::OrderbookTransactionSigner => "orderbook",
            IrohaRuntimeProviderSlotV1::GovernanceDagSigner => "governance-dag",
            IrohaRuntimeProviderSlotV1::PotrGatewaySigner => "potr-gateway",
            IrohaRuntimeProviderSlotV1::PotrProviderSigner => "potr-provider",
            IrohaRuntimeProviderSlotV1::BillingStatementSigner => "billing",
            IrohaRuntimeProviderSlotV1::EvidenceViewerReceiptSigner => "evidence-viewer",
            _ => return Err(CliError::Binding),
        })
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn fixed_signer_paths(role: &str) -> (PathBuf, PathBuf, PathBuf) {
        #[cfg(target_os = "linux")]
        let (bindings, runtime) = (
            Path::new("/etc/sorafs/signers"),
            Path::new("/run/sorafs-signers"),
        );
        #[cfg(target_os = "macos")]
        let (bindings, runtime) = (
            Path::new("/private/etc/sorafs/signers"),
            Path::new("/private/var/iroha/sorafs-signers"),
        );
        let runtime = runtime.join(role);
        (
            bindings.join(format!("{role}.binding.norito")),
            runtime.join("request.sock"),
            runtime.join("administrator.sock"),
        )
    }
    fn valid_credential_name(value: &str) -> bool {
        !value.is_empty()
            && value.len() <= 128
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
            && value != "."
            && value != ".."
    }
    fn parse_digest(value: &str) -> Result<[u8; 32], CliError> {
        if value.len() != 64 {
            return Err(CliError::Input);
        }
        let decoded = parse_lower_hex_bytes(value, 32)?;
        let digest: [u8; 32] = decoded.try_into().map_err(|_| CliError::Input)?;
        if digest == [0; 32] {
            return Err(CliError::Input);
        }
        Ok(digest)
    }
    fn parse_lower_hex_bytes(value: &str, maximum: usize) -> Result<Vec<u8>, CliError> {
        if value.is_empty()
            || !value.len().is_multiple_of(2)
            || value.len() > maximum.checked_mul(2).ok_or(CliError::Input)?
            || value
                .bytes()
                .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
        {
            return Err(CliError::Input);
        }
        hex::decode(value).map_err(|_| CliError::Input)
    }
    fn read_canonical<T>(path: &Path, maximum: usize) -> Result<T, CliError>
    where
        T: NoritoSerialize,
        for<'de> T: NoritoDeserialize<'de>,
    {
        let bytes = read_bounded_regular(path, maximum)?;
        norito::decode_canonical(&bytes).map_err(|_| CliError::Input)
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct DirectoryIdentity {
        device: u64,
        inode: u64,
        owner: u32,
        mode: u32,
    }
    impl DirectoryIdentity {
        fn try_from_metadata(metadata: &fs::Metadata) -> Result<Self, CliError> {
            let identity = Self {
                device: metadata.dev(),
                inode: metadata.ino(),
                owner: metadata.uid(),
                mode: metadata.mode(),
            };
            let effective_uid = rustix::process::geteuid().as_raw();
            if !metadata.is_dir()
                || (identity.owner != 0 && identity.owner != effective_uid)
                || identity.mode & 0o022 != 0
                || metadata.nlink() == 0
            {
                return Err(CliError::Input);
            }
            // A directory's link count can track its entries (including files
            // on APFS). Publishing an artifact must not change its directory
            // identity. Device, inode, owner and mode remain pinned; regular
            // file readers and writers separately require exactly one link.
            Ok(identity)
        }
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct FileIdentity {
        device: u64,
        inode: u64,
        owner: u32,
        mode: u32,
        links: u64,
        length: u64,
    }
    impl FileIdentity {
        fn from_metadata(metadata: &fs::Metadata) -> Self {
            Self {
                device: metadata.dev(),
                inode: metadata.ino(),
                owner: metadata.uid(),
                mode: metadata.mode(),
                links: metadata.nlink(),
                length: metadata.len(),
            }
        }
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct FileSnapshot {
        identity: FileIdentity,
        modified_seconds: i64,
        modified_nanoseconds: i64,
        changed_seconds: i64,
        changed_nanoseconds: i64,
    }
    impl FileSnapshot {
        fn from_metadata(metadata: &fs::Metadata) -> Self {
            Self {
                identity: FileIdentity::from_metadata(metadata),
                modified_seconds: metadata.mtime(),
                modified_nanoseconds: metadata.mtime_nsec(),
                changed_seconds: metadata.ctime(),
                changed_nanoseconds: metadata.ctime_nsec(),
            }
        }
    }
    struct AnchoredParent {
        directory: File,
        name: OsString,
        chain: Vec<DirectoryIdentity>,
    }
    fn open_anchored_parent(path: &Path, error: CliError) -> Result<AnchoredParent, CliError> {
        validate_absolute_normal(path).map_err(|_| error)?;
        let mut names = path
            .components()
            .filter_map(|component| match component {
                Component::Normal(name) => Some(name.to_owned()),
                _ => None,
            })
            .collect::<Vec<_>>();
        let name = names.pop().ok_or(error)?;
        let flags = rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC;
        let mut directory = rustix::fs::open("/", flags, rustix::fs::Mode::empty())
            .map(File::from)
            .map_err(|_| error)?;
        let mut chain = vec![
            DirectoryIdentity::try_from_metadata(&directory.metadata().map_err(|_| error)?)
                .map_err(|_| error)?,
        ];
        for component in names {
            directory =
                rustix::fs::openat(&directory, &component, flags, rustix::fs::Mode::empty())
                    .map(File::from)
                    .map_err(|_| error)?;
            chain.push(
                DirectoryIdentity::try_from_metadata(&directory.metadata().map_err(|_| error)?)
                    .map_err(|_| error)?,
            );
        }
        Ok(AnchoredParent {
            directory,
            name,
            chain,
        })
    }
    fn verify_parent_chain(
        path: &Path,
        expected: &AnchoredParent,
        error: CliError,
    ) -> Result<(), CliError> {
        let observed = open_anchored_parent(path, error)?;
        if observed.name != expected.name || observed.chain != expected.chain {
            return Err(error);
        }
        Ok(())
    }
    fn open_anchored_regular(parent: &AnchoredParent, error: CliError) -> Result<File, CliError> {
        rustix::fs::openat(
            &parent.directory,
            &parent.name,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::NONBLOCK
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map(File::from)
        .map_err(|_| error)
    }
    fn read_bounded_regular(path: &Path, maximum: usize) -> Result<Vec<u8>, CliError> {
        read_bounded_regular_with_hook(path, maximum, || {})
    }
    fn read_bounded_regular_with_hook<F>(
        path: &Path,
        maximum: usize,
        after_open: F,
    ) -> Result<Vec<u8>, CliError>
    where
        F: FnOnce(),
    {
        let parent = open_anchored_parent(path, CliError::Input)?;
        let mut file = open_anchored_regular(&parent, CliError::Input)?;
        let metadata = file.metadata().map_err(|_| CliError::Input)?;
        let before = FileSnapshot::from_metadata(&metadata);
        let effective_uid = rustix::process::geteuid().as_raw();
        if !metadata.is_file()
            || (before.identity.owner != 0 && before.identity.owner != effective_uid)
            || before.identity.mode & 0o7022 != 0
            || before.identity.links != 1
            || before.identity.length == 0
            || before.identity.length > u64::try_from(maximum).map_err(|_| CliError::Input)?
        {
            return Err(CliError::Input);
        }
        after_open();
        let mut bytes = Vec::new();
        (&mut file)
            .take(
                u64::try_from(maximum.checked_add(1).ok_or(CliError::Input)?)
                    .map_err(|_| CliError::Input)?,
            )
            .read_to_end(&mut bytes)
            .map_err(|_| CliError::Input)?;
        if bytes.is_empty() || bytes.len() > maximum {
            return Err(CliError::Input);
        }
        let after = FileSnapshot::from_metadata(&file.metadata().map_err(|_| CliError::Input)?);
        let reopened = open_anchored_regular(&parent, CliError::Input)?;
        let reopened =
            FileIdentity::from_metadata(&reopened.metadata().map_err(|_| CliError::Input)?);
        if after != before || reopened != before.identity {
            return Err(CliError::Input);
        }
        verify_parent_chain(path, &parent, CliError::Input)?;
        Ok(bytes)
    }
    fn write_canonical_new<T: NoritoSerialize>(
        path: &Path,
        value: &T,
        mode: u32,
    ) -> Result<(), CliError> {
        let bytes = norito::encode_canonical(value).map_err(|_| CliError::Output)?;
        write_new(path, &bytes, mode)
    }
    fn read_signature_receipt_json(
        path: &Path,
        binding: &SoftwareSignerPublicBindingV1,
    ) -> Result<SoftwareSignerSignatureReceiptV1, CliError> {
        let bytes = read_bounded_regular(path, MAX_PUBLIC_ARTIFACT_BYTES_V1)?;
        let value: norito::json::Value =
            norito::json::from_slice(&bytes).map_err(|_| CliError::Input)?;
        if norito::json::to_vec(&value).map_err(|_| CliError::Input)? != bytes {
            return Err(CliError::Input);
        }
        let parsed: SignatureReceiptJsonV1 =
            norito::json::from_slice(&bytes).map_err(|_| CliError::Input)?;
        let (_, public_key_payload) = binding
            .public_key
            .try_to_bytes()
            .map_err(|_| CliError::Binding)?;
        let binding_digest = binding.digest().map_err(|()| CliError::Binding)?;
        if parsed.schema != "sorafs.external_software_signer.signature_receipt.v1"
            || parsed.protocol_version != 1
            || parsed.digest_contract != "blake3-domain-separated-v1"
            || parsed.binding.handle != binding.handle
            || parsed.binding.service_id != binding.service_id
            || parsed.binding.administrator_id != binding.administrator_id
            || parsed.binding.service_uid != binding.service_uid
            || parsed.binding.client_uid != binding.client_uid
            || parsed.binding.administrator_uid != binding.administrator_uid
            || parsed.binding.role != binding.role.to_string()
            || parsed.binding.domain != binding.domain
            || parsed.binding.signature_algorithm != binding.key_algorithm.to_string()
            || parsed.binding.key_revision != binding.key_revision
            || parsed.binding.policy_revision != binding.policy_revision
            || parsed.binding.policy_digest_sha256 != hex::encode(binding.policy_digest)
            || parsed.binding.public_key_hex != hex::encode(public_key_payload)
            || parsed.binding.public_key_digest_blake3_hex != hex::encode(binding.public_key_digest)
            || parsed.binding.binding_digest_blake3_hex != hex::encode(binding_digest)
            || parsed.binding.audit_genesis_digest_blake3_hex
                != hex::encode(binding.audit_genesis_digest)
            || parsed.binding.max_request_bytes != binding.max_request_bytes
        {
            return Err(CliError::Binding);
        }
        let provenance = SoftwareSignerLiveProvenanceV1 {
            binding: binding.clone(),
            audit_sequence: parsed.provenance.audit_sequence,
            audit_head: parse_digest(&parsed.provenance.audit_head_blake3_hex)?,
            revoked: parsed.provenance.revoked,
            attestation: parse_lower_hex_bytes(
                &parsed.provenance.attestation_hex,
                MAX_PUBLIC_ARTIFACT_BYTES_V1,
            )?,
        };
        Ok(SoftwareSignerSignatureReceiptV1 {
            operation_id: parse_digest(&parsed.operation_id_hex)?,
            request_digest: parse_digest(&parsed.request_digest_blake3_hex)?,
            payload_digest: parse_digest(&parsed.payload_digest_blake3_hex)?,
            payload_length: parsed.payload_length,
            signature: parse_lower_hex_bytes(&parsed.signature_hex, MAX_PUBLIC_ARTIFACT_BYTES_V1)?,
            commit_sequence: parsed.commit_sequence,
            commit_audit_head: parse_digest(&parsed.commit_audit_head_blake3_hex)?,
            replayed: parsed.replayed,
            provenance,
            response_digest: parse_digest(&parsed.response_digest_blake3_hex)?,
            response_attestation: parse_lower_hex_bytes(
                &parsed.response_attestation_hex,
                MAX_PUBLIC_ARTIFACT_BYTES_V1,
            )?,
        })
    }
    fn write_receipt_validation_json_new(
        path: &Path,
        receipt: &SoftwareSignerSignatureReceiptV1,
        signature: &[u8],
        binding: &SoftwareSignerPublicBindingV1,
    ) -> Result<(), CliError> {
        use norito::json::{Map, Value};
        let mut root = Map::new();
        root.insert(
            "schema".into(),
            Value::from("sorafs.external_software_signer.signature_receipt_validation.v1"),
        );
        root.insert("status".into(), Value::from("valid"));
        root.insert(
            "operation_id_hex".into(),
            Value::from(hex::encode(receipt.operation_id)),
        );
        root.insert(
            "payload_digest_blake3_hex".into(),
            Value::from(hex::encode(receipt.payload_digest)),
        );
        root.insert("payload_length".into(), Value::from(receipt.payload_length));
        root.insert(
            "signature_digest_blake3_hex".into(),
            Value::from(blake3::hash(signature).to_hex().to_string()),
        );
        root.insert(
            "binding_digest_blake3_hex".into(),
            Value::from(hex::encode(
                binding.digest().map_err(|()| CliError::Binding)?,
            )),
        );
        root.insert("service_id".into(), Value::from(binding.service_id.clone()));
        root.insert(
            "administrator_id".into(),
            Value::from(binding.administrator_id.clone()),
        );
        root.insert("role".into(), Value::from(binding.role.to_string()));
        root.insert("domain".into(), Value::from(binding.domain.clone()));
        root.insert(
            "signature_algorithm".into(),
            Value::from(binding.key_algorithm.to_string()),
        );
        root.insert("key_revision".into(), Value::from(binding.key_revision));
        root.insert(
            "policy_revision".into(),
            Value::from(binding.policy_revision),
        );
        root.insert(
            "policy_digest_sha256".into(),
            Value::from(hex::encode(binding.policy_digest)),
        );
        root.insert(
            "public_key_digest_blake3_hex".into(),
            Value::from(hex::encode(binding.public_key_digest)),
        );
        root.insert(
            "commit_sequence".into(),
            Value::from(receipt.commit_sequence),
        );
        root.insert(
            "commit_audit_head_blake3_hex".into(),
            Value::from(hex::encode(receipt.commit_audit_head)),
        );
        root.insert(
            "audit_sequence".into(),
            Value::from(receipt.provenance.audit_sequence),
        );
        root.insert(
            "audit_head_blake3_hex".into(),
            Value::from(hex::encode(receipt.provenance.audit_head)),
        );
        root.insert("replayed".into(), Value::from(receipt.replayed));
        root.insert("revoked".into(), Value::from(false));
        root.insert("payload_signature_valid".into(), Value::from(true));
        root.insert("provenance_attestation_valid".into(), Value::from(true));
        root.insert("response_attestation_valid".into(), Value::from(true));
        let bytes = norito::json::to_vec(&Value::Object(root)).map_err(|_| CliError::Output)?;
        write_new(path, &bytes, 0o600)
    }
    fn write_signature_receipt_json_new(
        path: &Path,
        receipt: &SoftwareSignerSignatureReceiptV1,
    ) -> Result<(), CliError> {
        use norito::json::{Map, Value};
        let binding = &receipt.provenance.binding;
        let (_, public_key_payload) = binding
            .public_key
            .try_to_bytes()
            .map_err(|_| CliError::Output)?;
        let mut binding_json = Map::new();
        binding_json.insert("handle".into(), Value::from(binding.handle.clone()));
        binding_json.insert("service_id".into(), Value::from(binding.service_id.clone()));
        binding_json.insert(
            "administrator_id".into(),
            Value::from(binding.administrator_id.clone()),
        );
        binding_json.insert("service_uid".into(), Value::from(binding.service_uid));
        binding_json.insert("client_uid".into(), Value::from(binding.client_uid));
        binding_json.insert(
            "administrator_uid".into(),
            Value::from(binding.administrator_uid),
        );
        binding_json.insert("role".into(), Value::from(binding.role.to_string()));
        binding_json.insert("domain".into(), Value::from(binding.domain.clone()));
        binding_json.insert(
            "signature_algorithm".into(),
            Value::from(binding.key_algorithm.to_string()),
        );
        binding_json.insert("key_revision".into(), Value::from(binding.key_revision));
        binding_json.insert(
            "policy_revision".into(),
            Value::from(binding.policy_revision),
        );
        binding_json.insert(
            "policy_digest_sha256".into(),
            Value::from(hex::encode(binding.policy_digest)),
        );
        binding_json.insert(
            "public_key_hex".into(),
            Value::from(hex::encode(public_key_payload)),
        );
        binding_json.insert(
            "public_key_digest_blake3_hex".into(),
            Value::from(hex::encode(binding.public_key_digest)),
        );
        binding_json.insert(
            "binding_digest_blake3_hex".into(),
            Value::from(hex::encode(
                binding.digest().map_err(|()| CliError::Output)?,
            )),
        );
        binding_json.insert(
            "audit_genesis_digest_blake3_hex".into(),
            Value::from(hex::encode(binding.audit_genesis_digest)),
        );
        binding_json.insert(
            "max_request_bytes".into(),
            Value::from(binding.max_request_bytes),
        );
        let mut provenance_json = Map::new();
        provenance_json.insert(
            "audit_sequence".into(),
            Value::from(receipt.provenance.audit_sequence),
        );
        provenance_json.insert(
            "audit_head_blake3_hex".into(),
            Value::from(hex::encode(receipt.provenance.audit_head)),
        );
        provenance_json.insert("revoked".into(), Value::from(receipt.provenance.revoked));
        provenance_json.insert(
            "attestation_hex".into(),
            Value::from(hex::encode(&receipt.provenance.attestation)),
        );
        let mut root = Map::new();
        root.insert(
            "schema".into(),
            Value::from("sorafs.external_software_signer.signature_receipt.v1"),
        );
        root.insert("protocol_version".into(), Value::from(1_u16));
        root.insert(
            "digest_contract".into(),
            Value::from("blake3-domain-separated-v1"),
        );
        root.insert(
            "operation_id_hex".into(),
            Value::from(hex::encode(receipt.operation_id)),
        );
        root.insert(
            "request_digest_blake3_hex".into(),
            Value::from(hex::encode(receipt.request_digest)),
        );
        root.insert(
            "payload_digest_blake3_hex".into(),
            Value::from(hex::encode(receipt.payload_digest)),
        );
        root.insert("payload_length".into(), Value::from(receipt.payload_length));
        root.insert(
            "signature_hex".into(),
            Value::from(hex::encode(&receipt.signature)),
        );
        root.insert(
            "commit_sequence".into(),
            Value::from(receipt.commit_sequence),
        );
        root.insert(
            "commit_audit_head_blake3_hex".into(),
            Value::from(hex::encode(receipt.commit_audit_head)),
        );
        root.insert("replayed".into(), Value::from(receipt.replayed));
        root.insert("binding".into(), Value::Object(binding_json));
        root.insert("provenance".into(), Value::Object(provenance_json));
        root.insert(
            "response_digest_blake3_hex".into(),
            Value::from(hex::encode(receipt.response_digest)),
        );
        root.insert(
            "response_attestation_hex".into(),
            Value::from(hex::encode(&receipt.response_attestation)),
        );
        let bytes = norito::json::to_vec(&Value::Object(root)).map_err(|_| CliError::Output)?;
        write_new(path, &bytes, 0o644)
    }
    fn write_new(path: &Path, bytes: &[u8], mode: u32) -> Result<(), CliError> {
        write_new_with_hook(path, bytes, mode, || {})
    }
    fn write_new_with_hook<F>(
        path: &Path,
        bytes: &[u8],
        mode: u32,
        before_publish: F,
    ) -> Result<(), CliError>
    where
        F: FnOnce(),
    {
        if bytes.is_empty() || mode == 0 || mode & !0o777 != 0 || mode & 0o133 != 0 {
            return Err(CliError::Output);
        }
        let parent = open_anchored_parent(path, CliError::Output)?;
        match rustix::fs::statat(
            &parent.directory,
            &parent.name,
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        ) {
            Err(error) if error == rustix::io::Errno::NOENT => {}
            _ => return Err(CliError::Output),
        }
        let (staging_name, mut staging_file) = create_staging_file(&parent, mode)?;
        let initial_metadata = staging_file.metadata().map_err(|_| CliError::Output)?;
        let staging_node = (initial_metadata.dev(), initial_metadata.ino());
        let mut published = false;
        let result = (|| {
            staging_file
                .write_all(bytes)
                .and_then(|()| staging_file.sync_all())
                .map_err(|_| CliError::Output)?;
            let staging_metadata = staging_file.metadata().map_err(|_| CliError::Output)?;
            let staging_snapshot = FileSnapshot::from_metadata(&staging_metadata);
            if !staging_metadata.is_file()
                || staging_snapshot.identity.owner != rustix::process::geteuid().as_raw()
                || staging_snapshot.identity.mode & 0o7777 != mode
                || staging_snapshot.identity.links != 1
                || staging_snapshot.identity.length
                    != u64::try_from(bytes.len()).map_err(|_| CliError::Output)?
            {
                return Err(CliError::Output);
            }
            before_publish();
            let reopened = open_named_regular(&parent.directory, &staging_name, CliError::Output)?;
            let reopened_before =
                FileSnapshot::from_metadata(&reopened.metadata().map_err(|_| CliError::Output)?);
            if reopened_before != staging_snapshot
                || !file_matches_exact_bytes(reopened, bytes, reopened_before)?
            {
                return Err(CliError::Output);
            }
            rustix::fs::renameat_with(
                &parent.directory,
                &staging_name,
                &parent.directory,
                &parent.name,
                rustix::fs::RenameFlags::NOREPLACE,
            )
            .map_err(|_| CliError::Output)?;
            published = true;
            parent.directory.sync_all().map_err(|_| CliError::Output)?;
            let published = open_anchored_regular(&parent, CliError::Output)?;
            let published_before =
                FileSnapshot::from_metadata(&published.metadata().map_err(|_| CliError::Output)?);
            if published_before.identity != staging_snapshot.identity
                || !file_matches_exact_bytes(published, bytes, published_before)?
            {
                return Err(CliError::Output);
            }
            verify_parent_chain(path, &parent, CliError::Output)
        })();
        if result.is_err() {
            let name = if published {
                &parent.name
            } else {
                &staging_name
            };
            cleanup_exact_file(&parent.directory, name, staging_node);
            let _ = parent.directory.sync_all();
        }
        result
    }
    fn create_staging_file(
        parent: &AnchoredParent,
        mode: u32,
    ) -> Result<(OsString, File), CliError> {
        let mode = rustix::fs::Mode::from_raw_mode(mode.try_into().map_err(|_| CliError::Output)?);
        for _ in 0..16 {
            let name = OsString::from(format!(
                ".software-signer-cli-{}-{:016x}.pending",
                std::process::id(),
                rand::random::<u64>()
            ));
            match rustix::fs::openat(
                &parent.directory,
                &name,
                rustix::fs::OFlags::WRONLY
                    | rustix::fs::OFlags::CREATE
                    | rustix::fs::OFlags::EXCL
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                mode,
            ) {
                Ok(descriptor) => {
                    let file = File::from(descriptor);
                    if rustix::fs::fchmod(&file, mode).is_err() {
                        let metadata = file.metadata().map_err(|_| CliError::Output)?;
                        cleanup_exact_file(
                            &parent.directory,
                            &name,
                            (metadata.dev(), metadata.ino()),
                        );
                        return Err(CliError::Output);
                    }
                    return Ok((name, file));
                }
                Err(error) if error == rustix::io::Errno::EXIST => {}
                Err(_) => return Err(CliError::Output),
            }
        }
        Err(CliError::Output)
    }
    fn open_named_regular(
        parent: &File,
        name: &OsString,
        error: CliError,
    ) -> Result<File, CliError> {
        rustix::fs::openat(
            parent,
            name,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::NONBLOCK
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map(File::from)
        .map_err(|_| error)
    }
    fn file_matches_exact_bytes(
        mut file: File,
        expected: &[u8],
        before: FileSnapshot,
    ) -> Result<bool, CliError> {
        let limit = u64::try_from(expected.len())
            .map_err(|_| CliError::Output)?
            .checked_add(1)
            .ok_or(CliError::Output)?;
        let mut observed = Vec::new();
        (&mut file)
            .take(limit)
            .read_to_end(&mut observed)
            .map_err(|_| CliError::Output)?;
        let after = FileSnapshot::from_metadata(&file.metadata().map_err(|_| CliError::Output)?);
        Ok(before == after && observed == expected)
    }
    fn cleanup_exact_file(parent: &File, name: &OsString, expected_node: (u64, u64)) {
        let Ok(file) = open_named_regular(parent, name, CliError::Output) else {
            return;
        };
        let Ok(metadata) = file.metadata() else {
            return;
        };
        if metadata.is_file()
            && metadata.uid() == rustix::process::geteuid().as_raw()
            && metadata.nlink() == 1
            && (metadata.dev(), metadata.ino()) == expected_node
        {
            let _ = rustix::fs::unlinkat(parent, name, rustix::fs::AtFlags::empty());
        }
    }
    fn validate_absolute_normal(path: &Path) -> Result<(), CliError> {
        if !path.is_absolute()
            || path.components().any(|component| {
                matches!(
                    component,
                    Component::CurDir | Component::ParentDir | Component::Prefix(_)
                )
            })
        {
            return Err(CliError::Input);
        }
        Ok(())
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        use clap::CommandFactory as _;
        use std::os::unix::fs::symlink;

        #[cfg(any(target_os = "linux", target_os = "macos"))]
        fn broker_policy_for_test(
            contents: &str,
        ) -> iroha_config::parameters::actual::RuntimeProviderBroker {
            iroha_config::parameters::actual::RuntimeProviderBroker::from_toml_source(
                iroha_config::base::toml::TomlSource::inline(
                    contents.parse().expect("public broker policy table"),
                ),
            )
            .expect("validated broker policy")
        }

        #[cfg(any(target_os = "linux", target_os = "macos"))]
        fn broker_node_config_for_test(
            policy: &iroha_config::parameters::actual::RuntimeProviderBroker,
        ) -> iroha_config::parameters::actual::Root {
            // Checked-in development keys are fixture data. No runtime file or
            // credential input is opened while projecting this public catalog.
            let contents = include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../../defaults/kagami/iroha3-dev/peer0.toml"
            ))
            .replace(
                "expected_hash_file = \"genesis.expected_hash\"",
                "expected_hash = \"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E\"",
            );
            let mut config = iroha_config::parameters::actual::Root::from_toml_source(
                iroha_config::base::toml::TomlSource::inline(
                    contents.parse().expect("development node table"),
                ),
            )
            .expect("validated fixture node configuration");
            config.runtime_provider_broker = policy.clone();
            config
        }

        #[cfg(any(target_os = "linux", target_os = "macos"))]
        fn threshold_catalog_for_test(
            policy: &iroha_config::parameters::actual::RuntimeProviderBroker,
            slot: IrohaRuntimeProviderSlotV1,
        ) -> IrohaRuntimeProviderBindingsV1 {
            let mut config = broker_node_config_for_test(policy);
            match slot {
                IrohaRuntimeProviderSlotV1::GlobalBeaconPartialSigner => {
                    config.sumeragi.global_beacon_partial_signer_provider_handle =
                        Some("software://iroha/global-beacon/primary".into());
                    config
                        .sumeragi
                        .global_beacon_partial_signer_provider_revision = Some(1);
                    config
                        .sumeragi
                        .global_beacon_partial_signer_provider_policy_digest = Some([0xA1; 32]);
                }
                IrohaRuntimeProviderSlotV1::ParliamentTlePartialReleaseSigner => {
                    config
                        .gov
                        .parliament_tle_partial_release_signer_provider_handle =
                        Some("software://iroha/parliament-tle/primary".into());
                    config
                        .gov
                        .parliament_tle_partial_release_signer_provider_revision = Some(1);
                    config
                        .gov
                        .parliament_tle_partial_release_signer_provider_policy_digest =
                        Some([0xA2; 32]);
                }
                _ => panic!("fixture must request threshold custody"),
            }
            let catalog = IrohaRuntimeProviderBindingsV1::try_from_config(&config)
                .expect("project exact public credential assembly");
            assert_eq!(catalog.len(), 1);
            let canonical = catalog.export_canonical_v1().expect("export exact catalog");
            let restored = IrohaRuntimeProviderBindingsV1::load_canonical_v1(&canonical)
                .expect("reload exact public catalog artifact");
            assert_eq!(restored, catalog);
            restored
        }

        #[cfg(any(target_os = "linux", target_os = "macos"))]
        #[test]
        fn standard_broker_policy_creates_one_exact_default_or_nondefault_credential_pool() {
            for contents in ["", "credential_max_memory_bytes = 512"] {
                let policy = broker_policy_for_test(contents);
                for slot in [
                    IrohaRuntimeProviderSlotV1::GlobalBeaconPartialSigner,
                    IrohaRuntimeProviderSlotV1::ParliamentTlePartialReleaseSigner,
                ] {
                    let catalog = threshold_catalog_for_test(&policy, slot);
                    let budget = standard_broker_credential_budget_v1(&catalog, &policy)
                        .expect("exact file policy and catalog admit the original pool");
                    let limit = policy.credential_max_memory_bytes.get();
                    assert_eq!(catalog.credential_max_memory_bytes(), limit);
                    assert_eq!(budget.limit_bytes(), limit);
                    let retained = budget.clone();
                    assert!(budget.same_pool(&retained));
                    let charge = budget.try_reserve_bytes(limit).expect("exact bound");
                    drop(budget);
                    assert_eq!(retained.reserved_bytes(), limit);
                    assert!(retained.try_reserve_bytes(1).is_err());
                    drop(charge);
                    assert_eq!(retained.reserved_bytes(), 0);
                    assert!(retained.try_reserve_bytes(limit).is_ok());
                }
            }
        }

        #[cfg(any(target_os = "linux", target_os = "macos"))]
        #[test]
        fn standard_broker_rejects_larger_or_smaller_policy_before_platform_credential_input() {
            for contents in ["", "credential_max_memory_bytes = 512"] {
                let catalog_policy = broker_policy_for_test(contents);
                let limit = catalog_policy.credential_max_memory_bytes.get();
                for slot in [
                    IrohaRuntimeProviderSlotV1::GlobalBeaconPartialSigner,
                    IrohaRuntimeProviderSlotV1::ParliamentTlePartialReleaseSigner,
                ] {
                    let catalog = threshold_catalog_for_test(&catalog_policy, slot);
                    for supplied in [1, limit - 1, limit + 1] {
                        let file_policy = broker_policy_for_test(&format!(
                            "credential_max_memory_bytes = {supplied}"
                        ));
                        assert!(matches!(
                            standard_broker_credential_budget_v1(&catalog, &file_policy),
                            Err(CliError::Binding)
                        ));
                        // Exercise the production importer, including on macOS:
                        // the policy rejection must precede stdin inspection and
                        // any platform credential decoder or backend result.
                        assert!(matches!(
                            load_standard_threshold_signers_v1(&catalog, &file_policy),
                            Err(LauncherError::Operation(CliError::Binding))
                        ));
                    }
                }
            }
        }

        #[cfg(any(target_os = "linux", target_os = "macos"))]
        #[test]
        fn standard_broker_preserves_zero_bound_governance_catalog_without_threshold_custody() {
            let policy = broker_policy_for_test("credential_max_memory_bytes = 512");
            let mut config = broker_node_config_for_test(&policy);
            let service = &mut config.torii.sorafs_storage.governance_dag_service;
            service.enabled = true;
            service.head_mode = "ipns".into();
            service.signed_head_url = None;
            service.head_authenticator_handle = None;
            service.head_authenticator_revision = None;
            service.head_authenticator_policy_digest = None;
            service.head_request_auth_public_key = None;
            service.ipfs_api_url = Some("https://governance-ingress.invalid/ipfs/".into());
            service.ipns_name = Some("k51qzi5uqu5dtest".into());
            service.ipns_key_name = Some("governance-head".into());
            service.ipfs_authenticator_handle = Some("vault://governance/ipfs-primary".into());
            service.ipfs_authenticator_revision = Some(1);
            service.ipfs_authenticator_policy_digest = Some([0xA3; 32]);
            // Canonical Ed25519 base-point public key; no secret key is needed.
            let mut public_key = [0x66; 32];
            public_key[0] = 0x58;
            service.ipfs_request_auth_public_key = Some(public_key);
            service.checkpoint_store_handle = Some("kms://governance/checkpoint-primary".into());
            service.checkpoint_store_revision = Some(1);
            service.checkpoint_store_policy_digest = Some([0xA4; 32]);
            let view = iroha_config::parameters::actual::SorafsGovernanceDagServiceView {
                source_dir: None,
                producer_publisher_peer_id: None,
                producer_signer_handle: None,
                producer_signer_revision: None,
                producer_signer_policy_digest: None,
                producer_publisher_public_key_hex: None,
                service: config.torii.sorafs_storage.governance_dag_service,
            };
            let catalog = IrohaRuntimeProviderBindingsV1::try_from_governance_dag_service_view(
                &config.common.chain,
                iroha_data_model::NetworkId::from_genesis_hash(config.genesis.expected_hash),
                &view,
            )
            .expect("exact standalone governance inventory");
            let restored = IrohaRuntimeProviderBindingsV1::load_canonical_v1(
                &catalog
                    .export_canonical_v1()
                    .expect("export governance catalog"),
            )
            .expect("reload canonical no-threshold inventory");
            assert_eq!(restored.credential_max_memory_bytes(), 0);
            assert_eq!(
                restored
                    .iter()
                    .map(irohad::IrohaRuntimeProviderBindingV1::slot)
                    .collect::<Vec<_>>(),
                vec![
                    IrohaRuntimeProviderSlotV1::GovernanceDagIpfsAuthenticator,
                    IrohaRuntimeProviderSlotV1::GovernanceDagCheckpointStore,
                ]
            );
            assert_eq!(
                standard_broker_credential_budget_v1(&restored, &policy)
                    .expect("no threshold custody is requested")
                    .limit_bytes(),
                policy.credential_max_memory_bytes.get()
            );
        }

        #[test]
        fn artifact_roundtrip_preserves_directory_identity_and_rejects_file_hardlinks() {
            let root = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
            let directory = root.path().join("artifacts");
            fs::create_dir(&directory).unwrap();
            let before =
                DirectoryIdentity::try_from_metadata(&fs::metadata(&directory).unwrap()).unwrap();
            let output = directory.join("receipt.json");
            write_new(&output, b"public receipt", 0o644).unwrap();
            assert_eq!(
                read_bounded_regular(&output, 1024).unwrap(),
                b"public receipt"
            );
            assert_eq!(
                DirectoryIdentity::try_from_metadata(&fs::metadata(&directory).unwrap()).unwrap(),
                before
            );

            fs::hard_link(&output, directory.join("alias.json")).unwrap();
            assert!(read_bounded_regular(&output, 1024).is_err());
            let moved = root.path().join("moved");
            fs::rename(&directory, &moved).unwrap();
            fs::create_dir(&directory).unwrap();
            assert_ne!(
                DirectoryIdentity::try_from_metadata(&fs::metadata(&directory).unwrap()).unwrap(),
                before
            );
        }

        #[test]
        fn receipt_json_preserves_authority_without_backend_origin_claims() {
            let root = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
            let uid = rustix::process::geteuid().as_raw();
            let service = SoftwareSignerServiceV1::provision(
                root.path().join("state"),
                SoftwareSignerProvisioningV1 {
                    handle: "software://sorafs/promotion/primary".into(),
                    service_id: "promotion-primary".into(),
                    administrator_id: "promotion-security".into(),
                    service_uid: uid,
                    client_uid: uid.checked_add(1).unwrap(),
                    administrator_uid: uid.checked_add(2).unwrap(),
                    role: SignerRoleV1::Promotion,
                    purpose_binding: SignerPurposeBindingV1::NativeOrPromotion,
                    algorithm: SignerKeyAlgorithmV1::Ed25519,
                    key_revision: 1,
                    policy_revision: 1,
                    policy_digest: [0x71; 32],
                    max_request_bytes: 2048,
                },
                SoftwareSignerWrappingKeyV1::try_from_bytes([0x72; 32]).unwrap(),
            )
            .unwrap();
            let binding = service.public_binding().unwrap();
            // This is a transport-shape fixture. Its invented operation signature
            // must remain unauthorized after decoding; parsing grants no authority.
            let receipt = SoftwareSignerSignatureReceiptV1 {
                operation_id: [0x73; 32],
                request_digest: [0x74; 32],
                payload_digest: [0x75; 32],
                payload_length: 7,
                signature: vec![0x76; 64],
                commit_sequence: 1,
                commit_audit_head: [0x77; 32],
                replayed: false,
                provenance: service.provenance().unwrap(),
                response_digest: [0x78; 32],
                response_attestation: vec![0x79; 64],
            };
            let path = root.path().join("receipt.json");
            write_signature_receipt_json_new(&path, &receipt).unwrap();
            let value: norito::json::Value =
                norito::json::from_slice(&fs::read(&path).unwrap()).unwrap();
            assert!(value["binding"].get("backend").is_none());
            let decoded = read_signature_receipt_json(&path, &binding).unwrap();
            assert_eq!(decoded, receipt);
            assert!(
                decoded
                    .verify_offline(
                        &binding,
                        receipt.operation_id,
                        b"payload",
                        &receipt.signature
                    )
                    .is_err()
            );

            for backend in ["software", "hardware"] {
                let mut retired = value.clone();
                retired
                    .as_object_mut()
                    .unwrap()
                    .get_mut("binding")
                    .unwrap()
                    .as_object_mut()
                    .unwrap()
                    .insert("backend".into(), backend.into());
                let path = root.path().join(format!("retired-{backend}.json"));
                write_new(&path, &norito::json::to_vec(&retired).unwrap(), 0o600).unwrap();
                assert!(matches!(
                    read_signature_receipt_json(&path, &binding),
                    Err(CliError::Input)
                ));
            }
            let mut substituted = binding.clone();
            substituted.service_id = "promotion-substituted".into();
            assert!(matches!(
                read_signature_receipt_json(&path, &substituted),
                Err(CliError::Binding)
            ));

            // The validation writer is called only after verify_offline succeeds
            // in the command handler. Exercise its payload-free serialization here.
            let validation_path = root.path().join("validation.json");
            write_receipt_validation_json_new(
                &validation_path,
                &receipt,
                &receipt.signature,
                &binding,
            )
            .unwrap();
            let validation: norito::json::Value =
                norito::json::from_slice(&fs::read(&validation_path).unwrap()).unwrap();
            assert!(validation.get("backend").is_none());
            assert_eq!(
                validation["service_id"],
                norito::json::Value::from(binding.service_id)
            );
            assert_eq!(fs::metadata(validation_path).unwrap().mode() & 0o777, 0o600);
        }

        #[test]
        fn credential_values_never_enter_the_cli() {
            let help = Cli::command().render_long_help().to_string();
            assert!(!help.contains("private-key"));
            assert!(!help.contains("wrapping-key-hex"));
            assert!(!help.contains("secret"));
        }
        #[test]
        fn stream_token_cli_rejects_before_credentials_or_state() {
            let parent = tempfile::tempdir().expect("isolated CLI rejection directory");
            let state = parent.path().join("stream-state");
            let binding = parent.path().join("stream-binding.norito");
            let digest = "51".repeat(32);
            let cli = Cli::try_parse_from([
                "sorafs_external_software_signer",
                "provision",
                "--state-directory",
                state.to_str().unwrap(),
                "--binding-out",
                binding.to_str().unwrap(),
                "--handle",
                "software://sorafs/stream-token/primary",
                "--service-id",
                "stream-primary",
                "--administrator-id",
                "stream-security-primary",
                "--service-uid",
                "1001",
                "--client-uid",
                "1002",
                "--administrator-uid",
                "1003",
                "--role",
                "stream_token",
                "--algorithm",
                "ed25519",
                "--key-revision",
                "1",
                "--policy-revision",
                "1",
                "--policy-digest-sha256",
                &digest,
                "--max-request-bytes",
                "2048",
            ])
            .expect("well-formed command with a forbidden software role");
            let Command::Provision(args) = cli.command else {
                panic!("provision command")
            };
            assert!(matches!(
                purpose_binding_from_args(&args),
                Err(CliError::Input)
            ));
            // No wrapping-key source exists. Reaching credential loading would return Credential.
            assert!(matches!(provision(args), Err(CliError::Input)));
            assert!(!state.exists());
            assert!(!binding.exists());
            assert_eq!(fs::read_dir(parent.path()).unwrap().count(), 0);
        }
        #[test]
        fn digest_parser_is_canonical_and_nonzero() {
            assert!(parse_digest(&"11".repeat(32)).is_ok());
            assert!(parse_digest(&"00".repeat(32)).is_err());
            assert!(parse_digest(&"AA".repeat(32)).is_err());
        }
        #[test]
        fn standard_broker_alias_and_signer_paths_are_fixed() {
            assert!(is_standard_broker_argv0(Some(OsStr::new(
                "/usr/local/libexec/iroha-runtime-provider-broker-v1"
            ))));
            assert!(!is_standard_broker_argv0(Some(OsStr::new(
                "/usr/bin/sorafs_external_software_signer"
            ))));
            let (binding, request, administrator) = fixed_signer_paths("proof-outcome");
            assert!(binding.is_absolute());
            assert!(request.is_absolute());
            assert!(administrator.is_absolute());
            assert!(binding.ends_with("proof-outcome.binding.norito"));
            assert!(request.ends_with("proof-outcome/request.sock"));
            assert!(administrator.ends_with("proof-outcome/administrator.sock"));
            for role in [
                "governance-dag",
                "potr-gateway",
                "potr-provider",
                "billing",
                "evidence-viewer",
            ] {
                let (binding, request, administrator) = fixed_signer_paths(role);
                assert!(binding.ends_with(format!("{role}.binding.norito")));
                assert!(request.ends_with(format!("{role}/request.sock")));
                assert!(administrator.ends_with(format!("{role}/administrator.sock")));
            }
            assert!(
                !Cli::command()
                    .render_long_help()
                    .to_string()
                    .contains("broker-native-signers")
            );
        }
        #[test]
        fn launchd_threshold_bundle_requires_exact_root_fifo_custody() {
            let fifo = rustix::fs::FileType::Fifo;
            assert!(launchd_threshold_bundle_fifo_metadata_is_exact_v1(
                fifo, 0, 1, 0o600
            ));
            for (file_type, owner_uid, link_count, mode) in [
                (rustix::fs::FileType::RegularFile, 0, 1, 0o600),
                (fifo, 501, 1, 0o600),
                (fifo, 0, 2, 0o600),
                (fifo, 0, 1, 0o640),
                (fifo, 0, 1, 0o4600),
            ] {
                assert!(
                    !launchd_threshold_bundle_fifo_metadata_is_exact_v1(
                        file_type, owner_uid, link_count, mode,
                    ),
                    "unsafe launchd credential metadata must fail closed"
                );
            }
        }
        #[test]
        fn artifact_io_rejects_ancestor_symlinks_and_hardlinks() {
            let root = tempfile::tempdir_in(std::env::current_dir().expect("current directory"))
                .expect("secure temporary directory");
            let real = root.path().join("real");
            fs::create_dir(&real).expect("real directory");
            let input = real.join("input.bin");
            fs::write(&input, b"reviewed input").expect("input");
            let alias = root.path().join("alias");
            symlink(&real, &alias).expect("ancestor symlink");
            assert!(read_bounded_regular(&alias.join("input.bin"), 1024).is_err());
            assert!(write_new(&alias.join("output.bin"), b"output", 0o600).is_err());
            let linked = real.join("linked.bin");
            fs::hard_link(&input, &linked).expect("input hard link");
            assert!(read_bounded_regular(&input, 1024).is_err());
            assert!(write_new(&linked, b"replacement", 0o600).is_err());
            assert_eq!(
                fs::read(&input).expect("unchanged input"),
                b"reviewed input"
            );
        }
        #[test]
        fn artifact_io_rejects_leaf_and_staging_hardlink_races() {
            let root = tempfile::tempdir_in(std::env::current_dir().expect("current directory"))
                .expect("secure temporary directory");
            let directory = root.path().join("artifacts");
            fs::create_dir(&directory).expect("artifact directory");
            let input = directory.join("input.bin");
            fs::write(&input, b"reviewed input").expect("input");
            let replacement = directory.join("replacement.bin");
            fs::write(&replacement, b"substitution!").expect("replacement");
            assert!(
                read_bounded_regular_with_hook(&input, 1024, || {
                    fs::rename(&replacement, &input).expect("replace opened leaf");
                })
                .is_err()
            );
            let output = directory.join("receipt.json");
            let captured = root.path().join("captured-staging");
            assert!(
                write_new_with_hook(&output, b"payload-free receipt", 0o600, || {
                    let staging = fs::read_dir(&directory)
                        .expect("read artifact directory")
                        .map(|entry| entry.expect("artifact entry").path())
                        .find(|path| {
                            path.file_name()
                                .and_then(|name| name.to_str())
                                .is_some_and(|name| {
                                    name.starts_with(".software-signer-cli-")
                                        && name.ends_with(".pending")
                                })
                        })
                        .expect("staging artifact");
                    fs::hard_link(staging, &captured).expect("race staging hard link");
                })
                .is_err()
            );
            assert!(!output.exists());
        }
        #[test]
        fn artifact_read_rejects_an_ancestor_swap_after_open() {
            let root = tempfile::tempdir_in(std::env::current_dir().expect("current directory"))
                .expect("secure temporary directory");
            let directory = root.path().join("input");
            let moved = root.path().join("moved");
            fs::create_dir(&directory).expect("input directory");
            let path = directory.join("payload.bin");
            fs::write(&path, b"reviewed payload").expect("payload");
            assert!(
                read_bounded_regular_with_hook(&path, 1024, || {
                    fs::rename(&directory, &moved).expect("move opened parent");
                    fs::create_dir(&directory).expect("replacement parent");
                    fs::write(directory.join("payload.bin"), b"substitution")
                        .expect("replacement payload");
                })
                .is_err()
            );
        }
        #[test]
        fn artifact_write_rejects_an_ancestor_swap_before_publish() {
            let root = tempfile::tempdir_in(std::env::current_dir().expect("current directory"))
                .expect("secure temporary directory");
            let directory = root.path().join("output");
            let moved = root.path().join("moved");
            fs::create_dir(&directory).expect("output directory");
            let path = directory.join("receipt.json");
            assert!(
                write_new_with_hook(&path, b"payload-free receipt", 0o600, || {
                    fs::rename(&directory, &moved).expect("move staged parent");
                    fs::create_dir(&directory).expect("replacement parent");
                })
                .is_err()
            );
            assert!(!path.exists());
            assert!(!moved.join("receipt.json").exists());
        }

        #[test]
        fn threshold_decoder_failure_remains_typed_until_unavailable_launcher_diagnostic() {
            use iroha_core::beacon::credential::{
                ConsensusThresholdCredentialDecodeErrorV1, decode_consensus_threshold_credential_v1,
            };
            let secret = "credential diagnostic secret sentinel".to_owned();
            let bytes = norito::encode_canonical(&vec![secret.clone()]).unwrap();
            let error = norito::with_decode_limits_scope(
                norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX),
                || decode_consensus_threshold_credential_v1::<Vec<String>>(&bytes),
            )
            .unwrap_err();
            let error = LauncherError::ThresholdCredential(error.into());
            assert_eq!(
                error.message(),
                "runtime secret credential is locally unavailable"
            );
            assert!(!format!("{error:?}").contains(&secret));
            assert!(std::error::Error::source(&error).is_some());
            let LauncherError::ThresholdCredential(irohad::external_software_signer::RuntimeConsensusThresholdSignerCredentialErrorV1::DecodeResource(original)) = error else { panic!("terminal diagnostic must keep the original cause"); };
            assert_eq!(
                original.kind(),
                norito::core::DecodeAttemptErrorKind::EnclosingLimit
            );
            assert!(matches!(
                original.into_error(),
                norito::Error::ScopedDecodeResource(_)
            ));
            let rejected = LauncherError::ThresholdCredential(
                ConsensusThresholdCredentialDecodeErrorV1::Rejected.into(),
            );
            assert_eq!(rejected.message(), "runtime secret credential was rejected");
        }

        #[test]
        fn parliament_actual_pool_refusal_remains_typed_and_locally_unavailable() {
            let pool = iroha_allocation::AllocationBudget::new(1);
            let original = pool
                .try_reserve(std::alloc::Layout::array::<u8>(2).unwrap())
                .err()
                .unwrap();
            let error = LauncherError::ThresholdCredential(
                irohad::external_software_signer::RuntimeConsensusThresholdSignerCredentialErrorV1::ParliamentFunding(
                    irohad::external_software_signer::RuntimeParliamentTleCredentialFundingErrorV1::Storage(
                        iroha_allocation::ChargedBufferError::Admission(original.clone()),
                    ),
                ),
            );
            assert_eq!(
                error.message(),
                "runtime secret credential is locally unavailable"
            );
            assert!(std::error::Error::source(&error).is_some());
            let LauncherError::ThresholdCredential(
                irohad::external_software_signer::RuntimeConsensusThresholdSignerCredentialErrorV1::ParliamentFunding(
                    irohad::external_software_signer::RuntimeParliamentTleCredentialFundingErrorV1::Storage(
                        iroha_allocation::ChargedBufferError::Admission(retained),
                    ),
                ),
            ) = error else { panic!("retain original physical admission cause"); };
            assert_eq!(retained, original);
        }
    }
}
#[cfg(unix)]
fn main() {
    unix_main::main();
}
