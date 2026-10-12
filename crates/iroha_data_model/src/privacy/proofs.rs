/// Statement failure against activation-specific governed limits.
#[allow(variant_size_differences)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum PrivacyActivationStatementLimitsError {
    /// Statement and activation-limit protocol tags differ.
    #[error(
        "privacy activation-limit protocol {limits_protocol:?} differs from statement protocol {statement_protocol:?}"
    )]
    ProtocolMismatch {
        /// Protocol encoded by the limits.
        limits_protocol: PrivacyProtocolIdV1,
        /// Protocol encoded by the statement.
        statement_protocol: PrivacyProtocolIdV1,
    },
    /// A statement count exceeds the activation-specific maximum.
    #[error("privacy statement count {field:?} value {count} exceeds active maximum {max}")]
    CountExceeds {
        /// Count field.
        field: PrivacyActivationLimitFieldV1,
        /// Statement count.
        count: u32,
        /// Active governed maximum.
        max: u32,
    },
}
/// Validated raw proof payload for a protocol-specific proof variant.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::privacy::PrivacyProofBytesV1")]
pub struct PrivacyProofBytesV1 {
    /// Exact native proof encoding.
    #[norito(json = "crate::json_helpers::base64_vec")]
    pub bytes: Vec<u8>,
}
impl PrivacyProofBytesV1 {
    /// Construct a proof payload for subsequent validation.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }
    /// Borrow the exact native proof bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Validate proof presence, non-degeneracy, and the configured byte bound.
    ///
    /// # Errors
    ///
    /// Returns [`PrivacyProofValidationError`] if the configured limits are
    /// invalid or the proof is empty, all zero, or too large.
    pub fn validate(
        &self,
        limits: &PrivacyConsensusLimitsV1,
    ) -> Result<(), PrivacyProofValidationError> {
        limits
            .validate()
            .map_err(PrivacyProofValidationError::InvalidLimits)?;
        if self.bytes.is_empty() {
            return Err(PrivacyProofValidationError::Empty);
        }
        if self.bytes.iter().all(|byte| *byte == 0) {
            return Err(PrivacyProofValidationError::AllZero);
        }
        let len = u64::try_from(self.bytes.len())
            .map_err(|_| PrivacyProofValidationError::LengthOverflow)?;
        if len > u64::from(limits.max_proof_bytes_per_action) {
            return Err(PrivacyProofValidationError::TooLarge {
                bytes: len,
                max: limits.max_proof_bytes_per_action,
            });
        }
        Ok(())
    }
}
/// Action-typed native ZK-AMS proof.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[norito(tag = "action", content = "proof", deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::privacy::IrohaZkAmsProofV1")]
pub enum IrohaZkAmsProofV1 {
    /// Setup-free masked Relaxed Spartan batch-admission proof.
    MaskedRelaxedSpartanBatchAdmission(PrivacyProofBytesV1),
    /// Canonical one-layer MLSAGS/LSAG Ristretto255 provisioning signature.
    Ristretto255LsagProvisionAccount(PrivacyProofBytesV1),
}
impl IrohaZkAmsProofV1 {
    /// Borrow the exact native proof or signature bytes.
    #[must_use]
    pub const fn bytes(&self) -> &PrivacyProofBytesV1 {
        match self {
            Self::MaskedRelaxedSpartanBatchAdmission(bytes)
            | Self::Ristretto255LsagProvisionAccount(bytes) => bytes,
        }
    }
    /// Mutably borrow the exact native proof or signature bytes.
    #[must_use]
    pub const fn bytes_mut(&mut self) -> &mut PrivacyProofBytesV1 {
        match self {
            Self::MaskedRelaxedSpartanBatchAdmission(bytes)
            | Self::Ristretto255LsagProvisionAccount(bytes) => bytes,
        }
    }
}
/// Protocol-typed native proof payload.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[norito(tag = "protocol", content = "proof", deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::privacy::PrivacyProofV1",
    frame = "iroha.privacy.proof.v1"
)]
pub enum PrivacyProofV1 {
    /// ZK-ACE post-quantum authorization proof.
    ZkAcePqAuthorizationV1(PrivacyProofBytesV1),
    /// Anonymous PGC k-out-of-n payment proof.
    AnonymousPgcKOutOfNV1(PrivacyProofBytesV1),
    /// `VeRange` transparent range proof.
    VeRangeTransparentRangeV1(PrivacyProofBytesV1),
    /// Native Iroha ZK-AMS admission or provisioning proof.
    IrohaZkAmsV1(IrohaZkAmsProofV1),
    /// Vega existing-credential predicate proof.
    VegaExistingCredentialZkV1(PrivacyProofBytesV1),
    /// Native Iroha P-256 X.509 predicate STARK proof.
    IrohaZkX509StarkP256V1(PrivacyProofBytesV1),
    /// Native Iroha Jindo batched univariate lattice polynomial-commitment proof.
    IrohaJindoPolynomialCommitmentV1(PrivacyProofBytesV1),
    /// Native Bootle Lantern/LNP22 anonymous-credential proof.
    IrohaBootleLanternAnoncredV1(PrivacyProofBytesV1),
    /// Orchard Halo2 action proof.
    OrchardHalo2ActionsV1(PrivacyProofBytesV1),
    /// Monero FCMP++ membership proof.
    MoneroFcmpPlusPlusV1(PrivacyProofBytesV1),
    /// Native IVM private-note STARK proof.
    IrohaIvmPrivateNoteStarkV1(PrivacyProofBytesV1),
    /// Post-quantum MASP STARK proof.
    PqMaspStarkV1(PrivacyProofBytesV1),
}
impl PrivacyProofV1 {
    /// Exact protocol carried by this proof variant.
    #[must_use]
    pub const fn protocol_id(&self) -> PrivacyProtocolIdV1 {
        match self {
            Self::ZkAcePqAuthorizationV1(_) => PrivacyProtocolIdV1::ZkAcePqAuthorizationV1,
            Self::AnonymousPgcKOutOfNV1(_) => PrivacyProtocolIdV1::AnonymousPgcKOutOfNV1,
            Self::VeRangeTransparentRangeV1(_) => PrivacyProtocolIdV1::VeRangeTransparentRangeV1,
            Self::IrohaZkAmsV1(_) => PrivacyProtocolIdV1::IrohaZkAmsV1,
            Self::VegaExistingCredentialZkV1(_) => PrivacyProtocolIdV1::VegaExistingCredentialZkV1,
            Self::IrohaZkX509StarkP256V1(_) => PrivacyProtocolIdV1::IrohaZkX509StarkP256V1,
            Self::IrohaJindoPolynomialCommitmentV1(_) => {
                PrivacyProtocolIdV1::IrohaJindoPolynomialCommitmentV1
            }
            Self::IrohaBootleLanternAnoncredV1(_) => {
                PrivacyProtocolIdV1::IrohaBootleLanternAnoncredV1
            }
            Self::OrchardHalo2ActionsV1(_) => PrivacyProtocolIdV1::OrchardHalo2ActionsV1,
            Self::MoneroFcmpPlusPlusV1(_) => PrivacyProtocolIdV1::MoneroFcmpPlusPlusV1,
            Self::IrohaIvmPrivateNoteStarkV1(_) => PrivacyProtocolIdV1::IrohaIvmPrivateNoteStarkV1,
            Self::PqMaspStarkV1(_) => PrivacyProtocolIdV1::PqMaspStarkV1,
        }
    }
    /// Borrow the protocol-specific native proof payload.
    #[must_use]
    pub const fn bytes(&self) -> &PrivacyProofBytesV1 {
        match self {
            Self::ZkAcePqAuthorizationV1(bytes)
            | Self::AnonymousPgcKOutOfNV1(bytes)
            | Self::VeRangeTransparentRangeV1(bytes)
            | Self::VegaExistingCredentialZkV1(bytes)
            | Self::IrohaZkX509StarkP256V1(bytes)
            | Self::IrohaJindoPolynomialCommitmentV1(bytes)
            | Self::IrohaBootleLanternAnoncredV1(bytes)
            | Self::OrchardHalo2ActionsV1(bytes)
            | Self::MoneroFcmpPlusPlusV1(bytes)
            | Self::IrohaIvmPrivateNoteStarkV1(bytes)
            | Self::PqMaspStarkV1(bytes) => bytes,
            Self::IrohaZkAmsV1(proof) => proof.bytes(),
        }
    }
    /// Mutably borrow the protocol-specific native proof payload.
    ///
    /// Transaction-intent normalization uses this exhaustive accessor to
    /// empty the sole typed proof byte vector without protocol-shape drift.
    #[must_use]
    pub const fn bytes_mut(&mut self) -> &mut PrivacyProofBytesV1 {
        match self {
            Self::ZkAcePqAuthorizationV1(bytes)
            | Self::AnonymousPgcKOutOfNV1(bytes)
            | Self::VeRangeTransparentRangeV1(bytes)
            | Self::VegaExistingCredentialZkV1(bytes)
            | Self::IrohaZkX509StarkP256V1(bytes)
            | Self::IrohaJindoPolynomialCommitmentV1(bytes)
            | Self::IrohaBootleLanternAnoncredV1(bytes)
            | Self::OrchardHalo2ActionsV1(bytes)
            | Self::MoneroFcmpPlusPlusV1(bytes)
            | Self::IrohaIvmPrivateNoteStarkV1(bytes)
            | Self::PqMaspStarkV1(bytes) => bytes,
            Self::IrohaZkAmsV1(proof) => proof.bytes_mut(),
        }
    }
}
/// Fixed typed field used by statement validation diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivacyTypedFieldV1 {
    /// Privacy pool identifier.
    PoolId,
    /// ZK-AMS admitted-identity registry identifier.
    RegistryId,
    /// Governed policy identifier.
    PolicyId,
    /// Governed policy digest.
    PolicyDigest,
    /// Credential issuer identifier.
    IssuerId,
    /// Commitment or accumulator root.
    Root,
    /// Credential revocation root.
    RevocationRoot,
    /// Issuer parameter-set identifier.
    IssuerParameterId,
    /// Issuer parameter-set digest.
    IssuerParameterDigest,
    /// Digest of the committed Bootle/Lantern issuer-policy record.
    IssuerPolicyRecordDigest,
    /// Certificate subject-key digest.
    CertificateKeyDigest,
    /// Exact immutable X.509 trust-anchor record digest.
    X509TrustAnchorRecordDigest,
    /// Exact immutable X.509 certificate-policy record digest.
    X509CertificatePolicyRecordDigest,
    /// Exact immutable X.509 signed-CRL record digest.
    X509CrlRecordDigest,
    /// Exact immutable Vega issuer-key/policy record digest.
    VegaIssuerRecordDigest,
    /// Public Vega Figure 9 device-authentication digest `H_dev`.
    VegaDeviceAuthenticationDigest,
    /// ISO 18013-5 reader challenge.
    ReaderChallenge,
    /// ISO 18013-5 session transcript digest.
    SessionTranscriptDigest,
    /// Private IVM program identifier.
    ProgramId,
    /// Private IVM action digest.
    ActionDigest,
    /// Post-quantum authorization-key digest.
    AuthorizationKeyDigest,
    /// Post-quantum note-encryption-key digest.
    NoteEncryptionKeyDigest,
    /// Digest of the authoritative ZK-AMS issuer-policy record.
    ZkAmsIssuerPolicyRecordDigest,
    /// Digest of the authoritative ZK-AMS registry record.
    ZkAmsRegistryRecordDigest,
}
/// Epoch or height field used by statement validation diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivacyEpochFieldV1 {
    /// Commitment-root epoch.
    Root,
    /// Immutable Vega issuer-key/policy revision epoch.
    VegaIssuerRecord,
    /// X.509 certificate-authority membership epoch.
    CertificateAuthorityMembership,
    /// Immutable X.509 trust-anchor revision epoch.
    X509TrustAnchorRecord,
    /// Immutable X.509 certificate-policy revision epoch.
    X509CertificatePolicyRecord,
    /// Immutable X.509 signed-CRL revision epoch.
    X509CrlRecord,
    /// Revocation-state epoch.
    Revocation,
    /// Committed issuer-policy record epoch.
    IssuerPolicy,
    /// Authorization epoch.
    Authorization,
    /// Private-program execution epoch.
    Execution,
    /// Credential validity start epoch.
    ValidityStart,
    /// Credential validity end epoch.
    ValidityEnd,
    /// Credential presentation or validation epoch.
    Presentation,
    /// Transaction expiry block height.
    ExpiryHeight,
}
/// Proof-managed root transition selected by validation diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivacyRootTransitionFieldV1 {
    /// Mutable encrypted PGC account table.
    PgcAccountState,
    /// ZK-AMS admitted-identity registry.
    AccountRegistry,
    /// FCMP++ complete output set.
    OutputSet,
}
/// Twisted-ElGamal ciphertext component selected by validation diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivacyP256CiphertextComponentV1 {
    /// Left ciphertext point `C_L`.
    Left,
    /// Right ciphertext point `C_R`.
    Right,
}
/// Declared protocol count field used by validation diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivacyCountFieldV1 {
    /// `VeRange` aggregated commitments.
    AggregatedCommitments,
    /// Jindo claimed evaluations in polynomial-commitment order.
    JindoClaimedEvaluations,
}
/// Validation failure for a protocol-specific [`PrivacyStatementV1`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum PrivacyStatementValidationError {
    /// Supplied consensus limits are invalid.
    #[error("privacy statement limits are invalid: {0}")]
    InvalidLimits(PrivacyConsensusLimitsValidationError),
    /// Transcript network identity used the reserved all-zero hash.
    #[error("privacy statement network id must be non-zero")]
    ZeroNetworkId,
    /// Action index cannot occur under the transaction action limit.
    #[error("privacy statement action index {index} is outside 0..{max_actions}")]
    ActionIndexOutOfBounds {
        /// Encoded zero-based action index.
        index: u32,
        /// Maximum action count in one transaction.
        max_actions: u32,
    },
    /// Canonical transaction-intent projection digest is zero.
    #[error("privacy statement transaction-intent digest must be non-zero")]
    ZeroTransactionIntentDigest,
    /// Governed parameter-set identifier is zero.
    #[error("privacy statement parameter id must be non-zero")]
    ZeroParameterId,
    /// Governed parameter digest is zero.
    #[error("privacy statement parameter digest must be non-zero")]
    ZeroParameterDigest,
    /// Governed verifier digest is zero.
    #[error("privacy statement verifier digest must be non-zero")]
    ZeroVerifierDigest,
    /// Governed statement-schema digest is zero.
    #[error("privacy statement schema digest must be non-zero")]
    ZeroStatementSchemaDigest,
    /// Pinned engine-manifest digest is zero.
    #[error("privacy statement engine-manifest digest must be non-zero")]
    ZeroEngineManifestDigest,
    /// A protocol-specific fixed field is zero.
    #[error("privacy statement field {field:?} must be non-zero")]
    ZeroTypedField {
        /// Invalid field.
        field: PrivacyTypedFieldV1,
    },
    /// The private-IVM action projection could not be canonically encoded.
    #[error("private IVM action digest projection failed canonical encoding")]
    ActionDigestEncodingFailed,
    /// The supplied private-IVM action digest does not authenticate the exact
    /// canonical action projection.
    #[error("private IVM action digest does not match the canonical action projection")]
    ActionDigestMismatch,
    /// A protocol epoch or height is zero.
    #[error("privacy statement epoch or height {field:?} must be non-zero")]
    ZeroEpoch {
        /// Invalid epoch or height field.
        field: PrivacyEpochFieldV1,
    },
    /// A protocol-specific execution or authorization epoch differs from the
    /// authoritative root epoch consumed by the same action.
    #[error("privacy statement {field:?} epoch {bound_epoch} differs from root epoch {root_epoch}")]
    EpochBindingMismatch {
        /// Execution or authorization binding selected by the statement.
        field: PrivacyEpochFieldV1,
        /// Epoch of the authoritative root consumed by the action.
        root_epoch: u64,
        /// Observed execution or authorization epoch.
        bound_epoch: u64,
    },
    /// A proof-managed successor root is zero.
    #[error("privacy root transition {field:?} has a zero successor root")]
    ZeroNextRoot {
        /// Transition selected by the statement.
        field: PrivacyRootTransitionFieldV1,
    },
    /// A proof-managed successor root equals the current root.
    #[error("privacy root transition {field:?} must change the root")]
    UnchangedRootTransition {
        /// Transition selected by the statement.
        field: PrivacyRootTransitionFieldV1,
    },
    /// A proof-managed root epoch does not advance by exactly one.
    #[error(
        "privacy root transition {field:?} from epoch {current_epoch} has invalid successor epoch {next_epoch}"
    )]
    InvalidNextRootEpoch {
        /// Transition selected by the statement.
        field: PrivacyRootTransitionFieldV1,
        /// Current canonical epoch.
        current_epoch: u64,
        /// Claimed successor epoch.
        next_epoch: u64,
    },
    /// A transparent transfer amount is zero.
    #[error("privacy statement transfer amount must be non-zero")]
    ZeroAmount,
    /// The universal coordinator was supplied as a concrete balance partition.
    #[error("privacy statement public balance scope cannot be the universal dataspace")]
    UniversalPublicBalanceScope,
    /// Public value-balance direction and magnitude are inconsistent.
    #[error("privacy value balance {direction:?} has invalid amount {amount}")]
    InvalidValueBalance {
        /// Declared pool-relative direction.
        direction: PrivacyValueBalanceDirectionV1,
        /// Absolute atomic amount.
        amount: u128,
    },
    /// A required nullifier vector is empty.
    #[error("privacy statement requires at least one nullifier")]
    MissingNullifier,
    /// A required commitment vector is empty.
    #[error("privacy statement requires at least one commitment")]
    MissingCommitment,
    /// A required encrypted-output vector is empty.
    #[error("privacy statement requires at least one encrypted output")]
    MissingEncryptedOutput,
    /// One encrypted output is empty.
    #[error("privacy statement encrypted output {index} must not be empty")]
    EmptyEncryptedOutput {
        /// Zero-based output index.
        index: u32,
    },
    /// An encrypted output has a zero recipient identity.
    #[error("privacy statement encrypted output {index} has a zero recipient")]
    ZeroEncryptedOutputRecipient {
        /// Zero-based output index.
        index: u32,
    },
    /// An encrypted output has a zero ephemeral public key.
    #[error("privacy statement encrypted output {index} has a zero ephemeral key")]
    ZeroEncryptedOutputEphemeralKey {
        /// Zero-based output index.
        index: u32,
    },
    /// Encrypted-output and commitment vector lengths differ.
    #[error(
        "privacy statement encrypted output count {outputs} differs from commitment count {commitments}"
    )]
    EncryptedOutputCommitmentCountMismatch {
        /// Encrypted-output count.
        outputs: u32,
        /// Commitment count.
        commitments: u32,
    },
    /// An encrypted output carries a different commitment than its ordered public commitment.
    #[error("privacy statement encrypted output {index} commitment mismatch")]
    EncryptedOutputCommitmentMismatch {
        /// Zero-based output index.
        index: u32,
    },
    /// Encrypted-output count exceeds consensus limits.
    #[error("privacy statement encrypted output count {count} exceeds maximum {max}")]
    TooManyEncryptedOutputs {
        /// Observed encrypted-output count.
        count: u32,
        /// Configured maximum.
        max: u32,
    },
    /// One encrypted output is all zero.
    #[error("privacy statement encrypted output {index} must not be all zero")]
    AllZeroEncryptedOutput {
        /// Zero-based output index.
        index: u32,
    },
    /// An FCMP++ encrypted output does not use the sole fixed `IFCE` codec.
    #[error("FCMP++ encrypted output {index} has an invalid canonical codec shape")]
    InvalidFcmpEncryptedOutputCodec {
        /// Zero-based output index.
        index: u32,
    },
    /// A private-IVM encrypted output does not use the sole fixed `IPNE`
    /// codec.
    #[error("private-IVM encrypted output {index} has an invalid canonical codec shape")]
    InvalidIvmPrivateEncryptedOutputCodec {
        /// Zero-based output index.
        index: u32,
    },
    /// Nullifier count exceeds consensus limits.
    #[error("privacy statement nullifier count {count} exceeds maximum {max}")]
    TooManyNullifiers {
        /// Observed nullifier count.
        count: u32,
        /// Configured maximum.
        max: u32,
    },
    /// A nullifier is zero.
    #[error("privacy statement nullifier {index} must be non-zero")]
    ZeroNullifier {
        /// Zero-based nullifier index.
        index: u32,
    },
    /// Two nullifiers are equal.
    #[error("privacy statement contains a duplicate nullifier")]
    DuplicateNullifier,
    /// Commitment count exceeds consensus limits.
    #[error("privacy statement commitment count {count} exceeds maximum {max}")]
    TooManyCommitments {
        /// Observed commitment count.
        count: u32,
        /// Configured maximum.
        max: u32,
    },
    /// A commitment is zero.
    #[error("privacy statement commitment {index} must be non-zero")]
    ZeroCommitment {
        /// Zero-based commitment index.
        index: u32,
    },
    /// A compressed P-256 point is all zero.
    #[error("privacy statement P-256 point {index} must be non-zero")]
    ZeroP256Point {
        /// Zero-based point index.
        index: u32,
    },
    /// One twisted-ElGamal ciphertext point is all zero.
    #[error("privacy statement P-256 ciphertext {index} component {component:?} must be non-zero")]
    ZeroP256CiphertextPoint {
        /// Zero-based ciphertext index.
        index: u32,
        /// Invalid ciphertext component.
        component: PrivacyP256CiphertextComponentV1,
    },
    /// Two commitments are equal.
    #[error("privacy statement contains a duplicate commitment")]
    DuplicateCommitment,
    /// Anonymous PGC anonymity-set size is not one of the closed profile sizes.
    #[error("Anonymous PGC anonymity-set size {size} is not one of 16, 32, or 64")]
    InvalidPgcAnonymitySetSize {
        /// Observed anonymity-set size.
        size: u32,
    },
    /// Anonymous PGC public-key and transfer-ciphertext counts differ.
    #[error(
        "Anonymous PGC public-key count {public_keys} differs from ciphertext count {ciphertexts}"
    )]
    PgcPublicMemoCountMismatch {
        /// Ordered public-key count.
        public_keys: u32,
        /// Ordered transfer-ciphertext count.
        ciphertexts: u32,
    },
    /// Anonymous PGC public keys are duplicated or not canonically ordered.
    #[error("Anonymous PGC public keys must be strictly increasing")]
    PgcAnonymitySetNotStrictlyIncreasing,
    /// Anonymous PGC intended recipient count is outside the approved profile.
    #[error(
        "Anonymous PGC recipient count {count} is outside 1..={max} for anonymity-set size {anonymity_set_size}"
    )]
    InvalidPgcRecipientCount {
        /// Observed intended recipient count.
        count: u32,
        /// Derived anonymity-set size.
        anonymity_set_size: u32,
        /// Maximum admitted recipient count.
        max: u32,
    },
    /// `VeRange` aggregation count is outside the approved profile.
    #[error("VeRange aggregation count {count} is outside 1..={max}")]
    InvalidAggregationCount {
        /// Observed aggregation count.
        count: u32,
        /// Approved maximum.
        max: u32,
    },
    /// A declared protocol vector count differs from the encoded vector.
    #[error("privacy statement count {field:?} declares {declared}, encoded vector has {actual}")]
    DeclaredCountMismatch {
        /// Count field.
        field: PrivacyCountFieldV1,
        /// Declared count.
        declared: u32,
        /// Encoded vector count.
        actual: u32,
    },
    /// A batched protocol count is outside its approved profile.
    #[error("privacy statement batch size {count} is outside 1..={max}")]
    InvalidBatchSize {
        /// Observed batch count.
        count: u32,
        /// Approved maximum.
        max: u32,
    },
    /// A Jindo statement does not use the frozen first-release batch shape.
    #[error("Jindo polynomial count {count} differs from the required exact count {expected}")]
    InvalidJindoPolynomialCount {
        /// Observed polynomial count.
        count: u32,
        /// Exact count compiled into the parameter and transcript profile.
        expected: u32,
    },
    /// A consensus resource limit cannot contain the frozen Jindo batch shape.
    #[error("Jindo requires capacity for {required} commitments, but consensus permits {maximum}")]
    InsufficientJindoCommitmentCapacity {
        /// Consensus commitment ceiling.
        maximum: u32,
        /// Exact count required by the compiled Jindo profile.
        required: u32,
    },
    /// A ZK-AMS admission anchor has a zero PHC hash.
    #[error("ZK-AMS admission anchor {index} has a zero PHC hash")]
    ZeroZkAmsPhcHash {
        /// Zero-based anchor index.
        index: u32,
    },
    /// A ZK-AMS admission anchor or provisioning ring has a zero seed key.
    #[error("ZK-AMS seed public key {index} must be non-zero")]
    ZeroZkAmsSeedPublicKey {
        /// Zero-based anchor or ring index.
        index: u32,
    },
    /// Two ZK-AMS batch anchors carry the same PHC hash.
    #[error("ZK-AMS batch contains a duplicate PHC hash")]
    DuplicateZkAmsPhcHash,
    /// Two ZK-AMS batch anchors carry the same seed public key.
    #[error("ZK-AMS batch contains a duplicate seed public key")]
    DuplicateZkAmsSeedPublicKey,
    /// A ZK-AMS provisioning ring size is outside the closed profile.
    #[error("ZK-AMS provisioning ring size {size} is not one of 16, 32, or 64")]
    InvalidZkAmsRingSize {
        /// Observed ring size.
        size: u32,
    },
    /// A ZK-AMS seed-key ring is duplicated or non-canonical.
    #[error("ZK-AMS seed public-key ring must be strictly increasing")]
    ZkAmsSeedKeyRingNotStrictlyIncreasing,
    /// A ZK-AMS MLSAGS key image is the zero sentinel.
    #[error("ZK-AMS MLSAGS key image must be non-zero")]
    ZeroZkAmsKeyImage,
    /// Vega public presentation year is outside the trusted UTC domain.
    #[error("Vega presentation year {year} is outside {min}..={max}")]
    InvalidVegaPresentationYear {
        /// Observed public UTC year.
        year: u16,
        /// Lowest admitted UTC year.
        min: u16,
        /// Highest admitted UTC year.
        max: u16,
    },
    /// Vega public presentation date is not a Gregorian calendar date.
    #[error("Vega presentation date {year:04}-{month:02}-{day:02} is invalid")]
    InvalidVegaPresentationDate {
        /// Observed public UTC year.
        year: u16,
        /// Observed one-based UTC month.
        month: u8,
        /// Observed one-based UTC day.
        day: u8,
    },
    /// Vega public minimum-age threshold is outside the closed policy domain.
    #[error("Vega minimum-age threshold {years} is outside {min}..={max}")]
    InvalidVegaAgeThreshold {
        /// Observed threshold in completed years.
        years: u8,
        /// Lowest admitted threshold.
        min: u8,
        /// Highest admitted threshold.
        max: u8,
    },
    /// X.509 key usage does not authorize a signature.
    #[error("X.509 statement requires the digitalSignature key-usage bit")]
    InvalidX509KeyUsage,
    /// X.509 extended-key-usage vector is empty.
    #[error("X.509 statement requires at least one extended key usage")]
    MissingX509ExtendedKeyUsage,
    /// X.509 extended-key-usage vector exceeds the closed profile.
    #[error("X.509 statement has {actual} extended key usages; maximum is {max}")]
    TooManyX509ExtendedKeyUsages {
        /// Rejected count.
        actual: usize,
        /// Closed maximum.
        max: usize,
    },
    /// X.509 extended-key-usage values contain duplicates or are out of order.
    #[error("X.509 extended key usages must be strictly increasing")]
    X509ExtendedKeyUsagesNotStrictlyIncreasing,
    /// X.509 selective-disclosure vector exceeds the closed profile.
    #[error("X.509 statement has {actual} disclosed attributes; maximum is {max}")]
    TooManyX509DisclosedAttributes {
        /// Rejected count.
        actual: usize,
        /// Closed maximum.
        max: usize,
    },
    /// A selective-disclosure index is outside the closed C/O/OU/CN set.
    #[error("X.509 disclosed attribute index {index} is unsupported")]
    UnsupportedX509DisclosedAttributeIndex {
        /// Rejected index.
        index: u8,
    },
    /// A public selective-disclosure digest is the all-zero sentinel.
    #[error("X.509 disclosed attribute {index} digest must be non-zero")]
    ZeroX509DisclosedAttributeDigest {
        /// Attribute index.
        index: u8,
    },
    /// Selective disclosures contain duplicate or reordered indices.
    #[error("X.509 disclosed attributes must be strictly increasing by index")]
    X509DisclosedAttributesNotStrictlyIncreasing,
    /// The public presentation window is empty, reversed, or too wide.
    #[error(
        "X.509 presentation window [{start}, {end}] must be non-empty and no wider than {max_seconds} seconds"
    )]
    InvalidX509PresentationWindow {
        /// Inclusive presentation start.
        start: u64,
        /// Inclusive presentation end.
        end: u64,
        /// Closed first-release width ceiling.
        max_seconds: u64,
    },
    /// The common Jindo evaluation point is not the canonical residue in `[0, p)`.
    #[error("Jindo evaluation point is not a canonical coefficient-field element")]
    NonCanonicalJindoEvaluationPoint,
    /// A claimed Jindo evaluation is not the canonical residue in `[0, p)`.
    #[error("Jindo claimed evaluation {index} is not a canonical coefficient-field element")]
    NonCanonicalJindoClaimedEvaluation {
        /// Zero-based claimed-evaluation index.
        index: u32,
    },
    /// A Jindo lattice commitment has the wrong fixed-profile width.
    #[error("Jindo lattice commitment {index} uses {bytes} bytes; expected exactly {expected}")]
    InvalidJindoLatticeCommitmentSize {
        /// Zero-based commitment index.
        index: u32,
        /// Observed byte width.
        bytes: u32,
        /// Exact fixed-profile byte width.
        expected: u32,
    },
    /// A Jindo lattice commitment is the all-zero sentinel.
    #[error("Jindo lattice commitment {index} must not be all zero")]
    AllZeroJindoLatticeCommitment {
        /// Zero-based polynomial-commitment index.
        index: u32,
    },
    /// Two Jindo lattice commitments are identical.
    #[error("Jindo polynomial commitments must be distinct")]
    DuplicateJindoLatticeCommitment,
    /// A rounded public Jindo commitment coefficient is outside the fixed bound.
    #[error(
        "Jindo commitment {commitment_index} coefficient {coefficient_index} is {value}; expected {min}..={max}"
    )]
    JindoCommitmentCoefficientOutOfRange {
        /// Zero-based commitment index.
        commitment_index: u32,
        /// Zero-based coefficient index in row-major order.
        coefficient_index: u32,
        /// Decoded signed little-endian coefficient.
        value: i32,
        /// Inclusive fixed lower bound.
        min: i32,
        /// Inclusive fixed upper bound.
        max: i32,
    },
    /// Bootle/Lantern disclosed attribute count exceeds its fixed profile.
    #[error("Bootle/Lantern disclosed attribute count {count} exceeds {max}")]
    TooManyBootleLanternDisclosures {
        /// Observed disclosure count.
        count: u32,
        /// Approved maximum.
        max: u32,
    },
    /// A Bootle/Lantern disclosure index is outside the fixed eight attributes.
    #[error("Bootle/Lantern disclosed attribute index {index} is outside 0..8")]
    BootleLanternDisclosureIndexOutOfBounds {
        /// Invalid disclosed index.
        index: u8,
    },
    /// Bootle/Lantern disclosure indices contain a duplicate or are out of order.
    #[error("Bootle/Lantern disclosed attribute indices must be strictly increasing")]
    BootleLanternDisclosuresNotStrictlyIncreasing,
    /// Orchard action count is empty or exceeds the compiled/consensus bound.
    #[error("Orchard action count {count} is outside 1..={max}")]
    InvalidOrchardActionCount {
        /// Observed action count.
        count: u32,
        /// Effective compiled and governed maximum.
        max: u32,
    },
    /// An Orchard encrypted-note ciphertext does not have the exact V3 width.
    #[error(
        "Orchard action {index} encrypted-note ciphertext uses {bytes} bytes; expected exactly {expected}"
    )]
    InvalidOrchardEncryptedNoteSize {
        /// Zero-based ordered action index.
        index: u32,
        /// Observed byte width.
        bytes: u32,
        /// Exact required byte width.
        expected: u32,
    },
    /// An Orchard outgoing ciphertext does not have the exact V3 width.
    #[error(
        "Orchard action {index} outgoing ciphertext uses {bytes} bytes; expected exactly {expected}"
    )]
    InvalidOrchardOutgoingCiphertextSize {
        /// Zero-based ordered action index.
        index: u32,
        /// Observed byte width.
        bytes: u32,
        /// Exact required byte width.
        expected: u32,
    },
    /// Two Orchard actions use the same nullifier.
    #[error("Orchard action {index} duplicates an earlier nullifier")]
    DuplicateOrchardNullifier {
        /// Zero-based duplicate action index.
        index: u32,
    },
    /// Two Orchard actions use the same note commitment.
    #[error("Orchard action {index} duplicates an earlier note commitment")]
    DuplicateOrchardNoteCommitment {
        /// Zero-based duplicate action index.
        index: u32,
    },
    /// Orchard value balance is outside the signed native API range.
    #[error("Orchard value balance magnitude {amount} exceeds {max}")]
    OrchardValueBalanceOutOfRange {
        /// Observed absolute magnitude.
        amount: u128,
        /// Exact inclusive maximum.
        max: u128,
    },
    /// The typed FCMP++ root has an invalid layer count or zero point.
    #[error("FCMP++ output-set root is structurally invalid: {0}")]
    InvalidFcmpTreeRoot(PrivacyFcmpTreeRootValidationErrorV1),
    /// FCMP++ public-input count is empty or exceeds the effective profile.
    #[error("FCMP++ input count {count} is outside 1..={max}")]
    InvalidFcmpInputCount {
        /// Observed input count.
        count: u32,
        /// Effective first-release maximum.
        max: u32,
    },
    /// One FCMP++ public input contains a structurally invalid point.
    #[error("FCMP++ public input {index} is invalid: {source}")]
    InvalidFcmpInput {
        /// Zero-based input index.
        index: u32,
        /// Exact structural input failure.
        source: PrivacyFcmpInputValidationErrorV1,
    },
    /// Two FCMP++ public inputs use the same key image.
    #[error("FCMP++ public input {index} duplicates an earlier key image")]
    DuplicateFcmpKeyImage {
        /// Zero-based duplicate input index.
        index: u32,
    },
    /// Two FCMP++ public inputs use the same pseudo output.
    #[error("FCMP++ public input {index} duplicates an earlier pseudo output")]
    DuplicateFcmpPseudoOut {
        /// Zero-based duplicate input index.
        index: u32,
    },
    /// FCMP++ output count is empty or exceeds the effective profile.
    #[error("FCMP++ output count {count} is outside 1..={max}")]
    InvalidFcmpOutputCount {
        /// Observed output count.
        count: u32,
        /// Effective first-release maximum.
        max: u32,
    },
    /// One FCMP++ output tuple contains a structurally invalid point.
    #[error("FCMP++ output tuple {index} is invalid: {source}")]
    InvalidFcmpOutput {
        /// Zero-based output index.
        index: u32,
        /// Exact structural tuple failure.
        source: PrivacyFcmpOutputTupleValidationErrorV1,
    },
    /// Two FCMP++ outputs derive the same ledger identifier.
    #[error("FCMP++ output tuple {index} duplicates an earlier output id")]
    DuplicateFcmpOutputId {
        /// Zero-based duplicate output index.
        index: u32,
    },
    /// FCMP++ encrypted-output and tuple counts differ.
    #[error(
        "FCMP++ encrypted output count {encrypted_outputs} differs from output tuple count {outputs}"
    )]
    FcmpEncryptedOutputCountMismatch {
        /// Encrypted-output count.
        encrypted_outputs: u32,
        /// Public output-tuple count.
        outputs: u32,
    },
    /// An FCMP++ encrypted output identifies a different ordered tuple.
    #[error("FCMP++ encrypted output {index} output id mismatch")]
    FcmpEncryptedOutputIdMismatch {
        /// Zero-based output index.
        index: u32,
    },
    /// Public statement and encrypted outputs exceed the transaction budget.
    #[error("privacy statement and encrypted outputs use {bytes} bytes, exceeding maximum {max}")]
    StatementAndEncryptedOutputsTooLarge {
        /// Observed payload bytes.
        bytes: u64,
        /// Configured maximum.
        max: u32,
    },
    /// Canonical statement encoding failed.
    #[error("privacy statement canonical encoding failed")]
    EncodingFailure,
    /// A platform collection length could not be represented canonically.
    #[error("privacy statement payload length overflow")]
    PayloadLengthOverflow,
}
/// Validation failure for [`PrivacyProofBytesV1`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum PrivacyProofValidationError {
    /// Supplied consensus limits are invalid.
    #[error("privacy proof limits are invalid: {0}")]
    InvalidLimits(PrivacyConsensusLimitsValidationError),
    /// Proof payload is empty.
    #[error("privacy proof bytes must not be empty")]
    Empty,
    /// Proof payload is all zero.
    #[error("privacy proof bytes must not be all zero")]
    AllZero,
    /// Proof payload exceeds consensus limits.
    #[error("privacy proof uses {bytes} bytes, exceeding maximum {max}")]
    TooLarge {
        /// Observed proof bytes.
        bytes: u64,
        /// Configured maximum.
        max: u32,
    },
    /// A platform collection length could not be represented canonically.
    #[error("privacy proof length overflow")]
    LengthOverflow,
}
/// Complete protocol-bound privacy proof admission envelope.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::privacy::PrivacyProofEnvelopeV1",
    frame = "iroha.privacy.proof-envelope.v1"
)]
pub struct PrivacyProofEnvelopeV1 {
    /// Mandatory first-release wire marker; invalid markers fail decoding.
    pub wire_magic: PrivacyProofWireMagicV1,
    /// Commitment to the final ordered Exact12 catalog and security models.
    pub catalog_commitment: PrivacyExact12CatalogCommitmentV1,
    /// Exact protocol identity.
    pub protocol_id: PrivacyProtocolIdV1,
    /// Exact proof-system profile.
    pub proof_system_id: PrivacyProofSystemIdV1,
    /// Exact native verifier engine.
    pub engine_id: PrivacyEngineIdV1,
    /// Governed public-parameter set identifier.
    pub parameter_id: PrivacyParameterIdV1,
    /// Governed public-parameter digest.
    pub parameter_digest: PrivacyParameterDigestV1,
    /// Governed verifier artifact digest.
    pub verifier_digest: PrivacyVerifierDigestV1,
    /// Governed public-statement schema digest.
    pub statement_schema_digest: PrivacyStatementSchemaDigestV1,
    /// Governed native engine-manifest digest.
    pub engine_manifest_digest: PrivacyEngineManifestDigestV1,
    /// Digest of the complete protocol-tagged statement.
    pub statement_digest: PrivacyStatementDigestV1,
    /// Protocol-typed public statement.
    pub statement: PrivacyStatementV1,
    /// Protocol-typed proof bytes.
    pub proof: PrivacyProofV1,
}
impl PrivacyProofEnvelopeV1 {
    /// Validate internal protocol bindings and resource limits.
    ///
    /// This validates only the envelope's intrinsic shape. Chain admission must
    /// additionally call [`Self::validate_against_activation`] to bind the
    /// envelope to the active governed artifacts and current block height.
    ///
    /// # Errors
    ///
    /// Returns [`PrivacyProofEnvelopeValidationError`] for any mismatch,
    /// degenerate digest or payload, statement digest tampering, encoding
    /// failure, or resource-bound violation.
    pub fn validate_with_limits(
        &self,
        limits: &PrivacyConsensusLimitsV1,
    ) -> Result<(), PrivacyProofEnvelopeValidationError> {
        limits
            .validate()
            .map_err(PrivacyProofEnvelopeValidationError::InvalidLimits)?;
        self.validate_protocol_bindings()?;
        self.validate_artifact_bindings()?;
        self.validate_statement_and_proof(limits)?;
        self.validate_statement_digest()?;
        self.validate_encoded_size(limits)
    }
    fn validate_protocol_bindings(&self) -> Result<(), PrivacyProofEnvelopeValidationError> {
        let expected_proof_system = self.protocol_id.expected_proof_system();
        if self.proof_system_id != expected_proof_system {
            return Err(PrivacyProofEnvelopeValidationError::ProofSystemMismatch {
                expected: expected_proof_system,
                actual: self.proof_system_id,
            });
        }
        let expected_engine = self.protocol_id.expected_engine();
        if self.engine_id != expected_engine {
            return Err(PrivacyProofEnvelopeValidationError::EngineMismatch {
                expected: expected_engine,
                actual: self.engine_id,
            });
        }
        // The single role resolver owns protocol, statement, proof and ZK-AMS
        // action agreement; nothing else decides which role an envelope selects.
        self.action_role_v1().map(|_| ())
    }
    fn validate_artifact_bindings(&self) -> Result<(), PrivacyProofEnvelopeValidationError> {
        if self.parameter_id.is_zero() {
            return Err(PrivacyProofEnvelopeValidationError::ZeroParameterId);
        }
        if self.parameter_digest.is_zero() {
            return Err(PrivacyProofEnvelopeValidationError::ZeroParameterDigest);
        }
        if self.verifier_digest.is_zero() {
            return Err(PrivacyProofEnvelopeValidationError::ZeroVerifierDigest);
        }
        if self.statement_schema_digest.is_zero() {
            return Err(PrivacyProofEnvelopeValidationError::ZeroStatementSchemaDigest);
        }
        if self.engine_manifest_digest.is_zero() {
            return Err(PrivacyProofEnvelopeValidationError::ZeroEngineManifestDigest);
        }
        if self.statement_digest.is_zero() {
            return Err(PrivacyProofEnvelopeValidationError::ZeroStatementDigest);
        }
        let context = self.statement.context();
        if context.parameter_id != self.parameter_id {
            return Err(PrivacyProofEnvelopeValidationError::StatementParameterIdMismatch);
        }
        if context.parameter_digest != self.parameter_digest {
            return Err(PrivacyProofEnvelopeValidationError::StatementParameterDigestMismatch);
        }
        if context.verifier_digest != self.verifier_digest {
            return Err(PrivacyProofEnvelopeValidationError::StatementVerifierDigestMismatch);
        }
        if context.statement_schema_digest != self.statement_schema_digest {
            return Err(PrivacyProofEnvelopeValidationError::StatementSchemaDigestMismatch);
        }
        if context.engine_manifest_digest != self.engine_manifest_digest {
            return Err(PrivacyProofEnvelopeValidationError::StatementEngineManifestDigestMismatch);
        }
        Ok(())
    }
    fn validate_statement_and_proof(
        &self,
        limits: &PrivacyConsensusLimitsV1,
    ) -> Result<(), PrivacyProofEnvelopeValidationError> {
        self.statement
            .validate(limits)
            .map_err(PrivacyProofEnvelopeValidationError::Statement)?;
        self.proof
            .bytes()
            .validate(limits)
            .map_err(PrivacyProofEnvelopeValidationError::Proof)
    }
    fn validate_statement_digest(&self) -> Result<(), PrivacyProofEnvelopeValidationError> {
        let computed_statement_digest = self
            .statement
            .digest()
            .map_err(|_| PrivacyProofEnvelopeValidationError::EncodingFailure)?;
        if computed_statement_digest != self.statement_digest {
            return Err(
                PrivacyProofEnvelopeValidationError::StatementDigestMismatch {
                    expected: computed_statement_digest,
                    actual: self.statement_digest,
                },
            );
        }
        Ok(())
    }
    fn validate_encoded_size(
        &self,
        limits: &PrivacyConsensusLimitsV1,
    ) -> Result<(), PrivacyProofEnvelopeValidationError> {
        let encoded_len = norito::canonical_frame_len(self)
            .map_err(|_| PrivacyProofEnvelopeValidationError::EncodingFailure)?;
        let encoded_len = u64::try_from(encoded_len)
            .map_err(|_| PrivacyProofEnvelopeValidationError::EncodedLengthOverflow)?;
        if encoded_len > u64::from(limits.max_action_bytes) {
            return Err(PrivacyProofEnvelopeValidationError::ActionTooLarge {
                bytes: encoded_len,
                max: limits.max_action_bytes,
            });
        }
        if encoded_len > u64::from(limits.max_privacy_bytes_per_transaction) {
            return Err(
                PrivacyProofEnvelopeValidationError::TransactionPrivacyPayloadTooLarge {
                    bytes: encoded_len,
                    max: limits.max_privacy_bytes_per_transaction,
                },
            );
        }
        Ok(())
    }
    /// Validate this envelope against an active governed protocol record.
    ///
    /// # Errors
    ///
    /// Returns [`PrivacyProofEnvelopeValidationError`] if the activation record
    /// is invalid or inactive at `current_height`, any governed identity or
    /// digest differs, or intrinsic envelope validation fails.
    pub fn validate_against_activation(
        &self,
        activation: &PrivacyProtocolActivationRecordV1,
        consensus_limits: &PrivacyConsensusLimitsV1,
        current_height: u64,
    ) -> Result<(), PrivacyProofEnvelopeValidationError> {
        activation
            .validate()
            .map_err(PrivacyProofEnvelopeValidationError::InvalidActivation)?;
        if activation.protocol_id != self.protocol_id {
            return Err(
                PrivacyProofEnvelopeValidationError::ActivationProtocolMismatch {
                    activation: activation.protocol_id,
                    envelope: self.protocol_id,
                },
            );
        }
        let PrivacyProtocolLifecycleV1::Active(active_state) = activation.lifecycle else {
            return Err(PrivacyProofEnvelopeValidationError::ActivationNotActive);
        };
        if current_height < active_state.state_since_height {
            return Err(
                PrivacyProofEnvelopeValidationError::ActivationNotEffective {
                    current_height,
                    effective_height: active_state.state_since_height,
                },
            );
        }
        if activation.proof_system_id != self.proof_system_id {
            return Err(
                PrivacyProofEnvelopeValidationError::ActivationProofSystemMismatch {
                    activation: activation.proof_system_id,
                    envelope: self.proof_system_id,
                },
            );
        }
        if activation.engine_id != self.engine_id {
            return Err(
                PrivacyProofEnvelopeValidationError::ActivationEngineMismatch {
                    activation: activation.engine_id,
                    envelope: self.engine_id,
                },
            );
        }
        if activation.parameter_id != self.parameter_id {
            return Err(PrivacyProofEnvelopeValidationError::ActivationParameterIdMismatch);
        }
        if activation.parameter_digest != self.parameter_digest {
            return Err(PrivacyProofEnvelopeValidationError::ActivationParameterDigestMismatch);
        }
        if activation.verifier_digest != self.verifier_digest {
            return Err(PrivacyProofEnvelopeValidationError::ActivationVerifierDigestMismatch);
        }
        if activation.statement_schema_digest != self.statement_schema_digest {
            return Err(
                PrivacyProofEnvelopeValidationError::ActivationStatementSchemaDigestMismatch,
            );
        }
        if activation.engine_manifest_digest != self.engine_manifest_digest {
            return Err(
                PrivacyProofEnvelopeValidationError::ActivationEngineManifestDigestMismatch,
            );
        }
        activation
            .protocol_limits
            .validate_statement(&self.statement)
            .map_err(PrivacyProofEnvelopeValidationError::ActivationStatementLimits)?;
        self.validate_with_limits(consensus_limits)
    }
}
/// Validation failure for [`PrivacyProofEnvelopeV1`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum PrivacyProofEnvelopeValidationError {
    /// Supplied consensus limits are invalid.
    #[error("privacy envelope limits are invalid: {0}")]
    InvalidLimits(PrivacyConsensusLimitsValidationError),
    /// Protocol and proof-system identities differ.
    #[error("privacy envelope requires proof system {expected:?}, got {actual:?}")]
    ProofSystemMismatch {
        /// Required proof system.
        expected: PrivacyProofSystemIdV1,
        /// Supplied proof system.
        actual: PrivacyProofSystemIdV1,
    },
    /// Protocol and native engine identities differ.
    #[error("privacy envelope requires engine {expected:?}, got {actual:?}")]
    EngineMismatch {
        /// Required native engine.
        expected: PrivacyEngineIdV1,
        /// Supplied native engine.
        actual: PrivacyEngineIdV1,
    },
    /// Envelope and statement protocol variants differ.
    #[error("privacy envelope protocol {envelope:?} differs from statement protocol {statement:?}")]
    StatementProtocolMismatch {
        /// Envelope protocol.
        envelope: PrivacyProtocolIdV1,
        /// Statement variant protocol.
        statement: PrivacyProtocolIdV1,
    },
    /// Envelope and proof protocol variants differ.
    #[error("privacy envelope protocol {envelope:?} differs from proof protocol {proof:?}")]
    ProofProtocolMismatch {
        /// Envelope protocol.
        envelope: PrivacyProtocolIdV1,
        /// Proof variant protocol.
        proof: PrivacyProtocolIdV1,
    },
    /// ZK-AMS statement action and typed proof action differ.
    #[error("ZK-AMS statement action and proof variant differ")]
    ZkAmsActionProofMismatch,
    /// Parameter-set identifier is zero.
    #[error("privacy envelope parameter id must be non-zero")]
    ZeroParameterId,
    /// Parameter digest is zero.
    #[error("privacy envelope parameter digest must be non-zero")]
    ZeroParameterDigest,
    /// Verifier digest is zero.
    #[error("privacy envelope verifier digest must be non-zero")]
    ZeroVerifierDigest,
    /// Statement-schema digest is zero.
    #[error("privacy envelope statement-schema digest must be non-zero")]
    ZeroStatementSchemaDigest,
    /// Engine-manifest digest is zero.
    #[error("privacy envelope engine-manifest digest must be non-zero")]
    ZeroEngineManifestDigest,
    /// Statement digest is zero.
    #[error("privacy envelope statement digest must be non-zero")]
    ZeroStatementDigest,
    /// Statement and envelope parameter-set identifiers differ.
    #[error("privacy statement parameter id differs from envelope")]
    StatementParameterIdMismatch,
    /// Statement and envelope parameter digests differ.
    #[error("privacy statement parameter digest differs from envelope")]
    StatementParameterDigestMismatch,
    /// Statement and envelope verifier digests differ.
    #[error("privacy statement verifier digest differs from envelope")]
    StatementVerifierDigestMismatch,
    /// Statement and envelope schema digests differ.
    #[error("privacy statement schema digest differs from envelope")]
    StatementSchemaDigestMismatch,
    /// Statement and envelope engine-manifest digests differ.
    #[error("privacy statement engine-manifest digest differs from envelope")]
    StatementEngineManifestDigestMismatch,
    /// Statement validation failed.
    #[error("privacy envelope statement is invalid: {0}")]
    Statement(PrivacyStatementValidationError),
    /// Proof payload validation failed.
    #[error("privacy envelope proof is invalid: {0}")]
    Proof(PrivacyProofValidationError),
    /// Canonical statement digest does not match the envelope.
    #[error("privacy envelope statement digest mismatch")]
    StatementDigestMismatch {
        /// Digest recomputed from the canonical statement.
        expected: PrivacyStatementDigestV1,
        /// Digest carried by the envelope.
        actual: PrivacyStatementDigestV1,
    },
    /// Canonical Norito encoding failed.
    #[error("privacy envelope canonical encoding failed")]
    EncodingFailure,
    /// Encoded length cannot be represented canonically.
    #[error("privacy envelope encoded length overflow")]
    EncodedLengthOverflow,
    /// Encoded action exceeds its consensus bound.
    #[error("privacy envelope action uses {bytes} bytes, exceeding maximum {max}")]
    ActionTooLarge {
        /// Observed encoded bytes.
        bytes: u64,
        /// Configured maximum.
        max: u32,
    },
    /// Encoded action exceeds the transaction privacy budget.
    #[error("privacy envelope transaction payload uses {bytes} bytes, exceeding maximum {max}")]
    TransactionPrivacyPayloadTooLarge {
        /// Observed encoded bytes.
        bytes: u64,
        /// Configured maximum.
        max: u32,
    },
    /// Governed activation record is internally invalid.
    #[error("privacy activation record is invalid: {0}")]
    InvalidActivation(PrivacyActivationValidationError),
    /// Activation and envelope protocols differ.
    #[error(
        "privacy activation protocol {activation:?} differs from envelope protocol {envelope:?}"
    )]
    ActivationProtocolMismatch {
        /// Governed protocol.
        activation: PrivacyProtocolIdV1,
        /// Envelope protocol.
        envelope: PrivacyProtocolIdV1,
    },
    /// Governed activation is not active.
    #[error("privacy protocol activation is not active")]
    ActivationNotActive,
    /// The active state is not yet effective at the current height.
    #[error(
        "privacy activation effective height {effective_height} is later than current height {current_height}"
    )]
    ActivationNotEffective {
        /// Current block height.
        current_height: u64,
        /// First height of the current active interval.
        effective_height: u64,
    },
    /// Governed and envelope proof systems differ.
    #[error(
        "privacy activation proof system {activation:?} differs from envelope proof system {envelope:?}"
    )]
    ActivationProofSystemMismatch {
        /// Governed proof system.
        activation: PrivacyProofSystemIdV1,
        /// Envelope proof system.
        envelope: PrivacyProofSystemIdV1,
    },
    /// Governed and envelope native engines differ.
    #[error("privacy activation engine {activation:?} differs from envelope engine {envelope:?}")]
    ActivationEngineMismatch {
        /// Governed native engine.
        activation: PrivacyEngineIdV1,
        /// Envelope native engine.
        envelope: PrivacyEngineIdV1,
    },
    /// Governed and envelope parameter-set identifiers differ.
    #[error("privacy activation parameter id differs from envelope")]
    ActivationParameterIdMismatch,
    /// Governed and envelope parameter digests differ.
    #[error("privacy activation parameter digest differs from envelope")]
    ActivationParameterDigestMismatch,
    /// Governed and envelope verifier digests differ.
    #[error("privacy activation verifier digest differs from envelope")]
    ActivationVerifierDigestMismatch,
    /// Governed and envelope statement-schema digests differ.
    #[error("privacy activation statement-schema digest differs from envelope")]
    ActivationStatementSchemaDigestMismatch,
    /// Governed and envelope engine-manifest digests differ.
    #[error("privacy activation engine-manifest digest differs from envelope")]
    ActivationEngineManifestDigestMismatch,
    /// Statement exceeds activation-specific governed protocol limits.
    #[error("privacy statement violates active protocol limits: {0}")]
    ActivationStatementLimits(PrivacyActivationStatementLimitsError),
}
#[cfg(any(test, feature = "privacy-exact12-conformance"))]
mod exact12_fixture {
    use super::*;
    use crate::{
        NetworkId,
        block::BlockHeader,
        isi::{InstructionBox, privacy::SubmitPrivacyProofV1},
        transaction::{
            Executable, FeePaymentIntent, TransactionBuilder, TransactionDomain,
            TransactionPayload, signed::PrivacyTransactionIntentErrorV1,
        },
    };
    use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair};
    use iroha_model_base::domain::DomainId;
    use iroha_model_base::metadata::Metadata;
    use iroha_model_base::name::Name;
    use iroha_version::codec::EncodeVersioned as _;
    use std::{
        fmt::Write as _,
        num::{NonZeroU32, NonZeroU64},
        str::FromStr as _,
    };
    const _: [(); 12] = [(); PrivacyProtocolIdV1::COUNT];
    const EXACT12_CANONICAL_HEADER_V1: [&str; 4] = [
        "# Iroha first-release privacy parity matrix v1.",
        "# UTF-8, LF only, tab-separated, no aliases and no extension rows.",
        "# registry-sha256 hashes the concatenation of every protocol label plus LF in index order.",
        "# typed-envelope hashes bind the canonical sample statement digest and complete Norito envelope.",
    ];
    pub(super) fn raw(seed: u8) -> [u8; 32] {
        [seed; 32]
    }
    #[cfg(test)]
    pub(super) fn assert_fixed_width_norito<T, const N: usize>(value: &T, raw: &[u8; N])
    where
        T: norito::core::NoritoSerialize
            + for<'de> norito::core::NoritoDeserialize<'de>
            + PartialEq
            + core::fmt::Debug,
    {
        let (encoded, flags) = norito::codec::encode_with_header_flags(value);
        assert_eq!(
            flags,
            norito::core::header_flags::COMPACT_LEN,
            "fixed-width wrappers use the canonical compact field-length frame"
        );
        assert_eq!(encoded.len(), N + 1);
        assert_eq!(
            encoded.first().copied(),
            Some(u8::try_from(N).expect("test fixed width fits one compact-length byte"))
        );
        assert_eq!(&encoded[1..], raw);
        let (decoded, used) = norito::core::decode_field_canonical::<T>(&encoded)
            .expect("decode exact fixed-width value");
        assert_eq!(&decoded, value);
        assert_eq!(used, encoded.len());
        let mut truncated = encoded.clone();
        truncated.truncate(encoded.len() - 1);
        assert!(
            norito::core::decode_field_canonical::<T>(&truncated).is_err(),
            "truncated fixed-width value must fail closed"
        );
        let mut tailed = encoded;
        tailed.push(0);
        assert!(
            norito::core::decode_field_canonical::<T>(&tailed).is_err(),
            "trailing fixed-width bytes must fail closed"
        );
    }
    pub(super) fn p256_point(seed: u8) -> PrivacyP256PointV1 {
        let mut bytes = [seed; 33];
        bytes[0] = 0x02;
        PrivacyP256PointV1::new(bytes)
    }
    pub(super) fn p256_ciphertext(seed: u8) -> PrivacyP256CiphertextV1 {
        PrivacyP256CiphertextV1 {
            left: p256_point(seed),
            right: p256_point(seed.wrapping_add(64)),
        }
    }
    pub(super) fn account(seed: u8) -> AccountId {
        let key_pair = KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
            .expect("fixture seed derives Ed25519 keypair");
        AccountId::new(key_pair.public_key().clone())
    }
    pub(super) fn asset_definition_id() -> AssetDefinitionId {
        AssetDefinitionId::derive_from_components(
            DomainId::try_new("privacy", "universal").expect("domain"),
            Name::from_str("asset").expect("asset name"),
        )
    }
    pub(super) fn context() -> PrivacyStatementContextV1 {
        PrivacyStatementContextV1 {
            network_id: network_id(200),
            action_index: 0,
            transaction_intent_digest: PrivacyTransactionIntentDigestV1::new(raw(6)),
            parameter_id: PrivacyParameterIdV1::new(raw(1)),
            parameter_digest: PrivacyParameterDigestV1::new(raw(2)),
            verifier_digest: PrivacyVerifierDigestV1::new(raw(3)),
            statement_schema_digest: PrivacyStatementSchemaDigestV1::new(raw(4)),
            engine_manifest_digest: PrivacyEngineManifestDigestV1::new(raw(5)),
        }
    }
    pub(super) fn network_id(seed: u8) -> NetworkId {
        NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
            Hash::prehashed([seed; Hash::LENGTH]),
        ))
    }
    pub(super) fn commitment(seed: u8) -> PrivacyCommitmentV1 {
        PrivacyCommitmentV1::new(raw(seed))
    }
    pub(super) fn zk_ace_identity_commitment(seed: u8) -> PrivacyZkAceIdentityCommitmentV1 {
        PrivacyZkAceIdentityCommitmentV1::new([u64::from(seed) + 1; 6])
            .expect("small fixture words are canonical Goldilocks elements")
    }
    pub(super) fn zk_ace_replay_nullifier(seed: u8) -> PrivacyZkAceReplayNullifierV1 {
        PrivacyZkAceReplayNullifierV1::new([u64::from(seed) + 1; 6])
            .expect("small fixture words are canonical Goldilocks elements")
    }
    #[cfg(test)]
    pub(super) fn zk_ace_allowlist() -> Vec<AccountId> {
        let mut allowlist = vec![account(13), account(14), account(15)];
        allowlist.sort_unstable();
        allowlist
    }
    #[cfg(test)]
    pub(super) fn zk_ace_policy(
        epoch: u64,
        identity_seed: u8,
        lifecycle: PrivacyZkAcePolicyLifecycleV1,
    ) -> PrivacyZkAcePolicyRecordV1 {
        PrivacyZkAcePolicyRecordV1::new(
            PrivacyPolicyIdV1::new(raw(10)),
            zk_ace_identity_commitment(identity_seed),
            PrivacyPolicyDigestV1::new(raw(12)),
            epoch,
            asset_definition_id(),
            zk_ace_allowlist(),
            lifecycle,
        )
        .expect("canonical ZK-ACE policy fixture")
    }
    #[cfg(test)]
    pub(super) fn redigest_zk_ace_policy(record: &mut PrivacyZkAcePolicyRecordV1) {
        record.record_digest = PrivacyZkAcePolicyRecordDigestV1::new([0; 32]);
        record.record_digest = record
            .compute_record_digest()
            .expect("canonical ZK-ACE policy digest material");
    }
    #[cfg(test)]
    pub(super) fn zk_x509_trust_anchor(
        epoch: u64,
        trust_store_seed: u8,
        previous_record_digest: Option<PrivacyZkX509TrustAnchorRecordDigestV1>,
        lifecycle: PrivacyZkX509RecordLifecycleV1,
    ) -> PrivacyZkX509TrustAnchorRecordV1 {
        PrivacyZkX509TrustAnchorRecordV1::new(
            PrivacyIssuerIdV1::new(raw(61)),
            epoch,
            PrivacyX509TrustStoreDigestV1::new(raw(trust_store_seed)),
            PrivacyRootV1::new(raw(trust_store_seed.wrapping_add(1))),
            if lifecycle == PrivacyZkX509RecordLifecycleV1::Revoked {
                epoch.saturating_sub(1)
            } else {
                epoch
            },
            previous_record_digest,
            lifecycle,
        )
        .expect("canonical X.509 trust-anchor fixture")
    }
    #[cfg(test)]
    pub(super) fn zk_x509_certificate_policy(
        epoch: u64,
        policy_seed: u8,
        disclosures: Vec<u8>,
        previous_record_digest: Option<PrivacyZkX509CertificatePolicyRecordDigestV1>,
        lifecycle: PrivacyZkX509RecordLifecycleV1,
    ) -> PrivacyZkX509CertificatePolicyRecordV1 {
        PrivacyZkX509CertificatePolicyRecordV1::new(
            PrivacyIssuerIdV1::new(raw(61)),
            PrivacyPolicyIdV1::new(raw(62)),
            epoch,
            PrivacyPolicyDigestV1::new(raw(policy_seed)),
            PrivacyX509KeyUsageV1 {
                digital_signature: PrivacyX509KeyUsageRequirementV1::new(true),
                content_commitment: PrivacyX509KeyUsageRequirementV1::new(false),
                key_encipherment: PrivacyX509KeyUsageRequirementV1::new(false),
                key_agreement: PrivacyX509KeyUsageRequirementV1::new(false),
            },
            vec![
                PrivacyX509ExtendedKeyUsageV1::ClientAuthentication,
                PrivacyX509ExtendedKeyUsageV1::WalletIdentity,
            ],
            disclosures,
            previous_record_digest,
            lifecycle,
        )
        .expect("canonical X.509 certificate-policy fixture")
    }
    #[cfg(test)]
    pub(super) fn zk_x509_crl(
        epoch: u64,
        crl_der_seed: u8,
        this_update_unix_seconds: u64,
        previous_record_digest: Option<PrivacyZkX509CrlRecordDigestV1>,
        lifecycle: PrivacyZkX509RecordLifecycleV1,
    ) -> PrivacyZkX509CrlRecordV1 {
        PrivacyZkX509CrlRecordV1::new(
            PrivacyIssuerIdV1::new(raw(61)),
            PrivacyPolicyIdV1::new(raw(62)),
            epoch,
            epoch,
            PrivacyX509CrlDerDigestV1::new(raw(crl_der_seed)),
            PrivacyX509CrlIssuerSpkiDigestV1::new(raw(74)),
            this_update_unix_seconds,
            this_update_unix_seconds + 300,
            previous_record_digest,
            lifecycle,
        )
        .expect("canonical X.509 signed-CRL fixture")
    }
    pub(super) fn nullifier(seed: u8) -> PrivacyNullifierV1 {
        PrivacyNullifierV1::new(raw(seed))
    }
    pub(super) fn zk_ams_seed_key(seed: u8) -> PrivacyZkAmsSeedPublicKeyV1 {
        PrivacyZkAmsSeedPublicKeyV1::new(raw(seed))
    }
    pub(super) fn zk_ams_anchor(seed: u8) -> PrivacyZkAmsAdmissionAnchorV1 {
        PrivacyZkAmsAdmissionAnchorV1 {
            phc_hash: PrivacyZkAmsPhcHashV1::new(raw(seed)),
            seed_public_key: zk_ams_seed_key(seed.wrapping_add(32)),
        }
    }
    pub(super) fn zk_ams_provision_statement(ring_size: u8) -> PrivacyStatementV1 {
        PrivacyStatementV1::IrohaZkAmsV1(IrohaZkAmsStatementV1 {
            context: context(),
            issuer_id: PrivacyIssuerIdV1::new(raw(40)),
            issuer_public_key: p256_point(42),
            issuer_policy_record_digest: PrivacyZkAmsIssuerPolicyRecordDigestV1::new(raw(43)),
            registry_id: PrivacyZkAmsRegistryIdV1::new(raw(41)),
            registry_record_digest: PrivacyZkAmsRegistryRecordDigestV1::new(raw(44)),
            policy_id: PrivacyPolicyIdV1::new(raw(45)),
            policy_digest: PrivacyPolicyDigestV1::new(raw(46)),
            action: PrivacyZkAmsActionV1::ProvisionAccount(PrivacyZkAmsProvisionAccountV1 {
                account_registry_root: PrivacyRootV1::new(raw(144)),
                account_registry_root_epoch: 10,
                admitted_seed_key_ring: (1..=ring_size).map(zk_ams_seed_key).collect(),
                account_id: account(200),
                key_image: PrivacyZkAmsKeyImageV1::new(raw(201)),
            }),
        })
    }
    pub(super) fn jindo_field(seed: u8) -> PrivacyJindoFieldElementV1 {
        let mut encoding = [0; IROHA_JINDO_FIELD_ELEMENT_BYTES_V1];
        encoding[0] = seed;
        PrivacyJindoFieldElementV1::new(encoding)
    }
    pub(super) fn jindo_commitment(seed: u8) -> PrivacyJindoLatticeCommitmentV1 {
        let mut encoding = vec![0; IROHA_JINDO_LATTICE_COMMITMENT_BYTES_V1];
        encoding[..4].copy_from_slice(&i32::from(seed).to_le_bytes());
        PrivacyJindoLatticeCommitmentV1::new(encoding)
    }
    pub(super) fn encrypted_output(
        commitment_seed: u8,
        recipient_seed: u8,
    ) -> PrivacyEncryptedOutputV1 {
        let mut ciphertext = vec![0xA5; PRIVACY_IVM_PRIVATE_ENCRYPTED_OUTPUT_BYTES_V1];
        ciphertext[..4].copy_from_slice(&PRIVACY_IVM_PRIVATE_ENCRYPTED_OUTPUT_MAGIC_V1);
        ciphertext[4] = recipient_seed;
        PrivacyEncryptedOutputV1 {
            recipient: PrivacyRecipientIdV1::new(raw(recipient_seed)),
            ephemeral_public_key: PrivacyEncryptionKeyV1::new(raw(recipient_seed.wrapping_add(1))),
            commitment: commitment(commitment_seed),
            ciphertext,
        }
    }
    pub(super) fn fcmp_output(seed: u8) -> PrivacyFcmpOutputTupleV1 {
        PrivacyFcmpOutputTupleV1 {
            output_key: raw(seed),
            linking_tag_generator: raw(seed.wrapping_add(1)),
            amount_commitment: raw(seed.wrapping_add(2)),
        }
    }
    #[cfg(test)]
    pub(super) fn sorted_fcmp_outputs(seeds: &[u8]) -> Vec<PrivacyFcmpOutputTupleV1> {
        let mut outputs = seeds.iter().copied().map(fcmp_output).collect::<Vec<_>>();
        outputs.sort_unstable_by_key(|output| output.output_id());
        outputs
    }
    pub(super) fn fcmp_input(seed: u8) -> PrivacyFcmpInputPublicV1 {
        PrivacyFcmpInputPublicV1 {
            output_key_tilde: raw(seed),
            linking_tag_generator_tilde: raw(seed.wrapping_add(1)),
            rerandomization_commitment: raw(seed.wrapping_add(2)),
            pseudo_out: raw(seed.wrapping_add(3)),
            key_image: PrivacyFcmpKeyImageV1::new(raw(seed.wrapping_add(4))),
        }
    }
    pub(super) fn fcmp_encrypted_output(
        output: PrivacyFcmpOutputTupleV1,
        recipient_seed: u8,
    ) -> PrivacyFcmpEncryptedOutputV1 {
        let mut ciphertext = vec![0xA5; PRIVACY_FCMP_ENCRYPTED_OUTPUT_BYTES_V1];
        ciphertext[..4].copy_from_slice(&PRIVACY_FCMP_ENCRYPTED_OUTPUT_MAGIC_V1);
        ciphertext[4] = recipient_seed;
        PrivacyFcmpEncryptedOutputV1 {
            recipient: PrivacyRecipientIdV1::new(raw(recipient_seed)),
            ephemeral_public_key: PrivacyEncryptionKeyV1::new(raw(recipient_seed.wrapping_add(1))),
            output_id: output.output_id(),
            ciphertext,
        }
    }
    pub(super) fn orchard_action(seed: u8) -> PrivacyOrchardActionV1 {
        PrivacyOrchardActionV1 {
            nullifier: raw(seed),
            randomized_key: raw(seed.wrapping_add(1)),
            note_commitment: raw(seed.wrapping_add(2)),
            ephemeral_key: raw(seed.wrapping_add(3)),
            encrypted_note: vec![seed.wrapping_add(4); ORCHARD_ENCRYPTED_NOTE_BYTES_V1],
            outgoing_ciphertext: vec![seed.wrapping_add(5); ORCHARD_OUTGOING_CIPHERTEXT_BYTES_V1],
            value_commitment: raw(seed.wrapping_add(6)),
        }
    }
    #[cfg(test)]
    pub(super) fn bootle_lantern_policy() -> BootleLanternIssuerPolicyV1 {
        let first_column = core::array::from_fn(|block| BootleLanternPolynomialV1 {
            coefficients: (0..BOOTLE_LANTERN_RING_DEGREE_V1)
                .map(|coefficient| {
                    u16::try_from((block * 67 + coefficient + 1) % 12_288)
                        .expect("test residue fits u16")
                })
                .collect(),
        });
        let issuer_public_matrix =
            BootleLanternIssuerPublicMatrixV1::from_r512_first_column_blocks_v1(&first_column)
                .expect("canonical degree-512 multiplication matrix");
        let allowed_values = (0..BOOTLE_LANTERN_ATTRIBUTE_COUNT_V1)
            .map(|index| BootleLanternAllowedAttributeValuesV1 {
                values: if index == 1 {
                    vec![
                        BootleLanternAttributeValueV1::new([1; 8]),
                        BootleLanternAttributeValueV1::new([2; 8]),
                    ]
                } else {
                    Vec::new()
                },
            })
            .collect();
        let mut record = BootleLanternIssuerPolicyV1 {
            issuer_id: PrivacyIssuerIdV1::new(raw(171)),
            policy_id: PrivacyPolicyIdV1::new(raw(172)),
            epoch: 1,
            lifecycle: BootleLanternIssuerPolicyLifecycleV1::Active,
            issuer_parameter_id: PrivacyParameterIdV1::new(raw(173)),
            issuer_parameter_digest: PrivacyParameterDigestV1::new([0; 32]),
            issuer_public_matrix,
            required_disclosure_bitmap: 0b0001_0010,
            allowed_values,
            record_digest: PrivacyBootleLanternIssuerPolicyDigestV1::new([0; 32]),
        };
        redigest_bootle_lantern_policy(&mut record);
        record
    }
    #[cfg(test)]
    pub(super) fn redigest_bootle_lantern_policy(record: &mut BootleLanternIssuerPolicyV1) {
        record.issuer_parameter_digest = record
            .computed_issuer_parameter_digest()
            .expect("test issuer-parameter digest");
        record.record_digest = PrivacyBootleLanternIssuerPolicyDigestV1::new([0; 32]);
        record.record_digest = record
            .computed_record_digest()
            .expect("test issuer-policy digest");
    }
    fn sample_authorization_statements(asset: &AssetDefinitionId) -> [PrivacyStatementV1; 5] {
        [
            PrivacyStatementV1::ZkAcePqAuthorizationV1(ZkAcePqAuthorizationStatementV1 {
                context: context(),
                identity_commitment: zk_ace_identity_commitment(10),
                policy_id: PrivacyPolicyIdV1::new(raw(11)),
                policy_digest: PrivacyPolicyDigestV1::new(raw(12)),
                source: account(13),
                destination: account(14),
                asset_definition_id: asset.clone(),
                public_balance_scope: AssetBalanceScope::Global,
                amount: 1_000,
                authorization_epoch: 7,
                replay_nullifier: zk_ace_replay_nullifier(15),
            }),
            PrivacyStatementV1::AnonymousPgcKOutOfNV1(AnonymousPgcKOutOfNStatementV1 {
                context: context(),
                asset_definition_id: asset.clone(),
                pool_id: PrivacyPoolIdV1::new(raw(20)),
                account_state_root: PrivacyRootV1::new(raw(21)),
                account_state_root_epoch: 8,
                next_account_state_root: PrivacyRootV1::new(raw(22)),
                next_account_state_root_epoch: 9,
                anonymity_set_public_keys: (1..=16).map(p256_point).collect(),
                transfer_ciphertexts: (1..=16).map(p256_ciphertext).collect(),
                recipient_count: 2,
            }),
            PrivacyStatementV1::VeRangeTransparentRangeV1(VeRangeTransparentRangeStatementV1 {
                context: context(),
                asset_definition_id: asset.clone(),
                policy_id: PrivacyPolicyIdV1::new(raw(35)),
                value_commitments: vec![p256_point(36), p256_point(37)],
                bit_length: PrivacyVeRangeBitLengthV1::Bits32,
                aggregation_count: 2,
            }),
            PrivacyStatementV1::IrohaZkAmsV1(IrohaZkAmsStatementV1 {
                context: context(),
                issuer_id: PrivacyIssuerIdV1::new(raw(40)),
                issuer_public_key: p256_point(42),
                issuer_policy_record_digest: PrivacyZkAmsIssuerPolicyRecordDigestV1::new(raw(43)),
                registry_id: PrivacyZkAmsRegistryIdV1::new(raw(41)),
                registry_record_digest: PrivacyZkAmsRegistryRecordDigestV1::new(raw(44)),
                policy_id: PrivacyPolicyIdV1::new(raw(45)),
                policy_digest: PrivacyPolicyDigestV1::new(raw(46)),
                action: PrivacyZkAmsActionV1::BatchAdmission(PrivacyZkAmsBatchAdmissionV1 {
                    account_registry_root: PrivacyRootV1::new(raw(144)),
                    account_registry_root_epoch: 10,
                    next_account_registry_root: PrivacyRootV1::new(raw(145)),
                    next_account_registry_root_epoch: 11,
                    anchors: vec![zk_ams_anchor(44), zk_ams_anchor(45)],
                }),
            }),
            PrivacyStatementV1::VegaExistingCredentialZkV1(VegaExistingCredentialStatementV1 {
                context: context(),
                issuer_id: PrivacyIssuerIdV1::new(raw(49)),
                issuer_record_epoch: 3,
                issuer_record_digest: PrivacyVegaIssuerRecordDigestV1::new(raw(51)),
                document_type: PrivacyCredentialDocumentTypeV1::Iso18013_5Mdl,
                namespace: PrivacyVegaMdlNamespaceV1::OrgIso18013_5_1,
                digest_algorithm: PrivacyVegaMdlDigestAlgorithmV1::Sha256,
                issuer_authentication_algorithm: PrivacyVegaMdlSignatureAlgorithmV1::CoseSign1Es256,
                device_authentication_algorithm: PrivacyVegaMdlSignatureAlgorithmV1::CoseSign1Es256,
                issuer_public_key: p256_point(50),
                device_authentication_digest: PrivacyVegaDeviceAuthenticationDigestV1::new(raw(57)),
                presentation_date: PrivacyVegaMdlDateV1 {
                    year: 2_026,
                    month: 7,
                    day: 26,
                },
                minimum_age_years: 18,
                reader_challenge: PrivacyChallengeV1::new(raw(58)),
                session_transcript_digest: PrivacySessionTranscriptDigestV1::new(raw(59)),
            }),
        ]
    }
    fn sample_identity_statements() -> [PrivacyStatementV1; 3] {
        [
            PrivacyStatementV1::IrohaZkX509StarkP256V1(IrohaZkX509StarkP256StatementV1 {
                context: context(),
                trust_anchor_id: PrivacyIssuerIdV1::new(raw(61)),
                certificate_policy_id: PrivacyPolicyIdV1::new(raw(62)),
                trust_anchor_record_digest: PrivacyZkX509TrustAnchorRecordDigestV1::new(raw(69)),
                trust_anchor_record_epoch: 3,
                certificate_policy_record_digest: PrivacyZkX509CertificatePolicyRecordDigestV1::new(
                    raw(70),
                ),
                certificate_policy_record_epoch: 4,
                crl_record_digest: PrivacyZkX509CrlRecordDigestV1::new(raw(73)),
                crl_record_epoch: 5,
                subject_public_key_digest: PrivacyCertificateKeyDigestV1::new(raw(63)),
                ca_membership_root: PrivacyRootV1::new(raw(64)),
                ca_membership_root_epoch: 10,
                key_usage: PrivacyX509KeyUsageV1 {
                    digital_signature: PrivacyX509KeyUsageRequirementV1::new(true),
                    content_commitment: PrivacyX509KeyUsageRequirementV1::new(false),
                    key_encipherment: PrivacyX509KeyUsageRequirementV1::new(false),
                    key_agreement: PrivacyX509KeyUsageRequirementV1::new(false),
                },
                extended_key_usages: vec![
                    PrivacyX509ExtendedKeyUsageV1::ClientAuthentication,
                    PrivacyX509ExtendedKeyUsageV1::WalletIdentity,
                ],
                disclosed_attributes: vec![
                    PrivacyZkX509DisclosedAttributeV1 {
                        index: 0,
                        attribute_digest: PrivacyAttributeDigestV1::new(raw(71)),
                    },
                    PrivacyZkX509DisclosedAttributeV1 {
                        index: 3,
                        attribute_digest: PrivacyAttributeDigestV1::new(raw(72)),
                    },
                ],
                presentation_not_before_unix_seconds: 1_400,
                presentation_not_after_unix_seconds: 1_600,
                wallet_account: account(66),
                wallet_challenge: PrivacyChallengeV1::new(raw(67)),
                certificate_nullifier: nullifier(68),
            }),
            PrivacyStatementV1::IrohaJindoPolynomialCommitmentV1(
                IrohaJindoPolynomialCommitmentStatementV1 {
                    context: context(),
                    polynomial_commitments: (70..74).map(jindo_commitment).collect(),
                    evaluation_point: jindo_field(1),
                    claimed_evaluations: (4..8).map(jindo_field).collect(),
                },
            ),
            PrivacyStatementV1::IrohaBootleLanternAnoncredV1(
                IrohaBootleLanternAnoncredStatementV1 {
                    context: context(),
                    issuer_id: PrivacyIssuerIdV1::new(raw(72)),
                    policy_id: PrivacyPolicyIdV1::new(raw(73)),
                    issuer_policy_epoch: 12,
                    issuer_policy_record_digest: PrivacyBootleLanternIssuerPolicyDigestV1::new(
                        raw(76),
                    ),
                    issuer_parameter_id: PrivacyParameterIdV1::new(raw(74)),
                    issuer_parameter_digest: PrivacyParameterDigestV1::new(raw(75)),
                    disclosures: vec![
                        BootleLanternDisclosedAttributeV1 {
                            index: 1,
                            value: BootleLanternAttributeValueV1::new([0; 8]),
                        },
                        BootleLanternDisclosedAttributeV1 {
                            index: 4,
                            value: BootleLanternAttributeValueV1::new([u8::MAX; 8]),
                        },
                    ],
                },
            ),
        ]
    }
    fn sample_pool_statements(asset: &AssetDefinitionId) -> [PrivacyStatementV1; 4] {
        [
            PrivacyStatementV1::OrchardHalo2ActionsV1(OrchardHalo2ActionsStatementV1 {
                context: context(),
                asset_definition_id: asset.clone(),
                public_balance_scope: AssetBalanceScope::Global,
                pool_id: PrivacyPoolIdV1::new(raw(81)),
                anchor: PrivacyRootV1::new(raw(82)),
                anchor_epoch: 13,
                actions: vec![orchard_action(83)],
                value_balance: PrivacyValueBalanceV1::balanced(),
                expiry_height: 10_000,
            }),
            PrivacyStatementV1::MoneroFcmpPlusPlusV1({
                let output = fcmp_output(91);
                MoneroFcmpPlusPlusStatementV1 {
                    context: context(),
                    asset_definition_id: asset.clone(),
                    pool_id: PrivacyPoolIdV1::new(raw(87)),
                    output_set_root: PrivacyFcmpTreeRootV1 {
                        layers: 1,
                        point: raw(88),
                    },
                    root_epoch: 14,
                    inputs: vec![fcmp_input(89)],
                    outputs: vec![output],
                    encrypted_outputs: vec![fcmp_encrypted_output(output, 92)],
                }
            }),
            PrivacyStatementV1::IrohaIvmPrivateNoteStarkV1({
                let mut statement = IrohaIvmPrivateNoteStarkStatementV1 {
                    context: context(),
                    asset_definition_id: asset.clone(),
                    public_balance_scope: AssetBalanceScope::Global,
                    pool_id: PrivacyPoolIdV1::new(raw(94)),
                    program_id: PrivacyProgramIdV1::new(raw(95)),
                    action_digest: PrivacyActionDigestV1::new([0; 32]),
                    state_root: PrivacyRootV1::new(raw(96)),
                    root_epoch: 15,
                    nullifiers: vec![nullifier(97)],
                    output_commitments: vec![commitment(98)],
                    encrypted_outputs: vec![encrypted_output(98, 99)],
                    value_balance: PrivacyValueBalanceV1::balanced(),
                    execution_epoch: 15,
                };
                statement.action_digest = statement
                    .computed_action_digest()
                    .expect("compute private-IVM fixture action digest");
                statement
            }),
            PrivacyStatementV1::PqMaspStarkV1(PqMaspStarkStatementV1 {
                context: context(),
                asset_definition_id: asset.clone(),
                pool_id: PrivacyPoolIdV1::new(raw(101)),
                anchor: PrivacyRootV1::new(raw(102)),
                anchor_epoch: 17,
                nullifiers: vec![nullifier(103)],
                output_commitments: vec![commitment(104)],
                encrypted_outputs: vec![encrypted_output(104, 105)],
                authorization_profile: PrivacyPqAuthorizationProfileV1::MlDsa65,
                authorization_key_digest: PrivacyAuthorizationKeyDigestV1::new(raw(107)),
                note_encryption_profile:
                    PrivacyPqNoteEncryptionProfileV1::MlKem768XChaCha20Poly1305,
                note_encryption_key_digest: PrivacyNoteEncryptionKeyDigestV1::new(raw(108)),
                authorization_epoch: 17,
            }),
        ]
    }
    pub(super) fn sample_statements() -> Vec<PrivacyStatementV1> {
        let asset = asset_definition_id();
        let mut statements = Vec::with_capacity(PrivacyProtocolIdV1::COUNT);
        statements.extend(sample_authorization_statements(&asset));
        statements.extend(sample_identity_statements());
        statements.extend(sample_pool_statements(&asset));
        statements
    }
    #[cfg(test)]
    pub(super) fn statement_for(protocol: PrivacyProtocolIdV1) -> PrivacyStatementV1 {
        sample_statements()
            .into_iter()
            .find(|statement| statement.protocol_id() == protocol)
            .expect("sample statement for every protocol")
    }
    pub(super) fn proof_for(protocol: PrivacyProtocolIdV1) -> PrivacyProofV1 {
        let bytes = PrivacyProofBytesV1::new(vec![0xA5, 0x5A, 1]);
        match protocol {
            PrivacyProtocolIdV1::ZkAcePqAuthorizationV1 => {
                PrivacyProofV1::ZkAcePqAuthorizationV1(bytes)
            }
            PrivacyProtocolIdV1::AnonymousPgcKOutOfNV1 => {
                PrivacyProofV1::AnonymousPgcKOutOfNV1(bytes)
            }
            PrivacyProtocolIdV1::VeRangeTransparentRangeV1 => {
                PrivacyProofV1::VeRangeTransparentRangeV1(bytes)
            }
            PrivacyProtocolIdV1::IrohaZkAmsV1 => PrivacyProofV1::IrohaZkAmsV1(
                IrohaZkAmsProofV1::MaskedRelaxedSpartanBatchAdmission(bytes),
            ),
            PrivacyProtocolIdV1::VegaExistingCredentialZkV1 => {
                PrivacyProofV1::VegaExistingCredentialZkV1(bytes)
            }
            PrivacyProtocolIdV1::IrohaZkX509StarkP256V1 => {
                PrivacyProofV1::IrohaZkX509StarkP256V1(bytes)
            }
            PrivacyProtocolIdV1::IrohaJindoPolynomialCommitmentV1 => {
                PrivacyProofV1::IrohaJindoPolynomialCommitmentV1(bytes)
            }
            PrivacyProtocolIdV1::IrohaBootleLanternAnoncredV1 => {
                PrivacyProofV1::IrohaBootleLanternAnoncredV1(bytes)
            }
            PrivacyProtocolIdV1::OrchardHalo2ActionsV1 => {
                PrivacyProofV1::OrchardHalo2ActionsV1(bytes)
            }
            PrivacyProtocolIdV1::MoneroFcmpPlusPlusV1 => {
                PrivacyProofV1::MoneroFcmpPlusPlusV1(bytes)
            }
            PrivacyProtocolIdV1::IrohaIvmPrivateNoteStarkV1 => {
                PrivacyProofV1::IrohaIvmPrivateNoteStarkV1(bytes)
            }
            PrivacyProtocolIdV1::PqMaspStarkV1 => PrivacyProofV1::PqMaspStarkV1(bytes),
        }
    }
    pub(super) fn statement_variant_name(statement: &PrivacyStatementV1) -> &'static str {
        match statement {
            PrivacyStatementV1::ZkAcePqAuthorizationV1(_) => "ZkAcePqAuthorizationV1",
            PrivacyStatementV1::AnonymousPgcKOutOfNV1(_) => "AnonymousPgcKOutOfNV1",
            PrivacyStatementV1::VeRangeTransparentRangeV1(_) => "VeRangeTransparentRangeV1",
            PrivacyStatementV1::IrohaZkAmsV1(_) => "IrohaZkAmsV1",
            PrivacyStatementV1::VegaExistingCredentialZkV1(_) => "VegaExistingCredentialZkV1",
            PrivacyStatementV1::IrohaZkX509StarkP256V1(_) => "IrohaZkX509StarkP256V1",
            PrivacyStatementV1::IrohaJindoPolynomialCommitmentV1(_) => {
                "IrohaJindoPolynomialCommitmentV1"
            }
            PrivacyStatementV1::IrohaBootleLanternAnoncredV1(_) => "IrohaBootleLanternAnoncredV1",
            PrivacyStatementV1::OrchardHalo2ActionsV1(_) => "OrchardHalo2ActionsV1",
            PrivacyStatementV1::MoneroFcmpPlusPlusV1(_) => "MoneroFcmpPlusPlusV1",
            PrivacyStatementV1::IrohaIvmPrivateNoteStarkV1(_) => "IrohaIvmPrivateNoteStarkV1",
            PrivacyStatementV1::PqMaspStarkV1(_) => "PqMaspStarkV1",
        }
    }
    pub(super) fn proof_variant_name(proof: &PrivacyProofV1) -> &'static str {
        match proof {
            PrivacyProofV1::ZkAcePqAuthorizationV1(_) => "ZkAcePqAuthorizationV1",
            PrivacyProofV1::AnonymousPgcKOutOfNV1(_) => "AnonymousPgcKOutOfNV1",
            PrivacyProofV1::VeRangeTransparentRangeV1(_) => "VeRangeTransparentRangeV1",
            PrivacyProofV1::IrohaZkAmsV1(_) => "IrohaZkAmsV1",
            PrivacyProofV1::VegaExistingCredentialZkV1(_) => "VegaExistingCredentialZkV1",
            PrivacyProofV1::IrohaZkX509StarkP256V1(_) => "IrohaZkX509StarkP256V1",
            PrivacyProofV1::IrohaJindoPolynomialCommitmentV1(_) => {
                "IrohaJindoPolynomialCommitmentV1"
            }
            PrivacyProofV1::IrohaBootleLanternAnoncredV1(_) => "IrohaBootleLanternAnoncredV1",
            PrivacyProofV1::OrchardHalo2ActionsV1(_) => "OrchardHalo2ActionsV1",
            PrivacyProofV1::MoneroFcmpPlusPlusV1(_) => "MoneroFcmpPlusPlusV1",
            PrivacyProofV1::IrohaIvmPrivateNoteStarkV1(_) => "IrohaIvmPrivateNoteStarkV1",
            PrivacyProofV1::PqMaspStarkV1(_) => "PqMaspStarkV1",
        }
    }
    fn try_envelope(
        statement: PrivacyStatementV1,
    ) -> Result<PrivacyProofEnvelopeV1, PrivacyProofEnvelopeValidationError> {
        let proof = match &statement {
            PrivacyStatementV1::IrohaZkAmsV1(IrohaZkAmsStatementV1 {
                action: PrivacyZkAmsActionV1::ProvisionAccount(_),
                ..
            }) => {
                PrivacyProofV1::IrohaZkAmsV1(IrohaZkAmsProofV1::Ristretto255LsagProvisionAccount(
                    PrivacyProofBytesV1::new(vec![0xA5, 0x5A, 1]),
                ))
            }
            _ => proof_for(statement.protocol_id()),
        };
        PrivacyProofEnvelopeV1::bind_v1(statement, proof)
    }
    #[cfg(test)]
    pub(super) fn envelope(statement: PrivacyStatementV1) -> PrivacyProofEnvelopeV1 {
        try_envelope(statement).expect("fixture statement has a canonical digest")
    }
    /// One compiled semantic row of the canonical exact-12 cross-SDK fixture.
    ///
    /// This conformance-only type is derived from actual typed statements,
    /// proof variants, and canonical Norito envelope bytes. It never parses
    /// the checked-in TSV and carries no embedded digest constants.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct PrivacyExact12TypedEnvelopeRowV1 {
        /// Closed protocol identity in canonical discriminant order.
        pub protocol_id: PrivacyProtocolIdV1,
        /// Actual typed statement variant selected for the sample.
        pub statement_variant: &'static str,
        /// Actual typed proof variant selected for the sample envelope.
        pub proof_variant: &'static str,
        /// Digest recomputed from the actual typed sample statement.
        pub statement_digest: [u8; 32],
        /// SHA-256 of the actual canonical Norito proof envelope.
        pub envelope_sha256: [u8; 32],
    }
    /// One complete byte-level KAT row derived from the canonical typed Rust
    /// fixture.
    ///
    /// Every archive uses canonical uncompressed Norito. Keeping the protocol
    /// discriminant next to the complete statement, envelope, instruction,
    /// intent, unsigned-payload, and signed-transaction bytes lets downstream
    /// SDKs reject cross-protocol substitution at every transaction layer.
    #[derive(Clone, Debug, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
    #[norito_schema(
        name = "iroha_data_model::privacy::exact12_fixture::PrivacyExact12TypedFixtureRowV1",
        frame = "iroha.privacy.exact12-typed-fixture-row.v1"
    )]
    pub struct PrivacyExact12TypedFixtureRowV1 {
        /// Closed protocol identity in canonical discriminant order.
        pub protocol_id: PrivacyProtocolIdV1,
        /// Complete canonical [`PrivacyStatementV1`] bytes.
        pub statement_norito: Vec<u8>,
        /// Complete canonical [`PrivacyProofEnvelopeV1`] bytes.
        pub envelope_norito: Vec<u8>,
        /// Exact first-release instruction wire identifier.
        pub submit_proof_wire_id: String,
        /// Complete canonical [`SubmitPrivacyProofV1`] instruction archive.
        pub submit_proof_instruction_norito: Vec<u8>,
        /// Canonical normalized unsigned-payload preimage for the privacy intent.
        pub transaction_intent_projection_norito: Vec<u8>,
        /// BLAKE3 domain-separated digest of the normalized intent projection.
        pub transaction_intent_digest: [u8; 32],
        /// Canonical adaptive unsigned [`TransactionPayload`] bytes presented to signers.
        pub unsigned_transaction_payload_norito: Vec<u8>,
        /// Canonical versioned [`crate::transaction::SignedTransaction`] bytes submitted to Torii.
        pub signed_transaction_versioned_norito: Vec<u8>,
        /// Canonical pipeline transaction hash, which excludes authorization malleability.
        pub signed_transaction_hash: [u8; 32],
    }
    /// Signed byte-level KAT material for all first-release privacy protocols.
    #[derive(Clone, Debug, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
    #[norito_schema(
        name = "iroha_data_model::privacy::exact12_fixture::PrivacyExact12FixtureBundleV1",
        frame = "iroha.privacy.exact12-typed-fixture-bundle.v1"
    )]
    pub struct PrivacyExact12FixtureBundleV1 {
        /// Exact first-release bundle version.
        pub version: u32,
        /// Twelve rows in [`PrivacyProtocolIdV1::ALL`] order.
        pub rows: Vec<PrivacyExact12TypedFixtureRowV1>,
    }
    /// Maximum accepted encoded size of the complete exact-12 fixture bundle.
    pub const PRIVACY_EXACT12_FIXTURE_BUNDLE_MAX_BYTES_V1: usize = 2 * 1024 * 1024;
    const PRIVACY_EXACT12_FIXTURE_BUNDLE_MAX_NESTING_DEPTH_V1: usize = 64;
    /// Stable result of validating one untrusted exact-12 fixture bundle.
    #[repr(i32)]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum PrivacyExact12FixtureBundleValidationStatusV1 {
        /// The archive is byte-identical to the compiled canonical bundle.
        Valid = 0,
        /// A native ABI caller supplied a null pointer.
        NullPointer = 1,
        /// The archive contains no bytes.
        Empty = 2,
        /// The archive exceeds the fixed byte ceiling.
        ArchiveTooLarge = 3,
        /// Norito rejected a resource declaration before allocating it.
        DecodeResourceLimit = 4,
        /// The archive carries a different typed schema.
        SchemaMismatch = 5,
        /// The archive is a non-canonical representation of the typed value.
        NonCanonical = 6,
        /// The archive is malformed, truncated, or checksum-invalid.
        MalformedArchive = 7,
        /// The typed bundle differs from the one compiled Rust fixture.
        InvalidBundle = 8,
    }
    impl PrivacyExact12FixtureBundleValidationStatusV1 {
        /// Stable native ABI integer representation.
        #[must_use]
        pub const fn code(self) -> i32 {
            self as i32
        }
        /// Return whether the archive was accepted.
        #[must_use]
        pub const fn is_valid(self) -> bool {
            matches!(self, Self::Valid)
        }
    }
    /// Failure to derive the fixed exact-12 semantic fixture from current
    /// typed values and canonical Norito serialization.
    #[derive(Debug, Error)]
    pub enum PrivacyExact12FixtureErrorV1 {
        /// A typed statement digest or proof-envelope encoding failed.
        #[error("exact12 typed fixture canonical encoding failed: {0}")]
        CanonicalEncoding(#[from] norito::Error),
        /// The canonical envelope binding rejected a fixture statement and proof.
        #[error("exact12 typed fixture envelope binding failed: {0}")]
        EnvelopeBinding(#[from] PrivacyProofEnvelopeValidationError),
        /// The fixture constructor no longer produced the closed registry size.
        #[error("exact12 typed fixture produced {actual} rows instead of 12")]
        RowCount {
            /// Number of rows constructed from the current typed fixtures.
            actual: usize,
        },
        /// The role samples do not cover every Exact12 role exactly once.
        #[error("exact12 role samples do not cover the thirteen roles exactly once")]
        RoleCoverage,
        /// Canonical transaction-intent projection or binding failed.
        #[error("exact12 transaction-intent fixture failed: {0}")]
        TransactionIntent(#[from] PrivacyTransactionIntentErrorV1),
        /// Deterministic transaction construction or signature validation failed.
        #[error("exact12 deterministic transaction fixture failed: {0}")]
        Transaction(String),
    }
    struct PrivacyExact12CompleteRowV1 {
        statement: PrivacyStatementV1,
        envelope: PrivacyProofEnvelopeV1,
        submit_proof_instruction_norito: Vec<u8>,
        transaction_intent_projection_norito: Vec<u8>,
        transaction_intent_digest: [u8; 32],
        unsigned_transaction_payload_norito: Vec<u8>,
        signed_transaction_versioned_norito: Vec<u8>,
        signed_transaction_hash: [u8; 32],
    }
    fn exact12_signing_key_pair_v1() -> KeyPair {
        KeyPair::try_from_seed(vec![0xE7; 32], Algorithm::Ed25519)
            .expect("fixed exact12 Ed25519 signing seed is valid")
    }
    fn replace_exact12_submission_v1(
        payload: &mut TransactionPayload,
        intent: PrivacyTransactionIntentDigestV1,
    ) -> Result<SubmitPrivacyProofV1, PrivacyExact12FixtureErrorV1> {
        let Executable::Instructions(instructions) = &payload.instructions else {
            return Err(PrivacyExact12FixtureErrorV1::Transaction(
                "fixture executable is not a direct instruction list".to_owned(),
            ));
        };
        if instructions.len() != 1 {
            return Err(PrivacyExact12FixtureErrorV1::Transaction(format!(
                "fixture executable contains {} instructions instead of one",
                instructions.len()
            )));
        }
        let mut submission = instructions[0]
            .as_any()
            .downcast_ref::<SubmitPrivacyProofV1>()
            .ok_or_else(|| {
                PrivacyExact12FixtureErrorV1::Transaction(
                    "fixture instruction is not SubmitPrivacyProofV1".to_owned(),
                )
            })?
            .clone();
        submission
            .envelope
            .statement
            .context_mut()
            .transaction_intent_digest = intent;
        if let PrivacyStatementV1::IrohaIvmPrivateNoteStarkV1(statement) =
            &mut submission.envelope.statement
        {
            statement.action_digest = statement.computed_action_digest()?;
        }
        // Rebind through the one assembler so the envelope follows the changed statement.
        submission.envelope = PrivacyProofEnvelopeV1::bind_v1(
            submission.envelope.statement.clone(),
            submission.envelope.proof.clone(),
        )?;
        payload.instructions =
            Executable::Instructions(vec![InstructionBox::from(submission.clone())].into());
        Ok(submission)
    }
    fn exact12_complete_row_v1(
        statement: PrivacyStatementV1,
        row_index: usize,
    ) -> Result<PrivacyExact12CompleteRowV1, PrivacyExact12FixtureErrorV1> {
        let envelope = try_envelope(statement)?;
        let signing_key = exact12_signing_key_pair_v1();
        let authority = AccountId::new(signing_key.public_key().clone());
        let row_offset = u64::try_from(row_index).map_err(|_| {
            PrivacyExact12FixtureErrorV1::Transaction("row index does not fit u64".to_owned())
        })?;
        let nonce = u32::try_from(row_index + 1)
            .ok()
            .and_then(NonZeroU32::new)
            .ok_or_else(|| {
                PrivacyExact12FixtureErrorV1::Transaction(
                    "row nonce does not fit NonZeroU32".to_owned(),
                )
            })?;
        let mut payload = TransactionPayload {
            domain: TransactionDomain::Network(envelope.statement.context().network_id),
            authority,
            creation_time_ms: 1_700_000_000_000_u64
                .checked_add(row_offset)
                .ok_or_else(|| {
                    PrivacyExact12FixtureErrorV1::Transaction(
                        "fixture creation time overflow".to_owned(),
                    )
                })?,
            instructions: Executable::Instructions(
                vec![InstructionBox::from(SubmitPrivacyProofV1::new(envelope))].into(),
            ),
            time_to_live_ms: NonZeroU64::new(60_000),
            nonce: Some(nonce),
            fee_payment: FeePaymentIntent::authority(Vec::new(), None),

            metadata: Metadata::default(),
            attachments: None,
        };
        let intent = payload.privacy_transaction_intent_digest_v1()?;
        let submission = replace_exact12_submission_v1(&mut payload, intent)?;
        let observed = payload.validate_privacy_transaction_intent_binding_v1()?;
        if observed != intent {
            return Err(PrivacyExact12FixtureErrorV1::Transaction(
                "validated intent differs from the derived fixture intent".to_owned(),
            ));
        }
        let transaction_intent_projection_norito =
            payload.privacy_transaction_intent_projection_bytes_v1()?;
        let submit_proof_instruction_norito = norito::encode_canonical(&submission)?;
        let unsigned_transaction_payload_norito = TransactionBuilder::from_payload(payload.clone())
            .map_err(|error| PrivacyExact12FixtureErrorV1::Transaction(error.to_string()))?
            .encode_payload();
        let signed = TransactionBuilder::from_payload(payload)
            .map_err(|error| PrivacyExact12FixtureErrorV1::Transaction(error.to_string()))?
            .try_sign(signing_key.private_key())
            .map_err(|error| PrivacyExact12FixtureErrorV1::Transaction(error.to_string()))?;
        signed
            .verify_signature()
            .map_err(|error| PrivacyExact12FixtureErrorV1::Transaction(error.to_string()))?;
        let signed_transaction_hash = *signed.hash().as_ref();
        let signed_transaction_versioned_norito = signed.encode_versioned();
        Ok(PrivacyExact12CompleteRowV1 {
            statement: submission.envelope.statement.clone(),
            envelope: submission.envelope,
            submit_proof_instruction_norito,
            transaction_intent_projection_norito,
            transaction_intent_digest: *intent.as_bytes(),
            unsigned_transaction_payload_norito,
            signed_transaction_versioned_norito,
            signed_transaction_hash,
        })
    }
    /// Maximum governed limits of one protocol, as an activation record carries them.
    pub(super) fn sample_protocol_limits(
        protocol: PrivacyProtocolIdV1,
    ) -> PrivacyProtocolActivationLimitsV1 {
        match protocol {
            PrivacyProtocolIdV1::ZkAcePqAuthorizationV1 => {
                PrivacyProtocolActivationLimitsV1::ZkAcePqAuthorizationV1
            }
            PrivacyProtocolIdV1::AnonymousPgcKOutOfNV1 => {
                PrivacyProtocolActivationLimitsV1::AnonymousPgcKOutOfNV1(
                    AnonymousPgcActivationLimitsV1 {
                        max_anonymity_set_size: ANONYMOUS_PGC_MAX_ANONYMITY_SET_SIZE_V1,
                        max_recipient_count: ANONYMOUS_PGC_MAX_RECIPIENTS_V1,
                    },
                )
            }
            PrivacyProtocolIdV1::VeRangeTransparentRangeV1 => {
                PrivacyProtocolActivationLimitsV1::VeRangeTransparentRangeV1(
                    VeRangeActivationLimitsV1 {
                        max_aggregation_count: VERANGE_TAIRA_MAX_AGGREGATION_COUNT_V1,
                    },
                )
            }
            PrivacyProtocolIdV1::IrohaZkAmsV1 => {
                PrivacyProtocolActivationLimitsV1::IrohaZkAmsV1(ZkAmsActivationLimitsV1 {
                    max_batch_size: ZK_AMS_MAX_BATCH_SIZE_V1,
                    max_ring_size: ZK_AMS_MAX_RING_SIZE_V1,
                })
            }
            PrivacyProtocolIdV1::VegaExistingCredentialZkV1 => {
                PrivacyProtocolActivationLimitsV1::VegaExistingCredentialZkV1
            }
            PrivacyProtocolIdV1::IrohaZkX509StarkP256V1 => {
                PrivacyProtocolActivationLimitsV1::IrohaZkX509StarkP256V1
            }
            PrivacyProtocolIdV1::IrohaJindoPolynomialCommitmentV1 => {
                PrivacyProtocolActivationLimitsV1::IrohaJindoPolynomialCommitmentV1(
                    JindoActivationLimitsV1 {
                        max_polynomial_count: IROHA_JINDO_MAX_POLYNOMIALS_V1,
                    },
                )
            }
            PrivacyProtocolIdV1::IrohaBootleLanternAnoncredV1 => {
                PrivacyProtocolActivationLimitsV1::IrohaBootleLanternAnoncredV1
            }
            PrivacyProtocolIdV1::OrchardHalo2ActionsV1 => {
                PrivacyProtocolActivationLimitsV1::OrchardHalo2ActionsV1(
                    OrchardActivationLimitsV1 {
                        max_action_count: ORCHARD_MAX_ACTIONS_V1,
                    },
                )
            }
            PrivacyProtocolIdV1::MoneroFcmpPlusPlusV1 => {
                PrivacyProtocolActivationLimitsV1::MoneroFcmpPlusPlusV1(FcmpActivationLimitsV1 {
                    max_input_count: FCMP_MAX_INPUTS_V1,
                    max_output_count: FCMP_MAX_OUTPUTS_V1,
                })
            }
            PrivacyProtocolIdV1::IrohaIvmPrivateNoteStarkV1 => {
                PrivacyProtocolActivationLimitsV1::IrohaIvmPrivateNoteStarkV1(
                    IvmPrivateNoteActivationLimitsV1 {
                        max_input_count: IVM_PRIVATE_NOTE_MAX_INPUTS_V1,
                        max_output_count: IVM_PRIVATE_NOTE_MAX_OUTPUTS_V1,
                    },
                )
            }
            PrivacyProtocolIdV1::PqMaspStarkV1 => {
                PrivacyProtocolActivationLimitsV1::PqMaspStarkV1(PqMaspActivationLimitsV1 {
                    max_input_count: PQ_MASP_MAX_INPUTS_V1,
                    max_output_count: PQ_MASP_MAX_OUTPUTS_V1,
                })
            }
        }
    }
    /// An active activation record that admits `envelope` from height 2.
    pub(super) fn sample_activation(
        envelope: &PrivacyProofEnvelopeV1,
    ) -> PrivacyProtocolActivationRecordV1 {
        PrivacyProtocolActivationRecordV1 {
            protocol_id: envelope.protocol_id,
            proof_system_id: envelope.proof_system_id,
            engine_id: envelope.engine_id,
            parameter_id: envelope.parameter_id,
            parameter_digest: envelope.parameter_digest,
            verifier_digest: envelope.verifier_digest,
            statement_schema_digest: envelope.statement_schema_digest,
            engine_manifest_digest: envelope.engine_manifest_digest,
            lifecycle: PrivacyProtocolLifecycleV1::Active(PrivacyActiveLifecycleV1 {
                proposed_at_height: 1,
                activated_at_height: 2,
                state_since_height: 2,
            }),
            protocol_limits: sample_protocol_limits(envelope.protocol_id),
            pending_protocol_limits_tightening: None,
        }
    }
    /// One structurally valid sample of an Exact12 role.
    ///
    /// The envelope is the canonical binding of a typed sample statement and a
    /// placeholder proof; the activation record is active from height 2 and
    /// carries exactly the envelope's identities. A sample passes intrinsic and
    /// activation validation and is never accepted by a native verifier, so it
    /// exercises routing, substitution and refusal without a prover.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct PrivacyActionRoleSampleV1 {
        /// The role the sample selects.
        pub role: PrivacyActionRoleV1,
        /// Canonical envelope of the sample statement and placeholder proof.
        pub envelope: PrivacyProofEnvelopeV1,
        /// Active record whose identities equal the envelope's.
        pub activation: PrivacyProtocolActivationRecordV1,
    }
    /// Build one structurally valid sample for each of the thirteen Exact12 roles.
    ///
    /// The rows are in [`PrivacyActionRoleV1::ALL`] order. Like the other
    /// helpers of this module the function exists only in tests and in builds
    /// that enable `iroha_data_model/privacy-exact12-conformance`.
    ///
    /// # Errors
    ///
    /// Returns an error if a sample statement has no canonical digest, a sample
    /// proof does not bind, or the samples do not cover every role exactly once.
    pub fn privacy_action_role_samples_v1()
    -> Result<Vec<PrivacyActionRoleSampleV1>, PrivacyExact12FixtureErrorV1> {
        let mut statements = sample_statements();
        statements.push(zk_ams_provision_statement(16));
        let mut samples = statements
            .into_iter()
            .map(|statement| {
                let envelope = try_envelope(statement)?;
                let role = envelope.action_role_v1()?;
                let activation = sample_activation(&envelope);
                Ok(PrivacyActionRoleSampleV1 {
                    role,
                    envelope,
                    activation,
                })
            })
            .collect::<Result<Vec<_>, PrivacyExact12FixtureErrorV1>>()?;
        samples.sort_by_key(|sample| sample.role);
        if samples
            .iter()
            .map(|sample| sample.role)
            .ne(PrivacyActionRoleV1::ALL)
        {
            return Err(PrivacyExact12FixtureErrorV1::RoleCoverage);
        }
        Ok(samples)
    }
    /// Recompute all 12 canonical cross-SDK semantic rows from current Rust
    /// types and canonical Norito serialization.
    ///
    /// The helper is available only to tests and builds that explicitly enable
    /// `iroha_data_model/privacy-exact12-conformance`; ordinary validator
    /// builds do not compile this conformance surface. The feature does not
    /// expose the general data-model test fixtures.
    ///
    /// # Errors
    ///
    /// Returns an error if a typed statement or envelope cannot be encoded
    /// canonically, or if the fixture constructor does not produce exactly 12
    /// rows.
    pub fn privacy_exact12_typed_envelope_rows_v1()
    -> Result<[PrivacyExact12TypedEnvelopeRowV1; 12], PrivacyExact12FixtureErrorV1> {
        let rows = sample_statements()
            .into_iter()
            .enumerate()
            .map(|(row_index, statement)| {
                let complete = exact12_complete_row_v1(statement, row_index)?;
                let protocol_id = complete.statement.protocol_id();
                let proof_envelope = complete.envelope;
                let canonical_envelope = norito::encode_canonical(&proof_envelope)?;
                Ok(PrivacyExact12TypedEnvelopeRowV1 {
                    protocol_id,
                    statement_variant: statement_variant_name(&proof_envelope.statement),
                    proof_variant: proof_variant_name(&proof_envelope.proof),
                    statement_digest: *proof_envelope.statement_digest.as_bytes(),
                    envelope_sha256: Sha256::digest(canonical_envelope).into(),
                })
            })
            .collect::<Result<Vec<_>, PrivacyExact12FixtureErrorV1>>()?;
        rows.try_into()
            .map_err(|rows: Vec<PrivacyExact12TypedEnvelopeRowV1>| {
                PrivacyExact12FixtureErrorV1::RowCount { actual: rows.len() }
            })
    }
    /// Build the complete exact-12 byte-level KAT bundle from typed Rust
    /// values.
    ///
    /// # Errors
    ///
    /// Returns an error if any statement or envelope cannot be encoded
    /// canonically, or if the fixture no longer contains exactly twelve rows.
    pub fn privacy_exact12_fixture_bundle_v1()
    -> Result<PrivacyExact12FixtureBundleV1, PrivacyExact12FixtureErrorV1> {
        let rows = sample_statements()
            .into_iter()
            .enumerate()
            .map(|(row_index, statement)| {
                let complete = exact12_complete_row_v1(statement, row_index)?;
                let protocol_id = complete.statement.protocol_id();
                let statement_norito = norito::encode_canonical(&complete.statement)?;
                let envelope_norito = norito::encode_canonical(&complete.envelope)?;
                Ok(PrivacyExact12TypedFixtureRowV1 {
                    protocol_id,
                    statement_norito,
                    envelope_norito,
                    submit_proof_wire_id: SubmitPrivacyProofV1::WIRE_ID.to_owned(),
                    submit_proof_instruction_norito: complete.submit_proof_instruction_norito,
                    transaction_intent_projection_norito: complete
                        .transaction_intent_projection_norito,
                    transaction_intent_digest: complete.transaction_intent_digest,
                    unsigned_transaction_payload_norito: complete
                        .unsigned_transaction_payload_norito,
                    signed_transaction_versioned_norito: complete
                        .signed_transaction_versioned_norito,
                    signed_transaction_hash: complete.signed_transaction_hash,
                })
            })
            .collect::<Result<Vec<_>, PrivacyExact12FixtureErrorV1>>()?;
        if rows.len() != PrivacyProtocolIdV1::COUNT {
            return Err(PrivacyExact12FixtureErrorV1::RowCount { actual: rows.len() });
        }
        Ok(PrivacyExact12FixtureBundleV1 { version: 1, rows })
    }
    /// Encode the complete exact-12 byte-level KAT bundle as canonical Norito.
    ///
    /// # Errors
    ///
    /// Returns an error if fixture construction or canonical encoding fails.
    pub fn privacy_exact12_fixture_bundle_bytes_v1() -> Result<Vec<u8>, PrivacyExact12FixtureErrorV1>
    {
        let bundle = privacy_exact12_fixture_bundle_v1()?;
        Ok(norito::encode_canonical(&bundle)?)
    }
    /// Validate an untrusted byte-level KAT bundle against the exact bundle
    /// compiled from current typed Rust fixtures.
    ///
    /// The decoder is resource-bounded, requires canonical uncompressed
    /// Norito, and finally requires byte-for-byte semantic equality with the
    /// compiled bundle. It therefore rejects reordered rows, wrong variants,
    /// cross-protocol substitution, stale bytes at any transaction layer, and
    /// unknown extensions.
    #[must_use]
    pub fn validate_privacy_exact12_fixture_bundle_v1(
        archive: &[u8],
    ) -> PrivacyExact12FixtureBundleValidationStatusV1 {
        use PrivacyExact12FixtureBundleValidationStatusV1 as Status;
        if archive.is_empty() {
            return Status::Empty;
        }
        if archive.len() > PRIVACY_EXACT12_FIXTURE_BUNDLE_MAX_BYTES_V1 {
            return Status::ArchiveTooLarge;
        }
        // Wire bytes and decoded heap use different units: every byte vector
        // has container bookkeeping and some canonical layouts may represent
        // several logical elements per byte. Derive those budgets from this
        // already-capped frame instead of equating heap use with wire length.
        // Keeping the derivation frame-local also prevents a tiny hostile
        // archive from inheriting the full 2 MiB archive ceiling as an
        // allocation grant.
        let canonical_limits = norito::canonical_decode_limits(archive.len());
        let limits = norito::DecodeLimits::new(
            canonical_limits.max_sequence_elements(),
            canonical_limits.max_field_bytes(),
            canonical_limits.max_total_elements(),
            canonical_limits.max_total_allocated_bytes(),
            PRIVACY_EXACT12_FIXTURE_BUNDLE_MAX_NESTING_DEPTH_V1,
        );
        let decoded = match norito::decode_canonical_with_limits::<PrivacyExact12FixtureBundleV1>(
            archive, limits,
        ) {
            Ok(decoded) => decoded,
            Err(error) if error.is_decode_resource_limit() => return Status::DecodeResourceLimit,
            Err(norito::Error::SchemaMismatch) => return Status::SchemaMismatch,
            Err(
                norito::Error::NonCanonicalEncoding
                | norito::Error::DecodeFlagsMismatch { .. }
                | norito::Error::UnsupportedCompression { .. },
            ) => return Status::NonCanonical,
            Err(_) => return Status::MalformedArchive,
        };
        let Ok(expected) = privacy_exact12_fixture_bundle_v1() else {
            return Status::InvalidBundle;
        };
        if decoded != expected {
            return Status::InvalidBundle;
        }
        Status::Valid
    }
    fn canonical_sha256_hex_v1(digest: &[u8; 32]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(64);
        for byte in digest {
            output.push(char::from(HEX[usize::from(byte >> 4)]));
            output.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        output
    }
    /// Generate the complete canonical exact-12 cross-SDK matrix from the
    /// current compiled protocol registry and typed Norito envelope fixtures.
    ///
    /// `fixtures/privacy/exact12_v1.tsv` is a derived cross-SDK artifact of
    /// this function. Keeping construction here prevents a manually copied
    /// digest row or whole-file hash from becoming a second semantic source.
    ///
    /// # Errors
    ///
    /// Returns an error if the typed statement/envelope rows cannot be
    /// generated canonically or no longer have the exact closed registry size.
    pub fn privacy_exact12_matrix_bytes_v1() -> Result<Vec<u8>, PrivacyExact12FixtureErrorV1> {
        let semantic_rows = privacy_exact12_typed_envelope_rows_v1()?;
        let mut registry_preimage = Vec::new();
        for protocol_id in PrivacyProtocolIdV1::ALL {
            registry_preimage.extend_from_slice(protocol_id.canonical_label().as_bytes());
            registry_preimage.push(b'\n');
        }
        let registry_sha256: [u8; 32] = Sha256::digest(&registry_preimage).into();
        let mut output = String::new();
        for header in EXACT12_CANONICAL_HEADER_V1 {
            writeln!(&mut output, "{header}").expect("writing to String cannot fail");
        }
        writeln!(&mut output, "matrix-version\t1").expect("writing to String cannot fail");
        writeln!(
            &mut output,
            "registry-sha256\t{}",
            canonical_sha256_hex_v1(&registry_sha256)
        )
        .expect("writing to String cannot fail");
        for (index, protocol_id) in PrivacyProtocolIdV1::ALL.into_iter().enumerate() {
            let variant = protocol_id.canonical_typed_variant_label();
            writeln!(
                &mut output,
                "protocol\t{index}\t{}\t{variant}\t{variant}",
                protocol_id.canonical_label()
            )
            .expect("writing to String cannot fail");
        }
        for semantic in semantic_rows {
            writeln!(
                &mut output,
                "typed-envelope\t{}\t{}\t{}\t{}\t{}",
                semantic.protocol_id.canonical_label(),
                semantic.statement_variant,
                semantic.proof_variant,
                canonical_sha256_hex_v1(&semantic.statement_digest),
                canonical_sha256_hex_v1(&semantic.envelope_sha256)
            )
            .expect("writing to String cannot fail");
        }
        Ok(output.into_bytes())
    }
}

#[cfg(test)]
mod captured_proofs_schema_tests;
