/// One public selectively disclosed X.509 subject attribute.
///
/// Indices use the paper's closed order: `0=C`, `1=O`, `2=OU`, `3=CN`.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::privacy::PrivacyZkX509DisclosedAttributeV1")]
pub struct PrivacyZkX509DisclosedAttributeV1 {
    /// Closed attribute index.
    pub index: u8,
    /// Public digest of the privately salted canonical attribute value.
    pub attribute_digest: PrivacyAttributeDigestV1,
}
/// Native X.509 credential-predicate STARK statement.
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
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::privacy::IrohaZkX509StarkP256StatementV1")]
pub struct IrohaZkX509StarkP256StatementV1 {
    /// Shared chain and governed-artifact binding.
    pub context: PrivacyStatementContextV1,
    /// Trust-anchor issuer identifier.
    pub trust_anchor_id: PrivacyIssuerIdV1,
    /// Governed certificate-policy identifier.
    pub certificate_policy_id: PrivacyPolicyIdV1,
    /// Exact immutable trust-anchor revision selected by the statement.
    pub trust_anchor_record_digest: PrivacyZkX509TrustAnchorRecordDigestV1,
    /// Exact trust-anchor revision epoch selected by the statement.
    pub trust_anchor_record_epoch: u64,
    /// Exact immutable certificate-policy revision selected by the statement.
    pub certificate_policy_record_digest: PrivacyZkX509CertificatePolicyRecordDigestV1,
    /// Exact certificate-policy revision epoch selected by the statement.
    pub certificate_policy_record_epoch: u64,
    /// Exact immutable signed-CRL revision selected by the statement.
    pub crl_record_digest: PrivacyZkX509CrlRecordDigestV1,
    /// Exact signed-CRL revision epoch selected by the statement.
    pub crl_record_epoch: u64,
    /// Governance-scoped digest of the leaf certificate subject public key.
    ///
    /// Parent-chain keys and the private chain depth are deliberately excluded: the proof binds
    /// those through path validation, signatures, and the governed trust anchor.
    pub subject_public_key_digest: PrivacyCertificateKeyDigestV1,
    /// CA trust-store membership root authenticating the terminal certificate.
    pub ca_membership_root: PrivacyRootV1,
    /// Epoch at which the CA membership root was canonical.
    pub ca_membership_root_epoch: u64,
    /// Required RFC 5280 key usages.
    pub key_usage: PrivacyX509KeyUsageV1,
    /// Required extended-key-usage purposes, sorted in enum order.
    pub extended_key_usages: Vec<PrivacyX509ExtendedKeyUsageV1>,
    /// Canonical public selective disclosures in strict attribute-index order.
    pub disclosed_attributes: Vec<PrivacyZkX509DisclosedAttributeV1>,
    /// Earliest consensus timestamp at which this presentation may execute.
    ///
    /// The private certificate chain and signed CRL must cover the complete
    /// presentation window, so no exact certificate dates are disclosed.
    pub presentation_not_before_unix_seconds: u64,
    /// Latest consensus timestamp at which this presentation may execute.
    ///
    /// This bound is inclusive; the private CRL `nextUpdate` remains exclusive.
    pub presentation_not_after_unix_seconds: u64,
    /// Public wallet account to which the certificate showing is bound.
    pub wallet_account: AccountId,
    /// Wallet challenge preventing cross-account or cross-session replay.
    pub wallet_challenge: PrivacyChallengeV1,
    /// Nullifier derived from the certificate serial and policy.
    pub certificate_nullifier: PrivacyNullifierV1,
}
/// Canonical little-endian element of the fixed Jindo coefficient field.
///
/// The compiled modulus is `3611623616^8 + 1`. Fixed width at the type boundary
/// eliminates ambiguous byte order, truncation, and alternate field regimes.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::privacy::PrivacyJindoFieldElementV1")]
pub struct PrivacyJindoFieldElementV1 {
    /// Exact canonical little-endian residue.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub encoding: [u8; IROHA_JINDO_FIELD_ELEMENT_BYTES_V1],
}
impl PrivacyJindoFieldElementV1 {
    /// Construct a fixed-width field-element encoding.
    #[must_use]
    pub const fn new(encoding: [u8; IROHA_JINDO_FIELD_ELEMENT_BYTES_V1]) -> Self {
        Self { encoding }
    }
    /// Borrow the exact field-element bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; IROHA_JINDO_FIELD_ELEMENT_BYTES_V1] {
        &self.encoding
    }
}
/// Canonical public outer commitment in the fixed Jindo lattice profile.
///
/// The byte string contains 3 × 1024 signed little-endian `i32` coefficients. Native verification
/// additionally enforces the compiled rounded-coefficient bound.
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
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::privacy::PrivacyJindoLatticeCommitmentV1")]
pub struct PrivacyJindoLatticeCommitmentV1 {
    /// Exact governed lattice-commitment encoding.
    #[norito(json = "crate::json_helpers::base64_vec")]
    pub encoding: Vec<u8>,
}
impl PrivacyJindoLatticeCommitmentV1 {
    /// Construct a fixed-profile lattice-commitment encoding.
    #[must_use]
    pub fn new(encoding: Vec<u8>) -> Self {
        Self { encoding }
    }
    /// Borrow the exact lattice-commitment bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.encoding
    }
}
/// Native Jindo batched univariate lattice polynomial-opening statement.
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
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::privacy::IrohaJindoPolynomialCommitmentStatementV1")]
pub struct IrohaJindoPolynomialCommitmentStatementV1 {
    /// Shared chain and governed-artifact binding.
    pub context: PrivacyStatementContextV1,
    /// Public commitments to degree-bounded univariate polynomials.
    pub polynomial_commitments: Vec<PrivacyJindoLatticeCommitmentV1>,
    /// One common univariate evaluation point.
    pub evaluation_point: PrivacyJindoFieldElementV1,
    /// Claimed values in exact polynomial-commitment order.
    pub claimed_evaluations: Vec<PrivacyJindoFieldElementV1>,
}
/// One direct 64-bit attribute in the fixed Bootle/Lantern credential profile.
///
/// Bits are interpreted little-endian and become the 64 binary coefficients
/// of exactly one application-ring polynomial. This is deliberately not an
/// arbitrary byte string or a digest-preimage claim.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::privacy::BootleLanternAttributeValueV1")]
pub struct BootleLanternAttributeValueV1(
    /// Exact little-endian 64-bit attribute encoding.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub [u8; BOOTLE_LANTERN_ATTRIBUTE_BYTES_V1],
);
impl BootleLanternAttributeValueV1 {
    /// Construct one direct attribute value.
    #[must_use]
    pub const fn new(bytes: [u8; BOOTLE_LANTERN_ATTRIBUTE_BYTES_V1]) -> Self {
        Self(bytes)
    }
    /// Borrow the exact direct attribute bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; BOOTLE_LANTERN_ATTRIBUTE_BYTES_V1] {
        &self.0
    }
}
/// One polynomial in `Z_12289[X]/(X^64 + 1)`.
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
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::privacy::BootleLanternPolynomialV1")]
pub struct BootleLanternPolynomialV1 {
    /// Exactly 64 canonical coefficients, each strictly below 12,289.
    pub coefficients: Vec<u16>,
}
/// Canonical issuer verification matrix `B` in the application ring.
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
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::privacy::BootleLanternIssuerPublicMatrixV1")]
pub struct BootleLanternIssuerPublicMatrixV1 {
    /// Exactly 64 polynomials in row-major 8-by-8 order.
    pub entries: Vec<BootleLanternPolynomialV1>,
}
/// Minimum number of non-zero coefficients in the canonical degree-512
/// issuer public key `h` reconstructed from the eight first-column blocks.
///
/// Genuine Falcon/NTRU public keys are dense. This conservative floor rejects zero, monomial,
/// identity, and deliberately sparse matrices at the authoritative policy boundary without
/// attempting to prove possession of the issuer secret key.
pub const BOOTLE_LANTERN_ISSUER_PUBLIC_KEY_MIN_NONZERO_COEFFICIENTS_V1: usize = 256;
impl BootleLanternIssuerPublicMatrixV1 {
    /// Expand the eight canonical first-column blocks of one degree-512 Falcon/NTRU public key into
    /// its exact 8-by-8 multiplication matrix over `Z_12289[Y]/(Y^64 + 1)`.
    ///
    /// For `h` in `Z_12289[X]/(X^512 + 1)`, the interleaved coefficient
    /// isomorphism is exactly `H_i[j] = h[8*j+i]` for `0 <= i < 8` and
    /// `0 <= j < 64`; callers pass `[H_0, ..., H_7]` as `first_column`.
    ///
    /// If `H_i = B[i, 0]`, the unique row-major matrix is
    /// `B[r, c] = H_{r-c}` for `r >= c` and
    /// `B[r, c] = Y * H_{r-c+8}` otherwise.
    ///
    /// # Errors
    ///
    /// Rejects a first-column block with the wrong degree or a coefficient
    /// outside the canonical `0..12289` residue range.
    pub fn from_r512_first_column_blocks_v1(
        first_column: &[BootleLanternPolynomialV1; BOOTLE_LANTERN_ISSUER_MATRIX_DIMENSION_V1],
    ) -> Result<Self, BootleLanternIssuerPolicyValidationErrorV1> {
        for (row, polynomial) in first_column.iter().enumerate() {
            if polynomial.coefficients.len() != BOOTLE_LANTERN_RING_DEGREE_V1 {
                return Err(
                    BootleLanternIssuerPolicyValidationErrorV1::InvalidPolynomialCoefficientCount {
                        polynomial: u8::try_from(row * BOOTLE_LANTERN_ISSUER_MATRIX_DIMENSION_V1)
                            .expect("fixed first-column matrix index fits u8"),
                        count: u32::try_from(polynomial.coefficients.len()).map_err(|_| {
                            BootleLanternIssuerPolicyValidationErrorV1::
                                PolynomialCoefficientCountOverflow
                        })?,
                        expected: u32::try_from(BOOTLE_LANTERN_RING_DEGREE_V1)
                            .expect("fixed ring degree fits u32"),
                    },
                );
            }
            for (coefficient, value) in polynomial.coefficients.iter().copied().enumerate() {
                if value >= BOOTLE_LANTERN_APPLICATION_MODULUS_V1 {
                    return Err(
                        BootleLanternIssuerPolicyValidationErrorV1::NonCanonicalMatrixCoefficient {
                            row: u8::try_from(row).expect("fixed first-column row fits u8"),
                            column: 0,
                            coefficient: u8::try_from(coefficient)
                                .expect("fixed ring coefficient fits u8"),
                            value,
                        },
                    );
                }
            }
        }
        let mut entries = Vec::with_capacity(
            BOOTLE_LANTERN_ISSUER_MATRIX_DIMENSION_V1 * BOOTLE_LANTERN_ISSUER_MATRIX_DIMENSION_V1,
        );
        for row in 0..BOOTLE_LANTERN_ISSUER_MATRIX_DIMENSION_V1 - 1 {
            for column in 0..BOOTLE_LANTERN_ISSUER_MATRIX_DIMENSION_V1 {
                if row >= column {
                    entries.push(first_column[row - column].clone());
                } else {
                    let source =
                        &first_column[row + BOOTLE_LANTERN_ISSUER_MATRIX_DIMENSION_V1 - column];
                    let mut coefficients = vec![0_u16; BOOTLE_LANTERN_RING_DEGREE_V1];
                    let final_coefficient = source.coefficients[BOOTLE_LANTERN_RING_DEGREE_V1 - 1];
                    coefficients[0] = if final_coefficient == 0 {
                        0
                    } else {
                        BOOTLE_LANTERN_APPLICATION_MODULUS_V1 - final_coefficient
                    };
                    coefficients[1..]
                        .copy_from_slice(&source.coefficients[..BOOTLE_LANTERN_RING_DEGREE_V1 - 1]);
                    entries.push(BootleLanternPolynomialV1 { coefficients });
                }
            }
        }
        // The final row is the reversed first column. Clone it directly rather
        // than reconstructing the same polynomials coefficient by coefficient.
        entries.extend(first_column.iter().rev().cloned());
        Ok(Self { entries })
    }
    fn validate_matrix_entries_v1(
        &self,
        dimension: usize,
        degree: usize,
    ) -> Result<(), BootleLanternIssuerPolicyValidationErrorV1> {
        let expected_entries = dimension * dimension;
        if self.entries.len() != expected_entries {
            return Err(
                BootleLanternIssuerPolicyValidationErrorV1::InvalidIssuerMatrixEntryCount {
                    count: u32::try_from(self.entries.len()).map_err(|_| {
                        BootleLanternIssuerPolicyValidationErrorV1::IssuerMatrixEntryCountOverflow
                    })?,
                    expected: u32::try_from(expected_entries)
                        .expect("fixed matrix entry count fits u32"),
                },
            );
        }
        let mut matrix_is_zero = true;
        for (entry_index, polynomial) in self.entries.iter().enumerate() {
            if polynomial.coefficients.len() != degree {
                return Err(
                    BootleLanternIssuerPolicyValidationErrorV1::InvalidPolynomialCoefficientCount {
                        polynomial: u8::try_from(entry_index)
                            .expect("fixed matrix entry index fits u8"),
                        count: u32::try_from(polynomial.coefficients.len()).map_err(|_| {
                            BootleLanternIssuerPolicyValidationErrorV1::
                                PolynomialCoefficientCountOverflow
                        })?,
                        expected: u32::try_from(degree).expect("fixed ring degree fits u32"),
                    },
                );
            }
            for (coefficient_index, coefficient) in
                polynomial.coefficients.iter().copied().enumerate()
            {
                if coefficient >= BOOTLE_LANTERN_APPLICATION_MODULUS_V1 {
                    return Err(
                        BootleLanternIssuerPolicyValidationErrorV1::NonCanonicalMatrixCoefficient {
                            row: u8::try_from(entry_index / dimension)
                                .expect("fixed matrix row fits u8"),
                            column: u8::try_from(entry_index % dimension)
                                .expect("fixed matrix column fits u8"),
                            coefficient: u8::try_from(coefficient_index)
                                .expect("fixed ring coefficient fits u8"),
                            value: coefficient,
                        },
                    );
                }
                matrix_is_zero &= coefficient == 0;
            }
        }
        if matrix_is_zero {
            return Err(BootleLanternIssuerPolicyValidationErrorV1::AllZeroIssuerMatrix);
        }
        Ok(())
    }
    /// Validate the exact degree-512-to-eight-degree-64 negacyclic
    /// multiplication-block structure and conservative public-key density.
    ///
    /// This method validates entry counts, coefficient counts, canonical
    /// residues, and the all-zero sentinel before indexing any matrix entry,
    /// so it is safe to call directly on untrusted decoded values.
    ///
    /// # Errors
    ///
    /// Rejects a non-Toeplitz block, an incorrect negacyclic `Y` shift, or a
    /// public key whose eight first-column blocks are too sparse.
    pub fn validate_r512_multiplication_structure_v1(
        &self,
    ) -> Result<(), BootleLanternIssuerPolicyValidationErrorV1> {
        let dimension = BOOTLE_LANTERN_ISSUER_MATRIX_DIMENSION_V1;
        let degree = BOOTLE_LANTERN_RING_DEGREE_V1;
        self.validate_matrix_entries_v1(dimension, degree)?;
        for row in 0..dimension {
            for column in 0..dimension {
                let actual = &self.entries[row * dimension + column].coefficients;
                let (source_row, shifted) = if row >= column {
                    (row - column, false)
                } else {
                    (row + dimension - column, true)
                };
                let source = &self.entries[source_row * dimension].coefficients;
                for coefficient in 0..degree {
                    let expected = if !shifted {
                        source[coefficient]
                    } else if coefficient == 0 {
                        let final_coefficient = source[degree - 1];
                        if final_coefficient == 0 {
                            0
                        } else {
                            BOOTLE_LANTERN_APPLICATION_MODULUS_V1 - final_coefficient
                        }
                    } else {
                        source[coefficient - 1]
                    };
                    if actual[coefficient] != expected {
                        return Err(
                            BootleLanternIssuerPolicyValidationErrorV1::
                                InvalidR512MultiplicationMatrix {
                                    row: u8::try_from(row).expect("fixed matrix row fits u8"),
                                    column: u8::try_from(column)
                                        .expect("fixed matrix column fits u8"),
                                    coefficient: u8::try_from(coefficient)
                                        .expect("fixed ring coefficient fits u8"),
                                    expected,
                                    actual: actual[coefficient],
                                },
                        );
                    }
                }
            }
        }
        let nonzero_coefficients = (0..dimension)
            .flat_map(|row| &self.entries[row * dimension].coefficients)
            .filter(|coefficient| **coefficient != 0)
            .count();
        if nonzero_coefficients < BOOTLE_LANTERN_ISSUER_PUBLIC_KEY_MIN_NONZERO_COEFFICIENTS_V1 {
            return Err(
                BootleLanternIssuerPolicyValidationErrorV1::SparseIssuerPublicKey {
                    nonzero_coefficients: u16::try_from(nonzero_coefficients)
                        .expect("degree-512 nonzero count fits u16"),
                    minimum: u16::try_from(
                        BOOTLE_LANTERN_ISSUER_PUBLIC_KEY_MIN_NONZERO_COEFFICIENTS_V1,
                    )
                    .expect("fixed density floor fits u16"),
                },
            );
        }
        Ok(())
    }
}
/// Governed allowed values for one required public attribute.
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
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::privacy::BootleLanternAllowedAttributeValuesV1")]
pub struct BootleLanternAllowedAttributeValuesV1 {
    /// Strictly increasing values; empty means any disclosed value is allowed.
    pub values: Vec<BootleLanternAttributeValueV1>,
}
/// Forward-only lifecycle of one authoritative Bootle/Lantern issuer policy.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(tag = "state", content = "value", deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::privacy::BootleLanternIssuerPolicyLifecycleV1")]
pub enum BootleLanternIssuerPolicyLifecycleV1 {
    /// Presentations selecting the exact current record may be admitted.
    #[norito(rename = "active")]
    Active,
    /// Terminal state; the lineage cannot be rotated or reactivated.
    #[norito(rename = "revoked")]
    Revoked,
}
/// Committed issuer key and selective-disclosure policy trusted by verification.
///
/// The proof submitter supplies only the record identity and digest in the
/// statement. Core resolves this complete record from committed state.
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
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::privacy::BootleLanternIssuerPolicyV1")]
pub struct BootleLanternIssuerPolicyV1 {
    /// Credential issuer governed by this record.
    pub issuer_id: PrivacyIssuerIdV1,
    /// Stable policy identity within the issuer namespace.
    pub policy_id: PrivacyPolicyIdV1,
    /// Monotonically increasing policy/key epoch.
    pub epoch: u64,
    /// Forward-only active or terminal-revoked lifecycle.
    pub lifecycle: BootleLanternIssuerPolicyLifecycleV1,
    /// Exact issuer parameter artifact identity.
    pub issuer_parameter_id: PrivacyParameterIdV1,
    /// Digest of the exact issuer parameter artifact.
    pub issuer_parameter_digest: PrivacyParameterDigestV1,
    /// Canonical issuer verification matrix `B`.
    pub issuer_public_matrix: BootleLanternIssuerPublicMatrixV1,
    /// Bitmap of attributes that every presentation must disclose.
    pub required_disclosure_bitmap: u8,
    /// Per-attribute allowed public values in fixed attribute order.
    pub allowed_values: Vec<BootleLanternAllowedAttributeValuesV1>,
    /// Digest of this record with this field normalized to zero.
    pub record_digest: PrivacyBootleLanternIssuerPolicyDigestV1,
}
impl BootleLanternIssuerPolicyV1 {
    /// Compute the exact digest of the issuer verification matrix selected by
    /// `issuer_parameter_id`.
    ///
    /// # Errors
    ///
    /// Returns a Norito error if canonical encoding of the matrix unexpectedly fails.
    pub fn computed_issuer_parameter_digest(
        &self,
    ) -> Result<PrivacyParameterDigestV1, norito::Error> {
        let encoded = norito::encode_canonical(&self.issuer_public_matrix)?;
        let mut hasher = Sha256::new();
        hasher.update(BOOTLE_LANTERN_ISSUER_PARAMETER_DIGEST_DOMAIN_V1);
        hasher.update(self.issuer_parameter_id.as_bytes());
        hasher.update(
            u64::try_from(encoded.len())
                .expect("Norito output length fits u64 on supported targets")
                .to_le_bytes(),
        );
        hasher.update(encoded);
        Ok(PrivacyParameterDigestV1::new(hasher.finalize().into()))
    }
    /// Compute the canonical record digest with `record_digest` normalized to zero.
    ///
    /// # Errors
    ///
    /// Returns a Norito error if canonical encoding of the normalized record unexpectedly fails.
    pub fn computed_record_digest(
        &self,
    ) -> Result<PrivacyBootleLanternIssuerPolicyDigestV1, norito::Error> {
        let mut normalized = self.clone();
        normalized.record_digest = PrivacyBootleLanternIssuerPolicyDigestV1::new([0; 32]);
        let encoded = norito::encode_canonical(&normalized)?;
        let mut hasher = Sha256::new();
        hasher.update(BOOTLE_LANTERN_ISSUER_POLICY_DIGEST_DOMAIN_V1);
        hasher.update(
            u64::try_from(encoded.len())
                .expect("Norito output length fits u64 on supported targets")
                .to_le_bytes(),
        );
        hasher.update(encoded);
        Ok(PrivacyBootleLanternIssuerPolicyDigestV1::new(
            hasher.finalize().into(),
        ))
    }
    /// Validate canonical issuer key, disclosure rules, and self-authenticating digest.
    ///
    /// This intrinsic check does not make the record trusted. Core must resolve it from committed
    /// state and separately match its issuer parameter artifact before native verification.
    ///
    /// # Errors
    ///
    /// Returns the first deterministic structural or digest failure.
    pub fn validate(&self) -> Result<(), BootleLanternIssuerPolicyValidationErrorV1> {
        self.validate_identity()?;
        self.validate_issuer_public_matrix()?;
        self.validate_allowed_values()?;
        self.validate_record_digest()
    }
    fn validate_identity(&self) -> Result<(), BootleLanternIssuerPolicyValidationErrorV1> {
        if self.issuer_id.is_zero() {
            return Err(BootleLanternIssuerPolicyValidationErrorV1::ZeroIssuerId);
        }
        if self.policy_id.is_zero() {
            return Err(BootleLanternIssuerPolicyValidationErrorV1::ZeroPolicyId);
        }
        if self.epoch == 0 {
            return Err(BootleLanternIssuerPolicyValidationErrorV1::ZeroEpoch);
        }
        if self.issuer_parameter_id.is_zero() {
            return Err(BootleLanternIssuerPolicyValidationErrorV1::ZeroIssuerParameterId);
        }
        if self.issuer_parameter_digest.is_zero() {
            return Err(BootleLanternIssuerPolicyValidationErrorV1::ZeroIssuerParameterDigest);
        }
        Ok(())
    }
    fn validate_issuer_public_matrix(
        &self,
    ) -> Result<(), BootleLanternIssuerPolicyValidationErrorV1> {
        self.issuer_public_matrix
            .validate_r512_multiplication_structure_v1()?;
        let expected_issuer_parameter_digest =
            self.computed_issuer_parameter_digest().map_err(|_| {
                BootleLanternIssuerPolicyValidationErrorV1::IssuerParameterEncodingFailure
            })?;
        if self.issuer_parameter_digest != expected_issuer_parameter_digest {
            return Err(BootleLanternIssuerPolicyValidationErrorV1::IssuerParameterDigestMismatch);
        }
        Ok(())
    }
    fn validate_allowed_values(&self) -> Result<(), BootleLanternIssuerPolicyValidationErrorV1> {
        if self.allowed_values.len() != BOOTLE_LANTERN_ATTRIBUTE_COUNT_V1 {
            return Err(
                BootleLanternIssuerPolicyValidationErrorV1::InvalidAllowedValueRuleCount {
                    count: u32::try_from(self.allowed_values.len()).map_err(|_| {
                        BootleLanternIssuerPolicyValidationErrorV1::AllowedValueRuleCountOverflow
                    })?,
                    expected: u32::try_from(BOOTLE_LANTERN_ATTRIBUTE_COUNT_V1)
                        .expect("fixed attribute count fits u32"),
                },
            );
        }
        for (index, allowed) in self.allowed_values.iter().enumerate() {
            let count = u32::try_from(allowed.values.len()).map_err(|_| {
                BootleLanternIssuerPolicyValidationErrorV1::AllowedValueCountOverflow
            })?;
            if count > BOOTLE_LANTERN_MAX_ALLOWED_VALUES_PER_ATTRIBUTE_V1 {
                return Err(
                    BootleLanternIssuerPolicyValidationErrorV1::TooManyAllowedValues {
                        index: u8::try_from(index).expect("fixed attribute index fits u8"),
                        count,
                        max: BOOTLE_LANTERN_MAX_ALLOWED_VALUES_PER_ATTRIBUTE_V1,
                    },
                );
            }
            let required = self.required_disclosure_bitmap & (1_u8 << index) != 0;
            if !required && !allowed.values.is_empty() {
                return Err(
                    BootleLanternIssuerPolicyValidationErrorV1::AllowedValuesForOptionalAttribute {
                        index: u8::try_from(index).expect("fixed attribute index fits u8"),
                    },
                );
            }
            if allowed.values.windows(2).any(|pair| pair[0] >= pair[1]) {
                return Err(
                    BootleLanternIssuerPolicyValidationErrorV1::
                        AllowedValuesNotStrictlyIncreasing {
                            index: u8::try_from(index).expect("fixed attribute index fits u8"),
                        },
                );
            }
        }
        Ok(())
    }
    fn validate_record_digest(&self) -> Result<(), BootleLanternIssuerPolicyValidationErrorV1> {
        if self.record_digest.is_zero() {
            return Err(BootleLanternIssuerPolicyValidationErrorV1::ZeroRecordDigest);
        }
        let expected = self
            .computed_record_digest()
            .map_err(|_| BootleLanternIssuerPolicyValidationErrorV1::EncodingFailure)?;
        if self.record_digest != expected {
            return Err(BootleLanternIssuerPolicyValidationErrorV1::RecordDigestMismatch);
        }
        Ok(())
    }
    /// Validate a first record for a newly created issuer-policy key.
    ///
    /// # Errors
    ///
    /// Returns an intrinsic record failure or rejects any initial epoch other than one.
    pub fn validate_initial(&self) -> Result<(), BootleLanternIssuerPolicyValidationErrorV1> {
        self.validate()?;
        if self.epoch != 1 {
            return Err(
                BootleLanternIssuerPolicyValidationErrorV1::InvalidInitialEpoch {
                    epoch: self.epoch,
                },
            );
        }
        if self.lifecycle != BootleLanternIssuerPolicyLifecycleV1::Active {
            return Err(BootleLanternIssuerPolicyValidationErrorV1::InitialPolicyMustBeActive);
        }
        Ok(())
    }
    /// Validate an atomic replacement of one committed issuer-policy record.
    ///
    /// # Errors
    ///
    /// Rejects namespace changes, a non-increasing epoch, an unchanged
    /// rotation, or any intrinsically invalid successor.
    pub fn validate_successor(
        &self,
        previous: &Self,
    ) -> Result<(), BootleLanternIssuerPolicyValidationErrorV1> {
        previous.validate()?;
        self.validate()?;
        if previous.lifecycle == BootleLanternIssuerPolicyLifecycleV1::Revoked {
            return Err(BootleLanternIssuerPolicyValidationErrorV1::PolicyAlreadyRevoked);
        }
        if self.issuer_id != previous.issuer_id {
            return Err(BootleLanternIssuerPolicyValidationErrorV1::IssuerIdChanged);
        }
        if self.policy_id != previous.policy_id {
            return Err(BootleLanternIssuerPolicyValidationErrorV1::PolicyIdChanged);
        }
        let expected_epoch = previous
            .epoch
            .checked_add(1)
            .ok_or(BootleLanternIssuerPolicyValidationErrorV1::PolicyEpochOverflow)?;
        if self.epoch != expected_epoch {
            return Err(
                BootleLanternIssuerPolicyValidationErrorV1::NonConsecutiveEpoch {
                    previous: previous.epoch,
                    next: self.epoch,
                    expected: expected_epoch,
                },
            );
        }
        if self.issuer_parameter_id == previous.issuer_parameter_id
            && self.issuer_parameter_digest == previous.issuer_parameter_digest
            && self.issuer_public_matrix == previous.issuer_public_matrix
            && self.required_disclosure_bitmap == previous.required_disclosure_bitmap
            && self.allowed_values == previous.allowed_values
            && self.lifecycle == previous.lifecycle
        {
            return Err(BootleLanternIssuerPolicyValidationErrorV1::UnchangedRotation);
        }
        Ok(())
    }
    /// Validate an active-to-active exact successor.
    ///
    /// # Errors
    ///
    /// Returns the first generic successor failure or rejects a successor that
    /// does not remain active.
    pub fn validate_rotation_successor(
        &self,
        previous: &Self,
    ) -> Result<(), BootleLanternIssuerPolicyValidationErrorV1> {
        self.validate_successor(previous)?;
        if self.lifecycle != BootleLanternIssuerPolicyLifecycleV1::Active {
            return Err(BootleLanternIssuerPolicyValidationErrorV1::RotationMustRemainActive);
        }
        Ok(())
    }
    /// Validate an active-to-terminal-revoked exact successor.
    ///
    /// # Errors
    ///
    /// Returns the first generic successor failure or rejects a successor that
    /// is not terminal-revoked.
    pub fn validate_revocation_successor(
        &self,
        previous: &Self,
    ) -> Result<(), BootleLanternIssuerPolicyValidationErrorV1> {
        self.validate_successor(previous)?;
        if self.lifecycle != BootleLanternIssuerPolicyLifecycleV1::Revoked {
            return Err(BootleLanternIssuerPolicyValidationErrorV1::RevocationMustBeRevoked);
        }
        if self.issuer_parameter_id != previous.issuer_parameter_id
            || self.issuer_parameter_digest != previous.issuer_parameter_digest
            || self.issuer_public_matrix != previous.issuer_public_matrix
            || self.required_disclosure_bitmap != previous.required_disclosure_bitmap
            || self.allowed_values != previous.allowed_values
        {
            return Err(BootleLanternIssuerPolicyValidationErrorV1::RevocationMustPreservePolicy);
        }
        Ok(())
    }
}
/// Structural failure for a committed Bootle/Lantern issuer-policy record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum BootleLanternIssuerPolicyValidationErrorV1 {
    /// Issuer identifier is zero.
    #[error("Bootle/Lantern issuer id must be non-zero")]
    ZeroIssuerId,
    /// Policy identifier is zero.
    #[error("Bootle/Lantern policy id must be non-zero")]
    ZeroPolicyId,
    /// Record epoch is zero.
    #[error("Bootle/Lantern issuer-policy epoch must be non-zero")]
    ZeroEpoch,
    /// Issuer parameter identifier is zero.
    #[error("Bootle/Lantern issuer parameter id must be non-zero")]
    ZeroIssuerParameterId,
    /// Issuer parameter digest is zero.
    #[error("Bootle/Lantern issuer parameter digest must be non-zero")]
    ZeroIssuerParameterDigest,
    /// Matrix entry count overflowed its canonical diagnostic.
    #[error("Bootle/Lantern issuer matrix entry count overflow")]
    IssuerMatrixEntryCountOverflow,
    /// Matrix does not contain exactly 64 row-major polynomials.
    #[error("Bootle/Lantern issuer matrix has {count} entries; expected {expected}")]
    InvalidIssuerMatrixEntryCount {
        /// Observed entry count.
        count: u32,
        /// Fixed entry count.
        expected: u32,
    },
    /// Polynomial coefficient count overflowed its canonical diagnostic.
    #[error("Bootle/Lantern polynomial coefficient count overflow")]
    PolynomialCoefficientCountOverflow,
    /// One matrix polynomial does not contain exactly 64 coefficients.
    #[error(
        "Bootle/Lantern issuer matrix polynomial {polynomial} has {count} coefficients; expected {expected}"
    )]
    InvalidPolynomialCoefficientCount {
        /// Row-major matrix-polynomial index.
        polynomial: u8,
        /// Observed coefficient count.
        count: u32,
        /// Fixed coefficient count.
        expected: u32,
    },
    /// One issuer matrix coefficient is not a canonical residue.
    #[error(
        "Bootle/Lantern issuer matrix coefficient B[{row}][{column}][{coefficient}]={value} is not below 12289"
    )]
    NonCanonicalMatrixCoefficient {
        /// Matrix row.
        row: u8,
        /// Matrix column.
        column: u8,
        /// Polynomial coefficient.
        coefficient: u8,
        /// Rejected residue.
        value: u16,
    },
    /// Issuer matrix is the all-zero sentinel.
    #[error("Bootle/Lantern issuer matrix must not be all zero")]
    AllZeroIssuerMatrix,
    /// One block or coefficient does not match the canonical degree-512
    /// Falcon/NTRU multiplication-matrix embedding.
    #[error(
        "Bootle/Lantern issuer matrix B[{row}][{column}][{coefficient}]={actual} does not match canonical R512 multiplication coefficient {expected}"
    )]
    InvalidR512MultiplicationMatrix {
        /// Matrix row.
        row: u8,
        /// Matrix column.
        column: u8,
        /// Polynomial coefficient.
        coefficient: u8,
        /// Canonical coefficient derived from the first-column public key.
        expected: u16,
        /// Observed substituted coefficient.
        actual: u16,
    },
    /// The reconstructed degree-512 public key is too sparse to be a genuine
    /// first-release Falcon/NTRU issuer key.
    #[error(
        "Bootle/Lantern issuer public key has {nonzero_coefficients} non-zero coefficients; minimum is {minimum}"
    )]
    SparseIssuerPublicKey {
        /// Non-zero coefficients across the eight first-column blocks.
        nonzero_coefficients: u16,
        /// Conservative first-release density floor.
        minimum: u16,
    },
    /// Canonical encoding of the issuer verification matrix failed.
    #[error("Bootle/Lantern issuer parameter encoding failed")]
    IssuerParameterEncodingFailure,
    /// The declared issuer parameter digest does not authenticate the matrix.
    #[error("Bootle/Lantern issuer parameter digest does not match the verification matrix")]
    IssuerParameterDigestMismatch,
    /// An allowed-value vector length overflowed its canonical count.
    #[error("Bootle/Lantern allowed-value count overflow")]
    AllowedValueCountOverflow,
    /// Attribute-rule vector length overflowed its canonical diagnostic.
    #[error("Bootle/Lantern allowed-value rule count overflow")]
    AllowedValueRuleCountOverflow,
    /// Policy does not contain exactly eight attribute-rule entries.
    #[error("Bootle/Lantern policy has {count} attribute rules; expected {expected}")]
    InvalidAllowedValueRuleCount {
        /// Observed rule count.
        count: u32,
        /// Fixed rule count.
        expected: u32,
    },
    /// One attribute allows too many governed public values.
    #[error("Bootle/Lantern attribute {index} has {count} allowed values, exceeding maximum {max}")]
    TooManyAllowedValues {
        /// Attribute index.
        index: u8,
        /// Observed value count.
        count: u32,
        /// Fixed maximum.
        max: u32,
    },
    /// A non-required attribute carries an unenforceable allowed-value policy.
    #[error("Bootle/Lantern optional attribute {index} must not carry allowed values")]
    AllowedValuesForOptionalAttribute {
        /// Attribute index.
        index: u8,
    },
    /// Allowed values contain a duplicate or are out of order.
    #[error("Bootle/Lantern attribute {index} allowed values must be strictly increasing")]
    AllowedValuesNotStrictlyIncreasing {
        /// Attribute index.
        index: u8,
    },
    /// Record digest is zero.
    #[error("Bootle/Lantern issuer-policy record digest must be non-zero")]
    ZeroRecordDigest,
    /// Canonical normalized record encoding failed.
    #[error("Bootle/Lantern issuer-policy record encoding failed")]
    EncodingFailure,
    /// Record digest does not match the canonical record contents.
    #[error("Bootle/Lantern issuer-policy record digest mismatch")]
    RecordDigestMismatch,
    /// A newly created issuer-policy key did not start at epoch one.
    #[error("Bootle/Lantern initial issuer-policy epoch {epoch} must equal one")]
    InvalidInitialEpoch {
        /// Rejected initial epoch.
        epoch: u64,
    },
    /// A newly registered lineage was not active.
    #[error("Bootle/Lantern initial issuer policy must be active")]
    InitialPolicyMustBeActive,
    /// A terminal-revoked lineage was used as a successor parent.
    #[error("Bootle/Lantern issuer policy is already terminal-revoked")]
    PolicyAlreadyRevoked,
    /// The current epoch cannot be advanced.
    #[error("Bootle/Lantern issuer-policy epoch overflow")]
    PolicyEpochOverflow,
    /// A rotation changed the issuer namespace.
    #[error("Bootle/Lantern issuer-policy rotation must not change issuer id")]
    IssuerIdChanged,
    /// A rotation changed the policy namespace.
    #[error("Bootle/Lantern issuer-policy rotation must not change policy id")]
    PolicyIdChanged,
    /// A replacement epoch was not exactly the next epoch.
    #[error(
        "Bootle/Lantern issuer-policy epoch must advance exactly once: previous {previous}, next {next}, expected {expected}"
    )]
    NonConsecutiveEpoch {
        /// Current committed epoch.
        previous: u64,
        /// Proposed successor epoch.
        next: u64,
        /// Only accepted successor epoch.
        expected: u64,
    },
    /// A replacement changed only epoch and digest.
    #[error("Bootle/Lantern issuer-policy rotation must change key, parameters, or policy rules")]
    UnchangedRotation,
    /// A rotation attempted to revoke the lineage.
    #[error("Bootle/Lantern issuer-policy rotation successor must remain active")]
    RotationMustRemainActive,
    /// A revocation failed to enter the terminal state.
    #[error("Bootle/Lantern issuer-policy revocation successor must be revoked")]
    RevocationMustBeRevoked,
    /// A revocation attempted to rotate key material or disclosure rules.
    #[error("Bootle/Lantern issuer-policy revocation must preserve key material and policy rules")]
    RevocationMustPreservePolicy,
}
/// One canonical Bootle/Lantern selective-disclosure entry.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::privacy::BootleLanternDisclosedAttributeV1")]
pub struct BootleLanternDisclosedAttributeV1 {
    /// Zero-based index in the fixed eight-attribute credential.
    pub index: u8,
    /// Direct public 64-bit attribute value.
    pub value: BootleLanternAttributeValueV1,
}
/// Native Bootle Lantern/LNP22 module-lattice anonymous-credential statement.
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
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::privacy::IrohaBootleLanternAnoncredStatementV1")]
pub struct IrohaBootleLanternAnoncredStatementV1 {
    /// Shared chain and governed-artifact binding.
    pub context: PrivacyStatementContextV1,
    /// Anonymous-credential issuer identifier.
    pub issuer_id: PrivacyIssuerIdV1,
    /// Selective-disclosure policy identifier.
    pub policy_id: PrivacyPolicyIdV1,
    /// Exact current committed issuer-policy epoch.
    pub issuer_policy_epoch: u64,
    /// Digest of the complete committed issuer-policy record.
    pub issuer_policy_record_digest: PrivacyBootleLanternIssuerPolicyDigestV1,
    /// Exact issuer parameter-set identifier.
    pub issuer_parameter_id: PrivacyParameterIdV1,
    /// Digest of the issuer parameter set.
    pub issuer_parameter_digest: PrivacyParameterDigestV1,
    /// Strictly increasing direct selectively disclosed attributes.
    pub disclosures: Vec<BootleLanternDisclosedAttributeV1>,
}
/// Direction of a public value balance relative to a private pool.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(tag = "direction", content = "value", deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::privacy::PrivacyValueBalanceDirectionV1")]
pub enum PrivacyValueBalanceDirectionV1 {
    /// No public value enters or leaves the pool.
    Balanced,
    /// Public value enters the private pool.
    IntoPool,
    /// Private value leaves the pool.
    OutOfPool,
}
/// Signed public value balance represented without JSON-ambiguous `i128`.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::privacy::PrivacyValueBalanceV1")]
pub struct PrivacyValueBalanceV1 {
    /// Direction relative to the private pool.
    pub direction: PrivacyValueBalanceDirectionV1,
    /// Absolute atomic amount.
    pub amount: u128,
}
impl PrivacyValueBalanceV1 {
    /// Construct a zero public value balance.
    #[must_use]
    pub const fn balanced() -> Self {
        Self {
            direction: PrivacyValueBalanceDirectionV1::Balanced,
            amount: 0,
        }
    }
    /// Validate direction and magnitude consistency.
    ///
    /// # Errors
    ///
    /// Returns [`PrivacyStatementValidationError::InvalidValueBalance`] when a
    /// balanced value is non-zero or a directional value is zero.
    pub fn validate(&self) -> Result<(), PrivacyStatementValidationError> {
        let valid = match self.direction {
            PrivacyValueBalanceDirectionV1::Balanced => self.amount == 0,
            PrivacyValueBalanceDirectionV1::IntoPool
            | PrivacyValueBalanceDirectionV1::OutOfPool => self.amount != 0,
        };
        if !valid {
            return Err(PrivacyStatementValidationError::InvalidValueBalance {
                direction: self.direction,
                amount: self.amount,
            });
        }
        Ok(())
    }
}
/// Exact public data for one Orchard V3 action.
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
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::privacy::PrivacyOrchardActionV1")]
pub struct PrivacyOrchardActionV1 {
    /// Canonical Pallas-base nullifier encoding.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub nullifier: [u8; 32],
    /// Canonical non-identity randomized `RedPallas` verification key.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub randomized_key: [u8; 32],
    /// Canonical extracted note commitment.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub note_commitment: [u8; 32],
    /// Canonical non-identity ephemeral Pallas public key.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub ephemeral_key: [u8; 32],
    /// Exact 580-byte Orchard encrypted-note ciphertext.
    #[norito(json = "crate::json_helpers::base64_vec")]
    pub encrypted_note: Vec<u8>,
    /// Exact 80-byte Orchard outgoing ciphertext.
    #[norito(json = "crate::json_helpers::base64_vec")]
    pub outgoing_ciphertext: Vec<u8>,
    /// Canonical Pallas value commitment.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub value_commitment: [u8; 32],
}
/// Orchard Halo2 private action-bundle statement.
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
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::privacy::OrchardHalo2ActionsStatementV1")]
pub struct OrchardHalo2ActionsStatementV1 {
    /// Shared chain and governed-artifact binding.
    pub context: PrivacyStatementContextV1,
    /// Asset represented by the Orchard action.
    pub asset_definition_id: AssetDefinitionId,
    /// Exact transparent reserve partition used by directional value bridges.
    pub public_balance_scope: AssetBalanceScope,
    /// Orchard pool namespace.
    pub pool_id: PrivacyPoolIdV1,
    /// Admitted note-commitment tree anchor.
    pub anchor: PrivacyRootV1,
    /// Epoch at which `anchor` was canonical.
    pub anchor_epoch: u64,
    /// Non-empty ordered Orchard actions.
    ///
    /// The node derives the successor frontier and root by appending these
    /// note commitments to its authoritative pool frontier. A caller-selected
    /// successor root is intentionally unrepresentable.
    pub actions: Vec<PrivacyOrchardActionV1>,
    /// Public value balance in atomic units.
    pub value_balance: PrivacyValueBalanceV1,
    /// Last block height at which the action is valid.
    pub expiry_height: u64,
}
/// Monero FCMP++ full-chain-membership transfer statement.
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
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::privacy::MoneroFcmpPlusPlusStatementV1")]
pub struct MoneroFcmpPlusPlusStatementV1 {
    /// Shared chain and governed-artifact binding.
    pub context: PrivacyStatementContextV1,
    /// Asset transferred by the private action.
    pub asset_definition_id: AssetDefinitionId,
    /// FCMP++ output-set namespace.
    pub pool_id: PrivacyPoolIdV1,
    /// Canonical typed full-output-set root.
    pub output_set_root: PrivacyFcmpTreeRootV1,
    /// Epoch at which the output-set root was canonical.
    pub root_epoch: u64,
    /// Complete public inputs for each hidden consumed output.
    pub inputs: Vec<PrivacyFcmpInputPublicV1>,
    /// Complete new output tuples in canonical append order.
    ///
    /// Validators derive the successor typed root and epoch from these tuples and the authoritative
    /// mixed-radix frontier. A caller-selected successor is intentionally unrepresentable.
    pub outputs: Vec<PrivacyFcmpOutputTupleV1>,
    /// Encrypted new outputs, aligned one-to-one with `outputs`.
    pub encrypted_outputs: Vec<PrivacyFcmpEncryptedOutputV1>,
}
/// Native IVM private-note execution statement.
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
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::privacy::IrohaIvmPrivateNoteStarkStatementV1")]
pub struct IrohaIvmPrivateNoteStarkStatementV1 {
    /// Shared chain and governed-artifact binding.
    pub context: PrivacyStatementContextV1,
    /// Asset manipulated by the private program.
    pub asset_definition_id: AssetDefinitionId,
    /// Exact transparent reserve partition used by directional value bridges.
    pub public_balance_scope: AssetBalanceScope,
    /// Private-note pool namespace.
    pub pool_id: PrivacyPoolIdV1,
    /// Exact private IVM program identifier.
    pub program_id: PrivacyProgramIdV1,
    /// Digest of the exact canonical private-program action and public inputs.
    pub action_digest: PrivacyActionDigestV1,
    /// Canonical private-note state root.
    pub state_root: PrivacyRootV1,
    /// Epoch at which `state_root` was canonical.
    pub root_epoch: u64,
    /// Consumed note nullifiers.
    pub nullifiers: Vec<PrivacyNullifierV1>,
    /// New note commitments in canonical append order.
    ///
    /// Validators derive the successor program-state root and epoch from these
    /// commitments and the authoritative compact frontier. A caller-selected
    /// successor is intentionally unrepresentable.
    pub output_commitments: Vec<PrivacyCommitmentV1>,
    /// Encrypted new notes, in commitment order.
    pub encrypted_outputs: Vec<PrivacyEncryptedOutputV1>,
    /// Public value balance in atomic units.
    pub value_balance: PrivacyValueBalanceV1,
    /// Ledger epoch bound into private program execution.
    pub execution_epoch: u64,
}
impl IrohaIvmPrivateNoteStarkStatementV1 {
    /// Compute the action digest with its self-authenticating field normalized to zero.
    ///
    /// # Errors
    ///
    /// Returns a Norito error if canonical statement encoding unexpectedly fails.
    pub fn computed_action_digest(&self) -> Result<PrivacyActionDigestV1, norito::Error> {
        let mut normalized = self.clone();
        normalized.action_digest = PrivacyActionDigestV1::new([0; 32]);
        let encoded = norito::encode_canonical(&normalized)?;
        let mut hasher = Sha256::new();
        hasher.update(IVM_PRIVATE_NOTE_ACTION_DIGEST_DOMAIN_V1);
        hasher.update(
            u64::try_from(encoded.len())
                .expect("Norito output length fits u64 on supported targets")
                .to_le_bytes(),
        );
        hasher.update(encoded);
        Ok(PrivacyActionDigestV1::new(hasher.finalize().into()))
    }
}
/// Post-quantum authorization profile required by PQ-MASP V1.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(tag = "authorization", content = "value", deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::privacy::PrivacyPqAuthorizationProfileV1")]
pub enum PrivacyPqAuthorizationProfileV1 {
    /// ML-DSA-65 transaction authorization.
    MlDsa65,
}
/// Post-quantum note-encryption profile required by PQ-MASP V1.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(tag = "encryption", content = "value", deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::privacy::PrivacyPqNoteEncryptionProfileV1")]
pub enum PrivacyPqNoteEncryptionProfileV1 {
    /// ML-KEM-768 key establishment with XChaCha20-Poly1305 payload encryption.
    MlKem768XChaCha20Poly1305,
}
/// Post-quantum MASP STARK transfer statement.
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
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::privacy::PqMaspStarkStatementV1")]
pub struct PqMaspStarkStatementV1 {
    /// Shared chain and governed-artifact binding.
    pub context: PrivacyStatementContextV1,
    /// Asset transferred by the private action.
    pub asset_definition_id: AssetDefinitionId,
    /// PQ-MASP pool namespace.
    pub pool_id: PrivacyPoolIdV1,
    /// Admitted note-commitment tree anchor.
    pub anchor: PrivacyRootV1,
    /// Epoch at which `anchor` was canonical.
    pub anchor_epoch: u64,
    /// Consumed-note nullifiers.
    pub nullifiers: Vec<PrivacyNullifierV1>,
    /// New note commitments in canonical append order.
    ///
    /// Validators derive the successor anchor and epoch from these
    /// commitments and the authoritative compact frontier. A caller-selected
    /// successor is intentionally unrepresentable.
    pub output_commitments: Vec<PrivacyCommitmentV1>,
    /// ML-KEM-derived encrypted output notes, in commitment order.
    pub encrypted_outputs: Vec<PrivacyEncryptedOutputV1>,
    /// Required transaction-authorization profile.
    pub authorization_profile: PrivacyPqAuthorizationProfileV1,
    /// Digest of the authorized ML-DSA key.
    pub authorization_key_digest: PrivacyAuthorizationKeyDigestV1,
    /// Required note-encryption profile.
    pub note_encryption_profile: PrivacyPqNoteEncryptionProfileV1,
    /// Digest of the ordered `(recipient key, ML-KEM encapsulation)` pairs for
    /// every encrypted output.
    pub note_encryption_key_digest: PrivacyNoteEncryptionKeyDigestV1,
    /// Ledger epoch bound into authorization.
    pub authorization_epoch: u64,
}
/// Protocol-typed canonical privacy statement.
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
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(tag = "protocol", content = "statement", deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::privacy::PrivacyStatementV1",
    frame = "iroha.privacy.statement.v1"
)]
pub enum PrivacyStatementV1 {
    /// ZK-ACE post-quantum authorization statement.
    ZkAcePqAuthorizationV1(ZkAcePqAuthorizationStatementV1),
    /// Anonymous PGC k-out-of-n payment statement.
    AnonymousPgcKOutOfNV1(AnonymousPgcKOutOfNStatementV1),
    /// `VeRange` transparent range statement.
    VeRangeTransparentRangeV1(VeRangeTransparentRangeStatementV1),
    /// Native Iroha ZK-AMS admission/provisioning statement.
    IrohaZkAmsV1(IrohaZkAmsStatementV1),
    /// Vega existing-credential predicate statement.
    VegaExistingCredentialZkV1(VegaExistingCredentialStatementV1),
    /// Native Iroha P-256 X.509 predicate STARK statement.
    IrohaZkX509StarkP256V1(IrohaZkX509StarkP256StatementV1),
    /// Native Iroha Jindo batched univariate lattice polynomial-commitment statement.
    IrohaJindoPolynomialCommitmentV1(IrohaJindoPolynomialCommitmentStatementV1),
    /// Native Bootle Lantern/LNP22 anonymous-credential statement.
    IrohaBootleLanternAnoncredV1(IrohaBootleLanternAnoncredStatementV1),
    /// Orchard Halo2 action statement.
    OrchardHalo2ActionsV1(OrchardHalo2ActionsStatementV1),
    /// Monero FCMP++ membership statement.
    MoneroFcmpPlusPlusV1(MoneroFcmpPlusPlusStatementV1),
    /// Native IVM private-note STARK statement.
    IrohaIvmPrivateNoteStarkV1(IrohaIvmPrivateNoteStarkStatementV1),
    /// Post-quantum MASP STARK statement.
    PqMaspStarkV1(PqMaspStarkStatementV1),
}
impl PrivacyStatementV1 {
    /// Exact protocol carried by this statement variant.
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
    /// Borrow the explicit shared context inside this protocol statement.
    #[must_use]
    pub const fn context(&self) -> &PrivacyStatementContextV1 {
        match self {
            Self::ZkAcePqAuthorizationV1(statement) => &statement.context,
            Self::AnonymousPgcKOutOfNV1(statement) => &statement.context,
            Self::VeRangeTransparentRangeV1(statement) => &statement.context,
            Self::IrohaZkAmsV1(statement) => &statement.context,
            Self::VegaExistingCredentialZkV1(statement) => &statement.context,
            Self::IrohaZkX509StarkP256V1(statement) => &statement.context,
            Self::IrohaJindoPolynomialCommitmentV1(statement) => &statement.context,
            Self::IrohaBootleLanternAnoncredV1(statement) => &statement.context,
            Self::OrchardHalo2ActionsV1(statement) => &statement.context,
            Self::MoneroFcmpPlusPlusV1(statement) => &statement.context,
            Self::IrohaIvmPrivateNoteStarkV1(statement) => &statement.context,
            Self::PqMaspStarkV1(statement) => &statement.context,
        }
    }
    /// Mutably borrow the explicit shared context inside this protocol statement.
    ///
    /// Transaction-intent normalization uses this single exhaustive boundary
    /// instead of duplicating protocol-specific statement matches.
    #[must_use]
    pub const fn context_mut(&mut self) -> &mut PrivacyStatementContextV1 {
        match self {
            Self::ZkAcePqAuthorizationV1(statement) => &mut statement.context,
            Self::AnonymousPgcKOutOfNV1(statement) => &mut statement.context,
            Self::VeRangeTransparentRangeV1(statement) => &mut statement.context,
            Self::IrohaZkAmsV1(statement) => &mut statement.context,
            Self::VegaExistingCredentialZkV1(statement) => &mut statement.context,
            Self::IrohaZkX509StarkP256V1(statement) => &mut statement.context,
            Self::IrohaJindoPolynomialCommitmentV1(statement) => &mut statement.context,
            Self::IrohaBootleLanternAnoncredV1(statement) => &mut statement.context,
            Self::OrchardHalo2ActionsV1(statement) => &mut statement.context,
            Self::MoneroFcmpPlusPlusV1(statement) => &mut statement.context,
            Self::IrohaIvmPrivateNoteStarkV1(statement) => &mut statement.context,
            Self::PqMaspStarkV1(statement) => &mut statement.context,
        }
    }
    /// Hash this complete protocol-tagged statement using canonical Norito bytes.
    ///
    /// # Errors
    ///
    /// Returns a Norito encoding error if canonical statement encoding fails.
    pub fn digest(&self) -> Result<PrivacyStatementDigestV1, norito::Error> {
        let encoded = norito::encode_canonical(self)?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(PRIVACY_STATEMENT_DIGEST_DOMAIN_V1);
        hasher.update(
            &u64::try_from(encoded.len())
                .expect("Norito output length always fits u64 on supported targets")
                .to_le_bytes(),
        );
        hasher.update(&encoded);
        Ok(PrivacyStatementDigestV1::new(*hasher.finalize().as_bytes()))
    }
    /// Validate the exact protocol statement and consensus resource bounds.
    ///
    /// # Errors
    ///
    /// Returns [`PrivacyStatementValidationError`] for any invalid explicit
    /// field, count, epoch, state item, encrypted output, scalar, or bound.
    pub fn validate(
        &self,
        limits: &PrivacyConsensusLimitsV1,
    ) -> Result<(), PrivacyStatementValidationError> {
        limits
            .validate()
            .map_err(PrivacyStatementValidationError::InvalidLimits)?;
        self.context().validate(limits)?;
        match self {
            Self::ZkAcePqAuthorizationV1(statement) => validate_zk_ace(statement)?,
            Self::AnonymousPgcKOutOfNV1(statement) => validate_anonymous_pgc(statement, limits)?,
            Self::VeRangeTransparentRangeV1(statement) => validate_verange(statement, limits)?,
            Self::IrohaZkAmsV1(statement) => validate_zk_ams(statement)?,
            Self::VegaExistingCredentialZkV1(statement) => validate_vega(statement)?,
            Self::IrohaZkX509StarkP256V1(statement) => validate_zk_x509(statement)?,
            Self::IrohaJindoPolynomialCommitmentV1(statement) => validate_jindo(statement, limits)?,
            Self::IrohaBootleLanternAnoncredV1(statement) => validate_bootle_lantern(statement)?,
            Self::OrchardHalo2ActionsV1(statement) => validate_orchard(statement, limits)?,
            Self::MoneroFcmpPlusPlusV1(statement) => validate_fcmp(statement, limits)?,
            Self::IrohaIvmPrivateNoteStarkV1(statement) => {
                validate_ivm_private_note(statement, limits)?
            }
            Self::PqMaspStarkV1(statement) => validate_pq_masp(statement, limits)?,
        }
        let encoded_len = norito::canonical_frame_len(self)
            .map_err(|_| PrivacyStatementValidationError::EncodingFailure)?;
        let bytes = u64::try_from(encoded_len)
            .map_err(|_| PrivacyStatementValidationError::PayloadLengthOverflow)?;
        if bytes > u64::from(limits.max_statement_and_encrypted_output_bytes_per_transaction) {
            return Err(
                PrivacyStatementValidationError::StatementAndEncryptedOutputsTooLarge {
                    bytes,
                    max: limits.max_statement_and_encrypted_output_bytes_per_transaction,
                },
            );
        }
        Ok(())
    }
}
fn validate_zk_ace(
    statement: &ZkAcePqAuthorizationStatementV1,
) -> Result<(), PrivacyStatementValidationError> {
    validate_public_balance_scope(statement.public_balance_scope)?;
    if statement.identity_commitment.is_zero() {
        return Err(PrivacyStatementValidationError::ZeroCommitment { index: 0 });
    }
    require_nonzero_id(statement.policy_id.is_zero(), PrivacyTypedFieldV1::PolicyId)?;
    require_nonzero_id(
        statement.policy_digest.is_zero(),
        PrivacyTypedFieldV1::PolicyDigest,
    )?;
    if statement.amount == 0 {
        return Err(PrivacyStatementValidationError::ZeroAmount);
    }
    require_epoch(
        statement.authorization_epoch,
        PrivacyEpochFieldV1::Authorization,
    )?;
    if statement.replay_nullifier.is_zero() {
        return Err(PrivacyStatementValidationError::ZeroNullifier { index: 0 });
    }
    Ok(())
}
fn validate_anonymous_pgc(
    statement: &AnonymousPgcKOutOfNStatementV1,
    _limits: &PrivacyConsensusLimitsV1,
) -> Result<(), PrivacyStatementValidationError> {
    require_nonzero_id(statement.pool_id.is_zero(), PrivacyTypedFieldV1::PoolId)?;
    require_nonzero_id(
        statement.account_state_root.is_zero(),
        PrivacyTypedFieldV1::Root,
    )?;
    require_epoch(
        statement.account_state_root_epoch,
        PrivacyEpochFieldV1::Root,
    )?;
    validate_next_root_transition(
        statement.account_state_root,
        statement.account_state_root_epoch,
        statement.next_account_state_root,
        statement.next_account_state_root_epoch,
        PrivacyRootTransitionFieldV1::PgcAccountState,
    )?;
    let anonymity_set_size = u32_len(statement.anonymity_set_public_keys.len())?;
    if !ANONYMOUS_PGC_ANONYMITY_SET_SIZES_V1.contains(&anonymity_set_size) {
        return Err(
            PrivacyStatementValidationError::InvalidPgcAnonymitySetSize {
                size: anonymity_set_size,
            },
        );
    }
    let ciphertext_count = u32_len(statement.transfer_ciphertexts.len())?;
    if ciphertext_count != anonymity_set_size {
        return Err(
            PrivacyStatementValidationError::PgcPublicMemoCountMismatch {
                public_keys: anonymity_set_size,
                ciphertexts: ciphertext_count,
            },
        );
    }
    for (index, key) in statement
        .anonymity_set_public_keys
        .iter()
        .copied()
        .enumerate()
    {
        if key.is_zero() {
            return Err(PrivacyStatementValidationError::ZeroP256Point {
                index: u32_index(index)?,
            });
        }
        if index > 0 && statement.anonymity_set_public_keys[index - 1] >= key {
            return Err(PrivacyStatementValidationError::PgcAnonymitySetNotStrictlyIncreasing);
        }
    }
    for (index, ciphertext) in statement.transfer_ciphertexts.iter().enumerate() {
        let index = u32_index(index)?;
        if ciphertext.left.is_zero() {
            return Err(PrivacyStatementValidationError::ZeroP256CiphertextPoint {
                index,
                component: PrivacyP256CiphertextComponentV1::Left,
            });
        }
        if ciphertext.right.is_zero() {
            return Err(PrivacyStatementValidationError::ZeroP256CiphertextPoint {
                index,
                component: PrivacyP256CiphertextComponentV1::Right,
            });
        }
    }
    let max_recipient_count =
        ANONYMOUS_PGC_MAX_RECIPIENTS_V1.min(anonymity_set_size.saturating_sub(1));
    if statement.recipient_count == 0 || statement.recipient_count > max_recipient_count {
        return Err(PrivacyStatementValidationError::InvalidPgcRecipientCount {
            count: statement.recipient_count,
            anonymity_set_size,
            max: max_recipient_count,
        });
    }
    Ok(())
}
fn validate_verange(
    statement: &VeRangeTransparentRangeStatementV1,
    limits: &PrivacyConsensusLimitsV1,
) -> Result<(), PrivacyStatementValidationError> {
    require_nonzero_id(statement.policy_id.is_zero(), PrivacyTypedFieldV1::PolicyId)?;
    let aggregation_max =
        VERANGE_HARD_MAX_AGGREGATION_COUNT_V1.min(limits.max_commitments_per_action);
    if statement.aggregation_count == 0 || statement.aggregation_count > aggregation_max {
        return Err(PrivacyStatementValidationError::InvalidAggregationCount {
            count: statement.aggregation_count,
            max: aggregation_max,
        });
    }
    if statement.value_commitments.is_empty() {
        return Err(PrivacyStatementValidationError::MissingCommitment);
    }
    for (index, commitment) in statement.value_commitments.iter().copied().enumerate() {
        if commitment.is_zero() {
            return Err(PrivacyStatementValidationError::ZeroP256Point {
                index: u32_index(index)?,
            });
        }
    }
    if first_duplicate_index(&statement.value_commitments).is_some() {
        return Err(PrivacyStatementValidationError::DuplicateCommitment);
    }
    require_count(
        statement.value_commitments.len(),
        statement.aggregation_count,
        PrivacyCountFieldV1::AggregatedCommitments,
    )
}
fn validate_zk_ams(
    statement: &IrohaZkAmsStatementV1,
) -> Result<(), PrivacyStatementValidationError> {
    require_nonzero_id(statement.issuer_id.is_zero(), PrivacyTypedFieldV1::IssuerId)?;
    if statement.issuer_public_key.is_zero() {
        return Err(PrivacyStatementValidationError::ZeroP256Point { index: 0 });
    }
    require_nonzero_id(
        statement.issuer_policy_record_digest.is_zero(),
        PrivacyTypedFieldV1::ZkAmsIssuerPolicyRecordDigest,
    )?;
    require_nonzero_id(
        statement.registry_id.is_zero(),
        PrivacyTypedFieldV1::RegistryId,
    )?;
    require_nonzero_id(
        statement.registry_record_digest.is_zero(),
        PrivacyTypedFieldV1::ZkAmsRegistryRecordDigest,
    )?;
    require_nonzero_id(statement.policy_id.is_zero(), PrivacyTypedFieldV1::PolicyId)?;
    require_nonzero_id(
        statement.policy_digest.is_zero(),
        PrivacyTypedFieldV1::PolicyDigest,
    )?;
    match &statement.action {
        PrivacyZkAmsActionV1::BatchAdmission(batch) => validate_zk_ams_batch_admission(batch),
        PrivacyZkAmsActionV1::ProvisionAccount(provision) => {
            validate_zk_ams_provision_account(provision)
        }
    }
}
fn validate_zk_ams_batch_admission(
    batch: &PrivacyZkAmsBatchAdmissionV1,
) -> Result<(), PrivacyStatementValidationError> {
    require_nonzero_id(
        batch.account_registry_root.is_zero(),
        PrivacyTypedFieldV1::Root,
    )?;
    require_epoch(batch.account_registry_root_epoch, PrivacyEpochFieldV1::Root)?;
    validate_next_root_transition(
        batch.account_registry_root,
        batch.account_registry_root_epoch,
        batch.next_account_registry_root,
        batch.next_account_registry_root_epoch,
        PrivacyRootTransitionFieldV1::AccountRegistry,
    )?;
    let batch_size = u32_len(batch.anchors.len())?;
    if batch_size == 0 || batch_size > ZK_AMS_MAX_BATCH_SIZE_V1 {
        return Err(PrivacyStatementValidationError::InvalidBatchSize {
            count: batch_size,
            max: ZK_AMS_MAX_BATCH_SIZE_V1,
        });
    }
    for (index, anchor) in batch.anchors.iter().enumerate() {
        if anchor.phc_hash.is_zero() {
            return Err(PrivacyStatementValidationError::ZeroZkAmsPhcHash {
                index: u32_index(index)?,
            });
        }
        if anchor.seed_public_key.is_zero() {
            return Err(PrivacyStatementValidationError::ZeroZkAmsSeedPublicKey {
                index: u32_index(index)?,
            });
        }
    }
    for later in 1..batch.anchors.len() {
        if batch.anchors[..later]
            .iter()
            .any(|earlier| earlier.phc_hash == batch.anchors[later].phc_hash)
        {
            return Err(PrivacyStatementValidationError::DuplicateZkAmsPhcHash);
        }
        if batch.anchors[..later]
            .iter()
            .any(|earlier| earlier.seed_public_key == batch.anchors[later].seed_public_key)
        {
            return Err(PrivacyStatementValidationError::DuplicateZkAmsSeedPublicKey);
        }
    }
    Ok(())
}
fn validate_zk_ams_provision_account(
    provision: &PrivacyZkAmsProvisionAccountV1,
) -> Result<(), PrivacyStatementValidationError> {
    require_nonzero_id(
        provision.account_registry_root.is_zero(),
        PrivacyTypedFieldV1::Root,
    )?;
    require_epoch(
        provision.account_registry_root_epoch,
        PrivacyEpochFieldV1::Root,
    )?;
    let ring_size = u32_len(provision.admitted_seed_key_ring.len())?;
    if !ZK_AMS_RING_SIZES_V1.contains(&ring_size) {
        return Err(PrivacyStatementValidationError::InvalidZkAmsRingSize { size: ring_size });
    }
    for (index, key) in provision.admitted_seed_key_ring.iter().enumerate() {
        if key.is_zero() {
            return Err(PrivacyStatementValidationError::ZeroZkAmsSeedPublicKey {
                index: u32_index(index)?,
            });
        }
    }
    if provision
        .admitted_seed_key_ring
        .windows(2)
        .any(|pair| pair[0] >= pair[1])
    {
        return Err(PrivacyStatementValidationError::ZkAmsSeedKeyRingNotStrictlyIncreasing);
    }
    if provision.key_image.is_zero() {
        return Err(PrivacyStatementValidationError::ZeroZkAmsKeyImage);
    }
    Ok(())
}
fn validate_vega(
    statement: &VegaExistingCredentialStatementV1,
) -> Result<(), PrivacyStatementValidationError> {
    require_nonzero_id(statement.issuer_id.is_zero(), PrivacyTypedFieldV1::IssuerId)?;
    require_epoch(
        statement.issuer_record_epoch,
        PrivacyEpochFieldV1::VegaIssuerRecord,
    )?;
    require_nonzero_id(
        statement.issuer_record_digest.is_zero(),
        PrivacyTypedFieldV1::VegaIssuerRecordDigest,
    )?;
    if statement.issuer_public_key.is_zero() {
        return Err(PrivacyStatementValidationError::ZeroP256Point { index: 0 });
    }
    require_nonzero_id(
        statement.device_authentication_digest.is_zero(),
        PrivacyTypedFieldV1::VegaDeviceAuthenticationDigest,
    )?;
    require_nonzero_id(
        statement.reader_challenge.is_zero(),
        PrivacyTypedFieldV1::ReaderChallenge,
    )?;
    require_nonzero_id(
        statement.session_transcript_digest.is_zero(),
        PrivacyTypedFieldV1::SessionTranscriptDigest,
    )?;
    validate_vega_presentation_date(statement.presentation_date)?;
    if !(VEGA_MDL_MIN_AGE_THRESHOLD_YEARS_V1..=VEGA_MDL_MAX_AGE_THRESHOLD_YEARS_V1)
        .contains(&statement.minimum_age_years)
    {
        return Err(PrivacyStatementValidationError::InvalidVegaAgeThreshold {
            years: statement.minimum_age_years,
            min: VEGA_MDL_MIN_AGE_THRESHOLD_YEARS_V1,
            max: VEGA_MDL_MAX_AGE_THRESHOLD_YEARS_V1,
        });
    }
    Ok(())
}
fn validate_vega_presentation_date(
    date: PrivacyVegaMdlDateV1,
) -> Result<(), PrivacyStatementValidationError> {
    if !(VEGA_MDL_MIN_PRESENTATION_YEAR_V1..=VEGA_MDL_MAX_PRESENTATION_YEAR_V1).contains(&date.year)
    {
        return Err(
            PrivacyStatementValidationError::InvalidVegaPresentationYear {
                year: date.year,
                min: VEGA_MDL_MIN_PRESENTATION_YEAR_V1,
                max: VEGA_MDL_MAX_PRESENTATION_YEAR_V1,
            },
        );
    }
    let max_day = vega_gregorian_days_in_month(date.year, date.month).ok_or(
        PrivacyStatementValidationError::InvalidVegaPresentationDate {
            year: date.year,
            month: date.month,
            day: date.day,
        },
    )?;
    if date.day == 0 || date.day > max_day {
        return Err(
            PrivacyStatementValidationError::InvalidVegaPresentationDate {
                year: date.year,
                month: date.month,
                day: date.day,
            },
        );
    }
    Ok(())
}
fn vega_gregorian_days_in_month(year: u16, month: u8) -> Option<u8> {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => Some(31),
        4 | 6 | 9 | 11 => Some(30),
        2 if vega_is_gregorian_leap_year(year) => Some(29),
        2 => Some(28),
        _ => None,
    }
}
fn vega_is_gregorian_leap_year(year: u16) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}
fn validate_zk_x509_governance_bindings(
    statement: &IrohaZkX509StarkP256StatementV1,
) -> Result<(), PrivacyStatementValidationError> {
    require_nonzero_id(
        statement.trust_anchor_id.is_zero(),
        PrivacyTypedFieldV1::IssuerId,
    )?;
    require_nonzero_id(
        statement.certificate_policy_id.is_zero(),
        PrivacyTypedFieldV1::PolicyId,
    )?;
    require_nonzero_id(
        statement.trust_anchor_record_digest.is_zero(),
        PrivacyTypedFieldV1::X509TrustAnchorRecordDigest,
    )?;
    require_epoch(
        statement.trust_anchor_record_epoch,
        PrivacyEpochFieldV1::X509TrustAnchorRecord,
    )?;
    require_nonzero_id(
        statement.certificate_policy_record_digest.is_zero(),
        PrivacyTypedFieldV1::X509CertificatePolicyRecordDigest,
    )?;
    require_epoch(
        statement.certificate_policy_record_epoch,
        PrivacyEpochFieldV1::X509CertificatePolicyRecord,
    )?;
    require_nonzero_id(
        statement.crl_record_digest.is_zero(),
        PrivacyTypedFieldV1::X509CrlRecordDigest,
    )?;
    require_epoch(
        statement.crl_record_epoch,
        PrivacyEpochFieldV1::X509CrlRecord,
    )?;
    require_nonzero_id(
        statement.subject_public_key_digest.is_zero(),
        PrivacyTypedFieldV1::CertificateKeyDigest,
    )?;
    require_nonzero_id(
        statement.ca_membership_root.is_zero(),
        PrivacyTypedFieldV1::Root,
    )?;
    require_epoch(
        statement.ca_membership_root_epoch,
        PrivacyEpochFieldV1::CertificateAuthorityMembership,
    )?;
    Ok(())
}
fn validate_zk_x509_usage_and_disclosures(
    statement: &IrohaZkX509StarkP256StatementV1,
) -> Result<(), PrivacyStatementValidationError> {
    if !statement.key_usage.digital_signature.is_required() {
        return Err(PrivacyStatementValidationError::InvalidX509KeyUsage);
    }
    if statement.extended_key_usages.is_empty() {
        return Err(PrivacyStatementValidationError::MissingX509ExtendedKeyUsage);
    }
    if statement.extended_key_usages.len() > ZK_X509_MAX_EXTENDED_KEY_USAGES_V1 {
        return Err(
            PrivacyStatementValidationError::TooManyX509ExtendedKeyUsages {
                actual: statement.extended_key_usages.len(),
                max: ZK_X509_MAX_EXTENDED_KEY_USAGES_V1,
            },
        );
    }
    for index in 1..statement.extended_key_usages.len() {
        if statement.extended_key_usages[index - 1] >= statement.extended_key_usages[index] {
            return Err(
                PrivacyStatementValidationError::X509ExtendedKeyUsagesNotStrictlyIncreasing,
            );
        }
    }
    if statement.disclosed_attributes.len() > ZK_X509_MAX_DISCLOSED_ATTRIBUTES_V1 {
        return Err(
            PrivacyStatementValidationError::TooManyX509DisclosedAttributes {
                actual: statement.disclosed_attributes.len(),
                max: ZK_X509_MAX_DISCLOSED_ATTRIBUTES_V1,
            },
        );
    }
    for (position, disclosed) in statement.disclosed_attributes.iter().enumerate() {
        if usize::from(disclosed.index) >= ZK_X509_MAX_DISCLOSED_ATTRIBUTES_V1 {
            return Err(
                PrivacyStatementValidationError::UnsupportedX509DisclosedAttributeIndex {
                    index: disclosed.index,
                },
            );
        }
        if disclosed.attribute_digest.is_zero() {
            return Err(
                PrivacyStatementValidationError::ZeroX509DisclosedAttributeDigest {
                    index: disclosed.index,
                },
            );
        }
        if position > 0 && statement.disclosed_attributes[position - 1].index >= disclosed.index {
            return Err(
                PrivacyStatementValidationError::X509DisclosedAttributesNotStrictlyIncreasing,
            );
        }
    }
    validate_zk_x509_presentation_window(
        statement.presentation_not_before_unix_seconds,
        statement.presentation_not_after_unix_seconds,
    )?;
    Ok(())
}
fn validate_zk_x509(
    statement: &IrohaZkX509StarkP256StatementV1,
) -> Result<(), PrivacyStatementValidationError> {
    validate_zk_x509_governance_bindings(statement)?;
    validate_zk_x509_usage_and_disclosures(statement)?;
    require_nonzero_id(
        statement.wallet_challenge.is_zero(),
        PrivacyTypedFieldV1::ReaderChallenge,
    )?;
    require_nullifier(statement.certificate_nullifier, 0)
}
fn validate_zk_x509_presentation_window(
    start: u64,
    end: u64,
) -> Result<(), PrivacyStatementValidationError> {
    // The canonical interval definition owns the window shape; this adapter
    // only preserves the statement-level error identity.
    PrivacyZkX509PresentationWindowV1::new(start, end)
        .validate()
        .map_err(
            |_| PrivacyStatementValidationError::InvalidX509PresentationWindow {
                start,
                end,
                max_seconds: ZK_X509_MAX_PRESENTATION_WINDOW_SECONDS_V1,
            },
        )
}
fn validate_jindo(
    statement: &IrohaJindoPolynomialCommitmentStatementV1,
    limits: &PrivacyConsensusLimitsV1,
) -> Result<(), PrivacyStatementValidationError> {
    let polynomial_count = u32_len(statement.polynomial_commitments.len())?;
    // The frozen revised-Jindo parameter search and proof shape are exact
    // batch=4. Smaller batches are not padded and have no alternate transcript.
    if polynomial_count != IROHA_JINDO_MAX_POLYNOMIALS_V1 {
        return Err(
            PrivacyStatementValidationError::InvalidJindoPolynomialCount {
                count: polynomial_count,
                expected: IROHA_JINDO_MAX_POLYNOMIALS_V1,
            },
        );
    }
    if limits.max_commitments_per_action < IROHA_JINDO_MAX_POLYNOMIALS_V1 {
        return Err(
            PrivacyStatementValidationError::InsufficientJindoCommitmentCapacity {
                maximum: limits.max_commitments_per_action,
                required: IROHA_JINDO_MAX_POLYNOMIALS_V1,
            },
        );
    }
    for (index, commitment) in statement.polynomial_commitments.iter().enumerate() {
        let bytes = u32_len(commitment.encoding.len())?;
        if commitment.encoding.len() != IROHA_JINDO_LATTICE_COMMITMENT_BYTES_V1 {
            return Err(
                PrivacyStatementValidationError::InvalidJindoLatticeCommitmentSize {
                    index: u32_index(index)?,
                    bytes,
                    expected: u32::try_from(IROHA_JINDO_LATTICE_COMMITMENT_BYTES_V1)
                        .expect("fixed Jindo commitment width fits u32"),
                },
            );
        }
        if commitment.encoding.iter().all(|byte| *byte == 0) {
            return Err(
                PrivacyStatementValidationError::AllZeroJindoLatticeCommitment {
                    index: u32_index(index)?,
                },
            );
        }
        for (coefficient_index, bytes) in commitment.encoding.chunks_exact(4).enumerate() {
            let coefficient = i32::from_le_bytes(
                bytes
                    .try_into()
                    .expect("Jindo commitment width is a multiple of four"),
            );
            if !(IROHA_JINDO_MIN_ROUNDED_COMMITMENT_COEFFICIENT_V1
                ..=IROHA_JINDO_MAX_ROUNDED_COMMITMENT_COEFFICIENT_V1)
                .contains(&coefficient)
            {
                return Err(
                    PrivacyStatementValidationError::JindoCommitmentCoefficientOutOfRange {
                        commitment_index: u32_index(index)?,
                        coefficient_index: u32_index(coefficient_index)?,
                        value: coefficient,
                        min: IROHA_JINDO_MIN_ROUNDED_COMMITMENT_COEFFICIENT_V1,
                        max: IROHA_JINDO_MAX_ROUNDED_COMMITMENT_COEFFICIENT_V1,
                    },
                );
            }
        }
    }
    if first_duplicate_index(&statement.polynomial_commitments).is_some() {
        return Err(PrivacyStatementValidationError::DuplicateJindoLatticeCommitment);
    }
    require_count(
        statement.claimed_evaluations.len(),
        polynomial_count,
        PrivacyCountFieldV1::JindoClaimedEvaluations,
    )?;
    if !is_canonical_jindo_field_element(&statement.evaluation_point) {
        return Err(PrivacyStatementValidationError::NonCanonicalJindoEvaluationPoint);
    }
    for (index, claimed_evaluation) in statement.claimed_evaluations.iter().enumerate() {
        if !is_canonical_jindo_field_element(claimed_evaluation) {
            return Err(
                PrivacyStatementValidationError::NonCanonicalJindoClaimedEvaluation {
                    index: u32_index(index)?,
                },
            );
        }
    }
    Ok(())
}
fn is_canonical_jindo_field_element(element: &PrivacyJindoFieldElementV1) -> bool {
    for index in (0..IROHA_JINDO_FIELD_ELEMENT_BYTES_V1).rev() {
        if element.encoding[index] != IROHA_JINDO_FIELD_MODULUS_LE_V1[index] {
            return element.encoding[index] < IROHA_JINDO_FIELD_MODULUS_LE_V1[index];
        }
    }
    false
}
fn validate_bootle_lantern(
    statement: &IrohaBootleLanternAnoncredStatementV1,
) -> Result<(), PrivacyStatementValidationError> {
    require_nonzero_id(statement.issuer_id.is_zero(), PrivacyTypedFieldV1::IssuerId)?;
    require_nonzero_id(statement.policy_id.is_zero(), PrivacyTypedFieldV1::PolicyId)?;
    require_epoch(
        statement.issuer_policy_epoch,
        PrivacyEpochFieldV1::IssuerPolicy,
    )?;
    require_nonzero_id(
        statement.issuer_policy_record_digest.is_zero(),
        PrivacyTypedFieldV1::IssuerPolicyRecordDigest,
    )?;
    require_nonzero_id(
        statement.issuer_parameter_id.is_zero(),
        PrivacyTypedFieldV1::IssuerParameterId,
    )?;
    require_nonzero_id(
        statement.issuer_parameter_digest.is_zero(),
        PrivacyTypedFieldV1::IssuerParameterDigest,
    )?;
    let disclosed_count = u32::try_from(statement.disclosures.len())
        .map_err(|_| PrivacyStatementValidationError::PayloadLengthOverflow)?;
    if disclosed_count > BOOTLE_LANTERN_MAX_DISCLOSED_ATTRIBUTES_V1 {
        return Err(
            PrivacyStatementValidationError::TooManyBootleLanternDisclosures {
                count: disclosed_count,
                max: BOOTLE_LANTERN_MAX_DISCLOSED_ATTRIBUTES_V1,
            },
        );
    }
    let mut previous = None;
    for disclosure in &statement.disclosures {
        if usize::from(disclosure.index) >= BOOTLE_LANTERN_ATTRIBUTE_COUNT_V1 {
            return Err(
                PrivacyStatementValidationError::BootleLanternDisclosureIndexOutOfBounds {
                    index: disclosure.index,
                },
            );
        }
        if previous.is_some_and(|value| disclosure.index <= value) {
            return Err(
                PrivacyStatementValidationError::BootleLanternDisclosuresNotStrictlyIncreasing,
            );
        }
        previous = Some(disclosure.index);
    }
    Ok(())
}
fn validate_orchard(
    statement: &OrchardHalo2ActionsStatementV1,
    limits: &PrivacyConsensusLimitsV1,
) -> Result<(), PrivacyStatementValidationError> {
    validate_public_balance_scope(statement.public_balance_scope)?;
    require_nonzero_id(statement.pool_id.is_zero(), PrivacyTypedFieldV1::PoolId)?;
    require_nonzero_id(statement.anchor.is_zero(), PrivacyTypedFieldV1::Root)?;
    require_epoch(statement.anchor_epoch, PrivacyEpochFieldV1::Root)?;
    require_epoch(statement.expiry_height, PrivacyEpochFieldV1::ExpiryHeight)?;
    statement.value_balance.validate()?;
    if statement.value_balance.amount > ORCHARD_MAX_VALUE_BALANCE_V1 {
        return Err(
            PrivacyStatementValidationError::OrchardValueBalanceOutOfRange {
                amount: statement.value_balance.amount,
                max: ORCHARD_MAX_VALUE_BALANCE_V1,
            },
        );
    }
    let max = ORCHARD_MAX_ACTIONS_V1
        .min(limits.max_nullifiers_per_action)
        .min(limits.max_commitments_per_action);
    let count = u32_len(statement.actions.len())?;
    if count == 0 || count > max {
        return Err(PrivacyStatementValidationError::InvalidOrchardActionCount { count, max });
    }
    for (index, action) in statement.actions.iter().enumerate() {
        let index = u32_index(index)?;
        let encrypted_note_bytes = u32_len(action.encrypted_note.len())?;
        if action.encrypted_note.len() != ORCHARD_ENCRYPTED_NOTE_BYTES_V1 {
            return Err(
                PrivacyStatementValidationError::InvalidOrchardEncryptedNoteSize {
                    index,
                    bytes: encrypted_note_bytes,
                    expected: u32::try_from(ORCHARD_ENCRYPTED_NOTE_BYTES_V1)
                        .expect("compiled Orchard ciphertext width fits u32"),
                },
            );
        }
        let outgoing_ciphertext_bytes = u32_len(action.outgoing_ciphertext.len())?;
        if action.outgoing_ciphertext.len() != ORCHARD_OUTGOING_CIPHERTEXT_BYTES_V1 {
            return Err(
                PrivacyStatementValidationError::InvalidOrchardOutgoingCiphertextSize {
                    index,
                    bytes: outgoing_ciphertext_bytes,
                    expected: u32::try_from(ORCHARD_OUTGOING_CIPHERTEXT_BYTES_V1)
                        .expect("compiled Orchard ciphertext width fits u32"),
                },
            );
        }
        if statement.actions[..usize::try_from(index).expect("u32 index fits usize")]
            .iter()
            .any(|earlier| earlier.nullifier == action.nullifier)
        {
            return Err(PrivacyStatementValidationError::DuplicateOrchardNullifier { index });
        }
        if statement.actions[..usize::try_from(index).expect("u32 index fits usize")]
            .iter()
            .any(|earlier| earlier.note_commitment == action.note_commitment)
        {
            return Err(PrivacyStatementValidationError::DuplicateOrchardNoteCommitment { index });
        }
    }
    Ok(())
}
fn validate_fcmp(
    statement: &MoneroFcmpPlusPlusStatementV1,
    limits: &PrivacyConsensusLimitsV1,
) -> Result<(), PrivacyStatementValidationError> {
    require_nonzero_id(statement.pool_id.is_zero(), PrivacyTypedFieldV1::PoolId)?;
    statement
        .output_set_root
        .validate()
        .map_err(PrivacyStatementValidationError::InvalidFcmpTreeRoot)?;
    require_epoch(statement.root_epoch, PrivacyEpochFieldV1::Root)?;
    let max_inputs = FCMP_MAX_INPUTS_V1
        .min(limits.max_commitments_per_action)
        .min(limits.max_nullifiers_per_action);
    let input_count = u32_len(statement.inputs.len())?;
    if input_count == 0 || input_count > max_inputs {
        return Err(PrivacyStatementValidationError::InvalidFcmpInputCount {
            count: input_count,
            max: max_inputs,
        });
    }
    for (index, input) in statement.inputs.iter().copied().enumerate() {
        let canonical_index = u32_index(index)?;
        input.validate_nonzero().map_err(|source| {
            PrivacyStatementValidationError::InvalidFcmpInput {
                index: canonical_index,
                source,
            }
        })?;
        if statement.inputs[..index]
            .iter()
            .any(|earlier| earlier.key_image == input.key_image)
        {
            return Err(PrivacyStatementValidationError::DuplicateFcmpKeyImage {
                index: canonical_index,
            });
        }
        if statement.inputs[..index]
            .iter()
            .any(|earlier| earlier.pseudo_out == input.pseudo_out)
        {
            return Err(PrivacyStatementValidationError::DuplicateFcmpPseudoOut {
                index: canonical_index,
            });
        }
    }
    let max_outputs = FCMP_MAX_OUTPUTS_V1.min(limits.max_commitments_per_action);
    let output_count = u32_len(statement.outputs.len())?;
    if output_count == 0 || output_count > max_outputs {
        return Err(PrivacyStatementValidationError::InvalidFcmpOutputCount {
            count: output_count,
            max: max_outputs,
        });
    }
    for (index, output) in statement.outputs.iter().copied().enumerate() {
        let canonical_index = u32_index(index)?;
        output.validate_nonzero().map_err(|source| {
            PrivacyStatementValidationError::InvalidFcmpOutput {
                index: canonical_index,
                source,
            }
        })?;
        let output_id = output.output_id();
        if statement.outputs[..index]
            .iter()
            .copied()
            .any(|earlier| earlier.output_id() == output_id)
        {
            return Err(PrivacyStatementValidationError::DuplicateFcmpOutputId {
                index: canonical_index,
            });
        }
    }
    validate_fcmp_encrypted_outputs(
        &statement.encrypted_outputs,
        &statement.outputs,
        max_outputs,
    )
}
fn validate_fcmp_encrypted_outputs(
    encrypted_outputs: &[PrivacyFcmpEncryptedOutputV1],
    outputs: &[PrivacyFcmpOutputTupleV1],
    max: u32,
) -> Result<(), PrivacyStatementValidationError> {
    if encrypted_outputs.is_empty() {
        return Err(PrivacyStatementValidationError::MissingEncryptedOutput);
    }
    let count = u32_len(encrypted_outputs.len())?;
    if count > max {
        return Err(PrivacyStatementValidationError::TooManyEncryptedOutputs { count, max });
    }
    if encrypted_outputs.len() != outputs.len() {
        return Err(
            PrivacyStatementValidationError::FcmpEncryptedOutputCountMismatch {
                encrypted_outputs: count,
                outputs: u32_len(outputs.len())?,
            },
        );
    }
    for (index, (encrypted_output, output)) in encrypted_outputs.iter().zip(outputs).enumerate() {
        let index = u32_index(index)?;
        if encrypted_output.recipient.is_zero() {
            return Err(PrivacyStatementValidationError::ZeroEncryptedOutputRecipient { index });
        }
        if encrypted_output.ephemeral_public_key.is_zero() {
            return Err(PrivacyStatementValidationError::ZeroEncryptedOutputEphemeralKey { index });
        }
        if encrypted_output.output_id != output.output_id() {
            return Err(PrivacyStatementValidationError::FcmpEncryptedOutputIdMismatch { index });
        }
        if encrypted_output.ciphertext.len() != PRIVACY_FCMP_ENCRYPTED_OUTPUT_BYTES_V1
            || encrypted_output.ciphertext.get(..4)
                != Some(PRIVACY_FCMP_ENCRYPTED_OUTPUT_MAGIC_V1.as_slice())
            || encrypted_output.ciphertext[4..4 + PRIVACY_FCMP_ENCRYPTED_OUTPUT_NONCE_BYTES_V1]
                .iter()
                .all(|byte| *byte == 0)
            || encrypted_output.ciphertext[4 + PRIVACY_FCMP_ENCRYPTED_OUTPUT_NONCE_BYTES_V1..]
                .iter()
                .all(|byte| *byte == 0)
        {
            return Err(PrivacyStatementValidationError::InvalidFcmpEncryptedOutputCodec { index });
        }
    }
    Ok(())
}
fn validate_ivm_private_note(
    statement: &IrohaIvmPrivateNoteStarkStatementV1,
    limits: &PrivacyConsensusLimitsV1,
) -> Result<(), PrivacyStatementValidationError> {
    validate_public_balance_scope(statement.public_balance_scope)?;
    require_nonzero_id(statement.pool_id.is_zero(), PrivacyTypedFieldV1::PoolId)?;
    require_nonzero_id(
        statement.program_id.is_zero(),
        PrivacyTypedFieldV1::ProgramId,
    )?;
    require_nonzero_id(
        statement.action_digest.is_zero(),
        PrivacyTypedFieldV1::ActionDigest,
    )?;
    let computed_action_digest = statement
        .computed_action_digest()
        .map_err(|_| PrivacyStatementValidationError::ActionDigestEncodingFailed)?;
    if statement.action_digest != computed_action_digest {
        return Err(PrivacyStatementValidationError::ActionDigestMismatch);
    }
    require_nonzero_id(statement.state_root.is_zero(), PrivacyTypedFieldV1::Root)?;
    require_epoch(statement.root_epoch, PrivacyEpochFieldV1::Root)?;
    require_epoch(statement.execution_epoch, PrivacyEpochFieldV1::Execution)?;
    if statement.execution_epoch != statement.root_epoch {
        return Err(PrivacyStatementValidationError::EpochBindingMismatch {
            field: PrivacyEpochFieldV1::Execution,
            root_epoch: statement.root_epoch,
            bound_epoch: statement.execution_epoch,
        });
    }
    statement.value_balance.validate()?;
    validate_nullifiers_with_max(
        &statement.nullifiers,
        true,
        IVM_PRIVATE_NOTE_MAX_INPUTS_V1.min(limits.max_nullifiers_per_action),
    )?;
    validate_commitments_with_max(
        &statement.output_commitments,
        true,
        IVM_PRIVATE_NOTE_MAX_OUTPUTS_V1.min(limits.max_commitments_per_action),
    )?;
    validate_encrypted_outputs(
        &statement.encrypted_outputs,
        &statement.output_commitments,
        true,
        limits,
    )?;
    validate_ivm_private_encrypted_outputs(&statement.encrypted_outputs)
}
fn validate_public_balance_scope(
    scope: AssetBalanceScope,
) -> Result<(), PrivacyStatementValidationError> {
    if matches!(
        scope,
        AssetBalanceScope::Dataspace(iroha_model_base::topology::DataSpaceId::UNIVERSAL)
    ) {
        return Err(PrivacyStatementValidationError::UniversalPublicBalanceScope);
    }
    Ok(())
}
fn validate_pq_masp(
    statement: &PqMaspStarkStatementV1,
    limits: &PrivacyConsensusLimitsV1,
) -> Result<(), PrivacyStatementValidationError> {
    require_nonzero_id(statement.pool_id.is_zero(), PrivacyTypedFieldV1::PoolId)?;
    require_nonzero_id(statement.anchor.is_zero(), PrivacyTypedFieldV1::Root)?;
    require_epoch(statement.anchor_epoch, PrivacyEpochFieldV1::Root)?;
    require_epoch(
        statement.authorization_epoch,
        PrivacyEpochFieldV1::Authorization,
    )?;
    if statement.authorization_epoch != statement.anchor_epoch {
        return Err(PrivacyStatementValidationError::EpochBindingMismatch {
            field: PrivacyEpochFieldV1::Authorization,
            root_epoch: statement.anchor_epoch,
            bound_epoch: statement.authorization_epoch,
        });
    }
    require_nonzero_id(
        statement.authorization_key_digest.is_zero(),
        PrivacyTypedFieldV1::AuthorizationKeyDigest,
    )?;
    require_nonzero_id(
        statement.note_encryption_key_digest.is_zero(),
        PrivacyTypedFieldV1::NoteEncryptionKeyDigest,
    )?;
    validate_nullifiers_with_max(
        &statement.nullifiers,
        true,
        PQ_MASP_MAX_INPUTS_V1.min(limits.max_nullifiers_per_action),
    )?;
    validate_commitments_with_max(
        &statement.output_commitments,
        true,
        PQ_MASP_MAX_OUTPUTS_V1.min(limits.max_commitments_per_action),
    )?;
    validate_encrypted_outputs(
        &statement.encrypted_outputs,
        &statement.output_commitments,
        true,
        limits,
    )
}
fn validate_nullifiers_with_max(
    values: &[PrivacyNullifierV1],
    require_nonempty: bool,
    max: u32,
) -> Result<(), PrivacyStatementValidationError> {
    if require_nonempty && values.is_empty() {
        return Err(PrivacyStatementValidationError::MissingNullifier);
    }
    let count = u32_len(values.len())?;
    if count > max {
        return Err(PrivacyStatementValidationError::TooManyNullifiers { count, max });
    }
    for (index, value) in values.iter().copied().enumerate() {
        require_nullifier(value, u32_index(index)?)?;
    }
    if first_duplicate_index(values).is_some() {
        return Err(PrivacyStatementValidationError::DuplicateNullifier);
    }
    Ok(())
}
fn validate_commitments_with_max(
    values: &[PrivacyCommitmentV1],
    require_nonempty: bool,
    max: u32,
) -> Result<(), PrivacyStatementValidationError> {
    if require_nonempty && values.is_empty() {
        return Err(PrivacyStatementValidationError::MissingCommitment);
    }
    let count = u32_len(values.len())?;
    if count > max {
        return Err(PrivacyStatementValidationError::TooManyCommitments { count, max });
    }
    for (index, value) in values.iter().copied().enumerate() {
        require_commitment(value, u32_index(index)?)?;
    }
    if first_duplicate_index(values).is_some() {
        return Err(PrivacyStatementValidationError::DuplicateCommitment);
    }
    Ok(())
}
fn validate_encrypted_outputs(
    outputs: &[PrivacyEncryptedOutputV1],
    commitments: &[PrivacyCommitmentV1],
    require_nonempty: bool,
    limits: &PrivacyConsensusLimitsV1,
) -> Result<(), PrivacyStatementValidationError> {
    if require_nonempty && outputs.is_empty() {
        return Err(PrivacyStatementValidationError::MissingEncryptedOutput);
    }
    let count = u32_len(outputs.len())?;
    if count > limits.max_commitments_per_action {
        return Err(PrivacyStatementValidationError::TooManyEncryptedOutputs {
            count,
            max: limits.max_commitments_per_action,
        });
    }
    if outputs.len() != commitments.len() {
        return Err(
            PrivacyStatementValidationError::EncryptedOutputCommitmentCountMismatch {
                outputs: count,
                commitments: u32_len(commitments.len())?,
            },
        );
    }
    for (index, (output, expected_commitment)) in outputs.iter().zip(commitments).enumerate() {
        let index = u32_index(index)?;
        if output.recipient.is_zero() {
            return Err(PrivacyStatementValidationError::ZeroEncryptedOutputRecipient { index });
        }
        if output.ephemeral_public_key.is_zero() {
            return Err(PrivacyStatementValidationError::ZeroEncryptedOutputEphemeralKey { index });
        }
        if output.commitment.is_zero() {
            return Err(PrivacyStatementValidationError::ZeroCommitment { index });
        }
        if output.commitment != *expected_commitment {
            return Err(
                PrivacyStatementValidationError::EncryptedOutputCommitmentMismatch { index },
            );
        }
        if output.ciphertext.is_empty() {
            return Err(PrivacyStatementValidationError::EmptyEncryptedOutput { index });
        }
        if output.ciphertext.iter().all(|byte| *byte == 0) {
            return Err(PrivacyStatementValidationError::AllZeroEncryptedOutput { index });
        }
    }
    Ok(())
}
fn validate_ivm_private_encrypted_outputs(
    outputs: &[PrivacyEncryptedOutputV1],
) -> Result<(), PrivacyStatementValidationError> {
    for (index, output) in outputs.iter().enumerate() {
        let nonce_end = 4 + PRIVACY_IVM_PRIVATE_ENCRYPTED_OUTPUT_NONCE_BYTES_V1;
        if output.ciphertext.len() != PRIVACY_IVM_PRIVATE_ENCRYPTED_OUTPUT_BYTES_V1
            || output.ciphertext.get(..4)
                != Some(PRIVACY_IVM_PRIVATE_ENCRYPTED_OUTPUT_MAGIC_V1.as_slice())
            || output.ciphertext[4..nonce_end]
                .iter()
                .all(|byte| *byte == 0)
            || output.ciphertext[nonce_end..].iter().all(|byte| *byte == 0)
        {
            return Err(
                PrivacyStatementValidationError::InvalidIvmPrivateEncryptedOutputCodec {
                    index: u32_index(index)?,
                },
            );
        }
    }
    Ok(())
}
fn require_nonzero_id(
    is_zero: bool,
    field: PrivacyTypedFieldV1,
) -> Result<(), PrivacyStatementValidationError> {
    if is_zero {
        return Err(PrivacyStatementValidationError::ZeroTypedField { field });
    }
    Ok(())
}
fn require_epoch(
    epoch: u64,
    field: PrivacyEpochFieldV1,
) -> Result<(), PrivacyStatementValidationError> {
    if epoch == 0 {
        return Err(PrivacyStatementValidationError::ZeroEpoch { field });
    }
    Ok(())
}
fn validate_next_root_transition(
    current_root: PrivacyRootV1,
    current_epoch: u64,
    next_root: PrivacyRootV1,
    next_epoch: u64,
    field: PrivacyRootTransitionFieldV1,
) -> Result<(), PrivacyStatementValidationError> {
    if next_root.is_zero() {
        return Err(PrivacyStatementValidationError::ZeroNextRoot { field });
    }
    if next_root == current_root {
        return Err(PrivacyStatementValidationError::UnchangedRootTransition { field });
    }
    if current_epoch.checked_add(1) != Some(next_epoch) {
        return Err(PrivacyStatementValidationError::InvalidNextRootEpoch {
            field,
            current_epoch,
            next_epoch,
        });
    }
    Ok(())
}
fn require_nullifier(
    value: PrivacyNullifierV1,
    index: u32,
) -> Result<(), PrivacyStatementValidationError> {
    if value.is_zero() {
        return Err(PrivacyStatementValidationError::ZeroNullifier { index });
    }
    Ok(())
}
fn require_commitment(
    value: PrivacyCommitmentV1,
    index: u32,
) -> Result<(), PrivacyStatementValidationError> {
    if value.is_zero() {
        return Err(PrivacyStatementValidationError::ZeroCommitment { index });
    }
    Ok(())
}
fn require_count(
    actual: usize,
    declared: u32,
    field: PrivacyCountFieldV1,
) -> Result<(), PrivacyStatementValidationError> {
    let actual = u32_len(actual)?;
    if actual != declared {
        return Err(PrivacyStatementValidationError::DeclaredCountMismatch {
            field,
            declared,
            actual,
        });
    }
    Ok(())
}
fn u32_len(len: usize) -> Result<u32, PrivacyStatementValidationError> {
    u32::try_from(len).map_err(|_| PrivacyStatementValidationError::PayloadLengthOverflow)
}
fn u32_index(index: usize) -> Result<u32, PrivacyStatementValidationError> {
    u32_len(index)
}
fn first_duplicate_index<T: PartialEq>(values: &[T]) -> Option<usize> {
    for later in 1..values.len() {
        if values[..later].contains(&values[later]) {
            return Some(later);
        }
    }
    None
}
impl PrivacyProtocolActivationLimitsV1 {
    /// Validate a statement against activation-specific governed count limits.
    ///
    /// # Errors
    ///
    /// Returns [`PrivacyActivationStatementLimitsError`] if the statement uses
    /// another protocol or exceeds an activation-specific bound.
    pub fn validate_statement(
        &self,
        statement: &PrivacyStatementV1,
    ) -> Result<(), PrivacyActivationStatementLimitsError> {
        if self.protocol_id() != statement.protocol_id() {
            return Err(PrivacyActivationStatementLimitsError::ProtocolMismatch {
                limits_protocol: self.protocol_id(),
                statement_protocol: statement.protocol_id(),
            });
        }
        match (self, statement) {
            (
                Self::AnonymousPgcKOutOfNV1(limits),
                PrivacyStatementV1::AnonymousPgcKOutOfNV1(statement),
            ) => validate_anonymous_pgc_activation_statement(*limits, statement),
            (
                Self::VeRangeTransparentRangeV1(limits),
                PrivacyStatementV1::VeRangeTransparentRangeV1(statement),
            ) => validate_activation_statement_count(
                PrivacyActivationLimitFieldV1::VeRangeAggregationCount,
                statement.aggregation_count,
                limits.max_aggregation_count,
            ),
            (Self::IrohaZkAmsV1(limits), PrivacyStatementV1::IrohaZkAmsV1(statement)) => {
                validate_zk_ams_activation_statement(*limits, statement)
            }
            (
                Self::IrohaJindoPolynomialCommitmentV1(limits),
                PrivacyStatementV1::IrohaJindoPolynomialCommitmentV1(statement),
            ) => validate_activation_statement_count(
                PrivacyActivationLimitFieldV1::JindoPolynomialCount,
                u32::try_from(statement.polynomial_commitments.len()).unwrap_or(u32::MAX),
                limits.max_polynomial_count,
            ),
            (
                Self::OrchardHalo2ActionsV1(limits),
                PrivacyStatementV1::OrchardHalo2ActionsV1(statement),
            ) => validate_orchard_activation_statement(*limits, statement),
            (
                Self::MoneroFcmpPlusPlusV1(limits),
                PrivacyStatementV1::MoneroFcmpPlusPlusV1(statement),
            ) => validate_fcmp_activation_statement(*limits, statement),
            (
                Self::IrohaIvmPrivateNoteStarkV1(limits),
                PrivacyStatementV1::IrohaIvmPrivateNoteStarkV1(statement),
            ) => validate_ivm_private_note_activation_statement(*limits, statement),
            (Self::PqMaspStarkV1(limits), PrivacyStatementV1::PqMaspStarkV1(statement)) => {
                validate_pq_masp_activation_statement(*limits, statement)
            }
            _ => Ok(()),
        }
    }
}
fn validate_anonymous_pgc_activation_statement(
    limits: AnonymousPgcActivationLimitsV1,
    statement: &AnonymousPgcKOutOfNStatementV1,
) -> Result<(), PrivacyActivationStatementLimitsError> {
    validate_activation_statement_len(
        PrivacyActivationLimitFieldV1::AnonymousPgcAnonymitySetSize,
        statement.anonymity_set_public_keys.len(),
        limits.max_anonymity_set_size,
    )?;
    validate_activation_statement_count(
        PrivacyActivationLimitFieldV1::AnonymousPgcRecipientCount,
        statement.recipient_count,
        limits.max_recipient_count,
    )
}
fn validate_zk_ams_activation_statement(
    limits: ZkAmsActivationLimitsV1,
    statement: &IrohaZkAmsStatementV1,
) -> Result<(), PrivacyActivationStatementLimitsError> {
    match &statement.action {
        PrivacyZkAmsActionV1::BatchAdmission(batch) => validate_activation_statement_len(
            PrivacyActivationLimitFieldV1::ZkAmsBatchSize,
            batch.anchors.len(),
            limits.max_batch_size,
        ),
        PrivacyZkAmsActionV1::ProvisionAccount(provision) => validate_activation_statement_len(
            PrivacyActivationLimitFieldV1::ZkAmsRingSize,
            provision.admitted_seed_key_ring.len(),
            limits.max_ring_size,
        ),
    }
}
fn validate_orchard_activation_statement(
    limits: OrchardActivationLimitsV1,
    statement: &OrchardHalo2ActionsStatementV1,
) -> Result<(), PrivacyActivationStatementLimitsError> {
    validate_activation_statement_len(
        PrivacyActivationLimitFieldV1::OrchardActionCount,
        statement.actions.len(),
        limits.max_action_count,
    )
}
fn validate_fcmp_activation_statement(
    limits: FcmpActivationLimitsV1,
    statement: &MoneroFcmpPlusPlusStatementV1,
) -> Result<(), PrivacyActivationStatementLimitsError> {
    validate_activation_statement_len(
        PrivacyActivationLimitFieldV1::FcmpInputCount,
        statement.inputs.len(),
        limits.max_input_count,
    )?;
    validate_activation_statement_len(
        PrivacyActivationLimitFieldV1::FcmpOutputCount,
        statement.outputs.len(),
        limits.max_output_count,
    )
}
fn validate_ivm_private_note_activation_statement(
    limits: IvmPrivateNoteActivationLimitsV1,
    statement: &IrohaIvmPrivateNoteStarkStatementV1,
) -> Result<(), PrivacyActivationStatementLimitsError> {
    validate_activation_statement_len(
        PrivacyActivationLimitFieldV1::IvmPrivateNoteInputCount,
        statement.nullifiers.len(),
        limits.max_input_count,
    )?;
    validate_activation_statement_len(
        PrivacyActivationLimitFieldV1::IvmPrivateNoteOutputCount,
        statement.output_commitments.len(),
        limits.max_output_count,
    )
}
fn validate_pq_masp_activation_statement(
    limits: PqMaspActivationLimitsV1,
    statement: &PqMaspStarkStatementV1,
) -> Result<(), PrivacyActivationStatementLimitsError> {
    validate_activation_statement_len(
        PrivacyActivationLimitFieldV1::PqMaspInputCount,
        statement.nullifiers.len(),
        limits.max_input_count,
    )?;
    validate_activation_statement_len(
        PrivacyActivationLimitFieldV1::PqMaspOutputCount,
        statement.output_commitments.len(),
        limits.max_output_count,
    )
}
fn validate_activation_statement_count(
    field: PrivacyActivationLimitFieldV1,
    count: u32,
    max: u32,
) -> Result<(), PrivacyActivationStatementLimitsError> {
    if count > max {
        return Err(PrivacyActivationStatementLimitsError::CountExceeds { field, count, max });
    }
    Ok(())
}
fn validate_activation_statement_len(
    field: PrivacyActivationLimitFieldV1,
    count: usize,
    max: u32,
) -> Result<(), PrivacyActivationStatementLimitsError> {
    if count > max as usize {
        return Err(PrivacyActivationStatementLimitsError::CountExceeds {
            field,
            count: u32::try_from(count).unwrap_or(u32::MAX),
            max,
        });
    }
    Ok(())
}

#[cfg(test)]
mod captured_statements_schema_tests;
