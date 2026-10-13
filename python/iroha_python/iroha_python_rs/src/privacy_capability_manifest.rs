//! Source-bound Python view of the canonical Exact12 capability manifest.
//!
//! This module deliberately has no constructor from a local compiled-profile
//! catalog. Public archive decoding is inspection-only. Only the native fetch
//! boundary can bind an authenticated response from the configured Torii client
//! to its immutable local network identity for transaction construction.
use iroha_core_privacy::privacy_profiles::{CompiledPrivacyProfileV1, compiled_privacy_profile_v1};
use iroha_data_model::id::NetworkId;
use iroha_data_model::privacy::{
    IrohaZkX509StarkP256StatementV1, PrivacyCapabilityReadinessV1,
    PrivacyCapabilityUnavailableReasonV1, PrivacyCompiledProfileResultV1,
    PrivacyCompiledProfileSnapshotV1, PrivacyCompiledProfileUnavailableReasonV1,
    PrivacyConsensusLimitsV1, PrivacyEngineIdV1, PrivacyExact12CapabilityManifestV1,
    PrivacyExact12CapabilityRowV1, PrivacyProofBytesV1, PrivacyProofEnvelopeV1,
    PrivacyProofSystemIdV1, PrivacyProofV1, PrivacyProtocolActivationRecordV1, PrivacyProtocolIdV1,
    PrivacyProtocolLifecycleV1, PrivacyStatementV1, validate_privacy_capability_archive_v1,
};
use pyo3::{
    exceptions::{PyRuntimeError, PyValueError},
    prelude::*,
    types::{PyBytes, PyDict, PyList},
};
/// Validated canonical manifest bytes with a private optional Torii origin binding.
///
/// The Python class intentionally exposes no public constructor.  Instances
/// Public archive decoding applies native canonical and signature validation but grants
/// no admission. The transport-owned fetch function additionally pins the expected network.
#[pyclass(
    name = "PrivacyExact12CapabilityManifestV1",
    frozen,
    module = "iroha_native._crypto",
    from_py_object
)]
#[derive(Clone)]
pub(crate) struct PyPrivacyExact12CapabilityManifestV1 {
    manifest: PrivacyExact12CapabilityManifestV1,
    canonical_archive: Vec<u8>,
    authenticated_network_id: Option<NetworkId>,
}
impl PyPrivacyExact12CapabilityManifestV1 {
    pub(crate) fn decode(archive: &[u8]) -> PyResult<Self> {
        let status = validate_privacy_capability_archive_v1(archive);
        if !status.is_valid() {
            return Err(PyValueError::new_err(format!(
                "invalid canonical Exact12 capability manifest archive (native status {})",
                status.code()
            )));
        }
        let manifest: PrivacyExact12CapabilityManifestV1 = norito::decode_from_bytes(archive)
            .map_err(|_| {
                PyRuntimeError::new_err(
                    "native Exact12 capability manifest validation/decode disagreement",
                )
            })?;
        let canonical_archive = manifest.canonical_bytes().map_err(|_| {
            PyRuntimeError::new_err(
                "native Exact12 capability manifest validation/re-encoding disagreement",
            )
        })?;
        if canonical_archive.as_slice() != archive {
            return Err(PyRuntimeError::new_err(
                "native Exact12 capability manifest canonical bytes changed after validation",
            ));
        }
        Ok(Self {
            manifest,
            canonical_archive,
            authenticated_network_id: None,
        })
    }
    fn from_authenticated_torii(archive: &[u8], expected_network_id: NetworkId) -> PyResult<Self> {
        let mut decoded = Self::decode(archive)?;
        if decoded
            .manifest
            .qualification
            .as_ref()
            .is_some_and(|qualification| {
                qualification.deployment_qualification.network_id != expected_network_id
                    || &qualification.deployment_qualification.genesis_hash
                        != expected_network_id.as_bytes()
            })
        {
            return Err(PyValueError::new_err(
                "Exact12 deployment qualification belongs to a different network",
            ));
        }
        decoded.authenticated_network_id = Some(expected_network_id);
        Ok(decoded)
    }
    pub(crate) fn require_authenticated_network(
        &self,
        expected_network_id: NetworkId,
    ) -> PyResult<()> {
        let network_id = self.authenticated_network_id.ok_or_else(|| PyValueError::new_err(
            "Exact12 admission requires an authenticated Torii response; decoded archives are inspection-only",
        ))?;
        if network_id != expected_network_id {
            return Err(PyValueError::new_err(
                "Exact12 capability admission belongs to a different transaction network",
            ));
        }
        Ok(())
    }
    pub(crate) fn require_network_profile(
        &self,
        protocol_id: PrivacyProtocolIdV1,
    ) -> PyResult<CompiledPrivacyProfileV1> {
        let network_id = self.authenticated_network_id.ok_or_else(|| PyValueError::new_err(
            "Exact12 admission requires an authenticated Torii response; decoded archives are inspection-only",
        ))?;
        self.require_authenticated_network(network_id)?;
        let row = self
            .manifest
            .protocols
            .iter()
            .find(|row| row.protocol_id == protocol_id)
            .ok_or_else(|| {
                PyRuntimeError::new_err(format!(
                    "validated Exact12 manifest omitted protocol {}",
                    protocol_id.canonical_label()
                ))
            })?;
        if !row.is_network_available() {
            return Err(PyRuntimeError::new_err(format!(
                "privacy protocol {} is not available in the committed Exact12 manifest",
                protocol_id.canonical_label()
            )));
        }
        let PrivacyCompiledProfileResultV1::Available(network_profile) = row.compiled_profile
        else {
            return Err(PyRuntimeError::new_err(format!(
                "privacy protocol {} has no available committed compiled profile",
                protocol_id.canonical_label()
            )));
        };
        let local_profile = compiled_privacy_profile_v1(protocol_id).map_err(|error| {
            PyRuntimeError::new_err(format!(
                "local native profile for {} is unavailable: {error}",
                protocol_id.canonical_label()
            ))
        })?;
        let local_snapshot = PrivacyCompiledProfileSnapshotV1::from(local_profile);
        if network_profile != local_snapshot {
            return Err(PyRuntimeError::new_err(format!(
                "local native profile for {} does not match the committed Exact12 capability tuple",
                protocol_id.canonical_label()
            )));
        }
        Ok(local_profile)
    }
    pub(crate) fn require_governed_statement(
        &self,
        statement: &PrivacyStatementV1,
    ) -> PyResult<()> {
        self.require_authenticated_network(statement.context().network_id)?;
        self.require_network_profile(statement.protocol_id())?;
        let activation = self
            .manifest
            .protocols
            .iter()
            .find(|row| row.protocol_id == statement.protocol_id())
            .and_then(|row| row.activation.as_ref())
            .ok_or_else(|| PyValueError::new_err("Exact12 activation is absent"))?;
        require_governed_statement_v1(
            statement,
            activation,
            &self.manifest.consensus_policy.current_limits,
            self.manifest.committed_height,
        )
    }
    pub(crate) fn require_governed_x509_action(
        &self,
        statement: &IrohaZkX509StarkP256StatementV1,
        proof: &[u8],
    ) -> PyResult<()> {
        let limits = &self.manifest.consensus_policy.current_limits;
        if proof.is_empty() || proof.len() > limits.max_proof_bytes_per_action as usize {
            return Err(PyValueError::new_err(
                "Exact12 proof exceeds current consensus limits",
            ));
        }
        let statement = PrivacyStatementV1::IrohaZkX509StarkP256V1(statement.clone());
        self.require_governed_statement(&statement)?;
        let protocol_id = statement.protocol_id();
        let envelope = PrivacyProofEnvelopeV1::bind_v1(
            statement,
            PrivacyProofV1::IrohaZkX509StarkP256V1(PrivacyProofBytesV1::new(proof.to_vec())),
        )
        .map_err(|_| PyValueError::new_err("Exact12 statement encoding failed"))?;
        let activation = self
            .manifest
            .protocols
            .iter()
            .find(|row| row.protocol_id == protocol_id)
            .and_then(|row| row.activation.as_ref())
            .ok_or_else(|| PyValueError::new_err("Exact12 activation is absent"))?;
        require_governed_envelope_v1(
            &envelope,
            activation,
            limits,
            self.manifest.committed_height,
        )
    }
    #[cfg(test)]
    pub(crate) fn test_fetched_binding_for_protocol(
        protocol_id: PrivacyProtocolIdV1,
        network_id: NetworkId,
    ) -> Self {
        // Unit fixture for the post-fetch boundary; archive inspection itself grants no origin.
        let inspected = Self::test_binding_for_protocol(protocol_id);
        Self::from_authenticated_torii(&inspected.canonical_archive, network_id)
            .expect("validated test response at the authenticated transport boundary")
    }
    #[cfg(test)]
    pub(crate) fn test_binding_for_protocol(protocol_id: PrivacyProtocolIdV1) -> Self {
        use iroha_data_model::privacy::{
            PRIVACY_CAPABILITY_SNAPSHOT_VERSION_V1, PrivacyActiveLifecycleV1,
            PrivacyCapabilityRowV1, PrivacyCapabilitySnapshotV1, PrivacyConsensusPolicyV1,
            PrivacyProtocolLifecycleV1,
        };
        let catalog = iroha_core_privacy::privacy_profiles::compiled_privacy_profile_catalog_v1()
            .expect("test compiled-profile catalog");
        let protocols = catalog
            .protocols
            .into_iter()
            .map(|row| {
                let activation = (row.protocol_id == protocol_id).then(|| {
                    compiled_privacy_profile_v1(protocol_id)
                        .expect("selected test profile is compiled")
                        .activation_record(PrivacyProtocolLifecycleV1::Active(
                            PrivacyActiveLifecycleV1 {
                                proposed_at_height: 1,
                                activated_at_height: 2,
                                state_since_height: 2,
                            },
                        ))
                });
                PrivacyCapabilityRowV1 {
                    protocol_id: row.protocol_id,
                    compiled_profile: row.compiled_profile,
                    activation,
                }
            })
            .collect();
        let manifest = PrivacyCapabilitySnapshotV1 {
            version: PRIVACY_CAPABILITY_SNAPSHOT_VERSION_V1,
            committed_height: 3,
            consensus_policy: PrivacyConsensusPolicyV1::taira_default(),
            qualification: None,
            protocols,
        }
        .exact12_capability_manifest_v1()
        .expect("test Exact12 manifest");
        let archive = manifest.canonical_bytes().expect("test manifest archive");
        Self::decode(&archive).expect("test manifest binding")
    }
}

fn require_governed_statement_v1(
    statement: &PrivacyStatementV1,
    activation: &PrivacyProtocolActivationRecordV1,
    limits: &PrivacyConsensusLimitsV1,
    height: u64,
) -> PyResult<()> {
    activation
        .validate()
        .map_err(|error| PyValueError::new_err(format!("invalid Exact12 activation: {error}")))?;
    let PrivacyProtocolLifecycleV1::Active(active) = activation.lifecycle else {
        return Err(PyValueError::new_err("Exact12 activation is not active"));
    };
    let context = statement.context();
    if height < active.state_since_height
        || activation.protocol_id != statement.protocol_id()
        || activation.parameter_id != context.parameter_id
        || activation.parameter_digest != context.parameter_digest
        || activation.verifier_digest != context.verifier_digest
        || activation.statement_schema_digest != context.statement_schema_digest
        || activation.engine_manifest_digest != context.engine_manifest_digest
    {
        return Err(PyValueError::new_err(
            "Exact12 statement differs from the effective governed activation",
        ));
    }
    activation
        .protocol_limits
        .validate_statement(statement)
        .map_err(|error| {
            PyValueError::new_err(format!(
                "Exact12 governed statement limits rejected: {error}"
            ))
        })?;
    statement.validate(limits).map_err(|error| {
        PyValueError::new_err(format!(
            "Exact12 current consensus statement limits rejected: {error}"
        ))
    })
}

fn require_governed_envelope_v1(
    envelope: &PrivacyProofEnvelopeV1,
    activation: &PrivacyProtocolActivationRecordV1,
    limits: &PrivacyConsensusLimitsV1,
    height: u64,
) -> PyResult<()> {
    envelope
        .validate_against_activation(activation, limits, height)
        .map_err(|error| {
            PyValueError::new_err(format!(
                "Exact12 current governed envelope rejected: {error}"
            ))
        })
}
#[pymethods]
impl PyPrivacyExact12CapabilityManifestV1 {
    #[getter]
    fn canonical_archive<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.canonical_archive)
    }
    #[getter]
    fn manifest_digest<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.manifest.manifest_digest.as_bytes())
    }
    #[getter]
    const fn version(&self) -> u32 {
        self.manifest.version
    }
    #[getter]
    const fn committed_height(&self) -> u64 {
        self.manifest.committed_height
    }
    /// Return the exact twelve validated public capability tuples.
    fn protocol_tuples(&self, py: Python<'_>) -> PyResult<Py<PyList>> {
        let rows = PyList::empty(py);
        for row in &self.manifest.protocols {
            rows.append(capability_tuple_dict(py, &self.manifest, row)?)?;
        }
        Ok(rows.unbind())
    }
    /// Require one active committed row and exact equality with this binary.
    fn require_network_capability(
        &self,
        py: Python<'_>,
        protocol_id: &str,
    ) -> PyResult<Py<PyDict>> {
        let protocol_id = parse_protocol_id(protocol_id)?;
        self.require_network_profile(protocol_id)?;
        let row = self
            .manifest
            .protocols
            .iter()
            .find(|row| row.protocol_id == protocol_id)
            .expect("validated Exact12 manifest contains every canonical row");
        capability_tuple_dict(py, &self.manifest, row)
    }

    /// Reject offline inspection archives and admission replay across transaction networks.
    fn require_transaction_network(
        &self,
        network_id: PyRef<'_, crate::PyNetworkId>,
    ) -> PyResult<()> {
        self.require_authenticated_network(network_id.inner)
    }
}
fn parse_protocol_id(label: &str) -> PyResult<PrivacyProtocolIdV1> {
    PrivacyProtocolIdV1::from_canonical_label(label).ok_or_else(|| {
        PyValueError::new_err(
            "protocol_id must be one exact active Exact12 identifier; aliases and retired identifiers are rejected",
        )
    })
}
fn readiness_label(value: PrivacyCapabilityReadinessV1) -> &'static str {
    match value {
        PrivacyCapabilityReadinessV1::ProductionQualified => "production-qualified",
        PrivacyCapabilityReadinessV1::Unavailable(_) => "unavailable",
    }
}
fn compiled_profile_unavailable_reason_label(
    value: PrivacyCompiledProfileUnavailableReasonV1,
) -> &'static str {
    match value {
        PrivacyCompiledProfileUnavailableReasonV1::EngineUnavailable => "engine-unavailable",
        PrivacyCompiledProfileUnavailableReasonV1::ProfileInitializationFailed => {
            "profile-initialization-failed"
        }
        PrivacyCompiledProfileUnavailableReasonV1::StatementSchemaInvalid(_) => {
            "statement-schema-invalid"
        }
    }
}
fn unavailable_reason_label(value: PrivacyCapabilityUnavailableReasonV1) -> &'static str {
    match value {
        PrivacyCapabilityUnavailableReasonV1::CompiledProfile(reason) => {
            compiled_profile_unavailable_reason_label(reason)
        }
        PrivacyCapabilityUnavailableReasonV1::NotRegistered => "not-registered",
        PrivacyCapabilityUnavailableReasonV1::Proposed => "proposed",
        PrivacyCapabilityUnavailableReasonV1::Suspended => "suspended",
        PrivacyCapabilityUnavailableReasonV1::Retired => "retired",
        PrivacyCapabilityUnavailableReasonV1::MissingProductionQualification => {
            "missing-production-qualification"
        }
        PrivacyCapabilityUnavailableReasonV1::InvalidProductionQualification => {
            "invalid-production-qualification"
        }
    }
}
fn proof_system_label(value: PrivacyProofSystemIdV1) -> &'static str {
    match value {
        PrivacyProofSystemIdV1::StarkFriSha3_384Goldilocks => "stark-fri-sha3-384-goldilocks-v1",
        PrivacyProofSystemIdV1::ZkAmsMaskedRelaxedSpartanT256Ristretto255Sha3_512 => {
            "zk-ams-masked-relaxed-spartan-t256-ristretto255-sha3-512"
        }
        PrivacyProofSystemIdV1::AnonymousPgcP256 => "anonymous-pgc-p256",
        PrivacyProofSystemIdV1::IrohaVeRangeP256 => "iroha-verange-p256",
        PrivacyProofSystemIdV1::VegaNeutronNovaSpartanHyraxT256 => {
            "vega-neutron-nova-spartan-hyrax-t256"
        }
        PrivacyProofSystemIdV1::JindoPolynomialCommitment => "jindo-polynomial-commitment",
        PrivacyProofSystemIdV1::Halo2IpaPasta => "halo2-ipa-pasta",
        PrivacyProofSystemIdV1::FcmpPlusPlusCurveTreeBulletproofs => {
            "fcmp-plus-plus-curve-tree-bulletproofs"
        }
        PrivacyProofSystemIdV1::LanternLnp22ModuleLinearNorm => "lantern-lnp22-module-linear-norm",
    }
}
fn engine_label(value: PrivacyEngineIdV1) -> &'static str {
    match value {
        PrivacyEngineIdV1::NativeGoldilocksSha3_384StarkFri => {
            "native-goldilocks-sha3-384-stark-fri-v1"
        }
        PrivacyEngineIdV1::NativeZkAmsMaskedRelaxedSpartanT256Ristretto255 => {
            "native-zk-ams-masked-relaxed-spartan-t256-ristretto255"
        }
        PrivacyEngineIdV1::NativeAnonymousPgcP256 => "native-anonymous-pgc-p256",
        PrivacyEngineIdV1::NativeVeRangeP256 => "native-verange-p256",
        PrivacyEngineIdV1::NativeVega => "native-vega",
        PrivacyEngineIdV1::NativeJindo => "native-jindo",
        PrivacyEngineIdV1::NativeHalo2Orchard => "native-halo2-orchard",
        PrivacyEngineIdV1::NativeFcmpPlusPlus => "native-fcmp-plus-plus",
        PrivacyEngineIdV1::NativeLanternLnp22 => "native-lantern-lnp22",
    }
}
fn capability_tuple_dict(
    py: Python<'_>,
    manifest: &PrivacyExact12CapabilityManifestV1,
    row: &PrivacyExact12CapabilityRowV1,
) -> PyResult<Py<PyDict>> {
    let output = PyDict::new(py);
    output.set_item(
        "manifest_digest",
        PyBytes::new(py, manifest.manifest_digest.as_bytes()),
    )?;
    output.set_item("committed_height", manifest.committed_height)?;
    output.set_item("protocol_id", row.protocol_id.canonical_label())?;
    output.set_item("operation_schema", row.operation_schema.canonical_label())?;
    output.set_item("execution_mode", row.execution_mode.canonical_label())?;
    output.set_item("privacy_feature_mask", row.privacy_feature_mask.bits())?;
    output.set_item("readiness", readiness_label(row.readiness))?;
    let unavailable_reason = match row.readiness {
        PrivacyCapabilityReadinessV1::Unavailable(reason) => Some(unavailable_reason_label(reason)),
        PrivacyCapabilityReadinessV1::ProductionQualified => None,
    };
    output.set_item("unavailable_reason", unavailable_reason)?;
    output.set_item("network_available", row.is_network_available())?;
    match row.compiled_profile {
        PrivacyCompiledProfileResultV1::Available(profile) => {
            output.set_item("compiled_profile_status", "available")?;
            output.set_item(
                "proof_system_id",
                proof_system_label(profile.proof_system_id),
            )?;
            output.set_item("engine_id", engine_label(profile.engine_id))?;
            output.set_item(
                "parameter_id",
                PyBytes::new(py, profile.parameter_id.as_bytes()),
            )?;
            output.set_item(
                "parameter_digest",
                PyBytes::new(py, profile.parameter_digest.as_bytes()),
            )?;
            output.set_item(
                "verifier_digest",
                PyBytes::new(py, profile.verifier_digest.as_bytes()),
            )?;
            output.set_item(
                "statement_schema_digest",
                PyBytes::new(py, profile.statement_schema_digest.as_bytes()),
            )?;
            output.set_item(
                "engine_manifest_digest",
                PyBytes::new(py, profile.engine_manifest_digest.as_bytes()),
            )?;
        }
        PrivacyCompiledProfileResultV1::Unavailable(reason) => {
            output.set_item("compiled_profile_status", "unavailable")?;
            output.set_item(
                "unavailable_reason",
                compiled_profile_unavailable_reason_label(reason),
            )?;
            for key in [
                "proof_system_id",
                "engine_id",
                "parameter_id",
                "parameter_digest",
                "verifier_digest",
                "statement_schema_digest",
                "engine_manifest_digest",
            ] {
                output.set_item(key, py.None())?;
            }
        }
    }
    Ok(output.unbind())
}
#[pyfunction]
#[pyo3(name = "privacy_validate_exact12_capability_manifest_v1")]
pub(crate) fn privacy_validate_exact12_capability_manifest_v1_py(archive: &[u8]) -> i32 {
    validate_privacy_capability_archive_v1(archive).code()
}
#[pyfunction]
#[pyo3(name = "privacy_exact12_capability_manifest_v1")]
pub(crate) fn privacy_exact12_capability_manifest_v1_py(
    py: Python<'_>,
    archive: &[u8],
) -> PyResult<Py<PyPrivacyExact12CapabilityManifestV1>> {
    Py::new(py, PyPrivacyExact12CapabilityManifestV1::decode(archive)?)
}

/// Fetch through the fixed SDK transport owner; no caller-supplied archive can mint origin.
#[pyfunction]
#[pyo3(name = "_privacy_fetch_exact12_capability_manifest_v1")]
pub(crate) fn privacy_fetch_exact12_capability_manifest_v1_py(
    py: Python<'_>,
    client: &Bound<'_, PyAny>,
    canonical_auth: &Bound<'_, PyAny>,
) -> PyResult<Py<PyPrivacyExact12CapabilityManifestV1>> {
    let owner = py.import("iroha_python.client")?;
    if !client.get_type().is(&owner.getattr("ToriiClient")?) {
        return Err(PyValueError::new_err(
            "Exact12 admission requires the configured SDK ToriiClient transport owner",
        ));
    }
    let network = client
        .getattr("local_signing_context")?
        .getattr("network_id")?;
    let expected_network_id = network.extract::<PyRef<'_, crate::PyNetworkId>>()?.inner;
    let archive = owner
        .getattr("_fetch_authenticated_privacy_capabilities_archive_v1")?
        .call1((client, canonical_auth))?
        .extract::<Vec<u8>>()?;
    Py::new(
        py,
        PyPrivacyExact12CapabilityManifestV1::from_authenticated_torii(
            &archive,
            expected_network_id,
        )?,
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_data_model::privacy::PrivacyCapabilityArchiveValidationStatusV1;

    fn x509_governed_fixture() -> (PrivacyProofEnvelopeV1, PrivacyProtocolActivationRecordV1) {
        use iroha_data_model::privacy::{
            PrivacyActiveLifecycleV1, PrivacyProtocolActivationLimitsV1,
            privacy_exact12_fixture_bundle_v1,
        };
        let row = privacy_exact12_fixture_bundle_v1()
            .expect("canonical model fixture")
            .rows
            .into_iter()
            .find(|row| row.protocol_id == PrivacyProtocolIdV1::IrohaZkX509StarkP256V1)
            .expect("one X509 fixture row");
        let envelope: PrivacyProofEnvelopeV1 = norito::decode_from_bytes(&row.envelope_norito)
            .expect("canonical X509 envelope fixture");
        let activation = PrivacyProtocolActivationRecordV1 {
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
            protocol_limits: PrivacyProtocolActivationLimitsV1::IrohaZkX509StarkP256V1,
            pending_protocol_limits_tightening: None,
        };
        (envelope, activation)
    }

    #[test]
    fn x509_preparation_checks_effective_activation_and_current_statement_limits() {
        let (envelope, activation) = x509_governed_fixture();
        let limits = PrivacyConsensusLimitsV1::taira_default();
        assert!(
            require_governed_statement_v1(&envelope.statement, &activation, &limits, 3).is_ok()
        );
        assert!(
            require_governed_statement_v1(&envelope.statement, &activation, &limits, 1).is_err()
        );
        let mut other_verifier = activation;
        other_verifier.verifier_digest =
            iroha_data_model::privacy::PrivacyVerifierDigestV1::new([0x73; 32]);
        assert!(
            require_governed_statement_v1(&envelope.statement, &other_verifier, &limits, 3)
                .is_err()
        );
        let mut tightened = limits;
        tightened.max_statement_and_encrypted_output_bytes_per_transaction = 1;
        assert!(tightened.validate().is_ok());
        assert!(
            require_governed_statement_v1(&envelope.statement, &activation, &tightened, 3).is_err()
        );
    }

    #[test]
    fn x509_signing_checks_current_proof_and_action_byte_limits() {
        let (envelope, activation) = x509_governed_fixture();
        let limits = PrivacyConsensusLimitsV1::taira_default();
        // The fixture's model-valid proof bytes are not an engine proof or a release receipt.
        assert!(require_governed_envelope_v1(&envelope, &activation, &limits, 3).is_ok());
        let mut proof_tightened = limits;
        proof_tightened.max_proof_bytes_per_action = 2;
        assert!(proof_tightened.validate().is_ok());
        assert!(require_governed_envelope_v1(&envelope, &activation, &proof_tightened, 3).is_err());
        let mut action_tightened = limits;
        action_tightened.max_proof_bytes_per_action = 3;
        action_tightened.max_statement_and_encrypted_output_bytes_per_transaction = u32::try_from(
            norito::to_bytes(&envelope.statement)
                .expect("statement bytes")
                .len(),
        )
        .unwrap();
        action_tightened.max_action_bytes =
            u32::try_from(norito::to_bytes(&envelope).expect("envelope bytes").len() - 1).unwrap();
        assert!(action_tightened.validate().is_ok());
        assert!(
            require_governed_envelope_v1(&envelope, &activation, &action_tightened, 3).is_err()
        );
    }
    #[test]
    fn validation_status_codes_remain_the_data_model_contract() {
        assert_eq!(
            privacy_validate_exact12_capability_manifest_v1_py(&[]),
            PrivacyCapabilityArchiveValidationStatusV1::Empty.code()
        );
        assert_ne!(
            privacy_validate_exact12_capability_manifest_v1_py(b"local-catalog-shell"),
            PrivacyCapabilityArchiveValidationStatusV1::Valid.code()
        );
    }
    #[test]
    fn retired_and_alias_protocol_labels_are_not_selectable() {
        for label in [
            "jindo-lattice-pcs-zk-v0",
            "sis-with-hints",
            "zk-ams-recursive-admission-v0",
            "IROHA-ZK-AMS-V1",
            " iroha-zk-ams-v1",
        ] {
            assert!(parse_protocol_id(label).is_err(), "accepted {label}");
        }
    }
    #[test]
    fn validated_binding_preserves_bytes_and_fails_closed_without_registered_evidence() {
        let binding = PyPrivacyExact12CapabilityManifestV1::test_binding_for_protocol(
            PrivacyProtocolIdV1::AnonymousPgcKOutOfNV1,
        );
        assert_eq!(
            binding.canonical_archive,
            binding
                .manifest
                .canonical_bytes()
                .expect("validated manifest re-encodes")
        );
        assert!(
            binding
                .require_network_profile(PrivacyProtocolIdV1::AnonymousPgcKOutOfNV1)
                .is_err()
        );
        assert!(
            binding
                .require_network_profile(PrivacyProtocolIdV1::VegaExistingCredentialZkV1)
                .is_err()
        );
    }
    #[test]
    fn offline_archives_cannot_acquire_origin_and_fetched_bindings_pin_the_network() {
        let inspected = PyPrivacyExact12CapabilityManifestV1::test_binding_for_protocol(
            PrivacyProtocolIdV1::AnonymousPgcKOutOfNV1,
        );
        let network = crate::PyNetworkId::from_exact_bytes(&[0xA5; 32])
            .expect("marked canonical network")
            .inner;
        let other_network = crate::PyNetworkId::from_exact_bytes(&[0xA7; 32])
            .expect("different marked network")
            .inner;
        assert!(inspected.require_authenticated_network(network).is_err());
        // Exercise the private post-fetch constructor with a real Rust-validated unavailable
        // archive. This proves origin/network handling, not production qualification.
        let fetched = PyPrivacyExact12CapabilityManifestV1::from_authenticated_torii(
            &inspected.canonical_archive,
            network,
        )
        .expect("validated authenticated response boundary");
        assert!(fetched.require_authenticated_network(network).is_ok());
        assert!(
            fetched
                .require_authenticated_network(other_network)
                .is_err()
        );
        let replayed = PyPrivacyExact12CapabilityManifestV1::decode(&fetched.canonical_archive)
            .expect("archived bytes remain valid for inspection");
        assert!(replayed.require_authenticated_network(network).is_err());
        assert!(
            fetched
                .require_network_profile(PrivacyProtocolIdV1::AnonymousPgcKOutOfNV1)
                .is_err()
        );
    }
}
