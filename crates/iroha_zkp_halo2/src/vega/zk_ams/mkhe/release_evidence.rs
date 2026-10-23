//! Canonical, digest-bound evidence records for MKHE release-readiness gates.
//!
//! Static accounting and a nonzero digest are not release evidence.  These
//! records keep the governed profile, validator binary, fixtures, measured
//! values, and rejection coverage in one versioned object.  The frozen
//! records intentionally contain no installed artifacts yet, so all three
//! gates remain fail-closed.

use super::{BgvProfile, MKHE_VERSION_V1, ZkAmsMkheErrorV1};

use super::resource::ZkAmsMkheResourceCertificateV1;

#[cfg(test)]
const WIRE_EVIDENCE_TAG_V1: [u8; 4] = *b"ZAMW";
#[cfg(test)]
const RESOURCE_EVIDENCE_TAG_V1: [u8; 4] = *b"ZAMR";
#[cfg(test)]
const RELEASE_KAT_EVIDENCE_TAG_V1: [u8; 4] = *b"ZAMK";
const REQUIRED_WIRE_CODEC_COUNT_V1: u16 = 7;

/// Exact canonical bytes in one wire-validation evidence record.
#[cfg(test)]
pub const ZK_AMS_MKHE_WIRE_EVIDENCE_BYTES_V1: usize = 185;
/// Exact canonical bytes in one measured-resource evidence record.
#[cfg(test)]
pub const ZK_AMS_MKHE_RESOURCE_EVIDENCE_BYTES_V1: usize = 261;
/// Exact canonical bytes in one release-KAT evidence record.
#[cfg(test)]
pub const ZK_AMS_MKHE_RELEASE_KAT_EVIDENCE_BYTES_V1: usize = 249;

/// Canonical positive/negative coverage evidence for all MKHE wire codecs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkAmsMkheWireEvidenceV1 {
    /// Evidence schema version.
    pub version: u8,
    /// Digest of the exact governed BGV profile.
    pub profile_digest: [u8; 32],
    /// Number of canonical MKHE codecs which require coverage.
    pub required_codec_count: u16,
    /// Number of canonical MKHE codecs covered by the installed artifact.
    pub covered_codec_count: u16,
    /// Number of successful canonical fixture cases.
    pub canonical_case_count: u32,
    /// Number of malformed or mismatched cases rejected before allocation.
    pub adversarial_case_count: u32,
    /// Largest canonical artifact exercised by the validation run.
    pub max_observed_artifact_bytes: u64,
    /// Digest of the ordered positive fixtures and their canonical encodings.
    pub canonical_fixture_digest: [u8; 32],
    /// Digest of the ordered negative fixtures and expected failures.
    pub adversarial_fixture_digest: [u8; 32],
    /// Digest of the exact validator binary used for the run.
    pub validator_binary_digest: [u8; 32],
    /// Digest of every preceding field.
    pub evidence_digest: [u8; 32],
}

impl ZkAmsMkheWireEvidenceV1 {
    /// Recompute the profile binding and evidence digest.
    #[cfg(test)]
    pub fn validate(self) -> Result<(), ZkAmsMkheErrorV1> {
        self.validate_for_profile(&super::manifest::release_profile_v1())
    }

    /// Return true only when all codecs have positive and adversarial coverage.
    #[must_use]
    pub fn is_complete(self) -> bool {
        self.required_codec_count != 0
            && self.covered_codec_count == self.required_codec_count
            && self.canonical_case_count >= u32::from(self.required_codec_count)
            && self.adversarial_case_count >= u32::from(self.required_codec_count)
            && self.max_observed_artifact_bytes != 0
            && self.canonical_fixture_digest != [0; 32]
            && self.adversarial_fixture_digest != [0; 32]
            && self.validator_binary_digest != [0; 32]
    }

    /// Encode the sole fixed-width canonical evidence representation.
    #[cfg(test)]
    pub fn to_canonical_bytes_v1(
        self,
    ) -> Result<[u8; ZK_AMS_MKHE_WIRE_EVIDENCE_BYTES_V1], ZkAmsMkheErrorV1> {
        self.validate()?;
        let mut bytes = [0_u8; ZK_AMS_MKHE_WIRE_EVIDENCE_BYTES_V1];
        let mut cursor = 0;
        write(&mut bytes, &mut cursor, &WIRE_EVIDENCE_TAG_V1)?;
        write(&mut bytes, &mut cursor, &[self.version])?;
        write(&mut bytes, &mut cursor, &self.profile_digest)?;
        write(
            &mut bytes,
            &mut cursor,
            &self.required_codec_count.to_be_bytes(),
        )?;
        write(
            &mut bytes,
            &mut cursor,
            &self.covered_codec_count.to_be_bytes(),
        )?;
        write(
            &mut bytes,
            &mut cursor,
            &self.canonical_case_count.to_be_bytes(),
        )?;
        write(
            &mut bytes,
            &mut cursor,
            &self.adversarial_case_count.to_be_bytes(),
        )?;
        write(
            &mut bytes,
            &mut cursor,
            &self.max_observed_artifact_bytes.to_be_bytes(),
        )?;
        write(&mut bytes, &mut cursor, &self.canonical_fixture_digest)?;
        write(&mut bytes, &mut cursor, &self.adversarial_fixture_digest)?;
        write(&mut bytes, &mut cursor, &self.validator_binary_digest)?;
        write(&mut bytes, &mut cursor, &self.evidence_digest)?;
        finish_encode(cursor, bytes.len())?;
        Ok(bytes)
    }

    /// Decode and validate exactly one canonical evidence record.
    #[cfg(test)]
    pub fn from_canonical_bytes_exact_v1(bytes: &[u8]) -> Result<Self, ZkAmsMkheErrorV1> {
        if bytes.len() != ZK_AMS_MKHE_WIRE_EVIDENCE_BYTES_V1 {
            return Err(ZkAmsMkheErrorV1::InvalidWireEncoding);
        }
        let mut decoder = EvidenceDecoder::new(bytes);
        decoder.expect_tag(WIRE_EVIDENCE_TAG_V1)?;
        let evidence = Self {
            version: decoder.u8()?,
            profile_digest: decoder.array()?,
            required_codec_count: decoder.u16()?,
            covered_codec_count: decoder.u16()?,
            canonical_case_count: decoder.u32()?,
            adversarial_case_count: decoder.u32()?,
            max_observed_artifact_bytes: decoder.u64()?,
            canonical_fixture_digest: decoder.array()?,
            adversarial_fixture_digest: decoder.array()?,
            validator_binary_digest: decoder.array()?,
            evidence_digest: decoder.array()?,
        };
        decoder.finish()?;
        evidence.validate()?;
        Ok(evidence)
    }

    pub(super) fn validate_for_profile(self, profile: &BgvProfile) -> Result<(), ZkAmsMkheErrorV1> {
        if self.version != MKHE_VERSION_V1
            || self.profile_digest != profile.digest()?
            || self.required_codec_count != REQUIRED_WIRE_CODEC_COUNT_V1
            || self.covered_codec_count > self.required_codec_count
            || self.evidence_digest == [0; 32]
            || self.evidence_digest != wire_evidence_digest_v1(self)
        {
            return Err(ZkAmsMkheErrorV1::InvalidWireEncoding);
        }
        Ok(())
    }
}

/// Canonical measurements and authenticated run-artifact digests for MKHE resources.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkAmsMkheResourceEvidenceV1 {
    /// Evidence schema version.
    pub version: u8,
    /// Digest of the exact governed BGV profile.
    pub profile_digest: [u8; 32],
    /// Largest canonical contribution proof observed in the release run.
    pub max_contribution_proof_bytes: u64,
    /// Exact evaluated-key payload published, retrieved, and streamed.
    pub evaluated_key_transport_bytes: u64,
    /// Work units in the complete measured Phase-II/III trace.
    pub phase23_work_units: u64,
    /// Peak resident bytes in the governed release worker topology.
    pub peak_resident_bytes: u64,
    /// Digest of the proof-size report and its raw samples.
    pub proof_size_artifact_digest: [u8; 32],
    /// Digest of the SoraFS publication/retrieval/stream-verification report.
    pub transport_artifact_digest: [u8; 32],
    /// Digest of the complete Phase-II/III work trace.
    pub phase23_trace_digest: [u8; 32],
    /// Digest of the peak-memory trace.
    pub peak_memory_trace_digest: [u8; 32],
    /// Digest of the exact validator binary used for every measurement.
    pub validator_binary_digest: [u8; 32],
    /// Digest of every preceding field.
    pub evidence_digest: [u8; 32],
}

impl ZkAmsMkheResourceEvidenceV1 {
    /// Recompute the profile binding and evidence digest.
    #[cfg(test)]
    pub fn validate(self) -> Result<(), ZkAmsMkheErrorV1> {
        self.validate_for_profile(&super::manifest::release_profile_v1())
    }

    /// Encode the sole fixed-width canonical evidence representation.
    #[cfg(test)]
    pub fn to_canonical_bytes_v1(
        self,
    ) -> Result<[u8; ZK_AMS_MKHE_RESOURCE_EVIDENCE_BYTES_V1], ZkAmsMkheErrorV1> {
        self.validate()?;
        let mut bytes = [0_u8; ZK_AMS_MKHE_RESOURCE_EVIDENCE_BYTES_V1];
        let mut cursor = 0;
        write(&mut bytes, &mut cursor, &RESOURCE_EVIDENCE_TAG_V1)?;
        write(&mut bytes, &mut cursor, &[self.version])?;
        write(&mut bytes, &mut cursor, &self.profile_digest)?;
        for value in [
            self.max_contribution_proof_bytes,
            self.evaluated_key_transport_bytes,
            self.phase23_work_units,
            self.peak_resident_bytes,
        ] {
            write(&mut bytes, &mut cursor, &value.to_be_bytes())?;
        }
        for digest in [
            self.proof_size_artifact_digest,
            self.transport_artifact_digest,
            self.phase23_trace_digest,
            self.peak_memory_trace_digest,
            self.validator_binary_digest,
            self.evidence_digest,
        ] {
            write(&mut bytes, &mut cursor, &digest)?;
        }
        finish_encode(cursor, bytes.len())?;
        Ok(bytes)
    }

    /// Decode and validate exactly one canonical evidence record.
    #[cfg(test)]
    pub fn from_canonical_bytes_exact_v1(bytes: &[u8]) -> Result<Self, ZkAmsMkheErrorV1> {
        if bytes.len() != ZK_AMS_MKHE_RESOURCE_EVIDENCE_BYTES_V1 {
            return Err(ZkAmsMkheErrorV1::InvalidWireEncoding);
        }
        let mut decoder = EvidenceDecoder::new(bytes);
        decoder.expect_tag(RESOURCE_EVIDENCE_TAG_V1)?;
        let evidence = Self {
            version: decoder.u8()?,
            profile_digest: decoder.array()?,
            max_contribution_proof_bytes: decoder.u64()?,
            evaluated_key_transport_bytes: decoder.u64()?,
            phase23_work_units: decoder.u64()?,
            peak_resident_bytes: decoder.u64()?,
            proof_size_artifact_digest: decoder.array()?,
            transport_artifact_digest: decoder.array()?,
            phase23_trace_digest: decoder.array()?,
            peak_memory_trace_digest: decoder.array()?,
            validator_binary_digest: decoder.array()?,
            evidence_digest: decoder.array()?,
        };
        decoder.finish()?;
        evidence.validate()?;
        Ok(evidence)
    }

    pub(super) fn closes_gate(
        self,
        profile: &BgvProfile,
        certificate: ZkAmsMkheResourceCertificateV1,
    ) -> bool {
        self.validate_for_profile(profile).is_ok()
            && self.max_contribution_proof_bytes != 0
            && self.max_contribution_proof_bytes <= certificate.max_round_contribution_proof_bytes
            && self.evaluated_key_transport_bytes
                == certificate.total_collective_evaluated_key_artifact_bytes
            && self.phase23_work_units != 0
            && self.phase23_work_units <= profile.max_work_units
            && self.peak_resident_bytes != 0
            && usize::try_from(self.peak_resident_bytes)
                .is_ok_and(|peak| peak <= profile.max_workspace_bytes)
            && self.proof_size_artifact_digest != [0; 32]
            && self.transport_artifact_digest != [0; 32]
            && self.phase23_trace_digest != [0; 32]
            && self.peak_memory_trace_digest != [0; 32]
            && self.validator_binary_digest != [0; 32]
    }

    fn validate_for_profile(self, profile: &BgvProfile) -> Result<(), ZkAmsMkheErrorV1> {
        if self.version != MKHE_VERSION_V1
            || self.profile_digest != profile.digest()?
            || self.evidence_digest == [0; 32]
            || self.evidence_digest != resource_evidence_digest_v1(self)
        {
            return Err(ZkAmsMkheErrorV1::InvalidWireEncoding);
        }
        Ok(())
    }
}

/// Canonical release-size positive and adversarial known-answer-test evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkAmsMkheReleaseKatEvidenceV1 {
    /// Evidence schema version.
    pub version: u8,
    /// Digest of the exact governed BGV profile.
    pub profile_digest: [u8; 32],
    /// Number of release-size positive cases which verified.
    pub positive_case_count: u32,
    /// Number of release-size adversarial cases executed.
    pub adversarial_case_count: u32,
    /// Number of those adversarial cases rejected by the production verifier.
    pub rejected_adversarial_case_count: u32,
    /// Largest canonical proof emitted by the release KAT.
    pub max_proof_bytes: u64,
    /// Digest of the exact release-size inputs and deterministic randomness.
    pub input_fixture_digest: [u8; 32],
    /// Governed digest expected from the positive release execution.
    pub expected_output_digest: [u8; 32],
    /// Digest recomputed from the positive release execution.
    pub observed_output_digest: [u8; 32],
    /// Digest of the complete ordered prove/verify/rejection transcript.
    pub transcript_digest: [u8; 32],
    /// Digest of the exact validator binary used for the run.
    pub validator_binary_digest: [u8; 32],
    /// Digest of every preceding field.
    pub evidence_digest: [u8; 32],
}

impl ZkAmsMkheReleaseKatEvidenceV1 {
    /// Recompute the profile binding and evidence digest.
    #[cfg(test)]
    pub fn validate(self) -> Result<(), ZkAmsMkheErrorV1> {
        self.validate_for_profile(&super::manifest::release_profile_v1())
    }

    /// Encode the sole fixed-width canonical evidence representation.
    #[cfg(test)]
    pub fn to_canonical_bytes_v1(
        self,
    ) -> Result<[u8; ZK_AMS_MKHE_RELEASE_KAT_EVIDENCE_BYTES_V1], ZkAmsMkheErrorV1> {
        self.validate()?;
        let mut bytes = [0_u8; ZK_AMS_MKHE_RELEASE_KAT_EVIDENCE_BYTES_V1];
        let mut cursor = 0;
        write(&mut bytes, &mut cursor, &RELEASE_KAT_EVIDENCE_TAG_V1)?;
        write(&mut bytes, &mut cursor, &[self.version])?;
        write(&mut bytes, &mut cursor, &self.profile_digest)?;
        for count in [
            self.positive_case_count,
            self.adversarial_case_count,
            self.rejected_adversarial_case_count,
        ] {
            write(&mut bytes, &mut cursor, &count.to_be_bytes())?;
        }
        write(&mut bytes, &mut cursor, &self.max_proof_bytes.to_be_bytes())?;
        for digest in [
            self.input_fixture_digest,
            self.expected_output_digest,
            self.observed_output_digest,
            self.transcript_digest,
            self.validator_binary_digest,
            self.evidence_digest,
        ] {
            write(&mut bytes, &mut cursor, &digest)?;
        }
        finish_encode(cursor, bytes.len())?;
        Ok(bytes)
    }

    /// Decode and validate exactly one canonical evidence record.
    #[cfg(test)]
    pub fn from_canonical_bytes_exact_v1(bytes: &[u8]) -> Result<Self, ZkAmsMkheErrorV1> {
        if bytes.len() != ZK_AMS_MKHE_RELEASE_KAT_EVIDENCE_BYTES_V1 {
            return Err(ZkAmsMkheErrorV1::InvalidWireEncoding);
        }
        let mut decoder = EvidenceDecoder::new(bytes);
        decoder.expect_tag(RELEASE_KAT_EVIDENCE_TAG_V1)?;
        let evidence = Self {
            version: decoder.u8()?,
            profile_digest: decoder.array()?,
            positive_case_count: decoder.u32()?,
            adversarial_case_count: decoder.u32()?,
            rejected_adversarial_case_count: decoder.u32()?,
            max_proof_bytes: decoder.u64()?,
            input_fixture_digest: decoder.array()?,
            expected_output_digest: decoder.array()?,
            observed_output_digest: decoder.array()?,
            transcript_digest: decoder.array()?,
            validator_binary_digest: decoder.array()?,
            evidence_digest: decoder.array()?,
        };
        decoder.finish()?;
        evidence.validate()?;
        Ok(evidence)
    }

    pub(super) fn closes_gate(self, profile: &BgvProfile) -> bool {
        self.validate_for_profile(profile).is_ok()
            && self.positive_case_count != 0
            && self.adversarial_case_count != 0
            && self.rejected_adversarial_case_count == self.adversarial_case_count
            && self.max_proof_bytes != 0
            && usize::try_from(self.max_proof_bytes)
                .is_ok_and(|bytes| bytes <= profile.max_round_bytes)
            && self.input_fixture_digest != [0; 32]
            && self.expected_output_digest != [0; 32]
            && self.observed_output_digest == self.expected_output_digest
            && self.transcript_digest != [0; 32]
            && self.validator_binary_digest != [0; 32]
    }

    fn validate_for_profile(self, profile: &BgvProfile) -> Result<(), ZkAmsMkheErrorV1> {
        if self.version != MKHE_VERSION_V1
            || self.profile_digest != profile.digest()?
            || self.rejected_adversarial_case_count > self.adversarial_case_count
            || self.evidence_digest == [0; 32]
            || self.evidence_digest != release_kat_evidence_digest_v1(self)
        {
            return Err(ZkAmsMkheErrorV1::InvalidWireEncoding);
        }
        Ok(())
    }
}

pub(super) fn frozen_wire_evidence_v1(
    profile: &BgvProfile,
) -> Result<ZkAmsMkheWireEvidenceV1, ZkAmsMkheErrorV1> {
    // TODO: Replace the zero artifact fields with the governed full-shape
    // positive/adversarial wire-validation report after that run exists.
    let mut evidence = ZkAmsMkheWireEvidenceV1 {
        version: MKHE_VERSION_V1,
        profile_digest: profile.digest()?,
        required_codec_count: REQUIRED_WIRE_CODEC_COUNT_V1,
        covered_codec_count: 0,
        canonical_case_count: 0,
        adversarial_case_count: 0,
        max_observed_artifact_bytes: 0,
        canonical_fixture_digest: [0; 32],
        adversarial_fixture_digest: [0; 32],
        validator_binary_digest: [0; 32],
        evidence_digest: [0; 32],
    };
    evidence.evidence_digest = wire_evidence_digest_v1(evidence);
    evidence.validate_for_profile(profile)?;
    Ok(evidence)
}

pub(super) fn frozen_resource_evidence_v1(
    profile: &BgvProfile,
) -> Result<ZkAmsMkheResourceEvidenceV1, ZkAmsMkheErrorV1> {
    // TODO: Install authenticated proof-size, SoraFS, work, and RSS reports
    // together.  Partial or synthetic static accounting must not close this gate.
    let mut evidence = ZkAmsMkheResourceEvidenceV1 {
        version: MKHE_VERSION_V1,
        profile_digest: profile.digest()?,
        max_contribution_proof_bytes: 0,
        evaluated_key_transport_bytes: 0,
        phase23_work_units: 0,
        peak_resident_bytes: 0,
        proof_size_artifact_digest: [0; 32],
        transport_artifact_digest: [0; 32],
        phase23_trace_digest: [0; 32],
        peak_memory_trace_digest: [0; 32],
        validator_binary_digest: [0; 32],
        evidence_digest: [0; 32],
    };
    evidence.evidence_digest = resource_evidence_digest_v1(evidence);
    evidence.validate_for_profile(profile)?;
    Ok(evidence)
}

pub(super) fn frozen_release_kat_evidence_v1(
    profile: &BgvProfile,
) -> Result<ZkAmsMkheReleaseKatEvidenceV1, ZkAmsMkheErrorV1> {
    // TODO: Install the governed release-size positive/adversarial KAT only
    // after the production prover and verifier produce the authenticated run.
    let mut evidence = ZkAmsMkheReleaseKatEvidenceV1 {
        version: MKHE_VERSION_V1,
        profile_digest: profile.digest()?,
        positive_case_count: 0,
        adversarial_case_count: 0,
        rejected_adversarial_case_count: 0,
        max_proof_bytes: 0,
        input_fixture_digest: [0; 32],
        expected_output_digest: [0; 32],
        observed_output_digest: [0; 32],
        transcript_digest: [0; 32],
        validator_binary_digest: [0; 32],
        evidence_digest: [0; 32],
    };
    evidence.evidence_digest = release_kat_evidence_digest_v1(evidence);
    evidence.validate_for_profile(profile)?;
    Ok(evidence)
}

fn wire_evidence_digest_v1(evidence: ZkAmsMkheWireEvidenceV1) -> [u8; 32] {
    let mut hash = super::native_outer_identity_v1(
        super::NativeOuterIdentityRoleV1::Release,
        b"iroha.zk-ams.v1.mkhe.wire-validation-evidence",
        10,
    );
    hash.push_field(&[evidence.version])
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&evidence.profile_digest)
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&evidence.required_codec_count.to_be_bytes())
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&evidence.covered_codec_count.to_be_bytes())
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&evidence.canonical_case_count.to_be_bytes())
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&evidence.adversarial_case_count.to_be_bytes())
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&evidence.max_observed_artifact_bytes.to_be_bytes())
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&evidence.canonical_fixture_digest)
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&evidence.adversarial_fixture_digest)
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&evidence.validator_binary_digest)
        .expect("fixed bounded MKHE identity field");
    *hash
        .finish()
        .expect("exact MKHE outer identity field count")
        .as_bytes()
}

fn resource_evidence_digest_v1(evidence: ZkAmsMkheResourceEvidenceV1) -> [u8; 32] {
    let mut hash = super::native_outer_identity_v1(
        super::NativeOuterIdentityRoleV1::Release,
        b"iroha.zk-ams.v1.mkhe.measured-resource-evidence",
        11,
    );
    hash.push_field(&[evidence.version])
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&evidence.profile_digest)
        .expect("fixed bounded MKHE identity field");
    for value in [
        evidence.max_contribution_proof_bytes,
        evidence.evaluated_key_transport_bytes,
        evidence.phase23_work_units,
        evidence.peak_resident_bytes,
    ] {
        hash.push_field(&value.to_be_bytes())
            .expect("fixed bounded MKHE identity field");
    }
    for digest in [
        evidence.proof_size_artifact_digest,
        evidence.transport_artifact_digest,
        evidence.phase23_trace_digest,
        evidence.peak_memory_trace_digest,
        evidence.validator_binary_digest,
    ] {
        hash.push_field(&digest)
            .expect("fixed bounded MKHE identity field");
    }
    *hash
        .finish()
        .expect("exact MKHE outer identity field count")
        .as_bytes()
}

fn release_kat_evidence_digest_v1(evidence: ZkAmsMkheReleaseKatEvidenceV1) -> [u8; 32] {
    let mut hash = super::native_outer_identity_v1(
        super::NativeOuterIdentityRoleV1::Release,
        b"iroha.zk-ams.v1.mkhe.release-kat-evidence",
        11,
    );
    hash.push_field(&[evidence.version])
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&evidence.profile_digest)
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&evidence.positive_case_count.to_be_bytes())
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&evidence.adversarial_case_count.to_be_bytes())
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&evidence.rejected_adversarial_case_count.to_be_bytes())
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&evidence.max_proof_bytes.to_be_bytes())
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&evidence.input_fixture_digest)
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&evidence.expected_output_digest)
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&evidence.observed_output_digest)
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&evidence.transcript_digest)
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&evidence.validator_binary_digest)
        .expect("fixed bounded MKHE identity field");
    *hash
        .finish()
        .expect("exact MKHE outer identity field count")
        .as_bytes()
}

#[cfg(test)]
fn write<const N: usize>(
    destination: &mut [u8; N],
    cursor: &mut usize,
    source: &[u8],
) -> Result<(), ZkAmsMkheErrorV1> {
    let end = cursor
        .checked_add(source.len())
        .ok_or(ZkAmsMkheErrorV1::InvalidWireEncoding)?;
    let output = destination
        .get_mut(*cursor..end)
        .ok_or(ZkAmsMkheErrorV1::InvalidWireEncoding)?;
    output.copy_from_slice(source);
    *cursor = end;
    Ok(())
}

#[cfg(test)]
fn finish_encode(cursor: usize, expected: usize) -> Result<(), ZkAmsMkheErrorV1> {
    if cursor != expected {
        return Err(ZkAmsMkheErrorV1::InvalidWireEncoding);
    }
    Ok(())
}

#[cfg(test)]
struct EvidenceDecoder<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

#[cfg(test)]
impl<'a> EvidenceDecoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], ZkAmsMkheErrorV1> {
        let end = self
            .cursor
            .checked_add(N)
            .ok_or(ZkAmsMkheErrorV1::InvalidWireEncoding)?;
        let value = self
            .bytes
            .get(self.cursor..end)
            .ok_or(ZkAmsMkheErrorV1::InvalidWireEncoding)?
            .try_into()
            .map_err(|_| ZkAmsMkheErrorV1::InvalidWireEncoding)?;
        self.cursor = end;
        Ok(value)
    }

    fn expect_tag(&mut self, expected: [u8; 4]) -> Result<(), ZkAmsMkheErrorV1> {
        if self.array::<4>()? != expected {
            return Err(ZkAmsMkheErrorV1::InvalidWireEncoding);
        }
        Ok(())
    }

    fn u8(&mut self) -> Result<u8, ZkAmsMkheErrorV1> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, ZkAmsMkheErrorV1> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, ZkAmsMkheErrorV1> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, ZkAmsMkheErrorV1> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn finish(self) -> Result<(), ZkAmsMkheErrorV1> {
        if self.cursor != self.bytes.len() {
            return Err(ZkAmsMkheErrorV1::InvalidWireEncoding);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frozen_records_roundtrip_canonically_but_remain_incomplete() {
        let profile = super::super::manifest::release_profile_v1();
        let resource_certificate =
            super::super::manifest::zk_ams_mkhe_resource_certificate_v1().unwrap();

        let wire = frozen_wire_evidence_v1(&profile).unwrap();
        let wire_bytes = wire.to_canonical_bytes_v1().unwrap();
        assert_eq!(
            ZkAmsMkheWireEvidenceV1::from_canonical_bytes_exact_v1(&wire_bytes).unwrap(),
            wire
        );
        assert!(!wire.is_complete());

        let resource = frozen_resource_evidence_v1(&profile).unwrap();
        let resource_bytes = resource.to_canonical_bytes_v1().unwrap();
        assert_eq!(
            ZkAmsMkheResourceEvidenceV1::from_canonical_bytes_exact_v1(&resource_bytes).unwrap(),
            resource
        );
        assert!(!resource.closes_gate(&profile, resource_certificate));

        let kat = frozen_release_kat_evidence_v1(&profile).unwrap();
        let kat_bytes = kat.to_canonical_bytes_v1().unwrap();
        assert_eq!(
            ZkAmsMkheReleaseKatEvidenceV1::from_canonical_bytes_exact_v1(&kat_bytes).unwrap(),
            kat
        );
        assert!(!kat.closes_gate(&profile));
    }

    #[test]
    fn canonical_decoders_reject_lengths_tags_and_digest_mutation() {
        let profile = super::super::manifest::release_profile_v1();
        let mut cases = [
            frozen_wire_evidence_v1(&profile)
                .unwrap()
                .to_canonical_bytes_v1()
                .unwrap()
                .to_vec(),
            frozen_resource_evidence_v1(&profile)
                .unwrap()
                .to_canonical_bytes_v1()
                .unwrap()
                .to_vec(),
            frozen_release_kat_evidence_v1(&profile)
                .unwrap()
                .to_canonical_bytes_v1()
                .unwrap()
                .to_vec(),
        ];
        for (index, bytes) in cases.iter_mut().enumerate() {
            let truncated = &bytes[..bytes.len() - 1];
            let truncated_result = match index {
                0 => ZkAmsMkheWireEvidenceV1::from_canonical_bytes_exact_v1(truncated).map(|_| ()),
                1 => ZkAmsMkheResourceEvidenceV1::from_canonical_bytes_exact_v1(truncated)
                    .map(|_| ()),
                _ => ZkAmsMkheReleaseKatEvidenceV1::from_canonical_bytes_exact_v1(truncated)
                    .map(|_| ()),
            };
            assert_eq!(truncated_result, Err(ZkAmsMkheErrorV1::InvalidWireEncoding));

            let mut trailing = bytes.clone();
            trailing.push(0);
            let trailing_result = match index {
                0 => ZkAmsMkheWireEvidenceV1::from_canonical_bytes_exact_v1(&trailing).map(|_| ()),
                1 => ZkAmsMkheResourceEvidenceV1::from_canonical_bytes_exact_v1(&trailing)
                    .map(|_| ()),
                _ => ZkAmsMkheReleaseKatEvidenceV1::from_canonical_bytes_exact_v1(&trailing)
                    .map(|_| ()),
            };
            assert_eq!(trailing_result, Err(ZkAmsMkheErrorV1::InvalidWireEncoding));

            bytes[0] ^= 1;
            let bad_tag_result = match index {
                0 => ZkAmsMkheWireEvidenceV1::from_canonical_bytes_exact_v1(bytes).map(|_| ()),
                1 => ZkAmsMkheResourceEvidenceV1::from_canonical_bytes_exact_v1(bytes).map(|_| ()),
                _ => {
                    ZkAmsMkheReleaseKatEvidenceV1::from_canonical_bytes_exact_v1(bytes).map(|_| ())
                }
            };
            assert_eq!(bad_tag_result, Err(ZkAmsMkheErrorV1::InvalidWireEncoding));
            bytes[0] ^= 1;
            bytes[40] ^= 1;
            let bad_digest_result = match index {
                0 => ZkAmsMkheWireEvidenceV1::from_canonical_bytes_exact_v1(bytes).map(|_| ()),
                1 => ZkAmsMkheResourceEvidenceV1::from_canonical_bytes_exact_v1(bytes).map(|_| ()),
                _ => {
                    ZkAmsMkheReleaseKatEvidenceV1::from_canonical_bytes_exact_v1(bytes).map(|_| ())
                }
            };
            assert_eq!(
                bad_digest_result,
                Err(ZkAmsMkheErrorV1::InvalidWireEncoding)
            );
        }
    }

    #[test]
    fn every_evidence_axis_is_digest_bound() {
        let profile = super::super::manifest::release_profile_v1();

        let wire = frozen_wire_evidence_v1(&profile).unwrap();
        for changed in [
            ZkAmsMkheWireEvidenceV1 {
                version: wire.version + 1,
                ..wire
            },
            ZkAmsMkheWireEvidenceV1 {
                profile_digest: [1; 32],
                ..wire
            },
            ZkAmsMkheWireEvidenceV1 {
                required_codec_count: wire.required_codec_count + 1,
                ..wire
            },
            ZkAmsMkheWireEvidenceV1 {
                covered_codec_count: 1,
                ..wire
            },
            ZkAmsMkheWireEvidenceV1 {
                canonical_case_count: 1,
                ..wire
            },
            ZkAmsMkheWireEvidenceV1 {
                adversarial_case_count: 1,
                ..wire
            },
            ZkAmsMkheWireEvidenceV1 {
                max_observed_artifact_bytes: 1,
                ..wire
            },
            ZkAmsMkheWireEvidenceV1 {
                canonical_fixture_digest: [1; 32],
                ..wire
            },
            ZkAmsMkheWireEvidenceV1 {
                adversarial_fixture_digest: [1; 32],
                ..wire
            },
            ZkAmsMkheWireEvidenceV1 {
                validator_binary_digest: [1; 32],
                ..wire
            },
        ] {
            assert_ne!(wire_evidence_digest_v1(changed), wire.evidence_digest);
        }

        let resource = frozen_resource_evidence_v1(&profile).unwrap();
        for changed in [
            ZkAmsMkheResourceEvidenceV1 {
                version: resource.version + 1,
                ..resource
            },
            ZkAmsMkheResourceEvidenceV1 {
                profile_digest: [1; 32],
                ..resource
            },
            ZkAmsMkheResourceEvidenceV1 {
                max_contribution_proof_bytes: 1,
                ..resource
            },
            ZkAmsMkheResourceEvidenceV1 {
                evaluated_key_transport_bytes: 1,
                ..resource
            },
            ZkAmsMkheResourceEvidenceV1 {
                phase23_work_units: 1,
                ..resource
            },
            ZkAmsMkheResourceEvidenceV1 {
                peak_resident_bytes: 1,
                ..resource
            },
            ZkAmsMkheResourceEvidenceV1 {
                proof_size_artifact_digest: [1; 32],
                ..resource
            },
            ZkAmsMkheResourceEvidenceV1 {
                transport_artifact_digest: [1; 32],
                ..resource
            },
            ZkAmsMkheResourceEvidenceV1 {
                phase23_trace_digest: [1; 32],
                ..resource
            },
            ZkAmsMkheResourceEvidenceV1 {
                peak_memory_trace_digest: [1; 32],
                ..resource
            },
            ZkAmsMkheResourceEvidenceV1 {
                validator_binary_digest: [1; 32],
                ..resource
            },
        ] {
            assert_ne!(
                resource_evidence_digest_v1(changed),
                resource.evidence_digest
            );
        }

        let kat = frozen_release_kat_evidence_v1(&profile).unwrap();
        for changed in [
            ZkAmsMkheReleaseKatEvidenceV1 {
                version: kat.version + 1,
                ..kat
            },
            ZkAmsMkheReleaseKatEvidenceV1 {
                profile_digest: [1; 32],
                ..kat
            },
            ZkAmsMkheReleaseKatEvidenceV1 {
                positive_case_count: 1,
                ..kat
            },
            ZkAmsMkheReleaseKatEvidenceV1 {
                adversarial_case_count: 1,
                ..kat
            },
            ZkAmsMkheReleaseKatEvidenceV1 {
                rejected_adversarial_case_count: 1,
                ..kat
            },
            ZkAmsMkheReleaseKatEvidenceV1 {
                max_proof_bytes: 1,
                ..kat
            },
            ZkAmsMkheReleaseKatEvidenceV1 {
                input_fixture_digest: [1; 32],
                ..kat
            },
            ZkAmsMkheReleaseKatEvidenceV1 {
                expected_output_digest: [1; 32],
                ..kat
            },
            ZkAmsMkheReleaseKatEvidenceV1 {
                observed_output_digest: [1; 32],
                ..kat
            },
            ZkAmsMkheReleaseKatEvidenceV1 {
                transcript_digest: [1; 32],
                ..kat
            },
            ZkAmsMkheReleaseKatEvidenceV1 {
                validator_binary_digest: [1; 32],
                ..kat
            },
        ] {
            assert_ne!(release_kat_evidence_digest_v1(changed), kat.evidence_digest);
        }
    }
}
