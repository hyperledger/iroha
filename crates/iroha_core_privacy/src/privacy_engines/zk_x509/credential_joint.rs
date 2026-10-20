//! Exact joint auxiliary, oracle and opening transcript order for MAIN and CA.
//!
//! These public transcript records do not authenticate roots by themselves.
//! Consuming phase owners and the paired verifier must check each original
//! Merkle/FRI proof. Both local transcript states enter every joint transition,
//! including both complete local DEEP records and all 132 original-column openings.

use super::credential_pre_aux::ZkX509CredentialPreAuxBindingV1;
use super::proof_instance::ZkX509ProofInstanceV1;
use crate::privacy_engines::transparent_stark::{
    GoldilocksFp4V1 as E, PrivacyOuterDigestV1 as Digest, TransparentStarkErrorV1 as Error,
    TransparentTranscriptV1 as Transcript, privacy_outer_digest_frame_v1,
};

const AUX_DOMAIN: &[u8] = b"iroha:privacy:zk-x509:joint-auxiliary-roots:v1";
const ORACLE_DOMAIN: &[u8] = b"iroha:privacy:zk-x509:joint-original-oracles:v1";
const POINT_DOMAIN: &[u8] = b"iroha:privacy:zk-x509:joint-admitted-point:v1";
const OPENING_DOMAIN: &[u8] = b"iroha:privacy:zk-x509:joint-original-openings:v1";

/// Ordered subproof identity; never a caller-selected numerical tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JointSubproofV1 {
    Main,
    Ca,
}
impl JointSubproofV1 {
    fn context_v1(
        self,
        instance: ZkX509ProofInstanceV1,
    ) -> crate::privacy_engines::transparent_stark::TransparentStarkDigestContextV1 {
        match self {
            Self::Main => instance.main_context_v1(),
            Self::Ca => instance.ca_context_v1(),
        }
    }
    fn index(self) -> usize {
        match self {
            Self::Main => 0,
            Self::Ca => 1,
        }
    }
}

/// Public binding of both original auxiliary roots to the original X5B1 state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JointAuxiliaryBindingV1 {
    proof_instance: ZkX509ProofInstanceV1,
    pre_aux: Digest,
    roots: [Digest; 2],
    digest: Digest,
}
impl JointAuxiliaryBindingV1 {
    pub(crate) fn new_v1(
        binding: &ZkX509CredentialPreAuxBindingV1,
        roots: [Digest; 2],
    ) -> Result<Self, Error> {
        let proof_instance = binding.proof_instance_v1();
        let pre_aux = binding.transcript_state();
        let digest = privacy_outer_digest_frame_v1(
            proof_instance.joint_context_v1(),
            AUX_DOMAIN,
            b"main-then-ca",
            0,
            0,
            0,
            &[
                &pre_aux.to_bytes(),
                &roots[0].to_bytes(),
                &roots[1].to_bytes(),
            ],
        )?;
        Ok(Self {
            proof_instance,
            pre_aux,
            roots,
            digest,
        })
    }
    pub(crate) fn matches_v1(
        &self,
        binding: &ZkX509CredentialPreAuxBindingV1,
        family: JointSubproofV1,
        root: Digest,
    ) -> bool {
        self.proof_instance == binding.proof_instance_v1()
            && self.pre_aux == binding.transcript_state()
            && self.roots[family.index()] == root
    }
    pub(crate) fn absorb_v1(&self, transcript: &mut Transcript) -> Result<(), Error> {
        self.proof_instance.check_local_transcript_v1(transcript)?;
        transcript.absorb(
            AUX_DOMAIN,
            &[
                &self.digest.to_bytes(),
                &self.roots[0].to_bytes(),
                &self.roots[1].to_bytes(),
            ],
        )
    }
}

/// Both compositions, both independent FRI masks and both local checkpoints
/// precede the single shared point. Array positions are MAIN then CA.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JointOracleCheckpointsV1 {
    pub(crate) transcript_states: [Digest; 2],
    pub(crate) composition_roots: [Digest; 2],
    pub(crate) fri_mask_roots: [Digest; 2],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JointPointV1 {
    proof_instance: ZkX509ProofInstanceV1,
    point: E,
    sampled_state: Digest,
    checkpoints: [Digest; 2],
}
impl JointOracleCheckpointsV1 {
    pub(crate) fn derive_point_v1(
        self,
        auxiliary: JointAuxiliaryBindingV1,
        mut admissible: impl FnMut(E) -> bool,
    ) -> Result<JointPointV1, Error> {
        let proof_instance = auxiliary.proof_instance;
        let mut transcript = Transcript::new(
            proof_instance.joint_context_v1(),
            ORACLE_DOMAIN,
            &auxiliary.digest,
            &auxiliary.pre_aux,
        )?;
        transcript.absorb(
            ORACLE_DOMAIN,
            &[
                &self.transcript_states[0].to_bytes(),
                &self.transcript_states[1].to_bytes(),
                &self.composition_roots[0].to_bytes(),
                &self.composition_roots[1].to_bytes(),
                &self.fri_mask_roots[0].to_bytes(),
                &self.fri_mask_roots[1].to_bytes(),
            ],
        )?;
        let point = transcript.challenge_fp4_where(POINT_DOMAIN, |point| admissible(point))?;
        Ok(JointPointV1 {
            proof_instance,
            point,
            sampled_state: transcript.state(),
            checkpoints: self.transcript_states,
        })
    }
}
impl JointPointV1 {
    pub(crate) const fn point_v1(self) -> E {
        self.point
    }
    /// Refuse a transition from a different local transcript, rather than
    /// accepting a point supplied independently of its original oracle roots.
    pub(crate) fn absorb_v1(
        self,
        family: JointSubproofV1,
        transcript: &mut Transcript,
    ) -> Result<(), Error> {
        if transcript.context() != family.context_v1(self.proof_instance)
            || transcript.state() != self.checkpoints[family.index()]
        {
            return Err(Error::MalformedProof);
        }
        transcript.absorb(
            POINT_DOMAIN,
            &[
                &[family.index() as u8],
                &self.sampled_state.to_bytes(),
                &self.point.to_be_bytes(),
            ],
        )
    }
}

/// Exact public original-column openings carried by the credential envelope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JointOriginalOpeningsV1 {
    pub(crate) main: [E; 24],
    pub(crate) ca: [E; 108],
}
impl JointOriginalOpeningsV1 {
    pub(crate) const ENCODED_BYTES: usize = 132 * 32;
    pub(crate) fn validate_v1(&self) -> Result<(), Error> {
        if self
            .main
            .iter()
            .chain(&self.ca)
            .any(|value| !value.is_canonical())
        {
            return Err(Error::NonCanonicalField);
        }
        Ok(())
    }
    pub(crate) fn encode_v1(&self) -> Result<[u8; Self::ENCODED_BYTES], Error> {
        self.validate_v1()?;
        let mut bytes = [0; Self::ENCODED_BYTES];
        for (value, target) in self
            .main
            .iter()
            .chain(&self.ca)
            .zip(bytes.chunks_exact_mut(32))
        {
            target.copy_from_slice(&value.to_be_bytes());
        }
        Ok(bytes)
    }
    pub(crate) fn decode_v1(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != Self::ENCODED_BYTES {
            return Err(Error::MalformedProof);
        }
        let mut values = Self {
            main: [E::ZERO; 24],
            ca: [E::ZERO; 108],
        };
        for (target, source) in values
            .main
            .iter_mut()
            .chain(&mut values.ca)
            .zip(bytes.chunks_exact(32))
        {
            *target = E::canonical_be_bytes(source.try_into().map_err(|_| Error::MalformedProof)?)
                .ok_or(Error::MalformedProof)?;
        }
        Ok(values)
    }
    /// Both complete local DEEP records, including MAIN's31 key openings, are
    /// absorbed locally first. Their states plus all132 translated openings
    /// then enter both local transcripts before any DEEP batching coefficients.
    pub(crate) fn bind_both_v1(
        &self,
        proof_instance: ZkX509ProofInstanceV1,
        main: &mut Transcript,
        ca: &mut Transcript,
    ) -> Result<JointDeepBindingV1, Error> {
        if main.context() != proof_instance.main_context_v1()
            || ca.context() != proof_instance.ca_context_v1()
        {
            return Err(Error::MalformedProof);
        }
        self.validate_v1()?;
        let bytes = self.encode_v1()?;
        let digest = privacy_outer_digest_frame_v1(
            proof_instance.joint_context_v1(),
            OPENING_DOMAIN,
            b"both-local-deep-records",
            0,
            0,
            0,
            &[&main.state().to_bytes(), &ca.state().to_bytes(), &bytes],
        )?;
        main.absorb(OPENING_DOMAIN, &[b"main", &digest.to_bytes()])?;
        ca.absorb(OPENING_DOMAIN, &[b"ca", &digest.to_bytes()])?;
        Ok(JointDeepBindingV1 {
            proof_instance,
            states: [main.state(), ca.state()],
            openings: *self,
        })
    }
}

/// Consuming stages require the exact transcript after the paired opening bind.
/// Fields stay private so no unbound local DEEP state can create this token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JointDeepBindingV1 {
    proof_instance: ZkX509ProofInstanceV1,
    states: [Digest; 2],
    openings: JointOriginalOpeningsV1,
}
impl JointDeepBindingV1 {
    pub(crate) fn matches_v1(self, family: JointSubproofV1, transcript: &Transcript) -> bool {
        transcript.context() == family.context_v1(self.proof_instance)
            && self.states[family.index()] == transcript.state()
    }
    pub(crate) const fn openings_v1(self) -> JointOriginalOpeningsV1 {
        self.openings
    }
}

#[cfg(test)]
#[path = "credential_joint_tests.rs"]
mod tests;
