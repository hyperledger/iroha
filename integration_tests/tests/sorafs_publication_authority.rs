//! Signed-genesis admission material and exact council-signed Parliament revocation proposals.
//!
//! These helpers only construct signed inputs. The network executes the sole genesis initializer
//! and the full Parliament lifecycle; no fixture writes native State or supplies an admission cache.
use eyre::{Result, ensure};
use iroha_crypto::{Algorithm, KeyPair, Signature};
use iroha_data_model::{
    NetworkId,
    account::AccountId,
    governance::types::{ProposalKind, SorafsProviderGovernanceProposal},
    isi::{
        InstructionBox,
        sorafs::{InitializeSorafsProviderAdmissionV1, SorafsProviderGovernanceActionV1},
    },
    sorafs::provider_admission::{
        ProviderAdmissionCouncilPolicyV1,
        governance::{
            InitialProviderAdmissionCouncilV1, InitialProviderAdmissionV1,
            ProviderAdmissionGovernanceActionV1,
        },
    },
};
use sorafs_manifest::{
    AdvertSignature, CouncilSignature, ProviderAdmissionEnvelopeV1, ProviderAdmissionRevocationV1,
    ProviderAdvertV1, SignatureAlgorithm,
    provider_admission::{ProviderAdmissionGenesisMaterialV1, compute_envelope_digest},
};
use std::time::{SystemTime, UNIX_EPOCH};

// Advertisement delivery, task submission, and terminal repair observation each have the
// transport helper's finite deadline. A source must remain discoverable for all three phases.
const ADVERT_VALIDITY_SECS: u64 = 3 * super::sorafs_publication_http::DEADLINE.as_secs();

/// Independent test custody and networkless admission inputs for the actual provider network.
pub struct PublicationAuthorityFixture {
    council_key: KeyPair,
    council: InitialProviderAdmissionCouncilV1,
    owners: Vec<AccountId>,
    materials: Vec<ProviderAdmissionGenesisMaterialV1>,
    advert_keys: Vec<KeyPair>,
}
impl PublicationAuthorityFixture {
    /// Create bounded deterministic public material and real independent software signing keys.
    /// Endpoint-attestation fields come from the structural admission fixture; this does not
    /// qualify external TLS endpoint attestation. Native test traffic authenticates signed requests.
    pub fn new(provider_ids: &[[u8; 32]], owners: &[AccountId]) -> Result<Self> {
        ensure!(
            !provider_ids.is_empty()
                && provider_ids.len() <= 64
                && provider_ids.len() == owners.len(),
            "bounded one-to-one provider owners required"
        );
        ensure!(
            provider_ids.windows(2).all(|pair| pair[0] < pair[1]),
            "provider ids must be strictly sorted"
        );
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let council_key = KeyPair::try_from_seed(vec![0xe1; 32], Algorithm::Ed25519)?;
        let council = InitialProviderAdmissionCouncilV1 {
            policy_id: [0xe2; 32],
            trusted_signers: vec![
                council_key
                    .public_key()
                    .try_to_bytes()?
                    .1
                    .try_into()
                    .map_err(|_| eyre::eyre!("Ed25519 key length"))?,
            ],
            signature_threshold: 1,
        };
        let reference: ProviderAdmissionEnvelopeV1 = norito::decode_from_bytes(include_bytes!(
            "../../fixtures/sorafs_manifest/provider_admission/envelope_v1.to"
        ))?;
        let mut materials = Vec::new();
        let mut advert_keys = Vec::new();
        for (index, provider) in provider_ids.iter().enumerate() {
            let key = KeyPair::try_from_seed(
                vec![0x80 + u8::try_from(index).expect("fixture provider index fits u8"); 32],
                Algorithm::Ed25519,
            )?;
            let vrf = KeyPair::try_from_seed(
                vec![0x80 + u8::try_from(index).expect("fixture provider index fits u8"); 32],
                Algorithm::BlsNormal,
            )?;
            let mut proposal = reference.proposal.clone();
            proposal.provider_id = *provider;
            proposal.advert_key = key
                .public_key()
                .try_to_bytes()?
                .1
                .try_into()
                .map_err(|_| eyre::eyre!("Ed25519 key length"))?;
            proposal.por_vrf_key =
                sorafs_manifest::provider_admission::ProviderVrfPublicKeyV1::BlsNormal(
                    vrf.public_key()
                        .try_to_bytes()?
                        .1
                        .try_into()
                        .map_err(|_| eyre::eyre!("BLS key length"))?,
                );
            for endpoint in &mut proposal.endpoints {
                endpoint.endpoint.kind = sorafs_manifest::provider_advert::EndpointKind::Torii;
                endpoint.endpoint.host_pattern = "127.0.0.1".into();
                endpoint.attestation.kind =
                    sorafs_manifest::provider_admission::EndpointAttestationKind::Tls;
                endpoint.attestation.attested_at = now - 120;
                endpoint.attestation.expires_at = now + 86400;
            }
            let mut advert_body = reference.advert_body.clone();
            advert_body.provider_id = *provider;
            advert_body.endpoints = proposal
                .endpoints
                .iter()
                .map(|entry| entry.endpoint.clone())
                .collect();
            let material = ProviderAdmissionGenesisMaterialV1 {
                proposal,
                advert_body,
                issued_at: now - 120,
                retention_epoch: now + 86400,
            };
            material.validate()?;
            materials.push(material);
            advert_keys.push(key);
        }
        Ok(Self {
            council_key,
            council,
            owners: owners.to_vec(),
            materials,
            advert_keys,
        })
    }
    /// Return the exact network-independent initializer; owners must be registered before it.
    pub fn genesis_instructions(&self) -> Result<Vec<InstructionBox>> {
        let providers = self
            .owners
            .iter()
            .cloned()
            .zip(&self.materials)
            .map(|(owner, material)| {
                Ok(InitialProviderAdmissionV1 {
                    owner,
                    material: norito::encode_canonical(material)?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(vec![
            InitializeSorafsProviderAdmissionV1 {
                council: self.council.clone(),
                providers,
            }
            .into(),
        ])
    }
    /// Derive the council installed by this exact signed genesis after its hash exists.
    pub fn policy(&self, network: NetworkId) -> Result<ProviderAdmissionCouncilPolicyV1> {
        Ok(self.council.bind(*network.as_bytes())?)
    }
    /// Derive unsigned initial material for an independently authenticated actual genesis.
    /// This projection is deliberately rejected by every council-envelope verifier.
    pub fn initial_material(
        &self,
        index: usize,
        network: NetworkId,
    ) -> Result<ProviderAdmissionEnvelopeV1> {
        let policy = self.policy(network)?;
        Ok(self
            .materials
            .get(index)
            .ok_or_else(|| eyre::eyre!("provider index"))?
            .project(
                policy.network_id,
                policy.policy_id,
                policy.canonical_digest()?,
            )?)
    }
    /// Sign a fresh provider advert that exactly matches the genesis-admitted body and key.
    pub fn advert(&self, index: usize, network: NetworkId, now: u64) -> Result<ProviderAdvertV1> {
        let material = self
            .materials
            .get(index)
            .ok_or_else(|| eyre::eyre!("provider index"))?;
        let expires_at = now
            .checked_add(ADVERT_VALIDITY_SECS)
            .ok_or_else(|| eyre::eyre!("advert validity overflow"))?;
        ensure!(
            now >= material.issued_at
                && expires_at < material.retention_epoch
                && material
                    .proposal
                    .endpoints
                    .iter()
                    .all(|endpoint| { expires_at <= endpoint.attestation.expires_at }),
            "advert operation window must fit within admission and endpoint validity"
        );
        let key = &self.advert_keys[index];
        let mut advert = ProviderAdvertV1 {
            version: 1,
            network_id: *network.as_bytes(),
            issued_at: now,
            expires_at,
            body: material.advert_body.clone(),
            signature: AdvertSignature {
                algorithm: SignatureAlgorithm::Ed25519,
                public_key: key.public_key().try_to_bytes()?.1.to_vec(),
                signature: Vec::new(),
            },
            signature_strict: true,
            allow_unknown_capabilities: false,
        };
        advert.signature.signature =
            Signature::try_new(key.private_key(), &advert.signature_payload_bytes()?)?
                .payload()
                .to_vec();
        advert.verify_signature()?;
        Ok(advert)
    }
    /// Construct the exact council-signed successor proposal for the full Parliament lifecycle.
    /// The input assumes the initial head is still current; certified enactment enforces its CAS.
    pub fn revocation_proposal(
        &self,
        index: usize,
        network: NetworkId,
        now: u64,
    ) -> Result<ProposalKind> {
        let policy = self.policy(network)?;
        let initial = self.initial_material(index, network)?;
        ensure!(
            now >= initial.issued_at,
            "revocation cannot predate admission"
        );
        let digest = compute_envelope_digest(&initial)?;
        let mut revocation = ProviderAdmissionRevocationV1 {
            version: 1,
            network_id: policy.network_id,
            policy_id: policy.policy_id,
            policy_revision: 1,
            policy_digest: policy.canonical_digest()?,
            transition_revision: 2,
            expected_current_event_digest: digest,
            provider_id: initial.proposal.provider_id,
            envelope_digest: digest,
            revoked_at: now,
            reason: "network qualification revocation".into(),
            council_signatures: Vec::new(),
            notes: None,
        };
        revocation.council_signatures.push(CouncilSignature {
            signer: policy.trusted_signers[0],
            signature: Signature::try_new(self.council_key.private_key(), &revocation.digest()?)?
                .payload()
                .to_vec(),
        });
        Ok(ProposalKind::SorafsProviderGovernance(
            SorafsProviderGovernanceProposal {
                action: Box::new(SorafsProviderGovernanceActionV1::Admission(
                    ProviderAdmissionGovernanceActionV1::Revoke(norito::encode_canonical(
                        &revocation,
                    )?),
                )),
            },
        ))
    }
}
#[test]
fn genesis_material_has_no_network_fixed_point_and_revoke_is_council_signed() -> Result<()> {
    let owner = AccountId::new(
        KeyPair::try_from_seed(vec![0x44; 32], Algorithm::Ed25519)?
            .public_key()
            .clone(),
    );
    let fixture = PublicationAuthorityFixture::new(&[[0xa0; 32]], &[owner])?;
    let instructions = fixture.genesis_instructions()?;
    let bytes = norito::encode_canonical(&instructions[0])?;
    let network = NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(
        iroha_crypto::Hash::new(&bytes),
    ));
    let projection = fixture.initial_material(0, network)?;
    ensure!(
        projection.network_id == *network.as_bytes() && projection.council_signatures.is_empty()
    );
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let advert = fixture.advert(0, network, now)?;
    advert.verify_signature()?;
    ensure!(advert.expires_at == now + ADVERT_VALIDITY_SECS);
    // Even a source fetched at the end of delivery + submission + completion remains valid.
    advert.validate(now + ADVERT_VALIDITY_SECS)?;
    ensure!(matches!(
        advert.validate(now + ADVERT_VALIDITY_SECS + 1),
        Err(sorafs_manifest::provider_advert::AdvertValidationError::Expired { .. })
    ));
    ensure!(
        fixture
            .advert(
                0,
                network,
                projection.retention_epoch - ADVERT_VALIDITY_SECS
            )
            .is_err()
    );
    let proposal = fixture.revocation_proposal(0, network, now)?;
    let ProposalKind::SorafsProviderGovernance(proposal) = proposal else {
        unreachable!()
    };
    let SorafsProviderGovernanceActionV1::Admission(ProviderAdmissionGovernanceActionV1::Revoke(
        bytes,
    )) = *proposal.action
    else {
        unreachable!()
    };
    let revoke: ProviderAdmissionRevocationV1 = norito::decode_canonical(&bytes)?;
    let policy = fixture.policy(network)?;
    sorafs_manifest::provider_admission::verify_revocation_signatures(
        &revoke,
        &sorafs_manifest::ProviderAdmissionCouncilPolicy::new(policy.trusted_signers, 1)?,
    )?;
    Ok(())
}
