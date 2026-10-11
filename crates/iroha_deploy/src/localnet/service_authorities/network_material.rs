//! One original network pricing/council selection shared by all generated providers.

use super::*;
use iroha_data_model::sorafs::{
    pricing::PricingScheduleRecord,
    provider_admission::governance::InitialProviderAdmissionCouncilV1,
};

pub(super) const COUNCIL_KEYS: [&str; 3] = [
    "provider-council-0.key",
    "provider-council-1.key",
    "provider-council-2.key",
];
const MAX_BYTES: usize = 64 * 1024;
const LIMITS: norito::DecodeLimits =
    norito::DecodeLimits::new(MAX_BYTES, MAX_BYTES, MAX_BYTES * 2, MAX_BYTES * 8, 32);

#[derive(Clone, Debug, PartialEq, Eq, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_deploy::localnet::service_authorities::NetworkServicePlanV1")]
pub(super) struct NetworkServicePlanV1 {
    pub(super) creation_time_ms: u64,
    pub(super) pricing: PricingScheduleRecord,
    pub(super) council: InitialProviderAdmissionCouncilV1,
}

fn council_id(operations: &AccountId) -> Result<[u8; 32]> {
    let bytes = norito::encode_canonical(operations)?;
    Ok(
        *Hash::new_from_chunks(&[b"iroha:localnet:provider-admission-council:v1\0", &bytes])
            .as_ref(),
    )
}
fn public32(key: &iroha_crypto::PublicKey) -> Result<[u8; 32]> {
    ensure!(
        key.algorithm() == iroha_crypto::Algorithm::Ed25519,
        "network council key algorithm differs"
    );
    key.to_bytes()
        .1
        .try_into()
        .map_err(|_| eyre!("network council key is invalid"))
}
impl NetworkServicePlanV1 {
    pub(super) fn generate(
        directory: &Path,
        seed: Option<&[u8]>,
        operations: &AccountId,
        unique: &mut BTreeSet<iroha_crypto::PublicKey>,
    ) -> Result<Self> {
        let creation_time_ms = u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_millis(),
        )?;
        let mut trusted_signers = Vec::with_capacity(COUNCIL_KEYS.len());
        for name in COUNCIL_KEYS {
            let label = format!("native-service-network/{name}");
            let key = localnet_ephemeral_identity(seed, label.as_bytes())?;
            ensure!(
                unique.insert(key.public_key.clone()),
                "network council keys must be distinct"
            );
            write_private_key_sidecar(&directory.join(name), key.private_key.as_str())?;
            trusted_signers.push(public32(&key.public_key)?);
        }
        trusted_signers.sort_unstable();
        let plan = Self {
            creation_time_ms,
            pricing: PricingScheduleRecord::launch_default(),
            council: InitialProviderAdmissionCouncilV1 {
                policy_id: council_id(operations)?,
                trusted_signers,
                signature_threshold: 2,
            },
        };
        plan.validate(operations)?;
        Ok(plan)
    }
    pub(super) fn validate(&self, operations: &AccountId) -> Result<()> {
        self.bytes()?;
        self.pricing.validate()?;
        ensure!(
            self.creation_time_ms > 0
                && self.creation_time_ms < u64::MAX
                && self.pricing == PricingScheduleRecord::launch_default()
                && self.council.policy_id == council_id(operations)?
                && self.council.trusted_signers.len() == COUNCIL_KEYS.len()
                && self
                    .council
                    .trusted_signers
                    .windows(2)
                    .all(|pair| pair[0] < pair[1])
                && self.council.signature_threshold == 2,
            "original network pricing or admission council differs"
        );
        Ok(())
    }
    pub(super) fn bytes(&self) -> Result<Vec<u8>> {
        let _flags = norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
        norito::core::to_bytes_bounded(self, MAX_BYTES).map_err(Into::into)
    }
    pub(super) fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(
            !bytes.is_empty() && bytes.len() <= MAX_BYTES,
            "network plan exceeds bound"
        );
        norito::decode_canonical_with_limits(bytes, LIMITS).map_err(Into::into)
    }
    pub(super) fn validate_keys(
        &self,
        directory: &capture::CapturedDirectory,
        unique: &mut BTreeSet<iroha_crypto::PublicKey>,
    ) -> Result<()> {
        let mut signers = Vec::with_capacity(COUNCIL_KEYS.len());
        for name in COUNCIL_KEYS {
            let key = read_service_private_key(directory, name)?;
            ensure!(
                unique.insert(key.public_key().clone()),
                "retained network council key is not distinct"
            );
            signers.push(public32(key.public_key())?);
        }
        signers.sort_unstable();
        ensure!(
            signers == self.council.trusted_signers,
            "retained network council keys differ"
        );
        directory.revalidate()?;
        Ok(())
    }
}
