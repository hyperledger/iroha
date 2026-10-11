//! One immutable closed setup intent; transaction and once-only marker remain wallet-owned.

use super::*;
use crate::managed::native_operation::attempts::{self, History, Observation, Purpose, Selected};
use crate::managed::native_operation::{MAX_CHECKPOINT_BYTES, read_optional};
use iroha_fs::PublishMode;

pub(super) const MAX_INTENT_BYTES: usize = 64 * 1024;
const MAX_SELECTION_BYTES: usize = 16 * 1024;
const MAX_ORIGINAL_BYTES: usize = MAX_CHECKPOINT_BYTES + MAX_INTENT_BYTES + 16 * 1024;
#[derive(Clone, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_deploy::managed::service_setup::Intent")]
pub(super) enum Intent {
    ProviderIngest {
        chain_id: String,
        network_id: iroha_data_model::NetworkId,
        provider_id: iroha_data_model::sorafs::capacity::ProviderId,
        authority: ProviderIngestCompletionAuthorityV1,
    },
    Gateway {
        selection: InitialGatewaySetupSelection,
        policy: StreamTokenGatewayPolicyV1,
    },
    Reputation {
        selection: InitialReputationPolicySelection,
        policy: ReputationJournalAuthorityPolicyV1,
    },
}
impl Intent {
    pub(super) fn kind(&self) -> Kind {
        match self {
            Self::ProviderIngest { .. } => Kind::ProviderIngest,
            Self::Gateway { .. } => Kind::Gateway,
            Self::Reputation { .. } => Kind::Reputation,
        }
    }
    pub(super) fn provider_ingest(
        selected: &ServiceAuthority,
        authority: &ProviderIngestCompletionAuthorityV1,
    ) -> Result<Self> {
        encode(authority, 16 * 1024)?;
        if &authority.provider_owner
            != selected.provider_role(StreamTokenAuthorityRole::IssuerOperator)?
            || &authority.completion_signer
                != selected.provider_role(StreamTokenAuthorityRole::ProviderIngest)?
        {
            return Err(invalid(
                "ingest authority differs from original generated owner and completion role",
            ));
        }
        let value = Self::ProviderIngest {
            chain_id: selected.config.chain.to_string(),
            network_id: selected.config.network_id,
            provider_id: selected.provider_id()?,
            authority: authority.clone(),
        };
        value.validate()?;
        Ok(value)
    }
    pub(super) fn gateway(
        authority: &ServiceAuthority,
        policy: &StreamTokenGatewayPolicyV1,
    ) -> Result<Self> {
        encode(policy, 16 * 1024)?;
        let value = Self::Gateway {
            selection: InitialGatewaySetupSelection {
                chain_id: authority.config.chain.to_string(),
                network_id: authority.config.network_id,
                manager: authority.config.account.clone(),
                compliance_gateway_id: policy.compliance_gateway_id.clone(),
                gateway_id: derive_stream_token_gateway_id_v1(
                    &authority.config.network_id,
                    &policy.compliance_gateway_id,
                )
                .map_err(|_| invalid("invalid selected gateway label"))?,
                policy_digest: policy.qualification.policy_digest,
                operator: authority
                    .provider_role(StreamTokenAuthorityRole::GatewayOperator)?
                    .clone(),
                observer: authority
                    .provider_role(StreamTokenAuthorityRole::GatewayObserver)?
                    .clone(),
            },
            policy: policy.clone(),
        };
        value.validate()?;
        Ok(value)
    }
    pub(super) fn reputation(
        authority: &ServiceAuthority,
        labels: &[String],
        policy: &ReputationJournalAuthorityPolicyV1,
    ) -> Result<Self> {
        encode(policy, 32 * 1024)?;
        // Bound the complete caller graph before cloning; managed setup requires exactly
        // the whole original three-provider gateway set, not an arbitrary subset.
        if labels.len() != 3 {
            return Err(invalid("generated reputation requires all three gateways"));
        }
        validate_gateway_label_bound(labels)?;
        let mut expected = Vec::with_capacity(3);
        for provider in &authority.manifest.providers {
            let plan = authority.gateway_compliance_plan(provider.provider_id)?;
            let label = plan.gateway_label().to_owned();
            let id = derive_stream_token_gateway_id_v1(&authority.config.network_id, &label)
                .map_err(|_| invalid("invalid original compliance gateway label"))?;
            expected.push((id, label));
        }
        expected.sort_by_key(|(id, _)| *id);
        if !labels.iter().eq(expected.iter().map(|(_, label)| label)) {
            return Err(invalid(
                "recorder selection differs from all original gateways",
            ));
        }
        let gateway_ids = expected.iter().map(|(id, _)| *id).collect();
        let recorder = authority.network_role(
            crate::localnet::service_authorities::NetworkServiceAuthorityRole::ReputationRecorder,
        )?;
        let value = Self::Reputation {
            selection: InitialReputationPolicySelection {
                chain_id: authority.config.chain.to_string(),
                network_id: authority.config.network_id,
                manager: authority.config.account.clone(),
                compliance_gateway_ids: labels.to_vec(),
                gateway_ids,
                policy_digest: policy
                    .canonical_digest()
                    .map_err(|_| invalid("invalid recorder policy digest"))?,
                por_recorder: recorder.clone(),
                dispute_recorder: recorder.clone(),
                token_recorder: recorder.clone(),
            },
            policy: policy.clone(),
        };
        value.validate()?;
        Ok(value)
    }
    pub(super) fn validate(&self) -> Result<()> {
        encode(self, MAX_INTENT_BYTES)?;
        match self {
            Self::ProviderIngest {
                chain_id,
                provider_id,
                authority,
                ..
            } => {
                encode(authority, 16 * 1024)?;
                if chain_id.is_empty()
                    || chain_id.len() > 4096
                    || provider_id.as_bytes() == &[0; 32]
                    || !authority.is_valid()
                    || authority.signer_policy.revision != 1
                    || authority.signer_policy.predecessor_digest.is_some()
                {
                    return Err(invalid("invalid original initial ingest authority"));
                }
            }
            Self::Gateway { selection, policy } => {
                encode(selection, MAX_SELECTION_BYTES)?;
                encode(policy, 16 * 1024)?;
                policy
                    .validate()
                    .map_err(|_| invalid("invalid original gateway policy"))?;
                let id = derive_stream_token_gateway_id_v1(
                    &selection.network_id,
                    &selection.compliance_gateway_id,
                )
                .map_err(|_| invalid("invalid original gateway label"))?;
                if policy.qualification.revision != 1
                    || policy.network_id != selection.network_id
                    || policy.compliance_gateway_id != selection.compliance_gateway_id
                    || selection.gateway_id != id
                    || policy.qualification.gateway_id != id
                    || policy.qualification.policy_digest != selection.policy_digest
                    || policy.operators.len() != 1
                    || !policy.operators.contains(&selection.operator)
                    || policy.observers.len() != 1
                    || !policy.observers.contains(&selection.observer)
                {
                    return Err(invalid(
                        "original gateway intent differs from full policy and exact grants",
                    ));
                }
            }
            Self::Reputation { selection, policy } => {
                encode(selection, MAX_SELECTION_BYTES)?;
                encode(policy, 32 * 1024)?;
                policy
                    .validate()
                    .map_err(|_| invalid("invalid original recorder policy"))?;
                selection
                    .validate_gateway_selection()
                    .map_err(std::io::Error::other)?;
                if policy.revision != 1
                    || policy.predecessor_policy_digest.is_some()
                    || policy
                        .canonical_digest()
                        .map_err(|_| invalid("invalid recorder digest"))?
                        != selection.policy_digest
                    || policy.por_recorder_authority != selection.por_recorder
                    || policy.dispute_recorder_authority != selection.dispute_recorder
                    || policy.token_recorder_authority != selection.token_recorder
                    || policy.stream_token_delivery.allowed_gateways != selection.gateway_ids
                {
                    return Err(invalid(
                        "original recorder intent differs from full policy and exact generated roles",
                    ));
                }
            }
        }
        Ok(())
    }
}
#[derive(Clone, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_deploy::managed::service_setup::Original")]
pub(super) struct Original {
    pub intent: Intent,
    pub checkpoint: Vec<u8>,
}
impl Original {
    pub(super) fn validate(&self) -> Result<()> {
        self.intent.validate()?;
        if self.checkpoint.is_empty() || self.checkpoint.len() > MAX_CHECKPOINT_BYTES {
            return Err(invalid(
                "original service checkpoint exceeds bounds or is absent",
            ));
        }
        Ok(())
    }
    pub(super) fn matches_intent(&self, intent: &Intent) -> Result<()> {
        self.validate()?;
        intent.validate()?;
        if encode(&self.intent, MAX_INTENT_BYTES)? != encode(intent, MAX_INTENT_BYTES)? {
            return Err(invalid("original service setup cannot be replaced"));
        }
        Ok(())
    }
    pub(super) fn digest(&self) -> Result<[u8; 32]> {
        attempts::semantic_digest(self, MAX_ORIGINAL_BYTES)
    }
    pub(super) fn request(&self, terms: &Terms, deadline: Instant) -> Request {
        match &self.intent {
            Intent::ProviderIngest {
                chain_id,
                network_id,
                provider_id,
                authority,
            } => Request::ProviderIngest(InitialProviderIngestAuthorityRequest {
                chain_id: chain_id.clone(),
                network_id: *network_id,
                provider_id: *provider_id,
                authority: authority.clone(),
                deadline_unix_ms: terms.signing_deadline_unix_ms,
                options: terms.options(deadline),
            }),
            Intent::Gateway { selection, policy } => Request::Gateway(InitialGatewaySetupRequest {
                selection: selection.clone(),
                policy: policy.clone(),
                deadline_unix_ms: terms.signing_deadline_unix_ms,
                options: terms.options(deadline),
            }),
            Intent::Reputation { selection, policy } => {
                Request::Reputation(InitialReputationPolicyRequest {
                    selection: selection.clone(),
                    policy: policy.clone(),
                    deadline_unix_ms: terms.signing_deadline_unix_ms,
                    options: terms.options(deadline),
                })
            }
        }
    }
}
impl Selected<Original> {
    pub(super) fn matches(
        &self,
        intent: &Intent,
        utc: u64,
        options: &BoundedTransactionOptions,
    ) -> Result<()> {
        self.matches_intent(intent)?;
        self.terms.matches(utc, options)
    }
    pub(super) fn request(&self, deadline: Instant) -> Request {
        Original::request(self, &self.terms, deadline)
    }
}
pub(super) fn read_intent(directory: &PrivateDirectory) -> Result<Option<Original>> {
    let names = directory.entries(3)?;
    if names.iter().any(|name| {
        !["original.nrt", "dispatch.nrt", "attempts"]
            .iter()
            .any(|allowed| name == *allowed)
    }) {
        return Err(invalid("service setup contains unknown original material"));
    }
    let Some(bytes) = read_optional(directory, "original.nrt", MAX_ORIGINAL_BYTES)? else {
        require_empty(directory)?;
        return Ok(None);
    };
    let original: Original = norito::decode_canonical_with_limits(
        &bytes,
        norito::DecodeLimits::new(
            MAX_CHECKPOINT_BYTES,
            MAX_ORIGINAL_BYTES,
            MAX_ORIGINAL_BYTES,
            96 * 1024 * 1024,
            40,
        ),
    )
    .map_err(|error| std::io::Error::other(error))?;
    original.validate()?;
    Ok(Some(original))
}
pub(super) fn read_original(
    directory: &PrivateDirectory,
    purpose: Purpose,
) -> Result<Option<Selected<Original>>> {
    let Some(intent) = read_intent(directory)? else {
        return Ok(None);
    };
    let history = History::read(
        directory,
        purpose,
        intent.digest()?,
        &crate::managed::native_operation::attempts::HistoryScope::FixedBody,
    )?;
    Selected::from_history(intent, history).map(Some)
}
pub(super) fn required_original(
    directory: &PrivateDirectory,
    purpose: Purpose,
) -> Result<Selected<Original>> {
    read_original(directory, purpose)?
        .ok_or_else(|| invalid("original service setup intent is absent"))
}
pub(super) fn publish_intent(directory: &PrivateDirectory, original: &Original) -> Result<()> {
    original.validate()?;
    let bytes = encode(original, MAX_ORIGINAL_BYTES)?;
    if let Some(retained) = read_optional(directory, "original.nrt", MAX_ORIGINAL_BYTES)? {
        if retained != bytes {
            return Err(invalid("original service setup semantic selection changed"));
        }
        return Ok(());
    }
    directory.write_atomic("original.nrt", &bytes, PublishMode::CreateNew)?;
    Ok(())
}
pub(super) fn explicit(
    directory: &PrivateDirectory,
    purpose: Purpose,
    original: &Original,
    utc: u64,
    options: &BoundedTransactionOptions,
    account: &AccountService,
) -> Result<()> {
    let history = History::read(
        directory,
        purpose,
        original.digest()?,
        &crate::managed::native_operation::attempts::HistoryScope::FixedBody,
    )?;
    let terms = match history.retained_terms() {
        Some(terms) => {
            terms.matches(utc, options)?;
            terms.clone()
        }
        None => Terms::new(utc, options)?,
    };
    attempts::initial(
        history,
        terms,
        Observation::ordinary(),
        options.deadline,
        |attempt| {
            original
                .request(attempt.terms(), options.deadline)
                .inspect_in_parent(account, attempt.directory())
        },
        |attempt, _, deadline| {
            original
                .request(attempt.terms(), deadline)
                .retain(account, &attempt.wallet_path())
        },
    )
}

/// Measure the original borrowed labels with canonical vector framing before cloning them.
fn validate_gateway_label_bound(labels: &[String]) -> Result<()> {
    let mut measured =
        norito::core::SequencePayloadLength::new(norito::core::default_encode_flags())
            .map_err(|_| invalid("cannot size original gateway labels"))?;
    let empty_payload = measured.len();
    // This uses the actual Vec<String> frame, including its schema-independent alignment.
    let empty_frame = norito::canonical_frame_len(&Vec::<String>::new())
        .map_err(|_| invalid("cannot size original gateway labels"))?;
    for label in labels {
        measured
            .push(label)
            .map_err(|_| invalid("cannot size original gateway labels"))?;
        let frame = measured
            .len()
            .checked_sub(empty_payload)
            .and_then(|payload| empty_frame.checked_add(payload))
            .ok_or_else(|| invalid("original gateway labels exceed byte bound"))?;
        if frame > MAX_SELECTION_BYTES {
            return Err(invalid("original gateway labels exceed byte bound"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod label_bound_tests {
    use super::*;

    #[test]
    fn borrowed_label_measurement_matches_canonical_vector_boundary() {
        for labels in [
            vec![String::new(); 3],
            vec!["gateway-1".into(), "\u{1f338}".repeat(200), "a".repeat(512)],
        ] {
            assert!(norito::canonical_frame_len(&labels).unwrap() <= MAX_SELECTION_BYTES);
            validate_gateway_label_bound(&labels).unwrap();
        }
        let mut labels = vec![String::new(); 3];
        // Select the exact canonical size without presuming a length-prefix width.
        while norito::canonical_frame_len(&labels).unwrap() < MAX_SELECTION_BYTES {
            labels[0].push('x');
        }
        assert_eq!(
            norito::canonical_frame_len(&labels).unwrap(),
            MAX_SELECTION_BYTES
        );
        validate_gateway_label_bound(&labels).unwrap();
        labels[0].push('x');
        assert_eq!(
            norito::canonical_frame_len(&labels).unwrap(),
            MAX_SELECTION_BYTES + 1
        );
        assert!(validate_gateway_label_bound(&labels).is_err());
    }
}
