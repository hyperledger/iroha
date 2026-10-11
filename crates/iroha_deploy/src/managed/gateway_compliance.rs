//! Original generated catalogs, observed local reload and exact control-request recovery.
//!
//! Controller responses describe runtime state only. Native service admission and real package
//! reads remain required after this coordinator reports a promoted catalog.

use super::{
    PreparedLocalnet, Result,
    native_operation::{encode, invalid, now_ms, read_optional, require_deadline},
    service_authority::{ProviderPurpose, ServiceAuthority},
};
use crate::localnet::service_authorities::RetainedGatewayCompliancePlan;
use iroha::client::Client;
use iroha_data_model::{NetworkId, sorafs::capacity::ProviderId};
use iroha_fs::{PrivateDirectory, PublishMode};
use iroha_torii_shared::sorafs_gateway_compliance_api::{
    GatewayComplianceCatalogStatusV1, GatewayCompliancePromoteExpectationV1,
    GatewayComplianceStatusResponseV1, decode_lower_hex_32,
};
use sorafs_manifest::gateway_compliance::{
    GatewayComplianceAcknowledgementV1, GatewayComplianceCatalogV1, validate_catalog_transition,
};
use std::time::{Duration, Instant};

const MAX_RECORD_BYTES: usize = 16 * 1024;
const MAX_CATALOGS: usize = 64;
const CLOCK_SKEW_SECONDS: u64 = 300;

/// Implemented by the worker's owned-child and exact derived-revision owner.
/// It must reject a dead/replaced child, different endpoint/configuration or changed original.
pub(super) trait LiveGatewayProcess {
    fn validate(
        &mut self,
        prepared: &PreparedLocalnet,
        plan: &RetainedGatewayCompliancePlan,
    ) -> Result<()>;
}

/// Created only after the original live gateway reports the exact loaded candidate.
/// This is a local reload observation, not native admission or a serving capability.
pub(crate) struct ObservedGatewayCatalog {
    network: NetworkId,
    policy: [u8; 32],
    catalog: [u8; 32],
    observed_at: u64,
}
impl ObservedGatewayCatalog {
    pub(crate) fn network(&self) -> NetworkId {
        self.network
    }
    pub(crate) fn policy(&self) -> [u8; 32] {
        self.policy
    }
    pub(crate) fn catalog(&self) -> [u8; 32] {
        self.catalog
    }
    pub(crate) fn observed_at(&self) -> u64 {
        self.observed_at
    }
    pub(crate) fn is_fresh_at(&self, now: u64) -> bool {
        self.observed_at <= now && now.saturating_sub(self.observed_at) <= 30
    }
}

/// One exact promoted-catalog observation, without a native readiness claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct PromotedGeneratedCatalog {
    pub digest: [u8; 32],
    pub sequence: u64,
    pub generated_at_unix: u64,
    pub valid_until_unix: u64,
}

pub(super) struct ManagedGatewayCompliance {
    authority: ServiceAuthority,
    plan: RetainedGatewayCompliancePlan,
}
impl ManagedGatewayCompliance {
    pub(super) fn open(prepared: &PreparedLocalnet, provider: ProviderId) -> Result<Self> {
        let authority = ServiceAuthority::open_provider(
            prepared,
            provider,
            ProviderPurpose::GatewayCompliance,
        )?;
        let plan = authority.gateway_compliance_plan(authority.provider_id()?)?;
        Ok(Self { authority, plan })
    }

    /// Reuse retained originals; prepare a successor only after the original live controller
    /// confirms the current catalog as its exact promoted head and the refresh interval starts.
    pub(super) fn advance(
        &self,
        live: &mut impl LiveGatewayProcess,
        deadline: Instant,
    ) -> Result<PromotedGeneratedCatalog> {
        self.validate(live, deadline)?;
        let directory = self.authority.directory.ensure_child("catalogs")?;
        let mut chain = self.read_chain(&directory)?;
        let mut status = self.status(live, deadline)?;
        if self.read_chain(&directory)? != chain {
            return Err(invalid("retained catalog chain changed during observation"));
        }
        let now = now_ms()? / 1_000;
        if now < self.plan.issued_at_unix() || now >= self.plan.expires_at_unix() {
            return Err(invalid(
                "original generated compliance material has expired",
            ));
        }
        let selected = match chain.last() {
            Some(last) if is_promoted(&status, last)? => {
                let midpoint = last.payload.generated_at_unix
                    + (last.payload.valid_until_unix - last.payload.generated_at_unix) / 2;
                if now < midpoint || last.payload.valid_until_unix == self.plan.expires_at_unix() {
                    self.require_fresh_promoted(&status, last, now)?;
                    self.validate(live, deadline)?;
                    return report(last);
                }
                self.require_no_candidate(&status)?;
                self.authority.prepared.sign_gateway_compliance_catalog(
                    self.authority.provider_id()?,
                    Some(last),
                    now,
                )?
            }
            Some(last) => {
                self.require_predecessor(&status, chain.iter().rev().nth(1))?;
                self.require_candidate_or_absent(&status, last)?;
                last.clone()
            }
            None => {
                self.require_predecessor(&status, None)?;
                self.require_no_candidate(&status)?;
                self.authority.prepared.sign_gateway_compliance_catalog(
                    self.authority.provider_id()?,
                    None,
                    now,
                )?
            }
        };
        if chain.last() != Some(&selected) {
            if chain.len() >= MAX_CATALOGS {
                return Err(invalid("original generated catalog inventory is full"));
            }
            let child = directory.ensure_child(&catalog_name(selected.payload.sequence))?;
            if !child.entries(1)?.is_empty() {
                return Err(invalid(
                    "unpublished catalog contains unexpected retained state",
                ));
            }
            child.write_atomic(
                "original.nrt",
                &encode(&selected, MAX_RECORD_BYTES)?,
                PublishMode::CreateNew,
            )?;
            chain.push(selected.clone());
        }
        // Never renew the bytes of an expired, already staged original. A same-sequence rewrite
        // would violate controller equivocation protection and its original signing authority.
        selected
            .verify(self.plan.trust_policy(), now, 0)
            .map_err(|_| invalid("original staged generated catalog is no longer fresh"))?;
        let child = directory.open_child(&catalog_name(selected.payload.sequence))?;
        let retained_ack = self.read_ack(&child, &selected)?;
        self.call_retained(
            live,
            deadline,
            &child,
            &selected,
            retained_ack.as_ref(),
            |client| {
                client
                    .stage_sorafs_gateway_compliance_catalog(&selected, self.plan.trust_policy())
                    .map(|_| ())
                    .map_err(|_| invalid("original generated catalog stage was not confirmed"))
            },
        )?;
        status = self.status(live, deadline)?;
        self.validate_retained(&child, &selected, retained_ack.as_ref())?;
        self.require_predecessor(&status, chain.iter().rev().nth(1))?;
        if !status
            .candidate
            .as_ref()
            .is_some_and(|candidate| matches_catalog(candidate, &selected).unwrap_or(false))
        {
            return Err(invalid(
                "live original gateway did not load the exact staged catalog",
            ));
        }
        let observed_at = now_ms()? / 1_000;
        let observation = ObservedGatewayCatalog {
            network: self.plan.network_id(),
            policy: self
                .plan
                .trust_policy()
                .canonical_digest()
                .map_err(|_| invalid("original generated compliance trust is invalid"))?,
            catalog: selected
                .payload
                .catalog_digest()
                .map_err(|_| invalid("original generated catalog is invalid"))?,
            observed_at,
        };
        let acknowledgement = match retained_ack {
            Some(retained) if retained.payload.observed_at_unix > observed_at => {
                return Err(invalid(
                    "clock moved behind the original gateway acknowledgement",
                ));
            }
            Some(retained)
                if retained
                    .payload
                    .observed_at_unix
                    .saturating_add(CLOCK_SKEW_SECONDS / 2)
                    >= observed_at =>
            {
                retained
            }
            previous => {
                self.validate(live, deadline)?;
                let signed = self.authority.prepared.sign_observed_gateway_catalog(
                    self.authority.provider_id()?,
                    &observation,
                    &selected,
                )?;
                self.validate_retained(&child, &selected, previous.as_ref())?;
                child.write_atomic(
                    "acknowledgement.nrt",
                    &encode(&signed, MAX_RECORD_BYTES)?,
                    PublishMode::Replace,
                )?;
                signed
            }
        };
        self.call_retained(
            live,
            deadline,
            &child,
            &selected,
            Some(&acknowledgement),
            |client| {
                client
                    .acknowledge_sorafs_gateway_compliance_catalog(
                        &acknowledgement,
                        self.plan.trust_policy(),
                        observation.catalog,
                    )
                    .map(|_| ())
                    .map_err(|_| {
                        invalid("original generated gateway acknowledgement was not confirmed")
                    })
            },
        )?;
        self.call_retained(
            live,
            deadline,
            &child,
            &selected,
            Some(&acknowledgement),
            |client| {
                client
                    .promote_sorafs_gateway_compliance_catalog(
                        GatewayCompliancePromoteExpectationV1 {
                            catalog_digest: observation.catalog,
                            sequence: selected.payload.sequence,
                        },
                    )
                    .map(|_| ())
                    .map_err(|_| invalid("original generated catalog promotion was not confirmed"))
            },
        )?;
        let status = self.status(live, deadline)?;
        self.validate_retained(&child, &selected, Some(&acknowledgement))?;
        self.require_fresh_promoted(&status, &selected, now_ms()? / 1_000)?;
        self.validate(live, deadline)?;
        report(&selected)
    }

    /// Recheck the exact retained promoted original on a new owned launch, without signing,
    /// refreshing, staging, acknowledging, promoting or creating custody directories.
    pub(super) fn observe_promoted(
        &self,
        live: &mut impl LiveGatewayProcess,
        expected: PromotedGeneratedCatalog,
        deadline: Instant,
    ) -> Result<()> {
        self.validate(live, deadline)?;
        let directory = self.authority.directory.open_child("catalogs")?;
        let inventory = directory.entries(MAX_CATALOGS)?;
        let chain = self.read_chain(&directory)?;
        let selected = chain
            .last()
            .ok_or_else(|| invalid("original promoted catalog is absent"))?;
        if report(selected)? != expected {
            return Err(invalid("promoted catalog differs from original activation"));
        }
        let child = directory.open_child(&catalog_name(selected.payload.sequence))?;
        let acknowledgement = self
            .read_ack(&child, selected)?
            .ok_or_else(|| invalid("original promoted catalog acknowledgement is absent"))?;
        let status = self.call_retained(
            live,
            deadline,
            &child,
            selected,
            Some(&acknowledgement),
            |client| {
                client
                    .get_sorafs_gateway_compliance_status()
                    .map_err(|_| invalid("original gateway compliance status is unavailable"))
            },
        )?;
        self.validate_status(&status)?;
        directory.revalidate()?;
        if directory.entries(MAX_CATALOGS)? != inventory || self.read_chain(&directory)? != chain {
            return Err(invalid("retained catalog chain changed during observation"));
        }
        self.validate_retained(&child, selected, Some(&acknowledgement))?;
        self.require_fresh_promoted(&status, selected, now_ms()? / 1_000)?;
        self.validate(live, deadline)
    }

    fn validate(&self, live: &mut impl LiveGatewayProcess, deadline: Instant) -> Result<()> {
        require_deadline(deadline)?;
        self.authority.validate_profile()?;
        let current = self
            .authority
            .gateway_compliance_plan(self.authority.provider_id()?)?;
        if current.network_id() != self.plan.network_id()
            || current.original_commitment() != self.plan.original_commitment()
            || current.trust_policy() != self.plan.trust_policy()
        {
            return Err(invalid("original generated compliance plan changed"));
        }
        live.validate(&self.authority.prepared, &self.plan)
    }

    fn call<T>(
        &self,
        live: &mut impl LiveGatewayProcess,
        deadline: Instant,
        operation: impl FnOnce(&Client) -> Result<T>,
    ) -> Result<T> {
        self.validate(live, deadline)?;
        let client = &self
            .authority
            .peers
            .get(self.authority.provider_plan()?.peer_index())
            .ok_or_else(|| invalid("original gateway peer is absent"))?
            .1;
        let local_deadline = Instant::now()
            .checked_add(Duration::from_secs(5))
            .ok_or_else(|| invalid("gateway request deadline overflow"))?
            .min(deadline);
        let result = operation(&client.with_request_deadline(local_deadline));
        self.validate(live, deadline)?;
        result
    }

    fn validate_retained(
        &self,
        directory: &PrivateDirectory,
        catalog: &GatewayComplianceCatalogV1,
        acknowledgement: Option<&GatewayComplianceAcknowledgementV1>,
    ) -> Result<()> {
        self.authority.directory.revalidate()?;
        directory.revalidate()?;
        let files = directory.entries(2)?;
        if files.len() != 1 + usize::from(acknowledgement.is_some())
            || files
                .iter()
                .any(|file| file != "original.nrt" && file != "acknowledgement.nrt")
            || directory.read("original.nrt", MAX_RECORD_BYTES)?.as_slice()
                != encode(catalog, MAX_RECORD_BYTES)?.as_slice()
        {
            return Err(invalid(
                "retained original generated catalog changed before dispatch",
            ));
        }
        match (
            read_optional(directory, "acknowledgement.nrt", MAX_RECORD_BYTES)?,
            acknowledgement,
        ) {
            (None, None) => {}
            (Some(bytes), Some(expected))
                if bytes.as_slice() == encode(expected, MAX_RECORD_BYTES)?.as_slice() => {}
            _ => {
                return Err(invalid(
                    "retained original gateway acknowledgement changed before dispatch",
                ));
            }
        }
        directory.revalidate()?;
        Ok(())
    }

    fn call_retained<T>(
        &self,
        live: &mut impl LiveGatewayProcess,
        deadline: Instant,
        directory: &PrivateDirectory,
        catalog: &GatewayComplianceCatalogV1,
        acknowledgement: Option<&GatewayComplianceAcknowledgementV1>,
        operation: impl FnOnce(&Client) -> Result<T>,
    ) -> Result<T> {
        self.call(live, deadline, |client| {
            self.validate_retained(directory, catalog, acknowledgement)?;
            let result = operation(client);
            self.validate_retained(directory, catalog, acknowledgement)?;
            result
        })
    }

    fn status(
        &self,
        live: &mut impl LiveGatewayProcess,
        deadline: Instant,
    ) -> Result<GatewayComplianceStatusResponseV1> {
        let value = self.call(live, deadline, |client| {
            client
                .get_sorafs_gateway_compliance_status()
                .map_err(|_| invalid("original gateway compliance status is unavailable"))
        })?;
        self.validate_status(&value)?;
        Ok(value)
    }

    fn validate_status(&self, value: &GatewayComplianceStatusResponseV1) -> Result<()> {
        let digest = self
            .plan
            .trust_policy()
            .canonical_digest()
            .map_err(|_| invalid("original compliance trust is invalid"))?;
        let now = now_ms()? / 1_000;
        if decode_lower_hex_32(&value.policy_digest_hex) != Some(digest)
            || value.observed_at_unix.abs_diff(now) > CLOCK_SKEW_SECONDS
        {
            return Err(invalid(
                "gateway compliance status differs from original trust or clock",
            ));
        }
        Ok(())
    }

    fn read_chain(&self, directory: &PrivateDirectory) -> Result<Vec<GatewayComplianceCatalogV1>> {
        let mut entries = directory.entries(MAX_CATALOGS)?;
        entries.sort();
        let count = entries.len();
        let mut chain = Vec::with_capacity(entries.len());
        for (index, name) in entries.into_iter().enumerate() {
            let sequence =
                u64::try_from(index + 1).map_err(|_| invalid("catalog sequence overflow"))?;
            if name != std::ffi::OsString::from(catalog_name(sequence)) {
                return Err(invalid(
                    "retained generated catalog sequence is not contiguous",
                ));
            }
            let child = directory.open_child(&name)?;
            let files = child.entries(2)?;
            // Creating a private directory is separate from publishing its original. A crash
            // between the two leaves only the final next-sequence directory empty. Reuse that
            // unpublished slot; never ignore a gap or an acknowledgement without its original.
            if files.is_empty() && index + 1 == count {
                break;
            }
            for file in files {
                if file != "original.nrt" && file != "acknowledgement.nrt" {
                    return Err(invalid(
                        "retained generated catalog contains unexpected state",
                    ));
                }
            }
            let bytes = child.read("original.nrt", MAX_RECORD_BYTES)?;
            let catalog: GatewayComplianceCatalogV1 = decode(&bytes)?;
            if catalog.payload.sequence != sequence {
                return Err(invalid("retained generated catalog sequence differs"));
            }
            self.authority
                .prepared
                .validate_generated_gateway_catalog(self.authority.provider_id()?, &catalog)?;
            validate_catalog_transition(chain.last(), &catalog)
                .map_err(|_| invalid("retained generated catalog predecessor differs"))?;
            self.read_ack(&child, &catalog)?;
            chain.push(catalog);
        }
        Ok(chain)
    }

    fn read_ack(
        &self,
        directory: &PrivateDirectory,
        catalog: &GatewayComplianceCatalogV1,
    ) -> Result<Option<GatewayComplianceAcknowledgementV1>> {
        let Some(bytes) = read_optional(directory, "acknowledgement.nrt", MAX_RECORD_BYTES)? else {
            return Ok(None);
        };
        let ack: GatewayComplianceAcknowledgementV1 = decode(&bytes)?;
        if ack.payload.gateway_id != self.plan.gateway_label()
            || !ack.payload.accepted
            || ack.payload.rejection_code.is_some()
            || ack.payload.observed_at_unix < catalog.payload.generated_at_unix
            || ack.payload.observed_at_unix >= catalog.payload.valid_until_unix
        {
            return Err(invalid("retained original gateway acknowledgement differs"));
        }
        ack.verify(
            self.plan.trust_policy(),
            catalog
                .payload
                .catalog_digest()
                .map_err(|_| invalid("retained catalog digest is invalid"))?,
            ack.payload.observed_at_unix,
            0,
        )
        .map_err(|_| invalid("retained original gateway acknowledgement is invalid"))?;
        Ok(Some(ack))
    }

    fn require_no_candidate(&self, status: &GatewayComplianceStatusResponseV1) -> Result<()> {
        if status.candidate.is_some() || status.acknowledgement_count != 0 {
            return Err(invalid("original gateway retains an unexpected candidate"));
        }
        Ok(())
    }
    fn require_candidate_or_absent(
        &self,
        status: &GatewayComplianceStatusResponseV1,
        catalog: &GatewayComplianceCatalogV1,
    ) -> Result<()> {
        if let Some(candidate) = &status.candidate {
            if !matches_catalog(candidate, catalog)? {
                return Err(invalid("original gateway retains a different candidate"));
            }
        } else if status.acknowledgement_count != 0 {
            return Err(invalid(
                "original gateway acknowledgements have no candidate",
            ));
        }
        Ok(())
    }
    fn require_predecessor(
        &self,
        status: &GatewayComplianceStatusResponseV1,
        previous: Option<&GatewayComplianceCatalogV1>,
    ) -> Result<()> {
        match (previous, &status.chain_head, &status.serving) {
            (None, None, None) if status.previous_serving.is_none() => Ok(()),
            (Some(previous), Some(head), Some(serving))
                if matches_catalog(head, previous)? && matches_catalog(serving, previous)? =>
            {
                Ok(())
            }
            _ => Err(invalid("original gateway promoted predecessor differs")),
        }
    }
    fn require_fresh_promoted(
        &self,
        status: &GatewayComplianceStatusResponseV1,
        catalog: &GatewayComplianceCatalogV1,
        now: u64,
    ) -> Result<()> {
        self.require_no_candidate(status)?;
        if !is_promoted(status, catalog)? || !status.serving_ready {
            return Err(invalid(
                "original gateway did not confirm the exact promoted catalog",
            ));
        }
        catalog
            .verify(self.plan.trust_policy(), now, 0)
            .map_err(|_| invalid("original promoted catalog has expired"))?;
        Ok(())
    }
}

fn catalog_name(sequence: u64) -> String {
    format!("catalog-{sequence:016x}")
}
fn decode<T: norito::NoritoSerialize + for<'a> norito::NoritoDeserialize<'a>>(
    bytes: &[u8],
) -> Result<T> {
    norito::decode_canonical_with_limits(
        bytes,
        norito::DecodeLimits::new(
            MAX_RECORD_BYTES,
            MAX_RECORD_BYTES,
            MAX_RECORD_BYTES * 2,
            MAX_RECORD_BYTES * 8,
            32,
        ),
    )
    .map_err(|_| invalid("invalid retained generated compliance record"))
}
fn matches_catalog(
    status: &GatewayComplianceCatalogStatusV1,
    catalog: &GatewayComplianceCatalogV1,
) -> Result<bool> {
    Ok(decode_lower_hex_32(&status.digest_hex)
        == Some(
            catalog
                .payload
                .catalog_digest()
                .map_err(|_| invalid("invalid original generated catalog digest"))?,
        )
        && status.sequence == catalog.payload.sequence
        && status.generated_at_unix == catalog.payload.generated_at_unix
        && status.valid_until_unix == catalog.payload.valid_until_unix)
}
fn is_promoted(
    status: &GatewayComplianceStatusResponseV1,
    catalog: &GatewayComplianceCatalogV1,
) -> Result<bool> {
    match (&status.chain_head, &status.serving) {
        (Some(head), Some(serving)) => {
            Ok(matches_catalog(head, catalog)? && matches_catalog(serving, catalog)?)
        }
        _ => Ok(false),
    }
}
fn report(catalog: &GatewayComplianceCatalogV1) -> Result<PromotedGeneratedCatalog> {
    Ok(PromotedGeneratedCatalog {
        digest: catalog
            .payload
            .catalog_digest()
            .map_err(|_| invalid("invalid promoted catalog"))?,
        sequence: catalog.payload.sequence,
        generated_at_unix: catalog.payload.generated_at_unix,
        valid_until_unix: catalog.payload.valid_until_unix,
    })
}

#[cfg(test)]
mod material_tests;
#[cfg(test)]
mod tests;
