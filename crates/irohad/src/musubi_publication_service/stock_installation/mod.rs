//! Closed stock assembly from original generated intent and native daemon owners.
//!
//! Construction at H1 selects only signed intent. Cold readback requires fresh H2+ native
//! discovery; startup neither initializes custody nor grants any additional permission.

mod discovery;
#[cfg(test)]
mod generated_tests;
#[cfg(test)]
mod tests;

use super::{
    MusubiPublicationPrivateDeploymentV1, MusubiPublicationPrivateIngressBuilderV1,
    MusubiPublicationPrivateLocalFactorySettingsV1, MusubiPublicationPrivateLocalFactoryV1,
    MusubiPublicationPrivateServiceContextV1,
    MusubiPublicationPrivateServiceFactoryErrorV1 as Error,
    MusubiPublicationPrivateServiceFactoryV1, MusubiPublicationPrivateTlsIngressBuilderV1,
    MusubiPublicationPrivateTlsSettingsV1, NativeMusubiStorageBuilderV1,
    NativeMusubiStorageLimitsV1,
};
use crate::runtime_credential::{load_bound_software_key_v1, load_bounded_runtime_credential_v1};
use iroha_config::parameters::actual::MusubiPublication;
use iroha_core::{
    query::provider_admission::with_genesis_provider_admission_originals_v1, state::StateReadOnly,
};
use iroha_data_model::{account::AccountController, sorafs::capacity::ProviderId};
use iroha_musubi_service::SoftwareMusubiSeedIngressReceiptSignerV1;
use iroha_storage_client::musubi_archive_fetch::PreparedMusubiArchiveFetchConfigV1;
use sorafs_car::gateway::GeneratedLocalProviderTransportV1;
use std::{
    alloc::Layout,
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
    time::Duration,
};

type Cache = Arc<tokio::sync::RwLock<iroha_torii::sorafs::ProviderAdvertCache>>;

/// Select the sole explicit or configured factory without giving a default profile side effects.
pub fn select_factory(
    config: &MusubiPublication,
    context: Option<&MusubiPublicationPrivateServiceContextV1>,
    cache: Option<Cache>,
    supplied: Option<Box<dyn MusubiPublicationPrivateServiceFactoryV1>>,
    emergency_fast: bool,
) -> Result<Option<Box<dyn MusubiPublicationPrivateServiceFactoryV1>>, Error> {
    if emergency_fast {
        return Ok(None);
    }
    let Some(installation) = &config.installation else {
        return Ok(supplied);
    };
    if supplied.is_some() {
        return Err(Error::Unqualified);
    }
    let context = context.ok_or(Error::Unqualified)?;
    let cache = cache.ok_or(Error::Unqualified)?;
    if installation.network_id != context.network_id()
        || config.private_tls_bind.ip() != IpAddr::V4(Ipv4Addr::LOCALHOST)
        || config.private_tls_bind.port() == 0
        || !(1..=iroha_config::parameters::defaults::musubi_publication::MAX_READBACK_REQUEST_TIMEOUT_MS).contains(&installation.readback_request_timeout_ms) {
        return Err(Error::Unqualified);
    }
    let settings = MusubiPublicationPrivateLocalFactorySettingsV1::from_config(
        config,
        context.network_id(),
        installation.ingress_broker.clone(),
        installation.seed_provider,
    )?;
    let AccountController::Single(broker_public) = installation.ingress_broker.controller() else {
        return Err(Error::Unqualified);
    };
    let AccountController::Single(pin_public) =
        settings.paid_pin.transaction_authority.controller()
    else {
        return Err(Error::Unqualified);
    };
    let broker = load_bound_software_key_v1(&installation.broker_key_file, broker_public)
        .map_err(|_| Error::Unqualified)?;
    let pin = load_bound_software_key_v1(&installation.pin_key_file, pin_public)
        .map_err(|_| Error::Unqualified)?;
    let state = context.state();
    let budget = state.ivm_execution_budget();
    let view = state.view();
    let chain = view.chain_id().to_string();
    let mut selected = None;
    with_genesis_provider_admission_originals_v1(&view, 3, &budget, |originals| {
        let invalid = iroha_core::query::provider_admission::ProviderAdmissionErrorV1;
        if originals.len() != 3 { return Err(invalid); }
        // Two retained exact selections exist: the ordinary client and its native callback.
        // Admit their conservative nested material envelope before copying either one.
        let retained_bytes = originals.iter().try_fold(0usize, |total, (owner, material)| {
            let material_len = norito::canonical_frame_len(material).map_err(|_| invalid)?;
            let owner_len = norito::canonical_frame_len(owner).map_err(|_| invalid)?;
            total.checked_add(norito::canonical_decode_limits(material_len).max_total_allocated_bytes())
                .and_then(|total| total.checked_add(owner_len)).ok_or(invalid)
        })?.checked_mul(2).ok_or(invalid)?;
        let layout = Layout::array::<u8>(retained_bytes).map_err(|_| invalid)?;
        let selection_charge = budget.try_reserve(layout).map_err(|_| invalid)?
            .try_split(layout).map_err(|_| invalid)?;
        let mut transports = Vec::with_capacity(3);
        let mut tls = None;
        for (owner, material) in originals {
            let provider = ProviderId::new(material.proposal.provider_id);
            transports.push(GeneratedLocalProviderTransportV1::select(
                context.network_id(), &chain, provider, owner, material,
            ).map_err(|_| invalid)?);
            if provider == installation.seed_provider {
                if owner != &installation.ingress_broker || tls.is_some() { return Err(invalid); }
                let endpoint = &material.proposal.endpoints[0];
                let policy = sorafs_manifest::provider_advert::account_read::RegisteredAccountReadV1::from_capabilities(&material.proposal.capabilities)
                    .map_err(|_| invalid)?.ok_or(invalid)?;
                if installation.tls_server_name != endpoint.endpoint.host_pattern
                    || config.private_tls_bind.port() == policy.https_port { return Err(invalid); }
                let maximum = iroha_config::parameters::defaults::torii::transport::https::MAX_DER_BYTES;
                let certificate = load_bounded_runtime_credential_v1(&installation.tls_certificate_file, 1, maximum).map_err(|_| invalid)?;
                let root = load_bounded_runtime_credential_v1(&installation.tls_root_certificate_file, 1, maximum).map_err(|_| invalid)?;
                let key = load_bounded_runtime_credential_v1(&installation.tls_private_key_file, 1, maximum).map_err(|_| invalid)?;
                if certificate.as_slice() != endpoint.attestation.leaf_certificate
                    || endpoint.attestation.intermediate_certificates.len() != 1
                    || root.as_slice() != endpoint.attestation.intermediate_certificates[0] { return Err(invalid); }
                tls = Some(iroha_torii::native_https_server_identity_v1(&[certificate.as_slice()], &key).map_err(|_| invalid)?);
            }
        }
        let transports: [GeneratedLocalProviderTransportV1; 3] = transports.try_into().map_err(|_| invalid)?;
        selected = Some((transports, tls.ok_or(invalid)?, selection_charge));
        Ok(())
    }).map_err(|_| Error::Unqualified)?;
    drop(view);
    let (transports, tls, selection_charge) = selected.ok_or(Error::Unqualified)?;
    let timeout = Duration::from_millis(installation.readback_request_timeout_ms);
    let discovery = discovery::prepare(
        state,
        cache.clone(),
        transports.clone(),
        timeout,
        selection_charge,
    )?;
    let readback = PreparedMusubiArchiveFetchConfigV1::from_generated_local_account_signer(
        context.network_id(),
        &chain,
        installation.ingress_broker.clone(),
        broker.clone(),
        discovery,
        transports,
        timeout,
    )
    .map_err(|_| Error::Unqualified)?
    .build_client()
    .map_err(|_| Error::Unqualified)?;
    let signer =
        SoftwareMusubiSeedIngressReceiptSignerV1::new(installation.ingress_broker.clone(), broker)
            .map_err(|_| Error::Unqualified)?;
    let storage = NativeMusubiStorageBuilderV1::new(
        config.custody_root.join("pin"),
        installation.pin_session,
        pin,
        NativeMusubiStorageLimitsV1 {
            authorization_window_ms: installation.pin_authorization_window_ms,
            max_check_rounds: installation.pin_max_check_rounds,
            fee_asset: installation.pin_fee_asset.clone(),
            per_transaction_fee: installation.pin_per_transaction_fee_limit.clone(),
            total_fees: installation.pin_total_fee_limit.clone(),
        },
    )
    .map_err(|_| Error::Unqualified)?;
    Ok(Some(Box::new(MusubiPublicationPrivateLocalFactoryV1::new(
        settings,
        Box::new(signer),
        Box::new(storage),
        readback,
        cache,
        Box::new(Ingress {
            settings: MusubiPublicationPrivateTlsSettingsV1::from_config(config),
            tls,
        }),
    ))))
}

// Bind only after the local factory has successfully opened every original durable owner.
struct Ingress {
    settings: MusubiPublicationPrivateTlsSettingsV1,
    tls: Arc<tokio_rustls::rustls::ServerConfig>,
}
impl MusubiPublicationPrivateIngressBuilderV1 for Ingress {
    fn build(
        self: Box<Self>,
        service: iroha_musubi_service::MusubiPublicationPrivateServiceV1,
    ) -> Result<MusubiPublicationPrivateDeploymentV1, Error> {
        Box::new(MusubiPublicationPrivateTlsIngressBuilderV1::new(
            self.settings,
            self.tls,
        )?)
        .build(service)
    }
}
