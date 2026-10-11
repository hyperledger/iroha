//! Concrete configured enrollment service over native account authentication and private custody.
//!
//! Optional configuration is installed at node startup. It is the current in-memory operator
//! selection until restart; this service does not claim an unimplemented hot-reload authority.
//! Each operation rechecks complete selection, private custody and native World registration.
//! Platform execution is supported only on the configured Linux private-worker deployment.

use iroha_config::parameters::actual::{KagemushaEnrollmentIssuer, KagemushaEnrollmentProvider};
use iroha_core::{
    kagemusha_wallet_v1::enrollment_issuer::{
        EnrollmentIssuerErrorV1 as IssuerError, EnrollmentIssuerRuntimeV1, EnrollmentIssuerV1,
    },
    state::State as CoreState,
};
use iroha_core_zk::kagemusha_wallet_enrollment_v1::{
    PreKeyDispatchV1,
    issuer_worker::{VerifierConfigurationV1, VerifierExchangeV1},
};
use iroha_data_model::{account::AccountId, kagemusha::KagemushaWalletAssetScopeV1};
use iroha_torii_shared::kagemusha_enrollment::*;
use std::sync::Arc;

mod handler;
mod observation;
mod owner_thread;
mod signer;
#[cfg(test)]
mod test_fixture;
mod worker;
pub(super) use handler::handler;

type Result<T> = std::result::Result<T, IssuerError>;

// These shared online bounds must exactly preserve the native originals' accepted limits.
const _: () = assert!(
    ENROLLMENT_DISPATCH_MAX_BYTES_V1
        == iroha_core_zk::kagemusha_wallet_enrollment_v1::PREKEY_DISPATCH_MAX_BYTES
);
const _: () = assert!(
    ENROLLMENT_EVIDENCE_REQUEST_MAX_BYTES_V1
        == iroha_core_zk::kagemusha_wallet_enrollment_v1::REQUEST_MAX_BYTES
);
const _: () = assert!(
    ENROLLMENT_RESULT_MAX_BYTES_V1
        == iroha_core_zk::kagemusha_wallet_enrollment_v1::RESULT_MAX_BYTES
);

struct ProviderOwner {
    selected: KagemushaEnrollmentProvider,
    observation: observation::EligibilityObservationTransport,
    signer: signer::EnrollmentSigner,
    worker: worker::PrivateVerifier,
}
impl ProviderOwner {
    fn open(provider: &KagemushaEnrollmentProvider) -> Result<Self> {
        Ok(Self {
            selected: provider.clone(),
            observation: observation::EligibilityObservationTransport::open(provider)?,
            signer: signer::EnrollmentSigner::open(&provider.signer_private_key, provider)?,
            worker: worker::PrivateVerifier::open(provider)?,
        })
    }
    fn revalidate(&self, provider: &KagemushaEnrollmentProvider) -> Result<()> {
        if &self.selected != provider {
            return Err(IssuerError::Selection);
        }
        self.observation.revalidate(provider)?;
        self.signer.revalidate(provider)?;
        self.worker.revalidate(provider)
    }
}

/// Private original HTTP input. Only the server extractor constructs it, and the runtime
/// still verifies actual account signatures over every method/path/body byte before use.
struct HttpCall {
    method: axum::http::Method,
    uri: axum::http::Uri,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
}
struct Runtime {
    state: Arc<CoreState>,
    configured: Arc<KagemushaEnrollmentIssuer>,
    providers: Vec<ProviderOwner>,
}
impl Runtime {
    fn selected(&mut self, provider: &KagemushaEnrollmentProvider) -> Result<&mut ProviderOwner> {
        self.providers
            .iter_mut()
            .find(|owner| &owner.selected == provider)
            .ok_or(IssuerError::Selection)
    }
}
impl EnrollmentIssuerRuntimeV1 for Runtime {
    type Call = HttpCall;
    fn current_configuration(&mut self) -> Result<Arc<KagemushaEnrollmentIssuer>> {
        Ok(Arc::clone(&self.configured))
    }
    fn require_dependencies(&mut self, config: &KagemushaEnrollmentIssuer) -> Result<()> {
        if config != self.configured.as_ref() || config.providers.len() != self.providers.len() {
            return Err(IssuerError::Selection);
        }
        for (selected, owner) in config.providers.iter().zip(&self.providers) {
            owner.revalidate(selected)?;
        }
        Ok(())
    }
    fn authenticate_call(
        &mut self,
        call: &HttpCall,
        expected_dispatch: &[u8],
    ) -> Result<AccountId> {
        authenticate_http(&self.state, call, expected_dispatch)
    }
    fn now_ms(&mut self) -> Result<u64> {
        let elapsed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| IssuerError::Unavailable)?;
        u64::try_from(elapsed.as_millis()).map_err(|_| IssuerError::Unavailable)
    }
    fn observe_eligibility(
        &mut self,
        provider: &KagemushaEnrollmentProvider,
        asset: &KagemushaWalletAssetScopeV1,
        request: &[u8],
        timeout: std::time::Duration,
    ) -> Result<Vec<u8>> {
        self.selected(provider)?
            .observation
            .observe(provider, asset, request, timeout)
    }
    fn worker_configuration(
        &mut self,
        provider: &KagemushaEnrollmentProvider,
        asset: &KagemushaWalletAssetScopeV1,
    ) -> Result<VerifierConfigurationV1> {
        self.selected(provider)?
            .worker
            .configuration(provider, asset)
    }
    fn worker_exchange(
        &mut self,
        provider: &KagemushaEnrollmentProvider,
        configuration: &VerifierConfigurationV1,
        exchange: &VerifierExchangeV1,
    ) -> Result<Vec<u8>> {
        self.selected(provider)?
            .worker
            .exchange(provider, configuration, exchange)
    }
    fn sign_enrollment(
        &mut self,
        provider: &KagemushaEnrollmentProvider,
        message: &[u8; 32],
    ) -> Result<Vec<u8>> {
        self.selected(provider)?.signer.sign(provider, message)
    }
}

pub(super) struct EnrollmentService {
    owner: Arc<owner_thread::OwnerThread>,
    slots: Arc<tokio::sync::Semaphore>,
    body_timeout: std::time::Duration,
}
impl EnrollmentService {
    pub(super) fn open(state: Arc<CoreState>, config: KagemushaEnrollmentIssuer) -> Result<Self> {
        if config.max_inflight == 0 || config.max_inflight > 1024 {
            return Err(IssuerError::Selection);
        }
        let slots = Arc::new(tokio::sync::Semaphore::new(config.max_inflight));
        let body_timeout = config.request_timeout;
        let owner = Arc::new(owner_thread::OwnerThread::open(state, config)?);
        Ok(Self {
            owner,
            slots,
            body_timeout,
        })
    }
}

/// Register the private issuer thread in normal startup, rollback and test-router shutdown.
pub(super) fn register_worker(
    app: &crate::AppState,
    shutdown: iroha_futures::supervisor::ShutdownSignal,
    workers: &mut Vec<crate::ToriiCriticalWorker>,
) -> std::result::Result<(), &'static str> {
    if let Some(service) = app.kagemusha_enrollment.as_ref() {
        workers.push(crate::ToriiCriticalWorker {
            name: "kagemusha_enrollment",
            task: service
                .owner
                .supervise(shutdown, Arc::clone(&service.slots))?,
        });
    }
    Ok(())
}

fn execute(
    owner: &mut EnrollmentIssuerV1<Runtime>,
    call: &HttpCall,
) -> Result<EnrollmentServiceResponseV1> {
    let envelope = EnrollmentServiceRequestV1::decode_canonical(&call.body)
        .map_err(|_| IssuerError::Invalid)?;
    let mut session = owner.authenticate(call, &envelope.dispatch_original)?;
    match envelope.action {
        EnrollmentServiceActionV1::PreKey => owner
            .pre_key_permit(&mut session)
            .map(EnrollmentServiceResponseV1::Permit),
        EnrollmentServiceActionV1::Evidence => {
            match owner.verify_evidence(&mut session, &envelope.evidence_original) {
                Ok(()) => Ok(EnrollmentServiceResponseV1::EvidenceReady),
                Err(IssuerError::Pending) => Ok(EnrollmentServiceResponseV1::Pending),
                Err(error) => Err(error),
            }
        }
        EnrollmentServiceActionV1::Issue => owner
            .issue_credential(&mut session)
            .map(|()| EnrollmentServiceResponseV1::CredentialReady),
        EnrollmentServiceActionV1::Deliver => owner
            .deliver_credential(&mut session)
            .map(EnrollmentServiceResponseV1::Credential),
    }
}

fn authenticate_http(
    state: &Arc<CoreState>,
    call: &HttpCall,
    expected_dispatch: &[u8],
) -> Result<AccountId> {
    if call.method != axum::http::Method::POST
        || call.uri.path() != ENROLLMENT_SERVICE_ROUTE_V1
        || call.uri.query().is_some()
    {
        return Err(IssuerError::Invalid);
    }
    let envelope = EnrollmentServiceRequestV1::decode_canonical(&call.body)
        .map_err(|_| IssuerError::Invalid)?;
    if envelope.dispatch_original != expected_dispatch {
        return Err(IssuerError::Invalid);
    }
    let dispatch = PreKeyDispatchV1::decode(expected_dispatch).map_err(|_| IssuerError::Invalid)?;
    let context = norito::core::DecodeBudgetContext::new(norito::canonical_decode_limits(
        8 * ENROLLMENT_SERVICE_REQUEST_MAX_BYTES_V1,
    ));
    let authenticated = crate::app_auth::verify_canonical_network_request(
        state,
        state.network_id_ref(),
        &call.headers,
        &call.method,
        &call.uri,
        &call.body,
        Some(&dispatch.account),
        &context,
    )
    .map_err(|_| IssuerError::Invalid)?
    .ok_or(IssuerError::Invalid)?;
    Ok(authenticated.account)
}

#[cfg(test)]
mod tests;
