//! Cancellation across actual onboarding HTTP calls keeps exact signed recovery evidence.

use super::*;
use iroha::http::{HttpTransport as _, Method, Response, TransportRequest};
use std::{
    io::{Read as _, Write as _},
    net::TcpListener,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread::{self, JoinHandle},
};

const ONBOARDING_TOKEN: &str = "test-runtime-onboarding-token-00000000";

struct HttpFixture {
    url: Url,
    requests: Arc<Mutex<Vec<(String, String)>>>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl HttpFixture {
    fn start(handler: impl Fn(TransportRequest) -> Response<Vec<u8>> + Send + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
        let root = url.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = Arc::clone(&stop);
        let requests = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&requests);
        let worker = thread::spawn(move || {
            let _profile = ChainDiscriminantGuard::enter(0x02f1);
            while !stopped.load(Ordering::Acquire) {
                let (mut socket, _) = match listener.accept() {
                    Ok(socket) => socket,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                        continue;
                    }
                    Err(error) => panic!("HTTP fixture accept failed: {error}"),
                };
                // Accepted sockets may inherit O_NONBLOCK on macOS. The bounded parser
                // deliberately uses blocking reads on every platform.
                socket.set_nonblocking(false).unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                socket
                    .set_write_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut head = Vec::new();
                while !head.ends_with(b"\r\n\r\n") {
                    let mut byte = [0];
                    socket.read_exact(&mut byte).unwrap();
                    head.push(byte[0]);
                    assert!(head.len() <= 16 * 1024, "bounded fixture HTTP headers");
                }
                let head = String::from_utf8(head).unwrap();
                let mut lines = head.split("\r\n");
                let mut request_line = lines.next().unwrap().split_whitespace();
                let method: Method = request_line.next().unwrap().parse().unwrap();
                let url = root.join(request_line.next().unwrap()).unwrap();
                let length = lines
                    .filter_map(|line| line.split_once(':'))
                    .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                    .map_or(0, |(_, value)| value.trim().parse::<usize>().unwrap());
                assert!(length <= 1024 * 1024, "bounded fixture request body");
                let mut body = vec![0; length];
                socket.read_exact(&mut body).unwrap();
                recorded
                    .lock()
                    .unwrap()
                    .push((method.to_string(), url.path().to_owned()));
                let response = handler(TransportRequest {
                    method,
                    url,
                    headers: Vec::new(),
                    body,
                    timeout: None,
                    max_response_bytes: 1024 * 1024,
                    direct_loopback: true,
                });
                let content_type = response
                    .headers()
                    .get("content-type")
                    .unwrap()
                    .to_str()
                    .unwrap();
                write!(socket,
                    "HTTP/1.1 {} response\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    response.status().as_u16(), response.body().len()).unwrap();
                socket.write_all(response.body()).unwrap();
            }
        });
        Self {
            url,
            requests,
            stop,
            worker: Some(worker),
        }
    }

    fn observed(&self) -> Vec<(String, String)> {
        self.requests.lock().unwrap().clone()
    }
}

impl Drop for HttpFixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let result = worker.join();
            if !thread::panicking() {
                result.unwrap();
            }
        }
    }
}

fn json_response(value: &impl norito::json::JsonSerialize) -> Response<Vec<u8>> {
    Response::builder()
        .status(200)
        .header("Content-Type", "application/json")
        .body(json::to_vec(value).unwrap())
        .unwrap()
}

#[test]
fn cancellation_binding_survives_shorter_deadlines_and_rejects_replacement() {
    let (config, _) = faucet_fixture();
    let signal = Arc::new(AtomicBool::new(false));
    let deadline = Instant::now() + Duration::from_secs(30);
    let service = OnboardingService::new(config)
        .unwrap()
        .with_cancellation(Arc::clone(&signal))
        .unwrap()
        .with_deadline(deadline)
        .unwrap()
        .with_deadline(deadline + Duration::from_secs(30))
        .unwrap()
        .with_cancellation(Arc::clone(&signal))
        .unwrap();
    assert_eq!(service.deadline, Some(deadline));
    assert!(Arc::ptr_eq(service.cancellation.as_ref().unwrap(), &signal));
    assert!(
        service
            .with_cancellation(Arc::new(AtomicBool::new(false)))
            .is_err()
    );
}

#[test]
fn cancellation_during_real_onboarding_plan_refuses_prepare_and_journal_publication() {
    let _profile = ChainDiscriminantGuard::enter(0x02f1);
    let (mut config, operation) = onboarding_fixture(false);
    let OperationV1::Onboarding(onboarding) = operation.operation else {
        unreachable!()
    };
    let request = OnboardingRequest {
        alias: onboarding.request.alias.clone(),
        issuer: onboarding.issuer.clone(),
        permissions: onboarding.request.permissions.clone(),
        fee_payment: operation.fee_payment,
    };
    let signal = Arc::new(AtomicBool::new(false));
    let cancel = Arc::clone(&signal);
    let fixture = HttpFixture::start(move |request| {
        assert_eq!(request.method, Method::POST);
        assert_eq!(request.url.path(), "/v1/accounts/onboard/plan");
        cancel.store(true, Ordering::Release);
        json_response(&onboarding.receipt)
    });
    config.torii_api_url = fixture.url.clone();
    let service = OnboardingService::new(config)
        .unwrap()
        .with_cancellation(signal)
        .unwrap();
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("cancelled-plan");
    let error = service
        .prepare_onboarding(
            &request,
            ONBOARDING_TOKEN,
            &PreparationOptions::default(),
            &path,
        )
        .unwrap_err();
    assert!(error.to_string().contains("cancelled"), "{error:?}");
    assert!(!path.exists());
    assert_eq!(
        fixture.observed(),
        vec![("POST".into(), "/v1/accounts/onboard/plan".into())]
    );
    assert!(
        service
            .prepare_onboarding(
                &request,
                ONBOARDING_TOKEN,
                &PreparationOptions::default(),
                &path
            )
            .unwrap_err()
            .to_string()
            .contains("cancelled")
    );
    assert_eq!(
        fixture.observed().len(),
        1,
        "cancellation must prevent another plan POST"
    );
}

#[test]
fn cancelled_fresh_faucet_preparation_does_not_fetch_a_puzzle_or_create_custody() {
    let _profile = ChainDiscriminantGuard::enter(0x02f1);
    let (mut config, operation) = faucet_fixture();
    let OperationV1::Faucet(faucet) = operation.operation else {
        unreachable!()
    };
    let request = FaucetRequest {
        issuer: faucet.issuer,
        asset_definition: faucet.asset_definition,
        amount: faucet.amount,
        fee_payment: faucet.requested_fee,
    };
    let fixture = HttpFixture::start(|_| panic!("cancelled preparation must not reach HTTP"));
    config.torii_api_url = fixture.url.clone();
    let service = OnboardingService::new(config)
        .unwrap()
        .with_cancellation(Arc::new(AtomicBool::new(true)))
        .unwrap();
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("cancelled-faucet");
    let error = service
        .prepare_faucet(&request, &PreparationOptions::default(), &path)
        .unwrap_err();
    assert!(error.to_string().contains("cancelled"));
    assert!(!path.exists());
    assert!(fixture.observed().is_empty());
}

#[test]
fn cancellation_during_real_submit_preflight_preserves_signed_bytes_and_allows_exact_recovery() {
    let _profile = ChainDiscriminantGuard::enter(0x02f1);
    for (mut config, mut operation) in [onboarding_fixture(false), faucet_fixture()] {
        let transaction = operation
            .verify(&config, operation.kind())
            .unwrap()
            .unwrap();
        for attempted in [false, true] {
            let signal = Arc::new(AtomicBool::new(false));
            let cancel = Arc::clone(&signal);
            let applied = Arc::new(AtomicBool::new(false));
            let observed_applied = Arc::clone(&applied);
            let absent = RecoveryTransport {
                expected: transaction.clone(),
                returned: transaction.clone(),
                status: "Absent",
                source: "state",
                calls: AtomicUsize::new(0),
            };
            let present = RecoveryTransport {
                expected: transaction.clone(),
                returned: transaction.clone(),
                status: "Applied",
                source: "state",
                calls: AtomicUsize::new(0),
            };
            let fixture = HttpFixture::start(move |request| {
                if request.url.path() == "/v1/pipeline/transactions/status" {
                    cancel.store(true, Ordering::Release);
                }
                if observed_applied.load(Ordering::Acquire) {
                    present.send_blocking(request).unwrap()
                } else {
                    absent.send_blocking(request).unwrap()
                }
            });
            config.torii_api_url = fixture.url.clone();
            operation.torii_url = config.torii_api_url.to_string();
            let temporary = tempfile::tempdir().unwrap();
            let path = temporary.path().join("signed-bootstrap");
            {
                let journal = Journal::create_prepared(&path, &operation).unwrap();
                if attempted {
                    assert!(journal.record_submission(&operation).unwrap());
                }
            }
            let original = std::fs::read(path.join("operation.json")).unwrap();
            let marker = std::fs::read(path.join("submission.json")).ok();
            let service = OnboardingService::new(config.clone())
                .unwrap()
                .with_cancellation(signal)
                .unwrap();
            let faucet_request = match &operation.operation {
                OperationV1::Faucet(faucet) => Some(FaucetRequest {
                    issuer: faucet.issuer.clone(),
                    asset_definition: faucet.asset_definition.clone(),
                    amount: faucet.amount.clone(),
                    fee_payment: faucet.requested_fee.clone(),
                }),
                OperationV1::Onboarding(_) => None,
            };
            let result = if let Some(request) = &faucet_request {
                service.submit_faucet_with_request(&path, request, 5)
            } else {
                service.submit_onboarding(&path, ONBOARDING_TOKEN, 5)
            };
            if attempted {
                assert_eq!(result.unwrap().status, OperationStatus::Pending);
            } else {
                assert!(result.unwrap_err().to_string().contains("cancelled"));
            }
            assert_eq!(
                std::fs::read(path.join("operation.json")).unwrap(),
                original
            );
            assert_eq!(std::fs::read(path.join("submission.json")).ok(), marker);
            applied.store(true, Ordering::Release);
            let recovered = if let Some(request) = &faucet_request {
                service.verify_faucet_journal(&path, request).unwrap();
                service.resume_faucet_with_request(&path, request, 5)
            } else {
                service.resume_onboarding(&path, 5)
            };
            assert_eq!(recovered.unwrap().status, OperationStatus::Applied);
            assert_eq!(
                std::fs::read(path.join("operation.json")).unwrap(),
                original
            );
            assert_eq!(std::fs::read(path.join("submission.json")).ok(), marker);
            let requests = fixture.observed();
            assert!(
                requests.iter().any(|(method, path)| method == "POST"
                    && path == "/v1/pipeline/transactions/details"),
                "recovery must verify the saved transaction's committed wire"
            );
            assert!(
                requests
                    .iter()
                    .all(|(_, path)| !path.starts_with("/v1/accounts/")),
                "only exact read-only recovery is allowed; no onboarding/faucet mutation POST"
            );
        }
    }
}
