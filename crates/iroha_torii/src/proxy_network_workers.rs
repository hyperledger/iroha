//! Separately supervised proxy response delivery and bounded physical admission work.
use super::*;
use iroha_p2p::{
    network::{
        SubscriberFilter,
        message::{SubscriberRoute, Topic},
    },
    peer::message::{PeerMessage, PeerMessageRetentionGuard},
};
use tokio::{
    runtime::{Handle, RuntimeFlavor},
    sync::mpsc,
};

/// One admitted request, including its complete proxy working set and transport owner.
pub struct RequestWork {
    peer: Peer,
    request: Arc<ToriiProxyRequestV1>,
    proxy_memory: ToriiProxyMemoryReservation,
    transport: PeerMessageRetentionGuard,
}

/// Validate the executor before publishing any child or channel endpoint.
fn runtime() -> Result<Handle, &'static str> {
    let handle =
        Handle::try_current().map_err(|_| "Torii proxy workers require an active Tokio runtime")?;
    if handle.runtime_flavor() != RuntimeFlavor::MultiThread {
        return Err("Torii proxy workers require a multithreaded Tokio runtime");
    }
    Ok(handle)
}

/// One sequential physical worker. Inline ownership survives cancellation during synchronous work.
async fn run_work<T, F, Fut>(
    mut input: mpsc::Receiver<T>,
    shutdown: ShutdownSignal,
    runtime: Handle,
    mut process: F,
) -> ToriiCriticalWorkerExit
where
    F: FnMut(T) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    loop {
        let next = tokio::select! {
            biased;
            () = shutdown.receive() => return ToriiCriticalWorkerExit::StoppedByShutdown,
            next = input.recv() => next,
        };
        let Some(work) = next else {
            return if shutdown.is_sent() {
                ToriiCriticalWorkerExit::StoppedByShutdown
            } else {
                ToriiCriticalWorkerExit::UnexpectedExit
            };
        };
        // This is a separate supervised task from the response pump. Handing off its
        // executor core also permits response progress on a one-worker runtime. The
        // original request deadline remains in the message and all existing handlers.
        // No per-request task, detached blocking writer or unbounded queue is created.
        tokio::task::block_in_place(|| runtime.block_on(process(work)));
        tokio::task::yield_now().await;
    }
}

/// Start the exact two-child topology after validating its execution context.
pub fn start(
    app: SharedAppState,
    network: iroha_core::IrohaNetwork,
    shutdown: ShutdownSignal,
) -> Result<[ToriiCriticalWorker; 2], &'static str> {
    let runtime = runtime()?;
    let (request_tx, request_rx) = mpsc::channel(1);
    let request_app = app.clone();
    let request_network = network.clone();
    let request_task = runtime.spawn(run_work(
        request_rx,
        shutdown.clone(),
        runtime.clone(),
        move |work: RequestWork| {
            let app = request_app.clone();
            let network = request_network.clone();
            async move {
                let RequestWork {
                    peer,
                    request,
                    proxy_memory,
                    transport,
                } = work;
                process_incoming_torii_proxy_request(app, network, peer, request, proxy_memory)
                    .await;
                drop(transport);
            }
        },
    ));
    let response_task = runtime.spawn(pump(app, network, shutdown, request_tx));
    Ok([
        ToriiCriticalWorker {
            name: "torii_proxy_network",
            task: response_task,
        },
        ToriiCriticalWorker {
            name: "torii_proxy_request",
            task: request_task,
        },
    ])
}

/// Deliver responses without executing admission or polling its blocking future.
async fn pump(
    app: SharedAppState,
    network: iroha_core::IrohaNetwork,
    shutdown: ShutdownSignal,
    requests: mpsc::Sender<RequestWork>,
) -> ToriiCriticalWorkerExit {
    let (mut tx, mut rx) = mpsc::channel(network.subscriber_queue_cap().get());
    let filter = SubscriberFilter::topics_for_route([Topic::Control], SubscriberRoute::ToriiProxy);
    loop {
        if shutdown.is_sent() {
            return ToriiCriticalWorkerExit::StoppedByShutdown;
        }
        match network.subscribe_to_peers_messages_with_filter(tx, filter.clone()) {
            Ok(()) => break,
            Err(returned) => {
                tx = returned;
                tokio::select! {
                    () = shutdown.receive() => return ToriiCriticalWorkerExit::StoppedByShutdown,
                    () = tokio::time::sleep(Duration::from_millis(50)) => {}
                }
            }
        }
    }
    loop {
        let next = tokio::select! {
            biased;
            () = shutdown.receive() => return ToriiCriticalWorkerExit::StoppedByShutdown,
            next = rx.recv() => next,
        };
        let Some(message) = next else {
            return if shutdown.is_sent() {
                ToriiCriticalWorkerExit::StoppedByShutdown
            } else {
                ToriiCriticalWorkerExit::UnexpectedExit
            };
        };
        dispatch(&app, &network, &requests, message).await;
    }
}

/// Transfer each retained message to its final bounded owner, or drop it on explicit backpressure.
pub async fn dispatch(
    app: &SharedAppState,
    network: &iroha_core::IrohaNetwork,
    requests: &mpsc::Sender<RequestWork>,
    message: PeerMessage<iroha_core::NetworkMessage>,
) {
    let (peer, _authenticated_via, payload, _bytes, transport) = message.into_parts();
    match payload {
        iroha_core::NetworkMessage::ToriiProxyRequest(request) => {
            let proxy_memory = match try_acquire_torii_proxy_receiver_memory(app) {
                Ok(reservation) => reservation,
                Err(_) => {
                    reject_incoming_torii_proxy_request_capacity(
                        network,
                        &peer,
                        request.request_id,
                        request.deadline_unix_ms,
                    );
                    return;
                }
            };
            let work = RequestWork {
                peer,
                request,
                proxy_memory,
                transport,
            };
            if let Err(error) = requests.try_send(work) {
                let work = error.into_inner();
                reject_incoming_torii_proxy_request_capacity(
                    network,
                    &work.peer,
                    work.request.request_id,
                    work.request.deadline_unix_ms,
                );
            }
        }
        iroha_core::NetworkMessage::ToriiProxyResponse(response) => {
            process_incoming_torii_proxy_response(app, peer.id().clone(), *response).await;
            drop(transport);
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests;
