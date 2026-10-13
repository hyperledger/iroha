//! Proxy working-set ownership through asynchronous finalization and final response delivery.
use super::{Response, ToriiProxyMemoryReservation, hold_torii_proxy_memory_in_response_body};

/// Complete every source-owned admission step before transferring W to the final Body.
/// The finalizer executes inline; this function creates no independent task or writer.
pub async fn complete<F, Fut>(
    response: Response,
    memory: ToriiProxyMemoryReservation,
    finalize: F,
) -> Response
where
    F: FnOnce(Response) -> Fut,
    Fut: std::future::Future<Output = Response>,
{
    let response = finalize(response).await;
    hold_torii_proxy_memory_in_response_body(response, memory)
}

#[cfg(test)]
mod tests;
