#![allow(
    clippy::missing_errors_doc,
    missing_docs,
    clippy::panic,
    clippy::unwrap_used,
    clippy::unwrap_in_result,
    clippy::integer_arithmetic,
    clippy::expect_used
)]

use std::{
    convert::TryFrom,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
use std::{io, sync::Arc};

use dashmap::DashMap;
use iroha_error::{error, Result};
use once_cell::sync::Lazy;
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf},
    runtime::Handle,
    sync::mpsc::{self, Sender},
    task,
};

use super::{AsyncStream, Request, Response, State};

static ENDPOINTS: Lazy<DashMap<String, Sender<RequestStream>>> = Lazy::new(DashMap::new);

fn find_sender(server_url: &str) -> Sender<RequestStream> {
    if let Some(entry) = ENDPOINTS.get(server_url) {
        return entry.value().clone();
    }
    panic!("Can't find ENDPOINT: {}", server_url);
}

struct RequestStream {
    bytes: Vec<u8>,
    tx: Sender<Vec<u8>>,
}

impl Unpin for RequestStream {}

impl AsyncRead for RequestStream {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf,
    ) -> Poll<io::Result<()>> {
        let bytes = &mut self.get_mut().bytes;
        let length = if buf.remaining() > bytes.len() {
            bytes.len()
        } else {
            buf.remaining()
        };
        let bytes: Vec<_> = bytes.drain(..length).collect();
        buf.put_slice(&bytes);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for RequestStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let bytes = &mut self.get_mut().bytes;
        for byte in buf.to_vec() {
            bytes.push(byte);
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        task::block_in_place(|| Handle::current().block_on(self.tx.send(self.bytes.clone())))
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

pub async fn send_request_to(server_url: &str, request: Request) -> Result<Response> {
    let (tx, mut rx) = mpsc::channel(100);
    let mut stream = RequestStream {
        bytes: Vec::new(),
        tx,
    };
    let payload: Vec<u8> = request.into();
    stream.write_all(&payload).await?;
    find_sender(server_url)
        .send(stream)
        .await
        .map_err(|_err| error!("Receiver dropped."))?;
    //TODO: return actual response
    Response::try_from(rx.recv().await.unwrap())
}

pub async fn listen<H, F, S>(state: State<S>, server_url: &str, mut handler: H) -> Result<()>
where
    H: Send + FnMut(State<S>, Box<dyn AsyncStream>) -> F,
    F: Send + Future<Output = Result<()>>,
    State<S>: Send + Sync,
{
    let (tx, mut rx) = mpsc::channel(100);
    let _result = ENDPOINTS.insert(server_url.to_owned(), tx);
    while let Some(stream) = rx.recv().await {
        handler(Arc::clone(&state), Box::new(stream)).await?;
    }
    Ok(())
}
