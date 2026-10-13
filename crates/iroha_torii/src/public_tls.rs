//! Optional native HTTPS transport; identity loading grants no route or provider authority.

use std::{io, sync::Arc, time::Duration};

use iroha_config::parameters::{actual::ToriiHttpsTransport, defaults::torii::transport::https};
use iroha_primitives::addr::SocketAddr;
use tokio::net::TcpListener;
use tokio_rustls::{
    TlsAcceptor,
    rustls::{
        self,
        pki_types::{CertificateDer, PrivateKeyDer},
    },
};

/// Validate programmatically constructed actual configurations as well as parsed ones.
pub fn validate(config: &ToriiHttpsTransport) -> io::Result<()> {
    if !(1..=https::MAX_CERTIFICATES).contains(&config.certificate_chain.len())
        || config
            .certificate_chain
            .iter()
            .any(|path| path.as_os_str().is_empty())
        || config.private_key.as_os_str().is_empty()
        || config.handshake_timeout.is_zero()
        || config.handshake_timeout > Duration::from_millis(https::MAX_HANDSHAKE_TIMEOUT_MS)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid Torii HTTPS identity or handshake bounds",
        ));
    }
    Ok(())
}

/// Successfully loaded identity; neither listener nor service worker has started.
pub struct PreparedHttps {
    address: SocketAddr,
    acceptor: TlsAcceptor,
    handshake_timeout: Duration,
}
impl PreparedHttps {
    /// Read bounded native private files and check the actual leaf/key pair.
    pub(super) fn load(config: &ToriiHttpsTransport) -> io::Result<Self> {
        validate(config)?;
        let certificates = config
            .certificate_chain
            .iter()
            .map(|path| iroha_fs::read_private(path, https::MAX_DER_BYTES))
            .collect::<io::Result<Vec<_>>>()?;
        let bytes = iroha_fs::read_private(&config.private_key, https::MAX_DER_BYTES)?;
        let borrowed = certificates
            .iter()
            .map(|bytes| bytes.as_slice())
            .collect::<Vec<_>>();
        let server = native_https_server_identity_v1(&borrowed, &bytes)?;
        Ok(Self {
            address: config.address.value().clone(),
            acceptor: TlsAcceptor::from(server),
            handshake_timeout: config.handshake_timeout,
        })
    }

    /// Bind only after identity admission, before Torii starts its service workers.
    pub(super) async fn bind(self) -> io::Result<BoundHttpsListener> {
        let listener = super::bind_torii_tcp_listener(self.address).await?;
        Ok(BoundHttpsListener {
            listener,
            identity: HttpsIdentity {
                acceptor: self.acceptor,
                handshake_timeout: self.handshake_timeout,
            },
        })
    }
}

/// Build an ordinary native server identity from bounded runtime-held DER originals.
///
/// This shares the public and private listener's sole DER/key admission. It grants no route,
/// provider or native service authority. Root/name/time verification belongs to TLS clients.
/// # Errors
/// Invalid bounds, malformed/trailing DER, or a certificate/private-key mismatch.
pub fn native_https_server_identity_v1(
    certificate_chain: &[&[u8]],
    private_key: &[u8],
) -> io::Result<Arc<rustls::ServerConfig>> {
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, "invalid native HTTPS identity");
    if !(1..=https::MAX_CERTIFICATES).contains(&certificate_chain.len())
        || private_key.is_empty()
        || private_key.len() > https::MAX_DER_BYTES
    {
        return Err(invalid());
    }
    let mut certificates = Vec::with_capacity(certificate_chain.len());
    for bytes in certificate_chain {
        if bytes.is_empty() || bytes.len() > https::MAX_DER_BYTES {
            return Err(invalid());
        }
        let (remaining, _) = x509_parser::parse_x509_certificate(bytes).map_err(|_| invalid())?;
        if !remaining.is_empty() {
            return Err(invalid());
        }
        certificates.push(CertificateDer::from(bytes.to_vec()));
    }
    let private_key = PrivateKeyDer::try_from(private_key.to_vec()).map_err(|_| invalid())?;
    let mut server = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|_| invalid())?
    .with_no_client_auth()
    .with_single_cert(certificates, private_key)
    .map_err(|_| invalid())?;
    server.max_early_data_size = 0;
    server.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(server))
}

#[derive(Clone)]
pub struct HttpsIdentity {
    pub(super) acceptor: TlsAcceptor,
    pub(super) handshake_timeout: Duration,
}

pub struct BoundHttpsListener {
    pub(super) listener: TcpListener,
    pub(super) identity: HttpsIdentity,
}

#[cfg(test)]
mod tests;
