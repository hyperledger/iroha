//! Explicit original socket custody across renewal fixture HTTP phases.

use std::{
    io,
    net::{Ipv4Addr, SocketAddr, TcpListener},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

pub(in crate::managed) struct ReservedHttpListeners {
    listeners: Vec<Arc<ReservedListener>>,
}

struct ReservedListener {
    listener: TcpListener,
    address: SocketAddr,
    busy: AtomicBool,
}

pub(in crate::managed) struct ListenerLoan {
    owner: Arc<ReservedListener>,
}

fn endpoint(url: &url::Url) -> io::Result<SocketAddr> {
    if url.scheme() != "http"
        || url.host_str() != Some("127.0.0.1")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected exact loopback HTTP endpoint",
        ));
    }
    let port = url
        .port_or_known_default()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing HTTP endpoint port"))?;
    Ok((Ipv4Addr::LOCALHOST, port).into())
}

impl ReservedHttpListeners {
    pub(in crate::managed) fn new(
        listeners: Vec<TcpListener>,
        endpoints: &[url::Url],
    ) -> io::Result<Self> {
        if listeners.len() != 4 || endpoints.len() != 4 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "expected four original API sockets",
            ));
        }
        let mut retained = Vec::with_capacity(4);
        for (listener, url) in listeners.into_iter().zip(endpoints) {
            let address = endpoint(url)?;
            if listener.local_addr()? != address
                || retained
                    .iter()
                    .any(|prior: &Arc<ReservedListener>| prior.address == address)
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "reserved socket differs from generated endpoint",
                ));
            }
            listener.set_nonblocking(true)?;
            retained.push(Arc::new(ReservedListener {
                listener,
                address,
                busy: AtomicBool::new(false),
            }));
        }
        Ok(Self {
            listeners: retained,
        })
    }

    pub(in crate::managed) fn loan(&self, url: &url::Url) -> io::Result<ListenerLoan> {
        let address = endpoint(url)?;
        let owner = self
            .listeners
            .iter()
            .find(|owner| owner.address == address)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "endpoint is not an original reserved socket",
                )
            })?;
        owner
            .busy
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "original HTTP socket already has a responder",
                )
            })?;
        let loan = ListenerLoan {
            owner: Arc::clone(owner),
        };
        // No responder existed in the gap. A queued request is a fixture failure, not
        // work that a fresh phase may silently consume. Inspect at most one connection.
        owner.require_idle()?;
        Ok(loan)
    }

    pub(in crate::managed) fn loan_all(
        &self,
        endpoints: &[url::Url],
    ) -> io::Result<Vec<ListenerLoan>> {
        if endpoints.len() != self.listeners.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "generated peer count changed",
            ));
        }
        for (owner, url) in self.listeners.iter().zip(endpoints) {
            if endpoint(url)? != owner.address {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "generated peer endpoint changed",
                ));
            }
        }
        // collect drops every acquired loan on refusal, before a caller can spawn workers.
        endpoints.iter().map(|url| self.loan(url)).collect()
    }
}

impl ReservedListener {
    fn require_idle(&self) -> io::Result<()> {
        match self.listener.accept() {
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(()),
            Err(error) => Err(error),
            Ok(_) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "request queued without an active fixture responder",
            )),
        }
    }
}

impl Drop for ReservedListener {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            assert!(!self.busy.load(Ordering::SeqCst));
            self.require_idle()
                .expect("no HTTP request may escape the last fixture phase");
        }
    }
}

impl ListenerLoan {
    pub(in crate::managed) fn clone_listener(&self) -> io::Result<TcpListener> {
        self.owner.listener.try_clone()
    }
}

impl Drop for ListenerLoan {
    fn drop(&mut self) {
        assert!(self.owner.busy.swap(false, Ordering::SeqCst));
    }
}

#[cfg(test)]
#[path = "owned_listener_tests.rs"]
mod tests;
