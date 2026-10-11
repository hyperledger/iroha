//! One bounded outbound relay turn shared by native supervision and desktop callers.

use std::{num::NonZeroU64, time::Instant};

use iroha::{client::Client, config::Config};
use iroha_wallet::operations::BoundedTransactionOptions;

use super::*;
use crate::verify::finality::FinalitySource;

/// Compact local certificate retrieval; returned values confer no finality authority.
/// The attachment verifies every supplied successor against its parent-confirmed child cursor.
pub trait PrivateRootSource {
    /// Return the requested original certificate, or no work when that height is not available.
    ///
    /// # Errors
    /// Transport, local custody or decoding failed. An error never advances the parent cursor.
    fn anchor(&self, height: NonZeroU64) -> Result<Option<PrivateDataspaceAnchor>>;
}

/// Immutable owner-token client that can contact only the selected loopback private root.
/// Its credentials never enter the separate parent wallet or finality clients.
pub struct LocalPrivateRootSource {
    client: Client,
    registration: PrivateDataspaceRegistration,
    deadline: Instant,
}

impl LocalPrivateRootSource {
    /// Bind local reads to the owner, exact retained signed child identity and one deadline.
    /// No endpoint, identity or trust key is selected from an HTTP response.
    ///
    /// # Errors
    /// Rejects a changed child/signer, missing owner token, nonnumeric/nonloopback host,
    /// embedded URL credentials or exhausted deadline before performing any network I/O.
    pub fn new(config: Config, identity: &AttachmentIdentity, deadline: Instant) -> Result<Self> {
        identity.validate()?;
        require_time(deadline)?;
        let endpoint = &config.torii_api_url;
        let loopback = match endpoint.host() {
            Some(url::Host::Ipv4(address)) => address.is_loopback(),
            Some(url::Host::Ipv6(address)) => address.is_loopback(),
            _ => false,
        };
        if !loopback
            || config.api_token.is_none()
            || config.basic_auth.is_some()
            || config.account != identity.owner
            || config.network_id != identity.registration.child_network_id
            || config.chain != identity.registration.child_chain_id
        {
            return Err(AttachmentError::Invalid(
                "local relay client differs from the owner-private child context",
            ));
        }
        let client = Client::builder(config)
            .build()
            .map_err(|_| AttachmentError::Invalid("invalid local relay client context"))?
            .with_request_deadline(deadline);
        Ok(Self {
            client,
            registration: identity.registration.clone(),
            deadline,
        })
    }
}

impl PrivateRootSource for LocalPrivateRootSource {
    fn anchor(&self, height: NonZeroU64) -> Result<Option<PrivateDataspaceAnchor>> {
        require_time(self.deadline)?;
        if height.get() < 2 {
            return Err(AttachmentError::Invalid(
                "cannot relay private genesis bodies",
            ));
        }
        let registration = self
            .client
            .get_private_root_registration(self.registration.scope)
            .map_err(|_| AttachmentError::Operation("local private registration is unavailable"))?;
        if registration != self.registration {
            return Err(AttachmentError::Invalid(
                "local listener substituted its retained private genesis",
            ));
        }
        let client = iroha::blocking::Client::from_client(self.client.clone())
            .map_err(|_| AttachmentError::Operation("cannot open local private status client"))?;
        let status = client
            .status()
            .get()
            .map_err(|_| AttachmentError::Operation("local private status is unavailable"))?;
        require_time(self.deadline)?;
        // This hint suppresses idle polls only. It never establishes local finality or parent
        // anchoring; a claimed successor still needs the original compact native certificate.
        if status.blocks < height.get() {
            return Ok(None);
        }
        let anchor = self
            .client
            .get_private_root_anchor(self.registration.scope, height)
            .map_err(|_| AttachmentError::Operation("local original certificate is unavailable"))?;
        require_time(self.deadline)?;
        Ok(Some(anchor))
    }
}

/// Independently authenticated parent context for one relay turn.
/// Its absolute deadline and exact fee limits survive all preparation/recovery within the turn.
pub struct RelayParent<'a, S: FinalitySource + ?Sized> {
    /// Parent wallet configuration, without the child's listener credential.
    pub config: &'a Config,
    /// Independently authenticated installed network release.
    pub bootstrap: &'a AuthenticatedBootstrap,
    /// Retained native parent verification prefix.
    pub finality: &'a mut ParentFinalityStore,
    /// Challenge-bound committee observations and contiguous parent proofs.
    pub source: &'a S,
    /// Exact maximum fees and absolute scheduling deadline.
    pub options: &'a BoundedTransactionOptions,
}

/// Observations from one relay turn. Neither field claims knowledge of the latest child tip.
#[derive(Clone, Copy, Debug)]
pub struct RelayProgress {
    /// Native-verified local successor considered in this turn, before parent inclusion.
    /// `None` means this turn recovered prior work, registered genesis, or found no successor.
    pub local_successor: Option<PrivateDataspaceCursor>,
    /// Separate original transaction observation and durably parent-confirmed child cursor.
    pub parent: AttachmentProgress,
}

impl AttachmentStore {
    /// Reconcile retained work first, otherwise relay at most one contiguous child successor.
    ///
    /// This method performs no sleeps and creates no threads. The native supervisor schedules
    /// subsequent turns and supplies a new I/O deadline; exact prepared fees, signed bytes and
    /// pending certificates remain bound by the wallet journal. Only compact public exports
    /// cross the parent boundary. Parent failure leaves private execution intact.
    ///
    /// # Errors
    /// Local context/certificate failure, unsafe custody, exhausted deadline, or any exact
    /// transaction/independent finality failure from [`Self::advance_parent`].
    pub fn relay_once<S: FinalitySource + ?Sized>(
        &mut self,
        child: &impl PrivateRootSource,
        parent: RelayParent<'_, S>,
    ) -> Result<RelayProgress> {
        self.revalidate()?;
        require_time(parent.options.deadline)?;
        if self.record.pending.is_none() {
            self.require_active()?;
        }
        let next = self.next_child_anchor(child)?;
        let local_successor = next.as_ref().map(|(_, cursor)| *cursor);
        let progress = self.advance_parent(
            parent.config,
            parent.bootstrap,
            parent.finality,
            parent.source,
            parent.options,
            next.as_ref().map(|(anchor, _)| anchor),
        )?;
        Ok(RelayProgress {
            local_successor,
            parent: progress,
        })
    }

    fn next_child_anchor(
        &self,
        child: &impl PrivateRootSource,
    ) -> Result<Option<(PrivateDataspaceAnchor, PrivateDataspaceCursor)>> {
        self.revalidate()?;
        if self.record.pending.is_some() {
            return Ok(None);
        }
        let Some(state) = self.confirmed_child_state() else {
            return Ok(None);
        };
        let height = state
            .cursor()
            .height
            .checked_add(1)
            .and_then(NonZeroU64::new)
            .ok_or(AttachmentError::Invalid("private child height exhausted"))?;
        let Some(anchor) = child.anchor(height)? else {
            return Ok(None);
        };
        let mut next = state.clone();
        if anchor.height()? != height.get()
            || next.apply(&anchor)? != PrivateDataspaceAnchorOutcome::Advanced
        {
            return Err(AttachmentError::Invalid(
                "local relay certificate is not the exact contiguous successor",
            ));
        }
        Ok(Some((anchor, next.cursor())))
    }
}

fn require_time(deadline: Instant) -> Result<()> {
    if Instant::now() >= deadline {
        return Err(AttachmentError::Operation("private relay deadline elapsed"));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
