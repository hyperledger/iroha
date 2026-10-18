//! Validated runtime construction for `SoraNet` handshake configuration.

use std::{
    num::NonZeroUsize,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, RwLock},
    time::SystemTime,
};

use crate::{
    Error,
    peer::{SoranetHandshakeConfig, SoranetHandshakeParams, SoranetHandshakeSharedState},
    puzzle_work_admission::process_wide_admission,
};
use iroha_config::parameters::actual::{
    SoranetHandshake as ActualSoranetHandshake, SoranetPow as ActualSoranetPow,
};
use iroha_crypto::soranet::{
    pow::{TicketRevocationStore, TicketRevocationStoreLimits},
    puzzle,
};

fn absolute_replay_state_path(path: &Path) -> std::io::Result<PathBuf> {
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    Ok(std::env::current_dir()?.join(path))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SoranetHandshakeOwnerConfig {
    replay_state_path: PathBuf,
    revocation_limits: TicketRevocationStoreLimits,
    outbound_mint_capacity: NonZeroUsize,
    inbound_verify_capacity: NonZeroUsize,
}
impl SoranetHandshakeOwnerConfig {
    fn ensure_reload_compatible(&self, requested: &Self) -> Result<(), Error> {
        if self.replay_state_path != requested.replay_state_path {
            return Err(restart_required_error(
                "pow.revocation_store_path",
                self.replay_state_path.display(),
                requested.replay_state_path.display(),
            ));
        }
        if self.revocation_limits.max_entries != requested.revocation_limits.max_entries {
            return Err(restart_required_error(
                "pow.revocation_store_capacity",
                self.revocation_limits.max_entries,
                requested.revocation_limits.max_entries,
            ));
        }
        if self.revocation_limits.max_ttl != requested.revocation_limits.max_ttl {
            return Err(restart_required_error(
                "pow.revocation_max_ttl",
                format!("{:?}", self.revocation_limits.max_ttl),
                format!("{:?}", requested.revocation_limits.max_ttl),
            ));
        }
        if self.outbound_mint_capacity != requested.outbound_mint_capacity {
            return Err(restart_required_error(
                "pow.outbound_mint_capacity",
                self.outbound_mint_capacity,
                requested.outbound_mint_capacity,
            ));
        }
        if self.inbound_verify_capacity != requested.inbound_verify_capacity {
            return Err(restart_required_error(
                "pow.inbound_verify_capacity",
                self.inbound_verify_capacity,
                requested.inbound_verify_capacity,
            ));
        }
        Ok(())
    }
}

fn restart_required_error(
    field: &str,
    active: impl std::fmt::Display,
    requested: impl std::fmt::Display,
) -> Error {
    Error::HandshakeSoranet(format!(
        "SoraNet {field} cannot change while the network runtime is active; restart required (active {active}, requested {requested})"
    ))
}

struct ValidatedSoranetHandshake {
    policy: SoranetHandshakeParams,
    owner: SoranetHandshakeOwnerConfig,
}
impl ValidatedSoranetHandshake {
    fn into_policy(
        self,
        shared_state: SoranetHandshakeSharedState,
    ) -> Result<Arc<SoranetHandshakeConfig>, Error> {
        Ok(Arc::new(SoranetHandshakeConfig::new_with_shared_state(
            self.policy,
            shared_state,
        )?))
    }
}

/// Reloadable policy snapshots backed by one process-owned replay authority.
#[derive(Debug)]
pub struct SoranetHandshakeRuntime {
    policy: RwLock<Arc<SoranetHandshakeConfig>>,
    shared_state: SoranetHandshakeSharedState,
    owner: SoranetHandshakeOwnerConfig,
}
impl SoranetHandshakeRuntime {
    /// Snapshot the policy for one new handshake attempt.
    pub(crate) fn snapshot(&self) -> Result<Arc<SoranetHandshakeConfig>, Error> {
        self.policy
            .read()
            .map(|policy| Arc::clone(&policy))
            .map_err(|_| {
                Error::HandshakeSoranet(
                    "SoraNet handshake policy lock poisoned; refusing new handshakes".to_owned(),
                )
            })
    }

    /// Return the active replay-store path for reload compatibility tests.
    #[cfg(test)]
    pub(crate) fn replay_state_path_for_tests(&self) -> &Path {
        &self.owner.replay_state_path
    }

    /// Validate and atomically publish a policy that reuses the active owner.
    pub(crate) fn reload(
        &self,
        handshake: ActualSoranetHandshake,
    ) -> Result<Arc<SoranetHandshakeConfig>, Error> {
        let validated = validate_handshake(handshake)?;
        self.owner.ensure_reload_compatible(&validated.owner)?;
        let next = validated.into_policy(self.shared_state.clone())?;
        let mut policy = self.policy.write().map_err(|_| {
            Error::HandshakeSoranet(
                "SoraNet handshake policy lock poisoned; refusing policy reload".to_owned(),
            )
        })?;
        *policy = Arc::clone(&next);
        Ok(next)
    }
}

pub fn runtime_from_handshake(
    handshake: ActualSoranetHandshake,
) -> Result<Arc<SoranetHandshakeRuntime>, Error> {
    let validated = validate_handshake(handshake)?;
    let owner = validated.owner.clone();
    let puzzle_work_admission =
        process_wide_admission(owner.outbound_mint_capacity, owner.inbound_verify_capacity)
            .map_err(Error::HandshakeSoranet)?;
    let revocation_store = TicketRevocationStore::load(
        &owner.replay_state_path,
        owner.revocation_limits,
        SystemTime::now(),
    )
    .map_err(|err| {
        Error::HandshakeSoranet(format!(
            "failed to load soranet revocation store at {}: {err}",
            owner.replay_state_path.display()
        ))
    })?;
    let shared_state = SoranetHandshakeSharedState::new(
        Arc::new(Mutex::new(revocation_store)),
        puzzle_work_admission,
    );
    let policy = validated.into_policy(shared_state.clone())?;
    Ok(Arc::new(SoranetHandshakeRuntime {
        policy: RwLock::new(policy),
        shared_state,
        owner,
    }))
}

fn validate_handshake(
    handshake: ActualSoranetHandshake,
) -> Result<ValidatedSoranetHandshake, Error> {
    let ActualSoranetHandshake {
        descriptor_commit,
        client_capabilities,
        relay_capabilities,
        trust_gossip,
        kem_id,
        sig_id,
        resume_hash,
        pow,
    } = handshake;
    let ActualSoranetPow {
        difficulty,
        max_future_skew,
        min_ticket_ttl,
        ticket_ttl,
        outbound_mint_capacity,
        inbound_verify_capacity,
        revocation_store_capacity,
        revocation_max_ttl,
        revocation_store_path,
        puzzle,
    } = pow;
    validate_revocation_window(max_future_skew, revocation_max_ttl)?;
    validate_puzzle_work_capacities(outbound_mint_capacity, inbound_verify_capacity)?;
    let puzzle_params = puzzle::Parameters::try_new(
        puzzle.memory_kib,
        puzzle.time_cost,
        puzzle.lanes,
        difficulty,
        max_future_skew,
        min_ticket_ttl,
    )
    .map_err(|err| {
        Error::HandshakeSoranet(format!("invalid soranet puzzle configuration: {err}"))
    })?;
    if ticket_ttl <= min_ticket_ttl {
        return Err(Error::HandshakeSoranet(format!(
            "invalid soranet puzzle ticket timing: ticket_ttl {ticket_ttl:?} must exceed min_ticket_ttl {min_ticket_ttl:?}"
        )));
    }
    let revocation_limits =
        TicketRevocationStoreLimits::new(revocation_store_capacity, revocation_max_ttl).map_err(
            |err| {
                Error::HandshakeSoranet(format!("invalid soranet revocation configuration: {err}"))
            },
        )?;
    let replay_state_path = absolute_replay_state_path(Path::new(revocation_store_path.as_ref()))
        .map_err(|err| {
        Error::HandshakeSoranet(format!(
            "failed to resolve soranet revocation store path {revocation_store_path}: {err}"
        ))
    })?;
    Ok(ValidatedSoranetHandshake {
        policy: SoranetHandshakeParams {
            descriptor_commit: descriptor_commit.into_value(),
            client_capabilities: client_capabilities.into_value(),
            relay_capabilities: relay_capabilities.into_value(),
            trust_gossip,
            kem_id,
            sig_id,
            resume_hash: resume_hash.map(iroha_config::base::WithOrigin::into_value),
            puzzle_params,
            ticket_ttl,
        },
        owner: SoranetHandshakeOwnerConfig {
            replay_state_path,
            revocation_limits,
            outbound_mint_capacity,
            inbound_verify_capacity,
        },
    })
}

fn validate_revocation_window(
    max_future_skew: std::time::Duration,
    revocation_max_ttl: std::time::Duration,
) -> Result<(), Error> {
    if revocation_max_ttl < max_future_skew {
        return Err(Error::HandshakeSoranet(format!(
            "invalid soranet revocation configuration: revocation_store_ttl {revocation_max_ttl:?} must cover max_future_skew {max_future_skew:?}"
        )));
    }
    Ok(())
}

fn validate_puzzle_work_capacities(
    outbound_mint_capacity: NonZeroUsize,
    inbound_verify_capacity: NonZeroUsize,
) -> Result<(), Error> {
    for (name, capacity) in [
        ("outbound_mint_capacity", outbound_mint_capacity),
        ("inbound_verify_capacity", inbound_verify_capacity),
    ] {
        if capacity.get() > ActualSoranetPow::MAX_PUZZLE_WORK_CAPACITY_PER_DIRECTION {
            return Err(Error::HandshakeSoranet(format!(
                "invalid soranet puzzle work configuration: {name} {capacity} exceeds the per-direction maximum {}",
                ActualSoranetPow::MAX_PUZZLE_WORK_CAPACITY_PER_DIRECTION
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revocation_window_must_cover_every_accepted_ticket() {
        let max_future_skew = std::time::Duration::from_secs(300);
        let error =
            validate_revocation_window(max_future_skew, std::time::Duration::from_secs(299))
                .expect_err(
                    "a store that cannot retain every accepted ticket must fail at startup",
                );
        assert!(matches!(
            error,
            Error::HandshakeSoranet(message)
                if message.contains("revocation_store_ttl 299s must cover max_future_skew 300s")
        ));
        validate_revocation_window(max_future_skew, max_future_skew)
            .expect("an equal revocation and acceptance window is sufficient");
    }
}
