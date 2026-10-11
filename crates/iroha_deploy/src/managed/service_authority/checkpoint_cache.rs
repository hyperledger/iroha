//! One exact immutable checkpoint import per live service authority; no current-state evidence.

use super::ServiceAuthority;
use crate::{
    managed::{Result, native_operation::decode_checkpoint},
    verify::finality::FinalityVerifier,
};
use iroha_data_model::NetworkId;
use std::sync::{Mutex, TryLockError};

struct Entry {
    bytes: Vec<u8>,
    network: NetworkId,
    chain: String,
    verifier: FinalityVerifier,
}

/// The retained image and decoded original are bounded by the sole native checkpoint importer.
/// No entry is retained per body, purpose, height or peer, and no failure is remembered.
#[derive(Default)]
pub(super) struct CheckpointCache {
    entry: Mutex<Option<Entry>>,
    #[cfg(test)]
    decode_attempts: std::sync::atomic::AtomicUsize,
}

impl ServiceAuthority {
    /// Import an exact independently selected checkpoint, retaining only successful immutable work.
    /// Callers still read and authenticate their original custody before supplying these bytes.
    pub(in crate::managed) fn decode_checkpoint(&self, bytes: &[u8]) -> Result<FinalityVerifier> {
        self.checkpoint_cache
            .decode(bytes, self.config.network_id, self.config.chain.as_str())
    }
}

impl CheckpointCache {
    fn decode(&self, bytes: &[u8], network: NetworkId, chain: &str) -> Result<FinalityVerifier> {
        // Memoization never adds a wait or authority failure. A held/poisoned optional cache
        // uses the unchanged importer instead. No native custody or network work holds this gate.
        let may_store = match self.entry.try_lock() {
            Ok(mut selected) => {
                if let Some(entry) = selected.as_ref()
                    && entry.network == network
                    && entry.chain == chain
                    && entry.bytes == bytes
                {
                    // Mutating the returned verifier cannot advance this exact original.
                    return Ok(entry.verifier.clone());
                }
                // Drop the preceding retained graph before constructing a different one.
                drop(selected.take());
                true
            }
            Err(TryLockError::WouldBlock) => false,
            Err(TryLockError::Poisoned(mut poisoned)) => {
                drop(poisoned.get_mut().take());
                false
            }
        };
        #[cfg(test)]
        self.decode_attempts
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let verifier = decode_checkpoint(bytes, network, chain)?;
        if may_store {
            // Successful admission already enforces the original frame/chain bounds. Optional
            // key storage is fallible and never changes a successful canonical import to failure.
            let mut image = Vec::new();
            let mut selected_chain = String::new();
            if image.try_reserve_exact(bytes.len()).is_ok()
                && selected_chain.try_reserve_exact(chain.len()).is_ok()
            {
                image.extend_from_slice(bytes);
                selected_chain.push_str(chain);
                if let Ok(mut selected) = self.entry.try_lock() {
                    // A concurrent import may have filled the slot while this one decoded.
                    // Release that original graph before cloning the replacement into custody.
                    drop(selected.take());
                    *selected = Some(Entry {
                        bytes: image,
                        network,
                        chain: selected_chain,
                        verifier: verifier.clone(),
                    });
                }
            }
        }
        Ok(verifier)
    }
}

#[cfg(test)]
#[path = "checkpoint_cache/tests.rs"]
mod tests;
