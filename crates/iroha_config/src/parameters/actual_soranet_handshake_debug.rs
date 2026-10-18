//! Debug formatting for `SoraNet` handshake configuration.

use std::fmt;

use super::{SoranetHandshake, WithOrigin};

struct HexWithOrigin<'a>(&'a WithOrigin<Vec<u8>>);

impl fmt::Debug for HexWithOrigin<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WithOrigin")
            .field("value_hex", &hex::encode(self.0.value()))
            .field("origin", self.0.origin())
            .finish()
    }
}

impl fmt::Debug for SoranetHandshake {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SoranetHandshake")
            .field("descriptor_commit", &HexWithOrigin(&self.descriptor_commit))
            .field(
                "client_capabilities",
                &HexWithOrigin(&self.client_capabilities),
            )
            .field(
                "relay_capabilities",
                &HexWithOrigin(&self.relay_capabilities),
            )
            .field("trust_gossip", &self.trust_gossip)
            .field("kem_id", &self.kem_id)
            .field("sig_id", &self.sig_id)
            .field("resume_hash", &self.resume_hash.as_ref().map(HexWithOrigin))
            .field(
                "pow",
                &format_args!(
                    "SoranetPow {{ difficulty: {}, max_future_skew_secs: {}, min_ticket_ttl_secs: {}, ticket_ttl_secs: {}, outbound_mint_capacity: {}, inbound_verify_capacity: {}, revocation_store_capacity: {}, revocation_max_ttl_secs: {}, revocation_store_path: {}, puzzle: {{ memory_kib: {}, time_cost: {}, lanes: {} }} }}",
                    self.pow.difficulty,
                    self.pow.max_future_skew.as_secs(),
                    self.pow.min_ticket_ttl.as_secs(),
                    self.pow.ticket_ttl.as_secs(),
                    self.pow.outbound_mint_capacity,
                    self.pow.inbound_verify_capacity,
                    self.pow.revocation_store_capacity,
                    self.pow.revocation_max_ttl.as_secs(),
                    self.pow.revocation_store_path,
                    self.pow.puzzle.memory_kib.get(),
                    self.pow.puzzle.time_cost.get(),
                    self.pow.puzzle.lanes.get(),
                ),
            )
            .finish()
    }
}
