//! Future-beacon sortition helper for governance bodies (seeding + ranked alternates).
use iroha_crypto::blake2::{Blake2b512, Digest as _};
use iroha_data_model::{NetworkId, account::AccountId};
/// Compute deterministic sortition seed.
pub fn compute_seed(
    network_id: &NetworkId,
    epoch: u64,
    beacon: &[u8; 32],
    domain: &[u8],
) -> [u8; 64] {
    let mut hasher = Blake2b512::new();
    hasher.update(domain);
    hasher.update(network_id.as_bytes());
    hasher.update(epoch.to_be_bytes());
    hasher.update(beacon);
    let digest = hasher.finalize();
    let mut out = [0u8; 64];
    out.copy_from_slice(&digest);
    out
}
/// Build sortition input = domain || seed || `encode(account_id)`.
pub fn build_input(domain: &[u8], seed: &[u8; 64], account_id: &AccountId) -> Vec<u8> {
    use iroha_data_model::Encode;
    let account_bytes = Encode::encode(account_id);
    let mut buf = Vec::with_capacity(domain.len() + seed.len() + account_bytes.len());
    buf.extend_from_slice(domain);
    buf.extend_from_slice(seed);
    buf.extend_from_slice(&account_bytes);
    buf
}
#[cfg(test)]
mod tests {
    use super::compute_seed;
    use iroha_crypto::{Hash, HashOf};
    use iroha_data_model::{NetworkId, block::BlockHeader};
    fn network_id(seed: u8) -> NetworkId {
        NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
            Hash::prehashed([seed; Hash::LENGTH]),
        ))
    }
    #[test]
    fn seed_is_bound_to_exact_network_identity() {
        let beacon = [0xA5; 32];
        let first = compute_seed(&network_id(1), 7, &beacon, b"governance-test");
        let second = compute_seed(&network_id(2), 7, &beacon, b"governance-test");
        assert_ne!(first, second);
    }
}
