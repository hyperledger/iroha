//! Grouped integration harness for revision-4 consensus, DA, and localnet scenarios.
#[path = "da.rs"]
mod da;
#[path = "sumeragi_kagami_localnet.rs"]
mod sumeragi_kagami_localnet;
#[path = "sumeragi_localnet_smoke.rs"]
mod sumeragi_localnet_smoke;
#[path = "taikai_da.rs"]
mod taikai_da;
#[path = "zk_confidential_localnet.rs"]
mod zk_confidential_localnet;
#[path = "zk_stark_network.rs"]
mod zk_stark_network;
