//! Grouped integration harness for network churn and functional network scenarios.
#[path = "alias_registry_bootstrap_network.rs"]
mod alias_registry_bootstrap_network;
#[path = "concurrency.rs"]
mod concurrency;
#[path = "extra_functional/mod.rs"]
mod extra_functional;
#[cfg(feature = "privacy-release-evidence")]
#[path = "kaigi_privacy_network.rs"]
mod kaigi_privacy_network;
#[path = "observer_sync.rs"]
mod observer_sync;
#[cfg(feature = "zk-stark")]
#[path = "privacy_exact12_activation_network.rs"]
mod privacy_exact12_activation_network;
#[cfg(feature = "privacy-release-evidence")]
#[path = "privacy_exact12_jindo_network.rs"]
mod privacy_exact12_jindo_network;
#[cfg(any(feature = "privacy-release-evidence", feature = "zk-stark"))]
#[path = "privacy_exact12_network_support.rs"]
mod privacy_exact12_network_support;
#[cfg(feature = "privacy-release-evidence")]
#[path = "privacy_exact12_orchard_pq_masp_network.rs"]
mod privacy_exact12_orchard_pq_masp_network;
#[cfg(feature = "privacy-release-evidence")]
#[path = "privacy_exact12_retained_network.rs"]
mod privacy_exact12_retained_network;
#[cfg(feature = "privacy-release-evidence")]
#[path = "privacy_exact12_zk_ams_vega_network.rs"]
mod privacy_exact12_zk_ams_vega_network;
#[cfg(feature = "privacy-release-evidence")]
#[path = "privacy_exact12_zk_x509_network.rs"]
mod privacy_exact12_zk_x509_network;
#[cfg(feature = "zk-stark")]
#[path = "zk_ace_localnet.rs"]
mod zk_ace_localnet;
