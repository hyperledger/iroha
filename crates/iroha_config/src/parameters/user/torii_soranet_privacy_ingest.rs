/// Guard rails for `SoraNet` privacy ingestion endpoints.
#[derive(Debug, ReadConfig, Clone, norito::JsonDeserialize)]
pub struct ToriiSoranetPrivacyIngest {
    /// Master enable switch for the `/v1/soranet/privacy/*` endpoints.
    #[config(default = "defaults::torii::soranet_privacy_ingest::ENABLED")]
    pub enabled: bool,
    /// Requests-per-second budget (None disables limiting).
    pub rate_per_sec: Option<u32>,
    /// Burst capacity for the ingest limiter.
    pub burst: Option<u32>,
    /// CIDR allow-list for trusted submitters; empty -> deny.
    #[config(default = "defaults::torii::soranet_privacy_ingest::allow_cidrs()")]
    pub allow_cidrs: Vec<String>,
}
impl Default for ToriiSoranetPrivacyIngest {
    fn default() -> Self {
        Self {
            enabled: defaults::torii::soranet_privacy_ingest::ENABLED,
            rate_per_sec: defaults::torii::soranet_privacy_ingest::RATE_PER_SEC,
            burst: defaults::torii::soranet_privacy_ingest::BURST,
            allow_cidrs: defaults::torii::soranet_privacy_ingest::allow_cidrs(),
        }
    }
}
impl ToriiSoranetPrivacyIngest {
    fn parse(self) -> actual::SoranetPrivacyIngest {
        actual::SoranetPrivacyIngest {
            enabled: self.enabled,
            rate_per_sec: self
                .rate_per_sec
                .or(defaults::torii::soranet_privacy_ingest::RATE_PER_SEC)
                .and_then(std::num::NonZeroU32::new),
            burst: self
                .burst
                .or(defaults::torii::soranet_privacy_ingest::BURST)
                .and_then(std::num::NonZeroU32::new),
            allow_cidrs: self.allow_cidrs,
        }
    }
}
