//! Exact paid namespace requests built from public native policy and authoritative names.

use eyre::{Result, WrapErr as _, eyre};
use iroha::{blocking, config::Config, sns::SnsNamespacePath};
use iroha_data_model::{
    account::{AccountId, address::ChainDiscriminantGuard},
    alias_setup::{
        AccountAliasName, AccountAliasRoleV1, AccountProvisionV1, AliasAccountIntentV1,
        AliasDataSpaceIntentV1, AliasDomainIntentV1, AliasIntentV1, AliasLeaseAcquisitionV1,
        AliasQuoteGuardV1, AliasSetupPlanRequestV1, ResolvedAccountAliasV1, ResolvedDataSpaceV1,
        ResolvedDomainV1,
    },
    asset::AssetDefinitionId,
    isi::alias_setup::EnsureAlias,
    sns::{
        ACCOUNT_ALIAS_SUFFIX_ID, DATASPACE_ALIAS_SUFFIX_ID, DOMAIN_NAME_SUFFIX_ID, NameRecordV1,
        NameSelectorV1, NameStatus, SuffixPolicyV1, pricing::quote_lease_price,
    },
};
use iroha_model_base::{domain::DomainId, topology::DataSpaceId};
use iroha_primitives::numeric::Quantity;
use iroha_torii_shared::status::NexusDataspaceCatalogStatus;
use std::time::{Duration, Instant};

const MAX_QUOTE_LIFETIME_MS: u64 = 300_000;

/// One year of namespace rent, with the exact native request ready for fee quoting and planning.
#[derive(Debug, Clone)]
pub struct DomainNamespaceQuote {
    /// Exact owner-bound, one-year native namespace request.
    pub request: AliasSetupPlanRequestV1,
    /// Canonical fully qualified domain.
    pub domain: String,
    /// Exact advertised one-year rent, separate from transaction fees.
    pub rent: Quantity,
    /// Asset definition in which namespace rent is paid.
    pub payment_asset: AssetDefinitionId,
    /// Node-time deadline carried by the signed rent guard.
    pub valid_until_ms: u64,
}

/// One ordinary paid SNS request for a private dataspace and its exact owner alias.
#[derive(Debug, Clone)]
pub struct PrivateDataspaceNamespaceQuote {
    /// Ordered one-year dataspace and account-alias leases bound to the same wallet owner.
    pub request: AliasSetupPlanRequestV1,
    /// Canonical SNS name and its hash-derived dataspace id.
    pub dataspace: ResolvedDataSpaceV1,
    /// Exact owner alias resolved without a physical parent catalog.
    pub account_alias: ResolvedAccountAliasV1,
    /// Combined maximum quoted rent for both leases, separate from transaction fees.
    pub rent: Quantity,
    /// Exact rent currency selected by the native pricing policy.
    pub payment_asset: AssetDefinitionId,
    /// Node-time expiry of the signed acquisition guard.
    pub valid_until_ms: u64,
}

/// Prepare canonical private dataspace and owner-alias leases without a physical parent lane/catalog.
/// The caller has already selected and authenticated the parent network. These read-only policy
/// observations prepare an ordinary paid request; the native planner and committed execution
/// recheck exact owner, namespace, price and generation. They do not establish parent finality.
/// All discovery, status, pricing and optional existing-name reads share one absolute deadline.
///
/// # Errors
/// Rejects a noncanonical or reserved alias, changed network/profile, physical parent collision,
/// another owner or inactive lease, malformed policy, exhausted deadline or invalid rent guard.
pub fn prepare_private_dataspace_request(
    config: &Config,
    alias: &str,
    account_alias: &str,
    deadline: Instant,
) -> Result<PrivateDataspaceNamespaceQuote> {
    let selector = private_dataspace_selector(alias)?;
    let owner_alias = resolve_private_owner_alias(alias, account_alias)?;
    let _profile = ChainDiscriminantGuard::enter(config.account_chain_discriminant);
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(eyre!("private dataspace namespace deadline expired"));
    }
    let discovery = blocking::account_bootstrap::Client::new(
        config.torii_api_url.clone(),
        remaining.min(config.torii_request_timeout),
    )?;
    let capabilities = discovery.capabilities()?;
    let matches_account_profile = capabilities.network_prefix == config.account_chain_discriminant;
    if capabilities.network_id != config.network_id || !matches_account_profile {
        return Err(eyre!(
            "private dataspace endpoint changed the selected network/profile"
        ));
    }
    let client = blocking::Client::from_client(
        iroha::client::Client::builder(config.clone())
            .build()?
            .with_request_deadline(deadline),
    )?;
    let status = client.status().get()?;
    let policy = client
        .client()
        .sns()
        .get_policy(DATASPACE_ALIAS_SUFFIX_ID)?;
    let record = client
        .client()
        .sns()
        .get_name_optional(SnsNamespacePath::Dataspace, alias)?;
    let account_policy = client.client().sns().get_policy(ACCOUNT_ALIAS_SUFFIX_ID)?;
    let account_record = client.client().sns().get_name_optional(
        SnsNamespacePath::AccountAlias,
        &owner_alias.canonical_text(),
    )?;
    let quote = quote_private_dataspace(
        &policy,
        &selector,
        config.account.clone(),
        status.observed_at_ms,
        config.transaction_ttl,
        &status.dataspace_catalog,
        record.as_ref(),
        &account_policy,
        owner_alias,
        account_record.as_ref(),
    )?;
    if Instant::now() >= deadline {
        return Err(eyre!("private dataspace namespace deadline expired"));
    }
    Ok(quote)
}

/// Resolve one canonical owner label against the private dataspace's exact SNS name hash.
///
/// This constructs an explicit text/id pair for the native planner, which authenticates the
/// preceding paid dataspace intent or active SNS lease. It never invents a physical catalog entry.
///
/// # Errors
/// Rejects reserved or noncanonical dataspaces and owner labels containing another scope.
pub fn resolve_private_owner_alias(dataspace: &str, label: &str) -> Result<ResolvedAccountAliasV1> {
    let selector = private_dataspace_selector(dataspace)?;
    let canonical_name = AccountAliasName::try_new(label, None::<&str>, dataspace)?;
    if canonical_name.label.as_ref() != label || canonical_name.dataspace.as_ref() != dataspace {
        return Err(eyre!(
            "private owner alias must use exact canonical spelling"
        ));
    }
    Ok(ResolvedAccountAliasV1::new(
        canonical_name,
        DataSpaceId::from_hash(&selector.name_hash()),
    ))
}

fn private_dataspace_selector(alias: &str) -> Result<NameSelectorV1> {
    let selector = NameSelectorV1::new(DATASPACE_ALIAS_SUFFIX_ID, alias)?;
    if alias == "universal" || selector.normalized_label() != alias {
        return Err(eyre!(
            "private dataspace requires a canonical non-reserved SNS alias"
        ));
    }
    // The model's alias segment grammar also rejects hierarchy and ambiguous spelling.
    DomainId::parse_fully_qualified(&format!("app.{alias}"))?;
    Ok(selector)
}

#[allow(clippy::too_many_arguments)]
fn quote_private_dataspace(
    policy: &SuffixPolicyV1,
    selector: &NameSelectorV1,
    owner: AccountId,
    observed_at_ms: u64,
    ttl: Duration,
    catalog: &[NexusDataspaceCatalogStatus],
    record: Option<&NameRecordV1>,
    account_policy: &SuffixPolicyV1,
    account_alias: ResolvedAccountAliasV1,
    account_record: Option<&NameRecordV1>,
) -> Result<PrivateDataspaceNamespaceQuote> {
    let alias = selector.normalized_label();
    let dataspace_id = DataSpaceId::from_hash(&selector.name_hash());
    if observed_at_ms == 0
        || dataspace_id == DataSpaceId::UNIVERSAL
        || catalog
            .iter()
            .any(|entry| entry.alias == alias || entry.dataspace_id == dataspace_id.as_u64())
    {
        return Err(eyre!(
            "private dataspace requires fresh time and an independent namespace"
        ));
    }
    if let Some(record) = record
        && (active_dataspace(record, alias, observed_at_ms)? != dataspace_id
            || record.owner != owner)
    {
        return Err(eyre!(
            "existing dataspace lease differs from the selected owner or derived id"
        ));
    }
    let lifetime_ms = u64::try_from(ttl.as_millis())
        .unwrap_or(u64::MAX)
        .min(MAX_QUOTE_LIFETIME_MS);
    if lifetime_ms < 1_000 {
        return Err(eyre!(
            "namespace transaction lifetime must be at least one second"
        ));
    }
    let valid_until_ms = observed_at_ms
        .checked_add(lifetime_ms)
        .ok_or_else(|| eyre!("namespace quote deadline overflow"))?;
    let price = quote_lease_price(policy, selector, 1, None)?;
    if account_alias
        != resolve_private_owner_alias(alias, account_alias.canonical_name.label.as_ref())?
    {
        return Err(eyre!(
            "private owner alias differs from the exact dataspace scope"
        ));
    }
    let account_selector = NameSelectorV1 {
        version: NameSelectorV1::VERSION,
        suffix_id: ACCOUNT_ALIAS_SUFFIX_ID,
        label: account_alias.canonical_text(),
    };
    if let Some(record) = account_record
        && (record.selector != account_selector
            || record.name_hash != account_selector.name_hash()
            || record.owner != owner
            || !matches!(record.status, NameStatus::Active)
            || record.ownership_generation == 0
            || record.registered_at_ms > observed_at_ms
            || record.expires_at_ms <= observed_at_ms)
    {
        return Err(eyre!(
            "existing private owner alias is not the exact active owner lease"
        ));
    }
    let account_price = quote_lease_price(account_policy, &account_selector, 1, None)?;
    if account_price.payment_asset != price.payment_asset {
        return Err(eyre!(
            "private namespace leases must use one authorized rent currency"
        ));
    }
    let rent = price.amount.checked_add(&account_price.amount)?;
    let dataspace = ResolvedDataSpaceV1::new(alias.parse()?, dataspace_id);
    let request = AliasSetupPlanRequestV1::new(vec![
        EnsureAlias::new(
            AliasIntentV1::Dataspace(AliasDataSpaceIntentV1 {
                dataspace: dataspace.clone(),
                owner: owner.clone(),
            }),
            AliasLeaseAcquisitionV1::new(1, Some(price.pricing_class)),
            AliasQuoteGuardV1 {
                expected_policy_version: policy.policy_version,
                expected_payment_asset: price.payment_asset.clone(),
                max_amount: price.amount.clone(),
                valid_until_ms,
            },
        ),
        EnsureAlias::new(
            AliasIntentV1::AccountAlias(AliasAccountIntentV1 {
                alias: account_alias.clone(),
                target_account: owner,
                provision: AccountProvisionV1::Existing,
                role: AccountAliasRoleV1::Additional,
            }),
            AliasLeaseAcquisitionV1::new(1, Some(account_price.pricing_class)),
            AliasQuoteGuardV1 {
                expected_policy_version: account_policy.policy_version,
                expected_payment_asset: account_price.payment_asset,
                max_amount: account_price.amount,
                valid_until_ms,
            },
        ),
    ]);
    Ok(PrivateDataspaceNamespaceQuote {
        request,
        dataspace,
        account_alias,
        rent,
        payment_asset: price.payment_asset,
        valid_until_ms,
    })
}

/// Read current policy and resolve a full domain into one bounded, owner-bound native request.
///
/// The exact network/profile is checked at the configured HTTPS origin (or explicit loopback).
/// Quote time comes from a fresh native status snapshot. The native setup planner independently
/// revalidates the retained name/id pair, ownership, active policy and exact rent before signing.
/// This function never creates a transaction, submits, or writes a journal.
///
/// # Errors
/// Rejects malformed domains, changed network/profile, inactive or inconsistent names/policy,
/// unavailable one-year terms, stale reads, invalid payment currency and unrepresentable deadlines.
pub fn prepare_domain_request(config: &Config, domain: &str) -> Result<DomainNamespaceQuote> {
    let domain =
        DomainId::parse_fully_qualified(domain).wrap_err("namespace must be domain.dataspace")?;
    let account_profile = config.account_chain_discriminant;
    let _profile = ChainDiscriminantGuard::enter(account_profile);
    let bootstrap = blocking::account_bootstrap::Client::new(
        config.torii_api_url.clone(),
        config.torii_request_timeout,
    )?;
    let capabilities = bootstrap.capabilities()?;
    if capabilities.network_id != config.network_id
        || capabilities.network_prefix != account_profile
    {
        return Err(eyre!(
            "namespace endpoint changed the wallet's exact network or account profile"
        ));
    }
    let client = blocking::Client::new(config.clone())?;
    let status = client
        .status()
        .get()
        .wrap_err("read current namespace network time and catalog")?;
    let started = Instant::now();
    let name = domain.dataspace().as_ref();
    let catalog_id = catalog_dataspace(&status.dataspace_catalog, name)?;
    let dataspace_id = if let Some(id) = catalog_id {
        id
    } else if name == "universal" {
        DataSpaceId::UNIVERSAL
    } else {
        let record = client
            .client()
            .sns()
            .get_name(SnsNamespacePath::Dataspace, name)
            .wrap_err("resolve active namespace dataspace")?;
        active_dataspace(&record, name, status.observed_at_ms)?
    };
    if name == "universal" && dataspace_id != DataSpaceId::UNIVERSAL {
        return Err(eyre!(
            "public catalog remapped the reserved universal dataspace"
        ));
    }
    let policy = client
        .client()
        .sns()
        .get_policy(DOMAIN_NAME_SUFFIX_ID)
        .wrap_err("read current domain namespace pricing policy")?;
    let quote = quote_domain(
        &policy,
        domain,
        dataspace_id,
        config.account.clone(),
        status.observed_at_ms,
        config.transaction_ttl,
    )?;
    let lifetime = quote.valid_until_ms - status.observed_at_ms;
    if started.elapsed().as_millis() >= u128::from(lifetime / 2) {
        return Err(eyre!(
            "namespace reads consumed the rent quote lifetime; retry with a fresh policy"
        ));
    }
    Ok(quote)
}

fn catalog_dataspace(
    catalog: &[NexusDataspaceCatalogStatus],
    name: &str,
) -> Result<Option<DataSpaceId>> {
    let mut found = None;
    for entry in catalog.iter().filter(|entry| entry.alias == name) {
        let id = DataSpaceId::new(entry.dataspace_id);
        if found.is_some_and(|previous| previous != id) {
            return Err(eyre!(
                "public catalog contains conflicting ids for dataspace `{name}`"
            ));
        }
        found = Some(id);
    }
    if let Some(id) = found
        && catalog
            .iter()
            .any(|entry| entry.dataspace_id == id.as_u64() && entry.alias != name)
    {
        return Err(eyre!(
            "public catalog maps dataspace id {id} to more than one name"
        ));
    }
    Ok(found)
}

fn active_dataspace(record: &NameRecordV1, name: &str, now_ms: u64) -> Result<DataSpaceId> {
    let expected = NameSelectorV1::new(DATASPACE_ALIAS_SUFFIX_ID, name)?;
    if record.selector != expected
        || record.name_hash != expected.name_hash()
        || !matches!(record.status, NameStatus::Active)
        || record.ownership_generation == 0
        || record.registered_at_ms > now_ms
        || record.expires_at_ms <= now_ms
    {
        return Err(eyre!(
            "dataspace lookup is not the exact active SNS name `{name}`"
        ));
    }
    // This canonical SNS metadata field pins preconfigured numeric mappings. Names without it
    // use the protocol selector-derived id; the planner checks both live catalog directions.
    if let Some(value) = record.metadata.get("sns.dataspace_id") {
        return Ok(DataSpaceId::new(
            norito::json::from_str::<u64>(value.get())
                .wrap_err("dataspace record has invalid numeric mapping")?,
        ));
    }
    Ok(DataSpaceId::from_hash(&expected.name_hash()))
}

fn quote_domain(
    policy: &SuffixPolicyV1,
    domain: DomainId,
    dataspace_id: DataSpaceId,
    owner: AccountId,
    observed_at_ms: u64,
    ttl: Duration,
) -> Result<DomainNamespaceQuote> {
    if observed_at_ms == 0 {
        return Err(eyre!(
            "namespace status did not provide a current network timestamp"
        ));
    }
    let lifetime_ms = u64::try_from(ttl.as_millis())
        .unwrap_or(u64::MAX)
        .min(MAX_QUOTE_LIFETIME_MS);
    if lifetime_ms < 1_000 {
        return Err(eyre!(
            "namespace transaction lifetime must be at least one second"
        ));
    }
    let valid_until_ms = observed_at_ms
        .checked_add(lifetime_ms)
        .ok_or_else(|| eyre!("namespace quote deadline overflow"))?;
    let selector = NameSelectorV1::new(DOMAIN_NAME_SUFFIX_ID, domain.to_string())?;
    let price = quote_lease_price(policy, &selector, 1, None)?;
    let guard = AliasQuoteGuardV1 {
        expected_policy_version: policy.policy_version,
        expected_payment_asset: price.payment_asset.clone(),
        max_amount: price.amount.clone(),
        valid_until_ms,
    };
    Ok(DomainNamespaceQuote {
        domain: domain.to_string(),
        rent: price.amount,
        payment_asset: price.payment_asset,
        valid_until_ms,
        request: AliasSetupPlanRequestV1::new(vec![EnsureAlias::new(
            AliasIntentV1::Domain(AliasDomainIntentV1 {
                domain: ResolvedDomainV1::new(domain, dataspace_id),
                owner,
            }),
            AliasLeaseAcquisitionV1::new(1, Some(price.pricing_class)),
            guard,
        )]),
    })
}

#[cfg(test)]
mod tests;
