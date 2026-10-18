//! Mandatory signer-free wallet discovery and Parliament seating checks for the Taira doctor.
//!
//! The Parliament seating checks (`specs/sccp.md` §4.14.5) cover what signer-free public routes
//! can prove, and their names and details say so: `canonical_profile_seating` evaluates the
//! compiled canonical Taira `[gov]`/`[torii.faucet]` profile, and `canonical_bond_faucet_reach`
//! measures the live faucet amount against the compiled citizenship bond. Neither is evidence of
//! the live `[gov]` profile. `--parliament` adds one warning for every live seating requirement
//! those routes cannot prove.
use super::{
    DEFAULT_CHAIN_DISCRIMINANT, Duration, Result, Value, parliament_seating::SeatingProfile,
    push_check,
};
use iroha::{account_bootstrap::DiscoveryHttpError, blocking::account_bootstrap::Client};

const ACCOUNT_CAPABILITIES: &str = "account_capabilities";
const ACCOUNT_FAUCET_POLICY: &str = "account_faucet_policy";
/// Live faucet amount against the compiled canonical bond; the live bond is not read.
const CANONICAL_BOND_FAUCET_REACH: &str = "canonical_bond_faucet_reach";
/// Static §4.14.5 rules over the compiled canonical profile; the live profile is not read.
const CANONICAL_PROFILE_SEATING: &str = "canonical_profile_seating";
/// Exact detail of a passing [`CANONICAL_BOND_FAUCET_REACH`] check.
pub(super) const CANONICAL_BOND_FAUCET_REACH_DETAIL: &str = "live faucet amount against the compiled canonical citizenship_bond_amount; the live bond is not verified";
/// Exact detail of a passing [`CANONICAL_PROFILE_SEATING`] check.
pub(super) const CANONICAL_PROFILE_SEATING_DETAIL: &str = "compiled canonical configs/soranexus/taira/config.toml [gov] and [torii.faucet] profile; the live profile is not verified";

/// The wallet-discovery and Parliament seating checks every doctor report carries, in order.
#[cfg(test)]
pub(super) fn expected() -> [(&'static str, u64, Option<String>); 4] {
    [
        (ACCOUNT_CAPABILITIES, 200, None),
        (ACCOUNT_FAUCET_POLICY, 200, None),
        (
            CANONICAL_BOND_FAUCET_REACH,
            200,
            Some(CANONICAL_BOND_FAUCET_REACH_DETAIL.to_owned()),
        ),
        (
            CANONICAL_PROFILE_SEATING,
            0,
            Some(CANONICAL_PROFILE_SEATING_DETAIL.to_owned()),
        ),
    ]
}

pub(super) fn append_checks(
    public_root: &str,
    checks: &mut Vec<Value>,
    failures: &mut Vec<String>,
) -> Result<()> {
    let client = Client::new(public_root.parse()?, Duration::from_secs(30))?;
    let capabilities = match client.capabilities() {
        Ok(capabilities) if capabilities.network_prefix == DEFAULT_CHAIN_DISCRIMINANT => {
            push_check(checks, ACCOUNT_CAPABILITIES, 200, true, None);
            Some(capabilities)
        }
        Ok(_) => {
            record_failure(
                checks,
                failures,
                ACCOUNT_CAPABILITIES,
                Some(200),
                &eyre::eyre!(
                    "Taira wallet discovery requires address profile {DEFAULT_CHAIN_DISCRIMINANT}"
                ),
            );
            None
        }
        Err(error) => {
            record_failure(checks, failures, ACCOUNT_CAPABILITIES, None, &error);
            None
        }
    };
    let Some(capabilities) = capabilities else {
        let detail = "account_faucet_policy cannot be verified without the discovered exact Taira network identity".to_owned();
        push_check(
            checks,
            ACCOUNT_FAUCET_POLICY,
            0,
            false,
            Some(detail.clone()),
        );
        failures.push(detail);
        append_parliament_checks(None, checks, failures);
        return Ok(());
    };
    let xor = iroha_wallet::operations::XOR_ASSET_DEFINITION
        .parse::<iroha::data_model::asset::AssetDefinitionId>()?;
    let live_amount =
        match client.faucet_policy(capabilities.network_id, capabilities.network_prefix) {
            Ok(policy) if policy.asset_definition_id == xor => {
                push_check(checks, ACCOUNT_FAUCET_POLICY, 200, true, None);
                Some(policy.amount)
            }
            Ok(_) => {
                record_failure(
                    checks,
                    failures,
                    ACCOUNT_FAUCET_POLICY,
                    Some(200),
                    &eyre::eyre!(
                        "Taira wallet funding requires the canonical XOR asset {}",
                        iroha_wallet::operations::XOR_ASSET_DEFINITION
                    ),
                );
                None
            }
            Err(error) => {
                record_failure(checks, failures, ACCOUNT_FAUCET_POLICY, None, &error);
                None
            }
        };
    append_parliament_checks(live_amount.as_ref(), checks, failures);
    Ok(())
}

/// Push the two canonical-profile Parliament seating checks.
///
/// Both judge the compiled canonical profile, so a passing check carries the exact detail that
/// says the live values are not verified. Without a verified live faucet policy the reach check
/// is reported as not verified; its root cause is the faucet-policy failure already recorded, so
/// no second failure is added.
fn append_parliament_checks(
    live_faucet_amount: Option<&iroha_primitives::numeric::Quantity>,
    checks: &mut Vec<Value>,
    failures: &mut Vec<String>,
) {
    let profile = match SeatingProfile::canonical() {
        Ok(profile) => profile,
        Err(error) => {
            let detail = format!("canonical Taira seating profile is malformed: {error:#}");
            push_check(
                checks,
                CANONICAL_BOND_FAUCET_REACH,
                0,
                false,
                Some(detail.clone()),
            );
            push_check(
                checks,
                CANONICAL_PROFILE_SEATING,
                0,
                false,
                Some(detail.clone()),
            );
            failures.push(detail);
            return;
        }
    };
    match live_faucet_amount {
        Some(amount) => {
            let (ok, detail) = profile.bond_beyond_faucet_reach(Some(amount));
            if ok {
                push_check(
                    checks,
                    CANONICAL_BOND_FAUCET_REACH,
                    200,
                    true,
                    Some(CANONICAL_BOND_FAUCET_REACH_DETAIL.to_owned()),
                );
            } else {
                let detail = format!("{}: {detail}", CANONICAL_BOND_FAUCET_REACH);
                push_check(checks, CANONICAL_BOND_FAUCET_REACH, 200, false, Some(detail.clone()));
                failures.push(detail);
            }
        }
        None => push_check(
            checks,
            CANONICAL_BOND_FAUCET_REACH,
            0,
            false,
            Some(
                "canonical_bond_faucet_reach cannot be verified without the canonical faucet policy"
                    .to_owned(),
            ),
        ),
    }
    let failed = profile
        .requirements(None)
        .into_iter()
        .filter(|requirement| !requirement.ok)
        .map(|requirement| format!("{}: {}", requirement.name, requirement.detail))
        .collect::<Vec<_>>();
    if failed.is_empty() {
        push_check(
            checks,
            CANONICAL_PROFILE_SEATING,
            0,
            true,
            Some(CANONICAL_PROFILE_SEATING_DETAIL.to_owned()),
        );
    } else {
        let detail = format!("{}: {}", CANONICAL_PROFILE_SEATING, failed.join("; "));
        push_check(
            checks,
            CANONICAL_PROFILE_SEATING,
            0,
            false,
            Some(detail.clone()),
        );
        failures.push(detail);
    }
}

/// Live seating requirements that no signer-free public route exposes today.
///
/// `/v1/gov/capabilities` does return the live `citizenship_bond_amount`, citizenship escrow,
/// the invitation window and the target body sizes, but it is an
/// account-signed route and Torii's canonical-request check rejects an account that is not
/// registered, so an ephemeral doctor key cannot read it; the doctor deliberately loads no
/// signer. `/v1/gov/citizens` is signed too and returns only the registry total, not the citizens
/// bonded at `citizenship_bond_amount`; no route or client method reads the global-beacon session,
/// and no route exposes the adaptive faucet window.
/// TODO(ws35): serve a signer-free Parliament readiness projection from Torii (eligible citizen
/// census against every body size, the live `[gov]` seating profile and citizenship escrow, the
/// adaptive faucet policy and anchor age, and the active global-beacon session and its roster),
/// then turn these warnings and the two `canonical_*` checks into live checks.
/// TODO(ws42): report every active SCCP attempt with its next due checkpoint height, its last
/// progress height, and fail when an attempt is active and the tip is not growing.
pub(super) fn parliament_warnings() -> Result<Vec<String>> {
    let profile = SeatingProfile::canonical()?;
    let (body, size) = profile.largest_required_body();
    Ok(vec![
        format!(
            "parliament_eligible_citizens: not verified; signer-free routes expose no citizen census (the canonical profile needs at least {} citizens bonded at {} XOR; largest body {body}={size})",
            profile.minimum_citizens(),
            profile.citizenship_bond()
        ),
        "parliament_live_profile: not verified; the live [gov] seating profile, citizenship escrow and adaptive faucet policy are only on the account-signed /v1/gov/capabilities or on no route (canonical_profile_seating and canonical_bond_faucet_reach judge the compiled canonical profile)".to_owned(),
        "parliament_global_beacon_session: not verified; signer-free routes expose no active global-beacon session or its roster".to_owned(),
    ])
}

/// Append [`parliament_warnings`] to one doctor report.
pub(super) fn append_parliament_warnings(report: &mut Value) -> Result<()> {
    let warnings = report
        .as_object_mut()
        .and_then(|object| object.get_mut("warnings"))
        .and_then(Value::as_array_mut)
        .ok_or_else(|| eyre::eyre!("doctor report has no warnings array"))?;
    warnings.extend(parliament_warnings()?.into_iter().map(Value::String));
    Ok(())
}

fn record_failure(
    checks: &mut Vec<Value>,
    failures: &mut Vec<String>,
    name: &str,
    observed_status: Option<u16>,
    error: &eyre::Report,
) {
    let status = observed_status
        .or_else(|| {
            error
                .downcast_ref::<DiscoveryHttpError>()
                .map(|failure| failure.status)
        })
        .unwrap_or(0);
    let detail = format!("{name}: {error:#}");
    push_check(checks, name, status, false, Some(detail.clone()));
    failures.push(detail);
}
