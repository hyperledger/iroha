//! SORA Parliament seating for Taira resets and devnets (`specs/sccp.md` §4.14.5, §4.18).
//!
//! The Parliament is the only SCCP governance authority, so a fresh Taira network must seat it
//! in genesis. This module owns:
//!
//! - the refusal rules of §4.14.5, evaluated against one `[gov]`/`[torii.faucet]` profile and a
//!   genesis citizen count ([`SeatingProfile`], [`refuse_unseated`]);
//! - `iroha taira seat-parliament`, which turns a freshly generated Kagami Taira network into a
//!   seated one: it copies the canonical seating keys of `configs/soranexus/taira/config.toml`
//!   into every validator config, points `gov.citizenship_escrow_account` at a fresh escrow
//!   account whose key it discards (core moves citizenship bonds itself), generates the citizen
//!   keys as owner-only runtime secrets, and appends the escrow and each citizen's account, bond
//!   plus fee float, and `RegisterCitizen` to the unsigned genesis manifest. Re-signing the
//!   manifest stays with `kagami genesis sign`;
//! - the genesis citizen census that `iroha taira public-reset prepare-public-inputs` uses to
//!   refuse an unseated network ([`require_seated_localnet`]).
//!
//! Citizens act in Parliament attempts through `iroha gov parliament` (invitation responses,
//! endorsements, absences and the timed-OVN ballot commands) with their generated client
//! configurations; this module never signs for a citizen.

use std::{
    collections::BTreeSet,
    fs,
    io::Write as _,
    path::{Path, PathBuf},
};

use eyre::{Result, WrapErr as _, eyre};
use iroha::{
    data_model::{
        NetworkId,
        account::{Account, AccountId, address::ChainDiscriminantGuard},
        asset::{AssetDefinitionId, AssetId},
        isi::{
            Grant, GrantBox, InstructionBox, Mint, Register, governance::RegisterCitizen,
            register::RegisterBox, sccp::InitializeSccpV1,
        },
        sccp::params::SccpParametersV1,
    },
    executor_data_model::permission::{
        governance::CanManageParliament, sccp::CanProposeSccpRouteGovernance,
    },
};
use iroha_crypto::{Algorithm, ExposedPrivateKey, KeyPair};
use iroha_primitives::numeric::Quantity;
use norito::json::{self, JsonDeserialize, JsonSerialize, Map, Value};
use zeroize::Zeroizing;

use crate::{Run, RunContext};

/// Canonical Taira product profile; its `[gov]` and `[torii.faucet]` seating keys are the
/// recommended profile of `specs/sccp.md` §4.14.5.
pub(crate) const CANONICAL_TAIRA_PROFILE: &str =
    include_str!("../../../configs/soranexus/taira/config.toml");
/// Default number of genesis citizens `C`.
pub(crate) const DEFAULT_GENESIS_CITIZENS: u32 = 16;
/// Default XOR fee float minted to every genesis citizen on top of its bond.
pub(crate) const DEFAULT_FEE_FLOAT_XOR: &str = "1000";
/// Upper bound on genesis citizens rendered by one seating run.
const MAX_GENESIS_CITIZENS: u32 = 256;
/// Directory, relative to the generated network, holding the citizen runtime secrets.
pub(crate) const CITIZEN_DIRECTORY: &str = "runtime/taira-parliament-citizens";
/// Public citizen manifest written next to the citizen keys.
pub(crate) const CITIZEN_MANIFEST_FILE: &str = "citizens.json";
const CITIZEN_MANIFEST_SCHEMA_V1: &str = "iroha.taira.parliament-citizens.v1";
const SEAT_REPORT_SCHEMA_V1: &str = "iroha.taira.parliament-seating.v1";
/// The citizenship bond must be at least this many faucet claims (§4.14.5 item 1).
pub(crate) const BOND_FAUCET_CLAIMS: u32 = 40;
/// A Policy Jury of at most this many seats never needs a Confirmation Jury (§4.14.5 item 2).
const MARGIN_FREE_POLICY_JURY_SEATS: u64 = 20;
/// Citizens a Confirmation Jury needs outside the Policy Jury.
const CONFIRMATION_JURY_OUTSIDE_POLICY_JURY: u64 = 3;
/// Canonical Taira chain identifier.
const TAIRA_CHAIN_ID: &str = "fc56984b-2be7-431d-840e-21514d1883f0";
/// Canonical Taira account-address discriminant.
const TAIRA_CHAIN_DISCRIMINANT: u16 = 369;
/// Network identity file that every generated config reads and re-signing replaces.
const GENESIS_EXPECTED_HASH_FILE: &str = "genesis.expected_hash";
/// Kagami owns checked replacement of the pre-seating identity, publishing it last.
fn resign_instructions(prior: NetworkId) -> String {
    format!(
        "re-sign genesis in the network directory with `kagami genesis sign genesis.json --private-key-file genesis.private_key --config peer0.toml --out-file genesis.signed.nrt --bound-manifest-out genesis.json --nexus-context-output nexus-amx-context.v1.bin --expected-hash-out genesis.expected_hash --replace-expected-hash '{prior}'`; if interrupted, retry with this same prior identity; a stale-prior refusal requires verifying the signed block, bound manifest, Nexus AMX context, and published identity before proceeding"
    )
}

fn read_prior_network_identity(path: &Path) -> Result<NetworkId> {
    let bytes = read_bounded(path, "pre-seating genesis network identity")?;
    let text = std::str::from_utf8(&bytes).wrap_err("pre-seating network identity is not UTF-8")?;
    text.strip_suffix('\n')
        .ok_or_else(|| eyre!("pre-seating network identity must be one canonical line"))?
        .parse()
        .wrap_err("pre-seating network identity must be one canonical NetworkId")
}
/// Upper bound for one configuration or manifest read.
const MAX_INPUT_BYTES: u64 = 64 * 1024 * 1024;

/// Every Parliament body a Taira proposal kind can require before the Policy Jury, with its
/// `iroha_config` default size.
const PUBLIC_BODIES: [(&str, usize); 8] = {
    use iroha_config::parameters::defaults::governance as d;
    [
        ("rules_committee_size", d::PARLIAMENT_RULES_COMMITTEE_SIZE),
        ("agenda_council_size", d::PARLIAMENT_AGENDA_COUNCIL_SIZE),
        ("interest_panel_size", d::PARLIAMENT_INTEREST_PANEL_SIZE),
        ("review_panel_size", d::PARLIAMENT_REVIEW_PANEL_SIZE),
        (
            "coordination_council_size",
            d::PARLIAMENT_COORDINATION_COUNCIL_SIZE,
        ),
        ("mpc_committee_size", d::PARLIAMENT_MPC_COMMITTEE_SIZE),
        ("fma_committee_size", d::PARLIAMENT_FMA_COMMITTEE_SIZE),
        (
            "oversight_committee_size",
            d::PARLIAMENT_OVERSIGHT_COMMITTEE_SIZE,
        ),
    ]
};

/// `[gov]` keys copied verbatim from the canonical profile into every seated validator config.
pub(crate) const GOV_SEATING_KEYS: [&str; 18] = [
    "citizenship_asset_id",
    "citizenship_bond_amount",
    "min_enactment_delay",
    "parliament_alternate_size",
    "parliament_invitation_phase_blocks",
    "parliament_public_finding_phase_blocks",
    "rules_committee_size",
    "agenda_council_size",
    "interest_panel_size",
    "review_panel_size",
    "coordination_council_size",
    "mpc_committee_size",
    "fma_committee_size",
    "oversight_committee_size",
    "policy_jury_size",
    "confirmation_jury_size",
    "parliament_timed_ovn",
    "parliament_tle_key_lifecycle",
];

/// `[torii.faucet]` keys copied from the canonical profile when a validator enables a faucet.
pub(crate) const FAUCET_SEATING_KEYS: [&str; 4] = [
    "pow_max_anchor_age_blocks",
    "pow_adaptive_lookback_blocks",
    "pow_adaptive_claims_per_extra_bit",
    "pow_adaptive_max_extra_bits",
];

/// Repository configs that ship private keys beside their public keys. Every account controlled
/// by a public key named in them is public: it can never custody citizenship bonds.
const PUBLISHED_KEY_SOURCES: [&str; 5] = [
    include_str!("../../../defaults/client.toml"),
    include_str!("../../../defaults/kagami/iroha3-dev/peer0.toml"),
    include_str!("../../../defaults/kagami/iroha3-dev/peer1.toml"),
    include_str!("../../../defaults/kagami/iroha3-dev/peer2.toml"),
    include_str!("../../../defaults/kagami/iroha3-dev/peer3.toml"),
];
/// Public keys of the `iroha_test_samples` key pairs, whose private keys ship in the repository
/// (a unit test keeps this list equal to the samples).
const PUBLISHED_SAMPLE_PUBLIC_KEYS: [&str; 6] = [
    "ed01207233BFC89DCBD68C19FDE6CE6158225298EC1131B6A130D1AEB454C1AB5183C0",
    "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03",
    "ed012004FF5B81046DDCCF19E2E451C45DFB6F53759D4EB30FA2EFA807284D1CC33016",
    "ed0120E9F632D3034BAB6BB26D92AC8FD93EF878D9C5E69E01B61B4C47101884EE2F99",
    "ed01204164BF554923ECE1FD412D241036D863A6AE430476C898248B8237D77534CFC4",
    "ed0120EEF765223920C4D7D7ED4E204DCBDF3DAFE37F53B11F155D78206F24BC232646",
];

/// Faucet reach of one profile: what an anonymous claimant can collect and how fast.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FaucetReach {
    amount: Quantity,
    difficulty_bits: u64,
    max_anchor_age_blocks: u64,
    lookback_blocks: u64,
    claims_per_extra_bit: u64,
    max_extra_bits: u64,
}

impl FaucetReach {
    /// Scrypt evaluations of one proof at `bits` leading zero bits, saturating.
    fn evaluations_at(bits: u64) -> u128 {
        u32::try_from(bits)
            .ok()
            .and_then(|bits| 1_u128.checked_shl(bits))
            .unwrap_or(u128::MAX)
    }

    /// Scrypt evaluations `claims` faucet claims cost at the base difficulty alone.
    pub(crate) fn flat_evaluations(&self, claims: u64) -> u128 {
        Self::evaluations_at(self.difficulty_bits).saturating_mul(u128::from(claims))
    }

    /// The fewest scrypt evaluations `claims` faucet claims cost with adaptive difficulty.
    ///
    /// Torii counts the claims committed in the `pow_adaptive_lookback_blocks` blocks that end
    /// at the claimant-chosen anchor, and accepts anchors up to `pow_max_anchor_age_blocks`
    /// blocks old. The cheapest burst on an otherwise idle chain submits one claim per block and
    /// pins each claim to the oldest accepted anchor, so claim `j` counts only the
    /// `min(j - age, lookback)` earlier claims that are older than the anchor age.
    pub(crate) fn burst_evaluations(&self, claims: u64) -> u128 {
        (0..claims).fold(0_u128, |total, claim| {
            let counted = claim
                .saturating_sub(self.max_anchor_age_blocks)
                .min(self.lookback_blocks);
            let extra = counted
                .checked_div(self.claims_per_extra_bit)
                .unwrap_or(0)
                .min(self.max_extra_bits);
            total.saturating_add(Self::evaluations_at(
                self.difficulty_bits.saturating_add(extra),
            ))
        })
    }
}

/// The consensus `[gov]` and `[torii.faucet]` values that decide whether the Parliament can sit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SeatingProfile {
    public_bodies: Vec<(&'static str, u64)>,
    coordination_explicit: bool,
    policy_jury_size: u64,
    confirmation_jury_size: u64,
    max_corpus_entries: u64,
    registration_phase_blocks: u64,
    survivor_freeze_phase_blocks: u64,
    citizenship_bond: Quantity,
    citizenship_asset_id: String,
    /// Explicit `gov.citizenship_escrow_account` literal; `None` falls back to the published
    /// default governance account.
    citizenship_escrow_account: Option<String>,
    faucet: Option<FaucetReach>,
}

/// One §4.14.5 requirement with its verdict.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SeatingRequirement {
    /// Stable requirement name.
    pub(crate) name: &'static str,
    /// Whether the requirement holds.
    pub(crate) ok: bool,
    /// Bounded single-line explanation.
    pub(crate) detail: String,
}

fn table_u64(table: Option<&toml::Table>, key: &str, default: u64) -> Result<u64> {
    match table.and_then(|table| table.get(key)) {
        None => Ok(default),
        Some(toml::Value::Integer(value)) => {
            u64::try_from(*value).map_err(|_| eyre!("`{key}` must be a non-negative integer"))
        }
        Some(_) => Err(eyre!("`{key}` must be an integer")),
    }
}

fn table_quantity(table: Option<&toml::Table>, key: &str, default: Quantity) -> Result<Quantity> {
    match table.and_then(|table| table.get(key)) {
        None => Ok(default),
        Some(toml::Value::String(value)) => value
            .parse::<Quantity>()
            .map_err(|_| eyre!("`{key}` must be a canonical non-negative decimal")),
        Some(toml::Value::Integer(value)) => u64::try_from(*value)
            .map(Quantity::from)
            .map_err(|_| eyre!("`{key}` must be non-negative")),
        Some(_) => Err(eyre!("`{key}` must be a decimal string")),
    }
}

fn sub_table<'a>(table: Option<&'a toml::Table>, key: &str) -> Result<Option<&'a toml::Table>> {
    match table.and_then(|table| table.get(key)) {
        None => Ok(None),
        Some(toml::Value::Table(inner)) => Ok(Some(inner)),
        Some(_) => Err(eyre!("`{key}` must be a table")),
    }
}

impl SeatingProfile {
    /// Read the seating profile from the `[gov]` and `[torii.faucet]` tables of one validator
    /// configuration; absent keys take their `iroha_config` defaults.
    ///
    /// # Errors
    /// Returns an error for a malformed seating value.
    pub(crate) fn from_config(config: &toml::Table) -> Result<Self> {
        use iroha_config::parameters::defaults::{governance as d, torii::faucet as f};
        let gov = sub_table(Some(config), "gov")?;
        let timed_ovn = sub_table(gov, "parliament_timed_ovn")?;
        let torii = sub_table(Some(config), "torii")?;
        let faucet_table = sub_table(torii, "faucet")?;
        let mut public_bodies = Vec::with_capacity(PUBLIC_BODIES.len());
        for (key, default) in PUBLIC_BODIES {
            public_bodies.push((key, table_u64(gov, key, default as u64)?));
        }
        let faucet_enabled = match faucet_table.and_then(|table| table.get("enabled")) {
            None => faucet_table.is_some(),
            Some(toml::Value::Boolean(enabled)) => *enabled,
            Some(_) => return Err(eyre!("`torii.faucet.enabled` must be a boolean")),
        };
        let faucet = if faucet_enabled {
            let amount = table_quantity(faucet_table, "amount", Quantity::from(0_u32))?;
            if amount.is_zero() {
                return Err(eyre!("an enabled faucet must pay a positive `amount`"));
            }
            Some(FaucetReach {
                amount,
                difficulty_bits: table_u64(
                    faucet_table,
                    "pow_difficulty_bits",
                    u64::from(f::POW_DIFFICULTY_BITS),
                )?,
                max_anchor_age_blocks: table_u64(
                    faucet_table,
                    "pow_max_anchor_age_blocks",
                    f::POW_MAX_ANCHOR_AGE_BLOCKS.get(),
                )?,
                lookback_blocks: table_u64(
                    faucet_table,
                    "pow_adaptive_lookback_blocks",
                    f::POW_ADAPTIVE_LOOKBACK_BLOCKS,
                )?,
                claims_per_extra_bit: table_u64(
                    faucet_table,
                    "pow_adaptive_claims_per_extra_bit",
                    f::POW_ADAPTIVE_CLAIMS_PER_EXTRA_BIT,
                )?,
                max_extra_bits: table_u64(
                    faucet_table,
                    "pow_adaptive_max_extra_bits",
                    u64::from(f::POW_ADAPTIVE_MAX_EXTRA_BITS),
                )?,
            })
        } else {
            None
        };
        let citizenship_asset_id = match gov.and_then(|gov| gov.get("citizenship_asset_id")) {
            None => d::citizenship_asset_id(),
            Some(toml::Value::String(value)) => value.clone(),
            Some(_) => return Err(eyre!("`citizenship_asset_id` must be a string")),
        };
        let citizenship_escrow_account =
            match gov.and_then(|gov| gov.get("citizenship_escrow_account")) {
                None => None,
                Some(toml::Value::String(value)) => Some(value.clone()),
                Some(_) => return Err(eyre!("`citizenship_escrow_account` must be a string")),
            };
        Ok(Self {
            public_bodies,
            coordination_explicit: gov
                .is_some_and(|gov| gov.contains_key("coordination_council_size")),
            policy_jury_size: table_u64(
                gov,
                "policy_jury_size",
                d::PARLIAMENT_POLICY_JURY_SIZE as u64,
            )?,
            confirmation_jury_size: table_u64(
                gov,
                "confirmation_jury_size",
                d::PARLIAMENT_CONFIRMATION_JURY_SIZE as u64,
            )?,
            max_corpus_entries: table_u64(
                timed_ovn,
                "max_corpus_entries",
                u64::from(d::parliament_timed_ovn::MAX_CORPUS_ENTRIES),
            )?,
            registration_phase_blocks: table_u64(
                timed_ovn,
                "registration_phase_blocks",
                d::parliament_timed_ovn::REGISTRATION_PHASE_BLOCKS,
            )?,
            survivor_freeze_phase_blocks: table_u64(
                timed_ovn,
                "survivor_freeze_phase_blocks",
                d::parliament_timed_ovn::SURVIVOR_FREEZE_PHASE_BLOCKS,
            )?,
            citizenship_bond: table_quantity(
                gov,
                "citizenship_bond_amount",
                d::citizenship_bond_amount(),
            )?,
            citizenship_asset_id,
            citizenship_escrow_account,
            faucet,
        })
    }

    /// Read the seating profile of one TOML document.
    ///
    /// # Errors
    /// Returns an error for invalid TOML or a malformed seating value.
    pub(crate) fn from_toml(text: &str) -> Result<Self> {
        let config: toml::Table = toml::from_str(text).wrap_err("configuration is not TOML")?;
        Self::from_config(&config)
    }

    /// The compiled canonical Taira profile.
    ///
    /// # Errors
    /// Returns an error only if the checked-in profile is malformed.
    pub(crate) fn canonical() -> Result<Self> {
        Self::from_toml(CANONICAL_TAIRA_PROFILE)
    }

    /// Exact configured citizenship bond.
    pub(crate) fn citizenship_bond(&self) -> &Quantity {
        &self.citizenship_bond
    }

    /// The largest body a proposal can require: every public body and the Policy Jury.
    pub(crate) fn largest_required_body(&self) -> (&'static str, u64) {
        self.public_bodies
            .iter()
            .copied()
            .chain(std::iter::once(("policy_jury_size", self.policy_jury_size)))
            .fold(("policy_jury_size", 0), |largest, body| {
                if body.1 > largest.1 { body } else { largest }
            })
    }

    /// The smallest genesis citizen count this profile can seat.
    pub(crate) fn minimum_citizens(&self) -> u64 {
        let largest = self.largest_required_body().1;
        if self.policy_jury_size > MARGIN_FREE_POLICY_JURY_SEATS {
            largest.max(
                self.policy_jury_size
                    .saturating_add(CONFIRMATION_JURY_OUTSIDE_POLICY_JURY),
            )
        } else {
            largest
        }
    }

    /// Evaluate every §4.14.5 requirement. `citizens` is the eligible genesis citizen count;
    /// without it the citizen-count requirement is not reported.
    pub(crate) fn requirements(&self, citizens: Option<u64>) -> Vec<SeatingRequirement> {
        let minimum_hidden = u64::from(
            iroha::data_model::governance::types::MIN_PARLIAMENT_HIDDEN_BALLOT_ANONYMITY_V1,
        );
        let mut requirements = Vec::with_capacity(8);
        if let Some(citizens) = citizens {
            let (body, size) = self.largest_required_body();
            requirements.push(SeatingRequirement {
                name: "citizens_cover_bodies",
                ok: citizens >= size,
                detail: format!("{citizens} eligible citizens; largest body {body}={size}"),
            });
        }
        let margin_free = self.policy_jury_size <= MARGIN_FREE_POLICY_JURY_SEATS;
        let confirmation_ok = margin_free
            || citizens.is_some_and(|citizens| {
                self.policy_jury_size
                    .saturating_add(CONFIRMATION_JURY_OUTSIDE_POLICY_JURY)
                    <= citizens
            });
        requirements.push(SeatingRequirement {
            name: "policy_jury_confirmation_margin",
            ok: confirmation_ok,
            detail: if margin_free {
                format!(
                    "policy_jury_size={} <= {MARGIN_FREE_POLICY_JURY_SEATS} never needs a Confirmation Jury",
                    self.policy_jury_size
                )
            } else {
                format!(
                    "policy_jury_size={} > {MARGIN_FREE_POLICY_JURY_SEATS} requires policy_jury_size <= C - {CONFIRMATION_JURY_OUTSIDE_POLICY_JURY}",
                    self.policy_jury_size
                )
            },
        });
        requirements.push(SeatingRequirement {
            name: "hidden_ballot_anonymity",
            ok: self.policy_jury_size >= minimum_hidden
                && self.confirmation_jury_size >= minimum_hidden,
            detail: format!(
                "policy_jury_size={} confirmation_jury_size={} (floor {minimum_hidden})",
                self.policy_jury_size, self.confirmation_jury_size
            ),
        });
        let largest_jury = self.policy_jury_size.max(self.confirmation_jury_size);
        requirements.push(SeatingRequirement {
            name: "corpus_covers_juries",
            ok: self.max_corpus_entries >= largest_jury,
            detail: format!(
                "max_corpus_entries={} largest jury={largest_jury}",
                self.max_corpus_entries
            ),
        });
        requirements.push(SeatingRequirement {
            name: "windows_cover_corpus",
            ok: self.registration_phase_blocks > self.max_corpus_entries
                && self.survivor_freeze_phase_blocks >= self.max_corpus_entries,
            detail: format!(
                "registration_phase_blocks={} survivor_freeze_phase_blocks={} max_corpus_entries={}",
                self.registration_phase_blocks,
                self.survivor_freeze_phase_blocks,
                self.max_corpus_entries
            ),
        });
        requirements.push(SeatingRequirement {
            name: "coordination_council_explicit",
            ok: self.coordination_explicit,
            detail: "coordination_council_size must be set explicitly (its default is 150)"
                .to_owned(),
        });
        let (bond_ok, bond_detail) = self.bond_beyond_faucet_reach(None);
        requirements.push(SeatingRequirement {
            name: "bond_beyond_faucet_reach",
            ok: bond_ok,
            detail: bond_detail,
        });
        requirements.push(match &self.faucet {
            None => SeatingRequirement {
                name: "adaptive_faucet_difficulty",
                ok: true,
                detail: "faucet disabled".to_owned(),
            },
            Some(faucet) => SeatingRequirement {
                name: "adaptive_faucet_difficulty",
                ok: faucet.lookback_blocks > 0
                    && faucet.claims_per_extra_bit > 0
                    && faucet.max_extra_bits > 0,
                detail: format!(
                    "pow_adaptive_lookback_blocks={} pow_adaptive_claims_per_extra_bit={} pow_adaptive_max_extra_bits={}",
                    faucet.lookback_blocks, faucet.claims_per_extra_bit, faucet.max_extra_bits
                ),
            },
        });
        requirements.push(match &self.faucet {
            None => SeatingRequirement {
                name: "faucet_anchor_age_below_lookback",
                ok: true,
                detail: "faucet disabled".to_owned(),
            },
            Some(faucet) => {
                let claims = u64::from(BOND_FAUCET_CLAIMS);
                let burst = faucet.burst_evaluations(claims);
                let flat = faucet.flat_evaluations(claims);
                let adaptive = faucet.lookback_blocks > 0
                    && faucet.claims_per_extra_bit > 0
                    && faucet.max_extra_bits > 0;
                SeatingRequirement {
                    name: "faucet_anchor_age_below_lookback",
                    // With adaptive difficulty off only `adaptive_faucet_difficulty` fails.
                    ok: !adaptive
                        || (faucet.max_anchor_age_blocks < faucet.lookback_blocks && burst > flat),
                    detail: format!(
                        "pow_max_anchor_age_blocks={} pow_adaptive_lookback_blocks={}; the cheapest {claims}-claim burst costs {burst} scrypt evaluations ({flat} without adaptive difficulty)",
                        faucet.max_anchor_age_blocks, faucet.lookback_blocks
                    ),
                }
            }
        });
        requirements
    }

    /// Whether `gov.citizenship_escrow_account` names an account nobody can sign for.
    ///
    /// The escrow holds every citizen's bond. An escrow controlled by a key published in this
    /// repository (the default governance account among them) lets anyone drain the bonds and
    /// register fully bonded Sybil citizens for free, so a seated network uses a fresh escrow
    /// whose key was discarded; core moves citizenship bonds without the escrow's signature.
    pub(crate) fn citizenship_escrow_requirement(&self) -> SeatingRequirement {
        const NAME: &str = "citizenship_escrow_is_custodial";
        let Some(literal) = &self.citizenship_escrow_account else {
            return SeatingRequirement {
                name: NAME,
                ok: false,
                detail: "gov.citizenship_escrow_account is unset and its default names a key published in this repository".to_owned(),
            };
        };
        let parsed = {
            let _chain = ChainDiscriminantGuard::enter(TAIRA_CHAIN_DISCRIMINANT);
            parse_account(literal, "gov.citizenship_escrow_account")
        };
        match parsed {
            Err(error) => SeatingRequirement {
                name: NAME,
                ok: false,
                detail: format!("{error}"),
            },
            Ok(escrow) if published_accounts().contains(&escrow) => SeatingRequirement {
                name: NAME,
                ok: false,
                detail: format!(
                    "citizenship escrow {literal} is controlled by a key published in this repository, so anyone can drain the bonds"
                ),
            },
            Ok(_) => SeatingRequirement {
                name: NAME,
                ok: true,
                detail: format!(
                    "citizenship escrow {literal} is not controlled by a published key"
                ),
            },
        }
    }

    /// The parsed citizenship escrow account, when it is set and canonical.
    fn citizenship_escrow(&self) -> Option<AccountId> {
        let _chain = ChainDiscriminantGuard::enter(TAIRA_CHAIN_DISCRIMINANT);
        parse_account(self.citizenship_escrow_account.as_deref()?, "escrow").ok()
    }

    /// Whether the bond is at least [`BOND_FAUCET_CLAIMS`] claims of `live_amount`, or of the
    /// profile's own faucet amount when no live amount is given.
    pub(crate) fn bond_beyond_faucet_reach(
        &self,
        live_amount: Option<&Quantity>,
    ) -> (bool, String) {
        let Some(amount) = live_amount.or(self.faucet.as_ref().map(|faucet| &faucet.amount)) else {
            return (true, "faucet disabled".to_owned());
        };
        let reach = amount.try_mul_decimal(Quantity::from(BOND_FAUCET_CLAIMS).as_numeric());
        match reach {
            Ok(reach) => (
                self.citizenship_bond >= reach,
                format!(
                    "citizenship_bond_amount={} against {BOND_FAUCET_CLAIMS} faucet claims of {amount} = {reach}",
                    self.citizenship_bond
                ),
            ),
            Err(_) => (
                false,
                format!("faucet amount {amount} overflows the reach check"),
            ),
        }
    }
}

fn collect_published_keys(
    value: &toml::Value,
    name: Option<&str>,
    accounts: &mut BTreeSet<AccountId>,
) {
    match value {
        toml::Value::String(text) if name.is_some_and(|name| name.ends_with("public_key")) => {
            if let Ok(key) = text.parse::<iroha_crypto::PublicKey>() {
                accounts.insert(AccountId::new(key));
            }
        }
        toml::Value::Table(table) => {
            for (key, value) in table {
                collect_published_keys(value, Some(key), accounts);
            }
        }
        toml::Value::Array(items) => {
            for item in items {
                collect_published_keys(item, name, accounts);
            }
        }
        _ => {}
    }
}

/// Every account controlled by a key whose private half ships in this repository: the default
/// governance accounts, the `iroha_test_samples` accounts and every public key named in
/// [`PUBLISHED_KEY_SOURCES`].
pub(crate) fn published_accounts() -> BTreeSet<AccountId> {
    use iroha_config::parameters::defaults::governance as d;
    let mut accounts = BTreeSet::from([
        d::citizenship_escrow_account_id(),
        d::bond_escrow_account_id(),
        d::slash_receiver_account_id(),
    ]);
    for key in PUBLISHED_SAMPLE_PUBLIC_KEYS {
        if let Ok(key) = key.parse::<iroha_crypto::PublicKey>() {
            accounts.insert(AccountId::new(key));
        }
    }
    for source in PUBLISHED_KEY_SOURCES {
        if let Ok(table) = toml::from_str::<toml::Table>(source) {
            collect_published_keys(&toml::Value::Table(table), None, &mut accounts);
        }
    }
    accounts
}

/// Point `gov.citizenship_escrow_account` of one validator configuration at `escrow`.
///
/// # Errors
/// Returns an error when the configuration has a non-table `[gov]`.
pub(crate) fn set_citizenship_escrow(config: &mut toml::Table, escrow: &AccountId) -> Result<()> {
    let literal = {
        let _chain = ChainDiscriminantGuard::enter(TAIRA_CHAIN_DISCRIMINANT);
        escrow.to_string()
    };
    config
        .entry("gov")
        .or_insert_with(|| toml::Value::Table(toml::Table::new()))
        .as_table_mut()
        .ok_or_else(|| eyre!("validator [gov] must be a table"))?
        .insert(
            "citizenship_escrow_account".to_owned(),
            toml::Value::String(literal),
        );
    Ok(())
}

/// Refuse a network whose profile and citizen count cannot seat the Parliament.
///
/// # Errors
/// Lists every failed §4.14.5 requirement, including a citizenship escrow controlled by a
/// published key.
pub(crate) fn refuse_unseated(profile: &SeatingProfile, citizens: u64) -> Result<()> {
    let failed = profile
        .requirements(Some(citizens))
        .into_iter()
        .chain(std::iter::once(profile.citizenship_escrow_requirement()))
        .filter(|requirement| !requirement.ok)
        .map(|requirement| format!("{}: {}", requirement.name, requirement.detail))
        .collect::<Vec<_>>();
    if failed.is_empty() {
        Ok(())
    } else {
        Err(eyre!(
            "refusing a Taira network that cannot seat the SORA Parliament (specs/sccp.md §4.14.5): {}",
            failed.join("; ")
        ))
    }
}

/// Parliament-relevant content of one genesis manifest.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct GenesisCitizenCensus {
    /// Distinct citizens registered with at least the configured bond.
    pub(crate) eligible: BTreeSet<AccountId>,
    /// Citizen registrations below the configured bond.
    pub(crate) underbonded: usize,
    /// Genesis grants of `CanManageParliament`.
    pub(crate) parliament_manager_grants: usize,
    /// Accounts registered by the manifest.
    pub(crate) registered_accounts: BTreeSet<AccountId>,
    /// Asset definitions registered by the manifest.
    pub(crate) registered_asset_definitions: BTreeSet<AssetDefinitionId>,
}

fn registered_account(instruction: &InstructionBox) -> Option<AccountId> {
    match instruction.as_any().downcast_ref::<RegisterBox>() {
        Some(RegisterBox::Account(register)) => Some(register.object.id.clone()),
        _ => instruction
            .as_any()
            .downcast_ref::<Register<Account>>()
            .map(|register| register.object.id.clone()),
    }
}

fn registered_asset_definition(instruction: &InstructionBox) -> Option<AssetDefinitionId> {
    match instruction.as_any().downcast_ref::<RegisterBox>() {
        Some(RegisterBox::AssetDefinition(register)) => Some(register.object.id.clone()),
        _ => instruction
            .as_any()
            .downcast_ref::<Register<iroha::data_model::asset::AssetDefinition>>()
            .map(|register| register.object.id.clone()),
    }
}

fn grants_parliament_manager(instruction: &InstructionBox) -> bool {
    let name = iroha::data_model::permission::Permission::from(CanManageParliament);
    let matches = |grant: &Grant<iroha::data_model::permission::Permission, Account>| {
        grant.object.name() == name.name()
    };
    match instruction.as_any().downcast_ref::<GrantBox>() {
        Some(GrantBox::Permission(grant)) => matches(grant),
        Some(GrantBox::RolePermission(grant)) => grant.object.name() == name.name(),
        _ => instruction
            .as_any()
            .downcast_ref::<Grant<iroha::data_model::permission::Permission, Account>>()
            .is_some_and(matches),
    }
}

/// Take the Parliament census of one genesis instruction stream against `bond`.
pub(crate) fn genesis_citizen_census<'a>(
    instructions: impl IntoIterator<Item = &'a InstructionBox> + 'a,
    bond: &Quantity,
) -> GenesisCitizenCensus {
    let mut census = GenesisCitizenCensus::default();
    for instruction in instructions {
        if let Some(citizen) = instruction.as_any().downcast_ref::<RegisterCitizen>() {
            if citizen.amount >= *bond {
                census.eligible.insert(citizen.owner.clone());
            } else {
                census.underbonded += 1;
            }
        }
        if grants_parliament_manager(instruction) {
            census.parliament_manager_grants += 1;
        }
        if let Some(account) = registered_account(instruction) {
            census.registered_accounts.insert(account);
        }
        if let Some(definition) = registered_asset_definition(instruction) {
            census.registered_asset_definitions.insert(definition);
        }
    }
    census
}

/// Refuse a genesis that does not seat the Parliament under `profile`.
///
/// # Errors
/// Returns every failed requirement, including a `CanManageParliament` grant.
pub(crate) fn require_seated_genesis<'a>(
    profile: &SeatingProfile,
    instructions: impl IntoIterator<Item = &'a InstructionBox> + 'a,
) -> Result<GenesisCitizenCensus> {
    let census = genesis_citizen_census(instructions, &profile.citizenship_bond);
    if census.parliament_manager_grants != 0 {
        return Err(eyre!(
            "refusing a Taira genesis that grants CanManageParliament: SCCP attempts need no clerk (specs/sccp.md §4.14.5 item 3)"
        ));
    }
    let citizens = u64::try_from(census.eligible.len()).unwrap_or(u64::MAX);
    refuse_unseated(profile, citizens)?;
    if let Some(escrow) = profile.citizenship_escrow()
        && !census.registered_accounts.contains(&escrow)
    {
        return Err(eyre!(
            "refusing a Taira genesis that does not register the citizenship escrow {escrow}"
        ));
    }
    Ok(census)
}

fn read_bounded(path: &Path, label: &str) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)
        .wrap_err_with(|| format!("cannot inspect {label} `{}`", path.display()))?;
    if !metadata.is_file() || metadata.len() > MAX_INPUT_BYTES {
        return Err(eyre!(
            "{label} `{}` must be a bounded regular file",
            path.display()
        ));
    }
    fs::read(path).wrap_err_with(|| format!("cannot read {label} `{}`", path.display()))
}

/// Validator configurations `peer<N>.toml` of one generated network, in index order.
fn peer_configs(localnet_dir: &Path) -> Result<Vec<PathBuf>> {
    let mut peers = Vec::new();
    for index in 0_u32.. {
        let path = localnet_dir.join(format!("peer{index}.toml"));
        if !path.try_exists()? {
            break;
        }
        peers.push(path);
    }
    if peers.is_empty() {
        return Err(eyre!(
            "generated network `{}` contains no peer<N>.toml validator configs",
            localnet_dir.display()
        ));
    }
    Ok(peers)
}

/// One shared seating profile of every validator config in a generated network.
///
/// # Errors
/// Returns an error when a config is unreadable or two validators disagree.
pub(crate) fn localnet_seating_profile(localnet_dir: &Path) -> Result<SeatingProfile> {
    let mut shared: Option<SeatingProfile> = None;
    for path in peer_configs(localnet_dir)? {
        let text = String::from_utf8(read_bounded(&path, "validator config")?)
            .map_err(|_| eyre!("validator config `{}` is not UTF-8", path.display()))?;
        let profile = SeatingProfile::from_toml(&text)
            .wrap_err_with(|| format!("invalid seating profile in `{}`", path.display()))?;
        match &shared {
            None => shared = Some(profile),
            Some(expected) if *expected == profile => {}
            Some(_) => {
                return Err(eyre!(
                    "validator `{}` does not share the network's consensus [gov] seating profile",
                    path.display()
                ));
            }
        }
    }
    shared.ok_or_else(|| eyre!("generated network has no validator config"))
}

/// Refuse a generated network whose validators and genesis do not seat the Parliament.
///
/// # Errors
/// Returns an error when a validator config is unreadable or any requirement fails.
pub(crate) fn require_seated_localnet(
    localnet_dir: &Path,
    manifest: &iroha_genesis::RawGenesisTransaction,
) -> Result<GenesisCitizenCensus> {
    let profile = localnet_seating_profile(localnet_dir)?;
    require_seated_genesis(&profile, manifest.instructions())
}

/// Copy the canonical seating keys into one validator configuration.
///
/// # Errors
/// Returns an error when the configuration has a non-table `[gov]` or `[torii.faucet]`.
pub(crate) fn apply_seating_keys(config: &mut toml::Table, canonical: &toml::Table) -> Result<()> {
    let canonical_gov = sub_table(Some(canonical), "gov")?
        .ok_or_else(|| eyre!("canonical profile has no [gov] table"))?;
    let canonical_faucet = sub_table(sub_table(Some(canonical), "torii")?, "faucet")?
        .ok_or_else(|| eyre!("canonical profile has no [torii.faucet] table"))?;
    let gov = config
        .entry("gov")
        .or_insert_with(|| toml::Value::Table(toml::Table::new()))
        .as_table_mut()
        .ok_or_else(|| eyre!("validator [gov] must be a table"))?;
    for key in GOV_SEATING_KEYS {
        let value = canonical_gov
            .get(key)
            .ok_or_else(|| eyre!("canonical profile [gov] lacks `{key}`"))?;
        gov.insert(key.to_owned(), value.clone());
    }
    let faucet = match config.get_mut("torii") {
        Some(toml::Value::Table(torii)) => match torii.get_mut("faucet") {
            Some(toml::Value::Table(faucet)) => Some(faucet),
            Some(_) => return Err(eyre!("validator [torii.faucet] must be a table")),
            None => None,
        },
        Some(_) => return Err(eyre!("validator [torii] must be a table")),
        None => None,
    };
    if let Some(faucet) = faucet {
        for key in FAUCET_SEATING_KEYS {
            let value = canonical_faucet
                .get(key)
                .ok_or_else(|| eyre!("canonical profile [torii.faucet] lacks `{key}`"))?;
            faucet.insert(key.to_owned(), value.clone());
        }
    }
    Ok(())
}

/// A deterministic citizenship escrow outside every published key, for fixtures of seated
/// networks (a real seating run generates a fresh one and discards its key).
#[cfg(test)]
pub(crate) fn fixture_citizenship_escrow() -> AccountId {
    AccountId::new(
        KeyPair::try_from_seed(vec![0xE5; 32], Algorithm::Ed25519)
            .expect("fixture escrow key")
            .public_key()
            .clone(),
    )
}

/// A minimal validator configuration holding exactly the canonical seating keys, the
/// [`fixture_citizenship_escrow`] and an enabled faucet with the canonical amount, for fixtures
/// of seated networks.
#[cfg(test)]
pub(crate) fn canonical_seating_config_toml() -> String {
    let canonical: toml::Table =
        toml::from_str(CANONICAL_TAIRA_PROFILE).expect("canonical Taira profile");
    let canonical_faucet = canonical["torii"]["faucet"]
        .as_table()
        .expect("canonical faucet table");
    let mut faucet = toml::Table::new();
    faucet.insert("enabled".into(), toml::Value::Boolean(true));
    faucet.insert("amount".into(), canonical_faucet["amount"].clone());
    let mut torii = toml::Table::new();
    torii.insert("faucet".into(), toml::Value::Table(faucet));
    let mut config = toml::Table::new();
    config.insert("torii".into(), toml::Value::Table(torii));
    apply_seating_keys(&mut config, &canonical).expect("canonical seating keys");
    set_citizenship_escrow(&mut config, &fixture_citizenship_escrow()).expect("fixture escrow");
    toml::to_string(&config).expect("render seating fixture")
}

/// The genesis instructions that seat `citizens`.
///
/// Each citizen gets `Register<Account>`, a mint of `bond + fee_float` of the citizenship asset
/// and `RegisterCitizen { owner, amount: bond }`. The citizenship escrow is registered first when
/// genesis does not register it, and `sccp_proposer`, when given, receives the genesis-only
/// `CanProposeSccpRouteGovernance` grant. Nobody receives `CanManageParliament`.
///
/// # Errors
/// Returns an error when the fee float overflows the bond.
pub(crate) fn citizen_genesis_instructions(
    citizens: &[AccountId],
    asset: &AssetDefinitionId,
    bond: &Quantity,
    fee_float: &Quantity,
    escrow: Option<&AccountId>,
    sccp_proposer: Option<&AccountId>,
) -> Result<Vec<InstructionBox>> {
    let funded = bond
        .try_add(fee_float)
        .map_err(|_| eyre!("citizenship bond plus fee float overflows"))?;
    let mut instructions: Vec<InstructionBox> = Vec::with_capacity(citizens.len() * 3 + 2);
    if let Some(escrow) = escrow {
        instructions.push(Register::account(Account::new(escrow.clone())).into());
    }
    for citizen in citizens {
        instructions.push(Register::account(Account::new(citizen.clone())).into());
        instructions.push(
            Mint::asset_quantity(funded.clone(), AssetId::new(asset.clone(), citizen.clone()))
                .into(),
        );
        instructions.push(
            RegisterCitizen {
                owner: citizen.clone(),
                amount: bond.clone(),
            }
            .into(),
        );
    }
    if let Some(proposer) = sccp_proposer {
        instructions.push(
            Grant::account_permission(CanProposeSccpRouteGovernance, proposer.clone()).into(),
        );
    }
    Ok(instructions)
}

/// The genesis instruction that creates SCCP with the Taira defaults under `reset_nonce`
/// (`specs/sccp.md` §4.1, §4.18): its parameters, reset nonce, three route escrows and an empty
/// registry. Genesis carries no bridge keys; validators register their own after start.
///
/// # Errors
/// Returns an error for a zero reset nonce.
pub(crate) fn sccp_genesis_instruction(reset_nonce: [u8; 32]) -> Result<InstructionBox> {
    if reset_nonce == [0; 32] {
        return Err(eyre!("the SCCP reset nonce must be nonzero"));
    }
    Ok(InitializeSccpV1 {
        parameters: SccpParametersV1::taira_default(),
        reset_nonce,
    }
    .into())
}

/// Draw a fresh SCCP reset nonce from the OS CSPRNG, so every reset has a new identity (§4.18).
///
/// # Errors
/// Returns an error when the OS CSPRNG fails.
pub(crate) fn fresh_sccp_reset_nonce() -> Result<[u8; 32]> {
    use rand::rand_core::TryRngCore as _;
    let mut nonce = [0_u8; 32];
    rand::rngs::OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|error| eyre!("OS CSPRNG failed: {error}"))?;
    Ok(nonce)
}

/// Append one instruction-only transaction to a raw genesis manifest JSON document.
///
/// # Errors
/// Returns an error when the document has no transaction array.
pub(crate) fn append_genesis_transaction(
    manifest: &mut Value,
    instructions: &[InstructionBox],
) -> Result<()> {
    let transactions = manifest
        .as_object_mut()
        .and_then(|object| object.get_mut("transactions"))
        .and_then(Value::as_array_mut)
        .ok_or_else(|| eyre!("genesis manifest has no transaction array"))?;
    let mut transaction = Map::new();
    transaction.insert(
        "instructions".into(),
        iroha_genesis::genesis_instructions_json::instructions_to_value(instructions),
    );
    transaction.insert("ivm_triggers".into(), Value::Array(Vec::new()));
    transaction.insert("topology".into(), Value::Array(Vec::new()));
    transactions.push(Value::Object(transaction));
    Ok(())
}

/// Render a citizen's client configuration from the network's generated client config.
///
/// The account signs with `private_key_file` (the citizen's owner-only key file next to the
/// rendered config), never with an inline key, and the network identity always comes from
/// `network_id_file`, the absolute path of the `genesis.expected_hash` that re-signing the
/// seated genesis rewrites; an inline template `network_id` would be stale after re-signing.
///
/// # Errors
/// Returns an error when the template has no `[account]` table.
pub(crate) fn citizen_client_config(
    template: &toml::Table,
    public_key: &iroha_crypto::PublicKey,
    private_key_file: &str,
    network_id_file: &Path,
) -> Result<String> {
    let mut config = template.clone();
    config.remove("network_id");
    config.insert(
        "network_id_file".into(),
        toml::Value::String(network_id_file.display().to_string()),
    );
    let account = config
        .get_mut("account")
        .and_then(toml::Value::as_table_mut)
        .ok_or_else(|| eyre!("client config template has no [account] table"))?;
    account.remove("private_key");
    account.insert(
        "public_key".into(),
        toml::Value::String(public_key.to_string()),
    );
    account.insert(
        "private_key_file".into(),
        toml::Value::String(private_key_file.to_owned()),
    );
    toml::to_string(&config).wrap_err("cannot render citizen client config")
}

/// One genesis citizen in the public manifest.
#[derive(Clone, Debug, PartialEq, Eq, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub(crate) struct CitizenEntryV1 {
    /// Zero-based citizen index.
    pub(crate) index: u32,
    /// Canonical citizen account.
    pub(crate) account_id: String,
    /// Citizen public key.
    pub(crate) public_key: String,
    /// Owner-only private-key file, relative to the citizen directory.
    pub(crate) private_key_file: String,
    /// Owner-only client configuration, relative to the citizen directory.
    pub(crate) client_config_file: Option<String>,
}

/// Public manifest of one seating run; holds no secret.
#[derive(Clone, Debug, PartialEq, Eq, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub(crate) struct CitizenManifestV1 {
    /// Exact schema.
    pub(crate) schema: String,
    /// Chain identifier of the seated network.
    pub(crate) chain: String,
    /// Citizenship bond asset.
    pub(crate) citizenship_asset_id: String,
    /// Bond registered for every citizen.
    pub(crate) citizenship_bond_amount: String,
    /// Fresh citizenship escrow whose key was discarded; every validator config names it.
    pub(crate) citizenship_escrow_account: String,
    /// Fee float minted to every citizen on top of its bond.
    pub(crate) fee_float: String,
    /// Holder of the genesis `CanProposeSccpRouteGovernance` grant, if any.
    pub(crate) sccp_proposer: Option<String>,
    /// The genesis citizens in index order.
    pub(crate) citizens: Vec<CitizenEntryV1>,
}

/// Seat the SORA Parliament in a freshly generated Kagami Taira network.
#[derive(clap::Args, Debug)]
pub struct SeatParliament {
    /// Freshly generated, not yet deployed Kagami Taira network (owner-only directory).
    #[arg(long, value_name = "DIR")]
    pub localnet_dir: PathBuf,
    /// Number of genesis citizens `C`.
    #[arg(long, default_value_t = DEFAULT_GENESIS_CITIZENS, value_parser = clap::value_parser!(u32).range(1..=i64::from(MAX_GENESIS_CITIZENS)))]
    pub citizens: u32,
    /// XOR fee float minted to every citizen on top of its bond.
    #[arg(long, default_value = DEFAULT_FEE_FLOAT_XOR)]
    pub fee_float: Quantity,
    /// Grant the genesis-only `CanProposeSccpRouteGovernance` to the registered account of this
    /// public key (the reset operator's proposing account). Off unless given.
    #[arg(long, value_name = "PUBLIC_KEY", value_parser = parse_public_key)]
    pub sccp_proposer_public_key: Option<iroha_crypto::PublicKey>,
    /// Fresh owner-only directory for the citizen keys; defaults to
    /// `<localnet-dir>/runtime/taira-parliament-citizens`.
    #[arg(long, value_name = "DIR")]
    pub citizen_dir: Option<PathBuf>,
}

#[cfg(unix)]
fn require_owner_only_directory(path: &Path, label: &str) -> Result<()> {
    use std::os::unix::fs::MetadataExt as _;
    let metadata = fs::symlink_metadata(path)
        .wrap_err_with(|| format!("cannot inspect {label} `{}`", path.display()))?;
    if !metadata.is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
    {
        return Err(eyre!(
            "{label} `{}` must be an owner-only directory",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn require_owner_only_directory(_path: &Path, _label: &str) -> Result<()> {
    Err(eyre!("Parliament seating requires Unix owner-only custody"))
}

#[cfg(unix)]
fn create_owner_only_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt as _;
    fs::DirBuilder::new()
        .mode(0o700)
        .create(path)
        .wrap_err_with(|| {
            format!(
                "citizen directory `{}` must not exist before seating",
                path.display()
            )
        })
}

#[cfg(not(unix))]
fn create_owner_only_directory(_path: &Path) -> Result<()> {
    Err(eyre!("Parliament seating requires Unix owner-only custody"))
}

#[cfg(unix)]
fn write_new_owner_only(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .wrap_err_with(|| format!("cannot create fresh owner-only `{}`", path.display()))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn write_new_owner_only(_path: &Path, _bytes: &[u8]) -> Result<()> {
    Err(eyre!("Parliament seating requires Unix owner-only custody"))
}

/// Atomically replace an owner-only file in its directory.
#[cfg(unix)]
fn replace_owner_only(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    let parent = path
        .parent()
        .ok_or_else(|| eyre!("`{}` has no parent directory", path.display()))?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))?;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    temporary
        .persist(path)
        .map_err(|error| eyre!("cannot replace `{}`: {}", path.display(), error.error))?;
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn replace_owner_only(_path: &Path, _bytes: &[u8]) -> Result<()> {
    Err(eyre!("Parliament seating requires Unix owner-only custody"))
}

fn parse_public_key(value: &str) -> Result<iroha_crypto::PublicKey, String> {
    let key = value
        .parse::<iroha_crypto::PublicKey>()
        .map_err(|_| "must be a canonical public key".to_owned())?;
    if key.to_string() != value {
        return Err(format!("must use canonical form `{key}`"));
    }
    Ok(key)
}

fn parse_account(literal: &str, label: &str) -> Result<AccountId> {
    let account = AccountId::parse_encoded(literal)
        .map_err(|error| eyre!("{label} is not a canonical account: {error}"))?;
    if account.to_string() != literal {
        return Err(eyre!("{label} must use canonical form `{account}`"));
    }
    Ok(account)
}

impl SeatParliament {
    /// Seat the Parliament and write the JSON report to `writer`.
    ///
    /// # Errors
    /// Refuses a network that is already seated, whose genesis lacks the citizenship asset, or
    /// whose seated profile fails any §4.14.5 requirement.
    pub fn run_with_writer(&self, writer: &mut impl std::io::Write) -> Result<()> {
        let _chain = ChainDiscriminantGuard::enter(TAIRA_CHAIN_DISCRIMINANT);
        require_owner_only_directory(&self.localnet_dir, "generated network")?;
        let citizen_dir = self
            .citizen_dir
            .clone()
            .unwrap_or_else(|| self.localnet_dir.join(CITIZEN_DIRECTORY));
        let genesis_path = self.localnet_dir.join("genesis.json");
        let genesis_bytes = read_bounded(&genesis_path, "genesis manifest")?;
        let manifest: iroha_genesis::RawGenesisTransaction = json::from_slice(&genesis_bytes)
            .wrap_err("generated genesis.json is not a raw genesis manifest")?;
        if manifest.chain_id().to_string() != TAIRA_CHAIN_ID {
            return Err(eyre!("generated network is not the canonical Taira chain"));
        }
        if manifest
            .instructions()
            .any(|instruction| instruction.as_any().is::<RegisterCitizen>())
        {
            return Err(eyre!(
                "generated genesis already registers citizens; regenerate the network before seating"
            ));
        }
        let canonical: toml::Table =
            toml::from_str(CANONICAL_TAIRA_PROFILE).wrap_err("canonical Taira profile")?;
        // A fresh citizenship escrow whose key is dropped here, never written: core moves
        // citizenship bonds into and out of it without the escrow's signature, so no one can
        // drain them. Kagami's default escrow is the published sample governance key.
        let escrow = AccountId::new(
            KeyPair::try_random_with_algorithm(Algorithm::Ed25519)
                .map_err(|_| eyre!("citizenship escrow key generation failed"))?
                .public_key()
                .clone(),
        );
        let mut rendered = Vec::new();
        let mut profile: Option<SeatingProfile> = None;
        for path in peer_configs(&self.localnet_dir)? {
            let text = String::from_utf8(read_bounded(&path, "validator config")?)
                .map_err(|_| eyre!("validator config `{}` is not UTF-8", path.display()))?;
            let mut config: toml::Table = toml::from_str(&text)
                .wrap_err_with(|| format!("validator config `{}`", path.display()))?;
            apply_seating_keys(&mut config, &canonical)?;
            set_citizenship_escrow(&mut config, &escrow)?;
            let seated = SeatingProfile::from_config(&config)?;
            if profile.as_ref().is_some_and(|shared| *shared != seated) {
                return Err(eyre!(
                    "validator `{}` does not share the network's faucet policy",
                    path.display()
                ));
            }
            profile = Some(seated);
            rendered.push((path, toml::to_string(&config)?));
        }
        let profile = profile.ok_or_else(|| eyre!("generated network has no validator config"))?;
        refuse_unseated(&profile, u64::from(self.citizens))?;
        let census = genesis_citizen_census(manifest.instructions(), profile.citizenship_bond());
        if census.parliament_manager_grants != 0 {
            return Err(eyre!(
                "generated genesis grants CanManageParliament; SCCP attempts need no clerk"
            ));
        }
        let asset = AssetDefinitionId::parse_address_literal(&profile.citizenship_asset_id)
            .map_err(|_| eyre!("citizenship asset is not a canonical asset definition"))?;
        if !census.registered_asset_definitions.contains(&asset) {
            return Err(eyre!(
                "generated genesis does not register the citizenship asset {asset}"
            ));
        }
        if census.registered_accounts.contains(&escrow) {
            return Err(eyre!(
                "the generated citizenship escrow collides with a genesis account"
            ));
        }
        let sccp_proposer = self
            .sccp_proposer_public_key
            .as_ref()
            .map(|key| AccountId::new(key.clone()));
        if let Some(proposer) = &sccp_proposer {
            if !census.registered_accounts.contains(proposer) {
                return Err(eyre!(
                    "SCCP proposer {proposer} is not registered by the generated genesis"
                ));
            }
        }
        let keys = (0..self.citizens)
            .map(|_| {
                KeyPair::try_random_with_algorithm(Algorithm::Ed25519)
                    .map_err(|_| eyre!("citizen key generation failed"))
            })
            .collect::<Result<Vec<_>>>()?;
        let accounts = keys
            .iter()
            .map(|key| AccountId::new(key.public_key().clone()))
            .collect::<Vec<_>>();
        if accounts
            .iter()
            .any(|account| census.registered_accounts.contains(account) || *account == escrow)
        {
            return Err(eyre!("a generated citizen collides with a genesis account"));
        }
        let instructions = citizen_genesis_instructions(
            &accounts,
            &asset,
            profile.citizenship_bond(),
            &self.fee_float,
            Some(&escrow),
            sccp_proposer.as_ref(),
        )?;
        let mut document: Value = json::from_slice(&genesis_bytes)?;
        append_genesis_transaction(&mut document, &instructions)?;
        if !manifest
            .instructions()
            .any(|instruction| instruction.as_any().is::<InitializeSccpV1>())
        {
            append_genesis_transaction(
                &mut document,
                &[sccp_genesis_instruction(fresh_sccp_reset_nonce()?)?],
            )?;
        }
        let mut genesis_json = json::to_json_pretty(&document)?;
        genesis_json.push('\n');
        let reparsed: iroha_genesis::RawGenesisTransaction = json::from_str(&genesis_json)
            .wrap_err("seated genesis manifest does not round-trip")?;
        require_seated_genesis(&profile, reparsed.instructions())?;

        let client_template = match fs::symlink_metadata(self.localnet_dir.join("client.toml")) {
            Ok(_) => Some(
                toml::from_str::<toml::Table>(
                    &String::from_utf8(read_bounded(
                        &self.localnet_dir.join("client.toml"),
                        "client config",
                    )?)
                    .map_err(|_| eyre!("generated client config is not UTF-8"))?,
                )
                .wrap_err("generated client config is not TOML")?,
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
        };
        // Re-signing the seated genesis rewrites this file with the new network identity.
        let network_id_file = fs::canonicalize(&self.localnet_dir)
            .wrap_err("cannot resolve the generated network directory")?
            .join(GENESIS_EXPECTED_HASH_FILE);
        // Capture the exact prior trust root before the first seating output write. The signer
        // subsequently checks its file custody, held inode, and bytes before any publication.
        let prior_network_id = read_prior_network_identity(&network_id_file)?;
        if let Some(parent) = citizen_dir.parent() {
            fs::create_dir_all(parent)?;
        }
        create_owner_only_directory(&citizen_dir)?;
        let mut entries = Vec::with_capacity(keys.len());
        for (index, (key, account)) in keys.iter().zip(&accounts).enumerate() {
            let index = u32::try_from(index).expect("bounded citizen count");
            let private_key_file = format!("citizen-{index:02}.private_key");
            let encoded = Zeroizing::new(
                ExposedPrivateKey(key.private_key().clone())
                    .try_to_multihash_string()
                    .map_err(|_| eyre!("cannot encode citizen private key"))?,
            );
            let mut line = Zeroizing::new(encoded.as_bytes().to_vec());
            line.push(b'\n');
            write_new_owner_only(&citizen_dir.join(&private_key_file), &line)?;
            let client_config_file = match &client_template {
                Some(template) => {
                    let name = format!("citizen-{index:02}.client.toml");
                    let rendered = citizen_client_config(
                        template,
                        key.public_key(),
                        &private_key_file,
                        &network_id_file,
                    )?;
                    write_new_owner_only(&citizen_dir.join(&name), rendered.as_bytes())?;
                    Some(name)
                }
                None => None,
            };
            entries.push(CitizenEntryV1 {
                index,
                account_id: account.to_string(),
                public_key: key.public_key().to_string(),
                private_key_file,
                client_config_file,
            });
        }
        let escrow_literal = escrow.to_string();
        let citizen_manifest = CitizenManifestV1 {
            schema: CITIZEN_MANIFEST_SCHEMA_V1.to_owned(),
            chain: TAIRA_CHAIN_ID.to_owned(),
            citizenship_asset_id: asset.to_string(),
            citizenship_bond_amount: profile.citizenship_bond().to_string(),
            citizenship_escrow_account: escrow_literal.clone(),
            fee_float: self.fee_float.to_string(),
            sccp_proposer: sccp_proposer.as_ref().map(ToString::to_string),
            citizens: entries,
        };
        let mut manifest_bytes = json::to_json_pretty(&citizen_manifest)?.into_bytes();
        manifest_bytes.push(b'\n');
        write_new_owner_only(&citizen_dir.join(CITIZEN_MANIFEST_FILE), &manifest_bytes)?;
        for (path, text) in &rendered {
            replace_owner_only(path, text.as_bytes())?;
        }
        replace_owner_only(&genesis_path, genesis_json.as_bytes())?;

        let mut report = Map::new();
        report.insert("schema".into(), Value::from(SEAT_REPORT_SCHEMA_V1));
        report.insert("citizens".into(), Value::from(u64::from(self.citizens)));
        report.insert(
            "citizenship_bond_amount".into(),
            Value::from(profile.citizenship_bond().to_string()),
        );
        report.insert("fee_float".into(), Value::from(self.fee_float.to_string()));
        report.insert(
            "citizen_dir".into(),
            Value::from(citizen_dir.display().to_string()),
        );
        report.insert(
            "citizenship_escrow_account".into(),
            Value::from(escrow_literal),
        );
        report.insert(
            "sccp_proposer".into(),
            sccp_proposer.map_or(Value::Null, |proposer| Value::from(proposer.to_string())),
        );
        report.insert(
            "previous_network_id".into(),
            Value::from(prior_network_id.to_string()),
        );
        report.insert(
            "next".into(),
            Value::from(resign_instructions(prior_network_id)),
        );
        writeln!(writer, "{}", json::to_json(&Value::Object(report))?)?;
        Ok(())
    }
}

impl Run for SeatParliament {
    fn run<C: RunContext>(self, _context: &mut C) -> Result<()> {
        self.run_with_writer(&mut std::io::stdout().lock())
    }
}

#[cfg(test)]
#[path = "taira_parliament_seating_tests.rs"]
mod tests;
