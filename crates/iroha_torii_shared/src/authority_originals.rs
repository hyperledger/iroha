//! Scoped native authority originals for an already authorized ledger-wide reader.
//!
//! These data carriers grant no permission, finality, monetary ownership or release
//! authority. The exact request is signed by its holder; its derived challenge binds
//! the native node statement to the selected fixed-field family and fresh entropy.

use iroha_data_model::{
    Identifiable, NetworkId,
    account::{
        AccountId, AccountValue,
        rekey::{AccountAlias, AccountRekeyRecord},
    },
    alias_setup::AccountAliasName,
    asset::{
        AssetBalancePolicy, AssetBalanceScope, AssetDefinition, AssetDefinitionId, AssetId,
        AssetValue,
    },
    identifier::{IdentifierPolicy, IdentifierPolicyId},
    nexus::{
        FeeSponsorBudgetCounterKey, FeeSponsorEnrollment, FeeSponsorEnrollmentKey,
        FeeSponsorProgram, FeeSponsorProgramId, FeeSponsorProgramRevision,
        FeeSponsorProgramRevisionKey, FeeSponsorVault, FeeSponsorVaultKey,
    },
    ram_lfe::RamLfeProgramPolicy,
    sumeragi_finality::{
        MAX_WORLD_STATE_SNAPSHOT_ENTRIES_V1, SumeragiFinalityAttestation, WorldStateSnapshotV1,
    },
};
use norito::derive::{JsonDeserialize, JsonSerialize, NoritoDeserialize, NoritoSerialize};
use sha2::{Digest as _, Sha256};

/// Exact signed POST route; arbitrary paths, queries and state selectors are refused.
pub const NATIVE_AUTHORITY_ORIGINALS_ROUTE_V1: &str = "/v1/ledger/authority-originals";
/// Original canonical request body ceiling.
pub const NATIVE_AUTHORITY_ORIGINALS_REQUEST_MAX_BYTES_V1: usize = 64 * 1024;
/// Complete carrier reader ceiling, further restricted by the server's original pool.
pub const NATIVE_AUTHORITY_ORIGINALS_MAX_BYTES_V1: usize = 128 * 1024 * 1024;
/// Current first-release consumer ceiling for each complete fee key or selected row set.
pub const NATIVE_AUTHORITY_ORIGINALS_MAX_FEE_KEYS_V1: usize = 16_384;
/// Maximum original account, rekey, lease or funding row.
pub const NATIVE_AUTHORITY_ORIGINALS_MAX_ROW_BYTES_V1: usize = 1024 * 1024;
const CHALLENGE_DOMAIN: &[u8] = b"iroha.native-authority-originals.request.v1\0";

/// Request selects exactly one fixed-field family; a native fresh nonce also protects HTTP replay.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    JsonSerialize,
    JsonDeserialize,
    NoritoSerialize,
    NoritoDeserialize,
    norito::NoritoSchema,
)]
#[norito(deny_unknown_fields, no_fast_from_json)]
#[norito_schema(
    name = "iroha_torii_shared::authority_originals::NativeAuthorityOriginalsRequestV1",
    frame = "iroha.torii.v1.ledger.authority-originals.request"
)]
pub struct NativeAuthorityOriginalsRequestV1 {
    /// Exact genesis-derived native network.
    pub network_id: NetworkId,
    /// Caller fresh nonzero entropy, included in the signed original body.
    pub challenge: [u8; 32],
    /// Only a fixed canonical native authority family may be selected.
    pub selector: NativeAuthorityOriginalsSelectorV1,
}

/// Finite typed selectors; no table names, state paths, key bytes or raw prefixes.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    JsonSerialize,
    JsonDeserialize,
    NoritoSerialize,
    NoritoDeserialize,
    norito::NoritoSchema,
)]
#[norito(
    tag = "kind",
    content = "payload",
    deny_unknown_fields,
    no_fast_from_json
)]
#[norito_schema(
    name = "iroha_torii_shared::authority_originals::NativeAuthorityOriginalsSelectorV1"
)]
pub enum NativeAuthorityOriginalsSelectorV1 {
    /// An exact canonical textual alias; the server retains native catalog resolution.
    AccountAlias(AccountAliasName),
    /// Sponsor is derived from the native program id, including an absent new program.
    GlobalFeeProgram {
        /// Exact native sponsor/program identifier.
        program_id: FeeSponsorProgramId,
        /// Exact native definition for the derived Global funding bucket.
        fee_asset: AssetDefinitionId,
    },
    /// Exact identifier policy and the RAM-LFE program named by that original.
    IdentifierPolicy(IdentifierPolicyId),
}

/// One selected family; unrelated private values are never added to this carrier.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    JsonSerialize,
    JsonDeserialize,
    NoritoSerialize,
    NoritoDeserialize,
    norito::NoritoSchema,
)]
#[norito(
    tag = "kind",
    content = "payload",
    deny_unknown_fields,
    no_fast_from_json
)]
#[norito_schema(name = "iroha_torii_shared::authority_originals::NativeAuthorityOriginalsFamilyV1")]
#[expect(
    clippy::large_enum_variant,
    reason = "retain fixed-size owned family values inline without introducing a separate heap owner"
)]
pub enum NativeAuthorityOriginalsFamilyV1 {
    /// Complete canonical account binding keys and selected originals.
    AccountAlias(NativeAccountAliasStateV1),
    /// Complete six-table fee keys and selected originals.
    GlobalFeeProgram(NativeGlobalFeeProgramStateV1),
    /// Actual policy and its referenced program from the same certified World cut.
    IdentifierPolicy(NativeIdentifierPolicyStateV1),
}

fn refused(message: &str) -> norito::Error {
    norito::Error::Message(message.into())
}
impl NativeAuthorityOriginalsRequestV1 {
    /// Validate canonical native selectors and nonzero entropy; no permission is granted.
    /// # Errors
    /// Zero challenge or noncanonical textual native selector.
    pub fn validate(&self) -> Result<(), norito::Error> {
        if self.challenge == [0; 32] {
            return Err(refused("authority originals challenge must be nonzero"));
        }
        match &self.selector {
            NativeAuthorityOriginalsSelectorV1::AccountAlias(name) if !name.is_canonical() => Err(
                refused("authority originals account alias must be canonical"),
            ),
            NativeAuthorityOriginalsSelectorV1::GlobalFeeProgram { program_id, .. } => {
                let parsed = program_id
                    .to_string()
                    .parse::<FeeSponsorProgramId>()
                    .map_err(|_| refused("authority originals program id is not canonical"))?;
                if &parsed != program_id {
                    return Err(refused(
                        "authority originals program id changed canonical identity",
                    ));
                }
                Ok(())
            }
            NativeAuthorityOriginalsSelectorV1::IdentifierPolicy(policy_id) => {
                let parsed = policy_id
                    .to_string()
                    .parse::<IdentifierPolicyId>()
                    .map_err(|_| {
                        refused("authority originals identifier policy id is not canonical")
                    })?;
                if &parsed != policy_id {
                    return Err(refused(
                        "authority originals identifier policy identity changed",
                    ));
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }
    /// Encode the only original bytes signed by both provider and server verifier.
    /// # Errors
    /// Invalid native selector, serialization failure or oversized request.
    pub fn canonical_wire(&self) -> Result<Vec<u8>, norito::Error> {
        self.validate()?;
        let len = norito::canonical_frame_len(self)?;
        if len > NATIVE_AUTHORITY_ORIGINALS_REQUEST_MAX_BYTES_V1 {
            return Err(refused(
                "authority originals request exceeds its original bound",
            ));
        }
        norito::encode_canonical(self)
    }
}
/// Decode only the bounded original request; noncanonical bytes cannot be reinterpreted.
/// # Errors
/// Empty, oversized, malformed, trailing, noncanonical or invalid selector data.
pub fn decode_native_authority_originals_request_v1(
    bytes: &[u8],
) -> Result<NativeAuthorityOriginalsRequestV1, norito::Error> {
    if bytes.is_empty() || bytes.len() > NATIVE_AUTHORITY_ORIGINALS_REQUEST_MAX_BYTES_V1 {
        return Err(refused(
            "authority originals request exceeds its original bound",
        ));
    }
    let request: NativeAuthorityOriginalsRequestV1 =
        norito::decode_canonical_with_limits(bytes, norito::canonical_decode_limits(bytes.len()))?;
    request.validate()?;
    Ok(request)
}
/// Compute independent correlation digests from already validated original canonical bytes.
/// # Errors
/// Request bytes are not the sole bounded canonical native request layout.
pub fn native_authority_originals_request_digests_v1(
    bytes: &[u8],
) -> Result<([u8; 32], [u8; 32]), norito::Error> {
    decode_native_authority_originals_request_v1(bytes)?;
    let request_sha256 = Sha256::digest(bytes).into();
    let mut challenge = Sha256::new();
    challenge.update(CHALLENGE_DOMAIN);
    challenge.update(bytes);
    Ok((request_sha256, challenge.finalize().into()))
}
/// Decode bounded data only; typed keys and values still need independent World membership.
/// # Errors
/// Empty, oversized, malformed, trailing or noncanonical original response.
pub fn decode_unverified_native_authority_originals_v1(
    bytes: &[u8],
) -> Result<NativeAuthorityOriginalsV1, norito::Error> {
    if bytes.is_empty() || bytes.len() > NATIVE_AUTHORITY_ORIGINALS_MAX_BYTES_V1 {
        return Err(refused("authority originals response exceeds reader bound"));
    }
    norito::decode_canonical_with_limits(bytes, norito::canonical_decode_limits(bytes.len()))
}
impl NativeAuthorityOriginalsV1 {
    /// Check exact request correlation and private response shape, never ledger authority.
    /// # Errors
    /// Changed network, selector, digest/challenge, oversized rows, duplicate keys,
    /// unrelated selected values or missing mandatory Global source bucket data.
    pub fn validate_request_correlation(
        &self,
        request: &NativeAuthorityOriginalsRequestV1,
    ) -> Result<(), norito::Error> {
        let wire = request.canonical_wire()?;
        let (digest, challenge) = native_authority_originals_request_digests_v1(&wire)?;
        if self.request_sha256 != digest
            || self.selector != request.selector
            || self.attestation.body.network_id != request.network_id
            || self.attestation.body.challenge != challenge
        {
            return Err(refused(
                "authority originals response changed exact signed request",
            ));
        }
        match (&request.selector, &self.originals) {
            (
                NativeAuthorityOriginalsSelectorV1::AccountAlias(name),
                NativeAuthorityOriginalsFamilyV1::AccountAlias(state),
            ) => {
                if state.alias.label != name.label
                    || state
                        .alias
                        .domain
                        .as_ref()
                        .map(iroha_data_model::account::AccountAliasDomain::name)
                        != name.domain.as_ref()
                    || state.binding_keys.len() > MAX_WORLD_STATE_SNAPSHOT_ENTRIES_V1
                {
                    return Err(refused(
                        "authority originals selected alias changed or is oversized",
                    ));
                }
                ordered(&state.binding_keys)?;
                if state.binding_keys.binary_search(&state.alias).is_ok()
                    != state.selected.is_some()
                {
                    return Err(refused(
                        "authority originals alias presence changed selected originals",
                    ));
                }
                if let Some(value) = &state.selected {
                    if value.rekey_record.label != state.alias
                        || value.rekey_record.active_account_id != value.bound_account
                    {
                        return Err(refused("authority originals alias/rekey identity changed"));
                    }
                    bounded_row(&value.rekey_record)?;
                    bounded_row(&value.account_value)?;
                    if value.lease_value.is_empty()
                        || value.lease_value.len() > NATIVE_AUTHORITY_ORIGINALS_MAX_ROW_BYTES_V1
                    {
                        return Err(refused("authority originals account lease exceeds bound"));
                    }
                }
            }
            (
                NativeAuthorityOriginalsSelectorV1::GlobalFeeProgram {
                    program_id,
                    fee_asset,
                },
                NativeAuthorityOriginalsFamilyV1::GlobalFeeProgram(state),
            ) => {
                if &state.program_id != program_id || &state.fee_asset != fee_asset {
                    return Err(refused("authority originals fee selector changed"));
                }
                bounded_keys(&state.asset_keys)?;
                bounded_keys(&state.program_keys)?;
                bounded_keys(&state.revision_keys)?;
                bounded_keys(&state.enrollment_keys)?;
                bounded_keys(&state.vault_keys)?;
                bounded_keys(&state.budget_counter_keys)?;
                bounded_row(&state.sponsor_account_value)?;
                bounded_row(&state.fee_asset_definition)?;
                bounded_row(&state.source_asset_value)?;
                let source = AssetId::with_scope(
                    fee_asset.clone(),
                    program_id.sponsor.clone(),
                    AssetBalanceScope::Global,
                );
                if state.asset_keys.binary_search(&source).is_err()
                    || state.program_keys.binary_search(program_id).is_ok()
                        != state.program.is_some()
                {
                    return Err(refused(
                        "authority originals funding bucket or program presence changed",
                    ));
                }
                if state.fee_asset_definition.id() != fee_asset
                    || state.fee_asset_definition.balance_scope_policy()
                        != AssetBalancePolicy::Global
                {
                    return Err(refused("authority originals funding definition changed"));
                }
                if let Some(program) = &state.program {
                    if &program.id != program_id {
                        return Err(refused(
                            "authority originals disclosed an unrelated program",
                        ));
                    }
                    bounded_row(program)?;
                }
                for count in [
                    state.revisions.len(),
                    state.enrollments.len(),
                    state.vaults.len(),
                ] {
                    if count > NATIVE_AUTHORITY_ORIGINALS_MAX_FEE_KEYS_V1 {
                        return Err(refused(
                            "authority originals selected fee rows exceed bound",
                        ));
                    }
                }
                if state
                    .revisions
                    .windows(2)
                    .any(|p| p[0].revision >= p[1].revision)
                    || state.enrollments.windows(2).any(|p| p[0].key >= p[1].key)
                    || state.vaults.windows(2).any(|p| p[0].key >= p[1].key)
                {
                    return Err(refused(
                        "authority originals selected fee rows are duplicate or unordered",
                    ));
                }
                if !state
                    .revision_keys
                    .iter()
                    .filter(|k| &k.program_id == program_id)
                    .map(|k| k.revision)
                    .eq(state.revisions.iter().map(|r| r.revision))
                    || !state
                        .enrollment_keys
                        .iter()
                        .filter(|k| &k.program_id == program_id)
                        .eq(state.enrollments.iter().map(|r| &r.key))
                    || !state
                        .vault_keys
                        .iter()
                        .filter(|k| &k.program_id == program_id)
                        .eq(state.vaults.iter().map(|r| &r.key))
                {
                    return Err(refused(
                        "authority originals selected fee rows omit actual target keys",
                    ));
                }
                for row in &state.revisions {
                    if &row.program_id != program_id {
                        return Err(refused(
                            "authority originals disclosed an unrelated revision",
                        ));
                    }
                    bounded_row(row)?;
                }
                for row in &state.enrollments {
                    if &row.key.program_id != program_id {
                        return Err(refused(
                            "authority originals disclosed an unrelated enrollment",
                        ));
                    }
                    bounded_row(row)?;
                }
                for row in &state.vaults {
                    if &row.key.program_id != program_id {
                        return Err(refused("authority originals disclosed an unrelated vault"));
                    }
                    bounded_row(row)?;
                }
            }
            (
                NativeAuthorityOriginalsSelectorV1::IdentifierPolicy(policy_id),
                NativeAuthorityOriginalsFamilyV1::IdentifierPolicy(state),
            ) => {
                if &state.policy.id != policy_id
                    || state.policy.program_id != state.program.program_id
                {
                    return Err(refused(
                        "authority originals identifier policy/program changed",
                    ));
                }
                bounded_row(&state.policy)?;
                bounded_row(&state.program)?;
            }
            _ => {
                return Err(refused(
                    "authority originals response changed selected family",
                ));
            }
        }
        Ok(())
    }
}
fn ordered<T: Ord>(keys: &[T]) -> Result<(), norito::Error> {
    if keys.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(refused(
            "authority originals keys are duplicate or unordered",
        ));
    }
    Ok(())
}
fn bounded_keys<T: Ord>(keys: &[T]) -> Result<(), norito::Error> {
    if keys.len() > NATIVE_AUTHORITY_ORIGINALS_MAX_FEE_KEYS_V1 {
        return Err(refused(
            "authority originals complete fee keys exceed bound",
        ));
    }
    ordered(keys)
}
fn bounded_row<T: norito::NoritoSerialize>(row: &T) -> Result<(), norito::Error> {
    if norito::canonical_frame_len(row)? > NATIVE_AUTHORITY_ORIGINALS_MAX_ROW_BYTES_V1 {
        return Err(refused(
            "authority originals selected native row exceeds bound",
        ));
    }
    Ok(())
}
/// Selected native account alias originals and complete canonical binding keys.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    JsonSerialize,
    JsonDeserialize,
    NoritoSerialize,
    NoritoDeserialize,
    norito::NoritoSchema,
)]
#[norito(deny_unknown_fields, no_fast_from_json)]
#[norito_schema(name = "iroha_torii_shared::authority_originals::NativeAccountAliasStateV1")]
pub struct NativeAccountAliasStateV1 {
    /// Native numeric alias resolved against the retained native catalog.
    pub alias: AccountAlias,
    /// Every canonical `world.account_aliases` key, without reverse-index substitution.
    pub binding_keys: Vec<AccountAlias>,
    /// Exact selected originals; None only when the binding is absent at this cut.
    #[norito(required)]
    pub selected: Option<NativeAccountAliasOriginalV1>,
}

/// The selected actual stored account and alias history; no cleared-label projection.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    JsonSerialize,
    JsonDeserialize,
    NoritoSerialize,
    NoritoDeserialize,
    norito::NoritoSchema,
)]
#[norito(deny_unknown_fields, no_fast_from_json)]
#[norito_schema(name = "iroha_torii_shared::authority_originals::NativeAccountAliasOriginalV1")]
pub struct NativeAccountAliasOriginalV1 {
    /// Actual `world.account_aliases` value.
    pub bound_account: AccountId,
    /// Entire stored native rekey record, including history and provenance.
    pub rekey_record: AccountRekeyRecord,
    /// Actual Owned<AccountDetails>, preserving its stored label and identifiers.
    pub account_value: AccountValue,
    /// Bare native `NameRecord` bytes at the server-derived account lease `StatePath`.
    pub lease_value: Vec<u8>,
}

/// Exact original policy and only its referenced original RAM-LFE program.
/// These values grant no active-policy, execution, permission or World membership claim.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    JsonSerialize,
    JsonDeserialize,
    NoritoSerialize,
    NoritoDeserialize,
    norito::NoritoSchema,
)]
#[norito(deny_unknown_fields, no_fast_from_json)]
#[norito_schema(name = "iroha_torii_shared::authority_originals::NativeIdentifierPolicyStateV1")]
pub struct NativeIdentifierPolicyStateV1 {
    /// Original `world.identifier_policies` row for the exact selector.
    pub policy: IdentifierPolicy,
    /// Original `world.ram_lfe_program_policies` row selected by that policy.
    pub program: RamLfeProgramPolicy,
}

/// Complete native fee keys and only selected program/funding original values.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    JsonSerialize,
    JsonDeserialize,
    NoritoSerialize,
    NoritoDeserialize,
    norito::NoritoSchema,
)]
#[norito(deny_unknown_fields, no_fast_from_json)]
#[norito_schema(name = "iroha_torii_shared::authority_originals::NativeGlobalFeeProgramStateV1")]
pub struct NativeGlobalFeeProgramStateV1 {
    /// Exact native sponsor and program name; sponsor is present even before registration.
    pub program_id: FeeSponsorProgramId,
    /// Exact native fee definition selected by the independently approved caller.
    pub fee_asset: AssetDefinitionId,
    /// Every canonical world.assets key.
    pub asset_keys: Vec<AssetId>,
    /// Every canonical `world.fee_sponsor_programs` key.
    pub program_keys: Vec<FeeSponsorProgramId>,
    /// Every canonical immutable program-revision key.
    pub revision_keys: Vec<FeeSponsorProgramRevisionKey>,
    /// Every canonical beneficiary enrollment key.
    pub enrollment_keys: Vec<FeeSponsorEnrollmentKey>,
    /// Every canonical isolated vault key.
    pub vault_keys: Vec<FeeSponsorVaultKey>,
    /// Every canonical spent-budget key; unrelated counter values are withheld.
    pub budget_counter_keys: Vec<FeeSponsorBudgetCounterKey>,
    /// Actual sponsor account value, preserving its stored label.
    pub sponsor_account_value: AccountValue,
    /// Actual fee definition, without query-materialized alias changes.
    pub fee_asset_definition: AssetDefinition,
    /// Present actual Global source bucket; absence never supplies a zero amount.
    pub source_asset_value: AssetValue,
    /// Actual selected program, or certified complete-table absence.
    #[norito(required)]
    pub program: Option<FeeSponsorProgram>,
    /// Every original revision whose program key equals the exact selected program.
    pub revisions: Vec<FeeSponsorProgramRevision>,
    /// Every original beneficiary enrollment for the exact selected program.
    pub enrollments: Vec<FeeSponsorEnrollment>,
    /// Every original vault allocation for the exact selected program.
    pub vaults: Vec<FeeSponsorVault>,
}

/// Unverified challenged canonical data; independent installed-node/finality verification is required.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    JsonSerialize,
    JsonDeserialize,
    NoritoSerialize,
    NoritoDeserialize,
    norito::NoritoSchema,
)]
#[norito(deny_unknown_fields, no_fast_from_json)]
#[norito_schema(
    name = "iroha_torii_shared::authority_originals::NativeAuthorityOriginalsV1",
    frame = "iroha.torii.v1.ledger.authority-originals.response"
)]
pub struct NativeAuthorityOriginalsV1 {
    /// SHA256 of the exact original canonical request body, recomputed by the reader.
    pub request_sha256: [u8; 32],
    /// Exact selector echo; never independently grants permission or catalog authority.
    pub selector: NativeAuthorityOriginalsSelectorV1,
    /// Current native node statement bound to the full request-derived challenge.
    pub attestation: SumeragiFinalityAttestation,
    /// Complete original World hash preimages at this exact native certified cut.
    pub world_snapshot: WorldStateSnapshotV1,
    /// Only the selected fixed-field family's originals.
    pub originals: NativeAuthorityOriginalsFamilyV1,
}

/// Borrowed exact encoder of `NativeAccountAliasOriginalV1`; allocations stay with the original finite owner.
#[derive(NoritoSerialize, JsonSerialize)]
pub struct NativeAccountAliasOriginalRefV1<'a> {
    bound_account: FieldRef<'a, AccountId>,
    rekey_record: FieldRef<'a, AccountRekeyRecord>,
    account_value: FieldRef<'a, AccountValue>,
    lease_value: ByteRef<'a>,
}
impl<'a> NativeAccountAliasOriginalRefV1<'a> {
    /// Borrow only actual retained values and caller-funded complete key/row slices.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        bound_account: &'a AccountId,
        rekey_record: &'a AccountRekeyRecord,
        account_value: &'a AccountValue,
        lease_value: &'a [u8],
    ) -> Self {
        Self {
            bound_account: FieldRef(bound_account),
            rekey_record: FieldRef(rekey_record),
            account_value: FieldRef(account_value),
            lease_value: ByteRef(lease_value),
        }
    }
}

/// Borrowed exact encoder of `NativeAccountAliasStateV1`; allocations stay with the original finite owner.
#[derive(NoritoSerialize, JsonSerialize)]
pub struct NativeAccountAliasStateRefV1<'a> {
    alias: FieldRef<'a, AccountAlias>,
    binding_keys: KeySequenceRef<'a, AccountAlias>,
    selected: Option<NativeAccountAliasOriginalRefV1<'a>>,
}
impl<'a> NativeAccountAliasStateRefV1<'a> {
    /// Borrow only actual retained values and caller-funded complete key/row slices.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        alias: &'a AccountAlias,
        binding_keys: &'a [&'a AccountAlias],
        selected: Option<NativeAccountAliasOriginalRefV1<'a>>,
    ) -> Self {
        Self {
            alias: FieldRef(alias),
            binding_keys: KeySequenceRef(binding_keys),
            selected,
        }
    }
}

/// Borrowed exact encoder of the selected policy/program originals.
#[derive(NoritoSerialize, JsonSerialize)]
pub struct NativeIdentifierPolicyStateRefV1<'a> {
    policy: FieldRef<'a, IdentifierPolicy>,
    program: FieldRef<'a, RamLfeProgramPolicy>,
}
impl<'a> NativeIdentifierPolicyStateRefV1<'a> {
    /// Borrow actual same-cut rows without cloning either private value.
    #[must_use]
    pub fn new(policy: &'a IdentifierPolicy, program: &'a RamLfeProgramPolicy) -> Self {
        Self {
            policy: FieldRef(policy),
            program: FieldRef(program),
        }
    }
}

/// Borrowed exact encoder of `NativeGlobalFeeProgramStateV1`; allocations stay with the original finite owner.
#[derive(NoritoSerialize, JsonSerialize)]
pub struct NativeGlobalFeeProgramStateRefV1<'a> {
    program_id: FieldRef<'a, FeeSponsorProgramId>,
    fee_asset: FieldRef<'a, AssetDefinitionId>,
    asset_keys: KeySequenceRef<'a, AssetId>,
    program_keys: KeySequenceRef<'a, FeeSponsorProgramId>,
    revision_keys: KeySequenceRef<'a, FeeSponsorProgramRevisionKey>,
    enrollment_keys: KeySequenceRef<'a, FeeSponsorEnrollmentKey>,
    vault_keys: KeySequenceRef<'a, FeeSponsorVaultKey>,
    budget_counter_keys: KeySequenceRef<'a, FeeSponsorBudgetCounterKey>,
    sponsor_account_value: FieldRef<'a, AccountValue>,
    fee_asset_definition: FieldRef<'a, AssetDefinition>,
    source_asset_value: FieldRef<'a, AssetValue>,
    program: Option<FieldRef<'a, FeeSponsorProgram>>,
    revisions: KeySequenceRef<'a, FeeSponsorProgramRevision>,
    enrollments: KeySequenceRef<'a, FeeSponsorEnrollment>,
    vaults: KeySequenceRef<'a, FeeSponsorVault>,
}
impl<'a> NativeGlobalFeeProgramStateRefV1<'a> {
    /// Borrow only actual retained values and caller-funded complete key/row slices.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        program_id: &'a FeeSponsorProgramId,
        fee_asset: &'a AssetDefinitionId,
        asset_keys: &'a [&'a AssetId],
        program_keys: &'a [&'a FeeSponsorProgramId],
        revision_keys: &'a [&'a FeeSponsorProgramRevisionKey],
        enrollment_keys: &'a [&'a FeeSponsorEnrollmentKey],
        vault_keys: &'a [&'a FeeSponsorVaultKey],
        budget_counter_keys: &'a [&'a FeeSponsorBudgetCounterKey],
        sponsor_account_value: &'a AccountValue,
        fee_asset_definition: &'a AssetDefinition,
        source_asset_value: &'a AssetValue,
        program: Option<&'a FeeSponsorProgram>,
        revisions: &'a [&'a FeeSponsorProgramRevision],
        enrollments: &'a [&'a FeeSponsorEnrollment],
        vaults: &'a [&'a FeeSponsorVault],
    ) -> Self {
        Self {
            program_id: FieldRef(program_id),
            fee_asset: FieldRef(fee_asset),
            asset_keys: KeySequenceRef(asset_keys),
            program_keys: KeySequenceRef(program_keys),
            revision_keys: KeySequenceRef(revision_keys),
            enrollment_keys: KeySequenceRef(enrollment_keys),
            vault_keys: KeySequenceRef(vault_keys),
            budget_counter_keys: KeySequenceRef(budget_counter_keys),
            sponsor_account_value: FieldRef(sponsor_account_value),
            fee_asset_definition: FieldRef(fee_asset_definition),
            source_asset_value: FieldRef(source_asset_value),
            program: program.map(FieldRef),
            revisions: KeySequenceRef(revisions),
            enrollments: KeySequenceRef(enrollments),
            vaults: KeySequenceRef(vaults),
        }
    }
}

/// Borrowed exact encoder of `NativeAuthorityOriginalsV1`; allocations stay with the original finite owner.
#[derive(NoritoSerialize, JsonSerialize)]
pub struct NativeAuthorityOriginalsRefV1<'a> {
    request_sha256: [u8; 32],
    selector: FieldRef<'a, NativeAuthorityOriginalsSelectorV1>,
    attestation: FieldRef<'a, SumeragiFinalityAttestation>,
    world_snapshot: FieldRef<'a, WorldStateSnapshotV1>,
    originals: NativeAuthorityOriginalsFamilyRefV1<'a>,
}
impl<'a> NativeAuthorityOriginalsRefV1<'a> {
    /// Borrow private originals and copy only the fixed public request digest.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        request_sha256: &'a [u8; 32],
        selector: &'a NativeAuthorityOriginalsSelectorV1,
        attestation: &'a SumeragiFinalityAttestation,
        world_snapshot: &'a WorldStateSnapshotV1,
        originals: NativeAuthorityOriginalsFamilyRefV1<'a>,
    ) -> Self {
        Self {
            request_sha256: *request_sha256,
            selector: FieldRef(selector),
            attestation: FieldRef(attestation),
            world_snapshot: FieldRef(world_snapshot),
            originals,
        }
    }
}

/// Borrowed selected family; never clones or creates another private value owner.
#[derive(NoritoSerialize, JsonSerialize)]
#[norito(tag = "kind", content = "payload")]
pub enum NativeAuthorityOriginalsFamilyRefV1<'a> {
    /// Borrowed account alias originals.
    AccountAlias(NativeAccountAliasStateRefV1<'a>),
    /// Borrowed Global program/funding originals.
    GlobalFeeProgram(NativeGlobalFeeProgramStateRefV1<'a>),
    /// Borrowed identifier policy and its referenced program originals.
    IdentifierPolicy(NativeIdentifierPolicyStateRefV1<'a>),
}
impl norito::NoritoSchema for NativeAuthorityOriginalsRefV1<'_> {
    fn nominal_name() -> String {
        NativeAuthorityOriginalsV1::nominal_name()
    }
    fn frame_name() -> String {
        NativeAuthorityOriginalsV1::frame_name()
    }
}

struct FieldRef<'a, T: ?Sized>(&'a T);
impl<T: norito::core::SerializePayload + ?Sized> norito::core::SerializePayload
    for FieldRef<'_, T>
{
    fn serialize(&self, out: &mut norito::core::Encoder<'_>) -> Result<(), norito::Error> {
        self.0.serialize(out)
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        self.0.encoded_len_hint()
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        self.0.encoded_len_exact()
    }
}
impl<T: norito::json::JsonSerialize + ?Sized> norito::json::JsonSerialize for FieldRef<'_, T> {
    fn json_serialize(&self, out: &mut String) {
        self.0.json_serialize(out);
    }
    fn json_serialize_to(
        &self,
        out: &mut dyn norito::json::JsonWriteSink,
    ) -> Result<(), norito::json::BoundedJsonError> {
        self.0.json_serialize_to(out)
    }
}
struct KeySequenceRef<'a, T>(&'a [&'a T]);
impl<T: norito::core::SerializePayload> norito::core::SerializePayload for KeySequenceRef<'_, T> {
    fn serialize(&self, out: &mut norito::core::Encoder<'_>) -> Result<(), norito::Error> {
        norito::core::write_element_sequence::<T, _>(out, self.0.iter().copied())
    }
}
impl<T: norito::json::JsonSerialize> norito::json::JsonSerialize for KeySequenceRef<'_, T> {
    fn json_serialize(&self, out: &mut String) {
        out.push('[');
        for (index, value) in self.0.iter().enumerate() {
            if index != 0 {
                out.push(',');
            }
            value.json_serialize(out);
        }
        out.push(']');
    }
    fn json_serialize_to(
        &self,
        out: &mut dyn norito::json::JsonWriteSink,
    ) -> Result<(), norito::json::BoundedJsonError> {
        out.begin_container()?;
        let result = (|| -> Result<(), norito::json::BoundedJsonError> {
            out.push('[')?;
            for (index, value) in self.0.iter().enumerate() {
                if index != 0 {
                    out.push(',')?;
                }
                value.json_serialize_to(out)?;
            }
            out.push(']')?;
            Ok(())
        })();
        out.end_container();
        result?;
        Ok(())
    }
}
struct ByteRef<'a>(&'a [u8]);
impl norito::core::SerializePayload for ByteRef<'_> {
    fn serialize(&self, out: &mut norito::core::Encoder<'_>) -> Result<(), norito::Error> {
        norito::core::SerializePayload::serialize(&self.0, out)
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        self.0.len().checked_add(8)
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        self.0.len().checked_add(8)
    }
}
impl norito::json::JsonSerialize for ByteRef<'_> {
    fn json_serialize(&self, out: &mut String) {
        out.push('[');
        for (index, value) in self.0.iter().enumerate() {
            if index != 0 {
                out.push(',');
            }
            value.json_serialize(out);
        }
        out.push(']');
    }
    fn json_serialize_to(
        &self,
        out: &mut dyn norito::json::JsonWriteSink,
    ) -> Result<(), norito::json::BoundedJsonError> {
        out.begin_container()?;
        let result = (|| -> Result<(), norito::json::BoundedJsonError> {
            out.push('[')?;
            for (index, value) in self.0.iter().enumerate() {
                if index != 0 {
                    out.push(',')?;
                }
                value.json_serialize_to(out)?;
            }
            out.push(']')?;
            Ok(())
        })();
        out.end_container();
        result?;
        Ok(())
    }
}

#[cfg(test)]
#[path = "authority_originals/tests.rs"]
mod tests;

#[cfg(test)]
mod service_depth_tests {
    //! Owning checked service writers keep the caller depth on exact refusals.
    use super::*;
    use crate::service_checked_writer_test_support::{RefusingLeaf, audit, byte_refusal, error};
    use norito::json::{BoundedJsonError, JsonSerialize};

    #[test]
    fn original_authority_key_sequence_keeps_borrowed_manual_leaves_and_refusal_depth() {
        let values = [1_u64, 7];
        let refs = [&values[0], &values[1]];
        let source = KeySequenceRef(&refs);
        audit("[1,7]", |sink| source.json_serialize_to(sink));
        assert!(std::ptr::eq(source.0[0], &values[0]));
        let manual = RefusingLeaf {
            visits: std::cell::Cell::new(0),
        };
        let refs = [&manual];
        let source = KeySequenceRef(&refs);
        byte_refusal(|sink| source.json_serialize_to(sink));
        assert_eq!(manual.visits.get(), 0);
        error(BoundedJsonError::Unsupported, |sink| {
            source.json_serialize_to(sink)
        });
        assert_eq!(manual.visits.get(), 1);
    }
    #[test]
    fn original_authority_byte_sequence_keeps_all_exact_bytes_and_refusal_depth() {
        for values in [&[][..], &[0_u8, 7, 255][..]] {
            let source = ByteRef(values);
            let mut expected = String::new();
            source.json_serialize(&mut expected);
            audit(&expected, |sink| source.json_serialize_to(sink));
            assert_eq!(source.0.as_ptr(), values.as_ptr());
        }
    }
}
