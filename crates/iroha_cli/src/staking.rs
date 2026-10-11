//! `NPoS` staking lifecycle helpers for public lanes.
//! Monetary actions require exact network-bound Norito JSON plans; Core verifies
//! their retained custody, tenure and reward records when the signed action executes.
use crate::{Run, RunContext};
use eyre::{Result, WrapErr, eyre};
use iroha::data_model::{
    id::NetworkId,
    isi::InstructionBox,
    isi::staking::{
        ActivatePublicLaneValidator, BondPublicLaneStake, ClaimPublicLaneRewards,
        ExitPublicLaneValidator, FinalizePublicLaneUnbond, PublicLaneCandidateAuthorization,
        PublicLanePeerBindingAuthorization, RebindPublicLaneValidatorPeer,
        RegisterPublicLaneCandidate, RegisterPublicLaneValidator, SchedulePublicLaneUnbond,
    },
    nexus::{
        PublicLaneMonetaryPlanV1, PublicLaneMonetaryPreconditionV1, PublicLaneMonetaryScopeV1,
        PublicLanePreparationRequestV1, PublicLaneRewardClaimPlanV1,
    },
    prelude::AccountId,
};
use iroha_crypto::{Hash, SignatureOf};
use iroha_model_base::metadata::Metadata;
use iroha_model_base::peer::PeerId;
use iroha_model_base::topology::LaneId;
use std::{
    fs,
    path::{Path, PathBuf},
};

// A claim carries at most 64 record references and 64 exact custody sources.
// Bound bytes and JSON geometry before allocating the typed signed payload.
const MAX_STAKING_PLAN_BYTES: usize = 1024 * 1024;
const STAKING_PLAN_DECODE_LIMITS: norito::DecodeLimits = norito::DecodeLimits::new(
    64,
    MAX_STAKING_PLAN_BYTES,
    8192,
    4 * MAX_STAKING_PLAN_BYTES,
    32,
);
#[derive(clap::Subcommand, Debug)]
pub enum Command {
    /// Observe an exact monetary plan, reported finalized tip and custody reserves before signing
    Prepare(PrepareArgs),
    /// Register a stake-elected validator on a public lane
    Register(RegisterArgs),
    /// Admit a consented validator on a stake-elected lane; fresh global admission requires an epoch key transition
    RegisterCandidate(RegisterCandidateArgs),
    /// Rebind an existing validator to a replacement consensus peer
    Rebind(RebindArgs),
    /// Activate a pending validator once its scheduled activation height is reached
    Activate(ActivateArgs),
    /// Schedule or finalize a validator exit
    Exit(ExitArgs),
    /// Bond additional self stake or delegate stake to a registered validator
    Bond(BondArgs),
    /// Schedule a stake withdrawal after the configured unbonding delay
    ScheduleUnbond(ScheduleUnbondArgs),
    /// Withdraw a scheduled unbond once its time and liability bounds have passed
    FinalizeUnbond(FinalizeUnbondArgs),
    /// Process and pay rewards using an exact bounded claim plan
    ClaimRewards(ClaimRewardsArgs),
}
impl Run for Command {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        match self {
            Command::Prepare(args) => args.run(context),
            Command::Register(args) => args.run(context),
            Command::RegisterCandidate(args) => args.run(context),
            Command::Rebind(args) => args.run(context),
            Command::Activate(args) => args.run(context),
            Command::Exit(args) => args.run(context),
            Command::Bond(args) => args.run(context),
            Command::ScheduleUnbond(args) => args.run(context),
            Command::FinalizeUnbond(args) => args.run(context),
            Command::ClaimRewards(args) => args.run(context),
        }
    }
}
/// Read-only exact staking intent supplied as canonical Norito JSON.
#[derive(clap::Args, Debug)]
pub struct PrepareArgs {
    /// PublicLanePreparationRequestV1 with explicit operation, amount and expiry offset
    #[arg(long, value_name = "PATH")]
    pub request: PathBuf,
}
impl Run for PrepareArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let request: PublicLanePreparationRequestV1 =
            load_staking_json(&self.request, "--request")?;
        let client = iroha::blocking::Client::from_client(context.client_from_config()?)?;
        let observation = client.nexus().prepare_public_lane_plan(&request)?;
        // Preserve every binding and reserve alongside the exact plan. This read
        // does not authenticate the reported tip or authorize a transaction.
        context.print_data(&observation)
    }
}
#[derive(clap::Args, Debug)]
pub struct RegisterArgs {
    /// Lane id to register against
    #[arg(long)]
    pub lane_id: u32,
    /// Validator account identifier (canonical I105 account literal)
    #[arg(long, value_name = "ACCOUNT_ID")]
    pub validator: String,
    /// Peer identity that will participate in consensus for this validator
    #[arg(long, value_name = "PEER_ID")]
    pub peer_id: String,
    /// Optional staking account (defaults to validator)
    #[arg(long, value_name = "ACCOUNT_ID")]
    pub stake_account: Option<String>,
    /// Exact initial self-bond quantity.
    #[arg(long, value_name = "QUANTITY")]
    pub initial_stake: iroha_primitives::numeric::Quantity,
    /// Optional metadata JSON (Norito JSON object)
    #[arg(long, value_name = "PATH")]
    pub metadata: Option<PathBuf>,
    /// Norito JSON PublicLaneMonetaryPlanV1 with exact signed custody and transfer bindings
    #[arg(long, value_name = "PATH")]
    pub monetary_plan: PathBuf,
}
impl Run for RegisterArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let instruction = self.into_instruction(context)?;
        context.finish(vec![InstructionBox::from(instruction)])
    }
}
impl RegisterArgs {
    fn into_instruction<C: RunContext>(self, context: &C) -> Result<RegisterPublicLaneValidator> {
        let lane_id = LaneId::new(self.lane_id);
        let validator = parse_account_id(context, &self.validator, "--validator")?;
        let peer_id = self
            .peer_id
            .parse::<PeerId>()
            .wrap_err("--peer-id must be a valid peer id")?;
        let stake_account = match self.stake_account {
            Some(value) => parse_account_id(context, &value, "--stake-account")?,
            None => validator.clone(),
        };
        eyre::ensure!(
            stake_account == validator,
            "--stake-account must equal --validator"
        );
        let monetary_plan: PublicLaneMonetaryPlanV1 =
            load_staking_json(&self.monetary_plan, "--monetary-plan")?;
        validate_monetary_plan(context, &monetary_plan)?;
        eyre::ensure!(
            monetary_plan.source_asset.account() == &stake_account
                && monetary_plan.amount == self.initial_stake
                && matches!(
                    monetary_plan.precondition,
                    PublicLaneMonetaryPreconditionV1::Registration(_)
                ),
            "--monetary-plan must bind the registration source account, initial stake and registration precondition"
        );
        let metadata = load_metadata(self.metadata.as_ref())?;
        Ok(RegisterPublicLaneValidator {
            lane_id,
            validator,
            peer_id,
            stake_account,
            initial_stake: self.initial_stake,
            metadata,
            monetary_plan,
        })
    }
}
#[derive(clap::Args, Debug)]
pub struct RegisterCandidateArgs {
    /// Validator registration and initial self-bond
    #[command(flatten)]
    pub registration: RegisterArgs,
    /// Canonical network id derived from the target network's genesis header
    #[arg(long, value_name = "NETWORK_ID")]
    pub network_id: NetworkId,
    /// Exact future election boundary authorized by this candidate peer
    #[arg(long, value_name = "HEIGHT")]
    pub activation_height: u64,
    /// Absolute path to an owner-only mode-0600 BLS-normal peer private-key file
    #[arg(long, value_name = "PATH")]
    pub peer_private_key_file: PathBuf,
}
impl Run for RegisterCandidateArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let registration = self.registration.into_instruction(context)?;
        eyre::ensure!(
            self.network_id == context.config().network_id,
            "--network-id must match the configured submission network"
        );
        eyre::ensure!(
            matches!(
                &registration.monetary_plan.precondition,
                PublicLaneMonetaryPreconditionV1::Registration(precondition)
                    if precondition.activation_height == self.activation_height
            ),
            "--activation-height must match --monetary-plan registration precondition"
        );
        let key_pair = crate::operator_key::load_operator_key_pair(&self.peer_private_key_file)
            .wrap_err("failed to load --peer-private-key-file")?;
        eyre::ensure!(
            registration.peer_id.public_key() == key_pair.public_key(),
            "--peer-id does not match --peer-private-key-file"
        );
        let proof_of_possession = iroha_crypto::bls_normal_pop_prove(key_pair.private_key())
            .wrap_err("--peer-private-key-file must contain a BLS-normal consensus key")?;
        let authorization = PublicLaneCandidateAuthorization::new(
            self.network_id,
            registration.clone(),
            self.activation_height,
        );
        let peer_signature = SignatureOf::try_new(key_pair.private_key(), &authorization)
            .wrap_err("failed to sign candidate registration with the peer key")?;
        let instruction: InstructionBox = RegisterPublicLaneCandidate {
            registration,
            activation_height: self.activation_height,
            proof_of_possession,
            peer_signature,
        }
        .into();
        context.finish(vec![instruction])
    }
}
#[derive(clap::Args, Debug)]
pub struct RebindArgs {
    /// Lane id containing the validator
    #[arg(long)]
    pub lane_id: u32,
    /// Validator account identifier (canonical I105 account literal)
    #[arg(long, value_name = "ACCOUNT_ID")]
    pub validator: String,
    /// Replacement peer identity that will participate in consensus for this validator
    #[arg(long, value_name = "PEER_ID")]
    pub peer_id: String,
    /// Genesis-derived network id for replacement-peer consent
    #[arg(long, value_name = "NETWORK_ID")]
    pub network_id: NetworkId,
    /// Absolute owner-only mode-0600 replacement peer key file
    #[arg(long, value_name = "PATH")]
    pub peer_private_key_file: PathBuf,
    /// Stored pending validator activation height bound to the replacement consent
    #[arg(long, value_name = "HEIGHT")]
    pub activation_height: u64,
    /// Stored current peer binding being replaced
    #[arg(long, value_name = "PEER_ID")]
    pub previous_peer_id: PeerId,
}
impl Run for RebindArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let lane_id = LaneId::new(self.lane_id);
        let validator = parse_account_id(context, &self.validator, "--validator")?;
        let peer_id = self
            .peer_id
            .parse::<PeerId>()
            .wrap_err("--peer-id must be a valid peer id")?;
        eyre::ensure!(
            self.network_id == context.config().network_id,
            "--network-id must match the configured submission network"
        );
        let key_pair = crate::operator_key::load_operator_key_pair(&self.peer_private_key_file)
            .wrap_err("failed to load --peer-private-key-file")?;
        eyre::ensure!(
            peer_id.public_key() == key_pair.public_key(),
            "--peer-id does not match --peer-private-key-file"
        );
        let authorization = PublicLanePeerBindingAuthorization::new(
            self.network_id,
            lane_id,
            validator.clone(),
            peer_id.clone(),
            self.activation_height,
            self.previous_peer_id,
        );
        let signature = SignatureOf::try_new(key_pair.private_key(), &authorization)
            .wrap_err("failed to sign validator binding with the replacement peer key")?;
        let instruction =
            RebindPublicLaneValidatorPeer::new(lane_id, validator, peer_id, signature);
        context.finish(vec![InstructionBox::from(instruction)])
    }
}
#[derive(clap::Args, Debug)]
pub struct ActivateArgs {
    /// Lane id containing the pending validator
    #[arg(long)]
    pub lane_id: u32,
    /// Validator account identifier (canonical I105 account literal)
    #[arg(long, value_name = "ACCOUNT_ID")]
    pub validator: String,
}
impl Run for ActivateArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let lane_id = LaneId::new(self.lane_id);
        let validator = parse_account_id(context, &self.validator, "--validator")?;
        let instruction: InstructionBox = ActivatePublicLaneValidator { lane_id, validator }.into();
        context.finish(vec![instruction])
    }
}
#[derive(clap::Args, Debug)]
pub struct ExitArgs {
    /// Lane id containing the validator
    #[arg(long)]
    pub lane_id: u32,
    /// Validator account identifier (canonical I105 account literal)
    #[arg(long, value_name = "ACCOUNT_ID")]
    pub validator: String,
    /// Release timestamp in milliseconds (must not precede current block timestamp)
    #[arg(long, value_name = "MILLIS")]
    pub release_at_ms: u64,
}
impl Run for ExitArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let lane_id = LaneId::new(self.lane_id);
        let validator = parse_account_id(context, &self.validator, "--validator")?;
        let instruction: InstructionBox = ExitPublicLaneValidator {
            lane_id,
            validator,
            release_at_ms: self.release_at_ms,
        }
        .into();
        context.finish(vec![instruction])
    }
}
#[derive(clap::Args, Debug)]
pub struct BondArgs {
    /// Lane id containing the validator
    #[arg(long)]
    pub lane_id: u32,
    /// Target validator account identifier (canonical I105 account literal)
    #[arg(long, value_name = "ACCOUNT_ID")]
    pub validator: String,
    /// Account supplying stake (defaults to the configured transaction authority)
    #[arg(long, value_name = "ACCOUNT_ID")]
    pub staker: Option<String>,
    /// Exact positive stake quantity to lock
    #[arg(long, value_name = "QUANTITY")]
    pub amount: iroha_primitives::numeric::Quantity,
    /// Optional stake-share metadata JSON (Norito JSON object)
    #[arg(long, value_name = "PATH")]
    pub metadata: Option<PathBuf>,
    /// Norito JSON PublicLaneMonetaryPlanV1 with exact signed custody and transfer bindings
    #[arg(long, value_name = "PATH")]
    pub monetary_plan: PathBuf,
}
impl Run for BondArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        eyre::ensure!(!self.amount.is_zero(), "--amount must be positive");
        let validator = parse_account_id(context, &self.validator, "--validator")?;
        let staker = parse_account_or_authority(context, self.staker.as_deref(), "--staker")?;
        let monetary_plan: PublicLaneMonetaryPlanV1 =
            load_staking_json(&self.monetary_plan, "--monetary-plan")?;
        validate_monetary_plan(context, &monetary_plan)?;
        eyre::ensure!(
            monetary_plan.source_asset.account() == &staker
                && monetary_plan.amount == self.amount
                && matches!(
                    monetary_plan.precondition,
                    PublicLaneMonetaryPreconditionV1::Bond(_)
                ),
            "--monetary-plan must bind the staker source account, amount and bond precondition"
        );
        let metadata = load_metadata(self.metadata.as_ref())?;
        let instruction: InstructionBox = BondPublicLaneStake {
            lane_id: LaneId::new(self.lane_id),
            validator,
            staker,
            amount: self.amount,
            metadata,
            monetary_plan,
        }
        .into();
        context.finish(vec![instruction])
    }
}
#[derive(clap::Args, Debug)]
pub struct ScheduleUnbondArgs {
    /// Lane id containing the validator
    #[arg(long)]
    pub lane_id: u32,
    /// Validator whose stake position is being withdrawn
    #[arg(long, value_name = "ACCOUNT_ID")]
    pub validator: String,
    /// Stake owner (defaults to the configured transaction authority)
    #[arg(long, value_name = "ACCOUNT_ID")]
    pub staker: Option<String>,
    /// Unique withdrawal hash; retain it for finalize-unbond
    #[arg(long, value_name = "HASH")]
    pub request_id: Hash,
    /// Exact positive stake quantity to unlock
    #[arg(long, value_name = "QUANTITY")]
    pub amount: iroha_primitives::numeric::Quantity,
    /// Unix timestamp in milliseconds respecting the configured unbonding delay
    #[arg(long, value_name = "MILLIS")]
    pub release_at_ms: u64,
}
impl Run for ScheduleUnbondArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        eyre::ensure!(!self.amount.is_zero(), "--amount must be positive");
        let validator = parse_account_id(context, &self.validator, "--validator")?;
        let staker = parse_account_or_authority(context, self.staker.as_deref(), "--staker")?;
        let instruction: InstructionBox = SchedulePublicLaneUnbond {
            lane_id: LaneId::new(self.lane_id),
            validator,
            staker,
            request_id: self.request_id,
            amount: self.amount,
            release_at_ms: self.release_at_ms,
        }
        .into();
        context.finish(vec![instruction])
    }
}
#[derive(clap::Args, Debug)]
pub struct FinalizeUnbondArgs {
    /// Lane id containing the validator
    #[arg(long)]
    pub lane_id: u32,
    /// Validator whose stake position is being withdrawn
    #[arg(long, value_name = "ACCOUNT_ID")]
    pub validator: String,
    /// Stake owner receiving the withdrawal (defaults to the configured authority)
    #[arg(long, value_name = "ACCOUNT_ID")]
    pub staker: Option<String>,
    /// Exact withdrawal hash previously supplied to schedule-unbond
    #[arg(long, value_name = "HASH")]
    pub request_id: Hash,
    /// Norito JSON PublicLaneMonetaryPlanV1 with exact signed custody and transfer bindings
    #[arg(long, value_name = "PATH")]
    pub monetary_plan: PathBuf,
}
impl Run for FinalizeUnbondArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let validator = parse_account_id(context, &self.validator, "--validator")?;
        let staker = parse_account_or_authority(context, self.staker.as_deref(), "--staker")?;
        let monetary_plan: PublicLaneMonetaryPlanV1 =
            load_staking_json(&self.monetary_plan, "--monetary-plan")?;
        validate_monetary_plan(context, &monetary_plan)?;
        eyre::ensure!(
            monetary_plan.destination_asset.account() == &staker
                && matches!(
                    monetary_plan.precondition,
                    PublicLaneMonetaryPreconditionV1::Unbond(_)
                ),
            "--monetary-plan must bind the withdrawal recipient and unbond precondition"
        );
        // The request commitment covers retained state; Core compares it with
        // --request-id and the actual tenure, release and liability records.
        let instruction: InstructionBox = FinalizePublicLaneUnbond {
            lane_id: LaneId::new(self.lane_id),
            validator,
            staker,
            request_id: self.request_id,
            monetary_plan,
        }
        .into();
        context.finish(vec![instruction])
    }
}
#[derive(clap::Args, Debug)]
pub struct ClaimRewardsArgs {
    /// Lane id whose rewards are being claimed
    #[arg(long)]
    pub lane_id: u32,
    /// Reward recipient (defaults to the configured transaction authority)
    #[arg(long, value_name = "ACCOUNT_ID")]
    pub account: Option<String>,
    /// Norito JSON PublicLaneRewardClaimPlanV1 binding the exact automatic XOR entitlement
    #[arg(long, value_name = "PATH")]
    pub claim_plan: PathBuf,
}
impl Run for ClaimRewardsArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let account = parse_account_or_authority(context, self.account.as_deref(), "--account")?;
        let claim_plan: PublicLaneRewardClaimPlanV1 =
            load_staking_json(&self.claim_plan, "--claim-plan")?;
        validate_plan_network(context, &claim_plan.network_scope, "--claim-plan")?;
        eyre::ensure!(
            claim_plan.has_canonical_shape(&account),
            "--claim-plan must have bounded ordered records and sources, a positive deadline and exact recipient assets"
        );
        let instruction: InstructionBox = ClaimPublicLaneRewards {
            lane_id: LaneId::new(self.lane_id),
            account,
            claim_plan,
        }
        .into();
        context.finish(vec![instruction])
    }
}
/// Decode one exact staking request or monetary plan within fixed resource bounds.
pub(crate) fn load_staking_json<T: norito::json::JsonDeserialize>(
    path: &Path,
    flag: &str,
) -> Result<T> {
    load_bounded_staking_json(path, flag, STAKING_PLAN_DECODE_LIMITS)
}

/// Read committee evidence with its exact largest fixed proof field admitted.
pub(crate) fn load_committee_json(
    path: &Path,
    flag: &str,
) -> Result<iroha::data_model::nexus::ValidatorCommitteeOperationV1> {
    // The adaptive beacon proof's compressed G2 commitment is a 96-byte JSON
    // array. Reward-list limits stay at 64; committee rosters contain at most 31.
    let limits = norito::DecodeLimits::new(
        iroha_crypto::threshold_bls::THRESHOLD_BLS_PUBLIC_KEY_BYTES,
        STAKING_PLAN_DECODE_LIMITS.max_field_bytes(),
        STAKING_PLAN_DECODE_LIMITS.max_total_elements(),
        STAKING_PLAN_DECODE_LIMITS.max_total_allocated_bytes(),
        STAKING_PLAN_DECODE_LIMITS.max_nesting_depth(),
    );
    load_bounded_staking_json(path, flag, limits)
}

fn load_bounded_staking_json<T: norito::json::JsonDeserialize>(
    path: &Path,
    flag: &str,
    limits: norito::DecodeLimits,
) -> Result<T> {
    let mut file = fs::File::open(path)
        .wrap_err_with(|| format!("failed to open {flag} {}", path.display()))?;
    let before = file.metadata().wrap_err("inspect staking plan")?;
    eyre::ensure!(
        before.is_file() && before.len() <= MAX_STAKING_PLAN_BYTES as u64,
        "{flag} must be a regular file within {MAX_STAKING_PLAN_BYTES} bytes"
    );
    let bytes = crate::read_cli_input_bounded(&mut file, MAX_STAKING_PLAN_BYTES, flag)?;
    let after = file.metadata().wrap_err("reinspect staking plan")?;
    eyre::ensure!(
        before.len() == after.len() && after.len() == bytes.len() as u64,
        "{flag} changed while reading"
    );
    norito::json::preflight_slice(
        &bytes,
        norito::json::JsonPreflightLimits::from_decode_limits(MAX_STAKING_PLAN_BYTES, limits),
    )
    .map_err(|error| eyre!("{flag} exceeds JSON resource bounds: {error}"))?;
    norito::with_decode_limits_scope(limits, || norito::json::from_slice(&bytes))
        .wrap_err_with(|| format!("{flag} must contain a valid Norito JSON staking object"))
}
fn validate_plan_network<C: RunContext>(
    context: &C,
    scope: &PublicLaneMonetaryScopeV1,
    flag: &str,
) -> Result<()> {
    eyre::ensure!(
        *scope == PublicLaneMonetaryScopeV1::Network(context.config().network_id),
        "{flag} must bind the configured submission network; Genesis scope is not an ordinary signed action"
    );
    Ok(())
}
fn validate_monetary_plan<C: RunContext>(
    context: &C,
    plan: &PublicLaneMonetaryPlanV1,
) -> Result<()> {
    validate_plan_network(context, &plan.network_scope, "--monetary-plan")?;
    eyre::ensure!(
        plan.has_canonical_shape(),
        "--monetary-plan must have a positive amount and deadline, matching asset definition and scope, and a valid precondition"
    );
    Ok(())
}
fn parse_account_or_authority<C: RunContext>(
    context: &C,
    value: Option<&str>,
    flag: &str,
) -> Result<AccountId> {
    value.map_or_else(
        || Ok(context.config().account.clone()),
        |value| parse_account_id(context, value, flag),
    )
}
fn parse_account_id<C: RunContext>(context: &C, value: &str, flag: &str) -> Result<AccountId> {
    crate::resolve_account_id(context, value)
        .map_err(|err| eyre!("invalid account id passed to {flag}: {err}"))
}
fn load_metadata(path: Option<&PathBuf>) -> Result<Metadata> {
    let Some(path) = path else {
        return Ok(Metadata::default());
    };
    let raw = fs::read_to_string(path)
        .wrap_err_with(|| format!("failed to read metadata from {}", path.display()))?;
    norito::json::from_str(&raw).wrap_err("metadata file is not valid Norito JSON")
}
#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use eyre::Result;
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_i18n::Language;
    use iroha_test_samples::{ALICE_ID, BOB_ID};
    use norito::json::JsonSerialize;
    use std::fmt::Display;
    #[derive(Parser, Debug)]
    #[command(no_binary_name = true)]
    struct Wrapper {
        #[command(subcommand)]
        command: Command,
    }
    struct TestContext {
        cfg: crate::Config,
        submitted: Option<Vec<InstructionBox>>,
        i18n: crate::Localizer,
    }
    impl TestContext {
        fn new() -> Self {
            Self {
                cfg: crate::fallback_config(),
                submitted: None,
                i18n: crate::Localizer::new(crate::Bundle::Cli, Language::English),
            }
        }
    }
    impl RunContext for TestContext {
        fn config(&self) -> &crate::Config {
            &self.cfg
        }
        fn transaction_metadata(&self) -> Option<&Metadata> {
            None
        }
        fn input_instructions(&self) -> bool {
            false
        }
        fn output_instructions(&self) -> bool {
            false
        }
        fn i18n(&self) -> &crate::Localizer {
            &self.i18n
        }
        fn print_data<T>(&mut self, _data: &T) -> Result<()>
        where
            T: JsonSerialize + ?Sized,
        {
            Ok(())
        }
        fn println(&mut self, _data: impl Display) -> Result<()> {
            Ok(())
        }
        fn submit_with_metadata(
            &mut self,
            instructions: impl Into<crate::Executable>,
            _metadata: Metadata,
            _wait_for_confirmation: bool,
        ) -> Result<()> {
            self.submit(instructions)
        }
        fn submit(&mut self, instructions: impl Into<crate::Executable>) -> Result<()> {
            match instructions.into() {
                crate::Executable::Instructions(list) => {
                    self.submitted = Some(list.into_vec());
                    Ok(())
                }
                crate::Executable::ContractCall(_)
                | crate::Executable::Ivm(_)
                | crate::Executable::IvmProved(_)
                | crate::Executable::Batch(_) => {
                    eyre::bail!("unexpected non-instruction executable in staking test context")
                }
            }
        }
    }
    fn parse_command(args: &[&str]) -> clap::error::Result<Command> {
        Wrapper::try_parse_from(args).map(|wrapper| wrapper.command)
    }
    fn alice_literal() -> String {
        ALICE_ID.canonical_i105().expect("canonical I105")
    }
    fn checked_staking_key_fixture() -> KeyPair {
        KeyPair::try_random().expect("generate checked staking fixture key")
    }
    fn plan_file<T: JsonSerialize>(plan: &T) -> tempfile::NamedTempFile {
        let file = tempfile::NamedTempFile::new().unwrap();
        fs::write(file.path(), norito::json::to_json(plan).unwrap()).unwrap();
        file
    }
    fn plan_asset(account: AccountId) -> iroha::data_model::asset::AssetId {
        let definition = iroha::data_model::parameter::system::SumeragiNposParameters::default()
            .xor_asset_definition_id;
        iroha::data_model::asset::AssetId::of(definition, account)
    }
    fn registration_plan(amount: &str, activation_height: u64) -> PublicLaneMonetaryPlanV1 {
        PublicLaneMonetaryPlanV1 {
            network_scope: PublicLaneMonetaryScopeV1::Network(crate::fallback_config().network_id),
            valid_until_height: 3600,
            source_asset: plan_asset(ALICE_ID.clone()),
            destination_asset: plan_asset(BOB_ID.clone()),
            amount: amount.parse().unwrap(),
            precondition: PublicLaneMonetaryPreconditionV1::Registration(
                iroha::data_model::nexus::PublicLaneMonetaryRegistrationV1 { activation_height },
            ),
        }
    }
    fn bond_plan(staker: AccountId, amount: &str) -> PublicLaneMonetaryPlanV1 {
        let mut plan = registration_plan(amount, 1);
        plan.source_asset = plan_asset(staker);
        plan.precondition = PublicLaneMonetaryPreconditionV1::Bond(
            iroha::data_model::nexus::PublicLaneMonetaryBondV1 {
                activation_height: 1,
                peer_id: valid_peer_id_literal().parse().unwrap(),
            },
        );
        plan
    }
    fn unbond_plan(staker: AccountId, request_id: Hash) -> PublicLaneMonetaryPlanV1 {
        let request = iroha::data_model::nexus::PublicLaneUnbonding {
            request_id,
            amount: 1_u64.into(),
            release_at_ms: 1000,
            slashable_through_height: 1,
            liability_release_height: 2,
        };
        let mut plan = registration_plan("1", 1);
        plan.source_asset = plan_asset(BOB_ID.clone());
        plan.destination_asset = plan_asset(staker);
        plan.precondition = PublicLaneMonetaryPreconditionV1::Unbond(
            iroha::data_model::nexus::PublicLaneMonetaryUnbondV1 {
                activation_height: 1,
                request_hash: iroha::data_model::nexus::public_lane_unbonding_commitment(&request)
                    .unwrap(),
            },
        );
        plan
    }
    fn reward_claim_plan(recipient: AccountId, _lane_id: LaneId) -> PublicLaneRewardClaimPlanV1 {
        PublicLaneRewardClaimPlanV1 {
            network_scope: PublicLaneMonetaryScopeV1::Network(crate::fallback_config().network_id),
            valid_until_height: 3600,
            fee_claim: iroha::data_model::nexus::PublicLaneFeeRewardClaimV1 {
                lifecycle_seal: [1; 32],
                beneficiary_id: recipient.clone(),
                beneficiary_revision: 0,
                source_asset: plan_asset(BOB_ID.clone()),
                destination_asset: plan_asset(recipient),
                amount: 1_u64.into(),
                expected_claim_sequence: 0,
            },
        }
    }
    #[test]
    fn staking_fixture_uses_checked_default_key_generation() {
        let key_pair = checked_staking_key_fixture();
        let actual = key_pair
            .public_key()
            .try_algorithm()
            .expect("staking fixture key advertises a valid algorithm");
        assert_eq!(actual, Algorithm::default());
    }
    fn valid_peer_id_literal() -> String {
        PeerId::from(checked_staking_key_fixture().public_key().clone()).to_string()
    }
    #[cfg(unix)]
    #[test]
    fn register_candidate_signs_exact_registration_and_network() {
        let key_pair = KeyPair::try_from_seed(vec![0x93; 32], Algorithm::BlsNormal)
            .expect("candidate BLS key");
        let key_file = tempfile::NamedTempFile::new().expect("private key file");
        fs::write(
            key_file.path(),
            iroha_crypto::ExposedPrivateKey(key_pair.private_key().clone()).to_string(),
        )
        .expect("write runtime key");
        let peer_id = PeerId::new(key_pair.public_key().clone());
        let network_id = NetworkId::from_genesis_hash(
            iroha_crypto::HashOf::from_untyped_unchecked(Hash::new(b"staking-cli-network")),
        );
        let mut plan = registration_plan("25000.000000001", 3601);
        plan.network_scope = PublicLaneMonetaryScopeV1::Network(network_id);
        let file = plan_file(&plan);
        let command = parse_command(&[
            "register-candidate",
            "--monetary-plan",
            file.path().to_str().unwrap(),
            "--lane-id",
            "0",
            "--validator",
            &alice_literal(),
            "--peer-id",
            &peer_id.to_string(),
            "--initial-stake",
            "25000.000000001",
            "--activation-height",
            "3601",
            "--network-id",
            &network_id.to_string(),
            "--peer-private-key-file",
            key_file.path().to_str().expect("key path"),
        ])
        .expect("candidate command should parse");
        let mut context = TestContext::new();
        context.cfg.network_id = network_id;
        command.run(&mut context).expect("candidate should succeed");
        let submitted = context.submitted.expect("submitted candidate");
        assert_eq!(submitted.len(), 1);
        let instruction = submitted[0]
            .as_any()
            .downcast_ref::<RegisterPublicLaneCandidate>()
            .expect("candidate instruction");
        let expected_registration = RegisterPublicLaneValidator {
            lane_id: LaneId::SINGLE,
            validator: ALICE_ID.clone(),
            peer_id,
            stake_account: ALICE_ID.clone(),
            initial_stake: "25000.000000001".parse().expect("exact amount"),
            metadata: Metadata::default(),
            monetary_plan: plan,
        };
        assert_eq!(instruction.registration, expected_registration);
        assert_eq!(instruction.activation_height, 3601);
        iroha_crypto::bls_normal_pop_verify(
            key_pair.public_key(),
            &instruction.proof_of_possession,
        )
        .expect("valid peer proof of possession");
        instruction
            .peer_signature
            .verify(
                key_pair.public_key(),
                &PublicLaneCandidateAuthorization::new(
                    network_id,
                    expected_registration.clone(),
                    3601,
                ),
            )
            .expect("signature binds the entire registration and network");
        let other_network = NetworkId::from_genesis_hash(
            iroha_crypto::HashOf::from_untyped_unchecked(Hash::new(b"other-staking-network")),
        );
        assert!(
            instruction
                .peer_signature
                .verify(
                    key_pair.public_key(),
                    &PublicLaneCandidateAuthorization::new(
                        other_network,
                        expected_registration,
                        3601
                    ),
                )
                .is_err()
        );
    }
    #[cfg(unix)]
    #[test]
    fn register_candidate_rejects_wrong_peer_or_non_consensus_key() {
        let key_pair = checked_staking_key_fixture();
        let key_file = tempfile::NamedTempFile::new().expect("private key file");
        fs::write(
            key_file.path(),
            iroha_crypto::ExposedPrivateKey(key_pair.private_key().clone()).to_string(),
        )
        .expect("write runtime key");
        let network_id = NetworkId::from_genesis_hash(
            iroha_crypto::HashOf::from_untyped_unchecked(Hash::new(b"staking-cli-network")),
        );
        let mut plan = registration_plan("1000", 3601);
        plan.network_scope = PublicLaneMonetaryScopeV1::Network(network_id);
        let file = plan_file(&plan);
        for (peer_id, expected_error) in [
            (
                valid_peer_id_literal(),
                "--peer-id does not match --peer-private-key-file",
            ),
            (
                PeerId::new(key_pair.public_key().clone()).to_string(),
                "--peer-private-key-file must contain a BLS-normal consensus key",
            ),
        ] {
            let args = RegisterCandidateArgs {
                registration: RegisterArgs {
                    lane_id: 0,
                    validator: alice_literal(),
                    peer_id,
                    stake_account: None,
                    initial_stake: 1_000_u64.into(),
                    metadata: None,
                    monetary_plan: file.path().to_path_buf(),
                },
                network_id: NetworkId::from_genesis_hash(
                    iroha_crypto::HashOf::from_untyped_unchecked(Hash::new(b"staking-cli-network")),
                ),
                activation_height: 3601,
                peer_private_key_file: key_file.path().to_path_buf(),
            };
            let mut context = TestContext::new();
            context.cfg.network_id = network_id;
            let error = args.run(&mut context).expect_err("wrong key must fail");
            assert!(error.to_string().contains(expected_error));
            assert!(context.submitted.is_none());
        }
    }
    #[test]
    fn register_candidate_requires_network_and_private_key_file() {
        let error = parse_command(&[
            "register-candidate",
            "--lane-id",
            "0",
            "--validator",
            &alice_literal(),
            "--peer-id",
            &valid_peer_id_literal(),
            "--initial-stake",
            "25000",
        ])
        .expect_err("candidate signing inputs are required");
        assert_eq!(
            error.kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
        assert!(error.to_string().contains("--network-id"));
        assert!(error.to_string().contains("--peer-private-key-file"));
        assert!(error.to_string().contains("--activation-height"));
    }
    #[test]
    fn bond_defaults_to_signer_and_preserves_exact_quantity() {
        let plan = bond_plan(
            crate::fallback_config().account,
            "9007199254740993.000000001",
        );
        let file = plan_file(&plan);
        let command = parse_command(&[
            "bond",
            "--monetary-plan",
            file.path().to_str().unwrap(),
            "--lane-id",
            "0",
            "--validator",
            &alice_literal(),
            "--amount",
            "9007199254740993.000000001",
        ])
        .expect("bond command should parse");
        let mut context = TestContext::new();
        let expected: InstructionBox = BondPublicLaneStake {
            lane_id: LaneId::SINGLE,
            validator: ALICE_ID.clone(),
            staker: context.cfg.account.clone(),
            monetary_plan: plan,
            amount: "9007199254740993.000000001".parse().expect("exact amount"),
            metadata: Metadata::default(),
        }
        .into();
        command.run(&mut context).expect("bond should succeed");
        assert_eq!(context.submitted, Some(vec![expected]));
    }
    #[test]
    fn bond_preserves_explicit_staker_and_metadata() {
        let delegator = BOB_ID.canonical_i105().expect("canonical delegator I105");
        let metadata_file = tempfile::NamedTempFile::new().expect("metadata file");
        fs::write(metadata_file.path(), r#"{"purpose":"delegation"}"#).expect("write metadata");
        let plan = bond_plan(BOB_ID.clone(), "0.125");
        let file = plan_file(&plan);
        let command = parse_command(&[
            "bond",
            "--monetary-plan",
            file.path().to_str().unwrap(),
            "--lane-id",
            "7",
            "--validator",
            &alice_literal(),
            "--staker",
            &delegator,
            "--amount",
            "0.125",
            "--metadata",
            metadata_file.path().to_str().expect("metadata path"),
        ])
        .expect("delegation command should parse");
        let mut context = TestContext::new();
        let expected: InstructionBox = BondPublicLaneStake {
            lane_id: LaneId::new(7),
            validator: ALICE_ID.clone(),
            staker: BOB_ID.clone(),
            monetary_plan: plan,
            amount: "0.125".parse().expect("exact amount"),
            metadata: norito::json::from_str(r#"{"purpose":"delegation"}"#)
                .expect("expected metadata"),
        }
        .into();
        command
            .run(&mut context)
            .expect("delegation should succeed");
        assert_eq!(context.submitted, Some(vec![expected]));
    }
    #[test]
    fn schedule_unbond_preserves_request_amount_and_release() {
        let request_id = Hash::new(b"staking-cli-unbond");
        let command = parse_command(&[
            "schedule-unbond",
            "--lane-id",
            "3",
            "--validator",
            &alice_literal(),
            "--staker",
            &alice_literal(),
            "--request-id",
            &request_id.to_string(),
            "--amount",
            "0.000000001",
            "--release-at-ms",
            "2000000000000",
        ])
        .expect("schedule-unbond command should parse");
        let mut context = TestContext::new();
        let expected: InstructionBox = SchedulePublicLaneUnbond {
            lane_id: LaneId::new(3),
            validator: ALICE_ID.clone(),
            staker: ALICE_ID.clone(),
            request_id,
            amount: "0.000000001".parse().expect("exact amount"),
            release_at_ms: 2_000_000_000_000,
        }
        .into();
        command.run(&mut context).expect("unbond should succeed");
        assert_eq!(context.submitted, Some(vec![expected]));
    }
    #[test]
    fn finalize_unbond_defaults_to_signer_and_preserves_request() {
        let request_id = Hash::new(b"staking-cli-unbond");
        let plan = unbond_plan(crate::fallback_config().account, request_id);
        let file = plan_file(&plan);
        let command = parse_command(&[
            "finalize-unbond",
            "--monetary-plan",
            file.path().to_str().unwrap(),
            "--lane-id",
            "3",
            "--validator",
            &alice_literal(),
            "--request-id",
            &request_id.to_string(),
        ])
        .expect("finalize-unbond command should parse");
        let mut context = TestContext::new();
        let expected: InstructionBox = FinalizePublicLaneUnbond {
            lane_id: LaneId::new(3),
            validator: ALICE_ID.clone(),
            staker: context.cfg.account.clone(),
            request_id,
            monetary_plan: plan,
        }
        .into();
        command.run(&mut context).expect("finalize should succeed");
        assert_eq!(context.submitted, Some(vec![expected]));
    }
    #[test]
    fn claim_rewards_defaults_to_signer_and_preserves_bounded_plan() {
        let plan = reward_claim_plan(crate::fallback_config().account, LaneId::SINGLE);
        let file = plan_file(&plan);
        let command = parse_command(&[
            "claim-rewards",
            "--lane-id",
            "0",
            "--claim-plan",
            file.path().to_str().unwrap(),
        ])
        .expect("claim-rewards command should parse");
        let mut context = TestContext::new();
        let expected: InstructionBox = ClaimPublicLaneRewards {
            lane_id: LaneId::SINGLE,
            account: context.cfg.account.clone(),
            claim_plan: plan,
        }
        .into();
        command.run(&mut context).expect("claim should succeed");
        assert_eq!(context.submitted, Some(vec![expected]));
    }
    #[test]
    fn claim_rewards_preserves_exact_automatic_entitlement_consent() {
        let mut plan = reward_claim_plan(ALICE_ID.clone(), LaneId::new(4));
        plan.fee_claim = iroha::data_model::nexus::PublicLaneFeeRewardClaimV1 {
            lifecycle_seal: [1; 32],
            beneficiary_id: ALICE_ID.clone(),
            beneficiary_revision: 2,
            source_asset: plan_asset(BOB_ID.clone()),
            destination_asset: plan_asset(ALICE_ID.clone()),
            amount: 3_u64.into(),
            expected_claim_sequence: 4,
        };
        let file = plan_file(&plan);
        let command = parse_command(&[
            "claim-rewards",
            "--lane-id",
            "4",
            "--account",
            &alice_literal(),
            "--claim-plan",
            file.path().to_str().unwrap(),
        ])
        .expect("bounded claim should parse");
        let mut context = TestContext::new();
        let expected: InstructionBox = ClaimPublicLaneRewards {
            lane_id: LaneId::new(4),
            account: ALICE_ID.clone(),
            claim_plan: plan,
        }
        .into();
        command.run(&mut context).expect("claim should succeed");
        assert_eq!(context.submitted, Some(vec![expected]));
    }
    #[test]
    fn manual_reward_publication_is_not_a_command() {
        let error = parse_command(&["record-rewards", "--file", "rewards.json"])
            .expect_err("automatic accrual has no public payout-list command");
        assert_eq!(error.kind(), clap::error::ErrorKind::InvalidSubcommand);
    }
    #[test]
    fn stake_commands_reject_zero_before_submission() {
        for name in ["bond", "schedule-unbond"] {
            let account = alice_literal();
            let request = Hash::new(b"staking-cli-zero").to_string();
            let mut args = vec![
                name,
                "--lane-id",
                "0",
                "--validator",
                &account,
                "--amount",
                "0",
            ];
            if name == "bond" {
                args.extend(["--monetary-plan", "/unused/plan.json"]);
            }
            if name == "schedule-unbond" {
                args.extend(["--request-id", &request, "--release-at-ms", "2000000000000"]);
            }
            let command = parse_command(&args).expect("zero quantity parses");
            let mut context = TestContext::new();
            let error = command.run(&mut context).expect_err("zero must fail");
            assert!(error.to_string().contains("--amount must be positive"));
            assert!(context.submitted.is_none());
        }
    }
    #[test]
    fn bond_rejects_invalid_quantities_during_parsing() {
        for amount in ["NaN", "-1", "1e3"] {
            let error = parse_command(&[
                "bond",
                "--monetary-plan",
                "/unused/plan.json",
                "--lane-id",
                "0",
                "--validator",
                &alice_literal(),
                &format!("--amount={amount}"),
            ])
            .expect_err("invalid quantity must fail");
            assert_eq!(error.kind(), clap::error::ErrorKind::ValueValidation);
        }
    }
    #[test]
    fn unbond_commands_require_valid_request_hashes() {
        for name in ["schedule-unbond", "finalize-unbond"] {
            let account = alice_literal();
            let mut args = vec![name, "--lane-id", "0", "--validator", &account];
            if name == "finalize-unbond" {
                args.extend(["--monetary-plan", "/unused/plan.json"]);
            }
            if name == "schedule-unbond" {
                args.extend(["--amount", "1", "--release-at-ms", "2000000000000"]);
            }
            let error = parse_command(&args).expect_err("request id is mandatory");
            assert_eq!(
                error.kind(),
                clap::error::ErrorKind::MissingRequiredArgument
            );
            assert!(error.to_string().contains("--request-id"));
            args.extend(["--request-id", "not-a-hash"]);
            let error = parse_command(&args).expect_err("invalid request id must fail");
            assert_eq!(error.kind(), clap::error::ErrorKind::ValueValidation);
        }
    }
    #[test]
    fn parse_account_or_authority_rejects_invalid_explicit_account() {
        let context = TestContext::new();
        let error = parse_account_or_authority(&context, Some("not-an-account"), "--staker")
            .expect_err("invalid account must fail");
        assert!(
            error
                .to_string()
                .contains("invalid account id passed to --staker")
        );
    }
    #[test]
    fn register_requires_peer_id_flag() {
        let err = parse_command(&[
            "register",
            "--lane-id",
            "1",
            "--validator",
            &alice_literal(),
            "--initial-stake",
            "10",
        ])
        .expect_err("register without --peer-id should fail");
        assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
        assert!(err.to_string().contains("--peer-id"));
    }
    #[test]
    fn rebind_requires_peer_id_flag() {
        let err = parse_command(&["rebind", "--lane-id", "1", "--validator", &alice_literal()])
            .expect_err("rebind without --peer-id should fail");
        assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
        assert!(err.to_string().contains("--peer-id"));
    }
    #[test]
    fn rebind_requires_validator_flag() {
        let err = parse_command(&[
            "rebind",
            "--lane-id",
            "1",
            "--peer-id",
            &valid_peer_id_literal(),
        ])
        .expect_err("rebind without --validator should fail");
        assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
        assert!(err.to_string().contains("--validator"));
    }
    #[cfg(unix)]
    #[test]
    fn rebind_signs_replacement_peer_consent() {
        let key_pair = KeyPair::try_from_seed(vec![0x94; 32], Algorithm::BlsNormal)
            .expect("replacement peer key");
        let key_file = tempfile::NamedTempFile::new().expect("private key file");
        fs::write(
            key_file.path(),
            iroha_crypto::ExposedPrivateKey(key_pair.private_key().clone()).to_string(),
        )
        .expect("write runtime key");
        let peer_id = PeerId::new(key_pair.public_key().clone());
        let previous_peer_id: PeerId = valid_peer_id_literal().parse().expect("previous peer");
        let network_id = NetworkId::from_genesis_hash(
            iroha_crypto::HashOf::from_untyped_unchecked(Hash::new(b"staking-cli-network")),
        );
        let command = parse_command(&[
            "rebind",
            "--lane-id",
            "3",
            "--validator",
            &alice_literal(),
            "--peer-id",
            &peer_id.to_string(),
            "--activation-height",
            "3601",
            "--previous-peer-id",
            &previous_peer_id.to_string(),
            "--network-id",
            &network_id.to_string(),
            "--peer-private-key-file",
            key_file.path().to_str().expect("key path"),
        ])
        .expect("signed rebind should parse");
        let mut context = TestContext::new();
        context.cfg.network_id = network_id;
        command
            .run(&mut context)
            .expect("signed rebind should succeed");
        let submitted = context.submitted.expect("rebind submitted");
        assert_eq!(submitted.len(), 1);
        let instruction = submitted[0]
            .as_any()
            .downcast_ref::<RebindPublicLaneValidatorPeer>()
            .expect("rebind instruction");
        let expected = PublicLanePeerBindingAuthorization::new(
            network_id,
            LaneId::new(3),
            ALICE_ID.clone(),
            peer_id,
            3601,
            previous_peer_id,
        );
        instruction
            .peer_signature
            .verify(key_pair.public_key(), &expected)
            .expect("consent binds exact network, lane, validator, and peer");
    }
    #[test]
    fn rebind_requires_replacement_peer_consent() {
        let network_id = NetworkId::from_genesis_hash(
            iroha_crypto::HashOf::from_untyped_unchecked(Hash::new(b"staking-cli-network")),
        )
        .to_string();
        for (flag, value, required) in [
            (
                "--network-id",
                network_id.as_str(),
                "--peer-private-key-file",
            ),
            (
                "--peer-private-key-file",
                "/runtime/peer.key",
                "--network-id",
            ),
        ] {
            let error = parse_command(&[
                "rebind",
                "--lane-id",
                "0",
                "--validator",
                &alice_literal(),
                "--peer-id",
                &valid_peer_id_literal(),
                flag,
                value,
            ])
            .expect_err("incomplete peer consent input must fail");
            assert_eq!(
                error.kind(),
                clap::error::ErrorKind::MissingRequiredArgument
            );
            assert!(error.to_string().contains(required));
        }
    }
    #[test]
    fn register_submits_instruction_with_valid_peer_id() {
        let plan = registration_plan("10", 1);
        let file = plan_file(&plan);
        let command = parse_command(&[
            "register",
            "--monetary-plan",
            file.path().to_str().unwrap(),
            "--lane-id",
            "1",
            "--validator",
            &alice_literal(),
            "--peer-id",
            &valid_peer_id_literal(),
            "--initial-stake",
            "10",
        ])
        .expect("register command should parse");
        let mut context = TestContext::new();
        command.run(&mut context).expect("register should succeed");
        assert_eq!(
            context.submitted.as_ref().map(Vec::len),
            Some(1),
            "register should submit exactly one instruction"
        );
    }
    #[test]
    fn rebind_requires_peer_consent_when_all_flags_are_absent() {
        let error = parse_command(&[
            "rebind",
            "--lane-id",
            "1",
            "--validator",
            &alice_literal(),
            "--peer-id",
            &valid_peer_id_literal(),
        ])
        .expect_err("rebind without peer consent must fail");
        assert_eq!(
            error.kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
        for flag in [
            "--network-id",
            "--peer-private-key-file",
            "--activation-height",
            "--previous-peer-id",
        ] {
            assert!(error.to_string().contains(flag));
        }
    }
    #[test]
    fn register_rejects_invalid_peer_id_during_run() {
        let args = RegisterArgs {
            lane_id: 1,
            validator: alice_literal(),
            peer_id: "not-a-peer-id".to_owned(),
            stake_account: None,
            initial_stake: 10_u64.into(),
            metadata: None,
            monetary_plan: PathBuf::from("/unused/plan.json"),
        };
        let mut context = TestContext::new();
        let err = args
            .run(&mut context)
            .expect_err("invalid peer id should fail");
        assert!(
            err.to_string()
                .contains("--peer-id must be a valid peer id")
        );
        assert!(context.submitted.is_none());
    }
    #[test]
    fn rebind_rejects_invalid_peer_id_during_run() {
        let args = RebindArgs {
            lane_id: 1,
            validator: alice_literal(),
            peer_id: "not-a-peer-id".to_owned(),
            network_id: crate::fallback_config().network_id,
            peer_private_key_file: PathBuf::from("/unused/peer.key"),
            activation_height: 1,
            previous_peer_id: valid_peer_id_literal().parse().expect("previous peer"),
        };
        let mut context = TestContext::new();
        let err = args
            .run(&mut context)
            .expect_err("invalid peer id should fail");
        assert!(
            err.to_string()
                .contains("--peer-id must be a valid peer id")
        );
        assert!(context.submitted.is_none());
    }
    #[test]
    fn rebind_rejects_mismatched_submission_network() {
        let args = RebindArgs {
            lane_id: 1,
            validator: alice_literal(),
            peer_id: valid_peer_id_literal(),
            network_id: NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(
                Hash::new(b"other-network"),
            )),
            peer_private_key_file: PathBuf::from("/unused/peer.key"),
            activation_height: 1,
            previous_peer_id: valid_peer_id_literal().parse().expect("previous peer"),
        };
        let mut context = TestContext::new();
        let error = args.run(&mut context).expect_err("wrong network must fail");
        assert!(
            error
                .to_string()
                .contains("--network-id must match the configured submission network")
        );
        assert!(context.submitted.is_none());
    }
    #[test]
    fn monetary_commands_require_explicit_plan_files() {
        let validator = alice_literal();
        let peer = valid_peer_id_literal();
        let network = crate::fallback_config().network_id.to_string();
        let request = Hash::new(b"required plan withdrawal").to_string();
        for args in [
            vec![
                "register",
                "--lane-id",
                "0",
                "--validator",
                &validator,
                "--peer-id",
                &peer,
                "--initial-stake",
                "1",
            ],
            vec![
                "register-candidate",
                "--lane-id",
                "0",
                "--validator",
                &validator,
                "--peer-id",
                &peer,
                "--initial-stake",
                "1",
                "--network-id",
                &network,
                "--activation-height",
                "3601",
                "--peer-private-key-file",
                "/unused/key",
            ],
            vec![
                "bond",
                "--lane-id",
                "0",
                "--validator",
                &validator,
                "--amount",
                "1",
            ],
            vec![
                "finalize-unbond",
                "--lane-id",
                "0",
                "--validator",
                &validator,
                "--request-id",
                &request,
            ],
            vec!["claim-rewards", "--lane-id", "0"],
        ] {
            let flag = if args[0] == "claim-rewards" {
                "--claim-plan"
            } else {
                "--monetary-plan"
            };
            let error = parse_command(&args).expect_err("a signed plan file is mandatory");
            assert_eq!(
                error.kind(),
                clap::error::ErrorKind::MissingRequiredArgument
            );
            assert!(error.to_string().contains(flag));
        }
        let error = parse_command(&[
            "claim-rewards",
            "--lane-id",
            "0",
            "--claim-plan",
            "/unused/plan",
            "--upto-epoch",
            "12",
        ])
        .expect_err("retired epoch bound cannot replace exact record authorization");
        assert_eq!(error.kind(), clap::error::ErrorKind::UnknownArgument);
    }

    #[test]
    fn staking_plan_reader_rejects_oversize_malformed_and_deep_json() {
        let file = tempfile::NamedTempFile::new().unwrap();
        file.as_file()
            .set_len(MAX_STAKING_PLAN_BYTES as u64 + 1)
            .unwrap();
        let error = load_staking_json::<PublicLaneMonetaryPlanV1>(file.path(), "--monetary-plan")
            .unwrap_err();
        assert!(error.to_string().contains("regular file within"));
        for bytes in [
            Vec::new(),
            b"not-json".to_vec(),
            format!("{}0{}", "[".repeat(40), "]".repeat(40)).into_bytes(),
        ] {
            fs::write(file.path(), bytes).unwrap();
            assert!(
                load_staking_json::<PublicLaneMonetaryPlanV1>(file.path(), "--monetary-plan")
                    .is_err()
            );
        }
        let directory = tempfile::tempdir().unwrap();
        assert!(
            load_staking_json::<PublicLaneMonetaryPlanV1>(directory.path(), "--monetary-plan")
                .is_err()
        );
    }

    #[test]
    fn staking_plan_reader_rejects_unknown_fields() {
        let mut monetary =
            norito::json::to_value(&registration_plan("1", 1)).expect("monetary plan JSON");
        monetary
            .as_object_mut()
            .expect("monetary plan object")
            .insert("retired_transfer".into(), norito::json::Value::Null);
        let file = plan_file(&monetary);
        assert!(
            load_staking_json::<PublicLaneMonetaryPlanV1>(file.path(), "--monetary-plan").is_err()
        );

        let mut claim =
            norito::json::to_value(&reward_claim_plan(ALICE_ID.clone(), LaneId::SINGLE))
                .expect("claim plan JSON");
        claim
            .as_object_mut()
            .expect("claim plan object")
            .insert("upto_epoch".into(), norito::json::Value::Null);
        let file = plan_file(&claim);
        assert!(
            load_staking_json::<PublicLaneRewardClaimPlanV1>(file.path(), "--claim-plan").is_err()
        );
    }

    #[test]
    fn claim_rejects_missing_explicit_fee_reward_consent_before_submission() {
        let mut plan =
            norito::json::to_value(&reward_claim_plan(ALICE_ID.clone(), LaneId::SINGLE)).unwrap();
        plan.as_object_mut().unwrap().remove("fee_claim");
        let file = plan_file(&plan);
        let mut context = TestContext::new();
        let args = ClaimRewardsArgs {
            lane_id: 0,
            account: Some(alice_literal()),
            claim_plan: file.path().to_path_buf(),
        };
        assert!(args.run(&mut context).is_err());
        assert!(context.submitted.is_none());
    }

    #[test]
    fn monetary_plan_rejects_wrong_network_and_invalid_shape() {
        let context = TestContext::new();
        let valid = registration_plan("1", 1);
        validate_monetary_plan(&context, &valid).unwrap();
        for invalid in [
            PublicLaneMonetaryPlanV1 {
                network_scope: PublicLaneMonetaryScopeV1::Genesis,
                ..valid.clone()
            },
            PublicLaneMonetaryPlanV1 {
                network_scope: PublicLaneMonetaryScopeV1::Network(NetworkId::from_genesis_hash(
                    iroha_crypto::HashOf::from_untyped_unchecked(Hash::new(
                        b"foreign plan network",
                    )),
                )),
                ..valid.clone()
            },
            PublicLaneMonetaryPlanV1 {
                valid_until_height: 0,
                ..valid.clone()
            },
            PublicLaneMonetaryPlanV1 {
                amount: iroha_primitives::numeric::Quantity::zero(),
                ..valid.clone()
            },
            PublicLaneMonetaryPlanV1 {
                precondition: PublicLaneMonetaryPreconditionV1::Bond(
                    iroha::data_model::nexus::PublicLaneMonetaryBondV1 {
                        activation_height: 0,
                        peer_id: valid_peer_id_literal().parse().expect("peer id"),
                    },
                ),
                ..valid.clone()
            },
            PublicLaneMonetaryPlanV1 {
                precondition: PublicLaneMonetaryPreconditionV1::Registration(
                    iroha::data_model::nexus::PublicLaneMonetaryRegistrationV1 {
                        activation_height: 0,
                    },
                ),
                ..valid
            },
        ] {
            assert!(validate_monetary_plan(&context, &invalid).is_err());
        }
    }

    #[test]
    fn monetary_commands_reject_argument_and_operation_mismatches_before_submission() {
        let mut wrong_registration_source = registration_plan("1", 1);
        wrong_registration_source.source_asset = plan_asset(BOB_ID.clone());
        for plan in [
            wrong_registration_source,
            registration_plan("2", 1),
            bond_plan(ALICE_ID.clone(), "1"),
        ] {
            let file = plan_file(&plan);
            let mut context = TestContext::new();
            let args = RegisterArgs {
                lane_id: 0,
                validator: alice_literal(),
                peer_id: valid_peer_id_literal(),
                stake_account: None,
                initial_stake: 1_u64.into(),
                metadata: None,
                monetary_plan: file.path().to_path_buf(),
            };
            assert!(
                args.run(&mut context)
                    .unwrap_err()
                    .to_string()
                    .contains("registration source account")
            );
            assert!(context.submitted.is_none());
        }
        for plan in [
            bond_plan(BOB_ID.clone(), "1"),
            bond_plan(ALICE_ID.clone(), "2"),
            registration_plan("1", 1),
        ] {
            let file = plan_file(&plan);
            let mut context = TestContext::new();
            let args = BondArgs {
                lane_id: 0,
                validator: alice_literal(),
                staker: Some(alice_literal()),
                amount: 1_u64.into(),
                metadata: None,
                monetary_plan: file.path().to_path_buf(),
            };
            assert!(
                args.run(&mut context)
                    .unwrap_err()
                    .to_string()
                    .contains("staker source account")
            );
            assert!(context.submitted.is_none());
        }
        let request_id = Hash::new(b"invalid unbond plan binding");
        for plan in [
            unbond_plan(BOB_ID.clone(), request_id),
            registration_plan("1", 1),
        ] {
            let file = plan_file(&plan);
            let mut context = TestContext::new();
            let args = FinalizeUnbondArgs {
                lane_id: 0,
                validator: alice_literal(),
                staker: Some(alice_literal()),
                request_id,
                monetary_plan: file.path().to_path_buf(),
            };
            assert!(
                args.run(&mut context)
                    .unwrap_err()
                    .to_string()
                    .contains("withdrawal recipient")
            );
            assert!(context.submitted.is_none());
        }
    }

    #[test]
    fn candidate_rejects_plan_activation_and_consent_network_mismatches_before_key_read() {
        for wrong_activation in [false, true] {
            let plan = registration_plan("1", 3601);
            let file = plan_file(&plan);
            let mut context = TestContext::new();
            let network_id = if wrong_activation {
                context.cfg.network_id
            } else {
                NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(
                    Hash::new(b"foreign candidate consent"),
                ))
            };
            let args = RegisterCandidateArgs {
                registration: RegisterArgs {
                    lane_id: 0,
                    validator: alice_literal(),
                    peer_id: valid_peer_id_literal(),
                    stake_account: None,
                    initial_stake: 1_u64.into(),
                    metadata: None,
                    monetary_plan: file.path().to_path_buf(),
                },
                network_id,
                activation_height: if wrong_activation { 3602 } else { 3601 },
                peer_private_key_file: PathBuf::from("/unused/key-must-not-be-read"),
            };
            let error = args.run(&mut context).unwrap_err();
            assert!(error.to_string().contains(if wrong_activation {
                "--activation-height"
            } else {
                "--network-id"
            }));
            assert!(context.submitted.is_none());
        }
    }

    #[test]
    fn claim_rejects_recipient_network_custody_amount_and_expiry_mismatches() {
        let valid = reward_claim_plan(ALICE_ID.clone(), LaneId::SINGLE);
        let mut wrong_recipient = valid.clone();
        wrong_recipient.fee_claim.destination_asset = plan_asset(BOB_ID.clone());
        let mut zero_amount = valid.clone();
        zero_amount.fee_claim.amount = Quantity::zero();
        let mut zero_seal = valid.clone();
        zero_seal.fee_claim.lifecycle_seal = [0; 32];
        let mut genesis = valid.clone();
        genesis.network_scope = PublicLaneMonetaryScopeV1::Genesis;
        let mut foreign_network = valid.clone();
        foreign_network.network_scope =
            PublicLaneMonetaryScopeV1::Network(NetworkId::from_genesis_hash(
                iroha_crypto::HashOf::from_untyped_unchecked(Hash::new(b"foreign reward network")),
            ));
        let mut expired = valid;
        expired.valid_until_height = 0;
        for plan in [
            wrong_recipient,
            zero_amount,
            zero_seal,
            genesis,
            foreign_network,
            expired,
        ] {
            let file = plan_file(&plan);
            let mut context = TestContext::new();
            let args = ClaimRewardsArgs {
                lane_id: 0,
                account: Some(alice_literal()),
                claim_plan: file.path().to_path_buf(),
            };
            assert!(args.run(&mut context).is_err());
            assert!(context.submitted.is_none());
        }
    }
    #[test]
    fn claim_plan_reader_preserves_full_width_sequence_and_revision() {
        let mut plan = reward_claim_plan(ALICE_ID.clone(), LaneId::SINGLE);
        plan.fee_claim.expected_claim_sequence = u64::MAX;
        plan.fee_claim.beneficiary_revision = u64::MAX;
        let file = plan_file(&plan);
        assert_eq!(
            load_staking_json::<PublicLaneRewardClaimPlanV1>(file.path(), "--claim-plan").unwrap(),
            plan
        );
    }
}
