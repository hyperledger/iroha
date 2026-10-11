//! One owner definition selects and resumes one immutable native deployment.

use super::*;
use iroha_deploy::definition::{DataspaceDefinition, Visibility};

/// Semantic owner intent. Paths and formatting are deliberately not operation identity.
#[derive(Debug, Clone, PartialEq, Eq, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub(super) struct DefinitionBinding {
    network_id: NetworkId,
    owner: AccountId,
    network_url: String,
    name: String,
    restricted: bool,
    #[norito(required)]
    account_alias: Option<String>,
    lease_years: u8,
    max_fee: Quantity,
    trust_sha256: String,
}

impl DefinitionBinding {
    fn new(
        definition: &DataspaceDefinition,
        network_id: NetworkId,
        owner: AccountId,
        network_url: String,
        trust: &DeploymentTrustV1,
    ) -> Result<Self> {
        Ok(Self {
            network_id,
            owner,
            network_url,
            name: definition.dataspace.name.to_string(),
            restricted: definition.dataspace.visibility == Visibility::Restricted,
            account_alias: definition
                .dataspace
                .account_alias
                .as_ref()
                .map(ToString::to_string),
            lease_years: definition.dataspace.lease_years,
            max_fee: definition.dataspace.max_fee.clone(),
            trust_sha256: digest(&json::to_vec(trust)?),
        })
    }

    fn operation_id(&self) -> Result<String> {
        use norito::codec::Encode as _;
        // A cap, endpoint or visibility edit must collide with the original operation
        // for validation, never create another independently dispatchable journal.
        // Account JSON is display-profile dependent; canonical binary identity is not.
        Ok(digest(
            &(
                "iroha:dataspace-operation:v1",
                self.network_id,
                self.owner.clone(),
                self.name.clone(),
            )
                .encode(),
        ))
    }

    pub(super) fn verify_manifest(&self, manifest: &ManifestV1) -> Result<()> {
        use iroha_data_model::nexus::LaneVisibility;
        manifest.validate()?;
        let aliases: Vec<_> = manifest
            .alias_request
            .intents
            .iter()
            .filter_map(|intent| {
                if let AliasIntentV1::AccountAlias(alias) = &intent.intent {
                    Some(alias.alias.canonical_text())
                } else {
                    None
                }
            })
            .collect();
        let expected_aliases: Vec<_> = self
            .account_alias
            .iter()
            .map(|alias| format!("{alias}@{}", self.name))
            .collect();
        require(
            manifest.network_id == self.network_id
                && manifest.owner == self.owner
                && manifest.dataspace.descriptor.alias == self.name
                && manifest.operation_id.as_deref() == Some(self.operation_id()?.as_str())
                && manifest.lane.visibility
                    == if self.restricted {
                        LaneVisibility::Restricted
                    } else {
                        LaneVisibility::Public
                    }
                && manifest.spending.max_fee == self.max_fee
                && digest(&json::to_vec(&manifest.finality)?) == self.trust_sha256
                && aliases == expected_aliases
                && manifest
                    .alias_request
                    .intents
                    .iter()
                    .all(|intent| intent.acquisition.term_years == self.lease_years),
            "retained plan differs from the dataspace definition; restore the original definition and state before resuming",
        )
    }
}

/// Extend the catalog namespace without reusing holes or the committed elastic range.
fn select_lane(baseline: &LaneLifecycleStatusV1, parameters: &Parameters) -> Result<u32> {
    use iroha_data_model::sumeragi_lanes::SumeragiLanePolicy;
    baseline.validate()?;
    let policy = parameters
        .custom
        .get(&SumeragiLanePolicy::parameter_id())
        .map(|custom| {
            SumeragiLanePolicy::from_custom_parameter(custom)
                .ok_or_else(|| eyre!("lane policy parameter identity differs"))?
                .map_err(|error| eyre!(error))
        })
        .transpose()?;
    let mut lane = baseline.lane_count.max(1);
    loop {
        let id = iroha_model_base::topology::LaneId::new(lane);
        if let Some(range) = policy.as_ref().and_then(|policy| policy.autoscale.as_ref())
            && range.min_lane <= id
            && id < range.max_lane_exclusive
        {
            lane = range.max_lane_exclusive.as_u32();
            continue;
        }
        if !baseline.lanes.iter().any(|entry| entry.id == id)
            && !policy
                .as_ref()
                .is_some_and(|policy| policy.fixed_lane(id).is_some())
        {
            lane.checked_add(1)
                .ok_or_else(|| eyre!("no lane ID remains in the catalog"))?;
            return Ok(lane);
        }
        lane = lane
            .checked_add(1)
            .ok_or_else(|| eyre!("no lane ID remains in the catalog"))?;
    }
}

#[cfg(unix)]
fn state_root(path: &Path, create: bool) -> Result<PathBuf> {
    use rustix::fs::{Mode, OFlags};
    let path = std::path::absolute(path)?;
    let parent = path
        .parent()
        .ok_or_else(|| eyre!("state root has no parent"))?
        .canonicalize()?;
    let name = path
        .file_name()
        .ok_or_else(|| eyre!("state root has no name"))?;
    let parent_fd = rustix::fs::open(
        &parent,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )?;
    if create {
        match rustix::fs::mkdirat(&parent_fd, name, Mode::from_raw_mode(0o700)) {
            Ok(()) => File::from(parent_fd.try_clone()?).sync_all()?,
            Err(rustix::io::Errno::EXIST) => {}
            Err(error) => return Err(error.into()),
        }
    }
    let directory = File::from(rustix::fs::openat(
        &parent_fd,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )?);
    private_metadata(&directory.metadata()?, true)?;
    Ok(parent.join(name))
}

#[cfg(not(unix))]
fn state_root(_: &Path, _: bool) -> Result<PathBuf> {
    eyre::bail!("durable dataspace deployment requires Unix filesystem custody")
}

fn requested_state_root(explicit: Option<&Path>, home: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = explicit {
        return Ok(path.to_owned());
    }
    Ok(home
        .ok_or_else(|| eyre!("cannot determine home directory; select --state explicitly"))?
        .join(".iroha-dataspaces"))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DefinitionAction {
    Plan,
    Apply,
    Status,
}

fn retain_definition(
    journal: &Journal,
    binding: &DefinitionBinding,
    action: DefinitionAction,
) -> Result<()> {
    if let Some(retained) = journal.optional_json::<DefinitionBinding>("definition.json")? {
        if retained == *binding {
            return Ok(());
        }
        let mut without_cap_change = binding.clone();
        without_cap_change.max_fee = retained.max_fee.clone();
        require(
            action == DefinitionAction::Plan && retained == without_cap_change,
            "dataspace definition or network trust changed for this operation; restore the original inputs before resuming",
        )?;
        require(
            !binding.max_fee.is_zero(),
            "max_fee must be positive before planning",
        )?;
        replace_unplanned_definition(journal, &retained, binding)
            .wrap_err("max_fee can change only through explicit dataspace plan before any plan or deployment evidence is retained")
    } else {
        require(
            action != DefinitionAction::Status,
            "no saved dataspace definition; run dataspace plan first",
        )?;
        journal.require_unplanned()?;
        journal.install_json("definition.json", binding)
    }
}

/// Correct spending intent only before a plan exists, preserving the original on failed publication.
#[cfg(unix)]
fn replace_unplanned_definition(
    journal: &Journal,
    expected: &DefinitionBinding,
    replacement: &DefinitionBinding,
) -> Result<()> {
    use rustix::fs::{AtFlags, Mode, OFlags, RenameFlags};
    let expected_bytes = json::to_vec(expected)?;
    let bytes = json::to_vec(replacement)?;
    require(bytes.len() <= MAX_BYTES, "definition exceeds journal bound")?;
    let require_current = |current: &[u8]| -> Result<()> {
        journal.require_definition_only()?;
        require(
            journal.read_optional("definition.json")?.as_deref() == Some(current),
            "retained definition changed before fee-cap correction",
        )?;
        journal.revalidate()
    };
    require_current(&expected_bytes)?;
    let temporary = format!(
        ".staging-definition.json-{}",
        hex::encode(rand::random::<[u8; 16]>())
    );
    let mut file = File::from(rustix::fs::openat(
        &journal.directory,
        temporary.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::from_raw_mode(0o600),
    )?);
    let mut exchanged = false;
    let result: Result<()> = (|| {
        file.write_all(&bytes)?;
        file.sync_all()?;
        private_metadata(&file.metadata()?, false)?;
        require_current(&expected_bytes)?;
        rustix::fs::renameat_with(
            &journal.directory,
            temporary.as_str(),
            &journal.directory,
            "definition.json",
            RenameFlags::EXCHANGE,
        )?;
        exchanged = true;
        journal.directory.sync_all()?;
        require_current(&bytes)
    })();
    if result.is_err() && exchanged {
        rustix::fs::renameat_with(
            &journal.directory,
            temporary.as_str(),
            &journal.directory,
            "definition.json",
            RenameFlags::EXCHANGE,
        )
        .wrap_err("fee-cap correction failed and its original binding could not be restored")?;
        journal.directory.sync_all()?;
    }
    // A leftover private staging file is never an authorization input.
    if rustix::fs::unlinkat(&journal.directory, temporary.as_str(), AtFlags::empty()).is_ok() {
        let _ = journal.directory.sync_all();
    }
    result
}

#[cfg(not(unix))]
fn replace_unplanned_definition(
    _: &Journal,
    _: &DefinitionBinding,
    _: &DefinitionBinding,
) -> Result<()> {
    eyre::bail!("Unix filesystem custody is required to correct an unplanned fee cap")
}

/// Read-only chain evidence binds every semantic/trust field except the spending cap.
/// Spending authorization remains bound to the exact definition and any retained plan.
pub(super) fn preflight_identity(journal: &Journal) -> Result<(String, NetworkId, String)> {
    let mut binding: DefinitionBinding = journal.read_json("definition.json")?;
    require(
        journal.path.file_name() == Some(std::ffi::OsStr::new(&binding.operation_id()?)),
        "preflight definition belongs to another operation directory",
    )?;
    binding.max_fee = Quantity::zero();
    Ok((
        digest(&json::to_vec(&binding)?),
        binding.network_id,
        binding.trust_sha256,
    ))
}

#[cfg(all(test, unix))]
pub(super) fn preflight_test_journal(
    root: &Path,
    trust: &DeploymentTrustV1,
    network: NetworkId,
) -> Journal {
    let definition = DataspaceDefinition::parse(
        include_str!("../../../dataspaces/dpn.toml"),
        "/definitions/dpn.toml",
        Some(Path::new("/owner")),
    )
    .unwrap();
    let binding = DefinitionBinding::new(
        &definition,
        network,
        super::tests::manifest().owner,
        "https://parent.example/".into(),
        trust,
    )
    .unwrap();
    let journal = Journal::open(&root.join(binding.operation_id().unwrap()), true).unwrap();
    retain_definition(&journal, &binding, DefinitionAction::Apply).unwrap();
    journal
}

fn retained_plan(
    journal: &Journal,
    binding: &DefinitionBinding,
    refresh: bool,
) -> Result<Option<PlanV1>> {
    let plan = journal.optional_json::<PlanV1>("plan.json")?;
    if let Some(plan) = &plan {
        plan.verify()?;
        binding.verify_manifest(&plan.manifest)?;
        if refresh {
            journal.require_unprepared_plan(plan)?;
        }
    } else {
        journal.require_definition_only()?;
    }
    Ok(plan)
}

fn check_unsigned_plan_quote_expiry(journal: &Journal, plan: &PlanV1, now_ms: u64) -> Result<()> {
    if plan
        .manifest
        .alias_request
        .intents
        .iter()
        .all(|intent| intent.quote_guard.valid_until_ms > now_ms)
    {
        return Ok(());
    }
    for phase in PHASES {
        if journal
            .optional_json::<PreparedV1>(&format!("{phase}.prepared.json"))?
            .is_some()
        {
            // Existing signatures remain observable after their original quote deadline.
            // An unsigned future aliases phase may extend only its submission deadline;
            // run_saved_until preserves every retained signature and exact rent cap.
            return Ok(());
        }
    }
    journal.require_unprepared_plan(plan)?;
    eyre::bail!(
        "unsigned dataspace plan quotes expired; run `iroha dataspace plan <definition> --trust <profile>` to refresh the plan before applying"
    )
}

fn manifest_inputs(
    binding: &DefinitionBinding,
    lane_id: u32,
    policy: &iroha_data_model::sns::SuffixPolicyV1,
) -> Result<ManifestInputs> {
    Ok(ManifestInputs {
        dataspace: binding.name.clone(),
        lane_id,
        lane_profile: if binding.restricted {
            LaneProfile::RestrictedFullReplica
        } else {
            LaneProfile::PublicFullReplica
        },
        account_alias: binding.account_alias.clone(),
        payment_asset: iroha_data_model::sns::pricing::payment_asset_definition_id(policy)?,
        max_fee: binding.max_fee.clone(),
        lease_years: binding.lease_years,
        operation_id: Some(binding.operation_id()?),
    })
}

#[derive(JsonSerialize)]
struct PlanReport {
    schema: &'static str,
    operation_id: String,
    network_id: NetworkId,
    dataspace: String,
    owner: AccountId,
    lane_id: u32,
    visibility: &'static str,
    #[norito(required)]
    account_alias: Option<String>,
    fee_asset: AssetDefinitionId,
    exact_alias_rent: Quantity,
    max_fee: Quantity,
    state_path: PathBuf,
    steps: Vec<&'static str>,
    deployment_complete: bool,
}

fn plan_report(plan: &PlanV1, directory: &Path) -> Result<PlanReport> {
    use iroha_data_model::nexus::LaneVisibility;
    Ok(PlanReport {
        schema: "iroha.dataspace.plan.v1",
        operation_id: plan.operation_id.clone(),
        network_id: plan.manifest.network_id,
        dataspace: plan.manifest.dataspace.descriptor.alias.clone(),
        owner: plan.manifest.owner.clone(),
        lane_id: plan.manifest.lane.id.as_u32(),
        visibility: match plan.manifest.lane.visibility {
            LaneVisibility::Restricted => "restricted",
            LaneVisibility::Public => "public",
        },
        account_alias: plan
            .manifest
            .alias_request
            .intents
            .iter()
            .find_map(|intent| {
                if let AliasIntentV1::AccountAlias(alias) = &intent.intent {
                    Some(alias.alias.canonical_text())
                } else {
                    None
                }
            }),
        fee_asset: plan.manifest.spending.asset_definition_id.clone(),
        exact_alias_rent: alias_liability(&plan.manifest)?,
        max_fee: plan.manifest.spending.max_fee.clone(),
        state_path: directory.to_owned(),
        steps: vec![
            "Register the dataspace and its validator committee",
            "Authorize dataspace ownership",
            "Register the paid namespace",
        ],
        deployment_complete: false,
    })
}

pub(super) fn run<C: RunContext>(
    context: &mut C,
    command: &Command,
    definition: &DataspaceDefinition,
    trust: DeploymentTrustV1,
) -> Result<()> {
    let (args, apply, status) = match command {
        Command::Plan(args) => (args, false, false),
        Command::Apply(args) => (args, true, false),
        Command::Status(args) => (args, false, true),
        Command::ExportProfile(_) | Command::VerifyAuthority(_) => {
            eyre::bail!("local authority tooling has no deployment definition")
        }
    };
    let verification_origins = command.verification_origins(&trust)?;
    let runtime_update = if args.verification_runtime_update.is_empty() {
        None
    } else {
        let selected = match (
            args.verification_source_commit.as_deref(),
            args.verification_source_version.as_deref(),
        ) {
            (Some(commit), Some(version)) => Some((commit, version)),
            (None, None) => None,
            _ => eyre::bail!("incomplete explicit target source selection"),
        };
        Some(runtime_update::Verified::admit_chain(
            &args.verification_runtime_update,
            &trust,
            context.config().network_id,
            selected,
        )?)
    };
    let deadline = operation_deadline(args.timeout_ms)?;
    let binding = DefinitionBinding::new(
        definition,
        context.config().network_id,
        context.config().account.clone(),
        context.config().torii_api_url.to_string(),
        &trust,
    )?;
    let id = binding.operation_id()?;
    let requested_root =
        requested_state_root(args.state.as_deref(), std::env::home_dir().as_deref())?;
    // Status never creates state, selects a lane, refreshes quotes or prepares a transaction.
    let root = state_root(&requested_root, !status)?;
    let directory = root.join(&id);
    let journal = if status {
        Journal::open(&directory, false)?
    } else {
        Journal::open_unpublished(&directory)?
    };
    retain_definition(
        &journal,
        &binding,
        if status {
            DefinitionAction::Status
        } else if apply {
            DefinitionAction::Apply
        } else {
            DefinitionAction::Plan
        },
    )?;
    let previous = retained_plan(&journal, &binding, !apply && !status)?;
    let mut preflight_proofs = if status {
        None
    } else {
        Some(finality::Preflight::new(
            &journal,
            &trust,
            binding.network_id,
            deadline,
        )?)
    };
    let plan: PlanV1 = if (apply || status) && previous.is_some() {
        previous.clone().expect("checked retained plan")
    } else {
        require(
            !status,
            "dataspace has no saved plan; run dataspace plan first",
        )?;
        require_operation_budget(deadline, "planning dataspace")?;
        let client = context
            .client_from_config()?
            .with_request_deadline(deadline);
        let baseline = client.get_lane_lifecycle_status()?;
        let parameters = client.get_parameters()?;
        let baseline_overlay = overlay(&parameters, &baseline)?;
        let lane_id = select_lane(&baseline, &parameters)?;
        use iroha_data_model::sns::{ACCOUNT_ALIAS_SUFFIX_ID, DATASPACE_ALIAS_SUFFIX_ID};
        let dataspace_policy = client.sns().get_policy(DATASPACE_ALIAS_SUFFIX_ID)?;
        let init = manifest_inputs(&binding, lane_id, &dataspace_policy)?;
        let mut policies = vec![dataspace_policy];
        if binding.account_alias.is_some() {
            policies.push(client.sns().get_policy(ACCOUNT_ALIAS_SUFFIX_ID)?);
        }
        let now = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
        let quote_deadline = now
            .checked_add(3_600_000)
            .ok_or_else(|| eyre!("quote deadline overflow"))?;
        let manifest = init_manifest(
            &init,
            binding.network_id,
            binding.owner.clone(),
            trust,
            &policies,
            quote_deadline,
        )?;
        binding.verify_manifest(&manifest)?;
        let configured = preflight(context, &manifest, true, client)?;
        preflight_proofs
            .as_mut()
            .ok_or_else(|| eyre!("planning requires retained preflight proof custody"))?
            .verify(context)?;
        let grant = manifest.validate()?;
        let catalog_transition = transition(&manifest, &baseline)?;
        check_funding(configured.client(), &manifest, &manifest.spending.max_fee)?;
        let initial_alias_plan = configured.plan_alias_setup(&manifest.alias_request)?;
        validate_alias_plan(&manifest, &initial_alias_plan, configured.client())?;
        let plan = PlanV1 {
            schema_version: 1,
            operation_id: id.clone(),
            intent_sha256: manifest.intent_digest()?,
            manifest,
            baseline,
            baseline_overlay,
            catalog_transition,
            bootstrap_grant: grant,
            initial_alias_plan,
        };
        plan.verify()?;
        require_operation_budget(deadline, "retaining dataspace plan")?;
        if let Some(previous) = &previous {
            journal.replace_unprepared_plan(previous, &plan)?;
        } else {
            journal.install_json("plan.json", &plan)?;
        }
        plan
    };
    if apply {
        check_unsigned_plan_quote_expiry(
            &journal,
            &plan,
            u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?,
        )?;
    }
    if !apply && !status {
        return context.print_data(&plan_report(&plan, &directory)?);
    }
    // Keep the same operation lock and definition-validated plan through every
    // preparation, dispatch and finality read. There is no path-based handoff.
    let report = run_saved_until(
        context,
        &journal,
        &plan,
        preflight_proofs.as_mut(),
        apply,
        deadline,
        &verification_origins,
        runtime_update.as_ref(),
    )?;
    if let Some(destination) = &args.export_authority {
        authority::export(
            &journal,
            &plan,
            &report,
            &args.trust,
            runtime_update.as_ref(),
            destination,
        )?;
    }
    print_saved_report(&report, apply, |report| context.print_data(report))
}

#[cfg(test)]
mod tests {
    use super::super::tests::{alias_plan, fixture_plan, init_policies, prepared, private_tempdir};
    use super::*;
    use iroha_crypto::{Algorithm, Hash, KeyPair};
    use iroha_data_model::{
        nexus::LaneCatalog,
        parameter::system::SumeragiParameters,
        sumeragi_lanes::{
            SumeragiFixedLane, SumeragiLaneAutoscale, SumeragiLaneMember, SumeragiLanePolicy,
        },
    };
    use iroha_model_base::{
        peer::PeerId,
        topology::{DataSpaceId, LaneId},
    };
    use std::num::NonZeroU32;

    fn definition() -> DataspaceDefinition {
        DataspaceDefinition::parse(
            include_str!("../../../dataspaces/dpn.toml"),
            "/definitions/dpn.toml",
            Some(Path::new("/owner")),
        )
        .unwrap()
    }

    fn binding(definition: &DataspaceDefinition) -> DefinitionBinding {
        let reference = fixture_plan().manifest;
        DefinitionBinding::new(
            definition,
            reference.network_id,
            reference.owner,
            "https://taira.sora.org/".into(),
            &reference.finality,
        )
        .unwrap()
    }

    fn native_plan(definition: &DataspaceDefinition) -> Result<(DefinitionBinding, PlanV1)> {
        let reference = fixture_plan();
        let binding = binding(definition);
        let baseline = reference.baseline;
        let lane = select_lane(&baseline, &Parameters::default())?;
        let mut policy = iroha_data_model::sns::fixtures::default_policy();
        policy.payment_asset_id = reference.manifest.spending.asset_definition_id.to_string();
        let inputs = manifest_inputs(&binding, lane, &policy)?;
        let policies = init_policies(&inputs);
        let manifest = init_manifest(
            &inputs,
            binding.network_id,
            binding.owner.clone(),
            reference.manifest.finality,
            &policies,
            9_000_000_000_000,
        )?;
        binding.verify_manifest(&manifest)?;
        let plan = PlanV1 {
            schema_version: 1,
            operation_id: binding.operation_id()?,
            intent_sha256: manifest.intent_digest()?,
            bootstrap_grant: manifest.validate()?,
            catalog_transition: transition(&manifest, &baseline)?,
            initial_alias_plan: alias_plan(&manifest),
            manifest,
            baseline,
            baseline_overlay: reference.baseline_overlay,
        };
        plan.verify()?;
        Ok((binding, plan))
    }

    #[test]
    fn actual_dpn_definition_builds_a_native_restricted_plan_with_one_deliberate_cap() {
        let mut definition = definition();
        assert_eq!(definition.dataspace.max_fee, Quantity::from(25_000_u32));
        let (binding, plan) = native_plan(&definition).unwrap();
        assert_eq!(binding.name, "dpn");
        assert!(binding.restricted);
        assert_eq!(plan.manifest.lane.id.as_u32(), plan.baseline.lane_count);
        assert_eq!(plan.manifest.dataspace.descriptor.alias, "dpn");
        assert_eq!(plan.manifest.alias_request.intents.len(), 2);
        assert_eq!(plan.manifest.spending.max_fee, Quantity::from(25_000_u32));
        assert_eq!(
            plan.initial_alias_plan.body.totals_by_asset[0].amount,
            Quantity::from(1_u32)
        );
        definition.dataspace.account_alias = None;
        let (_, without_alias) = native_plan(&definition).unwrap();
        assert_eq!(without_alias.manifest.alias_request.intents.len(), 1);
        definition.dataspace.max_fee = Quantity::zero();
        assert!(native_plan(&definition).is_err());
    }

    #[test]
    fn plan_report_contains_reviewable_costs_and_choices_without_internal_evidence() {
        let mut definition = definition();
        definition.dataspace.max_fee = Quantity::from(20_u32);
        let (_, plan) = native_plan(&definition).unwrap();
        let directory = Path::new("/owner/.iroha-dataspaces/operation");
        let report = plan_report(&plan, directory).unwrap();
        assert_eq!(report.operation_id, plan.operation_id);
        assert_eq!(report.network_id, plan.manifest.network_id);
        assert_eq!(report.owner, plan.manifest.owner);
        assert_eq!(report.dataspace, "dpn");
        assert_eq!(report.visibility, "restricted");
        assert_eq!(report.account_alias.as_deref(), Some("admin@dpn"));
        assert_eq!(report.exact_alias_rent, Quantity::from(1_u32));
        assert_eq!(report.max_fee, Quantity::from(20_u32));
        assert_eq!(report.state_path, directory);
        let json = json::to_value(&report).unwrap();
        let object = json.as_object().unwrap();
        assert_eq!(object["deployment_complete"], norito::json!(false));
        assert_eq!(object["exact_alias_rent"], norito::json!("1"));
        assert_eq!(object["max_fee"], norito::json!("20"));
        assert_eq!(object["steps"].as_array().unwrap().len(), 3);
        for internal in [
            "finality",
            "genesis_signed_wire_hex",
            "instructions",
            "alias_request",
            "manifest",
        ] {
            assert!(!object.contains_key(internal));
        }
        assert!(json::to_vec(&report).unwrap().len() < 4096);
        definition.dataspace.account_alias = None;
        let (_, no_alias) = native_plan(&definition).unwrap();
        let report = plan_report(&no_alias, directory).unwrap();
        assert!(json::to_value(&report).unwrap()["account_alias"].is_null());
    }

    #[test]
    fn binding_changes_cannot_allocate_another_operation_or_reuse_the_saved_manifest() {
        let mut definition = definition();
        definition.dataspace.max_fee = Quantity::from(20_u32);
        let (original, plan) = native_plan(&definition).unwrap();
        let mut cap = original.clone();
        cap.max_fee = Quantity::from(21_u32);
        let mut visibility = original.clone();
        visibility.restricted = false;
        let mut trust = original.clone();
        trust.trust_sha256 = digest(b"different independently selected trust");
        let mut alias = original.clone();
        alias.account_alias = None;
        let mut lease = original.clone();
        lease.lease_years = 2;
        let mut endpoint = original.clone();
        endpoint.network_url = "https://different.example/".into();
        for changed in [&cap, &visibility, &trust, &alias, &lease, &endpoint] {
            assert_eq!(
                changed.operation_id().unwrap(),
                original.operation_id().unwrap()
            );
        }
        for changed in [&cap, &visibility, &trust, &alias, &lease] {
            assert!(changed.verify_manifest(&plan.manifest).is_err());
        }
        let root = private_tempdir();
        let journal =
            Journal::open(&root.path().join(original.operation_id().unwrap()), true).unwrap();
        retain_definition(&journal, &original, DefinitionAction::Apply).unwrap();
        journal.install_json("plan.json", &plan).unwrap();
        for changed in [&cap, &visibility, &trust, &alias, &lease, &endpoint] {
            assert!(retain_definition(&journal, changed, DefinitionAction::Apply).is_err());
            assert!(retain_definition(&journal, changed, DefinitionAction::Status).is_err());
            assert!(retain_definition(&journal, changed, DefinitionAction::Plan).is_err());
        }
        retain_definition(&journal, &original, DefinitionAction::Status).unwrap();
        let retained: PlanV1 = journal.read_json("plan.json").unwrap();
        assert_eq!(retained, plan);
    }

    #[test]
    fn explicit_plan_can_correct_only_the_cap_after_an_unplanned_failure() {
        let mut definition = definition();
        definition.dataspace.max_fee = "0.5".parse().unwrap();
        assert!(
            native_plan(&definition).is_err(),
            "rent exceeds the initial cap"
        );
        let original = binding(&definition);
        definition.dataspace.max_fee = Quantity::from(20_u32);
        let (corrected, plan) = native_plan(&definition).unwrap();
        assert_eq!(
            original.operation_id().unwrap(),
            corrected.operation_id().unwrap()
        );
        let root = private_tempdir();
        let journal =
            Journal::open(&root.path().join(original.operation_id().unwrap()), true).unwrap();
        retain_definition(&journal, &original, DefinitionAction::Plan).unwrap();
        let original_bytes = journal.read_optional("definition.json").unwrap().unwrap();
        let proof_owner = finality::Preflight::new(
            &journal,
            &plan.manifest.finality,
            plan.manifest.network_id,
            operation_deadline(60_000).unwrap(),
        )
        .unwrap();
        let child_binding = journal.path.join("preflight-finality/binding.json");
        let proof_binding_before = fs::read(&child_binding).unwrap();
        let proof_identity_before = preflight_identity(&journal).unwrap();
        for action in [DefinitionAction::Apply, DefinitionAction::Status] {
            assert!(retain_definition(&journal, &corrected, action).is_err());
            assert_eq!(
                journal.read_optional("definition.json").unwrap().unwrap(),
                original_bytes
            );
        }
        retain_definition(&journal, &corrected, DefinitionAction::Plan).unwrap();
        assert_eq!(
            journal
                .read_json::<DefinitionBinding>("definition.json")
                .unwrap(),
            corrected
        );
        assert_eq!(preflight_identity(&journal).unwrap(), proof_identity_before);
        assert_eq!(fs::read(&child_binding).unwrap(), proof_binding_before);
        finality::validate_preflight_cache(&journal).unwrap();
        drop(proof_owner);
        let _reopened = finality::Preflight::new(
            &journal,
            &plan.manifest.finality,
            plan.manifest.network_id,
            operation_deadline(60_000).unwrap(),
        )
        .unwrap();
        assert!(retained_plan(&journal, &corrected, true).unwrap().is_none());
        journal.install_json("plan.json", &plan).unwrap();
        assert_eq!(
            retained_plan(&journal, &corrected, false).unwrap(),
            Some(plan)
        );
        assert!(retain_definition(&journal, &original, DefinitionAction::Plan).is_err());
    }

    #[test]
    fn unplanned_cap_correction_rejects_every_other_binding_change_and_outer_evidence() {
        let mut definition = definition();
        definition.dataspace.max_fee = Quantity::from(20_u32);
        let original = binding(&definition);
        let mut corrected = original.clone();
        corrected.max_fee = Quantity::from(21_u32);
        for evidence in [
            None,
            Some("plan.json"),
            Some("catalog.prepared.json"),
            Some("bootstrap.prepared.json"),
            Some("aliases.prepared.json"),
            Some("catalog.claim.json"),
            Some("catalog.submitted.json"),
            Some("completion-retained.json"),
            Some("proof-00000000000000000001.json"),
        ] {
            let root = private_tempdir();
            let journal =
                Journal::open(&root.path().join(original.operation_id().unwrap()), true).unwrap();
            retain_definition(&journal, &original, DefinitionAction::Plan).unwrap();
            let original_bytes = journal.read_optional("definition.json").unwrap().unwrap();
            if let Some(name) = evidence {
                journal.install_json(name, &"retained evidence").unwrap();
                assert!(
                    retain_definition(&journal, &corrected, DefinitionAction::Plan).is_err(),
                    "{name}"
                );
            } else {
                for mutation in 0..6 {
                    let mut changed = corrected.clone();
                    match mutation {
                        0 => changed.restricted = false,
                        1 => changed.trust_sha256 = digest(b"another trust"),
                        2 => changed.account_alias = None,
                        3 => changed.lease_years = 2,
                        4 => changed.network_url = "https://another-parent.example/".into(),
                        _ => changed.name = "another-name".into(),
                    }
                    assert!(retain_definition(&journal, &changed, DefinitionAction::Plan).is_err());
                }
                let mut zero = corrected.clone();
                zero.max_fee = Quantity::zero();
                assert!(retain_definition(&journal, &zero, DefinitionAction::Plan).is_err());
            }
            assert_eq!(
                journal.read_optional("definition.json").unwrap().unwrap(),
                original_bytes
            );
        }
    }

    #[test]
    fn cap_correction_authenticates_existing_proof_cache_before_replacing_binding() {
        let mut definition = definition();
        definition.dataspace.max_fee = Quantity::from(20_u32);
        let (original, plan) = native_plan(&definition).unwrap();
        let mut corrected = original.clone();
        corrected.max_fee = Quantity::from(21_u32);
        let root = private_tempdir();
        let journal =
            Journal::open(&root.path().join(original.operation_id().unwrap()), true).unwrap();
        retain_definition(&journal, &original, DefinitionAction::Plan).unwrap();
        let _preflight = finality::Preflight::new(
            &journal,
            &plan.manifest.finality,
            plan.manifest.network_id,
            operation_deadline(60_000).unwrap(),
        )
        .unwrap();
        let before = journal.read_optional("definition.json").unwrap().unwrap();
        fs::write(journal.path.join("preflight-finality/binding.json"), b"{}").unwrap();
        assert!(retain_definition(&journal, &corrected, DefinitionAction::Plan).is_err());
        assert_eq!(
            journal.read_optional("definition.json").unwrap().unwrap(),
            before
        );
    }

    #[test]
    fn explicit_plan_refresh_is_unsigned_only_and_apply_resume_keeps_signed_intent() {
        let mut definition = definition();
        definition.dataspace.max_fee = Quantity::from(20_u32);
        let (binding, plan) = native_plan(&definition).unwrap();
        let root = private_tempdir();
        let journal = Journal::open(&root.path().join("operation"), true).unwrap();
        retain_definition(&journal, &binding, DefinitionAction::Apply).unwrap();
        journal.install_json("plan.json", &plan).unwrap();
        assert_eq!(
            retained_plan(&journal, &binding, true).unwrap(),
            Some(plan.clone())
        );
        assert_eq!(
            retained_plan(&journal, &binding, false).unwrap(),
            Some(plan.clone())
        );
        let signature = prepared(&plan);
        journal
            .install_json("catalog.prepared.json", &signature)
            .unwrap();
        assert!(retained_plan(&journal, &binding, true).is_err());
        assert_eq!(
            retained_plan(&journal, &binding, false).unwrap(),
            Some(plan)
        );
    }

    #[test]
    fn preflight_child_preserves_unsigned_refresh_and_cannot_adopt_lost_plan_evidence() {
        let mut definition = definition();
        definition.dataspace.max_fee = Quantity::from(20_u32);
        let (binding, plan) = native_plan(&definition).unwrap();
        for outer_evidence in [
            None,
            Some("catalog.prepared.json"),
            Some("catalog.submitted.json"),
            Some("proof-00000000000000000001.json"),
        ] {
            let root = private_tempdir();
            let journal =
                Journal::open(&root.path().join(binding.operation_id().unwrap()), true).unwrap();
            retain_definition(&journal, &binding, DefinitionAction::Apply).unwrap();
            let _preflight = finality::Preflight::new(
                &journal,
                &plan.manifest.finality,
                plan.manifest.network_id,
                operation_deadline(60_000).unwrap(),
            )
            .unwrap();
            assert!(retained_plan(&journal, &binding, false).unwrap().is_none());
            journal.install_json("plan.json", &plan).unwrap();
            assert_eq!(
                retained_plan(&journal, &binding, true).unwrap(),
                Some(plan.clone())
            );
            // The in-memory proof owner remains alive while the unsigned outer plan
            // exchanges, so this also checks nested child lock ownership.
            journal.replace_unprepared_plan(&plan, &plan).unwrap();
            finality::validate_preflight_cache(&journal).unwrap();
            if let Some(name) = outer_evidence {
                journal
                    .install_json(name, &"retained deployment evidence")
                    .unwrap();
                fs::remove_file(journal.path.join("plan.json")).unwrap();
                assert!(retained_plan(&journal, &binding, false).is_err(), "{name}");
                assert!(retained_plan(&journal, &binding, true).is_err(), "{name}");
            } else {
                fs::remove_file(journal.path.join("definition.json")).unwrap();
                assert!(retain_definition(&journal, &binding, DefinitionAction::Apply).is_err());
            }
        }
    }

    #[test]
    fn preflight_child_rejects_changed_definition_or_selected_trust() {
        let mut definition = definition();
        definition.dataspace.max_fee = Quantity::from(20_u32);
        let (binding, plan) = native_plan(&definition).unwrap();
        let root = private_tempdir();
        let journal =
            Journal::open(&root.path().join(binding.operation_id().unwrap()), true).unwrap();
        retain_definition(&journal, &binding, DefinitionAction::Apply).unwrap();
        let proof_owner = finality::Preflight::new(
            &journal,
            &plan.manifest.finality,
            plan.manifest.network_id,
            operation_deadline(60_000).unwrap(),
        )
        .unwrap();
        drop(proof_owner);
        let mut changed_trust = plan.manifest.finality.clone();
        changed_trust.peers[0].config_fingerprint = Hash::new(b"another parent configuration");
        assert!(
            finality::Preflight::new(
                &journal,
                &changed_trust,
                plan.manifest.network_id,
                operation_deadline(60_000).unwrap(),
            )
            .is_err()
        );
        let mut changed_definition = binding.clone();
        changed_definition.restricted = false;
        fs::write(
            journal.path.join("definition.json"),
            json::to_vec(&changed_definition).unwrap(),
        )
        .unwrap();
        assert!(finality::validate_preflight_cache(&journal).is_err());
        assert!(
            finality::Preflight::new(
                &journal,
                &plan.manifest.finality,
                plan.manifest.network_id,
                operation_deadline(60_000).unwrap(),
            )
            .is_err()
        );
    }

    #[test]
    fn preflight_child_recovers_interrupted_empty_creation_but_never_replaces_a_lost_lock() {
        use std::os::unix::fs::PermissionsExt as _;
        let reference = fixture_plan();
        for orphan in [
            None,
            Some("binding.json"),
            Some("proof-00000000000000000001.json"),
            Some(".staging-binding.json-00000000000000000000000000000000"),
        ] {
            let root = private_tempdir();
            let parent = preflight_test_journal(
                root.path(),
                &reference.manifest.finality,
                reference.manifest.network_id,
            );
            let path = parent.path.join("preflight-finality");
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            if let Some(name) = orphan {
                let evidence = path.join(name);
                fs::write(&evidence, b"retained evidence after a lost lock").unwrap();
                fs::set_permissions(&evidence, fs::Permissions::from_mode(0o600)).unwrap();
                assert!(parent.require_definition_only().is_err(), "{name}");
                assert!(
                    finality::Preflight::new(
                        &parent,
                        &reference.manifest.finality,
                        reference.manifest.network_id,
                        operation_deadline(60_000).unwrap(),
                    )
                    .is_err(),
                    "{name}"
                );
                assert!(
                    !path.join("lock").exists(),
                    "lost locks must not be replaced"
                );
            } else {
                // The outer unsigned inventory must admit the interrupted child before
                // Preflight::new can install its purpose/definition/trust binding.
                parent.require_definition_only().unwrap();
                let _preflight = finality::Preflight::new(
                    &parent,
                    &reference.manifest.finality,
                    reference.manifest.network_id,
                    operation_deadline(60_000).unwrap(),
                )
                .unwrap();
                parent.require_definition_only().unwrap();
                assert!(path.join("lock").is_file());
                assert!(path.join("binding.json").is_file());
            }
        }
    }

    #[test]
    fn unsigned_quote_expiry_requests_explicit_refresh_but_keeps_signed_observations_available() {
        let mut definition = definition();
        definition.dataspace.max_fee = Quantity::from(20_u32);
        let (binding, plan) = native_plan(&definition).unwrap();
        let root = private_tempdir();
        let journal = Journal::open(&root.path().join("operation"), true).unwrap();
        retain_definition(&journal, &binding, DefinitionAction::Apply).unwrap();
        journal.install_json("plan.json", &plan).unwrap();
        let expiry = plan.manifest.alias_request.intents[0]
            .quote_guard
            .valid_until_ms;
        check_unsigned_plan_quote_expiry(&journal, &plan, expiry - 1).unwrap();
        let expired = check_unsigned_plan_quote_expiry(&journal, &plan, expiry).unwrap_err();
        assert!(expired.to_string().contains("iroha dataspace plan"));
        let signature = prepared(&plan);
        journal
            .install_json("catalog.prepared.json", &signature)
            .unwrap();
        check_unsigned_plan_quote_expiry(&journal, &plan, expiry + 1).unwrap();

        let orphan = Journal::open(&root.path().join("orphan"), true).unwrap();
        retain_definition(&orphan, &binding, DefinitionAction::Apply).unwrap();
        orphan.install_json("plan.json", &plan).unwrap();
        orphan
            .install_json("catalog.submitted.json", &"orphan claim")
            .unwrap();
        let error = check_unsigned_plan_quote_expiry(&orphan, &plan, expiry).unwrap_err();
        assert!(!error.to_string().contains("to refresh the plan"));
    }

    #[test]
    fn definition_path_does_not_change_binding_or_default_state_root() {
        let first = definition();
        let mut moved = first.clone();
        moved.file = PathBuf::from("/elsewhere/dpn.toml");
        moved.dataspace.owner_key = PathBuf::from("/same-owner-different-key-path");
        assert_eq!(binding(&first), binding(&moved));
        let home = Path::new("/owner");
        assert_eq!(
            requested_state_root(None, Some(home)).unwrap(),
            home.join(".iroha-dataspaces")
        );
        assert!(requested_state_root(None, None).is_err());
        assert_eq!(
            requested_state_root(Some(Path::new("/explicit/state")), None).unwrap(),
            Path::new("/explicit/state")
        );
    }

    #[test]
    fn operation_identity_is_independent_of_account_display_discriminant() {
        use iroha_data_model::account::address::ChainDiscriminantGuard;
        let binding = binding(&definition());
        let first = {
            let _guard = ChainDiscriminantGuard::enter(369);
            binding.operation_id().unwrap()
        };
        let second = {
            let _guard = ChainDiscriminantGuard::enter(901);
            binding.operation_id().unwrap()
        };
        assert_eq!(first, second);
    }

    #[test]
    fn namespace_payment_asset_accepts_policy_settlement_holdings() {
        let definition = definition();
        let binding = binding(&definition);
        let mut policy = iroha_data_model::sns::fixtures::default_policy();
        let expected =
            iroha_data_model::sns::pricing::payment_asset_definition_id(&policy).unwrap();
        assert!(policy.payment_asset_id.contains('#'));
        assert_eq!(
            manifest_inputs(&binding, 8, &policy).unwrap().payment_asset,
            expected
        );
        policy.payment_asset_id = "malformed".into();
        assert!(manifest_inputs(&binding, 8, &policy).is_err());
    }

    fn parameters(policy: SumeragiLanePolicy) -> Parameters {
        let mut parameters = Parameters::default();
        let custom = policy.into_custom_parameter();
        parameters.custom.insert(custom.id.clone(), custom);
        parameters
    }

    #[test]
    fn lane_allocation_preserves_sparse_namespace_and_skips_fixed_and_elastic_reservations() {
        let baseline = fixture_plan().baseline;
        assert_eq!(baseline.lane_count, 8);
        assert_eq!(select_lane(&baseline, &Parameters::default()).unwrap(), 8);
        let mut policy = SumeragiLanePolicy::for_chain(
            SumeragiParameters::default(),
            iroha_sumeragi::availability::recommended_data_availability_layout(),
        );
        policy.autoscale = Some(SumeragiLaneAutoscale {
            min_lane: LaneId::new(8),
            max_lane_exclusive: LaneId::new(16),
            dataspace: DataSpaceId::UNIVERSAL,
            committee_size: 4,
            per_lane_target_tps: 500,
            window: 32,
            scale_out_permille: 750,
            scale_in_permille: 300,
            cooldown: 64,
        });
        let pair = KeyPair::from_seed(vec![91; 32], Algorithm::BlsNormal);
        policy.fixed.push(SumeragiFixedLane {
            lane: LaneId::new(16),
            dataspace: DataSpaceId::UNIVERSAL,
            committee: vec![SumeragiLaneMember {
                peer: PeerId::new(pair.public_key().clone()),
                pop: Vec::new(),
            }],
        });
        assert_eq!(
            select_lane(&baseline, &parameters(policy.clone())).unwrap(),
            17
        );
        policy.autoscale.as_mut().unwrap().max_lane_exclusive = LaneId::new(8);
        assert!(select_lane(&baseline, &parameters(policy)).is_err());
        let mut forged = baseline.clone();
        forged.catalog_hash = Hash::new(b"wrong catalog");
        assert!(select_lane(&forged, &Parameters::default()).is_err());
    }

    #[test]
    fn lane_allocation_reports_identifier_exhaustion_without_wrapping() {
        let baseline = fixture_plan().baseline;
        let catalog =
            LaneCatalog::new(NonZeroU32::new(u32::MAX).unwrap(), baseline.lanes.clone()).unwrap();
        let incarnations = baseline
            .incarnations
            .into_iter()
            .map(|entry| (entry.lane_id, entry.incarnation))
            .collect();
        let full = LaneLifecycleStatusV1::new(&catalog, &incarnations, None).unwrap();
        assert!(select_lane(&full, &Parameters::default()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn state_root_checks_custody_and_status_does_not_create_it() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};
        let parent = tempfile::tempdir().unwrap();
        let requested = parent.path().join("state");
        assert!(state_root(&requested, false).is_err());
        assert!(!requested.exists());
        let root = state_root(&requested, true).unwrap();
        assert_eq!(
            fs::metadata(&root).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(state_root(&requested, false).unwrap(), root);
        let link = parent.path().join("state-link");
        symlink(&root, &link).unwrap();
        assert!(state_root(&link, true).is_err());
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(state_root(&requested, true).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn binding_only_crash_resumes_and_missing_binding_cannot_adopt_signed_state() {
        use std::os::unix::fs::PermissionsExt as _;
        let parent = tempfile::tempdir().unwrap();
        let root = state_root(&parent.path().join("state"), true).unwrap();
        let binding = binding(&definition());
        let directory = root.join(binding.operation_id().unwrap());
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let journal = Journal::open_unpublished(&directory).unwrap();
        assert!(retain_definition(&journal, &binding, DefinitionAction::Status).is_err());
        assert!(!directory.join("definition.json").exists());
        retain_definition(&journal, &binding, DefinitionAction::Apply).unwrap();
        drop(journal);
        let reopened = Journal::open_unpublished(&directory).unwrap();
        retain_definition(&reopened, &binding, DefinitionAction::Apply).unwrap();
        assert!(
            reopened
                .optional_json::<PlanV1>("plan.json")
                .unwrap()
                .is_none()
        );
        drop(reopened);
        fs::remove_file(directory.join("lock")).unwrap();
        assert!(Journal::open_unpublished(&directory).is_err());
        let orphan = Journal::open_unpublished(&root.join("orphan")).unwrap();
        orphan
            .install_json("catalog.prepared.json", &"retained transaction evidence")
            .unwrap();
        assert!(retain_definition(&orphan, &binding, DefinitionAction::Apply).is_err());
        let missing_plan = Journal::open_unpublished(&root.join("missing-plan")).unwrap();
        retain_definition(&missing_plan, &binding, DefinitionAction::Apply).unwrap();
        missing_plan
            .install_json("catalog.submitted.json", &"uncertain submission")
            .unwrap();
        assert!(retained_plan(&missing_plan, &binding, false).is_err());
        assert!(retained_plan(&missing_plan, &binding, true).is_err());
    }
}
