//! Governance deployment CLI helpers.
use super::shared::{decode_hex32, print_with_summary, resolve_contract_address_target};
use crate::{
    Run, RunContext,
    json_utils::{json_array, json_object, json_value},
};
use eyre::{Result, eyre};
use iroha::client::Client;
use iroha::data_model::{
    governance::types::{AbiVersion, ContractAbiHash, ContractCodeHash},
    isi::{InstructionBox, SetParameter},
    parameter::{CustomParameterId, Parameter, custom::CustomParameter},
};
use iroha_model_base::name::Name;
#[derive(clap::Args, Debug)]
pub struct ProposeDeployArgs {
    #[arg(long, conflicts_with = "contract_alias")]
    pub contract_address: Option<String>,
    #[arg(long, conflicts_with = "contract_address")]
    pub contract_alias: Option<String>,
    #[arg(long)]
    pub code_hash: String,
    #[arg(long)]
    pub abi_hash: String,
    #[arg(long, default_value = "1")]
    pub abi_version: u16,
}
impl Run for ProposeDeployArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let client: Client = context.client_from_config()?;
        let (contract_address, contract_alias) = match (
            self.contract_address.as_deref(),
            self.contract_alias.as_deref(),
        ) {
            (Some(_), Some(_)) => {
                return Err(eyre!(
                    "exactly one of --contract-address or --contract-alias must be provided"
                ));
            }
            (Some(contract_address), None) => {
                let contract_address: iroha::data_model::smart_contract::ContractAddress =
                    contract_address
                        .parse()
                        .map_err(|err| eyre!("invalid --contract-address: {err}"))?;
                (Some(contract_address), None)
            }
            (None, Some(contract_alias)) => {
                let contract_alias: iroha::data_model::smart_contract::ContractAlias =
                    contract_alias
                        .parse()
                        .map_err(|err| eyre!("invalid --contract-alias: {err}"))?;
                (None, Some(contract_alias))
            }
            (None, None) => {
                return Err(eyre!(
                    "provide exactly one contract target via --contract-address or --contract-alias"
                ));
            }
        };
        let request = iroha::client::DeployContractProposalDraftRequestV1 {
            proposal_operator: client.account().clone(),
            contract_address,
            contract_alias,
            abi_version: AbiVersion::new(self.abi_version),
            code_hash: ContractCodeHash::new(decode_hex32(&self.code_hash)?),
            abi_hash: ContractAbiHash::new(decode_hex32(&self.abi_hash)?),
            manifest_provenance: None,
        };
        let response = client.post_deploy_contract_proposal_draft(&request)?;
        let summary = Some(format!(
            "deploy propose: proposal_id={}",
            response.proposal_id
        ));
        let value = norito::json::to_value(&response)?;
        print_with_summary(context, summary, &value)
    }
}
#[derive(clap::Args, Debug)]
pub struct ProtectedSetArgs {
    /// Comma-separated namespaces (e.g., apps,system)
    #[arg(long)]
    pub namespaces: String,
}
impl Run for ProtectedSetArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        // Build a SetParameter(Custom) instruction for gov_protected_namespaces
        let name: Name = "gov_protected_namespaces".parse()?;
        let id = CustomParameterId(name);
        let arr: Vec<String> = self
            .namespaces
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        let json_arr = json_value(&arr)?;
        let custom = CustomParameter::new(id, iroha_primitives::json::Json::from(json_arr));
        let isi = SetParameter::new(Parameter::Custom(custom));
        let boxed: InstructionBox = isi.into();
        let bytes = norito::to_bytes(&boxed)?;
        let (wire_id, payload_bytes) = norito::decode_from_bytes::<(String, Vec<u8>)>(&bytes)?;
        let payload_hex = hex::encode(payload_bytes);
        let tx_instruction = json_object(vec![
            ("wire_id", json_value(&wire_id)?),
            ("payload_hex", json_value(&payload_hex)?),
        ])?;
        let tx_instructions = json_array(vec![tx_instruction])?;
        let out = json_object(vec![
            ("ok", json_value(&true)?),
            ("tx_instructions", tx_instructions),
        ])?;
        let count = self
            .namespaces
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .count();
        let summary = Some(format!("protected set: namespaces_count={count}"));
        print_with_summary(context, summary, &out)
    }
}
#[derive(clap::Args, Debug)]
pub struct ProtectedApplyArgs {
    /// Comma-separated namespaces (e.g., apps,system)
    #[arg(long)]
    pub namespaces: String,
}
impl Run for ProtectedApplyArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let client: Client = context.client_from_config()?;
        let namespaces: Vec<String> = self
            .namespaces
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        let value = client.post_gov_protected_set_json(&namespaces)?;
        let ok = value
            .get("ok")
            .and_then(norito::json::Value::as_bool)
            .unwrap_or(false);
        let applied = value
            .get("applied")
            .and_then(norito::json::Value::as_u64)
            .unwrap_or(0);
        let summary = Some(format!("protected apply: ok={ok} applied={applied}"));
        print_with_summary(context, summary, &value)
    }
}
#[derive(clap::Args, Debug)]
pub struct ProtectedGetArgs {}
impl Run for ProtectedGetArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let client: Client = context.client_from_config()?;
        let value = client.get_gov_protected_namespaces_json()?;
        let found = value
            .get("found")
            .and_then(norito::json::Value::as_bool)
            .unwrap_or(false);
        let count = value
            .get("namespaces")
            .and_then(|v| v.as_array())
            .map_or(0, Vec::len);
        let summary = Some(format!("protected get: found={found} count={count}"));
        print_with_summary(context, summary, &value)
    }
}
#[derive(clap::Args, Debug)]
pub struct DeployMetaArgs {
    #[arg(long, conflicts_with = "contract_alias")]
    pub contract_address: Option<String>,
    #[arg(long, conflicts_with = "contract_address")]
    pub contract_alias: Option<String>,
    /// Optional validator account IDs (canonical I105 account literals) authorizing the deployment alongside the authority.
    #[arg(long = "approver", value_name = "ACCOUNT")]
    pub approvers: Vec<String>,
}
impl Run for DeployMetaArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let client: Client = context.client_from_config()?;
        let contract_address = resolve_contract_address_target(
            &client,
            self.contract_address.as_deref(),
            self.contract_alias.as_deref(),
        )?;
        let mut pairs = vec![("gov_contract_address", json_value(&contract_address)?)];
        if !self.approvers.is_empty() {
            let mut accounts = Vec::with_capacity(self.approvers.len());
            for (idx, raw) in self.approvers.iter().enumerate() {
                let trimmed = raw.trim();
                if trimmed.is_empty() {
                    return Err(eyre!(format!("--approver[{idx}] must not be blank")));
                }
                let account = crate::resolve_account_id(context, trimmed)
                    .map_err(|err| eyre!("invalid --approver[{idx}] `{trimmed}`: {err}"))?;
                accounts.push(account.to_string());
            }
            pairs.push(("gov_manifest_approvers", json_array(accounts)?));
        }
        let obj = json_object(pairs)?;
        context.print_data(&obj)?;
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use blake3::Hasher as Blake3Hasher;
    use iroha::config::Config;
    use iroha::crypto::{Algorithm, KeyPair};
    use iroha::data_model::{
        account::AccountId,
        transaction::{Executable, IvmBytecode},
    };
    use iroha_i18n::{Bundle, Language, Localizer};
    use iroha_model_base::chain::ChainId;
    use iroha_model_base::metadata::Metadata;
    use norito::json::JsonSerialize;
    use url::Url;
    struct TestContext {
        cfg: Config,
        printed: Vec<norito::json::Value>,
        i18n: Localizer,
    }
    impl TestContext {
        fn new() -> Self {
            let key_pair = fixture_key_pair(vec![0xA5; 32]);
            let account = AccountId::new(key_pair.public_key().clone());
            let cfg = Config {
                chain: ChainId::from("00000000-0000-0000-0000-000000000000"),
                network_id:
                    "hash:32C903E5B3497E34C2B844EBFE8A39C19E6CF8F95D44C1FFB8BA9DCB42F91149#A2F0"
                        .parse()
                        .expect("network id"),
                account,
                account_chain_discriminant:
                    iroha_config::parameters::defaults::common::chain_discriminant(),
                key_pair,
                basic_auth: None,
                api_token: None,
                http_transport_policy: iroha::config::HttpTransportPolicy::Ordinary,
                torii_api_url: Url::parse("http://127.0.0.1/").unwrap(),
                torii_request_timeout: iroha::config::DEFAULT_TORII_REQUEST_TIMEOUT,
                transaction_ttl: iroha::config::DEFAULT_TRANSACTION_TIME_TO_LIVE,
                transaction_status_timeout: iroha::config::DEFAULT_TRANSACTION_STATUS_TIMEOUT,
                transaction_add_nonce: iroha::config::DEFAULT_TRANSACTION_NONCE,
                sorafs_alias_cache: crate::config_utils::default_alias_cache_policy(),
                sorafs_anonymity_policy: crate::config_utils::default_anonymity_policy(),
                sorafs_rollout_phase: crate::config_utils::default_rollout_phase(),
            };
            Self {
                cfg,
                printed: Vec::new(),
                i18n: Localizer::new(Bundle::Cli, Language::English),
            }
        }
    }
    fn fixture_key_pair(seed: Vec<u8>) -> KeyPair {
        KeyPair::try_from_seed(seed, Algorithm::Ed25519)
            .expect("fixture seed must derive a valid keypair")
    }
    #[test]
    fn fixture_key_pair_uses_checked_seed_derivation() {
        assert_eq!(
            fixture_key_pair(vec![0xA6; 32]).algorithm(),
            Algorithm::Ed25519
        );
        assert!(
            KeyPair::try_from_seed(vec![0; 32], Algorithm::Ed25519).is_err(),
            "checked Ed25519 seed derivation must reject weak all-zero fixture seeds"
        );
    }
    impl RunContext for TestContext {
        fn config(&self) -> &Config {
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
        fn i18n(&self) -> &Localizer {
            &self.i18n
        }
        fn print_data<T>(&mut self, data: &T) -> Result<()>
        where
            T: JsonSerialize + ?Sized,
        {
            self.printed.push(norito::json::to_value(data)?);
            Ok(())
        }
        fn println(&mut self, _data: impl std::fmt::Display) -> Result<()> {
            Ok(())
        }
        fn submit_with_metadata(
            &mut self,
            instructions: impl Into<Executable>,
            _metadata: Metadata,
            _wait_for_confirmation: bool,
        ) -> Result<()> {
            self.submit(instructions)
        }
        fn submit(&mut self, instructions: impl Into<Executable>) -> Result<()> {
            match instructions.into() {
                Executable::Instructions(_) => Ok(()),
                Executable::ContractCall(_) => {
                    eyre::bail!("unexpected contract-call submission in test context")
                }
                Executable::Ivm(IvmBytecode { .. }) => {
                    eyre::bail!("unexpected IVM bytecode submission in test context")
                }
                Executable::IvmProved(_) => {
                    eyre::bail!("unexpected proved IVM submission in test context")
                }
                Executable::Batch(_) => {
                    eyre::bail!("unexpected mixed executable batch submission in test context")
                }
            }
        }
    }
    #[test]
    fn deploy_meta_args_outputs_expected_keys() {
        let mut ctx = TestContext::new();
        let args = DeployMetaArgs {
            contract_address: Some(
                "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw".into(),
            ),
            contract_alias: None,
            approvers: Vec::new(),
        };
        args.run(&mut ctx).expect("deploy-meta run");
        assert_eq!(ctx.printed.len(), 1);
        let value = &ctx.printed[0];
        assert_eq!(
            value.get("gov_contract_address").and_then(|v| v.as_str()),
            Some("irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw")
        );
        assert!(value.get("gov_manifest_approvers").is_none());
    }
    #[test]
    fn deploy_meta_args_accepts_manifest_approvers() {
        let mut ctx = TestContext::new();
        let validator = sample_account_string("validator");
        let bob = sample_account_string("bob");
        let args = DeployMetaArgs {
            contract_address: Some(
                "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw".into(),
            ),
            contract_alias: None,
            approvers: vec![validator.clone(), format!("   {bob}   ")],
        };
        args.run(&mut ctx).expect("deploy-meta run");
        let value = &ctx.printed[0];
        let approvers = value
            .get("gov_manifest_approvers")
            .and_then(|v| v.as_array())
            .expect("manifest approver array");
        let collected: Vec<_> = approvers
            .iter()
            .map(|entry| entry.as_str().unwrap_or(""))
            .collect();
        assert_eq!(collected, vec![validator, bob]);
    }
    #[test]
    fn deploy_meta_args_rejects_invalid_approver() {
        let mut ctx = TestContext::new();
        let args = DeployMetaArgs {
            contract_address: Some(
                "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw".into(),
            ),
            contract_alias: None,
            approvers: vec!["not-an-id".into()],
        };
        let err = args
            .run(&mut ctx)
            .expect_err("invalid approver should fail");
        assert!(
            err.to_string().contains("invalid --approver[0]"),
            "unexpected error: {err}"
        );
    }
    #[test]
    fn deploy_meta_args_rejects_legacy_approver_with_domain_suffix() {
        let mut ctx = TestContext::new();
        let args = DeployMetaArgs {
            contract_address: Some(
                "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw".into(),
            ),
            contract_alias: None,
            approvers: vec!["alice@invalid-domain".into()],
        };
        let err = args
            .run(&mut ctx)
            .expect_err("legacy approver literal should fail");
        assert!(
            err.to_string().contains("must not include '@domain'"),
            "unexpected error: {err}"
        );
    }
    fn sample_account_string(name: &str) -> String {
        let mut hasher = Blake3Hasher::new();
        hasher.update(b"gov-deploy-account");
        hasher.update(name.as_bytes());
        let digest = hasher.finalize();
        let key_pair = fixture_key_pair(digest.as_bytes().to_vec());
        AccountId::new(key_pair.public_key().clone()).to_string()
    }
}
