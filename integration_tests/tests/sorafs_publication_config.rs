//! Explicit software custody and native provider configuration for the publication network.

use eyre::{Result, ensure};
use iroha_crypto::{Algorithm, ExposedPrivateKey, KeyPair};
use iroha_data_model::{
    isi::sorafs::SetProviderIngestCompletionAuthority,
    prelude::*,
    sorafs::{
        capacity::ProviderId,
        pin_registry::{
            ProviderIngestCompletionAuthorityV1, ProviderIngestCompletionSignerPolicyV1,
        },
    },
};
use iroha_executor_data_model::permission::{
    query::CanReadAllLedgerData,
    sorafs::{CanCompleteSorafsReplicationOrder, CanDeclareSorafsCapacity, CanOperateSorafsRepair},
};
use std::{
    fs,
    io::Write as _,
    os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
};

/// One provider's distinct owner, completion signer, and four native role identities.
pub struct ProviderFixture {
    pub id: ProviderId,
    pub owner_key: KeyPair,
    pub completion_key: KeyPair,
    pub role_keys: [KeyPair; 4],
    pub storage_dir: PathBuf,
    credential_dir: PathBuf,
}

pub fn set(table: &mut toml::Table, path: &[&str], value: impl Into<toml::Value>) {
    let (last, prefix) = path.split_last().expect("nonempty fixture path");
    let mut cursor = table;
    for field in prefix {
        cursor = cursor
            .entry((*field).to_owned())
            .or_insert_with(|| toml::Value::Table(toml::Table::new()))
            .as_table_mut()
            .expect("fixture table path");
    }
    cursor.insert((*last).to_owned(), value.into());
}

fn credential(root: &Path, name: &str, key: &KeyPair) -> Result<PathBuf> {
    fs::create_dir_all(root)?;
    fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
    let path = root.join(name);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)?;
    let encoded = ExposedPrivateKey(key.private_key().clone()).try_to_multihash_string()?;
    file.write_all(encoded.as_bytes())?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(path)
}

impl ProviderFixture {
    pub fn new(root: &Path, index: u8) -> Result<Self> {
        ensure!(index < 3, "publication fixture has exactly three providers");
        let root = root.join(format!("provider-{index}"));
        fs::create_dir_all(&root)?;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
        let key = |offset| {
            KeyPair::try_from_seed(vec![0x40 + index * 8 + offset; 32], Algorithm::Ed25519)
        };
        Ok(Self {
            id: ProviderId::new([0xA0 + index; 32]),
            owner_key: key(0)?,
            completion_key: key(5)?,
            role_keys: [key(1)?, key(2)?, key(3)?, key(4)?],
            storage_dir: root.join("storage"),
            credential_dir: root.join("custody"),
        })
    }
    pub fn owner(&self) -> AccountId {
        AccountId::new(self.owner_key.public_key().clone())
    }
    pub fn completion_signer(&self) -> AccountId {
        AccountId::new(self.completion_key.public_key().clone())
    }
    pub fn completion_policy(&self) -> ProviderIngestCompletionSignerPolicyV1 {
        ProviderIngestCompletionSignerPolicyV1 {
            policy_id: *self.id.as_bytes(),
            revision: 1,
            predecessor_digest: None,
            policy_digest: [self.id.as_bytes()[0] + 1; 32],
        }
    }
    pub fn genesis_accounts(&self) -> Vec<InstructionBox> {
        let owner = self.owner();
        let mut instructions = vec![
            Register::account(Account::new(owner.clone())).into(),
            Register::account(Account::new(self.completion_signer())).into(),
            Grant::account_permission(
                Permission::from(CanCompleteSorafsReplicationOrder {
                    provider_id: self.id,
                }),
                self.completion_signer(),
            )
            .into(),
            Grant::account_permission(Permission::from(CanDeclareSorafsCapacity), owner.clone())
                .into(),
            Grant::account_permission(Permission::from(CanReadAllLedgerData), owner).into(),
        ];
        for key in &self.role_keys {
            instructions.push(
                Register::account(Account::new(AccountId::new(key.public_key().clone()))).into(),
            );
        }
        instructions.push(
            Grant::account_permission(
                Permission::from(CanOperateSorafsRepair {
                    provider_id: self.id,
                }),
                AccountId::new(self.role_keys[1].public_key().clone()),
            )
            .into(),
        );
        instructions
    }
    pub fn completion_authority(&self) -> SetProviderIngestCompletionAuthority {
        SetProviderIngestCompletionAuthority::new(
            self.id,
            None,
            ProviderIngestCompletionAuthorityV1::new(
                self.owner(),
                self.completion_signer(),
                self.completion_policy(),
            ),
        )
    }
    pub fn config(&self, origins: &[(ProviderId, String)]) -> Result<toml::Table> {
        let mut layer = toml::Table::new();
        set(&mut layer, &["sorafs", "storage", "enabled"], true);
        set(
            &mut layer,
            &["sorafs", "storage", "provider_id_hex"],
            hex::encode(self.id.as_bytes()),
        );
        set(
            &mut layer,
            &["sorafs", "storage", "data_dir"],
            self.storage_dir.display().to_string(),
        );
        set(
            &mut layer,
            &["sorafs", "storage", "max_capacity_bytes"],
            2_i64 * 1024 * 1024 * 1024,
        );
        set(&mut layer, &["sorafs", "storage", "max_pins"], 16_i64);
        let roles = ["proof_outcome", "repair", "reserve", "orderbook"];
        let mut role_paths = Vec::new();
        for (index, (role, key)) in roles.into_iter().zip(&self.role_keys).enumerate() {
            let path = credential(&self.credential_dir, &format!("{role}.key"), key)?;
            let base = ["sorafs", "storage", "native_transaction_signers", role];
            for (field, value) in [
                (
                    "software_credential",
                    toml::Value::String(path.display().to_string()),
                ),
                ("handle", format!("software://sorafs/{role}/primary").into()),
                (
                    "authority",
                    AccountId::new(key.public_key().clone()).to_string().into(),
                ),
                ("algorithm", "ed25519".into()),
                (
                    "public_key_hex",
                    hex::encode(key.public_key().try_to_bytes()?.1).into(),
                ),
                ("revision", 1_i64.into()),
                (
                    "policy_digest_hex",
                    hex::encode(
                        [u8::try_from(index).expect("fixture provider index fits u8") + 1; 32],
                    )
                    .into(),
                ),
            ] {
                set(&mut layer, &[base.as_slice(), &[field]].concat(), value);
            }
            role_paths.push(path);
        }
        let completion = credential(&self.credential_dir, "completion.key", &self.completion_key)?;
        let base = ["sorafs", "storage", "provider_ingest_runtime"];
        let policy = self.completion_policy();
        let sources = origins
            .iter()
            .filter(|(id, _)| *id != self.id)
            .map(|(id, endpoint)| (hex::encode(id.as_bytes()), endpoint.clone().into()))
            .collect::<toml::Table>();
        for (field, value) in [
            ("enabled", true.into()),
            (
                "native_completion_credential",
                completion.display().to_string().into(),
            ),
            ("native_source_origins", toml::Value::Table(sources.clone())),
            (
                "authenticated_source_fetch_handle",
                "software://sorafs/source/primary".into(),
            ),
            ("authenticated_source_fetch_revision", 1_i64.into()),
            (
                "authenticated_source_fetch_policy_digest_hex",
                hex::encode([0x71; 32]).into(),
            ),
            (
                "completion_signer_resolver_handle",
                "software://sorafs/completion-resolver/primary".into(),
            ),
            ("completion_signer_resolver_revision", 1_i64.into()),
            (
                "completion_signer_resolver_policy_digest_hex",
                hex::encode([0x72; 32]).into(),
            ),
            (
                "completion_signer_handle",
                "software://sorafs/completion/primary".into(),
            ),
            ("completion_signer_adapter_revision", 1_i64.into()),
            (
                "completion_signer_policy_id_hex",
                hex::encode(policy.policy_id).into(),
            ),
            ("completion_signer_policy_revision", 1_i64.into()),
            (
                "completion_signer_policy_digest_hex",
                hex::encode(policy.policy_digest).into(),
            ),
            ("completion_signer_algorithm", "ed25519".into()),
            (
                "completion_signer_public_key_hex",
                hex::encode(self.completion_key.public_key().try_to_bytes()?.1).into(),
            ),
            (
                "checkpoint_store_handle",
                "software://sorafs/checkpoint/primary".into(),
            ),
            ("checkpoint_store_revision", 1_i64.into()),
            (
                "checkpoint_store_policy_digest_hex",
                hex::encode([0x73; 32]).into(),
            ),
            ("scan_interval_ms", 250_i64.into()),
        ] {
            set(&mut layer, &[base.as_slice(), &[field]].concat(), value);
        }
        set(&mut layer, &["sorafs", "repair", "enabled"], true);
        set(
            &mut layer,
            &["sorafs", "repair", "source", "origins"],
            sources,
        );
        set(
            &mut layer,
            &["sorafs", "repair", "source", "authority"],
            AccountId::new(self.role_keys[1].public_key().clone()).to_string(),
        );
        set(
            &mut layer,
            &["sorafs", "repair", "source", "credential"],
            role_paths[1].display().to_string(),
        );
        Ok(layer)
    }
}

#[test]
fn software_fixture_writes_distinct_owner_only_runtime_custody() -> Result<()> {
    let root = tempfile::tempdir()?;
    let provider = ProviderFixture::new(root.path(), 0)?;
    let layer = provider.config(&[(
        ProviderId::new([0xA1; 32]),
        "http://127.0.0.1:18080/".into(),
    )])?;
    ensure!(layer["sorafs"]["storage"]["enabled"].as_bool() == Some(true));
    let mut publics = std::collections::BTreeSet::new();
    for key in std::iter::once(&provider.owner_key).chain(provider.role_keys.iter()) {
        ensure!(publics.insert(key.public_key().to_string()));
    }
    for entry in fs::read_dir(&provider.credential_dir)? {
        let mode = entry?.metadata()?.permissions().mode() & 0o777;
        ensure!(mode == 0o600);
    }
    Ok(())
}
