#[test]
fn sandbox_accounts_are_deterministic() {
    for (name, public, _) in SANDBOX_ACCOUNT_KEYS {
        assert_eq!(
            ACCOUNT[name].id.expect_single_signatory().to_string(),
            *public
        );
    }
}
/// Account credentials used by the sandbox (ID and signing key).
#[derive(Debug, Clone)]
pub struct Credential {
    /// Canonical domainless account identifier.
    pub id: AccountId,
    /// Private key used to sign transactions for the account.
    pub key: iroha_crypto::PrivateKey,
}
/// Credentials of the special genesis account used to bootstrap state.
pub static GENESIS_ACCOUNT: LazyLock<Credential> = LazyLock::new(|| {
    let (id, key_pair) = gen_account_in(GENESIS_DOMAIN_ID.name());
    Credential {
        id,
        key: key_pair.into_parts().1,
    }
});
/// Chain identifier used by sandbox state metadata.
pub static CHAIN_ID: LazyLock<ChainId> =
    LazyLock::new(|| ChainId::from("00000000-0000-0000-0000-000000000000"));
/// Build the [`AssetId`] for the sandbox test asset owned by a named account.
pub fn asset(account_name: &str) -> AssetId {
    AssetId::new(ASSET.clone(), ACCOUNT[account_name].id.clone())
}
/// Convenience builder that yields a single transfer instruction iterator.
///
/// Transfers `quantity` units of the sandbox asset from `src` to `dest`.
pub fn transfer<'a>(
    src: &'a str,
    quantity: u32,
    dest: &'a str,
) -> impl IntoIterator<Item = InstructionBox> + 'a {
    transfers_batched::<1>(src, quantity, dest)
}
/// Produce an iterator over `N_INSTRUCTIONS` transfer instructions.
///
/// Each instruction transfers `quantity_per_instruction` units of the sandbox
/// asset from `src` to `dest`.
pub fn transfers_batched<'a, const N_INSTRUCTIONS: usize>(
    src: &'a str,
    quantity_per_instruction: u32,
    dest: &'a str,
) -> impl IntoIterator<Item = InstructionBox> + 'a {
    (0..N_INSTRUCTIONS).map(move |_| {
        Transfer::asset_quantity(
            asset(src),
            quantity_per_instruction,
            ACCOUNT[dest].id.clone(),
        )
        .into()
    })
}
/// Assert that the emitted events match a stored JSON snapshot.
pub fn assert_events(actual: &[EventBox], snapshot_path: impl AsRef<std::path::Path>) {
    let snapshot_path_buf = {
        let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(snapshot_path.as_ref());
        path.set_extension("json");
        path
    };
    let (snapshot_text, line_endings) = load_snapshot(&snapshot_path_buf);
    let expected = expect_test::expect_file![snapshot_path_buf.clone()];
    let actual = actual
        .iter()
        .filter(|e| {
            !matches!(
                e,
                EventBox::Time(_) | EventBox::Pipeline(_) | EventBox::PipelineBatch(_)
            )
        })
        .map(EventSnapshot::from_event)
        .collect::<Vec<_>>();
    let rendered = if actual.is_empty() {
        "[]".to_owned()
    } else {
        norito::json::to_json_pretty(&actual).unwrap()
    };
    if let Some(text) = snapshot_text.as_deref() {
        let collapsed = collapse_to_unix_line_endings(text);
        let collapsed = collapsed
            .strip_suffix('\n')
            .unwrap_or_else(|| collapsed.as_ref());
        if collapsed == rendered {
            return;
        }
    }
    let normalised = normalise_line_endings(&rendered, line_endings);
    expected.assert_eq(normalised.as_ref());
}
enum EventSnapshot<'a> {
    Asset(AssetEventSnapshot<'a>),
    TriggerCompleted(TriggerCompletedSnapshot<'a>),
    Raw(String),
}
impl<'a> EventSnapshot<'a> {
    fn from_event(event: &'a EventBox) -> Self {
        match event {
            EventBox::Data(data) => AssetEventSnapshot::from_data_event(data.as_ref())
                .map_or_else(|| Self::Raw(format!("{event:?}")), Self::Asset),
            EventBox::TriggerCompleted(event) => {
                Self::TriggerCompleted(TriggerCompletedSnapshot(event))
            }
            other => Self::Raw(format!("{other:?}")),
        }
    }
}
impl norito::json::JsonSerialize for EventSnapshot<'_> {
    fn json_serialize(&self, out: &mut String) {
        match self {
            Self::Asset(asset) => asset.json_serialize(out),
            Self::TriggerCompleted(event) => event.json_serialize(out),
            Self::Raw(raw) => norito::json::write_json_string(raw, out),
        }
    }
}
enum AssetEventSnapshot<'a> {
    Added(&'a AssetChanged),
    Removed(&'a AssetChanged),
    Transferred(&'a AssetTransferred),
}
impl<'a> AssetEventSnapshot<'a> {
    fn from_data_event(event: &'a data::DataEvent) -> Option<Self> {
        match event {
            data::DataEvent::Domain(domain_event) => Self::from_domain_event(domain_event),
            data::DataEvent::Asset(event) => Self::from_asset_event(event),
            _ => None,
        }
    }
    fn from_domain_event(event: &'a DomainEvent) -> Option<Self> {
        match event {
            DomainEvent::Asset(event) => Self::from_asset_event(&event.event),
            _ => None,
        }
    }
    fn from_asset_event(event: &'a AssetEvent) -> Option<Self> {
        match event {
            AssetEvent::Added(change) => Some(Self::Added(change)),
            AssetEvent::Removed(change) => Some(Self::Removed(change)),
            AssetEvent::Transferred(transfer) => Some(Self::Transferred(transfer)),
            _ => None,
        }
    }
}
fn format_asset_id_for_snapshot(asset_id: &AssetId) -> String {
    let account = asset_id.account();
    let account_str = ACCOUNT_ALIAS_BY_ID.get(account).map_or_else(
        || format!("{}@{}", account.expect_single_signatory(), DOMAIN_STR),
        |alias| format!("{alias}@{DOMAIN_STR}"),
    );
    if asset_id.definition() == &*ASSET {
        format!("{ASSET_STR}##{account_str}")
    } else {
        format!("{}#{}", asset_id.definition(), account_str)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SnapshotLineEndings {
    Lf,
    Crlf,
}
fn load_snapshot(path: &std::path::Path) -> (Option<String>, SnapshotLineEndings) {
    std::fs::read_to_string(path).map_or((None, SnapshotLineEndings::Lf), |text| {
        let endings = detect_line_endings_from_text(&text);
        (Some(text), endings)
    })
}
fn normalise_line_endings(input: &str, endings: SnapshotLineEndings) -> std::borrow::Cow<'_, str> {
    match endings {
        SnapshotLineEndings::Lf => std::borrow::Cow::Borrowed(input),
        SnapshotLineEndings::Crlf => {
            if input.contains('\r') {
                std::borrow::Cow::Borrowed(input)
            } else {
                std::borrow::Cow::Owned(input.replace('\n', "\r\n"))
            }
        }
    }
}
fn detect_line_endings_from_text(text: &str) -> SnapshotLineEndings {
    if text.contains('\r') {
        SnapshotLineEndings::Crlf
    } else {
        SnapshotLineEndings::Lf
    }
}
fn collapse_to_unix_line_endings(text: &str) -> std::borrow::Cow<'_, str> {
    if text.contains('\r') {
        let collapsed = text.replace("\r\n", "\n").replace('\r', "\n");
        std::borrow::Cow::Owned(collapsed)
    } else {
        std::borrow::Cow::Borrowed(text)
    }
}
impl norito::json::JsonSerialize for AssetEventSnapshot<'_> {
    fn json_serialize(&self, out: &mut String) {
        let event = match self {
            Self::Added(change) => norito::json!({
                "Added": {"asset": (format_asset_id_for_snapshot(change.asset())),
                    "amount": (change.amount().to_string())}
            }),
            Self::Removed(change) => norito::json!({
                "Removed": {"asset": (format_asset_id_for_snapshot(change.asset())),
                    "amount": (change.amount().to_string())}
            }),
            Self::Transferred(transfer) => norito::json!({
                "Transferred": {"source": (format_asset_id_for_snapshot(transfer.source())),
                    "destination": (format_asset_id_for_snapshot(transfer.destination())),
                    "amount": (transfer.amount().to_string())}
            }),
        };
        norito::json::JsonSerialize::json_serialize(
            &norito::json!({"Data": {"Asset": event}}),
            out,
        );
    }
}
#[test]
fn current_asset_event_snapshots_preserve_deltas_and_complete_transfers() {
    let source = asset("alice");
    let destination = asset("bob");
    let amount = Quantity::from(7_u32);
    let cases = [
        (
            AssetEvent::Removed(AssetChanged {
                asset: source.clone(),
                amount: amount.clone(),
            }),
            norito::json!({"Data": {"Asset": {"Removed": {
                "asset": "rose##alice@wonderland", "amount": "7"}}}}),
        ),
        (
            AssetEvent::Added(AssetChanged {
                asset: destination.clone(),
                amount: amount.clone(),
            }),
            norito::json!({"Data": {"Asset": {"Added": {
                "asset": "rose##bob@wonderland", "amount": "7"}}}}),
        ),
        (
            AssetEvent::Transferred(AssetTransferred {
                source,
                destination,
                amount,
            }),
            norito::json!({"Data": {"Asset": {"Transferred": {
                "source": "rose##alice@wonderland", "destination": "rose##bob@wonderland",
                "amount": "7"}}}}),
        ),
    ];
    for (event, expected) in cases {
        let snapshot = AssetEventSnapshot::from_asset_event(&event)
            .expect("current balance and transfer events must be represented");
        assert_eq!(
            norito::json::to_value(&snapshot).expect("serialize exact event"),
            expected
        );
    }
}
struct TriggerCompletedSnapshot<'a>(&'a TriggerCompletedEvent);
impl norito::json::JsonSerialize for TriggerCompletedSnapshot<'_> {
    fn json_serialize(&self, out: &mut String) {
        out.push('{');
        norito::json::write_json_string("TriggerCompleted", out);
        out.push(':');
        out.push('{');
        norito::json::write_json_string("trigger_id", out);
        out.push(':');
        let trigger_id = self.0.trigger_id().to_string();
        norito::json::write_json_string(&trigger_id, out);
        out.push(',');
        norito::json::write_json_string("outcome", out);
        out.push(':');
        match self.0.outcome() {
            TriggerCompletedOutcome::Success => {
                norito::json::write_json_string("Success", out);
            }
            TriggerCompletedOutcome::Failure(message) => {
                out.push('{');
                norito::json::write_json_string("Failure", out);
                out.push(':');
                norito::json::write_json_string(message, out);
                out.push('}');
            }
        }
        out.push('}');
        out.push('}');
    }
}
impl Default for Sandbox {
    fn default() -> Self {
        Self::with_genesis_fastpq_source_policy(None)
    }
}
impl Sandbox {
    /// Construct a sandbox whose optional finite source policy is enacted by its signed genesis.
    pub(super) fn with_genesis_fastpq_source_policy(
        source_policy: Option<iroha_data_model::parameter::FastpqSourcePolicyV1>,
    ) -> Self {
        use crate::sumeragi::{
            startup,
            test_chain::{CertifiedTestChain, TestChainConfig},
        };
        let mut world = {
            let domain = Domain::new(DOMAIN.clone()).build(&GENESIS_ACCOUNT.id);
            let asset_def = {
                let __asset_definition_id = ASSET.clone();
                AssetDefinition::new(
                    __asset_definition_id.clone(),
                    "rose".to_owned(),
                    NumericSpec::default(),
                    iroha_data_model::asset::AssetBalancePolicy::Global,
                    None,
                )
            }
            .build(&GENESIS_ACCOUNT.id);
            let accounts = ACCOUNT
                .clone()
                .into_iter()
                .chain([("genesis", GENESIS_ACCOUNT.clone())])
                .map(|(_name, cred)| Account::new(cred.id.clone()).build(&GENESIS_ACCOUNT.id));
            let assets = INIT_BALANCE
                .iter()
                .map(|(name, num)| Asset::new(asset(name), *num));
            World::with_assets([domain], accounts, [asset_def], assets, [])
        };
        world.account_permissions.insert(
            GENESIS_ACCOUNT.id.clone(),
            std::collections::BTreeSet::from([
                iroha_executor_data_model::permission::trigger::CanRegisterGlobalDataTrigger {
                    authority: GENESIS_ACCOUNT.id.clone(),
                }
                .into(),
                iroha_executor_data_model::permission::asset::CanTransferAssetWithDefinition {
                    asset_definition: ASSET.clone(),
                }
                .into(),
            ]),
        );
        // The prepopulated accounts, permissions and balances belong to this
        // original State. Apply its signed genesis before ordinary Network
        // execution; the real producer also supplies its resolver checkpoint.
        let mut config = TestChainConfig::new(world, 0);
        if let Some(profile) = source_policy {
            config.genesis_parameters.push(Parameter::Block(
                iroha_data_model::parameter::BlockParameter::FastpqSource(profile),
            ));
        }
        config.chain_id = CHAIN_ID.clone();
        config.genesis_key = iroha_crypto::KeyPair::from_private_key(GENESIS_ACCOUNT.key.clone())
            .expect("original Sandbox genesis key");
        let consensus_mode = config.consensus_mode;
        let prepared = CertifiedTestChain::prepare(config).expect("prepare Sandbox signed genesis");
        let state = std::sync::Arc::try_unwrap(prepared.state)
            .unwrap_or_else(|_| panic!("unpublished Sandbox State is unique"));
        startup::apply_genesis(
            &state,
            prepared.genesis.block().clone(),
            &GENESIS_ACCOUNT.id,
            consensus_mode.into(),
            None,
        )
        .expect("apply the original Sandbox signed genesis");
        let mut sandbox = Self {
            state,
            transactions: vec![],
        };
        // Force deterministic single-threaded pipeline evaluation in tests to avoid
        // parallel scheduling reordering transactions that rely on chained data triggers.
        sandbox.state.edit_pipeline_for_testing(|pipeline| {
            pipeline.dynamic_prepass = false;
            pipeline.parallel_overlay = false;
            pipeline.parallel_apply = false;
            pipeline.workers = 1;
        });
        sandbox.with_max_execution_depth(INIT_EXECUTION_DEPTH)
    }
}
#[test]
fn sandbox_genesis_and_queued_input_share_original_native_network() {
    let mut sandbox = Sandbox::default();
    let view = sandbox.state.view();
    assert_eq!(view.height(), 1);
    assert_eq!(view.kura().blocks_count(), 1);
    let genesis = view
        .latest_block()
        .expect("completed original State read")
        .expect("original Sandbox genesis");
    assert_eq!(
        sandbox.state.network_id_ref().into_genesis_hash(),
        genesis.hash()
    );
    assert_eq!(
        view.native_execution_tip()
            .expect("applied original genesis")
            .height(),
        1
    );
    let revision = *view.world().musubi_resolver_index_revision.get();
    let checkpoint = view
        .world()
        .musubi_resolver_index_checkpoints
        .get(&revision)
        .expect("resolver checkpoint from the original genesis producer");
    assert_eq!(checkpoint.finalized_height, 1);
    assert_eq!(checkpoint.finalized_block_hash, *genesis.hash().as_ref());
    drop(view);
    sandbox.request_transfer("alice", 1, "bob");
    assert_eq!(sandbox.transactions.len(), 1);
    assert_eq!(
        sandbox.transactions[0].network_id(),
        Some(sandbox.state.network_id_ref())
    );
    let block = sandbox.block();
    block.assert_balances(INIT_BALANCE.clone());
    assert_eq!(
        block
            .block
            .as_ref()
            .expect("original queued carrier")
            .header()
            .prev_block_hash(),
        Some(genesis.hash())
    );
}
impl Sandbox {
    fn trigger_registration_metadata(&self, data_scope: bool) -> Metadata {
        let height = u64::try_from(self.state.view().height()).unwrap_or(u64::MAX);
        let registered_ms = self
            .state
            .view()
            .latest_block()
            .expect("completed original State read")
            .map(|block| block.header().creation_time().as_millis())
            .and_then(|ms| u64::try_from(ms).ok())
            .unwrap_or(0);
        let mut metadata = Metadata::default();
        let key_height = "__registered_block_height"
            .parse::<Name>()
            .expect("registered block height metadata key");
        let key_time = "__registered_at_ms"
            .parse::<Name>()
            .expect("registered timestamp metadata key");
        metadata.insert(key_height, Json::new(height));
        metadata.insert(key_time, Json::new(registered_ms));
        if data_scope {
            for (key, value) in crate::smartcontracts::isi::triggers::global_data_trigger_scope_metadata_for_testing(
                &GENESIS_ACCOUNT.id,
            )
            .iter()
            {
                metadata.insert(key.clone(), value.clone());
            }
        }
        metadata
    }
    /// Add a time trigger that transfers the test asset after a timer fires.
    ///
    /// Enqueues a time-based trigger which moves `quantity` units from `src`
    /// to `dest` on each firing. The trigger is configured for infinite repeats
    /// in the sandbox unless otherwise specified by a labeled variant.
    #[must_use]
    pub fn with_time_trigger_transfer(self, src: &str, quantity: u32, dest: &str) -> Self {
        self.with_time_trigger_transfer_internal(src, quantity, dest, Repeats::Indefinitely, 0)
    }
    /// Add a labeled time trigger variant for test disambiguation.
    #[must_use]
    pub fn with_time_trigger_transfer_labeled(
        self,
        src: &str,
        quantity: u32,
        dest: &str,
        label: u32,
    ) -> Self {
        self.with_time_trigger_transfer_internal(src, quantity, dest, Repeats::Indefinitely, label)
    }
    fn with_time_trigger_transfer_internal(
        self,
        src: &str,
        quantity: u32,
        dest: &str,
        repeats: Repeats,
        label: u32,
    ) -> Self {
        let mut block = self.state.world.triggers.block();
        let mut transaction = block.transaction();
        let trigger = Trigger::new(
            format!("time-{src}-{dest}-{label}").parse().unwrap(),
            Action::new(
                transfer(src, quantity, dest),
                repeats,
                GENESIS_ACCOUNT.id.clone(),
                TimeEventFilter::new(ExecutionTime::PreCommit),
            )
            .expect("sandbox time-trigger action satisfies validation invariants")
            .with_metadata(self.trigger_registration_metadata(false)),
        )
        .try_into()
        .unwrap();
        transaction.add_time_trigger(trigger).unwrap();
        transaction.apply();
        block.commit();
        self
    }
    /// Add a data trigger that reacts to asset-added events and forwards funds.
    #[must_use]
    pub fn with_data_trigger_transfer(self, src: &str, quantity: u32, dest: &str) -> Self {
        self.with_data_trigger_transfer_quantity_internal(
            src,
            Quantity::from(quantity),
            dest,
            Repeats::Indefinitely,
            0,
        )
    }
    /// Add a single-use data trigger that fires at most once.
    #[must_use]
    pub fn with_data_trigger_transfer_once(self, src: &str, quantity: u32, dest: &str) -> Self {
        self.with_data_trigger_transfer_quantity_internal(
            src,
            Quantity::from(quantity),
            dest,
            Repeats::Exactly(1),
            0,
        )
    }
    /// Add a labeled data trigger for disambiguation between similar triggers in tests.
    #[must_use]
    pub fn with_data_trigger_transfer_labeled(
        self,
        src: &str,
        quantity: u32,
        dest: &str,
        label: u32,
    ) -> Self {
        self.with_data_trigger_transfer_quantity_internal(
            src,
            Quantity::from(quantity),
            dest,
            Repeats::Indefinitely,
            label,
        )
    }
    /// Add a data trigger with an explicit [`Quantity`] amount.
    #[must_use]
    pub fn with_data_trigger_transfer_quantity(
        self,
        src: &str,
        amount: Quantity,
        dest: &str,
    ) -> Self {
        self.with_data_trigger_transfer_quantity_internal(
            src,
            amount,
            dest,
            Repeats::Indefinitely,
            0,
        )
    }
    fn with_data_trigger_transfer_quantity_internal(
        self,
        src: &str,
        amount: Quantity,
        dest: &str,
        repeats: Repeats,
        label: u32,
    ) -> Self {
        let mut block = self.state.world.triggers.block();
        let mut transaction = block.transaction();
        let trigger = Trigger::new(
            format!("data-{src}-{dest}-{label}").parse().unwrap(),
            Action::new(
                [InstructionBox::from(Transfer::asset_quantity(
                    asset(src),
                    amount,
                    ACCOUNT[dest].id.clone(),
                ))],
                repeats,
                GENESIS_ACCOUNT.id.clone(),
                AssetEventFilter::new()
                    .for_events(AssetEventSet::Added)
                    .for_asset(asset(src)),
            )
            .expect("sandbox data-trigger action satisfies validation invariants")
            .with_metadata(self.trigger_registration_metadata(true)),
        )
        .try_into()
        .unwrap();
        transaction.add_data_trigger(trigger).unwrap();
        transaction.apply();
        block.commit();
        self
    }
    /// Limit the maximum smart contract execution depth in the sandbox state.
    #[must_use]
    pub fn with_max_execution_depth(self, depth: u8) -> Self {
        let mut world = self.state.world.block();
        world
            .parameters
            .set_parameter(Parameter::SmartContract(
                iroha_data_model::parameter::SmartContractParameter::ExecutionDepth(depth),
            ))
            .expect("valid fixture parameters");
        world.commit();
        self
    }
    /// Queue a single transfer transaction from `src` to `dest`.
    ///
    /// This is a convenience wrapper over [`Self::request_transfers_batched`] with
    /// `N_INSTRUCTIONS = 1`.
    pub fn request_transfer(&mut self, src: &str, quantity: u32, dest: &str) {
        self.request_transfers_batched::<1>(src, quantity, dest);
    }
    /// Queue a transaction consisting of repeated Transfer instructions.
    ///
    /// Builds and buffers a signed transaction that contains `N_INSTRUCTIONS`
    /// transfer instructions, each moving `quantity_per_instruction` units of
    /// the test asset from `src` to `dest`. The buffered transaction is
    /// included the next time a sandbox block is constructed via [`Self::block`].
    ///
    /// - `N_INSTRUCTIONS`: number of identical transfer instructions to include
    /// - `src`: source account name (e.g., "alice")
    /// - `quantity_per_instruction`: amount transferred by each instruction
    /// - `dest`: destination account name (e.g., "bob")
    pub fn request_transfers_batched<const N_INSTRUCTIONS: usize>(
        &mut self,
        src: &str,
        quantity_per_instruction: u32,
        dest: &str,
    ) {
        let transaction = {
            let instructions =
                transfers_batched::<N_INSTRUCTIONS>(src, quantity_per_instruction, dest);
            TransactionBuilder::new(
                self.state.network_id_ref().clone(),
                GENESIS_ACCOUNT.id.clone(),
                iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
            )
            .with_instructions(instructions)
            .sign(&GENESIS_ACCOUNT.key)
        };
        self.transactions.push(transaction);
    }
    /// Build a signed block from all queued transactions and open it for assertions.
    ///
    /// Consumes the currently queued transactions, packs them into a signed
    /// block and returns a [`SandboxBlock`] handle which allows asserting
    /// balances and applying the block to the in-memory test state.
    pub fn block(&mut self) -> SandboxBlock<'_> {
        let block: SignedBlock = {
            let transactions = {
                let signed = core::mem::take(&mut self.transactions);
                // Skip static analysis (AcceptedTransaction::accept)
                signed
                    .into_iter()
                    .map(|tx| AcceptedTransaction::new_unchecked(Cow::Owned(tx)))
                    .collect::<Vec<_>>()
            };
            BlockBuilder::new(transactions)
                .chain(
                    0,
                    self.state
                        .view()
                        .latest_block()
                        .expect("completed original State read")
                        .as_deref(),
                )
                .sign(&GENESIS_ACCOUNT.key)
                .unpack(|_| {})
                .into()
        };
        let (state, recording) = ValidBlock::start_component_execution(&block, &self.state)
            .expect("sandbox original execution owner");
        SandboxBlock {
            state,
            block: Some(block),
            recording: Some(recording),
        }
    }
}
impl SandboxBlock<'_> {
    /// Validate and commit the prepared block to the sandbox state.
    ///
    /// Returns the list of emitted events together with the committed
    /// block for further inspection in tests.
    pub fn apply(&mut self) -> (Vec<EventBox>, CommittedBlock) {
        let valid = ValidBlock::validate_unchecked(
            core::mem::take(&mut self.block).unwrap(),
            &mut self.state,
            self.recording.take().expect("original execution recorder"),
        )
        .unpack(|_| {});
        let committed = valid
            .commit_unchecked(crate::block::reserve_block_for_tests())
            .unpack(|_| {});
        let events = self.state.apply_without_execution(
            &committed,
            // topology in state is only used by sumeragi
            vec![],
        );
        (events, committed)
    }
    /// Assert that selected accounts have the expected balances.
    ///
    /// The `expected` map specifies accounts (by short name like "alice")
    /// and their expected balances of the sandbox test asset. Only the
    /// accounts present in `expected` are checked.
    pub fn assert_balances(&self, expected: impl Into<AccountBalance>) {
        let expected = expected.into();
        let actual: AccountBalance = ACCOUNTS_STR
            .iter()
            .filter(|name| expected.contains_key(*name))
            .map(|name| {
                let balance_num = self.state.world.assets.get(&asset(name)).map_or_else(
                    || panic!("{name}'s asset not found"),
                    |asset| asset.0.clone(),
                );
                let balance = numeric_to_u64(balance_num.as_numeric()).unwrap_or_else(|error| {
                    panic!("account {name} has non-integer balance {balance_num}: {error:?}");
                });
                (*name, balance)
            })
            .collect();
        assert_eq!(actual, expected);
    }
}
