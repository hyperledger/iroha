//! Desktop views over Kagami's shared, persistent managed workspace.

mod accounts;
mod brand;
mod chrome;
mod develop;
mod endpoints;
mod home;
mod ledger;
mod theme;
mod widgets;

use eframe::egui;
use mochi_core::{
    ManagedBlockStream, ManagedEventStream, StatePage, StateQueryKind, TransactionPreview,
    developer::{
        ContractInput, DeveloperWorkspace, GeneratedPublishAction, GeneratedPublishOutcome,
        ManagedAttachmentPhase, ManagedAttachmentStatus, ManagedContext, ManagedDataspaceStatus,
        ManagedNetwork, ManagedPhase, ManagedStatus, PreparedLocalnet,
    },
    run_state_query,
};
use std::{
    collections::VecDeque,
    path::PathBuf,
    sync::mpsc::{self, Receiver, Sender},
    time::{Duration, Instant},
};
use widgets::icon;

/// Launch the desktop; the optional argument is a workspace directory, never a configuration file.
pub fn run(workspace: PathBuf) -> eframe::Result<()> {
    let mut viewport = egui::ViewportBuilder::default()
        .with_title("Mochi")
        .with_inner_size([1280.0, 840.0])
        .with_min_inner_size([920.0, 620.0]);
    if let Some(icon) = brand::window_icon() {
        viewport = viewport.with_icon(std::sync::Arc::new(icon));
    }
    eframe::run_native(
        "Mochi",
        eframe::NativeOptions {
            viewport,
            ..Default::default()
        },
        Box::new(move |creation| Ok(Box::new(Desktop::new(creation, workspace)))),
    )
}

type UiResult<T> = Result<T, String>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum View {
    Home,
    Accounts,
    Blocks,
    Activity,
    State,
    Composer,
    Contracts,
    Packages,
    Endpoints,
    Logs,
}
impl View {
    const ALL: [Self; 10] = [
        Self::Home,
        Self::Accounts,
        Self::Blocks,
        Self::Activity,
        Self::State,
        Self::Composer,
        Self::Contracts,
        Self::Packages,
        Self::Endpoints,
        Self::Logs,
    ];
    fn label(self) -> &'static str {
        match self {
            Self::Home => "Home",
            Self::Accounts => "Accounts",
            Self::Blocks => "Blocks",
            Self::Activity => "Activity",
            Self::State => "State",
            Self::Composer => "Transactions",
            Self::Contracts => "Contracts",
            Self::Packages => "Packages",
            Self::Endpoints => "Endpoints",
            Self::Logs => "Logs",
        }
    }
}

struct Selection {
    network: ManagedNetwork,
    phase: ManagedPhase,
    running: usize,
    failure: Option<String>,
    attachment: UiResult<Option<ManagedAttachmentStatus>>,
}

fn load_selection(workspace: &DeveloperWorkspace, name: Option<&str>) -> UiResult<Selection> {
    let network = workspace.network(name).map_err(|e| e.to_string())?;
    load_network_selection(workspace, network)
}

fn load_context_selection(
    workspace: &DeveloperWorkspace,
    expected: &ManagedContext,
) -> UiResult<Selection> {
    let network = workspace
        .network(Some(&expected.name))
        .map_err(|e| e.to_string())?;
    if &network.prepared().context != expected {
        return Err("Selected network was replaced; select it again.".into());
    }
    load_network_selection(workspace, network)
}

// Refresh the captured authority. Resolving its name again could silently adopt a generation
// that Kagami reset and recreated while the desktop remained open.
fn load_network_selection(
    workspace: &DeveloperWorkspace,
    network: ManagedNetwork,
) -> UiResult<Selection> {
    network.validate().map_err(|e| e.to_string())?;
    let status = workspace
        .status(&network.prepared().context.name)
        .map_err(|e| e.to_string())?;
    let attachment = workspace
        .dataspace_status(&network.prepared().context.name)
        .map_err(|e| e.to_string());
    validate_selection_observation(&network.prepared().context, &status, &attachment)?;
    // Include failed parent observations: they may not conceal a replaced local generation.
    network.validate().map_err(|e| e.to_string())?;
    Ok(Selection {
        network,
        phase: status.phase,
        running: status.running_peers,
        failure: status.failure,
        attachment: attachment.map(|status| status.map(|status| status.attachment)),
    })
}

fn validate_selection_observation(
    expected: &ManagedContext,
    status: &ManagedStatus,
    attachment: &UiResult<Option<ManagedDataspaceStatus>>,
) -> UiResult<()> {
    if &status.context != expected
        || attachment
            .as_ref()
            .ok()
            .and_then(Option::as_ref)
            .is_some_and(|status| &status.local.context != expected)
    {
        return Err("Selected network was replaced; select it again.".into());
    }
    Ok(())
}

// Even a queued success may update only the generation that is still displayed. An explicit
// Selected completion intentionally bypasses this automatic-observation admission.
fn validate_retained_selection(
    current: Option<&PreparedLocalnet>,
    observed: &PreparedLocalnet,
) -> UiResult<()> {
    if current.is_none_or(|current| current != observed) {
        return Err("Selected network was replaced; select it again.".into());
    }
    Ok(())
}

struct Opened {
    workspace: DeveloperWorkspace,
    names: Vec<String>,
    selected: UiResult<Option<Selection>>,
    profiles: UiResult<Vec<String>>,
}

fn open_workspace(path: PathBuf) -> UiResult<Opened> {
    let workspace = DeveloperWorkspace::open(&path).map_err(|e| e.to_string())?;
    inspect_workspace(workspace)
}

fn inspect_workspace(workspace: DeveloperWorkspace) -> UiResult<Opened> {
    inspect_workspace_with_selection(workspace, |workspace| {
        workspace
            .selected_name()
            .map_err(|e| e.to_string())
            .and_then(|name| {
                name.map(|name| load_selection(workspace, Some(&name)))
                    .transpose()
            })
    })
}

// Automatic completion observes only the action's captured authority. If failure preceded
// target capture, expose retained names for explicit selection without adopting a current name.
fn inspect_workspace_selection(
    workspace: DeveloperWorkspace,
    captured: Option<ManagedNetwork>,
) -> UiResult<Opened> {
    inspect_workspace_with_selection(workspace, |workspace| {
        captured
            .map(|network| load_network_selection(workspace, network))
            .transpose()
    })
}

fn inspect_workspace_with_selection(
    workspace: DeveloperWorkspace,
    observe: impl FnOnce(&DeveloperWorkspace) -> UiResult<Option<Selection>>,
) -> UiResult<Opened> {
    let profiles = workspace.network_profiles().map_err(|e| e.to_string());
    let names = workspace
        .contexts()
        .map_err(|e| e.to_string())?
        .into_iter()
        .map(|c| c.name)
        .collect::<Vec<_>>();
    let selected = observe(&workspace);
    Ok(Opened {
        workspace,
        names,
        selected,
        profiles,
    })
}

enum Message {
    Opened(UiResult<Opened>),
    Selected(UiResult<Selection>),
    SelectionObserved(UiResult<Selection>),
    LocalnetStarted {
        result: UiResult<Selection>,
        names: UiResult<Vec<String>>,
    },
    Reset(UiResult<Vec<String>>),
    Ledger(UiResult<accounts::LedgerSnapshot>),
    State(UiResult<StatePage>),
    Logs(UiResult<String>),
    Submitted(UiResult<String>),
    Review {
        evidence: String,
        decision: Sender<bool>,
    },
    Progress(String),
    Deployed {
        result: UiResult<String>,
        refreshed: UiResult<Opened>,
    },
    Published {
        result: UiResult<PublicationOutput>,
        refreshed: UiResult<Opened>,
    },
    Attached {
        result: UiResult<String>,
        refreshed: UiResult<Opened>,
    },
    AttachmentObserved {
        name: String,
        result: UiResult<Option<ManagedDataspaceStatus>>,
    },
}

struct Review {
    evidence: String,
    decision: Sender<bool>,
}

struct LocalnetDialog {
    name: String,
}

enum LocalnetDialogAction {
    Cancel,
    Start(String),
}

impl LocalnetDialog {
    fn new(names: &[String]) -> Self {
        let mut name = "local".to_owned();
        let mut suffix = 2;
        while names.contains(&name) {
            name = format!("local-{suffix}");
            suffix += 1;
        }
        Self { name }
    }

    fn show(
        &mut self,
        context: &egui::Context,
        names: &[String],
        busy: bool,
    ) -> Option<LocalnetDialogAction> {
        let palette = theme::palette(context);
        let mut action = None;
        let modal = egui::Modal::new(egui::Id::new("new-localnet")).show(context, |ui| {
            ui.set_width(440.0);
            widgets::card_title(ui, icon::NEW, "New localnet");
            ui.add_space(4.0);
            widgets::hint(
                ui,
                "Create four local validators and a funded account. No configuration files needed.",
            );
            widgets::hint(
                ui,
                "Your current environment stays available. The new localnet becomes selected when ready.",
            );
            ui.add_space(6.0);
            ui.label(widgets::eyebrow(palette, "Name"));
            ui.add(egui::TextEdit::singleline(&mut self.name).desired_width(f32::INFINITY));
            let name = self.name.trim();
            let exists = names.iter().any(|existing| existing == name);
            if exists {
                widgets::banner(
                    ui,
                    widgets::Tone::Warning,
                    "This name already exists. Choose it from the environment menu to resume it.",
                    false,
                );
            }
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                if ui.button("Cancel").clicked() {
                    action = Some(LocalnetDialogAction::Cancel);
                }
                if ui
                    .add_enabled(
                        !busy && !name.is_empty() && !exists,
                        widgets::primary_button(palette, "Create localnet"),
                    )
                    .clicked()
                {
                    action = Some(LocalnetDialogAction::Start(name.to_owned()));
                }
            });
        });
        if action.is_none() && modal.should_close() {
            action = Some(LocalnetDialogAction::Cancel);
        }
        action
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PublicationAction {
    Begin,
    Resume,
    Recover,
}

struct PublicationForm {
    manifest: String,
    package: String,
    detach: bool,
    operation_id: String,
}

impl Default for PublicationForm {
    fn default() -> Self {
        Self {
            manifest: ".".into(),
            package: String::new(),
            detach: false,
            operation_id: String::new(),
        }
    }
}

impl PublicationForm {
    fn action(&self, action: PublicationAction) -> UiResult<GeneratedPublishAction> {
        match action {
            PublicationAction::Begin => Ok(GeneratedPublishAction::Begin {
                package: optional_selector(&self.package)
                    .map(|value| value.parse())
                    .transpose()
                    .map_err(|error| format!("Invalid package selector: {error}"))?,
                detach: self.detach,
            }),
            PublicationAction::Resume | PublicationAction::Recover => {
                let operation_id = self
                    .operation_id
                    .trim()
                    .parse()
                    .map_err(|error| format!("Invalid publication operation ID: {error}"))?;
                Ok(if action == PublicationAction::Resume {
                    GeneratedPublishAction::Resume { operation_id }
                } else {
                    GeneratedPublishAction::Recover { operation_id }
                })
            }
        }
    }
}

// Presentation only. The canonical outcome owns all publication status and diagnostics.
struct PublicationOutput {
    exit_code: i32,
    stdout: String,
    stderr: String,
}

impl PublicationOutput {
    fn from_outcome(outcome: GeneratedPublishOutcome) -> UiResult<Self> {
        let rendered = outcome
            .render(Default::default())
            .map_err(|error| error.to_string())?;
        let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
        rendered
            .write_to(&mut stdout, &mut stderr)
            .map_err(|error| error.to_string())?;
        Ok(Self {
            exit_code: rendered.exit_code(),
            stdout: String::from_utf8(stdout).map_err(|error| error.to_string())?,
            stderr: String::from_utf8(stderr).map_err(|error| error.to_string())?,
        })
    }
}

/// The native workspace identity is separate from editable display text.
/// Rendering a non-Unicode path must not select its lossy Unicode counterpart.
struct WorkspacePath {
    native: PathBuf,
    text: String,
}

impl WorkspacePath {
    fn new(path: PathBuf) -> Self {
        Self {
            text: path.to_string_lossy().into_owned(),
            native: path,
        }
    }

    fn show(&mut self, ui: &mut egui::Ui) -> egui::Response {
        let response = ui.add(egui::TextEdit::singleline(&mut self.text).desired_width(320.0));
        if response.changed() {
            // A deliberate edit selects the typed path. An untouched display retains the
            // exact original native argument, including bytes Unicode cannot represent.
            self.native = PathBuf::from(&self.text);
        }
        response
    }
}

struct Desktop {
    runtime: Option<tokio::runtime::Runtime>,
    sender: Sender<(u64, Message)>,
    receiver: Receiver<(u64, Message)>,
    epoch: u64,
    busy: bool,
    /// Presentation only: the pending task was started by the developer, not by polling.
    foreground: bool,
    workspace_path: WorkspacePath,
    workspace: Option<DeveloperWorkspace>,
    names: Vec<String>,
    new_name: String,
    localnet_dialog: Option<LocalnetDialog>,
    profiles: UiResult<Vec<String>>,
    private_dialog: bool,
    private_alias: String,
    private_network: String,
    attaching: Option<String>,
    attachment_poll_pending: bool,
    attachment_progress: Option<ManagedDataspaceStatus>,
    selected: Option<Selection>,
    peer: usize,
    view: View,
    error: Option<String>,
    notice: Option<String>,
    reset_intent: bool,
    last_poll: Instant,
    brand: Option<brand::Brand>,
    /// Structured blocks from the observed validator's canonical stream, newest first.
    blocks_feed: VecDeque<ledger::BlockRow>,
    latest_height: Option<u64>,
    /// Accounts and holdings from the observed validator; cleared with the network.
    ledger: Option<accounts::LedgerSnapshot>,
    ledger_error: Option<String>,
    /// A committed block or submission made the ledger snapshot outdated.
    ledger_stale: bool,
    last_ledger_refresh: Instant,
    accounts_filter: String,
    quick: accounts::QuickActions,
    activity_kind: ledger::ActivityKind,
    activity_filter: String,
    /// `None` reads the supervisor log.
    logs_source: Option<usize>,
    endpoint_peer: usize,
    query: StateQueryKind,
    page: Option<StatePage>,
    filter: String,
    activity: VecDeque<String>,
    blocks: Option<(
        ManagedBlockStream,
        tokio::sync::broadcast::Receiver<mochi_core::BlockStreamEvent>,
    )>,
    events: Option<(
        ManagedEventStream,
        tokio::sync::broadcast::Receiver<mochi_core::EventStreamEvent>,
    )>,
    logs: String,
    drafts: String,
    action: usize,
    asset: String,
    quantity: String,
    destination: String,
    preview: Option<TransactionPreview>,
    submitted_hash: Option<String>,
    contract_path: String,
    contract_alias: String,
    package: String,
    contract: String,
    locked: bool,
    journal_path: String,
    review: Option<Review>,
    receipt: Option<String>,
    publication: PublicationForm,
    publication_output: Option<PublicationOutput>,
}

impl Desktop {
    fn new(creation: &eframe::CreationContext<'_>, path: PathBuf) -> Self {
        theme::install(&creation.egui_ctx);
        theme::install_fonts(&creation.egui_ctx);
        let mut app = Self::model(path);
        app.brand = brand::Brand::load(&creation.egui_ctx);
        app.open();
        app
    }

    fn model(path: PathBuf) -> Self {
        let (sender, receiver) = mpsc::channel();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build();
        let error = runtime
            .as_ref()
            .err()
            .map(|e| format!("Cannot start desktop task runtime: {e}"));
        Self {
            runtime: runtime.ok(),
            sender,
            receiver,
            epoch: 0,
            busy: false,
            foreground: false,
            workspace_path: WorkspacePath::new(path),
            workspace: None,
            names: Vec::new(),
            new_name: "local".into(),
            localnet_dialog: None,
            profiles: Ok(Vec::new()),
            private_dialog: false,
            private_alias: "myapp".into(),
            private_network: String::new(),
            attaching: None,
            attachment_poll_pending: false,
            attachment_progress: None,
            selected: None,
            peer: 0,
            view: View::Home,
            error,
            notice: None,
            reset_intent: false,
            last_poll: Instant::now(),
            brand: None,
            blocks_feed: VecDeque::new(),
            latest_height: None,
            ledger: None,
            ledger_error: None,
            ledger_stale: false,
            last_ledger_refresh: Instant::now(),
            accounts_filter: String::new(),
            quick: accounts::QuickActions::default(),
            activity_kind: ledger::ActivityKind::All,
            activity_filter: String::new(),
            logs_source: None,
            endpoint_peer: 0,
            query: StateQueryKind::Accounts,
            page: None,
            filter: String::new(),
            activity: VecDeque::new(),
            blocks: None,
            events: None,
            logs: String::new(),
            drafts: "[]".into(),
            action: 0,
            asset: String::new(),
            quantity: "1".into(),
            destination: String::new(),
            preview: None,
            submitted_hash: None,
            contract_path: String::new(),
            contract_alias: String::new(),
            package: String::new(),
            contract: String::new(),
            locked: false,
            journal_path: String::new(),
            review: None,
            receipt: None,
            publication: PublicationForm::default(),
            publication_output: None,
        }
    }

    fn spawn(&mut self, work: impl FnOnce() -> Message + Send + 'static) {
        self.error = None;
        self.notice = None;
        self.spawn_task(work);
        self.foreground = true;
    }

    fn spawn_task(&mut self, work: impl FnOnce() -> Message + Send + 'static) {
        self.busy = true;
        self.foreground = false;
        let sender = self.sender.clone();
        let epoch = self.epoch;
        std::thread::spawn(move || {
            let _ = sender.send((epoch, work()));
        });
    }

    fn clear_network(&mut self) {
        self.selected = None;
        self.peer = 0;
        self.blocks = None;
        self.events = None;
        self.page = None;
        self.logs.clear();
        self.activity.clear();
        self.blocks_feed.clear();
        self.latest_height = None;
        self.ledger = None;
        self.ledger_error = None;
        self.ledger_stale = false;
        // Generated test keys live only as long as the environment they were made for.
        self.quick.generated = None;
        self.quick.reveal_key = false;
        self.logs_source = None;
        self.endpoint_peer = 0;
        self.preview = None;
        self.submitted_hash = None;
        self.receipt = None;
        self.publication_output = None;
        self.publication.operation_id.clear();
        self.notice = None;
        self.reset_intent = false;
    }

    // Observations can withdraw a stale network, but completed evidence belongs to its
    // original operation and survives until an explicit selection or replacement action.
    fn retain_completed_evidence(&mut self, observe: impl FnOnce(&mut Self)) {
        let receipt = self.receipt.take();
        let notice = self.notice.take();
        let publication_output = self.publication_output.take();
        let operation_id = std::mem::take(&mut self.publication.operation_id);
        observe(self);
        self.receipt = receipt;
        self.notice = notice;
        self.publication_output = publication_output;
        self.publication.operation_id = operation_id;
    }

    fn withdraw_observed_network(&mut self) {
        self.retain_completed_evidence(Self::clear_network);
    }

    fn install_observed_workspace(&mut self, opened: Opened) {
        self.retain_completed_evidence(|desktop| desktop.install_opened(opened));
    }

    fn open(&mut self) {
        self.epoch = self.epoch.wrapping_add(1);
        self.clear_network();
        self.workspace = None;
        self.names.clear();
        self.new_name = "local".into();
        self.localnet_dialog = None;
        self.profiles = Ok(Vec::new());
        self.private_dialog = false;
        self.attaching = None;
        self.attachment_progress = None;
        self.attachment_poll_pending = false;
        let path = self.workspace_path.native.clone();
        self.spawn(move || Message::Opened(open_workspace(path)));
    }

    fn select(&mut self, name: String) {
        let Some(workspace) = self.workspace.clone() else {
            return;
        };
        self.epoch = self.epoch.wrapping_add(1);
        self.clear_network();
        self.spawn(move || {
            Message::Selected(
                workspace
                    .select(&name)
                    .map_err(|e| e.to_string())
                    .and_then(|expected| load_context_selection(&workspace, &expected)),
            )
        });
    }

    fn lifecycle(&mut self, start: bool) {
        let Some(workspace) = self.workspace.clone() else {
            return;
        };
        let captured = self
            .selected
            .as_ref()
            .map(|selected| selected.network.clone());
        let name = self.new_name.trim().to_owned();
        self.spawn(move || {
            if start {
                if let Some(network) = captured {
                    complete_localnet_start(
                        || {
                            workspace
                                .start(&network)
                                .map(|status| (status.phase, status.failure))
                                .map_err(|e| e.to_string())
                        },
                        || load_network_selection(&workspace, network.clone()),
                        || {
                            workspace
                                .contexts()
                                .map(|contexts| {
                                    contexts.into_iter().map(|context| context.name).collect()
                                })
                                .map_err(|e| e.to_string())
                        },
                    )
                } else {
                    complete_localnet_creation(&workspace, &name)
                }
            } else {
                Message::Selected(
                    captured
                        .ok_or_else(|| "Select an environment before stopping it.".to_owned())
                        .and_then(|network| {
                            workspace.stop(&network).map_err(|e| e.to_string())?;
                            load_network_selection(&workspace, network)
                        }),
                )
            }
        });
    }

    fn start_localnet(&mut self, name: String) {
        let Some(workspace) = self.workspace.clone() else {
            return;
        };
        self.spawn(move || complete_localnet_creation(&workspace, &name));
    }

    fn attach(&mut self) {
        let Some(workspace) = self.workspace.clone() else {
            return;
        };
        let alias = self.private_alias.trim().to_owned();
        let network = self.private_network.clone();
        if alias.is_empty()
            || !self
                .profiles
                .as_ref()
                .is_ok_and(|profiles| profiles.contains(&network))
        {
            return;
        }
        let captured = self
            .selected
            .as_ref()
            .map(|selected| selected.network.clone());
        self.epoch = self.epoch.wrapping_add(1);
        self.private_dialog = false;
        self.attaching = Some(alias.clone());
        self.attachment_poll_pending = false;
        self.attachment_progress = None;
        self.last_poll = Instant::now();
        // A failed attachment must not discard completed work or adopt a mutable name.
        self.retain_completed_evidence(|desktop| {
            desktop.clear_network();
            desktop.spawn(move || {
                let outcome = workspace
                    .start_dataspace(&alias, &network, &alias)
                    .map_err(|e| e.to_string());
                let refreshed =
                    inspect_workspace_with_selection(workspace, |workspace| match &outcome {
                        Ok(status) => {
                            load_context_selection(workspace, &status.local.context).map(Some)
                        }
                        Err(_) => captured
                            .map(|network| load_network_selection(workspace, network))
                            .transpose(),
                    });
                Message::Attached {
                    result: outcome.map(|status| attachment_summary(&status.attachment)),
                    refreshed,
                }
            });
        });
    }

    fn observe_attachment(&mut self) {
        let (Some(workspace), Some(name)) = (self.workspace.clone(), self.attaching.clone()) else {
            return;
        };
        self.attachment_poll_pending = true;
        self.last_poll = Instant::now();
        let sender = self.sender.clone();
        let epoch = self.epoch;
        std::thread::spawn(move || {
            let result = workspace.dataspace_status(&name).map_err(|e| e.to_string());
            let _ = sender.send((epoch, Message::AttachmentObserved { name, result }));
        });
    }

    fn install_opened(&mut self, opened: Opened) {
        self.workspace = Some(opened.workspace);
        self.names = opened.names;
        self.profiles = opened.profiles;
        if let Ok(profiles) = &self.profiles
            && !profiles.contains(&self.private_network)
        {
            self.private_network = profiles.first().cloned().unwrap_or_default();
        }
        match opened.selected {
            Ok(Some(selected)) => self.install_selection(selected),
            Ok(None) => self.clear_network(),
            Err(error) => {
                self.clear_network();
                self.error = Some(error);
            }
        }
    }

    fn refresh_selection(&mut self) {
        let (Some(workspace), Some(selected)) = (self.workspace.clone(), self.selected.as_ref())
        else {
            return;
        };
        let network = selected.network.clone();
        self.last_poll = Instant::now();
        // A background failure withdraws live context without erasing completed deployment evidence.
        self.spawn_task(move || {
            Message::SelectionObserved(load_network_selection(&workspace, network))
        });
    }

    fn install_selection(&mut self, selection: Selection) {
        let changed = self
            .selected
            .as_ref()
            .is_none_or(|old| old.network.prepared() != selection.network.prepared());
        if changed {
            self.clear_network();
        }
        let name = selection.network.prepared().context.name.clone();
        self.new_name = name.clone();
        if !self.names.contains(&name) {
            self.names.push(name);
            self.names.sort();
        }
        self.selected = Some(selection);
        self.last_poll = Instant::now();
        self.connect_streams();
    }

    fn connect_streams(&mut self) {
        let Some(selected) = self.selected.as_ref() else {
            return;
        };
        if selected.phase != ManagedPhase::Ready {
            self.blocks = None;
            self.events = None;
            return;
        }
        if self.blocks.is_some() && self.events.is_some() {
            return;
        }
        let Some(runtime) = &self.runtime else {
            return;
        };
        match selected.network.ledger_reader(self.peer) {
            Ok(reader) => {
                let label = format!("validator {}", self.peer + 1);
                let blocks =
                    ManagedBlockStream::spawn(runtime.handle(), label.clone(), reader.clone());
                let block_rx = blocks.subscribe();
                let events = ManagedEventStream::spawn(runtime.handle(), label, reader);
                let event_rx = events.subscribe();
                self.blocks = Some((blocks, block_rx));
                self.events = Some((events, event_rx));
            }
            Err(error) => self.error = Some(error.to_string()),
        }
    }

    fn poll(&mut self) {
        while let Ok((epoch, message)) = self.receiver.try_recv() {
            if epoch != self.epoch {
                continue;
            }
            match message {
                Message::Review { evidence, decision } => {
                    self.review = Some(Review { evidence, decision });
                    continue;
                }
                Message::Progress(progress) => {
                    push_activity(&mut self.activity, progress);
                    continue;
                }
                Message::AttachmentObserved { name, result } => {
                    if self.attaching.as_deref() == Some(&name) {
                        self.attachment_poll_pending = false;
                        if let Ok(Some(status)) = result {
                            self.attachment_progress = Some(status);
                        }
                    }
                    continue;
                }
                _ => {
                    self.busy = false;
                    self.foreground = false;
                }
            }
            match message {
                Message::Opened(result) => match result {
                    Ok(opened) => self.install_opened(opened),
                    Err(error) => self.error = Some(error),
                },
                Message::Selected(result) => match result {
                    Ok(selected) => self.install_selection(selected),
                    Err(error) => {
                        self.clear_network();
                        self.error = Some(error);
                    }
                },
                Message::SelectionObserved(result) => {
                    let result = result.and_then(|selection| {
                        validate_retained_selection(
                            self.selected
                                .as_ref()
                                .map(|current| current.network.prepared()),
                            selection.network.prepared(),
                        )?;
                        Ok(selection)
                    });
                    match result {
                        Ok(selected) => self.install_selection(selected),
                        Err(error) => {
                            self.withdraw_observed_network();
                            self.error = Some(error);
                        }
                    }
                }
                Message::LocalnetStarted { result, names } => {
                    match names {
                        Ok(names) => self.names = names,
                        Err(error) => self.error = Some(error),
                    }
                    match result {
                        Ok(selected) => self.install_selection(selected),
                        Err(error) => self.error = Some(error),
                    }
                }
                Message::Reset(result) => match result {
                    Ok(names) => {
                        self.clear_network();
                        self.names = names;
                        self.notice = Some(
                            "Local data reset. Any remote attachment history remains retained."
                                .into(),
                        );
                    }
                    Err(error) => self.error = Some(error),
                },
                Message::Ledger(result) => match result {
                    Ok(snapshot) => {
                        self.ledger = Some(snapshot);
                        self.ledger_error = None;
                    }
                    Err(error) => self.ledger_error = Some(error),
                },
                Message::State(result) => match result {
                    Ok(page) => self.page = Some(page),
                    Err(error) => self.error = Some(error),
                },
                Message::Logs(result) => match result {
                    Ok(logs) => self.logs = logs,
                    Err(error) => self.error = Some(error),
                },
                Message::Submitted(result) => match result {
                    Ok(message) => {
                        self.notice = Some(message);
                        self.ledger_stale = true;
                    }
                    Err(error) => self.error = Some(error),
                },
                Message::Deployed { result, refreshed } => {
                    self.review = None;
                    match refreshed {
                        Ok(opened) => self.install_observed_workspace(opened),
                        Err(_) if result.is_ok() => {
                            self.withdraw_observed_network();
                            self.notice = Some(
                                "Deployment applied. Workspace observation is unavailable; reopen the workspace to refresh it.".into(),
                            );
                        }
                        Err(error) => {
                            self.withdraw_observed_network();
                            self.error = Some(error);
                        }
                    }
                    match result {
                        Ok(receipt) => self.receipt = Some(receipt),
                        Err(error) => self.error = Some(error),
                    }
                }
                Message::Published { result, refreshed } => {
                    match refreshed {
                        Ok(opened) => self.install_observed_workspace(opened),
                        Err(error) => {
                            self.withdraw_observed_network();
                            self.error = Some(format!("Workspace refresh failed: {error}."))
                        }
                    }
                    match result {
                        Ok(output) => self.publication_output = Some(output),
                        Err(error) => self.error = Some(error),
                    }
                }
                Message::Attached { result, refreshed } => {
                    self.attaching = None;
                    self.attachment_poll_pending = false;
                    self.attachment_progress = None;
                    if result.is_ok() {
                        // Completed attachment replaces the previous operation's presentation,
                        // even if the new workspace observation is unavailable.
                        self.clear_network();
                    }
                    match refreshed {
                        Ok(opened) if result.is_ok() => self.install_opened(opened),
                        Ok(opened) => self.install_observed_workspace(opened),
                        Err(error) => {
                            self.withdraw_observed_network();
                            self.error = Some(error);
                        }
                    }
                    match result {
                        Ok(message) => self.notice = Some(message),
                        Err(error) => self.error = Some(error),
                    }
                }
                Message::Review { .. }
                | Message::Progress(_)
                | Message::AttachmentObserved { .. } => {}
            }
        }
        if let Some((_, receiver)) = self.blocks.as_mut() {
            let (feed, latest, stale) = (
                &mut self.blocks_feed,
                &mut self.latest_height,
                &mut self.ledger_stale,
            );
            drain_stream(receiver, &mut self.activity, block_activity, |event| {
                if let mochi_core::BlockStreamEvent::Block {
                    summary, raw_len, ..
                } = event
                    && let Some(height) = ledger::record_block(feed, summary, *raw_len)
                {
                    *latest = Some(latest.map_or(height, |current| current.max(height)));
                    *stale = true;
                }
            });
        }
        if let Some((_, receiver)) = self.events.as_mut() {
            drain_stream(receiver, &mut self.activity, event_activity, |_| {});
        }
        if self.attaching.is_some()
            && !self.attachment_poll_pending
            && self.last_poll.elapsed() >= Duration::from_secs(1)
        {
            self.observe_attachment();
        } else if !self.busy
            && self.selected.is_some()
            && self.last_poll.elapsed() >= Duration::from_secs(5)
        {
            self.refresh_selection();
        }
        // Balances follow committed blocks; idle chains make no blocks and cause no queries.
        let wanted = self.ledger_stale || (self.ledger.is_none() && self.ledger_error.is_none());
        if wanted
            && !self.busy
            && self.ready()
            && self.last_ledger_refresh.elapsed() >= Duration::from_secs(2)
        {
            self.refresh_ledger();
        }
    }

    fn refresh_ledger(&mut self) {
        let Some(selected) = &self.selected else {
            return;
        };
        if self.busy || selected.phase != ManagedPhase::Ready {
            return;
        }
        let Some(handle) = self.runtime.as_ref().map(|r| r.handle().clone()) else {
            return;
        };
        let network = selected.network.clone();
        let peer = self.peer;
        self.ledger_stale = false;
        self.last_ledger_refresh = Instant::now();
        // Background observation: keep the foreground notice, such as a just-applied hash.
        self.spawn_task(move || Message::Ledger(fetch_ledger(&handle, &network, peer)));
    }

    /// Stream from another validator. Observations bound to the previous one are dropped.
    fn observe_peer(&mut self, index: usize) {
        if self.busy || index == self.peer {
            return;
        }
        self.peer = index;
        self.blocks = None;
        self.events = None;
        self.page = None;
        self.blocks_feed.clear();
        self.latest_height = None;
        self.ledger = None;
        self.ledger_error = None;
        self.connect_streams();
    }

    /// Accept a contract dropped anywhere on the window as deployment input.
    fn accept_dropped_files(&mut self, context: &egui::Context) {
        let dropped = context.input(|input| {
            input
                .raw
                .dropped_files
                .iter()
                .filter_map(|file| file.path.clone())
                .collect::<Vec<_>>()
        });
        let Some(path) = dropped.into_iter().next() else {
            return;
        };
        if !develop::is_contract_input(&path) {
            self.error = Some(format!(
                "Mochi deploys .ko sources, .to bytecode, Musubi.toml manifests and package directories; {} is none of these.",
                path.display()
            ));
            return;
        }
        // A lossy rendering could name a different file, so only exact Unicode paths are taken.
        let Some(text) = path.to_str() else {
            self.error = Some(
                "The dropped path is not valid Unicode; type it into Contract path instead.".into(),
            );
            return;
        };
        self.contract_path = text.to_owned();
        self.view = View::Contracts;
        let name = path.file_name().map_or_else(
            || text.to_owned(),
            |name| name.to_string_lossy().into_owned(),
        );
        widgets::notify(context, format!("Ready to deploy {name}"));
    }

    fn fetch_state(&mut self, next: bool) {
        let Some(selected) = &self.selected else {
            return;
        };
        let network = selected.network.clone();
        let peer = self.peer;
        let kind = self.query;
        let cursor = if next {
            self.page.as_ref().and_then(|p| p.cursor.clone())
        } else {
            None
        };
        let Some(handle) = self.runtime.as_ref().map(|r| r.handle().clone()) else {
            return;
        };
        self.spawn(move || {
            Message::State((|| {
                let client = network.observer(peer).map_err(|e| e.to_string())?;
                let result = handle
                    .block_on(run_state_query(
                        client,
                        &network.signer(),
                        network.address_discriminant(),
                        kind,
                        cursor,
                        std::num::NonZeroU64::new(50),
                    ))
                    .map_err(|e| e.to_string());
                network.validate().map_err(|e| e.to_string())?;
                result
            })())
        });
    }

    fn deploy(&mut self, resume: bool) {
        let Some(workspace) = self.workspace.clone() else {
            return;
        };
        let mut captured = self
            .selected
            .as_ref()
            .map(|selected| selected.network.clone());
        let path = workspace.resolve_path(std::path::Path::new(if resume {
            &self.journal_path
        } else {
            &self.contract_path
        }));
        let alias = if self.contract_alias.trim().is_empty() {
            None
        } else {
            Some(self.contract_alias.trim().to_owned())
        };
        let package = optional_selector(&self.package);
        let contract = optional_selector(&self.contract);
        let locked = self.locked;
        let sender = self.sender.clone();
        let epoch = self.epoch;
        self.receipt = None;
        self.spawn(move || {
            let result = (|| {
                let mut review = |preflight: &mochi_core::developer::DeploymentPreflight| {
                    let evidence = norito::json::to_string_pretty(&preflight.to_json()?)?;
                    let (decision, answer) = mpsc::channel();
                    sender
                        .send((epoch, Message::Review { evidence, decision }))
                        .map_err(|_| std::io::Error::other("desktop closed before review"))?;
                    if !answer.recv().unwrap_or(false) {
                        return Err(
                            std::io::Error::other("deployment cancelled before dispatch").into(),
                        );
                    }
                    Ok(())
                };
                let mut progress = |event| {
                    let _ = sender.send((epoch, Message::Progress(format!("{event:?}"))));
                };
                let completed = if resume {
                    workspace.resume(&path, captured.as_ref(), &mut review, &mut progress)
                } else {
                    let input = ContractInput::from_path(&path, package, contract, locked)
                        .map_err(|e| e.to_string())?;
                    let alias = alias
                        .map(|value| value.parse())
                        .transpose()
                        .map_err(|e| format!("Invalid contract alias: {e}"))?;
                    workspace.deploy(&input, captured.as_ref(), alias, &mut review, &mut progress)
                }
                .map_err(|e| e.to_string())?;
                captured = Some(completed.network);
                let run = completed.outcome.map_err(|e| e.to_string())?;
                let mut result = run.execution_summary();
                if let Some(lifecycle) = &run.lifecycle {
                    result.push('\n');
                    result.push_str(&lifecycle.summary());
                }
                if let Some(parent) = run.parent_summary() {
                    result.push('\n');
                    result.push_str(&parent);
                }
                result.push('\n');
                result.push_str(
                    &norito::json::to_string_pretty(&run.to_json().map_err(|e| e.to_string())?)
                        .map_err(|e| e.to_string())?,
                );
                Ok(result)
            })();
            let refreshed = inspect_workspace_selection(workspace, captured);
            Message::Deployed { result, refreshed }
        });
    }

    fn publish_package(&mut self, action: PublicationAction) {
        if self.busy {
            return;
        }
        let action = match self.publication.action(action) {
            Ok(action) => action,
            Err(error) => {
                self.error = Some(error);
                return;
            }
        };
        let Some(workspace) = self.workspace.clone() else {
            return;
        };
        let mut captured = self
            .selected
            .as_ref()
            .map(|selected| selected.network.clone());
        let manifest = PathBuf::from(if self.publication.manifest.is_empty() {
            "."
        } else {
            &self.publication.manifest
        });
        self.publication_output = None;
        self.notice = None;
        self.spawn(move || {
            let result = (|| {
                let completed = workspace
                    .publish_package(&manifest, captured.as_ref(), action)
                    .map_err(|error| error.to_string())?;
                captured = Some(completed.network);
                PublicationOutput::from_outcome(
                    completed.outcome.map_err(|error| error.to_string())?,
                )
            })();
            Message::Published {
                result,
                refreshed: inspect_workspace_selection(workspace, captured),
            }
        });
    }

    fn ready(&self) -> bool {
        self.selected
            .as_ref()
            .is_some_and(|s| s.phase == ManagedPhase::Ready)
    }

    fn review_dialog(&mut self, context: &egui::Context) {
        let Some(review) = &self.review else {
            return;
        };
        let palette = theme::palette(context);
        let mut decision = None;
        let viewport = context.content_rect();
        let width = (viewport.width() - 48.0).clamp(160.0, 760.0);
        let evidence_height = (viewport.height() - 220.0).clamp(40.0, 400.0);
        // Only the explicit buttons decide; clicking outside the dialog withholds approval.
        egui::Modal::new(egui::Id::new("deployment-review")).show(context, |ui| {
            ui.set_width(width);
            widgets::card_title(ui, icon::CONTRACTS, "Review deployment");
            ui.label(
                egui::RichText::new("Review the exact deployment and quoted fees")
                    .strong()
                    .color(palette.text),
            );
            egui::Frame::new()
                .fill(palette.inset)
                .corner_radius(egui::CornerRadius::same(10))
                .inner_margin(egui::Margin::same(10))
                .show(ui, |ui| {
                    egui::ScrollArea::vertical()
                        .max_height(evidence_height)
                        .show(ui, |ui| {
                            ui.add(
                                egui::Label::new(egui::RichText::new(&review.evidence).monospace())
                                    .wrap(),
                            );
                        });
                });
            ui.add_space(4.0);
            ui.horizontal_wrapped(|ui| {
                if ui
                    .add(widgets::primary_button(palette, "Deploy with these fees"))
                    .clicked()
                {
                    decision = Some(true);
                }
                if ui.button("Cancel").clicked() {
                    decision = Some(false);
                }
            });
        });
        if let Some(accepted) = decision
            && let Some(review) = self.review.take()
        {
            let _ = review.decision.send(accepted);
        }
    }

    fn private_dataspace_dialog(&mut self, context: &egui::Context) {
        if !self.private_dialog {
            return;
        }
        let palette = theme::palette(context);
        let modal = egui::Modal::new(egui::Id::new("private-dataspace")).show(context, |ui| {
            ui.set_width(460.0);
            widgets::card_title(ui, icon::PRIVATE, "Private dataspace");
            ui.add_space(4.0);
            widgets::hint(
                ui,
                "Run four private validators here and connect them to your selected network.",
            );
            widgets::hint(
                ui,
                "Contract data stays on this computer. The parent receives certified commitments.",
            );
            ui.add_space(6.0);
            ui.label(widgets::eyebrow(palette, "Name"));
            ui.add(egui::TextEdit::singleline(&mut self.private_alias).desired_width(f32::INFINITY));
            ui.label(widgets::eyebrow(palette, "Parent network"));
            let available = match &self.profiles {
                Ok(profiles) if !profiles.is_empty() => {
                    egui::ComboBox::from_id_salt("private-network")
                        .selected_text(&self.private_network)
                        .show_ui(ui, |ui| {
                            for name in profiles {
                                ui.selectable_value(&mut self.private_network, name.clone(), name);
                            }
                        });
                    true
                }
                Ok(_) => {
                    widgets::banner(
                        ui,
                        widgets::Tone::Info,
                        "This installation has no network profiles. Install a bundle that includes your network.",
                        false,
                    );
                    false
                }
                Err(error) => {
                    widgets::banner(
                        ui,
                        widgets::Tone::Warning,
                        &format!(
                            "Installed network profiles are unavailable. Localnets remain available.\n{}",
                            bounded_text(error)
                        ),
                        false,
                    );
                    false
                }
            };
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                if ui.button("Cancel").clicked() {
                    self.private_dialog = false;
                }
                if ui
                    .add_enabled(
                        available
                            && !self.busy
                            && self.workspace.is_some()
                            && !self.private_alias.trim().is_empty(),
                        widgets::primary_button(palette, "Start private dataspace"),
                    )
                    .clicked()
                {
                    self.attach();
                }
            });
        });
        if modal.should_close() {
            self.private_dialog = false;
        }
    }

    fn reset_dialog(&mut self, context: &egui::Context) {
        if !self.reset_intent {
            return;
        }
        let palette = theme::palette(context);
        let modal = egui::Modal::new(egui::Id::new("reset-environment")).show(context, |ui| {
            ui.set_width(440.0);
            widgets::card_title(ui, icon::RESET, "Reset local environment?");
            ui.add_space(4.0);
            widgets::banner(
                ui,
                widgets::Tone::Warning,
                "This removes the stopped environment's local keys and ledger. Its old ledger cannot be restored. Remote attachment history remains retained.",
                false,
            );
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                if ui.button("Cancel").clicked() {
                    self.reset_intent = false;
                }
                if ui
                    .add_enabled(
                        !self.busy,
                        widgets::tonal_button("Reset local data", palette.on_sakura, palette.aka),
                    )
                    .clicked()
                {
                    self.reset_intent = false;
                    if let (Some(workspace), Some(selected)) =
                        (self.workspace.clone(), &self.selected)
                    {
                        let network = selected.network.clone();
                        self.spawn(move || {
                            Message::Reset(
                                workspace
                                    .reset(&network)
                                    .map_err(|e| e.to_string())
                                    .and_then(|_| {
                                        workspace
                                            .contexts()
                                            .map(|contexts| {
                                                contexts.into_iter().map(|c| c.name).collect()
                                            })
                                            .map_err(|e| e.to_string())
                                    }),
                            )
                        });
                    }
                }
            });
        });
        if modal.should_close() {
            self.reset_intent = false;
        }
    }
}

impl Desktop {
    fn show(&mut self, context: &egui::Context) {
        let palette = theme::palette(context);
        self.accept_dropped_files(context);
        egui::TopBottomPanel::top("header")
            .frame(
                egui::Frame::new()
                    .fill(palette.panel)
                    .inner_margin(egui::Margin::symmetric(16, 8)),
            )
            .show(context, |ui| self.header(ui));
        egui::TopBottomPanel::top("status")
            .frame(
                egui::Frame::new()
                    .fill(palette.panel)
                    .inner_margin(egui::Margin::symmetric(20, 8)),
            )
            .show(context, |ui| self.status_strip(ui));
        egui::SidePanel::left("navigation")
            .resizable(false)
            .exact_width(200.0)
            .frame(
                egui::Frame::new()
                    .fill(palette.panel)
                    .inner_margin(egui::Margin::symmetric(10, 8)),
            )
            .show(context, |ui| self.navigation(ui));
        egui::CentralPanel::default()
            .frame(
                egui::Frame::new()
                    .fill(palette.background)
                    .inner_margin(egui::Margin::symmetric(24, 16)),
            )
            .show(context, |ui| {
                self.banners(ui);
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        match self.view {
                            View::Home => self.home(ui),
                            View::Accounts => self.accounts(ui),
                            View::Blocks => self.blocks(ui),
                            View::Activity => self.activity(ui),
                            View::State => self.state(ui),
                            View::Composer => self.composer(ui),
                            View::Contracts => self.contracts(ui),
                            View::Packages => self.packages(ui),
                            View::Endpoints => self.endpoints(ui),
                            View::Logs => self.logs(ui),
                        }
                        ui.add_space(24.0);
                    });
                if context.input(|input| !input.raw.hovered_files.is_empty()) {
                    let rect = ui.max_rect();
                    let painter = context.layer_painter(egui::LayerId::new(
                        egui::Order::Foreground,
                        egui::Id::new("mochi-drop-overlay"),
                    ));
                    painter.rect_filled(
                        rect,
                        egui::CornerRadius::same(16),
                        palette.background.gamma_multiply(0.85),
                    );
                    painter.rect_stroke(
                        rect.shrink(10.0),
                        egui::CornerRadius::same(16),
                        egui::Stroke::new(2.0, palette.sakura),
                        egui::StrokeKind::Inside,
                    );
                    painter.text(
                        rect.center(),
                        egui::Align2::CENTER_CENTER,
                        format!("{}  Drop a contract to deploy it", icon::DROP),
                        egui::FontId::proportional(22.0),
                        palette.sakura,
                    );
                }
            });
        self.reset_dialog(context);
        if let Some(dialog) = &mut self.localnet_dialog
            && let Some(action) = dialog.show(context, &self.names, self.busy)
        {
            self.localnet_dialog = None;
            if let LocalnetDialogAction::Start(name) = action {
                self.start_localnet(name);
            }
        }
        self.private_dataspace_dialog(context);
        self.review_dialog(context);
        widgets::show_toasts(context);
        context.request_repaint_after(Duration::from_millis(100));
    }
}

impl eframe::App for Desktop {
    fn update(&mut self, context: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll();
        self.show(context);
    }
}

fn optional_selector(value: &str) -> Option<String> {
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_owned())
}

fn complete_localnet_creation(workspace: &DeveloperWorkspace, name: &str) -> Message {
    let started = workspace.create_localnet(name).map_err(|e| e.to_string());
    let expected = started
        .as_ref()
        .map(|status| status.context.clone())
        .map_err(Clone::clone);
    complete_localnet_start(
        || started.map(|status| (status.phase, status.failure)),
        || load_context_selection(workspace, &expected?),
        || {
            workspace
                .contexts()
                .map(|contexts| contexts.into_iter().map(|context| context.name).collect())
                .map_err(|e| e.to_string())
        },
    )
}

// Both startup controls retain the menu on ordinary failure. Only a Ready return followed
// by a fresh Ready observation can replace the desktop selection; the shared store owns it.
fn complete_localnet_start(
    start: impl FnOnce() -> UiResult<(ManagedPhase, Option<String>)>,
    observe: impl FnOnce() -> UiResult<Selection>,
    names: impl FnOnce() -> UiResult<Vec<String>>,
) -> Message {
    let result = start().and_then(|(phase, failure)| {
        require_ready_localnet(phase, failure.as_deref())?;
        let selection = observe()?;
        require_ready_localnet(selection.phase, selection.failure.as_deref())?;
        Ok(selection)
    });
    let names = names();
    Message::LocalnetStarted { result, names }
}

fn require_ready_localnet(phase: ManagedPhase, failure: Option<&str>) -> UiResult<()> {
    if phase == ManagedPhase::Ready {
        return Ok(());
    }
    let mut message = format!(
        "Localnet startup ended in {phase:?}. Its prepared generation is retained; choose its name from the environment menu to inspect or resume it."
    );
    if let Some(failure) = failure {
        message.push(' ');
        message.push_str(&bounded_text(failure));
    }
    Err(message)
}

fn attachment_summary(status: &ManagedAttachmentStatus) -> String {
    let phase =
        if status.stage == ManagedAttachmentPhase::Attached && status.parent_confirmed.is_none() {
            "awaiting verified receipt"
        } else {
            status.stage.as_str()
        };
    let mut summary = format!("Parent {} · {phase}", status.network);
    if let Some(confirmed) = &status.parent_confirmed {
        summary.push_str(&format!(
            " · last confirmed child block #{} in parent block #{}",
            confirmed.child.height, confirmed.parent_height
        ));
    }
    summary
}

fn attachment_details(ui: &mut egui::Ui, status: &ManagedAttachmentStatus) {
    let palette = theme::palette(ui.ctx());
    ui.label(egui::RichText::new(attachment_summary(status)).color(palette.text));
    if let Some(cursor) = &status.local_successor {
        ui.label(
            egui::RichText::new(format!("Last observed private block #{}", cursor.height))
                .color(palette.muted),
        );
    }
    if let Some(wallet) = &status.wallet_status {
        ui.label(egui::RichText::new(format!("Parent operation: {wallet}")).color(palette.muted));
    }
    if let Some(failure) = &status.failure {
        ui.colored_label(palette.aka, failure.to_string());
    }
}

/// Accounts and holdings of the exact captured generation, read through one validator.
fn fetch_ledger(
    handle: &tokio::runtime::Handle,
    network: &ManagedNetwork,
    peer: usize,
) -> UiResult<accounts::LedgerSnapshot> {
    let client = network.observer(peer).map_err(|e| e.to_string())?;
    let signer = network.signer();
    let discriminant = network.address_discriminant();
    let query = |kind, size| {
        handle
            .block_on(run_state_query(
                client.clone(),
                &signer,
                discriminant,
                kind,
                None,
                std::num::NonZeroU64::new(size),
            ))
            .map_err(|e| e.to_string())
    };
    let accounts = query(StateQueryKind::Accounts, 100)?;
    let holdings = query(StateQueryKind::Assets, 200)?;
    let definitions = query(StateQueryKind::AssetDefinitions, 100)?;
    network.validate().map_err(|e| e.to_string())?;
    Ok(accounts::LedgerSnapshot::new(
        accounts,
        holdings,
        &definitions,
    ))
}

fn push_activity(activity: &mut VecDeque<String>, value: String) {
    activity.push_back(value.chars().take(4096).collect());
    while activity.len() > 256 {
        activity.pop_front();
    }
}

fn bounded_text(value: &str) -> String {
    value.chars().take(4096).collect()
}

fn block_activity(event: &mochi_core::BlockStreamEvent) -> String {
    use mochi_core::BlockStreamEvent;
    match event {
        BlockStreamEvent::Block {
            summary, raw_len, ..
        } => format!(
            "Block #{} · {} transactions · {} rejected · {} bytes · {}",
            summary.height,
            summary.transaction_count,
            summary.rejected_transaction_count,
            raw_len,
            bounded_text(&summary.hash_hex)
        ),
        BlockStreamEvent::Text { text } => bounded_text(text),
        BlockStreamEvent::DecodeError { error } => {
            format!("Block {:?}: {}", error.stage, bounded_text(&error.message))
        }
        BlockStreamEvent::Lagged { skipped } => format!("Block stream skipped {skipped} messages"),
        BlockStreamEvent::Closed => "Block stream closed".into(),
    }
}

fn event_activity(event: &mochi_core::EventStreamEvent) -> String {
    use mochi_core::EventStreamEvent;
    match event {
        EventStreamEvent::Event {
            summary, raw_len, ..
        } => format!(
            "{} · {} · {} bytes · {}",
            summary.category.label(),
            bounded_text(&summary.label),
            raw_len,
            bounded_text(summary.detail.as_deref().unwrap_or_default())
        ),
        EventStreamEvent::Text { text } => bounded_text(text),
        EventStreamEvent::DecodeError { error } => {
            format!("Event {:?}: {}", error.stage, bounded_text(&error.message))
        }
        EventStreamEvent::Lagged { skipped } => format!("Event stream skipped {skipped} messages"),
        EventStreamEvent::Closed => "Event stream closed".into(),
    }
}

fn drain_stream<T: Clone>(
    receiver: &mut tokio::sync::broadcast::Receiver<T>,
    activity: &mut VecDeque<String>,
    summarize: impl Fn(&T) -> String,
    mut record: impl FnMut(&T),
) {
    for _ in 0..64 {
        match receiver.try_recv() {
            Ok(event) => {
                record(&event);
                push_activity(activity, summarize(&event));
            }
            Err(tokio::sync::broadcast::error::TryRecvError::Lagged(count)) => push_activity(
                activity,
                format!(
                    "Stream display skipped {count} messages; inspect canonical block history for complete data."
                ),
            ),
            Err(_) => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) fn render_frame(
        context: &egui::Context,
        events: Vec<egui::Event>,
        draw: &mut impl FnMut(&egui::Context),
    ) -> egui::FullOutput {
        render_sized_frame(context, egui::vec2(1280.0, 900.0), events, draw)
    }

    fn render_sized_frame(
        context: &egui::Context,
        size: egui::Vec2,
        events: Vec<egui::Event>,
        draw: &mut impl FnMut(&egui::Context),
    ) -> egui::FullOutput {
        context.run(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
                events,
                ..Default::default()
            },
            |context| draw(context),
        )
    }

    pub(super) fn text_position(output: &egui::FullOutput, expected: &str) -> Option<egui::Pos2> {
        fn find(shape: &egui::Shape, expected: &str) -> Option<egui::Pos2> {
            match shape {
                egui::Shape::Text(text) if text.galley.text() == expected => {
                    Some(text.pos + text.galley.size() * 0.5)
                }
                egui::Shape::Vec(shapes) => shapes.iter().find_map(|shape| find(shape, expected)),
                _ => None,
            }
        }
        output
            .shapes
            .iter()
            .find_map(|shape| find(&shape.shape, expected))
    }

    pub(super) fn click_label(
        context: &egui::Context,
        label: &str,
        mut draw: impl FnMut(&egui::Context),
    ) {
        // A window needs its measured previous frame before testing pointer hit regions.
        let _ = render_frame(context, Vec::new(), &mut draw);
        let output = render_frame(context, Vec::new(), &mut draw);
        let pos = text_position(&output, label).expect("requested control is rendered");
        for pressed in [true, false] {
            let _ = render_frame(
                context,
                vec![
                    egui::Event::PointerMoved(pos),
                    egui::Event::PointerButton {
                        pos,
                        button: egui::PointerButton::Primary,
                        pressed,
                        modifiers: egui::Modifiers::NONE,
                    },
                ],
                &mut draw,
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn initial_workspace_keeps_native_path_when_its_display_names_another_path() {
        use std::{ffi::OsString, os::unix::ffi::OsStringExt as _};

        let temporary = tempfile::tempdir().unwrap();
        let original = temporary
            .path()
            .join(OsString::from_vec(b"project-\xff".to_vec()));
        let displayed = PathBuf::from(original.to_string_lossy().as_ref());
        // Unix paths retain arbitrary bytes, but macOS filesystems reject this filename.
        // Linux additionally exercises two real directories with distinct native identities.
        #[cfg(target_os = "linux")]
        {
            std::fs::create_dir(&original).unwrap();
            std::fs::create_dir(&displayed).unwrap();
            assert_ne!(
                original.canonicalize().unwrap(),
                displayed.canonicalize().unwrap()
            );
        }

        let mut desktop = Desktop::model(original.clone());
        assert_eq!(desktop.workspace_path.native, original);
        let context = egui::Context::default();
        let _ = render_frame(&context, Vec::new(), &mut |context| {
            egui::CentralPanel::default().show(context, |ui| {
                desktop.workspace_path.show(ui);
            });
        });
        assert_eq!(desktop.workspace_path.text, displayed.to_string_lossy());
        assert_eq!(desktop.workspace_path.native, original);
        #[cfg(target_os = "linux")]
        assert_eq!(
            desktop.workspace_path.native.canonicalize().unwrap(),
            original.canonicalize().unwrap()
        );
        assert_ne!(desktop.workspace_path.native, displayed);
    }

    #[test]
    fn workspace_editor_selects_the_explicitly_pasted_path() {
        let mut path = WorkspacePath::new(PathBuf::new());
        let context = egui::Context::default();
        let mut editor = None;
        let _ = render_frame(&context, Vec::new(), &mut |context| {
            egui::CentralPanel::default().show(context, |ui| {
                editor = Some(path.show(ui).id);
            });
        });
        assert_eq!(path.native, PathBuf::new());
        context.memory_mut(|memory| memory.request_focus(editor.unwrap()));
        let selected = "a workspace/with spaces";
        let _ = render_frame(
            &context,
            vec![egui::Event::Paste(selected.into())],
            &mut |context| {
                egui::CentralPanel::default().show(context, |ui| {
                    path.show(ui);
                });
            },
        );
        assert_eq!(path.text, selected);
        assert_eq!(path.native, PathBuf::from(selected));
    }

    #[test]
    fn new_localnet_dialog_emits_only_the_explicit_available_name() {
        let names = vec!["local".into(), "local-2".into(), "private".into()];
        let mut dialog = LocalnetDialog::new(&names);
        assert_eq!(dialog.name, "local-3");
        dialog.name = "  contracts  ".into();
        let context = egui::Context::default();
        let mut requested = None;
        click_label(&context, "Create localnet", |context| {
            if let Some(action) = dialog.show(context, &names, false) {
                requested = Some(action);
            }
        });
        assert!(
            matches!(requested, Some(LocalnetDialogAction::Start(name)) if name == "contracts")
        );
        assert_eq!(names, ["local", "local-2", "private"]);
    }

    #[test]
    fn new_localnet_dialog_refuses_retained_names_empty_names_and_busy_work() {
        let names = vec!["local".into(), "private".into()];
        for (name, busy) in [(" private ", false), ("  ", false), ("new", true)] {
            let context = egui::Context::default();
            let mut dialog = LocalnetDialog { name: name.into() };
            let mut requested = None;
            click_label(&context, "Create localnet", |context| {
                if let Some(action) = dialog.show(context, &names, busy) {
                    requested = Some(action);
                }
            });
            assert!(requested.is_none());
        }
        let context = egui::Context::default();
        let mut dialog = LocalnetDialog::new(&names);
        let mut requested = None;
        click_label(&context, "Cancel", |context| {
            if let Some(action) = dialog.show(context, &names, false) {
                requested = Some(action);
            }
        });
        assert!(matches!(requested, Some(LocalnetDialogAction::Cancel)));
    }

    #[test]
    fn failed_new_localnet_keeps_current_observations_and_exposes_retained_name() {
        let mut desktop = Desktop::model(PathBuf::from("unused"));
        desktop.busy = true;
        desktop.new_name = "original".into();
        desktop.names = vec!["original".into()];
        desktop.logs = "original validator logs".into();
        desktop.receipt = Some("original deployment receipt".into());
        desktop
            .sender
            .send((
                0,
                Message::LocalnetStarted {
                    result: Err("startup timed out; prepared generation retained".into()),
                    names: Ok(vec!["contracts".into(), "original".into()]),
                },
            ))
            .unwrap();
        desktop.poll();
        assert!(!desktop.busy);
        assert_eq!(desktop.new_name, "original");
        assert_eq!(desktop.names, ["contracts", "original"]);
        assert_eq!(desktop.logs, "original validator logs");
        assert_eq!(
            desktop.receipt.as_deref(),
            Some("original deployment receipt")
        );
        assert!(
            desktop
                .error
                .as_deref()
                .unwrap()
                .contains("generation retained")
        );
    }

    #[test]
    fn primary_start_timeout_exposes_retained_name_without_selecting_it() {
        let calls = std::cell::RefCell::new(Vec::new());
        // Exercise the production completion owner at the existing UI string-error boundary.
        // The managed store can retain a generation before returning this original timeout.
        let timeout = "localnet startup did not complete within 30s";
        let completion = complete_localnet_start(
            || {
                calls.borrow_mut().push("start");
                Err(timeout.into())
            },
            || panic!("a failed start cannot select its observation"),
            || {
                calls.borrow_mut().push("names");
                Ok(vec!["contracts".into()])
            },
        );
        assert_eq!(*calls.borrow(), ["start", "names"]);
        let mut desktop = Desktop::model(PathBuf::from("unused"));
        desktop.busy = true;
        desktop.new_name = "contracts".into();
        desktop.sender.send((desktop.epoch, completion)).unwrap();
        desktop.poll();
        assert!(!desktop.busy);
        assert_eq!(desktop.names, ["contracts"]);
        assert_eq!(desktop.new_name, "contracts");
        assert!(desktop.selected.is_none());
        assert_eq!(desktop.error.as_deref(), Some(timeout));
    }

    #[test]
    fn primary_start_failed_status_keeps_retained_menu_and_prior_observations() {
        let calls = std::cell::RefCell::new(Vec::new());
        let completion = complete_localnet_start(
            || {
                calls.borrow_mut().push("start");
                Ok((ManagedPhase::Failed, Some("exact readiness failure".into())))
            },
            || panic!("Ok(Failed) is not permission to install a selection"),
            || {
                calls.borrow_mut().push("names");
                Ok(vec!["contracts".into(), "original".into()])
            },
        );
        assert_eq!(*calls.borrow(), ["start", "names"]);
        let mut desktop = Desktop::model(PathBuf::from("unused"));
        desktop.busy = true;
        desktop.new_name = "original".into();
        desktop.names = vec!["original".into()];
        desktop.logs = "original validator logs".into();
        desktop.receipt = Some("original deployment receipt".into());
        desktop.sender.send((desktop.epoch, completion)).unwrap();
        desktop.poll();
        assert!(!desktop.busy);
        assert_eq!(desktop.names, ["contracts", "original"]);
        assert_eq!(desktop.new_name, "original");
        assert!(desktop.selected.is_none());
        assert_eq!(desktop.logs, "original validator logs");
        assert_eq!(
            desktop.receipt.as_deref(),
            Some("original deployment receipt")
        );
        let error = desktop.error.as_deref().unwrap();
        assert!(error.contains("startup ended in Failed"));
        assert!(error.contains("prepared generation is retained"));
        assert!(error.contains("exact readiness failure"));
    }

    #[test]
    fn primary_start_keeps_original_error_when_retained_name_refresh_also_fails() {
        for started in [
            Err("original timeout".into()),
            Ok((ManagedPhase::Ready, None)),
        ] {
            let calls = std::cell::RefCell::new(Vec::new());
            let expected = if started.is_err() {
                "original timeout"
            } else {
                "original observation failure"
            };
            let completion = complete_localnet_start(
                || {
                    calls.borrow_mut().push("start");
                    started
                },
                || {
                    calls.borrow_mut().push("observe");
                    Err("original observation failure".into())
                },
                || {
                    calls.borrow_mut().push("names");
                    Err("retained name refresh failure".into())
                },
            );
            assert_eq!(
                *calls.borrow(),
                if expected == "original timeout" {
                    vec!["start", "names"]
                } else {
                    vec!["start", "observe", "names"]
                }
            );
            let mut desktop = Desktop::model(PathBuf::from("unused"));
            desktop.busy = true;
            desktop.names = vec!["original".into()];
            desktop.logs = "original validator logs".into();
            desktop.receipt = Some("original deployment receipt".into());
            desktop.sender.send((desktop.epoch, completion)).unwrap();
            desktop.poll();
            assert!(!desktop.busy);
            assert_eq!(desktop.names, ["original"]);
            assert!(desktop.selected.is_none());
            assert_eq!(desktop.logs, "original validator logs");
            assert_eq!(
                desktop.receipt.as_deref(),
                Some("original deployment receipt")
            );
            assert_eq!(desktop.error.as_deref(), Some(expected));
        }
    }

    #[test]
    fn new_localnet_selection_requires_ready_even_when_start_returned_a_status() {
        assert!(require_ready_localnet(ManagedPhase::Ready, None).is_ok());
        for phase in [
            ManagedPhase::Stopped,
            ManagedPhase::Starting,
            ManagedPhase::Failed,
        ] {
            let error = require_ready_localnet(phase, Some("exact readiness failure")).unwrap_err();
            assert!(error.contains(&format!("{phase:?}")));
            assert!(error.contains("prepared generation is retained"));
            assert!(error.contains("exact readiness failure"));
        }
    }

    #[test]
    fn automatic_observation_keeps_the_foreground_failure_until_another_action() {
        let mut desktop = Desktop::model(PathBuf::from("unused"));
        desktop.error = Some("new localnet failed; prepared generation retained".into());
        desktop.notice = Some("Original foreground observation".into());
        desktop.last_poll = Instant::now() - Duration::from_secs(6);
        // Exercise the exact task owner used by refresh_selection, without creating a
        // managed context or invoking native filesystem/process services from a UI test.
        desktop.spawn_task(|| Message::Logs(Ok("original context observation".into())));
        assert_eq!(
            desktop.error.as_deref(),
            Some("new localnet failed; prepared generation retained")
        );
        let completion = desktop
            .receiver
            .recv_timeout(Duration::from_secs(5))
            .unwrap();
        desktop.sender.send(completion).unwrap();
        desktop.poll();
        assert!(!desktop.busy);
        assert_eq!(desktop.logs, "original context observation");
        assert_eq!(
            desktop.notice.as_deref(),
            Some("Original foreground observation")
        );
        assert_eq!(
            desktop.error.as_deref(),
            Some("new localnet failed; prepared generation retained")
        );
        desktop.spawn(|| Message::Logs(Ok("explicit action".into())));
        assert!(desktop.error.is_none());
        assert!(desktop.notice.is_none());
        let completion = desktop
            .receiver
            .recv_timeout(Duration::from_secs(5))
            .unwrap();
        desktop.sender.send(completion).unwrap();
        desktop.poll();
        assert_eq!(desktop.logs, "explicit action");
    }

    #[test]
    fn deployment_review_is_visible_and_waits_for_explicit_approval_in_every_view() {
        for view in View::ALL {
            let mut desktop = Desktop::model(PathBuf::from("unused"));
            desktop.busy = true;
            desktop.view = view;
            let (decision, answer) = mpsc::channel();
            desktop
                .sender
                .send((
                    0,
                    Message::Review {
                        evidence: "exact original signed intent and quoted fees".into(),
                        decision,
                    },
                ))
                .unwrap();
            desktop.poll();
            let context = egui::Context::default();
            let _ = render_frame(&context, Vec::new(), &mut |context| desktop.show(context));
            let output = render_frame(&context, Vec::new(), &mut |context| desktop.show(context));
            assert!(
                text_position(&output, "exact original signed intent and quoted fees").is_some()
            );
            assert!(matches!(answer.try_recv(), Err(mpsc::TryRecvError::Empty)));
            assert!(desktop.busy);
            click_label(&context, "Deploy with these fees", |context| {
                desktop.show(context)
            });
            assert_eq!(answer.try_recv(), Ok(true));
            assert!(desktop.review.is_none());
            assert!(
                desktop.busy,
                "approval does not fabricate deployment completion"
            );
        }
    }

    #[test]
    fn deployment_review_cancel_from_another_view_withholds_approval() {
        let mut desktop = Desktop::model(PathBuf::from("unused"));
        desktop.busy = true;
        desktop.view = View::Activity;
        let (decision, answer) = mpsc::channel();
        desktop.review = Some(Review {
            evidence: "exact retained plan".into(),
            decision,
        });
        let context = egui::Context::default();
        click_label(&context, "Cancel", |context| desktop.show(context));
        assert_eq!(answer.try_recv(), Ok(false));
        assert!(desktop.review.is_none());
        assert!(desktop.busy);
    }

    #[test]
    fn deployment_review_keeps_decision_buttons_reachable_in_a_small_viewport() {
        let mut desktop = Desktop::model(PathBuf::from("unused"));
        desktop.busy = true;
        desktop.view = View::Home;
        let (decision, answer) = mpsc::channel();
        desktop.review = Some(Review {
            evidence: "a long original signed transaction and exact fee evidence ".repeat(300),
            decision,
        });
        let context = egui::Context::default();
        let size = egui::vec2(360.0, 320.0);
        let viewport = egui::Rect::from_min_size(egui::Pos2::ZERO, size);
        let _ = render_sized_frame(&context, size, Vec::new(), &mut |context| {
            desktop.show(context)
        });
        let output = render_sized_frame(&context, size, Vec::new(), &mut |context| {
            desktop.show(context)
        });
        for label in ["Deploy with these fees", "Cancel"] {
            let pos = text_position(&output, label).expect("decision button rendered");
            assert!(
                viewport.contains(pos),
                "{label} must remain inside the viewport"
            );
        }
        let pos = text_position(&output, "Cancel").unwrap();
        for pressed in [true, false] {
            let _ = render_sized_frame(
                &context,
                size,
                vec![
                    egui::Event::PointerMoved(pos),
                    egui::Event::PointerButton {
                        pos,
                        button: egui::PointerButton::Primary,
                        pressed,
                        modifiers: egui::Modifiers::NONE,
                    },
                ],
                &mut |context| desktop.show(context),
            );
        }
        assert_eq!(answer.try_recv(), Ok(false));
        assert!(desktop.review.is_none());
    }

    #[test]
    fn completed_deployment_survives_failed_workspace_refresh() {
        let mut desktop = Desktop::model(PathBuf::from("unused"));
        desktop.busy = true;
        desktop
            .sender
            .send((
                0,
                Message::Deployed {
                    result: Ok(
                        "Applied on private dataspace original; exact retained receipt".into(),
                    ),
                    refreshed: Err("generation was replaced".into()),
                },
            ))
            .unwrap();
        desktop.poll();
        assert!(!desktop.busy);
        assert!(desktop.error.is_none());
        assert_eq!(
            desktop.receipt.as_deref(),
            Some("Applied on private dataspace original; exact retained receipt")
        );
        assert!(
            desktop
                .notice
                .as_deref()
                .unwrap()
                .contains("Deployment applied")
        );
        assert!(desktop.selected.is_none());
    }

    #[test]
    fn completed_deployment_survives_automatic_selection_failure_until_explicit_selection() {
        let mut desktop = Desktop::model(PathBuf::from("unused"));
        let receipt = "Applied on private dataspace original; exact retained receipt";
        // Drive the real completion and polling owners; this is presentation evidence, not
        // a synthesized native transaction or managed network.
        desktop
            .sender
            .send((
                desktop.epoch,
                Message::Deployed {
                    result: Ok(receipt.into()),
                    refreshed: Err("original workspace observation unavailable".into()),
                },
            ))
            .unwrap();
        desktop.poll();
        assert_eq!(desktop.receipt.as_deref(), Some(receipt));
        let notice = desktop.notice.clone();
        assert!(notice.as_deref().unwrap().contains("Deployment applied"));
        let epoch = desktop.epoch;
        desktop.logs = "original context log observation".into();
        desktop.activity.push_back("original context event".into());

        // Use the same task owner and completion variant as refresh_selection. The context
        // must withdraw on failure while the original completed result remains inspectable.
        desktop.spawn_task(|| {
            Message::SelectionObserved(
                Err("automatic observation lost its original context".into()),
            )
        });
        assert!(desktop.busy);
        let completion = desktop
            .receiver
            .recv_timeout(Duration::from_secs(5))
            .unwrap();
        desktop.sender.send(completion).unwrap();
        desktop.poll();
        assert!(!desktop.busy);
        assert_eq!(desktop.epoch, epoch);
        assert!(desktop.selected.is_none());
        assert!(desktop.blocks.is_none());
        assert!(desktop.events.is_none());
        assert!(desktop.logs.is_empty());
        assert!(desktop.activity.is_empty());
        assert_eq!(desktop.receipt.as_deref(), Some(receipt));
        assert_eq!(desktop.notice, notice);
        assert_eq!(
            desktop.error.as_deref(),
            Some("automatic observation lost its original context")
        );

        desktop
            .sender
            .send((
                epoch.wrapping_add(1),
                Message::SelectionObserved(Err("stale context error".into())),
            ))
            .unwrap();
        desktop.poll();
        assert_eq!(desktop.receipt.as_deref(), Some(receipt));
        assert_eq!(desktop.notice, notice);
        assert_eq!(
            desktop.error.as_deref(),
            Some("automatic observation lost its original context")
        );

        // An explicit selection still follows the original clearing path.
        desktop
            .sender
            .send((
                epoch,
                Message::Selected(Err("explicit selection failed".into())),
            ))
            .unwrap();
        desktop.poll();
        assert!(desktop.receipt.is_none());
        assert!(desktop.notice.is_none());
        assert_eq!(desktop.error.as_deref(), Some("explicit selection failed"));
        assert_eq!(desktop.epoch, epoch);
    }

    #[test]
    fn a_new_foreground_failure_cannot_keep_an_earlier_deployment_success_notice() {
        let mut desktop = Desktop::model(PathBuf::from("unused"));
        desktop
            .sender
            .send((
                0,
                Message::Deployed {
                    result: Ok("Original Applied deployment receipt".into()),
                    refreshed: Err("original workspace observation unavailable".into()),
                },
            ))
            .unwrap();
        desktop.poll();
        assert!(
            desktop
                .notice
                .as_deref()
                .unwrap()
                .contains("Deployment applied")
        );
        // Exercise the real foreground task owner and failed Deployed completion path. No
        // native deployment or authenticated plan is fabricated by this presentation control.
        desktop.spawn(|| Message::Deployed {
            result: Err("new deployment refused before dispatch".into()),
            refreshed: Err("new workspace observation unavailable".into()),
        });
        assert!(desktop.busy);
        assert!(desktop.notice.is_none());
        let completion = desktop
            .receiver
            .recv_timeout(Duration::from_secs(5))
            .unwrap();
        desktop.sender.send(completion).unwrap();
        desktop.poll();
        assert!(!desktop.busy);
        assert_eq!(
            desktop.error.as_deref(),
            Some("new deployment refused before dispatch")
        );
        assert!(desktop.notice.is_none());
    }

    #[test]
    fn parent_status_requires_a_receipt_and_keeps_historical_confirmation_distinct() {
        let mut status = ManagedAttachmentStatus {
            network: "installed".into(),
            stage: ManagedAttachmentPhase::Attached,
            wallet_status: Some("Applied".into()),
            local_successor: None,
            parent_confirmed: None,
            failure: None,
        };
        assert_eq!(
            attachment_summary(&status),
            "Parent installed · awaiting verified receipt"
        );
        status.stage = ManagedAttachmentPhase::Unavailable;
        status.parent_confirmed = Some(mochi_core::developer::ManagedConfirmedAnchor {
            parent_height: u64::MAX,
            child: iroha_data_model::private_dataspace::PrivateDataspaceCursor {
                height: 7,
                consensus_hash: [1; 32],
                result: [2; 32],
            },
        });
        let summary = attachment_summary(&status);
        assert!(summary.contains("unavailable"));
        assert!(summary.contains("last confirmed child block #7"));
        assert!(summary.contains(&u64::MAX.to_string()));
    }

    #[test]
    fn attachment_observation_does_not_finish_background_work_or_escape_its_context() {
        let mut desktop = Desktop::model(PathBuf::from("unused"));
        desktop.busy = true;
        desktop.attaching = Some("private".into());
        desktop.attachment_poll_pending = true;
        desktop
            .sender
            .send((
                0,
                Message::AttachmentObserved {
                    name: "private".into(),
                    result: Err("generation is still preparing".into()),
                },
            ))
            .unwrap();
        desktop.poll();
        assert!(desktop.busy);
        assert!(!desktop.attachment_poll_pending);
        assert!(desktop.error.is_none());
        desktop.attaching = None;
        desktop.attachment_poll_pending = true;
        desktop
            .sender
            .send((
                0,
                Message::AttachmentObserved {
                    name: "private".into(),
                    result: Err("late observation".into()),
                },
            ))
            .unwrap();
        desktop.poll();
        assert!(desktop.attachment_poll_pending);
        assert!(desktop.busy);
    }

    #[test]
    fn private_dialog_without_installed_profiles_never_starts_or_invents_a_network() {
        let mut desktop = Desktop::model(PathBuf::from("unused"));
        desktop.private_dialog = true;
        let context = egui::Context::default();
        let output = context.run(egui::RawInput::default(), |context| {
            desktop.private_dataspace_dialog(context)
        });
        assert!(!output.shapes.is_empty());
        assert!(!desktop.busy);
        assert!(desktop.attaching.is_none());
        assert!(desktop.private_network.is_empty());
    }

    #[test]
    fn stream_summaries_bound_untrusted_text_and_show_lifecycle() {
        assert_eq!(
            block_activity(&mochi_core::BlockStreamEvent::Closed),
            "Block stream closed"
        );
        assert_eq!(
            event_activity(&mochi_core::EventStreamEvent::Closed),
            "Event stream closed"
        );
        let event = mochi_core::BlockStreamEvent::Text {
            text: "界".repeat(5000),
        };
        assert_eq!(block_activity(&event).chars().count(), 4096);
        assert!(event_activity(&mochi_core::EventStreamEvent::Lagged { skipped: 5 }).contains('5'));
    }

    #[test]
    fn optional_package_selectors_preserve_simple_source_default() {
        assert_eq!(optional_selector("  "), None);
        assert_eq!(optional_selector(" ledger "), Some("ledger".into()));
    }

    #[test]
    fn activity_is_bounded_by_record_count_and_unicode_characters() {
        let mut activity = VecDeque::new();
        for index in 0..300 {
            push_activity(&mut activity, index.to_string());
        }
        assert_eq!(activity.len(), 256);
        assert_eq!(activity.front().unwrap(), "44");
        push_activity(&mut activity, "界".repeat(5000));
        assert_eq!(activity.back().unwrap().chars().count(), 4096);
    }

    fn observation_context() -> ManagedContext {
        // Public metadata only; these controls never construct a signer, native worker or receipt.
        ManagedContext {
            name: "local".into(),
            chain_id: "original-chain".into(),
            network_id: "original-network".into(),
            account_id: "original-account".into(),
            dataspace_id: 0,
            dataspace_alias: "original".into(),
            torii_url: "http://127.0.0.1:18080".into(),
            client_config: PathBuf::from("original/client.toml"),
        }
    }

    fn observation_status(context: ManagedContext) -> ManagedStatus {
        ManagedStatus {
            context,
            phase: ManagedPhase::Stopped,
            running_peers: 0,
            failure: None,
        }
    }

    fn observation_attachment(local: ManagedStatus) -> UiResult<Option<ManagedDataspaceStatus>> {
        Ok(Some(ManagedDataspaceStatus {
            local,
            attachment: ManagedAttachmentStatus {
                network: "installed".into(),
                stage: ManagedAttachmentPhase::Connecting,
                wallet_status: None,
                local_successor: None,
                parent_confirmed: None,
                failure: None,
            },
        }))
    }

    #[test]
    fn selection_observation_refuses_recreated_names_and_mixed_local_generations() {
        let original = observation_context();
        let original_status = observation_status(original.clone());
        for field in [
            "name",
            "chain",
            "network",
            "account",
            "dataspace",
            "alias",
            "endpoint",
            "config",
        ] {
            let mut replacement = original.clone();
            match field {
                "name" => replacement.name.push('x'),
                "chain" => replacement.chain_id.push('x'),
                "network" => replacement.network_id.push('x'),
                "account" => replacement.account_id.push('x'),
                "dataspace" => replacement.dataspace_id += 1,
                "alias" => replacement.dataspace_alias.push('x'),
                "endpoint" => replacement.torii_url.push('x'),
                _ => replacement.client_config.push("replacement"),
            }
            let replacement_status = observation_status(replacement);
            // The status read and parent read can each cross a reset independently. Neither
            // the same name nor matching the other read grants the captured authority anew.
            for (status, attachment) in [
                (replacement_status.clone(), Ok(None)),
                (
                    replacement_status.clone(),
                    observation_attachment(original_status.clone()),
                ),
                (
                    original_status.clone(),
                    observation_attachment(replacement_status.clone()),
                ),
                (
                    replacement_status.clone(),
                    observation_attachment(replacement_status.clone()),
                ),
            ] {
                assert_eq!(
                    validate_selection_observation(&original, &status, &attachment).unwrap_err(),
                    "Selected network was replaced; select it again.",
                    "{field}"
                );
            }
        }
    }

    #[test]
    fn selection_observation_accepts_matching_stopped_and_unavailable_parent_states() {
        let original = observation_context();
        for phase in [
            ManagedPhase::Ready,
            ManagedPhase::Starting,
            ManagedPhase::Stopped,
            ManagedPhase::Failed,
        ] {
            let mut status = observation_status(original.clone());
            status.phase = phase;
            for attachment in [
                Ok(None),
                observation_attachment(status.clone()),
                Err("parent observation unavailable".into()),
            ] {
                validate_selection_observation(&original, &status, &attachment).unwrap();
            }
        }
        // An explicit Open/Select captures the replacement first, so matching reads for that
        // newly chosen identity remain valid; the guard does not pin one authority forever.
        let mut replacement = original;
        replacement.network_id = "explicitly-selected-replacement".into();
        let status = observation_status(replacement.clone());
        validate_selection_observation(
            &replacement,
            &status,
            &observation_attachment(status.clone()),
        )
        .unwrap();
    }

    #[test]
    fn automatic_selection_requires_the_current_complete_generation() {
        let current = PreparedLocalnet {
            service_profile: Default::default(),
            context: observation_context(),
            peers: Vec::new(),
        };
        validate_retained_selection(Some(&current), &current).unwrap();
        assert!(validate_retained_selection(None, &current).is_err());
        let mut replacement = current.clone();
        replacement.context.network_id = "recreated-network".into();
        assert_eq!(replacement.context.name, current.context.name);
        assert!(validate_retained_selection(Some(&current), &replacement).is_err());
        // After explicit selection, subsequent observations of the newly chosen generation
        // are accepted. The automatic path cannot itself make that transition.
        validate_retained_selection(Some(&replacement), &replacement).unwrap();
    }

    #[test]
    fn automatic_withdrawal_preserves_completed_operations_and_clears_live_observations() {
        let mut desktop = Desktop::model(PathBuf::from("unused"));
        desktop.logs = "stale validator observation".into();
        desktop.activity.push_back("stale event".into());
        desktop.peer = 3;
        desktop.reset_intent = true;
        desktop.receipt = Some("original deployment receipt".into());
        desktop.notice = Some("original completion".into());
        desktop.publication.operation_id = "original operation".into();
        desktop.publication_output = Some(PublicationOutput {
            exit_code: 7,
            stdout: "original publication output".into(),
            stderr: "original pending diagnostic".into(),
        });
        // The same preservation owner wraps both automatic install_opened (including its
        // inner selection error) and withdrawal after an outer workspace-observation error.
        desktop.retain_completed_evidence(|desktop| {
            desktop.clear_network();
            desktop.error = Some("selected generation was replaced".into());
        });
        desktop.withdraw_observed_network();
        assert!(desktop.selected.is_none());
        assert!(desktop.logs.is_empty());
        assert!(desktop.activity.is_empty());
        assert_eq!(desktop.peer, 0);
        assert!(!desktop.reset_intent);
        assert_eq!(
            desktop.receipt.as_deref(),
            Some("original deployment receipt")
        );
        assert_eq!(desktop.notice.as_deref(), Some("original completion"));
        assert_eq!(
            desktop.error.as_deref(),
            Some("selected generation was replaced")
        );
        assert_eq!(desktop.publication.operation_id, "original operation");
        let output = desktop.publication_output.as_ref().unwrap();
        assert_eq!(output.exit_code, 7);
        assert_eq!(output.stdout, "original publication output");
        assert_eq!(output.stderr, "original pending diagnostic");
    }

    #[test]
    fn deployment_refresh_failure_retains_earlier_publication_evidence() {
        let mut desktop = Desktop::model(PathBuf::from("unused"));
        desktop.busy = true;
        desktop.publication.operation_id = "original publication".into();
        desktop.publication_output = Some(PublicationOutput {
            exit_code: 0,
            stdout: "original publication output".into(),
            stderr: String::new(),
        });
        desktop
            .sender
            .send((
                desktop.epoch,
                Message::Deployed {
                    result: Ok("new verified deployment receipt".into()),
                    refreshed: Err("captured workspace unavailable".into()),
                },
            ))
            .unwrap();
        desktop.poll();
        assert!(!desktop.busy);
        assert_eq!(
            desktop.receipt.as_deref(),
            Some("new verified deployment receipt")
        );
        assert_eq!(desktop.publication.operation_id, "original publication");
        assert_eq!(
            desktop.publication_output.as_ref().unwrap().stdout,
            "original publication output"
        );
        assert!(
            desktop
                .notice
                .as_deref()
                .unwrap()
                .contains("Deployment applied")
        );
    }

    #[test]
    fn stale_selection_observation_cannot_erase_current_evidence_or_finish_work() {
        let mut desktop = Desktop::model(PathBuf::from("unused"));
        desktop.epoch = 2;
        desktop.busy = true;
        desktop.logs = "current logs".into();
        desktop.receipt = Some("current verified deployment receipt".into());
        desktop.notice = Some("current completion".into());
        desktop.error = Some("current observation diagnostic".into());
        desktop.publication.operation_id = "current operation".into();
        desktop.publication_output = Some(PublicationOutput {
            exit_code: 0,
            stdout: "current publication output".into(),
            stderr: String::new(),
        });
        desktop
            .sender
            .send((
                1,
                Message::SelectionObserved(Err("old generation was replaced".into())),
            ))
            .unwrap();
        desktop.poll();
        assert!(desktop.busy);
        assert_eq!(desktop.epoch, 2);
        assert_eq!(desktop.logs, "current logs");
        assert_eq!(
            desktop.receipt.as_deref(),
            Some("current verified deployment receipt")
        );
        assert_eq!(desktop.notice.as_deref(), Some("current completion"));
        assert_eq!(
            desktop.error.as_deref(),
            Some("current observation diagnostic")
        );
        assert_eq!(desktop.publication.operation_id, "current operation");
        assert_eq!(
            desktop.publication_output.as_ref().unwrap().stdout,
            "current publication output"
        );
    }

    #[test]
    fn stale_context_results_are_ignored_and_their_review_is_cancelled() {
        let mut desktop = Desktop::model(PathBuf::from("unused"));
        desktop.epoch = 2;
        desktop.logs = "current context".into();
        desktop
            .sender
            .send((1, Message::Logs(Ok("stale context".into()))))
            .unwrap();
        let (decision, answer) = mpsc::channel();
        desktop
            .sender
            .send((
                1,
                Message::Review {
                    evidence: "old fees".into(),
                    decision,
                },
            ))
            .unwrap();
        desktop.poll();
        assert_eq!(desktop.logs, "current context");
        assert!(desktop.review.is_none());
        assert!(answer.recv().is_err());
    }

    #[test]
    fn closing_desktop_with_pending_review_cancels_without_approval() {
        let mut desktop = Desktop::model(PathBuf::from("unused"));
        desktop.busy = true;
        let (decision, answer) = mpsc::channel();
        desktop
            .sender
            .send((
                0,
                Message::Review {
                    evidence: "quoted fees".into(),
                    decision,
                },
            ))
            .unwrap();
        desktop.poll();
        assert!(desktop.busy);
        assert_eq!(desktop.review.as_ref().unwrap().evidence, "quoted fees");
        drop(desktop);
        assert!(answer.recv().is_err());
    }

    #[test]
    fn every_empty_workspace_view_renders_without_starting_network_or_signer() {
        let mut desktop = Desktop::model(PathBuf::from("unused"));
        let context = egui::Context::default();
        for view in View::ALL {
            let output = context.run(egui::RawInput::default(), |context| {
                egui::CentralPanel::default().show(context, |ui| match view {
                    View::Home => desktop.home(ui),
                    View::Accounts => desktop.accounts(ui),
                    View::Blocks => desktop.blocks(ui),
                    View::Activity => desktop.activity(ui),
                    View::State => desktop.state(ui),
                    View::Composer => desktop.composer(ui),
                    View::Contracts => desktop.contracts(ui),
                    View::Packages => desktop.packages(ui),
                    View::Endpoints => desktop.endpoints(ui),
                    View::Logs => desktop.logs(ui),
                });
            });
            assert!(!output.shapes.is_empty());
            assert!(!desktop.busy);
            assert!(desktop.workspace.is_none());
            assert!(desktop.selected.is_none());
        }
    }

    #[test]
    fn stream_lag_is_visible_and_draining_is_bounded() {
        let (sender, mut receiver) = tokio::sync::broadcast::channel(2);
        for index in 0..10 {
            sender.send(index).unwrap();
        }
        let mut activity = VecDeque::new();
        let mut recorded = Vec::new();
        drain_stream(
            &mut receiver,
            &mut activity,
            |event| event.to_string(),
            |event| recorded.push(*event),
        );
        assert_eq!(recorded.first(), Some(&8));
        assert!(activity.front().unwrap().contains("skipped"));
        assert_eq!(activity.back().unwrap(), "9");
    }

    fn drop_file(desktop: &mut Desktop, path: PathBuf) {
        let context = egui::Context::default();
        let _ = context.run(
            egui::RawInput {
                dropped_files: vec![egui::DroppedFile {
                    path: Some(path),
                    ..Default::default()
                }],
                ..Default::default()
            },
            |context| desktop.show(context),
        );
    }

    #[test]
    fn dropped_contracts_become_deployment_input_without_deploying() {
        let temporary = tempfile::tempdir().unwrap();
        let mut desktop = Desktop::model(PathBuf::from("unused"));
        desktop.contract_path = "original.ko".into();
        drop_file(&mut desktop, temporary.path().join("notes.txt"));
        assert_eq!(desktop.contract_path, "original.ko");
        assert_eq!(desktop.view, View::Home);
        assert!(desktop.error.as_deref().unwrap().contains("notes.txt"));

        let contract = temporary.path().join("coffee.ko");
        drop_file(&mut desktop, contract.clone());
        assert_eq!(desktop.contract_path, contract.to_str().unwrap());
        assert_eq!(desktop.view, View::Contracts);
        assert!(!desktop.busy, "dropping never dispatches a deployment");
        assert!(desktop.review.is_none());
    }

    #[test]
    fn switching_validators_drops_observations_bound_to_the_previous_one() {
        let mut desktop = Desktop::model(PathBuf::from("unused"));
        desktop.blocks_feed.push_back(ledger::BlockRow {
            height: 3,
            hash: "aa".into(),
            transactions: 1,
            rejected: 0,
            signatures: 4,
            created_ms: 0,
            genesis: false,
            bytes: 10,
        });
        desktop.latest_height = Some(3);
        desktop.ledger_error = Some("original validator observation".into());
        desktop.busy = true;
        desktop.observe_peer(2);
        assert_eq!(desktop.peer, 0, "busy work keeps the observed validator");
        desktop.busy = false;
        desktop.observe_peer(2);
        assert_eq!(desktop.peer, 2);
        assert!(desktop.blocks_feed.is_empty());
        assert!(desktop.latest_height.is_none());
        assert!(desktop.ledger.is_none());
        assert!(desktop.ledger_error.is_none());
    }

    #[test]
    fn leaving_an_environment_forgets_generated_keys_and_ledger_observations() {
        let mut desktop = Desktop::model(PathBuf::from("unused"));
        desktop.quick.generated = Some(mochi_core::GeneratedAccount::generate());
        desktop.quick.reveal_key = true;
        desktop.quick.asset = "kept form input".into();
        desktop.ledger_stale = true;
        desktop.latest_height = Some(9);
        desktop.logs_source = Some(3);
        desktop.endpoint_peer = 3;
        desktop.clear_network();
        assert!(desktop.quick.generated.is_none());
        assert!(!desktop.quick.reveal_key);
        assert_eq!(desktop.quick.asset, "kept form input");
        assert!(!desktop.ledger_stale);
        assert!(desktop.latest_height.is_none());
        assert_eq!(desktop.logs_source, None);
        assert_eq!(desktop.endpoint_peer, 0);
    }

    #[test]
    fn submissions_mark_balances_stale_and_background_work_stays_quiet() {
        let mut desktop = Desktop::model(PathBuf::from("unused"));
        desktop.spawn(|| Message::Submitted(Ok("Applied original in block 4".into())));
        assert!(desktop.busy && desktop.foreground);
        let completion = desktop
            .receiver
            .recv_timeout(Duration::from_secs(5))
            .unwrap();
        desktop.sender.send(completion).unwrap();
        desktop.poll();
        assert!(!desktop.busy && !desktop.foreground);
        assert!(desktop.ledger_stale);
        assert_eq!(
            desktop.notice.as_deref(),
            Some("Applied original in block 4")
        );
        desktop.spawn_task(|| Message::Logs(Ok("background".into())));
        assert!(desktop.busy && !desktop.foreground);
    }
}

#[cfg(test)]
#[path = "gui/publication_tests.rs"]
mod publication_tests;

#[cfg(test)]
#[path = "gui/attachment_tests.rs"]
mod attachment_tests;

#[cfg(test)]
#[path = "gui/preview_tests.rs"]
mod preview_tests;
