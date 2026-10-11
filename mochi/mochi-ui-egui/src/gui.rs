//! Desktop views over Kagami's shared, persistent managed workspace.

use eframe::egui;
use mochi_core::{
    DashboardAccountInput, DashboardSnapshot, InstructionDraft, ManagedBlockStream,
    ManagedEventStream, StatePage, StateQueryKind, TransactionPreview,
    developer::{
        ContractInput, DeveloperWorkspace, GeneratedPublishAction, GeneratedPublishOutcome,
        ManagedAttachmentPhase, ManagedAttachmentStatus, ManagedDataspaceStatus, ManagedNetwork,
        ManagedPhase,
    },
    drafts_from_json_str, drafts_to_pretty_json, fetch_dashboard_snapshot, run_state_query,
};
use std::{
    collections::VecDeque,
    path::PathBuf,
    sync::mpsc::{self, Receiver, Sender},
    time::{Duration, Instant},
};

/// Launch the desktop; the optional argument is a workspace directory, never a configuration file.
pub fn run(workspace: PathBuf) -> eframe::Result<()> {
    eframe::run_native(
        "Mochi",
        eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default().with_inner_size([1160.0, 800.0]),
            ..Default::default()
        },
        Box::new(move |creation| Ok(Box::new(Desktop::new(creation, workspace)))),
    )
}

type UiResult<T> = Result<T, String>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum View {
    Dashboard,
    State,
    Activity,
    Composer,
    Contracts,
    Packages,
}
impl View {
    const ALL: [Self; 6] = [
        Self::Dashboard,
        Self::State,
        Self::Activity,
        Self::Composer,
        Self::Contracts,
        Self::Packages,
    ];
    fn label(self) -> &'static str {
        match self {
            Self::Dashboard => "Overview",
            Self::State => "State",
            Self::Activity => "Activity",
            Self::Composer => "Compose",
            Self::Contracts => "Contracts",
            Self::Packages => "Packages",
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
    let status = workspace
        .status(&network.prepared().context.name)
        .map_err(|e| e.to_string())?;
    let attachment = workspace
        .dataspace_status(&network.prepared().context.name)
        .map(|status| status.map(|status| status.attachment))
        .map_err(|e| e.to_string());
    Ok(Selection {
        network,
        phase: status.phase,
        running: status.running_peers,
        failure: status.failure,
        attachment,
    })
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
    let profiles = workspace.network_profiles().map_err(|e| e.to_string());
    let names = workspace
        .contexts()
        .map_err(|e| e.to_string())?
        .into_iter()
        .map(|c| c.name)
        .collect::<Vec<_>>();
    // An empty workspace deliberately creates neither a network nor a signing identity.
    let selected = workspace
        .selected_name()
        .map_err(|e| e.to_string())
        .and_then(|name| {
            name.map(|name| load_selection(&workspace, Some(&name)))
                .transpose()
        });
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
    Dashboard(UiResult<DashboardSnapshot>),
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
        let mut action = None;
        egui::Window::new("New localnet")
            .collapsible(false)
            .resizable(false)
            .show(context, |ui| {
                ui.label("Create four local validators and a funded account. No configuration files needed.");
                ui.label("Your current environment stays available. The new localnet becomes selected when ready.");
                ui.horizontal(|ui| {
                    ui.label("Name");
                    ui.text_edit_singleline(&mut self.name);
                });
                let name = self.name.trim();
                let exists = names.iter().any(|existing| existing == name);
                if exists {
                    ui.label("This name already exists. Choose it from the environment menu to resume it.");
                }
                ui.horizontal(|ui| {
                    if ui.button("Cancel").clicked() {
                        action = Some(LocalnetDialogAction::Cancel);
                    }
                    if ui
                        .add_enabled(
                            !busy && !name.is_empty() && !exists,
                            egui::Button::new("Create localnet"),
                        )
                        .clicked()
                    {
                        action = Some(LocalnetDialogAction::Start(name.to_owned()));
                    }
                });
            });
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

    fn show(&mut self, ui: &mut egui::Ui, available: bool) -> Option<PublicationAction> {
        let mut action = None;
        ui.heading("Publish a package");
        ui.label("Publish to the selected generated localnet. Publish starts a default localnet when none is selected.");
        ui.label("Publication can register the package namespace and pay transaction fees.");
        ui.add(
            egui::TextEdit::singleline(&mut self.manifest)
                .hint_text("Manifest or workspace path")
                .desired_width(700.0),
        );
        ui.add(
            egui::TextEdit::singleline(&mut self.package)
                .hint_text("Package selector (optional)")
                .desired_width(700.0),
        );
        ui.checkbox(&mut self.detach, "Return after durable seed staging");
        if ui
            .add_enabled(available, egui::Button::new("Publish package"))
            .clicked()
        {
            action = Some(PublicationAction::Begin);
        }
        ui.separator();
        ui.label("Use the original operation ID from publication output. Resume uses its retained package; Recover package files requires the original workspace.");
        ui.add(
            egui::TextEdit::singleline(&mut self.operation_id)
                .hint_text("Publication operation ID")
                .desired_width(700.0),
        );
        ui.horizontal_wrapped(|ui| {
            let enabled = available && !self.operation_id.trim().is_empty();
            if ui
                .add_enabled(enabled, egui::Button::new("Resume publication"))
                .clicked()
            {
                action = Some(PublicationAction::Resume);
            }
            if ui
                .add_enabled(enabled, egui::Button::new("Recover package files"))
                .clicked()
            {
                action = Some(PublicationAction::Recover);
            }
        });
        action
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

    fn show(&self, ui: &mut egui::Ui) {
        ui.separator();
        ui.strong(format!(
            "Publication output · exit status {}",
            self.exit_code
        ));
        if !self.stdout.is_empty() {
            ui.label("Output");
            if ui.button("Copy publication output").clicked() {
                ui.ctx().copy_text(self.stdout.clone());
            }
            ui.add(egui::Label::new(egui::RichText::new(&self.stdout).monospace()).wrap());
        }
        if !self.stderr.is_empty() {
            ui.label("Diagnostics");
            if ui.button("Copy publication diagnostics").clicked() {
                ui.ctx().copy_text(self.stderr.clone());
            }
            ui.add(egui::Label::new(egui::RichText::new(&self.stderr).monospace()).wrap());
        }
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
        let response = ui.add(egui::TextEdit::singleline(&mut self.text).desired_width(520.0));
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
    dashboard: Option<DashboardSnapshot>,
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
        let mut style = (*creation.egui_ctx.style()).clone();
        style.spacing.item_spacing = egui::vec2(10.0, 10.0);
        style.visuals = egui::Visuals::dark();
        style.visuals.selection.bg_fill = egui::Color32::from_rgb(72, 87, 167);
        creation.egui_ctx.set_style(style);
        let mut app = Self::model(path);
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
            view: View::Dashboard,
            error,
            notice: None,
            reset_intent: false,
            last_poll: Instant::now(),
            dashboard: None,
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
    }

    fn spawn_task(&mut self, work: impl FnOnce() -> Message + Send + 'static) {
        self.busy = true;
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
        self.dashboard = None;
        self.page = None;
        self.logs.clear();
        self.activity.clear();
        self.preview = None;
        self.submitted_hash = None;
        self.receipt = None;
        self.publication_output = None;
        self.publication.operation_id.clear();
        self.notice = None;
        self.reset_intent = false;
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
                    .and_then(|_| load_selection(&workspace, Some(&name))),
            )
        });
    }

    fn lifecycle(&mut self, start: bool) {
        let Some(workspace) = self.workspace.clone() else {
            return;
        };
        let name = self.selected.as_ref().map_or_else(
            || self.new_name.trim().to_owned(),
            |s| s.network.prepared().context.name.clone(),
        );
        self.spawn(move || {
            if start {
                complete_localnet_start(
                    || {
                        workspace
                            .start(&name)
                            .map(|status| (status.phase, status.failure))
                            .map_err(|e| e.to_string())
                    },
                    || load_selection(&workspace, Some(&name)),
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
                Message::Selected(
                    workspace
                        .stop(&name)
                        .map_err(|e| e.to_string())
                        .and_then(|_| load_selection(&workspace, Some(&name))),
                )
            }
        });
    }

    fn start_localnet(&mut self, name: String) {
        let Some(workspace) = self.workspace.clone() else {
            return;
        };
        self.spawn(move || {
            complete_localnet_start(
                || {
                    workspace
                        .create_localnet(&name)
                        .map(|status| (status.phase, status.failure))
                        .map_err(|e| e.to_string())
                },
                || load_selection(&workspace, Some(&name)),
                || {
                    workspace
                        .contexts()
                        .map(|contexts| contexts.into_iter().map(|context| context.name).collect())
                        .map_err(|e| e.to_string())
                },
            )
        });
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
        self.epoch = self.epoch.wrapping_add(1);
        self.clear_network();
        self.private_dialog = false;
        self.attaching = Some(alias.clone());
        self.attachment_poll_pending = false;
        self.attachment_progress = None;
        self.last_poll = Instant::now();
        self.spawn(move || {
            let result = workspace
                .start_dataspace(&alias, &network, &alias)
                .map(|status| attachment_summary(&status.attachment))
                .map_err(|e| e.to_string());
            Message::Attached {
                result,
                refreshed: inspect_workspace(workspace),
            }
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
        if let Ok(profiles) = &self.profiles {
            if !profiles.contains(&self.private_network) {
                self.private_network = profiles.first().cloned().unwrap_or_default();
            }
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
        let name = selected.network.prepared().context.name.clone();
        self.last_poll = Instant::now();
        // A background failure withdraws live context without erasing completed deployment evidence.
        self.spawn_task(move || {
            Message::SelectionObserved(load_selection(&workspace, Some(&name)))
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
                _ => self.busy = false,
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
                Message::SelectionObserved(result) => match result {
                    Ok(selected) => self.install_selection(selected),
                    Err(error) => {
                        let receipt = self.receipt.take();
                        let notice = self.notice.take();
                        let publication_output = self.publication_output.take();
                        let operation_id = std::mem::take(&mut self.publication.operation_id);
                        self.clear_network();
                        self.receipt = receipt;
                        self.notice = notice;
                        self.publication_output = publication_output;
                        self.publication.operation_id = operation_id;
                        self.error = Some(error);
                    }
                },
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
                Message::Dashboard(result) => match result {
                    Ok(snapshot) => self.dashboard = Some(snapshot),
                    Err(error) => self.error = Some(error),
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
                    Ok(message) => self.notice = Some(message),
                    Err(error) => self.error = Some(error),
                },
                Message::Deployed { result, refreshed } => {
                    self.review = None;
                    match refreshed {
                        Ok(opened) => self.install_opened(opened),
                        Err(_) if result.is_ok() => {
                            self.clear_network();
                            self.notice = Some(
                                "Deployment applied. Workspace observation is unavailable; reopen the workspace to refresh it.".into(),
                            );
                        }
                        Err(error) => self.error = Some(error),
                    }
                    match result {
                        Ok(receipt) => self.receipt = Some(receipt),
                        Err(error) => self.error = Some(error),
                    }
                }
                Message::Published { result, refreshed } => {
                    match refreshed {
                        Ok(opened) => self.install_opened(opened),
                        Err(error) => {
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
                    match refreshed {
                        Ok(opened) => self.install_opened(opened),
                        Err(error) => self.error = Some(error),
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
            drain_stream(receiver, &mut self.activity, block_activity);
        }
        if let Some((_, receiver)) = self.events.as_mut() {
            drain_stream(receiver, &mut self.activity, event_activity);
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
    }

    fn top_bar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.heading("Mochi");
            ui.label("Your Iroha workspace");
            if self.busy {
                ui.spinner();
                ui.label("Working…");
            }
        });
        ui.add_enabled_ui(!self.busy, |ui| {
            ui.horizontal(|ui| {
                ui.label("Workspace");
                self.workspace_path.show(ui);
                if ui.button("Open").clicked() {
                    self.open();
                }
            });
            ui.horizontal(|ui| {
                let selected = self
                    .selected
                    .as_ref()
                    .map(|s| s.network.prepared().context.name.clone());
                let mut chosen = selected.clone();
                egui::ComboBox::from_id_salt("context")
                    .selected_text(selected.as_deref().unwrap_or("Choose environment"))
                    .show_ui(ui, |ui| {
                        for name in &self.names {
                            ui.selectable_value(&mut chosen, Some(name.clone()), name);
                        }
                    });
                if chosen != selected {
                    if let Some(name) = chosen {
                        self.select(name);
                    }
                }
                if self.selected.is_none() {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.new_name)
                            .hint_text("Localnet name")
                            .desired_width(130.0),
                    );
                }
                let phase = self.selected.as_ref().map(|s| s.phase);
                if ui
                    .add_enabled(
                        self.workspace.is_some() && phase != Some(ManagedPhase::Ready),
                        egui::Button::new(if self.selected.is_some() {
                            "Start"
                        } else {
                            "Start localnet"
                        }),
                    )
                    .clicked()
                {
                    self.lifecycle(true);
                }
                if ui
                    .add_enabled(self.workspace.is_some(), egui::Button::new("New localnet…"))
                    .clicked()
                {
                    self.localnet_dialog = Some(LocalnetDialog::new(&self.names));
                }
                if ui
                    .add_enabled(
                        self.workspace.is_some(),
                        egui::Button::new("Private dataspace…"),
                    )
                    .clicked()
                {
                    self.private_dialog = true;
                }
                if ui
                    .add_enabled(
                        matches!(phase, Some(ManagedPhase::Ready | ManagedPhase::Starting)),
                        egui::Button::new("Stop"),
                    )
                    .clicked()
                {
                    self.lifecycle(false);
                }
                if ui
                    .add_enabled(self.selected.is_some(), egui::Button::new("Refresh"))
                    .clicked()
                {
                    self.error = None;
                    self.refresh_selection();
                }
                if ui
                    .add_enabled(
                        matches!(phase, Some(ManagedPhase::Stopped | ManagedPhase::Failed)),
                        egui::Button::new("Reset…"),
                    )
                    .clicked()
                {
                    self.reset_intent = true;
                }
            });
        });
        if let Some(selected) = &self.selected {
            ui.horizontal(|ui| {
                ui.strong(format!(
                    "{:?} · {} / 4 validators",
                    selected.phase, selected.running
                ));
                ui.label(&selected.network.prepared().context.chain_id);
            });
            if let Some(failure) = &selected.failure {
                ui.colored_label(egui::Color32::LIGHT_RED, failure);
            }
            match &selected.attachment {
                Ok(Some(status)) => attachment_details(ui, status),
                Err(error) => {
                    ui.colored_label(
                        egui::Color32::LIGHT_RED,
                        format!("Parent status unavailable: {error}"),
                    );
                }
                Ok(None) => {}
            }
        } else if let Some(name) = &self.attaching {
            ui.label(format!("Setting up private dataspace {name}…"));
            if let Some(status) = &self.attachment_progress {
                ui.label(format!(
                    "{:?} · {} / 4 local validators",
                    status.local.phase, status.local.running_peers
                ));
                attachment_details(ui, &status.attachment);
            }
        } else if self.workspace.is_some() {
            ui.label("Start creates four local validators, a funded account and your client context. No configuration files needed.");
        }
    }

    fn dashboard(&mut self, ui: &mut egui::Ui) {
        ui.heading("Your environment");
        ui.label(
            "Kagami and Mochi share this network. It stays available when you close the desktop.",
        );
        let Some(selected) = self.selected.as_ref() else {
            return;
        };
        let context = &selected.network.prepared().context;
        public_value(ui, "Account", &context.account_id);
        public_value(ui, "Network", &context.network_id);
        public_value(ui, "Dataspace", &context.dataspace_alias);
        ui.separator();
        for (index, peer) in selected.network.prepared().peers.iter().enumerate() {
            ui.horizontal(|ui| {
                ui.label(format!("Validator {}", index + 1));
                ui.monospace(&peer.torii_url);
                if ui.small_button("Copy URL").clicked() {
                    ui.ctx().copy_text(peer.torii_url.clone());
                }
            });
        }
        if ui
            .add_enabled(
                !self.busy && selected.phase == ManagedPhase::Ready,
                egui::Button::new("Refresh balances and blocks"),
            )
            .clicked()
        {
            let network = selected.network.clone();
            let peer = self.peer;
            if let Some(handle) = self.runtime.as_ref().map(|r| r.handle().clone()) {
                self.spawn(move || {
                    Message::Dashboard((|| {
                        let client = network.observer(peer).map_err(|e| e.to_string())?;
                        let context = &network.prepared().context;
                        let snapshot = handle
                            .block_on(fetch_dashboard_snapshot(
                                format!("Validator {}", peer + 1),
                                &client,
                                vec![DashboardAccountInput {
                                    label: context.name.clone(),
                                    account_id: context.account_id.clone(),
                                }],
                            ))
                            .map_err(|e| format!("{e:?}"))?;
                        network.validate().map_err(|e| e.to_string())?;
                        Ok(snapshot)
                    })())
                });
            }
        }
        if let Some(snapshot) = &self.dashboard {
            ui.separator();
            ui.strong("Balances");
            for account in &snapshot.accounts {
                for balance in &account.balances {
                    ui.label(format!("{}  {}", balance.value, balance.definition_id));
                }
            }
            ui.strong("Recent blocks");
            for block in &snapshot.recent_blocks {
                ui.label(format!(
                    "#{} · {} transactions · {} rejected",
                    block.height, block.transactions_total, block.transactions_rejected
                ));
            }
        }
    }

    fn state(&mut self, ui: &mut egui::Ui) {
        ui.heading("State explorer");
        ui.horizontal(|ui| {
            let before = self.query;
            egui::ComboBox::from_id_salt("state_kind")
                .selected_text(self.query.label())
                .show_ui(ui, |ui| {
                    for kind in StateQueryKind::all() {
                        ui.selectable_value(&mut self.query, kind, kind.label());
                    }
                });
            if self.query != before {
                self.page = None;
            }
            if ui
                .add_enabled(!self.busy && self.ready(), egui::Button::new("Query"))
                .clicked()
            {
                self.fetch_state(false);
            }
            if ui
                .add_enabled(
                    !self.busy && self.page.as_ref().is_some_and(|p| p.cursor.is_some()),
                    egui::Button::new("Next page"),
                )
                .clicked()
            {
                self.fetch_state(true);
            }
            ui.add(egui::TextEdit::singleline(&mut self.filter).hint_text("Filter this page"));
        });
        if let Some(page) = &self.page {
            if page.kind != self.query {
                return;
            }
            ui.label(format!(
                "{} records on this page · {} remaining",
                page.entries.len(),
                page.remaining
            ));
            let filter = self.filter.to_lowercase();
            for entry in page
                .entries
                .iter()
                .filter(|e| e.search_blob.contains(&filter))
            {
                egui::CollapsingHeader::new(&entry.title)
                    .id_salt(&entry.title)
                    .show(ui, |ui| {
                        ui.label(&entry.subtitle);
                        ui.label(&entry.detail);
                        ui.horizontal(|ui| {
                            if let Some(json) = &entry.json {
                                if ui.button("Copy JSON").clicked() {
                                    ui.ctx().copy_text(json.clone());
                                }
                            }
                            if let Some(bytes) = &entry.norito_bytes {
                                if ui.button("Copy Norito hex").clicked() {
                                    ui.ctx().copy_text(hex::encode(bytes));
                                }
                            }
                        });
                        ui.monospace(entry.json.as_deref().unwrap_or(&entry.raw));
                    });
            }
        }
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
                handle
                    .block_on(run_state_query(
                        client,
                        &network.signer(),
                        network.address_discriminant(),
                        kind,
                        cursor,
                        std::num::NonZeroU64::new(50),
                    ))
                    .map_err(|e| e.to_string())
            })())
        });
    }

    fn activity(&mut self, ui: &mut egui::Ui) {
        ui.heading("Activity");
        ui.label("Canonical block and event streams from the selected validator.");
        for entry in self.activity.iter().rev().take(100) {
            ui.monospace(entry);
        }
        ui.separator();
        ui.horizontal(|ui| {
            ui.strong("Validator logs");
            if ui
                .add_enabled(
                    !self.busy && self.selected.is_some(),
                    egui::Button::new("Read latest logs"),
                )
                .clicked()
            {
                if let (Some(workspace), Some(selected)) =
                    (self.workspace.clone(), self.selected.as_ref())
                {
                    let name = selected.network.prepared().context.name.clone();
                    let peer = self.peer;
                    self.spawn(move || {
                        Message::Logs(
                            workspace
                                .logs(&name, Some(peer), 64 * 1024)
                                .map_err(|e| e.to_string()),
                        )
                    });
                }
            }
        });
        ui.add(
            egui::TextEdit::multiline(&mut self.logs)
                .font(egui::TextStyle::Monospace)
                .desired_width(f32::INFINITY)
                .desired_rows(14)
                .interactive(false),
        );
    }

    fn composer(&mut self, ui: &mut egui::Ui) {
        let _address_profile = self.selected.as_ref().map(|selected| {
            iroha_data_model::account::address::ChainDiscriminantGuard::enter(
                selected.network.address_discriminant(),
            )
        });
        ui.heading("Compose a transaction");
        ui.label("Build instructions, review the exact signed transaction, then submit it once.");
        ui.horizontal(|ui| {
            const ACTIONS: [&str; 4] = ["Mint", "Burn", "Transfer", "Register account"];
            egui::ComboBox::from_id_salt("instruction")
                .selected_text(ACTIONS[self.action])
                .show_ui(ui, |ui| {
                    for (index, label) in ACTIONS.iter().enumerate() {
                        ui.selectable_value(&mut self.action, index, *label);
                    }
                });
            ui.add(
                egui::TextEdit::singleline(&mut self.asset)
                    .hint_text(if self.action == 3 {
                        "Account ID"
                    } else {
                        "Asset ID"
                    })
                    .desired_width(420.0),
            );
            if self.action != 3 {
                ui.add(
                    egui::TextEdit::singleline(&mut self.quantity)
                        .hint_text("Quantity")
                        .desired_width(90.0),
                );
            }
        });
        if self.action == 2 {
            ui.add(
                egui::TextEdit::singleline(&mut self.destination)
                    .hint_text("Destination account ID")
                    .desired_width(600.0),
            );
        }
        if ui.button("Add instruction").clicked() {
            let draft = match self.action {
                0 => InstructionDraft::mint_from_input(&self.asset, &self.quantity),
                1 => InstructionDraft::burn_from_input(&self.asset, &self.quantity),
                2 => InstructionDraft::transfer_from_input(
                    &self.asset,
                    &self.quantity,
                    &self.destination,
                ),
                _ => InstructionDraft::register_account_from_input(&self.asset),
            };
            let result = draft.and_then(|draft| {
                let mut drafts = drafts_from_json_str(&self.drafts)?;
                drafts.push(draft);
                drafts_to_pretty_json(&drafts)
            });
            match result {
                Ok(drafts) => {
                    self.drafts = drafts;
                    self.preview = None;
                }
                Err(error) => self.error = Some(error.to_string()),
            }
        }
        ui.label("Draft JSON also supports asset definitions, roles, multisig and chain policy instructions.");
        if ui
            .add(
                egui::TextEdit::multiline(&mut self.drafts)
                    .code_editor()
                    .desired_width(f32::INFINITY)
                    .desired_rows(12),
            )
            .changed()
        {
            self.preview = None;
        }
        if ui
            .add_enabled(
                !self.busy && self.ready(),
                egui::Button::new("Review transaction"),
            )
            .clicked()
        {
            if let Some(selected) = &self.selected {
                match drafts_from_json_str(&self.drafts)
                    .map_err(|e| e.to_string())
                    .and_then(|drafts| selected.network.preview(&drafts).map_err(|e| e.to_string()))
                {
                    Ok(preview) => {
                        self.preview = Some(preview);
                        self.submitted_hash = None;
                    }
                    Err(error) => self.error = Some(error),
                }
            }
        }
        if let Some(preview) = &self.preview {
            ui.separator();
            public_value(ui, "Authority", preview.authority());
            public_value(ui, "Transaction", preview.hash());
            for instruction in preview.instructions() {
                ui.label(instruction);
            }
            if ui.button("Copy signed Norito hex").clicked() {
                ui.ctx().copy_text(preview.encoded_hex().to_owned());
            }
            if ui
                .add_enabled(
                    !self.busy && self.submitted_hash.as_deref() != Some(preview.hash()),
                    egui::Button::new("Submit reviewed transaction"),
                )
                .clicked()
            {
                if let (Some(selected), Some(handle)) = (
                    &self.selected,
                    self.runtime.as_ref().map(|r| r.handle().clone()),
                ) {
                    let network = selected.network.clone();
                    let peer = self.peer;
                    let preview = preview.clone();
                    self.submitted_hash = Some(preview.hash().to_owned());
                    self.spawn(move || Message::Submitted(handle.block_on(network.submit(peer, &preview)).map(|commit| format!("Applied {} in block {}", preview.hash(), commit.block_height))
                        .map_err(|e| format!("Transaction {}: {e}. Keep this original hash when checking an uncertain outcome.", preview.hash()))));
                }
            }
        }
    }

    fn contracts(&mut self, ui: &mut egui::Ui) {
        ui.heading("Deploy a smart contract");
        ui.label("Choose a .ko source, .to artifact, or Musubi package. Compilation, fees and durable recovery use the same service as Kagami.");
        ui.add(
            egui::TextEdit::singleline(&mut self.contract_path)
                .hint_text("Contract path")
                .desired_width(700.0),
        );
        ui.add(
            egui::TextEdit::singleline(&mut self.contract_alias)
                .hint_text("Alias (optional; generated in the selected dataspace)")
                .desired_width(700.0),
        );
        egui::CollapsingHeader::new("Package options").show(ui, |ui| {
            ui.add(
                egui::TextEdit::singleline(&mut self.package)
                    .hint_text("Package selector (optional)"),
            );
            ui.add(
                egui::TextEdit::singleline(&mut self.contract)
                    .hint_text("Contract target (optional)"),
            );
            ui.checkbox(&mut self.locked, "Require unchanged dependency lock");
        });
        if ui
            .add_enabled(
                !self.busy && self.workspace.is_some() && !self.contract_path.trim().is_empty(),
                egui::Button::new("Prepare deployment"),
            )
            .clicked()
        {
            self.deploy(false);
        }
        ui.separator();
        ui.label("Resume an interrupted deployment using its retained journal.");
        ui.add(
            egui::TextEdit::singleline(&mut self.journal_path)
                .hint_text("Journal path")
                .desired_width(700.0),
        );
        if ui
            .add_enabled(
                !self.busy && self.workspace.is_some() && !self.journal_path.trim().is_empty(),
                egui::Button::new("Review and resume"),
            )
            .clicked()
        {
            self.deploy(true);
        }
        if let Some(receipt) = &self.receipt {
            ui.separator();
            ui.strong("Verified deployment receipt");
            if ui.button("Copy receipt").clicked() {
                ui.ctx().copy_text(receipt.clone());
            }
            ui.monospace(receipt);
        }
    }

    fn deploy(&mut self, resume: bool) {
        let Some(workspace) = self.workspace.clone() else {
            return;
        };
        let context = self
            .selected
            .as_ref()
            .map(|s| s.network.prepared().context.name.clone());
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
                let run = if resume {
                    workspace.resume(&path, context.as_deref(), &mut review, &mut progress)
                } else {
                    let input = ContractInput::from_path(&path, package, contract, locked)
                        .map_err(|e| e.to_string())?;
                    let alias = alias
                        .map(|value| value.parse())
                        .transpose()
                        .map_err(|e| format!("Invalid contract alias: {e}"))?;
                    workspace.deploy(
                        &input,
                        context.as_deref(),
                        alias,
                        &mut review,
                        &mut progress,
                    )
                }
                .map_err(|e| e.to_string())?;
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
            let refreshed = inspect_workspace(workspace);
            Message::Deployed { result, refreshed }
        });
    }

    fn packages(&mut self, ui: &mut egui::Ui) {
        if let Some(action) = self
            .publication
            .show(ui, !self.busy && self.workspace.is_some())
        {
            self.publish_package(action);
        }
        if let Some(output) = &self.publication_output {
            output.show(ui);
        }
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
        let context = self
            .selected
            .as_ref()
            .map(|selected| selected.network.prepared().context.name.clone());
        let manifest = PathBuf::from(if self.publication.manifest.is_empty() {
            "."
        } else {
            &self.publication.manifest
        });
        self.publication_output = None;
        self.notice = None;
        self.spawn(move || {
            let result = workspace
                .publish_package(&manifest, context.as_deref(), action)
                .map_err(|error| error.to_string())
                .and_then(PublicationOutput::from_outcome);
            Message::Published {
                result,
                refreshed: inspect_workspace(workspace),
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
        let mut decision = None;
        let viewport = context.content_rect();
        let width = (viewport.width() - 48.0).clamp(160.0, 760.0);
        let evidence_height = (viewport.height() - 200.0).clamp(40.0, 400.0);
        egui::Modal::new(egui::Id::new("deployment-review")).show(context, |ui| {
            ui.set_width(width);
            ui.heading("Review deployment");
            ui.strong("Review the exact deployment and quoted fees");
            egui::ScrollArea::vertical()
                .max_height(evidence_height)
                .show(ui, |ui| {
                    ui.add(
                        egui::Label::new(egui::RichText::new(&review.evidence).monospace()).wrap(),
                    );
                });
            ui.horizontal_wrapped(|ui| {
                if ui.button("Deploy with these fees").clicked() {
                    decision = Some(true);
                }
                if ui.button("Cancel").clicked() {
                    decision = Some(false);
                }
            });
        });
        if let Some(accepted) = decision {
            if let Some(review) = self.review.take() {
                let _ = review.decision.send(accepted);
            }
        }
    }

    fn private_dataspace_dialog(&mut self, context: &egui::Context) {
        if !self.private_dialog {
            return;
        }
        egui::Window::new("Private dataspace")
            .collapsible(false).resizable(false).show(context, |ui| {
                ui.label("Run four private validators here and connect them to your selected network.");
                ui.label("Contract data stays on this computer. The parent receives certified commitments.");
                ui.horizontal(|ui| {
                    ui.label("Name");
                    ui.text_edit_singleline(&mut self.private_alias);
                });
                let available = match &self.profiles {
                    Ok(profiles) if !profiles.is_empty() => {
                        egui::ComboBox::from_id_salt("private-network").selected_text(&self.private_network).show_ui(ui, |ui| {
                            for name in profiles { ui.selectable_value(&mut self.private_network, name.clone(), name); }
                        });
                        true
                    }
                    Ok(_) => { ui.label("This installation has no network profiles. Install a bundle that includes your network."); false }
                    Err(error) => { ui.label("Installed network profiles are unavailable. Localnets remain available."); ui.colored_label(egui::Color32::LIGHT_RED, bounded_text(error)); false }
                };
                ui.horizontal(|ui| {
                    if ui.button("Cancel").clicked() { self.private_dialog = false; }
                    if ui.add_enabled(available && !self.busy && self.workspace.is_some() && !self.private_alias.trim().is_empty(), egui::Button::new("Start private dataspace")).clicked() { self.attach(); }
                });
            });
    }
}

impl Desktop {
    fn show(&mut self, context: &egui::Context) {
        egui::TopBottomPanel::top("workspace").show(context, |ui| self.top_bar(ui));
        egui::SidePanel::left("navigation")
            .resizable(false)
            .min_width(155.0)
            .show(context, |ui| {
                ui.add_space(12.0);
                for view in View::ALL {
                    ui.selectable_value(&mut self.view, view, view.label());
                }
                ui.separator();
                if let Some(selected) = &self.selected {
                    ui.label("Observe validator");
                    let before = self.peer;
                    ui.add_enabled_ui(!self.busy, |ui| {
                        for index in 0..selected.network.prepared().peers.len() {
                            ui.selectable_value(
                                &mut self.peer,
                                index,
                                format!("Validator {}", index + 1),
                            );
                        }
                    });
                    if self.peer != before {
                        self.blocks = None;
                        self.events = None;
                        self.page = None;
                        self.dashboard = None;
                        self.connect_streams();
                    }
                }
            });
        egui::CentralPanel::default().show(context, |ui| {
            if let Some(error) = &self.error {
                ui.colored_label(egui::Color32::LIGHT_RED, error);
                ui.separator();
            }
            if let Some(notice) = &self.notice {
                ui.colored_label(egui::Color32::LIGHT_GREEN, notice);
                ui.separator();
            }
            egui::ScrollArea::vertical().show(ui, |ui| match self.view {
                View::Dashboard => self.dashboard(ui),
                View::State => self.state(ui),
                View::Activity => self.activity(ui),
                View::Composer => self.composer(ui),
                View::Contracts => self.contracts(ui),
                View::Packages => self.packages(ui),
            });
        });
        if self.reset_intent {
            egui::Window::new("Reset local environment?").collapsible(false).resizable(false).show(context, |ui| {
                ui.label("This removes the stopped environment's local keys and ledger. Its old ledger cannot be restored. Remote attachment history remains retained.");
                ui.horizontal(|ui| {
                    if ui.button("Cancel").clicked() { self.reset_intent = false; }
                    if ui.add_enabled(!self.busy, egui::Button::new("Reset local data")).clicked() {
                        self.reset_intent = false;
                        if let (Some(workspace), Some(selected)) = (self.workspace.clone(), &self.selected) {
                            let name = selected.network.prepared().context.name.clone();
                            self.spawn(move || Message::Reset(workspace.reset(&name).map_err(|e| e.to_string())
                                .and_then(|_| workspace.contexts().map(|contexts| contexts.into_iter().map(|c| c.name).collect()).map_err(|e| e.to_string()))));
                        }
                    }
                });
            });
        }
        if let Some(dialog) = &mut self.localnet_dialog {
            if let Some(action) = dialog.show(context, &self.names, self.busy) {
                self.localnet_dialog = None;
                if let LocalnetDialogAction::Start(name) = action {
                    self.start_localnet(name);
                }
            }
        }
        self.private_dataspace_dialog(context);
        self.review_dialog(context);
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
    ui.label(attachment_summary(status));
    if let Some(cursor) = &status.local_successor {
        ui.label(format!("Last observed private block #{}", cursor.height));
    }
    if let Some(wallet) = &status.wallet_status {
        ui.label(format!("Parent operation: {wallet}"));
    }
    if let Some(failure) = &status.failure {
        ui.colored_label(egui::Color32::LIGHT_RED, failure.to_string());
    }
}

fn public_value(ui: &mut egui::Ui, label: &str, value: &str) {
    ui.horizontal_wrapped(|ui| {
        ui.strong(label);
        ui.monospace(value);
        if ui.small_button("Copy").clicked() {
            ui.ctx().copy_text(value.to_owned());
        }
    });
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
) {
    for _ in 0..64 {
        match receiver.try_recv() {
            Ok(event) => push_activity(activity, summarize(&event)),
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
        desktop.view = View::Dashboard;
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
                    View::Dashboard => desktop.dashboard(ui),
                    View::State => desktop.state(ui),
                    View::Activity => desktop.activity(ui),
                    View::Composer => desktop.composer(ui),
                    View::Contracts => desktop.contracts(ui),
                    View::Packages => desktop.packages(ui),
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
        drain_stream(&mut receiver, &mut activity, |event| event.to_string());
        assert!(activity.front().unwrap().contains("skipped"));
        assert_eq!(activity.back().unwrap(), "9");
    }
}

#[cfg(test)]
#[path = "gui/publication_tests.rs"]
mod publication_tests;
