//! Window chrome: the brand header with environment switcher and lifecycle controls, the
//! Ganache-style status strip, the navigation sidebar and message banners.

use super::{
    Desktop, LocalnetDialog, View,
    brand::{self, Mood},
    theme,
    widgets::{self, Tone, icon},
};
use eframe::egui::{
    self, Align, Layout, PopupCloseBehavior, RichText, Sense, ThemePreference, Ui, Vec2,
};
use mochi_core::developer::ManagedPhase;

impl View {
    pub(super) fn icon(self) -> &'static str {
        match self {
            Self::Home => icon::HOME,
            Self::Accounts => icon::ACCOUNTS,
            Self::Blocks => icon::BLOCKS,
            Self::Activity => icon::ACTIVITY,
            Self::State => icon::STATE,
            Self::Composer => icon::COMPOSE,
            Self::Contracts => icon::CONTRACTS,
            Self::Packages => icon::PACKAGES,
            Self::Endpoints => icon::ENDPOINTS,
            Self::Logs => icon::LOGS,
        }
    }
}

/// Environment-menu choices, applied after the popup closes.
enum EnvironmentChoice {
    Select(String),
    NewLocalnet,
    PrivateDataspace,
}

impl Desktop {
    pub(super) fn header(&mut self, ui: &mut Ui) {
        let palette = widgets::palette(ui);
        let phase = self.selected.as_ref().map(|selected| selected.phase);
        ui.horizontal(|ui| {
            brand::lockup(
                ui,
                self.brand.as_ref(),
                palette.text,
                Mood::for_phase(phase),
            );
            ui.add_space(14.0);
            ui.add_enabled_ui(!self.busy, |ui| {
                self.environment_menu(ui);
                self.lifecycle_controls(ui);
            });
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                self.theme_toggle(ui);
                self.workspace_menu(ui);
                if self.busy && self.foreground {
                    ui.label(RichText::new("Working…").color(palette.muted));
                    ui.add(egui::Spinner::new().color(palette.sakura));
                }
            });
        });
    }

    fn environment_menu(&mut self, ui: &mut Ui) {
        let palette = widgets::palette(ui);
        let current = self.selected.as_ref().map(|selected| {
            (
                selected.network.prepared().context.name.clone(),
                selected.phase,
            )
        });
        let color = current.as_ref().map_or(palette.faint, |(_, phase)| {
            theme::phase_colors(palette, *phase).0
        });
        let label = current
            .as_ref()
            .map_or_else(|| "Choose environment".to_owned(), |(name, _)| name.clone());
        let response = egui::Frame::new()
            .fill(palette.inset)
            .corner_radius(egui::CornerRadius::same(theme::CONTROL_RADIUS))
            .inner_margin(egui::Margin::symmetric(10, 5))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 7.0;
                    widgets::dot(ui, color, 4.5);
                    ui.label(RichText::new(&label).strong().color(palette.text));
                    ui.label(RichText::new(icon::MENU).color(palette.muted));
                });
            })
            .response
            .interact(Sense::click())
            .on_hover_cursor(egui::CursorIcon::PointingHand)
            .on_hover_text("Switch, create or attach environments");
        let mut choice = None;
        egui::Popup::menu(&response).show(|ui| {
            ui.set_min_width(240.0);
            ui.label(widgets::eyebrow(palette, "Environments"));
            if self.names.is_empty() {
                ui.label(RichText::new("None yet").color(palette.faint));
            }
            for name in &self.names {
                let selected = current.as_ref().is_some_and(|(current, _)| current == name);
                if ui.selectable_label(selected, name.as_str()).clicked() && !selected {
                    choice = Some(EnvironmentChoice::Select(name.clone()));
                }
            }
            ui.separator();
            if ui
                .add_enabled(
                    self.workspace.is_some(),
                    egui::Button::new(format!("{}  New localnet…", icon::NEW)),
                )
                .clicked()
            {
                choice = Some(EnvironmentChoice::NewLocalnet);
            }
            if ui
                .add_enabled(
                    self.workspace.is_some(),
                    egui::Button::new(format!("{}  Private dataspace…", icon::PRIVATE)),
                )
                .clicked()
            {
                choice = Some(EnvironmentChoice::PrivateDataspace);
            }
        });
        match choice {
            Some(EnvironmentChoice::Select(name)) => self.select(name),
            Some(EnvironmentChoice::NewLocalnet) => {
                self.localnet_dialog = Some(LocalnetDialog::new(&self.names));
            }
            Some(EnvironmentChoice::PrivateDataspace) => self.private_dialog = true,
            None => {}
        }
    }

    fn lifecycle_controls(&mut self, ui: &mut Ui) {
        let palette = widgets::palette(ui);
        let phase = self.selected.as_ref().map(|selected| selected.phase);
        if self.selected.is_none() {
            if ui
                .add_enabled(
                    self.workspace.is_some(),
                    widgets::primary_button(palette, &format!("{}  Quickstart", icon::QUICKSTART)),
                )
                .on_hover_text("Create and start a new four-validator localnet")
                .clicked()
            {
                self.quickstart();
            }
            return;
        }
        let startable = phase != Some(ManagedPhase::Ready);
        let start = if startable {
            widgets::primary_button(palette, &format!("{}  Start", icon::START))
        } else {
            widgets::tonal_button(
                &format!("{}  Start", icon::START),
                palette.muted,
                palette.inset,
            )
        };
        if ui
            .add_enabled(self.workspace.is_some() && startable, start)
            .on_hover_text("Start this environment's validators")
            .clicked()
        {
            self.lifecycle(true);
        }
        if ui
            .add_enabled(
                matches!(phase, Some(ManagedPhase::Ready | ManagedPhase::Starting)),
                widgets::tonal_button(
                    &format!("{}  Stop", icon::STOP),
                    palette.text,
                    palette.inset,
                ),
            )
            .on_hover_text("Stop the validators; keys, ledger and selection are kept")
            .clicked()
        {
            self.lifecycle(false);
        }
        if ui
            .add(
                widgets::tonal_button(icon::REFRESH, palette.text, palette.inset)
                    .min_size(Vec2::new(34.0, 32.0)),
            )
            .on_hover_text("Refresh")
            .clicked()
        {
            self.error = None;
            self.refresh_selection();
        }
        if ui
            .add_enabled(
                matches!(phase, Some(ManagedPhase::Stopped | ManagedPhase::Failed)),
                widgets::tonal_button(
                    &format!("{}  Reset…", icon::RESET),
                    palette.aka,
                    palette.aka_soft,
                ),
            )
            .on_hover_text("Erase this stopped environment's local ledger and keys")
            .clicked()
        {
            self.reset_intent = true;
        }
    }

    fn theme_toggle(&mut self, ui: &mut Ui) {
        let palette = widgets::palette(ui);
        let dark = ui.ctx().theme() == egui::Theme::Dark;
        let (glyph, next, tip) = if dark {
            (
                icon::LIGHT,
                ThemePreference::Light,
                "Switch to the light theme",
            )
        } else {
            (
                icon::DARK,
                ThemePreference::Dark,
                "Switch to the dark theme",
            )
        };
        if ui
            .add(
                widgets::tonal_button(glyph, palette.text, palette.inset)
                    .min_size(Vec2::new(34.0, 32.0)),
            )
            .on_hover_text(tip)
            .clicked()
        {
            ui.ctx().set_theme(next);
        }
    }

    fn workspace_menu(&mut self, ui: &mut Ui) {
        let palette = widgets::palette(ui);
        let folder = self.workspace_path.native.file_name().map_or_else(
            || self.workspace_path.text.clone(),
            |name| name.to_string_lossy().into_owned(),
        );
        let response = ui
            .add(widgets::tonal_button(
                &format!("{}  {}", icon::FOLDER, widgets::short_middle(&folder, 12)),
                palette.text,
                palette.inset,
            ))
            .on_hover_text(format!("Workspace: {}", self.workspace_path.text));
        let mut open = false;
        egui::Popup::from_toggle_button_response(&response)
            .close_behavior(PopupCloseBehavior::CloseOnClickOutside)
            .width(460.0)
            .show(|ui| {
                ui.label(widgets::eyebrow(palette, "Workspace"));
                widgets::hint(
                    ui,
                    "Mochi and Kagami share environments per workspace directory. Opening one starts nothing.",
                );
                ui.add_enabled_ui(!self.busy, |ui| {
                    ui.horizontal(|ui| {
                        self.workspace_path.show(ui);
                        if ui.add(widgets::primary_button(palette, "Open")).clicked() {
                            open = true;
                        }
                    });
                });
                if let Some(workspace) = &self.workspace {
                    ui.label(
                        RichText::new(format!("State: {}", workspace.state_root().display()))
                            .small()
                            .color(palette.faint),
                    );
                }
            });
        if open {
            self.open();
        }
    }

    pub(super) fn status_strip(&mut self, ui: &mut Ui) {
        let palette = widgets::palette(ui);
        ui.horizontal_wrapped(|ui| {
            ui.spacing_mut().item_spacing.x = 22.0;
            if let Some(selected) = &self.selected {
                let prepared = selected.network.prepared();
                let context = &prepared.context;
                widgets::stat(ui, "Status", |ui| {
                    widgets::phase_pill(ui, selected.phase);
                });
                widgets::stat(ui, "Validators", |ui| {
                    ui.horizontal(|ui| {
                        widgets::validator_dots(ui, selected.running, prepared.peers.len());
                        ui.label(
                            RichText::new(format!("{}/{}", selected.running, prepared.peers.len()))
                                .strong()
                                .color(palette.text),
                        );
                    });
                });
                widgets::stat(ui, "Block height", |ui| {
                    ui.label(
                        RichText::new(
                            self.latest_height
                                .map_or_else(|| "—".to_owned(), |height| format!("#{height}")),
                        )
                        .strong()
                        .color(palette.sky),
                    );
                });
                let torii = prepared
                    .peers
                    .get(self.peer)
                    .map_or(context.torii_url.as_str(), |peer| peer.torii_url.as_str());
                for (label, value, keep) in [
                    ("Chain", context.chain_id.as_str(), 10),
                    ("Network", context.network_id.as_str(), 6),
                    ("Dataspace", context.dataspace_alias.as_str(), 12),
                    ("Torii", torii, 24),
                ] {
                    widgets::stat(ui, label, |ui| {
                        let response = ui
                            .add(
                                egui::Label::new(
                                    RichText::new(widgets::short_middle(value, keep))
                                        .monospace()
                                        .color(palette.text),
                                )
                                .sense(Sense::click()),
                            )
                            .on_hover_text(format!("{value}\nClick to copy"))
                            .on_hover_cursor(egui::CursorIcon::Copy);
                        if response.clicked() {
                            widgets::copy_to_clipboard(ui.ctx(), value, &label.to_lowercase());
                        }
                    });
                }
            } else if let Some(name) = &self.attaching {
                ui.add(egui::Spinner::new().color(palette.sakura));
                ui.label(
                    RichText::new(format!("Setting up private dataspace {name}…"))
                        .color(palette.text),
                );
                if let Some(status) = &self.attachment_progress {
                    widgets::phase_pill(ui, status.local.phase);
                    ui.label(
                        RichText::new(format!(
                            "{} / 4 local validators",
                            status.local.running_peers
                        ))
                        .color(palette.muted),
                    );
                }
            } else if self.workspace.is_some() {
                ui.label(
                    RichText::new(
                        "No environment selected. Quickstart creates four validators, a funded account and your client context. No configuration files needed.",
                    )
                    .color(palette.muted),
                );
            } else {
                ui.label(RichText::new("Opening workspace…").color(palette.muted));
            }
        });
    }

    pub(super) fn navigation(&mut self, ui: &mut Ui) {
        let palette = widgets::palette(ui);
        ui.add_space(10.0);
        for view in View::ALL {
            let badge = match view {
                View::Blocks => Some(self.blocks_feed.len()),
                View::Accounts => self
                    .ledger
                    .as_ref()
                    .map(|ledger| ledger.accounts.entries.len()),
                _ => None,
            };
            if widgets::nav_item(ui, self.view == view, view.icon(), view.label(), badge).clicked()
            {
                self.view = view;
            }
        }
        if let Some(selected) = &self.selected {
            let peers = selected.network.prepared().peers.len();
            ui.add_space(14.0);
            ui.label(widgets::eyebrow(palette, "Observe validator"));
            let mut chosen = self.peer;
            ui.add_enabled_ui(!self.busy, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.spacing_mut().item_spacing = Vec2::splat(4.0);
                    for index in 0..peers {
                        let selected = index == chosen;
                        let button = egui::Button::new(
                            RichText::new(format!("V{}", index + 1))
                                .strong()
                                .color(if selected {
                                    palette.on_sakura
                                } else {
                                    palette.muted
                                }),
                        )
                        .fill(if selected {
                            palette.sakura
                        } else {
                            palette.inset
                        })
                        .corner_radius(egui::CornerRadius::same(8))
                        .min_size(Vec2::new(36.0, 28.0));
                        if ui
                            .add(button)
                            .on_hover_text(format!("Stream from validator {}", index + 1))
                            .clicked()
                        {
                            chosen = index;
                        }
                    }
                });
            });
            if chosen != self.peer {
                self.observe_peer(chosen);
            }
        }
        // The mascot only takes room the navigation does not need on short windows.
        if ui.available_height() > 190.0 {
            ui.with_layout(Layout::bottom_up(Align::Center), |ui| {
                ui.add_space(12.0);
                let mood = Mood::for_phase(self.selected.as_ref().map(|selected| selected.phase));
                brand::speech_bubble(ui, mood.caption(), palette.inset, palette.muted);
                brand::mascot(ui, self.brand.as_ref(), 92.0, mood);
            });
        }
    }

    /// Error, notice and validator-failure messages above the current view.
    pub(super) fn banners(&mut self, ui: &mut Ui) {
        if let Some(error) = self.error.clone()
            && widgets::banner(ui, Tone::Error, &error, true)
        {
            self.error = None;
        }
        if let Some(notice) = self.notice.clone()
            && widgets::banner(ui, Tone::Success, &notice, true)
        {
            self.notice = None;
        }
        if let Some(failure) = self
            .selected
            .as_ref()
            .and_then(|selected| selected.failure.clone())
        {
            widgets::banner(ui, Tone::Error, &failure, false);
        }
    }
}
