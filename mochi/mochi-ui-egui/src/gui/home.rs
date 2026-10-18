//! Home: the Quickstart welcome when nothing is selected, otherwise a live overview of the
//! validators, the developer account, the latest blocks and quick actions.

use super::{
    Desktop, LocalnetDialog, View,
    accounts::QuickKind,
    brand::{self, Mood},
    theme,
    widgets::{self, icon},
};
use eframe::egui::{self, Align, Layout, RichText, Ui, Vec2};
use mochi_core::developer::ManagedPhase;

/// Name Quickstart gives its new localnet: the first unused `local`, `local-2`, ….
pub(crate) fn quickstart_name(names: &[String]) -> String {
    LocalnetDialog::new(names).name
}

impl Desktop {
    pub(super) fn home(&mut self, ui: &mut Ui) {
        if self.selected.is_some() {
            self.overview(ui);
        } else {
            self.welcome(ui);
        }
    }

    /// Create a new four-validator localnet with a fresh name; it is selected when ready.
    pub(super) fn quickstart(&mut self) {
        if self.busy || self.workspace.is_none() {
            return;
        }
        let name = quickstart_name(&self.names);
        self.start_localnet(name);
    }

    fn welcome(&mut self, ui: &mut Ui) {
        let palette = widgets::palette(ui);
        let mood = if self.busy {
            Mood::Excited
        } else {
            Mood::Curious
        };
        widgets::card(ui, |ui| {
            ui.horizontal(|ui| {
                brand::mascot(ui, self.brand.as_ref(), 168.0, mood);
                ui.add_space(12.0);
                ui.vertical(|ui| {
                    ui.add_space(14.0);
                    ui.label(
                        RichText::new("Your Iroha playground")
                            .size(30.0)
                            .strong()
                            .color(palette.text),
                    );
                    ui.add(
                        egui::Label::new(
                            RichText::new(
                                "Spin up four validators with a funded developer account and live endpoints in seconds. No configuration files.",
                            )
                            .size(15.0)
                            .color(palette.muted),
                        )
                        .wrap(),
                    );
                    ui.add_space(10.0);
                    ui.horizontal_wrapped(|ui| {
                        let ready = !self.busy && self.workspace.is_some();
                        if ui
                            .add_enabled(
                                ready,
                                widgets::primary_button(
                                    palette,
                                    &format!("{}  Quickstart", icon::QUICKSTART),
                                )
                                .min_size(Vec2::new(150.0, 40.0)),
                            )
                            .on_hover_text("Create and start a new localnet with an unused name")
                            .clicked()
                        {
                            self.quickstart();
                        }
                        if ui
                            .add_enabled(
                                ready,
                                egui::Button::new(format!("{}  New localnet…", icon::NEW))
                                    .min_size(Vec2::new(0.0, 40.0)),
                            )
                            .clicked()
                        {
                            self.localnet_dialog = Some(LocalnetDialog::new(&self.names));
                        }
                        if ui
                            .add_enabled(
                                ready,
                                egui::Button::new(format!("{}  Private dataspace…", icon::PRIVATE))
                                    .min_size(Vec2::new(0.0, 40.0)),
                            )
                            .clicked()
                        {
                            self.private_dialog = true;
                        }
                    });
                    if self.busy {
                        ui.horizontal(|ui| {
                            ui.spinner();
                            ui.label(
                                RichText::new("Preparing validators… this usually takes a few seconds.")
                                    .color(palette.muted),
                            );
                        });
                    }
                });
            });
        });
        if let Some(name) = &self.attaching {
            ui.add_space(12.0);
            widgets::card(ui, |ui| {
                widgets::card_title(
                    ui,
                    icon::PRIVATE,
                    &format!("Setting up private dataspace {name}…"),
                );
                if let Some(status) = &self.attachment_progress {
                    ui.horizontal(|ui| {
                        widgets::phase_pill(ui, status.local.phase);
                        ui.label(format!(
                            "{} / 4 local validators",
                            status.local.running_peers
                        ));
                    });
                    super::attachment_details(ui, &status.attachment);
                }
            });
        }
        ui.add_space(12.0);
        let tiles = [
            (
                icon::BLOCKS,
                "Four validators",
                "A real Sumeragi network on your machine, not a simulator.",
            ),
            (
                icon::COINS,
                "Funded account",
                "A generated developer signer, ready to mint and send.",
            ),
            (
                icon::ENDPOINTS,
                "Live endpoints",
                "Torii, metrics and MCP URLs to paste into tests.",
            ),
            (
                icon::CONTRACTS,
                "Contracts",
                "Deploy Kotodama with an exact fee review.",
            ),
        ];
        let columns = if ui.available_width() > 900.0 { 4 } else { 2 };
        widgets::card_grid(ui, &tiles, columns, |ui, (glyph, title, body)| {
            widgets::card(ui, |ui| {
                widgets::icon_badge(ui, glyph, palette.sakura, palette.sakura_soft);
                ui.label(RichText::new(*title).strong().color(palette.text));
                widgets::hint(ui, body);
            });
        });
        if !self.names.is_empty() {
            ui.add_space(16.0);
            ui.label(
                RichText::new("Your environments")
                    .size(18.0)
                    .strong()
                    .color(palette.text),
            );
            widgets::hint(
                ui,
                "Kept by this workspace and shared with Kagami. Opening one does not start it.",
            );
            ui.add_space(4.0);
            let mut chosen = None;
            ui.horizontal_wrapped(|ui| {
                for name in &self.names {
                    ui.allocate_ui_with_layout(
                        Vec2::new(220.0, 0.0),
                        Layout::top_down(Align::Min),
                        |ui| {
                            widgets::card(ui, |ui| {
                                ui.horizontal(|ui| {
                                    widgets::icon_badge(
                                        ui,
                                        icon::BLOCKS,
                                        palette.sky,
                                        palette.sky_soft,
                                    );
                                    ui.label(RichText::new(name).strong().color(palette.text));
                                });
                                if ui
                                    .add_enabled(!self.busy, egui::Button::new("Open"))
                                    .clicked()
                                {
                                    chosen = Some(name.clone());
                                }
                            });
                        },
                    );
                }
            });
            if let Some(name) = chosen {
                self.select(name);
            }
        }
        ui.add_space(12.0);
        ui.horizontal_wrapped(|ui| {
            widgets::hint(ui, "Closing Mochi leaves your networks running, and");
            ui.code("kagami localnet up");
            widgets::hint(ui, "works on the same environments.");
        });
    }

    fn overview(&mut self, ui: &mut Ui) {
        let palette = widgets::palette(ui);
        let Some(selected) = &self.selected else {
            return;
        };
        let prepared = selected.network.prepared().clone();
        let phase = selected.phase;
        let attachment = selected.attachment.clone();
        let context = &prepared.context;
        ui.horizontal(|ui| {
            ui.label(
                RichText::new(&context.name)
                    .size(26.0)
                    .strong()
                    .color(palette.text),
            );
            widgets::phase_pill(ui, phase);
            ui.label(
                RichText::new(&context.chain_id)
                    .monospace()
                    .color(palette.muted),
            );
        });
        widgets::hint(
            ui,
            "Kagami and Mochi share this network. It stays available when you close the desktop.",
        );
        ui.add_space(10.0);
        ui.label(
            RichText::new("Validators")
                .size(17.0)
                .strong()
                .color(palette.text),
        );
        ui.add_space(2.0);
        let columns = if ui.available_width() > 1000.0 { 4 } else { 2 };
        let mut observe = None;
        let mut open = None;
        let peers = prepared.peers.iter().enumerate().collect::<Vec<_>>();
        let (busy, observed_peer) = (self.busy, self.peer);
        widgets::card_grid(ui, &peers, columns, |ui, (index, peer)| {
            let (index, observed) = (*index, *index == observed_peer);
            widgets::accent_card(ui, observed.then_some(palette.sakura), |ui| {
                ui.horizontal(|ui| {
                    let (fg, bg) = theme::phase_colors(palette, phase);
                    widgets::icon_badge(ui, icon::BLOCKS, fg, bg);
                    ui.label(
                        RichText::new(format!("Validator {}", index + 1))
                            .strong()
                            .color(palette.text),
                    );
                    if observed {
                        widgets::pill(ui, "observing", palette.sakura, palette.sakura_soft);
                    }
                });
                ui.horizontal_wrapped(|ui| {
                    ui.label(
                        RichText::new(&peer.torii_url)
                            .monospace()
                            .small()
                            .color(palette.muted),
                    );
                    widgets::copy_button(
                        ui,
                        &peer.torii_url,
                        &format!("validator {} URL", index + 1),
                    );
                });
                ui.horizontal_wrapped(|ui| {
                    ui.spacing_mut().item_spacing.x = 4.0;
                    if !observed
                        && ui
                            .add_enabled(!busy, egui::Button::new("Observe").small())
                            .on_hover_text("Stream blocks and events from this validator")
                            .clicked()
                    {
                        observe = Some(index);
                    }
                    if ui.small_button("Logs").clicked() {
                        open = Some((View::Logs, Some(index)));
                    }
                    if ui.small_button("Endpoints").clicked() {
                        open = Some((View::Endpoints, Some(index)));
                    }
                });
            });
        });
        if let Some(index) = observe {
            self.observe_peer(index);
        }
        if let Some((view, peer)) = open {
            self.view = view;
            if let Some(peer) = peer {
                self.logs_source = Some(peer);
                self.endpoint_peer = peer;
            }
        }
        ui.add_space(12.0);
        let ready = phase == ManagedPhase::Ready;
        let account = context.account_id.clone();
        ui.columns(2, |columns| {
            widgets::card(&mut columns[0], |ui| {
                widgets::card_title(ui, icon::KEY, "Developer account");
                ui.horizontal(|ui| {
                    widgets::short_mono(ui, &account, 12);
                    widgets::copy_button(ui, &account, "developer account");
                });
                ui.add_space(4.0);
                ui.label(widgets::eyebrow(palette, "Balances"));
                match &self.ledger {
                    Some(ledger) => {
                        let holdings = ledger.holdings_of(&account);
                        if holdings.is_empty() {
                            widgets::hint(ui, "No balances yet.");
                        }
                        for holding in holdings.iter().take(4) {
                            ui.horizontal(|ui| {
                                ui.label(RichText::new(holding.value).size(18.0).strong().color(palette.text));
                                ui.label(
                                    RichText::new(ledger.asset_label(holding.definition))
                                        .strong()
                                        .color(palette.sakura),
                                )
                                .on_hover_text(holding.asset);
                            });
                        }
                    }
                    None => {
                        widgets::hint(
                            ui,
                            if ready {
                                "Loading balances…"
                            } else {
                                "Balances appear once the validators are ready."
                            },
                        );
                    }
                }
            });
            widgets::card(&mut columns[1], |ui| {
                widgets::card_title(ui, icon::BLOCKS, "Latest blocks");
                if self.blocks_feed.is_empty() {
                    widgets::hint(
                        ui,
                        "No blocks streamed yet. Idle chains create no blocks; submit a transaction to make one.",
                    );
                }
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX));
                for row in self.blocks_feed.iter().take(5) {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(format!("#{}", row.height)).strong().color(palette.sky));
                        ui.label(format!(
                            "{} tx{}",
                            row.transactions,
                            if row.rejected > 0 {
                                format!(" · {} rejected", row.rejected)
                            } else {
                                String::new()
                            }
                        ));
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            ui.label(RichText::new(widgets::time_ago(row.created_ms, now)).small().color(palette.muted));
                        });
                    });
                }
            });
        });
        ui.add_space(12.0);
        ui.label(
            RichText::new("Quick actions")
                .size(17.0)
                .strong()
                .color(palette.text),
        );
        ui.add_space(2.0);
        let actions = [
            (
                icon::MINT,
                "Mint tokens",
                View::Accounts,
                Some(QuickKind::Mint),
            ),
            (
                icon::ACCOUNTS,
                "New account",
                View::Accounts,
                Some(QuickKind::NewAccount),
            ),
            (
                icon::SEND,
                "Send tokens",
                View::Accounts,
                Some(QuickKind::Transfer),
            ),
            (icon::CONTRACTS, "Deploy contract", View::Contracts, None),
            (icon::STATE, "Query state", View::State, None),
            (icon::ENDPOINTS, "Endpoints", View::Endpoints, None),
        ];
        let mut chosen = None;
        ui.horizontal_wrapped(|ui| {
            for (glyph, label, view, quick) in actions {
                if ui
                    .add(
                        widgets::tonal_button(
                            &format!("{glyph}  {label}"),
                            palette.text,
                            palette.surface,
                        )
                        .stroke(egui::Stroke::new(1.0, palette.border))
                        .min_size(Vec2::new(150.0, 44.0)),
                    )
                    .clicked()
                {
                    chosen = Some((view, quick));
                }
            }
        });
        if let Some((view, quick)) = chosen {
            self.view = view;
            if let Some(kind) = quick {
                self.quick.kind = kind;
                self.preview = None;
            }
        }
        if let Ok(Some(status)) = &attachment {
            ui.add_space(12.0);
            widgets::card(ui, |ui| {
                widgets::card_title(ui, icon::PRIVATE, "Parent attachment");
                super::attachment_details(ui, status);
            });
        } else if let Err(error) = &attachment {
            ui.add_space(12.0);
            widgets::banner(
                ui,
                widgets::Tone::Warning,
                &format!("Parent status unavailable: {error}"),
                false,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quickstart_picks_the_first_unused_localnet_name() {
        assert_eq!(quickstart_name(&[]), "local");
        assert_eq!(
            quickstart_name(&["local".into(), "local-2".into(), "demo".into()]),
            "local-3"
        );
    }

    #[test]
    fn quickstart_without_a_workspace_or_while_busy_starts_nothing() {
        let mut desktop = Desktop::model(std::path::PathBuf::from("unused"));
        desktop.quickstart();
        assert!(!desktop.busy);
        assert!(desktop.receiver.try_recv().is_err());
        desktop.busy = true;
        desktop.quickstart();
        assert!(desktop.receiver.try_recv().is_err());
    }

    #[test]
    fn welcome_offers_quickstart_without_starting_anything() {
        let mut desktop = Desktop::model(std::path::PathBuf::from("unused"));
        let context = egui::Context::default();
        let mut draw = |context: &egui::Context| {
            egui::CentralPanel::default().show(context, |ui| desktop.home(ui));
        };
        let _ = super::super::tests::render_frame(&context, Vec::new(), &mut draw);
        let output = super::super::tests::render_frame(&context, Vec::new(), &mut draw);
        let label = format!("{}  Quickstart", icon::QUICKSTART);
        assert!(super::super::tests::text_position(&output, &label).is_some());
        assert!(super::super::tests::text_position(&output, "Your Iroha playground").is_some());
        super::super::tests::click_label(&context, &label, draw);
        assert!(!desktop.busy, "no workspace: Quickstart is disabled");
    }
}
