//! Build views: the transaction composer, the shared signed-transaction review, contract
//! deployment and package publication.

use super::{
    Desktop, Message, PublicationAction, PublicationForm, PublicationOutput,
    widgets::{self, icon},
};
use eframe::egui::{self, RichText, Ui};
use mochi_core::{InstructionDraft, drafts_from_json_str, drafts_to_pretty_json};

/// Instruction builder choices, in their segmented-control order.
const ACTIONS: [&str; 4] = ["Mint", "Burn", "Transfer", "Register account"];

/// File names and extensions Mochi accepts as contract deployment input.
pub(crate) fn is_contract_input(path: &std::path::Path) -> bool {
    path.is_dir()
        || path.file_name().is_some_and(|name| name == "Musubi.toml")
        || path
            .extension()
            .is_some_and(|extension| extension == "ko" || extension == "to")
}

impl Desktop {
    pub(super) fn composer(&mut self, ui: &mut Ui) {
        let _address_profile = self.selected.as_ref().map(|selected| {
            iroha_data_model::account::address::ChainDiscriminantGuard::enter(
                selected.network.address_discriminant(),
            )
        });
        let palette = widgets::palette(ui);
        widgets::page_title(
            ui,
            "Transactions",
            "Build instructions, review the exact signed transaction, then submit it once.",
        );
        widgets::card(ui, |ui| {
            widgets::card_title(ui, icon::COMPOSE, "Instruction builder");
            ui.add_space(4.0);
            let options = ACTIONS
                .iter()
                .enumerate()
                .map(|(index, label)| (index, *label))
                .collect::<Vec<_>>();
            widgets::segmented(ui, &mut self.action, &options);
            ui.add_space(4.0);
            ui.horizontal_wrapped(|ui| {
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
                            .desired_width(110.0),
                    );
                }
            });
            if self.action == 2 {
                ui.add(
                    egui::TextEdit::singleline(&mut self.destination)
                        .hint_text("Destination account ID")
                        .desired_width(540.0),
                );
            }
            if ui
                .button(format!("{}  Add instruction", icon::NEW))
                .clicked()
            {
                self.add_instruction();
            }
        });
        ui.add_space(12.0);
        widgets::card(ui, |ui| {
            ui.horizontal(|ui| {
                widgets::card_title(ui, icon::LOGS, "Draft");
                let count = drafts_from_json_str(&self.drafts).map_or(0, |drafts| drafts.len());
                widgets::pill(
                    ui,
                    format!("{count} instruction{}", if count == 1 { "" } else { "s" }),
                    palette.muted,
                    palette.inset,
                );
            });
            widgets::hint(
                ui,
                "Draft JSON also supports asset definitions, roles, multisig and chain policy instructions.",
            );
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
            ui.horizontal(|ui| {
                if ui
                    .add_enabled(
                        !self.busy && self.ready(),
                        widgets::primary_button(palette, "Review transaction"),
                    )
                    .clicked()
                {
                    self.review_drafts();
                }
                if ui.button("Clear draft").clicked() {
                    self.drafts = "[]".into();
                    self.preview = None;
                }
            });
        });
        ui.add_space(12.0);
        self.transaction_preview(ui);
    }

    fn add_instruction(&mut self) {
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

    fn review_drafts(&mut self) {
        let Some(selected) = &self.selected else {
            return;
        };
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

    /// The reviewed, signed transaction shared by Accounts and Transactions.
    pub(super) fn transaction_preview(&mut self, ui: &mut Ui) {
        let Some(preview) = &self.preview else {
            return;
        };
        let palette = widgets::palette(ui);
        let submitted = self.submitted_hash.as_deref() == Some(preview.hash());
        let (mut submit, mut discard) = (false, false);
        widgets::accent_card(ui, Some(palette.sakura), |ui| {
            ui.horizontal(|ui| {
                widgets::card_title(ui, icon::OK, "Review transaction");
                if submitted {
                    widgets::pill(ui, "submitted", palette.matcha, palette.matcha_soft);
                } else {
                    widgets::pill(
                        ui,
                        "signed · not submitted",
                        palette.kinako,
                        palette.kinako_soft,
                    );
                }
            });
            ui.add_space(4.0);
            widgets::copy_field(ui, "Authority", preview.authority());
            widgets::copy_field(ui, "Transaction", preview.hash());
            ui.label(widgets::eyebrow(palette, "Instructions"));
            // Draft summaries describe the same signed instructions one-to-one; anything else
            // falls back to the signed transaction's own descriptions.
            let lines = if preview.summaries().len() == preview.instructions().len() {
                preview.summaries()
            } else {
                preview.instructions()
            };
            for (index, instruction) in lines.iter().enumerate() {
                ui.horizontal_top(|ui| {
                    ui.label(RichText::new(format!("{}.", index + 1)).color(palette.faint));
                    ui.add(egui::Label::new(RichText::new(instruction).color(palette.text)).wrap());
                });
            }
            ui.add_space(4.0);
            ui.horizontal_wrapped(|ui| {
                if ui
                    .add_enabled(
                        !self.busy && !submitted,
                        widgets::primary_button(palette, "Submit reviewed transaction"),
                    )
                    .clicked()
                {
                    submit = true;
                }
                if ui.button("Copy signed Norito hex").clicked() {
                    widgets::copy_to_clipboard(
                        ui.ctx(),
                        preview.encoded_hex(),
                        "signed Norito hex",
                    );
                }
                if ui
                    .add_enabled(!self.busy, egui::Button::new("Discard"))
                    .clicked()
                {
                    discard = true;
                }
            });
        });
        if submit {
            self.submit_reviewed();
        } else if discard {
            self.preview = None;
        }
    }

    /// Submit the reviewed preview once; the original hash is kept for uncertain outcomes.
    pub(super) fn submit_reviewed(&mut self) {
        let (Some(selected), Some(handle), Some(preview)) = (
            &self.selected,
            self.runtime.as_ref().map(|r| r.handle().clone()),
            self.preview.clone(),
        ) else {
            return;
        };
        let network = selected.network.clone();
        let peer = self.peer;
        self.submitted_hash = Some(preview.hash().to_owned());
        self.spawn(move || {
            Message::Submitted(
                handle
                    .block_on(network.submit(peer, &preview))
                    .map(|commit| {
                        format!("Applied {} in block {}", preview.hash(), commit.block_height)
                    })
                    .map_err(|e| {
                        format!(
                            "Transaction {}: {e}. Keep this original hash when checking an uncertain outcome.",
                            preview.hash()
                        )
                    }),
            )
        });
    }

    pub(super) fn contracts(&mut self, ui: &mut Ui) {
        let palette = widgets::palette(ui);
        widgets::page_title(
            ui,
            "Contracts",
            "Deploy Kotodama sources (.ko), IVM bytecode (.to) or Musubi packages. Compilation, fee review and recovery use the same service as Kagami.",
        );
        let hovering = ui.ctx().input(|input| !input.raw.hovered_files.is_empty());
        widgets::accent_card(ui, hovering.then_some(palette.sakura), |ui| {
            ui.horizontal(|ui| {
                widgets::icon_badge(ui, icon::DROP, palette.sakura, palette.sakura_soft);
                ui.vertical(|ui| {
                    ui.label(
                        RichText::new("Deploy a smart contract")
                            .size(16.0)
                            .strong()
                            .color(palette.text),
                    );
                    widgets::hint(
                        ui,
                        "Drop a .ko, .to or Musubi.toml anywhere on this window, or type its path.",
                    );
                });
            });
            ui.add_space(4.0);
            ui.add(
                egui::TextEdit::singleline(&mut self.contract_path)
                    .hint_text("Contract path")
                    .desired_width(f32::INFINITY),
            );
            ui.add(
                egui::TextEdit::singleline(&mut self.contract_alias)
                    .hint_text("Alias (optional; generated in the selected dataspace)")
                    .desired_width(f32::INFINITY),
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
                    widgets::primary_button(palette, "Prepare deployment"),
                )
                .clicked()
            {
                self.deploy(false);
            }
            widgets::hint(
                ui,
                "Mochi shows the exact deployment and quoted fees before anything is dispatched.",
            );
        });
        ui.add_space(12.0);
        widgets::card(ui, |ui| {
            widgets::card_title(ui, icon::REFRESH, "Resume a deployment");
            widgets::hint(
                ui,
                "Resume an interrupted deployment using its retained journal.",
            );
            ui.add(
                egui::TextEdit::singleline(&mut self.journal_path)
                    .hint_text("Journal path")
                    .desired_width(f32::INFINITY),
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
        });
        if let Some(receipt) = &self.receipt {
            ui.add_space(12.0);
            widgets::accent_card(ui, Some(palette.matcha), |ui| {
                ui.horizontal(|ui| {
                    widgets::icon_badge(ui, icon::OK, palette.matcha, palette.matcha_soft);
                    ui.label(
                        RichText::new("Verified deployment receipt")
                            .size(16.0)
                            .strong()
                            .color(palette.text),
                    );
                    if ui.button("Copy receipt").clicked() {
                        widgets::copy_to_clipboard(ui.ctx(), receipt, "receipt");
                    }
                });
                ui.add(egui::Label::new(RichText::new(receipt).monospace()).wrap());
            });
        }
    }

    pub(super) fn packages(&mut self, ui: &mut Ui) {
        widgets::page_title(
            ui,
            "Packages",
            "Publish Musubi packages through the generated localnet's registry, shared with Kagami.",
        );
        if let Some(action) = self
            .publication
            .show(ui, !self.busy && self.workspace.is_some())
        {
            self.publish_package(action);
        }
        if let Some(output) = &self.publication_output {
            ui.add_space(12.0);
            output.show(ui);
        }
    }
}

impl PublicationForm {
    pub(super) fn show(&mut self, ui: &mut Ui, available: bool) -> Option<PublicationAction> {
        let palette = widgets::palette(ui);
        let mut action = None;
        widgets::card(ui, |ui| {
            widgets::card_title(ui, icon::PACKAGES, "Publish a package");
            widgets::hint(
                ui,
                "Publish to the selected generated localnet. Publish starts a default localnet when none is selected.",
            );
            widgets::hint(
                ui,
                "Publication can register the package namespace and pay transaction fees.",
            );
            ui.add(
                egui::TextEdit::singleline(&mut self.manifest)
                    .hint_text("Manifest or workspace path")
                    .desired_width(f32::INFINITY),
            );
            ui.add(
                egui::TextEdit::singleline(&mut self.package)
                    .hint_text("Package selector (optional)")
                    .desired_width(f32::INFINITY),
            );
            ui.checkbox(&mut self.detach, "Return after durable seed staging");
            if ui
                .add_enabled(
                    available,
                    widgets::primary_button(palette, "Publish package"),
                )
                .clicked()
            {
                action = Some(PublicationAction::Begin);
            }
        });
        ui.add_space(12.0);
        widgets::card(ui, |ui| {
            widgets::card_title(ui, icon::REFRESH, "Resume or recover");
            widgets::hint(
                ui,
                "Use the original operation ID from publication output. Resume uses its retained package; Recover package files requires the original workspace.",
            );
            ui.add(
                egui::TextEdit::singleline(&mut self.operation_id)
                    .hint_text("Publication operation ID")
                    .desired_width(f32::INFINITY),
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
        });
        action
    }
}

impl PublicationOutput {
    pub(super) fn show(&self, ui: &mut Ui) {
        let palette = widgets::palette(ui);
        let (fg, bg) = if self.exit_code == 0 {
            (palette.matcha, palette.matcha_soft)
        } else {
            (palette.aka, palette.aka_soft)
        };
        widgets::accent_card(ui, Some(fg), |ui| {
            ui.horizontal(|ui| {
                widgets::icon_badge(
                    ui,
                    if self.exit_code == 0 {
                        icon::OK
                    } else {
                        icon::WARNING
                    },
                    fg,
                    bg,
                );
                ui.label(
                    RichText::new(format!(
                        "Publication output · exit status {}",
                        self.exit_code
                    ))
                    .strong()
                    .color(palette.text),
                );
            });
            if !self.stdout.is_empty() {
                ui.label(widgets::eyebrow(palette, "Output"));
                if ui.button("Copy publication output").clicked() {
                    widgets::copy_to_clipboard(ui.ctx(), &self.stdout, "publication output");
                }
                ui.add(egui::Label::new(egui::RichText::new(&self.stdout).monospace()).wrap());
            }
            if !self.stderr.is_empty() {
                ui.label(widgets::eyebrow(palette, "Diagnostics"));
                if ui.button("Copy publication diagnostics").clicked() {
                    widgets::copy_to_clipboard(ui.ctx(), &self.stderr, "publication diagnostics");
                }
                ui.add(egui::Label::new(egui::RichText::new(&self.stderr).monospace()).wrap());
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dropped_contract_inputs_are_recognized_by_name_and_extension() {
        let temporary = tempfile::tempdir().unwrap();
        assert!(is_contract_input(temporary.path()));
        for accepted in ["coffee.ko", "coffee.to", "Musubi.toml"] {
            assert!(
                is_contract_input(&temporary.path().join(accepted)),
                "{accepted}"
            );
        }
        for refused in ["notes.txt", "Cargo.toml", "coffee.ko.bak", "ko"] {
            assert!(
                !is_contract_input(&temporary.path().join(refused)),
                "{refused}"
            );
        }
    }

    #[test]
    fn composer_appends_exact_drafts_and_reports_invalid_input() {
        let mut desktop = Desktop::model(std::path::PathBuf::from("unused"));
        desktop.action = 3;
        desktop.asset = "not an account".into();
        desktop.add_instruction();
        assert!(desktop.error.as_deref().unwrap().contains("not an account"));
        assert_eq!(desktop.drafts, "[]");
        desktop.error = None;
        desktop.action = 3;
        desktop.asset = iroha_test_samples::BOB_ID.to_string();
        desktop.add_instruction();
        assert!(desktop.error.is_none());
        assert_eq!(drafts_from_json_str(&desktop.drafts).unwrap().len(), 1);
        assert!(desktop.preview.is_none());
    }

    #[test]
    fn preview_card_is_hidden_without_a_reviewed_transaction() {
        let mut desktop = Desktop::model(std::path::PathBuf::from("unused"));
        let context = egui::Context::default();
        let output = context.run(egui::RawInput::default(), |context| {
            egui::CentralPanel::default().show(context, |ui| desktop.transaction_preview(ui));
        });
        assert!(super::super::tests::text_position(&output, "Review transaction").is_none());
        assert!(!desktop.busy);
    }
}
