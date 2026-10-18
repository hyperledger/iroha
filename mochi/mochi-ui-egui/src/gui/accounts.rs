//! Accounts: balances for every registered account and one-click ledger quick actions.
//!
//! Quick actions only build drafts. Each still becomes an exact signed preview that the
//! developer submits explicitly, exactly like the transaction composer.

use super::{
    Desktop,
    widgets::{self, icon},
};
use eframe::egui::{self, RichText, Ui};
use mochi_core::{GeneratedAccount, InstructionDraft, StateEntry, StatePage, asset_literal};
use std::collections::BTreeMap;

/// Accounts and holdings observed from one validator of the selected generation.
#[derive(Clone, Debug)]
pub(crate) struct LedgerSnapshot {
    pub(crate) accounts: StatePage,
    pub(crate) holdings: StatePage,
    /// Human-readable asset names keyed by definition literal; presentation only.
    names: BTreeMap<String, String>,
}

/// The `name` an asset definition record carries for display, if any.
fn definition_name(entry: &StateEntry) -> Option<String> {
    let value: norito::json::Value = norito::json::from_str(entry.json.as_deref()?).ok()?;
    let name = value.get("name")?.as_str()?.trim();
    (!name.is_empty()).then(|| name.chars().take(32).collect())
}

/// One balance of one account.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Holding<'a> {
    /// Exact asset literal, including any dataspace scope.
    pub(crate) asset: &'a str,
    pub(crate) definition: &'a str,
    pub(crate) value: &'a str,
}

fn holding(entry: &StateEntry) -> Option<Holding<'_>> {
    Some(Holding {
        asset: &entry.title,
        definition: entry.asset_definition.as_deref()?,
        value: entry.detail.strip_prefix("Value ").unwrap_or(&entry.detail),
    })
}

impl LedgerSnapshot {
    pub(crate) fn new(accounts: StatePage, holdings: StatePage, definitions: &StatePage) -> Self {
        let names = definitions
            .entries
            .iter()
            .filter_map(|entry| Some((entry.title.clone(), definition_name(entry)?)))
            .collect();
        Self {
            accounts,
            holdings,
            names,
        }
    }

    /// Display label for an asset definition: its name, else a shortened literal.
    pub(crate) fn asset_label(&self, definition: &str) -> String {
        self.names
            .get(definition)
            .cloned()
            .unwrap_or_else(|| widgets::short_middle(definition, 4))
    }

    /// Balances owned by `account`, in query order.
    pub(crate) fn holdings_of(&self, account: &str) -> Vec<Holding<'_>> {
        self.holdings
            .entries
            .iter()
            .filter(|entry| entry.owner.as_deref() == Some(account))
            .filter_map(holding)
            .collect()
    }

    /// Account literals in query order.
    pub(crate) fn account_ids(&self) -> impl Iterator<Item = &str> {
        self.accounts
            .entries
            .iter()
            .map(|entry| entry.title.as_str())
    }
}

/// The ledger change a quick action prepares.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum QuickKind {
    #[default]
    Mint,
    Transfer,
    Burn,
    NewAccount,
}

/// Form state for the quick actions; it never submits anything by itself.
#[derive(Clone, Debug)]
pub(crate) struct QuickActions {
    pub(crate) kind: QuickKind,
    /// Exact source holding (mint, burn, transfer) or the funding holding for new accounts.
    pub(crate) asset: String,
    /// Recipient of a transfer, or an optional other holder for a mint.
    pub(crate) recipient: String,
    pub(crate) quantity: String,
    /// Optional funding for a new account, taken from `asset`.
    pub(crate) fund: String,
    pub(crate) generated: Option<GeneratedAccount>,
    pub(crate) reveal_key: bool,
}

impl Default for QuickActions {
    fn default() -> Self {
        Self {
            kind: QuickKind::Mint,
            asset: String::new(),
            recipient: String::new(),
            quantity: "100".into(),
            fund: "100".into(),
            generated: None,
            reveal_key: false,
        }
    }
}

/// Width reserved beside a text field for its pick-from-list menu button.
const MENU_BUTTON_ROOM: f32 = 56.0;

/// The definition part of an asset literal (`<definition>#<account>[#dataspace:<id>]`).
fn definition_of(asset: &str) -> &str {
    asset.split('#').next().unwrap_or_default().trim()
}

impl QuickActions {
    /// Exact drafts for the selected action. Parsing belongs to the canonical composer.
    pub(crate) fn drafts(&self, discriminant: u16) -> Result<Vec<InstructionDraft>, String> {
        let asset = self.asset.trim();
        let recipient = self.recipient.trim();
        let quantity = self.quantity.trim();
        let draft = |result: Result<InstructionDraft, mochi_core::ComposeError>| {
            result.map_err(|error| error.to_string())
        };
        match self.kind {
            QuickKind::Mint if recipient.is_empty() => Ok(vec![draft(
                InstructionDraft::mint_from_input(asset, quantity),
            )?]),
            QuickKind::Mint => {
                let target = asset_literal(definition_of(asset), recipient, discriminant)
                    .map_err(|error| error.to_string())?;
                Ok(vec![draft(InstructionDraft::mint_from_input(
                    &target, quantity,
                ))?])
            }
            QuickKind::Burn => Ok(vec![draft(InstructionDraft::burn_from_input(
                asset, quantity,
            ))?]),
            QuickKind::Transfer => Ok(vec![draft(InstructionDraft::transfer_from_input(
                asset, quantity, recipient,
            ))?]),
            QuickKind::NewAccount => {
                let generated = self
                    .generated
                    .as_ref()
                    .ok_or("Generate a key pair for the new account first.")?;
                let mut drafts = vec![generated.register_draft()];
                let fund = self.fund.trim();
                if !asset.is_empty() && !fund.is_empty() {
                    drafts.push(draft(InstructionDraft::transfer_from_input(
                        asset,
                        fund,
                        &generated.account_literal(discriminant),
                    ))?);
                }
                Ok(drafts)
            }
        }
    }
}

impl Desktop {
    pub(super) fn accounts(&mut self, ui: &mut Ui) {
        let _address_profile = self.selected.as_ref().map(|selected| {
            iroha_data_model::account::address::ChainDiscriminantGuard::enter(
                selected.network.address_discriminant(),
            )
        });
        let palette = widgets::palette(ui);
        let mut refresh = false;
        widgets::page_header(
            ui,
            "Accounts",
            "Every registered account and its balances. Mint, send or create accounts in a couple of clicks.",
            |ui| {
                refresh = ui
                    .add_enabled(
                        !self.busy && self.ready(),
                        egui::Button::new(format!("{}  Refresh accounts", icon::REFRESH)),
                    )
                    .clicked();
            },
        );
        if refresh {
            self.refresh_ledger();
        }
        let Some(selected) = &self.selected else {
            widgets::card(ui, |ui| {
                widgets::empty_state(
                    ui,
                    icon::ACCOUNTS,
                    "No environment selected",
                    "Quickstart a localnet: it comes with a funded developer account.",
                );
            });
            return;
        };
        let developer = selected.network.prepared().context.account_id.clone();
        if let Some(error) = &self.ledger_error {
            widgets::banner(
                ui,
                widgets::Tone::Warning,
                &format!("Account observation failed: {error}"),
                false,
            );
            ui.add_space(8.0);
        }
        let wide = ui.available_width() > 980.0;
        // Borrow the snapshot out of the desktop for this frame instead of cloning it.
        let ledger = self.ledger.take();
        let mut columns = |ui: &mut Ui, index: usize| match index {
            0 => self.developer_card(ui, &developer, ledger.as_ref()),
            _ => self.quick_action_card(ui, &developer, ledger.as_ref()),
        };
        if wide {
            ui.columns(2, |uis| {
                columns(&mut uis[0], 0);
                columns(&mut uis[1], 1);
            });
        } else {
            columns(ui, 0);
            ui.add_space(12.0);
            columns(ui, 1);
        }
        ui.add_space(12.0);
        self.transaction_preview(ui);
        ui.add_space(12.0);
        widgets::card(ui, |ui| {
            ui.horizontal(|ui| {
                widgets::card_title(ui, icon::ACCOUNTS, "All accounts");
                if let Some(ledger) = &ledger {
                    widgets::pill(
                        ui,
                        ledger.accounts.entries.len().to_string(),
                        palette.muted,
                        palette.inset,
                    );
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.accounts_filter)
                            .hint_text("Filter accounts")
                            .desired_width(220.0),
                    );
                });
            });
            ui.add_space(6.0);
            let Some(ledger) = &ledger else {
                widgets::empty_state(
                    ui,
                    icon::ACCOUNTS,
                    "Nothing loaded yet",
                    "Accounts load automatically once validators are ready.",
                );
                return;
            };
            let filter = self.accounts_filter.trim().to_lowercase();
            let mut action = None;
            for (index, account) in ledger
                .account_ids()
                .filter(|account| filter.is_empty() || account.to_lowercase().contains(&filter))
                .enumerate()
            {
                ui.separator();
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(format!("{:>2}", index + 1))
                            .monospace()
                            .color(palette.faint),
                    );
                    widgets::short_mono(ui, account, 10);
                    widgets::copy_button(ui, account, "account ID");
                    if account == developer {
                        widgets::pill(ui, "you · signer", palette.sakura, palette.sakura_soft);
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.small_button(format!("{} Send", icon::SEND)).clicked() {
                            action = Some((QuickKind::Transfer, account.to_owned()));
                        }
                        if ui.small_button(format!("{} Mint", icon::MINT)).clicked() {
                            action = Some((QuickKind::Mint, account.to_owned()));
                        }
                    });
                });
                let holdings = ledger.holdings_of(account);
                ui.horizontal_wrapped(|ui| {
                    ui.add_space(28.0);
                    if holdings.is_empty() {
                        ui.label(RichText::new("No balances").small().color(palette.faint));
                    }
                    for holding in holdings {
                        widgets::pill(
                            ui,
                            format!(
                                "{} {}  {}",
                                icon::COINS,
                                holding.value,
                                ledger.asset_label(holding.definition)
                            ),
                            palette.text,
                            palette.inset,
                        )
                        .on_hover_text(holding.asset);
                    }
                });
            }
            if let Some((kind, account)) = action {
                self.quick.kind = kind;
                self.quick.recipient = account;
                if self.quick.asset.is_empty()
                    && let Some(holding) = ledger.holdings_of(&developer).first()
                {
                    self.quick.asset = holding.asset.to_owned();
                }
            }
            if ledger.accounts.remaining > 0 {
                widgets::hint(
                    ui,
                    &format!(
                        "{} more accounts are not shown. Use State to page through them.",
                        ledger.accounts.remaining
                    ),
                );
            }
        });
        if self.ledger.is_none() {
            self.ledger = ledger;
        }
    }

    fn developer_card(&mut self, ui: &mut Ui, developer: &str, ledger: Option<&LedgerSnapshot>) {
        let palette = widgets::palette(ui);
        widgets::accent_card(ui, Some(palette.sakura), |ui| {
            ui.horizontal(|ui| {
                widgets::card_title(ui, icon::KEY, "Developer account");
                widgets::pill(
                    ui,
                    "signs your transactions",
                    palette.sakura,
                    palette.sakura_soft,
                );
            });
            ui.add_space(4.0);
            ui.horizontal_wrapped(|ui| {
                ui.add(
                    egui::Label::new(RichText::new(developer).monospace().color(palette.text))
                        .wrap(),
                );
                widgets::copy_button(ui, developer, "developer account");
            });
            ui.add_space(6.0);
            ui.label(widgets::eyebrow(palette, "Balances"));
            match ledger {
                None => {
                    widgets::hint(ui, "Balances appear once the validators are ready.");
                }
                Some(ledger) => {
                    let holdings = ledger.holdings_of(developer);
                    if holdings.is_empty() {
                        widgets::hint(ui, "No balances yet.");
                    }
                    for holding in holdings {
                        ui.horizontal(|ui| {
                            ui.label(
                                RichText::new(holding.value)
                                    .size(20.0)
                                    .strong()
                                    .color(palette.text),
                            );
                            ui.label(
                                RichText::new(ledger.asset_label(holding.definition))
                                    .strong()
                                    .color(palette.sakura),
                            )
                            .on_hover_text(holding.asset);
                            widgets::copy_button(ui, holding.asset, "asset ID");
                        });
                    }
                }
            }
        });
    }

    fn quick_action_card(&mut self, ui: &mut Ui, developer: &str, ledger: Option<&LedgerSnapshot>) {
        let palette = widgets::palette(ui);
        let discriminant = self
            .selected
            .as_ref()
            .map(|selected| selected.network.address_discriminant());
        widgets::card(ui, |ui| {
            widgets::card_title(ui, icon::MINT, "Quick actions");
            ui.add_space(4.0);
            let tabs = [
                (QuickKind::Mint, format!("{} Mint", icon::MINT)),
                (QuickKind::Transfer, format!("{} Send", icon::SEND)),
                (QuickKind::Burn, format!("{} Burn", icon::BURN)),
                (QuickKind::NewAccount, format!("{} New account", icon::NEW)),
            ];
            let tabs = tabs
                .iter()
                .map(|(kind, label)| (*kind, label.as_str()))
                .collect::<Vec<_>>();
            if widgets::segmented(ui, &mut self.quick.kind, &tabs) {
                self.preview = None;
            }
            ui.add_space(6.0);
            let own = ledger
                .map(|ledger| ledger.holdings_of(developer))
                .unwrap_or_default();
            if self.quick.asset.is_empty()
                && let Some(first) = own.first()
            {
                self.quick.asset = first.asset.to_owned();
            }
            let asset_label = if self.quick.kind == QuickKind::NewAccount {
                "Fund from"
            } else {
                "Asset"
            };
            ui.label(widgets::eyebrow(palette, asset_label));
            ui.horizontal(|ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut self.quick.asset)
                        .hint_text("Asset ID (definition#account)")
                        .desired_width(ui.available_width() - MENU_BUTTON_ROOM),
                );
                let choices = ledger
                    .map(|ledger| {
                        ledger
                            .holdings
                            .entries
                            .iter()
                            .filter_map(holding)
                            .map(|holding| (holding.asset.to_owned(), holding.value.to_owned()))
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                ui.add_enabled_ui(!choices.is_empty(), |ui| {
                    ui.menu_button(icon::MENU, |ui| {
                        for (asset, value) in &choices {
                            if ui
                                .button(format!("{value} · {}", widgets::short_middle(asset, 10)))
                                .on_hover_text(asset)
                                .clicked()
                            {
                                self.quick.asset.clone_from(asset);
                                ui.close();
                            }
                        }
                    })
                    .response
                    .on_hover_text("Pick a known balance");
                });
            });
            match self.quick.kind {
                QuickKind::Mint | QuickKind::Transfer => {
                    let label = if self.quick.kind == QuickKind::Mint {
                        "Mint to (optional; defaults to the asset's holder)"
                    } else {
                        "Send to"
                    };
                    ui.label(widgets::eyebrow(palette, label));
                    self.account_picker(ui, ledger);
                    ui.label(widgets::eyebrow(palette, "Amount"));
                    ui.add(
                        egui::TextEdit::singleline(&mut self.quick.quantity).desired_width(160.0),
                    );
                }
                QuickKind::Burn => {
                    ui.label(widgets::eyebrow(palette, "Amount"));
                    ui.add(
                        egui::TextEdit::singleline(&mut self.quick.quantity).desired_width(160.0),
                    );
                }
                QuickKind::NewAccount => {
                    ui.label(widgets::eyebrow(palette, "Initial funding (optional)"));
                    ui.add(egui::TextEdit::singleline(&mut self.quick.fund).desired_width(160.0));
                    ui.add_space(4.0);
                    if ui
                        .button(format!("{}  Generate key pair", icon::KEY))
                        .on_hover_text("Creates a new Ed25519 key in memory only")
                        .clicked()
                    {
                        self.quick.generated = Some(GeneratedAccount::generate());
                        self.quick.reveal_key = false;
                        self.preview = None;
                    }
                    if let (Some(generated), Some(discriminant)) =
                        (&self.quick.generated, discriminant)
                    {
                        generated_key_card(ui, generated, discriminant, &mut self.quick.reveal_key);
                    }
                }
            }
            ui.add_space(8.0);
            let label = match self.quick.kind {
                QuickKind::Mint => "Review mint",
                QuickKind::Transfer => "Review transfer",
                QuickKind::Burn => "Review burn",
                QuickKind::NewAccount => "Review new account",
            };
            if ui
                .add_enabled(
                    !self.busy && self.ready(),
                    widgets::primary_button(palette, label),
                )
                .clicked()
            {
                self.review_quick_action();
            }
            widgets::hint(
                ui,
                "You will see the exact signed transaction before anything is submitted.",
            );
        });
    }

    fn account_picker(&mut self, ui: &mut Ui, ledger: Option<&LedgerSnapshot>) {
        ui.horizontal(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut self.quick.recipient)
                    .hint_text("Account ID")
                    .desired_width(ui.available_width() - MENU_BUTTON_ROOM),
            );
            let accounts = ledger
                .map(|ledger| ledger.account_ids().map(str::to_owned).collect::<Vec<_>>())
                .unwrap_or_default();
            ui.add_enabled_ui(!accounts.is_empty(), |ui| {
                ui.menu_button(icon::MENU, |ui| {
                    for account in &accounts {
                        if ui
                            .button(widgets::short_middle(account, 12))
                            .on_hover_text(account)
                            .clicked()
                        {
                            self.quick.recipient.clone_from(account);
                            ui.close();
                        }
                    }
                })
                .response
                .on_hover_text("Pick a registered account");
            });
        });
    }

    /// Turn the quick action into the shared reviewed preview.
    pub(super) fn review_quick_action(&mut self) {
        let Some(selected) = &self.selected else {
            return;
        };
        let discriminant = selected.network.address_discriminant();
        let _address_profile =
            iroha_data_model::account::address::ChainDiscriminantGuard::enter(discriminant);
        let reviewed = self.quick.drafts(discriminant).and_then(|drafts| {
            let json = mochi_core::drafts_to_pretty_json(&drafts).map_err(|e| e.to_string())?;
            let preview = selected
                .network
                .preview(&drafts)
                .map_err(|error| error.to_string())?;
            Ok((json, preview))
        });
        match reviewed {
            Ok((json, preview)) => {
                self.drafts = json;
                self.preview = Some(preview);
                self.submitted_hash = None;
            }
            Err(error) => self.error = Some(error),
        }
    }
}

fn generated_key_card(
    ui: &mut Ui,
    generated: &GeneratedAccount,
    discriminant: u16,
    reveal: &mut bool,
) {
    let palette = widgets::palette(ui);
    egui::Frame::new()
        .fill(palette.kinako_soft)
        .corner_radius(egui::CornerRadius::same(10))
        .inner_margin(egui::Margin::same(10))
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            let account = generated.account_literal(discriminant);
            widgets::copy_field(ui, "New account", &account);
            widgets::copy_field(ui, "Public key", &generated.public_key());
            ui.horizontal_wrapped(|ui| {
                ui.label(widgets::eyebrow(palette, "Private key"));
                let private = generated.exposed_private_key();
                if *reveal {
                    ui.add(egui::Label::new(RichText::new(&private).monospace()).wrap());
                } else {
                    ui.label(RichText::new("•".repeat(24)).monospace().color(palette.muted));
                }
                if ui.small_button(if *reveal { "Hide" } else { "Reveal" }).clicked() {
                    *reveal = !*reveal;
                }
                widgets::copy_button(ui, &private, "private key");
            });
            ui.label(
                RichText::new(format!(
                    "{} Localnet test key. Mochi keeps it in memory only and forgets it when you switch environments.",
                    icon::WARNING
                ))
                .small()
                .color(palette.kinako),
            );
        });
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_data_model::account::address::ChainDiscriminantGuard;

    const DISCRIMINANT: u16 = 0x02F1;

    fn entry(
        title: &str,
        owner: Option<&str>,
        definition: Option<&str>,
        detail: &str,
    ) -> StateEntry {
        StateEntry {
            title: title.into(),
            subtitle: String::new(),
            detail: detail.into(),
            raw: String::new(),
            domain: None,
            domain_lower: None,
            owner: owner.map(Into::into),
            owner_lower: owner.map(str::to_lowercase),
            asset_definition: definition.map(Into::into),
            asset_definition_lower: definition.map(str::to_lowercase),
            json: None,
            norito_bytes: None,
            search_blob: String::new(),
        }
    }

    fn page(kind: mochi_core::StateQueryKind, entries: Vec<StateEntry>) -> StatePage {
        StatePage {
            kind,
            entries,
            remaining: 0,
            cursor: None,
        }
    }

    fn definition(title: &str, json: &str) -> StateEntry {
        StateEntry {
            json: Some(json.into()),
            ..entry(title, None, Some(title), "")
        }
    }

    #[test]
    fn holdings_group_by_exact_owner_and_keep_scoped_literals() {
        let ledger = LedgerSnapshot::new(
            page(
                mochi_core::StateQueryKind::Accounts,
                vec![
                    entry("alice", Some("signatory-a"), None, ""),
                    entry("bob", None, None, ""),
                ],
            ),
            page(
                mochi_core::StateQueryKind::Assets,
                vec![
                    entry("rose#alice", Some("alice"), Some("rose"), "Value 10"),
                    entry(
                        "tea#alice#dataspace:3",
                        Some("alice"),
                        Some("tea"),
                        "Value 2.5",
                    ),
                    entry("rose#bob", Some("bob"), Some("rose"), "Value 1"),
                    entry("orphan", Some("carol"), None, "Value 4"),
                ],
            ),
            &page(
                mochi_core::StateQueryKind::AssetDefinitions,
                vec![
                    definition("rose", r#"{"id": "rose", "name": "Rose"}"#),
                    definition("tea", r#"{"id": "tea", "name": "  "}"#),
                    definition("6pEP9RjNoZ7beWkT3pLfKoM1dyfi", "not json"),
                ],
            ),
        );
        assert_eq!(ledger.asset_label("rose"), "Rose");
        assert_eq!(ledger.asset_label("tea"), "tea", "blank names fall back");
        assert_eq!(
            ledger.asset_label("6pEP9RjNoZ7beWkT3pLfKoM1dyfi"),
            "6pEP…dyfi"
        );
        assert_eq!(ledger.account_ids().collect::<Vec<_>>(), ["alice", "bob"]);
        assert_eq!(
            ledger.holdings_of("alice"),
            [
                Holding {
                    asset: "rose#alice",
                    definition: "rose",
                    value: "10"
                },
                Holding {
                    asset: "tea#alice#dataspace:3",
                    definition: "tea",
                    value: "2.5"
                },
            ]
        );
        assert_eq!(ledger.holdings_of("ALICE"), []);
    }

    #[test]
    fn definition_literals_split_before_the_holder() {
        assert_eq!(definition_of(" 6pEP#alice#dataspace:3"), "6pEP");
        assert_eq!(definition_of("solo"), "solo");
    }

    #[test]
    fn quick_actions_compose_exact_drafts_or_explain_what_is_missing() {
        let holder = GeneratedAccount::generate();
        let recipient = GeneratedAccount::generate();
        // Canonical Base58 asset definition used by the shared composer fixtures.
        let definition = "6pEP9RjNoZ7beWkT3pLfKoM1dyfi";
        let asset = asset_literal(
            definition,
            &holder.account_literal(DISCRIMINANT),
            DISCRIMINANT,
        )
        .unwrap();
        let _guard = ChainDiscriminantGuard::enter(DISCRIMINANT);
        let mut quick = QuickActions {
            asset: asset.clone(),
            quantity: "5".into(),
            ..QuickActions::default()
        };
        let drafts = quick.drafts(DISCRIMINANT).unwrap();
        assert!(
            matches!(&drafts[..], [InstructionDraft::MintAsset { asset: minted, .. }] if minted.to_string() == asset)
        );

        quick.recipient = recipient.account_literal(DISCRIMINANT);
        let drafts = quick.drafts(DISCRIMINANT).unwrap();
        assert!(matches!(
            &drafts[..],
            [InstructionDraft::MintAsset { asset: minted, .. }] if minted.account() == recipient.account_id()
        ));

        quick.kind = QuickKind::Transfer;
        assert!(matches!(
            &quick.drafts(DISCRIMINANT).unwrap()[..],
            [InstructionDraft::TransferAsset { destination, .. }] if destination == recipient.account_id()
        ));
        quick.kind = QuickKind::Burn;
        assert!(matches!(
            &quick.drafts(DISCRIMINANT).unwrap()[..],
            [InstructionDraft::BurnAsset { .. }]
        ));
        quick.quantity = "not a number".into();
        assert!(quick.drafts(DISCRIMINANT).is_err());

        quick.kind = QuickKind::NewAccount;
        assert!(
            quick
                .drafts(DISCRIMINANT)
                .unwrap_err()
                .contains("Generate a key pair")
        );
        quick.generated = Some(recipient.clone());
        let drafts = quick.drafts(DISCRIMINANT).unwrap();
        assert!(matches!(
            &drafts[..],
            [
                InstructionDraft::RegisterAccount { account },
                InstructionDraft::TransferAsset { destination, .. },
            ] if account == recipient.account_id() && destination == recipient.account_id()
        ));
        quick.fund.clear();
        assert_eq!(quick.drafts(DISCRIMINANT).unwrap().len(), 1);
    }
}
