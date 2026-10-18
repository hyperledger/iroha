//! Ledger explorers: live blocks, the activity feed, validator logs and paged state queries.

use super::{
    Desktop, Message,
    widgets::{self, icon},
};
use eframe::egui::{self, RichText, Ui};
use mochi_core::{BlockSummary, StateQueryKind};
use std::{
    collections::VecDeque,
    time::{SystemTime, UNIX_EPOCH},
};

/// One block summary from the canonical block stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BlockRow {
    pub(crate) height: u64,
    pub(crate) hash: String,
    pub(crate) transactions: usize,
    pub(crate) rejected: usize,
    pub(crate) signatures: usize,
    pub(crate) created_ms: u64,
    pub(crate) genesis: bool,
    pub(crate) bytes: usize,
}

/// Blocks kept for the explorer; older rows remain available from canonical history.
pub(crate) const BLOCK_FEED_LIMIT: usize = 200;

/// Record a streamed block newest-first, ignoring reconnect replays of a shown block.
/// Returns the recorded height.
pub(crate) fn record_block(
    feed: &mut VecDeque<BlockRow>,
    summary: &BlockSummary,
    raw_len: usize,
) -> Option<u64> {
    if feed
        .iter()
        .any(|row| row.height == summary.height && row.hash == summary.hash_hex)
    {
        return None;
    }
    let row = BlockRow {
        height: summary.height,
        hash: summary.hash_hex.chars().take(128).collect(),
        transactions: summary.transaction_count,
        rejected: summary.rejected_transaction_count,
        signatures: summary.signature_count,
        created_ms: summary.creation_time_ms,
        genesis: summary.is_genesis,
        bytes: raw_len,
    };
    let position = feed
        .iter()
        .position(|existing| existing.height < row.height)
        .unwrap_or(feed.len());
    feed.insert(position, row);
    feed.truncate(BLOCK_FEED_LIMIT);
    Some(summary.height)
}

/// Kinds used to color and filter the activity feed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ActivityKind {
    All,
    Block,
    Pipeline,
    Data,
    Trigger,
    Note,
}

/// Classify one bounded activity line by the stable prefix its summarizer wrote.
pub(crate) fn activity_kind(entry: &str) -> ActivityKind {
    if entry.starts_with("Block #") {
        ActivityKind::Block
    } else if entry.starts_with("Pipeline") {
        ActivityKind::Pipeline
    } else if entry.starts_with("Data ·") {
        ActivityKind::Data
    } else if entry.starts_with("Time ·")
        || entry.starts_with("Execute Trigger")
        || entry.starts_with("Trigger Completed")
    {
        ActivityKind::Trigger
    } else {
        ActivityKind::Note
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

impl Desktop {
    pub(super) fn blocks(&mut self, ui: &mut Ui) {
        let palette = widgets::palette(ui);
        let live = self.blocks.is_some();
        widgets::page_header(
            ui,
            "Blocks",
            "Committed blocks from the observed validator, newest first.",
            |ui| {
                if live {
                    widgets::pill(ui, "LIVE", palette.matcha, palette.matcha_soft)
                        .on_hover_text("Streaming from the observed validator");
                    widgets::dot(ui, palette.matcha, 4.0);
                }
            },
        );
        widgets::card(ui, |ui| {
            if self.blocks_feed.is_empty() {
                widgets::empty_state(
                    ui,
                    icon::BLOCKS,
                    "No blocks yet",
                    if self.ready() {
                        "Idle Iroha chains create no blocks. Submit a transaction from Accounts or Transactions and it appears here."
                    } else {
                        "Start an environment to stream its blocks."
                    },
                );
                return;
            }
            let now = now_ms();
            egui::ScrollArea::horizontal().show(ui, |ui| {
                egui::Grid::new("blocks")
                    .num_columns(7)
                    .spacing([22.0, 10.0])
                    .striped(true)
                    .show(ui, |ui| {
                        for title in [
                            "Height",
                            "Age",
                            "Txs",
                            "Rejected",
                            "Signatures",
                            "Size",
                            "Hash",
                        ] {
                            ui.label(widgets::eyebrow(palette, title));
                        }
                        ui.end_row();
                        for row in &self.blocks_feed {
                            ui.horizontal(|ui| {
                                ui.label(
                                    RichText::new(format!("#{}", row.height))
                                        .strong()
                                        .size(15.0)
                                        .color(palette.sky),
                                );
                                if row.genesis {
                                    widgets::pill(ui, "genesis", palette.fuji, palette.fuji_soft);
                                }
                            });
                            ui.label(
                                RichText::new(widgets::time_ago(row.created_ms, now))
                                    .color(palette.muted),
                            );
                            ui.label(row.transactions.to_string());
                            ui.label(RichText::new(row.rejected.to_string()).color(
                                if row.rejected > 0 {
                                    palette.aka
                                } else {
                                    palette.muted
                                },
                            ));
                            ui.label(row.signatures.to_string());
                            ui.label(
                                RichText::new(format!("{} B", row.bytes)).color(palette.muted),
                            );
                            ui.horizontal(|ui| {
                                widgets::short_mono(ui, &row.hash, 8);
                                widgets::copy_button(ui, &row.hash, "block hash");
                            });
                            ui.end_row();
                        }
                    });
            });
        });
    }

    pub(super) fn activity(&mut self, ui: &mut Ui) {
        let palette = widgets::palette(ui);
        widgets::page_title(
            ui,
            "Activity",
            "Canonical block and event streams from the observed validator, plus deployment progress.",
        );
        ui.horizontal_wrapped(|ui| {
            widgets::segmented(
                ui,
                &mut self.activity_kind,
                &[
                    (ActivityKind::All, "All"),
                    (ActivityKind::Block, "Blocks"),
                    (ActivityKind::Pipeline, "Pipeline"),
                    (ActivityKind::Data, "Data"),
                    (ActivityKind::Trigger, "Triggers"),
                    (ActivityKind::Note, "Notes"),
                ],
            );
            ui.add(
                egui::TextEdit::singleline(&mut self.activity_filter)
                    .hint_text("Filter activity")
                    .desired_width(220.0),
            );
        });
        ui.add_space(6.0);
        widgets::card(ui, |ui| {
            let filter = self.activity_filter.to_lowercase();
            let mut shown = 0;
            for entry in self.activity.iter().rev() {
                let kind = activity_kind(entry);
                if (self.activity_kind != ActivityKind::All && kind != self.activity_kind)
                    || (!filter.is_empty() && !entry.to_lowercase().contains(&filter))
                {
                    continue;
                }
                let (label, fg, bg) = match kind {
                    ActivityKind::Block => ("block", palette.sky, palette.sky_soft),
                    ActivityKind::Pipeline => ("pipeline", palette.fuji, palette.fuji_soft),
                    ActivityKind::Data => ("data", palette.matcha, palette.matcha_soft),
                    ActivityKind::Trigger => ("trigger", palette.kinako, palette.kinako_soft),
                    ActivityKind::Note | ActivityKind::All => {
                        ("note", palette.muted, palette.inset)
                    }
                };
                ui.horizontal_top(|ui| {
                    ui.add_sized([72.0, 20.0], |ui: &mut Ui| widgets::pill(ui, label, fg, bg));
                    ui.add(
                        egui::Label::new(RichText::new(entry).monospace().color(palette.text))
                            .wrap(),
                    );
                });
                shown += 1;
                if shown >= 150 {
                    break;
                }
            }
            if shown == 0 {
                widgets::empty_state(
                    ui,
                    icon::ACTIVITY,
                    "Nothing here yet",
                    "Blocks, events and deployment progress stream in while an environment runs.",
                );
            }
        });
    }

    pub(super) fn logs(&mut self, ui: &mut Ui) {
        let palette = widgets::palette(ui);
        widgets::page_title(
            ui,
            "Logs",
            "The newest 64 KiB of a validator or supervisor log, read from the shared workspace.",
        );
        let peers = self
            .selected
            .as_ref()
            .map_or(0, |selected| selected.network.prepared().peers.len());
        ui.horizontal_wrapped(|ui| {
            let mut options = vec![(None, "Supervisor".to_owned())];
            options
                .extend((0..peers).map(|index| (Some(index), format!("Validator {}", index + 1))));
            let labels = options
                .iter()
                .map(|(source, label)| (*source, label.as_str()))
                .collect::<Vec<_>>();
            if widgets::segmented(ui, &mut self.logs_source, &labels) {
                self.logs.clear();
            }
            if ui
                .add_enabled(
                    !self.busy && self.selected.is_some(),
                    widgets::primary_button(palette, "Read latest logs"),
                )
                .clicked()
            {
                self.read_logs();
            }
            if !self.logs.is_empty() {
                widgets::copy_button(ui, &self.logs, "logs");
            }
        });
        ui.add_space(6.0);
        egui::Frame::new()
            .fill(egui::Color32::from_rgb(24, 20, 31))
            .corner_radius(egui::CornerRadius::same(14))
            .inner_margin(egui::Margin::same(14))
            .show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                egui::ScrollArea::vertical()
                    .max_height(460.0)
                    .stick_to_bottom(true)
                    .show(ui, |ui| {
                        let text = if self.logs.is_empty() {
                            "Choose a log and press Read latest logs."
                        } else {
                            self.logs.as_str()
                        };
                        ui.add(
                            egui::Label::new(
                                RichText::new(text)
                                    .monospace()
                                    .color(egui::Color32::from_rgb(222, 214, 230)),
                            )
                            .wrap()
                            .selectable(true),
                        );
                    });
            });
    }

    /// Read the newest 64 KiB of the chosen log from the captured generation.
    pub(super) fn read_logs(&mut self) {
        let (Some(workspace), Some(selected)) = (self.workspace.clone(), self.selected.as_ref())
        else {
            return;
        };
        let network = selected.network.clone();
        let source = self.logs_source;
        self.spawn(move || {
            Message::Logs(
                workspace
                    .logs(&network, source, 64 * 1024)
                    .map_err(|e| e.to_string()),
            )
        });
    }

    pub(super) fn state(&mut self, ui: &mut Ui) {
        let palette = widgets::palette(ui);
        widgets::page_title(
            ui,
            "State",
            "Query world state through the observed validator with the developer account's signed queries.",
        );
        ui.horizontal_wrapped(|ui| {
            let before = self.query;
            let options = StateQueryKind::all().map(|kind| (kind, kind.label()));
            widgets::segmented(ui, &mut self.query, &options);
            if self.query != before {
                self.page = None;
            }
            if ui
                .add_enabled(
                    !self.busy && self.ready(),
                    widgets::primary_button(palette, "Query"),
                )
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
            ui.add(
                egui::TextEdit::singleline(&mut self.filter)
                    .hint_text("Filter this page")
                    .desired_width(200.0),
            );
        });
        ui.add_space(6.0);
        let Some(page) = &self.page else {
            widgets::card(ui, |ui| {
                widgets::empty_state(
                    ui,
                    icon::STATE,
                    "Pick a collection and press Query",
                    "Results are paged 50 at a time; each entry includes copyable JSON and Norito bytes.",
                );
            });
            return;
        };
        if page.kind != self.query {
            return;
        }
        ui.label(
            RichText::new(format!(
                "{} records on this page · {} remaining",
                page.entries.len(),
                page.remaining
            ))
            .color(palette.muted),
        );
        let filter = self.filter.to_lowercase();
        for entry in page
            .entries
            .iter()
            .filter(|e| e.search_blob.contains(&filter))
        {
            widgets::card(ui, |ui| {
                egui::CollapsingHeader::new(RichText::new(&entry.title).monospace().strong())
                    .id_salt(&entry.title)
                    .show(ui, |ui| {
                        ui.label(&entry.detail);
                        ui.horizontal(|ui| {
                            if let Some(json) = &entry.json
                                && ui.button("Copy JSON").clicked()
                            {
                                widgets::copy_to_clipboard(ui.ctx(), json, "JSON");
                            }
                            if let Some(bytes) = &entry.norito_bytes
                                && ui.button("Copy Norito hex").clicked()
                            {
                                widgets::copy_to_clipboard(
                                    ui.ctx(),
                                    &hex::encode(bytes),
                                    "Norito hex",
                                );
                            }
                        });
                        egui::Frame::new()
                            .fill(palette.inset)
                            .corner_radius(egui::CornerRadius::same(10))
                            .inner_margin(egui::Margin::same(10))
                            .show(ui, |ui| {
                                ui.set_min_width(ui.available_width());
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(entry.json.as_deref().unwrap_or(&entry.raw))
                                            .monospace(),
                                    )
                                    .wrap(),
                                );
                            });
                    });
                ui.label(RichText::new(&entry.subtitle).small().color(palette.muted));
            });
            ui.add_space(6.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn summary(height: u64, hash: &str) -> BlockSummary {
        BlockSummary {
            height,
            hash_hex: hash.into(),
            transaction_count: 2,
            rejected_transaction_count: 1,
            time_trigger_count: 0,
            signature_count: 4,
            view_change_index: 0,
            creation_time_ms: 1_000,
            is_genesis: height == 1,
        }
    }

    #[test]
    fn block_feed_is_newest_first_bounded_and_ignores_replays() {
        let mut feed = VecDeque::new();
        assert_eq!(record_block(&mut feed, &summary(1, "aa"), 512), Some(1));
        assert_eq!(record_block(&mut feed, &summary(3, "cc"), 512), Some(3));
        assert_eq!(record_block(&mut feed, &summary(2, "bb"), 512), Some(2));
        assert_eq!(record_block(&mut feed, &summary(3, "cc"), 512), None);
        assert_eq!(
            feed.iter().map(|row| row.height).collect::<Vec<_>>(),
            [3, 2, 1]
        );
        assert!(feed.back().unwrap().genesis);
        for height in 10..(10 + BLOCK_FEED_LIMIT as u64 + 5) {
            record_block(&mut feed, &summary(height, &height.to_string()), 512);
        }
        assert_eq!(feed.len(), BLOCK_FEED_LIMIT);
        assert_eq!(
            feed.front().unwrap().height,
            10 + BLOCK_FEED_LIMIT as u64 + 4
        );
    }

    #[test]
    fn activity_lines_classify_by_their_summarizer_prefix() {
        assert_eq!(
            activity_kind("Block #4 · 1 transactions"),
            ActivityKind::Block
        );
        assert_eq!(
            activity_kind("Pipeline · Block · 10 bytes"),
            ActivityKind::Pipeline
        );
        assert_eq!(activity_kind("Data · Asset · 10 bytes"), ActivityKind::Data);
        assert_eq!(activity_kind("Time · tick"), ActivityKind::Trigger);
        assert_eq!(activity_kind("Execute Trigger · x"), ActivityKind::Trigger);
        assert_eq!(activity_kind("Block stream closed"), ActivityKind::Note);
        assert_eq!(activity_kind("Compiling"), ActivityKind::Note);
    }
}
