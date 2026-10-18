//! Reusable Mochi components: cards, pills, copyable values, banners and navigation rows.
//!
//! Components only present data. Every action they report is handled by the desktop owner.

use super::theme::{self, CARD_RADIUS, CONTROL_RADIUS, Palette};
use eframe::egui::{
    self, Align, Align2, Color32, CornerRadius, FontId, Frame, Layout, Margin, Response, RichText,
    Sense, Stroke, Ui, Vec2, WidgetInfo, WidgetType,
};
use mochi_core::developer::ManagedPhase;

/// Glyphs used by navigation and actions; all must exist in egui's bundled fonts.
pub(crate) mod icon {
    pub(crate) const HOME: &str = "🏠";
    pub(crate) const ACCOUNTS: &str = "👤";
    pub(crate) const BLOCKS: &str = "⛓";
    pub(crate) const ACTIVITY: &str = "⚡";
    pub(crate) const STATE: &str = "🔍";
    pub(crate) const COMPOSE: &str = "✉";
    pub(crate) const CONTRACTS: &str = "📜";
    pub(crate) const PACKAGES: &str = "📦";
    pub(crate) const ENDPOINTS: &str = "🔌";
    pub(crate) const LOGS: &str = "📄";
    pub(crate) const START: &str = "▶";
    pub(crate) const STOP: &str = "⏹";
    pub(crate) const REFRESH: &str = "🔄";
    pub(crate) const RESET: &str = "🗑";
    pub(crate) const NEW: &str = "➕";
    pub(crate) const PRIVATE: &str = "🔒";
    pub(crate) const FOLDER: &str = "📁";
    pub(crate) const LIGHT: &str = "☀";
    pub(crate) const DARK: &str = "🌙";
    pub(crate) const QUICKSTART: &str = "🚀";
    pub(crate) const OK: &str = "✔";
    pub(crate) const WARNING: &str = "⚠";
    pub(crate) const ERROR: &str = "✖";
    pub(crate) const INFO: &str = "ℹ";
    pub(crate) const KEY: &str = "🔑";
    pub(crate) const MINT: &str = "✨";
    pub(crate) const SEND: &str = "📤";
    pub(crate) const BURN: &str = "🔥";
    pub(crate) const COINS: &str = "💰";
    pub(crate) const DROP: &str = "📥";
    pub(crate) const MENU: &str = "⏷";

    /// Every glyph, for the bundled-font coverage test.
    #[cfg(test)]
    pub(crate) const ALL: &[&str] = &[
        HOME, ACCOUNTS, BLOCKS, ACTIVITY, STATE, COMPOSE, CONTRACTS, PACKAGES, ENDPOINTS, LOGS,
        START, STOP, REFRESH, RESET, NEW, PRIVATE, FOLDER, LIGHT, DARK, QUICKSTART, OK, WARNING,
        ERROR, INFO, KEY, MINT, SEND, BURN, COINS, DROP, MENU,
    ];
}

pub(crate) fn palette(ui: &Ui) -> &'static Palette {
    theme::palette(ui.ctx())
}

fn card_frame(palette: &Palette, accent: Option<Color32>) -> Frame {
    Frame::new()
        .fill(palette.surface)
        .stroke(match accent {
            Some(color) => Stroke::new(1.5, color),
            None => Stroke::new(1.0, palette.border),
        })
        .corner_radius(CornerRadius::same(CARD_RADIUS))
        .inner_margin(Margin::same(16))
        .shadow(theme::card_shadow(palette))
}

/// A rounded, softly elevated container that fills the available width.
pub(crate) fn card<R>(ui: &mut Ui, add: impl FnOnce(&mut Ui) -> R) -> egui::InnerResponse<R> {
    accent_card(ui, None, add)
}

/// A card whose border is drawn in `accent`, used for the selected or highlighted item.
pub(crate) fn accent_card<R>(
    ui: &mut Ui,
    accent: Option<Color32>,
    add: impl FnOnce(&mut Ui) -> R,
) -> egui::InnerResponse<R> {
    let palette = palette(ui);
    card_frame(palette, accent).show(ui, |ui| {
        ui.set_min_width(ui.available_width());
        add(ui)
    })
}

/// Lay `items` out in rows of `columns` equal-width cells.
pub(crate) fn card_grid<T>(
    ui: &mut Ui,
    items: &[T],
    columns: usize,
    mut cell: impl FnMut(&mut Ui, &T),
) {
    let columns = columns.max(1);
    for row in items.chunks(columns) {
        ui.columns(columns, |cells| {
            for (ui, item) in cells.iter_mut().zip(row) {
                cell(ui, item);
            }
        });
        ui.add_space(4.0);
    }
}

/// Page heading with a muted one-line explanation.
pub(crate) fn page_title(ui: &mut Ui, title: &str, subtitle: &str) {
    page_header(ui, title, subtitle, |_| {});
}

/// Page heading with right-aligned controls on the title row and a wrapping explanation.
pub(crate) fn page_header(
    ui: &mut Ui,
    title: &str,
    subtitle: &str,
    trailing: impl FnOnce(&mut Ui),
) {
    let palette = palette(ui);
    ui.horizontal(|ui| {
        ui.label(RichText::new(title).size(26.0).strong().color(palette.text));
        ui.with_layout(Layout::right_to_left(Align::Center), trailing);
    });
    if !subtitle.is_empty() {
        ui.add(egui::Label::new(RichText::new(subtitle).color(palette.muted)).wrap());
    }
    ui.add_space(8.0);
}

/// Card heading with a tinted icon badge.
pub(crate) fn card_title(ui: &mut Ui, glyph: &str, title: &str) {
    let palette = palette(ui);
    ui.horizontal(|ui| {
        icon_badge(ui, glyph, palette.sakura, palette.sakura_soft);
        ui.label(RichText::new(title).size(16.0).strong().color(palette.text));
    });
}

/// Small rounded square holding one glyph.
pub(crate) fn icon_badge(ui: &mut Ui, glyph: &str, fg: Color32, bg: Color32) -> Response {
    let (rect, response) = ui.allocate_exact_size(Vec2::splat(28.0), Sense::hover());
    ui.painter().rect_filled(rect, CornerRadius::same(8), bg);
    ui.painter().text(
        rect.center(),
        Align2::CENTER_CENTER,
        glyph,
        FontId::proportional(14.0),
        fg,
    );
    response
}

/// Uppercase caption above a value.
pub(crate) fn eyebrow(palette: &Palette, text: &str) -> RichText {
    RichText::new(text.to_uppercase())
        .size(10.5)
        .strong()
        .color(palette.faint)
}

/// Muted helper text.
pub(crate) fn hint(ui: &mut Ui, text: &str) -> Response {
    let palette = palette(ui);
    ui.add(egui::Label::new(RichText::new(text).color(palette.muted)).wrap())
}

/// A rounded label chip.
pub(crate) fn pill(ui: &mut Ui, text: impl Into<String>, fg: Color32, bg: Color32) -> Response {
    Frame::new()
        .fill(bg)
        .corner_radius(CornerRadius::same(255))
        .inner_margin(Margin::symmetric(9, 3))
        .show(ui, |ui| {
            ui.label(RichText::new(text.into()).size(12.0).strong().color(fg));
        })
        .response
}

/// A filled circle sized for inline status.
pub(crate) fn dot(ui: &mut Ui, color: Color32, radius: f32) -> Response {
    let (rect, response) = ui.allocate_exact_size(
        Vec2::new(radius * 2.0 + 2.0, radius * 2.0 + 2.0),
        Sense::hover(),
    );
    ui.painter().circle_filled(rect.center(), radius, color);
    response
}

/// Lifecycle phase chip; Starting shows a small spinner.
pub(crate) fn phase_pill(ui: &mut Ui, phase: ManagedPhase) -> Response {
    let palette = palette(ui);
    let (fg, bg) = theme::phase_colors(palette, phase);
    Frame::new()
        .fill(bg)
        .corner_radius(CornerRadius::same(255))
        .inner_margin(Margin::symmetric(10, 3))
        .show(ui, |ui| {
            ui.spacing_mut().item_spacing.x = 6.0;
            ui.horizontal(|ui| {
                if phase == ManagedPhase::Starting {
                    ui.add(egui::Spinner::new().size(11.0).color(fg));
                } else {
                    dot(ui, fg, 4.0);
                }
                ui.label(
                    RichText::new(theme::phase_label(phase))
                        .size(12.5)
                        .strong()
                        .color(fg),
                );
            });
        })
        .response
}

/// Aggregate validator liveness: `running` filled dots out of `total`. The supervisor reports a
/// count only, so dots never claim which individual validator is alive.
pub(crate) fn validator_dots(ui: &mut Ui, running: usize, total: usize) -> Response {
    let palette = palette(ui);
    let response = ui
        .horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 3.0;
            for index in 0..total {
                dot(
                    ui,
                    if index < running {
                        palette.matcha
                    } else {
                        palette.border
                    },
                    4.5,
                );
            }
        })
        .response;
    response.on_hover_text(format!("{running} of {total} validators running"))
}

/// Filled sakura button for the main action of a view.
pub(crate) fn primary_button(palette: &Palette, text: &str) -> egui::Button<'static> {
    egui::Button::new(RichText::new(text).color(palette.on_sakura).strong())
        .fill(palette.sakura)
        .stroke(Stroke::NONE)
        .corner_radius(CornerRadius::same(CONTROL_RADIUS))
        .min_size(Vec2::new(0.0, 32.0))
}

/// Tinted button for secondary or contextual actions.
pub(crate) fn tonal_button(text: &str, fg: Color32, bg: Color32) -> egui::Button<'static> {
    egui::Button::new(RichText::new(text).color(fg).strong())
        .fill(bg)
        .stroke(Stroke::NONE)
        .corner_radius(CornerRadius::same(CONTROL_RADIUS))
        .min_size(Vec2::new(0.0, 32.0))
}

/// Copy `value` to the clipboard and confirm with a toast.
pub(crate) fn copy_to_clipboard(context: &egui::Context, value: &str, what: &str) {
    context.copy_text(value.to_owned());
    notify(context, format!("Copied {what}"));
}

/// Painted two-sheet copy button.
pub(crate) fn copy_button(ui: &mut Ui, value: &str, what: &str) -> Response {
    let palette = palette(ui);
    let (rect, response) = ui.allocate_exact_size(Vec2::splat(22.0), Sense::click());
    let color = if response.hovered() {
        ui.painter()
            .rect_filled(rect, CornerRadius::same(6), palette.sakura_soft);
        palette.sakura
    } else {
        palette.faint
    };
    let stroke = Stroke::new(1.3, color);
    let back = egui::Rect::from_min_size(rect.min + Vec2::new(5.0, 4.0), Vec2::new(9.0, 11.0));
    let front = back.translate(Vec2::new(3.5, 3.5));
    ui.painter().rect_stroke(
        back,
        CornerRadius::same(2),
        stroke,
        egui::StrokeKind::Inside,
    );
    ui.painter().rect_filled(
        front,
        CornerRadius::same(2),
        if response.hovered() {
            palette.sakura_soft
        } else {
            palette.surface
        },
    );
    ui.painter().rect_stroke(
        front,
        CornerRadius::same(2),
        stroke,
        egui::StrokeKind::Inside,
    );
    response.widget_info(|| WidgetInfo::labeled(WidgetType::Button, true, format!("Copy {what}")));
    let response = response.on_hover_text(format!("Copy {what}"));
    if response.clicked() {
        copy_to_clipboard(ui.ctx(), value, what);
    }
    response
}

/// Painted close cross; returns the click response.
pub(crate) fn close_button(ui: &mut Ui, color: Color32) -> Response {
    let (rect, response) = ui.allocate_exact_size(Vec2::splat(20.0), Sense::click());
    let color = if response.hovered() {
        color
    } else {
        color.gamma_multiply(0.7)
    };
    let inset = rect.shrink(6.0);
    let stroke = Stroke::new(1.6, color);
    ui.painter()
        .line_segment([inset.left_top(), inset.right_bottom()], stroke);
    ui.painter()
        .line_segment([inset.right_top(), inset.left_bottom()], stroke);
    response.widget_info(|| WidgetInfo::labeled(WidgetType::Button, true, "Dismiss"));
    response.on_hover_text("Dismiss")
}

/// Caption, monospace value and copy button on one wrapping row.
pub(crate) fn copy_field(ui: &mut Ui, label: &str, value: &str) {
    let palette = palette(ui);
    ui.horizontal_wrapped(|ui| {
        ui.label(eyebrow(palette, label));
        ui.add(egui::Label::new(RichText::new(value).monospace().color(palette.text)).wrap());
        copy_button(ui, value, label);
    });
}

/// Monospace value shortened in the middle, with the complete value on hover.
pub(crate) fn short_mono(ui: &mut Ui, value: &str, keep: usize) -> Response {
    let palette = palette(ui);
    ui.add(egui::Label::new(
        RichText::new(short_middle(value, keep))
            .monospace()
            .color(palette.text),
    ))
    .on_hover_text(value)
}

/// Keep the first and last `keep` characters of long identifiers.
pub(crate) fn short_middle(value: &str, keep: usize) -> String {
    let count = value.chars().count();
    if count <= keep * 2 + 1 {
        return value.to_owned();
    }
    let head = value.chars().take(keep).collect::<String>();
    let tail = value.chars().skip(count - keep).collect::<String>();
    format!("{head}…{tail}")
}

#[derive(Clone)]
struct Toast {
    message: String,
    shown_at: f64,
}

fn toast_id() -> egui::Id {
    egui::Id::new("mochi-toast")
}

const TOAST_SECONDS: f64 = 1.8;

/// Show a short confirmation near the bottom of the window.
pub(crate) fn notify(context: &egui::Context, message: impl Into<String>) {
    let shown_at = context.input(|input| input.time);
    context.data_mut(|data| {
        data.insert_temp(
            toast_id(),
            Toast {
                message: message.into(),
                shown_at,
            },
        );
    });
}

/// The current toast text, if one is still visible.
#[cfg(test)]
pub(crate) fn current_toast(context: &egui::Context) -> Option<String> {
    let now = context.input(|input| input.time);
    context
        .data(|data| data.get_temp::<Toast>(toast_id()))
        .filter(|toast| now - toast.shown_at <= TOAST_SECONDS)
        .map(|toast| toast.message)
}

/// Paint the toast, fading it out; call once per frame after all panels.
pub(crate) fn show_toasts(context: &egui::Context) {
    let Some(toast) = context.data(|data| data.get_temp::<Toast>(toast_id())) else {
        return;
    };
    let age = context.input(|input| input.time) - toast.shown_at;
    if age > TOAST_SECONDS {
        context.data_mut(|data| data.remove::<Toast>(toast_id()));
        return;
    }
    let alpha = ((TOAST_SECONDS - age) / 0.3).clamp(0.0, 1.0) as f32;
    let palette = theme::palette(context);
    egui::Area::new(egui::Id::new("mochi-toast-area"))
        .anchor(Align2::CENTER_BOTTOM, Vec2::new(0.0, -28.0))
        .order(egui::Order::Tooltip)
        .interactable(false)
        .show(context, |ui| {
            Frame::new()
                .fill(palette.text.gamma_multiply(alpha))
                .corner_radius(CornerRadius::same(255))
                .inner_margin(Margin::symmetric(16, 8))
                .show(ui, |ui| {
                    ui.label(
                        RichText::new(format!("{}  {}", icon::OK, toast.message))
                            .color(palette.background.gamma_multiply(alpha))
                            .strong(),
                    );
                });
        });
    context.request_repaint_after(std::time::Duration::from_millis(50));
}

/// Tone of an inline message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Tone {
    Error,
    Success,
    Info,
    Warning,
}

impl Tone {
    fn colors(self, palette: &Palette) -> (Color32, Color32, &'static str) {
        match self {
            Self::Error => (palette.aka, palette.aka_soft, icon::ERROR),
            Self::Success => (palette.matcha, palette.matcha_soft, icon::OK),
            Self::Info => (palette.sky, palette.sky_soft, icon::INFO),
            Self::Warning => (palette.kinako, palette.kinako_soft, icon::WARNING),
        }
    }
}

/// A full-width message with an optional dismiss control; returns true when dismissed.
pub(crate) fn banner(ui: &mut Ui, tone: Tone, text: &str, dismissible: bool) -> bool {
    let palette = palette(ui);
    let (fg, bg, glyph) = tone.colors(palette);
    let mut dismissed = false;
    Frame::new()
        .fill(bg)
        .stroke(Stroke::new(1.0, fg.gamma_multiply(0.35)))
        .corner_radius(CornerRadius::same(12))
        .inner_margin(Margin::symmetric(14, 10))
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.horizontal_top(|ui| {
                ui.label(RichText::new(glyph).color(fg).strong());
                let width = ui.available_width() - if dismissible { 28.0 } else { 0.0 };
                ui.allocate_ui_with_layout(
                    Vec2::new(width.max(40.0), 0.0),
                    Layout::top_down(Align::Min),
                    |ui| {
                        ui.add(egui::Label::new(RichText::new(text).color(palette.text)).wrap());
                    },
                );
                if dismissible && close_button(ui, fg).clicked() {
                    dismissed = true;
                }
            });
        });
    dismissed
}

/// Centered illustration-free empty state.
pub(crate) fn empty_state(ui: &mut Ui, glyph: &str, title: &str, body: &str) {
    let palette = palette(ui);
    ui.vertical_centered(|ui| {
        ui.add_space(18.0);
        ui.label(RichText::new(glyph).size(34.0).color(palette.faint));
        ui.add_space(4.0);
        ui.label(RichText::new(title).size(16.0).strong().color(palette.text));
        ui.add(egui::Label::new(RichText::new(body).color(palette.muted)).wrap());
        ui.add_space(18.0);
    });
}

/// Segmented control; returns true when the selection changed.
pub(crate) fn segmented<T: PartialEq + Copy>(
    ui: &mut Ui,
    value: &mut T,
    options: &[(T, &str)],
) -> bool {
    let palette = palette(ui);
    let mut changed = false;
    Frame::new()
        .fill(palette.inset)
        .corner_radius(CornerRadius::same(CONTROL_RADIUS + 2))
        .inner_margin(Margin::same(3))
        .show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.spacing_mut().item_spacing.x = 2.0;
                for (option, label) in options {
                    let selected = *value == *option;
                    let button = egui::Button::new(RichText::new(*label).color(if selected {
                        palette.text
                    } else {
                        palette.muted
                    }))
                    .fill(if selected {
                        palette.surface
                    } else {
                        Color32::TRANSPARENT
                    })
                    .stroke(if selected {
                        Stroke::new(1.0, palette.border)
                    } else {
                        Stroke::NONE
                    })
                    .corner_radius(CornerRadius::same(CONTROL_RADIUS))
                    .selected(selected);
                    if ui.add(button).clicked() && !selected {
                        *value = *option;
                        changed = true;
                    }
                }
            });
        });
    changed
}

/// Caption above arbitrary value content, for status strips and summaries.
pub(crate) fn stat(ui: &mut Ui, label: &str, add_value: impl FnOnce(&mut Ui)) -> Response {
    let palette = palette(ui);
    ui.vertical(|ui| {
        ui.spacing_mut().item_spacing.y = 2.0;
        ui.label(eyebrow(palette, label));
        add_value(ui);
    })
    .response
}

/// Sidebar row with a glyph, label and optional count badge.
pub(crate) fn nav_item(
    ui: &mut Ui,
    selected: bool,
    glyph: &str,
    label: &str,
    badge: Option<usize>,
) -> Response {
    let palette = palette(ui);
    let (rect, response) =
        ui.allocate_exact_size(Vec2::new(ui.available_width(), 34.0), Sense::click());
    response
        .widget_info(|| WidgetInfo::selected(WidgetType::SelectableLabel, true, selected, label));
    let painter = ui.painter();
    if selected {
        painter.rect_filled(rect, CornerRadius::same(10), palette.sakura_soft);
        let bar = egui::Rect::from_min_size(
            rect.left_top() + Vec2::new(0.0, 8.0),
            Vec2::new(3.0, rect.height() - 16.0),
        );
        painter.rect_filled(bar, CornerRadius::same(2), palette.sakura);
    } else if response.hovered() {
        painter.rect_filled(rect, CornerRadius::same(10), palette.inset);
    }
    let color = if selected {
        palette.sakura
    } else {
        palette.muted
    };
    painter.text(
        rect.left_center() + Vec2::new(16.0, 0.0),
        Align2::LEFT_CENTER,
        glyph,
        FontId::proportional(15.0),
        color,
    );
    painter.text(
        rect.left_center() + Vec2::new(42.0, 0.0),
        Align2::LEFT_CENTER,
        label,
        FontId::proportional(14.5),
        if selected {
            palette.text
        } else {
            palette.muted
        },
    );
    if let Some(count) = badge.filter(|count| *count > 0) {
        let text = if count > 99 {
            "99+".to_owned()
        } else {
            count.to_string()
        };
        let galley = painter.layout_no_wrap(text, FontId::proportional(11.0), palette.muted);
        let size = Vec2::new(galley.size().x + 12.0, 18.0);
        let badge = egui::Rect::from_min_size(
            rect.right_center() - Vec2::new(size.x + 10.0, size.y / 2.0),
            size,
        );
        painter.rect_filled(badge, CornerRadius::same(255), palette.inset);
        painter.galley(badge.center() - galley.size() / 2.0, galley, palette.muted);
    }
    response.on_hover_cursor(egui::CursorIcon::PointingHand)
}

/// Inset monospace block with its own copy control.
pub(crate) fn code_block(ui: &mut Ui, text: &str, what: &str) {
    let palette = palette(ui);
    Frame::new()
        .fill(palette.inset)
        .corner_radius(CornerRadius::same(10))
        .inner_margin(Margin::symmetric(12, 8))
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.horizontal_top(|ui| {
                let width = ui.available_width() - 30.0;
                ui.allocate_ui_with_layout(
                    Vec2::new(width.max(40.0), 0.0),
                    Layout::top_down(Align::Min),
                    |ui| {
                        ui.add(
                            egui::Label::new(RichText::new(text).monospace().color(palette.text))
                                .wrap(),
                        );
                    },
                );
                copy_button(ui, text, what);
            });
        });
}

/// Compact relative time for feeds.
pub(crate) fn time_ago(then_ms: u64, now_ms: u64) -> String {
    let seconds = now_ms.saturating_sub(then_ms) / 1000;
    match seconds {
        0..=4 => "just now".to_owned(),
        5..=59 => format!("{seconds}s ago"),
        60..=3599 => format!("{}m ago", seconds / 60),
        3600..=86_399 => format!("{}h ago", seconds / 3600),
        _ => format!("{}d ago", seconds / 86_400),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_icon_glyph_exists_in_the_bundled_fonts() {
        let context = egui::Context::default();
        let _ = context.run(egui::RawInput::default(), |_| {});
        for glyph in icon::ALL {
            assert!(
                context.fonts_mut(|fonts| fonts.has_glyphs(&FontId::proportional(14.0), glyph)),
                "missing glyph {glyph:?}"
            );
        }
    }

    #[test]
    fn identifiers_shorten_by_characters_not_bytes() {
        assert_eq!(short_middle("abcdef", 3), "abcdef");
        assert_eq!(short_middle("abcdefgh", 3), "abc…fgh");
        assert_eq!(short_middle("ｱｲｳｴｵｶｷｸ", 2), "ｱｲ…ｷｸ");
    }

    #[test]
    fn relative_times_are_compact_and_saturate() {
        assert_eq!(time_ago(10_000, 11_000), "just now");
        assert_eq!(time_ago(0, 42_000), "42s ago");
        assert_eq!(time_ago(0, 180_000), "3m ago");
        assert_eq!(time_ago(0, 7_200_000), "2h ago");
        assert_eq!(time_ago(0, 172_800_000), "2d ago");
        assert_eq!(time_ago(5_000, 0), "just now");
    }

    #[test]
    fn toasts_expire_and_segmented_controls_report_changes() {
        let context = egui::Context::default();
        let _ = context.run(egui::RawInput::default(), |context| {
            notify(context, "Copied account");
        });
        assert_eq!(current_toast(&context).as_deref(), Some("Copied account"));
        let _ = context.run(
            egui::RawInput {
                time: Some(10.0),
                ..Default::default()
            },
            show_toasts,
        );
        assert!(current_toast(&context).is_none());

        let mut value = 1;
        let mut changed = false;
        let mut draw = |context: &egui::Context| {
            egui::CentralPanel::default().show(context, |ui| {
                changed |= segmented(ui, &mut value, &[(1, "One"), (2, "Two")]);
            });
        };
        super::super::tests::click_label(&context, "Two", &mut draw);
        assert!(changed);
        assert_eq!(value, 2);
    }

    #[test]
    fn banners_report_dismissal_only_when_allowed() {
        for dismissible in [false, true] {
            let context = egui::Context::default();
            let mut dismissed = false;
            let mut draw = |context: &egui::Context| {
                egui::CentralPanel::default().show(context, |ui| {
                    dismissed |= banner(ui, Tone::Error, "exact original failure", dismissible);
                });
            };
            let _ = super::super::tests::render_frame(&context, Vec::new(), &mut draw);
            let output = super::super::tests::render_frame(&context, Vec::new(), &mut draw);
            assert!(
                super::super::tests::text_position(&output, "exact original failure").is_some()
            );
            assert!(!dismissed);
        }
    }
}
