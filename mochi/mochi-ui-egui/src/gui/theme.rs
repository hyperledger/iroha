//! Mochi's light and dark palettes, typography and optional system font fallbacks.
//!
//! Colors follow the brand: rice-cake cream surfaces, sakura pink actions, SORA red for
//! failures, matcha green for healthy networks and kinako gold for work in progress.

use eframe::egui::{
    self, Color32, CornerRadius, FontData, FontDefinitions, FontFamily, FontId, Margin, Shadow,
    Stroke, TextStyle, Theme, ThemePreference, Visuals, style::WidgetVisuals,
};
use mochi_core::developer::ManagedPhase;
use std::{path::Path, sync::Arc};

/// Semantic colors shared by every Mochi surface.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct Palette {
    /// Canvas behind cards.
    pub(crate) background: Color32,
    /// Header, status strip and sidebar.
    pub(crate) panel: Color32,
    /// Cards and dialogs.
    pub(crate) surface: Color32,
    /// Text fields, code and quiet buttons.
    pub(crate) inset: Color32,
    pub(crate) border: Color32,
    pub(crate) text: Color32,
    pub(crate) muted: Color32,
    pub(crate) faint: Color32,
    /// Primary actions and the selected navigation item.
    pub(crate) sakura: Color32,
    pub(crate) sakura_soft: Color32,
    pub(crate) on_sakura: Color32,
    /// Links and informational accents.
    pub(crate) sky: Color32,
    pub(crate) sky_soft: Color32,
    /// Healthy, ready and successful states.
    pub(crate) matcha: Color32,
    pub(crate) matcha_soft: Color32,
    /// Work in progress and warnings.
    pub(crate) kinako: Color32,
    pub(crate) kinako_soft: Color32,
    /// Failures and destructive actions.
    pub(crate) aka: Color32,
    pub(crate) aka_soft: Color32,
    /// Event category accent for triggers and contracts.
    pub(crate) fuji: Color32,
    pub(crate) fuji_soft: Color32,
    pub(crate) shadow: Color32,
}

pub(crate) const LIGHT: Palette = Palette {
    background: Color32::from_rgb(248, 244, 241),
    panel: Color32::from_rgb(255, 255, 255),
    surface: Color32::from_rgb(255, 255, 255),
    inset: Color32::from_rgb(245, 239, 235),
    border: Color32::from_rgb(234, 225, 219),
    text: Color32::from_rgb(46, 34, 48),
    muted: Color32::from_rgb(112, 99, 116),
    faint: Color32::from_rgb(160, 148, 162),
    sakura: Color32::from_rgb(207, 53, 109),
    sakura_soft: Color32::from_rgb(252, 230, 238),
    on_sakura: Color32::from_rgb(255, 255, 255),
    sky: Color32::from_rgb(52, 104, 214),
    sky_soft: Color32::from_rgb(229, 238, 253),
    matcha: Color32::from_rgb(38, 140, 84),
    matcha_soft: Color32::from_rgb(224, 243, 231),
    kinako: Color32::from_rgb(176, 117, 14),
    kinako_soft: Color32::from_rgb(251, 240, 217),
    aka: Color32::from_rgb(211, 38, 50),
    aka_soft: Color32::from_rgb(252, 228, 230),
    fuji: Color32::from_rgb(124, 77, 196),
    fuji_soft: Color32::from_rgb(239, 231, 251),
    shadow: Color32::from_black_alpha(22),
};

pub(crate) const DARK: Palette = Palette {
    background: Color32::from_rgb(21, 18, 28),
    panel: Color32::from_rgb(28, 24, 38),
    surface: Color32::from_rgb(35, 30, 47),
    inset: Color32::from_rgb(25, 21, 34),
    border: Color32::from_rgb(54, 46, 70),
    text: Color32::from_rgb(243, 237, 245),
    muted: Color32::from_rgb(182, 171, 192),
    faint: Color32::from_rgb(128, 118, 141),
    sakura: Color32::from_rgb(255, 120, 166),
    sakura_soft: Color32::from_rgb(66, 34, 54),
    on_sakura: Color32::from_rgb(38, 12, 26),
    sky: Color32::from_rgb(130, 170, 255),
    sky_soft: Color32::from_rgb(31, 42, 70),
    matcha: Color32::from_rgb(98, 214, 150),
    matcha_soft: Color32::from_rgb(24, 52, 42),
    kinako: Color32::from_rgb(244, 190, 96),
    kinako_soft: Color32::from_rgb(58, 46, 23),
    aka: Color32::from_rgb(255, 112, 118),
    aka_soft: Color32::from_rgb(64, 29, 35),
    fuji: Color32::from_rgb(190, 160, 255),
    fuji_soft: Color32::from_rgb(45, 34, 70),
    shadow: Color32::from_black_alpha(96),
};

/// The palette for the theme currently shown by `context`.
pub(crate) fn palette(context: &egui::Context) -> &'static Palette {
    palette_for(context.theme())
}

pub(crate) fn palette_for(theme: Theme) -> &'static Palette {
    match theme {
        Theme::Dark => &DARK,
        Theme::Light => &LIGHT,
    }
}

/// Foreground and soft background for a lifecycle phase.
pub(crate) fn phase_colors(palette: &Palette, phase: ManagedPhase) -> (Color32, Color32) {
    match phase {
        ManagedPhase::Ready => (palette.matcha, palette.matcha_soft),
        ManagedPhase::Starting => (palette.kinako, palette.kinako_soft),
        ManagedPhase::Stopped => (palette.muted, palette.inset),
        ManagedPhase::Failed => (palette.aka, palette.aka_soft),
    }
}

/// Friendly phase name for chips and the mascot.
pub(crate) fn phase_label(phase: ManagedPhase) -> &'static str {
    match phase {
        ManagedPhase::Ready => "Ready",
        ManagedPhase::Starting => "Starting",
        ManagedPhase::Stopped => "Stopped",
        ManagedPhase::Failed => "Failed",
    }
}

pub(crate) const CARD_RADIUS: u8 = 14;
pub(crate) const CONTROL_RADIUS: u8 = 9;

/// Soft elevation used by cards.
pub(crate) fn card_shadow(palette: &Palette) -> Shadow {
    Shadow {
        offset: [0, 2],
        blur: 10,
        spread: 0,
        color: palette.shadow,
    }
}

/// Install both theme styles and follow the operating-system appearance by default.
pub(crate) fn install(context: &egui::Context) {
    for theme in [Theme::Light, Theme::Dark] {
        let mut style = (*context.style_of(theme)).clone();
        apply(&mut style, palette_for(theme), theme == Theme::Dark);
        context.set_style_of(theme, style);
    }
    context.set_theme(ThemePreference::System);
}

fn apply(style: &mut egui::Style, palette: &Palette, dark: bool) {
    style.text_styles = [
        (
            TextStyle::Small,
            FontId::new(11.5, FontFamily::Proportional),
        ),
        (TextStyle::Body, FontId::new(14.0, FontFamily::Proportional)),
        (
            TextStyle::Button,
            FontId::new(14.0, FontFamily::Proportional),
        ),
        (
            TextStyle::Monospace,
            FontId::new(13.0, FontFamily::Monospace),
        ),
        (
            TextStyle::Heading,
            FontId::new(22.0, FontFamily::Proportional),
        ),
    ]
    .into();
    let spacing = &mut style.spacing;
    spacing.item_spacing = egui::vec2(8.0, 8.0);
    spacing.button_padding = egui::vec2(12.0, 6.0);
    spacing.interact_size = egui::vec2(40.0, 28.0);
    spacing.window_margin = Margin::same(18);
    spacing.menu_margin = Margin::same(8);
    spacing.indent = 16.0;
    spacing.combo_width = 160.0;
    spacing.text_edit_width = 320.0;
    style.visuals = visuals(palette, dark);
}

fn widget(fill: Color32, stroke: Color32, text: Color32, expansion: f32) -> WidgetVisuals {
    WidgetVisuals {
        bg_fill: fill,
        weak_bg_fill: fill,
        bg_stroke: Stroke::new(1.0, stroke),
        corner_radius: CornerRadius::same(CONTROL_RADIUS),
        fg_stroke: Stroke::new(1.0, text),
        expansion,
    }
}

fn visuals(palette: &Palette, dark: bool) -> Visuals {
    let mut visuals = if dark {
        Visuals::dark()
    } else {
        Visuals::light()
    };
    visuals.widgets.noninteractive = widget(palette.surface, palette.border, palette.text, 0.0);
    visuals.widgets.inactive = widget(palette.inset, palette.border, palette.text, 0.0);
    visuals.widgets.hovered = widget(palette.sakura_soft, palette.sakura, palette.text, 1.0);
    visuals.widgets.active = widget(palette.sakura_soft, palette.sakura, palette.text, 1.0);
    visuals.widgets.open = widget(palette.inset, palette.sakura, palette.text, 0.0);
    visuals.selection.bg_fill = if dark {
        Color32::from_rgb(110, 46, 78)
    } else {
        Color32::from_rgb(248, 200, 218)
    };
    visuals.selection.stroke = Stroke::new(1.5, palette.sakura);
    visuals.hyperlink_color = palette.sky;
    visuals.faint_bg_color = palette.inset;
    visuals.extreme_bg_color = palette.inset;
    visuals.text_edit_bg_color = Some(palette.inset);
    visuals.code_bg_color = palette.inset;
    visuals.warn_fg_color = palette.kinako;
    visuals.error_fg_color = palette.aka;
    visuals.panel_fill = palette.background;
    visuals.window_fill = palette.surface;
    visuals.window_stroke = Stroke::new(1.0, palette.border);
    visuals.window_corner_radius = CornerRadius::same(16);
    visuals.menu_corner_radius = CornerRadius::same(12);
    visuals.window_shadow = Shadow {
        offset: [0, 10],
        blur: 32,
        spread: 0,
        color: palette.shadow,
    };
    visuals.popup_shadow = Shadow {
        offset: [0, 6],
        blur: 18,
        spread: 0,
        color: palette.shadow,
    };
    visuals.striped = true;
    visuals.indent_has_left_vline = false;
    visuals
}

/// Font files tried, in order, to render the halfwidth katakana used by I105 account
/// literals. egui's bundled fonts have no CJK coverage; absence keeps the defaults.
const CJK_FALLBACKS: &[(&str, u32)] = &[
    ("/System/Library/Fonts/ヒラギノ角ゴシック W3.ttc", 0),
    ("/System/Library/Fonts/Supplemental/Arial Unicode.ttf", 0),
    ("/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc", 0),
    ("/usr/share/fonts/noto-cjk/NotoSansCJK-Regular.ttc", 0),
    (
        "/usr/share/fonts/google-noto-cjk/NotoSansCJK-Regular.ttc",
        0,
    ),
    (
        "/usr/share/fonts/truetype/droid/DroidSansFallbackFull.ttf",
        0,
    ),
    ("C:\\Windows\\Fonts\\YuGothR.ttc", 0),
    ("C:\\Windows\\Fonts\\meiryo.ttc", 0),
    ("C:\\Windows\\Fonts\\msgothic.ttc", 0),
];

/// Friendlier rounded UI faces where the platform ships one.
const ROUNDED_UI_FONTS: &[(&str, u32)] = &[("/System/Library/Fonts/SFNSRounded.ttf", 0)];

/// Add optional system fonts. Every candidate is test-loaded first: egui panics on a font it
/// cannot parse, so an unreadable system file must never reach the live context.
pub(crate) fn install_fonts(context: &egui::Context) {
    let mut fonts = FontDefinitions::default();
    if let Some(data) = first_loadable(ROUNDED_UI_FONTS) {
        fonts.font_data.insert("mochi-ui".into(), Arc::new(data));
        if let Some(family) = fonts.families.get_mut(&FontFamily::Proportional) {
            family.insert(0, "mochi-ui".into());
        }
    }
    if let Some(data) = first_loadable(CJK_FALLBACKS) {
        // Halfwidth katakana sit high beside Latin glyphs; lower them onto the baseline.
        let data = FontData {
            tweak: egui::FontTweak {
                y_offset_factor: 0.08,
                ..Default::default()
            },
            ..data
        };
        fonts.font_data.insert("mochi-cjk".into(), Arc::new(data));
        for family in [FontFamily::Proportional, FontFamily::Monospace] {
            if let Some(fonts) = fonts.families.get_mut(&family) {
                fonts.push("mochi-cjk".into());
            }
        }
    }
    context.set_fonts(fonts);
}

fn first_loadable(candidates: &[(&str, u32)]) -> Option<FontData> {
    candidates.iter().find_map(|(path, index)| {
        let bytes = std::fs::read(Path::new(path)).ok()?;
        let mut data = FontData::from_owned(bytes);
        data.index = *index;
        font_loads(&data).then_some(data)
    })
}

/// Whether egui can parse `data`, checked in a throwaway context.
pub(crate) fn font_loads(data: &FontData) -> bool {
    let data = data.clone();
    std::panic::catch_unwind(move || {
        let mut fonts = FontDefinitions::empty();
        fonts.font_data.insert("probe".into(), Arc::new(data));
        fonts
            .families
            .insert(FontFamily::Proportional, vec!["probe".into()]);
        fonts
            .families
            .insert(FontFamily::Monospace, vec!["probe".into()]);
        let context = egui::Context::default();
        context.set_fonts(fonts);
        let _ = context.run(egui::RawInput::default(), |context| {
            egui::CentralPanel::default().show(context, |ui| ui.label("ｱ"));
        });
    })
    .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn luminance(color: Color32) -> f32 {
        let channel = |value: u8| {
            let value = f32::from(value) / 255.0;
            if value <= 0.039_28 {
                value / 12.92
            } else {
                ((value + 0.055) / 1.055).powf(2.4)
            }
        };
        0.2126 * channel(color.r()) + 0.7152 * channel(color.g()) + 0.0722 * channel(color.b())
    }

    fn contrast(a: Color32, b: Color32) -> f32 {
        let (a, b) = (luminance(a), luminance(b));
        (a.max(b) + 0.05) / (a.min(b) + 0.05)
    }

    #[test]
    fn body_text_and_primary_actions_meet_readable_contrast() {
        for palette in [&LIGHT, &DARK] {
            for surface in [palette.background, palette.surface, palette.panel] {
                assert!(contrast(palette.text, surface) >= 7.0);
                assert!(contrast(palette.muted, surface) >= 4.5);
            }
            assert!(contrast(palette.on_sakura, palette.sakura) >= 4.5);
            for accent in [palette.matcha, palette.kinako, palette.aka, palette.sky] {
                assert!(contrast(accent, palette.surface) >= 3.0);
            }
        }
    }

    #[test]
    fn every_phase_has_distinct_colors_and_label() {
        let phases = [
            ManagedPhase::Ready,
            ManagedPhase::Starting,
            ManagedPhase::Stopped,
            ManagedPhase::Failed,
        ];
        for palette in [&LIGHT, &DARK] {
            let colors = phases.map(|phase| phase_colors(palette, phase).0);
            for (index, color) in colors.iter().enumerate() {
                assert!(!colors[index + 1..].contains(color));
            }
        }
        assert_eq!(
            phases.map(phase_label),
            ["Ready", "Starting", "Stopped", "Failed"]
        );
    }

    #[test]
    fn installed_styles_follow_each_theme() {
        let context = egui::Context::default();
        install(&context);
        assert_eq!(
            context.style_of(Theme::Light).visuals.panel_fill,
            LIGHT.background
        );
        assert_eq!(
            context.style_of(Theme::Dark).visuals.panel_fill,
            DARK.background
        );
        assert!(context.style_of(Theme::Dark).visuals.dark_mode);
        assert_eq!(palette_for(Theme::Dark), &DARK);
    }

    #[test]
    fn unparsable_font_files_are_refused_before_reaching_the_context() {
        assert!(!font_loads(&FontData::from_static(b"not a font file")));
        assert!(first_loadable(&[("/nonexistent/mochi-font.ttf", 0)]).is_none());
    }
}
