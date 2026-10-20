//! Mochi brand marks: the window icon, the mascot and the wordmark.
//!
//! The mascot is a *kagami-mochi* (`mochi/assets/mochi-mark.svg`): two rice-cake tiers crowned
//! with the Hyperledger Iroha sakura, on a stand carrying the SORA crest. The stand stays still
//! while the rice cake bounces, and its face is painted here so it can follow network state.

use eframe::egui::{
    self, Color32, ColorImage, CornerRadius, FontId, Pos2, Rect, Response, Sense, Stroke,
    TextureFilter, TextureHandle, TextureOptions, Ui, Vec2,
};
use mochi_core::developer::ManagedPhase;
use std::time::Duration;

const ICON_PNG: &[u8] = include_bytes!("../../../assets/mochi-icon-512.png");
const MASCOT_PNG: &[u8] = include_bytes!("../../../assets/mochi-mascot-512.png");
const STAND_PNG: &[u8] = include_bytes!("../../../assets/mochi-stand-512.png");

/// Ink used for the face and wordmark on light surfaces.
const INK: Color32 = Color32::from_rgb(46, 34, 48);
/// SORA red, used for the wordmark's i-dot.
pub(crate) const SORA_RED: Color32 = Color32::from_rgb(227, 36, 45);
const BLUSH_COLOR: Color32 = Color32::from_rgba_premultiplied(140, 79, 94, 140);

// Face geometry in the 512-unit artwork coordinates of `mochi-mark.svg`.
/// Where the rice cake rests on its paper; squash and bounce pivot here.
const FEET_Y: f32 = 368.0;
const EYES_X: [f32; 2] = [212.0, 300.0];
const EYE_Y: f32 = 306.0;
const MOUTH_Y: f32 = 324.0;
const BLUSH_X: [f32; 2] = [174.0, 338.0];
const BLUSH_Y: f32 = 328.0;

/// The window and dock icon decoded from the bundled artwork.
pub(crate) fn window_icon() -> Option<egui::IconData> {
    eframe::icon_data::from_png_bytes(ICON_PNG).ok()
}

/// GPU textures of the mascot layers, uploaded once per context.
pub(crate) struct Brand {
    mascot: TextureHandle,
    stand: TextureHandle,
}

fn texture(context: &egui::Context, name: &str, png: &[u8]) -> Option<TextureHandle> {
    let decoded = eframe::icon_data::from_png_bytes(png).ok()?;
    let size = [
        usize::try_from(decoded.width).ok()?,
        usize::try_from(decoded.height).ok()?,
    ];
    let image = ColorImage::from_rgba_unmultiplied(size, &decoded.rgba);
    Some(context.load_texture(
        name,
        image,
        TextureOptions::LINEAR.with_mipmap_mode(Some(TextureFilter::Linear)),
    ))
}

impl Brand {
    pub(crate) fn load(context: &egui::Context) -> Option<Self> {
        Some(Self {
            mascot: texture(context, "mochi-mascot", MASCOT_PNG)?,
            stand: texture(context, "mochi-stand", STAND_PNG)?,
        })
    }
}

/// The mascot's expression, chosen from the selected network's lifecycle phase.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Mood {
    /// No environment yet.
    Curious,
    Happy,
    Excited,
    Sleepy,
    Dizzy,
}

impl Mood {
    pub(crate) fn for_phase(phase: Option<ManagedPhase>) -> Self {
        match phase {
            None => Self::Curious,
            Some(ManagedPhase::Ready) => Self::Happy,
            Some(ManagedPhase::Starting) => Self::Excited,
            Some(ManagedPhase::Stopped) => Self::Sleepy,
            Some(ManagedPhase::Failed) => Self::Dizzy,
        }
    }

    /// A short speech-bubble line.
    pub(crate) fn caption(self) -> &'static str {
        match self {
            Self::Curious => "Let's make a localnet!",
            Self::Happy => "All set. Let's build!",
            Self::Excited => "Warming up the validators…",
            Self::Sleepy => "Zzz… press Start to wake me.",
            Self::Dizzy => "Ouch. The logs know why.",
        }
    }
}

/// Mascot body transform: horizontal squash factor and upward lift in points.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct Pose {
    pub(crate) squash: f32,
    pub(crate) lift: f32,
    pub(crate) animating: bool,
}

/// Pose at `time`, bouncing while validators start and wobbling after a poke.
pub(crate) fn pose(mood: Mood, size: f32, time: f64, poked_at: Option<f64>) -> Pose {
    let mut pose = Pose {
        squash: 1.0,
        lift: 0.0,
        animating: false,
    };
    if mood == Mood::Excited {
        let phase = (time * 2.0).fract() as f32;
        let height = (phase * std::f32::consts::PI).sin();
        pose.lift = height * size * 0.06;
        pose.squash = 1.0 + (1.0 - height).powi(6) * 0.08 - height * 0.03;
        pose.animating = true;
    }
    if let Some(poked_at) = poked_at {
        let elapsed = (time - poked_at) as f32;
        if (0.0..0.8).contains(&elapsed) {
            pose.squash *= 1.0 + 0.2 * (-5.5 * elapsed).exp() * (17.0 * elapsed).cos();
            pose.animating = true;
        }
    }
    pose
}

/// Paint the mascot in a `size` square. Clicking it gives it a squishy poke.
pub(crate) fn mascot(ui: &mut Ui, brand: Option<&Brand>, size: f32, mood: Mood) -> Response {
    let (rect, response) = ui.allocate_exact_size(Vec2::splat(size), Sense::click());
    let time = ui.input(|input| input.time);
    let poke = response.id.with("poke");
    if response.clicked() {
        ui.ctx().data_mut(|data| data.insert_temp(poke, time));
    }
    let poked_at = ui.ctx().data(|data| data.get_temp::<f64>(poke));
    let pose = pose(mood, size, time, poked_at);
    if pose.animating {
        ui.ctx().request_repaint_after(Duration::from_millis(16));
    }
    if ui.is_rect_visible(rect) {
        paint_mascot(ui.painter(), rect, brand, mood, pose, time);
    }
    response
        .on_hover_text(mood.caption())
        .on_hover_cursor(egui::CursorIcon::PointingHand)
}

/// Maps artwork units (a 512 square) into the posed screen rectangle, pivoting at the feet.
struct Canvas {
    anchor: Pos2,
    x_scale: f32,
    y_scale: f32,
}

impl Canvas {
    fn new(rect: Rect, pose: Pose) -> Self {
        let unit = rect.width() / 512.0;
        Self {
            anchor: Pos2::new(rect.center().x, rect.top() + FEET_Y * unit - pose.lift),
            x_scale: unit * pose.squash,
            y_scale: unit / pose.squash,
        }
    }

    fn at(&self, x: f32, y: f32) -> Pos2 {
        Pos2::new(
            self.anchor.x + (x - 256.0) * self.x_scale,
            self.anchor.y + (y - FEET_Y) * self.y_scale,
        )
    }

    fn len(&self, value: f32) -> f32 {
        value * (self.x_scale + self.y_scale) * 0.5
    }

    fn image_rect(&self) -> Rect {
        Rect::from_min_max(self.at(0.0, 0.0), self.at(512.0, 512.0))
    }
}

fn paint_mascot(
    painter: &egui::Painter,
    rect: Rect,
    brand: Option<&Brand>,
    mood: Mood,
    pose: Pose,
    time: f64,
) {
    let canvas = Canvas::new(rect, pose);
    let full = Rect::from_min_max(Pos2::ZERO, Pos2::new(1.0, 1.0));
    let tint = if mood == Mood::Sleepy {
        Color32::from_rgb(232, 232, 240)
    } else {
        Color32::WHITE
    };
    match brand {
        Some(brand) => {
            // The stand stays on the floor while the rice cake bounces on it.
            painter.image(brand.stand.id(), rect, full, Color32::WHITE);
            painter.image(brand.mascot.id(), canvas.image_rect(), full, tint);
        }
        None => {
            // Without textures (headless rendering), keep a recognizable stand and two tiers.
            let still = Canvas::new(
                rect,
                Pose {
                    squash: 1.0,
                    lift: 0.0,
                    animating: false,
                },
            );
            painter.rect_filled(
                Rect::from_min_max(still.at(72.0, 362.0), still.at(440.0, 470.0)),
                CornerRadius::same(2),
                Color32::from_rgb(237, 203, 142),
            );
            for (y, rx, ry) in [(312.0, 160.0, 58.0), (218.0, 106.0, 46.0)] {
                painter.add(egui::Shape::ellipse_filled(
                    canvas.at(256.0, y),
                    Vec2::new(canvas.len(rx), canvas.len(ry)),
                    Color32::from_rgb(248, 249, 252),
                ));
            }
        }
    }
    paint_face(painter, &canvas, mood, time);
}

fn stroke_points(painter: &egui::Painter, canvas: &Canvas, points: &[(f32, f32)], width: f32) {
    let width = canvas.len(width);
    let points = points
        .iter()
        .map(|(x, y)| canvas.at(*x, *y))
        .collect::<Vec<_>>();
    if let (Some(first), Some(last)) = (points.first(), points.last()) {
        painter.circle_filled(*first, width / 2.0, INK);
        painter.circle_filled(*last, width / 2.0, INK);
    }
    painter.line(points, Stroke::new(width, INK));
}

fn quad(from: (f32, f32), control: (f32, f32), to: (f32, f32)) -> Vec<(f32, f32)> {
    (0..=12)
        .map(|step| {
            let t = step as f32 / 12.0;
            let u = 1.0 - t;
            (
                u * u * from.0 + 2.0 * u * t * control.0 + t * t * to.0,
                u * u * from.1 + 2.0 * u * t * control.1 + t * t * to.1,
            )
        })
        .collect()
}

fn paint_face(painter: &egui::Painter, canvas: &Canvas, mood: Mood, time: f64) {
    for x in BLUSH_X {
        painter.add(egui::Shape::ellipse_filled(
            canvas.at(x, BLUSH_Y),
            Vec2::new(canvas.len(20.0), canvas.len(11.0)),
            BLUSH_COLOR,
        ));
    }
    match mood {
        Mood::Happy | Mood::Curious => {
            let look = if mood == Mood::Curious {
                (3.0, -5.0)
            } else {
                (0.0, 0.0)
            };
            for x in EYES_X {
                painter.add(egui::Shape::ellipse_filled(
                    canvas.at(x, EYE_Y),
                    Vec2::new(canvas.len(12.0), canvas.len(14.0)),
                    INK,
                ));
                painter.circle_filled(
                    canvas.at(x - 4.0 + look.0, EYE_Y - 6.0 + look.1),
                    canvas.len(4.0),
                    Color32::WHITE,
                );
            }
            if mood == Mood::Happy {
                let mut mouth = quad(
                    (240.0, MOUTH_Y),
                    (248.0, MOUTH_Y + 10.0),
                    (256.0, MOUTH_Y + 1.0),
                );
                mouth.extend(quad(
                    (256.0, MOUTH_Y + 1.0),
                    (264.0, MOUTH_Y + 10.0),
                    (272.0, MOUTH_Y),
                ));
                stroke_points(painter, canvas, &mouth, 6.0);
            } else {
                let mouth = quad(
                    (246.0, MOUTH_Y + 2.0),
                    (256.0, MOUTH_Y + 10.0),
                    (266.0, MOUTH_Y + 2.0),
                );
                stroke_points(painter, canvas, &mouth, 6.0);
            }
        }
        Mood::Excited => {
            for x in EYES_X {
                stroke_points(
                    painter,
                    canvas,
                    &[
                        (x - 12.0, EYE_Y + 6.0),
                        (x, EYE_Y - 7.0),
                        (x + 12.0, EYE_Y + 6.0),
                    ],
                    6.0,
                );
            }
            let mouth = (0..=12)
                .map(|step| {
                    let angle = std::f32::consts::PI * step as f32 / 12.0;
                    canvas.at(
                        256.0 + 12.0 * angle.cos(),
                        MOUTH_Y - 3.0 + 12.0 * angle.sin(),
                    )
                })
                .collect::<Vec<_>>();
            painter.add(egui::Shape::convex_polygon(
                mouth,
                Color32::from_rgb(178, 58, 84),
                Stroke::new(canvas.len(4.0), INK),
            ));
        }
        Mood::Sleepy => {
            for x in EYES_X {
                let lid = quad(
                    (x - 12.0, EYE_Y - 1.0),
                    (x, EYE_Y + 9.0),
                    (x + 12.0, EYE_Y - 1.0),
                );
                stroke_points(painter, canvas, &lid, 5.0);
            }
            painter.add(egui::Shape::ellipse_stroke(
                canvas.at(256.0, MOUTH_Y + 5.0),
                Vec2::new(canvas.len(5.0), canvas.len(6.0)),
                Stroke::new(canvas.len(4.0), INK),
            ));
            // Two lazily drifting z's beside the upper tier.
            let drift = ((time * 0.8).fract() as f32) * 18.0;
            for (index, (x, y, size)) in [(392.0, 214.0, 52.0_f32), (430.0, 160.0, 70.0)]
                .into_iter()
                .enumerate()
            {
                let offset = if index == 0 { drift } else { drift * 0.6 };
                painter.text(
                    canvas.at(x + offset * 0.4, y - offset),
                    egui::Align2::CENTER_CENTER,
                    "z",
                    FontId::proportional(canvas.len(size)),
                    Color32::from_rgb(118, 132, 170),
                );
            }
        }
        Mood::Dizzy => {
            for x in EYES_X {
                stroke_points(
                    painter,
                    canvas,
                    &[(x - 10.0, EYE_Y - 9.0), (x + 10.0, EYE_Y + 9.0)],
                    5.0,
                );
                stroke_points(
                    painter,
                    canvas,
                    &[(x + 10.0, EYE_Y - 9.0), (x - 10.0, EYE_Y + 9.0)],
                    5.0,
                );
            }
            let wave = (0..=16)
                .map(|step| {
                    let t = step as f32 / 16.0;
                    (
                        236.0 + 40.0 * t,
                        MOUTH_Y + 4.0 + 3.5 * (t * std::f32::consts::TAU * 2.0).sin(),
                    )
                })
                .collect::<Vec<_>>();
            stroke_points(painter, canvas, &wave, 4.0);
            let drop = canvas.at(372.0, 284.0);
            let radius = canvas.len(10.0);
            painter.circle_filled(drop, radius, Color32::from_rgb(142, 197, 255));
            painter.add(egui::Shape::convex_polygon(
                vec![
                    drop + Vec2::new(-radius * 0.95, -radius * 0.3),
                    canvas.at(372.0, 262.0),
                    drop + Vec2::new(radius * 0.95, -radius * 0.3),
                ],
                Color32::from_rgb(142, 197, 255),
                Stroke::NONE,
            ));
        }
    }
}

/// Speech bubble beside the mascot.
pub(crate) fn speech_bubble(ui: &mut Ui, text: &str, fill: Color32, color: Color32) -> Response {
    egui::Frame::new()
        .fill(fill)
        .corner_radius(CornerRadius::same(12))
        .inner_margin(egui::Margin::symmetric(10, 6))
        .show(ui, |ui| {
            ui.add(egui::Label::new(egui::RichText::new(text).size(12.5).color(color)).wrap());
        })
        .response
}

/// Width-to-height ratio of the wordmark artwork.
const WORDMARK_UNITS: Vec2 = Vec2::new(735.0, 210.0);

/// Paint the rounded "mochi" wordmark at `height` points; its i-dot is SORA red.
pub(crate) fn wordmark(ui: &mut Ui, height: f32, ink: Color32) -> Response {
    let scale = height / WORDMARK_UNITS.y;
    let (rect, response) = ui.allocate_exact_size(WORDMARK_UNITS * scale, Sense::hover());
    if !ui.is_rect_visible(rect) {
        return response;
    }
    let at = |x: f32, y: f32| Pos2::new(rect.left() + x * scale, rect.top() + (y - 4.0) * scale);
    let width = 28.0 * scale;
    let arc = |center: (f32, f32), radius: f32, from: f32, to: f32| {
        (0..=20)
            .map(|step| {
                let angle = from + (to - from) * step as f32 / 20.0;
                at(
                    center.0 + radius * angle.cos(),
                    center.1 - radius * angle.sin(),
                )
            })
            .collect::<Vec<_>>()
    };
    let pi = std::f32::consts::PI;
    let hx = 570.8;
    let mut strokes: Vec<Vec<Pos2>> = Vec::new();
    for (left, right) in [(14.0, 102.0), (102.0, 190.0)] {
        let mut stroke = vec![at(left, 200.0)];
        stroke.extend(arc(((left + right) / 2.0, 128.0), 44.0, pi, 0.0));
        stroke.push(at(right, 200.0));
        strokes.push(stroke);
    }
    strokes.push(arc((310.0, 142.0), 58.0, 0.0, 2.0 * pi));
    strokes.push(arc(
        (488.0, 142.0),
        58.0,
        48_f32.to_radians(),
        312_f32.to_radians(),
    ));
    strokes.push(vec![at(hx, 18.0), at(hx, 200.0)]);
    let mut shoulder = arc((hx + 44.0, 128.0), 44.0, pi, 0.0);
    shoulder.push(at(hx + 88.0, 200.0));
    strokes.push(shoulder);
    strokes.push(vec![at(720.8, 96.0), at(720.8, 200.0)]);
    let painter = ui.painter();
    for points in strokes {
        if let (Some(first), Some(last)) = (points.first(), points.last()) {
            painter.circle_filled(*first, width / 2.0, ink);
            painter.circle_filled(*last, width / 2.0, ink);
        }
        painter.line(points, Stroke::new(width, ink));
    }
    painter.circle_filled(at(720.8, 40.0), 19.0 * scale, SORA_RED);
    response
}

/// Header lockup: a small happy mascot and the wordmark.
pub(crate) fn lockup(ui: &mut Ui, brand: Option<&Brand>, ink: Color32, mood: Mood) -> Response {
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 6.0;
        mascot(ui, brand, 38.0, mood);
        wordmark(ui, 19.0, ink);
    })
    .response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_artwork_decodes_to_square_textures() {
        let icon = window_icon().expect("bundled window icon decodes");
        assert_eq!((icon.width, icon.height), (512, 512));
        let context = egui::Context::default();
        let brand = Brand::load(&context).expect("bundled mascot layers decode");
        assert_eq!(brand.mascot.size(), [512, 512]);
        assert_eq!(brand.stand.size(), [512, 512]);
    }

    #[test]
    fn mood_follows_lifecycle_phase() {
        assert_eq!(Mood::for_phase(None), Mood::Curious);
        assert_eq!(Mood::for_phase(Some(ManagedPhase::Ready)), Mood::Happy);
        assert_eq!(Mood::for_phase(Some(ManagedPhase::Starting)), Mood::Excited);
        assert_eq!(Mood::for_phase(Some(ManagedPhase::Stopped)), Mood::Sleepy);
        assert_eq!(Mood::for_phase(Some(ManagedPhase::Failed)), Mood::Dizzy);
        for mood in [
            Mood::Curious,
            Mood::Happy,
            Mood::Excited,
            Mood::Sleepy,
            Mood::Dizzy,
        ] {
            assert!(!mood.caption().is_empty());
        }
    }

    #[test]
    fn only_startup_and_pokes_animate_and_pokes_settle() {
        let resting = pose(Mood::Happy, 100.0, 3.0, None);
        assert_eq!(
            resting,
            Pose {
                squash: 1.0,
                lift: 0.0,
                animating: false
            }
        );
        assert!(pose(Mood::Excited, 100.0, 3.25, None).animating);
        assert!(pose(Mood::Excited, 100.0, 3.25, None).lift > 0.0);
        let poked = pose(Mood::Sleepy, 100.0, 3.05, Some(3.0));
        assert!(poked.animating);
        assert!((poked.squash - 1.0).abs() > 0.01);
        let settled = pose(Mood::Sleepy, 100.0, 4.0, Some(3.0));
        assert!(!settled.animating);
        assert!((settled.squash - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn every_mood_paints_inside_its_square() {
        let context = egui::Context::default();
        for mood in [
            Mood::Curious,
            Mood::Happy,
            Mood::Excited,
            Mood::Sleepy,
            Mood::Dizzy,
        ] {
            let mut area = Rect::NOTHING;
            let output = context.run(egui::RawInput::default(), |context| {
                egui::CentralPanel::default().show(context, |ui| {
                    area = mascot(ui, None, 120.0, mood).rect;
                    wordmark(ui, 20.0, INK);
                });
            });
            assert!(!output.shapes.is_empty());
            assert!((area.width() - 120.0).abs() < f32::EPSILON);
        }
    }
}
