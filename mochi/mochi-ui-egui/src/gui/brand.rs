//! Mochi brand marks: the window icon, the mascot and the wordmark.
//!
//! The mascot artwork (`mochi/assets/mochi-mascot.svg`) combines the Hyperledger Iroha sakura
//! and the SORA seal on a mochi. Its face is painted here so it can follow network state.

use eframe::egui::{
    self, Color32, ColorImage, CornerRadius, FontId, Pos2, Rect, Response, Sense, Stroke,
    TextureFilter, TextureHandle, TextureOptions, Ui, Vec2,
};
use mochi_core::developer::ManagedPhase;
use std::time::Duration;

const ICON_PNG: &[u8] = include_bytes!("../../../assets/mochi-icon-512.png");
const MASCOT_PNG: &[u8] = include_bytes!("../../../assets/mochi-mascot-512.png");

/// Ink used for the face and wordmark on light surfaces.
const INK: Color32 = Color32::from_rgb(46, 34, 48);
/// SORA red, used for the wordmark's i-dot.
pub(crate) const SORA_RED: Color32 = Color32::from_rgb(227, 36, 45);
const BLUSH: Color32 = Color32::from_rgba_premultiplied(153, 86, 103, 153);

/// The window and dock icon decoded from the bundled artwork.
pub(crate) fn window_icon() -> Option<egui::IconData> {
    eframe::icon_data::from_png_bytes(ICON_PNG).ok()
}

/// GPU texture of the face-less mascot, uploaded once per context.
pub(crate) struct Brand {
    mascot: TextureHandle,
}

impl Brand {
    pub(crate) fn load(context: &egui::Context) -> Option<Self> {
        let decoded = eframe::icon_data::from_png_bytes(MASCOT_PNG).ok()?;
        let size = [
            usize::try_from(decoded.width).ok()?,
            usize::try_from(decoded.height).ok()?,
        ];
        let image = ColorImage::from_rgba_unmultiplied(size, &decoded.rgba);
        Some(Self {
            mascot: context.load_texture(
                "mochi-mascot",
                image,
                TextureOptions::LINEAR.with_mipmap_mode(Some(TextureFilter::Linear)),
            ),
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
        pose.lift = height * size * 0.07;
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

/// Maps artwork units (a 512 square, feet at y = 470) into the posed screen rectangle.
struct Canvas {
    anchor: Pos2,
    x_scale: f32,
    y_scale: f32,
}

impl Canvas {
    fn new(rect: Rect, pose: Pose) -> Self {
        let unit = rect.width() / 512.0;
        Self {
            anchor: Pos2::new(rect.center().x, rect.top() + 470.0 * unit - pose.lift),
            x_scale: unit * pose.squash,
            y_scale: unit / pose.squash,
        }
    }

    fn at(&self, x: f32, y: f32) -> Pos2 {
        Pos2::new(
            self.anchor.x + (x - 256.0) * self.x_scale,
            self.anchor.y + (y - 470.0) * self.y_scale,
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
    // Ground shadow stays on the floor while the body bounces.
    let unit = rect.width() / 512.0;
    let shadow_width = 170.0 * unit * (1.0 - pose.lift / rect.width() * 2.0);
    painter.add(egui::Shape::ellipse_filled(
        Pos2::new(rect.center().x, rect.top() + 474.0 * unit),
        Vec2::new(shadow_width, 14.0 * unit),
        Color32::from_black_alpha(28),
    ));
    let tint = if mood == Mood::Sleepy {
        Color32::from_rgb(232, 232, 240)
    } else {
        Color32::WHITE
    };
    match brand {
        Some(brand) => {
            painter.image(
                brand.mascot.id(),
                canvas.image_rect(),
                Rect::from_min_max(Pos2::ZERO, Pos2::new(1.0, 1.0)),
                tint,
            );
        }
        None => {
            // Without the texture (headless rendering), keep a recognizable soft body.
            painter.add(egui::Shape::ellipse_filled(
                canvas.at(256.0, 340.0),
                Vec2::new(canvas.len(206.0), canvas.len(130.0)),
                Color32::from_rgb(255, 247, 239),
            ));
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
    let eyes = [196.0_f32, 316.0];
    for x in [160.0, 352.0] {
        painter.add(egui::Shape::ellipse_filled(
            canvas.at(x, 384.0),
            Vec2::new(canvas.len(24.0), canvas.len(13.0)),
            BLUSH,
        ));
    }
    match mood {
        Mood::Happy | Mood::Curious => {
            let look = if mood == Mood::Curious {
                (4.0, -6.0)
            } else {
                (0.0, 0.0)
            };
            for x in eyes {
                painter.add(egui::Shape::ellipse_filled(
                    canvas.at(x, 350.0),
                    Vec2::new(canvas.len(14.0), canvas.len(17.0)),
                    INK,
                ));
                painter.circle_filled(
                    canvas.at(x - 5.0 + look.0, 343.0 + look.1),
                    canvas.len(5.0),
                    Color32::WHITE,
                );
            }
            if mood == Mood::Happy {
                let mut mouth = quad((234.0, 376.0), (245.0, 389.0), (256.0, 377.0));
                mouth.extend(quad((256.0, 377.0), (267.0, 389.0), (278.0, 376.0)));
                stroke_points(painter, canvas, &mouth, 7.0);
            } else {
                let mouth = quad((244.0, 378.0), (256.0, 388.0), (268.0, 378.0));
                stroke_points(painter, canvas, &mouth, 7.0);
            }
        }
        Mood::Excited => {
            for x in eyes {
                stroke_points(
                    painter,
                    canvas,
                    &[(x - 14.0, 357.0), (x, 342.0), (x + 14.0, 357.0)],
                    7.0,
                );
            }
            let mouth = (0..=12)
                .map(|step| {
                    let angle = std::f32::consts::PI * step as f32 / 12.0;
                    canvas.at(256.0 + 15.0 * angle.cos(), 372.0 + 14.0 * angle.sin())
                })
                .collect::<Vec<_>>();
            painter.add(egui::Shape::convex_polygon(
                mouth,
                Color32::from_rgb(178, 58, 84),
                Stroke::new(canvas.len(5.0), INK),
            ));
        }
        Mood::Sleepy => {
            for x in eyes {
                let lid = quad((x - 14.0, 349.0), (x, 360.0), (x + 14.0, 349.0));
                stroke_points(painter, canvas, &lid, 6.0);
            }
            painter.add(egui::Shape::ellipse_stroke(
                canvas.at(256.0, 381.0),
                Vec2::new(canvas.len(6.0), canvas.len(7.0)),
                Stroke::new(canvas.len(5.0), INK),
            ));
            // Two lazily drifting z's.
            let drift = ((time * 0.8).fract() as f32) * 18.0;
            for (index, (x, y, size)) in [(386.0, 250.0, 58.0_f32), (432.0, 190.0, 78.0)]
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
            for x in eyes {
                stroke_points(
                    painter,
                    canvas,
                    &[(x - 11.0, 339.0), (x + 11.0, 361.0)],
                    6.0,
                );
                stroke_points(
                    painter,
                    canvas,
                    &[(x + 11.0, 339.0), (x - 11.0, 361.0)],
                    6.0,
                );
            }
            let wave = (0..=16)
                .map(|step| {
                    let t = step as f32 / 16.0;
                    (
                        232.0 + 48.0 * t,
                        381.0 + 4.0 * (t * std::f32::consts::TAU * 2.0).sin(),
                    )
                })
                .collect::<Vec<_>>();
            stroke_points(painter, canvas, &wave, 5.0);
            let drop = canvas.at(392.0, 276.0);
            let radius = canvas.len(11.0);
            painter.circle_filled(drop, radius, Color32::from_rgb(142, 197, 255));
            painter.add(egui::Shape::convex_polygon(
                vec![
                    drop + Vec2::new(-radius * 0.95, -radius * 0.3),
                    canvas.at(392.0, 252.0),
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
        let brand = Brand::load(&context).expect("bundled mascot decodes");
        assert_eq!(brand.mascot.size(), [512, 512]);
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
