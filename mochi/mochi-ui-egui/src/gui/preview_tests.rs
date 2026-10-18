//! Design previews rendered headlessly from the real desktop state machine.
//!
//! The harness runs the genuine Quickstart against real validators (dispatch, working state and
//! its exact outcome), then renders every running-network view on that real generation with
//! staged phases and fixture observations, and rasterizes egui's output in software. Signed
//! previews and validator logs are genuine; balances, blocks and activity are presentation
//! fixtures and assert nothing about ledger state. It needs matching `kagami` and `iroha3d`:
//!
//! ```sh
//! MOCHI_PREVIEW_RUNTIME=target/release MOCHI_PREVIEW_OUT=/tmp/mochi-previews \
//!   cargo test -p mochi-ui --features gui --bin mochi design_previews -- --ignored --nocapture
//! ```
//!
//! Each view is written as a binary PPM image; the generation is stopped afterwards.

use super::*;
use eframe::egui::{Color32, ColorImage, Pos2, Rect, TextureId, Theme, Vec2, epaint::Primitive};
use iroha_deploy::managed::InstalledRuntime;
use std::{collections::HashMap, io::Write as _, path::Path};

/// Software rasterizer for egui meshes, matching the premultiplied gamma-space blending of
/// the native renderer closely enough for design review.
struct Renderer {
    context: egui::Context,
    textures: HashMap<TextureId, ColorImage>,
    size: Vec2,
    pixels_per_point: f32,
    time: f64,
}

impl Renderer {
    fn new(theme: Theme) -> Self {
        let context = egui::Context::default();
        theme::install(&context);
        theme::install_fonts(&context);
        context.set_theme(theme);
        Self {
            context,
            textures: HashMap::new(),
            size: Vec2::new(1280.0, 840.0),
            pixels_per_point: 2.0,
            time: 100.0,
        }
    }

    fn frame(&mut self, desktop: &mut Desktop) -> egui::FullOutput {
        self.time += 0.1;
        let mut input = egui::RawInput {
            screen_rect: Some(Rect::from_min_size(Pos2::ZERO, self.size)),
            time: Some(self.time),
            ..Default::default()
        };
        input
            .viewports
            .entry(egui::ViewportId::ROOT)
            .or_default()
            .native_pixels_per_point = Some(self.pixels_per_point);
        let output = self.context.run(input, |context| desktop.show(context));
        for (id, delta) in &output.textures_delta.set {
            let egui::ImageData::Color(image) = &delta.image;
            match delta.pos {
                None => {
                    self.textures.insert(*id, (**image).clone());
                }
                Some([x, y]) => {
                    let target = self.textures.get_mut(id).expect("patched texture exists");
                    for row in 0..image.size[1] {
                        for column in 0..image.size[0] {
                            target.pixels[(y + row) * target.size[0] + x + column] =
                                image.pixels[row * image.size[0] + column];
                        }
                    }
                }
            }
        }
        for id in &output.textures_delta.free {
            self.textures.remove(id);
        }
        output
    }

    /// Render a few frames so layout settles, then write the last one.
    fn capture(&mut self, desktop: &mut Desktop, path: &Path) {
        for _ in 0..3 {
            let _ = self.frame(desktop);
        }
        let output = self.frame(desktop);
        let primitives = self
            .context
            .tessellate(output.shapes, output.pixels_per_point);
        let width = (self.size.x * self.pixels_per_point) as usize;
        let height = (self.size.y * self.pixels_per_point) as usize;
        let mut pixels = vec![[0.0_f32; 4]; width * height];
        for primitive in &primitives {
            let Primitive::Mesh(mesh) = &primitive.primitive else {
                continue;
            };
            let clip = Rect::from_min_max(
                (primitive.clip_rect.min.to_vec2() * output.pixels_per_point).to_pos2(),
                (primitive.clip_rect.max.to_vec2() * output.pixels_per_point).to_pos2(),
            );
            let texture = self.textures.get(&mesh.texture_id);
            for triangle in mesh.indices.chunks_exact(3) {
                let vertices = [
                    &mesh.vertices[triangle[0] as usize],
                    &mesh.vertices[triangle[1] as usize],
                    &mesh.vertices[triangle[2] as usize],
                ];
                rasterize(
                    &mut pixels,
                    width,
                    height,
                    clip,
                    output.pixels_per_point,
                    vertices,
                    texture,
                );
            }
        }
        let mut file = std::fs::File::create(path).unwrap();
        write!(file, "P6\n{width} {height}\n255\n").unwrap();
        let bytes = pixels
            .iter()
            .flat_map(|pixel| {
                [0, 1, 2].map(|channel| (pixel[channel].clamp(0.0, 1.0) * 255.0).round() as u8)
            })
            .collect::<Vec<_>>();
        file.write_all(&bytes).unwrap();
        eprintln!("wrote {}", path.display());
    }
}

fn premultiplied(color: Color32) -> [f32; 4] {
    color.to_array().map(|channel| f32::from(channel) / 255.0)
}

fn sample(texture: &ColorImage, uv: Pos2) -> [f32; 4] {
    let [width, height] = texture.size;
    let x = (uv.x * width as f32 - 0.5).clamp(0.0, (width - 1) as f32);
    let y = (uv.y * height as f32 - 0.5).clamp(0.0, (height - 1) as f32);
    let (x0, y0) = (x.floor() as usize, y.floor() as usize);
    let (x1, y1) = ((x0 + 1).min(width - 1), (y0 + 1).min(height - 1));
    let (fx, fy) = (x - x0 as f32, y - y0 as f32);
    let at = |x: usize, y: usize| premultiplied(texture.pixels[y * width + x]);
    let (a, b, c, d) = (at(x0, y0), at(x1, y0), at(x0, y1), at(x1, y1));
    std::array::from_fn(|channel| {
        let top = a[channel] + (b[channel] - a[channel]) * fx;
        let bottom = c[channel] + (d[channel] - c[channel]) * fx;
        top + (bottom - top) * fy
    })
}

fn rasterize(
    pixels: &mut [[f32; 4]],
    width: usize,
    height: usize,
    clip: Rect,
    scale: f32,
    vertices: [&egui::epaint::Vertex; 3],
    texture: Option<&ColorImage>,
) {
    let points = vertices.map(|vertex| vertex.pos.to_vec2() * scale);
    let edge = |a: Vec2, b: Vec2, c: Vec2| (c.x - a.x) * (b.y - a.y) - (c.y - a.y) * (b.x - a.x);
    let area = edge(points[0], points[1], points[2]);
    if area.abs() < f32::EPSILON {
        return;
    }
    let min_x = points
        .iter()
        .map(|p| p.x)
        .fold(f32::INFINITY, f32::min)
        .max(clip.min.x)
        .max(0.0);
    let max_x = points
        .iter()
        .map(|p| p.x)
        .fold(f32::NEG_INFINITY, f32::max)
        .min(clip.max.x)
        .min(width as f32);
    let min_y = points
        .iter()
        .map(|p| p.y)
        .fold(f32::INFINITY, f32::min)
        .max(clip.min.y)
        .max(0.0);
    let max_y = points
        .iter()
        .map(|p| p.y)
        .fold(f32::NEG_INFINITY, f32::max)
        .min(clip.max.y)
        .min(height as f32);
    if min_x >= max_x || min_y >= max_y {
        return;
    }
    let colors = vertices.map(|vertex| premultiplied(vertex.color));
    for y in (min_y.floor() as usize)..(max_y.ceil() as usize).min(height) {
        for x in (min_x.floor() as usize)..(max_x.ceil() as usize).min(width) {
            let center = Vec2::new(x as f32 + 0.5, y as f32 + 0.5);
            if center.x < clip.min.x
                || center.x >= clip.max.x
                || center.y < clip.min.y
                || center.y >= clip.max.y
            {
                continue;
            }
            let weights = [
                edge(points[1], points[2], center) / area,
                edge(points[2], points[0], center) / area,
                edge(points[0], points[1], center) / area,
            ];
            if weights.iter().any(|weight| *weight < -1e-4) {
                continue;
            }
            let mut source: [f32; 4] = std::array::from_fn(|channel| {
                (0..3)
                    .map(|index| colors[index][channel] * weights[index])
                    .sum()
            });
            if let Some(texture) = texture {
                let uv = (0..3).fold(Vec2::ZERO, |sum, index| {
                    sum + vertices[index].uv.to_vec2() * weights[index]
                });
                let texel = sample(texture, uv.to_pos2());
                for channel in 0..4 {
                    source[channel] *= texel[channel];
                }
            }
            let target = &mut pixels[y * width + x];
            for channel in 0..4 {
                target[channel] = source[channel] + target[channel] * (1.0 - source[3]);
            }
        }
    }
}

fn wait_until(
    desktop: &mut Desktop,
    timeout: Duration,
    mut done: impl FnMut(&Desktop) -> bool,
) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        desktop.poll();
        if done(desktop) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

/// Stops the genuine validators even when an assertion fails midway.
struct StopOnDrop(Option<(DeveloperWorkspace, ManagedNetwork)>);

impl Drop for StopOnDrop {
    fn drop(&mut self) {
        if let Some((workspace, network)) = self.0.take() {
            let _ = workspace.stop(&network);
        }
    }
}

fn entry(
    title: &str,
    subtitle: &str,
    detail: &str,
    owner: Option<&str>,
    definition: Option<&str>,
    json: Option<String>,
) -> mochi_core::StateEntry {
    mochi_core::StateEntry {
        title: title.into(),
        subtitle: subtitle.into(),
        detail: detail.into(),
        raw: String::new(),
        domain: None,
        domain_lower: None,
        owner: owner.map(Into::into),
        owner_lower: owner.map(str::to_lowercase),
        asset_definition: definition.map(Into::into),
        asset_definition_lower: definition.map(str::to_lowercase),
        json,
        norito_bytes: None,
        search_blob: title.to_lowercase(),
    }
}

fn page(kind: StateQueryKind, entries: Vec<mochi_core::StateEntry>) -> StatePage {
    StatePage {
        kind,
        entries,
        remaining: 0,
        cursor: None,
    }
}

/// Presentation data for the running-network views, shaped like genuine observations and
/// built on the real generation's identities. It is never submitted or claimed as ledger state.
fn fixture_observations(desktop: &mut Desktop, network: &ManagedNetwork) {
    let discriminant = network.address_discriminant();
    let _guard = iroha_data_model::account::address::ChainDiscriminantGuard::enter(discriminant);
    let developer = network.prepared().context.account_id.clone();
    let definition = |seed: u8| {
        let mut bytes = [seed; 16];
        bytes[6] = (bytes[6] & 0x0f) | 0x40;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        iroha_data_model::asset::id::AssetDefinitionId::from_uuid_bytes(bytes)
            .unwrap()
            .to_string()
    };
    let (xor, matcha) = (definition(7), definition(42));
    let friends = (0..3)
        .map(|_| mochi_core::GeneratedAccount::generate().account_literal(discriminant))
        .collect::<Vec<_>>();
    let accounts = std::iter::once(developer.clone())
        .chain(friends.iter().cloned())
        .map(|account| {
            let json = format!("{{\n  \"id\": \"{account}\",\n  \"metadata\": {{}}\n}}");
            entry(
                &account,
                "Signatory ed0120…",
                "No metadata",
                None,
                None,
                Some(json),
            )
        })
        .collect::<Vec<_>>();
    let holding = |definition: &str, owner: &str, value: &str| {
        let asset = mochi_core::asset_literal(definition, owner, discriminant).unwrap();
        entry(
            &asset,
            &format!("Owner {owner}"),
            &format!("Value {value}"),
            Some(owner),
            Some(definition),
            None,
        )
    };
    let holdings = vec![
        holding(&xor, &developer, "999750"),
        holding(&matcha, &developer, "5000"),
        holding(&xor, &friends[0], "250"),
        holding(&xor, &friends[1], "75.5"),
        holding(&matcha, &friends[1], "12"),
    ];
    let definitions = [(&xor, "XOR"), (&matcha, "MATCHA")]
        .into_iter()
        .map(|(id, name)| {
            let json = format!("{{\"id\": \"{id}\", \"name\": \"{name}\"}}");
            entry(id, "Owner genesis", "Numeric", None, Some(id), Some(json))
        })
        .collect::<Vec<_>>();
    desktop.ledger = Some(accounts::LedgerSnapshot::new(
        page(StateQueryKind::Accounts, accounts.clone()),
        page(StateQueryKind::Assets, holdings),
        &page(StateQueryKind::AssetDefinitions, definitions),
    ));
    desktop.page = Some(page(StateQueryKind::Accounts, accounts));
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    for height in 1..=14_u64 {
        let hash = format!(
            "{:064x}",
            u128::from(height) * 0x9e37_79b9_7f4a_7c15_f39c_c060_5ced_c834
        );
        let summary = mochi_core::BlockSummary {
            height,
            hash_hex: hash,
            transaction_count: if height == 1 {
                6
            } else {
                1 + (height as usize % 3)
            },
            rejected_transaction_count: usize::from(height == 9),
            time_trigger_count: 0,
            signature_count: 4,
            view_change_index: 0,
            creation_time_ms: now - (14 - height) * 41_000,
            is_genesis: height == 1,
        };
        ledger::record_block(
            &mut desktop.blocks_feed,
            &summary,
            1200 + height as usize * 37,
        );
        push_activity(
            &mut desktop.activity,
            format!(
                "Block #{} · {} transactions · {} rejected · {} bytes · {}",
                summary.height,
                summary.transaction_count,
                summary.rejected_transaction_count,
                1200 + height * 37,
                summary.hash_hex
            ),
        );
        if height % 4 == 0 {
            push_activity(
                &mut desktop.activity,
                format!("Pipeline · Transaction Approved · 412 bytes · block {height}"),
            );
            push_activity(
                &mut desktop.activity,
                format!("Data · Asset Added · 198 bytes · 250 of {xor}"),
            );
        }
    }
    push_activity(
        &mut desktop.activity,
        "Data · Account Created · 233 bytes · new developer test account".into(),
    );
    desktop.latest_height = Some(14);
}

#[test]
#[ignore = "starts genuine validators; set MOCHI_PREVIEW_RUNTIME and MOCHI_PREVIEW_OUT"]
fn design_previews_with_a_real_generation() {
    let Some(runtime) = std::env::var_os("MOCHI_PREVIEW_RUNTIME") else {
        eprintln!("MOCHI_PREVIEW_RUNTIME is unset; nothing rendered");
        return;
    };
    let out = PathBuf::from(std::env::var_os("MOCHI_PREVIEW_OUT").expect("MOCHI_PREVIEW_OUT"));
    std::fs::create_dir_all(&out).unwrap();
    let temporary = tempfile::tempdir().unwrap();
    let project = temporary.path().join("coffee-shop");
    std::fs::create_dir(&project).unwrap();
    std::fs::write(
        project.join("coffee.ko"),
        "seiyaku Coffee { view fn quote(int cups) authorize(anyone) -> int { return cups * 10; } }",
    )
    .unwrap();
    let workspace = DeveloperWorkspace::with_runtime(
        &temporary.path().join("state"),
        &project,
        InstalledRuntime::from_directory(Path::new(&runtime)).unwrap(),
    )
    .unwrap();
    let mut desktop = Desktop::model(project.clone());
    desktop.install_opened(inspect_workspace(workspace.clone()).unwrap());
    let mut light = Renderer::new(Theme::Light);
    desktop.brand = brand::Brand::load(&light.context);
    light.capture(&mut desktop, &out.join("01-welcome.ppm"));

    // The genuine Quickstart: dispatch, working state and its exact outcome.
    desktop.quickstart();
    assert!(desktop.busy, "Quickstart dispatched");
    light.capture(&mut desktop, &out.join("02-quickstart-working.ppm"));
    assert!(
        wait_until(&mut desktop, Duration::from_secs(120), |desktop| !desktop
            .busy),
        "localnet creation finished"
    );
    light.capture(&mut desktop, &out.join("03-quickstart-outcome.ppm"));
    let network = workspace.network(Some("local")).unwrap();
    let _stop = StopOnDrop(Some((workspace.clone(), network.clone())));
    let failure = desktop.error.take();

    // Running-network views on the real generation, with staged phases and fixture
    // observations. Automatic observation and streams are paused so nothing replaces them.
    let stage = |desktop: &mut Desktop, phase, failure: Option<String>| {
        desktop.install_selection(Selection {
            network: network.clone(),
            phase,
            running: if phase == ManagedPhase::Ready { 4 } else { 0 },
            failure,
            attachment: Ok(None),
        });
        desktop.blocks = None;
        desktop.events = None;
        desktop.last_poll = Instant::now() + Duration::from_secs(3600);
        desktop.last_ledger_refresh = Instant::now() + Duration::from_secs(3600);
    };
    stage(&mut desktop, ManagedPhase::Starting, None);
    light.capture(&mut desktop, &out.join("04-home-starting.ppm"));
    stage(&mut desktop, ManagedPhase::Ready, None);
    fixture_observations(&mut desktop, &network);
    light.capture(&mut desktop, &out.join("05-home.ppm"));
    desktop.view = View::Accounts;
    light.capture(&mut desktop, &out.join("06-accounts.ppm"));
    let developer = network.prepared().context.account_id.clone();
    let funding = desktop.ledger.as_ref().unwrap().holdings_of(&developer)[0]
        .asset
        .to_owned();
    desktop.quick.kind = accounts::QuickKind::NewAccount;
    desktop.quick.asset = funding;
    desktop.quick.fund = "250".into();
    desktop.quick.generated = Some(mochi_core::GeneratedAccount::generate());
    desktop.review_quick_action();
    assert!(desktop.error.is_none(), "{:?}", desktop.error);
    assert!(desktop.preview.is_some(), "a genuine signed preview");
    light.capture(&mut desktop, &out.join("07-accounts-review.ppm"));
    desktop.view = View::Blocks;
    light.capture(&mut desktop, &out.join("08-blocks.ppm"));
    desktop.view = View::Activity;
    light.capture(&mut desktop, &out.join("09-activity.ppm"));
    desktop.view = View::Endpoints;
    light.capture(&mut desktop, &out.join("10-endpoints.ppm"));
    // Long pages once more at full height so their lower sections are reviewed too.
    light.size.y = 1500.0;
    light.capture(&mut desktop, &out.join("10b-endpoints-full.ppm"));
    desktop.view = View::Accounts;
    light.capture(&mut desktop, &out.join("07b-accounts-full.ppm"));
    light.size.y = 840.0;
    desktop.view = View::State;
    light.capture(&mut desktop, &out.join("11-state.ppm"));
    desktop.view = View::Composer;
    light.capture(&mut desktop, &out.join("12-transactions.ppm"));
    desktop.view = View::Contracts;
    desktop.contract_path = "coffee.ko".into();
    desktop.receipt = None;
    light.capture(&mut desktop, &out.join("13-contracts.ppm"));
    desktop.view = View::Logs;
    desktop.logs_source = Some(0);
    desktop.read_logs();
    assert!(wait_until(
        &mut desktop,
        Duration::from_secs(30),
        |desktop| !desktop.busy
    ));
    light.capture(&mut desktop, &out.join("14-logs.ppm"));

    let mut dark = Renderer::new(Theme::Dark);
    desktop.brand = brand::Brand::load(&dark.context);
    desktop.view = View::Home;
    dark.capture(&mut desktop, &out.join("15-home-dark.ppm"));
    desktop.view = View::Accounts;
    dark.capture(&mut desktop, &out.join("16-accounts-dark.ppm"));
    desktop.view = View::Endpoints;
    dark.capture(&mut desktop, &out.join("17-endpoints-dark.ppm"));

    desktop.brand = brand::Brand::load(&light.context);
    desktop.view = View::Home;
    stage(&mut desktop, ManagedPhase::Stopped, None);
    light.capture(&mut desktop, &out.join("18-home-stopped.ppm"));
    stage(&mut desktop, ManagedPhase::Failed, failure);
    light.capture(&mut desktop, &out.join("19-home-failed.ppm"));
}
