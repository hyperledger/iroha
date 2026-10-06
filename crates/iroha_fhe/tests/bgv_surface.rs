//! Source checks of the BGV production surface.
//!
//! Three properties of the scheme cannot be shown by running it and are
//! checked against the source instead:
//!
//! - seeded entry points, explicit-coin entry points, secret-derived probes
//!   and fault injection exist only behind the `bgv-test-fixtures` feature,
//!   and no manifest of the workspace enables that feature outside the
//!   dev-dependencies of this crate;
//! - the production dependencies of this crate are the four it documents, so
//!   no policy, node or SDK crate can be reached from it;
//! - the production path of the scheme uses no floating point and no
//!   reconstruction through `u128`.
use std::{
    fs,
    path::{Path, PathBuf},
};

const FIXTURE_FEATURE: &str = "bgv-test-fixtures";

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn workspace_root() -> PathBuf {
    crate_root()
        .parent()
        .and_then(Path::parent)
        .expect("crates/iroha_fhe lies two levels below the workspace root")
        .to_path_buf()
}

fn read(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

/// Every `Cargo.toml` of the workspace, skipping build output and vendored trees.
fn manifests(root: &Path) -> Vec<PathBuf> {
    const SKIPPED: [&str; 8] = [
        "target",
        "dist",
        "vendor",
        "node_modules",
        ".git",
        ".gradle",
        "build",
        ".build",
    ];
    let mut found = Vec::new();
    let mut pending = vec![(root.to_path_buf(), 0_usize)];
    while let Some((directory, depth)) = pending.pop() {
        let Ok(entries) = fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if path.is_dir() {
                if depth < 5 && !SKIPPED.contains(&name.as_ref()) {
                    pending.push((path, depth + 1));
                }
            } else if name == "Cargo.toml" {
                found.push(path);
            }
        }
    }
    found.sort();
    found
}

/// The body of one TOML table of a manifest, up to the next table header.
fn table<'a>(manifest: &'a str, header: &str) -> &'a str {
    let Some(start) = manifest.find(&format!("\n{header}\n")) else {
        return "";
    };
    let body = &manifest[start + header.len() + 2..];
    body.find("\n[").map_or(body, |end| &body[..end])
}

fn bgv_sources() -> Vec<(String, String)> {
    let directory = crate_root().join("src/bgv");
    let mut sources: Vec<(String, String)> = fs::read_dir(&directory)
        .expect("src/bgv")
        .flatten()
        .map(|entry| {
            (
                entry.file_name().to_string_lossy().into_owned(),
                read(&entry.path()),
            )
        })
        .collect();
    sources.sort();
    assert!(sources.len() >= 12, "src/bgv lost files: {}", sources.len());
    sources
}

/// The part of a source file before its inline test module.
fn production_part(source: &str) -> &str {
    source
        .find("\n#[cfg(test)]\nmod tests")
        .or_else(|| source.find("\n#[cfg(test)]\npub(super) mod tests"))
        .map_or(source, |end| &source[..end])
}

#[test]
fn only_this_crate_enables_the_fixture_feature_and_only_for_its_tests() {
    let root = workspace_root();
    let own = crate_root().join("Cargo.toml");
    let all = manifests(&root);
    assert!(
        all.len() > 50,
        "the workspace walk found only {} manifests",
        all.len()
    );
    assert!(all.contains(&own));
    for manifest in &all {
        let text = read(manifest);
        if manifest == &own {
            // Declared as a feature and enabled from the dev-dependencies, nowhere else.
            assert!(table(&text, "[features]").contains(&format!("{FIXTURE_FEATURE} = []")));
            assert!(table(&text, "[dev-dependencies]").contains(FIXTURE_FEATURE));
            assert!(!table(&text, "[dependencies]").contains(FIXTURE_FEATURE));
            let default_line = table(&text, "[features]")
                .lines()
                .find(|line| line.starts_with("default ="))
                .expect("default features");
            assert!(!default_line.contains(FIXTURE_FEATURE));
            // Once as the feature declaration and once in the dev-dependency.
            assert_eq!(
                text.matches(FIXTURE_FEATURE).count(),
                2,
                "{}",
                manifest.display()
            );
        } else {
            assert!(
                !text.contains(FIXTURE_FEATURE),
                "{} names the test-only feature",
                manifest.display()
            );
        }
    }
}

#[test]
fn production_dependencies_are_the_documented_four() {
    let text = read(&crate_root().join("Cargo.toml"));
    let mut names: Vec<&str> = table(&text, "[dependencies]")
        .lines()
        .filter(|line| !line.trim_start().starts_with('#') && line.contains('='))
        .filter_map(|line| line.split('=').next())
        .map(str::trim)
        .collect();
    names.sort_unstable();
    assert_eq!(names, ["blake3", "getrandom", "thiserror", "zeroize"]);
    // No target-specific or build dependency table adds another production edge.
    assert!(!text.contains("[target."));
    assert!(!text.contains("[build-dependencies]"));
}

#[test]
fn seeded_and_explicit_coin_entry_points_are_not_public_outside_the_fixtures() {
    let sources = bgv_sources();
    let module = &sources
        .iter()
        .find(|(name, _)| name == "mod.rs")
        .expect("mod.rs")
        .1;
    // The fixture module is compiled only for tests or with the fixture feature.
    assert!(
        module.contains("#[cfg(any(test, feature = \"bgv-test-fixtures\"))]\npub mod fixtures;")
    );
    assert_eq!(module.matches("mod fixtures;").count(), 1);
    for (name, source) in &sources {
        let production = production_part(source);
        if name == "fixtures.rs" {
            continue;
        }
        for line in production.lines() {
            let trimmed = line.trim_start();
            let Some(rest) = trimmed
                .strip_prefix("pub fn ")
                .or_else(|| trimmed.strip_prefix("pub const fn "))
            else {
                continue;
            };
            let function = rest.split(['(', '<']).next().unwrap_or("");
            // Entry points that take an entropy source, a seed or coins stay inside the module.
            for suffix in ["_with", "_from_coins", "from_coins", "from_coefficients"] {
                assert!(
                    !function.ends_with(suffix),
                    "{name}: `{function}` takes caller-chosen coins and must not be public"
                );
            }
            if name == "fault.rs" {
                // `arm` and `disarm` are public only under the fixture configuration.
                assert!(matches!(function, "arm" | "disarm"), "{name}: {function}");
            }
        }
        // No production signature mentions a seed or the fixture entropy.
        assert!(
            !production.contains("FixtureEntropy"),
            "{name} names the fixture entropy"
        );
    }
    let fault = &sources
        .iter()
        .find(|(name, _)| name == "fault.rs")
        .expect("fault.rs")
        .1;
    for function in ["pub fn arm(", "pub fn disarm("] {
        let position = fault.find(function).expect("fault hook");
        assert!(
            fault[..position].ends_with("#[cfg(any(test, feature = \"bgv-test-fixtures\"))]\n"),
            "{function} is not gated"
        );
    }
    // The only entropy the public generators use is the operating system's.
    let coins = &sources
        .iter()
        .find(|(name, _)| name == "coins.rs")
        .expect("coins.rs")
        .1;
    assert!(production_part(coins).contains("getrandom::fill(seed)"));
    assert!(production_part(coins).contains("pub(super) trait EntropySource"));
}

#[test]
fn the_production_path_uses_no_floating_point_and_no_u128_reconstruction() {
    let mut sources = bgv_sources();
    for name in ["natural.rs", "ntt_plan.rs", "rns_chain.rs"] {
        sources.push((name.to_owned(), read(&crate_root().join("src").join(name))));
    }
    for (name, source) in &sources {
        let production = production_part(source);
        for forbidden in ["f32", "f64", ".powf(", ".sqrt(", ".ln(", ".log2("] {
            assert!(
                !production
                    .lines()
                    .filter(|line| !line.trim_start().starts_with("//"))
                    .any(|line| line.contains(forbidden)),
                "{name}: floating point `{forbidden}` in production code"
            );
        }
        // The retained 128-bit reconstruction helpers are not used by the new path.
        for retained in [
            "rns::reconstruct",
            "reconstruct_coefficient",
            "reconstruct_polynomial",
            "basis_extend_target_limbs",
            "checked_modulus_product",
            "garner_reconstruct_u128",
        ] {
            assert!(
                !production.contains(retained),
                "{name}: `{retained}` reconstructs through u128"
            );
        }
    }
}
