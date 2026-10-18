//! Connection details for the selected environment: endpoints, identities and terminal snippets.
//!
//! Everything shown here is public metadata from the managed context. Generated keys, API tokens
//! and owner-private configuration paths are never rendered.

use super::{
    Desktop,
    widgets::{self, icon},
};
use eframe::egui::{self, RichText, Ui};

/// One Torii route worth handing to tests, SDKs or agents.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Route {
    pub(crate) label: &'static str,
    pub(crate) path: &'static str,
    pub(crate) detail: &'static str,
}

/// Routes served by every managed validator. Diagnostics are unauthenticated on ordinary
/// localnets; private dataspace roots require their generated API token on every route.
pub(crate) const ROUTES: &[Route] = &[
    Route {
        label: "Torii API",
        path: "",
        detail: "Base URL for SDK clients and the iroha CLI",
    },
    Route {
        label: "Health",
        path: "health",
        detail: "Liveness probe for test harnesses",
    },
    Route {
        label: "Status",
        path: "status",
        detail: "Block height, peers and queue telemetry",
    },
    Route {
        label: "Metrics",
        path: "metrics",
        detail: "Prometheus exposition",
    },
    Route {
        label: "OpenAPI",
        path: "openapi.json",
        detail: "Machine-readable API description",
    },
    Route {
        label: "MCP",
        path: "v1/mcp",
        detail: "Model Context Protocol endpoint for AI agents",
    },
];

/// Join a Torii base URL and a relative route without doubling slashes.
pub(crate) fn route_url(base: &str, path: &str) -> String {
    let base = base.trim_end_matches('/');
    if path.is_empty() {
        format!("{base}/")
    } else {
        format!("{base}/{path}")
    }
}

/// Quote one POSIX shell argument only when it needs quoting.
pub(crate) fn shell_arg(value: &str) -> String {
    let plain = !value.is_empty()
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "._/:@%+=,-".contains(character));
    if plain {
        value.to_owned()
    } else {
        format!("'{}'", value.replace('\'', r"'\''"))
    }
}

/// Copyable terminal commands for the exact environment, sharing Kagami's workspace store.
///
/// A workspace path that is not valid Unicode is omitted rather than rewritten lossily; the
/// commands then rely on Kagami's default of the current directory.
pub(crate) fn terminal_snippets(
    name: &str,
    workspace: Option<&str>,
    torii: &str,
    peer: usize,
) -> Vec<(&'static str, String)> {
    let name = shell_arg(name);
    let workspace = workspace
        .map(|path| format!(" --workspace {}", shell_arg(path)))
        .unwrap_or_default();
    vec![
        (
            "Probe the observed validator",
            format!("curl -s {}", shell_arg(&route_url(torii, "status"))),
        ),
        (
            "Show this environment",
            format!("kagami localnet status {name}{workspace}"),
        ),
        (
            "Read validator logs",
            format!("kagami localnet logs {name}{workspace} --peer {peer}"),
        ),
        (
            "Deploy a contract from the terminal",
            format!("kagami contract deploy path/to/contract.ko --context {name}{workspace}"),
        ),
        (
            "Stop the validators (state is kept)",
            format!("kagami localnet down {name}{workspace}"),
        ),
    ]
}

impl Desktop {
    pub(super) fn endpoints(&mut self, ui: &mut Ui) {
        widgets::page_title(
            ui,
            "Endpoints",
            "Point tests, SDKs, CLIs and AI agents at this environment. Click any value to copy it.",
        );
        let Some(selected) = &self.selected else {
            widgets::card(ui, |ui| {
                widgets::empty_state(
                    ui,
                    icon::ENDPOINTS,
                    "No environment selected",
                    "Start or select a localnet to see its endpoints.",
                );
            });
            return;
        };
        let palette = widgets::palette(ui);
        let prepared = selected.network.prepared();
        let context = &prepared.context;
        let private = matches!(selected.attachment, Ok(Some(_)));
        widgets::card(ui, |ui| {
            widgets::card_title(ui, icon::KEY, "Network identity");
            ui.add_space(4.0);
            widgets::copy_field(ui, "Chain ID", &context.chain_id);
            widgets::copy_field(ui, "Network ID", &context.network_id);
            widgets::copy_field(ui, "Developer account", &context.account_id);
            widgets::copy_field(
                ui,
                "Dataspace",
                &format!("{} (#{})", context.dataspace_alias, context.dataspace_id),
            );
            widgets::hint(
                ui,
                "The developer account signs Mochi's transactions. Its key stays in the owner-private workspace store.",
            );
        });
        ui.add_space(12.0);
        let peers = prepared.peers.len();
        let mut chosen = self.endpoint_peer.min(peers.saturating_sub(1));
        widgets::card(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                widgets::card_title(ui, icon::ENDPOINTS, "Validator routes");
                ui.add_space(8.0);
                let options = (0..peers)
                    .map(|index| (index, format!("Validator {}", index + 1)))
                    .collect::<Vec<_>>();
                let labels = options
                    .iter()
                    .map(|(index, label)| (*index, label.as_str()))
                    .collect::<Vec<_>>();
                widgets::segmented(ui, &mut chosen, &labels);
            });
            ui.add_space(4.0);
            if let Some(peer) = prepared.peers.get(chosen) {
                egui::Grid::new("validator-routes")
                    .num_columns(3)
                    .spacing([16.0, 10.0])
                    .striped(true)
                    .show(ui, |ui| {
                        for route in ROUTES {
                            let url = route_url(&peer.torii_url, route.path);
                            ui.vertical(|ui| {
                                ui.set_min_width(250.0);
                                ui.spacing_mut().item_spacing.y = 0.0;
                                ui.label(RichText::new(route.label).strong().color(palette.text));
                                ui.label(RichText::new(route.detail).small().color(palette.muted));
                            });
                            ui.label(RichText::new(&url).monospace().color(palette.text));
                            widgets::copy_button(ui, &url, &format!("{} URL", route.label));
                            ui.end_row();
                        }
                    });
            }
            if private {
                ui.add_space(6.0);
                widgets::banner(
                    ui,
                    widgets::Tone::Info,
                    "Private dataspace validators require the generated API token on every route. Mochi keeps that token private; use Kagami or Mochi actions instead of raw requests.",
                    false,
                );
            }
        });
        self.endpoint_peer = chosen;
        ui.add_space(12.0);
        let torii = prepared
            .peers
            .get(chosen)
            .map_or(context.torii_url.as_str(), |peer| peer.torii_url.as_str());
        let snippets = terminal_snippets(
            &context.name,
            self.workspace_path.native.to_str(),
            torii,
            chosen,
        );
        widgets::card(ui, |ui| {
            widgets::card_title(ui, icon::LOGS, "From your terminal");
            widgets::hint(
                ui,
                "Kagami shares this workspace with Mochi, so these commands act on the same environment.",
            );
            ui.add_space(4.0);
            for (title, command) in &snippets {
                ui.label(RichText::new(*title).strong().color(palette.text));
                widgets::code_block(ui, command, "command");
                ui.add_space(4.0);
            }
            if self.workspace_path.native.to_str().is_none() {
                widgets::hint(
                    ui,
                    "Run these from the workspace directory: its path is not valid Unicode, so Mochi does not spell it out.",
                );
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_urls_join_without_doubled_slashes() {
        assert_eq!(
            route_url("http://127.0.0.1:8080/", "status"),
            "http://127.0.0.1:8080/status"
        );
        assert_eq!(
            route_url("http://127.0.0.1:8080", ""),
            "http://127.0.0.1:8080/"
        );
        assert_eq!(
            route_url("http://127.0.0.1:8080//", "v1/mcp"),
            "http://127.0.0.1:8080/v1/mcp"
        );
        assert!(ROUTES.iter().all(|route| !route.path.starts_with('/')));
    }

    #[test]
    fn shell_arguments_are_quoted_only_when_needed() {
        assert_eq!(shell_arg("local-2"), "local-2");
        assert_eq!(shell_arg("/Users/dev/app"), "/Users/dev/app");
        assert_eq!(shell_arg("/Users/dev/my app"), "'/Users/dev/my app'");
        assert_eq!(shell_arg("it's"), r"'it'\''s'");
        assert_eq!(shell_arg(""), "''");
        assert_eq!(shell_arg("$(rm -rf ~)"), "'$(rm -rf ~)'");
    }

    #[test]
    fn snippets_bind_the_exact_environment_and_workspace() {
        let snippets = terminal_snippets(
            "local-2",
            Some("/tmp/my project"),
            "http://127.0.0.1:8081/",
            1,
        );
        let commands = snippets
            .iter()
            .map(|(_, command)| command.as_str())
            .collect::<Vec<_>>();
        assert_eq!(commands[0], "curl -s http://127.0.0.1:8081/status");
        assert!(
            commands[1..]
                .iter()
                .all(|command| command.contains("local-2 --workspace '/tmp/my project'"))
        );
        assert!(commands[2].ends_with("--peer 1"));
        assert!(commands[3].contains("--context local-2"));
        let without_workspace = terminal_snippets("local", None, "http://127.0.0.1:8080/", 0);
        assert!(
            without_workspace
                .iter()
                .all(|(_, command)| !command.contains("--workspace"))
        );
    }
}
