//! Doc-sync tests for the Sumeragi governance and evidence documentation.

use iroha_config::parameters::defaults::sumeragi::npos;
use std::path::Path;
#[test]
fn sumeragi_doc_mentions_governed_reconfig_defaults_and_errors() {
    let repo_root = workspace_root();
    let doc =
        std::fs::read_to_string(repo_root.join("specs/sumeragi.md")).expect("read sumeragi.md");
    let horizon = npos::RECONFIG_EVIDENCE_HORIZON_BLOCKS;
    let activation = npos::RECONFIG_ACTIVATION_LAG_BLOCKS;
    let slashing_delay = npos::SLASHING_DELAY_BLOCKS;
    assert!(
        doc.contains(&format!(
            "SumeragiNposParameters.reconfig.evidence_horizon_blocks = {horizon}"
        )),
        "specs/sumeragi.md is missing the governed evidence horizon default ({horizon})"
    );
    assert!(
        doc.contains(&format!(
            "SumeragiNposParameters.reconfig.activation_lag_blocks = {activation}"
        )),
        "specs/sumeragi.md is missing the governed activation lag default ({activation})"
    );
    assert!(
        doc.contains(&format!(
            "SumeragiNposParameters.reconfig.slashing_delay_blocks = {slashing_delay}"
        )),
        "specs/sumeragi.md is missing the governed slashing delay default ({slashing_delay})"
    );
    assert!(
        doc.contains("mode_activation_height requires next_mode to be set in the same block"),
        "specs/sumeragi.md must document the joint-consensus staging error message"
    );
    assert!(
        doc.contains("immutable after the initial signed installation")
            && doc.contains("horizon plus delay may span at most three epochs"),
        "specs/sumeragi.md must pin the first-release accountability-capacity invariant"
    );
}
#[test]
fn governance_api_doc_covers_joint_consensus_flow() {
    let repo_root = workspace_root();
    let doc = std::fs::read_to_string(repo_root.join("specs/governance_api.md"))
        .expect("read governance_api.md");
    // Markdown soft wrapping does not alter the governed value or its exact wording.
    let doc = doc.split_whitespace().collect::<Vec<_>>().join(" ");
    let horizon = npos::RECONFIG_EVIDENCE_HORIZON_BLOCKS;
    let activation = npos::RECONFIG_ACTIVATION_LAG_BLOCKS;
    let slashing_delay = npos::SLASHING_DELAY_BLOCKS;
    assert!(
        doc.contains(&format!(
            "SumeragiNposParameters.reconfig.evidence_horizon_blocks` (default `{horizon}` blocks)"
        )),
        "specs/governance_api.md must mention the governed evidence horizon ({horizon})"
    );
    assert!(
        doc.contains(&format!(
            "SumeragiNposParameters.reconfig.activation_lag_blocks` (default `{activation}`)"
        )),
        "specs/governance_api.md must mention the governed activation lag ({activation})"
    );
    assert!(
        doc.contains(&format!(
            "SumeragiNposParameters.reconfig.slashing_delay_blocks` (default `{slashing_delay}`)"
        )),
        "specs/governance_api.md must mention the governed slashing delay ({slashing_delay})"
    );
    assert!(
        doc.contains("mode_activation_height requires next_mode to be set in the same block"),
        "specs/governance_api.md must document the joint-consensus staging error message"
    );
    assert!(
        doc.contains("become immutable after their initial")
            && doc.contains("horizon plus delay cannot exceed three epochs"),
        "specs/governance_api.md must pin immutable bounded accountability windows"
    );

    let lane_doc = std::fs::read_to_string(repo_root.join("specs/nexus_public_lanes.md"))
        .expect("read nexus_public_lanes.md");
    assert!(
        lane_doc
            .contains("slashable_through_height + evidence_horizon_blocks + slashing_delay_blocks")
            && lane_doc.contains("Consensus effects run before ordinary transactions"),
        "public-lane docs must pin the inclusive effects-first unbond liability formula"
    );
}
fn workspace_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
}
