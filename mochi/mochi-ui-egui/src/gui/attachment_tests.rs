//! Attachment failure selection and completed-evidence regressions.

use super::*;
use iroha_deploy::managed::{Error as ManagedError, InstalledRuntime};

fn workspace() -> (tempfile::TempDir, DeveloperWorkspace) {
    let temporary = tempfile::tempdir().unwrap();
    let project = temporary.path().join("project");
    let bin = temporary.path().join("bin");
    std::fs::create_dir(&project).unwrap();
    std::fs::create_dir(&bin).unwrap();
    for program in ["kagami", "iroha3d"] {
        std::fs::copy(
            std::env::current_exe().unwrap(),
            bin.join(format!("{program}{}", std::env::consts::EXE_SUFFIX)),
        )
        .unwrap();
    }
    let workspace = DeveloperWorkspace::with_runtime(
        &temporary.path().join("state"),
        &project,
        InstalledRuntime::from_directory(&bin).unwrap(),
    )
    .unwrap();
    (temporary, workspace)
}

fn prepare_selected(workspace: &DeveloperWorkspace) -> ManagedNetwork {
    // As in mochi-core's workspace tests, the native test executable is not Kagami's
    // worker. Genuine preparation must reach the original worker-start timeout; this
    // fixture never reports a ready localnet or an authenticated remote attachment.
    let failure = workspace.create_localnet("original").unwrap_err();
    assert!(
        matches!(
            failure.downcast_ref::<ManagedError>(),
            Some(ManagedError::Timeout(timeout)) if *timeout == Duration::from_secs(30)
        ),
        "genuine preparation must retain the original startup failure: {failure}"
    );
    workspace.select("original").unwrap();
    workspace.network(None).unwrap()
}

fn seed_completed_evidence(desktop: &mut Desktop) {
    desktop.receipt = Some("original deployment receipt".into());
    desktop.notice = Some("original completion".into());
    desktop.publication.operation_id = "original publication operation".into();
    desktop.publication_output = Some(PublicationOutput {
        exit_code: 7,
        stdout: "original publication output".into(),
        stderr: "original recovery diagnostic".into(),
    });
}

fn assert_completed_evidence(desktop: &Desktop) {
    assert_eq!(
        desktop.receipt.as_deref(),
        Some("original deployment receipt")
    );
    assert_eq!(desktop.notice.as_deref(), Some("original completion"));
    assert_eq!(
        desktop.publication.operation_id,
        "original publication operation"
    );
    let output = desktop.publication_output.as_ref().unwrap();
    assert_eq!(output.exit_code, 7);
    assert_eq!(output.stdout, "original publication output");
    assert_eq!(output.stderr, "original recovery diagnostic");
}

fn fail_invalid_alias(desktop: &mut Desktop, replaced: bool) {
    // Only the dialog's already-loaded menu is populated. Canonical name admission
    // rejects this alias before opening any installed profile or contacting a parent.
    desktop.profiles = Ok(vec!["taira".into()]);
    desktop.private_network = "taira".into();
    desktop.private_alias = "bad name".into();
    desktop.private_dialog = true;
    desktop.logs = "old live observation".into();
    let epoch = desktop.epoch;
    desktop.attach();
    assert_eq!(desktop.epoch, epoch.wrapping_add(1));
    assert!(desktop.busy);
    assert!(desktop.selected.is_none());
    assert!(!desktop.private_dialog);
    assert_eq!(desktop.attaching.as_deref(), Some("bad name"));
    assert!(desktop.logs.is_empty());
    assert_completed_evidence(desktop);

    let completion = desktop
        .receiver
        .recv_timeout(Duration::from_secs(10))
        .unwrap();
    assert_eq!(completion.0, desktop.epoch);
    let Message::Attached { result, refreshed } = &completion.1 else {
        panic!("attachment returned another action's completion");
    };
    assert!(
        result
            .as_ref()
            .unwrap_err()
            .contains("managed names must contain")
    );
    let opened = refreshed.as_ref().expect("workspace remains readable");
    if replaced {
        assert!(opened.selected.as_ref().err().unwrap().contains("replaced"));
    } else {
        assert!(opened.selected.is_ok());
    }
    desktop.sender.send(completion).unwrap();
    desktop.last_poll = Instant::now();
    desktop.poll();
    assert!(!desktop.busy);
    assert!(desktop.attaching.is_none());
    assert!(!desktop.attachment_poll_pending);
    assert!(desktop.attachment_progress.is_none());
    assert!(
        desktop
            .error
            .as_deref()
            .unwrap()
            .contains("managed names must contain")
    );
    assert_completed_evidence(desktop);
}

#[test]
fn attachment_failure_preserves_exact_selection_and_refuses_replacement() {
    let (_temporary, workspace) = workspace();
    let mut desktop = Desktop::model(workspace.resolve_path(std::path::Path::new(".")));
    desktop.workspace = Some(workspace.clone());
    seed_completed_evidence(&mut desktop);

    fail_invalid_alias(&mut desktop, false);
    assert!(desktop.selected.is_none());
    assert!(workspace.contexts().unwrap().is_empty());
    assert_eq!(workspace.selected_name().unwrap(), None);

    let original = prepare_selected(&workspace);
    // A current store default is not authority to select it after an uncaptured failure.
    fail_invalid_alias(&mut desktop, false);
    assert!(desktop.selected.is_none());
    assert_eq!(desktop.names, ["original"]);
    assert_eq!(
        workspace.selected_name().unwrap().as_deref(),
        Some("original")
    );
    desktop.install_selection(load_network_selection(&workspace, original.clone()).unwrap());
    seed_completed_evidence(&mut desktop);
    fail_invalid_alias(&mut desktop, false);
    assert_eq!(
        desktop.selected.as_ref().unwrap().network.prepared(),
        original.prepared()
    );
    assert_eq!(
        workspace.contexts().unwrap(),
        [original.prepared().context.clone()]
    );
    assert_eq!(
        workspace.selected_name().unwrap().as_deref(),
        Some("original")
    );

    // This is a completion-presentation test over the genuine retained selection, not a
    // remote success fixture. A successful replacement clears even same-selection evidence.
    desktop.busy = true;
    desktop.error = None;
    desktop.attaching = Some("presentation-only".into());
    desktop
        .sender
        .send((
            desktop.epoch,
            Message::Attached {
                result: Ok("completed attachment observation".into()),
                refreshed: inspect_workspace_selection(workspace.clone(), Some(original.clone())),
            },
        ))
        .unwrap();
    desktop.poll();
    assert!(!desktop.busy);
    assert!(desktop.error.is_none());
    assert!(desktop.receipt.is_none());
    assert!(desktop.publication.operation_id.is_empty());
    assert!(desktop.publication_output.is_none());
    assert_eq!(
        desktop.notice.as_deref(),
        Some("completed attachment observation")
    );
    assert_eq!(
        desktop.selected.as_ref().unwrap().network.prepared(),
        original.prepared()
    );

    // Keep the original UI capture while another frontend resets and recreates its name.
    // Name-based recovery would adopt this genuine replacement and fail the assertions.
    workspace.reset(&original).unwrap();
    let replacement = prepare_selected(&workspace);
    assert_ne!(replacement.prepared(), original.prepared());
    seed_completed_evidence(&mut desktop);
    fail_invalid_alias(&mut desktop, true);
    assert!(desktop.selected.is_none());
    assert_eq!(
        workspace.network(None).unwrap().prepared(),
        replacement.prepared()
    );
    assert_eq!(
        workspace.contexts().unwrap(),
        [replacement.prepared().context.clone()]
    );
    assert_eq!(
        workspace.selected_name().unwrap().as_deref(),
        Some("original")
    );
}

#[test]
fn failed_attachment_preserves_evidence_when_workspace_refresh_also_fails() {
    let mut desktop = Desktop::model(PathBuf::from("unused"));
    seed_completed_evidence(&mut desktop);
    desktop.busy = true;
    desktop.attaching = Some("pending".into());
    desktop
        .sender
        .send((
            desktop.epoch,
            Message::Attached {
                result: Err("original attachment failure".into()),
                refreshed: Err("workspace refresh failure".into()),
            },
        ))
        .unwrap();
    desktop.poll();
    assert!(!desktop.busy);
    assert!(desktop.selected.is_none());
    assert!(desktop.attaching.is_none());
    assert_eq!(
        desktop.error.as_deref(),
        Some("original attachment failure")
    );
    assert_completed_evidence(&desktop);
}

#[test]
fn successful_attachment_clears_prior_evidence_even_when_refresh_fails() {
    let mut desktop = Desktop::model(PathBuf::from("unused"));
    seed_completed_evidence(&mut desktop);
    desktop.busy = true;
    desktop.attaching = Some("pending".into());
    desktop
        .sender
        .send((
            desktop.epoch,
            Message::Attached {
                result: Ok("completed attachment observation".into()),
                refreshed: Err("workspace refresh failure".into()),
            },
        ))
        .unwrap();
    desktop.poll();
    assert!(!desktop.busy);
    assert!(desktop.selected.is_none());
    assert!(desktop.attaching.is_none());
    assert!(desktop.receipt.is_none());
    assert!(desktop.publication.operation_id.is_empty());
    assert!(desktop.publication_output.is_none());
    assert_eq!(
        desktop.notice.as_deref(),
        Some("completed attachment observation")
    );
    assert_eq!(desktop.error.as_deref(), Some("workspace refresh failure"));
}

#[test]
fn stale_attachment_completion_cannot_replace_current_work_or_evidence() {
    let mut desktop = Desktop::model(PathBuf::from("unused"));
    seed_completed_evidence(&mut desktop);
    desktop.epoch = 2;
    desktop.busy = true;
    desktop.attaching = Some("current".into());
    desktop.attachment_poll_pending = true;
    desktop.logs = "current live observation".into();
    desktop.error = Some("current diagnostic".into());
    for result in [Ok("stale completion".into()), Err("stale failure".into())] {
        desktop
            .sender
            .send((
                1,
                Message::Attached {
                    result,
                    refreshed: Err("stale refresh failure".into()),
                },
            ))
            .unwrap();
    }
    desktop.poll();
    assert_eq!(desktop.epoch, 2);
    assert!(desktop.busy);
    assert_eq!(desktop.attaching.as_deref(), Some("current"));
    assert!(desktop.attachment_poll_pending);
    assert_eq!(desktop.logs, "current live observation");
    assert_eq!(desktop.error.as_deref(), Some("current diagnostic"));
    assert_completed_evidence(&desktop);
}
