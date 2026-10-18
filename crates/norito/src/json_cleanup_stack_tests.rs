//! Child-isolated default-stack cleanup controls with complete parent libtest accounting.

use crate::{
    json,
    json_cleanup_comb::{CombContainer, deep_comb},
};
use std::{io::Write as _, process::Command};

const CHILD_ENV: &str = "NORITO_JSON_CLEANUP_TEST_CHILD";
const STACK_CAUSE: &str = "original JSON cleanup must not overflow the default-stack child";

#[derive(Debug, PartialEq, Eq)]
enum ChildOutcome {
    Passed,
    StackOverflow,
    Rejected,
}

fn decimal(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit())
}

fn successful_summary(line: &str) -> bool {
    let Some(tail) =
        line.strip_prefix("test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; ")
    else {
        return false;
    };
    let Some((filtered, elapsed)) = tail.split_once(" filtered out; finished in ") else {
        return false;
    };
    let Some(elapsed) = elapsed.strip_suffix('s') else {
        return false;
    };
    let Some((seconds, fraction)) = elapsed.split_once('.') else {
        return false;
    };
    decimal(filtered) && decimal(seconds) && fraction.len() == 2 && decimal(fraction)
}

fn stack_overflow_line(line: &str, name: &str) -> bool {
    let prefix = format!("thread '{name}' (");
    line.strip_prefix(&prefix)
        .and_then(|tail| tail.strip_suffix(") has overflowed its stack"))
        .is_some_and(decimal)
}

fn child_outcome(name: &str, success: bool, stdout: &str, stderr: &str) -> ChildOutcome {
    let mut output = stdout
        .lines()
        .map(str::trim_end)
        .filter(|line| !line.is_empty());
    let mut errors = stderr.lines().filter(|line| !line.is_empty());
    if output.next() != Some("running 1 test")
        || errors.next() != Some(format!("NORITO_CLEANUP_READY:{name}").as_str())
    {
        return ChildOutcome::Rejected;
    }
    if success {
        if output.next() == Some(format!("test {name} ... ok").as_str())
            && output.next().is_some_and(successful_summary)
            && output.next().is_none()
            && errors.next().is_none()
        {
            return ChildOutcome::Passed;
        }
    } else if output.next() == Some(format!("test {name} ...").as_str())
        && output.next().is_none()
        && errors
            .next()
            .is_some_and(|line| stack_overflow_line(line, name))
        && errors.next() == Some("fatal runtime error: stack overflow, aborting")
        && errors.next().is_none()
    {
        return ChildOutcome::StackOverflow;
    }
    ChildOutcome::Rejected
}

fn cleanup_in_original_child(name: &str, container: CombContainer) {
    assert!(
        std::env::var_os("RUST_MIN_STACK").is_none(),
        "cleanup control requires the default test stack"
    );
    if let Some(child) = std::env::var_os(CHILD_ENV) {
        assert_eq!(
            child.to_str(),
            Some(name),
            "cleanup child must own the exact selected test"
        );
        let value = deep_comb(container, 4_096);
        eprintln!("NORITO_CLEANUP_READY:{name}");
        json::drop_json_value_iteratively(value);
        return;
    }
    let output = Command::new(std::env::current_exe().expect("current owning libtest path"))
        .args([
            "--exact",
            name,
            "--nocapture",
            "--test-threads=1",
            "--format=pretty",
            "--color=never",
        ])
        .env(CHILD_ENV, name)
        .output()
        .expect("start and await the original cleanup child");
    // Escape every child newline/control byte before it reaches the parent's libtest
    // output. A child terminal or panic must never masquerade as a parent result.
    {
        let mut log = std::io::stderr().lock();
        writeln!(log, "\ncleanup child status: {}", output.status)
            .expect("record cleanup child status");
        writeln!(
            log,
            "cleanup child stdout: {}",
            output.stdout.escape_ascii()
        )
        .expect("record escaped cleanup child stdout");
        writeln!(
            log,
            "cleanup child stderr: {}",
            output.stderr.escape_ascii()
        )
        .expect("record escaped cleanup child stderr");
    }
    let stdout = std::str::from_utf8(&output.stdout).expect("cleanup child stdout is UTF-8");
    let stderr = std::str::from_utf8(&output.stderr).expect("cleanup child stderr is UTF-8");
    let outcome = child_outcome(name, output.status.success(), stdout, stderr);
    assert_ne!(
        outcome,
        ChildOutcome::Rejected,
        "cleanup child did not complete its exact declared protocol"
    );
    assert_ne!(outcome, ChildOutcome::StackOverflow, "{STACK_CAUSE}");
}

#[test]
fn array_comb_cleanup_survives_default_stack_child() {
    cleanup_in_original_child(
        "json_cleanup_stack_tests::array_comb_cleanup_survives_default_stack_child",
        CombContainer::Array,
    );
}

#[test]
fn object_comb_cleanup_survives_default_stack_child() {
    cleanup_in_original_child(
        "json_cleanup_stack_tests::object_comb_cleanup_survives_default_stack_child",
        CombContainer::Object,
    );
}

#[test]
fn child_success_requires_one_exact_terminal_and_complete_summary() {
    let name = "json_cleanup_stack_tests::synthetic";
    let stdout = format!(
        "\nrunning 1 test\ntest {name} ... ok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 73 filtered out; finished in 0.01s\n"
    );
    let stderr = format!("NORITO_CLEANUP_READY:{name}\n");
    assert_eq!(
        child_outcome(name, true, &stdout, &stderr),
        ChildOutcome::Passed
    );
    for bad in [
        stdout.replace("running 1 test", "running 0 tests"),
        stdout.replace(" ... ok", " ... ignored"),
        stdout.replace("1 passed", "0 passed"),
        stdout.replace("0 failed", "1 failed"),
        stdout.replace("0 ignored", "1 ignored"),
        stdout.replace(name, "foreign"),
        format!("{stdout}{stdout}"),
        stdout.replace("test result: ok.", "missing result:"),
    ] {
        assert_eq!(
            child_outcome(name, true, &bad, &stderr),
            ChildOutcome::Rejected
        );
    }
    assert_eq!(
        child_outcome(name, false, &stdout, &stderr),
        ChildOutcome::Rejected
    );
    assert_eq!(
        child_outcome(name, true, &stdout, ""),
        ChildOutcome::Rejected
    );
    assert_eq!(
        child_outcome(name, true, &stdout, &format!("{stderr}{stderr}")),
        ChildOutcome::Rejected
    );
}

#[test]
fn only_the_started_exact_child_stack_overflow_is_causal() {
    let name = "json_cleanup_stack_tests::synthetic";
    let stdout = format!("\nrunning 1 test\ntest {name} ... ");
    let stderr = format!(
        "NORITO_CLEANUP_READY:{name}\n\nthread '{name}' (123) has overflowed its stack\nfatal runtime error: stack overflow, aborting\n"
    );
    assert_eq!(
        child_outcome(name, false, &stdout, &stderr),
        ChildOutcome::StackOverflow
    );
    assert_eq!(
        child_outcome(name, true, &stdout, &stderr),
        ChildOutcome::Rejected
    );
    for bad in [
        stderr.replace("NORITO_CLEANUP_READY", "unrelated marker"),
        stderr.replace(
            "thread 'json_cleanup_stack_tests::synthetic'",
            "thread 'foreign'",
        ),
        stderr.replace("(123)", "(not-an-id)"),
        stderr.replace("has overflowed its stack", "panicked at other.rs:1:1:"),
        stderr.replace(
            "fatal runtime error: stack overflow, aborting",
            "unrelated abort",
        ),
        format!("{stderr}another diagnostic\n"),
    ] {
        assert_eq!(
            child_outcome(name, false, &stdout, &bad),
            ChildOutcome::Rejected
        );
    }
    for bad in [
        stdout.replace(name, "foreign"),
        stdout.replace("running 1 test", "running 2 tests"),
        format!("{stdout}\ntest extra ... ok\n"),
        String::new(),
    ] {
        assert_eq!(
            child_outcome(name, false, &bad, &stderr),
            ChildOutcome::Rejected
        );
    }
}
