//! Bounded LSP input and cancellation state, independent of semantic analysis.
use super::*;
use std::{
    collections::VecDeque,
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

const MAX_PENDING_MESSAGES: usize = 64;
const MAX_PENDING_BYTES: usize = 16 * MAX_SOURCE_BYTES;
// The dispatcher can own one request in addition to the bounded input queue.
const MAX_PENDING_REQUESTS: usize = MAX_PENDING_MESSAGES + 1;

#[derive(Clone)]
pub(super) struct Inbox {
    shared: Arc<(Mutex<State>, Condvar)>,
}

#[derive(Default)]
struct State {
    queue: VecDeque<PendingMessage>,
    queued_bytes: usize,
    requests: HashMap<String, Arc<AtomicBool>>,
    versions: HashMap<String, Option<i64>>,
    generation: u64,
    finished: bool,
    failure: Option<String>,
}

pub(super) struct PendingMessage {
    pub(super) message: norito::json::Value,
    generation: u64,
    bytes: usize,
    request: Option<(String, Arc<AtomicBool>)>,
}

fn request_key(id: &norito::json::Value) -> Option<String> {
    if id.as_str().is_some() || id.as_i64().is_some() || id.as_u64().is_some() {
        // JSON encoding keeps string IDs distinct from numeric IDs.
        norito::json::to_string(id).ok()
    } else {
        None
    }
}

fn is_analysis_request(message: &norito::json::Value) -> bool {
    matches!(
        message.get("method").and_then(norito::json::Value::as_str),
        Some(
            "textDocument/completion"
                | "textDocument/hover"
                | "textDocument/signatureHelp"
                | "textDocument/definition"
                | "textDocument/references"
                | "textDocument/documentHighlight"
                | "textDocument/documentSymbol"
                | "textDocument/foldingRange"
                | "textDocument/semanticTokens/full"
                | "textDocument/codeLens"
                | "workspace/symbol"
                | "textDocument/prepareRename"
                | "textDocument/rename"
                | "textDocument/codeAction"
                | "textDocument/formatting"
        )
    )
}

impl State {
    fn observe_document_change(&mut self, message: &norito::json::Value) -> Result<bool, String> {
        let method = message.get("method").and_then(norito::json::Value::as_str);
        let changed = match method {
            Some("textDocument/didOpen" | "textDocument/didChange") => {
                let Some(uri) = message
                    .pointer("/params/textDocument/uri")
                    .and_then(norito::json::Value::as_str)
                    .filter(|uri| uri.len() <= MAX_LSP_URI_BYTES)
                else {
                    return Ok(true);
                };
                let text_path = if method == Some("textDocument/didOpen") {
                    "/params/textDocument/text"
                } else {
                    "/params/contentChanges/0/text"
                };
                if message
                    .pointer(text_path)
                    .and_then(norito::json::Value::as_str)
                    .is_none()
                {
                    return Ok(true);
                }
                let version = message
                    .pointer("/params/textDocument/version")
                    .and_then(norito::json::Value::as_i64);
                if let Some(version) = version
                    && self
                        .versions
                        .get(uri)
                        .copied()
                        .flatten()
                        .is_some_and(|old| old >= version)
                {
                    // Drop non-increasing revisions before they can invalidate a newer result.
                    return Ok(false);
                }
                if self.versions.contains_key(uri) || self.versions.len() < MAX_LSP_OPEN_DOCUMENTS {
                    let previous = self.versions.get(uri).copied().flatten();
                    self.versions.insert(uri.to_owned(), version.or(previous));
                }
                true
            }
            Some("textDocument/didClose") => {
                if let Some(uri) = message
                    .pointer("/params/textDocument/uri")
                    .and_then(norito::json::Value::as_str)
                {
                    self.versions.remove(uri);
                }
                true
            }
            Some("textDocument/didSave" | "workspace/didChangeWatchedFiles") => true,
            _ => false,
        };
        if changed {
            self.generation = self
                .generation
                .checked_add(1)
                .ok_or_else(|| "LSP document generation limit exceeded".to_owned())?;
        }
        Ok(true)
    }

    fn rejection(&self, pending: &PendingMessage) -> Option<(i64, &'static str)> {
        if pending
            .request
            .as_ref()
            .is_some_and(|(_, canceled)| canceled.load(Ordering::Acquire))
        {
            Some((-32800, "request canceled"))
        } else if is_analysis_request(&pending.message) && pending.generation != self.generation {
            Some((-32801, "document content changed during the request"))
        } else {
            None
        }
    }

    fn finish(&mut self, pending: &PendingMessage) {
        if let Some((key, token)) = &pending.request
            && self
                .requests
                .get(key)
                .is_some_and(|registered| Arc::ptr_eq(registered, token))
        {
            self.requests.remove(key);
        }
    }
}

impl Inbox {
    pub(super) fn new() -> Self {
        Self {
            shared: Arc::new((Mutex::new(State::default()), Condvar::new())),
        }
    }

    pub(super) fn read_from(&self, input: &mut impl BufRead) {
        let result = (|| {
            while let Some((message, bytes)) = read_lsp_message_frame(input)? {
                let exit =
                    message.get("method").and_then(norito::json::Value::as_str) == Some("exit");
                self.push(message, bytes)?;
                if exit {
                    break;
                }
            }
            Ok(())
        })();
        let (lock, ready) = &*self.shared;
        let mut state = lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.finished = true;
        if let Err(error) = result {
            state.failure = Some(error);
            state.queue.clear();
            state.queued_bytes = 0;
            state.requests.clear();
        }
        ready.notify_one();
    }

    fn push(&self, message: norito::json::Value, bytes: usize) -> Result<(), String> {
        let (lock, ready) = &*self.shared;
        let mut state = lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.finished {
            return Err("LSP input dispatcher is closed".to_owned());
        }
        if message.get("method").and_then(norito::json::Value::as_str) == Some("$/cancelRequest") {
            if let Some(key) = message.pointer("/params/id").and_then(request_key)
                && let Some(token) = state.requests.get(&key)
            {
                token.store(true, Ordering::Release);
            }
            // Unknown or completed IDs create no retained state, and cancellation needs no
            // queue slot, even when analysis has filled the pending request budget.
            return Ok(());
        }
        if state.queue.len() >= MAX_PENDING_MESSAGES
            || bytes > MAX_PENDING_BYTES.saturating_sub(state.queued_bytes)
        {
            return Err(format!(
                "LSP pending input exceeds the {MAX_PENDING_MESSAGES}-message/{MAX_PENDING_BYTES}-byte limit"
            ));
        }
        if !state.observe_document_change(&message)? {
            return Ok(());
        }
        let request = if let Some(id) = message.get("id") {
            let key = request_key(id)
                .ok_or_else(|| "LSP request ID must be an integer or string".to_owned())?;
            if state.requests.contains_key(&key) {
                return Err("LSP request ID is already pending".to_owned());
            }
            if state.requests.len() >= MAX_PENDING_REQUESTS {
                return Err(format!(
                    "LSP pending request limit reached ({MAX_PENDING_REQUESTS})"
                ));
            }
            let token = Arc::new(AtomicBool::new(false));
            state.requests.insert(key.clone(), token.clone());
            Some((key, token))
        } else {
            None
        };
        let generation = state.generation;
        state.queue.push_back(PendingMessage {
            message,
            generation,
            bytes,
            request,
        });
        state.queued_bytes += bytes;
        ready.notify_one();
        Ok(())
    }

    pub(super) fn next(&self) -> Result<Option<PendingMessage>, String> {
        let (lock, ready) = &*self.shared;
        let mut state = lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        loop {
            if let Some(error) = &state.failure {
                return Err(error.clone());
            }
            if let Some(pending) = state.queue.pop_front() {
                state.queued_bytes -= pending.bytes;
                return Ok(Some(pending));
            }
            if state.finished {
                return Ok(None);
            }
            state = ready
                .wait(state)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }

    pub(super) fn is_current(&self, pending: &PendingMessage) -> bool {
        let state = self
            .shared
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.failure.is_none() && pending.generation == state.generation
    }

    pub(super) fn reject_before_analysis(
        &self,
        pending: &PendingMessage,
        output: &mut impl Write,
    ) -> Result<bool, String> {
        let mut state = self
            .shared
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(error) = &state.failure {
            return Err(error.clone());
        }
        if pending.request.is_some()
            && let Some((code, message)) = state.rejection(pending)
        {
            state.finish(pending);
            drop(state);
            write_lsp_error(output, pending.message.get("id").cloned(), code, message)?;
            return Ok(true);
        }
        Ok(false)
    }

    pub(super) fn complete(
        &self,
        pending: &PendingMessage,
        output: &mut impl Write,
        buffered: &[u8],
    ) -> Result<bool, String> {
        // The locked check/removal is the completion point. Release the input lock before
        // writing so stdout backpressure cannot prevent cancellation/change intake. Later
        // cancellations refer to an already completed request and retain no state.
        let mut state = self
            .shared
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(error) = &state.failure {
            return Err(error.clone());
        }
        let rejection = pending
            .request
            .as_ref()
            .and_then(|_| state.rejection(pending));
        let committed = rejection.is_none()
            && (pending.request.is_some() || pending.generation == state.generation);
        state.finish(pending);
        drop(state);
        if let Some((code, message)) = rejection {
            write_lsp_error(output, pending.message.get("id").cloned(), code, message)?;
        } else if committed {
            output
                .write_all(buffered)
                .and_then(|()| output.flush())
                .map_err(|error| format!("write LSP output: {error}"))?;
        }
        Ok(committed)
    }

    pub(super) fn close(&self) {
        let (lock, ready) = &*self.shared;
        let mut state = lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.finished = true;
        state.queue.clear();
        state.queued_bytes = 0;
        state.requests.clear();
        ready.notify_one();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(id: norito::json::Value) -> norito::json::Value {
        json_object(vec![
            ("jsonrpc", "2.0".into()),
            ("id", id),
            ("method", "textDocument/hover".into()),
            (
                "params",
                json_object(vec![
                    (
                        "textDocument",
                        json_object(vec![("uri", "file:///kotodama.ko".into())]),
                    ),
                    ("position", lsp_position(0_u64, 0_u64)),
                ]),
            ),
        ])
    }

    fn cancel(id: norito::json::Value) -> norito::json::Value {
        json_object(vec![
            ("method", "$/cancelRequest".into()),
            ("params", json_object(vec![("id", id)])),
        ])
    }

    fn document_change(version: i64, text: &str) -> norito::json::Value {
        json_object(vec![
            ("method", "textDocument/didChange".into()),
            (
                "params",
                json_object(vec![
                    (
                        "textDocument",
                        json_object(vec![
                            ("uri", "file:///kotodama.ko".into()),
                            ("version", version.into()),
                        ]),
                    ),
                    (
                        "contentChanges",
                        norito::json::Value::Array(vec![json_object(vec![("text", text.into())])]),
                    ),
                ]),
            ),
        ])
    }

    fn messages(bytes: Vec<u8>) -> Vec<norito::json::Value> {
        let mut input = std::io::Cursor::new(bytes);
        let mut messages = Vec::new();
        while let Some(message) = read_lsp_message(&mut input).expect("valid output frame") {
            messages.push(message);
        }
        messages
    }

    #[test]
    fn wire_dispatch_rejects_queued_cancel_without_aliasing_string_ids() {
        let mut input = Vec::new();
        for message in [
            request(7_i64.into()),
            request("7".into()),
            cancel(7_i64.into()),
        ] {
            write_lsp_message(&mut input, &message).expect("encode input");
        }
        let inbox = Inbox::new();
        inbox.read_from(&mut std::io::Cursor::new(input));
        let mut output = Vec::new();
        language_server_dispatch(&inbox, &mut output, None, &ServerOptions::default())
            .expect("dispatch");
        let output = messages(output);
        assert_eq!(output.len(), 2);
        assert_eq!(
            output[0]
                .pointer("/error/code")
                .and_then(norito::json::Value::as_i64),
            Some(-32800)
        );
        assert_eq!(
            output[0].get("id").and_then(norito::json::Value::as_i64),
            Some(7)
        );
        assert_eq!(
            output[1].get("id").and_then(norito::json::Value::as_str),
            Some("7")
        );
        assert!(output[1].get("result").is_some());
        assert!(inbox.shared.0.lock().expect("state").requests.is_empty());
    }

    #[test]
    fn initialize_reports_server_version_and_editor_capabilities() {
        let result = lsp_initialize_result();
        assert_eq!(
            result
                .pointer("/serverInfo/name")
                .and_then(norito::json::Value::as_str),
            Some("koto")
        );
        assert_eq!(
            result
                .pointer("/serverInfo/version")
                .and_then(norito::json::Value::as_str),
            Some(env!("CARGO_PKG_VERSION"))
        );
        for capability in [
            "documentSymbolProvider",
            "workspaceSymbolProvider",
            "documentHighlightProvider",
            "foldingRangeProvider",
        ] {
            assert_eq!(
                result
                    .pointer(&format!("/capabilities/{capability}"))
                    .and_then(norito::json::Value::as_bool),
                Some(true),
                "{capability}"
            );
        }
        assert!(result.pointer("/capabilities/codeLensProvider").is_some());
        let types = result
            .pointer("/capabilities/semanticTokensProvider/legend/tokenTypes")
            .and_then(norito::json::Value::as_array)
            .expect("semantic token legend");
        assert!(
            types
                .iter()
                .any(|kind| kind.as_str() == Some("brandedKeyword"))
        );
        for method in [
            "textDocument/documentSymbol",
            "textDocument/semanticTokens/full",
            "workspace/symbol",
        ] {
            assert!(is_analysis_request(&json_object(vec![(
                "method",
                method.into()
            )])));
        }
    }
    #[test]
    fn wire_shutdown_drains_prior_replies_and_exit_stops_input() {
        let mut input = Vec::new();
        for (id, method) in [
            (Some(1_i64), "initialize"),
            (Some(2), "shutdown"),
            (None, "exit"),
        ] {
            let mut fields = vec![("method", method.into())];
            if let Some(id) = id {
                fields.push(("id", id.into()));
            }
            write_lsp_message(&mut input, &json_object(fields)).expect("encode input");
        }
        input.extend_from_slice(b"invalid input after exit is never read");
        let inbox = Inbox::new();
        inbox.read_from(&mut std::io::Cursor::new(input));
        let mut output = Vec::new();
        language_server_dispatch(&inbox, &mut output, None, &ServerOptions::default())
            .expect("shutdown");
        inbox.close();
        let output = messages(output);
        assert_eq!(output.len(), 2);
        assert!(output[0].pointer("/result/capabilities").is_some());
        assert_eq!(output[1].get("result"), Some(&norito::json::Value::Null));
        let state = inbox.shared.0.lock().expect("state");
        assert!(state.requests.is_empty());
        assert!(state.queue.is_empty());
        assert!(state.failure.is_none());
    }

    #[test]
    fn wire_dispatch_only_publishes_latest_japanese_document_version() {
        let mut input = Vec::new();
        let latest = "// 日本語🙂\nmodule Editor { fn value() -> int { return 2; } }";
        let opened = json_object(vec![
            ("method", "textDocument/didOpen".into()),
            (
                "params",
                json_object(vec![(
                    "textDocument",
                    json_object(vec![
                        ("uri", "file:///kotodama.ko".into()),
                        ("version", 1_i64.into()),
                        ("text", "@@".into()),
                    ]),
                )]),
            ),
        ]);
        for message in [
            opened,
            request(1_i64.into()),
            document_change(2, latest),
            document_change(1, "@@ stale Japanese revision"),
            request(2_i64.into()),
        ] {
            write_lsp_message(&mut input, &message).expect("encode input");
        }
        let inbox = Inbox::new();
        inbox.read_from(&mut std::io::Cursor::new(input));
        let mut output = Vec::new();
        language_server_dispatch(&inbox, &mut output, None, &ServerOptions::default())
            .expect("dispatch");
        let output = messages(output);
        let old = output
            .iter()
            .find(|message| message.get("id").and_then(norito::json::Value::as_i64) == Some(1))
            .expect("old reply");
        assert_eq!(
            old.pointer("/error/code")
                .and_then(norito::json::Value::as_i64),
            Some(-32801)
        );
        let diagnostics = output
            .iter()
            .filter(|message| {
                message.get("method").and_then(norito::json::Value::as_str)
                    == Some("textDocument/publishDiagnostics")
            })
            .collect::<Vec<_>>();
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(
            diagnostics[0]
                .pointer("/params/version")
                .and_then(norito::json::Value::as_i64),
            Some(2)
        );
        assert!(output.iter().any(
            |message| message.get("id").and_then(norito::json::Value::as_i64) == Some(2)
                && message.get("result").is_some()
        ));
    }

    #[test]
    fn active_cancellation_discards_buffer_and_does_not_poison_reused_ids() {
        let inbox = Inbox::new();
        inbox.push(request(9_i64.into()), 100).expect("request");
        let pending = inbox.next().expect("read").expect("pending");
        let mut buffered = Vec::new();
        write_lsp_response(&mut buffered, Some(9_i64.into()), true.into())
            .expect("buffer response");
        let reader = inbox.clone();
        std::thread::spawn(move || {
            reader
                .push(cancel(9_i64.into()), 80)
                .expect("cancel active")
        })
        .join()
        .expect("reader");
        let mut output = Vec::new();
        assert!(
            !inbox
                .complete(&pending, &mut output, &buffered)
                .expect("complete")
        );
        let output = messages(output);
        assert_eq!(output.len(), 1);
        assert_eq!(
            output[0]
                .pointer("/error/code")
                .and_then(norito::json::Value::as_i64),
            Some(-32800)
        );
        assert!(output[0].get("result").is_none());
        for _ in 0..100 {
            inbox
                .push(cancel(9_i64.into()), 80)
                .expect("late cancellation");
        }
        inbox
            .push(request(9_i64.into()), 100)
            .expect("reuse completed ID");
        let pending = inbox.next().expect("read").expect("pending");
        assert!(
            !inbox
                .reject_before_analysis(&pending, &mut Vec::new())
                .expect("fresh ID")
        );
        assert!(
            inbox
                .complete(&pending, &mut Vec::new(), &buffered)
                .expect("fresh result")
        );
        assert!(inbox.shared.0.lock().expect("state").requests.is_empty());
    }

    #[test]
    fn active_changes_discard_stale_results_and_diagnostics() {
        let inbox = Inbox::new();
        inbox.push(request(1_i64.into()), 100).expect("request");
        let pending = inbox.next().expect("read").expect("pending");
        let reader = inbox.clone();
        std::thread::spawn(move || {
            reader
                .push(document_change(2, "// 日本語🙂"), 140)
                .expect("change during work")
        })
        .join()
        .expect("reader");
        let mut output = Vec::new();
        assert!(
            !inbox
                .complete(&pending, &mut output, b"obsolete response")
                .expect("reject stale")
        );
        assert_eq!(
            messages(output)[0]
                .pointer("/error/code")
                .and_then(norito::json::Value::as_i64),
            Some(-32801)
        );
        let old_diagnostics = inbox.next().expect("read").expect("change");
        inbox
            .push(document_change(3, "// 新しい文書🙂"), 140)
            .expect("newer change");
        let mut output = Vec::new();
        assert!(
            !inbox
                .complete(&old_diagnostics, &mut output, b"obsolete diagnostics")
                .expect("drop stale diagnostics")
        );
        assert!(output.is_empty());
        let latest = inbox.next().expect("read").expect("latest");
        inbox
            .push(document_change(2, "// 古い文書"), 140)
            .expect("ignore older revision");
        assert!(inbox.is_current(&latest));
        assert!(inbox.shared.0.lock().expect("state").queue.is_empty());
    }

    #[test]
    fn input_overload_is_bounded_but_cancellations_need_no_queue_space() {
        let inbox = Inbox::new();
        for id in 0..MAX_PENDING_MESSAGES {
            inbox
                .push(request((id as u64).into()), 100)
                .expect("bounded queued request");
        }
        inbox
            .push(cancel(((MAX_PENDING_MESSAGES - 1) as u64).into()), 80)
            .expect("cancel at queue capacity");
        assert!(
            inbox
                .push(request(1000_u64.into()), 100)
                .expect_err("message overload")
                .contains("pending input")
        );
        let state = inbox.shared.0.lock().expect("state");
        assert_eq!(state.queue.len(), MAX_PENDING_MESSAGES);
        assert_eq!(state.queued_bytes, 100 * MAX_PENDING_MESSAGES);
        assert_eq!(state.requests.len(), MAX_PENDING_MESSAGES);
        assert!(
            state
                .queue
                .back()
                .expect("last request")
                .request
                .as_ref()
                .expect("token")
                .1
                .load(Ordering::Acquire)
        );
        drop(state);
        inbox.close();
        assert!(inbox.next().expect("closed").is_none());

        let inbox = Inbox::new();
        inbox
            .push(request(1_u64.into()), MAX_LSP_MESSAGE_BYTES)
            .expect("first large message");
        inbox
            .push(request(2_u64.into()), MAX_LSP_MESSAGE_BYTES)
            .expect("second large message");
        assert!(
            inbox
                .push(request(3_u64.into()), MAX_LSP_MESSAGE_BYTES)
                .expect_err("byte overload")
                .contains("pending input")
        );
        assert!(inbox.shared.0.lock().expect("state").queued_bytes <= MAX_PENDING_BYTES);
    }

    #[test]
    fn save_watch_and_close_invalidate_analysis_without_retaining_closed_versions() {
        let inbox = Inbox::new();
        inbox
            .push(document_change(1, "// 契約"), 100)
            .expect("document");
        let _ = inbox.next().expect("read").expect("change");
        for method in [
            "textDocument/didSave",
            "workspace/didChangeWatchedFiles",
            "textDocument/didClose",
        ] {
            inbox.push(request(1_u64.into()), 100).expect("request");
            let pending = inbox.next().expect("read").expect("request");
            inbox
                .push(
                    json_object(vec![
                        ("method", method.into()),
                        (
                            "params",
                            json_object(vec![(
                                "textDocument",
                                json_object(vec![("uri", "file:///kotodama.ko".into())]),
                            )]),
                        ),
                    ]),
                    100,
                )
                .expect("invalidation");
            let mut output = Vec::new();
            assert!(
                inbox
                    .reject_before_analysis(&pending, &mut output)
                    .expect("reject obsolete")
            );
            assert_eq!(
                messages(output)[0]
                    .pointer("/error/code")
                    .and_then(norito::json::Value::as_i64),
                Some(-32801)
            );
            let _ = inbox.next().expect("read").expect("notification");
        }
        assert!(inbox.shared.0.lock().expect("state").versions.is_empty());
    }

    #[test]
    fn latest_diagnostic_publication_clears_previously_published_closed_uris() {
        let driver = BuildDriver::new(
            CompilerSession::new(CompilerOptions::default()),
            "lsp-closed-test",
        );
        let previous = BTreeSet::from(["file:///closed.ko".to_owned()]);
        let mut output = Vec::new();
        let current = publish_lsp_project_diagnostics(
            &mut output,
            &driver,
            &HashMap::new(),
            ProjectDiagnosticContext {
                snapshot: &ProjectSnapshot::default(),
                options: &ServerOptions {
                    source_root: None,
                    zk_enabled: false,
                    chain_discriminant: CompilerOptions::default().chain_discriminant,
                },
                error: None,
            },
            &HashMap::new(),
            &previous,
        )
        .expect("clear diagnostics");
        assert!(current.is_empty());
        let output = messages(output);
        assert_eq!(output.len(), 1);
        assert_eq!(
            output[0]
                .pointer("/params/uri")
                .and_then(norito::json::Value::as_str),
            Some("file:///closed.ko")
        );
        assert_eq!(
            output[0]
                .pointer("/params/diagnostics")
                .and_then(norito::json::Value::as_array)
                .map(Vec::len),
            Some(0)
        );
    }
}
