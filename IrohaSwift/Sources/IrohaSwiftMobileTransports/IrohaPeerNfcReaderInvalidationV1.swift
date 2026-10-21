import Foundation

/// A reader result does not release the application to present authentication
/// until CoreNFC invalidates that exact session. The owner serializes access.
struct IrohaPeerNfcReaderInvalidationV1<Value> {
    private var pending: (session: ObjectIdentifier, result: Result<Value, Error>)?

    var isPending: Bool { pending != nil }

    mutating func begin(session: ObjectIdentifier, result: Result<Value, Error>) {
        precondition(pending == nil)
        pending = (session, result)
    }

    /// Cancellation can retire a successful read while its sheet is closing.
    /// It never turns an interrupted read into authorization to move value.
    mutating func cancel(with error: Error) {
        guard let saved = pending else { return }
        pending = (saved.session, .failure(error))
    }

    mutating func invalidated(session: ObjectIdentifier) -> Result<Value, Error>? {
        guard let saved = pending, saved.session == session else { return nil }
        pending = nil
        return saved.result
    }

    /// A missing platform callback is a failure, never permission to show the
    /// next system prompt. Preserve an earlier failure when there was one.
    mutating func timedOut(session: ObjectIdentifier, error: Error) -> Result<Value, Error>? {
        guard let saved = pending, saved.session == session else { return nil }
        pending = nil
        if case .failure = saved.result { return saved.result }
        return .failure(error)
    }
}
