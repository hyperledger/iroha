/// Cleanup of the exact owner/token already handed to execute_reviewed. This never
/// classifies a monetary outcome or makes the consumed Swift capability reusable.
enum KagemushaWalletReviewedExecutionV1 {
  static func run<Value>(execute: () throws -> Value, discard: () -> Int32,
                        close: () throws -> Void) throws -> Value {
    do { return try execute() }
    catch {
      let primary = error
      // Native execute_reviewed_inner takes its one-use token before rechecking or
      // executing the review. Tokens.take reports INVALID (-1), not CLOSED (-2),
      // when this later discard finds that exact token absent. A successful discard
      // also resolves a dispatch refused before token consumption. Only this cleanup
      // return is interpreted here: an execution INVALID remains the primary error.
      switch discard() {
      case 0, -1, -2: break
      default: try close()
      }
      throw primary
    }
  }
}
