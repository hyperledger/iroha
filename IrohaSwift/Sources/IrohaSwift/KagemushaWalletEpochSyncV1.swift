import Foundation

extension KagemushaWalletV1 {
  /// Synchronize bounded epoch transitions for this exact receipt, without changing value.
  /// Each successful boundary is durable; retry after cancellation or a page limit resumes it.
  /// A full batch may return partial progress; repeat while `boundaryHeight < original.blockHeight`.
  /// Call ordinary `load` afterward; it independently verifies the receipt against retained authority.
  public func synchronizeLoadEpochs(
    original: KagemushaWalletLoadOriginalV1, transport: ToriiClient,
    canonicalAuth: ToriiCanonicalRequestAuth,
    maximumBoundaries: Int = 64,
    requireCurrentOwner: @escaping @Sendable () async throws -> Void
  ) async throws -> KagemushaWalletEpochProgressV1 {
    try await kagemushaWalletSynchronizeEpochsV1(receiptHeight: original.blockHeight,
      maximumBoundaries: maximumBoundaries, requireCurrentOwner: requireCurrentOwner,
      progress: { try self.epochProgress() },
      fetch: { height in
        try await transport.getKagemushaWalletLoadEpochOriginalV1(selection: original.selection,
          boundaryHeight: height, canonicalAuth: canonicalAuth, requireCurrentOwner: requireCurrentOwner)
      }, ingest: { epoch, bytes in try self.ingestEpochBoundary(expectedEpoch: epoch, original: bytes) })
  }
}

// The callbacks separate transport scheduling tests from cryptographic authority: production
// always supplies the installed wallet's sealed progress and ingestion entry points above.
func kagemushaWalletSynchronizeEpochsV1(
  receiptHeight: UInt64, maximumBoundaries: Int,
  requireCurrentOwner: () async throws -> Void,
  progress: () throws -> KagemushaWalletEpochProgressV1,
  fetch: (UInt64) async throws -> Data,
  ingest: (UInt64, Data) throws -> KagemushaWalletEpochProgressV1
) async throws -> KagemushaWalletEpochProgressV1 {
  guard receiptHeight > 0, (1...64).contains(maximumBoundaries) else { throw KagemushaWalletErrorV1.invalidInput }
  try Task.checkCancellation()
  try await requireCurrentOwner()
  var selected = try progress()
  var remaining = maximumBoundaries
  while receiptHeight > selected.boundaryHeight {
    guard remaining > 0 else { break }
    try Task.checkCancellation()
    try await requireCurrentOwner()
    let bytes = try await fetch(selected.boundaryHeight)
    try Task.checkCancellation()
    try await requireCurrentOwner()
    let next = try ingest(selected.epoch, bytes)
    guard next.epoch > selected.epoch, next.boundaryHeight > selected.boundaryHeight else {
      throw KagemushaWalletErrorV1.invalidNativeOutput
    }
    selected = next
    remaining -= 1
  }
  try Task.checkCancellation()
  try await requireCurrentOwner()
  return selected
}
