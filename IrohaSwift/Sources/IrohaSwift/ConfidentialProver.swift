import Foundation

/// An unsigned 128-bit note amount, usable as an integer literal.
/// Swift-managed values and copies do not carry a memory-erasure guarantee.
public struct ConfidentialAmount: Equatable, Sendable, ExpressibleByIntegerLiteral {
    let low: UInt64
    let high: UInt64

    public init(integerLiteral value: UInt64) { low = value; high = 0 }
    public init(_ value: UInt64) { low = value; high = 0 }

    /// Exact decimal spelling for interoperability with note derivation APIs.
    public var decimal: String {
        var lo = low
        var hi = high
        var digits: [UInt8] = []
        repeat {
            let division = UInt64(10).dividingFullWidth((high: hi % 10, low: lo))
            hi /= 10
            lo = division.quotient
            digits.append(UInt8(division.remainder) + 48)
        } while hi != 0 || lo != 0
        return String(decoding: digits.reversed(), as: UTF8.self)
    }

    /// Parse an exact decimal integer with no sign, whitespace or leading zeroes.
    public init(decimal: String) throws {
        guard !decimal.isEmpty, decimal.utf8.count <= 39,
              decimal == "0" || !decimal.hasPrefix("0") else {
            throw ConfidentialProverError.invalidInput("amount")
        }
        var lo: UInt64 = 0
        var hi: UInt64 = 0
        for byte in decimal.utf8 {
            guard byte >= 48, byte <= 57 else {
                throw ConfidentialProverError.invalidInput("amount")
            }
            let product = lo.multipliedFullWidth(by: 10)
            let upper = hi.multipliedReportingOverflow(by: 10)
            let carry = upper.partialValue.addingReportingOverflow(product.high)
            let digit = product.low.addingReportingOverflow(UInt64(byte - 48))
            let final = carry.partialValue.addingReportingOverflow(digit.overflow ? 1 : 0)
            guard !upper.overflow, !carry.overflow, !final.overflow else {
                throw ConfidentialProverError.invalidInput("amount")
            }
            lo = digit.partialValue
            hi = final.partialValue
        }
        low = lo
        high = hi
    }
}

/// One actual owned note; an absent second note needs no dummy witness.
public struct ConfidentialInput: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public let amount: ConfidentialAmount
    public let rho: Data
    public let diversifier: Data
    public let leafIndex: UInt64

    public init(amount: ConfidentialAmount, rho: Data, diversifier: Data, leafIndex: UInt64) throws {
        guard rho.count == 32, diversifier.count == 32, leafIndex < 65_536 else {
            throw ConfidentialProverError.invalidInput("input note")
        }
        self.amount = amount; self.rho = rho; self.diversifier = diversifier; self.leafIndex = leafIndex
    }
    public var description: String { "ConfidentialInput([REDACTED])" }
    public var debugDescription: String { description }
}

/// A transfer output. Generate `rho` with a cryptographically secure random source.
public struct ConfidentialOutput: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public let amount: ConfidentialAmount
    public let rho: Data
    public let ownerTag: Data

    public init(amount: ConfidentialAmount, rho: Data, ownerTag: Data) throws {
        guard rho.count == 32, ownerTag.count == 32 else {
            throw ConfidentialProverError.invalidInput("output note")
        }
        self.amount = amount; self.rho = rho; self.ownerTag = ownerTag
    }
    public var description: String { "ConfidentialOutput([REDACTED])" }
    public var debugDescription: String { description }
}

/// Private change returned to this wallet during partial redemption.
public struct ConfidentialChange: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public let amount: ConfidentialAmount
    public let rho: Data

    public init(amount: ConfidentialAmount, rho: Data) throws {
        guard rho.count == 32 else { throw ConfidentialProverError.invalidInput("change note") }
        self.amount = amount; self.rho = rho
    }
    /// Retain this opening and use its authenticated tree index when spending change.
    /// The native default owner is independent of the consumed notes' diversifiers.
    public func asInput(leafIndex: UInt64) throws -> ConfidentialInput {
        guard leafIndex < 65_536 else {
            throw ConfidentialProverError.invalidInput("input note")
        }
        return try ConfidentialInput(amount: amount, rho: rho,
                                     diversifier: ConfidentialOwnerTag.defaultDiversifier(),
                                     leafIndex: leafIndex)
    }
    public var description: String { "ConfidentialChange([REDACTED])" }
    public var debugDescription: String { description }
}

/// Authenticate the expected root independently, then supply complete leaves or actual-input paths.
public enum ConfidentialTree: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    case commitments(root: Data, leaves: [Data])
    case paths(root: Data, paths: [ZkAssetMerklePath])

    var root: Data {
        switch self {
        case let .commitments(root, _), let .paths(root, _): return root
        }
    }
    func validate(inputs: [ConfidentialInput]) throws {
        guard root.count == 32 else { throw ConfidentialProverError.invalidInput("root") }
        switch self {
        case let .commitments(_, leaves):
            guard leaves.count <= 65_536, leaves.allSatisfy({ $0.count == 32 }),
                  inputs.allSatisfy({ $0.leafIndex < UInt64(leaves.count) }) else {
                throw ConfidentialProverError.invalidInput("commitments or input index")
            }
        case let .paths(root, paths):
            guard paths.count == inputs.count else {
                throw ConfidentialProverError.invalidInput("one path per input note is required")
            }
            for (input, path) in zip(inputs, paths) {
                guard path.rootAtHeight == root, path.leafIndex == input.leafIndex,
                      path.siblings.count == 16, path.directions.count == 16 else {
                    throw ConfidentialProverError.invalidInput("path root, index or depth")
                }
            }
        }
    }
    public var description: String { "ConfidentialTree([REDACTED])" }
    public var debugDescription: String { description }
}

/// A locally verified proof artifact. Creating it submits no transaction.
public struct ConfidentialProof: Sendable {
    public enum Relation: String, Sendable {
        case transfer
        case fullRedemption
        case redemptionWithChange
    }
    public let relation: Relation
    public let backend: String
    public let proof: Data
    public let root: Data
    public let nullifiers: [Data]
    public let outputCommitments: [Data]
}

/// Stable local proving failures; no private witness values are included.
public enum ConfidentialProverError: Error, Equatable, Sendable, LocalizedError {
    case bridgeUnavailable
    case closed
    case invalidInput(String)
    case native(code: Int32)
    case invalidNativeOutput

    public var errorDescription: String? {
        switch self {
        case .bridgeUnavailable: return "The current confidential proving native bridge is required."
        case .closed: return "The confidential prover is closed."
        case let .invalidInput(field): return "Invalid confidential proving input: \(field)."
        case let .native(code):
            switch code {
            case -3: return "The native prover is busy; close unused wallets or wait for active jobs."
            case -10: return "Provide a nonzero 32-byte spend key."
            case -11: return "Provide one or two actual input notes."
            case -12: return "The confidential tree exceeds its fixed capacity."
            case -13, -14, -15, -16: return "Check each input's membership path, root and leaf index."
            case -17: return "An input note was supplied more than once."
            case -18: return "Provide one or two transfer outputs."
            case -19, -20, -21, -22: return "Check note amounts, public redemption and change conservation."
            case -23: return "Native proving key preparation failed."
            case -24: return "The native proof could not be produced and locally verified."
            default: return "Native confidential proving failed (code \(code))."
            }
        case .invalidNativeOutput: return "The native prover returned inconsistent proof material."
        }
    }
}

protocol ConfidentialProverDriver: AnyObject, Sendable {
    func create(network: NetworkId, asset: String, key: Data) throws -> UInt64
    func close(_ handle: UInt64) throws
    func createJob(_ handle: UInt64, transfer: Bool, root: Data, publicAmount: ConfidentialAmount) throws -> UInt64
    func input(_ job: UInt64, note: ConfidentialInput) throws
    func output(_ job: UInt64, amount: ConfidentialAmount, rho: Data, owner: Data) throws
    func evidence(_ job: UInt64, tree: ConfidentialTree) throws
    func prove(_ job: UInt64) throws -> Data
    func closeJob(_ job: UInt64)
}

/// Owns a clearing native spend key and automatically selects the circuit and keys.
///
/// Proof work runs on a background queue. `close()` rejects future jobs; jobs
/// already accepted retain their native key until completion. Task cancellation
/// does not interrupt an accepted native proof. Swift `Data` copies do not carry
/// an erasure guarantee. Protocol admission still decides whether an artifact
/// can authorize a ledger operation.
public final class ConfidentialProver: @unchecked Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    private let driver: ConfidentialProverDriver
    private let lock = NSLock()
    private var handle: UInt64

    public convenience init(networkId: NetworkId, assetDefinitionId: String, spendKey: Data) throws {
        #if canImport(Darwin)
        try self.init(networkId: networkId, assetDefinitionId: assetDefinitionId,
                      spendKey: spendKey, driver: ConfidentialProverNativeDriver())
        #else
        throw ConfidentialProverError.bridgeUnavailable
        #endif
    }

    init(networkId: NetworkId, assetDefinitionId: String, spendKey: Data,
         driver: ConfidentialProverDriver) throws {
        guard spendKey.count == 32, spendKey.contains(where: { $0 != 0 }),
              assetDefinitionId.utf8.count <= 512,
              AssetDefinitionAddressCodec.canonicalDefinitionLiteral(assetDefinitionId) == assetDefinitionId else {
            throw ConfidentialProverError.invalidInput("spend key or canonical asset")
        }
        self.driver = driver
        handle = try driver.create(network: networkId, asset: assetDefinitionId, key: spendKey)
        guard handle != 0 else { throw ConfidentialProverError.invalidNativeOutput }
    }

    deinit { try? close() }
    public var description: String { "ConfidentialProver(privateContext: [REDACTED])" }
    public var debugDescription: String { description }

    /// Close this wallet. Calling it again is harmless; accepted work remains valid.
    public func close() throws {
        lock.lock()
        let owner = handle
        handle = 0
        lock.unlock()
        if owner != 0 { try driver.close(owner) }
    }

    public func proveTransfer(tree: ConfidentialTree, inputs: [ConfidentialInput],
                              outputs: [ConfidentialOutput]) async throws -> ConfidentialProof {
        guard (1...2).contains(outputs.count) else {
            throw ConfidentialProverError.invalidInput("output count")
        }
        let job = try prepare(tree: tree, inputs: inputs, transfer: true, publicAmount: 0)
        for note in outputs {
            try driver.output(job.handle, amount: note.amount, rho: note.rho, owner: note.ownerTag)
        }
        try driver.evidence(job.handle, tree: tree)
        return try await finish(job, root: tree.root, inputs: inputs.count,
                                outputs: outputs.count, relation: .transfer)
    }

    public func proveUnshield(tree: ConfidentialTree, inputs: [ConfidentialInput],
                              publicAmount: ConfidentialAmount,
                              change: ConfidentialChange? = nil) async throws -> ConfidentialProof {
        let job = try prepare(tree: tree, inputs: inputs, transfer: false, publicAmount: publicAmount)
        if let change {
            try driver.output(job.handle, amount: change.amount, rho: change.rho, owner: Data())
        }
        try driver.evidence(job.handle, tree: tree)
        return try await finish(job, root: tree.root, inputs: inputs.count,
                                outputs: change == nil ? 0 : 1,
                                relation: change == nil ? .fullRedemption : .redemptionWithChange)
    }

    private func prepare(tree: ConfidentialTree, inputs: [ConfidentialInput], transfer: Bool,
                         publicAmount: ConfidentialAmount) throws -> ConfidentialNativeJob {
        guard (1...2).contains(inputs.count) else {
            throw ConfidentialProverError.invalidInput("input count")
        }
        try tree.validate(inputs: inputs)
        lock.lock()
        let jobHandle: UInt64
        do {
            guard handle != 0 else { throw ConfidentialProverError.closed }
            jobHandle = try driver.createJob(handle, transfer: transfer, root: tree.root,
                                              publicAmount: publicAmount)
            lock.unlock()
        } catch {
            lock.unlock()
            throw error
        }
        guard jobHandle != 0 else { throw ConfidentialProverError.invalidNativeOutput }
        let job = ConfidentialNativeJob(jobHandle, driver: driver)
        for input in inputs { try driver.input(job.handle, note: input) }
        return job
    }

    private func finish(_ job: ConfidentialNativeJob, root: Data, inputs: Int, outputs: Int,
                        relation: ConfidentialProof.Relation) async throws -> ConfidentialProof {
        try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                do {
                    let data = try job.prove()
                    continuation.resume(returning: try ConfidentialProof.decode(
                        data, root: root, inputs: inputs, outputs: outputs, relation: relation
                    ))
                } catch { continuation.resume(throwing: error) }
            }
        }
    }
}

/// One native-owned job, removed exactly once even on partial wrapper failure.
private final class ConfidentialNativeJob: @unchecked Sendable {
    private(set) var handle: UInt64
    private let driver: ConfidentialProverDriver
    init(_ handle: UInt64, driver: ConfidentialProverDriver) { self.handle = handle; self.driver = driver }
    deinit { if handle != 0 { driver.closeJob(handle) } }
    func prove() throws -> Data {
        let consumed = handle
        handle = 0
        // The native call normally consumes the job. A driver can fail before
        // entering it, so also close on return; already-consumed handles are harmless.
        defer { driver.closeJob(consumed) }
        return try driver.prove(consumed)
    }
}

extension ConfidentialProof {
    static func decode(_ data: Data, root: Data, inputs: Int, outputs: Int,
                       relation: Relation) throws -> ConfidentialProof {
        struct Envelope: Decodable {
            let relation: String
            let backend: String
            let proof_hex: String
            let root_hex: String
            let nullifiers_hex: [String]
            let output_commitments_hex: [String]
        }
        do {
            guard data.count <= 16 * 1024 * 1024 else { throw ConfidentialProverError.invalidNativeOutput }
            let value = try JSONDecoder().decode(Envelope.self, from: data)
            let tag: String
            switch relation {
            case .transfer: tag = "confidential_transfer"
            case .fullRedemption: tag = "confidential_full_unshield"
            case .redemptionWithChange: tag = "confidential_change_unshield"
            }
            func bytes(_ text: String, count: Int? = nil) throws -> Data {
                guard !text.isEmpty, text.utf8.count % 2 == 0,
                      text.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }),
                      count == nil || text.utf8.count == count! * 2,
                      let decoded = Data(hexString: text) else {
                    throw ConfidentialProverError.invalidNativeOutput
                }
                return decoded
            }
            guard value.relation == tag, value.backend == "pipa-r/pasta",
                  value.nullifiers_hex.count == inputs, value.output_commitments_hex.count == outputs,
                  try bytes(value.root_hex, count: 32) == root else {
                throw ConfidentialProverError.invalidNativeOutput
            }
            return ConfidentialProof(relation: relation, backend: value.backend,
                                     proof: try bytes(value.proof_hex), root: root,
                                     nullifiers: try value.nullifiers_hex.map { try bytes($0, count: 32) },
                                     outputCommitments: try value.output_commitments_hex.map { try bytes($0, count: 32) })
        } catch { throw ConfidentialProverError.invalidNativeOutput }
    }
}
