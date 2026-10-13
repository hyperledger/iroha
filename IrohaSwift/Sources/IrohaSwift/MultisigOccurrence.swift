import Foundation

public enum MultisigOccurrenceError: Error, Equatable, Sendable {
    case invalidInput
    case nativeUnavailable
    case nativeRejected(Int32)
    case invalidNativeResult
}

/// Native occurrence identity; retries must retain the original nonce.
public enum MultisigOccurrence {
    static func validateProposalId(_ value: String) throws -> String {
        guard value.utf8.count == 64,
              value.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }),
              value.contains(where: { $0 != "0" }) else { throw MultisigOccurrenceError.invalidInput }
        return value
    }

    public static func derive(networkId: NetworkId, accountId: String, proposalNonce: String) throws -> String {
        guard proposalNonce.count == 64,
              proposalNonce.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }),
              proposalNonce.contains(where: { $0 != "0" }) else { throw MultisigOccurrenceError.invalidInput }
        let request = ["network_id": networkId.description, "account_id": accountId, "proposal_nonce": proposalNonce]
        let input = try JSONEncoder().encode(request)
        guard input.count <= 4096 else { throw MultisigOccurrenceError.invalidInput }
        return try NoritoNativeBridge.shared.deriveMultisigOccurrence(input)
    }
}

extension NoritoNativeBridge {
    func deriveMultisigOccurrence(_ input: Data) throws -> String {
        #if canImport(Darwin)
        typealias Invoke = @convention(c) (UnsafePointer<UInt8>?, CUnsignedLong, UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?, UnsafeMutablePointer<CUnsignedLong>?) -> Int32
        typealias Free = @convention(c) (UnsafeMutablePointer<UInt8>?) -> Void
        guard isAvailable,
              let invoke = resolveNativeSymbol("connect_norito_multisig_proposal_id", as: Invoke.self),
              let free = resolveNativeSymbol("connect_norito_free", as: Free.self) else { throw MultisigOccurrenceError.nativeUnavailable }
        var output: UnsafeMutablePointer<UInt8>?
        var length: CUnsignedLong = 0
        let status = input.withUnsafeBytes { raw in invoke(raw.bindMemory(to: UInt8.self).baseAddress, CUnsignedLong(raw.count), &output, &length) }
        defer { if let output { free(output) } }
        guard status == 0 else { throw MultisigOccurrenceError.nativeRejected(status) }
        guard let output, length == 64,
              let literal = String(data: Data(bytes: output, count: 64), encoding: .utf8),
              literal.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else { throw MultisigOccurrenceError.invalidNativeResult }
        do { return try MultisigOccurrence.validateProposalId(literal) }
        catch { throw MultisigOccurrenceError.invalidNativeResult }
        #else
        throw MultisigOccurrenceError.nativeUnavailable
        #endif
    }
}
