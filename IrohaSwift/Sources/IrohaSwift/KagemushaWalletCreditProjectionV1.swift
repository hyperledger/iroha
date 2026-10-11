import Foundation

/// Native-authenticated evidence for one credit. Display data never grants operation permission.
public struct KagemushaWalletCreditProjectionV1: Sendable, Equatable {
    public enum Evidence: UInt8, Sendable { case unfolded = 1, credited = 2, burned = 3 }
    public enum Archive: UInt8, Sendable { case receiver = 0, awaitingFold = 1, removed = 2, retained = 3 }
    public let evidence: Evidence
    public let archive: Archive
    public let corePending: Bool
    public let creditId: Data
    public let paymentDigest: Data
    public let amount: KagemushaWalletUInt128V1
    /// Fresh Native-generated receiver evidence. Payer observations never carry an original.
    public let creditedOriginal: Data?

    init(_ result: KagemushaWalletCallV1) throws {
        let bytes = [UInt8](result.bytes)
        guard result.status == 47, result.sequenceLow == 0, result.sequenceHigh == 0,
            result.detail == 0, (92...10_092).contains(bytes.count),
            bytes[0] == 1, bytes[1] == 0,
            let evidence = Evidence(rawValue: bytes[2]),
            let archive = Archive(rawValue: bytes[3]), bytes[4] <= 1,
            bytes[5..<8].allSatisfy({ $0 == 0 })
        else { throw KagemushaWalletErrorV1.invalidNativeOutput }
        func u64(_ at: Int) -> UInt64 {
            (0..<8).reduce(UInt64(0)) { $0 | (UInt64(bytes[at + $1]) << (8 * $1)) }
        }
        let credit = Data(bytes[8..<40]), payment = Data(bytes[40..<72])
        let amount = KagemushaWalletUInt128V1(low: u64(72), high: u64(80))
        let length = (0..<4).reduce(UInt32(0)) { $0 | (UInt32(bytes[88 + $1]) << (8 * $1)) }
        guard credit.contains(where: { $0 != 0 }), payment.contains(where: { $0 != 0 }),
            amount.low != 0 || amount.high != 0,
            length <= 10_000, bytes.count == 92 + Int(length),
            archive == .receiver ? (bytes[4] == 0 && length > 0) : length == 0
        else { throw KagemushaWalletErrorV1.invalidNativeOutput }
        self.evidence = evidence; self.archive = archive; corePending = bytes[4] == 1
        creditId = credit; paymentDigest = payment; self.amount = amount
        creditedOriginal = length == 0 ? nil : Data(bytes[92...])
    }

    func requireReceiver() throws -> Self {
        guard archive == .receiver else { throw KagemushaWalletErrorV1.invalidNativeOutput }
        return self
    }
    func requirePayer() throws -> Self {
        guard archive != .receiver else { throw KagemushaWalletErrorV1.invalidNativeOutput }
        return self
    }
}

extension KagemushaWalletV1 {
    /// Read this Receive's current credit evidence and exact Native-generated Credited original.
    public func creditProjection(receiveRequestId: Data) throws -> KagemushaWalletCreditProjectionV1 {
        try KagemushaWalletCreditProjectionV1(setup(.init(selector: 43, identity: receiveRequestId)))
            .requireReceiver()
    }

    /// Keep receiver burn evidence separate from this Send's Archive fold progress.
    /// The first original anchors the completed Archive; an optional newer original cannot replace it.
    public func deliveryProjection(sendRequestId: Data, archiveCredited: Data,
        newerCredited: Data? = nil) throws -> KagemushaWalletCreditProjectionV1 {
        guard newerCredited.map({ !$0.isEmpty }) ?? true else { throw KagemushaWalletErrorV1.invalidInput }
        return try KagemushaWalletCreditProjectionV1(setup(.init(selector: 44, identity: sendRequestId,
            first: archiveCredited, second: newerCredited ?? Data()))).requirePayer()
    }
}
