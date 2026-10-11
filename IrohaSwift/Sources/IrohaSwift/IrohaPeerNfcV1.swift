import Foundation

// TODO(G4): carry the payer's Offer, its optional Lineage (IPM1 kind `lineage`) and
// SessionControl envelopes over NFC. Until then the receiver obtains the Offer before
// it builds the Request, over another carrier of the same envelope, and verifies Ω(pred)
// from the Payment.

/// Transport-neutral NFC V1 constants for exchanging `IPM1` messages.
///
/// V1 has one application identifier, one command set, and no codec negotiation
/// or fallback. One session carries the KAGEMUSHA wallet Request (hosted by the
/// receiver), the payer's Payment and the receiver's durable acknowledgement, which
/// is the wallet's Credited envelope (IPM1 kind `credited`).
public enum IrohaPeerNfcV1 {
    /// ISO/IEC 7816 application identifier `F0504B45504B524E464301`.
    public static let applicationIdentifierHex = "F0504B45504B524E464301"
    public static let applicationIdentifier = decodeHex(applicationIdentifierHex)
    public static let buildProfileMarker = "IrohaPeerNfcV1.AID.F0504B45504B524E464301"
    public static let commandClass: UInt8 = 0x80
    public static let wireVersion: UInt8 = 1
    public static let sessionIDBytes = 16
    public static let hashBytes = 32
    public static let maximumChunkBytes = 4_096
    public static let maximumMessageBytes =
        IrohaPeerWireMessageV1.headerBytes + IrohaPeerWireLimitsV1.maximumWalletProfileBytes
    public static let infoBytes = 98
    public static let statusBytes = 174

    private static func decodeHex(_ value: String) -> Data {
        precondition(value.count.isMultiple(of: 2))
        var bytes = Data()
        bytes.reserveCapacity(value.count / 2)
        var cursor = value.startIndex
        while cursor < value.endIndex {
            let next = value.index(cursor, offsetBy: 2)
            guard let byte = UInt8(value[cursor..<next], radix: 16) else {
                preconditionFailure("Iroha peer NFC AID must be hexadecimal")
            }
            bytes.append(byte)
            cursor = next
        }
        return bytes
    }
    public static let paymentAdmissionBytes = 244

    fileprivate static let infoMagic = Data("INF1".utf8)
    fileprivate static let statusMagic = Data("NST1".utf8)
    fileprivate static let paymentAdmissionMagic = Data("IPA1".utf8)
    fileprivate static let durableAckMagic = Data("IDA1".utf8)
    fileprivate static let senderCheckpointMagic = Data("ISC1".utf8)
}

/// The only proprietary instructions accepted by Iroha peer NFC V1.
public enum IrohaPeerNfcInstructionV1: UInt8, CaseIterable, Sendable {
    case getInfo = 0x10
    case readRequest = 0x11
    case beginPayment = 0x20
    case write = 0x21
    case commit = 0x22
    case readAcknowledgement = 0x23
    case confirmAcknowledgement = 0x24
    case getStatus = 0x25
}

/// Receiver phases exposed by `GET_INFO` and `GET_STATUS`.
public enum IrohaPeerNfcPhaseV1: UInt8, CaseIterable, Sendable {
    case requestReady = 1
    case paymentReceiving = 2
    case acknowledgementReady = 3
    case complete = 4
}

/// Capabilities and durability boundaries advertised in NFC status records.
public struct IrohaPeerNfcFlagsV1: OptionSet, Equatable, Sendable {
    public let rawValue: UInt8

    public init(rawValue: UInt8) {
        self.rawValue = rawValue
    }

    /// Replayed or partially overlapping `WRITE` commands are accepted only
    /// when every already-received byte is identical.
    public static let idempotentWrites = IrohaPeerNfcFlagsV1(rawValue: 1 << 0)
    /// The acknowledgement was persisted before `COMMIT` returned success.
    public static let durableAcknowledgement = IrohaPeerNfcFlagsV1(rawValue: 1 << 1)

    fileprivate static let known: IrohaPeerNfcFlagsV1 = [
        .idempotentWrites,
        .durableAcknowledgement,
    ]
}

/// Bounded message and APDU chunk sizes for a peer NFC endpoint.
public struct IrohaPeerNfcLimitsV1: Equatable, Sendable {
    public let maximumMessageBytes: Int
    public let maximumReadChunkBytes: Int
    public let maximumWriteChunkBytes: Int

    public init(
        maximumMessageBytes: Int = IrohaPeerNfcV1.maximumMessageBytes,
        maximumReadChunkBytes: Int = IrohaPeerNfcV1.maximumChunkBytes,
        maximumWriteChunkBytes: Int = IrohaPeerNfcV1.maximumChunkBytes
    ) {
        precondition(
            Self.areValid(
                maximumMessageBytes: maximumMessageBytes,
                maximumReadChunkBytes: maximumReadChunkBytes,
                maximumWriteChunkBytes: maximumWriteChunkBytes
            )
        )
        self.maximumMessageBytes = maximumMessageBytes
        self.maximumReadChunkBytes = maximumReadChunkBytes
        self.maximumWriteChunkBytes = maximumWriteChunkBytes
    }

    public static let `default` = IrohaPeerNfcLimitsV1()

    static func areValid(
        maximumMessageBytes: Int,
        maximumReadChunkBytes: Int,
        maximumWriteChunkBytes: Int
    ) -> Bool {
        (IrohaPeerWireMessageV1.headerBytes...IrohaPeerNfcV1.maximumMessageBytes)
            .contains(maximumMessageBytes) &&
            (1...IrohaPeerNfcV1.maximumChunkBytes).contains(maximumReadChunkBytes) &&
            (1...IrohaPeerNfcV1.maximumChunkBytes).contains(maximumWriteChunkBytes)
    }
}

/// One immutable application profile for every IPM1 phase in an NFC session.
/// Receive request, payment, and acknowledgement (Credited) must all use this profile.
public struct IrohaPeerNfcProfilePolicyV1: Equatable, Sendable {
    public let profile: IrohaPeerPayloadProfile

    public init(profile: IrohaPeerPayloadProfile) {
        precondition(profile != .reject)
        self.profile = profile
    }

    /// Convenience spelling equivalent to `init(profile:)`.
    public static func sameProfile(
        _ profile: IrohaPeerPayloadProfile
    ) -> IrohaPeerNfcProfilePolicyV1 {
        IrohaPeerNfcProfilePolicyV1(profile: profile)
    }

    public func accepts(_ candidate: IrohaPeerPayloadProfile) -> Bool {
        profile == candidate
    }
}

public enum IrohaPeerNfcErrorV1: Error, Equatable, LocalizedError, Sendable {
    case invalidApplicationIdentifier
    case invalidCommandClass(UInt8)
    case unsupportedInstruction(UInt8)
    case invalidAPDU
    case invalidLength
    case messageTooLarge(actual: Int, maximum: Int)
    case invalidOffset
    case invalidSession
    case invalidHash
    case invalidProfile
    case invalidKind
    case invalidFlags
    case invalidIPM1
    case continuityMismatch
    case conflictingReplay
    case stateMismatch
    case durableAdmissionRequired
    case durableCommitRequired
    case acknowledgementNotDurable
    case peerRejected(operation: IrohaPeerNfcOperationV1)
    case peerPersistenceFailure(operation: IrohaPeerNfcOperationV1)

    public var errorDescription: String? {
        switch self {
        case .invalidApplicationIdentifier:
            return "The Iroha peer NFC application identifier is invalid."
        case .invalidCommandClass(let value):
            return String(format: "Unsupported NFC command class %02X.", value)
        case .unsupportedInstruction(let value):
            return String(format: "Unsupported NFC instruction %02X.", value)
        case .invalidAPDU: return "The NFC command APDU is malformed."
        case .invalidLength: return "The NFC record length is invalid."
        case .messageTooLarge(let actual, let maximum):
            return "The NFC message is \(actual) bytes; the limit is \(maximum)."
        case .invalidOffset: return "The NFC chunk offset is invalid."
        case .invalidSession: return "The NFC session identifier is invalid."
        case .invalidHash: return "The NFC message hash is invalid."
        case .invalidProfile: return "The NFC payload profile is invalid."
        case .invalidKind: return "The NFC IPM1 message kind is invalid."
        case .invalidFlags: return "The NFC status flags are invalid."
        case .invalidIPM1: return "The NFC payload is not a valid IPM1 message."
        case .continuityMismatch: return "The NFC transfer continuity does not match."
        case .conflictingReplay: return "The NFC retry conflicts with already-received bytes."
        case .stateMismatch: return "The NFC command is not valid in the current phase."
        case .durableAdmissionRequired:
            return "BEGIN_PAYMENT requires application-provided durable admission."
        case .durableCommitRequired:
            return "COMMIT requires an application-provided durable acknowledgement."
        case .acknowledgementNotDurable:
            return "The acknowledgement must be durable before it can be confirmed."
        case .peerRejected(let operation):
            return "The nearby NFC peer rejected \(operation.rawValue)."
        case .peerPersistenceFailure(let operation):
            return "The nearby NFC peer could not durably persist \(operation.rawValue)."
        }
    }
}

/// Stable command names used by typed peer failures without exposing APDU
/// bytes or collapsing persistence failures into generic state errors.
public enum IrohaPeerNfcOperationV1: String, CaseIterable, Sendable {
    case selectApplication
    case getInfo
    case readRequest
    case beginPayment
    case write
    case commit
    case readAcknowledgement
    case confirmAcknowledgement
    case getStatus
}

/// Marker for a transport error that makes delivery of the final CONFIRM
/// response unknowable. Other errors remain deterministic failures.
public protocol IrohaPeerNfcAmbiguousResponseErrorV1: Error, Sendable {}

/// Stable request identity shared by the NFC reader and card endpoint.
public struct IrohaPeerNfcRequestIdentityV1: Equatable, Sendable {
    public let profile: IrohaPeerPayloadProfile
    public let sessionID: Data
    public let requestCanonicalHash: Data
    public let requestWireHash: Data

    public init(
        profile: IrohaPeerPayloadProfile,
        sessionID: Data,
        requestCanonicalHash: Data,
        requestWireHash: Data
    ) throws {
        guard profile != .reject else { throw IrohaPeerNfcErrorV1.invalidProfile }
        try nfcRequireSession(sessionID)
        try nfcRequireHash(requestCanonicalHash)
        try nfcRequireHash(requestWireHash)
        self.profile = profile
        self.sessionID = Data(sessionID)
        self.requestCanonicalHash = Data(requestCanonicalHash)
        self.requestWireHash = Data(requestWireHash)
    }
}

/// Fixed 98-byte response to `GET_INFO`.
public struct IrohaPeerNfcInfoV1: Equatable, Sendable {
    public let phase: IrohaPeerNfcPhaseV1
    public let flags: IrohaPeerNfcFlagsV1
    public let identity: IrohaPeerNfcRequestIdentityV1
    public let requestLength: Int
    public let maximumReadChunkBytes: Int
    public let maximumWriteChunkBytes: Int

    public init(
        phase: IrohaPeerNfcPhaseV1,
        flags: IrohaPeerNfcFlagsV1,
        identity: IrohaPeerNfcRequestIdentityV1,
        requestLength: Int,
        maximumReadChunkBytes: Int,
        maximumWriteChunkBytes: Int
    ) throws {
        guard flags.subtracting(.known).isEmpty else {
            throw IrohaPeerNfcErrorV1.invalidFlags
        }
        guard requestLength > IrohaPeerWireMessageV1.headerBytes,
              requestLength <= IrohaPeerNfcV1.maximumMessageBytes else {
            throw IrohaPeerNfcErrorV1.invalidLength
        }
        try nfcRequireChunkLimit(maximumReadChunkBytes)
        try nfcRequireChunkLimit(maximumWriteChunkBytes)
        let mustBeDurable = phase == .acknowledgementReady || phase == .complete
        guard flags.contains(.idempotentWrites),
              flags.contains(.durableAcknowledgement) == mustBeDurable else {
            throw IrohaPeerNfcErrorV1.invalidFlags
        }
        self.phase = phase
        self.flags = flags
        self.identity = identity
        self.requestLength = requestLength
        self.maximumReadChunkBytes = maximumReadChunkBytes
        self.maximumWriteChunkBytes = maximumWriteChunkBytes
    }

    public func encode() -> Data {
        var output = IrohaPeerNfcV1.infoMagic
        output.append(IrohaPeerNfcV1.wireVersion)
        output.append(phase.rawValue)
        output.nfcAppendUInt16BE(identity.profile.rawValue)
        output.append(flags.rawValue)
        output.append(0)
        output.append(identity.sessionID)
        output.nfcAppendUInt32BE(UInt32(requestLength))
        output.append(identity.requestCanonicalHash)
        output.append(identity.requestWireHash)
        output.nfcAppendUInt16BE(UInt16(maximumReadChunkBytes))
        output.nfcAppendUInt16BE(UInt16(maximumWriteChunkBytes))
        precondition(output.count == IrohaPeerNfcV1.infoBytes)
        return output
    }

    public static func decode(_ data: Data) throws -> Self {
        guard data.count == IrohaPeerNfcV1.infoBytes else {
            throw IrohaPeerNfcErrorV1.invalidLength
        }
        guard data.prefix(4) == IrohaPeerNfcV1.infoMagic,
              data[4] == IrohaPeerNfcV1.wireVersion else {
            throw IrohaPeerNfcErrorV1.invalidAPDU
        }
        guard let phase = IrohaPeerNfcPhaseV1(rawValue: data[5]),
              let profile = IrohaPeerPayloadProfile(rawValue: data.nfcUInt16BE(at: 6)),
              profile != .reject,
              data[9] == 0 else {
            throw IrohaPeerNfcErrorV1.invalidAPDU
        }
        let identity = try IrohaPeerNfcRequestIdentityV1(
            profile: profile,
            sessionID: data.subdata(in: 10..<26),
            requestCanonicalHash: data.subdata(in: 30..<62),
            requestWireHash: data.subdata(in: 62..<94)
        )
        return try Self(
            phase: phase,
            flags: IrohaPeerNfcFlagsV1(rawValue: data[8]),
            identity: identity,
            requestLength: Int(data.nfcUInt32BE(at: 26)),
            maximumReadChunkBytes: Int(data.nfcUInt16BE(at: 94)),
            maximumWriteChunkBytes: Int(data.nfcUInt16BE(at: 96))
        )
    }
}

/// Fixed 174-byte response to `GET_STATUS`.
public struct IrohaPeerNfcStatusV1: Equatable, Sendable {
    public let phase: IrohaPeerNfcPhaseV1
    public let flags: IrohaPeerNfcFlagsV1
    public let identity: IrohaPeerNfcRequestIdentityV1
    public let paymentProfile: IrohaPeerPayloadProfile?
    public let paymentLength: Int
    public let receivedPaymentBytes: Int
    public let paymentWireHash: Data
    public let acknowledgementProfile: IrohaPeerPayloadProfile?
    public let acknowledgementLength: Int
    public let acknowledgementWireHash: Data
    public let maximumReadChunkBytes: Int
    public let maximumWriteChunkBytes: Int

    public init(
        phase: IrohaPeerNfcPhaseV1,
        flags: IrohaPeerNfcFlagsV1,
        identity: IrohaPeerNfcRequestIdentityV1,
        paymentProfile: IrohaPeerPayloadProfile?,
        paymentLength: Int,
        receivedPaymentBytes: Int,
        paymentWireHash: Data,
        acknowledgementProfile: IrohaPeerPayloadProfile?,
        acknowledgementLength: Int,
        acknowledgementWireHash: Data,
        maximumReadChunkBytes: Int,
        maximumWriteChunkBytes: Int
    ) throws {
        guard flags.subtracting(.known).isEmpty,
              flags.contains(.idempotentWrites) else {
            throw IrohaPeerNfcErrorV1.invalidFlags
        }
        try nfcRequireChunkLimit(maximumReadChunkBytes)
        try nfcRequireChunkLimit(maximumWriteChunkBytes)
        let zeroHash = Data(repeating: 0, count: IrohaPeerNfcV1.hashBytes)
        let isValid: Bool
        switch phase {
        case .requestReady:
            isValid = paymentLength == 0
                && paymentProfile == nil
                && receivedPaymentBytes == 0
                && paymentWireHash == zeroHash
                && acknowledgementProfile == nil
                && acknowledgementLength == 0
                && acknowledgementWireHash == zeroHash
                && !flags.contains(.durableAcknowledgement)
        case .paymentReceiving:
            isValid = paymentProfile != nil
                && paymentProfile != .reject
                && paymentLength > IrohaPeerWireMessageV1.headerBytes
                && paymentLength <= IrohaPeerNfcV1.maximumMessageBytes
                && receivedPaymentBytes >= 0
                && receivedPaymentBytes <= paymentLength
                && paymentWireHash.count == IrohaPeerNfcV1.hashBytes
                && paymentWireHash != zeroHash
                && acknowledgementProfile == nil
                && acknowledgementLength == 0
                && acknowledgementWireHash == zeroHash
                && !flags.contains(.durableAcknowledgement)
        case .acknowledgementReady, .complete:
            isValid = paymentProfile != nil
                && paymentProfile != .reject
                && paymentLength > IrohaPeerWireMessageV1.headerBytes
                && paymentLength <= IrohaPeerNfcV1.maximumMessageBytes
                && receivedPaymentBytes == paymentLength
                && paymentWireHash.count == IrohaPeerNfcV1.hashBytes
                && paymentWireHash != zeroHash
                && acknowledgementProfile != nil
                && acknowledgementProfile != .reject
                && acknowledgementLength > IrohaPeerWireMessageV1.headerBytes
                && acknowledgementLength <= IrohaPeerNfcV1.maximumMessageBytes
                && acknowledgementWireHash.count == IrohaPeerNfcV1.hashBytes
                && acknowledgementWireHash != zeroHash
                && flags.contains(.durableAcknowledgement)
        }
        guard isValid else { throw IrohaPeerNfcErrorV1.invalidLength }
        self.phase = phase
        self.flags = flags
        self.identity = identity
        self.paymentProfile = paymentProfile
        self.paymentLength = paymentLength
        self.receivedPaymentBytes = receivedPaymentBytes
        self.paymentWireHash = Data(paymentWireHash)
        self.acknowledgementProfile = acknowledgementProfile
        self.acknowledgementLength = acknowledgementLength
        self.acknowledgementWireHash = Data(acknowledgementWireHash)
        self.maximumReadChunkBytes = maximumReadChunkBytes
        self.maximumWriteChunkBytes = maximumWriteChunkBytes
    }

    public func encode() -> Data {
        var output = IrohaPeerNfcV1.statusMagic
        output.append(IrohaPeerNfcV1.wireVersion)
        output.append(phase.rawValue)
        output.nfcAppendUInt16BE(identity.profile.rawValue)
        output.append(flags.rawValue)
        output.append(0)
        output.append(identity.sessionID)
        output.append(identity.requestCanonicalHash)
        output.append(identity.requestWireHash)
        output.nfcAppendUInt16BE(paymentProfile?.rawValue ?? 0)
        output.nfcAppendUInt32BE(UInt32(paymentLength))
        output.nfcAppendUInt32BE(UInt32(receivedPaymentBytes))
        output.append(paymentWireHash)
        output.nfcAppendUInt16BE(acknowledgementProfile?.rawValue ?? 0)
        output.nfcAppendUInt32BE(UInt32(acknowledgementLength))
        output.append(acknowledgementWireHash)
        output.nfcAppendUInt16BE(UInt16(maximumReadChunkBytes))
        output.nfcAppendUInt16BE(UInt16(maximumWriteChunkBytes))
        precondition(output.count == IrohaPeerNfcV1.statusBytes)
        return output
    }

    public static func decode(_ data: Data) throws -> Self {
        guard data.count == IrohaPeerNfcV1.statusBytes else {
            throw IrohaPeerNfcErrorV1.invalidLength
        }
        guard data.prefix(4) == IrohaPeerNfcV1.statusMagic,
              data[4] == IrohaPeerNfcV1.wireVersion,
              let phase = IrohaPeerNfcPhaseV1(rawValue: data[5]),
              let profile = IrohaPeerPayloadProfile(rawValue: data.nfcUInt16BE(at: 6)),
              profile != .reject,
              data[9] == 0 else {
            throw IrohaPeerNfcErrorV1.invalidAPDU
        }
        let identity = try IrohaPeerNfcRequestIdentityV1(
            profile: profile,
            sessionID: data.subdata(in: 10..<26),
            requestCanonicalHash: data.subdata(in: 26..<58),
            requestWireHash: data.subdata(in: 58..<90)
        )
        let rawPaymentProfile = data.nfcUInt16BE(at: 90)
        let paymentProfile = rawPaymentProfile == 0
            ? nil
            : IrohaPeerPayloadProfile(rawValue: rawPaymentProfile)
        let rawAcknowledgementProfile = data.nfcUInt16BE(at: 132)
        let acknowledgementProfile = rawAcknowledgementProfile == 0
            ? nil
            : IrohaPeerPayloadProfile(rawValue: rawAcknowledgementProfile)
        guard rawPaymentProfile == 0 || paymentProfile != nil,
              rawAcknowledgementProfile == 0 || acknowledgementProfile != nil else {
            throw IrohaPeerNfcErrorV1.invalidProfile
        }
        return try Self(
            phase: phase,
            flags: IrohaPeerNfcFlagsV1(rawValue: data[8]),
            identity: identity,
            paymentProfile: paymentProfile,
            paymentLength: Int(data.nfcUInt32BE(at: 92)),
            receivedPaymentBytes: Int(data.nfcUInt32BE(at: 96)),
            paymentWireHash: data.subdata(in: 100..<132),
            acknowledgementProfile: acknowledgementProfile,
            acknowledgementLength: Int(data.nfcUInt32BE(at: 134)),
            acknowledgementWireHash: data.subdata(in: 138..<170),
            maximumReadChunkBytes: Int(data.nfcUInt16BE(at: 170)),
            maximumWriteChunkBytes: Int(data.nfcUInt16BE(at: 172))
        )
    }
}

/// Typed command representation. All chunk offsets are UInt32 values encoded
/// in the APDU command body in network (big-endian) byte order.
public enum IrohaPeerNfcCommandV1: Equatable, Sendable {
    case selectApplication
    case getInfo
    case readRequest(sessionID: Data, requestCanonicalHash: Data, offset: UInt32, length: Int)
    case beginPayment(sessionID: Data, requestCanonicalHash: Data, paymentHeader: Data)
    case write(sessionID: Data, paymentWireHash: Data, offset: UInt32, bytes: Data)
    case commit(sessionID: Data, requestCanonicalHash: Data, paymentWireHash: Data)
    case readAcknowledgement(sessionID: Data, paymentWireHash: Data, offset: UInt32, length: Int)
    case confirmAcknowledgement(sessionID: Data, paymentWireHash: Data, acknowledgementWireHash: Data)
    case getStatus(sessionID: Data, requestCanonicalHash: Data)

    public var operation: IrohaPeerNfcOperationV1 {
        switch self {
        case .selectApplication: return .selectApplication
        case .getInfo: return .getInfo
        case .readRequest: return .readRequest
        case .beginPayment: return .beginPayment
        case .write: return .write
        case .commit: return .commit
        case .readAcknowledgement: return .readAcknowledgement
        case .confirmAcknowledgement: return .confirmAcknowledgement
        case .getStatus: return .getStatus
        }
    }
}

/// ISO/IEC 7816 status words returned by the transport-neutral card core.
public enum IrohaPeerNfcStatusWordV1: UInt16, Sendable {
    case success = 0x9000
    case storageFailure = 0x6581
    case wrongLength = 0x6700
    case securityStatusNotSatisfied = 0x6982
    case conditionsNotSatisfied = 0x6985
    case wrongData = 0x6A80
    case notFound = 0x6A82
    case instructionNotSupported = 0x6D00
    case classNotSupported = 0x6E00
}

/// APDU response with data and an ISO/IEC 7816 status word.
public struct IrohaPeerNfcAPDUResponseV1: Equatable, Sendable {
    public let data: Data
    public let statusWord: IrohaPeerNfcStatusWordV1

    public init(data: Data = Data(), statusWord: IrohaPeerNfcStatusWordV1) {
        self.data = Data(data)
        self.statusWord = statusWord
    }

    /// Card-emulation response bytes (`data || SW1 || SW2`).
    public var encoded: Data {
        data + Data([
            UInt8(truncatingIfNeeded: statusWord.rawValue >> 8),
            UInt8(truncatingIfNeeded: statusWord.rawValue),
        ])
    }
}

/// Strict raw APDU codec used by both CoreNFC adapters and test transports.
public enum IrohaPeerNfcAPDUCodecV1 {
    public static func encode(_ command: IrohaPeerNfcCommandV1) throws -> Data {
        switch command {
        case .selectApplication:
            return try encodeEnvelope(
                cla: 0x00,
                instruction: 0xA4,
                p1: 0x04,
                p2: 0x00,
                data: IrohaPeerNfcV1.applicationIdentifier,
                expectedResponseLength: 256
            )
        case .getInfo:
            return try encodeProprietary(
                instruction: .getInfo,
                expectedResponseLength: IrohaPeerNfcV1.infoBytes
            )
        case .readRequest(let sessionID, let requestHash, let offset, let length):
            try validateRead(sessionID: sessionID, hash: requestHash, length: length)
            return try encodeProprietary(
                instruction: .readRequest,
                data: sessionID + requestHash + nfcUInt32BE(offset),
                expectedResponseLength: length
            )
        case .beginPayment(let sessionID, let requestHash, let paymentHeader):
            try nfcRequireSession(sessionID)
            try nfcRequireHash(requestHash)
            _ = try inspectPaymentHeader(paymentHeader)
            return try encodeProprietary(
                instruction: .beginPayment,
                data: sessionID + requestHash + paymentHeader
            )
        case .write(let sessionID, let paymentHash, let offset, let bytes):
            try nfcRequireSession(sessionID)
            try nfcRequireHash(paymentHash)
            guard !bytes.isEmpty, bytes.count <= IrohaPeerNfcV1.maximumChunkBytes else {
                throw IrohaPeerNfcErrorV1.invalidLength
            }
            return try encodeProprietary(
                instruction: .write,
                data: sessionID + paymentHash + nfcUInt32BE(offset) + bytes
            )
        case .commit(let sessionID, let requestHash, let paymentHash):
            try validateControl(sessionID: sessionID, firstHash: requestHash, secondHash: paymentHash)
            return try encodeProprietary(
                instruction: .commit,
                data: sessionID + requestHash + paymentHash
            )
        case .readAcknowledgement(let sessionID, let paymentHash, let offset, let length):
            try validateRead(sessionID: sessionID, hash: paymentHash, length: length)
            return try encodeProprietary(
                instruction: .readAcknowledgement,
                data: sessionID + paymentHash + nfcUInt32BE(offset),
                expectedResponseLength: length
            )
        case .confirmAcknowledgement(let sessionID, let paymentHash, let ackHash):
            try validateControl(sessionID: sessionID, firstHash: paymentHash, secondHash: ackHash)
            return try encodeProprietary(
                instruction: .confirmAcknowledgement,
                data: sessionID + paymentHash + ackHash
            )
        case .getStatus(let sessionID, let requestHash):
            try nfcRequireSession(sessionID)
            try nfcRequireHash(requestHash)
            return try encodeProprietary(
                instruction: .getStatus,
                data: sessionID + requestHash,
                expectedResponseLength: IrohaPeerNfcV1.statusBytes
            )
        }
    }

    public static func decode(_ apdu: Data) throws -> IrohaPeerNfcCommandV1 {
        let envelope = try decodeEnvelope(apdu)
        if envelope.cla == 0x00, envelope.instruction == 0xA4 {
            guard envelope.p1 == 0x04,
                  envelope.p2 == 0x00,
                  envelope.data == IrohaPeerNfcV1.applicationIdentifier,
                  envelope.expectedResponseLength == 256 else {
                throw IrohaPeerNfcErrorV1.invalidApplicationIdentifier
            }
            return .selectApplication
        }
        guard envelope.cla == IrohaPeerNfcV1.commandClass else {
            throw IrohaPeerNfcErrorV1.invalidCommandClass(envelope.cla)
        }
        guard envelope.p1 == 0, envelope.p2 == 0 else {
            throw IrohaPeerNfcErrorV1.invalidAPDU
        }
        guard let instruction = IrohaPeerNfcInstructionV1(rawValue: envelope.instruction) else {
            throw IrohaPeerNfcErrorV1.unsupportedInstruction(envelope.instruction)
        }
        switch instruction {
        case .getInfo:
            guard envelope.data.isEmpty,
                  envelope.expectedResponseLength == IrohaPeerNfcV1.infoBytes else {
                throw IrohaPeerNfcErrorV1.invalidAPDU
            }
            return .getInfo
        case .readRequest, .readAcknowledgement:
            guard envelope.data.count == 52,
                  let length = envelope.expectedResponseLength else {
                throw IrohaPeerNfcErrorV1.invalidAPDU
            }
            let sessionID = envelope.data.subdata(in: 0..<16)
            let hash = envelope.data.subdata(in: 16..<48)
            try validateRead(sessionID: sessionID, hash: hash, length: length)
            let offset = envelope.data.nfcUInt32BE(at: 48)
            if instruction == .readRequest {
                return .readRequest(
                    sessionID: sessionID,
                    requestCanonicalHash: hash,
                    offset: offset,
                    length: length
                )
            }
            return .readAcknowledgement(
                sessionID: sessionID,
                paymentWireHash: hash,
                offset: offset,
                length: length
            )
        case .beginPayment:
            guard envelope.expectedResponseLength == nil,
                  envelope.data.count == 16 + 32 + IrohaPeerWireMessageV1.headerBytes else {
                throw IrohaPeerNfcErrorV1.invalidAPDU
            }
            let sessionID = envelope.data.subdata(in: 0..<16)
            let requestHash = envelope.data.subdata(in: 16..<48)
            let paymentHeader = envelope.data.subdata(in: 48..<envelope.data.count)
            try nfcRequireSession(sessionID)
            try nfcRequireHash(requestHash)
            _ = try inspectPaymentHeader(paymentHeader)
            return .beginPayment(
                sessionID: sessionID,
                requestCanonicalHash: requestHash,
                paymentHeader: paymentHeader
            )
        case .write:
            guard envelope.expectedResponseLength == nil,
                  envelope.data.count > 52,
                  envelope.data.count <= 52 + IrohaPeerNfcV1.maximumChunkBytes else {
                throw IrohaPeerNfcErrorV1.invalidAPDU
            }
            let sessionID = envelope.data.subdata(in: 0..<16)
            let paymentHash = envelope.data.subdata(in: 16..<48)
            try nfcRequireSession(sessionID)
            try nfcRequireHash(paymentHash)
            return .write(
                sessionID: sessionID,
                paymentWireHash: paymentHash,
                offset: envelope.data.nfcUInt32BE(at: 48),
                bytes: envelope.data.subdata(in: 52..<envelope.data.count)
            )
        case .commit, .confirmAcknowledgement:
            guard envelope.expectedResponseLength == nil,
                  envelope.data.count == 80 else {
                throw IrohaPeerNfcErrorV1.invalidAPDU
            }
            let sessionID = envelope.data.subdata(in: 0..<16)
            let firstHash = envelope.data.subdata(in: 16..<48)
            let secondHash = envelope.data.subdata(in: 48..<80)
            try validateControl(sessionID: sessionID, firstHash: firstHash, secondHash: secondHash)
            if instruction == .commit {
                return .commit(
                    sessionID: sessionID,
                    requestCanonicalHash: firstHash,
                    paymentWireHash: secondHash
                )
            }
            return .confirmAcknowledgement(
                sessionID: sessionID,
                paymentWireHash: firstHash,
                acknowledgementWireHash: secondHash
            )
        case .getStatus:
            guard envelope.data.count == 48,
                  envelope.expectedResponseLength == IrohaPeerNfcV1.statusBytes else {
                throw IrohaPeerNfcErrorV1.invalidAPDU
            }
            let sessionID = envelope.data.subdata(in: 0..<16)
            let requestHash = envelope.data.subdata(in: 16..<48)
            try nfcRequireSession(sessionID)
            try nfcRequireHash(requestHash)
            return .getStatus(sessionID: sessionID, requestCanonicalHash: requestHash)
        }
    }

    private struct Envelope {
        let cla: UInt8
        let instruction: UInt8
        let p1: UInt8
        let p2: UInt8
        let data: Data
        let expectedResponseLength: Int?
    }

    private static func encodeProprietary(
        instruction: IrohaPeerNfcInstructionV1,
        data: Data = Data(),
        expectedResponseLength: Int? = nil
    ) throws -> Data {
        try encodeEnvelope(
            cla: IrohaPeerNfcV1.commandClass,
            instruction: instruction.rawValue,
            p1: 0,
            p2: 0,
            data: data,
            expectedResponseLength: expectedResponseLength
        )
    }

    private static func encodeEnvelope(
        cla: UInt8,
        instruction: UInt8,
        p1: UInt8,
        p2: UInt8,
        data: Data,
        expectedResponseLength: Int?
    ) throws -> Data {
        guard data.count <= Int(UInt16.max),
              expectedResponseLength.map({ (1...65_536).contains($0) }) ?? true else {
            throw IrohaPeerNfcErrorV1.invalidLength
        }
        var output = Data([cla, instruction, p1, p2])
        if data.isEmpty {
            guard let expectedResponseLength else { return output }
            if expectedResponseLength <= 256 {
                output.append(expectedResponseLength == 256 ? 0 : UInt8(expectedResponseLength))
            } else {
                output.append(0)
                output.nfcAppendUInt16BE(expectedResponseLength == 65_536 ? 0 : UInt16(expectedResponseLength))
            }
            return output
        }
        let useExtended = data.count > Int(UInt8.max)
            || (expectedResponseLength.map { $0 > 256 } ?? false)
        if useExtended {
            output.append(0)
            output.nfcAppendUInt16BE(UInt16(data.count))
            output.append(data)
            if let expectedResponseLength {
                output.nfcAppendUInt16BE(expectedResponseLength == 65_536 ? 0 : UInt16(expectedResponseLength))
            }
        } else {
            output.append(UInt8(data.count))
            output.append(data)
            if let expectedResponseLength {
                output.append(expectedResponseLength == 256 ? 0 : UInt8(expectedResponseLength))
            }
        }
        return output
    }

    private static func decodeEnvelope(_ apdu: Data) throws -> Envelope {
        guard apdu.count >= 4 else { throw IrohaPeerNfcErrorV1.invalidAPDU }
        let header = (apdu[0], apdu[1], apdu[2], apdu[3])
        guard apdu.count > 4 else {
            return Envelope(
                cla: header.0,
                instruction: header.1,
                p1: header.2,
                p2: header.3,
                data: Data(),
                expectedResponseLength: nil
            )
        }
        let firstLength = Int(apdu[4])
        if firstLength != 0 {
            if apdu.count == 5 {
                return Envelope(
                    cla: header.0,
                    instruction: header.1,
                    p1: header.2,
                    p2: header.3,
                    data: Data(),
                    expectedResponseLength: firstLength
                )
            }
            if apdu.count == 5 + firstLength {
                return Envelope(
                    cla: header.0,
                    instruction: header.1,
                    p1: header.2,
                    p2: header.3,
                    data: apdu.subdata(in: 5..<apdu.count),
                    expectedResponseLength: nil
                )
            }
            if apdu.count == 6 + firstLength {
                let rawLe = Int(apdu[apdu.count - 1])
                return Envelope(
                    cla: header.0,
                    instruction: header.1,
                    p1: header.2,
                    p2: header.3,
                    data: apdu.subdata(in: 5..<(5 + firstLength)),
                    expectedResponseLength: rawLe == 0 ? 256 : rawLe
                )
            }
            throw IrohaPeerNfcErrorV1.invalidAPDU
        }
        if apdu.count == 5 {
            return Envelope(
                cla: header.0,
                instruction: header.1,
                p1: header.2,
                p2: header.3,
                data: Data(),
                expectedResponseLength: 256
            )
        }
        guard apdu.count >= 7 else { throw IrohaPeerNfcErrorV1.invalidAPDU }
        let extendedLength = Int(apdu.nfcUInt16BE(at: 5))
        if apdu.count == 7 {
            // Case 2E is canonical only when the response length cannot be
            // represented by the one-byte Case 2S form. Rejecting alternate
            // encodings avoids parser differentials between NFC stacks.
            guard extendedLength == 0 || extendedLength > 256 else {
                throw IrohaPeerNfcErrorV1.invalidAPDU
            }
            return Envelope(
                cla: header.0,
                instruction: header.1,
                p1: header.2,
                p2: header.3,
                data: Data(),
                expectedResponseLength: extendedLength == 0 ? 65_536 : extendedLength
            )
        }
        guard extendedLength > 0 else { throw IrohaPeerNfcErrorV1.invalidAPDU }
        if apdu.count == 7 + extendedLength {
            guard extendedLength > Int(UInt8.max) else {
                throw IrohaPeerNfcErrorV1.invalidAPDU
            }
            return Envelope(
                cla: header.0,
                instruction: header.1,
                p1: header.2,
                p2: header.3,
                data: apdu.subdata(in: 7..<apdu.count),
                expectedResponseLength: nil
            )
        }
        if apdu.count == 9 + extendedLength {
            let rawLe = Int(apdu.nfcUInt16BE(at: 7 + extendedLength))
            let expectedResponseLength = rawLe == 0 ? 65_536 : rawLe
            guard extendedLength > Int(UInt8.max)
                    || expectedResponseLength > 256 else {
                throw IrohaPeerNfcErrorV1.invalidAPDU
            }
            return Envelope(
                cla: header.0,
                instruction: header.1,
                p1: header.2,
                p2: header.3,
                data: apdu.subdata(in: 7..<(7 + extendedLength)),
                expectedResponseLength: expectedResponseLength
            )
        }
        throw IrohaPeerNfcErrorV1.invalidAPDU
    }

    private static func validateRead(sessionID: Data, hash: Data, length: Int) throws {
        try nfcRequireSession(sessionID)
        try nfcRequireHash(hash)
        try nfcRequireChunkLimit(length)
    }

    private static func validateControl(
        sessionID: Data,
        firstHash: Data,
        secondHash: Data
    ) throws {
        try nfcRequireSession(sessionID)
        try nfcRequireHash(firstHash)
        try nfcRequireHash(secondHash)
    }

    private static func inspectPaymentHeader(_ data: Data) throws -> IrohaPeerWireHeaderV1 {
        do {
            return try IrohaPeerWireMessageV1.inspectHeader(data, expectedKind: .payment)
        } catch {
            throw IrohaPeerNfcErrorV1.invalidIPM1
        }
    }
}

/// Metadata accepted by `BEGIN_PAYMENT`. The complete IPM1 header is carried
/// in that command so profile, kind, lengths, and both IPM1 hashes are checked
/// before the first payment byte is buffered.
public struct IrohaPeerNfcPaymentDescriptorV1: Equatable, Sendable {
    public let profile: IrohaPeerPayloadProfile
    public let schemaVersion: UInt16
    public let messageLength: Int
    public let canonicalHash: Data
    public let wireHash: Data
    public let header: Data

    public init(paymentHeader: Data, limits: IrohaPeerNfcLimitsV1 = .default) throws {
        let inspected: IrohaPeerWireHeaderV1
        do {
            inspected = try IrohaPeerWireMessageV1.inspectHeader(
                paymentHeader,
                expectedKind: .payment
            )
        } catch {
            throw IrohaPeerNfcErrorV1.invalidIPM1
        }
        let messageLength = IrohaPeerWireMessageV1.headerBytes + inspected.encodedLength
        guard inspected.canonicalLength > 0,
              inspected.encodedLength > 0,
              messageLength <= limits.maximumMessageBytes else {
            throw IrohaPeerNfcErrorV1.messageTooLarge(
                actual: messageLength,
                maximum: limits.maximumMessageBytes
            )
        }
        self.profile = inspected.profile
        self.schemaVersion = inspected.schemaVersion
        self.messageLength = messageLength
        self.canonicalHash = Data(inspected.canonicalHash)
        self.wireHash = Data(inspected.wireHash)
        self.header = Data(paymentHeader)
    }
}

/// Validated BEGIN_PAYMENT metadata that must be durable before any payment
/// byte is accepted.
public struct IrohaPeerNfcPaymentAdmissionContextV1: Equatable, Sendable {
    public let identity: IrohaPeerNfcRequestIdentityV1
    public let profilePolicy: IrohaPeerNfcProfilePolicyV1
    public let descriptor: IrohaPeerNfcPaymentDescriptorV1

    public init(
        identity: IrohaPeerNfcRequestIdentityV1,
        profilePolicy: IrohaPeerNfcProfilePolicyV1,
        descriptor: IrohaPeerNfcPaymentDescriptorV1
    ) throws {
        guard profilePolicy.profile == identity.profile,
              profilePolicy.accepts(descriptor.profile) else {
            throw IrohaPeerNfcErrorV1.invalidProfile
        }
        self.identity = identity
        self.profilePolicy = profilePolicy
        self.descriptor = descriptor
    }

    public init(
        identity: IrohaPeerNfcRequestIdentityV1,
        profilePolicy: IrohaPeerNfcProfilePolicyV1,
        paymentHeader: Data,
        limits: IrohaPeerNfcLimitsV1 = .default
    ) throws {
        try self.init(
            identity: identity,
            profilePolicy: profilePolicy,
            descriptor: IrohaPeerNfcPaymentDescriptorV1(
                paymentHeader: paymentHeader,
                limits: limits
            )
        )
    }

    public var paymentHeader: Data { descriptor.header }
}

/// Fixed 244-byte IPA1 record returned by durable admission storage. The
/// callback input context is intentionally separate from this persistable
/// output so BEGIN_PAYMENT cannot succeed merely because validation ran.
public struct IrohaPeerNfcDurablePaymentAdmissionV1: Equatable, Sendable {
    public let context: IrohaPeerNfcPaymentAdmissionContextV1

    public var identity: IrohaPeerNfcRequestIdentityV1 { context.identity }
    public var profilePolicy: IrohaPeerNfcProfilePolicyV1 { context.profilePolicy }
    public var descriptor: IrohaPeerNfcPaymentDescriptorV1 { context.descriptor }
    public var paymentHeader: Data { context.paymentHeader }

    public init(
        context: IrohaPeerNfcPaymentAdmissionContextV1,
        limits: IrohaPeerNfcLimitsV1 = .default
    ) throws {
        let validated = try IrohaPeerNfcPaymentAdmissionContextV1(
            identity: context.identity,
            profilePolicy: context.profilePolicy,
            paymentHeader: context.paymentHeader,
            limits: limits
        )
        guard validated == context else { throw IrohaPeerNfcErrorV1.continuityMismatch }
        self.context = validated
    }

    public var encoded: Data {
        var output = IrohaPeerNfcV1.paymentAdmissionMagic
        output.append(IrohaPeerNfcV1.wireVersion)
        output.nfcAppendUInt16BE(identity.profile.rawValue)
        output.append(0)
        output.append(identity.sessionID)
        output.append(identity.requestCanonicalHash)
        output.append(identity.requestWireHash)
        output.nfcAppendUInt16BE(descriptor.profile.rawValue)
        output.nfcAppendUInt16BE(descriptor.schemaVersion)
        output.nfcAppendUInt32BE(UInt32(descriptor.messageLength))
        output.append(descriptor.canonicalHash)
        output.append(descriptor.wireHash)
        output.append(descriptor.header)
        precondition(output.count == IrohaPeerNfcV1.paymentAdmissionBytes)
        return output
    }

    public static func decode(
        _ data: Data,
        profilePolicy: IrohaPeerNfcProfilePolicyV1? = nil,
        limits: IrohaPeerNfcLimitsV1 = .default
    ) throws -> Self {
        guard data.count == IrohaPeerNfcV1.paymentAdmissionBytes,
              data.prefix(4) == IrohaPeerNfcV1.paymentAdmissionMagic,
              data[4] == IrohaPeerNfcV1.wireVersion,
              data[7] == 0,
              let requestProfile = IrohaPeerPayloadProfile(
                rawValue: data.nfcUInt16BE(at: 5)
              ), requestProfile != .reject,
              let paymentProfile = IrohaPeerPayloadProfile(
                rawValue: data.nfcUInt16BE(at: 88)
              ), paymentProfile != .reject else {
            throw IrohaPeerNfcErrorV1.invalidLength
        }
        let effectivePolicy = profilePolicy ?? .init(profile: requestProfile)
        let identity = try IrohaPeerNfcRequestIdentityV1(
            profile: requestProfile,
            sessionID: data.subdata(in: 8..<24),
            requestCanonicalHash: data.subdata(in: 24..<56),
            requestWireHash: data.subdata(in: 56..<88)
        )
        let context = try IrohaPeerNfcPaymentAdmissionContextV1(
            identity: identity,
            profilePolicy: effectivePolicy,
            paymentHeader: data.subdata(in: 160..<244),
            limits: limits
        )
        guard effectivePolicy.profile == requestProfile,
              context.descriptor.profile == paymentProfile,
              context.descriptor.schemaVersion == data.nfcUInt16BE(at: 90),
              context.descriptor.messageLength == Int(data.nfcUInt32BE(at: 92)),
              context.descriptor.canonicalHash == data.subdata(in: 96..<128),
              context.descriptor.wireHash == data.subdata(in: 128..<160) else {
            throw IrohaPeerNfcErrorV1.continuityMismatch
        }
        return try Self(context: context, limits: limits)
    }
}

/// A structurally bound exchange presented to application persistence at COMMIT.
/// Native authentication and monetary admission remain required before acknowledging receipt.
public struct IrohaPeerNfcCommitContextV1: Equatable, Sendable {
    public let identity: IrohaPeerNfcRequestIdentityV1
    public let profilePolicy: IrohaPeerNfcProfilePolicyV1
    public let receiveRequest: IrohaPeerWireMessageV1
    public let payment: IrohaPeerWireMessageV1

    public init(
        identity: IrohaPeerNfcRequestIdentityV1,
        profilePolicy: IrohaPeerNfcProfilePolicyV1,
        receiveRequest: IrohaPeerWireMessageV1,
        payment: IrohaPeerWireMessageV1
    ) throws {
        guard profilePolicy.profile == identity.profile,
              profilePolicy.accepts(receiveRequest.profile),
              profilePolicy.accepts(payment.profile) else {
            throw IrohaPeerNfcErrorV1.invalidProfile
        }
        guard receiveRequest.kind == .request, payment.kind == .payment else {
            throw IrohaPeerNfcErrorV1.invalidKind
        }
        guard receiveRequest.canonicalHash == identity.requestCanonicalHash,
              receiveRequest.wireHash == identity.requestWireHash else {
            throw IrohaPeerNfcErrorV1.continuityMismatch
        }
        try nfcRequireWalletExchange(request: receiveRequest, payment: payment)

        self.identity = identity
        self.profilePolicy = profilePolicy
        self.receiveRequest = receiveRequest
        self.payment = payment
    }
}

/// Opaque, persistable receiver record proving that payment ingest and its
/// exact IPM1 acknowledgement crossed the application's durability boundary.
///
/// A COMMIT handler must store `encoded` durably before returning this value.
/// Reloading it reconstructs `ACKNOWLEDGEMENT_READY` after RF loss or relaunch.
public struct IrohaPeerNfcDurableAcknowledgementV1: Equatable, Sendable {
    public let identity: IrohaPeerNfcRequestIdentityV1
    public let paymentProfile: IrohaPeerPayloadProfile
    public let paymentLength: Int
    public let paymentWireHash: Data
    public let acknowledgement: IrohaPeerWireMessageV1

    public init(
        context: IrohaPeerNfcCommitContextV1,
        acknowledgement: Data,
        limits: IrohaPeerNfcLimitsV1 = .default
    ) throws {
        guard context.payment.encoded.count <= limits.maximumMessageBytes else {
            throw IrohaPeerNfcErrorV1.messageTooLarge(
                actual: context.payment.encoded.count,
                maximum: limits.maximumMessageBytes
            )
        }
        let decoded = try nfcDecodeMessage(
            acknowledgement,
            expectedProfile: nil,
            expectedKind: .credited,
            limits: limits
        )
        guard context.profilePolicy.accepts(decoded.profile) else {
            throw IrohaPeerNfcErrorV1.invalidProfile
        }
        try nfcRequireWalletExchange(
            request: context.receiveRequest, payment: context.payment, credited: decoded)
        self.identity = context.identity
        self.paymentProfile = context.payment.profile
        self.paymentLength = context.payment.encoded.count
        self.paymentWireHash = Data(context.payment.wireHash)
        self.acknowledgement = decoded
    }

    private init(
        identity: IrohaPeerNfcRequestIdentityV1,
        paymentProfile: IrohaPeerPayloadProfile,
        paymentLength: Int,
        paymentWireHash: Data,
        acknowledgement: IrohaPeerWireMessageV1,
        limits: IrohaPeerNfcLimitsV1
    ) throws {
        guard paymentProfile != .reject,
              paymentLength > IrohaPeerWireMessageV1.headerBytes,
              paymentLength <= limits.maximumMessageBytes else {
            throw IrohaPeerNfcErrorV1.invalidLength
        }
        try nfcRequireHash(paymentWireHash)
        guard acknowledgement.kind == .credited else {
            throw IrohaPeerNfcErrorV1.invalidKind
        }
        guard !acknowledgement.canonicalPayload.isEmpty,
              acknowledgement.encoded.count <= limits.maximumMessageBytes else {
            throw IrohaPeerNfcErrorV1.invalidLength
        }
        self.identity = identity
        self.paymentProfile = paymentProfile
        self.paymentLength = paymentLength
        self.paymentWireHash = Data(paymentWireHash)
        self.acknowledgement = acknowledgement
    }

    public var encoded: Data {
        var output = IrohaPeerNfcV1.durableAckMagic
        output.append(IrohaPeerNfcV1.wireVersion)
        output.nfcAppendUInt16BE(identity.profile.rawValue)
        output.append(0)
        output.append(identity.sessionID)
        output.append(identity.requestCanonicalHash)
        output.append(identity.requestWireHash)
        output.nfcAppendUInt16BE(paymentProfile.rawValue)
        output.nfcAppendUInt32BE(UInt32(paymentLength))
        output.append(paymentWireHash)
        output.nfcAppendUInt32BE(UInt32(acknowledgement.encoded.count))
        output.append(acknowledgement.encoded)
        return output
    }

    public static func decode(
        _ data: Data,
        profilePolicy: IrohaPeerNfcProfilePolicyV1? = nil,
        limits: IrohaPeerNfcLimitsV1 = .default
    ) throws -> Self {
        let fixedBytes = 130
        guard data.count > fixedBytes,
              data.prefix(4) == IrohaPeerNfcV1.durableAckMagic,
              data[4] == IrohaPeerNfcV1.wireVersion,
              data[7] == 0,
              let profile = IrohaPeerPayloadProfile(rawValue: data.nfcUInt16BE(at: 5)),
              profile != .reject else {
            throw IrohaPeerNfcErrorV1.invalidLength
        }
        guard let paymentProfile = IrohaPeerPayloadProfile(rawValue: data.nfcUInt16BE(at: 88)),
              paymentProfile != .reject else {
            throw IrohaPeerNfcErrorV1.invalidProfile
        }
        let acknowledgementLength = Int(data.nfcUInt32BE(at: 126))
        guard acknowledgementLength > IrohaPeerWireMessageV1.headerBytes,
              acknowledgementLength <= limits.maximumMessageBytes,
              fixedBytes <= data.count - acknowledgementLength,
              fixedBytes + acknowledgementLength == data.count else {
            throw IrohaPeerNfcErrorV1.invalidLength
        }
        let identity = try IrohaPeerNfcRequestIdentityV1(
            profile: profile,
            sessionID: data.subdata(in: 8..<24),
            requestCanonicalHash: data.subdata(in: 24..<56),
            requestWireHash: data.subdata(in: 56..<88)
        )
        let acknowledgement = try nfcDecodeMessage(
            data.subdata(in: fixedBytes..<data.count),
            expectedProfile: nil,
            expectedKind: .credited,
            limits: limits
        )
        let effectivePolicy = profilePolicy ?? .init(profile: profile)
        guard effectivePolicy.profile == profile,
              effectivePolicy.accepts(paymentProfile),
              effectivePolicy.accepts(acknowledgement.profile) else {
            throw IrohaPeerNfcErrorV1.invalidProfile
        }
        return try Self(
            identity: identity,
            paymentProfile: paymentProfile,
            paymentLength: Int(data.nfcUInt32BE(at: 90)),
            paymentWireHash: data.subdata(in: 94..<126),
            acknowledgement: acknowledgement,
            limits: limits
        )
    }
}

public enum IrohaPeerNfcCommitDispositionV1: Equatable, Sendable {
    /// The application must atomically ingest the payment and persist an ACK,
    /// then install the returned durable record before replying with `9000`.
    case requiresDurableCommit(IrohaPeerNfcCommitContextV1)
    /// The exact COMMIT was already durably accepted; replay is idempotent.
    case alreadyCommitted
}

public enum IrohaPeerNfcPaymentAdmissionDispositionV1: Equatable, Sendable {
    case requiresDurableAdmission(IrohaPeerNfcPaymentAdmissionContextV1)
    case alreadyAdmitted
}

/// Transport-neutral receiver/card state for one NFC transfer session.
public struct IrohaPeerNfcReceiverSessionV1: Sendable {
    public typealias DurableAdmissionHandler =
        (IrohaPeerNfcPaymentAdmissionContextV1) throws ->
            IrohaPeerNfcDurablePaymentAdmissionV1
    public typealias DurableCommitHandler =
        (IrohaPeerNfcCommitContextV1) throws -> IrohaPeerNfcDurableAcknowledgementV1

    private struct PendingPayment: Sendable {
        let descriptor: IrohaPeerNfcPaymentDescriptorV1
        var bytes: Data
    }

    public let identity: IrohaPeerNfcRequestIdentityV1
    public let profilePolicy: IrohaPeerNfcProfilePolicyV1
    public let receiveRequest: IrohaPeerWireMessageV1
    public let limits: IrohaPeerNfcLimitsV1

    private var pendingPayment: PendingPayment?
    private var durableAcknowledgement: IrohaPeerNfcDurableAcknowledgementV1?
    private var acknowledgementConfirmed = false

    public init(
        sessionID: Data,
        receiveRequest: Data,
        durableAcknowledgement: IrohaPeerNfcDurableAcknowledgementV1? = nil,
        restoredPaymentAdmission: IrohaPeerNfcDurablePaymentAdmissionV1? = nil,
        profilePolicy: IrohaPeerNfcProfilePolicyV1? = nil,
        limits: IrohaPeerNfcLimitsV1 = .default
    ) throws {
        try nfcRequireSession(sessionID)
        let request = try nfcDecodeMessage(
            receiveRequest,
            expectedProfile: nil,
            expectedKind: .request,
            limits: limits
        )
        let identity = try IrohaPeerNfcRequestIdentityV1(
            profile: request.profile,
            sessionID: sessionID,
            requestCanonicalHash: request.canonicalHash,
            requestWireHash: request.wireHash
        )
        let effectivePolicy = profilePolicy ?? .init(profile: request.profile)
        guard effectivePolicy.profile == request.profile else {
            throw IrohaPeerNfcErrorV1.invalidProfile
        }
        if let durableAcknowledgement {
            guard durableAcknowledgement.identity == identity,
                  effectivePolicy.accepts(durableAcknowledgement.paymentProfile),
                  effectivePolicy.accepts(
                    durableAcknowledgement.acknowledgement.profile
                  ) else {
                throw IrohaPeerNfcErrorV1.continuityMismatch
            }
        }
        if let durableAcknowledgement {
            try nfcRequireCreditedScheme(request: request, credited: durableAcknowledgement.acknowledgement)
        }
        var initialPendingPayment: PendingPayment?
        if let restoredPaymentAdmission {
            let validated = try IrohaPeerNfcDurablePaymentAdmissionV1.decode(
                restoredPaymentAdmission.encoded,
                profilePolicy: effectivePolicy,
                limits: limits
            )
            guard validated == restoredPaymentAdmission,
                  validated.identity == identity,
                  validated.profilePolicy == effectivePolicy else {
                throw IrohaPeerNfcErrorV1.continuityMismatch
            }
            if let durableAcknowledgement {
                guard validated.descriptor.profile == durableAcknowledgement.paymentProfile,
                      validated.descriptor.messageLength == durableAcknowledgement.paymentLength,
                      validated.descriptor.wireHash == durableAcknowledgement.paymentWireHash else {
                    throw IrohaPeerNfcErrorV1.continuityMismatch
                }
                initialPendingPayment = nil
            } else {
                initialPendingPayment = PendingPayment(
                    descriptor: validated.descriptor,
                    bytes: Data()
                )
            }
        } else {
            initialPendingPayment = nil
        }
        self.identity = identity
        self.receiveRequest = request
        self.profilePolicy = effectivePolicy
        self.limits = limits
        self.pendingPayment = initialPendingPayment
        self.durableAcknowledgement = durableAcknowledgement
    }

    public var phase: IrohaPeerNfcPhaseV1 {
        if acknowledgementConfirmed { return .complete }
        if durableAcknowledgement != nil { return .acknowledgementReady }
        if pendingPayment != nil { return .paymentReceiving }
        return .requestReady
    }

    public func info() throws -> IrohaPeerNfcInfoV1 {
        try IrohaPeerNfcInfoV1(
            phase: phase,
            flags: currentFlags,
            identity: identity,
            requestLength: receiveRequest.encoded.count,
            maximumReadChunkBytes: limits.maximumReadChunkBytes,
            maximumWriteChunkBytes: limits.maximumWriteChunkBytes
        )
    }

    public func status() throws -> IrohaPeerNfcStatusV1 {
        let zeroHash = Data(repeating: 0, count: IrohaPeerNfcV1.hashBytes)
        let paymentLength: Int
        let receivedPaymentBytes: Int
        let paymentHash: Data
        let paymentProfile: IrohaPeerPayloadProfile?
        if let durableAcknowledgement {
            paymentLength = durableAcknowledgement.paymentLength
            receivedPaymentBytes = durableAcknowledgement.paymentLength
            paymentHash = durableAcknowledgement.paymentWireHash
            paymentProfile = durableAcknowledgement.paymentProfile
        } else if let pendingPayment {
            paymentLength = pendingPayment.descriptor.messageLength
            receivedPaymentBytes = pendingPayment.bytes.count
            paymentHash = pendingPayment.descriptor.wireHash
            paymentProfile = pendingPayment.descriptor.profile
        } else {
            paymentLength = 0
            receivedPaymentBytes = 0
            paymentHash = zeroHash
            paymentProfile = nil
        }
        let acknowledgementLength = durableAcknowledgement?.acknowledgement.encoded.count ?? 0
        let acknowledgementHash = durableAcknowledgement?.acknowledgement.wireHash ?? zeroHash
        return try IrohaPeerNfcStatusV1(
            phase: phase,
            flags: currentFlags,
            identity: identity,
            paymentProfile: paymentProfile,
            paymentLength: paymentLength,
            receivedPaymentBytes: receivedPaymentBytes,
            paymentWireHash: paymentHash,
            acknowledgementProfile: durableAcknowledgement?.acknowledgement.profile,
            acknowledgementLength: acknowledgementLength,
            acknowledgementWireHash: acknowledgementHash,
            maximumReadChunkBytes: limits.maximumReadChunkBytes,
            maximumWriteChunkBytes: limits.maximumWriteChunkBytes
        )
    }

    /// Handles every command except COMMIT. Use `prepareCommit` and
    /// `installDurableAcknowledgement`, or the `process` convenience below,
    /// for the persistence-sensitive COMMIT boundary.
    public mutating func handle(_ command: IrohaPeerNfcCommandV1) throws -> Data {
        switch command {
        case .selectApplication:
            return Data()
        case .getInfo:
            return try info().encode()
        case .readRequest(let sessionID, let requestHash, let offset, let length):
            try requireRequestContinuity(sessionID: sessionID, requestHash: requestHash)
            return try readSlice(
                receiveRequest.encoded,
                offset: offset,
                requestedLength: length
            )
        case .beginPayment:
            throw IrohaPeerNfcErrorV1.durableAdmissionRequired
        case .write(let sessionID, let paymentHash, let offset, let bytes):
            try writePayment(
                sessionID: sessionID,
                paymentHash: paymentHash,
                offset: offset,
                bytes: bytes
            )
            return Data()
        case .commit:
            throw IrohaPeerNfcErrorV1.durableCommitRequired
        case .readAcknowledgement(let sessionID, let paymentHash, let offset, let length):
            guard let durableAcknowledgement else {
                throw IrohaPeerNfcErrorV1.stateMismatch
            }
            try requireSession(sessionID)
            guard paymentHash == durableAcknowledgement.paymentWireHash else {
                throw IrohaPeerNfcErrorV1.continuityMismatch
            }
            return try readSlice(
                durableAcknowledgement.acknowledgement.encoded,
                offset: offset,
                requestedLength: length
            )
        case .confirmAcknowledgement(let sessionID, let paymentHash, let ackHash):
            try confirmAcknowledgement(
                sessionID: sessionID,
                paymentHash: paymentHash,
                acknowledgementHash: ackHash
            )
            return Data()
        case .getStatus(let sessionID, let requestHash):
            try requireRequestContinuity(sessionID: sessionID, requestHash: requestHash)
            return try status().encode()
        }
    }

    public func preparePaymentAdmission(
        _ command: IrohaPeerNfcCommandV1
    ) throws -> IrohaPeerNfcPaymentAdmissionDispositionV1 {
        guard case .beginPayment(let sessionID, let requestHash, let header) = command else {
            throw IrohaPeerNfcErrorV1.stateMismatch
        }
        try requireRequestContinuity(sessionID: sessionID, requestHash: requestHash)
        let descriptor = try IrohaPeerNfcPaymentDescriptorV1(
            paymentHeader: header,
            limits: limits
        )
        guard profilePolicy.accepts(descriptor.profile) else {
            throw IrohaPeerNfcErrorV1.invalidProfile
        }
        if durableAcknowledgement != nil {
            throw IrohaPeerNfcErrorV1.stateMismatch
        }
        if let pendingPayment {
            guard pendingPayment.descriptor == descriptor else {
                throw IrohaPeerNfcErrorV1.conflictingReplay
            }
            return .alreadyAdmitted
        }
        return .requiresDurableAdmission(
            try IrohaPeerNfcPaymentAdmissionContextV1(
                identity: identity,
                profilePolicy: profilePolicy,
                descriptor: descriptor
            )
        )
    }

    public mutating func installPaymentAdmission(
        _ record: IrohaPeerNfcDurablePaymentAdmissionV1
    ) throws {
        let validated = try IrohaPeerNfcDurablePaymentAdmissionV1.decode(
            record.encoded,
            profilePolicy: profilePolicy,
            limits: limits
        )
        guard validated == record,
              validated.identity == identity,
              validated.profilePolicy == profilePolicy else {
            throw IrohaPeerNfcErrorV1.continuityMismatch
        }
        if durableAcknowledgement != nil {
            throw IrohaPeerNfcErrorV1.stateMismatch
        }
        if let pendingPayment {
            guard pendingPayment.descriptor == validated.descriptor else {
                throw IrohaPeerNfcErrorV1.conflictingReplay
            }
            return
        }
        pendingPayment = PendingPayment(descriptor: validated.descriptor, bytes: Data())
    }

    public func prepareCommit(
        _ command: IrohaPeerNfcCommandV1
    ) throws -> IrohaPeerNfcCommitDispositionV1 {
        guard case .commit(let sessionID, let requestHash, let paymentHash) = command else {
            throw IrohaPeerNfcErrorV1.stateMismatch
        }
        try requireRequestContinuity(sessionID: sessionID, requestHash: requestHash)
        if let durableAcknowledgement {
            guard paymentHash == durableAcknowledgement.paymentWireHash else {
                throw IrohaPeerNfcErrorV1.continuityMismatch
            }
            return .alreadyCommitted
        }
        guard let pendingPayment else { throw IrohaPeerNfcErrorV1.stateMismatch }
        guard paymentHash == pendingPayment.descriptor.wireHash else {
            throw IrohaPeerNfcErrorV1.continuityMismatch
        }
        guard pendingPayment.bytes.count == pendingPayment.descriptor.messageLength else {
            throw IrohaPeerNfcErrorV1.stateMismatch
        }
        let payment = try nfcDecodeMessage(
            pendingPayment.bytes,
            expectedProfile: nil,
            expectedKind: .payment,
            limits: limits
        )
        guard profilePolicy.accepts(payment.profile),
              payment.header.bytes == pendingPayment.descriptor.header,
              payment.wireHash == pendingPayment.descriptor.wireHash else {
            throw IrohaPeerNfcErrorV1.invalidHash
        }
        return .requiresDurableCommit(
            try IrohaPeerNfcCommitContextV1(
                identity: identity,
                profilePolicy: profilePolicy,
                receiveRequest: receiveRequest,
                payment: payment
            )
        )
    }

    /// Installs only a record for the exact pending payment. Call this after
    /// the application has atomically persisted the payment outcome and ACK.
    public mutating func installDurableAcknowledgement(
        _ record: IrohaPeerNfcDurableAcknowledgementV1
    ) throws {
        guard record.identity == identity else {
            throw IrohaPeerNfcErrorV1.continuityMismatch
        }
        guard profilePolicy.accepts(record.paymentProfile),
              profilePolicy.accepts(record.acknowledgement.profile) else {
            throw IrohaPeerNfcErrorV1.invalidProfile
        }
        try nfcRequireCreditedScheme(request: receiveRequest, credited: record.acknowledgement)
        if let durableAcknowledgement {
            guard durableAcknowledgement == record else {
                throw IrohaPeerNfcErrorV1.conflictingReplay
            }
            return
        }
        guard let pendingPayment,
              record.paymentProfile == pendingPayment.descriptor.profile,
              record.paymentLength == pendingPayment.descriptor.messageLength,
              record.paymentWireHash == pendingPayment.descriptor.wireHash else {
            throw IrohaPeerNfcErrorV1.continuityMismatch
        }
        durableAcknowledgement = record
        self.pendingPayment = nil
    }

    /// Decodes and executes a raw APDU. A successful COMMIT response is never
    /// produced until `durableCommit` returns an exact persisted record.
    public mutating func process(
        apdu: Data,
        admitPayment: DurableAdmissionHandler? = nil,
        durableCommit: DurableCommitHandler? = nil
    ) -> IrohaPeerNfcAPDUResponseV1 {
        let command: IrohaPeerNfcCommandV1
        do {
            command = try IrohaPeerNfcAPDUCodecV1.decode(apdu)
        } catch let error as IrohaPeerNfcErrorV1 {
            return Self.failureResponse(for: error)
        } catch {
            return IrohaPeerNfcAPDUResponseV1(statusWord: .wrongData)
        }
        if case .beginPayment = command {
            do {
                switch try preparePaymentAdmission(command) {
                case .alreadyAdmitted:
                    return IrohaPeerNfcAPDUResponseV1(statusWord: .success)
                case .requiresDurableAdmission(let context):
                    guard let admitPayment else {
                        throw IrohaPeerNfcErrorV1.durableAdmissionRequired
                    }
                    let record: IrohaPeerNfcDurablePaymentAdmissionV1
                    do { record = try admitPayment(context) } catch {
                        return IrohaPeerNfcAPDUResponseV1(statusWord: .storageFailure)
                    }
                    guard record.context == context else {
                        return IrohaPeerNfcAPDUResponseV1(
                            statusWord: .securityStatusNotSatisfied
                        )
                    }
                    try installPaymentAdmission(record)
                    return IrohaPeerNfcAPDUResponseV1(statusWord: .success)
                }
            } catch let error as IrohaPeerNfcErrorV1 {
                return Self.failureResponse(for: error)
            } catch {
                return IrohaPeerNfcAPDUResponseV1(statusWord: .storageFailure)
            }
        } else if case .commit = command {
            do {
                switch try prepareCommit(command) {
                case .alreadyCommitted:
                    return IrohaPeerNfcAPDUResponseV1(statusWord: .success)
                case .requiresDurableCommit(let context):
                    guard let durableCommit else {
                        throw IrohaPeerNfcErrorV1.durableCommitRequired
                    }
                    let record: IrohaPeerNfcDurableAcknowledgementV1
                    do {
                        record = try durableCommit(context)
                    } catch {
                        return IrohaPeerNfcAPDUResponseV1(statusWord: .storageFailure)
                    }
                    try installDurableAcknowledgement(record)
                    return IrohaPeerNfcAPDUResponseV1(statusWord: .success)
                }
            } catch let error as IrohaPeerNfcErrorV1 {
                return Self.failureResponse(for: error)
            } catch {
                return IrohaPeerNfcAPDUResponseV1(statusWord: .storageFailure)
            }
        }
        do {
            return IrohaPeerNfcAPDUResponseV1(
                data: try handle(command),
                statusWord: .success
            )
        } catch let error as IrohaPeerNfcErrorV1 {
            return Self.failureResponse(for: error)
        } catch {
            return IrohaPeerNfcAPDUResponseV1(statusWord: .wrongData)
        }
    }

    private var currentFlags: IrohaPeerNfcFlagsV1 {
        var flags: IrohaPeerNfcFlagsV1 = [.idempotentWrites]
        if durableAcknowledgement != nil { flags.insert(.durableAcknowledgement) }
        return flags
    }

    private mutating func writePayment(
        sessionID: Data,
        paymentHash: Data,
        offset: UInt32,
        bytes: Data
    ) throws {
        try requireSession(sessionID)
        guard !bytes.isEmpty, bytes.count <= limits.maximumWriteChunkBytes else {
            throw IrohaPeerNfcErrorV1.invalidLength
        }
        guard var pendingPayment else { throw IrohaPeerNfcErrorV1.stateMismatch }
        guard paymentHash == pendingPayment.descriptor.wireHash else {
            throw IrohaPeerNfcErrorV1.continuityMismatch
        }
        guard let start = Int(exactly: offset) else {
            throw IrohaPeerNfcErrorV1.invalidOffset
        }
        guard start <= pendingPayment.bytes.count,
              start <= pendingPayment.descriptor.messageLength - bytes.count else {
            throw IrohaPeerNfcErrorV1.invalidOffset
        }
        let overlap = min(pendingPayment.bytes.count - start, bytes.count)
        if overlap > 0 {
            let existing = pendingPayment.bytes.subdata(in: start..<(start + overlap))
            guard existing == bytes.prefix(overlap) else {
                throw IrohaPeerNfcErrorV1.conflictingReplay
            }
        }
        if overlap < bytes.count {
            pendingPayment.bytes.append(bytes.dropFirst(overlap))
        }
        self.pendingPayment = pendingPayment
    }

    private mutating func confirmAcknowledgement(
        sessionID: Data,
        paymentHash: Data,
        acknowledgementHash: Data
    ) throws {
        try requireSession(sessionID)
        guard let durableAcknowledgement else {
            throw IrohaPeerNfcErrorV1.acknowledgementNotDurable
        }
        guard paymentHash == durableAcknowledgement.paymentWireHash,
              acknowledgementHash == durableAcknowledgement.acknowledgement.wireHash else {
            throw IrohaPeerNfcErrorV1.continuityMismatch
        }
        acknowledgementConfirmed = true
    }

    private func requireSession(_ sessionID: Data) throws {
        try nfcRequireSession(sessionID)
        guard sessionID == identity.sessionID else {
            throw IrohaPeerNfcErrorV1.continuityMismatch
        }
    }

    private func requireRequestContinuity(sessionID: Data, requestHash: Data) throws {
        try requireSession(sessionID)
        try nfcRequireHash(requestHash)
        guard requestHash == identity.requestCanonicalHash else {
            throw IrohaPeerNfcErrorV1.continuityMismatch
        }
    }

    private func readSlice(
        _ message: Data,
        offset: UInt32,
        requestedLength: Int
    ) throws -> Data {
        guard requestedLength > 0,
              requestedLength <= limits.maximumReadChunkBytes else {
            throw IrohaPeerNfcErrorV1.invalidLength
        }
        guard let start = Int(exactly: offset), start < message.count else {
            throw IrohaPeerNfcErrorV1.invalidOffset
        }
        let end = start + min(requestedLength, message.count - start)
        return message.subdata(in: start..<end)
    }

    private static func failureResponse(
        for error: IrohaPeerNfcErrorV1
    ) -> IrohaPeerNfcAPDUResponseV1 {
        let statusWord: IrohaPeerNfcStatusWordV1
        switch error {
        case .invalidCommandClass:
            statusWord = .classNotSupported
        case .unsupportedInstruction:
            statusWord = .instructionNotSupported
        case .invalidLength, .messageTooLarge:
            statusWord = .wrongLength
        case .invalidSession, .invalidHash, .invalidProfile, .invalidKind,
             .continuityMismatch, .invalidIPM1:
            statusWord = .securityStatusNotSatisfied
        case .stateMismatch, .durableAdmissionRequired, .durableCommitRequired,
             .acknowledgementNotDurable, .conflictingReplay, .peerRejected,
             .peerPersistenceFailure:
            statusWord = .conditionsNotSatisfied
        case .invalidApplicationIdentifier:
            statusWord = .notFound
        case .invalidAPDU, .invalidOffset, .invalidFlags:
            statusWord = .wrongData
        }
        return IrohaPeerNfcAPDUResponseV1(statusWord: statusWord)
    }
}

/// Helpers for the request-reading phase before a payment checkpoint exists.
public enum IrohaPeerNfcReaderPlanningV1 {
    public static func getStatusCommand(
        for info: IrohaPeerNfcInfoV1
    ) -> IrohaPeerNfcCommandV1 {
        .getStatus(
            sessionID: info.identity.sessionID,
            requestCanonicalHash: info.identity.requestCanonicalHash
        )
    }

    public static func readRequestCommand(
        for info: IrohaPeerNfcInfoV1,
        offset: Int,
        localLimits: IrohaPeerNfcLimitsV1 = .default
    ) throws -> IrohaPeerNfcCommandV1 {
        guard info.requestLength <= localLimits.maximumMessageBytes else {
            throw IrohaPeerNfcErrorV1.messageTooLarge(
                actual: info.requestLength,
                maximum: localLimits.maximumMessageBytes
            )
        }
        guard offset >= 0, offset < info.requestLength, offset <= Int(UInt32.max) else {
            throw IrohaPeerNfcErrorV1.invalidOffset
        }
        return .readRequest(
            sessionID: info.identity.sessionID,
            requestCanonicalHash: info.identity.requestCanonicalHash,
            offset: UInt32(offset),
            length: min(
                min(
                    localLimits.maximumReadChunkBytes,
                    info.maximumReadChunkBytes
                ),
                info.requestLength - offset
            )
        )
    }

    @discardableResult
    public static func validateReceiveRequest(
        _ data: Data,
        against info: IrohaPeerNfcInfoV1,
        limits: IrohaPeerNfcLimitsV1 = .default
    ) throws -> IrohaPeerWireMessageV1 {
        guard data.count == info.requestLength,
              data.count <= limits.maximumMessageBytes else {
            throw IrohaPeerNfcErrorV1.invalidLength
        }
        let message = try nfcDecodeMessage(
            data,
            expectedProfile: info.identity.profile,
            expectedKind: .request,
            limits: limits
        )
        guard message.canonicalHash == info.identity.requestCanonicalHash,
              message.wireHash == info.identity.requestWireHash else {
            throw IrohaPeerNfcErrorV1.invalidHash
        }
        return message
    }
}

/// Sender state that must be saved before the first payment byte is written.
/// Restoring the encoded checkpoint reuses the exact IPM1 payment and can never
/// create or debit a replacement payment on the second tap.
public struct IrohaPeerNfcSenderCheckpointV1: Equatable, Sendable {
    public let identity: IrohaPeerNfcRequestIdentityV1
    public let profilePolicy: IrohaPeerNfcProfilePolicyV1
    public let receiveRequest: IrohaPeerWireMessageV1
    public let payment: IrohaPeerWireMessageV1
    public let durableAcknowledgement: IrohaPeerWireMessageV1?

    public init(
        sessionID: Data,
        receiveRequest: Data,
        payment: Data,
        durableAcknowledgement: Data? = nil,
        profilePolicy: IrohaPeerNfcProfilePolicyV1? = nil,
        limits: IrohaPeerNfcLimitsV1 = .default
    ) throws {
        try nfcRequireSession(sessionID)
        let requestMessage = try nfcDecodeMessage(
            receiveRequest,
            expectedProfile: nil,
            expectedKind: .request,
            limits: limits
        )
        let effectivePolicy = profilePolicy ?? .init(profile: requestMessage.profile)
        guard effectivePolicy.profile == requestMessage.profile else {
            throw IrohaPeerNfcErrorV1.invalidProfile
        }
        let paymentMessage = try nfcDecodeMessage(
            payment,
            expectedProfile: nil,
            expectedKind: .payment,
            limits: limits
        )
        guard effectivePolicy.accepts(paymentMessage.profile) else {
            throw IrohaPeerNfcErrorV1.invalidProfile
        }
        let ackMessage: IrohaPeerWireMessageV1?
        if let durableAcknowledgement {
            ackMessage = try nfcDecodeMessage(
                durableAcknowledgement,
                expectedProfile: nil,
                expectedKind: .credited,
                limits: limits
            )
            guard effectivePolicy.accepts(ackMessage!.profile) else {
                throw IrohaPeerNfcErrorV1.invalidProfile
            }
        } else {
            ackMessage = nil
        }
        try nfcRequireWalletExchange(
            request: requestMessage, payment: paymentMessage, credited: ackMessage)
        self.identity = try IrohaPeerNfcRequestIdentityV1(
            profile: requestMessage.profile,
            sessionID: sessionID,
            requestCanonicalHash: requestMessage.canonicalHash,
            requestWireHash: requestMessage.wireHash
        )
        self.profilePolicy = effectivePolicy
        self.receiveRequest = requestMessage
        self.payment = paymentMessage
        self.durableAcknowledgement = ackMessage
    }

    public var encoded: Data {
        let ack = durableAcknowledgement?.encoded ?? Data()
        var output = IrohaPeerNfcV1.senderCheckpointMagic
        output.append(IrohaPeerNfcV1.wireVersion)
        output.nfcAppendUInt16BE(identity.profile.rawValue)
        output.append(0)
        output.append(identity.sessionID)
        output.nfcAppendUInt32BE(UInt32(receiveRequest.encoded.count))
        output.nfcAppendUInt32BE(UInt32(payment.encoded.count))
        output.nfcAppendUInt32BE(UInt32(ack.count))
        output.append(receiveRequest.encoded)
        output.append(payment.encoded)
        output.append(ack)
        return output
    }

    public static func decode(
        _ data: Data,
        profilePolicy: IrohaPeerNfcProfilePolicyV1? = nil,
        limits: IrohaPeerNfcLimitsV1 = .default
    ) throws -> Self {
        let fixedBytes = 36
        guard data.count > fixedBytes,
              data.prefix(4) == IrohaPeerNfcV1.senderCheckpointMagic,
              data[4] == IrohaPeerNfcV1.wireVersion,
              data[7] == 0,
              let profile = IrohaPeerPayloadProfile(rawValue: data.nfcUInt16BE(at: 5)),
              profile != .reject else {
            throw IrohaPeerNfcErrorV1.invalidLength
        }
        let requestLength = Int(data.nfcUInt32BE(at: 24))
        let paymentLength = Int(data.nfcUInt32BE(at: 28))
        let acknowledgementLength = Int(data.nfcUInt32BE(at: 32))
        guard requestLength > IrohaPeerWireMessageV1.headerBytes,
              paymentLength > IrohaPeerWireMessageV1.headerBytes,
              acknowledgementLength == 0
                || acknowledgementLength > IrohaPeerWireMessageV1.headerBytes,
              requestLength <= limits.maximumMessageBytes,
              paymentLength <= limits.maximumMessageBytes,
              acknowledgementLength <= limits.maximumMessageBytes,
              fixedBytes <= data.count - requestLength,
              fixedBytes + requestLength <= data.count - paymentLength,
              fixedBytes + requestLength + paymentLength <= data.count - acknowledgementLength,
              fixedBytes + requestLength + paymentLength + acknowledgementLength == data.count else {
            throw IrohaPeerNfcErrorV1.invalidLength
        }
        let requestStart = fixedBytes
        let paymentStart = requestStart + requestLength
        let acknowledgementStart = paymentStart + paymentLength
        let checkpoint = try Self(
            sessionID: data.subdata(in: 8..<24),
            receiveRequest: data.subdata(in: requestStart..<paymentStart),
            payment: data.subdata(in: paymentStart..<acknowledgementStart),
            durableAcknowledgement: acknowledgementLength == 0
                ? nil
                : data.subdata(in: acknowledgementStart..<data.count),
            profilePolicy: profilePolicy,
            limits: limits
        )
        guard checkpoint.identity.profile == profile else {
            throw IrohaPeerNfcErrorV1.invalidProfile
        }
        return checkpoint
    }

    fileprivate func addingDurableAcknowledgement(
        _ acknowledgement: Data,
        limits: IrohaPeerNfcLimitsV1
    ) throws -> Self {
        try Self(
            sessionID: identity.sessionID,
            receiveRequest: receiveRequest.encoded,
            payment: payment.encoded,
            durableAcknowledgement: acknowledgement,
            profilePolicy: profilePolicy,
            limits: limits
        )
    }
}

/// One deterministic next step from a status-reconciled sender.
public enum IrohaPeerNfcSenderActionV1: Equatable, Sendable {
    case send(IrohaPeerNfcCommandV1)
    /// Persist the supplied complete, validated ACK via `persistAcknowledgement`.
    case persistAcknowledgement(Data)
    /// The peer is complete and this exact ACK was already durable locally.
    case complete(Data)
}

/// Status-driven sender reducer designed for RF loss between any two APDUs.
///
/// On a second tap, read `GET_INFO`, require the same identity, then pass
/// `GET_STATUS` here. Receiver progress is authoritative; the exact durable
/// payment checkpoint supplies bytes for replay without creating a new debit.
public struct IrohaPeerNfcTwoTapReducerV1: Sendable {
    public typealias AcknowledgementPersistenceHandler = (Data) throws -> Void

    public private(set) var checkpoint: IrohaPeerNfcSenderCheckpointV1
    public let limits: IrohaPeerNfcLimitsV1

    private var acknowledgementBuffer = Data()
    private var expectedAcknowledgementLength: Int?
    private var expectedAcknowledgementHash: Data?

    public init(
        checkpoint: IrohaPeerNfcSenderCheckpointV1,
        limits: IrohaPeerNfcLimitsV1 = .default
    ) {
        self.checkpoint = checkpoint
        self.limits = limits
    }

    public func requireSamePeer(_ info: IrohaPeerNfcInfoV1) throws {
        guard info.identity == checkpoint.identity,
              info.requestLength == checkpoint.receiveRequest.encoded.count else {
            throw IrohaPeerNfcErrorV1.continuityMismatch
        }
    }

    public mutating func nextAction(
        observing status: IrohaPeerNfcStatusV1
    ) throws -> IrohaPeerNfcSenderActionV1 {
        try validateContinuity(status)
        let payment = checkpoint.payment
        switch status.phase {
        case .requestReady:
            guard checkpoint.durableAcknowledgement == nil else {
                throw IrohaPeerNfcErrorV1.continuityMismatch
            }
            resetAcknowledgementBuffer()
            return .send(.beginPayment(
                sessionID: checkpoint.identity.sessionID,
                requestCanonicalHash: checkpoint.identity.requestCanonicalHash,
                paymentHeader: payment.header.bytes
            ))
        case .paymentReceiving:
            guard checkpoint.durableAcknowledgement == nil,
                  status.paymentProfile == payment.profile,
                  status.paymentLength == payment.encoded.count,
                  status.paymentWireHash == payment.wireHash else {
                throw IrohaPeerNfcErrorV1.continuityMismatch
            }
            resetAcknowledgementBuffer()
            if status.receivedPaymentBytes < status.paymentLength {
                let offset = status.receivedPaymentBytes
                let count = min(
                    min(
                        limits.maximumWriteChunkBytes,
                        status.maximumWriteChunkBytes
                    ),
                    status.paymentLength - offset
                )
                guard offset <= Int(UInt32.max) else {
                    throw IrohaPeerNfcErrorV1.invalidOffset
                }
                return .send(.write(
                    sessionID: checkpoint.identity.sessionID,
                    paymentWireHash: payment.wireHash,
                    offset: UInt32(offset),
                    bytes: payment.encoded.subdata(in: offset..<(offset + count))
                ))
            }
            return .send(.commit(
                sessionID: checkpoint.identity.sessionID,
                requestCanonicalHash: checkpoint.identity.requestCanonicalHash,
                paymentWireHash: payment.wireHash
            ))
        case .acknowledgementReady:
            try requirePaymentAndAcknowledgementMetadata(status)
            if let durableAcknowledgement = checkpoint.durableAcknowledgement {
                guard status.acknowledgementProfile == durableAcknowledgement.profile,
                      durableAcknowledgement.encoded.count == status.acknowledgementLength,
                      durableAcknowledgement.wireHash == status.acknowledgementWireHash else {
                    throw IrohaPeerNfcErrorV1.continuityMismatch
                }
                return .send(.confirmAcknowledgement(
                    sessionID: checkpoint.identity.sessionID,
                    paymentWireHash: payment.wireHash,
                    acknowledgementWireHash: durableAcknowledgement.wireHash
                ))
            }
            configureAcknowledgementBuffer(for: status)
            if acknowledgementBuffer.count == status.acknowledgementLength {
                return .persistAcknowledgement(acknowledgementBuffer)
            }
            let offset = acknowledgementBuffer.count
            let count = min(
                min(
                    limits.maximumReadChunkBytes,
                    status.maximumReadChunkBytes
                ),
                status.acknowledgementLength - offset
            )
            return .send(.readAcknowledgement(
                sessionID: checkpoint.identity.sessionID,
                paymentWireHash: payment.wireHash,
                offset: UInt32(offset),
                length: count
            ))
        case .complete:
            try requirePaymentAndAcknowledgementMetadata(status)
            guard let durableAcknowledgement = checkpoint.durableAcknowledgement,
                  status.acknowledgementProfile == durableAcknowledgement.profile,
                  durableAcknowledgement.encoded.count == status.acknowledgementLength,
                  durableAcknowledgement.wireHash == status.acknowledgementWireHash else {
                throw IrohaPeerNfcErrorV1.acknowledgementNotDurable
            }
            return .complete(durableAcknowledgement.encoded)
        }
    }

    /// Supplies the response to the last READ_ACK action. Partial ACK bytes
    /// are intentionally restartable rather than treated as durable state.
    @discardableResult
    public mutating func consumeAcknowledgementChunk(_ bytes: Data) throws -> Bool {
        guard let expectedAcknowledgementLength,
              let expectedAcknowledgementHash,
              !bytes.isEmpty,
              bytes.count <= limits.maximumReadChunkBytes,
              acknowledgementBuffer.count < expectedAcknowledgementLength,
              bytes.count <= expectedAcknowledgementLength - acknowledgementBuffer.count else {
            throw IrohaPeerNfcErrorV1.invalidLength
        }
        acknowledgementBuffer.append(bytes)
        guard acknowledgementBuffer.count == expectedAcknowledgementLength else {
            return false
        }
        let acknowledgement = try nfcDecodeMessage(
            acknowledgementBuffer,
            expectedProfile: nil,
            expectedKind: .credited,
            limits: limits
        )
        guard checkpoint.profilePolicy.accepts(acknowledgement.profile),
              acknowledgement.wireHash == expectedAcknowledgementHash else {
            throw IrohaPeerNfcErrorV1.invalidHash
        }
        try nfcRequireWalletExchange(
            request: checkpoint.receiveRequest, payment: checkpoint.payment, credited: acknowledgement)
        return true
    }

    /// Persists the full sender checkpoint including ACK before allowing
    /// `CONFIRM_ACK`. If persistence throws, the reducer remains ACK-pending.
    public mutating func persistAcknowledgement(
        using persist: AcknowledgementPersistenceHandler
    ) throws {
        let candidate = try acknowledgementCheckpointCandidate()
        try persist(candidate.encoded)
        try installPersistedCheckpoint(candidate)
    }

    /// Builds the exact checkpoint that includes the complete validated ACK.
    /// The caller may persist this value asynchronously, then install it with
    /// `installPersistedCheckpoint(_:)`. Separating those operations keeps the
    /// transport from confirming an ACK before an actor/database write ends.
    public func acknowledgementCheckpointCandidate()
        throws -> IrohaPeerNfcSenderCheckpointV1 {
        guard let expectedAcknowledgementLength,
              let expectedAcknowledgementHash,
              acknowledgementBuffer.count == expectedAcknowledgementLength else {
            throw IrohaPeerNfcErrorV1.stateMismatch
        }
        let candidate = try checkpoint.addingDurableAcknowledgement(
            acknowledgementBuffer,
            limits: limits
        )
        guard candidate.durableAcknowledgement?.wireHash == expectedAcknowledgementHash else {
            throw IrohaPeerNfcErrorV1.invalidHash
        }
        return candidate
    }

    /// Installs only the byte-identical checkpoint previously returned by
    /// `acknowledgementCheckpointCandidate()`. This is the in-memory half of
    /// the sender durability boundary and must follow successful persistence.
    public mutating func installPersistedCheckpoint(
        _ candidate: IrohaPeerNfcSenderCheckpointV1
    ) throws {
        let expected = try acknowledgementCheckpointCandidate()
        guard candidate == expected else {
            throw IrohaPeerNfcErrorV1.continuityMismatch
        }
        checkpoint = candidate
        resetAcknowledgementBuffer()
    }

    private func validateContinuity(_ status: IrohaPeerNfcStatusV1) throws {
        guard status.identity == checkpoint.identity else {
            throw IrohaPeerNfcErrorV1.continuityMismatch
        }
    }

    private func requirePaymentAndAcknowledgementMetadata(
        _ status: IrohaPeerNfcStatusV1
    ) throws {
        guard let acknowledgementProfile = status.acknowledgementProfile,
              checkpoint.profilePolicy.accepts(acknowledgementProfile),
              status.paymentLength == checkpoint.payment.encoded.count,
              status.paymentProfile == checkpoint.payment.profile,
              status.paymentWireHash == checkpoint.payment.wireHash,
              status.acknowledgementLength > IrohaPeerWireMessageV1.headerBytes,
              status.acknowledgementLength <= limits.maximumMessageBytes else {
            throw IrohaPeerNfcErrorV1.continuityMismatch
        }
    }

    private mutating func configureAcknowledgementBuffer(
        for status: IrohaPeerNfcStatusV1
    ) {
        if expectedAcknowledgementLength != status.acknowledgementLength
            || expectedAcknowledgementHash != status.acknowledgementWireHash {
            acknowledgementBuffer.removeAll(keepingCapacity: false)
            expectedAcknowledgementLength = status.acknowledgementLength
            expectedAcknowledgementHash = status.acknowledgementWireHash
        }
    }

    private mutating func resetAcknowledgementBuffer() {
        acknowledgementBuffer.removeAll(keepingCapacity: false)
        expectedAcknowledgementLength = nil
        expectedAcknowledgementHash = nil
    }
}

// Carrier checks preserve exact bytes; only Native can authenticate monetary effects.
private func nfcRequireWalletExchange(
    request: IrohaPeerWireMessageV1, payment: IrohaPeerWireMessageV1,
    credited: IrohaPeerWireMessageV1? = nil
) throws {
    do {
        try KagemushaWalletWireV1.requireExchangeBinding(
            request: IrohaPeerKagemushaWalletAdapterV1.decode(request),
            payment: IrohaPeerKagemushaWalletAdapterV1.decode(payment),
            credited: try credited.map { try IrohaPeerKagemushaWalletAdapterV1.decode($0) })
    } catch { throw IrohaPeerNfcErrorV1.continuityMismatch }
}

private func nfcRequireCreditedScheme(
    request: IrohaPeerWireMessageV1, credited: IrohaPeerWireMessageV1
) throws {
    do {
        try KagemushaWalletWireV1.requireCreditedScheme(
            request: IrohaPeerKagemushaWalletAdapterV1.decode(request),
            credited: IrohaPeerKagemushaWalletAdapterV1.decode(credited))
    } catch { throw IrohaPeerNfcErrorV1.continuityMismatch }
}

private func nfcDecodeMessage(
    _ data: Data,
    expectedProfile: IrohaPeerPayloadProfile?,
    expectedKind: IrohaPeerPayloadKind,
    limits: IrohaPeerNfcLimitsV1
) throws -> IrohaPeerWireMessageV1 {
    guard data.count > IrohaPeerWireMessageV1.headerBytes else {
        throw IrohaPeerNfcErrorV1.invalidLength
    }
    guard data.count <= limits.maximumMessageBytes else {
        throw IrohaPeerNfcErrorV1.messageTooLarge(
            actual: data.count,
            maximum: limits.maximumMessageBytes
        )
    }
    do {
        let message = try IrohaPeerWireMessageV1.decode(
            data,
            expectedProfile: expectedProfile,
            expectedKind: expectedKind
        )
        guard !message.canonicalPayload.isEmpty else {
            throw IrohaPeerNfcErrorV1.invalidLength
        }
        return message
    } catch let error as IrohaPeerNfcErrorV1 {
        throw error
    } catch let error as IrohaPeerWireMessageErrorV1 {
        switch error {
        case .unexpectedProfile, .invalidProfile:
            throw IrohaPeerNfcErrorV1.invalidProfile
        case .unexpectedKind, .invalidKind:
            throw IrohaPeerNfcErrorV1.invalidKind
        case .canonicalHashMismatch, .wireHashMismatch:
            throw IrohaPeerNfcErrorV1.invalidHash
        case .canonicalLengthOutOfRange, .encodedLengthOutOfRange, .lengthMismatch:
            throw IrohaPeerNfcErrorV1.invalidLength
        default:
            throw IrohaPeerNfcErrorV1.invalidIPM1
        }
    } catch {
        throw IrohaPeerNfcErrorV1.invalidIPM1
    }
}

/// Complete sender-side result. `checkpoint` contains the durable ACK and is
/// safe to reload if the final `CONFIRM_ACK` response was lost.
public enum IrohaPeerNfcConfirmationStateV1: Equatable, Sendable {
    case confirmed
    case responseUnknown
}

public struct IrohaPeerNfcReaderExchangeResultV1: Equatable, Sendable {
    public let checkpoint: IrohaPeerNfcSenderCheckpointV1
    public let acknowledgement: IrohaPeerWireMessageV1
    public let confirmationState: IrohaPeerNfcConfirmationStateV1

    public init(
        checkpoint: IrohaPeerNfcSenderCheckpointV1,
        acknowledgement: IrohaPeerWireMessageV1,
        confirmationState: IrohaPeerNfcConfirmationStateV1 = .confirmed
    ) {
        self.checkpoint = checkpoint
        self.acknowledgement = acknowledgement
        self.confirmationState = confirmationState
    }
}

/// Transport-neutral, status-reconciled reader exchange.
///
/// `loadOrCreateDurableCheckpoint` is the sole fresh-value boundary. It must
/// atomically return an already-durable exact checkpoint, either by loading the
/// existing request-bound value or by creating and storing it in one
/// transaction. The exchange validates that returned checkpoint before the
/// first `BEGIN_PAYMENT`. `updateDurableCheckpoint` is reserved for the later
/// monotonic ACK-bearing checkpoint update before `CONFIRM_ACK` is emitted.
public enum IrohaPeerNfcReaderExchangeV1 {
    public typealias Transceive = @Sendable (
        IrohaPeerNfcCommandV1
    ) async throws -> IrohaPeerNfcAPDUResponseV1
    public typealias LoadOrCreateDurableCheckpoint = @Sendable (
        IrohaPeerNfcInfoV1,
        IrohaPeerWireMessageV1
    ) async throws -> IrohaPeerNfcSenderCheckpointV1
    public typealias UpdateDurableCheckpoint = @Sendable (Data) async throws -> Void

    /// Covers three protocol-maximum messages at the minimum one-byte chunk,
    /// plus SELECT/INFO, phase probes, controls, and durable transitions.
    public static let defaultMaximumActions =
        3 * IrohaPeerNfcV1.maximumMessageBytes + 16

    private struct ActionBudget {
        var remaining: Int

        mutating func consume() throws {
            guard remaining > 0 else {
                throw IrohaPeerNfcErrorV1.stateMismatch
            }
            remaining -= 1
        }
    }

    public static func run(
        restoredCheckpoint: Data? = nil,
        profilePolicy: IrohaPeerNfcProfilePolicyV1,
        limits: IrohaPeerNfcLimitsV1 = .default,
        maximumActions: Int = IrohaPeerNfcReaderExchangeV1.defaultMaximumActions,
        transceive: Transceive,
        loadOrCreateDurableCheckpoint: LoadOrCreateDurableCheckpoint,
        updateDurableCheckpoint: UpdateDurableCheckpoint
    ) async throws -> IrohaPeerNfcReaderExchangeResultV1 {
        precondition(maximumActions > 0)
        var actionBudget = ActionBudget(remaining: maximumActions)

        try actionBudget.consume()
        try requireEmptySuccess(await transceive(.selectApplication), operation: .selectApplication)
        try actionBudget.consume()
        let infoResponse = try await requireSuccess(transceive(.getInfo), operation: .getInfo)
        let info = try IrohaPeerNfcInfoV1.decode(infoResponse.data)
        guard info.identity.profile == profilePolicy.profile else {
            throw IrohaPeerNfcErrorV1.invalidProfile
        }
        guard info.requestLength <= limits.maximumMessageBytes else {
            throw IrohaPeerNfcErrorV1.messageTooLarge(
                actual: info.requestLength,
                maximum: limits.maximumMessageBytes
            )
        }
        if restoredCheckpoint == nil {
            // Only a newly advertised request may authorize value creation.
            // Other phases belong to an already-started exchange and require
            // its exact durable sender checkpoint to resume without re-debit.
            guard info.phase == .requestReady else {
                throw IrohaPeerNfcErrorV1.stateMismatch
            }
        }

        let checkpoint: IrohaPeerNfcSenderCheckpointV1
        if let restoredCheckpoint {
            checkpoint = try IrohaPeerNfcSenderCheckpointV1.decode(
                restoredCheckpoint,
                profilePolicy: profilePolicy,
                limits: limits
            )
            let continuity = IrohaPeerNfcTwoTapReducerV1(
                checkpoint: checkpoint,
                limits: limits
            )
            try continuity.requireSamePeer(info)
        } else {
            var requestBytes = Data()
            requestBytes.reserveCapacity(info.requestLength)
            while requestBytes.count < info.requestLength {
                let command = try IrohaPeerNfcReaderPlanningV1.readRequestCommand(
                    for: info,
                    offset: requestBytes.count,
                    localLimits: limits
                )
                guard case .readRequest(_, _, _, let requestedLength) = command else {
                    throw IrohaPeerNfcErrorV1.stateMismatch
                }
                try actionBudget.consume()
                let response = try await requireSuccess(
                    transceive(command), operation: command.operation
                )
                guard !response.data.isEmpty,
                      response.data.count <= requestedLength,
                      response.data.count <= info.requestLength - requestBytes.count else {
                    throw IrohaPeerNfcErrorV1.invalidLength
                }
                requestBytes.append(response.data)
            }
            let request = try IrohaPeerNfcReaderPlanningV1.validateReceiveRequest(
                requestBytes,
                against: info,
                limits: limits
            )
            // Loading or atomically creating the mandatory pre-BEGIN_PAYMENT
            // durable checkpoint is one application transition. Charge it
            // before invoking application code so a hostile one-byte peer
            // cannot exhaust the budget only after value has been created.
            try actionBudget.consume()
            checkpoint = try await loadOrCreateDurableCheckpoint(info, request)
            let continuity = IrohaPeerNfcTwoTapReducerV1(
                checkpoint: checkpoint,
                limits: limits
            )
            guard checkpoint.profilePolicy == profilePolicy,
                  checkpoint.receiveRequest == request else {
                throw IrohaPeerNfcErrorV1.continuityMismatch
            }
            try continuity.requireSamePeer(info)
        }

        var reducer = IrohaPeerNfcTwoTapReducerV1(
            checkpoint: checkpoint,
            limits: limits
        )
        while true {
            let statusCommand = IrohaPeerNfcReaderPlanningV1.getStatusCommand(for: info)
            try actionBudget.consume()
            let statusResponse = try await requireSuccess(
                transceive(statusCommand), operation: statusCommand.operation
            )
            let status = try IrohaPeerNfcStatusV1.decode(statusResponse.data)
            let action = try reducer.nextAction(observing: status)
            try actionBudget.consume()
            switch action {
            case .send(let command):
                let rawResponse: IrohaPeerNfcAPDUResponseV1
                do {
                    rawResponse = try await transceive(command)
                } catch {
                    if error is any IrohaPeerNfcAmbiguousResponseErrorV1,
                       case .confirmAcknowledgement = command,
                       let acknowledgement = reducer.checkpoint
                        .durableAcknowledgement {
                        // The payment and semantic ACK are already durable on
                        // both wallets. CONFIRM_ACK is cleanup-only, and its
                        // response is ambiguous after RF loss.
                        return IrohaPeerNfcReaderExchangeResultV1(
                            checkpoint: reducer.checkpoint,
                            acknowledgement: acknowledgement,
                            confirmationState: .responseUnknown
                        )
                    }
                    throw error
                }
                let response = try requireSuccess(rawResponse, operation: command.operation)
                switch command {
                case .readAcknowledgement:
                    break
                default:
                    guard response.data.isEmpty else {
                        throw IrohaPeerNfcErrorV1.invalidLength
                    }
                }
                switch command {
                case .write(_, _, let rawOffset, let bytes):
                    // A successful WRITE response proves that exact contiguous
                    // range was accepted. Continue from the next local offset
                    // without paying for a redundant status round-trip. If
                    // any later response is lost, this run throws and the next
                    // run resumes from receiver-authoritative GET_STATUS.
                    let payment = reducer.checkpoint.payment
                    guard let start = Int(exactly: rawOffset),
                          start <= payment.encoded.count,
                          bytes.count <= payment.encoded.count - start else {
                        throw IrohaPeerNfcErrorV1.invalidOffset
                    }
                    var offset = start + bytes.count
                    while offset < payment.encoded.count {
                        let count = min(
                            min(
                                limits.maximumWriteChunkBytes,
                                status.maximumWriteChunkBytes
                            ),
                            payment.encoded.count - offset
                        )
                        guard count > 0, offset <= Int(UInt32.max) else {
                            throw IrohaPeerNfcErrorV1.invalidOffset
                        }
                        let nextWrite = IrohaPeerNfcCommandV1.write(
                            sessionID: reducer.checkpoint.identity.sessionID,
                            paymentWireHash: payment.wireHash,
                            offset: UInt32(offset),
                            bytes: payment.encoded.subdata(
                                in: offset..<(offset + count)
                            )
                        )
                        try actionBudget.consume()
                        try requireEmptySuccess(
                            await transceive(nextWrite), operation: nextWrite.operation
                        )
                        offset += count
                    }

                    // Every payment byte has a successful response, so COMMIT
                    // is safe without another status read. A lost COMMIT
                    // response remains resumable because the receiver either
                    // reports paymentReceiving or acknowledgementReady on the
                    // next run.
                    try actionBudget.consume()
                    let commitCommand = IrohaPeerNfcCommandV1.commit(
                        sessionID: reducer.checkpoint.identity.sessionID,
                        requestCanonicalHash:
                            reducer.checkpoint.identity.requestCanonicalHash,
                        paymentWireHash: payment.wireHash
                    )
                    try requireEmptySuccess(
                        await transceive(commitCommand), operation: .commit
                    )

                case .readAcknowledgement(_, _, _, let requestedLength):
                    guard response.data.count <= requestedLength else {
                        throw IrohaPeerNfcErrorV1.invalidLength
                    }
                    _ = try reducer.consumeAcknowledgementChunk(response.data)
                    var acknowledgementAction = try reducer.nextAction(
                        observing: status
                    )
                    while true {
                        try actionBudget.consume()
                        switch acknowledgementAction {
                        case .send(let nextCommand):
                            switch nextCommand {
                            case .readAcknowledgement(_, _, _, let nextRequestedLength):
                                let nextResponse = try await requireSuccess(
                                    transceive(nextCommand), operation: nextCommand.operation
                                )
                                guard nextResponse.data.count <= nextRequestedLength else {
                                    throw IrohaPeerNfcErrorV1.invalidLength
                                }
                                _ = try reducer.consumeAcknowledgementChunk(
                                    nextResponse.data
                                )
                            case .confirmAcknowledgement:
                                // The ACK-bearing checkpoint was persisted and
                                // installed before this command was produced.
                                // A lost response is recovered from COMPLETE
                                // status using that same durable checkpoint.
                                guard let acknowledgement = reducer.checkpoint
                                    .durableAcknowledgement else {
                                    throw IrohaPeerNfcErrorV1
                                        .acknowledgementNotDurable
                                }
                                let confirmResponse: IrohaPeerNfcAPDUResponseV1
                                do {
                                    confirmResponse = try await transceive(
                                        nextCommand
                                    )
                                } catch where error is any IrohaPeerNfcAmbiguousResponseErrorV1 {
                                    // The durable ACK makes a lost final
                                    // response financially complete.
                                    return IrohaPeerNfcReaderExchangeResultV1(
                                        checkpoint: reducer.checkpoint,
                                        acknowledgement: acknowledgement,
                                        confirmationState: .responseUnknown
                                    )
                                }
                                try requireEmptySuccess(
                                    confirmResponse, operation: nextCommand.operation
                                )
                                return IrohaPeerNfcReaderExchangeResultV1(
                                    checkpoint: reducer.checkpoint,
                                    acknowledgement: acknowledgement
                                )
                            default:
                                throw IrohaPeerNfcErrorV1.stateMismatch
                            }

                        case .persistAcknowledgement:
                            let candidate = try reducer
                                .acknowledgementCheckpointCandidate()
                            try await updateDurableCheckpoint(candidate.encoded)
                            try reducer.installPersistedCheckpoint(candidate)

                        case .complete:
                            throw IrohaPeerNfcErrorV1.stateMismatch
                        }
                        acknowledgementAction = try reducer.nextAction(
                            observing: status
                        )
                    }

                case .confirmAcknowledgement:
                    guard let acknowledgement = reducer.checkpoint
                        .durableAcknowledgement else {
                        throw IrohaPeerNfcErrorV1.acknowledgementNotDurable
                    }
                    return IrohaPeerNfcReaderExchangeResultV1(
                        checkpoint: reducer.checkpoint,
                        acknowledgement: acknowledgement
                    )

                default:
                    // BEGIN_PAYMENT and COMMIT are phase boundaries. Re-enter
                    // through GET_STATUS so the receiver remains authoritative
                    // before the next phase.
                    break
                }

            case .persistAcknowledgement:
                let candidate = try reducer.acknowledgementCheckpointCandidate()
                try await updateDurableCheckpoint(candidate.encoded)
                try reducer.installPersistedCheckpoint(candidate)

            case .complete:
                guard let acknowledgement = reducer.checkpoint.durableAcknowledgement else {
                    throw IrohaPeerNfcErrorV1.acknowledgementNotDurable
                }
                return IrohaPeerNfcReaderExchangeResultV1(
                    checkpoint: reducer.checkpoint,
                    acknowledgement: acknowledgement
                )
            }
        }
    }

    private static func requireSuccess(
        _ response: IrohaPeerNfcAPDUResponseV1,
        operation: IrohaPeerNfcOperationV1
    ) throws -> IrohaPeerNfcAPDUResponseV1 {
        switch response.statusWord {
        case .success:
            return response
        case .storageFailure:
            throw IrohaPeerNfcErrorV1.peerPersistenceFailure(operation: operation)
        case .wrongLength:
            throw IrohaPeerNfcErrorV1.invalidLength
        case .securityStatusNotSatisfied:
            throw IrohaPeerNfcErrorV1.continuityMismatch
        case .conditionsNotSatisfied:
            throw IrohaPeerNfcErrorV1.peerRejected(operation: operation)
        case .wrongData:
            throw IrohaPeerNfcErrorV1.invalidAPDU
        case .notFound:
            throw IrohaPeerNfcErrorV1.invalidApplicationIdentifier
        case .instructionNotSupported:
            throw IrohaPeerNfcErrorV1.unsupportedInstruction(0)
        case .classNotSupported:
            throw IrohaPeerNfcErrorV1.invalidCommandClass(0)
        }
    }

    private static func requireEmptySuccess(
        _ response: IrohaPeerNfcAPDUResponseV1,
        operation: IrohaPeerNfcOperationV1
    ) throws {
        let successful = try requireSuccess(response, operation: operation)
        guard successful.data.isEmpty else {
            throw IrohaPeerNfcErrorV1.invalidLength
        }
    }
}

private func nfcRequireSession(_ data: Data) throws {
    guard data.count == IrohaPeerNfcV1.sessionIDBytes,
          data.contains(where: { $0 != 0 }) else {
        throw IrohaPeerNfcErrorV1.invalidSession
    }
}

private func nfcRequireHash(_ data: Data) throws {
    guard data.count == IrohaPeerNfcV1.hashBytes,
          data.contains(where: { $0 != 0 }) else {
        throw IrohaPeerNfcErrorV1.invalidHash
    }
}

private func nfcRequireChunkLimit(_ value: Int) throws {
    guard (1...IrohaPeerNfcV1.maximumChunkBytes).contains(value) else {
        throw IrohaPeerNfcErrorV1.invalidLength
    }
}

private func nfcUInt32BE(_ value: UInt32) -> Data {
    var data = Data()
    data.nfcAppendUInt32BE(value)
    return data
}

private extension Data {
    mutating func nfcAppendUInt16BE(_ value: UInt16) {
        append(UInt8(truncatingIfNeeded: value >> 8))
        append(UInt8(truncatingIfNeeded: value))
    }

    mutating func nfcAppendUInt32BE(_ value: UInt32) {
        append(UInt8(truncatingIfNeeded: value >> 24))
        append(UInt8(truncatingIfNeeded: value >> 16))
        append(UInt8(truncatingIfNeeded: value >> 8))
        append(UInt8(truncatingIfNeeded: value))
    }

    func nfcUInt16BE(at offset: Int) -> UInt16 {
        UInt16(self[offset]) << 8 | UInt16(self[offset + 1])
    }

    func nfcUInt32BE(at offset: Int) -> UInt32 {
        UInt32(self[offset]) << 24
            | UInt32(self[offset + 1]) << 16
            | UInt32(self[offset + 2]) << 8
            | UInt32(self[offset + 3])
    }
}
