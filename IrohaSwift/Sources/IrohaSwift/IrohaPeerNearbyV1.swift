import CryptoKit
import Foundation

/// Transport-independent authenticated session records for Nearby Connections.
///
/// Google Nearby verifies that both users approved the same connection code.
/// This layer additionally binds the monetary profile, request, device
/// certificate and ephemeral key to an application transcript. Radio adapters
/// must never skip either verification step.
public enum IrohaPeerNearbyV1 {
    public static let serviceID = "org.hyperledger.iroha.kagemusha.transfer.v1"
    public static let bonjourService = "_F2EBA4BCB49B._tcp"
    public static let wireVersion: UInt8 = 1
    public static let maximumCertificateBytes = 16 * 1_024
    /// Leaves a conservative 64-byte record-overhead budget inside 32 KiB.
    public static let maximumMessageBytes = 32 * 1_024 - 64
    /// Keeps the complete 60-byte-header authentication record within the
    /// common 32 KiB iOS/Android radio ceiling.
    public static let maximumAuthenticationSignatureBytes = 32 * 1_024 - 60

    fileprivate static let magic = Data("IPN1".utf8)
    fileprivate static let discoveryMagic = Data("IPD1".utf8)
    fileprivate static let transcriptDomain = Data("IROHA-PEER-NEARBY-TRANSCRIPT-V1\0".utf8)
    fileprivate static let authenticationDomain = Data("IROHA-PEER-NEARBY-AUTH-V1\0".utf8)
    fileprivate static let keyDomain = Data("IROHA-PEER-NEARBY-KEYS-V1\0".utf8)
    fileprivate static let pictureDomain = Data("IROHA-PEER-NEARBY-PICTURE-V1\0".utf8)
}

public enum IrohaPeerNearbyRoleV1: UInt8, Sendable {
    case sender = 1
    case receiver = 2

    public var peer: IrohaPeerNearbyRoleV1 {
        self == .sender ? .receiver : .sender
    }
}

public enum IrohaPeerNearbyRecordKindV1: UInt8, Sendable {
    case hello = 1
    case authentication = 2
    case encryptedMessage = 3
    /// The receiver's `IAK1` ask, sealed like a message (`IrohaPeerNearbySessionV1.sealAsk`).
    case encryptedAsk = 4
}

public enum IrohaPeerNearbyErrorV1: Error, Equatable, Sendable {
    case invalidLength
    case invalidMagic
    case unsupportedVersion
    case invalidRecordKind
    case invalidProfile
    case invalidRole
    case invalidFlags
    case invalidSession
    case invalidRequest
    case invalidPublicKey
    case invalidCertificate
    case invalidDiscoveryRepresentation
    case transcriptMismatch
    case authenticationFailed
    case verificationRequired
    case notAuthenticated
    case sessionDestroyed
    case replayOrReordering
    case messageTooLarge
    case cryptographicFailure
    /// Picture pairing got digits outside 4 to 12 ASCII digits, or a target that
    /// is not one of the pictures.
    case invalidPictureCode
}

/// Small discovery payload. It lets a sender reject unrelated advertisements
/// before requesting a connection, without exposing an account identifier.
public struct IrohaPeerNearbyDiscoveryContextV1: Equatable, Sendable {
    public let profile: IrohaPeerPayloadProfile
    public let role: IrohaPeerNearbyRoleV1
    public let sessionID: Data
    public let requestCanonicalHash: Data

    public init(
        profile: IrohaPeerPayloadProfile,
        role: IrohaPeerNearbyRoleV1,
        sessionID: Data,
        requestCanonicalHash: Data
    ) throws {
        try self.init(
            profile: profile,
            role: role,
            sessionID: sessionID,
            requestCanonicalHash: requestCanonicalHash,
            allowsBootstrapSentinel: false
        )
    }

    /// Explicit pre-authentication discovery sentinel for a sender that does
    /// not know the receiver's request context yet. It is never a valid IPN1
    /// session context; the receiver's nonzero advertisement must replace it
    /// before a connection is requested.
    public static func senderBootstrap(
        profile: IrohaPeerPayloadProfile
    ) throws -> Self {
        try Self(
            profile: profile,
            role: .sender,
            sessionID: Data(repeating: 0, count: 16),
            requestCanonicalHash: Data(repeating: 0, count: 32),
            allowsBootstrapSentinel: true
        )
    }

    /// Receiver context for a session that starts before the receiver holds a
    /// Request: a random session identifier and a random 32-byte binding in
    /// place of the Request hash. The Offer, Request, Payment and Credited then
    /// all travel inside the authenticated session
    /// (`specs/kagemusha_wallet_wire_v1.md` §6).
    public static func freshReceiver(profile: IrohaPeerPayloadProfile) throws -> Self {
        var generator = SystemRandomNumberGenerator()
        func randomNonzero(_ count: Int) -> Data {
            while true {
                let bytes = Data((0..<count).map { _ in UInt8.random(in: .min ... .max, using: &generator) })
                if bytes.contains(where: { $0 != 0 }) { return bytes }
            }
        }
        return try Self(
            profile: profile,
            role: .receiver,
            sessionID: randomNonzero(16),
            requestCanonicalHash: randomNonzero(32)
        )
    }

    private init(
        profile: IrohaPeerPayloadProfile,
        role: IrohaPeerNearbyRoleV1,
        sessionID: Data,
        requestCanonicalHash: Data,
        allowsBootstrapSentinel: Bool
    ) throws {
        guard profile.rawValue != 0 else { throw IrohaPeerNearbyErrorV1.invalidProfile }
        guard sessionID.count == 16,
              allowsBootstrapSentinel || sessionID.contains(where: { $0 != 0 }) else {
            throw IrohaPeerNearbyErrorV1.invalidSession
        }
        guard requestCanonicalHash.count == 32,
              allowsBootstrapSentinel || requestCanonicalHash.contains(where: { $0 != 0 }) else {
            throw IrohaPeerNearbyErrorV1.invalidRequest
        }
        if allowsBootstrapSentinel {
            guard sessionID.allSatisfy({ $0 == 0 }),
                  requestCanonicalHash.allSatisfy({ $0 == 0 }) else {
                throw IrohaPeerNearbyErrorV1.invalidRequest
            }
        }
        self.profile = profile
        self.role = role
        self.sessionID = Data(sessionID)
        self.requestCanonicalHash = Data(requestCanonicalHash)
    }

    public func encode() -> Data {
        var output = IrohaPeerNearbyV1.discoveryMagic
        output.append(IrohaPeerNearbyV1.wireVersion)
        output.appendUInt16BE(profile.rawValue)
        output.append(role.rawValue)
        output.append(sessionID)
        output.append(requestCanonicalHash)
        return output
    }

    /// Canonical Google Nearby discovery representation: Base64URL without
    /// padding, encoded as ASCII on the radio. Keeping this transform in the
    /// portable core prevents the iOS and Android adapters from drifting.
    public func encodeRadioDiscovery() -> String {
        encode()
            .base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    /// Strictly decodes the canonical radio form. Standard Base64, padding,
    /// whitespace, non-ASCII text and non-canonical pad-bit aliases fail.
    public static func decodeRadioDiscovery(_ representation: String) throws -> Self {
        let scalars = representation.unicodeScalars
        guard representation.utf8.count == 75,
              scalars.allSatisfy({ scalar in
                  (48...57).contains(scalar.value)
                      || (65...90).contains(scalar.value)
                      || (97...122).contains(scalar.value)
                      || scalar.value == 45
                      || scalar.value == 95
              }) else {
            throw IrohaPeerNearbyErrorV1.invalidDiscoveryRepresentation
        }
        var standard = representation
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        standard.append(String(repeating: "=", count: (4 - standard.count % 4) % 4))
        guard let bytes = Data(base64Encoded: standard),
              bytes.count == 56 else {
            throw IrohaPeerNearbyErrorV1.invalidDiscoveryRepresentation
        }
        let decoded = try decode(bytes)
        guard decoded.encodeRadioDiscovery() == representation else {
            throw IrohaPeerNearbyErrorV1.invalidDiscoveryRepresentation
        }
        return decoded
    }

    public var isSenderBootstrap: Bool {
        role == .sender
            && sessionID.allSatisfy { $0 == 0 }
            && requestCanonicalHash.allSatisfy { $0 == 0 }
    }

    public static func decode(_ data: Data) throws -> Self {
        guard data.count == 4 + 1 + 2 + 1 + 16 + 32 else {
            throw IrohaPeerNearbyErrorV1.invalidLength
        }
        let bytes = [UInt8](data)
        guard Data(bytes[0..<4]) == IrohaPeerNearbyV1.discoveryMagic else {
            throw IrohaPeerNearbyErrorV1.invalidMagic
        }
        guard bytes[4] == IrohaPeerNearbyV1.wireVersion else {
            throw IrohaPeerNearbyErrorV1.unsupportedVersion
        }
        guard let profile = IrohaPeerPayloadProfile(rawValue: readUInt16BE(bytes, at: 5)),
              profile.rawValue != 0 else {
            throw IrohaPeerNearbyErrorV1.invalidProfile
        }
        guard let role = IrohaPeerNearbyRoleV1(rawValue: bytes[7]) else {
            throw IrohaPeerNearbyErrorV1.invalidRole
        }
        let sessionID = Data(bytes[8..<24])
        let requestCanonicalHash = Data(bytes[24..<56])
        let hasZeroSession = sessionID.allSatisfy { $0 == 0 }
        let hasZeroRequest = requestCanonicalHash.allSatisfy { $0 == 0 }
        if hasZeroSession || hasZeroRequest {
            guard hasZeroSession && hasZeroRequest else {
                throw hasZeroSession
                    ? IrohaPeerNearbyErrorV1.invalidSession
                    : IrohaPeerNearbyErrorV1.invalidRequest
            }
            guard role == .sender else {
                throw IrohaPeerNearbyErrorV1.invalidRole
            }
            return try Self.senderBootstrap(profile: profile)
        }
        return try Self(
            profile: profile,
            role: role,
            sessionID: sessionID,
            requestCanonicalHash: requestCanonicalHash
        )
    }
}

/// Pure discovery selection shared by radio adapters and tests. A sender may
/// begin with the explicit zero sentinel and adopts the advertised receiver's
/// nonzero request context before it requests a connection. No other zero
/// context participates in matching.
public enum IrohaPeerNearbyDiscoveryMatcherV1 {
    public static func selectLocalContext(
        local: IrohaPeerNearbyDiscoveryContextV1,
        remote: IrohaPeerNearbyDiscoveryContextV1,
        expectedRemoteRole: IrohaPeerNearbyRoleV1
    ) -> IrohaPeerNearbyDiscoveryContextV1? {
        guard remote.profile == local.profile,
              remote.role == expectedRemoteRole else {
            return nil
        }
        if local.isSenderBootstrap {
            guard !remote.isSenderBootstrap,
                  remote.sessionID.contains(where: { $0 != 0 }),
                  remote.requestCanonicalHash.contains(where: { $0 != 0 }) else {
                return nil
            }
            return try? IrohaPeerNearbyDiscoveryContextV1(
                profile: local.profile,
                role: local.role,
                sessionID: remote.sessionID,
                requestCanonicalHash: remote.requestCanonicalHash
            )
        }
        guard !remote.isSenderBootstrap,
              remote.sessionID == local.sessionID,
              remote.requestCanonicalHash == local.requestCanonicalHash else {
            return nil
        }
        return local
    }
}

public enum IrohaPeerNearbyVerificationCodeV1 {
    public static func isValid(_ code: String) -> Bool {
        (4...12).contains(code.utf8.count) &&
            code.utf8.allSatisfy { (48...57).contains($0) }
    }
}

/// Picture pairing in place of the transport's verification digits
/// (`specs/kagemusha_wallet_wire_v1.md` §6). Both phones derive the same one of
/// ``pictureCount`` pictures from the digits, which are never shown. The
/// connecting payer shows that picture; the receiver shows ``gridSize``
/// pictures that include it, in a fresh random order, and accepts the
/// connection only when the person picks the payer's picture. The pick gates
/// the radio connection only; the IPN1 signatures still authenticate the peer.
public enum IrohaPeerNearbyPictureCodeV1 {
    public static let pictureCount = 16
    public static let gridSize = 6

    /// `SHA-256("IROHA-PEER-NEARBY-PICTURE-V1" ‖ 0x00 ‖ digits)[0] & 0x0f` for
    /// digits that ``IrohaPeerNearbyVerificationCodeV1/isValid(_:)`` accepts.
    ///
    /// - Throws: ``IrohaPeerNearbyErrorV1/invalidPictureCode`` for any other text.
    public static func targetIndex(digits: String) throws -> Int {
        guard IrohaPeerNearbyVerificationCodeV1.isValid(digits) else {
            throw IrohaPeerNearbyErrorV1.invalidPictureCode
        }
        var hasher = SHA256()
        hasher.update(data: IrohaPeerNearbyV1.pictureDomain)
        hasher.update(data: Data(digits.utf8))
        return Int(Array(hasher.finalize())[0] & 0x0f)
    }

    /// ``gridSize`` distinct pictures, `target` among them, in a uniformly random
    /// order drawn from the system random source.
    ///
    /// - Throws: ``IrohaPeerNearbyErrorV1/invalidPictureCode`` for a target
    ///   outside `0..<pictureCount`.
    public static func grid(target: Int) throws -> [Int] {
        var generator = SystemRandomNumberGenerator()
        return try grid(target: target, using: &generator)
    }

    /// ``grid(target:)`` from `generator`. A partial Fisher–Yates draw picks the
    /// other pictures and a Fisher–Yates shuffle orders all of them; every draw
    /// is `Int.random(in:using:)`, which has no modulo bias.
    public static func grid<Generator: RandomNumberGenerator>(
        target: Int,
        using generator: inout Generator
    ) throws -> [Int] {
        guard (0..<pictureCount).contains(target) else {
            throw IrohaPeerNearbyErrorV1.invalidPictureCode
        }
        var pictures = Array(0..<pictureCount)
        pictures.swapAt(0, target)
        for index in 1..<gridSize {
            pictures.swapAt(index, Int.random(in: index..<pictureCount, using: &generator))
        }
        var grid = Array(pictures.prefix(gridSize))
        for index in stride(from: gridSize - 1, to: 0, by: -1) {
            grid.swapAt(index, Int.random(in: 0...index, using: &generator))
        }
        return grid
    }
}

public struct IrohaPeerNearbyHelloV1: Equatable, Sendable {
    public let profile: IrohaPeerPayloadProfile
    public let role: IrohaPeerNearbyRoleV1
    public let sessionID: Data
    public let nonce: Data
    public let requestCanonicalHash: Data
    public let ephemeralPublicKey: Data
    public let deviceCertificate: Data

    public init(
        profile: IrohaPeerPayloadProfile,
        role: IrohaPeerNearbyRoleV1,
        sessionID: Data,
        nonce: Data,
        requestCanonicalHash: Data,
        ephemeralPublicKey: Data,
        deviceCertificate: Data
    ) throws {
        guard profile.rawValue != 0 else { throw IrohaPeerNearbyErrorV1.invalidProfile }
        guard sessionID.count == 16,
              sessionID.contains(where: { $0 != 0 }) else {
            throw IrohaPeerNearbyErrorV1.invalidSession
        }
        guard nonce.count == 32,
              nonce.contains(where: { $0 != 0 }) else {
            throw IrohaPeerNearbyErrorV1.invalidLength
        }
        guard requestCanonicalHash.count == 32,
              requestCanonicalHash.contains(where: { $0 != 0 }) else {
            throw IrohaPeerNearbyErrorV1.invalidRequest
        }
        guard ephemeralPublicKey.count == 65,
              (try? P256.KeyAgreement.PublicKey(x963Representation: ephemeralPublicKey)) != nil else {
            throw IrohaPeerNearbyErrorV1.invalidPublicKey
        }
        guard !deviceCertificate.isEmpty,
              deviceCertificate.count <= IrohaPeerNearbyV1.maximumCertificateBytes else {
            throw IrohaPeerNearbyErrorV1.invalidCertificate
        }
        self.profile = profile
        self.role = role
        self.sessionID = Data(sessionID)
        self.nonce = Data(nonce)
        self.requestCanonicalHash = Data(requestCanonicalHash)
        self.ephemeralPublicKey = Data(ephemeralPublicKey)
        self.deviceCertificate = Data(deviceCertificate)
    }

    public func encode() -> Data {
        var output = IrohaPeerNearbyV1.magic
        output.append(IrohaPeerNearbyV1.wireVersion)
        output.append(IrohaPeerNearbyRecordKindV1.hello.rawValue)
        output.appendUInt16BE(profile.rawValue)
        output.append(role.rawValue)
        output.append(0)
        output.append(sessionID)
        output.append(nonce)
        output.append(requestCanonicalHash)
        output.appendUInt16BE(UInt16(ephemeralPublicKey.count))
        output.append(ephemeralPublicKey)
        output.appendUInt32BE(UInt32(deviceCertificate.count))
        output.append(deviceCertificate)
        return output
    }

    public static func decode(_ data: Data) throws -> Self {
        let fixedLength = 4 + 1 + 1 + 2 + 1 + 1 + 16 + 32 + 32 + 2
        guard data.count >= fixedLength + 65 + 4 + 1,
              data.count <= fixedLength + 65 + 4
                + IrohaPeerNearbyV1.maximumCertificateBytes else {
            throw IrohaPeerNearbyErrorV1.invalidLength
        }
        let bytes = [UInt8](data)
        guard Data(bytes[0..<4]) == IrohaPeerNearbyV1.magic else {
            throw IrohaPeerNearbyErrorV1.invalidMagic
        }
        guard bytes[4] == IrohaPeerNearbyV1.wireVersion else {
            throw IrohaPeerNearbyErrorV1.unsupportedVersion
        }
        guard bytes[5] == IrohaPeerNearbyRecordKindV1.hello.rawValue else {
            throw IrohaPeerNearbyErrorV1.invalidRecordKind
        }
        guard let profile = IrohaPeerPayloadProfile(rawValue: readUInt16BE(bytes, at: 6)),
              profile.rawValue != 0 else {
            throw IrohaPeerNearbyErrorV1.invalidProfile
        }
        guard let role = IrohaPeerNearbyRoleV1(rawValue: bytes[8]) else {
            throw IrohaPeerNearbyErrorV1.invalidRole
        }
        guard bytes[9] == 0 else { throw IrohaPeerNearbyErrorV1.invalidFlags }
        var cursor = 10
        let sessionID = Data(bytes[cursor..<(cursor + 16)])
        cursor += 16
        let nonce = Data(bytes[cursor..<(cursor + 32)])
        cursor += 32
        let requestHash = Data(bytes[cursor..<(cursor + 32)])
        cursor += 32
        let publicKeyLength = Int(readUInt16BE(bytes, at: cursor))
        cursor += 2
        guard publicKeyLength == 65,
              cursor <= bytes.count - publicKeyLength - 4 else {
            throw IrohaPeerNearbyErrorV1.invalidPublicKey
        }
        let publicKey = Data(bytes[cursor..<(cursor + publicKeyLength)])
        cursor += publicKeyLength
        let certificateLength = Int(readUInt32BE(bytes, at: cursor))
        cursor += 4
        guard certificateLength > 0,
              certificateLength <= IrohaPeerNearbyV1.maximumCertificateBytes,
              cursor <= bytes.count - certificateLength,
              cursor + certificateLength == bytes.count else {
            throw IrohaPeerNearbyErrorV1.invalidCertificate
        }
        return try Self(
            profile: profile,
            role: role,
            sessionID: sessionID,
            nonce: nonce,
            requestCanonicalHash: requestHash,
            ephemeralPublicKey: publicKey,
            deviceCertificate: Data(bytes[cursor..<(cursor + certificateLength)])
        )
    }
}

public struct IrohaPeerNearbyAuthenticationV1: Equatable, Sendable {
    public let profile: IrohaPeerPayloadProfile
    public let role: IrohaPeerNearbyRoleV1
    public let sessionID: Data
    public let transcriptHash: Data
    public let signature: Data

    public init(
        profile: IrohaPeerPayloadProfile,
        role: IrohaPeerNearbyRoleV1,
        sessionID: Data,
        transcriptHash: Data,
        signature: Data
    ) throws {
        guard profile.rawValue != 0 else { throw IrohaPeerNearbyErrorV1.invalidProfile }
        guard sessionID.count == 16,
              sessionID.contains(where: { $0 != 0 }) else {
            throw IrohaPeerNearbyErrorV1.invalidSession
        }
        guard transcriptHash.count == 32,
              transcriptHash.contains(where: { $0 != 0 }) else {
            throw IrohaPeerNearbyErrorV1.transcriptMismatch
        }
        guard !signature.isEmpty,
              signature.count <= IrohaPeerNearbyV1.maximumAuthenticationSignatureBytes else {
            throw IrohaPeerNearbyErrorV1.authenticationFailed
        }
        self.profile = profile
        self.role = role
        self.sessionID = Data(sessionID)
        self.transcriptHash = Data(transcriptHash)
        self.signature = Data(signature)
    }

    public func encode() -> Data {
        var output = IrohaPeerNearbyV1.magic
        output.append(IrohaPeerNearbyV1.wireVersion)
        output.append(IrohaPeerNearbyRecordKindV1.authentication.rawValue)
        output.appendUInt16BE(profile.rawValue)
        output.append(role.rawValue)
        output.append(0)
        output.append(sessionID)
        output.append(transcriptHash)
        output.appendUInt16BE(UInt16(signature.count))
        output.append(signature)
        return output
    }

    public static func decode(_ data: Data) throws -> Self {
        let fixedLength = 4 + 1 + 1 + 2 + 1 + 1 + 16 + 32 + 2
        guard data.count >= fixedLength + 1,
              data.count <= fixedLength
                + IrohaPeerNearbyV1.maximumAuthenticationSignatureBytes else {
            throw IrohaPeerNearbyErrorV1.invalidLength
        }
        let bytes = [UInt8](data)
        guard Data(bytes[0..<4]) == IrohaPeerNearbyV1.magic else {
            throw IrohaPeerNearbyErrorV1.invalidMagic
        }
        guard bytes[4] == IrohaPeerNearbyV1.wireVersion else {
            throw IrohaPeerNearbyErrorV1.unsupportedVersion
        }
        guard bytes[5] == IrohaPeerNearbyRecordKindV1.authentication.rawValue else {
            throw IrohaPeerNearbyErrorV1.invalidRecordKind
        }
        guard let profile = IrohaPeerPayloadProfile(rawValue: readUInt16BE(bytes, at: 6)),
              profile.rawValue != 0 else {
            throw IrohaPeerNearbyErrorV1.invalidProfile
        }
        guard let role = IrohaPeerNearbyRoleV1(rawValue: bytes[8]) else {
            throw IrohaPeerNearbyErrorV1.invalidRole
        }
        guard bytes[9] == 0 else { throw IrohaPeerNearbyErrorV1.invalidFlags }
        let signatureLength = Int(readUInt16BE(bytes, at: 58))
        guard signatureLength > 0, fixedLength + signatureLength == bytes.count else {
            throw IrohaPeerNearbyErrorV1.invalidLength
        }
        return try Self(
            profile: profile,
            role: role,
            sessionID: Data(bytes[10..<26]),
            transcriptHash: Data(bytes[26..<58]),
            signature: Data(bytes[60..<bytes.count])
        )
    }
}

public struct IrohaPeerNearbyEncryptedRecordV1: Equatable, Sendable {
    public let profile: IrohaPeerPayloadProfile
    public let senderRole: IrohaPeerNearbyRoleV1
    public let sessionID: Data
    public let sequence: UInt64
    public let ciphertextAndTag: Data
    /// `encryptedMessage` for an `IPM1` message or `encryptedAsk` for the
    /// receiver's ask, sealed in exactly 72 bytes. The header, kind included,
    /// is the AEAD associated data.
    public let kind: IrohaPeerNearbyRecordKindV1

    public init(
        profile: IrohaPeerPayloadProfile,
        senderRole: IrohaPeerNearbyRoleV1,
        sessionID: Data,
        sequence: UInt64,
        ciphertextAndTag: Data,
        kind: IrohaPeerNearbyRecordKindV1 = .encryptedMessage
    ) throws {
        guard profile.rawValue != 0 else { throw IrohaPeerNearbyErrorV1.invalidProfile }
        guard sessionID.count == 16,
              sessionID.contains(where: { $0 != 0 }) else {
            throw IrohaPeerNearbyErrorV1.invalidSession
        }
        guard ciphertextAndTag.count >= 16,
              ciphertextAndTag.count <= IrohaPeerNearbyV1.maximumMessageBytes + 16 else {
            throw IrohaPeerNearbyErrorV1.messageTooLarge
        }
        guard kind == .encryptedMessage || kind == .encryptedAsk else {
            throw IrohaPeerNearbyErrorV1.invalidRecordKind
        }
        guard kind != .encryptedAsk || ciphertextAndTag.count == IrohaPeerAskV1.recordBytes + 16 else {
            throw IrohaPeerNearbyErrorV1.invalidLength
        }
        self.profile = profile
        self.senderRole = senderRole
        self.sessionID = Data(sessionID)
        self.sequence = sequence
        self.ciphertextAndTag = Data(ciphertextAndTag)
        self.kind = kind
    }

    fileprivate func header() -> Data {
        var output = IrohaPeerNearbyV1.magic
        output.append(IrohaPeerNearbyV1.wireVersion)
        output.append(kind.rawValue)
        output.appendUInt16BE(profile.rawValue)
        output.append(senderRole.rawValue)
        output.append(0)
        output.append(sessionID)
        output.appendUInt64BE(sequence)
        output.appendUInt32BE(UInt32(ciphertextAndTag.count))
        return output
    }

    public func encode() -> Data {
        header() + ciphertextAndTag
    }

    public static func decode(_ data: Data) throws -> Self {
        let headerLength = 4 + 1 + 1 + 2 + 1 + 1 + 16 + 8 + 4
        guard data.count >= headerLength + 16,
              data.count <= headerLength + IrohaPeerNearbyV1.maximumMessageBytes + 16 else {
            throw IrohaPeerNearbyErrorV1.invalidLength
        }
        let bytes = [UInt8](data)
        guard Data(bytes[0..<4]) == IrohaPeerNearbyV1.magic else {
            throw IrohaPeerNearbyErrorV1.invalidMagic
        }
        guard bytes[4] == IrohaPeerNearbyV1.wireVersion else {
            throw IrohaPeerNearbyErrorV1.unsupportedVersion
        }
        guard let kind = IrohaPeerNearbyRecordKindV1(rawValue: bytes[5]),
              kind == .encryptedMessage || kind == .encryptedAsk else {
            throw IrohaPeerNearbyErrorV1.invalidRecordKind
        }
        guard let profile = IrohaPeerPayloadProfile(rawValue: readUInt16BE(bytes, at: 6)),
              profile.rawValue != 0 else {
            throw IrohaPeerNearbyErrorV1.invalidProfile
        }
        guard let role = IrohaPeerNearbyRoleV1(rawValue: bytes[8]) else {
            throw IrohaPeerNearbyErrorV1.invalidRole
        }
        guard bytes[9] == 0 else { throw IrohaPeerNearbyErrorV1.invalidFlags }
        let payloadLength = Int(readUInt32BE(bytes, at: 34))
        guard payloadLength >= 16,
              payloadLength <= IrohaPeerNearbyV1.maximumMessageBytes + 16,
              headerLength + payloadLength == bytes.count else {
            throw IrohaPeerNearbyErrorV1.invalidLength
        }
        return try Self(
            profile: profile,
            senderRole: role,
            sessionID: Data(bytes[10..<26]),
            sequence: readUInt64BE(bytes, at: 26),
            ciphertextAndTag: Data(bytes[headerLength..<bytes.count]),
            kind: kind
        )
    }
}

/// Stateful, radio-independent handshake. Construct a fresh instance for each
/// operation; reconnecting a durable transfer must use a newly authenticated
/// session while reusing the exact durable peer message.
public final class IrohaPeerNearbySessionV1: @unchecked Sendable {
    public typealias SignatureVerifier = (
        _ role: IrohaPeerNearbyRoleV1,
        _ certificate: Data,
        _ signedBytes: Data,
        _ signature: Data
    ) throws -> Bool

    private struct VerificationMaterial {
        let role: IrohaPeerNearbyRoleV1
        let certificate: Data
        let signedBytes: Data
        let signature: Data
        let peerPublicKey: Data
        let transcriptHash: Data
    }

    public let profile: IrohaPeerPayloadProfile
    public let localRole: IrohaPeerNearbyRoleV1
    public let sessionID: Data
    public let requestCanonicalHash: Data

    private let stateLock = NSRecursiveLock()
    private var localHelloState: IrohaPeerNearbyHelloV1?
    private var ephemeralPrivateKey: P256.KeyAgreement.PrivateKey?
    private var peerHello: IrohaPeerNearbyHelloV1?
    private var acceptedTranscriptHash: Data?
    private var outboundKey: SymmetricKey?
    private var inboundKey: SymmetricKey?
    private var outboundSequence: UInt64 = 0
    private var inboundSequence: UInt64 = 0
    private var authenticationInProgress = false
    private var destroyed = false

    public init(
        profile: IrohaPeerPayloadProfile,
        localRole: IrohaPeerNearbyRoleV1,
        sessionID: Data,
        requestCanonicalHash: Data,
        deviceCertificate: Data,
        nonce: Data? = nil,
        ephemeralPrivateKey: P256.KeyAgreement.PrivateKey = P256.KeyAgreement.PrivateKey()
    ) throws {
        let nonce = nonce ?? Self.randomBytes(count: 32)
        guard profile.rawValue != 0 else { throw IrohaPeerNearbyErrorV1.invalidProfile }
        guard sessionID.count == 16,
              sessionID.contains(where: { $0 != 0 }) else {
            throw IrohaPeerNearbyErrorV1.invalidSession
        }
        guard requestCanonicalHash.count == 32,
              requestCanonicalHash.contains(where: { $0 != 0 }) else {
            throw IrohaPeerNearbyErrorV1.invalidRequest
        }
        guard nonce.count == 32,
              nonce.contains(where: { $0 != 0 }) else {
            throw IrohaPeerNearbyErrorV1.invalidLength
        }
        guard !deviceCertificate.isEmpty,
              deviceCertificate.count <= IrohaPeerNearbyV1.maximumCertificateBytes else {
            throw IrohaPeerNearbyErrorV1.invalidCertificate
        }
        self.profile = profile
        self.localRole = localRole
        self.sessionID = Data(sessionID)
        self.requestCanonicalHash = Data(requestCanonicalHash)
        self.ephemeralPrivateKey = ephemeralPrivateKey
        self.localHelloState = try IrohaPeerNearbyHelloV1(
            profile: profile,
            role: localRole,
            sessionID: sessionID,
            nonce: nonce,
            requestCanonicalHash: requestCanonicalHash,
            ephemeralPublicKey: ephemeralPrivateKey.publicKey.x963Representation,
            deviceCertificate: deviceCertificate
        )
    }

    /// The local handshake record while this session remains active.
    public var localHello: IrohaPeerNearbyHelloV1 {
        get throws {
            stateLock.lock()
            defer { stateLock.unlock() }
            try requireActive()
            guard let localHelloState else {
                throw IrohaPeerNearbyErrorV1.sessionDestroyed
            }
            return localHelloState
        }
    }

    public var isAuthenticated: Bool {
        stateLock.lock()
        defer { stateLock.unlock() }
        return !destroyed
            && outboundKey != nil
            && inboundKey != nil
            && acceptedTranscriptHash != nil
    }

    /// Whether `destroy()` has permanently closed this session.
    public var isDestroyed: Bool {
        stateLock.lock()
        defer { stateLock.unlock() }
        return destroyed
    }

    /// Permanently closes the session and releases its retained key objects.
    ///
    /// CryptoKit owns the private and symmetric key storage opaquely, so Swift
    /// cannot guarantee a physical overwrite of those internals. Destruction
    /// drops every retained key reference promptly and all later operations
    /// fail closed with `sessionDestroyed`.
    public func destroy() {
        stateLock.lock()
        defer { stateLock.unlock() }
        guard !destroyed else { return }
        destroyed = true
        ephemeralPrivateKey = nil
        outboundKey = nil
        inboundKey = nil
        acceptedTranscriptHash = nil
        peerHello = nil
        localHelloState = nil
        outboundSequence = 0
        inboundSequence = 0
        authenticationInProgress = false
    }

    deinit {
        destroy()
    }

    public func acceptPeerHello(_ hello: IrohaPeerNearbyHelloV1) throws {
        stateLock.lock()
        defer { stateLock.unlock() }
        try requireActive()
        guard let localHelloState else {
            throw IrohaPeerNearbyErrorV1.sessionDestroyed
        }
        guard peerHello == nil else {
            throw IrohaPeerNearbyErrorV1.replayOrReordering
        }
        guard hello.profile == profile else { throw IrohaPeerNearbyErrorV1.invalidProfile }
        guard hello.role == localRole.peer else { throw IrohaPeerNearbyErrorV1.invalidRole }
        guard hello.sessionID == sessionID else { throw IrohaPeerNearbyErrorV1.invalidSession }
        guard hello.requestCanonicalHash == requestCanonicalHash else {
            throw IrohaPeerNearbyErrorV1.invalidRequest
        }
        guard hello.ephemeralPublicKey != localHelloState.ephemeralPublicKey,
              hello.nonce != localHelloState.nonce else {
            throw IrohaPeerNearbyErrorV1.authenticationFailed
        }
        peerHello = hello
    }

    public func authenticationPreimage() throws -> Data {
        stateLock.lock()
        defer { stateLock.unlock() }
        try requireActive()
        let hash = try transcriptHash()
        var preimage = IrohaPeerNearbyV1.authenticationDomain
        preimage.append(localRole.rawValue)
        preimage.append(hash)
        return preimage
    }

    public func makeAuthentication(signature: Data) throws -> IrohaPeerNearbyAuthenticationV1 {
        stateLock.lock()
        defer { stateLock.unlock() }
        try requireActive()
        return try IrohaPeerNearbyAuthenticationV1(
            profile: profile,
            role: localRole,
            sessionID: sessionID,
            transcriptHash: transcriptHash(),
            signature: signature
        )
    }

    public func acceptPeerAuthentication(
        _ authentication: IrohaPeerNearbyAuthenticationV1,
        verifier: SignatureVerifier
    ) throws {
        stateLock.lock()
        let verification: VerificationMaterial
        do {
            verification = try prepareVerification(authentication)
        } catch {
            stateLock.unlock()
            throw error
        }
        stateLock.unlock()

        let verified: Bool
        do {
            verified = try verifier(
                verification.role,
                verification.certificate,
                verification.signedBytes,
                verification.signature
            )
        } catch {
            stateLock.lock()
            authenticationInProgress = false
            let wasDestroyed = destroyed
            stateLock.unlock()
            if wasDestroyed {
                throw IrohaPeerNearbyErrorV1.sessionDestroyed
            }
            throw error
        }

        stateLock.lock()
        defer {
            authenticationInProgress = false
            stateLock.unlock()
        }
        try requireActive()
        guard verified else {
            throw IrohaPeerNearbyErrorV1.authenticationFailed
        }
        let peerPublicKey: P256.KeyAgreement.PublicKey
        do {
            peerPublicKey = try P256.KeyAgreement.PublicKey(
                x963Representation: verification.peerPublicKey
            )
        } catch {
            throw IrohaPeerNearbyErrorV1.invalidPublicKey
        }
        guard let ephemeralPrivateKey else {
            throw IrohaPeerNearbyErrorV1.sessionDestroyed
        }
        let (senderToReceiver, receiverToSender) = try Self.deriveDirectionalKeys(
            privateKey: ephemeralPrivateKey,
            peerPublicKey: peerPublicKey,
            transcriptHash: verification.transcriptHash
        )
        self.ephemeralPrivateKey = nil
        if localRole == .sender {
            outboundKey = senderToReceiver
            inboundKey = receiverToSender
        } else {
            outboundKey = receiverToSender
            inboundKey = senderToReceiver
        }
        acceptedTranscriptHash = verification.transcriptHash
        outboundSequence = 0
        inboundSequence = 0
    }

    public func seal(_ message: Data) throws -> IrohaPeerNearbyEncryptedRecordV1 {
        try seal(message, kind: .encryptedMessage)
    }

    /// Seals the receiver's ask as an `encryptedAsk` record, the first record the
    /// receiver sends after authentication, so the payer builds its Offer for
    /// the asked amount. It shares the key, nonce rule and per-direction sequence
    /// of ``seal(_:)``. Only the receiver seals an ask.
    public func sealAsk(_ ask: IrohaPeerAskV1) throws -> IrohaPeerNearbyEncryptedRecordV1 {
        stateLock.lock()
        defer { stateLock.unlock() }
        try requireActive()
        guard localRole == .receiver else { throw IrohaPeerNearbyErrorV1.invalidRole }
        return try seal(ask.encode(), kind: .encryptedAsk)
    }

    /// One sealing path for both kinds; internal so tests can seal hostile asks.
    func seal(
        _ message: Data,
        kind: IrohaPeerNearbyRecordKindV1
    ) throws -> IrohaPeerNearbyEncryptedRecordV1 {
        stateLock.lock()
        defer { stateLock.unlock() }
        try requireActive()
        guard let outboundKey else { throw IrohaPeerNearbyErrorV1.notAuthenticated }
        guard !message.isEmpty, message.count <= IrohaPeerNearbyV1.maximumMessageBytes else {
            throw IrohaPeerNearbyErrorV1.messageTooLarge
        }
        let sequence = outboundSequence
        let placeholder = try IrohaPeerNearbyEncryptedRecordV1(
            profile: profile,
            senderRole: localRole,
            sessionID: sessionID,
            sequence: sequence,
            ciphertextAndTag: Data(repeating: 0, count: message.count + 16),
            kind: kind
        )
        let nonce = try Self.nonce(senderRole: localRole, sequence: sequence)
        let sealed: AES.GCM.SealedBox
        do {
            sealed = try AES.GCM.seal(
                message,
                using: outboundKey,
                nonce: nonce,
                authenticating: placeholder.header()
            )
        } catch {
            throw IrohaPeerNearbyErrorV1.cryptographicFailure
        }
        guard outboundSequence < UInt64.max else {
            throw IrohaPeerNearbyErrorV1.replayOrReordering
        }
        outboundSequence += 1
        return try IrohaPeerNearbyEncryptedRecordV1(
            profile: profile,
            senderRole: localRole,
            sessionID: sessionID,
            sequence: sequence,
            ciphertextAndTag: sealed.ciphertext + sealed.tag,
            kind: kind
        )
    }

    public func open(_ record: IrohaPeerNearbyEncryptedRecordV1) throws -> Data {
        try open(record, kind: .encryptedMessage) { $0 }
    }

    /// Opens the receiver's ask sealed by ``sealAsk(_:)``. Only the sender (the
    /// payer) opens an ask, only from an `encryptedAsk` record of the receiver;
    /// replay, reordering, tampering and routing fail exactly as in ``open(_:)``,
    /// and an authenticated plaintext that is not a valid ask advances nothing.
    ///
    /// - Throws: ``IrohaPeerNearbyErrorV1``, or ``IrohaPeerAskErrorV1`` when the
    ///   authenticated plaintext is not a valid `IAK1` ask.
    public func openAsk(_ record: IrohaPeerNearbyEncryptedRecordV1) throws -> IrohaPeerAskV1 {
        stateLock.lock()
        defer { stateLock.unlock() }
        try requireActive()
        guard localRole == .sender else { throw IrohaPeerNearbyErrorV1.invalidRole }
        return try open(record, kind: .encryptedAsk, decode: IrohaPeerAskV1.decode)
    }

    /// One opening path for both kinds: the record's kind must be `kind`, and
    /// the sequence advances only once `decode` accepted the plaintext.
    private func open<Value>(
        _ record: IrohaPeerNearbyEncryptedRecordV1,
        kind: IrohaPeerNearbyRecordKindV1,
        decode: (Data) throws -> Value
    ) throws -> Value {
        stateLock.lock()
        defer { stateLock.unlock() }
        try requireActive()
        guard let inboundKey else { throw IrohaPeerNearbyErrorV1.notAuthenticated }
        guard record.kind == kind else { throw IrohaPeerNearbyErrorV1.invalidRecordKind }
        guard record.profile == profile else { throw IrohaPeerNearbyErrorV1.invalidProfile }
        guard record.senderRole == localRole.peer else { throw IrohaPeerNearbyErrorV1.invalidRole }
        guard record.sessionID == sessionID else { throw IrohaPeerNearbyErrorV1.invalidSession }
        guard record.sequence == inboundSequence else {
            throw IrohaPeerNearbyErrorV1.replayOrReordering
        }
        let tagStart = record.ciphertextAndTag.count - 16
        let nonce = try Self.nonce(senderRole: record.senderRole, sequence: record.sequence)
        let box: AES.GCM.SealedBox
        let decoded: Result<Value, Error>
        do {
            box = try AES.GCM.SealedBox(
                nonce: nonce,
                ciphertext: record.ciphertextAndTag.prefix(tagStart),
                tag: record.ciphertextAndTag.suffix(16)
            )
            let plaintext = try AES.GCM.open(
                box,
                using: inboundKey,
                authenticating: record.header()
            )
            guard inboundSequence < UInt64.max else {
                throw IrohaPeerNearbyErrorV1.replayOrReordering
            }
            decoded = Result { try decode(plaintext) }
        } catch let error as IrohaPeerNearbyErrorV1 {
            throw error
        } catch {
            throw IrohaPeerNearbyErrorV1.authenticationFailed
        }
        let value = try decoded.get()
        inboundSequence += 1
        return value
    }

    /// Captures verifier input and marks authentication in flight. The caller
    /// holds `stateLock` and releases it before invoking external verifier code.
    private func prepareVerification(
        _ authentication: IrohaPeerNearbyAuthenticationV1
    ) throws -> VerificationMaterial {
        try requireActive()
        guard !authenticationInProgress,
              outboundKey == nil,
              inboundKey == nil,
              acceptedTranscriptHash == nil else {
            throw IrohaPeerNearbyErrorV1.replayOrReordering
        }
        guard let peerHello else { throw IrohaPeerNearbyErrorV1.verificationRequired }
        guard authentication.profile == profile else { throw IrohaPeerNearbyErrorV1.invalidProfile }
        guard authentication.role == localRole.peer else { throw IrohaPeerNearbyErrorV1.invalidRole }
        guard authentication.sessionID == sessionID else { throw IrohaPeerNearbyErrorV1.invalidSession }
        let expectedHash = try transcriptHash()
        guard authentication.transcriptHash == expectedHash else {
            throw IrohaPeerNearbyErrorV1.transcriptMismatch
        }
        var signedBytes = IrohaPeerNearbyV1.authenticationDomain
        signedBytes.append(authentication.role.rawValue)
        signedBytes.append(expectedHash)
        let verification = VerificationMaterial(
            role: authentication.role,
            certificate: peerHello.deviceCertificate,
            signedBytes: signedBytes,
            signature: authentication.signature,
            peerPublicKey: peerHello.ephemeralPublicKey,
            transcriptHash: expectedHash
        )
        authenticationInProgress = true
        return verification
    }

    private func transcriptHash() throws -> Data {
        try requireActive()
        guard let peerHello else { throw IrohaPeerNearbyErrorV1.verificationRequired }
        guard let localHelloState else {
            throw IrohaPeerNearbyErrorV1.sessionDestroyed
        }
        let senderHello = localRole == .sender ? localHelloState : peerHello
        let receiverHello = localRole == .receiver ? localHelloState : peerHello
        var transcript = IrohaPeerNearbyV1.transcriptDomain
        let service = Data(IrohaPeerNearbyV1.serviceID.utf8)
        transcript.appendUInt16BE(UInt16(service.count))
        transcript.append(service)
        transcript.append(IrohaPeerNearbyV1.wireVersion)
        transcript.appendUInt16BE(profile.rawValue)
        transcript.append(sessionID)
        transcript.append(requestCanonicalHash)
        let senderBytes = senderHello.encode()
        let receiverBytes = receiverHello.encode()
        transcript.appendUInt32BE(UInt32(senderBytes.count))
        transcript.append(senderBytes)
        transcript.appendUInt32BE(UInt32(receiverBytes.count))
        transcript.append(receiverBytes)
        return Data(SHA256.hash(data: transcript))
    }

    private func requireActive() throws {
        guard !destroyed else {
            throw IrohaPeerNearbyErrorV1.sessionDestroyed
        }
    }

    private static func deriveDirectionalKeys(
        privateKey: P256.KeyAgreement.PrivateKey,
        peerPublicKey: P256.KeyAgreement.PublicKey,
        transcriptHash: Data
    ) throws -> (SymmetricKey, SymmetricKey) {
        let secret: SharedSecret
        do {
            secret = try privateKey.sharedSecretFromKeyAgreement(with: peerPublicKey)
        } catch {
            throw IrohaPeerNearbyErrorV1.cryptographicFailure
        }
        return (
            deriveKey(
                secret: secret,
                transcriptHash: transcriptHash,
                direction: Data("sender-to-receiver".utf8)
            ),
            deriveKey(
                secret: secret,
                transcriptHash: transcriptHash,
                direction: Data("receiver-to-sender".utf8)
            )
        )
    }

    private static func deriveKey(
        secret: SharedSecret,
        transcriptHash: Data,
        direction: Data
    ) -> SymmetricKey {
        var info = IrohaPeerNearbyV1.keyDomain
        info.append(direction)
        return secret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: transcriptHash,
            sharedInfo: info,
            outputByteCount: 32
        )
    }

    private static func nonce(
        senderRole: IrohaPeerNearbyRoleV1,
        sequence: UInt64
    ) throws -> AES.GCM.Nonce {
        var data = senderRole == .sender
            ? Data([0x53, 0x32, 0x52, 0x00])
            : Data([0x52, 0x32, 0x53, 0x00])
        data.appendUInt64BE(sequence)
        do {
            return try AES.GCM.Nonce(data: data)
        } catch {
            throw IrohaPeerNearbyErrorV1.cryptographicFailure
        }
    }

    private static func randomBytes(count: Int) -> Data {
        var generator = SystemRandomNumberGenerator()
        return Data((0..<count).map { _ in UInt8.random(in: .min ... .max, using: &generator) })
    }
}

private extension Data {
    mutating func appendUInt16BE(_ value: UInt16) {
        append(UInt8((value >> 8) & 0xff))
        append(UInt8(value & 0xff))
    }

    mutating func appendUInt32BE(_ value: UInt32) {
        append(UInt8((value >> 24) & 0xff))
        append(UInt8((value >> 16) & 0xff))
        append(UInt8((value >> 8) & 0xff))
        append(UInt8(value & 0xff))
    }

    mutating func appendUInt64BE(_ value: UInt64) {
        appendUInt32BE(UInt32((value >> 32) & 0xffff_ffff))
        appendUInt32BE(UInt32(value & 0xffff_ffff))
    }
}

private func readUInt16BE(_ bytes: [UInt8], at offset: Int) -> UInt16 {
    (UInt16(bytes[offset]) << 8) | UInt16(bytes[offset + 1])
}

private func readUInt32BE(_ bytes: [UInt8], at offset: Int) -> UInt32 {
    (UInt32(bytes[offset]) << 24)
        | (UInt32(bytes[offset + 1]) << 16)
        | (UInt32(bytes[offset + 2]) << 8)
        | UInt32(bytes[offset + 3])
}

private func readUInt64BE(_ bytes: [UInt8], at offset: Int) -> UInt64 {
    (UInt64(readUInt32BE(bytes, at: offset)) << 32)
        | UInt64(readUInt32BE(bytes, at: offset + 4))
}
