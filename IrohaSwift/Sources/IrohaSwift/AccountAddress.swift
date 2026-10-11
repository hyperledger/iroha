import Foundation

public enum AccountAddressError: Error, Equatable {
    case unsupportedAlgorithm(String)
    case keyPayloadTooLong(Int)
    case invalidHeaderVersion(UInt8)
    case invalidNormVersion(UInt8)
    case invalidI105Prefix(UInt16)
    case invalidI105Encoding
    case invalidLength
    case checksumMismatch
    case unexpectedNetworkPrefix(expected: UInt16, found: UInt16)
    case unknownAddressClass(UInt8)
    case unexpectedExtensionFlag
    case unknownControllerTag(UInt8)
    case invalidPublicKey
    case unknownCurve(UInt8)
    case unexpectedTrailingBytes
    case invalidI105PrefixEncoding(UInt8)
    case missingI105Sentinel
    case invalidI105Base
    case invalidI105Digit(Int)
    case i105TooShort
    case invalidI105Char(Character)
    case unsupportedAddressFormat
    case multisigMemberOverflow(Int)
    case invalidMultisigPolicy(String)
    /// Complete account admission requires the ABI-29 Rust address codec.
    case nativeBridgeUnavailable

    /// Stable Norito error code (`ERR_*`) that mirrors the Rust data model.
    public var code: String {
        switch self {
        case .unsupportedAlgorithm:
            return "ERR_UNSUPPORTED_ALGORITHM"
        case .keyPayloadTooLong:
            return "ERR_KEY_PAYLOAD_TOO_LONG"
        case .invalidHeaderVersion:
            return "ERR_INVALID_HEADER_VERSION"
        case .invalidNormVersion:
            return "ERR_INVALID_NORM_VERSION"
        case .invalidI105Prefix:
            return "ERR_INVALID_I105_PREFIX"
        case .invalidI105Encoding:
            return "ERR_INVALID_I105_ENCODING"
        case .invalidLength:
            return "ERR_INVALID_LENGTH"
        case .checksumMismatch:
            return "ERR_CHECKSUM_MISMATCH"
        case .unexpectedNetworkPrefix:
            return "ERR_UNEXPECTED_NETWORK_PREFIX"
        case .unknownAddressClass:
            return "ERR_UNKNOWN_ADDRESS_CLASS"
        case .unexpectedExtensionFlag:
            return "ERR_UNEXPECTED_EXTENSION_FLAG"
        case .unknownControllerTag:
            return "ERR_UNKNOWN_CONTROLLER_TAG"
        case .invalidPublicKey:
            return "ERR_INVALID_PUBLIC_KEY"
        case .unknownCurve:
            return "ERR_UNKNOWN_CURVE"
        case .unexpectedTrailingBytes:
            return "ERR_UNEXPECTED_TRAILING_BYTES"
        case .invalidI105PrefixEncoding:
            return "ERR_INVALID_I105_PREFIX_ENCODING"
        case .missingI105Sentinel:
            return "ERR_MISSING_I105_SENTINEL"
        case .invalidI105Base:
            return "ERR_INVALID_I105_BASE"
        case .invalidI105Digit:
            return "ERR_INVALID_I105_DIGIT"
        case .i105TooShort:
            return "ERR_I105_TOO_SHORT"
        case .invalidI105Char:
            return "ERR_INVALID_I105_CHAR"
        case .unsupportedAddressFormat:
            return "ERR_UNSUPPORTED_ADDRESS_FORMAT"
        case .multisigMemberOverflow:
            return "ERR_MULTISIG_MEMBER_OVERFLOW"
        case .invalidMultisigPolicy:
            return "ERR_INVALID_MULTISIG_POLICY"
        case .nativeBridgeUnavailable:
            return "ERR_NATIVE_BRIDGE_UNAVAILABLE"
        }
    }
}

/// Structured representation of i105 outputs used by wallet/explorer UX.
public struct AccountAddressDisplayFormats: Equatable {
    public let i105: String
    public let networkPrefix: UInt16
    public let i105Warning: String
}

public struct AccountAddressNetworkPrefix: Equatable {
    public let sentinel: String
    public let chainDiscriminant: UInt16
    public let profileName: String?
}

public struct AccountAddress {
    private let header: AddressHeader
    private let controller: ControllerPayload
    private let rawCanonicalBytes: Data?

    struct ControllerInfo {
        let algorithm: SigningAlgorithm
        let publicKey: Data
    }

    public struct MultisigPolicyInfo {
        public struct Member {
            public let algorithm: String
            public let weight: UInt16
            public let publicKeyHex: String
        }

        public let version: UInt8
        public let threshold: UInt16
        public let totalWeight: UInt32
        public let members: [Member]
        public let ctap2CborHex: String
        public let digestBlake2b256Hex: String
    }

    public static func fromAccount(publicKey: Data, algorithm: String = "ed25519", distid: String? = nil) throws -> AccountAddress {
        let header = try AddressHeader.new(version: 0, classId: .singleKey, normVersion: 1)
        let controller = try ControllerPayload.singleKey(publicKey: publicKey, algorithm: algorithm, distid: distid)
        var canonical = Data([header.encode()])
        try controller.encode(into: &canonical)
        return try fromCanonicalBytes(canonical)
    }

    /// Validate the complete controller with the mandatory ABI-29 Rust owner.
    public static func fromCanonicalBytes(_ bytes: Data) throws -> AccountAddress {
        guard !bytes.isEmpty else { throw AccountAddressError.invalidLength }
        guard let _ = try NoritoNativeBridge.shared.renderAccountAddress(
            canonicalBytes: bytes, networkPrefix: AccountId.defaultNetworkPrefix
        ) else { throw AccountAddressError.nativeBridgeUnavailable }
        return try decodeNativeValidatedCanonicalBytes(bytes)
    }

    private static func decodeNativeValidatedCanonicalBytes(_ bytes: Data) throws -> AccountAddress {
        // Public callers may pass a `Data` slice whose indices do not start at zero.
        // Rebase once before the decoder uses wire-format offsets.
        let bytes = Data(bytes)
        guard !bytes.isEmpty else { throw AccountAddressError.invalidLength }
        let header = try AddressHeader.decode(bytes[0])
        let (controller, cursor) = try ControllerPayload.decode(bytes: bytes, cursor: 1)
        guard cursor == bytes.count else { throw AccountAddressError.unexpectedTrailingBytes }
        let canonicalHeader = try AddressHeader.new(
            version: 0,
            classId: controller.addressClass,
            normVersion: 1
        )
        guard header.version == canonicalHeader.version else {
            throw AccountAddressError.invalidHeaderVersion(header.version)
        }
        guard header.normVersion == canonicalHeader.normVersion else {
            throw AccountAddressError.invalidNormVersion(header.normVersion)
        }
        guard header.classId.rawValue == canonicalHeader.classId.rawValue else {
            throw AccountAddressError.unsupportedAddressFormat
        }
        try controller.validatePublicKeys()
        return AccountAddress(
            header: header,
            controller: controller,
            rawCanonicalBytes: bytes
        )
    }

    static func parseCanonicalI105(_ input: String, expectedPrefix: UInt16? = nil) throws -> AccountAddress {
        let trimmed = input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { throw AccountAddressError.invalidLength }
        guard trimmed == input else { throw AccountAddressError.unsupportedAddressFormat }
        if trimmed.lowercased().hasPrefix("0x") {
            throw AccountAddressError.unsupportedAddressFormat
        }
        guard let parsed = try NoritoNativeBridge.shared.parseAccountAddress(
            literal: trimmed, expectedPrefix: expectedPrefix
        ) else { throw AccountAddressError.nativeBridgeUnavailable }
        let address = try decodeNativeValidatedCanonicalBytes(parsed.canonicalBytes)
        try ensureCanonicalI105Literal(trimmed, address: address)
        return address
    }

    public static func fromI105(_ encoded: String, expectedPrefix: UInt16? = nil) throws -> AccountAddress {
        return try parseCanonicalI105(encoded, expectedPrefix: expectedPrefix)
    }

    public static func inspectI105NetworkPrefix(_ encoded: String,
                                                expectedPrefix: UInt16? = nil) throws -> AccountAddressNetworkPrefix {
        let trimmed = encoded.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { throw AccountAddressError.invalidLength }
        guard trimmed == encoded else { throw AccountAddressError.unsupportedAddressFormat }
        let (discriminant, _) = try decodeI105String(trimmed, expectedDiscriminant: expectedPrefix)
        return AccountAddressNetworkPrefix(
            sentinel: try i105SentinelLiteral(from: trimmed),
            chainDiscriminant: discriminant,
            profileName: i105ProfileName(for: discriminant)
        )
    }

    public static func parseEncoded(_ input: String, expectedPrefix: UInt16? = nil) throws -> AccountAddress {
        let trimmed = input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { throw AccountAddressError.invalidLength }
        guard trimmed == input else { throw AccountAddressError.unsupportedAddressFormat }
        if trimmed.lowercased().hasPrefix("0x") {
            throw AccountAddressError.unsupportedAddressFormat
        }
        do {
            return try AccountAddress.fromI105(trimmed, expectedPrefix: expectedPrefix)
        } catch AccountAddressError.missingI105Sentinel {
            throw AccountAddressError.unsupportedAddressFormat
        } catch {
            throw error
        }
    }

    public func canonicalBytes() throws -> Data {
        if let rawCanonicalBytes {
            return rawCanonicalBytes
        }
        var bytes = Data()
        bytes.append(header.encode())
        try controller.encode(into: &bytes)
        return bytes
    }

    public func canonicalHex() throws -> String {
        let canonical = try canonicalBytes()
        return "0x" + canonical.map { String(format: "%02x", $0) }.joined()
    }

    public func toI105(networkPrefix: UInt16) throws -> String {
        let canonical = try canonicalBytes()
        return try encodeI105String(discriminant: networkPrefix, canonical: canonical)
    }

    public func toI105(chainDiscriminant: UInt16) throws -> String {
        try toI105(networkPrefix: chainDiscriminant)
    }

    /// Returns canonical I105 output plus the UX warning required by
    /// `specs/sns/address_display_guidelines.md`.
    public func displayFormats(networkPrefix: UInt16 = 753) throws -> AccountAddressDisplayFormats {
        let canonical = try canonicalBytes()
        return AccountAddressDisplayFormats(
            i105: try encodeI105String(discriminant: networkPrefix, canonical: canonical),
            networkPrefix: networkPrefix,
            i105Warning: AccountAddress.i105WarningMessage
        )
    }

    public func multisigPolicyInfo() throws -> MultisigPolicyInfo? {
        guard case let .multiSig(version, threshold, members) = controller else {
            return nil
        }
        let ctap2 = encodeMultisigPolicyCTAP2(version: version, threshold: threshold, members: members)
        let digest = blake2bMac256(ctap2, personal: AccountAddress.multisigPersonalisation)
        let infoMembers = members.map { member -> MultisigPolicyInfo.Member in
            MultisigPolicyInfo.Member(
                algorithm: member.curve.algorithmIdentifier,
                weight: member.weight,
                publicKeyHex: "0x\(member.publicKey.hexUppercased())"
            )
        }
        let totalWeight = members.reduce(UInt32(0)) { partial, member in
            partial &+ UInt32(member.weight)
        }
        return MultisigPolicyInfo(
            version: version,
            threshold: threshold,
            totalWeight: totalWeight,
            members: infoMembers,
            ctap2CborHex: "0x\(ctap2.hexUppercased())",
            digestBlake2b256Hex: "0x\(digest.hexUppercased())"
        )
    }

    func singleControllerInfo() -> ControllerInfo? {
        switch controller {
        case .singleKey(let curve, let publicKey):
            guard let algorithm = curve.signingAlgorithm else { return nil }
            return ControllerInfo(algorithm: algorithm, publicKey: publicKey)
        case .multiSig:
            return nil
        }
    }

    static let multisigPersonalisation = Data("iroha-ms-policy".utf8)
    private static let i105WarningMessage =
        "i105 addresses use the canonical I105 alphabet: Base58 plus the 47 half-width katakana from the Iroha poem. " +
        "Render and validate them with the intended chain discriminant."
}

// MARK: - Internal components

private struct AddressHeader {
    let version: UInt8
    let classId: AddressClass
    let normVersion: UInt8
    let extFlag: Bool

    static func new(version: UInt8, classId: AddressClass, normVersion: UInt8) throws -> AddressHeader {
        guard version <= 0b111 else { throw AccountAddressError.invalidHeaderVersion(version) }
        guard normVersion <= 0b11 else { throw AccountAddressError.invalidNormVersion(normVersion) }
        return AddressHeader(version: version, classId: classId, normVersion: normVersion, extFlag: false)
    }

    func encode() -> UInt8 {
        var byte: UInt8 = (version & 0b111) << 5
        byte |= (classId.rawValue & 0b11) << 3
        byte |= (normVersion & 0b11) << 1
        byte |= extFlag ? 1 : 0
        return byte
    }

    static func decode(_ byte: UInt8) throws -> AddressHeader {
        let version = (byte >> 5) & 0b111
        let classBits = (byte >> 3) & 0b11
        let normVersion = (byte >> 1) & 0b11
        let extFlag = (byte & 1) == 1
        if extFlag {
            throw AccountAddressError.unexpectedExtensionFlag
        }
        guard let classId = AddressClass(rawValue: classBits) else {
            throw AccountAddressError.unknownAddressClass(classBits)
        }
        return try AddressHeader.new(version: version, classId: classId, normVersion: normVersion)
    }
}

private extension CurveId {
    var algorithmIdentifier: String {
        switch self {
        case .ed25519:
            return "ed25519"
        #if IROHASWIFT_ENABLE_SECP256K1
        case .secp256k1:
            return "secp256k1"
        #endif
        #if IROHASWIFT_ENABLE_MLDSA
        case .mldsa:
            return "ml-dsa"
        #endif
        #if IROHASWIFT_ENABLE_BLS
        case .blsNormal:
            return "bls_normal"
        case .blsSmall:
            return "bls_small"
        #endif
        #if IROHASWIFT_ENABLE_GOST
        case .gost256A:
            return "gost3410-2012-256-paramset-a"
        case .gost256B:
            return "gost3410-2012-256-paramset-b"
        case .gost256C:
            return "gost3410-2012-256-paramset-c"
        case .gost512A:
            return "gost3410-2012-512-paramset-a"
        case .gost512B:
            return "gost3410-2012-512-paramset-b"
        #endif
        #if IROHASWIFT_ENABLE_SM
        case .sm2:
            return "sm2"
        #endif
        }
    }

    var signingAlgorithm: SigningAlgorithm? {
        switch self {
        case .ed25519:
            return .ed25519
        #if IROHASWIFT_ENABLE_SECP256K1
        case .secp256k1:
            return .secp256k1
        #endif
        #if IROHASWIFT_ENABLE_MLDSA
        case .mldsa:
            return .mlDsa
        #endif
        #if IROHASWIFT_ENABLE_BLS
        case .blsNormal:
            return .blsNormal
        case .blsSmall:
            return .blsSmall
        #endif
        #if IROHASWIFT_ENABLE_GOST
        case .gost256A:
            return .gost2012_256A
        case .gost256B:
            return .gost2012_256B
        case .gost256C:
            return .gost2012_256C
        case .gost512A:
            return .gost2012_512A
        case .gost512B:
            return .gost2012_512B
        #endif
        #if IROHASWIFT_ENABLE_SM
        case .sm2:
            return .sm2
        #endif
        }
    }
}

private enum AddressClass: UInt8 {
    case singleKey = 0
    case multiSig = 1
}

private enum ControllerPayload {
    case singleKey(curve: CurveId, publicKey: Data)
    case multiSig(version: UInt8, threshold: UInt16, members: [MultisigMember])

    var addressClass: AddressClass {
        switch self {
        case .singleKey:
            return .singleKey
        case .multiSig:
            return .multiSig
        }
    }

    struct MultisigMember {
        let curve: CurveId
        let weight: UInt16
        let publicKey: Data
    }

    static func singleKey(publicKey: Data, algorithm: String, distid: String? = nil) throws -> ControllerPayload {
        let curve = try CurveId.from(algorithm: algorithm)
        guard !publicKey.isEmpty else {
            throw AccountAddressError.invalidPublicKey
        }
        let payload = try canonicalPublicKeyPayload(publicKey: publicKey, curve: curve, distid: distid)
        return .singleKey(curve: curve, publicKey: payload)
    }

    private static func canonicalPublicKeyPayload(publicKey: Data, curve: CurveId, distid: String?) throws -> Data {
        #if IROHASWIFT_ENABLE_SM
        if curve == .sm2 {
            guard publicKey.count == Sm2Keypair.publicKeyLength else {
                throw AccountAddressError.invalidPublicKey
            }
            let resolvedDistid = distid ?? Sm2Keypair.defaultDistid()
            guard let distidBytes = resolvedDistid.data(using: .utf8),
                  distidBytes.count <= Int(UInt16.max) else {
                throw AccountAddressError.invalidPublicKey
            }
            var payload = Data()
            var length = UInt16(distidBytes.count).bigEndian
            withUnsafeBytes(of: &length) { payload.append(contentsOf: $0) }
            payload.append(distidBytes)
            payload.append(publicKey)
            try validatePublicKey(curve: curve, publicKey: payload)
            return payload
        }
        #endif
        if let expected = curve.expectedPublicKeyLength, publicKey.count != expected {
            throw AccountAddressError.invalidPublicKey
        }
        try validatePublicKey(curve: curve, publicKey: publicKey)
        return publicKey
    }

    static func validatePublicKey(curve: CurveId, publicKey: Data) throws {
        do {
            try AccountAddress.validateCompactNoritoPublicKey(curve: curve, publicKey: publicKey)
        } catch {
            throw AccountAddressError.invalidPublicKey
        }
    }

    func validatePublicKeys() throws {
        switch self {
        case let .singleKey(curve, publicKey):
            try Self.validatePublicKey(curve: curve, publicKey: publicKey)
        case let .multiSig(_, _, members):
            for member in members {
                try Self.validatePublicKey(curve: member.curve, publicKey: member.publicKey)
            }
        }
    }

    func encode(into buffer: inout Data) throws {
        switch self {
        case .singleKey(let curve, let key):
            guard key.count <= Int(UInt16.max) else {
                throw AccountAddressError.keyPayloadTooLong(key.count)
            }
            if key.count <= Int(UInt8.max) {
                buffer.append(ControllerPayloadTag.singleKey.rawValue)
                buffer.append(curve.rawValue)
                buffer.append(UInt8(key.count))
            } else {
                buffer.append(ControllerPayloadTag.singleKeyExtended.rawValue)
                buffer.append(curve.rawValue)
                var lengthBE = UInt16(key.count).bigEndian
                withUnsafeBytes(of: &lengthBE) { buffer.append(contentsOf: $0) }
            }
            buffer.append(key)
        case .multiSig(let version, let threshold, let members):
            guard !members.isEmpty else {
                throw AccountAddressError.invalidMultisigPolicy("InvalidMemberCount")
            }
            guard members.count <= multisigMemberMax,
                  let memberCount = UInt16(exactly: members.count) else {
                throw AccountAddressError.multisigMemberOverflow(members.count)
            }
            buffer.append(ControllerPayloadTag.multiSig.rawValue)
            buffer.append(version)
            var thresholdBE = threshold.bigEndian
            withUnsafeBytes(of: &thresholdBE) { buffer.append(contentsOf: $0) }
            // Final V1 addresses always carry the complete u16 big-endian count.
            var memberCountBE = memberCount.bigEndian
            withUnsafeBytes(of: &memberCountBE) { buffer.append(contentsOf: $0) }
            for member in members {
                buffer.append(member.curve.rawValue)
                var weightBE = member.weight.bigEndian
                withUnsafeBytes(of: &weightBE) { buffer.append(contentsOf: $0) }
                guard member.publicKey.count <= 0xFFFF else {
                    throw AccountAddressError.keyPayloadTooLong(member.publicKey.count)
                }
                var lengthBE = UInt16(member.publicKey.count).bigEndian
                withUnsafeBytes(of: &lengthBE) { buffer.append(contentsOf: $0) }
                buffer.append(member.publicKey)
            }
        }
    }

    static func decode(bytes: Data, cursor: Int) throws -> (ControllerPayload, Int) {
        guard cursor < bytes.count else { throw AccountAddressError.invalidLength }
        let tagValue = bytes[cursor]
        guard let tag = ControllerPayloadTag(rawValue: tagValue) else {
            throw AccountAddressError.unknownControllerTag(tagValue)
        }
        var cursor = cursor + 1
        switch tag {
        case .singleKey:
            guard cursor < bytes.count else { throw AccountAddressError.invalidLength }
            let curveRaw = bytes[cursor]
            cursor += 1
            let curve = try CurveId.decode(rawValue: curveRaw)
            guard cursor < bytes.count else { throw AccountAddressError.invalidLength }
            let length = Int(bytes[cursor])
            cursor += 1
            let end = cursor + length
            guard end <= bytes.count else { throw AccountAddressError.invalidLength }
            let key = bytes[cursor..<end]
            return (.singleKey(curve: curve, publicKey: Data(key)), end)
        case .singleKeyExtended:
            guard cursor < bytes.count else { throw AccountAddressError.invalidLength }
            let curveRaw = bytes[cursor]
            cursor += 1
            let curve = try CurveId.decode(rawValue: curveRaw)
            guard cursor + 1 < bytes.count else { throw AccountAddressError.invalidLength }
            let length = Int((UInt16(bytes[cursor]) << 8) | UInt16(bytes[cursor + 1]))
            cursor += 2
            guard length > Int(UInt8.max) else {
                throw AccountAddressError.invalidLength
            }
            let end = cursor + length
            guard end <= bytes.count else { throw AccountAddressError.invalidLength }
            let key = bytes[cursor..<end]
            return (.singleKey(curve: curve, publicKey: Data(key)), end)
        case .multiSig:
            guard cursor < bytes.count else { throw AccountAddressError.invalidLength }
            let version = bytes[cursor]
            cursor += 1
            guard cursor + 1 < bytes.count else { throw AccountAddressError.invalidLength }
            let threshold = (UInt16(bytes[cursor]) << 8) | UInt16(bytes[cursor + 1])
            cursor += 2
            guard threshold > 0 else {
                throw AccountAddressError.invalidMultisigPolicy("ZeroThreshold")
            }
            if let decoded = try decodeMultisigMembers(
                bytes: bytes, cursor: cursor, version: version, threshold: threshold
            ) { return decoded }
            throw AccountAddressError.invalidLength
        }
    }

    private enum ControllerPayloadTag: UInt8 {
        case singleKey = 0x00
        case multiSig = 0x01
        case singleKeyExtended = 0x02
    }

    private static func decodeMultisigMembers(
        bytes: Data,
        cursor: Int,
        version: UInt8,
        threshold: UInt16
    ) throws -> (ControllerPayload, Int)? {
        var cursor = cursor
        guard version == 1 else { throw AccountAddressError.invalidMultisigPolicy("InvalidVersion") }
        guard cursor + 1 < bytes.count else { return nil }
        let memberCount = Int((UInt16(bytes[cursor]) << 8) | UInt16(bytes[cursor + 1]))
        cursor += 2
        guard memberCount > 0, memberCount <= multisigMemberMax else {
            throw AccountAddressError.invalidMultisigPolicy("InvalidMemberCount")
        }
        guard memberCount <= (bytes.count - cursor) / 6 else { return nil }
        var previousSortKey: Data?
        var totalWeight: UInt64 = 0
        var members: [MultisigMember] = []
        members.reserveCapacity(memberCount)
        for _ in 0..<memberCount {
            guard cursor < bytes.count else {
                return nil
            }
            let curveRaw = bytes[cursor]
            cursor += 1
            let curve = try CurveId.decode(rawValue: curveRaw)
            guard cursor + 1 < bytes.count else {
                return nil
            }
            let weight = (UInt16(bytes[cursor]) << 8) | UInt16(bytes[cursor + 1])
            cursor += 2
            guard cursor + 1 < bytes.count else {
                return nil
            }
            let keyLength = Int((UInt16(bytes[cursor]) << 8) | UInt16(bytes[cursor + 1]))
            cursor += 2
            let end = cursor + keyLength
            guard end <= bytes.count else {
                return nil
            }
            let key = Data(bytes[cursor..<end])
            cursor = end
            guard weight > 0, let algorithm = curve.signingAlgorithm else {
                throw AccountAddressError.invalidMultisigPolicy("InvalidMember")
            }
            var sortKey = Data(algorithm.wireName.utf8)
            sortKey.append(0); sortKey.append(key)
            guard previousSortKey.map({ $0.lexicographicallyPrecedes(sortKey) }) ?? true else {
                throw AccountAddressError.invalidMultisigPolicy("NonCanonicalMembers")
            }
            previousSortKey = sortKey
            totalWeight += UInt64(weight)
            members.append(MultisigMember(curve: curve, weight: weight, publicKey: key))
        }

        guard UInt64(threshold) <= totalWeight else {
            throw AccountAddressError.invalidMultisigPolicy("ThresholdExceedsTotalWeight")
        }
        return (.multiSig(version: version, threshold: threshold, members: members), cursor)
    }
}

private func encodeMultisigPolicyCTAP2(
    version: UInt8,
    threshold: UInt16,
    members: [ControllerPayload.MultisigMember]
) -> Data {
    var buffer = Data()
    cborAppendLength(into: &buffer, major: 0b101, length: 3)
    cborAppendUnsigned(into: &buffer, value: 0x01)
    cborAppendUnsigned(into: &buffer, value: UInt64(version))
    cborAppendUnsigned(into: &buffer, value: 0x02)
    cborAppendUnsigned(into: &buffer, value: UInt64(threshold))
    cborAppendUnsigned(into: &buffer, value: 0x03)
    cborAppendLength(into: &buffer, major: 0b100, length: members.count)
    for member in members {
        cborAppendLength(into: &buffer, major: 0b101, length: 3)
        cborAppendUnsigned(into: &buffer, value: 0x01)
        cborAppendUnsigned(into: &buffer, value: UInt64(member.curve.rawValue))
        cborAppendUnsigned(into: &buffer, value: 0x02)
        cborAppendUnsigned(into: &buffer, value: UInt64(member.weight))
        cborAppendUnsigned(into: &buffer, value: 0x03)
        cborAppendBytes(into: &buffer, bytes: member.publicKey)
    }
    return buffer
}

private func blake2bMac256(_ data: Data, personal: Data) -> Data {
    // Blake2bMac with an empty key still emits a zero-padded key block.
    var prefixed = Data(repeating: 0, count: blake2bBlockLength)
    prefixed.append(data)
    return Blake2b.hash256(prefixed, personal: personal)
}

private func cborAppendUnsigned(into buffer: inout Data, value: UInt64) {
    switch value {
    case 0...23:
        buffer.append(UInt8(value))
    case 24...0xFF:
        buffer.append(0x18)
        buffer.append(UInt8(value))
    case 0x100...0xFFFF:
        buffer.append(0x19)
        var be = UInt16(value).bigEndian
        withUnsafeBytes(of: &be) { buffer.append(contentsOf: $0) }
    case 0x1_0000...0xFFFF_FFFF:
        buffer.append(0x1A)
        var be = UInt32(value).bigEndian
        withUnsafeBytes(of: &be) { buffer.append(contentsOf: $0) }
    default:
        buffer.append(0x1B)
        var be = value.bigEndian
        withUnsafeBytes(of: &be) { buffer.append(contentsOf: $0) }
    }
}

private func cborAppendLength(into buffer: inout Data, major: UInt8, length: Int) {
    precondition(major <= 0b111)
    let base = major << 5
    let value = UInt64(length)
    switch value {
    case 0...23:
        buffer.append(base | UInt8(value))
    case 24...0xFF:
        buffer.append(base | 24)
        buffer.append(UInt8(value))
    case 0x100...0xFFFF:
        buffer.append(base | 25)
        var be = UInt16(value).bigEndian
        withUnsafeBytes(of: &be) { buffer.append(contentsOf: $0) }
    case 0x1_0000...0xFFFF_FFFF:
        buffer.append(base | 26)
        var be = UInt32(value).bigEndian
        withUnsafeBytes(of: &be) { buffer.append(contentsOf: $0) }
    default:
        buffer.append(base | 27)
        var be = value.bigEndian
        withUnsafeBytes(of: &be) { buffer.append(contentsOf: $0) }
    }
}

private func cborAppendBytes(into buffer: inout Data, bytes: Data) {
    cborAppendLength(into: &buffer, major: 0b010, length: bytes.count)
    buffer.append(bytes)
}

/// Supported curve identifiers mirroring the registry in `specs/account_structure.md`.
/// Additional cases compile only when the corresponding feature flag is enabled so preview
/// curves fail closed by default.
private enum CurveId: UInt8 {
    case ed25519 = 1
    #if IROHASWIFT_ENABLE_SECP256K1
    case secp256k1 = 4
    #endif
    #if IROHASWIFT_ENABLE_MLDSA
    case mldsa = 2
    #endif
    #if IROHASWIFT_ENABLE_BLS
    case blsNormal = 3
    case blsSmall = 5
    #endif
    #if IROHASWIFT_ENABLE_GOST
    case gost256A = 10
    case gost256B = 11
    case gost256C = 12
    case gost512A = 13
    case gost512B = 14
    #endif
    #if IROHASWIFT_ENABLE_SM
    case sm2 = 15
    #endif

    static func decode(rawValue: UInt8) throws -> CurveId {
        switch rawValue {
        case CurveId.ed25519.rawValue:
            return .ed25519
        #if IROHASWIFT_ENABLE_SECP256K1
        case CurveId.secp256k1.rawValue:
            return .secp256k1
        #endif
        #if IROHASWIFT_ENABLE_MLDSA
        case CurveId.mldsa.rawValue:
            return .mldsa
        #endif
        #if IROHASWIFT_ENABLE_BLS
        case CurveId.blsNormal.rawValue:
            return .blsNormal
        case CurveId.blsSmall.rawValue:
            return .blsSmall
        #endif
        #if IROHASWIFT_ENABLE_GOST
        case CurveId.gost256A.rawValue:
            return .gost256A
        case CurveId.gost256B.rawValue:
            return .gost256B
        case CurveId.gost256C.rawValue:
            return .gost256C
        case CurveId.gost512A.rawValue:
            return .gost512A
        case CurveId.gost512B.rawValue:
            return .gost512B
        #endif
        #if IROHASWIFT_ENABLE_SM
        case CurveId.sm2.rawValue:
            return .sm2
        #endif
        default:
            throw AccountAddressError.unknownCurve(rawValue)
        }
    }

    static func from(algorithm: String) throws -> CurveId {
        guard !algorithm.isEmpty, algorithm.utf8.allSatisfy({ byte in
            (byte >= 0x30 && byte <= 0x39)
                || (byte >= 0x41 && byte <= 0x5A)
                || (byte >= 0x61 && byte <= 0x7A)
                || byte == 0x2D
                || byte == 0x5F
        }) else {
            throw AccountAddressError.unsupportedAlgorithm(algorithm)
        }
        let normalized = algorithm.lowercased()
        switch normalized {
        case "ed25519", "ed":
            return .ed25519
        #if IROHASWIFT_ENABLE_SECP256K1
        case "secp256k1", "secp":
            return .secp256k1
        #endif
        #if IROHASWIFT_ENABLE_MLDSA
        case "ml-dsa", "mldsa", "ml_dsa",
             "mldsa65", "ml-dsa-65", "ml_dsa_65", "ml_dsa-65":
            return .mldsa
        #endif
        #if IROHASWIFT_ENABLE_BLS
        case "bls_normal", "bls-normal", "blsnormal", "bls12-381-g1":
            return .blsNormal
        case "bls_small", "bls-small", "blssmall", "bls12-381-g2":
            return .blsSmall
        #endif
        #if IROHASWIFT_ENABLE_GOST
        case "gost256a", "gost-256-a", "gost3410-2012-256-paramset-a":
            return .gost256A
        case "gost256b", "gost-256-b", "gost3410-2012-256-paramset-b":
            return .gost256B
        case "gost256c", "gost-256-c", "gost3410-2012-256-paramset-c":
            return .gost256C
        case "gost512a", "gost-512-a", "gost3410-2012-512-paramset-a":
            return .gost512A
        case "gost512b", "gost-512-b", "gost3410-2012-512-paramset-b":
            return .gost512B
        #endif
        #if IROHASWIFT_ENABLE_SM
        case "sm2", "sm-2":
            return .sm2
        #endif
        default:
            throw AccountAddressError.unsupportedAlgorithm(algorithm)
        }
    }

    var expectedPublicKeyLength: Int? {
        switch self {
        case .ed25519:
            return 32
        #if IROHASWIFT_ENABLE_SECP256K1
        case .secp256k1:
            return 33
        #endif
        #if IROHASWIFT_ENABLE_MLDSA
        case .mldsa:
            return 1_952
        #endif
        #if IROHASWIFT_ENABLE_BLS
        case .blsNormal:
            return 48
        case .blsSmall:
            return 96
        #endif
        #if IROHASWIFT_ENABLE_GOST
        case .gost256A, .gost256B, .gost256C:
            return 64
        case .gost512A, .gost512B:
            return 128
        #endif
        #if IROHASWIFT_ENABLE_SM
        case .sm2:
            return 65
        #endif
        default:
            return nil
        }
    }
}

// MARK: - Encoding helpers

private let base58Alphabet = Array("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz").map(String.init)
private let irohaPoemKanaHalfwidth: [String] = [
    "ｲ", "ﾛ", "ﾊ", "ﾆ", "ﾎ", "ﾍ", "ﾄ", "ﾁ", "ﾘ", "ﾇ", "ﾙ", "ｦ", "ﾜ", "ｶ", "ﾖ", "ﾀ",
    "ﾚ", "ｿ", "ﾂ", "ﾈ", "ﾅ", "ﾗ", "ﾑ", "ｳ", "ヰ", "ﾉ", "ｵ", "ｸ", "ﾔ", "ﾏ", "ｹ", "ﾌ",
    "ｺ", "ｴ", "ﾃ", "ｱ", "ｻ", "ｷ", "ﾕ", "ﾒ", "ﾐ", "ｼ", "ヱ", "ﾋ", "ﾓ", "ｾ", "ｽ",
]
private let multisigMemberMax = 0xFFFF
private let blake2bBlockLength = 128
private let compressedAlphabet: [String] = base58Alphabet + irohaPoemKanaHalfwidth
private let compressedChecksumLength = 6
private let compressedBase = compressedAlphabet.count
private let i105DiscriminantSora: UInt16 = 0x02F1
private let i105DiscriminantTest: UInt16 = 0x0171
private let i105DiscriminantDev: UInt16 = 0x0000
private let i105SentinelSora = "sora"
private let i105SentinelTest = "test"
private let i105SentinelDev = "dev"
private let i105SentinelNumericPrefix = "n"

private func lookupI105Digit(_ symbol: String) -> Int? {
    if let canonical = compressedAlphabet.firstIndex(of: symbol) {
        return canonical
    }
    return nil
}

private func ensureCanonicalI105Literal(_ literal: String, address: AccountAddress) throws {
    guard let (discriminant, _) = parseI105SentinelAndPayload(literal) else {
        throw AccountAddressError.unsupportedAddressFormat
    }
    let canonical = try address.toI105(networkPrefix: discriminant)
    guard canonical == literal else { throw AccountAddressError.unsupportedAddressFormat }
}

private func decodeI105String(_ encoded: String,
                              expectedDiscriminant: UInt16? = nil) throws -> (UInt16, Data) {
    guard let (discriminant, payload) = parseI105SentinelAndPayload(encoded) else {
        throw AccountAddressError.missingI105Sentinel
    }
    if let expectedDiscriminant, discriminant != expectedDiscriminant {
        throw AccountAddressError.unexpectedNetworkPrefix(expected: expectedDiscriminant,
                                                          found: discriminant)
    }
    return (discriminant, try decodeI105Payload(String(payload)))
}

private func encodeI105String(discriminant: UInt16,
                              canonical: Data,
                              fullWidth: Bool = false) throws -> String {
    let digits = try encodeBaseN(bytes: Array(canonical), base: compressedBase)
    let checksum = compressedChecksumDigits(canonical: canonical)
    let alphabet = compressedAlphabet
    var parts = [i105Sentinel(for: discriminant)]
    parts.append(contentsOf: digits.map { alphabet[$0] })
    parts.append(contentsOf: checksum.map { alphabet[$0] })
    return parts.joined()
}

private func decodeI105Payload(_ payload: String) throws -> Data {
    let digits = try payload.map { symbol -> Int in
        let string = String(symbol)
        guard let value = lookupI105Digit(string) else {
            throw AccountAddressError.invalidI105Char(symbol)
        }
        return value
    }
    guard digits.count > compressedChecksumLength else {
        throw AccountAddressError.i105TooShort
    }
    let dataDigits = Array(digits.dropLast(compressedChecksumLength))
    let checksumDigits = Array(digits.suffix(compressedChecksumLength))
    let canonicalBytes = try decodeBaseN(digits: dataDigits, base: compressedBase)
    let expected = compressedChecksumDigits(canonical: Data(canonicalBytes))
    guard checksumDigits.elementsEqual(expected) else {
        throw AccountAddressError.checksumMismatch
    }
    return Data(canonicalBytes)
}

private func encodeBaseN(bytes: [UInt8], base: Int) throws -> [Int] {
    guard base >= 2 else { throw AccountAddressError.invalidI105Base }
    if bytes.isEmpty { return [0] }
    var value = bytes
    var leadingZeros = 0
    while leadingZeros < value.count && value[leadingZeros] == 0 {
        leadingZeros += 1
    }
    var digits: [Int] = []
    var start = leadingZeros
    while start < value.count {
        var remainder = 0
        for idx in start..<value.count {
            let acc = (remainder << 8) | Int(value[idx])
            value[idx] = UInt8(acc / base)
            remainder = acc % base
        }
        digits.append(remainder)
        while start < value.count && value[start] == 0 {
            start += 1
        }
    }
    digits.append(contentsOf: Array(repeating: 0, count: leadingZeros))
    if digits.isEmpty { digits.append(0) }
    return digits.reversed()
}

private func decodeBaseN(digits: [Int], base: Int) throws -> [UInt8] {
    guard base >= 2 else { throw AccountAddressError.invalidI105Base }
    guard !digits.isEmpty else { throw AccountAddressError.invalidLength }
    for digit in digits where digit < 0 || digit >= base {
        throw AccountAddressError.invalidI105Digit(digit)
    }
    var value = digits
    var leadingZeros = 0
    while leadingZeros < value.count && value[leadingZeros] == 0 {
        leadingZeros += 1
    }
    var bytes: [UInt8] = []
    var start = leadingZeros
    while start < value.count {
        var remainder = 0
        for idx in start..<value.count {
            let acc = remainder * base + value[idx]
            value[idx] = acc / 256
            remainder = acc % 256
        }
        bytes.append(UInt8(remainder))
        while start < value.count && value[start] == 0 {
            start += 1
        }
    }
    bytes.append(contentsOf: Array(repeating: 0, count: leadingZeros))
    if bytes.isEmpty { bytes.append(0) }
    return bytes.reversed()
}

private func i105Sentinel(for discriminant: UInt16) -> String {
    switch discriminant {
    case i105DiscriminantSora:
        return i105SentinelSora
    case i105DiscriminantTest:
        return i105SentinelTest
    case i105DiscriminantDev:
        return i105SentinelDev
    default:
        return "\(i105SentinelNumericPrefix)\(discriminant)"
    }
}

private func i105ProfileName(for discriminant: UInt16) -> String? {
    switch discriminant {
    case i105DiscriminantSora:
        return "minamoto"
    case i105DiscriminantTest:
        return "taira"
    case i105DiscriminantDev:
        return "dev"
    default:
        return nil
    }
}

private func i105SentinelLiteral(from encoded: String) throws -> String {
    if encoded.hasPrefix(i105SentinelSora) {
        return i105SentinelSora
    }
    if encoded.hasPrefix(i105SentinelTest) {
        return i105SentinelTest
    }
    if encoded.hasPrefix(i105SentinelDev) {
        return i105SentinelDev
    }
    guard encoded.hasPrefix(i105SentinelNumericPrefix) else {
        throw AccountAddressError.missingI105Sentinel
    }
    let tail = encoded.dropFirst(i105SentinelNumericPrefix.count)
    var digits = ""
    var index = tail.startIndex
    while index < tail.endIndex, let value = asciiDigit(from: tail[index]) {
        digits.append(value)
        index = tail.index(after: index)
    }
    guard !digits.isEmpty, UInt16(digits) != nil else {
        throw AccountAddressError.missingI105Sentinel
    }
    return "\(i105SentinelNumericPrefix)\(digits)"
}

private func parseI105SentinelAndPayload(_ encoded: String) -> (UInt16, Substring)? {
    if encoded.hasPrefix(i105SentinelSora) {
        return (i105DiscriminantSora, encoded.dropFirst(i105SentinelSora.count))
    }
    if encoded.hasPrefix(i105SentinelTest) {
        return (i105DiscriminantTest, encoded.dropFirst(i105SentinelTest.count))
    }
    if encoded.hasPrefix(i105SentinelDev) {
        return (i105DiscriminantDev, encoded.dropFirst(i105SentinelDev.count))
    }

    let tail: Substring
    if encoded.hasPrefix(i105SentinelNumericPrefix) {
        tail = encoded.dropFirst(i105SentinelNumericPrefix.count)
    } else {
        return nil
    }

    var digits = ""
    var index = tail.startIndex
    while index < tail.endIndex, let value = asciiDigit(from: tail[index]) {
        digits.append(value)
        index = tail.index(after: index)
    }
    guard !digits.isEmpty, let parsed = UInt16(digits) else { return nil }
    return (parsed, tail[index...])
}

private func asciiDigit(from character: Character) -> Character? {
    guard let scalar = character.unicodeScalars.first,
          character.unicodeScalars.count == 1 else {
        return nil
    }
    switch scalar.value {
    case 0x30...0x39:
        return character
    default:
        return nil
    }
}

private func convertToBase32(data: Data) -> [Int] {
    var acc = 0
    var bits = 0
    var out: [Int] = []
    for byte in data {
        acc = (acc << 8) | Int(byte)
        bits += 8
        while bits >= 5 {
            bits -= 5
            out.append((acc >> bits) & 0x1F)
        }
    }
    if bits > 0 {
        out.append((acc << (5 - bits)) & 0x1F)
    }
    return out
}

private func bech32Polymod(values: [Int]) -> UInt32 {
    let generators: [UInt32] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    var chk: UInt32 = 1
    for value in values {
        let top = chk >> 25
        chk = ((chk & 0x1ff_ffff) << 5) ^ UInt32(value)
        for (index, generator) in generators.enumerated() where ((top >> index) & 1) == 1 {
            chk ^= generator
        }
    }
    return chk
}

private func expandHrp(_ hrp: String) -> [Int] {
    var out: [Int] = []
    for character in hrp {
        let code = Int(character.unicodeScalars.first!.value)
        out.append(code >> 5)
    }
    out.append(0)
    for character in hrp {
        let code = Int(character.unicodeScalars.first!.value)
        out.append(code & 0x1F)
    }
    return out
}

private func bech32mChecksum(data: Data) -> [Int] {
    var values = expandHrp("snx")
    values.append(contentsOf: convertToBase32(data: data))
    values.append(contentsOf: Array(repeating: 0, count: compressedChecksumLength))
    let polymod = bech32Polymod(values: values) ^ 0x2bc830a3
    var checksum: [Int] = []
    for i in 0..<compressedChecksumLength {
        let shift = 5 * (compressedChecksumLength - 1 - i)
        checksum.append(Int((polymod >> shift) & 0x1F))
    }
    return checksum
}

private func compressedChecksumDigits(canonical: Data) -> [Int] {
    bech32mChecksum(data: canonical)
}

extension AccountAddressError {
    struct BridgePayload {
        let code: String
        let message: String
        let fields: [String: Any]
    }

    static func bridgePayload(from data: Data) -> BridgePayload? {
        guard
            let raw = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
            let code = raw["code"] as? String
        else {
            return nil
        }
        let message = raw["message"] as? String ?? code
        let fields = raw["fields"] as? [String: Any] ?? [:]
        return BridgePayload(code: code, message: message, fields: fields)
    }

    static func fromBridgePayload(_ payload: BridgePayload) -> AccountAddressError? {
        let fields = payload.fields
        switch payload.code {
        case "ERR_UNSUPPORTED_ALGORITHM":
            if let algorithm = fields["algorithm"] as? String {
                return AccountAddressError.unsupportedAlgorithm(algorithm)
            }
        case "ERR_KEY_PAYLOAD_TOO_LONG":
            if let length = intField("length", fields: fields) {
                return AccountAddressError.keyPayloadTooLong(length)
            }
        case "ERR_INVALID_HEADER_VERSION":
            if let value = uInt8Field("value", fields: fields) {
                return AccountAddressError.invalidHeaderVersion(value)
            }
        case "ERR_INVALID_NORM_VERSION":
            if let value = uInt8Field("value", fields: fields) {
                return AccountAddressError.invalidNormVersion(value)
            }
        case "ERR_INVALID_I105_PREFIX":
            if let prefix = uInt16Field("prefix", fields: fields) {
                return AccountAddressError.invalidI105Prefix(prefix)
            }
        case "ERR_INVALID_I105_ENCODING":
            return AccountAddressError.invalidI105Encoding
        case "ERR_INVALID_LENGTH":
            return AccountAddressError.invalidLength
        case "ERR_CHECKSUM_MISMATCH":
            return AccountAddressError.checksumMismatch
        case "ERR_UNEXPECTED_NETWORK_PREFIX":
            if let expected = uInt16Field("expected", fields: fields),
               let found = uInt16Field("found", fields: fields) {
                return AccountAddressError.unexpectedNetworkPrefix(expected: expected, found: found)
            }
        case "ERR_UNKNOWN_ADDRESS_CLASS":
            if let value = uInt8Field("value", fields: fields) {
                return AccountAddressError.unknownAddressClass(value)
            }
        case "ERR_UNEXPECTED_EXTENSION_FLAG":
            return AccountAddressError.unexpectedExtensionFlag
        case "ERR_UNKNOWN_CONTROLLER_TAG":
            if let value = uInt8Field("value", fields: fields) {
                return AccountAddressError.unknownControllerTag(value)
            }
        case "ERR_INVALID_PUBLIC_KEY":
            return AccountAddressError.invalidPublicKey
        case "ERR_UNKNOWN_CURVE":
            if let value = uInt8Field("value", fields: fields) {
                return AccountAddressError.unknownCurve(value)
            }
        case "ERR_UNEXPECTED_TRAILING_BYTES":
            return AccountAddressError.unexpectedTrailingBytes
        case "ERR_INVALID_I105_PREFIX_ENCODING":
            if let value = uInt8Field("value", fields: fields) {
                return AccountAddressError.invalidI105PrefixEncoding(value)
            }
        case "ERR_MISSING_I105_SENTINEL":
            return AccountAddressError.missingI105Sentinel
        case "ERR_INVALID_I105_BASE":
            return AccountAddressError.invalidI105Base
        case "ERR_INVALID_I105_DIGIT":
            if let digit = intField("digit", fields: fields) {
                return AccountAddressError.invalidI105Digit(digit)
            }
        case "ERR_I105_TOO_SHORT":
            return AccountAddressError.i105TooShort
        case "ERR_INVALID_I105_CHAR":
            if let value = fields["char"] as? String, let character = value.first {
                return AccountAddressError.invalidI105Char(character)
            }
        case "ERR_UNSUPPORTED_ADDRESS_FORMAT":
            return AccountAddressError.unsupportedAddressFormat
        case "ERR_MULTISIG_MEMBER_OVERFLOW":
            if let count = intField("count", fields: fields) {
                return AccountAddressError.multisigMemberOverflow(count)
            }
        case "ERR_INVALID_MULTISIG_POLICY":
            if let detail = fields["policy_error"] as? String {
                return AccountAddressError.invalidMultisigPolicy(detail)
            }
        default:
            return nil
        }
        return nil
    }

    private static func intField(_ name: String, fields: [String: Any]) -> Int? {
        StrictJSONNumber.int(from: fields[name])
    }

    private static func uInt8Field(_ name: String, fields: [String: Any]) -> UInt8? {
        guard let value = intField(name, fields: fields) else { return nil }
        guard value >= 0, value <= Int(UInt8.max) else { return nil }
        return UInt8(value)
    }

    private static func uInt16Field(_ name: String, fields: [String: Any]) -> UInt16? {
        guard let value = intField(name, fields: fields) else { return nil }
        guard value >= 0, value <= Int(UInt16.max) else { return nil }
        return UInt16(value)
    }
}

extension AccountAddress {
    func noritoAccountControllerPayload() throws -> Data {
        var writer = CanonicalNoritoWriter()
        switch controller {
        case .singleKey(let curve, let publicKey):
            let keyPayload = try noritoPublicKeyPayload(curve: curve, publicKey: publicKey)
            writer.writeUInt32LE(0)
            writer.writeLength(UInt64(keyPayload.count))
            writer.writeBytes(keyPayload)
        case .multiSig(let version, let threshold, let members):
            let policyPayload = try noritoMultisigPolicyPayload(version: version,
                                                                threshold: threshold,
                                                                members: members)
            writer.writeUInt32LE(1)
            writer.writeLength(UInt64(policyPayload.count))
            writer.writeBytes(policyPayload)
        }
        return writer.data
    }

    /// Encode this address as the bare compact-Norito `AccountId` controller payload.
    ///
    /// `AccountId` is domainless in the first-release wire model. Exposing the
    /// canonical controller encoder lets downstream SDK consumers embed typed
    /// account identifiers in larger compact-Norito structures without
    /// reimplementing single-key and multisig layouts.
    public func compactNoritoAccountControllerPayload() throws -> Data {
        var writer = CompactNoritoWriter()
        switch controller {
        case .singleKey(let curve, let publicKey):
            let keyPayload = try compactNoritoPublicKeyPayload(curve: curve, publicKey: publicKey)
            writer.writeUInt32LE(0)
            writer.writeField(keyPayload)
        case .multiSig(let version, let threshold, let members):
            let policyPayload = try compactNoritoMultisigPolicyPayload(version: version,
                                                                       threshold: threshold,
                                                                       members: members)
            writer.writeUInt32LE(1)
            writer.writeField(policyPayload)
        }
        return writer.data
    }

    // Full AccountId frame callers still perform framing, checksum and byte-for-byte checks.
    static func fromCanonicalCompactAccountPayload(_ payload: Data) throws -> AccountAddress {
        let (controller, addressClass) = try decodeCompactNoritoAccountControllerPayload(payload)
        let address = AccountAddress(header: try AddressHeader.new(version: 0,
            classId: addressClass, normVersion: 1), controller: controller, rawCanonicalBytes: nil)
        let validated = try fromCanonicalBytes(address.canonicalBytes())
        guard try validated.compactNoritoAccountControllerPayload() == payload else {
            throw AccountAddressError.invalidLength
        }
        return validated
    }

    /// Returns whether `payload` is one exact compact-Norito `AccountId`
    /// controller encoding supported by this SDK build.
    static func isCanonicalCompactNoritoAccountControllerPayload(_ payload: Data) -> Bool {
        do {
            let (controller, addressClass) = try Self.decodeCompactNoritoAccountControllerPayload(
                payload
            )
            let address = AccountAddress(
                header: try AddressHeader.new(
                    version: 0,
                    classId: addressClass,
                    normVersion: 1
                ),
                controller: controller,
                rawCanonicalBytes: nil
            )
            let validated = try fromCanonicalBytes(address.canonicalBytes())
            return try validated.compactNoritoAccountControllerPayload() == payload
        } catch {
            return false
        }
    }

    private static func decodeCompactNoritoAccountControllerPayload(
        _ payload: Data
    ) throws -> (ControllerPayload, AddressClass) {
        var reader = CanonicalNoritoReader(data: payload)
        let discriminant = try reader.readUInt32LE()
        let body = try reader.readCompactField()
        guard reader.remaining() == 0 else {
            throw CanonicalNoritoDecodingError.invalidField(
                "compact AccountId contains trailing bytes"
            )
        }
        switch discriminant {
        case 0:
            let key = try decodeCompactNoritoPublicKeyPayload(body)
            return (
                .singleKey(curve: key.curve, publicKey: key.publicKey),
                .singleKey
            )
        case 1:
            return (
                try decodeCompactNoritoMultisigPolicyPayload(body),
                .multiSig
            )
        default:
            throw CanonicalNoritoDecodingError.invalidField(
                "compact AccountId controller discriminant is unknown"
            )
        }
    }

    private static func decodeCompactNoritoPublicKeyPayload(
        _ payload: Data
    ) throws -> (curve: CurveId, publicKey: Data) {
        var reader = CanonicalNoritoReader(data: payload)
        let count = try reader.readUInt64LE()
        guard count > 1,
              count <= UInt64(UInt16.max) + 1,
              count <= UInt64(reader.remaining() / 2) else {
            throw CanonicalNoritoDecodingError.invalidField(
                "compact AccountId public key length is invalid"
            )
        }
        var bytes = Data()
        bytes.reserveCapacity(Int(count))
        for _ in 0..<count {
            let element = try reader.readCompactField()
            guard element.count == 1 else {
                throw CanonicalNoritoDecodingError.invalidField(
                    "compact AccountId public key element is not canonical"
                )
            }
            bytes.append(element[0])
        }
        guard reader.remaining() == 0,
              let algorithmByte = bytes.first,
              let algorithm = SigningAlgorithm(noritoDiscriminant: algorithmByte),
              let curve = try? CurveId.from(algorithm: algorithm.wireName) else {
            throw CanonicalNoritoDecodingError.invalidField(
                "compact AccountId public key is unsupported"
            )
        }
        let publicKey = Data(bytes.dropFirst())
        try validateCompactNoritoPublicKey(curve: curve, publicKey: publicKey)
        return (curve, publicKey)
    }

    fileprivate static func validateCompactNoritoPublicKey(
        curve: CurveId,
        publicKey: Data
    ) throws {
        let isValid: Bool
        switch curve {
        case .ed25519:
            isValid = Ed25519PublicKeyAdmission.isValidPublicKey(publicKey)
        #if IROHASWIFT_ENABLE_SECP256K1
        case .secp256k1:
            isValid = publicKey.count == 33
                && (publicKey.first == 0x02 || publicKey.first == 0x03)
                && publicKey.dropFirst().contains(where: { $0 != 0 })
        #endif
        #if IROHASWIFT_ENABLE_MLDSA
        case .mldsa:
            // Iroha's `ml-dsa` algorithm is the protocol-fixed ML-DSA-65 suite.
            isValid = publicKey.count == 1_952
                && publicKey.contains(where: { $0 != 0 })
        #endif
        #if IROHASWIFT_ENABLE_BLS
        case .blsNormal:
            isValid = publicKey.count == 48
                && publicKey.contains(where: { $0 != 0 })
        case .blsSmall:
            isValid = publicKey.count == 96
                && publicKey.contains(where: { $0 != 0 })
        #endif
        #if IROHASWIFT_ENABLE_GOST
        case .gost256A, .gost256B, .gost256C:
            isValid = publicKey.count == 64
                && publicKey.contains(where: { $0 != 0 })
        case .gost512A, .gost512B:
            isValid = publicKey.count == 128
                && publicKey.contains(where: { $0 != 0 })
        #endif
        #if IROHASWIFT_ENABLE_SM
        case .sm2:
            isValid = isCanonicalSm2PublicKeyEnvelope(publicKey)
        #endif
        }
        guard isValid else {
            throw CanonicalNoritoDecodingError.invalidField(
                "compact AccountId public key material is invalid"
            )
        }
    }

    #if IROHASWIFT_ENABLE_SM
    private static func isCanonicalSm2PublicKeyEnvelope(_ payload: Data) -> Bool {
        guard payload.count >= 2 + Sm2Keypair.publicKeyLength else {
            return false
        }
        let distidLength = (Int(payload[payload.startIndex]) << 8)
            | Int(payload[payload.index(after: payload.startIndex)])
        guard distidLength <= Int(UInt16.max) / 8,
              payload.count == 2 + distidLength + Sm2Keypair.publicKeyLength else {
            return false
        }
        let distidStart = payload.index(payload.startIndex, offsetBy: 2)
        let distidEnd = payload.index(distidStart, offsetBy: distidLength)
        guard String(data: payload[distidStart..<distidEnd], encoding: .utf8) != nil else {
            return false
        }
        let sec1 = payload[distidEnd...]
        return sec1.first == 0x04
            && sec1.dropFirst().contains(where: { $0 != 0 })
    }
    #endif

    private static func compactNoritoMultisigMemberSortKey(
        curve: CurveId,
        publicKey: Data
    ) throws -> Data {
        guard let algorithm = curve.signingAlgorithm else {
            throw CanonicalNoritoDecodingError.invalidField(
                "compact AccountId multisig member algorithm is unsupported"
            )
        }
        var key = Data(algorithm.wireName.utf8)
        key.append(0)
        key.append(publicKey)
        return key
    }

    private static func decodeCompactNoritoMultisigPolicyPayload(
        _ payload: Data
    ) throws -> ControllerPayload {
        var policy = CanonicalNoritoReader(data: payload)

        var version = CanonicalNoritoReader(data: try policy.readCompactField())
        let versionValue = try version.readUInt8()
        guard versionValue == 1, version.remaining() == 0 else {
            throw CanonicalNoritoDecodingError.invalidField(
                "compact AccountId multisig version is not canonical"
            )
        }

        var threshold = CanonicalNoritoReader(data: try policy.readCompactField())
        let thresholdValue = try threshold.readUInt16LE()
        guard thresholdValue > 0, threshold.remaining() == 0 else {
            throw CanonicalNoritoDecodingError.invalidField(
                "compact AccountId multisig threshold is invalid"
            )
        }

        var members = CanonicalNoritoReader(data: try policy.readCompactField())
        let memberCount = try members.readUInt64LE()
        guard memberCount > 0,
              memberCount <= UInt64(multisigMemberMax),
              memberCount <= UInt64(members.remaining()) else {
            throw CanonicalNoritoDecodingError.invalidField(
                "compact AccountId multisig member count is invalid"
            )
        }
        var decodedMembers: [ControllerPayload.MultisigMember] = []
        decodedMembers.reserveCapacity(Int(memberCount))
        var totalWeight: UInt64 = 0
        var previousSortKey: Data?
        for _ in 0..<memberCount {
            var member = CanonicalNoritoReader(data: try members.readCompactField())
            let key = try decodeCompactNoritoPublicKeyPayload(member.readCompactField())
            var weight = CanonicalNoritoReader(data: try member.readCompactField())
            let weightValue = try weight.readUInt16LE()
            let sortKey = try compactNoritoMultisigMemberSortKey(
                curve: key.curve,
                publicKey: key.publicKey
            )
            guard weightValue > 0,
                  weight.remaining() == 0,
                  member.remaining() == 0,
                  previousSortKey.map({ $0.lexicographicallyPrecedes(sortKey) }) ?? true else {
                throw CanonicalNoritoDecodingError.invalidField(
                    "compact AccountId multisig member is not canonical"
                )
            }
            totalWeight += UInt64(weightValue)
            previousSortKey = sortKey
            decodedMembers.append(ControllerPayload.MultisigMember(
                curve: key.curve,
                weight: weightValue,
                publicKey: key.publicKey
            ))
        }
        guard members.remaining() == 0,
              policy.remaining() == 0,
              UInt64(thresholdValue) <= totalWeight else {
            throw CanonicalNoritoDecodingError.invalidField(
                "compact AccountId multisig policy is invalid"
            )
        }
        return .multiSig(
            version: versionValue,
            threshold: thresholdValue,
            members: decodedMembers
        )
    }

    private func noritoPublicKeyPayload(curve: CurveId, publicKey: Data) throws -> Data {
        let algorithm = try noritoSigningAlgorithm(for: curve)
        var bytes = Data([algorithm.noritoDiscriminant])
        bytes.append(publicKey)
        return CanonicalNorito.encodeConstVec(bytes)
    }

    private func compactNoritoPublicKeyPayload(curve: CurveId, publicKey: Data) throws -> Data {
        let algorithm = try noritoSigningAlgorithm(for: curve)
        var bytes = Data([algorithm.noritoDiscriminant])
        bytes.append(publicKey)
        var writer = CompactNoritoWriter()
        writer.writeUInt64LE(UInt64(bytes.count))
        writer.writeByteFields(bytes)
        return writer.data
    }

    private func noritoMultisigPolicyPayload(
        version: UInt8,
        threshold: UInt16,
        members: [ControllerPayload.MultisigMember]
    ) throws -> Data {
        var writer = CanonicalNoritoWriter()
        writer.writeField(CanonicalNorito.encodeUInt8(version))
        writer.writeField(CanonicalNorito.encodeUInt16(threshold))
        let membersPayload = try CanonicalNorito.encodeVec(members) { member in
            var memberWriter = CanonicalNoritoWriter()
            let keyPayload = try noritoPublicKeyPayload(curve: member.curve, publicKey: member.publicKey)
            memberWriter.writeField(keyPayload)
            memberWriter.writeField(CanonicalNorito.encodeUInt16(member.weight))
            return memberWriter.data
        }
        writer.writeField(membersPayload)
        return writer.data
    }

    private func compactNoritoMultisigPolicyPayload(
        version: UInt8,
        threshold: UInt16,
        members: [ControllerPayload.MultisigMember]
    ) throws -> Data {
        var writer = CompactNoritoWriter()
        writer.writeField(CompactNorito.encodeUInt8(version))
        writer.writeField(CompactNorito.encodeUInt16(threshold))
        var membersPayload = CompactNoritoWriter()
        membersPayload.writeUInt64LE(UInt64(members.count))
        for member in members {
            var memberWriter = CompactNoritoWriter()
            let keyPayload = try compactNoritoPublicKeyPayload(curve: member.curve, publicKey: member.publicKey)
            memberWriter.writeField(keyPayload)
            memberWriter.writeField(CompactNorito.encodeUInt16(member.weight))
            membersPayload.writeField(memberWriter.data)
        }
        writer.writeField(membersPayload.data)
        return writer.data
    }

    private func noritoSigningAlgorithm(for curve: CurveId) throws -> SigningAlgorithm {
        switch curve {
        case .ed25519:
            return .ed25519
        #if IROHASWIFT_ENABLE_SECP256K1
        case .secp256k1:
            return .secp256k1
        #endif
        #if IROHASWIFT_ENABLE_MLDSA
        case .mldsa:
            return .mlDsa
        #endif
        #if IROHASWIFT_ENABLE_BLS
        case .blsNormal:
            return .blsNormal
        case .blsSmall:
            return .blsSmall
        #endif
        #if IROHASWIFT_ENABLE_GOST
        case .gost256A:
            return .gost2012_256A
        case .gost256B:
            return .gost2012_256B
        case .gost256C:
            return .gost2012_256C
        case .gost512A:
            return .gost2012_512A
        case .gost512B:
            return .gost2012_512B
        #endif
        #if IROHASWIFT_ENABLE_SM
        case .sm2:
            return .sm2
        #endif
        }
    }
}

// MARK: - Multisig builder

public enum MultisigBuilderError: Error, LocalizedError {
    case thresholdNotSet
    case noMembers
    case memberOverflow(Int)
    case invalidPolicy(String)
    case unsupportedAlgorithm(SigningAlgorithm)

    public var errorDescription: String? {
        switch self {
        case .thresholdNotSet:
            return "Multisig threshold must be configured before building a policy."
        case .noMembers:
            return "Multisig policies require at least one member."
        case let .memberOverflow(count):
            return "Multisig member count \(count) exceeds the supported maximum."
        case let .invalidPolicy(reason):
            return "Invalid multisig policy: \(reason)."
        case let .unsupportedAlgorithm(algorithm):
            return "Algorithm \(algorithm) is not available in this build."
        }
    }
}

public struct MultisigMemberDescriptor: Sendable {
    public let algorithm: SigningAlgorithm
    public let weight: UInt16
    public let publicKey: Data

    public init(algorithm: SigningAlgorithm, weight: UInt16, publicKey: Data) {
        self.algorithm = algorithm
        self.weight = weight
        self.publicKey = publicKey
    }
}

public struct MultisigPolicy: Sendable {
    public let version: UInt8
    public let threshold: UInt16
    public let members: [MultisigMemberDescriptor]
    public let ctap2Cbor: Data
    public let digestBlake2b256: Data

    public var ctap2CborHex: String { "0x\(ctap2Cbor.hexUppercased())" }
    public var digestHex: String { "0x\(digestBlake2b256.hexUppercased())" }
}

public final class MultisigPolicyBuilder {
    private var version: UInt8 = 1
    private var threshold: UInt16?
    private var members: [MultisigMemberDescriptor] = []

    public init() {}

    @discardableResult
    public func setVersion(_ version: UInt8) -> MultisigPolicyBuilder {
        self.version = version
        return self
    }

    @discardableResult
    public func setThreshold(_ threshold: UInt16) -> MultisigPolicyBuilder {
        self.threshold = threshold
        return self
    }

    @discardableResult
    public func addMember(_ descriptor: MultisigMemberDescriptor) -> MultisigPolicyBuilder {
        members.append(descriptor)
        return self
    }

    @discardableResult
    public func addMember(algorithm: SigningAlgorithm,
                          weight: UInt16,
                          publicKey: Data) -> MultisigPolicyBuilder {
        addMember(MultisigMemberDescriptor(algorithm: algorithm,
                                           weight: weight,
                                           publicKey: publicKey))
    }

    public func build() throws -> MultisigPolicy {
        guard let resolvedThreshold = threshold else {
            throw MultisigBuilderError.thresholdNotSet
        }
        guard !members.isEmpty else {
            throw MultisigBuilderError.noMembers
        }
        guard members.count <= multisigMemberMax else {
            throw MultisigBuilderError.memberOverflow(members.count)
        }

        guard version == 1, resolvedThreshold > 0 else {
            throw MultisigBuilderError.invalidPolicy("version and threshold must be canonical V1")
        }
        let canonicalMembers = members.sorted { left, right in
            let algorithmOrder = left.algorithm.wireName.compare(right.algorithm.wireName)
            return algorithmOrder == .orderedSame
                ? left.publicKey.lexicographicallyPrecedes(right.publicKey)
                : algorithmOrder == .orderedAscending
        }
        var previousSortKey: Data?
        var totalWeight: UInt64 = 0
        let payloadMembers = try canonicalMembers.map { descriptor -> ControllerPayload.MultisigMember in
            guard descriptor.weight > 0 else { throw MultisigBuilderError.invalidPolicy("zero member weight") }
            var sortKey = Data(descriptor.algorithm.wireName.utf8)
            sortKey.append(0); sortKey.append(descriptor.publicKey)
            guard previousSortKey != sortKey else { throw MultisigBuilderError.invalidPolicy("duplicate member") }
            previousSortKey = sortKey
            totalWeight += UInt64(descriptor.weight)
            let curve = try curveId(for: descriptor.algorithm)
            try ControllerPayload.validatePublicKey(
                curve: curve,
                publicKey: descriptor.publicKey
            )
            return ControllerPayload.MultisigMember(curve: curve,
                                                    weight: descriptor.weight,
                                                    publicKey: descriptor.publicKey)
        }
        guard UInt64(resolvedThreshold) <= totalWeight else {
            throw MultisigBuilderError.invalidPolicy("threshold exceeds total member weight")
        }
        var canonical = Data([try AddressHeader.new(version: 0, classId: .multiSig, normVersion: 1).encode()])
        try ControllerPayload.multiSig(version: version, threshold: resolvedThreshold, members: payloadMembers)
            .encode(into: &canonical)
        _ = try AccountAddress.fromCanonicalBytes(canonical)
        let cbor = encodeMultisigPolicyCTAP2(version: version,
                                             threshold: resolvedThreshold,
                                             members: payloadMembers)
        let digest = blake2bMac256(cbor, personal: AccountAddress.multisigPersonalisation)
        return MultisigPolicy(version: version,
                              threshold: resolvedThreshold,
                              members: canonicalMembers,
                              ctap2Cbor: cbor,
                              digestBlake2b256: digest)
    }

    private func curveId(for algorithm: SigningAlgorithm) throws -> CurveId {
        switch algorithm {
        case .ed25519:
            return .ed25519
        case .mlDsa:
            #if IROHASWIFT_ENABLE_MLDSA
            return .mldsa
            #else
            throw MultisigBuilderError.unsupportedAlgorithm(algorithm)
            #endif
        case .blsNormal:
            #if IROHASWIFT_ENABLE_BLS
            return .blsNormal
            #else
            throw MultisigBuilderError.unsupportedAlgorithm(algorithm)
            #endif
        case .blsSmall:
            #if IROHASWIFT_ENABLE_BLS
            return .blsSmall
            #else
            throw MultisigBuilderError.unsupportedAlgorithm(algorithm)
            #endif
        case .gost2012_256A:
            #if IROHASWIFT_ENABLE_GOST
            return .gost256A
            #else
            throw MultisigBuilderError.unsupportedAlgorithm(algorithm)
            #endif
        case .gost2012_256B:
            #if IROHASWIFT_ENABLE_GOST
            return .gost256B
            #else
            throw MultisigBuilderError.unsupportedAlgorithm(algorithm)
            #endif
        case .gost2012_256C:
            #if IROHASWIFT_ENABLE_GOST
            return .gost256C
            #else
            throw MultisigBuilderError.unsupportedAlgorithm(algorithm)
            #endif
        case .gost2012_512A:
            #if IROHASWIFT_ENABLE_GOST
            return .gost512A
            #else
            throw MultisigBuilderError.unsupportedAlgorithm(algorithm)
            #endif
        case .gost2012_512B:
            #if IROHASWIFT_ENABLE_GOST
            return .gost512B
            #else
            throw MultisigBuilderError.unsupportedAlgorithm(algorithm)
            #endif
        case .sm2:
            #if IROHASWIFT_ENABLE_SM
            return .sm2
            #else
            throw MultisigBuilderError.unsupportedAlgorithm(algorithm)
            #endif
        case .secp256k1:
            #if IROHASWIFT_ENABLE_SECP256K1
            return .secp256k1
            #else
            throw MultisigBuilderError.unsupportedAlgorithm(algorithm)
            #endif
        }
    }
}
