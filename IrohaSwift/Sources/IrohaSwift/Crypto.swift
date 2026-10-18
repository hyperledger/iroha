import Foundation
import CryptoKit

public enum SigningAlgorithm: UInt8, CaseIterable, Sendable {
    case ed25519 = 0
    case secp256k1 = 1
    case blsNormal = 2
    case blsSmall = 3
    case mlDsa = 4
    case gost2012_256A = 5
    case gost2012_256B = 6
    case gost2012_256C = 7
    case gost2012_512A = 8
    case gost2012_512B = 9
    case sm2 = 10

    public var noritoDiscriminant: UInt8 { rawValue }

    public init?(noritoDiscriminant: UInt8) {
        self.init(rawValue: noritoDiscriminant)
    }

    public var requiresDistId: Bool {
        switch self {
        case .sm2:
            return true
        default:
            return false
        }
    }

    public var wireName: String {
        switch self {
        case .ed25519:
            return "ed25519"
        case .secp256k1:
            return "secp256k1"
        case .blsNormal:
            return "bls_normal"
        case .blsSmall:
            return "bls_small"
        case .mlDsa:
            return "ml-dsa"
        case .gost2012_256A:
            return "gost3410-2012-256-paramset-a"
        case .gost2012_256B:
            return "gost3410-2012-256-paramset-b"
        case .gost2012_256C:
            return "gost3410-2012-256-paramset-c"
        case .gost2012_512A:
            return "gost3410-2012-512-paramset-a"
        case .gost2012_512B:
            return "gost3410-2012-512-paramset-b"
        case .sm2:
            return "sm2"
        }
    }
}

private enum Ed25519FieldParameters: PastaFieldParameters {
    static let modulus: [UInt64] = [
        0xffff_ffff_ffff_ffed,
        0xffff_ffff_ffff_ffff,
        0xffff_ffff_ffff_ffff,
        0x7fff_ffff_ffff_ffff,
    ]
    static let montgomeryInv: UInt64 = 0x86bc_a1af_286b_ca1b
    static let r: [UInt64] = [0x26, 0, 0, 0]
    static let r2: [UInt64] = [0x5a4, 0, 0, 0]
    static let r3: [UInt64] = [0xd658, 0, 0, 0]
    static let rootOfUnity: [UInt64] = [
        0xc4ee_1b27_4a0e_a0b0,
        0x2f43_1806_ad2f_e478,
        0x2b4d_0099_3dfb_d7a7,
        0x2b83_2480_4fc1_df0b,
    ]
    static let rootOfUnityInv: [UInt64] = [
        0x3b11_e4d8_b5f1_5f3d,
        0xd0bc_e7f9_52d0_1b87,
        0xd4b2_ff66_c204_2858,
        0x547c_db7f_b03e_20f4,
    ]
    static let zeta: [UInt64] = [0, 0, 0, 0]
    static let twoAdicity = 2
    static let t: [UInt64] = [
        0xffff_ffff_ffff_fffb,
        0xffff_ffff_ffff_ffff,
        0xffff_ffff_ffff_ffff,
        0x1fff_ffff_ffff_ffff,
    ]
    static let tPlusOneOverTwo: [UInt64] = [
        0xffff_ffff_ffff_fffe,
        0xffff_ffff_ffff_ffff,
        0xffff_ffff_ffff_ffff,
        0x0fff_ffff_ffff_ffff,
    ]
}

enum Ed25519CompressedPointAdmission {
    private typealias Field = PastaField<Ed25519FieldParameters>

    private struct ExtendedPoint {
        let x: Field
        let y: Field
        let z: Field
        let t: Field

        static let identity = ExtendedPoint(x: .zero, y: .one, z: .one, t: .zero)

        var isIdentity: Bool {
            z != .zero && x == .zero && y == z
        }

        func adding(_ other: ExtendedPoint) -> ExtendedPoint {
            // Complete extended Edwards addition for a = -1. This remains
            // deterministic across platforms because PastaField is fixed-width.
            let a = (y - x) * (other.y - other.x)
            let b = (y + x) * (other.y + other.x)
            let c = twiceCurveD * t * other.t
            let d = Field(2) * z * other.z
            let e = b - a
            let f = d - c
            let g = d + c
            let h = b + a
            return ExtendedPoint(x: e * f, y: g * h, z: f * g, t: e * h)
        }
    }

    static let compressedPointLength = 32
    private static let curveD = Field.fromRawLimbs([
        0x75eb_4dca_1359_78a3,
        0x0070_0a4d_4141_d8ab,
        0x8cc7_4079_7779_e898,
        0x5203_6cee_2b6f_fe73,
    ])
    private static let twiceCurveD = Field.fromRawLimbs([
        0xebd6_9b94_26b2_f159,
        0x00e0_149a_8283_b156,
        0x198e_80f2_eef3_d130,
        0x2406_d9dc_56df_fce7,
    ])
    private static let subgroupOrder: [UInt64] = [
        0x5812_631a_5cf5_d3ed,
        0x14de_f9de_a2f7_9cd6,
        0,
        0x1000_0000_0000_0000,
    ]
    private static let fieldPrimeLittleEndian: [UInt8] = [
        0xED, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F,
    ]
    private static let smallOrderCompressedPoints: [[UInt8]] = [
        [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ],
        [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80,
        ],
        [
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ],
        [
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80,
        ],
        [
            0xEC, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F,
        ],
        [
            0xEC, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        ],
        [
            0x26, 0xE8, 0x95, 0x8F, 0xC2, 0xB2, 0x27, 0xB0,
            0x45, 0xC3, 0xF4, 0x89, 0xF2, 0xEF, 0x98, 0xF0,
            0xD5, 0xDF, 0xAC, 0x05, 0xD3, 0xC6, 0x33, 0x39,
            0xB1, 0x38, 0x02, 0x88, 0x6D, 0x53, 0xFC, 0x05,
        ],
        [
            0xC7, 0x17, 0x6A, 0x70, 0x3D, 0x4D, 0xD8, 0x4F,
            0xBA, 0x3C, 0x0B, 0x76, 0x0D, 0x10, 0x67, 0x0F,
            0x2A, 0x20, 0x53, 0xFA, 0x2C, 0x39, 0xCC, 0xC6,
            0x4E, 0xC7, 0xFD, 0x77, 0x92, 0xAC, 0x03, 0x7A,
        ],
        [
            0x13, 0x88, 0x8E, 0xCB, 0x61, 0xC5, 0xC9, 0x57,
            0x39, 0xD9, 0x5C, 0x69, 0xCE, 0x51, 0x77, 0xC4,
            0x50, 0xE9, 0x91, 0x28, 0xE7, 0xA9, 0x0B, 0x3E,
            0xCB, 0xC5, 0x95, 0xE0, 0x35, 0xC1, 0x55, 0x00,
        ],
        [
            0xB4, 0xDF, 0xC5, 0x3E, 0x58, 0x08, 0x02, 0x46,
            0x83, 0x9B, 0x2C, 0x4E, 0x6F, 0x3D, 0xB6, 0x3E,
            0x18, 0x5F, 0x6C, 0x73, 0x0B, 0x31, 0xE9, 0x90,
            0xB6, 0xF3, 0xF2, 0x51, 0x92, 0x95, 0x55, 0x0F,
        ],
    ]

    static func isValidCompressedPoint(_ compressed: Data) -> Bool {
        let bytes = [UInt8](compressed)
        guard isCanonicalCompressedEdwardsY(bytes),
              !isSmallOrderCompressedEdwardsY(bytes),
              let point = decompress(compressed),
              !point.isIdentity else {
            return false
        }
        return multiply(point, by: subgroupOrder).isIdentity
    }

    private static func decompress(_ compressed: Data) -> ExtendedPoint? {
        guard compressed.count == compressedPointLength else {
            return nil
        }
        // `Data.SubSequence` is also `Data` and can retain a non-zero start index.
        // Rebase before the field decoder performs zero-based indexing.
        var yBytes = Data(compressed)
        let lastIndex = yBytes.index(before: yBytes.endIndex)
        let xIsOdd = (yBytes[lastIndex] & 0x80) != 0
        yBytes[lastIndex] &= 0x7f
        guard let y = Field.fromCanonicalBytes(yBytes) else {
            return nil
        }

        let ySquared = y.squared()
        let numerator = ySquared - .one
        let denominator = curveD * ySquared + .one
        guard let ratio = Field.sqrtRatio(numerator: numerator, denominator: denominator),
              ratio.isSquare else {
            return nil
        }
        var x = ratio.root
        if x.isOdd != xIsOdd {
            x = -x
        }
        // RFC 8032 requires the sign bit to be zero when x is zero.
        guard !(x == .zero && xIsOdd) else {
            return nil
        }

        var canonical = y.canonicalBytes()
        let canonicalLastIndex = canonical.index(before: canonical.endIndex)
        if x.isOdd {
            canonical[canonicalLastIndex] |= 0x80
        }
        guard canonical == compressed else {
            return nil
        }
        return ExtendedPoint(x: x, y: y, z: .one, t: x * y)
    }

    private static func multiply(_ point: ExtendedPoint, by scalar: [UInt64]) -> ExtendedPoint {
        precondition(scalar.count == 4)
        var result = ExtendedPoint.identity
        for bit in stride(from: 255, through: 0, by: -1) {
            result = result.adding(result)
            if ((scalar[bit / 64] >> UInt64(bit % 64)) & 1) == 1 {
                result = result.adding(point)
            }
        }
        return result
    }

    private static func isCanonicalCompressedEdwardsY(_ compressed: [UInt8]) -> Bool {
        guard compressed.count == compressedPointLength else {
            return false
        }
        var y = compressed
        y[compressedPointLength - 1] &= 0x7F
        for index in stride(from: compressedPointLength - 1, through: 0, by: -1) {
            if y[index] < fieldPrimeLittleEndian[index] {
                return true
            }
            if y[index] > fieldPrimeLittleEndian[index] {
                return false
            }
        }
        return false
    }

    private static func isSmallOrderCompressedEdwardsY(_ compressed: [UInt8]) -> Bool {
        smallOrderCompressedPoints.contains { candidate in
            candidate.elementsEqual(compressed)
        }
    }
}

enum Ed25519PublicKeyAdmission {
    static let publicKeyLength = Ed25519CompressedPointAdmission.compressedPointLength
    private static let validatedKeys = ValidatedKeys()

    static func isValidPublicKey(_ publicKey: Data) -> Bool {
        guard publicKey.count == publicKeyLength else { return false }
        // Validate and retain the same owned byte snapshot, including for bridged Data.
        let candidate = Data([UInt8](publicKey))
        if validatedKeys.contains(candidate) { return true }
        guard Ed25519CompressedPointAdmission.isValidCompressedPoint(candidate) else {
            return false
        }
        validatedKeys.insert(candidate)
        return true
    }

    /// Admission is a pure property of the exact public key bytes. Retain only successful
    /// complete curve/subgroup checks; this does not cache signatures or account ownership.
    private final class ValidatedKeys: @unchecked Sendable {
        private let lock = NSLock()
        private var keys = Set<Data>()
        private let capacity = 128

        func contains(_ key: Data) -> Bool {
            lock.lock()
            defer { lock.unlock() }
            return keys.contains(key)
        }

        func insert(_ key: Data) {
            lock.lock()
            defer { lock.unlock() }
            guard !keys.contains(key) else { return }
            // Eviction changes only how often the complete admission check runs.
            if keys.count == capacity { keys.removeAll(keepingCapacity: true) }
            keys.insert(key)
        }
    }
}

enum Ed25519SignatureAdmission {
    static let signatureLength = 64
    private static let scalarLength = 32
    private static let subgroupOrderLittleEndian: [UInt8] = [
        0xED, 0xD3, 0xF5, 0x5C, 0x1A, 0x63, 0x12, 0x58,
        0xD6, 0x9C, 0xF7, 0xA2, 0xDE, 0xF9, 0xDE, 0x14,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
    ]

    static func isValidSignature(_ signature: Data) -> Bool {
        guard signature.count == signatureLength else {
            return false
        }
        let bytes = [UInt8](signature)
        guard bytes.contains(where: { $0 != 0 }) else {
            return false
        }
        let r = Data(bytes.prefix(Ed25519CompressedPointAdmission.compressedPointLength))
        let s = bytes.suffix(scalarLength)
        return Ed25519CompressedPointAdmission.isValidCompressedPoint(r)
            && isCanonicalScalar(s)
    }

    private static func isCanonicalScalar(_ scalar: ArraySlice<UInt8>) -> Bool {
        guard scalar.count == scalarLength else {
            return false
        }
        let bytes = Array(scalar)
        for index in stride(from: scalarLength - 1, through: 0, by: -1) {
            if bytes[index] < subgroupOrderLittleEndian[index] {
                return true
            }
            if bytes[index] > subgroupOrderLittleEndian[index] {
                return false
            }
        }
        // Equality is non-canonical: RFC 8032 requires 0 <= S < l.
        return false
    }
}

public enum SigningStorageBackend: String, Sendable {
    case inMemory
    case secureEnclave
    case bridge
    case external
}

public struct SigningMetadata: Sendable {
    public var distid: String?
    public var label: String?
    public var storage: SigningStorageBackend

    public init(distid: String? = nil,
                label: String? = nil,
                storage: SigningStorageBackend = .inMemory) {
        self.distid = distid
        self.label = label
        self.storage = storage
    }

    public static func inMemory(label: String? = nil) -> SigningMetadata {
        SigningMetadata(distid: nil, label: label, storage: .inMemory)
    }

    public static func secureEnclave(label: String) -> SigningMetadata {
        SigningMetadata(distid: nil, label: label, storage: .secureEnclave)
    }
}

public struct SignatureEnvelope: Sendable {
    public let algorithm: SigningAlgorithm
    public let publicKey: Data
    public let signature: Data
    public let metadata: SigningMetadata?

    public init(algorithm: SigningAlgorithm,
                publicKey: Data,
                signature: Data,
                metadata: SigningMetadata?) {
        self.algorithm = algorithm
        self.publicKey = publicKey
        self.signature = signature
        self.metadata = metadata
    }

    public var noritoAlgorithmIdentifier: UInt8 { algorithm.noritoDiscriminant }
}

public enum SigningKeyError: Error, LocalizedError {
    case unsupportedAlgorithm(String)
    case publicKeyUnavailable

    public var errorDescription: String? {
        switch self {
        case let .unsupportedAlgorithm(label):
            return "Signing algorithm \(label) is not supported in this build."
        case .publicKeyUnavailable:
            return "Unable to load the public key for this signing key."
        }
    }
}

public enum MultihashPrivateKeyError: Error, LocalizedError {
    case invalidFormat(String)
    case invalidLength(expected: Int, actual: Int)
    case unsupportedAlgorithm(String)

    public var errorDescription: String? {
        switch self {
        case let .invalidFormat(reason):
            return "Invalid multihash private key: \(reason)"
        case let .invalidLength(expected, actual):
            return "Multihash private key length mismatch (expected \(expected), got \(actual))."
        case let .unsupportedAlgorithm(reason):
            return "Unsupported multihash private key algorithm: \(reason)"
        }
    }
}

@available(macOS 10.15, iOS 13.0, *)
public struct SigningKey {
    public let algorithm: SigningAlgorithm
    public var metadata: SigningMetadata

    private let signer: (Data) throws -> Data
    private let publicKeyProvider: () throws -> Data
    private let rawPrivateKeyProvider: (() throws -> Data)?

    private init(algorithm: SigningAlgorithm,
                 metadata: SigningMetadata,
                 signer: @escaping (Data) throws -> Data,
                 publicKeyProvider: @escaping () throws -> Data,
                 rawPrivateKeyProvider: (() throws -> Data)?) {
        self.algorithm = algorithm
        self.metadata = metadata
        self.signer = signer
        self.publicKeyProvider = publicKeyProvider
        self.rawPrivateKeyProvider = rawPrivateKeyProvider
    }

    public func publicKey() throws -> Data {
        try publicKeyProvider()
    }

    public func sign(_ message: Data) throws -> Data {
        try signer(message)
    }

    public func makeEnvelope(message: Data) throws -> SignatureEnvelope {
        let signature = try sign(message)
        let publicKey = try publicKey()
        return SignatureEnvelope(algorithm: algorithm,
                                 publicKey: publicKey,
                                 signature: signature,
                                 metadata: metadata)
    }

    public static func ed25519(privateKey: Data,
                               metadata: SigningMetadata = SigningMetadata()) throws -> SigningKey {
        let key = try Curve25519.Signing.PrivateKey(rawRepresentation: privateKey)
        let sanitizedMetadata = metadata.storage == .bridge
            ? SigningMetadata(distid: metadata.distid, label: metadata.label, storage: .inMemory)
            : metadata
        return SigningKey(algorithm: .ed25519,
                          metadata: sanitizedMetadata,
                          signer: { message in try key.signature(for: message) },
                          publicKeyProvider: { key.publicKey.rawRepresentation },
                          rawPrivateKeyProvider: { key.rawRepresentation })
    }

    public static func sm2(_ keypair: Sm2Keypair,
                           metadata: SigningMetadata? = nil) -> SigningKey {
        let resolvedMetadata: SigningMetadata = {
            if var provided = metadata {
                if provided.distid == nil {
                    provided.distid = keypair.distid
                }
                if provided.storage == .inMemory {
                    provided.storage = .bridge
                }
                return provided
            }
            return SigningMetadata(distid: keypair.distid,
                                   label: nil,
                                   storage: .bridge)
        }()
        return SigningKey(algorithm: .sm2,
                          metadata: resolvedMetadata,
                          signer: { message in try keypair.sign(message: message) },
                          publicKeyProvider: { keypair.publicKey },
                          rawPrivateKeyProvider: { keypair.privateKey })
    }

    public static func secp256k1(privateKey: Data,
                                 metadata: SigningMetadata = SigningMetadata()) throws -> SigningKey {
        let keypair = try Secp256k1Keypair(privateKey: privateKey)
        return secp256k1(keypair, metadata: metadata)
    }

    public static func secp256k1(_ keypair: Secp256k1Keypair,
                                 metadata: SigningMetadata = SigningMetadata()) -> SigningKey {
        let sanitizedMetadata = metadata.storage == .bridge
            ? SigningMetadata(distid: metadata.distid, label: metadata.label, storage: .inMemory)
            : metadata
        if let key = try? nativeSigningKey(algorithm: .secp256k1,
                                           privateKey: keypair.privateKey,
                                           metadata: sanitizedMetadata) {
            return key
        }
        return SigningKey(algorithm: .secp256k1,
                          metadata: sanitizedMetadata,
                          signer: { message in try keypair.sign(message: message) },
                          publicKeyProvider: { keypair.publicKey },
                          rawPrivateKeyProvider: { keypair.privateKey })
    }

    public static func mlDsa(privateKey: Data,
                             metadata: SigningMetadata = SigningMetadata()) throws -> SigningKey {
        try nativeSigningKey(algorithm: .mlDsa,
                             privateKey: privateKey,
                             metadata: metadata)
    }

    public static func native(algorithm: SigningAlgorithm,
                              privateKey: Data,
                              metadata: SigningMetadata = SigningMetadata()) throws -> SigningKey {
        guard algorithm != .ed25519 else {
            return try SigningKey.ed25519(privateKey: privateKey, metadata: metadata)
        }
        return try nativeSigningKey(algorithm: algorithm,
                                    privateKey: privateKey,
                                    metadata: metadata)
    }

    /// Wrap an ML-DSA-65 keypair for Iroha protocol signing.
    public static func mldsa(_ keypair: MlDsaKeypair,
                             metadata: SigningMetadata = SigningMetadata()) throws -> SigningKey {
        guard keypair.suite == .mlDsa65 else {
            throw MlDsaError.unsupportedProtocolSuite
        }
        let signingKey = try nativeSigningKey(algorithm: .mlDsa,
                                              privateKey: keypair.secretKey,
                                              metadata: metadata)
        guard try signingKey.publicKey() == keypair.publicKey else {
            throw MlDsaError.inconsistentKeypair
        }
        return signingKey
    }
}

extension SigningKey {
    /// Build a signing key from multihash-encoded private key bytes.
    public static func fromMultihashPrivateKey(_ multihash: Data,
                                               metadata: SigningMetadata = SigningMetadata()) throws -> SigningKey {
        let (algorithm, payload) = try MultihashPrivateKey.decode(multihash)
        switch algorithm {
        case .ed25519:
            return try SigningKey.ed25519(privateKey: payload, metadata: metadata)
        default:
            return try SigningKey.native(algorithm: algorithm,
                                         privateKey: payload,
                                         metadata: metadata)
        }
    }

    func exportPrivateKeyBytes() -> Data? {
        guard let rawPrivateKeyProvider else {
            return nil
        }
        guard let raw = try? rawPrivateKeyProvider() else {
            return nil
        }
        if algorithm.requiresDistId {
            guard let distid = metadata.distid else {
                return nil
            }
            let distidBytes = Data(distid.utf8)
            guard distidBytes.count <= Int(UInt16.max),
                  raw.count == Sm2Keypair.privateKeyLength else {
                return nil
            }
            var length = UInt16(distidBytes.count).bigEndian
            var encoded = Data()
            withUnsafeBytes(of: &length) { encoded.append(contentsOf: $0) }
            encoded.append(distidBytes)
            encoded.append(raw)
            return encoded
        }
        return raw
    }

    private static func nativeSigningKey(algorithm: SigningAlgorithm,
                                         privateKey: Data,
                                         metadata: SigningMetadata) throws -> SigningKey {
        guard let publicKey = NoritoNativeBridge.shared.publicKeyFromPrivate(
            algorithm: algorithm,
            privateKey: privateKey
        ) else {
            throw SigningKeyError.publicKeyUnavailable
        }
        return SigningKey(algorithm: algorithm,
                          metadata: metadata,
                          signer: { message in
                              guard let signature = NoritoNativeBridge.shared.signDetached(
                                algorithm: algorithm,
                                privateKey: privateKey,
                                message: message
                              ) else {
                                  throw SigningKeyError.unsupportedAlgorithm(String(describing: algorithm))
                              }
                              return signature
                          },
                          publicKeyProvider: { publicKey },
                          rawPrivateKeyProvider: { privateKey })
    }
}

private enum MultihashPrivateKey {
    static func decode(_ bytes: Data) throws -> (SigningAlgorithm, Data) {
        let raw = [UInt8](bytes)
        let (functionCode, functionEnd) = try decodeVarint(raw, startIndex: 0)
        let (length, lengthEnd) = try decodeVarint(raw, startIndex: functionEnd)
        guard lengthEnd <= raw.count else {
            throw MultihashPrivateKeyError.invalidFormat("digest size not found")
        }
        let payload = Data(raw[lengthEnd...])
        guard payload.count == Int(length) else {
            throw MultihashPrivateKeyError.invalidLength(expected: Int(length), actual: payload.count)
        }
        let algorithm = try signingAlgorithm(multihashCode: functionCode)
        return (algorithm, payload)
    }

    private static func decodeVarint(_ bytes: [UInt8], startIndex: Int) throws -> (UInt64, Int) {
        var value: UInt64 = 0
        var shift: UInt64 = 0
        var index = startIndex
        while index < bytes.count {
            let byte = bytes[index]
            let chunk = UInt64(byte & 0x7F)
            if shift >= 64 {
                throw MultihashPrivateKeyError.invalidFormat("varint overflow")
            }
            value |= chunk << shift
            index += 1
            if (byte & 0x80) == 0 {
                return (value, index)
            }
            shift += 7
        }
        throw MultihashPrivateKeyError.invalidFormat("varint truncated")
    }

    private static func signingAlgorithm(multihashCode: UInt64) throws -> SigningAlgorithm {
        switch multihashCode {
        case 0x1300:
            return .ed25519
        case 0x1301:
            return .secp256k1
        case 0x1309:
            return .blsNormal
        case 0x130a:
            return .blsSmall
        case 0x130b:
            return .mlDsa
        case 0x130c:
            return .gost2012_256A
        case 0x130d:
            return .gost2012_256B
        case 0x130e:
            return .gost2012_256C
        case 0x130f:
            return .gost2012_512A
        case 0x1310:
            return .gost2012_512B
        case 0x1311:
            return .sm2
        default:
            let reason = String(format: "multihash code 0x%X", multihashCode)
            throw MultihashPrivateKeyError.unsupportedAlgorithm(reason)
        }
    }
}

@available(macOS 10.15, iOS 13.0, *)
public struct Keypair {
    public let privateKey: Curve25519.Signing.PrivateKey
    public var publicKey: Data { privateKey.publicKey.rawRepresentation }
    public var privateKeyBytes: Data { privateKey.rawRepresentation }

    @available(macOS 10.15, iOS 13.0, *)
    public static func generate() throws -> Keypair {
        return Keypair(privateKey: Curve25519.Signing.PrivateKey())
    }

    @available(macOS 10.15, iOS 13.0, *)
    init(privateKey: Curve25519.Signing.PrivateKey) {
        self.privateKey = privateKey
    }

    @available(macOS 10.15, iOS 13.0, *)
    public init(privateKeyBytes: Data) throws {
        self.privateKey = try Curve25519.Signing.PrivateKey(rawRepresentation: privateKeyBytes)
    }

    @available(macOS 10.15, iOS 13.0, *)
    public func sign(_ message: Data) throws -> Data {
        return try privateKey.signature(for: message)
    }

    /// Build i105 format account ID for this keypair.
    ///
    /// - Parameters:
    ///   - networkPrefix: Network prefix for i105 encoding (defaults to Iroha mainnet)
    /// - Returns: Account ID in format `<i105>`
    /// - Throws: `AccountAddressError` if conversion fails
    @available(macOS 10.15, iOS 13.0, *)
    public func accountId(networkPrefix: UInt16 = AccountId.defaultNetworkPrefix) throws -> String {
        try AccountId.makeI105(publicKey: publicKey, networkPrefix: networkPrefix)
    }
}

public enum AccountId {
    /// Default network prefix for i105 encoding (Iroha mainnet).
    public static let defaultNetworkPrefix: UInt16 = 0x02F1

    /// Build the I105 account id literal of an Ed25519 `publicKey` on the
    /// default network prefix.
    ///
    /// - Throws: `AccountAddressError` when the key is not a valid Ed25519
    ///   public key. Use `makeI105(publicKey:algorithm:distid:networkPrefix:)`
    ///   for other algorithms or networks.
    public static func make(publicKey: Data) throws -> String {
        try makeI105(publicKey: publicKey)
    }

    /// Build i105 format account ID string required by Torii API.
    ///
    /// Torii API requires account IDs in i105 format for canonical output; this method
    /// converts a public key to the correct format.
    ///
    /// - Parameters:
    ///   - publicKey: Public key bytes (32 bytes for ed25519, 33 for secp256k1, 65-byte SEC1 for SM2)
    ///   - algorithm: Signing algorithm, defaults to "ed25519"
    ///   - distid: SM2 distinguishing identifier. Defaults to the bridge's SM2 default when omitted.
    ///   - networkPrefix: Network prefix for i105 encoding (defaults to Iroha mainnet)
    /// - Returns: Account ID in format `<i105>`
    /// - Throws: `AccountAddressError` if conversion fails
    public static func makeI105(
        publicKey: Data,
        algorithm: String = "ed25519",
        distid: String? = nil,
        networkPrefix: UInt16 = defaultNetworkPrefix
    ) throws -> String {
        let address = try AccountAddress.fromAccount(publicKey: publicKey, algorithm: algorithm, distid: distid)
        return try address.toI105(networkPrefix: networkPrefix)
    }

    /// Normalizes account id literals for equality checks.
    ///
    /// Semantics:
    /// - If the literal is an encoded `AccountAddress`, returns the canonical I105 rendering.
    /// - Otherwise, returns the trimmed literal unchanged.
    public static func normalizeForComparison(
        _ literal: String,
        expectedPrefix: UInt16 = defaultNetworkPrefix
    ) -> String {
        let trimmed = literal.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return "" }

        if let address = try? AccountAddress.parseEncoded(trimmed, expectedPrefix: expectedPrefix),
           let i105 = try? address.toI105(networkPrefix: expectedPrefix) {
            return i105
        }

        return trimmed
    }

    /// Returns true when both account id literals refer to the same address under `normalizeForComparison`.
    public static func matchesForComparison(
        _ lhs: String,
        _ rhs: String,
        expectedPrefix: UInt16 = defaultNetworkPrefix
    ) -> Bool {
        normalizeForComparison(lhs, expectedPrefix: expectedPrefix) == normalizeForComparison(rhs, expectedPrefix: expectedPrefix)
    }
}

public enum Secp256k1Error: Error, LocalizedError, Sendable {
    case bridgeUnavailable
    case invalidKeyLength
    case invalidSignatureLength
    case signFailed
    case verifyFailed

    public var errorDescription: String? {
        switch self {
        case .bridgeUnavailable:
            return NoritoNativeBridge.bridgeUnavailableMessage(
                "secp256k1 support is unavailable."
            )
        case .invalidKeyLength:
            return "secp256k1 keys must be 32-byte private / 33-byte compressed public values."
        case .invalidSignatureLength:
            return "secp256k1 signatures must be 64 bytes (r∥s)."
        case .signFailed:
            return "Failed to produce a secp256k1 signature."
        case .verifyFailed:
            return "secp256k1 verification could not be performed."
        }
    }
}

public struct Secp256k1Keypair: Sendable {
    public static let privateKeyLength = 32
    public static let publicKeyLength = 33
    public static let signatureLength = 64

    public let privateKey: Data
    public let publicKey: Data

    public init(privateKey: Data, publicKey: Data? = nil) throws {
        guard privateKey.count == Self.privateKeyLength else {
            throw Secp256k1Error.invalidKeyLength
        }
        let resolvedPublicKey: Data
        if let publicKey {
            guard publicKey.count == Self.publicKeyLength else {
                throw Secp256k1Error.invalidKeyLength
            }
            resolvedPublicKey = publicKey
        } else if let derived = NoritoNativeBridge.shared.publicKeyFromPrivate(
            algorithm: .secp256k1,
            privateKey: privateKey
        ) {
            guard derived.count == Self.publicKeyLength else {
                throw Secp256k1Error.invalidKeyLength
            }
            resolvedPublicKey = derived
        } else {
            guard let derived = NoritoNativeBridge.shared.secp256k1PublicKey(privateKey: privateKey) else {
                throw Secp256k1Error.bridgeUnavailable
            }
            resolvedPublicKey = derived
        }
        guard resolvedPublicKey.count == Self.publicKeyLength else {
            throw Secp256k1Error.invalidKeyLength
        }
        self.privateKey = privateKey
        self.publicKey = resolvedPublicKey
    }

    public func sign(message: Data) throws -> Data {
        guard privateKey.count == Self.privateKeyLength else {
            throw Secp256k1Error.invalidKeyLength
        }
        if let signature = NoritoNativeBridge.shared.signDetached(algorithm: .secp256k1,
                                                                  privateKey: privateKey,
                                                                  message: message) {
            guard signature.count == Self.signatureLength else {
                throw Secp256k1Error.invalidSignatureLength
            }
            return signature
        }
        guard let signature = NoritoNativeBridge.shared.secp256k1Sign(privateKey: privateKey, message: message),
              signature.count == Self.signatureLength else {
            throw Secp256k1Error.signFailed
        }
        return signature
    }

    public func verify(message: Data, signature: Data) throws -> Bool {
        guard signature.count == Self.signatureLength else {
            throw Secp256k1Error.invalidSignatureLength
        }
        if let verified = NoritoNativeBridge.shared.verifyDetached(algorithm: .secp256k1,
                                                                   publicKey: publicKey,
                                                                   message: message,
                                                                   signature: signature) {
            return verified
        }
        guard let verified = NoritoNativeBridge.shared.secp256k1Verify(publicKey: publicKey,
                                                                       message: message,
                                                                       signature: signature) else {
            throw Secp256k1Error.verifyFailed
        }
        return verified
    }
}

public enum Sm2Error: Error, LocalizedError, Sendable {
    case bridgeUnavailable
    case invalidKeyLength
    case invalidSignatureLength
    case signFailed
    case verifyFailed

    public var errorDescription: String? {
        switch self {
        case .bridgeUnavailable:
            return NoritoNativeBridge.bridgeUnavailableMessage("SM2 support is unavailable.")
        case .invalidKeyLength:
            return "SM2 keys must be 32-byte private / 65-byte public values."
        case .invalidSignatureLength:
            return "SM2 signatures must be 64 bytes (r∥s)."
        case .signFailed:
            return "Failed to produce an SM2 signature."
        case .verifyFailed:
            return "SM2 verification could not be performed."
        }
    }
}

public struct Sm2Keypair: Sendable {
    public static let privateKeyLength = 32
    public static let publicKeyLength = 65
    public static let signatureLength = 64

    public let distid: String
    public let privateKey: Data
    public let publicKey: Data

    public init(distid: String, privateKey: Data, publicKey: Data) throws {
        guard privateKey.count == Self.privateKeyLength else {
            throw Sm2Error.invalidKeyLength
        }
        guard publicKey.count == Self.publicKeyLength else {
            throw Sm2Error.invalidKeyLength
        }
        self.distid = distid
        self.privateKey = privateKey
        self.publicKey = publicKey
    }

    public static func defaultDistid() -> String {
        NoritoNativeBridge.shared.sm2DefaultDistid() ?? "1234567812345678"
    }

    public static func deriveFromSeed(distid: String? = nil, seed: Data) throws -> Sm2Keypair {
        let targetDistid = distid ?? defaultDistid()
        guard let pair = NoritoNativeBridge.shared.sm2KeypairFromSeed(distid: targetDistid, seed: seed) else {
            throw Sm2Error.bridgeUnavailable
        }
        return try Sm2Keypair(distid: targetDistid, privateKey: pair.privateKey, publicKey: pair.publicKey)
    }

    public func sign(message: Data) throws -> Data {
        guard let signature = NoritoNativeBridge.shared.sm2Sign(distid: distid, privateKey: privateKey, message: message),
              signature.count == Sm2Keypair.signatureLength else {
            throw Sm2Error.signFailed
        }
        return signature
    }

    public func verify(message: Data, signature: Data) throws -> Bool {
        guard signature.count == Sm2Keypair.signatureLength else {
            throw Sm2Error.invalidSignatureLength
        }
        guard let result = NoritoNativeBridge.shared.sm2Verify(distid: distid, publicKey: publicKey, message: message, signature: signature) else {
            throw Sm2Error.verifyFailed
        }
        return result
    }

    public func publicKeyPrefixed() throws -> String {
        guard let prefixed = NoritoNativeBridge.shared.sm2PublicKeyPrefixed(distid: distid, publicKey: publicKey) else {
            throw Sm2Error.bridgeUnavailable
        }
        return prefixed
    }

    public func publicKeyMultihash() throws -> String {
        guard let multihash = NoritoNativeBridge.shared.sm2PublicKeyMultihash(distid: distid, publicKey: publicKey) else {
            throw Sm2Error.bridgeUnavailable
        }
        return multihash
    }

    public func computeZA() throws -> Data {
        guard let za = NoritoNativeBridge.shared.sm2ComputeZa(distid: distid, publicKey: publicKey) else {
            throw Sm2Error.bridgeUnavailable
        }
        return za
    }
}

public enum MlDsaError: Error, LocalizedError, Sendable {
    case bridgeUnavailable
    case invalidKeyLength
    case invalidSignatureLength
    case unsupportedProtocolSuite
    case inconsistentKeypair
    case generateFailed
    case signFailed
    case verifyFailed

    public var errorDescription: String? {
        switch self {
        case .bridgeUnavailable:
            return NoritoNativeBridge.bridgeUnavailableMessage("ML-DSA support is unavailable.")
        case .invalidKeyLength:
            return "ML-DSA keys do not match the expected length for this suite."
        case .invalidSignatureLength:
            return "ML-DSA signatures must match the suite's signature length."
        case .unsupportedProtocolSuite:
            return "Iroha protocol signing requires ML-DSA-65."
        case .inconsistentKeypair:
            return "The ML-DSA public key does not match the supplied secret key."
        case .generateFailed:
            return "Failed to generate an ML-DSA keypair."
        case .signFailed:
            return "Failed to produce an ML-DSA signature."
        case .verifyFailed:
            return "ML-DSA verification could not be performed."
        }
    }
}

public struct MlDsaParameters: Sendable {
    public let publicKeyLength: Int
    public let secretKeyLength: Int
    public let signatureLength: Int
}

public enum MlDsaSuite: UInt8, CaseIterable, Sendable {
    case mlDsa44 = 0
    case mlDsa65 = 1
    case mlDsa87 = 2

    func parameters() -> MlDsaParameters {
        switch self {
        case .mlDsa44:
            return MlDsaParameters(publicKeyLength: 1_312,
                                   secretKeyLength: 2_560,
                                   signatureLength: 2_420)
        case .mlDsa65:
            return MlDsaParameters(publicKeyLength: 1_952,
                                   secretKeyLength: 4_032,
                                   signatureLength: 3_309)
        case .mlDsa87:
            return MlDsaParameters(publicKeyLength: 2_592,
                                   secretKeyLength: 4_896,
                                   signatureLength: 4_627)
        }
    }
}

public struct MlDsaKeypair: Sendable {
    public let suite: MlDsaSuite
    public let publicKey: Data
    public let secretKey: Data
    private let params: MlDsaParameters

    public init(suite: MlDsaSuite, publicKey: Data, secretKey: Data) throws {
        let parameters = suite.parameters()
        guard publicKey.count == parameters.publicKeyLength,
              secretKey.count == parameters.secretKeyLength else {
            throw MlDsaError.invalidKeyLength
        }
        self.suite = suite
        self.publicKey = publicKey
        self.secretKey = secretKey
        self.params = parameters
    }

    public static func generate(suite: MlDsaSuite) throws -> MlDsaKeypair {
        let parameters = suite.parameters()
        guard NoritoNativeBridge.shared.mldsaSupported else {
            throw MlDsaError.bridgeUnavailable
        }
        guard let pair = NoritoNativeBridge.shared.mldsaGenerateKeypair(
            suiteId: suite.rawValue,
            publicKeyLength: parameters.publicKeyLength,
            secretKeyLength: parameters.secretKeyLength
        ) else {
            throw MlDsaError.generateFailed
        }
        return try MlDsaKeypair(suite: suite, publicKey: pair.publicKey, secretKey: pair.secretKey)
    }

    public func sign(message: Data) throws -> Data {
        guard NoritoNativeBridge.shared.mldsaSupported else {
            throw MlDsaError.bridgeUnavailable
        }
        guard let signature = NoritoNativeBridge.shared.mldsaSign(
            suiteId: suite.rawValue,
            secretKey: secretKey,
            message: message,
            signatureLength: params.signatureLength
        ) else {
            throw MlDsaError.signFailed
        }
        return signature
    }

    public func verify(message: Data, signature: Data) throws -> Bool {
        guard signature.count == params.signatureLength else {
            throw MlDsaError.invalidSignatureLength
        }
        guard NoritoNativeBridge.shared.mldsaSupported else {
            throw MlDsaError.bridgeUnavailable
        }
        guard let result = NoritoNativeBridge.shared.mldsaVerify(
            suiteId: suite.rawValue,
            publicKey: publicKey,
            message: message,
            signature: signature
        ) else {
            throw MlDsaError.verifyFailed
        }
        return result
    }
}
