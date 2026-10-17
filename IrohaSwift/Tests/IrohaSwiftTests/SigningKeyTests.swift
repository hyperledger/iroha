import CryptoKit
import Foundation
import XCTest
@testable import IrohaSwift

private struct Ed25519PublicKeyAdmissionFixture: Decodable {
    struct Vector: Decodable {
        let name: String
        let valid: Bool
        let keyHex: String
        let singleCanonicalHex: String

        private enum CodingKeys: String, CodingKey {
            case name
            case valid
            case keyHex = "key_hex"
            case singleCanonicalHex = "single_canonical_hex"
        }
    }

    let vectors: [Vector]
}

final class SigningKeyTests: XCTestCase {
    func testConcurrentPublicKeyAdmissionKeepsMixedInputsExact() async throws {
        let fixtureURL = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("fixtures/crypto/ed25519_public_key_admission_v1.json")
        let fixture = try JSONDecoder().decode(Ed25519PublicKeyAdmissionFixture.self,
                                               from: Data(contentsOf: fixtureURL))
        let vectors = try fixture.vectors.map { vector in
            let bytes = try XCTUnwrap(Data(hexString: vector.keyHex), vector.name)
            XCTAssertEqual(Ed25519CompressedPointAdmission.isValidCompressedPoint(bytes), vector.valid, vector.name)
            return (name: vector.name, bytes: bytes, valid: vector.valid)
        }
        let workerKeys = try (0..<8).map { worker in
            let key = try Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: UInt8(0x70 + worker), count: 32))
                .publicKey.rawRepresentation
            XCTAssertTrue(Ed25519CompressedPointAdmission.isValidCompressedPoint(key))
            return key
        }
        let warm = try XCTUnwrap(vectors.first { $0.valid })
        XCTAssertTrue(Ed25519PublicKeyAdmission.isValidPublicKey(warm.bytes))

        struct Observation: Sendable {
            let worker: Int
            let name: String
            let actual: Bool
            let expected: Bool
        }
        let observations = await withTaskGroup(of: [Observation].self) { group in
            for worker in workerKeys.indices {
                group.addTask {
                    var result: [Observation] = []
                    for pass in 0..<2 {
                        // Distinct generated keys exercise concurrent insertion; the shared
                        // valid vector exercises hits among invalid length/curve/subgroup inputs.
                        result.append(Observation(worker: worker, name: "generated-key-\(pass)",
                            actual: Ed25519PublicKeyAdmission.isValidPublicKey(workerKeys[worker]), expected: true))
                        for offset in vectors.indices {
                            let vector = vectors[(worker + pass + offset) % vectors.count]
                            result.append(Observation(worker: worker, name: vector.name,
                                actual: Ed25519PublicKeyAdmission.isValidPublicKey(vector.bytes), expected: vector.valid))
                        }
                    }
                    return result
                }
            }
            var result: [Observation] = []
            for await workerResult in group { result.append(contentsOf: workerResult) }
            return result
        }
        XCTAssertEqual(observations.count, workerKeys.count * 2 * (vectors.count + 1))
        for worker in workerKeys.indices {
            let rows = observations.filter { $0.worker == worker }
            XCTAssertEqual(rows.count, 2 * (vectors.count + 1))
            for vector in vectors { XCTAssertEqual(rows.filter { $0.name == vector.name }.count, 2) }
            for row in rows { XCTAssertEqual(row.actual, row.expected, "worker \(worker): \(row.name)") }
        }
    }

    func testPublicKeyAdmissionOwnsBorrowedStorageBeforeItsCallerMutatesIt() throws {
        let key = try Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: 0x6d, count: 32))
        let original = key.publicKey.rawRepresentation
        XCTAssertTrue(Ed25519CompressedPointAdmission.isValidCompressedPoint(original))
        let storage = UnsafeMutableRawPointer.allocate(byteCount: original.count, alignment: 1)
        defer { storage.deallocate() }
        original.withUnsafeBytes { bytes in
            storage.copyMemory(from: bytes.baseAddress!, byteCount: bytes.count)
        }
        let borrowed = Data(bytesNoCopy: storage, count: original.count, deallocator: .none)
        XCTAssertEqual(borrowed, original)
        XCTAssertTrue(Ed25519PublicKeyAdmission.isValidPublicKey(borrowed))

        // This is a sequential external-buffer mutation, not Swift Data copy-on-write.
        // The memo must retain its own validated bytes rather than this caller-owned view.
        storage.initializeMemory(as: UInt8.self, repeating: 0, count: original.count)
        XCTAssertEqual(borrowed, Data(repeating: 0, count: 32))
        XCTAssertFalse(Ed25519PublicKeyAdmission.isValidPublicKey(borrowed))
        XCTAssertTrue(Ed25519PublicKeyAdmission.isValidPublicKey(original))
        original.withUnsafeBytes { bytes in
            storage.copyMemory(from: bytes.baseAddress!, byteCount: bytes.count)
        }
        XCTAssertEqual(borrowed, original)
        XCTAssertTrue(Ed25519PublicKeyAdmission.isValidPublicKey(borrowed))
    }

    func testRepeatedPublicKeyAdmissionMatchesUncachedSharedVectors() throws {
        let fixtureURL = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("fixtures/crypto/ed25519_public_key_admission_v1.json")
        let fixture = try JSONDecoder().decode(Ed25519PublicKeyAdmissionFixture.self,
                                               from: Data(contentsOf: fixtureURL))
        for vector in fixture.vectors {
            let bytes = try XCTUnwrap(Data(hexString: vector.keyHex), vector.name)
            let uncached = Ed25519CompressedPointAdmission.isValidCompressedPoint(bytes)
            XCTAssertEqual(uncached, vector.valid, vector.name)
            for _ in 0..<3 {
                XCTAssertEqual(Ed25519PublicKeyAdmission.isValidPublicKey(bytes), uncached, vector.name)
            }
        }
    }

    func testPreviouslyAdmittedPublicKeyDoesNotAuthorizeChangedOrSlicedBytes() throws {
        let key = try Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: 0x2a, count: 32))
        let original = key.publicKey.rawRepresentation
        XCTAssertTrue(Ed25519PublicKeyAdmission.isValidPublicKey(original))
        var framed = Data([0xaa])
        framed.append(original)
        framed.append(0xbb)
        let slice = framed[1..<33]
        XCTAssertNotEqual(slice.startIndex, 0)
        XCTAssertTrue(Ed25519PublicKeyAdmission.isValidPublicKey(slice))
        framed.replaceSubrange(1..<33, with: Data(repeating: 0, count: 32))
        XCTAssertFalse(Ed25519PublicKeyAdmission.isValidPublicKey(framed[1..<33]))
        XCTAssertTrue(Ed25519PublicKeyAdmission.isValidPublicKey(slice))
        XCTAssertTrue(Ed25519PublicKeyAdmission.isValidPublicKey(original))
        XCTAssertFalse(Ed25519PublicKeyAdmission.isValidPublicKey(Data(original.dropLast())))
    }

    func testPublicKeyAdmissionRemainsExactAfterMoreThanOneMemoCapacity() throws {
        let first = try Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: 0x29, count: 32))
            .publicKey.rawRepresentation
        XCTAssertTrue(Ed25519PublicKeyAdmission.isValidPublicKey(first))
        // More distinct valid keys than the bounded128-entry memo can retain.
        for value in UInt16(0)..<UInt16(129) {
            var seed = Data(repeating: 0, count: 32)
            seed[0] = UInt8(truncatingIfNeeded: value)
            seed[1] = UInt8(truncatingIfNeeded: value >> 8)
            let key = try Curve25519.Signing.PrivateKey(rawRepresentation: seed).publicKey.rawRepresentation
            XCTAssertTrue(Ed25519PublicKeyAdmission.isValidPublicKey(key))
        }
        XCTAssertTrue(Ed25519PublicKeyAdmission.isValidPublicKey(first))
        let mixedTorsion = try XCTUnwrap(Data(hexString:
            "6AEBC0B955CE4A2F1344029986B775E6EA5C40F93F1112B86EC51678EB9DC0FB"))
        XCTAssertFalse(Ed25519PublicKeyAdmission.isValidPublicKey(mixedTorsion))
        XCTAssertFalse(Ed25519CompressedPointAdmission.isValidCompressedPoint(mixedTorsion))
    }

    func testEd25519SigningProducesEnvelope() throws {
        let key = Curve25519.Signing.PrivateKey()
        let signingKey = try SigningKey.ed25519(privateKey: key.rawRepresentation,
                                                metadata: SigningMetadata(label: "unit-test"))
        let message = Data("swift-signing".utf8)
        let envelope = try signingKey.makeEnvelope(message: message)

        XCTAssertEqual(envelope.algorithm, .ed25519)
        XCTAssertEqual(try signingKey.publicKey(), key.publicKey.rawRepresentation)
        let publicKey = try Curve25519.Signing.PublicKey(rawRepresentation: envelope.publicKey)
        XCTAssertTrue(publicKey.isValidSignature(envelope.signature, for: message))
    }

    func testEd25519SignatureAdmissionRejectsInertMalformedRAndNoncanonicalS() throws {
        let key = Curve25519.Signing.PrivateKey()
        let message = Data("swift-ed25519-signature-admission".utf8)
        let signature = try key.signature(for: message)
        XCTAssertTrue(Ed25519SignatureAdmission.isValidSignature(signature))

        let smallOrderR = Data([
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ])
        let noncanonicalR = Data([
            0xEE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F,
        ])
        let mixedTorsionR = try XCTUnwrap(
            Data(hexString: "6AEBC0B955CE4A2F1344029986B775E6EA5C40F93F1112B86EC51678EB9DC0FB")
        )
        let negativeZeroR = Data([0x01] + Array(repeating: 0, count: 30) + [0x80])

        XCTAssertFalse(Ed25519SignatureAdmission.isValidSignature(Data(repeating: 0, count: 64)))
        XCTAssertFalse(Ed25519SignatureAdmission.isValidSignature(Data(signature.dropLast())))
        for replacementR in [smallOrderR, noncanonicalR, mixedTorsionR, negativeZeroR] {
            var malformed = signature
            malformed.replaceSubrange(0..<replacementR.count, with: replacementR)
            XCTAssertFalse(Ed25519SignatureAdmission.isValidSignature(malformed))
        }

        let subgroupOrder = try XCTUnwrap(
            Data(hexString: "EDD3F55C1A631258D69CF7A2DEF9DE1400000000000000000000000000000010")
        )
        var orderMinusOne = subgroupOrder
        orderMinusOne[orderMinusOne.startIndex] = 0xEC
        var orderPlusOne = subgroupOrder
        orderPlusOne[orderPlusOne.startIndex] = 0xEE

        var structurallyCanonical = signature
        structurallyCanonical.replaceSubrange(32..<64, with: orderMinusOne)
        XCTAssertTrue(Ed25519SignatureAdmission.isValidSignature(structurallyCanonical))
        structurallyCanonical.replaceSubrange(32..<64, with: Data(repeating: 0, count: 32))
        XCTAssertTrue(Ed25519SignatureAdmission.isValidSignature(structurallyCanonical))
        for replacementS in [subgroupOrder, orderPlusOne] {
            var noncanonical = signature
            noncanonical.replaceSubrange(32..<64, with: replacementS)
            XCTAssertFalse(Ed25519SignatureAdmission.isValidSignature(noncanonical))
        }
    }

    func testEd25519PublicKeyAdmissionRejectsWeakOrNoncanonicalMaterial() throws {
        let key = Curve25519.Signing.PrivateKey()
        XCTAssertTrue(Ed25519PublicKeyAdmission.isValidPublicKey(key.publicKey.rawRepresentation))

        let smallOrderKey = Data([
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ])
        let noncanonicalKey = Data([
            0xEE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F,
        ])
        let negativeZeroKey = Data([0x01] + Array(repeating: 0, count: 30) + [0x80])

        XCTAssertFalse(Ed25519PublicKeyAdmission.isValidPublicKey(Data(repeating: 0, count: 32)))
        XCTAssertFalse(Ed25519PublicKeyAdmission.isValidPublicKey(Data(repeating: 0x42, count: 31)))
        XCTAssertFalse(Ed25519PublicKeyAdmission.isValidPublicKey(smallOrderKey))
        XCTAssertFalse(Ed25519PublicKeyAdmission.isValidPublicKey(noncanonicalKey))
        XCTAssertFalse(Ed25519PublicKeyAdmission.isValidPublicKey(negativeZeroKey))
    }

    func testEd25519PublicKeyAdmissionMatchesSharedVectorsAndAccountBoundaries() throws {
        let fixtureURL = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent("fixtures/crypto/ed25519_public_key_admission_v1.json")
        let fixture = try JSONDecoder().decode(
            Ed25519PublicKeyAdmissionFixture.self,
            from: Data(contentsOf: fixtureURL)
        )

        for vector in fixture.vectors {
            let publicKey = try XCTUnwrap(Data(hexString: vector.keyHex), vector.name)
            let canonical = try XCTUnwrap(
                Data(hexString: vector.singleCanonicalHex),
                vector.name
            )
            XCTAssertEqual(
                Ed25519PublicKeyAdmission.isValidPublicKey(publicKey),
                vector.valid,
                vector.name
            )
            if vector.valid {
                let constructed = try AccountAddress.fromAccount(publicKey: publicKey)
                XCTAssertEqual(try constructed.canonicalBytes(), canonical, vector.name)
                XCTAssertNoThrow(try AccountAddress.fromCanonicalBytes(canonical), vector.name)
            } else {
                XCTAssertThrowsError(
                    try AccountAddress.fromAccount(publicKey: publicKey),
                    vector.name
                ) { error in
                    XCTAssertEqual(error as? AccountAddressError, .invalidPublicKey, vector.name)
                }
                XCTAssertThrowsError(
                    try AccountAddress.fromCanonicalBytes(canonical),
                    vector.name
                ) { error in
                    XCTAssertEqual(error as? AccountAddressError, .invalidPublicKey, vector.name)
                }
            }
        }
    }

    func testEd25519AdmissionRebasesNonzeroIndexDataSlices() throws {
        let publicKey = Curve25519.Signing.PrivateKey().publicKey.rawRepresentation
        var framedKey = Data([0xAA])
        framedKey.append(publicKey)
        framedKey.append(0xBB)
        let keySlice = framedKey[1..<(1 + publicKey.count)]
        XCTAssertNotEqual(keySlice.startIndex, 0)
        XCTAssertTrue(Ed25519PublicKeyAdmission.isValidPublicKey(keySlice))

        let address = try AccountAddress.fromAccount(publicKey: keySlice)
        let canonical = try address.canonicalBytes()
        var framedAddress = Data([0xAA, 0xBB])
        framedAddress.append(canonical)
        framedAddress.append(0xCC)
        let addressSlice = framedAddress[2..<(2 + canonical.count)]
        XCTAssertNotEqual(addressSlice.startIndex, 0)
        XCTAssertEqual(
            try AccountAddress.fromCanonicalBytes(addressSlice).canonicalBytes(),
            canonical
        )
    }

    func testMultisigBuilderRejectsMixedTorsionEd25519Member() throws {
        let mixedTorsion = try XCTUnwrap(
            Data(hexString: "6AEBC0B955CE4A2F1344029986B775E6EA5C40F93F1112B86EC51678EB9DC0FB")
        )
        let builder = MultisigPolicyBuilder()
            .setThreshold(1)
            .addMember(algorithm: .ed25519, weight: 1, publicKey: mixedTorsion)

        XCTAssertThrowsError(try builder.build()) { error in
            XCTAssertEqual(error as? AccountAddressError, .invalidPublicKey)
        }
    }

    func testCanonicalMultisigRejectsMixedTorsionEd25519Member() throws {
        var canonical = try XCTUnwrap(Data(hexString:
            "0A010100030003010001002068F4B6017D0F876A55C80A82B8388A54AAD264D367269E2DE8BE079C935B5F96" +
            "01000100207EA0E3BD52E207C9D3B0EBA65C0704E66FCA2D8E165A175218B174FC4160E413" +
            "0100020020884B8857F4EAA1613C61504DB34D4BEAF346517A0E31DE3CDDD4D9B4201D9D0B"
        ))
        let validFirstMember = try XCTUnwrap(
            Data(hexString: "68F4B6017D0F876A55C80A82B8388A54AAD264D367269E2DE8BE079C935B5F96")
        )
        let mixedTorsion = try XCTUnwrap(
            Data(hexString: "6AEBC0B955CE4A2F1344029986B775E6EA5C40F93F1112B86EC51678EB9DC0FB")
        )
        let memberRange = try XCTUnwrap(canonical.range(of: validFirstMember))
        canonical.replaceSubrange(memberRange, with: mixedTorsion)

        XCTAssertThrowsError(try AccountAddress.fromCanonicalBytes(canonical)) { error in
            XCTAssertEqual(error as? AccountAddressError, .invalidPublicKey)
        }
    }

    func testSm2SigningKeyPreservesMetadata() throws {
        let privateKey = Data(repeating: 0xAB, count: Sm2Keypair.privateKeyLength)
        let publicKey = Data(repeating: 0xCD, count: Sm2Keypair.publicKeyLength)
        let pair = try Sm2Keypair(distid: "dist", privateKey: privateKey, publicKey: publicKey)
        let signingKey = SigningKey.sm2(pair)

        XCTAssertEqual(signingKey.algorithm, .sm2)
        XCTAssertEqual(signingKey.metadata.distid, pair.distid)
        XCTAssertEqual(signingKey.metadata.storage, .bridge)
        XCTAssertEqual(try signingKey.publicKey(), publicKey)
    }

    func testSecp256k1SigningRoundTrip() throws {
        try requireNativeTestCapability(
            NoritoNativeBridge.shared.secp256k1Supported,
            "Secp256k1 bridge functions are unavailable on this platform."
        )
        let privateKey = Data(repeating: 0x01, count: Secp256k1Keypair.privateKeyLength)
        let keypair = try Secp256k1Keypair(privateKey: privateKey)
        let signingKey = SigningKey.secp256k1(keypair, metadata: SigningMetadata(label: "secp"))
        let message = Data("swift-secp256k1-signing".utf8)
        let signature = try signingKey.sign(message)
        XCTAssertEqual(signature.count, Secp256k1Keypair.signatureLength)
        XCTAssertTrue(try keypair.verify(message: message, signature: signature))

        let envelope = try signingKey.makeEnvelope(message: message)
        XCTAssertEqual(envelope.algorithm, .secp256k1)
        XCTAssertEqual(envelope.publicKey, keypair.publicKey)
        XCTAssertEqual(envelope.signature.count, Secp256k1Keypair.signatureLength)

        let verified = NoritoNativeBridge.shared.secp256k1Verify(
            publicKey: envelope.publicKey,
            message: message,
            signature: envelope.signature
        )
        XCTAssertEqual(verified, true)
    }

    func testMlDsaSigningRoundTripWhenBridgeAvailable() throws {
        try requireNativeTestCapability(
            NoritoNativeBridge.shared.mldsaSupported,
            "ML-DSA bridge is unavailable in this environment."
        )
        let keypair = try MlDsaKeypair.generate(suite: .mlDsa65)
        let signingKey = try SigningKey.mldsa(keypair,
                                              metadata: SigningMetadata(label: "mldsa"))
        let message = Data("swift-ml-dsa".utf8)
        let signature = try signingKey.sign(message)
        let expectedLength = keypair.suite.parameters().signatureLength
        XCTAssertEqual(signature.count, expectedLength)

        guard let verified = NoritoNativeBridge.shared.verifyDetached(
            algorithm: .mlDsa,
            publicKey: try signingKey.publicKey(),
            message: message,
            signature: signature
        ) else {
            try failRequiredNativeTestCapability(
                "ML-DSA verify bridge is unavailable in this environment."
            )
        }
        XCTAssertTrue(verified)

        let otherKeypair = try MlDsaKeypair.generate(suite: .mlDsa65)
        let inconsistentKeypair = try MlDsaKeypair(
            suite: .mlDsa65,
            publicKey: otherKeypair.publicKey,
            secretKey: keypair.secretKey
        )
        XCTAssertThrowsError(try SigningKey.mldsa(inconsistentKeypair)) { error in
            guard case MlDsaError.inconsistentKeypair = error else {
                return XCTFail("inconsistent ML-DSA-65 keypair failed with unexpected error: \(error)")
            }
        }
    }

    func testProtocolMlDsaSigningKeyRejectsNon65SuitesBeforeBridge() throws {
        for suite in [MlDsaSuite.mlDsa44, .mlDsa87] {
            let parameters = suite.parameters()
            let keypair = try MlDsaKeypair(
                suite: suite,
                publicKey: Data(repeating: 0xA5, count: parameters.publicKeyLength),
                secretKey: Data(repeating: 0x5A, count: parameters.secretKeyLength)
            )
            XCTAssertThrowsError(try SigningKey.mldsa(keypair)) { error in
                guard case MlDsaError.unsupportedProtocolSuite = error else {
                    return XCTFail("\(suite) failed with unexpected error: \(error)")
                }
            }
        }
    }

    func testMlDsaSuiteParametersAreAvailableBeforeBridge() {
        let expected: [(MlDsaSuite, Int, Int, Int)] = [
            (.mlDsa44, 1_312, 2_560, 2_420),
            (.mlDsa65, 1_952, 4_032, 3_309),
            (.mlDsa87, 2_592, 4_896, 4_627),
        ]
        for (suite, publicKeyLength, secretKeyLength, signatureLength) in expected {
            let parameters = suite.parameters()
            XCTAssertEqual(parameters.publicKeyLength, publicKeyLength)
            XCTAssertEqual(parameters.secretKeyLength, secretKeyLength)
            XCTAssertEqual(parameters.signatureLength, signatureLength)
        }
    }

    func testMlDsaKeypairRejectsMalformedKeyLengthsBeforeBridge() {
        let parameters = MlDsaSuite.mlDsa65.parameters()
        let publicKey = Data(repeating: 0xA5, count: parameters.publicKeyLength)
        let secretKey = Data(repeating: 0x5A, count: parameters.secretKeyLength)
        XCTAssertNoThrow(try MlDsaKeypair(suite: .mlDsa65,
                                          publicKey: publicKey,
                                          secretKey: secretKey))

        XCTAssertThrowsError(try MlDsaKeypair(suite: .mlDsa65,
                                              publicKey: Data(publicKey.dropLast()),
                                              secretKey: secretKey)) { error in
            guard case MlDsaError.invalidKeyLength = error else {
                return XCTFail("short ML-DSA public key failed with unexpected error: \(error)")
            }
        }

        var overlongSecretKey = secretKey
        overlongSecretKey.append(0x42)
        XCTAssertThrowsError(try MlDsaKeypair(suite: .mlDsa65,
                                              publicKey: publicKey,
                                              secretKey: overlongSecretKey)) { error in
            guard case MlDsaError.invalidKeyLength = error else {
                return XCTFail("overlong ML-DSA secret key failed with unexpected error: \(error)")
            }
        }
    }

    func testMlDsaVerifyRejectsMalformedSignatureLengthsBeforeBridge() throws {
        let parameters = MlDsaSuite.mlDsa65.parameters()
        let keypair = try MlDsaKeypair(suite: .mlDsa65,
                                       publicKey: Data(repeating: 0xA5, count: parameters.publicKeyLength),
                                       secretKey: Data(repeating: 0x5A, count: parameters.secretKeyLength))
        let message = Data("swift-ml-dsa-length-admission".utf8)

        XCTAssertThrowsError(try keypair.verify(message: message,
                                                signature: Data(repeating: 0x11,
                                                                count: parameters.signatureLength - 1))) { error in
            guard case MlDsaError.invalidSignatureLength = error else {
                return XCTFail("short ML-DSA signature failed with unexpected error: \(error)")
            }
        }

        XCTAssertThrowsError(try keypair.verify(message: message,
                                                signature: Data(repeating: 0x22,
                                                                count: parameters.signatureLength + 1))) { error in
            guard case MlDsaError.invalidSignatureLength = error else {
                return XCTFail("overlong ML-DSA signature failed with unexpected error: \(error)")
            }
        }
    }

    func testMlDsaExactLengthVerifyReportsUnavailableBridge() throws {
        let parameters = MlDsaSuite.mlDsa65.parameters()
        let keypair = try MlDsaKeypair(suite: .mlDsa65,
                                       publicKey: Data(repeating: 0xA5, count: parameters.publicKeyLength),
                                       secretKey: Data(repeating: 0x5A, count: parameters.secretKeyLength))

        let message = Data("swift-ml-dsa-bridge-unavailable".utf8)
        let signature = Data(repeating: 0x33, count: parameters.signatureLength)
        if NoritoNativeBridge.shared.mldsaSupported {
            XCTAssertFalse(try keypair.verify(message: message, signature: signature))
        } else {
            XCTAssertThrowsError(try keypair.verify(message: message, signature: signature)) { error in
                guard case MlDsaError.bridgeUnavailable = error else {
                    return XCTFail("exact-length ML-DSA verification failed with unexpected error: \(error)")
                }
            }
        }
    }

    func testMlDsaVerifyRejectsMalformedSignaturesWhenBridgeAvailable() throws {
        try requireNativeTestCapability(
            NoritoNativeBridge.shared.mldsaSupported,
            "ML-DSA bridge is unavailable in this environment."
        )
        let keypair = try MlDsaKeypair.generate(suite: .mlDsa65)
        let message = Data("swift-ml-dsa-signature-admission".utf8)
        let signature = try keypair.sign(message: message)

        XCTAssertTrue(try keypair.verify(message: message, signature: signature))

        var shortSignature = signature
        shortSignature.removeLast()
        XCTAssertThrowsError(try keypair.verify(message: message, signature: shortSignature)) { error in
            guard case MlDsaError.invalidSignatureLength = error else {
                return XCTFail("short ML-DSA signature failed with unexpected error: \(error)")
            }
        }

        var overlongSignature = signature
        overlongSignature.append(0x42)
        XCTAssertThrowsError(try keypair.verify(message: message, signature: overlongSignature)) { error in
            guard case MlDsaError.invalidSignatureLength = error else {
                return XCTFail("overlong ML-DSA signature failed with unexpected error: \(error)")
            }
        }

        let allZeroSignature = Data(repeating: 0, count: signature.count)
        XCTAssertEqual(NoritoNativeBridge.shared.mldsaVerify(
            suiteId: keypair.suite.rawValue,
            publicKey: keypair.publicKey,
            message: message,
            signature: allZeroSignature
        ), false)
        XCTAssertFalse(try keypair.verify(message: message, signature: allZeroSignature))
    }

    func testMultihashPrivateKeyMatchesKnownAuthority() throws {
        let authorityId = "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV"
        guard let privateKeyBytes = Data(hexString: "802620CCF31D85E3B32A4BEA59987CE0C78E3B8E2DB93881468AB2435FE45D5C9DCD53") else {
            return XCTFail("invalid multihash private key hex")
        }
        let signingKey = try SigningKey.fromMultihashPrivateKey(privateKeyBytes)
        XCTAssertEqual(signingKey.algorithm, .ed25519)

        let publicKey = try signingKey.publicKey()
        let address = try AccountAddress.parseEncoded(authorityId, expectedPrefix: 753)
        guard let controller = address.singleControllerInfo() else {
            return XCTFail("expected single-key controller in authority_id")
        }
        XCTAssertEqual(controller.algorithm, .ed25519)
        XCTAssertEqual(controller.publicKey, publicKey)
    }

}
