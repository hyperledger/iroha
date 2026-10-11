import CryptoKit
import Dispatch
import XCTest
@testable import IrohaSwift

final class IrohaPeerNearbyV1Tests: XCTestCase {
    func testEncryptedRequestPreservesCompanionAndRejectsRecordReplay() throws {
        // Local transport signing keys authenticate this test channel, not wallet monetary DATA.
        let envelope = irohaPeerWalletStructuralEnvelopeV1(kind: .request, payload: Data([0x31]))
        let account = try irohaPeerWalletRequestAccountOriginalV1()
        let request = try IrohaPeerKagemushaWalletAdapterV1.wrap(
            envelope, destinationAccountOriginal: account)
        let pair = try makeAuthenticatedPair(requestHash: request.canonicalHash)
        let record = try pair.receiver.seal(request.encoded)
        let plaintext = try pair.sender.open(record)
        let decoded = try IrohaPeerWireMessageV1.decode(plaintext)
        XCTAssertEqual(decoded, request)
        XCTAssertEqual(try IrohaPeerKagemushaWalletAdapterV1.decode(decoded), envelope)
        XCTAssertEqual(try IrohaPeerKagemushaWalletAdapterV1.destinationAccountOriginal(decoded), account)
        XCTAssertThrowsError(try pair.sender.open(record))
    }

    func testAuthenticationSignatureFitsCommonRadioRecordCeiling() throws {
        let maximum = IrohaPeerNearbyV1.maximumAuthenticationSignatureBytes
        let authentication = try IrohaPeerNearbyAuthenticationV1(
            profile: .kagemushaWalletV1,
            role: .sender,
            sessionID: Data(repeating: 1, count: 16),
            transcriptHash: Data(repeating: 2, count: 32),
            signature: Data(repeating: 3, count: maximum)
        )
        XCTAssertEqual(authentication.encode().count, 32 * 1_024)
        XCTAssertEqual(
            try IrohaPeerNearbyAuthenticationV1.decode(authentication.encode()),
            authentication
        )
        XCTAssertThrowsError(try IrohaPeerNearbyAuthenticationV1(
            profile: .kagemushaWalletV1,
            role: .sender,
            sessionID: Data(repeating: 1, count: 16),
            transcriptHash: Data(repeating: 2, count: 32),
            signature: Data(repeating: 3, count: maximum + 1)
        ))
    }

    func testRecordDecodersRejectOversizedInputsBeforeMaterialization() {
        let helloFixedLength = 4 + 1 + 1 + 2 + 1 + 1 + 16 + 32 + 32 + 2
        let oversizedHello = Data(
            repeating: 0,
            count: helloFixedLength + 65 + 4
                + IrohaPeerNearbyV1.maximumCertificateBytes + 1
        )
        XCTAssertThrowsError(try IrohaPeerNearbyHelloV1.decode(oversizedHello)) {
            XCTAssertEqual($0 as? IrohaPeerNearbyErrorV1, .invalidLength)
        }

        let authenticationFixedLength = 4 + 1 + 1 + 2 + 1 + 1 + 16 + 32 + 2
        let oversizedAuthentication = Data(
            repeating: 0,
            count: authenticationFixedLength
                + IrohaPeerNearbyV1.maximumAuthenticationSignatureBytes + 1
        )
        XCTAssertThrowsError(
            try IrohaPeerNearbyAuthenticationV1.decode(oversizedAuthentication)
        ) {
            XCTAssertEqual($0 as? IrohaPeerNearbyErrorV1, .invalidLength)
        }

        let encryptedHeaderLength = 4 + 1 + 1 + 2 + 1 + 1 + 16 + 8 + 4
        let oversizedEncrypted = Data(
            repeating: 0,
            count: encryptedHeaderLength + IrohaPeerNearbyV1.maximumMessageBytes + 16 + 1
        )
        XCTAssertThrowsError(
            try IrohaPeerNearbyEncryptedRecordV1.decode(oversizedEncrypted)
        ) {
            XCTAssertEqual($0 as? IrohaPeerNearbyErrorV1, .invalidLength)
        }
    }

    func testSessionRejectsOversizedInputsBeforeRetainingCopies() throws {
        let privateKey = P256.KeyAgreement.PrivateKey()
        XCTAssertThrowsError(try IrohaPeerNearbySessionV1(
            profile: .kagemushaWalletV1,
            localRole: .sender,
            sessionID: Data(repeating: 1, count: 17),
            requestCanonicalHash: Data(repeating: 2, count: 32),
            deviceCertificate: Data([3]),
            nonce: Data(repeating: 4, count: 32),
            ephemeralPrivateKey: privateKey
        )) {
            XCTAssertEqual($0 as? IrohaPeerNearbyErrorV1, .invalidSession)
        }
        XCTAssertThrowsError(try IrohaPeerNearbySessionV1(
            profile: .kagemushaWalletV1,
            localRole: .sender,
            sessionID: Data(repeating: 1, count: 16),
            requestCanonicalHash: Data(repeating: 2, count: 33),
            deviceCertificate: Data([3]),
            nonce: Data(repeating: 4, count: 32),
            ephemeralPrivateKey: privateKey
        )) {
            XCTAssertEqual($0 as? IrohaPeerNearbyErrorV1, .invalidRequest)
        }
        XCTAssertThrowsError(try IrohaPeerNearbySessionV1(
            profile: .kagemushaWalletV1,
            localRole: .sender,
            sessionID: Data(repeating: 1, count: 16),
            requestCanonicalHash: Data(repeating: 2, count: 32),
            deviceCertificate: Data(
                repeating: 3,
                count: IrohaPeerNearbyV1.maximumCertificateBytes + 1
            ),
            nonce: Data(repeating: 4, count: 32),
            ephemeralPrivateKey: privateKey
        )) {
            XCTAssertEqual($0 as? IrohaPeerNearbyErrorV1, .invalidCertificate)
        }
    }

    func testDiscoveryContextRoundTripsAndRejectsWrongVersion() throws {
        let context = try IrohaPeerNearbyDiscoveryContextV1(
            profile: .kagemushaWalletV1,
            role: .receiver,
            sessionID: Data(repeating: 0x11, count: 16),
            requestCanonicalHash: Data(repeating: 0x22, count: 32)
        )
        let encoded = context.encode()
        XCTAssertEqual(try IrohaPeerNearbyDiscoveryContextV1.decode(encoded), context)

        var changed = encoded
        changed[4] = 2
        XCTAssertThrowsError(try IrohaPeerNearbyDiscoveryContextV1.decode(changed)) {
            XCTAssertEqual($0 as? IrohaPeerNearbyErrorV1, .unsupportedVersion)
        }
    }

    func testZeroContextIsRejectedExceptForExplicitDiscoveryBootstrap() throws {
        XCTAssertThrowsError(try IrohaPeerNearbyDiscoveryContextV1(
            profile: .kagemushaWalletV1,
            role: .sender,
            sessionID: Data(repeating: 0, count: 16),
            requestCanonicalHash: Data(repeating: 0x22, count: 32)
        )) {
            XCTAssertEqual($0 as? IrohaPeerNearbyErrorV1, .invalidSession)
        }
        XCTAssertThrowsError(try IrohaPeerNearbyDiscoveryContextV1(
            profile: .kagemushaWalletV1,
            role: .sender,
            sessionID: Data(repeating: 0x11, count: 16),
            requestCanonicalHash: Data(repeating: 0, count: 32)
        )) {
            XCTAssertEqual($0 as? IrohaPeerNearbyErrorV1, .invalidRequest)
        }

        let bootstrap = try IrohaPeerNearbyDiscoveryContextV1.senderBootstrap(
            profile: .kagemushaWalletV1
        )
        XCTAssertEqual(
            try IrohaPeerNearbyDiscoveryContextV1.decode(bootstrap.encode()),
            bootstrap
        )

        var halfZero = try IrohaPeerNearbyDiscoveryContextV1(
            profile: .kagemushaWalletV1,
            role: .sender,
            sessionID: Data(repeating: 0x11, count: 16),
            requestCanonicalHash: Data(repeating: 0x22, count: 32)
        ).encode()
        halfZero.replaceSubrange(8..<24, with: Data(repeating: 0, count: 16))
        XCTAssertThrowsError(try IrohaPeerNearbyDiscoveryContextV1.decode(halfZero)) {
            XCTAssertEqual($0 as? IrohaPeerNearbyErrorV1, .invalidSession)
        }

        var receiverBootstrap = bootstrap.encode()
        receiverBootstrap[7] = IrohaPeerNearbyRoleV1.receiver.rawValue
        XCTAssertThrowsError(
            try IrohaPeerNearbyDiscoveryContextV1.decode(receiverBootstrap)
        ) {
            XCTAssertEqual($0 as? IrohaPeerNearbyErrorV1, .invalidRole)
        }
    }

    func testRadioDiscoveryEncodingIsStrictCanonicalBase64URLWithoutPadding() throws {
        let discovery = try IrohaPeerNearbyDiscoveryContextV1(
            profile: .kagemushaWalletV1,
            role: .receiver,
            sessionID: Data((1...16).map(UInt8.init)),
            requestCanonicalHash: Data((2...33).map(UInt8.init))
        )
        let canonical = discovery.encodeRadioDiscovery()
        XCTAssertEqual(canonical.utf8.count, 75)
        XCTAssertFalse(canonical.contains("="))
        XCTAssertEqual(
            try IrohaPeerNearbyDiscoveryContextV1.decodeRadioDiscovery(canonical),
            discovery
        )
        XCTAssertThrowsError(
            try IrohaPeerNearbyDiscoveryContextV1.decodeRadioDiscovery(canonical + "=")
        ) {
            XCTAssertEqual(
                $0 as? IrohaPeerNearbyErrorV1,
                .invalidDiscoveryRepresentation
            )
        }
        XCTAssertThrowsError(
            try IrohaPeerNearbyDiscoveryContextV1.decodeRadioDiscovery(
                " " + String(canonical.dropFirst())
            )
        )
        XCTAssertThrowsError(
            try IrohaPeerNearbyDiscoveryContextV1.decodeRadioDiscovery(
                String(canonical.dropLast()) + "R"
            )
        )
    }

    func testBootstrapSenderAdoptsAdvertisedReceiverContextBeforeConnecting() throws {
        let sender = try IrohaPeerNearbyDiscoveryContextV1.senderBootstrap(
            profile: .kagemushaWalletV1
        )
        let receiver = try IrohaPeerNearbyDiscoveryContextV1(
            profile: .kagemushaWalletV1,
            role: .receiver,
            sessionID: Data(repeating: 0x31, count: 16),
            requestCanonicalHash: Data(repeating: 0x32, count: 32)
        )
        let selected = IrohaPeerNearbyDiscoveryMatcherV1.selectLocalContext(
            local: sender,
            remote: receiver,
            expectedRemoteRole: .receiver
        )
        XCTAssertEqual(selected?.role, .sender)
        XCTAssertEqual(selected?.sessionID, receiver.sessionID)
        XCTAssertEqual(
            selected?.requestCanonicalHash,
            receiver.requestCanonicalHash
        )
        XCTAssertNil(IrohaPeerNearbyDiscoveryMatcherV1.selectLocalContext(
            local: sender,
            remote: try IrohaPeerNearbyDiscoveryContextV1(
                profile: .kagemushaWalletV1,
                role: .sender,
                sessionID: receiver.sessionID,
                requestCanonicalHash: receiver.requestCanonicalHash
            ),
            expectedRemoteRole: .receiver
        ))
    }

    func testGoogleVerificationCodeRequiresFourToTwelveASCIIDigits() {
        XCTAssertTrue(IrohaPeerNearbyVerificationCodeV1.isValid("1234"))
        XCTAssertTrue(IrohaPeerNearbyVerificationCodeV1.isValid("123456"))
        XCTAssertTrue(IrohaPeerNearbyVerificationCodeV1.isValid("123456789012"))
        XCTAssertFalse(IrohaPeerNearbyVerificationCodeV1.isValid(""))
        XCTAssertFalse(IrohaPeerNearbyVerificationCodeV1.isValid("123"))
        XCTAssertFalse(IrohaPeerNearbyVerificationCodeV1.isValid("1234567890123"))
        XCTAssertFalse(IrohaPeerNearbyVerificationCodeV1.isValid("123 456"))
        XCTAssertFalse(IrohaPeerNearbyVerificationCodeV1.isValid("١٢٣٤٥٦"))
        XCTAssertFalse(IrohaPeerNearbyVerificationCodeV1.isValid("１２３４５６"))
    }

    func testSessionRecordsRejectZeroSecurityContext() throws {
        let ephemeralKey = P256.KeyAgreement.PrivateKey()
        let certificate = Data(repeating: 0x31, count: 32)
        let sessionID = Data(repeating: 0x41, count: 16)
        let requestHash = Data(repeating: 0x42, count: 32)
        let nonce = Data(repeating: 0x43, count: 32)

        XCTAssertThrowsError(try IrohaPeerNearbyHelloV1(
            profile: .kagemushaWalletV1,
            role: .sender,
            sessionID: Data(repeating: 0, count: 16),
            nonce: nonce,
            requestCanonicalHash: requestHash,
            ephemeralPublicKey: ephemeralKey.publicKey.x963Representation,
            deviceCertificate: certificate
        )) {
            XCTAssertEqual($0 as? IrohaPeerNearbyErrorV1, .invalidSession)
        }
        XCTAssertThrowsError(try IrohaPeerNearbyHelloV1(
            profile: .kagemushaWalletV1,
            role: .sender,
            sessionID: sessionID,
            nonce: Data(repeating: 0, count: 32),
            requestCanonicalHash: requestHash,
            ephemeralPublicKey: ephemeralKey.publicKey.x963Representation,
            deviceCertificate: certificate
        )) {
            XCTAssertEqual($0 as? IrohaPeerNearbyErrorV1, .invalidLength)
        }
        XCTAssertThrowsError(try IrohaPeerNearbyHelloV1(
            profile: .kagemushaWalletV1,
            role: .sender,
            sessionID: sessionID,
            nonce: nonce,
            requestCanonicalHash: Data(repeating: 0, count: 32),
            ephemeralPublicKey: ephemeralKey.publicKey.x963Representation,
            deviceCertificate: certificate
        )) {
            XCTAssertEqual($0 as? IrohaPeerNearbyErrorV1, .invalidRequest)
        }
        XCTAssertThrowsError(try IrohaPeerNearbyAuthenticationV1(
            profile: .kagemushaWalletV1,
            role: .sender,
            sessionID: sessionID,
            transcriptHash: Data(repeating: 0, count: 32),
            signature: Data([1])
        )) {
            XCTAssertEqual($0 as? IrohaPeerNearbyErrorV1, .transcriptMismatch)
        }
        XCTAssertThrowsError(try IrohaPeerNearbyEncryptedRecordV1(
            profile: .kagemushaWalletV1,
            senderRole: .sender,
            sessionID: Data(repeating: 0, count: 16),
            sequence: 0,
            ciphertextAndTag: Data(repeating: 0x51, count: 16)
        )) {
            XCTAssertEqual($0 as? IrohaPeerNearbyErrorV1, .invalidSession)
        }
    }

    func testAuthenticatedSessionsExchangeEncryptedMessagesInBothDirections() throws {
        let pair = try makeAuthenticatedPair()
        let payment = Data("IPM1-payment-fixture".utf8)
        let paymentRecord = try pair.sender.seal(payment)
        XCTAssertEqual(try pair.receiver.open(paymentRecord), payment)

        let acknowledgement = Data("IPM1-ack-fixture".utf8)
        let acknowledgementRecord = try pair.receiver.seal(acknowledgement)
        XCTAssertEqual(try pair.sender.open(acknowledgementRecord), acknowledgement)
    }

    func testFullPeerMessageAndNearbyRecordCeilingsAreExact() throws {
        XCTAssertEqual(IrohaPeerNearbyV1.maximumMessageBytes, 32 * 1_024 - 64)
        XCTAssertEqual(
            IrohaPeerNfcV1.maximumMessageBytes,
            IrohaPeerWireMessageV1.headerBytes + IrohaPeerWireLimitsV1.maximumWalletProfileBytes
        )
        XCTAssertLessThanOrEqual(
            IrohaPeerNfcV1.maximumMessageBytes,
            IrohaPeerNearbyV1.maximumMessageBytes
        )

        let pair = try makeAuthenticatedPair()
        let maximumPlaintext = Data(
            repeating: 0xA5,
            count: IrohaPeerNearbyV1.maximumMessageBytes
        )
        let record = try pair.sender.seal(maximumPlaintext)
        XCTAssertEqual(
            record.encode().count,
            IrohaPeerNearbyV1.maximumMessageBytes + 54
        )
        XCTAssertLessThanOrEqual(record.encode().count, 32 * 1_024)
        XCTAssertEqual(try pair.receiver.open(record), maximumPlaintext)

        XCTAssertThrowsError(
            try pair.sender.seal(maximumPlaintext + Data([0]))
        ) {
            XCTAssertEqual($0 as? IrohaPeerNearbyErrorV1, .messageTooLarge)
        }
        XCTAssertThrowsError(try IrohaPeerNearbyEncryptedRecordV1(
            profile: .kagemushaWalletV1,
            senderRole: .sender,
            sessionID: Data(repeating: 0xA6, count: 16),
            sequence: 0,
            ciphertextAndTag: Data(
                repeating: 0xA7,
                count: IrohaPeerNearbyV1.maximumMessageBytes + 17
            )
        )) {
            XCTAssertEqual($0 as? IrohaPeerNearbyErrorV1, .messageTooLarge)
        }
    }

    func testEncryptedRecordsRejectReplayAndTampering() throws {
        let pair = try makeAuthenticatedPair()
        let record = try pair.sender.seal(Data("payment".utf8))
        XCTAssertEqual(try pair.receiver.open(record), Data("payment".utf8))
        XCTAssertThrowsError(try pair.receiver.open(record)) {
            XCTAssertEqual($0 as? IrohaPeerNearbyErrorV1, .replayOrReordering)
        }

        let secondPair = try makeAuthenticatedPair()
        let original = try secondPair.sender.seal(Data("payment".utf8))
        var bytes = original.encode()
        bytes[bytes.count - 1] ^= 0x01
        let tampered = try IrohaPeerNearbyEncryptedRecordV1.decode(bytes)
        XCTAssertThrowsError(try secondPair.receiver.open(tampered)) {
            XCTAssertEqual($0 as? IrohaPeerNearbyErrorV1, .authenticationFailed)
        }
    }

    func testHandshakeRejectsRequestAndRetiredProfileSubstitution() throws {
        let senderKey = Curve25519.Signing.PrivateKey()
        let receiverKey = Curve25519.Signing.PrivateKey()
        let sessionID = Data(repeating: 0x33, count: 16)
        let requestHash = Data(repeating: 0x44, count: 32)
        let sender = try IrohaPeerNearbySessionV1(
            profile: .kagemushaWalletV1,
            localRole: .sender,
            sessionID: sessionID,
            requestCanonicalHash: requestHash,
            deviceCertificate: senderKey.publicKey.rawRepresentation,
            nonce: Data(repeating: 0x51, count: 32)
        )
        let wrongRequestReceiver = try IrohaPeerNearbySessionV1(
            profile: .kagemushaWalletV1,
            localRole: .receiver,
            sessionID: sessionID,
            requestCanonicalHash: Data(repeating: 0x45, count: 32),
            deviceCertificate: receiverKey.publicKey.rawRepresentation,
            nonce: Data(repeating: 0x52, count: 32)
        )
        XCTAssertThrowsError(try sender.acceptPeerHello(wrongRequestReceiver.localHello)) {
            XCTAssertEqual($0 as? IrohaPeerNearbyErrorV1, .invalidRequest)
        }

        let validReceiver = try IrohaPeerNearbySessionV1(
            profile: .kagemushaWalletV1,
            localRole: .receiver,
            sessionID: sessionID,
            requestCanonicalHash: requestHash,
            deviceCertificate: receiverKey.publicKey.rawRepresentation,
            nonce: Data(repeating: 0x52, count: 32)
        )
        var retiredProfileHello = try validReceiver.localHello.encode()
        retiredProfileHello[6] = 0
        retiredProfileHello[7] = 0
        XCTAssertThrowsError(try IrohaPeerNearbyHelloV1.decode(retiredProfileHello)) {
            XCTAssertEqual($0 as? IrohaPeerNearbyErrorV1, .invalidProfile)
        }
        var unknownProfileHello = try validReceiver.localHello.encode()
        unknownProfileHello[6] = 0xFF
        unknownProfileHello[7] = 0xFF
        XCTAssertThrowsError(try IrohaPeerNearbyHelloV1.decode(unknownProfileHello)) {
            XCTAssertEqual($0 as? IrohaPeerNearbyErrorV1, .invalidProfile)
        }
    }

    func testHandshakeCannotEncryptBeforePeerCertificateAuthentication() throws {
        let signingKey = Curve25519.Signing.PrivateKey()
        let sender = try IrohaPeerNearbySessionV1(
            profile: .kagemushaWalletV1,
            localRole: .sender,
            sessionID: Data(repeating: 0x61, count: 16),
            requestCanonicalHash: Data(repeating: 0x62, count: 32),
            deviceCertificate: signingKey.publicKey.rawRepresentation,
            nonce: Data(repeating: 0x63, count: 32)
        )
        XCTAssertThrowsError(try sender.seal(Data("message".utf8))) {
            XCTAssertEqual($0 as? IrohaPeerNearbyErrorV1, .notAuthenticated)
        }
    }

    func testHelloAndAuthenticationReplayCannotResetEncryptedSequence() throws {
        let pair = try makeAuthenticatedPair()

        XCTAssertThrowsError(try pair.sender.acceptPeerHello(pair.receiver.localHello)) {
            XCTAssertEqual($0 as? IrohaPeerNearbyErrorV1, .replayOrReordering)
        }

        let first = try pair.sender.seal(Data("first".utf8))
        XCTAssertEqual(first.sequence, 0)
        XCTAssertEqual(try pair.receiver.open(first), Data("first".utf8))
        XCTAssertThrowsError(try pair.sender.acceptPeerAuthentication(
            pair.receiverAuthentication,
            verifier: pair.verifier
        )) {
            XCTAssertEqual($0 as? IrohaPeerNearbyErrorV1, .replayOrReordering)
        }

        let second = try pair.sender.seal(Data("second".utf8))
        XCTAssertEqual(second.sequence, 1)
        XCTAssertEqual(try pair.receiver.open(second), Data("second".utf8))
    }

    func testDestroyIsAliasSafeIdempotentAndRejectsEveryLaterOperation() throws {
        let pair = try makeAuthenticatedPair()
        let alias = pair.sender
        let inboundRecord = try pair.receiver.seal(Data("reply".utf8))

        pair.sender.destroy()
        alias.destroy()

        XCTAssertTrue(pair.sender.isDestroyed)
        XCTAssertTrue(alias.isDestroyed)
        XCTAssertFalse(pair.sender.isAuthenticated)

        XCTAssertThrowsError(try alias.localHello) {
            XCTAssertEqual($0 as? IrohaPeerNearbyErrorV1, .sessionDestroyed)
        }
        XCTAssertThrowsError(try alias.acceptPeerHello(pair.receiver.localHello)) {
            XCTAssertEqual($0 as? IrohaPeerNearbyErrorV1, .sessionDestroyed)
        }
        XCTAssertThrowsError(try alias.authenticationPreimage()) {
            XCTAssertEqual($0 as? IrohaPeerNearbyErrorV1, .sessionDestroyed)
        }
        XCTAssertThrowsError(try alias.makeAuthentication(signature: Data([0x01]))) {
            XCTAssertEqual($0 as? IrohaPeerNearbyErrorV1, .sessionDestroyed)
        }
        var verifierCalls = 0
        XCTAssertThrowsError(try alias.acceptPeerAuthentication(
            pair.receiverAuthentication,
            verifier: { _, _, _, _ in
                verifierCalls += 1
                return true
            }
        )) {
            XCTAssertEqual($0 as? IrohaPeerNearbyErrorV1, .sessionDestroyed)
        }
        XCTAssertEqual(verifierCalls, 0)
        XCTAssertThrowsError(try alias.seal(Data("message".utf8))) {
            XCTAssertEqual($0 as? IrohaPeerNearbyErrorV1, .sessionDestroyed)
        }
        XCTAssertThrowsError(try alias.open(inboundRecord)) {
            XCTAssertEqual($0 as? IrohaPeerNearbyErrorV1, .sessionDestroyed)
        }
    }

    func testConcurrentDestroyFromVerifierPreventsKeyDerivation() throws {
        let sessionID = Data(repeating: 0x75, count: 16)
        let requestHash = Data(repeating: 0x76, count: 32)
        let sender = try IrohaPeerNearbySessionV1(
            profile: .kagemushaWalletV1,
            localRole: .sender,
            sessionID: sessionID,
            requestCanonicalHash: requestHash,
            deviceCertificate: Data(repeating: 0x77, count: 32),
            nonce: Data(repeating: 0x78, count: 32)
        )
        let receiver = try IrohaPeerNearbySessionV1(
            profile: .kagemushaWalletV1,
            localRole: .receiver,
            sessionID: sessionID,
            requestCanonicalHash: requestHash,
            deviceCertificate: Data(repeating: 0x79, count: 32),
            nonce: Data(repeating: 0x7A, count: 32)
        )
        try sender.acceptPeerHello(receiver.localHello)
        try receiver.acceptPeerHello(sender.localHello)
        let receiverAuthentication = try receiver.makeAuthentication(
            signature: Data([0x7B])
        )
        var verifierCalls = 0

        XCTAssertThrowsError(try sender.acceptPeerAuthentication(
            receiverAuthentication,
            verifier: { _, _, _, _ in
                verifierCalls += 1
                let closed = DispatchSemaphore(value: 0)
                DispatchQueue.global().async {
                    sender.destroy()
                    closed.signal()
                }
                guard closed.wait(timeout: .now() + 2) == .success else {
                    XCTFail("Session destroy deadlocked behind verifier callback")
                    throw IrohaPeerNearbyErrorV1.cryptographicFailure
                }
                return true
            }
        )) {
            XCTAssertEqual($0 as? IrohaPeerNearbyErrorV1, .sessionDestroyed)
        }
        XCTAssertEqual(verifierCalls, 1)
        XCTAssertTrue(sender.isDestroyed)
        XCTAssertFalse(sender.isAuthenticated)
    }

    func testNearbyRecordDecodersRejectTruncationTrailingBytesAndForgedLengths() throws {
        let sessionID = Data(repeating: 0x81, count: 16)
        let requestHash = Data(repeating: 0x82, count: 32)
        let hello = try IrohaPeerNearbyHelloV1(
            profile: .kagemushaWalletV1,
            role: .sender,
            sessionID: sessionID,
            nonce: Data(repeating: 0x83, count: 32),
            requestCanonicalHash: requestHash,
            ephemeralPublicKey: fixedP256Key(scalar: 7).publicKey.x963Representation,
            deviceCertificate: Data(repeating: 0x84, count: 32)
        ).encode()
        let authentication = try IrohaPeerNearbyAuthenticationV1(
            profile: .kagemushaWalletV1,
            role: .sender,
            sessionID: sessionID,
            transcriptHash: Data(repeating: 0x85, count: 32),
            signature: Data(repeating: 0x86, count: 64)
        ).encode()
        let encrypted = try IrohaPeerNearbyEncryptedRecordV1(
            profile: .kagemushaWalletV1,
            senderRole: .sender,
            sessionID: sessionID,
            sequence: UInt64.max,
            ciphertextAndTag: Data(repeating: 0x87, count: 48)
        ).encode()
        let discovery = try IrohaPeerNearbyDiscoveryContextV1(
            profile: .kagemushaWalletV1,
            role: .receiver,
            sessionID: sessionID,
            requestCanonicalHash: requestHash
        ).encode()

        for cut in 0..<hello.count {
            XCTAssertThrowsError(
                try IrohaPeerNearbyHelloV1.decode(Data(hello.prefix(cut))),
                "Hello truncation at byte \(cut) must fail"
            )
        }
        for cut in 0..<authentication.count {
            XCTAssertThrowsError(
                try IrohaPeerNearbyAuthenticationV1.decode(Data(authentication.prefix(cut))),
                "Authentication truncation at byte \(cut) must fail"
            )
        }
        for cut in 0..<encrypted.count {
            XCTAssertThrowsError(
                try IrohaPeerNearbyEncryptedRecordV1.decode(Data(encrypted.prefix(cut))),
                "Encrypted-record truncation at byte \(cut) must fail"
            )
        }
        for cut in 0..<discovery.count {
            XCTAssertThrowsError(
                try IrohaPeerNearbyDiscoveryContextV1.decode(Data(discovery.prefix(cut))),
                "Discovery truncation at byte \(cut) must fail"
            )
        }

        XCTAssertThrowsError(try IrohaPeerNearbyHelloV1.decode(hello + Data([0])))
        XCTAssertThrowsError(try IrohaPeerNearbyAuthenticationV1.decode(authentication + Data([0])))
        XCTAssertThrowsError(try IrohaPeerNearbyEncryptedRecordV1.decode(encrypted + Data([0])))
        XCTAssertThrowsError(try IrohaPeerNearbyDiscoveryContextV1.decode(discovery + Data([0])))

        for publicKeyLength in [0, 64, 66, Int(UInt16.max)] {
            var forged = hello
            forged[90] = UInt8((publicKeyLength >> 8) & 0xff)
            forged[91] = UInt8(publicKeyLength & 0xff)
            XCTAssertThrowsError(try IrohaPeerNearbyHelloV1.decode(forged))
        }
        var zeroCertificate = hello
        zeroCertificate[157...160] = Data(repeating: 0, count: 4)
        XCTAssertThrowsError(try IrohaPeerNearbyHelloV1.decode(zeroCertificate))
        var oversizedCertificate = hello
        let excessiveCertificateLength = IrohaPeerNearbyV1.maximumCertificateBytes + 1
        oversizedCertificate[157] = UInt8((excessiveCertificateLength >> 24) & 0xff)
        oversizedCertificate[158] = UInt8((excessiveCertificateLength >> 16) & 0xff)
        oversizedCertificate[159] = UInt8((excessiveCertificateLength >> 8) & 0xff)
        oversizedCertificate[160] = UInt8(excessiveCertificateLength & 0xff)
        XCTAssertThrowsError(try IrohaPeerNearbyHelloV1.decode(oversizedCertificate))

        var zeroSignature = authentication
        zeroSignature[58] = 0
        zeroSignature[59] = 0
        XCTAssertThrowsError(try IrohaPeerNearbyAuthenticationV1.decode(zeroSignature))
        var forgedCiphertextLength = encrypted
        let excessiveCiphertextLength = IrohaPeerNearbyV1.maximumMessageBytes + 17
        forgedCiphertextLength[34] = UInt8((excessiveCiphertextLength >> 24) & 0xff)
        forgedCiphertextLength[35] = UInt8((excessiveCiphertextLength >> 16) & 0xff)
        forgedCiphertextLength[36] = UInt8((excessiveCiphertextLength >> 8) & 0xff)
        forgedCiphertextLength[37] = UInt8(excessiveCiphertextLength & 0xff)
        XCTAssertThrowsError(
            try IrohaPeerNearbyEncryptedRecordV1.decode(forgedCiphertextLength)
        )
    }

    func testSequenceExtremesRoundTripAndRejectedRecordsDoNotAdvanceState() throws {
        for sequence in [UInt64(0), UInt64.max / 2, UInt64.max / 2 + 1, UInt64.max] {
            let record = try IrohaPeerNearbyEncryptedRecordV1(
                profile: .kagemushaWalletV1,
                senderRole: .sender,
                sessionID: Data(repeating: 0x91, count: 16),
                sequence: sequence,
                ciphertextAndTag: Data(repeating: 0x92, count: 16)
            )
            XCTAssertEqual(try IrohaPeerNearbyEncryptedRecordV1.decode(record.encode()), record)
        }

        let reordered = try makeAuthenticatedPair()
        let first = try reordered.sender.seal(Data("first".utf8))
        let second = try reordered.sender.seal(Data("second".utf8))
        XCTAssertThrowsError(try reordered.receiver.open(second)) { error in
            XCTAssertEqual(error as? IrohaPeerNearbyErrorV1, .replayOrReordering)
        }
        XCTAssertEqual(try reordered.receiver.open(first), Data("first".utf8))
        XCTAssertEqual(try reordered.receiver.open(second), Data("second".utf8))

        let tampered = try makeAuthenticatedPair()
        let original = try tampered.sender.seal(Data("payment".utf8))
        var tamperedBytes = original.encode()
        tamperedBytes[tamperedBytes.count - 1] ^= 1
        let invalid = try IrohaPeerNearbyEncryptedRecordV1.decode(tamperedBytes)
        XCTAssertThrowsError(try tampered.receiver.open(invalid)) { error in
            XCTAssertEqual(error as? IrohaPeerNearbyErrorV1, .authenticationFailed)
        }
        XCTAssertEqual(try tampered.receiver.open(original), Data("payment".utf8))
    }

    private func makeAuthenticatedPair(
        requestHash: Data = Data(repeating: 0x72, count: 32)
    ) throws -> (
        sender: IrohaPeerNearbySessionV1,
        receiver: IrohaPeerNearbySessionV1,
        receiverAuthentication: IrohaPeerNearbyAuthenticationV1,
        verifier: IrohaPeerNearbySessionV1.SignatureVerifier
    ) {
        let senderSigningKey = Curve25519.Signing.PrivateKey()
        let receiverSigningKey = Curve25519.Signing.PrivateKey()
        let sessionID = Data(repeating: 0x71, count: 16)
        let sender = try IrohaPeerNearbySessionV1(
            profile: .kagemushaWalletV1,
            localRole: .sender,
            sessionID: sessionID,
            requestCanonicalHash: requestHash,
            deviceCertificate: senderSigningKey.publicKey.rawRepresentation,
            nonce: Data(repeating: 0x73, count: 32),
            ephemeralPrivateKey: P256.KeyAgreement.PrivateKey()
        )
        let receiver = try IrohaPeerNearbySessionV1(
            profile: .kagemushaWalletV1,
            localRole: .receiver,
            sessionID: sessionID,
            requestCanonicalHash: requestHash,
            deviceCertificate: receiverSigningKey.publicKey.rawRepresentation,
            nonce: Data(repeating: 0x74, count: 32),
            ephemeralPrivateKey: P256.KeyAgreement.PrivateKey()
        )
        try sender.acceptPeerHello(receiver.localHello)
        try receiver.acceptPeerHello(sender.localHello)
        let senderSignature = try senderSigningKey.signature(for: sender.authenticationPreimage())
        let receiverSignature = try receiverSigningKey.signature(for: receiver.authenticationPreimage())
        let senderAuthentication = try sender.makeAuthentication(signature: senderSignature)
        let receiverAuthentication = try receiver.makeAuthentication(signature: receiverSignature)

        let verifier: IrohaPeerNearbySessionV1.SignatureVerifier = {
            _, certificate, signedBytes, signature in
            let key = try Curve25519.Signing.PublicKey(rawRepresentation: certificate)
            return key.isValidSignature(signature, for: signedBytes)
        }
        try sender.acceptPeerAuthentication(receiverAuthentication, verifier: verifier)
        try receiver.acceptPeerAuthentication(senderAuthentication, verifier: verifier)
        XCTAssertTrue(sender.isAuthenticated)
        XCTAssertTrue(receiver.isAuthenticated)
        return (sender, receiver, receiverAuthentication, verifier)
    }

    private func fixedP256Key(
        scalar: UInt8
    ) throws -> P256.KeyAgreement.PrivateKey {
        try P256.KeyAgreement.PrivateKey(
            rawRepresentation: Data(repeating: 0, count: 31) + Data([scalar])
        )
    }
}
