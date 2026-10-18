import XCTest
@testable import IrohaSwift

/// NFC Offer intake and continuous Offer/Request/Payment/ACK exchanges,
/// the app-supplied application identifier and the byte-exact spec vectors that the
/// Kotlin SDK asserts too (`specs/kagemusha_wallet_wire_v1.md` §6).
final class IrohaPeerNfcOfferIntakeV1Tests: XCTestCase {
    private let bpng = try! IrohaPeerNfcApplicationIdentifierV1(hex: "F05047444B4E464301")
    private let policy = IrohaPeerNfcProfilePolicyV1(profile: .kagemushaWalletV1)
    private let s = Data(repeating: 0x11, count: 16)

    // MARK: Spec vectors

    func testCommandsAndRecordsMatchTheSharedSpecVectors() throws {
        let hr = Data(repeating: 0x22, count: 32)
        let wr = Data(repeating: 0x33, count: 32)
        let wp = Data(repeating: 0x44, count: 32)
        let wa = Data(repeating: 0x55, count: 32)
        let wo = Data(repeating: 0x66, count: 32)
        let offerHeader = ipm1Header(kind: 1, length: 600, canonicalHash: Data(repeating: 0x77, count: 32), wireHash: wo)
        let paymentHeader = ipm1Header(kind: 3, length: 9_000, canonicalHash: Data(repeating: 0x88, count: 32), wireHash: wp)
        let chunk200 = Data((0..<200).map { UInt8($0) })
        let chunk300 = Data((0..<300).map { UInt8(truncatingIfNeeded: $0 * 7) })
        let commands: [(String, IrohaPeerNfcCommandV1)] = [
            ("selectBpng", .selectApplication(bpng)),
            ("selectProtocol", .selectApplication(.protocolDefault)),
            ("getIntake", .getIntake),
            ("beginOffer", .beginOffer(sessionID: s, offerHeader: offerHeader)),
            ("writeOffer200", .writeOffer(sessionID: s, offerWireHash: wo, offset: 0, bytes: chunk200)),
            ("writeOffer300At400", .writeOffer(sessionID: s, offerWireHash: wo, offset: 400, bytes: chunk300)),
            ("submitOffer", .submitOffer(sessionID: s, offerWireHash: wo)),
            ("getInfo", .getInfo),
            ("readRequest240At0", .readRequest(sessionID: s, requestCanonicalHash: hr, offset: 0, length: 240)),
            ("readRequest4096At4096", .readRequest(sessionID: s, requestCanonicalHash: hr, offset: 4_096, length: 4_096)),
            ("beginPayment", .beginPayment(sessionID: s, requestCanonicalHash: hr, paymentHeader: paymentHeader)),
            ("write200At0", .write(sessionID: s, paymentWireHash: wp, offset: 0, bytes: chunk200)),
            ("write300At8700", .write(sessionID: s, paymentWireHash: wp, offset: 8_700, bytes: chunk300)),
            ("commit", .commit(sessionID: s, requestCanonicalHash: hr, paymentWireHash: wp)),
            ("readAcknowledgement256At512", .readAcknowledgement(sessionID: s, paymentWireHash: wp, offset: 512, length: 256)),
            ("confirmAcknowledgement", .confirmAcknowledgement(sessionID: s, paymentWireHash: wp, acknowledgementWireHash: wa)),
            ("getStatus", .getStatus(sessionID: s, requestCanonicalHash: hr)),
        ]
        for (name, command) in commands {
            let expected = try XCTUnwrap(Self.vectors[name], name)
            let encoded = try IrohaPeerNfcAPDUCodecV1.encode(command)
            XCTAssertEqual(hexString(encoded), expected, name)
            XCTAssertEqual(try IrohaPeerNfcAPDUCodecV1.decode(encoded), command, name)
        }

        let zero = Data(repeating: 0, count: 32)
        let records: [(String, Data)] = [
            ("ioi1Awaiting", try IrohaPeerNfcIntakeRecordV1(
                state: .awaitingOffer, profile: .kagemushaWalletV1, sessionID: s, offerLength: 0,
                receivedOfferBytes: 0, offerWireHash: zero, maximumWriteChunkBytes: 4_096, reason: 0).encode()),
            ("ioi1Receiving", try IrohaPeerNfcIntakeRecordV1(
                state: .receivingOffer, profile: .kagemushaWalletV1, sessionID: s, offerLength: 684,
                receivedOfferBytes: 200, offerWireHash: wo, maximumWriteChunkBytes: 4_096, reason: 0).encode()),
            ("ioi1Declined", try IrohaPeerNfcIntakeRecordV1(
                state: .declined, profile: .kagemushaWalletV1, sessionID: s, offerLength: 684,
                receivedOfferBytes: 684, offerWireHash: wo, maximumWriteChunkBytes: 4_096, reason: 7).encode()),
            ("inf1RequestReady", try IrohaPeerNfcInfoV1(
                phase: .requestReady, flags: [.idempotentWrites],
                identity: IrohaPeerNfcRequestIdentityV1(profile: .kagemushaWalletV1, sessionID: s,
                    requestCanonicalHash: hr, requestWireHash: wr),
                requestLength: 9_500, maximumReadChunkBytes: 4_096, maximumWriteChunkBytes: 4_096).encode()),
            ("nst1PaymentReceiving", try IrohaPeerNfcStatusV1(
                phase: .paymentReceiving, flags: [.idempotentWrites],
                identity: IrohaPeerNfcRequestIdentityV1(profile: .kagemushaWalletV1, sessionID: s,
                    requestCanonicalHash: hr, requestWireHash: wr),
                paymentProfile: .kagemushaWalletV1, paymentLength: 9_084, receivedPaymentBytes: 4_096,
                paymentWireHash: wp, acknowledgementProfile: nil, acknowledgementLength: 0,
                acknowledgementWireHash: zero, maximumReadChunkBytes: 4_096, maximumWriteChunkBytes: 4_096).encode()),
            ("nst1AcknowledgementReady", try IrohaPeerNfcStatusV1(
                phase: .acknowledgementReady, flags: [.idempotentWrites, .durableAcknowledgement],
                identity: IrohaPeerNfcRequestIdentityV1(profile: .kagemushaWalletV1, sessionID: s,
                    requestCanonicalHash: hr, requestWireHash: wr),
                paymentProfile: .kagemushaWalletV1, paymentLength: 9_084, receivedPaymentBytes: 9_084,
                paymentWireHash: wp, acknowledgementProfile: .kagemushaWalletV1, acknowledgementLength: 1_200,
                acknowledgementWireHash: wa, maximumReadChunkBytes: 4_096, maximumWriteChunkBytes: 4_096).encode()),
        ]
        for (name, encoded) in records {
            XCTAssertEqual(hexString(encoded), try XCTUnwrap(Self.vectors[name], name), name)
        }
        XCTAssertEqual(try IrohaPeerNfcIntakeRecordV1.decode(records[1].1).receivedOfferBytes, 200)
    }

    func testApplicationIdentifierIsFiveToSixteenStrictHexBytes() throws {
        XCTAssertEqual(bpng.hex, "F05047444B4E464301")
        XCTAssertEqual(try IrohaPeerNfcApplicationIdentifierV1(hex: "f05047444b4e464301"), bpng)
        for invalid in ["", "F0504", "F05047444B4E46430", "F0504744 4B4E464301", "+F5047444B4E464301",
                        String(repeating: "AB", count: 4), String(repeating: "AB", count: 17)] {
            XCTAssertThrowsError(try IrohaPeerNfcApplicationIdentifierV1(hex: invalid), invalid)
        }
        XCTAssertNoThrow(try IrohaPeerNfcApplicationIdentifierV1(Data(repeating: 0xF0, count: 5)))
        XCTAssertNoThrow(try IrohaPeerNfcApplicationIdentifierV1(Data(repeating: 0xF0, count: 16)))
        // SELECT carries any registered identifier; only the card's own is answered.
        var card = IrohaPeerNfcCardEndpointV1(
            applicationIdentifier: bpng,
            intake: try IrohaPeerNfcOfferIntakeV1(sessionID: s, profilePolicy: policy)
        )
        XCTAssertEqual(card.process(apdu: try IrohaPeerNfcAPDUCodecV1.encode(.selectApplication(bpng))).response.statusWord, .success)
        XCTAssertEqual(card.process(apdu: try IrohaPeerNfcAPDUCodecV1.encode(.selectApplication(.protocolDefault))).response.statusWord, .notFound)
    }

    // MARK: Card intake

    func testIntakeReplacesAnUnfinishedOfferAndBindsTheSubmittedOne() throws {
        let offer = try message(kind: .offer, byte: 0x51, count: 600)
        let other = try message(kind: .offer, byte: 0x52, count: 640)
        var card = IrohaPeerNfcCardEndpointV1(
            applicationIdentifier: bpng,
            intake: try IrohaPeerNfcOfferIntakeV1(sessionID: s, profilePolicy: policy)
        )
        XCTAssertEqual(try intake(&card).state, .awaitingOffer)
        // Request commands before the Request exists are refused, not answered.
        XCTAssertEqual(step(&card, .getInfo).response.statusWord, .conditionsNotSatisfied)
        XCTAssertEqual(step(&card, .writeOffer(sessionID: s, offerWireHash: other.wireHash, offset: 0,
            bytes: other.encoded.prefix(10))).response.statusWord, .conditionsNotSatisfied)

        XCTAssertEqual(step(&card, .beginOffer(sessionID: s, offerHeader: other.header.bytes)).response.statusWord, .success)
        XCTAssertEqual(step(&card, .writeOffer(sessionID: s, offerWireHash: other.wireHash, offset: 0,
            bytes: other.encoded.prefix(100))).response.statusWord, .success)
        XCTAssertEqual(try intake(&card).receivedOfferBytes, 100)
        // A different payer replaces the unfinished Offer before SUBMIT_OFFER.
        XCTAssertEqual(step(&card, .beginOffer(sessionID: s, offerHeader: offer.header.bytes)).response.statusWord, .success)
        var record = try intake(&card)
        XCTAssertEqual(record.state, .receivingOffer)
        XCTAssertEqual(record.offerWireHash, offer.wireHash)
        XCTAssertEqual(record.receivedOfferBytes, 0)
        XCTAssertEqual(record.offerLength, offer.encoded.count)
        // The same BEGIN keeps progress; overlapping writes must be byte-identical.
        XCTAssertEqual(step(&card, .writeOffer(sessionID: s, offerWireHash: offer.wireHash, offset: 0,
            bytes: offer.encoded.prefix(300))).response.statusWord, .success)
        XCTAssertEqual(step(&card, .beginOffer(sessionID: s, offerHeader: offer.header.bytes)).response.statusWord, .success)
        XCTAssertEqual(try intake(&card).receivedOfferBytes, 300)
        var tampered = offer.encoded.subdata(in: 200..<400)
        tampered[0] ^= 0xFF
        XCTAssertEqual(step(&card, .writeOffer(sessionID: s, offerWireHash: offer.wireHash, offset: 200,
            bytes: tampered)).response.statusWord, .conditionsNotSatisfied)
        XCTAssertEqual(step(&card, .writeOffer(sessionID: s, offerWireHash: offer.wireHash, offset: 301,
            bytes: Data([0]))).response.statusWord, .wrongData)
        XCTAssertEqual(step(&card, .submitOffer(sessionID: s, offerWireHash: offer.wireHash)).response.statusWord,
            .conditionsNotSatisfied, "SUBMIT needs every byte")
        XCTAssertEqual(step(&card, .writeOffer(sessionID: s, offerWireHash: offer.wireHash, offset: 200,
            bytes: offer.encoded.subdata(in: 200..<offer.encoded.count))).response.statusWord, .success)
        let submitted = step(&card, .submitOffer(sessionID: s, offerWireHash: offer.wireHash))
        XCTAssertEqual(submitted.response.statusWord, .success)
        XCTAssertEqual(submitted.submittedOffer, offer)
        XCTAssertEqual(try intake(&card).state, .preparingRequest)

        // Bound: the same Offer is idempotent and never resubmitted; another is refused.
        let replay = step(&card, .submitOffer(sessionID: s, offerWireHash: offer.wireHash))
        XCTAssertEqual(replay.response.statusWord, .success)
        XCTAssertNil(replay.submittedOffer)
        XCTAssertEqual(step(&card, .beginOffer(sessionID: s, offerHeader: other.header.bytes)).response.statusWord, .conditionsNotSatisfied)
        XCTAssertEqual(step(&card, .getInfo).response.statusWord, .conditionsNotSatisfied)

        let request = try message(kind: .request, byte: 0x53, count: 700)
        let identity = try card.installRequest(request.encoded)
        XCTAssertEqual(identity.sessionID, s)
        record = try intake(&card)
        XCTAssertEqual(record.state, .requestReady)
        XCTAssertEqual(record.offerWireHash, offer.wireHash)
        let info = try IrohaPeerNfcInfoV1.decode(step(&card, .getInfo).response.data)
        XCTAssertEqual(info.identity.sessionID, s)
        XCTAssertEqual(info.identity.requestCanonicalHash, request.canonicalHash)
        XCTAssertThrowsError(try card.installRequest(request.encoded))
    }

    func testCorruptOfferIsNeverBoundAndDeclineCarriesItsReason() throws {
        let offer = try message(kind: .offer, byte: 0x61, count: 500)
        var card = IrohaPeerNfcCardEndpointV1(
            applicationIdentifier: bpng,
            intake: try IrohaPeerNfcOfferIntakeV1(sessionID: s, profilePolicy: policy)
        )
        var corrupt = offer.encoded
        corrupt[corrupt.count - 1] ^= 0x01
        XCTAssertEqual(step(&card, .beginOffer(sessionID: s, offerHeader: offer.header.bytes)).response.statusWord, .success)
        XCTAssertEqual(step(&card, .writeOffer(sessionID: s, offerWireHash: offer.wireHash, offset: 0,
            bytes: corrupt)).response.statusWord, .success)
        let rejected = step(&card, .submitOffer(sessionID: s, offerWireHash: offer.wireHash))
        XCTAssertEqual(rejected.response.statusWord, .securityStatusNotSatisfied)
        XCTAssertNil(rejected.submittedOffer)
        XCTAssertEqual(try intake(&card).state, .awaitingOffer)

        XCTAssertEqual(step(&card, .beginOffer(sessionID: s, offerHeader: offer.header.bytes)).response.statusWord, .success)
        XCTAssertEqual(step(&card, .writeOffer(sessionID: s, offerWireHash: offer.wireHash, offset: 0,
            bytes: offer.encoded)).response.statusWord, .success)
        XCTAssertEqual(step(&card, .submitOffer(sessionID: s, offerWireHash: offer.wireHash)).submittedOffer, offer)
        XCTAssertThrowsError(try card.decline(reason: 0))
        try card.decline(reason: 7)
        let record = try intake(&card)
        XCTAssertEqual(record.state, .declined)
        XCTAssertEqual(record.reason, 7)
        XCTAssertEqual(hexString(record.encode()).prefix(12), "494F49310105")
        XCTAssertEqual(step(&card, .getInfo).response.statusWord, .conditionsNotSatisfied)
    }

    func testHostedRequestAnswersIntakeAsReadyWithoutAnOffer() throws {
        let request = try message(kind: .request, byte: 0x71, count: 400)
        let receiver = try IrohaPeerNfcReceiverSessionV1(
            sessionID: s, receiveRequest: request.encoded, applicationIdentifier: bpng)
        var card = IrohaPeerNfcCardEndpointV1(receiver: receiver)
        let record = try intake(&card)
        XCTAssertEqual(record.state, .requestReady)
        XCTAssertEqual(record.offerLength, 0)
        XCTAssertEqual(record.offerWireHash, Data(repeating: 0, count: 32))
        let offer = try message(kind: .offer, byte: 0x72, count: 300)
        XCTAssertEqual(step(&card, .beginOffer(sessionID: s, offerHeader: offer.header.bytes)).response.statusWord,
            .conditionsNotSatisfied)
    }

    // MARK: Continuous hold and interrupted-contact recovery

    func testOneHoldCarriesOfferRequestPaymentAndDurableAcknowledgement() async throws {
        let limits = IrohaPeerNfcLimitsV1(maximumReadChunkBytes: 240, maximumWriteChunkBytes: 240)
        let offer = try message(kind: .offer, byte: 0x81, count: 900)
        let request = try message(kind: .request, byte: 0x82, count: 1_200)
        let payment = try message(kind: .payment, byte: 0x83, count: 1_500)
        let credited = try message(kind: .credited, byte: 0x84, count: 300)
        let policy = self.policy
        let card = try IrohaPeerNfcIntakeCardV1(
            applicationIdentifier: bpng, limits: limits, request: request, credited: credited,
            preparationPolls: 3)
        let persisted = IrohaPeerNfcPersistedDataV1()

        let result = try await IrohaPeerNfcReaderExchangeV1.run(
            offer: offer, applicationIdentifier: bpng, profilePolicy: policy, limits: limits,
            transceive: { command in
                if case .beginPayment = command {
                    XCTAssertEqual(persisted.values.count, 1, "Payment must already be durable")
                }
                if case .confirmAcknowledgement = command {
                    XCTAssertEqual(persisted.values.count, 2, "ACK must already be durable")
                }
                return try await card.transceive(command)
            },
            sleep: { _ in },
            loadOrCreateDurableCheckpoint: { info, received in
                XCTAssertEqual(received, request)
                let commands = await card.commands
                XCTAssertFalse(commands.contains { $0.operation == .beginPayment })
                let checkpoint = try IrohaPeerNfcSenderCheckpointV1(
                    sessionID: info.identity.sessionID, receiveRequest: received.encoded,
                    payment: payment.encoded, profilePolicy: policy, limits: limits)
                persisted.append(checkpoint.encoded)
                return checkpoint
            },
            updateDurableCheckpoint: { persisted.append($0) })

        XCTAssertEqual(result.acknowledgement, credited)
        XCTAssertEqual(result.confirmationState, .confirmed)
        let commands = await card.commands
        XCTAssertEqual(commands.filter { $0.operation == .selectApplication }.count, 1)
        XCTAssertEqual(commands.filter { $0.operation == .getInfo }.count, 1)
        XCTAssertEqual(commands.filter { $0.operation == .readRequest }.count,
            (request.encoded.count + 239) / 240, "Request is read only once")
        let commits = await card.durableCommits
        XCTAssertEqual(commits, 1)
    }

    /// Receiver-led one hold: the card's ask, the Offer the factory builds for it, the Request, the approval inside
    /// `loadOrCreateDurableCheckpoint`, the Payment and the ACK all travel over ONE contact, and the factory runs once.
    func testOneHoldFromAskBuildsTheOfferOnceAndCarriesTheWholePaymentOverOneContact() async throws {
        let limits = IrohaPeerNfcLimitsV1(maximumReadChunkBytes: 240, maximumWriteChunkBytes: 240)
        let ask = try sampleAsk()
        let offer = try message(kind: .offer, byte: 0xB1, count: 900)
        let request = try message(kind: .request, byte: 0xB2, count: 1_200)
        let payment = try message(kind: .payment, byte: 0xB3, count: 1_500)
        let credited = try message(kind: .credited, byte: 0xB4, count: 300)
        let policy = self.policy
        let card = try IrohaPeerNfcIntakeCardV1(
            applicationIdentifier: bpng, limits: limits, request: request, credited: credited,
            preparationPolls: 3, ask: ask)
        let factory = IrohaPeerNfcOfferFactoryRecorderV1(offer: offer)
        let persisted = IrohaPeerNfcPersistedDataV1()

        let result = try await IrohaPeerNfcReaderExchangeV1.run(
            offerFactory: { try await factory.offer(for: $0) },
            applicationIdentifier: bpng, profilePolicy: policy, limits: limits,
            transceive: { command in
                if case .beginPayment = command {
                    XCTAssertEqual(persisted.values.count, 1, "Payment must already be durable")
                }
                return try await card.transceive(command)
            },
            sleep: { _ in },
            loadOrCreateDurableCheckpoint: { info, received in
                XCTAssertEqual(received, request)
                let commands = await card.commands
                XCTAssertTrue(commands.contains { $0.operation == .getAsk }, "the ask was read before the Offer existed")
                XCTAssertFalse(commands.contains { $0.operation == .beginPayment })
                let checkpoint = try IrohaPeerNfcSenderCheckpointV1(
                    sessionID: info.identity.sessionID, receiveRequest: received.encoded,
                    payment: payment.encoded, profilePolicy: policy, limits: limits)
                persisted.append(checkpoint.encoded)
                return checkpoint
            },
            updateDurableCheckpoint: { persisted.append($0) })

        XCTAssertEqual(result.acknowledgement, credited)
        XCTAssertEqual(result.confirmationState, .confirmed)
        let asks = await factory.asks
        XCTAssertEqual(asks, [ask], "the factory ran exactly once, for the card's ask")
        let commands = await card.commands
        XCTAssertEqual(commands.filter { $0.operation == .selectApplication }.count, 1, "one contact")
        XCTAssertEqual(commands.filter { $0.operation == .getAsk }.count, 1)
        XCTAssertEqual(commands.filter { $0.operation == .getInfo }.count, 1)
        let commits = await card.durableCommits
        XCTAssertEqual(commits, 1)
        let preparedOffers = await card.preparedOffers
        XCTAssertEqual(preparedOffers, [offer])
    }

    /// A restored checkpoint means the Payment exists: the ask-led entry skips Offer intake and never calls the factory.
    func testOneHoldFromAskWithARestoredCheckpointNeverAsksOrBuildsAnOffer() async throws {
        let limits = IrohaPeerNfcLimitsV1(maximumReadChunkBytes: 240, maximumWriteChunkBytes: 240)
        let ask = try sampleAsk()
        let offer = try message(kind: .offer, byte: 0xB5, count: 700)
        let request = try message(kind: .request, byte: 0xB6, count: 600)
        let payment = try message(kind: .payment, byte: 0xB7, count: 800)
        let credited = try message(kind: .credited, byte: 0xB8, count: 200)
        let policy = self.policy
        let card = try IrohaPeerNfcIntakeCardV1(
            applicationIdentifier: bpng, limits: limits, request: request, credited: credited,
            preparationPolls: 1, ask: ask)
        // The first contact reached the Request, then stopped before the Payment was delivered.
        let first = IrohaPeerNfcOfferFactoryRecorderV1(offer: offer)
        let read = try await IrohaPeerNfcOfferExchangeV1.runFromAsk(
            offerFactory: { try await first.offer(for: $0) }, applicationIdentifier: bpng,
            profilePolicy: policy, limits: limits, transceive: { try await card.transceive($0) },
            sleep: { _ in })
        let checkpoint = try IrohaPeerNfcSenderCheckpointV1(
            sessionID: read.info.identity.sessionID, receiveRequest: read.request.encoded,
            payment: payment.encoded, profilePolicy: policy, limits: limits)

        let second = IrohaPeerNfcOfferFactoryRecorderV1(offer: offer)
        let persisted = IrohaPeerNfcPersistedDataV1()
        let before = await card.commands.count
        let result = try await IrohaPeerNfcReaderExchangeV1.run(
            offerFactory: { try await second.offer(for: $0) }, restoredCheckpoint: checkpoint.encoded,
            applicationIdentifier: bpng, profilePolicy: policy, limits: limits,
            transceive: { try await card.transceive($0) }, sleep: { _ in },
            loadOrCreateDurableCheckpoint: { _, _ in throw IrohaPeerNfcErrorV1.stateMismatch },
            updateDurableCheckpoint: { persisted.append($0) })
        XCTAssertEqual(result.acknowledgement, credited)
        let asks = await second.asks
        XCTAssertEqual(asks, [], "recovery never asks and never builds another Offer")
        let operations = await card.commands.dropFirst(before).map(\.operation)
        XCTAssertFalse(operations.contains(.getAsk))
        XCTAssertFalse(operations.contains(.beginOffer))
    }

    func testOneHoldApprovalCancellationNeverBeginsPayment() async throws {
        let offer = try message(kind: .offer, byte: 0x81, count: 100)
        let request = try message(kind: .request, byte: 0x82, count: 100)
        let credited = try message(kind: .credited, byte: 0x84, count: 100)
        let card = try IrohaPeerNfcIntakeCardV1(
            applicationIdentifier: bpng, limits: .default, request: request, credited: credited,
            preparationPolls: 0)
        do {
            _ = try await IrohaPeerNfcReaderExchangeV1.run(
                offer: offer, applicationIdentifier: bpng, profilePolicy: policy,
                transceive: { try await card.transceive($0) }, sleep: { _ in },
                loadOrCreateDurableCheckpoint: { _, _ in throw CancellationError() },
                updateDurableCheckpoint: { _ in XCTFail("no ACK after cancelled approval") })
            XCTFail("approval was cancelled")
        } catch is CancellationError {}
        let commands = await card.commands
        XCTAssertFalse(commands.contains { $0.operation == .beginPayment })
        XCTAssertFalse(commands.contains { $0.operation == .commit })
    }

    func testOneHoldRejectsCheckpointBoundToAnotherRequestBeforePayment() async throws {
        let offer = try message(kind: .offer, byte: 0x81, count: 100)
        let request = try message(kind: .request, byte: 0x82, count: 100)
        let otherRequest = try message(kind: .request, byte: 0x85, count: 120)
        let payment = try message(kind: .payment, byte: 0x83, count: 100)
        let credited = try message(kind: .credited, byte: 0x84, count: 100)
        let policy = self.policy
        let card = try IrohaPeerNfcIntakeCardV1(
            applicationIdentifier: bpng, limits: .default, request: request, credited: credited,
            preparationPolls: 0)
        do {
            _ = try await IrohaPeerNfcReaderExchangeV1.run(
                offer: offer, applicationIdentifier: bpng, profilePolicy: policy,
                transceive: { try await card.transceive($0) }, sleep: { _ in },
                loadOrCreateDurableCheckpoint: { info, _ in
                    try IrohaPeerNfcSenderCheckpointV1(
                        sessionID: info.identity.sessionID, receiveRequest: otherRequest.encoded,
                        payment: payment.encoded, profilePolicy: policy)
                },
                updateDurableCheckpoint: { _ in XCTFail("no ACK for a mismatched Request") })
            XCTFail("a checkpoint must match this hold's exact Request")
        } catch IrohaPeerNfcErrorV1.continuityMismatch {}
        let commands = await card.commands
        XCTAssertFalse(commands.contains { $0.operation == .beginPayment })
    }

    func testCancelledApprovalTaskRetainsCheckpointWithoutSendingPayment() async throws {
        let offer = try message(kind: .offer, byte: 0x81, count: 100)
        let request = try message(kind: .request, byte: 0x82, count: 100)
        let payment = try message(kind: .payment, byte: 0x83, count: 100)
        let credited = try message(kind: .credited, byte: 0x84, count: 100)
        let policy = self.policy
        let applicationIdentifier = bpng
        let card = try IrohaPeerNfcIntakeCardV1(
            applicationIdentifier: bpng, limits: .default, request: request, credited: credited,
            preparationPolls: 0)
        let persisted = IrohaPeerNfcPersistedDataV1()
        let operation = Task {
            try await IrohaPeerNfcReaderExchangeV1.run(
                offer: offer, applicationIdentifier: applicationIdentifier, profilePolicy: policy,
                transceive: { try await card.transceive($0) }, sleep: { _ in },
                loadOrCreateDurableCheckpoint: { info, received in
                    let checkpoint = try IrohaPeerNfcSenderCheckpointV1(
                        sessionID: info.identity.sessionID, receiveRequest: received.encoded,
                        payment: payment.encoded, profilePolicy: policy)
                    persisted.append(checkpoint.encoded)
                    // A platform deadline can cancel the task while a wallet
                    // callback finishes an already-started durable transition.
                    withUnsafeCurrentTask { $0?.cancel() }
                    return checkpoint
                },
                updateDurableCheckpoint: { _ in XCTFail("cancelled operation cannot accept ACK") })
        }
        do {
            _ = try await operation.value
            XCTFail("the cancelled operation must stop after persistence")
        } catch is CancellationError {}
        XCTAssertEqual(persisted.values.count, 1, "exact recovery bytes remain durable")
        let commands = await card.commands
        XCTAssertFalse(commands.contains { $0.operation == .beginPayment })
    }

    func testInterruptedOneHoldResumesExactPaymentWithoutNewOfferOrDebit() async throws {
        let limits = IrohaPeerNfcLimitsV1(maximumReadChunkBytes: 240, maximumWriteChunkBytes: 240)
        let offer = try message(kind: .offer, byte: 0x81, count: 300)
        let request = try message(kind: .request, byte: 0x82, count: 300)
        let payment = try message(kind: .payment, byte: 0x83, count: 1_500)
        let credited = try message(kind: .credited, byte: 0x84, count: 300)
        let policy = self.policy
        let card = try IrohaPeerNfcIntakeCardV1(
            applicationIdentifier: bpng, limits: limits, request: request, credited: credited,
            preparationPolls: 0, dropAfterPaymentWrites: 2)
        let persisted = IrohaPeerNfcPersistedDataV1()
        do {
            _ = try await IrohaPeerNfcReaderExchangeV1.run(
                offer: offer, applicationIdentifier: bpng, profilePolicy: policy, limits: limits,
                transceive: { try await card.transceive($0) }, sleep: { _ in },
                loadOrCreateDurableCheckpoint: { info, received in
                    let checkpoint = try IrohaPeerNfcSenderCheckpointV1(
                        sessionID: info.identity.sessionID, receiveRequest: received.encoded,
                        payment: payment.encoded, profilePolicy: policy, limits: limits)
                    persisted.append(checkpoint.encoded)
                    return checkpoint
                },
                updateDurableCheckpoint: { persisted.append($0) })
            XCTFail("contact must be interrupted")
        } catch is IrohaPeerNfcContactLostV1 {}
        XCTAssertEqual(persisted.values.count, 1)
        let commandsBeforeRetry = await card.commands.count
        let result = try await IrohaPeerNfcReaderExchangeV1.run(
            offer: offer, restoredCheckpoint: try XCTUnwrap(persisted.values.first),
            applicationIdentifier: bpng, profilePolicy: policy, limits: limits,
            transceive: { try await card.transceive($0) }, sleep: { _ in },
            loadOrCreateDurableCheckpoint: { _, _ in
                XCTFail("retry must never debit again")
                throw IrohaPeerNfcErrorV1.stateMismatch
            },
            updateDurableCheckpoint: { persisted.append($0) })
        XCTAssertEqual(result.checkpoint.payment, payment)
        XCTAssertEqual(result.acknowledgement, credited)
        let retryCommands = await Array(card.commands.dropFirst(commandsBeforeRetry))
        XCTAssertFalse(retryCommands.contains { $0.operation == .getIntake })
        XCTAssertFalse(retryCommands.contains { $0.operation == .readRequest })
        let writes = retryCommands.compactMap { command -> UInt32? in
            guard case .write(_, _, let offset, let bytes) = command else { return nil }
            XCTAssertEqual(bytes, payment.encoded.subdata(in: Int(offset)..<(Int(offset) + bytes.count)))
            return offset
        }
        XCTAssertEqual(writes.first, 480)
        XCTAssertEqual(persisted.values.count, 2)
    }

    func testReadOnlyRequestCanResumeFromADurablePaymentCheckpoint() async throws {
        let limits = IrohaPeerNfcLimitsV1(maximumReadChunkBytes: 240, maximumWriteChunkBytes: 240)
        let offer = try message(kind: .offer, byte: 0x81, count: 900)
        let request = try message(kind: .request, byte: 0x82, count: 1_200)
        let payment = try message(kind: .payment, byte: 0x83, count: 1_500)
        let credited = try message(kind: .credited, byte: 0x84, count: 300)
        let card = try IrohaPeerNfcIntakeCardV1(
            applicationIdentifier: bpng, limits: limits, request: request, credited: credited,
            preparationPolls: 3)
        let delivered = IrohaPeerNfcFlagV1()

        let read = try await IrohaPeerNfcOfferExchangeV1.run(
            offer: offer, applicationIdentifier: bpng, profilePolicy: policy, limits: limits,
            transceive: { try await card.transceive($0) }, sleep: { _ in },
            onOfferDelivered: { delivered.set() })
        XCTAssertTrue(delivered.isSet)
        XCTAssertEqual(read.request, request)
        XCTAssertEqual(read.intake.state, .requestReady)
        let preparedOffers = await card.preparedOffers
        XCTAssertEqual(preparedOffers, [offer])

        // If contact stopped after reading the Request, resume only the exact
        // durable Payment. Recovery never invokes the value-creation callback.
        let checkpoint = try IrohaPeerNfcSenderCheckpointV1(
            sessionID: read.info.identity.sessionID, receiveRequest: read.request.encoded,
            payment: payment.encoded, profilePolicy: policy, limits: limits)
        let persisted = IrohaPeerNfcPersistedDataV1()
        let result = try await IrohaPeerNfcReaderExchangeV1.run(
            restoredCheckpoint: checkpoint.encoded, applicationIdentifier: bpng, profilePolicy: policy,
            limits: limits, transceive: { try await card.transceive($0) },
            loadOrCreateDurableCheckpoint: { _, _ in throw IrohaPeerNfcErrorV1.stateMismatch },
            updateDurableCheckpoint: { persisted.append($0) })
        XCTAssertEqual(result.acknowledgement, credited)
        XCTAssertEqual(result.confirmationState, .confirmed)
        XCTAssertEqual(persisted.values.count, 1)
        let commits = await card.durableCommits
        XCTAssertEqual(commits, 1)
    }

    func testOfferIntakeResumesInterruptedOfferAndReportsDeclineAndTimeout() async throws {
        let limits = IrohaPeerNfcLimitsV1(maximumReadChunkBytes: 240, maximumWriteChunkBytes: 240)
        let offer = try message(kind: .offer, byte: 0x91, count: 1_000)
        let request = try message(kind: .request, byte: 0x92, count: 600)
        let credited = try message(kind: .credited, byte: 0x93, count: 200)

        let card = try IrohaPeerNfcIntakeCardV1(
            applicationIdentifier: bpng, limits: limits, request: request, credited: credited,
            preparationPolls: 1, dropAfterOfferWrites: 2)
        do {
            _ = try await IrohaPeerNfcOfferExchangeV1.run(
                offer: offer, applicationIdentifier: bpng, profilePolicy: policy, limits: limits,
                transceive: { try await card.transceive($0) }, sleep: { _ in })
            XCTFail("the first contact is lost mid-Offer")
        } catch is IrohaPeerNfcContactLostV1 {}
        let resumed = try await IrohaPeerNfcOfferExchangeV1.run(
            offer: offer, applicationIdentifier: bpng, profilePolicy: policy, limits: limits,
            transceive: { try await card.transceive($0) }, sleep: { _ in })
        XCTAssertEqual(resumed.request, request)
        let writes = await card.offerWriteLog
        XCTAssertEqual(Array(writes.prefix(3)), ["1:0", "1:240", "2:480"],
            "the second contact resumes at the received offset")

        let declining = try IrohaPeerNfcIntakeCardV1(
            applicationIdentifier: bpng, limits: limits, request: request, credited: credited,
            preparationPolls: 1, declineReason: 9)
        do {
            _ = try await IrohaPeerNfcOfferExchangeV1.run(
                offer: offer, applicationIdentifier: bpng, profilePolicy: policy, limits: limits,
                transceive: { try await declining.transceive($0) }, sleep: { _ in })
            XCTFail("declined")
        } catch IrohaPeerNfcErrorV1.offerDeclined(let reason) {
            XCTAssertEqual(reason, 9)
        }

        let slow = try IrohaPeerNfcIntakeCardV1(
            applicationIdentifier: bpng, limits: limits, request: request, credited: credited,
            preparationPolls: 1_000)
        do {
            _ = try await IrohaPeerNfcOfferExchangeV1.run(
                offer: offer, applicationIdentifier: bpng, profilePolicy: policy, limits: limits,
                preparationTimeoutMilliseconds: 500, pollIntervalMilliseconds: 50,
                transceive: { try await slow.transceive($0) }, sleep: { _ in })
            XCTFail("timed out")
        } catch IrohaPeerNfcErrorV1.requestPreparationTimedOut {}

        let wrongCard = try IrohaPeerNfcIntakeCardV1(
            applicationIdentifier: .protocolDefault, limits: limits, request: request, credited: credited,
            preparationPolls: 1)
        do {
            _ = try await IrohaPeerNfcOfferExchangeV1.run(
                offer: offer, applicationIdentifier: bpng, profilePolicy: policy, limits: limits,
                transceive: { try await wrongCard.transceive($0) }, sleep: { _ in })
            XCTFail("another application's card")
        } catch IrohaPeerNfcErrorV1.invalidApplicationIdentifier {}
    }

    // MARK: Receiver's ask (GET_ASK)

    func testCardAnswersItsAskOnlyBeforeTheOfferIsBound() throws {
        let ask = try sampleAsk()
        let offer = try message(kind: .offer, byte: 0xA1, count: 600)
        var card = IrohaPeerNfcCardEndpointV1(
            applicationIdentifier: bpng,
            intake: try IrohaPeerNfcOfferIntakeV1(sessionID: s, profilePolicy: policy, ask: ask)
        )
        let awaiting = try intake(&card)
        for _ in 0..<2 {
            let answer = step(&card, .getAsk).response
            XCTAssertEqual(answer.statusWord, .success)
            XCTAssertEqual(answer.data, ask.encode())
            XCTAssertEqual(try IrohaPeerAskV1.decode(answer.data), ask)
        }
        XCTAssertEqual(try intake(&card), awaiting, "GET_ASK changes nothing")
        XCTAssertEqual(step(&card, .beginOffer(sessionID: s, offerHeader: offer.header.bytes)).response.statusWord, .success)
        XCTAssertEqual(step(&card, .getAsk).response.data, ask.encode(), "still answered while receiving")
        XCTAssertEqual(try intake(&card).state, .receivingOffer)
        XCTAssertEqual(step(&card, .writeOffer(sessionID: s, offerWireHash: offer.wireHash, offset: 0,
            bytes: offer.encoded)).response.statusWord, .success)
        XCTAssertEqual(step(&card, .submitOffer(sessionID: s, offerWireHash: offer.wireHash)).submittedOffer, offer)
        // Bound to that Offer: preparing, ready and declined intakes hand out no ask.
        XCTAssertEqual(step(&card, .getAsk).response.statusWord, .conditionsNotSatisfied)
        XCTAssertEqual(try intake(&card).state, .preparingRequest)
        try card.installRequest(try message(kind: .request, byte: 0xA2, count: 500).encoded)
        XCTAssertEqual(step(&card, .getAsk).response.statusWord, .conditionsNotSatisfied)
        XCTAssertEqual(try intake(&card).state, .requestReady)

        var declining = IrohaPeerNfcCardEndpointV1(
            applicationIdentifier: bpng,
            intake: try IrohaPeerNfcOfferIntakeV1(sessionID: s, profilePolicy: policy, ask: ask)
        )
        XCTAssertEqual(step(&declining, .beginOffer(sessionID: s, offerHeader: offer.header.bytes)).response.statusWord, .success)
        XCTAssertEqual(step(&declining, .writeOffer(sessionID: s, offerWireHash: offer.wireHash, offset: 0,
            bytes: offer.encoded)).response.statusWord, .success)
        XCTAssertEqual(step(&declining, .submitOffer(sessionID: s, offerWireHash: offer.wireHash)).submittedOffer, offer)
        try declining.decline(reason: 3)
        XCTAssertEqual(step(&declining, .getAsk).response.statusWord, .conditionsNotSatisfied)
        XCTAssertEqual(try intake(&declining).state, .declined)

        // A corrupt Offer is never bound, so the card answers its ask again.
        var resetting = IrohaPeerNfcCardEndpointV1(
            applicationIdentifier: bpng,
            intake: try IrohaPeerNfcOfferIntakeV1(sessionID: s, profilePolicy: policy, ask: ask)
        )
        var corrupt = offer.encoded
        corrupt[corrupt.count - 1] ^= 0x01
        XCTAssertEqual(step(&resetting, .beginOffer(sessionID: s, offerHeader: offer.header.bytes)).response.statusWord, .success)
        XCTAssertEqual(step(&resetting, .writeOffer(sessionID: s, offerWireHash: offer.wireHash, offset: 0,
            bytes: corrupt)).response.statusWord, .success)
        XCTAssertEqual(step(&resetting, .submitOffer(sessionID: s, offerWireHash: offer.wireHash)).response.statusWord,
            .securityStatusNotSatisfied)
        XCTAssertEqual(try intake(&resetting).state, .awaitingOffer)
        XCTAssertEqual(step(&resetting, .getAsk).response.data, ask.encode())
    }

    func testCardsWithoutAnAskOrHostingARequestRefuseGetAsk() throws {
        var plain = IrohaPeerNfcCardEndpointV1(
            applicationIdentifier: bpng,
            intake: try IrohaPeerNfcOfferIntakeV1(sessionID: s, profilePolicy: policy)
        )
        XCTAssertNil(plain.intake?.ask)
        XCTAssertEqual(step(&plain, .getAsk).response.statusWord, .conditionsNotSatisfied)
        XCTAssertEqual(try intake(&plain).state, .awaitingOffer)

        let request = try message(kind: .request, byte: 0xA3, count: 400)
        var hosted = IrohaPeerNfcCardEndpointV1(receiver: try IrohaPeerNfcReceiverSessionV1(
            sessionID: s, receiveRequest: request.encoded, applicationIdentifier: bpng))
        XCTAssertEqual(step(&hosted, .getAsk).response.statusWord, .conditionsNotSatisfied)
        var receiver = try IrohaPeerNfcReceiverSessionV1(sessionID: s, receiveRequest: request.encoded)
        XCTAssertThrowsError(try receiver.handle(.getAsk)) {
            XCTAssertEqual($0 as? IrohaPeerNfcErrorV1, .stateMismatch)
        }
        XCTAssertEqual(receiver.process(apdu: try IrohaPeerNfcAPDUCodecV1.encode(.getAsk)).statusWord,
            .conditionsNotSatisfied)

        // The endpoint factory arms a fresh-session intake, with or without an ask.
        let ask = try sampleAsk()
        var armed = try IrohaPeerNfcCardEndpointV1.intake(
            applicationIdentifier: bpng, profilePolicy: policy, ask: ask)
        XCTAssertEqual(armed.intake?.ask, ask)
        XCTAssertEqual(armed.sessionID, armed.intake?.sessionID)
        XCTAssertEqual(armed.process(apdu: try IrohaPeerNfcAPDUCodecV1.encode(.getAsk)).response.data, ask.encode())
        var unarmed = try IrohaPeerNfcCardEndpointV1.intake(applicationIdentifier: bpng, profilePolicy: policy)
        XCTAssertNil(unarmed.intake?.ask)
        XCTAssertNotEqual(unarmed.sessionID, armed.sessionID)
        XCTAssertEqual(step(&unarmed, .getAsk).response.statusWord, .conditionsNotSatisfied)
    }

    func testRunFromAskBuildsTheOfferInsideTheContactAndReadsTheRequest() async throws {
        let limits = IrohaPeerNfcLimitsV1(maximumReadChunkBytes: 240, maximumWriteChunkBytes: 240)
        let ask = try sampleAsk()
        let offer = try message(kind: .offer, byte: 0xB1, count: 900)
        let request = try message(kind: .request, byte: 0xB2, count: 1_200)
        let credited = try message(kind: .credited, byte: 0xB3, count: 300)
        let card = try IrohaPeerNfcIntakeCardV1(
            applicationIdentifier: bpng, limits: limits, request: request, credited: credited,
            preparationPolls: 2, ask: ask)
        let factory = IrohaPeerNfcOfferFactoryRecorderV1(offer: offer)
        let delivered = IrohaPeerNfcFlagV1()

        let read = try await IrohaPeerNfcOfferExchangeV1.runFromAsk(
            offerFactory: { try await factory.offer(for: $0) },
            applicationIdentifier: bpng, profilePolicy: policy, limits: limits,
            transceive: { try await card.transceive($0) }, sleep: { _ in },
            onOfferDelivered: { delivered.set() })
        XCTAssertEqual(read.ask, ask)
        XCTAssertEqual(read.request, request)
        XCTAssertEqual(read.intake.state, .requestReady)
        XCTAssertTrue(delivered.isSet)
        let asks = await factory.asks
        XCTAssertEqual(asks, [ask], "the factory runs exactly once, with the card's ask")
        let preparedOffers = await card.preparedOffers
        XCTAssertEqual(preparedOffers, [offer])
        let operations = await card.commands.map(\.operation)
        XCTAssertEqual(Array(operations.prefix(4)), [.selectApplication, .getIntake, .getAsk, .beginOffer])
        XCTAssertEqual(operations.filter { $0 == .getAsk }.count, 1)
        XCTAssertEqual(operations.last, .readRequest)

        // Tap 2 is unchanged.
        let checkpoint = try IrohaPeerNfcSenderCheckpointV1(
            sessionID: read.info.identity.sessionID, receiveRequest: read.request.encoded,
            payment: try message(kind: .payment, byte: 0xB4, count: 1_500).encoded,
            profilePolicy: policy, limits: limits)
        let result = try await IrohaPeerNfcReaderExchangeV1.run(
            restoredCheckpoint: checkpoint.encoded, applicationIdentifier: bpng, profilePolicy: policy,
            limits: limits, transceive: { try await card.transceive($0) },
            loadOrCreateDurableCheckpoint: { _, _ in throw IrohaPeerNfcErrorV1.stateMismatch },
            updateDurableCheckpoint: { _ in })
        XCTAssertEqual(result.acknowledgement, credited)

        // The payer-built Offer path never reads the ask and reports none.
        let payerLed = try IrohaPeerNfcIntakeCardV1(
            applicationIdentifier: bpng, limits: limits, request: request, credited: credited,
            preparationPolls: 1, ask: ask)
        let plain = try await IrohaPeerNfcOfferExchangeV1.run(
            offer: offer, applicationIdentifier: bpng, profilePolicy: policy, limits: limits,
            transceive: { try await payerLed.transceive($0) }, sleep: { _ in })
        XCTAssertNil(plain.ask)
        XCTAssertEqual(plain.request, request)
        let plainCommands = await payerLed.commands
        XCTAssertFalse(plainCommands.contains(.getAsk))
    }

    func testRunFromAskRefusesAnUnarmedOrBoundCardBeforeTheFactoryRuns() async throws {
        let limits = IrohaPeerNfcLimitsV1(maximumReadChunkBytes: 240, maximumWriteChunkBytes: 240)
        let ask = try sampleAsk()
        let offer = try message(kind: .offer, byte: 0xC1, count: 700)
        let request = try message(kind: .request, byte: 0xC2, count: 600)
        let credited = try message(kind: .credited, byte: 0xC3, count: 200)
        let factory = IrohaPeerNfcOfferFactoryRecorderV1(offer: offer)

        // No amount set: GET_ASK answers 6985, the existing typed peer refusal.
        let plain = try IrohaPeerNfcIntakeCardV1(
            applicationIdentifier: bpng, limits: limits, request: request, credited: credited,
            preparationPolls: 1)
        do {
            _ = try await IrohaPeerNfcOfferExchangeV1.runFromAsk(
                offerFactory: { try await factory.offer(for: $0) }, applicationIdentifier: bpng,
                profilePolicy: policy, limits: limits, transceive: { try await plain.transceive($0) },
                sleep: { _ in })
            XCTFail("a card without an ask")
        } catch IrohaPeerNfcErrorV1.peerRejected(let operation) {
            XCTAssertEqual(operation, .getAsk)
        }
        let plainOperations = await plain.commands.map(\.operation)
        XCTAssertEqual(plainOperations, [.selectApplication, .getIntake, .getAsk])

        // An intake already holding another payer's Offer: refused before GET_ASK. (A receiving intake is served: see
        // testRunFromAskServesAReceivingIntakeWhoseEarlierOfferWasAbandoned.)
        let other = try message(kind: .offer, byte: 0xC9, count: 300)
        do {
            let busy = try IrohaPeerNfcIntakeCardV1(
                applicationIdentifier: bpng, limits: limits, request: request, credited: credited,
                preparationPolls: 1_000, ask: ask)
            let initial = try IrohaPeerNfcIntakeRecordV1.decode(await busy.transceive(.getIntake).data)
            let session = initial.sessionID
            let began = try await busy.transceive(.beginOffer(sessionID: session, offerHeader: other.header.bytes))
            XCTAssertEqual(began.statusWord, .success)
            let bytes = other.encoded
            let chunk = min(limits.maximumWriteChunkBytes, initial.maximumWriteChunkBytes)
            for offset in stride(from: 0, to: bytes.count, by: chunk) {
                let written = try await busy.transceive(.writeOffer(
                    sessionID: session, offerWireHash: other.wireHash, offset: UInt32(offset),
                    bytes: bytes.subdata(in: offset..<min(offset + chunk, bytes.count))))
                XCTAssertEqual(written.statusWord, .success)
            }
            let submitted = try await busy.transceive(.submitOffer(sessionID: session, offerWireHash: other.wireHash))
            XCTAssertEqual(submitted.statusWord, .success)
            let bound = try IrohaPeerNfcIntakeRecordV1.decode(await busy.transceive(.getIntake).data)
            XCTAssertEqual(bound.state, .preparingRequest)
            XCTAssertEqual(bound.offerWireHash, other.wireHash)
            XCTAssertEqual(bound.receivedOfferBytes, bytes.count)
            let prepared = await busy.preparedOffers
            XCTAssertEqual(prepared, [other])
            let before = await busy.commands.count
            do {
                _ = try await IrohaPeerNfcOfferExchangeV1.runFromAsk(
                    offerFactory: { try await factory.offer(for: $0) }, applicationIdentifier: bpng,
                    profilePolicy: policy, limits: limits, transceive: { try await busy.transceive($0) },
                    sleep: { _ in })
                XCTFail("a bound intake")
            } catch IrohaPeerNfcErrorV1.stateMismatch {}
            let operations = await busy.commands.dropFirst(before).map(\.operation)
            XCTAssertEqual(operations, [.selectApplication, .getIntake], "no GET_ASK once an Offer is bound")
        }

        // A card hosting a Request whose Offer came over another carrier.
        let hosted = IrohaPeerNfcLoopbackCardV1(IrohaPeerNfcCardEndpointV1(
            receiver: try IrohaPeerNfcReceiverSessionV1(
                sessionID: s, receiveRequest: request.encoded, applicationIdentifier: bpng)))
        do {
            _ = try await IrohaPeerNfcOfferExchangeV1.runFromAsk(
                offerFactory: { try await factory.offer(for: $0) }, applicationIdentifier: bpng,
                profilePolicy: policy, limits: limits, transceive: { try await hosted.transceive($0) },
                sleep: { _ in })
            XCTFail("a hosted Request")
        } catch IrohaPeerNfcErrorV1.stateMismatch {}
        let hostedOperations = await hosted.commands.map(\.operation)
        XCTAssertEqual(hostedOperations, [.selectApplication, .getIntake])
        let asks = await factory.asks
        XCTAssertEqual(asks, [], "the factory never ran")
    }

    /// An abandoned contact leaves an intake that is receiving an Offer. The next payer's ask-led contact is served: the
    /// factory runs once and its Offer replaces the unfinished one, exactly as `run` replaces it.
    func testRunFromAskServesAReceivingIntakeWhoseEarlierOfferWasAbandoned() async throws {
        let limits = IrohaPeerNfcLimitsV1(maximumReadChunkBytes: 240, maximumWriteChunkBytes: 240)
        let ask = try sampleAsk()
        let abandoned = try message(kind: .offer, byte: 0xC9, count: 300)
        let offer = try message(kind: .offer, byte: 0xCA, count: 700)
        let request = try message(kind: .request, byte: 0xCB, count: 600)
        let credited = try message(kind: .credited, byte: 0xCC, count: 200)
        let factory = IrohaPeerNfcOfferFactoryRecorderV1(offer: offer)
        let card = try IrohaPeerNfcIntakeCardV1(
            applicationIdentifier: bpng, limits: limits, request: request, credited: credited,
            preparationPolls: 1, ask: ask)
        let session = try IrohaPeerNfcIntakeRecordV1.decode(await card.transceive(.getIntake).data).sessionID
        _ = try await card.transceive(.beginOffer(sessionID: session, offerHeader: abandoned.header.bytes))
        let receiving = try IrohaPeerNfcIntakeRecordV1.decode(await card.transceive(.getIntake).data)
        XCTAssertEqual(receiving.state, .receivingOffer)

        let read = try await IrohaPeerNfcOfferExchangeV1.runFromAsk(
            offerFactory: { try await factory.offer(for: $0) }, applicationIdentifier: bpng,
            profilePolicy: policy, limits: limits, transceive: { try await card.transceive($0) },
            sleep: { _ in })
        XCTAssertEqual(read.ask, ask)
        XCTAssertEqual(read.request, request)
        XCTAssertEqual(read.intake.state, .requestReady)
        let asks = await factory.asks
        XCTAssertEqual(asks, [ask], "the factory ran exactly once")
        let operations = await card.commands.map(\.operation)
        XCTAssertEqual(operations.filter { $0 == .getAsk }.count, 1)
        XCTAssertEqual(operations.filter { $0 == .beginOffer }.count, 2, "the new Offer's header replaced the unfinished one")
    }

    func testRunFromAskRefusesMalformedAsksBeforeTheFactory() async throws {
        let limits = IrohaPeerNfcLimitsV1(maximumReadChunkBytes: 240, maximumWriteChunkBytes: 240)
        let offer = try message(kind: .offer, byte: 0xD1, count: 700)
        let request = try message(kind: .request, byte: 0xD2, count: 600)
        let credited = try message(kind: .credited, byte: 0xD3, count: 200)
        let valid = try sampleAsk().encode()
        var answers: [(IrohaPeerNfcAPDUResponseV1, IrohaPeerNfcErrorV1)] = [
            (IrohaPeerNfcAPDUResponseV1(data: valid.prefix(55), statusWord: .success), .invalidLength),
            (IrohaPeerNfcAPDUResponseV1(data: valid + Data([0]), statusWord: .success), .invalidLength),
            (IrohaPeerNfcAPDUResponseV1(statusWord: .success), .invalidLength),
            (IrohaPeerNfcAPDUResponseV1(statusWord: .wrongData), .invalidAPDU),
        ]
        for vector in try irohaPeerAskVectorsV1("invalid_records", in: irohaPeerAskFixtureV1()) {
            let record = try irohaPeerAskBytesV1(vector["record_hex"])
            if record.count == IrohaPeerNfcV1.askBytes {
                answers.append((IrohaPeerNfcAPDUResponseV1(data: record, statusWord: .success), .invalidAsk))
            }
        }
        XCTAssertEqual(answers.count, 4 + 8)
        for (answer, expected) in answers {
            let card = try IrohaPeerNfcIntakeCardV1(
                applicationIdentifier: bpng, limits: limits, request: request, credited: credited,
                preparationPolls: 1, ask: try sampleAsk(), askResponse: answer)
            let factory = IrohaPeerNfcOfferFactoryRecorderV1(offer: offer)
            do {
                _ = try await IrohaPeerNfcOfferExchangeV1.runFromAsk(
                    offerFactory: { try await factory.offer(for: $0) }, applicationIdentifier: bpng,
                    profilePolicy: policy, limits: limits, transceive: { try await card.transceive($0) },
                    sleep: { _ in })
                XCTFail("malformed ask \(expected)")
            } catch let error as IrohaPeerNfcErrorV1 {
                XCTAssertEqual(error, expected)
            }
            let asks = await factory.asks
            XCTAssertEqual(asks, [])
            let last = await card.commands.last
            XCTAssertEqual(last, .getAsk, "nothing is sent after a malformed ask")
        }
    }

    func testThrowingOrInvalidOfferFactorySendsNothingFurther() async throws {
        let limits = IrohaPeerNfcLimitsV1(maximumReadChunkBytes: 240, maximumWriteChunkBytes: 240)
        let ask = try sampleAsk()
        let offer = try message(kind: .offer, byte: 0xE1, count: 900)
        let request = try message(kind: .request, byte: 0xE2, count: 600)
        let credited = try message(kind: .credited, byte: 0xE3, count: 200)

        let failing = IrohaPeerNfcOfferFactoryRecorderV1(failure: IrohaPeerNfcOfferFactoryFailureV1())
        let card = try IrohaPeerNfcIntakeCardV1(
            applicationIdentifier: bpng, limits: limits, request: request, credited: credited,
            preparationPolls: 1, ask: ask)
        do {
            _ = try await IrohaPeerNfcOfferExchangeV1.runFromAsk(
                offerFactory: { try await failing.offer(for: $0) }, applicationIdentifier: bpng,
                profilePolicy: policy, limits: limits, transceive: { try await card.transceive($0) },
                sleep: { _ in })
            XCTFail("the factory threw")
        } catch is IrohaPeerNfcOfferFactoryFailureV1 {}
        let asks = await failing.asks
        XCTAssertEqual(asks, [ask])
        let operations = await card.commands.map(\.operation)
        XCTAssertEqual(operations, [.selectApplication, .getIntake, .getAsk])
        let after = try IrohaPeerNfcIntakeRecordV1.decode(await card.transceive(.getIntake).data)
        XCTAssertEqual(after.state, .awaitingOffer, "the card still awaits an Offer")

        // The factory's Offer is checked exactly as `run` checks the payer's own.
        let small = IrohaPeerNfcLimitsV1(
            maximumMessageBytes: 400, maximumReadChunkBytes: 240, maximumWriteChunkBytes: 240)
        let invalid: [(IrohaPeerWireMessageV1, IrohaPeerNfcLimitsV1, IrohaPeerNfcErrorV1)] = [
            (request, limits, .invalidKind),
            (offer, small, .messageTooLarge(actual: offer.encoded.count, maximum: 400)),
        ]
        for (built, localLimits, expected) in invalid {
            let card = try IrohaPeerNfcIntakeCardV1(
                applicationIdentifier: bpng, limits: limits, request: request, credited: credited,
                preparationPolls: 1, ask: ask)
            let factory = IrohaPeerNfcOfferFactoryRecorderV1(offer: built)
            do {
                _ = try await IrohaPeerNfcOfferExchangeV1.runFromAsk(
                    offerFactory: { try await factory.offer(for: $0) }, applicationIdentifier: bpng,
                    profilePolicy: policy, limits: localLimits, transceive: { try await card.transceive($0) },
                    sleep: { _ in })
                XCTFail("invalid Offer \(expected)")
            } catch let error as IrohaPeerNfcErrorV1 {
                XCTAssertEqual(error, expected)
            }
            let last = await card.commands.last
            XCTAssertEqual(last, .getAsk)
        }
    }

    func testInterruptedAskedOfferResumesWithTheBuiltOfferThroughRun() async throws {
        let limits = IrohaPeerNfcLimitsV1(maximumReadChunkBytes: 240, maximumWriteChunkBytes: 240)
        let ask = try sampleAsk()
        let offer = try message(kind: .offer, byte: 0xF4, count: 1_000)
        let request = try message(kind: .request, byte: 0xF5, count: 600)
        let card = try IrohaPeerNfcIntakeCardV1(
            applicationIdentifier: bpng, limits: limits, request: request,
            credited: try message(kind: .credited, byte: 0xF6, count: 200),
            preparationPolls: 1, dropAfterOfferWrites: 2, ask: ask)
        let factory = IrohaPeerNfcOfferFactoryRecorderV1(offer: offer)
        do {
            _ = try await IrohaPeerNfcOfferExchangeV1.runFromAsk(
                offerFactory: { try await factory.offer(for: $0) }, applicationIdentifier: bpng,
                profilePolicy: policy, limits: limits, transceive: { try await card.transceive($0) },
                sleep: { _ in })
            XCTFail("the first contact is lost mid-Offer")
        } catch is IrohaPeerNfcContactLostV1 {}
        // The card holds part of that Offer: `run` resumes the Offer the factory already built, from the received
        // offset, without asking again (an ask-led run would build a second Offer, so the payer never uses it here).
        let resumed = try await IrohaPeerNfcOfferExchangeV1.run(
            offer: offer, applicationIdentifier: bpng, profilePolicy: policy, limits: limits,
            transceive: { try await card.transceive($0) }, sleep: { _ in })
        XCTAssertEqual(resumed.request, request)
        let asks = await factory.asks
        XCTAssertEqual(asks, [ask], "the factory ran once")
        let writes = await card.offerWriteLog
        XCTAssertEqual(Array(writes.prefix(3)), ["1:0", "1:240", "2:480"],
            "the second contact resumes the retained Offer at the receiver's received offset")
        let operations = await card.commands.map(\.operation)
        XCTAssertEqual(operations.filter { $0 == .selectApplication }.count, 2, "one SELECT per contact")
        XCTAssertEqual(operations.filter { $0 == .getAsk }.count, 1, "resume never asks for a new Offer")
        XCTAssertEqual(operations.filter { $0 == .beginOffer }.count, 1, "resume does not restart the partial Offer")
        let preparedOffers = await card.preparedOffers
        XCTAssertEqual(preparedOffers, [offer])
    }

    func testReceiverGuardDeclinesAnOfferForAnotherAmount() async throws {
        // The receiver's wallet compares the submitted Offer's amount with its own ask.
        let limits = IrohaPeerNfcLimitsV1(maximumReadChunkBytes: 240, maximumWriteChunkBytes: 240)
        let ask = try sampleAsk()
        let request = try message(kind: .request, byte: 0xF7, count: 600)
        let credited = try message(kind: .credited, byte: 0xF8, count: 200)
        let other = KagemushaWalletUInt128V1(low: ask.amount.low + 1, high: ask.amount.high)
        for (amount, accepted) in [(other, false), (ask.amount, true)] {
            let offer = try amountOffer(amount)
            XCTAssertEqual(try KagemushaWalletWireV1.offerAmountData(IrohaPeerKagemushaWalletAdapterV1.decode(offer)), amount)
            let card = try IrohaPeerNfcIntakeCardV1(
                applicationIdentifier: bpng, limits: limits, request: request, credited: credited,
                preparationPolls: 1, ask: ask, guardsAskedAmount: true)
            let factory = IrohaPeerNfcOfferFactoryRecorderV1(offer: offer)
            do {
                let read = try await IrohaPeerNfcOfferExchangeV1.runFromAsk(
                    offerFactory: { try await factory.offer(for: $0) }, applicationIdentifier: bpng,
                    profilePolicy: policy, limits: limits, transceive: { try await card.transceive($0) },
                    sleep: { _ in })
                XCTAssertTrue(accepted)
                XCTAssertEqual(read.request, request)
            } catch IrohaPeerNfcErrorV1.offerDeclined(let reason) {
                XCTAssertFalse(accepted)
                XCTAssertEqual(reason, IrohaPeerNfcIntakeCardV1.askedAmountMismatch)
            }
        }
    }

    func testDecliningReceiverAfterTheAskReportsItsReason() async throws {
        let limits = IrohaPeerNfcLimitsV1(maximumReadChunkBytes: 240, maximumWriteChunkBytes: 240)
        let ask = try sampleAsk()
        let offer = try message(kind: .offer, byte: 0xF1, count: 800)
        let declining = try IrohaPeerNfcIntakeCardV1(
            applicationIdentifier: bpng, limits: limits,
            request: try message(kind: .request, byte: 0xF2, count: 600),
            credited: try message(kind: .credited, byte: 0xF3, count: 200),
            preparationPolls: 1, declineReason: 9, ask: ask)
        let factory = IrohaPeerNfcOfferFactoryRecorderV1(offer: offer)
        do {
            _ = try await IrohaPeerNfcOfferExchangeV1.runFromAsk(
                offerFactory: { try await factory.offer(for: $0) }, applicationIdentifier: bpng,
                profilePolicy: policy, limits: limits, transceive: { try await declining.transceive($0) },
                sleep: { _ in })
            XCTFail("declined")
        } catch IrohaPeerNfcErrorV1.offerDeclined(let reason) {
            XCTAssertEqual(reason, 9)
        }
        let preparedOffers = await declining.preparedOffers
        XCTAssertEqual(preparedOffers, [offer])
    }

    // MARK: Helpers

    private func sampleAsk() throws -> IrohaPeerAskV1 {
        try IrohaPeerAskV1(
            amount: .init(low: 250_000, high: 0),
            receiverAccountDigest: Data((0..<32).map { UInt8($0 * 3 + 1) }))
    }

    /// Structural Offer DATA `{body, payer_credential, certificates, signature}` whose 8-field
    /// body proposes `amount`; it authenticates nothing.
    private func amountOffer(_ amount: KagemushaWalletUInt128V1) throws -> IrohaPeerWireMessageV1 {
        func record(_ fields: [Data]) -> Data {
            fields.reduce(into: Data()) { result, field in
                var length = field.count
                repeat {
                    let byte = UInt8(length & 0x7f)
                    length >>= 7
                    result.append(byte | (length == 0 ? 0 : 0x80))
                } while length != 0
                result.append(field)
            }
        }
        let amountBytes = withUnsafeBytes(of: amount.low.littleEndian) { Data($0) }
            + withUnsafeBytes(of: amount.high.littleEndian) { Data($0) }
        let body = [Data([1, 0]), irohaPeerWalletStructuralSchemeV1, Data(repeating: 0x29, count: 32),
                    Data(repeating: 0x2A, count: 32), Data(repeating: 0x2B, count: 32),
                    Data([4]) + Data(count: 15), amountBytes, Data(repeating: 0x5E, count: 32)]
        let offer = record([record(body), Data([1]), Data(), Data(repeating: 0x36, count: 64)])
        let tag = withUnsafeBytes(of: UInt32(IrohaPeerWireKindV1.offer.rawValue).littleEndian) { Data($0) }
        let envelope = noritoEncode(
            typeName: KagemushaWalletWireV1.envelopeFrameName,
            payload: record([Data([1, 0]), tag + record([offer])]),
            flags: NoritoHeader.compactLen,
            payloadAlignment: KagemushaWalletWireV1.envelopePayloadAlignment)
        return try IrohaPeerKagemushaWalletAdapterV1.wrap(envelope, destinationAccountOriginal: nil)
    }

    private func step(
        _ card: inout IrohaPeerNfcCardEndpointV1,
        _ command: IrohaPeerNfcCommandV1
    ) -> IrohaPeerNfcCardStepV1 {
        card.process(apdu: try! IrohaPeerNfcAPDUCodecV1.encode(command))
    }

    private func intake(_ card: inout IrohaPeerNfcCardEndpointV1) throws -> IrohaPeerNfcIntakeRecordV1 {
        let response = step(&card, .getIntake).response
        XCTAssertEqual(response.statusWord, .success)
        return try IrohaPeerNfcIntakeRecordV1.decode(response.data)
    }

    private func message(kind: IrohaPeerPayloadKind, byte: UInt8, count: Int) throws -> IrohaPeerWireMessageV1 {
        try irohaPeerWalletExchangeMessageV1(kind: kind, payload: Data(repeating: byte, count: count))
    }

    private func ipm1Header(kind: UInt8, length: UInt32, canonicalHash: Data, wireHash: Data) -> Data {
        var header = Data("IPM1".utf8) + Data([1, 0, 0, 1, kind, 0, 0, 1])
        for value in [length, length] {
            header.append(contentsOf: [24, 16, 8, 0].map { UInt8(truncatingIfNeeded: value >> $0) })
        }
        return header + canonicalHash + wireHash
    }

    private func hexString(_ data: Data) -> String {
        data.map { String(format: "%02X", $0) }.joined()
    }

    private static func hex(_ parts: String...) -> String { parts.joined() }

    /// Generated from the spec layout; the Kotlin SDK test asserts the same bytes.
    private static let vectors: [String: String] = [
        "selectBpng": "00A4040009F05047444B4E46430100",
        "selectProtocol": "00A404000BF0504B45504B524E46430100",
        "getIntake": "8030000044",
        "beginOffer": hex(
            "80310000641111111111111111111111111111111149504D310100000101000001000002580000025877777777777777",
            "777777777777777777777777777777777777777777777777776666666666666666666666666666666666666666666666",
            "666666666666666666"
        ),
        "writeOffer200": hex(
            "80320000FC11111111111111111111111111111111666666666666666666666666666666666666666666666666666666",
            "666666666600000000000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20212223242526",
            "2728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F50515253545556",
            "5758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F80818283848586",
            "8788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6",
            "B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7"
        ),
        "writeOffer300At400": hex(
            "803200000001601111111111111111111111111111111166666666666666666666666666666666666666666666666666",
            "666666666666660000019000070E151C232A31383F464D545B626970777E858C939AA1A8AFB6BDC4CBD2D9E0E7EEF5FC",
            "030A11181F262D343B424950575E656C737A81888F969DA4ABB2B9C0C7CED5DCE3EAF1F8FF060D141B222930373E454C",
            "535A61686F767D848B9299A0A7AEB5BCC3CAD1D8DFE6EDF4FB020910171E252C333A41484F565D646B727980878E959C",
            "A3AAB1B8BFC6CDD4DBE2E9F0F7FE050C131A21282F363D444B525960676E757C838A91989FA6ADB4BBC2C9D0D7DEE5EC",
            "F3FA01080F161D242B323940474E555C636A71787F868D949BA2A9B0B7BEC5CCD3DAE1E8EFF6FD040B121920272E353C",
            "434A51585F666D747B828990979EA5ACB3BAC1C8CFD6DDE4EBF2F900070E151C232A31383F464D545B626970777E858C",
            "939AA1A8AFB6BDC4CBD2D9E0E7EEF5FC030A11181F262D"
        ),
        "submitOffer": hex(
            "803300003011111111111111111111111111111111666666666666666666666666666666666666666666666666666666",
            "6666666666"
        ),
        "getInfo": "8010000062",
        "readRequest240At0": hex(
            "801100003411111111111111111111111111111111222222222222222222222222222222222222222222222222222222",
            "222222222200000000F0"
        ),
        "readRequest4096At4096": hex(
            "801100000000341111111111111111111111111111111122222222222222222222222222222222222222222222222222",
            "22222222222222000010001000"
        ),
        "beginPayment": hex(
            "802000008411111111111111111111111111111111222222222222222222222222222222222222222222222222222222",
            "222222222249504D31010000010300000100002328000023288888888888888888888888888888888888888888888888",
            "8888888888888888884444444444444444444444444444444444444444444444444444444444444444"
        ),
        "write200At0": hex(
            "80210000FC11111111111111111111111111111111444444444444444444444444444444444444444444444444444444",
            "444444444400000000000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20212223242526",
            "2728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F50515253545556",
            "5758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F80818283848586",
            "8788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6",
            "B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7"
        ),
        "write300At8700": hex(
            "802100000001601111111111111111111111111111111144444444444444444444444444444444444444444444444444",
            "44444444444444000021FC00070E151C232A31383F464D545B626970777E858C939AA1A8AFB6BDC4CBD2D9E0E7EEF5FC",
            "030A11181F262D343B424950575E656C737A81888F969DA4ABB2B9C0C7CED5DCE3EAF1F8FF060D141B222930373E454C",
            "535A61686F767D848B9299A0A7AEB5BCC3CAD1D8DFE6EDF4FB020910171E252C333A41484F565D646B727980878E959C",
            "A3AAB1B8BFC6CDD4DBE2E9F0F7FE050C131A21282F363D444B525960676E757C838A91989FA6ADB4BBC2C9D0D7DEE5EC",
            "F3FA01080F161D242B323940474E555C636A71787F868D949BA2A9B0B7BEC5CCD3DAE1E8EFF6FD040B121920272E353C",
            "434A51585F666D747B828990979EA5ACB3BAC1C8CFD6DDE4EBF2F900070E151C232A31383F464D545B626970777E858C",
            "939AA1A8AFB6BDC4CBD2D9E0E7EEF5FC030A11181F262D"
        ),
        "commit": hex(
            "802200005011111111111111111111111111111111222222222222222222222222222222222222222222222222222222",
            "22222222224444444444444444444444444444444444444444444444444444444444444444"
        ),
        "readAcknowledgement256At512": hex(
            "802300003411111111111111111111111111111111444444444444444444444444444444444444444444444444444444",
            "44444444440000020000"
        ),
        "confirmAcknowledgement": hex(
            "802400005011111111111111111111111111111111444444444444444444444444444444444444444444444444444444",
            "44444444445555555555555555555555555555555555555555555555555555555555555555"
        ),
        "getStatus": hex(
            "802500003011111111111111111111111111111111222222222222222222222222222222222222222222222222222222",
            "2222222222AE"
        ),
        "ioi1Awaiting": hex(
            "494F49310101000111111111111111111111111111111111000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000010000000"
        ),
        "ioi1Receiving": hex(
            "494F49310102000111111111111111111111111111111111000002AC000000C866666666666666666666666666666666",
            "6666666666666666666666666666666610000000"
        ),
        "ioi1Declined": hex(
            "494F49310105000111111111111111111111111111111111000002AC000002AC66666666666666666666666666666666",
            "6666666666666666666666666666666610000007"
        ),
        "inf1RequestReady": hex(
            "494E4631010100010100111111111111111111111111111111110000251C222222222222222222222222222222222222",
            "222222222222222222222222222233333333333333333333333333333333333333333333333333333333333333331000",
            "1000"
        ),
        "nst1PaymentReceiving": hex(
            "4E5354310102000101001111111111111111111111111111111122222222222222222222222222222222222222222222",
            "22222222222222222222333333333333333333333333333333333333333333333333333333333333333300010000237C",
            "000010004444444444444444444444444444444444444444444444444444444444444444000000000000000000000000",
            "000000000000000000000000000000000000000000000000000010001000"
        ),
        "nst1AcknowledgementReady": hex(
            "4E5354310103000103001111111111111111111111111111111122222222222222222222222222222222222222222222",
            "22222222222222222222333333333333333333333333333333333333333333333333333333333333333300010000237C",
            "0000237C44444444444444444444444444444444444444444444444444444444444444440001000004B0555555555555",
            "555555555555555555555555555555555555555555555555555510001000"
        ),
    ]
}

/// RF loss injected by the loopback card.
private struct IrohaPeerNfcContactLostV1: Error, IrohaPeerNfcAmbiguousResponseErrorV1 {}

private final class IrohaPeerNfcFlagV1: @unchecked Sendable {
    private let lock = NSLock()
    private var value = false
    func set() { lock.lock(); value = true; lock.unlock() }
    var isSet: Bool { lock.lock(); defer { lock.unlock() }; return value }
}

private final class IrohaPeerNfcPersistedDataV1: @unchecked Sendable {
    private let lock = NSLock()
    private var stored: [Data] = []
    func append(_ data: Data) { lock.lock(); stored.append(data); lock.unlock() }
    var values: [Data] { lock.lock(); defer { lock.unlock() }; return stored }
}

/// The payer's offer factory: records every ask it is called with.
private actor IrohaPeerNfcOfferFactoryRecorderV1 {
    private let result: Result<IrohaPeerWireMessageV1, Error>
    private(set) var asks: [IrohaPeerAskV1] = []

    init(offer: IrohaPeerWireMessageV1) { result = .success(offer) }
    init(failure: Error) { result = .failure(failure) }

    func offer(for ask: IrohaPeerAskV1) throws -> IrohaPeerWireMessageV1 {
        asks.append(ask)
        return try result.get()
    }
}

/// The payer's wallet could not create its Offer.
private struct IrohaPeerNfcOfferFactoryFailureV1: Error {}

/// Any card endpoint behind raw APDUs, logging every command it receives.
private actor IrohaPeerNfcLoopbackCardV1 {
    private var endpoint: IrohaPeerNfcCardEndpointV1
    private(set) var commands: [IrohaPeerNfcCommandV1] = []

    init(_ endpoint: IrohaPeerNfcCardEndpointV1) { self.endpoint = endpoint }

    func transceive(_ command: IrohaPeerNfcCommandV1) throws -> IrohaPeerNfcAPDUResponseV1 {
        commands.append(command)
        return endpoint.process(apdu: try IrohaPeerNfcAPDUCodecV1.encode(command)).response
    }
}

/// A receiver card driven through raw APDUs: intake, a wallet that signs the
/// Request after a few polls, durable admission and commit.
private actor IrohaPeerNfcIntakeCardV1 {
    private var endpoint: IrohaPeerNfcCardEndpointV1
    private let request: IrohaPeerWireMessageV1
    private let credited: IrohaPeerWireMessageV1
    private let limits: IrohaPeerNfcLimitsV1
    private let preparationPolls: Int
    private let declineReason: UInt16?
    private var dropAfterOfferWrites: Int?
    private var dropAfterPaymentWrites: Int?
    private var pendingPolls: Int?
    /// A hostile card's answer to GET_ASK in place of its intake's.
    private let askResponse: IrohaPeerNfcAPDUResponseV1?
    /// The wallet declines an Offer whose amount is not its ask's.
    private let guardsAskedAmount: Bool
    private var offerDeclinedByGuard = false
    static let askedAmountMismatch: UInt16 = 0x0A5C
    private(set) var preparedOffers: [IrohaPeerWireMessageV1] = []
    private(set) var durableCommits = 0
    private(set) var offerWriteLog: [String] = []
    private(set) var commands: [IrohaPeerNfcCommandV1] = []
    private var contact = 0

    init(
        applicationIdentifier: IrohaPeerNfcApplicationIdentifierV1,
        limits: IrohaPeerNfcLimitsV1,
        request: IrohaPeerWireMessageV1,
        credited: IrohaPeerWireMessageV1,
        preparationPolls: Int,
        declineReason: UInt16? = nil,
        dropAfterOfferWrites: Int? = nil,
        dropAfterPaymentWrites: Int? = nil,
        ask: IrohaPeerAskV1? = nil,
        askResponse: IrohaPeerNfcAPDUResponseV1? = nil,
        guardsAskedAmount: Bool = false
    ) throws {
        endpoint = IrohaPeerNfcCardEndpointV1(
            applicationIdentifier: applicationIdentifier,
            intake: try IrohaPeerNfcOfferIntakeV1(
                profilePolicy: .init(profile: .kagemushaWalletV1), limits: limits, ask: ask)
        )
        self.request = request
        self.credited = credited
        self.limits = limits
        self.preparationPolls = preparationPolls
        self.declineReason = declineReason
        self.dropAfterOfferWrites = dropAfterOfferWrites
        self.dropAfterPaymentWrites = dropAfterPaymentWrites
        self.askResponse = askResponse
        self.guardsAskedAmount = guardsAskedAmount
    }

    func transceive(_ command: IrohaPeerNfcCommandV1) throws -> IrohaPeerNfcAPDUResponseV1 {
        commands.append(command)
        if case .getAsk = command, let askResponse { return askResponse }
        if case .write = command, let remaining = dropAfterPaymentWrites {
            if remaining == 0 {
                dropAfterPaymentWrites = nil
                throw IrohaPeerNfcContactLostV1()
            }
            dropAfterPaymentWrites = remaining - 1
        }
        if case .selectApplication = command { contact += 1 }
        if case .writeOffer(_, _, let offset, _) = command {
            if let remaining = dropAfterOfferWrites {
                if remaining == 0 {
                    dropAfterOfferWrites = nil
                    throw IrohaPeerNfcContactLostV1()
                }
                dropAfterOfferWrites = remaining - 1
            }
            offerWriteLog.append("\(contact):\(offset)")
        }
        if case .getIntake = command, let remaining = pendingPolls {
            if remaining <= 0 {
                pendingPolls = nil
                if offerDeclinedByGuard {
                    try endpoint.decline(reason: Self.askedAmountMismatch)
                } else if let declineReason {
                    try endpoint.decline(reason: declineReason)
                } else {
                    try endpoint.installRequest(request.encoded)
                }
            } else {
                pendingPolls = remaining - 1
            }
        }
        let credited = self.credited
        let limits = self.limits
        let step = endpoint.process(
            apdu: try IrohaPeerNfcAPDUCodecV1.encode(command),
            admitPayment: { context in try IrohaPeerNfcDurablePaymentAdmissionV1(context: context, limits: limits) },
            durableCommit: { context in
                try IrohaPeerNfcDurableAcknowledgementV1(context: context, acknowledgement: credited.encoded, limits: limits)
            }
        )
        if case .commit = command, step.response.statusWord == .success { durableCommits += 1 }
        if let offer = step.submittedOffer {
            preparedOffers.append(offer)
            pendingPolls = preparationPolls
            if guardsAskedAmount, let ask = endpoint.intake?.ask {
                let offered = try? KagemushaWalletWireV1.offerAmountData(
                    IrohaPeerKagemushaWalletAdapterV1.decode(offer))
                offerDeclinedByGuard = offered != ask.amount
            }
        }
        return step.response
    }
}
