import XCTest
@testable import IrohaSwift

/// NFC direct mode: the card hosts the receiver's open Request from the start, and one hold, or a
/// short Request read followed by a Payment contact, carries the Request, the Payment and the
/// durable acknowledgement. Also the app-supplied application identifier and the byte-exact
/// spec vectors that the Kotlin SDK asserts too (`specs/kagemusha_wallet_wire_v1.md` §6).
final class IrohaPeerNfcDirectModeV1Tests: XCTestCase {
    private let bpng = try! IrohaPeerNfcApplicationIdentifierV1(hex: "F05047444B4E464301")
    private let policy = IrohaPeerNfcProfilePolicyV1(profile: .kagemushaWalletV1)
    private let s = Data(repeating: 0x11, count: 16)

    // MARK: Spec vectors

    func testCommandsAndRecordsMatchTheSharedSpecVectors() throws {
        let hr = Data(repeating: 0x22, count: 32)
        let wr = Data(repeating: 0x33, count: 32)
        let wp = Data(repeating: 0x44, count: 32)
        let wa = Data(repeating: 0x55, count: 32)
        let paymentHeader = ipm1Header(kind: 3, length: 9_000, canonicalHash: Data(repeating: 0x88, count: 32), wireHash: wp)
        let chunk200 = Data((0..<200).map { UInt8($0) })
        let chunk300 = Data((0..<300).map { UInt8(truncatingIfNeeded: $0 * 7) })
        let commands: [(String, IrohaPeerNfcCommandV1)] = [
            ("selectBpng", .selectApplication(bpng)),
            ("selectProtocol", .selectApplication(.protocolDefault)),
            ("getIntake", .getIntake),
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
            ("ioi1RequestReady", try IrohaPeerNfcIntakeRecordV1(
                profile: .kagemushaWalletV1, sessionID: s, maximumWriteChunkBytes: 4_096).encode()),
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
        XCTAssertEqual(try IrohaPeerNfcIntakeRecordV1.decode(records[0].1).sessionID, s)
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
        var card = try directCard(message(kind: .request, byte: 0x41, count: 200))
        XCTAssertEqual(step(&card, .selectApplication(bpng)).statusWord, .success)
        XCTAssertEqual(step(&card, .selectApplication(.protocolDefault)).statusWord, .notFound)
    }

    // MARK: Direct card

    func testCardHostsTheOpenRequestAsReadyAndRefusesRetiredOfferCommands() throws {
        let request = try message(kind: .request, byte: 0x71, count: 400)
        var card = try directCard(request)
        XCTAssertEqual(card.sessionID, s)
        XCTAssertEqual(IrohaPeerNfcCardEndpointV1.route(.selectApplication(bpng)), .select)
        XCTAssertEqual(IrohaPeerNfcCardEndpointV1.route(.getIntake), .request)
        XCTAssertEqual(IrohaPeerNfcCardEndpointV1.route(.getInfo), .request)

        let record = try intake(&card)
        XCTAssertEqual(record.state, .requestReady)
        XCTAssertEqual(record.profile, .kagemushaWalletV1)
        XCTAssertEqual(record.sessionID, s)
        XCTAssertEqual(record.maximumWriteChunkBytes, IrohaPeerNfcV1.maximumChunkBytes)
        let encoded = record.encode()
        XCTAssertEqual(encoded.count, IrohaPeerNfcV1.intakeBytes)
        XCTAssertEqual(Data(encoded[24..<64]), Data(count: 40))
        XCTAssertEqual(Data(encoded[66..<68]), Data(count: 2))

        let info = try IrohaPeerNfcInfoV1.decode(step(&card, .getInfo).data)
        XCTAssertEqual(info.phase, .requestReady)
        XCTAssertEqual(info.identity.sessionID, s)
        XCTAssertEqual(info.identity.requestCanonicalHash, request.canonicalHash)
        // BEGIN_OFFER, WRITE_OFFER, SUBMIT_OFFER and GET_ASK are no longer instructions.
        for instruction: UInt8 in [0x31, 0x32, 0x33, 0x34] {
            let response = card.process(apdu: Data([IrohaPeerNfcV1.commandClass, instruction, 0, 0]))
            XCTAssertEqual(response.statusWord, .instructionNotSupported, "\(instruction)")
        }
        XCTAssertEqual(card.receiver.phase, .requestReady, "refused commands change nothing")
    }

    func testIntakeRecordAdmitsOnlyRequestReadyWithZeroReservedBytes() throws {
        let record = try IrohaPeerNfcIntakeRecordV1(
            profile: .kagemushaWalletV1, sessionID: s, maximumWriteChunkBytes: 4_096)
        XCTAssertEqual(try IrohaPeerNfcIntakeRecordV1.decode(record.encode()), record)
        XCTAssertEqual(IrohaPeerNfcIntakeStateV1.allCases.map(\.rawValue), [4])
        for state: UInt8 in [0, 1, 2, 3, 5, 0xFF] {
            var bytes = record.encode()
            bytes[5] = state
            XCTAssertThrowsError(try IrohaPeerNfcIntakeRecordV1.decode(bytes), "\(state)") {
                XCTAssertEqual($0 as? IrohaPeerNfcErrorV1, .invalidAPDU, "\(state)")
            }
        }
        for offset in [24, 31, 32, 63, 66, 67] {
            var bytes = record.encode()
            bytes[offset] = 1
            XCTAssertThrowsError(try IrohaPeerNfcIntakeRecordV1.decode(bytes), "\(offset)") {
                XCTAssertEqual($0 as? IrohaPeerNfcErrorV1, .invalidLength, "\(offset)")
            }
        }
        XCTAssertThrowsError(try IrohaPeerNfcIntakeRecordV1.decode(record.encode().dropLast())) {
            XCTAssertEqual($0 as? IrohaPeerNfcErrorV1, .invalidLength)
        }
        XCTAssertThrowsError(try IrohaPeerNfcIntakeRecordV1(
            profile: .kagemushaWalletV1, sessionID: Data(count: 16), maximumWriteChunkBytes: 4_096)) {
            XCTAssertEqual($0 as? IrohaPeerNfcErrorV1, .invalidSession)
        }
        XCTAssertThrowsError(try IrohaPeerNfcIntakeRecordV1(
            profile: .kagemushaWalletV1, sessionID: s, maximumWriteChunkBytes: 0)) {
            XCTAssertEqual($0 as? IrohaPeerNfcErrorV1, .invalidLength)
        }
    }

    func testRandomSessionIDsAreNonzeroAndFresh() {
        let first = IrohaPeerNfcReceiverSessionV1.randomSessionID()
        let second = IrohaPeerNfcReceiverSessionV1.randomSessionID()
        XCTAssertEqual(first.count, IrohaPeerNfcV1.sessionIDBytes)
        XCTAssertTrue(first.contains { $0 != 0 })
        XCTAssertNotEqual(first, second)
    }

    // MARK: Continuous hold and interrupted-contact recovery

    func testOneHoldCarriesRequestPaymentAndDurableAcknowledgement() async throws {
        let limits = IrohaPeerNfcLimitsV1(maximumReadChunkBytes: 240, maximumWriteChunkBytes: 240)
        let request = try message(kind: .request, byte: 0x82, count: 1_200)
        let payment = try message(kind: .payment, byte: 0x83, count: 1_500)
        let credited = try message(kind: .credited, byte: 0x84, count: 300)
        let policy = self.policy
        let card = try IrohaPeerNfcDirectCardV1(
            applicationIdentifier: bpng, sessionID: s, limits: limits, request: request, credited: credited)
        let persisted = IrohaPeerNfcPersistedDataV1()

        let result = try await IrohaPeerNfcReaderExchangeV1.run(
            applicationIdentifier: bpng, profilePolicy: policy, limits: limits,
            transceive: { command in
                if case .beginPayment = command {
                    XCTAssertEqual(persisted.values.count, 1, "Payment must already be durable")
                }
                if case .confirmAcknowledgement = command {
                    XCTAssertEqual(persisted.values.count, 2, "ACK must already be durable")
                }
                return try await card.transceive(command)
            },
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
        XCTAssertEqual(result.checkpoint.payment, payment)
        let commands = await card.commands
        XCTAssertEqual(commands.filter { $0.operation == .selectApplication }.count, 1)
        XCTAssertEqual(commands.filter { $0.operation == .getInfo }.count, 1)
        XCTAssertEqual(commands.filter { $0.operation == .readRequest }.count,
            (request.encoded.count + 239) / 240, "Request is read only once")
        let commits = await card.durableCommits
        XCTAssertEqual(commits, 1)
        // The card commits the exact Payment carrier, its payer companion included.
        let committed = await card.committedPayments
        XCTAssertEqual(committed, [payment])
        XCTAssertEqual(try IrohaPeerKagemushaWalletAdapterV1.payerCompanion(payment),
                       irohaPeerWalletPayerCompanionV1())
    }

    func testOneHoldApprovalCancellationNeverBeginsPayment() async throws {
        let request = try message(kind: .request, byte: 0x82, count: 100)
        let credited = try message(kind: .credited, byte: 0x84, count: 100)
        let card = try IrohaPeerNfcDirectCardV1(
            applicationIdentifier: bpng, sessionID: s, limits: .default, request: request, credited: credited)
        do {
            _ = try await IrohaPeerNfcReaderExchangeV1.run(
                applicationIdentifier: bpng, profilePolicy: policy,
                transceive: { try await card.transceive($0) },
                loadOrCreateDurableCheckpoint: { _, _ in throw CancellationError() },
                updateDurableCheckpoint: { _ in XCTFail("no ACK after cancelled approval") })
            XCTFail("approval was cancelled")
        } catch is CancellationError {}
        let commands = await card.commands
        XCTAssertFalse(commands.contains { $0.operation == .beginPayment })
        XCTAssertFalse(commands.contains { $0.operation == .commit })
    }

    func testOneHoldRejectsCheckpointBoundToAnotherRequestBeforePayment() async throws {
        let request = try message(kind: .request, byte: 0x82, count: 100)
        let otherRequest = try message(kind: .request, byte: 0x85, count: 120)
        let payment = try message(kind: .payment, byte: 0x83, count: 100)
        let credited = try message(kind: .credited, byte: 0x84, count: 100)
        let policy = self.policy
        let card = try IrohaPeerNfcDirectCardV1(
            applicationIdentifier: bpng, sessionID: s, limits: .default, request: request, credited: credited)
        do {
            _ = try await IrohaPeerNfcReaderExchangeV1.run(
                applicationIdentifier: bpng, profilePolicy: policy,
                transceive: { try await card.transceive($0) },
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
        let request = try message(kind: .request, byte: 0x82, count: 100)
        let payment = try message(kind: .payment, byte: 0x83, count: 100)
        let credited = try message(kind: .credited, byte: 0x84, count: 100)
        let policy = self.policy
        let applicationIdentifier = bpng
        let card = try IrohaPeerNfcDirectCardV1(
            applicationIdentifier: bpng, sessionID: s, limits: .default, request: request, credited: credited)
        let persisted = IrohaPeerNfcPersistedDataV1()
        let operation = Task {
            try await IrohaPeerNfcReaderExchangeV1.run(
                applicationIdentifier: applicationIdentifier, profilePolicy: policy,
                transceive: { try await card.transceive($0) },
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

    func testInterruptedOneHoldResumesExactPaymentWithoutReadingTheRequestAgain() async throws {
        let limits = IrohaPeerNfcLimitsV1(maximumReadChunkBytes: 240, maximumWriteChunkBytes: 240)
        let request = try message(kind: .request, byte: 0x82, count: 300)
        let payment = try message(kind: .payment, byte: 0x83, count: 1_500)
        let credited = try message(kind: .credited, byte: 0x84, count: 300)
        let policy = self.policy
        let card = try IrohaPeerNfcDirectCardV1(
            applicationIdentifier: bpng, sessionID: s, limits: limits, request: request, credited: credited,
            dropAfterPaymentWrites: 2)
        let persisted = IrohaPeerNfcPersistedDataV1()
        do {
            _ = try await IrohaPeerNfcReaderExchangeV1.run(
                applicationIdentifier: bpng, profilePolicy: policy, limits: limits,
                transceive: { try await card.transceive($0) },
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
            restoredCheckpoint: try XCTUnwrap(persisted.values.first),
            applicationIdentifier: bpng, profilePolicy: policy, limits: limits,
            transceive: { try await card.transceive($0) },
            loadOrCreateDurableCheckpoint: { _, _ in
                XCTFail("retry must never debit again")
                throw IrohaPeerNfcErrorV1.stateMismatch
            },
            updateDurableCheckpoint: { persisted.append($0) })
        XCTAssertEqual(result.checkpoint.payment, payment)
        XCTAssertEqual(result.acknowledgement, credited)
        let retryCommands = await Array(card.commands.dropFirst(commandsBeforeRetry))
        XCTAssertFalse(retryCommands.contains { $0.operation == .readRequest })
        let writes = retryCommands.compactMap { command -> UInt32? in
            guard case .write(_, _, let offset, let bytes) = command else { return nil }
            XCTAssertEqual(bytes, payment.encoded.subdata(in: Int(offset)..<(Int(offset) + bytes.count)))
            return offset
        }
        XCTAssertEqual(writes.first, 480)
        XCTAssertEqual(persisted.values.count, 2)
    }

    // MARK: Request read over its own contact

    func testReadRequestReturnsTheOpenRequestAndItsAccountThenAPaymentContactResumes() async throws {
        let limits = IrohaPeerNfcLimitsV1(maximumReadChunkBytes: 240, maximumWriteChunkBytes: 240)
        let request = try message(kind: .request, byte: 0x82, count: 1_200)
        let payment = try message(kind: .payment, byte: 0x83, count: 1_500)
        let credited = try message(kind: .credited, byte: 0x84, count: 300)
        let card = try IrohaPeerNfcDirectCardV1(
            applicationIdentifier: bpng, sessionID: s, limits: limits, request: request, credited: credited)

        let read = try await IrohaPeerNfcReaderExchangeV1.readRequest(
            applicationIdentifier: bpng, profilePolicy: policy, limits: limits,
            transceive: { try await card.transceive($0) })
        XCTAssertEqual(read.request, request)
        XCTAssertEqual(read.intake.state, .requestReady)
        XCTAssertEqual(read.intake.sessionID, s)
        XCTAssertEqual(read.info.identity.sessionID, s)
        XCTAssertEqual(read.requestEnvelope, try IrohaPeerKagemushaWalletAdapterV1.decode(request))
        XCTAssertEqual(read.destinationAccountOriginal, try irohaPeerWalletRequestAccountOriginalV1())
        let readOperations = await card.commands.map(\.operation)
        XCTAssertEqual(Array(readOperations.prefix(3)), [.selectApplication, .getIntake, .getInfo])
        XCTAssertEqual(readOperations.dropFirst(3).count, (request.encoded.count + 239) / 240)
        XCTAssertTrue(readOperations.dropFirst(3).allSatisfy { $0 == .readRequest }, "no value moves")

        // The payer approves away from the card; the next contact delivers only the durable Payment.
        let checkpoint = try IrohaPeerNfcSenderCheckpointV1(
            sessionID: read.info.identity.sessionID, receiveRequest: read.request.encoded,
            payment: payment.encoded, profilePolicy: policy, limits: limits)
        let persisted = IrohaPeerNfcPersistedDataV1()
        let before = await card.commands.count
        let result = try await IrohaPeerNfcReaderExchangeV1.run(
            restoredCheckpoint: checkpoint.encoded, applicationIdentifier: bpng, profilePolicy: policy,
            limits: limits, transceive: { try await card.transceive($0) },
            loadOrCreateDurableCheckpoint: { _, _ in throw IrohaPeerNfcErrorV1.stateMismatch },
            updateDurableCheckpoint: { persisted.append($0) })
        XCTAssertEqual(result.acknowledgement, credited)
        XCTAssertEqual(result.confirmationState, .confirmed)
        XCTAssertEqual(persisted.values.count, 1)
        let paymentOperations = await card.commands.dropFirst(before).map(\.operation)
        XCTAssertFalse(paymentOperations.contains(.readRequest))
        XCTAssertFalse(paymentOperations.contains(.getIntake))
        let commits = await card.durableCommits
        XCTAssertEqual(commits, 1)
    }

    func testReadRequestRefusesForeignCardsMismatchedIntakesAndStartedExchanges() async throws {
        let limits = IrohaPeerNfcLimitsV1(maximumReadChunkBytes: 240, maximumWriteChunkBytes: 240)
        let request = try message(kind: .request, byte: 0x91, count: 600)
        let payment = try message(kind: .payment, byte: 0x92, count: 700)
        let credited = try message(kind: .credited, byte: 0x93, count: 200)
        let policy = self.policy
        func read(_ card: IrohaPeerNfcDirectCardV1) async throws -> IrohaPeerNfcRequestReadV1 {
            try await IrohaPeerNfcReaderExchangeV1.readRequest(
                applicationIdentifier: bpng, profilePolicy: policy, limits: limits,
                transceive: { try await card.transceive($0) })
        }

        let foreign = try IrohaPeerNfcDirectCardV1(
            applicationIdentifier: .protocolDefault, sessionID: s, limits: limits, request: request,
            credited: credited)
        do {
            _ = try await read(foreign)
            XCTFail("another application's card")
        } catch IrohaPeerNfcErrorV1.invalidApplicationIdentifier {}

        let otherSession = try IrohaPeerNfcIntakeRecordV1(
            profile: .kagemushaWalletV1, sessionID: Data(repeating: 0x12, count: 16), maximumWriteChunkBytes: 240)
        let mismatched = try IrohaPeerNfcDirectCardV1(
            applicationIdentifier: bpng, sessionID: s, limits: limits, request: request, credited: credited,
            intakeResponse: IrohaPeerNfcAPDUResponseV1(data: otherSession.encode(), statusWord: .success))
        do {
            _ = try await read(mismatched)
            XCTFail("IOI1 and INF1 must name one session")
        } catch IrohaPeerNfcErrorV1.continuityMismatch {}
        let mismatchedOperations = await mismatched.commands.map(\.operation)
        XCTAssertFalse(mismatchedOperations.contains(.readRequest))

        var reserved = try IrohaPeerNfcIntakeRecordV1(
            profile: .kagemushaWalletV1, sessionID: s, maximumWriteChunkBytes: 240).encode()
        reserved[40] = 1
        let hostile = try IrohaPeerNfcDirectCardV1(
            applicationIdentifier: bpng, sessionID: s, limits: limits, request: request, credited: credited,
            intakeResponse: IrohaPeerNfcAPDUResponseV1(data: reserved, statusWord: .success))
        do {
            _ = try await read(hostile)
            XCTFail("nonzero reserved IOI1 bytes")
        } catch IrohaPeerNfcErrorV1.invalidLength {}

        // A started exchange resumes only from the payer's retained checkpoint.
        let started = try IrohaPeerNfcDirectCardV1(
            applicationIdentifier: bpng, sessionID: s, limits: limits, request: request, credited: credited)
        let admitted = try await started.transceive(.beginPayment(
            sessionID: s, requestCanonicalHash: request.canonicalHash, paymentHeader: payment.header.bytes))
        XCTAssertEqual(admitted.statusWord, .success)
        do {
            _ = try await read(started)
            XCTFail("a payment is already being received")
        } catch IrohaPeerNfcErrorV1.stateMismatch {}
    }

    func testRequestReadBindsTheIntakeSessionTheInfoAndTheExactRequest() throws {
        let request = try message(kind: .request, byte: 0xA1, count: 300)
        let other = try message(kind: .request, byte: 0xA2, count: 300)
        let payment = try message(kind: .payment, byte: 0xA3, count: 300)
        let intake = try IrohaPeerNfcIntakeRecordV1(
            profile: .kagemushaWalletV1, sessionID: s, maximumWriteChunkBytes: 240)
        let info = try IrohaPeerNfcInfoV1(
            phase: .requestReady, flags: [.idempotentWrites],
            identity: IrohaPeerNfcRequestIdentityV1(profile: .kagemushaWalletV1, sessionID: s,
                requestCanonicalHash: request.canonicalHash, requestWireHash: request.wireHash),
            requestLength: request.encoded.count, maximumReadChunkBytes: 240, maximumWriteChunkBytes: 240)
        let read = try IrohaPeerNfcRequestReadV1(intake: intake, info: info, request: request)
        XCTAssertEqual(read.requestEnvelope, try IrohaPeerKagemushaWalletAdapterV1.decode(request))
        XCTAssertEqual(read.destinationAccountOriginal,
                       try IrohaPeerKagemushaWalletAdapterV1.destinationAccountOriginal(request))

        let foreignIntake = try IrohaPeerNfcIntakeRecordV1(
            profile: .kagemushaWalletV1, sessionID: Data(repeating: 0x12, count: 16), maximumWriteChunkBytes: 240)
        XCTAssertThrowsError(try IrohaPeerNfcRequestReadV1(intake: foreignIntake, info: info, request: request)) {
            XCTAssertEqual($0 as? IrohaPeerNfcErrorV1, .continuityMismatch)
        }
        XCTAssertThrowsError(try IrohaPeerNfcRequestReadV1(intake: intake, info: info, request: other)) {
            XCTAssertEqual($0 as? IrohaPeerNfcErrorV1, .invalidHash)
        }
        XCTAssertThrowsError(try IrohaPeerNfcRequestReadV1(intake: intake, info: info, request: payment)) {
            XCTAssertEqual($0 as? IrohaPeerNfcErrorV1, .invalidKind)
        }
    }

    // MARK: Helpers

    private func directCard(_ request: IrohaPeerWireMessageV1) throws -> IrohaPeerNfcCardEndpointV1 {
        IrohaPeerNfcCardEndpointV1(receiver: try IrohaPeerNfcReceiverSessionV1(
            sessionID: s, receiveRequest: request.encoded, applicationIdentifier: bpng))
    }

    private func step(
        _ card: inout IrohaPeerNfcCardEndpointV1,
        _ command: IrohaPeerNfcCommandV1
    ) -> IrohaPeerNfcAPDUResponseV1 {
        card.process(apdu: try! IrohaPeerNfcAPDUCodecV1.encode(command))
    }

    private func intake(_ card: inout IrohaPeerNfcCardEndpointV1) throws -> IrohaPeerNfcIntakeRecordV1 {
        let response = step(&card, .getIntake)
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
        "ioi1RequestReady": hex(
            "494F49310104000111111111111111111111111111111111000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000010000000"
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

/// RF loss injected by the direct card.
private struct IrohaPeerNfcContactLostV1: Error, IrohaPeerNfcAmbiguousResponseErrorV1 {}

private final class IrohaPeerNfcPersistedDataV1: @unchecked Sendable {
    private let lock = NSLock()
    private var stored: [Data] = []
    func append(_ data: Data) { lock.lock(); stored.append(data); lock.unlock() }
    var values: [Data] { lock.lock(); defer { lock.unlock() }; return stored }
}

/// A receiver card hosting its open Request from the start, driven through raw APDUs, with
/// durable admission and commit.
private actor IrohaPeerNfcDirectCardV1 {
    private var endpoint: IrohaPeerNfcCardEndpointV1
    private let credited: IrohaPeerWireMessageV1
    private let limits: IrohaPeerNfcLimitsV1
    private var dropAfterPaymentWrites: Int?
    /// A hostile card's answer to GET_INTAKE in place of its own.
    private let intakeResponse: IrohaPeerNfcAPDUResponseV1?
    private(set) var commands: [IrohaPeerNfcCommandV1] = []
    private(set) var durableCommits = 0
    private(set) var committedPayments: [IrohaPeerWireMessageV1] = []

    init(
        applicationIdentifier: IrohaPeerNfcApplicationIdentifierV1,
        sessionID: Data,
        limits: IrohaPeerNfcLimitsV1,
        request: IrohaPeerWireMessageV1,
        credited: IrohaPeerWireMessageV1,
        dropAfterPaymentWrites: Int? = nil,
        intakeResponse: IrohaPeerNfcAPDUResponseV1? = nil
    ) throws {
        endpoint = IrohaPeerNfcCardEndpointV1(receiver: try IrohaPeerNfcReceiverSessionV1(
            sessionID: sessionID,
            receiveRequest: request.encoded,
            profilePolicy: .init(profile: .kagemushaWalletV1),
            limits: limits,
            applicationIdentifier: applicationIdentifier
        ))
        self.credited = credited
        self.limits = limits
        self.dropAfterPaymentWrites = dropAfterPaymentWrites
        self.intakeResponse = intakeResponse
    }

    func transceive(_ command: IrohaPeerNfcCommandV1) throws -> IrohaPeerNfcAPDUResponseV1 {
        commands.append(command)
        if case .getIntake = command, let intakeResponse { return intakeResponse }
        if case .write = command, let remaining = dropAfterPaymentWrites {
            if remaining == 0 {
                dropAfterPaymentWrites = nil
                throw IrohaPeerNfcContactLostV1()
            }
            dropAfterPaymentWrites = remaining - 1
        }
        let credited = self.credited
        let limits = self.limits
        var committed: IrohaPeerWireMessageV1?
        let response = endpoint.process(
            apdu: try IrohaPeerNfcAPDUCodecV1.encode(command),
            admitPayment: { context in try IrohaPeerNfcDurablePaymentAdmissionV1(context: context, limits: limits) },
            durableCommit: { context in
                committed = context.payment
                return try IrohaPeerNfcDurableAcknowledgementV1(
                    context: context, acknowledgement: credited.encoded, limits: limits)
            }
        )
        if case .commit = command, response.statusWord == .success { durableCommits += 1 }
        if let committed { committedPayments.append(committed) }
        return response
    }
}
