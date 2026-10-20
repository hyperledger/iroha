import XCTest
import IrohaSwift
@testable import IrohaSwiftMobileTransports

final class IrohaPeerNfcRequestReadPublicationV1Tests: XCTestCase {
    func testDiscoveryPartialReadsAndFinalReplayObserveOnlyTheCompletedRequest() throws {
        let request = try irohaPeerWalletExchangeMessageV1(kind: .request,
            payload: Data(repeating: 0x31, count: 400))
        let session = Data(repeating: 0x11, count: IrohaPeerNfcV1.sessionIDBytes)
        let limits = IrohaPeerNfcLimitsV1(maximumReadChunkBytes: 64, maximumWriteChunkBytes: 64)
        var endpoint = IrohaPeerNfcCardEndpointV1(receiver: try IrohaPeerNfcReceiverSessionV1(
            sessionID: session, receiveRequest: request.encoded,
            profilePolicy: .init(profile: .kagemushaWalletV1), limits: limits))
        func process(_ command: IrohaPeerNfcCommandV1) throws -> IrohaPeerNfcAPDUResponseV1 {
            endpoint.process(apdu: try IrohaPeerNfcAPDUCodecV1.encode(command))
        }
        func observed(_ command: IrohaPeerNfcCommandV1, _ response: IrohaPeerNfcAPDUResponseV1) -> Bool {
            IrohaPeerNfcRequestReadPublicationV1.completedRead(command, response: response,
                requestLength: request.encoded.count)
        }
        for command in [IrohaPeerNfcCommandV1.getIntake, .getInfo] {
            let response = try process(command)
            XCTAssertEqual(response.statusWord, .success)
            XCTAssertFalse(observed(command, response))
        }
        XCTAssertGreaterThan(request.encoded.count, limits.maximumReadChunkBytes)
        var received = Data()
        var finalCommand: IrohaPeerNfcCommandV1?
        var finalResponse: IrohaPeerNfcAPDUResponseV1?
        while received.count < request.encoded.count {
            let command = IrohaPeerNfcCommandV1.readRequest(sessionID: session,
                requestCanonicalHash: request.canonicalHash, offset: UInt32(received.count), length: 64)
            let response = try process(command)
            guard response.statusWord == .success, !response.data.isEmpty else {
                XCTFail("A valid same-session Request chunk must succeed")
                return
            }
            received.append(response.data)
            XCTAssertEqual(observed(command, response), received.count == request.encoded.count)
            finalCommand = command; finalResponse = response
        }
        XCTAssertEqual(received, request.encoded)
        let last = try XCTUnwrap(finalCommand), original = try XCTUnwrap(finalResponse)
        let replay = try process(last)
        XCTAssertEqual(replay, original)
        XCTAssertTrue(observed(last, replay), "The exact final chunk can report handover again")
        XCTAssertFalse(observed(last, .init(statusWord: .storageFailure)))
        let discovery = try process(.getInfo)
        XCTAssertFalse(observed(.getInfo, discovery))
        XCTAssertEqual(endpoint.receiver.receiveRequest.encoded, request.encoded)
        XCTAssertEqual(endpoint.receiver.phase, .requestReady)
    }

    func testWrongSessionOrRequestCannotReportHandover() throws {
        let request = try irohaPeerWalletExchangeMessageV1(kind: .request,
            payload: Data(repeating: 0x32, count: 96))
        let session = Data(repeating: 0x11, count: IrohaPeerNfcV1.sessionIDBytes)
        var endpoint = IrohaPeerNfcCardEndpointV1(receiver: try IrohaPeerNfcReceiverSessionV1(
            sessionID: session, receiveRequest: request.encoded,
            profilePolicy: .init(profile: .kagemushaWalletV1)))
        for (id, hash) in [(Data(repeating: 0x22, count: session.count), request.canonicalHash),
                           (session, Data(repeating: 0x33, count: request.canonicalHash.count))] {
            let command = IrohaPeerNfcCommandV1.readRequest(sessionID: id,
                requestCanonicalHash: hash, offset: UInt32(request.encoded.count - 1), length: 1)
            let response = endpoint.process(apdu: try IrohaPeerNfcAPDUCodecV1.encode(command))
            XCTAssertNotEqual(response.statusWord, .success)
            XCTAssertFalse(IrohaPeerNfcRequestReadPublicationV1.completedRead(command,
                response: response, requestLength: request.encoded.count))
        }
        XCTAssertEqual(endpoint.receiver.receiveRequest.encoded, request.encoded)
        XCTAssertEqual(endpoint.receiver.phase, .requestReady)
    }
}
