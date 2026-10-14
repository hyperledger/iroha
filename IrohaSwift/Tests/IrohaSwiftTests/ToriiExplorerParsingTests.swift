import Foundation
import XCTest
@testable import IrohaSwift

final class ToriiExplorerParsingTests: XCTestCase {
    func testExplorerSharedQueryRejectsMalformedCursorAndLimit() {
        for cursor in ["", "padded=", "contains space", String(repeating: "A", count: 4097)] {
            XCTAssertThrowsError(try ToriiListQuery(cursor: cursor).validate())
        }
        XCTAssertThrowsError(try ToriiListQuery(limit: 0).validate())
    }

    func testExplorerSharedPageRequiresCursorAndRejectsRetiredEnvelope() throws {
        let page = try JSONDecoder().decode(ToriiPage<ToriiExplorerInstructionItem>.self,
            from: Data(#"{"items":[],"next_cursor":"opaque"}"#.utf8))
        XCTAssertEqual(page.nextCursor, "opaque")
        for payload in [
            #"{"items":[]}"#,
            #"{"items":[],"pagination":{"next_cursor":null,"has_more":false}}"#,
            #"{"items":[],"next_cursor":null,"sampled_at_ms":0}"#,
            #"{"items":[],"next_cursor":""}"#,
            #"{"items":[],"next_cursor":null,"total_items":0}"#,
        ] {
            XCTAssertThrowsError(try JSONDecoder().decode(ToriiPage<ToriiExplorerInstructionItem>.self,
                from: Data(payload.utf8)), payload)
        }
    }

    func testCanonicalQuerySelectorsRejectSurroundingWhitespace() {
        let assetId = "62Fk4FPcMuLvW5QjDGNF2a4jAmjM"
        let cases: [(String, () throws -> Void)] = [
            (
                "uaid portfolio asset",
                { _ = try ToriiUaidPortfolioQuery(assetId: " \(assetId)").queryItems() }
            ),
        ]

        for (label, action) in cases {
            XCTAssertThrowsError(try action(), label) { error in
                guard case let ToriiClientError.invalidPayload(reason) = error else {
                    return XCTFail("Expected invalidPayload for \(label), got \(error)")
                }
                XCTAssertTrue(
                    reason.contains("surrounding whitespace"),
                    "Expected whitespace diagnostic for \(label), got \(reason)"
                )
            }
        }
    }

    func testExplorerTransferDetailsParsesAsset() throws {
        let json = """
        {
            "authority":"sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
            "created_at":"2025-01-01T00:00:00Z",
            "kind":"Transfer",
            "box":\(try explorerTransferBoxFixture(sourceAssetId: "62Fk4FPcMuLvW5QjDGNF2a4jAmjM#sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV", destination: "sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D", amount: "10")),
            "transaction_hash":"hash",
            "transaction_status":"Committed",
            "block":1,
            "index":0
        }
        """
        let item = try JSONDecoder().decode(ToriiExplorerInstructionItem.self, from: Data(json.utf8))
        guard let details = item.transferDetails() else {
            return XCTFail("Expected transfer details.")
        }
        switch details {
        case .asset(let asset):
            XCTAssertEqual(asset.destinationAccountId, "sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D")
            XCTAssertEqual(asset.amount, "10")
            XCTAssertEqual(asset.senderAccountId, "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV")
            XCTAssertEqual(asset.assetDefinitionId, "62Fk4FPcMuLvW5QjDGNF2a4jAmjM")
            XCTAssertNil(details.role(for: "sorauﾛ1PgﾉﾀXﾖnWｱﾊｷﾕﾈjｷZﾖrﾅxｲWﾔﾀﾘYヰﾍxｺﾀﾃﾛｽfﾖ2Gｲ8P3LSM"))
            XCTAssertEqual(details.role(for: "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV"), .sender)
            XCTAssertEqual(details.role(for: "sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D"), .receiver)
            XCTAssertTrue(details.involvesAccount("sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D"))
            XCTAssertTrue(details.involvesAssetDefinition("62Fk4FPcMuLvW5QjDGNF2a4jAmjM"))
            XCTAssertFalse(details.involvesAssetDefinition("61CtjvNd9T3THAR65GsMVHr82Bjc"))
        case .assetBatch:
            XCTFail("Expected asset transfer details.")
        }
    }

    func testExplorerTransferDetailsParsesAssetBatch() throws {
        let json = """
        {
            "authority":"sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
            "created_at":"2025-01-01T00:00:00Z",
            "kind":"Transfer",
            "box":\(try explorerBatchBoxFixture([("sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV", "sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D", "62Fk4FPcMuLvW5QjDGNF2a4jAmjM", "5"), ("sorauﾛ1Pﾀﾚｿ1ﾍｶsFｲAfｾeB3ｽヱヱｳcyﾊyｹ1ﾂﾈヰヰ6ﾛヰEAﾃｱｳﾖLPN4XM", "sorauﾛ1PﾜKNﾗ7ｼｺa2WｸｼﾒﾐQﾎbｺﾄocﾆﾁヰJaｱbg6sｾgｲﾖPfX7WAWRY", "61CtjvNd9T3THAR65GsMVHr82Bjc", "2")])),
            "transaction_hash":"hash",
            "transaction_status":"Committed",
            "block":1,
            "index":0
        }
        """
        let item = try JSONDecoder().decode(ToriiExplorerInstructionItem.self, from: Data(json.utf8))
        guard let details = item.transferDetails() else {
            return XCTFail("Expected transfer details.")
        }
        switch details {
        case .asset:
            XCTFail("Expected batch transfer details.")
        case .assetBatch(let entries):
            XCTAssertEqual(entries.count, 2)
            XCTAssertEqual(entries[0].senderAccountId, "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV")
            XCTAssertEqual(entries[0].receiverAccountId, "sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D")
            XCTAssertEqual(entries[0].assetDefinitionId, "62Fk4FPcMuLvW5QjDGNF2a4jAmjM")
            XCTAssertEqual(entries[0].amount, "5")
            XCTAssertEqual(entries[1].senderAccountId, "sorauﾛ1Pﾀﾚｿ1ﾍｶsFｲAfｾeB3ｽヱヱｳcyﾊyｹ1ﾂﾈヰヰ6ﾛヰEAﾃｱｳﾖLPN4XM")
            XCTAssertEqual(entries[1].receiverAccountId, "sorauﾛ1PﾜKNﾗ7ｼｺa2WｸｼﾒﾐQﾎbｺﾄocﾆﾁヰJaｱbg6sｾgｲﾖPfX7WAWRY")
            XCTAssertEqual(entries[1].assetDefinitionId, "61CtjvNd9T3THAR65GsMVHr82Bjc")
            XCTAssertEqual(entries[1].amount, "2")
            XCTAssertEqual(details.role(for: "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV"), .sender)
            XCTAssertEqual(details.role(for: "sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D"), .receiver)
            XCTAssertTrue(details.involvesAccount("sorauﾛ1PﾜKNﾗ7ｼｺa2WｸｼﾒﾐQﾎbｺﾄocﾆﾁヰJaｱbg6sｾgｲﾖPfX7WAWRY"))
            XCTAssertTrue(details.involvesAssetDefinition("62Fk4FPcMuLvW5QjDGNF2a4jAmjM"))
            XCTAssertTrue(details.involvesAssetDefinition("61CtjvNd9T3THAR65GsMVHr82Bjc"))
            XCTAssertFalse(details.involvesAssetDefinition("5ywNgSPQ5KyuQh7SwaZmwMW4GTXu"))
        }
    }

    func testExplorerTransferRecordsFiltersByAccountAndAssetDefinition() throws {
        let json = """
        {
            "next_cursor":null,
            "items": [
                {
                    "authority":"sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
                    "created_at":"2025-01-01T00:00:00Z",
                    "kind":"Transfer",
                    "box":\(try explorerTransferBoxFixture(sourceAssetId: "62Fk4FPcMuLvW5QjDGNF2a4jAmjM#sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV", destination: "sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D", amount: "10")),
                    "transaction_hash":"hash1",
                    "transaction_status":"Committed",
                    "block":1,
                    "index":0
                },
                {
                    "authority":"sorauﾛ1Pﾀﾚｿ1ﾍｶsFｲAfｾeB3ｽヱヱｳcyﾊyｹ1ﾂﾈヰヰ6ﾛヰEAﾃｱｳﾖLPN4XM",
                    "created_at":"2025-01-01T00:00:00Z",
                    "kind":"Transfer",
                    "box":\(try explorerBatchBoxFixture([("sorauﾛ1Pﾀﾚｿ1ﾍｶsFｲAfｾeB3ｽヱヱｳcyﾊyｹ1ﾂﾈヰヰ6ﾛヰEAﾃｱｳﾖLPN4XM", "sorauﾛ1PﾜKNﾗ7ｼｺa2WｸｼﾒﾐQﾎbｺﾄocﾆﾁヰJaｱbg6sｾgｲﾖPfX7WAWRY", "61CtjvNd9T3THAR65GsMVHr82Bjc", "2")])),
                    "transaction_hash":"hash2",
                    "transaction_status":"Committed",
                    "block":1,
                    "index":1
                }
            ]
        }
        """
        let page = try JSONDecoder().decode(ToriiPage<ToriiExplorerInstructionItem>.self, from: Data(json.utf8))
        XCTAssertEqual(page.transferRecords().count, 2)
        XCTAssertEqual(page.transferRecords(matchingAccount: "sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D").count, 1)
        XCTAssertEqual(page.transferRecords(matchingAccount: "sorauﾛ1Pﾀﾚｿ1ﾍｶsFｲAfｾeB3ｽヱヱｳcyﾊyｹ1ﾂﾈヰヰ6ﾛヰEAﾃｱｳﾖLPN4XM").count, 1)
        XCTAssertEqual(page.transferRecords(assetDefinitionId: "61CtjvNd9T3THAR65GsMVHr82Bjc").count, 1)
        XCTAssertEqual(page.transferRecords(assetDefinitionId: "62Fk4FPcMuLvW5QjDGNF2a4jAmjM").count, 1)
        XCTAssertEqual(page.transferRecords(matchingAccount: "sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D",
                                            assetDefinitionId: "61CtjvNd9T3THAR65GsMVHr82Bjc").count, 0)
    }

    func testExplorerTransferSummariesDeriveDirection() throws {
        let json = """
        {
            "next_cursor":null,
            "items": [
                {
                    "authority":"sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
                    "created_at":"2025-01-01T00:00:00Z",
                    "kind":"Transfer",
                    "box":\(try explorerTransferBoxFixture(sourceAssetId: "62Fk4FPcMuLvW5QjDGNF2a4jAmjM#sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV", destination: "sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D", amount: "10")),
                    "transaction_hash":"hash1",
                    "transaction_status":"Committed",
                    "block":1,
                    "index":0
                }
            ]
        }
        """
        let page = try JSONDecoder().decode(ToriiPage<ToriiExplorerInstructionItem>.self, from: Data(json.utf8))
        let summaries = page.transferSummaries(matchingAccount: "sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D")
        XCTAssertEqual(summaries.count, 1)
        let summary = summaries[0]
        XCTAssertEqual(summary.direction, .incoming)
        XCTAssertEqual(summary.senderAccountId, "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV")
        XCTAssertEqual(summary.receiverAccountId, "sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D")
        XCTAssertEqual(summary.assetDefinitionId, "62Fk4FPcMuLvW5QjDGNF2a4jAmjM")
        XCTAssertEqual(summary.amount, "10")
        XCTAssertTrue(summary.isIncoming)
        XCTAssertFalse(summary.isOutgoing)
        XCTAssertFalse(summary.isSelfTransfer)
        XCTAssertEqual(summary.transferIndex, 0)
        XCTAssertEqual(summary.id, "hash1|0|0")
        XCTAssertEqual(summary.direction(relativeTo: "sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D"), .incoming)
        XCTAssertEqual(summary.counterpartyAccountId(relativeTo: "sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D"), "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV")
        XCTAssertTrue(summary.isIncoming(relativeTo: "sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D"))
        XCTAssertFalse(summary.isOutgoing(relativeTo: "sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D"))
        XCTAssertFalse(summary.isSelfTransfer(relativeTo: "sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D"))
        XCTAssertEqual(summary.signedAmount(relativeTo: "sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D"), "+10")
        XCTAssertEqual(summary.signedAmount(relativeTo: "sorauﾛ1PgﾉﾀXﾖnWｱﾊｷﾕﾈjｷZﾖrﾅxｲWﾔﾀﾘYヰﾍxｺﾀﾃﾛｽfﾖ2Gｲ8P3LSM"), "10")
    }

    func testExplorerTransferSummariesDeriveSelfTransfer() throws {
        let json = """
        {
            "next_cursor":null,
            "items": [
                {
                    "authority":"sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
                    "created_at":"2025-01-01T00:00:00Z",
                    "kind":"Transfer",
                    "box":\(try explorerTransferBoxFixture(sourceAssetId: "62Fk4FPcMuLvW5QjDGNF2a4jAmjM#sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV", destination: "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV", amount: "10")),
                    "transaction_hash":"hash1",
                    "transaction_status":"Committed",
                    "block":1,
                    "index":0
                }
            ]
        }
        """
        let page = try JSONDecoder().decode(ToriiPage<ToriiExplorerInstructionItem>.self, from: Data(json.utf8))
        let summaries = page.transferSummaries(matchingAccount: "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV")
        XCTAssertEqual(summaries.count, 1)
        let summary = summaries[0]
        XCTAssertEqual(summary.direction, .selfTransfer)
        XCTAssertTrue(summary.isSelfTransfer)
        XCTAssertFalse(summary.isIncoming)
        XCTAssertFalse(summary.isOutgoing)
        XCTAssertEqual(summary.direction(relativeTo: "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV"), .selfTransfer)
        XCTAssertEqual(summary.counterpartyAccountId(relativeTo: "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV"), "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV")
        XCTAssertNil(summary.counterpartyAccountId(relativeTo: "sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D"))
        XCTAssertTrue(summary.isSelfTransfer(relativeTo: "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV"))
        XCTAssertFalse(summary.isIncoming(relativeTo: "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV"))
        XCTAssertFalse(summary.isOutgoing(relativeTo: "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV"))
        XCTAssertEqual(summary.signedAmount(relativeTo: "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV"), "10")
    }

    func testTransferSummarySignedAmountPreservesExistingSign() {
        let outgoing = ToriiExplorerTransferSummary(transactionHash: "hash1",
                                                    block: 1,
                                                    createdAt: "2025-01-01T00:00:00Z",
                                                    status: "Committed",
                                                    authority: "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
                                                    instructionIndex: 0,
                                                    senderAccountId: "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
                                                    receiverAccountId: "sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D",
                                                    assetDefinitionId: "62Fk4FPcMuLvW5QjDGNF2a4jAmjM",
                                                    amount: "-10",
                                                    direction: .outgoing,
                                                    kind: "Transfer",
                                                    transferIndex: 0)
        XCTAssertEqual(outgoing.signedAmount(relativeTo: "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV"), "-10")

        let incoming = ToriiExplorerTransferSummary(transactionHash: "hash2",
                                                    block: 1,
                                                    createdAt: "2025-01-01T00:00:00Z",
                                                    status: "Committed",
                                                    authority: "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
                                                    instructionIndex: 0,
                                                    senderAccountId: "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
                                                    receiverAccountId: "sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D",
                                                    assetDefinitionId: "62Fk4FPcMuLvW5QjDGNF2a4jAmjM",
                                                    amount: "+10",
                                                    direction: .incoming,
                                                    kind: "Transfer",
                                                    transferIndex: 0)
        XCTAssertEqual(incoming.signedAmount(relativeTo: "sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D"), "+10")
    }

    func testExplorerTransferSummariesAssignBatchIndices() throws {
        let json = """
        {
            "next_cursor":null,
            "items": [
                {
                    "authority":"sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
                    "created_at":"2025-01-01T00:00:00Z",
                    "kind":"Transfer",
                    "box":\(try explorerBatchBoxFixture([("sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV", "sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D", "62Fk4FPcMuLvW5QjDGNF2a4jAmjM", "5"), ("sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV", "sorauﾛ1Pﾀﾚｿ1ﾍｶsFｲAfｾeB3ｽヱヱｳcyﾊyｹ1ﾂﾈヰヰ6ﾛヰEAﾃｱｳﾖLPN4XM", "62Fk4FPcMuLvW5QjDGNF2a4jAmjM", "7")])),
                    "transaction_hash":"hash1",
                    "transaction_status":"Committed",
                    "block":1,
                    "index":0
                }
            ]
        }
        """
        let page = try JSONDecoder().decode(ToriiPage<ToriiExplorerInstructionItem>.self, from: Data(json.utf8))
        let summaries = page.transferSummaries()
        XCTAssertEqual(summaries.count, 2)
        XCTAssertEqual(summaries[0].transferIndex, 0)
        XCTAssertEqual(summaries[1].transferIndex, 1)
        XCTAssertEqual(summaries[0].id, "hash1|0|0")
        XCTAssertEqual(summaries[1].id, "hash1|0|1")
    }

    // MARK: - Mint / Burn instruction parsing

    func testExplorerMintInstructionParsedAsSummary() throws {
        // Real Mint response from Iroha explorer API
        let json = """
        {
            "next_cursor":null,
            "items":[{
                "authority":"sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D",
                "created_at":"2026-03-17T14:07:35.576Z",
                "kind":"Mint",
                "box":\(try explorerTransferBoxFixture(sourceAssetId: "62Fk4FPcMuLvW5QjDGNF2a4jAmjM#sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D", destination: "sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D", amount: "500", kind: "Mint")),
                "transaction_hash":"9bca4ad18474058cbbad5bbc49e5e11cf58d90fc28b094ac8f8963a5116fdff5",
                "transaction_status":"Committed",
                "block":17,
                "index":0
            }]
        }
        """
        let page = try JSONDecoder().decode(ToriiPage<ToriiExplorerInstructionItem>.self, from: Data(json.utf8))
        XCTAssertEqual(page.items.count, 1)

        let item = page.items[0]
        XCTAssertEqual(item.kind, "Mint")

        // transferDetails() should parse Mint payloads
        let details = item.transferDetails()
        XCTAssertNotNil(details, "transferDetails() should parse Mint instructions")

        // Generate summaries relative to the mint recipient
        let accountId = "sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D"
        let summaries = page.transferSummaries(relativeTo: accountId)
        XCTAssertEqual(summaries.count, 1, "Mint should produce exactly 1 summary")

        let summary = summaries[0]
        XCTAssertEqual(summary.kind, "Mint")
        XCTAssertEqual(summary.amount, "500")
        XCTAssertEqual(summary.direction, .incoming, "Mint should always be incoming")
        XCTAssertEqual(summary.status, "Committed")
        XCTAssertEqual(summary.transactionHash, "9bca4ad18474058cbbad5bbc49e5e11cf58d90fc28b094ac8f8963a5116fdff5")
        // assetDefinitionId should remain in canonical Base58 form
        XCTAssertFalse(summary.assetDefinitionId.isEmpty)
        XCTAssertFalse(summary.assetDefinitionId.contains(":"),
                       "assetDefinitionId should decode to unprefixed Base58 form")
        // receiverAccountId should be extracted from the canonical asset ID
        XCTAssertFalse(summary.receiverAccountId.isEmpty, "receiverAccountId should not be empty")
    }

}
