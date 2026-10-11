import CryptoKit
import Foundation
import XCTest
@testable import IrohaSwift

// MARK: - Golden vectors

/// `fixtures/torii/list_query/vectors.json`, shared with Torii and every SDK.
private struct ListQueryVectors: Decodable {
    struct FilterCase: Decodable {
        let text: String
        let canonical: String
        let json: ToriiFilter
    }

    struct FilterJSONCase: Decodable {
        let json: ToriiJSONValue
    }

    /// A JSON-form filter that decodes to a different (normalized) tree.
    struct NormalizedFilterCase: Decodable {
        let json: ToriiFilter
        let canonical: String
        let normalized: ToriiJSONValue
    }

    struct SortCase: Decodable {
        let text: String
        let canonical: String
        let json: [String]
    }

    struct SyntaxErrorCase: Decodable {
        let text: String
        let message: String
        let line: Int
        let column: Int
    }

    struct QueryCase: Decodable {
        let body: ToriiJSONValue
        let queryPairs: [[String]]

        private enum CodingKeys: String, CodingKey {
            case body
            case queryPairs = "query_pairs"
        }
    }

    struct PageCase: Decodable {
        let json: ToriiPage<ToriiJSONObject>
        let hasMore: Bool

        private enum CodingKeys: String, CodingKey {
            case json
            case hasMore = "has_more"
        }
    }

    struct BodyErrorCase: Decodable {
        let body: ToriiJSONValue
        let code: String
        let parameter: String
    }

    struct PairErrorCase: Decodable {
        let queryPairs: [[String]]
        let code: String
        let parameter: String

        private enum CodingKeys: String, CodingKey {
            case queryPairs = "query_pairs"
            case code
            case parameter
        }
    }

    let version: Int
    let filters: [FilterCase]
    let filterErrors: [SyntaxErrorCase]
    let jsonFilters: [NormalizedFilterCase]
    let sorts: [SortCase]
    let sortErrors: [SyntaxErrorCase]
    let queries: [QueryCase]
    let pages: [PageCase]
    let queryBodyErrors: [BodyErrorCase]
    let queryPairErrors: [PairErrorCase]

    private enum CodingKeys: String, CodingKey {
        case version
        case filters
        case filterErrors = "filter_errors"
        case jsonFilters = "json_filters"
        case sorts
        case sortErrors = "sort_errors"
        case queries
        case pages
        case queryBodyErrors = "query_body_errors"
        case queryPairErrors = "query_pair_errors"
    }

    /// The filter vectors decoded as plain JSON for structural comparison.
    struct FilterJSONVectors: Decodable {
        let filters: [FilterJSONCase]
    }

    static func fixtureURL() -> URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent() // ToriiCollectionQueryTests.swift
            .deletingLastPathComponent() // IrohaSwiftTests
            .deletingLastPathComponent() // Tests
            .deletingLastPathComponent() // IrohaSwift
            .appendingPathComponent("fixtures/torii/list_query/vectors.json")
    }

    static func load() throws -> (ListQueryVectors, FilterJSONVectors) {
        let data = try Data(contentsOf: fixtureURL())
        return (
            try JSONDecoder().decode(ListQueryVectors.self, from: data),
            try JSONDecoder().decode(FilterJSONVectors.self, from: data)
        )
    }
}

private func jsonValue(_ data: Data) throws -> ToriiJSONValue {
    try JSONDecoder().decode(ToriiJSONValue.self, from: data)
}

final class ToriiCollectionQueryVectorTests: XCTestCase {
    func testFilterVectorsRenderCanonicalTextAndJSON() throws {
        let (vectors, raw) = try ListQueryVectors.load()
        XCTAssertEqual(vectors.version, 1)
        XCTAssertEqual(vectors.filters.count, raw.filters.count)
        XCTAssertFalse(vectors.filters.isEmpty)
        for (index, vector) in vectors.filters.enumerated() {
            let filter = vector.json
            XCTAssertEqual(filter.description, vector.canonical, "canonical text for `\(vector.text)`")
            XCTAssertEqual(try jsonValue(filter.jsonData()), raw.filters[index].json, "JSON form for `\(vector.text)`")
            XCTAssertEqual(try JSONDecoder().decode(ToriiFilter.self, from: filter.jsonData()), filter)
            XCTAssertNoThrow(try filter.validate(), "vector `\(vector.text)` must validate")
        }
    }

    func testJSONFilterVectorsDecodeToTheNormalizedTree() throws {
        let (vectors, _) = try ListQueryVectors.load()
        XCTAssertFalse(vectors.jsonFilters.isEmpty)
        for vector in vectors.jsonFilters {
            let filter = vector.json
            XCTAssertEqual(filter.description, vector.canonical)
            XCTAssertEqual(try jsonValue(filter.jsonData()), vector.normalized, "normalized JSON for `\(vector.canonical)`")
            XCTAssertEqual(try ToriiFilter(jsonData: filter.jsonData()), filter)
            XCTAssertNoThrow(try filter.validate(), "vector `\(vector.canonical)` must validate")
        }
    }

    func testBuilderReproducesFilterVectors() throws {
        let (vectors, _) = try ListQueryVectors.load()
        let byCanonical = Dictionary(uniqueKeysWithValues: vectors.filters.map { ($0.canonical, $0.json) })
        let a = ToriiField("a")
        let tenAndAHalf = try KotodamaDecimal("10.5")
        let wide = try KotodamaInt("340282366920938463463374607431768211455")
        let oneAndAQuarter = try ToriiFilterValue.decimal("1.25")
        let built: [String: ToriiFilter] = [
            #"owned_by = "alice""#: ToriiField("owned_by") == "alice",
            #"owned_by = "alice" and quantity >= "10.5""#:
                ToriiField("owned_by") == "alice" && ToriiField("quantity") >= tenAndAHalf,
            "a = 1": a == 1,
            "a != -2": a != -2,
            #"a < "340282366920938463463374607431768211455""#:
                a < wide,
            #"a <= 0 or b > "1.25""#: a <= 0 || ToriiField("b") > oneAndAQuarter,
            "flag = true and other = false and gone = null":
                ToriiField("flag") == true && ToriiField("other") == false && ToriiField("gone") == ToriiFilterValue.null,
            #"status in ["active", "paused"]"#: ToriiField("status").in(["active", "paused"]),
            "tier not in [1, 2, 3]": ToriiField("tier").notIn([1, 2, 3]),
            "exists(metadata.tier)": ToriiField.metadata("tier").exists,
            "note is null": ToriiField("note").isNull,
            "note is not null": ToriiField("note").isNotNull,
            "not exists(metadata.archived)": !ToriiField.metadata("archived").exists,
            "a = 1 or not b = 2 and c = 3": a == 1 || (!(ToriiField("b") == 2) && ToriiField("c") == 3),
            "(a = 1 or b = 2) and c = 3": (a == 1 || ToriiField("b") == 2) && ToriiField("c") == 3,
            "not (a = 1 and b = 2)": !(a == 1 && ToriiField("b") == 2),
            "not not a = 1": !(!(a == 1)),
            #"metadata.`display-name` = "x""#: ToriiField.metadata("display-name") == "x",
            "`and` = 1": ToriiField("and") == 1,
            "metadata.null = 1": ToriiField.metadata("null") == 1,
            #"text = "quote \" backslash \\ newline \n unicode é""#:
                ToriiField("text") == "quote \" backslash \\ newline \n unicode é",
            #"tx_hash = "hash" and tx_status in ["Approved", "Rejected"]"#:
                ToriiEventFields.txHash == "hash" && ToriiEventFields.txStatus.in(["Approved", "Rejected"]),
            "note = \"del\u{7F} c1\u{85}\"": ToriiField("note") == "del\u{7F} c1\u{85}",
        ]
        XCTAssertEqual(Set(built.keys), Set(byCanonical.keys), "every vector has a builder expression")
        for (canonical, filter) in built {
            XCTAssertEqual(filter, byCanonical[canonical], canonical)
            XCTAssertEqual(filter.description, canonical)
        }
    }

    func testSortVectorsRenderCanonicalSpecificationsAndJSON() throws {
        let (vectors, _) = try ListQueryVectors.load()
        XCTAssertFalse(vectors.sorts.isEmpty)
        for vector in vectors.sorts {
            let keys = try ToriiSortKey.parseList(vector.text)
            XCTAssertEqual(keys.map(\.description).joined(separator: ","), vector.canonical)
            XCTAssertEqual(keys.map(\.description), vector.json)
            XCTAssertEqual(try vector.json.map(ToriiSortKey.init(parsing:)), keys)
        }
        XCTAssertEqual(
            try ToriiSortKey.parseList("-quantity, id ,metadata.`ui-order`"),
            [.descending("quantity"), .ascending("id"), .ascending(.metadata("ui-order"))]
        )
    }

    func testSortErrorVectorsMatchTorii() throws {
        let (vectors, _) = try ListQueryVectors.load()
        XCTAssertFalse(vectors.sortErrors.isEmpty)
        for vector in vectors.sortErrors {
            XCTAssertThrowsError(try ToriiSortKey.parseList(vector.text), vector.text) { error in
                guard let error = error as? ToriiListQueryError else {
                    return XCTFail("expected ToriiListQueryError for `\(vector.text)`, got \(error)")
                }
                XCTAssertEqual(error.code, "invalid_sort")
                let location = vector.text.contains("\n")
                    ? "line \(vector.line), column \(vector.column)"
                    : "column \(vector.column)"
                XCTAssertEqual(error.message, "\(vector.message) (\(location))", vector.text)
            }
        }
    }

    func testQueryVectorsEncodeCanonicalBodiesAndQueryPairs() throws {
        let (vectors, _) = try ListQueryVectors.load()
        // The same queries the Rust reference generates the vectors from.
        let queries = [
            ToriiListQuery(),
            ToriiListQuery(
                filter: ToriiField("owned_by") == "alice" && ToriiField("quantity") > 1,
                sort: [.descending("quantity"), .ascending("id")],
                select: ["id", "quantity"],
                limit: 25,
                includeTotal: true
            ),
            ToriiListQuery(limit: 10, cursor: "q1_abc-DEF"),
        ]
        XCTAssertEqual(queries.count, vectors.queries.count)
        for (query, vector) in zip(queries, vectors.queries) {
            XCTAssertEqual(try jsonValue(query.requestBody()), vector.body)
            let pairs = try query.queryItems().map { [$0.name, $0.value ?? ""] }
            XCTAssertEqual(pairs, vector.queryPairs)
        }
    }

    func testPageVectorsDecode() throws {
        let (vectors, _) = try ListQueryVectors.load()
        XCTAssertFalse(vectors.pages.isEmpty)
        for vector in vectors.pages {
            XCTAssertEqual(vector.json.hasMore, vector.hasMore)
        }
        let first = try XCTUnwrap(vectors.pages.first?.json)
        XCTAssertEqual(first.nextCursor, "q1_next")
        XCTAssertEqual(first.total, 3)
        XCTAssertEqual(first.items, [["id": .string("a")]])
        let last = try XCTUnwrap(vectors.pages.last?.json)
        XCTAssertNil(last.nextCursor)
        XCTAssertNil(last.total)
        XCTAssertTrue(last.items.isEmpty)
    }

    func testRequestErrorVectorsExposeTheToriiCode() throws {
        let (vectors, _) = try ListQueryVectors.load()
        for vector in vectors.queryBodyErrors {
            XCTAssertEqual(ToriiListQueryError.code(forParameter: vector.parameter), vector.code)
        }
        for vector in vectors.queryPairErrors {
            XCTAssertEqual(ToriiListQueryError.code(forParameter: vector.parameter), vector.code)
        }
    }

    func testRepresentableRequestErrorVectorsAreRejectedLocally() throws {
        let aggregate = ToriiAggregate(metrics: [.count(as: "n")])
        let cases: [(ToriiListQuery, String)] = [
            (ToriiListQuery(select: []), "invalid_select"),
            (ToriiListQuery(select: ["id"], aggregate: aggregate), "invalid_select"),
            (ToriiListQuery(limit: 0), "invalid_limit"),
            (ToriiListQuery(cursor: "has space"), "invalid_cursor"),
            (ToriiListQuery(select: "id,,name".split(separator: ",", omittingEmptySubsequences: false)
                .map { ToriiFieldPath(String($0)) }), "invalid_select"),
            (ToriiListQuery(filter: ToriiField("a`b") == 1), "invalid_filter"),
            (ToriiListQuery(aggregate: ToriiAggregate(
                groupBy: ["a", "b", "c", "d", "e", "f", "g", "h", "i"],
                metrics: [.count(as: "n")]
            )), "invalid_aggregate"),
        ]
        for (query, code) in cases {
            XCTAssertThrowsError(try query.requestBody()) { error in
                XCTAssertEqual((error as? ToriiListQueryError)?.code, code, "\(query)")
            }
        }
        for text in ["id:desc", "id:asc"] {
            XCTAssertThrowsError(try ToriiSortKey(parsing: text)) { error in
                XCTAssertEqual((error as? ToriiListQueryError)?.code, "invalid_sort")
            }
        }
        XCTAssertThrowsError(try JSONDecoder().decode(ToriiFilter.self, from: Data(#"{"op":"eq"}"#.utf8)))
    }
}

// MARK: - Builder, rendering and validation

final class ToriiFilterBuilderTests: XCTestCase {
    func testLiteralsFollowTheTextGrammarNumberRule() throws {
        XCTAssertEqual(ToriiFilterValue.integer(7).description, "7")
        XCTAssertEqual(ToriiFilterValue.integer(-7).description, "-7")
        XCTAssertEqual(ToriiFilterValue.integer(UInt64.max).description, "18446744073709551615")
        XCTAssertEqual(ToriiFilterValue.integer(Int64.min).description, "-9223372036854775808")
        XCTAssertEqual(try KotodamaQuantity("25").toriiFilterValue, .integer(25))
        XCTAssertEqual(try KotodamaDecimal("10.5").toriiFilterValue, .string("10.5"))
        XCTAssertEqual(try KotodamaInt("18446744073709551616").toriiFilterValue, .string("18446744073709551616"))
        XCTAssertEqual(try ToriiFilterValue.decimal("-0.25"), .string("-0.25"))
        XCTAssertEqual(try ToriiFilterValue.decimal("42"), .integer(42))
        for invalid in ["1e5", "007", ".5", "1.", "+1", "", "-", "1.2.3"] {
            XCTAssertThrowsError(try ToriiFilterValue.decimal(invalid), invalid) { error in
                XCTAssertEqual((error as? ToriiListQueryError)?.code, "invalid_filter")
            }
        }
        let optional: String? = nil
        XCTAssertEqual(ToriiField("note").eq(optional).description, "note = null")
    }

    func testStringsUseJSONEscapes() {
        let filter = ToriiField("s") == "tab\t cr\r bs\u{08} ff\u{0C} ctl\u{01} del\u{7F} sep\u{2028} \"q\" \\"
        XCTAssertEqual(
            filter.description,
            "s = \"tab\\t cr\\r bs\\b ff\\f ctl\\u0001 del\u{7F} sep\u{2028} \\\"q\\\" \\\\\""
        )
    }

    func testDelAndC1CharactersRenderLiterally() {
        // Only `"`, `\` and U+0000..U+001F are escaped; DEL and C1 stay raw, as in JSON.
        let filter = ToriiField("note") == "x\u{7F}y\u{80}\u{85}\u{9F}z\u{1F}"
        XCTAssertEqual(filter.description, "note = \"x\u{7F}y\u{80}\u{85}\u{9F}z\\u001f\"")
        XCTAssertEqual(filter.jsonString, "{\"args\":[\"note\",\"x\u{7F}y\u{80}\u{85}\u{9F}z\\u001f\"],\"op\":\"eq\"}")
    }

    func testFieldPathsMustNotContainBackticks() throws {
        XCTAssertThrowsError(try (ToriiField("metadata.a`b") == 1).validate()) { error in
            XCTAssertEqual((error as? ToriiListQueryError)?.code, "invalid_filter")
            XCTAssertEqual(
                (error as? ToriiListQueryError)?.message,
                "invalid field `metadata.a`b`: field paths must not contain backticks"
            )
        }
        XCTAssertThrowsError(try ToriiFilter(jsonData: Data(#"{"op":"exists","args":["a`b"]}"#.utf8)).validate()) { error in
            XCTAssertEqual((error as? ToriiListQueryError)?.code, "invalid_filter")
        }
        XCTAssertThrowsError(try ToriiListQuery(select: ["id", "a`b"]).requestBody()) { error in
            XCTAssertEqual((error as? ToriiListQueryError)?.code, "invalid_select")
        }
        XCTAssertThrowsError(try ToriiListQuery(sort: [.ascending("a`b")]).requestBody()) { error in
            XCTAssertEqual((error as? ToriiListQueryError)?.code, "invalid_sort")
        }
        // A backtick in the text form always opens or closes a quoted segment.
        XCTAssertEqual(try ToriiSortKey.parseList("`a-b`.c"), [.ascending("a-b.c")])
    }

    func testSingleOperandConnectivesDecodeToTheirOperand() throws {
        for op in ["and", "or"] {
            let filter = try ToriiFilter(jsonData: Data(#"{"op":"\#(op)","args":[{"op":"eq","args":["a",1]}]}"#.utf8))
            XCTAssertEqual(filter, ToriiField("a") == 1)
            XCTAssertEqual(filter.description, "a = 1")
        }
        let nested = try ToriiFilter(jsonData: Data(
            #"{"op":"and","args":[{"op":"or","args":[{"op":"and","args":[{"op":"eq","args":["a",1]},{"op":"is_null","args":["b"]}]}]},{"op":"or","args":[{"op":"eq","args":["a",1]}]}]}"#
                .utf8
        ))
        XCTAssertEqual(nested, .and([.and([ToriiField("a") == 1, ToriiField("b").isNull]), ToriiField("a") == 1]))
        XCTAssertEqual(nested.description, "(a = 1 and b is null) and a = 1")
        XCTAssertThrowsError(try ToriiFilter(jsonData: Data(#"{"op":"or","args":[]}"#.utf8)))
    }

    func testStructuredMetadataLiteralsAreCompactWithSortedKeys() throws {
        let filter = ToriiField.metadata("tags") == ToriiFilterValue.object(["z": [1, "two"], "a": .null])
        XCTAssertEqual(filter.description, #"metadata.tags = {"a":null,"z":[1,"two"]}"#)
        XCTAssertEqual(filter.jsonString, #"{"args":["metadata.tags",{"a":null,"z":[1,"two"]}],"op":"eq"}"#)
        XCTAssertNoThrow(try filter.validate())
        XCTAssertThrowsError(try (ToriiField("tags") == ToriiFilterValue.array([1])).validate())
    }

    func testFieldPathsQuoteSegmentsThatAreNotIdentifiers() {
        XCTAssertEqual(ToriiFieldPath("owned_by").description, "owned_by")
        XCTAssertEqual(ToriiFieldPath("metadata.ui-order").description, "metadata.`ui-order`")
        XCTAssertEqual(ToriiFieldPath("1st").description, "`1st`")
        XCTAssertEqual(ToriiFieldPath("NOT.in").description, "`NOT`.in")
        XCTAssertEqual(ToriiFieldPath("metadata.exists").description, "metadata.exists")
        XCTAssertEqual(ToriiFieldPath("é").description, "`é`")
    }

    func testJunctionsFlattenAndParenthesizeToKeepTheTree() {
        let a = ToriiField("a") == 1
        let b = ToriiField("b") == 2
        let c = ToriiField("c") == 3
        XCTAssertEqual(a && b && c, .and([a, b, c]))
        XCTAssertEqual(a && (b && c), .and([a, b, c]))
        XCTAssertEqual(a || b || c, .or([a, b, c]))
        XCTAssertEqual(ToriiFilter.or([.or([a, b]), c]).description, "(a = 1 or b = 2) or c = 3")
        XCTAssertEqual(ToriiFilter.and([.and([a, b]), c]).description, "(a = 1 and b = 2) and c = 3")
        XCTAssertEqual(ToriiFilter.all([a]), a)
        XCTAssertNil(ToriiFilter.any([]))
        let includeArchived = false
        let built = ToriiFilter.all {
            a
            if includeArchived {
                b
            }
            for value in [3] {
                ToriiField("c") == value
            }
        }
        XCTAssertEqual(built, a && c)
    }

    func testJSONDecodingAppliesToriiLiteralRules() throws {
        let filter = try ToriiFilter(jsonData: Data(#"{"op":"in","args":["tier",[1,-2,"3.5"]]}"#.utf8))
        XCTAssertEqual(filter, .in("tier", [1, -2, "3.5"]))
        for invalid in [
            #"{"op":"eq","args":["a",1.5]}"#,
            #"{"op":"eq","args":["a",1.0]}"#,
            #"{"op":"eq","args":["a",1e2]}"#,
            #"{"op":"eq","op":"ne","args":["a",1]}"#,
            #"{"op":"eq","args":["a",1],"extra":true}"#,
            #"{"op":"near","args":["a",1]}"#,
            #"{"op":"not","args":[]}"#,
        ] {
            XCTAssertThrowsError(try ToriiFilter(jsonData: Data(invalid.utf8)), invalid)
        }
    }

    func testJSONFormMatchesTheReference() {
        let filter = ToriiField("owned_by") == "alice" && ToriiField("quantity") >= 10 && !ToriiField.metadata("frozen").exists
        XCTAssertEqual(filter.description, #"owned_by = "alice" and quantity >= 10 and not exists(metadata.frozen)"#)
        XCTAssertEqual(
            filter.jsonString,
            #"{"args":[{"args":["owned_by","alice"],"op":"eq"},{"args":["quantity",10],"op":"gte"},{"args":[{"args":["metadata.frozen"],"op":"exists"}],"op":"not"}],"op":"and"}"#
        )
    }

    func testValidationMirrorsToriiLimits() {
        func assertInvalid(_ filter: ToriiFilter, contains needle: String, line: UInt = #line) {
            XCTAssertThrowsError(try filter.validate(), line: line) { error in
                guard let error = error as? ToriiListQueryError else {
                    return XCTFail("unexpected \(error)", line: line)
                }
                XCTAssertEqual(error.code, "invalid_filter", line: line)
                XCTAssertTrue(error.message.contains(needle), "\(error.message)", line: line)
            }
        }
        var deep: ToriiFilter = ToriiField("a") == 1
        for _ in 0..<11 {
            deep = !deep
        }
        assertInvalid(deep, contains: "nesting depth")
        assertInvalid(.and([]), contains: "at least one operand")
        assertInvalid(ToriiField("a").in([Int]()), contains: "must not be empty")
        assertInvalid(ToriiField("a").in([1, 1]), contains: "must be unique")
        assertInvalid(.in("a", [1, "x"]), contains: "strings, numbers or booleans")
        XCTAssertNoThrow(try ToriiFilter.in("metadata.a", [1, "x"]).validate())
        XCTAssertNoThrow(try ToriiField("a").in([ToriiFilterValue.integer(1), .string("1.5")]).validate())
        assertInvalid(ToriiField("a") <= true, contains: "range comparisons")
        assertInvalid(ToriiField("a b") == 1, contains: "whitespace")
        assertInvalid(ToriiField("a..b") == 1, contains: "segments must not be empty")
        assertInvalid(ToriiField("") == 1, contains: "must not be empty")
        assertInvalid(ToriiField(String(repeating: "x", count: 257)) == 1, contains: "256 bytes")
        assertInvalid(ToriiField("a").in(Array(0..<1_025)), contains: "membership list size")
    }

    func testNestedFractionalNumbersAreRejected() {
        for json in [
            #"{"op":"eq","args":["metadata.x",{"a":[1,{"b":1.5}]}]}"#,
            #"{"op":"in","args":["a",[1,2.5]]}"#,
            #"{"op":"eq","args":["metadata.x",[1e3]]}"#,
        ] {
            XCTAssertThrowsError(try ToriiFilter(jsonData: Data(json.utf8)), json)
        }
        XCTAssertNoThrow(try ToriiFilter(jsonData: Data(#"{"op":"eq","args":["metadata.x",{"a":[1,{"b":"1.5"}]}]}"#.utf8)))
    }
}

// MARK: - List query encoding

final class ToriiListQueryTests: XCTestCase {
    func testRequestBodyIsCanonicalAndDeterministic() throws {
        let query = ToriiListQuery(
            filter: ToriiField("quantity") > 0,
            sort: [.descending("supply")],
            aggregate: ToriiAggregate(
                groupBy: ["asset"],
                metrics: [.count(as: "holders"), .sum("quantity", as: "supply")],
                havingText: "holders >= 10"
            ),
            limit: 20,
            cursor: "c_1",
            includeTotal: true
        )
        XCTAssertEqual(
            String(decoding: try query.requestBody(), as: UTF8.self),
            #"{"aggregate":{"group_by":["asset"],"having":"holders >= 10","metrics":[{"alias":"holders","fn":"count"},{"alias":"supply","field":"quantity","fn":"sum"}]},"cursor":"c_1","filter":{"args":["quantity",0],"op":"gt"},"include_total":true,"limit":20,"sort":["-supply"]}"#
        )
        XCTAssertThrowsError(try query.queryItems()) { error in
            XCTAssertEqual((error as? ToriiListQueryError)?.code, "invalid_aggregate")
        }
        XCTAssertEqual(String(decoding: try ToriiListQuery().requestBody(), as: UTF8.self), "{}")
    }

    func testAggregatesAreBoundedAndTheirPathsValidated() throws {
        func aggregateQuery(groups: Int, metrics: Int) -> ToriiListQuery {
            ToriiListQuery(aggregate: ToriiAggregate(
                groupBy: (0..<groups).map { ToriiFieldPath("metadata.k\($0)") },
                metrics: (0..<metrics).map { ToriiAggregate.Metric.count(as: "m\($0)") }
            ))
        }
        XCTAssertNoThrow(
            try aggregateQuery(groups: ToriiAggregate.maximumGroupBy, metrics: ToriiAggregate.maximumMetrics).requestBody()
        )
        let count = ToriiAggregate.Metric.count(as: "n")
        let rejected: [(ToriiListQuery, String)] = [
            (aggregateQuery(groups: ToriiAggregate.maximumGroupBy + 1, metrics: 1), "`group_by` lists at most 8 fields"),
            (aggregateQuery(groups: 0, metrics: ToriiAggregate.maximumMetrics + 1), "`metrics` lists at most 16 metrics"),
            (
                ToriiListQuery(aggregate: ToriiAggregate(groupBy: ["a..b"], metrics: [count])),
                "invalid field `a..b`: field path segments must not be empty"
            ),
            (
                ToriiListQuery(aggregate: ToriiAggregate(groupBy: ["a`b"], metrics: [count])),
                "invalid field `a`b`: field paths must not contain backticks"
            ),
            (
                ToriiListQuery(aggregate: ToriiAggregate(metrics: [.sum("a b", as: "s")])),
                "invalid field `a b`: field paths must not contain whitespace or control characters"
            ),
        ]
        for (query, message) in rejected {
            XCTAssertThrowsError(try query.requestBody(), message) { error in
                XCTAssertEqual((error as? ToriiListQueryError)?.code, "invalid_aggregate", message)
                XCTAssertEqual((error as? ToriiListQueryError)?.message, message)
            }
        }
    }

    func testTextFiltersPassThroughVerbatim() throws {
        let text = #"owned_by = 'alice'   AND quantity>=10.5"#
        let query = ToriiListQuery(filterText: text, limit: 5)
        XCTAssertEqual(String(decoding: try query.requestBody(), as: UTF8.self), #"{"filter":"owned_by = 'alice'   AND quantity>=10.5","limit":5}"#)
        XCTAssertEqual(try query.queryItems().first?.value, text)
        XCTAssertThrowsError(try ToriiListQuery(filterText: "  ").requestBody()) { error in
            XCTAssertEqual((error as? ToriiListQueryError)?.code, "invalid_filter")
        }
    }

    func testSortAndSelectValidation() {
        XCTAssertThrowsError(try ToriiListQuery(sort: [.ascending("id"), .descending("id")]).requestBody()) { error in
            XCTAssertEqual((error as? ToriiListQueryError)?.message, "sort key `id` appears more than once")
        }
        XCTAssertThrowsError(try ToriiListQuery(sort: (0..<9).map { .ascending(ToriiFieldPath("f\($0)")) }).requestBody()) { error in
            XCTAssertEqual((error as? ToriiListQueryError)?.code, "invalid_sort")
        }
        XCTAssertThrowsError(try ToriiListQuery(select: ["id", "id"]).requestBody()) { error in
            XCTAssertEqual((error as? ToriiListQueryError)?.code, "invalid_select")
        }
        XCTAssertThrowsError(try ToriiListQuery(aggregate: ToriiAggregate(metrics: [])).requestBody()) { error in
            XCTAssertEqual((error as? ToriiListQueryError)?.code, "invalid_aggregate")
        }
        XCTAssertThrowsError(try ToriiListQuery(limit: Int(UInt32.max) + 1).requestBody()) { error in
            XCTAssertEqual((error as? ToriiListQueryError)?.code, "invalid_limit")
        }
    }

    func testFluentModifiersAndContinuation() throws {
        let query = ToriiListQuery()
            .filtered(by: ToriiField("id") == "x")
            .sorted(by: ToriiField("id").descending)
            .selecting("id")
            .limited(to: 3)
            .includingTotal()
        XCTAssertEqual(try query.queryItems().map(\.name), ["filter", "sort", "select", "limit", "include_total"])
        XCTAssertEqual(query.next(after: ToriiPage<Int>(items: [], nextCursor: "n1"))?.cursor, "n1")
        XCTAssertNil(query.next(after: ToriiPage<Int>(items: [])))
    }

    func testNewCollectionRowsDecodeStructuredPayloadsAndLedgerPositions() throws {
        let decoder = JSONDecoder()
        let permissions = try decoder.decode(ToriiPage<ToriiAccountPermission>.self, from: Data(#"{"items":[{"name":"CanSetParameters","payload":null},{"name":"CanSetMetadata","payload":{"scope":7}}],"next_cursor":null,"total":2}"#.utf8))
        XCTAssertEqual(permissions.items.map(\.name), ["CanSetParameters", "CanSetMetadata"])
        let history = try decoder.decode(ToriiAccountHistoryRow.self, from: Data(#"{"id":"movement","block_height":4,"block_index":2,"movement_index":3,"amount":"1.25"}"#.utf8))
        XCTAssertEqual(history.blockHeight, 4)
        XCTAssertEqual(history.blockIndex, 2)
        XCTAssertEqual(history.movementIndex, 3)
        XCTAssertEqual(history.amount, "1.25")
    }

    func testPageDecodingIsStrictAboutTheEnvelope() throws {
        let decoder = JSONDecoder()
        let page = try decoder.decode(ToriiPage<ToriiJSONObject>.self, from: Data(#"{"items":[{"id":"a","extra":1}],"next_cursor":null,"total":null}"#.utf8))
        XCTAssertNil(page.nextCursor)
        XCTAssertNil(page.total)
        XCTAssertFalse(page.hasMore)
        for invalid in [#"{"items":[]}"#, #"{"items":[],"next_cursor":""}"#, #"{"items":[],"next_cursor":null,"has_more":false}"#, #"{"items":[{}],"next_cursor":null,"total":0}"#, #"{"next_cursor":null}"#, #"{"items":[],"next_cursor":5}"#, #"{"items":[],"total":-1}"#, #"{"items":{}}"#] {
            XCTAssertThrowsError(try decoder.decode(ToriiPage<ToriiJSONObject>.self, from: Data(invalid.utf8)), invalid)
        }
    }

    func testQueryStringEncodingEscapesPlusAndReservedCharacters() {
        XCTAssertEqual(
            ToriiQueryStringEncoding.encode([URLQueryItem(name: "filter", value: #"note = "a+b&c=d""#)]),
            "filter=note%20%3D%20%22a%2Bb%26c%3Dd%22"
        )
    }

    func testStructuredLiteralsTravelOnlyInTheJSONForm() throws {
        let filter = ToriiField.metadata("tags") == ToriiFilterValue.array(["a", "b"])
        XCTAssertTrue(filter.hasStructuredLiterals)
        XCTAssertFalse((ToriiField("a") == 1).hasStructuredLiterals)
        let query = ToriiListQuery(filter: filter, limit: 5)
        XCTAssertEqual(String(decoding: try query.requestBody(), as: UTF8.self),
                       #"{"filter":{"args":["metadata.tags",["a","b"]],"op":"eq"},"limit":5}"#)
        XCTAssertThrowsError(try query.queryItems()) { error in
            XCTAssertEqual((error as? ToriiListQueryError)?.code, "invalid_filter")
        }
        let nested = ToriiField("a") == 1 || !ToriiFilter.in("metadata.x", [ToriiFilterValue.object(["k": 1])])
        XCTAssertTrue(nested.hasStructuredLiterals)
        XCTAssertThrowsError(try ToriiListQuery(filter: nested).queryItems())
        XCTAssertNoThrow(try ToriiListQuery(filterText: #"metadata.tags = "a""#).queryItems())
    }
}

// MARK: - Pager

private actor FetchLog {
    private(set) var queries: [ToriiListQuery] = []

    func record(_ query: ToriiListQuery) {
        queries.append(query)
    }
}

final class ToriiPageSequenceTests: XCTestCase {
    private func pages(_ cursors: [String?], log: FetchLog) -> ToriiPageSequence<Int> {
        let query = ToriiListQuery(limit: 2, includeTotal: true)
        return ToriiPageSequence(query: query) { query in
            await log.record(query)
            let index: Int
            switch query.cursor {
            case nil: index = 0
            case let cursor?: index = Int(cursor.dropFirst())!
            }
            return ToriiPage(
                items: [index * 2, index * 2 + 1],
                nextCursor: cursors[index],
                total: query.includeTotal ? 6 : nil
            )
        }
    }

    func testPagesAreFetchedOnDemandAndFollowCursors() async throws {
        let log = FetchLog()
        var iterator = pages(["c1", "c2", nil], log: log).makeAsyncIterator()
        let queriesBeforeIteration = await log.queries
        XCTAssertTrue(queriesBeforeIteration.isEmpty, "nothing is fetched before the first next()")
        let first = try await iterator.next()
        XCTAssertEqual(first?.total, 6)
        let queriesAfterFirstPage = await log.queries
        XCTAssertEqual(queriesAfterFirstPage.count, 1)
        let second = try await iterator.next()
        XCTAssertNil(second?.total, "only the first page pays for the total")
        let third = try await iterator.next()
        XCTAssertEqual(third?.items, [4, 5])
        let end = try await iterator.next()
        XCTAssertNil(end)
        let queries = await log.queries
        XCTAssertEqual(queries.map(\.cursor), [nil, "c1", "c2"])
        XCTAssertEqual(queries.map(\.includeTotal), [true, false, false])
        XCTAssertEqual(queries.map(\.limit), [2, 2, 2])
    }

    func testItemSequenceFlattensPagesLazily() async throws {
        let log = FetchLog()
        var collected: [Int] = []
        for try await item in ToriiItemSequence(pages: pages(["c1", "c2", nil], log: log)) {
            collected.append(item)
            if item == 2 {
                break
            }
        }
        XCTAssertEqual(collected, [0, 1, 2])
        let queries = await log.queries
        XCTAssertEqual(queries.count, 2, "breaking out stops paging")
    }

    func testRepeatedCursorStopsWithAnError() async throws {
        let sequence = ToriiPageSequence<Int>(query: ToriiListQuery(cursor: "same")) { _ in
            ToriiPage(items: [1], nextCursor: "same")
        }
        var iterator = sequence.makeAsyncIterator()
        await XCTAssertThrowsErrorAsync(try await iterator.next())
        let afterError = try await iterator.next()
        XCTAssertNil(afterError)
    }

    func testCursorCycleStopsBeforeFetchingAnotherPage() async throws {
        let log = FetchLog()
        let sequence = pages(["c1", "c2", "c1"], log: log)
        var iterator = sequence.makeAsyncIterator()
        _ = try await iterator.next()
        _ = try await iterator.next()
        await XCTAssertThrowsErrorAsync(try await iterator.next())
        let stopped = try await iterator.next()
        XCTAssertNil(stopped)
        let queries = await log.queries
        XCTAssertEqual(queries.count, 3)
    }

    func testCancellationStopsBeforeTheNextRequest() async throws {
        let log = FetchLog()
        let sequence = pages(["c1", "c2", nil], log: log)
        let task = Task {
            var iterator = sequence.makeAsyncIterator()
            _ = try await iterator.next()
            withUnsafeCurrentTask { $0?.cancel() }
            return try await iterator.next()
        }
        do {
            _ = try await task.value
            XCTFail("expected cancellation")
        } catch {
            XCTAssertTrue(error is CancellationError, "\(error)")
        }
        let queries = await log.queries
        XCTAssertEqual(queries.count, 1)
    }
}

// MARK: - Collections over HTTP

/// URL-protocol stub keyed by host, so concurrent tests never share a handler.
final class CollectionQueryStubProtocol: URLProtocol {
    typealias Handler = (URLRequest) throws -> (HTTPURLResponse, Data)

    private static let lock = NSLock()
    private static var handlers: [String: Handler] = [:]

    static func register(_ handler: @escaping Handler) -> URL {
        let host = "collections-\(UUID().uuidString.lowercased()).test"
        lock.lock()
        handlers[host] = handler
        lock.unlock()
        return URL(string: "https://\(host)")!
    }

    private static func handler(for host: String?) -> Handler? {
        lock.lock()
        defer { lock.unlock() }
        return host.flatMap { handlers[$0] }
    }

    override class func canInit(with request: URLRequest) -> Bool { true }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        guard let handler = Self.handler(for: request.url?.host) else {
            client?.urlProtocol(self, didFailWithError: URLError(.unsupportedURL))
            return
        }
        do {
            let (response, data) = try handler(request)
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: data)
            client?.urlProtocolDidFinishLoading(self)
        } catch {
            client?.urlProtocol(self, didFailWithError: error)
        }
    }

    override func stopLoading() {}
}

private func jsonResponse(_ request: URLRequest, status: Int = 200, _ body: String,
                          headers: [String: String] = [:]) -> (HTTPURLResponse, Data) {
    var fields = ["Content-Type": "application/json"]
    fields.merge(headers) { _, new in new }
    return (HTTPURLResponse(url: request.url!, statusCode: status, httpVersion: nil, headerFields: fields)!, Data(body.utf8))
}

final class ToriiCollectionClientTests: XCTestCase {
    private let signingSeed = Data(repeating: 0x41, count: 32)
    private let accountId = "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV"

    private func client(baseURL: URL,
                        signed: Bool = false,
                        freshness: ToriiCanonicalRequestFreshness? = nil) throws -> ToriiClient {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [CollectionQueryStubProtocol.self]
        let auth = signed
            ? ToriiCanonicalRequestAuth(
                accountId: try Keypair(privateKeyBytes: signingSeed).accountId(networkPrefix: AccountId.defaultNetworkPrefix),
                privateKey: signingSeed
            )
            : nil
        return ToriiClient(
            baseURL: baseURL,
            session: URLSession(configuration: configuration),
            localSigningContext: ToriiLocalSigningContext(networkId: TestNetworkIds.canonical),
            canonicalRequestAuth: auth,
            canonicalRequestFreshness: freshness
        )
    }

    private func canonicalHeaders(_ request: URLRequest) -> [String?] {
        [
            ToriiCanonicalRequest.headerAccount,
            ToriiCanonicalRequest.headerSignature,
            ToriiCanonicalRequest.headerTimestampMs,
            ToriiCanonicalRequest.headerNonce,
        ].map { request.value(forHTTPHeaderField: $0) }
    }

    func testPagePostsTheCanonicalBodyAnonymouslyAndDecodesRows() async throws {
        let query = ToriiListQuery(
            filter: ToriiDomain.Fields.ownedBy == accountId,
            sort: [ToriiDomain.Fields.id.descending],
            limit: 2,
            includeTotal: true
        )
        let expectedBody = try query.requestBody()
        let baseURL = CollectionQueryStubProtocol.register { request in
            XCTAssertEqual(request.httpMethod, "POST")
            XCTAssertEqual(request.url?.path, "/v1/domains/query")
            XCTAssertNil(request.url?.query)
            XCTAssertEqual(request.value(forHTTPHeaderField: "Content-Type"), "application/json")
            XCTAssertEqual(request.value(forHTTPHeaderField: "Accept"), "application/json")
            XCTAssertEqual(toriiClientTestBodyData(from: request), expectedBody)
            XCTAssertEqual(self.canonicalHeaders(request).compactMap { $0 }, [], "anonymous reads carry no signature")
            return jsonResponse(request, """
            {"items":[{"id":"wonderland","owned_by":"\(self.accountId)","logo":null,"metadata":{"tier":2},"new_field":true},
                      {"id":"looking_glass","owned_by":"\(self.accountId)"}],
             "next_cursor":"q1_next","total":5}
            """)
        }
        let page = try await client(baseURL: baseURL).domains.page(query)
        XCTAssertEqual(page.items.map(\.id), ["wonderland", "looking_glass"])
        XCTAssertEqual(page.items.first?.metadata["tier"], .number(2))
        XCTAssertEqual(page.items.last?.metadata, [:])
        XCTAssertEqual(page.nextCursor, "q1_next")
        XCTAssertEqual(page.total, 5)
        XCTAssertTrue(page.hasMore)
    }

    func testSignedClientsSignTheExactQueryRequest() async throws {
        let baseURL = CollectionQueryStubProtocol.register { request in
            let headers = self.canonicalHeaders(request)
            XCTAssertTrue(headers.allSatisfy { $0 != nil }, "signed reads carry every canonical header")
            let body = toriiClientTestBodyData(from: request) ?? Data()
            let message = try ToriiCanonicalRequest.signatureMessage(
                networkId: TestNetworkIds.canonical,
                method: "POST",
                url: request.url!,
                body: body,
                timestampMs: UInt64(headers[2]!)!,
                nonce: headers[3]!
            )
            let signature = try XCTUnwrap(Data(base64Encoded: headers[1]!))
            let publicKey = try Curve25519.Signing.PrivateKey(rawRepresentation: self.signingSeed).publicKey
            XCTAssertTrue(publicKey.isValidSignature(signature, for: message))
            return jsonResponse(request, #"{"items":[],"next_cursor":null}"#)
        }
        let page = try await client(baseURL: baseURL, signed: true).rwas.page(ToriiListQuery(limit: 1))
        XCTAssertTrue(page.items.isEmpty)
        XCTAssertFalse(page.hasMore)
    }

    func testReusedCredentialsNeverReplayANonce() async throws {
        let lock = NSLock()
        var nonces: [String] = []
        let baseURL = CollectionQueryStubProtocol.register { request in
            lock.lock()
            nonces.append(request.value(forHTTPHeaderField: ToriiCanonicalRequest.headerNonce) ?? "")
            lock.unlock()
            return jsonResponse(request, #"{"items":[],"next_cursor":null}"#)
        }
        let torii = try client(baseURL: baseURL, signed: true)
        _ = try await torii.rwas.page(ToriiListQuery(limit: 1))
        _ = try await torii.rwas.page(ToriiListQuery(limit: 1))
        XCTAssertEqual(nonces.count, 2)
        XCTAssertFalse(nonces.contains(""))
        XCTAssertNotEqual(nonces.first, nonces.last, "one credential must not reuse a nonce")
    }

    func testInjectedFreshnessSuppliesEachSignedRequest() async throws {
        let baseURL = CollectionQueryStubProtocol.register { request in
            XCTAssertEqual(request.value(forHTTPHeaderField: ToriiCanonicalRequest.headerTimestampMs), "1700000000123")
            XCTAssertEqual(request.value(forHTTPHeaderField: ToriiCanonicalRequest.headerNonce), "collection-test-nonce")
            return jsonResponse(request, #"{"items":[],"next_cursor":null}"#)
        }
        let freshness = ToriiCanonicalRequestFreshness(
            timestampMs: { 1_700_000_000_123 },
            nonce: { "collection-test-nonce" }
        )
        _ = try await client(baseURL: baseURL, signed: true, freshness: freshness).nfts.page()
    }

    func testItemsFollowCursorsAcrossPages() async throws {
        let log = NSLock()
        var bodies: [String] = []
        let baseURL = CollectionQueryStubProtocol.register { request in
            let body = String(decoding: toriiClientTestBodyData(from: request) ?? Data(), as: UTF8.self)
            log.lock()
            bodies.append(body)
            log.unlock()
            let page = body.contains("\"cursor\":\"q1_2\"")
                ? #"{"items":[{"id":"nft-3","owned_by":"o","metadata":{}}],"next_cursor":null}"#
                : #"{"items":[{"id":"nft-1","owned_by":"o"},{"id":"nft-2","owned_by":"o"}],"next_cursor":"q1_2","total":3}"#
            return jsonResponse(request, page)
        }
        var ids: [String] = []
        for try await nft in try client(baseURL: baseURL).nfts.items(ToriiListQuery(limit: 2, includeTotal: true)) {
            ids.append(nft.id)
        }
        XCTAssertEqual(ids, ["nft-1", "nft-2", "nft-3"])
        XCTAssertEqual(bodies, [#"{"include_total":true,"limit":2}"#, #"{"cursor":"q1_2","limit":2}"#])
    }

    func testErrorEnvelopeSurfacesCodeMessageAndDetails() async throws {
        let baseURL = CollectionQueryStubProtocol.register { request in
            jsonResponse(request, status: 400, """
            {"code":"invalid_filter","message":"invalid `filter`: unknown field `colour`",
             "details":{"field":"filter","expected":"id, owned_by","actual":"colour","hint":"did you mean `owned_by`?"}}
            """, headers: ["X-Iroha-Reject-Code": "QUERY_REJECTED"])
        }
        do {
            _ = try await client(baseURL: baseURL).domains.page(ToriiListQuery(filterText: #"colour = "red""#))
            XCTFail("expected an error")
        } catch let error as ToriiClientError {
            guard case let .api(apiError) = error else {
                return XCTFail("expected .api, got \(error)")
            }
            XCTAssertEqual(apiError.status, 400)
            XCTAssertEqual(apiError.code, "invalid_filter")
            XCTAssertEqual(apiError.message, "invalid `filter`: unknown field `colour`")
            XCTAssertEqual(apiError.details?.field, "filter")
            XCTAssertEqual(apiError.details?.expected, "id, owned_by")
            XCTAssertEqual(apiError.details?.actual, "colour")
            XCTAssertEqual(apiError.details?.hint, "did you mean `owned_by`?")
            XCTAssertEqual(apiError.rejectCode, "QUERY_REJECTED")
            XCTAssertEqual(error.code, "invalid_filter")
            XCTAssertEqual(error.status, 400)
            XCTAssertTrue(error.localizedDescription.contains("invalid_filter"))
        }
    }

    func testNonEnvelopeErrorsKeepTheStatusAndBody() async throws {
        let baseURL = CollectionQueryStubProtocol.register { request in
            (HTTPURLResponse(url: request.url!, statusCode: 502, httpVersion: nil, headerFields: ["Content-Type": "text/plain"])!,
             Data("bad gateway".utf8))
        }
        do {
            _ = try await client(baseURL: baseURL).accounts.page()
            XCTFail("expected an error")
        } catch let ToriiClientError.api(error) {
            XCTAssertEqual(error.status, 502)
            XCTAssertNil(error.code)
            XCTAssertEqual(error.message, "bad gateway")
        }
    }

    func testInvalidQueriesAreRejectedBeforeAnyRequest() async throws {
        let baseURL = CollectionQueryStubProtocol.register { request in
            XCTFail("no request may be sent")
            return jsonResponse(request, "{}")
        }
        let torii = try client(baseURL: baseURL)
        await XCTAssertThrowsErrorAsync(try await torii.assetDefinitions.page(ToriiListQuery(limit: 0))) { error in
            guard case let ToriiClientError.invalidQuery(queryError) = error else {
                return XCTFail("expected .invalidQuery, got \(error)")
            }
            XCTAssertEqual(queryError.code, "invalid_limit")
            XCTAssertEqual((error as? ToriiClientError)?.code, "invalid_limit")
        }
        await XCTAssertThrowsErrorAsync(try await torii.assetDefinitions.page(ToriiListQuery(select: ["id"]))) { error in
            guard case let ToriiClientError.invalidQuery(queryError) = error else {
                return XCTFail("expected .invalidQuery, got \(error)")
            }
            XCTAssertEqual(queryError.code, "invalid_select")
        }
    }

    func testProjectionsAndAggregatesDecodeAsJSONObjects() async throws {
        let baseURL = CollectionQueryStubProtocol.register { request in
            let body = String(decoding: toriiClientTestBodyData(from: request) ?? Data(), as: UTF8.self)
            XCTAssertEqual(request.url?.path, "/v1/assets/62Fk4FPcMuLvW5QjDGNF2a4jAmjM/holders/query")
            XCTAssertEqual(body, #"{"aggregate":{"group_by":["scope"],"metrics":[{"alias":"supply","field":"quantity","fn":"sum"}]}}"#)
            return jsonResponse(request, #"{"items":[{"scope":"global","supply":"12.5"}],"next_cursor":null}"#)
        }
        let query = ToriiListQuery(aggregate: ToriiAggregate(groupBy: ["scope"], metrics: [.sum("quantity", as: "supply")]))
        let page = try await client(baseURL: baseURL)
            .assetHolders(of: "62Fk4FPcMuLvW5QjDGNF2a4jAmjM")
            .page(query, as: ToriiJSONObject.self)
        XCTAssertEqual(page.items, [["scope": .string("global"), "supply": .string("12.5")]])
    }

    func testAccountScopedCollectionsEncodeTheAccountPath() async throws {
        let taira = try AccountAddress
            .fromAccount(publicKey: Keypair(privateKeyBytes: Data(repeating: 0x61, count: 32)).publicKey)
            .toI105(networkPrefix: TairaTestnetProfile.i105Discriminant)
        let paths = NSLock()
        var seen: [String] = []
        let baseURL = CollectionQueryStubProtocol.register { request in
            paths.lock()
            seen.append(request.url?.path ?? "")
            paths.unlock()
            if request.url?.path.hasSuffix("/assets/query") == true {
                return jsonResponse(request, """
                {"items":[{"asset":"62Fk4FPcMuLvW5QjDGNF2a4jAmjM","asset_name":"Gold","asset_alias":null,
                           "scope":"global","account_id":"\(taira)","quantity":"1.5","primary_alias":"x"}],
                 "next_cursor":null}
                """)
            }
            return jsonResponse(request, """
            {"items":[{"entrypoint_hash":"aa","block_height":5,"block_index":0,"block_hash":"bb","authority":"\(taira)",
                       "entrypoint_kind":"Transaction","timestamp_ms":1,"result_ok":true,
                       "asset_ids":["62Fk4FPcMuLvW5QjDGNF2a4jAmjM#\(taira)"],"asset_definition_ids":["62Fk4FPcMuLvW5QjDGNF2a4jAmjM"],
                       "metadata":{}}],
             "next_cursor":null}
            """)
        }
        let torii = try client(baseURL: baseURL.appendingPathComponent("api"))
        let assets = try await torii.accountAssets(of: taira).page()
        XCTAssertEqual(assets.items.first?.quantity.canonicalString, "1.5")
        XCTAssertNil(assets.items.first?.assetAlias)
        let transactions = try await torii.accountTransactions(of: taira).page(
            ToriiListQuery(filter: ToriiTransaction.Fields.resultOk == true)
        )
        XCTAssertEqual(transactions.items.first?.entrypointKind, "Transaction")
        XCTAssertEqual(transactions.items.first?.timestampMs, 1)
        XCTAssertEqual(transactions.items.first?.blockHeight, 5)
        XCTAssertEqual(transactions.items.first?.assetDefinitionIds, ["62Fk4FPcMuLvW5QjDGNF2a4jAmjM"])
        XCTAssertEqual(seen, ["/api/v1/accounts/\(taira)/assets/query", "/api/v1/accounts/\(taira)/transactions/query"])
    }

    func testMalformedAccountLiteralsAreRejectedBeforeAnyRequest() async throws {
        let baseURL = CollectionQueryStubProtocol.register { request in
            XCTFail("no request may be sent")
            return jsonResponse(request, "{}")
        }
        let torii = try client(baseURL: baseURL)
        await XCTAssertThrowsErrorAsync(try await torii.accountAssets(of: "  \(accountId)  ").page()) { error in
            guard case let ToriiClientError.invalidPayload(reason) = error else {
                return XCTFail("expected invalidPayload, got \(error)")
            }
            XCTAssertEqual(reason, "accountId must not contain surrounding whitespace.")
        }
        await XCTAssertThrowsErrorAsync(try await torii.accountTransactions(of: "\(accountId)%2Fother").page())
        await XCTAssertThrowsErrorAsync(try await torii.accounts.get("not an account"))
        await XCTAssertThrowsErrorAsync(try await torii.assetHolders(of: " ").page())
    }

    func testGetReadsOneRowByIdentifier() async throws {
        let baseURL = CollectionQueryStubProtocol.register { request in
            let body = String(decoding: toriiClientTestBodyData(from: request) ?? Data(), as: UTF8.self)
            if request.url?.path == "/v1/accounts/query" {
                XCTAssertEqual(body, #"{"filter":{"args":["id","\#(self.accountId)"],"op":"eq"},"limit":1}"#)
                return jsonResponse(request, #"{"items":[{"id":"\#(self.accountId)","label":"Alice","uaid":null}],"next_cursor":null}"#)
            }
            XCTAssertEqual(request.url?.path, "/v1/assets/definitions/query")
            return jsonResponse(request, #"{"items":[],"next_cursor":null}"#)
        }
        let torii = try client(baseURL: baseURL)
        let account = try await torii.accounts.get(accountId)
        XCTAssertEqual(account?.label, "Alice")
        XCTAssertNil(account?.uaid)
        let missing = try await torii.assetDefinitions.get("62Fk4FPcMuLvW5QjDGNF2a4jAmjM")
        XCTAssertNil(missing)
    }

    func testRowsDecodeTheSpecifiedFields() throws {
        let decoder = JSONDecoder()
        let definition = try decoder.decode(ToriiAssetDefinition.self, from: Data("""
        {"id":"62Fk4FPcMuLvW5QjDGNF2a4jAmjM","name":"Gold","alias":"gold#issuer","owned_by":"o","owning_domain":"issuer.main",
         "mintable":"Infinitely","description":null,"logo":"https://logo","spec":{"scale":2},"balance_scope_policy":"Global",
         "alias_binding":{"alias":"gold#issuer","status":"active","lease_expiry_ms":10,"grace_until_ms":null,"bound_at_ms":5},
         "metadata":{"k":"v"}}
        """.utf8))
        XCTAssertEqual(definition.aliasBinding?.boundAtMs, 5)
        XCTAssertEqual(definition.spec, .object(["scale": .number(2)]))
        XCTAssertEqual(definition.metadata["k"], .string("v"))

        let rwa = try decoder.decode(ToriiRwa.self, from: Data("""
        {"id":"lot-1$commodities.sora","owned_by":"o","primary_reference":"vault://1","status":"active",
         "quantity":"10","is_frozen":false,"metadata":{}}
        """.utf8))
        XCTAssertEqual(rwa.quantity?.canonicalString, "10")

        let repo = try decoder.decode(ToriiRepoAgreement.self, from: Data("""
        {"id":"repo-1","initiator":"a","counterparty":"b","custodian":null,"status":"active","cash_source":"initiator",
         "cash_leg":{"asset_definition_id":"cash","quantity":"100","metadata":{}},
         "collateral_leg":{"asset_definition_id":"bond","quantity":"110.5","metadata":{"isin":"X"}},
         "collateral_custody_asset":"bond","rate_bps":250,"maturity_timestamp_ms":3,"initiated_timestamp_ms":1,
         "last_margin_check_timestamp_ms":2,"settlement_timestamp_ms":null,
         "governance":{"haircut_bps":500,"margin_frequency_secs":60}}
        """.utf8))
        XCTAssertEqual(repo.collateralLeg?.quantity?.canonicalString, "110.5")
        XCTAssertNil(repo.custodian)
        XCTAssertEqual(repo.governance?.haircutBps, 500)

        let holder = try decoder.decode(ToriiAssetHolder.self, from: Data("""
        {"account_id":"a","asset":"62Fk4FPcMuLvW5QjDGNF2a4jAmjM","scope":"dataspace:1","quantity":"0"}
        """.utf8))
        XCTAssertEqual(holder.scope, "dataspace:1")

        for quantity in ["-1", "01", "1.0", " 1", "1e0"] {
            XCTAssertThrowsError(try decoder.decode(ToriiAssetHolder.self, from: Data("""
            {"account_id":"a","asset":"x","scope":"global","quantity":"\(quantity)"}
            """.utf8)), quantity)
        }

        let transaction = try decoder.decode(ToriiTransaction.self, from: Data("""
        {"entrypoint_hash":"aa","block_height":12,"block_index":3,"block_hash":"bb","authority":null,"timestamp_ms":null,
         "entrypoint_kind":"Time","result_ok":false,"asset_ids":[],"asset_definition_ids":["x","y"],"metadata":{"k":1}}
        """.utf8))
        XCTAssertEqual(transaction.blockIndex, 3)
        XCTAssertNil(transaction.authority)
        XCTAssertEqual(transaction.resultOk, false)
        XCTAssertEqual(transaction.assetDefinitionIds, ["x", "y"])
        XCTAssertEqual(transaction.metadata["k"], .number(1))
    }

    func testDirectAssetDefinitionHomesPreserveExactUnsignedIdentity() throws {
        let decoder = JSONDecoder()
        for home in ["1", "9007199254740993", "8648377547929788715", "18446744073709551615"] {
            let definition = try decoder.decode(ToriiAssetDefinition.self, from: Data(#"{"id":"62Fk4FPcMuLvW5QjDGNF2a4jAmjM","owning_domain":null,"owning_dataspace":"\#(home)"}"#.utf8))
            XCTAssertEqual(definition.owningDataspace, home)
            XCTAssertNil(definition.owningDomain)
        }
        for row in [
            #"{"id":"62Fk4FPcMuLvW5QjDGNF2a4jAmjM"}"#,
            #"{"id":"62Fk4FPcMuLvW5QjDGNF2a4jAmjM","owning_domain":null,"owning_dataspace":null}"#,
            #"{"id":"62Fk4FPcMuLvW5QjDGNF2a4jAmjM","owning_domain":"treasury.bpng","owning_dataspace":null}"#,
        ] {
            let definition = try decoder.decode(ToriiAssetDefinition.self, from: Data(row.utf8))
            XCTAssertNil(definition.owningDataspace)
        }
        let selected = try decoder.decode(ToriiAssetDefinition.self, from: Data(#"{"id":"62Fk4FPcMuLvW5QjDGNF2a4jAmjM","owning_dataspace":"7"}"#.utf8))
        XCTAssertEqual(selected.owningDataspace, "7", "selected rows need not repeat an absent domain field")
        XCTAssertNil(selected.owningDomain)
    }

    func testDirectAssetDefinitionHomesRejectNoncanonicalAndConflictingValues() throws {
        let decoder = JSONDecoder()
        for home in ["0", "00", "01", "18446744073709551616", "184467440737095516150", "", "+1", "-1", "1.0", "1e0", " 1", "1 ", "１"] {
            XCTAssertThrowsError(try decoder.decode(ToriiAssetDefinition.self, from: Data(#"{"id":"62Fk4FPcMuLvW5QjDGNF2a4jAmjM","owning_dataspace":"\#(home)"}"#.utf8)), home)
        }
        for home in ["0", "7", "9007199254740992", "true", "{}", "[]"] {
            XCTAssertThrowsError(try decoder.decode(ToriiAssetDefinition.self, from: Data(#"{"id":"62Fk4FPcMuLvW5QjDGNF2a4jAmjM","owning_dataspace":\#(home)}"#.utf8)), home)
        }
        XCTAssertThrowsError(try decoder.decode(ToriiAssetDefinition.self, from: Data(#"{"id":"62Fk4FPcMuLvW5QjDGNF2a4jAmjM","owning_domain":"treasury.bpng","owning_dataspace":"7"}"#.utf8)))
    }

    func testOnlyIdentityFieldsAreRequired() throws {
        let decoder = JSONDecoder()
        let domain = try decoder.decode(ToriiDomain.self, from: Data(#"{"id":"wonderland","owned_by":null}"#.utf8))
        XCTAssertNil(domain.ownedBy)
        XCTAssertEqual(domain.metadata, [:])
        let definition = try decoder.decode(ToriiAssetDefinition.self, from: Data(#"{"id":"62Fk4FPcMuLvW5QjDGNF2a4jAmjM","alias_binding":{"alias":null}}"#.utf8))
        XCTAssertNil(definition.name)
        XCTAssertNil(definition.mintable)
        XCTAssertNil(definition.owningDomain)
        XCTAssertNil(definition.owningDataspace)
        XCTAssertNil(definition.aliasBinding?.boundAtMs)
        let rwa = try decoder.decode(ToriiRwa.self, from: Data(#"{"id":"lot-1","quantity":null}"#.utf8))
        XCTAssertNil(rwa.quantity)
        XCTAssertNil(rwa.isFrozen)
        let nft = try decoder.decode(ToriiNft.self, from: Data(#"{"id":"nft-1"}"#.utf8))
        XCTAssertNil(nft.ownedBy)
        let repo = try decoder.decode(ToriiRepoAgreement.self, from: Data(#"{"id":"repo-1","cash_leg":{"quantity":null}}"#.utf8))
        XCTAssertNil(repo.cashLeg?.quantity)
        XCTAssertNil(repo.governance)
        let balance = try decoder.decode(ToriiAccountAsset.self, from: Data(#"{"asset":"x","scope":"global","account_id":"a","quantity":"0"}"#.utf8))
        XCTAssertNil(balance.assetName)
        let transaction = try decoder.decode(ToriiTransaction.self, from: Data(#"{"entrypoint_hash":"aa","block_height":1,"block_index":0}"#.utf8))
        XCTAssertNil(transaction.blockHash)
        XCTAssertNil(transaction.resultOk)
        XCTAssertEqual(transaction.assetIds, [])

        // Identity fields are required.
        XCTAssertThrowsError(try decoder.decode(ToriiDomain.self, from: Data(#"{"owned_by":"o"}"#.utf8)))
        XCTAssertThrowsError(try decoder.decode(ToriiAccountAsset.self,
                                                from: Data(#"{"asset":"x","scope":"global","account_id":"a"}"#.utf8)))
        XCTAssertThrowsError(try decoder.decode(ToriiAssetHolder.self,
                                                from: Data(#"{"account_id":"a","asset":"x","quantity":"1"}"#.utf8)))
        XCTAssertThrowsError(try decoder.decode(ToriiTransaction.self,
                                                from: Data(#"{"entrypoint_hash":"aa","block_height":1}"#.utf8)))
    }

    func testResponsesMustBeJSON() async throws {
        let baseURL = CollectionQueryStubProtocol.register { request in
            (HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: ["Content-Type": "text/html"])!,
             Data(#"{"items":[],"next_cursor":null}"#.utf8))
        }
        await XCTAssertThrowsErrorAsync(try await client(baseURL: baseURL).repoAgreements.page()) { error in
            guard case ToriiClientError.invalidPayload = error else {
                return XCTFail("expected invalidPayload, got \(error)")
            }
        }
    }

    func testTransactionsReadTheGlobalHistoryCollection() async throws {
        let baseURL = CollectionQueryStubProtocol.register { request in
            XCTAssertEqual(request.httpMethod, "POST")
            XCTAssertEqual(request.url?.path, "/v1/transactions/query")
            XCTAssertEqual(
                String(decoding: toriiClientTestBodyData(from: request) ?? Data(), as: UTF8.self),
                #"{"filter":{"args":[{"args":["block_height",1200],"op":"gte"},{"args":["asset_definition_ids","62Fk4FPcMuLvW5QjDGNF2a4jAmjM"],"op":"eq"}],"op":"and"},"limit":10}"#
            )
            return jsonResponse(request, #"{"items":[{"entrypoint_hash":"aa","block_height":1500,"block_index":2}],"next_cursor":null}"#)
        }
        let query = ToriiListQuery(
            filter: ToriiTransaction.Fields.blockHeight >= 1200
                && ToriiTransaction.Fields.assetDefinitionIds == "62Fk4FPcMuLvW5QjDGNF2a4jAmjM",
            limit: 10
        )
        let page = try await client(baseURL: baseURL).transactions.page(query)
        XCTAssertEqual(page.items.map(\.blockHeight), [1500])
        XCTAssertEqual(page.items.first?.blockIndex, 2)
    }

    func testHistoryCollectionsRejectSortTotalAndAggregateBeforeAnyRequest() async throws {
        let baseURL = CollectionQueryStubProtocol.register { request in
            XCTFail("no request may be sent")
            return jsonResponse(request, "{}")
        }
        let torii = try client(baseURL: baseURL)
        let cases: [(ToriiListQuery, String)] = [
            (ToriiListQuery(sort: [ToriiTransaction.Fields.blockHeight.descending]), "invalid_sort"),
            (ToriiListQuery(includeTotal: true), "invalid_include_total"),
            (ToriiListQuery(aggregate: ToriiAggregate(metrics: [.count(as: "n")])), "invalid_aggregate"),
        ]
        for (query, code) in cases {
            for collection in [torii.transactions, torii.accountTransactions(of: accountId)] {
                await XCTAssertThrowsErrorAsync(try await collection.page(query)) { error in
                    XCTAssertEqual((error as? ToriiClientError)?.code, code)
                }
                await XCTAssertThrowsErrorAsync(try await collection.page(query, as: ToriiJSONObject.self)) { error in
                    XCTAssertEqual((error as? ToriiClientError)?.code, code)
                }
            }
        }
    }

    func testHistoryPagesKeepFollowingShortAndEmptyPages() async throws {
        let log = NSLock()
        var bodies: [String] = []
        let baseURL = CollectionQueryStubProtocol.register { request in
            let body = String(decoding: toriiClientTestBodyData(from: request) ?? Data(), as: UTF8.self)
            log.lock()
            bodies.append(body)
            log.unlock()
            switch body {
            case #"{"limit":2}"#:
                return jsonResponse(request, #"{"items":[],"next_cursor":"h1"}"#)
            case #"{"cursor":"h1","limit":2}"#:
                return jsonResponse(request, #"{"items":[{"entrypoint_hash":"aa","block_height":9,"block_index":0}],"next_cursor":"h2"}"#)
            default:
                return jsonResponse(request, #"{"items":[],"next_cursor":null}"#)
            }
        }
        var hashes: [String] = []
        for try await transaction in try client(baseURL: baseURL).accountTransactions(of: accountId).items(ToriiListQuery(limit: 2)) {
            hashes.append(transaction.entrypointHash)
        }
        XCTAssertEqual(hashes, ["aa"])
        XCTAssertEqual(bodies, [#"{"limit":2}"#, #"{"cursor":"h1","limit":2}"#, #"{"cursor":"h2","limit":2}"#])
    }
}

// MARK: - Event streams and transport policy

final class ToriiEventStreamPolicyTests: XCTestCase {
    private static let hash = "a3f2c1b0a3f2c1b0a3f2c1b0a3f2c1b0a3f2c1b0a3f2c1b0a3f2c1b0a3f2c1b1"

    private func client(baseURL: URL, defaultHeaders: [String: String] = [:]) -> ToriiClient {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [CollectionQueryStubProtocol.self]
        return ToriiClient(baseURL: baseURL,
                           session: URLSession(configuration: configuration),
                           defaultHeaders: defaultHeaders)
    }

    func testTransactionStatusStreamUsesTheTextFilterAndChecksEveryHash() async throws {
        let other = String(Self.hash.dropLast()) + "3"
        let baseURL = CollectionQueryStubProtocol.register { request in
            let components = URLComponents(url: request.url!, resolvingAgainstBaseURL: false)
            XCTAssertEqual(components?.queryItems, [URLQueryItem(name: "filter", value: "tx_hash = \"\(Self.hash)\"")])
            let stream = """
            data: {"category":"Pipeline","event":"Transaction","hash":"\(Self.hash)","status":"Queued","block_height":null}

            data: {"category":"Pipeline","event":"Transaction","hash":"\(other)","status":"Approved","block_height":2}
            """
            return (HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil,
                                    headerFields: ["Content-Type": "text/event-stream"])!, Data(stream.utf8))
        }
        var iterator = client(baseURL: baseURL).streamTransactionStatusEvents(hashHex: Self.hash).makeAsyncIterator()
        let first = try await iterator.next()
        XCTAssertEqual(first?.event.status, .queued)
        await XCTAssertThrowsErrorAsync(try await iterator.next(), "the trailing event's hash must be checked too")
    }

    func testEventStreamRejectionCarriesTheErrorEnvelope() async throws {
        let baseURL = CollectionQueryStubProtocol.register { request in
            jsonResponse(request, status: 400, #"{"code":"invalid_filter","message":"invalid `filter`: unsupported filter field: colour"}"#)
        }
        var iterator = client(baseURL: baseURL).streamTransactionStatusEvents(hashHex: Self.hash).makeAsyncIterator()
        await XCTAssertThrowsErrorAsync(try await iterator.next()) { error in
            XCTAssertEqual((error as? ToriiClientError)?.code, "invalid_filter")
        }
    }

    func testCredentialedEventStreamsRequireHTTPS() async throws {
        let torii = client(baseURL: URL(string: "http://insecure.test")!,
                           defaultHeaders: ["Authorization": "Bearer secret"])
        var iterator = torii.streamTransactionStatusEvents(hashHex: Self.hash).makeAsyncIterator()
        await XCTAssertThrowsErrorAsync(try await iterator.next()) { error in
            guard case let ToriiClientError.invalidPayload(reason) = error else {
                return XCTFail("expected invalidPayload, got \(error)")
            }
            XCTAssertTrue(reason.contains("insecure transport"), reason)
        }
    }

    func testEveryExplorerFeedUsesSharedPagesAndFixedOrder() async throws {
        let paths = ["accounts", "domains", "asset-definitions", "assets", "nfts", "rwas", "blocks",
                     "transactions", "transactions/latest", "instructions", "instructions/latest"]
        let lock = NSLock()
        var observed = 0
        let baseURL = CollectionQueryStubProtocol.register { request in
            lock.lock()
            defer { lock.unlock() }
            XCTAssertEqual(request.httpMethod, "POST")
            XCTAssertLessThan(observed, paths.count)
            if observed < paths.count {
                XCTAssertEqual(request.url?.path, "/v1/explorer/\(paths[observed])/query")
            }
            observed += 1
            return jsonResponse(request, #"{"items":[],"next_cursor":null}"#)
        }
        let torii = try client(baseURL: baseURL)
        _ = try await torii.explorerAccounts.page()
        _ = try await torii.explorerDomains.page()
        _ = try await torii.explorerAssetDefinitions.page()
        _ = try await torii.explorerAssets.page()
        _ = try await torii.explorerNfts.page()
        _ = try await torii.explorerRwas.page()
        _ = try await torii.explorerBlocks.page()
        _ = try await torii.explorerTransactions.page()
        _ = try await torii.explorerLatestTransactions.page()
        _ = try await torii.explorerInstructions.page()
        _ = try await torii.explorerLatestInstructions.page()
        await XCTAssertThrowsErrorAsync(try await torii.explorerAccounts.page(ToriiListQuery(includeTotal: true)))
        await XCTAssertThrowsErrorAsync(try await torii.explorerTransactions.page(ToriiListQuery(sort: [.ascending("block")])))
    }

    func testExplorerTransferHelperPreservesCallerFilter() async throws {
        let query = ToriiListQuery(filter: ToriiField("metadata.note") == ToriiFilterValue.object(["tag": .string("a+b")]), limit: 3)
        let baseURL = CollectionQueryStubProtocol.register { request in
            let body = try JSONSerialization.jsonObject(with: XCTUnwrap(toriiClientTestBodyData(from: request))) as! [String: Any]
            let filterData = try JSONSerialization.data(withJSONObject: XCTUnwrap(body["filter"]))
            let expected = (ToriiField("metadata.note") == ToriiFilterValue.object(["tag": .string("a+b")])).and(ToriiField("kind") == "Transfer")
            XCTAssertEqual(try ToriiFilter(jsonData: filterData), expected)
            XCTAssertEqual(body["limit"] as? Int, 3)
            return jsonResponse(request, #"{"items":[],"next_cursor":null}"#)
        }
        _ = try await client(baseURL: baseURL).getExplorerTransfers(query: query)
    }

    func testExplorerCollectionPreservesPlusInFilterLiteral() async throws {
        let baseURL = CollectionQueryStubProtocol.register { request in
            XCTAssertEqual(request.url?.path, "/v1/explorer/instructions/query")
            let body = try JSONSerialization.jsonObject(with: XCTUnwrap(toriiClientTestBodyData(from: request))) as! [String: Any]
            XCTAssertEqual((body["filter"] as? [String: Any])?["args"] as? [String], ["kind", "a+b"])
            return jsonResponse(request, #"{"next_cursor":null,"items":[]}"#)
        }
        _ = try await client(baseURL: baseURL).explorerInstructions.page(ToriiListQuery(filter: ToriiField("kind") == "a+b"))
    }

    func testStreamEventsSendsTheTextFilterAndDecodesEveryKind() async throws {
        let baseURL = CollectionQueryStubProtocol.register { request in
            let components = URLComponents(url: request.url!, resolvingAgainstBaseURL: false)
            XCTAssertEqual(components?.queryItems,
                           [URLQueryItem(name: "filter", value: #"tx_status in ["Approved", "Rejected"] and tx_lane_id = 0"#)])
            let stream = """
            data: {"category":"Pipeline","event":"Transaction","hash":"\(Self.hash)","lane_id":0,"dataspace_id":0,"block_height":4,"status":"Rejected","rejection_code":"ivm_execution","rejection_reason":"contract execution failed"}

            data: {"category":"Pipeline","event":"Block","status":"Rejected","rejection_code":"EmptyBlock"}

            data: {"category":"Data","event":"Asset","summary":"Asset(..)"}

            data: {"category":"Other","event":"Time","summary":"Time(..)"}

            data: {"category":"Pipeline","event":"Checkpoint","height":3}
            """
            return (HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil,
                                    headerFields: ["Content-Type": "text/event-stream"])!, Data(stream.utf8))
        }
        let filter = ToriiEventFields.txStatus.in(["Approved", "Rejected"]) && ToriiEventFields.txLaneId == 0
        var events: [ToriiEvent] = []
        for try await message in client(baseURL: baseURL).streamEvents(filter: filter) {
            events.append(message.event)
        }
        XCTAssertEqual(events.map(\.name), ["Transaction", "Block", "Asset", "Time", "Checkpoint"])
        guard events.count == 5, case let .transaction(transaction) = events[0], case let .block(block) = events[1] else {
            return XCTFail("unexpected events \(events)")
        }
        XCTAssertEqual(transaction.status, .rejected)
        XCTAssertEqual(transaction.rejectionCode, .ivmExecution)
        XCTAssertEqual(transaction.rejectionReason, "contract execution failed")
        XCTAssertEqual(transaction.blockHeight, 4)
        XCTAssertEqual(block, ToriiPipelineBlockEvent(status: .rejected, rejectionCode: "EmptyBlock"))
        XCTAssertEqual(events[2], .data(ToriiEventNotice(category: "Data", event: "Asset", summary: "Asset(..)")))
        XCTAssertEqual(events[3], .other(ToriiEventNotice(category: "Other", event: "Time", summary: "Time(..)")))
        XCTAssertEqual(events[4], .other(ToriiEventNotice(category: "Pipeline", event: "Checkpoint", summary: nil)))
    }

    func testStreamEventsRejectsStructuredLiteralsBeforeConnecting() async throws {
        let baseURL = CollectionQueryStubProtocol.register { request in
            XCTFail("no request may be sent")
            return jsonResponse(request, "{}")
        }
        let filter = ToriiField.metadata("tags") == ToriiFilterValue.array(["a"])
        var iterator = client(baseURL: baseURL).streamEvents(filter: filter).makeAsyncIterator()
        await XCTAssertThrowsErrorAsync(try await iterator.next()) { error in
            XCTAssertEqual((error as? ToriiClientError)?.code, "invalid_filter")
        }
    }

    func testStreamEventsPassesTextFiltersVerbatim() async throws {
        let text = #"tx_status = 'Rejected'"#
        let baseURL = CollectionQueryStubProtocol.register { request in
            let components = URLComponents(url: request.url!, resolvingAgainstBaseURL: false)
            XCTAssertEqual(components?.queryItems, [URLQueryItem(name: "filter", value: text)])
            return (HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil,
                                    headerFields: ["Content-Type": "text/event-stream"])!, Data())
        }
        var iterator = client(baseURL: baseURL).streamEvents(filterText: text).makeAsyncIterator()
        let event = try await iterator.next()
        XCTAssertNil(event)
    }

    func testBuiltEventFiltersAreCheckedAgainstTheEventStreamSubset() async throws {
        let baseURL = CollectionQueryStubProtocol.register { request in
            XCTFail("no request may be sent")
            return jsonResponse(request, "{}")
        }
        let torii = client(baseURL: baseURL)
        let rejected: [ToriiFilter] = [
            ToriiEventFields.blockHeight > 1,
            ToriiEventFields.txStatus == "Applied",
            ToriiField("colour") == "red",
            !(ToriiEventFields.txHash == Self.hash),
            ToriiEventFields.blockHeight.isNull,
            ToriiEventFields.txBlockHeight.isNotNull,
            ToriiEventFields.blockStatus.in(["Committed", "Final"]),
        ]
        for filter in rejected {
            var iterator = torii.streamEvents(filter: filter).makeAsyncIterator()
            await XCTAssertThrowsErrorAsync(try await iterator.next(), filter.description) { error in
                XCTAssertEqual((error as? ToriiClientError)?.code, "invalid_filter", filter.description)
            }
        }
    }

    func testEventFiltersMayNegateStatusesAndMatchMissingBlockHeights() async throws {
        let expected = #"not tx_status = "Rejected" and tx_block_height is null or block_status in ["Committed", "Applied"]"#
        let baseURL = CollectionQueryStubProtocol.register { request in
            let components = URLComponents(url: request.url!, resolvingAgainstBaseURL: false)
            XCTAssertEqual(components?.queryItems, [URLQueryItem(name: "filter", value: expected)])
            return (HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil,
                                    headerFields: ["Content-Type": "text/event-stream"])!, Data())
        }
        let filter = (!(ToriiEventFields.txStatus == "Rejected") && ToriiEventFields.txBlockHeight.isNull)
            || ToriiEventFields.blockStatus.in(["Committed", "Applied"])
        XCTAssertEqual(filter.description, expected)
        var iterator = client(baseURL: baseURL).streamEvents(filter: filter).makeAsyncIterator()
        let event = try await iterator.next()
        XCTAssertNil(event)
    }
}

// MARK: - Event payloads

final class ToriiEventDecodingTests: XCTestCase {
    private func decode(_ json: String) throws -> ToriiEvent {
        try JSONDecoder().decode(ToriiEvent.self, from: Data(json.utf8))
    }

    func testPipelineEventsDecodeTypedFields() throws {
        let hash = String(repeating: "c", count: 63) + "d"
        let rejected = try decode("""
        {"category":"Pipeline","event":"Transaction","hash":"\(hash)","lane_id":1,"dataspace_id":7,"block_height":null,
         "status":"Rejected","rejection_code":"account_does_not_exist","rejection_reason":"the authority account does not exist"}
        """)
        XCTAssertEqual(rejected, .transaction(ToriiPipelineTransactionEvent(
            hash: hash,
            status: .rejected,
            laneId: 1,
            dataspaceId: 7,
            blockHeight: nil,
            rejectionCode: .accountDoesNotExist,
            rejectionReason: "the authority account does not exist"
        )))
        XCTAssertEqual(rejected.category, "Pipeline")
        XCTAssertEqual(try decode(#"{"category":"Pipeline","event":"Block","status":"Committed"}"#),
                       .block(ToriiPipelineBlockEvent(status: .committed)))
        XCTAssertEqual(try decode(#"{"category":"Pipeline","event":"Block","status":"Rejected","rejection_code":"EmptyBlock"}"#),
                       .block(ToriiPipelineBlockEvent(status: .rejected, rejectionCode: "EmptyBlock")))
        XCTAssertEqual(try decode(#"{"category":"Pipeline","event":"Warning","kind":"slow","details":"took long","height":5}"#),
                       .warning(ToriiPipelineWarningEvent(kind: "slow", details: "took long", height: 5)))
        XCTAssertEqual(
            try decode(#"{"category":"Pipeline","event":"Witness","block_hash":"ab","height":5,"view":1,"epoch":0,"read_count":3,"write_count":2}"#),
            .witness(ToriiPipelineWitnessEvent(blockHash: "ab", height: 5, view: 1, epoch: 0, readCount: 3, writeCount: 2))
        )
        XCTAssertEqual(ToriiPipelineBlockEvent.Status(name: "Sealed"), .other("Sealed"))
        XCTAssertEqual(ToriiPipelineBlockEvent.Status.applied.name, "Applied")
    }

    func testRejectionCodesKeepTheirWireSpelling() {
        for code in ["account_does_not_exist", "limit_check", "validation", "instruction_execution",
                     "ivm_execution", "trigger_execution", "future_code"] {
            XCTAssertEqual(ToriiTransactionRejectionCode(rawValue: code).rawValue, code)
        }
        XCTAssertEqual(ToriiTransactionRejectionCode(rawValue: "future_code"), .other("future_code"))
        XCTAssertEqual(ToriiTransactionRejectionCode(rawValue: "trigger_execution"), .triggerExecution)
    }

    func testProofEventsDecode() throws {
        let hash = String(repeating: "a", count: 64)
        let verified = try decode("""
        {"category":"Data","event":"ProofVerified","backend":"pipa-r/pasta","proof_hash":"\(hash)","call_hash":null,
         "envelope_hash":null,"vk_ref":"pipa-r/pasta::vk_main","vk_commitment":null}
        """)
        XCTAssertEqual(verified, .proof(.verified(ToriiProofEventBody(
            id: ToriiProofId(backend: "pipa-r/pasta", proofHashHex: hash),
            verifyingKeyRef: "pipa-r/pasta::vk_main"
        ))))
        XCTAssertEqual(verified.name, "ProofVerified")
        guard case let .proof(.pruned(pruned)) = try decode("""
        {"category":"Data","event":"ProofPruned","backend":"pipa-r/pasta","removed_count":0,"remaining":4,"cap":4,
         "grace_blocks":0,"prune_batch":8,"pruned_at_height":2,"pruned_by":"a","origin":"Scheduled","removed":[]}
        """) else {
            return XCTFail("expected a pruning event")
        }
        XCTAssertEqual(pruned.origin, .other("Scheduled"))
        XCTAssertEqual(pruned.removed, [])
        XCTAssertThrowsError(try decode(#"{"category":"Data","event":"ProofRejected","backend":"pipa-r/pasta"}"#))
    }

    func testUnknownEventsDoNotFailTheStream() throws {
        XCTAssertEqual(try decode(#"{"category":"Data","event":"Sccp","summary":"Sccp(..)","extra":1}"#),
                       .data(ToriiEventNotice(category: "Data", event: "Sccp", summary: "Sccp(..)")))
        XCTAssertEqual(try decode(#"{"category":"Data","event":"Proof","summary":{"structured":true}}"#),
                       .data(ToriiEventNotice(category: "Data", event: "Proof", summary: nil)))
        XCTAssertEqual(try decode(#"{"category":"Other","event":"TriggerCompleted","summary":"done"}"#),
                       .other(ToriiEventNotice(category: "Other", event: "TriggerCompleted", summary: "done")))
        XCTAssertEqual(try decode(#"{"category":"Telemetry","event":"Tick"}"#),
                       .other(ToriiEventNotice(category: "Telemetry", event: "Tick", summary: nil)))
    }

    func testMalformedEventsAreRejected() {
        for json in [
            #"{"event":"Transaction"}"#,
            #"{"category":"Pipeline"}"#,
            #"[{"category":"Pipeline","event":"Block","status":"Applied"}]"#,
            #"{"category":"Pipeline","event":"Transaction","hash":"abc","status":"Queued"}"#,
            #"{"category":"Pipeline","event":"Block"}"#,
        ] {
            XCTAssertThrowsError(try decode(json), json)
        }
    }

    func testProofFilterMatchesPrunedEventsLikeTorii() throws {
        let removedHash = String(repeating: "e", count: 64)
        let pruned = ToriiProofEvent.pruned(ToriiProofPrunedEvent(
            backend: "pipa-r/pasta",
            removedCount: 1,
            remaining: 0,
            cap: 1,
            graceBlocks: 0,
            pruneBatch: 1,
            prunedAtHeight: 3,
            prunedBy: "a",
            origin: .manual,
            removed: [ToriiProofId(backend: "pipa-r/pasta", proofHashHex: removedHash)]
        ))
        XCTAssertTrue(ToriiProofEventFilter().matches(pruned))
        XCTAssertTrue(ToriiProofEventFilter(backend: "pipa-r/pasta", proofHashHex: removedHash).matches(pruned))
        XCTAssertFalse(ToriiProofEventFilter(proofHashHex: String(repeating: "f", count: 64)).matches(pruned))
        XCTAssertFalse(ToriiProofEventFilter(callHashHex: removedHash).matches(pruned))
        XCTAssertFalse(ToriiProofEventFilter(includePruned: false).matches(pruned))
        XCTAssertNoThrow(try ToriiProofEventFilter(includeVerified: false, includeRejected: false).serverFilter())
        XCTAssertThrowsError(try ToriiProofEventFilter(includeVerified: false, includeRejected: false, includePruned: false).serverFilter())
    }
}

// MARK: - Fixed footguns

final class ToriiSDKFootgunTests: XCTestCase {
    func testAccountIdMakeThrowsForInvalidKeys() {
        XCTAssertThrowsError(try AccountId.make(publicKey: Data([1, 2, 3])))
    }

    func testTransferDescriptionsAreRejectedInsteadOfDropped() throws {
        let keypair = try Keypair(privateKeyBytes: Data(repeating: 0x2A, count: 32))
        let authority = try AccountId.make(publicKey: keypair.publicKey)
        let transfer = TransferRequest(networkId: TestNetworkIds.canonical,
                                       authority: authority,
                                       assetDefinitionId: "62Fk4FPcMuLvW5QjDGNF2a4jAmjM",
                                       quantity: "1",
                                       destination: authority,
                                       description: "invoice 42",
                                       feePayment: .authority(chargeLimits: [], gasLimit: nil))
        XCTAssertThrowsError(
            try SwiftTransactionEncoder.encodeTransfer(
                transfer: transfer,
                signingKey: SigningKey.ed25519(privateKey: keypair.privateKeyBytes),
                creationTimeMs: 1
            )
        ) { error in
            XCTAssertEqual(error as? TransactionInputError, .transferDescriptionUnsupported)
        }
    }

    func testConcurrentStatusSnapshotsDoNotRace() async throws {
        let baseURL = CollectionQueryStubProtocol.register { request in
            jsonResponse(request, #"{"peers":1,"blocks":1,"blocks_non_empty":1,"commit_time_ms":1,"txs_approved":1,"txs_rejected":0,"uptime":{"secs":1,"nanos":0},"view_changes":0,"queue_size":0}"#)
        }
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [CollectionQueryStubProtocol.self]
        let torii = ToriiClient(baseURL: baseURL, session: URLSession(configuration: configuration))
        let snapshots = await withTaskGroup(of: Bool.self) { group -> Int in
            for _ in 0..<16 {
                group.addTask { (try? await torii.getStatusSnapshot()) != nil }
            }
            var recorded = 0
            for await succeeded in group where succeeded {
                recorded += 1
            }
            return recorded
        }
        XCTAssertEqual(snapshots, 16, "every concurrent snapshot reserves and records its sample")
    }
}
