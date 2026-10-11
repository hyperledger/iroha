import Foundation

#if canImport(Darwin)
import Darwin
#endif

private struct RetailFeeAnyCodingKey: CodingKey {
    let stringValue: String
    let intValue: Int? = nil

    init?(stringValue: String) {
        self.stringValue = stringValue
    }

    init?(intValue: Int) {
        return nil
    }
}

private func requireExactRetailFeeKeys(
    from decoder: Decoder,
    expected: Set<String>
) throws {
    let container = try decoder.container(keyedBy: RetailFeeAnyCodingKey.self)
    let actual = Set(container.allKeys.map(\.stringValue))
    guard actual == expected else {
        throw DecodingError.dataCorrupted(
            .init(
                codingPath: decoder.codingPath,
                debugDescription: "Retail fee object must contain exactly the first-release fields."
            )
        )
    }
}

/// Local native retail-fee codec failures. A decoded assessment is not a ledger proof.
public enum RetailFeeNativeError: Error, Equatable, Sendable {
    /// The exact ABI-29 bridge and three retail-fee symbols are unavailable.
    case bridgeUnavailable
    /// The native typed parser or canonical encoder rejected the input.
    case nativeRejected(Int32)
    /// Native output violated the bounded first-release result shape.
    case invalidNativeOutput
}

/// One ordered retail payment leg in the customer's reviewed intent.
public struct RetailFeePaymentLegV1: Codable, Equatable, Sendable {
    public let destinationAccountId: String
    public let amountMinorUnits: UInt64

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case destinationAccountId = "destination_account_id"
        case amountMinorUnits = "amount_minor_units"
    }

    public init(destinationAccountId: String, amountMinorUnits: UInt64) {
        self.destinationAccountId = destinationAccountId
        self.amountMinorUnits = amountMinorUnits
    }

    public init(from decoder: Decoder) throws {
        try requireExactRetailFeeKeys(
            from: decoder,
            expected: Set(CodingKeys.allCases.map(\.stringValue))
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        destinationAccountId = try container.decode(String.self, forKey: .destinationAccountId)
        amountMinorUnits = try container.decode(UInt64.self, forKey: .amountMinorUnits)
    }
}

/// Native retail-fee payment intent; mutable ledger counters are not caller inputs.
public struct RetailFeeQuoteRequestV1: Codable, Equatable, Sendable {
    public let accountId: String
    public let assetDefinitionId: String
    public let transfers: [RetailFeePaymentLegV1]

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case accountId = "account_id"
        case assetDefinitionId = "asset_definition_id"
        case transfers
    }

    public init(
        accountId: String,
        assetDefinitionId: String,
        transfers: [RetailFeePaymentLegV1]
    ) {
        self.accountId = accountId
        self.assetDefinitionId = assetDefinitionId
        self.transfers = transfers
    }

    public init(from decoder: Decoder) throws {
        try requireExactRetailFeeKeys(
            from: decoder,
            expected: Set(CodingKeys.allCases.map(\.stringValue))
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        accountId = try container.decode(String.self, forKey: .accountId)
        assetDefinitionId = try container.decode(String.self, forKey: .assetDefinitionId)
        transfers = try container.decode([RetailFeePaymentLegV1].self, forKey: .transfers)
    }

    /// Hash the exact ordered intent with the authoritative native Norito codec.
    public func intentHash() throws -> Data {
        try RetailFeeAssessmentNative.intentHash(self)
    }
}

/// Complete fee assessment bound to ledger state and the ordered intent hash.
///
/// Decoding this value validates local shape only. The caller must independently
/// verify the signed read and finality before authorizing a payment.
public struct RetailFeeAssessmentV1: Codable, Equatable, Sendable {
    public let accountId: String
    public let retailEnrolled: Bool
    public let billingMonthStartMs: UInt64
    public let policyRevision: UInt64
    public let paymentsUsedBefore: UInt64
    public let qualifyingPayments: UInt64
    public let feeMinor: UInt64
    public let stateCommitment: String
    public let intentHash: String
    public let expiresAtMs: UInt64

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case accountId = "account_id"
        case retailEnrolled = "retail_enrolled"
        case billingMonthStartMs = "billing_month_start_ms"
        case policyRevision = "policy_revision"
        case paymentsUsedBefore = "payments_used_before"
        case qualifyingPayments = "qualifying_payments"
        case feeMinor = "fee_minor"
        case stateCommitment = "state_commitment"
        case intentHash = "intent_hash"
        case expiresAtMs = "expires_at_ms"
    }

    public init(
        accountId: String,
        retailEnrolled: Bool,
        billingMonthStartMs: UInt64,
        policyRevision: UInt64,
        paymentsUsedBefore: UInt64,
        qualifyingPayments: UInt64,
        feeMinor: UInt64,
        stateCommitment: String,
        intentHash: String,
        expiresAtMs: UInt64
    ) {
        self.accountId = accountId
        self.retailEnrolled = retailEnrolled
        self.billingMonthStartMs = billingMonthStartMs
        self.policyRevision = policyRevision
        self.paymentsUsedBefore = paymentsUsedBefore
        self.qualifyingPayments = qualifyingPayments
        self.feeMinor = feeMinor
        self.stateCommitment = stateCommitment
        self.intentHash = intentHash
        self.expiresAtMs = expiresAtMs
    }

    public init(from decoder: Decoder) throws {
        try requireExactRetailFeeKeys(
            from: decoder,
            expected: Set(CodingKeys.allCases.map(\.stringValue))
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        accountId = try container.decode(String.self, forKey: .accountId)
        retailEnrolled = try container.decode(Bool.self, forKey: .retailEnrolled)
        billingMonthStartMs = try container.decode(UInt64.self, forKey: .billingMonthStartMs)
        policyRevision = try container.decode(UInt64.self, forKey: .policyRevision)
        paymentsUsedBefore = try container.decode(UInt64.self, forKey: .paymentsUsedBefore)
        qualifyingPayments = try container.decode(UInt64.self, forKey: .qualifyingPayments)
        feeMinor = try container.decode(UInt64.self, forKey: .feeMinor)
        stateCommitment = try container.decode(String.self, forKey: .stateCommitment)
        intentHash = try container.decode(String.self, forKey: .intentHash)
        expiresAtMs = try container.decode(UInt64.self, forKey: .expiresAtMs)
    }

    /// Encode the complete assessment as a canonical transaction signing marker.
    public func marker() throws -> String {
        try RetailFeeAssessmentNative.assessmentMarker(self)
    }

    /// Decode one canonical signing marker with the native typed parser.
    public static func decodeMarker(_ marker: String) throws -> Self {
        try RetailFeeAssessmentNative.decodeAssessmentMarker(marker)
    }
}

/// Exact ABI-29 entrypoints for retail intent and assessment encoding.
public enum RetailFeeAssessmentNative {
    public static let requiredBridgeAbiVersion: UInt32 = 29
    public static let maximumIntentJSONBytes = 262_144
    public static let maximumAssessmentJSONBytes = 4_096
    public static let maximumAssessmentMarkerBytes = 4_096

    /// Return the native 32-byte intent hash for the complete ordered request.
    public static func intentHash(_ request: RetailFeeQuoteRequestV1) throws -> Data {
        try intentHashV1(requestJSON: JSONEncoder().encode(request))
    }

    /// Hash one complete request JSON projection through native typed Norito.
    public static func intentHashV1(requestJSON input: Data) throws -> Data {
        guard !input.isEmpty, input.count <= maximumIntentJSONBytes else {
            throw RetailFeeNativeError.invalidNativeOutput
        }
        let output = try NoritoNativeBridge.shared.retailFeeInvokeV1(
            "connect_norito_retail_fee_intent_hash_v1",
            input: input,
            maximumOutputBytes: 32
        )
        guard output.count == 32 else { throw RetailFeeNativeError.invalidNativeOutput }
        return output
    }

    /// Return the exact canonical signing marker for a typed assessment.
    public static func assessmentMarker(_ assessment: RetailFeeAssessmentV1) throws -> String {
        let input = try JSONEncoder().encode(assessment)
        guard !input.isEmpty, input.count <= maximumAssessmentJSONBytes else {
            throw RetailFeeNativeError.invalidNativeOutput
        }
        let output = try NoritoNativeBridge.shared.retailFeeInvokeV1(
            "connect_norito_retail_fee_assessment_marker_v1",
            input: input,
            maximumOutputBytes: maximumAssessmentMarkerBytes
        )
        guard let marker = String(data: output, encoding: .utf8),
              marker.hasPrefix("iroha:retail_fee:assessment:v1:") else {
            throw RetailFeeNativeError.invalidNativeOutput
        }
        return marker
    }

    /// Return the typed local projection of one canonical assessment marker.
    public static func decodeAssessmentMarker(_ marker: String) throws -> RetailFeeAssessmentV1 {
        let input = Data(marker.utf8)
        guard !input.isEmpty, input.count <= maximumAssessmentMarkerBytes else {
            throw RetailFeeNativeError.invalidNativeOutput
        }
        let output = try NoritoNativeBridge.shared.retailFeeInvokeV1(
            "connect_norito_retail_fee_assessment_decode_v1",
            input: input,
            maximumOutputBytes: maximumAssessmentJSONBytes
        )
        do {
            return try JSONDecoder().decode(RetailFeeAssessmentV1.self, from: output)
        } catch {
            throw RetailFeeNativeError.invalidNativeOutput
        }
    }
}

extension NoritoNativeBridge {
    #if canImport(Darwin)
    private typealias RetailFeeFn = @convention(c) (
        UnsafePointer<UInt8>?, CUnsignedLong,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
        UnsafeMutablePointer<CUnsignedLong>?
    ) -> Int32
    private typealias RetailFeeFreeFn = @convention(c) (UnsafeMutablePointer<UInt8>?) -> Void
    #endif

    func retailFeeInvokeV1(
        _ symbol: String,
        input: Data,
        maximumOutputBytes: Int
    ) throws -> Data {
        #if canImport(Darwin)
        guard isAvailable,
              let function = resolveNativeSymbol(symbol, as: RetailFeeFn.self),
              let free = resolveNativeSymbol("connect_norito_free", as: RetailFeeFreeFn.self) else {
            throw RetailFeeNativeError.bridgeUnavailable
        }
        var output: UnsafeMutablePointer<UInt8>?
        var outputLength: CUnsignedLong = 0
        let status = input.withUnsafeBytes { bytes in
            function(
                bytes.bindMemory(to: UInt8.self).baseAddress,
                CUnsignedLong(bytes.count),
                &output,
                &outputLength
            )
        }
        guard status == 0 else {
            if let output { free(output) }
            throw RetailFeeNativeError.nativeRejected(status)
        }
        guard let output, outputLength > 0,
              outputLength <= CUnsignedLong(maximumOutputBytes),
              UInt64(outputLength) <= UInt64(Int.max) else {
            if let output { free(output) }
            throw RetailFeeNativeError.invalidNativeOutput
        }
        defer { free(output) }
        return Data(bytes: output, count: Int(outputLength))
        #else
        _ = symbol
        _ = input
        _ = maximumOutputBytes
        throw RetailFeeNativeError.bridgeUnavailable
        #endif
    }
}
