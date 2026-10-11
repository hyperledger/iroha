import Foundation

/// One proposal parsed with the shared exact-number scanner and governance's
/// stricter all-unsigned-integer policy.
struct GovernanceValidatedProposalJSON {
    let value: ToriiJSONValue
    let numberLexemes: [String: String]
}

func governanceValidatedProposalJSON(_ data: Data) throws -> GovernanceValidatedProposalJSON {
    let lexemes = try ExactJSONNumberLexemeScanner.scan(data)
    let decoder = JSONDecoder()
    decoder.userInfo[exactJSONNumberLexemesUserInfoKey] = lexemes
    let root = try decoder.decode(ToriiJSONValue.self, from: data)
    guard case .object = root else {
        throw ToriiClientError.invalidPayload("governance proposal must be a JSON object")
    }

    func walk(_ value: ToriiJSONValue, path: [GovernanceProposalCodingKey]) throws {
        switch value {
        case .bool, .string, .null:
            break
        case .number, .integer:
            let pathKey = exactJSONNumberCodingPathKey(path)
            guard let token = lexemes[pathKey],
                  let parsed = SccpUInt128.parse(token) else {
                throw ToriiClientError.invalidPayload(
                    "governance proposal requires canonical unsigned JSON integer tokens"
                )
            }
            if parsed.exceedsMaximumSafeJSONInteger {
                throw ToriiClientError.invalidPayload(
                    "governance proposal integer is outside the exact first-release JSON range"
                )
            }
        case .object(let object):
            for (key, item) in object {
                try walk(item, path: path + [GovernanceProposalCodingKey(key)])
            }
        case .array(let array):
            for (index, item) in array.enumerated() {
                try walk(item, path: path + [GovernanceProposalCodingKey(intValue: index)!])
            }
        }
    }

    try walk(root, path: [])
    return GovernanceValidatedProposalJSON(value: root, numberLexemes: lexemes)
}

let governanceFirstReleaseMaxExactJSONInteger = 9_007_199_254_740_991.0

func governanceRequireExactJSONIntegers(
    _ value: ToriiJSONValue,
    codingPath: [CodingKey],
    context: String,
    exactIntegerLexemes: [String: String]? = nil
) throws {
    switch value {
    case let .array(values):
        for (index, item) in values.enumerated() {
            try governanceRequireExactJSONIntegers(
                item,
                codingPath: codingPath + [GovernanceProposalCodingKey(intValue: index)!],
                context: "\(context)[\(index)]",
                exactIntegerLexemes: exactIntegerLexemes
            )
        }
    case let .object(object):
        for (key, item) in object {
            try governanceRequireExactJSONIntegers(
                item,
                codingPath: codingPath + [GovernanceProposalCodingKey(key)],
                context: "\(context).\(key)",
                exactIntegerLexemes: exactIntegerLexemes
            )
        }
    case let .number(number):
        let isSafelyRepresentable = number.isFinite
            && number >= 0
            && number.rounded(.towardZero) == number
            && abs(number) <= governanceFirstReleaseMaxExactJSONInteger
        let token = exactIntegerLexemes?[exactJSONNumberCodingPathKey(codingPath)]
        let parsed = token.flatMap(SccpUInt128.parse)
        let hasValidatedExactLexeme = parsed.map { !$0.exceedsMaximumSafeJSONInteger } ?? false
        guard token == nil ? isSafelyRepresentable : hasValidatedExactLexeme else {
            throw DecodingError.dataCorrupted(
                .init(
                    codingPath: codingPath,
                    debugDescription: "\(context) is outside the exact first-release JSON integer range"
                )
            )
        }
    case .integer:
        let token = exactIntegerLexemes?[exactJSONNumberCodingPathKey(codingPath)]
        let parsed = token.flatMap(SccpUInt128.parse)
        guard let parsed, !parsed.exceedsMaximumSafeJSONInteger else {
            throw DecodingError.dataCorrupted(
                .init(
                    codingPath: codingPath,
                    debugDescription: "\(context) is outside the exact first-release JSON integer range"
                )
            )
        }
    case .string, .bool, .null:
        break
    }
}

private struct GovernanceProposalCodingKey: CodingKey {
    let stringValue: String
    let intValue: Int?

    init(_ stringValue: String) {
        self.stringValue = stringValue
        intValue = nil
    }

    init?(stringValue: String) {
        self.init(stringValue)
    }

    init?(intValue: Int) {
        stringValue = String(intValue)
        self.intValue = intValue
    }
}

func governanceRejectUnknownFields(
    _ decoder: Decoder,
    allowed: Set<String>,
    name: String
) throws {
    let container = try decoder.container(keyedBy: GovernanceProposalCodingKey.self)
    guard container.allKeys.allSatisfy({ allowed.contains($0.stringValue) }) else {
        throw DecodingError.dataCorrupted(
            .init(
                codingPath: decoder.codingPath,
                debugDescription: "\(name) contains an unknown or retired field"
            )
        )
    }
}

func governanceCanonicalAccount(
    _ raw: String,
    codingPath: [CodingKey],
    field: String
) throws -> String {
    do {
        _ = try exactCanonicalToriiAccountAddress(raw)
        return raw
    } catch {
        throw DecodingError.dataCorrupted(
            .init(
                codingPath: codingPath,
                debugDescription: "\(field) must be an exact canonical account address"
            )
        )
    }
}

private func governanceCanonicalAssetDefinition(
    _ raw: String,
    codingPath: [CodingKey],
    field: String
) throws -> String {
    guard AssetDefinitionAddress.decode(raw) != nil else {
        throw DecodingError.dataCorrupted(
            .init(
                codingPath: codingPath,
                debugDescription: "\(field) must be an exact canonical asset definition address"
            )
        )
    }
    return raw
}

private func governanceCanonicalContractAddress(
    _ raw: String,
    codingPath: [CodingKey],
    field: String
) throws -> String {
    guard raw.utf8.elementsEqual(
        raw.trimmingCharacters(in: .whitespacesAndNewlines).utf8
    ), ContractAddressV1.isCanonical(raw) else {
        throw DecodingError.dataCorrupted(
            .init(
                codingPath: codingPath,
                debugDescription: "\(field) must be an exact canonical ABI V1 contract address"
            )
        )
    }
    return raw
}

func governanceFixedBytes(
    _ bytes: [UInt8],
    count: Int,
    nonzero: Bool = false,
    codingPath: [CodingKey],
    field: String
) throws -> Data {
    guard bytes.count == count, !nonzero || bytes.contains(where: { $0 != 0 }) else {
        throw DecodingError.dataCorrupted(
            .init(
                codingPath: codingPath,
                debugDescription: "\(field) must contain exactly \(count)\(nonzero ? " non-zero" : "") bytes"
            )
        )
    }
    return Data(bytes)
}

private func governanceLowercaseHash32(
    _ raw: String,
    codingPath: [CodingKey],
    field: String
) throws -> Data {
    guard raw.utf8.count == 64,
          raw.utf8.allSatisfy({ byte in
              (0x30...0x39).contains(byte) || (0x61...0x66).contains(byte)
          }),
          let bytes = Data(hexString: raw),
          bytes.count == 32 else {
        throw DecodingError.dataCorrupted(
            .init(
                codingPath: codingPath,
                debugDescription: "\(field) must be exactly 64 lowercase hexadecimal characters"
            )
        )
    }
    return bytes
}

private func governanceNonBlankReason(
    _ raw: String,
    codingPath: [CodingKey],
    field: String
) throws -> String {
    guard !raw.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
        throw DecodingError.dataCorrupted(
            .init(
                codingPath: codingPath,
                debugDescription: "\(field) must contain non-whitespace text"
            )
        )
    }
    return raw
}

private func governanceCanonicalBase64(
    _ raw: String,
    codingPath: [CodingKey],
    field: String
) throws -> Data {
    guard let decoded = Data(base64Encoded: raw), decoded.base64EncodedString() == raw else {
        throw DecodingError.dataCorrupted(
            .init(
                codingPath: codingPath,
                debugDescription: "\(field) must use exact canonical base64"
            )
        )
    }
    return decoded
}

private func governanceCanonicalQuantity(
    _ raw: String,
    codingPath: [CodingKey],
    field: String
) throws -> String {
    do {
        let decoded = try KotodamaNumericV1Codec.decodeQuantityJSON(raw)
        guard decoded.canonicalString == raw else {
            throw DecodingError.dataCorrupted(
                .init(codingPath: codingPath, debugDescription: "noncanonical Quantity")
            )
        }
        return raw
    } catch {
        throw DecodingError.dataCorrupted(
            .init(
                codingPath: codingPath,
                debugDescription: "\(field) must be a canonical non-negative Quantity string"
            )
        )
    }
}

private func governanceCanonicalNumeric(
    _ raw: String,
    codingPath: [CodingKey],
    field: String
) throws -> String {
    do {
        let decoded = try KotodamaNumericV1Codec.decodeDecimalJSON(raw)
        guard decoded.canonicalString == raw else {
            throw DecodingError.dataCorrupted(
                .init(codingPath: codingPath, debugDescription: "noncanonical Numeric")
            )
        }
        return raw
    } catch {
        throw DecodingError.dataCorrupted(
            .init(
                codingPath: codingPath,
                debugDescription: "\(field) must be a canonical Numeric string"
            )
        )
    }
}

private func governanceCanonicalUInt64String(
    _ raw: String,
    codingPath: [CodingKey],
    field: String,
    positive: Bool = false
) throws -> String {
    guard !raw.isEmpty,
          raw.allSatisfy({ $0 >= "0" && $0 <= "9" }),
          raw == "0" || raw.first != "0",
          let parsed = UInt64(raw),
          !positive || parsed > 0 else {
        throw DecodingError.dataCorrupted(
            .init(
                codingPath: codingPath,
                debugDescription: "\(field) must be a canonical UInt64 decimal string"
            )
        )
    }
    return raw
}

/// Stored payload for a governed runtime-upgrade proposal.
public struct ToriiGovernanceRuntimeUpgradeProposal: Decodable, Sendable, Equatable {
    public let proposalOperator: String
    public let manifest: ToriiGovernanceRuntimeUpgradeManifest

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case proposalOperator = "proposal_operator"
        case manifest
    }

    public init(from decoder: Decoder) throws {
        try governanceRejectUnknownFields(
            decoder,
            allowed: Set(CodingKeys.allCases.map(\.stringValue)),
            name: "runtime-upgrade proposal"
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        proposalOperator = try governanceCanonicalAccount(
            container.decode(String.self, forKey: .proposalOperator),
            codingPath: container.codingPath + [CodingKeys.proposalOperator],
            field: "proposal_operator"
        )
        manifest = try container.decode(ToriiGovernanceRuntimeUpgradeManifest.self, forKey: .manifest)
    }
}

/// Exact SBOM digest carried by a governed runtime-upgrade manifest.
public struct ToriiGovernanceRuntimeUpgradeSbomDigest: Decodable, Sendable, Equatable {
    public let algorithm: String
    public let digest: Data

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case algorithm
        case digest
    }

    public init(from decoder: Decoder) throws {
        try governanceRejectUnknownFields(
            decoder,
            allowed: Set(CodingKeys.allCases.map(\.stringValue)),
            name: "runtime-upgrade SBOM digest"
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        algorithm = try container.decode(String.self, forKey: .algorithm)
        guard !algorithm.isEmpty,
              algorithm.utf8.elementsEqual(
                  algorithm.trimmingCharacters(in: .whitespacesAndNewlines).utf8
              ) else {
            throw DecodingError.dataCorruptedError(
                forKey: .algorithm,
                in: container,
                debugDescription: "SBOM algorithm must be an exact non-empty string"
            )
        }
        digest = try governanceCanonicalBase64(
            container.decode(String.self, forKey: .digest),
            codingPath: container.codingPath + [CodingKeys.digest],
            field: "digest"
        )
    }
}

/// Canonical V1 runtime-upgrade manifest stored inside a governance proposal.
public struct ToriiGovernanceRuntimeUpgradeManifest: Decodable, Sendable, Equatable {
    public let name: String
    public let description: String
    public let abiVersion: UInt16
    public let abiHash: Data
    public let addedSyscalls: [UInt16]
    public let addedPointerTypes: [UInt16]
    public let startHeight: UInt64
    public let endHeight: UInt64
    public let sbomDigests: [ToriiGovernanceRuntimeUpgradeSbomDigest]
    public let slsaAttestation: Data
    public let provenance: [ToriiContractManifestProvenance]

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case name
        case description
        case abiVersion = "abi_version"
        case abiHash = "abi_hash"
        case addedSyscalls = "added_syscalls"
        case addedPointerTypes = "added_pointer_types"
        case startHeight = "start_height"
        case endHeight = "end_height"
        case sbomDigests = "sbom_digests"
        case slsaAttestation = "slsa_attestation"
        case provenance
    }

    public init(from decoder: Decoder) throws {
        try governanceRejectUnknownFields(
            decoder,
            allowed: Set(CodingKeys.allCases.map(\.stringValue)),
            name: "runtime-upgrade manifest"
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        name = try container.decode(String.self, forKey: .name)
        description = try container.decode(String.self, forKey: .description)
        abiVersion = try container.decode(UInt16.self, forKey: .abiVersion)
        guard abiVersion == 1 else {
            throw DecodingError.dataCorruptedError(
                forKey: .abiVersion,
                in: container,
                debugDescription: "runtime-upgrade abi_version must be exactly 1"
            )
        }
        abiHash = try governanceFixedBytes(
            container.decode([UInt8].self, forKey: .abiHash),
            count: 32,
            codingPath: container.codingPath + [CodingKeys.abiHash],
            field: "abi_hash"
        )
        addedSyscalls = try container.decode([UInt16].self, forKey: .addedSyscalls)
        addedPointerTypes = try container.decode([UInt16].self, forKey: .addedPointerTypes)
        guard addedSyscalls.isEmpty, addedPointerTypes.isEmpty else {
            throw DecodingError.dataCorrupted(
                .init(
                    codingPath: container.codingPath,
                    debugDescription: "runtime-upgrade V1 delta lists must be empty"
                )
            )
        }
        startHeight = try container.decode(UInt64.self, forKey: .startHeight)
        endHeight = try container.decode(UInt64.self, forKey: .endHeight)
        guard startHeight < endHeight else {
            throw DecodingError.dataCorruptedError(
                forKey: .endHeight,
                in: container,
                debugDescription: "runtime-upgrade end_height must be greater than start_height"
            )
        }
        sbomDigests = try container.decode(
            [ToriiGovernanceRuntimeUpgradeSbomDigest].self,
            forKey: .sbomDigests
        )
        slsaAttestation = try governanceCanonicalBase64(
            container.decode(String.self, forKey: .slsaAttestation),
            codingPath: container.codingPath + [CodingKeys.slsaAttestation],
            field: "slsa_attestation"
        )
        provenance = try container.decode(
            [ToriiContractManifestProvenance].self,
            forKey: .provenance
        )
    }
}

/// Stored payload for one network-bound SCCP governance proposal.
///
/// The wrapper is exact: `proposal` is its only field and holds the closed
/// `SccpGovernanceProposalV1` envelope (specs/sccp.md §4.14.3), which is checked
/// before the body is kept as the validated JSON value:
/// - the body has exactly `network_id`, `base_revisions` and `actions`;
/// - `network_id` is a canonical `NetworkId` literal;
/// - `base_revisions` holds 1...16 exact `{subject, revision}` entries, where
///   `revision` is an exact unsigned JSON integer and `subject` is `route`,
///   `route_control` or `light_client` keyed by an external network with a null
///   profile, `parameters` with a null key, or `bridge_key_fault` keyed by a
///   canonical BLS validator id;
/// - `actions` holds 1...16 exact `{action, payload}` entries with a known action
///   tag and a JSON object payload.
// TODO: decode each action `payload` into its typed `SccpGovernanceActionV1` body and
// run the remaining `SccpGovernanceProposalV1::validate_static` checks (for example
// that `base_revisions` lists exactly the subjects the actions touch) once SDK SCCP
// support is exported through `connect_norito_bridge` (specs/sccp.md §8). Torii and
// the node remain authoritative for those checks.
public struct ToriiGovernanceSccpRouteProposal: Decodable, Sendable, Equatable {
    /// Complete network-bound SCCP proposal: base revisions and ordered actions.
    public let proposal: ToriiJSONValue

    private enum CodingKeys: String, CodingKey, CaseIterable { case proposal }

    private static let maximumEntries = 16
    private static let externalNetworks: Set<String> = [
        "ethereum_mainnet", "bsc_mainnet", "ton_mainnet", "tron_mainnet",
    ]
    private static let actionTags: Set<String> = [
        "register_route", "activate_revision", "switch_revision", "deactivate_outbound",
        "retire_revision", "remove_staged", "release_stranded", "set_taira_paused",
        "set_destination_paused", "initialize_light_client", "install_trusted_checkpoint",
        "freeze_light_client", "set_parameters", "clear_bridge_key_fault",
    ]

    public init(from decoder: Decoder) throws {
        try governanceRejectUnknownFields(
            decoder,
            allowed: Set(CodingKeys.allCases.map(\.stringValue)),
            name: "SCCP route-governance proposal"
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let proposal = try container.decode(ToriiJSONValue.self, forKey: .proposal)
        let codingPath: [CodingKey] = container.codingPath + [CodingKeys.proposal]
        try governanceRequireExactJSONIntegers(
            proposal,
            codingPath: codingPath,
            context: "SCCP route-governance proposal",
            exactIntegerLexemes: decoder.userInfo[exactJSONNumberLexemesUserInfoKey]
                as? [String: String]
        )
        try Self.validateEnvelope(proposal, codingPath: codingPath)
        self.proposal = proposal
    }

    private static func validateEnvelope(
        _ proposal: ToriiJSONValue,
        codingPath: [CodingKey]
    ) throws {
        let body = try exactObject(
            proposal,
            fields: ["network_id", "base_revisions", "actions"],
            label: "proposal",
            codingPath: codingPath
        )
        guard case let .string(networkId)? = body["network_id"],
              (try? NetworkId(literal: networkId)) != nil else {
            throw invalid("network_id must be a canonical NetworkId literal", codingPath)
        }
        let baseRevisions = try boundedEntries(
            body["base_revisions"],
            label: "base_revisions",
            codingPath: codingPath
        )
        for (index, item) in baseRevisions.enumerated() {
            let label = "base_revisions[\(index)]"
            let entry = try exactObject(
                item,
                fields: ["subject", "revision"],
                label: label,
                codingPath: codingPath
            )
            try validateSubject(entry["subject"], label: "\(label).subject", codingPath: codingPath)
            guard case let .number(revision)? = entry["revision"],
                  revision.isFinite,
                  revision >= 0,
                  revision.rounded(.towardZero) == revision,
                  revision <= governanceFirstReleaseMaxExactJSONInteger else {
                throw invalid("\(label).revision must be an exact unsigned JSON integer", codingPath)
            }
        }
        let actions = try boundedEntries(body["actions"], label: "actions", codingPath: codingPath)
        for (index, item) in actions.enumerated() {
            let label = "actions[\(index)]"
            let entry = try exactObject(
                item,
                fields: ["action", "payload"],
                label: label,
                codingPath: codingPath
            )
            guard case let .string(action)? = entry["action"], actionTags.contains(action) else {
                throw invalid("\(label).action is unknown", codingPath)
            }
            guard case .object? = entry["payload"] else {
                throw invalid("\(label).payload must be a JSON object", codingPath)
            }
        }
    }

    private static func validateSubject(
        _ value: ToriiJSONValue?,
        label: String,
        codingPath: [CodingKey]
    ) throws {
        let subject = try exactObject(
            value,
            fields: ["subject", "key"],
            label: label,
            codingPath: codingPath
        )
        guard case let .string(tag)? = subject["subject"] else {
            throw invalid("\(label).subject is unknown", codingPath)
        }
        switch tag {
        case "route", "route_control", "light_client":
            let key = try exactObject(
                subject["key"],
                fields: ["network", "profile"],
                label: "\(label).key",
                codingPath: codingPath
            )
            guard case let .string(network)? = key["network"],
                  externalNetworks.contains(network) else {
                throw invalid("\(label).key.network is not an external SCCP network", codingPath)
            }
            guard case .null? = key["profile"] else {
                throw invalid("\(label).key.profile must be null", codingPath)
            }
        case "parameters":
            guard case .null? = subject["key"] else {
                throw invalid("\(label).key must be null", codingPath)
            }
        case "bridge_key_fault":
            guard case let .string(peer)? = subject["key"], isCanonicalBlsValidatorId(peer) else {
                throw invalid("\(label).key must be a canonical BLS validator id", codingPath)
            }
        default:
            throw invalid("\(label).subject is unknown", codingPath)
        }
    }

    /// Matches `ea0130` followed by 96 uppercase hex digits, the multihash form of a BLS
    /// validator public key.
    private static func isCanonicalBlsValidatorId(_ value: String) -> Bool {
        let prefix = "ea0130"
        let bytes = Array(value.utf8)
        guard bytes.count == prefix.utf8.count + 96, value.hasPrefix(prefix) else {
            return false
        }
        return bytes.dropFirst(prefix.utf8.count).allSatisfy {
            (0x30...0x39).contains($0) || (0x41...0x46).contains($0)
        }
    }

    private static func exactObject(
        _ value: ToriiJSONValue?,
        fields: Set<String>,
        label: String,
        codingPath: [CodingKey]
    ) throws -> [String: ToriiJSONValue] {
        guard case let .object(object)? = value, Set(object.keys) == fields else {
            throw invalid(
                "\(label) must be an object with exactly the fields \(fields.sorted().joined(separator: ", "))",
                codingPath
            )
        }
        return object
    }

    private static func boundedEntries(
        _ value: ToriiJSONValue?,
        label: String,
        codingPath: [CodingKey]
    ) throws -> [ToriiJSONValue] {
        guard case let .array(entries)? = value,
              (1...maximumEntries).contains(entries.count) else {
            throw invalid("\(label) must hold 1 to \(maximumEntries) entries", codingPath)
        }
        return entries
    }

    private static func invalid(_ message: String, _ codingPath: [CodingKey]) -> DecodingError {
        .dataCorrupted(
            .init(
                codingPath: codingPath,
                debugDescription: "SCCP route-governance proposal \(message)"
            )
        )
    }
}

/// Exact first-release native fee hashes use uppercase hexadecimal JSON.
private func governanceNativeFeeHash(_ value:String,codingPath:[CodingKey]) throws -> Data {
    guard value.count == 64, value.range(of:"^[0-9A-F]{64}$",options:.regularExpression) != nil, value != String(repeating:"0",count:64) else {
        throw DecodingError.dataCorrupted(.init(codingPath:codingPath,debugDescription:"Native fee hash must be nonzero uppercase hexadecimal"))
    }
    var result=Data();var index=value.startIndex
    for _ in 0..<32 {let end=value.index(index,offsetBy:2);result.append(UInt8(value[index..<end],radix:16)!);index=end}
    return result
}
private func governanceFeeRequire(_ condition:Bool,_ decoder:Decoder,_ message:String) throws {
    guard condition else {throw DecodingError.dataCorrupted(.init(codingPath:decoder.codingPath,debugDescription:message))}
}
public enum ToriiGovernanceValidationFeeChargingMode:String,Decodable,Sendable,Equatable {
    case retailMonthlyAllowance="RETAIL_MONTHLY_ALLOWANCE"
    private enum CodingKeys:String,CodingKey,CaseIterable {case chargingMode="charging_mode",value}
    public init(from decoder:Decoder)throws {
        try governanceRejectUnknownFields(decoder,allowed:Set(CodingKeys.allCases.map(\.stringValue)),name:"fee charging mode")
        let c=try decoder.container(keyedBy:CodingKeys.self)
        try governanceFeeRequire((try c.decodeNil(forKey:.value)),decoder,"Fee mode payload must be null")
        let raw=try c.decode(String.self,forKey:.chargingMode)
        try governanceFeeRequire(raw==Self.retailMonthlyAllowance.rawValue,decoder,"Unknown fee mode")
        self = .retailMonthlyAllowance
    }
}

/// Balance band in SBD cents.
public struct ToriiGovernanceRetailFeeTier:Decodable,Sendable,Equatable {
    public let minimumAverageBalanceMinor:UInt64
    public let monthlyFeeMinor:UInt64
    private enum CodingKeys:String,CodingKey,CaseIterable {
        case minimumAverageBalanceMinor="minimum_average_balance_minor"
        case monthlyFeeMinor="monthly_fee_minor"
    }
    public init(from decoder:Decoder)throws {
        try governanceRejectUnknownFields(decoder,allowed:Set(CodingKeys.allCases.map(\.stringValue)),name:"ToriiGovernanceRetailFeeTier")
        let c=try decoder.container(keyedBy:CodingKeys.self)
        minimumAverageBalanceMinor=try c.decode(UInt64.self,forKey:.minimumAverageBalanceMinor)
        monthlyFeeMinor=try c.decode(UInt64.self,forKey:.monthlyFeeMinor)
        try governanceFeeRequire(monthlyFeeMinor>0,decoder,"Monthly fee must be positive")
    }
}

/// Parliament tariff.
public struct ToriiGovernanceRetailFeeSchedule:Decodable,Sendable,Equatable {
    public let includedPayments:UInt32
    public let overageMinor:UInt64
    public let maintenanceTiers:[ToriiGovernanceRetailFeeTier]
    private enum CodingKeys:String,CodingKey,CaseIterable {
        case includedPayments="included_payments"
        case overageMinor="overage_minor"
        case maintenanceTiers="maintenance_tiers"
    }
    public init(from decoder:Decoder)throws {
        try governanceRejectUnknownFields(decoder,allowed:Set(CodingKeys.allCases.map(\.stringValue)),name:"ToriiGovernanceRetailFeeSchedule")
        let c=try decoder.container(keyedBy:CodingKeys.self)
        includedPayments=try c.decode(UInt32.self,forKey:.includedPayments)
        overageMinor=try c.decode(UInt64.self,forKey:.overageMinor)
        maintenanceTiers=try c.decode([ToriiGovernanceRetailFeeTier].self,forKey:.maintenanceTiers)
        try governanceFeeRequire(includedPayments>0 && overageMinor>0 && !maintenanceTiers.isEmpty && maintenanceTiers.count<=32 && maintenanceTiers.first?.minimumAverageBalanceMinor==0,decoder,"Invalid retail schedule")
        for index in 1..<maintenanceTiers.count {try governanceFeeRequire(maintenanceTiers[index].minimumAverageBalanceMinor>maintenanceTiers[index-1].minimumAverageBalanceMinor && maintenanceTiers[index].monthlyFeeMinor>=maintenanceTiers[index-1].monthlyFeeMinor,decoder,"Invalid maintenance tiers")}
    }
}

/// Immutable fee reward custody.
public struct ToriiGovernanceValidationFeeRewardCustody:Decodable,Sendable,Equatable {
    public let contractAddress:String
    public let treasuryAccountId:String
    public let dsAssetId:String
    public let xorAssetId:String
    public let rewardPoolAccountId:String
    public let validatorLaneId:UInt32
    private enum CodingKeys:String,CodingKey,CaseIterable {
        case contractAddress="contract_address"
        case treasuryAccountId="treasury_account_id"
        case dsAssetId="ds_asset_id"
        case xorAssetId="xor_asset_id"
        case rewardPoolAccountId="reward_pool_account_id"
        case validatorLaneId="validator_lane_id"
    }
    public init(from decoder:Decoder)throws {
        try governanceRejectUnknownFields(decoder,allowed:Set(CodingKeys.allCases.map(\.stringValue)),name:"ToriiGovernanceValidationFeeRewardCustody")
        let c=try decoder.container(keyedBy:CodingKeys.self)
        contractAddress=try governanceCanonicalContractAddress(c.decode(String.self,forKey:.contractAddress),codingPath:decoder.codingPath,field:"contract_address")
        treasuryAccountId=try governanceCanonicalAccount(c.decode(String.self,forKey:.treasuryAccountId),codingPath:decoder.codingPath,field:"treasury_account_id")
        dsAssetId=try governanceCanonicalAssetDefinition(c.decode(String.self,forKey:.dsAssetId),codingPath:decoder.codingPath,field:"ds_asset_id")
        xorAssetId=try governanceCanonicalAssetDefinition(c.decode(String.self,forKey:.xorAssetId),codingPath:decoder.codingPath,field:"xor_asset_id")
        rewardPoolAccountId=try governanceCanonicalAccount(c.decode(String.self,forKey:.rewardPoolAccountId),codingPath:decoder.codingPath,field:"reward_pool_account_id")
        validatorLaneId=try c.decode(UInt32.self,forKey:.validatorLaneId)
        try governanceFeeRequire(treasuryAccountId != rewardPoolAccountId && dsAssetId != xorAssetId,decoder,"Reward custody roles must differ")
    }
}

/// Independent Parliament conversion and validator allocation settings.
public struct ToriiGovernanceValidationFeePayoutBinding:Decodable,Sendable,Equatable {
    public let contractAddress:String
    public let codeHash:Data
    public let entrypoint:String
    public let treasuryAccountId:String
    public let dsAssetId:String
    public let xorAssetId:String
    public let poolContractAddress:String
    public let poolCodeHash:Data
    public let poolVaultAccountId:String
    public let rewardPoolAccountId:String
    public let referenceFeedId:[String]
    public let referenceFeedConfigVersion:UInt32
    public let referenceProviderAccounts:[String]
    public let maxSbdPerAttemptMinor:UInt64
    public let maxSbdPerDayMinor:UInt64
    public let minIntervalMs:UInt64
    public let maxSourceAgeMs:UInt64
    public let maxSlippageBps:UInt16
    public let validatorLaneId:UInt32
    public let minRewardClaimXorMinor:UInt64
    private enum CodingKeys:String,CodingKey,CaseIterable {
        case contractAddress="contract_address"
        case codeHash="code_hash"
        case entrypoint="entrypoint"
        case treasuryAccountId="treasury_account_id"
        case dsAssetId="ds_asset_id"
        case xorAssetId="xor_asset_id"
        case poolContractAddress="pool_contract_address"
        case poolCodeHash="pool_code_hash"
        case poolVaultAccountId="pool_vault_account_id"
        case rewardPoolAccountId="reward_pool_account_id"
        case referenceFeedId="reference_feed_id"
        case referenceFeedConfigVersion="reference_feed_config_version"
        case referenceProviderAccounts="reference_provider_accounts"
        case maxSbdPerAttemptMinor="max_sbd_per_attempt_minor"
        case maxSbdPerDayMinor="max_sbd_per_day_minor"
        case minIntervalMs="min_interval_ms"
        case maxSourceAgeMs="max_source_age_ms"
        case maxSlippageBps="max_slippage_bps"
        case validatorLaneId="validator_lane_id"
        case minRewardClaimXorMinor="min_reward_claim_xor_minor"
    }
    public init(from decoder:Decoder)throws {
        try governanceRejectUnknownFields(decoder,allowed:Set(CodingKeys.allCases.map(\.stringValue)),name:"ToriiGovernanceValidationFeePayoutBinding")
        let c=try decoder.container(keyedBy:CodingKeys.self)
        contractAddress=try governanceCanonicalContractAddress(c.decode(String.self,forKey:.contractAddress),codingPath:decoder.codingPath,field:"contract_address")
        codeHash=try governanceNativeFeeHash(c.decode(String.self,forKey:.codeHash),codingPath:decoder.codingPath)
        entrypoint=try c.decode(String.self,forKey:.entrypoint)
        treasuryAccountId=try governanceCanonicalAccount(c.decode(String.self,forKey:.treasuryAccountId),codingPath:decoder.codingPath,field:"treasury_account_id")
        dsAssetId=try governanceCanonicalAssetDefinition(c.decode(String.self,forKey:.dsAssetId),codingPath:decoder.codingPath,field:"ds_asset_id")
        xorAssetId=try governanceCanonicalAssetDefinition(c.decode(String.self,forKey:.xorAssetId),codingPath:decoder.codingPath,field:"xor_asset_id")
        poolContractAddress=try governanceCanonicalContractAddress(c.decode(String.self,forKey:.poolContractAddress),codingPath:decoder.codingPath,field:"pool_contract_address")
        poolCodeHash=try governanceNativeFeeHash(c.decode(String.self,forKey:.poolCodeHash),codingPath:decoder.codingPath)
        poolVaultAccountId=try governanceCanonicalAccount(c.decode(String.self,forKey:.poolVaultAccountId),codingPath:decoder.codingPath,field:"pool_vault_account_id")
        rewardPoolAccountId=try governanceCanonicalAccount(c.decode(String.self,forKey:.rewardPoolAccountId),codingPath:decoder.codingPath,field:"reward_pool_account_id")
        referenceFeedId=try c.decode([String].self,forKey:.referenceFeedId)
        referenceFeedConfigVersion=try c.decode(UInt32.self,forKey:.referenceFeedConfigVersion)
        referenceProviderAccounts=try c.decode([String].self,forKey:.referenceProviderAccounts)
        maxSbdPerAttemptMinor=try c.decode(UInt64.self,forKey:.maxSbdPerAttemptMinor)
        maxSbdPerDayMinor=try c.decode(UInt64.self,forKey:.maxSbdPerDayMinor)
        minIntervalMs=try c.decode(UInt64.self,forKey:.minIntervalMs)
        maxSourceAgeMs=try c.decode(UInt64.self,forKey:.maxSourceAgeMs)
        maxSlippageBps=try c.decode(UInt16.self,forKey:.maxSlippageBps)
        validatorLaneId=try c.decode(UInt32.self,forKey:.validatorLaneId)
        minRewardClaimXorMinor=try c.decode(UInt64.self,forKey:.minRewardClaimXorMinor)
        try governanceFeeRequire(entrypoint=="autonomous_validation_fee_tick" && Set([treasuryAccountId,poolVaultAccountId,rewardPoolAccountId]).count==3 && dsAssetId != xorAssetId,decoder,"Invalid conversion custody")
        try governanceFeeRequire(referenceFeedId.count==1 && !(referenceFeedId.first?.isEmpty ?? true) && referenceFeedConfigVersion>0 && referenceProviderAccounts.count==5 && Set(referenceProviderAccounts).count==5,decoder,"Invalid reference feed")
        for provider in referenceProviderAccounts {_ = try governanceCanonicalAccount(provider,codingPath:decoder.codingPath,field:"reference provider")}
        try governanceFeeRequire(maxSbdPerAttemptMinor>0 && maxSbdPerDayMinor>=maxSbdPerAttemptMinor && minIntervalMs>0 && maxSourceAgeMs>0 && maxSlippageBps<10000 && minRewardClaimXorMinor>0,decoder,"Invalid governed conversion limits")
    }
}

/// Calendar-activated customer fee policy. Conversion rules have a separate enactment.
public struct ToriiGovernanceValidationFeePolicy:Decodable,Sendable,Equatable {
    public let schemaVersion:UInt16
    public let networkId:NetworkId
    public let policyVersion:String
    public let previousPolicyHash:Data?
    public let dsAssetId:String
    public let dsScale:UInt8
    public let retailSchedule:ToriiGovernanceRetailFeeSchedule
    public let effectiveFromMs:UInt64
    public let noticePublishedAtMs:UInt64
    public let fee:String
    public let treasuryAccountId:String
    public let chargingMode:ToriiGovernanceValidationFeeChargingMode
    public let exemptionClasses:[String]
    public let rewardCustody:ToriiGovernanceValidationFeeRewardCustody
    private enum CodingKeys:String,CodingKey,CaseIterable {
        case schemaVersion="schema_version"
        case networkId="network_id"
        case policyVersion="policy_version"
        case previousPolicyHash="previous_policy_hash"
        case dsAssetId="ds_asset_id"
        case dsScale="ds_scale"
        case retailSchedule="retail_schedule"
        case effectiveFromMs="effective_from_ms"
        case noticePublishedAtMs="notice_published_at_ms"
        case fee="fee"
        case treasuryAccountId="treasury_account_id"
        case chargingMode="charging_mode"
        case exemptionClasses="exemption_classes"
        case rewardCustody="reward_custody"
    }
    public init(from decoder:Decoder)throws {
        try governanceRejectUnknownFields(decoder,allowed:Set(CodingKeys.allCases.map(\.stringValue)),name:"ToriiGovernanceValidationFeePolicy")
        let c=try decoder.container(keyedBy:CodingKeys.self)
        schemaVersion=try c.decode(UInt16.self,forKey:.schemaVersion)
        networkId=try c.decode(NetworkId.self,forKey:.networkId)
        policyVersion=try governanceCanonicalUInt64String(c.decode(String.self,forKey:.policyVersion),codingPath:decoder.codingPath,field:"policy_version",positive:true)
        try governanceFeeRequire(c.contains(.previousPolicyHash),decoder,"previous_policy_hash must be explicit")
        previousPolicyHash=try c.decodeIfPresent(String.self,forKey:.previousPolicyHash).map {try governanceNativeFeeHash($0,codingPath:decoder.codingPath)}
        dsAssetId=try governanceCanonicalAssetDefinition(c.decode(String.self,forKey:.dsAssetId),codingPath:decoder.codingPath,field:"ds_asset_id")
        dsScale=try c.decode(UInt8.self,forKey:.dsScale)
        retailSchedule=try c.decode(ToriiGovernanceRetailFeeSchedule.self,forKey:.retailSchedule)
        effectiveFromMs=try c.decode(UInt64.self,forKey:.effectiveFromMs)
        noticePublishedAtMs=try c.decode(UInt64.self,forKey:.noticePublishedAtMs)
        fee=try governanceCanonicalQuantity(c.decode(String.self,forKey:.fee),codingPath:decoder.codingPath,field:"fee")
        treasuryAccountId=try governanceCanonicalAccount(c.decode(String.self,forKey:.treasuryAccountId),codingPath:decoder.codingPath,field:"treasury_account_id")
        chargingMode=try c.decode(ToriiGovernanceValidationFeeChargingMode.self,forKey:.chargingMode)
        exemptionClasses=try c.decode([String].self,forKey:.exemptionClasses)
        rewardCustody=try c.decode(ToriiGovernanceValidationFeeRewardCustody.self,forKey:.rewardCustody)
        try governanceFeeRequire(schemaVersion==1 && dsScale==2 && (policyVersion=="1") == (previousPolicyHash==nil) && fee != "0" && (fee.split(separator:".").dropFirst().first?.count ?? 0) <= 2,decoder,"Invalid tariff policy")
        try governanceFeeRequire(effectiveFromMs>=noticePublishedAtMs && effectiveFromMs-noticePublishedAtMs>=30*86_400_000,decoder,"Fee changes require public notice")
        var calendar=Calendar(identifier:.gregorian);calendar.timeZone=TimeZone(secondsFromGMT:11*3600)!
        let date=Date(timeIntervalSince1970:Double(effectiveFromMs)/1000)
        let components=calendar.dateComponents([.day,.hour,.minute,.second],from:date)
        try governanceFeeRequire(effectiveFromMs%1000==0 && components.day==1 && components.hour==0 && components.minute==0 && components.second==0,decoder,"Fee activation requires Honiara month boundary")
        try governanceFeeRequire(exemptionClasses==["TREASURY_PAYOUT"] && rewardCustody.treasuryAccountId==treasuryAccountId && rewardCustody.dsAssetId==dsAssetId,decoder,"Fee reward custody differs from tariff")
    }
}

/// Exact customer fee proposal.
public struct ToriiGovernanceValidationFeePolicyProposal:Decodable,Sendable,Equatable {
    public let proposalOperator:String
    public let policy:ToriiGovernanceValidationFeePolicy
    private enum CodingKeys:String,CodingKey,CaseIterable {
        case proposalOperator="proposal_operator"
        case policy="policy"
    }
    public init(from decoder:Decoder)throws {
        try governanceRejectUnknownFields(decoder,allowed:Set(CodingKeys.allCases.map(\.stringValue)),name:"ToriiGovernanceValidationFeePolicyProposal")
        let c=try decoder.container(keyedBy:CodingKeys.self)
        proposalOperator=try governanceCanonicalAccount(c.decode(String.self,forKey:.proposalOperator),codingPath:decoder.codingPath,field:"proposal_operator")
        policy=try c.decode(ToriiGovernanceValidationFeePolicy.self,forKey:.policy)

    }
}
/// Stored payload authorizing one exact validation-fee payout lifecycle.
public struct ToriiGovernanceValidationFeePayoutLifecycleProposal: Decodable, Sendable, Equatable {
    public let proposalOperator: String
    public let payoutBinding: ToriiGovernanceValidationFeePayoutBinding

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case proposalOperator = "proposal_operator"
        case payoutBinding = "payout_binding"
    }

    public init(from decoder: Decoder) throws {
        try governanceRejectUnknownFields(
            decoder,
            allowed: Set(CodingKeys.allCases.map(\.stringValue)),
            name: "validation-fee payout-lifecycle proposal"
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        proposalOperator = try governanceCanonicalAccount(
            container.decode(String.self, forKey: .proposalOperator),
            codingPath: container.codingPath + [CodingKeys.proposalOperator],
            field: "proposal_operator"
        )
        payoutBinding = try container.decode(
            ToriiGovernanceValidationFeePayoutBinding.self,
            forKey: .payoutBinding
        )
    }
}

/// Closed Musubi registry-admission mode carried by a Parliament policy action.
public enum ToriiGovernanceMusubiAdmissionMode: String, Decodable, Sendable, Equatable {
    case closed = "Closed"
    case allowlisted = "Allowlisted"
    case open = "Open"

    private enum CodingKeys: String, CodingKey, CaseIterable { case kind, value }

    public init(from decoder: Decoder) throws {
        try governanceRejectUnknownFields(
            decoder,
            allowed: Set(CodingKeys.allCases.map(\.stringValue)),
            name: "Musubi registry-admission mode"
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        guard container.contains(.value), try container.decodeNil(forKey: .value) else {
            throw DecodingError.dataCorruptedError(
                forKey: .value,
                in: container,
                debugDescription: "Musubi registry-admission mode value must be explicit null"
            )
        }
        let raw = try container.decode(String.self, forKey: .kind)
        guard let value = Self(rawValue: raw) else {
            throw DecodingError.dataCorruptedError(
                forKey: .kind,
                in: container,
                debugDescription: "unsupported Musubi registry-admission mode"
            )
        }
        self = value
    }
}

/// Prospective whole-XOR price schedule for permanent Musubi aliases.
public struct ToriiGovernanceMusubiAliasPricingPolicy: Decodable, Sendable, Equatable {
    public let revision: UInt64
    public let length1Xor: UInt64
    public let length2Xor: UInt64
    public let length3Xor: UInt64
    public let length4Xor: UInt64
    public let length5To32Xor: UInt64

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case revision
        case length1Xor = "length_1_xor"
        case length2Xor = "length_2_xor"
        case length3Xor = "length_3_xor"
        case length4Xor = "length_4_xor"
        case length5To32Xor = "length_5_to_32_xor"
    }

    public init(from decoder: Decoder) throws {
        try governanceRejectUnknownFields(
            decoder,
            allowed: Set(CodingKeys.allCases.map(\.stringValue)),
            name: "Musubi alias-pricing policy"
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        revision = try container.decode(UInt64.self, forKey: .revision)
        length1Xor = try container.decode(UInt64.self, forKey: .length1Xor)
        length2Xor = try container.decode(UInt64.self, forKey: .length2Xor)
        length3Xor = try container.decode(UInt64.self, forKey: .length3Xor)
        length4Xor = try container.decode(UInt64.self, forKey: .length4Xor)
        length5To32Xor = try container.decode(UInt64.self, forKey: .length5To32Xor)
        guard [revision, length1Xor, length2Xor, length3Xor, length4Xor, length5To32Xor]
            .allSatisfy({ $0 > 0 }) else {
            throw DecodingError.dataCorrupted(
                .init(codingPath: container.codingPath, debugDescription: "Musubi alias prices must be non-zero")
            )
        }
    }
}

/// Complete first-release Musubi registry policy carried by Parliament.
public struct ToriiGovernanceMusubiRegistryPolicy: Decodable, Sendable, Equatable {
    public let version: UInt8
    public let revision: UInt64
    public let mode: ToriiGovernanceMusubiAdmissionMode
    public let allowlistedDataspaces: [UInt64]
    public let aliasPricing: ToriiGovernanceMusubiAliasPricingPolicy

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case version
        case revision
        case mode
        case allowlistedDataspaces = "allowlisted_dataspaces"
        case aliasPricing = "alias_pricing"
    }

    public init(from decoder: Decoder) throws {
        try governanceRejectUnknownFields(
            decoder,
            allowed: Set(CodingKeys.allCases.map(\.stringValue)),
            name: "Musubi registry policy"
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        version = try container.decode(UInt8.self, forKey: .version)
        revision = try container.decode(UInt64.self, forKey: .revision)
        mode = try container.decode(ToriiGovernanceMusubiAdmissionMode.self, forKey: .mode)
        allowlistedDataspaces = try container.decode(
            [UInt64].self,
            forKey: .allowlistedDataspaces
        )
        aliasPricing = try container.decode(
            ToriiGovernanceMusubiAliasPricingPolicy.self,
            forKey: .aliasPricing
        )
        guard version == 1,
              revision > 0,
              allowlistedDataspaces.count <= 1_024,
              zip(allowlistedDataspaces, allowlistedDataspaces.dropFirst())
                .allSatisfy({ $0.0 < $0.1 }),
              mode == .allowlisted || allowlistedDataspaces.isEmpty else {
            throw DecodingError.dataCorrupted(
                .init(codingPath: container.codingPath, debugDescription: "Musubi registry policy is invalid")
            )
        }
    }
}

/// Parliament package-owner recovery payload.
public struct ToriiGovernanceMusubiRecoverPackageOwners: Decodable, Sendable, Equatable {
    public let package: MusubiPackageIdV1
    public let owners: [String]
    public let expectedRevision: UInt64

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case package
        case owners
        case expectedRevision = "expected_revision"
    }

    public init(from decoder: Decoder) throws {
        try governanceRejectUnknownFields(
            decoder,
            allowed: Set(CodingKeys.allCases.map(\.stringValue)),
            name: "Musubi package-owner recovery"
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        package = try container.decode(MusubiPackageIdV1.self, forKey: .package)
        let rawOwners = try container.decode([String].self, forKey: .owners)
        owners = try rawOwners.enumerated().map { index, owner in
            try governanceCanonicalAccount(
                owner,
                codingPath: container.codingPath + [CodingKeys.owners, GovernanceProposalCodingKey(intValue: index)!],
                field: "owners"
            )
        }
        expectedRevision = try container.decode(UInt64.self, forKey: .expectedRevision)
        guard !owners.isEmpty,
              owners.count <= 64,
              Set(owners).count == owners.count,
              expectedRevision > 0 else {
            throw DecodingError.dataCorrupted(
                .init(codingPath: container.codingPath, debugDescription: "Musubi owner recovery is invalid")
            )
        }
    }
}

/// Parliament permanent-alias recovery payload.
public struct ToriiGovernanceMusubiRetargetAlias: Decodable, Sendable, Equatable {
    public let alias: MusubiAliasNameV1
    public let target: MusubiPackageIdV1
    public let expectedRevision: UInt64

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case alias
        case target
        case expectedRevision = "expected_revision"
    }

    public init(from decoder: Decoder) throws {
        try governanceRejectUnknownFields(
            decoder,
            allowed: Set(CodingKeys.allCases.map(\.stringValue)),
            name: "Musubi alias-retarget action"
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        alias = try container.decode(MusubiAliasNameV1.self, forKey: .alias)
        target = try container.decode(MusubiPackageIdV1.self, forKey: .target)
        expectedRevision = try container.decode(UInt64.self, forKey: .expectedRevision)
        guard expectedRevision > 0 else {
            throw DecodingError.dataCorruptedError(
                forKey: .expectedRevision,
                in: container,
                debugDescription: "Musubi alias-retarget revision must be non-zero"
            )
        }
    }
}

/// Parliament immutable-artifact takedown payload.
public struct ToriiGovernanceMusubiTakedownArtifact: Decodable, Sendable, Equatable {
    public let release: MusubiReleaseIdV1
    public let reason: MusubiReasonV1
    public let expectedArtifactGovernanceRevision: UInt64

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case release
        case reason
        case expectedArtifactGovernanceRevision = "expected_artifact_governance_revision"
    }

    public init(from decoder: Decoder) throws {
        try governanceRejectUnknownFields(
            decoder,
            allowed: Set(CodingKeys.allCases.map(\.stringValue)),
            name: "Musubi artifact-takedown action"
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        release = try container.decode(MusubiReleaseIdV1.self, forKey: .release)
        reason = try container.decode(MusubiReasonV1.self, forKey: .reason)
        expectedArtifactGovernanceRevision = try container.decode(
            UInt64.self,
            forKey: .expectedArtifactGovernanceRevision
        )
        guard expectedArtifactGovernanceRevision > 0 else {
            throw DecodingError.dataCorruptedError(
                forKey: .expectedArtifactGovernanceRevision,
                in: container,
                debugDescription: "Musubi artifact-governance revision must be non-zero"
            )
        }
    }
}

/// Parliament registry-policy replacement payload.
public struct ToriiGovernanceMusubiSetRegistryPolicy: Decodable, Sendable, Equatable {
    public let policy: ToriiGovernanceMusubiRegistryPolicy
    public let expectedRevision: UInt64

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case policy
        case expectedRevision = "expected_revision"
    }

    public init(from decoder: Decoder) throws {
        try governanceRejectUnknownFields(
            decoder,
            allowed: Set(CodingKeys.allCases.map(\.stringValue)),
            name: "Musubi registry-policy action"
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        policy = try container.decode(ToriiGovernanceMusubiRegistryPolicy.self, forKey: .policy)
        expectedRevision = try container.decode(UInt64.self, forKey: .expectedRevision)
        guard expectedRevision > 0,
              expectedRevision < UInt64.max,
              policy.revision == expectedRevision + 1 else {
            throw DecodingError.dataCorrupted(
                .init(codingPath: container.codingPath, debugDescription: "Musubi policy replacement is not the exact successor")
            )
        }
    }
}

/// Closed Parliament-only Musubi governance action inventory.
public enum ToriiGovernanceMusubiRegistryAction: Decodable, Sendable, Equatable {
    case recoverPackageOwners(ToriiGovernanceMusubiRecoverPackageOwners)
    case retargetAlias(ToriiGovernanceMusubiRetargetAlias)
    case takedownArtifact(ToriiGovernanceMusubiTakedownArtifact)
    case setRegistryPolicy(ToriiGovernanceMusubiSetRegistryPolicy)

    private enum CodingKeys: String, CodingKey, CaseIterable { case kind, value }

    public init(from decoder: Decoder) throws {
        try governanceRejectUnknownFields(
            decoder,
            allowed: Set(CodingKeys.allCases.map(\.stringValue)),
            name: "Musubi Parliament action"
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        switch try container.decode(String.self, forKey: .kind) {
        case "RecoverPackageOwners":
            self = .recoverPackageOwners(
                try container.decode(
                    ToriiGovernanceMusubiRecoverPackageOwners.self,
                    forKey: .value
                )
            )
        case "RetargetAlias":
            self = .retargetAlias(
                try container.decode(ToriiGovernanceMusubiRetargetAlias.self, forKey: .value)
            )
        case "TakedownArtifact":
            self = .takedownArtifact(
                try container.decode(ToriiGovernanceMusubiTakedownArtifact.self, forKey: .value)
            )
        case "SetRegistryPolicy":
            self = .setRegistryPolicy(
                try container.decode(ToriiGovernanceMusubiSetRegistryPolicy.self, forKey: .value)
            )
        case let tag:
            throw DecodingError.dataCorruptedError(
                forKey: .kind,
                in: container,
                debugDescription: "unsupported Musubi Parliament action \(tag)"
            )
        }
    }
}

/// Canonical Norito JSON newtype for one non-zero SoraFS provider id.
public struct ToriiGovernanceSorafsProviderId: Decodable, Sendable, Equatable {
    public let bytes: Data

    public init(from decoder: Decoder) throws {
        var outer = try decoder.unkeyedContainer()
        let raw = try outer.decode([UInt8].self)
        guard outer.isAtEnd else {
            throw DecodingError.dataCorruptedError(
                in: outer,
                debugDescription: "SoraFS provider id must contain one Norito newtype item"
            )
        }
        bytes = try governanceFixedBytes(
            raw,
            count: 32,
            nonzero: true,
            codingPath: decoder.codingPath,
            field: "provider_id"
        )
    }
}

/// Establish one previously unknown SoraFS provider-owner binding.
public struct ToriiGovernanceSorafsEstablishProvider: Decodable, Sendable, Equatable {
    public let providerId: ToriiGovernanceSorafsProviderId
    public let owner: String

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case providerId = "provider_id"
        case owner
    }

    public init(from decoder: Decoder) throws {
        try governanceRejectUnknownFields(
            decoder,
            allowed: Set(CodingKeys.allCases.map(\.stringValue)),
            name: "SoraFS provider-owner establish action"
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        providerId = try container.decode(ToriiGovernanceSorafsProviderId.self, forKey: .providerId)
        owner = try governanceCanonicalAccount(
            container.decode(String.self, forKey: .owner),
            codingPath: container.codingPath + [CodingKeys.owner],
            field: "owner"
        )
    }
}

/// Compare-and-set one SoraFS provider-owner replacement.
public struct ToriiGovernanceSorafsRebindProvider: Decodable, Sendable, Equatable {
    public let providerId: ToriiGovernanceSorafsProviderId
    public let expectedOwner: String
    public let nextOwner: String

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case providerId = "provider_id"
        case expectedOwner = "expected_owner"
        case nextOwner = "next_owner"
    }

    public init(from decoder: Decoder) throws {
        try governanceRejectUnknownFields(
            decoder,
            allowed: Set(CodingKeys.allCases.map(\.stringValue)),
            name: "SoraFS provider-owner rebind action"
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        providerId = try container.decode(ToriiGovernanceSorafsProviderId.self, forKey: .providerId)
        expectedOwner = try governanceCanonicalAccount(
            container.decode(String.self, forKey: .expectedOwner),
            codingPath: container.codingPath + [CodingKeys.expectedOwner],
            field: "expected_owner"
        )
        nextOwner = try governanceCanonicalAccount(
            container.decode(String.self, forKey: .nextOwner),
            codingPath: container.codingPath + [CodingKeys.nextOwner],
            field: "next_owner"
        )
        guard expectedOwner != nextOwner else {
            throw DecodingError.dataCorrupted(
                .init(codingPath: container.codingPath, debugDescription: "SoraFS rebind must change the owner")
            )
        }
    }
}

/// Compare-and-remove one SoraFS provider-owner binding.
public struct ToriiGovernanceSorafsRemoveProvider: Decodable, Sendable, Equatable {
    public let providerId: ToriiGovernanceSorafsProviderId
    public let expectedOwner: String

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case providerId = "provider_id"
        case expectedOwner = "expected_owner"
    }

    public init(from decoder: Decoder) throws {
        try governanceRejectUnknownFields(
            decoder,
            allowed: Set(CodingKeys.allCases.map(\.stringValue)),
            name: "SoraFS provider-owner remove action"
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        providerId = try container.decode(ToriiGovernanceSorafsProviderId.self, forKey: .providerId)
        expectedOwner = try governanceCanonicalAccount(
            container.decode(String.self, forKey: .expectedOwner),
            codingPath: container.codingPath + [CodingKeys.expectedOwner],
            field: "expected_owner"
        )
    }
}

/// Closed SoraFS provider-owner governance action inventory.
public enum ToriiGovernanceSorafsProviderAction: Decodable, Sendable, Equatable {
    case establish(ToriiGovernanceSorafsEstablishProvider)
    case rebind(ToriiGovernanceSorafsRebindProvider)
    case remove(ToriiGovernanceSorafsRemoveProvider)

    private enum CodingKeys: String, CodingKey, CaseIterable { case action, value }

    public init(from decoder: Decoder) throws {
        try governanceRejectUnknownFields(
            decoder,
            allowed: Set(CodingKeys.allCases.map(\.stringValue)),
            name: "SoraFS provider governance action"
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        switch try container.decode(String.self, forKey: .action) {
        case "establish":
            self = .establish(
                try container.decode(ToriiGovernanceSorafsEstablishProvider.self, forKey: .value)
            )
        case "rebind":
            self = .rebind(
                try container.decode(ToriiGovernanceSorafsRebindProvider.self, forKey: .value)
            )
        case "remove":
            self = .remove(
                try container.decode(ToriiGovernanceSorafsRemoveProvider.self, forKey: .value)
            )
        case let tag:
            throw DecodingError.dataCorruptedError(
                forKey: .action,
                in: container,
                debugDescription: "unsupported SoraFS provider governance action \(tag)"
            )
        }
    }
}

/// Stored payload for one governed SoraFS provider-owner transition.
public struct ToriiGovernanceSorafsProviderProposal: Decodable, Sendable, Equatable {
    public let action: ToriiGovernanceSorafsProviderAction

    private enum CodingKeys: String, CodingKey, CaseIterable { case action }

    public init(from decoder: Decoder) throws {
        try governanceRejectUnknownFields(
            decoder,
            allowed: Set(CodingKeys.allCases.map(\.stringValue)),
            name: "SoraFS provider governance proposal"
        )
        action = try decoder.container(keyedBy: CodingKeys.self)
            .decode(ToriiGovernanceSorafsProviderAction.self, forKey: .action)
    }
}

/// Exact activation payload in a governed contract-lifecycle transition.
public struct ToriiGovernanceContractActivateActionV1: Decodable, Sendable, Equatable {
    public let codeHash: Data
    public let abiHash: Data
    public let abiVersion: UInt16
    public let manifestProvenance: ToriiContractManifestProvenance?

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case codeHash = "code_hash"
        case abiHash = "abi_hash"
        case abiVersion = "abi_version"
        case manifestProvenance = "manifest_provenance"
    }

    public init(from decoder: Decoder) throws {
        try governanceRejectUnknownFields(
            decoder,
            allowed: Set(CodingKeys.allCases.map(\.stringValue)),
            name: "contract lifecycle activation"
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        codeHash = try governanceLowercaseHash32(
            container.decode(String.self, forKey: .codeHash),
            codingPath: container.codingPath + [CodingKeys.codeHash],
            field: "code_hash"
        )
        abiHash = try governanceLowercaseHash32(
            container.decode(String.self, forKey: .abiHash),
            codingPath: container.codingPath + [CodingKeys.abiHash],
            field: "abi_hash"
        )
        abiVersion = try container.decode(UInt16.self, forKey: .abiVersion)
        guard abiVersion == 1 else {
            throw DecodingError.dataCorruptedError(
                forKey: .abiVersion,
                in: container,
                debugDescription: "contract lifecycle activation abi_version must be exactly 1"
            )
        }
        guard container.contains(.manifestProvenance) else {
            throw DecodingError.keyNotFound(
                CodingKeys.manifestProvenance,
                .init(
                    codingPath: container.codingPath,
                    debugDescription: "manifest_provenance must be explicit, including null"
                )
            )
        }
        manifestProvenance = try container.decodeIfPresent(
            ToriiContractManifestProvenance.self,
            forKey: .manifestProvenance
        )
    }
}

/// Exact deactivation payload in a governed contract-lifecycle transition.
public struct ToriiGovernanceContractDeactivateActionV1: Decodable, Sendable, Equatable {
    public let expectedCodeHash: Data
    public let reason: String?

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case expectedCodeHash = "expected_code_hash"
        case reason
    }

    public init(from decoder: Decoder) throws {
        try governanceRejectUnknownFields(
            decoder,
            allowed: Set(CodingKeys.allCases.map(\.stringValue)),
            name: "contract lifecycle deactivation"
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        expectedCodeHash = try governanceLowercaseHash32(
            container.decode(String.self, forKey: .expectedCodeHash),
            codingPath: container.codingPath + [CodingKeys.expectedCodeHash],
            field: "expected_code_hash"
        )
        reason = try container.decodeIfPresent(String.self, forKey: .reason)
    }
}

/// Exact ownership-offer payload in a governed contract-lifecycle transition.
public struct ToriiGovernanceContractOfferOwnershipActionV1: Decodable, Sendable, Equatable {
    public let newOwner: String

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case newOwner = "new_owner"
    }

    public init(from decoder: Decoder) throws {
        try governanceRejectUnknownFields(
            decoder,
            allowed: Set(CodingKeys.allCases.map(\.stringValue)),
            name: "contract lifecycle ownership offer"
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        newOwner = try governanceCanonicalAccount(
            container.decode(String.self, forKey: .newOwner),
            codingPath: container.codingPath + [CodingKeys.newOwner],
            field: "new_owner"
        )
    }
}

/// Exact retained-hold binding and certified finding for an emergency-hold retrospective.
public struct ToriiGovernanceCompleteContractEmergencyHoldRetrospectiveActionV1:
    Decodable, Sendable, Equatable
{
    public let holdProposalContentId: Data
    public let holdGovernanceAttemptId: Data
    public let incidentDigest: Data
    public let retrospectiveFindingRoot: Data

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case holdProposalContentId = "hold_proposal_content_id"
        case holdGovernanceAttemptId = "hold_governance_attempt_id"
        case incidentDigest = "incident_digest"
        case retrospectiveFindingRoot = "retrospective_finding_root"
    }

    public init(from decoder: Decoder) throws {
        try governanceRejectUnknownFields(
            decoder,
            allowed: Set(CodingKeys.allCases.map(\.stringValue)),
            name: "contract emergency-hold retrospective"
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        holdProposalContentId = try governanceFixedBytes(
            container.decode([UInt8].self, forKey: .holdProposalContentId),
            count: 32,
            nonzero: true,
            codingPath: container.codingPath + [CodingKeys.holdProposalContentId],
            field: "hold_proposal_content_id"
        )
        holdGovernanceAttemptId = try governanceFixedBytes(
            container.decode([UInt8].self, forKey: .holdGovernanceAttemptId),
            count: 32,
            nonzero: true,
            codingPath: container.codingPath + [CodingKeys.holdGovernanceAttemptId],
            field: "hold_governance_attempt_id"
        )
        incidentDigest = try governanceFixedBytes(
            container.decode([UInt8].self, forKey: .incidentDigest),
            count: 32,
            nonzero: true,
            codingPath: container.codingPath + [CodingKeys.incidentDigest],
            field: "incident_digest"
        )
        retrospectiveFindingRoot = try governanceFixedBytes(
            container.decode([UInt8].self, forKey: .retrospectiveFindingRoot),
            count: 32,
            nonzero: true,
            codingPath: container.codingPath + [CodingKeys.retrospectiveFindingRoot],
            field: "retrospective_finding_root"
        )
    }
}

/// Closed owner-consented contract-lifecycle action inventory.
public enum ToriiGovernanceContractLifecycleActionV1: Decodable, Sendable, Equatable {
    case activate(ToriiGovernanceContractActivateActionV1)
    case deactivate(ToriiGovernanceContractDeactivateActionV1)
    case offerOwnership(ToriiGovernanceContractOfferOwnershipActionV1)
    case cancelOwnershipOffer
    case acceptParliamentOwnership
    case completeEmergencyHoldRetrospective(
        ToriiGovernanceCompleteContractEmergencyHoldRetrospectiveActionV1
    )

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case action
        case payload
    }

    public init(from decoder: Decoder) throws {
        try governanceRejectUnknownFields(
            decoder,
            allowed: Set(CodingKeys.allCases.map(\.stringValue)),
            name: "contract lifecycle action"
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        switch try container.decode(String.self, forKey: .action) {
        case "Activate":
            self = .activate(
                try container.decode(
                    ToriiGovernanceContractActivateActionV1.self,
                    forKey: .payload
                )
            )
        case "Deactivate":
            self = .deactivate(
                try container.decode(
                    ToriiGovernanceContractDeactivateActionV1.self,
                    forKey: .payload
                )
            )
        case "OfferOwnership":
            self = .offerOwnership(
                try container.decode(
                    ToriiGovernanceContractOfferOwnershipActionV1.self,
                    forKey: .payload
                )
            )
        case "CancelOwnershipOffer":
            try Self.requireNullPayload(container, tag: "CancelOwnershipOffer")
            self = .cancelOwnershipOffer
        case "AcceptParliamentOwnership":
            try Self.requireNullPayload(container, tag: "AcceptParliamentOwnership")
            self = .acceptParliamentOwnership
        case "CompleteEmergencyHoldRetrospective":
            self = .completeEmergencyHoldRetrospective(
                try container.decode(
                    ToriiGovernanceCompleteContractEmergencyHoldRetrospectiveActionV1.self,
                    forKey: .payload
                )
            )
        case let tag:
            throw DecodingError.dataCorruptedError(
                forKey: .action,
                in: container,
                debugDescription: "unsupported contract lifecycle action \(tag)"
            )
        }
    }

    private static func requireNullPayload(
        _ container: KeyedDecodingContainer<CodingKeys>,
        tag: String
    ) throws {
        guard container.contains(.payload), try container.decodeNil(forKey: .payload) else {
            throw DecodingError.dataCorruptedError(
                forKey: .payload,
                in: container,
                debugDescription: "\(tag) payload must be explicit null"
            )
        }
    }
}

/// Complete compare-and-swap proposal for one governed contract-lifecycle transition.
public struct ToriiGovernanceContractLifecycleProposalV1: Decodable, Sendable, Equatable {
    public let proposalOperator: String
    public let contractAddress: String
    public let expectedRevision: UInt64
    public let action: ToriiGovernanceContractLifecycleActionV1

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case proposalOperator = "proposal_operator"
        case contractAddress = "contract_address"
        case expectedRevision = "expected_revision"
        case action
    }

    public init(from decoder: Decoder) throws {
        try governanceRejectUnknownFields(
            decoder,
            allowed: Set(CodingKeys.allCases.map(\.stringValue)),
            name: "contract lifecycle governance proposal"
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        proposalOperator = try governanceCanonicalAccount(
            container.decode(String.self, forKey: .proposalOperator),
            codingPath: container.codingPath + [CodingKeys.proposalOperator],
            field: "proposal_operator"
        )
        contractAddress = try governanceCanonicalContractAddress(
            container.decode(String.self, forKey: .contractAddress),
            codingPath: container.codingPath + [CodingKeys.contractAddress],
            field: "contract_address"
        )
        expectedRevision = try container.decode(UInt64.self, forKey: .expectedRevision)
        guard (1...9_007_199_254_740_991).contains(expectedRevision) else {
            throw DecodingError.dataCorruptedError(
                forKey: .expectedRevision,
                in: container,
                debugDescription: "expected_revision must be a positive exact first-release JSON integer"
            )
        }
        action = try container.decode(
            ToriiGovernanceContractLifecycleActionV1.self,
            forKey: .action
        )
    }
}

/// Complete time-bounded emergency-containment proposal for one active contract.
public struct ToriiGovernanceContractEmergencyHoldProposalV1: Decodable, Sendable, Equatable {
    public let contractAddress: String
    public let expectedRevision: UInt64
    public let expectedCodeHash: Data
    public let incidentDigest: Data
    public let reason: String
    public let durationBlocks: UInt64

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case contractAddress = "contract_address"
        case expectedRevision = "expected_revision"
        case expectedCodeHash = "expected_code_hash"
        case incidentDigest = "incident_digest"
        case reason
        case durationBlocks = "duration_blocks"
    }

    public init(from decoder: Decoder) throws {
        try governanceRejectUnknownFields(
            decoder,
            allowed: Set(CodingKeys.allCases.map(\.stringValue)),
            name: "contract emergency-hold proposal"
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        contractAddress = try governanceCanonicalContractAddress(
            container.decode(String.self, forKey: .contractAddress),
            codingPath: container.codingPath + [CodingKeys.contractAddress],
            field: "contract_address"
        )
        expectedRevision = try container.decode(UInt64.self, forKey: .expectedRevision)
        guard (1...9_007_199_254_740_991).contains(expectedRevision) else {
            throw DecodingError.dataCorruptedError(
                forKey: .expectedRevision,
                in: container,
                debugDescription: "expected_revision must be a positive exact first-release JSON integer"
            )
        }
        expectedCodeHash = try governanceLowercaseHash32(
            container.decode(String.self, forKey: .expectedCodeHash),
            codingPath: container.codingPath + [CodingKeys.expectedCodeHash],
            field: "expected_code_hash"
        )
        incidentDigest = try governanceFixedBytes(
            container.decode([UInt8].self, forKey: .incidentDigest),
            count: 32,
            nonzero: true,
            codingPath: container.codingPath + [CodingKeys.incidentDigest],
            field: "incident_digest"
        )
        reason = try governanceNonBlankReason(
            container.decode(String.self, forKey: .reason),
            codingPath: container.codingPath + [CodingKeys.reason],
            field: "reason"
        )
        durationBlocks = try container.decode(UInt64.self, forKey: .durationBlocks)
        guard (1...3_600).contains(durationBlocks) else {
            throw DecodingError.dataCorruptedError(
                forKey: .durationBlocks,
                in: container,
                debugDescription: "duration_blocks must be between 1 and 3600"
            )
        }
    }
}

/// Closed exact-account global data-trigger permission transition.
public enum ToriiGovernanceGlobalDataTriggerPermissionActionV1: String, Decodable, Sendable, Equatable {
    case grant
    case revoke

    private enum CodingKeys: String, CodingKey, CaseIterable { case action, value }

    public init(from decoder: Decoder) throws {
        try governanceRejectUnknownFields(
            decoder,
            allowed: Set(CodingKeys.allCases.map(\.stringValue)),
            name: "global data-trigger permission action"
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        guard container.contains(.value), try container.decodeNil(forKey: .value) else {
            throw DecodingError.dataCorruptedError(
                forKey: .value,
                in: container,
                debugDescription: "global data-trigger permission action value must be explicit null"
            )
        }
        let raw = try container.decode(String.self, forKey: .action)
        guard let action = Self(rawValue: raw) else {
            throw DecodingError.dataCorruptedError(
                forKey: .action,
                in: container,
                debugDescription: "global data-trigger permission action must be grant or revoke"
            )
        }
        self = action
    }
}

/// Complete Parliament proposal for one exact account's global data-trigger capability.
public struct ToriiGovernanceGlobalDataTriggerPermissionProposalV1:
    Decodable, Sendable, Equatable
{
    public let authority: String
    public let action: ToriiGovernanceGlobalDataTriggerPermissionActionV1

    private enum CodingKeys: String, CodingKey, CaseIterable { case authority, action }

    public init(from decoder: Decoder) throws {
        try governanceRejectUnknownFields(
            decoder,
            allowed: Set(CodingKeys.allCases.map(\.stringValue)),
            name: "global data-trigger permission governance proposal"
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        authority = try governanceCanonicalAccount(
            container.decode(String.self, forKey: .authority),
            codingPath: container.codingPath + [CodingKeys.authority],
            field: "authority"
        )
        action = try container.decode(
            ToriiGovernanceGlobalDataTriggerPermissionActionV1.self,
            forKey: .action
        )
    }
}
