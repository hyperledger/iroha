import Foundation

/// Lossless JSON values returned in native transaction metadata inspections.
public enum NativeBridgeJSONValue: Codable, Sendable, Equatable {
    case string(String)
    case signedInteger(Int64)
    case unsignedInteger(UInt64)
    case decimal(Decimal)
    case bool(Bool)
    case array([NativeBridgeJSONValue])
    case object([String: NativeBridgeJSONValue])
    case null

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if container.decodeNil() {
            self = .null
        } else if let value = try? container.decode(Bool.self) {
            self = .bool(value)
        } else if let value = try? container.decode(Int64.self) {
            self = .signedInteger(value)
        } else if let value = try? container.decode(UInt64.self) {
            self = .unsignedInteger(value)
        } else if let value = try? container.decode(Decimal.self) {
            self = .decimal(value)
        } else if let value = try? container.decode(String.self) {
            self = .string(value)
        } else if let value = try? container.decode([NativeBridgeJSONValue].self) {
            self = .array(value)
        } else if let value = try? container.decode([String: NativeBridgeJSONValue].self) {
            self = .object(value)
        } else {
            throw DecodingError.dataCorruptedError(
                in: container,
                debugDescription: "Unsupported native bridge JSON value"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case let .string(value):
            try container.encode(value)
        case let .signedInteger(value):
            try container.encode(value)
        case let .unsignedInteger(value):
            try container.encode(value)
        case let .decimal(value):
            try container.encode(value)
        case let .bool(value):
            try container.encode(value)
        case let .array(value):
            try container.encode(value)
        case let .object(value):
            try container.encode(value)
        case .null:
            try container.encodeNil()
        }
    }
}

public struct DetachedContractCallInspection: Sendable, Equatable {
    public let contractAddress: String
    public let expectedCodeHash: String
    public let entrypoint: String
    public let arguments: Data?
}

public enum DetachedAssetScopeInspection: Sendable, Equatable {
    case global
    case dataspace(UInt64)
}

public struct DetachedAssetTransferInspection: Sendable, Equatable {
    public let assetDefinitionId: String
    public let assetScope: DetachedAssetScopeInspection
    public let sourceAssetId: String
    public let sourceAccountId: String
    public let destinationAccountId: String
    public let amount: String
}

public enum DetachedTransactionExecutableInspection: Sendable, Equatable {
    case contractCall(DetachedContractCallInspection)
    case assetTransfer(DetachedAssetTransferInspection)
    case atomicTransferSequence([DetachedAssetTransferInspection])
    case transferInstructionSequence([DetachedAssetTransferInspection])
    case assetTransferBatch(DetachedAssetTransferBatchInspection)
    case conditionalEscrowOpen(DetachedConditionalEscrowInspection)
}

public struct DetachedTransactionScaffoldInspection: Sendable, Equatable {
    public static let schema = "iroha.detached_transaction_scaffold.v1"

    public let payloadSigningHash: Data
    /// Hash of the canonical unsigned payload wire, independently derived by Rust.
    public let payloadHash: Data
    public let feePayment: FeePaymentIntent
    public let authority: String
    public let networkId: NetworkId
    public let creationTimeMs: UInt64
    public let timeToLiveMs: UInt64?
    public let metadata: [String: NativeBridgeJSONValue]
    public let entrypointHash: Data
    public let executable: DetachedTransactionExecutableInspection
}

public struct DetachedTransactionFinalization: Sendable, Equatable {
    public static let schema = "iroha.detached_transaction_finalization.v1"

    public let payloadSigningHash: Data
    public let transactionHash: Data
    public let entrypointHash: Data
}

public struct DetachedTransactionFinalizationResult: Sendable, Equatable {
    public let signedTransaction: Data
    public let finalization: DetachedTransactionFinalization
}

public struct CanonicalJSONBlake3Result: Sendable, Equatable {
    public let canonicalJSON: Data
    public let hash: Data
}

private struct ScaffoldDTO: Decodable {
    let schema: String
    let payloadSigningHashHex: String
    let payloadHashHex: String
    let feePayment: FeePaymentIntent
    let authority: String
    let networkId: NetworkId
    let creationTimeMs: UInt64
    let timeToLiveMs: UInt64?
    let metadata: [String: NativeBridgeJSONValue]
    let entrypointHashHex: String
    let executable: ExecutableDTO

    enum CodingKeys: String, CodingKey {
        case schema
        case payloadSigningHashHex = "payload_signing_hash_hex"
        case payloadHashHex = "payload_hash_hex"
        case feePayment = "fee_payment"
        case authority
        case networkId = "network_id"
        case creationTimeMs = "creation_time_ms"
        case timeToLiveMs = "time_to_live_ms"
        case metadata
        case entrypointHashHex = "entrypoint_hash_hex"
        case executable
    }
}

private enum ExecutableDTO: Decodable {
    case contractCall(ContractCallDTO)
    case assetTransfer(AssetTransferDTO)
    case atomicTransferSequence([AssetTransferDTO])
    case transferInstructionSequence([AssetTransferDTO])
    case assetTransferBatch(DetachedAssetTransferBatchInspection)
    case conditionalEscrowOpen(DetachedConditionalEscrowInspection)

    private enum CodingKeys: String, CodingKey {
        case kind, transfers
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        switch try container.decode(String.self, forKey: .kind) {
        case "contract_call":
            self = .contractCall(try ContractCallDTO(from: decoder))
        case "asset_transfer":
            self = .assetTransfer(try AssetTransferDTO(from: decoder))
        case "atomic_transfer_sequence":
            self = .atomicTransferSequence(try container.decode([AssetTransferDTO].self, forKey: .transfers))
        case "transfer_instruction_sequence":
            self = .transferInstructionSequence(try container.decode([AssetTransferDTO].self, forKey: .transfers))
        case "asset_transfer_batch":
            self = .assetTransferBatch(try DetachedAssetTransferBatchInspection(from: decoder))
        case "conditional_escrow_open":
            self = .conditionalEscrowOpen(try DetachedConditionalEscrowInspection(from: decoder))
        case let kind:
            throw DecodingError.dataCorruptedError(
                forKey: .kind,
                in: container,
                debugDescription: "Unsupported detached executable kind \(kind)"
            )
        }
    }
}

private struct ContractCallDTO: Decodable {
    let contractAddress: String
    let expectedCodeHash: String
    let entrypoint: String
    let argumentsB64: String?

    enum CodingKeys: String, CodingKey {
        case contractAddress = "contract_address"
        case expectedCodeHash = "expected_code_hash"
        case entrypoint
        case argumentsB64 = "arguments_b64"
    }
}

private struct AssetTransferDTO: Decodable {
    let assetDefinitionId: String
    let assetScope: AssetScopeDTO
    let sourceAssetId: String
    let sourceAccountId: String
    let destinationAccountId: String
    let amount: String

    enum CodingKeys: String, CodingKey {
        case assetDefinitionId = "asset_definition_id"
        case assetScope = "asset_scope"
        case sourceAssetId = "source_asset_id"
        case sourceAccountId = "source_account_id"
        case destinationAccountId = "destination_account_id"
        case amount
    }
}

private struct AssetScopeDTO: Decodable {
    let kind: String
    let dataspaceId: UInt64?

    enum CodingKeys: String, CodingKey {
        case kind
        case dataspaceId = "dataspace_id"
    }
}

private struct FinalizationDTO: Decodable {
    let schema: String
    let payloadSigningHashHex: String
    let transactionHashHex: String
    let entrypointHashHex: String

    enum CodingKeys: String, CodingKey {
        case schema
        case payloadSigningHashHex = "payload_signing_hash_hex"
        case transactionHashHex = "transaction_hash_hex"
        case entrypointHashHex = "entrypoint_hash_hex"
    }
}

enum DetachedTransactionBridgeJSONCodec {
    private static let decoder = JSONDecoder()

    private static func transferInspection(_ transfer: AssetTransferDTO) throws -> DetachedAssetTransferInspection {
            let scope: DetachedAssetScopeInspection
            switch (transfer.assetScope.kind, transfer.assetScope.dataspaceId) {
            case ("global", nil):
                scope = .global
            case let ("dataspace", .some(dataspaceId)):
                scope = .dataspace(dataspaceId)
            default:
                throw NativeBridgeError.invalidDetachedTransactionOutput
            }
            guard !transfer.assetDefinitionId.isEmpty,
                  !transfer.sourceAssetId.isEmpty,
                  !transfer.sourceAccountId.isEmpty,
                  !transfer.destinationAccountId.isEmpty,
                  !transfer.amount.isEmpty else {
                throw NativeBridgeError.invalidDetachedTransactionOutput
            }
            return DetachedAssetTransferInspection(
                    assetDefinitionId: transfer.assetDefinitionId,
                    assetScope: scope,
                    sourceAssetId: transfer.sourceAssetId,
                    sourceAccountId: transfer.sourceAccountId,
                    destinationAccountId: transfer.destinationAccountId,
                    amount: transfer.amount
            )
    }

    static func decodeInspection(_ data: Data) throws -> DetachedTransactionScaffoldInspection {
        try validateInspectionShape(data)
        let dto = try decoder.decode(ScaffoldDTO.self, from: data)
        guard dto.schema == DetachedTransactionScaffoldInspection.schema,
              !dto.authority.isEmpty,
              let timeToLiveMs = dto.timeToLiveMs,
              timeToLiveMs > 0 else {
            throw NativeBridgeError.invalidDetachedTransactionOutput
        }
        let executable: DetachedTransactionExecutableInspection
        switch dto.executable {
        case let .contractCall(call):
            guard !call.contractAddress.isEmpty,
                  !call.expectedCodeHash.isEmpty,
                  !call.entrypoint.isEmpty else {
                throw NativeBridgeError.invalidDetachedTransactionOutput
            }
            let arguments: Data?
            if let encoded = call.argumentsB64 {
                guard let decoded = Data(base64Encoded: encoded),
                      decoded.base64EncodedString() == encoded else {
                    throw NativeBridgeError.invalidDetachedTransactionOutput
                }
                arguments = decoded
            } else {
                arguments = nil
            }
            executable = .contractCall(
                DetachedContractCallInspection(
                    contractAddress: call.contractAddress,
                    expectedCodeHash: call.expectedCodeHash,
                    entrypoint: call.entrypoint,
                    arguments: arguments
                )
            )
        case let .assetTransfer(transfer):
            executable = .assetTransfer(try transferInspection(transfer))
        case let .atomicTransferSequence(transfers):
            guard transfers.count == 2 else { throw NativeBridgeError.invalidDetachedTransactionOutput }
            executable = .atomicTransferSequence(try transfers.map(transferInspection))
        case let .transferInstructionSequence(transfers):
            guard (2...16).contains(transfers.count) else { throw NativeBridgeError.invalidDetachedTransactionOutput }
            executable = .transferInstructionSequence(try transfers.map(transferInspection))
        case let .assetTransferBatch(batch):
            executable = .assetTransferBatch(batch)
        case let .conditionalEscrowOpen(escrow):
            executable = .conditionalEscrowOpen(escrow)
        }
        return DetachedTransactionScaffoldInspection(
            payloadSigningHash: try decodeHash(dto.payloadSigningHashHex),
            payloadHash: try decodeHash(dto.payloadHashHex),
            feePayment: dto.feePayment,
            authority: dto.authority,
            networkId: dto.networkId,
            creationTimeMs: dto.creationTimeMs,
            timeToLiveMs: timeToLiveMs,
            metadata: dto.metadata,
            entrypointHash: try decodeHash(dto.entrypointHashHex),
            executable: executable
        )
    }

    static func decodeFinalization(_ data: Data) throws -> DetachedTransactionFinalization {
        try validateFinalizationShape(data)
        let dto = try decoder.decode(FinalizationDTO.self, from: data)
        guard dto.schema == DetachedTransactionFinalization.schema else {
            throw NativeBridgeError.invalidDetachedTransactionOutput
        }
        return DetachedTransactionFinalization(
            payloadSigningHash: try decodeHash(dto.payloadSigningHashHex),
            transactionHash: try decodeHash(dto.transactionHashHex),
            entrypointHash: try decodeHash(dto.entrypointHashHex)
        )
    }

    private static func decodeHash(_ value: String) throws -> Data {
        guard value.count == 64,
              value == value.lowercased(),
              !value.hasPrefix("0x") else {
            throw NativeBridgeError.invalidDetachedTransactionOutput
        }
        var bytes = Data()
        bytes.reserveCapacity(32)
        var index = value.startIndex
        for _ in 0..<32 {
            let next = value.index(index, offsetBy: 2)
            guard let byte = UInt8(value[index..<next], radix: 16) else {
                throw NativeBridgeError.invalidDetachedTransactionOutput
            }
            bytes.append(byte)
            index = next
        }
        return bytes
    }

    private static func validateInspectionShape(_ data: Data) throws {
        let root = try strictObject(data)
        guard Set(root.keys) == [
            "schema", "payload_signing_hash_hex", "payload_hash_hex", "fee_payment", "authority", "network_id",
            "creation_time_ms", "time_to_live_ms", "metadata",
            "entrypoint_hash_hex", "executable",
        ], root["metadata"] is [String: Any],
        let executable = root["executable"] as? [String: Any],
        let kind = executable["kind"] as? String else {
            throw NativeBridgeError.invalidDetachedTransactionOutput
        }
        switch kind {
        case "contract_call":
            guard Set(executable.keys) == [
                "kind", "contract_address", "expected_code_hash", "entrypoint", "arguments_b64",
            ] else {
                throw NativeBridgeError.invalidDetachedTransactionOutput
            }
        case "asset_transfer":
            try validateTransferShape(executable)
        case "atomic_transfer_sequence", "transfer_instruction_sequence":
            guard Set(executable.keys) == ["kind", "transfers"],
                  let transfers = executable["transfers"] as? [[String: Any]],
                  (kind == "atomic_transfer_sequence" ? transfers.count == 2 : (2...16).contains(transfers.count)) else { throw NativeBridgeError.invalidDetachedTransactionOutput }
            for transfer in transfers {
                guard transfer["kind"] as? String == "asset_transfer" else { throw NativeBridgeError.invalidDetachedTransactionOutput }
                try validateTransferShape(transfer)
            }
        case "asset_transfer_batch", "conditional_escrow_open":
            // Each native monetary DTO rejects unknown fields recursively.
            break
        default:
            throw NativeBridgeError.invalidDetachedTransactionOutput
        }
    }

    private static func validateTransferShape(_ executable: [String: Any]) throws {
            guard Set(executable.keys) == [
                "kind", "asset_definition_id", "asset_scope", "source_asset_id",
                "source_account_id", "destination_account_id", "amount",
            ], let scope = executable["asset_scope"] as? [String: Any],
            let scopeKind = scope["kind"] as? String else {
                throw NativeBridgeError.invalidDetachedTransactionOutput
            }
            switch scopeKind {
            case "global" where Set(scope.keys) == ["kind"]:
                break
            case "dataspace" where Set(scope.keys) == ["kind", "dataspace_id"]:
                break
            default:
                throw NativeBridgeError.invalidDetachedTransactionOutput
            }
    }

    private static func validateFinalizationShape(_ data: Data) throws {
        let root = try strictObject(data)
        guard Set(root.keys) == [
            "schema", "payload_signing_hash_hex", "transaction_hash_hex",
            "entrypoint_hash_hex",
        ] else {
            throw NativeBridgeError.invalidDetachedTransactionOutput
        }
    }

    private static func strictObject(_ data: Data) throws -> [String: Any] {
        do {
            try StrictJSONDuplicateKeyRejector.rejectDuplicateObjectKeys(in: data)
            guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                throw NativeBridgeError.invalidDetachedTransactionOutput
            }
            return object
        } catch let error as NativeBridgeError {
            throw error
        } catch {
            throw NativeBridgeError.invalidDetachedTransactionOutput
        }
    }
}
