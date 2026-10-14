import Foundation

/// Decodes the current explorer's registry wire ID and canonical Norito frame.
/// Monetary projections are validated while decoding the response, so a malformed
/// transfer cannot silently disappear from a history page.
enum ToriiExplorerInstructionCodec {
    static let boxSchema = "(alloc::string::String, alloc::vec::Vec<u8>)"

    static func instructionPayload(_ frame: Data, wireID: String) throws -> Data {
        let payload = try canonicalFrame(frame, schema: boxSchema)
        var reader = CanonicalNoritoReader(data: payload)
        let embeddedWireID = try string(reader.readCompactField())
        var vector = CanonicalNoritoReader(data: try reader.readCompactField())
        let inner = try vector.readField()
        guard reader.remaining() == 0, vector.remaining() == 0,
              !wireID.isEmpty, wireID == embeddedWireID,
              wireID.utf8.allSatisfy({ $0 > 0x20 && $0 < 0x7f }),
              let decoded = noritoDecodeFrame(inner),
              decoded.header.flags == NoritoHeader.compactLen else {
            throw invalid("instruction wire ID or inner frame is invalid")
        }
        var encoded = CompactNoritoWriter()
        encoded.writeField(CompactNorito.encodeString(embeddedWireID))
        encoded.writeField(CanonicalNorito.encodeBytesVec(inner))
        guard encoded.data == payload else {
            throw invalid("instruction tuple is not canonical")
        }
        return inner
    }

    static func transferDetails(box: ToriiExplorerInstructionBox,
                                authority: String,
                                kind: String) throws -> ToriiExplorerTransferDetails? {
        let schema: String
        let expectedKind: String
        switch box.wireId {
        case "iroha.transfer":
            schema = "iroha_data_model::isi::transfer::TransferBox"
            expectedKind = "Transfer"
        case "iroha.transfer_batch":
            schema = "iroha_data_model::isi::transfer::TransferAssetBatch"
            expectedKind = "Transfer"
        case "iroha.mint":
            schema = "iroha_data_model::isi::mint_burn::MintBox"
            expectedKind = "Mint"
        case "iroha.burn":
            schema = "iroha_data_model::isi::mint_burn::BurnBox"
            expectedKind = "Burn"
        default:
            guard !["Transfer", "Mint", "Burn"].contains(kind) else {
                throw invalid("instruction kind does not match its wire ID")
            }
            return nil
        }
        guard kind == expectedKind else {
            throw invalid("instruction kind does not match its wire ID")
        }
        var reader = CanonicalNoritoReader(data: try canonicalFrame(box.framedPayload, schema: schema))
        if box.wireId == "iroha.transfer_batch" {
            var mode = CanonicalNoritoReader(data: try reader.readCompactField())
            guard try mode.readUInt32LE() <= 1, mode.remaining() == 0 else {
                throw invalid("batch mode is invalid")
            }
            var entries = CanonicalNoritoReader(data: try reader.readCompactField())
            try finish(reader)
            let count = try entries.readUInt64LE()
            guard count <= UInt64(entries.remaining()) else {
                throw invalid("batch entry count is invalid")
            }
            let prefix = try AccountAddress.inspectI105NetworkPrefix(authority).chainDiscriminant
            var projected: [ToriiExplorerTransferBatchEntry] = []
            for _ in 0..<count {
                var entry = CanonicalNoritoReader(data: try entries.readCompactField())
                _ = try string(entry.readCompactField()) // receipt correlation leg_id
                let sender = try account(entry.readCompactField(), prefix: prefix)
                let receiver = try account(entry.readCompactField(), prefix: prefix)
                let definition = try assetDefinition(entry.readCompactField())
                let amount = try CanonicalNorito.decodeCompactQuantity(entry.readCompactField())
                try finish(entry)
                projected.append(.init(senderAccountId: sender, receiverAccountId: receiver,
                                       assetDefinitionId: definition, amount: amount.canonicalString))
            }
            try finish(entries)
            return .assetBatch(projected)
        }
        let variant = try reader.readUInt32LE()
        var body = CanonicalNoritoReader(data: try reader.readCompactField())
        try finish(reader)
        let assetVariant: UInt32 = box.wireId == "iroha.transfer" ? 2 : 0
        guard variant == assetVariant else {
            guard variant <= (box.wireId == "iroha.transfer" ? 3 : 1) else {
                throw invalid("instruction variant is unknown")
            }
            return nil // domain, NFT, definition, or trigger action, not an asset balance movement
        }
        let prefix = try AccountAddress.inspectI105NetworkPrefix(authority).chainDiscriminant
        let sender: String
        let receiver: String
        let definition: String
        let amount: KotodamaQuantity
        if box.wireId == "iroha.transfer" {
            let source = try asset(body.readCompactField(), prefix: prefix)
            amount = try CanonicalNorito.decodeCompactQuantity(body.readCompactField())
            receiver = try account(body.readCompactField(), prefix: prefix)
            sender = source.account
            definition = source.definition
        } else {
            amount = try CanonicalNorito.decodeCompactQuantity(body.readCompactField())
            let destination = try asset(body.readCompactField(), prefix: prefix)
            sender = box.wireId == "iroha.burn" ? destination.account : authority
            receiver = box.wireId == "iroha.mint" ? destination.account : authority
            definition = destination.definition
        }
        try finish(body)
        return .asset(.init(destinationAccountId: receiver, amount: amount.canonicalString,
                            senderAccountId: sender, assetDefinitionId: definition))
    }

    static func canonicalFrame(_ data: Data, schema: String) throws -> Data {
        guard let frame = noritoDecodeFrame(data),
              frame.header.schema == noritoSchemaHash(forTypeName: schema),
              frame.header.flags == NoritoHeader.compactLen,
              frame.paddingLength == 0,
              noritoEncode(typeName: schema, payload: frame.payload,
                           flags: NoritoHeader.compactLen) == data else {
            throw invalid("instruction frame has an invalid schema, checksum, or canonical encoding")
        }
        return frame.payload
    }

    private static func string(_ payload: Data) throws -> String {
        var reader = CanonicalNoritoReader(data: payload)
        let bytes = try reader.readCompactField()
        try finish(reader)
        guard let value = String(data: bytes, encoding: .utf8) else {
            throw invalid("instruction string is not UTF-8")
        }
        return value
    }

    private static func account(_ payload: Data, prefix: UInt16) throws -> String {
        try AccountAddress.fromCanonicalCompactAccountPayload(payload).toI105(networkPrefix: prefix)
    }

    private static func assetDefinition(_ payload: Data) throws -> String {
        var reader = CanonicalNoritoReader(data: payload)
        var bytes = Data()
        // Fixed arrays have no element count in their compact encoding.
        for _ in 0..<16 {
            let byte = try reader.readCompactField()
            guard byte.count == 1 else { throw invalid("asset definition byte is invalid") }
            bytes.append(byte)
        }
        try finish(reader)
        guard let definition = AssetDefinitionAddress.encode(uuidBytes: bytes) else {
            throw invalid("asset definition is invalid")
        }
        return definition
    }

    private static func asset(_ payload: Data, prefix: UInt16) throws -> (account: String, definition: String) {
        var reader = CanonicalNoritoReader(data: payload)
        let owner = try account(reader.readCompactField(), prefix: prefix)
        let definition = try assetDefinition(reader.readCompactField())
        var scope = CanonicalNoritoReader(data: try reader.readCompactField())
        switch try scope.readUInt32LE() {
        case 0: break
        case 1:
            var dataspace = CanonicalNoritoReader(data: try scope.readCompactField())
            _ = try dataspace.readUInt64LE()
            try finish(dataspace)
        default: throw invalid("asset balance scope is invalid")
        }
        try finish(scope)
        try finish(reader)
        return (owner, definition)
    }

    private static func finish(_ reader: CanonicalNoritoReader) throws {
        guard reader.remaining() == 0 else { throw invalid("instruction contains trailing bytes") }
    }

    private static func invalid(_ reason: String) -> ToriiClientError {
        .invalidPayload("explorer: \(reason)")
    }
}
