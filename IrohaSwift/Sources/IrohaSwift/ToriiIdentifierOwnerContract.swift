import Foundation

/// Current identifier wire checks. DATA parsing does not establish authority or ledger admission.
enum ToriiIdentifierOwnerContract {
    static let backend = "hkdf-sha3-512-prf-v1"
    static func exact(_ value: String, _ field: String) throws -> String {
        guard !value.isEmpty else { throw ToriiClientError.invalidPayload("\(field) must be nonempty.") }
        guard value.trimmingCharacters(in: .whitespacesAndNewlines) == value else {
            throw ToriiClientError.invalidPayload("\(field) must not contain surrounding whitespace.")
        }
        return value
    }
    static func input(_ value: String) throws -> String {
        guard (1...512).contains(value.utf8.count) else {
            throw ToriiClientError.invalidPayload("normalized_input requires 1...512 UTF-8 bytes.")
        }
        return value
    }
    static func lowerHex(_ value: String, bytes: Int? = nil, field: String) throws -> String {
        let raw = Array(value.utf8)
        guard !raw.isEmpty, raw.count.isMultiple(of: 2),
              bytes.map({ raw.count == $0 * 2 }) ?? true,
              raw.allSatisfy({ (0x30...0x39).contains($0) || (0x61...0x66).contains($0) }) else {
            throw ToriiClientError.invalidPayload("\(field) requires exact lowercase raw hex.")
        }
        return value
    }
    static func upperHex32(_ value: String, field: String) throws -> String {
        guard value == value.uppercased() else { throw ToriiClientError.invalidPayload("\(field) requires exact uppercase raw32 hex.") }
        _ = try lowerHex(value.lowercased(), bytes: 32, field: field)
        return value
    }
    static func markedHash(_ bytes: Data) -> String {
        var hash = Blake2b.hash256(bytes)
        hash[hash.count - 1] |= 1
        return hash.map { String(format: "%02x", $0) }.joined()
    }
    static func outputHash(_ opaque: String) throws -> String {
        guard let bytes = Data(hexString: try upperHex32(opaque, field: "opaque_output")) else { throw ToriiClientError.invalidPayload("opaque_output requires raw32 bytes.") }
        return markedHash(Data("iroha.ram_lfe.output_hash.v1".utf8) + bytes)
    }
    static func programFrame(_ value: String) throws -> Data {
        guard value == value.uppercased(), !value.isEmpty, value.utf8.count <= 8192 else { throw ToriiClientError.invalidPayload("program_id_canonical requires exact uppercase native frame hex within 4096 bytes.") }
        _ = try lowerHex(value.lowercased(), field: "program_id_canonical")
        guard let bytes = Data(hexString: value) else { throw ToriiClientError.invalidPayload("Invalid program_id_canonical DATA.") }
        return bytes
    }
    static func outputCommitments(programFrame: Data, opaque: String) throws -> (output: String, opaque: String, receipt: String, associated: String) {
        let output = try outputHash(opaque)
        let outputBytes = Data(hexString: output)!
        let opaqueHash = markedHash(Data("iroha.ram_lfe.identifier.opaque_hash.v1".utf8) + programFrame + outputBytes)
        let receipt = markedHash(Data("iroha.ram_lfe.identifier.receipt_hash.v1".utf8) + programFrame + outputBytes + Data(hexString: opaqueHash)!)
        return (output, opaqueHash, receipt, markedHash(programFrame))
    }
    static func hash32(_ value: String, field: String) throws -> String {
        let hex = try lowerHex(value, bytes: 32, field: field)
        guard let bytes = Data(hexString: hex), bytes.last.map({ $0 & 1 == 1 }) == true else {
            throw ToriiClientError.invalidPayload("\(field) requires the existing Model hash marker.")
        }
        return hex
    }
    static func nonce(_ value: String) throws -> String {
        let exact = try lowerHex(value, bytes: 32, field: "input_nonce")
        guard exact.contains(where: { $0 != "0" }) else {
            throw ToriiClientError.invalidPayload("input_nonce must be private and nonzero.")
        }
        return exact
    }
    static func signature(_ value: String, field: String) throws -> String {
        let hex = try lowerHex(value, field: field)
        guard hex.utf8.count <= 2 * 3309 else {
            throw ToriiClientError.invalidPayload("\(field) exceeds the canonical signature bound.")
        }
        return hex
    }
    static func modelSignature(_ value: String, field: String) throws -> String {
        _ = try exact(value, field)
        guard value == value.uppercased(), !value.hasPrefix("0X") else {
            throw ToriiClientError.invalidPayload("\(field) requires exact uppercase Model signature hex.")
        }
        return try signature(value.lowercased(), field: field)
    }
    static func network(_ raw: String) throws -> NetworkId {
        let hex = try hash32(raw, field: "network_id")
        guard let bytes = Data(hexString: hex) else { throw NetworkIdError.invalidRawBytes }
        return try NetworkId(bytes: bytes)
    }
    static func rawNetwork(_ network: NetworkId) -> String { network.bytes.map { String(format: "%02x", $0) }.joined() }
    static func modelHash(_ raw: String) throws -> String {
        try network(raw).literal
    }
    static func rawModelHash(_ literal: String) throws -> String {
        try rawNetwork(NetworkId(literal: literal))
    }
    static func uaid(_ raw: String) throws -> String {
        guard raw.hasPrefix("uaid:") else { throw ToriiClientError.invalidPayload("UAID must be exact uaid:lowerhex32.") }
        _ = try hash32(String(raw.dropFirst(5)), field: "uaid")
        return raw
    }
    static func lease(_ opened: UInt64, _ expires: UInt64?) throws {
        guard let expires, opened > 0, expires > opened, expires - opened <= 120_000 else {
            throw ToriiClientError.invalidPayload("Original owner opening requires its unchanged bounded lease.")
        }
    }
    static func sameOpening(_ lhs: ToriiRamLfeOutputOpening, _ rhs: ToriiRamLfeOutputOpening) -> Bool {
        let a = lhs.payload, b = rhs.payload
        return a.programId == b.programId && a.inputCiphertextHash == b.inputCiphertextHash && a.outputCiphertextHash == b.outputCiphertextHash && a.parameterDigest == b.parameterDigest && a.evaluationKeyDigest == b.evaluationKeyDigest && a.openedOutputHash == b.openedOutputHash && a.openedAtMs == b.openedAtMs && a.expiresAtMs == b.expiresAtMs && lhs.signature == rhs.signature
    }
    static func json<T: Encodable>(_ value: T) throws -> Data {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(value)
    }
    /// Translate validation failures only at a Decodable boundary, retaining the source error.
    static func decodedValue<Value>(at codingPath: [CodingKey], _ validate: () throws -> Value) throws -> Value {
        do {
            return try validate()
        } catch let error as DecodingError {
            throw error
        } catch {
            let reason: String
            if case let ToriiClientError.invalidPayload(message) = error {
                reason = message
            } else {
                reason = String(describing: error)
            }
            throw DecodingError.dataCorrupted(.init(
                codingPath: codingPath, debugDescription: reason, underlyingError: error))
        }
    }
    static func decodeString<Key: CodingKey, Value>(
        from container: KeyedDecodingContainer<Key>, forKey key: Key,
        validating validate: (String) throws -> Value
    ) throws -> Value {
        let raw = try container.decode(String.self, forKey: key)
        return try decodedValue(at: container.codingPath + [key]) { try validate(raw) }
    }
    static func fields(_ decoder: Decoder, required: Set<String>, optional: Set<String> = []) throws {
        let values = try decoder.container(keyedBy: IdentifierOwnerJSONKey.self)
        let keys = Set(values.allKeys.map(\.stringValue))
        guard required.isSubset(of: keys), keys.isSubset(of: required.union(optional)) else {
            throw DecodingError.dataCorrupted(.init(
                codingPath: decoder.codingPath,
                debugDescription: "Identifier JSON requires its exact current fields."))
        }
    }
}

private struct IdentifierOwnerJSONKey: CodingKey {
    let stringValue: String
    let intValue: Int? = nil
    init?(stringValue: String) { self.stringValue = stringValue }
    init?(intValue: Int) { return nil }
}
private struct IdentifierOwnerProgram: Codable, Sendable {
    let name: String
    enum CodingKeys: String, CodingKey { case name }
    init(name: String) throws { self.name = try ToriiIdentifierOwnerContract.exact(name, "program_id.name") }
    init(from decoder: Decoder) throws {
        try ToriiIdentifierOwnerContract.fields(decoder, required: ["name"])
        let c = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(name: c.decode(String.self, forKey: .name))
    }
}
private struct IdentifierOwnerPhonePolicy: Codable, Sendable {
    let kind: String = "phone"
    let businessRule: String = "retail"
    enum CodingKeys: String, CodingKey { case kind; case businessRule = "business_rule" }
    init() {}
    init(from decoder: Decoder) throws {
        try ToriiIdentifierOwnerContract.fields(decoder, required: ["kind", "business_rule"])
        let c = try decoder.container(keyedBy: CodingKeys.self)
        guard try c.decode(String.self, forKey: .kind) == "phone", try c.decode(String.self, forKey: .businessRule) == "retail" else {
            throw ToriiClientError.invalidPayload("Original phone policy must be exactly phone#retail.")
        }
    }
}

/// Encodes/decodes the original typed Model opening; public receipt openings remain flat DTOs.
struct ToriiIdentifierOriginalOpening: Codable, Sendable {
    let opening: ToriiRamLfeOutputOpening
    init(_ opening: ToriiRamLfeOutputOpening) { self.opening = opening }
    enum CodingKeys: String, CodingKey { case payload; case signature }
    private struct Payload: Codable, Sendable {
        let programId: IdentifierOwnerProgram
        let inputCiphertextHash: String, outputCiphertextHash: String, parameterDigest: String, evaluationKeyDigest: String, openedOutputHash: String
        let openedAtMs: UInt64, expiresAtMs: UInt64
        enum CodingKeys: String, CodingKey {
            case programId = "program_id", inputCiphertextHash = "input_ciphertext_hash", outputCiphertextHash = "output_ciphertext_hash", parameterDigest = "parameter_digest", evaluationKeyDigest = "evaluation_key_digest", openedOutputHash = "opened_output_hash", openedAtMs = "opened_at_ms", expiresAtMs = "expires_at_ms"
        }
        init(_ source: ToriiRamLfeOutputOpeningPayload) throws {
            try ToriiIdentifierOwnerContract.lease(source.openedAtMs, source.expiresAtMs)
            programId = try IdentifierOwnerProgram(name: source.programId)
            inputCiphertextHash = try ToriiIdentifierOwnerContract.modelHash(source.inputCiphertextHash)
            outputCiphertextHash = try ToriiIdentifierOwnerContract.modelHash(source.outputCiphertextHash)
            parameterDigest = try ToriiIdentifierOwnerContract.modelHash(source.parameterDigest)
            evaluationKeyDigest = try ToriiIdentifierOwnerContract.modelHash(source.evaluationKeyDigest)
            openedOutputHash = try ToriiIdentifierOwnerContract.modelHash(source.openedOutputHash)
            openedAtMs = source.openedAtMs; expiresAtMs = source.expiresAtMs!
        }
        init(from decoder: Decoder) throws {
            try ToriiIdentifierOwnerContract.fields(decoder, required: ["program_id", "input_ciphertext_hash", "output_ciphertext_hash", "parameter_digest", "evaluation_key_digest", "opened_output_hash", "opened_at_ms", "expires_at_ms"])
            let c = try decoder.container(keyedBy: CodingKeys.self)
            programId = try c.decode(IdentifierOwnerProgram.self, forKey: .programId)
            inputCiphertextHash = try c.decode(String.self, forKey: .inputCiphertextHash); _ = try ToriiIdentifierOwnerContract.rawModelHash(inputCiphertextHash)
            outputCiphertextHash = try c.decode(String.self, forKey: .outputCiphertextHash); _ = try ToriiIdentifierOwnerContract.rawModelHash(outputCiphertextHash)
            parameterDigest = try c.decode(String.self, forKey: .parameterDigest); _ = try ToriiIdentifierOwnerContract.rawModelHash(parameterDigest)
            evaluationKeyDigest = try c.decode(String.self, forKey: .evaluationKeyDigest); _ = try ToriiIdentifierOwnerContract.rawModelHash(evaluationKeyDigest)
            openedOutputHash = try c.decode(String.self, forKey: .openedOutputHash); _ = try ToriiIdentifierOwnerContract.rawModelHash(openedOutputHash)
            openedAtMs = try c.decode(UInt64.self, forKey: .openedAtMs); expiresAtMs = try c.decode(UInt64.self, forKey: .expiresAtMs)
            try ToriiIdentifierOwnerContract.lease(openedAtMs, expiresAtMs)
        }
        func value() throws -> ToriiRamLfeOutputOpeningPayload {
            ToriiRamLfeOutputOpeningPayload(programId: programId.name, inputCiphertextHash: try ToriiIdentifierOwnerContract.rawModelHash(inputCiphertextHash), outputCiphertextHash: try ToriiIdentifierOwnerContract.rawModelHash(outputCiphertextHash), parameterDigest: try ToriiIdentifierOwnerContract.rawModelHash(parameterDigest), evaluationKeyDigest: try ToriiIdentifierOwnerContract.rawModelHash(evaluationKeyDigest), openedOutputHash: try ToriiIdentifierOwnerContract.rawModelHash(openedOutputHash), openedAtMs: openedAtMs, expiresAtMs: expiresAtMs)
        }
    }
    init(from decoder: Decoder) throws {
        try ToriiIdentifierOwnerContract.fields(decoder, required: ["payload", "signature"])
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let payload = try c.decode(Payload.self, forKey: .payload)
        opening = ToriiRamLfeOutputOpening(payload: try payload.value(), signature: try ToriiIdentifierOwnerContract.modelSignature(c.decode(String.self, forKey: .signature), field: "opening.signature"))
    }
    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(Payload(opening.payload), forKey: .payload)
        try c.encode(ToriiIdentifierOwnerContract.signature(opening.signature, field: "opening.signature").uppercased(), forKey: .signature)
    }
}

/// Exact original phone projection. Constructing this DATA carrier establishes no authority.
public struct ToriiPhoneRetailCanonicalityPayloadV1: Codable, Sendable {
    public let networkId: NetworkId
    public let policyId: String, programId: String
    public let inputCiphertextHash: String, outputCiphertextHash: String, openedOutputHash: String, canonicalPhoneNullifier: String
    public let uaid: String, accountId: String
    public let issuedAtMs: UInt64, expiresAtMs: UInt64
    enum CodingKeys: String, CodingKey {
        case networkId = "network_id", policyId = "policy_id", programId = "program_id", inputCiphertextHash = "input_ciphertext_hash", outputCiphertextHash = "output_ciphertext_hash", openedOutputHash = "opened_output_hash", canonicalPhoneNullifier = "canonical_phone_nullifier", uaid, accountId = "account_id", issuedAtMs = "issued_at_ms", expiresAtMs = "expires_at_ms"
    }
    public init(networkId: NetworkId, policyId: String, programId: String, inputCiphertextHash: String, outputCiphertextHash: String, openedOutputHash: String, canonicalPhoneNullifier: String, uaid: String, accountId: String, issuedAtMs: UInt64, expiresAtMs: UInt64) throws {
        guard policyId == "phone#retail", programId == "phone_retail" else { throw ToriiClientError.invalidPayload("Exact phone#retail/phone_retail original required.") }
        try ToriiIdentifierOwnerContract.lease(issuedAtMs, expiresAtMs)
        _ = try exactCanonicalToriiAccountAddress(accountId)
        self.networkId = networkId; self.policyId = policyId; self.programId = programId
        self.inputCiphertextHash = try ToriiIdentifierOwnerContract.hash32(inputCiphertextHash, field: "phone.input_ciphertext_hash")
        self.outputCiphertextHash = try ToriiIdentifierOwnerContract.hash32(outputCiphertextHash, field: "phone.output_ciphertext_hash")
        self.openedOutputHash = try ToriiIdentifierOwnerContract.hash32(openedOutputHash, field: "phone.opened_output_hash")
        self.canonicalPhoneNullifier = try ToriiIdentifierOwnerContract.hash32(canonicalPhoneNullifier, field: "phone.canonical_phone_nullifier")
        guard outputCiphertextHash == openedOutputHash, openedOutputHash == canonicalPhoneNullifier else { throw ToriiClientError.invalidPayload("Phone nullifier differs from native opaque output hash.") }
        self.uaid = try ToriiIdentifierOwnerContract.uaid(uaid); self.accountId = accountId; self.issuedAtMs = issuedAtMs; self.expiresAtMs = expiresAtMs
    }
    public init(from decoder: Decoder) throws {
        try ToriiIdentifierOwnerContract.fields(decoder, required: ["network_id", "policy_id", "program_id", "input_ciphertext_hash", "output_ciphertext_hash", "opened_output_hash", "canonical_phone_nullifier", "uaid", "account_id", "issued_at_ms", "expires_at_ms"])
        let c = try decoder.container(keyedBy: CodingKeys.self)
        _ = try c.decode(IdentifierOwnerPhonePolicy.self, forKey: .policyId)
        let uaidTuple = try c.decode([String].self, forKey: .uaid)
        guard uaidTuple.count == 1 else { throw ToriiClientError.invalidPayload("Phone UAID requires the exact one-field Model tuple.") }
        try self.init(networkId: c.decode(NetworkId.self, forKey: .networkId), policyId: "phone#retail", programId: c.decode(IdentifierOwnerProgram.self, forKey: .programId).name, inputCiphertextHash: ToriiIdentifierOwnerContract.rawModelHash(c.decode(String.self, forKey: .inputCiphertextHash)), outputCiphertextHash: ToriiIdentifierOwnerContract.rawModelHash(c.decode(String.self, forKey: .outputCiphertextHash)), openedOutputHash: ToriiIdentifierOwnerContract.rawModelHash(c.decode(String.self, forKey: .openedOutputHash)), canonicalPhoneNullifier: ToriiIdentifierOwnerContract.rawModelHash(c.decode(String.self, forKey: .canonicalPhoneNullifier)), uaid: "uaid:" + ToriiIdentifierOwnerContract.rawModelHash(uaidTuple[0]), accountId: c.decode(String.self, forKey: .accountId), issuedAtMs: c.decode(UInt64.self, forKey: .issuedAtMs), expiresAtMs: c.decode(UInt64.self, forKey: .expiresAtMs))
    }
    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(networkId, forKey: .networkId); try c.encode(IdentifierOwnerPhonePolicy(), forKey: .policyId); try c.encode(IdentifierOwnerProgram(name: programId), forKey: .programId)
        try c.encode(ToriiIdentifierOwnerContract.modelHash(inputCiphertextHash), forKey: .inputCiphertextHash); try c.encode(ToriiIdentifierOwnerContract.modelHash(outputCiphertextHash), forKey: .outputCiphertextHash)
        try c.encode(ToriiIdentifierOwnerContract.modelHash(openedOutputHash), forKey: .openedOutputHash); try c.encode(ToriiIdentifierOwnerContract.modelHash(canonicalPhoneNullifier), forKey: .canonicalPhoneNullifier)
        try c.encode([ToriiIdentifierOwnerContract.modelHash(String(uaid.dropFirst(5)))], forKey: .uaid); try c.encode(accountId, forKey: .accountId); try c.encode(issuedAtMs, forKey: .issuedAtMs); try c.encode(expiresAtMs, forKey: .expiresAtMs)
    }
    func requireOriginal(_ opening: ToriiRamLfeOutputOpening) throws {
        let p = opening.payload
        guard programId == p.programId, inputCiphertextHash == p.inputCiphertextHash, outputCiphertextHash == p.outputCiphertextHash, openedOutputHash == p.openedOutputHash, issuedAtMs == p.openedAtMs, expiresAtMs == p.expiresAtMs else { throw ToriiClientError.invalidPayload("Phone statement differs from its exact original opening.") }
    }
}

/// Original independent phone attestor signature; Core/Torii verify the governed pinned key.
public struct ToriiPhoneRetailCanonicalityAttestationV1: Codable, Sendable {
    public let payload: ToriiPhoneRetailCanonicalityPayloadV1
    public let signature: String
    enum CodingKeys: String, CodingKey { case payload, signature }
    public init(payload: ToriiPhoneRetailCanonicalityPayloadV1, signature: String) throws {
        self.payload = payload; self.signature = try ToriiIdentifierOwnerContract.signature(signature, field: "phone.signature")
    }
    public init(from decoder: Decoder) throws {
        try ToriiIdentifierOwnerContract.fields(decoder, required: ["payload", "signature"])
        let c = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(payload: c.decode(ToriiPhoneRetailCanonicalityPayloadV1.self, forKey: .payload), signature: ToriiIdentifierOwnerContract.modelSignature(c.decode(String.self, forKey: .signature), field: "phone.signature"))
    }
    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self); try c.encode(payload, forKey: .payload); try c.encode(signature.uppercased(), forKey: .signature)
    }
}

/// Current owner input request. Original opening/phone fields appear only in claim phase.
public struct ToriiIdentifierLookupRequest: Encodable, Sendable {
    public let phase: String, policyId: String, normalizedInput: String, inputNonceHex: String
    public let outputOpening: ToriiRamLfeOutputOpening?
    public let phoneRetailCanonicality: ToriiPhoneRetailCanonicalityAttestationV1?
    enum CodingKeys: String, CodingKey { case phase; case policyId = "policy_id", normalizedInput = "normalized_input", inputNonceHex = "input_nonce", outputOpening = "output_opening", phoneRetailCanonicality = "phone_retail_canonicality" }
    private init(phase: String, policyId: String, normalizedInput: String, inputNonceHex: String, outputOpening: ToriiRamLfeOutputOpening?, phoneRetailCanonicality: ToriiPhoneRetailCanonicalityAttestationV1?) throws {
        self.phase = phase; self.policyId = try ToriiIdentifierOwnerContract.exact(policyId, "policy_id"); self.normalizedInput = try ToriiIdentifierOwnerContract.input(normalizedInput); self.inputNonceHex = try ToriiIdentifierOwnerContract.nonce(inputNonceHex); self.outputOpening = outputOpening; self.phoneRetailCanonicality = phoneRetailCanonicality
    }
    public static func prepare(policyId: String, normalizedInput: String, inputNonceHex: String) throws -> Self {
        try Self(phase: "prepare", policyId: policyId, normalizedInput: normalizedInput, inputNonceHex: inputNonceHex, outputOpening: nil, phoneRetailCanonicality: nil)
    }
    public static func claim(policyId: String, normalizedInput: String, inputNonceHex: String, outputOpening: ToriiRamLfeOutputOpening, phoneRetailCanonicality: ToriiPhoneRetailCanonicalityAttestationV1? = nil) throws -> Self {
        try ToriiIdentifierOwnerContract.lease(outputOpening.payload.openedAtMs, outputOpening.payload.expiresAtMs)
        if policyId == "phone#retail" {
            guard let phoneRetailCanonicality else { throw ToriiClientError.invalidPayload("phone#retail requires the original independent signed phone statement.") }
            try phoneRetailCanonicality.payload.requireOriginal(outputOpening)
        } else if phoneRetailCanonicality != nil { throw ToriiClientError.invalidPayload("Nonphone claims must not contain phone canonicality.") }
        return try Self(phase: "claim", policyId: policyId, normalizedInput: normalizedInput, inputNonceHex: inputNonceHex, outputOpening: outputOpening, phoneRetailCanonicality: phoneRetailCanonicality)
    }
    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self); try c.encode(phase, forKey: .phase); try c.encode(policyId, forKey: .policyId); try c.encode(normalizedInput, forKey: .normalizedInput); try c.encode(inputNonceHex, forKey: .inputNonceHex)
        if let outputOpening { try c.encode(ToriiIdentifierOriginalOpening(outputOpening), forKey: .outputOpening) }
        try c.encodeIfPresent(phoneRetailCanonicality, forKey: .phoneRetailCanonicality)
    }
}

/// Preparation DATA with an independently compared selected-network audience and original opening.
public struct ToriiIdentifierPrfPrepareResponse: Decodable, Sendable {
    public let networkId: NetworkId
    public let policyId: String, accountId: String, uaid: String
    public let outputOpening: ToriiRamLfeOutputOpening
    public let phoneRetailCanonicalityPayload: ToriiPhoneRetailCanonicalityPayloadV1?
    enum CodingKeys: String, CodingKey { case networkId = "network_id", policyId = "policy_id", accountId = "account_id", uaid, outputOpening = "output_opening", phoneRetailCanonicalityPayload = "phone_retail_canonicality_payload" }
    public init(from decoder: Decoder) throws {
        try ToriiIdentifierOwnerContract.fields(decoder, required: ["network_id", "policy_id", "account_id", "uaid", "output_opening"], optional: ["phone_retail_canonicality_payload"])
        let c = try decoder.container(keyedBy: CodingKeys.self)
        networkId = try ToriiIdentifierOwnerContract.network(c.decode(String.self, forKey: .networkId)); policyId = try ToriiIdentifierOwnerContract.exact(c.decode(String.self, forKey: .policyId), "policy_id"); accountId = try c.decode(String.self, forKey: .accountId); _ = try exactCanonicalToriiAccountAddress(accountId)
        uaid = try ToriiIdentifierOwnerContract.uaid(c.decode(String.self, forKey: .uaid)); outputOpening = try c.decode(ToriiIdentifierOriginalOpening.self, forKey: .outputOpening).opening
        phoneRetailCanonicalityPayload = try c.decodeIfPresent(ToriiPhoneRetailCanonicalityPayloadV1.self, forKey: .phoneRetailCanonicalityPayload)
        if policyId == "phone#retail" {
            guard let phone = phoneRetailCanonicalityPayload, phone.networkId == networkId, phone.accountId == accountId, phone.uaid == uaid else { throw ToriiClientError.invalidPayload("Phone projection differs from the original prepare scope.") }
            try phone.requireOriginal(outputOpening)
        } else if phoneRetailCanonicalityPayload != nil { throw ToriiClientError.invalidPayload("Nonphone prepare contains a phone projection.") }
    }
}

/// Program-only public execution receipt DTO; no identifier network field is retrofitted here.
struct ToriiIdentifierExecutionReceiptDTO: Decodable, Sendable {
    let payload: ToriiIdentifierResolutionExecutionPayload
    let attestation: ToriiIdentifierReceiptAttestation
    enum CodingKeys: String, CodingKey { case payload, attestation }
    init(from decoder: Decoder) throws {
        try ToriiIdentifierOwnerContract.fields(decoder, required: ["payload", "attestation"])
        let c = try decoder.container(keyedBy: CodingKeys.self)
        payload = try c.decode(ToriiIdentifierResolutionExecutionPayload.self, forKey: .payload)
        attestation = try c.decode(ToriiIdentifierReceiptAttestation.self, forKey: .attestation)
    }
}
