import Foundation

/// Canonical AccountId DATA. Only Native review authenticates its binding to a signed Request.
public enum KagemushaWalletAccountOriginalV1 {
    public static let maximumBytes = 4_096
    private static let schema = "iroha_data_model::account::model::AccountId"

    public static func encode(_ accountID: String) throws -> Data {
        let account = try AccountAddress.fromI105(accountID)
        let payload = try account.compactNoritoAccountControllerPayload()
        guard payload.count <= maximumBytes - NoritoHeader.encodedLength else {
            throw KagemushaWalletErrorV1.invalidInput
        }
        return noritoEncode(typeName: schema, payload: payload, flags: NoritoHeader.compactLen)
    }

    /// Render only under the application's independently selected network discriminant.
    public static func decode(_ original: Data, chainDiscriminant: UInt16) throws -> String {
        guard (NoritoHeader.encodedLength...maximumBytes).contains(original.count),
              let frame = noritoDecodeFrame(original), frame.paddingLength == 0,
              frame.header.schema == noritoSchemaHash(forTypeName: schema),
              frame.header.compression == .none, frame.header.flags == NoritoHeader.compactLen else {
            throw KagemushaWalletErrorV1.invalidInput
        }
        let account = try AccountAddress.fromCanonicalCompactAccountPayload(frame.payload)
        let literal = try account.toI105(chainDiscriminant: chainDiscriminant)
        guard try encode(literal) == original else { throw KagemushaWalletErrorV1.invalidInput }
        return literal
    }
}
