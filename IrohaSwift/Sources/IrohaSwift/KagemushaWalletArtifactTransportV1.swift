import Foundation

/// One immutable encoded original. Native authenticates stored and decoded identities.
public struct KagemushaWalletArtifactExtentV1: Equatable, Sendable {
    public let rawBytes: Int, rawSha256: String, storedBytes: Int, storedSha256: String
    public init(rawBytes: Int, rawSha256: String, storedBytes: Int, storedSha256: String) {
        self.rawBytes = rawBytes; self.rawSha256 = rawSha256
        self.storedBytes = storedBytes; self.storedSha256 = storedSha256
    }
}

/// Bounded delivery metadata only; parsing never grants proof or wallet admission.
public enum KagemushaWalletArtifactTransportV1 {
    public static let maxBytes = 32 * 1024 * 1024
    public static let maxRawBytes = 1024 * 1024 * 1024
    public static let maxStoredBytes = maxRawBytes + 4 * 1024 * 1024
    public static let schema = "iroha.kagemusha.wallet-artifact-original-transport.v1"

    /// Decode the sole canonical zstd transport, rejecting raw and noncanonical forms.
    public static func decode(_ original: Data) throws -> [KagemushaWalletArtifactExtentV1] {
        func invalid() -> KagemushaWalletErrorV1 { .invalidInput }
        guard (1...maxBytes).contains(original.count) else { throw invalid() }
        try preflight(original)
        guard let body = try JSONSerialization.jsonObject(with: original) as? [String: Any],
              Set(body.keys) == ["schema", "encoding", "walletOriginals"],
              body["schema"] as? String == schema, body["encoding"] as? String == "zstd",
              let rows = body["walletOriginals"] as? [[String: Any]], (1...12288).contains(rows.count)
        else { throw invalid() }
        func digest(_ row: [String: Any], _ key: String) throws -> String {
            guard let value = row[key] as? String, value.utf8.count == 64,
                  value.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }),
                  value.contains(where: { $0 != "0" }) else { throw invalid() }
            return value
        }
        func length(_ row: [String: Any], _ key: String, _ maximum: Int) throws -> Int {
            guard let number = row[key] as? NSNumber, String(cString: number.objCType) != "c",
                  let value = Int(number.stringValue), (1...maximum).contains(value) else { throw invalid() }
            return value
        }
        var canonical = "{\"schema\":\"\(schema)\",\"encoding\":\"zstd\",\"walletOriginals\":[", previous = ""
        var result: [KagemushaWalletArtifactExtentV1] = []
        for (index, row) in rows.enumerated() {
            guard Set(row.keys) == ["bytes", "sha256", "storedBytes", "storedSha256"] else { throw invalid() }
            let extent = try KagemushaWalletArtifactExtentV1(rawBytes: length(row, "bytes", maxRawBytes),
                rawSha256: digest(row, "sha256"), storedBytes: length(row, "storedBytes", maxStoredBytes),
                storedSha256: digest(row, "storedSha256"))
            guard extent.rawSha256 > previous else { throw invalid() }
            previous = extent.rawSha256
            if index > 0 { canonical += "," }
            canonical += "{\"bytes\":\(extent.rawBytes),\"sha256\":\"\(extent.rawSha256)\",\"storedBytes\":\(extent.storedBytes),\"storedSha256\":\"\(extent.storedSha256)\"}"
            result.append(extent)
        }
        canonical += "]}\n"
        guard Data(canonical.utf8) == original else { throw invalid() }
        return result
    }

    /// Bound structure allocation before Foundation creates any JSON objects.
    private static func preflight(_ original: Data) throws {
        var quoted = false, depth = 0, containers = 0, separators = 0
        for byte in original {
            // Canonical field names, schema and hex digests never need JSON escaping.
            guard byte != 92 else { throw KagemushaWalletErrorV1.invalidInput }
            if byte == 34 { quoted.toggle() }
            else if !quoted {
                switch byte {
                case 123, 91:
                    depth += 1; containers += 1
                    guard depth <= 4, containers <= 12290 else { throw KagemushaWalletErrorV1.invalidInput }
                case 125, 93:
                    depth -= 1
                    guard depth >= 0 else { throw KagemushaWalletErrorV1.invalidInput }
                case 44, 58:
                    separators += 1
                    guard separators <= 8 * 12288 + 4 else { throw KagemushaWalletErrorV1.invalidInput }
                default: break
                }
            }
        }
        guard !quoted, depth == 0 else { throw KagemushaWalletErrorV1.invalidInput }
    }

}
