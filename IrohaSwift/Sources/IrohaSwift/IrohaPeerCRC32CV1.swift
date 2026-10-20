/// Shared CRC-32C implementation for peer QR frames and Petal payloads.
enum IrohaPeerCRC32CV1 {
    private static let table: [UInt32] = (0..<256).map { value in
        var crc = UInt32(value)
        for _ in 0..<8 {
            crc = (crc & 1) == 0 ? crc >> 1 : (crc >> 1) ^ 0x82F6_3B78
        }
        return crc
    }

    static func checksum<C: Collection>(_ bytes: C) -> UInt32 where C.Element == UInt8 {
        var crc: UInt32 = 0xFFFF_FFFF
        for byte in bytes {
            let tableIndex = Int((crc ^ UInt32(byte)) & 0xFF)
            crc = (crc >> 8) ^ table[tableIndex]
        }
        return crc ^ 0xFFFF_FFFF
    }
}
