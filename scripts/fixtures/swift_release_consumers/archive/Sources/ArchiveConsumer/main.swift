import Darwin
import Foundation
import NoritoBridge

enum SmokeFailure: Error {
    case failed(String)
}

func require(_ condition: Bool, _ message: String) throws {
    guard condition else { throw SmokeFailure.failed(message) }
}

func canonicalize(_ input: [UInt8]) throws -> (canonical: [UInt8], digest: [UInt8]) {
    var canonicalPointer: UnsafeMutablePointer<UInt8>? = nil
    var canonicalLength: UInt = 0
    var digest = [UInt8](repeating: 0, count: 32)
    let status = input.withUnsafeBufferPointer { bytes in
        digest.withUnsafeMutableBufferPointer { hash in
            connect_norito_canonical_json_blake3_v1(
                bytes.baseAddress, UInt(bytes.count),
                &canonicalPointer, &canonicalLength,
                hash.baseAddress, UInt(hash.count)
            )
        }
    }
    defer {
        if let canonicalPointer { connect_norito_free(canonicalPointer) }
    }
    try require(status == 0, "Native canonicalization failed with status \(status).")
    try require(canonicalLength <= 4096, "Native canonicalization exceeded the smoke bound.")
    if canonicalLength == 0 {
        try require(input.isEmpty, "Nonempty JSON became an empty canonical value.")
        return ([], digest)
    }
    guard let canonicalPointer else { throw SmokeFailure.failed("Native canonical bytes are missing.") }
    return (Array(UnsafeBufferPointer(start: canonicalPointer, count: Int(canonicalLength))), digest)
}

func verify(message: [UInt8], publicKey: UnsafePointer<UInt8>, publicKeyLength: UInt,
            signature: UnsafePointer<UInt8>, signatureLength: UInt) throws -> Bool {
    var valid: UInt8 = 0
    let status = message.withUnsafeBufferPointer { bytes in
        connect_norito_verify_detached(
            0, publicKey, publicKeyLength,
            bytes.baseAddress, UInt(bytes.count),
            signature, signatureLength, &valid
        )
    }
    try require(status == 0 && valid <= 1, "Native signature verification failed.")
    return valid == 1
}

func runNativeSmoke() throws {
    try require(connect_norito_bridge_abi_version() == 30, "The ZIP did not expose native ABI 30.")

    // This deterministic seed is a public smoke fixture, never an operational signer.
    let seed = [UInt8](repeating: 0x71, count: 32)
    var privatePointer: UnsafeMutablePointer<UInt8>? = nil
    var privateLength: UInt = 0
    var publicPointer: UnsafeMutablePointer<UInt8>? = nil
    var publicLength: UInt = 0
    let keypairStatus = seed.withUnsafeBufferPointer { bytes in
        connect_norito_keypair_from_seed(
            0, bytes.baseAddress, UInt(bytes.count),
            &privatePointer, &privateLength, &publicPointer, &publicLength
        )
    }
    defer {
        if let privatePointer { connect_norito_free(privatePointer) }
        if let publicPointer { connect_norito_free(publicPointer) }
    }
    try require(keypairStatus == 0 && privateLength == 32 && publicLength == 32,
                "Native Ed25519 key derivation failed or returned wrong lengths.")
    guard let privateKey = privatePointer, let publicKey = publicPointer else {
        throw SmokeFailure.failed("Native Ed25519 keypair buffers are missing.")
    }

    let message = Array("authenticated-swiftpm-binary-zip".utf8)
    let changedMessage = Array("authenticated-swiftpm-binary-zip-changed".utf8)
    var signaturePointer: UnsafeMutablePointer<UInt8>? = nil
    var signatureLength: UInt = 0
    let signStatus = message.withUnsafeBufferPointer { bytes in
        connect_norito_sign_detached(
            0, privateKey, privateLength,
            bytes.baseAddress, UInt(bytes.count), &signaturePointer, &signatureLength
        )
    }
    defer {
        if let signaturePointer { connect_norito_free(signaturePointer) }
    }
    try require(signStatus == 0 && signatureLength == 64, "Native Ed25519 signing failed.")
    guard let signature = signaturePointer else { throw SmokeFailure.failed("Native signature is missing.") }
    try require(try verify(message: message, publicKey: UnsafePointer(publicKey),
                           publicKeyLength: publicLength, signature: UnsafePointer(signature),
                           signatureLength: signatureLength), "Native Ed25519 rejected its signature.")
    try require(try !verify(message: changedMessage, publicKey: UnsafePointer(publicKey),
                            publicKeyLength: publicLength, signature: UnsafePointer(signature),
                            signatureLength: signatureLength), "Native Ed25519 accepted a changed message.")

    let canonical = Array(#"{"a":1,"z":[true,null]}"#.utf8)
    let reordered = Array(#"{ "z": [true,null], "a": 1 }"#.utf8)
    let first = try canonicalize(reordered)
    let second = try canonicalize(canonical)
    try require(first.canonical == canonical && first.canonical == second.canonical
                && first.digest == second.digest, "Native canonical JSON/BLAKE3 disagreed.")
    let empty = try canonicalize([])
    let emptyDigest = empty.digest.map { String(format: "%02x", $0) }.joined()
    try require(empty.canonical.isEmpty
                && emptyDigest == "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
                "Native BLAKE3(empty) did not match the maintained known-answer vector.")

    var appPublic = [UInt8](repeating: 0, count: 32)
    var appPrivate = [UInt8](repeating: 0, count: 32)
    var walletPublic = [UInt8](repeating: 0, count: 32)
    var walletPrivate = [UInt8](repeating: 0, count: 32)
    try require(connect_norito_connect_generate_keypair(&appPublic, &appPrivate) == 0
                && connect_norito_connect_generate_keypair(&walletPublic, &walletPrivate) == 0,
                "Native Connect key generation failed.")
    var derivedPublic = [UInt8](repeating: 0, count: 32)
    try require(connect_norito_connect_public_from_private(appPrivate, &derivedPublic) == 0
                && derivedPublic == appPublic, "Native Connect public-key derivation disagreed.")
    let session = [UInt8](repeating: 0x3E, count: 32)
    var appSend = [UInt8](repeating: 0, count: 32)
    var appReceive = [UInt8](repeating: 0, count: 32)
    var walletReceive = [UInt8](repeating: 0, count: 32)
    var walletSend = [UInt8](repeating: 0, count: 32)
    try require(connect_norito_connect_derive_keys(appPrivate, walletPublic, session, &appSend, &appReceive) == 0
                && connect_norito_connect_derive_keys(walletPrivate, appPublic, session, &walletReceive, &walletSend) == 0
                && appSend == walletReceive && appReceive == walletSend && appSend != appReceive,
                "Native Connect peers did not agree on distinct directional keys.")
    let zeroPeer = [UInt8](repeating: 0, count: 32)
    try require(connect_norito_connect_derive_keys(appPrivate, zeroPeer, session, &appSend, &appReceive) != 0,
                "Native Connect accepted an all-zero peer key.")
}

do {
    try runNativeSmoke()
    print("PASS: SwiftPM ZIP Release native ABI 30, Ed25519 signing, BLAKE3 and Connect agreement")
} catch {
    FileHandle.standardError.write(Data("FAIL: SwiftPM ZIP native smoke: \(error)\n".utf8))
    exit(1)
}
