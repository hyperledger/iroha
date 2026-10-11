import Darwin
import Foundation
import IrohaSwift

enum SmokeFailure: Error {
    case failed(String)
}

func require(_ condition: Bool, _ message: String) throws {
    guard condition else { throw SmokeFailure.failed(message) }
}

func runNativeSmoke() throws {
    let bridge = NoritoNativeBridge.shared
    try require(bridge.isAvailable, "The public SDK could not load the native bridge.")
    // Resolve through the application image: importing the native module here
    // would add direct references and hide an SDK export-retention regression.
    guard let process = dlopen(nil, RTLD_NOW),
          let abiSymbol = dlsym(process, "connect_norito_bridge_abi_version") else {
        throw SmokeFailure.failed("The SDK did not retain the native ABI export.")
    }
    defer { dlclose(process) }
    let abiVersion = unsafeBitCast(abiSymbol, to: (@convention(c) () -> UInt32).self)
    try require(abiVersion() == 29, "The SDK did not load native ABI 29.")

    let message = Data("downstream-swiftpm-native-consumer".utf8)
    let changedMessage = Data("downstream-swiftpm-native-consumer-changed".utf8)

    // ML-DSA-65 requires the packaged native PQ implementation for every step.
    let pqKeypair = try MlDsaKeypair.generate(suite: .mlDsa65)
    let pqSignature = try pqKeypair.sign(message: message)
    try require(pqKeypair.publicKey.count == 1_952, "ML-DSA-65 public-key length is wrong.")
    try require(pqSignature.count == 3_309, "ML-DSA-65 signature length is wrong.")
    try require(try pqKeypair.verify(message: message, signature: pqSignature),
                "Native ML-DSA-65 rejected its valid signature.")
    try require(try !pqKeypair.verify(message: changedMessage, signature: pqSignature),
                "Native ML-DSA-65 accepted a changed message.")

    // Derivation, signing, and verification use the real native secp256k1 API.
    // This constant key is a public smoke fixture, never an operational signer.
    let secpKeypair = try Secp256k1Keypair(privateKey: Data(repeating: 1, count: 32))
    let secpSignature = try secpKeypair.sign(message: message)
    try require(secpKeypair.publicKey.count == 33, "Native secp256k1 public-key length is wrong.")
    try require(secpSignature.count == 64, "Native secp256k1 signature length is wrong.")
    try require(try secpKeypair.verify(message: message, signature: secpSignature),
                "Native secp256k1 rejected its valid signature.")
    try require(try !secpKeypair.verify(message: changedMessage, signature: secpSignature),
                "Native secp256k1 accepted a changed message.")

    // Exercise ABI-29 canonicalization and native BLAKE3 through its public API.
    let canonical = Data(#"{"a":{"x":null,"y":true},"z":[3,2,1]}"#.utf8)
    let reordered = Data(#"{ "z": [3,2,1], "a": {"y":true,"x":null} }"#.utf8)
    let first = try bridge.canonicalizeJSONBlake3(reordered)
    let second = try bridge.canonicalizeJSONBlake3(canonical)
    try require(first == second, "Equivalent JSON produced different native canonical bytes or hashes.")
    try require(first.canonicalJSON == canonical, "Native JSON canonicalization returned wrong bytes.")
    try require(first.hash.count == 32 && first.hash.contains(where: { $0 != 0 }),
                "Native BLAKE3 returned an invalid digest.")

    // Round-trip a real native Connect envelope, ciphertext frame and AEAD tag.
    let sessionID = Data(repeating: 0x3E, count: 32)
    let appKeys = try ConnectCrypto.generateKeyPair()
    let walletKeys = try ConnectCrypto.generateKeyPair()
    try require(appKeys.privateKey.count == 32 && appKeys.publicKey.count == 32,
                "Native Connect key generation returned invalid lengths.")
    try require(try ConnectCrypto.publicKey(fromPrivateKey: appKeys.privateKey) == appKeys.publicKey,
                "Native Connect public-key derivation disagreed with key generation.")
    let appDirections = try ConnectCrypto.deriveDirectionKeys(
        localPrivateKey: appKeys.privateKey, peerPublicKey: walletKeys.publicKey, sessionID: sessionID)
    let walletDirections = try ConnectCrypto.deriveDirectionKeys(
        localPrivateKey: walletKeys.privateKey, peerPublicKey: appKeys.publicKey, sessionID: sessionID)
    try require(appDirections.appToWallet == walletDirections.appToWallet
                && appDirections.walletToApp == walletDirections.walletToApp
                && appDirections.appToWallet != appDirections.walletToApp
                && appDirections.appToWallet.count == 32 && appDirections.walletToApp.count == 32,
                "Native Connect peers did not agree on distinct directional keys.")
    let zeroPeerRejected: Bool
    do {
        _ = try ConnectCrypto.deriveDirectionKeys(localPrivateKey: appKeys.privateKey,
            peerPublicKey: Data(repeating: 0, count: 32), sessionID: sessionID)
        zeroPeerRejected = false
    } catch {
        zeroPeerRejected = true
    }
    try require(zeroPeerRejected, "Native Connect accepted an all-zero peer key.")
    let connectKey = walletDirections.walletToApp
    let rejection = ConnectReject(code: 403, codeID: "USER_DENIED", reason: "Downstream smoke fixture")
    let ciphertext = try ConnectEnvelopeCodec.encryptControlReject(
        sequence: 11, code: rejection.code, codeID: rejection.codeID,
        reason: rejection.reason, key: connectKey, sessionID: sessionID,
        direction: .walletToApp
    )
    let frame = try ConnectCodec.decode(ciphertext)
    try require(frame.sessionID == sessionID && frame.direction == .walletToApp,
                "Native Connect frame lost its session or direction.")
    try require(try ConnectCodec.encode(frame) == ciphertext,
                "Native Connect frame did not round-trip canonically.")
    let envelope = try ConnectEnvelope.decrypt(frame: frame, symmetricKey: connectKey)
    try require(envelope == ConnectEnvelope(sequence: 11, payload: .controlReject(rejection)),
                "Native Connect decryption changed the envelope payload.")
    let wrongKeyRejected: Bool
    do {
        _ = try ConnectEnvelope.decrypt(frame: frame, symmetricKey: Data(repeating: 0x2E, count: 32))
        wrongKeyRejected = false
    } catch {
        wrongKeyRejected = true
    }
    try require(wrongKeyRejected, "Native Connect AEAD accepted the wrong key.")
}

do {
    try runNativeSmoke()
    print("PASS: SwiftPM SDK Release ABI 29, signatures, canonical JSON, BLAKE3 and Connect agreement/AEAD")
} catch {
    fputs("FAIL: downstream SwiftPM native smoke: \(error)\n", stderr)
    exit(1)
}
