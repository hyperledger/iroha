package org.hyperledger.iroha.sdk.tools

import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.nio.file.StandardCopyOption
import java.security.MessageDigest
import java.security.cert.CertificateException
import java.io.IOException
import org.hyperledger.iroha.sdk.client.JsonEncoder
import org.hyperledger.iroha.sdk.crypto.keystore.KeyAttestation
import org.hyperledger.iroha.sdk.crypto.keystore.attestation.AndroidAttestationRevocationPolicyV1
import org.hyperledger.iroha.sdk.crypto.keystore.attestation.AttestationResult
import org.hyperledger.iroha.sdk.crypto.keystore.attestation.AttestationVerificationException
import org.hyperledger.iroha.sdk.crypto.keystore.attestation.AttestationVerifier
import kotlin.system.exitProcess

/** Offline attestation verification with separately supplied trust and identity commitments. */
object AndroidAttestationCommand {
    /** Verified summary; mutable evidence and certificate objects are never exposed. */
    class Result internal constructor(
        val alias: String,
        val attestationSecurityLevel: AttestationResult.SecurityLevel,
        val keymasterSecurityLevel: AttestationResult.SecurityLevel,
        val strongBoxAttestation: Boolean,
        val challengeHex: String,
        val chainLength: Int,
        val evaluationTimeMillis: Long,
        val revocationSnapshotSha256: String,
        val leafSpkiSha256: String,
    ) {
        /** One deterministic JSON object containing the verified result and trusted commitments. */
        fun toJson(): String = JsonEncoder.encode(linkedMapOf(
            "schema" to "iroha.android.attestation.verification.v1",
            "alias" to alias,
            "attestation_security_level" to attestationSecurityLevel.name,
            "keymaster_security_level" to keymasterSecurityLevel.name,
            "strongbox_attestation" to strongBoxAttestation,
            "challenge_hex" to challengeHex,
            "chain_length" to chainLength,
            "evaluation_time_ms" to evaluationTimeMillis,
            "revocation_snapshot_sha256" to revocationSnapshotSha256,
            "leaf_spki_sha256" to leafSpkiSha256,
        )) + "\n"
    }

    /** Command entry point: JSON on success, diagnostics and nonzero exit on failure. */
    @JvmStatic
    fun main(args: Array<String>) {
        if (args.contentEquals(arrayOf("--help"))) {
            print(USAGE)
            return
        }
        try {
            print(run(args).toJson())
        } catch (error: Exception) {
            System.err.println("[attestation] ${error.message ?: "verification failed"}")
            exitProcess(1)
        }
    }

    /** Verify the complete command inputs; no trust is inferred from the evidence directory. */
    @JvmStatic
    @Throws(IOException::class, CertificateException::class, AttestationVerificationException::class)
    fun run(args: Array<String>): Result {
        val arguments = Arguments.parse(args)
        val inputs = AttestationInputs()
        val snapshot = inputs.readFile(arguments.path("--revocation-snapshot"), 512 * 1024)
        val snapshotHash = digest(arguments.required("--revocation-snapshot-sha256"))
        val expectedSpki = digest(arguments.required("--expected-leaf-spki-sha256"))
        val challenge = arguments.single["--challenge-hex"]?.let(::challenge)
            ?: challenge(String(
                inputs.readFile(arguments.path("--challenge-file"), 4096), StandardCharsets.US_ASCII,
            ).trim())
        val time = arguments.required("--evaluation-time-ms").let {
            require(it.matches(Regex("[1-9][0-9]{0,18}"))) { "--evaluation-time-ms must be a positive integer" }
            it.toLongOrNull() ?: throw IllegalArgumentException("--evaluation-time-ms is outside the supported range")
        }
        val policy = AndroidAttestationRevocationPolicyV1.fromCanonicalSnapshot(snapshot, snapshotHash)
        val verifier = AttestationVerifier.builder(policy, time).requireStrongBox(arguments.strongBox)
        val roots = inputs.trustedRoots(arguments.roots, arguments.rootDirectories, arguments.rootBundles)
        roots.forEach(verifier::addTrustedRoot)
        val chain = if (arguments.single.containsKey("--chain")) {
            inputs.chain(arguments.path("--chain"), false)
        } else {
            inputs.chain(arguments.path("--bundle-dir"), true)
        }
        val attestation = KeyAttestation(arguments.required("--alias"), chain.map { it.encoded })
        val verified = verifier.build().verify(attestation, challenge)
        val spki = verified.leafCertificate.publicKey.encoded
            ?: throw AttestationVerificationException("Attestation leaf has no public-key SPKI encoding")
        val actualSpki = MessageDigest.getInstance("SHA-256").digest(spki)
        if (!MessageDigest.isEqual(expectedSpki, actualSpki)) {
            throw AttestationVerificationException(
                "Attestation leaf public key does not match the separately trusted alias key commitment",
            )
        }
        val result = Result(
            verified.alias, verified.attestationSecurityLevel, verified.keymasterSecurityLevel,
            verified.isStrongBoxAttestation, hex(verified.attestationChallenge()), verified.certificateChain().size,
            time, hex(snapshotHash), hex(actualSpki),
        )
        arguments.single["--output"]?.let { output ->
            writeResult(Paths.get(output).toAbsolutePath().normalize(), result.toJson(), inputs)
        }
        return result
    }

    private fun writeResult(path: Path, json: String, inputs: AttestationInputs) {
        require(!Files.isSymbolicLink(path)) { "--output must not be a symlink" }
        val parent = path.parent ?: throw IllegalArgumentException("--output needs a parent directory")
        Files.createDirectories(parent)
        val target = parent.toRealPath().resolve(path.fileName)
        inputs.requireDistinctOutput(target)
        val temporary = Files.createTempFile(parent, ".iroha-attestation-", ".json")
        try {
            Files.write(temporary, json.toByteArray(StandardCharsets.UTF_8))
            Files.move(temporary, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
        } finally {
            Files.deleteIfExists(temporary)
        }
    }

    private fun challenge(value: String): ByteArray {
        require(value.isNotEmpty() && value.length <= 2048 && value.length % 2 == 0 &&
            value.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) {
            "Challenge must contain 1..1024 bytes of hexadecimal"
        }
        return ByteArray(value.length / 2) { value.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    }

    private fun digest(value: String): ByteArray {
        require(value.matches(Regex("[0-9a-f]{64}")) && value.any { it != '0' }) {
            "Trusted SHA-256 commitments require a nonzero 32-byte value in lowercase hexadecimal"
        }
        return challenge(value)
    }

    private fun hex(value: ByteArray): String = value.joinToString("") { "%02x".format(it.toInt() and 255) }

    private class Arguments(
        val single: Map<String, String>,
        val roots: List<Path>,
        val rootDirectories: List<Path>,
        val rootBundles: List<Path>,
        val strongBox: Boolean,
    ) {
        fun required(flag: String): String = single[flag] ?: throw IllegalArgumentException("$flag is required")
        fun path(flag: String): Path = Paths.get(required(flag)).toAbsolutePath().normalize()

        companion object {
            fun parse(args: Array<String>): Arguments {
                require(args.size <= 256 && args.all { it.length <= 8192 }) { "Command arguments exceed size bounds" }
                val single = linkedMapOf<String, String>()
                val repeated = mapOf(
                    "--trust-root" to mutableListOf<Path>(),
                    "--trust-root-dir" to mutableListOf<Path>(),
                    "--trust-root-bundle" to mutableListOf<Path>(),
                )
                val flags = setOf("--chain", "--bundle-dir", "--alias", "--challenge-hex", "--challenge-file",
                    "--expected-leaf-spki-sha256", "--revocation-snapshot", "--revocation-snapshot-sha256",
                    "--evaluation-time-ms", "--output")
                var strongBox = false
                var index = 0
                while (index < args.size) {
                    val flag = args[index++]
                    if (flag == "--require-strongbox") {
                        require(!strongBox) { "Duplicate --require-strongbox" }
                        strongBox = true
                        continue
                    }
                    require(flag in flags || flag in repeated) { "Unknown argument: $flag; use --help" }
                    require(index < args.size && args[index].isNotEmpty() && !args[index].startsWith("--")) {
                        "$flag requires a value"
                    }
                    val value = args[index++]
                    val paths = repeated[flag]
                    if (paths == null) {
                        require(single.put(flag, value) == null) { "Duplicate $flag" }
                    } else {
                        paths.add(Paths.get(value).toAbsolutePath().normalize())
                    }
                }
                require(single.containsKey("--chain") xor single.containsKey("--bundle-dir")) {
                    "Exactly one --chain or --bundle-dir is required"
                }
                require(single.containsKey("--challenge-hex") xor single.containsKey("--challenge-file")) {
                    "Exactly one separately trusted --challenge-hex or --challenge-file is required"
                }
                val alias = single["--alias"]
                require(alias != null && alias.isNotBlank() && alias == alias.trim() && alias.length <= 255 &&
                    alias.none { Character.isISOControl(it) }) { "A canonical separately trusted --alias is required" }
                require(repeated.values.any { it.isNotEmpty() }) { "At least one separately trusted root source is required" }
                for (flag in listOf("--revocation-snapshot", "--revocation-snapshot-sha256",
                    "--expected-leaf-spki-sha256", "--evaluation-time-ms")) {
                    require(single.containsKey(flag)) { "$flag is required" }
                }
                return Arguments(single.toMap(), repeated.getValue("--trust-root").toList(),
                    repeated.getValue("--trust-root-dir").toList(), repeated.getValue("--trust-root-bundle").toList(), strongBox)
            }
        }
    }

    private const val USAGE = """Usage: iroha-attestation (--chain FILE | --bundle-dir DIR) [options]

Required independently trusted inputs:
  --trust-root FILE             PEM/DER trust anchors (repeatable).
  --trust-root-dir DIR          Recursively scan trusted certificate/ZIP sources (repeatable).
  --trust-root-bundle ZIP       Trusted root ZIP archive (repeatable).
  --alias LABEL                 Trusted keystore alias; never read from evidence metadata.
  --challenge-hex HEX           Expected nonempty challenge, or --challenge-file FILE (hex text).
  --expected-leaf-spki-sha256 HEX  Trusted alias public-key commitment, lowercase SHA-256.
  --revocation-snapshot FILE    Canonical governed V1 certificate-status snapshot.
  --revocation-snapshot-sha256 HEX  Independently trusted snapshot SHA-256.
  --evaluation-time-ms TIME     Explicit positive epoch milliseconds within snapshot freshness.

Options:
  --require-strongbox           Require StrongBox attestation security level.
  --output FILE                Atomically write the verified JSON also printed to stdout.
  --help                       Print this help.

Supply at least one root source. Bundle metadata never supplies trust or identity.
Limits: 16 chain certificates, 256 roots, 1 MiB per certificate file, 8 MiB total
input/archive bytes, 1024 directory/archive entries, directory depth 16, 1024-byte
challenge and 512 KiB revocation snapshot. Symlink inputs are rejected.
"""
}
