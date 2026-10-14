// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
package org.hyperledger.iroha.sdk.offline.wallet

import java.util.UUID
import org.hyperledger.iroha.sdk.crypto.keystore.attestation.AndroidAttestationE1PolicyV1
import org.hyperledger.iroha.sdk.json.JsonArray
import org.hyperledger.iroha.sdk.json.JsonObject

/** Closed test commands; names deliberately match the Apple driver where stages are shared. */
internal class EnrollmentProbeCommand(row: JsonObject) {
    val action = row.text("action")
    val pins: Map<String, EnrollmentProbePin>
    init {
        probeRequire(row.keys == setOf("action", "inputs"))
        val input = row["inputs"] as? JsonObject ?: throw EnrollmentProbeFailure("input")
        val expected = when (action) {
            "install", "begin", "collect-evidence", "inspect", "abandon", "release-wallet", "stop" -> emptySet()
            "permit", "accept-result" -> setOf("response")
            "authorize", "retain-request" -> setOf("signature")
            "start-enrollment", "renew-session" -> setOf("access-token", "dpop-proof")
            "open" -> setOf("result")
            "abandon-expired" -> setOf("proof")
            else -> null
        }
        if (expected == null) KagemushaMonetaryProbeManifest.validate(action, input.keys)
        else probeRequire(input.keys == expected)
        pins = input.members.mapValues { (_, value) ->
            EnrollmentProbePin(value as? JsonObject ?: throw EnrollmentProbeFailure("input")) }
    }
}

/** One actor per explicitly disposable application UID; no platform or keystore overrides. */
internal class EnrollmentProbeConfiguration(
    val files: EnrollmentProbeFiles, row: JsonObject, val run: String, val invocation: String,
    val packageName: String, independentGenesis: String,
) {
    val actor = row.text("actor")
    val role = row.text("role")
    val requiredStage = row.text("requiredStage")
    val account: ByteArray
    val requestId: ByteArray
    val catalog: Map<String, EnrollmentProbePin>
    val catalogDigest: String
    val identity: ByteArray
    companion object {
        fun uuid(text: String): String {
            probeRequire(UUID.fromString(text).toString() == text); return text
        }
        val stages = setOf("installed", "dispatch", "e5", "e6", "opened", "abandoned",
            "activated", "loaded", "sent", "received", "folded", "unloaded")
    }
    init {
        probeRequire(row.keys == setOf("version", "actor", "role", "requiredStage", "account", "catalog"))
        probeRequire(row.text("version") == "1" && role in setOf("A", "B", "C") && requiredStage in stages)
        uuid(run); uuid(invocation); uuid(actor)
        probeRequire(packageName.startsWith("org.hyperledger.iroha.kagemusha.enrollmentprobe."))
        val accountPin = EnrollmentProbePin(row["account"] as? JsonObject ?: throw EnrollmentProbeFailure("input"))
        probeRequire(accountPin.path.startsWith("catalog/"))
        account = files.pinned(accountPin, 4096); probeRequire(account.isNotEmpty())
        val entries = row["catalog"] as? JsonArray ?: throw EnrollmentProbeFailure("input")
        val rows = entries.map { EnrollmentProbePin(it as? JsonObject ?: throw EnrollmentProbeFailure("input")) }
        probeRequire(rows.size in 1..4096 && rows.all { it.path.startsWith("catalog/") } &&
            rows.map { it.path }.toSet().size == rows.size && rows.sumOf { it.size } <= 8_589_934_592L)
        catalog = rows.associateBy { it.path }
        probeRequire(catalog[accountPin.path]?.sha256 == accountPin.sha256 &&
            catalog[accountPin.path]?.size == accountPin.size)
        val names = listOf("app-manifest.bin", "envelope.bin", "wallet-runtime.bin", "verifier-pack.bin",
            "producer-inventory.bin", "signed-genesis.bin", "registration-source.bin", "app-policy.bin",
            "enrollment-policy.bin")
        probeRequire(names.all { catalog["catalog/$it"]?.size?.let { size -> size > 0 } == true })
        // Generic disposable application releases require real finalized registration originals.
        probeRequire(EnrollmentProbeFiles.isDigest(independentGenesis) &&
            catalog["catalog/signed-genesis.bin"]!!.sha256 == independentGenesis)
        val canonicalPins = catalog.toSortedMap().map { (path, pin) -> "$path:${pin.size}:${pin.sha256}" }
            .joinToString("\n").toByteArray(Charsets.UTF_8)
        catalogDigest = EnrollmentProbeFiles.digest(canonicalPins)
        requestId = java.security.MessageDigest.getInstance("SHA-256").digest(
            "kagemusha-device-enrollment:$actor:${EnrollmentProbeFiles.digest(account)}".toByteArray(Charsets.UTF_8))
        identity = probeJson("run" to run, "actor" to actor, "role" to role,
            "accountSHA256" to EnrollmentProbeFiles.digest(account), "catalogSHA256" to catalogDigest,
            "applicationNamespace" to packageName, "requestIDSHA256" to EnrollmentProbeFiles.digest(requestId))
    }
    fun verifyCatalog() {
        probeRequire(files.inventory("catalog") == catalog.keys)
        catalog.values.forEach(files::verify)
        EnrollmentProbeFiles.directory(files.file("catalog/originals"))
        EnrollmentProbeFiles.directory(files.file("catalog/registration"))
    }
    private fun original(name: String, maximum: Int) = files.pinned(catalog["catalog/$name"]!!, maximum)
    fun originals(): KagemushaWalletInstallationOriginalsV1 = KagemushaWalletInstallationOriginalsV1(
        original("app-manifest.bin", 8_388_608), original("envelope.bin", 2048),
        original("wallet-runtime.bin", 131_072), original("verifier-pack.bin", 16_842_752),
        original("producer-inventory.bin", 16_777_216), original("signed-genesis.bin", 67_108_864),
        files.file("catalog/originals").path.toByteArray(Charsets.UTF_8),
        KagemushaWalletInstallationOriginalsV1.relocateRegistrationSource(
            original("registration-source.bin", 8192), files.file("catalog/registration").path),
    )
    fun androidPolicy(): AndroidAttestationE1PolicyV1 = AndroidAttestationE1PolicyV1.fromPolicyOriginals(
        original("app-policy.bin", 65_536), original("enrollment-policy.bin", 65_536),
    ).also { probeRequire(it.packageName == packageName) }
}
