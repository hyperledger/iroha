package org.hyperledger.iroha.samples.attestationprobe

import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.text.InputType
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import java.io.File
import java.lang.ref.WeakReference
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Security
import java.security.SecureRandom
import java.security.Signature
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/** Offline public-certificate capture through registered platform JCA providers. */
class MainActivity : Activity() {
    private lateinit var status: TextView
    private lateinit var capture: Button
    private lateinit var export: Button
    private lateinit var challengeInput: EditText
    private var latestZip: File? = null
    private var pendingExport: File? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(32, 48, 32, 32)
        }
        content.addView(TextView(this).apply {
            text = "Diagnostic capture; no enrollment decision\n\nGenerates a fresh P-256 key in each available " +
                "AndroidKeyStore / HwKeyStore provider. Exports public certificates and a challenge signature, " +
                "then deletes the diagnostic keys. Certificates require independent verification.\n\n32-byte challenge (hex):"
        })
        challengeInput = EditText(this).apply {
            setText(savedInstanceState?.getString("challengeHex") ?: ProbeEncoding.hex(
                ByteArray(32).apply { SecureRandom().nextBytes(this) },
            ))
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
            setSingleLine(false)
        }
        content.addView(challengeInput)
        capture = Button(this).apply {
            text = "Capture public attestation"
            setOnClickListener { captureEvidence() }
        }
        content.addView(capture)
        export = Button(this).apply {
            text = "Export latest ZIP"
            isEnabled = false
            setOnClickListener {
                pendingExport = latestZip
                startActivityForResult(Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
                    addCategory(Intent.CATEGORY_OPENABLE)
                    type = "application/zip"
                    putExtra(Intent.EXTRA_TITLE, latestZip!!.name)
                }, EXPORT_REQUEST)
            }
        }
        content.addView(export)
        status = TextView(this).apply {
            text = "Ready. This app has no network or device-identifier permissions."
            setTextIsSelectable(true)
        }
        content.addView(status)
        setContentView(ScrollView(this).apply { addView(content) })
        pendingExport = savedInstanceState?.getString("pendingExport")?.let { File(it) }
    }

    override fun onResume() {
        super.onResume()
        foregroundActivity = WeakReference(this)
        val directory = getExternalFilesDir(null)?.let { File(it, "attestation-probe") }
        val completed = directory?.listFiles()?.filter { it.isFile && it.extension == "zip" }
            ?.maxByOrNull { it.lastModified() }
        if (completed != null) showCapture(completed)
        capture.isEnabled = !captureRunning.get()
        export.isEnabled = !captureRunning.get() && latestZip != null
        if (captureRunning.get()) status.text = "Capturing public evidence…"
    }

    override fun onPause() {
        if (foregroundActivity.get() === this) foregroundActivity.clear()
        super.onPause()
    }

    override fun onSaveInstanceState(outState: Bundle) {
        outState.putString("challengeHex", challengeInput.text.toString())
        pendingExport?.let { outState.putString("pendingExport", it.absolutePath) }
        super.onSaveInstanceState(outState)
    }

    private fun showCapture(zip: File) {
        latestZip = zip
        val report = File(zip.parentFile, "${zip.nameWithoutExtension}/report.txt")
        status.text = "Public evidence saved:\n${zip.absolutePath}\n\n${report.takeIf { it.isFile }?.readText().orEmpty()}"
        capture.isEnabled = true
        export.isEnabled = true
    }

    private fun captureEvidence() {
        val challenge = try {
            ProbeEncoding.challenge(challengeInput.text.toString().trim())
        } catch (error: IllegalArgumentException) {
            status.text = error.message
            return
        }
        if (!captureRunning.compareAndSet(false, true)) {
            status.text = "A diagnostic capture is already running."
            return
        }
        capture.isEnabled = false
        export.isEnabled = false
        status.text = "Capturing public evidence…"
        Thread {
            try {
                val external = requireNotNull(getExternalFilesDir(null)) { "App-specific export storage unavailable" }
                val directory = File(external, "attestation-probe/${System.currentTimeMillis()}-${UUID.randomUUID()}")
                check(directory.mkdirs()) { "Cannot create export directory" }
                val report = StringBuilder().apply {
                    appendLine("format=iroha-public-attestation-probe-1")
                    appendLine("captured_at_epoch_ms=${System.currentTimeMillis()}")
                    appendLine("package=$packageName")
                    appendLine("version_code=1")
                    appendLine("manufacturer=${Build.MANUFACTURER}")
                    appendLine("model=${Build.MODEL}")
                    appendLine("api=${Build.VERSION.SDK_INT}")
                    appendLine("security_patch=${Build.VERSION.SECURITY_PATCH}")
                    appendLine("challenge_hex=${ProbeEncoding.hex(challenge)}")
                    appendLine("key_algorithm=EC_secp256r1")
                    appendLine("user_authentication_required=false")
                    appendLine("verification=not_performed_capture_only")
                    appendLine("enrollment_decision=none_diagnostic_capture")
                    appendLine("registered_providers=${Security.getProviders().joinToString(",") { it.name }}")
                    appendLine("hwkeystore_shared_library_present=${packageManager.systemSharedLibraryNames?.contains("hwkeystore") == true}")
                    appendLine("missing_provider_meaning=not_registered_activation_and_provisioning_unknown")
                    try {
                        val permission = packageManager.getPermissionInfo(HUAWEI_KEYSTORE_PERMISSION, 0)
                        appendLine("huawei_keystore_permission_exists=true")
                        appendLine("huawei_keystore_permission_protection_level=${permission.protectionLevel}")
                        appendLine("huawei_keystore_permission_granted=${checkSelfPermission(HUAWEI_KEYSTORE_PERMISSION) == PackageManager.PERMISSION_GRANTED}")
                    } catch (_: PackageManager.NameNotFoundException) {
                        appendLine("huawei_keystore_permission_exists=false")
                    }
                }
                File(directory, "challenge.bin").writeBytes(challenge)
                captureProvider("AndroidKeyStore", "android-keystore", challenge, directory, report)
                captureProvider("HwKeyStore", "huawei-keystore", challenge, directory, report)
                File(directory, "report.txt").writeText(report.toString())
                val zip = File(directory.parentFile, "${directory.name}.zip")
                val partialZip = File(directory.parentFile, "${directory.name}.partial")
                ZipOutputStream(partialZip.outputStream()).use { output ->
                    directory.walkTopDown().filter { it.isFile }.sortedBy { it.path }.forEach { file ->
                        output.putNextEntry(ZipEntry(file.relativeTo(directory).invariantSeparatorsPath))
                        file.inputStream().use { it.copyTo(output) }
                        output.closeEntry()
                    }
                }
                check(partialZip.renameTo(zip)) { "Cannot finish ZIP export" }
                runOnUiThread {
                    foregroundActivity.get()?.showCapture(zip)
                }
            } catch (error: Exception) {
                runOnUiThread {
                    foregroundActivity.get()?.apply {
                        status.text = "Capture failed: ${error.javaClass.simpleName}: ${error.message}"
                        capture.isEnabled = true
                    }
                }
            } finally {
                captureRunning.set(false)
            }
        }.start()
    }

    private fun captureProvider(
        storeType: String,
        label: String,
        challenge: ByteArray,
        output: File,
        report: StringBuilder,
    ) {
        report.appendLine("\n[$label]")
        val keyStore = try {
            KeyStore.getInstance(storeType).apply { load(null) }
        } catch (error: Exception) {
            report.appendLine("status=unavailable")
            report.appendLine("reason=${error.javaClass.simpleName}: ${error.message}")
            return
        }
        report.appendLine("keystore_provider=${keyStore.provider.name}")
        val alias = "iroha-public-attestation-probe-${UUID.randomUUID()}"
        try {
            // These aliases belong only to this diagnostic package; clear interrupted probes.
            val staleAliases = java.util.Collections.list(keyStore.aliases())
                .filter { it.startsWith("iroha-public-attestation-probe-") }
            staleAliases.forEach { keyStore.deleteEntry(it) }
            val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, keyStore.provider)
            report.appendLine("generator_provider=${generator.provider.name}")
            generator.initialize(
                KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY)
                    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setAttestationChallenge(challenge.copyOf())
                    .setUserAuthenticationRequired(false)
                    .build(),
            )
            val keyPair = generator.generateKeyPair()
            val chain = requireNotNull(keyStore.getCertificateChain(alias)) { "Provider returned no chain" }
            require(chain.isNotEmpty()) { "Provider returned an empty chain" }
            require(chain.all { it is X509Certificate }) { "Provider returned a non-X.509 certificate" }
            val leafKeyMatches = chain.first().publicKey.encoded.contentEquals(keyPair.public.encoded)
            val destination = File(output, label).apply { check(mkdirs()) }
            File(destination, "public-key.spki.der").writeBytes(keyPair.public.encoded)
            File(destination, "public-key.pem").writeText(ProbeEncoding.pem("PUBLIC KEY", keyPair.public.encoded))
            File(destination, "chain.pem").writeText(chain.joinToString("") { ProbeEncoding.pem("CERTIFICATE", it.encoded) })
            chain.forEachIndexed { index, certificate ->
                File(destination, "certificate-$index.der").writeBytes(certificate.encoded)
                report.appendLine("certificate_${index}_sha256=${ProbeEncoding.sha256(certificate.encoded)}")
                report.appendLine("certificate_${index}_spki_sha256=${ProbeEncoding.sha256(certificate.publicKey.encoded)}")
            }
            report.appendLine("certificate_count=${chain.size}")
            report.appendLine("chain_order=provider_order_expected_leaf_first")
            report.appendLine("leaf_public_key_matches_generated=$leafKeyMatches")
            report.appendLine("spki_sha256=${ProbeEncoding.sha256(keyPair.public.encoded)}")
            report.appendLine("generated_key_algorithm=${keyPair.public.algorithm}")
            // Preserve the raw public chain even if this provider cannot sign through JCA.
            try {
                val signature = Signature.getInstance("SHA256withECDSA").apply {
                    initSign(keyPair.private)
                    update(challenge)
                }.sign()
                File(destination, "challenge-signature.der").writeBytes(signature)
                val signatureValid = Signature.getInstance("SHA256withECDSA").run {
                    initVerify(keyPair.public)
                    update(challenge)
                    verify(signature)
                }
                report.appendLine("challenge_signature_locally_verified=$signatureValid")
            } catch (error: Exception) {
                report.appendLine("challenge_signature_locally_verified=false")
                report.appendLine("signature_error=${error.javaClass.simpleName}: ${error.message}")
            }
            report.appendLine("status=captured_unverified")
        } catch (error: Exception) {
            report.appendLine("status=failed")
            report.appendLine("reason=${error.javaClass.simpleName}: ${error.message}")
        } finally {
            try {
                keyStore.deleteEntry(alias)
                report.appendLine("diagnostic_alias_deleted=${!keyStore.containsAlias(alias)}")
            } catch (error: Exception) {
                report.appendLine("diagnostic_alias_deleted=false")
                report.appendLine("cleanup_error=${error.javaClass.simpleName}: ${error.message}")
            }
        }
    }

    @Deprecated("Platform callback retained for this dependency-free diagnostic activity")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode != EXPORT_REQUEST) return
        val zip = pendingExport
        pendingExport = null
        if (resultCode != RESULT_OK || zip == null) return
        val uri = data?.data ?: return
        try {
            requireNotNull(contentResolver.openOutputStream(uri)).use { output ->
                zip.inputStream().use { it.copyTo(output) }
            }
            status.append("\nZIP exported.")
        } catch (error: Exception) {
            status.append("\nExport failed: ${error.javaClass.simpleName}: ${error.message}")
        }
    }

    private companion object {
        const val EXPORT_REQUEST = 1
        const val HUAWEI_KEYSTORE_PERMISSION = "com.huawei.permission.ACCESS_HW_KEYSTORE"
        val captureRunning = AtomicBoolean(false)
        var foregroundActivity = WeakReference<MainActivity>(null)
    }
}
