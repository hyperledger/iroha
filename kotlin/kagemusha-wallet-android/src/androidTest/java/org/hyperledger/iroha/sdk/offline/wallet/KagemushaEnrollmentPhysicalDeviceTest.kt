// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
package org.hyperledger.iroha.sdk.offline.wallet

import android.os.Build
import android.os.Process
import android.os.SystemClock
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import java.io.FileInputStream
import java.security.MessageDigest
import org.junit.AssumptionViolatedException
import org.junit.Test
import org.junit.runner.RunWith

/** Explicit disposable-app campaign; ordinary instrumentation does not opt into this lifecycle. */
@RunWith(AndroidJUnit4::class)
class KagemushaEnrollmentPhysicalDeviceTest {
    @Test fun retainedNativeEnrollmentMailbox() {
        val args = InstrumentationRegistry.getArguments()
        if (args.getString("kagemushaProbe") == null) {
            throw AssumptionViolatedException("Explicit enrollment-v1 campaign required; no device evidence collected")
        }
        var files: EnrollmentProbeFiles? = null
        var invocation: String? = null
        try {
            probeRequire(args.getString("kagemushaProbe") == "enrollment-v1")
            fun required(name: String): String = args.getString(name)?.takeIf { it.isNotEmpty() }
                ?: throw EnrollmentProbeFailure("input")
            val run = EnrollmentProbeConfiguration.uuid(required("kagemushaRun"))
            val currentInvocation = EnrollmentProbeConfiguration.uuid(required("kagemushaInvocation"))
            invocation = currentInvocation
            val context = InstrumentationRegistry.getInstrumentation().targetContext
            val testContext = InstrumentationRegistry.getInstrumentation().context
            probeRequire(context.packageName.startsWith("org.hyperledger.iroha.kagemusha.enrollmentprobe."), "namespace")
            probeRequire(Build.DEVICE == required("kagemushaDevice") && Build.MODEL == required("kagemushaModel") &&
                Build.FINGERPRINT == required("kagemushaFingerprint"), "device")
            probeRequire(Build.VERSION.SDK_INT >= 26 && !context.isDeviceProtectedStorage, "device")
            probeRequire(context.applicationInfo.splitSourceDirs.isNullOrEmpty() &&
                testContext.applicationInfo.splitSourceDirs.isNullOrEmpty(), "apk-layout")
            val targetAPK = apkDigest(context.applicationInfo.sourceDir)
            val testAPK = apkDigest(testContext.applicationInfo.sourceDir)
            probeRequire(targetAPK == required("kagemushaTargetAPK_SHA256") &&
                testAPK == required("kagemushaTestAPK_SHA256"), "candidate")
            // Resolve Android's own app-data alias before selecting the strict mailbox leaf.
            val ownedFiles = EnrollmentProbeFiles(File(context.noBackupFilesDir.canonicalFile, "kagemusha-enrollment-probe"))
            files = ownedFiles
            ownedFiles.lock().use {
                val bytes = ownedFiles.read("inbox/$currentInvocation/configuration.json", 8_388_608)
                val digest = required("kagemushaConfigurationSHA256")
                probeRequire(EnrollmentProbeFiles.isDigest(digest) && EnrollmentProbeFiles.digest(bytes) == digest, "collision")
                val config = EnrollmentProbeConfiguration(ownedFiles, probeObject(bytes), run,
                    currentInvocation, context.packageName, required("kagemushaGenesisSHA256"))
                ownedFiles.publish("identity.json", config.identity)
                ownedFiles.mkdir("public/$currentInvocation", exclusive = true)
                ownedFiles.mkdir("private/$currentInvocation", exclusive = true)
                ownedFiles.publish("private/$currentInvocation/configuration.json", bytes)
                ownedFiles.publish("public/$currentInvocation/invocation.json", probeJson(
                    "scope" to "native-enrollment-and-monetary-stages", "run" to run, "role" to config.role,
                    "actorUUID" to config.actor, "invocation" to currentInvocation,
                    "pid" to Process.myPid().toString(), "applicationNamespace" to context.packageName,
                    "keystoreNamespace" to "application-uid-${Process.myUid()}",
                    "device" to Build.DEVICE, "model" to Build.MODEL, "fingerprint" to Build.FINGERPRINT,
                    "api" to Build.VERSION.SDK_INT.toString(), "osRelease" to Build.VERSION.RELEASE,
                    "configurationSHA256" to digest, "catalogSHA256" to config.catalogDigest,
                    "targetAPKSHA256" to targetAPK, "testAPKSHA256" to testAPK,
                    "accountSHA256" to EnrollmentProbeFiles.digest(config.account),
                    "clock" to "SystemClock.elapsedRealtimeNanos", "clockUnit" to "nanoseconds",
                    "clockScope" to "this-invocation-only", "candidateAttestationClaimed" to "false"))
                val timeout = required("kagemushaTimeoutSeconds").toLongOrNull()
                    ?: throw EnrollmentProbeFailure("input")
                probeRequire(timeout in 1..1800)
                val driver = EnrollmentDeviceDriver(config, KagemushaWalletAndroidPlatformV1.create(context))
                var failures = 0
                val stages = mutableSetOf<String>()
                val started = SystemClock.elapsedRealtimeNanos()
                val deadline = EnrollmentProbeDeadline(started, timeout * 1_000_000_000L,
                    SystemClock::elapsedRealtimeNanos)
                try {
                    for (sequence in 0..9999) {
                        val name = sequence.toString().padStart(4, '0')
                        val base = "inbox/$currentInvocation/$name"
                        var commandBytes = deadline.select { ownedFiles.committedCommand(base, 131_072) }
                        while (commandBytes == null) {
                            Thread.sleep(200)
                            commandBytes = deadline.select { ownedFiles.committedCommand(base, 131_072) }
                        }
                        val command = EnrollmentProbeCommand(probeObject(commandBytes))
                        ownedFiles.publish("private/$currentInvocation/$name.json", commandBytes)
                        val before = SystemClock.elapsedRealtimeNanos()
                        driver.output("started.json", probeJson("sequence" to sequence.toString(),
                            "action" to command.action, "ticks" to before.toString(),
                            "commandSHA256" to EnrollmentProbeFiles.digest(commandBytes)), sequence)
                        // Publication may have suspended past the bound; no late Native dispatch.
                        deadline.check()
                        val outcome = try { driver.execute(command, sequence) } catch (failure: Throwable) {
                            failures++
                            val after = SystemClock.elapsedRealtimeNanos()
                            driver.output("finished.json", failureRecord(failure, sequence, command.action, before, after), sequence)
                            if (failure is InterruptedException || Thread.currentThread().isInterrupted) throw EnrollmentProbeFailure("cancelled")
                            continue
                        }
                        val after = SystemClock.elapsedRealtimeNanos()
                        enrollmentProbeStage(outcome)?.let(stages::add)
                        driver.output("finished.json", probeJson("sequence" to sequence.toString(),
                            "action" to command.action, "status" to outcome, "ticks" to after.toString(),
                            "durationNanoseconds" to (after - before).toString()), sequence)
                        if (command.action == "stop") {
                            probeRequire(apkDigest(context.applicationInfo.sourceDir) == targetAPK &&
                                apkDigest(testContext.applicationInfo.sourceDir) == testAPK, "candidate")
                            ownedFiles.publish("public/$currentInvocation/closed.json", probeJson(
                                "failedCommands" to failures.toString(), "commands" to (sequence + 1).toString(),
                                "requiredStage" to config.requiredStage, "achievedStages" to stages.sorted().joinToString(","),
                                "ticks" to after.toString(), "qualificationClaimed" to "false"))
                            probeRequire(failures == 0, "command-failures")
                            probeRequire(config.requiredStage in stages, "required-stage")
                            return
                        }
                    }
                    throw EnrollmentProbeFailure("command-limit")
                } finally {
                    // Close never abandons an enrollment or deletes its payment key. Failure stays visible.
                    driver.close()
                }
            }
        } catch (failure: Throwable) {
            // No arbitrary exception message, stack cause, session input or private path is exported.
            if (files != null && invocation != null) {
                try { files.publish("public/$invocation/harness-failed.json",
                    failureRecord(failure, -1, "harness", 0, SystemClock.elapsedRealtimeNanos())) }
                catch (_: Throwable) { /* An absent/partial record remains an unresolved attempt. */ }
            }
            throw EnrollmentProbeFailure("campaign-failed-see-retained-closed-diagnostics")
        }
    }

    /** Installed public APK only; this never walks data/custody or reads signing material. */
    private fun apkDigest(path: String): String {
        val file = File(path)
        probeRequire(file.isFile && file.canonicalFile == file, "candidate")
        val size = file.length(); val modified = file.lastModified()
        probeRequire(size in 1..2_147_483_648L, "candidate")
        val digest = MessageDigest.getInstance("SHA-256")
        var seen = 0L
        FileInputStream(file).use { input ->
            val chunk = ByteArray(65_536)
            while (true) {
                val n = input.read(chunk)
                if (n < 0) break
                probeRequire(n > 0 && seen + n <= size, "candidate")
                digest.update(chunk, 0, n); seen += n
            }
        }
        probeRequire(seen == size && file.length() == size && file.lastModified() == modified, "candidate")
        return EnrollmentProbeFiles.hex(digest.digest())
    }

    private fun failureRecord(failure: Throwable, sequence: Int, action: String, start: Long, end: Long): ByteArray {
        val fields = mutableListOf("sequence" to sequence.toString(), "action" to action,
            "status" to "failed", "ticks" to end.toString(),
            "durationNanoseconds" to if (start == 0L) "unavailable" else (end - start).toString())
        when (failure) {
            is KagemushaWalletExceptionV1 -> fields.addAll(listOf("nativeStatus" to failure.status.toString(),
                "nativeReason" to failure.reason.toString(), "platformCode" to failure.platformCode.toString()))
            is KagemushaProbeAuthenticationFailure -> fields.add("confirmationCode" to failure.code.toString())
            is EnrollmentProbeFailure -> fields.add("harnessFailure" to failure.code)
            is android.system.ErrnoException -> fields.add("errno" to failure.errno.toString())
            is InterruptedException -> fields.add("harnessFailure" to "cancelled")
            is SecurityException -> fields.add("platformFailure" to "security-exception")
            else -> fields.add("harnessFailure" to "unclassified-retained-failure")
        }
        return probeJson(*fields.toTypedArray())
    }
}
