// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
package org.hyperledger.iroha.sdk.release

import android.os.Build
import android.os.Bundle
import android.os.Process
import androidx.test.platform.app.InstrumentationRegistry
import java.nio.charset.StandardCharsets
import org.hyperledger.iroha.sdk.client.JsonEncoder
import org.junit.runner.Description
import org.junit.runner.Result
import org.junit.runner.notification.Failure
import org.junit.runner.notification.RunListener

/** Retains actual JUnit callbacks, including failures and skips, in test-private storage. */
class TairaOriginalJUnitListener : RunListener() {
    private class Case(val selector: String) {
        var finished = false
        var ignored = false
        var assumptionFailed = false
        val failureTypes = mutableListOf<String>()
    }

    private lateinit var evidence: TairaQualificationEvidence
    private lateinit var startedAt: String
    private val cases = linkedMapOf<String, Case>()
    private val listenerErrors = mutableListOf<String>()

    @Synchronized override fun testRunStarted(description: Description) {
        startedAt = TairaQualificationEvidence.timestamp()
        evidence = TairaQualificationEvidence.start(TairaQualificationArguments.read())
        // Direct process facts distinguish actual ARMv7 execution from an install request.
        // Keep the exact retained run.json schema and original-file inventory unchanged.
        val processObservation = JsonEncoder.encode(mapOf(
            "schema" to "bpng.taira-android-sdk-process-observation.v1",
            "runId" to evidence.arguments.runId,
            "sdkInt" to Build.VERSION.SDK_INT,
            "supportedAbis" to Build.SUPPORTED_ABIS.toList(),
            "is64Bit" to Process.is64Bit(),
        ))
        InstrumentationRegistry.getInstrumentation().sendStatus(2, Bundle().apply {
            putString("bpngSdkProcessObservationV1", processObservation)
        })
    }

    @Synchronized override fun testStarted(description: Description) {
        val selector = selector(description) ?: return
        if (cases.containsKey(selector)) {
            listenerErrors += "duplicate-test-start"
            return
        }
        cases[selector] = Case(selector)
        evidence.testStarted(selector)
    }

    @Synchronized override fun testFailure(failure: Failure) {
        val record = cases[selector(failure.description)]
        if (record == null) listenerErrors += "failure-without-test-start"
        else record.failureTypes += failure.exception.javaClass.name
        // Never export the exception message/stack, payload, signature or private material.
    }

    @Synchronized override fun testAssumptionFailure(failure: Failure) {
        val record = cases[selector(failure.description)]
        if (record == null) listenerErrors += "assumption-without-test-start"
        else record.assumptionFailed = true
    }

    @Synchronized override fun testIgnored(description: Description) {
        val selector = selector(description) ?: return
        if (cases.containsKey(selector)) listenerErrors += "duplicate-ignored-test"
        else cases[selector] = Case(selector).apply { ignored = true; finished = true }
    }

    @Synchronized override fun testFinished(description: Description) {
        val selector = selector(description) ?: return
        val record = cases[selector]
        if (record == null || record.finished) {
            listenerErrors += "finish-without-active-test"
            return
        }
        record.finished = true
        evidence.testFinished(selector)
    }

    @Synchronized override fun testRunFinished(result: Result) {
        val finishedAt = TairaQualificationEvidence.timestamp()
        if (cases.keys.toSet() != evidence.arguments.selectedTests.toSet()) {
            listenerErrors += "actual-test-selection-mismatch"
        }
        if (cases.values.any { !it.finished }) listenerErrors += "unfinished-test"
        val failed = cases.values.count { it.failureTypes.isNotEmpty() }
        val ignored = cases.values.count { it.ignored }
        val assumptions = cases.values.count { it.assumptionFailed }
        if (result.runCount != cases.size - ignored || result.ignoreCount != ignored ||
            result.failureCount != cases.values.sumOf { it.failureTypes.size }) {
            listenerErrors += "junit-result-callback-mismatch"
        }
        val ordered = evidence.arguments.selectedTests.mapNotNull { cases[it] }
        val xml = buildString {
            append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
            append("<testsuite name=\"TairaAndroidSdkQualification\" tests=\"")
            append(cases.size).append("\" failures=\"").append(failed)
            append("\" errors=\"").append(listenerErrors.size)
            append("\" skipped=\"").append(ignored + assumptions).append("\">\n")
            for (record in ordered) {
                append("  <testcase classname=\"").append(xmlEscape(record.selector.substringBefore('/')))
                append("\" name=\"").append(xmlEscape(record.selector.substringAfter('/'))).append("\">")
                for (type in record.failureTypes) {
                    append("<failure type=\"").append(xmlEscape(type)).append("\"/>")
                }
                if (record.ignored || record.assumptionFailed) append("<skipped/>")
                if (!record.finished) append("<error type=\"incomplete-original-callbacks\"/>")
                append("</testcase>\n")
            }
            append("</testsuite>\n")
        }
        evidence.retainCasesManifest()
        evidence.write("junit.xml", xml.toByteArray(StandardCharsets.UTF_8))
        evidence.writeJson("run.json", mapOf(
            "schema" to "bpng.taira-android-sdk-original-run.v1",
            "runId" to evidence.arguments.runId,
            "kind" to evidence.arguments.kind,
            "expectedBridgeAbiVersion" to evidence.arguments.expectedBridgeAbiVersion,
            "expectedNativeSignerContractRevision" to
                evidence.arguments.expectedNativeSignerContractRevision,
            "selectedTests" to evidence.arguments.selectedTests,
            "startedAt" to startedAt,
            "finishedAt" to finishedAt,
            "testCount" to cases.size,
            "failureCount" to failed,
            "ignoredCount" to ignored,
            "assumptionFailureCount" to assumptions,
            "listenerErrors" to listenerErrors.toList(),
        ))
    }

    private fun selector(description: Description): String? {
        val className = description.className
        val methodName = description.methodName
        val selector = if (className != null && methodName != null) "$className/$methodName" else null
        if (selector == null || selector !in evidence.arguments.selectedTests) {
            listenerErrors += "unexpected-junit-description"
            return null
        }
        return selector
    }

    private fun xmlEscape(value: String): String = value.replace("&", "&amp;")
        .replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        .replace("'", "&apos;")
}
