// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
package org.hyperledger.iroha.sdk.offline.wallet

/** Test APK only: errno-returning Linux atomic no-replace rename, never a wallet Native ABI. */
internal object EnrollmentProbeRename {
    init { System.loadLibrary("kagemusha_enrollment_probe_files") }
    external fun publish(parent: String, stage: String, target: String): Int
}
