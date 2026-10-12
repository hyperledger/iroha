import CryptoKit
import Foundation
import XCTest
@testable import IrohaSwift

final class PrivacyExact12CapabilityManifestV1Tests: XCTestCase {
    private let executionModes: [UInt32] = [0, 1, 2, 3, 4, 4, 2, 4, 5, 1, 5, 5]
    private let featureMasks: [UInt8] = [0, 6, 1, 2, 2, 2, 0, 2, 7, 2, 7, 31]
    private let networkBytes = Data(repeating: 0xd1, count: 32)

    func testManagedProjectionPreservesFieldsWithoutGrantingNativeQualification() throws {
        let fixture = makeFixture(includePendingState: true)
        let manifest = try PrivacyExact12CapabilityManifestCodecV1.decode(
            fixture.manifest,
            nativeCatalogArchive: fixture.catalog
        )

        XCTAssertEqual(manifest.version, 1)
        XCTAssertEqual(manifest.committedHeight, 3)
        XCTAssertEqual(manifest.canonicalBytes(), fixture.manifest)
        XCTAssertEqual(manifest.protocols.count, 12)
        let expectedConsensusLimits: [UInt32] = [
            1, 2, 9 * 1024 * 1024, 9_699_840, 9_699_840,
            16_711_680, 256 * 1024, 8, 8, 2_048,
        ]
        XCTAssertEqual(
            manifest.consensusPolicy.currentLimits.orderedValues,
            expectedConsensusLimits
        )
        let consensusTightening = try XCTUnwrap(
            manifest.consensusPolicy.pendingTightening
        )
        XCTAssertEqual(consensusTightening.scheduledAtHeight, 2)
        XCTAssertEqual(consensusTightening.effectiveAtHeight, 302)
        XCTAssertEqual(consensusTightening.nextLimits.retainedRootCount, 1_024)
        XCTAssertEqual(
            manifest.consensusPolicy.canonicalNorito,
            consensusPolicy(includePendingState: true)
        )

        let first = manifest.row(for: .zkAcePqAuthorizationV1)
        XCTAssertTrue(first.localCompiledTupleMatches)
        XCTAssertTrue(first.isNetworkAvailable)
        XCTAssertEqual(first.readiness, .productionQualified)
        guard let activation = first.activation else {
            return XCTFail("active row lost its complete committed activation")
        }
        XCTAssertEqual(activation.protocolId, .zkAcePqAuthorizationV1)
        XCTAssertEqual(activation.proofSystemId, .starkFriSha3_384Goldilocks)
        XCTAssertEqual(activation.engineId, .nativeGoldilocksSha3_384StarkFri)
        XCTAssertEqual(activation.parameterId, Data(repeating: 0x31, count: 32))
        XCTAssertEqual(activation.parameterDigest, Data(repeating: 0x31, count: 32))
        XCTAssertEqual(activation.verifierDigest, Data(repeating: 0x31, count: 32))
        XCTAssertEqual(
            activation.statementSchemaDigest,
            Data(repeating: 0x31, count: 32)
        )
        XCTAssertEqual(
            activation.engineManifestDigest,
            Data(repeating: 0x31, count: 32)
        )
        XCTAssertEqual(activation.protocolLimits.values, [])
        XCTAssertNil(activation.pendingProtocolLimitsTightening)
        let qualification = try XCTUnwrap(manifest.qualification)
        XCTAssertEqual(qualification.deploymentQualification.networkId.bytes, networkBytes)
        XCTAssertEqual(qualification.deploymentQualification.genesisHash, networkBytes)
        let releaseBinding = qualification.releaseManifest.protocols[0]
        XCTAssertEqual(releaseBinding.securityClaim.protocolId, .zkAcePqAuthorizationV1)
        XCTAssertEqual(releaseBinding.securityClaim.securityModel, .postQuantumQrom)
        XCTAssertEqual(releaseBinding.securityClaim.targetSecurityBits, 128)
        XCTAssertEqual(releaseBinding.securityClaim.achievedSecurityBits, 128)
        XCTAssertEqual(
            releaseBinding.securityClaim.catalogCommitment,
            exact12CatalogCommitment()
        )
        let expectedClaimDigest = try XCTUnwrap(Data(
            hexString: "810fdc49f332423016cb7dbb7383dd03ccae74bf605202e0b8de7101439878a2"
        ))
        XCTAssertEqual(
            releaseBinding.securityClaimDigest,
            expectedClaimDigest
        )
        XCTAssertEqual(
            qualification.releaseManifest.manifestDigest,
            Data(repeating: 0xe3, count: 32)
        )
        XCTAssertEqual(
            qualification.deploymentQualification.releaseManifestDigest,
            Data(repeating: 0xe3, count: 32)
        )
        XCTAssertEqual(
            qualification.deploymentQualification.qualificationDigest,
            Data(repeating: 0xe4, count: 32)
        )
        XCTAssertEqual(activation.canonicalNorito, activationForProfileZero())
        guard case let .active(proposed, activated, since) = activation.lifecycle else {
            return XCTFail("active lifecycle projection was not retained")
        }
        XCTAssertEqual([proposed, activated, since], [1, 2, 2])

        let jindo = manifest.row(for: .irohaJindoPolynomialCommitmentV1)
        XCTAssertEqual(jindo.readiness, .productionQualified)
        XCTAssertTrue(jindo.isNetworkAvailable)
        let jindoActivation = try XCTUnwrap(jindo.activation)
        XCTAssertEqual(jindoActivation.protocolLimits.values, [4])
        let jindoTightening = try XCTUnwrap(
            jindoActivation.pendingProtocolLimitsTightening
        )
        XCTAssertEqual(jindoTightening.scheduledAtHeight, 2)
        XCTAssertEqual(jindoTightening.effectiveAtHeight, 302)
        XCTAssertEqual(jindoTightening.nextLimits.values, [3])
        XCTAssertEqual(
            jindoActivation.canonicalNorito,
            activationForJindoWithPendingTightening()
        )
    }

    func testPendingTighteningAcceptsNextBlockAndRejectsInvalidSnapshotHeights() throws {
        let cases: [(UInt64, UInt64, UInt64, Bool)] = [
            (3, 4, 3, true), (3, 5, 3, true),
            (UInt64.max - 1, UInt64.max, UInt64.max - 1, true),
            (0, 4, 3, false), (3, 3, 3, false), (3, 2, 3, false),
            (4, 5, 3, false), (3, 4, 4, false),
            (UInt64.max, UInt64.max, UInt64.max, false),
        ]
        for consensus in [true, false] {
            for (scheduled, effective, committed, accepted) in cases {
                let valid = (committed, committed == UInt64.max ? UInt64.max : committed + 1)
                let fixture = makeFixture(
                    includeQualification: false,
                    committedHeight: committed,
                    includePendingState: true,
                    consensusSchedule: consensus ? (scheduled, effective) : valid,
                    protocolSchedule: consensus ? valid : (scheduled, effective)
                )
                if accepted {
                    let manifest = try PrivacyExact12CapabilityManifestCodecV1.decode(
                        fixture.manifest, nativeCatalogArchive: fixture.catalog
                    )
                    XCTAssertEqual(manifest.canonicalBytes(), fixture.manifest)
                    XCTAssertFalse(manifest.row(for: .irohaJindoPolynomialCommitmentV1).isNetworkAvailable)
                } else {
                    XCTAssertThrowsError(try PrivacyExact12CapabilityManifestCodecV1.decode(
                        fixture.manifest, nativeCatalogArchive: fixture.catalog
                    ))
                }
            }
        }
    }

    func testProposedRemainsPendingUntilExplicitActivationAtEveryCommittedHeight() throws {
        for committedHeight in [UInt64(1), UInt64(3), UInt64.max] {
            let fixture = makeFixture(
                rowZeroReadiness: enumValue(1, enumValue(2)),
                rowZeroLifecycle: enumValue(0, structure(u64(1))),
                includeQualification: false,
                committedHeight: committedHeight
            )
            let manifest = try PrivacyExact12CapabilityManifestCodecV1.decode(
                fixture.manifest, nativeCatalogArchive: fixture.catalog
            )
            let row = manifest.row(for: .zkAcePqAuthorizationV1)
            guard case let .proposed(proposed) = try XCTUnwrap(row.activation).lifecycle else {
                return XCTFail("pending lifecycle was not retained")
            }
            XCTAssertEqual(proposed, 1)
            XCTAssertEqual(row.readiness, .unavailable(.proposed))
            XCTAssertFalse(row.isNetworkAvailable)
            let forged = makeFixture(
                rowZeroLifecycle: enumValue(0, structure(u64(1))),
                includeQualification: false,
                committedHeight: committedHeight
            )
            XCTAssertThrowsError(try PrivacyExact12CapabilityManifestCodecV1.decode(
                forged.manifest, nativeCatalogArchive: forged.catalog
            ))
        }
    }

    func testSameHeightActivationRetainsQualificationAndHistoryRequirements() throws {
        let cases: [(UInt32, UInt64, UInt32)] = [(1, 1, 5), (2, 2, 3), (3, 2, 4)]
        for (tag, since, reason) in cases {
            let activated = tag == 3 ? option(u64(1)) : u64(1)
            let fixture = makeFixture(
                rowZeroReadiness: enumValue(1, enumValue(reason)),
                rowZeroLifecycle: enumValue(tag, structure(u64(1), activated, u64(since))),
                includeQualification: false
            )
            let manifest = try PrivacyExact12CapabilityManifestCodecV1.decode(
                fixture.manifest, nativeCatalogArchive: fixture.catalog
            )
            let row = manifest.row(for: .zkAcePqAuthorizationV1)
            let lifecycle = try XCTUnwrap(row.activation).lifecycle
            switch lifecycle {
            case let .active(proposed, activated, stateSince):
                XCTAssertEqual([proposed, activated, stateSince], [1, 1, 1])
                XCTAssertEqual(row.readiness, .unavailable(.missingProductionQualification))
            case let .suspended(proposed, activated, stateSince):
                XCTAssertEqual([proposed, activated, stateSince], [1, 1, 2])
                XCTAssertEqual(row.readiness, .unavailable(.suspended))
            case let .retired(proposed, activated, stateSince):
                XCTAssertEqual(proposed, 1)
                XCTAssertEqual(activated, 1)
                XCTAssertEqual(stateSince, 2)
                XCTAssertEqual(row.readiness, .unavailable(.retired))
            case .proposed:
                XCTFail("explicit activation was lost")
            }
            XCTAssertFalse(row.isNetworkAvailable)
        }
    }

    func testExplicitActivationRejectsRemovedScheduleAndInvalidHistory() throws {
        let cases: [(Data, UInt32)] = [
            (enumValue(0, structure(u64(1), u64(4))), 2),
            (enumValue(0, structure()), 2),
            (enumValue(0, structure(u64(0))), 2),
            (enumValue(0, structure(u64(4))), 2),
            (enumValue(1, structure(u64(2), u64(1), u64(2))), 5),
            (enumValue(1, structure(u64(1), u64(2), u64(1))), 5),
            (enumValue(1, structure(u64(1), u64(4), u64(4))), 5),
            (enumValue(2, structure(u64(1), u64(1), u64(1))), 3),
            (enumValue(3, structure(u64(1), option(u64(1)), u64(1))), 4),
            (enumValue(3, structure(u64(1), option(nil), u64(1))), 4),
        ]
        for (lifecycle, reason) in cases {
            let fixture = makeFixture(
                rowZeroReadiness: enumValue(1, enumValue(reason)),
                rowZeroLifecycle: lifecycle,
                includeQualification: false
            )
            XCTAssertThrowsError(try PrivacyExact12CapabilityManifestCodecV1.decode(
                fixture.manifest, nativeCatalogArchive: fixture.catalog
            ))
        }
    }

    func testActiveProtocolWithoutSingletonEvidenceIsUnavailable() throws {
        let fixture = makeFixture(includeQualification: false)
        let manifest = try PrivacyExact12CapabilityManifestCodecV1.decode(
            fixture.manifest,
            nativeCatalogArchive: fixture.catalog
        )
        XCTAssertNil(manifest.qualification)
        XCTAssertEqual(
            manifest.row(for: .zkAcePqAuthorizationV1).readiness,
            .unavailable(.missingProductionQualification)
        )
    }

    func testManagedProjectionUsesTheCanonicalArchiveBoundForOpaqueEvidence() throws {
        // This internal codec only retains evidence bytes; Rust alone validates their contents.
        for evidenceBytes in [130 * 1024, 241 * 1024] {
            let fixture = makeFixture(opaqueProofArtifacts: Data(repeating: 0, count: evidenceBytes))
            XCTAssertLessThanOrEqual(
                fixture.manifest.count,
                PrivacyExact12CapabilityManifestV1.maximumArchiveBytes
            )
            let projection = try PrivacyExact12CapabilityManifestCodecV1.decode(
                fixture.manifest,
                nativeCatalogArchive: fixture.catalog
            )
            XCTAssertEqual(projection.canonicalBytes(), fixture.manifest)
        }
    }

    func testStandaloneProjectionCannotMintAuthenticatedNetworkAdmission() throws {
        let fixture = makeFixture()
        let projection = try PrivacyExact12CapabilityManifestCodecV1.decode(
            fixture.manifest,
            nativeCatalogArchive: fixture.catalog
        )
        XCTAssertThrowsError(try PrivacyExact12CapabilityAdmissionV1.requireExact12CapabilityTupleV1(
            projection,
            protocolId: .zkAcePqAuthorizationV1
        )) { error in
            XCTAssertEqual(error as? PrivacyExact12CapabilityManifestErrorV1, .invalidAdmission)
        }
    }

    func testMismatchedSingletonEvidenceCanOnlyDeriveInvalidReadiness() throws {
        let invalid = makeFixture(
            rowZeroReadiness: enumValue(1, enumValue(6)),
            committedHeight: 4,
            qualificationActivationHeight: 3,
            qualificationConvergenceHeight: 4
        )
        let manifest = try PrivacyExact12CapabilityManifestCodecV1.decode(
            invalid.manifest,
            nativeCatalogArchive: invalid.catalog
        )
        XCTAssertEqual(
            manifest.row(for: .zkAcePqAuthorizationV1).readiness,
            .unavailable(.invalidProductionQualification)
        )

        let forged = makeFixture(
            committedHeight: 4,
            qualificationActivationHeight: 3,
            qualificationConvergenceHeight: 4
        )
        XCTAssertThrowsError(try PrivacyExact12CapabilityManifestCodecV1.decode(
            forged.manifest,
            nativeCatalogArchive: forged.catalog
        ))
    }

    func testEveryTruncationAndOneByteSuffixFailClosed() throws {
        let fixture = makeFixture()
        for end in 0..<fixture.manifest.count {
            XCTAssertThrowsError(try PrivacyExact12CapabilityManifestCodecV1.decode(
                Data(fixture.manifest.prefix(end)),
                nativeCatalogArchive: fixture.catalog
            ), "accepted truncation at byte \(end)")
        }
        for suffix in UInt8.min...UInt8.max {
            var hostile = fixture.manifest
            hostile.append(suffix)
            XCTAssertThrowsError(try PrivacyExact12CapabilityManifestCodecV1.decode(
                hostile,
                nativeCatalogArchive: fixture.catalog
            ), "accepted suffix byte \(suffix)")
        }
    }

    func testSemanticShellsWithRecomputedOuterFramingFailClosed() throws {
        let cases: [(String, Fixture)] = [
            (
                "readiness projection",
                makeFixture(rowZeroReadiness: enumValue(1, enumValue(5)))
            ),
            ("experimental readiness", makeFixture(rowZeroReadiness: enumValue(1))),
            ("consensus ceiling", makeFixture(maxActionsPerTransaction: 2)),
            ("activation tuple", makeFixture(activationDigestByte: 0x32)),
            ("security claim digest", makeFixture(corruptSecurityClaimDigest: true)),
            ("reordered rows", makeFixture(swapFirstRows: true)),
        ]
        for (label, fixture) in cases {
            XCTAssertThrowsError(try PrivacyExact12CapabilityManifestCodecV1.decode(
                fixture.manifest,
                nativeCatalogArchive: fixture.catalog
            ), "accepted hostile \(label)")
        }

        let fixture = makeFixture()
        let frame = try XCTUnwrap(noritoDecodeFrame(fixture.manifest))
        var overlong = frame.payload
        XCTAssertEqual(overlong.removeFirst(), 4)
        overlong.insert(contentsOf: [0x84, 0x00], at: overlong.startIndex)
        XCTAssertThrowsError(try PrivacyExact12CapabilityManifestCodecV1.decode(
            manifestFrame(overlong),
            nativeCatalogArchive: fixture.catalog
        ))

        var nestedSuffix = frame.payload
        nestedSuffix.append(0)
        XCTAssertThrowsError(try PrivacyExact12CapabilityManifestCodecV1.decode(
            manifestFrame(nestedSuffix),
            nativeCatalogArchive: fixture.catalog
        ))
    }

    func testOldNineFieldRowsAndExperimentalAssuranceFailClosed() throws {
        for fixture in [
            makeFixture(useRetiredNineFieldRows: true),
            makeFixture(useRetiredExperimentalAssurance: true),
        ] {
            XCTAssertThrowsError(try PrivacyExact12CapabilityManifestCodecV1.decode(
                fixture.manifest,
                nativeCatalogArchive: fixture.catalog
            ))
        }
    }

    func testCatalogSubstitutionAndDigestShellsFailClosed() throws {
        let fixture = makeFixture()
        let substituted = makeFixture(catalogDigestByte: 0x32)
        XCTAssertThrowsError(try PrivacyExact12CapabilityManifestCodecV1.decode(
            fixture.manifest,
            nativeCatalogArchive: substituted.catalog
        )) { error in
            XCTAssertEqual(
                error as? PrivacyExact12CapabilityManifestErrorV1,
                .compiledTupleMismatch(.zkAcePqAuthorizationV1)
            )
        }

        for digest in [Data(repeating: 0, count: 32), Data(repeating: 0xa5, count: 32)] {
            let shell = makeFixture(embeddedDigest: digest)
            XCTAssertThrowsError(try PrivacyExact12CapabilityManifestCodecV1.decode(
                shell.manifest,
                nativeCatalogArchive: shell.catalog
            ))
        }
    }

    func testSubmitProofConstructionBindsProtocolAndFullCompiledTuple() throws {
        let fixture = makeFixture()
        let manifest = try PrivacyExact12CapabilityManifestCodecV1.decode(
            fixture.manifest,
            nativeCatalogArchive: fixture.catalog
        )
        let row = manifest.row(for: .zkAcePqAuthorizationV1)
        let limits = manifest.consensusPolicy.currentLimits
        try PrivacyExact12CapabilityManifestCodecV1.requireSubmitProofInstruction(
            submitProofInstruction(),
            row: row,
            consensusLimits: limits,
            expectedNetworkId: try NetworkId(bytes: networkBytes)
        )

        let hostile = [
            submitProofInstruction(protocolTag: 1),
            submitProofInstruction(proofSystemTag: 1),
            submitProofInstruction(engineTag: 1),
            submitProofInstruction(parameterIdByte: 0x32),
            submitProofInstruction(statementDigestByte: 0),
            submitProofInstruction(statementTag: 1),
            submitProofInstruction(proofTag: 1),
            submitProofInstruction(statementNetworkBytes: Data(repeating: 0xd3, count: 32)),
            submitProofInstruction(wireMagic: Data(repeating: 0, count: 8)),
            submitProofInstruction(catalogCommitment: Data(repeating: 0, count: 48)),
            submitProofInstruction(retiredElevenFieldEnvelope: true),
        ]
        for instruction in hostile {
            XCTAssertThrowsError(
                try PrivacyExact12CapabilityManifestCodecV1
                    .requireSubmitProofInstruction(
                        instruction,
                        row: row,
                        consensusLimits: limits,
                        expectedNetworkId: try NetworkId(bytes: networkBytes)
                    )
            )
        }
    }

    func testSubmitProofChargesCanonicalEnvelopeWithoutItsInstructionWrapper() throws {
        let fixture = makeFixture()
        let manifest = try PrivacyExact12CapabilityManifestCodecV1.decode(
            fixture.manifest, nativeCatalogArchive: fixture.catalog
        )
        let archive = submitProofInstruction()
        let frame = try XCTUnwrap(noritoDecodeFrame(archive))
        var prefixBytes = 0
        for byte in frame.payload {
            prefixBytes += 1
            if byte & 0x80 == 0 { break }
        }
        // The synthetic projection has no valid proof; this checks framing only.
        let envelopeCharge = UInt32(archive.count - prefixBytes)
        let defaults = manifest.consensusPolicy.currentLimits
        func limits(_ actionBytes: UInt32) -> PrivacyConsensusLimitsV1 {
            PrivacyConsensusLimitsV1(
                maxActionsPerTransaction: 1, maxActionsPerBlock: 2,
                maxProofBytesPerAction: 1, maxActionBytes: actionBytes,
                maxPrivacyBytesPerTransaction: defaults.maxPrivacyBytesPerTransaction,
                maxPrivacyBytesPerBlock: defaults.maxPrivacyBytesPerBlock,
                maxStatementAndEncryptedOutputBytesPerTransaction: 1,
                maxNullifiersPerAction: 8, maxCommitmentsPerAction: 8, retainedRootCount: 2048
            )
        }
        let row = manifest.row(for: .zkAcePqAuthorizationV1)
        let network = try NetworkId(bytes: networkBytes)
        XCTAssertGreaterThan(archive.count, Int(envelopeCharge))
        try PrivacyExact12CapabilityManifestCodecV1.requireSubmitProofInstruction(
            archive, row: row, consensusLimits: limits(envelopeCharge), expectedNetworkId: network
        )
        XCTAssertThrowsError(try PrivacyExact12CapabilityManifestCodecV1.requireSubmitProofInstruction(
            archive, row: row, consensusLimits: limits(envelopeCharge - 1), expectedNetworkId: network
        ))
    }

    func testFinalEnvelopeRequiresEveryWireMarkerAndCatalogByte() throws {
        let fixture = makeFixture()
        let manifest = try PrivacyExact12CapabilityManifestCodecV1.decode(
            fixture.manifest, nativeCatalogArchive: fixture.catalog
        )
        let expected = try NetworkId(bytes: networkBytes)
        for index in 0..<48 {
            var catalog = exact12CatalogCommitment()
            catalog[index] ^= 1
            XCTAssertThrowsError(try PrivacyExact12CapabilityManifestCodecV1.requireSubmitProofInstruction(
                submitProofInstruction(catalogCommitment: catalog),
                row: manifest.row(for: .zkAcePqAuthorizationV1),
                consensusLimits: manifest.consensusPolicy.currentLimits,
                expectedNetworkId: expected
            ))
        }
        for index in 0..<8 {
            var marker = Data([0x49, 0x52, 0x48, 0x5a, 0x4b, 0x31, 0xa5, 0x5a])
            marker[index] ^= 1
            XCTAssertThrowsError(try PrivacyExact12CapabilityManifestCodecV1.requireSubmitProofInstruction(
                submitProofInstruction(wireMagic: marker),
                row: manifest.row(for: .zkAcePqAuthorizationV1),
                consensusLimits: manifest.consensusPolicy.currentLimits,
                expectedNetworkId: expected
            ))
        }
    }

    func testDeploymentProjectionBindsExactNetworkAndGenesisWithoutGrantingAuthority() throws {
        let expected = try NetworkId(bytes: networkBytes)
        let fixture = makeFixture()
        let manifest = try PrivacyExact12CapabilityManifestCodecV1.decode(
            fixture.manifest, nativeCatalogArchive: fixture.catalog
        )
        try PrivacyExact12CapabilityManifestCodecV1.requireDeploymentNetworkV1(
            manifest, expectedNetworkId: expected
        )
        // Each changed byte remains a canonical NetworkId; recomputing the
        // unsigned manifest digest cannot change the caller's expected network.
        for index in 0..<32 {
            var changed = networkBytes
            changed[index] ^= 2
            let other = try NetworkId(bytes: changed)
            let moved = makeFixture(deploymentNetworkBytes: changed, deploymentGenesisBytes: changed)
            let projection = try PrivacyExact12CapabilityManifestCodecV1.decode(
                moved.manifest, nativeCatalogArchive: moved.catalog
            )
            XCTAssertEqual(projection.qualification?.deploymentQualification.networkId, other)
            XCTAssertThrowsError(try PrivacyExact12CapabilityManifestCodecV1.requireDeploymentNetworkV1(
                projection, expectedNetworkId: expected
            ))
            XCTAssertThrowsError(try PrivacyExact12CapabilityAdmissionV1.requireExact12CapabilityTupleV1(
                projection, protocolId: .zkAcePqAuthorizationV1
            )) { error in
                XCTAssertEqual(error as? PrivacyExact12CapabilityManifestErrorV1, .invalidAdmission)
            }
            let mismatched = makeFixture(deploymentGenesisBytes: changed)
            XCTAssertThrowsError(try PrivacyExact12CapabilityManifestCodecV1.decode(
                mismatched.manifest, nativeCatalogArchive: mismatched.catalog
            ))
        }
    }

    func testDeploymentProjectionRejectsNoncanonicalNetworkAndGenesisFields() throws {
        for invalid in [Data(), Data(repeating: 0xd1, count: 31),
                        Data(repeating: 0xd1, count: 33), structure(networkBytes),
                        Data(repeating: 0, count: 32), Data(repeating: 0xd0, count: 32)] {
            for fixture in [makeFixture(deploymentNetworkBytes: invalid),
                            makeFixture(deploymentGenesisBytes: invalid)] {
                XCTAssertThrowsError(try PrivacyExact12CapabilityManifestCodecV1.decode(
                    fixture.manifest, nativeCatalogArchive: fixture.catalog
                ))
            }
        }
        let missing = makeFixture(includeQualification: false)
        let projection = try PrivacyExact12CapabilityManifestCodecV1.decode(
            missing.manifest, nativeCatalogArchive: missing.catalog
        )
        XCTAssertThrowsError(try PrivacyExact12CapabilityManifestCodecV1.requireDeploymentNetworkV1(
            projection, expectedNetworkId: NetworkId(bytes: networkBytes)
        ))
    }

    func testAllTwelveStatementContextsRequireExactExpectedNetwork() throws {
        let expected = try NetworkId(bytes: networkBytes)
        for protocolId in PrivacyProtocolIdV1.allCases {
            try PrivacyExact12CapabilityManifestCodecV1.requireStatementNetworkV1(
                syntheticStatement(tag: protocolId.noritoDiscriminant, network: networkBytes),
                protocolId: protocolId, expectedNetworkId: expected
            )
            for index in 0..<32 {
                var changed = networkBytes
                changed[index] ^= 2
                XCTAssertThrowsError(try PrivacyExact12CapabilityManifestCodecV1.requireStatementNetworkV1(
                    syntheticStatement(tag: protocolId.noritoDiscriminant, network: changed),
                    protocolId: protocolId, expectedNetworkId: expected
                ))
            }
            for invalid in [Data(), Data(repeating: 0xd1, count: 31),
                            Data(repeating: 0xd1, count: 33), structure(networkBytes),
                            Data(repeating: 0xd0, count: 32)] {
                XCTAssertThrowsError(try PrivacyExact12CapabilityManifestCodecV1.requireStatementNetworkV1(
                    syntheticStatement(tag: protocolId.noritoDiscriminant, network: invalid),
                    protocolId: protocolId, expectedNetworkId: expected
                ))
            }
            for malformed in [
                enumValue(protocolId.noritoDiscriminant, Data([1])),
                enumValue(protocolId.noritoDiscriminant, structure(structure(networkBytes))),
                syntheticStatement(tag: protocolId.noritoDiscriminant, network: networkBytes,
                                   contextSuffix: Data([0])),
                syntheticStatement(tag: (protocolId.noritoDiscriminant + 1) % 12, network: networkBytes),
            ] {
                XCTAssertThrowsError(try PrivacyExact12CapabilityManifestCodecV1.requireStatementNetworkV1(
                    malformed, protocolId: protocolId, expectedNetworkId: expected
                ))
            }
        }
    }

    func testGenericInstructionConstructionCannotBypassPrivacyAdmission() throws {
        let frame = noritoEncode(
            typeName: "iroha_data_model::isi::privacy::SubmitPrivacyProofV1",
            payload: Data(),
            flags: NoritoHeader.compactLen,
            payloadAlignment: 16
        )
        XCTAssertThrowsError(try TransactionInstructionFrame(
            wireName: PrivacyExact12FixtureCodecV1.submitProofWireId,
            framedPayload: frame
        )) { error in
            XCTAssertEqual(
                error as? ExecutableBatchInputError,
                .privacyExact12CapabilityAdmissionRequired
            )
        }

        let ordinary = try TransactionInstructionFrame(
            wireName: "iroha.test.non_privacy.v1",
            framedPayload: frame
        )
        let ordinaryBytes = try ordinary.compactInstructionBoxPayload()
        XCTAssertFalse(ordinaryBytes.isEmpty)
        XCTAssertEqual(
            try ordinary.compactInstructionBoxPayload(expectedNetworkId: NetworkId(bytes: networkBytes)),
            ordinaryBytes
        )
    }

    func testCapabilityRequestBypassesCachesAndPreservesExactCanonicalAuthentication() throws {
        let network = try NetworkId(bytes: networkBytes)
        let privateKey = Data(repeating: 0x11, count: 32)
        let account = try Keypair(privateKeyBytes: privateKey)
            .accountId(networkPrefix: AccountId.defaultNetworkPrefix)
        let auth = ToriiCanonicalRequestAuth(
            accountId: account, privateKey: privateKey
        )
        let client = ToriiClient(
            baseURL: URL(string: "https://example.invalid")!,
            defaultHeaders: ["cache-control": "max-age=3600", "Accept": "application/json"],
            localSigningContext: ToriiLocalSigningContext(networkId: network),
            canonicalRequestFreshness: ToriiCanonicalRequestFreshness(
                timestampMs: { 1_700_000_000_000 },
                nonce: { "privacy-cache-policy" }
            )
        )
        // This returns only a request, never a validated manifest or admission.
        let request = try client.makePrivacyExact12CapabilityRequestV1(canonicalAuth: auth)
        let url = try XCTUnwrap(request.url)
        XCTAssertEqual(url.absoluteString, "https://example.invalid/v1/privacy/capabilities")
        XCTAssertEqual(request.httpMethod, "GET")
        XCTAssertNil(request.httpBody)
        XCTAssertEqual(request.cachePolicy, .reloadIgnoringLocalCacheData)
        XCTAssertEqual(request.value(forHTTPHeaderField: "Cache-Control"), "no-cache, no-store")
        XCTAssertEqual(request.value(forHTTPHeaderField: "Accept"), "application/x-norito")
        let expectedHeaders = try ToriiCanonicalRequest.buildHeaders(
            method: "GET", url: url, body: nil, accountId: account, privateKey: privateKey,
            networkId: network, timestampMs: 1_700_000_000_000, nonce: "privacy-cache-policy"
        )
        for (header, value) in expectedHeaders where header != ToriiCanonicalRequest.headerSignature {
            XCTAssertEqual(request.value(forHTTPHeaderField: header), value, header)
        }
        let signature = try XCTUnwrap(Data(base64Encoded: XCTUnwrap(
            request.value(forHTTPHeaderField: ToriiCanonicalRequest.headerSignature)
        )))
        let publicKey = try Curve25519.Signing.PrivateKey(rawRepresentation: privateKey).publicKey
        let message = try ToriiCanonicalRequest.signatureMessage(
            networkId: network, method: "GET", url: url, body: nil,
            timestampMs: 1_700_000_000_000, nonce: "privacy-cache-policy"
        )
        XCTAssertTrue(publicKey.isValidSignature(signature, for: message))
        let changedBodyMessage = try ToriiCanonicalRequest.signatureMessage(
            networkId: network, method: "GET", url: url, body: Data([1]),
            timestampMs: 1_700_000_000_000, nonce: "privacy-cache-policy"
        )
        XCTAssertFalse(publicKey.isValidSignature(signature, for: changedBodyMessage))
        let changedNetworkMessage = try ToriiCanonicalRequest.signatureMessage(
            networkId: NetworkId(bytes: Data(repeating: 0xd3, count: 32)),
            method: "GET", url: url, body: nil,
            timestampMs: 1_700_000_000_000, nonce: "privacy-cache-policy"
        )
        XCTAssertFalse(publicKey.isValidSignature(signature, for: changedNetworkMessage))
    }

    func testToriiManifestRequiresLocalSigningNetworkBeforeNativeOrTransport() async throws {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [UnexpectedPrivacyCapabilityTransport.self]
        let session = URLSession(configuration: configuration)
        defer { session.invalidateAndCancel() }
        let client = ToriiClient(baseURL: URL(string: "https://example.invalid")!, session: session)
        // The guard must run before authentication, native validation, or transport.
        let auth = ToriiCanonicalRequestAuth(
            accountId: "unused-before-network-guard", privateKey: Data(repeating: 1, count: 32)
        )
        do {
            _ = try await client.getPrivacyExact12CapabilityManifestV1(canonicalAuth: auth)
            XCTFail("missing expected network must reject")
        } catch ToriiClientError.invalidPayload(let message) {
            XCTAssertEqual(message, "privacy capability authority requires the expected local signing network")
        }
    }

    func testMissingOrStaleNativeArtifactRejectsManifestValidation() throws {
        guard !PrivacyNativeBridge.isNativeAvailable else { return }
        let fixture = makeFixture()
        XCTAssertThrowsError(try PrivacyNativeBridge.validateExact12CapabilityManifestV1(
            fixture.manifest
        )) { error in
            XCTAssertEqual(
                error as? PrivacyExact12CapabilityManifestErrorV1,
                .nativeUnavailable
            )
        }
    }

    func testPublicValidatorRejectsEmptyReleaseAndDeploymentEvidence() throws {
        // This structurally framed fixture has no executable/stage/audit evidence,
        // no release signatures, and no validator canaries or signatures.
        let fixture = makeFixture()
        XCTAssertThrowsError(try PrivacyNativeBridge.validateExact12CapabilityManifestV1(
            fixture.manifest
        )) { error in
            if PrivacyNativeBridge.isNativeAvailable {
                guard let nativeError = error as? PrivacyExact12CapabilityManifestErrorV1,
                      case .invalidArchive = nativeError else {
                    return XCTFail("Rust must reject the unsigned qualification: \(error)")
                }
            } else {
                XCTAssertEqual(error as? PrivacyExact12CapabilityManifestErrorV1, .nativeUnavailable)
            }
        }
    }

    private func makeFixture(
        rowZeroReadiness: Data? = nil,
        rowZeroLifecycle: Data? = nil,
        maxActionsPerTransaction: UInt32 = 1,
        activationDigestByte: UInt8 = 0x31,
        catalogDigestByte: UInt8 = 0x31,
        includeQualification: Bool = true,
        corruptSecurityClaimDigest: Bool = false,
        committedHeight: UInt64 = 3,
        qualificationActivationHeight: UInt64 = 2,
        qualificationConvergenceHeight: UInt64 = 3,
        useRetiredNineFieldRows: Bool = false,
        useRetiredExperimentalAssurance: Bool = false,
        swapFirstRows: Bool = false,
        embeddedDigest: Data? = nil,
        includePendingState: Bool = false,
        consensusSchedule: (UInt64, UInt64) = (2, 302),
        protocolSchedule: (UInt64, UInt64) = (2, 302),
        opaqueProofArtifacts: Data? = nil,
        deploymentNetworkBytes: Data? = nil,
        deploymentGenesisBytes: Data? = nil
    ) -> Fixture {
        var profiles = (0..<12).map { _ in enumValue(1, enumValue(0)) }
        profiles[0] = availableProfile(
            protocolTag: 0,
            proofSystemTag: 0,
            engineTag: 0,
            digestByte: 0x31,
            limits: enumValue(0)
        )
        profiles[6] = availableProfile(
            protocolTag: 6,
            proofSystemTag: 5,
            engineTag: 5,
            digestByte: 0x61,
            limits: enumValue(6, structure(u32(4)))
        )

        var catalogProfiles = profiles
        if catalogDigestByte != 0x31 {
            catalogProfiles[0] = availableProfile(
                protocolTag: 0,
                proofSystemTag: 0,
                engineTag: 0,
                digestByte: catalogDigestByte,
                limits: enumValue(0)
            )
        }

        var rows: [Data] = []
        for index in 0..<12 {
            let readiness: Data
            if index == 0 {
                readiness = rowZeroReadiness ?? (
                    includeQualification
                        ? enumValue(0)
                        : enumValue(1, enumValue(5))
                )
            } else if index == 6 {
                readiness = includePendingState
                    ? (includeQualification ? enumValue(0) : enumValue(1, enumValue(5)))
                    : enumValue(1, enumValue(1))
            } else {
                readiness = enumValue(1, enumValue(0, enumValue(0)))
            }
            let activation: Data
            if index == 0 {
                activation = option(activationForProfileZero(
                    digestByte: activationDigestByte,
                    useRetiredExperimentalAssurance: useRetiredExperimentalAssurance,
                    lifecycle: rowZeroLifecycle
                ))
            } else if index == 6, includePendingState {
                activation = option(activationForJindoWithPendingTightening(schedule: protocolSchedule))
            } else {
                activation = option(nil)
            }
            let commonFields = structure(
                enumValue(UInt32(index)),
                enumValue(UInt32(index)),
                enumValue(executionModes[index]),
                structure(Data([featureMasks[index]])),
                profiles[index],
                readiness
            )
            var encodedRow = commonFields
            if useRetiredNineFieldRows {
                appendField(
                    enumValue(index == 0 || (index == 6 && includePendingState) ? 2 : 0),
                    to: &encodedRow
                )
                appendField(activation, to: &encodedRow)
                appendField(option(nil), to: &encodedRow)
            } else {
                appendField(activation, to: &encodedRow)
            }
            rows.append(encodedRow)
        }
        if swapFirstRows { rows.swapAt(0, 1) }

        let catalogRows = catalogProfiles.enumerated().map { index, profile in
            structure(enumValue(UInt32(index)), profile)
        }
        let catalog = noritoEncode(
            typeName: "iroha.privacy.compiled-profile-catalog.v1",
            payload: structure(u32(1), sequence(catalogRows)),
            flags: NoritoHeader.compactLen,
            payloadAlignment: 8
        )

        let digest: Data
        let qualification = includeQualification
            ? exact12Qualification(
                corruptSecurityClaimDigest: corruptSecurityClaimDigest,
                firstActivationHeight: qualificationActivationHeight,
                convergenceHeight: qualificationConvergenceHeight,
                opaqueProofArtifacts: opaqueProofArtifacts,
                deploymentNetworkBytes: deploymentNetworkBytes ?? networkBytes,
                deploymentGenesisBytes: deploymentGenesisBytes ?? networkBytes
            )
            : nil
        if let embeddedDigest {
            digest = embeddedDigest
        } else {
            let normalized = buildManifest(
                rows: rows,
                qualification: qualification,
                digest: Data(repeating: 0, count: 32),
                maxActionsPerTransaction: maxActionsPerTransaction,
                includePendingState: includePendingState,
                schedule: consensusSchedule,
                committedHeight: committedHeight
            )
            var preimage = Data("iroha:privacy:exact12-capability-manifest:v1".utf8)
            preimage.append(u64(UInt64(normalized.count)))
            preimage.append(normalized)
            digest = Data(SHA256.hash(data: preimage))
        }
        return Fixture(
            manifest: buildManifest(
                rows: rows,
                qualification: qualification,
                digest: digest,
                maxActionsPerTransaction: maxActionsPerTransaction,
                includePendingState: includePendingState,
                schedule: consensusSchedule,
                committedHeight: committedHeight
            ),
            catalog: catalog
        )
    }

    private func availableProfile(
        protocolTag: UInt32,
        proofSystemTag: UInt32,
        engineTag: UInt32,
        digestByte: UInt8,
        limits: Data
    ) -> Data {
        let digest = structure(Data(repeating: digestByte, count: 32))
        return enumValue(0, structure(
            enumValue(protocolTag), enumValue(proofSystemTag), enumValue(engineTag),
            digest, digest, digest, digest, digest, limits
        ))
    }

    private func activationForProfileZero(
        digestByte: UInt8 = 0x31,
        useRetiredExperimentalAssurance: Bool = false,
        lifecycle: Data? = nil
    ) -> Data {
        let digest = structure(Data(repeating: digestByte, count: 32))
        var activation = structure(
            enumValue(0), enumValue(0), enumValue(0),
            digest, digest, digest, digest, digest,
            lifecycle ?? enumValue(1, structure(u64(1), u64(2), u64(2))),
            enumValue(0), option(nil)
        )
        if useRetiredExperimentalAssurance {
            appendField(enumValue(0), to: &activation)
        }
        return activation
    }

    private func securityClaim(
        protocolId: PrivacyProtocolIdV1,
        digestByte: UInt8,
        corruptDigest: Bool = false
    ) -> (claim: Data, digest: Data) {
        let bindingDigest = structure(Data(repeating: digestByte, count: 32))
        let claim = structure(
            exact12CatalogCommitment(),
            enumValue(protocolId.noritoDiscriminant),
            enumValue(securityModelTag(protocolId)),
            u16(128),
            u16(128),
            bindingDigest,
            bindingDigest,
            structure(Data(repeating: 0xe1, count: 32)),
            structure(Data(repeating: 0xe2, count: 32))
        )
        let canonicalClaim = noritoEncode(
            typeName: "iroha_data_model::privacy::protocol::PrivacySecurityClaimV1",
            payload: claim,
            flags: NoritoHeader.compactLen,
            payloadAlignment: 2
        )
        var preimage = Data("iroha:privacy:security-claim:v1".utf8)
        preimage.append(u64(UInt64(canonicalClaim.count)))
        preimage.append(canonicalClaim)
        var claimDigest = Data(SHA256.hash(data: preimage))
        if corruptDigest {
            claimDigest[claimDigest.startIndex] ^= 0xff
        }
        return (claim, claimDigest)
    }

    private func exact12Qualification(
        corruptSecurityClaimDigest: Bool,
        firstActivationHeight: UInt64,
        convergenceHeight: UInt64,
        opaqueProofArtifacts: Data?,
        deploymentNetworkBytes: Data,
        deploymentGenesisBytes: Data
    ) -> Data {
        let releaseDigest = Data(repeating: 0xe3, count: 32)
        let releaseBindings = PrivacyProtocolIdV1.allCases.enumerated().map { index, protocolId in
            releaseBinding(
                protocolId,
                digestByte: profileDigestByte(index),
                corruptSecurityClaimDigest: corruptSecurityClaimDigest && index == 0
            )
        }
        let source = structure(
            structure(Data(repeating: 0xa1, count: 32)),
            Data([1]),
            compactString("swift-test-toolchain"),
            structure(Data(repeating: 0xa2, count: 32)),
            structure(Data(repeating: 0xa3, count: 32))
        )
        let release = structure(
            u16(1),
            compactString("iroha-privacy-exact12-v1"),
            exact12CatalogCommitment(),
            source,
            u16(1),
            structure(Data(repeating: 0xa4, count: 32)),
            structure(Data(repeating: 0xa5, count: 32)),
            sequence([]),
            sequence(releaseBindings),
            sequence([]),
            opaqueProofArtifacts ?? sequence([]),
            sequence([]),
            sequence([]),
            structure(Data(repeating: 0xa6, count: 32)),
            sequence([]),
            structure(Data(repeating: 0xe2, count: 32)),
            sequence([]),
            structure(releaseDigest)
        )
        let activations = PrivacyProtocolIdV1.allCases.enumerated().map { index, protocolId in
            structure(
                enumValue(protocolId.noritoDiscriminant),
                u64(index == 0 ? firstActivationHeight : 2)
            )
        }
        let deployment = structure(
            u16(1),
            compactString("swift-test-chain"),
            // Rust COMPACT_LEN encodes both owning fields with raw32 inner bytes.
            deploymentNetworkBytes,
            deploymentGenesisBytes,
            structure(releaseDigest),
            structure(Data(repeating: 0xd1, count: 32)),
            sequence(activations),
            structure(Data(repeating: 0xd2, count: 32)),
            compactString("v1"),
            u64(convergenceHeight),
            structure(Data(repeating: 0xd3, count: 32)),
            sequence([]),
            sequence([]),
            structure(Data(repeating: 0xe4, count: 32))
        )
        return structure(release, deployment)
    }

    private func releaseBinding(
        _ protocolId: PrivacyProtocolIdV1,
        digestByte: UInt8,
        corruptSecurityClaimDigest: Bool
    ) -> Data {
        let digest = structure(Data(repeating: digestByte, count: 32))
        let claim = securityClaim(
            protocolId: protocolId,
            digestByte: digestByte,
            corruptDigest: corruptSecurityClaimDigest
        )
        return structure(
            enumValue(protocolId.noritoDiscriminant),
            enumValue(protocolId.expectedProofSystem.rawValue),
            enumValue(protocolId.expectedEngine.rawValue),
            digest,
            digest,
            digest,
            digest,
            digest,
            claim.claim,
            structure(claim.digest)
        )
    }

    private func profileDigestByte(_ index: Int) -> UInt8 {
        switch index {
        case 0: return 0x31
        case 6: return 0x61
        default: return UInt8(0x40 + index)
        }
    }

    private func securityModelTag(_ protocolId: PrivacyProtocolIdV1) -> UInt32 {
        switch protocolId {
        case .zkAcePqAuthorizationV1, .irohaJindoPolynomialCommitmentV1,
             .irohaBootleLanternAnoncredV1, .irohaIvmPrivateNoteStarkV1,
             .pqMaspStarkV1:
            return 0
        default:
            return 1
        }
    }

    private func exact12CatalogCommitment() -> Data {
        let words: [UInt64] = [
            0x7c30_a004_39f1_37e0,
            0x6b40_fb5c_d815_db00,
            0x49a9_4401_d272_97d7,
            0x2e34_8ea7_fdf3_f0de,
            0xfabf_bf7c_7865_7f74,
            0xffbb_e269_c311_4fc9,
        ]
        return words.reduce(into: Data()) { output, word in
            output.append(u64(word))
        }
    }

    private func submitProofInstruction(
        protocolTag: UInt32 = 0,
        proofSystemTag: UInt32 = 0,
        engineTag: UInt32 = 0,
        parameterIdByte: UInt8 = 0x31,
        statementDigestByte: UInt8 = 0x71,
        statementTag: UInt32 = 0,
        proofTag: UInt32 = 0,
        statementNetworkBytes: Data? = nil,
        wireMagic: Data = Data([0x49, 0x52, 0x48, 0x5a, 0x4b, 0x31, 0xa5, 0x5a]),
        catalogCommitment: Data? = nil,
        retiredElevenFieldEnvelope: Bool = false
    ) -> Data {
        let profileDigest = structure(Data(repeating: 0x31, count: 32))
        let parameterId = structure(Data(repeating: parameterIdByte, count: 32))
        let statementDigest = structure(
            Data(repeating: statementDigestByte, count: 32)
        )
        let retainedFields = structure(
            enumValue(protocolTag),
            enumValue(proofSystemTag),
            enumValue(engineTag),
            parameterId,
            profileDigest,
            profileDigest,
            profileDigest,
            profileDigest,
            statementDigest,
            syntheticStatement(tag: statementTag, network: statementNetworkBytes ?? networkBytes),
            enumValue(proofTag, Data([1]))
        )
        let envelope = retiredElevenFieldEnvelope
            ? retainedFields
            : structure(wireMagic, catalogCommitment ?? exact12CatalogCommitment()) + retainedFields
        return noritoEncode(
            typeName: "iroha_data_model::isi::privacy::SubmitPrivacyProofV1",
            payload: structure(envelope),
            flags: NoritoHeader.compactLen,
            payloadAlignment: 16
        )
    }

    /// Projection-only statement shell; it has no proof or native authority.
    private func syntheticStatement(tag: UInt32, network: Data, contextSuffix: Data = Data()) -> Data {
        let digest = structure(Data(repeating: 0x31, count: 32))
        let context = structure(network, u32(0), digest, digest, digest, digest, digest, digest)
            + contextSuffix
        return enumValue(tag, structure(context, Data([1])))
    }

    private func activationForJindoWithPendingTightening(
        schedule: (UInt64, UInt64) = (2, 302)
    ) -> Data {
        let digest = structure(Data(repeating: 0x61, count: 32))
        return structure(
            enumValue(6), enumValue(5), enumValue(5),
            digest, digest, digest, digest, digest,
            enumValue(1, structure(u64(1), u64(2), u64(2))),
            enumValue(6, structure(u32(4))),
            option(structure(
                u64(schedule.0), u64(schedule.1), enumValue(6, structure(u32(3)))
            ))
        )
    }

    private func consensusPolicy(
        maxActionsPerTransaction: UInt32 = 1,
        includePendingState: Bool = false,
        schedule: (UInt64, UInt64) = (2, 302)
    ) -> Data {
        let current = structure(
            u32(maxActionsPerTransaction), u32(2),
            u32(9 * 1024 * 1024), u32(9_699_840),
            u32(9_699_840), u32(16_711_680),
            u32(256 * 1024), u32(8), u32(8), u32(2_048)
        )
        let pending: Data?
        if includePendingState {
            pending = structure(
                u64(schedule.0),
                u64(schedule.1),
                structure(
                    u32(maxActionsPerTransaction), u32(2),
                    u32(9 * 1024 * 1024), u32(9_699_840),
                    u32(9_699_840), u32(16_711_680),
                    u32(256 * 1024), u32(8), u32(8), u32(1_024)
                )
            )
        } else {
            pending = nil
        }
        return structure(
            current,
            option(pending)
        )
    }

    private func buildManifest(
        rows: [Data],
        qualification: Data?,
        digest: Data,
        maxActionsPerTransaction: UInt32,
        includePendingState: Bool,
        schedule: (UInt64, UInt64),
        committedHeight: UInt64
    ) -> Data {
        manifestFrame(structure(
            u32(1), u64(committedHeight),
            consensusPolicy(
                maxActionsPerTransaction: maxActionsPerTransaction,
                includePendingState: includePendingState,
                schedule: schedule
            ),
            option(qualification),
            sequence(rows), structure(digest)
        ))
    }

    private func manifestFrame(_ payload: Data) -> Data {
        noritoEncode(
            typeName: "iroha.privacy.exact12-capability-manifest.v1",
            payload: payload,
            flags: NoritoHeader.compactLen,
            payloadAlignment: 8
        )
    }

    private func structure(_ fields: Data...) -> Data {
        var output = Data()
        for field in fields { appendField(field, to: &output) }
        return output
    }

    private func sequence(_ values: [Data]) -> Data {
        var output = u64(UInt64(values.count))
        for value in values { appendField(value, to: &output) }
        return output
    }

    private func enumValue(_ tag: UInt32, _ payload: Data? = nil) -> Data {
        var output = u32(tag)
        if let payload { appendField(payload, to: &output) }
        return output
    }

    private func option(_ value: Data?) -> Data {
        var output = Data([value == nil ? 0 : 1])
        if let value { appendField(value, to: &output) }
        return output
    }

    private func u32(_ value: UInt32) -> Data {
        var value = value.littleEndian
        return Data(bytes: &value, count: 4)
    }

    private func u16(_ value: UInt16) -> Data {
        var value = value.littleEndian
        return Data(bytes: &value, count: 2)
    }

    private func u64(_ value: UInt64) -> Data {
        var value = value.littleEndian
        return Data(bytes: &value, count: 8)
    }

    private func appendField(_ field: Data, to output: inout Data) {
        appendCompactLength(UInt64(field.count), to: &output)
        output.append(field)
    }

    private func compactString(_ value: String) -> Data {
        let bytes = Data(value.utf8)
        var output = Data()
        appendCompactLength(UInt64(bytes.count), to: &output)
        output.append(bytes)
        return output
    }

    private func appendCompactLength(_ value: UInt64, to output: inout Data) {
        var length = value
        while length >= 0x80 {
            output.append(UInt8(length & 0x7f) | 0x80)
            length >>= 7
        }
        output.append(UInt8(length))
    }

    private struct Fixture {
        let manifest: Data
        let catalog: Data
    }
}

private final class UnexpectedPrivacyCapabilityTransport: URLProtocol {
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        XCTFail("privacy admission without an expected network must never reach transport")
        client?.urlProtocol(self, didFailWithError: URLError(.cancelled))
    }
    override func stopLoading() {}
}
