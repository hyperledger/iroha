import CryptoKit
import Foundation

/// Strict failure surface for the first-release Exact12 capability contract.
public enum PrivacyExact12CapabilityManifestErrorV1: Error, LocalizedError, Equatable, Sendable {
    case nativeUnavailable
    case invalidArchive(String)
    case unavailableProtocol(PrivacyProtocolIdV1)
    case compiledTupleMismatch(PrivacyProtocolIdV1)
    case invalidAdmission

    public var errorDescription: String? {
        switch self {
        case .nativeUnavailable:
            return "Exact12 capability admission requires the exact ABI29 native bridge."
        case let .invalidArchive(reason):
            return "Exact12 capability manifest is invalid: \(reason)"
        case let .unavailableProtocol(protocolId):
            return "Exact12 protocol \(protocolId.rawValue) is not production-qualified in committed state."
        case let .compiledTupleMismatch(protocolId):
            return "Exact12 protocol \(protocolId.rawValue) differs from this binary's compiled profile tuple."
        case .invalidAdmission:
            return "Exact12 capability admission is missing, stale, or bound to a different protocol or network."
        }
    }
}

/// Closed operation schema in the canonical protocol order.
public enum PrivacyOperationSchemaV1: UInt32, CaseIterable, Sendable {
    case zkAceAuthorizationActionV1 = 0
    case anonymousPgcPaymentActionV1 = 1
    case veRangeRangeProofV1 = 2
    case zkAmsAdmissionAndProvisioningV1 = 3
    case vegaCredentialPresentationV1 = 4
    case zkX509IdentityPresentationV1 = 5
    case jindoPolynomialEvaluationV1 = 6
    case bootleLanternCredentialPresentationV1 = 7
    case orchardNoteActionV1 = 8
    case fcmpMembershipPaymentV1 = 9
    case ivmPrivateNoteActionV1 = 10
    case pqMaspNoteActionV1 = 11

    public var canonicalLabel: String {
        switch self {
        case .zkAceAuthorizationActionV1: return "zk_ace_authorization_action_v1"
        case .anonymousPgcPaymentActionV1: return "anonymous_pgc_payment_action_v1"
        case .veRangeRangeProofV1: return "verange_range_proof_v1"
        case .zkAmsAdmissionAndProvisioningV1:
            return "zk_ams_admission_and_provisioning_v1"
        case .vegaCredentialPresentationV1: return "vega_credential_presentation_v1"
        case .zkX509IdentityPresentationV1: return "zk_x509_identity_presentation_v1"
        case .jindoPolynomialEvaluationV1: return "jindo_polynomial_evaluation_v1"
        case .bootleLanternCredentialPresentationV1:
            return "bootle_lantern_credential_presentation_v1"
        case .orchardNoteActionV1: return "orchard_note_action_v1"
        case .fcmpMembershipPaymentV1: return "fcmp_membership_payment_v1"
        case .ivmPrivateNoteActionV1: return "ivm_private_note_action_v1"
        case .pqMaspNoteActionV1: return "pq_masp_note_action_v1"
        }
    }
}

/// Closed execution classification carried by a committed row.
public enum PrivacyExecutionModeV1: UInt32, CaseIterable, Sendable {
    case authorizationAction = 0
    case paymentAction = 1
    case component = 2
    case admissionAction = 3
    case presentationAction = 4
    case noteAction = 5

    public var canonicalLabel: String {
        switch self {
        case .authorizationAction: return "authorization_action"
        case .paymentAction: return "payment_action"
        case .component: return "component"
        case .admissionAction: return "admission_action"
        case .presentationAction: return "presentation_action"
        case .noteAction: return "note_action"
        }
    }
}

public enum PrivacyCompiledProfileUnavailableReasonV1: Equatable, Sendable {
    case engineUnavailable
    case profileInitializationFailed
    case statementSchemaInvalid(conflictingStableTypeId: Bool)
}

public struct PrivacyProtocolActivationLimitsV1: Equatable, Sendable {
    public let protocolId: PrivacyProtocolIdV1
    public let values: [UInt32]
    let canonicalNorito: Data
}

/// Complete immutable profile/schema tuple compiled into a retained protocol.
public struct PrivacyCompiledProfileSnapshotV1: Equatable, Sendable {
    public let protocolId: PrivacyProtocolIdV1
    public let proofSystemId: PrivacyProofSystemIdV1
    public let engineId: PrivacyEngineIdV1
    public let parameterId: Data
    public let parameterDigest: Data
    public let verifierDigest: Data
    public let statementSchemaDigest: Data
    public let engineManifestDigest: Data
    public let protocolLimits: PrivacyProtocolActivationLimitsV1
}

public enum PrivacyCompiledProfileResultV1: Equatable, Sendable {
    case available(PrivacyCompiledProfileSnapshotV1)
    case unavailable(PrivacyCompiledProfileUnavailableReasonV1)
}

public enum PrivacyCapabilityUnavailableReasonV1: Equatable, Sendable {
    case compiledProfile(PrivacyCompiledProfileUnavailableReasonV1)
    case notRegistered
    case proposed
    case suspended
    case retired
    case missingProductionQualification
    case invalidProductionQualification
}

public enum PrivacyCapabilityReadinessV1: Equatable, Sendable {
    case productionQualified
    case unavailable(PrivacyCapabilityUnavailableReasonV1)
}

public struct PrivacyConsensusLimitsV1: Equatable, Sendable {
    public let maxActionsPerTransaction: UInt32
    public let maxActionsPerBlock: UInt32
    public let maxProofBytesPerAction: UInt32
    public let maxActionBytes: UInt32
    public let maxPrivacyBytesPerTransaction: UInt32
    public let maxPrivacyBytesPerBlock: UInt32
    public let maxStatementAndEncryptedOutputBytesPerTransaction: UInt32
    public let maxNullifiersPerAction: UInt32
    public let maxCommitmentsPerAction: UInt32
    public let retainedRootCount: UInt32

    var orderedValues: [UInt32] {
        [
            maxActionsPerTransaction, maxActionsPerBlock, maxProofBytesPerAction,
            maxActionBytes, maxPrivacyBytesPerTransaction, maxPrivacyBytesPerBlock,
            maxStatementAndEncryptedOutputBytesPerTransaction,
            maxNullifiersPerAction, maxCommitmentsPerAction, retainedRootCount,
        ]
    }
}

public struct PrivacyConsensusPolicyTighteningV1: Equatable, Sendable {
    public let scheduledAtHeight: UInt64
    public let effectiveAtHeight: UInt64
    public let nextLimits: PrivacyConsensusLimitsV1
}

public struct PrivacyConsensusPolicyV1: Equatable, Sendable {
    public let currentLimits: PrivacyConsensusLimitsV1
    public let pendingTightening: PrivacyConsensusPolicyTighteningV1?
    /// Exact canonical nested value retained from Torii.
    public let canonicalNorito: Data
}

public enum PrivacyProtocolLifecycleV1: Equatable, Sendable {
    case proposed(proposedAtHeight: UInt64)
    case active(proposedAtHeight: UInt64, activatedAtHeight: UInt64, stateSinceHeight: UInt64)
    case suspended(proposedAtHeight: UInt64, activatedAtHeight: UInt64, stateSinceHeight: UInt64)
    case retired(proposedAtHeight: UInt64, activatedAtHeight: UInt64?, stateSinceHeight: UInt64)
}

public struct PrivacyProtocolLimitsTighteningV1: Equatable, Sendable {
    public let scheduledAtHeight: UInt64
    public let effectiveAtHeight: UInt64
    public let nextLimits: PrivacyProtocolActivationLimitsV1
}

/// Weakest security model in the complete protocol composition.
public enum PrivacySecurityModelV1: UInt32, CaseIterable, Sendable {
    case postQuantumQrom = 0
    case classicalRom = 1

    public var canonicalLabel: String {
        switch self {
        case .postQuantumQrom: return "pq-qrom"
        case .classicalRom: return "classical-rom"
        }
    }
}

/// Complete independently reviewable security claim bound to one activation.
public struct PrivacySecurityClaimV1: Equatable, Sendable {
    public let catalogCommitment: Data
    public let protocolId: PrivacyProtocolIdV1
    public let securityModel: PrivacySecurityModelV1
    public let targetSecurityBits: UInt16
    public let achievedSecurityBits: UInt16
    public let parameterDigest: Data
    public let verifierDigest: Data
    public let reductionDigest: Data
    public let auditBundleDigest: Data
    /// Exact canonical nested value retained from Torii.
    public let canonicalNorito: Data
}

/// Exact release tuple for one retained protocol.
public struct PrivacyReleaseProtocolBindingV1: Equatable, Sendable {
    public let protocolId: PrivacyProtocolIdV1
    public let proofSystemId: PrivacyProofSystemIdV1
    public let engineId: PrivacyEngineIdV1
    public let parameterId: Data
    public let parameterDigest: Data
    public let verifierDigest: Data
    public let statementSchemaDigest: Data
    public let engineManifestDigest: Data
    public let securityClaim: PrivacySecurityClaimV1
    public let securityClaimDigest: Data
    public let canonicalNorito: Data
}

/// Full portable release evidence retained from the native-validated archive.
public struct PrivacyExact12ReleaseManifestV1: Equatable, Sendable {
    public let version: UInt16
    public let catalogCommitment: Data
    public let abiVersion: UInt16
    public let protocols: [PrivacyReleaseProtocolBindingV1]
    public let auditBundleDigest: Data
    public let manifestDigest: Data
    public let canonicalNorito: Data
}

/// One protocol activation height bound by the target deployment.
public struct PrivacyDeploymentActivationV1: Equatable, Sendable {
    public let protocolId: PrivacyProtocolIdV1
    public let activationHeight: UInt64
}

/// Full network-bound deployment evidence retained from the native-validated archive.
public struct PrivacyExact12DeploymentQualificationV1: Equatable, Sendable {
    public let version: UInt16
    public let networkId: NetworkId
    public let genesisHash: Data
    public let releaseManifestDigest: Data
    public let activations: [PrivacyDeploymentActivationV1]
    public let convergenceHeight: UInt64
    public let qualificationDigest: Data
    public let canonicalNorito: Data
}

/// Singleton release plus target-network evidence from committed state.
public struct PrivacyExact12QualificationRecordV1: Equatable, Sendable {
    public let releaseManifest: PrivacyExact12ReleaseManifestV1
    public let deploymentQualification: PrivacyExact12DeploymentQualificationV1
    public let canonicalNorito: Data
}

/// Full committed activation record, including all profile/schema bindings.
public struct PrivacyProtocolActivationRecordV1: Equatable, Sendable {
    public let protocolId: PrivacyProtocolIdV1
    public let proofSystemId: PrivacyProofSystemIdV1
    public let engineId: PrivacyEngineIdV1
    public let parameterId: Data
    public let parameterDigest: Data
    public let verifierDigest: Data
    public let statementSchemaDigest: Data
    public let engineManifestDigest: Data
    public let lifecycle: PrivacyProtocolLifecycleV1
    public let protocolLimits: PrivacyProtocolActivationLimitsV1
    public let pendingProtocolLimitsTightening: PrivacyProtocolLimitsTighteningV1?
    /// Exact canonical nested value retained from Torii.
    public let canonicalNorito: Data
}

public struct PrivacyExact12CapabilityRowV1: Equatable, Sendable {
    public let protocolId: PrivacyProtocolIdV1
    public let operationSchema: PrivacyOperationSchemaV1
    public let executionMode: PrivacyExecutionModeV1
    public let privacyFeatureMask: UInt8
    public let compiledProfile: PrivacyCompiledProfileResultV1
    public let readiness: PrivacyCapabilityReadinessV1
    public let activation: PrivacyProtocolActivationRecordV1?
    /// True only after byte-exact comparison with the ABI29-validated local catalog.
    public let localCompiledTupleMatches: Bool

    public var isNetworkAvailable: Bool {
        readiness == .productionQualified
    }

    let compiledProfileCanonicalNorito: Data
}

/// Immutable native-validated projection; network admission also requires authenticated Torii origin.
public final class PrivacyExact12CapabilityManifestV1: @unchecked Sendable {
    public static let versionV1: UInt32 = 1
    public static let maximumArchiveBytes = 256 * 1024

    public let version: UInt32
    public let committedHeight: UInt64
    public let consensusPolicy: PrivacyConsensusPolicyV1
    public let qualification: PrivacyExact12QualificationRecordV1?
    public let protocols: [PrivacyExact12CapabilityRowV1]
    public let manifestDigest: Data
    private let archive: Data
    fileprivate let authenticatedNetworkId: NetworkId?

    fileprivate init(
        version: UInt32,
        committedHeight: UInt64,
        consensusPolicy: PrivacyConsensusPolicyV1,
        qualification: PrivacyExact12QualificationRecordV1?,
        protocols: [PrivacyExact12CapabilityRowV1],
        manifestDigest: Data,
        canonicalArchive: Data,
        authenticatedNetworkId: NetworkId? = nil
    ) {
        self.version = version
        self.committedHeight = committedHeight
        self.consensusPolicy = consensusPolicy
        self.qualification = qualification
        self.protocols = protocols
        self.manifestDigest = Data(manifestDigest)
        archive = Data(canonicalArchive)
        self.authenticatedNetworkId = authenticatedNetworkId
    }

    /// Issue network authority only after the Torii client authenticates and bounds the response.
    static func fromAuthenticatedToriiResponseV1(
        _ archive: Data,
        expectedNetworkId: NetworkId
    ) throws -> PrivacyExact12CapabilityManifestV1 {
        let validated = try PrivacyNativeBridge.validateExact12CapabilityManifestV1(archive)
        if validated.qualification != nil {
            try PrivacyExact12CapabilityManifestCodecV1.requireDeploymentNetworkV1(
                validated, expectedNetworkId: expectedNetworkId
            )
        }
        return PrivacyExact12CapabilityManifestV1(
            version: validated.version,
            committedHeight: validated.committedHeight,
            consensusPolicy: validated.consensusPolicy,
            qualification: validated.qualification,
            protocols: validated.protocols,
            manifestDigest: validated.manifestDigest,
            canonicalArchive: validated.canonicalBytes(),
            authenticatedNetworkId: expectedNetworkId
        )
    }

    /// Defensive copy of the exact canonical bytes returned by Torii.
    public func canonicalBytes() -> Data { Data(archive) }

    public func row(for protocolId: PrivacyProtocolIdV1) -> PrivacyExact12CapabilityRowV1 {
        let index = Int(protocolId.noritoDiscriminant)
        precondition(protocols[index].protocolId == protocolId)
        return protocols[index]
    }
}

/// Opaque token which revalidates its source manifest and native tuple at use time.
public final class PrivacyExact12CapabilityTupleAdmissionV1: @unchecked Sendable {
    public let protocolId: PrivacyProtocolIdV1
    public let networkId: NetworkId
    public let committedHeight: UInt64
    public let manifestDigest: Data
    public let operationSchema: PrivacyOperationSchemaV1

    private final class Seal: @unchecked Sendable {}
    private static let authenticSeal = Seal()
    private let seal: Seal
    private let manifestArchive: Data

    private init(
        manifest: PrivacyExact12CapabilityManifestV1,
        row: PrivacyExact12CapabilityRowV1,
        networkId: NetworkId
    ) {
        protocolId = row.protocolId
        self.networkId = networkId
        committedHeight = manifest.committedHeight
        manifestDigest = Data(manifest.manifestDigest)
        operationSchema = row.operationSchema
        manifestArchive = manifest.canonicalBytes()
        seal = Self.authenticSeal
    }

    fileprivate static func issue(
        manifest: PrivacyExact12CapabilityManifestV1,
        row: PrivacyExact12CapabilityRowV1,
        networkId: NetworkId
    ) -> PrivacyExact12CapabilityTupleAdmissionV1 {
        PrivacyExact12CapabilityTupleAdmissionV1(
            manifest: manifest, row: row, networkId: networkId
        )
    }

    fileprivate func requireAuthentic(
        for expectedProtocol: PrivacyProtocolIdV1,
        expectedNetworkId: NetworkId,
        instructionArchive: Data
    ) throws {
        guard seal === Self.authenticSeal, protocolId == expectedProtocol,
              networkId == expectedNetworkId else {
            throw PrivacyExact12CapabilityManifestErrorV1.invalidAdmission
        }
        let current = try PrivacyNativeBridge.validateExact12CapabilityManifestV1(
            manifestArchive
        )
        guard current.committedHeight == committedHeight,
              current.manifestDigest == manifestDigest else {
            throw PrivacyExact12CapabilityManifestErrorV1.invalidAdmission
        }
        try PrivacyExact12CapabilityManifestCodecV1.requireDeploymentNetworkV1(
            current, expectedNetworkId: networkId
        )
        let row = current.row(for: expectedProtocol)
        guard row.isNetworkAvailable else {
            throw PrivacyExact12CapabilityManifestErrorV1.unavailableProtocol(expectedProtocol)
        }
        guard row.localCompiledTupleMatches else {
            throw PrivacyExact12CapabilityManifestErrorV1.compiledTupleMismatch(expectedProtocol)
        }
        try PrivacyExact12CapabilityManifestCodecV1.requireSubmitProofInstruction(
            instructionArchive,
            row: row,
            consensusLimits: current.consensusPolicy.currentLimits,
            expectedNetworkId: expectedNetworkId
        )
    }
}

/// The sole path from a committed manifest to retained-protocol construction.
public enum PrivacyExact12CapabilityAdmissionV1 {
    public static func requireExact12CapabilityTupleV1(
        _ manifest: PrivacyExact12CapabilityManifestV1,
        protocolId: PrivacyProtocolIdV1
    ) throws -> PrivacyExact12CapabilityTupleAdmissionV1 {
        guard let expectedNetworkId = manifest.authenticatedNetworkId else {
            throw PrivacyExact12CapabilityManifestErrorV1.invalidAdmission
        }
        // Decode again so admission cannot rely on stale managed state or a prior native load.
        let current = try PrivacyNativeBridge.validateExact12CapabilityManifestV1(
            manifest.canonicalBytes()
        )
        guard current.manifestDigest == manifest.manifestDigest,
              current.committedHeight == manifest.committedHeight else {
            throw PrivacyExact12CapabilityManifestErrorV1.invalidAdmission
        }
        try PrivacyExact12CapabilityManifestCodecV1.requireDeploymentNetworkV1(
            current, expectedNetworkId: expectedNetworkId
        )
        let row = current.row(for: protocolId)
        guard row.isNetworkAvailable else {
            throw PrivacyExact12CapabilityManifestErrorV1.unavailableProtocol(protocolId)
        }
        guard row.localCompiledTupleMatches else {
            throw PrivacyExact12CapabilityManifestErrorV1.compiledTupleMismatch(protocolId)
        }
        return PrivacyExact12CapabilityTupleAdmissionV1.issue(
            manifest: current,
            row: row,
            networkId: expectedNetworkId
        )
    }

    public static func requireForConstruction(
        _ admission: PrivacyExact12CapabilityTupleAdmissionV1,
        protocolId: PrivacyProtocolIdV1,
        expectedNetworkId: NetworkId,
        submitProofInstructionNorito: Data
    ) throws {
        try admission.requireAuthentic(
            for: protocolId,
            expectedNetworkId: expectedNetworkId,
            instructionArchive: submitProofInstructionNorito
        )
    }
}

extension PrivacyProtocolIdV1 {
    fileprivate var expectedOperationSchemaV1: PrivacyOperationSchemaV1 {
        PrivacyOperationSchemaV1(rawValue: noritoDiscriminant)!
    }

    fileprivate var expectedExecutionModeV1: PrivacyExecutionModeV1 {
        switch self {
        case .zkAcePqAuthorizationV1: return .authorizationAction
        case .anonymousPgcKOutOfNV1, .moneroFcmpPlusPlusV1: return .paymentAction
        case .veRangeTransparentRangeV1, .irohaJindoPolynomialCommitmentV1:
            return .component
        case .irohaZkAmsV1: return .admissionAction
        case .vegaExistingCredentialZkV1, .irohaZkX509StarkP256V1,
             .irohaBootleLanternAnoncredV1:
            return .presentationAction
        case .orchardHalo2ActionsV1, .irohaIvmPrivateNoteStarkV1, .pqMaspStarkV1:
            return .noteAction
        }
    }

    fileprivate var expectedPrivacyFeatureMaskV1: UInt8 {
        switch self {
        case .zkAcePqAuthorizationV1, .irohaJindoPolynomialCommitmentV1: return 0
        case .anonymousPgcKOutOfNV1: return 0b00110
        case .veRangeTransparentRangeV1: return 0b00001
        case .irohaZkAmsV1, .vegaExistingCredentialZkV1,
             .irohaZkX509StarkP256V1, .irohaBootleLanternAnoncredV1,
             .moneroFcmpPlusPlusV1:
            return 0b00010
        case .orchardHalo2ActionsV1, .irohaIvmPrivateNoteStarkV1: return 0b00111
        case .pqMaspStarkV1: return 0b11111
        }
    }

    fileprivate var expectedSecurityModelV1: PrivacySecurityModelV1 {
        switch self {
        case .zkAcePqAuthorizationV1, .irohaJindoPolynomialCommitmentV1,
             .irohaBootleLanternAnoncredV1, .irohaIvmPrivateNoteStarkV1,
             .pqMaspStarkV1:
            return .postQuantumQrom
        case .anonymousPgcKOutOfNV1, .veRangeTransparentRangeV1,
             .irohaZkAmsV1, .vegaExistingCredentialZkV1,
             .irohaZkX509StarkP256V1, .orchardHalo2ActionsV1,
             .moneroFcmpPlusPlusV1:
            return .classicalRom
        }
    }
}

/// Bounded Norito field projection used after Rust validates the entire archive and its evidence.
enum PrivacyExact12CapabilityManifestCodecV1 {
    private static let manifestSchema = "iroha.privacy.exact12-capability-manifest.v1"
    private static let catalogSchema = "iroha.privacy.compiled-profile-catalog.v1"
    private static let submitProofSchema =
        "iroha_data_model::isi::privacy::SubmitPrivacyProofV1"
    private static let securityClaimSchema =
        "iroha_data_model::privacy::protocol::PrivacySecurityClaimV1"
    private static let manifestDigestDomain =
        Data("iroha:privacy:exact12-capability-manifest:v1".utf8)
    private static let securityClaimDigestDomain =
        Data("iroha:privacy:security-claim:v1".utf8)
    private static let proofWireMagic = Data([0x49, 0x52, 0x48, 0x5a, 0x4b, 0x31, 0xa5, 0x5a])
    private static let exact12CatalogCommitment: Data = {
        let words: [UInt64] = [
            0x7c30_a004_39f1_37e0,
            0x6b40_fb5c_d815_db00,
            0x49a9_4401_d272_97d7,
            0x2e34_8ea7_fdf3_f0de,
            0xfabf_bf7c_7865_7f74,
            0xffbb_e269_c311_4fc9,
        ]
        var bytes = Data()
        for var word in words {
            word = word.littleEndian
            bytes.append(Data(bytes: &word, count: MemoryLayout<UInt64>.size))
        }
        return bytes
    }()
    private static let maximumFieldBytes = PrivacyExact12CapabilityManifestV1.maximumArchiveBytes
    private static let maximumEvidenceBytes = PrivacyExact12CapabilityManifestV1.maximumArchiveBytes
    private static let maximumActionBytes = 9 * 1024 * 1024

    static func decode(
        _ archive: Data,
        nativeCatalogArchive: Data
    ) throws -> PrivacyExact12CapabilityManifestV1 {
        let localProfiles = try decodeCatalog(nativeCatalogArchive)
        let frame = try strictFrame(
            archive,
            schema: manifestSchema,
            alignment: 8,
            maximum: PrivacyExact12CapabilityManifestV1.maximumArchiveBytes,
            label: "manifest"
        )
        var reader = WireReader(frame.payload)
        let versionField = try reader.readField(maximum: 4, label: "version")
        let heightField = try reader.readField(maximum: 8, label: "committed height")
        let policyField = try reader.readField(maximum: maximumFieldBytes, label: "consensus policy")
        let qualificationField = try reader.readField(
            maximum: maximumEvidenceBytes,
            label: "qualification"
        )
        let protocolsField = try reader.readField(maximum: maximumFieldBytes, label: "protocols")
        let digestField = try reader.readField(maximum: 33, label: "manifest digest")
        try reader.requireFinished("manifest")

        let version = try exactUInt32(versionField, "version")
        guard version == PrivacyExact12CapabilityManifestV1.versionV1 else {
            throw invalid("version must be exactly 1")
        }
        let committedHeight = try exactUInt64(heightField, "committed height")
        let policy = try decodeConsensusPolicy(policyField, committedHeight: committedHeight)
        let qualification = try decodeOption(
            qualificationField,
            label: "qualification",
            maximum: maximumEvidenceBytes
        ).map { try decodeQualification($0) }
        let digest = try fixed32(digestField, label: "manifest digest", nonzero: true)

        var rowsReader = WireReader(protocolsField)
        guard try rowsReader.readUInt64("protocol count") == 12 else {
            throw invalid("protocols must contain exactly 12 rows")
        }
        var rows: [PrivacyExact12CapabilityRowV1] = []
        rows.reserveCapacity(12)
        for (index, protocolId) in PrivacyProtocolIdV1.allCases.enumerated() {
            let rowBytes = try rowsReader.readField(
                maximum: maximumFieldBytes,
                label: "protocol row \(index)"
            )
            rows.append(
                try decodeRow(
                    rowBytes,
                    expected: protocolId,
                    committedHeight: committedHeight,
                    qualification: qualification,
                    localCompiledProfile: localProfiles[index]
                )
            )
        }
        try rowsReader.requireFinished("protocols")

        var normalizedPayload = Data()
        for field in [versionField, heightField, policyField, qualificationField, protocolsField] {
            appendField(field, to: &normalizedPayload)
        }
        appendField(array32(Data(repeating: 0, count: 32)), to: &normalizedPayload)
        let normalized = noritoEncode(
            typeName: manifestSchema,
            payload: normalizedPayload,
            flags: NoritoHeader.compactLen,
            payloadAlignment: 8
        )
        var digestPreimage = manifestDigestDomain
        appendUInt64(UInt64(normalized.count), to: &digestPreimage)
        digestPreimage.append(normalized)
        let computed = Data(SHA256.hash(data: digestPreimage))
        guard computed == digest else {
            throw invalid("manifest digest does not bind the canonical archive")
        }

        return PrivacyExact12CapabilityManifestV1(
            version: version,
            committedHeight: committedHeight,
            consensusPolicy: policy,
            qualification: qualification,
            protocols: rows,
            manifestDigest: digest,
            canonicalArchive: archive
        )
    }

    private static func decodeCatalog(_ archive: Data) throws -> [Data] {
        let frame = try strictFrame(
            archive,
            schema: catalogSchema,
            alignment: 8,
            maximum: PrivacyNativeBridge.compiledProfileCatalogArchiveMaximumBytes,
            label: "native compiled-profile catalog"
        )
        var reader = WireReader(frame.payload)
        guard try exactUInt32(
            try reader.readField(maximum: 4, label: "catalog version"),
            "catalog version"
        ) == 1 else {
            throw invalid("native compiled-profile catalog version must be 1")
        }
        let rowsField = try reader.readField(maximum: maximumFieldBytes, label: "catalog rows")
        try reader.requireFinished("native compiled-profile catalog")
        var rowsReader = WireReader(rowsField)
        guard try rowsReader.readUInt64("catalog row count") == 12 else {
            throw invalid("native compiled-profile catalog must contain 12 rows")
        }
        var profiles: [Data] = []
        for (index, protocolId) in PrivacyProtocolIdV1.allCases.enumerated() {
            var row = WireReader(
                try rowsReader.readField(maximum: maximumFieldBytes, label: "catalog row \(index)")
            )
            guard try decodeProtocol(
                row.readField(maximum: 4, label: "catalog protocol"),
                label: "catalog protocol"
            ) == protocolId else {
                throw invalid("native compiled-profile catalog order drifted")
            }
            let compiled = try row.readField(maximum: maximumFieldBytes, label: "catalog profile")
            try row.requireFinished("catalog row \(index)")
            _ = try decodeCompiledProfile(compiled, expected: protocolId)
            profiles.append(compiled)
        }
        try rowsReader.requireFinished("native compiled-profile catalog rows")
        return profiles
    }

    private static func decodeRow(
        _ bytes: Data,
        expected protocolId: PrivacyProtocolIdV1,
        committedHeight: UInt64,
        qualification: PrivacyExact12QualificationRecordV1?,
        localCompiledProfile: Data
    ) throws -> PrivacyExact12CapabilityRowV1 {
        var row = WireReader(bytes)
        guard try decodeProtocol(row.readField(maximum: 4, label: "protocol id"), label: "protocol id")
            == protocolId else {
            throw invalid("protocol rows are missing, duplicated, or reordered")
        }
        let operation = try unitEnum(
            row.readField(maximum: 4, label: "operation schema"),
            as: PrivacyOperationSchemaV1.self,
            label: "operation schema"
        )
        guard operation == protocolId.expectedOperationSchemaV1 else {
            throw invalid("operation schema differs from the closed protocol mapping")
        }
        let execution = try unitEnum(
            row.readField(maximum: 4, label: "execution mode"),
            as: PrivacyExecutionModeV1.self,
            label: "execution mode"
        )
        guard execution == protocolId.expectedExecutionModeV1 else {
            throw invalid("execution mode differs from the closed protocol mapping")
        }
        let maskField = try row.readField(maximum: 2, label: "privacy feature mask")
        let mask = try byteNewtype(maskField, label: "privacy feature mask")
        guard mask == protocolId.expectedPrivacyFeatureMaskV1 else {
            throw invalid("privacy feature mask differs from the closed protocol mapping")
        }
        let compiledBytes = try row.readField(maximum: maximumFieldBytes, label: "compiled profile")
        let compiled = try decodeCompiledProfile(compiledBytes, expected: protocolId)
        guard compiledBytes == localCompiledProfile else {
            throw PrivacyExact12CapabilityManifestErrorV1.compiledTupleMismatch(protocolId)
        }
        let readiness = try decodeReadiness(
            row.readField(maximum: maximumFieldBytes, label: "readiness")
        )
        let activationBytes = try decodeOption(
            row.readField(maximum: maximumFieldBytes, label: "activation"),
            label: "activation"
        )
        let activation = try activationBytes.map {
            try decodeActivation(
                $0,
                expected: protocolId,
                committedHeight: committedHeight,
                compiled: compiled
            )
        }
        try row.requireFinished("capability row")

        let expectedReadiness: PrivacyCapabilityReadinessV1
        switch compiled {
        case let .unavailable(reason):
            expectedReadiness = .unavailable(.compiledProfile(reason))
            guard activation == nil else {
                throw invalid("an unavailable compiled profile cannot carry activation")
            }
        case .available where activation == nil:
            expectedReadiness = .unavailable(.notRegistered)
        case .available:
            guard let activation else {
                preconditionFailure("the nil activation case was handled above")
            }
            switch activation.lifecycle {
            case .proposed:
                expectedReadiness = .unavailable(.proposed)
            case .suspended:
                expectedReadiness = .unavailable(.suspended)
            case .retired:
                expectedReadiness = .unavailable(.retired)
            case .active:
                if qualification == nil {
                    expectedReadiness = .unavailable(.missingProductionQualification)
                } else if qualificationMatches(
                    qualification,
                    protocolId: protocolId,
                    compiled: compiled,
                    activation: activation,
                    committedHeight: committedHeight
                ) {
                    expectedReadiness = .productionQualified
                } else {
                    expectedReadiness = .unavailable(.invalidProductionQualification)
                }
            }
        }
        guard readiness == expectedReadiness else {
            throw invalid("readiness was not derived from compiled, lifecycle, and qualification evidence")
        }

        return PrivacyExact12CapabilityRowV1(
            protocolId: protocolId,
            operationSchema: operation,
            executionMode: execution,
            privacyFeatureMask: protocolId.expectedPrivacyFeatureMaskV1,
            compiledProfile: compiled,
            readiness: readiness,
            activation: activation,
            localCompiledTupleMatches: true,
            compiledProfileCanonicalNorito: compiledBytes
        )
    }

    private static func decodeCompiledProfile(
        _ bytes: Data,
        expected protocolId: PrivacyProtocolIdV1
    ) throws -> PrivacyCompiledProfileResultV1 {
        let tagged = try taggedPayload(bytes, label: "compiled profile")
        switch tagged.tag {
        case 0:
            guard let payload = tagged.payload else {
                throw invalid("available compiled profile has no tuple")
            }
            return .available(try decodeProfile(payload, expected: protocolId))
        case 1:
            guard let payload = tagged.payload else {
                throw invalid("unavailable compiled profile has no typed reason")
            }
            return .unavailable(try decodeUnavailableReason(payload))
        default:
            throw invalid("compiled profile has an unknown result discriminant")
        }
    }

    private static func decodeProfile(
        _ bytes: Data,
        expected protocolId: PrivacyProtocolIdV1
    ) throws -> PrivacyCompiledProfileSnapshotV1 {
        var profile = WireReader(bytes)
        guard try decodeProtocol(profile.readField(maximum: 4, label: "profile protocol"), label: "profile protocol")
            == protocolId else {
            throw invalid("compiled profile protocol differs from its row")
        }
        guard let proof = PrivacyProofSystemIdV1(rawValue: try exactUInt32(
            profile.readField(maximum: 4, label: "proof system"), "proof system"
        )), proof == protocolId.expectedProofSystem else {
            throw invalid("compiled proof system differs from the closed protocol mapping")
        }
        guard let engine = PrivacyEngineIdV1(rawValue: try exactUInt32(
            profile.readField(maximum: 4, label: "engine"), "engine"
        )), engine == protocolId.expectedEngine else {
            throw invalid("compiled engine differs from the closed protocol mapping")
        }
        let parameterId = try fixed32(
            profile.readField(maximum: 33, label: "parameter id"),
            label: "parameter id", nonzero: true
        )
        let parameterDigest = try fixed32(
            profile.readField(maximum: 33, label: "parameter digest"),
            label: "parameter digest", nonzero: true
        )
        let verifierDigest = try fixed32(
            profile.readField(maximum: 33, label: "verifier digest"),
            label: "verifier digest", nonzero: true
        )
        let statementSchemaDigest = try fixed32(
            profile.readField(maximum: 33, label: "statement schema digest"),
            label: "statement schema digest", nonzero: true
        )
        let engineManifestDigest = try fixed32(
            profile.readField(maximum: 33, label: "engine manifest digest"),
            label: "engine manifest digest", nonzero: true
        )
        let limits = try decodeProtocolLimits(
            profile.readField(maximum: 64, label: "compiled protocol limits"),
            expected: protocolId
        )
        try profile.requireFinished("compiled profile")
        return PrivacyCompiledProfileSnapshotV1(
            protocolId: protocolId,
            proofSystemId: proof,
            engineId: engine,
            parameterId: parameterId,
            parameterDigest: parameterDigest,
            verifierDigest: verifierDigest,
            statementSchemaDigest: statementSchemaDigest,
            engineManifestDigest: engineManifestDigest,
            protocolLimits: limits
        )
    }

    private static func decodeUnavailableReason(
        _ bytes: Data
    ) throws -> PrivacyCompiledProfileUnavailableReasonV1 {
        let tagged = try taggedPayload(bytes, label: "unavailable reason")
        switch tagged.tag {
        case 0 where tagged.payload == nil: return .engineUnavailable
        case 1 where tagged.payload == nil: return .profileInitializationFailed
        case 2:
            guard let payload = tagged.payload,
                  payload.count == 4,
                  let tag = payload.readUInt32LE(at: 0), tag < 2 else {
                throw invalid("statement-schema failure is malformed")
            }
            return .statementSchemaInvalid(conflictingStableTypeId: tag == 0)
        default:
            throw invalid("compiled profile has an unknown unavailable reason")
        }
    }

    private static func decodeReadiness(_ bytes: Data) throws -> PrivacyCapabilityReadinessV1 {
        let tagged = try taggedPayload(bytes, label: "readiness")
        switch tagged.tag {
        case 0 where tagged.payload == nil:
            return .productionQualified
        case 1:
            guard let payload = tagged.payload else {
                throw invalid("unavailable readiness has no typed reason")
            }
            return .unavailable(try decodeCapabilityUnavailableReason(payload))
        default:
            throw invalid("readiness has an unknown discriminant")
        }
    }

    private static func decodeCapabilityUnavailableReason(
        _ bytes: Data
    ) throws -> PrivacyCapabilityUnavailableReasonV1 {
        let tagged = try taggedPayload(bytes, label: "capability unavailable reason")
        switch tagged.tag {
        case 0:
            guard let payload = tagged.payload else {
                throw invalid("compiled-profile readiness reason has no typed detail")
            }
            return .compiledProfile(try decodeUnavailableReason(payload))
        case 1 where tagged.payload == nil:
            return .notRegistered
        case 2 where tagged.payload == nil:
            return .proposed
        case 3 where tagged.payload == nil:
            return .suspended
        case 4 where tagged.payload == nil:
            return .retired
        case 5 where tagged.payload == nil:
            return .missingProductionQualification
        case 6 where tagged.payload == nil:
            return .invalidProductionQualification
        default:
            throw invalid("readiness has an unknown unavailable reason")
        }
    }

    private static func decodeConsensusPolicy(
        _ bytes: Data,
        committedHeight: UInt64
    ) throws -> PrivacyConsensusPolicyV1 {
        var policy = WireReader(bytes)
        let current = try decodeConsensusLimits(
            policy.readField(maximum: 64, label: "current consensus limits")
        )
        let pendingBytes = try decodeOption(
            policy.readField(maximum: 128, label: "pending consensus tightening"),
            label: "pending consensus tightening"
        )
        try policy.requireFinished("consensus policy")
        let pending = try pendingBytes.map { value -> PrivacyConsensusPolicyTighteningV1 in
            var tightening = WireReader(value)
            let scheduled = try exactUInt64(
                tightening.readField(maximum: 8, label: "scheduled height"), "scheduled height"
            )
            let effective = try exactUInt64(
                tightening.readField(maximum: 8, label: "effective height"), "effective height"
            )
            let next = try decodeConsensusLimits(
                tightening.readField(maximum: 64, label: "next consensus limits")
            )
            try tightening.requireFinished("pending consensus tightening")
            try validateSchedule(scheduled, effective, committedHeight: committedHeight)
            try requireStrictTightening(current.orderedValues, next.orderedValues, label: "consensus")
            return PrivacyConsensusPolicyTighteningV1(
                scheduledAtHeight: scheduled,
                effectiveAtHeight: effective,
                nextLimits: next
            )
        }
        return PrivacyConsensusPolicyV1(
            currentLimits: current,
            pendingTightening: pending,
            canonicalNorito: bytes
        )
    }

    private static func decodeConsensusLimits(_ bytes: Data) throws -> PrivacyConsensusLimitsV1 {
        var reader = WireReader(bytes)
        var values: [UInt32] = []
        for index in 0..<10 {
            values.append(try exactUInt32(
                reader.readField(maximum: 4, label: "consensus limit \(index)"),
                "consensus limit \(index)"
            ))
        }
        try reader.requireFinished("consensus limits")
        let maxima: [UInt32] = [
            1, 2, 9 * 1024 * 1024, 9 * 1024 * 1024,
            9 * 1024 * 1024, 18 * 1024 * 1024, 256 * 1024, 8, 8, 2048,
        ]
        for index in values.indices where values[index] == 0 || values[index] > maxima[index] {
            throw invalid("consensus limit \(index) is zero or exceeds its V1 hard ceiling")
        }
        guard values[0] <= values[1], values[2] <= values[3],
              values[3] <= values[4], values[4] <= values[5], values[6] <= values[3] else {
            throw invalid("consensus limits violate containing-scope ordering")
        }
        return PrivacyConsensusLimitsV1(
            maxActionsPerTransaction: values[0], maxActionsPerBlock: values[1],
            maxProofBytesPerAction: values[2], maxActionBytes: values[3],
            maxPrivacyBytesPerTransaction: values[4], maxPrivacyBytesPerBlock: values[5],
            maxStatementAndEncryptedOutputBytesPerTransaction: values[6],
            maxNullifiersPerAction: values[7], maxCommitmentsPerAction: values[8],
            retainedRootCount: values[9]
        )
    }

    private static func decodeActivation(
        _ bytes: Data,
        expected protocolId: PrivacyProtocolIdV1,
        committedHeight: UInt64,
        compiled: PrivacyCompiledProfileResultV1
    ) throws -> PrivacyProtocolActivationRecordV1 {
        guard case let .available(profile) = compiled else {
            throw invalid("unavailable compiled profile cannot have activation")
        }
        var record = WireReader(bytes)
        guard try decodeProtocol(record.readField(maximum: 4, label: "activation protocol"), label: "activation protocol")
            == protocolId else {
            throw invalid("activation protocol differs from its row")
        }
        guard let proof = PrivacyProofSystemIdV1(rawValue: try exactUInt32(
            record.readField(maximum: 4, label: "activation proof system"),
            "activation proof system"
        )), proof == profile.proofSystemId else {
            throw invalid("activation proof system differs from the compiled tuple")
        }
        guard let engine = PrivacyEngineIdV1(rawValue: try exactUInt32(
            record.readField(maximum: 4, label: "activation engine"), "activation engine"
        )), engine == profile.engineId else {
            throw invalid("activation engine differs from the compiled tuple")
        }
        let bindingLabels = [
            "parameter id", "parameter digest", "verifier digest",
            "statement schema digest", "engine manifest digest",
        ]
        let expectedBindings = [
            profile.parameterId, profile.parameterDigest, profile.verifierDigest,
            profile.statementSchemaDigest, profile.engineManifestDigest,
        ]
        var bindings: [Data] = []
        for (index, label) in bindingLabels.enumerated() {
            let binding = try fixed32(
                record.readField(maximum: 33, label: "activation \(label)"),
                label: "activation \(label)", nonzero: true
            )
            guard binding == expectedBindings[index] else {
                throw invalid("activation \(label) differs from the compiled tuple")
            }
            bindings.append(binding)
        }
        let lifecycle = try decodeLifecycle(
            record.readField(maximum: 64, label: "lifecycle"),
            committedHeight: committedHeight
        )
        let limits = try decodeProtocolLimits(
            record.readField(maximum: 64, label: "activation protocol limits"),
            expected: protocolId
        )
        try requireAtMost(limits.values, profile.protocolLimits.values, label: "activation limits")
        let pendingBytes = try decodeOption(
            record.readField(maximum: 128, label: "pending protocol limits"),
            label: "pending protocol limits"
        )
        let pending = try pendingBytes.map { value -> PrivacyProtocolLimitsTighteningV1 in
            var tightening = WireReader(value)
            let scheduled = try exactUInt64(
                tightening.readField(maximum: 8, label: "protocol scheduled height"),
                "protocol scheduled height"
            )
            let effective = try exactUInt64(
                tightening.readField(maximum: 8, label: "protocol effective height"),
                "protocol effective height"
            )
            let next = try decodeProtocolLimits(
                tightening.readField(maximum: 64, label: "next protocol limits"),
                expected: protocolId
            )
            try tightening.requireFinished("pending protocol limits")
            try validateSchedule(scheduled, effective, committedHeight: committedHeight)
            try requireStrictTightening(limits.values, next.values, label: "protocol")
            return PrivacyProtocolLimitsTighteningV1(
                scheduledAtHeight: scheduled,
                effectiveAtHeight: effective,
                nextLimits: next
            )
        }
        try record.requireFinished("activation record")
        return PrivacyProtocolActivationRecordV1(
            protocolId: protocolId, proofSystemId: proof, engineId: engine,
            parameterId: bindings[0], parameterDigest: bindings[1],
            verifierDigest: bindings[2], statementSchemaDigest: bindings[3],
            engineManifestDigest: bindings[4], lifecycle: lifecycle,
            protocolLimits: limits, pendingProtocolLimitsTightening: pending,
            canonicalNorito: bytes
        )
    }

    private static func decodeQualification(
        _ bytes: Data
    ) throws -> PrivacyExact12QualificationRecordV1 {
        var record = WireReader(bytes)
        let releaseBytes = try record.readField(
            maximum: maximumEvidenceBytes,
            label: "qualification release manifest"
        )
        let deploymentBytes = try record.readField(
            maximum: maximumEvidenceBytes,
            label: "qualification deployment"
        )
        try record.requireFinished("qualification")
        let release = try decodeReleaseManifest(releaseBytes)
        let deployment = try decodeDeploymentQualification(deploymentBytes)
        guard release.manifestDigest == deployment.releaseManifestDigest else {
            throw invalid("deployment qualification names a different release manifest")
        }
        return PrivacyExact12QualificationRecordV1(
            releaseManifest: release,
            deploymentQualification: deployment,
            canonicalNorito: bytes
        )
    }

    private static func decodeReleaseManifest(
        _ bytes: Data
    ) throws -> PrivacyExact12ReleaseManifestV1 {
        var release = WireReader(bytes)
        let version = try exactUInt16(
            release.readField(maximum: 2, label: "release version"),
            "release version"
        )
        guard version == 1 else { throw invalid("release version must be exactly 1") }
        let catalogId = try exactString(
            release.readField(maximum: 64, label: "release catalog id"),
            label: "release catalog id"
        )
        guard catalogId == "iroha-privacy-exact12-v1" else {
            throw invalid("release uses an unknown catalog id")
        }
        let catalogCommitment = try release.readField(
            maximum: 48,
            label: "release catalog commitment"
        )
        guard catalogCommitment == exact12CatalogCommitment else {
            throw invalid("release uses an unknown catalog commitment")
        }
        _ = try release.readField(maximum: maximumFieldBytes, label: "release source")
        let abiVersion = try exactUInt16(
            release.readField(maximum: 2, label: "release ABI version"),
            "release ABI version"
        )
        guard abiVersion == 1 else { throw invalid("release ABI version must be exactly 1") }
        _ = try fixed32(
            release.readField(maximum: 33, label: "release ABI hash"),
            label: "release ABI hash",
            nonzero: true
        )
        _ = try fixed32(
            release.readField(maximum: 33, label: "release syscall digest"),
            label: "release syscall digest",
            nonzero: true
        )
        _ = try release.readField(maximum: maximumFieldBytes, label: "release executables")
        let protocolsBytes = try release.readField(
            maximum: maximumFieldBytes,
            label: "release protocol bindings"
        )
        _ = try release.readField(maximum: maximumFieldBytes, label: "release stage receipts")
        _ = try release.readField(maximum: maximumFieldBytes, label: "release proof artifacts")
        _ = try release.readField(maximum: maximumFieldBytes, label: "release SDK packages")
        _ = try release.readField(maximum: maximumFieldBytes, label: "release hardware results")
        _ = try fixed32(
            release.readField(maximum: 33, label: "release artifact-set digest"),
            label: "release artifact-set digest",
            nonzero: true
        )
        _ = try release.readField(maximum: maximumFieldBytes, label: "release audits")
        let auditBundleDigest = try fixed32(
            release.readField(maximum: 33, label: "release audit-bundle digest"),
            label: "release audit-bundle digest",
            nonzero: true
        )
        _ = try release.readField(maximum: maximumFieldBytes, label: "release signatures")
        let manifestDigest = try fixed32(
            release.readField(maximum: 33, label: "release manifest digest"),
            label: "release manifest digest",
            nonzero: true
        )
        try release.requireFinished("release manifest")

        var protocolsReader = WireReader(protocolsBytes)
        guard try protocolsReader.readUInt64("release protocol count") == 12 else {
            throw invalid("release must bind exactly 12 protocols")
        }
        var protocols: [PrivacyReleaseProtocolBindingV1] = []
        protocols.reserveCapacity(12)
        for (index, protocolId) in PrivacyProtocolIdV1.allCases.enumerated() {
            let binding = try decodeReleaseBinding(
                protocolsReader.readField(
                    maximum: maximumFieldBytes,
                    label: "release protocol binding \(index)"
                ),
                expected: protocolId
            )
            guard binding.securityClaim.catalogCommitment == catalogCommitment,
                  binding.securityClaim.auditBundleDigest == auditBundleDigest else {
                throw invalid("release security claim differs from global release evidence")
            }
            protocols.append(binding)
        }
        try protocolsReader.requireFinished("release protocol bindings")
        return PrivacyExact12ReleaseManifestV1(
            version: version,
            catalogCommitment: catalogCommitment,
            abiVersion: abiVersion,
            protocols: protocols,
            auditBundleDigest: auditBundleDigest,
            manifestDigest: manifestDigest,
            canonicalNorito: bytes
        )
    }

    private static func decodeReleaseBinding(
        _ bytes: Data,
        expected protocolId: PrivacyProtocolIdV1
    ) throws -> PrivacyReleaseProtocolBindingV1 {
        var binding = WireReader(bytes)
        guard try decodeProtocol(
            binding.readField(maximum: 4, label: "release protocol"),
            label: "release protocol"
        ) == protocolId else {
            throw invalid("release protocol bindings are reordered or substituted")
        }
        guard let proofSystemId = PrivacyProofSystemIdV1(rawValue: try exactUInt32(
            binding.readField(maximum: 4, label: "release proof system"),
            "release proof system"
        )), proofSystemId == protocolId.expectedProofSystem else {
            throw invalid("release proof system differs from the final Exact12 tuple")
        }
        guard let engineId = PrivacyEngineIdV1(rawValue: try exactUInt32(
            binding.readField(maximum: 4, label: "release engine"),
            "release engine"
        )), engineId == protocolId.expectedEngine else {
            throw invalid("release engine differs from the final Exact12 tuple")
        }
        let parameterId = try fixed32(
            binding.readField(maximum: 33, label: "release parameter id"),
            label: "release parameter id",
            nonzero: true
        )
        let parameterDigest = try fixed32(
            binding.readField(maximum: 33, label: "release parameter digest"),
            label: "release parameter digest",
            nonzero: true
        )
        let verifierDigest = try fixed32(
            binding.readField(maximum: 33, label: "release verifier digest"),
            label: "release verifier digest",
            nonzero: true
        )
        let statementSchemaDigest = try fixed32(
            binding.readField(maximum: 33, label: "release statement-schema digest"),
            label: "release statement-schema digest",
            nonzero: true
        )
        let engineManifestDigest = try fixed32(
            binding.readField(maximum: 33, label: "release engine-manifest digest"),
            label: "release engine-manifest digest",
            nonzero: true
        )
        let claimBytes = try binding.readField(
            maximum: maximumFieldBytes,
            label: "release security claim"
        )
        let claim = try decodeSecurityClaim(
            claimBytes,
            expected: protocolId,
            parameterDigest: parameterDigest,
            verifierDigest: verifierDigest
        )
        let securityClaimDigest = try fixed32(
            binding.readField(maximum: 33, label: "release security-claim digest"),
            label: "release security-claim digest",
            nonzero: true
        )
        try binding.requireFinished("release protocol binding")
        let canonicalClaim = noritoEncode(
            typeName: securityClaimSchema,
            payload: claimBytes,
            flags: NoritoHeader.compactLen,
            payloadAlignment: 2
        )
        var digestPreimage = securityClaimDigestDomain
        appendUInt64(UInt64(canonicalClaim.count), to: &digestPreimage)
        digestPreimage.append(canonicalClaim)
        guard securityClaimDigest == Data(SHA256.hash(data: digestPreimage)) else {
            throw invalid("release security-claim digest does not bind its canonical claim")
        }
        return PrivacyReleaseProtocolBindingV1(
            protocolId: protocolId,
            proofSystemId: proofSystemId,
            engineId: engineId,
            parameterId: parameterId,
            parameterDigest: parameterDigest,
            verifierDigest: verifierDigest,
            statementSchemaDigest: statementSchemaDigest,
            engineManifestDigest: engineManifestDigest,
            securityClaim: claim,
            securityClaimDigest: securityClaimDigest,
            canonicalNorito: bytes
        )
    }

    private static func decodeDeploymentQualification(
        _ bytes: Data
    ) throws -> PrivacyExact12DeploymentQualificationV1 {
        var deployment = WireReader(bytes)
        let version = try exactUInt16(
            deployment.readField(maximum: 2, label: "deployment version"),
            "deployment version"
        )
        guard version == 1 else { throw invalid("deployment version must be exactly 1") }
        _ = try deployment.readField(maximum: maximumFieldBytes, label: "deployment chain id")
        // NetworkId and [u8; 32] each occupy exactly 32 inner field bytes.
        let networkId = try exactNetworkId(
            deployment.readField(maximum: 32, label: "deployment network id"),
            label: "deployment network id"
        )
        let genesisHash = try deployment.readField(maximum: 32, label: "deployment genesis hash")
        guard genesisHash.count == 32, genesisHash == networkId.bytes else {
            throw invalid("deployment genesis hash differs from its exact network id")
        }
        let releaseManifestDigest = try fixed32(
            deployment.readField(maximum: 33, label: "deployed release digest"),
            label: "deployed release digest",
            nonzero: true
        )
        _ = try fixed32(
            deployment.readField(maximum: 33, label: "activation transaction digest"),
            label: "activation transaction digest",
            nonzero: true
        )
        let activationsBytes = try deployment.readField(
            maximum: maximumFieldBytes,
            label: "deployment activations"
        )
        _ = try fixed32(
            deployment.readField(maximum: 33, label: "validator roster digest"),
            label: "validator roster digest",
            nonzero: true
        )
        _ = try deployment.readField(maximum: maximumFieldBytes, label: "endpoint version")
        let convergenceHeight = try exactUInt64(
            deployment.readField(maximum: 8, label: "convergence height"),
            "convergence height"
        )
        guard convergenceHeight > 0 else { throw invalid("convergence height must be nonzero") }
        _ = try fixed32(
            deployment.readField(maximum: 33, label: "converged state digest"),
            label: "converged state digest",
            nonzero: true
        )
        _ = try deployment.readField(maximum: maximumFieldBytes, label: "validator canaries")
        _ = try deployment.readField(maximum: maximumFieldBytes, label: "validator signatures")
        let qualificationDigest = try fixed32(
            deployment.readField(maximum: 33, label: "qualification digest"),
            label: "qualification digest",
            nonzero: true
        )
        try deployment.requireFinished("deployment qualification")

        var activationsReader = WireReader(activationsBytes)
        guard try activationsReader.readUInt64("deployment activation count") == 12 else {
            throw invalid("deployment must bind exactly 12 activation heights")
        }
        var activations: [PrivacyDeploymentActivationV1] = []
        activations.reserveCapacity(12)
        for (index, protocolId) in PrivacyProtocolIdV1.allCases.enumerated() {
            var activation = WireReader(try activationsReader.readField(
                maximum: 32,
                label: "deployment activation \(index)"
            ))
            guard try decodeProtocol(
                activation.readField(maximum: 4, label: "deployment activation protocol"),
                label: "deployment activation protocol"
            ) == protocolId else {
                throw invalid("deployment activations are reordered or substituted")
            }
            let height = try exactUInt64(
                activation.readField(maximum: 8, label: "deployment activation height"),
                "deployment activation height"
            )
            guard height > 0, height < convergenceHeight else {
                throw invalid("deployment activation height must precede convergence")
            }
            try activation.requireFinished("deployment activation")
            activations.append(PrivacyDeploymentActivationV1(
                protocolId: protocolId,
                activationHeight: height
            ))
        }
        try activationsReader.requireFinished("deployment activations")
        return PrivacyExact12DeploymentQualificationV1(
            version: version,
            networkId: networkId,
            genesisHash: genesisHash,
            releaseManifestDigest: releaseManifestDigest,
            activations: activations,
            convergenceHeight: convergenceHeight,
            qualificationDigest: qualificationDigest,
            canonicalNorito: bytes
        )
    }

    private static func qualificationMatches(
        _ qualification: PrivacyExact12QualificationRecordV1?,
        protocolId: PrivacyProtocolIdV1,
        compiled: PrivacyCompiledProfileResultV1,
        activation: PrivacyProtocolActivationRecordV1,
        committedHeight: UInt64
    ) -> Bool {
        guard let qualification,
              qualification.deploymentQualification.convergenceHeight <= committedHeight,
              case let .available(profile) = compiled,
              case let .active(_, activatedAtHeight, _) = activation.lifecycle else {
            return false
        }
        let index = Int(protocolId.noritoDiscriminant)
        let release = qualification.releaseManifest.protocols[index]
        let deployment = qualification.deploymentQualification.activations[index]
        return release.protocolId == protocolId
            && deployment.protocolId == protocolId
            && release.proofSystemId == profile.proofSystemId
            && release.proofSystemId == activation.proofSystemId
            && release.engineId == profile.engineId
            && release.engineId == activation.engineId
            && release.parameterId == profile.parameterId
            && release.parameterId == activation.parameterId
            && release.parameterDigest == profile.parameterDigest
            && release.parameterDigest == activation.parameterDigest
            && release.verifierDigest == profile.verifierDigest
            && release.verifierDigest == activation.verifierDigest
            && release.statementSchemaDigest == profile.statementSchemaDigest
            && release.statementSchemaDigest == activation.statementSchemaDigest
            && release.engineManifestDigest == profile.engineManifestDigest
            && release.engineManifestDigest == activation.engineManifestDigest
            && deployment.activationHeight == activatedAtHeight
    }

    private static func decodeSecurityClaim(
        _ bytes: Data,
        expected protocolId: PrivacyProtocolIdV1,
        parameterDigest: Data,
        verifierDigest: Data
    ) throws -> PrivacySecurityClaimV1 {
        var claim = WireReader(bytes)
        let catalogCommitment = try claim.readField(
            maximum: 48,
            label: "security claim catalog commitment"
        )
        guard catalogCommitment == exact12CatalogCommitment else {
            throw invalid("security claim has an unknown Exact12 catalog commitment")
        }
        guard try decodeProtocol(
            claim.readField(maximum: 4, label: "security claim protocol"),
            label: "security claim protocol"
        ) == protocolId else {
            throw invalid("security claim protocol differs from its activation")
        }
        let securityModel = try unitEnum(
            claim.readField(maximum: 4, label: "security model"),
            as: PrivacySecurityModelV1.self,
            label: "security model"
        )
        guard securityModel == protocolId.expectedSecurityModelV1 else {
            throw invalid("security claim uses the wrong complete-composition model")
        }
        let targetSecurityBits = try exactUInt16(
            claim.readField(maximum: 2, label: "target security bits"),
            "target security bits"
        )
        let achievedSecurityBits = try exactUInt16(
            claim.readField(maximum: 2, label: "achieved security bits"),
            "achieved security bits"
        )
        guard targetSecurityBits == 128,
              achievedSecurityBits >= targetSecurityBits else {
            throw invalid("security claim does not establish the required 128-bit target")
        }
        let claimedParameterDigest = try fixed32(
            claim.readField(maximum: 33, label: "claimed parameter digest"),
            label: "claimed parameter digest",
            nonzero: true
        )
        guard claimedParameterDigest == parameterDigest else {
            throw invalid("security claim parameter digest differs from its activation")
        }
        let claimedVerifierDigest = try fixed32(
            claim.readField(maximum: 33, label: "claimed verifier digest"),
            label: "claimed verifier digest",
            nonzero: true
        )
        guard claimedVerifierDigest == verifierDigest else {
            throw invalid("security claim verifier digest differs from its activation")
        }
        let reductionDigest = try fixed32(
            claim.readField(maximum: 33, label: "security reduction digest"),
            label: "security reduction digest",
            nonzero: true
        )
        let auditBundleDigest = try fixed32(
            claim.readField(maximum: 33, label: "audit bundle digest"),
            label: "audit bundle digest",
            nonzero: true
        )
        try claim.requireFinished("security claim")
        return PrivacySecurityClaimV1(
            catalogCommitment: catalogCommitment,
            protocolId: protocolId,
            securityModel: securityModel,
            targetSecurityBits: targetSecurityBits,
            achievedSecurityBits: achievedSecurityBits,
            parameterDigest: claimedParameterDigest,
            verifierDigest: claimedVerifierDigest,
            reductionDigest: reductionDigest,
            auditBundleDigest: auditBundleDigest,
            canonicalNorito: bytes
        )
    }

    private static func decodeLifecycle(
        _ bytes: Data,
        committedHeight: UInt64
    ) throws -> PrivacyProtocolLifecycleV1 {
        let tagged = try taggedPayload(bytes, label: "lifecycle")
        guard let payload = tagged.payload else { throw invalid("lifecycle record is missing") }
        var state = WireReader(payload)
        let proposed = try exactUInt64(
            state.readField(maximum: 8, label: "proposed height"), "proposed height"
        )
        guard proposed > 0, proposed <= committedHeight else {
            throw invalid("lifecycle proposal height is outside committed state")
        }
        let lifecycle: PrivacyProtocolLifecycleV1
        switch tagged.tag {
        case 0:
            lifecycle = .proposed(proposedAtHeight: proposed)
        case 1, 2:
            let activated = try exactUInt64(
                state.readField(maximum: 8, label: "activated height"), "activated height"
            )
            let since = try exactUInt64(
                state.readField(maximum: 8, label: "state-since height"), "state-since height"
            )
            let validSince = tagged.tag == 1 ? since >= activated : since > activated
            guard activated >= proposed, validSince,
                  activated <= committedHeight, since <= committedHeight else {
                throw invalid("active/suspended lifecycle heights are invalid")
            }
            lifecycle = tagged.tag == 1
                ? .active(proposedAtHeight: proposed, activatedAtHeight: activated,
                          stateSinceHeight: since)
                : .suspended(proposedAtHeight: proposed, activatedAtHeight: activated,
                             stateSinceHeight: since)
        case 3:
            let activated = try decodeOptionUInt64(
                state.readField(maximum: 16, label: "retired activation height"),
                label: "retired activation height"
            )
            let since = try exactUInt64(
                state.readField(maximum: 8, label: "retired state-since height"),
                "retired state-since height"
            )
            if let activated {
                guard activated >= proposed, since > activated else {
                    throw invalid("retired lifecycle activation history is invalid")
                }
            } else if since <= proposed {
                throw invalid("retired lifecycle state height must follow proposal")
            }
            guard activated.map({ $0 <= committedHeight }) ?? true,
                  since <= committedHeight else {
                throw invalid("retired lifecycle claims a future committed height")
            }
            lifecycle = .retired(
                proposedAtHeight: proposed,
                activatedAtHeight: activated,
                stateSinceHeight: since
            )
        default:
            throw invalid("lifecycle has an unknown discriminant")
        }
        try state.requireFinished("lifecycle")
        return lifecycle
    }

    private static func decodeProtocolLimits(
        _ bytes: Data,
        expected protocolId: PrivacyProtocolIdV1
    ) throws -> PrivacyProtocolActivationLimitsV1 {
        let tagged = try taggedPayload(bytes, label: "protocol limits")
        guard tagged.tag == protocolId.noritoDiscriminant else {
            throw invalid("protocol limits use a different protocol variant")
        }
        let expectedValueCount: Int
        switch protocolId {
        case .anonymousPgcKOutOfNV1, .irohaZkAmsV1, .moneroFcmpPlusPlusV1,
             .irohaIvmPrivateNoteStarkV1, .pqMaspStarkV1:
            expectedValueCount = 2
        case .veRangeTransparentRangeV1, .irohaJindoPolynomialCommitmentV1,
             .orchardHalo2ActionsV1:
            expectedValueCount = 1
        default:
            expectedValueCount = 0
        }
        if expectedValueCount == 0 {
            guard tagged.payload == nil else { throw invalid("unit protocol limits carry payload") }
            return PrivacyProtocolActivationLimitsV1(
                protocolId: protocolId,
                values: [],
                canonicalNorito: bytes
            )
        }
        guard let payload = tagged.payload else { throw invalid("protocol limits payload is missing") }
        var reader = WireReader(payload)
        var values: [UInt32] = []
        for index in 0..<expectedValueCount {
            values.append(try exactUInt32(
                reader.readField(maximum: 4, label: "protocol limit \(index)"),
                "protocol limit \(index)"
            ))
        }
        try reader.requireFinished("protocol limits")
        let maxima: [UInt32]
        switch protocolId {
        case .anonymousPgcKOutOfNV1: maxima = [64, 8]
        case .veRangeTransparentRangeV1: maxima = [8]
        case .irohaZkAmsV1: maxima = [8, 64]
        case .irohaJindoPolynomialCommitmentV1: maxima = [4]
        case .orchardHalo2ActionsV1: maxima = [2]
        case .moneroFcmpPlusPlusV1: maxima = [2, 4]
        case .irohaIvmPrivateNoteStarkV1, .pqMaspStarkV1: maxima = [2, 2]
        default: maxima = []
        }
        for index in values.indices where values[index] == 0 || values[index] > maxima[index] {
            throw invalid("protocol limit \(index) is zero or exceeds its V1 hard ceiling")
        }
        if protocolId == .anonymousPgcKOutOfNV1, ![16, 32, 64].contains(values[0]) {
            throw invalid("Anonymous PGC anonymity set must be 16, 32, or 64")
        }
        if protocolId == .irohaZkAmsV1, ![16, 32, 64].contains(values[1]) {
            throw invalid("ZK-AMS ring size must be 16, 32, or 64")
        }
        return PrivacyProtocolActivationLimitsV1(
            protocolId: protocolId,
            values: values,
            canonicalNorito: bytes
        )
    }

    /// Projection check only; this never creates authenticated network authority.
    static func requireDeploymentNetworkV1(
        _ manifest: PrivacyExact12CapabilityManifestV1,
        expectedNetworkId: NetworkId
    ) throws {
        guard let deployment = manifest.qualification?.deploymentQualification,
              deployment.networkId == expectedNetworkId,
              deployment.genesisHash == expectedNetworkId.bytes else {
            throw invalid("deployment qualification differs from the expected signing network")
        }
    }

    static func requireSubmitProofInstruction(
        _ archive: Data,
        row: PrivacyExact12CapabilityRowV1,
        consensusLimits: PrivacyConsensusLimitsV1,
        expectedNetworkId: NetworkId
    ) throws {
        guard archive.count <= Int(consensusLimits.maxActionBytes) else {
            throw invalid("submit-proof instruction exceeds committed consensus action bytes")
        }
        let frame = try strictFrame(
            archive,
            schema: submitProofSchema,
            alignment: 16,
            maximum: maximumActionBytes,
            label: "submit-proof instruction"
        )
        var instruction = WireReader(frame.payload)
        let envelope = try instruction.readField(
            maximum: maximumActionBytes,
            label: "proof envelope"
        )
        try instruction.requireFinished("submit-proof instruction")
        var envelopeReader = WireReader(envelope)
        var fields: [Data] = []
        fields.reserveCapacity(13)
        for index in 0..<13 {
            fields.append(try envelopeReader.readField(
                maximum: maximumActionBytes,
                label: "proof envelope field \(index)"
            ))
        }
        try envelopeReader.requireFinished("proof envelope")

        guard fields[0] == proofWireMagic, fields[1] == exact12CatalogCommitment else {
            throw invalid("submit-proof envelope differs from the final V1 wire marker or catalog")
        }
        guard try decodeProtocol(fields[2], label: "envelope protocol") == row.protocolId else {
            throw invalid("submit-proof instruction protocol differs from its admission")
        }
        guard case let .available(profile) = row.compiledProfile,
              try exactUInt32(fields[3], "envelope proof system") == profile.proofSystemId.rawValue,
              try exactUInt32(fields[4], "envelope engine") == profile.engineId.rawValue,
              try fixed32(fields[5], label: "envelope parameter id", nonzero: true)
                == profile.parameterId,
              try fixed32(fields[6], label: "envelope parameter digest", nonzero: true)
                == profile.parameterDigest,
              try fixed32(fields[7], label: "envelope verifier digest", nonzero: true)
                == profile.verifierDigest,
              try fixed32(fields[8], label: "envelope statement schema digest", nonzero: true)
                == profile.statementSchemaDigest,
              try fixed32(fields[9], label: "envelope engine manifest digest", nonzero: true)
                == profile.engineManifestDigest else {
            throw invalid("submit-proof envelope differs from the admitted compiled profile tuple")
        }
        _ = try fixed32(fields[10], label: "envelope statement digest", nonzero: true)
        try requireStatementNetworkV1(
            fields[11], protocolId: row.protocolId, expectedNetworkId: expectedNetworkId
        )
        for (index, label) in [(11, "statement"), (12, "proof")] {
            let tagged = try taggedPayload(fields[index], label: "envelope \(label)")
            guard tagged.tag == row.protocolId.noritoDiscriminant,
                  let payload = tagged.payload, !payload.isEmpty else {
                throw invalid("submit-proof envelope \(label) differs from its admitted protocol")
            }
        }
    }

    /// Every retained statement begins with PrivacyStatementContextV1. This
    /// exact projection binds its network; native validation owns proof semantics.
    static func requireStatementNetworkV1(
        _ bytes: Data,
        protocolId: PrivacyProtocolIdV1,
        expectedNetworkId: NetworkId
    ) throws {
        let tagged = try taggedPayload(bytes, label: "envelope statement")
        guard tagged.tag == protocolId.noritoDiscriminant, let payload = tagged.payload else {
            throw invalid("submit-proof envelope statement differs from its admitted protocol")
        }
        var statement = WireReader(payload)
        var context = WireReader(try statement.readField(
            maximum: maximumActionBytes, label: "statement context"
        ))
        let networkId = try exactNetworkId(
            context.readField(maximum: 32, label: "statement network id"),
            label: "statement network id"
        )
        guard networkId == expectedNetworkId else {
            throw invalid("statement context differs from the expected signing network")
        }
        _ = try exactUInt32(
            context.readField(maximum: 4, label: "statement action index"),
            "statement action index"
        )
        for label in [
            "transaction intent digest", "parameter id", "parameter digest",
            "verifier digest", "statement schema digest", "engine manifest digest",
        ] {
            _ = try fixed32(
                context.readField(maximum: 33, label: "statement \(label)"),
                label: "statement \(label)", nonzero: true
            )
        }
        try context.requireFinished("statement context")
    }

    private static func exactNetworkId(_ bytes: Data, label: String) throws -> NetworkId {
        guard let networkId = try? NetworkId(bytes: bytes) else {
            throw invalid("\(label) must contain exactly 32 canonical network-id bytes")
        }
        return networkId
    }

    private static func validateSchedule(
        _ scheduled: UInt64,
        _ effective: UInt64,
        committedHeight: UInt64
    ) throws {
        guard scheduled > 0, effective > scheduled,
              scheduled <= committedHeight, effective > committedHeight else {
            throw invalid("pending tightening violates future or committed-height bounds")
        }
    }

    private static func requireAtMost(
        _ values: [UInt32],
        _ ceilings: [UInt32],
        label: String
    ) throws {
        guard values.count == ceilings.count,
              zip(values, ceilings).allSatisfy({ $0.0 <= $0.1 }) else {
            throw invalid("\(label) exceeds its compiled ceiling")
        }
    }

    private static func requireStrictTightening(
        _ current: [UInt32],
        _ next: [UInt32],
        label: String
    ) throws {
        try requireAtMost(next, current, label: "\(label) tightening")
        guard next != current else { throw invalid("\(label) tightening is a no-op") }
    }

    private static func strictFrame(
        _ archive: Data,
        schema: String,
        alignment: Int,
        maximum: Int,
        label: String
    ) throws -> NoritoFrame {
        guard !archive.isEmpty, archive.count <= maximum,
              let frame = noritoDecodeFrame(archive),
              frame.header.compression == .none,
              frame.header.flags == NoritoHeader.compactLen,
              frame.header.schema == noritoSchemaHash(forTypeName: schema),
              frame.paddingLength == noritoHeaderPaddingLength(payloadAlignment: alignment),
              archive.prefix(NoritoHeader.encodedLength) == frame.header.encode(),
              noritoEncode(
                  typeName: schema,
                  payload: frame.payload,
                  flags: NoritoHeader.compactLen,
                  payloadAlignment: alignment
              ) == archive else {
            throw invalid("\(label) is not the exact canonical uncompressed Norito type")
        }
        return frame
    }

    private static func decodeProtocol(_ bytes: Data, label: String) throws -> PrivacyProtocolIdV1 {
        let tag = try exactUInt32(bytes, label)
        do { return try PrivacyProtocolIdV1(noritoDiscriminant: tag) }
        catch { throw invalid("\(label) has an unknown discriminant") }
    }

    private static func unitEnum<T: RawRepresentable>(
        _ bytes: Data,
        as type: T.Type,
        label: String
    ) throws -> T where T.RawValue == UInt32 {
        guard let value = T(rawValue: try exactUInt32(bytes, label)) else {
            throw invalid("\(label) has an unknown discriminant")
        }
        return value
    }

    private static func taggedPayload(
        _ bytes: Data,
        label: String
    ) throws -> (tag: UInt32, payload: Data?) {
        guard bytes.count >= 4, let tag = bytes.readUInt32LE(at: 0) else {
            throw invalid("\(label) is truncated")
        }
        if bytes.count == 4 { return (tag, nil) }
        var reader = WireReader(Data(bytes.dropFirst(4)))
        let payload = try reader.readField(maximum: maximumFieldBytes, label: "\(label) payload")
        try reader.requireFinished(label)
        return (tag, payload)
    }

    private static func decodeOption(
        _ bytes: Data,
        label: String,
        maximum: Int = maximumFieldBytes
    ) throws -> Data? {
        var reader = WireReader(bytes)
        switch try reader.readUInt8("\(label) tag") {
        case 0:
            try reader.requireFinished(label)
            return nil
        case 1:
            let value = try reader.readField(maximum: maximum, label: "\(label) value")
            try reader.requireFinished(label)
            return value
        default:
            throw invalid("\(label) has an invalid option tag")
        }
    }

    private static func decodeOptionUInt64(_ bytes: Data, label: String) throws -> UInt64? {
        try decodeOption(bytes, label: label).map { try exactUInt64($0, label) }
    }

    private static func fixed32(
        _ bytes: Data,
        label: String,
        nonzero: Bool
    ) throws -> Data {
        var reader = WireReader(bytes)
        guard try reader.readCompactLength("\(label) width") == 32 else {
            throw invalid("\(label) must declare exactly 32 bytes")
        }
        let value = try reader.readBytes(32, label: label)
        try reader.requireFinished(label)
        guard !nonzero || value.contains(where: { $0 != 0 }) else {
            throw invalid("\(label) must be nonzero")
        }
        return value
    }

    private static func exactString(_ bytes: Data, label: String) throws -> String {
        var reader = WireReader(bytes)
        let length = try reader.readCompactLength("\(label) width")
        guard length <= UInt64(maximumFieldBytes), length <= UInt64(Int.max) else {
            throw invalid("\(label) exceeds its byte ceiling")
        }
        let value = try reader.readBytes(Int(length), label: label)
        try reader.requireFinished(label)
        guard let text = String(data: value, encoding: .utf8) else {
            throw invalid("\(label) is not UTF-8")
        }
        return text
    }

    private static func byteNewtype(_ bytes: Data, label: String) throws -> UInt8 {
        var reader = WireReader(bytes)
        let value = try reader.readField(maximum: 1, label: "\(label) value")
        try reader.requireFinished(label)
        guard value.count == 1 else {
            throw invalid("\(label) must contain exactly one byte")
        }
        return value[value.startIndex]
    }

    private static func array32(_ bytes: Data) -> Data {
        precondition(bytes.count == 32)
        var value = Data()
        appendCompactLength(32, to: &value)
        value.append(bytes)
        return value
    }

    private static func exactUInt32(_ bytes: Data, _ label: String) throws -> UInt32 {
        guard bytes.count == 4, let value = bytes.readUInt32LE(at: 0) else {
            throw invalid("\(label) must occupy exactly four bytes")
        }
        return value
    }

    private static func exactUInt16(_ bytes: Data, _ label: String) throws -> UInt16 {
        guard bytes.count == 2 else {
            throw invalid("\(label) must occupy exactly two bytes")
        }
        return UInt16(bytes[bytes.startIndex])
            | UInt16(bytes[bytes.startIndex + 1]) << 8
    }

    private static func exactUInt64(_ bytes: Data, _ label: String) throws -> UInt64 {
        guard bytes.count == 8, let value = bytes.readUInt64LE(at: 0) else {
            throw invalid("\(label) must occupy exactly eight bytes")
        }
        return value
    }

    private static func appendUInt64(_ value: UInt64, to output: inout Data) {
        var little = value.littleEndian
        output.append(Data(bytes: &little, count: 8))
    }

    private static func appendCompactLength(_ value: UInt64, to output: inout Data) {
        var remaining = value
        while remaining >= 0x80 {
            output.append(UInt8(remaining & 0x7f) | 0x80)
            remaining >>= 7
        }
        output.append(UInt8(remaining))
    }

    private static func appendField(_ field: Data, to output: inout Data) {
        appendCompactLength(UInt64(field.count), to: &output)
        output.append(field)
    }

    private static func invalid(_ reason: String) -> PrivacyExact12CapabilityManifestErrorV1 {
        .invalidArchive(reason)
    }

    private struct WireReader {
        private let data: Data
        private var offset = 0

        init(_ data: Data) { self.data = data }

        mutating func readUInt8(_ label: String) throws -> UInt8 {
            guard offset < data.count else { throw invalid("\(label) is truncated") }
            defer { offset += 1 }
            return data[data.startIndex + offset]
        }

        mutating func readUInt64(_ label: String) throws -> UInt64 {
            let bytes = try readBytes(8, label: label)
            guard let value = bytes.readUInt64LE(at: 0) else { throw invalid("\(label) is truncated") }
            return value
        }

        mutating func readCompactLength(_ label: String) throws -> UInt64 {
            var value: UInt64 = 0
            var shift: UInt64 = 0
            for index in 0..<10 {
                let byte = try readUInt8(label)
                let payload = UInt64(byte & 0x7f)
                if shift == 63, payload > 1 { throw invalid("\(label) overflows u64") }
                value |= payload << shift
                if byte & 0x80 == 0 {
                    if index > 0, payload == 0 { throw invalid("\(label) is noncanonical") }
                    return value
                }
                shift += 7
            }
            throw invalid("\(label) is overlong")
        }

        mutating func readField(maximum: Int, label: String) throws -> Data {
            let length = try readCompactLength("\(label) length")
            guard length <= UInt64(maximum), length <= UInt64(Int.max) else {
                throw invalid("\(label) exceeds its byte ceiling")
            }
            return try readBytes(Int(length), label: label)
        }

        mutating func readBytes(_ count: Int, label: String) throws -> Data {
            guard count >= 0, offset <= data.count, count <= data.count - offset else {
                throw invalid("\(label) is truncated")
            }
            let start = data.index(data.startIndex, offsetBy: offset)
            let end = data.index(start, offsetBy: count)
            offset += count
            return Data(data[start..<end])
        }

        func requireFinished(_ label: String) throws {
            guard offset == data.count else { throw invalid("\(label) contains a suffix") }
        }
    }
}

private extension Data {
    func readUInt32LE(at offset: Int) -> UInt32? {
        guard offset >= 0, count - offset >= 4 else { return nil }
        var value: UInt32 = 0
        self[index(startIndex, offsetBy: offset)..<index(startIndex, offsetBy: offset + 4)]
            .withUnsafeBytes { buffer in
                if let base = buffer.baseAddress { memcpy(&value, base, 4) }
            }
        return UInt32(littleEndian: value)
    }

    func readUInt64LE(at offset: Int) -> UInt64? {
        guard offset >= 0, count - offset >= 8 else { return nil }
        var value: UInt64 = 0
        self[index(startIndex, offsetBy: offset)..<index(startIndex, offsetBy: offset + 8)]
            .withUnsafeBytes { buffer in
                if let base = buffer.baseAddress { memcpy(&value, base, 8) }
            }
        return UInt64(littleEndian: value)
    }
}
