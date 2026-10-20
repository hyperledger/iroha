import Foundation
import IrohaSwift
#if os(iOS) && canImport(CoreNFC)
@preconcurrency import CoreNFC
#endif

/// Closed diagnostic labels. Associated values and arbitrary Error/NSError
/// strings never enter a terminal reader log.
enum IrohaPeerNfcReaderFailureCodeV1: String, Sendable {
    case unknown
    case cancelled
    case operationTimedOut = "operation.timedOut"
    case platformNfc = "platform.coreNfc"
    case peerInvalidApplicationIdentifier = "peer.invalidApplicationIdentifier"
    case peerInvalidCommandClass = "peer.invalidCommandClass"
    case peerUnsupportedInstruction = "peer.unsupportedInstruction"
    case peerInvalidAPDU = "peer.invalidAPDU"
    case peerInvalidLength = "peer.invalidLength"
    case peerMessageTooLarge = "peer.messageTooLarge"
    case peerInvalidOffset = "peer.invalidOffset"
    case peerInvalidSession = "peer.invalidSession"
    case peerInvalidHash = "peer.invalidHash"
    case peerInvalidProfile = "peer.invalidProfile"
    case peerInvalidKind = "peer.invalidKind"
    case peerInvalidFlags = "peer.invalidFlags"
    case peerInvalidIPM1 = "peer.invalidIPM1"
    case peerContinuityMismatch = "peer.continuityMismatch"
    case peerConflictingReplay = "peer.conflictingReplay"
    case peerStateMismatch = "peer.stateMismatch"
    case peerDurableAdmissionRequired = "peer.durableAdmissionRequired"
    case peerDurableCommitRequired = "peer.durableCommitRequired"
    case peerAcknowledgementNotDurable = "peer.acknowledgementNotDurable"
    case peerPeerRejected = "peer.peerRejected"
    case peerPeerPersistenceFailure = "peer.peerPersistenceFailure"
    case adapterInvalidCommandAPDU = "adapter.invalidCommandAPDU"
    case adapterUnavailable = "adapter.unavailable"
    case adapterCardEmulationUnavailable = "adapter.cardEmulationUnavailable"
    case adapterCardEmulationIneligible = "adapter.cardEmulationIneligible"
    case adapterCardSessionSystemUnavailable = "adapter.cardSessionSystemUnavailable"
    case adapterCardSessionAccessNotAccepted = "adapter.cardSessionAccessNotAccepted"
    case adapterCardSessionRadioDisabled = "adapter.cardSessionRadioDisabled"
    case adapterInvalidTag = "adapter.invalidTag"
    case adapterOperationInProgress = "adapter.operationInProgress"
    case adapterRetryExhausted = "adapter.retryExhausted"
    case adapterReaderOperationTimedOut = "adapter.readerOperationTimedOut"
    case adapterCardSessionTimedOut = "adapter.cardSessionTimedOut"
    case adapterPlatformCallTimedOut = "adapter.platformCallTimedOut"
}

struct IrohaPeerNfcReaderTerminalDiagnosticV1: Equatable, Sendable {
    let failure: IrohaPeerNfcReaderFailureCodeV1
    let operation: IrohaPeerNfcOperationV1?
    let lastStage: IrohaPeerNfcProgressStageV1?
    let elapsedMilliseconds: UInt64
    let platformCode: Int?

    init(
        error: Error,
        operation: IrohaPeerNfcOperationV1?,
        lastStage: IrohaPeerNfcProgressStageV1?,
        elapsedMilliseconds: UInt64
    ) {
        let metadata = Self.classify(error)
        failure = metadata.0
        self.operation = metadata.1 ?? operation
        self.lastStage = lastStage
        self.elapsedMilliseconds = elapsedMilliseconds
        platformCode = metadata.2
    }

    var logLine: String {
        var line = "iroha_kagemusha_nfc_ios_reader_terminal error=\(failure.rawValue)"
            + " operation=\(operation?.rawValue ?? "none")"
            + " elapsed_ms=\(elapsedMilliseconds)"
            + " last_stage=\(lastStage?.rawValue ?? "none")"
        if let platformCode {
            // A fixed public framework-domain label, never an arbitrary domain.
            line += " platform_domain=CoreNFC.NFCErrorDomain platform_code=\(platformCode)"
        }
        return line
    }

    private static func classify(_ error: Error) -> (
        IrohaPeerNfcReaderFailureCodeV1, IrohaPeerNfcOperationV1?, Int?
    ) {
        if let peer = error as? IrohaPeerNfcErrorV1 {
            switch peer {
            case .invalidApplicationIdentifier: return (.peerInvalidApplicationIdentifier, nil, nil)
            case .invalidCommandClass: return (.peerInvalidCommandClass, nil, nil)
            case .unsupportedInstruction: return (.peerUnsupportedInstruction, nil, nil)
            case .invalidAPDU: return (.peerInvalidAPDU, nil, nil)
            case .invalidLength: return (.peerInvalidLength, nil, nil)
            case .messageTooLarge: return (.peerMessageTooLarge, nil, nil)
            case .invalidOffset: return (.peerInvalidOffset, nil, nil)
            case .invalidSession: return (.peerInvalidSession, nil, nil)
            case .invalidHash: return (.peerInvalidHash, nil, nil)
            case .invalidProfile: return (.peerInvalidProfile, nil, nil)
            case .invalidKind: return (.peerInvalidKind, nil, nil)
            case .invalidFlags: return (.peerInvalidFlags, nil, nil)
            case .invalidIPM1: return (.peerInvalidIPM1, nil, nil)
            case .continuityMismatch: return (.peerContinuityMismatch, nil, nil)
            case .conflictingReplay: return (.peerConflictingReplay, nil, nil)
            case .stateMismatch: return (.peerStateMismatch, nil, nil)
            case .durableAdmissionRequired: return (.peerDurableAdmissionRequired, nil, nil)
            case .durableCommitRequired: return (.peerDurableCommitRequired, nil, nil)
            case .acknowledgementNotDurable: return (.peerAcknowledgementNotDurable, nil, nil)
            case .peerRejected(let operation): return (.peerPeerRejected, operation, nil)
            case .peerPersistenceFailure(let operation): return (.peerPeerPersistenceFailure, operation, nil)
            }
        }
        if error is CancellationError { return (.cancelled, nil, nil) }
        if error is IrohaPeerNfcOperationDeadlineErrorV1 {
            return (.operationTimedOut, nil, nil)
        }
#if os(iOS) && canImport(CoreNFC)
        if let adapter = error as? IrohaPeerNfcCoreNFCErrorV1 {
            switch adapter {
            case .cancelled: return (.cancelled, nil, nil)
            case .invalidCommandAPDU: return (.adapterInvalidCommandAPDU, nil, nil)
            case .unavailable: return (.adapterUnavailable, nil, nil)
            case .cardEmulationUnavailable: return (.adapterCardEmulationUnavailable, nil, nil)
            case .cardEmulationIneligible: return (.adapterCardEmulationIneligible, nil, nil)
            case .cardSessionSystemUnavailable: return (.adapterCardSessionSystemUnavailable, nil, nil)
            case .cardSessionAccessNotAccepted: return (.adapterCardSessionAccessNotAccepted, nil, nil)
            case .cardSessionRadioDisabled: return (.adapterCardSessionRadioDisabled, nil, nil)
            case .invalidTag: return (.adapterInvalidTag, nil, nil)
            case .operationInProgress: return (.adapterOperationInProgress, nil, nil)
            case .retryExhausted: return (.adapterRetryExhausted, nil, nil)
            case .readerOperationTimedOut: return (.adapterReaderOperationTimedOut, nil, nil)
            case .cardSessionTimedOut: return (.adapterCardSessionTimedOut, nil, nil)
            case .platformCallTimedOut: return (.adapterPlatformCallTimedOut, nil, nil)
            }
        }
        if let reader = error as? NFCReaderError {
            let code = reader.code.rawValue
            // Public NFCError.h values only. Unknown future/platform codes
            // receive the same closed unknown label as application errors.
            switch code {
            case 1...8, 100...105, 200...204, 300, 400...403, 500...502:
                return (.platformNfc, nil, code)
            default:
                break
            }
        }
#endif
        return (.unknown, nil, nil)
    }
}
