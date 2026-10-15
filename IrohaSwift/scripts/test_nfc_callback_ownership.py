"""Execute the CoreNFC callback ownership cut without invoking platform radio.

The guarded statements and retry/epoch gates come from maintained Swift source.
The harness supplies only session identity and progress observation; NSLock and
Task cancellation are genuine Foundation/Swift behavior. This catches stale
callbacks clearing a newer operation's deadline without requiring NFC hardware.
It is not device, native monetary, or full CoreNFC runtime qualification.
"""

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
SWIFTC = shutil.which("swiftc")
CORE_NFC_SOURCE = (
    "IrohaSwift/Sources/IrohaSwiftMobileTransports/IrohaPeerNfcCoreNFCV1.swift"
)
PROGRESS_SOURCE = (
    "IrohaSwift/Sources/IrohaSwiftMobileTransports/IrohaPeerNfcProgressV1.swift"
)


def extract_swift_declaration(source, declaration_start):
    start = source.index(declaration_start)
    opening_brace = source.index("{", start)
    depth = 1
    end = opening_brace + 1
    while depth:
        if source[end] == "{":
            depth += 1
        if source[end] == "}":
            depth -= 1
        end += 1
    return source[start:end] + "\n"


def extract_invalid_detection_prefix(source):
    callback_start = source.index(
        "public func tagReaderSession(_ session: NFCTagReaderSession, "
        "didDetect tags: [NFCTag]) {"
    )
    prefix_start = source.index("            lock.lock()", callback_start)
    prefix_end = source.index("            switch disposition {", prefix_start)
    return source[prefix_start:prefix_end]


def ownership_harness(callback_prefix, gate_declarations):
    return (
        "import Foundation\n"
        + gate_declarations
        + """
// Only identity and observation stand-ins: no CoreNFC API or native payment is modeled.
final class Session {}

enum Stage {
    case tagDetected
}

final class Reporter {
    var count = 0

    func emit(_ stage: Stage) {
        count += 1
    }
}

final class ReaderCut {
    let lock = NSLock()
    var completed = false
    let session = Session()
    var operationGate = IrohaPeerNfcReaderOperationGateV1()
    var retryGate: IrohaPeerNfcRetryGateV1? = .init(.init(maximumContactAttempts: 3))
    var platformCallGate: IrohaPeerNfcReaderPlatformCallGateV1? = .init()
    var retryTimeoutTask: Task<Void, Never>?
    var operationTimeoutTask: Task<Void, Never>?
    var progressReporter: Reporter? = Reporter()

    func invalidDetection(_ session: Session) {
"""
        + callback_prefix
        + """
        _ = disposition
        _ = platformCallGate
    }
}

var assertions = 0, failures = 0

func require(_ value: @autoclosure () -> Bool, _ label: String) {
    assertions += 1
    if !value() {
        failures += 1
        print("FAIL " + label)
    }
}

for mode in ["current", "stale-session", "completed", "inactive-epoch"] {
    let reader = ReaderCut()
    if mode != "inactive-epoch" {
        _ = reader.operationGate.beginOperation()
    }
    if mode == "completed" {
        reader.completed = true
    }
    let retry = Task<Void, Never> {}
    let operation = Task<Void, Never> {}
    reader.retryTimeoutTask = retry
    reader.operationTimeoutTask = operation
    let supplied = mode == "stale-session" ? Session() : reader.session
    reader.invalidDetection(supplied)
    let current = mode == "current"
    require((reader.retryTimeoutTask == nil) == current, mode + ": deadline ownership")
    require(retry.isCancelled == current, mode + ": cancellation ownership")
    require(reader.operationTimeoutTask != nil, mode + ": operation deadline retained")
    require(!operation.isCancelled, mode + ": operation deadline not cancelled")
    require(reader.progressReporter!.count == (current ? 1 : 0), mode + ": progress ownership")
    let dispositions = (0..<3).map { _ in reader.retryGate!.recordInvalidDetection() }
    require(
        dispositions == (current ? [.retry, .exhausted, .exhausted] : [.retry, .retry, .exhausted]),
        mode + ": shared retry budget"
    )
    let unlocked = reader.lock.try()
    require(unlocked, mode + ": lock released")
    if unlocked {
        reader.lock.unlock()
    }
    retry.cancel()
    operation.cancel()
}

print("ASSERTIONS \\(assertions) FAILURES \\(failures); exact source ownership cut, no platform radio")
exit(failures == 0 ? 0 : 1)
"""
    )


@unittest.skipUnless(SWIFTC, "this behavioral Swift source regression requires swiftc")
class NfcCallbackOwnershipTests(unittest.TestCase):
    def test_invalid_detection_preserves_another_operations_deadline(self):
        progress_source = (REPOSITORY_ROOT / PROGRESS_SOURCE).read_text()
        declaration_names = (
            "public struct IrohaPeerNfcReaderRetryPolicyV1:",
            "final class IrohaPeerNfcReaderPlatformCallGateV1:",
            "final class IrohaPeerNfcRetryGateV1:",
            "struct IrohaPeerNfcReaderOperationGateV1:",
        )
        declarations = "\n".join(
            extract_swift_declaration(progress_source, name)
            for name in declaration_names
        )
        callback_prefix = extract_invalid_detection_prefix(
            (REPOSITORY_ROOT / CORE_NFC_SOURCE).read_text()
        )
        harness_source = ownership_harness(callback_prefix, declarations)

        with tempfile.TemporaryDirectory(prefix="iroha-nfc-callback-") as temporary:
            directory = Path(temporary)
            main = directory / "main.swift"
            binary = directory / "ownership"
            main.write_text(harness_source)
            compiled = subprocess.run(
                [SWIFTC, "-swift-version", "5", str(main), "-o", str(binary)],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
            result = subprocess.run(
                [str(binary)],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
