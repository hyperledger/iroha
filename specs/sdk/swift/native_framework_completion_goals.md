# Swift native framework completion goals

The current Swift SDK requires the real ABI-30 NoritoBridge native implementation.
The ABI-25 artifact and test results below are historical component evidence;
the typed-wallet ABI-30 candidate requires a fresh build and consumer qualification.
The build and artifact contract is [NoritoBridge release packaging](../../../docs/norito_bridge_release.md).

| Goal | Owner | State | Completion criteria |
| --- | --- | --- | --- |
| SW1: Build the native framework | Bridge/build | Complete | Build all five supported Apple targets from the current source and locked graph; preserve the warm build lane; pass whole-archive consumer, ABI, symbol and artifact checks. |
| SW2: Make SwiftPM installation usable | Swift/package | Complete | Make SwiftPM the sole supported Swift packaging path and retire CocoaPods tooling, metadata and documentation; integrate the authenticated XCFramework ZIP; qualify an ordinary public `IrohaSwift` dependency in Release with native execution and no unsafe linker flags; correct installation instructions. |
| SW3: Qualify the Swift SDK | Swift/tests | Complete | Run the complete Swift package suite with native support and fix failures; verify query, signing, codec and native lifecycle behavior without disabled tests or replacement implementations. |
| SW4: Keep delivery claims accurate | SDK/docs | Complete | Record the actual artifact and checks, update current blockers, and distinguish host/simulator validation from physical-device and signed public-release qualification. |
| SW5: Install on consumer Macs | Swift/package | Complete | Authenticate a trusted release ZIP and matching source without requiring consumer tools to equal producer binaries; retain strict producer verification and reject altered inputs. |
| SW6: Decode exact integer fields | Swift/tests | Complete | Reject fractional, exponent and rounded JSON epoch/revision values before numeric conversion; preserve all valid UInt64 values and add public decoder regressions. |
| SW7: Retain Release consumer gates | Swift/CI | Complete | Keep executable ZIP and public SDK consumers in the repository; execute native operations in Release before CI publishes Apple artifacts. |

Implementation and current artifacts are authoritative. Routine validation
commands and results belong in the change report; generated artifacts stay
untracked.

Historical ABI-25 state: SW1 produced the genuine five-target ABI-25 XCFramework and
authenticated ZIP from signed, frozen source, reusing the fixed warm Cargo
build lane. The macOS universal archive passes the arm64 native consumer and
the x86_64 consumer under Rosetta. SW2 is complete: SwiftPM is the sole delivery
path, CocoaPods is retired, the authenticated framework is installed, and
ordinary public SDK Release consumers execute native cryptography and Connect
encryption without unsafe linker flags. SW3 is complete: the full native Swift
package suites pass on both the signed producing source and the current
checkout, including the repaired query, replication and Python integration
paths. The checked-in iOS demo also builds and passes its simulator suite.
The producing source is signed commit
`412af34ebfb80749c2803a85b63fd61851793066`; its ZIP SHA-256 is
`e60fd1c45f66621dc5b9e39803224e5d602458439829385d7d16439c257999c3`.
SW4 records these completed host/simulator outcomes. Physical-device
qualification and signed public publication require their own release evidence.
Review follow-ups SW5–SW7 are implemented and locally qualified. Consumer
admission binds independently trusted archive and source inputs while preserving
the strict producer path. Exact integer decoding uses original JSON lexemes.
Maintained ZIP and public SDK executables now perform actual native operations
in Release and gate CI publication. These source changes are newer than the
producing commit above; the existing archive validates their consumer behavior,
and does not constitute a newly produced or published release of these changes.
