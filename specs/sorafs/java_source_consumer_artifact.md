# SoraFS Java-source consumer artifact

`scripts/build_sorafs_java_consumer_artifact.py` owns an unsigned host-consumer
artifact for the canonical Kotlin APIs. It compiles the one shared Java source
against the actual core JAR, then against the same core JAR and Android AAR's
`classes.jar`. Each lane must execute all 25 existing SoraFS assertion groups
successfully with the same authenticated host JNI library. There is no Java SDK
implementation or accepted `java_android` evidence alias in this interface.

The shared source lives in `kotlin/core-jvm/src/sorafsJavaTest/java`; both JVM
and Android source sets include it. Its `host-native` tag places Android execution
in `:client-android:testDebugHostNative`, which requires actual host JNI. It remains
part of `:core-jvm:test`. Managed tests without JNI are not substitutes.

## Inputs and execution

The producer requires these explicit arguments:

- `--source-root`: the candidate source checkout. Native ABI-26 verification
  requires the native manifest's exact clean commit and source manifest.
- `--core-jar`, `--client-aar`: the actual package bytes to exercise. The producer
  refuses duplicated SDK classes, foreign class namespaces, hidden classpaths,
  malformed archives, and SDK classes outside the JDK 8 target.
- `--native-artifact`, `--native-manifest`: the same host C/JNI artifact and
  `iroha.native-sdk-abi26-artifact.v1` evidence. The existing native verifier runs
  before and after both lanes against original bytes and their private copy.
- `--jdk-home`: canonical JDK 21 home. `javac --release 8 -proc:none` compiles only
  the captured consumer/runner sources with an empty implicit source path.
- `--dependency-manifest`, `--dependency-manifest-sha256`: an independently reviewed
  exact tool dependency inventory and its expected SHA-256. A digest supplied with
  unreviewed dependencies is not an independent review or supply-chain attestation.
- `--work-dir`: a fresh directory outside the candidate checkout, beneath an
  existing canonical parent. It retains inputs and failure logs as well as output.

The dependency document has exactly `schema` and `jars`. Its schema is
`sorafs.java_consumer.dependencies.v1`; every row has exactly `module`, `version`,
`path`, `sha256`, and integer `size`. Paths are absolute. The nine required modules
are Kotlin stdlib, JetBrains annotations, JUnit Jupiter API/engine, JUnit Platform
commons/engine/launcher, API Guardian, and OpenTest4J, using their Maven coordinates
listed in the producer. No dependency may define SDK classes or overlap another
ordinary dependency class. Version strings are inventory metadata; the independent
pin and actual file bytes bind the tool inputs.

The producer copies package, tool, fixture, and source inputs into its private
work directory. Runtime class-load logs must identify the exact copied package
entries and compiled Java assertion owner. JVM-generated lambda records require
an already observed enclosing class with a real LambdaMetafactory bootstrap;
they are recorded as runtime-generated, not as class bytes from the package.
The native-load log must identify the sole authenticated JNI copy. Source,
package, native, fixture, compiled-class, report, and tool identities are checked
again before packaging. Missing files, skips, extra/missing/failed cases, changed
bytes, failed commands, and deadlines fail without creating an output artifact.

## Output and scope

The output is `java-source-kotlin-consumer.zip`, schema
`sorafs.java_source_kotlin.consumer_artifact.v1`. It contains captured source and
fixtures, compiled Java classes, exact runtime reports and logs, native/dependency
metadata, the actual Python producer/helper sources, and their identities.
Package/native bytes remain in the private work directory and are referenced by
actual digest and size in the artifact. These references must later be joined to
the same release's content-addressed package inventory.

ZIP member order, timestamps, and permissions are deterministic for the same
captured observations. Separate executions can produce different timing and
runtime logs; repeatable assembly does not claim identical runtime observations.
The package is a distinct Java-consumer qualification artifact, not a duplicate
Kotlin SDK implementation or a reused Kotlin package digest.

The Android host lane tests the canonical core SoraFS APIs with the actual Android
AAR on its classpath. A separate enum linkage probe proves an Android package
class loaded. It does not exercise Android framework/device behavior. Physical
Android qualification, all six SoraFS consumer package bindings, signed release
inventory, reproducible builds, dependency audits, and final promotion remain
separate required work. JDK evidence identifies the selected executables,
modules, `ct.sym`, and release descriptor; it is not a complete JDK installation
or operating-system attestation. Classfile SourceFile metadata and executed
class-byte identity do not establish Kotlin compiler build provenance.

Focused controls:

```text
python3 -m pytest -q scripts/tests/sorafs_java_consumer_artifact_test.py scripts/tests/check_kotlin_jni_test.py
```

The process-injection unit tests deliberately substitute compiler/native services
to test failure plumbing. Their synthetic artifacts never qualify a release.
A candidate pass requires the unchanged producer to execute against its actual
packages and native evidence; no existing report or qualification boolean can be
supplied as an input.

The Java processes emit class loading, native library loading, diagnostics, and
one framed XML report through the same bounded stdout pipe. There are no JVM
file logs or rotation segments. The producer rejects overflow, deadline expiry,
partial output, a missing or repeated report frame, and incomplete log streams;
only then does it create retained XML and class/library logs from those exact
observed bytes. The fixed runner admits at most 25 result records and 16 KiB of
XML. Dependency and native manifests are parsed from their original captured
bytes; a later path reread never supplies a replacement parsed input.
