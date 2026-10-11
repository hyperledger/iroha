# Generated binding qualification

The Rust test `bindgen::tests::admitted_artifact_generates_deterministic_kind_specific_bindings`
compiles and admits its source fixture. Set `MUSUBI_BINDGEN_CAPTURE_DIR` to an absolute
output directory when running that test to capture `Sample.ts`, `Sample.swift`, and
`Sample.kt`. These generated files are temporary test output, not checked-in wire
fixtures.

Compile each captured file with its matching round-trip consumer and the current
SDK. Run the resulting programs. The consumers check wide signed integers, exact
decimal and quantity strings, nested options, nominal errors and ordinary enums,
list bounds, complete product fields, Unicode, and the four entrypoint kinds.
TypeScript's `@ts-expect-error` assertion is part of its successful strict compile.
Compile each `KindMismatch` file separately and require a type mismatch between
`ViewRequest` and `KotoageRequest`.

- TypeScript: use strict `NodeNext` module and resolution modes, an ES2022 target,
  and the repository's `@iroha/iroha-js` package. Place `roundtrip.ts` beside the
  captured `Sample.ts`, then run the emitted `roundtrip.js` with Node.
- Kotlin: compile `Sample.kt` and `Roundtrip.kt` against the SDK's `core-jvm`
  classes and Kotlin standard library with `-Xjdk-release=8`; run `RoundtripKt`.
  Keep that same target when compiling the negative kind fixture.
- Swift: compile `Sample.swift` and `Roundtrip.swift` against the built
  `IrohaSwift` module and its matching authenticated native bridge. Link the
  SDK's platform frameworks, including CoreGraphics and Metal on macOS, then run
  the executable. Typecheck the negative fixture separately.

These tests exercise generated client models and request builders. Current native
artifact admission, complete SDK suites, and deployed transport behavior remain
separate qualification gates. Request builders never sign, activate, upgrade, or
submit contracts; applications select the appropriate SDK operation explicitly.
