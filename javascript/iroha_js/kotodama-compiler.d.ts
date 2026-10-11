import type { EntrypointAuthorizationV1, ContractPermissionDescriptorV1 } from "./index.js";

/** One immutable source file; paths are relative to their owning source root. */
export interface KotodamaCompilerSourceFile { sourceName: string; source: string }
/** A complete immutable compiled interface; the compiler admits every used artifact. */
export interface KotodamaCompilerContractArtifact { sourceName: string; artifact: ReadonlyArray<number> }
/** An already locked package alias, resolved without network access. */
export interface KotodamaCompilerSourceImport { alias: string; package: string }
/** Complete immutable inventory for one locked dependency package. */
export interface KotodamaCompilerSourcePackage {
  identity: string;
  modules: ReadonlyArray<KotodamaCompilerSourceFile>;
  artifacts?: ReadonlyArray<KotodamaCompilerContractArtifact>;
  sources?: ReadonlyArray<KotodamaCompilerSourceFile>;
  exports: ReadonlyArray<string>;
  imports?: ReadonlyArray<KotodamaCompilerSourceImport>;
}

export type KotodamaCompilerDiagnosticPhase =
  | "lex"
  | "parse"
  | "resolve"
  | "semantic"
  | "lowering"
  | "artifact";

export interface KotodamaCompilerSourcePosition {
  line: number;
  column: number;
}

export interface KotodamaCompilerSourceSpan {
  /** Exact locked package identity, or null for the owning source root. */
  package_identity: string | null;
  source: string | null;
  start: KotodamaCompilerSourcePosition;
  end: KotodamaCompilerSourcePosition;
  /** Exact half-open UTF-8 byte range, when the Rust frontend has source text. */
  byte_range: { start: number; end: number } | null;
}

export interface KotodamaCompilerDiagnosticLabel {
  span: KotodamaCompilerSourceSpan;
  message: string;
}

export interface KotodamaCompilerDiagnosticFix {
  span: KotodamaCompilerSourceSpan;
  replacement: string;
}

/** Optional human presentation; canonical diagnostic message and help remain unchanged. */
export interface KotodamaCompilerLocalizedText {
  language: string;
  message: string;
  help: string | null;
}

/** Exact semantic record emitted by `Diagnostic::to_json_value` in Rust. */
export interface KotodamaCompilerDiagnostic {
  code: string;
  severity: "error" | "warning";
  phase: KotodamaCompilerDiagnosticPhase;
  message: string;
  primary_span: KotodamaCompilerSourceSpan | null;
  labels: KotodamaCompilerDiagnosticLabel[];
  notes: string[];
  help: string | null;
  fix: KotodamaCompilerDiagnosticFix | null;
  alternative_fixes: KotodamaCompilerDiagnosticFix[];
  localized: KotodamaCompilerLocalizedText | null;
}

export interface KotodamaCompiledTriggerDescriptor {
  id: string;
  repeats: { Indefinitely: null } | { Exactly: number };
  /** Canonical standard-base64 NRT0 frame for `EventFilterBox`. */
  filter: string;
  authority: string | null;
  metadata: Record<string, unknown>;
  callback: {
    namespace: string | null;
    entrypoint: string;
  };
}

export interface KotodamaCompiledManifestEntrypointKind {
  kind: "Kotoage" | "View" | "Hajimari" | "Kaizen";
  value: null;
}

export interface KotodamaCompiledKotobaTranslation {
  lang: string;
  text: string;
}

export interface KotodamaCompiledKotobaEntry {
  msg_id: string;
  translations: KotodamaCompiledKotobaTranslation[];
}

export type KotodamaCompiledEntrypointValueKindName =
  | "Int"
  | "Decimal"
  | "Quantity"
  | "Bool"
  | "String"
  | "Json"
  | "Name"
  | "AccountId"
  | "AssetDefinitionId"
  | "AssetId"
  | "DomainId"
  | "NftId"
  | "DataSpaceId"
  | "Blob";

export interface KotodamaCompiledEntrypointValueKind {
  kind: KotodamaCompiledEntrypointValueKindName;
  value: null;
}

export interface KotodamaCompiledEntrypointValueType {
  nodes: KotodamaCompiledEntrypointValueTypeNode[];
}

export type KotodamaCompiledEntrypointValueTypeNode =
  | {
      kind: "Struct";
      value: { name: string; fields: string[] };
    }
  | { kind: "Tuple"; value: number }
  | { kind: "Option"; value: null }
  | { kind: "Result"; value: null }
  | {
      kind: "List";
      value: { capacity: number };
    }
  | { kind: "Leaf"; value: KotodamaCompiledEntrypointValueKind }
  | { kind: "Unit"; value: null }
  | { kind: "StateCursor"; value: KotodamaCompiledEntrypointValueKind }
  | { kind: "Error"; value: KotodamaCompiledErrorTypeDescriptor }
  | { kind: "Enum"; value: KotodamaCompiledEnumTypeDescriptor };

export interface KotodamaCompiledEntrypointArgumentSchema {
  fields: Array<{
    name: string;
    ty: KotodamaCompiledEntrypointValueType;
  }>;
}

export interface KotodamaCompiledEntrypoint {
  name: string;
  kind: KotodamaCompiledManifestEntrypointKind;
  params: Array<{
    name: string;
    type_name: string;
  }>;
  argument_schema: KotodamaCompiledEntrypointArgumentSchema | null;
  return_type: string;
  return_schema: KotodamaCompiledEntrypointValueType;
  authorization: EntrypointAuthorizationV1;
  read_keys: string[];
  write_keys: string[];
  access_hints_complete: boolean | null;
  access_hints_skipped: string[];
  triggers: KotodamaCompiledTriggerDescriptor[];
}

export interface KotodamaCompiledSourceMapEntry {
  /** Statement locations include inlined helpers; function locations describe generated gaps. */
  source_kind: "function" | "statement";
  function_name: string;
  pc_start: number;
  pc_end: number;
  source_path: string | null;
  source_id: number;
  byte_start: number;
  byte_end: number;
  line: number;
  column: number;
}

export interface KotodamaCompiledBudgetEntry {
  function_name: string;
  pc_start: number;
  pc_end: number;
  bytecode_bytes: number;
  bytecode_words: number;
  frame_bytes: number;
  jump_span_words: number;
  jump_range_risk: boolean;
  source_path: string | null;
  source_id: number | null;
  byte_start: number | null;
  byte_end: number | null;
  line: number | null;
  column: number | null;
}

export type KotodamaCompiledStateMapKeyTypeName =
  | "int"
  | "decimal"
  | "quantity"
  | "bool"
  | "string"
  | "bytes"
  | "DataSpaceId"
  | "AccountId"
  | "AssetDefinitionId"
  | "AssetId"
  | "NftId"
  | "DomainId"
  | "Name";

export type KotodamaCompiledDynamicAccessBoundKind = "page" | "take";

export interface KotodamaCompiledDynamicAccessHint {
  base_key: string;
  key_type: KotodamaCompiledStateMapKeyTypeName;
  bound_kind: KotodamaCompiledDynamicAccessBoundKind;
  max_keys: number;
}

export interface KotodamaCompiledStateDescriptor {
  name: string;
  type_name: string;
}

export interface KotodamaCompiledEnumVariantDescriptor { name: string; code: number; }
export interface KotodamaCompiledEnumTypeDescriptor {
  identity: string;
  variants: KotodamaCompiledEnumVariantDescriptor[];
}
export interface KotodamaCompiledEventDescriptor {
  name: string;
  payload_type: KotodamaCompiledEntrypointValueType;
}

export interface KotodamaCompiledErrorVariantDescriptor { name: string; code: number; }
export interface KotodamaCompiledErrorTypeDescriptor {
  identity: string;
  variants: KotodamaCompiledErrorVariantDescriptor[];
}

export interface KotodamaCompiledManifestProvenance {
  signer: string;
  signature: string;
}

export interface KotodamaCompiledManifestMetadata {
  seiyaku_name: string;
  code_hash: string;
  abi_hash: string;
  compiler_fingerprint: string;
  features_bitmap: number;
  permissions: ContractPermissionDescriptorV1[];
  events: KotodamaCompiledEventDescriptor[];
  enum_types: KotodamaCompiledEnumTypeDescriptor[];
  entrypoints: KotodamaCompiledEntrypoint[];
  access_set_hints: {
    read_keys: string[];
    write_keys: string[];
    dynamic_reads: KotodamaCompiledDynamicAccessHint[];
    dynamic_writes: KotodamaCompiledDynamicAccessHint[];
  } | null;
  states: KotodamaCompiledStateDescriptor[];
  error_types: KotodamaCompiledErrorTypeDescriptor[] | null;
  error_messages?: ReadonlyArray<{ error_type: string; code: number; message: string }> | null;
  kotoba: KotodamaCompiledKotobaEntry[] | null;
  /** Signed provenance is not accepted until its exact V1 message can be verified. */
  provenance: null;
}

export interface KotodamaCompilerRequestOptions {
  artifacts?: ReadonlyArray<KotodamaCompilerContractArtifact>;
  /** Logical UTF-8 source path preserved in diagnostics and hash-keyed sidecars. */
  sourceName?: string;
  /** Explicit companion files for include/import; paths are relative to the source-set root. */
  sources?: ReadonlyArray<KotodamaCompilerSourceFile>;
  imports?: ReadonlyArray<KotodamaCompilerSourceImport>;
  packages?: ReadonlyArray<KotodamaCompilerSourcePackage>;
  /** Select the canonical ZK contract policy required by `Secret<T>`. */
  zk?: boolean;
}

/** Exact bounded request sent to `iroha_js_host` or the compiler service. */
export interface KotodamaCompilerRequest {
  artifacts: ReadonlyArray<KotodamaCompilerContractArtifact>;
  source: string;
  sourceName?: string;
  sources?: ReadonlyArray<KotodamaCompilerSourceFile>;
  imports?: ReadonlyArray<KotodamaCompilerSourceImport>;
  packages?: ReadonlyArray<KotodamaCompilerSourcePackage>;
  zk: boolean;
}

export interface KotodamaCompilerTransportOptions {
  /** Abort one remote compilation; the exact caller reason is preserved. */
  signal?: AbortSignal;
  /** Total fetch-and-body deadline in milliseconds (default 30,000; maximum 120,000). */
  timeoutMs?: number;
}

export interface KotodamaCompilerCallOptions
  extends KotodamaCompilerRequestOptions,
    KotodamaCompilerTransportOptions {}

export interface KotodamaCompilerOptions extends KotodamaCompilerCallOptions {
  /**
   * Canonical Rust compiler-service URL. Required in browsers; optional in
   * Node, which otherwise compiles asynchronously through `iroha_js_host`.
   * Remote services receive the complete source and must be trusted. They must
   * use HTTPS; loopback development URLs may use HTTP. Responses must be
   * uncompressed (`Content-Encoding` absent or `identity`).
   */
  compilerUrl?: string;
  /** Fetch implementation used only with `compilerUrl`. */
  fetchImpl?: typeof fetch;
}

export interface KotodamaCompilerOutput {
  /**
   * Bounded IVM 1.1/ABI-1 artifact with a validated CNTR frame and
   * word-aligned instruction stream.
   */
  artifactBytes: Uint8Array;
  codeHashHex: string;
  abiHashHex: string;
  compilerFingerprint: string;
  manifest: KotodamaCompiledManifestMetadata;
  sourceMap: KotodamaCompiledSourceMapEntry[];
  budgetReport: KotodamaCompiledBudgetEntry[];
}

/** Compiler errors are values; transport and malformed responses reject the promise. */
export type KotodamaCompilerResult =
  | { ok: true; output: KotodamaCompilerOutput }
  | { ok: false; diagnostics: KotodamaCompilerDiagnostic[] };

export declare function compileKotodamaProgram(
  source: string,
  options?: KotodamaCompilerOptions,
): Promise<KotodamaCompilerResult>;

export declare class KotodamaCompilerClient {
  constructor(baseUrl: string, options?: { fetchImpl?: typeof fetch });
  compile(
    source: string,
    options?: KotodamaCompilerCallOptions,
  ): Promise<KotodamaCompilerResult>;
}
