export type CanonicalContractPayloadValue =
  | null
  | boolean
  | string
  | number
  | readonly CanonicalContractPayloadValue[]
  | { readonly [key: string]: CanonicalContractPayloadValue };

export const CONTRACT_PAYLOAD_MAX_CANONICAL_BYTES: 1048576;
export const CONTRACT_PAYLOAD_MAX_DEPTH: 128;
export const CONTRACT_PAYLOAD_MAX_NODES: 1000000;

/** Scalar kind of a `Leaf` node in a signed entrypoint argument schema. */
export type ContractArgumentLeafKind =
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

/** Tuple arity or list capacity as manifest JSON may publish it: a number, bigint or decimal string. */
export type ContractArgumentSchemaCount = number | bigint | string;

/** One preorder node of an entrypoint value type, as published in the signed contract manifest. */
export type ContractArgumentTypeNode =
  | { readonly kind: "Struct"; readonly value: { readonly name: string; readonly fields: readonly string[] } }
  | { readonly kind: "Tuple"; readonly value: ContractArgumentSchemaCount }
  | { readonly kind: "Option" | "Result" | "Unit"; readonly value?: null }
  | { readonly kind: "List"; readonly value: { readonly capacity: ContractArgumentSchemaCount } }
  | { readonly kind: "Leaf"; readonly value: { readonly kind: ContractArgumentLeafKind; readonly value?: null } }
  | {
    readonly kind: "Error";
    readonly value: {
      readonly identity: string;
      readonly variants: readonly { readonly name: string; readonly code: number }[];
    };
  }
  | { readonly kind: "StateCursor"; readonly value: { readonly kind: ContractArgumentLeafKind } };

/** The signed `argument_schema` of one entrypoint: named fields with preorder type tapes. */
export interface ContractArgumentSchema {
  readonly fields: readonly {
    readonly name: string;
    readonly ty: { readonly nodes: readonly ContractArgumentTypeNode[] };
  }[];
}

/**
 * Argument canonicalization options.
 *
 * `argumentSchema` is the entrypoint's signed `argument_schema`; `null` declares a zero-parameter
 * entrypoint. When the key is omitted the declared types are unknown.
 */
export interface ContractArgumentOptions {
  readonly argumentSchema?: ContractArgumentSchema | null;
}

/**
 * Canonicalize named contract arguments before signing or hashing.
 *
 * With an `argumentSchema`, `int`, `decimal` and `quantity` values given as safe integers or
 * bigints become canonical decimal strings, `DataSpaceId` stays a JSON integer, `Blob` accepts a
 * `Uint8Array`, and any mismatch throws a `TypeError` naming the argument path (for example
 * ``argument `order.lines[1]` expects quantity ...``). Without an `argumentSchema` key, any JSON
 * number is rejected with its argument path because it cannot be checked against the IVM's
 * canonical decimal-string encoding. Returns `null` for an absent payload.
 */
export function canonicalContractArguments(
  payload: unknown,
  options?: ContractArgumentOptions,
): { readonly [key: string]: CanonicalContractPayloadValue } | null;

/**
 * Return Torii's exact compact canonical JSON for the browser-safe contract payload profile.
 *
 * Without `options` this hashes exactly the JSON that will be sent: numbers must be safe integers
 * other than negative zero, which only `Json` and `DataSpaceId` parameters accept. Pass `options`
 * to apply {@link canonicalContractArguments} first. `null` and `undefined` represent an absent
 * optional payload.
 */
export function canonicalContractPayloadJson(
  payload?: unknown,
  options?: ContractArgumentOptions,
): string | null;

/** Return BLAKE3(canonical payload JSON), or BLAKE3(empty bytes) for an absent payload. */
export function contractPayloadDigestHex(
  payload?: unknown,
  options?: ContractArgumentOptions,
): string;
