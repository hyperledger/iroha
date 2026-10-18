/** Native JSON keeps integers above the JavaScript safe range as bigint. */
export type ToriiProofJson = null | boolean | string | number | bigint
  | ReadonlyArray<ToriiProofJson> | { readonly [key: string]: ToriiProofJson };

export interface ToriiExplorerTransactionMerkleProof {
  readonly leaf_index: number;
  /** Canonical checksummed hash literals; null represents an absent sibling. */
  readonly audit_path: ReadonlyArray<string | null>;
}

export interface ToriiExplorerTransactionProofHeader {
  readonly height: string;
  readonly prev_block_hash: string | null;
  readonly merkle_root: string | null;
  readonly da_proof_policies_hash: string | null;
  readonly da_commitments_hash: string | null;
  readonly da_pin_intents_hash: string | null;
  readonly npos_effects_hash: string | null;
  readonly creation_time_ms: string;
  readonly view_change_index: string;
  readonly confidential_features: Readonly<Record<string, ToriiProofJson>> | null;
  readonly execution_context_hash: string | null;
  readonly global_beacon_pulse_hash: string | null;
}

/** Selective native evidence; successful retrieval is not a finality verification verdict. */
export interface ToriiExplorerTransactionProof {
  readonly version: 1;
  /** Exact canonical genesis-derived NetworkId, checked against client configuration when present. */
  readonly network_id: string;
  /** Exact u64 normalized to decimal text. */
  readonly block_height: string;
  readonly block_header: ToriiExplorerTransactionProofHeader;
  readonly transaction: {
    readonly block_hash: string;
    readonly entrypoint_hash: string;
    readonly entrypoint_proof: ToriiExplorerTransactionMerkleProof;
    /** Native TransactionEntrypoint JSON. */
    readonly entrypoint: Readonly<Record<string, ToriiProofJson>>;
    readonly output_hash: string;
    readonly output_proof: ToriiExplorerTransactionMerkleProof;
    /** Native ExecutionOutputV1 JSON, including this transaction's own completions. */
    readonly output: Readonly<Record<string, ToriiProofJson>>;
  };
  /**
   * Canonical padded base64 of native compact certificate components. Authenticate
   * these using an independently trusted checkpoint before trusting their roots.
   */
  readonly certificate: {
    readonly consensus_header: string;
    readonly commit_qc: string;
    readonly result_preimage: string;
  };
}
