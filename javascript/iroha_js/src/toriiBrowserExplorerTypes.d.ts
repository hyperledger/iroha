export interface ToriiBrowserExplorerBlock {
  hash: string;
  height: number;
  created_at: string;
  prev_block_hash: string | null;
  transactions_hash: string | null;
  transactions_rejected: number;
  transactions_total: number;
}

export interface ToriiBrowserExplorerTransaction {
  authority: string;
  hash: string;
  block: number;
  created_at: string;
  executable: string;
  status: string;
}

export interface ToriiBrowserExplorerInstructionBox {
  /** Registered native instruction wire identifier. */
  wire_id: string;
  /** Lowercase SHA-256 of the exact decoded InstructionBox frame, without a prefix. */
  framed_sha256: string;
  /** Canonical padded base64 of one native Norito InstructionBox frame. */
  instruction: string;
}

export interface ToriiBrowserExplorerTransactionRejection {
  /** Canonical padded base64 of one native Norito TransactionRejectionReason frame. */
  reason: string;
  message: string;
}

export interface ToriiBrowserExplorerTransactionDetail extends ToriiBrowserExplorerTransaction {
  rejection_reason: ToriiBrowserExplorerTransactionRejection | null;
  executable_payload: unknown;
  metadata: unknown;
  nonce: number | null;
  signature: string;
  time_to_live: { ms: number } | null;
}

export interface ToriiBrowserExplorerInstruction {
  authority: string;
  created_at: string;
  kind: string;
  box: ToriiBrowserExplorerInstructionBox;
  transaction_hash: string;
  transaction_status: string;
  block: number;
  index: number;
}

export interface ToriiBrowserExplorerAssetDefinition {
  readonly id: string;
  /** Domain home when present; direct dataspace homes are separate. */
  readonly owning_domain: string | null;
  /** Exact immutable direct namespace; canonical nonzero u64 decimal text. */
  readonly owning_dataspace: string | null;
  readonly mintable: string;
  readonly logo: string | null;
  readonly metadata: Readonly<Record<string, unknown>>;
  readonly owned_by: string;
  readonly assets: number;
  readonly total_quantity: string;
  readonly locked_quantity: string | null;
  readonly circulating_quantity: string | null;
}
