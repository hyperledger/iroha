//! Bounds on untrusted RPC responses (spec §4.13.4, §8).
//!
//! Every response is read under a byte cap: the cap of its route
//! ([`json_rpc_response_cap`], [`http_response_cap`]) clipped to the
//! transport's [`HttpConfig::max_response_bytes`](crate::http::HttpConfig).
//! The caps are sized to the real answers of each route with headroom; a route
//! this table does not know is bounded by the transport ceiling only.
//!
//! A JSON body is then admitted in two steps, both derived from the byte cap
//! alone ([`JsonLimits::for_cap`]), so every validator applies the same bounds
//! to the same route whatever its hardware:
//!
//! 1. an allocation-free lexical preflight (`norito::json::preflight_slice`)
//!    rejects documents with more than one value per
//!    [`JSON_MIN_BYTES_PER_VALUE`] bytes of the cap or nested deeper than
//!    [`JSON_MAX_NESTING_DEPTH`]; recorded answers average 35 bytes or more
//!    per value and nest at most 11 deep;
//! 2. the `norito::json::Value` tree is built under a Norito decode budget
//!    that charges every array slot, object node and string before allocating
//!    it, capped at [`JSON_ALLOCATION_FACTOR`] times the byte cap. Recorded
//!    answers of a kilobyte or more allocate at most 6.5 times their size,
//!    and the large ones (receipts, TRON blocks) at most 5.3 times, below the
//!    factor even at their cap; object-heavy hostile bodies
//!    (`[{"aaaaaaaaaa":0},…]`) would allocate over 40 times theirs.
//!
//! A body over its cap or over either JSON bound is a failover error
//! ([`RpcError::ResponseTooLarge`](crate::http::RpcError::ResponseTooLarge),
//! [`RpcError::ResponseTooComplex`](crate::http::RpcError::ResponseTooComplex)),
//! never a panic or an unbounded allocation, so one hostile endpoint can cost
//! a node about `cap · (1 + JSON_ALLOCATION_FACTOR)` bytes per attempt at
//! most.

use norito::{
    DecodeLimits,
    json::{JsonPreflightLimits, Value},
};

/// One kibibyte.
const KIB: usize = 1024;
/// One mebibyte.
const MIB: usize = 1024 * KIB;

/// Fewest JSON source bytes per value a response may average. Recorded
/// answers of every route average 35 bytes or more per value.
pub const JSON_MIN_BYTES_PER_VALUE: usize = 8;
/// Deepest accepted JSON nesting (the root counts as one). Recorded TRON
/// blocks, the deepest answers, nest 11 deep; some contract types add a few
/// levels.
pub const JSON_MAX_NESTING_DEPTH: usize = 32;
/// Decoded-tree allocation budget as a multiple of the byte cap. Recorded
/// TRON blocks, the most object-heavy large answers, allocate about 5.3 times
/// their size.
pub const JSON_ALLOCATION_FACTOR: usize = 6;

/// Answers of small JSON-RPC calls and HTTP routes (a quantity, a hash, a
/// status object, an error).
pub const SMALL_RESPONSE_BYTES: usize = 64 * KIB;
/// `eth_getCode` and `eth_call`: contract code is at most tens of KiB.
pub const EVM_CODE_RESPONSE_BYTES: usize = MIB;
/// `eth_getProof`: an account proof and a few storage proofs.
pub const EVM_PROOF_RESPONSE_BYTES: usize = 4 * MIB;
/// `eth_getBlockBy*` with transaction hashes: a full BSC block lists a few
/// thousand hashes (under 0.5 MiB).
pub const EVM_BLOCK_RESPONSE_BYTES: usize = 4 * MIB;
/// `eth_getTransactionReceipt`: one receipt, whose logs are bounded by the
/// transaction gas limit.
pub const EVM_RECEIPT_RESPONSE_BYTES: usize = 16 * MIB;
/// Beacon `light_client/bootstrap` (about 55 KiB).
pub const BEACON_BOOTSTRAP_RESPONSE_BYTES: usize = MIB;
/// One beacon light-client update (about 60 KiB with its sync committee); the
/// `light_client/updates` cap is this times the requested count.
pub const BEACON_UPDATE_RESPONSE_BYTES: usize = 256 * KIB;
/// Most updates one `light_client/updates` request may ask for
/// (`MAX_REQUEST_LIGHT_CLIENT_UPDATES`).
pub const BEACON_MAX_UPDATES_PER_REQUEST: usize = 128;
/// One TRON block with full transactions: a 2 MB block prints as at most
/// about 10 MiB of JSON.
pub const TRON_BLOCK_RESPONSE_BYTES: usize = 16 * MIB;
/// TRON transaction info (logs are bounded by the energy limit).
pub const TRON_TRANSACTION_INFO_RESPONSE_BYTES: usize = 16 * MIB;
/// TRON `getcontractinfo` (runtime code and ABI).
pub const TRON_CONTRACT_RESPONSE_BYTES: usize = 4 * MIB;
/// TRON constant calls (a `TransactionExtention` with the return data).
pub const TRON_CONSTANT_CALL_RESPONSE_BYTES: usize = MIB;

/// Decode limits of one JSON body, derived from its byte cap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JsonLimits {
    /// Largest body.
    pub body_bytes: usize,
    /// Most JSON values (the root, every array and object entry).
    pub values: usize,
    /// Deepest nesting, counting the root as one.
    pub depth: usize,
    /// Most bytes the decoded tree may allocate (array slots, object nodes
    /// and strings).
    pub allocated_bytes: usize,
}

impl JsonLimits {
    /// The limits of a body capped at `max_bytes`: one value per
    /// [`JSON_MIN_BYTES_PER_VALUE`] bytes, [`JSON_MAX_NESTING_DEPTH`] levels and
    /// [`JSON_ALLOCATION_FACTOR`] times `max_bytes` of allocation.
    pub const fn for_cap(max_bytes: usize) -> Self {
        let values = max_bytes / JSON_MIN_BYTES_PER_VALUE;
        Self {
            body_bytes: max_bytes,
            values: if values == 0 { 1 } else { values },
            depth: JSON_MAX_NESTING_DEPTH,
            allocated_bytes: max_bytes.saturating_mul(JSON_ALLOCATION_FACTOR),
        }
    }

    /// The lexical preflight limits.
    pub fn preflight(&self) -> JsonPreflightLimits {
        JsonPreflightLimits::new(
            self.body_bytes,
            self.values,
            self.body_bytes,
            self.body_bytes,
            self.body_bytes,
            self.values,
            self.values,
            self.values,
            self.values,
            self.depth,
        )
    }

    /// The Norito decode budget of the `Value` tree.
    pub fn decode(&self) -> DecodeLimits {
        DecodeLimits::new(
            self.values,
            self.body_bytes,
            self.values,
            self.allocated_bytes,
            self.depth,
        )
    }
}

/// Why a body was not admitted as JSON.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsonBodyError {
    /// The body is not UTF-8 JSON (an HTML page, a truncated body).
    Malformed(String),
    /// The body is JSON but exceeds the value, depth or allocation limits.
    TooComplex(String),
}

/// Parses `body` as one JSON document within `limits`.
///
/// The lexical preflight runs first and allocates nothing; the tree is built
/// under a Norito decode budget, so a body over either bound is refused before
/// its allocation happens.
///
/// # Errors
/// [`JsonBodyError::Malformed`] for a body that is not UTF-8 JSON, and
/// [`JsonBodyError::TooComplex`] for one over the limits.
pub fn parse_json(body: &[u8], limits: JsonLimits) -> Result<Value, JsonBodyError> {
    if let Err(error) = norito::json::preflight_slice(body, limits.preflight()) {
        let detail = error.to_string();
        return Err(if error.resource_kind().is_some() {
            JsonBodyError::TooComplex(detail)
        } else {
            JsonBodyError::Malformed(detail)
        });
    }
    let text = std::str::from_utf8(body)
        .map_err(|_| JsonBodyError::Malformed("the body is not UTF-8".to_owned()))?;
    norito::with_decode_limits_scope(limits.decode(), || norito::json::parse_value(text)).map_err(
        |error| {
            let detail = error.to_string();
            if is_resource_error(&error) {
                JsonBodyError::TooComplex(detail)
            } else {
                JsonBodyError::Malformed(detail)
            }
        },
    )
}

/// Whether a JSON error is a refusal by the decode budget rather than a
/// syntax error.
fn is_resource_error(error: &norito::json::Error) -> bool {
    use norito::json::Error;
    matches!(
        error,
        Error::DecodeResourceLimit
            | Error::ScopedDecodeResource(_)
            | Error::DecodeResource(_)
            | Error::AllocationFailed
            | Error::NestingDepthExceeded { .. }
    )
}

/// The byte cap of the answer to JSON-RPC `method`, or `None` for a method
/// bounded by the transport ceiling only (`eth_getBlockReceipts`, whose
/// answer grows with everything a block logged, and unknown methods).
pub fn json_rpc_response_cap(method: &str) -> Option<usize> {
    Some(match method {
        "eth_chainId"
        | "eth_blockNumber"
        | "eth_estimateGas"
        | "eth_getTransactionCount"
        | "eth_maxPriorityFeePerGas"
        | "eth_gasPrice"
        | "eth_sendRawTransaction"
        | "net_version" => SMALL_RESPONSE_BYTES,
        "eth_getCode" | "eth_call" => EVM_CODE_RESPONSE_BYTES,
        "eth_getProof" => EVM_PROOF_RESPONSE_BYTES,
        "eth_getBlockByNumber" | "eth_getBlockByHash" => EVM_BLOCK_RESPONSE_BYTES,
        "eth_getTransactionReceipt" => EVM_RECEIPT_RESPONSE_BYTES,
        _ => return None,
    })
}

/// The byte cap of a JSON-RPC batch answer: the sum of its calls' caps, or
/// `None` when one call is bounded by the transport ceiling only.
pub fn json_rpc_batch_response_cap<S: AsRef<str>>(
    methods: impl IntoIterator<Item = S>,
) -> Option<usize> {
    methods
        .into_iter()
        .try_fold(0_usize, |total: usize, method| {
            json_rpc_response_cap(method.as_ref()).map(|cap| total.saturating_add(cap))
        })
}

/// The byte cap of the answer to HTTP route `path_and_query` (beacon API or
/// TRON HTTP), or `None` for a route bounded by the transport ceiling only
/// (TRON `getblockbylimitnext`, unknown routes).
///
/// The beacon `light_client/updates` cap grows with the `count` query
/// parameter, up to [`BEACON_MAX_UPDATES_PER_REQUEST`] updates.
pub fn http_response_cap(path_and_query: &str) -> Option<usize> {
    let (path, query) = path_and_query
        .split_once('?')
        .map_or((path_and_query, ""), |(path, query)| (path, query));
    if path.starts_with("/eth/v1/beacon/headers/") {
        return Some(SMALL_RESPONSE_BYTES);
    }
    if path.starts_with("/eth/v1/beacon/light_client/bootstrap/") {
        return Some(BEACON_BOOTSTRAP_RESPONSE_BYTES);
    }
    Some(match path {
        "/eth/v1/beacon/light_client/finality_update"
        | "/eth/v1/beacon/light_client/optimistic_update" => BEACON_UPDATE_RESPONSE_BYTES,
        "/eth/v1/beacon/light_client/updates" => {
            BEACON_UPDATE_RESPONSE_BYTES.saturating_mul(beacon_update_count(query))
        }
        "/wallet/getnowblock"
        | "/walletsolidity/getnowblock"
        | "/wallet/getblockbynum"
        | "/walletsolidity/getblockbynum" => TRON_BLOCK_RESPONSE_BYTES,
        "/wallet/gettransactioninfobyid" | "/walletsolidity/gettransactioninfobyid" => {
            TRON_TRANSACTION_INFO_RESPONSE_BYTES
        }
        "/wallet/getcontractinfo" => TRON_CONTRACT_RESPONSE_BYTES,
        "/wallet/triggerconstantcontract" | "/walletsolidity/triggerconstantcontract" => {
            TRON_CONSTANT_CALL_RESPONSE_BYTES
        }
        "/wallet/broadcasthex" | "/wallet/getnextmaintenancetime" => SMALL_RESPONSE_BYTES,
        // TODO(WP9): TRON range segments download full blocks (tens of MiB per
        // 100 blocks); the builders should step by bytes or read headers only,
        // after which this route gets a cap of its own.
        _ => return None,
    })
}

/// The `count` of a `light_client/updates` query, clamped to
/// `1..=BEACON_MAX_UPDATES_PER_REQUEST` (an absent or unreadable count reads
/// as the maximum).
fn beacon_update_count(query: &str) -> usize {
    query
        .split('&')
        .find_map(|pair| pair.strip_prefix("count="))
        .and_then(|count| count.parse::<usize>().ok())
        .map_or(BEACON_MAX_UPDATES_PER_REQUEST, |count| {
            count.clamp(1, BEACON_MAX_UPDATES_PER_REQUEST)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_derive_from_the_cap_alone() {
        let limits = JsonLimits::for_cap(64 * KIB);
        assert_eq!(limits.body_bytes, 64 * KIB);
        assert_eq!(limits.values, 8 * KIB);
        assert_eq!(limits.depth, JSON_MAX_NESTING_DEPTH);
        assert_eq!(limits.allocated_bytes, 384 * KIB);
        assert_eq!(JsonLimits::for_cap(3).values, 1);
        assert_eq!(JsonLimits::for_cap(usize::MAX).allocated_bytes, usize::MAX);
        assert_eq!(limits.decode().max_total_allocated_bytes(), 384 * KIB);
        assert_eq!(limits.decode().max_nesting_depth(), JSON_MAX_NESTING_DEPTH);
        assert_eq!(limits.preflight(), limits.preflight());
    }

    #[test]
    fn ordinary_bodies_parse() {
        let value = parse_json(br#"{"a":[1,"x",{"b":null}]}"#, JsonLimits::for_cap(1024))
            .expect("ordinary JSON");
        assert_eq!(
            value.get("a").and_then(Value::as_array).map(Vec::len),
            Some(3)
        );
    }

    #[test]
    fn malformed_bodies_are_not_json() {
        for body in [&b"<html>"[..], b"{", b"\xff", b"[1,]", b"{} x"] {
            assert!(
                matches!(
                    parse_json(body, JsonLimits::for_cap(1024)),
                    Err(JsonBodyError::Malformed(_))
                ),
                "{body:?}"
            );
        }
    }

    #[test]
    fn element_heavy_bodies_are_too_complex() {
        // 2 bytes per value against a floor of 8.
        let body = format!("[{}0]", "0,".repeat(1_000));
        let error =
            parse_json(body.as_bytes(), JsonLimits::for_cap(4 * KIB)).expect_err("element heavy");
        assert!(matches!(error, JsonBodyError::TooComplex(_)), "{error:?}");
    }

    #[test]
    fn deep_bodies_are_too_complex() {
        let depth = JSON_MAX_NESTING_DEPTH + 1;
        let body = format!("{}{}", "[".repeat(depth), "]".repeat(depth));
        let error =
            parse_json(body.as_bytes(), JsonLimits::for_cap(64 * KIB)).expect_err("too deep");
        assert!(matches!(error, JsonBodyError::TooComplex(_)), "{error:?}");
        let ok = format!(
            "{}{}",
            "[".repeat(JSON_MAX_NESTING_DEPTH),
            "]".repeat(JSON_MAX_NESTING_DEPTH)
        );
        assert!(parse_json(ok.as_bytes(), JsonLimits::for_cap(64 * KIB)).is_ok());
    }

    #[test]
    fn object_heavy_bodies_exceed_the_allocation_budget() {
        // Each `{"aaaaaaaaaa":0},` is 2 values in 17 bytes (within the value
        // floor) but allocates a whole B-tree leaf of several hundred bytes.
        let body = format!(
            "[{}{{\"aaaaaaaaaa\":0}}]",
            "{\"aaaaaaaaaa\":0},".repeat(2_000)
        );
        let limits = JsonLimits::for_cap(body.len());
        assert!(norito::json::preflight_slice(body.as_bytes(), limits.preflight()).is_ok());
        let error = parse_json(body.as_bytes(), limits).expect_err("object heavy");
        assert!(matches!(error, JsonBodyError::TooComplex(_)), "{error:?}");
    }

    /// Every recorded JSON answer parses under the limits of a cap only
    /// slightly above its own size (25 % plus 4 KiB), so the value floor and
    /// the allocation factor admit real answers close to a route's cap.
    #[test]
    fn recorded_answers_fit_limits_derived_from_a_tight_cap() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/sccp/rpc");
        let mut pending = vec![root];
        let mut checked = 0;
        while let Some(dir) = pending.pop() {
            for entry in std::fs::read_dir(&dir).expect("fixture dir") {
                let path = entry.expect("entry").path();
                if path.is_dir() {
                    pending.push(path);
                    continue;
                }
                if path.extension().is_none_or(|extension| extension != "json") {
                    continue;
                }
                let body = std::fs::read(&path).expect("fixture");
                if norito::json::parse_value(std::str::from_utf8(&body).expect("utf8")).is_err() {
                    continue;
                }
                parse_json(&body, JsonLimits::for_cap(body.len() * 5 / 4 + 4 * KIB))
                    .unwrap_or_else(|error| panic!("{}: {error:?}", path.display()));
                checked += 1;
            }
        }
        assert!(checked > 40, "{checked} fixtures");
    }

    #[test]
    fn json_rpc_caps_follow_the_method() {
        assert_eq!(
            json_rpc_response_cap("eth_chainId"),
            Some(SMALL_RESPONSE_BYTES)
        );
        assert_eq!(
            json_rpc_response_cap("eth_getBlockByNumber"),
            Some(EVM_BLOCK_RESPONSE_BYTES)
        );
        assert_eq!(
            json_rpc_response_cap("eth_getProof"),
            Some(EVM_PROOF_RESPONSE_BYTES)
        );
        assert_eq!(
            json_rpc_response_cap("eth_call"),
            Some(EVM_CODE_RESPONSE_BYTES)
        );
        assert_eq!(
            json_rpc_response_cap("eth_getTransactionReceipt"),
            Some(EVM_RECEIPT_RESPONSE_BYTES)
        );
        assert_eq!(json_rpc_response_cap("eth_getBlockReceipts"), None);
        assert_eq!(json_rpc_response_cap("debug_traceBlock"), None);
        assert_eq!(
            json_rpc_batch_response_cap(["eth_blockNumber", "eth_getProof"]),
            Some(SMALL_RESPONSE_BYTES + EVM_PROOF_RESPONSE_BYTES)
        );
        assert_eq!(
            json_rpc_batch_response_cap(["eth_blockNumber", "eth_getBlockReceipts"]),
            None
        );
    }

    #[test]
    fn http_caps_follow_the_route() {
        assert_eq!(
            http_response_cap("/eth/v1/beacon/headers/finalized"),
            Some(SMALL_RESPONSE_BYTES)
        );
        assert_eq!(
            http_response_cap("/eth/v1/beacon/light_client/bootstrap/0xab"),
            Some(BEACON_BOOTSTRAP_RESPONSE_BYTES)
        );
        assert_eq!(
            http_response_cap("/eth/v1/beacon/light_client/finality_update"),
            Some(BEACON_UPDATE_RESPONSE_BYTES)
        );
        assert_eq!(
            http_response_cap("/eth/v1/beacon/light_client/updates?start_period=7&count=3"),
            Some(3 * BEACON_UPDATE_RESPONSE_BYTES)
        );
        assert_eq!(
            http_response_cap("/eth/v1/beacon/light_client/updates?count=100000"),
            Some(BEACON_MAX_UPDATES_PER_REQUEST * BEACON_UPDATE_RESPONSE_BYTES)
        );
        assert_eq!(
            http_response_cap("/eth/v1/beacon/light_client/updates?start_period=7"),
            Some(BEACON_MAX_UPDATES_PER_REQUEST * BEACON_UPDATE_RESPONSE_BYTES)
        );
        assert_eq!(
            http_response_cap("/eth/v1/beacon/light_client/updates?count=0"),
            Some(BEACON_UPDATE_RESPONSE_BYTES)
        );
        assert_eq!(
            http_response_cap("/wallet/getblockbynum"),
            Some(TRON_BLOCK_RESPONSE_BYTES)
        );
        assert_eq!(
            http_response_cap("/walletsolidity/gettransactioninfobyid"),
            Some(TRON_TRANSACTION_INFO_RESPONSE_BYTES)
        );
        assert_eq!(
            http_response_cap("/wallet/getcontractinfo"),
            Some(TRON_CONTRACT_RESPONSE_BYTES)
        );
        assert_eq!(
            http_response_cap("/walletsolidity/triggerconstantcontract"),
            Some(TRON_CONSTANT_CALL_RESPONSE_BYTES)
        );
        assert_eq!(
            http_response_cap("/wallet/broadcasthex"),
            Some(SMALL_RESPONSE_BYTES)
        );
        assert_eq!(http_response_cap("/wallet/getblockbylimitnext"), None);
        assert_eq!(http_response_cap("/blob"), None);
    }

    #[test]
    fn update_counts_are_clamped() {
        assert_eq!(beacon_update_count("count=5"), 5);
        assert_eq!(beacon_update_count("start_period=1&count=2"), 2);
        assert_eq!(
            beacon_update_count("count=x"),
            BEACON_MAX_UPDATES_PER_REQUEST
        );
        assert_eq!(beacon_update_count(""), BEACON_MAX_UPDATES_PER_REQUEST);
        assert_eq!(beacon_update_count("count=0"), 1);
    }
}
