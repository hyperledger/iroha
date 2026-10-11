//! Ethereum beacon API client (spec §4.13.3, §7.2, §8).
//!
//! [`BeaconClient`] serves the JSON header route
//! (`/eth/v1/beacon/headers/{block_id}`). The light-client routes (bootstraps,
//! sync-committee period updates and finality updates) are fetched as JSON by
//! [`crate::builders::ethereum`] through [`BeaconClient::transport`].
//!
//! Answers are bounded by their route's byte cap
//! ([`crate::limits::http_response_cap`]: the `light_client/updates` cap grows
//! with the requested count) and the header answer is decoded inside its
//! attempt, so an endpoint that answers with malformed data is discredited.
//!
//! Nothing is verified here: fork handling and sync-committee verification
//! belong to `iroha_sccp`.

use crate::{
    evm::{HexError, format_data, parse_data_array},
    http::{
        HttpTransport, RpcError, expect_object, invalid_response, optional, required, required_str,
    },
};

/// A beacon block identifier of the header route.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BeaconBlockId(String);

impl BeaconBlockId {
    /// `head`.
    pub fn head() -> Self {
        Self("head".to_owned())
    }

    /// `finalized`.
    pub fn finalized() -> Self {
        Self("finalized".to_owned())
    }

    /// `genesis`.
    pub fn genesis() -> Self {
        Self("genesis".to_owned())
    }

    /// A slot.
    pub fn slot(slot: u64) -> Self {
        Self(slot.to_string())
    }

    /// A block root.
    pub fn root(root: &[u8; 32]) -> Self {
        Self(format_data(root))
    }

    /// The path segment.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A beacon block header as returned by the header route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BeaconHeader {
    /// Block root reported by the endpoint.
    pub root: [u8; 32],
    /// Whether the endpoint considers the block canonical.
    pub canonical: bool,
    /// `slot`.
    pub slot: u64,
    /// `proposer_index`.
    pub proposer_index: u64,
    /// `parent_root`.
    pub parent_root: [u8; 32],
    /// `state_root`.
    pub state_root: [u8; 32],
    /// `body_root`.
    pub body_root: [u8; 32],
    /// Proposer signature.
    pub signature: [u8; 96],
    /// `execution_optimistic`, when reported.
    pub execution_optimistic: Option<bool>,
    /// `finalized`, when reported.
    pub finalized: Option<bool>,
}

/// Beacon API client of the JSON header route; [`Self::transport`] serves the
/// JSON light-client routes that [`crate::builders::ethereum`] fetches.
#[derive(Debug)]
pub struct BeaconClient {
    transport: HttpTransport,
}

impl BeaconClient {
    /// A client over `transport`.
    pub fn new(transport: HttpTransport) -> Self {
        Self { transport }
    }

    /// The underlying transport.
    pub fn transport(&self) -> &HttpTransport {
        &self.transport
    }

    /// `GET /eth/v1/beacon/headers/finalized` (JSON).
    ///
    /// # Errors
    /// Any [`RpcError`].
    pub fn finalized_header(&self) -> Result<BeaconHeader, RpcError> {
        self.header(&BeaconBlockId::finalized())
    }

    /// `GET /eth/v1/beacon/headers/{block_id}` (JSON).
    ///
    /// # Errors
    /// Any [`RpcError`]; an unknown block is an HTTP 404 [`RpcError::Status`].
    pub fn header(&self, block: &BeaconBlockId) -> Result<BeaconHeader, RpcError> {
        self.transport.get_json_then(
            &format!("/eth/v1/beacon/headers/{}", block.as_str()),
            |value| parse_header_response(&value),
        )
    }
}

/// A beacon API `uint64`: a decimal string without sign or leading zeros.
///
/// # Errors
/// [`RpcError::InvalidResponse`] for anything else.
pub fn parse_decimal_u64(text: &str, what: &str) -> Result<u64, RpcError> {
    let canonical = !text.is_empty()
        && text.bytes().all(|byte| byte.is_ascii_digit())
        && (text == "0" || !text.starts_with('0'));
    if !canonical {
        return Err(invalid_response(format!(
            "{what} is not a canonical decimal uint64"
        )));
    }
    text.parse()
        .map_err(|_| invalid_response(format!("{what} exceeds uint64")))
}

fn root_field<const N: usize>(
    map: &norito::json::Map,
    key: &str,
    what: &str,
) -> Result<[u8; N], RpcError> {
    parse_data_array::<N>(required_str(map, key, what)?)
        .map_err(|error: HexError| invalid_response(format!("{what}.{key}: {error}")))
}

fn optional_bool(map: &norito::json::Map, key: &str, what: &str) -> Result<Option<bool>, RpcError> {
    optional(map, key)
        .map(|value| {
            value
                .as_bool()
                .ok_or_else(|| invalid_response(format!("{what}.{key} is not a boolean")))
        })
        .transpose()
}

fn parse_header_response(value: &norito::json::Value) -> Result<BeaconHeader, RpcError> {
    let outer = expect_object(value, "header response")?;
    let data = expect_object(required(outer, "data", "header response")?, "header data")?;
    let header = expect_object(required(data, "header", "header data")?, "header")?;
    let message = expect_object(required(header, "message", "header")?, "header message")?;
    let canonical = required(data, "canonical", "header data")?
        .as_bool()
        .ok_or_else(|| invalid_response("header data.canonical is not a boolean"))?;
    Ok(BeaconHeader {
        root: root_field(data, "root", "header data")?,
        canonical,
        slot: parse_decimal_u64(
            required_str(message, "slot", "header message")?,
            "header message.slot",
        )?,
        proposer_index: parse_decimal_u64(
            required_str(message, "proposer_index", "header message")?,
            "header message.proposer_index",
        )?,
        parent_root: root_field(message, "parent_root", "header message")?,
        state_root: root_field(message, "state_root", "header message")?,
        body_root: root_field(message, "body_root", "header message")?,
        signature: root_field(header, "signature", "header")?,
        execution_optimistic: optional_bool(outer, "execution_optimistic", "header response")?,
        finalized: optional_bool(outer, "finalized", "header response")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decimals_are_strict() {
        assert_eq!(parse_decimal_u64("0", "x").expect("zero"), 0);
        assert_eq!(
            parse_decimal_u64("15301120", "x").expect("slot"),
            15_301_120
        );
        for bad in ["", "01", "+1", "-1", "1.0", "0x10", "18446744073709551616"] {
            assert!(parse_decimal_u64(bad, "x").is_err(), "{bad}");
        }
    }

    #[test]
    fn block_ids_spell_route_segments() {
        assert_eq!(BeaconBlockId::head().as_str(), "head");
        assert_eq!(BeaconBlockId::finalized().as_str(), "finalized");
        assert_eq!(BeaconBlockId::genesis().as_str(), "genesis");
        assert_eq!(BeaconBlockId::slot(42).as_str(), "42");
        assert_eq!(
            BeaconBlockId::root(&[0xab; 32]).as_str(),
            format!("0x{}", "ab".repeat(32))
        );
    }

    #[test]
    fn header_responses_parse_strictly() {
        let text = format!(
            r#"{{"data":{{"root":"0x{r}","canonical":true,"header":{{"message":{{"slot":"7","proposer_index":"9","parent_root":"0x{r}","state_root":"0x{r}","body_root":"0x{r}"}},"signature":"0x{s}"}}}},"execution_optimistic":false}}"#,
            r = "01".repeat(32),
            s = "02".repeat(96),
        );
        let value = norito::json::parse_value(&text).expect("json");
        let header = parse_header_response(&value).expect("header");
        assert_eq!(header.slot, 7);
        assert_eq!(header.proposer_index, 9);
        assert!(header.canonical);
        assert_eq!(header.signature, [2; 96]);
        assert_eq!(header.execution_optimistic, Some(false));
        assert_eq!(header.finalized, None);
        let bad_slot =
            norito::json::parse_value(&text.replace(r#""slot":"7""#, r#""slot":7"#)).expect("json");
        assert!(parse_header_response(&bad_slot).is_err());
        let short_root =
            norito::json::parse_value(&text.replacen(&"01".repeat(32), "01", 1)).expect("json");
        assert!(parse_header_response(&short_root).is_err());
    }
}
