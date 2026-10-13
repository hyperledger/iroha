//! Incremental JSON receipt decoding with one canonical RLP spool and bounded metadata.

use crate::{
    RpcError,
    evm::{parse_data_array, parse_quantity_u64},
    http::{decode_json_rpc_response, invalid_response},
};
use iroha_sccp::ethereum_source::{rlp_encode_bytes, rlp_encode_u64};
use norito::json::{Map, Value};
use std::io::{BufReader, Read as _};

/// Consensus receipt bytes plus the original source locator used for RPC consistency checks.
pub struct Receipt {
    pub bytes: Vec<u8>,
    pub transaction_hash: [u8; 32],
    pub transaction_index: u64,
    pub block_hash: [u8; 32],
    pub block_number: u64,
    pub cumulative_gas: u64,
    pub gas_used: u64,
}

struct Json<'a> {
    input: BufReader<&'a mut dyn std::io::Read>,
    look: Option<u8>,
    metadata_values: usize,
}
impl<'a> Json<'a> {
    fn new(input: &'a mut dyn std::io::Read) -> Self {
        Self {
            input: BufReader::with_capacity(8192, input),
            look: None,
            metadata_values: 0,
        }
    }
    fn byte(&mut self) -> Result<Option<u8>, RpcError> {
        if let Some(byte) = self.look.take() {
            return Ok(Some(byte));
        }
        let mut byte = [0];
        self.input
            .read(&mut byte)
            .map(|n| (n != 0).then_some(byte[0]))
            .map_err(|_| invalid_response("receipt stream read failed"))
    }
    fn need(&mut self) -> Result<u8, RpcError> {
        self.byte()?
            .ok_or_else(|| invalid_response("truncated receipt JSON"))
    }
    fn peek(&mut self) -> Result<Option<u8>, RpcError> {
        if self.look.is_none() {
            self.look = self.byte()?;
        }
        Ok(self.look)
    }
    fn ws(&mut self) -> Result<(), RpcError> {
        while self
            .peek()?
            .is_some_and(|byte| matches!(byte, b' ' | b'\n' | b'\r' | b'\t'))
        {
            self.byte()?;
        }
        Ok(())
    }
    fn expect(&mut self, expected: u8) -> Result<(), RpcError> {
        self.ws()?;
        if self.need()? != expected {
            return Err(invalid_response("invalid receipt JSON delimiter"));
        }
        Ok(())
    }
    fn end_or_next(&mut self, first: &mut bool, end: u8) -> Result<bool, RpcError> {
        self.ws()?;
        if self.peek()? == Some(end) {
            self.byte()?;
            return Ok(false);
        }
        if !*first {
            self.expect(b',')?;
            self.ws()?;
            if self.peek()? == Some(end) {
                return Err(invalid_response("trailing receipt JSON comma"));
            }
        }
        *first = false;
        Ok(true)
    }
    fn member(&mut self, first: &mut bool) -> Result<Option<String>, RpcError> {
        if !self.end_or_next(first, b'}')? {
            return Ok(None);
        }
        let key = self.text(128)?;
        self.expect(b':')?;
        Ok(Some(key))
    }
    fn hex_digit(byte: u8) -> Result<u8, RpcError> {
        match byte {
            b'0'..=b'9' => Ok(byte - b'0'),
            b'a'..=b'f' => Ok(byte - b'a' + 10),
            b'A'..=b'F' => Ok(byte - b'A' + 10),
            _ => Err(invalid_response("invalid receipt hexadecimal digit")),
        }
    }
    fn unicode(&mut self) -> Result<u16, RpcError> {
        let mut out = 0;
        for _ in 0..4 {
            out = (out << 4) | u16::from(Self::hex_digit(self.need()?)?);
        }
        Ok(out)
    }
    fn character(&mut self) -> Result<Option<char>, RpcError> {
        let byte = self.need()?;
        if byte == b'"' {
            return Ok(None);
        }
        if byte < 32 {
            return Err(invalid_response("control byte in receipt string"));
        }
        if byte == b'\\' {
            return Ok(Some(match self.need()? {
                b'"' => '"',
                b'\\' => '\\',
                b'/' => '/',
                b'b' => '\u{8}',
                b'f' => '\u{c}',
                b'n' => '\n',
                b'r' => '\r',
                b't' => '\t',
                b'u' => {
                    let first = self.unicode()?;
                    let point = if (0xd800..=0xdbff).contains(&first) {
                        if self.need()? != b'\\' || self.need()? != b'u' {
                            return Err(invalid_response("missing receipt Unicode surrogate"));
                        }
                        let second = self.unicode()?;
                        if !(0xdc00..=0xdfff).contains(&second) {
                            return Err(invalid_response("invalid receipt Unicode surrogate"));
                        }
                        0x10000 + ((u32::from(first) - 0xd800) << 10) + (u32::from(second) - 0xdc00)
                    } else {
                        u32::from(first)
                    };
                    char::from_u32(point)
                        .ok_or_else(|| invalid_response("invalid receipt Unicode scalar"))?
                }
                _ => return Err(invalid_response("invalid receipt JSON escape")),
            }));
        }
        if byte < 128 {
            return Ok(Some(char::from(byte)));
        }
        let length = match byte {
            0xc2..=0xdf => 2,
            0xe0..=0xef => 3,
            0xf0..=0xf4 => 4,
            _ => return Err(invalid_response("invalid receipt UTF-8")),
        };
        let mut bytes = [0; 4];
        bytes[0] = byte;
        for cell in &mut bytes[1..length] {
            *cell = self.need()?;
        }
        let text = std::str::from_utf8(&bytes[..length])
            .map_err(|_| invalid_response("invalid receipt UTF-8"))?;
        Ok(text.chars().next())
    }
    fn text(&mut self, limit: usize) -> Result<String, RpcError> {
        self.expect(b'"')?;
        let mut out = String::new();
        while let Some(ch) = self.character()? {
            if out.len().saturating_add(ch.len_utf8()) > limit {
                return Err(invalid_response(
                    "receipt metadata string exceeds its bound",
                ));
            }
            out.push(ch);
        }
        Ok(out)
    }
    fn hex(&mut self, limit: usize) -> Result<Vec<u8>, RpcError> {
        self.expect(b'"')?;
        if self.character()? != Some('0') || self.character()? != Some('x') {
            return Err(invalid_response("receipt hex lacks prefix"));
        }
        let mut out = Vec::new();
        while let Some(first) = self.character()? {
            let second = self
                .character()?
                .ok_or_else(|| invalid_response("odd receipt hex length"))?;
            if !first.is_ascii() || !second.is_ascii() {
                return Err(invalid_response("non-ASCII receipt hex"));
            }
            if out.len() == limit {
                return Err(invalid_response(
                    "canonical receipt exceeds its caller byte budget",
                ));
            }
            out.try_reserve(1)
                .map_err(|_| invalid_response("receipt allocation unavailable"))?;
            out.push((Self::hex_digit(first as u8)? << 4) | Self::hex_digit(second as u8)?);
        }
        Ok(out)
    }
    fn scalar(&mut self) -> Result<Value, RpcError> {
        self.ws()?;
        if self.peek()? == Some(b'"') {
            return self.text(4096).map(Value::from);
        }
        let mut token = Vec::new();
        while self
            .peek()?
            .is_some_and(|byte| !matches!(byte, b',' | b']' | b'}' | b' ' | b'\n' | b'\r' | b'\t'))
        {
            if token.len() == 128 {
                return Err(invalid_response("receipt scalar exceeds bound"));
            }
            token.push(self.need()?);
        }
        norito::json::from_slice(&token)
            .map_err(|_| invalid_response("invalid receipt JSON scalar"))
    }
    fn skip(&mut self, depth: usize) -> Result<(), RpcError> {
        if depth > 32 {
            return Err(invalid_response("receipt JSON nesting exceeds bound"));
        }
        self.ws()?;
        match self.peek()? {
            Some(b'"') => {
                self.expect(b'"')?;
                while self.character()?.is_some() {}
            }
            Some(b'{') => {
                self.expect(b'{')?;
                let mut first = true;
                while self.member(&mut first)?.is_some() {
                    self.skip(depth + 1)?;
                }
            }
            Some(b'[') => {
                self.expect(b'[')?;
                let mut first = true;
                while self.end_or_next(&mut first, b']')? {
                    self.skip(depth + 1)?;
                }
            }
            _ => {
                self.scalar()?;
            }
        }
        Ok(())
    }

    fn value(&mut self, depth: usize) -> Result<Value, RpcError> {
        self.metadata_values += 1;
        if self.metadata_values > 128 {
            return Err(invalid_response("receipt envelope metadata exceeds bound"));
        }
        if depth > 32 {
            return Err(invalid_response("receipt JSON nesting exceeds bound"));
        }
        self.ws()?;
        match self.peek()? {
            Some(b'{') => {
                self.expect(b'{')?;
                let mut first = true;
                let mut map = Map::new();
                while let Some(key) = self.member(&mut first)? {
                    if map.len() == 64 || map.contains_key(&key) {
                        return Err(invalid_response(
                            "receipt metadata object exceeds bound or repeats a key",
                        ));
                    }
                    map.insert(key, self.value(depth + 1)?);
                }
                Ok(Value::Object(map))
            }
            Some(b'[') => {
                self.expect(b'[')?;
                let mut first = true;
                let mut values = Vec::new();
                while self.end_or_next(&mut first, b']')? {
                    if values.len() == 64 {
                        return Err(invalid_response("receipt metadata array exceeds bound"));
                    }
                    values.push(self.value(depth + 1)?);
                }
                Ok(Value::Array(values))
            }
            _ => self.scalar(),
        }
    }
}

fn append(out: &mut Vec<u8>, bytes: &[u8], limit: usize) -> Result<(), RpcError> {
    if out
        .len()
        .checked_add(bytes.len())
        .is_none_or(|len| len > limit)
    {
        return Err(invalid_response(
            "canonical receipt exceeds its caller byte budget",
        ));
    }
    out.try_reserve(bytes.len())
        .map_err(|_| invalid_response("receipt allocation unavailable"))?;
    out.extend_from_slice(bytes);
    Ok(())
}
fn wrap(mut payload: Vec<u8>, list: bool, limit: usize) -> Result<Vec<u8>, RpcError> {
    if !list && payload.len() == 1 && payload[0] < 128 {
        return Ok(payload);
    }
    let mut prefix = [0; 9];
    let length = payload.len();
    let count = if length < 56 {
        prefix[0] = if list { 0xc0 } else { 0x80 }
            + u8::try_from(length)
                .map_err(|_| invalid_response("short RLP receipt length exceeds one byte"))?;
        1
    } else {
        let bytes = length.to_be_bytes();
        let start = bytes
            .iter()
            .position(|byte| *byte != 0)
            .unwrap_or(bytes.len() - 1);
        let n = bytes.len() - start;
        prefix[0] = if list { 0xf7 } else { 0xb7 }
            + u8::try_from(n)
                .map_err(|_| invalid_response("RLP receipt length prefix exceeds one byte"))?;
        prefix[1..=n].copy_from_slice(&bytes[start..]);
        n + 1
    };
    let old = payload.len();
    append(&mut payload, &prefix[..count], limit)?;
    payload.copy_within(0..old, count);
    payload[..count].copy_from_slice(&prefix[..count]);
    Ok(payload)
}
fn word(value: &Value) -> Result<u64, RpcError> {
    parse_quantity_u64(
        value
            .as_str()
            .ok_or_else(|| invalid_response("receipt quantity is not text"))?,
    )
    .map_err(|_| invalid_response("invalid receipt quantity"))
}
fn hash(value: &Value) -> Result<[u8; 32], RpcError> {
    parse_data_array(
        value
            .as_str()
            .ok_or_else(|| invalid_response("receipt hash is not text"))?,
    )
    .map_err(|_| invalid_response("invalid receipt hash"))
}
fn required<'a>(map: &'a Map, name: &str) -> Result<&'a Value, RpcError> {
    map.get(name)
        .ok_or_else(|| invalid_response("missing receipt field"))
}

fn logs(json: &mut Json<'_>, limit: usize) -> Result<Vec<u8>, RpcError> {
    json.expect(b'[')?;
    let mut first = true;
    let mut out = Vec::new();
    while json.end_or_next(&mut first, b']')? {
        json.expect(b'{')?;
        let mut field = true;
        let mut address = None;
        let mut topics = None;
        let mut data = None;
        let mut seen = std::collections::BTreeSet::new();
        while let Some(key) = json.member(&mut field)? {
            if !seen.insert(key.clone()) || seen.len() > 64 {
                return Err(invalid_response(
                    "receipt log repeats a field or exceeds bound",
                ));
            }
            match key.as_str() {
                "address" => {
                    let bytes = json.hex(20)?;
                    if bytes.len() != 20 {
                        return Err(invalid_response("invalid log address"));
                    }
                    address = Some(rlp_encode_bytes(&bytes));
                }
                "topics" => {
                    json.expect(b'[')?;
                    let mut first = true;
                    let mut bytes = Vec::new();
                    let mut count = 0;
                    while json.end_or_next(&mut first, b']')? {
                        count += 1;
                        if count > 4 {
                            return Err(invalid_response("receipt log has more than four topics"));
                        }
                        let topic = json.hex(32)?;
                        if topic.len() != 32 {
                            return Err(invalid_response("invalid log topic"));
                        }
                        append(&mut bytes, &rlp_encode_bytes(&topic), limit)?;
                    }
                    topics = Some(wrap(bytes, true, limit)?);
                }
                "data" => {
                    data = Some(wrap(
                        json.hex(limit.saturating_sub(out.len()))?,
                        false,
                        limit,
                    )?)
                }
                _ => {
                    json.skip(0)?;
                }
            }
        }
        let mut item = address.ok_or_else(|| invalid_response("missing log address"))?;
        append(
            &mut item,
            &topics.ok_or_else(|| invalid_response("missing log topics"))?,
            limit,
        )?;
        append(
            &mut item,
            &data.ok_or_else(|| invalid_response("missing log data"))?,
            limit,
        )?;
        append(&mut out, &wrap(item, true, limit)?, limit)?;
    }
    wrap(out, true, limit)
}

fn receipt(json: &mut Json<'_>, limit: usize) -> Result<Receipt, RpcError> {
    json.expect(b'{')?;
    let mut first = true;
    let mut fields = Map::new();
    let mut encoded_logs = None;
    while let Some(key) = json.member(&mut first)? {
        if fields.contains_key(&key) || fields.len() > 64 {
            return Err(invalid_response("receipt repeats a field or exceeds bound"));
        }
        if key == "logs" {
            encoded_logs = Some(logs(json, limit)?);
            fields.insert(key, Value::Null);
        } else if matches!(
            key.as_str(),
            "status"
                | "cumulativeGasUsed"
                | "logsBloom"
                | "type"
                | "transactionHash"
                | "transactionIndex"
                | "blockHash"
                | "blockNumber"
                | "gasUsed"
        ) {
            fields.insert(key, json.scalar()?);
        } else {
            json.skip(0)?;
            fields.insert(key, Value::Null);
        }
    }
    let status = word(required(&fields, "status")?)?;
    if status > 1 {
        return Err(invalid_response("invalid receipt status"));
    }
    let cumulative = word(required(&fields, "cumulativeGasUsed")?)?;
    let bloom = crate::evm::parse_data(
        required(&fields, "logsBloom")?
            .as_str()
            .ok_or_else(|| invalid_response("receipt bloom is not text"))?,
    )
    .map_err(|_| invalid_response("invalid bloom hex"))?;
    if bloom.len() != 256 {
        return Err(invalid_response("invalid receipt bloom length"));
    }
    let mut bytes = rlp_encode_u64(status);
    append(&mut bytes, &rlp_encode_u64(cumulative), limit)?;
    append(&mut bytes, &rlp_encode_bytes(&bloom), limit)?;
    append(
        &mut bytes,
        &encoded_logs.ok_or_else(|| invalid_response("missing receipt logs"))?,
        limit,
    )?;
    bytes = wrap(bytes, true, limit)?;
    let kind = fields.get("type").map(word).transpose()?.unwrap_or(0);
    if kind > 127 {
        return Err(invalid_response("invalid typed receipt prefix"));
    }
    if kind > 0 {
        let old = bytes.len();
        append(&mut bytes, &[0], limit)?;
        bytes.copy_within(0..old, 1);
        bytes[0] =
            u8::try_from(kind).map_err(|_| invalid_response("invalid typed receipt prefix"))?;
    }
    Ok(Receipt {
        bytes,
        transaction_hash: hash(required(&fields, "transactionHash")?)?,
        transaction_index: word(required(&fields, "transactionIndex")?)?,
        block_hash: hash(required(&fields, "blockHash")?)?,
        block_number: word(required(&fields, "blockNumber")?)?,
        cumulative_gas: cumulative,
        gas_used: word(required(&fields, "gasUsed")?)?,
    })
}

/// Decode one exact JSON-RPC result without materializing the receipt's JSON tree.
pub fn decode(
    input: &mut dyn std::io::Read,
    id: u64,
    endpoint: &str,
    limit: usize,
) -> Result<Receipt, RpcError> {
    let mut json = Json::new(input);
    json.expect(b'{')?;
    let mut first = true;
    let mut envelope = Map::new();
    let mut output = None;
    while let Some(key) = json.member(&mut first)? {
        if envelope.contains_key(&key) || envelope.len() > 16 {
            return Err(invalid_response("invalid receipt response envelope"));
        }
        if key == "result" {
            output = Some(receipt(&mut json, limit)?);
            envelope.insert(key, Value::Null);
        } else {
            envelope.insert(key, json.value(0)?);
        }
    }
    json.ws()?;
    if json.peek()?.is_some() {
        return Err(invalid_response("trailing receipt response bytes"));
    }
    decode_json_rpc_response(Value::Object(envelope), Some(id), endpoint)?;
    output.ok_or_else(|| invalid_response("receipt result is absent"))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn receipt(data: &str) -> String {
        format!(
            r#"{{"status":"0x1","type":"0x2","cumulativeGasUsed":"0x5208","logsBloom":"0x{}","logs":[{{"data":"{}","topics":["0x{}"],"address":"0x{}","ignored":{{"nested":[null,true,false,"é😀"]}}}}],"transactionHash":"0x{}","transactionIndex":"0x0","blockHash":"0x{}","blockNumber":"0x1","gasUsed":"0x5208"}}"#,
            "00".repeat(256),
            data,
            "22".repeat(32),
            "33".repeat(20),
            "44".repeat(32),
            "55".repeat(32)
        )
    }
    struct Chunk<'a> {
        bytes: &'a [u8],
        maximum: usize,
    }
    impl std::io::Read for Chunk<'_> {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            let count = out.len().min(self.maximum).min(self.bytes.len());
            out[..count].copy_from_slice(&self.bytes[..count]);
            self.bytes = &self.bytes[count..];
            Ok(count)
        }
    }
    #[test]
    fn every_chunk_boundary_preserves_canonical_receipt_rlp_and_json_escapes() {
        for data in ["0x", "0x00", "0x7f", "0x80", "0x010203", r"0\u00783031"] {
            let value = receipt(data);
            let expected =
                crate::evm::parse_receipt(&norito::json::from_str::<Value>(&value).unwrap())
                    .unwrap();
            let wire = format!(r#"{{"result":{value},"id":7,"jsonrpc":"2.0"}}"#);
            for maximum in [1, 2, 3, 7, 8192] {
                let actual = decode(
                    &mut Chunk {
                        bytes: wire.as_bytes(),
                        maximum,
                    },
                    7,
                    "test",
                    4096,
                )
                .unwrap();
                assert_eq!(
                    actual.bytes,
                    crate::builders::ethereum::receipt_rlp(&expected)
                );
                assert_eq!(actual.transaction_hash, expected.transaction_hash);
                assert_eq!(actual.block_hash, expected.block_hash);
            }
        }
    }
    #[test]
    fn malformed_streams_and_selected_proof_limits_refuse_without_suffix_acceptance() {
        let value = receipt("0x010203");
        let valid = format!(r#"{{"result":{value},"id":7,"jsonrpc":"2.0"}}"#);
        for wire in [
            format!("{valid}null"),
            valid.replace("\"id\":7", "\"id\":8"),
            valid.replace("0x010203", "0x0"),
            valid.replace("0x010203", r"0x\uD800"),
            valid.replace("\"status\":\"0x1\"", "\"status\":\"0x2\""),
            valid.replace("\"id\":7", "\"id\":7,\"id\":7"),
            valid[..valid.len() - 1].to_owned(),
        ] {
            assert!(decode(&mut wire.as_bytes(), 7, "test", 4096).is_err());
        }
        assert!(decode(&mut valid.as_bytes(), 7, "test", 300).is_err());
        let error = r#"{"jsonrpc":"2.0","id":7,"error":{"code":-32601,"message":"missing"}}"#;
        assert!(matches!(
            decode(&mut error.as_bytes(), 7, "test", 4096),
            Err(RpcError::JsonRpc { code: -32601, .. })
        ));
    }
}
