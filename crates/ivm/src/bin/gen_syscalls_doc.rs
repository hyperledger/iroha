//! Generate or check the generated syscall list section in `docs/syscalls.md`. Usage:
//!   cargo run -p ivm --features dev-tools --bin gen_syscalls_doc -- --write
//!   cargo run -p ivm --features dev-tools --bin gen_syscalls_doc -- --check
//!   cargo run -p ivm --features dev-tools --bin gen_syscalls_doc -- --write --root /tmp/ivm-doc-stage
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::PathBuf,
};
mod support;
use support::{GeneratedOutput, parse_generation_options, sync_generated_outputs};
const BEGIN: &str = "<!-- BEGIN GENERATED SYSCALLS -->";
const END: &str = "<!-- END GENERATED SYSCALLS -->";
const ABI_SYSCALL_GOLDEN_BEGIN: &str = "    // BEGIN GENERATED ABI V1 SYSCALL LIST";
const ABI_SYSCALL_GOLDEN_END: &str = "    // END GENERATED ABI V1 SYSCALL LIST";
fn guess_defaults(n: u32) -> (String, String, String) {
    let name = ivm::syscalls::syscall_name(n).unwrap_or("");
    // Baseline defaults
    let mut args = String::from("-");
    let mut ret = String::from("-");
    let mut gas = String::from("-");
    let up = name;
    // Heuristics for common patterns; conservative and non-binding
    if up.contains("ZK_VERIFY_BATCH") || n == 0x64 {
        args = "r10=&NoritoBytes(Vec<OpenVerifyEnvelope>)".into();
        ret = "r10=ptr (&NoritoBytes(Vec<u8> statuses)), r11=status:u64".into();
        gas = "G_verify + bytes".into();
    } else if matches!(n, 0x60..=0x61) {
        args = "r10=&NoritoBytes(OpenVerifyEnvelope)".into();
        ret = "u64=0/1".into();
        gas = "G_verify_proof + bytes".into();
    } else if up.contains("VRF_VERIFY_BATCH") || n == 0x67 {
        args =
            "r10=&NoritoBytes(VrfVerifyBatchRequest), 1..=16 items, canonical frame <=65536 bytes"
                .into();
        ret = "r10=ptr (&NoritoBytes(Vec<[u8;32]>)), r11=status:u64, r12=fail_index?:u64".into();
        gas = "64 + 250,000 per examined item + 5 per canonical request byte".into();
    } else if up.contains("VRF_VERIFY") || n == 0x66 {
        args = "r10=&NoritoBytes(VrfVerifyRequest), canonical frame <=65536 bytes".into();
        ret = "r10=ptr (&Blob(32-byte output)), r11=status:u64".into();
        gas = "64 + 250,000 per examined item + 5 per canonical request byte".into();
    } else if up.contains("VERIFY_PROOF") || n == 0xF6 {
        args = "r10=&NoritoBytes(OpenVerifyEnvelope)".into();
        ret = "r10=0/1, r11=status:u64".into();
        gas = "G_verify_proof + bytes".into();
    } else if up.contains("ROOTS_GET") || n == 0x62 {
        args = "r10=&NoritoBytes(RootsGetRequest)".into();
        ret = "host-owned ptr (&NoritoBytes)".into();
        gas = "G_roots_get + bytes".into();
    } else if up.contains("VOTE_GET_TALLY") || n == 0x63 {
        args = "r10=&NoritoBytes(VoteGetTallyRequest)".into();
        ret = "host-owned ptr (&NoritoBytes)".into();
        gas = "G_vote_get + bytes".into();
    } else if up.contains("BUILD_PATH_KEY_NORITO") || n == 0x56 {
        args = "r10=&Name(base), r11=&NoritoBytes(key)".into();
        ret = "r10=ptr (&NoritoBytes(StatePath))".into();
        gas = "G_path + bytes".into();
    } else if up.contains("JSON_ENCODE") || n == 0x57 {
        args = "r10=&Json".into();
        ret = "ptr (&NoritoBytes)".into();
        gas = "G_json_encode + bytes".into();
    } else if up.contains("JSON_DECODE") || n == 0x58 {
        args = "r10=&NoritoBytes(JSON bytes)".into();
        ret = "ptr (&Json)".into();
        gas = "G_json_decode + bytes".into();
    } else if up.contains("JSON_GET_") {
        args = "r10=&Json(object), r11=&Name(key)".into();
        ret = "r10=Option<T> sum handle".into();
        gas = "G_json_get + input bytes + active payload + sum allocation".into();
    } else if up.contains("JSON_OBJECT") || n == 0x81 {
        args = "-".into();
        ret = "ptr (&Json({}))".into();
        gas = "G_json_object + bytes".into();
    } else if up.contains("JSON_SET_I64") || n == 0x82 {
        args = "r10=&Json(object), r11=&Name(key), r12=value:i64".into();
        ret = "ptr (&Json)".into();
        gas = "G_json_set + bytes".into();
    } else if up.contains("JSON_SET_ACCOUNT_ID") || n == 0x83 {
        args = "r10=&Json(object), r11=&Name(key), r12=&AccountId".into();
        ret = "ptr (&Json)".into();
        gas = "G_json_set + bytes".into();
    } else if up.contains("SCHEMA_ENCODE") || n == 0x59 {
        args = "r10=&Name(schema), r11=&Json".into();
        ret = "ptr (&NoritoBytes)".into();
        gas = "G_schema + bytes".into();
    } else if up.contains("SCHEMA_DECODE") || n == 0x5A {
        args = "r10=&Name(schema), r11=&NoritoBytes".into();
        ret = "ptr (&Json)".into();
        gas = "G_schema + bytes".into();
    } else if up.contains("SCHEMA_INFO") || n == 0x5B {
        args = "r10=&Name(schema)".into();
        ret = "ptr (&Json{\"id\":...,\"version\":...})".into();
        gas = "G_schema + bytes".into();
    } else if up.contains("PRIVATE_NUMERIC_VALCOM") || n == 0xF8 {
        args = "r10=private:&Int|&Decimal|&Quantity(value), r11=private:&Int|&Decimal|&Quantity(blind)".into();
        ret = "r10=public:&Int(full compressed Pedersen point)".into();
        gas = "G_private_numeric_valcom".into();
    } else if up.contains("GET_ACCOUNT_BALANCE") || n == 0xF9 {
        args = "r10=&AccountId, r11=&AssetDefinitionId".into();
        ret = "ptr (&Quantity)".into();
        gas = "G_get_bal".into();
    } else if up.contains("NAME_DECODE") || n == 0x5C {
        args = "r10=&NoritoBytes(Name)".into();
        ret = "ptr (&Name)".into();
        gas = "G_name_decode + bytes".into();
    } else if up.contains("POINTER_TO_NORITO") || n == 0x5D {
        args = "r10=&PointerType<T>".into();
        ret = "ptr (&NoritoBytes(TLV envelope))".into();
        gas = "G_pointer + bytes".into();
    } else if up.contains("POINTER_FROM_NORITO") || n == 0x5E {
        args = "r10=&NoritoBytes(TLV envelope), r11=expected?:u16".into();
        ret = "ptr (&PointerType<T>)".into();
        gas = "G_pointer + bytes".into();
    } else if up.contains("TLV_EQ") || n == 0x5F {
        args = "r10=&Tlv, r11=&Tlv".into();
        ret = "r10=1/0".into();
        gas = "G_tlv_eq + bytes".into();
    } else if up.contains("TLV_LEN") || n == 0x77 {
        args = "r10=&Tlv".into();
        ret = "r10=payload_len:u64".into();
        gas = "G_tlv_len + bytes".into();
    } else if up.contains("VRF_EPOCH_SEED") || n == 0x7E {
        args = "r10=epoch:u64".into();
        ret = "r10=&Blob(seed[32]) or 0 if absent".into();
        gas = "G_state_query + 8 + 32 if found, otherwise G_state_query + 8".into();
    } else if up.starts_with("INT_") || up.starts_with("DECIMAL_") || up.starts_with("QUANTITY_") {
        // Numeric ABI rows are mandatory in `spec/syscalls.toml`; this branch
        // is only the diagnostic starting point printed when one is missing.
        // Keep it aligned with the first-release pointer-backed staged family
        // rather than suggesting the retired scalar `NUMERIC_*` protocol.
        let value_type = if up.starts_with("INT_") {
            "Int"
        } else if up.starts_with("DECIMAL_") {
            "Decimal"
        } else {
            "Quantity"
        };
        gas = "G_numeric_staged".into();
        if up.contains("FROM_INT") {
            args = "r10=&Int".into();
            ret = format!("r10=&{value_type}");
        } else if up.contains("TO_INT") {
            args = format!("r10=&{value_type}");
            ret = "r10=&Int-or-zero, r11=NumericFaultV1-or-zero".into();
        } else if up.contains("NEG") {
            args = format!("r10=&{value_type}");
            ret = format!("r10=&{value_type}-or-zero, r11=NumericFaultV1-or-zero");
        } else if up.contains("EQ")
            || up.contains("NE")
            || up.contains("LT")
            || up.contains("LE")
            || up.contains("GT")
            || up.contains("GE")
        {
            args = format!("r10=&{value_type}, r11=&{value_type}");
            ret = "r10=u64(0/1)".into();
        } else {
            args = format!("r10=&{value_type}, r11=&{value_type}");
            ret = format!("r10=&{value_type}-or-zero, r11=NumericFaultV1-or-zero");
        }
    } else if up.contains("EXECUTION_SUMMARY") || n == 0xF4 {
        ret = "r10=ptr (&NoritoBytes(ExecutionSummary)), r11=status:u64".into();
        gas = "G_execution_summary".into();
    } else if up.contains("SM4_GCM_SEAL") || n == 0x92 {
        args = "r10=&Blob(key16), r11=&Blob(nonce12), r12=&Blob(aad)?, r13=&Blob(plaintext)".into();
        ret = "r10=ptr (&Blob(ciphertext || tag16))".into();
        gas = "G_sm4 + bytes".into();
    } else if up.contains("SM4_GCM_OPEN") || n == 0x93 {
        args =
            "r10=&Blob(key16), r11=&Blob(nonce12), r12=&Blob(aad)?, r13=&Blob(ciphertext || tag16)"
                .into();
        ret = "r10=ptr (&Blob(plaintext)) or 0".into();
        gas = "G_sm4 + bytes".into();
    } else if up.contains("SM4_CCM_SEAL") || n == 0x94 {
        args =
            "r10=&Blob(key16), r11=&Blob(nonce[7..13]), r12=&Blob(aad)?, r13=&Blob(plaintext), r14=tag_len:u64"
                .into();
        ret = "r10=ptr (&Blob(ciphertext || tag))".into();
        gas = "G_sm4 + bytes".into();
    } else if up.contains("SM4_CCM_OPEN") || n == 0x95 {
        args =
            "r10=&Blob(key16), r11=&Blob(nonce[7..13]), r12=&Blob(aad)?, r13=&Blob(ciphertext || tag), r14=tag_len:u64"
                .into();
        ret = "r10=ptr (&Blob(plaintext)) or 0".into();
        gas = "G_sm4 + bytes".into();
    } else if up.contains("VERIFY_SIGNATURE") || n == 0xFC {
        args = "r10=&Blob(message), r11=&Blob(signature), r12=&Blob(pubkey), r13=scheme:u8".into();
        ret = "r10=0/1".into();
        gas = "G_verify_sig + bytes".into();
    } else if up.contains("VERIFY_DS_PROOF") || n == 0xB3 {
        args = "r10=&DataSpaceId, r11=&ProofBlob or 0".into();
        ret = "u64=0/1".into();
        gas = "G_verify + bytes".into();
    } else if up.contains("VERIFY") {
        ret = "u64=0/1".into();
        gas = "G_verify".into();
    } else if up.contains("ALLOC") || n == 0xF0 {
        args = "r10=bytes:u64".into();
        ret = "ptr (r10)".into();
        gas = "G_alloc + bytes".into();
    } else if up.contains("GROW_HEAP") || n == 0xF5 {
        args = "r10=bytes:u64".into();
        ret = "u64=new_limit".into();
        gas = "G_grow_heap per page".into();
    } else if up.contains("GET_PRIVATE_INPUT") || n == 0xFD {
        args = "r10=index:u64, r11=PrivateInputKindV1".into();
        ret = "r10=private:&Int|&Decimal|&Quantity".into();
        gas = "G_get_priv".into();
    } else if up.contains("GET_PUBLIC_INPUT") || n == 0xF1 {
        args = "r10=&Name".into();
        ret = "ptr (r10)".into();
        gas = "G_get_pub".into();
    } else if up.contains("GET_AUTHORITY") || n == 0xA4 {
        ret = "host-owned ptr (&AccountId)".into();
        gas = "G_get_auth + bytes".into();
    } else if up.contains("RESOLVE_ACCOUNT_ALIAS") || n == 0xA7 {
        args = "r10=&Blob(alias literal)".into();
        ret = "host-owned ptr (&AccountId)".into();
        gas = "G_alias_resolve".into();
    } else if up.contains("CURRENT_TIME_MS") || n == 0xA8 {
        ret = "r10=unix_time_ms:u64".into();
        gas = "G_sysvar".into();
    } else if up.contains("STATE_GET") || n == 0x50 {
        args = "r10=&NoritoBytes(StatePath)".into();
        ret = "r10=ptr (&NoritoBytes) or 0".into();
        gas = "G_state_get + canonical path frame bytes + returned value bytes".into();
    } else if up.contains("STATE_SET") || n == 0x51 {
        args = "r10=&NoritoBytes(StatePath), r11=&NoritoBytes".into();
        ret = "u64=0".into();
        gas = "G_state_set + canonical path frame bytes + value bytes".into();
    } else if up.contains("STATE_DEL") || n == 0x52 {
        args = "r10=&NoritoBytes(StatePath)".into();
        ret = "u64=0".into();
        gas = "G_state_del + canonical path frame bytes".into();
    } else if up.contains("INPUT_PUBLISH_TLV") || n == 0xE0 {
        args = "r10=&Blob(TLV)".into();
        ret = "ptr (r10)".into();
        gas = "G_input_publish + bytes".into();
    } else if up.contains("MERKLE_PATH") || n == 0xF7 {
        args = "r10=addr:u64, r11=out:u64, r12=root_out?:u64".into();
        ret = "u64=len".into();
        gas = "G_mpath + len".into();
    } else if up.contains("MERKLE_COMPACT") || n == 0xFA || n == 0xFF {
        args = "r10=addr, r11=out, r12=depth_cap?, r13=root_out?".into();
        ret = "u64=depth".into();
        gas = "G_mpath + depth".into();
    } else if up.contains("QUERY_EXECUTE_NORITO") || n == 0x01_0000 {
        args = "r10=&NoritoBytes(QueryRequest)".into();
        ret = "r10=ptr (&NoritoBytes(QueryResponse))".into();
        gas = "G_scq".into();
    } else if up == "CORE_QUERY_GET" || n == 0x01_0001 {
        args = "r10=CoreQueryEntityTagV1:u64, r11=&typed entity id".into();
        ret = "r10=Option<View> sum handle (typed leaf TLVs)".into();
        gas = "G_scq + query items + encoded bytes".into();
    } else if up == "CORE_QUERY_PAGE" || n == 0x01_0002 {
        args = "r10=CoreQueryEntityTagV1:u64, r11=offset:i64 bits, r12=limit:1..=64".into();
        ret = "r10=List<View,64> handle, r11=Option<int> sum handle".into();
        gas = "G_scq + offset + query items + encoded bytes".into();
    } else if up == "JSON_BUILD" || n == 0x01_004E {
        args = "r10=&NoritoBytes(JsonConstructionSchemaV1), r11=word_table, r12=word_count".into();
        ret = "r10=&Json".into();
        gas = "G_json_build + schema + source + words + elements + encoded bytes".into();
    } else if up.contains("SYSVAR_CHAIN_ID") || n == 0x01_0020 {
        ret = "r10=ptr (&Blob(chain_id)) or 0".into();
        gas = "G_sysvar + bytes".into();
    } else if up.contains("SYSVAR_BLOCK_HEIGHT") || n == 0x01_0021 {
        ret = "r10=height:u64".into();
        gas = "G_sysvar".into();
    } else if up.contains("SYSVAR_BLOCK_TIME_MS") || n == 0x01_0022 {
        ret = "r10=block_time_ms:u64".into();
        gas = "G_sysvar".into();
    } else if up.contains("SYSVAR_AUTHORITY") || n == 0x01_0023 {
        ret = "r10=ptr (&AccountId)".into();
        gas = "G_get_auth + bytes".into();
    } else if up.contains("SYSVAR_CONTRACT_ADDRESS") || n == 0x01_0024 {
        ret = "r10=&Blob(canonical ContractAddress UTF-8 literal, exactly 60 bytes) or 0 without contract context".into();
        gas = "G_sysvar + bytes".into();
    } else if up.contains("SYSVAR_ENTRYPOINT") || n == 0x01_0025 {
        ret = "r10=ptr (&Blob(entrypoint)) or 0".into();
        gas = "G_sysvar + bytes".into();
    } else if up.contains("DECODE_ARGUMENT_RECORD") || n == 0x01_0026 {
        args = "r10=raw &NoritoBytes(EntrypointArgumentRecordV1) or prepared &NoritoBytes(record binding), r11=&NoritoBytes(EntrypointArgumentSchemaV1)".into();
        ret = "r10=ptr (&Blob(pad:u8 then [u64; word_count]))".into();
        gas = "G_argument_decode + record + schema + complete materialization".into();
    } else if up.contains("NORMALIZE_NORITO_BYTES") || n == 0x01_0028 {
        args = "r10=&Blob or &NoritoBytes (validated public TLV)".into();
        ret = "r10=&NoritoBytes(same payload)".into();
        gas = "G_pointer + bytes".into();
    } else if up.contains("STATE_HAS") || n == 0x01_0031 {
        args = "r10=&NoritoBytes(StatePath)".into();
        ret = "r10=present:u64".into();
        gas = "G_state_has + canonical path frame bytes".into();
    } else if up.contains("STATE_LEN") || n == 0x01_0032 {
        args = "r10=&NoritoBytes(StatePath)".into();
        ret = "r10=len:u64, r11=found:u64".into();
        gas = "G_state_len + canonical path frame bytes".into();
    } else if up.contains("STATE_COUNT") || n == 0x01_0033 {
        args = "r10=&NoritoBytes(StatePath prefix)".into();
        ret = "r10=total:u64".into();
        gas = "G_state_count + canonical prefix frame bytes + 1 per examined candidate + examined candidate UTF-8 bytes".into();
    } else if up.contains("STATE_MAP_KEY_AT") || n == 0x01_0034 {
        args = "r10=&NoritoBytes(Vec<StatePath>), r11=&Name(base), r12=index:u64".into();
        ret = "r10=ptr (&NoritoBytes(canonical key)) or 0".into();
        gas = "G_path + bytes".into();
    } else if up.contains("STATE_VALUE_ENCODE") || n == 0x01_0035 {
        args = "r10=&NoritoBytes(StateValueSchemaV1), r11=&[u64], r12=word_count:u64".into();
        ret = "r10=ptr (&NoritoBytes(StateValueRecordV1))".into();
        gas = "G_state_value + schema + words + pointers + output".into();
    } else if up.contains("STATE_VALUE_DECODE") || n == 0x01_0036 {
        args = "r10=&NoritoBytes(StateValueSchemaV1), r11=&NoritoBytes(StateValueRecordV1)".into();
        ret = "r10=ptr (&Blob(pad:u8 then [u64; word_count]))".into();
        gas = "G_state_value + schema + record + pointers + output".into();
    } else if up.contains("STATE_PATH_FROM_NAME") || n == 0x01_0037 {
        args = "r10=&Name".into();
        ret = "r10=ptr (&NoritoBytes(StatePath))".into();
        gas = "G_path + bytes".into();
    } else if up.contains("EXECUTE_QUERY") || n == 0xA1 {
        args = "r10=&Json".into();
        ret = "ptr (r10)".into();
        gas = "G_scq".into();
    } else if up.contains("EXECUTE_INSTRUCTION") || n == 0xA0 {
        args = "r10=&Json".into();
        ret = "u64=0".into();
        gas = "G_sci".into();
    } else if up.contains("COMMIT_OUTPUT") || n == 0xFE {
        args = "r10=&Json".into();
        ret = "u64=0".into();
        gas = "G_commit".into();
    } else if up.is_empty() {
        // Unknown number without a name: keep dashes
    } else {
        // Safe default for side-effect syscalls
        ret = "u64=0".into();
    }
    (args, ret, gas)
}
fn spec_entry(
    map: &std::collections::BTreeMap<u32, (String, String, String)>,
    n: u32,
) -> (String, String, String) {
    map.get(&n).cloned().unwrap_or_else(|| {
        let (args, ret, gas) = guess_defaults(n);
        panic!(
            "ABI syscall 0x{n:06X} has no explicit spec row; suggested starting point: args={args:?}, ret={ret:?}, gas={gas:?}"
        )
    })
}
fn split_gas_terms(gas_raw: &str) -> Vec<&str> {
    let mut terms = Vec::new();
    let mut start = 0;
    let mut paren_depth = 0_u32;
    for (idx, ch) in gas_raw.char_indices() {
        match ch {
            '(' => paren_depth += 1,
            ')' => paren_depth = paren_depth.saturating_sub(1),
            '+' if paren_depth == 0 => {
                terms.push(&gas_raw[start..idx]);
                start = idx + ch.len_utf8();
            }
            _ => {}
        }
    }
    terms.push(&gas_raw[start..]);
    terms
}
fn rewrite_gas_tokens(gas_raw: &str) -> (String, Vec<String>) {
    let mut out_gas = String::new();
    let mut gas_keys = Vec::new();
    for (i, part) in split_gas_terms(gas_raw)
        .into_iter()
        .map(|s| s.trim())
        .enumerate()
    {
        if i > 0 {
            out_gas.push_str(" + ");
        }
        if let Some(tok) = part.split_whitespace().next()
            && tok.starts_with('G')
        {
            gas_keys.push(tok.to_string());
            out_gas.push_str(&format!("asset:gas/{tok}@ivm.core/v2"));
            let tail = part.strip_prefix(tok).unwrap_or("").trim();
            if !tail.is_empty() {
                out_gas.push(' ');
                out_gas.push_str(tail);
            }
            continue;
        }
        out_gas.push_str(part);
    }
    (out_gas, gas_keys)
}
fn is_valid_gas_token(token: &str) -> bool {
    token.strip_prefix("G_").is_some_and(|suffix| {
        !suffix.is_empty()
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    })
}
fn is_valid_explicit_gas_formula(gas: &str) -> bool {
    gas.as_bytes().first().is_some_and(u8::is_ascii_digit)
        && gas.contains(" per ")
        && gas.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b' ' | b',' | b'+' | b'-' | b'/' | b'(' | b')')
        })
}
fn parse_basic_toml_string(raw: &str, line_number: usize) -> Result<String, String> {
    let value = raw
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .ok_or_else(|| {
            format!(
                "syscall spec line {line_number}: values must be canonical double-quoted strings"
            )
        })?;
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(ch) = chars.next() {
        if ch == '"' {
            return Err(format!(
                "syscall spec line {line_number}: unescaped quote in basic string"
            ));
        }
        if ch.is_control() {
            return Err(format!(
                "syscall spec line {line_number}: control character in basic string"
            ));
        }
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        match chars.next() {
            Some('"') => out.push('"'),
            Some('\\') => out.push('\\'),
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('t') => out.push('\t'),
            Some(other) => {
                return Err(format!(
                    "syscall spec line {line_number}: unsupported escape `\\{other}`"
                ));
            }
            None => {
                return Err(format!(
                    "syscall spec line {line_number}: trailing backslash in basic string"
                ));
            }
        }
    }
    Ok(out)
}
fn parse_syscall_number(value: &str, line_number: usize) -> Result<u32, String> {
    if let Some(hex) = value.strip_prefix("0x") {
        if hex.is_empty() || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(format!(
                "syscall spec line {line_number}: malformed hexadecimal syscall number `{value}`"
            ));
        }
        return u32::from_str_radix(hex, 16).map_err(|error| {
            format!(
                "syscall spec line {line_number}: syscall number `{value}` is outside u32: {error}"
            )
        });
    }
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(format!(
            "syscall spec line {line_number}: malformed decimal syscall number `{value}`"
        ));
    }
    value.parse::<u32>().map_err(|error| {
        format!("syscall spec line {line_number}: syscall number `{value}` is outside u32: {error}")
    })
}
fn finish_syscall_spec_row(
    fields: BTreeMap<String, String>,
    row_line: usize,
) -> Result<(u32, String, String, String), String> {
    let keys = fields.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected = ["args", "gas", "number", "ret"]
        .into_iter()
        .collect::<BTreeSet<_>>();
    if keys != expected {
        let missing = expected.difference(&keys).copied().collect::<Vec<_>>();
        let unexpected = keys.difference(&expected).copied().collect::<Vec<_>>();
        return Err(format!(
            "syscall spec row beginning on line {row_line} has invalid fields; missing={missing:?}, unexpected={unexpected:?}"
        ));
    }
    let number_text = fields
        .get("number")
        .expect("validated syscall number field");
    let number = parse_syscall_number(number_text, row_line)?;
    let args = fields.get("args").expect("validated args field").clone();
    let ret = fields.get("ret").expect("validated ret field").clone();
    let gas = fields.get("gas").expect("validated gas field").clone();
    if args.is_empty() || ret.is_empty() || gas.is_empty() {
        return Err(format!(
            "syscall spec row beginning on line {row_line} must define non-empty args, ret, and gas"
        ));
    }
    let (_, gas_tokens) = rewrite_gas_tokens(&gas);
    let canonical_first_token = gas
        .split_whitespace()
        .next()
        .is_some_and(is_valid_gas_token);
    let canonical_asset_expression = canonical_first_token
        && !gas_tokens.is_empty()
        && gas_tokens.iter().all(|token| is_valid_gas_token(token));
    let explicit_formula = gas_tokens.is_empty() && is_valid_explicit_gas_formula(&gas);
    if !canonical_asset_expression && !explicit_formula {
        return Err(format!(
            "syscall spec row beginning on line {row_line} must use canonical G_<name> gas tokens or a bounded numeric `per` formula"
        ));
    }
    Ok((number, args, ret, gas))
}
fn parse_syscall_spec(spec: &str) -> Result<BTreeMap<u32, (String, String, String)>, String> {
    let mut map = BTreeMap::new();
    let mut current: Option<(usize, BTreeMap<String, String>)> = None;
    for (line_index, line) in spec.lines().enumerate() {
        let line_number = line_index + 1;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if trimmed == "[[syscall]]" {
            if let Some((row_line, fields)) = current.take() {
                let (number, args, ret, gas) = finish_syscall_spec_row(fields, row_line)?;
                if map.insert(number, (args, ret, gas)).is_some() {
                    return Err(format!(
                        "syscall spec line {line_number}: duplicate syscall number 0x{number:06X}"
                    ));
                }
            }
            current = Some((line_number, BTreeMap::new()));
            continue;
        }
        if trimmed.starts_with('[') {
            return Err(format!(
                "syscall spec line {line_number}: unknown table declaration `{trimmed}`"
            ));
        }
        let Some((key, raw_value)) = trimmed.split_once('=') else {
            return Err(format!(
                "syscall spec line {line_number}: expected `key = \"value\"`"
            ));
        };
        let key = key.trim();
        if !matches!(key, "number" | "args" | "ret" | "gas") {
            return Err(format!(
                "syscall spec line {line_number}: unknown field `{key}`"
            ));
        }
        let Some((_, fields)) = current.as_mut() else {
            return Err(format!(
                "syscall spec line {line_number}: field `{key}` appears outside [[syscall]]"
            ));
        };
        let value = parse_basic_toml_string(raw_value.trim(), line_number)?;
        if fields.insert(key.to_owned(), value).is_some() {
            return Err(format!(
                "syscall spec line {line_number}: duplicate field `{key}`"
            ));
        }
    }
    let Some((row_line, fields)) = current.take() else {
        return Err("syscall spec contains no [[syscall]] rows".to_owned());
    };
    let (number, args, ret, gas) = finish_syscall_spec_row(fields, row_line)?;
    if map.insert(number, (args, ret, gas)).is_some() {
        return Err(format!(
            "syscall spec row beginning on line {row_line}: duplicate syscall number 0x{number:06X}"
        ));
    }
    Ok(map)
}
fn escape_rust_string_literal(value: &str) -> String {
    value.escape_default().to_string()
}
fn render_table(map: &std::collections::BTreeMap<u32, (String, String, String)>) -> String {
    let mut nums: Vec<u32> = ivm::syscalls::abi_syscall_list().to_vec();
    nums.sort_unstable();
    let mut out = String::new();
    out.push_str("| Number | Name | Args | Return | Gas |\n");
    out.push_str("|---|---|---|---|---|\n");
    for n in nums {
        let name = ivm::syscalls::syscall_name(n).unwrap_or("");
        let (args, ret, gas_raw) = spec_entry(map, n);
        let (gas, _) = rewrite_gas_tokens(&gas_raw);
        out.push_str(&format!(
            "| 0x{n:02X} | {name} | {args} | {ret} | {gas} |\n"
        ));
    }
    out
}
fn render_docs(text: &str, table: &str) -> Result<String, String> {
    let replacement = format!("{BEGIN}\n{table}{END}\n");
    let begin_matches = text.match_indices(BEGIN).collect::<Vec<_>>();
    let end_matches = text.match_indices(END).collect::<Vec<_>>();
    if begin_matches.len() != 1 || end_matches.len() != 1 {
        return Err(format!(
            "syscalls.md must contain exactly one generated-section marker pair; begin={}, end={}",
            begin_matches.len(),
            end_matches.len()
        ));
    }
    let begin = begin_matches[0].0;
    let end_start = end_matches[0].0;
    if end_start <= begin {
        return Err("syscalls.md generated-section end marker precedes begin marker".to_owned());
    }
    let mut replace_end = end_start + END.len();
    if text[replace_end..].starts_with('\n') {
        replace_end += 1;
    }
    let mut rendered =
        String::with_capacity(text.len() - (replace_end - begin) + replacement.len());
    rendered.push_str(&text[..begin]);
    rendered.push_str(&replacement);
    rendered.push_str(&text[replace_end..]);
    Ok(rendered)
}
fn gas_prose_tokens(text: &str) -> BTreeSet<String> {
    let mut tokens = BTreeSet::new();
    for line in text.lines() {
        if let Some(index) = line.find("Gas:") {
            let tail = &line[index + 4..];
            for segment in tail.split(&['+', '|', '—'][..]) {
                let segment = segment.trim();
                if let Some(position) = segment.find('G') {
                    let candidate = &segment[position..];
                    let end = candidate
                        .char_indices()
                        .find_map(|(index, character)| {
                            (!(character == '_' || character.is_ascii_alphanumeric()))
                                .then_some(index)
                        })
                        .unwrap_or(candidate.len());
                    if end > 1 {
                        tokens.insert(candidate[..end].to_owned());
                    }
                }
            }
        }
    }
    tokens
}
fn validate_gas_prose(text: &str, generated_tokens: &BTreeSet<String>) -> Result<(), String> {
    let invalid_generated = generated_tokens
        .iter()
        .filter(|token| !is_valid_gas_token(token))
        .cloned()
        .collect::<Vec<_>>();
    if !invalid_generated.is_empty() {
        return Err(format!(
            "canonical syscall spec contains invalid gas tokens: {}",
            invalid_generated.join(", ")
        ));
    }
    let prose_tokens = gas_prose_tokens(text);
    if prose_tokens == *generated_tokens {
        return Ok(());
    }
    let prose_only = prose_tokens
        .difference(generated_tokens)
        .cloned()
        .collect::<Vec<_>>();
    let spec_only = generated_tokens
        .difference(&prose_tokens)
        .cloned()
        .collect::<Vec<_>>();
    Err(format!(
        "syscall gas prose does not exactly match canonical spec tokens; prose_only={prose_only:?}, spec_only={spec_only:?}"
    ))
}
fn replace_generated_section(
    text: &str,
    begin_marker: &str,
    end_marker: &str,
    expected_section: &str,
) -> Result<String, String> {
    let begin_matches = text.match_indices(begin_marker).collect::<Vec<_>>();
    if begin_matches.len() != 1 {
        return Err(format!(
            "expected exactly one generated-section begin marker `{begin_marker}`, found {}",
            begin_matches.len()
        ));
    }
    let end_matches = text.match_indices(end_marker).collect::<Vec<_>>();
    if end_matches.len() != 1 {
        return Err(format!(
            "expected exactly one generated-section end marker `{end_marker}`, found {}",
            end_matches.len()
        ));
    }
    let begin = begin_matches[0].0;
    let end_start = end_matches[0].0;
    if end_start <= begin {
        return Err(format!(
            "generated-section end marker `{end_marker}` precedes begin marker `{begin_marker}`"
        ));
    }
    let end = end_start + end_marker.len();
    let mut rendered = String::with_capacity(text.len() - (end - begin) + expected_section.len());
    rendered.push_str(&text[..begin]);
    rendered.push_str(expected_section);
    rendered.push_str(&text[end..]);
    Ok(rendered)
}
fn render_abi_syscall_golden_section(numbers: &[u32]) -> Result<String, String> {
    let mut sorted = numbers.to_vec();
    sorted.sort_unstable();
    if sorted.windows(2).any(|window| window[0] == window[1]) {
        return Err("ABI syscall list contains duplicate numbers".to_owned());
    }
    let mut rendered = String::new();
    rendered.push_str(ABI_SYSCALL_GOLDEN_BEGIN);
    rendered.push_str("\n    let golden: &[u32] = &[\n");
    for number in sorted {
        let name = ivm::syscalls::syscall_name(number)
            .ok_or_else(|| format!("ABI syscall 0x{number:06X} has no canonical symbolic name"))?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return Err(format!(
                "ABI syscall 0x{number:06X} has invalid symbolic name `{name}`"
            ));
        }
        rendered.push_str("        S::SYSCALL_");
        rendered.push_str(name);
        rendered.push_str(",\n");
    }
    rendered.push_str("    ];\n");
    rendered.push_str(ABI_SYSCALL_GOLDEN_END);
    Ok(rendered)
}
fn prepare_exact_outputs(
    outputs: impl IntoIterator<Item = (PathBuf, String)>,
) -> Result<Vec<GeneratedOutput>, String> {
    outputs
        .into_iter()
        .map(|(path, expected)| GeneratedOutput::exact(path, expected))
        .collect()
}
fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .expect("workspace root")
        .to_path_buf()
}
fn main() {
    let options = match parse_generation_options(std::env::args().skip(1), workspace_root()) {
        Ok(options) => options,
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(2);
        }
    };
    let manifest_dir = options.root.join("crates/ivm");
    let path = manifest_dir.join("docs/syscalls.md");
    let text = fs::read_to_string(&path).expect("read syscalls.md");
    // The explicit spec is the canonical source for ABI signatures and gas
    // documentation. Heuristic defaults are diagnostic suggestions only.
    let spec_path = manifest_dir.join("spec/syscalls.toml");
    let spec = fs::read_to_string(&spec_path).expect("read canonical syscall spec");
    let map = parse_syscall_spec(&spec).unwrap_or_else(|error| {
        panic!(
            "parse canonical syscall spec {}: {error}",
            spec_path.display()
        )
    });
    let allowed = ivm::syscalls::abi_syscall_list()
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>();
    let specified = map
        .keys()
        .copied()
        .collect::<std::collections::BTreeSet<_>>();
    let missing = allowed.difference(&specified).copied().collect::<Vec<_>>();
    let extra = specified.difference(&allowed).copied().collect::<Vec<_>>();
    assert!(
        missing.is_empty() && extra.is_empty(),
        "canonical syscall spec must exactly cover ABI v1; missing={missing:#X?}, extra={extra:#X?}"
    );
    for (&number, (args, ret, gas)) in &map {
        assert!(
            !args.is_empty() && !ret.is_empty() && !gas.is_empty(),
            "syscall spec row 0x{number:06X} must define non-empty args, ret, and gas"
        );
    }
    // Generate the expected code and gas assets for the `ivm_abi` crate, which
    // owns the syscall renderer used by docs/tests. Rendering is deliberately
    // side-effect free; publication happens only after every output is ready.
    let (generated_docs_code, generated_gas_code) = {
        let mut buf = String::new();
        buf.push_str("// @generated by gen_syscalls_doc.rs; do not edit manually\n");
        buf.push_str("#[rustfmt::skip]\n");
        buf.push_str("#[allow(dead_code)]\n");
        buf.push_str("pub static DOCS: &[crate::syscalls::SyscallDoc] = &[\n");
        let mut nums: Vec<u32> = ivm::syscalls::abi_syscall_list().to_vec();
        nums.sort_unstable();
        let mut gas_keys: std::collections::BTreeSet<String> = Default::default();
        for n in nums {
            let (args, ret, gas_raw) = spec_entry(&map, n);
            let (out_gas, discovered_gas_keys) = rewrite_gas_tokens(&gas_raw);
            for gas_key in discovered_gas_keys {
                gas_keys.insert(gas_key);
            }
            let args = escape_rust_string_literal(&args);
            let ret = escape_rust_string_literal(&ret);
            let out_gas = escape_rust_string_literal(&out_gas);
            buf.push_str(&format!(
                "    crate::syscalls::SyscallDoc {{ number: {n}, args: \"{args}\", ret: \"{ret}\", gas: \"{out_gas}\" }},\n"
            ));
        }
        buf.push_str("];\n");
        // Generate gas_spec.rs
        let mut gbuf = String::new();
        gbuf.push_str("// @generated by gen_syscalls_doc.rs; do not edit manually\n");
        gbuf.push_str("#[rustfmt::skip]\n");
        gbuf.push_str("#[derive(Clone, Copy)]\n");
        gbuf.push_str("pub struct GasAsset { pub key: &'static str, pub asset_id: &'static str, pub unit: &'static str, pub version: &'static str, pub group: &'static str }\n");
        gbuf.push_str("#[rustfmt::skip]\n");
        gbuf.push_str("pub static GAS_ASSETS: &[GasAsset] = &[\n");
        for k in gas_keys.iter() {
            let asset_id = format!("asset:gas/{k}@ivm.core/v2");
            gbuf.push_str(&format!(
                "    GasAsset {{ key: \"{k}\", asset_id: \"{asset_id}\", unit: \"gas\", version: \"v1\", group: \"syscall\" }},\n"
            ));
        }
        gbuf.push_str("];\n");
        if let Err(error) = validate_gas_prose(&text, &gas_keys) {
            eprintln!("{error}");
            std::process::exit(1);
        }
        (buf, gbuf)
    };
    // Render the documentation from the same canonical specification as the
    // Rust assets so check mode can compare all outputs without mutating any.
    let table = render_table(&map);
    let rendered_docs = match render_docs(&text, &table) {
        Ok(rendered) => rendered,
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    };
    let abi_syscall_golden_path = manifest_dir.join("tests/abi_syscall_list_golden.rs");
    let abi_syscall_golden_text =
        fs::read_to_string(&abi_syscall_golden_path).expect("read ABI syscall-list golden test");
    let abi_syscall_golden_section =
        match render_abi_syscall_golden_section(ivm::syscalls::abi_syscall_list()) {
            Ok(rendered) => rendered,
            Err(error) => {
                eprintln!("{error}");
                std::process::exit(1);
            }
        };
    let rendered_abi_syscall_golden = match replace_generated_section(
        &abi_syscall_golden_text,
        ABI_SYSCALL_GOLDEN_BEGIN,
        ABI_SYSCALL_GOLDEN_END,
        &abi_syscall_golden_section,
    ) {
        Ok(rendered) => rendered,
        Err(error) => {
            eprintln!("{}: {error}", abi_syscall_golden_path.display());
            std::process::exit(1);
        }
    };
    let abi_src_dir = options.root.join("crates/ivm_abi/src");
    let code_path = abi_src_dir.join("syscalls_doc_gen.rs");
    let gas_code_path = abi_src_dir.join("gas_spec.rs");
    let regenerate_command =
        "cargo run --locked -p ivm --features dev-tools --bin gen_syscalls_doc -- --write";
    let outputs = prepare_exact_outputs([
        (code_path, generated_docs_code),
        (gas_code_path, generated_gas_code),
        (path, rendered_docs),
        (abi_syscall_golden_path, rendered_abi_syscall_golden),
    ])
    .unwrap_or_else(|error| panic!("prepare generated syscall outputs: {error}"));
    let updated = sync_generated_outputs(&outputs, options.mode, regenerate_command)
        .unwrap_or_else(|error| panic!("{error}"));
    for output_path in updated {
        eprintln!("updated: {}", output_path.display());
    }
}
#[cfg(test)]
mod tests {
    use super::support::GenerationMode as Mode;
    use super::{
        ABI_SYSCALL_GOLDEN_BEGIN, ABI_SYSCALL_GOLDEN_END, BEGIN, END, parse_generation_options,
        parse_syscall_spec, prepare_exact_outputs, render_abi_syscall_golden_section, render_docs,
        replace_generated_section, rewrite_gas_tokens, sync_generated_outputs, validate_gas_prose,
    };
    use std::{
        collections::BTreeSet,
        fs,
        sync::atomic::{AtomicU64, Ordering},
    };
    static NEXT_TEMP_FILE: AtomicU64 = AtomicU64::new(0);
    fn temp_file(name: &str) -> std::path::PathBuf {
        let serial = NEXT_TEMP_FILE.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "ivm-gen-syscalls-doc-{}-{serial}-{name}",
            std::process::id()
        ))
    }
    #[test]
    fn rewrite_gas_tokens_preserves_parenthesized_plus_text() {
        let (rendered, keys) =
            rewrite_gas_tokens("G_soracloud + request bytes (+ response bytes under host)");
        assert_eq!(
            rendered,
            "asset:gas/G_soracloud@ivm.core/v2 + request bytes (+ response bytes under host)"
        );
        assert_eq!(keys, ["G_soracloud"]);
    }
    #[test]
    fn command_mode_and_staged_root_are_explicit_and_unambiguous() {
        let default_root = std::path::PathBuf::from("/workspace");
        let check =
            parse_generation_options(["--check".to_owned()], &default_root).expect("check options");
        assert_eq!(check.mode, Mode::Check);
        assert_eq!(check.root, default_root);
        let write = parse_generation_options(
            [
                "--write".to_owned(),
                "--root".to_owned(),
                "/staged/repository".to_owned(),
            ],
            "/workspace",
        )
        .expect("staged write options");
        assert_eq!(write.mode, Mode::Write);
        assert_eq!(write.root, std::path::Path::new("/staged/repository"));
        assert!(parse_generation_options(Vec::new(), "/workspace").is_err());
        assert!(
            parse_generation_options(["--check".to_owned(), "--write".to_owned()], "/workspace",)
                .is_err()
        );
        assert!(parse_generation_options(["--no-code".to_owned()], "/workspace").is_err());
    }
    fn valid_spec_row(number: &str) -> String {
        format!(
            r#"[[syscall]]
number = "{number}"
args = "r10=\"value\""
ret = "u64=0"
gas = "G_test + bytes"
"#
        )
    }
    #[test]
    fn syscall_spec_parser_accepts_only_complete_canonical_rows() {
        let parsed = parse_syscall_spec(&valid_spec_row("0x01")).expect("parse canonical row");
        assert_eq!(
            parsed.get(&1),
            Some(&(
                "r10=\"value\"".to_owned(),
                "u64=0".to_owned(),
                "G_test + bytes".to_owned(),
            ))
        );
        let explicit_formula = valid_spec_row("0x02")
            .replace("G_test + bytes", "250,000 per proof + 5 per encoded byte");
        assert!(parse_syscall_spec(&explicit_formula).is_ok());
        assert!(parse_syscall_spec("").is_err());
        assert!(parse_syscall_spec("[[other]]\n").is_err());
        assert!(
            parse_syscall_spec(
                "[[syscall]]\nnumber = \"0x01\"\nargs = \"-\"\nret = \"-\"\nunknown = \"x\"\ngas = \"G_test\"\n"
            )
            .is_err()
        );
        assert!(
            parse_syscall_spec(
                "[[syscall]]\nnumber = \"not-a-number\"\nargs = \"-\"\nret = \"-\"\ngas = \"G_test\"\n"
            )
            .is_err()
        );
        assert!(
            parse_syscall_spec(
                "[[syscall]]\nnumber = 1\nargs = \"-\"\nret = \"-\"\ngas = \"G_test\"\n"
            )
            .is_err()
        );
        assert!(
            parse_syscall_spec(
                "[[syscall]]\nnumber = \"1\"\nnumber = \"2\"\nargs = \"-\"\nret = \"-\"\ngas = \"G_test\"\n"
            )
            .is_err()
        );
        assert!(
            parse_syscall_spec(
                "[[syscall]]\nnumber = \"1\"\nargs = \"\\u0041\"\nret = \"-\"\ngas = \"G_test\"\n"
            )
            .is_err()
        );
        assert!(
            parse_syscall_spec(
                "[[syscall]]\nnumber = \"1\"\nargs = \"-\"\nret = \"-\"\ngas = \"bytes only\"\n"
            )
            .is_err()
        );
        assert!(
            parse_syscall_spec("[[syscall]]\nnumber = \"1\"\nargs = \"-\"\nret = \"-\"\n").is_err()
        );
        let duplicate = format!("{}{}", valid_spec_row("1"), valid_spec_row("0x01"));
        assert!(parse_syscall_spec(&duplicate).is_err());
    }
    #[test]
    fn gas_prose_must_exactly_cover_generated_tokens_without_exceptions() {
        let generated = ["G_alloc".to_owned(), "G_test".to_owned()]
            .into_iter()
            .collect::<BTreeSet<_>>();
        let prose = "- allocation — Gas: G_alloc + bytes\n- test — Gas: G_test\n";
        assert!(validate_gas_prose(prose, &generated).is_ok());
        assert!(validate_gas_prose("- test — Gas: G_test\n", &generated).is_err());
        assert!(
            validate_gas_prose(
                "- allocation — Gas: G_alloc\n- test — Gas: G_test\n- stray — Gas: G_extra\n",
                &generated
            )
            .is_err()
        );
        assert!(
            validate_gas_prose(
                prose,
                &["Garbage".to_owned()].into_iter().collect::<BTreeSet<_>>()
            )
            .is_err()
        );
    }
    #[test]
    fn document_rendering_is_idempotent() {
        let table = "| Number |\n|---|\n";
        let stale = format!("prose\n\n{BEGIN}\nstale\n{END}\n\ntail\n");
        let rendered = render_docs(&stale, table).expect("render generated section");
        assert_eq!(
            render_docs(&rendered, table).expect("render generated section again"),
            rendered
        );
        assert!(render_docs("prose\n", table).is_err());
        assert!(render_docs(&format!("{BEGIN}\nunterminated\n"), table).is_err());
        assert!(render_docs(&format!("{END}\n{BEGIN}\n"), table).is_err());
        assert!(
            render_docs(
                &format!("{BEGIN}\none\n{END}\n{BEGIN}\ntwo\n{END}\n"),
                table,
            )
            .is_err()
        );
    }
    #[test]
    fn abi_syscall_golden_rendering_is_owned_and_idempotent() {
        let section = render_abi_syscall_golden_section(&[
            ivm::syscalls::SYSCALL_ABORT,
            ivm::syscalls::SYSCALL_EXIT,
        ])
        .expect("render ABI syscall golden section");
        assert!(section.contains("S::SYSCALL_EXIT"));
        assert!(section.contains("S::SYSCALL_ABORT"));
        let stale = format!(
            "prefix\n{ABI_SYSCALL_GOLDEN_BEGIN}\n        stale\n{ABI_SYSCALL_GOLDEN_END}\nsuffix\n"
        );
        let rendered = replace_generated_section(
            &stale,
            ABI_SYSCALL_GOLDEN_BEGIN,
            ABI_SYSCALL_GOLDEN_END,
            &section,
        )
        .expect("replace ABI syscall golden section");
        assert_eq!(
            replace_generated_section(
                &rendered,
                ABI_SYSCALL_GOLDEN_BEGIN,
                ABI_SYSCALL_GOLDEN_END,
                &section,
            )
            .expect("replace ABI syscall golden section again"),
            rendered
        );
        assert!(
            replace_generated_section(
                &format!("{stale}{ABI_SYSCALL_GOLDEN_BEGIN}\n"),
                ABI_SYSCALL_GOLDEN_BEGIN,
                ABI_SYSCALL_GOLDEN_END,
                &section,
            )
            .is_err()
        );
    }
    #[test]
    fn check_is_nonmutating_and_write_is_idempotent() {
        let path = temp_file("asset.rs");
        fs::write(&path, "stale\n").expect("create stale generated asset");
        let before = fs::read(&path).expect("read stale generated asset");
        let outputs = prepare_exact_outputs([(path.clone(), "current\n".to_owned())])
            .expect("prepare generated asset");
        let error = sync_generated_outputs(&outputs, Mode::Check, "generator --write")
            .expect_err("check must reject stale output");
        assert!(error.contains("generator --write"));
        assert_eq!(
            fs::read(&path).expect("read after check"),
            before,
            "check mode must not mutate stale output"
        );
        assert_eq!(
            sync_generated_outputs(&outputs, Mode::Write, "generator --write")
                .expect("publish generated output"),
            [path.clone()]
        );
        assert_eq!(
            fs::read_to_string(&path).expect("read published output"),
            "current\n"
        );
        let current_outputs = prepare_exact_outputs([(path.clone(), "current\n".to_owned())])
            .expect("prepare current generated asset");
        assert!(
            sync_generated_outputs(&current_outputs, Mode::Write, "generator --write")
                .expect("repeat publication")
                .is_empty()
        );
        fs::remove_file(path).expect("remove temporary generated asset");
        let missing_path = temp_file("missing.rs");
        let missing_outputs =
            prepare_exact_outputs([(missing_path.clone(), "generated\n".to_owned())])
                .expect("prepare missing generated output");
        sync_generated_outputs(&missing_outputs, Mode::Check, "generator --write")
            .expect_err("check must reject a missing output");
        assert!(
            !missing_path.exists(),
            "check mode must not create a missing output"
        );
        assert_eq!(
            sync_generated_outputs(&missing_outputs, Mode::Write, "generator --write")
                .expect("create missing generated output"),
            [missing_path.clone()]
        );
        fs::remove_file(missing_path).expect("remove generated output");
    }
    #[test]
    fn late_invalid_destination_does_not_publish_earlier_asset() {
        let first = temp_file("first.rs");
        let second = temp_file("second.rs");
        fs::write(&first, "stale\n").expect("write first generated asset");
        fs::create_dir(&second).expect("create invalid later destination");
        let before = fs::read(&first).expect("snapshot first generated asset");
        assert!(
            prepare_exact_outputs([
                (first.clone(), "current\n".to_owned()),
                (second.clone(), "generated\n".to_owned()),
            ])
            .is_err()
        );
        assert_eq!(
            fs::read(&first).expect("read first after late failure"),
            before
        );
        fs::remove_file(first).expect("remove first generated asset");
        fs::remove_dir(second).expect("remove invalid destination");
    }
}
