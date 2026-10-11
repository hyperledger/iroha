//! Inspect a Norito-framed `SignedBlock` (e.g., encoded genesis) for debugging.
use iroha_crypto::{KeyPair, SignatureOf};
use iroha_data_model::{
    block::{
        BlockHeader, BlockSignature, decode_framed_signed_block,
        deframe_versioned_signed_block_bytes,
    },
    prelude::SetParameter,
    transaction::{ExecutableBatchItem, executable::Executable, signed::TransactionResult},
};
use nonzero_ext::nonzero;
use std::{convert::TryFrom, env, error::Error, fs};
fn reference_signer() -> Result<KeyPair, iroha_crypto::Error> {
    KeyPair::try_random()
}
fn execution_result_description(result: Option<&TransactionResult>) -> String {
    match result.map(|result| result.as_ref()) {
        Some(Err(err)) => format!("execution error: {err:?}"),
        Some(Ok(_)) => "execution result: Ok (details not printed)".into(),
        None => "execution result: not attached".into(),
    }
}
fn read_varint(bytes: &[u8], mut pos: usize) -> Result<(u64, usize), Box<dyn Error>> {
    let mut value = 0u64;
    let mut shift = 0u32;
    loop {
        let byte = *bytes
            .get(pos)
            .ok_or_else(|| format!("varint: unexpected EOF at offset {pos}"))?;
        value |= u64::from(byte & 0x7F) << shift;
        pos += 1;
        if (byte & 0x80) == 0 {
            return Ok((value, pos));
        }
        shift += 7;
        if shift >= 64 {
            return Err("varint too large".into());
        }
    }
}
fn extract_first_signature_element(payload: &[u8]) -> Result<&[u8], Box<dyn Error>> {
    let (len, mut pos) = read_varint(payload, 0)?;
    if len == 0 {
        return Err("empty set".into());
    }
    let offset_slots = usize::try_from(len + 1).map_err(|_| "offset count overflow")?;
    let mut offsets = Vec::with_capacity(offset_slots);
    for _ in 0..=len {
        let (offset, next) = read_varint(payload, pos)?;
        let offset = usize::try_from(offset).map_err(|_| "offset too large")?;
        offsets.push(offset);
        pos = next;
    }
    let total = *offsets.last().ok_or("missing offsets")?;
    let data_region = payload
        .get(pos..pos + total)
        .ok_or("data region truncated")?;
    let start = offsets[0];
    let end = offsets[1];
    Ok(data_region
        .get(start..end)
        .ok_or("element span out of range")?)
}
fn dump_reference_encoding() -> Result<(), Box<dyn Error>> {
    let kp = reference_signer()?;
    let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let sig = SignatureOf::<BlockHeader>::from_hash(kp.private_key(), header.hash());
    let block_sig = BlockSignature::new(0, sig);
    let set = iroha_data_model::block::BlockSignatures::try_from_iter([block_sig])?;
    let mut buf = Vec::new();
    norito::core::serialize_to_buffer(&set, &mut buf).unwrap();
    println!(
        "reference ordered signature bytes len={} head={}",
        buf.len(),
        buf.iter()
            .take(32)
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(" ")
    );
    Ok(())
}
#[allow(clippy::too_many_lines)]
fn main() -> Result<(), Box<dyn Error>> {
    dump_reference_encoding()?;
    let path = env::args()
        .nth(1)
        .ok_or("usage: decode_signed_block <path>")?;
    let bytes = fs::read(&path)?;
    println!("file: {path}");
    println!("total bytes: {}", bytes.len());
    let deframed = deframe_versioned_signed_block_bytes(&bytes)?;
    let header_index = 1 + norito::core::Header::SIZE - 1;
    let header_flags = bytes
        .get(header_index)
        .copied()
        .unwrap_or(norito::core::default_encode_flags());
    println!("framed header flags: 0x{header_flags:02x}");
    println!("bare versioned len: {}", deframed.bare_versioned.len());
    let versioned = deframed.bare_versioned.as_ref();
    if versioned.is_empty() {
        return Err("versioned payload empty".into());
    }
    let payload = &versioned[1..];
    println!("payload len: {}", payload.len());
    println!(
        "payload head: {}",
        payload
            .iter()
            .take(32)
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(" ")
    );
    norito::core::reset_decode_state();
    match norito::core::decode_field_canonical::<iroha_data_model::block::BlockSignatures>(payload)
    {
        Ok((signatures, used)) => {
            println!(
                "decoded signatures set: {} entries (bytes consumed: {used})",
                signatures.len()
            );
        }
        Err(err) => {
            println!("failed to decode signatures set: {err}");
        }
    }
    match extract_first_signature_element(payload) {
        Ok(element) => {
            println!(
                "element bytes len={} head={}",
                element.len(),
                element
                    .iter()
                    .take(32)
                    .map(|b| format!("{b:02x}"))
                    .collect::<Vec<_>>()
                    .join(" ")
            );
            match std::panic::catch_unwind(|| {
                norito::core::decode_field_canonical::<BlockSignature>(element)
            }) {
                Ok(Ok((sig, used))) => {
                    println!(
                        "decoded BlockSignature (used {used} bytes): index={} payload_len={}",
                        sig.index(),
                        sig.signature().payload().len()
                    );
                }
                Ok(Err(err)) => println!("decode BlockSignature error: {err}"),
                Err(_) => println!("decode BlockSignature panicked"),
            }
        }
        Err(err) => {
            println!("failed to extract element: {err}");
        }
    }
    match std::panic::catch_unwind(|| decode_framed_signed_block(&bytes)) {
        Ok(Ok(block)) => {
            let header = block.header();
            println!(
                "block header: height={} prev={:?} txs={}",
                header.height(),
                header.prev_block_hash(),
                block.external_transactions().len()
            );
            println!("block has results: {}", block.has_results());
            println!("block hash: {:?}", block.hash());
            println!("block signatures via API: {}", block.signatures().count());
            println!(
                "transaction signature lens: {:?}",
                block
                    .external_transactions()
                    .map(|tx| {
                        let mut buf = Vec::new();
                        norito::core::serialize_to_buffer(tx.signature(), &mut buf)
                            .map(|()| buf.len())
                            .unwrap_or_default()
                    })
                    .collect::<Vec<_>>()
            );
            for idx in 0..block.external_entrypoint_count() {
                let Some(tx) = block.external_signed_transaction_ref_at(idx) else {
                    continue;
                };
                println!("tx[{idx}] authority={}", tx.authority());
                match tx.instructions() {
                    Executable::Instructions(instrs) => {
                        for (j, instr) in instrs.iter().enumerate() {
                            println!("  instr[{j}]: {instr:?}");
                            if let Some(set_param) = instr.as_any().downcast_ref::<SetParameter>() {
                                println!("    set parameter payload: {:?}", set_param.inner());
                            }
                        }
                    }
                    Executable::ContractCall(call) => {
                        println!("  contract call: {call:?}");
                    }
                    Executable::Ivm(bytecode) => {
                        println!("  ivm bytecode: {bytecode:?}");
                    }
                    Executable::IvmProved(_) => {
                        println!(
                            "  ivm proved: bytecode {} bytes overlay {} instructions",
                            tx.instructions().ivm_size_bytes(),
                            tx.instructions().instruction_count()
                        );
                    }
                    Executable::Batch(items) => {
                        for (item_index, item) in items.iter().enumerate() {
                            match item {
                                ExecutableBatchItem::Instruction(instruction) => {
                                    println!("  batch[{item_index}] instruction: {instruction:?}");
                                    if let Some(set_param) =
                                        instruction.as_any().downcast_ref::<SetParameter>()
                                    {
                                        println!(
                                            "    set parameter payload: {:?}",
                                            set_param.inner()
                                        );
                                    }
                                }
                                ExecutableBatchItem::ContractCall(call) => {
                                    println!("  batch[{item_index}] contract call: {call:?}")
                                }
                            }
                        }
                    }
                }
                let result = u32::try_from(idx)
                    .ok()
                    .and_then(|index| block.network_output_at(index))
                    .map(|(_, output)| &output.result);
                println!("  tx[{idx}] {}", execution_result_description(result));
            }
        }
        Ok(Err(err)) => {
            println!("decode_framed_signed_block error: {err}");
        }
        Err(_) => {
            println!("decode_framed_signed_block panicked");
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn execution_result_description_distinguishes_missing_success_and_rejection() {
        use iroha_data_model::{ValidationFail, transaction::error::TransactionRejectionReason};

        assert_eq!(
            execution_result_description(None),
            "execution result: not attached"
        );
        let success = TransactionResult::new(Ok(Vec::new()));
        assert_eq!(
            execution_result_description(Some(&success)),
            "execution result: Ok (details not printed)"
        );
        let rejection = TransactionResult::new(Err(TransactionRejectionReason::Validation(
            ValidationFail::NotPermitted("example rejection".into()),
        )));
        assert_eq!(
            execution_result_description(Some(&rejection)),
            format!("execution error: {:?}", rejection.as_ref().unwrap_err())
        );
    }
    #[test]
    fn reference_signer_uses_checked_default_key_generation() {
        let key_pair = reference_signer().expect("checked reference signer generation");
        assert_eq!(
            key_pair
                .public_key()
                .try_algorithm()
                .expect("generated public key algorithm"),
            iroha_crypto::Algorithm::Ed25519
        );
    }
}
