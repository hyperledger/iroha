//! Receipt-trie construction retaining unrelated leaf hashes and only the selected proof.

use crate::{RpcError, http::invalid_response};
use iroha_sccp::{
    ethereum_source::EthereumNativeMptProofV1,
    ethereum_source::{rlp_encode_bytes, rlp_encode_list, rlp_encode_u64},
    v1::hashes::keccak256,
};

struct Leaf {
    index: u64,
    key: Vec<u8>,
    depth: usize,
    hash: Option<[u8; 32]>,
}
pub struct Trie {
    leaves: Vec<Leaf>,
    target: u64,
    target_leaf: Option<Vec<u8>>,
    limit: usize,
}
fn prefix(left: &[u8], right: &[u8]) -> usize {
    left.iter().zip(right).take_while(|(a, b)| a == b).count()
}
fn compact(nibbles: &[u8], leaf: bool) -> Vec<u8> {
    let odd = nibbles.len() % 2 == 1;
    let flag = if leaf { 2 } else { 0 };
    let mut out = Vec::with_capacity(nibbles.len() / 2 + 1);
    let start = if odd {
        out.push(((flag + 1) << 4) | nibbles[0]);
        1
    } else {
        out.push(flag << 4);
        0
    };
    for pair in nibbles[start..].chunks_exact(2) {
        out.push((pair[0] << 4) | pair[1]);
    }
    out
}
fn bytes_prefix(length: usize, list: bool) -> Vec<u8> {
    if length < 56 {
        return vec![
            (if list { 0xc0 } else { 0x80 })
                + u8::try_from(length).expect("short RLP payload is below 56 bytes"),
        ];
    }
    let bytes = length.to_be_bytes();
    let start = bytes
        .iter()
        .position(|b| *b != 0)
        .unwrap_or(bytes.len() - 1);
    let mut out = vec![
        (if list { 0xf7 } else { 0xb7 })
            + u8::try_from(bytes.len() - start).expect("usize length uses at most eight bytes"),
    ];
    out.extend_from_slice(&bytes[start..]);
    out
}
impl Trie {
    pub(crate) fn new(count: usize, target: u64, limit: usize) -> Result<Self, RpcError> {
        if target >= u64::try_from(count).unwrap_or(u64::MAX) {
            return Err(invalid_response("receipt target is outside the block"));
        }
        let mut leaves: Vec<_> = (0..count)
            .map(|index| {
                let index = index as u64;
                let key = rlp_encode_u64(index)
                    .into_iter()
                    .flat_map(|byte| [byte >> 4, byte & 15])
                    .collect();
                Leaf {
                    index,
                    key,
                    depth: 0,
                    hash: None,
                }
            })
            .collect();
        leaves.sort_by(|a, b| a.key.cmp(&b.key));
        for index in 0..leaves.len() {
            let before = if index == 0 {
                0
            } else {
                prefix(&leaves[index - 1].key, &leaves[index].key) + 1
            };
            let after = if index + 1 == leaves.len() {
                0
            } else {
                prefix(&leaves[index].key, &leaves[index + 1].key) + 1
            };
            leaves[index].depth = before.max(after);
        }
        Ok(Self {
            leaves,
            target,
            target_leaf: None,
            limit,
        })
    }
    pub(crate) fn insert(&mut self, index: u64, receipt: &[u8]) -> Result<(), RpcError> {
        let key: Vec<_> = rlp_encode_u64(index)
            .into_iter()
            .flat_map(|byte| [byte >> 4, byte & 15])
            .collect();
        let position = self
            .leaves
            .binary_search_by(|leaf| leaf.key.cmp(&key))
            .map_err(|_| invalid_response("unexpected receipt index"))?;
        let leaf = &mut self.leaves[position];
        if leaf.hash.is_some() {
            return Err(invalid_response("duplicate receipt index"));
        }
        let path = rlp_encode_bytes(&compact(&leaf.key[leaf.depth..], true));
        // Canonical receipts contain a 256-byte bloom, so the leaf is always hash-referenced.
        if receipt.len() < 256 {
            return Err(invalid_response("receipt leaf is too short"));
        }
        let value_prefix = bytes_prefix(receipt.len(), false);
        let list_prefix = bytes_prefix(path.len() + value_prefix.len() + receipt.len(), true);
        leaf.hash = Some(keccak256(&[&list_prefix, &path, &value_prefix, receipt]));
        if index == self.target {
            let length = list_prefix.len() + path.len() + value_prefix.len() + receipt.len();
            if length > self.limit {
                return Err(invalid_response(
                    "target receipt leaf exceeds the selected proof budget",
                ));
            }
            let mut node = Vec::with_capacity(length);
            for bytes in [&list_prefix[..], &path, &value_prefix, receipt] {
                node.extend_from_slice(bytes);
            }
            self.target_leaf = Some(node);
        }
        Ok(())
    }
    pub(crate) fn finish(self) -> Result<([u8; 32], EthereumNativeMptProofV1), RpcError> {
        let mut nodes = vec![
            self.target_leaf
                .ok_or_else(|| invalid_response("target receipt is missing"))?,
        ];
        let root = build(&self.leaves, 0, self.target, &mut nodes)?;
        nodes.reverse();
        let bytes = nodes
            .iter()
            .try_fold(0usize, |total, node| total.checked_add(node.len()))
            .ok_or_else(|| invalid_response("receipt proof size overflows"))?;
        if bytes > self.limit {
            return Err(invalid_response(
                "receipt proof exceeds the selected proof budget",
            ));
        }
        Ok((root, EthereumNativeMptProofV1 { nodes }))
    }
}
fn build(
    leaves: &[Leaf],
    depth: usize,
    target: u64,
    nodes: &mut Vec<Vec<u8>>,
) -> Result<[u8; 32], RpcError> {
    if leaves.len() == 1 {
        return leaves[0]
            .hash
            .ok_or_else(|| invalid_response("block receipt missing"));
    }
    let shared = prefix(&leaves[0].key, &leaves[leaves.len() - 1].key).saturating_sub(depth);
    let node = if shared > 0 {
        rlp_encode_list(&[
            rlp_encode_bytes(&compact(&leaves[0].key[depth..depth + shared], false)),
            rlp_encode_bytes(&build(leaves, depth + shared, target, nodes)?),
        ])
    } else {
        let mut items = Vec::with_capacity(17);
        let mut start = 0;
        for nibble in 0..16 {
            let mut end = start;
            while end < leaves.len() && leaves[end].key.get(depth) == Some(&nibble) {
                end += 1;
            }
            items.push(if start == end {
                rlp_encode_bytes(&[])
            } else {
                rlp_encode_bytes(&build(&leaves[start..end], depth + 1, target, nodes)?)
            });
            start = end;
        }
        if start != leaves.len() {
            return Err(invalid_response("receipt trie key is not prefix-free"));
        }
        items.push(rlp_encode_bytes(&[]));
        rlp_encode_list(&items)
    };
    let hash = keccak256(&[&node]);
    if leaves.iter().any(|leaf| leaf.index == target) {
        nodes.push(node);
    }
    Ok(hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn streamed_leaf_hashes_match_full_trie_roots_and_every_target_path() {
        for count in [1, 2, 16, 128, 129, 256, 513] {
            let entries: Vec<_> = (0..count)
                .map(|index| {
                    (
                        rlp_encode_u64(index),
                        vec![
                            index.to_le_bytes()[0];
                            300 + usize::try_from(index % 13)
                                .expect("fixture remainder is below 13")
                        ],
                    )
                })
                .collect();
            for target in [0, count / 2, count - 1] {
                let mut trie = Trie::new(
                    usize::try_from(count).expect("fixture count is at most 513"),
                    target,
                    4096,
                )
                .unwrap();
                for (index, (_, value)) in entries.iter().enumerate().rev() {
                    trie.insert(index as u64, value).unwrap();
                }
                let (root, proof) = trie.finish().unwrap();
                assert_eq!(Some(root), iroha_sccp::ethereum_source::mpt_root(&entries));
                assert_eq!(
                    Some(proof),
                    iroha_sccp::ethereum_source::mpt_proof(&entries, &rlp_encode_u64(target))
                );
            }
        }
    }
    #[test]
    fn incomplete_duplicate_and_over_budget_trie_outputs_refuse() {
        assert!(Trie::new(1, 1, 4096).is_err());
        let mut trie = Trie::new(2, 0, 4096).unwrap();
        trie.insert(0, &[1; 300]).unwrap();
        assert!(trie.insert(0, &[1; 300]).is_err());
        assert!(trie.finish().is_err());
        let mut trie = Trie::new(1, 0, 300).unwrap();
        assert!(trie.insert(0, &[1; 300]).is_err());
    }
}
