//! Independent canonical SHA3 adapters for generic toy-tree topology tests.
//!
//! These graphs are deliberately smaller/larger than the proof geometry. They
//! are not a proof protocol, proof decoder, or synthetic execution-relation test.
use super::super::compact_sha3::{BodyFields, Context};
use crate::Result;
use fastpq_isi::keccak256::Sha3Digest256V1 as Digest;
pub(super) fn leaf(context: &Context, round: u8, index: u32, bytes: &[u8]) -> Result<Digest> {
    context
        .hash_frame(&context.frame(1, 3, round, 0, index, 32, BodyFields::One(bytes)))
        .map_err(|_| super::shape("canonical SHA3 reference leaf failed"))
}
pub(super) fn parent(
    context: &Context,
    round: u8,
    level: u32,
    index: u32,
    left: Digest,
    right: Digest,
) -> Result<Digest> {
    context
        .hash_frame(&context.frame(
            2,
            3,
            round,
            level,
            index,
            32,
            BodyFields::Two(left.as_bytes(), right.as_bytes()),
        ))
        .map_err(|_| super::shape("canonical SHA3 reference parent failed"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn independently_encoded_sha3_tree_matches_every_leaf_and_root() {
        // Leaves and root computed by `scripts/zk_semantic_profile_reference.py`
        // under the frozen transcript profile descriptor, without this crate.
        let context = Context::new(b"complete public context without a private witness").unwrap();
        let expected = [
            "8de249d4aadbe0a614c883e739d3616c1b90fc80b0a3ca8d279f393f188a4a29",
            "8b479fdd2cd2cebd0880e0d09097157a293319920fae844ae9fea7026f214c50",
            "56c2bb31ec7dd0b580eb83894c39dfeebef6781a89a60fc67ab36962b2e63e4c",
            "fe74b54571648acfee45d47de565ab38e7ffe5e07f1dd38f0358a629534d1b72",
            "39a387af9d2681cc75a72ad7116a1036cfa553462bdbc9b36aa5aade08f4bc8a",
            "05d075ee8bcdb3defe90acca9ee0d28071aee7fb53e0982e07dbaa79cdcc99c3",
            "cb972551c46ef5032ddaa858c7cfc27bcc7a4368ae23614e2a2b30edd46c2eaa",
            "3e8f96f54fcbafd951576dcb02e3f821f633330b7679fb795523cea65deaf85f",
        ];
        let mut levels = vec![
            (0..8_u32)
                .map(|index| {
                    let mut payload = [0; 64];
                    payload[..8].copy_from_slice(&u64::from(index + 1).to_le_bytes());
                    let actual = leaf(&context, 3, index, &payload).unwrap();
                    assert_eq!(hex::encode(actual.into_bytes()), expected[index as usize]);
                    actual
                })
                .collect::<Vec<_>>(),
        ];
        while levels.last().unwrap().len() > 1 {
            let next = levels
                .last()
                .unwrap()
                .chunks_exact(2)
                .enumerate()
                .map(|(index, children)| {
                    parent(
                        &context,
                        3,
                        u32::try_from(levels.len()).expect("bounded reference tree depth"),
                        u32::try_from(index).expect("bounded reference tree index"),
                        children[0],
                        children[1],
                    )
                    .unwrap()
                })
                .collect();
            levels.push(next);
        }
        assert_eq!(
            hex::encode(levels.last().unwrap()[0].into_bytes()),
            "01ff7485b636024096bed836a1d2b98c9d5fc2a4a0778ef36ba988d2779a1cc7"
        );
    }
}
