//! Sole CS1 callable tape codec, with header-advertised Norito child layouts.

use norito::Error;
use norito::core::{Archived, DecodeFromSlice, DeserializePayload, Encoder, SerializePayload};

use super::{CallSchemaV1, CallTypeNodeV1};
use crate::{call::MAX_CALL_SCHEMA_NODES_V1, entrypoint::EntrypointValueKindV1};

const MAGIC: &[u8; 4] = b"CS1\0";

fn kind_tag(kind: EntrypointValueKindV1) -> u8 {
    use EntrypointValueKindV1 as Kind;
    match kind {
        Kind::Int => 0,
        Kind::Decimal => 1,
        Kind::Quantity => 2,
        Kind::Bool => 3,
        Kind::String => 4,
        Kind::Json => 5,
        Kind::Name => 6,
        Kind::AccountId => 7,
        Kind::AssetDefinitionId => 8,
        Kind::AssetId => 9,
        Kind::DomainId => 10,
        Kind::NftId => 11,
        Kind::DataSpaceId => 12,
        Kind::Blob => 13,
    }
}
fn decode_kind(tag: u8) -> Result<EntrypointValueKindV1, Error> {
    use EntrypointValueKindV1 as Kind;
    Ok(match tag {
        0 => Kind::Int,
        1 => Kind::Decimal,
        2 => Kind::Quantity,
        3 => Kind::Bool,
        4 => Kind::String,
        5 => Kind::Json,
        6 => Kind::Name,
        7 => Kind::AccountId,
        8 => Kind::AssetDefinitionId,
        9 => Kind::AssetId,
        10 => Kind::DomainId,
        11 => Kind::NftId,
        12 => Kind::DataSpaceId,
        13 => Kind::Blob,
        tag => {
            return Err(Error::InvalidTag {
                context: "CS1 scalar kind",
                tag,
            });
        }
    })
}
impl SerializePayload for CallSchemaV1 {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), Error> {
        writer.write_all(MAGIC)?;
        norito::core::write_seq_len(
            writer,
            u64::try_from(self.nodes.len()).map_err(|_| Error::LengthMismatch)?,
        )?;
        // Preserve the former encoder's ability to encode malformed test models;
        // the sole decoder validates the entire forest before publishing it.
        for node in &self.nodes {
            use CallTypeNodeV1 as Node;
            let tag: u8 = match node {
                Node::Struct { .. } => 0,
                Node::Tuple(_) => 1,
                Node::Option => 2,
                Node::Result => 3,
                Node::List { .. } => 4,
                Node::Leaf(_) => 5,
                Node::Unit => 6,
                Node::Error(_) => 7,
                Node::StateCursor(_) => 8,
                Node::StateRoot => 9,
                Node::Pointer(_) => 10,
                Node::SecretNumeric(_) => 11,
                Node::Enum(_) => 12,
            };
            tag.serialize(writer)?;
            match node {
                Node::Struct { name, fields } => {
                    name.serialize(writer)?;
                    fields.serialize(writer)?;
                }
                Node::Tuple(arity) => arity.serialize(writer)?,
                Node::List { capacity } => capacity.serialize(writer)?,
                Node::Leaf(kind) => kind_tag(*kind).serialize(writer)?,
                Node::StateCursor(key) => norito::core::write_len_prefixed(writer, key)?,
                Node::Error(error) => norito::core::write_len_prefixed(writer, error)?,
                Node::Enum(enumeration) => norito::core::write_len_prefixed(writer, enumeration)?,
                Node::Pointer(id) | Node::SecretNumeric(id) => id.serialize(writer)?,
                Node::Option | Node::Result | Node::Unit | Node::StateRoot => {}
            }
        }
        Ok(())
    }
}
fn field<'a, T: DecodeFromSlice<'a>>(bytes: &'a [u8], offset: &mut usize) -> Result<T, Error> {
    let (value, used) = T::decode_from_slice(bytes.get(*offset..).ok_or(Error::LengthMismatch)?)?;
    *offset = offset.checked_add(used).ok_or(Error::LengthMismatch)?;
    Ok(value)
}
fn decode(bytes: &[u8]) -> Result<(CallSchemaV1, usize), Error> {
    if bytes.get(..MAGIC.len()) != Some(MAGIC.as_slice()) {
        return Err(Error::InvalidMagic);
    }
    norito::core::note_payload_access(bytes, MAGIC.len());
    let (count, count_used) = norito::core::read_seq_len_slice(&bytes[MAGIC.len()..])?;
    let mut offset = MAGIC.len() + count_used;
    // Every node occupies at least its tag. Reject impossible declarations
    // before accounting for node backing under the active Norito decode budget.
    if count > MAX_CALL_SCHEMA_NODES_V1 || count > bytes.len() - offset {
        return Err(Error::LengthMismatch);
    }
    let backing = count
        .checked_mul(std::mem::size_of::<CallTypeNodeV1>())
        .ok_or(Error::LengthMismatch)?;
    norito::core::reserve_decode_allocation(backing)?;
    let mut nodes = Vec::new();
    nodes
        .try_reserve_exact(count)
        .map_err(|_| Error::AllocationFailed {
            bytes: u64::try_from(backing).unwrap_or(u64::MAX),
        })?;
    let excess = nodes
        .capacity()
        .checked_sub(count)
        .and_then(|n| n.checked_mul(std::mem::size_of::<CallTypeNodeV1>()))
        .ok_or(Error::LengthMismatch)?;
    norito::core::reserve_decode_allocation(excess)?;
    for _ in 0..count {
        use CallTypeNodeV1 as Node;
        let tag: u8 = field(bytes, &mut offset)?;
        let node = match tag {
            0 => Node::Struct {
                name: field::<String>(bytes, &mut offset)?,
                fields: field::<Vec<String>>(bytes, &mut offset)?,
            },
            1 => Node::Tuple(field(bytes, &mut offset)?),
            2 => Node::Option,
            3 => Node::Result,
            4 => Node::List {
                capacity: field(bytes, &mut offset)?,
            },
            5 => Node::Leaf(decode_kind(field(bytes, &mut offset)?)?),
            6 => Node::Unit,
            7 => {
                let suffix = bytes.get(offset..).ok_or(Error::LengthMismatch)?;
                let (len, prefix) = norito::core::read_len_from_slice(suffix)?;
                let used = prefix.checked_add(len).ok_or(Error::LengthMismatch)?;
                let payload = suffix.get(prefix..used).ok_or(Error::LengthMismatch)?;
                let (error, consumed) = norito::core::decode_field_canonical(payload)?;
                if consumed != len {
                    return Err(Error::LengthMismatch);
                }
                offset = offset.checked_add(used).ok_or(Error::LengthMismatch)?;
                Node::Error(error)
            }
            12 => {
                let suffix = bytes.get(offset..).ok_or(Error::LengthMismatch)?;
                let (len, prefix) = norito::core::read_len_from_slice(suffix)?;
                let used = prefix.checked_add(len).ok_or(Error::LengthMismatch)?;
                let payload = suffix.get(prefix..used).ok_or(Error::LengthMismatch)?;
                let (error, consumed) = norito::core::decode_field_canonical(payload)?;
                if consumed != len {
                    return Err(Error::LengthMismatch);
                }
                offset = offset.checked_add(used).ok_or(Error::LengthMismatch)?;
                Node::Enum(error)
            }
            8 => {
                let suffix = bytes.get(offset..).ok_or(Error::LengthMismatch)?;
                let (len, prefix) = norito::core::read_len_from_slice(suffix)?;
                let used = prefix.checked_add(len).ok_or(Error::LengthMismatch)?;
                let payload = suffix.get(prefix..used).ok_or(Error::LengthMismatch)?;
                let (key, consumed) = norito::core::decode_field_canonical(payload)?;
                if consumed != len {
                    return Err(Error::LengthMismatch);
                }
                offset = offset.checked_add(used).ok_or(Error::LengthMismatch)?;
                Node::StateCursor(key)
            }
            9 => Node::StateRoot,
            10 => Node::Pointer(field(bytes, &mut offset)?),
            11 => Node::SecretNumeric(field(bytes, &mut offset)?),
            tag => {
                return Err(Error::InvalidTag {
                    context: "CS1 callable node",
                    tag,
                });
            }
        };
        nodes.push(node);
    }
    let schema = CallSchemaV1 { nodes };
    if schema.analyze().is_none() {
        return Err(Error::LengthMismatch);
    }
    norito::core::note_payload_access(bytes, offset);
    Ok((schema, offset))
}
impl<'de> DeserializePayload<'de> for CallSchemaV1 {
    fn deserialize(archived: &'de Archived<Self>) -> Self {
        Self::try_deserialize(archived).expect("canonical CS1 callable schema")
    }
    fn try_deserialize(archived: &'de Archived<Self>) -> Result<Self, Error> {
        let bytes =
            norito::core::payload_slice_from_ptr(std::ptr::from_ref(archived).cast::<u8>())?;
        let (schema, used) = decode(bytes)?;
        if used != bytes.len() {
            return Err(Error::LengthMismatch);
        }
        Ok(schema)
    }
}
impl<'de> DecodeFromSlice<'de> for CallSchemaV1 {
    fn decode_from_slice(bytes: &'de [u8]) -> Result<(Self, usize), Error> {
        decode(bytes)
    }
}

#[cfg(test)]
mod tests;
