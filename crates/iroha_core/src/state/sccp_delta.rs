//! Exact streaming counterpart of the canonical SCCP World write-set encoding.
//!
//! Only the output owner changes. Names, fixed little-endian lengths, current values,
//! deletion tags and original revert-key order match the existing merge delta.
use super::*;
use std::io::Write;

fn component(out: &mut impl Write, bytes: &[u8]) -> Result<(), norito::Error> {
    out.write_all(
        &u64::try_from(bytes.len())
            .map_err(|_| norito::Error::LengthMismatch)?
            .to_le_bytes(),
    )?;
    out.write_all(bytes)?;
    Ok(())
}
fn value<T: norito::core::SerializePayload>(
    out: &mut impl Write,
    value: &T,
) -> Result<(), norito::Error> {
    let length = norito::codec::encode_adaptive_into(value, &mut std::io::sink())?;
    out.write_all(
        &u64::try_from(length)
            .map_err(|_| norito::Error::LengthMismatch)?
            .to_le_bytes(),
    )?;
    if norito::codec::encode_adaptive_into(value, out)? != length {
        return Err(norito::Error::LengthMismatch);
    }
    Ok(())
}
pub(super) fn storage<K, V, M>(
    out: &mut impl Write,
    name: &'static str,
    storage: &StorageBlock<'_, K, V, M>,
) -> Result<(), norito::Error>
where
    K: MvKey + Encode,
    V: MvValue + Encode,
    M: mv::storage::StorageMode<K, V>,
{
    if !storage.is_dirty() {
        return Ok(());
    }
    component(out, name.as_bytes())?;
    out.write_all(
        &u64::try_from(storage.revert_map().len())
            .map_err(|_| norito::Error::LengthMismatch)?
            .to_le_bytes(),
    )?;
    for key in storage.revert_map().keys() {
        value(out, key)?;
        match storage.get(key) {
            Some(current) => {
                out.write_all(&[1])?;
                value(out, current)?;
            }
            None => out.write_all(&[0])?,
        }
    }
    Ok(())
}
pub(super) fn cell<V, C>(
    out: &mut impl Write,
    name: &'static str,
    cell: &CellBlock<'_, V, C>,
) -> Result<(), norito::Error>
where
    V: MvValue + Encode,
    C: Send + Sync + 'static,
{
    if !cell.is_dirty() {
        return Ok(());
    }
    component(out, name.as_bytes())?;
    value(out, cell.get())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn streaming_cells_and_sorted_storage_insert_delete_match_original_encoder() {
        let cell = mv::cell::Cell::new(1_u64);
        let storage = mv::storage::Storage::<u64, [u8; 32]>::default();
        {
            let mut block = storage.block();
            block.insert(3, [3; 32]);
            block.commit();
        }
        let mut block = storage.block();
        block.insert(7, [7; 32]);
        block.insert(1, [1; 32]);
        block.remove(3);
        let mut changed = cell.block();
        *changed.get_mut() = 2;
        let mut original = Vec::new();
        append_merge_cell_delta(&mut original, "cell", &changed);
        append_merge_storage_delta(&mut original, "storage", &block);
        let mut stream = Vec::new();
        super::cell(&mut stream, "cell", &changed).unwrap();
        super::storage(&mut stream, "storage", &block).unwrap();
        assert_eq!(stream, original);
        let clean = mv::cell::Cell::new(0_u64);
        let mut empty = Vec::new();
        super::cell(&mut empty, "clean", &clean.block()).unwrap();
        assert!(empty.is_empty());
        struct Refuse;
        impl Write for Refuse {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::ErrorKind::WriteZero.into())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        assert!(super::storage(&mut Refuse, "storage", &block).is_err());
    }
}
