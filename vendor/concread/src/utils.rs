use std::borrow::Borrow;
use std::cmp::Ordering;
use std::ptr;

pub(crate) unsafe fn slice_insert<T>(slice: &mut [T], new: T, idx: usize) {
    let len = slice.len();
    let slice = slice.as_mut_ptr();
    ptr::copy(slice.add(idx), slice.add(idx + 1), len - idx - 1);
    ptr::write(slice.add(idx), new);
}

// From std::collections::btree::node.rs
pub(crate) unsafe fn slice_remove<T>(slice: &mut [T], idx: usize) -> T {
    // setup the value to be returned, IE give ownership to ret.
    let len = slice.len();
    let ret = ptr::read(slice.get_unchecked(idx));
    let slice = slice.as_mut_ptr();
    ptr::copy(slice.add(idx + 1), slice.add(idx), len - idx - 1);
    ret
}

pub(crate) unsafe fn slice_merge<T>(dst: &mut [T], start_idx: usize, src: &mut [T], count: usize) {
    let dst_ptr = dst.as_mut_ptr().add(start_idx);
    let src_ptr = src.as_ptr();

    ptr::copy_nonoverlapping(src_ptr, dst_ptr, count);
}

pub(crate) unsafe fn slice_move<T>(
    dst: &mut [T],
    dst_start_idx: usize,
    src: &mut [T],
    src_start_idx: usize,
    count: usize,
) {
    let dst_ptr = dst.as_mut_ptr().add(dst_start_idx);
    let src_ptr = src.as_ptr().add(src_start_idx);

    ptr::copy_nonoverlapping(src_ptr, dst_ptr, count);
}

pub(crate) fn slice_search_linear<K, Q>(slice: &[K], k: &Q) -> Result<usize, usize>
where
    K: Borrow<Q>,
    Q: Ord + ?Sized,
{
    for (idx, nk) in slice.iter().enumerate() {
        let r = k.cmp(nk.borrow());
        match r {
            Ordering::Greater => {}
            Ordering::Equal => return Ok(idx),
            Ordering::Less => return Err(idx),
        }
    }
    Err(slice.len())
}
