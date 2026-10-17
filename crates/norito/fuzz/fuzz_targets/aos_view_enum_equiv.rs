#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
#[derive(Clone, Debug, Arbitrary)]
enum E {
    Name(#[arbitrary(with = arbitrary_string_cap)] String),
    Code(u32),
}
#[derive(Clone, Debug, Arbitrary)]
struct Row {
    id: u64,
    e: E,
    flag: bool,
}
fn arbitrary_string_cap(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<String> {
    let n: usize = u.int_in_range(0..=32)?;
    let mut s = String::with_capacity(n);
    for _ in 0..n {
        let c: u8 = u.int_in_range(0x20..=0x7e)?;
        s.push(c as char);
    }
    Ok(s)
}
fuzz_target!(|rows: Vec<Row>| {
    use norito::columnar::{AosEnumRef, EnumBorrow};
    let rows = rows.into_iter().take(128).collect::<Vec<_>>();
    let borrowed: Vec<(u64, EnumBorrow<'_>, bool)> = rows
        .iter()
        .map(|r| match &r.e {
            E::Name(s) => (r.id, EnumBorrow::Name(s.as_str()), r.flag),
            E::Code(v) => (r.id, EnumBorrow::Code(*v), r.flag),
        })
        .collect();
    let body = norito::aos::encode_rows_u64_enum_bool(&borrowed);
    let view = norito::columnar::view_aos_u64_enum_bool(&body).expect("view");
    assert_eq!(view.len(), borrowed.len());
    for (i, (id, payload, flag)) in borrowed.iter().enumerate() {
        assert_eq!(view.id(i), *id);
        match (payload, view.payload(i).expect("payload")) {
            (EnumBorrow::Name(s), AosEnumRef::Name(ns)) => assert_eq!(*s, ns),
            (EnumBorrow::Code(v), AosEnumRef::Code(cv)) => assert_eq!(*v, cv),
            _ => panic!("variant mismatch"),
        }
        assert_eq!(view.flag(i), *flag);
    }
});
