#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
#[derive(Clone, Debug, Arbitrary)]
struct Row {
    id: u64,
    present: bool,
    #[arbitrary(with = arbitrary_string_cap)]
    val: String,
    flag: bool,
}
fn arbitrary_string_cap(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<String> {
    // Cap string length to keep encodes cheap
    let n: usize = u.int_in_range(0..=32)?;
    let mut s = String::with_capacity(n);
    for _ in 0..n {
        // printable ASCII range
        let c: u8 = u.int_in_range(0x20..=0x7e)?;
        s.push(c as char);
    }
    Ok(s)
}
fuzz_target!(|rows: Vec<Row>| {
    let rows = rows.into_iter().take(64).collect::<Vec<_>>();
    let borrowed: Vec<(u64, Option<&str>, bool)> = rows
        .iter()
        .map(|r| {
            (
                r.id,
                if r.present {
                    Some(r.val.as_str())
                } else {
                    None
                },
                r.flag,
            )
        })
        .collect();
    let body = norito::aos::encode_rows_u64_optstr_bool(&borrowed);
    let view = norito::columnar::view_aos_u64_optstr_bool(&body).expect("view");
    assert_eq!(view.len(), borrowed.len());
    for (i, &(id, value, flag)) in borrowed.iter().enumerate() {
        assert_eq!(view.id(i), id);
        let got = view.name(i).expect("utf8");
        match value {
            None => assert_eq!(got, None),
            Some(s) => assert_eq!(got, Some(s)),
        }
        assert_eq!(view.flag(i), flag);
    }
});
