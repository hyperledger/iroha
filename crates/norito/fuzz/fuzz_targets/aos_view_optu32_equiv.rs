#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
#[derive(Clone, Debug, Arbitrary)]
struct Row {
    id: u64,
    present: bool,
    val: u32,
    flag: bool,
}
fuzz_target!(|rows: Vec<Row>| {
    let rows = rows.into_iter().take(128).collect::<Vec<_>>();
    let borrowed: Vec<(u64, Option<u32>, bool)> = rows
        .iter()
        .map(|r| (r.id, if r.present { Some(r.val) } else { None }, r.flag))
        .collect();
    let body = norito::aos::encode_rows_u64_optu32_bool(&borrowed);
    let view = norito::columnar::view_aos_u64_optu32_bool(&body).expect("view");
    assert_eq!(view.len(), borrowed.len());
    for (i, &(id, value, flag)) in borrowed.iter().enumerate() {
        assert_eq!(view.id(i), id);
        assert_eq!(view.val(i), value);
        assert_eq!(view.flag(i), flag);
    }
});
