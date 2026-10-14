//! Generate hex goldens for Norito AoS/NCB datasets used in tests.
use clap::Parser;
use color_eyre::eyre::{Result, WrapErr};
#[derive(Parser)]
struct Args {
    /// Print only dataset name filter (substring match)
    #[arg(long)]
    filter: Option<String>,
    /// Write fixtures to this directory (e.g., crates/norito/tests/data)
    #[arg(long)]
    out: Option<String>,
    /// When set, write known fixtures into `--out` directory
    #[arg(long)]
    write_fixtures: bool,
}
fn to_hex(bs: &[u8]) -> String {
    let mut s = String::with_capacity(bs.len() * 2);
    for b in bs {
        use core::fmt::Write as _;
        let _ = write!(&mut s, "{:02x}", b);
    }
    s
}
fn main() -> Result<()> {
    color_eyre::install()?;
    let args = Args::parse();
    let mut all = Vec::new();
    // AoS small: (u64, bytes, bool)
    {
        let rows: Vec<(u64, &[u8], bool)> = vec![(1, b"abc", true), (2, b"\x00\xff", false)];
        let bytes = norito::columnar::encode_rows_u64_bytes_bool_adaptive(&rows);
        all.push(("aos_bytes_bool_small".to_string(), bytes));
    }
    // AoS small: (u64, str, u32, bool)
    {
        let rows: Vec<(u64, &str, u32, bool)> = vec![(1, "x", 7, true), (2, "yy", 9, false)];
        let bytes = norito::columnar::encode_rows_u64_str_u32_bool_adaptive(&rows);
        all.push(("aos_str_u32_bool_small".to_string(), bytes));
    }
    // NCB small: (u64, str, bool)
    {
        let rows: Vec<(u64, &str, bool)> = vec![(1, "alice", true), (2, "bob", false)];
        let bytes = norito::columnar::encode_ncb_u64_str_bool(&rows);
        all.push(("ncb_str_bool_small".to_string(), bytes));
    }
    // NCB medium: (u64, str, bool) id-delta path
    {
        let rows: Vec<(u64, &str, bool)> = vec![
            (0, "a", true),
            (1, "b", false),
            (2, "c", true),
            (3, "d", false),
            (4, "e", true),
            (5, "f", false),
            (6, "g", true),
            (7, "h", false),
        ];
        let bytes = norito::columnar::encode_ncb_u64_str_bool(&rows);
        all.push(("ncb_str_bool_medium".to_string(), bytes));
    }
    // NCB small: (u64, Option<str>, bool)
    {
        let rows: Vec<(u64, Option<&str>, bool)> = vec![
            (1, Some("a"), false),
            (2, None, true),
            (3, Some("bc"), false),
        ];
        let bytes = norito::columnar::encode_ncb_u64_optstr_bool(&rows);
        all.push(("ncb_opt_str_bool_small".to_string(), bytes));
    }
    // NCB small: (u64, Option<u32>, bool)
    {
        let rows: Vec<(u64, Option<u32>, bool)> =
            vec![(1, Some(7), false), (2, None, true), (3, Some(9), false)];
        let bytes = norito::columnar::encode_ncb_u64_optu32_bool(&rows);
        all.push(("ncb_opt_u32_bool_small".to_string(), bytes));
    }
    // NCB dict(str): (u64, str, bool)
    {
        let rows: Vec<(u64, &str, bool)> = vec![
            (1, "ab", true),
            (2, "cd", false),
            (3, "ab", false),
            (4, "cd", true),
        ];
        let bytes = norito::columnar::encode_ncb_u64_str_bool_force_dict(&rows);
        all.push(("ncb_str_bool_dict_small".to_string(), bytes));
    }
    // NCB enum dict+code-delta: (u64, enum, bool)
    {
        use norito::columnar::EnumBorrow;
        let rows: Vec<(u64, EnumBorrow<'_>, bool)> = vec![
            (10, EnumBorrow::Name("x"), false),
            (12, EnumBorrow::Name("y"), true),
            (14, EnumBorrow::Code(7), false),
            (15, EnumBorrow::Code(8), true),
        ];
        let bytes = norito::columnar::encode_ncb_u64_enum_bool(&rows, false, true, true);
        all.push(("ncb_enum_dict_code_delta_small".to_string(), bytes));
    }
    // NCB enum offsets-based names + id-delta
    {
        use norito::columnar::EnumBorrow;
        let rows: Vec<(u64, EnumBorrow<'_>, bool)> = vec![
            (100, EnumBorrow::Name("aa"), true),
            (101, EnumBorrow::Code(7), false),
            (105, EnumBorrow::Name("bbb"), true),
            (112, EnumBorrow::Code(9), false),
        ];
        let bytes = norito::columnar::encode_ncb_u64_enum_bool(&rows, true, false, false);
        all.push(("ncb_enum_offsets_id_delta_small".to_string(), bytes));
    }
    // AoS enum small adaptive
    {
        use norito::columnar::EnumBorrow;
        let rows: Vec<(u64, EnumBorrow<'_>, bool)> = vec![
            (1, EnumBorrow::Name("x"), false),
            (2, EnumBorrow::Code(7), true),
        ];
        let bytes = norito::columnar::encode_rows_u64_enum_bool_adaptive(&rows);
        all.push(("aos_enum_small".to_string(), bytes));
    }
    // Offsets + code-delta variants
    {
        use norito::columnar::EnumBorrow;
        let rows: Vec<(u64, EnumBorrow<'_>, bool)> = vec![
            (1, EnumBorrow::Code(100), false),
            (2, EnumBorrow::Name("x"), true),
            (3, EnumBorrow::Code(100), false),
            (4, EnumBorrow::Code(105), true),
            (5, EnumBorrow::Name("y"), false),
        ];
        let bytes = norito::columnar::encode_ncb_u64_enum_bool(&rows, false, false, true);
        all.push(("ncb_enum_offsets_code_delta_variant1".to_string(), bytes));
    }
    {
        use norito::columnar::EnumBorrow;
        let rows: Vec<(u64, EnumBorrow<'_>, bool)> = vec![
            (10, EnumBorrow::Name("aa"), true),
            (11, EnumBorrow::Name("bb"), false),
            (12, EnumBorrow::Code(5), true),
            (13, EnumBorrow::Name("ccc"), false),
            (14, EnumBorrow::Code(6), true),
        ];
        let bytes = norito::columnar::encode_ncb_u64_enum_bool(&rows, false, false, true);
        all.push(("ncb_enum_offsets_code_delta_variant2".to_string(), bytes));
    }
    // Offsets + id/code deltas long-run pattern
    {
        use norito::columnar::EnumBorrow;
        let mut rows: Vec<(u64, EnumBorrow<'_>, bool)> = Vec::new();
        let mut id = 100u64;
        for i in 0..30u64 {
            let flag = i % 3 != 1;
            if i % 7 == 0 || i % 7 == 3 {
                let name = if i % 14 < 7 { "aa" } else { "bb" };
                rows.push((id, EnumBorrow::Name(name), flag));
            } else if i < 18 {
                rows.push((id, EnumBorrow::Code(300), flag));
            } else {
                rows.push((id, EnumBorrow::Code(301), flag));
            }
            id += 1;
        }
        let bytes = norito::columnar::encode_ncb_u64_enum_bool(&rows, true, false, true);
        all.push((
            "ncb_enum_offsets_long_repeats_zero_delta_codes".to_string(),
            bytes,
        ));
    }
    // Dict + id/code deltas long-run pattern
    {
        use norito::columnar::EnumBorrow;
        let mut rows: Vec<(u64, EnumBorrow<'_>, bool)> = Vec::new();
        let mut id = 1u64;
        for i in 0..28u64 {
            let flag = i % 4 != 2;
            if i % 6 == 0 || i % 6 == 4 {
                let name = if i % 12 < 6 { "aa" } else { "cc" };
                rows.push((id, EnumBorrow::Name(name), flag));
            } else if i < 16 {
                rows.push((id, EnumBorrow::Code(50), flag));
            } else {
                rows.push((id, EnumBorrow::Code(51), flag));
            }
            id += 1;
        }
        let bytes = norito::columnar::encode_ncb_u64_enum_bool(&rows, true, true, true);
        all.push((
            "ncb_enum_dict_long_repeats_zero_delta_codes".to_string(),
            bytes,
        ));
    }
    // Offsets alternating aa/300
    {
        use norito::columnar::EnumBorrow;
        let mut rows: Vec<(u64, EnumBorrow<'_>, bool)> = Vec::new();
        let mut id = 10u64;
        for i in 0..16u64 {
            if i % 2 == 0 {
                rows.push((id, EnumBorrow::Name("aa"), true));
            } else {
                rows.push((id, EnumBorrow::Code(300), true));
            }
            id += 1;
        }
        let bytes = norito::columnar::encode_ncb_u64_enum_bool(&rows, true, false, true);
        all.push(("ncb_enum_offsets_alternating_aa_300".to_string(), bytes));
    }
    // Dict alternating zz/77
    {
        use norito::columnar::EnumBorrow;
        let mut rows: Vec<(u64, EnumBorrow<'_>, bool)> = Vec::new();
        let mut id = 1u64;
        for i in 0..10u64 {
            if i % 2 == 0 {
                rows.push((id, EnumBorrow::Name("zz"), true));
            } else {
                rows.push((id, EnumBorrow::Code(77), true));
            }
            id += 1;
        }
        let bytes = norito::columnar::encode_ncb_u64_enum_bool(&rows, true, true, true);
        all.push(("ncb_enum_dict_alternating_zz_77".to_string(), bytes));
    }
    // Offsets nested window sequence
    {
        use norito::columnar::EnumBorrow;
        let rows: Vec<(u64, EnumBorrow<'_>, bool)> = vec![
            (10, EnumBorrow::Code(299), false),
            (11, EnumBorrow::Name("aa"), true),
            (12, EnumBorrow::Code(300), true),
            (13, EnumBorrow::Code(300), true),
            (14, EnumBorrow::Name("bb"), true),
            (15, EnumBorrow::Code(300), true),
            (16, EnumBorrow::Code(301), false),
        ];
        let bytes = norito::columnar::encode_ncb_u64_enum_bool(&rows, true, false, true);
        all.push(("ncb_enum_offsets_nested_window".to_string(), bytes));
    }
    for (name, bytes) in &all {
        if let Some(f) = &args.filter
            && !name.contains(f)
        {
            continue;
        }
        println!("{}: {}", name, to_hex(bytes));
    }
    if args.write_fixtures {
        let out_dir = args.out.as_deref().unwrap_or("crates/norito/tests/data");
        std::fs::create_dir_all(out_dir).wrap_err_with(|| format!("create out dir {}", out_dir))?;
        let write = |fname: &str, name_match: &str| -> Result<()> {
            if let Some((_, bytes)) = all.iter().find(|(n, _)| n.contains(name_match)) {
                let path = format!("{}/{}", out_dir, fname);
                std::fs::write(&path, to_hex(bytes)).wrap_err_with(|| format!("write {}", path))?;
            }
            Ok(())
        };
        // Known fixtures to write
        write(
            "enum_offsets_id_code_delta_large.hex",
            "ncb_enum_offsets_id_code_delta_large",
        )?;
        write(
            "enum_offsets_code_delta_small.hex",
            "ncb_enum_offsets_code_delta_small",
        )?;
        write(
            "enum_dict_id_code_delta_small.hex",
            "ncb_enum_dict_id_code_delta_small",
        )?;
        // Additional fixtures
        write(
            "enum_offsets_id_delta_small.hex",
            "ncb_enum_offsets_id_delta_small",
        )?;
        write(
            "enum_dict_code_delta_small.hex",
            "ncb_enum_dict_code_delta_small",
        )?;
        write(
            "enum_offsets_code_delta_variant1.hex",
            "ncb_enum_offsets_code_delta_variant1",
        )?;
        write(
            "enum_offsets_code_delta_variant2.hex",
            "ncb_enum_offsets_code_delta_variant2",
        )?;
        write(
            "enum_offsets_id_code_delta_small.hex",
            "ncb_enum_offsets_id_code_delta_small",
        )?;
        write(
            "enum_dict_id_delta_small.hex",
            "ncb_enum_dict_id_delta_small",
        )?;
        write(
            "enum_offsets_long_repeats_zero_delta_codes.hex",
            "ncb_enum_offsets_long_repeats_zero_delta_codes",
        )?;
        write(
            "enum_dict_long_repeats_zero_delta_codes.hex",
            "ncb_enum_dict_long_repeats_zero_delta_codes",
        )?;
        write(
            "enum_offsets_alternating_aa_300.hex",
            "ncb_enum_offsets_alternating_aa_300",
        )?;
        write(
            "enum_dict_alternating_zz_77.hex",
            "ncb_enum_dict_alternating_zz_77",
        )?;
        write(
            "enum_offsets_nested_window.hex",
            "ncb_enum_offsets_nested_window",
        )?;
    }
    Ok(())
}
