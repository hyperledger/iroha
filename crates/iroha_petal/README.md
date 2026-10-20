# iroha_petal

Reference implementation of **Petal Stream**, Iroha's animated optical transport: a `天`-shaped field
of katakana tiles inside three dotted rings, framed by four sakura-blossom finders. A phone camera
reads the animation and reassembles the payload. The wire format, geometry and receiver rules are
specified in [`specs/petal_stream.md`](../../specs/petal_stream.md).

The crate is `std`-only and has no runtime dependencies.

| Module | Purpose |
| --- | --- |
| `rs`, `crc`, `prng` | GF(256) Reed–Solomon with erasures, CRC-32C, xorshift32 |
| `layout`, `glyphs` | normative geometry, the 256-tile `天` mask, rings, finders, 16 katakana |
| `lanes`, `fountain`, `stream` | the three lane codewords, the GF(2) fountain code, `StreamEncoder` / `StreamAssembler` |
| `render` | software renderer for frames (SDKs also expose a vector draw list) |
| `locate`, `decode`, `session` | camera luma → finders (three are enough) → pose → lanes; `ScanSession` tracks the pose between frames and merges the captures of one shown frame |
| `sim`, `qualify` | deterministic camera simulator and end-to-end stream trials |

```text
cargo test -p iroha_petal                                   # unit tests + golden fixtures + golden captures
cargo run --release -p iroha_petal --example qualify -- 60  # per-frame decode matrix over camera conditions
cargo run --release -p iroha_petal --example stress -- 40   # light, motion and hidden-corner stress
cargo run --release -p iroha_petal --example stream_sim -- 8 10000 8   # end to end, a KAGEMUSHA-sized message
cargo run -p iroha_petal --example gen_fixtures -- fixtures/petal/petal_stream_v1.json
cargo run --release -p iroha_petal --example gen_captures -- fixtures/petal/petal_captures_v1.json
```

`fixtures/petal/*.json` are the cross-SDK conformance suite; `tests/fixtures.rs` and `tests/captures.rs`
fail if they drift from this implementation. The `iroha offline petal` commands in `iroha_cli` are thin wrappers.
