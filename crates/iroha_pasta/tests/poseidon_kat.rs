//! Known-answer tests of the KAGEMUSHA RP57 Poseidon permutation and sponge.
//!
//! These historical vectors were exported by a scratch program from the
//! now-deleted vendor/halo2-base `OptimizedPoseidonSpec::<F, 3, 2>::new::<8, 57, 0>()`
//! and snark-verifier `Poseidon` sponge. No live `iroha_plonk_oracle` or vendored
//! prover is required. This suite checks the retained answers and regenerates
//! the constant tables from RP57 parameters via `iroha_pasta::poseidon::grain`.
//! `fixtures/native_prover/verify_kats_v1.py` separately rederives the recorded
//! RP57 hash and transcript KATs using plain integer arithmetic.

use ff::{Field, PrimeField};
use iroha_pasta::poseidon::{PoseidonField, PoseidonParams, Sponge, hash, hash_with_domain};
use iroha_pasta::{Fp, Fq};
use sha2::{Digest, Sha256};

fn hex_bytes(bytes: &[u8]) -> String {
    use core::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

fn hex<F: PrimeField<Repr = [u8; 32]>>(v: F) -> String {
    hex_bytes(&v.to_repr())
}

macro_rules! kat_suite {
    ($field:ty) => {{
        type F = $field;
        // Table pins.
        assert_eq!(
            hex_bytes(&Sha256::digest(F::rp57().to_table())),
            TABLE_SHA256
        );
        assert_eq!(PoseidonParams::<F>::generate(), *F::rp57());
        // Sequential preimages i * 0x9e3779b9 + 1.
        for (len, expected) in SEQ {
            let pre: Vec<F> = (0..len as u64)
                .map(|i| F::from(i * 0x9e37_79b9 + 1))
                .collect();
            assert_eq!(hex(hash(&pre)), expected, "seq len = {len}");
        }
        // Repeated special values.
        let specials = [
            F::ZERO,
            F::ONE,
            -F::ONE,
            F::from_u128(u128::MAX),
            F::from(0x6b67_6d73_7461_7465u64),
        ];
        for (i, len, expected) in SPECIAL {
            let pre = vec![specials[i]; len];
            assert_eq!(hex(hash(&pre)), expected, "special {i} len = {len}");
        }
        // The empty depth-256 replay root (`kagemusha_v1_poseidon` in kats_v1.json).
        let empty = u64::from_le_bytes(*b"kgmemp_1");
        let node = u64::from_le_bytes(*b"kgmnode1");
        let mut root = hash_with_domain::<F>(empty, &[]);
        assert_eq!(hex(root), EMPTY_LEAF);
        for _ in 0..256 {
            root = hash_with_domain(node, &[root, root]);
        }
        assert_eq!(hex(root), EMPTY_ROOT256);
        // A reused sponge resets exactly like the reference.
        let mut sponge = Sponge::<F>::new();
        sponge.update(&[F::from(1u64)]);
        let first = sponge.squeeze();
        sponge.clear();
        sponge.update(&[F::from(1u64)]);
        assert_eq!(sponge.squeeze(), first);
    }};
}

#[test]
fn fp_rp57_known_answers() {
    const SEQ: [(usize, &str); 10] = [
        (
            0,
            "23f1b32003877d36d483529dffb86a64860e264cff6d1ac5a5d41f56a024c737",
        ),
        (
            1,
            "712798cdffb3d3f4f533af5e7fb89d76515be8066f3acc8f678fe80947099807",
        ),
        (
            2,
            "d00001a978ab605be788a836d6dc7ca2df1deebc8b6954090238c1460538832f",
        ),
        (
            3,
            "a75b6782d2fc8eeda44a50c3954ce62f609be22977a762a3d1b0087a1eb07f2e",
        ),
        (
            4,
            "104f5caebfcb4a90d8d07c0ffaea50ba63a87613552ca5c92787e9b8d135d23d",
        ),
        (
            5,
            "0f7baf85a0129ad4ef1218b110217a88a0d2667afb40648ee4ef043bdafbba23",
        ),
        (
            6,
            "249779afa6b638c9ff86e8fef94e88c5f28e36cfae3ffc94948c9ed10709e83c",
        ),
        (
            7,
            "9c9ee2eb080ce1b4c8514efdfa23d01282ee071947d2e5da84e767722ba7c213",
        ),
        (
            8,
            "d5903abdef9ccdbfbc6b7635a165d00e042c84fd66ac9b2abb039d597d7bca19",
        ),
        (
            9,
            "9c0d364ceb40a42a388a9516de6e382ac6f8833cc056ebe98a0ed44095e48807",
        ),
    ];
    const SPECIAL: [(usize, usize, &str); 15] = [
        (
            0,
            1,
            "12aa4d0e2b74040117d865bf43828ebddd4dc3aa263da93b082bda66a582643a",
        ),
        (
            0,
            2,
            "8e88de5682805018349d8eac33b79973d7072ede3e891bbd1f350572e61b2220",
        ),
        (
            0,
            3,
            "c620b9352f8d208996d59ef6ac3968687dda5063fb9d4a2d4f729cc14976b93e",
        ),
        (
            1,
            1,
            "712798cdffb3d3f4f533af5e7fb89d76515be8066f3acc8f678fe80947099807",
        ),
        (
            1,
            2,
            "d5c1a8e6acb3e4e50d14c4ddcfc6cdd73919b567f36d5f7f55a4bb0667327520",
        ),
        (
            1,
            3,
            "1dce2b43155fdf09a104fef7e8c056985c45c143fdc78816b2b07a273d425900",
        ),
        (
            2,
            1,
            "f2be99046adc127a725a3c51e8d2dccd9513a5466b229aa32161c1ab545f7d29",
        ),
        (
            2,
            2,
            "738b8df2a784bfc67ce9434dbcf0aad2a7a42cbbb1f3250bb8e041d9a9c48b3c",
        ),
        (
            2,
            3,
            "add5fc529cbd9fb917901d97e2f1e4d93d3f57b26f8cb5dcc7471509bc080b34",
        ),
        (
            3,
            1,
            "359af6bff11ab69ccc5f85840f50cc2c54f9c5642b6ade6fb18dd74e71df3f21",
        ),
        (
            3,
            2,
            "bf0252413f12333674cb67d0c3bc8bca2feb5f9e137bab2756a27fc686a8ac38",
        ),
        (
            3,
            3,
            "0a9c7dfdc33d7023418c4885387f173c60b8e1fb747c898416bd9ec2b694ed26",
        ),
        (
            4,
            1,
            "4728c888d6e455e35477d4a2aa39074e161ae4c37e3b2d0cdc66594105977831",
        ),
        (
            4,
            2,
            "4653d0b5d6625ac09eee13afc907c1805bcb10c02796233a751891b2729ae32c",
        ),
        (
            4,
            3,
            "1025a22d07f5acfacf783fb260d04e6b9053e7a252475dc507c611fbfae1fd22",
        ),
    ];
    const EMPTY_LEAF: &str = "2174eb6c57efaaccc234104db9386ed1bec889b4407135c41b9627e768a73206";
    const EMPTY_ROOT256: &str = "3b2058d379473de650709a862def06e614056fb0bfa2d76d50f1e95a4345693b";
    const TABLE_SHA256: &str = "9193ac5da831ecf38647ad4050ce4c557d688c4aabc12fe75e3b1e090c454a20";
    kat_suite!(Fp);
}

#[test]
fn fq_rp57_known_answers() {
    const SEQ: [(usize, &str); 10] = [
        (
            0,
            "e9040fd5b92dd549b30d5f1c370eb3e6156bcdf59540809c81b75596ee74ed04",
        ),
        (
            1,
            "0be5dbd1d8df9f839bb1434b74ae9fe4e795785803d9b9d118f3875ca6a4d718",
        ),
        (
            2,
            "0e855fd3efcfb3a2d9d943cbf8d5b8301559b1936f20a458fec4e87ae493f104",
        ),
        (
            3,
            "9e521c1c018a89591e1174c3e2d0d42f0a65aa4a923f26e1995de1bb4d71893b",
        ),
        (
            4,
            "32b6c80830a8384b052cba0a115581041915890872d137e7753835804df2363a",
        ),
        (
            5,
            "051399b49536ea54bc5f78e1ecd200c52fc923d10042659604da4570c85e043e",
        ),
        (
            6,
            "5b34b93a58b8e67c9a2ef1c0b24c90262f672ba0dc9ef506169ba73d855b7812",
        ),
        (
            7,
            "94a99726e4e75ea2edd650afb2de666b81a82bc1f3007950346959d7b22b333b",
        ),
        (
            8,
            "04e55ab661764e7b47deeb2614bcc53d034d9725c27e7018bac95c2efeb5e13f",
        ),
        (
            9,
            "c1726da90b01aa62a567b747c2e3838a8df8508a747f949364d7370c761c210f",
        ),
    ];
    const SPECIAL: [(usize, usize, &str); 15] = [
        (
            0,
            1,
            "c933853fe01febf71c6e0b89f604ec4c30ab92482337038b4f31eb233829f209",
        ),
        (
            0,
            2,
            "9496fcb2221767761f5d9724599ec898ca131f1e6c139714bdee00d08c68501f",
        ),
        (
            0,
            3,
            "61d2d427a28002659a1b784e08cb03b5ef6ab21180d792c75b788f7a6742502d",
        ),
        (
            1,
            1,
            "0be5dbd1d8df9f839bb1434b74ae9fe4e795785803d9b9d118f3875ca6a4d718",
        ),
        (
            1,
            2,
            "d1a0f261274e2db466043f9927749b385d471d4e48258c55e8a54ce4cf3b2e22",
        ),
        (
            1,
            3,
            "855c9172184c19c50bc350656c81f951c52d57c666f9b59f9d5279a32a90903e",
        ),
        (
            2,
            1,
            "b7e943f5b0aa5229c5cbbe5edd8302e43162924460df6dac9d7858b08206dc08",
        ),
        (
            2,
            2,
            "a7e94b389f34c31d61ea40bf6d384f57a15309c6b2d9ab8b3e43fafc0938ca3d",
        ),
        (
            2,
            3,
            "c3f035009b9c6cbbe7f911b637eb791a10b88496d422ecdb5ba24f8d1b9c3635",
        ),
        (
            3,
            1,
            "c0fc637608a3bdc5e2ec661fe2e01012b9cf6abbc7a7c6454b9c895b6272aa2a",
        ),
        (
            3,
            2,
            "189e3647c7ffb1e1264116241bd3dcab7ba1ac37be81ac562dea596fc6232832",
        ),
        (
            3,
            3,
            "1d57d18f551dff265a988be9236ab9e4059e76420207e2ca2a6d5beaebf4aa3c",
        ),
        (
            4,
            1,
            "45bbbd0dd99c1b4be29b0124a8c28e5eeed61df5851c63d150d31787971a7b35",
        ),
        (
            4,
            2,
            "385d9ed3008f2631f501692c86dd8e93ced2eea43b77cbb53ec7b6be514dba31",
        ),
        (
            4,
            3,
            "431343dd60e8dd5d6cf50512484f76ea778b8f3ec41d97e5e4321f03a418be01",
        ),
    ];
    const EMPTY_LEAF: &str = "d3dafc9b703fe4b540ce4d8503a1cf4ae26224a6e3d91014dce038230690333b";
    const EMPTY_ROOT256: &str = "5b25531d37f82b21a6ca4e752016fdc7373500ca624ad02f2a15686c94645e2c";
    const TABLE_SHA256: &str = "1adf5ad0fabbd99fedfeebd70a2a374c896cf47c9d7e92dfe04f1146cdab5830";
    kat_suite!(Fq);
}
