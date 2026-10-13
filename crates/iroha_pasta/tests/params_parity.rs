//! Parameter KATs against bytes captured before the external prover was retired.
//!
//! The SHA-256 digests below were exported from vendor/halo2-axiom at the M1a
//! baseline by a scratch program calling
//! `ParamsIPA::<EqAffine | EpAffine>::new(k).write(..)`. Those sources and
//! `iroha_plonk_oracle` are now deleted. These tests freshly derive native
//! parameters, compare the retained digests and check the strict codec round
//! trip. `params::tests::lagrange_basis_matches_naive_group_dft` separately
//! checks the group IFFT. A changed digest is a format change, never a test
//! update.

use iroha_pasta::params::ParamsIpa;
use iroha_pasta::{Ep, Eq, PastaCurve};
use sha2::{Digest, Sha256};

const VESTA_DIGESTS: [(u32, &str); 16] = [
    (
        1,
        "5f154f1e7de63390ff038c01f7ba8d41980fe43fb37a16a9880a4d6949faec03",
    ),
    (
        2,
        "91a6d514d942b065f9ec98af3fbd331b27738e7b8b931fc63c99548ffcacb15c",
    ),
    (
        3,
        "0bd0df6b76a96eb97bf1de8d1ceb133dc1eb09560532f2874821e0520059e79b",
    ),
    (
        4,
        "5c0b8093a964af7191df4749a7310c00140ebc9977b118debe5715fda30efa7f",
    ),
    (
        5,
        "106977185e775dffe917fe065308d3469d747e79617911bfb7d3f78e2bcb552c",
    ),
    (
        6,
        "606ec71853588ea2414707e98ffb181091f6985d294d03d4165fb400a9a6b3a6",
    ),
    (
        7,
        "432e492288c43ccabdffb913625109ca76f66312cd4625c9a258a2e33a28c400",
    ),
    (
        8,
        "96d2448c483f4df37e69b4f72db328cd8520b09d49f5e7c801da7994150b9b33",
    ),
    (
        9,
        "b7ea13dd3cfe5db384fab28fd90c4ca7327fb20d3fde16c12eb8b3f81538cb62",
    ),
    (
        10,
        "65235f086265cdf98b12514ab36fe9b849198870918d73cd160903ceb0a954dc",
    ),
    (
        11,
        "1eab6f93a080ce41b908d935c04bd2e3ed1ac23f277c15d11c499d56d28fa0f7",
    ),
    (
        12,
        "1b97b06da453b9efb1ae18b9ba77c3d870f22dc72898297d5707e340c3f44865",
    ),
    (
        13,
        "76ebe6b75b5281cb1dcc2eb04888968573758672b521522f62abedf6366bb876",
    ),
    (
        14,
        "1cb278fe4d9cf5325e5cbc710d863c0deca3e961e1b8f6c8736890c43345c461",
    ),
    (
        15,
        "e1fb29749c7bd0870768044d5329b4e293cb2d44dae24db2554605427b19d0dd",
    ),
    (
        16,
        "174780f80c577d968d10bc3f0a8f819e55a96b9e882ffe73c15d55e9f94053e2",
    ),
];

const PALLAS_DIGESTS: [(u32, &str); 16] = [
    (
        1,
        "39f988690976928ca024e703f670a78cd493e797aadc034756c4726f04daa7ec",
    ),
    (
        2,
        "d8880eac8d6714dbbb6f5c342067e3306e6938b6b71fad874f6430bb80489e1d",
    ),
    (
        3,
        "6983c94f529842fef70117753bde985b60f69e18353e3bcd6d64bdf6534c3e71",
    ),
    (
        4,
        "49708ed23c310f1c97fae59d99dd7d7eaec88f2f4f077610ce3dda92ad0d0707",
    ),
    (
        5,
        "4d0841527d3ff9b49ce6153351988ff961ddc39e76153b1439461cc8682e97ef",
    ),
    (
        6,
        "81ecfc65612a3e22f46adcd8775b547b476671a5e17e98e53081408d5c9c7aa7",
    ),
    (
        7,
        "f999cf187832b2fe6c54e68656bcedc92d0902ab42fa279f5c845f31338c5ecf",
    ),
    (
        8,
        "6e3c9ff565425ebea04de329b34fb3bb6061a3d43417706448ab00e8e3efb602",
    ),
    (
        9,
        "30c2a8e1a423467b96a586ee97f2e6b04d6cc95de1d0dab4f233a9ddad3d0c51",
    ),
    (
        10,
        "422e1701e538cf2c50fa2f7489c30d73477d5700d8da6ff73f75c2a7aedf04e4",
    ),
    (
        11,
        "56ec863de1374a91a99e53b247ec804c4ea7888400df9f23add747e227000a6a",
    ),
    (
        12,
        "4b20d41b76f4249829f16b08b1df0a8d6cc8897fa4394b74681b51332f4039b6",
    ),
    (
        13,
        "345da39c48ee9d86cc74c9610536ff007bd8b611d801d00598dd3b90c22149d4",
    ),
    (
        14,
        "2527d71bdb1d374a1b5cc29cf73f7849a87bce5e24c0d1bda0b284f12bf570c4",
    ),
    (
        15,
        "0e177a0c9bcf63020c884269dbc3db8a27e583394f1ac65383e7fb2ed45df687",
    ),
    (
        16,
        "2eb6e09a8f0dfdd18df0ec2ad5186d900acd5374eac817bdbb72f0f51b694628",
    ),
];

fn hex(bytes: &[u8]) -> String {
    use core::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

fn check<C: PastaCurve>(digests: &[(u32, &str)], ks: core::ops::RangeInclusive<u32>) {
    for &(k, expected) in digests.iter().filter(|(k, _)| ks.contains(k)) {
        let params = ParamsIpa::<C>::new(k).expect("supported k");
        let bytes = params.to_bytes();
        assert_eq!(bytes.len(), iroha_pasta::params::encoded_len(k).unwrap());
        assert_eq!(
            hex(&Sha256::digest(&bytes)),
            expected,
            "{} k = {k}",
            C::CURVE_ID
        );
        let decoded = ParamsIpa::<C>::from_bytes(&bytes).expect("strict decode");
        assert!(decoded == params, "round trip k = {k}");
    }
}

#[test]
fn vesta_params_match_vendored_k1_to_k14() {
    check::<Eq>(&VESTA_DIGESTS, 1..=14);
}

#[test]
fn pallas_params_match_vendored_k1_to_k14() {
    check::<Ep>(&PALLAS_DIGESTS, 1..=14);
}

#[test]
#[ignore = "k15 and k16 take seconds per curve; run with --include-ignored"]
fn params_match_vendored_k15_k16() {
    check::<Eq>(&VESTA_DIGESTS, 15..=16);
    check::<Ep>(&PALLAS_DIGESTS, 15..=16);
}
