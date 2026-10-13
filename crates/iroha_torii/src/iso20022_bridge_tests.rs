use super::*;
use iroha_core::iso_bridge::reference_data::SnapshotState;
use iroha_core::state::World;
use iroha_crypto::{Algorithm, KeyPair, PublicKey, Signature};
use iroha_data_model::{
    Registrable, ValidationFail,
    account::Account,
    asset::{AssetDefinition, AssetDefinitionAlias},
    domain::Domain,
    nexus::{AxtRejectContext, AxtRejectReason},
    transaction::error::{TransactionLimitError, TransactionRejectionReason},
};
use iroha_model_base::chain::ChainId;
use iroha_model_base::{topology::DataSpaceId, topology::LaneId};
use p256::{
    ecdsa::{SigningKey as P256SigningKey, signature::Signer as _},
    pkcs8::DecodePrivateKey as _,
};
use rcgen::{
    BasicConstraints, CertificateParams, CustomExtension, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair as RcgenKeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
    PKCS_ECDSA_P384_SHA384, PublicKeyData, SignatureAlgorithm, SigningKey as _, date_time_ymd,
};
use std::{str::FromStr, time::SystemTime};
use tempfile::{NamedTempFile, TempDir};
const LEGACY_PUBLIC_KEY_LITERAL: &str =
    "ed0120AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA@test";
const XML_SIGNATURE_TEST_SIGNING_TIME: &str = "2026-06-02T12:00:00Z";
const TEST_PACS008_NAMESPACE: &str = "urn:iso:std:iso:20022:tech:xsd:pacs.008.001.08";
const OFFICIAL_XSD_PACS008_001_08: &str =
    include_str!(r"../../../fixtures/iso20022/xsd/iso/pacs.008.001.08.xsd");
const OFFICIAL_XSD_PACS009_001_08: &str =
    include_str!(r"../../../fixtures/iso20022/xsd/iso/pacs.009.001.08.xsd");
const OFFICIAL_XSD_PACS002_001_10: &str =
    include_str!(r"../../../fixtures/iso20022/xsd/iso/pacs.002.001.10.xsd");
const OFFICIAL_XSD_PACS004_001_09: &str =
    include_str!(r"../../../fixtures/iso20022/xsd/iso/pacs.004.001.09.xsd");
const OFFICIAL_XSD_PACS004_001_10: &str =
    include_str!(r"../../../fixtures/iso20022/xsd/iso/pacs.004.001.10.xsd");
const OFFICIAL_XSD_CAMT056_001_08: &str =
    include_str!(r"../../../fixtures/iso20022/xsd/iso/camt.056.001.08.xsd");
const OFFICIAL_XSD_CAMT056_001_09: &str =
    include_str!(r"../../../fixtures/iso20022/xsd/iso/camt.056.001.09.xsd");
const PACS002_FIXTURE_XML: &str = include_str!(r"../../../fixtures/iso20022/pacs002_fixture.xml");
const PACS004_FIXTURE_XML: &str = include_str!(r"../../../fixtures/iso20022/pacs004_fixture.xml");
const CAMT056_FIXTURE_XML: &str = include_str!(r"../../../fixtures/iso20022/camt056_fixture.xml");
const SESE023_FIXTURE_XML: &str = include_str!(r"../../../fixtures/iso20022/sese023_fixture.xml");
const SESE024_FIXTURE_XML: &str = include_str!(r"../../../fixtures/iso20022/sese024_fixture.xml");
const SESE025_FIXTURE_XML: &str = include_str!(r"../../../fixtures/iso20022/sese025_fixture.xml");
const COLR012_FIXTURE_XML: &str = include_str!(r"../../../fixtures/iso20022/colr012_fixture.xml");
const TEST_X509_CERTIFICATE_DER_B64: &str = "MIIBlTCCATugAwIBAgIUXiaSrYGsJgKt3u4x6BKKksfNLiAwCgYIKoZIzj0EAwIwIDEeMBwGA1UEAwwVSXJvaGEgSVNPIFRlc3QgU2lnbmVyMB4XDTI2MDYwMTExMjgyOVoXDTM2MDUyOTExMjgyOVowIDEeMBwGA1UEAwwVSXJvaGEgSVNPIFRlc3QgU2lnbmVyMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAWqzmlOSaGzSgxorUv+ewSw3Fy3Sde/6hMOgKLkgt21a791Jequ1zTyts6rrpZoBLozZBqHl0A7E8vTW587o9KNTMFEwHQYDVR0OBBYEFBL9Vo3Y+LvYlfKs0v5haxjUm1rtMB8GA1UdIwQYMBaAFBL9Vo3Y+LvYlfKs0v5haxjUm1rtMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIgZQdqU2vQe1kA3tnVW3/Md+A0CvjHC4VwaRGw1GTVsQwCIQD7mrXnQAnnVmnriWX35eVtmDSz2uGA5Xztav0D1Gd0PA==";
const TEST_X509_CHAIN_LEAF_SIGNING_KEY_PKCS8_DER_B64: &str = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgUryIDQvn/6N9fG2pQEVTQEP9UqzRspBrkNdwndN+s+WhRANCAARTR4/Y7uTA2FBawlygx0Q7obN3BTEoh3AKjHTqZl+nMYfoiY+9bGJ7YHVDy6Ca/xWf2Yd0y64/7P1Ti9rJqPM6";
const TEST_X509_CHAIN_LEAF_CERTIFICATE_DER_B64: &str = "MIIBnzCCAUagAwIBAgIUUOi8MD0vRAq9AAbDmuxRfRDZdeQwCgYIKoZIzj0EAwIwHjEcMBoGA1UEAwwTSXJvaGEgSVNPIFRlc3QgUm9vdDAgFw0yNjA2MDExMjAwMzhaGA8yMTI2MDUwODEyMDAzOFowHjEcMBoGA1UEAwwTSXJvaGEgSVNPIFRlc3QgTGVhZjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABFNHj9ju5MDYUFrCXKDHRDuhs3cFMSiHcAqMdOpmX6cxh+iJj71sYntgdUPLoJr/FZ/Zh3TLrj/s/VOL2smo8zqjYDBeMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeAMB0GA1UdDgQWBBS7L2CAjWtk6fBcYscT8f7Cjpv4vDAfBgNVHSMEGDAWgBRD+yqEVN85+okIsrT2tOc86jK3HzAKBggqhkjOPQQDAgNHADBEAiAled9C2Mpk2BdR84/evD5DyQ+Kt9TZuNrZMkkrjx6tiwIgLHYNDEXdEZMgKj838ELQ/9vtz5f2WSNaUN5ehURQBjY=";
const TEST_X509_CHAIN_ROOT_CERTIFICATE_DER_B64: &str = "MIIBpzCCAUygAwIBAgIUN59zZbCa78pNzUJAco7cB7HX9S0wCgYIKoZIzj0EAwIwHjEcMBoGA1UEAwwTSXJvaGEgSVNPIFRlc3QgUm9vdDAgFw0yNjA2MDExMjAwMzhaGA8yMTI2MDUwODEyMDAzOFowHjEcMBoGA1UEAwwTSXJvaGEgSVNPIFRlc3QgUm9vdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJtrF+Op4oQRaLLDdmComaR9cvtsrLpACh9gm1HLvCGC0HB9r50w6P1cgrEZ2j2dokVXpdx3axIUM9+BjrhmI4SjZjBkMB8GA1UdIwQYMBaAFEP7KoRU3zn6iQiytPa05zzqMrcfMBIGA1UdEwEB/wQIMAYBAf8CAQEwDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBRD+yqEVN85+okIsrT2tOc86jK3HzAKBggqhkjOPQQDAgNJADBGAiEA4Y9l0Zhe+cgWss7+jyOXJ/bsqLJ+MLGtD54H9dKRA/UCIQDRkR+vyF4COJO3ZGMeLGxZDf/e4bEYwEu72okoPu9/RA==";
const TEST_X509_UNKNOWN_CRITICAL_LEAF_SIGNING_KEY_PKCS8_DER_B64: &str = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgwU8aNjPS3jld2m1xIeGpj9006lOpLzF66Jc3OrrvzsWhRANCAAQ7OfFyeTB68ox7nX66Br7Az7o1dG4lEePTIgQDxOWnQNrDJDMRDAC2SrB9qT02pqXShqN+i/zSnf/ULeuaZOmq";
const TEST_X509_UNKNOWN_CRITICAL_LEAF_CERTIFICATE_DER_B64: &str = "MIIBxTCCAWqgAwIBAgICUQEwCgYIKoZIzj0EAwIwLzEtMCsGA1UEAwwkSXJvaGEgSVNPIFVua25vd24gQ3JpdGljYWwgVGVzdCBSb290MCAXDTI2MDYwMTAwMDAwMFoYDzIxMjYwNTA4MDAwMDAwWjAvMS0wKwYDVQQDDCRJcm9oYSBJU08gVW5rbm93biBDcml0aWNhbCBUZXN0IExlYWYwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQ7OfFyeTB68ox7nX66Br7Az7o1dG4lEePTIgQDxOWnQNrDJDMRDAC2SrB9qT02pqXShqN+i/zSnf/ULeuaZOmqo3QwcjAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIHgDAdBgNVHQ4EFgQU0PAOpCGj0CuPwuWetUFFPNgJVSYwHwYDVR0jBBgwFoAUFILzl7ccbofpo9P/TlWVjtux/uYwEgYFKgMEBQYBAf8EBgQEZGVueTAKBggqhkjOPQQDAgNJADBGAiEA1Xcu7wyj9eRGRCQQQhI75D+lRVootpWB2fw0I+ZJMxACIQCYhjqnSvkfMQDYbXtgVhjlzGrGmrMZW7OCkPzLH4TMPg==";
const TEST_X509_UNKNOWN_CRITICAL_ROOT_CERTIFICATE_DER_B64: &str = "MIIBtzCCAVygAwIBAgICUQAwCgYIKoZIzj0EAwIwLzEtMCsGA1UEAwwkSXJvaGEgSVNPIFVua25vd24gQ3JpdGljYWwgVGVzdCBSb290MCAXDTI2MDYwMTAwMDAwMFoYDzIxMjYwNTA4MDAwMDAwWjAvMS0wKwYDVQQDDCRJcm9oYSBJU08gVW5rbm93biBDcml0aWNhbCBUZXN0IFJvb3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQ+qc16/Tw0+Jwm0K4Ubdse6Ucaf+GEqaX2QcM2DkakIJ0DLH+A8W6ZFlDHYH8Dswx3oNhwgkaGBG5XTykdmLVRo2YwZDAfBgNVHSMEGDAWgBQUgvOXtxxuh+mj0/9OVZWO27H+5jASBgNVHRMBAf8ECDAGAQH/AgEBMA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUFILzl7ccbofpo9P/TlWVjtux/uYwCgYIKoZIzj0EAwIDSQAwRgIhAJeaEZvvddOVWj1hCHp6D8UzU/iiHRPzHfKHmYMYfG0XAiEA2gtAnkmepG3hxrb3n03iZZ5pfI6CsZjA3m7XUoWGyto=";
const TEST_X509_SIGNER_KEY_USAGE_LEAF_SIGNING_KEY_PKCS8_DER_B64: &str = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg5UFXQIVYvipD5b/bJIJwUlvT/wtHRLPRQAHR7/Xo3zihRANCAAQaUrTehs+FPEzXTPpCc4QKx4tj2YBjKgg6fB0GCywzaUSpA5xJqgl5n4X7m4kk9IZikRcB8g555pZAlVoEmEE+";
const TEST_X509_SIGNER_KEY_USAGE_CRITICAL_LEAF_CERTIFICATE_DER_B64: &str = "MIIB1zCCAX2gAwIBAgIDAPIyMAoGCCqGSM49BAMCMDUxMzAxBgNVBAMMKklyb2hhIElTTyBYTUxTaWcgU2lnbmVyIEtleVVzYWdlIFRlc3QgUm9vdDAgFw0yNjA2MDExOTI3MDdaGA8yMTI2MDUwODE5MjcwN1owNzE1MDMGA1UEAwwsSXJvaGEgSVNPIFhNTFNpZyBTaWduZXIgS2V5VXNhZ2UgVGVzdCBTaWduZXIwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQaUrTehs+FPEzXTPpCc4QKx4tj2YBjKgg6fB0GCywzaUSpA5xJqgl5n4X7m4kk9IZikRcB8g555pZAlVoEmEE+o3gwdjAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIHgDAWBgNVHSUBAf8EDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQUKgvg9C1cI4oB4tNiE3OvyEDlolMwHwYDVR0jBBgwFoAUnb9uvIuaroSGC6Jzlv3lWiREJIcwCgYIKoZIzj0EAwIDSAAwRQIhAKNuC/zhQzy8NDIKmTCakHj65AvJ627JJCHKGUkc1cYDAiBzkgMAhhSadW5bgEgST7YirOGaizOeiYIo4nCQVw5BjA==";
const TEST_X509_SIGNER_KEY_USAGE_NONCRITICAL_LEAF_CERTIFICATE_DER_B64: &str = "MIIB1TCCAXqgAwIBAgIDAPIzMAoGCCqGSM49BAMCMDUxMzAxBgNVBAMMKklyb2hhIElTTyBYTUxTaWcgU2lnbmVyIEtleVVzYWdlIFRlc3QgUm9vdDAgFw0yNjA2MDExOTI3MDdaGA8yMTI2MDUwODE5MjcwN1owNzE1MDMGA1UEAwwsSXJvaGEgSVNPIFhNTFNpZyBTaWduZXIgS2V5VXNhZ2UgVGVzdCBTaWduZXIwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQaUrTehs+FPEzXTPpCc4QKx4tj2YBjKgg6fB0GCywzaUSpA5xJqgl5n4X7m4kk9IZikRcB8g555pZAlVoEmEE+o3UwczAMBgNVHRMBAf8EAjAAMAsGA1UdDwQEAwIHgDAWBgNVHSUBAf8EDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQUKgvg9C1cI4oB4tNiE3OvyEDlolMwHwYDVR0jBBgwFoAUnb9uvIuaroSGC6Jzlv3lWiREJIcwCgYIKoZIzj0EAwIDSQAwRgIhAJYUdJGsThOe7M0v5IdaJoP62D8HiOxXIjKWDuo1UzHdAiEA1as/FoNbk6nBOy52nSluR91TzEn9Nbyf+2hVGbqUVug=";
const TEST_X509_SIGNER_KEY_USAGE_ROOT_CERTIFICATE_DER_B64: &str = "MIIBwzCCAWmgAwIBAgIDAPIxMAoGCCqGSM49BAMCMDUxMzAxBgNVBAMMKklyb2hhIElTTyBYTUxTaWcgU2lnbmVyIEtleVVzYWdlIFRlc3QgUm9vdDAgFw0yNjA2MDExOTI3MDdaGA8yMTI2MDUwODE5MjcwN1owNTEzMDEGA1UEAwwqSXJvaGEgSVNPIFhNTFNpZyBTaWduZXIgS2V5VXNhZ2UgVGVzdCBSb290MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAELYvhBCgswQnmjIP212n/Sg8aaHIc88jWhsxFBCUYk25HvvTQ3w0PbF48hwDedzXYNthUQKTwOKYR1D9o+IzvWaNmMGQwHwYDVR0jBBgwFoAUnb9uvIuaroSGC6Jzlv3lWiREJIcwEgYDVR0TAQH/BAgwBgEB/wIBATAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFJ2/bryLmq6Ehguic5b95VokRCSHMAoGCCqGSM49BAMCA0gAMEUCIBQMQk64nXDmfx+cc9ch4DdqTg9ePtJxe1zgCW3hx7GfAiEAihlUpuQvkUteb0Pc6DRT7lynuKOCSj+ugEZH22mK49k=";
const TEST_X509_POLICY_OID: &str = "1.3.6.1.4.1.55555.1.1";
const TEST_X509_POLICY_OID_ARCS: &[u64] = &[1, 3, 6, 1, 4, 1, 55555, 1, 1];
const TEST_X509_WRONG_POLICY_OID_ARCS: &[u64] = &[1, 3, 6, 1, 4, 1, 55555, 1, 2];
const X509_ANY_POLICY_OID_ARCS: &[u64] = &[2, 5, 29, 32, 0];
const TEST_X509_POLICY_LEAF_SIGNING_KEY_PKCS8_DER_B64: &str = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgQf3eEFqA7jglOKGQ5WsPZaDme/HcKmlcWRlmlqR4bHGhRANCAASVooKXzWhB5zksBPxZWOT58wiH+r0Ibqwf2Ru5Rh7zw4nw8H7/j2vY8zbRJ3E3r/Rh3pOdK3z1Qw/w0bT3gB5A";
const TEST_X509_POLICY_LEAF_CERTIFICATE_DER_B64: &str = "MIIBxzCCAW2gAwIBAgIUPuFsDaDMpHF3NgeTGnIEhCOq3NEwCgYIKoZIzj0EAwIwJTEjMCEGA1UEAwwaSXJvaGEgSVNPIFBvbGljeSBUZXN0IFJvb3QwIBcNMjYwNjAxMTIxNzAwWhgPMjEyNjA1MDgxMjE3MDBaMCUxIzAhBgNVBAMMGklyb2hhIElTTyBQb2xpY3kgVGVzdCBMZWFmMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAElaKCl81oQec5LAT8WVjk+fMIh/q9CG6sH9kbuUYe88OJ8PB+/49r2PM20SdxN6/0Yd6TnSt89UMP8NG094AeQKN5MHcwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0OBBYEFER1X6dAjJEwRyZR0U9snoEqP1m3MB8GA1UdIwQYMBaAFDdfynzPJ3kOExwR74uNUYowe1IRMBcGA1UdIAQQMA4wDAYKKwYBBAGDsgMBATAKBggqhkjOPQQDAgNIADBFAiA6Q8LV3dY5W+t3TkfF4CG5cSPnp0Ck1Y8syE121dXjbgIhAP0h9a2FZzfQP04iu/e8T8iE/VK1EJ+cUQJaGs09Wa9R";
const TEST_X509_POLICY_ROOT_CERTIFICATE_DER_B64: &str = "MIIBszCCAVqgAwIBAgIUL5B/imcHZ4KDLP8LZnFRqYSmTqEwCgYIKoZIzj0EAwIwJTEjMCEGA1UEAwwaSXJvaGEgSVNPIFBvbGljeSBUZXN0IFJvb3QwIBcNMjYwNjAxMTIxNzAwWhgPMjEyNjA1MDgxMjE3MDBaMCUxIzAhBgNVBAMMGklyb2hhIElTTyBQb2xpY3kgVGVzdCBSb290MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEbpV/eWHEwxV+no2+2M6BIGiPho0U+Ky+iUZ/J/4KXdEk0y81+/MC72LiD0rbSxLL+nxRE9VwhzILejQG8KVg8qNmMGQwHwYDVR0jBBgwFoAUN1/KfM8neQ4THBHvi41RijB7UhEwEgYDVR0TAQH/BAgwBgEB/wIBATAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFDdfynzPJ3kOExwR74uNUYowe1IRMAoGCCqGSM49BAMCA0cAMEQCIFDwLtr3jD6nngIPGkIb5a5VU3vI8CEp1TLTFkZDEi1EAiANb9nOlWWaTbgaVU6efVlbrwNmMVgH3aVRcGszRdg4BA==";
const TEST_X509_CRL_LEAF_SIGNING_KEY_PKCS8_DER_B64: &str = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgB7VSSxZw4i1maCz0tjs+Ig0seslvt33h+wfolIqxj1WhRANCAAS9vJu7tpKTX3O6vPLlaZNh+xMjHSJKNGmIXYYATkVrcb5E/S0TEDC7t2ZEm1erCRqjbOnoF9n2u6UmlaZCRoJ0";
const TEST_X509_CRL_LEAF_CERTIFICATE_DER_B64: &str = "MIIBljCCATygAwIBAgICEAAwCgYIKoZIzj0EAwIwIjEgMB4GA1UEAwwXSXJvaGEgSVNPIENSTCBUZXN0IFJvb3QwIBcNMjYwNjAxMDAwMDAwWhgPMjEyNjA1MDgwMDAwMDBaMCIxIDAeBgNVBAMMF0lyb2hhIElTTyBDUkwgVGVzdCBMZWFmMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEvbybu7aSk19zurzy5WmTYfsTIx0iSjRpiF2GAE5Fa3G+RP0tExAwu7dmRJtXqwkao2zp6BfZ9rulJpWmQkaCdKNgMF4wDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0OBBYEFA3XcZGfO52bKHnCO+4ym+iUaRQeMB8GA1UdIwQYMBaAFAfSITIYh7s/HFXEuWgTWUbY7FPYMAoGCCqGSM49BAMCA0gAMEUCIQDWg/T42cqMyz1Tv0BnJ3RIX7FXTMwm6qQD6wdMrSaqBQIgXb5ibnHAYMbe+lEwXDLY8sc9r2LlkWIC+hDuyzXB6cU=";
const TEST_X509_CRL_ROOT_CERTIFICATE_DER_B64: &str = "MIIBrzCCAVSgAwIBAgIUJE41eX9WgYGLzBP/qB9/8FA/CxEwCgYIKoZIzj0EAwIwIjEgMB4GA1UEAwwXSXJvaGEgSVNPIENSTCBUZXN0IFJvb3QwIBcNMjYwNjAxMTMxNjU4WhgPMjEyNjA1MDgxMzE2NThaMCIxIDAeBgNVBAMMF0lyb2hhIElTTyBDUkwgVGVzdCBSb290MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEtgOtGpXNN/v42vMmR8TYH2rdZi+q/medyz6OmLvSsI68PD1170XuJV1C9qPC3rdWztfYo2RuBndGfLc0IoCfzqNmMGQwEgYDVR0TAQH/BAgwBgEB/wIBATAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFAfSITIYh7s/HFXEuWgTWUbY7FPYMB8GA1UdIwQYMBaAFAfSITIYh7s/HFXEuWgTWUbY7FPYMAoGCCqGSM49BAMCA0kAMEYCIQC6Yim3bERFkQSXw2dO06K31ojFQw5Jf+SomCPXQjcu4QIhAIW+jPETlQXYt8lDbOC6nb/0m3gSbm8R3vn3bZTqX9Ir";
const TEST_X509_CRL_EMPTY_DER_B64: &str = "MIHdMIGFAgEBMAoGCCqGSM49BAMCMCIxIDAeBgNVBAMMF0lyb2hhIElTTyBDUkwgVGVzdCBSb290Fw0yNjA2MDEwMDAwMDBaGA8yMTI2MDUwODAwMDAwMFqgMDAuMB8GA1UdIwQYMBaAFAfSITIYh7s/HFXEuWgTWUbY7FPYMAsGA1UdFAQEAgIQADAKBggqhkjOPQQDAgNHADBEAiA/m/8+c7k15xNLpd2sfai08GTXDRVzbGJiRGvBeRxACQIgBOyF2PNzol2If3Vg4UgVkf/5COVXoDvkLlUelTaj62Y=";
const TEST_X509_CRL_REVOKED_DER_B64: &str = "MIIBBDCBqgIBATAKBggqhkjOPQQDAjAiMSAwHgYDVQQDDBdJcm9oYSBJU08gQ1JMIFRlc3QgUm9vdBcNMjYwNjAxMDAwMDAwWhgPMjEyNjA1MDgwMDAwMDBaMCMwIQICEAAXDTI2MDYwMTEzMTY1OFowDDAKBgNVHRUEAwoBAaAwMC4wHwYDVR0jBBgwFoAUB9IhMhiHuz8cVcS5aBNZRtjsU9gwCwYDVR0UBAQCAhACMAoGCCqGSM49BAMCA0kAMEYCIQC7LiVi/w7PlmRroPXn4kBMQ2Ep7nTFJ6t35H8wb2abGAIhAOKFvALdoshlevpu4FPYtj/uTdDolRjW/J8ZknJhQEcg";
const TEST_X509_CRL_EXPIRED_DER_B64: &str = "MIHbMIGDAgEBMAoGCCqGSM49BAMCMCIxIDAeBgNVBAMMF0lyb2hhIElTTyBDUkwgVGVzdCBSb290Fw0yMDAxMDEwMDAwMDBaFw0yMDAxMDIwMDAwMDBaoDAwLjAfBgNVHSMEGDAWgBQH0iEyGIe7PxxVxLloE1lG2OxT2DALBgNVHRQEBAICEAEwCgYIKoZIzj0EAwIDRwAwRAIgOgcF6ZCKDyVWfidxODibs3k6iUMctmh2OEGdUPZ0B6ECIEqgqdL/2jFlr6Z9em1M8QMxr03lpE9UdO+viTFWf/3Z";
const TEST_X509_CRL_OTHER_ISSUER_DER_B64: &str = "MIHgMIGGAgEBMAoGCCqGSM49BAMCMCMxITAfBgNVBAMMGElyb2hhIElTTyBDUkwgT3RoZXIgUm9vdBcNMjYwNjAxMDAwMDAwWhgPMjEyNjA1MDgwMDAwMDBaoDAwLjAfBgNVHSMEGDAWgBTl4dhk5NXuYpKTUaMkMpK/Z4BA2TALBgNVHRQEBAICIAAwCgYIKoZIzj0EAwIDSQAwRgIhAMTqzMxhaAlCO/l+dcrm+UCIQ1JiPqoOBugTIVaCM/pRAiEA8evRaUSJ6ixL+lyNSDt/4dnii8NZOKFTzDe8hYxDQBM=";
const TEST_X509_OCSP_LEAF_SIGNING_KEY_PKCS8_DER_B64: &str = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgOzTGZkOgS1T9pB1fWVC+0w+Prc/yFCID0klpj9gC5wyhRANCAAShay14G5YTdNi3gcQ1HU57Tqq/djk9NjZUUB188pQKBl28Re1rPtOGcqnp/cQ/fXJ4wCZL+VZIZLBXPnWI+ycM";
const TEST_X509_OCSP_LEAF_CERTIFICATE_DER_B64: &str = "MIIB3zCCAYWgAwIBAgIUVzuYJYNzXMyTPXW0KohPO/1jeMAwCgYIKoZIzj0EAwIwIzEhMB8GA1UEAwwYSXJvaGEgSVNPIE9DU1AgVGVzdCBSb290MCAXDTI2MDYwMTE0MTYwNloYDzIxMjYwNTA4MTQxNjA2WjAjMSEwHwYDVQQDDBhJcm9oYSBJU08gT0NTUCBUZXN0IExlYWYwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAShay14G5YTdNi3gcQ1HU57Tqq/djk9NjZUUB188pQKBl28Re1rPtOGcqnp/cQ/fXJ4wCZL+VZIZLBXPnWI+ycMo4GUMIGRMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeAMB0GA1UdDgQWBBRP6VxpI7GgZ0OiFNO9GbKev40fszAfBgNVHSMEGDAWgBTGJreH2IBwn1DyPNeDcsR5YP9ifTAxBggrBgEFBQcBAQQlMCMwIQYIKwYBBQUHMAGGFWh0dHA6Ly9vY3NwLmJhbmsudGVzdDAKBggqhkjOPQQDAgNIADBFAiAWRjZFwlw986e0nBGrWO646+QR1+kYlnWG4pJLXC5i7QIhAJ52kUkChDHZgwU8+y9YQ+8nn3qHbFn7elYJ0FlC9dyD";
const TEST_X509_OCSP_ROOT_CERTIFICATE_DER_B64: &str = "MIIBsDCCAVagAwIBAgIUAJAyggtpTfF3RPeQ3TydTPhQeiMwCgYIKoZIzj0EAwIwIzEhMB8GA1UEAwwYSXJvaGEgSVNPIE9DU1AgVGVzdCBSb290MCAXDTI2MDYwMTE0MTYwNloYDzIxMjYwNTA4MTQxNjA2WjAjMSEwHwYDVQQDDBhJcm9oYSBJU08gT0NTUCBUZXN0IFJvb3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASGfoQ2ey3oZKXuPvsT+e+lrzJHfvlYp5zyTd1Nvdwd0TzLIziFEdnVB22ADa6GobI1NvlbGp9q51qezbMImvx6o2YwZDASBgNVHRMBAf8ECDAGAQH/AgEBMA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQUxia3h9iAcJ9Q8jzXg3LEeWD/Yn0wHwYDVR0jBBgwFoAUxia3h9iAcJ9Q8jzXg3LEeWD/Yn0wCgYIKoZIzj0EAwIDSAAwRQIhAP0oYY1kvA31qfhBVo97pTyV3nRW+UKK/pLOg79IvOYJAiAYlhB9BkARGqNxO60RfPOCwd3Z5YLMMUY/qIhu/VK1Aw==";
const TEST_X509_OCSP_GOOD_RESPONSE_DER_B64: &str = "MIIBbAoBAKCCAWUwggFhBgkrBgEFBQcwAQEEggFSMIIBTjCB9KElMCMxITAfBgNVBAMMGElyb2hhIElTTyBPQ1NQIFRlc3QgUm9vdBgPMjAyNjA2MDExNDE2MDZaMIGUMIGRMGkwDQYJYIZIAWUDBAIBBQAEIOKw7yAGJupJX6XKZEMFbrvYLi40IxU/Id/RvO6sDO5aBCAqmLjm6DUnDfjI4vbf7mfWINfEFWta/zrWYVHyyQn4jQIUVzuYJYNzXMyTPXW0KohPO/1jeMCAABgPMjAyNjA2MDExNDE2MDZaoBEYDzIxMjYwNTA4MTQxNjA2WqEjMCEwHwYJKwYBBQUHMAECBBIEECHLWkORHnikxmVlHHc7YawwCgYIKoZIzj0EAwIDSQAwRgIhAKzvPh2bC3v/udrO0riVUkmc0OLpbJpl/UYdWY1wOeSyAiEAyj2Zl7T15Y5wZsUSIcBoGPCCVhJDol1a2YIbSF5d2HI=";
const TEST_X509_OCSP_REVOKED_RESPONSE_DER_B64: &str = "MIIBfAoBAKCCAXUwggFxBgkrBgEFBQcwAQEEggFiMIIBXjCCAQWhJTAjMSEwHwYDVQQDDBhJcm9oYSBJU08gT0NTUCBUZXN0IFJvb3QYDzIwMjYwNjAxMTQxNjA2WjCBpTCBojBpMA0GCWCGSAFlAwQCAQUABCDisO8gBibqSV+lymRDBW672C4uNCMVPyHf0bzurAzuWgQgKpi45ug1Jw34yOL23+5n1iDXxBVrWv861mFR8skJ+I0CFFc7mCWDc1zMkz11tCqITzv9Y3jAoREYDzIwMjYwNjAxMDAwMDAwWhgPMjAyNjA2MDExNDE2MDZaoBEYDzIxMjYwNTA4MTQxNjA2WqEjMCEwHwYJKwYBBQUHMAECBBIEECHLWkORHnikxmVlHHc7YawwCgYIKoZIzj0EAwIDRwAwRAIgSyzZpk3IKV0xaXhD738PO3pV3sBVQPT23d7q2Pseb6gCIDoSy7PNbPsEuptSWFozu2/mU2BQF/R+YtOowEYZ/b1A";
const TEST_X509_OCSP_DELEGATED_GOOD_RESPONSE_DER_B64: &str = "MIIDUwoBAKCCA0wwggNIBgkrBgEFBQcwAQEEggM5MIIDNTCB/qEvMC0xKzApBgNVBAMMIklyb2hhIElTTyBPQ1NQIERlbGVnYXRlZCBSZXNwb25kZXIYDzIwMjYwNjAxMTQzNjI3WjCBlDCBkTBpMA0GCWCGSAFlAwQCAQUABCCdvQl6x4ExlidXQVvJaOO18NCxQamAPKLpdT3RYW2aZwQgOR36gtHUOgMjPcOprp5f1+pmvdtIaCE5GBV0FmFzSU8CFC7Dci4NhmbybLsbtGeBNfq44P8FgAAYDzIwMjYwNjAxMTQzNjI3WqARGA8yMTI2MDUwODE0MzYyN1qhIzAhMB8GCSsGAQUFBzABAgQSBBC7tDgAD3HvEmvGnxZumAhBMAoGCCqGSM49BAMCA0gAMEUCIFUNO3cufftkA53FMOw9jL55Pn9DYhk2sY/3ZqHxByVwAiEA7ppZRWYFtpqWGsd26/alBWQrvJNNXhIiL2TDb+Z5C7CgggHaMIIB1jCCAdIwggF3oAMCAQICFC7Dci4NhmbybLsbtGeBNfq44P8GMAoGCCqGSM49BAMCMCgxJjAkBgNVBAMMHUlyb2hhIElTTyBPQ1NQIERlbGVnYXRlZCBSb290MCAXDTI2MDYwMTE0MzYyN1oYDzIxMjYwNTA4MTQzNjI3WjAtMSswKQYDVQQDDCJJcm9oYSBJU08gT0NTUCBEZWxlZ2F0ZWQgUmVzcG9uZGVyMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEGTD2ooQHAbEE/MDCFGMkyP49kdn13dUG9OqfuQJT5WGUaElh+XRiebSgzrsJT4UZJ5CROd4RjJ5L35cspDr5KqN4MHYwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwkwHQYDVR0OBBYEFCV3N7muRz5ulCe3ltUOfKcWwsRDMB8GA1UdIwQYMBaAFETROUIW9SV+wTWLmyaMBQCdIe5eMAoGCCqGSM49BAMCA0kAMEYCIQCzL+5oyJ5K2V2JvwqqOzT0OLFM5bpcfQzcE+4IMb+DZwIhAMmwczkcst9vLrwTjqZFAoNu0+GSnwnRWwpGJRSENSFq";
const TEST_X509_OCSP_DELEGATED_GOOD_NO_CERTS_RESPONSE_DER_B64: &str = "MIIBdQoBAKCCAW4wggFqBgkrBgEFBQcwAQEEggFbMIIBVzCB/qEvMC0xKzApBgNVBAMMIklyb2hhIElTTyBPQ1NQIERlbGVnYXRlZCBSZXNwb25kZXIYDzIwMjYwNjAxMTQzNjI3WjCBlDCBkTBpMA0GCWCGSAFlAwQCAQUABCCdvQl6x4ExlidXQVvJaOO18NCxQamAPKLpdT3RYW2aZwQgOR36gtHUOgMjPcOprp5f1+pmvdtIaCE5GBV0FmFzSU8CFC7Dci4NhmbybLsbtGeBNfq44P8FgAAYDzIwMjYwNjAxMTQzNjI3WqARGA8yMTI2MDUwODE0MzYyN1qhIzAhMB8GCSsGAQUFBzABAgQSBBC7tDgAD3HvEmvGnxZumAhBMAoGCCqGSM49BAMCA0gAMEUCIC3xUMoiVdy4ENrVP6PHecQfp4PsrBxPercEvmEcpV0rAiEAjIe5JEkGyBNjY+VhKHCAdPvnKeLGbt6KKnLNJ3wChuQ=";
fn assert_outbox_error_contains(err: crate::Error, expected: &str) {
    match err {
        crate::Error::Query(ValidationFail::QueryFailed(
            iroha_data_model::query::error::QueryExecutionFail::Conversion(message),
        )) => assert!(
            message.contains(expected),
            "expected `{message}` to contain `{expected}`"
        ),
        other => panic!("unexpected error: {other:?}"),
    }
}
fn fixture_key_pair(seed: u8) -> KeyPair {
    KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
        .expect("fixture seed must derive a valid keypair")
}
#[test]
fn fixture_key_pair_uses_checked_seed_derivation() {
    assert!(fixture_key_pair(0xAA).public_key() != fixture_key_pair(0xAB).public_key());
    assert!(
        KeyPair::try_from_seed(vec![0; 32], Algorithm::Ed25519).is_err(),
        "checked Ed25519 seed derivation must reject weak all-zero fixture seeds"
    );
}
fn sample_account_bundle() -> (AccountId, String, iroha_crypto::PrivateKey) {
    let key_pair = fixture_key_pair(0xAA);
    let (public_key, private_key) = key_pair.into_parts();
    let account = AccountId::new(public_key);
    let literal = account.to_string();
    (account, literal, private_key)
}
fn sample_asset_definition_literal() -> String {
    AssetDefinitionId::derive_from_components(
        DomainId::try_new("test", "universal").expect("domain"),
        "usd".parse().expect("name"),
    )
    .to_string()
}
fn sample_config() -> actual::IsoBridge {
    let (_account_id, account_literal, private_key) = sample_account_bundle();
    let asset_definition = sample_asset_definition_literal();
    let originator_operator = fixture_key_pair(0xAB).public_key().clone();
    let counterparty_operator = fixture_key_pair(0xAC).public_key().clone();
    actual::IsoBridge {
        enabled: true,
        max_body_bytes: iroha_config::parameters::defaults::torii::ISO_BRIDGE_MAX_BODY_BYTES,
        dedupe_ttl_secs: 60,
        default_profile: "generic-iso20022".to_owned(),
        profiles: Vec::new(),
        store_dir: None,
        store_retention_secs:
            iroha_config::parameters::defaults::torii::ISO_BRIDGE_STORE_RETENTION_SECS,
        store_max_records: iroha_config::parameters::defaults::torii::ISO_BRIDGE_STORE_MAX_RECORDS,
        audit_export_dir: None,
        embedded_signature_policy: None,
        signer: Some(actual::IsoBridgeSigner {
            account_id: account_literal.clone(),
            private_key,
        }),
        participants: vec![
            actual::IsoBridgeParticipant {
                id: "originator-bank".to_owned(),
                operator_keys: vec![originator_operator],
                financial_identifiers: vec!["DEUTDEFF".to_owned()],
                allowed_profiles: vec!["generic-iso20022".to_owned()],
                roles: vec!["originator".to_owned(), "counterparty".to_owned()],
            },
            actual::IsoBridgeParticipant {
                id: "counterparty-bank".to_owned(),
                operator_keys: vec![counterparty_operator],
                financial_identifiers: vec!["MARKDEFF".to_owned()],
                allowed_profiles: vec!["generic-iso20022".to_owned()],
                roles: vec!["originator".to_owned(), "counterparty".to_owned()],
            },
        ],
        audit_admin_keys: Vec::new(),
        account_aliases: vec![actual::IsoAccountAlias {
            iban: "GB82 WEST 1234 5698 7654 32".to_string(),
            account_id: account_literal,
        }],
        currency_assets: vec![actual::IsoCurrencyAsset {
            currency: "USD".to_string(),
            asset_definition,
            max_amount: Quantity::from(10_000_u64),
        }],
        reference_data: actual::IsoReferenceData::default(),
    }
}
fn sample_pacs008() -> ParsedMessage {
    parse_message(
            "pacs.008",
            b"MsgId=m-profile\nIntrBkSttlmAmt=10.00\nIntrBkSttlmCcy=USD\nIntrBkSttlmDt=2024-01-01\nDbtrAcct=GB82WEST12345698765432\nCdtrAcct=GB82WEST12345698765432\nDbtrAgt=DEUTDEFF\nCdtrAgt=DEUTDEFF",
        )
        .expect("parsed")
}
fn live_message_profile(message_type: &str, version: &str) -> actual::IsoBridgeProfile {
    actual::IsoBridgeProfile {
        id: format!("{message_type}-live-test"),
        rail: "generic-iso20022".to_owned(),
        embedded_signature_policy: None,
        signature_public_key_sha256_pins: Vec::new(),
        x509_trust_anchor_sha256_pins: Vec::new(),
        x509_required_certificate_policy_oids: Vec::new(),
        x509_require_crl_revocation_check: false,
        x509_crl_der_base64: Vec::new(),
        x509_require_ocsp_revocation_check: false,
        x509_ocsp_response_der_base64: Vec::new(),
        revoked_certificate_sha256: Vec::new(),
        required_reference_datasets: Vec::new(),
        message_profiles: vec![actual::IsoMessageProfile {
            message_type: message_type.to_owned(),
            direction: "inbound".to_owned(),
            versions: vec![version.to_owned()],
            business_services: vec!["swift.cbprplus.02".to_owned()],
            require_app_header: true,
            require_business_service: true,
            require_uetr: false,
            structured_address_mode: "permissive".to_owned(),
            supplementary_data_max_bytes: 4096,
            amount_minor_units: Vec::new(),
        }],
    }
}
fn live_securities_lifecycle_profile() -> actual::IsoBridgeProfile {
    let message_profile = |message_type: &str, version: &str| actual::IsoMessageProfile {
        message_type: message_type.to_owned(),
        direction: "inbound".to_owned(),
        versions: vec![version.to_owned()],
        business_services: vec!["securities.csd.cash".to_owned()],
        require_app_header: true,
        require_business_service: true,
        require_uetr: false,
        structured_address_mode: "permissive".to_owned(),
        supplementary_data_max_bytes: 4096,
        amount_minor_units: Vec::new(),
    };
    actual::IsoBridgeProfile {
        id: "securities-csd-lifecycle-fixtures".to_owned(),
        rail: "securities-csd".to_owned(),
        embedded_signature_policy: None,
        signature_public_key_sha256_pins: Vec::new(),
        x509_trust_anchor_sha256_pins: Vec::new(),
        x509_required_certificate_policy_oids: Vec::new(),
        x509_require_crl_revocation_check: false,
        x509_crl_der_base64: Vec::new(),
        x509_require_ocsp_revocation_check: false,
        x509_ocsp_response_der_base64: Vec::new(),
        revoked_certificate_sha256: Vec::new(),
        required_reference_datasets: vec![
            "bic-lei".to_owned(),
            "isin-cusip".to_owned(),
            "mic-directory".to_owned(),
        ],
        message_profiles: vec![
            message_profile("sese.023", "sese.023.001.11"),
            message_profile("sese.024", "sese.024.001.10"),
            message_profile("sese.025", "sese.025.001.11"),
        ],
    }
}
fn live_collateral_lifecycle_profile() -> actual::IsoBridgeProfile {
    actual::IsoBridgeProfile {
        id: "collateral-lifecycle-fixtures".to_owned(),
        rail: "generic-iso20022".to_owned(),
        embedded_signature_policy: None,
        signature_public_key_sha256_pins: Vec::new(),
        x509_trust_anchor_sha256_pins: Vec::new(),
        x509_required_certificate_policy_oids: Vec::new(),
        x509_require_crl_revocation_check: false,
        x509_crl_der_base64: Vec::new(),
        x509_require_ocsp_revocation_check: false,
        x509_ocsp_response_der_base64: Vec::new(),
        revoked_certificate_sha256: Vec::new(),
        required_reference_datasets: Vec::new(),
        message_profiles: vec![actual::IsoMessageProfile {
            message_type: "colr.012".to_owned(),
            direction: "inbound".to_owned(),
            versions: vec!["colr.012".to_owned(), "colr.012.001.05".to_owned()],
            business_services: Vec::new(),
            require_app_header: false,
            require_business_service: false,
            require_uetr: false,
            structured_address_mode: "permissive".to_owned(),
            supplementary_data_max_bytes: 4096,
            amount_minor_units: Vec::new(),
        }],
    }
}
fn signed_message_profile(policy: &str) -> actual::IsoBridgeProfile {
    actual::IsoBridgeProfile {
        id: "signed-pacs008-test".to_owned(),
        rail: "generic-iso20022".to_owned(),
        embedded_signature_policy: Some(policy.to_owned()),
        signature_public_key_sha256_pins: vec![test_p256_public_key_pin()],
        x509_trust_anchor_sha256_pins: Vec::new(),
        x509_required_certificate_policy_oids: Vec::new(),
        x509_require_crl_revocation_check: false,
        x509_crl_der_base64: Vec::new(),
        x509_require_ocsp_revocation_check: false,
        x509_ocsp_response_der_base64: Vec::new(),
        revoked_certificate_sha256: Vec::new(),
        required_reference_datasets: Vec::new(),
        message_profiles: vec![actual::IsoMessageProfile {
            message_type: "pacs.008".to_owned(),
            direction: "inbound".to_owned(),
            versions: vec!["pacs.008".to_owned(), "pacs.008.001.08".to_owned()],
            business_services: Vec::new(),
            require_app_header: false,
            require_business_service: false,
            require_uetr: false,
            structured_address_mode: "permissive".to_owned(),
            supplementary_data_max_bytes: 4096,
            amount_minor_units: Vec::new(),
        }],
    }
}
fn xml_signature_test_signing_key() -> P256SigningKey {
    P256SigningKey::from_bytes(&[0x31; 32].into()).expect("deterministic P-256 key")
}
fn low_s_p256_signature(signature: P256Signature) -> P256Signature {
    signature.normalize_s().unwrap_or(signature)
}
fn low_s_p256_signature_der_from_bytes(signature: &[u8]) -> Vec<u8> {
    let signature = if signature.len() == P256_XMLDSIG_SIGNATURE_LEN {
        P256Signature::from_slice(signature)
    } else {
        P256Signature::from_der(signature)
    }
    .expect("rcgen P-256 signature");
    low_s_p256_signature(signature).to_der().as_bytes().to_vec()
}
fn high_s_p256_signature(signature: P256Signature) -> P256Signature {
    const P256_ORDER: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63,
        0x25, 0x51,
    ];
    let low_s = low_s_p256_signature(signature);
    let low_s_bytes = low_s.to_bytes();
    let mut high_s_bytes = [0_u8; P256_XMLDSIG_SIGNATURE_LEN];
    high_s_bytes[..32].copy_from_slice(&low_s_bytes[..32]);
    let mut borrow = 0_u16;
    for i in (0..32).rev() {
        let minuend = i16::from(P256_ORDER[i]) - i16::from(borrow as u8);
        let subtrahend = i16::from(low_s_bytes[32 + i]);
        if minuend >= subtrahend {
            high_s_bytes[32 + i] = (minuend - subtrahend) as u8;
            borrow = 0;
        } else {
            high_s_bytes[32 + i] = (minuend + 256 - subtrahend) as u8;
            borrow = 1;
        }
    }
    assert_eq!(
        borrow, 0,
        "low-S fixture scalar must be below the curve order"
    );
    let high_s = P256Signature::from_slice(&high_s_bytes).expect("high-S signature");
    assert!(
        high_s.normalize_s().is_some(),
        "test helper must produce a non-canonical high-S signature"
    );
    high_s
}
fn unsigned_pacs008_xml() -> String {
    unsigned_pacs008_xml_with_message_id("sig-001")
}
fn unsigned_pacs008_xml_with_message_id(message_id: &str) -> String {
    format!(
        concat!(
            r#"<Document xmlns="urn:iso:std:iso:20022:tech:xsd:pacs.008.001.08">"#,
            "<FIToFICstmrCdtTrf><GrpHdr><MsgId>{}</MsgId></GrpHdr>",
            r#"<CdtTrfTxInf><IntrBkSttlmAmt Ccy="USD">10.00</IntrBkSttlmAmt>"#,
            "<IntrBkSttlmDt>2024-01-01</IntrBkSttlmDt>",
            "<DbtrAcct><Id><IBAN>GB82WEST12345698765432</IBAN></Id></DbtrAcct>",
            "<CdtrAcct><Id><IBAN>GB82WEST12345698765432</IBAN></Id></CdtrAcct>",
            "<DbtrAgt><FinInstnId><BICFI>DEUTDEFF</BICFI></FinInstnId></DbtrAgt>",
            "<CdtrAgt><FinInstnId><BICFI>DEUTDEFF</BICFI></FinInstnId></CdtrAgt>",
            "</CdtTrfTxInf></FIToFICstmrCdtTrf></Document>",
        ),
        message_id
    )
}
fn unsigned_pacs008_xml_with_document_id(reference_id: &str) -> String {
    unsigned_pacs008_xml().replacen(
        "<Document ",
        &format!(r#"<Document Id="{reference_id}" "#),
        1,
    )
}
fn unsigned_pacs008_xml_with_inherited_default_namespace_reference_id(
    reference_id: &str,
) -> String {
    unsigned_pacs008_xml().replacen(
        "<FIToFICstmrCdtTrf>",
        &format!(r#"<FIToFICstmrCdtTrf Id="{reference_id}">"#),
        1,
    )
}
fn unsigned_pacs008_xml_with_inherited_unused_namespace_reference_id(reference_id: &str) -> String {
    unsigned_pacs008_xml_with_inherited_default_namespace_reference_id(reference_id).replacen(
        r#"<Document xmlns=""#,
        r#"<Document xmlns:unused="urn:unused" xmlns=""#,
        1,
    )
}
fn test_p256_signing_key() -> P256SigningKey {
    P256SigningKey::from_bytes(&[0x31; 32].into()).expect("deterministic P-256 key")
}
fn signed_pacs008_xml() -> String {
    signed_pacs008_xml_with_c14n_algorithm(XML_C14N_1_0)
}
fn test_p256_public_key_pin() -> String {
    let public_key = test_p256_signing_key()
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    sha256_hex(&public_key)
}
macro_rules! p256_signing_key_fixtures {
        ($($name:ident => ($encoded:ident, $label:literal);)+) => {
            $(
                fn $name() -> P256SigningKey {
                    let pkcs8 = BASE64_STANDARD
                        .decode($encoded)
                        .expect(concat!($label, " PKCS#8 fixture must decode"));
                    P256SigningKey::from_pkcs8_der(&pkcs8)
                        .expect(concat!($label, " PKCS#8 fixture must parse"))
                }
            )+
        };
    }
macro_rules! x509_certificate_pin_fixtures {
        ($($name:ident => ($encoded:ident, $label:literal);)+) => {
            $(
                fn $name() -> String {
                    let certificate = BASE64_STANDARD
                        .decode($encoded)
                        .expect(concat!($label, " X.509 fixture must decode"));
                    sha256_hex(&certificate)
                }
            )+
        };
    }
macro_rules! x509_public_key_pin_fixtures {
        ($($name:ident => ($encoded:ident, $decode:literal, $parse:literal);)+) => {
            $(
                fn $name() -> String {
                    let certificate = BASE64_STANDARD.decode($encoded).expect($decode);
                    let (_, certificate) =
                        X509Certificate::from_der(&certificate).expect($parse);
                    let public_key = certificate.public_key().subject_public_key.data.to_vec();
                    sha256_hex(&public_key)
                }
            )+
        };
    }
p256_signing_key_fixtures! {
    test_x509_chain_leaf_signing_key => (TEST_X509_CHAIN_LEAF_SIGNING_KEY_PKCS8_DER_B64, "chain leaf");
    test_x509_unknown_critical_leaf_signing_key => (TEST_X509_UNKNOWN_CRITICAL_LEAF_SIGNING_KEY_PKCS8_DER_B64, "unknown-critical leaf");
    test_x509_signer_key_usage_leaf_signing_key => (TEST_X509_SIGNER_KEY_USAGE_LEAF_SIGNING_KEY_PKCS8_DER_B64, "signer KeyUsage leaf");
    test_x509_policy_leaf_signing_key => (TEST_X509_POLICY_LEAF_SIGNING_KEY_PKCS8_DER_B64, "policy leaf");
    test_x509_crl_leaf_signing_key => (TEST_X509_CRL_LEAF_SIGNING_KEY_PKCS8_DER_B64, "CRL leaf");
    test_x509_ocsp_leaf_signing_key => (TEST_X509_OCSP_LEAF_SIGNING_KEY_PKCS8_DER_B64, "OCSP leaf");
}
x509_certificate_pin_fixtures! {
    test_x509_chain_root_certificate_pin => (TEST_X509_CHAIN_ROOT_CERTIFICATE_DER_B64, "chain root");
    test_x509_signer_key_usage_root_certificate_pin => (TEST_X509_SIGNER_KEY_USAGE_ROOT_CERTIFICATE_DER_B64, "signer KeyUsage root");
    test_x509_leaf_certificate_pin => (TEST_X509_CHAIN_LEAF_CERTIFICATE_DER_B64, "chain leaf");
    test_x509_policy_root_certificate_pin => (TEST_X509_POLICY_ROOT_CERTIFICATE_DER_B64, "policy root");
    test_x509_crl_root_certificate_pin => (TEST_X509_CRL_ROOT_CERTIFICATE_DER_B64, "CRL root");
    test_x509_ocsp_root_certificate_pin => (TEST_X509_OCSP_ROOT_CERTIFICATE_DER_B64, "OCSP root");
}
x509_public_key_pin_fixtures! {
    test_x509_unknown_critical_leaf_public_key_pin => (TEST_X509_UNKNOWN_CRITICAL_LEAF_CERTIFICATE_DER_B64, "unknown-critical leaf X.509 fixture must decode", "unknown-critical leaf must parse");
    test_x509_signer_key_usage_leaf_public_key_pin => (TEST_X509_SIGNER_KEY_USAGE_CRITICAL_LEAF_CERTIFICATE_DER_B64, "critical signer KeyUsage leaf X.509 fixture must decode", "critical signer KeyUsage leaf X.509 fixture must parse");
}
fn signed_pacs008_xml_with_public_key(public_key_base64: &str) -> String {
    let payload = signed_pacs008_xml();
    let public_key_start =
        payload.find("<PublicKey>").expect("fixture PublicKey") + "<PublicKey>".len();
    let public_key_end = payload[public_key_start..]
        .find("</PublicKey>")
        .expect("fixture PublicKey end")
        + public_key_start;
    format!(
        "{}{}{}",
        &payload[..public_key_start],
        public_key_base64,
        &payload[public_key_end..]
    )
}
fn canonicalize_xmlsig_signed_info(signed_info: &str, mode: CanonicalXmlMode) -> String {
    let inherited_namespaces = [CanonicalXmlAttribute {
        name: "xmlns".to_owned(),
        value: XMLDSIG_NS.to_owned(),
        kind: CanonicalXmlAttributeKind::Namespace,
    }];
    canonicalize_supported_xml_with_mode(signed_info, &inherited_namespaces, mode)
        .expect("canonical XMLDSig SignedInfo")
}
fn default_xmlsig_namespace_bindings() -> [CanonicalXmlNamespaceBinding; 1] {
    [CanonicalXmlNamespaceBinding {
        prefix: String::new(),
        uri: XMLDSIG_NS.to_owned(),
    }]
}
fn signed_pacs008_xml_with_c14n_algorithm(c14n_algorithm: &str) -> String {
    signed_pacs008_xml_with_c14n_algorithm_and_signed_info_style(c14n_algorithm, false)
}
fn signed_pacs008_xml_with_self_closing_signed_info() -> String {
    signed_pacs008_xml_with_c14n_algorithm_and_signed_info_style(XML_C14N_1_0, true)
}
fn signed_pacs008_xml_with_raw_self_closing_signed_info_signature() -> String {
    signed_pacs008_xml_with_c14n_algorithm_and_signed_info_options(XML_C14N_1_0, true, false)
}
fn signed_pacs008_xml_with_fixed_width_signature_value() -> String {
    signed_pacs008_xml_from_unsigned_with_signature_encoding(
        unsigned_pacs008_xml(),
        XML_C14N_1_0,
        false,
        true,
        XmlSignatureValueEncoding::FixedWidth,
    )
}
fn signed_pacs008_xml_with_sgntr_signature_carrier() -> String {
    let unsigned = unsigned_pacs008_xml().replacen(
        "</FIToFICstmrCdtTrf>",
        &format!(r#"<Sgntr xmlns:ds="{XMLDSIG_NS}"></Sgntr></FIToFICstmrCdtTrf>"#),
        1,
    );
    let insertion = unsigned.find("</Sgntr>").expect("Sgntr insertion point");
    let canonical_unsigned = canonicalize_supported_xml(&unsigned).expect("canonical payload");
    let digest = BASE64_STANDARD.encode(Sha256::digest(canonical_unsigned.as_bytes()));
    let signed_info = signed_info_xml_prefixed(XML_C14N_1_0, &digest);
    let inherited_namespaces = [
        CanonicalXmlAttribute {
            name: "xmlns".to_owned(),
            value: TEST_PACS008_NAMESPACE.to_owned(),
            kind: CanonicalXmlAttributeKind::Namespace,
        },
        CanonicalXmlAttribute {
            name: "xmlns:ds".to_owned(),
            value: XMLDSIG_NS.to_owned(),
            kind: CanonicalXmlAttributeKind::Namespace,
        },
    ];
    let canonical_signed_info = canonicalize_supported_xml_with_mode(
        &signed_info,
        &inherited_namespaces,
        CanonicalXmlMode::Inclusive,
    )
    .expect("canonical Sgntr-wrapped SignedInfo");
    let signing_key = xml_signature_test_signing_key();
    let signature = low_s_p256_signature(signing_key.sign(canonical_signed_info.as_bytes()));
    let signature_value = BASE64_STANDARD.encode(signature.to_der().as_bytes());
    let public_key = BASE64_STANDARD.encode(
        signing_key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes(),
    );
    let signature_xml = format!(
        concat!(
            r#"<ds:Signature Id="sig-001">{signed_info}"#,
            "<ds:SignatureValue>{signature_value}</ds:SignatureValue>",
            "<ds:KeyInfo><ds:KeyValue><ds:ECKeyValue>",
            r#"<ds:NamedCurve URI="urn:oid:1.2.840.10045.3.1.7"></ds:NamedCurve>"#,
            "<ds:PublicKey>{public_key}</ds:PublicKey>",
            "</ds:ECKeyValue></ds:KeyValue></ds:KeyInfo>",
            r##"<ds:Object><xades:QualifyingProperties xmlns:xades="http://uri.etsi.org/01903/v1.3.2#" Target="#sig-001"></xades:QualifyingProperties></ds:Object>"##,
            "</ds:Signature>"
        ),
        signed_info = signed_info,
        signature_value = signature_value,
        public_key = public_key
    );
    format!(
        "{}{}{}",
        &unsigned[..insertion],
        signature_xml,
        &unsigned[insertion..]
    )
}
fn signed_pacs008_xml_with_extra_sgntr_carrier() -> String {
    let unsigned = unsigned_pacs008_xml().replacen(
            "</FIToFICstmrCdtTrf>",
            "<Sgntr><SignedInfo><SignatureMethod>ignored</SignatureMethod></SignedInfo><SignatureValue>ignored</SignatureValue></Sgntr></FIToFICstmrCdtTrf>",
            1,
        );
    signed_pacs008_xml_from_unsigned(unsigned, XML_C14N_1_0, false, true)
}
fn signed_pacs008_xml_with_same_document_reference() -> String {
    let reference_id = "doc-001";
    let unsigned = unsigned_pacs008_xml_with_document_id(reference_id);
    signed_pacs008_xml_from_unsigned_with_reference_uri_and_signature_encoding(
        unsigned,
        XML_C14N_1_0,
        &format!("#{reference_id}"),
        false,
        true,
        XmlSignatureValueEncoding::Der,
    )
}
fn signed_pacs008_xml_with_inherited_namespace_same_document_reference() -> String {
    let reference_id = "doc-001";
    let unsigned = unsigned_pacs008_xml_with_inherited_default_namespace_reference_id(reference_id);
    signed_pacs008_xml_from_unsigned_with_reference_uri_and_signature_encoding(
        unsigned,
        XML_C14N_1_0,
        &format!("#{reference_id}"),
        false,
        true,
        XmlSignatureValueEncoding::Der,
    )
}
fn signed_pacs008_xml_with_app_header_outside_same_document_reference() -> String {
    let reference_id = "payment-001";
    let document = unsigned_pacs008_xml_with_inherited_default_namespace_reference_id(reference_id);
    let unsigned = data_pdu_with_app_header(
        "header-outside-reference",
        "pacs.008.001.08",
        "swift.cbprplus.02",
        &document,
    );
    signed_pacs008_xml_from_unsigned_with_reference_uri_and_signature_encoding(
        unsigned,
        XML_C14N_1_0,
        &format!("#{reference_id}"),
        false,
        true,
        XmlSignatureValueEncoding::Der,
    )
}
fn signed_pacs008_xml_with_header_only_same_document_reference() -> String {
    let reference_id = "grp-header-001";
    let unsigned =
        unsigned_pacs008_xml().replacen("<GrpHdr>", &format!(r#"<GrpHdr Id="{reference_id}">"#), 1);
    signed_pacs008_xml_from_unsigned_with_reference_uri_and_signature_encoding(
        unsigned,
        XML_C14N_1_0,
        &format!("#{reference_id}"),
        false,
        true,
        XmlSignatureValueEncoding::Der,
    )
}
fn signed_pacs008_xml_with_reference_c14n_transform() -> String {
    let reference_id = "doc-001";
    let unsigned = unsigned_pacs008_xml_with_inherited_unused_namespace_reference_id(reference_id);
    signed_pacs008_xml_from_unsigned_with_reference_options(
        unsigned,
        XML_C14N_1_0,
        &format!("#{reference_id}"),
        false,
        true,
        XmlSignatureValueEncoding::Der,
        Some(XML_C14N_1_0),
    )
}
fn signed_pacs008_xml_with_extra_reference_transform() -> String {
    let unsigned = unsigned_pacs008_xml();
    let insertion = unsigned
        .find("</FIToFICstmrCdtTrf>")
        .expect("signature insertion point");
    let canonical_unsigned = canonicalize_supported_xml(&unsigned).expect("canonical payload");
    let digest = BASE64_STANDARD.encode(Sha256::digest(canonical_unsigned.as_bytes()));
    let supported_transform =
        format!(r#"<Transform Algorithm="{XMLDSIG_ENVELOPED_SIGNATURE}"></Transform>"#);
    let signed_info = signed_info_xml(XML_C14N_1_0, &digest, false).replace(
        &supported_transform,
        &format!(
            r#"{supported_transform}<Transform Algorithm="urn:unsupported-transform"></Transform>"#
        ),
    );
    let canonical_signed_info =
        canonicalize_xmlsig_signed_info(&signed_info, CanonicalXmlMode::Inclusive);
    let signing_key = xml_signature_test_signing_key();
    let signature = low_s_p256_signature(signing_key.sign(canonical_signed_info.as_bytes()));
    let signature_value = BASE64_STANDARD.encode(signature.to_der().as_bytes());
    let public_key = BASE64_STANDARD.encode(
        signing_key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes(),
    );
    let signature_xml = format!(
        concat!(
            r#"<Signature xmlns="{XMLDSIG_NS}" Id="sig-001">{signed_info}<SignatureValue>{signature_value}</SignatureValue>"#,
            "<KeyInfo><KeyValue><ECKeyValue>",
            r#"<NamedCurve URI="urn:oid:1.2.840.10045.3.1.7"></NamedCurve>"#,
            "<PublicKey>{public_key}</PublicKey>",
            "</ECKeyValue></KeyValue></KeyInfo>",
            r##"<Object><QualifyingProperties xmlns="{XADES_NS}" Target="#sig-001"></QualifyingProperties></Object>"##,
            "</Signature>"
        ),
        signed_info = signed_info,
        signature_value = signature_value,
        public_key = public_key,
        XMLDSIG_NS = XMLDSIG_NS,
        XADES_NS = XADES_NS
    );
    format!(
        "{}{}{}",
        &unsigned[..insertion],
        signature_xml,
        &unsigned[insertion..]
    )
}
fn signed_pacs008_xml_with_x509_material(
    signing_key: &P256SigningKey,
    certificates: &[&str],
    x509_data_extra: &str,
    signing_time: &str,
) -> String {
    let certificates_xml = certificates
        .iter()
        .map(|certificate| format!("<X509Certificate>{certificate}</X509Certificate>"))
        .collect::<String>();
    let key_info =
        format!("<KeyInfo><X509Data>{certificates_xml}{x509_data_extra}</X509Data></KeyInfo>");
    signed_pacs008_xml_with_key_info_at(signing_key, &key_info, signing_time)
}
fn x509_certificates_with_optional_root<'a>(
    leaf: &'a str,
    root: &'a str,
    include_root: bool,
) -> Vec<&'a str> {
    if include_root {
        vec![leaf, root]
    } else {
        vec![leaf]
    }
}
fn signed_pacs008_xml_with_x509_certificate() -> String {
    let signing_key = test_x509_chain_leaf_signing_key();
    signed_pacs008_xml_with_x509_material(
        &signing_key,
        &[TEST_X509_CHAIN_LEAF_CERTIFICATE_DER_B64],
        "",
        XML_SIGNATURE_TEST_SIGNING_TIME,
    )
}
fn signed_pacs008_xml_with_x509_certificate_chain() -> String {
    let signing_key = test_x509_chain_leaf_signing_key();
    signed_pacs008_xml_with_x509_material(
        &signing_key,
        &[
            TEST_X509_CHAIN_LEAF_CERTIFICATE_DER_B64,
            TEST_X509_CHAIN_ROOT_CERTIFICATE_DER_B64,
        ],
        "",
        XML_SIGNATURE_TEST_SIGNING_TIME,
    )
}
fn signed_pacs008_xml_with_unknown_critical_leaf_x509_certificate_chain(
    include_root: bool,
) -> String {
    let signing_key = test_x509_unknown_critical_leaf_signing_key();
    let certificates = x509_certificates_with_optional_root(
        TEST_X509_UNKNOWN_CRITICAL_LEAF_CERTIFICATE_DER_B64,
        TEST_X509_UNKNOWN_CRITICAL_ROOT_CERTIFICATE_DER_B64,
        include_root,
    );
    signed_pacs008_xml_with_x509_material(
        &signing_key,
        &certificates,
        "",
        XML_SIGNATURE_TEST_SIGNING_TIME,
    )
}
fn signed_pacs008_xml_with_signer_key_usage_x509_certificate_chain(
    leaf_certificate: &str,
    include_root: bool,
) -> String {
    let signing_key = test_x509_signer_key_usage_leaf_signing_key();
    let certificates = x509_certificates_with_optional_root(
        leaf_certificate,
        TEST_X509_SIGNER_KEY_USAGE_ROOT_CERTIFICATE_DER_B64,
        include_root,
    );
    signed_pacs008_xml_with_x509_material(
        &signing_key,
        &certificates,
        "",
        XML_SIGNATURE_TEST_SIGNING_TIME,
    )
}
fn signed_pacs008_xml_with_leaf_x509_certificate() -> String {
    signed_pacs008_xml_with_x509_certificate()
}
fn signed_pacs008_xml_with_policy_x509_certificate_chain() -> String {
    let signing_key = test_x509_policy_leaf_signing_key();
    signed_pacs008_xml_with_x509_material(
        &signing_key,
        &[
            TEST_X509_POLICY_LEAF_CERTIFICATE_DER_B64,
            TEST_X509_POLICY_ROOT_CERTIFICATE_DER_B64,
        ],
        "",
        XML_SIGNATURE_TEST_SIGNING_TIME,
    )
}
fn signed_pacs008_xml_with_crl_x509_certificate_chain(embedded_crl: Option<&str>) -> String {
    signed_pacs008_xml_with_crl_x509_certificate_chain_at(
        embedded_crl,
        XML_SIGNATURE_TEST_SIGNING_TIME,
    )
}
fn signed_pacs008_xml_with_crl_x509_certificate_chain_at(
    embedded_crl: Option<&str>,
    signing_time: &str,
) -> String {
    let signing_key = test_x509_crl_leaf_signing_key();
    let crl_xml = embedded_crl
        .map(|crl| format!("<X509CRL>{crl}</X509CRL>"))
        .unwrap_or_default();
    signed_pacs008_xml_with_x509_material(
        &signing_key,
        &[
            TEST_X509_CRL_LEAF_CERTIFICATE_DER_B64,
            TEST_X509_CRL_ROOT_CERTIFICATE_DER_B64,
        ],
        &crl_xml,
        signing_time,
    )
}
fn signed_pacs008_xml_with_ocsp_x509_certificate_chain(embedded_ocsp: Option<&str>) -> String {
    signed_pacs008_xml_with_ocsp_x509_certificate_chain_at(
        embedded_ocsp,
        XML_SIGNATURE_TEST_SIGNING_TIME,
    )
}
fn signed_pacs008_xml_with_ocsp_x509_certificate_chain_at(
    embedded_ocsp: Option<&str>,
    signing_time: &str,
) -> String {
    let signing_key = test_x509_ocsp_leaf_signing_key();
    let ocsp_xml = embedded_ocsp
        .map(|ocsp| format!("<EncapsulatedOCSPValue>{ocsp}</EncapsulatedOCSPValue>"))
        .unwrap_or_default();
    signed_pacs008_xml_with_x509_material(
        &signing_key,
        &[
            TEST_X509_OCSP_LEAF_CERTIFICATE_DER_B64,
            TEST_X509_OCSP_ROOT_CERTIFICATE_DER_B64,
        ],
        &ocsp_xml,
        signing_time,
    )
}
fn signed_pacs008_xml_with_key_info_at(
    signing_key: &P256SigningKey,
    key_info: &str,
    signing_time: &str,
) -> String {
    let unsigned = unsigned_pacs008_xml();
    let insertion = unsigned
        .find("</FIToFICstmrCdtTrf>")
        .expect("signature insertion point");
    let canonical_unsigned = canonicalize_supported_xml(&unsigned).expect("canonical payload");
    let payload_digest = BASE64_STANDARD.encode(Sha256::digest(canonical_unsigned.as_bytes()));
    let signed_properties_id = "signed-props-001";
    let signed_properties = xml_signature_x509_certificates_with_namespaces(
        key_info,
        &default_xmlsig_namespace_bindings(),
    )
    .ok()
    .and_then(|certificates| certificates.first().cloned())
    .map(|leaf_der| {
        signed_properties_xml_with_signing_certificate_v2_at(
            signed_properties_id,
            &leaf_der,
            signing_time,
        )
        .0
    });
    let signed_info = if let Some(signed_properties) = signed_properties.as_ref() {
        let canonical_signed_properties =
            canonicalize_supported_xml(signed_properties).expect("canonical SignedProperties");
        let signed_properties_digest =
            BASE64_STANDARD.encode(Sha256::digest(canonical_signed_properties.as_bytes()));
        signed_info_xml_with_signed_properties_reference(
            XML_C14N_1_0,
            &payload_digest,
            signed_properties_id,
            &signed_properties_digest,
        )
    } else {
        signed_info_xml(XML_C14N_1_0, &payload_digest, false)
    };
    let canonical_signed_info =
        canonicalize_xmlsig_signed_info(&signed_info, CanonicalXmlMode::Inclusive);
    let signature: P256Signature = signing_key.sign(canonical_signed_info.as_bytes());
    let signature = low_s_p256_signature(signature);
    let signature_value = BASE64_STANDARD.encode(signature.to_der().as_bytes());
    let qualifying_properties = if let Some(signed_properties) = signed_properties {
        format!(
            r##"<Object><QualifyingProperties xmlns="{XADES_NS}" Target="#sig-001">{signed_properties}</QualifyingProperties></Object>"##
        )
    } else {
        r##"<Object><QualifyingProperties xmlns="{XADES_NS}" Target="#sig-001"></QualifyingProperties></Object>"##
            .to_owned()
    };
    let signature_xml = format!(
        concat!(
            r#"<Signature xmlns="{XMLDSIG_NS}" Id="sig-001">{signed_info}<SignatureValue>{signature_value}</SignatureValue>"#,
            "{key_info}",
            "{qualifying_properties}",
            "</Signature>"
        ),
        signed_info = signed_info,
        signature_value = signature_value,
        key_info = key_info,
        qualifying_properties = qualifying_properties,
        XMLDSIG_NS = XMLDSIG_NS
    );
    format!(
        "{}{}{}",
        &unsigned[..insertion],
        signature_xml,
        &unsigned[insertion..]
    )
}
fn signed_pacs008_xml_with_signed_info_rewrite(
    rewrite_signed_info: impl FnOnce(String) -> String,
) -> String {
    let unsigned = unsigned_pacs008_xml();
    let insertion = unsigned
        .find("</FIToFICstmrCdtTrf>")
        .expect("signature insertion point");
    let canonical_unsigned = canonicalize_supported_xml(&unsigned).expect("canonical payload");
    let digest = BASE64_STANDARD.encode(Sha256::digest(canonical_unsigned.as_bytes()));
    let signed_info = rewrite_signed_info(signed_info_xml(XML_C14N_1_0, &digest, false));
    let canonical_signed_info =
        canonicalize_xmlsig_signed_info(&signed_info, CanonicalXmlMode::Inclusive);
    let signing_key = xml_signature_test_signing_key();
    let signature = low_s_p256_signature(signing_key.sign(canonical_signed_info.as_bytes()));
    let signature_value = BASE64_STANDARD.encode(signature.to_der().as_bytes());
    let public_key = BASE64_STANDARD.encode(
        signing_key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes(),
    );
    let signature_xml = format!(
        concat!(
            r#"<Signature xmlns="{XMLDSIG_NS}" Id="sig-001">{signed_info}<SignatureValue>{signature_value}</SignatureValue>"#,
            "<KeyInfo><KeyValue><ECKeyValue>",
            r#"<NamedCurve URI="urn:oid:1.2.840.10045.3.1.7"></NamedCurve>"#,
            "<PublicKey>{public_key}</PublicKey>",
            "</ECKeyValue></KeyValue></KeyInfo>",
            r##"<Object><QualifyingProperties xmlns="{XADES_NS}" Target="#sig-001"></QualifyingProperties></Object>"##,
            "</Signature>"
        ),
        signed_info = signed_info,
        signature_value = signature_value,
        public_key = public_key,
        XMLDSIG_NS = XMLDSIG_NS,
        XADES_NS = XADES_NS
    );
    format!(
        "{}{}{}",
        &unsigned[..insertion],
        signature_xml,
        &unsigned[insertion..]
    )
}
fn signed_pacs008_xml_with_signed_properties_reference() -> String {
    let signed_properties_id = "signed-props-001";
    let signed_properties = signed_properties_xml(signed_properties_id);
    signed_pacs008_xml_with_signed_properties(signed_properties_id, &signed_properties)
}
fn signed_pacs008_xml_with_prefixed_xades_signed_properties() -> String {
    let signed_properties_id = "signed-props-001";
    let signed_properties = signed_properties_xml_prefixed(signed_properties_id, XADES_NS);
    signed_pacs008_xml_with_signed_properties(signed_properties_id, &signed_properties)
}
fn signed_pacs008_xml_with_wrong_prefixed_xades_namespace() -> String {
    let signed_properties_id = "signed-props-001";
    let signed_properties = signed_properties_xml_prefixed(signed_properties_id, "urn:not-xades");
    signed_pacs008_xml_with_signed_properties(signed_properties_id, &signed_properties)
}
fn signed_pacs008_xml_with_wrong_default_xades_namespace() -> String {
    let signed_properties_id = "signed-props-001";
    let signed_properties =
        signed_properties_xml_with_default_namespace(signed_properties_id, "urn:not-xades");
    signed_pacs008_xml_with_signed_properties(signed_properties_id, &signed_properties).replacen(
        &format!(r##"<QualifyingProperties xmlns="{XADES_NS}" Target="#sig-001">"##),
        r##"<QualifyingProperties xmlns="urn:not-xades" Target="#sig-001">"##,
        1,
    )
}
fn signed_pacs008_xml_with_signed_properties(
    signed_properties_id: &str,
    signed_properties: &str,
) -> String {
    let unsigned = unsigned_pacs008_xml();
    let insertion = unsigned
        .find("</FIToFICstmrCdtTrf>")
        .expect("signature insertion point");
    let canonical_unsigned = canonicalize_supported_xml(&unsigned).expect("canonical payload");
    let payload_digest = BASE64_STANDARD.encode(Sha256::digest(canonical_unsigned.as_bytes()));
    let canonical_signed_properties =
        canonicalize_supported_xml(signed_properties).expect("canonical SignedProperties");
    let signed_properties_digest =
        BASE64_STANDARD.encode(Sha256::digest(canonical_signed_properties.as_bytes()));
    let signed_info = signed_info_xml_with_signed_properties_reference(
        XML_C14N_1_0,
        &payload_digest,
        signed_properties_id,
        &signed_properties_digest,
    );
    let canonical_signed_info =
        canonicalize_xmlsig_signed_info(&signed_info, CanonicalXmlMode::Inclusive);
    let signing_key = xml_signature_test_signing_key();
    let signature = low_s_p256_signature(signing_key.sign(canonical_signed_info.as_bytes()));
    let signature_value = BASE64_STANDARD.encode(signature.to_der().as_bytes());
    let public_key = BASE64_STANDARD.encode(
        signing_key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes(),
    );
    let signature_xml = format!(
        concat!(
            r#"<Signature xmlns="{XMLDSIG_NS}" Id="sig-001">{signed_info}<SignatureValue>{signature_value}</SignatureValue>"#,
            "<KeyInfo><KeyValue><ECKeyValue>",
            r#"<NamedCurve URI="urn:oid:1.2.840.10045.3.1.7"></NamedCurve>"#,
            "<PublicKey>{public_key}</PublicKey>",
            "</ECKeyValue></KeyValue></KeyInfo>",
            r##"<Object><QualifyingProperties xmlns="{XADES_NS}" Target="#sig-001">"##,
            "{signed_properties}",
            "</QualifyingProperties></Object>",
            "</Signature>"
        ),
        signed_info = signed_info,
        signature_value = signature_value,
        public_key = public_key,
        signed_properties = signed_properties,
        XMLDSIG_NS = XMLDSIG_NS,
        XADES_NS = XADES_NS
    );
    format!(
        "{}{}{}",
        &unsigned[..insertion],
        signature_xml,
        &unsigned[insertion..]
    )
}
fn signed_properties_xml(id: &str) -> String {
    format!(
        concat!(
            r#"<SignedProperties xmlns="{XADES_NS}" Id="{id}"><SignedSignatureProperties>"#,
            "<SigningTime>{signing_time}</SigningTime>",
            "</SignedSignatureProperties></SignedProperties>"
        ),
        id = id,
        signing_time = XML_SIGNATURE_TEST_SIGNING_TIME,
        XADES_NS = XADES_NS
    )
}
fn signed_properties_xml_prefixed(id: &str, xades_namespace: &str) -> String {
    format!(
        concat!(
            r#"<xades:SignedProperties xmlns:xades="{xades_namespace}" Id="{id}">"#,
            "<xades:SignedSignatureProperties>",
            "<xades:SigningTime>{signing_time}</xades:SigningTime>",
            "</xades:SignedSignatureProperties>",
            "</xades:SignedProperties>"
        ),
        id = id,
        signing_time = XML_SIGNATURE_TEST_SIGNING_TIME,
        xades_namespace = xades_namespace
    )
}
fn signed_properties_xml_with_default_namespace(id: &str, xades_namespace: &str) -> String {
    format!(
        concat!(
            r#"<SignedProperties xmlns="{xades_namespace}" Id="{id}">"#,
            "<SignedSignatureProperties>",
            "<SigningTime>{signing_time}</SigningTime>",
            "</SignedSignatureProperties>",
            "</SignedProperties>"
        ),
        id = id,
        signing_time = XML_SIGNATURE_TEST_SIGNING_TIME,
        xades_namespace = xades_namespace
    )
}
fn signed_properties_xml_with_signing_certificate_v2(
    id: &str,
    leaf_der: &[u8],
) -> (String, String) {
    signed_properties_xml_with_signing_certificate_v2_at(
        id,
        leaf_der,
        XML_SIGNATURE_TEST_SIGNING_TIME,
    )
}
fn signed_properties_xml_with_signing_certificate_v2_at(
    id: &str,
    leaf_der: &[u8],
    signing_time: &str,
) -> (String, String) {
    let leaf_digest = BASE64_STANDARD.encode(Sha256::digest(leaf_der));
    (
        format!(
            concat!(
                r#"<SignedProperties xmlns="{XADES_NS}" xmlns:ds="{XMLDSIG_NS}" Id="{id}"><SignedSignatureProperties>"#,
                "<SigningTime>{signing_time}</SigningTime>",
                "<SigningCertificateV2><Cert><CertDigest>",
                r#"<ds:DigestMethod Algorithm="{sha256}"></ds:DigestMethod>"#,
                "<ds:DigestValue>{leaf_digest}</ds:DigestValue>",
                "</CertDigest></Cert></SigningCertificateV2>",
                "</SignedSignatureProperties></SignedProperties>"
            ),
            id = id,
            signing_time = signing_time,
            sha256 = XMLDSIG_SHA256,
            leaf_digest = leaf_digest,
            XMLDSIG_NS = XMLDSIG_NS,
            XADES_NS = XADES_NS
        ),
        leaf_digest,
    )
}
fn test_xades_signed_properties_xml() -> String {
    signed_properties_xml("signed-props-001")
}
fn test_xades_signed_properties_xml_for_certificate(certificate_der_b64: &str) -> String {
    let certificate_der = BASE64_STANDARD
        .decode(certificate_der_b64)
        .expect("XAdES certificate fixture must decode");
    signed_properties_xml_with_signing_certificate_v2("signed-props-001", &certificate_der).0
}
fn test_xades_signing_certificate_v2_xml(certificate_der_b64: &str) -> String {
    test_xades_signing_certificate_v2_xml_with_cert_extra(certificate_der_b64, "")
}
fn test_xades_signing_certificate_v2_xml_with_cert_extra(
    certificate_der_b64: &str,
    cert_extra: &str,
) -> String {
    let certificate_der = BASE64_STANDARD
        .decode(certificate_der_b64)
        .expect("XAdES certificate fixture must decode");
    let digest = BASE64_STANDARD.encode(Sha256::digest(&certificate_der));
    format!(
        concat!(
            r#"<SigningCertificateV2 xmlns="{XADES_NS}" xmlns:ds="{XMLDSIG_NS}"><Cert><CertDigest>"#,
            r#"<ds:DigestMethod Algorithm="{sha256}"></ds:DigestMethod>"#,
            "<ds:DigestValue>{digest}</ds:DigestValue>",
            "</CertDigest>{cert_extra}</Cert></SigningCertificateV2>"
        ),
        sha256 = XMLDSIG_SHA256,
        digest = digest,
        cert_extra = cert_extra,
        XMLDSIG_NS = XMLDSIG_NS,
        XADES_NS = XADES_NS
    )
}
fn test_xades_signed_properties_xml_with_extra(extra: &str) -> String {
    format!(
        concat!(
            r#"<SignedProperties xmlns="{XADES_NS}" Id="signed-props-001"><SignedSignatureProperties>"#,
            "<SigningTime>{signing_time}</SigningTime>",
            "{extra}",
            "</SignedSignatureProperties></SignedProperties>"
        ),
        signing_time = XML_SIGNATURE_TEST_SIGNING_TIME,
        extra = extra,
        XADES_NS = XADES_NS
    )
}
fn signed_properties_id_from_xml(signed_properties_xml: &str) -> &str {
    let start = signed_properties_xml
        .find(r#"Id=""#)
        .map(|index| index + r#"Id=""#.len())
        .expect("SignedProperties Id attribute");
    let end = signed_properties_xml[start..]
        .find('"')
        .map(|index| start + index)
        .expect("SignedProperties Id closing quote");
    &signed_properties_xml[start..end]
}
fn test_xades_signed_properties_reference_for_xml(signed_properties_xml: &str) -> String {
    let signed_properties_id = signed_properties_id_from_xml(signed_properties_xml);
    let canonical_signed_properties =
        canonicalize_supported_xml(signed_properties_xml).expect("canonical SignedProperties");
    let digest = BASE64_STANDARD.encode(Sha256::digest(canonical_signed_properties.as_bytes()));
    format!(
        concat!(
            r##"<Reference URI="#{signed_properties_id}" Type="{signed_properties_type}">"##,
            r#"<Transforms><Transform Algorithm="{exclusive_c14n}"></Transform></Transforms>"#,
            r#"<DigestMethod Algorithm="{sha256}"></DigestMethod>"#,
            "<DigestValue>{digest}</DigestValue></Reference>"
        ),
        signed_properties_id = signed_properties_id,
        signed_properties_type = XADES_SIGNED_PROPERTIES_TYPE,
        exclusive_c14n = XML_EXCLUSIVE_C14N_1_0,
        sha256 = XMLDSIG_SHA256,
        digest = digest
    )
}
fn test_xades_object_xml(signed_properties_xml: &str) -> String {
    format!(
        r##"<Object><QualifyingProperties xmlns="{XADES_NS}" Target="#sig-001">{signed_properties_xml}</QualifyingProperties></Object>"##
    )
}
fn test_p256_key_info(signing_key: &P256SigningKey) -> String {
    let public_key = BASE64_STANDARD.encode(
        signing_key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes(),
    );
    format!(
        concat!(
            "<KeyInfo><KeyValue><ECKeyValue>",
            r#"<NamedCurve URI="{named_curve}"></NamedCurve>"#,
            "<PublicKey>{public_key}</PublicKey>",
            "</ECKeyValue></KeyValue></KeyInfo>"
        ),
        named_curve = XMLDSIG_P256_NAMED_CURVE,
        public_key = public_key
    )
}
fn signed_pacs008_xml_with_x509_certificate_chain_and_signed_properties(
    signed_properties_xml: &str,
) -> String {
    let signed_properties_reference =
        test_xades_signed_properties_reference_for_xml(signed_properties_xml);
    let xades_object = test_xades_object_xml(signed_properties_xml);
    let key_info = format!(
        concat!(
            "<KeyInfo><X509Data>",
            "<X509Certificate>{leaf}</X509Certificate>",
            "<X509Certificate>{root}</X509Certificate>",
            "</X509Data></KeyInfo>"
        ),
        leaf = TEST_X509_CHAIN_LEAF_CERTIFICATE_DER_B64,
        root = TEST_X509_CHAIN_ROOT_CERTIFICATE_DER_B64
    );
    signed_pacs008_xml_with_key_info_and_xades_parts(
        &test_x509_chain_leaf_signing_key(),
        &key_info,
        &signed_properties_reference,
        &xades_object,
    )
}
fn signed_pacs008_xml_with_key_info_and_xades_parts(
    signing_key: &P256SigningKey,
    key_info: &str,
    signed_properties_reference_xml: &str,
    xades_object_xml: &str,
) -> String {
    let unsigned = unsigned_pacs008_xml();
    let insertion = unsigned
        .find("</FIToFICstmrCdtTrf>")
        .expect("signature insertion point");
    let canonical_unsigned = canonicalize_supported_xml(&unsigned).expect("canonical payload");
    let payload_digest = BASE64_STANDARD.encode(Sha256::digest(canonical_unsigned.as_bytes()));
    let signed_info = format!(
        concat!(
            r#"<SignedInfo><CanonicalizationMethod Algorithm="{c14n}"></CanonicalizationMethod>"#,
            r#"<SignatureMethod Algorithm="{ecdsa_sha256}"></SignatureMethod>"#,
            r#"<Reference URI=""><Transforms><Transform Algorithm="{enveloped_signature}"></Transform></Transforms>"#,
            r#"<DigestMethod Algorithm="{sha256}"></DigestMethod><DigestValue>{payload_digest}</DigestValue></Reference>"#,
            "{signed_properties_reference_xml}",
            "</SignedInfo>"
        ),
        c14n = XML_C14N_1_0,
        ecdsa_sha256 = XMLDSIG_ECDSA_SHA256,
        enveloped_signature = XMLDSIG_ENVELOPED_SIGNATURE,
        sha256 = XMLDSIG_SHA256,
        payload_digest = payload_digest,
        signed_properties_reference_xml = signed_properties_reference_xml
    );
    let canonical_signed_info =
        canonicalize_xmlsig_signed_info(&signed_info, CanonicalXmlMode::Inclusive);
    let signature = low_s_p256_signature(signing_key.sign(canonical_signed_info.as_bytes()));
    let signature_value = BASE64_STANDARD.encode(signature.to_der().as_bytes());
    let signature_xml = format!(
        r#"<Signature xmlns="{XMLDSIG_NS}" Id="sig-001">{signed_info}<SignatureValue>{signature_value}</SignatureValue>{key_info}{xades_object_xml}</Signature>"#
    );
    format!(
        "{}{}{}",
        &unsigned[..insertion],
        signature_xml,
        &unsigned[insertion..]
    )
}
fn signed_properties_xml_with_signing_certificate_v2_digest_bytes(
    id: &str,
    digests: &[[u8; 32]],
) -> String {
    let certs = digests
        .iter()
        .map(|digest| {
            let digest = BASE64_STANDARD.encode(digest);
            format!(
                concat!(
                    "<Cert><CertDigest>",
                    r#"<ds:DigestMethod Algorithm="{sha256}"></ds:DigestMethod>"#,
                    "<ds:DigestValue>{digest}</ds:DigestValue>",
                    "</CertDigest></Cert>"
                ),
                sha256 = XMLDSIG_SHA256,
                digest = digest
            )
        })
        .collect::<String>();
    format!(
        concat!(
            r#"<SignedProperties xmlns="{XADES_NS}" xmlns:ds="{XMLDSIG_NS}" Id="{id}"><SignedSignatureProperties>"#,
            "<SigningTime>{signing_time}</SigningTime>",
            "<SigningCertificateV2>{certs}</SigningCertificateV2>",
            "</SignedSignatureProperties></SignedProperties>"
        ),
        id = id,
        signing_time = XML_SIGNATURE_TEST_SIGNING_TIME,
        certs = certs,
        XMLDSIG_NS = XMLDSIG_NS,
        XADES_NS = XADES_NS
    )
}
struct CertificateChainSignedPropertiesPayload {
    payload: String,
    issuer_sha256: String,
    signing_certificate_digest: String,
}
fn signed_pacs008_xml_with_certificate_chain_signed_properties_reference()
-> CertificateChainSignedPropertiesPayload {
    let unsigned = unsigned_pacs008_xml();
    let insertion = unsigned
        .find("</FIToFICstmrCdtTrf>")
        .expect("signature insertion point");
    let canonical_unsigned = canonicalize_supported_xml(&unsigned).expect("canonical payload");
    let payload_digest = BASE64_STANDARD.encode(Sha256::digest(canonical_unsigned.as_bytes()));
    let issuer_key = RcgenKeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("issuer key");
    let mut issuer_params =
        CertificateParams::new(vec!["iso-issuer.example".to_owned()]).expect("issuer params");
    issuer_params
        .distinguished_name
        .push(DnType::CommonName, "ISO Bridge Test Issuer");
    issuer_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    issuer_params.not_before = date_time_ymd(2020, 1, 1);
    issuer_params.not_after = date_time_ymd(2030, 1, 1);
    issuer_params
        .custom_extensions
        .push(critical_key_usage_digital_signature_key_cert_sign_extension());
    let issuer_cert = issuer_params
        .self_signed(&issuer_key)
        .expect("issuer certificate");
    let issuer_sha256 = sha256_hex(issuer_cert.der().as_ref());
    let issuer = Issuer::from_params(&issuer_params, issuer_key);
    let leaf_key = RcgenKeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("leaf key");
    let mut leaf_params =
        CertificateParams::new(vec!["iso-leaf.example".to_owned()]).expect("leaf params");
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, "ISO Bridge Test Leaf");
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_params.not_before = date_time_ymd(2020, 1, 1);
    leaf_params.not_after = date_time_ymd(2030, 1, 1);
    let leaf_cert = leaf_params
        .signed_by(&leaf_key, &issuer)
        .expect("leaf certificate");
    let signed_properties_id = "signed-props-001";
    let (signed_properties, signing_certificate_digest) =
        signed_properties_xml_with_signing_certificate_v2(
            signed_properties_id,
            leaf_cert.der().as_ref(),
        );
    let canonical_signed_properties =
        canonicalize_supported_xml(&signed_properties).expect("canonical SignedProperties");
    let signed_properties_digest =
        BASE64_STANDARD.encode(Sha256::digest(canonical_signed_properties.as_bytes()));
    let signed_info = signed_info_xml_with_signed_properties_reference(
        XML_C14N_1_0,
        &payload_digest,
        signed_properties_id,
        &signed_properties_digest,
    );
    let canonical_signed_info =
        canonicalize_xmlsig_signed_info(&signed_info, CanonicalXmlMode::Inclusive);
    let signature = leaf_key
        .sign(canonical_signed_info.as_bytes())
        .expect("leaf XMLDSig signature");
    let signature_value = BASE64_STANDARD.encode(low_s_p256_signature_der_from_bytes(&signature));
    let leaf_certificate = BASE64_STANDARD.encode(leaf_cert.der().as_ref());
    let issuer_certificate = BASE64_STANDARD.encode(issuer_cert.der().as_ref());
    let signature_xml = format!(
        concat!(
            r#"<Signature xmlns="{XMLDSIG_NS}" Id="sig-001">{signed_info}<SignatureValue>{signature_value}</SignatureValue>"#,
            "<KeyInfo><X509Data>",
            "<X509Certificate>{leaf_certificate}</X509Certificate>",
            "<X509Certificate>{issuer_certificate}</X509Certificate>",
            "</X509Data></KeyInfo>",
            r##"<Object><QualifyingProperties xmlns="{XADES_NS}" Target="#sig-001">"##,
            "{signed_properties}",
            "</QualifyingProperties></Object>",
            "</Signature>"
        ),
        signed_info = signed_info,
        signature_value = signature_value,
        leaf_certificate = leaf_certificate,
        issuer_certificate = issuer_certificate,
        signed_properties = signed_properties,
        XMLDSIG_NS = XMLDSIG_NS,
        XADES_NS = XADES_NS
    );
    CertificateChainSignedPropertiesPayload {
        payload: format!(
            "{}{}{}",
            &unsigned[..insertion],
            signature_xml,
            &unsigned[insertion..]
        ),
        issuer_sha256,
        signing_certificate_digest,
    }
}
fn signed_pacs008_xml_with_comments() -> String {
    let unsigned = unsigned_pacs008_xml_with_comments();
    let insertion = unsigned
        .find("</FIToFICstmrCdtTrf>")
        .expect("signature insertion point");
    let canonical_unsigned =
        canonicalize_supported_xml(&unsigned).expect("canonical commented payload");
    let digest = BASE64_STANDARD.encode(Sha256::digest(canonical_unsigned.as_bytes()));
    let signed_info = signed_info_xml(XML_C14N_1_0, &digest, false)
        .replace("<Reference", "<!--signed-info comment--><Reference")
        .replace("</SignedInfo>", "<!--signed-info tail--></SignedInfo>");
    let canonical_signed_info =
        canonicalize_xmlsig_signed_info(&signed_info, CanonicalXmlMode::Inclusive);
    let signing_key = xml_signature_test_signing_key();
    let signature = low_s_p256_signature(signing_key.sign(canonical_signed_info.as_bytes()));
    let signature_value = BASE64_STANDARD.encode(signature.to_der().as_bytes());
    let public_key = BASE64_STANDARD.encode(
        signing_key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes(),
    );
    let signature_xml = format!(
        concat!(
            r#"<Signature xmlns="{XMLDSIG_NS}">{signed_info}<SignatureValue>{signature_value}</SignatureValue>"#,
            "<KeyInfo><KeyValue><ECKeyValue>",
            r#"<NamedCurve URI="urn:oid:1.2.840.10045.3.1.7"></NamedCurve>"#,
            "<PublicKey>{public_key}</PublicKey>",
            "</ECKeyValue></KeyValue></KeyInfo>",
            r##"<Object><QualifyingProperties xmlns="{XADES_NS}" Target="#sig-001"></QualifyingProperties></Object>"##,
            "</Signature>"
        ),
        signed_info = signed_info,
        signature_value = signature_value,
        public_key = public_key,
        XMLDSIG_NS = XMLDSIG_NS,
        XADES_NS = XADES_NS
    );
    format!(
        "{}{}{}",
        &unsigned[..insertion],
        signature_xml,
        &unsigned[insertion..]
    )
}
fn unsigned_pacs008_xml_with_comments() -> String {
    unsigned_pacs008_xml()
        .replace(
            "<FIToFICstmrCdtTrf>",
            "<!--document comment--><FIToFICstmrCdtTrf><!--payment comment-->",
        )
        .replace(
            "<MsgId>sig-001</MsgId>",
            "<!--group header comment--><MsgId>sig-001</MsgId>",
        )
        .replace(
            "</CdtTrfTxInf>",
            "<!--transaction tail comment--></CdtTrfTxInf>",
        )
}
fn signed_pacs008_xml_with_character_reference_message_id() -> String {
    signed_pacs008_xml_from_unsigned(
        unsigned_pacs008_xml_with_message_id("sig&amp;001"),
        XML_C14N_1_0,
        false,
        true,
    )
}
fn unsigned_pacs008_xml_with_xml_namespace_attribute() -> String {
    unsigned_pacs008_xml().replace("<GrpHdr>", r#"<GrpHdr xml:lang="en">"#)
}
fn unsigned_pacs008_xml_with_prefixed_attribute() -> String {
    unsigned_pacs008_xml().replace(
        "<GrpHdr>",
        r#"<GrpHdr xmlns:pay="urn:iso:test:pay" pay:scope="retail">"#,
    )
}
fn signed_pacs008_xml_with_xml_namespace_attribute() -> String {
    signed_pacs008_xml_from_unsigned(
        unsigned_pacs008_xml_with_xml_namespace_attribute(),
        XML_C14N_1_0,
        false,
        true,
    )
}
fn signed_pacs008_xml_with_prefixed_attribute() -> String {
    signed_pacs008_xml_from_unsigned(
        unsigned_pacs008_xml_with_prefixed_attribute(),
        XML_C14N_1_0,
        false,
        true,
    )
}
fn signed_pacs008_xml_with_signed_info_xml_namespace_attribute() -> String {
    let unsigned = unsigned_pacs008_xml();
    let insertion = unsigned
        .find("</FIToFICstmrCdtTrf>")
        .expect("signature insertion point");
    let canonical_unsigned = canonicalize_supported_xml(&unsigned).expect("canonical payload");
    let digest = BASE64_STANDARD.encode(Sha256::digest(canonical_unsigned.as_bytes()));
    let signed_info = signed_info_xml(XML_C14N_1_0, &digest, false).replacen(
        "<SignedInfo>",
        r#"<SignedInfo xml:lang="en">"#,
        1,
    );
    let canonical_signed_info =
        canonicalize_xmlsig_signed_info(&signed_info, CanonicalXmlMode::Inclusive);
    let signing_key = xml_signature_test_signing_key();
    let signature = low_s_p256_signature(signing_key.sign(canonical_signed_info.as_bytes()));
    let signature_value = BASE64_STANDARD.encode(signature.to_der().as_bytes());
    let public_key = BASE64_STANDARD.encode(
        signing_key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes(),
    );
    let signature_xml = format!(
        concat!(
            r#"<Signature xmlns="{XMLDSIG_NS}">{signed_info}<SignatureValue>{signature_value}</SignatureValue>"#,
            "<KeyInfo><KeyValue><ECKeyValue>",
            r#"<NamedCurve URI="urn:oid:1.2.840.10045.3.1.7"></NamedCurve>"#,
            "<PublicKey>{public_key}</PublicKey>",
            "</ECKeyValue></KeyValue></KeyInfo>",
            r##"<Object><QualifyingProperties xmlns="{XADES_NS}" Target="#sig-001"></QualifyingProperties></Object>"##,
            "</Signature>"
        ),
        signed_info = signed_info,
        signature_value = signature_value,
        public_key = public_key,
        XMLDSIG_NS = XMLDSIG_NS,
        XADES_NS = XADES_NS
    );
    format!(
        "{}{}{}",
        &unsigned[..insertion],
        signature_xml,
        &unsigned[insertion..]
    )
}
fn signed_pacs008_xml_with_signed_info_inherited_prefixed_attribute() -> String {
    let unsigned = unsigned_pacs008_xml();
    let insertion = unsigned
        .find("</FIToFICstmrCdtTrf>")
        .expect("signature insertion point");
    let canonical_unsigned = canonicalize_supported_xml(&unsigned).expect("canonical payload");
    let digest = BASE64_STANDARD.encode(Sha256::digest(canonical_unsigned.as_bytes()));
    let signed_info = signed_info_xml(XML_EXCLUSIVE_C14N_1_0, &digest, false).replacen(
        "<SignedInfo>",
        r#"<SignedInfo ext:role="authorization">"#,
        1,
    );
    let inherited_namespaces = vec![
        CanonicalXmlAttribute {
            name: "xmlns".to_owned(),
            value: XMLDSIG_NS.to_owned(),
            kind: CanonicalXmlAttributeKind::Namespace,
        },
        CanonicalXmlAttribute {
            name: "xmlns:ext".to_owned(),
            value: "urn:iso:test:ext".to_owned(),
            kind: CanonicalXmlAttributeKind::Namespace,
        },
    ];
    let canonical_signed_info = canonicalize_supported_xml_with_mode(
        &signed_info,
        &inherited_namespaces,
        CanonicalXmlMode::Exclusive,
    )
    .expect("canonical inherited prefixed-attribute SignedInfo");
    let signing_key = xml_signature_test_signing_key();
    let signature = low_s_p256_signature(signing_key.sign(canonical_signed_info.as_bytes()));
    let signature_value = BASE64_STANDARD.encode(signature.to_der().as_bytes());
    let public_key = BASE64_STANDARD.encode(
        signing_key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes(),
    );
    let signature_xml = format!(
        concat!(
            r#"<Signature xmlns="{XMLDSIG_NS}" xmlns:ext="urn:iso:test:ext">{signed_info}"#,
            "<SignatureValue>{signature_value}</SignatureValue>",
            "<KeyInfo><KeyValue><ECKeyValue>",
            r#"<NamedCurve URI="urn:oid:1.2.840.10045.3.1.7"></NamedCurve>"#,
            "<PublicKey>{public_key}</PublicKey>",
            "</ECKeyValue></KeyValue></KeyInfo>",
            r##"<Object><QualifyingProperties xmlns="{XADES_NS}" Target="#sig-001"></QualifyingProperties></Object>"##,
            "</Signature>"
        ),
        signed_info = signed_info,
        signature_value = signature_value,
        public_key = public_key,
        XMLDSIG_NS = XMLDSIG_NS,
        XADES_NS = XADES_NS
    );
    format!(
        "{}{}{}",
        &unsigned[..insertion],
        signature_xml,
        &unsigned[insertion..]
    )
}
fn signed_pacs008_xml_with_prefixed_signature_namespace() -> String {
    signed_pacs008_xml_with_prefixed_signature_namespace_options(XML_C14N_1_0, false, true)
}
fn signed_pacs008_xml_with_wrong_prefixed_signature_namespace() -> String {
    signed_pacs008_xml_with_prefixed_signature_namespace_options_and_namespace(
        XML_C14N_1_0,
        false,
        true,
        "urn:not-xmldsig",
    )
}
fn signed_pacs008_xml_with_wrong_default_signature_namespace() -> String {
    signed_pacs008_xml_with_default_signature_namespace("urn:not-xmldsig")
}
fn signed_pacs008_xml_with_default_signature_namespace(xmldsig_namespace: &str) -> String {
    let unsigned = unsigned_pacs008_xml();
    let insertion = unsigned
        .find("</FIToFICstmrCdtTrf>")
        .expect("signature insertion point");
    let canonical_unsigned = canonicalize_supported_xml(&unsigned).expect("canonical payload");
    let digest = BASE64_STANDARD.encode(Sha256::digest(canonical_unsigned.as_bytes()));
    let signed_info = signed_info_xml(XML_C14N_1_0, &digest, false);
    let inherited_namespaces = [CanonicalXmlAttribute {
        name: "xmlns".to_owned(),
        value: xmldsig_namespace.to_owned(),
        kind: CanonicalXmlAttributeKind::Namespace,
    }];
    let canonical_signed_info = canonicalize_supported_xml_with_mode(
        &signed_info,
        &inherited_namespaces,
        CanonicalXmlMode::Inclusive,
    )
    .expect("canonical default-namespaced SignedInfo");
    let signing_key = xml_signature_test_signing_key();
    let signature = low_s_p256_signature(signing_key.sign(canonical_signed_info.as_bytes()));
    let signature_value = BASE64_STANDARD.encode(signature.to_der().as_bytes());
    let public_key = BASE64_STANDARD.encode(
        signing_key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes(),
    );
    let signature_xml = format!(
        concat!(
            r#"<Signature xmlns="{xmldsig_ns}" Id="sig-001">{signed_info}"#,
            "<SignatureValue>{signature_value}</SignatureValue>",
            "<KeyInfo><KeyValue><ECKeyValue>",
            r#"<NamedCurve URI="urn:oid:1.2.840.10045.3.1.7"></NamedCurve>"#,
            "<PublicKey>{public_key}</PublicKey>",
            "</ECKeyValue></KeyValue></KeyInfo>",
            r##"<Object><QualifyingProperties Target="#sig-001"></QualifyingProperties></Object>"##,
            "</Signature>"
        ),
        xmldsig_ns = xmldsig_namespace,
        signed_info = signed_info,
        signature_value = signature_value,
        public_key = public_key
    );
    format!(
        "{}{}{}",
        &unsigned[..insertion],
        signature_xml,
        &unsigned[insertion..]
    )
}
fn signed_pacs008_xml_with_inclusive_unused_signature_namespace() -> String {
    signed_pacs008_xml_with_prefixed_signature_namespace_options(XML_C14N_1_0, true, true)
}
fn signed_pacs008_xml_with_exclusive_bytes_declared_as_inclusive() -> String {
    signed_pacs008_xml_with_prefixed_signature_namespace_options(XML_C14N_1_0, true, false)
}
fn signed_pacs008_xml_with_prefixed_signature_namespace_options(
    c14n_algorithm: &str,
    include_unused_namespace: bool,
    sign_with_declared_c14n_mode: bool,
) -> String {
    signed_pacs008_xml_with_prefixed_signature_namespace_options_and_namespace(
        c14n_algorithm,
        include_unused_namespace,
        sign_with_declared_c14n_mode,
        XMLDSIG_NS,
    )
}
fn signed_pacs008_xml_with_prefixed_signature_namespace_options_and_namespace(
    c14n_algorithm: &str,
    include_unused_namespace: bool,
    sign_with_declared_c14n_mode: bool,
    xmldsig_namespace: &str,
) -> String {
    let unsigned = unsigned_pacs008_xml();
    let insertion = unsigned
        .find("</FIToFICstmrCdtTrf>")
        .expect("signature insertion point");
    let canonical_unsigned = canonicalize_supported_xml(&unsigned).expect("canonical payload");
    let digest = BASE64_STANDARD.encode(Sha256::digest(canonical_unsigned.as_bytes()));
    let signed_info = signed_info_xml_prefixed(c14n_algorithm, &digest);
    let mut inherited_namespaces = vec![
        CanonicalXmlAttribute {
            name: "xmlns".to_owned(),
            value: TEST_PACS008_NAMESPACE.to_owned(),
            kind: CanonicalXmlAttributeKind::Namespace,
        },
        CanonicalXmlAttribute {
            name: "xmlns:ds".to_owned(),
            value: xmldsig_namespace.to_owned(),
            kind: CanonicalXmlAttributeKind::Namespace,
        },
    ];
    if include_unused_namespace {
        inherited_namespaces.push(CanonicalXmlAttribute {
            name: "xmlns:unused".to_owned(),
            value: "urn:unused".to_owned(),
            kind: CanonicalXmlAttributeKind::Namespace,
        });
    }
    let signing_mode = if sign_with_declared_c14n_mode {
        xml_canonicalization_mode(c14n_algorithm).expect("test canonicalization algorithm")
    } else {
        CanonicalXmlMode::Exclusive
    };
    let canonical_signed_info =
        canonicalize_supported_xml_with_mode(&signed_info, &inherited_namespaces, signing_mode)
            .expect("canonical prefixed SignedInfo");
    let signing_key = xml_signature_test_signing_key();
    let signature = low_s_p256_signature(signing_key.sign(canonical_signed_info.as_bytes()));
    let signature_value = BASE64_STANDARD.encode(signature.to_der().as_bytes());
    let public_key = BASE64_STANDARD.encode(
        signing_key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes(),
    );
    let signature_xml = format!(
        concat!(
            r#"<ds:Signature xmlns:ds="{xmldsig_ns}"{unused_namespace}>{signed_info}"#,
            "<ds:SignatureValue>{signature_value}</ds:SignatureValue>",
            "<ds:KeyInfo><ds:KeyValue><ds:ECKeyValue>",
            r#"<ds:NamedCurve URI="urn:oid:1.2.840.10045.3.1.7"></ds:NamedCurve>"#,
            "<ds:PublicKey>{public_key}</ds:PublicKey>",
            "</ds:ECKeyValue></ds:KeyValue></ds:KeyInfo>",
            r##"<ds:Object><xades:QualifyingProperties xmlns:xades="http://uri.etsi.org/01903/v1.3.2#" Target="#sig-001"></xades:QualifyingProperties></ds:Object>"##,
            "</ds:Signature>"
        ),
        signed_info = signed_info,
        signature_value = signature_value,
        public_key = public_key,
        xmldsig_ns = xmldsig_namespace,
        unused_namespace = if include_unused_namespace {
            r#" xmlns:unused="urn:unused""#
        } else {
            ""
        }
    );
    format!(
        "{}{}{}",
        &unsigned[..insertion],
        signature_xml,
        &unsigned[insertion..]
    )
}
fn signed_pacs008_xml_with_c14n_algorithm_and_signed_info_style(
    c14n_algorithm: &str,
    self_closing_signed_info_methods: bool,
) -> String {
    signed_pacs008_xml_with_c14n_algorithm_and_signed_info_options(
        c14n_algorithm,
        self_closing_signed_info_methods,
        true,
    )
}
fn signed_pacs008_xml_with_c14n_algorithm_and_signed_info_options(
    c14n_algorithm: &str,
    self_closing_signed_info_methods: bool,
    sign_canonical_signed_info: bool,
) -> String {
    signed_pacs008_xml_from_unsigned(
        unsigned_pacs008_xml(),
        c14n_algorithm,
        self_closing_signed_info_methods,
        sign_canonical_signed_info,
    )
}
fn signed_pacs008_xml_from_unsigned(
    unsigned: String,
    c14n_algorithm: &str,
    self_closing_signed_info_methods: bool,
    sign_canonical_signed_info: bool,
) -> String {
    signed_pacs008_xml_from_unsigned_with_signature_encoding(
        unsigned,
        c14n_algorithm,
        self_closing_signed_info_methods,
        sign_canonical_signed_info,
        XmlSignatureValueEncoding::Der,
    )
}
fn signed_pacs008_xml_from_unsigned_with_signature_encoding(
    unsigned: String,
    c14n_algorithm: &str,
    self_closing_signed_info_methods: bool,
    sign_canonical_signed_info: bool,
    signature_encoding: XmlSignatureValueEncoding,
) -> String {
    signed_pacs008_xml_from_unsigned_with_reference_uri_and_signature_encoding(
        unsigned,
        c14n_algorithm,
        "",
        self_closing_signed_info_methods,
        sign_canonical_signed_info,
        signature_encoding,
    )
}
fn signed_pacs008_xml_from_unsigned_with_reference_uri_and_signature_encoding(
    unsigned: String,
    c14n_algorithm: &str,
    reference_uri: &str,
    self_closing_signed_info_methods: bool,
    sign_canonical_signed_info: bool,
    signature_encoding: XmlSignatureValueEncoding,
) -> String {
    signed_pacs008_xml_from_unsigned_with_reference_options(
        unsigned,
        c14n_algorithm,
        reference_uri,
        self_closing_signed_info_methods,
        sign_canonical_signed_info,
        signature_encoding,
        None,
    )
}
fn signed_pacs008_xml_from_unsigned_with_reference_options(
    unsigned: String,
    c14n_algorithm: &str,
    reference_uri: &str,
    self_closing_signed_info_methods: bool,
    sign_canonical_signed_info: bool,
    signature_encoding: XmlSignatureValueEncoding,
    reference_c14n_algorithm: Option<&str>,
) -> String {
    let insertion = unsigned
        .find("</FIToFICstmrCdtTrf>")
        .expect("signature insertion point");
    let reference_target =
        xml_signature_reference_target(&unsigned, reference_uri).expect("reference target");
    let reference_c14n_mode = reference_c14n_algorithm
        .map(xml_canonicalization_mode)
        .transpose()
        .expect("reference canonicalization algorithm")
        .unwrap_or(CanonicalXmlMode::Exclusive);
    let canonical_reference = canonicalize_supported_xml_with_mode(
        reference_target.xml,
        &reference_target.inherited_namespaces,
        reference_c14n_mode,
    )
    .expect("canonical payload");
    let digest = BASE64_STANDARD.encode(Sha256::digest(canonical_reference.as_bytes()));
    let signed_info = signed_info_xml_with_reference_options(
        c14n_algorithm,
        &digest,
        reference_uri,
        self_closing_signed_info_methods,
        reference_c14n_algorithm,
    );
    let mut signature_namespace_scope = xml_namespace_bindings_before_offset(&unsigned, insertion)
        .expect("signature ancestor namespace scope");
    if let Some(default_namespace) = signature_namespace_scope
        .iter_mut()
        .find(|binding| binding.prefix.is_empty())
    {
        default_namespace.uri = XMLDSIG_NS.to_owned();
    } else {
        signature_namespace_scope.push(CanonicalXmlNamespaceBinding {
            prefix: String::new(),
            uri: XMLDSIG_NS.to_owned(),
        });
    }
    let signature_namespaces =
        inherited_namespace_attributes_from_scope(&signature_namespace_scope);
    let canonical_signed_info = if sign_canonical_signed_info {
        canonicalize_supported_xml_with_mode(
            &signed_info,
            &signature_namespaces,
            xml_canonicalization_mode(c14n_algorithm).expect("supported SignedInfo C14N"),
        )
        .expect("canonical SignedInfo")
    } else {
        signed_info.clone()
    };
    let signing_key = xml_signature_test_signing_key();
    let signature = low_s_p256_signature(signing_key.sign(canonical_signed_info.as_bytes()));
    let signature_value = encode_p256_signature_value(&signature, signature_encoding);
    let public_key = BASE64_STANDARD.encode(
        signing_key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes(),
    );
    let signature_xml = format!(
        concat!(
            r#"<Signature xmlns="{xmldsig_ns}">{signed_info}<SignatureValue>{signature_value}</SignatureValue>"#,
            "<KeyInfo><KeyValue><ECKeyValue>",
            r#"<NamedCurve URI="urn:oid:1.2.840.10045.3.1.7"></NamedCurve>"#,
            "<PublicKey>{public_key}</PublicKey>",
            "</ECKeyValue></KeyValue></KeyInfo>",
            r##"<Object><QualifyingProperties xmlns="{xades_ns}" Target="#sig-001"/></Object>"##,
            "</Signature>"
        ),
        signed_info = signed_info,
        signature_value = signature_value,
        public_key = public_key,
        xmldsig_ns = XMLDSIG_NS,
        xades_ns = XADES_NS,
    );
    format!(
        "{}{}{}",
        &unsigned[..insertion],
        signature_xml,
        &unsigned[insertion..]
    )
}
fn encode_p256_signature_value(
    signature: &P256Signature,
    encoding: XmlSignatureValueEncoding,
) -> String {
    match encoding {
        XmlSignatureValueEncoding::Der => BASE64_STANDARD.encode(signature.to_der().as_bytes()),
        XmlSignatureValueEncoding::FixedWidth => {
            BASE64_STANDARD.encode(signature.to_bytes().as_slice())
        }
    }
}
fn signed_info_xml(c14n_algorithm: &str, digest: &str, self_closing_methods: bool) -> String {
    signed_info_xml_with_reference_uri(c14n_algorithm, digest, "", self_closing_methods)
}
fn signed_info_xml_with_reference_uri(
    c14n_algorithm: &str,
    digest: &str,
    reference_uri: &str,
    self_closing_methods: bool,
) -> String {
    signed_info_xml_with_reference_options(
        c14n_algorithm,
        digest,
        reference_uri,
        self_closing_methods,
        None,
    )
}
fn signed_info_xml_with_reference_options(
    c14n_algorithm: &str,
    digest: &str,
    reference_uri: &str,
    self_closing_methods: bool,
    reference_c14n_algorithm: Option<&str>,
) -> String {
    if self_closing_methods {
        let c14n_transform = reference_c14n_algorithm
            .map(|algorithm| format!(r#"<Transform Algorithm="{algorithm}"/>"#))
            .unwrap_or_default();
        return format!(
            r#"<SignedInfo><CanonicalizationMethod Algorithm="{c14n_algorithm}"/><SignatureMethod Algorithm="{XMLDSIG_ECDSA_SHA256}"/><Reference URI="{reference_uri}"><Transforms><Transform Algorithm="{XMLDSIG_ENVELOPED_SIGNATURE}"/>{c14n_transform}</Transforms><DigestMethod Algorithm="{XMLDSIG_SHA256}"/><DigestValue>{digest}</DigestValue></Reference></SignedInfo>"#
        );
    }
    let c14n_transform = reference_c14n_algorithm
        .map(|algorithm| format!(r#"<Transform Algorithm="{algorithm}"></Transform>"#))
        .unwrap_or_default();
    format!(
        r#"<SignedInfo><CanonicalizationMethod Algorithm="{c14n_algorithm}"></CanonicalizationMethod><SignatureMethod Algorithm="{XMLDSIG_ECDSA_SHA256}"></SignatureMethod><Reference URI="{reference_uri}"><Transforms><Transform Algorithm="{XMLDSIG_ENVELOPED_SIGNATURE}"></Transform>{c14n_transform}</Transforms><DigestMethod Algorithm="{XMLDSIG_SHA256}"></DigestMethod><DigestValue>{digest}</DigestValue></Reference></SignedInfo>"#
    )
}
fn signed_info_xml_with_signed_properties_reference(
    c14n_algorithm: &str,
    payload_digest: &str,
    signed_properties_id: &str,
    signed_properties_digest: &str,
) -> String {
    format!(
        concat!(
            r#"<SignedInfo><CanonicalizationMethod Algorithm="{c14n_algorithm}"></CanonicalizationMethod>"#,
            r#"<SignatureMethod Algorithm="{ecdsa_sha256}"></SignatureMethod>"#,
            r#"<Reference URI=""><Transforms><Transform Algorithm="{enveloped_signature}"></Transform></Transforms>"#,
            r#"<DigestMethod Algorithm="{sha256}"></DigestMethod><DigestValue>{payload_digest}</DigestValue></Reference>"#,
            r##"<Reference URI="#{signed_properties_id}" Type="{signed_properties_type}">"##,
            r#"<Transforms><Transform Algorithm="{exclusive_c14n}"></Transform></Transforms>"#,
            r#"<DigestMethod Algorithm="{sha256}"></DigestMethod><DigestValue>{signed_properties_digest}</DigestValue></Reference>"#,
            "</SignedInfo>"
        ),
        c14n_algorithm = c14n_algorithm,
        ecdsa_sha256 = XMLDSIG_ECDSA_SHA256,
        enveloped_signature = XMLDSIG_ENVELOPED_SIGNATURE,
        sha256 = XMLDSIG_SHA256,
        payload_digest = payload_digest,
        signed_properties_id = signed_properties_id,
        signed_properties_type = XADES_SIGNED_PROPERTIES_TYPE,
        exclusive_c14n = XML_EXCLUSIVE_C14N_1_0,
        signed_properties_digest = signed_properties_digest
    )
}
fn signed_info_xml_prefixed(c14n_algorithm: &str, digest: &str) -> String {
    format!(
        r#"<ds:SignedInfo><ds:CanonicalizationMethod Algorithm="{c14n_algorithm}"></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm="{XMLDSIG_ECDSA_SHA256}"></ds:SignatureMethod><ds:Reference URI=""><ds:Transforms><ds:Transform Algorithm="{XMLDSIG_ENVELOPED_SIGNATURE}"></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="{XMLDSIG_SHA256}"></ds:DigestMethod><ds:DigestValue>{digest}</ds:DigestValue></ds:Reference></ds:SignedInfo>"#
    )
}
struct CertificateChainSignedPayload {
    payload: String,
    leaf_sha256: String,
    issuer_sha256: String,
}
#[derive(Clone, Copy)]
enum CertificateChainValidity {
    Valid,
    ExpiredLeaf,
    FutureIssuer,
}
#[derive(Clone, Copy)]
enum CertificateChainIssuerName {
    Matching,
    MismatchedLeafIssuer,
}
#[derive(Clone, Copy)]
enum CertificateChainCriticalUnknownExtension {
    Leaf,
    Issuer,
}
#[derive(Clone, Copy)]
enum CertificateChainCriticalUnsupportedParsedExtension {
    Leaf,
    Issuer,
}
#[derive(Clone, Copy)]
enum CertificatePolicyPathMode {
    Required,
    AnyPolicy,
    Wrong,
    Missing,
}
#[derive(Clone, Copy)]
enum UnsupportedPolicyProcessingExtension {
    PolicyMappings,
    PolicyConstraints,
    InhibitAnyPolicy,
}
#[derive(Clone, Copy)]
enum XmlSignatureValueEncoding {
    Der,
    FixedWidth,
}
fn signed_pacs008_xml_with_certificate_chain() -> CertificateChainSignedPayload {
    signed_pacs008_xml_with_certificate_chain_policy(true, true, true)
}
fn signed_pacs008_xml_with_certificate_chain_policy(
    issuer_is_ca: bool,
    issuer_key_cert_sign: bool,
    leaf_digital_signature: bool,
) -> CertificateChainSignedPayload {
    signed_pacs008_xml_with_certificate_chain_options(
        issuer_is_ca,
        issuer_key_cert_sign,
        leaf_digital_signature,
        CertificateChainValidity::Valid,
        CertificateChainIssuerName::Matching,
        false,
    )
}
fn signed_pacs008_xml_with_certificate_chain_options(
    issuer_is_ca: bool,
    issuer_key_cert_sign: bool,
    leaf_digital_signature: bool,
    validity: CertificateChainValidity,
    issuer_name: CertificateChainIssuerName,
    leaf_is_ca: bool,
) -> CertificateChainSignedPayload {
    let issuer_key = RcgenKeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("issuer key");
    let mut issuer_params =
        CertificateParams::new(vec!["iso-issuer.example".to_owned()]).expect("issuer params");
    issuer_params
        .distinguished_name
        .push(DnType::CommonName, "ISO Bridge Test Issuer");
    issuer_params.is_ca = if issuer_is_ca {
        IsCa::Ca(BasicConstraints::Unconstrained)
    } else {
        IsCa::NoCa
    };
    issuer_params.not_before = match validity {
        CertificateChainValidity::FutureIssuer => date_time_ymd(2027, 1, 1),
        CertificateChainValidity::Valid | CertificateChainValidity::ExpiredLeaf => {
            date_time_ymd(2020, 1, 1)
        }
    };
    issuer_params.not_after = date_time_ymd(2030, 1, 1);
    issuer_params.key_usages = if issuer_key_cert_sign {
        vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
        ]
    } else {
        vec![KeyUsagePurpose::DigitalSignature]
    };
    let issuer_cert = issuer_params
        .self_signed(&issuer_key)
        .expect("issuer certificate");
    let signing_issuer_params = match issuer_name {
        CertificateChainIssuerName::Matching => issuer_params.clone(),
        CertificateChainIssuerName::MismatchedLeafIssuer => {
            let mut params = issuer_params.clone();
            params.distinguished_name = rcgen::DistinguishedName::new();
            params
                .distinguished_name
                .push(DnType::CommonName, "ISO Bridge Mismatched Leaf Issuer");
            params
        }
    };
    let issuer = Issuer::new(signing_issuer_params, issuer_key);
    let leaf_key = RcgenKeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("leaf key");
    let mut leaf_params =
        CertificateParams::new(vec!["iso-leaf.example".to_owned()]).expect("leaf params");
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, "ISO Bridge Test Leaf");
    leaf_params.is_ca = if leaf_is_ca {
        IsCa::Ca(BasicConstraints::Unconstrained)
    } else {
        IsCa::NoCa
    };
    leaf_params.key_usages = if leaf_digital_signature {
        vec![KeyUsagePurpose::DigitalSignature]
    } else {
        vec![KeyUsagePurpose::KeyEncipherment]
    };
    leaf_params.not_before = date_time_ymd(2020, 1, 1);
    leaf_params.not_after = match validity {
        CertificateChainValidity::ExpiredLeaf => date_time_ymd(2024, 1, 1),
        CertificateChainValidity::Valid | CertificateChainValidity::FutureIssuer => {
            date_time_ymd(2030, 1, 1)
        }
    };
    let leaf_cert = leaf_params
        .signed_by(&leaf_key, &issuer)
        .expect("leaf certificate");
    signed_pacs008_xml_with_certificate_chain_material(
        &leaf_key,
        &[leaf_cert.der().as_ref(), issuer_cert.der().as_ref()],
    )
}
fn signed_pacs008_xml_with_policy_intermediate_x509_certificate_chain(
    intermediate_policy: CertificatePolicyPathMode,
) -> CertificateChainSignedPayload {
    signed_pacs008_xml_with_policy_intermediate_x509_certificate_chain_options(
        intermediate_policy,
        None,
    )
}
fn signed_pacs008_xml_with_unsupported_policy_processing_x509_certificate_chain(
    extension: UnsupportedPolicyProcessingExtension,
) -> CertificateChainSignedPayload {
    signed_pacs008_xml_with_policy_intermediate_x509_certificate_chain_options(
        CertificatePolicyPathMode::Required,
        Some(extension),
    )
}
fn signed_pacs008_xml_with_policy_intermediate_x509_certificate_chain_options(
    intermediate_policy: CertificatePolicyPathMode,
    unsupported_policy_processing_extension: Option<UnsupportedPolicyProcessingExtension>,
) -> CertificateChainSignedPayload {
    let root_key = RcgenKeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("root key");
    let mut root_params =
        CertificateParams::new(vec!["iso-root.example".to_owned()]).expect("root params");
    root_params
        .distinguished_name
        .push(DnType::CommonName, "ISO Bridge Policy Path Test Root");
    root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    root_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
    ];
    root_params.not_before = date_time_ymd(2020, 1, 1);
    root_params.not_after = date_time_ymd(2030, 1, 1);
    let root_cert = root_params
        .self_signed(&root_key)
        .expect("root certificate");
    let root = Issuer::new(root_params, root_key);
    let intermediate_key =
        RcgenKeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("intermediate key");
    let mut intermediate_params =
        CertificateParams::new(vec!["iso-intermediate.example".to_owned()])
            .expect("intermediate params");
    intermediate_params.distinguished_name.push(
        DnType::CommonName,
        "ISO Bridge Policy Path Test Intermediate",
    );
    intermediate_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    intermediate_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
    ];
    intermediate_params.not_before = date_time_ymd(2020, 1, 1);
    intermediate_params.not_after = date_time_ymd(2030, 1, 1);
    apply_certificate_policy_extension(&mut intermediate_params, intermediate_policy);
    if let Some(extension) = unsupported_policy_processing_extension {
        intermediate_params
            .custom_extensions
            .push(unsupported_policy_processing_x509_extension(extension));
    }
    let intermediate_cert = intermediate_params
        .signed_by(&intermediate_key, &root)
        .expect("intermediate certificate");
    let intermediate = Issuer::new(intermediate_params, intermediate_key);
    let leaf_key = RcgenKeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("leaf key");
    let mut leaf_params =
        CertificateParams::new(vec!["iso-leaf.example".to_owned()]).expect("leaf params");
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, "ISO Bridge Policy Path Test Leaf");
    leaf_params.is_ca = IsCa::NoCa;
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_params.not_before = date_time_ymd(2020, 1, 1);
    leaf_params.not_after = date_time_ymd(2030, 1, 1);
    apply_certificate_policy_extension(&mut leaf_params, CertificatePolicyPathMode::Required);
    let leaf_cert = leaf_params
        .signed_by(&leaf_key, &intermediate)
        .expect("leaf certificate");
    signed_pacs008_xml_with_certificate_chain_material(
        &leaf_key,
        &[
            leaf_cert.der().as_ref(),
            intermediate_cert.der().as_ref(),
            root_cert.der().as_ref(),
        ],
    )
}
fn apply_certificate_policy_extension(
    params: &mut CertificateParams,
    policy: CertificatePolicyPathMode,
) {
    let policy_arcs = match policy {
        CertificatePolicyPathMode::Required => Some(TEST_X509_POLICY_OID_ARCS),
        CertificatePolicyPathMode::AnyPolicy => Some(X509_ANY_POLICY_OID_ARCS),
        CertificatePolicyPathMode::Wrong => Some(TEST_X509_WRONG_POLICY_OID_ARCS),
        CertificatePolicyPathMode::Missing => None,
    };
    if let Some(policy_arcs) = policy_arcs {
        params
            .custom_extensions
            .push(certificate_policies_x509_extension(&[policy_arcs]));
    }
}
fn signed_pacs008_xml_with_compressed_leaf_certificate_spki() -> CertificateChainSignedPayload {
    let issuer_key = RcgenKeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("issuer key");
    let mut issuer_params =
        CertificateParams::new(vec!["iso-issuer.example".to_owned()]).expect("issuer params");
    issuer_params
        .distinguished_name
        .push(DnType::CommonName, "ISO Bridge Test Issuer");
    issuer_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    issuer_params.not_before = date_time_ymd(2020, 1, 1);
    issuer_params.not_after = date_time_ymd(2030, 1, 1);
    issuer_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
    ];
    let issuer_cert = issuer_params
        .self_signed(&issuer_key)
        .expect("issuer certificate");
    let issuer = Issuer::new(issuer_params, issuer_key);
    let leaf_key = RcgenKeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("leaf key");
    let compressed_leaf_spki = compressed_p256_subject_public_key_info(&leaf_key);
    let mut leaf_params =
        CertificateParams::new(vec!["iso-leaf.example".to_owned()]).expect("leaf params");
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, "ISO Bridge Test Leaf");
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_params.not_before = date_time_ymd(2020, 1, 1);
    leaf_params.not_after = date_time_ymd(2030, 1, 1);
    let leaf_cert = leaf_params
        .signed_by(&compressed_leaf_spki, &issuer)
        .expect("leaf certificate");
    signed_pacs008_xml_with_certificate_chain_material(
        &leaf_key,
        &[leaf_cert.der().as_ref(), issuer_cert.der().as_ref()],
    )
}
fn signed_pacs008_xml_with_compressed_issuer_certificate_spki() -> CertificateChainSignedPayload {
    let issuer_key = RcgenKeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("issuer key");
    let compressed_issuer_spki = compressed_p256_subject_public_key_info(&issuer_key);
    let mut issuer_params =
        CertificateParams::new(vec!["iso-issuer.example".to_owned()]).expect("issuer params");
    issuer_params
        .distinguished_name
        .push(DnType::CommonName, "ISO Bridge Test Issuer");
    issuer_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    issuer_params.not_before = date_time_ymd(2020, 1, 1);
    issuer_params.not_after = date_time_ymd(2030, 1, 1);
    issuer_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
    ];
    let issuer = Issuer::new(issuer_params.clone(), issuer_key);
    let issuer_cert = issuer_params
        .signed_by(&compressed_issuer_spki, &issuer)
        .expect("issuer certificate");
    let leaf_key = RcgenKeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("leaf key");
    let mut leaf_params =
        CertificateParams::new(vec!["iso-leaf.example".to_owned()]).expect("leaf params");
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, "ISO Bridge Test Leaf");
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_params.not_before = date_time_ymd(2020, 1, 1);
    leaf_params.not_after = date_time_ymd(2030, 1, 1);
    let leaf_cert = leaf_params
        .signed_by(&leaf_key, &issuer)
        .expect("leaf certificate");
    signed_pacs008_xml_with_certificate_chain_material(
        &leaf_key,
        &[leaf_cert.der().as_ref(), issuer_cert.der().as_ref()],
    )
}
struct CompressedP256PublicKey {
    bytes: Vec<u8>,
}
impl PublicKeyData for CompressedP256PublicKey {
    fn der_bytes(&self) -> &[u8] {
        &self.bytes
    }
    fn algorithm(&self) -> &'static SignatureAlgorithm {
        &PKCS_ECDSA_P256_SHA256
    }
}
fn compressed_p256_subject_public_key_info(key_pair: &RcgenKeyPair) -> CompressedP256PublicKey {
    let compressed_point = P256VerifyingKey::from_sec1_bytes(key_pair.public_key_raw())
        .expect("rcgen P-256 public key")
        .to_encoded_point(true);
    CompressedP256PublicKey {
        bytes: compressed_point.as_bytes().to_vec(),
    }
}
fn signed_pacs008_xml_with_three_certificate_chain(
    root_path_len: u8,
) -> CertificateChainSignedPayload {
    let root_key = RcgenKeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("root key");
    let mut root_params =
        CertificateParams::new(vec!["iso-root.example".to_owned()]).expect("root params");
    root_params
        .distinguished_name
        .push(DnType::CommonName, "ISO Bridge Test Root");
    root_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(root_path_len));
    root_params.not_before = date_time_ymd(2020, 1, 1);
    root_params.not_after = date_time_ymd(2030, 1, 1);
    root_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
    ];
    let root_cert = root_params
        .self_signed(&root_key)
        .expect("root certificate");
    let root_issuer = Issuer::new(root_params, root_key);
    let intermediate_key =
        RcgenKeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("intermediate key");
    let mut intermediate_params =
        CertificateParams::new(vec!["iso-intermediate.example".to_owned()])
            .expect("intermediate params");
    intermediate_params
        .distinguished_name
        .push(DnType::CommonName, "ISO Bridge Test Intermediate");
    intermediate_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    intermediate_params.not_before = date_time_ymd(2020, 1, 1);
    intermediate_params.not_after = date_time_ymd(2030, 1, 1);
    intermediate_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
    ];
    let intermediate_cert = intermediate_params
        .signed_by(&intermediate_key, &root_issuer)
        .expect("intermediate certificate");
    let intermediate_issuer = Issuer::new(intermediate_params, intermediate_key);
    let leaf_key = RcgenKeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("leaf key");
    let mut leaf_params =
        CertificateParams::new(vec!["iso-leaf.example".to_owned()]).expect("leaf params");
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, "ISO Bridge Test Leaf");
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_params.not_before = date_time_ymd(2020, 1, 1);
    leaf_params.not_after = date_time_ymd(2030, 1, 1);
    let leaf_cert = leaf_params
        .signed_by(&leaf_key, &intermediate_issuer)
        .expect("leaf certificate");
    signed_pacs008_xml_with_certificate_chain_material(
        &leaf_key,
        &[
            leaf_cert.der().as_ref(),
            intermediate_cert.der().as_ref(),
            root_cert.der().as_ref(),
        ],
    )
}
fn signed_pacs008_xml_with_certificate_chain_material(
    leaf_key: &RcgenKeyPair,
    certificates_der: &[&[u8]],
) -> CertificateChainSignedPayload {
    signed_pacs008_xml_with_certificate_chain_material_and_x509_extra(
        leaf_key,
        certificates_der,
        "",
        XML_SIGNATURE_TEST_SIGNING_TIME,
    )
}
fn signed_pacs008_xml_with_certificate_chain_material_and_x509_extra(
    leaf_key: &RcgenKeyPair,
    certificates_der: &[&[u8]],
    extra_x509_data_xml: &str,
    signing_time: &str,
) -> CertificateChainSignedPayload {
    let unsigned = unsigned_pacs008_xml();
    let insertion = unsigned
        .find("</FIToFICstmrCdtTrf>")
        .expect("signature insertion point");
    let canonical_unsigned = canonicalize_supported_xml(&unsigned).expect("canonical payload");
    let payload_digest = BASE64_STANDARD.encode(Sha256::digest(canonical_unsigned.as_bytes()));
    let signed_properties_id = "signed-props-001";
    let (signed_properties, _) = signed_properties_xml_with_signing_certificate_v2_at(
        signed_properties_id,
        certificates_der[0],
        signing_time,
    );
    let canonical_signed_properties =
        canonicalize_supported_xml(&signed_properties).expect("canonical SignedProperties");
    let signed_properties_digest =
        BASE64_STANDARD.encode(Sha256::digest(canonical_signed_properties.as_bytes()));
    let signed_info = signed_info_xml_with_signed_properties_reference(
        XML_C14N_1_0,
        &payload_digest,
        signed_properties_id,
        &signed_properties_digest,
    );
    let canonical_signed_info =
        canonicalize_xmlsig_signed_info(&signed_info, CanonicalXmlMode::Inclusive);
    let signature = leaf_key
        .sign(canonical_signed_info.as_bytes())
        .expect("leaf XMLDSig signature");
    let signature_value = BASE64_STANDARD.encode(low_s_p256_signature_der_from_bytes(&signature));
    let certificates_xml = certificates_der
        .iter()
        .map(|certificate_der| {
            format!(
                "<X509Certificate>{}</X509Certificate>",
                BASE64_STANDARD.encode(certificate_der)
            )
        })
        .collect::<String>();
    let signature_xml = format!(
        concat!(
            r#"<Signature xmlns="{XMLDSIG_NS}" Id="sig-001">{signed_info}<SignatureValue>{signature_value}</SignatureValue>"#,
            "<KeyInfo><X509Data>",
            "{certificates_xml}",
            "{extra_x509_data_xml}",
            "</X509Data></KeyInfo>",
            r##"<Object><QualifyingProperties xmlns="{XADES_NS}" Target="#sig-001">"##,
            "{signed_properties}",
            "</QualifyingProperties></Object>",
            "</Signature>"
        ),
        signed_info = signed_info,
        signature_value = signature_value,
        certificates_xml = certificates_xml,
        extra_x509_data_xml = extra_x509_data_xml,
        signed_properties = signed_properties,
        XMLDSIG_NS = XMLDSIG_NS,
        XADES_NS = XADES_NS
    );
    CertificateChainSignedPayload {
        payload: format!(
            "{}{}{}",
            &unsigned[..insertion],
            signature_xml,
            &unsigned[insertion..]
        ),
        leaf_sha256: sha256_hex(certificates_der[0]),
        issuer_sha256: sha256_hex(certificates_der[certificates_der.len() - 1]),
    }
}
#[derive(Clone, Copy)]
enum TestOcspResponseStatus {
    Good,
    Revoked,
}
struct GeneratedOcspSignedPayload {
    payload: String,
    trust_anchor_pin: String,
    response_der_base64: String,
}
fn signed_pacs008_xml_with_generated_ocsp_x509_certificate_chain(
    response_status: TestOcspResponseStatus,
    embed_ocsp_response: bool,
    signing_time: &str,
) -> GeneratedOcspSignedPayload {
    for _ in 0..128 {
        if let Some(payload) = try_signed_pacs008_xml_with_generated_ocsp_x509_certificate_chain(
            response_status,
            embed_ocsp_response,
            signing_time,
        ) {
            return payload;
        }
    }
    panic!("generated OCSP X.509 fixture must satisfy low-S certificate signature policy")
}
fn try_signed_pacs008_xml_with_generated_ocsp_x509_certificate_chain(
    response_status: TestOcspResponseStatus,
    embed_ocsp_response: bool,
    signing_time: &str,
) -> Option<GeneratedOcspSignedPayload> {
    let issuer_key = RcgenKeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("issuer key");
    let mut issuer_params =
        CertificateParams::new(vec!["ocsp-issuer.example".to_owned()]).expect("issuer params");
    issuer_params
        .distinguished_name
        .push(DnType::CommonName, "ISO Bridge Generated OCSP Issuer");
    issuer_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    issuer_params.not_before = date_time_ymd(2020, 1, 1);
    issuer_params.not_after = date_time_ymd(2030, 1, 1);
    issuer_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
    ];
    let issuer_cert = issuer_params
        .self_signed(&issuer_key)
        .expect("issuer certificate");
    let issuer = Issuer::new(issuer_params, issuer_key);
    let leaf_key = RcgenKeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("leaf key");
    let mut leaf_params =
        CertificateParams::new(vec!["ocsp-leaf.example".to_owned()]).expect("leaf params");
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, "ISO Bridge Generated OCSP Leaf");
    leaf_params.is_ca = IsCa::NoCa;
    leaf_params.not_before = date_time_ymd(2020, 1, 1);
    leaf_params.not_after = date_time_ymd(2030, 1, 1);
    leaf_params
        .custom_extensions
        .push(critical_key_usage_digital_signature_extension());
    let leaf_cert = leaf_params
        .signed_by(&leaf_key, &issuer)
        .expect("leaf certificate");
    if !generated_x509_certificate_signatures_are_accepted(
        leaf_cert.der().as_ref(),
        issuer_cert.der().as_ref(),
        None,
    ) {
        return None;
    }
    let response_der = test_ocsp_response_der(
        leaf_cert.der().as_ref(),
        issuer_cert.der().as_ref(),
        issuer_cert.der().as_ref(),
        issuer.key(),
        response_status,
        None,
    );
    let response_der_base64 = BASE64_STANDARD.encode(&response_der);
    let extra_x509_data_xml = embed_ocsp_response
        .then(|| format!("<EncapsulatedOCSPValue>{response_der_base64}</EncapsulatedOCSPValue>"))
        .unwrap_or_default();
    let certificates_der = [leaf_cert.der().as_ref(), issuer_cert.der().as_ref()];
    let signed_payload = signed_pacs008_xml_with_certificate_chain_material_and_x509_extra(
        &leaf_key,
        &certificates_der,
        &extra_x509_data_xml,
        signing_time,
    );
    Some(GeneratedOcspSignedPayload {
        payload: signed_payload.payload,
        trust_anchor_pin: signed_payload.issuer_sha256,
        response_der_base64,
    })
}
fn signed_pacs008_xml_with_generated_delegated_ocsp_x509_certificate_chain(
    include_responder_certificate: bool,
) -> GeneratedOcspSignedPayload {
    for _ in 0..128 {
        if let Some(payload) =
            try_signed_pacs008_xml_with_generated_delegated_ocsp_x509_certificate_chain(
                include_responder_certificate,
            )
        {
            return payload;
        }
    }
    panic!("generated delegated OCSP X.509 fixture must satisfy low-S certificate signature policy")
}
fn try_signed_pacs008_xml_with_generated_delegated_ocsp_x509_certificate_chain(
    include_responder_certificate: bool,
) -> Option<GeneratedOcspSignedPayload> {
    let issuer_key = RcgenKeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("issuer key");
    let mut issuer_params =
        CertificateParams::new(vec!["delegated-ocsp-issuer.example".to_owned()])
            .expect("issuer params");
    issuer_params.distinguished_name.push(
        DnType::CommonName,
        "ISO Bridge Generated Delegated OCSP Issuer",
    );
    issuer_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    issuer_params.not_before = date_time_ymd(2020, 1, 1);
    issuer_params.not_after = date_time_ymd(2030, 1, 1);
    issuer_params
        .custom_extensions
        .push(critical_key_usage_digital_signature_key_cert_sign_extension());
    let issuer_cert = issuer_params
        .self_signed(&issuer_key)
        .expect("issuer certificate");
    let issuer = Issuer::new(issuer_params, issuer_key);
    let leaf_key = RcgenKeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("leaf key");
    let mut leaf_params = CertificateParams::new(vec!["delegated-ocsp-leaf.example".to_owned()])
        .expect("leaf params");
    leaf_params.distinguished_name.push(
        DnType::CommonName,
        "ISO Bridge Generated Delegated OCSP Leaf",
    );
    leaf_params.is_ca = IsCa::NoCa;
    leaf_params.not_before = date_time_ymd(2020, 1, 1);
    leaf_params.not_after = date_time_ymd(2030, 1, 1);
    leaf_params
        .custom_extensions
        .push(critical_key_usage_digital_signature_extension());
    let leaf_cert = leaf_params
        .signed_by(&leaf_key, &issuer)
        .expect("leaf certificate");
    let responder_key = RcgenKeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("responder key");
    let mut responder_params =
        CertificateParams::new(vec!["delegated-ocsp-responder.example".to_owned()])
            .expect("responder params");
    responder_params.distinguished_name.push(
        DnType::CommonName,
        "ISO Bridge Generated Delegated OCSP Responder",
    );
    responder_params.is_ca = IsCa::NoCa;
    responder_params.not_before = date_time_ymd(2020, 1, 1);
    responder_params.not_after = date_time_ymd(2030, 1, 1);
    responder_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::OcspSigning];
    responder_params
        .custom_extensions
        .push(critical_key_usage_digital_signature_extension());
    let responder_cert = responder_params
        .signed_by(&responder_key, &issuer)
        .expect("responder certificate");
    if !generated_x509_certificate_signatures_are_accepted(
        leaf_cert.der().as_ref(),
        issuer_cert.der().as_ref(),
        Some(responder_cert.der().as_ref()),
    ) {
        return None;
    }
    let response_der = test_ocsp_response_der(
        leaf_cert.der().as_ref(),
        issuer_cert.der().as_ref(),
        responder_cert.der().as_ref(),
        &responder_key,
        TestOcspResponseStatus::Good,
        include_responder_certificate.then(|| responder_cert.der().as_ref()),
    );
    let response_der_base64 = BASE64_STANDARD.encode(&response_der);
    let certificates_der = [leaf_cert.der().as_ref(), issuer_cert.der().as_ref()];
    let signed_payload = signed_pacs008_xml_with_certificate_chain_material_and_x509_extra(
        &leaf_key,
        &certificates_der,
        "",
        XML_SIGNATURE_TEST_SIGNING_TIME,
    );
    Some(GeneratedOcspSignedPayload {
        payload: signed_payload.payload,
        trust_anchor_pin: signed_payload.issuer_sha256,
        response_der_base64,
    })
}
fn generated_x509_certificate_signatures_are_accepted(
    leaf_der: &[u8],
    issuer_der: &[u8],
    responder_der: Option<&[u8]>,
) -> bool {
    let Ok(leaf) = parse_x509_certificate_der(leaf_der) else {
        return false;
    };
    let Ok(issuer) = parse_x509_certificate_der(issuer_der) else {
        return false;
    };
    if verify_x509_certificate_signature(&leaf, &issuer).is_err()
        || verify_x509_certificate_signature(&issuer, &issuer).is_err()
    {
        return false;
    }
    if let Some(responder_der) = responder_der {
        let Ok(responder) = parse_x509_certificate_der(responder_der) else {
            return false;
        };
        return verify_x509_certificate_signature(&responder, &issuer).is_ok();
    }
    true
}
fn test_ocsp_response_der(
    leaf_der: &[u8],
    issuer_der: &[u8],
    responder_der: &[u8],
    signer_key: &RcgenKeyPair,
    status: TestOcspResponseStatus,
    responder_certificate_der: Option<&[u8]>,
) -> Vec<u8> {
    let leaf = parse_x509_certificate_der(leaf_der).expect("leaf certificate DER");
    let issuer = parse_x509_certificate_der(issuer_der).expect("issuer certificate DER");
    let responder = parse_x509_certificate_der(responder_der).expect("responder certificate DER");
    let mut single_response = test_ocsp_cert_id_der(&leaf, &issuer);
    single_response.extend(test_ocsp_cert_status_der(status));
    single_response.extend(der_tlv(0x18, b"20260601141606Z".to_vec()));
    single_response.extend(der_tlv(0xA0, der_tlv(0x18, b"21260508141606Z".to_vec())));
    let single_response = der_sequence(single_response);
    let mut response_data = Vec::new();
    response_data.extend(der_tlv(0xA1, responder.subject().as_raw().to_vec()));
    response_data.extend(der_tlv(0x18, b"20260601141606Z".to_vec()));
    response_data.extend(der_sequence(single_response));
    let tbs_response_data = der_sequence(response_data);
    let signature = signer_key
        .sign(&tbs_response_data)
        .expect("OCSP response signature");
    let signature = low_s_p256_signature_der_from_bytes(&signature);
    let mut signature_bits = vec![0];
    signature_bits.extend(signature);
    let mut basic_response = tbs_response_data.clone();
    basic_response.extend(der_sequence(der_tlv(
        0x06,
        OID_ECDSA_WITH_SHA256_DER.to_vec(),
    )));
    basic_response.extend(der_tlv(0x03, signature_bits));
    if let Some(certificate_der) = responder_certificate_der {
        basic_response.extend(der_tlv(0xA0, der_sequence(certificate_der.to_vec())));
    }
    let basic_response = der_sequence(basic_response);
    let mut response_bytes = Vec::new();
    response_bytes.extend(der_tlv(0x06, OID_OCSP_BASIC_RESPONSE_DER.to_vec()));
    response_bytes.extend(der_tlv(0x04, basic_response));
    let response_bytes = der_sequence(response_bytes);
    let mut ocsp_response = Vec::new();
    ocsp_response.extend(der_tlv(0x0A, vec![0]));
    ocsp_response.extend(der_tlv(0xA0, response_bytes));
    der_sequence(ocsp_response)
}
fn test_ocsp_cert_id_der(leaf: &X509Certificate<'_>, issuer: &X509Certificate<'_>) -> Vec<u8> {
    let issuer_name_hash = Sha256::digest(issuer.subject().as_raw());
    let issuer_key_hash = Sha256::digest(issuer.public_key().subject_public_key.data.as_ref());
    let mut cert_id = Vec::new();
    cert_id.extend(der_sequence(der_tlv(0x06, OID_SHA256_DER.to_vec())));
    cert_id.extend(der_tlv(0x04, issuer_name_hash.to_vec()));
    cert_id.extend(der_tlv(0x04, issuer_key_hash.to_vec()));
    cert_id.extend(der_tlv(0x02, leaf.raw_serial().to_vec()));
    der_sequence(cert_id)
}
fn test_ocsp_cert_status_der(status: TestOcspResponseStatus) -> Vec<u8> {
    match status {
        TestOcspResponseStatus::Good => der_tlv(0x80, Vec::new()),
        TestOcspResponseStatus::Revoked => {
            der_tlv(0xA1, der_tlv(0x18, b"20260601000000Z".to_vec()))
        }
    }
}
fn test_fixture_text(template: &str) -> &str {
    template.strip_suffix('\n').unwrap_or(template)
}
fn render_test_template(template: &str, replacements: &[(&str, &str)]) -> String {
    let mut rendered = test_fixture_text(template).to_owned();
    for (placeholder, value) in replacements {
        rendered = rendered.replace(placeholder, value);
    }
    rendered
}
fn swift_pacs008_xml(business_message_id: &str, uetr: &str) -> String {
    render_test_template(
        include_str!(r"../../../fixtures/iso20022/swift_pacs008_test_template.xml"),
        &[
            ("{business_message_id}", business_message_id),
            ("{uetr}", uetr),
        ],
    )
}
fn live_pacs008_xml(
    business_message_id: &str,
    msg_def_id: &str,
    business_service: &str,
    currency: &str,
    amount: &str,
    uetr: &str,
) -> String {
    render_test_template(
        include_str!(r"../../../fixtures/iso20022/live_pacs008_test_template.xml"),
        &[
            ("{business_message_id}", business_message_id),
            ("{msg_def_id}", msg_def_id),
            ("{business_service}", business_service),
            ("{currency}", currency),
            ("{amount}", amount),
            ("{uetr}", uetr),
        ],
    )
}
fn live_fedwire_pacs008_xml(business_message_id: &str, uetr: &str) -> String {
    live_pacs008_xml(
        business_message_id,
        "pacs.008.001.08",
        "fedwire.funds.01",
        "USD",
        "10.00",
        uetr,
    )
}
fn live_pacs002_xml(business_message_id: &str, msg_def_id: &str, business_service: &str) -> String {
    render_test_template(
        include_str!(r"../../../fixtures/iso20022/live_pacs002_test_template.xml"),
        &[
            ("{business_message_id}", business_message_id),
            ("{msg_def_id}", msg_def_id),
            ("{business_service}", business_service),
        ],
    )
}
fn live_pacs004_xml(business_message_id: &str, msg_def_id: &str, business_service: &str) -> String {
    render_test_template(
        include_str!(r"../../../fixtures/iso20022/live_pacs004_test_template.xml"),
        &[
            ("{business_message_id}", business_message_id),
            ("{msg_def_id}", msg_def_id),
            ("{business_service}", business_service),
        ],
    )
}
fn live_camt056_xml(business_message_id: &str, msg_def_id: &str, business_service: &str) -> String {
    render_test_template(
        include_str!(r"../../../fixtures/iso20022/live_camt056_test_template.xml"),
        &[
            ("{business_message_id}", business_message_id),
            ("{msg_def_id}", msg_def_id),
            ("{business_service}", business_service),
        ],
    )
}
fn xsd_tag_with_attr<'a>(
    xsd: &'a str,
    tag_name: &str,
    attr_name: &str,
    expected_value: &str,
) -> Option<&'a str> {
    let pattern = format!("<{tag_name}");
    let mut rest = xsd;
    while let Some(offset) = rest.find(&pattern) {
        let candidate = &rest[offset..];
        let end = candidate.find('>')?;
        let tag = &candidate[..=end];
        if attr_value(tag, attr_name).as_deref() == Some(expected_value) {
            return Some(tag);
        }
        rest = candidate.get(end + 1..)?;
    }
    None
}
fn xsd_schema_target_namespace(xsd: &str) -> Option<String> {
    let schema_start = xsd.find("<xs:schema")?;
    let schema = &xsd[schema_start..];
    let schema_end = schema.find('>')?;
    attr_value(&schema[..=schema_end], "targetNamespace")
}
fn xsd_document_payload_root(xsd: &str) -> Option<String> {
    let document_tag = xsd_tag_with_attr(xsd, "xs:element", "name", "Document")?;
    let document_type = attr_value(document_tag, "type")?;
    let document_type_tag = xsd_tag_with_attr(xsd, "xs:complexType", "name", &document_type)?;
    let document_type_start = xsd.find(document_type_tag)?;
    let document_type_body = &xsd[document_type_start + document_type_tag.len()..];
    let sequence_start = document_type_body.find("<xs:sequence")?;
    let sequence = &document_type_body[sequence_start..];
    let element_start = sequence.find("<xs:element")?;
    let element = &sequence[element_start..];
    let element_end = element.find('>')?;
    attr_value(&element[..=element_end], "name")
}
fn live_pacs009_xml(business_message_id: &str, msg_def_id: &str, business_service: &str) -> String {
    render_test_template(
        include_str!(r"../../../fixtures/iso20022/live_pacs009_test_template.xml"),
        &[
            ("{business_message_id}", business_message_id),
            ("{msg_def_id}", msg_def_id),
            ("{business_service}", business_service),
        ],
    )
}
fn remove_xml_element(payload: &str, tag: &str) -> String {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = payload
        .find(&open)
        .unwrap_or_else(|| panic!("fixture must contain <{tag}>"));
    let close_start = payload[start..]
        .find(&close)
        .map(|offset| start + offset)
        .unwrap_or_else(|| panic!("fixture must contain </{tag}>"));
    let end = close_start + close.len();
    let mut stripped = payload.to_owned();
    stripped.replace_range(start..end, "");
    stripped
}
fn data_pdu_with_app_header(
    business_message_id: &str,
    msg_def_id: &str,
    business_service: &str,
    document: &str,
) -> String {
    format!(
        r#"<DataPDU>
  <AppHdr xmlns="urn:iso:std:iso:20022:tech:xsd:head.001.001.01">
    <BizMsgIdr>{business_message_id}</BizMsgIdr>
    <MsgDefIdr>{msg_def_id}</MsgDefIdr>
    <BizSvc>{business_service}</BizSvc>
    <CreDt>2025-01-01T12:00:00Z</CreDt>
  </AppHdr>
{document}
</DataPDU>"#
    )
}
fn sample_config_with_live_reference_data() -> (actual::IsoBridge, Vec<NamedTempFile>) {
    let asset_definition_id = sample_asset_definition_literal();
    let bic_lei = write_snapshot(test_fixture_text(include_str!(
        r"../../../fixtures/iso20022/live_bic_lei_test_reference.json"
    )));
    let isin_crosswalk = write_snapshot(&render_test_template(
        include_str!(r"../../../fixtures/iso20022/live_isin_crosswalk_test_template.json"),
        &[("{asset_definition_id}", &asset_definition_id)],
    ));
    let mic_directory = write_snapshot(test_fixture_text(include_str!(
        r"../../../fixtures/iso20022/live_mic_directory_test_reference.json"
    )));
    let csd_venue = write_snapshot(test_fixture_text(include_str!(
        r"../../../fixtures/iso20022/live_csd_venue_test_reference.json"
    )));
    let delivery_account_id = sample_account_bundle().1;
    let receiving_account_id = sample_account_bundle().1;
    let securities_account = write_snapshot(&render_test_template(
        include_str!(r"../../../fixtures/iso20022/live_securities_account_test_template.json"),
        &[
            ("{delivery_account_id}", &delivery_account_id),
            ("{receiving_account_id}", &receiving_account_id),
        ],
    ));
    let cash_leg = write_snapshot(&render_test_template(
        include_str!(r"../../../fixtures/iso20022/live_cash_leg_test_template.json"),
        &[("{asset_definition_id}", &asset_definition_id)],
    ));
    let mut config = sample_config();
    config.currency_assets.push(actual::IsoCurrencyAsset {
        currency: "EUR".to_owned(),
        asset_definition: asset_definition_id.clone(),
        max_amount: Quantity::from(10_000_u64),
    });
    config.reference_data.bic_lei_path = Some(bic_lei.path().to_path_buf());
    config.reference_data.isin_crosswalk_path = Some(isin_crosswalk.path().to_path_buf());
    config.reference_data.mic_directory_path = Some(mic_directory.path().to_path_buf());
    config.reference_data.csd_venue_path = Some(csd_venue.path().to_path_buf());
    config.reference_data.securities_account_path = Some(securities_account.path().to_path_buf());
    config.reference_data.cash_leg_path = Some(cash_leg.path().to_path_buf());
    (
        config,
        vec![
            bic_lei,
            isin_crosswalk,
            mic_directory,
            csd_venue,
            securities_account,
            cash_leg,
        ],
    )
}
fn sample_runtime() -> Iso20022BridgeRuntime {
    Iso20022BridgeRuntime::from_config(&sample_config())
        .expect("cfg")
        .expect("enabled")
}
fn runtime_with_live_reference_data() -> (Iso20022BridgeRuntime, Vec<NamedTempFile>) {
    let (config, reference_files) = sample_config_with_live_reference_data();
    let runtime = Iso20022BridgeRuntime::from_config(&config)
        .expect("cfg")
        .expect("enabled");
    (runtime, reference_files)
}
fn inbound_metadata(message_id: &str, message_type: &str) -> IsoMessageMetadata {
    IsoMessageMetadata::inbound(
        "generic-iso20022",
        message_type,
        None,
        Some(format!("{message_id}-biz")),
        None,
        format!("{message_id}-payload-hash"),
        "snapshot".to_owned(),
        false,
    )
}
fn record_original(runtime: &Iso20022BridgeRuntime, message_id: &str, message_type: &str) {
    assert!(
        runtime.check_and_record_inbound(message_id, inbound_metadata(message_id, message_type)),
        "record original {message_id}"
    );
}
fn record_lifecycle(runtime: &Iso20022BridgeRuntime, message_id: &str, message_type: &str) {
    let metadata = inbound_metadata(message_id, message_type);
    let mut parties = runtime.compatibility_test_parties(&metadata);
    if message_type == "pacs.004" {
        parties.admitting_participant_id = parties.counterparty_participant_id.clone();
        parties.admitting_operator_key = runtime
            .participants_by_key
            .iter()
            .find(|(_, participant)| participant.id == parties.counterparty_participant_id)
            .expect("configured return counterparty")
            .0
            .to_string();
    }
    assert!(
        runtime
            .admit_inbound(message_id, metadata, parties, false)
            .is_ok(),
        "record lifecycle {message_id}"
    );
}

fn signed_pacs008_xml_with_certificate_chain_issuer_name_mismatch() -> CertificateChainSignedPayload
{
    signed_pacs008_xml_with_certificate_chain_options(
        true,
        true,
        true,
        CertificateChainValidity::Valid,
        CertificateChainIssuerName::MismatchedLeafIssuer,
        false,
    )
}
fn signed_pacs008_xml_with_leaf_ca_certificate_chain() -> CertificateChainSignedPayload {
    signed_pacs008_xml_with_certificate_chain_options(
        true,
        true,
        true,
        CertificateChainValidity::Valid,
        CertificateChainIssuerName::Matching,
        true,
    )
}
fn signed_pacs008_xml_with_generated_two_certificate_chain(
    issuer_algorithm: &'static SignatureAlgorithm,
    configure_issuer: impl FnOnce(&mut CertificateParams),
    configure_leaf: impl FnOnce(&mut CertificateParams),
) -> CertificateChainSignedPayload {
    let issuer_key = RcgenKeyPair::generate_for(issuer_algorithm).expect("issuer key");
    let mut issuer_params =
        CertificateParams::new(vec!["iso-issuer.example".to_owned()]).expect("issuer params");
    issuer_params
        .distinguished_name
        .push(DnType::CommonName, "ISO Bridge Test Issuer");
    issuer_params.not_before = date_time_ymd(2020, 1, 1);
    issuer_params.not_after = date_time_ymd(2030, 1, 1);
    configure_issuer(&mut issuer_params);
    let issuer_cert = issuer_params
        .self_signed(&issuer_key)
        .expect("issuer certificate");
    let issuer = Issuer::new(issuer_params, issuer_key);
    let leaf_key = RcgenKeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("leaf key");
    let mut leaf_params =
        CertificateParams::new(vec!["iso-leaf.example".to_owned()]).expect("leaf params");
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, "ISO Bridge Test Leaf");
    leaf_params.not_before = date_time_ymd(2020, 1, 1);
    leaf_params.not_after = date_time_ymd(2030, 1, 1);
    configure_leaf(&mut leaf_params);
    let leaf_cert = leaf_params
        .signed_by(&leaf_key, &issuer)
        .expect("leaf certificate");
    signed_pacs008_xml_with_certificate_chain_material(
        &leaf_key,
        &[leaf_cert.der().as_ref(), issuer_cert.der().as_ref()],
    )
}
fn signed_pacs008_xml_with_certificate_chain_noncritical_issuer_basic_constraints()
-> CertificateChainSignedPayload {
    signed_pacs008_xml_with_generated_two_certificate_chain(
        &PKCS_ECDSA_P256_SHA256,
        |issuer| {
            issuer.key_usages = vec![
                KeyUsagePurpose::DigitalSignature,
                KeyUsagePurpose::KeyCertSign,
            ];
            issuer
                .custom_extensions
                .push(noncritical_basic_constraints_ca_extension());
        },
        |leaf| leaf.key_usages = vec![KeyUsagePurpose::DigitalSignature],
    )
}
fn signed_pacs008_xml_with_certificate_chain_noncritical_issuer_key_usage()
-> CertificateChainSignedPayload {
    signed_pacs008_xml_with_generated_two_certificate_chain(
        &PKCS_ECDSA_P256_SHA256,
        |issuer| {
            issuer.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            issuer
                .custom_extensions
                .push(noncritical_key_usage_digital_signature_key_cert_sign_extension());
        },
        |leaf| leaf.key_usages = vec![KeyUsagePurpose::DigitalSignature],
    )
}
fn signed_pacs008_xml_with_p384_issuer_certificate_chain() -> CertificateChainSignedPayload {
    signed_pacs008_xml_with_generated_two_certificate_chain(
        &PKCS_ECDSA_P384_SHA384,
        |issuer| {
            issuer.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            issuer.key_usages = vec![
                KeyUsagePurpose::DigitalSignature,
                KeyUsagePurpose::KeyCertSign,
            ];
        },
        |leaf| leaf.key_usages = vec![KeyUsagePurpose::DigitalSignature],
    )
}
fn signed_pacs008_xml_with_certificate_chain_noncritical_leaf_key_usage()
-> CertificateChainSignedPayload {
    signed_pacs008_xml_with_generated_two_certificate_chain(
        &PKCS_ECDSA_P256_SHA256,
        |issuer| {
            issuer.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            issuer.key_usages = vec![
                KeyUsagePurpose::DigitalSignature,
                KeyUsagePurpose::KeyCertSign,
            ];
        },
        |leaf| {
            leaf.custom_extensions
                .push(noncritical_key_usage_digital_signature_extension());
        },
    )
}
fn signed_pacs008_xml_with_certificate_chain_critical_unknown_extension(
    target: CertificateChainCriticalUnknownExtension,
) -> CertificateChainSignedPayload {
    signed_pacs008_xml_with_generated_two_certificate_chain(
        &PKCS_ECDSA_P256_SHA256,
        |issuer| {
            issuer.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            issuer.key_usages = vec![
                KeyUsagePurpose::DigitalSignature,
                KeyUsagePurpose::KeyCertSign,
            ];
            if matches!(target, CertificateChainCriticalUnknownExtension::Issuer) {
                issuer
                    .custom_extensions
                    .push(critical_unknown_x509_extension());
            }
        },
        |leaf| {
            leaf.key_usages = vec![KeyUsagePurpose::DigitalSignature];
            if matches!(target, CertificateChainCriticalUnknownExtension::Leaf) {
                leaf.custom_extensions
                    .push(critical_unknown_x509_extension());
            }
        },
    )
}
fn signed_pacs008_xml_with_certificate_chain_critical_unsupported_parsed_extension(
    target: CertificateChainCriticalUnsupportedParsedExtension,
) -> CertificateChainSignedPayload {
    signed_pacs008_xml_with_generated_two_certificate_chain(
        &PKCS_ECDSA_P256_SHA256,
        |issuer| {
            issuer.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            issuer.key_usages = vec![
                KeyUsagePurpose::DigitalSignature,
                KeyUsagePurpose::KeyCertSign,
            ];
            if matches!(
                target,
                CertificateChainCriticalUnsupportedParsedExtension::Issuer
            ) {
                issuer
                    .custom_extensions
                    .push(critical_extended_key_usage_x509_extension());
            }
        },
        |leaf| {
            leaf.key_usages = vec![KeyUsagePurpose::DigitalSignature];
            if matches!(
                target,
                CertificateChainCriticalUnsupportedParsedExtension::Leaf
            ) {
                leaf.custom_extensions
                    .push(critical_extended_key_usage_x509_extension());
            }
        },
    )
}
fn critical_unknown_x509_extension() -> CustomExtension {
    let mut extension =
        CustomExtension::from_oid_content(&[1, 3, 6, 1, 4, 1, 55555, 42], vec![0x05, 0x00]);
    extension.set_criticality(true);
    extension
}
fn critical_extended_key_usage_x509_extension() -> CustomExtension {
    let mut extension = CustomExtension::from_oid_content(
        &[2, 5, 29, 37],
        vec![
            0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01,
        ],
    );
    extension.set_criticality(true);
    extension
}
fn certificate_policies_x509_extension(policy_oids: &[&[u64]]) -> CustomExtension {
    let mut policies = Vec::new();
    for policy_oid in policy_oids {
        policies.extend(der_sequence(der_oid(policy_oid)));
    }
    CustomExtension::from_oid_content(&[2, 5, 29, 32], der_sequence(policies))
}
fn unsupported_policy_processing_x509_extension(
    extension: UnsupportedPolicyProcessingExtension,
) -> CustomExtension {
    match extension {
        UnsupportedPolicyProcessingExtension::PolicyMappings => {
            let mut mapping = Vec::new();
            mapping.extend(der_oid(TEST_X509_POLICY_OID_ARCS));
            mapping.extend(der_oid(TEST_X509_WRONG_POLICY_OID_ARCS));
            CustomExtension::from_oid_content(&[2, 5, 29, 33], der_sequence(der_sequence(mapping)))
        }
        UnsupportedPolicyProcessingExtension::PolicyConstraints => {
            CustomExtension::from_oid_content(&[2, 5, 29, 36], vec![0x30, 0x03, 0x80, 0x01, 0x00])
        }
        UnsupportedPolicyProcessingExtension::InhibitAnyPolicy => {
            CustomExtension::from_oid_content(&[2, 5, 29, 54], vec![0x02, 0x01, 0x00])
        }
    }
}
fn der_oid(arcs: &[u64]) -> Vec<u8> {
    assert!(
        arcs.len() >= 2,
        "OID fixtures must include at least two arcs"
    );
    assert!(
        arcs[0] <= 2,
        "OID first arc must fit DER object identifier rules"
    );
    assert!(
        arcs[0] == 2 || arcs[1] < 40,
        "OID second arc must fit DER object identifier rules"
    );
    let mut encoded = Vec::new();
    append_der_oid_arc(&mut encoded, arcs[0] * 40 + arcs[1]);
    for arc in &arcs[2..] {
        append_der_oid_arc(&mut encoded, *arc);
    }
    der_tlv(0x06, encoded)
}
fn append_der_oid_arc(out: &mut Vec<u8>, arc: u64) {
    let mut bytes = vec![(arc & 0x7f) as u8];
    let mut remaining = arc >> 7;
    while remaining > 0 {
        bytes.push(((remaining & 0x7f) as u8) | 0x80);
        remaining >>= 7;
    }
    out.extend(bytes.into_iter().rev());
}
fn der_sequence(content: Vec<u8>) -> Vec<u8> {
    der_tlv(0x30, content)
}
fn der_tlv(tag: u8, content: Vec<u8>) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend(der_length(content.len()));
    out.extend(content);
    out
}
fn der_length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        return vec![len as u8];
    }
    let mut bytes = Vec::new();
    let mut remaining = len;
    while remaining > 0 {
        bytes.push((remaining & 0xff) as u8);
        remaining >>= 8;
    }
    bytes.reverse();
    let mut out = vec![0x80 | bytes.len() as u8];
    out.extend(bytes);
    out
}
fn noncritical_basic_constraints_ca_extension() -> CustomExtension {
    CustomExtension::from_oid_content(&[2, 5, 29, 19], vec![0x30, 0x03, 0x01, 0x01, 0xff])
}
fn noncritical_key_usage_digital_signature_key_cert_sign_extension() -> CustomExtension {
    CustomExtension::from_oid_content(&[2, 5, 29, 15], vec![0x03, 0x02, 0x02, 0x84])
}
fn critical_key_usage_digital_signature_key_cert_sign_extension() -> CustomExtension {
    let mut extension =
        CustomExtension::from_oid_content(&[2, 5, 29, 15], vec![0x03, 0x02, 0x02, 0x84]);
    extension.set_criticality(true);
    extension
}
fn noncritical_key_usage_digital_signature_extension() -> CustomExtension {
    CustomExtension::from_oid_content(&[2, 5, 29, 15], vec![0x03, 0x02, 0x07, 0x80])
}
fn critical_key_usage_digital_signature_extension() -> CustomExtension {
    let mut extension =
        CustomExtension::from_oid_content(&[2, 5, 29, 15], vec![0x03, 0x02, 0x07, 0x80]);
    extension.set_criticality(true);
    extension
}
fn validate_require_verified_signed_payload(
    payload: &str,
    configure_profile: impl FnOnce(&mut actual::IsoBridgeProfile),
) -> Result<IsoMessageMetadata, MsgError> {
    let mut config = sample_config();
    let mut profile = signed_message_profile("require-verified");
    configure_profile(&mut profile);
    config.profiles.push(profile);
    let runtime = Iso20022BridgeRuntime::from_config(&config)
        .expect("cfg")
        .expect("enabled");
    let parsed = parse_xml_message("pacs.008", payload.as_bytes())?;
    let profile = runtime
        .resolve_profile(Some("signed-pacs008-test"))
        .expect("signed profile");
    runtime.validate_profile_submission(profile, "pacs.008", &parsed, payload.as_bytes())
}
fn assert_pinned_certificate_chain_rejected(
    fixture: CertificateChainSignedPayload,
    expected: &str,
) {
    let CertificateChainSignedPayload {
        payload,
        issuer_sha256,
        ..
    } = fixture;
    let err = validate_require_verified_signed_payload(&payload, move |profile| {
        profile.signature_public_key_sha256_pins.clear();
        profile.x509_trust_anchor_sha256_pins = vec![issuer_sha256];
    })
    .expect_err(expected);
    assert!(matches!(err, MsgError::ValidationFailed));
}
fn assert_pinned_certificate_chain_accepted(
    fixture: CertificateChainSignedPayload,
    expected: &str,
) {
    let CertificateChainSignedPayload {
        payload,
        issuer_sha256,
        ..
    } = fixture;
    let metadata = validate_require_verified_signed_payload(&payload, move |profile| {
        profile.signature_public_key_sha256_pins.clear();
        profile.x509_trust_anchor_sha256_pins = vec![issuer_sha256];
    })
    .expect(expected);
    assert!(metadata.embedded_signature_detected());
}
fn assert_required_x509_policy_path_payload_accepted(fixture: CertificateChainSignedPayload) {
    let CertificateChainSignedPayload {
        payload,
        issuer_sha256,
        ..
    } = fixture;
    let metadata = validate_require_verified_signed_payload(&payload, move |profile| {
        profile.signature_public_key_sha256_pins.clear();
        profile.x509_trust_anchor_sha256_pins = vec![issuer_sha256];
        profile.x509_required_certificate_policy_oids = vec![TEST_X509_POLICY_OID.to_owned()];
    })
    .expect("required X.509 certificate policy path should verify");
    assert!(metadata.embedded_signature_detected());
}
fn assert_required_x509_policy_path_payload_rejected(
    fixture: CertificateChainSignedPayload,
    expected: &str,
) {
    let CertificateChainSignedPayload {
        payload,
        issuer_sha256,
        ..
    } = fixture;
    let err = validate_require_verified_signed_payload(&payload, move |profile| {
        profile.signature_public_key_sha256_pins.clear();
        profile.x509_trust_anchor_sha256_pins = vec![issuer_sha256];
        profile.x509_required_certificate_policy_oids = vec![TEST_X509_POLICY_OID.to_owned()];
    })
    .expect_err(expected);
    assert!(matches!(err, MsgError::ValidationFailed));
}
fn assert_x509_trust_anchor_payload_accepted(
    payload: String,
    trust_anchor_pin: String,
    configure_profile: impl FnOnce(&mut actual::IsoBridgeProfile),
    expected: &str,
) {
    let metadata = validate_require_verified_signed_payload(&payload, move |profile| {
        profile.signature_public_key_sha256_pins.clear();
        profile.x509_trust_anchor_sha256_pins = vec![trust_anchor_pin];
        configure_profile(profile);
    })
    .expect(expected);
    assert!(metadata.embedded_signature_detected());
}
fn assert_x509_trust_anchor_payload_rejected(
    payload: String,
    trust_anchor_pin: String,
    configure_profile: impl FnOnce(&mut actual::IsoBridgeProfile),
    expected: &str,
) {
    let err = validate_require_verified_signed_payload(&payload, move |profile| {
        profile.signature_public_key_sha256_pins.clear();
        profile.x509_trust_anchor_sha256_pins = vec![trust_anchor_pin];
        configure_profile(profile);
    })
    .expect_err(expected);
    assert!(matches!(err, MsgError::ValidationFailed));
}
fn assert_require_verified_signed_payload_accepted(
    payload: String,
    expected: &str,
    expected_business_message_id: Option<&str>,
) {
    let metadata = validate_require_verified_signed_payload(&payload, |_| {}).expect(expected);
    assert!(metadata.embedded_signature_detected());
    if let Some(expected_business_message_id) = expected_business_message_id {
        assert_eq!(
            metadata.business_message_id(),
            Some(expected_business_message_id)
        );
    }
}
fn assert_require_verified_signed_payload_rejected(payload: String, expected: &str) {
    let err = validate_require_verified_signed_payload(&payload, |_| {}).expect_err(expected);
    assert!(matches!(err, MsgError::ValidationFailed));
}
macro_rules! signed_payload_tests {
        ($($name:ident: $assertion:ident($($argument:expr),* $(,)?);)+) => {
            $(
                #[test]
                fn $name() {
                    $assertion($($argument),*);
                }
            )+
        };
    }
macro_rules! rejected_signed_payload_tests {
        ($($name:ident: $payload:block => $expected:expr;)+) => {
            $(
                #[test]
                fn $name() {
                    assert_require_verified_signed_payload_rejected($payload, $expected);
                }
            )+
        };
    }
fn sample_world(asset_alias: Option<&str>) -> World {
    let (authority, _, _) = sample_account_bundle();
    let domain_id: DomainId = DomainId::try_new("test", "universal").expect("domain");
    let asset_definition_id =
        AssetDefinitionId::derive_from_components(domain_id.clone(), "usd".parse().expect("name"));
    let domain = Domain::new(domain_id.clone()).build(&authority);
    let account = Account::new(authority.clone()).build(&authority);
    let asset_definition = AssetDefinition::numeric(
        asset_definition_id.clone(),
        "USD".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(&authority);
    let world = World::with([domain], [account], [asset_definition]);
    if let Some(alias_literal) = asset_alias {
        let alias: AssetDefinitionAlias = alias_literal.parse().expect("asset alias");
        let mut block = world.block();
        let mut tx = block.transaction_without_telemetry(
            iroha_config::parameters::actual::LaneConfig::default(),
            0,
        );
        tx.bind_asset_definition_alias(&asset_definition_id, alias, None, None, 10_000)
            .expect("bind alias");
        tx.apply();
        block.commit();
    }
    world
}
fn write_snapshot(contents: &str) -> NamedTempFile {
    let mut file = NamedTempFile::new().expect("snapshot file");
    file.write_all(contents.as_bytes()).expect("write snapshot");
    file
}
fn native_payment_recipient() -> AccountId {
    AccountId::new(fixture_key_pair(0xAD).public_key().clone())
}
fn native_payment_message(message_type: &str, fields: &[u8]) -> Result<ParsedMessage, MsgError> {
    let fields = std::str::from_utf8(fields)
        .expect("UTF-8 test fields")
        .replace(
            "CdtrAcct=GB82WEST12345698765432",
            "CdtrAcct=GB33BUKB20201555555555",
        )
        .replace(
            "CdtrAcct=GB29NWBK60161331926819",
            "CdtrAcct=GB33BUKB20201555555555",
        );
    let network = crate::test_utils::signed_query_network_id();
    let mut fields = format!(
        "{fields}\nUETR=123e4567-e89b-42d3-a456-426614174000\nNexusSettlement/NetworkId={network}\nNexusSettlement/ExpiresAtHeight=100"
    );
    for (name, value) in [
        ("SourceAccountId", sample_account_bundle().0.to_string()),
        ("TargetAccountId", native_payment_recipient().to_string()),
        ("AssetDefinitionId", sample_asset_definition_literal()),
    ] {
        let key = format!("NexusSettlement/{name}=");
        if !fields.lines().any(|line| line.starts_with(&key)) {
            fields.push_str(&format!("\n{key}{value}"));
        }
    }
    parse_message(message_type, fields.as_bytes())
}
fn payment_runtime_with_bic_reference(
    mut config: actual::IsoBridge,
) -> (Iso20022BridgeRuntime, NamedTempFile) {
    config.account_aliases.push(actual::IsoAccountAlias {
        iban: "GB33BUKB20201555555555".into(),
        account_id: native_payment_recipient().to_string(),
    });
    let reference_file = write_snapshot(include_str!(
        r"../../../fixtures/iso_bridge/bic_lei.sample.json"
    ));
    config.reference_data.bic_lei_path = Some(reference_file.path().to_path_buf());
    let runtime = Iso20022BridgeRuntime::from_config(&config)
        .expect("cfg")
        .expect("enabled");
    (runtime, reference_file)
}
fn runtime_config_error(config: &actual::IsoBridge, success_message: &str) -> eyre::Report {
    match Iso20022BridgeRuntime::from_config(config) {
        Ok(_) => panic!("{success_message}"),
        Err(error) => error,
    }
}
macro_rules! runtime_config_rejection_tests {
        ($($name:ident: $config:block => ($success:literal, $expected:literal);)+) => {
            $(
                #[test]
                fn $name() {
                    let config = $config;
                    let err = runtime_config_error(&config, $success);
                    assert!(
                        err.to_string().contains($expected),
                        "unexpected error: {err:?}"
                    );
                }
            )+
        };
    }
macro_rules! live_pacs008_parse_rejection_tests {
        ($expected:path; $($name:ident: $payload:expr => $message:literal;)+) => {
            $(
                #[test]
                fn $name() {
                    let payload = $payload;
                    let error = parse_message("pacs.008", payload.as_bytes())
                        .expect_err($message);
                    assert!(matches!(error, $expected));
                }
            )+
        };
    }
#[test]
fn parse_account_address_literal_rejects_invalid_input() {
    let error = super::parse_account_address_literal("not-an-address")
        .expect_err("invalid supplementary address must fail closed");
    assert!(matches!(error, MsgError::ValidationFailed));
}
#[test]
fn parse_account_address_literal_returns_canonical_bytes() {
    let key_pair = fixture_key_pair(0xAB);
    let account = AccountId::new(key_pair.public_key().clone());
    let address = AccountAddress::from_account_id(&account).expect("address");
    let i105 = address
        .to_i105_for_discriminant(iroha_data_model::account::address::chain_discriminant())
        .expect("i105 encoding");
    let value = super::parse_account_address_literal(&i105).expect("canonical I105 must parse");
    assert_eq!(value, address.canonical_hex().expect("canonical hex"));
}
#[test]
fn parse_account_address_literal_rejects_canonical_hex() {
    let key_pair = fixture_key_pair(0xAC);
    let account = AccountId::new(key_pair.public_key().clone());
    let address = AccountAddress::from_account_id(&account).expect("address");
    let canonical = address.canonical_hex().expect("canonical hex");
    let error = super::parse_account_address_literal(&canonical)
        .expect_err("canonical hex must not be retained as an unvalidated address");
    assert!(matches!(error, MsgError::ValidationFailed));
}
#[test]
fn runtime_from_config_normalises_aliases() {
    let runtime = sample_runtime();
    let resolved = runtime
        .resolve_account("gb82west12345698765432")
        .expect("alias");
    let (expected_account, _, _) = sample_account_bundle();
    assert_eq!(resolved, expected_account);
}
#[test]
fn runtime_from_config_rejects_zero_body_limit() {
    let mut config = sample_config();
    config.max_body_bytes = 0_u64.into();
    let error = runtime_config_error(
        &config,
        "enabled ISO bridge must reject a zero request-body limit",
    );
    assert!(
        error
            .to_string()
            .contains("max_body_bytes must be greater than zero")
    );
}
#[test]
fn runtime_maps_alias_indices() {
    let runtime = sample_runtime();
    let index = runtime
        .resolve_alias_index("GB82 WEST 1234 5698 7654 32")
        .expect("alias index");
    assert_eq!(index, AliasIndex(0));
    let (alias, account) = runtime
        .resolve_account_by_index(index)
        .expect("alias by index");
    assert_eq!(alias, "GB82WEST12345698765432");
    let (expected_account, _, _) = sample_account_bundle();
    assert_eq!(account, expected_account);
}
#[test]
fn runtime_exposes_reference_data_snapshots() {
    let runtime = sample_runtime();
    assert_eq!(
        runtime.reference_data().isin_cusip().state(),
        SnapshotState::Missing
    );
}
#[test]
fn runtime_resolves_default_profile() {
    let runtime = sample_runtime();
    assert_eq!(runtime.default_profile().id, "generic-iso20022");
    assert!(runtime.resolve_profile(Some("swift-cbpr-plus")).is_some());
    assert!(runtime.resolve_profile(Some("unknown-profile")).is_none());
}
runtime_config_rejection_tests! {
    runtime_from_config_rejects_noncanonical_xml_signature_pin: {
        let mut config = sample_config();
        let mut profile = signed_message_profile("require-verified");
        profile.signature_public_key_sha256_pins = vec!["AB".repeat(32)];
        config.profiles.push(profile);
        config
    } => ("uppercase SHA-256 pins must fail configuration", "signature_public_key_sha256_pins");
    runtime_from_config_rejects_noncanonical_xml_signature_revocation_pin: {
        let mut config = sample_config();
        let mut profile = signed_message_profile("require-verified");
        profile.revoked_certificate_sha256 = vec!["AB".repeat(32)];
        config.profiles.push(profile);
        config
    } => ("uppercase SHA-256 revocation pins must fail configuration", "revoked_certificate_sha256");
    runtime_from_config_rejects_empty_message_version_allowlist: {
        let mut config = sample_config();
        let mut profile = live_message_profile("pacs.008", "pacs.008.001.08");
        profile.message_profiles[0].versions.clear();
        config.profiles.push(profile);
        config
    } => ("message profiles with no accepted versions must fail configuration", "requires at least one versions entry");
    runtime_from_config_rejects_duplicate_message_version_entries: {
        let mut config = sample_config();
        let mut profile = live_message_profile("pacs.008", "pacs.008.001.08");
        profile.message_profiles[0].versions =
            vec!["pacs.008.001.08".to_owned(), "PACS.008.001.08".to_owned()];
        config.profiles.push(profile);
        config
    } => ("duplicate version allowlist entries must fail", "versions entries must be duplicate-free");
    runtime_from_config_rejects_required_business_service_without_allowlist: {
        let mut config = sample_config();
        let mut profile = live_message_profile("pacs.008", "pacs.008.001.08");
        profile.message_profiles[0].business_services.clear();
        config.profiles.push(profile);
        config
    } => ("required BizSvc profile with no allowlist must fail configuration", "requires at least one business_services entry");
    runtime_from_config_rejects_duplicate_business_service_allowlist_entries: {
        let mut config = sample_config();
        let mut profile = live_message_profile("pacs.008", "pacs.008.001.08");
        profile.message_profiles[0].business_services = vec![
            "swift.cbprplus.02".to_owned(),
            "SWIFT.CBPRPLUS.02".to_owned(),
        ];
        config.profiles.push(profile);
        config
    } => ("duplicate BizSvc allowlist entries must fail", "business_services entries must be duplicate-free");
    runtime_from_config_rejects_duplicate_currency_minor_unit_entries: {
        let mut config = sample_config();
        let mut profile = live_message_profile("pacs.008", "pacs.008.001.08");
        profile.message_profiles[0].amount_minor_units = vec![
            actual::IsoCurrencyMinorUnit {
                currency: "usd".to_owned(),
                minor_units: 2,
            },
            actual::IsoCurrencyMinorUnit {
                currency: "USD".to_owned(),
                minor_units: 3,
            },
        ];
        config.profiles.push(profile);
        config
    } => ("duplicate minor-unit currency entries must fail", "duplicate currency `USD`");
    runtime_from_config_rejects_excessive_currency_minor_units: {
        let mut config = sample_config();
        let mut profile = live_message_profile("pacs.008", "pacs.008.001.08");
        profile.message_profiles[0].amount_minor_units = vec![actual::IsoCurrencyMinorUnit {
            currency: "USD".to_owned(),
            minor_units: 5,
        }];
        config.profiles.push(profile);
        config
    } => ("excessive fiat minor-unit precision must fail", "minor_units must be at most 4");
    runtime_from_config_rejects_padded_default_profile_id: {
        let mut config = sample_config();
        config.default_profile = " generic-iso20022".to_owned();
        config
    } => ("padded default profile id must fail", "iso_bridge default_profile must be a non-empty trimmed string");
    runtime_from_config_rejects_padded_reference_dataset_requirements: {
        let mut config = sample_config();
        let mut profile = live_message_profile("pacs.008", "pacs.008.001.08");
        profile.required_reference_datasets = vec![" bic-lei".to_owned()];
        config.profiles.push(profile);
        config
    } => ("padded reference dataset ids must fail", "required_reference_datasets entry must be a non-empty trimmed string");
    runtime_from_config_rejects_padded_x509_policy_oid_entries: {
        let mut config = sample_config();
        let mut profile = signed_message_profile("require-verified");
        profile.x509_required_certificate_policy_oids = vec![format!("{TEST_X509_POLICY_OID} ")];
        config.profiles.push(profile);
        config
    } => ("padded X.509 policy OID entries must fail", "x509_required_certificate_policy_oids entry must be a non-empty trimmed string");
    runtime_from_config_rejects_duplicate_x509_policy_oid_entries: {
        let mut config = sample_config();
        let mut profile = signed_message_profile("require-verified");
        profile.x509_required_certificate_policy_oids = vec![
            TEST_X509_POLICY_OID.to_owned(),
            TEST_X509_POLICY_OID.to_owned(),
        ];
        config.profiles.push(profile);
        config
    } => ("duplicate X.509 policy OID entries must fail", "x509_required_certificate_policy_oids entries must be duplicate-free");
    runtime_from_config_rejects_padded_x509_crl_der_entries: {
        let mut config = sample_config();
        let mut profile = signed_message_profile("require-verified");
        profile.x509_crl_der_base64 = vec![format!("{TEST_X509_CRL_EMPTY_DER_B64} ")];
        config.profiles.push(profile);
        config
    } => ("padded X.509 CRL DER entries must fail", "x509_crl_der_base64 entry must be a non-empty trimmed string");
    runtime_from_config_rejects_duplicate_x509_crl_der_entries: {
        let mut config = sample_config();
        let mut profile = signed_message_profile("require-verified");
        profile.x509_crl_der_base64 = vec![
            TEST_X509_CRL_EMPTY_DER_B64.to_owned(),
            TEST_X509_CRL_EMPTY_DER_B64.to_owned(),
        ];
        config.profiles.push(profile);
        config
    } => ("duplicate X.509 CRL DER entries must fail", "x509_crl_der_base64 entries must be duplicate-free");
    runtime_from_config_rejects_too_many_x509_crl_der_entries: {
        let mut config = sample_config();
        let mut profile = signed_message_profile("require-verified");
        profile.x509_crl_der_base64 = vec!["not-base64".to_owned(); XMLDSIG_MAX_X509_CRLS + 1];
        config.profiles.push(profile);
        config
    } => ("over-limit X.509 CRL DER entries must fail", "x509_crl_der_base64 must not contain more than");
    runtime_from_config_rejects_padded_x509_ocsp_response_der_entries: {
        let fixture = signed_pacs008_xml_with_generated_ocsp_x509_certificate_chain(
            TestOcspResponseStatus::Good,
            false,
            XML_SIGNATURE_TEST_SIGNING_TIME,
        );
        let mut config = sample_config();
        let mut profile = signed_message_profile("require-verified");
        profile.x509_ocsp_response_der_base64 = vec![format!("{} ", fixture.response_der_base64)];
        config.profiles.push(profile);
        config
    } => ("padded X.509 OCSP response DER entries must fail", "x509_ocsp_response_der_base64 entry must be a non-empty trimmed string");
    runtime_from_config_rejects_duplicate_x509_ocsp_response_der_entries: {
        let fixture = signed_pacs008_xml_with_generated_ocsp_x509_certificate_chain(
            TestOcspResponseStatus::Good,
            false,
            XML_SIGNATURE_TEST_SIGNING_TIME,
        );
        let mut config = sample_config();
        let mut profile = signed_message_profile("require-verified");
        profile.x509_ocsp_response_der_base64 = vec![
            fixture.response_der_base64.clone(),
            fixture.response_der_base64,
        ];
        config.profiles.push(profile);
        config
    } => ("duplicate X.509 OCSP response DER entries must fail", "x509_ocsp_response_der_base64 entries must be duplicate-free");
    runtime_from_config_rejects_too_many_x509_ocsp_response_der_entries: {
        let mut config = sample_config();
        let mut profile = signed_message_profile("require-verified");
        profile.x509_ocsp_response_der_base64 =
            vec!["not-base64".to_owned(); XMLDSIG_MAX_X509_OCSP_RESPONSES + 1];
        config.profiles.push(profile);
        config
    } => ("over-limit X.509 OCSP response DER entries must fail", "x509_ocsp_response_der_base64 must not contain more than");
    runtime_from_config_rejects_duplicate_override_profile_ids: {
        let mut config = sample_config();
        config
            .profiles
            .push(live_message_profile("pacs.008", "pacs.008.001.08"));
        config
            .profiles
            .push(live_message_profile("pacs.008", "pacs.008.001.08"));
        config
    } => ("duplicate override profile ids must fail", "duplicate profile id `pacs.008-live-test`");
    runtime_from_config_rejects_duplicate_reference_dataset_requirements: {
        let mut config = sample_config();
        let mut profile = live_message_profile("pacs.008", "pacs.008.001.08");
        profile.required_reference_datasets = vec!["bic-lei".to_owned(), "BIC_LEI".to_owned()];
        config.profiles.push(profile);
        config
    } => ("duplicate reference dataset requirements must fail", "required_reference_datasets entries must be duplicate-free");
    runtime_from_config_rejects_duplicate_message_profile_family_direction: {
        let mut config = sample_config();
        let mut profile = live_message_profile("pacs.008", "pacs.008.001.08");
        profile
            .message_profiles
            .push(profile.message_profiles[0].clone());
        config.profiles.push(profile);
        config
    } => ("duplicate message family/direction profiles must fail", "message_profiles entries must be unique by message_type and direction");
}
#[test]
fn runtime_from_config_rejects_overlapping_xml_signature_pin_roles() {
    let public_pin = test_p256_public_key_pin();
    let mut config = sample_config();
    let mut profile = signed_message_profile("require-verified");
    profile.x509_trust_anchor_sha256_pins = vec![public_pin];
    config.profiles.push(profile);
    let err = runtime_config_error(
        &config,
        "overlapping public-key and certificate pins must fail configuration",
    );
    assert!(
        err.to_string().contains("must not overlap"),
        "unexpected public-key overlap error: {err:?}"
    );
    let certificate_pin = "ab".repeat(32);
    let mut config = sample_config();
    let mut profile = signed_message_profile("require-verified");
    profile.x509_trust_anchor_sha256_pins = vec![certificate_pin.clone()];
    profile.revoked_certificate_sha256 = vec![certificate_pin];
    config.profiles.push(profile);
    let err = runtime_config_error(
        &config,
        "overlapping trusted and revoked certificate pins must fail configuration",
    );
    assert!(
        err.to_string().contains("must not overlap"),
        "unexpected certificate overlap error: {err:?}"
    );
}
#[test]
fn runtime_from_config_rejects_blank_message_version_entries() {
    for version in ["", " ", " pacs.008.001.08", "pacs.008.001.08 "] {
        let mut config = sample_config();
        let mut profile = live_message_profile("pacs.008", "pacs.008.001.08");
        profile.message_profiles[0].versions = vec![version.to_owned()];
        config.profiles.push(profile);
        let err = runtime_config_error(
            &config,
            "blank or padded version allowlist entries must fail",
        );
        assert!(
            err.to_string().contains("non-empty trimmed strings"),
            "unexpected error for {version:?}: {err:?}"
        );
    }
}
#[test]
fn runtime_from_config_rejects_blank_business_service_allowlist_entries() {
    for service in ["", " ", " swift.cbprplus.02", "swift.cbprplus.02 "] {
        let mut config = sample_config();
        let mut profile = live_message_profile("pacs.008", "pacs.008.001.08");
        profile.message_profiles[0].business_services = vec![service.to_owned()];
        config.profiles.push(profile);
        let err = runtime_config_error(
            &config,
            "blank or padded BizSvc allowlist entries must fail",
        );
        assert!(
            err.to_string().contains("non-empty trimmed strings"),
            "unexpected error for {service:?}: {err:?}"
        );
    }
}
#[test]
fn runtime_from_config_rejects_padded_profile_identity_fields() {
    let cases: [(&str, fn(&mut actual::IsoBridgeProfile), &str); 3] = [
        (
            "profile id",
            |profile: &mut actual::IsoBridgeProfile| profile.id = " padded-profile".to_owned(),
            "iso_bridge profile id must be a non-empty trimmed string",
        ),
        (
            "rail",
            |profile: &mut actual::IsoBridgeProfile| {
                profile.rail = " swift-cbpr-plus".to_owned();
            },
            "rail must be a non-empty trimmed string",
        ),
        (
            "embedded signature policy",
            |profile: &mut actual::IsoBridgeProfile| {
                profile.embedded_signature_policy = Some(" reject-unsupported".to_owned());
            },
            "ISO embedded signature policy must be a non-empty trimmed string",
        ),
    ];
    for (name, mutate, expected) in cases {
        let mut config = sample_config();
        let mut profile = live_message_profile("pacs.008", "pacs.008.001.08");
        mutate(&mut profile);
        config.profiles.push(profile);
        let err = runtime_config_error(&config, &format!("padded {name} must fail"));
        assert!(
            err.to_string().contains(expected),
            "unexpected error for {name}: {err:?}"
        );
    }
}
#[test]
fn runtime_from_config_rejects_padded_message_profile_fields() {
    let cases: [(&str, fn(&mut actual::IsoMessageProfile), &str); 4] = [
        (
            "message_type",
            |message: &mut actual::IsoMessageProfile| {
                message.message_type = " pacs.008".to_owned();
            },
            "message_type must be a non-empty trimmed string",
        ),
        (
            "direction",
            |message: &mut actual::IsoMessageProfile| {
                message.direction = " inbound".to_owned();
            },
            "direction must be a non-empty trimmed string",
        ),
        (
            "structured_address_mode",
            |message: &mut actual::IsoMessageProfile| {
                message.structured_address_mode = " permissive".to_owned();
            },
            "structured_address_mode must be a non-empty trimmed string",
        ),
        (
            "minor unit currency",
            |message: &mut actual::IsoMessageProfile| {
                message.amount_minor_units = vec![actual::IsoCurrencyMinorUnit {
                    currency: " USD".to_owned(),
                    minor_units: 2,
                }];
            },
            "amount_minor_units currency must be a non-empty trimmed string",
        ),
    ];
    for (name, mutate, expected) in cases {
        let mut config = sample_config();
        let mut profile = live_message_profile("pacs.008", "pacs.008.001.08");
        mutate(&mut profile.message_profiles[0]);
        config.profiles.push(profile);
        let err = runtime_config_error(&config, &format!("padded {name} must fail"));
        assert!(
            err.to_string().contains(expected),
            "unexpected error for {name}: {err:?}"
        );
    }
}
#[test]
fn runtime_from_config_rejects_malformed_x509_crl_der_entries() {
    for der in [
        vec![0x02, 0x01, 0x00],
        vec![0x30, 0x00],
        vec![0x30, 0x03, 0x02, 0x01, 0x00],
        vec![0x30, 0x81, 0x00],
    ] {
        let mut config = sample_config();
        let mut profile = signed_message_profile("require-verified");
        profile.x509_crl_der_base64 = vec![BASE64_STANDARD.encode(der)];
        config.profiles.push(profile);
        let err = runtime_config_error(&config, "malformed X.509 CRL DER entries must fail");
        assert!(
            err.to_string()
                .contains("x509_crl_der_base64 entries must parse as DER CRLs"),
            "unexpected error: {err:?}"
        );
    }
}
#[test]
fn runtime_from_config_rejects_malformed_x509_ocsp_response_der_entries() {
    for der in [
        vec![0x02, 0x01, 0x00],
        vec![0x30, 0x00],
        vec![0x30, 0x03, 0x02, 0x01, 0x00],
        vec![
            0x30, 0x16, 0x0A, 0x01, 0x01, 0xA0, 0x11, 0x30, 0x0F, 0x06, 0x09, 0x2B, 0x06, 0x01,
            0x05, 0x05, 0x07, 0x30, 0x01, 0x01, 0x04, 0x02, 0x30, 0x00,
        ],
    ] {
        let mut config = sample_config();
        let mut profile = signed_message_profile("require-verified");
        profile.x509_ocsp_response_der_base64 = vec![BASE64_STANDARD.encode(der)];
        config.profiles.push(profile);
        let err = runtime_config_error(
            &config,
            "malformed X.509 OCSP response DER entries must fail",
        );
        assert!(
            err.to_string()
                .contains("x509_ocsp_response_der_base64 entries must parse as DER OCSP responses"),
            "unexpected error: {err:?}"
        );
    }
}
#[test]
fn profile_validation_records_metadata_for_generic_messages() {
    let runtime = sample_runtime();
    let parsed = sample_pacs008();
    let metadata = runtime
        .validate_profile_submission(
            runtime.default_profile(),
            "pacs.008",
            &parsed,
            b"profile payload",
        )
        .expect("generic profile accepts message");
    assert_eq!(metadata.profile_id(), Some("generic-iso20022"));
    assert_eq!(metadata.message_type(), Some("pacs.008"));
    assert!(metadata.payload_hash().is_some());
    assert!(metadata.reference_snapshot_id().is_some());
    assert!(!metadata.embedded_signature_detected());
}
#[test]
fn profile_validation_records_reference_snapshot_checksum() {
    let snapshot = test_fixture_text(include_str!(
        r"../../../fixtures/iso20022/single_bic_lei_test_reference.json"
    ));
    let file = write_snapshot(snapshot);
    let mut config = sample_config();
    config.reference_data.bic_lei_path = Some(file.path().to_path_buf());
    let runtime = Iso20022BridgeRuntime::from_config(&config)
        .expect("cfg")
        .expect("enabled");
    let parsed = sample_pacs008();
    let expected_snapshot_id = runtime.reference_data().snapshot_id();
    let metadata = runtime
        .validate_profile_submission(
            runtime.default_profile(),
            "pacs.008",
            &parsed,
            b"profile payload",
        )
        .expect("generic profile accepts message");
    assert_eq!(
        metadata.reference_snapshot_id(),
        Some(expected_snapshot_id.as_str())
    );
    assert_ne!(
        expected_snapshot_id,
        ReferenceDataSnapshots::from_config(&actual::IsoReferenceData::default()).snapshot_id()
    );
}
#[test]
fn live_profile_accepts_bah_fields_with_data_pdu_prefixes() {
    let mut config = sample_config();
    config
        .profiles
        .push(live_message_profile("pacs.008", "pacs.008.001.08"));
    let runtime = Iso20022BridgeRuntime::from_config(&config)
        .expect("cfg")
        .expect("enabled");
    let profile = runtime
        .resolve_profile(Some("pacs.008-live-test"))
        .expect("custom profile");
    let parsed = parse_message(
            "pacs.008",
            b"DataPDU/AppHdr/BizMsgIdr=HDR-123\nDataPDU/AppHdr/MsgDefIdr=pacs.008.001.08\nDataPDU/AppHdr/CreDt=2025-01-01T12:00:00Z\nDataPDU/AppHdr/BizSvc=swift.cbprplus.02\nMsgId=m-profile\nIntrBkSttlmAmt=10.00\nIntrBkSttlmCcy=USD\nIntrBkSttlmDt=2024-01-01\nDbtrAcct=GB82WEST12345698765432\nCdtrAcct=GB82WEST12345698765432\nDbtrAgt=DEUTDEFF\nCdtrAgt=DEUTDEFF",
        )
        .expect("parsed");
    let metadata = runtime
        .validate_profile_submission(profile, "pacs.008", &parsed, b"profile payload")
        .expect("BAH suffix fields should satisfy live profile");
    assert_eq!(metadata.business_service(), Some("swift.cbprplus.02"));
    assert_eq!(metadata.business_message_id(), Some("HDR-123"));
}
#[test]
fn live_profile_accepts_pacs009_canonical_app_header_aliases() {
    let mut config = sample_config();
    config
        .profiles
        .push(live_message_profile("pacs.009", "pacs.009.001.10"));
    let runtime = Iso20022BridgeRuntime::from_config(&config)
        .expect("cfg")
        .expect("enabled");
    let profile = runtime
        .resolve_profile(Some("pacs.009-live-test"))
        .expect("custom profile");
    let parsed = parse_message(
            "pacs.009",
            b"AppHdr/BizMsgIdr=HDR-009\nAppHdr/MsgDefIdr=pacs.009.001.10\nAppHdr/CreDt=2025-01-01T12:00:00Z\nAppHdr/BizSvc=swift.cbprplus.02\nMsgId=PACS009-GRP\nIntrBkSttlmAmt=2500\nIntrBkSttlmCcy=USD\nIntrBkSttlmDt=2024-01-03\nDbtrAcct=GB82WEST12345698765432\nCdtrAcct=GB82WEST12345698765432\nInstgAgt=DEUTDEFF\nInstdAgt=DEUTDEFF",
        )
        .expect("parsed");
    let metadata = runtime
        .validate_profile_submission(profile, "pacs.009", &parsed, b"profile payload")
        .expect("canonicalized BAH aliases should satisfy live profile");
    assert_eq!(metadata.business_service(), Some("swift.cbprplus.02"));
    assert_eq!(metadata.business_message_id(), Some("HDR-009"));
}
#[test]
fn live_profile_rejects_empty_required_business_service() {
    let mut config = sample_config();
    config
        .profiles
        .push(live_message_profile("pacs.008", "pacs.008.001.08"));
    let runtime = Iso20022BridgeRuntime::from_config(&config)
        .expect("cfg")
        .expect("enabled");
    let profile = runtime
        .resolve_profile(Some("pacs.008-live-test"))
        .expect("custom profile");
    let parsed = parse_message(
            "pacs.008",
            b"DataPDU/AppHdr/BizMsgIdr=HDR-EMPTY-SVC\nDataPDU/AppHdr/MsgDefIdr=pacs.008.001.08\nDataPDU/AppHdr/CreDt=2025-01-01T12:00:00Z\nDataPDU/AppHdr/BizSvc=\nMsgId=m-profile\nIntrBkSttlmAmt=10.00\nIntrBkSttlmCcy=USD\nIntrBkSttlmDt=2024-01-01\nDbtrAcct=GB82WEST12345698765432\nCdtrAcct=GB82WEST12345698765432\nDbtrAgt=DEUTDEFF\nCdtrAgt=DEUTDEFF",
        )
        .expect("parsed");
    let err = runtime
        .validate_profile_submission(profile, "pacs.008", &parsed, b"profile payload")
        .expect_err("empty BizSvc must not satisfy required business service policy");
    assert!(matches!(err, MsgError::MissingField("AppHdr/BizSvc")));
}
#[test]
fn profile_validation_rejects_selected_profile_message_type_mismatch() {
    let mut config = sample_config();
    config
        .profiles
        .push(live_message_profile("pacs.009", "pacs.009.001.10"));
    let runtime = Iso20022BridgeRuntime::from_config(&config)
        .expect("cfg")
        .expect("enabled");
    let profile = runtime
        .resolve_profile(Some("pacs.009-live-test"))
        .expect("custom profile");
    let parsed = sample_pacs008();
    let err = runtime
        .validate_profile_submission(profile, "pacs.008", &parsed, b"profile payload")
        .expect_err("pacs.009 profile must not admit pacs.008 endpoint submissions");
    assert!(matches!(err, MsgError::UnknownMessageType));
}
#[test]
fn live_profile_rejects_app_header_message_definition_mismatch() {
    let mut config = sample_config();
    config
        .profiles
        .push(live_message_profile("pacs.008", "pacs.008.001.08"));
    let runtime = Iso20022BridgeRuntime::from_config(&config)
        .expect("cfg")
        .expect("enabled");
    let profile = runtime
        .resolve_profile(Some("pacs.008-live-test"))
        .expect("custom profile");
    let parsed = parse_message(
            "pacs.008",
            b"DataPDU/AppHdr/BizMsgIdr=HDR-MISMATCH\nDataPDU/AppHdr/MsgDefIdr=pacs.009.001.10\nDataPDU/AppHdr/CreDt=2025-01-01T12:00:00Z\nDataPDU/AppHdr/BizSvc=swift.cbprplus.02\nMsgId=m-profile\nIntrBkSttlmAmt=10.00\nIntrBkSttlmCcy=USD\nIntrBkSttlmDt=2024-01-01\nDbtrAcct=GB82WEST12345698765432\nCdtrAcct=GB82WEST12345698765432\nDbtrAgt=DEUTDEFF\nCdtrAgt=DEUTDEFF",
        )
        .expect("parsed");
    let err = runtime
        .validate_profile_submission(profile, "pacs.008", &parsed, b"profile payload")
        .expect_err("BAH MsgDefIdr must match the selected profile version set");
    assert!(matches!(err, MsgError::UnknownMessageType));
}
signed_payload_tests! {
    require_verified_profile_accepts_valid_p256_xmldsig_xades: assert_require_verified_signed_payload_accepted(
        signed_pacs008_xml(),
        "valid XMLDSig/XAdES payload should pass require-verified profile",
        None,
    );
    require_verified_profile_accepts_xades_signed_properties_reference: assert_require_verified_signed_payload_accepted(
        signed_pacs008_xml_with_signed_properties_reference(),
        "XAdES SignedProperties Reference digest should verify",
        Some("sig-001"),
    );
    require_verified_profile_accepts_prefixed_xades_signed_properties_reference: assert_require_verified_signed_payload_accepted(
        signed_pacs008_xml_with_prefixed_xades_signed_properties(),
        "prefixed XAdES SignedProperties should bind to the supported namespace",
        Some("sig-001"),
    );
    require_verified_profile_rejects_prefixed_xades_with_wrong_namespace: assert_require_verified_signed_payload_rejected(
        signed_pacs008_xml_with_wrong_prefixed_xades_namespace(),
        "prefixed XAdES elements must bind to the supported XAdES namespace",
    );
    require_verified_profile_rejects_unprefixed_xades_with_wrong_default_namespace: assert_require_verified_signed_payload_rejected(
        signed_pacs008_xml_with_wrong_default_xades_namespace(),
        "unprefixed XAdES elements must reject wrong default namespaces",
    );
}
rejected_signed_payload_tests! {
    require_verified_profile_rejects_unreferenced_signed_properties: {
        signed_pacs008_xml().replacen(
            &format!(r##"<Object><QualifyingProperties xmlns="{XADES_NS}" Target="#sig-001"/></Object>"##),
            &format!(
                r##"<Object><QualifyingProperties xmlns="{XADES_NS}" Target="#sig-001">{}</QualifyingProperties></Object>"##,
                signed_properties_xml("unsigned-props-001")
            ),
            1,
        )
    } => "unreferenced SignedProperties must fail closed";
    require_verified_profile_rejects_duplicate_signed_properties: {
        signed_pacs008_xml_with_signed_properties_reference().replacen(
            "</SignedProperties>",
            &format!(
                "</SignedProperties>{}",
                signed_properties_xml("unsigned-props-002")
            ),
            1,
        )
    } => "duplicate SignedProperties must fail closed";
    require_verified_profile_rejects_signed_signing_time_unsupported_attribute: {
        let signed_properties_id = "signed-props-001";
        let signed_properties = format!(
            concat!(
                r#"<SignedProperties xmlns="{XADES_NS}" Id="{id}"><SignedSignatureProperties>"#,
                r#"<SigningTime Source="unsupported">{signing_time}</SigningTime>"#,
                "</SignedSignatureProperties></SignedProperties>"
            ),
            id = signed_properties_id,
            signing_time = XML_SIGNATURE_TEST_SIGNING_TIME,
            XADES_NS = XADES_NS
        );
        signed_pacs008_xml_with_signed_properties(signed_properties_id, &signed_properties)
    } => "unsupported signed SigningTime attributes must fail closed";
    require_verified_profile_rejects_public_key_xades_signing_certificate_v2: {
        let signing_key = test_p256_signing_key();
        let signed_properties_xml = test_xades_signed_properties_xml_for_certificate(
            TEST_X509_CHAIN_LEAF_CERTIFICATE_DER_B64,
        );
        let signed_properties_reference_xml =
            test_xades_signed_properties_reference_for_xml(&signed_properties_xml);
        let xades_object_xml = test_xades_object_xml(&signed_properties_xml);
        signed_pacs008_xml_with_key_info_and_xades_parts(
            &signing_key,
            &test_p256_key_info(&signing_key),
            &signed_properties_reference_xml,
            &xades_object_xml,
        )
    } => "SigningCertificateV2 cannot authorize raw public-key KeyInfo";
    require_verified_profile_rejects_wrapped_signed_info: {
        signed_pacs008_xml()
            .replacen("<SignedInfo>", "<Wrapper><SignedInfo>", 1)
            .replacen("</SignedInfo>", "</SignedInfo></Wrapper>", 1)
    } => "wrapped SignedInfo must fail closed";
    require_verified_profile_rejects_signature_extra_child: {
        signed_pacs008_xml().replacen("<KeyInfo>", "<Manifest></Manifest><KeyInfo>", 1)
    } => "unsupported direct Signature children must fail closed";
    require_verified_profile_rejects_reordered_signature_children: {
        let payload = signed_pacs008_xml();
        let signature_value_start = payload.find("<SignatureValue>").expect("SignatureValue");
        let signature_value_end = payload
            .find("</SignatureValue>")
            .expect("SignatureValue end")
            + "</SignatureValue>".len();
        let key_info_start = payload.find("<KeyInfo>").expect("KeyInfo");
        let key_info_end = payload.find("</KeyInfo>").expect("KeyInfo end") + "</KeyInfo>".len();
        format!(
            "{}{}{}{}{}",
            &payload[..signature_value_start],
            &payload[key_info_start..key_info_end],
            &payload[signature_value_start..signature_value_end],
            &payload[signature_value_end..key_info_start],
            &payload[key_info_end..]
        )
    } => "reordered Signature children must fail closed";
    require_verified_profile_rejects_signed_info_extra_child: {
        signed_pacs008_xml().replacen(
            "</SignatureMethod>",
            "</SignatureMethod><Object></Object>",
            1,
        )
    } => "unsupported direct SignedInfo children must fail closed";
    require_verified_profile_rejects_reordered_signed_info_children: {
        signed_pacs008_xml_with_signed_info_rewrite(|signed_info| {
            let canonicalization_method = format!(
                r#"<CanonicalizationMethod Algorithm="{XML_C14N_1_0}"></CanonicalizationMethod>"#
            );
            let signature_method = format!(
                r#"<SignatureMethod Algorithm="{XMLDSIG_ECDSA_SHA256}"></SignatureMethod>"#
            );
            signed_info.replacen(
                &format!("{canonicalization_method}{signature_method}"),
                &format!("{signature_method}{canonicalization_method}"),
                1,
            )
        })
    } => "reordered SignedInfo children must fail closed";
    require_verified_profile_rejects_canonicalization_method_parameters: {
        signed_pacs008_xml().replace(
            &format!(r#"<CanonicalizationMethod Algorithm="{XML_C14N_1_0}"></CanonicalizationMethod>"#),
            &format!(
                r#"<CanonicalizationMethod Algorithm="{XML_C14N_1_0}"><InclusiveNamespaces PrefixList="unused"></InclusiveNamespaces></CanonicalizationMethod>"#
            ),
        )
    } => "parameterized SignedInfo canonicalization must fail closed";
    require_verified_profile_rejects_duplicate_canonicalization_method: {
        let method = format!(
            r#"<CanonicalizationMethod Algorithm="{XML_C14N_1_0}"></CanonicalizationMethod>"#
        );
        signed_pacs008_xml().replace(&method, &format!("{method}{method}"))
    } => "duplicate SignedInfo canonicalization methods must fail closed";
    require_verified_profile_rejects_signature_method_parameters: {
        signed_pacs008_xml().replace(
            &format!(r#"<SignatureMethod Algorithm="{XMLDSIG_ECDSA_SHA256}"></SignatureMethod>"#),
            &format!(
                r#"<SignatureMethod Algorithm="{XMLDSIG_ECDSA_SHA256}"><HMACOutputLength>256</HMACOutputLength></SignatureMethod>"#
            ),
        )
    } => "parameterized SignatureMethod must fail closed";
    require_verified_profile_rejects_duplicate_signature_method: {
        let method =
            format!(r#"<SignatureMethod Algorithm="{XMLDSIG_ECDSA_SHA256}"></SignatureMethod>"#);
        signed_pacs008_xml().replace(&method, &format!("{method}{method}"))
    } => "duplicate SignatureMethod elements must fail closed";
    require_verified_profile_rejects_unsupported_signature_method: {
        signed_pacs008_xml().replace(XMLDSIG_ECDSA_SHA256, "urn:unsupported:rsa-sha1")
    } => "unsupported signature methods must fail closed";
    require_verified_profile_rejects_digest_method_parameters: {
        signed_pacs008_xml().replace(
            &format!(r#"<DigestMethod Algorithm="{XMLDSIG_SHA256}"></DigestMethod>"#),
            &format!(
                r#"<DigestMethod Algorithm="{XMLDSIG_SHA256}"><DigestParams>not-supported</DigestParams></DigestMethod>"#
            ),
        )
    } => "parameterized DigestMethod must fail closed";
    require_verified_profile_rejects_duplicate_digest_method: {
        let method = format!(r#"<DigestMethod Algorithm="{XMLDSIG_SHA256}"></DigestMethod>"#);
        signed_pacs008_xml().replace(&method, &format!("{method}{method}"))
    } => "duplicate DigestMethod elements must fail closed";
    require_verified_profile_rejects_reordered_reference_children: {
        signed_pacs008_xml_with_signed_info_rewrite(|signed_info| {
            let transforms = format!(
                r#"<Transforms><Transform Algorithm="{XMLDSIG_ENVELOPED_SIGNATURE}"></Transform></Transforms>"#
            );
            let digest_method =
                format!(r#"<DigestMethod Algorithm="{XMLDSIG_SHA256}"></DigestMethod>"#);
            signed_info.replacen(
                &format!("{transforms}{digest_method}"),
                &format!("{digest_method}{transforms}"),
                1,
            )
        })
    } => "reordered Reference children must fail closed";
    require_verified_profile_rejects_reference_c14n_transform_parameters: {
        signed_pacs008_xml_with_reference_c14n_transform().replace(
            &format!(r#"<Transform Algorithm="{XML_C14N_1_0}"></Transform>"#),
            &format!(
                r#"<Transform Algorithm="{XML_C14N_1_0}"><InclusiveNamespaces PrefixList="unused"></InclusiveNamespaces></Transform>"#
            ),
        )
    } => "parameterized Reference C14N transforms must fail closed";
    require_verified_profile_rejects_reference_transform_without_wrapper: {
        let wrapped = format!(
            r#"<Transforms><Transform Algorithm="{XMLDSIG_ENVELOPED_SIGNATURE}"></Transform></Transforms>"#
        );
        let unwrapped =
            format!(r#"<Transform Algorithm="{XMLDSIG_ENVELOPED_SIGNATURE}"></Transform>"#);
        signed_pacs008_xml().replace(&wrapped, &unwrapped)
    } => "Reference transforms outside Transforms wrapper must fail closed";
    require_verified_profile_rejects_payload_digest_tampering: {
        signed_pacs008_xml().replace(">10.00<", ">10.01<")
    } => "reference digest mismatch must fail closed";
    require_verified_profile_rejects_signed_properties_digest_tampering: {
        signed_pacs008_xml_with_signed_properties_reference()
            .replace(XML_SIGNATURE_TEST_SIGNING_TIME, "2025-01-01T12:00:01Z")
    } => "SignedProperties digest tampering must fail closed";
    require_verified_profile_rejects_signed_properties_target_drift: {
        signed_pacs008_xml_with_signed_properties_reference()
            .replace(r##"Target="#sig-001""##, r##"Target="#other-sig""##)
    } => "QualifyingProperties Target must bind to the enclosing Signature Id";
    require_verified_profile_rejects_wrapped_qualifying_properties: {
        signed_pacs008_xml_with_signed_properties_reference()
            .replacen(
                &format!(r##"<Object><QualifyingProperties xmlns="{XADES_NS}" Target="#sig-001">"##),
                &format!(r##"<Object><Wrapper><QualifyingProperties xmlns="{XADES_NS}" Target="#sig-001">"##),
                1,
            )
            .replacen(
                "</QualifyingProperties></Object>",
                "</QualifyingProperties></Wrapper></Object>",
                1,
            )
    } => "wrapped QualifyingProperties must fail closed";
    require_verified_profile_rejects_wrapped_xades_signed_properties: {
        signed_pacs008_xml_with_signed_properties_reference()
            .replacen("<SignedProperties", "<Wrapper><SignedProperties", 1)
            .replacen("</SignedProperties>", "</SignedProperties></Wrapper>", 1)
    } => "wrapped XAdES SignedProperties must fail closed";
    require_verified_profile_rejects_signature_value_tampering: {
        signed_pacs008_xml().replacen("<SignatureValue>", "<SignatureValue>A", 1)
    } => "invalid signature bytes must fail closed";
    require_verified_profile_rejects_high_s_signature_value: {
        let payload = signed_pacs008_xml();
        let signature_value_start =
            payload.find("<SignatureValue>").expect("SignatureValue") + "<SignatureValue>".len();
        let signature_value_end = payload
            .find("</SignatureValue>")
            .expect("SignatureValue end");
        let signature_value = BASE64_STANDARD
            .decode(&payload[signature_value_start..signature_value_end])
            .expect("fixture SignatureValue base64");
        let signature =
            P256Signature::from_der(&signature_value).expect("fixture DER SignatureValue");
        let high_s = high_s_p256_signature(signature);
        let high_s_signature_value = BASE64_STANDARD.encode(high_s.to_der().as_bytes());
        format!(
            "{}{}{}",
            &payload[..signature_value_start],
            high_s_signature_value,
            &payload[signature_value_end..]
        )
    } => "high-S SignatureValue must fail closed";
    require_verified_profile_rejects_duplicate_signature_value: {
        signed_pacs008_xml().replacen(
            "</SignatureValue>",
            "</SignatureValue><SignatureValue>AA==</SignatureValue>",
            1,
        )
    } => "duplicate SignatureValue elements must fail closed";
    require_verified_profile_rejects_signature_value_unsupported_attribute: {
        signed_pacs008_xml().replacen(
            "<SignatureValue>",
            "<SignatureValue Id=\"signature-value-001\">",
            1,
        )
    } => "unsupported SignatureValue attributes must fail closed";
    require_verified_profile_rejects_duplicate_digest_value: {
        signed_pacs008_xml().replacen(
            "</DigestValue>",
            "</DigestValue><DigestValue>AA==</DigestValue>",
            1,
        )
    } => "duplicate DigestValue elements must fail closed";
    require_verified_profile_rejects_duplicate_public_key: {
        signed_pacs008_xml().replacen(
            "</PublicKey>",
            "</PublicKey><PublicKey>AA==</PublicKey>",
            1,
        )
    } => "duplicate PublicKey elements must fail closed";
    require_verified_profile_rejects_public_key_nested_markup: {
        signed_pacs008_xml().replacen("</PublicKey>", "<Chunk></Chunk></PublicKey>", 1)
    } => "nested PublicKey markup must fail closed";
    require_verified_profile_rejects_duplicate_key_info: {
        signed_pacs008_xml().replacen(
            "</KeyInfo>",
            "</KeyInfo><KeyInfo><PublicKey>AQ==</PublicKey></KeyInfo>",
            1,
        )
    } => "duplicate KeyInfo elements must fail closed";
    require_verified_profile_rejects_public_key_outside_key_info: {
        signed_pacs008_xml().replacen("<KeyInfo>", "<PublicKey>AQ==</PublicKey><KeyInfo>", 1)
    } => "PublicKey outside KeyInfo must fail closed";
    require_verified_profile_rejects_public_key_wrong_named_curve: {
        signed_pacs008_xml().replace(XMLDSIG_P256_NAMED_CURVE, "urn:oid:1.3.132.0.34")
    } => "PublicKey must declare the supported P-256 NamedCurve";
    require_verified_profile_rejects_public_key_without_key_value_wrapper: {
        signed_pacs008_xml()
            .replace("<KeyInfo><KeyValue><ECKeyValue>", "<KeyInfo><ECKeyValue>")
            .replace(
                "</ECKeyValue></KeyValue></KeyInfo>",
                "</ECKeyValue></KeyInfo>",
            )
    } => "PublicKey must be wrapped in KeyValue/ECKeyValue";
    require_verified_profile_rejects_key_info_extra_child: {
        signed_pacs008_xml().replacen(
            "</KeyInfo>",
            "<RetrievalMethod></RetrievalMethod></KeyInfo>",
            1,
        )
    } => "unsupported KeyInfo child elements must fail closed";
    require_verified_profile_rejects_key_value_extra_child: {
        signed_pacs008_xml().replacen(
            "</KeyValue>",
            "<ECParameters></ECParameters></KeyValue>",
            1,
        )
    } => "unsupported KeyValue child elements must fail closed";
    require_verified_profile_rejects_ec_key_value_extra_child: {
        signed_pacs008_xml().replacen(
            "</ECKeyValue>",
            "<ECParameters></ECParameters></ECKeyValue>",
            1,
        )
    } => "unsupported ECKeyValue child elements must fail closed";
    require_verified_profile_rejects_key_info_unsupported_attribute: {
        signed_pacs008_xml().replacen("<KeyInfo>", "<KeyInfo Id=\"key-001\">", 1)
    } => "unsupported KeyInfo attributes must fail closed";
    require_verified_profile_rejects_named_curve_unsupported_attribute: {
        signed_pacs008_xml().replacen("<NamedCurve URI=", "<NamedCurve Type=\"named\" URI=", 1)
    } => "unsupported NamedCurve attributes must fail closed";
    require_verified_profile_rejects_mixed_public_key_and_certificate_material: {
        signed_pacs008_xml().replacen(
            "</KeyInfo>",
            "<X509Data><X509Certificate>AQ==</X509Certificate></X509Data></KeyInfo>",
            1,
        )
    } => "mixed PublicKey and X509Certificate key material must fail closed";
}
#[test]
fn require_verified_profile_accepts_xades_signing_certificate_v2_binding() {
    let CertificateChainSignedPropertiesPayload {
        payload,
        issuer_sha256,
        ..
    } = signed_pacs008_xml_with_certificate_chain_signed_properties_reference();
    let metadata = validate_require_verified_signed_payload(&payload, move |profile| {
        profile.signature_public_key_sha256_pins.clear();
        profile.x509_trust_anchor_sha256_pins = vec![issuer_sha256];
    })
    .expect("SigningCertificateV2 leaf digest should bind to the XMLDSig leaf certificate");
    assert!(metadata.embedded_signature_detected());
    assert_eq!(metadata.business_message_id(), Some("sig-001"));
}
#[test]
fn require_verified_profile_accepts_supported_canonicalization_algorithms() {
    for c14n_algorithm in [XML_C14N_1_1, XML_EXCLUSIVE_C14N_1_0] {
        let mut config = sample_config();
        config
            .profiles
            .push(signed_message_profile("require-verified"));
        let runtime = Iso20022BridgeRuntime::from_config(&config)
            .expect("cfg")
            .expect("enabled");
        let payload = signed_pacs008_xml_with_c14n_algorithm(c14n_algorithm);
        let parsed = parse_message("pacs.008", payload.as_bytes()).expect("parse signed XML");
        let profile = runtime
            .resolve_profile(Some("signed-pacs008-test"))
            .expect("signed profile");
        runtime
            .validate_profile_submission(profile, "pacs.008", &parsed, payload.as_bytes())
            .expect("supported canonicalization URI should pass");
    }
}
#[test]
fn supported_xml_canonicalizer_expands_empty_elements_and_sorts_attributes() {
    let canonical =
        canonicalize_supported_xml(r#"<A z='last' xmlns="urn:test" a="first"><B /></A>"#)
            .expect("supported XML subset should canonicalize");
    assert_eq!(
        canonical,
        r#"<A xmlns="urn:test" a="first" z="last"><B></B></A>"#
    );
}
#[test]
fn supported_xml_canonicalizer_decodes_character_references() {
    let canonical = canonicalize_supported_xml(
        r#"<A attr='&quot;&amp;&lt;&apos;&#x9;&#10;&#xD;'>one&amp;&lt;&gt;&#13;</A>"#,
    )
    .expect("predefined and numeric XML character references should canonicalize");
    assert_eq!(
        canonical,
        r#"<A attr="&quot;&amp;&lt;'&#x9;&#xA;&#xD;">one&amp;&lt;&gt;&#xD;</A>"#
    );
}
#[test]
fn supported_xml_canonicalizer_accepts_xml_namespace_attributes() {
    let canonical =
        canonicalize_supported_xml(r#"<A z='last' xml:lang="en" a="first" xml:id='id-1'></A>"#)
            .expect("implicit xml namespace attributes are inside the supported subset");
    assert_eq!(
        canonical,
        r#"<A a="first" z="last" xml:id="id-1" xml:lang="en"></A>"#
    );
}
#[test]
fn supported_xml_canonicalizer_omits_legal_xml_namespace_declaration() {
    let canonical = canonicalize_supported_xml(
            r#"<A xmlns:xml="http://www.w3.org/XML/1998/namespace" xml:lang="en"><B xml:id="b-1"></B></A>"#,
        )
        .expect("the fixed XML namespace declaration should be accepted and omitted");
    assert_eq!(canonical, r#"<A xml:lang="en"><B xml:id="b-1"></B></A>"#);
    let inherited_namespaces = vec![CanonicalXmlAttribute {
        name: "xmlns:xml".to_owned(),
        value: XML_NS.to_owned(),
        kind: CanonicalXmlAttributeKind::Namespace,
    }];
    let canonical = canonicalize_supported_xml_with_mode(
        r#"<A xml:space="preserve"></A>"#,
        &inherited_namespaces,
        CanonicalXmlMode::Inclusive,
    )
    .expect("inherited XML namespace declaration should not serialize");
    assert_eq!(canonical, r#"<A xml:space="preserve"></A>"#);
}
#[test]
fn supported_xml_reference_target_resolves_same_document_id() {
    let xml = r#"<A><B xml:id="target"><C Id="other"></C></B></A>"#;
    let target = xml_signature_reference_target(xml, "#target")
        .expect("same-document xml:id reference should resolve");
    assert_eq!(target.xml, r#"<B xml:id="target"><C Id="other"></C></B>"#);
}
#[test]
fn supported_xml_reference_target_carries_inherited_namespaces() {
    let xml =
        r#"<Root xmlns:p="urn:p"><p:Payload Id="target"><p:Child></p:Child></p:Payload></Root>"#;
    let target = xml_signature_reference_target(xml, "#target")
        .expect("same-document reference target should inherit ancestor namespaces");
    let canonical = canonicalize_supported_xml_with_inherited_namespaces(
        target.xml,
        &target.inherited_namespaces,
    )
    .expect("inherited namespace should canonicalize on referenced root");
    assert_eq!(
        canonical,
        r#"<p:Payload xmlns:p="urn:p" Id="target"><p:Child></p:Child></p:Payload>"#
    );
}
#[test]
fn supported_xml_reference_target_rejects_invalid_same_document_uris() {
    for uri in [
        "target",
        "https://example.invalid/#target",
        "#",
        "#bad:prefix",
    ] {
        let err = xml_signature_reference_target(r#"<A Id="target"></A>"#, uri)
            .expect_err("unsupported Reference URIs must fail closed");
        assert!(matches!(err, MsgError::ValidationFailed));
    }
    let err = xml_signature_reference_target(r#"<A Id="dup"><B Id="dup"></B></A>"#, "#dup")
        .expect_err("duplicate same-document IDs must fail closed");
    assert!(matches!(err, MsgError::ValidationFailed));
    let err =
        xml_signature_reference_target(r#"<A xmlns:p="urn:test" p:Id="target"></A>"#, "#target")
            .expect_err("namespace-qualified non-xml ID attributes must fail closed");
    assert!(matches!(err, MsgError::ValidationFailed));
}
#[test]
fn supported_xml_reference_transform_accepts_optional_c14n_transform() {
    let inherited_namespaces = default_xmlsig_namespace_bindings();
    let valid = format!(
        r#"<Reference URI=""><Transforms><Transform Algorithm="{XMLDSIG_ENVELOPED_SIGNATURE}"></Transform></Transforms></Reference>"#
    );
    assert_eq!(
        supported_xml_signature_reference_c14n_mode_with_namespaces(&valid, &inherited_namespaces)
            .expect("the supported Reference transform set should pass"),
        CanonicalXmlMode::Exclusive
    );
    let valid_with_c14n = format!(
        r#"<Reference URI=""><Transforms><Transform Algorithm="{XMLDSIG_ENVELOPED_SIGNATURE}"></Transform><Transform Algorithm="{XML_C14N_1_0}"></Transform></Transforms></Reference>"#
    );
    assert_eq!(
        supported_xml_signature_reference_c14n_mode_with_namespaces(
            &valid_with_c14n,
            &inherited_namespaces,
        )
        .expect("a final supported C14N transform should pass"),
        CanonicalXmlMode::Inclusive
    );
    let valid_with_transform_comments = format!(
        r#"<Reference URI=""><Transforms><!--before--><Transform Algorithm="{XMLDSIG_ENVELOPED_SIGNATURE}"></Transform><!--after--></Transforms></Reference>"#
    );
    assert_eq!(
        supported_xml_signature_reference_c14n_mode_with_namespaces(
            &valid_with_transform_comments,
            &inherited_namespaces,
        )
        .expect("comments in no-comments SignedInfo transform wrappers should pass"),
        CanonicalXmlMode::Exclusive
    );
    for reference in [
            format!(
                r#"<Reference URI="" Id="ref-001"><Transforms><Transform Algorithm="{XMLDSIG_ENVELOPED_SIGNATURE}"></Transform></Transforms></Reference>"#
            ),
            format!(
                r#"<Reference ds:URI="" xmlns:ds="{XMLDSIG_NS}"><Transforms><Transform Algorithm="{XMLDSIG_ENVELOPED_SIGNATURE}"></Transform></Transforms></Reference>"#
            ),
            r#"<Reference URI=""><Transforms></Transforms></Reference>"#.to_owned(),
            format!(
                r#"<Reference URI=""><Transforms Id="transforms-001"><Transform Algorithm="{XMLDSIG_ENVELOPED_SIGNATURE}"></Transform></Transforms></Reference>"#
            ),
            format!(
                r#"<Reference URI=""><Transforms><Transform Id="transform-001" Algorithm="{XMLDSIG_ENVELOPED_SIGNATURE}"></Transform></Transforms></Reference>"#
            ),
            format!(
                r#"<Reference URI=""><Transforms><Transform ds:Algorithm="{XMLDSIG_ENVELOPED_SIGNATURE}" xmlns:ds="{XMLDSIG_NS}"></Transform></Transforms></Reference>"#
            ),
            format!(
                r#"<Reference URI=""><Transforms><Ignored></Ignored><Transform Algorithm="{XMLDSIG_ENVELOPED_SIGNATURE}"></Transform></Transforms></Reference>"#
            ),
            format!(
                r#"<Reference URI=""><Transforms><Transform Algorithm="{XMLDSIG_ENVELOPED_SIGNATURE}"></Transform><Ignored></Ignored></Transforms></Reference>"#
            ),
            format!(
                r#"<Reference URI=""><DigestMethod Algorithm="{XMLDSIG_SHA256}"></DigestMethod><Transforms><Transform Algorithm="{XMLDSIG_ENVELOPED_SIGNATURE}"></Transform></Transforms><DigestValue>AQ==</DigestValue></Reference>"#
            ),
            format!(
                r#"<Reference URI=""><Transforms><Transform Algorithm="{XMLDSIG_ENVELOPED_SIGNATURE}"></Transform></Transforms><DigestValue>AQ==</DigestValue><DigestMethod Algorithm="{XMLDSIG_SHA256}"></DigestMethod></Reference>"#
            ),
            format!(
                r#"<Reference URI=""><Object></Object><Transforms><Transform Algorithm="{XMLDSIG_ENVELOPED_SIGNATURE}"></Transform></Transforms></Reference>"#
            ),
            format!(
                r#"<Reference URI=""><Transform Algorithm="{XMLDSIG_ENVELOPED_SIGNATURE}"></Transform></Reference>"#
            ),
            format!(
                r#"<Reference URI=""><Transforms><Transform Algorithm="{XML_C14N_1_0}"></Transform></Transforms></Reference>"#
            ),
            format!(
                r#"<Reference URI=""><Transforms><Transform Algorithm="{XML_C14N_1_0}"></Transform><Transform Algorithm="{XMLDSIG_ENVELOPED_SIGNATURE}"></Transform></Transforms></Reference>"#
            ),
            r#"<Reference URI=""><Transforms><Transform Algorithm="urn:unsupported"></Transform></Transforms></Reference>"#
                .to_owned(),
            format!(
                r#"<Reference URI=""><Transforms><Transform Algorithm="{XMLDSIG_ENVELOPED_SIGNATURE}"></Transform><Transform Algorithm="urn:unsupported"></Transform></Transforms></Reference>"#
            ),
            format!(
                r#"<Reference URI=""><Transforms><Transform Algorithm="{XMLDSIG_ENVELOPED_SIGNATURE}"><XPath>not-supported</XPath></Transform></Transforms></Reference>"#
            ),
            format!(
                r#"<Reference URI=""><Transforms><Transform Algorithm="{XMLDSIG_ENVELOPED_SIGNATURE}"></Transform><Transform Algorithm="{XML_C14N_1_0}"><InclusiveNamespaces PrefixList="unused"></InclusiveNamespaces></Transform></Transforms></Reference>"#
            ),
            format!(
                r#"<Reference URI=""><Transforms><Transform Algorithm="{XMLDSIG_ENVELOPED_SIGNATURE}"></Transform></Transforms><Transforms><Transform Algorithm="{XML_C14N_1_0}"></Transform></Transforms></Reference>"#
            ),
            format!(
                r#"<Reference URI=""><Transforms><Transform Algorithm="{XMLDSIG_ENVELOPED_SIGNATURE}"></Transform></Transforms><Transform Algorithm="{XML_C14N_1_0}"></Transform></Reference>"#
            ),
            format!(
                r#"<Reference URI=""><Transforms><Transform Algorithm="{XMLDSIG_ENVELOPED_SIGNATURE}"></Transform><Transform Algorithm="{XML_C14N_1_0}"></Transform><Transform Algorithm="{XML_EXCLUSIVE_C14N_1_0}"></Transform></Transforms></Reference>"#
            ),
        ] {
            let err = supported_xml_signature_reference_c14n_mode_with_namespaces(
                &reference,
                &inherited_namespaces,
            )
                .expect_err("missing, reordered, extra, or unsupported transforms must fail closed");
            assert!(matches!(err, MsgError::ValidationFailed));
        }
}
#[test]
fn supported_xml_signature_reference_rejects_wrong_prefixed_namespace() {
    let inherited_namespaces = vec![CanonicalXmlNamespaceBinding {
        prefix: "ds".to_owned(),
        uri: XMLDSIG_NS.to_owned(),
    }];
    let valid = format!(
        r#"<ds:Reference URI=""><ds:Transforms><ds:Transform Algorithm="{XMLDSIG_ENVELOPED_SIGNATURE}"></ds:Transform></ds:Transforms></ds:Reference>"#
    );
    assert_eq!(
        supported_xml_signature_reference_c14n_mode_with_namespaces(&valid, &inherited_namespaces)
            .expect("XMLDSig-prefixed Reference should resolve through inherited namespace"),
        CanonicalXmlMode::Exclusive
    );
    let wrong_transforms = format!(
        r#"<ds:Reference URI=""><bad:Transforms xmlns:bad="urn:not-xmldsig"><ds:Transform Algorithm="{XMLDSIG_ENVELOPED_SIGNATURE}"></ds:Transform></bad:Transforms></ds:Reference>"#
    );
    let err = supported_xml_signature_reference_c14n_mode_with_namespaces(
        &wrong_transforms,
        &inherited_namespaces,
    )
    .expect_err("Transforms bound outside XMLDSig must fail closed");
    assert!(matches!(err, MsgError::ValidationFailed));
    let canonical = "<Document></Document>";
    let digest = BASE64_STANDARD.encode(Sha256::digest(canonical.as_bytes()));
    let wrong_digest_method = format!(
        r#"<ds:Reference URI=""><ds:DigestMethod xmlns:bad="urn:not-xmldsig" Algorithm="{XMLDSIG_SHA256}"></ds:DigestMethod><bad:DigestValue xmlns:bad="urn:not-xmldsig">{digest}</bad:DigestValue></ds:Reference>"#
    );
    let err = verify_xml_signature_reference_digest_with_namespaces(
        &wrong_digest_method,
        canonical,
        &inherited_namespaces,
    )
    .expect_err("DigestValue bound outside XMLDSig must fail closed");
    assert!(matches!(err, MsgError::ValidationFailed));
}
#[test]
fn supported_xml_signature_reference_rejects_malformed_qnames() {
    let inherited_namespaces = default_xmlsig_namespace_bindings();
    let malformed_reference = format!(
        r#"<ds::Reference xmlns:ds="{XMLDSIG_NS}" URI=""><Transforms><Transform Algorithm="{XMLDSIG_ENVELOPED_SIGNATURE}"></Transform></Transforms></ds::Reference>"#
    );
    let err = supported_xml_signature_reference_c14n_mode_with_namespaces(
        &malformed_reference,
        &inherited_namespaces,
    )
    .expect_err("malformed XMLDSig Reference QName must fail closed");
    assert!(matches!(err, MsgError::ValidationFailed));
    let malformed_transform = format!(
        r#"<Reference URI=""><Transforms><ds::Transform xmlns:ds="{XMLDSIG_NS}" Algorithm="{XMLDSIG_ENVELOPED_SIGNATURE}"></ds::Transform></Transforms></Reference>"#
    );
    let err = supported_xml_signature_reference_c14n_mode_with_namespaces(
        &malformed_transform,
        &inherited_namespaces,
    )
    .expect_err("malformed direct XMLDSig Transform QName must fail closed");
    assert!(matches!(err, MsgError::ValidationFailed));
    let canonical = "<Document></Document>";
    let digest = BASE64_STANDARD.encode(Sha256::digest(canonical.as_bytes()));
    let malformed_digest_method = format!(
        r#"<Reference URI=""><ds::DigestMethod xmlns:ds="{XMLDSIG_NS}" Algorithm="{XMLDSIG_SHA256}"></ds::DigestMethod><DigestValue>{digest}</DigestValue></Reference>"#
    );
    let err = verify_xml_signature_reference_digest_with_namespaces(
        &malformed_digest_method,
        canonical,
        &inherited_namespaces,
    )
    .expect_err("malformed namespace-bound DigestMethod QName must fail closed");
    assert!(matches!(err, MsgError::ValidationFailed));
}
#[test]
fn supported_xml_signed_properties_reference_requires_supported_c14n_transform() {
    let inherited_namespaces = default_xmlsig_namespace_bindings();
    let valid = format!(
        r##"<Reference URI="#signed-props-001" Type="{XADES_SIGNED_PROPERTIES_TYPE}"><Transforms><Transform Algorithm="{XML_EXCLUSIVE_C14N_1_0}"></Transform></Transforms></Reference>"##
    );
    assert_eq!(
        signed_properties_reference_c14n_mode_with_namespaces(&valid, &inherited_namespaces)
            .expect("SignedProperties Reference with supported C14N should pass"),
        CanonicalXmlMode::Exclusive
    );
    for reference in [
            format!(
                r##"<Reference URI="#signed-props-001" Type="{XADES_SIGNED_PROPERTIES_TYPE}" Id="ref-001"><Transforms><Transform Algorithm="{XML_EXCLUSIVE_C14N_1_0}"></Transform></Transforms></Reference>"##
            ),
            r##"<Reference URI="#signed-props-001" Type="http://uri.etsi.org/01903#SignedProperties"><Transforms></Transforms></Reference>"##
                .to_owned(),
            format!(
                r##"<Reference URI="#signed-props-001" Type="{XADES_SIGNED_PROPERTIES_TYPE}"><Transforms Id="transforms-001"><Transform Algorithm="{XML_EXCLUSIVE_C14N_1_0}"></Transform></Transforms></Reference>"##
            ),
            format!(
                r##"<Reference URI="#signed-props-001" Type="{XADES_SIGNED_PROPERTIES_TYPE}"><Transforms><Transform Id="transform-001" Algorithm="{XML_EXCLUSIVE_C14N_1_0}"></Transform></Transforms></Reference>"##
            ),
            format!(
                r##"<Reference URI="#signed-props-001" Type="{XADES_SIGNED_PROPERTIES_TYPE}"><Transforms><Ignored></Ignored><Transform Algorithm="{XML_EXCLUSIVE_C14N_1_0}"></Transform></Transforms></Reference>"##
            ),
            format!(
                r##"<Reference URI="#signed-props-001" Type="{XADES_SIGNED_PROPERTIES_TYPE}"><DigestMethod Algorithm="{XMLDSIG_SHA256}"></DigestMethod><Transforms><Transform Algorithm="{XML_EXCLUSIVE_C14N_1_0}"></Transform></Transforms><DigestValue>AQ==</DigestValue></Reference>"##
            ),
            format!(
                r##"<Reference URI="#signed-props-001" Type="{XADES_SIGNED_PROPERTIES_TYPE}"><Transforms><Transform Algorithm="{XML_EXCLUSIVE_C14N_1_0}"></Transform></Transforms><DigestValue>AQ==</DigestValue><DigestMethod Algorithm="{XMLDSIG_SHA256}"></DigestMethod></Reference>"##
            ),
            format!(
                r##"<Reference URI="#signed-props-001" Type="{XADES_SIGNED_PROPERTIES_TYPE}"><Object></Object><Transforms><Transform Algorithm="{XML_EXCLUSIVE_C14N_1_0}"></Transform></Transforms></Reference>"##
            ),
            format!(
                r##"<Reference URI="#signed-props-001" Type="{XADES_SIGNED_PROPERTIES_TYPE}"><Transform Algorithm="{XML_EXCLUSIVE_C14N_1_0}"></Transform></Reference>"##
            ),
            r##"<Reference URI="#signed-props-001" Type="http://uri.etsi.org/01903#SignedProperties"><Transforms><Transform Algorithm="urn:unsupported"></Transform></Transforms></Reference>"##
                .to_owned(),
            format!(
                r##"<Reference URI="#signed-props-001" Type="{XADES_SIGNED_PROPERTIES_TYPE}"><Transforms><Transform Algorithm="{XML_EXCLUSIVE_C14N_1_0}"><InclusiveNamespaces PrefixList="ds"></InclusiveNamespaces></Transform></Transforms></Reference>"##
            ),
            format!(
                r##"<Reference URI="#signed-props-001" Type="{XADES_SIGNED_PROPERTIES_TYPE}"><Transforms><Transform Algorithm="{XML_EXCLUSIVE_C14N_1_0}"></Transform></Transforms><Transforms><Transform Algorithm="{XML_C14N_1_0}"></Transform></Transforms></Reference>"##
            ),
            format!(
                r##"<Reference URI="#signed-props-001" Type="{XADES_SIGNED_PROPERTIES_TYPE}"><Transforms><Transform Algorithm="{XML_C14N_1_0}"></Transform><Transform Algorithm="{XML_C14N_1_1}"></Transform></Transforms></Reference>"##
            ),
        ] {
            let err = signed_properties_reference_c14n_mode_with_namespaces(
                &reference,
                &inherited_namespaces,
            )
                .expect_err("SignedProperties references require one supported C14N transform");
            assert!(matches!(err, MsgError::ValidationFailed));
        }
}
#[test]
fn supported_xml_reference_digest_rejects_digest_method_unsupported_attributes() {
    let inherited_namespaces = default_xmlsig_namespace_bindings();
    let canonical = "<Document></Document>";
    let digest = BASE64_STANDARD.encode(Sha256::digest(canonical.as_bytes()));
    let valid = format!(
        r#"<Reference URI=""><DigestMethod Algorithm="{XMLDSIG_SHA256}"></DigestMethod><DigestValue>{digest}</DigestValue></Reference>"#
    );
    verify_xml_signature_reference_digest_with_namespaces(&valid, canonical, &inherited_namespaces)
        .expect("SHA-256 Reference digest should pass");
    let invalid = format!(
        r#"<Reference URI=""><DigestMethod Algorithm="{XMLDSIG_SHA256}" Id="digest-method-001"></DigestMethod><DigestValue>{digest}</DigestValue></Reference>"#
    );
    let err = verify_xml_signature_reference_digest_with_namespaces(
        &invalid,
        canonical,
        &inherited_namespaces,
    )
    .expect_err("unsupported DigestMethod attributes must fail closed");
    assert!(matches!(err, MsgError::ValidationFailed));
    let namespace_qualified_algorithm = format!(
        r#"<Reference URI=""><DigestMethod ds:Algorithm="{XMLDSIG_SHA256}" xmlns:ds="{XMLDSIG_NS}"></DigestMethod><DigestValue>{digest}</DigestValue></Reference>"#
    );
    let err = verify_xml_signature_reference_digest_with_namespaces(
        &namespace_qualified_algorithm,
        canonical,
        &inherited_namespaces,
    )
    .expect_err("namespace-qualified DigestMethod Algorithm must fail closed");
    assert!(matches!(err, MsgError::ValidationFailed));
}
#[test]
fn supported_xml_signed_properties_reference_verifies_generated_fixture() {
    let payload = signed_pacs008_xml_with_signed_properties_reference();
    let signature_span = find_first_xml_element(&payload, "Signature").expect("signature");
    let signature_xml = &payload[signature_span.start..signature_span.end];
    ensure_xades_qualifying_properties_target(signature_xml)
        .expect("QualifyingProperties Target should bind to Signature Id");
    let signed_info_span = find_first_xml_element(signature_xml, "SignedInfo").expect("SignedInfo");
    let signed_info_xml = &signature_xml[signed_info_span.start..signed_info_span.end];
    let inherited_namespaces = default_xmlsig_namespace_bindings();
    verify_xml_signature_references(
        &payload,
        signature_span,
        signature_span,
        signature_xml,
        signed_info_xml,
        &inherited_namespaces,
    )
    .expect("generated XAdES fixture references should verify");
}
#[test]
fn supported_xml_xades_qualifying_properties_requires_direct_shape() {
    let payload = signed_pacs008_xml_with_signed_properties_reference();
    let signature_span = find_first_xml_element(&payload, "Signature").expect("signature");
    let signature_xml = &payload[signature_span.start..signature_span.end];
    ensure_xades_qualifying_properties_target(signature_xml)
        .expect("direct XAdES QualifyingProperties should be accepted");
    let prefixed_signature = format!(
        r##"<Signature xmlns="{XMLDSIG_NS}" Id="sig-001"><Object><xades:QualifyingProperties xmlns:xades="{XADES_NS}" Target="#sig-001"><xades:SignedProperties Id="signed-props-001"></xades:SignedProperties></xades:QualifyingProperties></Object></Signature>"##
    );
    ensure_xades_qualifying_properties_target(&prefixed_signature)
        .expect("prefixed XAdES QualifyingProperties should bind to the supported namespace");
    for invalid_payload in [
            format!(
                r##"<Signature xmlns="{XMLDSIG_NS}" Id="sig-001"><Object><xades:QualifyingProperties xmlns:xades="urn:not-xades" Target="#sig-001"><xades:SignedProperties Id="signed-props-001"></xades:SignedProperties></xades:QualifyingProperties></Object></Signature>"##
            ),
            format!(r##"<Signature xmlns="{XMLDSIG_NS}" Id="sig-001"><Object><QualifyingProperties xmlns="urn:not-xades" Target="#sig-001"><SignedProperties Id="signed-props-001"></SignedProperties></QualifyingProperties></Object></Signature>"##),
            signed_pacs008_xml_with_signed_properties_reference().replacen(
                &format!(r##"<QualifyingProperties xmlns="{XADES_NS}" Target="#sig-001">"##),
                &format!(r##"<QualifyingProperties xmlns="{XADES_NS}" Target="#sig-001" Id="qp-001">"##),
                1,
            ),
            signed_pacs008_xml_with_signed_properties_reference()
                .replacen(
                    &format!(r##"<Object><QualifyingProperties xmlns="{XADES_NS}" Target="#sig-001">"##),
                    &format!(r##"<Object><Wrapper><QualifyingProperties xmlns="{XADES_NS}" Target="#sig-001">"##),
                    1,
                )
                .replacen(
                    "</QualifyingProperties></Object>",
                    "</QualifyingProperties></Wrapper></Object>",
                    1,
                ),
            signed_pacs008_xml_with_signed_properties_reference()
                .replacen("<SignedProperties", "<Wrapper><SignedProperties", 1)
                .replacen("</SignedProperties>", "</SignedProperties></Wrapper>", 1),
            signed_pacs008_xml_with_signed_properties_reference().replacen(
                "</SignedProperties>",
                "</SignedProperties><UnsignedProperties></UnsignedProperties>",
                1,
            ),
        ] {
            let signature_span =
                find_first_xml_element(&invalid_payload, "Signature").expect("signature");
            let signature_xml = &invalid_payload[signature_span.start..signature_span.end];
            let err = ensure_xades_qualifying_properties_target(signature_xml)
                .expect_err("unsupported XAdES wrapper shape must fail closed");
            assert!(matches!(err, MsgError::ValidationFailed));
        }
}
#[test]
fn supported_xml_xades_signing_certificate_v2_requires_direct_cert_children() {
    let digest = BASE64_STANDARD.encode([7_u8; 32]);
    let cert = format!(
        r#"<Cert><CertDigest xmlns:ds="{XMLDSIG_NS}"><ds:DigestMethod Algorithm="{XMLDSIG_SHA256}"></ds:DigestMethod><ds:DigestValue>{digest}</ds:DigestValue></CertDigest></Cert>"#
    );
    let valid =
        format!(r#"<SigningCertificateV2 xmlns="{XADES_NS}">{cert}</SigningCertificateV2>"#);
    assert_eq!(
        xades_signing_certificate_v2_digests(&valid)
            .expect("direct Cert children should be accepted"),
        vec![lower_hex(&[7_u8; 32])]
    );
    let prefixed_cert = format!(
        r#"<xades:Cert><xades:CertDigest xmlns:ds="{XMLDSIG_NS}"><ds:DigestMethod Algorithm="{XMLDSIG_SHA256}"></ds:DigestMethod><ds:DigestValue>{digest}</ds:DigestValue></xades:CertDigest></xades:Cert>"#
    );
    let prefixed = format!(
        r#"<xades:SigningCertificateV2 xmlns:xades="{XADES_NS}">{prefixed_cert}</xades:SigningCertificateV2>"#
    );
    assert_eq!(
        xades_signing_certificate_v2_digests(&prefixed)
            .expect("prefixed XAdES SigningCertificateV2 should decode"),
        vec![lower_hex(&[7_u8; 32])]
    );
    for invalid in [
        format!(
            r#"<xades:SigningCertificateV2 xmlns:xades="urn:not-xades">{prefixed_cert}</xades:SigningCertificateV2>"#
        ),
        format!(
            r#"<SigningCertificateV2 xmlns="{XADES_NS}" Id="certs-001">{cert}</SigningCertificateV2>"#
        ),
        format!(
            r#"<SigningCertificateV2 xmlns="{XADES_NS}"><Wrapper>{cert}</Wrapper></SigningCertificateV2>"#
        ),
        format!(
            r#"<SigningCertificateV2 xmlns="{XADES_NS}">{cert}<Wrapper>{cert}</Wrapper></SigningCertificateV2>"#
        ),
    ] {
        let err = xades_signing_certificate_v2_digests(&invalid)
            .expect_err("wrapped Cert children must fail closed");
        assert!(matches!(err, MsgError::ValidationFailed));
    }
}
#[test]
fn supported_xml_xades_signing_certificate_v2_binds_ordered_chain_prefix() {
    let leaf = [1_u8; 32];
    let issuer = [2_u8; 32];
    let root = [3_u8; 32];
    let extra = [4_u8; 32];
    let key_material = XmlSignatureKeyMaterial {
        public_key: Vec::new(),
        certificate_sha256: vec![lower_hex(&leaf), lower_hex(&issuer), lower_hex(&root)],
    };
    for valid in [
        signed_properties_xml_with_signing_certificate_v2_digest_bytes("signed-props-001", &[leaf]),
        signed_properties_xml_with_signing_certificate_v2_digest_bytes(
            "signed-props-001",
            &[leaf, issuer],
        ),
        signed_properties_xml_with_signing_certificate_v2_digest_bytes(
            "signed-props-001",
            &[leaf, issuer, root],
        ),
    ] {
        verify_xades_signing_certificate_v2_binding(&valid, &key_material)
            .expect("ordered certificate chain prefix should be accepted");
    }
    for invalid in [
        signed_properties_xml_with_signing_certificate_v2_digest_bytes(
            "signed-props-001",
            &[issuer],
        ),
        signed_properties_xml_with_signing_certificate_v2_digest_bytes(
            "signed-props-001",
            &[leaf, root],
        ),
        signed_properties_xml_with_signing_certificate_v2_digest_bytes(
            "signed-props-001",
            &[leaf, leaf],
        ),
        signed_properties_xml_with_signing_certificate_v2_digest_bytes(
            "signed-props-001",
            &[leaf, issuer, leaf],
        ),
        signed_properties_xml_with_signing_certificate_v2_digest_bytes(
            "signed-props-001",
            &[leaf, issuer, root, extra],
        ),
    ] {
        let err = verify_xades_signing_certificate_v2_binding(&invalid, &key_material)
            .expect_err("unordered, duplicate, or unknown chain digest must fail closed");
        assert!(matches!(err, MsgError::ValidationFailed));
    }
}
#[test]
fn supported_xml_xades_cert_digest_requires_direct_child() {
    let digest = BASE64_STANDARD.encode([9_u8; 32]);
    let cert_digest = format!(
        r#"<CertDigest xmlns:ds="{XMLDSIG_NS}"><ds:DigestMethod Algorithm="{XMLDSIG_SHA256}"></ds:DigestMethod><ds:DigestValue>{digest}</ds:DigestValue></CertDigest>"#
    );
    let valid = format!(r#"<Cert xmlns="{XADES_NS}">{cert_digest}</Cert>"#);
    assert_eq!(
        xades_cert_digest_sha256(&valid).expect("direct CertDigest should be accepted"),
        lower_hex(&[9_u8; 32])
    );
    for invalid in [
        format!(r#"<Cert xmlns="{XADES_NS}" Id="cert-001">{cert_digest}</Cert>"#),
        format!(
            r#"<Cert xmlns="{XADES_NS}" xmlns:ds="{XMLDSIG_NS}"><CertDigest Id="digest-001"><ds:DigestMethod Algorithm="{XMLDSIG_SHA256}"></ds:DigestMethod><ds:DigestValue>{digest}</ds:DigestValue></CertDigest></Cert>"#
        ),
        format!(
            r#"<Cert xmlns="{XADES_NS}" xmlns:ds="{XMLDSIG_NS}"><CertDigest><ds:DigestMethod Algorithm="{XMLDSIG_SHA256}" Id="method-001"></ds:DigestMethod><ds:DigestValue>{digest}</ds:DigestValue></CertDigest></Cert>"#
        ),
        format!(r#"<Cert xmlns="{XADES_NS}"><Wrapper>{cert_digest}</Wrapper></Cert>"#),
        format!(r#"<Cert xmlns="{XADES_NS}">{cert_digest}<Wrapper>{cert_digest}</Wrapper></Cert>"#),
        format!(
            r#"<Cert xmlns="{XADES_NS}" xmlns:ds="{XMLDSIG_NS}"><CertDigest><ds:DigestMethod Algorithm="{XMLDSIG_SHA256}"></ds:DigestMethod><ds:DigestValue>{digest}</ds:DigestValue><Other></Other></CertDigest></Cert>"#
        ),
    ] {
        let err = xades_cert_digest_sha256(&invalid)
            .expect_err("wrapped CertDigest children must fail closed");
        assert!(matches!(err, MsgError::ValidationFailed));
    }
}
#[test]
fn supported_xml_xades_signed_signature_properties_requires_direct_shape() {
    let valid = signed_properties_xml("signed-props-001");
    xades_signed_signature_properties_xml(&valid)
        .expect("direct SignedSignatureProperties should be accepted");
    assert_eq!(
        xades_signed_properties_signing_time(&valid)
            .expect("direct SigningTime should be accepted"),
        Some(XML_SIGNATURE_TEST_SIGNING_TIME.to_owned())
    );
    let prefixed = signed_properties_xml_prefixed("signed-props-001", XADES_NS);
    xades_signed_signature_properties_xml(&prefixed)
        .expect("prefixed SignedSignatureProperties should bind to the supported namespace");
    assert_eq!(
        xades_signed_properties_signing_time(&prefixed)
            .expect("prefixed SigningTime should be accepted"),
        Some(XML_SIGNATURE_TEST_SIGNING_TIME.to_owned())
    );
    for invalid in [
        signed_properties_xml_prefixed("signed-props-001", "urn:not-xades"),
        format!(
            r#"<SignedProperties xmlns="{XADES_NS}" Id="signed-props-001"><Wrapper>{}</Wrapper></SignedProperties>"#,
            signed_properties_xml("inner")
        ),
        format!(
            r#"<SignedProperties xmlns="{XADES_NS}" Id="signed-props-001"><SignedSignatureProperties><Wrapper><SigningTime>{XML_SIGNATURE_TEST_SIGNING_TIME}</SigningTime></Wrapper></SignedSignatureProperties></SignedProperties>"#
        ),
        format!(
            r#"<SignedProperties xmlns="{XADES_NS}" Id="signed-props-001"><SignedSignatureProperties><SigningTime>{XML_SIGNATURE_TEST_SIGNING_TIME}</SigningTime></SignedSignatureProperties><SignedDataObjectProperties></SignedDataObjectProperties></SignedProperties>"#
        ),
        format!(
            r#"<SignedProperties xmlns="{XADES_NS}" Id="signed-props-001"><SignedSignatureProperties Profile="unsupported"><SigningTime>{XML_SIGNATURE_TEST_SIGNING_TIME}</SigningTime></SignedSignatureProperties></SignedProperties>"#
        ),
        format!(
            r#"<SignedProperties xmlns="{XADES_NS}" Id="signed-props-001"><SignedSignatureProperties><SigningCertificate></SigningCertificate></SignedSignatureProperties></SignedProperties>"#
        ),
        format!(
            r#"<SignedProperties xmlns="{XADES_NS}" Id="signed-props-001"><SignedSignatureProperties><SigningTime>{XML_SIGNATURE_TEST_SIGNING_TIME}</SigningTime></SignedSignatureProperties><SignedSignatureProperties><SigningTime>{XML_SIGNATURE_TEST_SIGNING_TIME}</SigningTime></SignedSignatureProperties></SignedProperties>"#
        ),
    ] {
        let err = xades_signed_signature_properties_xml(&invalid)
            .expect_err("unsupported SignedProperties shape must fail closed");
        assert!(matches!(err, MsgError::ValidationFailed));
    }
    for invalid in [
        format!(
            r#"<SignedProperties xmlns="{XADES_NS}" Id="signed-props-001"><SignedSignatureProperties><SigningTime Source="unsupported">{XML_SIGNATURE_TEST_SIGNING_TIME}</SigningTime></SignedSignatureProperties></SignedProperties>"#
        ),
        format!(
            r#"<SignedProperties xmlns="{XADES_NS}" Id="signed-props-001"><SignedSignatureProperties><SigningTime>{XML_SIGNATURE_TEST_SIGNING_TIME}<Chunk></Chunk></SigningTime></SignedSignatureProperties></SignedProperties>"#
        ),
        format!(
            r#"<SignedProperties xmlns="{XADES_NS}" Id="signed-props-001"><SignedSignatureProperties><SigningTime>{XML_SIGNATURE_TEST_SIGNING_TIME}<!--comment--></SigningTime></SignedSignatureProperties></SignedProperties>"#
        ),
    ] {
        let err = xades_signed_properties_signing_time(&invalid)
            .expect_err("unsupported SigningTime leaf shape must fail closed");
        assert!(matches!(err, MsgError::ValidationFailed));
    }
}
#[test]
fn supported_xml_certificate_evaluation_time_uses_verified_signed_properties_time() {
    let parsed =
        parse_message("pacs.008", unsigned_pacs008_xml().as_bytes()).expect("parse pacs.008");
    assert!(
        xml_signature_evaluation_time(&parsed, None)
            .expect("missing signed time and BAH creation date should be valid")
            .is_none(),
        "certificate evaluation time must not come from unsigned signature-local data"
    );
    let signed_properties = signed_properties_xml("signed-props-001");
    assert!(
        xml_signature_evaluation_time(&parsed, Some(&signed_properties))
            .expect("verified SignedProperties SigningTime should parse")
            .is_some()
    );
    let duplicate_signing_time = signed_properties.replacen(
        "</SigningTime>",
        &format!("</SigningTime><SigningTime>{XML_SIGNATURE_TEST_SIGNING_TIME}</SigningTime>"),
        1,
    );
    let err = xml_signature_evaluation_time(&parsed, Some(&duplicate_signing_time))
        .expect_err("duplicate signed SigningTime values must fail closed");
    assert!(matches!(err, MsgError::ValidationFailed));
}
#[test]
fn supported_xml_signature_shape_requires_direct_children() {
    assert!(
        find_first_xml_element(
            &format!(r#"<ds:Signature xmlns:ds="{XMLDSIG_NS}"></bad:Signature>"#),
            "Signature",
        )
        .is_none(),
        "opening and closing XML element QNames must match exactly"
    );
    let payload = signed_pacs008_xml();
    let signature_span =
        find_first_xml_element(&payload, "Signature").expect("fixture Signature element");
    let signature_xml = &payload[signature_span.start..signature_span.end];
    let signature_children = xml_signature_direct_child_spans(signature_xml)
        .expect("direct XMLDSig Signature children should be accepted");
    let signed_info_xml =
        &signature_xml[signature_children.signed_info.start..signature_children.signed_info.end];
    let inherited_namespaces = default_xmlsig_namespace_bindings();
    xml_signed_info_direct_child_spans_with_namespaces(signed_info_xml, &inherited_namespaces)
        .expect("direct XMLDSig SignedInfo children should be accepted");
    for invalid_payload in [
        signed_pacs008_xml()
            .replacen("<SignedInfo>", "<Wrapper><SignedInfo>", 1)
            .replacen("</SignedInfo>", "</SignedInfo></Wrapper>", 1),
        format!(
            r#"<Signature xmlns="{XMLDSIG_NS}"><SignatureValue>AQ==</SignatureValue><SignedInfo></SignedInfo><KeyInfo></KeyInfo></Signature>"#
        ),
        format!(
            r#"<Signature xmlns="{XMLDSIG_NS}"><SignedInfo></SignedInfo><KeyInfo></KeyInfo><SignatureValue>AQ==</SignatureValue></Signature>"#
        ),
        format!(
            r#"<Signature xmlns="{XMLDSIG_NS}"><SignedInfo></SignedInfo><SignatureValue>AQ==</SignatureValue><Object></Object><KeyInfo></KeyInfo></Signature>"#
        ),
        signed_pacs008_xml().replacen(
            "</SignatureValue>",
            "</SignatureValue><SignatureValue>AQ==</SignatureValue>",
            1,
        ),
        signed_pacs008_xml().replacen("<KeyInfo>", "<Manifest></Manifest><KeyInfo>", 1),
        format!(
            r#"<ds:Signature xmlns:ds="{XMLDSIG_NS}"><ds:SignedInfo></bad:SignedInfo><ds:SignatureValue>AQ==</ds:SignatureValue><ds:KeyInfo></ds:KeyInfo></ds:Signature>"#
        ),
    ] {
        let signature_span = find_first_xml_element(&invalid_payload, "Signature")
            .expect("invalid fixture Signature element");
        let signature_xml = &invalid_payload[signature_span.start..signature_span.end];
        let err = xml_signature_direct_child_spans(signature_xml)
            .expect_err("unsupported Signature shape must fail closed");
        assert!(matches!(err, MsgError::ValidationFailed));
    }
    for invalid_signed_info in [
            format!(
                r#"<SignedInfo><SignatureMethod Algorithm="{XMLDSIG_ECDSA_SHA256}"></SignatureMethod><CanonicalizationMethod Algorithm="{XML_C14N_1_0}"></CanonicalizationMethod><Reference URI=""></Reference></SignedInfo>"#
            ),
            format!(
                r#"<SignedInfo><CanonicalizationMethod Algorithm="{XML_C14N_1_0}"></CanonicalizationMethod><Reference URI=""></Reference><SignatureMethod Algorithm="{XMLDSIG_ECDSA_SHA256}"></SignatureMethod></SignedInfo>"#
            ),
            signed_info_xml
                .replacen(
                    "<CanonicalizationMethod",
                    "<Wrapper><CanonicalizationMethod",
                    1,
                )
                .replacen("</CanonicalizationMethod>", "</CanonicalizationMethod></Wrapper>", 1),
            signed_info_xml.replacen("</SignatureMethod>", "</SignatureMethod><Object></Object>", 1),
            signed_info_xml.replacen(
                "</SignatureMethod>",
                &format!(
                    r#"</SignatureMethod><SignatureMethod Algorithm="{XMLDSIG_ECDSA_SHA256}"></SignatureMethod>"#
                ),
                1,
            ),
        ] {
            let err = xml_signed_info_direct_child_spans_with_namespaces(
                &invalid_signed_info,
                &inherited_namespaces,
            )
                .expect_err("unsupported SignedInfo shape must fail closed");
            assert!(matches!(err, MsgError::ValidationFailed));
        }
}
#[test]
fn supported_xml_signature_carrier_preserves_ancestor_namespace_scope() {
    let payload = format!(
        concat!(
            r#"<Envelope xmlns:ds="{XMLDSIG_NS}">"#,
            r#"<ds:Signature xmlns="{XMLDSIG_NS}">"#,
            "<SignedInfo></SignedInfo>",
            "<SignatureValue>AQ==</SignatureValue>",
            "<KeyInfo></KeyInfo>",
            "</ds:Signature></Envelope>"
        ),
        XMLDSIG_NS = XMLDSIG_NS
    );
    let carrier = xml_signature_carrier(&payload)
        .expect("carrier discovery")
        .expect("signature carrier");
    assert!(
        carrier
            .inherited_namespaces
            .iter()
            .any(|binding| binding.prefix == "ds" && binding.uri == XMLDSIG_NS)
    );
    let signature_xml = &payload[carrier.signature_span.start..carrier.signature_span.end];
    xml_signature_direct_child_spans_with_namespaces(signature_xml, &carrier.inherited_namespaces)
        .expect("ancestor-declared Signature prefix should resolve");
}
#[test]
fn supported_xml_p256_signature_rejects_all_zero_signature_material() {
    let err = decode_p256_xmldsig_signature(&[0_u8; P256_XMLDSIG_SIGNATURE_LEN])
        .expect_err("all-zero fixed-width P-256 signatures must fail closed");
    assert!(matches!(err, MsgError::ValidationFailed));
}
#[test]
fn supported_xml_p256_der_signature_rejects_all_zero_signature_material() {
    let err = decode_p256_der_signature(&[0_u8; 72])
        .expect_err("all-zero DER P-256 signatures must fail closed");
    assert!(matches!(err, MsgError::ValidationFailed));
}
#[test]
fn supported_p256_der_signature_rejects_high_s() {
    let signing_key = xml_signature_test_signing_key();
    let signature: P256Signature = signing_key.sign(b"high-s der regression");
    let low_s = low_s_p256_signature(signature);
    decode_p256_der_signature(low_s.to_der().as_bytes())
        .expect("low-S DER signatures should be accepted");
    let high_s = high_s_p256_signature(low_s);
    signing_key
        .verifying_key()
        .verify(b"high-s der regression", &high_s)
        .expect("high-S counterpart remains mathematically valid ECDSA");
    let err = decode_p256_der_signature(high_s.to_der().as_bytes())
        .expect_err("high-S DER P-256 signatures must fail closed");
    assert!(matches!(err, MsgError::ValidationFailed));
}
#[test]
fn supported_xml_p256_public_key_rejects_all_zero_coordinate_material() {
    let mut public_key = Vec::with_capacity(P256_UNCOMPRESSED_SEC1_PUBLIC_KEY_LEN);
    public_key.push(0x04);
    public_key.extend_from_slice(&[0u8; 64]);
    let err = ensure_xml_signature_p256_public_key(&public_key)
        .expect_err("all-zero P-256 public-key coordinates must fail closed");
    assert!(matches!(err, MsgError::ValidationFailed));
}
#[test]
fn supported_xml_p256_signature_rejects_high_s() {
    let signing_key = xml_signature_test_signing_key();
    let signature: P256Signature = signing_key.sign(b"high-s regression");
    let low_s = low_s_p256_signature(signature);
    decode_p256_xmldsig_signature(low_s.to_bytes().as_slice())
        .expect("low-S fixed-width signatures should be accepted");
    decode_p256_xmldsig_signature(low_s.to_der().as_bytes())
        .expect("low-S DER signatures should be accepted");
    let high_s = high_s_p256_signature(low_s);
    signing_key
        .verifying_key()
        .verify(b"high-s regression", &high_s)
        .expect("high-S counterpart remains mathematically valid ECDSA");
    for signature_value in [
        high_s.to_bytes().to_vec(),
        high_s.to_der().as_bytes().to_vec(),
    ] {
        let err = decode_p256_xmldsig_signature(&signature_value)
            .expect_err("high-S P-256 signatures must fail closed");
        assert!(matches!(err, MsgError::ValidationFailed));
    }
}
#[test]
fn supported_xml_required_base64_rejects_duplicate_children() {
    let err = decode_required_child_base64(
        r#"<Reference><DigestValue>AQ==</DigestValue><DigestValue>Ag==</DigestValue></Reference>"#,
        "DigestValue",
    )
    .expect_err("duplicate required base64 children must fail closed");
    assert!(matches!(err, MsgError::ValidationFailed));
    let err = decode_required_child_base64(
        r#"<Reference><DigestValue Id="digest-001">AQ==</DigestValue></Reference>"#,
        "DigestValue",
    )
    .expect_err("required base64 attributes must fail closed");
    assert!(matches!(err, MsgError::ValidationFailed));
    let err = decode_required_child_base64(
        r#"<Reference><DigestValue><Chunk>AQ==</Chunk></DigestValue></Reference>"#,
        "DigestValue",
    )
    .expect_err("nested required base64 markup must fail closed");
    assert!(matches!(err, MsgError::ValidationFailed));
    let err = decode_required_child_base64(
        r#"<Reference><DigestValue>A<!--comment-->Q==</DigestValue></Reference>"#,
        "DigestValue",
    )
    .expect_err("required base64 comments must fail closed");
    assert!(matches!(err, MsgError::ValidationFailed));
}
#[test]
fn supported_xml_key_material_enforces_key_info_shape() {
    let signing_key = xml_signature_test_signing_key();
    let public_key = BASE64_STANDARD.encode(
        signing_key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes(),
    );
    let default_namespaces = default_xmlsig_namespace_bindings();
    let xml_signature_key_material = |signature_xml: &str, evaluation_time: Option<ASN1Time>| {
        xml_signature_key_material_with_namespaces(
            signature_xml,
            evaluation_time,
            &default_namespaces,
        )
    };
    let xml_signature_x509_certificates = |key_info_xml: &str| {
        xml_signature_x509_certificates_with_namespaces(key_info_xml, &default_namespaces)
    };
    let valid = format!(
        r#"<Signature><KeyInfo><KeyValue><ECKeyValue><NamedCurve URI="{XMLDSIG_P256_NAMED_CURVE}"></NamedCurve><PublicKey>{public_key}</PublicKey></ECKeyValue></KeyValue></KeyInfo></Signature>"#
    );
    xml_signature_key_material(&valid, None)
        .expect("structured P-256 public-key KeyInfo should decode");
    let inherited_namespaces = vec![CanonicalXmlNamespaceBinding {
        prefix: "ds".to_owned(),
        uri: XMLDSIG_NS.to_owned(),
    }];
    let prefixed = format!(
        r#"<ds:KeyInfo><ds:KeyValue><ds:ECKeyValue><ds:NamedCurve URI="{XMLDSIG_P256_NAMED_CURVE}"></ds:NamedCurve><ds:PublicKey>{public_key}</ds:PublicKey></ds:ECKeyValue></ds:KeyValue></ds:KeyInfo>"#
    );
    xml_signature_key_material_with_namespaces(&prefixed, None, &inherited_namespaces)
        .expect("prefixed XMLDSig KeyInfo should resolve inherited namespaces");
    let wrong_key_value_namespace = format!(
        r#"<ds:KeyInfo><bad:KeyValue xmlns:bad="urn:not-xmldsig"><ds:ECKeyValue><ds:NamedCurve URI="{XMLDSIG_P256_NAMED_CURVE}"></ds:NamedCurve><ds:PublicKey>{public_key}</ds:PublicKey></ds:ECKeyValue></bad:KeyValue></ds:KeyInfo>"#
    );
    let err = xml_signature_key_material_with_namespaces(
        &wrong_key_value_namespace,
        None,
        &inherited_namespaces,
    )
    .expect_err("KeyValue bound outside XMLDSig must fail closed");
    assert!(matches!(err, MsgError::ValidationFailed));
    let malformed_public_key = BASE64_STANDARD.encode([1_u8, 2, 3]);
    let malformed_public_key_xml = format!(
        r#"<Signature><KeyInfo><KeyValue><ECKeyValue><NamedCurve URI="{XMLDSIG_P256_NAMED_CURVE}"></NamedCurve><PublicKey>{malformed_public_key}</PublicKey></ECKeyValue></KeyValue></KeyInfo></Signature>"#
    );
    let err = xml_signature_key_material(&malformed_public_key_xml, None)
        .expect_err("malformed P-256 public-key bytes must fail closed");
    assert!(matches!(err, MsgError::ValidationFailed));
    let compressed_public_key = BASE64_STANDARD.encode(
        signing_key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes(),
    );
    let compressed_public_key_xml = format!(
        r#"<Signature><KeyInfo><KeyValue><ECKeyValue><NamedCurve URI="{XMLDSIG_P256_NAMED_CURVE}"></NamedCurve><PublicKey>{compressed_public_key}</PublicKey></ECKeyValue></KeyValue></KeyInfo></Signature>"#
    );
    let err = xml_signature_key_material(&compressed_public_key_xml, None)
        .expect_err("compressed P-256 public-key bytes must fail closed");
    assert!(matches!(err, MsgError::ValidationFailed));
    let duplicate = format!(
        "<Signature><KeyInfo><PublicKey>{public_key}</PublicKey><PublicKey>{public_key}</PublicKey></KeyInfo></Signature>"
    );
    let err = xml_signature_key_material(&duplicate, None)
        .expect_err("duplicate PublicKey elements must fail closed");
    assert!(matches!(err, MsgError::ValidationFailed));
    let mixed = format!(
        "<Signature><KeyInfo><PublicKey>{public_key}</PublicKey><X509Data><X509Certificate>AQ==</X509Certificate></X509Data></KeyInfo></Signature>"
    );
    let err = xml_signature_key_material(&mixed, None)
        .expect_err("mixed PublicKey and X509Certificate material must fail closed");
    assert!(matches!(err, MsgError::ValidationFailed));
    let wrong_curve = format!(
        r#"<Signature><KeyInfo><KeyValue><ECKeyValue><NamedCurve URI="urn:oid:1.3.132.0.34"></NamedCurve><PublicKey>{public_key}</PublicKey></ECKeyValue></KeyValue></KeyInfo></Signature>"#
    );
    let err = xml_signature_key_material(&wrong_curve, None)
        .expect_err("unsupported public-key curves must fail closed");
    assert!(matches!(err, MsgError::ValidationFailed));
    let missing_key_value = format!(
        r#"<Signature><KeyInfo><ECKeyValue><NamedCurve URI="{XMLDSIG_P256_NAMED_CURVE}"></NamedCurve><PublicKey>{public_key}</PublicKey></ECKeyValue></KeyInfo></Signature>"#
    );
    let err = xml_signature_key_material(&missing_key_value, None)
        .expect_err("PublicKey must be wrapped in KeyValue/ECKeyValue");
    assert!(matches!(err, MsgError::ValidationFailed));
    let public_key_outside_ec_key_value = format!(
        r#"<Signature><KeyInfo><KeyValue><ECKeyValue><NamedCurve URI="{XMLDSIG_P256_NAMED_CURVE}"></NamedCurve></ECKeyValue><PublicKey>{public_key}</PublicKey></KeyValue></KeyInfo></Signature>"#
    );
    let err = xml_signature_key_material(&public_key_outside_ec_key_value, None)
        .expect_err("PublicKey outside ECKeyValue must fail closed");
    assert!(matches!(err, MsgError::ValidationFailed));
    let key_info_extra_child = format!(
        r#"<Signature><KeyInfo><KeyValue><ECKeyValue><NamedCurve URI="{XMLDSIG_P256_NAMED_CURVE}"></NamedCurve><PublicKey>{public_key}</PublicKey></ECKeyValue></KeyValue><RetrievalMethod></RetrievalMethod></KeyInfo></Signature>"#
    );
    let err = xml_signature_key_material(&key_info_extra_child, None)
        .expect_err("unsupported KeyInfo child elements must fail closed");
    assert!(matches!(err, MsgError::ValidationFailed));
    let key_value_extra_child = format!(
        r#"<Signature><KeyInfo><KeyValue><ECKeyValue><NamedCurve URI="{XMLDSIG_P256_NAMED_CURVE}"></NamedCurve><PublicKey>{public_key}</PublicKey></ECKeyValue><ECParameters></ECParameters></KeyValue></KeyInfo></Signature>"#
    );
    let err = xml_signature_key_material(&key_value_extra_child, None)
        .expect_err("unsupported KeyValue child elements must fail closed");
    assert!(matches!(err, MsgError::ValidationFailed));
    let ec_key_value_extra_child = format!(
        r#"<Signature><KeyInfo><KeyValue><ECKeyValue><NamedCurve URI="{XMLDSIG_P256_NAMED_CURVE}"></NamedCurve><PublicKey>{public_key}</PublicKey><ECParameters></ECParameters></ECKeyValue></KeyValue></KeyInfo></Signature>"#
    );
    let err = xml_signature_key_material(&ec_key_value_extra_child, None)
        .expect_err("unsupported ECKeyValue child elements must fail closed");
    assert!(matches!(err, MsgError::ValidationFailed));
    let key_info_text = format!(
        r#"<Signature><KeyInfo>text<KeyValue><ECKeyValue><NamedCurve URI="{XMLDSIG_P256_NAMED_CURVE}"></NamedCurve><PublicKey>{public_key}</PublicKey></ECKeyValue></KeyValue></KeyInfo></Signature>"#
    );
    let err = xml_signature_key_material(&key_info_text, None)
        .expect_err("non-whitespace KeyInfo text must fail closed");
    assert!(matches!(err, MsgError::ValidationFailed));
    let key_info_attribute = format!(
        r#"<Signature><KeyInfo Id="key-001"><KeyValue><ECKeyValue><NamedCurve URI="{XMLDSIG_P256_NAMED_CURVE}"></NamedCurve><PublicKey>{public_key}</PublicKey></ECKeyValue></KeyValue></KeyInfo></Signature>"#
    );
    let err = xml_signature_key_material(&key_info_attribute, None)
        .expect_err("unsupported KeyInfo attributes must fail closed");
    assert!(matches!(err, MsgError::ValidationFailed));
    let key_value_attribute = format!(
        r#"<Signature><KeyInfo><KeyValue Id="key-value-001"><ECKeyValue><NamedCurve URI="{XMLDSIG_P256_NAMED_CURVE}"></NamedCurve><PublicKey>{public_key}</PublicKey></ECKeyValue></KeyValue></KeyInfo></Signature>"#
    );
    let err = xml_signature_key_material(&key_value_attribute, None)
        .expect_err("unsupported KeyValue attributes must fail closed");
    assert!(matches!(err, MsgError::ValidationFailed));
    let ec_key_value_attribute = format!(
        r#"<Signature><KeyInfo><KeyValue><ECKeyValue Type="named"><NamedCurve URI="{XMLDSIG_P256_NAMED_CURVE}"></NamedCurve><PublicKey>{public_key}</PublicKey></ECKeyValue></KeyValue></KeyInfo></Signature>"#
    );
    let err = xml_signature_key_material(&ec_key_value_attribute, None)
        .expect_err("unsupported ECKeyValue attributes must fail closed");
    assert!(matches!(err, MsgError::ValidationFailed));
    let named_curve_attribute = format!(
        r#"<Signature><KeyInfo><KeyValue><ECKeyValue><NamedCurve URI="{XMLDSIG_P256_NAMED_CURVE}" Type="named"></NamedCurve><PublicKey>{public_key}</PublicKey></ECKeyValue></KeyValue></KeyInfo></Signature>"#
    );
    let err = xml_signature_key_material(&named_curve_attribute, None)
        .expect_err("unsupported NamedCurve attributes must fail closed");
    assert!(matches!(err, MsgError::ValidationFailed));
    let public_key_attribute = format!(
        r#"<Signature><KeyInfo><KeyValue><ECKeyValue><NamedCurve URI="{XMLDSIG_P256_NAMED_CURVE}"></NamedCurve><PublicKey Encoding="base64">{public_key}</PublicKey></ECKeyValue></KeyValue></KeyInfo></Signature>"#
    );
    let err = xml_signature_key_material(&public_key_attribute, None)
        .expect_err("unsupported PublicKey attributes must fail closed");
    assert!(matches!(err, MsgError::ValidationFailed));
    let public_key_nested_markup = format!(
        r#"<Signature><KeyInfo><KeyValue><ECKeyValue><NamedCurve URI="{XMLDSIG_P256_NAMED_CURVE}"></NamedCurve><PublicKey>{public_key}<Chunk></Chunk></PublicKey></ECKeyValue></KeyValue></KeyInfo></Signature>"#
    );
    let err = xml_signature_key_material(&public_key_nested_markup, None)
        .expect_err("nested PublicKey markup must fail closed");
    assert!(matches!(err, MsgError::ValidationFailed));
    let public_key_comment = format!(
        r#"<Signature><KeyInfo><KeyValue><ECKeyValue><NamedCurve URI="{XMLDSIG_P256_NAMED_CURVE}"></NamedCurve><PublicKey>{public_key}<!--comment--></PublicKey></ECKeyValue></KeyValue></KeyInfo></Signature>"#
    );
    let err = xml_signature_key_material(&public_key_comment, None)
        .expect_err("PublicKey comments must fail closed");
    assert!(matches!(err, MsgError::ValidationFailed));
    let certificate_without_x509_data =
        "<Signature><KeyInfo><X509Certificate>AQ==</X509Certificate></KeyInfo></Signature>";
    let err = xml_signature_key_material(certificate_without_x509_data, None)
        .expect_err("X509Certificate outside X509Data must fail closed");
    assert!(matches!(err, MsgError::ValidationFailed));
    let duplicate_x509_data = concat!(
        "<Signature><KeyInfo><X509Data><X509Certificate>AQ==</X509Certificate></X509Data>",
        "<X509Data><X509Certificate>Ag==</X509Certificate></X509Data></KeyInfo></Signature>"
    );
    let err = xml_signature_key_material(duplicate_x509_data, None)
        .expect_err("duplicate X509Data wrappers must fail closed");
    assert!(matches!(err, MsgError::ValidationFailed));
    let x509_data_extra_child = concat!(
        "<Signature><KeyInfo><X509Data><X509Certificate>AQ==</X509Certificate>",
        "<X509IssuerSerial></X509IssuerSerial></X509Data></KeyInfo></Signature>"
    );
    let err = xml_signature_key_material(x509_data_extra_child, None)
        .expect_err("unsupported X509Data child elements must fail closed");
    assert!(matches!(err, MsgError::ValidationFailed));
    let x509_data_attribute = concat!(
        "<Signature><KeyInfo><X509Data Id=\"certs-001\">",
        "<X509Certificate>AQ==</X509Certificate></X509Data></KeyInfo></Signature>"
    );
    let err = xml_signature_key_material(x509_data_attribute, None)
        .expect_err("unsupported X509Data attributes must fail closed");
    assert!(matches!(err, MsgError::ValidationFailed));
    let x509_certificate_attribute = concat!(
        "<Signature><KeyInfo><X509Data>",
        "<X509Certificate Encoding=\"base64\">AQ==</X509Certificate>",
        "</X509Data></KeyInfo></Signature>"
    );
    let err = xml_signature_key_material(x509_certificate_attribute, None)
        .expect_err("unsupported X509Certificate attributes must fail closed");
    assert!(matches!(err, MsgError::ValidationFailed));
    let x509_certificate_nested_markup = concat!(
        "<KeyInfo><X509Data><X509Certificate>AQ==<Chunk></Chunk></X509Certificate>",
        "</X509Data></KeyInfo>"
    );
    let err = xml_signature_x509_certificates(x509_certificate_nested_markup)
        .expect_err("nested X509Certificate markup must fail closed");
    assert!(matches!(err, MsgError::ValidationFailed));
    let x509_certificate_comment = concat!(
        "<KeyInfo><X509Data><X509Certificate>AQ==<!--comment--></X509Certificate>",
        "</X509Data></KeyInfo>"
    );
    let err = xml_signature_x509_certificates(x509_certificate_comment)
        .expect_err("X509Certificate comments must fail closed");
    assert!(matches!(err, MsgError::ValidationFailed));
    let missing_key_info = format!("<Signature><PublicKey>{public_key}</PublicKey></Signature>");
    let err = xml_signature_key_material(&missing_key_info, None)
        .expect_err("PublicKey outside KeyInfo must fail closed");
    assert!(matches!(err, MsgError::ValidationFailed));
    let out_of_scope = format!(
        "<Signature><PublicKey>{public_key}</PublicKey><KeyInfo><PublicKey>{public_key}</PublicKey></KeyInfo></Signature>"
    );
    let err = xml_signature_key_material(&out_of_scope, None)
        .expect_err("key material outside KeyInfo must fail closed");
    assert!(matches!(err, MsgError::ValidationFailed));
}
#[test]
fn supported_xml_x509_certificate_chain_bounds_reject_duplicates_and_overlong_chains() {
    let valid = (0..XML_SIGNATURE_MAX_X509_CERTIFICATES)
        .map(|index| vec![index as u8])
        .collect::<Vec<_>>();
    ensure_xml_signature_certificate_chain_bounds(&valid)
        .expect("maximum supported unique X509 chain should be accepted");
    let empty = Vec::new();
    let err = ensure_xml_signature_certificate_chain_bounds(&empty)
        .expect_err("empty X509 chain must fail closed");
    assert!(matches!(err, MsgError::ValidationFailed));
    let duplicate = vec![vec![1_u8], vec![1_u8]];
    let err = ensure_xml_signature_certificate_chain_bounds(&duplicate)
        .expect_err("duplicate X509 DER entries must fail closed");
    assert!(matches!(err, MsgError::ValidationFailed));
    let overlong = (0..=XML_SIGNATURE_MAX_X509_CERTIFICATES)
        .map(|index| vec![index as u8])
        .collect::<Vec<_>>();
    let err = ensure_xml_signature_certificate_chain_bounds(&overlong)
        .expect_err("overlong X509 chain must fail closed");
    assert!(matches!(err, MsgError::ValidationFailed));
}
#[test]
fn supported_xml_xades_cert_digest_rejects_duplicate_methods() {
    let digest = BASE64_STANDARD.encode([0_u8; 32]);
    let cert_xml = format!(
        r#"<Cert xmlns="{XADES_NS}" xmlns:ds="{XMLDSIG_NS}"><CertDigest><ds:DigestMethod Algorithm="{XMLDSIG_SHA256}"></ds:DigestMethod><ds:DigestMethod Algorithm="{XMLDSIG_SHA256}"></ds:DigestMethod><ds:DigestValue>{digest}</ds:DigestValue></CertDigest></Cert>"#
    );
    let err = xades_cert_digest_sha256(&cert_xml)
        .expect_err("duplicate XAdES CertDigest methods must fail closed");
    assert!(matches!(err, MsgError::ValidationFailed));
}
#[test]
fn supported_xml_canonicalizer_accepts_prefixed_attributes() {
    let canonical = canonicalize_supported_xml(
        r#"<A xmlns:z="urn:z" z:flag="yes" b="2" xmlns:a="urn:a" a:flag="no"></A>"#,
    )
    .expect("declared prefixed attributes should canonicalize by expanded name");
    assert_eq!(
        canonical,
        r#"<A xmlns:a="urn:a" xmlns:z="urn:z" b="2" a:flag="no" z:flag="yes"></A>"#
    );
}
#[test]
fn supported_xml_canonicalizer_accepts_inherited_prefixed_attributes() {
    let canonical = canonicalize_supported_xml(r#"<A xmlns:p="urn:p"><B p:flag="true"></B></A>"#)
        .expect("child attributes should resolve namespace bindings from ancestors");
    assert_eq!(canonical, r#"<A xmlns:p="urn:p"><B p:flag="true"></B></A>"#);
}
#[test]
fn supported_xml_canonicalizer_strips_comments_for_no_comments_c14n() {
    let canonical = canonicalize_supported_xml(
        "<!--before--><A><!--inside--><B>value<!--text comment--></B><!--tail--></A><!--after-->",
    )
    .expect("no-comments XML canonicalization should omit comments");
    assert_eq!(canonical, "<A><B>value</B></A>");
}
#[test]
fn supported_xml_canonicalizer_rejects_malformed_comments() {
    for xml in ["<A><!--unterminated</A>", "<A><!--bad--comment--></A>"] {
        let err =
            canonicalize_supported_xml(xml).expect_err("malformed XML comments must fail closed");
        assert!(matches!(err, MsgError::ValidationFailed));
    }
}
#[test]
fn supported_xml_canonicalizer_rejects_unsupported_entities() {
    for xml in [
        "<A>&custom;</A>",
        "<A>&amp</A>",
        "<A>&#0;</A>",
        "<A>&#xD800;</A>",
        "<A>&#X41;</A>",
        "<A>&#x110000;</A>",
        "<A>bad]]>tail</A>",
    ] {
        let err = canonicalize_supported_xml(xml)
            .expect_err("unsupported or invalid XML character data must fail closed");
        assert!(matches!(err, MsgError::ValidationFailed));
    }
}
#[test]
fn der_reader_rejects_noncanonical_lengths_and_integers() {
    let mut valid_long_form = vec![0x30, 0x81, 0x80];
    valid_long_form.extend([0_u8; 128]);
    let element = der_expect_single(&valid_long_form, 0x30)
        .expect("minimal DER long-form length should parse");
    assert_eq!(element.value.len(), 128);
    let mut leading_zero_length = vec![0x30, 0x82, 0x00, 0x80];
    leading_zero_length.extend([0_u8; 128]);
    let err = der_expect_single(&leading_zero_length, 0x30)
        .expect_err("long-form DER length with leading zero must fail closed");
    assert!(matches!(err, MsgError::ValidationFailed));
    let mut unnecessary_long_form = vec![0x30, 0x81, 0x7f];
    unnecessary_long_form.extend([0_u8; 127]);
    let err = der_expect_single(&unnecessary_long_form, 0x30)
        .expect_err("long-form DER length below 128 must fail closed");
    assert!(matches!(err, MsgError::ValidationFailed));
    assert_eq!(der_integer_value(&[0]).expect("zero is canonical"), 0);
    assert_eq!(der_integer_value(&[0x7f]).expect("127 is canonical"), 127);
    assert_eq!(
        der_integer_value(&[0x00, 0x80]).expect("leading zero is needed for positive 128"),
        128
    );
    let err = der_integer_value(&[0x00, 0x7f])
        .expect_err("unneeded leading zero in DER integer must fail closed");
    assert!(matches!(err, MsgError::ValidationFailed));
    let err =
        der_integer_value(&[0x80]).expect_err("negative DER integer encodings must fail closed");
    assert!(matches!(err, MsgError::ValidationFailed));
}
#[test]
fn ocsp_parser_rejects_unsupported_extensions() {
    fn test_ocsp_single_response_der(include_extensions: bool) -> Vec<u8> {
        let algorithm_identifier = der_sequence(der_tlv(0x06, OID_SHA256_DER.to_vec()));
        let cert_id = der_sequence(
            [
                algorithm_identifier,
                der_tlv(0x04, vec![0x11; 32]),
                der_tlv(0x04, vec![0x22; 32]),
                der_tlv(0x02, vec![0x01]),
            ]
            .concat(),
        );
        let mut content = [
            cert_id,
            der_tlv(0x80, Vec::new()),
            der_tlv(0x18, b"20260601141606Z".to_vec()),
            der_tlv(0xA0, der_tlv(0x18, b"21260508141606Z".to_vec())),
        ]
        .concat();
        if include_extensions {
            content.extend(der_tlv(0xA1, der_sequence(Vec::new())));
        }
        der_sequence(content)
    }
    fn test_ocsp_response_data_der(include_extensions: bool) -> Vec<u8> {
        let mut content = [
            der_tlv(0x82, vec![0x33; 20]),
            der_tlv(0x18, b"20260601141606Z".to_vec()),
            der_sequence(test_ocsp_single_response_der(false)),
        ]
        .concat();
        if include_extensions {
            content.extend(der_tlv(0xA1, der_sequence(Vec::new())));
        }
        der_sequence(content)
    }
    let single_response = test_ocsp_single_response_der(false);
    let single_response = der_expect_single(&single_response, 0x30)
        .expect("test SingleResponse")
        .value;
    parse_ocsp_single_response(single_response)
        .expect("minimal SingleResponse without extensions should parse");
    let single_response_with_extensions = test_ocsp_single_response_der(true);
    let single_response_with_extensions = der_expect_single(&single_response_with_extensions, 0x30)
        .expect("test SingleResponse with extensions")
        .value;
    let err = match parse_ocsp_single_response(single_response_with_extensions) {
        Ok(_) => panic!("unsupported SingleResponse extensions must fail closed"),
        Err(err) => err,
    };
    assert!(matches!(err, MsgError::ValidationFailed));
    let response_data = test_ocsp_response_data_der(false);
    let response_data = der_expect_single(&response_data, 0x30)
        .expect("test ResponseData")
        .value;
    parse_ocsp_response_data(response_data)
        .expect("minimal ResponseData without extensions should parse");
    let response_data_with_extensions = test_ocsp_response_data_der(true);
    let response_data_with_extensions = der_expect_single(&response_data_with_extensions, 0x30)
        .expect("test ResponseData with extensions")
        .value;
    let err = match parse_ocsp_response_data(response_data_with_extensions) {
        Ok(_) => panic!("unsupported ResponseData extensions must fail closed"),
        Err(err) => err,
    };
    assert!(matches!(err, MsgError::ValidationFailed));
    for response_der_base64 in [
        TEST_X509_OCSP_GOOD_RESPONSE_DER_B64,
        TEST_X509_OCSP_REVOKED_RESPONSE_DER_B64,
        TEST_X509_OCSP_DELEGATED_GOOD_RESPONSE_DER_B64,
        TEST_X509_OCSP_DELEGATED_GOOD_NO_CERTS_RESPONSE_DER_B64,
    ] {
        let response_der = BASE64_STANDARD
            .decode(response_der_base64)
            .expect("legacy OCSP fixture must decode");
        let err = match parse_ocsp_response_der(&response_der) {
            Ok(_) => panic!("legacy OCSP fixture with unsupported extensions must fail closed"),
            Err(err) => err,
        };
        assert!(matches!(err, MsgError::ValidationFailed));
    }
}
#[test]
fn supported_xml_canonicalizer_rejects_reserved_namespace_declarations() {
    for xml in [
        r#"<A xmlns:xml="urn:not-xml"></A>"#,
        r#"<A xmlns="http://www.w3.org/XML/1998/namespace"></A>"#,
        r#"<A xmlns:xmlns="http://www.w3.org/2000/xmlns/"></A>"#,
        r#"<A xmlns:bad="http://www.w3.org/XML/1998/namespace"></A>"#,
        r#"<A xmlns:bad="http://www.w3.org/2000/xmlns/"></A>"#,
    ] {
        let err = canonicalize_supported_xml(xml)
            .expect_err("reserved namespace declarations must fail closed");
        assert!(matches!(err, MsgError::ValidationFailed));
    }
}
#[test]
fn supported_xml_canonicalizer_rejects_unbound_prefixed_attributes() {
    let err = canonicalize_supported_xml(r#"<A p:id="id-1"></A>"#)
        .expect_err("prefixed attributes without in-scope namespace bindings must fail closed");
    assert!(matches!(err, MsgError::ValidationFailed));
}
#[test]
fn supported_xml_canonicalizer_rejects_duplicate_expanded_attributes() {
    let err = canonicalize_supported_xml(
        r#"<A xmlns:p="urn:same" xmlns:q="urn:same" p:id="one" q:id="two"></A>"#,
    )
    .expect_err("attributes with duplicate expanded names must fail closed");
    assert!(matches!(err, MsgError::ValidationFailed));
}
#[test]
fn supported_xml_canonicalizer_accepts_locally_declared_prefixes() {
    let canonical = canonicalize_supported_xml(r#"<ds:A xmlns:ds="urn:test"><ds:B /></ds:A>"#)
        .expect("locally declared namespace prefixes are inside the supported subset");
    assert_eq!(
        canonical,
        r#"<ds:A xmlns:ds="urn:test"><ds:B></ds:B></ds:A>"#
    );
}
#[test]
fn supported_xml_canonicalizer_applies_inherited_root_namespace() {
    let inherited_namespaces = vec![CanonicalXmlAttribute {
        name: "xmlns:ds".to_owned(),
        value: XMLDSIG_NS.to_owned(),
        kind: CanonicalXmlAttributeKind::Namespace,
    }];
    let canonical = canonicalize_supported_xml_with_inherited_namespaces(
        "<ds:A><ds:B /></ds:A>",
        &inherited_namespaces,
    )
    .expect("root namespace inherited from the enclosing XMLDSig element should canonicalize");
    assert_eq!(
        canonical,
        r#"<ds:A xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:B></ds:B></ds:A>"#
    );
}
#[test]
fn supported_xml_canonicalizer_distinguishes_inclusive_and_exclusive_namespaces() {
    let inherited_namespaces = vec![
        CanonicalXmlAttribute {
            name: "xmlns:ds".to_owned(),
            value: XMLDSIG_NS.to_owned(),
            kind: CanonicalXmlAttributeKind::Namespace,
        },
        CanonicalXmlAttribute {
            name: "xmlns:unused".to_owned(),
            value: "urn:unused".to_owned(),
            kind: CanonicalXmlAttributeKind::Namespace,
        },
    ];
    let inclusive = canonicalize_supported_xml_with_mode(
        "<ds:A><ds:B /></ds:A>",
        &inherited_namespaces,
        CanonicalXmlMode::Inclusive,
    )
    .expect("inclusive canonicalization should carry inherited namespaces");
    let exclusive = canonicalize_supported_xml_with_mode(
        "<ds:A><ds:B /></ds:A>",
        &inherited_namespaces,
        CanonicalXmlMode::Exclusive,
    )
    .expect("exclusive canonicalization should carry only visibly used namespaces");
    assert_eq!(
        inclusive,
        r#"<ds:A xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:unused="urn:unused"><ds:B></ds:B></ds:A>"#
    );
    assert_eq!(
        exclusive,
        r#"<ds:A xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:B></ds:B></ds:A>"#
    );
}
#[test]
fn supported_xml_canonicalizer_rejects_inherited_prefix_context() {
    let err = canonicalize_supported_xml("<ds:A></ds:A>")
        .expect_err("inherited namespace context is outside this canonicalizer");
    assert!(matches!(err, MsgError::ValidationFailed));
}
#[test]
fn supported_xml_canonicalizer_rejects_attribute_whitespace_rewrites() {
    let err = canonicalize_supported_xml("<A value='line\nbreak'></A>")
        .expect_err("attribute whitespace normalization is outside this canonicalizer");
    assert!(matches!(err, MsgError::ValidationFailed));
}
#[test]
fn require_verified_profile_rejects_unpinned_public_key() {
    let payload = signed_pacs008_xml();
    let err = validate_require_verified_signed_payload(&payload, |profile| {
        profile.signature_public_key_sha256_pins = vec!["11".repeat(32)];
    })
    .expect_err("require-verified must fail closed for unpinned XMLDSig keys");
    assert!(matches!(err, MsgError::ValidationFailed));
}
signed_payload_tests! {
    require_verified_profile_accepts_comments_in_no_comments_c14n: assert_require_verified_signed_payload_accepted(
        signed_pacs008_xml_with_comments(),
        "no-comments C14N should omit XML comments before digest and signature checks",
        Some("sig-001"),
    );
    require_verified_profile_accepts_character_references_in_payload_digest: assert_require_verified_signed_payload_accepted(
        signed_pacs008_xml_with_character_reference_message_id(),
        "canonicalized character references should satisfy the XMLDSig digest",
        Some("sig&001"),
    );
    require_verified_profile_accepts_xml_namespace_attribute_in_payload_digest: assert_require_verified_signed_payload_accepted(
        signed_pacs008_xml_with_xml_namespace_attribute(),
        "implicit xml namespace attributes should satisfy the XMLDSig digest",
        Some("sig-001"),
    );
    require_verified_profile_accepts_prefixed_attribute_in_payload_digest: assert_require_verified_signed_payload_accepted(
        signed_pacs008_xml_with_prefixed_attribute(),
        "prefixed payload attributes should satisfy the XMLDSig digest",
        Some("sig-001"),
    );
    require_verified_profile_accepts_xml_namespace_attribute_in_signed_info: assert_require_verified_signed_payload_accepted(
        signed_pacs008_xml_with_signed_info_xml_namespace_attribute(),
        "implicit xml namespace attributes should canonicalize inside SignedInfo",
        Some("sig-001"),
    );
    require_verified_profile_accepts_same_document_id_reference: assert_require_verified_signed_payload_accepted(
        signed_pacs008_xml_with_same_document_reference(),
        "same-document #id XMLDSig references should verify",
        Some("sig-001"),
    );
}
#[test]
fn require_verified_profile_accepts_same_document_reference_with_inherited_namespace() {
    let mut config = sample_config();
    config
        .profiles
        .push(signed_message_profile("require-verified"));
    let runtime = Iso20022BridgeRuntime::from_config(&config)
        .expect("cfg")
        .expect("enabled");
    let payload = signed_pacs008_xml_with_inherited_namespace_same_document_reference();
    let parsed =
        parse_xml_message("pacs.008", payload.as_bytes()).expect("parse same-document signed XML");
    let profile = runtime
        .resolve_profile(Some("signed-pacs008-test"))
        .expect("signed profile");
    let metadata = runtime
        .validate_profile_submission(profile, "pacs.008", &parsed, payload.as_bytes())
        .expect("same-document references should inherit ancestor namespace context");
    assert!(metadata.embedded_signature_detected());
    assert_eq!(metadata.business_message_id(), Some("sig-001"));
}
#[test]
fn require_verified_profile_rejects_parsed_fields_from_another_xml_source() {
    let mut config = sample_config();
    config
        .profiles
        .push(signed_message_profile("require-verified"));
    let runtime = Iso20022BridgeRuntime::from_config(&config)
        .expect("cfg")
        .expect("enabled");
    let parsed_payload = signed_pacs008_xml();
    let parsed = parse_xml_message("pacs.008", parsed_payload.as_bytes()).expect("parse payload A");
    let signed_payload = signed_pacs008_xml_from_unsigned(
        unsigned_pacs008_xml_with_message_id("sig-002"),
        XML_C14N_1_0,
        false,
        true,
    );
    let profile = runtime
        .resolve_profile(Some("signed-pacs008-test"))
        .expect("signed profile");
    let err = runtime
        .validate_profile_submission(profile, "pacs.008", &parsed, signed_payload.as_bytes())
        .expect_err("semantic fields and verified bytes must share one XML source");
    assert!(matches!(err, MsgError::ValidationFailed));
}
#[test]
fn require_verified_profile_rejects_developer_format_field_provenance() {
    let mut config = sample_config();
    config
        .profiles
        .push(signed_message_profile("require-verified"));
    let runtime = Iso20022BridgeRuntime::from_config(&config)
        .expect("cfg")
        .expect("enabled");
    let parsed = sample_pacs008();
    let payload = signed_pacs008_xml();
    let profile = runtime
        .resolve_profile(Some("signed-pacs008-test"))
        .expect("signed profile");
    let err = runtime
        .validate_profile_submission(profile, "pacs.008", &parsed, payload.as_bytes())
        .expect_err("developer-format fields do not carry signed XML provenance");
    assert!(matches!(err, MsgError::ValidationFailed));
}
signed_payload_tests! {
    require_verified_profile_rejects_same_document_reference_outside_signature_carrier: assert_require_verified_signed_payload_rejected(
        signed_pacs008_xml_with_header_only_same_document_reference(),
        "same-document payload Reference must cover the XMLDSig carrier",
    );
    require_verified_profile_rejects_same_document_reference_with_semantic_header_outside: assert_require_verified_signed_payload_rejected(
        signed_pacs008_xml_with_app_header_outside_same_document_reference(),
        "every bridge-consumed field must be covered by the verified Reference",
    );
    require_verified_profile_accepts_reference_c14n_transform: assert_require_verified_signed_payload_accepted(
        signed_pacs008_xml_with_reference_c14n_transform(),
        "payload Reference C14N transform should drive digest canonicalization",
        Some("sig-001"),
    );
    require_verified_profile_accepts_inherited_prefixed_attribute_in_signed_info: assert_require_verified_signed_payload_accepted(
        signed_pacs008_xml_with_signed_info_inherited_prefixed_attribute(),
        "exclusive C14N should inherit namespaces visibly used by SignedInfo attributes",
        Some("sig-001"),
    );
    require_verified_profile_accepts_prefixed_signed_info_with_inherited_namespace: assert_require_verified_signed_payload_accepted(
        signed_pacs008_xml_with_prefixed_signature_namespace(),
        "prefixed XMLDSig SignedInfo should inherit the Signature namespace",
        None,
    );
    require_verified_profile_accepts_sgntr_wrapped_signature_carrier: assert_require_verified_signed_payload_accepted(
        signed_pacs008_xml_with_sgntr_signature_carrier(),
        "Sgntr wrappers with one direct XMLDSig Signature must verify",
        None,
    );
}
#[test]
fn require_verified_profile_rejects_prefixed_signature_with_wrong_namespace() {
    let payload = signed_pacs008_xml_with_wrong_prefixed_signature_namespace();
    let err = parse_xml_message("pacs.008", payload.as_bytes())
        .expect_err("prefixed Signature must bind to the XMLDSig namespace");
    assert!(matches!(err, MsgError::InvalidFormat));
}
#[test]
fn require_verified_profile_rejects_unprefixed_signature_with_wrong_default_namespace() {
    let payload = signed_pacs008_xml_with_wrong_default_signature_namespace();
    let err = parse_xml_message("pacs.008", payload.as_bytes())
        .expect_err("unprefixed Signature must bind to the XMLDSig namespace");
    assert!(matches!(err, MsgError::InvalidFormat));
}
signed_payload_tests! {
    require_verified_profile_accepts_inclusive_c14n_with_unused_inherited_namespace: assert_require_verified_signed_payload_accepted(
        signed_pacs008_xml_with_inclusive_unused_signature_namespace(),
        "inclusive XML canonicalization should carry inherited root namespaces",
        None,
    );
    require_verified_profile_rejects_exclusive_bytes_declared_as_inclusive_c14n: assert_require_verified_signed_payload_rejected(
        signed_pacs008_xml_with_exclusive_bytes_declared_as_inclusive(),
        "declared inclusive C14N must not verify exclusive canonical bytes",
    );
    require_verified_profile_accepts_fixed_width_ecdsa_signature_value: assert_require_verified_signed_payload_accepted(
        signed_pacs008_xml_with_fixed_width_signature_value(),
        "XMLDSig ECDSA SignatureValue should accept fixed-width r||s bytes",
        None,
    );
    require_verified_profile_accepts_self_closing_signed_info_methods: assert_require_verified_signed_payload_accepted(
        signed_pacs008_xml_with_self_closing_signed_info(),
        "supported canonicalizer must expand self-closing SignedInfo methods",
        None,
    );
    require_verified_profile_rejects_raw_self_closing_signed_info_signature: assert_require_verified_signed_payload_rejected(
        signed_pacs008_xml_with_raw_self_closing_signed_info_signature(),
        "signature must be checked against canonical SignedInfo bytes",
    );
    require_verified_profile_rejects_extra_sgntr_signature_carrier: assert_require_verified_signed_payload_rejected(
        signed_pacs008_xml_with_extra_sgntr_carrier(),
        "extra XMLDSig/Sgntr signature carriers must fail closed",
    );
    require_verified_profile_accepts_certificate_chain_with_pinned_issuer: assert_pinned_certificate_chain_accepted(
        signed_pacs008_xml_with_certificate_chain(),
        "certificate chain ending at a pinned issuer must pass",
    );
    require_verified_profile_accepts_certificate_chain_with_path_len_permitting_intermediate: assert_pinned_certificate_chain_accepted(
        signed_pacs008_xml_with_three_certificate_chain(1),
        "pathLenConstraint=1 should allow one subordinate intermediate CA",
    );
}
#[test]
fn require_verified_profile_accepts_x509_certificate_chain_trust_anchor() {
    assert_x509_trust_anchor_payload_accepted(
        signed_pacs008_xml_with_x509_certificate_chain(),
        test_x509_chain_root_certificate_pin(),
        |_| {},
        "X.509 chain signed by a pinned trust anchor should pass",
    );
}
#[test]
fn require_verified_profile_rejects_x509_xades_missing_signing_certificate_v2() {
    let signed_properties_xml = test_xades_signed_properties_xml();
    let payload = signed_pacs008_xml_with_x509_certificate_chain_and_signed_properties(
        &signed_properties_xml,
    );
    assert_x509_trust_anchor_payload_rejected(
        payload,
        test_x509_chain_root_certificate_pin(),
        |_| {},
        "X.509 XAdES signatures must identify the signing certificate",
    );
}
#[test]
fn require_verified_profile_rejects_x509_xades_signing_certificate_wrong_digest() {
    let signed_properties_xml =
        test_xades_signed_properties_xml_for_certificate(TEST_X509_CHAIN_ROOT_CERTIFICATE_DER_B64);
    let payload = signed_pacs008_xml_with_x509_certificate_chain_and_signed_properties(
        &signed_properties_xml,
    );
    assert_x509_trust_anchor_payload_rejected(
        payload,
        test_x509_chain_root_certificate_pin(),
        |_| {},
        "XAdES SigningCertificateV2 digest must match the signer leaf",
    );
}
#[test]
fn require_verified_profile_rejects_x509_xades_signing_certificate_wrong_algorithm() {
    let signed_properties_xml =
        test_xades_signed_properties_xml_for_certificate(TEST_X509_CHAIN_LEAF_CERTIFICATE_DER_B64)
            .replace(XMLDSIG_SHA256, "urn:unsupported:sha1");
    let payload = signed_pacs008_xml_with_x509_certificate_chain_and_signed_properties(
        &signed_properties_xml,
    );
    assert_x509_trust_anchor_payload_rejected(
        payload,
        test_x509_chain_root_certificate_pin(),
        |_| {},
        "XAdES SigningCertificateV2 must use SHA-256 cert digests",
    );
}
#[test]
fn require_verified_profile_rejects_x509_xades_duplicate_signing_certificate_v2() {
    let signing_certificate =
        test_xades_signing_certificate_v2_xml(TEST_X509_CHAIN_LEAF_CERTIFICATE_DER_B64);
    let signed_properties_xml = test_xades_signed_properties_xml_with_extra(&format!(
        "{signing_certificate}{signing_certificate}"
    ));
    let payload = signed_pacs008_xml_with_x509_certificate_chain_and_signed_properties(
        &signed_properties_xml,
    );
    assert_x509_trust_anchor_payload_rejected(
        payload,
        test_x509_chain_root_certificate_pin(),
        |_| {},
        "duplicate XAdES SigningCertificateV2 entries must fail closed",
    );
}
#[test]
fn require_verified_profile_rejects_x509_xades_signing_certificate_issuer_serial_metadata() {
    let mut config = sample_config();
    let mut profile = signed_message_profile("require-verified");
    profile.signature_public_key_sha256_pins.clear();
    profile.x509_trust_anchor_sha256_pins = vec![test_x509_chain_root_certificate_pin()];
    config.profiles.push(profile);
    let runtime = Iso20022BridgeRuntime::from_config(&config)
        .expect("cfg")
        .expect("enabled");
    let profile = runtime
        .resolve_profile(Some("signed-pacs008-test"))
        .expect("signed profile");
    let cases = [
        "<IssuerSerial><X509IssuerName>CN=Wrong Root</X509IssuerName><X509SerialNumber>999</X509SerialNumber></IssuerSerial>",
        "<IssuerSerialV2><X509IssuerName>CN=Wrong Root</X509IssuerName><X509SerialNumber>999</X509SerialNumber></IssuerSerialV2>",
        r#"<xades:IssuerSerialV2 xmlns:xades="http://uri.etsi.org/01903/v1.3.2#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509IssuerName>CN=Wrong Root</ds:X509IssuerName><ds:X509SerialNumber>999</ds:X509SerialNumber></xades:IssuerSerialV2>"#,
        "<X509IssuerSerial><X509IssuerName>CN=Wrong Root</X509IssuerName><X509SerialNumber>999</X509SerialNumber></X509IssuerSerial>",
    ];
    for issuer_serial in cases {
        let signing_certificate = test_xades_signing_certificate_v2_xml_with_cert_extra(
            TEST_X509_CHAIN_LEAF_CERTIFICATE_DER_B64,
            issuer_serial,
        );
        let signed_properties_xml =
            test_xades_signed_properties_xml_with_extra(&signing_certificate);
        let payload = signed_pacs008_xml_with_x509_certificate_chain_and_signed_properties(
            &signed_properties_xml,
        );
        let parsed = parse_message("pacs.008", payload.as_bytes()).expect("parse signed XML");
        let err = runtime
            .validate_profile_submission(profile, "pacs.008", &parsed, payload.as_bytes())
            .expect_err("unsupported SigningCertificateV2 issuer/serial metadata must fail");
        assert!(
            matches!(err, MsgError::ValidationFailed),
            "unexpected error for issuer/serial {issuer_serial:?}: {err:?}",
        );
    }
}
#[test]
fn require_verified_profile_rejects_x509_xades_signing_certificate_v2_outside_signature_properties()
{
    let signing_certificate =
        test_xades_signing_certificate_v2_xml(TEST_X509_CHAIN_LEAF_CERTIFICATE_DER_B64);
    let signed_properties_xml = format!(
        concat!(
            r#"<SignedProperties xmlns="{XADES_NS}" Id="xades-signed-props-001">"#,
            "<SignedSignatureProperties><SigningTime>2026-06-02T00:00:00Z</SigningTime></SignedSignatureProperties>",
            "<SignedDataObjectProperties>{signing_certificate}</SignedDataObjectProperties>",
            "</SignedProperties>"
        ),
        signing_certificate = signing_certificate,
        XADES_NS = XADES_NS
    );
    let payload = signed_pacs008_xml_with_x509_certificate_chain_and_signed_properties(
        &signed_properties_xml,
    );
    assert_x509_trust_anchor_payload_rejected(
        payload,
        test_x509_chain_root_certificate_pin(),
        |_| {},
        "SigningCertificateV2 outside SignedSignatureProperties must fail closed",
    );
}
#[test]
fn require_verified_profile_accepts_directly_pinned_x509_critical_signer_key_usage() {
    let payload = signed_pacs008_xml_with_signer_key_usage_x509_certificate_chain(
        TEST_X509_SIGNER_KEY_USAGE_CRITICAL_LEAF_CERTIFICATE_DER_B64,
        false,
    );
    let metadata = validate_require_verified_signed_payload(&payload, |profile| {
        profile.signature_public_key_sha256_pins =
            vec![test_x509_signer_key_usage_leaf_public_key_pin()];
    })
    .expect("directly pinned signer leaf with critical digitalSignature should pass");
    assert!(metadata.embedded_signature_detected());
}
#[test]
fn require_verified_profile_rejects_directly_pinned_x509_noncritical_signer_key_usage() {
    let payload = signed_pacs008_xml_with_signer_key_usage_x509_certificate_chain(
        TEST_X509_SIGNER_KEY_USAGE_NONCRITICAL_LEAF_CERTIFICATE_DER_B64,
        false,
    );
    let err = validate_require_verified_signed_payload(&payload, |profile| {
        profile.signature_public_key_sha256_pins =
            vec![test_x509_signer_key_usage_leaf_public_key_pin()];
    })
    .expect_err("direct public-key pins must not bypass non-critical signer KeyUsage");
    assert!(matches!(err, MsgError::ValidationFailed));
}
#[test]
fn require_verified_profile_accepts_trust_anchor_x509_critical_signer_key_usage() {
    assert_x509_trust_anchor_payload_accepted(
        signed_pacs008_xml_with_signer_key_usage_x509_certificate_chain(
            TEST_X509_SIGNER_KEY_USAGE_CRITICAL_LEAF_CERTIFICATE_DER_B64,
            true,
        ),
        test_x509_signer_key_usage_root_certificate_pin(),
        |_| {},
        "trust-anchor signer leaf with critical digitalSignature should pass",
    );
}
#[test]
fn require_verified_profile_rejects_trust_anchor_x509_noncritical_signer_key_usage() {
    assert_x509_trust_anchor_payload_rejected(
        signed_pacs008_xml_with_signer_key_usage_x509_certificate_chain(
            TEST_X509_SIGNER_KEY_USAGE_NONCRITICAL_LEAF_CERTIFICATE_DER_B64,
            true,
        ),
        test_x509_signer_key_usage_root_certificate_pin(),
        |_| {},
        "trust-anchor chains must not bypass non-critical signer KeyUsage",
    );
}
#[test]
fn require_verified_profile_rejects_directly_pinned_x509_unknown_critical_leaf() {
    let payload = signed_pacs008_xml_with_unknown_critical_leaf_x509_certificate_chain(false);
    let err = validate_require_verified_signed_payload(&payload, |profile| {
        profile.signature_public_key_sha256_pins =
            vec![test_x509_unknown_critical_leaf_public_key_pin()];
    })
    .expect_err("direct public-key pins must not bypass unknown critical X.509 extensions");
    assert!(matches!(err, MsgError::ValidationFailed));
}
#[test]
fn runtime_from_config_rejects_revoked_x509_trust_anchor_pin_overlap() {
    let CertificateChainSignedPayload { issuer_sha256, .. } =
        signed_pacs008_xml_with_certificate_chain();
    let mut config = sample_config();
    let mut profile = signed_message_profile("require-verified");
    profile.signature_public_key_sha256_pins.clear();
    profile.x509_trust_anchor_sha256_pins = vec![issuer_sha256.clone()];
    profile.revoked_certificate_sha256 = vec![issuer_sha256];
    config.profiles.push(profile);
    let err = runtime_config_error(
        &config,
        "trust-anchor and revoked certificate pins must be disjoint",
    );
    assert!(
        err.to_string().contains("x509_trust_anchor_sha256_pins")
            && err.to_string().contains("revoked_certificate_sha256"),
        "unexpected overlap error: {err:?}"
    );
}
#[test]
fn require_verified_profile_rejects_certificate_chain_with_revoked_leaf() {
    let CertificateChainSignedPayload {
        payload,
        leaf_sha256,
        issuer_sha256,
    } = signed_pacs008_xml_with_certificate_chain();
    assert_x509_trust_anchor_payload_rejected(
        payload,
        issuer_sha256,
        move |profile| profile.revoked_certificate_sha256 = vec![leaf_sha256],
        "revoked leaf certificate pins must override matching issuer trust pins",
    );
}
signed_payload_tests! {
    require_verified_profile_rejects_certificate_chain_with_non_ca_issuer: assert_pinned_certificate_chain_rejected(
        signed_pacs008_xml_with_certificate_chain_policy(false, true, true),
        "certificate-chain issuers must be CA certificates",
    );
    require_verified_profile_rejects_certificate_chain_without_issuer_key_cert_sign: assert_pinned_certificate_chain_rejected(
        signed_pacs008_xml_with_certificate_chain_policy(true, false, true),
        "certificate-chain issuers must carry keyCertSign usage",
    );
    certificate_chain_rejects_noncritical_issuer_basic_constraints: assert_pinned_certificate_chain_rejected(
        signed_pacs008_xml_with_certificate_chain_noncritical_issuer_basic_constraints(),
        "certificate-chain issuers must carry critical CA basicConstraints",
    );
    certificate_chain_rejects_noncritical_issuer_key_usage: assert_pinned_certificate_chain_rejected(
        signed_pacs008_xml_with_certificate_chain_noncritical_issuer_key_usage(),
        "certificate-chain issuers must carry critical keyCertSign usage",
    );
    certificate_chain_rejects_unsupported_certificate_algorithm: assert_pinned_certificate_chain_rejected(
        signed_pacs008_xml_with_p384_issuer_certificate_chain(),
        "certificate chains must stay in the supported P-256/SHA-256 corridor",
    );
    certificate_chain_rejects_compressed_leaf_spki: assert_pinned_certificate_chain_rejected(
        signed_pacs008_xml_with_compressed_leaf_certificate_spki(),
        "XMLDSig leaf certificate SPKI must be an uncompressed P-256 point",
    );
    certificate_chain_rejects_compressed_issuer_spki: assert_pinned_certificate_chain_rejected(
        signed_pacs008_xml_with_compressed_issuer_certificate_spki(),
        "XMLDSig issuer certificate SPKI must be an uncompressed P-256 point",
    );
    require_verified_profile_rejects_certificate_chain_without_leaf_digital_signature: assert_pinned_certificate_chain_rejected(
        signed_pacs008_xml_with_certificate_chain_policy(true, true, false),
        "XMLDSig leaf certificates must carry digitalSignature usage",
    );
    certificate_chain_rejects_noncritical_leaf_key_usage: assert_pinned_certificate_chain_rejected(
        signed_pacs008_xml_with_certificate_chain_noncritical_leaf_key_usage(),
        "XMLDSig leaf certificates must carry critical digitalSignature usage",
    );
    require_verified_profile_rejects_certificate_chain_with_leaf_ca_basic_constraints: assert_pinned_certificate_chain_rejected(
        signed_pacs008_xml_with_leaf_ca_certificate_chain(),
        "XMLDSig leaf certificates must not be CA certificates",
    );
    require_verified_profile_rejects_expired_certificate_chain_leaf: assert_pinned_certificate_chain_rejected(
        signed_pacs008_xml_with_certificate_chain_options(
            true,
            true,
            true,
            CertificateChainValidity::ExpiredLeaf,
            CertificateChainIssuerName::Matching,
            false,
        ),
        "XMLDSig leaf certificate must be valid at signing time",
    );
    require_verified_profile_rejects_certificate_chain_with_future_issuer: assert_pinned_certificate_chain_rejected(
        signed_pacs008_xml_with_certificate_chain_options(
            true,
            true,
            true,
            CertificateChainValidity::FutureIssuer,
            CertificateChainIssuerName::Matching,
            false,
        ),
        "XMLDSig issuer certificate must be valid at signing time",
    );
    require_verified_profile_rejects_certificate_chain_with_issuer_name_mismatch: assert_pinned_certificate_chain_rejected(
        signed_pacs008_xml_with_certificate_chain_issuer_name_mismatch(),
        "certificate-chain issuers must match child issuer distinguished names",
    );
    require_verified_profile_rejects_certificate_chain_path_len_violation: assert_pinned_certificate_chain_rejected(
        signed_pacs008_xml_with_three_certificate_chain(0),
        "pathLenConstraint=0 must reject a subordinate intermediate CA",
    );
    require_verified_profile_rejects_leaf_with_critical_unknown_extension: assert_pinned_certificate_chain_rejected(
        signed_pacs008_xml_with_certificate_chain_critical_unknown_extension(
            CertificateChainCriticalUnknownExtension::Leaf,
        ),
        "critical unknown leaf certificate extensions must fail closed",
    );
    require_verified_profile_rejects_issuer_with_critical_unknown_extension: assert_pinned_certificate_chain_rejected(
        signed_pacs008_xml_with_certificate_chain_critical_unknown_extension(
            CertificateChainCriticalUnknownExtension::Issuer,
        ),
        "critical unknown issuer certificate extensions must fail closed",
    );
    require_verified_profile_rejects_leaf_with_critical_unsupported_parsed_extension: assert_pinned_certificate_chain_rejected(
        signed_pacs008_xml_with_certificate_chain_critical_unsupported_parsed_extension(
            CertificateChainCriticalUnsupportedParsedExtension::Leaf,
        ),
        "critical parsed leaf certificate extensions outside the enforced subset must fail closed",
    );
    require_verified_profile_rejects_issuer_with_critical_unsupported_parsed_extension: assert_pinned_certificate_chain_rejected(
        signed_pacs008_xml_with_certificate_chain_critical_unsupported_parsed_extension(
            CertificateChainCriticalUnsupportedParsedExtension::Issuer,
        ),
        "critical parsed issuer certificate extensions outside the enforced subset must fail closed",
    );
}
#[test]
fn require_verified_profile_rejects_non_ascii_certificate_signing_time() {
    let mut fixture = signed_pacs008_xml_with_certificate_chain();
    fixture.payload = fixture.payload.replace(
        XML_SIGNATURE_TEST_SIGNING_TIME,
        "\u{ff12}\u{ff10}\u{ff12}\u{ff15}-01-01T12:00:00Z",
    );
    assert_pinned_certificate_chain_rejected(
        fixture,
        "XMLDSig certificate signing time parser must reject non-ASCII dates without panicking",
    );
}
#[test]
fn require_verified_profile_rejects_missing_signature() {
    let mut config = sample_config();
    config
        .profiles
        .push(signed_message_profile("require-verified"));
    let runtime = Iso20022BridgeRuntime::from_config(&config)
        .expect("cfg")
        .expect("enabled");
    let payload = unsigned_pacs008_xml();
    let parsed = parse_message("pacs.008", payload.as_bytes()).expect("parse unsigned XML");
    let profile = runtime
        .resolve_profile(Some("signed-pacs008-test"))
        .expect("signed profile");
    let err = runtime
        .validate_profile_submission(profile, "pacs.008", &parsed, payload.as_bytes())
        .expect_err("require-verified must fail closed when the signature is absent");
    assert!(matches!(err, MsgError::ValidationFailed));
}
#[test]
fn require_verified_profile_rejects_unsupported_canonicalization_method() {
    let payload = signed_pacs008_xml_with_x509_certificate_chain();
    assert_x509_trust_anchor_payload_rejected(
        payload,
        "22".repeat(32),
        |_| {},
        "untrusted X.509 chains must fail closed",
    );
}
#[test]
fn require_verified_profile_rejects_missing_x509_certificate_policy_oid() {
    let payload = signed_pacs008_xml_with_x509_certificate_chain();
    assert_x509_trust_anchor_payload_rejected(
        payload,
        test_x509_chain_root_certificate_pin(),
        |profile| {
            profile.x509_required_certificate_policy_oids = vec![TEST_X509_POLICY_OID.to_owned()];
        },
        "X.509 leaf certificates missing a required policy OID must fail closed",
    );
}
#[test]
fn require_verified_profile_rejects_wrong_x509_certificate_policy_oid() {
    let payload = signed_pacs008_xml_with_policy_x509_certificate_chain();
    assert_x509_trust_anchor_payload_rejected(
        payload,
        test_x509_policy_root_certificate_pin(),
        |profile| {
            profile.x509_required_certificate_policy_oids =
                vec!["1.3.6.1.4.1.55555.1.2".to_owned()];
        },
        "X.509 leaf certificates with the wrong policy OID must fail closed",
    );
}
#[test]
fn require_verified_profile_accepts_x509_certificate_policy_intermediate_path() {
    let fixture = signed_pacs008_xml_with_policy_intermediate_x509_certificate_chain(
        CertificatePolicyPathMode::Required,
    );
    assert_required_x509_policy_path_payload_accepted(fixture);
}
#[test]
fn require_verified_profile_accepts_x509_certificate_policy_intermediate_any_policy() {
    let fixture = signed_pacs008_xml_with_policy_intermediate_x509_certificate_chain(
        CertificatePolicyPathMode::AnyPolicy,
    );
    assert_required_x509_policy_path_payload_accepted(fixture);
}
#[test]
fn require_verified_profile_rejects_x509_certificate_policy_intermediate_gap() {
    let fixture = signed_pacs008_xml_with_policy_intermediate_x509_certificate_chain(
        CertificatePolicyPathMode::Missing,
    );
    assert_required_x509_policy_path_payload_rejected(
        fixture,
        "intermediate CAs without required certificate policies must fail closed",
    );
}
#[test]
fn require_verified_profile_rejects_x509_certificate_policy_intermediate_drift() {
    let fixture = signed_pacs008_xml_with_policy_intermediate_x509_certificate_chain(
        CertificatePolicyPathMode::Wrong,
    );
    assert_required_x509_policy_path_payload_rejected(
        fixture,
        "intermediate CAs with unrelated certificate policies must fail closed",
    );
}
#[test]
fn require_verified_profile_rejects_x509_policy_mappings_extension() {
    let fixture = signed_pacs008_xml_with_unsupported_policy_processing_x509_certificate_chain(
        UnsupportedPolicyProcessingExtension::PolicyMappings,
    );
    assert_required_x509_policy_path_payload_rejected(
        fixture,
        "X.509 policy mappings require full policy-tree processing and must fail closed",
    );
}
#[test]
fn require_verified_profile_rejects_x509_policy_constraints_extension() {
    let fixture = signed_pacs008_xml_with_unsupported_policy_processing_x509_certificate_chain(
        UnsupportedPolicyProcessingExtension::PolicyConstraints,
    );
    assert_required_x509_policy_path_payload_rejected(
        fixture,
        "X.509 policy constraints require full policy-tree processing and must fail closed",
    );
}
#[test]
fn require_verified_profile_rejects_x509_inhibit_any_policy_extension() {
    let fixture = signed_pacs008_xml_with_unsupported_policy_processing_x509_certificate_chain(
        UnsupportedPolicyProcessingExtension::InhibitAnyPolicy,
    );
    assert_required_x509_policy_path_payload_rejected(
        fixture,
        "X.509 inhibit-any-policy requires full policy-tree processing and must fail closed",
    );
}
#[test]
fn require_verified_profile_rejects_missing_x509_crl_when_required() {
    assert_x509_trust_anchor_payload_rejected(
        signed_pacs008_xml_with_crl_x509_certificate_chain(None),
        test_x509_crl_root_certificate_pin(),
        |profile| profile.x509_require_crl_revocation_check = true,
        "profiles requiring CRL revocation checking must fail without CRL material",
    );
}
signed_payload_tests! {
    require_verified_profile_accepts_x509_certificate_with_configured_crl: assert_x509_trust_anchor_payload_accepted(
        signed_pacs008_xml_with_crl_x509_certificate_chain(None),
        test_x509_crl_root_certificate_pin(),
        |profile| {
            profile.x509_require_crl_revocation_check = true;
            profile.x509_crl_der_base64 = vec![TEST_X509_CRL_EMPTY_DER_B64.to_owned()];
        },
        "configured CRL material should satisfy required signer revocation checking",
    );
    require_verified_profile_accepts_x509_certificate_with_embedded_crl: assert_x509_trust_anchor_payload_accepted(
        signed_pacs008_xml_with_crl_x509_certificate_chain(Some(TEST_X509_CRL_EMPTY_DER_B64)),
        test_x509_crl_root_certificate_pin(),
        |profile| profile.x509_require_crl_revocation_check = true,
        "embedded CRL material should satisfy required signer revocation checking",
    );
    require_verified_profile_rejects_x509_crl_not_yet_fresh_at_signing_time: assert_x509_trust_anchor_payload_rejected(
        signed_pacs008_xml_with_crl_x509_certificate_chain_at(None, "2026-05-01T12:00:00Z"),
        test_x509_crl_root_certificate_pin(),
        |profile| {
            profile.x509_require_crl_revocation_check = true;
            profile.x509_crl_der_base64 = vec![TEST_X509_CRL_EMPTY_DER_B64.to_owned()];
        },
        "CRLs whose lastUpdate is after the signed evaluation time must fail closed",
    );
}
#[test]
fn require_verified_profile_rejects_x509_crl_outside_key_info() {
    let payload = signed_pacs008_xml_with_crl_x509_certificate_chain(None).replacen(
            &format!(r##"<Object><QualifyingProperties xmlns="{XADES_NS}" Target="#sig-001">"##),
            &format!(
                r##"<Object><X509CRL>{TEST_X509_CRL_EMPTY_DER_B64}</X509CRL><QualifyingProperties xmlns="{XADES_NS}" Target="#sig-001">"##
            ),
            1,
        );
    assert_x509_trust_anchor_payload_rejected(
        payload,
        test_x509_crl_root_certificate_pin(),
        |profile| profile.x509_require_crl_revocation_check = true,
        "CRL material outside signed KeyInfo/X509Data must fail closed",
    );
}
#[test]
fn require_verified_profile_rejects_x509_crl_in_key_info_outside_x509_data() {
    let payload = signed_pacs008_xml_with_crl_x509_certificate_chain(None).replacen(
        "</X509Data></KeyInfo>",
        &format!("</X509Data><X509CRL>{TEST_X509_CRL_EMPTY_DER_B64}</X509CRL></KeyInfo>"),
        1,
    );
    assert_x509_trust_anchor_payload_rejected(
        payload,
        test_x509_crl_root_certificate_pin(),
        |profile| profile.x509_require_crl_revocation_check = true,
        "CRL material outside X509Data must fail closed",
    );
}
#[test]
fn require_verified_profile_rejects_x509_certificate_revoked_by_configured_crl() {
    let payload = signed_pacs008_xml_with_crl_x509_certificate_chain(None);
    assert_x509_trust_anchor_payload_rejected(
        payload,
        test_x509_crl_root_certificate_pin(),
        |profile| {
            profile.x509_crl_der_base64 = vec![TEST_X509_CRL_REVOKED_DER_B64.to_owned()];
        },
        "configured CRL material must reject revoked signer certificates",
    );
}
#[test]
fn require_verified_profile_rejects_expired_x509_crl() {
    let payload = signed_pacs008_xml_with_crl_x509_certificate_chain(None);
    assert_x509_trust_anchor_payload_rejected(
        payload,
        test_x509_crl_root_certificate_pin(),
        |profile| {
            profile.x509_require_crl_revocation_check = true;
            profile.x509_crl_der_base64 = vec![TEST_X509_CRL_EXPIRED_DER_B64.to_owned()];
        },
        "expired CRLs must fail closed",
    );
}
#[test]
fn require_verified_profile_rejects_x509_crl_from_wrong_issuer() {
    assert_x509_trust_anchor_payload_rejected(
        signed_pacs008_xml_with_crl_x509_certificate_chain(None),
        test_x509_crl_root_certificate_pin(),
        |profile| {
            profile.x509_require_crl_revocation_check = true;
            profile.x509_crl_der_base64 = vec![TEST_X509_CRL_OTHER_ISSUER_DER_B64.to_owned()];
        },
        "CRLs from unrelated issuers must not satisfy signer revocation checking",
    );
}
signed_payload_tests! {
    require_verified_profile_rejects_missing_x509_ocsp_when_required: assert_x509_trust_anchor_payload_rejected(
        signed_pacs008_xml_with_ocsp_x509_certificate_chain(None),
        test_x509_ocsp_root_certificate_pin(),
        |profile| profile.x509_require_ocsp_revocation_check = true,
        "profiles requiring OCSP revocation checking must fail without OCSP material",
    );
}
#[test]
fn require_verified_profile_accepts_x509_certificate_with_configured_ocsp() {
    let fixture = signed_pacs008_xml_with_generated_ocsp_x509_certificate_chain(
        TestOcspResponseStatus::Good,
        false,
        XML_SIGNATURE_TEST_SIGNING_TIME,
    );
    let response_der_base64 = fixture.response_der_base64.clone();
    assert_x509_trust_anchor_payload_accepted(
        fixture.payload,
        fixture.trust_anchor_pin,
        move |profile| {
            profile.x509_require_ocsp_revocation_check = true;
            profile.x509_ocsp_response_der_base64 = vec![response_der_base64];
        },
        "configured OCSP material should satisfy required signer revocation checking",
    );
}
#[test]
fn require_verified_profile_accepts_x509_certificate_with_embedded_ocsp() {
    let fixture = signed_pacs008_xml_with_generated_ocsp_x509_certificate_chain(
        TestOcspResponseStatus::Good,
        true,
        XML_SIGNATURE_TEST_SIGNING_TIME,
    );
    assert_x509_trust_anchor_payload_accepted(
        fixture.payload,
        fixture.trust_anchor_pin,
        |profile| profile.x509_require_ocsp_revocation_check = true,
        "embedded OCSP material should satisfy required signer revocation checking",
    );
}
#[test]
fn require_verified_profile_rejects_x509_ocsp_not_yet_fresh_at_signing_time() {
    let fixture = signed_pacs008_xml_with_generated_ocsp_x509_certificate_chain(
        TestOcspResponseStatus::Good,
        false,
        "2026-05-01T12:00:00Z",
    );
    let response_der_base64 = fixture.response_der_base64.clone();
    assert_x509_trust_anchor_payload_rejected(
        fixture.payload,
        fixture.trust_anchor_pin,
        move |profile| {
            profile.x509_require_ocsp_revocation_check = true;
            profile.x509_ocsp_response_der_base64 = vec![response_der_base64];
        },
        "OCSP responses produced after the signed evaluation time must fail closed",
    );
}
#[test]
fn require_verified_profile_rejects_x509_ocsp_outside_key_info() {
    let fixture = signed_pacs008_xml_with_generated_ocsp_x509_certificate_chain(
        TestOcspResponseStatus::Good,
        false,
        XML_SIGNATURE_TEST_SIGNING_TIME,
    );
    let payload = fixture.payload.replacen(
            &format!(r##"<Object><QualifyingProperties xmlns="{XADES_NS}" Target="#sig-001">"##),
            &format!(
                r##"<Object><EncapsulatedOCSPValue>{}</EncapsulatedOCSPValue><QualifyingProperties xmlns="{XADES_NS}" Target="#sig-001">"##,
                fixture.response_der_base64
            ),
            1,
        );
    assert_x509_trust_anchor_payload_rejected(
        payload,
        fixture.trust_anchor_pin,
        |profile| profile.x509_require_ocsp_revocation_check = true,
        "OCSP material outside signed KeyInfo/X509Data must fail closed",
    );
}
#[test]
fn require_verified_profile_rejects_x509_ocsp_in_key_info_outside_x509_data() {
    let fixture = signed_pacs008_xml_with_generated_ocsp_x509_certificate_chain(
        TestOcspResponseStatus::Good,
        false,
        XML_SIGNATURE_TEST_SIGNING_TIME,
    );
    let payload = fixture.payload.replacen(
        "</X509Data></KeyInfo>",
        &format!(
            "</X509Data><EncapsulatedOCSPValue>{}</EncapsulatedOCSPValue></KeyInfo>",
            fixture.response_der_base64
        ),
        1,
    );
    assert_x509_trust_anchor_payload_rejected(
        payload,
        fixture.trust_anchor_pin,
        |profile| profile.x509_require_ocsp_revocation_check = true,
        "OCSP material outside X509Data must fail closed",
    );
}
#[test]
fn require_verified_profile_rejects_x509_certificate_revoked_by_configured_ocsp() {
    let fixture = signed_pacs008_xml_with_generated_ocsp_x509_certificate_chain(
        TestOcspResponseStatus::Revoked,
        false,
        XML_SIGNATURE_TEST_SIGNING_TIME,
    );
    let response_der_base64 = fixture.response_der_base64.clone();
    assert_x509_trust_anchor_payload_rejected(
        fixture.payload,
        fixture.trust_anchor_pin,
        move |profile| profile.x509_ocsp_response_der_base64 = vec![response_der_base64],
        "configured OCSP material must reject revoked signer certificates",
    );
}
#[test]
fn require_verified_profile_accepts_delegated_x509_ocsp_responder() {
    let fixture = signed_pacs008_xml_with_generated_delegated_ocsp_x509_certificate_chain(true);
    let response_der_base64 = fixture.response_der_base64.clone();
    assert_x509_trust_anchor_payload_accepted(
        fixture.payload,
        fixture.trust_anchor_pin,
        move |profile| {
            profile.x509_require_ocsp_revocation_check = true;
            profile.x509_ocsp_response_der_base64 = vec![response_der_base64];
        },
        "delegated OCSP responders with embedded responder certificates should verify",
    );
}
#[test]
fn require_verified_profile_rejects_delegated_x509_ocsp_without_responder_certificate() {
    let fixture = signed_pacs008_xml_with_generated_delegated_ocsp_x509_certificate_chain(false);
    let response_der_base64 = fixture.response_der_base64.clone();
    assert_x509_trust_anchor_payload_rejected(
        fixture.payload,
        fixture.trust_anchor_pin,
        move |profile| {
            profile.x509_require_ocsp_revocation_check = true;
            profile.x509_ocsp_response_der_base64 = vec![response_der_base64];
        },
        "delegated OCSP responses must include a verifiable responder certificate",
    );
}
#[test]
fn require_verified_profile_rejects_x509_chain_missing_trust_anchor_certificate() {
    let payload = signed_pacs008_xml_with_leaf_x509_certificate();
    assert_x509_trust_anchor_payload_rejected(
        payload,
        test_x509_chain_root_certificate_pin(),
        |_| {},
        "leaf-only X.509 key info must not satisfy a root-anchor profile",
    );
}
#[test]
fn require_verified_profile_rejects_non_ca_x509_trust_anchor() {
    let payload = signed_pacs008_xml_with_leaf_x509_certificate();
    assert_x509_trust_anchor_payload_rejected(
        payload,
        test_x509_leaf_certificate_pin(),
        |_| {},
        "non-CA certificates must not act as X.509 trust anchors",
    );
}
#[test]
fn require_verified_profile_rejects_x509_chain_issuer_mismatch() {
    let payload = signed_pacs008_xml_with_leaf_x509_certificate().replace(
        "</X509Data>",
        &format!("<X509Certificate>{TEST_X509_CERTIFICATE_DER_B64}</X509Certificate></X509Data>"),
    );
    assert_x509_trust_anchor_payload_rejected(
        payload,
        sha256_hex(
            &BASE64_STANDARD
                .decode(TEST_X509_CERTIFICATE_DER_B64)
                .expect("X.509 fixture must decode"),
        ),
        |_| {},
        "issuer/subject mismatches in X.509 chains must fail closed",
    );
}
#[test]
fn require_verified_profile_rejects_missing_key_pin() {
    let payload = signed_pacs008_xml();
    let err = validate_require_verified_signed_payload(&payload, |profile| {
        profile.signature_public_key_sha256_pins.clear();
    })
    .expect_err("require-verified must fail closed without a configured key pin");
    assert!(matches!(err, MsgError::ValidationFailed));
}
#[test]
fn require_verified_profile_rejects_wrong_public_key_pin() {
    let payload = signed_pacs008_xml();
    let err = validate_require_verified_signed_payload(&payload, |profile| {
        profile.signature_public_key_sha256_pins = vec!["11".repeat(32)];
    })
    .expect_err("mismatched signer public-key pins must fail closed");
    assert!(matches!(err, MsgError::ValidationFailed));
}
#[test]
fn require_verified_profile_rejects_unpinned_x509_certificate() {
    let payload = signed_pacs008_xml_with_x509_certificate();
    let err = validate_require_verified_signed_payload(&payload, |profile| {
        profile.signature_public_key_sha256_pins.clear();
    })
    .expect_err("X.509 XMLDSig payloads must fail closed without a configured key pin");
    assert!(matches!(err, MsgError::ValidationFailed));
}
#[test]
fn require_verified_profile_rejects_signed_info_method_unsupported_attributes() {
    let canonicalization_payload = signed_pacs008_xml_with_signed_info_rewrite(|signed_info| {
        let method = format!(
            r#"<CanonicalizationMethod Algorithm="{XML_C14N_1_0}"></CanonicalizationMethod>"#
        );
        let unsupported = format!(
            r#"<CanonicalizationMethod Algorithm="{XML_C14N_1_0}" Id="c14n-001"></CanonicalizationMethod>"#
        );
        signed_info.replacen(&method, &unsupported, 1)
    });
    let signature_payload = signed_pacs008_xml_with_signed_info_rewrite(|signed_info| {
        let method =
            format!(r#"<SignatureMethod Algorithm="{XMLDSIG_ECDSA_SHA256}"></SignatureMethod>"#);
        let unsupported = format!(
            r#"<SignatureMethod Algorithm="{XMLDSIG_ECDSA_SHA256}" Id="signature-method-001"></SignatureMethod>"#
        );
        signed_info.replacen(&method, &unsupported, 1)
    });
    for payload in [canonicalization_payload, signature_payload] {
        assert_require_verified_signed_payload_rejected(
            payload,
            "unsupported SignedInfo method attributes must fail closed",
        );
    }
}
#[test]
fn require_verified_profile_rejects_reference_unsupported_attributes() {
    let reference_payload = signed_pacs008_xml_with_signed_info_rewrite(|signed_info| {
        signed_info.replacen(
            r#"<Reference URI="">"#,
            r#"<Reference URI="" Id="payload-ref-001">"#,
            1,
        )
    });
    let transforms_payload = signed_pacs008_xml_with_signed_info_rewrite(|signed_info| {
        signed_info.replacen("<Transforms>", r#"<Transforms Id="transforms-001">"#, 1)
    });
    let transform_payload = signed_pacs008_xml_with_signed_info_rewrite(|signed_info| {
        let transform =
            format!(r#"<Transform Algorithm="{XMLDSIG_ENVELOPED_SIGNATURE}"></Transform>"#);
        let unsupported = format!(
            r#"<Transform Algorithm="{XMLDSIG_ENVELOPED_SIGNATURE}" Id="transform-001"></Transform>"#
        );
        signed_info.replacen(&transform, &unsupported, 1)
    });
    let digest_method_payload = signed_pacs008_xml_with_signed_info_rewrite(|signed_info| {
        let method = format!(r#"<DigestMethod Algorithm="{XMLDSIG_SHA256}"></DigestMethod>"#);
        let unsupported = format!(
            r#"<DigestMethod Algorithm="{XMLDSIG_SHA256}" Id="digest-method-001"></DigestMethod>"#
        );
        signed_info.replacen(&method, &unsupported, 1)
    });
    for payload in [
        reference_payload,
        transforms_payload,
        transform_payload,
        digest_method_payload,
    ] {
        assert_require_verified_signed_payload_rejected(
            payload,
            "unsupported Reference attributes must fail closed",
        );
    }
}
signed_payload_tests! {
    require_verified_profile_rejects_extra_reference_transform: assert_require_verified_signed_payload_rejected(
        signed_pacs008_xml_with_extra_reference_transform(),
        "Reference transforms outside the supported set must fail closed",
    );
}
#[test]
fn require_verified_profile_rejects_signing_certificate_v2_digest_tampering() {
    let fixture = signed_pacs008_xml_with_certificate_chain_signed_properties_reference();
    let tampered_digest = BASE64_STANDARD.encode([0u8; 32]);
    let payload = fixture
        .payload
        .replace(&fixture.signing_certificate_digest, &tampered_digest);
    assert_x509_trust_anchor_payload_rejected(
        payload,
        fixture.issuer_sha256,
        |_| {},
        "SigningCertificateV2 digest tampering must fail closed",
    );
}
#[test]
fn require_verified_profile_rejects_compressed_public_key() {
    let signing_key = xml_signature_test_signing_key();
    let compressed_public_key = signing_key
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .to_vec();
    let payload =
        signed_pacs008_xml_with_public_key(&BASE64_STANDARD.encode(&compressed_public_key));
    let err = validate_require_verified_signed_payload(&payload, |profile| {
        profile.signature_public_key_sha256_pins = vec![sha256_hex(&compressed_public_key)];
    })
    .expect_err("compressed SEC1 PublicKey material must fail closed");
    assert!(matches!(err, MsgError::ValidationFailed));
}
#[test]
fn require_verified_profile_rejects_certificate_without_x509_data_wrapper() {
    let mut fixture = signed_pacs008_xml_with_certificate_chain();
    fixture.payload = fixture
        .payload
        .replace("<X509Data>", "")
        .replace("</X509Data>", "");
    assert_pinned_certificate_chain_rejected(
        fixture,
        "X509Certificate elements must be wrapped in X509Data",
    );
}
#[test]
fn require_verified_profile_rejects_x509_data_extra_child() {
    let mut fixture = signed_pacs008_xml_with_certificate_chain();
    fixture.payload = fixture.payload.replacen(
        "</X509Data>",
        "<X509IssuerSerial></X509IssuerSerial></X509Data>",
        1,
    );
    assert_pinned_certificate_chain_rejected(
        fixture,
        "unsupported X509Data child elements must fail closed",
    );
}
#[test]
fn require_verified_profile_rejects_x509_certificate_unsupported_attribute() {
    let mut fixture = signed_pacs008_xml_with_certificate_chain();
    fixture.payload = fixture.payload.replacen(
        "<X509Certificate>",
        "<X509Certificate Encoding=\"base64\">",
        1,
    );
    assert_pinned_certificate_chain_rejected(
        fixture,
        "unsupported X509Certificate attributes must fail closed",
    );
}
#[test]
fn require_verified_profile_rejects_x509_certificate_nested_markup() {
    let mut fixture = signed_pacs008_xml_with_certificate_chain();
    fixture.payload =
        fixture
            .payload
            .replacen("</X509Certificate>", "<Chunk></Chunk></X509Certificate>", 1);
    assert_pinned_certificate_chain_rejected(
        fixture,
        "nested X509Certificate markup must fail closed",
    );
}
#[test]
fn require_verified_profile_rejects_duplicate_x509_certificate_der() {
    let mut fixture = signed_pacs008_xml_with_certificate_chain();
    let certificate_start = fixture
        .payload
        .find("<X509Certificate>")
        .expect("fixture X509Certificate start");
    let certificate_end = fixture
        .payload
        .find("</X509Certificate>")
        .map(|end| end + "</X509Certificate>".len())
        .expect("fixture X509Certificate end");
    let duplicate_certificate = fixture.payload[certificate_start..certificate_end].to_owned();
    fixture
        .payload
        .insert_str(certificate_end, &duplicate_certificate);
    assert_pinned_certificate_chain_rejected(
        fixture,
        "duplicate X509Certificate DER entries must fail closed",
    );
}
#[test]
fn reject_unsupported_profile_still_rejects_valid_embedded_signature() {
    let mut config = sample_config();
    config
        .profiles
        .push(signed_message_profile("reject-unsupported"));
    let runtime = Iso20022BridgeRuntime::from_config(&config)
        .expect("cfg")
        .expect("enabled");
    let payload = signed_pacs008_xml();
    let parsed = parse_message("pacs.008", payload.as_bytes()).expect("parse signed XML");
    let profile = runtime
        .resolve_profile(Some("signed-pacs008-test"))
        .expect("signed profile");
    let err = runtime
        .validate_profile_submission(profile, "pacs.008", &parsed, payload.as_bytes())
        .expect_err("reject-unsupported live profiles must keep rejecting signatures");
    assert!(matches!(err, MsgError::ValidationFailed));
}
#[test]
fn live_profile_requires_reference_datasets() {
    let runtime = sample_runtime();
    let parsed = sample_pacs008();
    let profile = runtime
        .resolve_profile(Some("swift-cbpr-plus"))
        .expect("swift profile");
    let err = runtime
        .validate_profile_submission(profile, "pacs.008", &parsed, b"profile payload")
        .expect_err("missing reference data must reject live profile");
    assert!(matches!(err, MsgError::ValidationFailed));
}
#[test]
fn live_profile_records_exact_reference_snapshot_checksum() {
    let first_snapshot = r#"{
            "version":"2024-05-01",
            "source":"GLEIF sample A",
            "entries":[{"bic":"DEUTDEFF","lei":"5493001KJTIIGC8Y1R12"}]
        }"#;
    let second_snapshot = r#"{
            "version":"2024-05-02",
            "source":"GLEIF sample B",
            "entries":[{"bic":"DEUTDEFF","lei":"5493001KJTIIGC8Y1R12"}]
        }"#;
    let first_file = write_snapshot(first_snapshot);
    let second_file = write_snapshot(second_snapshot);
    let payload = swift_pacs008_xml("HDR-SNAPSHOT-1", "123e4567-e89b-12d3-a456-426614174000");
    let parsed = parse_message("pacs.008", payload.as_bytes()).expect("parse live XML");
    let mut first_config = sample_config();
    first_config.reference_data.bic_lei_path = Some(first_file.path().to_path_buf());
    let first_runtime = Iso20022BridgeRuntime::from_config(&first_config)
        .expect("cfg")
        .expect("enabled");
    let first_profile = first_runtime
        .resolve_profile(Some("swift-cbpr-plus"))
        .expect("swift profile");
    let first_snapshot_id = first_runtime.reference_data().snapshot_id();
    let first_metadata = first_runtime
        .validate_profile_submission(first_profile, "pacs.008", &parsed, payload.as_bytes())
        .expect("first reference snapshot validates");
    assert_eq!(
        first_metadata.reference_snapshot_id(),
        Some(first_snapshot_id.as_str())
    );
    let mut second_config = sample_config();
    second_config.reference_data.bic_lei_path = Some(second_file.path().to_path_buf());
    let second_runtime = Iso20022BridgeRuntime::from_config(&second_config)
        .expect("cfg")
        .expect("enabled");
    let second_profile = second_runtime
        .resolve_profile(Some("swift-cbpr-plus"))
        .expect("swift profile");
    let second_snapshot_id = second_runtime.reference_data().snapshot_id();
    let second_metadata = second_runtime
        .validate_profile_submission(second_profile, "pacs.008", &parsed, payload.as_bytes())
        .expect("second reference snapshot validates");
    assert_eq!(
        second_metadata.reference_snapshot_id(),
        Some(second_snapshot_id.as_str())
    );
    assert_ne!(first_snapshot_id, second_snapshot_id);
}
#[test]
fn securities_profile_rejects_unknown_reference_crosswalk_values() {
    let (mut config, _reference_files) = sample_config_with_live_reference_data();
    config.profiles.push(live_securities_lifecycle_profile());
    let runtime = Iso20022BridgeRuntime::from_config(&config)
        .expect("cfg")
        .expect("enabled");
    let profile = runtime
        .resolve_profile(Some("securities-csd-lifecycle-fixtures"))
        .expect("securities lifecycle profile");
    let cases = [
        (
            "unknown instrument",
            SESE023_FIXTURE_XML.replace("US0378331005", "US5949181045"),
            "SctiesLeg/FinInstrmId",
            IdentifierKind::Isin,
        ),
        (
            "unknown venue MIC",
            SESE023_FIXTURE_XML.replace("XNAS", "XNYS"),
            "PlcOfSttlm/MktId",
            IdentifierKind::Mic,
        ),
        (
            "unknown settlement-party BIC",
            SESE023_FIXTURE_XML.replacen("DEUTDEFF", "TESTUS33", 1),
            "DlvrgSttlmPties/Pty/Bic",
            IdentifierKind::Bic,
        ),
    ];
    for (label, document, expected_field, expected_kind) in cases {
        let business_id = format!("SEC-INSTR-{}", label.replace(' ', "-"));
        let payload = data_pdu_with_app_header(
            &business_id,
            "sese.023.001.11",
            "securities.csd.cash",
            &document,
        );
        let parsed = parse_message("sese.023", payload.as_bytes())
            .unwrap_or_else(|err| panic!("{label} fixture must parse before lookup: {err:?}"));
        let err = match runtime.validate_profile_submission(
            profile,
            "sese.023",
            &parsed,
            payload.as_bytes(),
        ) {
            Ok(_) => panic!("{label} must fail reference-data validation"),
            Err(err) => err,
        };
        match err {
            MsgError::InvalidIdentifier { field, kind } => {
                assert_eq!(field, expected_field, "{label} field");
                assert_eq!(kind, expected_kind, "{label} kind");
            }
            other => panic!("{label} produced unexpected error: {other:?}"),
        }
    }
    assert!(
        runtime.message_status("sese.023:DVP-FIXTURE-1").is_none(),
        "rejected reference-data drift must not create a settlement record"
    );
}
#[test]
fn securities_profile_requires_sese023_ledger_crosswalk_snapshots() {
    let missing_cases = ["csd_venue_path", "securities_account_path", "cash_leg_path"];
    for missing in missing_cases {
        let (mut config, _reference_files) = sample_config_with_live_reference_data();
        match missing {
            "csd_venue_path" => config.reference_data.csd_venue_path = None,
            "securities_account_path" => config.reference_data.securities_account_path = None,
            "cash_leg_path" => config.reference_data.cash_leg_path = None,
            _ => unreachable!(),
        }
        config.profiles.push(live_securities_lifecycle_profile());
        let runtime = Iso20022BridgeRuntime::from_config(&config)
            .expect("cfg")
            .expect("enabled");
        let profile = runtime
            .resolve_profile(Some("securities-csd-lifecycle-fixtures"))
            .expect("securities lifecycle profile");
        let payload = data_pdu_with_app_header(
            &format!("SEC-INSTR-MISSING-{missing}"),
            "sese.023.001.11",
            "securities.csd.cash",
            SESE023_FIXTURE_XML,
        );
        let parsed = parse_message("sese.023", payload.as_bytes())
            .expect("sese.023 fixture parses before ledger gate");
        let err = runtime
            .validate_profile_submission(profile, "sese.023", &parsed, payload.as_bytes())
            .unwrap_err();
        assert!(
            matches!(err, MsgError::ValidationFailed),
            "{missing} should fail closed, got {err:?}"
        );
        assert!(
            runtime.message_status("sese.023:DVP-FIXTURE-1").is_none(),
            "missing {missing} must not create a settlement record"
        );
    }
}
#[test]
fn generic_securities_validation_cannot_skip_unconfigured_reference_data() {
    let mut config = sample_config();
    let mut profile = live_securities_lifecycle_profile();
    profile.id = "generic-securities-reference-gate".to_owned();
    profile.rail = "generic-iso20022".to_owned();
    profile.required_reference_datasets.clear();
    config.profiles.push(profile);
    let runtime = Iso20022BridgeRuntime::from_config(&config)
        .expect("cfg")
        .expect("enabled");
    let profile = runtime
        .resolve_profile(Some("generic-securities-reference-gate"))
        .expect("generic securities profile");
    let payload = data_pdu_with_app_header(
        "SEC-INSTR-MISSING-REFERENCE-DATA",
        "sese.023.001.11",
        "securities.csd.cash",
        SESE023_FIXTURE_XML,
    );
    let parsed = parse_message("sese.023", payload.as_bytes()).expect("sese.023 fixture parses");
    let err = runtime
        .validate_profile_submission(profile, "sese.023", &parsed, payload.as_bytes())
        .expect_err("unconfigured reference data must fail closed");
    assert!(matches!(err, MsgError::ValidationFailed));
}
#[test]
fn securities_profile_rejects_incomplete_sese023_ledger_crosswalk_rows() {
    let cases = [
        (
            "instrument asset mapping",
            "isin_crosswalk_path",
            r#"{
                    "version":"2024-05-01",
                    "source":"ANNA DSB sample",
                    "entries":[{"isin":"US0378331005","cusip":"037833100"}]
                }"#,
        ),
        (
            "CSD ledger domain",
            "csd_venue_path",
            r#"{
                    "version":"2024-05-01",
                    "source":"CSD sample",
                    "entries":[{"mic":"XNAS","csd_id":"DTC"}]
                }"#,
        ),
        (
            "settlement account",
            "securities_account_path",
            r#"{
                    "version":"2024-05-01",
                    "source":"CSD account sample",
                    "entries":[
                        {"settlement_account":"DLVRY-ACC","bic":"DEUTDEFF"},
                        {"settlement_account":"RCVG-ACC","bic":"MARKDEFF","account_id":"sorauﾛ1NfｷgﾉﾓﾉBｦKﾌﾘﾒoﾇﾂﾛrG81ﾋjWﾎﾕVncwﾌSｱ3pﾘﾋﾉhUS9Q76"}
                    ]
                }"#,
        ),
        (
            "cash-leg asset",
            "cash_leg_path",
            r#"{
                    "version":"2024-05-01",
                    "source":"CSD cash-leg sample",
                    "entries":[{"currency":"USD","payment_type":"APMT"}]
                }"#,
        ),
    ];
    for (label, path_name, snapshot) in cases {
        let (mut config, _reference_files) = sample_config_with_live_reference_data();
        let replacement = write_snapshot(snapshot);
        match path_name {
            "isin_crosswalk_path" => {
                config.reference_data.isin_crosswalk_path = Some(replacement.path().to_path_buf());
            }
            "csd_venue_path" => {
                config.reference_data.csd_venue_path = Some(replacement.path().to_path_buf());
            }
            "securities_account_path" => {
                config.reference_data.securities_account_path =
                    Some(replacement.path().to_path_buf());
            }
            "cash_leg_path" => {
                config.reference_data.cash_leg_path = Some(replacement.path().to_path_buf());
            }
            _ => unreachable!(),
        }
        config.profiles.push(live_securities_lifecycle_profile());
        let runtime = Iso20022BridgeRuntime::from_config(&config)
            .expect("cfg")
            .expect("enabled");
        let profile = runtime
            .resolve_profile(Some("securities-csd-lifecycle-fixtures"))
            .expect("securities lifecycle profile");
        let payload = data_pdu_with_app_header(
            &format!("SEC-INSTR-INCOMPLETE-{}", label.replace(' ', "-")),
            "sese.023.001.11",
            "securities.csd.cash",
            SESE023_FIXTURE_XML,
        );
        let parsed = parse_message("sese.023", payload.as_bytes())
            .unwrap_or_else(|err| panic!("{label} fixture must parse: {err:?}"));
        let err = runtime
            .validate_profile_submission(profile, "sese.023", &parsed, payload.as_bytes())
            .unwrap_err();
        assert!(
            matches!(err, MsgError::ValidationFailed),
            "{label} should fail closed, got {err:?}"
        );
        assert!(
            runtime.message_status("sese.023:DVP-FIXTURE-1").is_none(),
            "incomplete {label} mapping must not create a settlement record"
        );
    }
}
#[test]
fn securities_profile_rejects_sese023_ledger_crosswalk_value_mismatches() {
    let cases = [
        (
            "unknown delivery account",
            SESE023_FIXTURE_XML.replace("DLVRY-ACC", "UNKNOWN-ACC"),
            "DlvrgSttlmPties/Acct",
            InvalidValueKind::Enum,
        ),
        (
            "wrong party for account",
            SESE023_FIXTURE_XML.replace("DEUTDEFF", "MARKDEFF"),
            "DlvrgSttlmPties/Acct",
            InvalidValueKind::Enum,
        ),
    ];
    for (label, document, expected_field, expected_kind) in cases {
        let (mut config, _reference_files) = sample_config_with_live_reference_data();
        config.profiles.push(live_securities_lifecycle_profile());
        let runtime = Iso20022BridgeRuntime::from_config(&config)
            .expect("cfg")
            .expect("enabled");
        let profile = runtime
            .resolve_profile(Some("securities-csd-lifecycle-fixtures"))
            .expect("securities lifecycle profile");
        let payload = data_pdu_with_app_header(
            &format!("SEC-INSTR-MISMATCH-{}", label.replace(' ', "-")),
            "sese.023.001.11",
            "securities.csd.cash",
            &document,
        );
        let parsed = parse_message("sese.023", payload.as_bytes())
            .unwrap_or_else(|err| panic!("{label} fixture must parse: {err:?}"));
        let err = runtime
            .validate_profile_submission(profile, "sese.023", &parsed, payload.as_bytes())
            .unwrap_err();
        match err {
            MsgError::InvalidValue { field, kind } => {
                assert_eq!(field, expected_field, "{label} field");
                assert_eq!(kind, expected_kind, "{label} kind");
            }
            other => panic!("{label} produced unexpected error: {other:?}"),
        }
        assert!(
            runtime.message_status("sese.023:DVP-FIXTURE-1").is_none(),
            "mismatched {label} must not create a settlement record"
        );
    }
    let (mut config, _reference_files) = sample_config_with_live_reference_data();
    config.profiles.push(live_securities_lifecycle_profile());
    let runtime = Iso20022BridgeRuntime::from_config(&config)
        .expect("cfg")
        .expect("enabled");
    let profile = runtime
        .resolve_profile(Some("securities-csd-lifecycle-fixtures"))
        .expect("securities lifecycle profile");
    let payload = data_pdu_with_app_header(
        "SEC-INSTR-MISMATCH-CURRENCY",
        "sese.023.001.11",
        "securities.csd.cash",
        &SESE023_FIXTURE_XML.replace("Ccy=\"USD\"", "Ccy=\"EUR\""),
    );
    let parsed = parse_message("sese.023", payload.as_bytes())
        .expect("cash-leg mismatch fixture must parse");
    let err = runtime
        .validate_profile_submission(profile, "sese.023", &parsed, payload.as_bytes())
        .unwrap_err();
    match err {
        MsgError::InvalidIdentifier { field, kind } => {
            assert_eq!(field, "CashLeg/Ccy");
            assert_eq!(kind, IdentifierKind::Currency);
        }
        other => panic!("cash-leg mismatch produced unexpected error: {other:?}"),
    }
}
#[test]
fn checked_in_securities_fixtures_reject_profile_version_and_root_drift() {
    let (mut config, _reference_files) = sample_config_with_live_reference_data();
    config.profiles.push(live_securities_lifecycle_profile());
    let runtime = Iso20022BridgeRuntime::from_config(&config)
        .expect("cfg")
        .expect("enabled");
    let profile = runtime
        .resolve_profile(Some("securities-csd-lifecycle-fixtures"))
        .expect("securities lifecycle profile");
    let wrong_version_payload = data_pdu_with_app_header(
        "SEC-INSTR-BAD-VERSION",
        "sese.023.999.99",
        "securities.csd.cash",
        &SESE023_FIXTURE_XML.replace("sese.023.001.11", "sese.023.999.99"),
    );
    let wrong_version = parse_message("sese.023", wrong_version_payload.as_bytes())
        .expect("version-drift fixture parses before profile validation");
    let err = runtime
        .validate_profile_submission(
            profile,
            "sese.023",
            &wrong_version,
            wrong_version_payload.as_bytes(),
        )
        .expect_err("securities profile must reject unsupported sese.023 version drift");
    assert!(matches!(err, MsgError::UnknownMessageType));
    let root_drift_payload = data_pdu_with_app_header(
        "SEC-INSTR-ROOT-DRIFT",
        "sese.023.001.11",
        "securities.csd.cash",
        &SESE023_FIXTURE_XML.replace("SctiesSttlmTxInstr", "SctiesSttlmTxConf"),
    );
    let err = parse_message("sese.023", root_drift_payload.as_bytes())
        .expect_err("sese.023 parser must reject a sese.025-style document root");
    assert!(matches!(err, MsgError::UnknownMessageType));
    assert!(
        runtime.message_status("sese.023:DVP-FIXTURE-1").is_none(),
        "negative fixture drift must not create a securities settlement record"
    );
}
#[test]
fn checked_in_colr012_fixture_records_collateral_context() {
    let mut config = sample_config();
    let asset_definition_id = sample_asset_definition_literal();
    let isin_crosswalk = write_snapshot(&format!(
        r#"{{
            "version":"2024-05-01",
            "source":"ISO 20022 collateral fixture",
            "entries":[
                {{"isin":"US0378331005","asset_definition_id":"{asset_definition_id}"}},
                {{"isin":"US5949181045","asset_definition_id":"{asset_definition_id}"}}
            ]
        }}"#
    ));
    config.reference_data.isin_crosswalk_path = Some(isin_crosswalk.path().to_path_buf());
    config.profiles.push(live_collateral_lifecycle_profile());
    let runtime = Iso20022BridgeRuntime::from_config(&config)
        .expect("cfg")
        .expect("enabled");
    let profile = runtime
        .resolve_profile(Some("collateral-lifecycle-fixtures"))
        .expect("collateral lifecycle fixture profile");
    let parsed =
        parse_message("colr.012", COLR012_FIXTURE_XML.as_bytes()).expect("colr.012 fixture");
    let metadata = runtime
        .validate_profile_submission(profile, "colr.012", &parsed, COLR012_FIXTURE_XML.as_bytes())
        .expect("collateral fixture profile accepts colr.012 fixture");
    assert_eq!(metadata.profile_id(), Some("collateral-lifecycle-fixtures"));
    assert_eq!(metadata.message_type(), Some("colr.012"));
    assert_eq!(metadata.business_message_id(), None);
    let message_id = Iso20022BridgeRuntime::lifecycle_message_id("colr.012", &parsed)
        .expect("colr.012 durable id");
    assert_eq!(message_id, "colr.012:COLR-FIXTURE-1");
    assert!(runtime.check_and_record_inbound(&message_id, metadata));
    let outcome = runtime
        .apply_inbound_lifecycle_message(&message_id, "colr.012", &parsed)
        .expect("record colr.012 lifecycle");
    assert_eq!(outcome.action(), "recorded");
    assert_eq!(outcome.lifecycle_status_code(), Some("ACSC"));
    assert_eq!(outcome.lifecycle_reason_code(), Some("MARGIN"));
    assert_eq!(outcome.referenced_message_id(), None);
    let status = runtime
        .message_status(&message_id)
        .expect("colr.012 durable status");
    assert_eq!(status.status_label(), "Accepted");
    assert_eq!(status.pacs002_code(), "ACSP");
    assert_eq!(status.collateral_obligation_id(), Some("REPO-123"));
    assert_eq!(status.collateral_original_amount(), Some("1000000"));
    assert_eq!(status.collateral_original_currency(), Some("USD"));
    assert_eq!(
        status.collateral_original_instrument_id(),
        Some("US0378331005")
    );
    assert_eq!(status.collateral_substitute_amount(), Some("1002000"));
    assert_eq!(status.collateral_substitute_currency(), Some("USD"));
    assert_eq!(
        status.collateral_substitute_instrument_id(),
        Some("US5949181045")
    );
    assert_eq!(status.collateral_effective_date(), Some("2024-04-05"));
    assert_eq!(status.collateral_substitution_type(), Some("PARTIAL"));
    assert_eq!(status.collateral_haircut(), Some("50"));
    assert_eq!(status.collateral_reason_code(), Some("MARGIN"));
}
#[test]
fn live_rail_profile_xsd_fixtures_accept_supported_messages() {
    let (runtime, _reference_files) = runtime_with_live_reference_data();
    let cases = vec![
        (
            "swift-cbpr-plus",
            "pacs.008",
            "swift.cbprplus.02",
            live_pacs008_xml(
                "SWIFT-XSD-1",
                "pacs.008.001.08",
                "swift.cbprplus.02",
                "USD",
                "10.00",
                "123e4567-e89b-12d3-a456-426614174100",
            ),
        ),
        (
            "fedwire-funds",
            "pacs.008",
            "fedwire.funds.01",
            live_pacs008_xml(
                "FEDWIRE-XSD-1",
                "pacs.008.001.08",
                "fedwire.funds.01",
                "USD",
                "10.00",
                "123e4567-e89b-12d3-a456-426614174101",
            ),
        ),
        (
            "sepa-sct-inst",
            "pacs.008",
            "sepa.sct.inst",
            live_pacs008_xml(
                "SEPA-XSD-1",
                "pacs.008.001.08",
                "sepa.sct.inst",
                "EUR",
                "10.00",
                "123e4567-e89b-12d3-a456-426614174102",
            ),
        ),
        (
            "securities-csd",
            "pacs.009",
            "securities.csd.cash",
            live_pacs009_xml("SECURITIES-XSD-1", "pacs.009.001.08", "securities.csd.cash"),
        ),
    ];
    for (profile_id, message_type, expected_service, payload) in cases {
        let parsed = parse_message(message_type, payload.as_bytes())
            .unwrap_or_else(|err| panic!("{profile_id} fixture must parse: {err:?}"));
        let profile = runtime
            .resolve_profile(Some(profile_id))
            .unwrap_or_else(|| panic!("{profile_id} profile"));
        let metadata = runtime
            .validate_profile_submission(profile, message_type, &parsed, payload.as_bytes())
            .unwrap_or_else(|err| panic!("{profile_id} fixture must validate: {err:?}"));
        assert_eq!(metadata.profile_id(), Some(profile_id));
        assert_eq!(metadata.business_service(), Some(expected_service));
        assert_eq!(
            metadata.reference_snapshot_id(),
            Some(runtime.reference_data().snapshot_id().as_str())
        );
        assert_eq!(metadata.message_type(), Some(message_type));
    }
}
#[test]
fn live_rail_profile_xsd_fixtures_reject_wrong_business_services() {
    let (runtime, _reference_files) = runtime_with_live_reference_data();
    let cases = vec![
        (
            "fedwire-funds",
            "pacs.008",
            live_pacs008_xml(
                "FEDWIRE-BAD-SVC",
                "pacs.008.001.08",
                "swift.cbprplus.02",
                "USD",
                "10.00",
                "123e4567-e89b-12d3-a456-426614174201",
            ),
        ),
        (
            "sepa-sct-inst",
            "pacs.008",
            live_pacs008_xml(
                "SEPA-BAD-SVC",
                "pacs.008.001.08",
                "fedwire.funds.01",
                "EUR",
                "10.00",
                "123e4567-e89b-12d3-a456-426614174202",
            ),
        ),
        (
            "securities-csd",
            "pacs.009",
            live_pacs009_xml("SECURITIES-BAD-SVC", "pacs.009.001.08", "sepa.sct.inst"),
        ),
    ];
    for (profile_id, message_type, payload) in cases {
        let parsed = parse_message(message_type, payload.as_bytes())
            .unwrap_or_else(|err| panic!("{profile_id} wrong-service fixture parses: {err:?}"));
        let profile = runtime
            .resolve_profile(Some(profile_id))
            .unwrap_or_else(|| panic!("{profile_id} profile"));
        let err = runtime
            .validate_profile_submission(profile, message_type, &parsed, payload.as_bytes())
            .unwrap_err();
        assert!(matches!(
            err,
            MsgError::InvalidValue {
                field,
                kind: InvalidValueKind::Enum
            } if field == "AppHdr/BizSvc"
        ));
    }
}
#[test]
fn live_rail_profile_xsd_fixtures_reject_missing_required_app_header_members() {
    let (runtime, _reference_files) = runtime_with_live_reference_data();
    let base_payload = live_pacs008_xml(
        "SWIFT-MISSING-BAH",
        "pacs.008.001.08",
        "swift.cbprplus.02",
        "USD",
        "10.00",
        "123e4567-e89b-12d3-a456-426614174220",
    );
    let profile = runtime
        .resolve_profile(Some("swift-cbpr-plus"))
        .expect("swift profile");
    for tag in ["BizMsgIdr", "MsgDefIdr", "CreDt"] {
        let payload = remove_xml_element(&base_payload, tag);
        let parsed = parse_message("pacs.008", payload.as_bytes())
            .unwrap_or_else(|err| panic!("missing-{tag} fixture parses: {err:?}"));
        let err = runtime
            .validate_profile_submission(profile, "pacs.008", &parsed, payload.as_bytes())
            .unwrap_err();
        assert!(
            matches!(err, MsgError::MissingField("AppHdr")),
            "missing {tag} returned {err:?}"
        );
    }
}
#[test]
fn live_rail_profile_xsd_fixtures_reject_missing_required_business_service() {
    let (runtime, _reference_files) = runtime_with_live_reference_data();
    let cases = vec![
        (
            "fedwire-funds",
            "pacs.008",
            remove_xml_element(
                &live_pacs008_xml(
                    "FEDWIRE-MISSING-SVC",
                    "pacs.008.001.08",
                    "fedwire.funds.01",
                    "USD",
                    "10.00",
                    "123e4567-e89b-12d3-a456-426614174221",
                ),
                "BizSvc",
            ),
        ),
        (
            "sepa-sct-inst",
            "pacs.008",
            remove_xml_element(
                &live_pacs008_xml(
                    "SEPA-MISSING-SVC",
                    "pacs.008.001.08",
                    "sepa.sct.inst",
                    "EUR",
                    "10.00",
                    "123e4567-e89b-12d3-a456-426614174222",
                ),
                "BizSvc",
            ),
        ),
        (
            "securities-csd",
            "pacs.009",
            remove_xml_element(
                &live_pacs009_xml(
                    "SECURITIES-MISSING-SVC",
                    "pacs.009.001.08",
                    "securities.csd.cash",
                ),
                "BizSvc",
            ),
        ),
    ];
    for (profile_id, message_type, payload) in cases {
        let parsed = parse_message(message_type, payload.as_bytes())
            .unwrap_or_else(|err| panic!("{profile_id} missing-service fixture parses: {err:?}"));
        let profile = runtime
            .resolve_profile(Some(profile_id))
            .unwrap_or_else(|| panic!("{profile_id} profile"));
        let err = runtime
            .validate_profile_submission(profile, message_type, &parsed, payload.as_bytes())
            .unwrap_err();
        assert!(
            matches!(err, MsgError::MissingField("AppHdr/BizSvc")),
            "{profile_id} returned {err:?}"
        );
    }
}
#[test]
fn live_rail_profile_xsd_fixtures_reject_empty_required_business_service() {
    let (runtime, _reference_files) = runtime_with_live_reference_data();
    let payload = live_pacs008_xml(
        "FEDWIRE-EMPTY-SVC",
        "pacs.008.001.08",
        "fedwire.funds.01",
        "USD",
        "10.00",
        "123e4567-e89b-12d3-a456-426614174223",
    )
    .replace("<BizSvc>fedwire.funds.01</BizSvc>", "<BizSvc></BizSvc>");
    let parsed =
        parse_message("pacs.008", payload.as_bytes()).expect("empty-service XML fixture parses");
    let profile = runtime
        .resolve_profile(Some("fedwire-funds"))
        .expect("fedwire profile");
    let err = runtime
        .validate_profile_submission(profile, "pacs.008", &parsed, payload.as_bytes())
        .expect_err("empty BizSvc must not satisfy live rail service policy");
    assert!(matches!(err, MsgError::MissingField("AppHdr/BizSvc")));
}
#[test]
fn live_rail_profile_xsd_fixtures_reject_unstructured_postal_address_lines() {
    let (runtime, _reference_files) = runtime_with_live_reference_data();
    let payload = live_pacs008_xml(
        "SWIFT-UNSTRUCTURED-ADDRESS",
        "pacs.008.001.08",
        "swift.cbprplus.02",
        "USD",
        "10.00",
        "123e4567-e89b-12d3-a456-426614174230",
    )
    .replace(
        "<DbtrAcct>",
        "<Dbtr><PstlAdr><AdrLine>flat address line</AdrLine></PstlAdr></Dbtr>\n        <DbtrAcct>",
    );
    let parsed =
        parse_message("pacs.008", payload.as_bytes()).expect("unstructured-address XML parses");
    let profile = runtime
        .resolve_profile(Some("swift-cbpr-plus"))
        .expect("swift profile");
    let err = runtime
        .validate_profile_submission(profile, "pacs.008", &parsed, payload.as_bytes())
        .expect_err("live profiles require structured postal addresses");
    assert!(matches!(
        err,
        MsgError::InvalidValue {
            field,
            kind: InvalidValueKind::Enum
        } if field == "PstlAdr/AdrLine"
    ));
}
#[test]
fn live_profile_rejects_exact_unstructured_postal_address_field() {
    let (runtime, _reference_files) = runtime_with_live_reference_data();
    let parsed = parse_message(
            "pacs.008",
            b"DataPDU/AppHdr/BizMsgIdr=SWIFT-UNSTRUCTURED-ADDRESS-FIELD\nDataPDU/AppHdr/MsgDefIdr=pacs.008.001.08\nDataPDU/AppHdr/CreDt=2025-01-01T12:00:00Z\nDataPDU/AppHdr/BizSvc=swift.cbprplus.02\nMsgId=m-profile\nUETR=123e4567-e89b-12d3-a456-426614174232\nIntrBkSttlmAmt=10.00\nIntrBkSttlmCcy=USD\nIntrBkSttlmDt=2024-01-01\nDbtrAcct=GB82WEST12345698765432\nCdtrAcct=GB82WEST12345698765432\nDbtrAgt=DEUTDEFF\nCdtrAgt=MARKDEFF\nPstlAdr/AdrLine=flat address line",
        )
        .expect("exact unstructured address field parses");
    let profile = runtime
        .resolve_profile(Some("swift-cbpr-plus"))
        .expect("swift profile");
    let err = runtime
        .validate_profile_submission(profile, "pacs.008", &parsed, b"profile payload")
        .expect_err("live profiles reject exact unstructured address fields");
    assert!(matches!(
        err,
        MsgError::InvalidValue {
            field,
            kind: InvalidValueKind::Enum
        } if field == "PstlAdr/AdrLine"
    ));
}
#[test]
fn live_rail_profile_xsd_fixtures_reject_oversized_supplementary_data() {
    let (runtime, _reference_files) = runtime_with_live_reference_data();
    let oversized = "A".repeat(2100);
    let payload = live_pacs008_xml(
        "FEDWIRE-OVERSIZED-SUPPLEMENTARY",
        "pacs.008.001.08",
        "fedwire.funds.01",
        "USD",
        "10.00",
        "123e4567-e89b-12d3-a456-426614174231",
    )
    .replace(
        "</CdtTrfTxInf>",
        &format!(
            "<SplmtryData><Envelope>{oversized}</Envelope></SplmtryData>\n      </CdtTrfTxInf>"
        ),
    );
    let parsed =
        parse_message("pacs.008", payload.as_bytes()).expect("oversized supplementary XML parses");
    let profile = runtime
        .resolve_profile(Some("fedwire-funds"))
        .expect("fedwire profile");
    let err = runtime
        .validate_profile_submission(profile, "pacs.008", &parsed, payload.as_bytes())
        .expect_err("fedwire profile caps supplementary data");
    assert!(matches!(
        err,
        MsgError::TooManyOccurrences {
            field: "SplmtryData",
            max: 2048,
            actual
        } if actual > 2048
    ));
}
#[test]
fn live_rail_profile_xsd_fixtures_reject_version_and_amount_drift() {
    let (runtime, _reference_files) = runtime_with_live_reference_data();
    let bad_version = live_pacs008_xml(
        "FEDWIRE-BAD-VERSION",
        "pacs.008.999.99",
        "fedwire.funds.01",
        "USD",
        "10.00",
        "123e4567-e89b-12d3-a456-426614174301",
    );
    let parsed_bad_version =
        parse_message("pacs.008", bad_version.as_bytes()).expect("bad-version XML parses");
    let fedwire = runtime
        .resolve_profile(Some("fedwire-funds"))
        .expect("fedwire profile");
    let err = runtime
        .validate_profile_submission(
            fedwire,
            "pacs.008",
            &parsed_bad_version,
            bad_version.as_bytes(),
        )
        .expect_err("unsupported MDR version must fail profile validation");
    assert!(matches!(err, MsgError::UnknownMessageType));
    let bad_minor_units = live_pacs008_xml(
        "SEPA-BAD-AMOUNT",
        "pacs.008.001.08",
        "sepa.sct.inst",
        "EUR",
        "10.001",
        "123e4567-e89b-12d3-a456-426614174302",
    );
    let parsed_bad_minor_units =
        parse_message("pacs.008", bad_minor_units.as_bytes()).expect("bad-amount XML parses");
    let sepa = runtime
        .resolve_profile(Some("sepa-sct-inst"))
        .expect("sepa profile");
    let err = runtime
        .validate_profile_submission(
            sepa,
            "pacs.008",
            &parsed_bad_minor_units,
            bad_minor_units.as_bytes(),
        )
        .expect_err("minor-unit drift must fail profile validation");
    assert!(matches!(
        err,
        MsgError::InvalidValue {
            field,
            kind: InvalidValueKind::Amount
        } if field == "IntrBkSttlmAmt"
    ));
}
live_pacs008_parse_rejection_tests! {
    MsgError::UnknownMessageType;
    live_rail_profile_xsd_fixtures_reject_header_document_definition_drift:
        live_fedwire_pacs008_xml(
            "FEDWIRE-BAH-DOCUMENT-DRIFT",
            "123e4567-e89b-12d3-a456-426614174303",
        )
        .replace(
            "urn:iso:std:iso:20022:tech:xsd:pacs.008.001.08",
            "urn:iso:std:iso:20022:tech:xsd:pacs.008.001.10",
        )
        => "BAH MsgDefIdr and Document namespace drift must fail parsing";
    live_rail_profile_xsd_fixtures_reject_spoofed_document_namespace:
        live_fedwire_pacs008_xml(
            "FEDWIRE-SPOOFED-DOCUMENT-NS",
            "123e4567-e89b-12d3-a456-426614174304",
        )
        .replace(
            "urn:iso:std:iso:20022:tech:xsd:pacs.008.001.08",
            "https://attacker.invalid/schema:pacs.008.001.08",
        )
        => "Document namespace suffix spoofing must fail parsing";
    live_rail_profile_xsd_fixtures_reject_unqualified_document_namespace:
        live_fedwire_pacs008_xml(
            "FEDWIRE-UNQUALIFIED-DOCUMENT-NS",
            "123e4567-e89b-12d3-a456-426614174305",
        )
        .replace(
            r#"<Document xmlns="urn:iso:std:iso:20022:tech:xsd:pacs.008.001.08">"#,
            "<Document>",
        )
        => "Document without an ISO namespace must fail parsing";
}
live_pacs008_parse_rejection_tests! {
    MsgError::InvalidFormat;
    live_rail_profile_xsd_fixtures_reject_mismatched_closing_tag:
        live_fedwire_pacs008_xml(
            "FEDWIRE-MISMATCHED-CLOSE",
            "123e4567-e89b-12d3-a456-426614174307",
        )
        .replace("</GrpHdr>", "</WrongGrpHdr>")
        => "mismatched XML close tags must fail parsing";
    live_rail_profile_xsd_fixtures_reject_mixed_xml_content:
        live_fedwire_pacs008_xml(
            "FEDWIRE-MIXED-CONTENT",
            "123e4567-e89b-12d3-a456-426614174314",
        )
        .replace("<GrpHdr><MsgId>", "<GrpHdr>mixed<MsgId>")
        => "mixed XML content must fail parsing";
    live_rail_profile_xsd_fixtures_reject_unquoted_document_namespace_attribute:
        live_fedwire_pacs008_xml(
            "FEDWIRE-UNQUOTED-DOCUMENT-NS",
            "123e4567-e89b-12d3-a456-426614174308",
        )
        .replace(
            r#"<Document xmlns="urn:iso:std:iso:20022:tech:xsd:pacs.008.001.08">"#,
            r#"<Document xmlns=urn:iso:std:iso:20022:tech:xsd:pacs.008.001.08>"#,
        )
        => "unquoted Document namespace attributes must fail parsing";
    live_rail_profile_xsd_fixtures_reject_doctype_declaration:
        format!(
            "{}{}",
            r#"<!DOCTYPE Document [<!ENTITY x "boom">]>"#,
            live_fedwire_pacs008_xml(
                "FEDWIRE-DOCTYPE",
                "123e4567-e89b-12d3-a456-426614174309",
            ),
        )
        => "DOCTYPE declarations must fail parsing";
    live_rail_profile_xsd_fixtures_reject_malformed_document_qname:
        live_fedwire_pacs008_xml(
            "FEDWIRE-MALFORMED-QNAME",
            "123e4567-e89b-12d3-a456-426614174310",
        )
        .replace(
            r#"<Document xmlns="urn:iso:std:iso:20022:tech:xsd:pacs.008.001.08">"#,
            r#"<pacs::Document xmlns:pacs="urn:iso:std:iso:20022:tech:xsd:pacs.008.001.08">"#,
        )
        .replace("</Document>", "</pacs::Document>")
        => "malformed Document QNames must fail parsing";
    live_rail_profile_xsd_fixtures_reject_unknown_xml_entity_reference:
        live_fedwire_pacs008_xml(
            "FEDWIRE-&xxe;-ENTITY",
            "123e4567-e89b-12d3-a456-426614174311",
        )
        => "unknown XML entity references must fail parsing";
    live_rail_profile_xsd_fixtures_reject_unterminated_xml_entity_reference:
        live_fedwire_pacs008_xml(
            "FEDWIRE-UNTERMINATED-ENTITY",
            "123e4567-e89b-12d3-a456-426614174312",
        )
        .replace(r#"Ccy="USD""#, r#"Ccy="US&amp""#)
        => "unterminated XML entity references must fail parsing";
    live_rail_profile_xsd_fixtures_reject_invalid_numeric_xml_character_reference:
        live_fedwire_pacs008_xml(
            "FEDWIRE-BAD-NUMERIC-ENTITY",
            "123e4567-e89b-12d3-a456-426614174313",
        )
        .replace(r#"Ccy="USD""#, r#"Ccy="US&#x0;""#)
        => "invalid XML numeric character references must fail parsing";
}
#[test]
fn live_rail_profile_xsd_fixtures_accept_prefixed_document_namespace() {
    let (runtime, _reference_files) = runtime_with_live_reference_data();
    let profile = runtime
        .resolve_profile(Some("fedwire-funds"))
        .expect("fedwire profile");
    let payload = live_pacs008_xml(
        "FEDWIRE-PREFIXED-DOCUMENT-NS",
        "pacs.008.001.08",
        "fedwire.funds.01",
        "USD",
        "10.00",
        "123e4567-e89b-12d3-a456-426614174306",
    )
    .replace(
        r#"<Document xmlns="urn:iso:std:iso:20022:tech:xsd:pacs.008.001.08">"#,
        r#"<pacs:Document xmlns="urn:iso:std:iso:20022:tech:xsd:pacs.008.001.08" xmlns:pacs="urn:iso:std:iso:20022:tech:xsd:pacs.008.001.08">"#,
    )
    .replace("<FIToFICstmrCdtTrf>", "<pacs:FIToFICstmrCdtTrf>")
    .replace("</FIToFICstmrCdtTrf>", "</pacs:FIToFICstmrCdtTrf>")
    .replace("</Document>", "</pacs:Document>");
    let parsed = parse_message("pacs.008", payload.as_bytes())
        .expect("prefixed ISO Document namespace should parse");
    runtime
        .validate_profile_submission(profile, "pacs.008", &parsed, payload.as_bytes())
        .expect("prefixed ISO Document namespace should pass live profile validation");
}
#[test]
fn live_rail_profile_rejects_malformed_uetr_values() {
    let (runtime, _reference_files) = runtime_with_live_reference_data();
    let profile = runtime
        .resolve_profile(Some("swift-cbpr-plus"))
        .expect("swift profile");
    let cases = [
        "123e4567e89b12d3a456426614174000",
        "123e4567-e89b-12d3-a456-42661417400",
        "123e4567-e89b-12d3-a456-4266141740000",
        "123e4567_e89b_12d3_a456_426614174000",
        "123e4567-e89b-12d3-a456-42661417400g",
    ];
    for (idx, bad_uetr) in cases.into_iter().enumerate() {
        let payload = live_pacs008_xml(
            &format!("SWIFT-BAD-UETR-{idx}"),
            "pacs.008.001.08",
            "swift.cbprplus.02",
            "USD",
            "10.00",
            bad_uetr,
        );
        let parsed = parse_message("pacs.008", payload.as_bytes())
            .unwrap_or_else(|err| panic!("bad UETR fixture {idx} parses: {err:?}"));
        let err = runtime
            .validate_profile_submission(profile, "pacs.008", &parsed, payload.as_bytes())
            .unwrap_err();
        assert!(matches!(
            err,
            MsgError::InvalidValue {
                field,
                kind: InvalidValueKind::Enum
            } if field == "UETR"
        ));
    }
}
#[test]
fn live_rail_profile_rejects_missing_required_uetr() {
    let (runtime, _reference_files) = runtime_with_live_reference_data();
    let profile = runtime
        .resolve_profile(Some("swift-cbpr-plus"))
        .expect("swift profile");
    let payload = live_pacs008_xml(
        "SWIFT-MISSING-UETR",
        "pacs.008.001.08",
        "swift.cbprplus.02",
        "USD",
        "10.00",
        "123e4567-e89b-12d3-a456-426614174510",
    )
    .replace(
        "<PmtId><UETR>123e4567-e89b-12d3-a456-426614174510</UETR></PmtId>",
        "<PmtId/>",
    );
    let parsed = parse_message("pacs.008", payload.as_bytes()).expect("missing-UETR XML parses");
    let err = runtime
        .validate_profile_submission(profile, "pacs.008", &parsed, payload.as_bytes())
        .expect_err("live pacs.008 profiles require UETR");
    assert!(matches!(err, MsgError::MissingField("UETR")));
}
#[test]
fn uetr_validator_rejects_malformed_and_padded_values() {
    assert!(is_valid_uetr("123e4567-e89b-12d3-a456-426614174000"));
    assert!(is_valid_uetr("123E4567-E89B-12D3-A456-426614174000"));
    for bad_uetr in [
        "123e4567e89b12d3a456426614174000",
        "123e4567-e89b-12d3-a456-42661417400",
        "123e4567-e89b-12d3-a456-4266141740000",
        "123e4567_e89b_12d3_a456_426614174000",
        "123e4567-e89b-12d3-a456-42661417400g",
        " 123e4567-e89b-12d3-a456-426614174000",
        "123e4567-e89b-12d3-a456-426614174000 ",
    ] {
        assert!(!is_valid_uetr(bad_uetr), "{bad_uetr} must be invalid");
    }
}
#[test]
fn unstructured_postal_address_detector_matches_exact_indexed_and_xml_paths() {
    for field in [
        "AdrLine",
        "AdrLine[0]",
        "PstlAdr/AdrLine",
        "Document/FIToFICstmrCdtTrf/CdtTrfTxInf/Dbtr/PstlAdr/AdrLine",
        "Document/FIToFICstmrCdtTrf/CdtTrfTxInf/Dbtr/PstlAdr/AdrLine[0]",
    ] {
        assert!(
            is_unstructured_postal_address_field(field),
            "expected {field} to be treated as an unstructured address"
        );
    }
    for field in [
        "PstlAdr/Ctry",
        "Document/FIToFICstmrCdtTrf/CdtTrfTxInf/Dbtr/PstlAdr/Ctry",
        "NotAdrLine",
    ] {
        assert!(
            !is_unstructured_postal_address_field(field),
            "expected {field} to remain allowed"
        );
    }
}
#[test]
fn live_profile_idempotency_rejects_validated_business_message_id_and_uetr_replays() {
    let (runtime, _reference_files) = runtime_with_live_reference_data();
    let profile = runtime
        .resolve_profile(Some("swift-cbpr-plus"))
        .expect("swift profile");
    let first_payload = live_pacs008_xml(
        "SWIFT-REPLAY-1",
        "pacs.008.001.08",
        "swift.cbprplus.02",
        "USD",
        "10.00",
        "123e4567-e89b-12d3-a456-426614174500",
    );
    let first =
        parse_message("pacs.008", first_payload.as_bytes()).expect("first replay fixture parses");
    let first_metadata = runtime
        .validate_profile_submission(profile, "pacs.008", &first, first_payload.as_bytes())
        .expect("first live-profile message validates");
    assert!(runtime.check_and_record_inbound("rail-msg-1", first_metadata));
    let uetr_replay_payload = live_pacs008_xml(
        "SWIFT-REPLAY-2",
        "pacs.008.001.08",
        "swift.cbprplus.02",
        "USD",
        "10.00",
        "123E4567-E89B-12D3-A456-426614174500",
    );
    let uetr_replay = parse_message("pacs.008", uetr_replay_payload.as_bytes())
        .expect("UETR replay fixture parses");
    let uetr_replay_metadata = runtime
        .validate_profile_submission(
            profile,
            "pacs.008",
            &uetr_replay,
            uetr_replay_payload.as_bytes(),
        )
        .expect("case-drifted UETR replay still validates before idempotency");
    assert!(!runtime.check_and_record_inbound("rail-msg-2", uetr_replay_metadata));
    let biz_replay_payload = live_pacs008_xml(
        "SWIFT-REPLAY-1",
        "pacs.008.001.08",
        "swift.cbprplus.02",
        "USD",
        "10.00",
        "123e4567-e89b-12d3-a456-426614174501",
    );
    let biz_replay = parse_message("pacs.008", biz_replay_payload.as_bytes())
        .expect("BizMsgIdr replay fixture parses");
    let biz_replay_metadata = runtime
        .validate_profile_submission(
            profile,
            "pacs.008",
            &biz_replay,
            biz_replay_payload.as_bytes(),
        )
        .expect("business-message replay still validates before idempotency");
    assert!(!runtime.check_and_record_inbound("rail-msg-3", biz_replay_metadata));
    assert_eq!(
        runtime
            .uetr_index
            .get(&normalise_uetr("123e4567-e89b-12d3-a456-426614174500"))
            .map(|entry| entry.clone()),
        Some("rail-msg-1".to_owned())
    );
    assert_eq!(
        runtime
            .business_message_id_index
            .get("SWIFT-REPLAY-1")
            .map(|entry| entry.value().clone()),
        Some("rail-msg-1".to_owned())
    );
}
#[test]
fn live_profile_rejects_mismatched_message_version() {
    let snapshot = test_fixture_text(include_str!(
        r"../../../fixtures/iso20022/compact_bic_lei_test_reference.json"
    ));
    let file = write_snapshot(snapshot);
    let mut config = sample_config();
    config.reference_data.bic_lei_path = Some(file.path().to_path_buf());
    let runtime = Iso20022BridgeRuntime::from_config(&config)
        .expect("cfg")
        .expect("enabled");
    let profile = runtime
        .resolve_profile(Some("swift-cbpr-plus"))
        .expect("swift profile");
    let payload = swift_pacs008_xml("HDR-BAD-VERSION", "123e4567-e89b-12d3-a456-426614174000")
        .replace("pacs.008.001.08", "pacs.008.999.99");
    let parsed = parse_message("pacs.008", payload.as_bytes()).expect("parse bad version XML");
    let err = runtime
        .validate_profile_submission(profile, "pacs.008", &parsed, payload.as_bytes())
        .expect_err("unsupported live profile version must fail");
    assert!(matches!(err, MsgError::UnknownMessageType));
}
#[test]
fn live_profile_rejects_mismatched_business_service() {
    let snapshot = test_fixture_text(include_str!(
        r"../../../fixtures/iso20022/compact_bic_lei_test_reference.json"
    ));
    let file = write_snapshot(snapshot);
    let mut config = sample_config();
    config.reference_data.bic_lei_path = Some(file.path().to_path_buf());
    let runtime = Iso20022BridgeRuntime::from_config(&config)
        .expect("cfg")
        .expect("enabled");
    let profile = runtime
        .resolve_profile(Some("swift-cbpr-plus"))
        .expect("swift profile");
    let payload = swift_pacs008_xml("HDR-BAD-SERVICE", "123e4567-e89b-12d3-a456-426614174000")
        .replace("swift.cbprplus.02", "fedwire.funds.01");
    let parsed = parse_message("pacs.008", payload.as_bytes()).expect("parse bad service XML");
    let err = runtime
        .validate_profile_submission(profile, "pacs.008", &parsed, payload.as_bytes())
        .expect_err("unsupported business service must fail");
    assert!(matches!(
        err,
        MsgError::InvalidValue {
            field,
            kind: InvalidValueKind::Enum
        } if field == "AppHdr/BizSvc"
    ));
}
#[test]
fn profile_validation_rejects_amount_minor_unit_mismatch() {
    let runtime = sample_runtime();
    let parsed = parse_message(
            "pacs.008",
            b"MsgId=m-minor\nIntrBkSttlmAmt=10.001\nIntrBkSttlmCcy=USD\nIntrBkSttlmDt=2024-01-01\nDbtrAcct=GB82WEST12345698765432\nCdtrAcct=GB82WEST12345698765432\nDbtrAgt=DEUTDEFF\nCdtrAgt=DEUTDEFF",
        )
        .expect("parsed");
    let err = runtime
        .validate_profile_submission(runtime.default_profile(), "pacs.008", &parsed, b"minor")
        .expect_err("USD has two minor units");
    assert!(matches!(
        err,
        MsgError::InvalidValue {
            field,
            kind: InvalidValueKind::Amount
        } if field == "IntrBkSttlmAmt"
    ));
}
#[test]
fn profile_idempotency_rejects_replayed_uetr() {
    let runtime = sample_runtime();
    let first = IsoMessageMetadata::inbound(
        "generic-iso20022",
        "pacs.008",
        None,
        Some("biz-1".to_owned()),
        Some("123e4567-e89b-12d3-a456-426614174000".to_owned()),
        "hash-1".to_owned(),
        "snapshot".to_owned(),
        false,
    );
    let replay = IsoMessageMetadata::inbound(
        "generic-iso20022",
        "pacs.008",
        None,
        Some("biz-2".to_owned()),
        Some("123E4567-E89B-12D3-A456-426614174000".to_owned()),
        "hash-2".to_owned(),
        "snapshot".to_owned(),
        false,
    );
    assert!(runtime.check_and_record_inbound("msg-1", first));
    assert!(!runtime.check_and_record_inbound("msg-2", replay));
}
#[test]
fn profile_idempotency_rejects_replayed_business_message_id() {
    let runtime = sample_runtime();
    let first = IsoMessageMetadata::inbound(
        "generic-iso20022",
        "pacs.008",
        None,
        Some(" biz-duplicate ".to_owned()),
        Some("123e4567-e89b-12d3-a456-426614174000".to_owned()),
        "hash-1".to_owned(),
        "snapshot".to_owned(),
        false,
    );
    let replay = IsoMessageMetadata::inbound(
        "generic-iso20022",
        "pacs.008",
        None,
        Some("biz-duplicate".to_owned()),
        Some("123e4567-e89b-12d3-a456-426614174001".to_owned()),
        "hash-2".to_owned(),
        "snapshot".to_owned(),
        false,
    );
    assert!(runtime.check_and_record_inbound("msg-1", first));
    assert!(!runtime.check_and_record_inbound("msg-2", replay));
    assert_eq!(
        runtime
            .business_message_id_index
            .get("biz-duplicate")
            .map(|entry| entry.value().clone()),
        Some("msg-1".to_owned())
    );
}
#[test]
fn concurrent_admission_commits_one_complete_identity_tuple() {
    use std::sync::Barrier;

    let runtime = Arc::new(sample_runtime());
    let barrier = Arc::new(Barrier::new(3));
    let mut workers = Vec::new();
    for suffix in ["a", "b"] {
        let runtime = Arc::clone(&runtime);
        let barrier = Arc::clone(&barrier);
        workers.push(std::thread::spawn(move || {
            let metadata = IsoMessageMetadata::inbound(
                "generic-iso20022",
                "pacs.008",
                None,
                Some("biz-race".to_owned()),
                Some("123e4567-e89b-12d3-a456-426614174500".to_owned()),
                "payload-race".to_owned(),
                "snapshot".to_owned(),
                false,
            );
            barrier.wait();
            runtime.check_and_record_inbound(&format!("race-message-{suffix}"), metadata)
        }));
    }
    barrier.wait();
    let accepted = workers
        .into_iter()
        .map(|worker| worker.join().expect("admission worker"))
        .filter(|accepted| *accepted)
        .count();
    assert_eq!(accepted, 1);
    assert_eq!(runtime.records.len(), 1);
    assert_eq!(runtime.payload_hash_index.len(), 1);
    assert_eq!(runtime.business_message_id_index.len(), 1);
    assert_eq!(runtime.uetr_index.len(), 1);
}
#[test]
fn pacs009_group_message_id_owns_payment_replay_reservation() {
    let parse = |business_message_id: &str| {
        parse_message(
            "pacs.009",
            format!(
                "MsgId=pacs009-stable-group\nBizMsgIdr={business_message_id}\nMsgDefIdr=pacs.009.001.10\nCreDtTm=2024-01-01T12:00:00Z\nIntrBkSttlmAmt=2500\nIntrBkSttlmCcy=USD\nIntrBkSttlmDt=2024-01-03\nDbtrAcct=GB82WEST12345698765432\nCdtrAcct=GB33BUKB20201555555555\nInstgAgt=DEUTDEFF\nInstdAgt=MARKDEFF\nPurp=SECU"
            )
            .as_bytes(),
        )
        .expect("valid pacs.009 payment")
    };
    let first = parse("pacs009-header-a");
    let replay = parse("pacs009-header-b");
    let first_id =
        Iso20022BridgeRuntime::payment_message_id("pacs.009", &first).expect("group message id");
    let replay_id =
        Iso20022BridgeRuntime::payment_message_id("pacs.009", &replay).expect("group message id");
    assert_eq!(first_id, "pacs009-stable-group");
    assert_eq!(replay_id, first_id);

    let runtime = sample_runtime();
    let first_metadata = IsoMessageMetadata::inbound(
        "generic-iso20022",
        "pacs.009",
        None,
        Some("pacs009-header-a".to_owned()),
        None,
        "pacs009-payload-a".to_owned(),
        "snapshot".to_owned(),
        false,
    );
    let replay_metadata = IsoMessageMetadata::inbound(
        "generic-iso20022",
        "pacs.009",
        None,
        Some("pacs009-header-b".to_owned()),
        None,
        "pacs009-payload-b".to_owned(),
        "snapshot".to_owned(),
        false,
    );
    assert!(runtime.check_and_record_inbound(&first_id, first_metadata));
    assert!(!runtime.check_and_record_inbound(&replay_id, replay_metadata));

    let missing_group_id = parse_message(
        "pacs.009",
        b"BizMsgIdr=pacs009-header-only\nMsgDefIdr=pacs.009.001.10\nCreDtTm=2024-01-01T12:00:00Z\nIntrBkSttlmAmt=2500\nIntrBkSttlmCcy=USD\nIntrBkSttlmDt=2024-01-03\nDbtrAcct=GB82WEST12345698765432\nCdtrAcct=GB33BUKB20201555555555\nInstgAgt=DEUTDEFF\nInstdAgt=MARKDEFF\nPurp=SECU",
    )
    .expect("schema-compatible pacs.009 without group id");
    assert!(matches!(
        Iso20022BridgeRuntime::payment_message_id("pacs.009", &missing_group_id),
        Err(MsgError::MissingField("MsgId"))
    ));
}
#[test]
fn durable_in_flight_reservation_pins_capacity_until_transaction_binding() {
    let store = TempDir::new().expect("tempdir");
    let mut config = sample_config();
    config.store_dir = Some(store.path().to_path_buf());
    config.store_max_records = 1;
    let runtime = Iso20022BridgeRuntime::from_config(&config)
        .expect("cfg")
        .expect("enabled");
    let metadata = IsoMessageMetadata::inbound(
        "generic-iso20022",
        "pacs.008",
        None,
        Some("in-flight-biz".to_owned()),
        Some("123e4567-e89b-12d3-a456-426614174550".to_owned()),
        "in-flight-payload".to_owned(),
        "snapshot".to_owned(),
        false,
    );
    assert!(runtime.check_and_record_inbound("in-flight", metadata));
    assert!(
        !runtime.check_and_record_inbound("capacity-racer", inbound_metadata("racer", "pacs.008")),
        "an unresolved reservation must not be evicted to admit another payment"
    );
    assert!(runtime.update_message_context("in-flight", IsoMessageContext::default()));
    assert!(runtime.bind_transaction_hash("in-flight", "tx-in-flight"));
    assert_eq!(
        runtime
            .message_status("in-flight")
            .expect("reservation survives")
            .transaction_hash(),
        Some("tx-in-flight")
    );
    assert!(!runtime.update_message_context("missing", IsoMessageContext::default()));
}
#[test]
fn rejected_original_identity_blocks_both_exact_and_changed_retries() {
    let runtime = sample_runtime();
    let original = IsoMessageMetadata::inbound(
        "generic-iso20022",
        "pacs.008",
        None,
        Some("biz-exact-retry".to_owned()),
        None,
        "payload-original".to_owned(),
        "snapshot".to_owned(),
        false,
    );
    assert!(runtime.check_and_record_inbound("exact-retry", original.clone()));
    assert!(runtime.mark_rejected(
        "exact-retry",
        Some("definite pre-admission rejection".to_owned()),
        Some("ED05")
    ));
    let mut changed = original.clone();
    changed.payload_hash = Some("payload-replacement".to_owned());
    assert!(!runtime.check_and_record_inbound("exact-retry", changed));
    assert!(!runtime.check_and_record_inbound("exact-retry", original));
}
#[test]
fn queued_lifecycle_rejection_keeps_transaction_identity_and_blocks_retry() {
    let runtime = sample_runtime();
    let original_id = "queued-lifecycle-rejection";
    let lifecycle_id = "queued-lifecycle-rejection-status";
    let original = inbound_metadata(original_id, "pacs.008");
    assert!(runtime.check_and_record_inbound(original_id, original.clone()));
    runtime.mark_accepted(original_id, "tx-queued-lifecycle-rejection");
    record_lifecycle(&runtime, lifecycle_id, "pacs.002");
    assert_eq!(
        runtime
            .apply_lifecycle_update(
                lifecycle_id,
                original_id,
                "pacs.002",
                Some("RJCT"),
                Some("AC04"),
                Some("downstream rejection".to_owned()),
            )
            .expect("lifecycle rejection applies"),
        "marked_rejected"
    );
    let status = runtime.message_status(original_id).expect("status");
    assert_eq!(status.status_label(), "Rejected");
    assert_eq!(
        status.transaction_hash(),
        Some("tx-queued-lifecycle-rejection")
    );
    assert_eq!(
        runtime
            .tx_hash_index
            .get("tx-queued-lifecycle-rejection")
            .as_deref()
            .map(String::as_str),
        Some(original_id)
    );
    assert!(
        !runtime.check_and_record_inbound(original_id, original),
        "an already-queued transaction must not become retryable from lifecycle status alone"
    );
    assert!(runtime.mark_transaction_applied("tx-queued-lifecycle-rejection", SystemTime::now()));
    let settled = runtime.message_status(original_id).expect("settled status");
    assert_eq!(settled.status_label(), "Accepted");
    assert_eq!(settled.pacs002_code(), "ACSC");
}
#[test]
fn candidate_execution_events_do_not_terminalize_queued_iso_payment() {
    let runtime = sample_runtime();
    let message_id = "candidate-execution-is-not-final";
    let hash_text = "11".repeat(32);
    let hash = crate::parse_signed_transaction_hash(&hash_text).expect("canonical hash");
    assert!(runtime.check_and_record_inbound(message_id, inbound_metadata(message_id, "pacs.008")));
    runtime.mark_accepted(message_id, &hash_text);

    let approved = iroha_data_model::events::pipeline::TransactionEvent {
        hash,
        block_height: std::num::NonZeroU64::new(7),
        lane_id: LaneId::new(1),
        dataspace_id: DataSpaceId::new(1),
        status: iroha_data_model::events::pipeline::TransactionStatus::Approved,
    };
    crate::process_iso_bridge_transaction_event(&runtime, &approved)
        .expect("candidate approval is only a hint");
    assert!(runtime.has_queued_transaction_hash(&hash_text));

    let rejected = iroha_data_model::events::pipeline::TransactionEvent {
        status: iroha_data_model::events::pipeline::TransactionStatus::Rejected(Box::new(
            TransactionRejectionReason::Validation(ValidationFail::TooComplex),
        )),
        ..approved
    };
    crate::process_iso_bridge_transaction_event(&runtime, &rejected)
        .expect("candidate rejection is only a hint");
    assert!(runtime.has_queued_transaction_hash(&hash_text));
    let status = runtime.message_status(message_id).expect("status");
    assert_eq!(status.status_label(), "Accepted");
    assert!(status.settled_at().is_none());
}
#[test]
fn pacs004_return_update_preserves_original_before_and_after_settlement() {
    let runtime = sample_runtime();
    let original_id = "settled-payment-return";
    let lifecycle_id = "settled-payment-return-message";
    let hash = record_report_original(&runtime, original_id, false);
    record_lifecycle(&runtime, lifecycle_id, "pacs.004");
    for settled in [false, true] {
        if settled {
            assert!(runtime.mark_settled(original_id, SystemTime::now()));
        }
        let before =
            persisted_record_value(original_id, &runtime.records.get(original_id).unwrap());
        assert_eq!(
            runtime
                .apply_lifecycle_update(
                    lifecycle_id,
                    original_id,
                    "pacs.004",
                    None,
                    Some("AC04"),
                    None
                )
                .expect("separate return report"),
            "recorded_return"
        );
        assert_eq!(
            persisted_record_value(original_id, &runtime.records.get(original_id).unwrap()),
            before
        );
        assert_eq!(
            runtime
                .message_status(original_id)
                .unwrap()
                .transaction_hash(),
            Some(hash.as_str())
        );
    }
}
#[test]
fn retry_replacement_rejects_conflicting_uetr() {
    let runtime = sample_runtime();
    let first = IsoMessageMetadata::inbound(
        "generic-iso20022",
        "pacs.008",
        None,
        Some("biz-1".to_owned()),
        Some("123e4567-e89b-12d3-a456-426614174000".to_owned()),
        "hash-1".to_owned(),
        "snapshot".to_owned(),
        false,
    );
    let second = IsoMessageMetadata::inbound(
        "generic-iso20022",
        "pacs.008",
        None,
        Some("biz-2".to_owned()),
        Some("123e4567-e89b-12d3-a456-426614174001".to_owned()),
        "hash-2".to_owned(),
        "snapshot".to_owned(),
        false,
    );
    let conflicting_retry = IsoMessageMetadata::inbound(
        "generic-iso20022",
        "pacs.008",
        None,
        Some("biz-1-retry".to_owned()),
        Some("123E4567-E89B-12D3-A456-426614174001".to_owned()),
        "hash-3".to_owned(),
        "snapshot".to_owned(),
        false,
    );
    assert!(runtime.check_and_record_inbound("msg-1", first));
    assert!(runtime.check_and_record_inbound("msg-2", second));
    runtime.mark_rejected("msg-1", Some("retry allowed".to_owned()), Some("ED05"));
    assert!(!runtime.check_and_record_inbound("msg-1", conflicting_retry));
    assert_eq!(
        runtime
            .uetr_index
            .get(&normalise_uetr("123e4567-e89b-12d3-a456-426614174001"))
            .map(|entry| entry.clone()),
        Some("msg-2".to_owned())
    );
}
#[test]
fn retry_replacement_rejects_conflicting_business_message_id() {
    let runtime = sample_runtime();
    let first = IsoMessageMetadata::inbound(
        "generic-iso20022",
        "pacs.008",
        None,
        Some("biz-1".to_owned()),
        None,
        "hash-1".to_owned(),
        "snapshot".to_owned(),
        false,
    );
    let second = IsoMessageMetadata::inbound(
        "generic-iso20022",
        "pacs.008",
        None,
        Some("biz-2".to_owned()),
        None,
        "hash-2".to_owned(),
        "snapshot".to_owned(),
        false,
    );
    let conflicting_retry = IsoMessageMetadata::inbound(
        "generic-iso20022",
        "pacs.008",
        None,
        Some(" biz-2 ".to_owned()),
        None,
        "hash-3".to_owned(),
        "snapshot".to_owned(),
        false,
    );
    assert!(runtime.check_and_record_inbound("msg-1", first));
    assert!(runtime.check_and_record_inbound("msg-2", second));
    runtime.mark_rejected("msg-1", Some("retry allowed".to_owned()), Some("ED05"));
    assert!(!runtime.check_and_record_inbound("msg-1", conflicting_retry));
    assert_eq!(
        runtime
            .business_message_id_index
            .get(&normalise_business_message_id("biz-2").expect("non-empty business id"))
            .map(|entry| entry.clone()),
        Some("msg-2".to_owned())
    );
}
#[test]
fn durable_store_reloads_message_status() {
    let store = TempDir::new().expect("tempdir");
    let mut config = sample_config();
    config.store_dir = Some(store.path().to_path_buf());
    {
        let runtime = Iso20022BridgeRuntime::from_config(&config)
            .expect("cfg")
            .expect("enabled");
        let metadata = IsoMessageMetadata::inbound(
            "generic-iso20022",
            "pacs.008",
            None,
            Some("persisted-biz".to_owned()),
            None,
            "persisted-hash".to_owned(),
            "snapshot".to_owned(),
            false,
        );
        assert!(runtime.check_and_record_inbound("persisted-msg", metadata));
        runtime.update_message_context(
            "persisted-msg",
            IsoMessageContext {
                settlement_amount: Some("99.50".to_owned()),
                settlement_currency: Some("USD".to_owned()),
                ..IsoMessageContext::default()
            },
        );
        runtime.mark_accepted("persisted-msg", "tx-persisted");
    }
    let reloaded = Iso20022BridgeRuntime::from_config(&config)
        .expect("cfg")
        .expect("enabled");
    let status = reloaded
        .message_status("persisted-msg")
        .expect("reloaded status");
    assert_eq!(status.status_label(), "Accepted");
    assert_eq!(status.transaction_hash(), Some("tx-persisted"));
    assert_eq!(status.settlement_amount(), Some("99.50"));
    assert_eq!(status.settlement_currency(), Some("USD"));
    assert!(!status.status_history().is_empty());
    let persisted_path = store
        .path()
        .join("messages")
        .join(message_filename("persisted-msg"));
    let persisted = fs::read_to_string(persisted_path).expect("persisted JSON");
    let persisted_value =
        norito::json::from_json::<JsonValue>(&persisted).expect("persisted JSON parses");
    assert!(persisted_record_from_value(&persisted_value).is_some());
    assert!(
        persisted_value
            .as_object()
            .and_then(|obj| obj.get(ISO_PERSISTED_RECORD_DIGEST_FIELD))
            .and_then(JsonValue::as_str)
            .is_some_and(|digest| digest.len() == 64)
    );
    let replay = IsoMessageMetadata::inbound(
        "generic-iso20022",
        "pacs.008",
        None,
        Some("persisted-biz".to_owned()),
        None,
        "replay-hash".to_owned(),
        "snapshot".to_owned(),
        false,
    );
    assert!(!reloaded.check_and_record_inbound("persisted-replay", replay));
}
#[test]
fn configured_durable_store_must_be_available_at_startup() {
    let store = TempDir::new().expect("tempdir");
    let blocked_store = store.path().join("not-a-directory");
    fs::write(&blocked_store, b"file blocks durable store creation").expect("write blocker");
    let mut config = sample_config();
    config.store_dir = Some(blocked_store);
    let error = runtime_config_error(
        &config,
        "an unavailable configured durable store must stop startup",
    );
    assert!(
        error.to_string().contains("is not a real directory"),
        "unexpected hard-cut error: {error:?}"
    );
}
#[test]
fn status_transition_is_not_published_when_candidate_persistence_fails() {
    let store = TempDir::new().expect("tempdir");
    let mut config = sample_config();
    config.store_dir = Some(store.path().to_path_buf());
    let runtime = Iso20022BridgeRuntime::from_config(&config)
        .expect("cfg")
        .expect("enabled");
    assert!(runtime.check_and_record_message("atomic-status"));
    let messages_dir = store.path().join("messages");
    let backup_dir = store.path().join("messages-backup");
    fs::rename(&messages_dir, &backup_dir).expect("move valid message store aside");
    fs::write(&messages_dir, b"block candidate persistence").expect("write directory blocker");

    let returned = runtime.mark_accepted("atomic-status", "tx-must-not-publish");
    assert_eq!(returned.status_label(), "Pending");
    let retained = runtime
        .message_status("atomic-status")
        .expect("original pending record retained");
    assert_eq!(retained.status_label(), "Pending");
    assert_eq!(retained.transaction_hash(), None);
    assert!(!runtime.tx_hash_index.contains_key("tx-must-not-publish"));
    let lifecycle_error = runtime
        .try_transition_existing("atomic-status", |record| {
            record.detail = Some("must not publish".to_owned());
        })
        .expect_err("lifecycle candidate persistence must fail");
    assert_eq!(lifecycle_error, IsoStatusHistoryLimitError::Persistence);
    assert_eq!(
        runtime
            .message_status("atomic-status")
            .expect("original record still retained")
            .detail(),
        None
    );

    fs::remove_file(&messages_dir).expect("remove directory blocker");
    fs::rename(&backup_dir, &messages_dir).expect("restore valid message store");
    let persisted = fs::read_to_string(messages_dir.join(message_filename("atomic-status")))
        .expect("read original persisted record");
    let value = norito::json::from_json::<JsonValue>(&persisted).expect("parse persisted record");
    let (_, record) = persisted_record_from_value(&value).expect("valid persisted record");
    assert_eq!(record.state, IsoMessageState::Pending);
    assert_eq!(record.transaction_hash, None);
}
#[test]
fn lifecycle_apply_classifies_unavailable_journal_as_retryable() {
    let store = TempDir::new().expect("tempdir");
    let mut config = sample_config();
    config.store_dir = Some(store.path().to_path_buf());
    let runtime = Iso20022BridgeRuntime::from_config(&config)
        .expect("cfg")
        .expect("enabled");
    let original_id = "journal-unavailable-original";
    let lifecycle_id = "journal-unavailable-status";
    record_original(&runtime, original_id, "pacs.008");
    runtime.mark_accepted(original_id, "tx-journal-unavailable");
    record_lifecycle(&runtime, lifecycle_id, "pacs.002");
    let lifecycle = parse_message(
        "pacs.002",
        b"BizMsgIdr=journal-unavailable-status\nOrgnlMsgId=journal-unavailable-original\nTxSts=PDNG",
    )
    .expect("lifecycle message");
    let authorization = runtime
        .compatibility_lifecycle_authorization("pacs.002", &lifecycle)
        .expect("bind original record");
    let original_code = runtime
        .message_status(original_id)
        .expect("original status")
        .pacs002_code()
        .to_owned();

    let operations_dir = store.path().join(ISO_PERSISTED_LIFECYCLE_OPERATION_DIR);
    let backup_dir = store.path().join("lifecycle-operations-backup");
    fs::rename(&operations_dir, &backup_dir).expect("move lifecycle journal directory aside");
    fs::write(&operations_dir, b"block lifecycle journal persistence")
        .expect("write journal directory blocker");

    let error = runtime
        .apply_inbound_lifecycle_message_with_evidence(
            lifecycle_id,
            "pacs.002",
            &lifecycle,
            &authorization,
            None,
        )
        .expect_err("unavailable lifecycle journal must not become a validation rejection");
    assert!(matches!(
        error,
        IsoLifecycleApplyError::PersistenceUnavailable
    ));
    assert_eq!(
        runtime
            .message_status(original_id)
            .expect("original remains unchanged")
            .pacs002_code(),
        original_code
    );
    assert_eq!(
        runtime
            .message_status(lifecycle_id)
            .expect("admitted lifecycle record remains pending")
            .status_label(),
        "Pending"
    );
}
#[test]
fn committed_lifecycle_journal_recovers_both_records_after_materialization_outage() {
    let store = TempDir::new().expect("tempdir");
    let mut config = sample_config();
    config.store_dir = Some(store.path().to_path_buf());
    let runtime = Iso20022BridgeRuntime::from_config(&config)
        .expect("cfg")
        .expect("enabled");
    let original_id = "journal-outage-original";
    let lifecycle_id = "journal-outage-status";
    record_original(&runtime, original_id, "pacs.008");
    runtime.mark_accepted(original_id, "tx-journal-outage");
    record_lifecycle(&runtime, lifecycle_id, "pacs.002");
    let lifecycle = parse_message(
        "pacs.002",
        b"BizMsgIdr=journal-outage-status\nOrgnlMsgId=journal-outage-original\nTxSts=PDNG",
    )
    .expect("lifecycle message");

    let messages_dir = store.path().join("messages");
    let backup_dir = store.path().join("messages-backup");
    fs::rename(&messages_dir, &backup_dir).expect("move message store aside");
    fs::write(&messages_dir, b"block lifecycle materialization").expect("write blocker");
    let (outcome, lifecycle_status) = runtime
        .apply_inbound_lifecycle_message_with_status(lifecycle_id, "pacs.002", &lifecycle)
        .expect("the durable journal is the lifecycle commit point");
    assert_eq!(outcome.action(), "marked_pending");
    assert_eq!(lifecycle_status.status_label(), "Accepted");
    assert_eq!(
        runtime
            .message_status(original_id)
            .expect("journaled original after-image is visible")
            .pacs002_code(),
        "PDNG"
    );
    assert!(!runtime.lifecycle_persistence_is_healthy());
    assert!(lifecycle_journal_path(store.path()).is_file());
    assert!(
        !runtime.mark_rejected(
            lifecycle_id,
            Some("must not overwrite a committed journal".to_owned()),
            None,
        ),
        "ordinary transitions must freeze until journal recovery"
    );

    fs::remove_file(&messages_dir).expect("remove blocker");
    fs::rename(&backup_dir, &messages_dir).expect("restore message store");
    drop(runtime);

    let reloaded = Iso20022BridgeRuntime::from_config(&config)
        .expect("startup rolls the committed operation forward")
        .expect("enabled");
    assert!(reloaded.lifecycle_persistence_is_healthy());
    assert!(!lifecycle_journal_path(store.path()).exists());
    assert_eq!(
        reloaded
            .message_status(original_id)
            .expect("original recovered")
            .pacs002_code(),
        "PDNG"
    );
    assert_eq!(
        reloaded
            .message_status(lifecycle_id)
            .expect("lifecycle recovered")
            .status_label(),
        "Accepted"
    );
}
#[test]
fn lifecycle_journal_recovers_second_record_after_partial_roll_forward() {
    let store = TempDir::new().expect("tempdir");
    let mut config = sample_config();
    config.store_dir = Some(store.path().to_path_buf());
    let runtime = Iso20022BridgeRuntime::from_config(&config)
        .expect("cfg")
        .expect("enabled");
    let original_id = "journal-partial-original";
    let lifecycle_id = "journal-partial-status";
    record_original(&runtime, original_id, "pacs.008");
    runtime.mark_accepted(original_id, "tx-journal-partial");
    record_lifecycle(&runtime, lifecycle_id, "pacs.002");
    let (_, original) = runtime
        .prepare_lifecycle_update(
            lifecycle_id,
            original_id,
            "pacs.002",
            Some("PDNG"),
            None,
            None,
            None,
        )
        .expect("prepare original after-image");
    let original = original.expect("status transition mutates original");
    let lifecycle = runtime
        .prepare_lifecycle_record(
            lifecycle_id,
            None,
            Some("recorded test lifecycle".to_owned()),
        )
        .expect("prepare lifecycle after-image");
    let journal = IsoLifecycleJournal {
        original: Some(lifecycle_journal_mutation(&original)),
        lifecycle: lifecycle_journal_mutation(&lifecycle),
    };
    assert!(runtime.preflight_lifecycle_journal(&journal));
    assert!(runtime.persist_lifecycle_journal(&journal));
    runtime
        .materialize_lifecycle_journal_mutation(
            journal.original.as_ref().expect("original journal row"),
            true,
        )
        .expect("first record materializes before simulated crash");
    drop(runtime);

    let reloaded = Iso20022BridgeRuntime::from_config(&config)
        .expect("startup completes partial roll-forward")
        .expect("enabled");
    assert_eq!(
        reloaded
            .message_status(original_id)
            .expect("original recovered")
            .pacs002_code(),
        "PDNG"
    );
    assert_eq!(
        reloaded
            .message_status(lifecycle_id)
            .expect("lifecycle recovered")
            .status_label(),
        "Accepted"
    );
    assert!(!lifecycle_journal_path(store.path()).exists());
}
#[test]
fn context_update_preserves_previous_record_when_candidate_exceeds_byte_cap() {
    let store = TempDir::new().expect("tempdir");
    let mut config = sample_config();
    config.store_dir = Some(store.path().to_path_buf());
    let runtime = Iso20022BridgeRuntime::from_config(&config)
        .expect("cfg")
        .expect("enabled");
    assert!(runtime.check_and_record_message("oversized-candidate"));
    let path = store
        .path()
        .join("messages")
        .join(message_filename("oversized-candidate"));
    let before = fs::read(&path).expect("read original record");
    let oversized = "x".repeat(
        usize::try_from(ISO_PERSISTED_RECORD_MAX_BYTES).expect("record cap fits usize") + 1,
    );
    assert!(!runtime.update_message_context(
        "oversized-candidate",
        IsoMessageContext {
            settlement_amount: Some(oversized),
            ..IsoMessageContext::default()
        },
    ));
    assert_eq!(
        runtime
            .message_status("oversized-candidate")
            .expect("original record retained")
            .settlement_amount(),
        None
    );
    assert_eq!(fs::read(path).expect("read retained record"), before);
}
fn read_audit_index(store: &TempDir) -> JsonValue {
    let index_path = store
        .path()
        .join(ISO_PERSISTED_AUDIT_DIR)
        .join(ISO_PERSISTED_AUDIT_INDEX_FILE);
    let index = fs::read_to_string(index_path).expect("audit index JSON");
    norito::json::from_json::<JsonValue>(&index).expect("audit index parses")
}
fn rewrite_persisted_record(path: &Path, mutate: impl FnOnce(&mut norito::json::Map)) {
    let text = fs::read_to_string(path).expect("persisted JSON");
    let mut value = norito::json::from_json::<JsonValue>(&text).expect("persisted JSON parses");
    {
        let obj = value.as_object_mut().expect("persisted object");
        mutate(obj);
        obj.remove(ISO_PERSISTED_RECORD_DIGEST_FIELD);
        let digest = persisted_record_digest(&JsonValue::Object(obj.clone()));
        obj.insert(
            ISO_PERSISTED_RECORD_DIGEST_FIELD.to_owned(),
            JsonValue::from(digest.as_str()),
        );
        assert!(
            persisted_record_digest_matches(obj),
            "mutation must keep a valid persisted-record digest"
        );
    }
    fs::write(
        path,
        norito::json::to_string_pretty(&value).expect("serialize mutated JSON"),
    )
    .expect("write mutated JSON");
}
fn rewrite_persisted_audit_index(store: &TempDir, mutate: impl FnOnce(&mut norito::json::Map)) {
    let path = store
        .path()
        .join(ISO_PERSISTED_AUDIT_DIR)
        .join(ISO_PERSISTED_AUDIT_INDEX_FILE);
    let mut value = read_audit_index(store);
    {
        let object = value.as_object_mut().expect("audit index object");
        mutate(object);
        object.remove(ISO_PERSISTED_AUDIT_INDEX_DIGEST_FIELD);
        let digest = persisted_record_digest(&JsonValue::Object(object.clone()));
        object.insert(
            ISO_PERSISTED_AUDIT_INDEX_DIGEST_FIELD.to_owned(),
            JsonValue::from(digest.as_str()),
        );
        assert!(persisted_audit_index_digest_matches(object));
    }
    fs::write(
        path,
        norito::json::to_string_pretty(&value).expect("serialize mutated audit index"),
    )
    .expect("write mutated audit index");
}
fn rewrite_persisted_tombstone(
    store: &TempDir,
    message_id: &str,
    mutate: impl FnOnce(&mut norito::json::Map),
) {
    let path = store
        .path()
        .join(ISO_PERSISTED_REPLAY_TOMBSTONE_DIR)
        .join(message_filename(message_id));
    let text = fs::read_to_string(&path).expect("persisted tombstone");
    let mut value = norito::json::from_json::<JsonValue>(&text).expect("tombstone JSON");
    {
        let object = value.as_object_mut().expect("tombstone object");
        mutate(object);
        object.remove(ISO_PERSISTED_REPLAY_TOMBSTONE_DIGEST_FIELD);
        let digest = persisted_record_digest(&JsonValue::Object(object.clone()));
        object.insert(
            ISO_PERSISTED_REPLAY_TOMBSTONE_DIGEST_FIELD.to_owned(),
            JsonValue::from(digest.as_str()),
        );
    }
    fs::write(
        path,
        norito::json::to_string_pretty(&value).expect("serialize mutated tombstone"),
    )
    .expect("write mutated tombstone");
}
#[test]
fn persisted_record_reader_enforces_the_open_file_byte_limit() {
    assert!(persisted_json_fits_cap("1234", 4));
    assert!(!persisted_json_fits_cap("12345", 4));
    let cap = usize::try_from(ISO_PERSISTED_RECORD_MAX_BYTES).expect("record cap fits usize");
    let mut exact = NamedTempFile::new().expect("exact-size record");
    exact
        .write_all(&vec![b'a'; cap])
        .expect("write exact-size record");
    assert_eq!(
        read_persisted_record_bounded(exact.path())
            .expect("exact-size UTF-8 record")
            .len(),
        cap
    );
    let mut excessive = NamedTempFile::new().expect("oversized record");
    excessive
        .write_all(&vec![b'a'; cap + 1])
        .expect("write oversized record");
    assert!(read_persisted_record_bounded(excessive.path()).is_none());
}
#[test]
fn persisted_record_reader_rejects_a_replaced_path_identity() {
    let directory = TempDir::new().expect("tempdir");
    let path = directory.path().join("record.json");
    let displaced = directory.path().join("record.displaced.json");
    fs::write(&path, b"same-length").expect("write original record");
    let expected = secure_file_metadata::from_path(&path).expect("inspect original record");
    fs::rename(&path, &displaced).expect("displace original record");
    fs::write(&path, b"same-length").expect("write replacement record");

    assert!(
        read_persisted_json_bounded_with_metadata(
            &path,
            &expected,
            ISO_PERSISTED_RECORD_MAX_BYTES,
        )
        .is_none(),
        "a same-sized replacement must not satisfy the enumerated identity"
    );
}
#[test]
fn persisted_record_reader_rejects_hard_linked_input() {
    let directory = TempDir::new().expect("tempdir");
    let path = directory.path().join("record.json");
    let alias = directory.path().join("record-alias.json");
    fs::write(&path, b"{}").expect("write original record");
    fs::hard_link(&path, alias).expect("create hard link");

    assert!(
        read_persisted_record_bounded(&path).is_none(),
        "a multiply-linked persistence object must fail closed"
    );
}
#[test]
fn startup_scan_budget_bounds_entry_work_and_aggregate_bytes() {
    let mut entry_budget = IsoStartupScanBudget {
        entries: 0,
        bytes: 0,
        max_entries: 1,
        max_bytes: 16,
    };
    entry_budget
        .charge_entry(Path::new("first.json"), 1)
        .expect("first entry fits");
    let entry_error = entry_budget
        .charge_entry(Path::new("second.json"), 1)
        .expect_err("second entry exceeds work bound");
    assert!(entry_error.to_string().contains("startup work limit"));

    let mut byte_budget = IsoStartupScanBudget {
        entries: 0,
        bytes: 0,
        max_entries: 2,
        max_bytes: 3,
    };
    byte_budget
        .charge_entry(Path::new("first.json"), 2)
        .expect("first entry fits");
    let byte_error = byte_budget
        .charge_entry(Path::new("second.json"), 2)
        .expect_err("aggregate bytes exceed bound");
    assert!(
        byte_error
            .to_string()
            .contains("aggregate startup byte limit")
    );
}
#[test]
fn startup_removes_exact_bounded_writer_crash_temps() {
    for directory in ["messages", ISO_PERSISTED_REPLAY_TOMBSTONE_DIR] {
        let store = TempDir::new().expect("tempdir");
        let owned_dir = store.path().join(directory);
        fs::create_dir_all(&owned_dir).expect("create owned store directory");
        let target = message_filename("crashed-writer");
        let temp_path = owned_dir.join(iso_record_temp_filename(&target, 42, 7));
        fs::write(&temp_path, [0xff, 0xfe, 0xfd]).expect("write partial crash temp");
        let mut config = sample_config();
        config.store_dir = Some(store.path().to_path_buf());

        Iso20022BridgeRuntime::from_config(&config)
            .expect("an exact writer temp is recoverable")
            .expect("bridge remains enabled");

        assert!(
            !temp_path.exists(),
            "startup must durably remove a recognized crash temp in {directory}"
        );
    }
}
#[test]
fn startup_writer_temp_cleanup_is_budgeted_before_unlink() {
    for (max_entries, max_bytes, expected) in [
        (0, ISO_PERSISTED_RECORD_MAX_BYTES, "startup work limit"),
        (1, 0, "aggregate startup byte limit"),
    ] {
        let store = TempDir::new().expect("tempdir");
        let owned_dir = store.path().join("messages");
        fs::create_dir_all(&owned_dir).expect("create messages directory");
        let target = message_filename("budgeted-crash-temp");
        let temp_path = owned_dir.join(iso_record_temp_filename(&target, 42, 7));
        fs::write(&temp_path, b"x").expect("write crash temp");
        let entry = fs::read_dir(&owned_dir)
            .expect("enumerate crash temp")
            .next()
            .expect("crash temp entry")
            .expect("read crash temp entry");
        let mut directory_entries = 0;
        let mut budget = IsoStartupScanBudget {
            entries: 0,
            bytes: 0,
            max_entries,
            max_bytes,
        };

        let error =
            read_startup_record_entry(entry, &mut directory_entries, &mut budget, "message")
                .expect_err("a crash temp cannot bypass startup bounds");

        assert!(error.to_string().contains(expected), "{error:?}");
        assert_eq!(directory_entries, 1);
        assert_eq!(budget.entries, 1);
        assert!(
            temp_path.exists(),
            "startup must not unlink work it refused to account"
        );
    }
}
#[test]
fn durable_store_usage_enforces_runtime_count_and_byte_limits() {
    let mut usage = IsoDurableStoreUsage {
        message_bytes: std::collections::HashMap::new(),
        tombstone_bytes: std::collections::HashMap::new(),
        bytes: 0,
        max_directory_entries: 1,
        max_entries: 2,
        max_bytes: 10,
    };
    usage
        .record_existing(IsoDurableRecordKind::Message, "first", 6)
        .expect("first message fits");
    assert_eq!(
        usage.record_existing(IsoDurableRecordKind::Message, "second", 1),
        Err(IsoDurableStoreUsageError::DirectoryEntries)
    );
    assert_eq!(
        usage.record_existing(IsoDurableRecordKind::ReplayTombstone, "first", 5),
        Err(IsoDurableStoreUsageError::AggregateBytes)
    );
    assert_eq!(usage.bytes, 6, "rejected reservations do not mutate usage");
    usage
        .record_replacement(IsoDurableRecordKind::Message, "first", 4)
        .expect("smaller replacement releases bytes");
    usage
        .record_existing(IsoDurableRecordKind::ReplayTombstone, "first", 5)
        .expect("tombstone fits after replacement");
    assert_eq!(usage.bytes, 9);
    usage
        .remove(IsoDurableRecordKind::Message, "first")
        .expect("removal updates usage");
    assert_eq!(usage.bytes, 5);
}
#[test]
fn runtime_refuses_writes_beyond_the_restart_byte_budget() {
    let store = TempDir::new().expect("tempdir");
    let mut config = sample_config();
    config.store_dir = Some(store.path().to_path_buf());
    let runtime = Iso20022BridgeRuntime::from_config(&config)
        .expect("cfg")
        .expect("enabled");
    runtime.durable_store_usage.lock().max_bytes = 1;

    assert!(!runtime.check_and_record_message("runtime-byte-budget"));
    assert!(!runtime.records.contains_key("runtime-byte-budget"));
    assert!(
        !runtime
            .replay_tombstones
            .contains_key("runtime-byte-budget")
    );
    let usage = runtime.durable_store_usage.lock();
    assert_eq!(usage.bytes, 0);
    assert!(usage.message_bytes.is_empty());
    assert!(usage.tombstone_bytes.is_empty());
}
#[test]
fn startup_rejects_unexpected_entries_in_owned_record_directories() {
    for directory in ["messages", ISO_PERSISTED_REPLAY_TOMBSTONE_DIR] {
        let target = message_filename("writer-temp-lookalike");
        for unexpected_name in [
            "unexpected.tmp".to_owned(),
            format!(".{target}.01.0.tmp"),
            format!(".{target}.1.00.tmp"),
            format!(".{target}.1.0.tmp.extra"),
        ] {
            let store = TempDir::new().expect("tempdir");
            let owned_dir = store.path().join(directory);
            fs::create_dir_all(&owned_dir).expect("create owned store directory");
            fs::write(
                owned_dir.join(&unexpected_name),
                b"ignored work is forbidden",
            )
            .expect("write unexpected entry");
            let mut config = sample_config();
            config.store_dir = Some(store.path().to_path_buf());
            let error = runtime_config_error(&config, "unexpected entries must stop startup");
            assert!(
                error.to_string().contains("contains unexpected entry"),
                "unexpected hard-cut error for {directory}/{unexpected_name}: {error:?}"
            );
        }
    }
}
#[cfg(unix)]
#[test]
fn startup_rejects_symlinked_writer_temps_without_touching_the_target() {
    for directory in ["messages", ISO_PERSISTED_REPLAY_TOMBSTONE_DIR] {
        let store = TempDir::new().expect("tempdir");
        let owned_dir = store.path().join(directory);
        fs::create_dir_all(&owned_dir).expect("create owned store directory");
        let target_path = store.path().join("outside-writer-temp-target");
        fs::write(&target_path, b"must survive").expect("write symlink target");
        let target = message_filename("symlinked-writer-temp");
        let temp_path = owned_dir.join(iso_record_temp_filename(&target, 42, 7));
        std::os::unix::fs::symlink(&target_path, &temp_path).expect("symlink writer temp");
        let mut config = sample_config();
        config.store_dir = Some(store.path().to_path_buf());

        let error = runtime_config_error(&config, "writer temp symlinks must stop startup");

        assert!(
            error.to_string().contains("not a direct regular file"),
            "unexpected hard-cut error for {directory}: {error:?}"
        );
        assert_eq!(
            fs::read(&target_path).expect("read retained symlink target"),
            b"must survive"
        );
    }
}
#[test]
fn durable_unlink_keeps_accounting_when_directory_sync_fails() {
    let store = TempDir::new().expect("tempdir");
    let mut config = sample_config();
    config.store_dir = Some(store.path().to_path_buf());
    let runtime = Iso20022BridgeRuntime::from_config(&config)
        .expect("cfg")
        .expect("enabled");
    let message_id = "directory-sync-failure";
    assert!(runtime.check_and_record_message(message_id));
    let messages_dir = store.path().join("messages");
    let path = messages_dir.join(message_filename(message_id));
    let before_bytes = runtime.durable_store_usage.lock().bytes;
    let sync_called = std::cell::Cell::new(false);

    assert!(!runtime.remove_durable_identity_file_with_directory_sync(
        IsoDurableRecordKind::Message,
        message_id,
        &path,
        |parent| {
            sync_called.set(true);
            assert_eq!(parent, messages_dir.as_path());
            Err(std::io::Error::other("injected directory sync failure"))
        },
    ));

    assert!(sync_called.get());
    assert!(!path.exists(), "unlink itself succeeded");
    assert!(
        runtime.records.contains_key(message_id),
        "the in-memory identity remains authoritative while durability is uncertain"
    );
    {
        let usage = runtime.durable_store_usage.lock();
        assert_eq!(usage.bytes, before_bytes);
        assert!(usage.message_bytes.contains_key(message_id));
    }
    let retry_sync_called = std::cell::Cell::new(false);
    assert!(runtime.remove_durable_identity_file_with_directory_sync(
        IsoDurableRecordKind::Message,
        message_id,
        &path,
        |parent| {
            retry_sync_called.set(true);
            assert_eq!(parent, messages_dir.as_path());
            Ok(())
        },
    ));
    assert!(
        retry_sync_called.get(),
        "an already absent name still requires a durable directory sync"
    );
    let usage = runtime.durable_store_usage.lock();
    assert!(!usage.message_bytes.contains_key(message_id));
    assert!(usage.bytes < before_bytes);
}
#[test]
fn durable_directory_initialization_resyncs_an_existing_name_after_failure() {
    let parent = TempDir::new().expect("tempdir");
    let directory = parent.path().join("iso-store");
    let durable_parent = fs::canonicalize(parent.path()).expect("canonical parent");
    let durable_directory = durable_parent.join("iso-store");
    let first_syncs = std::cell::RefCell::new(Vec::new());

    let error = prepare_real_directory_with_sync(&directory, |path| {
        first_syncs.borrow_mut().push(path.to_path_buf());
        if path == durable_parent.as_path() {
            return Err(std::io::Error::other(
                "injected parent-directory sync failure",
            ));
        }
        Ok(())
    })
    .expect_err("the first parent sync must fail");

    assert_eq!(
        error.kind(),
        std::io::ErrorKind::Other,
        "unexpected initialization failure: {error}"
    );
    assert!(is_real_directory(&directory));
    assert_eq!(
        first_syncs.into_inner(),
        vec![durable_directory.clone(), durable_parent.clone()]
    );

    let retry_syncs = std::cell::RefCell::new(Vec::new());
    prepare_real_directory_with_sync(&directory, |path| {
        retry_syncs.borrow_mut().push(path.to_path_buf());
        Ok(())
    })
    .expect("an existing directory must repeat both durability syncs");
    assert_eq!(
        retry_syncs.into_inner(),
        vec![durable_directory, durable_parent]
    );
}
#[test]
fn durable_directory_initialization_does_not_create_unowned_parent_trees() {
    let holder = TempDir::new().expect("tempdir");
    let missing_parent = holder.path().join("operator-owned-parent");
    let directory = missing_parent.join("iso-store");

    let error = prepare_real_directory_with_sync(&directory, |_| Ok(()))
        .expect_err("a missing operator-owned parent must fail closed");

    assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
    assert!(!missing_parent.exists());
}
#[test]
fn durable_directory_initialization_allows_unrelated_sibling_creation() {
    let parent = TempDir::new().expect("tempdir");
    let directory = parent.path().join("iso-store");
    let sibling = parent.path().join("other-service");
    let mut synchronized = 0;
    prepare_real_directory_with_sync(&directory, |_| {
        synchronized += 1;
        if synchronized == 1 {
            fs::create_dir(&sibling)?;
        }
        Ok(())
    })
    .expect("a sibling name does not replace the pinned parent or store");
    assert_eq!(synchronized, 2);
    assert!(is_real_directory(&directory));
    assert!(is_real_directory(&sibling));
}
#[test]
fn durable_directory_initialization_rejects_parent_replacement_during_sync() {
    let holder = TempDir::new().expect("tempdir");
    let parent = holder.path().join("parent");
    fs::create_dir(&parent).expect("original parent");
    let directory = parent.join("iso-store");
    let retired = holder.path().join("retained-original-parent");
    let mut synchronized = 0;
    let error = prepare_real_directory_with_sync(&directory, |_| {
        synchronized += 1;
        if synchronized == 1 {
            fs::rename(&parent, &retired)?;
            fs::create_dir(&parent)?;
            fs::create_dir(&directory)?;
        }
        Ok(())
    })
    .expect_err("replacing both names must not replace the original open identity");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    assert!(is_real_directory(&retired.join("iso-store")));
    assert!(is_real_directory(&directory));
}
#[test]
fn runtime_prepares_identity_directories_once_and_does_not_recreate_them() {
    let holder = TempDir::new().expect("tempdir");
    let store = holder.path().join("iso-store");
    let mut config = sample_config();
    config.store_dir = Some(store.clone());
    let runtime = Iso20022BridgeRuntime::from_config(&config)
        .expect("cfg")
        .expect("enabled");
    let messages = store.join("messages");
    let tombstones = store.join(ISO_PERSISTED_REPLAY_TOMBSTONE_DIR);
    let audit = store.join(ISO_PERSISTED_AUDIT_DIR);
    assert!(is_real_directory(&messages));
    assert!(is_real_directory(&tombstones));
    assert!(is_real_directory(&audit));

    fs::remove_dir(&tombstones).expect("remove empty tombstone directory");
    assert!(!runtime.check_and_record_message("missing-tombstone-directory"));
    assert!(
        !tombstones.exists(),
        "runtime persistence must fail closed instead of rebuilding directory topology"
    );
}
#[test]
fn runtime_rejects_unbounded_or_excessive_store_counts() {
    assert_eq!(
        ISO_PERSISTED_RECORD_MAX_COUNT_V1,
        iroha_config::parameters::defaults::torii::ISO_BRIDGE_STORE_MAX_RECORDS_HARD_LIMIT_V1
    );
    for (value, expected) in [
        (0, "must be greater than zero"),
        (
            ISO_PERSISTED_RECORD_MAX_COUNT_V1 + 1,
            "must not exceed the first-release hard maximum",
        ),
    ] {
        let mut config = sample_config();
        config.store_max_records = value;
        let error = runtime_config_error(&config, "invalid store count must fail closed");
        assert!(error.to_string().contains(expected), "{error}");
    }
}
#[test]
fn lowering_store_capacity_preserves_every_unexpired_replay_identity() {
    let store = TempDir::new().expect("tempdir");
    let mut config = sample_config();
    config.store_dir = Some(store.path().to_path_buf());
    config.store_retention_secs = 0;
    config.store_max_records = 4;
    {
        let runtime = Iso20022BridgeRuntime::from_config(&config)
            .expect("cfg")
            .expect("enabled");
        for message_id in ["old", "middle", "tie-a", "tie-z"] {
            assert!(runtime.check_and_record_inbound(
                message_id,
                IsoMessageMetadata::inbound(
                    "generic-iso20022",
                    "pacs.008",
                    None,
                    Some(format!("{message_id}-biz")),
                    None,
                    format!("{message_id}-hash"),
                    "snapshot".to_owned(),
                    false,
                ),
            ));
            runtime.mark_accepted(message_id, &format!("tx-{message_id}"));
            runtime.mark_settled(message_id, SystemTime::now());
        }
    }
    // A record rename can commit immediately before the derived audit index is
    // rewritten. Exercise that valid-but-stale crash window explicitly.
    for (message_id, updated_at_ms) in [
        ("old", 1_000_u64),
        ("middle", 2_000),
        ("tie-a", 3_000),
        ("tie-z", 3_000),
    ] {
        let path = store
            .path()
            .join("messages")
            .join(message_filename(message_id));
        rewrite_persisted_record(&path, |obj| {
            obj.insert("updated_at_ms".to_owned(), JsonValue::from(updated_at_ms));
        });
    }
    config.store_max_records = 2;
    let reloaded = Iso20022BridgeRuntime::from_config(&config)
        .expect("cfg")
        .expect("enabled");
    assert_eq!(reloaded.records.len(), 4);
    assert_eq!(reloaded.tx_hash_index.len(), 4);
    assert_eq!(reloaded.payload_hash_index.len(), 4);
    assert_eq!(reloaded.business_message_id_index.len(), 4);
    assert!(reloaded.message_status("old").is_some());
    assert!(reloaded.message_status("middle").is_some());
    assert!(reloaded.message_status("tie-a").is_some());
    assert!(reloaded.message_status("tie-z").is_some());
    for protected in ["old", "middle", "tie-a", "tie-z"] {
        assert!(
            store
                .path()
                .join("messages")
                .join(message_filename(protected))
                .exists()
        );
    }
    assert!(!reloaded.check_and_record_inbound(
        "capacity-rejected",
        IsoMessageMetadata::inbound(
            "generic-iso20022",
            "pacs.008",
            None,
            Some("capacity-rejected-biz".to_owned()),
            None,
            "capacity-rejected-hash".to_owned(),
            "snapshot".to_owned(),
            false,
        ),
    ));
}
fn assert_digest_correct_record_mutation_is_rejected(
    message_id: &str,
    mutate: impl FnOnce(&mut norito::json::Map),
) {
    let store = TempDir::new().expect("tempdir");
    let mut config = sample_config();
    config.store_dir = Some(store.path().to_path_buf());
    {
        let runtime = Iso20022BridgeRuntime::from_config(&config)
            .expect("cfg")
            .expect("enabled");
        assert!(runtime.check_and_record_inbound(
            message_id,
            IsoMessageMetadata::inbound(
                "generic-iso20022",
                "pacs.008",
                None,
                Some(format!("{message_id}-biz")),
                None,
                format!("{message_id}-hash"),
                "snapshot".to_owned(),
                false,
            ),
        ));
        runtime.mark_accepted(message_id, &format!("tx-{message_id}"));
    }
    let path = store
        .path()
        .join("messages")
        .join(message_filename(message_id));
    rewrite_persisted_record(&path, mutate);
    let error = runtime_config_error(
        &config,
        "digest-correct malformed ISO stores must stop startup",
    );
    assert!(
        error
            .to_string()
            .contains("regenerate the first-release ISO store"),
        "unexpected hard-cut error: {error:?}"
    );
}
fn assert_digest_correct_audit_mutation_is_rejected(
    case: &str,
    mutate: impl FnOnce(&mut norito::json::Map),
) {
    let store = TempDir::new().expect("tempdir");
    let mut config = sample_config();
    config.store_dir = Some(store.path().to_path_buf());
    {
        let runtime = Iso20022BridgeRuntime::from_config(&config)
            .expect("cfg")
            .expect("enabled");
        for message_id in ["audit-a", "audit-b"] {
            assert!(runtime.check_and_record_inbound(
                message_id,
                IsoMessageMetadata::inbound(
                    "generic-iso20022",
                    "pacs.008",
                    None,
                    Some(format!("{case}-{message_id}-biz")),
                    None,
                    format!("{case}-{message_id}-hash"),
                    "snapshot".to_owned(),
                    false,
                ),
            ));
        }
    }
    rewrite_persisted_audit_index(&store, mutate);
    let error = runtime_config_error(&config, "malformed ISO audit indexes must stop startup");
    assert!(
        error
            .to_string()
            .contains("is invalid or corrupt for schema V3"),
        "unexpected hard-cut error for {case}: {error:?}"
    );
}
fn read_external_audit_index(export: &TempDir) -> JsonValue {
    let index_path = export.path().join(ISO_PERSISTED_AUDIT_INDEX_FILE);
    let index = fs::read_to_string(index_path).expect("external audit index JSON");
    norito::json::from_json::<JsonValue>(&index).expect("external audit index parses")
}
fn read_latest_audit_anchor(export: &TempDir) -> JsonValue {
    let anchor_path = export.path().join(ISO_AUDIT_EXPORT_LATEST_ANCHOR_FILE);
    let anchor = fs::read_to_string(anchor_path).expect("external audit anchor JSON");
    norito::json::from_json::<JsonValue>(&anchor).expect("external audit anchor parses")
}
#[test]
fn durable_store_retention_is_independent_from_dedupe_ttl() {
    let store = TempDir::new().expect("tempdir");
    let mut config = sample_config();
    config.store_dir = Some(store.path().to_path_buf());
    config.dedupe_ttl_secs = 0;
    let runtime = Iso20022BridgeRuntime::from_config(&config)
        .expect("cfg")
        .expect("enabled");
    assert!(runtime.check_and_record_inbound(
        "ttl-kept-a",
        IsoMessageMetadata::inbound(
            "generic-iso20022",
            "pacs.008",
            None,
            Some("ttl-kept-a-biz".to_owned()),
            None,
            "ttl-kept-a-hash".to_owned(),
            "snapshot".to_owned(),
            false,
        ),
    ));
    runtime.mark_accepted("ttl-kept-a", "tx-ttl-kept-a");
    std::thread::sleep(Duration::from_millis(1));
    assert!(runtime.check_and_record_inbound(
        "ttl-kept-b",
        IsoMessageMetadata::inbound(
            "generic-iso20022",
            "pacs.008",
            None,
            Some("ttl-kept-b-biz".to_owned()),
            None,
            "ttl-kept-b-hash".to_owned(),
            "snapshot".to_owned(),
            false,
        ),
    ));
    assert!(runtime.message_status("ttl-kept-a").is_some());
    assert!(runtime.message_status("ttl-kept-b").is_some());
    let index_value = read_audit_index(&store);
    assert_eq!(
        index_value
            .as_object()
            .and_then(|obj| obj.get("record_count"))
            .and_then(JsonValue::as_u64),
        Some(2)
    );
}
#[test]
fn durable_store_never_evicts_an_unexpired_identity_for_capacity() {
    let store = TempDir::new().expect("tempdir");
    let mut config = sample_config();
    config.store_dir = Some(store.path().to_path_buf());
    config.store_max_records = 1;
    let runtime = Iso20022BridgeRuntime::from_config(&config)
        .expect("cfg")
        .expect("enabled");
    assert!(runtime.check_and_record_inbound(
        "compact-old",
        IsoMessageMetadata::inbound(
            "generic-iso20022",
            "pacs.008",
            None,
            Some("compact-old-biz".to_owned()),
            None,
            "compact-old-hash".to_owned(),
            "snapshot".to_owned(),
            false,
        ),
    ));
    runtime.mark_accepted("compact-old", "tx-compact-old");
    runtime.mark_settled("compact-old", SystemTime::now());
    std::thread::sleep(Duration::from_millis(1));
    assert!(!runtime.check_and_record_inbound(
        "compact-new",
        IsoMessageMetadata::inbound(
            "generic-iso20022",
            "pacs.008",
            None,
            Some("compact-new-biz".to_owned()),
            None,
            "compact-new-hash".to_owned(),
            "snapshot".to_owned(),
            false,
        ),
    ));
    assert!(runtime.message_status("compact-old").is_some());
    assert!(runtime.message_status("compact-new").is_none());
    assert!(
        runtime
            .business_message_id_index
            .get(&normalise_business_message_id("compact-old-biz").expect("business id"))
            .is_some()
    );
    assert!(
        store
            .path()
            .join("messages")
            .join(message_filename("compact-old"))
            .exists()
    );
    let index_value = read_audit_index(&store);
    let index_obj = index_value.as_object().expect("audit index object");
    assert!(persisted_audit_index_digest_matches(index_obj));
    assert_eq!(
        index_obj.get("record_count").and_then(JsonValue::as_u64),
        Some(1)
    );
    assert_eq!(
        index_obj
            .get("records")
            .and_then(JsonValue::as_array)
            .and_then(|entries| entries.first())
            .and_then(JsonValue::as_object)
            .and_then(|entry| entry.get("message_id"))
            .and_then(JsonValue::as_str),
        Some("compact-old")
    );
}
#[test]
fn durable_store_compacts_records_older_than_retention_window() {
    let store = TempDir::new().expect("tempdir");
    let mut config = sample_config();
    config.store_dir = Some(store.path().to_path_buf());
    config.store_retention_secs = 1;
    let runtime = Iso20022BridgeRuntime::from_config(&config)
        .expect("cfg")
        .expect("enabled");
    assert!(runtime.check_and_record_inbound(
        "age-expired",
        IsoMessageMetadata::inbound(
            "generic-iso20022",
            "pacs.008",
            None,
            Some("age-expired-biz".to_owned()),
            None,
            "age-expired-hash".to_owned(),
            "snapshot".to_owned(),
            false,
        ),
    ));
    runtime.mark_accepted("age-expired", "tx-age-expired");
    runtime.mark_settled("age-expired", SystemTime::now());
    {
        let mut record = runtime.records.get_mut("age-expired").expect("record");
        record.updated_at = SystemTime::UNIX_EPOCH;
    }
    runtime.persist_message("age-expired");
    assert!(runtime.message_status("age-expired").is_none());
    assert!(runtime.replay_tombstones.contains_key("age-expired"));
    assert!(
        runtime
            .business_message_id_index
            .contains_key(&normalise_business_message_id("age-expired-biz").expect("business id"))
    );
    assert!(
        !store
            .path()
            .join("messages")
            .join(message_filename("age-expired"))
            .exists()
    );
    let index_value = read_audit_index(&store);
    let index_obj = index_value.as_object().expect("audit index object");
    assert!(persisted_audit_index_digest_matches(index_obj));
    assert_eq!(
        index_obj.get("record_count").and_then(JsonValue::as_u64),
        Some(0)
    );
}
#[test]
fn durable_store_writes_tamper_evident_audit_index() {
    let store = TempDir::new().expect("tempdir");
    let mut config = sample_config();
    config.store_dir = Some(store.path().to_path_buf());
    let runtime = Iso20022BridgeRuntime::from_config(&config)
        .expect("cfg")
        .expect("enabled");
    for (message_id, business_id, payload_hash, tx_hash) in [
        ("audit-b", "audit-biz-b", "audit-hash-b", "tx-b"),
        ("audit-a", "audit-biz-a", "audit-hash-a", "tx-a"),
    ] {
        assert!(runtime.check_and_record_inbound(
            message_id,
            IsoMessageMetadata::inbound(
                "generic-iso20022",
                "pacs.008",
                None,
                Some(business_id.to_owned()),
                None,
                payload_hash.to_owned(),
                "snapshot".to_owned(),
                false,
            ),
        ));
        runtime.mark_accepted(message_id, tx_hash);
    }
    let index_value = read_audit_index(&store);
    let index_obj = index_value.as_object().expect("audit index object");
    assert_eq!(
        index_obj.get("version").and_then(JsonValue::as_u64),
        Some(ISO_PERSISTED_AUDIT_INDEX_VERSION)
    );
    assert_eq!(
        index_obj.get("record_count").and_then(JsonValue::as_u64),
        Some(2)
    );
    assert!(
        index_obj
            .get(ISO_PERSISTED_AUDIT_INDEX_DIGEST_FIELD)
            .and_then(JsonValue::as_str)
            .is_some_and(|digest| digest.len() == 64)
    );
    assert!(persisted_audit_index_digest_matches(index_obj));
    let entries = index_obj
        .get("records")
        .and_then(JsonValue::as_array)
        .expect("audit records");
    let message_ids = entries
        .iter()
        .map(|entry| {
            entry
                .as_object()
                .and_then(|obj| obj.get("message_id"))
                .and_then(JsonValue::as_str)
                .expect("message_id")
        })
        .collect::<Vec<_>>();
    assert_eq!(message_ids, vec!["audit-a", "audit-b"]);
    for entry in entries {
        let entry = entry.as_object().expect("audit entry object");
        let filename = entry
            .get("filename")
            .and_then(JsonValue::as_str)
            .expect("record filename");
        let entry_digest = entry
            .get(ISO_PERSISTED_RECORD_DIGEST_FIELD)
            .and_then(JsonValue::as_str)
            .expect("record digest");
        let record_path = store.path().join("messages").join(filename);
        let record = fs::read_to_string(record_path).expect("record JSON");
        let record_value =
            norito::json::from_json::<JsonValue>(&record).expect("record JSON parses");
        let record_obj = record_value.as_object().expect("record object");
        assert!(persisted_record_digest_matches(record_obj));
        assert_eq!(
            record_obj
                .get(ISO_PERSISTED_RECORD_DIGEST_FIELD)
                .and_then(JsonValue::as_str),
            Some(entry_digest)
        );
    }
    let mut tampered_index = index_value.clone();
    tampered_index
        .as_object_mut()
        .expect("audit index object")
        .insert("record_count".to_owned(), JsonValue::from(3_u64));
    assert!(!persisted_audit_index_digest_matches(
        tampered_index.as_object().expect("audit index object")
    ));
}
#[test]
fn durable_store_exports_external_audit_notary_spool() {
    let store = TempDir::new().expect("store tempdir");
    let export = TempDir::new().expect("export tempdir");
    let mut config = sample_config();
    config.store_dir = Some(store.path().to_path_buf());
    config.audit_export_dir = Some(export.path().to_path_buf());
    let runtime = Iso20022BridgeRuntime::from_config(&config)
        .expect("cfg")
        .expect("enabled");
    assert!(runtime.check_and_record_inbound(
        "external-audit-msg",
        IsoMessageMetadata::inbound(
            "generic-iso20022",
            "pacs.008",
            None,
            Some("external-audit-biz".to_owned()),
            None,
            "external-audit-hash".to_owned(),
            "snapshot".to_owned(),
            false,
        ),
    ));
    runtime.mark_accepted("external-audit-msg", "tx-external-audit");
    let local = read_audit_index(&store);
    let external = read_external_audit_index(&export);
    assert_eq!(external, local);
    let index_digest = audit_index_digest(&external).expect("index digest");
    let anchor = read_latest_audit_anchor(&export);
    let anchor_obj = anchor.as_object().expect("anchor object");
    assert!(audit_export_anchor_digest_matches(anchor_obj));
    assert_eq!(
        anchor_obj.get("index_sha256").and_then(JsonValue::as_str),
        Some(index_digest)
    );
    assert_eq!(
        anchor_obj.get("record_count").and_then(JsonValue::as_u64),
        Some(1)
    );
    assert_eq!(
        anchor_obj.get("audit_index").and_then(JsonValue::as_object),
        external.as_object()
    );
    assert!(
        export
            .path()
            .join(ISO_AUDIT_EXPORT_ANCHOR_DIR)
            .join(format!("{index_digest}.notary.json"))
            .exists(),
        "digest-addressed notary preimage missing"
    );
    let mut tampered = anchor.clone();
    tampered
        .as_object_mut()
        .expect("tampered anchor object")
        .insert("record_count".to_owned(), JsonValue::from(2_u64));
    assert!(!audit_export_anchor_digest_matches(
        tampered.as_object().expect("tampered anchor")
    ));
}
#[tokio::test]
async fn external_audit_write_failure_marks_runtime_unhealthy_and_retries() {
    let store = TempDir::new().expect("store tempdir");
    let export = TempDir::new().expect("export tempdir");
    let mut config = sample_config();
    config.store_dir = Some(store.path().to_path_buf());
    config.audit_export_dir = Some(export.path().to_path_buf());
    let runtime = Arc::new(
        Iso20022BridgeRuntime::from_config(&config)
            .expect("cfg")
            .expect("enabled"),
    );
    let latest_anchor = export.path().join(ISO_AUDIT_EXPORT_LATEST_ANCHOR_FILE);
    fs::remove_file(&latest_anchor).expect("remove initial latest anchor");
    fs::create_dir(&latest_anchor).expect("block latest anchor replacement");

    assert!(runtime.check_and_record_inbound(
        "external-audit-failure",
        IsoMessageMetadata::inbound(
            "generic-iso20022",
            "pacs.008",
            None,
            Some("external-audit-failure-biz".to_owned()),
            None,
            "external-audit-failure-hash".to_owned(),
            "snapshot".to_owned(),
            false,
        ),
    ));
    assert!(!runtime.audit_persistence_is_healthy());

    let shutdown = iroha_futures::supervisor::ShutdownSignal::new();
    let worker = runtime.start_audit_persistence_worker(shutdown.clone());
    fs::remove_dir(&latest_anchor).expect("repair latest anchor path");
    tokio::time::timeout(Duration::from_secs(1), async {
        while !runtime.audit_persistence_is_healthy() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("audit retry should recover");
    shutdown.send();
    assert_eq!(
        worker.await.expect("audit worker joins"),
        crate::ToriiCriticalWorkerExit::StoppedByShutdown
    );
}
#[test]
fn durable_store_exports_audit_index_matching_persisted_manifest() {
    let store = TempDir::new().expect("tempdir");
    let mut config = sample_config();
    config.store_dir = Some(store.path().to_path_buf());
    let runtime = Iso20022BridgeRuntime::from_config(&config)
        .expect("cfg")
        .expect("enabled");
    assert!(runtime.check_and_record_inbound(
        "audit-export",
        IsoMessageMetadata::inbound(
            "generic-iso20022",
            "pacs.008",
            None,
            Some("audit-export-biz".to_owned()),
            None,
            "audit-export-hash".to_owned(),
            "snapshot".to_owned(),
            false,
        ),
    ));
    runtime.mark_accepted("audit-export", "tx-export");
    let exported = runtime.audit_index();
    let persisted = read_audit_index(&store);
    assert_eq!(exported, persisted);
    let exported_obj = exported.as_object().expect("exported audit index object");
    assert!(persisted_audit_index_digest_matches(exported_obj));
    let mut tampered = exported.clone();
    tampered
        .as_object_mut()
        .expect("tampered audit index object")
        .insert("record_count".to_owned(), JsonValue::from(2_u64));
    assert!(!persisted_audit_index_digest_matches(
        tampered.as_object().expect("tampered audit index object")
    ));
}
#[test]
fn durable_store_audit_index_stops_startup_on_tampered_record() {
    let store = TempDir::new().expect("tempdir");
    let mut config = sample_config();
    config.store_dir = Some(store.path().to_path_buf());
    {
        let runtime = Iso20022BridgeRuntime::from_config(&config)
            .expect("cfg")
            .expect("enabled");
        for (message_id, business_id, payload_hash, tx_hash) in [
            (
                "audit-clean",
                "audit-clean-biz",
                "audit-clean-hash",
                "tx-clean",
            ),
            (
                "audit-tampered",
                "audit-tampered-biz",
                "audit-tampered-hash",
                "tx-tampered",
            ),
        ] {
            assert!(runtime.check_and_record_inbound(
                message_id,
                IsoMessageMetadata::inbound(
                    "generic-iso20022",
                    "pacs.008",
                    None,
                    Some(business_id.to_owned()),
                    None,
                    payload_hash.to_owned(),
                    "snapshot".to_owned(),
                    false,
                ),
            ));
            runtime.mark_accepted(message_id, tx_hash);
        }
    }
    let tampered_path = store
        .path()
        .join("messages")
        .join(message_filename("audit-tampered"));
    let original = fs::read_to_string(&tampered_path).expect("persisted JSON");
    assert!(original.contains("tx-tampered"));
    fs::write(&tampered_path, original.replace("tx-tampered", "tx-forged")).expect("tamper record");
    let error = runtime_config_error(&config, "tampered ISO records must stop startup");
    assert!(
        error
            .to_string()
            .contains("invalid or corrupt for schema V3"),
        "unexpected hard-cut error: {error:?}"
    );
}
#[test]
fn durable_store_rejects_tampered_record_body() {
    let store = TempDir::new().expect("tempdir");
    let mut config = sample_config();
    config.store_dir = Some(store.path().to_path_buf());
    {
        let runtime = Iso20022BridgeRuntime::from_config(&config)
            .expect("cfg")
            .expect("enabled");
        assert!(runtime.check_and_record_inbound(
            "tamper-msg",
            IsoMessageMetadata::inbound(
                "generic-iso20022",
                "pacs.008",
                None,
                Some("tamper-biz".to_owned()),
                None,
                "tamper-hash".to_owned(),
                "snapshot".to_owned(),
                false,
            ),
        ));
        runtime.mark_accepted("tamper-msg", "tx-original");
    }
    let path = store
        .path()
        .join("messages")
        .join(message_filename("tamper-msg"));
    let original = fs::read_to_string(&path).expect("persisted JSON");
    assert!(original.contains("tx-original"));
    let tampered = original.replace("tx-original", "tx-forged");
    fs::write(&path, &tampered).expect("tamper record");
    let audit_path = store
        .path()
        .join(ISO_PERSISTED_AUDIT_DIR)
        .join(ISO_PERSISTED_AUDIT_INDEX_FILE);
    let audit_before = fs::read_to_string(&audit_path).expect("audit index");
    let error = runtime_config_error(&config, "tampered ISO records must stop startup");
    assert!(
        error
            .to_string()
            .contains("invalid or corrupt for schema V3"),
        "unexpected hard-cut error: {error:?}"
    );
    assert_eq!(fs::read_to_string(path).expect("tampered record"), tampered);
    assert_eq!(
        fs::read_to_string(audit_path).expect("audit index"),
        audit_before,
        "failed startup must not regenerate the derived audit index"
    );
}
#[test]
fn durable_store_rejects_missing_record_digest() {
    let store = TempDir::new().expect("tempdir");
    let mut config = sample_config();
    config.store_dir = Some(store.path().to_path_buf());
    {
        let runtime = Iso20022BridgeRuntime::from_config(&config)
            .expect("cfg")
            .expect("enabled");
        assert!(runtime.check_and_record_inbound(
            "missing-digest-msg",
            IsoMessageMetadata::inbound(
                "generic-iso20022",
                "pacs.008",
                None,
                Some("missing-digest-biz".to_owned()),
                None,
                "missing-digest-hash".to_owned(),
                "snapshot".to_owned(),
                false,
            ),
        ));
    }
    let path = store
        .path()
        .join("messages")
        .join(message_filename("missing-digest-msg"));
    let text = fs::read_to_string(&path).expect("persisted JSON");
    let mut value = norito::json::from_json::<JsonValue>(&text).expect("persisted JSON parses");
    let obj = value.as_object_mut().expect("persisted object");
    assert!(obj.remove(ISO_PERSISTED_RECORD_DIGEST_FIELD).is_some());
    fs::write(
        &path,
        norito::json::to_string_pretty(&value).expect("serialize tampered JSON"),
    )
    .expect("write tampered JSON");
    let error = runtime_config_error(&config, "digest-free ISO records must stop startup");
    assert!(
        error
            .to_string()
            .contains("invalid or corrupt for schema V3"),
        "unexpected hard-cut error: {error:?}"
    );
}
#[test]
fn durable_store_rejects_malformed_record_digest() {
    let store = TempDir::new().expect("tempdir");
    let mut config = sample_config();
    config.store_dir = Some(store.path().to_path_buf());
    {
        let runtime = Iso20022BridgeRuntime::from_config(&config)
            .expect("cfg")
            .expect("enabled");
        assert!(runtime.check_and_record_inbound(
            "bad-digest-msg",
            IsoMessageMetadata::inbound(
                "generic-iso20022",
                "pacs.008",
                None,
                Some("bad-digest-biz".to_owned()),
                None,
                "bad-digest-hash".to_owned(),
                "snapshot".to_owned(),
                false,
            ),
        ));
    }
    let path = store
        .path()
        .join("messages")
        .join(message_filename("bad-digest-msg"));
    let text = fs::read_to_string(&path).expect("persisted JSON");
    let mut value = norito::json::from_json::<JsonValue>(&text).expect("persisted JSON parses");
    let obj = value.as_object_mut().expect("persisted object");
    obj.insert(
        ISO_PERSISTED_RECORD_DIGEST_FIELD.to_owned(),
        JsonValue::from("not-a-canonical-sha256"),
    );
    fs::write(
        &path,
        norito::json::to_string_pretty(&value).expect("serialize tampered JSON"),
    )
    .expect("write tampered JSON");
    let error = runtime_config_error(&config, "malformed ISO record digests must stop startup");
    assert!(
        error
            .to_string()
            .contains("invalid or corrupt for schema V3"),
        "unexpected hard-cut error: {error:?}"
    );
}
#[test]
fn durable_store_rejects_digest_correct_malformed_record_schema() {
    assert_digest_correct_record_mutation_is_rejected("missing-detail", |obj| {
        assert!(obj.remove("detail").is_some());
    });
    assert_digest_correct_record_mutation_is_rejected("missing-updated-at", |obj| {
        assert!(obj.remove("updated_at_ms").is_some());
    });
    assert_digest_correct_record_mutation_is_rejected("missing-ledger-queue-flag", |obj| {
        assert!(obj.remove("ledger_tx_queued").is_some());
    });
    assert_digest_correct_record_mutation_is_rejected("extra-root-field", |obj| {
        obj.insert("unexpected".to_owned(), JsonValue::from("drift"));
    });
    assert_digest_correct_record_mutation_is_rejected("missing-context-ledger", |obj| {
        let context = obj
            .get_mut("context")
            .and_then(JsonValue::as_object_mut)
            .expect("context object");
        assert!(context.remove("ledger_id").is_some());
    });
    assert_digest_correct_record_mutation_is_rejected("missing-metadata-service", |obj| {
        let metadata = obj
            .get_mut("metadata")
            .and_then(JsonValue::as_object_mut)
            .expect("metadata object");
        assert!(metadata.remove("business_service").is_some());
    });
    assert_digest_correct_record_mutation_is_rejected("extra-metadata-field", |obj| {
        let metadata = obj
            .get_mut("metadata")
            .and_then(JsonValue::as_object_mut)
            .expect("metadata object");
        metadata.insert("unexpected".to_owned(), JsonValue::from("drift"));
    });
    assert_digest_correct_record_mutation_is_rejected("missing-history-reason", |obj| {
        let history = obj
            .get_mut("status_history")
            .and_then(JsonValue::as_array_mut)
            .expect("status history array")
            .first_mut()
            .and_then(JsonValue::as_object_mut)
            .expect("status history entry");
        assert!(history.remove("reason_code").is_some());
    });
    assert_digest_correct_record_mutation_is_rejected("missing-history-updated-at", |obj| {
        let history = obj
            .get_mut("status_history")
            .and_then(JsonValue::as_array_mut)
            .expect("status history array")
            .first_mut()
            .and_then(JsonValue::as_object_mut)
            .expect("status history entry");
        assert!(history.remove("updated_at_ms").is_some());
    });
    assert_digest_correct_record_mutation_is_rejected("empty-status-history", |obj| {
        obj.insert("status_history".to_owned(), JsonValue::Array(Vec::new()));
    });
    assert_digest_correct_record_mutation_is_rejected("status-history-entry-overflow", |obj| {
        let history = obj
            .get_mut("status_history")
            .and_then(JsonValue::as_array_mut)
            .expect("status history array");
        let entry = history.first().expect("initial history entry").clone();
        history.resize(ISO_STATUS_HISTORY_MAX_ENTRIES_V1 + 1, entry);
    });
    assert_digest_correct_record_mutation_is_rejected("status-history-byte-overflow", |obj| {
        let history = obj
            .get_mut("status_history")
            .and_then(JsonValue::as_array_mut)
            .expect("status history array");
        history[0]
            .as_object_mut()
            .expect("status history entry")
            .insert(
                "detail".to_owned(),
                JsonValue::from("x".repeat(ISO_STATUS_HISTORY_MAX_ENCODED_BYTES_V1)),
            );
    });
    assert_digest_correct_record_mutation_is_rejected("non-string-change-reason", |obj| {
        obj.insert(
            "change_reason_codes".to_owned(),
            JsonValue::Array(vec![JsonValue::from("RJCT"), JsonValue::from(7_u64)]),
        );
    });
    assert_digest_correct_record_mutation_is_rejected("change-reason-entry-overflow", |obj| {
        obj.insert(
            "change_reason_codes".to_owned(),
            JsonValue::Array(
                (0..=ISO_CHANGE_REASON_MAX_ENTRIES_V1)
                    .map(|index| JsonValue::from(format!("U{index:03}")))
                    .collect(),
            ),
        );
    });
    assert_digest_correct_record_mutation_is_rejected("change-reason-byte-overflow", |obj| {
        obj.insert(
            "change_reason_codes".to_owned(),
            JsonValue::Array(vec![JsonValue::from(
                "x".repeat(ISO_CHANGE_REASON_MAX_ENCODED_BYTES_V1),
            )]),
        );
    });
    assert_digest_correct_record_mutation_is_rejected("control-detail", |obj| {
        obj.insert("detail".to_owned(), JsonValue::from("bad\nvalue"));
    });
    assert_digest_correct_record_mutation_is_rejected("padded-transaction-hash", |obj| {
        obj.insert("transaction_hash".to_owned(), JsonValue::from(" tx-drift"));
    });
    assert_digest_correct_record_mutation_is_rejected("padded-change-reason", |obj| {
        obj.insert(
            "change_reason_codes".to_owned(),
            JsonValue::Array(vec![JsonValue::from(" RJCT")]),
        );
    });
    assert_digest_correct_record_mutation_is_rejected("control-context-ledger", |obj| {
        let context = obj
            .get_mut("context")
            .and_then(JsonValue::as_object_mut)
            .expect("context object");
        context.insert("ledger_id".to_owned(), JsonValue::from("ledger\nid"));
    });
    assert_digest_correct_record_mutation_is_rejected("padded-metadata-service", |obj| {
        let metadata = obj
            .get_mut("metadata")
            .and_then(JsonValue::as_object_mut)
            .expect("metadata object");
        metadata.insert("business_service".to_owned(), JsonValue::from(" service"));
    });
    assert_digest_correct_record_mutation_is_rejected("control-history-detail", |obj| {
        let history = obj
            .get_mut("status_history")
            .and_then(JsonValue::as_array_mut)
            .expect("status history array")
            .first_mut()
            .and_then(JsonValue::as_object_mut)
            .expect("status history entry");
        history.insert("detail".to_owned(), JsonValue::from("bad\nhistory"));
    });
}
#[test]
fn durable_store_rejects_digest_correct_message_id_filename_drift() {
    assert_digest_correct_record_mutation_is_rejected("embedded-message-id-drift", |obj| {
        obj.insert(
            "message_id".to_owned(),
            JsonValue::from("forged-embedded-message-id"),
        );
    });
    let store = TempDir::new().expect("tempdir");
    let mut config = sample_config();
    config.store_dir = Some(store.path().to_path_buf());
    {
        let runtime = Iso20022BridgeRuntime::from_config(&config)
            .expect("cfg")
            .expect("enabled");
        assert!(runtime.check_and_record_inbound(
            "filename-drift",
            IsoMessageMetadata::inbound(
                "generic-iso20022",
                "pacs.008",
                None,
                Some("filename-drift-biz".to_owned()),
                None,
                "filename-drift-hash".to_owned(),
                "snapshot".to_owned(),
                false,
            ),
        ));
        runtime.mark_accepted("filename-drift", "tx-filename-drift");
    }
    let messages_dir = store.path().join("messages");
    let expected_path = messages_dir.join(message_filename("filename-drift"));
    let drifted_path = messages_dir.join(message_filename("filename-drift-forged"));
    fs::rename(&expected_path, &drifted_path).expect("rename persisted record");
    let error = runtime_config_error(&config, "drifted ISO record filenames must stop startup");
    assert!(
        error
            .to_string()
            .contains("does not match its embedded message identity"),
        "unexpected hard-cut error: {error:?}"
    );
}
#[cfg(unix)]
#[test]
fn durable_store_rejects_symlinked_record_on_reload() {
    let store = TempDir::new().expect("tempdir");
    let mut config = sample_config();
    config.store_dir = Some(store.path().to_path_buf());
    {
        let runtime = Iso20022BridgeRuntime::from_config(&config)
            .expect("cfg")
            .expect("enabled");
        assert!(runtime.check_and_record_inbound(
            "symlinked-record",
            IsoMessageMetadata::inbound(
                "generic-iso20022",
                "pacs.008",
                None,
                Some("symlinked-record-biz".to_owned()),
                None,
                "symlinked-record-hash".to_owned(),
                "snapshot".to_owned(),
                false,
            ),
        ));
        runtime.mark_accepted("symlinked-record", "tx-symlinked-record");
    }
    let messages_dir = store.path().join("messages");
    let expected_path = messages_dir.join(message_filename("symlinked-record"));
    let target_path = store.path().join("symlink-target.json");
    fs::rename(&expected_path, &target_path).expect("move persisted record");
    std::os::unix::fs::symlink(&target_path, &expected_path).expect("symlink persisted record");
    let error = runtime_config_error(&config, "symlinked ISO records must stop startup");
    assert!(
        error.to_string().contains("is not a regular file"),
        "unexpected hard-cut error: {error:?}"
    );
}
#[cfg(unix)]
#[test]
fn durable_store_rejects_symlinked_messages_dir_on_reload() {
    let target = TempDir::new().expect("target tempdir");
    let mut target_config = sample_config();
    target_config.store_dir = Some(target.path().to_path_buf());
    {
        let runtime = Iso20022BridgeRuntime::from_config(&target_config)
            .expect("cfg")
            .expect("enabled");
        assert!(runtime.check_and_record_inbound(
            "symlinked-messages-dir",
            IsoMessageMetadata::inbound(
                "generic-iso20022",
                "pacs.008",
                None,
                Some("symlinked-messages-dir-biz".to_owned()),
                None,
                "symlinked-messages-dir-hash".to_owned(),
                "snapshot".to_owned(),
                false,
            ),
        ));
        runtime.mark_accepted("symlinked-messages-dir", "tx-symlinked-messages-dir");
    }
    let store = TempDir::new().expect("store tempdir");
    std::os::unix::fs::symlink(
        target.path().join("messages"),
        store.path().join("messages"),
    )
    .expect("symlink messages dir");
    let mut config = sample_config();
    config.store_dir = Some(store.path().to_path_buf());
    let error = runtime_config_error(&config, "symlinked ISO message stores must stop startup");
    assert!(
        error.to_string().contains("is not a real directory"),
        "unexpected hard-cut error: {error:?}"
    );
}
#[cfg(unix)]
#[test]
fn durable_store_rejects_non_real_replay_tombstone_directories() {
    for kind in ["file", "symlink"] {
        let store = TempDir::new().expect("store tempdir");
        let tombstones = store.path().join(ISO_PERSISTED_REPLAY_TOMBSTONE_DIR);
        let _target = if kind == "symlink" {
            let target = TempDir::new().expect("target tempdir");
            std::os::unix::fs::symlink(target.path(), &tombstones)
                .expect("symlink tombstone directory");
            Some(target)
        } else {
            fs::write(&tombstones, b"not a directory").expect("tombstone directory blocker");
            None
        };
        let mut config = sample_config();
        config.store_dir = Some(store.path().to_path_buf());
        let error = runtime_config_error(
            &config,
            "non-real ISO replay tombstone stores must stop startup",
        );
        assert!(
            error.to_string().contains("is not a real directory"),
            "unexpected hard-cut error for {kind}: {error:?}"
        );
    }
}
#[cfg(unix)]
#[test]
fn durable_store_refuses_symlinked_messages_dir_on_persist() {
    let store = TempDir::new().expect("store tempdir");
    let target = TempDir::new().expect("target tempdir");
    std::os::unix::fs::symlink(target.path(), store.path().join("messages"))
        .expect("symlink messages dir");
    let mut config = sample_config();
    config.store_dir = Some(store.path().to_path_buf());
    let error = runtime_config_error(&config, "symlinked ISO message stores must stop startup");
    assert!(
        error.to_string().contains("is not a real directory"),
        "unexpected hard-cut error: {error:?}"
    );
    assert!(
        target
            .path()
            .read_dir()
            .expect("target directory")
            .next()
            .is_none()
    );
}
#[cfg(unix)]
#[test]
fn durable_store_refuses_symlinked_audit_dir_on_persist() {
    let store = TempDir::new().expect("store tempdir");
    let target = TempDir::new().expect("target tempdir");
    std::os::unix::fs::symlink(target.path(), store.path().join(ISO_PERSISTED_AUDIT_DIR))
        .expect("symlink audit dir");
    let mut config = sample_config();
    config.store_dir = Some(store.path().to_path_buf());
    let error = runtime_config_error(&config, "symlinked ISO audit stores must stop startup");
    assert!(
        error.to_string().contains("is not a real directory"),
        "unexpected hard-cut error: {error:?}"
    );
    assert!(
        target
            .path()
            .read_dir()
            .expect("target directory")
            .next()
            .is_none()
    );
}
#[cfg(unix)]
#[test]
fn durable_store_refuses_symlinked_external_export_dirs() {
    let store = TempDir::new().expect("store tempdir");
    let export_parent = TempDir::new().expect("export parent tempdir");
    let export_target = TempDir::new().expect("export target tempdir");
    let export_link = export_parent.path().join("export-link");
    std::os::unix::fs::symlink(export_target.path(), &export_link).expect("symlink export dir");
    let mut config = sample_config();
    config.store_dir = Some(store.path().to_path_buf());
    config.audit_export_dir = Some(export_link);
    let error = runtime_config_error(
        &config,
        "symlinked ISO audit export roots must stop startup",
    );
    assert!(
        error.to_string().contains("audit persistence targets"),
        "unexpected hard-cut error: {error:?}"
    );
    assert!(
        !export_target
            .path()
            .join(ISO_PERSISTED_AUDIT_INDEX_FILE)
            .exists(),
        "external export must not follow a symlinked export root"
    );
    assert!(
        !export_target
            .path()
            .join(ISO_AUDIT_EXPORT_LATEST_ANCHOR_FILE)
            .exists(),
        "external export must not write latest anchor through a symlinked root"
    );
    let export = TempDir::new().expect("export tempdir");
    let anchor_target = TempDir::new().expect("anchor target tempdir");
    std::os::unix::fs::symlink(
        anchor_target.path(),
        export.path().join(ISO_AUDIT_EXPORT_ANCHOR_DIR),
    )
    .expect("symlink anchor dir");
    let mut anchor_config = sample_config();
    anchor_config.store_dir = Some(store.path().to_path_buf());
    anchor_config.audit_export_dir = Some(export.path().to_path_buf());
    let error = runtime_config_error(
        &anchor_config,
        "symlinked ISO audit anchor directories must stop startup",
    );
    assert!(
        error.to_string().contains("audit persistence targets"),
        "unexpected hard-cut error: {error:?}"
    );
    assert!(
        !export
            .path()
            .join(ISO_AUDIT_EXPORT_LATEST_ANCHOR_FILE)
            .exists(),
        "latest anchor must not advance when the immutable anchor cannot be written"
    );
    assert!(
        anchor_target
            .path()
            .read_dir()
            .expect("anchor target directory")
            .next()
            .is_none(),
        "digest-addressed anchors must not follow a symlinked anchors directory"
    );
}
#[test]
fn durable_store_rejects_oversized_record_on_reload() {
    assert_digest_correct_record_mutation_is_rejected("oversized-record", |obj| {
        let oversized_detail =
            "x".repeat(usize::try_from(ISO_PERSISTED_RECORD_MAX_BYTES).expect("cap fits") + 1);
        obj.insert(
            "detail".to_owned(),
            JsonValue::from(oversized_detail.as_str()),
        );
    });
}
#[test]
fn durable_store_refuses_oversized_update_without_mutating_original_record() {
    let store = TempDir::new().expect("tempdir");
    let mut config = sample_config();
    config.store_dir = Some(store.path().to_path_buf());
    let runtime = Iso20022BridgeRuntime::from_config(&config)
        .expect("cfg")
        .expect("enabled");
    assert!(runtime.check_and_record_inbound(
        "oversized-persist",
        IsoMessageMetadata::inbound(
            "generic-iso20022",
            "pacs.008",
            None,
            Some("oversized-persist-biz".to_owned()),
            None,
            "oversized-persist-hash".to_owned(),
            "snapshot".to_owned(),
            false,
        ),
    ));
    let path = store
        .path()
        .join("messages")
        .join(message_filename("oversized-persist"));
    assert!(path.exists(), "initial persisted record missing");
    let original_bytes = fs::read(&path).expect("original persisted record");
    let original_index = read_audit_index(&store);
    let oversized_detail =
        "x".repeat(usize::try_from(ISO_PERSISTED_RECORD_MAX_BYTES).expect("cap fits") + 1);
    assert!(!runtime.update_message_context(
        "oversized-persist",
        IsoMessageContext {
            ledger_id: Some(oversized_detail),
            ..IsoMessageContext::default()
        },
    ));
    assert_eq!(
        fs::read(&path).expect("retained original record"),
        original_bytes
    );
    assert!(
        runtime
            .message_status("oversized-persist")
            .unwrap()
            .ledger_id()
            .is_none()
    );
    assert!(runtime.message_status("oversized-persist").is_some());
    let index_value = read_audit_index(&store);
    assert_eq!(index_value, original_index);
    let index_obj = index_value.as_object().expect("audit index object");
    assert!(persisted_audit_index_digest_matches(index_obj));
    assert_eq!(
        index_obj.get("record_count").and_then(JsonValue::as_u64),
        Some(1)
    );
    let reloaded = Iso20022BridgeRuntime::from_config(&config)
        .expect("cfg")
        .expect("enabled");
    assert!(
        reloaded
            .message_status("oversized-persist")
            .unwrap()
            .ledger_id()
            .is_none()
    );
}
#[test]
fn runtime_rejects_invalid_alias_iban() {
    let mut config = sample_config();
    config.account_aliases[0].iban = "INVALID".to_string();
    let err = Iso20022BridgeRuntime::from_config(&config)
        .err()
        .expect("invalid IBAN");
    assert!(
        err.to_string()
            .contains("iso_bridge account alias `INVALID` is not a valid IBAN")
    );
}
#[test]
fn runtime_rejects_invalid_currency_code() {
    let mut config = sample_config();
    config.currency_assets[0].currency = "ZZZ".to_string();
    let err = Iso20022BridgeRuntime::from_config(&config)
        .err()
        .expect("invalid currency binding");
    assert!(
        err.to_string()
            .contains("iso_bridge currency binding `ZZZ` is not a valid ISO 4217 code")
    );
}
#[test]
fn runtime_rejects_zero_or_duplicate_currency_caps() {
    let mut zero = sample_config();
    zero.currency_assets[0].max_amount = Quantity::zero();
    let err = Iso20022BridgeRuntime::from_config(&zero)
        .err()
        .expect("zero settlement cap must fail");
    assert!(
        err.to_string()
            .contains("max_amount must be greater than zero")
    );
    let mut duplicate = sample_config();
    duplicate
        .currency_assets
        .push(duplicate.currency_assets[0].clone());
    let err = Iso20022BridgeRuntime::from_config(&duplicate)
        .err()
        .expect("duplicate settlement currency must fail");
    assert!(err.to_string().contains("duplicate currency binding `USD`"));
}
#[test]
fn runtime_accepts_asset_alias_currency_binding() {
    let mut config = sample_config();
    config.currency_assets[0].asset_definition = "usd#test".to_string();
    let runtime = Iso20022BridgeRuntime::from_config(&config)
        .expect("cfg")
        .expect("enabled");
    let world = sample_world(Some("usd#test"));
    let world_view = world.view();
    let resolved = runtime
        .resolve_asset(&world_view, 10_000, "USD")
        .expect("currency binding should resolve");
    assert_eq!(resolved.to_string(), sample_asset_definition_literal());
}
#[test]
fn runtime_rejects_legacy_signer_account_literal() {
    let mut config = sample_config();
    if let Some(ref mut signer) = config.signer {
        signer.account_id = LEGACY_PUBLIC_KEY_LITERAL.to_string();
    }
    let err = Iso20022BridgeRuntime::from_config(&config)
        .err()
        .expect("legacy signer literal must be rejected");
    assert!(err.to_string().contains("signer account_id"));
}
#[test]
fn runtime_rejects_legacy_alias_account_literal() {
    let mut config = sample_config();
    config.account_aliases[0].account_id = LEGACY_PUBLIC_KEY_LITERAL.to_string();
    let err = Iso20022BridgeRuntime::from_config(&config)
        .err()
        .expect("legacy alias literal must be rejected");
    assert!(err.to_string().contains("account alias"));
}
#[test]
fn dedupe_prevents_duplicates_within_ttl() {
    let runtime = sample_runtime();
    assert!(runtime.check_and_record_message("abc"));
    assert!(!runtime.check_and_record_message("abc"));
}
#[test]
fn build_transaction_extracts_native_payment() {
    let (runtime, _reference_file) = payment_runtime_with_bic_reference(sample_config());
    let (expected_account, canonical_account, _) = sample_account_bundle();
    let account_address = AccountAddress::from_account_id(&expected_account).expect("address");
    let account_i105 = account_address
        .to_i105_for_discriminant(iroha_data_model::account::address::chain_discriminant())
        .expect("i105 encoding");
    let canonical_address = account_address.canonical_hex().expect("canonical hex");
    let msg = native_payment_message(
            "pacs.008",
            format!("MsgId=m1\nIntrBkSttlmAmt=10\nIntrBkSttlmCcy=USD\nIntrBkSttlmDt=2024-01-01\nDbtrAcct=GB82WEST12345698765432\nCdtrAcct=GB82WEST12345698765432\nDbtrAgt=DEUTDEFF\nCdtrAgt=DEUTDEFF\nSplmtryData/SourceAccountAddress={account_i105}\nSplmtryData/TargetAccountAddress={account_i105}").as_bytes(),
        )
        .expect("parsed");
    let world = sample_world(None);
    let world_view = world.view();
    let chain_id: ChainId = "test-chain".parse().unwrap();
    let telemetry = MaybeTelemetry::for_tests();
    let (payload, context) = runtime
        .build_pacs008_payload(
            &msg,
            &world_view,
            10_000,
            &chain_id,
            &crate::test_utils::signed_query_network_id(),
            &telemetry,
        )
        .expect("build");
    assert_eq!(context.ledger_id.as_deref(), Some(chain_id.as_str()));
    assert_eq!(
        context.source_account_id.as_deref(),
        Some(canonical_account.as_str())
    );
    assert_eq!(
        context.target_account_id.as_deref(),
        Some(native_payment_recipient().to_string().as_str())
    );
    let asset_definition = sample_asset_definition_literal();
    assert_eq!(
        context.asset_definition_id.as_deref(),
        Some(asset_definition.as_str())
    );
    assert_eq!(
        context.source_account_address.as_deref(),
        Some(canonical_address.as_str())
    );
    assert_eq!(
        context.target_account_address.as_deref(),
        Some(canonical_address.as_str())
    );
    assert!(context.asset_id.as_ref().is_some());
    assert_eq!(
        payload.network_id().copied(),
        Some(crate::test_utils::signed_query_network_id())
    );
    runtime
        .sign_transaction_payload(payload.clone())
        .expect("sign pacs.008 payload")
        .verify_signature()
        .expect("pacs.008 transaction signature should verify");
    let metadata = &payload.metadata;
    let ledger_key = Name::from_str("iso20022_ledger_id").unwrap();
    let stored_ledger = metadata
        .get(&ledger_key)
        .and_then(|json| json.try_into_any_norito::<String>().ok())
        .expect("ledger metadata");
    assert_eq!(stored_ledger, chain_id.as_str());
    let source_key = Name::from_str("iso20022_source_account_id").unwrap();
    let stored_source = metadata
        .get(&source_key)
        .and_then(|json| json.try_into_any_norito::<String>().ok())
        .expect("source metadata");
    assert_eq!(stored_source, canonical_account);
    let asset_key = Name::from_str("iso20022_asset_definition_id").unwrap();
    let stored_asset = metadata
        .get(&asset_key)
        .and_then(|json| json.try_into_any_norito::<String>().ok())
        .expect("asset metadata");
    assert_eq!(stored_asset, asset_definition);
    let asset_id_key = Name::from_str("iso20022_asset_id").unwrap();
    let stored_asset_id = metadata
        .get(&asset_id_key)
        .and_then(|json| json.try_into_any_norito::<String>().ok())
        .expect("asset id metadata");
    assert_eq!(context.asset_id.as_deref(), Some(stored_asset_id.as_str()));
}
#[test]
fn build_transaction_validates_configured_asset_alias_against_canonical_signed_definition() {
    let mut config = sample_config();
    config.currency_assets[0].asset_definition = "usd#test".to_owned();
    let (runtime, _reference_file) = payment_runtime_with_bic_reference(config);
    let msg = native_payment_message(
            "pacs.008",
            b"MsgId=m1\nIntrBkSttlmAmt=10\nIntrBkSttlmCcy=USD\nIntrBkSttlmDt=2024-01-01\nDbtrAcct=GB82WEST12345698765432\nCdtrAcct=GB82WEST12345698765432\nDbtrAgt=DEUTDEFF\nCdtrAgt=DEUTDEFF",
        )
        .expect("parsed");
    let world = sample_world(Some("usd#test"));
    let world_view = world.view();
    let chain_id: ChainId = "test-chain".parse().unwrap();
    let telemetry = MaybeTelemetry::for_tests();
    let (_tx, context) = runtime
        .build_pacs008_payload(
            &msg,
            &world_view,
            10_000,
            &chain_id,
            &crate::test_utils::signed_query_network_id(),
            &telemetry,
        )
        .expect("build");
    let expected_asset_definition = sample_asset_definition_literal();
    assert_eq!(
        context.asset_definition_id.as_deref(),
        Some(expected_asset_definition.as_str())
    );
}
#[derive(Clone, Copy)]
enum PaymentRail {
    CustomerCreditTransfer,
    FinancialInstitutionCreditTransfer,
}
impl PaymentRail {
    fn message_type(self) -> &'static str {
        match self {
            Self::CustomerCreditTransfer => "pacs.008",
            Self::FinancialInstitutionCreditTransfer => "pacs.009",
        }
    }
    fn default_amount(self) -> &'static str {
        match self {
            Self::CustomerCreditTransfer => "10",
            Self::FinancialInstitutionCreditTransfer => "2500",
        }
    }
    fn debtor_agent_field(self) -> &'static str {
        match self {
            Self::CustomerCreditTransfer => "DbtrAgt",
            Self::FinancialInstitutionCreditTransfer => "InstgAgt",
        }
    }
    fn message(
        self,
        amount: &str,
        currency: &str,
        iban: &str,
        bic: &str,
        extra: &str,
    ) -> ParsedMessage {
        let input = match self {
            Self::CustomerCreditTransfer => format!(
                "MsgId=m1\nIntrBkSttlmAmt={amount}\nIntrBkSttlmCcy={currency}\nIntrBkSttlmDt=2024-01-01\nDbtrAcct={iban}\nCdtrAcct={iban}\nDbtrAgt={bic}\nCdtrAgt={bic}\n{extra}"
            ),
            Self::FinancialInstitutionCreditTransfer => format!(
                "MsgId=pacs009-group\nBizMsgIdr=b1\nMsgDefIdr=pacs.009.001.10\nCreDtTm=2024-01-01T12:00:00Z\nIntrBkSttlmAmt={amount}\nIntrBkSttlmCcy={currency}\nIntrBkSttlmDt=2024-01-03\nDbtrAcct={iban}\nCdtrAcct={iban}\nInstgAgt={bic}\nInstdAgt={bic}\nPurp=SECU\n{extra}"
            ),
        };
        native_payment_message(self.message_type(), input.as_bytes())
            .expect("payment message parses")
    }
    fn build(
        self,
        runtime: &Iso20022BridgeRuntime,
        parsed: &ParsedMessage,
        world: &impl WorldReadOnly,
        chain_id: &ChainId,
        telemetry: &MaybeTelemetry,
    ) -> Result<(TransactionPayload, IsoMessageContext), MsgError> {
        let network_id = crate::test_utils::signed_query_network_id();
        match self {
            Self::CustomerCreditTransfer => runtime.build_pacs008_payload(
                parsed,
                world,
                10_000,
                chain_id,
                &network_id,
                telemetry,
            ),
            Self::FinancialInstitutionCreditTransfer => runtime.build_pacs009_payload(
                parsed,
                world,
                10_000,
                chain_id,
                &network_id,
                telemetry,
            ),
        }
    }
}
fn assert_supplementary_accounts_match_iban_bindings(rail: PaymentRail) {
    let (runtime, _reference_file) = payment_runtime_with_bic_reference(sample_config());
    let mismatched_account =
        AccountId::new(fixture_key_pair(0xAB).public_key().clone()).to_string();
    let world = sample_world(None);
    let world_view = world.view();
    let chain_id: ChainId = "test-chain".parse().unwrap();
    let telemetry = MaybeTelemetry::for_tests();
    for hint_field in [
        "NexusSettlement/SourceAccountId",
        "NexusSettlement/TargetAccountId",
    ] {
        let extra = format!("{hint_field}={mismatched_account}");
        let parsed = rail.message(
            rail.default_amount(),
            "USD",
            "GB82WEST12345698765432",
            "DEUTDEFF",
            &extra,
        );
        let err = rail
            .build(&runtime, &parsed, &world_view, &chain_id, &telemetry)
            .expect_err("mismatched account hint must not replace the IBAN binding");
        assert!(matches!(
            err,
            MsgError::InvalidValue {
                field,
                kind: InvalidValueKind::Enum,
            } if field == hint_field
        ));
    }
}
fn assert_currency_cap_and_asset_binding(rail: PaymentRail) {
    let mut config = sample_config();
    config.currency_assets[0].max_amount = Quantity::from(100_u32);
    let (runtime, _reference_file) = payment_runtime_with_bic_reference(config);
    let world = sample_world(None);
    let world_view = world.view();
    let chain_id: ChainId = "test-chain".parse().unwrap();
    let telemetry = MaybeTelemetry::for_tests();
    let message = |amount: &str, extra: &str| {
        rail.message(amount, "USD", "GB82WEST12345698765432", "DEUTDEFF", extra)
    };
    rail.build(
        &runtime,
        &message("100", ""),
        &world_view,
        &chain_id,
        &telemetry,
    )
    .expect("amount equal to the configured cap must be accepted");
    let err = rail
        .build(
            &runtime,
            &message("100.01", ""),
            &world_view,
            &chain_id,
            &telemetry,
        )
        .expect_err("amount above the configured cap must fail");
    assert!(matches!(
        err,
        MsgError::InvalidValue {
            ref field,
            kind: InvalidValueKind::Amount,
        } if field == "IntrBkSttlmAmt"
    ));
    let other_asset = AssetDefinitionId::derive_from_components(
        DomainId::try_new("test", "universal").expect("domain"),
        "eur".parse().expect("name"),
    );
    let err = rail
        .build(
            &runtime,
            &message(
                "10",
                &format!("NexusSettlement/AssetDefinitionId={other_asset}"),
            ),
            &world_view,
            &chain_id,
            &telemetry,
        )
        .expect_err("asset hint must not replace the currency binding");
    assert!(matches!(
        err,
        MsgError::InvalidValue {
            ref field,
            kind: InvalidValueKind::Enum,
        } if field == "NexusSettlement/AssetDefinitionId"
    ));
}
#[derive(Clone, Copy)]
enum InvalidPaymentIdentifier {
    UnmappedIban,
    UnboundCurrency,
    UnknownBic,
}
fn assert_payment_identifier_rejected(rail: PaymentRail, violation: InvalidPaymentIdentifier) {
    let (runtime, _reference_file) = payment_runtime_with_bic_reference(sample_config());
    let (iban, currency, bic, field, kind) = match violation {
        InvalidPaymentIdentifier::UnmappedIban => (
            "GB29NWBK60161331926819",
            "USD",
            "DEUTDEFF",
            "DbtrAcct",
            IdentifierKind::Iban,
        ),
        InvalidPaymentIdentifier::UnboundCurrency => (
            "GB82WEST12345698765432",
            "EUR",
            "DEUTDEFF",
            "IntrBkSttlmCcy",
            IdentifierKind::Currency,
        ),
        InvalidPaymentIdentifier::UnknownBic => (
            "GB82WEST12345698765432",
            "USD",
            "TESTUS33",
            rail.debtor_agent_field(),
            IdentifierKind::Bic,
        ),
    };
    let parsed = rail.message(rail.default_amount(), currency, iban, bic, "");
    let world = sample_world(None);
    let world_view = world.view();
    let chain_id: ChainId = "test-chain".parse().unwrap();
    let telemetry = MaybeTelemetry::for_tests();
    let err = rail
        .build(&runtime, &parsed, &world_view, &chain_id, &telemetry)
        .expect_err("invalid payment identifier must fail");
    match err {
        MsgError::InvalidIdentifier {
            field: actual_field,
            kind: actual_kind,
        } => {
            assert_eq!(actual_field, field);
            assert_eq!(actual_kind, kind);
        }
        other => panic!("unexpected error: {other:?}"),
    }
}
#[test]
fn pacs008_supplementary_accounts_must_match_iban_bindings() {
    assert_supplementary_accounts_match_iban_bindings(PaymentRail::CustomerCreditTransfer);
}
#[test]
fn pacs008_enforces_currency_cap_and_asset_binding() {
    assert_currency_cap_and_asset_binding(PaymentRail::CustomerCreditTransfer);
}
#[test]
fn pacs008_rejects_unknown_bic() {
    assert_payment_identifier_rejected(
        PaymentRail::CustomerCreditTransfer,
        InvalidPaymentIdentifier::UnknownBic,
    );
}
#[test]
fn pacs008_rejects_unmapped_iban() {
    assert_payment_identifier_rejected(
        PaymentRail::CustomerCreditTransfer,
        InvalidPaymentIdentifier::UnmappedIban,
    );
}
#[test]
fn pacs008_rejects_unbound_currency() {
    assert_payment_identifier_rejected(
        PaymentRail::CustomerCreditTransfer,
        InvalidPaymentIdentifier::UnboundCurrency,
    );
}
#[test]
fn build_pacs009_payload_extracts_native_payment() {
    let (runtime, _reference_file) = payment_runtime_with_bic_reference(sample_config());
    let (expected_account, _, _) = sample_account_bundle();
    let account_i105 = AccountAddress::from_account_id(&expected_account)
        .expect("address")
        .to_i105_for_discriminant(iroha_data_model::account::address::chain_discriminant())
        .expect("i105 encoding");
    let msg = native_payment_message(
            "pacs.009",
            format!("MsgId=pacs009-group\nBizMsgIdr=b1\nMsgDefIdr=pacs.009.001.10\nCreDtTm=2024-01-01T12:00:00Z\nIntrBkSttlmAmt=2500\nIntrBkSttlmCcy=USD\nIntrBkSttlmDt=2024-01-03\nDbtrAcct=GB82WEST12345698765432\nCdtrAcct=GB82WEST12345698765432\nInstgAgt=DEUTDEFF\nInstdAgt=DEUTDEFF\nPurp=SECU\nSplmtryData/SourceAccountAddress={account_i105}\nSplmtryData/TargetAccountAddress={account_i105}").as_bytes(),
        )
        .expect("parsed");
    let world = sample_world(None);
    let world_view = world.view();
    let chain_id: ChainId = "test-chain".parse().unwrap();
    let telemetry = MaybeTelemetry::for_tests();
    let (payload, context) = runtime
        .build_pacs009_payload(
            &msg,
            &world_view,
            10_000,
            &chain_id,
            &crate::test_utils::signed_query_network_id(),
            &telemetry,
        )
        .expect("build");
    assert_eq!(context.ledger_id.as_deref(), Some(chain_id.as_str()));
    let (_expected_account, canonical_account, _) = sample_account_bundle();
    assert_eq!(
        context.source_account_id.as_deref(),
        Some(canonical_account.as_str())
    );
    assert_eq!(
        context.target_account_id.as_deref(),
        Some(native_payment_recipient().to_string().as_str())
    );
    let asset_definition = sample_asset_definition_literal();
    assert_eq!(
        context.asset_definition_id.as_deref(),
        Some(asset_definition.as_str())
    );
    runtime
        .sign_transaction_payload(payload.clone())
        .expect("sign pacs.009 payload")
        .verify_signature()
        .expect("pacs.009 transaction signature should verify");
    let metadata = &payload.metadata;
    let purpose_key = Name::from_str("iso20022_category_purpose").unwrap();
    let stored_purpose = metadata
        .get(&purpose_key)
        .and_then(|json| json.try_into_any_norito::<String>().ok())
        .expect("purpose metadata");
    assert_eq!(stored_purpose, "SECU");
}
#[test]
fn pacs009_supplementary_accounts_must_match_iban_bindings() {
    assert_supplementary_accounts_match_iban_bindings(
        PaymentRail::FinancialInstitutionCreditTransfer,
    );
}
#[test]
fn pacs009_enforces_currency_cap_and_asset_binding() {
    assert_currency_cap_and_asset_binding(PaymentRail::FinancialInstitutionCreditTransfer);
}
#[test]
fn pacs009_requires_securities_purpose() {
    let (runtime, _reference_file) = payment_runtime_with_bic_reference(sample_config());
    let msg = parse_message(
            "pacs.009",
            b"MsgId=pacs009-group\nBizMsgIdr=b1\nMsgDefIdr=pacs.009.001.10\nCreDtTm=2024-01-01T12:00:00Z\nIntrBkSttlmAmt=2500\nIntrBkSttlmCcy=USD\nIntrBkSttlmDt=2024-01-03\nDbtrAcct=GB82WEST12345698765432\nCdtrAcct=GB82WEST12345698765432\nInstgAgt=DEUTDEFF\nInstdAgt=DEUTDEFF\nPurp=OTHR",
        )
        .expect("parsed");
    let world = sample_world(None);
    let world_view = world.view();
    let chain_id: ChainId = "test-chain".parse().unwrap();
    let telemetry = MaybeTelemetry::for_tests();
    let err = runtime
        .build_pacs009_payload(
            &msg,
            &world_view,
            10_000,
            &chain_id,
            &crate::test_utils::signed_query_network_id(),
            &telemetry,
        )
        .expect_err("non-SECU purpose must fail");
    match err {
        MsgError::InvalidValue { field, kind } => {
            assert_eq!(field, "Purp");
            assert_eq!(kind, InvalidValueKind::Enum);
        }
        other => panic!("unexpected error: {other:?}"),
    }
}
#[test]
fn pacs009_rejects_unmapped_iban() {
    assert_payment_identifier_rejected(
        PaymentRail::FinancialInstitutionCreditTransfer,
        InvalidPaymentIdentifier::UnmappedIban,
    );
}
#[test]
fn pacs009_rejects_unbound_currency() {
    assert_payment_identifier_rejected(
        PaymentRail::FinancialInstitutionCreditTransfer,
        InvalidPaymentIdentifier::UnboundCurrency,
    );
}
#[test]
fn pacs009_rejects_unknown_bic() {
    assert_payment_identifier_rejected(
        PaymentRail::FinancialInstitutionCreditTransfer,
        InvalidPaymentIdentifier::UnknownBic,
    );
}
#[test]
fn rejected_message_identity_remains_reserved_until_dedupe_expiry() {
    let runtime = sample_runtime();
    assert!(runtime.check_and_record_message("m1"));
    runtime.mark_rejected("m1", Some("missing mapping".to_string()), None);
    assert!(!runtime.check_and_record_message("m1"));
}
#[test]
fn status_transitions_are_recorded() {
    let runtime = sample_runtime();
    assert!(runtime.check_and_record_message("m2"));
    let pending = runtime.message_status("m2").expect("status");
    assert_eq!(pending.status_label(), "Pending");
    assert!(pending.ledger_id().is_none());
    assert_eq!(pending.pacs002_code(), "ACTC");
    let accepted_update = runtime.mark_accepted("m2", "hash-1");
    assert_eq!(accepted_update.status_label(), "Accepted");
    assert_eq!(accepted_update.transaction_hash(), Some("hash-1"));
    let accepted = runtime.message_status("m2").expect("status");
    assert_eq!(accepted.status_label(), "Accepted");
    assert_eq!(accepted.pacs002_code(), "ACSP");
    assert_eq!(accepted.transaction_hash(), Some("hash-1"));
    runtime.mark_transaction_applied("hash-1", SystemTime::now());
    let settled = runtime.message_status("m2").expect("status");
    assert_eq!(settled.pacs002_code(), "ACSC");
}
#[test]
fn memory_only_runtime_refuses_transaction_binding_before_queue_admission() {
    let mut config = sample_config();
    config.dedupe_ttl_secs = 0;
    let runtime = Iso20022BridgeRuntime::from_config(&config)
        .expect("cfg")
        .expect("enabled");
    assert!(runtime.check_and_record_message("queue-unknown"));
    assert!(!runtime.bind_transaction_hash("queue-unknown", "tx-queue-unknown"));
    let status = runtime.message_status("queue-unknown").expect("status");
    assert_eq!(status.status_label(), "Pending");
    assert_eq!(status.transaction_hash(), None);
    assert!(!runtime.tx_hash_index.contains_key("tx-queue-unknown"));
}
#[test]
fn unrepresentable_replay_expiry_refuses_admission_without_mutation() {
    for ttl_seconds in [u64::MAX, u64::MAX / 1000 + 1] {
        let mut config = sample_config();
        config.dedupe_ttl_secs = ttl_seconds;
        let runtime = Iso20022BridgeRuntime::from_config(&config)
            .expect("cfg")
            .expect("enabled");
        let metadata = IsoMessageMetadata::default();
        let parties = runtime.compatibility_test_parties(&metadata);
        assert_eq!(
            runtime.admit_inbound("overflowing-expiry", metadata, parties, false),
            Err(IsoAdmissionError::PersistenceUnavailable)
        );
        assert!(runtime.records.is_empty());
        assert!(runtime.replay_tombstones.is_empty());
        assert!(runtime.payload_hash_index.is_empty());
        assert!(runtime.business_message_id_index.is_empty());
        assert!(runtime.uetr_index.is_empty());
    }
    assert_eq!(system_time_from_ms(0), Some(SystemTime::UNIX_EPOCH));
    for millis in [1, 86_400_000, u64::MAX] {
        // A platform may have a narrower SystemTime; every representable value
        // must survive exact persistence without saturation or a panic.
        if let Some(time) = system_time_from_ms(millis) {
            assert_eq!(system_time_to_ms(time), millis);
        }
    }
}

#[test]
fn durable_prepared_transaction_survives_reload_and_pins_capacity() {
    let store = TempDir::new().expect("tempdir");
    let mut config = sample_config();
    config.dedupe_ttl_secs = 0;
    config.store_dir = Some(store.path().to_path_buf());
    config.store_max_records = 1;
    {
        let runtime = Iso20022BridgeRuntime::from_config(&config)
            .expect("cfg")
            .expect("enabled");
        assert!(runtime.check_and_record_message("durable-prepared"));
        assert!(runtime.bind_transaction_hash("durable-prepared", "tx-durable-prepared"));
        assert!(!runtime.check_and_record_message("capacity-must-fail-closed"));
    }
    let reloaded = Iso20022BridgeRuntime::from_config(&config)
        .expect("cfg")
        .expect("enabled");
    let status = reloaded
        .message_status("durable-prepared")
        .expect("original prepared transaction reloads");
    assert_eq!(status.transaction_hash(), Some("tx-durable-prepared"));
    assert_eq!(status.pacs002_code(), "ACTC");
    assert!(status.hold_reason_code().is_none());
    assert!(!reloaded.check_and_record_message("durable-prepared"));
    assert!(reloaded.mark_transaction_applied("tx-durable-prepared", SystemTime::now()));
    assert_eq!(
        reloaded
            .message_status("durable-prepared")
            .expect("reconciled status")
            .pacs002_code(),
        "ACSC"
    );
}
#[test]
fn status_history_encoded_byte_cap_accepts_exact_boundary() {
    let mut exact = IsoMessageRecordV2::pending(Instant::now());
    exact.status_history.clear();
    exact.state = IsoMessageState::Rejected;
    exact.updated_at = std::time::UNIX_EPOCH;
    exact.detail = Some(String::new());
    let empty_entry_bytes = status_history_entry_encoded_len(
        exact.state,
        exact.derived_status(),
        exact.updated_at,
        exact.detail.as_deref(),
        None,
    )
    .expect("fixed entry length");
    let detail_bytes = ISO_STATUS_HISTORY_MAX_ENCODED_BYTES_V1
        .checked_sub(2 + empty_entry_bytes)
        .expect("V1 byte cap exceeds fixed history syntax");
    exact.detail = Some("x".repeat(detail_bytes));
    assert!(exact.try_push_history().expect("exact byte cap must fit"));
    assert_eq!(
        status_history_encoded_len(&exact.status_history),
        Some(ISO_STATUS_HISTORY_MAX_ENCODED_BYTES_V1)
    );
    let canonical = norito::json::to_string(&JsonValue::Array(
        exact.status_history.iter().map(history_value).collect(),
    ))
    .expect("encode exact-bound history");
    assert_eq!(canonical.len(), ISO_STATUS_HISTORY_MAX_ENCODED_BYTES_V1);
    let mut overflow = IsoMessageRecordV2::pending(Instant::now());
    overflow.status_history.clear();
    overflow.state = IsoMessageState::Rejected;
    overflow.updated_at = std::time::UNIX_EPOCH;
    overflow.detail = Some("x".repeat(detail_bytes + 1));
    assert_eq!(
        overflow.try_push_history(),
        Err(IsoStatusHistoryLimitError::EncodedBytes)
    );
    assert!(overflow.status_history.is_empty());
}
#[test]
fn alternating_status_history_refuses_entry_overflow_before_memory_or_disk_mutation() {
    let mut record = IsoMessageRecordV2::pending(Instant::now());
    for index in 1..ISO_STATUS_HISTORY_MAX_ENTRIES_V1 {
        let accepted = index % 2 == 1;
        record
            .try_transition(|candidate| {
                candidate.updated_at = std::time::UNIX_EPOCH
                    + Duration::from_millis(u64::try_from(index).expect("index fits u64"));
                candidate.state = if accepted {
                    IsoMessageState::Accepted
                } else {
                    IsoMessageState::Rejected
                };
                candidate.ledger_tx_queued = accepted;
                candidate.detail = (!accepted).then(|| "alternating rejection".to_owned());
                candidate.rejection_reason_code = (!accepted).then(|| "RJCT".to_owned());
            })
            .expect("history below the entry cap must advance");
    }
    assert_eq!(
        record.status_history.len(),
        ISO_STATUS_HISTORY_MAX_ENTRIES_V1
    );
    let tx_hash = "bounded-alternating-tx";
    record.transaction_hash = Some(tx_hash.to_owned());
    let store = TempDir::new().expect("tempdir");
    let mut config = sample_config();
    config.store_dir = Some(store.path().to_path_buf());
    let runtime = Iso20022BridgeRuntime::from_config(&config)
        .expect("cfg")
        .expect("enabled");
    let message_id = "bounded-alternating-history";
    let metadata = inbound_metadata(message_id, "pacs.008");
    let parties = runtime.compatibility_test_parties(&metadata);
    runtime
        .admit_authenticated_inbound(message_id, metadata, parties)
        .expect("precommit replay identity");
    let admitted = runtime.records.get(message_id).expect("admitted record");
    record.metadata = admitted.metadata.clone();
    record.parties = admitted.parties.clone();
    record.replay_expires_at = admitted.replay_expires_at;
    drop(admitted);
    runtime.records.insert(message_id.to_owned(), record);
    runtime
        .tx_hash_index
        .insert(tx_hash.to_owned(), message_id.to_owned());
    runtime.persist_message(message_id);
    let path = store
        .path()
        .join("messages")
        .join(message_filename(message_id));
    let before = fs::read(&path).expect("read exact-bound persisted record");
    assert!(!runtime.mark_rejected(
        message_id,
        Some("capacity overflow rejection".to_owned()),
        Some("RJCT"),
    ));
    let after = fs::read(&path).expect("capacity refusal must retain persisted record");
    assert_eq!(after, before);
    let status = runtime
        .message_status(message_id)
        .expect("status remains present");
    assert_eq!(status.status_label(), "Accepted");
    assert_eq!(status.transaction_hash(), Some(tx_hash));
    assert_eq!(
        runtime
            .tx_hash_index
            .get(tx_hash)
            .as_deref()
            .map(String::as_str),
        Some(message_id),
        "capacity refusal must retain the transaction index"
    );
    assert_eq!(
        status.status_history().len(),
        ISO_STATUS_HISTORY_MAX_ENTRIES_V1
    );
    let reloaded = Iso20022BridgeRuntime::from_config(&config)
        .expect("reload cfg")
        .expect("reload enabled");
    assert_eq!(
        reloaded
            .message_status(message_id)
            .expect("exact-bound persisted history reloads")
            .status_history()
            .len(),
        ISO_STATUS_HISTORY_MAX_ENTRIES_V1
    );
}
#[test]
fn change_reason_encoded_byte_cap_accepts_exact_boundary() {
    let code_bytes = ISO_CHANGE_REASON_MAX_ENCODED_BYTES_V1
        .checked_sub(4)
        .expect("V1 byte cap exceeds array and string syntax");
    let mut exact = IsoMessageRecordV2::pending(Instant::now());
    exact
        .try_transition(|candidate| {
            candidate.change_reason_codes = vec!["x".repeat(code_bytes)];
        })
        .expect("exact change-reason byte cap must fit");
    assert_eq!(
        change_reason_codes_encoded_len(&exact.change_reason_codes),
        Some(ISO_CHANGE_REASON_MAX_ENCODED_BYTES_V1)
    );
    let canonical = norito::json::to_string(&JsonValue::Array(
        exact
            .change_reason_codes
            .iter()
            .map(|code| JsonValue::from(code.as_str()))
            .collect(),
    ))
    .expect("encode exact-bound change reasons");
    assert_eq!(canonical.len(), ISO_CHANGE_REASON_MAX_ENCODED_BYTES_V1);
    let mut overflow = IsoMessageRecordV2::pending(Instant::now());
    let before = persisted_record_json("change-reason-overflow", &overflow)
        .expect("encode pre-transition record");
    assert_eq!(
        overflow.try_transition(|candidate| {
            candidate.change_reason_codes = vec!["x".repeat(code_bytes + 1)];
        }),
        Err(IsoStatusHistoryLimitError::ChangeReasonEncodedBytes)
    );
    assert_eq!(
        persisted_record_json("change-reason-overflow", &overflow).expect("encode refused record"),
        before
    );
}
#[test]
fn unknown_lifecycle_codes_refuse_unique_growth_before_memory_or_disk_mutation() {
    let store = TempDir::new().expect("tempdir");
    let mut config = sample_config();
    config.store_dir = Some(store.path().to_path_buf());
    let runtime = Iso20022BridgeRuntime::from_config(&config)
        .expect("cfg")
        .expect("enabled");
    let message_id = "bounded-unknown-lifecycle-codes";
    let lifecycle_id = "bounded-unknown-lifecycle-codes-status";
    record_original(&runtime, message_id, "pacs.008");
    assert!(runtime.mark_queued(message_id));
    record_lifecycle(&runtime, lifecycle_id, "pacs.002");
    for index in 0..ISO_CHANGE_REASON_MAX_ENTRIES_V1 {
        let code = format!("U{index:03}");
        assert_eq!(
            runtime
                .apply_lifecycle_update(
                    lifecycle_id,
                    message_id,
                    "pacs.002",
                    Some(&code),
                    None,
                    None,
                )
                .expect("unique code below cap must apply"),
            "recorded_status_code"
        );
    }
    let status = runtime.message_status(message_id).expect("bounded status");
    assert_eq!(
        status.change_reason_codes().len(),
        ISO_CHANGE_REASON_MAX_ENTRIES_V1
    );
    assert_eq!(
        status.status_history().len(),
        3,
        "unknown codes after the first ACWC transition must not grow status history"
    );
    let path = store
        .path()
        .join("messages")
        .join(message_filename(message_id));
    let before = fs::read(&path).expect("read exact-bound persisted record");
    assert_eq!(
        runtime.apply_lifecycle_update(
            lifecycle_id,
            message_id,
            "pacs.002",
            Some("U_OVERFLOW"),
            None,
            None,
        ),
        Err(IsoStatusHistoryLimitError::ChangeReasonCount)
    );
    assert_eq!(
        fs::read(&path).expect("read record after capacity refusal"),
        before
    );
    assert_eq!(
        runtime
            .message_status(message_id)
            .expect("status survives refusal")
            .change_reason_codes()
            .len(),
        ISO_CHANGE_REASON_MAX_ENTRIES_V1
    );
    let reloaded = Iso20022BridgeRuntime::from_config(&config)
        .expect("reload cfg")
        .expect("reload enabled");
    assert_eq!(
        reloaded
            .message_status(message_id)
            .expect("exact-bound change reasons reload")
            .change_reason_codes()
            .len(),
        ISO_CHANGE_REASON_MAX_ENTRIES_V1
    );
}
#[test]
fn rejected_status_carries_reason() {
    let runtime = sample_runtime();
    assert!(runtime.check_and_record_message("m3"));
    runtime.mark_rejected("m3", Some("validation failed".to_string()), None);
    let status = runtime.message_status("m3").expect("status");
    assert_eq!(status.status_label(), "Rejected");
    assert_eq!(status.pacs002_code(), "RJCT");
    assert_eq!(status.detail(), Some("validation failed"));
    assert!(status.transaction_hash().is_none());
}
#[test]
fn message_context_is_preserved_in_status() {
    let runtime = sample_runtime();
    let message_id = "m_ctx";
    assert!(runtime.check_and_record_message(message_id));
    let context = IsoMessageContext {
        ledger_id: Some("ledger-A".to_string()),
        source_account_id: Some("sorauﾛ1NfｷgﾉﾓﾉBｦKﾌﾘﾒoﾇﾂﾛrG81ﾋjWﾎﾕVncwﾌSｱ3pﾘﾋﾉhUS9Q76".to_string()),
        ..IsoMessageContext::default()
    };
    runtime.update_message_context(message_id, context.clone());
    runtime.mark_accepted(message_id, "hash-ctx");
    let status = runtime.message_status(message_id).expect("status");
    assert_eq!(status.ledger_id(), Some("ledger-A"));
    assert_eq!(
        status.source_account_id(),
        Some("sorauﾛ1NfｷgﾉﾓﾉBｦKﾌﾘﾒoﾇﾂﾛrG81ﾋjWﾎﾕVncwﾌSｱ3pﾘﾋﾉhUS9Q76")
    );
    assert_eq!(status.transaction_hash(), Some("hash-ctx"));
}
#[test]
fn payment_outbox_xml_uses_durable_amount_currency_and_escapes_reasons() {
    let (runtime, _reference_file) = payment_runtime_with_bic_reference(sample_config());
    let msg = native_payment_message(
            "pacs.008",
            b"MsgId=m-outbox\nIntrBkSttlmAmt=10.25\nIntrBkSttlmCcy=USD\nIntrBkSttlmDt=2024-01-01\nDbtrAcct=GB82WEST12345698765432\nCdtrAcct=GB82WEST12345698765432\nDbtrAgt=DEUTDEFF\nCdtrAgt=DEUTDEFF",
        )
        .expect("parsed");
    let world = sample_world(None);
    let world_view = world.view();
    let chain_id: ChainId = "test-chain".parse().unwrap();
    let telemetry = MaybeTelemetry::for_tests();
    let (_tx, context) = runtime
        .build_pacs008_payload(
            &msg,
            &world_view,
            10_000,
            &chain_id,
            &crate::test_utils::signed_query_network_id(),
            &telemetry,
        )
        .expect("build");
    assert_eq!(context.settlement_amount(), Some("10.25"));
    assert_eq!(context.settlement_currency(), Some("USD"));
    assert!(runtime.check_and_record_message("m-outbox"));
    runtime.update_message_context("m-outbox", context);
    runtime.mark_rejected(
        "m-outbox",
        Some("return <detail> & audit".to_owned()),
        Some("PRTRY:RETURN<&>"),
    );
    let status = runtime.message_status("m-outbox").expect("status");
    let pacs004 = crate::iso_pacs004_xml(&status).expect("pacs.004 xml");
    assert!(pacs004.contains("<RtrdIntrBkSttlmAmt Ccy=\"USD\">10.25</RtrdIntrBkSttlmAmt>"));
    assert!(pacs004.contains("return &lt;detail&gt; &amp; audit"));
    assert!(!pacs004.contains("return <detail> & audit"));
    parse_message("pacs.004", pacs004.as_bytes()).expect("generated pacs.004 parses");
    let camt029 = crate::iso_camt029_xml(&status);
    assert!(camt029.contains("<Conf>CNCL</Conf>"));
    assert!(camt029.contains("RETURN&lt;&amp;&gt;"));
    parse_message("camt.029", camt029.as_bytes()).expect("generated camt.029 parses");
}
#[test]
fn pacs004_outbox_refuses_missing_settlement_amount_or_currency() {
    let runtime = sample_runtime();
    assert!(runtime.check_and_record_message("m-missing-amount"));
    runtime.update_message_context(
        "m-missing-amount",
        IsoMessageContext {
            settlement_currency: Some("USD".to_owned()),
            ..IsoMessageContext::default()
        },
    );
    runtime.mark_rejected("m-missing-amount", Some("return".to_owned()), Some("BE01"));
    let status = runtime.message_status("m-missing-amount").expect("status");
    let err = crate::iso_pacs004_xml(&status).expect_err("missing amount must fail");
    assert_outbox_error_contains(err, "settlement_amount");
    assert!(runtime.check_and_record_message("m-missing-currency"));
    runtime.update_message_context(
        "m-missing-currency",
        IsoMessageContext {
            settlement_amount: Some("10".to_owned()),
            ..IsoMessageContext::default()
        },
    );
    runtime.mark_rejected(
        "m-missing-currency",
        Some("return".to_owned()),
        Some("BE01"),
    );
    let status = runtime
        .message_status("m-missing-currency")
        .expect("status");
    let err = crate::iso_pacs004_xml(&status).expect_err("missing currency must fail");
    assert_outbox_error_contains(err, "settlement_currency");
}
#[test]
fn securities_outbox_xml_uses_sese023_context_and_settlement_state() {
    let runtime = sample_runtime();
    let parsed = parse_message(
            "sese.023",
            b"TxId=SETT-123\nSttlmDt=2025-11-12\nSttlmTpAndAddtlParams/SctiesMvmntTp=DELI\nSttlmTpAndAddtlParams/Pmt=APMT\nSctiesLeg/FinInstrmId=US0378331005\nSctiesLeg/Qty=42\nCashLeg/Amt=1234.56\nCashLeg/Ccy=USD\nDlvrgSttlmPties/Pty/Bic=DEUTDEFF\nDlvrgSttlmPties/Acct=DELIVER-1\nRcvgSttlmPties/Pty/Bic=MARKDEFF\nRcvgSttlmPties/Acct=RECEIVE-1\nPlan/ExecutionOrder=DELIVERY_THEN_PAYMENT\nPlan/Atomicity=ALL_OR_NOTHING",
        )
        .expect("parsed sese.023");
    let message_id =
        Iso20022BridgeRuntime::lifecycle_message_id("sese.023", &parsed).expect("message id");
    assert_eq!(message_id, "sese.023:SETT-123");
    assert!(runtime.check_and_record_message(&message_id));
    runtime
        .apply_inbound_lifecycle_message(&message_id, "sese.023", &parsed)
        .expect("record sese.023");
    let accepted = runtime
        .message_status(&message_id)
        .expect("accepted status");
    assert_eq!(accepted.settlement_amount(), Some("1234.56"));
    assert_eq!(accepted.settlement_quantity(), Some("42"));
    let accepted_status = crate::iso_sese024_xml(&accepted);
    assert!(accepted_status.contains("<TxId>SETT-123</TxId>"));
    assert!(accepted_status.contains("<Sts><Cd>ACCP</Cd></Sts>"));
    parse_message("sese.024", accepted_status.as_bytes())
        .expect("generated accepted sese.024 parses");
    runtime.mark_hold(&message_id, Some("NORE"));
    let pending = runtime.message_status(&message_id).expect("pending status");
    let pending_status = crate::iso_sese024_xml(&pending);
    assert!(pending_status.contains("<Sts><Cd>PEND</Cd></Sts>"));
    assert!(pending_status.contains("<Rsn><Cd>NORE</Cd></Rsn>"));
    parse_message("sese.024", pending_status.as_bytes())
        .expect("generated pending sese.024 parses");
    runtime.mark_settled(&message_id, SystemTime::now());
    let settled = runtime.message_status(&message_id).expect("settled status");
    let confirmation = crate::iso_sese025_xml(&settled).expect("sese.025 xml");
    assert!(confirmation.contains("<TxId>SETT-123</TxId>"));
    assert!(confirmation.contains("<SttlmAmt Ccy=\"USD\">1234.56</SttlmAmt>"));
    assert!(confirmation.contains("<Unit>42</Unit>"));
    assert!(confirmation.contains("<ExecutionOrder>DELIVERY_THEN_PAYMENT</ExecutionOrder>"));
    parse_message("sese.025", confirmation.as_bytes()).expect("generated sese.025 parses");
}
fn participant_message(
    message_type: &str,
    from: &str,
    to: &str,
    extra_fields: &str,
) -> ParsedMessage {
    // Authorization tests still enter through the current schema validator.
    let required = match message_type {
        "pacs.008" => {
            "IntrBkSttlmCcy=USD\nIntrBkSttlmAmt=10\nIntrBkSttlmDt=2026-01-01\nDbtrAcct=GB82WEST12345698765432\nCdtrAcct=GB33BUKB20201555555555\nDbtrAgt=DEUTDEFF\nCdtrAgt=MARKDEFF\n"
        }
        "pacs.004" => {
            "MsgId=participant-return\nCreDtTm=2026-01-01T00:00:00Z\nTxInf[0]/OrgnlInstrId=original\nTxInf[0]/RtrdInstdAmt=10\nTxInf[0]/RtrdInstdAmtCcy=USD\n"
        }
        "camt.056" => "Assgnmt/Id=participant-cancellation\nAssgnmt/CreDtTm=2026-01-01T00:00:00Z\n",
        "sese.023" => {
            "SttlmDt=2026-01-01\nSttlmTpAndAddtlParams/SctiesMvmntTp=DELI\nSttlmTpAndAddtlParams/Pmt=APMT\nSctiesLeg/FinInstrmId=US0378331005\nSctiesLeg/Qty=1\nCashLeg/Amt=10\nCashLeg/Ccy=USD\nDlvrgSttlmPties/Pty/Bic=DEUTDEFF\nDlvrgSttlmPties/Acct=DELIVER-1\nRcvgSttlmPties/Pty/Bic=MARKDEFF\nRcvgSttlmPties/Acct=RECEIVE-1\nPlan/ExecutionOrder=DELIVERY_THEN_PAYMENT\nPlan/Atomicity=ALL_OR_NOTHING\n"
        }
        "sese.025" => {
            "SttlmDt=2026-01-01\nSttlmTpAndAddtlParams/SctiesMvmntTp=DELI\nSttlmTpAndAddtlParams/Pmt=APMT\nSttlmQty=1\nSttlmAmt=10\nSttlmCcy=USD\nPlan/ExecutionOrder=DELIVERY_THEN_PAYMENT\nPlan/Atomicity=ALL_OR_NOTHING\n"
        }
        _ => "",
    };
    let fields = format!(
        "AppHdr/Fr/FIId/FinInstnId/BICFI={from}\n\
         AppHdr/To/FIId/FinInstnId/BICFI={to}\n\
         {required}\
         {extra_fields}"
    );
    parse_message(message_type, fields.as_bytes()).expect("participant message parses")
}

#[test]
fn participant_catalog_binds_initial_from_and_scopes_reads_to_both_parties() {
    let store = TempDir::new().expect("tempdir");
    let audit_admin = fixture_key_pair(0xAD);
    let other_party = fixture_key_pair(0xAE);
    let mut config = sample_config();
    config.store_dir = Some(store.path().to_path_buf());
    config.audit_admin_keys = vec![audit_admin.public_key().clone()];
    config.participants.push(actual::IsoBridgeParticipant {
        id: "other-bank".to_owned(),
        operator_keys: vec![other_party.public_key().clone()],
        financial_identifiers: vec!["OTHRDEFF".to_owned()],
        allowed_profiles: vec!["generic-iso20022".to_owned()],
        roles: vec!["originator".to_owned(), "counterparty".to_owned()],
    });
    let runtime = Iso20022BridgeRuntime::from_config(&config)
        .expect("valid participant config")
        .expect("enabled runtime");
    let originator = fixture_key_pair(0xAB);
    let counterparty = fixture_key_pair(0xAC);
    let parsed = participant_message(
        "pacs.008",
        "DEUTDEFF",
        "MARKDEFF",
        "MsgId=participant-payment",
    );
    let profile = runtime.default_profile();
    let parties = runtime
        .authorize_initial_submission(originator.public_key(), profile, &parsed)
        .expect("configured From owner");
    assert_eq!(parties.originator_participant_id, "originator-bank");
    assert_eq!(parties.counterparty_participant_id, "counterparty-bank");
    assert_eq!(
        runtime.authorize_initial_submission(counterparty.public_key(), profile, &parsed),
        Err(IsoAdmissionError::NotAuthorized)
    );
    let ambiguous_from = parse_message(
        "pacs.008",
        b"AppHdr/Fr/FIId/FinInstnId/BICFI=DEUTDEFF\nAppHdr/Fr/FIId/FinInstnId/LEI=5493001KJTIIGC8Y1R12\nAppHdr/To/FIId/FinInstnId/BICFI=MARKDEFF\nMsgId=ambiguous\nIntrBkSttlmCcy=USD\nIntrBkSttlmAmt=10\nIntrBkSttlmDt=2026-01-01\nDbtrAcct=GB82WEST12345698765432\nCdtrAcct=GB33BUKB20201555555555\nDbtrAgt=DEUTDEFF\nCdtrAgt=MARKDEFF",
    )
    .expect("ambiguous From parses");
    assert_eq!(
        runtime.authorize_initial_submission(originator.public_key(), profile, &ambiguous_from),
        Err(IsoAdmissionError::NotAuthorized)
    );
    assert_eq!(
        runtime.authorize_initial_submission(audit_admin.public_key(), profile, &parsed),
        Err(IsoAdmissionError::NotAuthorized)
    );
    runtime
        .admit_authenticated_inbound(
            "participant-payment",
            inbound_metadata("participant-payment", "pacs.008"),
            parties,
        )
        .expect("durable authenticated admission");
    let other_message =
        participant_message("pacs.008", "OTHRDEFF", "MARKDEFF", "MsgId=other-payment");
    let other_parties = runtime
        .authorize_initial_submission(other_party.public_key(), profile, &other_message)
        .expect("other participant owns its From identity");
    runtime
        .admit_authenticated_inbound(
            "other-payment",
            inbound_metadata("other-payment", "pacs.008"),
            other_parties,
        )
        .expect("second durable authenticated admission");
    assert!(
        runtime
            .authorized_message_status(originator.public_key(), "participant-payment")
            .is_some()
    );
    assert!(
        runtime
            .authorized_message_status(counterparty.public_key(), "participant-payment")
            .is_some()
    );
    assert!(
        runtime
            .authorized_message_status(audit_admin.public_key(), "participant-payment")
            .is_some()
    );
    assert!(
        runtime
            .authorized_message_status(other_party.public_key(), "participant-payment")
            .is_none()
    );
    assert!(
        runtime
            .authorized_message_status(fixture_key_pair(0xAF).public_key(), "participant-payment")
            .is_none()
    );

    let originator_audit = runtime
        .audit_index_for(originator.public_key())
        .expect("participant audit index");
    let counterparty_audit = runtime
        .audit_index_for(counterparty.public_key())
        .expect("shared counterparty audit index");
    let other_audit = runtime
        .audit_index_for(other_party.public_key())
        .expect("other participant audit index");
    let admin_audit = runtime
        .audit_index_for(audit_admin.public_key())
        .expect("audit admin global index");
    assert_eq!(originator_audit["record_count"].as_u64(), Some(1));
    assert_eq!(counterparty_audit["record_count"].as_u64(), Some(2));
    assert_eq!(other_audit["record_count"].as_u64(), Some(1));
    assert_eq!(admin_audit["record_count"].as_u64(), Some(2));
    assert!(
        runtime
            .audit_index_for(fixture_key_pair(0xAF).public_key())
            .is_none()
    );
}

#[test]
fn participant_catalog_rejects_legacy_unscoped_and_overlapping_admin_keys() {
    let mut unscoped = sample_config();
    unscoped.participants.clear();
    let error = runtime_config_error(&unscoped, "unscoped participant catalog must fail");
    assert!(
        error
            .to_string()
            .contains("legacy unscoped bridge configuration")
    );

    let mut overlapping = sample_config();
    overlapping.audit_admin_keys = vec![overlapping.participants[0].operator_keys[0].clone()];
    let error = runtime_config_error(&overlapping, "audit mutation key overlap must fail");
    assert!(
        error
            .to_string()
            .contains("must not also be a participant mutation key")
    );
}

#[test]
fn lifecycle_roles_reject_cross_party_updates() {
    let store = TempDir::new().expect("tempdir");
    let mut config = sample_config();
    config.store_dir = Some(store.path().to_path_buf());
    for participant in &mut config.participants {
        participant
            .allowed_profiles
            .push("swift-cbpr-plus".to_owned());
    }
    let runtime = Iso20022BridgeRuntime::from_config(&config)
        .expect("valid participant config")
        .expect("enabled runtime");
    let originator = fixture_key_pair(0xAB);
    let counterparty = fixture_key_pair(0xAC);
    let original = participant_message("pacs.008", "DEUTDEFF", "MARKDEFF", "MsgId=owned-payment");
    let profile = runtime.default_profile();
    let parties = runtime
        .authorize_initial_submission(originator.public_key(), profile, &original)
        .expect("originator owns From");
    runtime
        .admit_authenticated_inbound(
            "owned-payment",
            inbound_metadata("owned-payment", "pacs.008"),
            parties,
        )
        .expect("original admitted");
    let lifecycle = participant_message(
        "pacs.002",
        "MARKDEFF",
        "DEUTDEFF",
        "BizMsgIdr=status-1\nOrgnlMsgId=owned-payment\nTxSts=ACSC",
    );
    assert_eq!(
        runtime.authorize_lifecycle_submission(
            originator.public_key(),
            profile,
            "pacs.002",
            &lifecycle,
        ),
        Err(IsoAdmissionError::NotAuthorized)
    );
    let lifecycle_parties = runtime
        .authorize_lifecycle_submission(counterparty.public_key(), profile, "pacs.002", &lifecycle)
        .expect("original counterparty owns pacs.002");
    assert_eq!(
        lifecycle_parties.parties().admitting_participant_id,
        "counterparty-bank"
    );
    for (label, malformed) in [
        (
            "missing From",
            parse_message(
                "pacs.002",
                b"AppHdr/To/FIId/FinInstnId/BICFI=DEUTDEFF\nBizMsgIdr=status-missing-from\nOrgnlMsgId=owned-payment\nTxSts=ACSC",
            )
            .expect("missing-From lifecycle parses"),
        ),
        (
            "missing To",
            parse_message(
                "pacs.002",
                b"AppHdr/Fr/FIId/FinInstnId/BICFI=MARKDEFF\nBizMsgIdr=status-missing-to\nOrgnlMsgId=owned-payment\nTxSts=ACSC",
            )
            .expect("missing-To lifecycle parses"),
        ),
        (
            "wrong To",
            participant_message(
                "pacs.002",
                "MARKDEFF",
                "MARKDEFF",
                "BizMsgIdr=status-wrong-to\nOrgnlMsgId=owned-payment\nTxSts=ACSC",
            ),
        ),
    ] {
        assert_eq!(
            runtime.authorize_lifecycle_submission(
                counterparty.public_key(),
                profile,
                "pacs.002",
                &malformed,
            ),
            Err(IsoAdmissionError::NotAuthorized),
            "{label} must not be accepted",
        );
    }
    let downgraded_profile = runtime
        .resolve_profile(Some("swift-cbpr-plus"))
        .expect("built-in SWIFT profile");
    assert_eq!(
        runtime.authorize_lifecycle_submission(
            counterparty.public_key(),
            downgraded_profile,
            "pacs.002",
            &lifecycle,
        ),
        Err(IsoAdmissionError::NotAuthorized)
    );
    let cancellation = participant_message(
        "camt.056",
        "DEUTDEFF",
        "MARKDEFF",
        "BizMsgIdr=cancel-1\nUndrlyg/TxInf/OrgnlGrpInf/OrgnlMsgId=owned-payment",
    );
    runtime
        .authorize_lifecycle_submission(originator.public_key(), profile, "camt.056", &cancellation)
        .expect("original originator owns camt.056");
    assert_eq!(
        runtime.authorize_lifecycle_submission(
            counterparty.public_key(),
            profile,
            "camt.056",
            &cancellation,
        ),
        Err(IsoAdmissionError::NotAuthorized)
    );
}

#[test]
fn lifecycle_apply_rejects_original_pruned_after_authorization() {
    let store = TempDir::new().expect("tempdir");
    let mut config = sample_config();
    config.store_dir = Some(store.path().to_path_buf());
    config.store_retention_secs = 3_600;
    let runtime = Iso20022BridgeRuntime::from_config(&config)
        .expect("valid participant config")
        .expect("enabled runtime");
    let originator = fixture_key_pair(0xAB);
    let counterparty = fixture_key_pair(0xAC);
    let profile = runtime.default_profile();

    let original = participant_message(
        "pacs.008",
        "DEUTDEFF",
        "MARKDEFF",
        "MsgId=expiry-boundary-original",
    );
    let original_parties = runtime
        .authorize_initial_submission(originator.public_key(), profile, &original)
        .expect("originator owns original");
    runtime
        .admit_authenticated_inbound(
            "expiry-boundary-original",
            inbound_metadata("expiry-boundary-original", "pacs.008"),
            original_parties,
        )
        .expect("original admitted");
    runtime.mark_accepted("expiry-boundary-original", "tx-expiry-boundary");
    assert!(runtime.mark_settled("expiry-boundary-original", SystemTime::now()));
    assert!(runtime.lifecycle_reference_is_live_at("expiry-boundary-original", SystemTime::now(),));

    let lifecycle = participant_message(
        "pacs.004",
        "MARKDEFF",
        "DEUTDEFF",
        "BizMsgIdr=expiry-boundary-return\n\
         OrgnlGrpInf/OrgnlMsgId=expiry-boundary-original",
    );
    let lifecycle_parties = runtime
        .authorize_lifecycle_submission(counterparty.public_key(), profile, "pacs.004", &lifecycle)
        .expect("counterparty is authorized before the original expires");
    runtime
        .records
        .get_mut("expiry-boundary-original")
        .expect("original remains before retention pruning")
        .updated_at = SystemTime::UNIX_EPOCH;
    assert!(
        !runtime.lifecycle_reference_is_live_at("expiry-boundary-original", SystemTime::now(),)
    );

    let lifecycle_metadata = inbound_metadata("expiry-boundary-return", "pacs.004");
    runtime
        .admit_authenticated_inbound(
            "expiry-boundary-return",
            lifecycle_metadata.clone(),
            lifecycle_parties.parties().clone(),
        )
        .expect("lifecycle identity admitted after retention pruning");
    assert!(
        runtime.message_status("expiry-boundary-original").is_none(),
        "admission must reproduce the retention-pruning side of the race"
    );

    let error = runtime
        .apply_inbound_lifecycle_message_with_evidence(
            "expiry-boundary-return",
            "pacs.004",
            &lifecycle,
            &lifecycle_parties,
            None,
        )
        .expect_err("a lifecycle message must not be accepted without its original");
    assert!(matches!(
        error,
        IsoLifecycleApplyError::Validation(MsgError::ValidationFailed)
    ));
    assert_eq!(
        runtime
            .message_status("expiry-boundary-return")
            .expect("failed lifecycle identity remains reserved")
            .status_label(),
        "Pending"
    );
    assert!(runtime.mark_rejected("expiry-boundary-return", Some(error.to_string()), None,));
    assert_eq!(
        runtime.admit_authenticated_inbound(
            "expiry-boundary-return",
            lifecycle_metadata,
            lifecycle_parties.parties().clone(),
        ),
        Err(IsoAdmissionError::Duplicate),
        "rejection must retain lifecycle replay protection"
    );
}

#[test]
fn lifecycle_authorization_rejects_prune_readmit_aba_and_old_settlement_hash() {
    let store = TempDir::new().expect("tempdir");
    let mut config = sample_config();
    config.store_dir = Some(store.path().to_path_buf());
    config.store_retention_secs = 3_600;
    // Keep the original identity live until this test deliberately expires both
    // the record and its tombstone; a zero TTL may prune it during settlement.
    config.dedupe_ttl_secs = 3_600;
    let runtime = Iso20022BridgeRuntime::from_config(&config)
        .expect("valid participant config")
        .expect("enabled runtime");
    let originator = fixture_key_pair(0xAB);
    let counterparty = fixture_key_pair(0xAC);
    let profile = runtime.default_profile();
    let original = participant_message("pacs.008", "DEUTDEFF", "MARKDEFF", "MsgId=aba-original");
    let original_parties = runtime
        .authorize_initial_submission(originator.public_key(), profile, &original)
        .expect("originator owns original");
    runtime
        .admit_authenticated_inbound(
            "aba-original",
            inbound_metadata("aba-original-v1", "pacs.008"),
            original_parties,
        )
        .expect("first incarnation admitted");
    runtime.mark_accepted("aba-original", "tx-aba-original-v1");
    assert!(runtime.mark_settled("aba-original", SystemTime::now()));

    let lifecycle = participant_message(
        "pacs.002",
        "MARKDEFF",
        "DEUTDEFF",
        "BizMsgIdr=aba-status\nOrgnlMsgId=aba-original\nTxSts=ACSC",
    );
    let authorization = runtime
        .authorize_lifecycle_submission(counterparty.public_key(), profile, "pacs.002", &lifecycle)
        .expect("counterparty authorized against first incarnation");
    {
        let mut record = runtime
            .records
            .get_mut("aba-original")
            .expect("first incarnation remains");
        record.updated_at = SystemTime::UNIX_EPOCH;
        record.replay_expires_at = SystemTime::UNIX_EPOCH;
    }
    runtime
        .replay_tombstones
        .get_mut("aba-original")
        .expect("first incarnation tombstone")
        .expires_at = SystemTime::UNIX_EPOCH;
    runtime
        .admit_authenticated_inbound(
            "aba-status",
            inbound_metadata("aba-status", "pacs.002"),
            authorization.parties().clone(),
        )
        .expect("lifecycle admission prunes the expired first incarnation");
    assert!(!runtime.records.contains_key("aba-original"));

    let replacement_parties = runtime
        .authorize_initial_submission(originator.public_key(), profile, &original)
        .expect("same external identifier may be readmitted after expiry");
    runtime
        .admit_authenticated_inbound(
            "aba-original",
            inbound_metadata("aba-original-v2", "pacs.008"),
            replacement_parties,
        )
        .expect("replacement incarnation admitted");
    runtime.mark_accepted("aba-original", "tx-aba-original-v2");

    let error = runtime
        .apply_inbound_lifecycle_message_with_evidence(
            "aba-status",
            "pacs.002",
            &lifecycle,
            &authorization,
            Some(IsoSuccessfulExecution {
                transaction_hash: "tx-aba-original-v1",
                settled_at: SystemTime::UNIX_EPOCH + Duration::from_secs(123),
            }),
        )
        .expect_err("authorization and evidence for the old incarnation must fail closed");
    assert!(matches!(
        error,
        IsoLifecycleApplyError::Validation(MsgError::ValidationFailed)
    ));
    let replacement = runtime
        .message_status("aba-original")
        .expect("replacement remains untouched");
    assert_eq!(replacement.transaction_hash(), Some("tx-aba-original-v2"));
    assert_ne!(replacement.pacs002_code(), "ACSC");
}

#[test]
fn counterparty_owns_every_return_and_securities_lifecycle_message() {
    let store = TempDir::new().expect("tempdir");
    let mut config = sample_config();
    config.store_dir = Some(store.path().to_path_buf());
    let runtime = Iso20022BridgeRuntime::from_config(&config)
        .expect("valid participant config")
        .expect("enabled runtime");
    let originator = fixture_key_pair(0xAB);
    let counterparty = fixture_key_pair(0xAC);
    let profile = runtime.default_profile();

    let payment = participant_message(
        "pacs.008",
        "DEUTDEFF",
        "MARKDEFF",
        "MsgId=return-role-payment",
    );
    let payment_parties = runtime
        .authorize_initial_submission(originator.public_key(), profile, &payment)
        .expect("originator owns payment From identity");
    runtime
        .admit_authenticated_inbound(
            "return-role-payment",
            inbound_metadata("return-role-payment", "pacs.008"),
            payment_parties,
        )
        .expect("payment original admitted");
    let payment_return = participant_message(
        "pacs.004",
        "MARKDEFF",
        "DEUTDEFF",
        "BizMsgIdr=return-role-1\nOrgnlGrpInf/OrgnlMsgId=return-role-payment",
    );
    assert_eq!(
        runtime.authorize_lifecycle_submission(
            originator.public_key(),
            profile,
            "pacs.004",
            &payment_return,
        ),
        Err(IsoAdmissionError::NotAuthorized)
    );
    let admitted_return = runtime
        .authorize_lifecycle_submission(
            counterparty.public_key(),
            profile,
            "pacs.004",
            &payment_return,
        )
        .expect("original counterparty owns pacs.004");
    assert_eq!(
        admitted_return.parties().admitting_participant_id,
        "counterparty-bank"
    );

    let securities = participant_message(
        "sese.023",
        "DEUTDEFF",
        "MARKDEFF",
        "TxId=securities-role-trade",
    );
    let securities_parties = runtime
        .authorize_initial_submission(originator.public_key(), profile, &securities)
        .expect("originator owns securities From identity");
    runtime
        .admit_authenticated_inbound(
            "sese.023:securities-role-trade",
            inbound_metadata("sese.023:securities-role-trade", "sese.023"),
            securities_parties,
        )
        .expect("securities original admitted");
    for (message_type, lifecycle) in [
        (
            "sese.024",
            participant_message(
                "sese.024",
                "MARKDEFF",
                "DEUTDEFF",
                "BizMsgIdr=securities-status-1\nTxId=securities-role-trade\nSttlmSts=ACCP",
            ),
        ),
        (
            "sese.025",
            participant_message(
                "sese.025",
                "MARKDEFF",
                "DEUTDEFF",
                "BizMsgIdr=securities-confirmation-1\nTxId=securities-role-trade\nConfSts=ACCP",
            ),
        ),
    ] {
        assert_eq!(
            runtime.authorize_lifecycle_submission(
                originator.public_key(),
                profile,
                message_type,
                &lifecycle,
            ),
            Err(IsoAdmissionError::NotAuthorized),
            "originator must not submit {message_type}"
        );
        let admitted = runtime
            .authorize_lifecycle_submission(
                counterparty.public_key(),
                profile,
                message_type,
                &lifecycle,
            )
            .unwrap_or_else(|error| panic!("counterparty must own {message_type}: {error:?}"));
        assert_eq!(
            admitted.parties().admitting_participant_id,
            "counterparty-bank"
        );
    }
}

#[test]
fn settling_pacs002_requires_successful_transaction_evidence() {
    let runtime = sample_runtime();
    record_original(&runtime, "settlement-evidence", "pacs.008");
    runtime.mark_accepted("settlement-evidence", "tx-settlement-evidence");
    let lifecycle_id = "settlement-evidence-status";
    assert!(
        runtime.check_and_record_inbound(lifecycle_id, inbound_metadata(lifecycle_id, "pacs.002"))
    );
    let lifecycle = parse_message(
        "pacs.002",
        b"BizMsgIdr=settlement-evidence-status\nOrgnlMsgId=settlement-evidence\nTxSts=ACSC",
    )
    .expect("pacs.002 parses");
    let authorization = runtime
        .compatibility_lifecycle_authorization("pacs.002", &lifecycle)
        .expect("bind exact original");
    assert!(
        runtime
            .apply_inbound_lifecycle_message_with_evidence(
                lifecycle_id,
                "pacs.002",
                &lifecycle,
                &authorization,
                None,
            )
            .is_err()
    );
    assert_ne!(
        runtime
            .message_status("settlement-evidence")
            .expect("original remains")
            .pacs002_code(),
        "ACSC"
    );
    assert!(
        runtime
            .apply_inbound_lifecycle_message_with_evidence(
                lifecycle_id,
                "pacs.002",
                &lifecycle,
                &authorization,
                Some(IsoSuccessfulExecution {
                    transaction_hash: "tx-from-another-record",
                    settled_at: SystemTime::UNIX_EPOCH + Duration::from_secs(123),
                }),
            )
            .is_err(),
        "an unrelated committed hash must not authorize settlement"
    );
    runtime
        .apply_inbound_lifecycle_message_with_evidence(
            lifecycle_id,
            "pacs.002",
            &lifecycle,
            &authorization,
            Some(IsoSuccessfulExecution {
                transaction_hash: "tx-settlement-evidence",
                settled_at: SystemTime::UNIX_EPOCH + Duration::from_secs(123),
            }),
        )
        .expect("committed evidence permits settlement transition");
    assert_eq!(
        runtime
            .message_status("settlement-evidence")
            .expect("original settles")
            .pacs002_code(),
        "ACSC"
    );
}

#[test]
fn unexpired_replay_tombstone_survives_detail_pruning_and_restart() {
    let store = TempDir::new().expect("tempdir");
    let mut config = sample_config();
    config.store_dir = Some(store.path().to_path_buf());
    config.store_retention_secs = 1;
    config.dedupe_ttl_secs = 3_600;
    let runtime = Iso20022BridgeRuntime::from_config(&config)
        .expect("runtime")
        .expect("enabled");
    let metadata = inbound_metadata("durable-replay", "pacs.008");
    assert!(runtime.check_and_record_inbound("durable-replay", metadata.clone()));
    runtime.mark_accepted("durable-replay", "tx-durable-replay");
    runtime.mark_settled("durable-replay", SystemTime::now());
    runtime
        .records
        .get_mut("durable-replay")
        .expect("rich record")
        .updated_at = SystemTime::UNIX_EPOCH;
    runtime.compact_persisted_records();
    assert!(!runtime.records.contains_key("durable-replay"));
    assert!(runtime.replay_tombstones.contains_key("durable-replay"));
    drop(runtime);
    let reloaded = Iso20022BridgeRuntime::from_config(&config)
        .expect("restart loads tombstone")
        .expect("enabled");
    assert!(!reloaded.check_and_record_inbound("durable-replay", metadata));
}

#[test]
fn protected_replay_capacity_fails_closed_without_mutation() {
    let store = TempDir::new().expect("tempdir");
    let mut config = sample_config();
    config.store_dir = Some(store.path().to_path_buf());
    config.store_max_records = 1;
    let runtime = Iso20022BridgeRuntime::from_config(&config)
        .expect("runtime")
        .expect("enabled");
    let first = runtime.compatibility_test_parties(&inbound_metadata("one", "pacs.008"));
    runtime
        .admit_authenticated_inbound("one", inbound_metadata("one", "pacs.008"), first)
        .expect("first admission");
    let second = runtime.compatibility_test_parties(&inbound_metadata("two", "pacs.008"));
    assert_eq!(
        runtime.admit_authenticated_inbound("two", inbound_metadata("two", "pacs.008"), second,),
        Err(IsoAdmissionError::ProtectedCapacity)
    );
    assert!(!runtime.records.contains_key("two"));
}

#[test]
fn detail_persistence_failure_keeps_the_precommitted_replay_tombstone() {
    let store = TempDir::new().expect("tempdir");
    let mut config = sample_config();
    config.store_dir = Some(store.path().to_path_buf());
    let runtime = Iso20022BridgeRuntime::from_config(&config)
        .expect("runtime")
        .expect("enabled");
    let messages = store.path().join("messages");
    let messages_backup = store.path().join("messages-backup");
    fs::rename(&messages, &messages_backup).expect("move initialized message directory");
    fs::write(&messages, b"block rich-record persistence").expect("write rich-record blocker");
    let metadata = inbound_metadata("precommitted-replay", "pacs.008");
    let parties = runtime.compatibility_test_parties(&metadata);
    assert_eq!(
        runtime.admit_authenticated_inbound("precommitted-replay", metadata.clone(), parties,),
        Err(IsoAdmissionError::PersistenceUnavailable)
    );
    assert!(!runtime.records.contains_key("precommitted-replay"));
    assert!(
        runtime
            .replay_tombstones
            .contains_key("precommitted-replay")
    );
    drop(runtime);
    fs::remove_file(&messages).expect("remove rich-record blocker");
    fs::rename(messages_backup, messages).expect("restore initialized message directory");

    let reloaded = Iso20022BridgeRuntime::from_config(&config)
        .expect("restart loads precommitted tombstone")
        .expect("enabled");
    let parties = reloaded.compatibility_test_parties(&metadata);
    assert_eq!(
        reloaded.admit_authenticated_inbound("precommitted-replay", metadata, parties),
        Err(IsoAdmissionError::Duplicate)
    );
}

#[test]
fn outbound_document_signature_covers_exact_xml_bytes() {
    let runtime = sample_runtime();
    let signed = runtime
        .sign_outbound_document("<Document>status</Document>".to_owned())
        .expect("outbound signature");
    let public_key = PublicKey::from_str(&signed.public_key).expect("canonical signer key");
    let signature = Signature::from_bytes(
        &BASE64_STANDARD
            .decode(signed.signature)
            .expect("base64 signature"),
    );
    let mut payload = b"iroha.iso20022.outbound.v2\0".to_vec();
    payload.extend_from_slice(signed.xml.as_bytes());
    signature
        .verify(&public_key, &payload)
        .expect("signature verifies exact XML");
    payload.push(b'!');
    assert!(signature.verify(&public_key, &payload).is_err());
}

#[test]
fn legacy_iso_record_store_fails_fast_with_schema_incompatibility() {
    let store = TempDir::new().expect("tempdir");
    let messages = store.path().join("messages");
    fs::create_dir_all(&messages).expect("messages directory");
    fs::write(
        messages.join(message_filename("legacy-record")),
        r#"{"version":1,"message_id":"legacy-record"}"#,
    )
    .expect("legacy record fixture");
    let mut config = sample_config();
    config.store_dir = Some(store.path().to_path_buf());
    let error = match Iso20022BridgeRuntime::from_config(&config) {
        Ok(_) => panic!("legacy store must not be accepted"),
        Err(error) => error,
    };
    assert!(
        error
            .to_string()
            .contains("incompatible ISO bridge store record schema version 1")
    );
}

#[test]
fn persisted_record_rejects_same_id_profile_policy_drift_on_restart() {
    let store = TempDir::new().expect("tempdir");
    let mut profile = live_message_profile("pacs.008", "pacs.008");
    profile.id = "generic-iso20022".to_owned();
    let mut config = sample_config();
    config.store_dir = Some(store.path().to_path_buf());
    config.profiles = vec![profile];
    {
        let runtime = Iso20022BridgeRuntime::from_config(&config)
            .expect("profile override")
            .expect("enabled");
        assert!(runtime.check_and_record_inbound(
            "profile-policy-pinned",
            inbound_metadata("profile-policy-pinned", "pacs.008"),
        ));
        let status = runtime
            .message_status("profile-policy-pinned")
            .expect("pinned record");
        assert!(is_canonical_sha256_hex(
            status.pinned_profile_policy_sha256()
        ));
    }

    // Keep the stable profile id and coarse signature label unchanged while weakening one
    // message constraint. V3 records bind the whole policy and must stop this restart.
    config.profiles[0].message_profiles[0].require_uetr = true;
    let error = runtime_config_error(
        &config,
        "same-id profile policy drift must not reinterpret persisted records",
    );
    assert!(
        error.to_string().contains("full profile policy absent"),
        "unexpected policy hard-cut error: {error:?}"
    );
}

#[test]
fn profile_policy_digest_covers_every_security_and_message_constraint() {
    let base = profiles::default_profile("generic-iso20022").expect("default profile");
    let mutations: &[(&str, fn(&mut TradfiRailProfile))] = &[
        ("id", |profile| profile.id.push_str("-changed")),
        ("rail", |profile| profile.rail = TradfiRail::SwiftCbprPlus),
        ("embedded signature policy", |profile| {
            profile.embedded_signature_policy = EmbeddedSignaturePolicy::RequireVerified;
        }),
        ("public-key pins", |profile| {
            profile
                .signature_public_key_sha256_pins
                .push("11".repeat(32));
        }),
        ("trust-anchor pins", |profile| {
            profile.x509_trust_anchor_sha256_pins.push("22".repeat(32));
        }),
        ("certificate policy OIDs", |profile| {
            profile
                .x509_required_certificate_policy_oids
                .push("1.2.3.4".to_owned());
        }),
        ("CRL requirement", |profile| {
            profile.x509_require_crl_revocation_check = !profile.x509_require_crl_revocation_check;
        }),
        ("CRL material", |profile| {
            profile.x509_crl_der_base64.push("AA==".to_owned());
        }),
        ("OCSP requirement", |profile| {
            profile.x509_require_ocsp_revocation_check =
                !profile.x509_require_ocsp_revocation_check;
        }),
        ("OCSP material", |profile| {
            profile
                .x509_ocsp_response_der_base64
                .push("AA==".to_owned());
        }),
        ("revoked certificates", |profile| {
            profile.revoked_certificate_sha256.push("33".repeat(32));
        }),
        ("reference datasets", |profile| {
            if profile
                .required_reference_datasets
                .contains(&ReferenceDatasetRequirement::BicLei)
            {
                profile
                    .required_reference_datasets
                    .retain(|item| *item != ReferenceDatasetRequirement::BicLei);
            } else {
                profile
                    .required_reference_datasets
                    .push(ReferenceDatasetRequirement::BicLei);
            }
        }),
        ("message type", |profile| {
            profile.message_profiles[0]
                .message_type
                .push_str(".changed");
        }),
        ("message direction", |profile| {
            profile.message_profiles[0].direction = MessageDirection::FollowUp;
        }),
        ("message versions", |profile| {
            profile.message_profiles[0]
                .versions
                .push("changed.version".to_owned());
        }),
        ("business services", |profile| {
            profile.message_profiles[0]
                .business_services
                .push("changed.service".to_owned());
        }),
        ("application header requirement", |profile| {
            profile.message_profiles[0].require_app_header =
                !profile.message_profiles[0].require_app_header;
        }),
        ("business service requirement", |profile| {
            profile.message_profiles[0].require_business_service =
                !profile.message_profiles[0].require_business_service;
        }),
        ("UETR requirement", |profile| {
            profile.message_profiles[0].require_uetr = !profile.message_profiles[0].require_uetr;
        }),
        ("address mode", |profile| {
            profile.message_profiles[0].structured_address_mode =
                StructuredAddressMode::ForbidUnstructured;
        }),
        ("supplementary data limit", |profile| {
            profile.message_profiles[0].supplementary_data_max_bytes += 1;
        }),
        ("currency precision", |profile| {
            profile.message_profiles[0]
                .amount_minor_units
                .insert("ZZZ".to_owned(), 4);
        }),
    ];
    let base_digest = profile_policy_sha256(&base);
    for (label, mutate) in mutations {
        let mut candidate = base.clone();
        mutate(&mut candidate);
        assert_ne!(
            profile_policy_sha256(&candidate),
            base_digest,
            "{label} must be part of the pinned profile policy"
        );
    }
}

#[test]
fn conflicting_v2_replay_and_transaction_identities_stop_startup() {
    let transaction_store = TempDir::new().expect("transaction store");
    let mut transaction_config = sample_config();
    transaction_config.store_dir = Some(transaction_store.path().to_path_buf());
    {
        let runtime = Iso20022BridgeRuntime::from_config(&transaction_config)
            .expect("cfg")
            .expect("enabled");
        for message_id in ["tx-owner-a", "tx-owner-b"] {
            assert!(runtime.check_and_record_inbound(
                message_id,
                IsoMessageMetadata::inbound(
                    "generic-iso20022",
                    "pacs.008",
                    None,
                    Some(format!("{message_id}-biz")),
                    None,
                    format!("{message_id}-hash"),
                    "snapshot".to_owned(),
                    false,
                ),
            ));
            runtime.mark_accepted(message_id, &format!("{message_id}-transaction"));
        }
    }
    rewrite_persisted_record(
        &transaction_store
            .path()
            .join("messages")
            .join(message_filename("tx-owner-b")),
        |object| {
            object.insert(
                "transaction_hash".to_owned(),
                JsonValue::from("tx-owner-a-transaction"),
            );
        },
    );
    let error = runtime_config_error(
        &transaction_config,
        "conflicting ISO transaction identities must stop startup",
    );
    assert!(
        error
            .to_string()
            .contains("conflicting transaction identities"),
        "unexpected transaction hard-cut error: {error:?}"
    );

    let replay_store = TempDir::new().expect("replay store");
    let mut replay_config = sample_config();
    replay_config.store_dir = Some(replay_store.path().to_path_buf());
    {
        let runtime = Iso20022BridgeRuntime::from_config(&replay_config)
            .expect("cfg")
            .expect("enabled");
        for message_id in ["replay-owner-a", "replay-owner-b"] {
            assert!(runtime.check_and_record_inbound(
                message_id,
                IsoMessageMetadata::inbound(
                    "generic-iso20022",
                    "pacs.008",
                    None,
                    Some(format!("{message_id}-biz")),
                    None,
                    format!("{message_id}-hash"),
                    "snapshot".to_owned(),
                    false,
                ),
            ));
        }
    }
    rewrite_persisted_record(
        &replay_store
            .path()
            .join("messages")
            .join(message_filename("replay-owner-b")),
        |object| {
            object
                .get_mut("metadata")
                .and_then(JsonValue::as_object_mut)
                .expect("metadata object")
                .insert(
                    "payload_hash".to_owned(),
                    JsonValue::from("replay-owner-a-hash"),
                );
        },
    );
    rewrite_persisted_tombstone(&replay_store, "replay-owner-b", |object| {
        object.insert(
            "payload_hash".to_owned(),
            JsonValue::from("replay-owner-a-hash"),
        );
    });
    let error = runtime_config_error(
        &replay_config,
        "conflicting ISO replay identities must stop startup",
    );
    assert!(
        error
            .to_string()
            .contains("conflicting immutable identities"),
        "unexpected replay hard-cut error: {error:?}"
    );
}

#[test]
fn unversioned_or_malformed_iso_record_store_stops_startup() {
    for (name, contents, expected) in [
        (
            "missing-version",
            r#"{"message_id":"missing-version"}"#,
            "does not advertise numeric schema version V3",
        ),
        (
            "string-version",
            r#"{"version":"3","message_id":"string-version"}"#,
            "does not advertise numeric schema version V3",
        ),
        ("invalid-json", "{", "is not valid JSON"),
        (
            "incomplete-v3",
            r#"{"version":3,"message_id":"incomplete-v3"}"#,
            "is invalid or corrupt for schema V3",
        ),
    ] {
        let store = TempDir::new().expect("tempdir");
        let messages = store.path().join("messages");
        fs::create_dir_all(&messages).expect("messages directory");
        fs::write(messages.join(message_filename(name)), contents).expect("record fixture");
        let mut config = sample_config();
        config.store_dir = Some(store.path().to_path_buf());
        let error = runtime_config_error(&config, "malformed ISO stores must stop startup");
        assert!(
            error.to_string().contains(expected),
            "unexpected hard-cut error for {name}: {error:?}"
        );
    }
}

#[test]
fn persisted_iso_records_regenerate_a_missing_v3_audit_index() {
    let store = TempDir::new().expect("tempdir");
    let mut config = sample_config();
    config.store_dir = Some(store.path().to_path_buf());
    {
        let runtime = Iso20022BridgeRuntime::from_config(&config)
            .expect("cfg")
            .expect("enabled");
        assert!(runtime.check_and_record_inbound(
            "audit-required",
            IsoMessageMetadata::inbound(
                "generic-iso20022",
                "pacs.008",
                None,
                Some("audit-required-biz".to_owned()),
                None,
                "audit-required-hash".to_owned(),
                "snapshot".to_owned(),
                false,
            ),
        ));
    }
    fs::remove_file(
        store
            .path()
            .join(ISO_PERSISTED_AUDIT_DIR)
            .join(ISO_PERSISTED_AUDIT_INDEX_FILE),
    )
    .expect("remove audit index");
    let reloaded = Iso20022BridgeRuntime::from_config(&config)
        .expect("missing derived audit index is recoverable")
        .expect("enabled");
    assert!(reloaded.message_status("audit-required").is_some());
    let regenerated = read_audit_index(&store);
    let object = regenerated.as_object().expect("audit index object");
    assert!(persisted_audit_index_digest_matches(object));
    assert_eq!(
        object.get("record_count").and_then(JsonValue::as_u64),
        Some(1)
    );
}

#[test]
fn malformed_or_unversioned_iso_audit_index_stops_startup() {
    for (name, contents, expected) in [
        ("invalid-json", "{", "is not valid JSON"),
        (
            "missing-version",
            r#"{"record_count":0,"records":[],"index_sha256":"00"}"#,
            "does not advertise numeric schema version V3",
        ),
        (
            "string-version",
            r#"{"version":"3","record_count":0,"records":[],"index_sha256":"00"}"#,
            "does not advertise numeric schema version V3",
        ),
        (
            "legacy-version",
            r#"{"version":1,"record_count":0,"records":[],"index_sha256":"00"}"#,
            "incompatible ISO bridge audit index schema version 1",
        ),
        (
            "invalid-current-schema",
            r#"{"version":3,"record_count":0,"records":[],"index_sha256":"00"}"#,
            "is invalid or corrupt for schema V3",
        ),
    ] {
        let store = TempDir::new().expect("tempdir");
        let audit_dir = store.path().join(ISO_PERSISTED_AUDIT_DIR);
        fs::create_dir_all(&audit_dir).expect("audit directory");
        fs::write(audit_dir.join(ISO_PERSISTED_AUDIT_INDEX_FILE), contents).expect("audit fixture");
        let mut config = sample_config();
        config.store_dir = Some(store.path().to_path_buf());
        let error = runtime_config_error(&config, "malformed ISO audit stores must stop startup");
        assert!(
            error.to_string().contains(expected),
            "unexpected hard-cut error for {name}: {error:?}"
        );
    }
}

#[test]
fn digest_correct_malformed_iso_audit_entries_stop_startup() {
    assert_digest_correct_audit_mutation_is_rejected("extra-root-field", |object| {
        object.insert("unexpected".to_owned(), JsonValue::from("drift"));
    });
    assert_digest_correct_audit_mutation_is_rejected("missing-row-field", |object| {
        let row = object
            .get_mut("records")
            .and_then(JsonValue::as_array_mut)
            .and_then(|records| records.first_mut())
            .and_then(JsonValue::as_object_mut)
            .expect("audit row");
        assert!(row.remove("profile_id").is_some());
    });
    assert_digest_correct_audit_mutation_is_rejected("unsorted-rows", |object| {
        let records = object
            .get_mut("records")
            .and_then(JsonValue::as_array_mut)
            .expect("audit rows");
        records.swap(0, 1);
    });
    assert_digest_correct_audit_mutation_is_rejected("duplicate-row", |object| {
        let records = object
            .get_mut("records")
            .and_then(JsonValue::as_array_mut)
            .expect("audit rows");
        records[1] = records[0].clone();
    });
    assert_digest_correct_audit_mutation_is_rejected("noncanonical-filename", |object| {
        let row = object
            .get_mut("records")
            .and_then(JsonValue::as_array_mut)
            .and_then(|records| records.first_mut())
            .and_then(JsonValue::as_object_mut)
            .expect("audit row");
        row.insert("filename".to_owned(), JsonValue::from("forged.json"));
    });
}

#[test]
fn valid_but_stale_iso_audit_index_is_regenerated_after_validation() {
    let store = TempDir::new().expect("tempdir");
    let mut config = sample_config();
    config.store_dir = Some(store.path().to_path_buf());
    {
        let runtime = Iso20022BridgeRuntime::from_config(&config)
            .expect("cfg")
            .expect("enabled");
        assert!(runtime.check_and_record_inbound(
            "stale-audit",
            IsoMessageMetadata::inbound(
                "generic-iso20022",
                "pacs.008",
                None,
                Some("stale-audit-biz".to_owned()),
                None,
                "stale-audit-hash".to_owned(),
                "snapshot".to_owned(),
                false,
            ),
        ));
    }
    rewrite_persisted_audit_index(&store, |object| {
        object.insert("record_count".to_owned(), JsonValue::from(0_u64));
        object.insert("records".to_owned(), JsonValue::Array(Vec::new()));
    });
    let reloaded = Iso20022BridgeRuntime::from_config(&config)
        .expect("valid stale derived index is recoverable")
        .expect("enabled");
    assert!(reloaded.message_status("stale-audit").is_some());
    let regenerated = read_audit_index(&store);
    let object = regenerated.as_object().expect("audit index object");
    assert!(persisted_audit_index_digest_matches(object));
    assert_eq!(
        object.get("record_count").and_then(JsonValue::as_u64),
        Some(1)
    );
}

include!("iso20022_bridge/tests/lifecycle_tail.rs");
include!("iso20022_bridge/tests/wrong_family_test.rs");

include!("iso20022_bridge/tests/reported_returns.rs");

include!("iso20022_bridge/tests/native_payments.rs");
