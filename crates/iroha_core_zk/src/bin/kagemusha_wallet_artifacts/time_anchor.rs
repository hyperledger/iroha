//! One direct issuer response to an actual wallet nonce; Native owns timely acceptance.

use super::application::{canonical, input, output, parse, recheck};
use super::*;

/// Explicit public bindings and a selected private issuer directory; no inline secret.
#[derive(JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct Request {
    schema: String,
    scheme: OriginalInput,
    scheme_id_hex: String,
    certificate: OriginalInput,
    issuer_public_key_hex: String,
    wallet_id_hex: String,
    nonce: OriginalInput,
    custody_directory: String,
    output_parent: String,
    output_name: String,
}

fn request(bytes: &[u8]) -> io::Result<Request> {
    parse(bytes, REQUEST_MAX, false)?;
    let request: Request = checked(json::from_slice(bytes), "closed time issuer request")?;
    if request.schema != "iroha.kagemusha.wallet-time-anchor-issuance.v1" {
        return Err(invalid("time issuer schema"));
    }
    digest(&request.scheme_id_hex)?;
    digest(&request.wallet_id_hex)?;
    point(&request.issuer_public_key_hex)?;
    Ok(request)
}

fn response(
    scheme: &KagemushaWalletSchemeV1,
    certificate: &KagemushaWalletSignerCertificateV1,
    key: &SigningKey,
    wallet_id: [u8; 32],
    nonce: [u8; 32],
    now_ms: u64,
) -> io::Result<KagemushaWalletTimeAnchorV1> {
    checked(
        certificate.verify_role(scheme, KagemushaWalletSignerRoleV1::TimeAnchor),
        "time issuer authority",
    )?;
    if now_ms == 0 {
        return Err(invalid("issuer UTC unavailable"));
    }
    let body = KagemushaWalletTimeAnchorBodyV1 {
        version: KAGEMUSHA_WALLET_VERSION_V1,
        scheme_id: scheme.scheme_id(),
        wallet_id,
        nonce,
        issuer_time_ms: now_ms,
        signer_certificate: certificate.certificate_digest(),
    };
    checked(body.validate(), "time response binding")?;
    let anchor = checked(
        KagemushaWalletTimeAnchorV1::sign(
            body,
            certificate,
            signature(key, &body.signing_message()),
        ),
        "time response signing",
    )?;
    checked(
        anchor.verify(scheme, certificate),
        "time response verification",
    )?;
    Ok(anchor)
}

pub(super) fn run(path: &str) -> io::Result<()> {
    let source = Original::open(path, REQUEST_MAX, None)?;
    let request = request(&source.bytes)?;
    let request_sha = BlobV1::of(&source.bytes).sha256;
    let mut held = vec![source];
    let scheme_bytes = input(&request.scheme, 4096, &mut held)?;
    let scheme = checked(
        KagemushaWalletSchemeV1::decode_canonical(&scheme_bytes, &digest(&request.scheme_id_hex)?),
        "time issuer scheme",
    )?;
    let certificate_bytes = input(&request.certificate, 4096, &mut held)?;
    let certificate = checked(
        KagemushaWalletSignerCertificateV1::decode_canonical(&certificate_bytes, &scheme),
        "time issuer certificate",
    )?;
    checked(
        certificate.verify_role(&scheme, KagemushaWalletSignerRoleV1::TimeAnchor),
        "time issuer certificate role",
    )?;
    if certificate.body.key != point(&request.issuer_public_key_hex)?
        || certificate.body.key == scheme.scheme_root_key
    {
        return Err(invalid("separate selected time issuer key required"));
    }
    let nonce: [u8; 32] = checked(
        input(&request.nonce, 32, &mut held)?.try_into(),
        "exact time nonce required",
    )?;
    if nonce == [0; 32] {
        return Err(invalid("zero time nonce"));
    }
    let wallet = digest(&request.wallet_id_hex)?;
    let certificate_set = checked(
        KagemushaWalletCertificateSetV1::new(vec![certificate]),
        "time certificate set",
    )?;
    let certificate_set_bytes = checked(
        norito::encode_canonical(&certificate_set),
        "time certificate set encoding",
    )?;
    let destination = output(&request.output_parent, &request.output_name)?;
    let custody = PrivateDirectory::open_exact(&request.custody_directory)?;
    let key = private_key(&custody, "time-anchor.pkcs8.der", certificate.body.key)?;
    recheck(&held)?;
    // Only the issuer's current clock supplies T. No request field or environment override
    // can turn a captured timestamp into a purported direct response.
    let now = checked(
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH),
        "issuer UTC unavailable",
    )?;
    let now_ms = checked(u64::try_from(now.as_millis()), "issuer UTC extent")?;
    let anchor = response(&scheme, &certificate, &key, wallet, nonce, now_ms)?;
    drop(key);
    let anchor_bytes = checked(anchor.to_canonical_bytes(), "time anchor encoding")?;
    publish(&destination, "time-anchor.norito", &anchor_bytes)?;
    publish(&destination, "time-certificate.norito", &certificate_bytes)?;
    publish(
        &destination,
        "time-certificates.norito",
        &certificate_set_bytes,
    )?;
    recheck(&held)?;
    custody.revalidate()?;
    let completion = canonical(
        &norito::json!({
            "schema":"iroha.kagemusha.wallet-time-anchor-issued.v1",
            "requestSha256":(hex::encode(request_sha)),
            "schemeId":(request.scheme_id_hex), "walletId":(request.wallet_id_hex),
            "nonceSha256":(hex::encode(BlobV1::of(&nonce).sha256)),
            "issuerTimeMs":now_ms,
            "anchorSha256":(hex::encode(BlobV1::of(&anchor_bytes).sha256)),
            "certificateSha256":(hex::encode(BlobV1::of(&certificate_bytes).sha256)),
            "certificatesSha256":(hex::encode(BlobV1::of(&certificate_set_bytes).sha256))
        }),
        4096,
    )?;
    publish(&destination, "time-anchor-complete.json", &completion)?;
    // The phone must still consume its live Native exchange token in the same boot and
    // within its monotonic response-age bound, then commit an ordinary TimeAnchor Refresh.
    Ok(())
}

#[cfg(test)]
#[path = "time_anchor/tests.rs"]
mod tests;
