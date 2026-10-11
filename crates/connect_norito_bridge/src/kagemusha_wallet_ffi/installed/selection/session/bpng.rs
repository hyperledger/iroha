//! The actual BPNG retail JWT contract, selected by the signed v7 runtime.
//! Core separately verifies its registered-device request proof before issuing a permit.

use super::*;

const ISSUER: &str = "https://bpng-core.soramitsu.io/mibank";
const FI: &str = "mibank.bpng";

pub(in super::super) struct Authority {
    key: PublicKey,
    release: [u8; 32],
    /// The signed runtime's Apple App Attestation root DER. Android selects no root original.
    apple_root: Vec<u8>,
}

pub(in super::super) fn authority(
    value: &Value,
    signed_app: &[u8],
    apple_root: Vec<u8>,
) -> Result<Authority> {
    let selected = exact(
        value,
        &[
            "schema",
            "jwt_issuer",
            "jwt_audience",
            "fi_id",
            "jwt_public_key_hex",
        ],
    )?;
    if text(selected, "schema")? != "bpng.wallet-enrollment-session-selection.v1"
        || text(selected, "jwt_issuer")? != ISSUER
        || text(selected, "jwt_audience")? != FI
        || text(selected, "fi_id")? != FI
    {
        return Err(invalid());
    }
    let key = sha(text(selected, "jwt_public_key_hex")?)?;
    Ok(Authority {
        key: PublicKey::from_bytes(Algorithm::Ed25519, &key).map_err(|_| invalid())?,
        // Raw SHA-256 of the exact authenticated application manifest is the bounded
        // release preimage. The enclosing v7 signature, not this hash, grants authority.
        release: hash(signed_app),
        apple_root,
    })
}

pub(super) fn authenticate(
    selection: &Selection,
    selected: &Authority,
    android: bool,
    originals: [&[u8]; 3],
) -> Result<Session> {
    let [token, proof, root] = originals;
    // BPNG has a registered Ed25519 HTTP request proof at Core, not a DPoP JWT.
    // Native selects this grammar from the authenticated release, never a caller flag.
    // Apple supplies exactly the signed runtime's root; Android supplies none.
    if !proof.is_empty() || (!android && root != selected.apple_root.as_slice()) {
        return Err(invalid());
    }
    let (header, claims, signature) = compact(token, 16_384)?;
    let header_value = json(&segment(header)?, 1024, false)?;
    let header_map = exact(&header_value, &["alg", "typ"])?;
    if text(header_map, "alg")? != "EdDSA" || text(header_map, "typ")? != "JWT" {
        return Err(invalid());
    }
    let signature = segment(signature)?;
    if signature.len() != 64 {
        return Err(invalid());
    }
    Signature::from_bytes(&signature)
        .verify(&selected.key, format!("{header}.{claims}").as_bytes())
        .map_err(|_| invalid())?;
    let claims_value = json(&segment(claims)?, 16_384, false)?;
    let claims = exact(
        &claims_value,
        &[
            "sub",
            "dataspace_id",
            "roles",
            "iat",
            "nbf",
            "exp",
            "iss",
            "aud",
        ],
    )?;
    let roles = field(claims, "roles")?.as_array().ok_or(invalid())?;
    if text(claims, "iss")? != ISSUER
        || text(claims, "aud")? != FI
        || text(claims, "dataspace_id")? != FI
        || roles.len() != 1
        || roles[0].as_str() != Some("RETAIL_USER")
    {
        return Err(invalid());
    }
    // The existing Core mutation journal bounds actor originals at 256 UTF-8 bytes.
    let actor = exact_text(claims, "sub", 256)?.as_bytes().to_vec();
    let issued = seconds(claims, "iat")?;
    let not_before = seconds(claims, "nbf")?;
    let expires = seconds(claims, "exp")?;
    if issued != not_before || not_before >= expires {
        return Err(invalid());
    }
    // Native intersects these authenticated bounds with the signed live permit's
    // observed time and elapsed-time deadline; no app wall clock grants freshness.
    let valid_from = not_before.checked_mul(1000).ok_or(invalid())?;
    let valid_until = expires.checked_mul(1000).ok_or(invalid())?;
    let (app, policy) = if android {
        &selection.android_enrollment
    } else {
        &selection.apple_enrollment
    };
    let attestation_root_der = session_root(android, policy, root)?;
    Ok(Session {
        token: Zeroizing::new(token.to_vec()),
        proof: Zeroizing::new(Vec::new()),
        root: root.to_vec(),
        device_binding: None,
        config: iroha_core_zk::kagemusha_wallet_enrollment_v1::EnrollmentConfigV1 {
            scheme: selection.scheme,
            app: app.clone(),
            policy: policy.clone(),
            attestation_root_der,
            installation: selection.installation,
            enrollment_certificate: selection.enrollment_certificate,
            service_origin: ISSUER.as_bytes().to_vec(),
            fi: FI.as_bytes().to_vec(),
            actor,
            release: selected.release.to_vec(),
            session_valid_from_ms: valid_from,
            session_expires_at_ms: valid_until,
        },
    })
}
