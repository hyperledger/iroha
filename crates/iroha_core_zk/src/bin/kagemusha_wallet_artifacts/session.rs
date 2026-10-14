//! Separate offline session issuer. Tokens confer neither attestation nor monetary authority.
use super::application::{
    RUNTIME_MAX, canonical, input, origin_valid, output, parse, path_valid, recheck, text_valid,
};
use super::*;
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use iroha_crypto::{PrivateKey, Signature as EdSignature};
use norito::json::Value;
use rand::rand_core::TryRngCore as _;
use zeroize::Zeroizing;

#[derive(JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct Request {
    schema: String,
    runtime: OriginalInput,
    issuer: String,
    audience: String,
    platform: String,
    subject: String,
    registered_device_id: String,
    roles: Vec<String>,
    token_lifetime_seconds: u64,
    issuer_custody_directory: String,
    device_custody_directory: String,
    dpop_public_key_hex: String,
    output_parent: String,
    output_name: String,
}
struct Scope {
    public: [u8; 32],
    issuer: String,
    audience: String,
    app: String,
    origin: String,
    path: String,
    roles: std::collections::BTreeSet<String>,
    required: String,
    root: Vec<u8>,
}
fn text<'a>(value: &'a Value, name: &str) -> io::Result<&'a str> {
    value
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("session field"))
}
fn raw(value: &Value, name: &str, max: usize) -> io::Result<Vec<u8>> {
    let encoded = text(value, name)?;
    if encoded.len() > max.div_ceil(3) * 4 {
        return Err(invalid("session base64 bound"));
    }
    let bytes = checked(STANDARD.decode(encoded), "session base64")?;
    if bytes.is_empty() || bytes.len() > max || STANDARD.encode(&bytes) != encoded {
        return Err(invalid("canonical session base64"));
    }
    Ok(bytes)
}
fn exact(value: &Value, fields: &[&str]) -> io::Result<()> {
    let map = value.as_object().ok_or_else(|| invalid("session object"))?;
    if map.len() != fields.len() || fields.iter().any(|key| !map.contains_key(*key)) {
        return Err(invalid("closed session fields"));
    }
    Ok(())
}
fn scope(runtime: &[u8], issuer: &str, audience: &str, platform: &str) -> io::Result<Scope> {
    let value = parse(runtime, RUNTIME_MAX, true)?;
    exact(
        &value,
        &[
            "schema",
            "version",
            "scheme_id",
            "scheme_original_base64",
            "enrollment_certificate_original_base64",
            "artifact_signer_certificate_original_base64",
            "artifact_manifest_original_base64",
            "android",
            "apple",
            "sessions",
        ],
    )?;
    if text(&value, "schema")? != "iroha.kagemusha.wallet-runtime.v1"
        || value.get("version").and_then(Value::as_u64) != Some(1)
    {
        return Err(invalid("session runtime schema"));
    }
    let scheme_id = digest(text(&value, "scheme_id")?)?;
    let rows = value
        .get("sessions")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("session authorities"))?;
    if !(1..=64).contains(&rows.len()) {
        return Err(invalid("session authority count"));
    }
    let selected: Vec<_> = rows
        .iter()
        .filter(|row| {
            text(row, "issuer").ok() == Some(issuer) && text(row, "audience").ok() == Some(audience)
        })
        .collect();
    if selected.len() != 1 {
        return Err(invalid("unique selected session authority required"));
    }
    let row = selected[0];
    exact(
        row,
        &[
            "issuer",
            "audience",
            "requestOrigin",
            "verificationKeyEd25519Base64",
            "releaseOriginalBase64",
            "androidClientApp",
            "appleClientApp",
            "enrollmentChallengePath",
            "roles",
            "requiredRole",
        ],
    )?;
    let public: [u8; 32] = raw(row, "verificationKeyEd25519Base64", 32)?
        .try_into()
        .map_err(|_| invalid("Ed25519 key extent"))?;
    checked(
        PublicKey::from_bytes(Algorithm::Ed25519, &public),
        "Ed25519 public key",
    )?;
    let origin = text(row, "requestOrigin")?.to_owned();
    let path = text(row, "enrollmentChallengePath")?.to_owned();
    if !text_valid(issuer, 512)
        || !text_valid(audience, 512)
        || !text_valid(&origin, 2048)
        || !origin_valid(&origin)
        || !path_valid(&path)
    {
        return Err(invalid("session issuer endpoint scope"));
    }
    raw(row, "releaseOriginalBase64", 16_384)?;
    let role_values = row
        .get("roles")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("session roles"))?;
    let mut roles = std::collections::BTreeSet::new();
    if !(1..=16).contains(&role_values.len()) {
        return Err(invalid("session role count"));
    }
    for value in role_values {
        let role = value.as_str().ok_or_else(|| invalid("session role"))?;
        if role.is_empty()
            || role.len() > 128
            || !role.is_ascii()
            || role.chars().any(char::is_control)
            || !roles.insert(role.to_owned())
        {
            return Err(invalid("session role grammar"));
        }
    }
    let required = text(row, "requiredRole")?.to_owned();
    if !text_valid(&required, 128) || !roles.contains(&required) {
        return Err(invalid("required role absent"));
    }
    let selected = value
        .get(platform)
        .ok_or_else(|| invalid("session platform"))?;
    let policy_bytes = raw(
        selected,
        "app_policy_original_base64",
        KAGEMUSHA_WALLET_ENROLLMENT_POLICY_MAX_BYTES_V1,
    )?;
    let policy = checked(
        KagemushaWalletAppPolicyV1::decode_canonical(&policy_bytes, &scheme_id),
        "session app policy",
    )?;
    let template_bytes = raw(
        selected,
        "enrollment_template_original_base64",
        KAGEMUSHA_WALLET_ENROLLMENT_POLICY_MAX_BYTES_V1,
    )?;
    let template = checked(
        KagemushaWalletEnrollmentPolicyTemplateV1::decode_canonical(&template_bytes, &scheme_id),
        "session enrollment template",
    )?;
    checked(
        template.validate_for_app(&policy),
        "session platform binding",
    )?;
    let (app, root) = match (platform, &policy.identity, &template.platform) {
        (
            "android",
            KagemushaWalletAppIdentityV1::Android { package_name, .. },
            KagemushaWalletEnrollmentPlatformV1::Android { .. },
        ) => {
            exact(
                selected,
                &[
                    "app_policy_original_base64",
                    "enrollment_template_original_base64",
                ],
            )?;
            if text(row, "androidClientApp")? != package_name {
                return Err(invalid("Android session identity"));
            }
            (package_name.clone(), Vec::new())
        }
        (
            "apple",
            KagemushaWalletAppIdentityV1::Apple { app_id },
            KagemushaWalletEnrollmentPlatformV1::Apple {
                attestation_root_sha256,
            },
        ) => {
            exact(
                selected,
                &[
                    "app_policy_original_base64",
                    "enrollment_template_original_base64",
                    "attestation_root_der_base64",
                ],
            )?;
            let root = raw(selected, "attestation_root_der_base64", 16_384)?;
            if text(row, "appleClientApp")? != app_id
                || BlobV1::of(&root).sha256 != *attestation_root_sha256
            {
                return Err(invalid("Apple session identity/root"));
            }
            (app_id.clone(), root)
        }
        _ => return Err(invalid("session platform mismatch")),
    };
    Ok(Scope {
        public,
        issuer: issuer.into(),
        audience: audience.into(),
        app,
        origin,
        path,
        roles,
        required,
        root,
    })
}
fn uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, b)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
}
fn random_uuid() -> io::Result<String> {
    let mut bytes = [0u8; 16];
    checked(
        rand::rngs::OsRng.try_fill_bytes(&mut bytes),
        "nonce entropy",
    )?;
    bytes[6] = (bytes[6] & 15) | 64;
    bytes[8] = (bytes[8] & 63) | 128;
    let h = hex::encode(bytes);
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    ))
}
fn compact_input(header: &Value, payload: &Value, maximum: usize) -> io::Result<Zeroizing<String>> {
    // JWT member JSON need not be LF-terminated; both parts are canonical Norito JSON.
    let h = checked(json::to_json_bounded(header, 1024), "JWT header bound")?;
    let p = Zeroizing::new(checked(
        json::to_json_bounded(payload, maximum),
        "JWT claim bound",
    )?);
    Ok(Zeroizing::new(format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(h),
        URL_SAFE_NO_PAD.encode(p.as_bytes())
    )))
}
fn issue(
    scope: &Scope,
    request: &Request,
    ed: &PrivateKey,
    dpop: &SigningKey,
    now: u64,
    jti: &str,
) -> io::Result<(Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>)> {
    if !text_valid(&request.subject, 512)
        || !uuid(&request.registered_device_id)
        || !uuid(jti)
        || !(1..=3600).contains(&request.token_lifetime_seconds)
        || now == 0
        || now > 9_007_199_254_737_391
    {
        return Err(invalid("session subject/device/time bound"));
    }
    let roles: std::collections::BTreeSet<_> = request.roles.iter().cloned().collect();
    if roles.is_empty()
        || roles.len() != request.roles.len()
        || !roles.is_subset(&scope.roles)
        || !roles.contains(&scope.required)
    {
        return Err(invalid("session roles exceed selected authority"));
    }
    let expected = checked(
        PublicKey::from_bytes(Algorithm::Ed25519, &scope.public),
        "session authority public key",
    )?;
    if checked(
        PublicKey::from_private_key(ed),
        "session issuer private key",
    )? != expected
    {
        return Err(invalid("issuer custody differs from pinned runtime"));
    }
    let point = dpop.verifying_key().to_encoded_point(false);
    if point.as_bytes() != point_from_request(request)?.as_sec1_bytes() {
        return Err(invalid("DPoP custody differs from selected device binding"));
    }
    let x = URL_SAFE_NO_PAD.encode(point.x().ok_or_else(|| invalid("DPoP x"))?);
    let y = URL_SAFE_NO_PAD.encode(point.y().ok_or_else(|| invalid("DPoP y"))?);
    let jwk = norito::json!({"crv":("P-256"),"kty":("EC"),"x":(x),"y":(y)});
    let thumbprint = format!("{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{x}\",\"y\":\"{y}\"}}");
    let claims = norito::json!({"sub":(request.subject),"dataspace_id":(scope.audience),"roles":(request.roles),
        "iat":(now),"nbf":(now),"exp":(now+request.token_lifetime_seconds),"iss":(scope.issuer),"aud":(scope.audience),
        "device_id":(request.registered_device_id),"client_app":(scope.app),"cnf":{"jkt":(URL_SAFE_NO_PAD.encode(BlobV1::of(thumbprint.as_bytes()).sha256))}});
    let unsigned = compact_input(
        &norito::json!({"alg":("EdDSA"),"typ":("JWT")}),
        &claims,
        16_384,
    )?;
    let signature = EdSignature::new(ed, unsigned.as_bytes());
    let token = Zeroizing::new(
        format!(
            "{}.{}",
            unsigned.as_str(),
            URL_SAFE_NO_PAD.encode(signature.payload())
        )
        .into_bytes(),
    );
    if token.len() > 16_384 {
        return Err(invalid("token extent"));
    }
    let unsigned = compact_input(
        &norito::json!({"typ":("dpop+jwt"),"alg":("ES256"),"jwk":(jwk)}),
        &norito::json!({"htm":("POST"),"htu":(format!("{}{}",scope.origin,scope.path)),"iat":(now),"jti":(jti),
            "ath":(URL_SAFE_NO_PAD.encode(BlobV1::of(&token).sha256))}),
        4096,
    )?;
    let signature: Signature = dpop.sign(unsigned.as_bytes());
    let proof = Zeroizing::new(
        format!(
            "{}.{}",
            unsigned.as_str(),
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        )
        .into_bytes(),
    );
    if proof.len() > 4096 {
        return Err(invalid("DPoP proof extent"));
    }
    Ok((token, proof))
}
fn point_from_request(request: &Request) -> io::Result<KagemushaDevicePublicKeyV1> {
    point(&request.dpop_public_key_hex)
}
pub(super) fn run(path: &str) -> io::Result<()> {
    let source = Original::open(path, REQUEST_MAX, None)?;
    parse(&source.bytes, REQUEST_MAX, false)?;
    let request: Request = checked(json::from_slice(&source.bytes), "closed session request")?;
    if request.schema != "iroha.kagemusha.wallet-session-issuance.v1"
        || !matches!(request.platform.as_str(), "android" | "apple")
    {
        return Err(invalid("session issuance schema/platform"));
    }
    let mut held = vec![source];
    let runtime = input(&request.runtime, RUNTIME_MAX, &mut held)?;
    let selected = scope(
        &runtime,
        &request.issuer,
        &request.audience,
        &request.platform,
    )?;
    let issuer_custody = PrivateDirectory::open_exact(&request.issuer_custody_directory)?;
    let device_custody = PrivateDirectory::open_exact(&request.device_custody_directory)?;
    let seed = issuer_custody.read("session-issuer.ed25519.seed", 32)?;
    if seed.len() != 32 {
        return Err(invalid("Ed25519 seed extent"));
    }
    let ed = checked(
        PrivateKey::from_bytes(Algorithm::Ed25519, &seed),
        "Ed25519 private custody",
    )?;
    let dpop = private_key(
        &device_custody,
        "session-device-dpop.pkcs8.der",
        point_from_request(&request)?,
    )?;
    let now = checked(
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH),
        "system clock",
    )?
    .as_secs();
    let (token, proof) = issue(&selected, &request, &ed, &dpop, now, &random_uuid()?)?;
    issuer_custody.revalidate()?;
    device_custody.revalidate()?;
    recheck(&held)?;
    let out = output(&request.output_parent, &request.output_name)?;
    publish(&out, "access-token.jwt", &token)?;
    publish(&out, "dpop-proof.jwt", &proof)?;
    // The Android empty root is deliberate and is accepted by the native session owner.
    publish(&out, "attestation-root.der", &selected.root)?;
    issuer_custody.revalidate()?;
    device_custody.revalidate()?;
    recheck(&held)?;
    out.revalidate()?;
    publish(
        &out,
        "session-complete.json",
        &canonical(
            &norito::json!({"schema":("iroha.kagemusha.wallet-session-issued.v1"),
        "issuedAtSeconds":(now),"tokenExpiresAtSeconds":(now+request.token_lifetime_seconds),
        "proofExpiresBeforeSeconds":(now+61),"platform":(request.platform),"runtimeSha256":(request.runtime.sha256)}),
            4096,
        )?,
    )
}

#[cfg(test)]
#[path = "session/tests.rs"]
mod tests;
