//! One authenticated application release selects shared policy; native ledger execution selects
//! each token independently. No token list, caller trust key or fallback authority is accepted.
use super::*;
use iroha_core_zk::kagemusha_wallet_registration_v1::{
    RegistrationErrorV1, RegistrationSourceV1, verify_registration_source_v1,
};

pub(super) fn application(document: &Value) -> Result<&Map> {
    let app = exact(
        document,
        &[
            "schema",
            "nativeBridgeAbiVersion",
            "runtimeSha256",
            "signedGenesisSha256",
            "genesisBlockHash",
            "genesisPublicKey",
            "chainId",
            "networkId",
            "financialOriginals",
        ],
    )?;
    if text(app, "schema")? != "iroha.kagemusha.wallet-application-release.v1"
        || field(app, "nativeBridgeAbiVersion")?.as_u64()
            != Some(u64::from(crate::CONNECT_NORITO_BRIDGE_ABI_VERSION))
    {
        return Err(invalid());
    }
    for key in ["runtimeSha256", "signedGenesisSha256", "genesisBlockHash"] {
        sha(text(app, key)?)?;
    }
    let chain = text(app, "chainId")?;
    if chain.is_empty() || chain.len() > 1024 || chain.chars().any(char::is_control) {
        return Err(invalid());
    }
    Ok(app)
}
fn blob(value: &Value, maximum: usize) -> Result<BlobV1> {
    let value = exact(value, &["sha256", "bytes"])?;
    let bytes = field(value, "bytes")?.as_u64().ok_or_else(invalid)?;
    if bytes == 0 || bytes > maximum as u64 {
        return Err(invalid());
    }
    Ok(BlobV1 {
        sha256: sha(text(value, "sha256")?)?,
        bytes,
    })
}
fn finality(
    app: &Map,
    input: &RuntimeOriginals<'_>,
    scheme: &KagemushaWalletSchemeV1,
) -> Result<SumeragiFinalityVerifier> {
    if BlobV1::of(input.signed_genesis).sha256 != sha(text(app, "signedGenesisSha256")?)? {
        return Err(invalid());
    }
    let genesis = iroha_genesis::decode_signed_genesis(bounded(input.signed_genesis, GENESIS_MAX)?)
        .map_err(|_| invalid())?;
    if *genesis.hash().as_ref() != sha(text(app, "genesisBlockHash")?)? {
        return Err(invalid());
    }
    let network = NetworkId::from_genesis_hash(genesis.hash());
    if network.to_string() != text(app, "networkId")? || *network.as_bytes() != scheme.network_id {
        return Err(invalid());
    }
    let public = PublicKey::from_str(text(app, "genesisPublicKey")?).map_err(|_| invalid())?;
    if public.algorithm() != Algorithm::Ed25519
        || genesis
            .external_transactions()
            .next()
            .and_then(|tx| tx.authority().try_signatory())
            != Some(&public)
    {
        return Err(invalid());
    }
    let epoch = authenticated_genesis(&genesis)
        .map(|genesis| genesis.into_parts().0)
        .map_err(|_| invalid())?;
    let roster = epoch
        .committee
        .iter()
        .map(|member| FinalityValidator {
            public_key: member.validator.public_key().clone(),
            proof_of_possession: member.proof_of_possession.clone(),
        })
        .collect();
    SumeragiFinalityVerifier::new(&genesis, text(app, "chainId")?, roster).map_err(|_| invalid())
}
pub(super) fn load(document: &Value, input: &RuntimeOriginals<'_>) -> Result<Selection> {
    load_with_registration(document, input, |base, original| {
        let source = RegistrationSourceV1::decode_canonical(original).map_err(|_| invalid())?;
        verify_registration_source_v1(&source, &base.genesis, &base.scheme, || false)
            .map_err(registration_error)
    })
}
fn registration_error(error: RegistrationErrorV1) -> Failure {
    Failure::code(match error {
        RegistrationErrorV1::Absent | RegistrationErrorV1::Unavailable(_) => ARTIFACTS_UNAVAILABLE,
        RegistrationErrorV1::Custody(_) => CUSTODY_LOST,
        RegistrationErrorV1::Cancelled => CANCELLED,
        _ => INVALID,
    })
}
// The authenticator is private trusted native code, never caller DATA or a public trait.
// Shared source qualification can consume base before asset-dependent templates are derived.
fn load_with_registration(
    document: &Value,
    input: &RuntimeOriginals<'_>,
    authenticate: impl FnOnce(
        &Arc<AuthenticatedBase>,
        &[u8],
    ) -> Result<
        iroha_core_zk::kagemusha_wallet_registration_v1::FinalizedKagemushaWalletRegistrationV1,
    >,
) -> Result<Selection> {
    let app = application(document)?;
    if BlobV1::of(input.wallet_runtime).sha256 != sha(text(app, "runtimeSha256")?)? {
        return Err(invalid());
    }
    let financial = exact(
        field(app, "financialOriginals")?,
        &[
            "verifierPack",
            "producerInventory",
            "producerCatalogDigest",
            "transport",
        ],
    )?;
    let financial = FinancialSelection {
        pack_identity: blob(
            field(financial, "verifierPack")?,
            VERIFIER_PACK_MAX_BYTES_V1,
        )?,
        catalog_identity: blob(field(financial, "producerInventory")?, CATALOG_MAX_BYTES_V1)?,
        producer_catalog_digest: sha(text(financial, "producerCatalogDigest")?)?,
        transport_identity: blob(field(financial, "transport")?, CATALOG_MAX_BYTES_V1)?,
    };
    let runtime_value = json(input.wallet_runtime, WALLET_RUNTIME_MAX, true)?;
    let runtime = exact(
        &runtime_value,
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
    if text(runtime, "schema")? != "iroha.kagemusha.wallet-runtime.v1"
        || field(runtime, "version")?.as_u64() != Some(1)
    {
        return Err(invalid());
    }
    let scheme = KagemushaWalletSchemeV1::decode_canonical(
        &raw(
            runtime,
            "scheme_original_base64",
            KAGEMUSHA_WALLET_SCHEME_MAX_BYTES_V1,
        )?,
        &sha(text(runtime, "scheme_id")?)?,
    )
    .map_err(|_| invalid())?;
    let artifact_certificate = raw(
        runtime,
        "artifact_signer_certificate_original_base64",
        KAGEMUSHA_WALLET_CERTIFICATE_MAX_BYTES_V1,
    )?;
    let artifact_signer =
        KagemushaWalletSignerCertificateV1::decode_canonical(&artifact_certificate, &scheme)
            .map_err(|_| invalid())?;
    artifact_signer
        .verify_role(&scheme, KagemushaWalletSignerRoleV1::Artifact)
        .map_err(|_| invalid())?;
    let artifact_manifest = raw(
        runtime,
        "artifact_manifest_original_base64",
        KAGEMUSHA_WALLET_ARTIFACT_MANIFEST_MAX_BYTES_V1,
    )?;
    let manifest = KagemushaWalletArtifactManifestV1::decode_canonical(&artifact_manifest, &scheme)
        .map_err(|_| invalid())?;
    manifest
        .verify(&scheme, &artifact_signer)
        .map_err(|_| invalid())?;
    let enrollment_certificate = KagemushaWalletSignerCertificateV1::decode_canonical(
        &raw(
            runtime,
            "enrollment_certificate_original_base64",
            KAGEMUSHA_WALLET_CERTIFICATE_MAX_BYTES_V1,
        )?,
        &scheme,
    )
    .map_err(|_| invalid())?;
    enrollment_certificate
        .verify_role(&scheme, KagemushaWalletSignerRoleV1::Enrollment)
        .map_err(|_| invalid())?;
    let genesis = finality(app, input, &scheme)?;
    let base = Arc::new(AuthenticatedBase {
        _originals: RetainedBaseOriginals {
            _app_manifest: input.app_manifest.into(),
            _envelope: input.envelope.into(),
            _wallet_runtime: input.wallet_runtime.into(),
            _signed_genesis: input.signed_genesis.into(),
        },
        financial: Some(financial),
        scheme,
        artifact_certificate,
        artifact_manifest,
        installation: InstallationV1 {
            scheme_id: scheme.scheme_id(),
            manifest_digest: manifest.manifest_digest(),
        },
        genesis: Arc::new(genesis),
    });
    let registration = authenticate(&base, input.registration_source)?;
    let asset = registration.asset().clone();
    let asset_original = registration.asset_original().to_vec();
    let platform = |name| -> Result<(
        KagemushaWalletAppPolicyV1,
        KagemushaWalletEnrollmentPolicyV1,
    )> {
        // Android pins roots by SPKI in its policy; only Apple selects a root DER original.
        let mut fields = vec![
            "app_policy_original_base64",
            "enrollment_template_original_base64",
        ];
        if name == "apple" {
            fields.push("attestation_root_der_base64");
        }
        let selected = exact(field(runtime, name)?, &fields)?;
        let app = KagemushaWalletAppPolicyV1::decode_canonical(
            &raw(selected, "app_policy_original_base64", 1024)?,
            &scheme.scheme_id(),
        )
        .map_err(|_| invalid())?;
        let template = KagemushaWalletEnrollmentPolicyTemplateV1::decode_canonical(
            &raw(selected, "enrollment_template_original_base64", 1024)?,
            &scheme.scheme_id(),
        )
        .map_err(|_| invalid())?;
        template.validate_for_app(&app).map_err(|_| invalid())?;
        require_qualified_adapters(&template.platform)?;
        match (&template.platform, name) {
            (KagemushaWalletEnrollmentPlatformV1::Android { .. }, "android") => {}
            (
                KagemushaWalletEnrollmentPlatformV1::Apple {
                    attestation_root_sha256,
                },
                "apple",
            ) => {
                if BlobV1::of(&raw(selected, "attestation_root_der_base64", 16_384)?).sha256
                    != *attestation_root_sha256
                {
                    return Err(invalid());
                }
            }
            _ => return Err(invalid()),
        }
        Ok((app, template.for_asset(&asset).map_err(|_| invalid())?))
    };
    let android = platform("android")?;
    let apple = platform("apple")?;
    let sessions =
        session::universal_authorities(field(runtime, "sessions")?, &android.0, &apple.0)?;
    Ok(Selection {
        base,
        application: ApplicationBinding::ApplicationReleaseV1 {
            _registration: Box::new(registration),
            _source: input.registration_source.into(),
        },
        enrollment_certificate,
        asset,
        asset_original,
        android_app_policy: android.0.policy_digest().map_err(|_| invalid())?,
        apple_app_policy: apple.0.policy_digest().map_err(|_| invalid())?,
        android_enrollment: android,
        apple_enrollment: apple,
        fi_sessions: sessions,
        bpng_session: None,
    })
}
