/// Redacted failure returned by a deployment-owned identity-request signer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[error("identity-bound request signing failed")]
pub struct IdentityRequestSigningErrorV1;

/// Deployment-owned signer for identity-bound Torii requests.
///
/// Implementations may keep the private key behind a deployment-owned signing
/// boundary. The client constructs the exact canonical request message and
/// independently verifies the returned signature before adding any
/// authentication headers.
pub trait IdentityRequestSignerV1: Send + Sync {
    /// Exact public identity advertised in the authenticated request headers.
    fn public_key(&self) -> &PublicKey;

    /// Sign one exact client-constructed request-authentication message.
    ///
    /// # Errors
    ///
    /// Returns a redacted provider failure without exposing backend details.
    fn sign_identity_request(
        &self,
        message: &[u8],
    ) -> core::result::Result<Signature, IdentityRequestSigningErrorV1>;
}

/// Borrowed software-key adapter for identity-bound Torii requests.
///
/// This adapter never serializes the private key. Production clients can
/// replace it with any [`IdentityRequestSignerV1`] implementation.
#[derive(Clone, Copy)]
pub struct BorrowedKeyPairIdentityRequestSignerV1<'a> {
    key_pair: &'a KeyPair,
}

impl core::fmt::Debug for BorrowedKeyPairIdentityRequestSignerV1<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("BorrowedKeyPairIdentityRequestSignerV1")
            .field("public_key", self.key_pair.public_key())
            .finish_non_exhaustive()
    }
}

impl<'a> BorrowedKeyPairIdentityRequestSignerV1<'a> {
    /// Borrow one software signing key for the duration of a request.
    #[must_use]
    pub const fn new(key_pair: &'a KeyPair) -> Self {
        Self { key_pair }
    }
}

impl IdentityRequestSignerV1 for BorrowedKeyPairIdentityRequestSignerV1<'_> {
    fn public_key(&self) -> &PublicKey {
        self.key_pair.public_key()
    }

    fn sign_identity_request(
        &self,
        message: &[u8],
    ) -> core::result::Result<Signature, IdentityRequestSigningErrorV1> {
        Signature::try_new(self.key_pair.private_key(), message)
            .map_err(|_| IdentityRequestSigningErrorV1)
    }
}

impl Client {
    fn request_without_iroha_identity_auth(
        &self,
        method: HttpMethod,
        url: Url,
    ) -> DefaultRequestBuilder {
        let headers = self.headers.iter().filter(|(name, _)| {
            ![
                "x-iroha-witness",
                HEADER_ACCOUNT,
                HEADER_SIGNATURE,
                HEADER_TIMESTAMP_MS,
                HEADER_NONCE,
                HEADER_OPERATOR_PUBLIC_KEY,
                HEADER_OPERATOR_TIMESTAMP_MS,
                HEADER_OPERATOR_NONCE,
                HEADER_OPERATOR_SIGNATURE,
            ]
            .iter()
            .any(|reserved| name.eq_ignore_ascii_case(reserved))
        });
        let mut builder = DefaultRequestBuilder::new(method, url)
            .with_transport(self.http_transport.clone())
            .headers(headers);
        if self.torii_request_timeout != Duration::ZERO {
            builder = builder.timeout(self.torii_request_timeout);
        }
        builder
    }
    // Listener admission and operator/validator/auditor identity are distinct gates. Carry
    // only the canonical listener credential from Config or the typed builder setter alongside fresh identity
    // authentication; ambient token, Authorization and stale identity headers stay stripped.
    fn request_for_identity_signature(
        &self,
        method: HttpMethod,
        url: Url,
    ) -> DefaultRequestBuilder {
        let headers = self.headers.iter().filter(|(name, _)| {
            ![
                "authorization",
                "x-api-token",
                "x-iroha-witness",
                HEADER_ACCOUNT,
                HEADER_SIGNATURE,
                HEADER_TIMESTAMP_MS,
                HEADER_NONCE,
                HEADER_OPERATOR_PUBLIC_KEY,
                HEADER_OPERATOR_TIMESTAMP_MS,
                HEADER_OPERATOR_NONCE,
                HEADER_OPERATOR_SIGNATURE,
            ]
            .iter()
            .any(|reserved| name.eq_ignore_ascii_case(reserved))
                || (self.has_configured_api_token && name.as_str() == "x-api-token")
        });
        let mut builder = DefaultRequestBuilder::new(method, url)
            .with_transport(self.http_transport.clone())
            .headers(headers);
        if self.torii_request_timeout != Duration::ZERO {
            builder = builder.timeout(self.torii_request_timeout);
        }
        builder
    }
    fn operator_signed_request(
        &self,
        method: HttpMethod,
        url: Url,
        body: Vec<u8>,
    ) -> Result<DefaultRequestBuilder> {
        let operator_key_pair = self
            .operator_key_pair
            .as_ref()
            .ok_or_else(|| eyre!("operator signing key is required before request dispatch"))?;
        self.identity_signed_request(operator_key_pair, method, url, body)
    }
    fn identity_signed_request(
        &self,
        identity_key_pair: &KeyPair,
        method: HttpMethod,
        url: Url,
        body: Vec<u8>,
    ) -> Result<DefaultRequestBuilder> {
        self.identity_signed_request_with_signer(
            &BorrowedKeyPairIdentityRequestSignerV1::new(identity_key_pair),
            method,
            url,
            body,
        )
    }
    fn identity_signed_request_with_signer<S: IdentityRequestSignerV1 + ?Sized>(
        &self,
        signer: &S,
        method: HttpMethod,
        url: Url,
        body: Vec<u8>,
    ) -> Result<DefaultRequestBuilder> {
        let identity_public_key = signer.public_key().clone();
        let timestamp_ms: u64 = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX);
        let nonce = Self::signed_request_nonce()?;
        let message = Self::operator_network_request_message(
            &self.network_id,
            &method,
            &url,
            &body,
            timestamp_ms,
            nonce.as_str(),
        )?;
        let signature = signer
            .sign_identity_request(&message)
            .map_err(|_| eyre!("identity-bound request signing failed"))?;
        signature
            .verify(&identity_public_key, &message)
            .map_err(|_| eyre!("identity-bound request signing failed"))?;
        let public_key = identity_public_key
            .try_to_multihash_string()
            .wrap_err("failed to encode identity-bound public key header")?;
        let timestamp = canonical_request_timestamp_header_value(timestamp_ms)?;
        let signature_b64 = canonical_request_signature_header_value(&signature)?;
        let builder = self
            .request_for_identity_signature(method, url)
            .header(HEADER_OPERATOR_PUBLIC_KEY, &public_key)
            .header(HEADER_OPERATOR_TIMESTAMP_MS, &timestamp)
            .header(HEADER_OPERATOR_NONCE, &nonce)
            .header(HEADER_OPERATOR_SIGNATURE, &signature_b64);
        if body.is_empty() {
            Ok(builder)
        } else {
            Ok(builder.body(body))
        }
    }
}
