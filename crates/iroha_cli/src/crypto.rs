//! SM cryptography helpers exposed via the CLI.
use crate::{Run, RunContext};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use clap::{Args, Subcommand};
use eyre::{Result, WrapErr, eyre};
use iroha_crypto::{
    Algorithm, PrivateKey, PublicKey, Sm2PrivateKey, Sm2PublicKey, Sm3Digest, Sm4Key,
    sm::{encode_sm2_private_key_payload, encode_sm2_public_key_payload},
};
use norito::json;
use rand::{rand_core::TryCryptoRng, rngs::OsRng};
use std::{fs, path::PathBuf};
use zeroize::{Zeroize, Zeroizing};
enum PrivateInput {
    Hex(String),
    Pem(String),
}
#[derive(Subcommand, Debug)]
pub enum Command {
    /// SM2 key management helpers.
    #[command(subcommand)]
    Sm2(Sm2Command),
    /// SM3 hashing helpers.
    #[command(subcommand)]
    Sm3(Sm3Command),
    /// SM4 AEAD helpers (GCM/CCM modes).
    #[command(subcommand)]
    Sm4(Sm4Command),
}
impl Run for Command {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        match self {
            Command::Sm2(cmd) => cmd.run(context),
            Command::Sm3(cmd) => cmd.run(context),
            Command::Sm4(cmd) => cmd.run(context),
        }
    }
}
#[derive(Subcommand, Debug)]
pub enum Sm2Command {
    /// Generate a new SM2 key pair (distinguishing ID aware).
    Keygen(Sm2KeygenArgs),
    /// Import an existing SM2 private key and derive metadata.
    Import(Sm2ImportArgs),
    /// Export SM2 key material with config snippets.
    Export(Sm2ExportArgs),
}
impl Run for Sm2Command {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        match self {
            Sm2Command::Keygen(args) => args.run(context),
            Sm2Command::Import(args) => args.run(context),
            Sm2Command::Export(args) => args.run(context),
        }
    }
}
#[derive(Subcommand, Debug)]
pub enum Sm3Command {
    /// Hash input data with SM3.
    Hash(Sm3HashArgs),
}
impl Run for Sm3Command {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        match self {
            Sm3Command::Hash(args) => args.run(context),
        }
    }
}
#[derive(Subcommand, Debug)]
pub enum Sm4Command {
    /// Encrypt data with SM4-GCM.
    GcmSeal(Sm4GcmSealArgs),
    /// Decrypt data with SM4-GCM.
    GcmOpen(Sm4GcmOpenArgs),
    /// Encrypt data with SM4-CCM.
    CcmSeal(Sm4CcmSealArgs),
    /// Decrypt data with SM4-CCM.
    CcmOpen(Sm4CcmOpenArgs),
}
impl Run for Sm4Command {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        match self {
            Sm4Command::GcmSeal(args) => args.run(context),
            Sm4Command::GcmOpen(args) => args.run(context),
            Sm4Command::CcmSeal(args) => args.run(context),
            Sm4Command::CcmOpen(args) => args.run(context),
        }
    }
}
#[derive(Args, Debug)]
pub struct Sm2KeygenArgs {
    /// Distinguishing identifier embedded into SM2 signatures (defaults to `1234567812345678`).
    #[arg(long, value_name = "DISTID")]
    distid: Option<String>,
    /// Optional seed (hex) for deterministic key generation. Helpful for tests/backups.
    #[arg(long, value_name = "HEX")]
    seed_hex: Option<String>,
    /// Write the generated JSON payload to a file instead of stdout.
    #[arg(long, value_name = "PATH")]
    output: Option<PathBuf>,
    /// Suppress stdout printing of the JSON payload.
    #[arg(long)]
    quiet: bool,
}
impl Sm2KeygenArgs {
    fn material(&self) -> Result<Sm2KeyMaterial> {
        self.material_with_rng(&mut OsRng)
    }
    fn material_with_rng<R: TryCryptoRng>(&self, rng: &mut R) -> Result<Sm2KeyMaterial> {
        let distid = parse_distid(self.distid.clone())?;
        let private = if let Some(seed_hex) = &self.seed_hex {
            let seed = decode_hex_bytes("seed", seed_hex)?;
            Sm2PrivateKey::from_seed(distid.clone(), &seed)
                .wrap_err("failed to derive SM2 key from seed")?
        } else {
            let mut seed = Zeroizing::new([0_u8; 32]);
            rng.try_fill_bytes(seed.as_mut())
                .map_err(|error| eyre!("failed to generate random SM2 seed: {error}"))?;
            Sm2PrivateKey::from_seed(distid.clone(), seed.as_ref())
                .wrap_err("failed to derive SM2 key from random seed")?
        };
        Ok(Sm2KeyMaterial::new(&private))
    }
}
impl Run for Sm2KeygenArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let material = self.material()?;
        if let Some(path) = &self.output {
            fs::write(path, material.as_json_pretty().as_bytes()).with_context(|| {
                format!("failed to write SM2 key material to {}", path.display())
            })?;
        }
        if !self.quiet {
            context.print_data(&material.json)?;
        }
        Ok(())
    }
}
#[derive(Args, Debug)]
pub struct Sm2ImportArgs {
    /// Existing SM2 private key in hex (32 bytes).
    #[arg(
        long,
        value_name = "HEX",
        conflicts_with_all = ["private_key_file", "private_key_pem", "private_key_pem_file"]
    )]
    private_key_hex: Option<String>,
    /// Path to a file containing a hex-encoded SM2 private key (32 bytes).
    #[arg(
        long,
        value_name = "PATH",
        conflicts_with_all = ["private_key_hex", "private_key_pem", "private_key_pem_file"]
    )]
    private_key_file: Option<PathBuf>,
    /// Existing SM2 private key encoded as PKCS#8 PEM.
    #[arg(
        long,
        value_name = "PEM",
        conflicts_with_all = ["private_key_hex", "private_key_file", "private_key_pem_file"]
    )]
    private_key_pem: Option<String>,
    /// Path to a PKCS#8 PEM file containing an SM2 private key.
    #[arg(
        long,
        value_name = "PATH",
        conflicts_with_all = ["private_key_hex", "private_key_file", "private_key_pem"]
    )]
    private_key_pem_file: Option<PathBuf>,
    /// Optional SM2 public key in PEM (verified against derived public key).
    #[arg(long, value_name = "PEM", conflicts_with = "public_key_pem_file")]
    public_key_pem: Option<String>,
    /// Path to a PEM file containing an SM2 public key to verify against the derived key.
    #[arg(long, value_name = "PATH", conflicts_with = "public_key_pem")]
    public_key_pem_file: Option<PathBuf>,
    /// Distinguishing identifier used by the signer (defaults to `1234567812345678`).
    #[arg(long, value_name = "DISTID")]
    distid: Option<String>,
    /// Write the derived JSON payload to a file instead of stdout.
    #[arg(long, value_name = "PATH")]
    output: Option<PathBuf>,
    /// Suppress stdout printing of the JSON payload.
    #[arg(long)]
    quiet: bool,
}
impl Run for Sm2ImportArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let Sm2ImportArgs {
            private_key_hex,
            private_key_file,
            private_key_pem,
            private_key_pem_file,
            public_key_pem,
            public_key_pem_file,
            distid,
            output,
            quiet,
        } = self;
        let distid = parse_distid(distid)?;
        let source = match (
            private_key_hex,
            private_key_file,
            private_key_pem,
            private_key_pem_file,
        ) {
            (Some(hex), None, None, None) => PrivateInput::Hex(hex.trim().to_string()),
            (None, Some(path), None, None) => {
                let data = fs::read_to_string(&path).with_context(|| {
                    format!("failed to read private key from {}", path.display())
                })?;
                PrivateInput::Hex(data.trim().to_string())
            }
            (None, None, Some(pem), None) => PrivateInput::Pem(pem),
            (None, None, None, Some(path)) => {
                let data = fs::read_to_string(&path).with_context(|| {
                    format!("failed to read PKCS#8 private key from {}", path.display())
                })?;
                PrivateInput::Pem(data)
            }
            _ => {
                return Err(eyre!(
                    "provide exactly one of --private-key-hex, --private-key-file, \
 --private-key-pem, or --private-key-pem-file"
                ));
            }
        };
        let private = match source {
            PrivateInput::Hex(hex) => {
                let key_bytes = decode_hex_fixed::<32>("SM2 private key", &hex)?;
                Sm2PrivateKey::from_bytes(distid.clone(), &key_bytes)
                    .wrap_err("invalid SM2 key material")?
            }
            PrivateInput::Pem(pem) => Sm2PrivateKey::from_pkcs8_pem(distid.clone(), pem.trim())
                .wrap_err("invalid SM2 PKCS#8 key")?,
        };
        let provided_public_pem =
            match (public_key_pem, public_key_pem_file) {
                (Some(_), Some(_)) => {
                    return Err(eyre!(
                        "use either --public-key-pem or --public-key-pem-file, not both"
                    ));
                }
                (Some(pem), None) => Some(pem),
                (None, Some(path)) => Some(fs::read_to_string(&path).with_context(|| {
                    format!("failed to read public key from {}", path.display())
                })?),
                (None, None) => None,
            };
        if let Some(pem) = provided_public_pem {
            let provided = Sm2PublicKey::from_public_key_pem(distid.clone(), pem.trim())
                .map_err(|err| eyre!("provided SM2 public key PEM is invalid: {err}"))?;
            if provided.to_sec1_bytes(false) != private.public_key().to_sec1_bytes(false) {
                return Err(eyre!(
                    "provided SM2 public key does not match the derived public key"
                ));
            }
        }
        let material = Sm2KeyMaterial::new(&private);
        if let Some(path) = &output {
            fs::write(path, material.as_json_pretty().as_bytes()).with_context(|| {
                format!("failed to write SM2 key material to {}", path.display())
            })?;
        }
        if !quiet {
            context.print_data(&material.json)?;
        }
        Ok(())
    }
}
#[derive(Args, Debug)]
pub struct Sm2ExportArgs {
    /// Existing SM2 private key in hex (32 bytes).
    #[arg(
        long,
        value_name = "HEX",
        conflicts_with_all = ["private_key_file", "private_key_pem", "private_key_pem_file"]
    )]
    private_key_hex: Option<String>,
    /// Path to a file containing a hex-encoded SM2 private key (32 bytes).
    #[arg(
        long,
        value_name = "PATH",
        conflicts_with_all = ["private_key_hex", "private_key_pem", "private_key_pem_file"]
    )]
    private_key_file: Option<PathBuf>,
    /// PKCS#8 PEM-encoded SM2 private key.
    #[arg(
        long,
        value_name = "PEM",
        conflicts_with_all = ["private_key_hex", "private_key_file", "private_key_pem_file"]
    )]
    private_key_pem: Option<String>,
    /// Path to a PKCS#8 PEM SM2 private key.
    #[arg(
        long,
        value_name = "PATH",
        conflicts_with_all = ["private_key_hex", "private_key_file", "private_key_pem"]
    )]
    private_key_pem_file: Option<PathBuf>,
    /// Distinguishing identifier used by the signer (defaults to `1234567812345678`).
    #[arg(long, value_name = "DISTID")]
    distid: Option<String>,
    /// Write the TOML snippet to a file.
    #[arg(long, value_name = "PATH")]
    snippet_output: Option<PathBuf>,
    /// Emit the JSON key material alongside the config snippet.
    #[arg(long)]
    emit_json: bool,
    /// Suppress stdout output.
    #[arg(long)]
    quiet: bool,
}
impl Run for Sm2ExportArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let distid = parse_distid(self.distid.clone())?;
        let source = match (
            self.private_key_hex,
            self.private_key_file,
            self.private_key_pem,
            self.private_key_pem_file,
        ) {
            (Some(hex), None, None, None) => PrivateInput::Hex(hex.trim().to_string()),
            (None, Some(path), None, None) => {
                let data = fs::read_to_string(&path).with_context(|| {
                    format!("failed to read private key from {}", path.display())
                })?;
                PrivateInput::Hex(data.trim().to_string())
            }
            (None, None, Some(pem), None) => PrivateInput::Pem(pem),
            (None, None, None, Some(path)) => {
                let data = fs::read_to_string(&path).with_context(|| {
                    format!("failed to read PKCS#8 private key from {}", path.display())
                })?;
                PrivateInput::Pem(data)
            }
            _ => {
                return Err(eyre!(
                    "provide exactly one of --private-key-hex, --private-key-file, \
 --private-key-pem, or --private-key-pem-file when exporting SM2 keys"
                ));
            }
        };
        let private = match source {
            PrivateInput::Hex(hex) => {
                let key_bytes = decode_hex_fixed::<32>("SM2 private key", &hex)?;
                Sm2PrivateKey::from_bytes(distid.clone(), &key_bytes)
                    .wrap_err("invalid SM2 key material")?
            }
            PrivateInput::Pem(pem) => Sm2PrivateKey::from_pkcs8_pem(distid.clone(), pem.trim())
                .wrap_err("invalid SM2 PKCS#8 key")?,
        };
        let material = Sm2KeyMaterial::new(&private);
        if let Some(path) = &self.snippet_output {
            fs::write(path, material.snippet.as_bytes())
                .with_context(|| format!("failed to write SM2 snippet to {}", path.display()))?;
        }
        if !self.quiet {
            context.println(material.snippet.trim_end())?;
            if self.emit_json {
                context.print_data(&material.json)?;
            }
        } else if self.emit_json {
            context.print_data(&material.json)?;
        }
        Ok(())
    }
}
#[derive(Args, Debug)]
pub struct Sm3HashArgs {
    /// UTF-8 string to hash (mutually exclusive with other inputs).
    #[arg(long, value_name = "STRING", conflicts_with_all = ["data_hex", "file"])]
    data: Option<String>,
    /// Raw bytes to hash provided as hex.
    #[arg(long, value_name = "HEX", conflicts_with = "file")]
    data_hex: Option<String>,
    /// Path to a file whose contents will be hashed.
    #[arg(long, value_name = "PATH")]
    file: Option<PathBuf>,
    /// Write the digest JSON to a file.
    #[arg(long, value_name = "PATH")]
    output: Option<PathBuf>,
    /// Suppress stdout printing of the digest JSON.
    #[arg(long)]
    quiet: bool,
}
impl Run for Sm3HashArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let message = if let Some(data) = &self.data {
            data.as_bytes().to_vec()
        } else if let Some(hex) = &self.data_hex {
            decode_hex_bytes("message", hex)?
        } else if let Some(file) = &self.file {
            fs::read(file)
                .with_context(|| format!("failed to read data from {}", file.display()))?
        } else {
            return Err(eyre!(
                "provide --data, --data-hex, or --file to hash with SM3"
            ));
        };
        let digest = Sm3Digest::hash(&message);
        let digest_hex = hex::encode_upper(digest.as_bytes());
        let digest_b64 = BASE64.encode(digest.as_bytes());
        let payload = json::object([
            ("algorithm", json::Value::from("sm3")),
            ("digest_hex", json::Value::from(digest_hex)),
            ("digest_b64", json::Value::from(digest_b64)),
        ])
        .expect("static SM3 digest payload");
        if let Some(path) = &self.output {
            fs::write(path, to_pretty_json(&payload).as_bytes())
                .with_context(|| format!("failed to write digest to {}", path.display()))?;
        }
        if !self.quiet {
            context.print_data(&payload)?;
        }
        Ok(())
    }
}
#[derive(Args, Debug)]
pub struct Sm4GcmSealArgs {
    /// SM4 key (16 bytes hex).
    #[arg(long, value_name = "HEX32")]
    key_hex: String,
    /// GCM nonce (12 bytes hex).
    #[arg(long, value_name = "HEX24")]
    nonce_hex: String,
    /// Additional authenticated data (hex, optional).
    #[arg(long, value_name = "HEX", default_value = "")]
    aad_hex: String,
    /// Plaintext to encrypt (hex, mutually exclusive with file).
    #[arg(long, value_name = "HEX", conflicts_with = "plaintext_file")]
    plaintext_hex: Option<String>,
    /// Path to plaintext bytes to encrypt.
    #[arg(long, value_name = "PATH")]
    plaintext_file: Option<PathBuf>,
    /// Write the ciphertext bytes to a file.
    #[arg(long, value_name = "PATH")]
    ciphertext_file: Option<PathBuf>,
    /// Write the authentication tag bytes to a file.
    #[arg(long, value_name = "PATH")]
    tag_file: Option<PathBuf>,
    /// Suppress stdout JSON output.
    #[arg(long)]
    quiet: bool,
}
impl Run for Sm4GcmSealArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let key = decode_hex_fixed::<16>("SM4 key", &self.key_hex)?;
        let nonce = decode_hex_fixed::<12>("SM4 nonce", &self.nonce_hex)?;
        let aad = if self.aad_hex.trim().is_empty() {
            Vec::new()
        } else {
            decode_hex_bytes("aad", &self.aad_hex)?
        };
        let plaintext = load_hex_or_file_bytes(
            self.plaintext_hex.as_ref(),
            self.plaintext_file.as_ref(),
            "plaintext",
        )?;
        let key = Sm4Key::new(key);
        let (ciphertext, tag) = key
            .encrypt_gcm(&nonce, &aad, &plaintext)
            .wrap_err("failed to encrypt with SM4-GCM")?;
        if let Some(path) = &self.ciphertext_file {
            fs::write(path, &ciphertext)
                .with_context(|| format!("failed to write ciphertext to {}", path.display()))?;
        }
        if let Some(path) = &self.tag_file {
            fs::write(path, tag.as_ref())
                .with_context(|| format!("failed to write tag to {}", path.display()))?;
        }
        if !self.quiet {
            let payload = json::object([
                ("algorithm", json::Value::from("sm4-gcm")),
                (
                    "ciphertext_hex",
                    json::Value::from(hex::encode_upper(&ciphertext)),
                ),
                (
                    "ciphertext_b64",
                    json::Value::from(BASE64.encode(&ciphertext)),
                ),
                ("tag_hex", json::Value::from(hex::encode_upper(tag))),
                ("tag_b64", json::Value::from(BASE64.encode(tag))),
            ])
            .expect("static SM4-GCM payload");
            context.print_data(&payload)?;
        }
        Ok(())
    }
}
#[derive(Args, Debug)]
pub struct Sm4GcmOpenArgs {
    /// SM4 key (16 bytes hex).
    #[arg(long, value_name = "HEX32")]
    key_hex: String,
    /// GCM nonce (12 bytes hex).
    #[arg(long, value_name = "HEX24")]
    nonce_hex: String,
    /// Additional authenticated data (hex, optional).
    #[arg(long, value_name = "HEX", default_value = "")]
    aad_hex: String,
    /// Ciphertext to decrypt (hex, mutually exclusive with file).
    #[arg(long, value_name = "HEX", conflicts_with = "ciphertext_file")]
    ciphertext_hex: Option<String>,
    /// Path to ciphertext bytes.
    #[arg(long, value_name = "PATH")]
    ciphertext_file: Option<PathBuf>,
    /// Authentication tag (hex, mutually exclusive with file).
    #[arg(long, value_name = "HEX", conflicts_with = "tag_file")]
    tag_hex: Option<String>,
    /// Path to authentication tag bytes.
    #[arg(long, value_name = "PATH")]
    tag_file: Option<PathBuf>,
    /// Write the decrypted plaintext to a file.
    #[arg(long, value_name = "PATH")]
    plaintext_file: Option<PathBuf>,
    /// Suppress stdout JSON output.
    #[arg(long)]
    quiet: bool,
}
impl Run for Sm4GcmOpenArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let key = decode_hex_fixed::<16>("SM4 key", &self.key_hex)?;
        let nonce = decode_hex_fixed::<12>("SM4 nonce", &self.nonce_hex)?;
        let aad = if self.aad_hex.trim().is_empty() {
            Vec::new()
        } else {
            decode_hex_bytes("aad", &self.aad_hex)?
        };
        let ciphertext = load_hex_or_file_bytes(
            self.ciphertext_hex.as_ref(),
            self.ciphertext_file.as_ref(),
            "ciphertext",
        )?;
        let tag_bytes =
            load_hex_or_file_bytes(self.tag_hex.as_ref(), self.tag_file.as_ref(), "tag")?;
        if tag_bytes.len() != 16 {
            return Err(eyre!(
                "SM4-GCM tag must be 16 bytes (got {} bytes)",
                tag_bytes.len()
            ));
        }
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&tag_bytes);
        let key = Sm4Key::new(key);
        let plaintext = key
            .decrypt_gcm(&nonce, &aad, &ciphertext, &tag)
            .wrap_err("failed to decrypt with SM4-GCM")?;
        if let Some(path) = &self.plaintext_file {
            fs::write(path, &plaintext)
                .with_context(|| format!("failed to write plaintext to {}", path.display()))?;
        }
        if !self.quiet {
            let payload = json::object([
                ("algorithm", json::Value::from("sm4-gcm")),
                (
                    "plaintext_hex",
                    json::Value::from(hex::encode_upper(&plaintext)),
                ),
                (
                    "plaintext_b64",
                    json::Value::from(BASE64.encode(&plaintext)),
                ),
            ])
            .expect("static SM4-GCM decrypt payload");
            context.print_data(&payload)?;
        }
        Ok(())
    }
}
#[derive(Args, Debug)]
pub struct Sm4CcmSealArgs {
    /// SM4 key (16 bytes hex).
    #[arg(long, value_name = "HEX32")]
    key_hex: String,
    /// CCM nonce (7–13 bytes hex).
    #[arg(long, value_name = "HEX14-26")]
    nonce_hex: String,
    /// Additional authenticated data (hex, optional).
    #[arg(long, value_name = "HEX", default_value = "")]
    aad_hex: String,
    /// Plaintext to encrypt (hex, mutually exclusive with file).
    #[arg(long, value_name = "HEX", conflicts_with = "plaintext_file")]
    plaintext_hex: Option<String>,
    /// Path to plaintext bytes to encrypt.
    #[arg(long, value_name = "PATH")]
    plaintext_file: Option<PathBuf>,
    /// CCM authentication tag length (bytes). Supported: 4,6,8,10,12,14,16. Defaults to 16.
    #[arg(long, value_name = "BYTES", default_value_t = 16)]
    tag_len: usize,
    /// Write the ciphertext bytes to a file.
    #[arg(long, value_name = "PATH")]
    ciphertext_file: Option<PathBuf>,
    /// Write the authentication tag bytes to a file.
    #[arg(long, value_name = "PATH")]
    tag_file: Option<PathBuf>,
    /// Suppress stdout JSON output.
    #[arg(long)]
    quiet: bool,
}
impl Run for Sm4CcmSealArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let key = decode_hex_fixed::<16>("SM4 key", &self.key_hex)?;
        let nonce = decode_ccm_nonce(&self.nonce_hex)?;
        let tag_len = normalize_ccm_tag_len(self.tag_len)?;
        let aad = if self.aad_hex.trim().is_empty() {
            Vec::new()
        } else {
            decode_hex_bytes("aad", &self.aad_hex)?
        };
        let plaintext = load_hex_or_file_bytes(
            self.plaintext_hex.as_ref(),
            self.plaintext_file.as_ref(),
            "plaintext",
        )?;
        let key = Sm4Key::new(key);
        let (ciphertext, tag) = key
            .encrypt_ccm(&nonce, &aad, &plaintext, tag_len)
            .wrap_err("failed to encrypt with SM4-CCM")?;
        if let Some(path) = &self.ciphertext_file {
            fs::write(path, &ciphertext)
                .with_context(|| format!("failed to write ciphertext to {}", path.display()))?;
        }
        if let Some(path) = &self.tag_file {
            fs::write(path, &tag)
                .with_context(|| format!("failed to write tag to {}", path.display()))?;
        }
        if !self.quiet {
            let payload = json::object([
                ("algorithm", json::Value::from("sm4-ccm")),
                (
                    "ciphertext_hex",
                    json::Value::from(hex::encode_upper(&ciphertext)),
                ),
                (
                    "ciphertext_b64",
                    json::Value::from(BASE64.encode(&ciphertext)),
                ),
                ("tag_hex", json::Value::from(hex::encode_upper(&tag))),
                ("tag_b64", json::Value::from(BASE64.encode(&tag))),
                ("tag_len", json::Value::from(tag.len())),
            ])
            .expect("static SM4-CCM payload");
            context.print_data(&payload)?;
        }
        Ok(())
    }
}
#[derive(Args, Debug)]
pub struct Sm4CcmOpenArgs {
    /// SM4 key (16 bytes hex).
    #[arg(long, value_name = "HEX32")]
    key_hex: String,
    /// CCM nonce (7–13 bytes hex).
    #[arg(long, value_name = "HEX14-26")]
    nonce_hex: String,
    /// Additional authenticated data (hex, optional).
    #[arg(long, value_name = "HEX", default_value = "")]
    aad_hex: String,
    /// Ciphertext to decrypt (hex, mutually exclusive with file).
    #[arg(long, value_name = "HEX", conflicts_with = "ciphertext_file")]
    ciphertext_hex: Option<String>,
    /// Path to ciphertext bytes.
    #[arg(long, value_name = "PATH")]
    ciphertext_file: Option<PathBuf>,
    /// Authentication tag (hex, mutually exclusive with file).
    #[arg(long, value_name = "HEX", conflicts_with = "tag_file")]
    tag_hex: Option<String>,
    /// Path to authentication tag bytes.
    #[arg(long, value_name = "PATH")]
    tag_file: Option<PathBuf>,
    /// Expected CCM tag length (bytes). If omitted, inferred from the tag input.
    #[arg(long, value_name = "BYTES")]
    tag_len: Option<usize>,
    /// Write the decrypted plaintext to a file.
    #[arg(long, value_name = "PATH")]
    plaintext_file: Option<PathBuf>,
    /// Suppress stdout JSON output.
    #[arg(long)]
    quiet: bool,
}
impl Run for Sm4CcmOpenArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let key = decode_hex_fixed::<16>("SM4 key", &self.key_hex)?;
        let nonce = decode_ccm_nonce(&self.nonce_hex)?;
        let aad = if self.aad_hex.trim().is_empty() {
            Vec::new()
        } else {
            decode_hex_bytes("aad", &self.aad_hex)?
        };
        let ciphertext = load_hex_or_file_bytes(
            self.ciphertext_hex.as_ref(),
            self.ciphertext_file.as_ref(),
            "ciphertext",
        )?;
        let tag = load_hex_or_file_bytes(self.tag_hex.as_ref(), self.tag_file.as_ref(), "tag")?;
        let inferred_len = normalize_ccm_tag_len(tag.len())?;
        if let Some(expected) = self.tag_len
            && expected != inferred_len
        {
            return Err(eyre!(
                "tag length mismatch: expected {expected} bytes, got {inferred_len}"
            ));
        }
        let key = Sm4Key::new(key);
        let plaintext = key
            .decrypt_ccm(&nonce, &aad, &ciphertext, &tag)
            .wrap_err("failed to decrypt with SM4-CCM")?;
        if let Some(path) = &self.plaintext_file {
            fs::write(path, &plaintext)
                .with_context(|| format!("failed to write plaintext to {}", path.display()))?;
        }
        if !self.quiet {
            let payload = json::object([
                ("algorithm", json::Value::from("sm4-ccm")),
                (
                    "plaintext_hex",
                    json::Value::from(hex::encode_upper(&plaintext)),
                ),
                (
                    "plaintext_b64",
                    json::Value::from(BASE64.encode(&plaintext)),
                ),
                ("tag_len", json::Value::from(inferred_len)),
            ])
            .expect("static SM4-CCM decrypt payload");
            context.print_data(&payload)?;
        }
        Ok(())
    }
}
struct Sm2KeyMaterial {
    json: json::Value,
    snippet: String,
}
impl Sm2KeyMaterial {
    fn new(private: &Sm2PrivateKey) -> Self {
        let artifacts = collect_sm2_artifacts(private);
        let json = json::object([
            ("algorithm", json::Value::from("sm2")),
            ("distid", json::Value::from(artifacts.distid.clone())),
            (
                "private_key_hex",
                json::Value::from(artifacts.private_key_hex.clone()),
            ),
            (
                "private_key_b64",
                json::Value::from(artifacts.private_key_b64.clone()),
            ),
            (
                "private_key_config",
                json::Value::from(artifacts.private_key_config.clone()),
            ),
            (
                "private_key_pem",
                json::Value::from(artifacts.private_key_pem.clone()),
            ),
            (
                "public_key_sec1_hex",
                json::Value::from(artifacts.public_key_hex.clone()),
            ),
            (
                "public_key_sec1_compressed_hex",
                json::Value::from(artifacts.public_key_compressed_hex.clone()),
            ),
            (
                "public_key_b64",
                json::Value::from(artifacts.public_key_b64.clone()),
            ),
            (
                "public_key_config",
                json::Value::from(artifacts.public_key_config.clone()),
            ),
            (
                "public_key_pem",
                json::Value::from(artifacts.public_key_pem.clone()),
            ),
        ])
        .expect("static SM2 key payload");
        let snippet = render_sm2_snippet(&artifacts);
        Self { json, snippet }
    }
    fn as_json_pretty(&self) -> String {
        to_pretty_json(&self.json)
    }
}
struct Sm2Artifacts {
    distid: String,
    private_key_hex: String,
    private_key_b64: String,
    private_key_config: String,
    private_key_pem: String,
    public_key_hex: String,
    public_key_b64: String,
    public_key_compressed_hex: String,
    public_key_config: String,
    public_key_pem: String,
}
fn collect_sm2_artifacts(private: &Sm2PrivateKey) -> Sm2Artifacts {
    let distid = private.distid().to_string();
    let mut secret = private.secret_bytes();
    let private_key_hex = hex::encode_upper(secret.as_ref());
    let private_key_b64 = BASE64.encode(secret.as_ref());
    let private_key_config = encode_sm2_private_key_payload(&distid, &secret)
        .ok()
        .and_then(|payload| PrivateKey::from_bytes(Algorithm::Sm2, &payload).ok())
        .map_or_else(|| "<unavailable>".to_string(), |pk| pk.to_string());
    let private_key_pem = private
        .to_pkcs8_pem()
        .unwrap_or_else(|_| "<unavailable>".to_string());
    let public = private.public_key();
    let public_bytes = public.to_sec1_bytes(false);
    let public_compressed = public.to_sec1_bytes(true);
    let public_key_hex = hex::encode_upper(&public_bytes);
    let public_key_b64 = BASE64.encode(&public_bytes);
    let public_key_compressed_hex = hex::encode_upper(&public_compressed);
    let public_key_config = encode_sm2_public_key_payload(&distid, &public_bytes)
        .ok()
        .and_then(|payload| PublicKey::from_bytes(Algorithm::Sm2, &payload).ok())
        .map_or_else(|| "<unavailable>".to_string(), |pk| pk.to_string());
    let public_key_pem = public
        .to_public_key_pem()
        .unwrap_or_else(|_| "<unavailable>".to_string());
    secret.zeroize();
    Sm2Artifacts {
        distid,
        private_key_hex,
        private_key_b64,
        private_key_config,
        private_key_pem,
        public_key_hex,
        public_key_b64,
        public_key_compressed_hex,
        public_key_config,
        public_key_pem,
    }
}
fn render_sm2_snippet(artifacts: &Sm2Artifacts) -> String {
    format!(
        r#"# Account key material
public_key = "{public_key}"
private_key = "{private_key}"
# public_key_pem = \"\"\"\
{public_key_pem}\"\"\"
# private_key_pem = \"\"\"\
{private_key_pem}\"\"\"

[crypto]
default_hash = "sm3-256"
allowed_signing = ["ed25519", "sm2"]  # remove "sm2" to stay in verify-only mode
sm2_distid_default = "{distid}"
# enable_sm_openssl_preview = true  # optional: only when deploying the OpenSSL/Tongsuo path
"#,
        public_key = artifacts.public_key_config,
        private_key = artifacts.private_key_hex,
        public_key_pem = artifacts.public_key_pem.trim_end(),
        private_key_pem = artifacts.private_key_pem.trim_end(),
        distid = artifacts.distid
    )
}
fn parse_distid(distid: Option<String>) -> Result<String> {
    let value = distid
        .map(|d| d.trim().to_string())
        .filter(|d| !d.is_empty())
        .unwrap_or_else(Sm2PublicKey::default_distid);
    if value.trim().is_empty() {
        return Err(eyre!("distid must not be empty"));
    }
    Ok(value)
}
fn decode_hex_bytes(label: &str, raw: &str) -> Result<Vec<u8>> {
    let trimmed = raw.trim();
    let without_prefix = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    hex::decode(without_prefix).with_context(|| format!("{label} is not valid hex"))
}
fn decode_hex_fixed<const N: usize>(label: &str, raw: &str) -> Result<[u8; N]> {
    let bytes = decode_hex_bytes(label, raw)?;
    if bytes.len() != N {
        return Err(eyre!(
            "{label} must be {N} bytes (got {} bytes)",
            bytes.len()
        ));
    }
    let mut arr = [0u8; N];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}
fn decode_ccm_nonce(raw: &str) -> Result<Vec<u8>> {
    let nonce = decode_hex_bytes("SM4-CCM nonce", raw)?;
    if (7..=13).contains(&nonce.len()) {
        Ok(nonce)
    } else {
        Err(eyre!(
            "SM4-CCM nonce must be between 7 and 13 bytes (got {} bytes)",
            nonce.len()
        ))
    }
}
fn normalize_ccm_tag_len(len: usize) -> Result<usize> {
    match len {
        4 | 6 | 8 | 10 | 12 | 14 | 16 => Ok(len),
        other => Err(eyre!(
            "SM4-CCM tag length must be one of {{4,6,8,10,12,14,16}} bytes (got {other})"
        )),
    }
}
fn load_hex_or_file_bytes(
    hex: Option<&String>,
    file: Option<&PathBuf>,
    label: &str,
) -> Result<Vec<u8>> {
    match (hex, file) {
        (Some(hex), None) => decode_hex_bytes(label, hex),
        (None, Some(path)) => fs::read(path)
            .with_context(|| format!("failed to read {label} from {}", path.display())),
        (Some(_), Some(_)) => Err(eyre!(
            "use either --{label}-hex or --{label}-file, not both"
        )),
        (None, None) => Err(eyre!("provide --{label}-hex or --{label}-file")),
    }
}
fn to_pretty_json(value: &json::Value) -> String {
    norito::json::to_json_pretty(value).expect("SM payloads serialize")
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::RunContext;
    use eyre::{Result, eyre};
    use iroha::{
        config::Config,
        crypto::{Algorithm, KeyPair},
        data_model::prelude::*,
    };
    use iroha_i18n::{Bundle, Language, Localizer};
    use iroha_model_base::chain::ChainId;
    use iroha_model_base::metadata::Metadata;
    use norito::json::{self, JsonSerialize};
    use rand::rand_core::{TryCryptoRng, TryRngCore};
    use std::fmt;
    use url::Url;
    struct FailingSm2SeedRng;
    #[derive(Debug)]
    struct FailingSm2SeedRngError;
    impl fmt::Display for FailingSm2SeedRngError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("failing SM2 seed RNG")
        }
    }
    impl TryRngCore for FailingSm2SeedRng {
        type Error = FailingSm2SeedRngError;
        fn try_next_u32(&mut self) -> std::result::Result<u32, Self::Error> {
            Err(FailingSm2SeedRngError)
        }
        fn try_next_u64(&mut self) -> std::result::Result<u64, Self::Error> {
            Err(FailingSm2SeedRngError)
        }
        fn try_fill_bytes(&mut self, _dst: &mut [u8]) -> std::result::Result<(), Self::Error> {
            Err(FailingSm2SeedRngError)
        }
    }
    impl TryCryptoRng for FailingSm2SeedRng {}
    #[test]
    fn sm2_keygen_seed_produces_expected_public_key() {
        let mut ctx = TestContext::new();
        let args = Sm2KeygenArgs {
            distid: Some("CN12345678901234".to_string()),
            seed_hex: Some(
                "00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF".into(),
            ),
            output: None,
            quiet: false,
        };
        args.run(&mut ctx).expect("sm2 keygen");
        assert_eq!(ctx.json_outputs.len(), 1);
        let value: json::Value = json::from_str(&ctx.json_outputs[0]).expect("valid JSON output");
        let obj = value.as_object().expect("object");
        assert_eq!(
            obj.get("distid").expect("distid").as_str().expect("string"),
            "CN12345678901234"
        );
        assert!(
            !obj.get("public_key_sec1_hex")
                .and_then(|v| v.as_str())
                .expect("public hex")
                .is_empty()
        );
        let public_pem = obj
            .get("public_key_pem")
            .and_then(|v| v.as_str())
            .expect("public pem");
        assert!(
            public_pem.contains("BEGIN PUBLIC KEY"),
            "public key PEM missing header"
        );
        let private_pem = obj
            .get("private_key_pem")
            .and_then(|v| v.as_str())
            .expect("private pem");
        assert!(
            private_pem.contains("BEGIN PRIVATE KEY"),
            "private key PEM missing header"
        );
    }
    #[test]
    fn sm2_keygen_random_reports_rng_failure() {
        let args = Sm2KeygenArgs {
            distid: Some("CN12345678901234".to_string()),
            seed_hex: None,
            output: None,
            quiet: false,
        };
        let mut rng = FailingSm2SeedRng;
        let error = match args.material_with_rng(&mut rng) {
            Ok(_) => panic!("random SM2 keygen should fail when entropy fails"),
            Err(error) => error,
        };
        let message = format!("{error:?}");
        assert!(message.contains("failed to generate random SM2 seed"));
        assert!(message.contains("failing SM2 seed RNG"));
    }
    #[test]
    fn sm2_import_accepts_pkcs8_pem() {
        let private =
            Sm2PrivateKey::from_seed("cli-import-pem", b"cli-import-pem").expect("seeded key");
        let private_pem = private.to_pkcs8_pem().expect("encode pem");
        let public_pem = private
            .public_key()
            .to_public_key_pem()
            .expect("public pem");
        let mut ctx = TestContext::new();
        Sm2ImportArgs {
            private_key_hex: None,
            private_key_file: None,
            private_key_pem: Some(private_pem),
            private_key_pem_file: None,
            public_key_pem: Some(public_pem),
            public_key_pem_file: None,
            distid: Some("cli-import-pem".into()),
            output: None,
            quiet: false,
        }
        .run(&mut ctx)
        .expect("import sm2 pem");
        assert_eq!(ctx.json_outputs.len(), 1);
        let value: json::Value = json::from_str(&ctx.json_outputs[0]).expect("valid JSON");
        let obj = value.as_object().expect("object");
        assert_eq!(
            obj.get("distid").and_then(|v| v.as_str()).expect("distid"),
            "cli-import-pem"
        );
    }
    #[test]
    fn sm2_import_rejects_mismatched_public_key() {
        let private =
            Sm2PrivateKey::from_seed("cli-import-pem", b"cli-import-pem").expect("seeded key");
        let private_pem = private.to_pkcs8_pem().expect("encode pem");
        let other_public = Sm2PrivateKey::from_seed("other", b"other-key")
            .expect("other")
            .public_key()
            .to_public_key_pem()
            .expect("other public pem");
        let mut ctx = TestContext::new();
        let err = Sm2ImportArgs {
            private_key_hex: None,
            private_key_file: None,
            private_key_pem: Some(private_pem),
            private_key_pem_file: None,
            public_key_pem: Some(other_public),
            public_key_pem_file: None,
            distid: Some("cli-import-pem".into()),
            output: None,
            quiet: false,
        }
        .run(&mut ctx)
        .expect_err("mismatched public key should fail");
        assert!(
            err.to_string()
                .contains("does not match the derived public key"),
            "unexpected error message: {err}"
        );
    }
    #[test]
    fn sm2_export_snippet_includes_pem_blobs() {
        let private =
            Sm2PrivateKey::from_seed("cli-export-pem", b"cli-export-pem").expect("seeded key");
        let private_hex = hex::encode_upper(private.secret_bytes());
        let mut ctx = TestContext::new();
        Sm2ExportArgs {
            private_key_hex: Some(private_hex),
            private_key_file: None,
            private_key_pem: None,
            private_key_pem_file: None,
            distid: Some("cli-export-pem".into()),
            snippet_output: None,
            emit_json: false,
            quiet: false,
        }
        .run(&mut ctx)
        .expect("export sm2");
        assert_eq!(ctx.lines.len(), 1);
        let snippet = &ctx.lines[0];
        assert!(
            snippet.contains("BEGIN PUBLIC KEY"),
            "snippet missing public key PEM block"
        );
        assert!(
            snippet.contains("BEGIN PRIVATE KEY"),
            "snippet missing private key PEM block"
        );
        assert!(
            snippet.contains("[crypto]"),
            "snippet missing crypto section header: {snippet}"
        );
        assert!(
            snippet.contains("default_hash = \"sm3-256\""),
            "snippet missing default_hash guidance: {snippet}"
        );
        assert!(
            snippet.contains("allowed_signing = [\"ed25519\", \"sm2\"]"),
            "snippet missing allowed_signing guidance: {snippet}"
        );
    }
    #[test]
    fn sm2_export_accepts_pkcs8_pem_input() {
        let private =
            Sm2PrivateKey::from_seed("cli-export-pem", b"cli-export-pem").expect("seeded key");
        let private_pem = private.to_pkcs8_pem().expect("encode pem");
        let mut ctx = TestContext::new();
        Sm2ExportArgs {
            private_key_hex: None,
            private_key_file: None,
            private_key_pem: Some(private_pem),
            private_key_pem_file: None,
            distid: Some("cli-export-pem".into()),
            snippet_output: None,
            emit_json: false,
            quiet: false,
        }
        .run(&mut ctx)
        .expect("export sm2 from pem");
        assert!(!ctx.lines.is_empty(), "expected snippet output from export");
    }
    #[test]
    fn sm3_hash_string_matches_known_vector() {
        let mut ctx = TestContext::new();
        let args = Sm3HashArgs {
            data: Some("iroha".into()),
            data_hex: None,
            file: None,
            output: None,
            quiet: false,
        };
        args.run(&mut ctx).expect("sm3 hash");
        let value: json::Value = json::from_str(&ctx.json_outputs[0]).expect("valid JSON output");
        let obj = value.as_object().expect("object");
        let digest = obj
            .get("digest_hex")
            .and_then(|v| v.as_str())
            .expect("digest hex");
        assert_eq!(
            digest,
            "1DD3CF971A92489A81DDFBD884CD4D4886D34F752C190F36A40FF9DF03BE5E19"
        );
    }
    #[test]
    fn sm4_gcm_roundtrip() {
        let key = "00112233445566778899AABBCCDDEEFF";
        let nonce = "0102030405060708090A0B0C";
        let plaintext_hex = "DEADBEEF";
        let mut ctx = TestContext::new();
        Sm4GcmSealArgs {
            key_hex: key.into(),
            nonce_hex: nonce.into(),
            aad_hex: String::new(),
            plaintext_hex: Some(plaintext_hex.into()),
            plaintext_file: None,
            ciphertext_file: None,
            tag_file: None,
            quiet: false,
        }
        .run(&mut ctx)
        .expect("sm4 seal");
        assert_eq!(ctx.json_outputs.len(), 1);
        let seal_value: json::Value = json::from_str(&ctx.json_outputs[0]).expect("seal json");
        let seal_obj = seal_value.as_object().expect("object");
        let ciphertext_hex = seal_obj
            .get("ciphertext_hex")
            .and_then(|v| v.as_str())
            .expect("ciphertext");
        let tag_hex = seal_obj
            .get("tag_hex")
            .and_then(|v| v.as_str())
            .expect("tag");
        let mut ctx_open = TestContext::new();
        Sm4GcmOpenArgs {
            key_hex: key.into(),
            nonce_hex: nonce.into(),
            aad_hex: String::new(),
            ciphertext_hex: Some(ciphertext_hex.into()),
            ciphertext_file: None,
            tag_hex: Some(tag_hex.into()),
            tag_file: None,
            plaintext_file: None,
            quiet: false,
        }
        .run(&mut ctx_open)
        .expect("sm4 open");
        let open_value: json::Value = json::from_str(&ctx_open.json_outputs[0]).expect("open json");
        let open_obj = open_value.as_object().expect("object");
        assert_eq!(
            open_obj
                .get("plaintext_hex")
                .and_then(|v| v.as_str())
                .expect("plaintext"),
            plaintext_hex
        );
    }
    #[test]
    fn sm4_ccm_roundtrip() {
        let key = "00112233445566778899AABBCCDDEEFF";
        let nonce = "01020304050607";
        let plaintext_hex = "CAFEF00D";
        let mut ctx = TestContext::new();
        Sm4CcmSealArgs {
            key_hex: key.into(),
            nonce_hex: nonce.into(),
            aad_hex: String::new(),
            plaintext_hex: Some(plaintext_hex.into()),
            plaintext_file: None,
            tag_len: 10,
            ciphertext_file: None,
            tag_file: None,
            quiet: false,
        }
        .run(&mut ctx)
        .expect("sm4 ccm seal");
        assert_eq!(ctx.json_outputs.len(), 1);
        let seal_value: json::Value = json::from_str(&ctx.json_outputs[0]).expect("seal json");
        let seal_obj = seal_value.as_object().expect("object");
        let ciphertext_hex = seal_obj
            .get("ciphertext_hex")
            .and_then(|v| v.as_str())
            .expect("ciphertext");
        let tag_hex = seal_obj
            .get("tag_hex")
            .and_then(|v| v.as_str())
            .expect("tag");
        let mut ctx_open = TestContext::new();
        Sm4CcmOpenArgs {
            key_hex: key.into(),
            nonce_hex: nonce.into(),
            aad_hex: String::new(),
            ciphertext_hex: Some(ciphertext_hex.into()),
            ciphertext_file: None,
            tag_hex: Some(tag_hex.into()),
            tag_file: None,
            tag_len: Some(10),
            plaintext_file: None,
            quiet: false,
        }
        .run(&mut ctx_open)
        .expect("sm4 ccm open");
        let open_value: json::Value = json::from_str(&ctx_open.json_outputs[0]).expect("open json");
        let open_obj = open_value.as_object().expect("object");
        assert_eq!(
            open_obj
                .get("plaintext_hex")
                .and_then(|v| v.as_str())
                .expect("plaintext"),
            plaintext_hex
        );
    }
    struct TestContext {
        cfg: Config,
        json_outputs: Vec<String>,
        lines: Vec<String>,
        i18n: Localizer,
    }
    impl TestContext {
        fn new() -> Self {
            let key_pair = checked_crypto_ed25519_key_fixture();
            let account_id = AccountId::new(key_pair.public_key().clone());
            let cfg = Config {
                chain: ChainId::from("00000000-0000-0000-0000-000000000000"),
                network_id:
                    "hash:32C903E5B3497E34C2B844EBFE8A39C19E6CF8F95D44C1FFB8BA9DCB42F91149#A2F0"
                        .parse()
                        .expect("network id"),
                account: account_id,
                account_chain_discriminant:
                    iroha_config::parameters::defaults::common::chain_discriminant(),
                key_pair,
                basic_auth: None,
                api_token: None,
                http_transport_policy: iroha::config::HttpTransportPolicy::Ordinary,
                torii_api_url: Url::parse("http://127.0.0.1/").unwrap(),
                torii_request_timeout: iroha::config::DEFAULT_TORII_REQUEST_TIMEOUT,
                transaction_ttl: iroha::config::DEFAULT_TRANSACTION_TIME_TO_LIVE,
                transaction_status_timeout: iroha::config::DEFAULT_TRANSACTION_STATUS_TIMEOUT,
                transaction_add_nonce: iroha::config::DEFAULT_TRANSACTION_NONCE,
                sorafs_alias_cache: crate::config_utils::default_alias_cache_policy(),
                sorafs_anonymity_policy: crate::config_utils::default_anonymity_policy(),
                sorafs_rollout_phase: crate::config_utils::default_rollout_phase(),
            };
            Self {
                cfg,
                json_outputs: Vec::new(),
                lines: Vec::new(),
                i18n: Localizer::new(Bundle::Cli, Language::English),
            }
        }
    }
    fn checked_crypto_ed25519_key_fixture() -> KeyPair {
        KeyPair::try_random_with_algorithm(Algorithm::Ed25519)
            .expect("generate checked crypto fixture key")
    }
    #[test]
    fn crypto_fixture_uses_checked_ed25519_key_generation() {
        let key_pair = checked_crypto_ed25519_key_fixture();
        let actual = key_pair
            .public_key()
            .try_algorithm()
            .expect("crypto fixture key advertises a valid algorithm");
        assert_eq!(actual, Algorithm::Ed25519);
    }
    impl RunContext for TestContext {
        fn config(&self) -> &Config {
            &self.cfg
        }
        fn transaction_metadata(&self) -> Option<&Metadata> {
            None
        }
        fn input_instructions(&self) -> bool {
            false
        }
        fn output_instructions(&self) -> bool {
            false
        }
        fn i18n(&self) -> &Localizer {
            &self.i18n
        }
        fn print_data<T>(&mut self, data: &T) -> Result<()>
        where
            T: JsonSerialize + ?Sized,
        {
            let json = norito::json::to_json_pretty(data).map_err(|err| eyre!(err.to_string()))?;
            self.json_outputs.push(json);
            Ok(())
        }
        fn println(&mut self, data: impl std::fmt::Display) -> Result<()> {
            self.lines.push(data.to_string());
            Ok(())
        }
    }
    #[test]
    fn sm2_parse_distid_defaults_to_runtime_value() {
        struct DistidGuard(String);
        impl Drop for DistidGuard {
            fn drop(&mut self) {
                Sm2PublicKey::set_default_distid(self.0.clone()).expect("restore default distid");
            }
        }
        let original = Sm2PublicKey::default_distid();
        let _guard = DistidGuard(original.clone());
        Sm2PublicKey::set_default_distid("runtime-default-test").expect("override distid");
        let parsed = super::parse_distid(None).expect("parse distid");
        assert_eq!(parsed, "runtime-default-test");
    }
}
