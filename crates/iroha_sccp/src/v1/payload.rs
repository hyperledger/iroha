//! SCCP v1 transfer payload codec (spec §3.1, §3.2).
//!
//! The payload is a fixed big-endian layout that destination contracts parse from calldata or
//! cells without byte swaps:
//!
//! ```text
//! u8 kind = 0x02 ‖ u8 version = 0x01 ‖ u32 source_domain ‖ u32 dest_domain ‖ u64 nonce
//! ‖ u32 route_revision ‖ u64 deadline_ms ‖ u32 asset_home_domain = 0
//! ‖ u8 asset_id_codec = 1 ‖ u16 len ‖ "xor" ‖ u128 amount
//! ‖ u8 sender_codec ‖ u16 len ‖ sender ‖ u8 recipient_codec ‖ u16 len ‖ recipient
//! ‖ u8 route_id_codec = 1 ‖ u16 len ‖ route_id
//! ```
//!
//! [`SccpTransferPayloadV1::decode`] enforces every §3.1/§3.2 rule and rejects trailing bytes;
//! [`SccpTransferPayloadV1::encode`] validates the same rules before writing, so the two are
//! exact inverses on valid payloads.

use iroha_data_model::bridge::SccpNetworkV1;

use super::{
    amount::check_lane_amount,
    constants::{
        ASSET_ID_XOR, CODEC_CANONICAL_TEXT, CODEC_EVM_ADDRESS20, CODEC_TAIRA_ACCOUNT,
        CODEC_TON_ACCOUNT36, MAX_CANONICAL_TEXT_BYTES, MAX_PAYLOAD_BYTES, MAX_TAIRA_ACCOUNT_BYTES,
        PAYLOAD_KIND_TRANSFER, PAYLOAD_VERSION,
    },
    hashes,
    network::{self, account_codec, network_from_domain},
};

/// Encoded bytes before the sender value (everything through the sender length prefix).
pub const PAYLOAD_HEAD_BYTES: usize = 59;

unit_error! {
    /// Violations of the §3.1/§3.2 payload rules.
    pub enum PayloadError {
        /// The input ends before a field is complete.
        Truncated => "payload is truncated",
        /// Bytes follow the route id.
        TrailingBytes => "payload has trailing bytes",
        /// The encoded payload exceeds 4096 bytes.
        TooLong => "payload exceeds 4096 bytes",
        /// The kind byte is not `0x02`.
        WrongKind => "payload kind must be 0x02 (transfer)",
        /// The version byte is not `0x01`.
        WrongVersion => "payload version must be 0x01",
        /// The domains are equal, both external, or unknown.
        BadDomains => "payload domains must be distinct known domains with exactly one Taira endpoint",
        /// `deadline_ms` is zero on an outbound payload or nonzero on an inbound one.
        DeadlineMismatch => "deadline_ms must be nonzero iff the source is Taira",
        /// `route_revision` is zero.
        ZeroRevision => "route_revision must be nonzero",
        /// The asset home domain, codec or id is not Taira XOR.
        BadAsset => "asset must be home domain 0, codec 1, id \"xor\"",
        /// `amount` is zero.
        ZeroAmount => "amount must be nonzero",
        /// `amount` is `2^96` or more on a TON lane.
        TonAmountBound => "amount must be below 2^96 when TON is an endpoint",
        /// The sender codec does not match the direction table.
        WrongSenderCodec => "sender codec does not match the lane direction",
        /// The recipient codec does not match the direction table.
        WrongRecipientCodec => "recipient codec does not match the lane direction",
        /// The sender bytes are invalid for their codec.
        BadSender => "sender bytes are invalid for their codec",
        /// The recipient bytes are invalid for their codec.
        BadRecipient => "recipient bytes are invalid for their codec",
        /// The route id codec is not 1 or its text is not canonical.
        BadRouteId => "route_id must be codec 1 printable ASCII of 1..=256 bytes",
        /// `route_id` is not the route of the external endpoint.
        RouteMismatch => "route_id does not name the route of the external endpoint",
        /// A variable field is longer than a `u16` length prefix can express.
        FieldTooLong => "variable field exceeds the u16 length prefix",
    }
}

/// An account field: codec tag and raw bytes (§3.1).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PayloadAccountV1 {
    /// Codec tag (§3.1).
    pub codec: u8,
    /// Raw account bytes, valid for `codec`.
    pub bytes: Vec<u8>,
}

impl PayloadAccountV1 {
    /// Construct an account field.
    #[must_use]
    pub fn new(codec: u8, bytes: Vec<u8>) -> Self {
        Self { codec, bytes }
    }

    /// Whether `bytes` satisfies the length and validity rule of `codec` (§3.1).
    #[must_use]
    pub fn is_valid(&self) -> bool {
        is_valid_account(self.codec, &self.bytes)
    }
}

/// Whether `bytes` satisfies the §3.1 rule of `codec`.
///
/// Codec 1 is printable ASCII of 1..=256 bytes; 2 is 20 nonzero bytes; 3 is 1..=1024 bytes
/// (Taira decodes the `AccountAddress` itself); 7 is a big-endian `i32` workchain 0 then a
/// nonzero 32-byte account id. Codecs 4, 5, 6 and every other value are unassigned; codec 5
/// belonged to the removed TRON profile.
#[must_use]
pub fn is_valid_account(codec: u8, bytes: &[u8]) -> bool {
    match codec {
        CODEC_CANONICAL_TEXT => is_canonical_text(bytes),
        CODEC_EVM_ADDRESS20 => bytes.len() == 20 && bytes.iter().any(|byte| *byte != 0),
        CODEC_TAIRA_ACCOUNT => (1..=MAX_TAIRA_ACCOUNT_BYTES).contains(&bytes.len()),
        CODEC_TON_ACCOUNT36 => {
            bytes.len() == 36 && bytes[..4] == [0; 4] && bytes[4..].iter().any(|byte| *byte != 0)
        }
        _ => false,
    }
}

/// Whether `bytes` is canonical text: 1..=256 bytes of printable ASCII `0x21..=0x7e`.
#[must_use]
pub fn is_canonical_text(bytes: &[u8]) -> bool {
    (1..=MAX_CANONICAL_TEXT_BYTES).contains(&bytes.len())
        && bytes.iter().all(|byte| (0x21..=0x7e).contains(byte))
}

/// The SCCP v1 transfer payload (§3.2). Kind, version and the XOR asset fields are constant.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SccpTransferPayloadV1 {
    /// Domain where the transfer is locked or burned.
    pub source_domain: u32,
    /// Domain where the transfer is minted or released.
    pub dest_domain: u32,
    /// Dense per-revision outbound nonce, or the source contract's burn nonce.
    pub nonce: u64,
    /// Nonzero route revision.
    pub route_revision: u32,
    /// Destination-time mint deadline for Taira → X; zero for X → Taira.
    pub deadline_ms: u64,
    /// Amount in Taira units (= destination token units).
    pub amount: u128,
    /// Sender account on the source network.
    pub sender: PayloadAccountV1,
    /// Recipient account on the destination network.
    pub recipient: PayloadAccountV1,
    /// Route id text of the external endpoint.
    pub route_id: String,
}

impl SccpTransferPayloadV1 {
    /// Build and validate a Taira → `target` payload (`sender_codec 3`).
    ///
    /// # Errors
    ///
    /// Returns [`PayloadError`] when `target` is Taira or any §3.2 rule fails.
    pub fn outbound(
        target: SccpNetworkV1,
        nonce: u64,
        route_revision: u32,
        deadline_ms: u64,
        amount: u128,
        sender: Vec<u8>,
        recipient: Vec<u8>,
    ) -> Result<Self, PayloadError> {
        let route_id = network::route_id(target).ok_or(PayloadError::BadDomains)?;
        let payload = Self {
            source_domain: network::domain(SccpNetworkV1::SoraTaira),
            dest_domain: network::domain(target),
            nonce,
            route_revision,
            deadline_ms,
            amount,
            sender: PayloadAccountV1::new(CODEC_TAIRA_ACCOUNT, sender),
            recipient: PayloadAccountV1::new(account_codec(target), recipient),
            route_id: route_id.to_owned(),
        };
        payload.validate()?;
        Ok(payload)
    }

    /// Build and validate a `source` → Taira payload (`recipient_codec 3`, `deadline_ms 0`).
    ///
    /// # Errors
    ///
    /// Returns [`PayloadError`] when `source` is Taira or any §3.2 rule fails.
    pub fn inbound(
        source: SccpNetworkV1,
        nonce: u64,
        route_revision: u32,
        amount: u128,
        sender: Vec<u8>,
        recipient: Vec<u8>,
    ) -> Result<Self, PayloadError> {
        let route_id = network::route_id(source).ok_or(PayloadError::BadDomains)?;
        let payload = Self {
            source_domain: network::domain(source),
            dest_domain: network::domain(SccpNetworkV1::SoraTaira),
            nonce,
            route_revision,
            deadline_ms: 0,
            amount,
            sender: PayloadAccountV1::new(account_codec(source), sender),
            recipient: PayloadAccountV1::new(CODEC_TAIRA_ACCOUNT, recipient),
            route_id: route_id.to_owned(),
        };
        payload.validate()?;
        Ok(payload)
    }

    /// Source profile, if the domain is known.
    #[must_use]
    pub fn source(&self) -> Option<SccpNetworkV1> {
        network_from_domain(self.source_domain)
    }

    /// Destination profile, if the domain is known.
    #[must_use]
    pub fn target(&self) -> Option<SccpNetworkV1> {
        network_from_domain(self.dest_domain)
    }

    /// Whether this is a Taira → external payload.
    #[must_use]
    pub fn is_outbound(&self) -> bool {
        self.source_domain == network::domain(SccpNetworkV1::SoraTaira)
    }

    /// The external endpoint of a well-formed lane.
    ///
    /// # Errors
    ///
    /// Returns [`PayloadError::BadDomains`] unless exactly one endpoint is Taira and both
    /// domains are known.
    pub fn external_network(&self) -> Result<SccpNetworkV1, PayloadError> {
        let (Some(source), Some(target)) = (self.source(), self.target()) else {
            return Err(PayloadError::BadDomains);
        };
        match (source.is_sora(), target.is_sora()) {
            (true, false) => Ok(target),
            (false, true) => Ok(source),
            _ => Err(PayloadError::BadDomains),
        }
    }

    /// Check every §3.1/§3.2 rule except the total length (see [`Self::encode`]).
    ///
    /// # Errors
    ///
    /// Returns the first violated [`PayloadError`] in layout order.
    pub fn validate(&self) -> Result<(), PayloadError> {
        let external = self.external_network()?;
        let source = self.source().ok_or(PayloadError::BadDomains)?;
        let target = self.target().ok_or(PayloadError::BadDomains)?;
        if self.route_revision == 0 {
            return Err(PayloadError::ZeroRevision);
        }
        if (self.deadline_ms != 0) != source.is_sora() {
            return Err(PayloadError::DeadlineMismatch);
        }
        if self.amount == 0 {
            return Err(PayloadError::ZeroAmount);
        }
        if check_lane_amount(self.amount, source, target).is_err() {
            return Err(PayloadError::TonAmountBound);
        }
        if self.sender.codec != account_codec(source) {
            return Err(PayloadError::WrongSenderCodec);
        }
        if !self.sender.is_valid() {
            return Err(PayloadError::BadSender);
        }
        if self.recipient.codec != account_codec(target) {
            return Err(PayloadError::WrongRecipientCodec);
        }
        if !self.recipient.is_valid() {
            return Err(PayloadError::BadRecipient);
        }
        if !is_canonical_text(self.route_id.as_bytes()) {
            return Err(PayloadError::BadRouteId);
        }
        if network::route_id(external) != Some(self.route_id.as_str()) {
            return Err(PayloadError::RouteMismatch);
        }
        Ok(())
    }

    /// Encoded length of this payload.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        PAYLOAD_HEAD_BYTES
            + self.sender.bytes.len()
            + 3
            + self.recipient.bytes.len()
            + 3
            + self.route_id.len()
    }

    /// Validate and encode (§3.2).
    ///
    /// # Errors
    ///
    /// Returns [`PayloadError`] when any rule fails or the result exceeds 4096 bytes.
    pub fn encode(&self) -> Result<Vec<u8>, PayloadError> {
        self.validate()?;
        if self.encoded_len() > MAX_PAYLOAD_BYTES {
            return Err(PayloadError::TooLong);
        }
        self.encode_unvalidated()
    }

    /// Write the §3.2 layout without checking the semantic rules.
    ///
    /// Intended for building negative test vectors; production code uses [`Self::encode`].
    ///
    /// # Errors
    ///
    /// Returns [`PayloadError::FieldTooLong`] when a variable field exceeds `u16::MAX` bytes.
    pub fn encode_unvalidated(&self) -> Result<Vec<u8>, PayloadError> {
        let mut out = Vec::with_capacity(self.encoded_len());
        out.push(PAYLOAD_KIND_TRANSFER);
        out.push(PAYLOAD_VERSION);
        out.extend_from_slice(&self.source_domain.to_be_bytes());
        out.extend_from_slice(&self.dest_domain.to_be_bytes());
        out.extend_from_slice(&self.nonce.to_be_bytes());
        out.extend_from_slice(&self.route_revision.to_be_bytes());
        out.extend_from_slice(&self.deadline_ms.to_be_bytes());
        out.extend_from_slice(&0_u32.to_be_bytes());
        push_field(&mut out, CODEC_CANONICAL_TEXT, ASSET_ID_XOR.as_bytes())?;
        out.extend_from_slice(&self.amount.to_be_bytes());
        push_field(&mut out, self.sender.codec, &self.sender.bytes)?;
        push_field(&mut out, self.recipient.codec, &self.recipient.bytes)?;
        push_field(&mut out, CODEC_CANONICAL_TEXT, self.route_id.as_bytes())?;
        Ok(out)
    }

    /// Strictly decode a payload, enforcing every §3.1/§3.2 rule and rejecting trailing bytes.
    ///
    /// # Errors
    ///
    /// Returns the first violated [`PayloadError`].
    pub fn decode(bytes: &[u8]) -> Result<Self, PayloadError> {
        if bytes.len() > MAX_PAYLOAD_BYTES {
            return Err(PayloadError::TooLong);
        }
        let mut reader = Reader { bytes, offset: 0 };
        if reader.u8()? != PAYLOAD_KIND_TRANSFER {
            return Err(PayloadError::WrongKind);
        }
        if reader.u8()? != PAYLOAD_VERSION {
            return Err(PayloadError::WrongVersion);
        }
        let source_domain = reader.u32()?;
        let dest_domain = reader.u32()?;
        let nonce = reader.u64()?;
        let route_revision = reader.u32()?;
        let deadline_ms = reader.u64()?;
        let asset_home_domain = reader.u32()?;
        let (asset_codec, asset_id) = reader.field()?;
        if asset_home_domain != 0
            || asset_codec != CODEC_CANONICAL_TEXT
            || asset_id != ASSET_ID_XOR.as_bytes()
        {
            return Err(PayloadError::BadAsset);
        }
        let amount = reader.u128()?;
        let (sender_codec, sender) = reader.field()?;
        let (recipient_codec, recipient) = reader.field()?;
        let (route_codec, route_id) = reader.field()?;
        if reader.offset != bytes.len() {
            return Err(PayloadError::TrailingBytes);
        }
        if route_codec != CODEC_CANONICAL_TEXT || !is_canonical_text(route_id) {
            return Err(PayloadError::BadRouteId);
        }
        let route_id = core::str::from_utf8(route_id)
            .map_err(|_| PayloadError::BadRouteId)?
            .to_owned();
        let payload = Self {
            source_domain,
            dest_domain,
            nonce,
            route_revision,
            deadline_ms,
            amount,
            sender: PayloadAccountV1::new(sender_codec, sender.to_vec()),
            recipient: PayloadAccountV1::new(recipient_codec, recipient.to_vec()),
            route_id,
        };
        payload.validate()?;
        Ok(payload)
    }

    /// `lane_bytes(source, target)` of this payload.
    ///
    /// # Errors
    ///
    /// Returns [`PayloadError::BadDomains`] for an invalid lane.
    pub fn lane_bytes(&self, taira_network_id: &[u8; 32]) -> Result<[u8; 66], PayloadError> {
        let source = self.source().ok_or(PayloadError::BadDomains)?;
        let target = self.target().ok_or(PayloadError::BadDomains)?;
        network::lane_bytes(source, target, taira_network_id).ok_or(PayloadError::BadDomains)
    }

    /// `payload_hash` of the validated encoding (§3.3).
    ///
    /// # Errors
    ///
    /// See [`Self::encode`].
    pub fn payload_hash(&self) -> Result<[u8; 32], PayloadError> {
        Ok(hashes::payload_hash(&self.encode()?))
    }

    /// `message_id` of this payload under the given Taira network id (§3.3).
    ///
    /// # Errors
    ///
    /// See [`Self::encode`].
    pub fn message_id(&self, taira_network_id: &[u8; 32]) -> Result<[u8; 32], PayloadError> {
        let lane = self.lane_bytes(taira_network_id)?;
        Ok(hashes::message_id(&lane, &self.payload_hash()?))
    }
}

fn push_field(out: &mut Vec<u8>, codec: u8, bytes: &[u8]) -> Result<(), PayloadError> {
    let len = u16::try_from(bytes.len()).map_err(|_| PayloadError::FieldTooLong)?;
    out.push(codec);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8], PayloadError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(PayloadError::Truncated)?;
        let slice = self
            .bytes
            .get(self.offset..end)
            .ok_or(PayloadError::Truncated)?;
        self.offset = end;
        Ok(slice)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], PayloadError> {
        let mut out = [0_u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8, PayloadError> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, PayloadError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, PayloadError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, PayloadError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn u128(&mut self) -> Result<u128, PayloadError> {
        Ok(u128::from_be_bytes(self.array()?))
    }

    fn field(&mut self) -> Result<(u8, &'a [u8]), PayloadError> {
        let codec = self.u8()?;
        let len = usize::from(self.u16()?);
        Ok((codec, self.take(len)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v1::constants::TON_AMOUNT_BOUND;

    const TAIRA: [u8; 32] = [0x11; 32];

    fn taira_account() -> Vec<u8> {
        vec![0x01, 0x02, 0x03, 0x04, 0x05]
    }

    fn external_account(network: SccpNetworkV1) -> Vec<u8> {
        match network {
            SccpNetworkV1::EthereumMainnet | SccpNetworkV1::BscMainnet => vec![0x22; 20],
            SccpNetworkV1::TonMainnet => {
                let mut bytes = vec![0; 4];
                bytes.extend_from_slice(&[0x44; 32]);
                bytes
            }
            SccpNetworkV1::SoraTaira => taira_account(),
        }
    }

    fn outbound(network: SccpNetworkV1) -> SccpTransferPayloadV1 {
        SccpTransferPayloadV1::outbound(
            network,
            7,
            1,
            1_800_000_000_000,
            1_000_000_000,
            taira_account(),
            external_account(network),
        )
        .expect("outbound payload")
    }

    fn inbound(network: SccpNetworkV1) -> SccpTransferPayloadV1 {
        SccpTransferPayloadV1::inbound(network, 3, 2, 5, external_account(network), taira_account())
            .expect("inbound payload")
    }

    #[test]
    fn all_six_directions_roundtrip() {
        for network in network::EXTERNAL_NETWORKS {
            for payload in [outbound(network), inbound(network)] {
                let encoded = payload.encode().expect("encode");
                assert_eq!(encoded.len(), payload.encoded_len());
                assert_eq!(SccpTransferPayloadV1::decode(&encoded), Ok(payload.clone()));
                assert_eq!(payload.external_network(), Ok(network));
                let message_id = payload.message_id(&TAIRA).expect("message id");
                let lane = payload.lane_bytes(&TAIRA).expect("lane");
                assert_eq!(
                    message_id,
                    hashes::message_id(&lane, &hashes::payload_hash(&encoded))
                );
            }
        }
    }

    #[test]
    fn encoding_layout_is_big_endian() {
        let payload = outbound(SccpNetworkV1::EthereumMainnet);
        let bytes = payload.encode().unwrap();
        assert_eq!(bytes[0], 0x02);
        assert_eq!(bytes[1], 0x01);
        assert_eq!(bytes[2..6], [0, 0, 0, 0]);
        assert_eq!(bytes[6..10], [0, 0, 0, 1]);
        assert_eq!(bytes[10..18], 7_u64.to_be_bytes());
        assert_eq!(bytes[18..22], [0, 0, 0, 1]);
        assert_eq!(bytes[22..30], 1_800_000_000_000_u64.to_be_bytes());
        assert_eq!(bytes[30..34], [0; 4]);
        assert_eq!(bytes[34..40], [1, 0, 3, b'x', b'o', b'r']);
        assert_eq!(bytes[40..56], 1_000_000_000_u128.to_be_bytes());
        assert_eq!(bytes[56..59], [3, 0, 5]);
        assert_eq!(bytes[59..64], [1, 2, 3, 4, 5]);
        assert_eq!(bytes[64..67], [2, 0, 20]);
        assert_eq!(bytes[87..90], [1, 0, 13]);
        assert_eq!(&bytes[90..], b"taira_eth_xor");
    }

    #[test]
    fn decoder_rejects_every_rule_violation() {
        let valid = outbound(SccpNetworkV1::EthereumMainnet).encode().unwrap();
        let decode = |bytes: &[u8]| SccpTransferPayloadV1::decode(bytes);
        let mut trailing = valid.clone();
        trailing.push(0);
        assert_eq!(decode(&trailing), Err(PayloadError::TrailingBytes));
        assert_eq!(
            decode(&valid[..valid.len() - 1]),
            Err(PayloadError::Truncated)
        );
        assert_eq!(decode(&[]), Err(PayloadError::Truncated));
        let mutate = |index: usize, value: u8| {
            let mut bytes = valid.clone();
            bytes[index] = value;
            decode(&bytes)
        };
        assert_eq!(mutate(0, 0x01), Err(PayloadError::WrongKind));
        assert_eq!(mutate(1, 0x02), Err(PayloadError::WrongVersion));
        assert_eq!(mutate(9, 0x00), Err(PayloadError::BadDomains));
        assert_eq!(mutate(9, 0x03), Err(PayloadError::BadDomains));
        assert_eq!(mutate(9, 0x05), Err(PayloadError::BadDomains));
        assert_eq!(mutate(21, 0x00), Err(PayloadError::ZeroRevision));
        assert_eq!(mutate(33, 0x01), Err(PayloadError::BadAsset));
        assert_eq!(mutate(34, 0x02), Err(PayloadError::BadAsset));
        assert_eq!(mutate(39, b's'), Err(PayloadError::BadAsset));
        assert_eq!(mutate(56, 0x02), Err(PayloadError::WrongSenderCodec));
        assert_eq!(mutate(64, 0x05), Err(PayloadError::WrongRecipientCodec));
        assert_eq!(mutate(87, 0x02), Err(PayloadError::BadRouteId));
        assert_eq!(mutate(90, b' '), Err(PayloadError::BadRouteId));
        assert_eq!(mutate(96, b'b'), Err(PayloadError::RouteMismatch));
        // Deadline zeroed on an outbound payload.
        let mut bytes = valid.clone();
        bytes[22..30].copy_from_slice(&[0; 8]);
        assert_eq!(decode(&bytes), Err(PayloadError::DeadlineMismatch));
        // Amount zeroed.
        let mut bytes = valid.clone();
        bytes[40..56].copy_from_slice(&[0; 16]);
        assert_eq!(decode(&bytes), Err(PayloadError::ZeroAmount));
        // Zero recipient address.
        let mut bytes = valid;
        bytes[67..87].copy_from_slice(&[0; 20]);
        assert_eq!(decode(&bytes), Err(PayloadError::BadRecipient));
    }

    #[test]
    fn payload_rejects_the_retired_tron_domain_and_codec_5() {
        // The retired TRON account: codec 5, `0x41` then 20 nonzero bytes.
        let mut tron_account = vec![0x41];
        tron_account.extend_from_slice(&[0x33; 20]);
        assert!(!is_valid_account(5, &tron_account));

        // Outbound to domain 5 and inbound from domain 5, as the retired profile encoded them.
        let mut outbound_tron = outbound(SccpNetworkV1::EthereumMainnet);
        outbound_tron.dest_domain = 5;
        outbound_tron.recipient = PayloadAccountV1::new(5, tron_account.clone());
        outbound_tron.route_id = "taira_tron_xor".to_owned();
        let mut inbound_tron = inbound(SccpNetworkV1::EthereumMainnet);
        inbound_tron.source_domain = 5;
        inbound_tron.sender = PayloadAccountV1::new(5, tron_account.clone());
        inbound_tron.route_id = "taira_tron_xor".to_owned();
        for retired in [outbound_tron, inbound_tron] {
            assert_eq!(retired.validate(), Err(PayloadError::BadDomains));
            assert_eq!(retired.encode(), Err(PayloadError::BadDomains));
            assert_eq!(retired.external_network(), Err(PayloadError::BadDomains));
            assert_eq!(retired.lane_bytes(&TAIRA), Err(PayloadError::BadDomains));
            let bytes = retired.encode_unvalidated().expect("layout only");
            assert_eq!(
                SccpTransferPayloadV1::decode(&bytes),
                Err(PayloadError::BadDomains)
            );
        }

        // Codec 5 on a surviving lane is refused by the direction table.
        for network in network::EXTERNAL_NETWORKS {
            let mut recipient = outbound(network);
            recipient.recipient = PayloadAccountV1::new(5, tron_account.clone());
            let bytes = recipient.encode_unvalidated().expect("layout only");
            assert_eq!(
                SccpTransferPayloadV1::decode(&bytes),
                Err(PayloadError::WrongRecipientCodec)
            );
            let mut sender = inbound(network);
            sender.sender = PayloadAccountV1::new(5, tron_account.clone());
            let bytes = sender.encode_unvalidated().expect("layout only");
            assert_eq!(
                SccpTransferPayloadV1::decode(&bytes),
                Err(PayloadError::WrongSenderCodec)
            );
        }
    }

    #[test]
    fn inbound_rules() {
        let mut payload = inbound(SccpNetworkV1::BscMainnet);
        payload.deadline_ms = 1;
        assert_eq!(payload.validate(), Err(PayloadError::DeadlineMismatch));
        let mut payload = inbound(SccpNetworkV1::BscMainnet);
        payload.sender.bytes = vec![0; 20];
        assert_eq!(payload.validate(), Err(PayloadError::BadSender));
        let mut payload = inbound(SccpNetworkV1::TonMainnet);
        payload.sender.bytes[3] = 1;
        assert_eq!(payload.validate(), Err(PayloadError::BadSender));
        let mut payload = inbound(SccpNetworkV1::TonMainnet);
        payload.amount = TON_AMOUNT_BOUND;
        assert_eq!(payload.validate(), Err(PayloadError::TonAmountBound));
        payload.amount = TON_AMOUNT_BOUND - 1;
        assert_eq!(payload.validate(), Ok(()));
        let mut payload = inbound(SccpNetworkV1::BscMainnet);
        payload.route_id = "taira_eth_xor".to_owned();
        assert_eq!(payload.validate(), Err(PayloadError::RouteMismatch));
    }

    #[test]
    fn taira_account_length_bounds_and_total_length() {
        let make = |len: usize| {
            SccpTransferPayloadV1::outbound(
                SccpNetworkV1::EthereumMainnet,
                0,
                1,
                1,
                1,
                vec![0xab; len],
                vec![0x22; 20],
            )
        };
        assert_eq!(make(0), Err(PayloadError::BadSender));
        assert!(make(1).is_ok());
        let max = make(1024).expect("1024-byte account");
        assert!(max.encode().is_ok());
        assert_eq!(make(1025), Err(PayloadError::BadSender));
        // Codec 3 is at most 1024 bytes, so a valid payload stays far below 4096 bytes; a
        // longer input is rejected before parsing.
        let mut long = max.encode().unwrap();
        long.resize(4097, 0);
        assert_eq!(
            SccpTransferPayloadV1::decode(&long),
            Err(PayloadError::TooLong)
        );
    }

    #[test]
    fn account_codec_table() {
        assert!(is_valid_account(1, b"xor"));
        assert!(!is_valid_account(1, b""));
        assert!(!is_valid_account(1, &[0x7f]));
        assert!(!is_valid_account(1, &[b'a'; 257]));
        assert!(is_valid_account(2, &[1; 20]));
        assert!(!is_valid_account(2, &[0; 20]));
        assert!(!is_valid_account(2, &[1; 21]));
        assert!(!is_valid_account(3, &[]));
        assert!(is_valid_account(3, &[0; 1024]));
        let mut ton_account = vec![0; 36];
        assert!(!is_valid_account(7, &ton_account));
        ton_account[35] = 1;
        assert!(is_valid_account(7, &ton_account));
        ton_account[0] = 0xff;
        assert!(!is_valid_account(7, &ton_account));
        for unassigned in [0_u8, 4, 5, 6, 8, 255] {
            assert!(!is_valid_account(unassigned, &[1; 20]));
        }
    }

    #[test]
    fn constructors_reject_taira_endpoints() {
        assert_eq!(
            SccpTransferPayloadV1::outbound(
                SccpNetworkV1::SoraTaira,
                0,
                1,
                1,
                1,
                taira_account(),
                taira_account()
            ),
            Err(PayloadError::BadDomains)
        );
        assert_eq!(
            SccpTransferPayloadV1::inbound(
                SccpNetworkV1::SoraTaira,
                0,
                1,
                1,
                taira_account(),
                taira_account()
            ),
            Err(PayloadError::BadDomains)
        );
        let payload = outbound(SccpNetworkV1::TonMainnet);
        assert!(payload.is_outbound());
        assert_eq!(payload.source(), Some(SccpNetworkV1::SoraTaira));
        assert_eq!(payload.target(), Some(SccpNetworkV1::TonMainnet));
        assert!(!inbound(SccpNetworkV1::TonMainnet).is_outbound());
    }

    #[test]
    fn encode_unvalidated_rejects_oversized_fields() {
        let mut payload = outbound(SccpNetworkV1::EthereumMainnet);
        payload.sender.bytes = vec![1; usize::from(u16::MAX) + 1];
        assert_eq!(
            payload.encode_unvalidated(),
            Err(PayloadError::FieldTooLong)
        );
        assert_eq!(payload.encode(), Err(PayloadError::BadSender));
    }
}
