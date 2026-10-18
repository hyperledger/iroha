//! Mandatory canonical Norito credit records and authenticated payload binding.
use super::*;

pub(in crate::peer) const HEADER_CAP: usize = 512;
const RECORD_VERSION: u8 = 1;
const AAD_DOMAIN: &[u8] = b"iroha:p2p:receive-credit-record:v1|";

/// Application credits never authorize these fixed transport-control records.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::peer) enum Kind {
    Request,
    Grant,
    Data,
    Ping,
    Pong,
}
impl Kind {
    const fn code(self) -> u8 {
        match self {
            Self::Request => 0,
            Self::Grant => 1,
            Self::Data => 2,
            Self::Ping => 3,
            Self::Pong => 4,
        }
    }
}

/// One record authorizes exactly one canonical application message; no batch.
/// The Norito header declares the codec layout; V1 fixes the field meanings.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode, norito::NoritoSchema)]
#[norito(decode_from_slice)]
#[norito_schema(name = "iroha_p2p::peer::receive_credit::RecordHeaderV1")]
pub(in crate::peer) struct Header {
    version: u8,
    kind: u8,
    class: u8,
    binding: [u8; 32],
    pub(in crate::peer) sequence: u64,
    pub(in crate::peer) plaintext: u64,
}
impl Header {
    pub(in crate::peer) fn request(
        binding: [u8; 32],
        class: Class,
        sequence: u64,
        plaintext: usize,
    ) -> Result<Self, Error> {
        if sequence == 0 || plaintext == 0 {
            return Err(Error::Format);
        }
        Ok(Self {
            version: RECORD_VERSION,
            kind: Kind::Request.code(),
            class: class.wire_code(),
            binding,
            sequence,
            plaintext: u64::try_from(plaintext).map_err(|_| Error::Format)?,
        })
    }
    pub(in crate::peer) fn ping(binding: [u8; 32], sequence: u64) -> Result<Self, Error> {
        // Fixed transport cells; Low is a canonical sentinel, not a Low grant.
        Ok(Self::request(binding, Class::Low, sequence, 1)?.with_kind(Kind::Ping))
    }
    pub(in crate::peer) fn class(&self) -> Result<Class, Error> {
        Class::ALL
            .get(usize::from(self.class))
            .copied()
            .ok_or(Error::Format)
    }
    pub(in crate::peer) fn kind(&self) -> Result<Kind, Error> {
        match self.kind {
            0 => Ok(Kind::Request),
            1 => Ok(Kind::Grant),
            2 => Ok(Kind::Data),
            3 => Ok(Kind::Ping),
            4 => Ok(Kind::Pong),
            _ => Err(Error::Format),
        }
    }
    pub(in crate::peer) fn with_kind(mut self, kind: Kind) -> Self {
        self.kind = kind.code();
        self
    }
    pub(in crate::peer) fn check(&self, binding: &[u8; 32]) -> Result<(), Error> {
        if self.version != RECORD_VERSION
            || &self.binding != binding
            || self.sequence == 0
            || self.plaintext == 0
        {
            return Err(Error::Format);
        }
        self.class()?;
        if matches!(self.kind()?, Kind::Ping | Kind::Pong)
            && (self.class()? != Class::Low || self.plaintext != 1)
        {
            return Err(Error::Format);
        }
        Ok(())
    }
    pub(in crate::peer) fn bytes(&self) -> Result<Vec<u8>, Error> {
        let _layout = ncore::DecodeFlagsGuard::enter(ncore::default_encode_flags());
        let bytes = ncore::to_bytes(self).map_err(Error::NoritoCodec)?;
        if bytes.len() > HEADER_CAP {
            return Err(Error::FrameTooLarge);
        }
        Ok(bytes)
    }
    pub(in crate::peer) fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.is_empty() || bytes.len() > HEADER_CAP {
            return Err(Error::Format);
        }
        let header: Self = ncore::decode_from_bytes_with_limits(
            bytes,
            norito::canonical_decode_limits(bytes.len()),
        )
        .map_err(Error::NoritoCodec)?;
        if header.bytes()? != bytes {
            return Err(Error::Format);
        }
        Ok(header)
    }
}

/// The caller may construct this only from the *verified* identity handshake.
/// Both complete `PeerIds`, the network, full session key hash and mandatory
/// TLS/QUIC binding enter the directional record authority. No `ConnectionId` or
/// compact session disambiguator is used as a security identity.
#[derive(Clone, Debug)]
pub(in crate::peer) struct Binding {
    pub(in crate::peer) incoming: [u8; 32],
    pub(in crate::peer) outgoing: [u8; 32],
}
impl Binding {
    pub(in crate::peer) fn verified(
        network: &iroha_data_model::NetworkId,
        local: &PeerId,
        remote: &PeerId,
        session: [u8; 32],
        transport: TransportBinding,
        incoming_geometry: [u8; 32],
        outgoing_geometry: [u8; 32],
    ) -> Result<Self, Error> {
        fn direction(
            network: &iroha_data_model::NetworkId,
            sender: &PeerId,
            receiver: &PeerId,
            session: [u8; 32],
            transport: TransportBinding,
            geometry: [u8; 32],
        ) -> Result<[u8; 32], Error> {
            let bytes = ncore::to_bytes(&(
                b"iroha:p2p:receive-credit-binding:v1|".to_vec(),
                *network,
                sender.clone(),
                receiver.clone(),
                session,
                transport,
                geometry,
                RECORD_VERSION,
            ))
            .map_err(Error::NoritoCodec)?;
            Ok(iroha_crypto::Hash::new(&bytes).into())
        }
        if local == remote {
            return Err(Error::Format);
        }
        let _layout = ncore::DecodeFlagsGuard::enter(ncore::default_encode_flags());
        Ok(Self {
            incoming: direction(
                network,
                remote,
                local,
                session,
                transport,
                incoming_geometry,
            )?,
            outgoing: direction(
                network,
                local,
                remote,
                session,
                transport,
                outgoing_geometry,
            )?,
        })
    }
}

/// Header bytes are authenticated verbatim. Control records authenticate an
/// empty payload, so they never need an application grant to release capacity.
/// A plaintext Data header transfers an already exact bounded grant solely for
/// payload allocation. Its tag must verify before canonical application decoding
/// or delivery. Request/Grant ledger mutations require a verified empty-body tag.
/// A failed tag fences the unique reader; there is no early grant reuse.
#[cfg(test)]
pub(in crate::peer) fn seal<E: Enc>(
    crypto: &cryptographer::Cryptographer<E>,
    header: &Header,
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let record = seal_record(crypto, header, plaintext)?;
    let header_len = header_len_prefix(&record)?;
    let ciphertext = record[4 + header_len..].to_vec();
    let mut encoded = record;
    encoded.truncate(4 + header_len);
    encoded.drain(..4);
    Ok((encoded, ciphertext))
}
/// Seal one complete wire record into a single buffer:
/// `u32 header length || header || nonce || ciphertext || tag`.
///
/// The plaintext is copied once into its final position and encrypted in
/// place, so the writer emits the whole record with one buffer and no further
/// allocation or copy. The bytes are identical to sending the length prefix,
/// the header and the sealed envelope separately.
pub(in crate::peer) fn seal_record<E: Enc>(
    crypto: &cryptographer::Cryptographer<E>,
    header: &Header,
    plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    if (header.kind()? == Kind::Data
        && plaintext.len() != usize::try_from(header.plaintext).map_err(|_| Error::Format)?)
        || (header.kind()? != Kind::Data && !plaintext.is_empty())
    {
        return Err(Error::Format);
    }
    let bytes = header.bytes()?;
    let nonce = core::mem::size_of::<aead::Nonce<E>>();
    let sealed_len = encrypted_len::<E>(plaintext.len())?;
    let total = 4usize
        .checked_add(bytes.len())
        .and_then(|n| n.checked_add(sealed_len))
        .ok_or(Error::FrameTooLarge)?;
    let mut record = Vec::with_capacity(total);
    record.extend_from_slice(
        &u32::try_from(bytes.len())
            .map_err(|_| Error::Format)?
            .to_be_bytes(),
    );
    record.extend_from_slice(&bytes);
    let sealed_start = record.len();
    record.resize(sealed_start + nonce, 0);
    record.extend_from_slice(plaintext);
    record.resize(total, 0);
    with_aad(&bytes, |aad| {
        crypto
            .encryptor
            .encrypt_easy_in_place(aad, &mut record[sealed_start..])
    })?;
    Ok(record)
}
/// Length of the header carried by a sealed record.
#[cfg(test)]
fn header_len_prefix(record: &[u8]) -> Result<usize, Error> {
    let prefix: [u8; 4] = record
        .get(..4)
        .ok_or(Error::Format)?
        .try_into()
        .map_err(|_| Error::Format)?;
    Ok(u32::from_be_bytes(prefix) as usize)
}
/// Run `f` with the record AAD (`domain || header bytes`) on the stack.
fn with_aad<R>(header_bytes: &[u8], f: impl FnOnce(&[u8]) -> R) -> R {
    let mut aad = [0_u8; AAD_DOMAIN.len() + HEADER_CAP];
    let header_bytes = &header_bytes[..header_bytes.len().min(HEADER_CAP)];
    let len = AAD_DOMAIN.len() + header_bytes.len();
    aad[..AAD_DOMAIN.len()].copy_from_slice(AAD_DOMAIN);
    aad[AAD_DOMAIN.len()..len].copy_from_slice(header_bytes);
    f(&aad[..len])
}
pub(in crate::peer) fn open<'a, E: Enc>(
    crypto: &cryptographer::Cryptographer<E>,
    header_bytes: &[u8],
    ciphertext: &'a mut [u8],
) -> Result<&'a mut [u8], Error> {
    if header_bytes.len() > HEADER_CAP {
        return Err(Error::Format);
    }
    with_aad(header_bytes, |aad| {
        crypto.encryptor.decrypt_easy_in_place(aad, ciphertext)
    })
    .map_err(Into::into)
}
pub(in crate::peer) fn encrypted_len<E: Enc>(plaintext: usize) -> Result<usize, Error> {
    plaintext
        .checked_add(core::mem::size_of::<aead::Nonce<E>>())
        .and_then(|n| n.checked_add(core::mem::size_of::<aead::Tag<E>>()))
        .ok_or(Error::FrameTooLarge)
}
