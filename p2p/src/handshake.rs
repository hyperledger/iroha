//! This is a WIP module containing the refactored state-machine based
//! handshake process. Currently, problems pertain to actor
//! implementations.
#![allow(missing_docs, clippy::missing_errors_doc)]

use async_trait::async_trait;
use iroha_actor::broker::Broker;
use iroha_crypto::ursa::{encryption::symm::Encryptor, kex::KeyExchangeScheme};
use iroha_data_model::{peer, Identifiable};
use iroha_data_model_derive::IdOrdEqHash;
use parity_scale_codec::{Decode, Encode};

use crate::peer::{Connection, Cryptographer};

mod boilerplate {
    //! Module containing trait shorthands. Remove when trait aliases
    //! are stable <https://github.com/rust-lang/rust/issues/41517>
    use super::*;

    pub trait Pload: Encode + Decode + Send + Clone + 'static {}
    impl<T> Pload for T where T: Encode + Decode + Send + Clone + 'static {}

    pub trait Kex: KeyExchangeScheme + Send + 'static {}
    impl<T> Kex for T where T: KeyExchangeScheme + Send + 'static {}

    pub trait Enc: Encryptor + Send + 'static {}
    impl<T> Enc for T where T: Encryptor + Send + 'static {}
}

pub mod process {
    //! Implementations of the handshake process. Mostly <T, K, E>
    //! boilerplate. Possibly useful to rewrite as `dyn T` objects.
    #![allow(missing_docs, clippy::missing_errors_doc)]

    use super::{boilerplate::*, peer_state::*, *};

    #[async_trait]
    pub trait Stage<T: Pload, K: Kex, E: Enc> {
        type NextStage;

        async fn advance_to_next_stage(self) -> Result<Self::NextStage, crate::Error>;
    }

    // TODO: rewrite when GAT stable.
    macro_rules! stage {
        ( $func:ident : $curstage:ty => $nextstage:ty ) => {
            #[async_trait]
            impl<T: Pload, K: Kex, E: Enc> Stage<T, K, E> for $curstage {
                type NextStage = $nextstage;

                async fn advance_to_next_stage(self) -> Result<Self::NextStage, crate::Error> {
                    Self::$func(self).await
                }
            }
        };
    }

    stage!(connect_to: Connecting => ConnectedTo);
    stage!(send_client_hello: ConnectedTo => SendKey<T, K, E>);
    stage!(read_client_hello: ConnectedFrom => SendKey<T, K, E>);
    stage!(send_our_public_key: SendKey<T, K, E> => GetKey<T, K, E>);
    stage!(read_their_public_key: GetKey<T, K, E> => Ready<T, K, E>);

    #[async_trait]
    trait Handshake<T: Pload, K: Kex, E: Enc> {
        async fn handshake(self) -> Result<Ready<T, K, E>, crate::Error>;
    }

    macro_rules! impl_handshake {
        ( base_case $typ:ty ) => {
            // Base case, should be all states that lead to `Ready`
            #[async_trait]
            impl<T: Pload, K: Kex, E: Enc> Handshake<T, K, E> for $typ {
                #[inline]
                async fn handshake(self) -> Result<Ready<T, K, E>, crate::Error> {
                    <$typ as Stage<T, K, E>>::advance_to_next_stage(self).await
                }
            }
        };
        ( $typ:ty ) => {
            #[async_trait]
            impl<T: Pload, K: Kex, E: Enc> Handshake<T, K, E> for $typ {
                #[inline]
                async fn handshake(self) -> Result<Ready<T, K, E>, crate::Error> {
                    <$typ as Stage<T, K, E>>::advance_to_next_stage(self)
                        .await?
                        .handshake()
                        .await
                }
            }
        };
    }

    impl_handshake!(base_case GetKey<T, K, E>);
    impl_handshake!(SendKey<T, K, E>);
    impl_handshake!(ConnectedFrom);
    impl_handshake!(ConnectedTo);
    impl_handshake!(Connecting);
}

pub mod peer_state {
    //! Peer state machine and inherent implementations.
    #![allow(missing_docs, clippy::missing_errors_doc)]

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpStream,
    };

    use super::{boilerplate::*, *};

    /// Peer that is connecting. This is the initial stage of a new
    /// outgoing peer.
    #[derive(Debug, IdOrdEqHash)]
    pub struct Connecting(#[id] peer::Id, pub Broker);

    impl Connecting {
        pub async fn connect_to(Self(id, broker): Self) -> Result<ConnectedTo, crate::Error> {
            let stream = TcpStream::connect(id.address.clone()).await?;
            let connection = Connection::new(rand::random(), stream);
            Ok(ConnectedTo(id, broker, connection))
        }
    }

    /// Peer that is being connected to.
    #[derive(Debug, IdOrdEqHash)]
    pub struct ConnectedTo(#[id] peer::Id, Broker, Connection);

    impl ConnectedTo {
        pub async fn send_client_hello<T: Pload, K: Kex, E: Enc>(
            Self(id, broker, mut connection): Self,
        ) -> Result<SendKey<T, K, E>, crate::Error> {
            #[allow(clippy::expect_used)]
            let write_half = connection
                .write
                .as_mut()
                .expect("Never fails as in this function we already have the stream.");
            write_half.as_ref().writable().await?;
            let mut crypto = Cryptographer::default_or_err()?;
            crate::peer::send_client_hello(write_half, crypto.public_key.0.as_slice()).await?;
            // Read server hello with node's public key
            #[allow(clippy::expect_used)]
            let read_half = connection
                .read
                .as_mut()
                .expect("Never fails as in this function we already have the stream.");
            let public_key = crate::peer::read_server_hello(read_half).await?;
            crypto.derive_shared_key(&public_key)?;
            Ok(SendKey(id, broker, connection, crypto))
        }
    }

    /// Peer that is being connected from
    #[derive(Debug, IdOrdEqHash)]
    pub struct ConnectedFrom(#[id] peer::Id, Broker, Connection);

    impl ConnectedFrom {
        #[allow(clippy::expect_used)]
        pub async fn read_client_hello<T: Pload, K: Kex, E: Enc>(
            Self(id, broker, mut connection): Self,
        ) -> Result<SendKey<T, K, E>, crate::Error> {
            let mut crypto = Cryptographer::default_or_err()?;
            let read_half = connection.read.as_mut().expect("Infallible");
            let public_key = crate::peer::read_client_hello(read_half).await?;
            crypto.derive_shared_key(&public_key)?;
            let write_half = connection.write.as_mut().expect("Infallible");
            crate::peer::send_server_hello(write_half, crypto.public_key.0.as_slice()).await?;
            Ok(SendKey(id, broker, connection, crypto))
        }
    }

    /// Peer that needs to send key.
    pub struct SendKey<T: Pload, K: Kex, E: Enc>(
        peer::Id,
        Broker,
        Connection,
        Cryptographer<T, K, E>,
    );

    impl<T: Pload, K: Kex, E: Enc> SendKey<T, K, E> {
        pub async fn send_our_public_key(
            Self(id, broker, mut connection, crypto): Self,
        ) -> Result<GetKey<T, K, E>, crate::Error> {
            #[allow(clippy::expect_used)]
            let write_half = connection
                .write
                .as_mut()
                .expect("Never fails as in this function we already have the stream.");
            write_half.as_ref().writable().await?;

            // We take our public key from our `id` and will replace it with theirs when we read it
            // Packing length and message in one network packet for efficiency
            let data = id.public_key.encode();

            let data = &crypto.encrypt(data)?;

            #[allow(clippy::arithmetic)]
            let mut buf = Vec::<u8>::with_capacity(data.len() + 1);
            #[allow(clippy::cast_possible_truncation)]
            buf.push(data.len() as u8);
            buf.extend_from_slice(data.as_slice());

            write_half.write_all(&buf).await?;
            Ok(GetKey(id, broker, connection, crypto))
        }
    }

    /// Peer that needs to get key.
    pub struct GetKey<T: Pload, K: Kex, E: Enc>(
        peer::Id,
        Broker,
        Connection,
        Cryptographer<T, K, E>,
    );

    impl<T: Pload, K: Kex, E: Enc> GetKey<T, K, E> {
        /// Read the peer's public key
        ///
        /// # Panics
        /// Never
        pub async fn read_their_public_key(
            Self(mut id, broker, mut connection, crypto): Self,
        ) -> Result<Ready<T, K, E>, crate::Error> {
            #[allow(clippy::expect_used)]
            let read_half = connection
                .read
                .as_mut()
                .expect("Read half always available");
            let size = read_half.read_u8().await? as usize;
            if size >= crate::peer::MAX_HANDSHAKE_LENGTH {
                return Err(crate::HandshakeError::Length(size).into());
            }
            // Reading public key
            read_half.as_ref().readable().await?;
            let mut data = vec![0_u8; size];
            let _ = read_half.read_exact(&mut data).await?;

            let data = crypto.decrypt(data)?;

            let pub_key = Decode::decode(&mut data.as_slice())?;

            id.public_key = pub_key;
            Ok(Ready(id, broker, connection, crypto))
        }
    }

    /// Peer that is ready for communication after finishing the
    /// handshake process.
    pub struct Ready<T: Pload, K: Kex, E: Enc>(
        peer::Id,
        pub Broker,
        pub Connection,
        Cryptographer<T, K, E>,
    );

    /// Peer in disconnected state.
    #[derive(Debug, IdOrdEqHash)]
    pub struct Disconnected(#[id] peer::Id);

    /// Peer in broken state.
    #[derive(Debug, IdOrdEqHash)]
    pub struct Broken(#[id] peer::Id, crate::Error);
}
