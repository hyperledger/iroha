use iroha::{crypto, prelude::*, torii::uri};
use iroha_derive::log;
use iroha_network::{prelude::*, Network};
use std::{
    convert::{TryFrom, TryInto},
    fmt::{self, Debug, Formatter},
};

pub struct Client {
    torii_url: String,
    public_key: PublicKey,
    private_key: PrivateKey,
}

impl Debug for Client {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("public_key", &self.public_key)
            .field("torii_url", &self.torii_url)
            .finish()
    }
}

/// Representation of `Iroha` client.
impl Client {
    pub fn new(config: &Configuration) -> Self {
        let (public_key, private_key) =
            crypto::generate_key_pair().expect("Failed to generate key pair.");
        Client {
            torii_url: config.torii_url.clone(),
            public_key: public_key[..]
                .try_into()
                .expect("Public key should be [u8;32]"),
            private_key,
        }
    }

    /// Contract API entry point. Submits contract to `Iroha` peers.
    #[log]
    pub async fn submit(&mut self, command: Contract) -> Result<(), String> {
        let network = Network::new(&self.torii_url);
        let transaction: RequestedTransaction =
            RequestedTransaction::new(vec![command], Id::new("account", "domain"))
                .accept()?
                .sign(&self.public_key, &self.private_key)?
                .into();
        if let Response::InternalError = network
            .send_request(Request::new(
                uri::INSTRUCTIONS_URI.to_string(),
                Vec::from(&transaction),
            ))
            .await
            .map_err(|e| {
                format!(
                    "Error: {}, Failed to write a transaction request: {:?}",
                    e, &transaction
                )
            })?
        {
            return Err("Server error.".to_string());
        }
        Ok(())
    }

    /// Contract API entry point. Submits contracts to `Iroha` peers.
    #[log]
    pub async fn submit_all(&mut self, commands: Vec<Contract>) -> Result<(), String> {
        let network = Network::new(&self.torii_url);
        let transaction: RequestedTransaction =
            RequestedTransaction::new(commands, Id::new("account", "domain"))
                .accept()?
                .sign(&self.public_key, &self.private_key)?
                .into();
        if let Response::InternalError = network
            .send_request(Request::new(
                uri::INSTRUCTIONS_URI.to_string(),
                Vec::from(&transaction),
            ))
            .await
            .map_err(|e| {
                format!(
                    "Error: {}, Failed to write a transaction request: {:?}",
                    e, &transaction
                )
            })?
        {
            return Err("Server error.".to_string());
        }
        Ok(())
    }

    /// Query API entry point. Requests queries from `Iroha` peers.
    #[log]
    pub async fn request(&mut self, request: &QueryRequest) -> Result<QueryResult, String> {
        let network = Network::new(&self.torii_url);
        match network
            .send_request(Request::new(uri::QUERY_URI.to_string(), request.into()))
            .await
            .map_err(|e| format!("Failed to write a get request: {}", e))?
        {
            Response::Ok(payload) => Ok(
                QueryResult::try_from(payload).expect("Failed to try Query Result from vector.")
            ),
            Response::InternalError => Err("Server error.".to_string()),
        }
    }
}

pub mod assets {
    use super::*;
    use iroha::asset::query::GetAccountAssets;

    pub fn by_account_id(account_id: Id) -> QueryRequest {
        GetAccountAssets::build_request(account_id)
    }
}
