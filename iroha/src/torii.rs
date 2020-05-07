use crate::{prelude::*, sumeragi::Message, MessageSender};
use async_std::{sync::RwLock, task};
use iroha_network::prelude::*;
use std::{convert::TryFrom, sync::Arc};

pub struct Torii {
    url: String,
    world_state_view: Arc<RwLock<WorldStateView>>,
    transaction_sender: Arc<RwLock<TransactionSender>>,
    message_sender: Arc<RwLock<MessageSender>>,
}

impl Torii {
    pub fn new(
        url: &str,
        world_state_view: Arc<RwLock<WorldStateView>>,
        transaction_sender: TransactionSender,
        message_sender: MessageSender,
    ) -> Self {
        Torii {
            url: url.to_string(),
            world_state_view,
            transaction_sender: Arc::new(RwLock::new(transaction_sender)),
            message_sender: Arc::new(RwLock::new(message_sender)),
        }
    }

    pub async fn start(&mut self) -> Result<(), String> {
        let url = &self.url.clone();
        let world_state_view = Arc::clone(&self.world_state_view);
        let transaction_sender = Arc::clone(&self.transaction_sender);
        let message_sender = Arc::clone(&self.message_sender);
        let state = ToriiState {
            world_state_view,
            transaction_sender,
            message_sender,
        };
        Network::listen(Arc::new(RwLock::new(state)), url, handle_connection).await?;
        Ok(())
    }
}

struct ToriiState {
    world_state_view: Arc<RwLock<WorldStateView>>,
    transaction_sender: Arc<RwLock<TransactionSender>>,
    message_sender: Arc<RwLock<MessageSender>>,
}

async fn handle_connection(
    state: State<ToriiState>,
    stream: Box<dyn AsyncStream>,
) -> Result<(), String> {
    let state_arc = Arc::clone(&state);
    task::spawn(async {
        if let Err(e) = Network::handle_message_async(state_arc, stream, handle_request).await {
            eprintln!("Failed to handle message: {}", e);
        }
    });
    Ok(())
}

async fn handle_request(state: State<ToriiState>, request: Request) -> Result<Response, String> {
    match request.url() {
        uri::INSTRUCTIONS_URI => match Transaction::try_from(request.payload().to_vec()) {
            Ok(transaction) => {
                state
                    .write()
                    .await
                    .transaction_sender
                    .write()
                    .await
                    .send(transaction.accept()?)
                    .await;
                Ok(Response::empty_ok())
            }
            Err(e) => {
                eprintln!("Failed to decode transaction: {}", e);
                Ok(Response::InternalError)
            }
        },
        uri::QUERY_URI => match QueryRequest::try_from(request.payload().to_vec()) {
            Ok(request) => match request
                .query
                .execute(&*state.read().await.world_state_view.read().await)
            {
                Ok(result) => {
                    let result = &result;
                    Ok(Response::Ok(result.into()))
                }
                Err(e) => {
                    eprintln!("{}", e);
                    Ok(Response::InternalError)
                }
            },
            Err(e) => {
                eprintln!("Failed to decode transaction: {}", e);
                Ok(Response::InternalError)
            }
        },
        uri::BLOCKS_URI => match Message::try_from(request.payload().to_vec()) {
            Ok(message) => {
                state
                    .write()
                    .await
                    .message_sender
                    .write()
                    .await
                    .send(message)
                    .await;
                Ok(Response::empty_ok())
            }
            Err(e) => {
                eprintln!("Failed to decode peer message: {}", e);
                Ok(Response::InternalError)
            }
        },
        non_supported_uri => panic!("URI not supported: {}.", &non_supported_uri),
    }
}

pub mod uri {
    pub const QUERY_URI: &str = "/query";
    pub const INSTRUCTIONS_URI: &str = "/instruction";
    pub const BLOCKS_URI: &str = "/block";
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Configuration;
    use async_std::{sync, task};
    use std::time::Duration;

    const CONFIGURATION_PATH: &str = "tests/test_config.json";

    #[async_std::test]
    async fn create_and_start_torii() {
        let config =
            Configuration::from_path(CONFIGURATION_PATH).expect("Failed to load configuration.");
        let torii_url = config.torii_url.to_string();
        let (tx_tx, _) = sync::channel(100);
        let (ms_tx, _) = sync::channel(100);
        let mut torii = Torii::new(
            &torii_url,
            Arc::new(RwLock::new(WorldStateView::new(Peer::new(
                torii_url.clone(),
                &Vec::new(),
            )))),
            tx_tx,
            ms_tx,
        );
        task::spawn(async move {
            if let Err(e) = torii.start().await {
                eprintln!("Failed to start Torii: {}", e);
            }
        });
        std::thread::sleep(Duration::from_millis(50));
    }
}
