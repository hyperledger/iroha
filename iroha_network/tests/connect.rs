#[cfg(test)]
mod tests {
    use async_std::{prelude::*, sync::RwLock, task};
    use iroha_network::prelude::*;
    use std::{sync::Arc, thread, time::Duration};

    #[async_std::test]
    async fn test_connect_handling() {
        thread::spawn(|| {
            task::block_on(async {
                Network::listen(
                    Arc::new(RwLock::new(())),
                    "127.0.0.1:8888",
                    handle_connection,
                )
                .await
                .expect("Failed to listen.");
            });
        });
        thread::sleep(Duration::from_millis(50));
        let network = Network::new("127.0.0.1:8888");
        let mut actual_changes = Vec::new();
        let mut connection = network
            .connect(&[0u8, 10])
            .await
            .expect("Failed to connect.");
        while let Some(mut change) = connection.next() {
            println!("Change #{} - {:?}", actual_changes.len(), change);
            actual_changes.append(&mut change);
        }
        assert_eq!(actual_changes.len(), 99);
    }

    async fn handle_connection(
        _state: State<()>,
        mut stream: Box<dyn AsyncStream>,
    ) -> Result<(), String> {
        for i in 1..100 {
            stream
                .write_all(&[i])
                .await
                .map_err(|e| format!("Failed to write message: {}", e))?;
            stream
                .flush()
                .await
                .map_err(|e| format!("Failed to flush: {}", e))?;
            let mut receipt = [0u8; 4];
            stream
                .read(&mut receipt)
                .await
                .map_err(|e| format!("Failed to read receipt: {}", e))?;
        }
        Ok(())
    }
}
