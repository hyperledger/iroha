use iroha::isi::Command;

#[derive(Default)]
pub struct Client {}

/// Representation of `Iroha` client.
impl Client {
    pub fn new() -> Self {
        Client {}
    }

    /// Command API entry point. Submits commands to `Iroha` peers.
    pub fn submit(&self, _command: Command) -> Result<(), ()> {
        Ok(())
    }
}
