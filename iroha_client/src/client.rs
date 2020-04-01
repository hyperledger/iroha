use iroha::isi::Contract;

#[derive(Default)]
pub struct Client {}

/// Representation of `Iroha` client.
impl Client {
    pub fn new() -> Self {
        Client {}
    }

    /// Contract API entry point. Submits commands to `Iroha` peers.
    pub fn submit(&self, _command: Contract) -> Result<(), ()> {
        Ok(())
    }
}
