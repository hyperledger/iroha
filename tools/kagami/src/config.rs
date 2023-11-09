use std::str::FromStr as _;

use clap::{Parser, Subcommand};
use iroha_crypto::{Algorithm, PrivateKey, PublicKey};
use iroha_primitives::small::SmallStr;

use super::*;

#[derive(Parser, Debug, Clone, Copy)]
pub struct Args {
    #[clap(subcommand)]
    mode: Mode,
}

#[derive(Subcommand, Debug, Clone, Copy)]
pub enum Mode {
    Client(client::Args),
    Peer(peer::Args),
}

impl<T: Write> RunArgs<T> for Args {
    fn run(self, writer: &mut BufWriter<T>) -> Outcome {
        match self.mode {
            Mode::Client(args) => args.run(writer),
            Mode::Peer(args) => args.run(writer),
        }
    }
}

mod client {
    use iroha_config::{
        client::{BasicAuth, ConfigurationProxy, WebLogin},
        torii::uri::DEFAULT_API_ADDR,
    };

    use super::*;

    #[derive(ClapArgs, Debug, Clone, Copy)]
    pub struct Args;

    impl<T: Write> RunArgs<T> for Args {
        fn run(self, writer: &mut BufWriter<T>) -> Outcome {
            let config = ConfigurationProxy {
                    torii_api_url: Some(format!("http://{DEFAULT_API_ADDR}").parse()?),
                    account_id: Some("alice@wonderland".parse()?),
                    basic_auth: Some(Some(BasicAuth {
                        web_login: WebLogin::new("mad_hatter")?,
                        password: SmallStr::from_str("ilovetea"),
                    })),
                    public_key: Some(PublicKey::from_str(
                        "ed01207233BFC89DCBD68C19FDE6CE6158225298EC1131B6A130D1AEB454C1AB5183C0",
                    )?),
                    private_key: Some(PrivateKey::from_hex(
                        Algorithm::Ed25519,
                        "9AC47ABF59B356E0BD7DCBBBB4DEC080E302156A48CA907E47CB6AEA1D32719E7233BFC89DCBD68C19FDE6CE6158225298EC1131B6A130D1AEB454C1AB5183C0"
                    )?),
                    ..ConfigurationProxy::default()
                }
                .build()?;
            writeln!(writer, "{}", serde_json::to_string_pretty(&config)?)
                .wrap_err("Failed to write serialized client configuration to the buffer.")
        }
    }
}

mod peer {
    use iroha_config::iroha::ConfigurationProxy as IrohaConfigurationProxy;

    use super::*;

    #[derive(ClapArgs, Debug, Clone, Copy)]
    pub struct Args;

    impl<T: Write> RunArgs<T> for Args {
        fn run(self, writer: &mut BufWriter<T>) -> Outcome {
            let config = IrohaConfigurationProxy::default();
            writeln!(writer, "{}", serde_json::to_string_pretty(&config)?)
                .wrap_err("Failed to write serialized peer configuration to the buffer.")
        }
    }
}
