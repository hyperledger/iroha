# Iroha CLI Client

Iroha CLI Client provides an ability to interact with Iroha Peers Web API without direct network usage.
It's a "light" client which only converts Command Line Interface commands into Iroha Web API Network Requests.

## Installation

//TODO:

## Examples

Full description and list of commands detailed in `iroha_cli --help`.

```
$: ./iroha_client_cli --help
Iroha CLI Client 0.1.0
Nikita Puzankov <puzankov@soramitsu.co.jp>
Iroha CLI Client provides an ability to interact with Iroha Peers Web API without direct network usage.

USAGE:
    iroha_client_cli [OPTIONS] [SUBCOMMAND]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -c, --config <FILE>    Sets a config file path. [default: config.json]

SUBCOMMANDS:
    create    Use this command to request entities creation in Iroha Peer.
    help      Prints this message or the help of the given subcommand(s)

```

### Create new Domain

Let's start with domain creation. We need to provide `create` command first, 
following by entity type (`domain` in our case) and list of required parameters.
For domain entity we only need `name` parameter which is stringly typed.

```bash
iroha_cli create domain --name="Soramitsu"
```

### Create new Account

Right now we have the only domain without any accounts, let's fix it.
Like in the previous example, we need to define domain name, this time as 
`domain` argument, because `name` argument should be filled with account's name.
We also give a `key` argument with account's public key as a double-quoted
string value.

```bash
iroha_cli create account --domain="Soramitsu" --name="White Rabbit" --key=""
```

### Add Asset to Account

Okay, it's time to give something to our account. We will add some assets amount to it.
This time we need to create an asset first and then add some amount of it to the account.
As you can see, we use new command `update` to add some assets amount to the account. Asset entity is like a schema for account holding amounts of it.

```bash
iroha_cli create asset --domain="Soramitsu" --name="XOR" --decimals=10 
iroha_cli update asset add --account_id="White Rabbit@Soramitsu" --id="XOR@Soramitsu" --amount=1010 
```

### Query Account Assets Amount

Because distributed systems heavily relay on the concept of eventual consistency and Iroha works in Consensus between peers, your requests may or may not be processed
while Iroha Client will successufully send them and Iroha Peer will accept them. Different stages of transactions processing and different cases may lead to
rejection of transaction after your receive response from Command Line Interface. To check that your instruction were applied and system now in the desired state
you need to become familar and use Query API.

Let's use Get Account Assets Query as an example. Command will look familar because it almost the same as the update command.
We need to know amount so we skipp this argument and replace `update asset add` part with `get asset`.

```bash
iroha_cli get asset --account_id="White Rabbit@Soramitsu" --id="XOR@Soramitsu" 
```
