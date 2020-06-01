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

### TL;DR

```bash
./iroha_client_cli domain add --name="Soramitsu"
./iroha_client_cli account register --domain="Soramitsu" --name="White Rabbit" --key=""
./iroha_client_cli asset register --domain="Soramitsu" --name="XOR" 
./iroha_client_cli asset mint --account_id="White Rabbit@Soramitsu" --id="XOR#Soramitsu" --quantity=1010 
./iroha_client_cli asset get --account_id="White Rabbit@Soramitsu" --id="XOR#Soramitsu" 
```

### Create new Domain

Let's start with domain creation. We need to provide `create` command first, 
following by entity type (`domain` in our case) and list of required parameters.
For domain entity we only need `name` parameter which is stringly typed.

```bash
./iroha_client_cli domain add --name="Soramitsu"
```

### Create new Account

Right now we have the only domain without any accounts, let's fix it.
Like in the previous example, we need to define domain name, this time as 
`domain` argument, because `name` argument should be filled with account's name.
We also give a `key` argument with account's public key as a double-quoted
string value.

```bash
./iroha_client_cli account register --domain="Soramitsu" --name="White Rabbit" --key=""
```

### Mint Asset to Account

Okay, it's time to give something to our Account. We will add some Assets quantity to it.
This time we need to register an Asset Definition first and then add some Assets to the account.
As you can see, we use new command `asset` and it's subcommands `register` and `mint`. 

```bash
./iroha_client_cli asset register --domain="Soramitsu" --name="XOR" 
./iroha_client_cli asset mint --account_id="White Rabbit@Soramitsu" --id="XOR#Soramitsu" --quantity=1010 
```

### Query Account Assets Quantity

Because distributed systems heavily relay on the concept of eventual consistency and Iroha works in Consensus between peers, your requests may or may not be processed
while Iroha Client will successufully send them and Iroha Peer will accept them. Different stages of transactions processing and different cases may lead to
rejection of transaction after your receive response from Command Line Interface. To check that your instruction were applied and system now in the desired state
you need to become familar and use Query API.

Let's use Get Account Assets Query as an example. Command will look familar because it almost the same as the update command.
We need to know quantity so we skipp this argument and replace `update asset add` part with `get asset`.

```bash
./iroha_client_cli asset get --account_id="White Rabbit@Soramitsu" --id="XOR#Soramitsu" 
```
