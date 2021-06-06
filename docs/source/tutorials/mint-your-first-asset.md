# Minting your first Asset

When you use Iroha in your application you will definitely face the need to mint an asset.
Use this tutorial to master Iroha Special Instructions in general and `MintAsset` in particular.

## Prerequisites

* [Rust](https://www.rust-lang.org/tools/install)
* Text Editor or IDE
* Existing Rust project //TODO: create some sandbox project

## Steps

### 1. Add dependency on Iroha crate

Inside `path_to_your_project/Cargo.toml` add a new dependency:

```toml
iroha = "2.0.0"
```

### 2. Find a place where you need to mint an asset

Usually any business operation will have a need to mint an asset:

* Uploading of digital documents
* Withdrawl and initial supply of crypto currencies
* Etc.

Look at your project and find a good place to put it, which will encapsulate Iroha related logic inside
and may be easily modified if needed in future.

### 3. Use Iroha CLI Client to prepare Iroha Peer

Iroha Special Instructions executed on behalf of an authority - Account.

If you already has an account to store assets on - feel free to skip these step.
If not - you will need to receive Account's Key Pair with permissions to Register an Account.

TL;DR - after [configuration of Iroha CLI](https://github.com/hyperledger/iroha/blob/iroha2-dev/iroha_client_cli/README.md)
run this command:

```bash
./iroha_client_cli account register --id="my_account@my_domain" --key="{account_public_key}"
```

### 4. Construct Iroha Special Instruction

Now we can write some real code, let's imagine that you need to mint 200 amount of crypto currency "xor":

```rust
let mint_asset = isi::Mint {
    object: 200,
    destination_id: AssetId {
        definition_id: "xor#soramitsu",
        account_id: "my_account@my_domain",
    },
};
```

And let's see what it consist of:

* `isi` module contains basic Iroha special instructions functionality
* `Mint` structure is a declaration - "Iroha - Mint this object to the following destination"
* `object` in our case is an amount of "xor" to mint. In other cases it can be bytes of digital document or other data.
* `destination_id` in our case is an asset's identification which consist of a asset's definition identification and 
account's identification cross product.

This functionality also available via Iroha CLI Client but we did it via Rust code on purpose.

### 5. Submit Iroha Special Instruction

```rust
iroha_client
  .submit(mint_asset.into())
  .await
  .expect("Failed to mint an asset.");
```

`iroha_client` provides functionality to submit iroha special instructions and it will be automatically 
"pack" them into transaction signed on behalf of the client. As a result of this operation
you will receive transaction acceptance status - if transaction was accepted by the peer
(signature was valid and payload is legal set of iroha special instructions) then
it will be `Result::Ok(())`, if some problems arrive - it will be `Result::Err(String)` 
with textual error message.

## Conclusion
It is necessary to be aware of Iroha domain model and set of out-of-the-box Iroha Special Instructions 
and Queries to develop custom projects based on it. But once you understand this model, it provides 
very simple and clean approach to declaratively define desired steps and send them for execution.

## Further reading
