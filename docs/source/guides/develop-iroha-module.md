# How to Develop a New Iroha Module

When you need to add some functionality to Iroha, use this guide to develop a new Iroha Module.

## Prerequisites

* [Rust](https://www.rust-lang.org/tools/install)
* Text Editor or IDE

## Steps

### 1. Create new Rust module inside Iroha crate

Inside `iroha/src/lib.rs` add a declaration of your new module.
For example, for `bridge` module we add the following declaration,

```rust
#[cfg(feature = "bridge")]
pub mod bridge;
```

so for you module `x` you would add `pub mod x;`.
You should also place your new module under the [Cargo feature](https://doc.rust-lang.org/cargo/reference/features.html) so other developers would be able to turn it on and off when needed.

Now, create a separate file for your module.
For `bridge` module it will be `iroha/src/bridge.rs`.
Likewise, for your module `x` you will need to create a new file `iroha/src/x.rs`.

### 2. Add documentation

Each module must provide description of its own functionality via Rust Docs.

For that, at the beginning of the module file you should place docs block for the enclosing item.

```rust
//! Here you can see a good description of the module `x` and its functionality.
```

All public entites of your module should be documented as well. But first, let's create them.

### 3. Write your logic

The development of a new Iroha Module has a goal - to bring new functionality to Iroha.
So based on the goal and requirements, you have you will introduce new entities and place them inside newly created module.

Let's specify particular categories of such entities and look how they can be implemented according to Iroha best practices.

#### 4. Add custom Iroha Special Instruction

If you need to have some module-related Iroha Special Instructions you should add `isi` submodule to the file of your newly created module, like that:

```rust
...
pub mod isi {
}
```

Inside this submodule you may declare new Iroha Special Instructions.
To provide safety guarantees, Iroha Modules can create new Iroha Special Instructions composed of the Out of the Box Instructions.

Let's look at the [example](https://github.com/hyperledger/iroha/blob/2005335348585b03b3ee7887272af4c76170c10a/iroha/src/bridge.rs) from the `bridge` Iroha Module:

```rust
...
pub fn register_bridge(&self, bridge_definition: BridgeDefinition) -> Instruction {
    let seed = crate::crypto::hash(bridge_definition.encode());
    let public_key = crate::crypto::generate_key_pair_from_seed(seed)
        .expect("Failed to generate key pair.")
        .0;
    let domain = Domain::new(bridge_definition.id.name.clone());
    let account = Account::new("bridge", &domain.name, public_key);
    Instruction::If(
        Box::new(Instruction::ExecuteQuery(IrohaQuery::GetAccount(
            GetAccount {
                account_id: bridge_definition.owner_account_id.clone(),
            },
        ))),
        Box::new(Instruction::Sequence(vec![
            Add {
                object: domain.clone(),
                destination_id: self.id.clone(),
            }
            .into(),
            Register {
                object: account.clone(),
                destination_id: domain.name,
            }
            .into(),
            Mint {
                object: (
                    "owner_id".to_string(),
                    bridge_definition.owner_account_id.to_string(),
                ),
                destination_id: AssetId {
                    definition_id: owner_asset_definition_id(),
                    account_id: account.id.clone(),
                },
            }
            .into(),
            Mint {
                object: (
                    "bridge_definition".to_string(),
                    format!("{:?}", bridge_definition.encode()),
                ),
                destination_id: AssetId {
                    definition_id: bridge_asset_definition_id(),
                    account_id: account.id,
                },
            }
            .into(),
        ])),
        None,
    )
}
...
```

And see what it does to register a new Bridge:

1. Check that Bridge's Owner's Account exists and terminate execution if not.
1. Add new Domain.
1. Register new Account.
1. Mint one Asset.
1. Mint another Asset.

We will not discuss Bridge-related terminology here – the thing we want to look at is how we can compose these steps into one new Iroha Special Instruction.

As you can see, we have `Instruction::If(...)` here - it's [the utility Iroha Special Instruction](references/glossary#utility-iroha-special-instruction).
It takes three arguments - `condition`, `instruction_to_do_if_true`, `instruction_to_do_if_false_or_nothing`.
By this instruction we've made the first step of our algorithm - run a check and terminated execution if there is no Owner's Account.
Inside `condition` we placed `Instruction::ExecuteQuery(...)` which fails if [Iroha Query](references/glossary#iroha-query) fails.

If the first step succeeds, we should move forward and execute sequence of the following steps.
For this purpose we also have a utility Iroha Special Instruction `Sequence` with a [vector](https://doc.rust-lang.org/alloc/vec/struct.Vec.html) of Iroha Special Instructions executed one by one.

Inside this sequence we use [domains-related Iroha Special Instructions](references/glossary#domains-related-iroha-special-instruction) `Add`, `Register`, and `Mint` twice.

## Additional resources

* //TODO: add link to the pair programming session on `Bridge` module.
