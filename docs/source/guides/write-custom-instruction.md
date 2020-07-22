# How to Write a Custom Iroha Special Instruction

When you need to add new instruction to Iroha, use this guide to write custom Iroha Special Instruction.

## Prerequisites

* [Rust](https://www.rust-lang.org/tools/install)
* Text Editor or IDE

## Steps

### 1. Declare your intention

Iroha Special Instruction is a high level representation of changes to the World State View.
They have more imperative instructions under the hood, while you may concentrate on
the business logic. Let's take an example the following User's Story for `Bridge` module:

```gherkin
Feature: Bridge feature
  Scenario: Owner registers Bridge
    Given Iroha Peer is up
    And Iroha Bridge module enabled
    And Iroha has Domain with name company
    And Iroha has Account with name bridge_owner and domain company
    When bridge_owner Account from company domain registers Bridge with name polkadot
    Then Iroha has Domain with name polkadot
    And Iroha has Account with name bridge and domain polkadot
    And Iroha has Bridge Definition with name polkadot and kind iclaim and owner bridge_owner
    And Iroha has Asset with definition bridge_asset in domain bridge and under account bridge in domain polkadot 
```

### 2. Extract the algorithm

As you can see - **Then** section contains expected output of our **When** instruction.

Let's look at it from another perspective and instead of **Then** use **Do**

```
Register polkadot domain 
Register bridge account under polkadot domain
Register Bridge Definition polkadot with kind iclaim and bridge_owner owner
Mint Asset with definition bridge_asset in domain bridge under account bridge in domain polkadot
```

This representation looks more like an algorithm and can be used to compose several [out-of-the-box instructions](#)
into a new [custome Iroha special instruction](#).

### 3. Write your own instruction

Now let's write some code:

```rust
    /// Constructor of Iroha Special Instruction for bridge registration.
    pub fn register_bridge(
        peer_id: <Peer as Identifiable>::Id,
        bridge_definition: &BridgeDefinition,
    ) -> Instruction {
        let domain = Domain::new(bridge_definition.id.name.clone());
        let account = Account::new(BRIDGE_ACCOUNT_NAME, &domain.name);
        Instruction::If(
            Box::new(Instruction::ExecuteQuery(IrohaQuery::GetAccount(
                GetAccount {
                    account_id: bridge_definition.owner_account_id.clone(),
                },
            ))),
            Box::new(Instruction::Sequence(vec![
                Add {
                    object: domain.clone(),
                    destination_id: peer_id,
                }
                .into(),
                Register {
                    object: account.clone(),
                    destination_id: domain.name,
                }
                .into(),
                Mint {
                    object: (
                        BRIDGE_ASSET_BRIDGE_DEFINITION_PARAMETER_KEY.to_string(),
                        bridge_definition.encode(),
                    ),
                    destination_id: AssetId {
                        definition_id: bridge_asset_definition_id(),
                        account_id: account.id,
                    },
                }
                .into(),
                Mint {
                    object: (
                        bridge_definition.id.name.clone(),
                        bridge_definition.encode(),
                    ),
                    destination_id: AssetId {
                        definition_id: bridges_asset_definition_id(),
                        account_id: bridge_definition.owner_account_id.clone(),
                    },
                }
                .into(),
                // TODO: add incoming transfer event listener
            ])),
            Some(Box::new(Instruction::Fail(
                "Account not found.".to_string(),
            ))),
        )
    }

```

Using a sequence of Iroha Special Instructions we compose existing functionality into a new one.

## Additional resources

//TODO add additional references
