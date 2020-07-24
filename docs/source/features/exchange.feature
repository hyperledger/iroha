Feature: Decentralized Exchange

  Scenario: Buyer exchanges 20xor for 100usd
    Given Iroha Peer is up
    And Iroha DEX module enabled
    And Peer has Domain with name exchange
    And Peer has Account with name buyer and domain exchange
    And Peer has Account with name seller and domain exchange
    And Peer has Asset Definition with name xor and domain exchange
    And Peer has Asset Definition with name usd and domain exchange
    And buyer Account in domain exchange has 100 amount of Asset with definition usd in domain exchange
    And seller Account in domain exchange has 20 amount of Asset with definition xor in domain exchange
    When buyer Account places Exchange Order 20xor for 100usd
    And seller Account places Exchange Order 100usd for 20 xor
    Then Iroha transfer 20 amount of Asset with definition xor in domain exchange from seller account in domain exchange to buyer account in domain exchange
    And Iroha transfer 100 amount of Asset with definition usd in domain exchange from account buyer in domain exchange to seller account in domain exchange

  Scenario: Buyer exchanges 1btc for 20eth across bridges
    Given Iroha Peer is up
    And Iroha Bridge module enabled
    And Iroha DEX module enabled
    And Peer has Domain with name exchange
    And Peer has Account with name buyer and domain exchange
    And Peer has Account with name seller and domain exchange
    And Peer has Asset Definition with name btc and domain exchange
    And Peer has Asset Definition with name eth and domain exchange
    And Peer has Bridge with name btc and owner btc_owner
    And Peer has Bridge with name eth and owner eth_owner
    And eth Brdige has buyer Account in domain exchange registered
    And btc Brdige has seller Account in domain exchange registered
    When buyer Account places Exchange Order 20xor for 100usd
    And seller Account places Exchange Order 100usd for 20 xor
    Then Iroha mint 1 amount of Asset with definition btc in domain exchange to seller Account in domain exchange using btc Bridge
    And Iroha mint 20 amount of Asset with definition eth in domain exchange to buyer Account in domain exchange using eth Bridge
    And Iroha transfer 1 amount of Asset with definition btc in domain exchange from seller account in domain exchange to buyer account in domain exchange
    And Iroha transfer 20 amount of Asset with definition eth in domain exchange from buyer account in domain exchange to seller account in domain exchange

  Scenario: Liquidity provider exchanges with seller
    Given Iroha Peer is up
    And Iroha DEX module enabled
    And Peer has Domain with name exchange
    And Peer has Account with name liquidity_provider and domain exchange
    And Peer has Account with name seller and domain exchange
    And Peer has Asset Definition with name xor and domain exchange
    And Peer has Asset Definition with name btc and domain exchange
    And Peer has Asset Definition with name eth and domain exchange
    And liquidity_provider Account in domain exchange has 1 amount of Asset with definition btc in domain exchange
    And liquidity_provider Account in domain exchange has 20 amount of Asset with definition eth in domain exchange
    And liquidity_provider Account in domain exchange has 20 amount of Asset with definition xor in domain exchange
    And seller Account in domain exchange has 20 amount of Asset with definition eth in domain exchange
    When liquidity_provider Account registers Exchange Liquidity 20xor and 20eth and 1btc
    And seller Account places Exchange Order 20eth for 1btc
    Then Iroha transfer 1 amount of Asset with definition btc in domain exchange from seller account in domain exchange to liquidity_provider account in domain exchange
    And Iroha transfer 20 amount of Asset with definition eth in domain exchange from liquidity_provider account in domain exchange to seller account in domain exchange
