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
