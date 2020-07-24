Feature: Bridge feature
  Scenario: Owner registers Bridge
    Given Iroha Peer is up
    And Iroha Bridge module enabled
    And Peer has Domain with name company
    And Peer has Account with name bridge_owner and domain company
    When bridge_owner Account from company domain registers Bridge with name polkadot
    Then Peer has Domain with name polkadot
    And Peer has Account with name bridge and domain polkadot
    And Peer has Bridge Definition with name polkadot and kind iclaim and owner bridge_owner
    And Peer has Asset with definition bridge_asset in domain bridge and under account bridge in domain polkadot
    And Iroha Peer is down
