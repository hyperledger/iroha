Feature: Queries feature
  Scenario: Root requests all Domains
    Given Iroha Peer is up
    And Peer has Domain with name company
    And Peer has Domain with name another_company
    When root Account from global domain requests all domains
    Then QueryResult has Domain with name company
    And QueryResult has Domain with name another_company
    And Iroha Peer is down
  Scenario: Root requests all Accounts
    Given Iroha Peer is up
    And Peer has Domain with name company
    And Peer has Account with name nikita and domain company
    And Peer has Account with name another_nikita and domain company
    When root Account from global domain requests all accounts
    Then QueryResult has Account with name nikita
    And QueryResult has Account with name another_nikita
    And Iroha Peer is down
  Scenario: Root requests all Asset Definitions
    Given Iroha Peer is up
    And Peer has Domain with name company
    And Peer has Asset Definition with name xor and domain company
    And Peer has Asset Definition with name another_xor and domain company
    When root Account from global domain requests all asset definitions
    Then QueryResult has Asset Definition with name xor and domain company
    And QueryResult has Asset Definition with name another_xor and domain company
    And Iroha Peer is down
  Scenario: Root requests all Assets
    Given Iroha Peer is up
    And Peer has Domain with name company
    And Peer has Asset Definition with name xor and domain company
    And Peer has Account with name nikita and domain company
    And nikita Account in domain company has 1 quantity of Asset with definition xor in domain company
    And Peer has Asset Definition with name another_xor and domain company
    And Peer has Account with name another_nikita and domain company
    And another_nikita Account in domain company has 1 quantity of Asset with definition another_xor in domain company
    When root Account from global domain requests all assets
    Then QueryResult has Asset with definition xor in domain company
    And QueryResult has Asset with definition another_xor in domain company
    And Iroha Peer is down
