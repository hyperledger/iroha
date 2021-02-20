Feature: Iroha Special Instructions feature
  Scenario: Root sets Block Time 
    Given Iroha Peer is up
    When root Account from global domain sets Block Time to 47 milliseconds
    And root Account from global domain requests Block Time
    Then QueryResult contains Parameter Block Time with value 47
    And Iroha Peer is down
  Scenario: Root sets Transaction Receipt Time
    Given Iroha Peer is up
    When root Account from global domain sets Transaction Receipt Time to 84 milliseconds
    And root Account from global domain requests Transaction Receipt Time
    Then QueryResult contains Parameter Transaction Receipt Time with value 84
    And Iroha Peer is down
  Scenario: Root sets Commit Time
    Given Iroha Peer is up
    When root Account from global domain sets Commit Time to 111 milliseconds
    And root Account from global domain requests Commit Time
    Then QueryResult contains Parameter Commit Time with value 111
    And Iroha Peer is down
  Scenario: Root sets Maximum Faulty Peers Amount
    Given Iroha Peer is up
    When root Account from global domain sets Maximum Faulty Peers Amount to 2
    And root Account from global domain requests Maximum Faulty Peers Amount
    Then QueryResult contains Parameter Maximum Faulty Peers Amount with value 2
    And Iroha Peer is down
  Scenario: Root registers new Trusted Peer
    Given Iroha Peer is up
    When root Account from global domain registers new Trusted Peer with URL trust and Public Key ed01207233bfc89dcbd68c19fde6ce6158225298ec1131b6a130d1aeb454c1ab5183c0
    And root Account from global domain requests List of Trusted Peers
    Then QueryResult contains Trusted Peer with URL trust and Public Key ed01207233bfc89dcbd68c19fde6ce6158225298ec1131b6a130d1aeb454c1ab5183c0
    And Iroha Peer is down
