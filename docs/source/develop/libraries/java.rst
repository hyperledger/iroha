Java Library
------------

Client library of Iroha written completely in Java 8, which includes:

- SDK to work with Iroha API

- async wrapper over Iroha API

- `testcontainers` wrapper for convenient integration testing with Iroha

- examples in Java and Groovy

Both options are described in the following sections.
Please check readme file in `project's repo <https://github.com/hyperledger/iroha-java>`__.

How to use
^^^^^^^^^^

- `JitPack <https://jitpack.io/#hyperledger/iroha-java>`__
- `GitHub <https://github.com/hyperledger/iroha-java>`__

Example code
^^^^^^^^^^^^

.. code-block:: java

  import iroha.protocol.BlockOuterClass;
  import iroha.protocol.Primitive.RolePermission;
  import java.math.BigDecimal;
  import java.security.KeyPair;
  import java.util.Arrays;
  import jp.co.soramitsu.crypto.ed25519.Ed25519Sha3;
  import jp.co.soramitsu.iroha.testcontainers.IrohaContainer;
  import jp.co.soramitsu.iroha.testcontainers.PeerConfig;
  import jp.co.soramitsu.iroha.testcontainers.detail.GenesisBlockBuilder;
  import lombok.val;

  public class Example1 {

    private static final String bankDomain = "bank";
    private static final String userRole = "user";
    private static final String usdName = "usd";

    private static final Ed25519Sha3 crypto = new Ed25519Sha3();

    private static final KeyPair peerKeypair = crypto.generateKeypair();

    private static final KeyPair useraKeypair = crypto.generateKeypair();
    private static final KeyPair userbKeypair = crypto.generateKeypair();

    private static String user(String name) {
      return String.format("%s@%s", name, bankDomain);
    }

    private static final String usd = String.format("%s#%s", usdName, bankDomain);

    /**
     * <pre>
     * Our initial state cosists of:
     * - domain "bank", with default role "user" - can transfer assets and can query their amount
     * - asset usd#bank with precision 2
     * - user_a@bank, which has 100 usd
     * - user_b@bank, which has 0 usd
     * </pre>
     */
    private static BlockOuterClass.Block getGenesisBlock() {
      return new GenesisBlockBuilder()
          // first transaction
          .addTransaction(
              // transactions in genesis block can have no creator
              Transaction.builder(null)
                  // by default peer is listening on port 10001
                  .addPeer("0.0.0.0:10001", peerKeypair.getPublic())
                  // create default "user" role
                  .createRole(userRole,
                      Arrays.asList(
                          RolePermission.can_transfer,
                          RolePermission.can_get_my_acc_ast,
                          RolePermission.can_get_my_txs,
                          RolePermission.can_receive
                      )
                  )
                  .createDomain(bankDomain, userRole)
                  // create user A
                  .createAccount("user_a", bankDomain, useraKeypair.getPublic())
                  // create user B
                  .createAccount("user_b", bankDomain, userbKeypair.getPublic())
                  // create usd#bank with precision 2
                  .createAsset(usdName, bankDomain, 2)
                  // transactions in genesis block can be unsigned
                  .build() // returns ipj model Transaction
                  .build() // returns unsigned protobuf Transaction
          )
          // we want to increase user_a balance by 100 usd
          .addTransaction(
              Transaction.builder(user("user_a"))
                  .addAssetQuantity(usd, new BigDecimal("100"))
                  .build()
                  .build()
          )
          .build();
    }

    public static PeerConfig getPeerConfig() {
      PeerConfig config = PeerConfig.builder()
          .genesisBlock(getGenesisBlock())
          .build();

      // don't forget to add peer keypair to config
      config.withPeerKeyPair(peerKeypair);

      return config;
    }

    /**
     * Custom facade over GRPC Query
     */
    public static int getBalance(IrohaAPI api, String userId, KeyPair keyPair) {
      // build protobuf query, sign it
      val q = Query.builder(userId, 1)
          .getAccountAssets(userId)
          .buildSigned(keyPair);

      // execute query, get response
      val res = api.query(q);

      // get list of assets from our response
      val assets = res.getAccountAssetsResponse().getAccountAssetsList();

      // find usd asset
      val assetUsdOptional = assets
          .stream()
          .filter(a -> a.getAssetId().equals(usd))
          .findFirst();

      // numbers are small, so we use int here for simplicity
      return assetUsdOptional
          .map(a -> Integer.parseInt(a.getBalance()))
          .orElse(0);
    }

    public static void main(String[] args) {
      // for simplicity, we will create Iroha peer in place
      IrohaContainer iroha = new IrohaContainer()
          .withPeerConfig(getPeerConfig());

      // start the peer. blocking call
      iroha.start();

      // create API wrapper
      IrohaAPI api = new IrohaAPI(iroha.getToriiAddress());

      // transfer 100 usd from user_a to user_b
      val tx = Transaction.builder("user_a@bank")
          .transferAsset("user_a@bank", "user_b@bank", usd, "For pizza", "10")
          .sign(useraKeypair)
          .build();

      // create transaction observer
      // here you can specify any kind of handlers on transaction statuses
      val observer = TransactionStatusObserver.builder()
          // executed when stateless or stateful validation is failed
          .onTransactionFailed(t -> System.out.println(String.format(
              "transaction %s failed with msg: %s",
              t.getTxHash(),
              t.getErrOrCmdName()
          )))
          // executed when got any exception in handlers or grpc
          .onError(e -> System.out.println("Failed with exception: " + e))
          // executed when we receive "committed" status
          .onTransactionCommitted((t) -> System.out.println("Committed :)"))
          // executed when transfer is complete (failed or succeed) and observable is closed
          .onComplete(() -> System.out.println("Complete"))
          .build();

      // blocking send.
      // use .subscribe() for async sending
      api.transaction(tx)
          .blockingSubscribe(observer);

      /// now lets query balances
      val balanceUserA = getBalance(api, user("user_a"), useraKeypair);
      val balanceUserB = getBalance(api, user("user_b"), userbKeypair);

      // ensure we got correct balances
      assert balanceUserA == 90;
      assert balanceUserB == 10;
    }
  }
