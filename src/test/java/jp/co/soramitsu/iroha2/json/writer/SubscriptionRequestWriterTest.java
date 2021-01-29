package jp.co.soramitsu.iroha2.json.writer;

import java.util.Arrays;
import jp.co.soramitsu.iroha2.model.events.EntityType;
import jp.co.soramitsu.iroha2.model.events.SubscriptionRequest;
import jp.co.soramitsu.iroha2.model.events.SubscriptionRequest.Data;
import jp.co.soramitsu.iroha2.model.events.SubscriptionRequest.Pipeline;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * Test JSON serialization of SubscriptionRequestWriter
 */
public class SubscriptionRequestWriterTest {

  SubscriptionRequestWriter writer = new SubscriptionRequestWriter();

  /**
   * SubscriptionRequest initialized with Data event filter. Expected data from iroha2 Rust
   * implementations.
   */
  @Test
  public void testDataEventFilter() {
    SubscriptionRequest subscriptionRequest = new SubscriptionRequest(new Data());

    Assertions.assertEquals("{\"Data\":null}", writer.write(subscriptionRequest));
  }

  /**
   * SubscriptionRequest initialized with Pipeline event filter. Expected data from iroha2 Rust
   * implementations.
   */
  @Test
  public void testPipelineEventFilter() {
    SubscriptionRequest subscriptionRequest = new SubscriptionRequest(new Pipeline());

    Assertions.assertEquals("{\"Pipeline\":{\"entity\":null,\"hash\":null}}",
        writer.write(subscriptionRequest));
  }

  /**
   * SubscriptionRequest initialized with Pipeline event filter by transaction. Expected data from
   * iroha2 Rust implementations.
   */
  @Test
  public void testPipelineEventFilterByTransaction() {
    SubscriptionRequest subscriptionRequest = new SubscriptionRequest(
        new Pipeline(EntityType.Transaction));

    Assertions.assertEquals("{\"Pipeline\":{\"entity\":\"Transaction\",\"hash\":null}}",
        writer.write(subscriptionRequest));
  }

  /**
   * SubscriptionRequest initialized with Pipeline event filter by transaction hash. Expected data
   * from iroha2 Rust implementations.
   */
  @Test
  public void testPipelineEventFilterByTransactionHash() {
    byte[] hash = new byte[32];
    Arrays.fill(hash, (byte) 2);
    SubscriptionRequest subscriptionRequest = new SubscriptionRequest(
        new Pipeline(EntityType.Transaction, hash));

    Assertions.assertEquals(
        "{\"Pipeline\":{\"entity\":\"Transaction\",\"hash\":[2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2]}}",
        writer.write(subscriptionRequest));
  }

  /**
   * SubscriptionRequest initialized with Pipeline event filter by transaction hash. Expected data
   * from iroha2 Rust implementations.
   */
  @Test
  public void testPipelineEventFilterByBlockHash() {
    byte[] hash = new byte[32];
    Arrays.fill(hash, (byte) 2);
    SubscriptionRequest subscriptionRequest = new SubscriptionRequest(
        new Pipeline(EntityType.Block, hash));

    Assertions.assertEquals(
        "{\"Pipeline\":{\"entity\":\"Block\",\"hash\":[2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2]}}",
        writer.write(subscriptionRequest));
  }
}
