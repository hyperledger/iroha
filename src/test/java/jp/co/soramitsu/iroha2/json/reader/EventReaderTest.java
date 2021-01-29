package jp.co.soramitsu.iroha2.json.reader;

import com.google.gson.JsonParseException;
import jp.co.soramitsu.iroha2.model.events.EntityType;
import jp.co.soramitsu.iroha2.model.events.Event;
import jp.co.soramitsu.iroha2.model.events.Event.Data;
import jp.co.soramitsu.iroha2.model.events.Event.Pipeline;
import jp.co.soramitsu.iroha2.model.events.Event.Pipeline.Committed;
import jp.co.soramitsu.iroha2.model.events.Event.Pipeline.Rejected;
import jp.co.soramitsu.iroha2.model.events.Event.Pipeline.Validating;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class EventReaderTest {

  /**
   * Event response contains invalid event type - should throw
   */
  @Test
  public void testInvalidEventType() {
    Assertions.assertThrows(JsonParseException.class, () -> {
      String json = "{\"Invalid\":null}";
      EventReader reader = new EventReader();
      Event event = reader.read(json);
    });
  }

  /**
   * Event response contains Data event type - not implemented yet
   */
  @Test
  public void testDataEventType() {
    String json = "{\"Data\":null}";
    EventReader reader = new EventReader();
    Event event = reader.read(json);
    Assertions.assertTrue(event.getEvent() instanceof Data);
  }

  /**
   * Event response contains Pipeline event type with Validating tx status and hash
   */
  @Test
  public void testEventPipelineValidating() {
    String json = "{\"Pipeline\":{\"entity_type\":\"Transaction\",\"status\":\"Validating\",\"hash\":[18,46,132,205,31,133,146,156,172,82,218,63,96,81,57,222,72,175,111,163,149,247,235,237,62,231,49,103,132,119,96,71]}}";
    EventReader reader = new EventReader();
    Event event = reader.read(json);
    Assertions.assertTrue(event.getEvent() instanceof Pipeline);
    Pipeline pipeline = (Pipeline) event.getEvent();
    Assertions.assertEquals(EntityType.Transaction, pipeline.getEntityType());
    Assertions.assertTrue(pipeline.getStatus() instanceof Validating);
    Assertions.assertEquals(32, pipeline.getHash().length);
  }

  /**
   * Event response contains Pipeline event type with Block Committed status and hash
   */
  @Test
  public void testEventBlockCommitted() {
    String json = "{\"Pipeline\":{\"entity_type\":\"Block\",\"status\":\"Committed\",\"hash\":[141,51,138,117,230,160,13,118,224,248,120,6,38,230,202,226,255,146,211,99,171,239,240,150,240,50,180,127,222,232,11,12]}}";
    EventReader reader = new EventReader();
    Event event = reader.read(json);
    Assertions.assertTrue(event.getEvent() instanceof Pipeline);
    Pipeline pipeline = (Pipeline) event.getEvent();
    Assertions.assertEquals(EntityType.Block, pipeline.getEntityType());
    Assertions.assertTrue(pipeline.getStatus() instanceof Committed);
    Assertions.assertEquals(32, pipeline.getHash().length);
  }

  /**
   * Event response contains Pipeline event with tx rejected
   */
  @Test
  public void testEventTransactionRejected() {
    String json = "{\"Pipeline\":{\"entity_type\":\"Transaction\",\"status\":{\"Rejected\":\"Failed to find domain.\"},\"hash\":[191,135,19,209,197,227,19,112,1,114,234,217,131,90,0,122,202,30,247,164,166,102,123,216,110,222,45,3,79,137,67,191]}}";
    EventReader reader = new EventReader();
    Event event = reader.read(json);
    Assertions.assertTrue(event.getEvent() instanceof Pipeline);
    Pipeline pipeline = (Pipeline) event.getEvent();
    Assertions.assertEquals(EntityType.Transaction, pipeline.getEntityType());
    Assertions.assertTrue(pipeline.getStatus() instanceof Rejected);
    Rejected rejected = (Rejected) pipeline.getStatus();
    Assertions.assertEquals("Failed to find domain.", rejected.getRejectedReason());
    Assertions.assertEquals(32, pipeline.getHash().length);
  }

}
