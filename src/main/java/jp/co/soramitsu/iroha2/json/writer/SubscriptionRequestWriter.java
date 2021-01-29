package jp.co.soramitsu.iroha2.json.writer;

import jp.co.soramitsu.iroha2.model.events.EntityType;
import jp.co.soramitsu.iroha2.model.events.SubscriptionRequest;
import jp.co.soramitsu.iroha2.model.events.SubscriptionRequest.Data;
import jp.co.soramitsu.iroha2.model.events.SubscriptionRequest.EventFilter;
import jp.co.soramitsu.iroha2.model.events.SubscriptionRequest.Pipeline;

public class SubscriptionRequestWriter implements JsonWriter<SubscriptionRequest> {

  public static class PipelineWriter implements JsonWriter<Pipeline> {

    @Override
    public String write(Pipeline value) {
      StringBuilder sb = new StringBuilder("{\"Pipeline\":{\"entity\":");
      EntityType entity = value.getEntity();
      if (entity != null) {
        sb.append('"');
        sb.append(entity.toString());
        sb.append('"');
      } else {
        sb.append("null");
      }
      sb.append(",\"hash\":");
      byte[] hash = value.getHash();
      if (hash != null) {
        sb.append('[');
        for (int i = 0; i < hash.length - 1; i++) {
          sb.append(Byte.toUnsignedInt(hash[i]));
          sb.append(',');
        }
        sb.append(Byte.toUnsignedInt(hash[hash.length - 1]));
        sb.append(']');
      } else {
        sb.append("null");
      }
      sb.append("}}");
      return sb.toString();
    }
  }

  private static final PipelineWriter PIPELINE_WRITER = new PipelineWriter();

  @Override
  public String write(SubscriptionRequest value) {
    StringBuilder sb = new StringBuilder();
    EventFilter eventFilter = value.getEventFilter();
    if (eventFilter instanceof Pipeline) {
      sb.append(PIPELINE_WRITER.write((Pipeline) eventFilter));
    } else if (eventFilter instanceof Data) {
      sb.append("{\"Data\":null}");
    }
    return sb.toString();
  }

}
