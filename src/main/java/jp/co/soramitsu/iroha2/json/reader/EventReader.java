package jp.co.soramitsu.iroha2.json.reader;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonDeserializationContext;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import java.lang.reflect.Type;
import jp.co.soramitsu.iroha2.model.events.EntityType;
import jp.co.soramitsu.iroha2.model.events.Event;
import jp.co.soramitsu.iroha2.model.events.Event.Data;
import jp.co.soramitsu.iroha2.model.events.Event.EventType;
import jp.co.soramitsu.iroha2.model.events.Event.Pipeline;
import jp.co.soramitsu.iroha2.model.events.Event.Pipeline.Committed;
import jp.co.soramitsu.iroha2.model.events.Event.Pipeline.Rejected;
import jp.co.soramitsu.iroha2.model.events.Event.Pipeline.Status;
import jp.co.soramitsu.iroha2.model.events.Event.Pipeline.Validating;

public class EventReader implements JsonReader<Event> {

  private static class EventDeserializer implements JsonDeserializer<Event> {

    @Override
    public Event deserialize(JsonElement json, Type typeOfT,
        JsonDeserializationContext context) throws JsonParseException {
      EventType eventType;
      if (json.getAsJsonObject().get("Data") != null) {
        eventType = new Data();
      } else if (json.getAsJsonObject().get("Pipeline") != null) {
        JsonObject pipeline = json.getAsJsonObject().get("Pipeline").getAsJsonObject();
        EntityType entityType;
        String entityString = pipeline.get("entity_type").getAsString();
        if (entityString.equals("Transaction")) {
          entityType = EntityType.Transaction;
        } else if (entityString.equals("Block")) {
          entityType = EntityType.Block;
        } else {
          throw new JsonParseException("Unexpected entity_type: " + entityString);
        }

        JsonElement statusJsonElement = pipeline.get("status");
        Status status;
        if (statusJsonElement.isJsonObject()) {
          JsonObject statusJsonObject = statusJsonElement.getAsJsonObject();
          status = new Rejected(statusJsonObject.get("Rejected").getAsString());
        } else {
          String statusString = statusJsonElement.getAsString();
          if (statusString.equals("Validating")) {
            status = new Validating();
          } else if (statusString.equals("Committed")) {
            status = new Committed();
          } else {
            throw new JsonParseException("Unexpected status: " + statusString);
          }
        }

        JsonArray bytes = pipeline.get("hash").getAsJsonArray();
        byte[] hash = new byte[bytes.size()];
        for (int i = 0; i < bytes.size(); ++i) {
          hash[i] = bytes.get(i).getAsByte();
        }
        eventType = new Pipeline(entityType, status, hash);
      } else {
        throw new JsonParseException("Unexpected event type.");
      }

      return new Event(eventType);
    }
  }

  private static final Gson GSON = new GsonBuilder()
      .registerTypeAdapter(Event.class, new EventDeserializer()).create();

  @Override
  public Event read(String json) {
    return GSON.fromJson(json, Event.class);
  }

}
