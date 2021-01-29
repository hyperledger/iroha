package jp.co.soramitsu.iroha2.model.events;

import lombok.Data;
import lombok.NonNull;

@Data
public class SubscriptionRequest {

  public interface EventFilter {

  }

  public static class Pipeline implements EventFilter {

    private EntityType entity;
    private byte[] hash;

    public Pipeline() {
    }

    public Pipeline(EntityType entity) {
      this.entity = entity;
    }

    public Pipeline(EntityType entity, byte[] hash) {
      this.entity = entity;
      this.hash = hash;
    }

    public EntityType getEntity() {
      return entity;
    }

    public void setEntity(EntityType entity) {
      this.entity = entity;
    }

    public byte[] getHash() {
      return hash;
    }

    public void setHash(byte[] hash) {
      this.hash = hash;
    }
  }

  public static class Data implements EventFilter {

  }

  @NonNull
  private EventFilter eventFilter;
}
