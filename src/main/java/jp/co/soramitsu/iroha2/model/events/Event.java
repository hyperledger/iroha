package jp.co.soramitsu.iroha2.model.events;

import lombok.Data;
import lombok.NonNull;

/**
 * Responses to event subscription.
 */
@Data
public class Event {

  public interface EventType {

  }

  public static class Data implements EventType {

  }

  @lombok.Data
  public static class Pipeline implements EventType {

    public interface Status {

    }

    public static class Validating implements Status {

    }

    @lombok.Data
    public static class Rejected implements Status {

      @NonNull
      private String rejectedReason;
    }

    public static class Committed implements Status {

    }

    @NonNull
    private EntityType entityType;
    @NonNull
    private Status status;
    @NonNull
    private byte[] hash;
  }

  @NonNull
  private EventType event;

}
