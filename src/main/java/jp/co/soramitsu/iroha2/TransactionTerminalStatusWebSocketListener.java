package jp.co.soramitsu.iroha2;

import java.net.http.WebSocket;
import java.net.http.WebSocket.Listener;
import java.util.Arrays;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import jp.co.soramitsu.iroha2.json.reader.EventReader;
import jp.co.soramitsu.iroha2.model.events.EntityType;
import jp.co.soramitsu.iroha2.model.events.Event;
import jp.co.soramitsu.iroha2.model.events.Event.Pipeline;
import jp.co.soramitsu.iroha2.model.events.Event.Pipeline.Committed;
import jp.co.soramitsu.iroha2.model.events.Event.Pipeline.Rejected;

/**
 * Listener waits for terminal status (committed or rejected).
 * Result can be obtained with getResult() method.
 */
public class TransactionTerminalStatusWebSocketListener implements Listener {

  static class TerminalStatus {

    private boolean committed;
    private String message;

    public TerminalStatus(boolean committed) {
      this.committed = committed;
    }

    public TerminalStatus(boolean committed, String message) {
      this.committed = committed;
      this.message = message;
    }

    public boolean isCommitted() {
      return committed;
    }

    public void setCommitted(boolean committed) {
      this.committed = committed;
    }

    public String getMessage() {
      return message;
    }

    public void setMessage(String message) {
      this.message = message;
    }
  }

  CompletableFuture<TerminalStatus> result = new CompletableFuture<>();
  EntityType entityType;
  byte[] hash;

  private static final EventReader EVENT_READER = new EventReader();

  public TransactionTerminalStatusWebSocketListener(EntityType entityType, byte[] hash) {
    this.entityType = entityType;
    this.hash = hash;
  }

  @Override
  public void onOpen(WebSocket webSocket) {
    WebSocket.Listener.super.onOpen(webSocket);
  }

  @Override
  public CompletionStage<?> onText(WebSocket webSocket, CharSequence data, boolean last) {
    Event event = EVENT_READER.read(data.toString());

    if (event.getEvent() instanceof Pipeline) {
      Pipeline pipeline = (Pipeline) event.getEvent();
      if (pipeline.getEntityType() == entityType && Arrays.equals(pipeline.getHash(), hash)) {
        if (pipeline.getStatus() instanceof Committed) {
          result.complete(new TerminalStatus(true));
        } else if (pipeline.getStatus() instanceof Rejected) {
          result.complete(
              new TerminalStatus(false, ((Rejected) pipeline.getStatus()).getRejectedReason()));
        }
      }
    }

    // event received response
    webSocket.sendText("null", true).join();
    Listener.super.onText(webSocket, data, last);
    return null;
  }

  public CompletableFuture<TerminalStatus> getResult() {
    return result;
  }
}
