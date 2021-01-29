package jp.co.soramitsu.iroha2;

import java.net.http.WebSocket;
import java.net.http.WebSocket.Listener;
import java.nio.ByteBuffer;
import java.util.concurrent.CompletionStage;

public class PrintingWebSocketListener implements Listener {

  @Override
  public void onOpen(WebSocket webSocket) {
    System.out.println("onOpen");
    WebSocket.Listener.super.onOpen(webSocket);
  }

  @Override
  public CompletionStage<?> onText(WebSocket webSocket, CharSequence data, boolean last) {
    System.out.println("onText");
    System.out.println("  data: " + data.toString());
    System.out.println("  last: " + last);

    // event received response
    webSocket.sendText("null", true).join();
    WebSocket.Listener.super.onText(webSocket, data, last);
    return null;
  }

  @Override
  public CompletionStage<?> onBinary(WebSocket webSocket, ByteBuffer data, boolean last) {
    System.out.println("onBinary");
    System.out.println("  data: " + data.toString());
    System.out.println("  last: " + last);
    return null;
  }

  @Override
  public CompletionStage<?> onPing(WebSocket webSocket, ByteBuffer message) {
    System.out.println("onPing");
    System.out.println("  message: " + message.toString());
    return null;
  }

  @Override
  public CompletionStage<?> onPong(WebSocket webSocket, ByteBuffer message) {
    System.out.println("onPong");
    System.out.println("  message: " + message.toString());
    return null;
  }

  @Override
  public CompletionStage<?> onClose(WebSocket webSocket, int statusCode, String reason) {
    System.out.println("onClose");
    System.out.println("  statusCode: " + statusCode);
    System.out.println("  reason: " + reason);
    return null;
  }

  @Override
  public void onError(WebSocket webSocket, Throwable error) {
    System.out.println("onError");
    System.out.println("  error: " + error.getMessage());
  }
}
