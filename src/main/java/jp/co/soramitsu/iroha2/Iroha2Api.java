package jp.co.soramitsu.iroha2;

import io.emeraldpay.polkaj.scale.ScaleCodecReader;
import io.emeraldpay.polkaj.scale.ScaleCodecWriter;
import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.net.http.WebSocket;
import java.net.http.WebSocket.Listener;
import java.util.concurrent.Future;
import jp.co.soramitsu.iroha2.TransactionTerminalStatusWebSocketListener.TerminalStatus;
import jp.co.soramitsu.iroha2.json.writer.SubscriptionRequestWriter;
import jp.co.soramitsu.iroha2.model.events.EntityType;
import jp.co.soramitsu.iroha2.model.events.SubscriptionRequest;
import jp.co.soramitsu.iroha2.model.events.SubscriptionRequest.Pipeline;
import jp.co.soramitsu.iroha2.model.instruction.Transaction;
import jp.co.soramitsu.iroha2.model.query.QueryResult;
import jp.co.soramitsu.iroha2.model.query.SignedQueryRequest;
import jp.co.soramitsu.iroha2.scale.reader.query.QueryResultReader;
import jp.co.soramitsu.iroha2.scale.writer.instruction.TransactionWriter;
import jp.co.soramitsu.iroha2.scale.writer.query.SignedQueryRequestWriter;
import org.eclipse.jetty.client.HttpClient;
import org.eclipse.jetty.client.api.ContentResponse;
import org.eclipse.jetty.client.api.Request;
import org.eclipse.jetty.client.util.BytesRequestContent;
import org.eclipse.jetty.client.util.FutureResponseListener;
import org.eclipse.jetty.http.HttpMethod;
import org.eclipse.jetty.http.HttpStatus;

public class Iroha2Api {

  private static final SubscriptionRequestWriter SUBSCRIPTION_REQUEST_WRITER = new SubscriptionRequestWriter();

  URI queryUri;
  URI instructionUri;
  URI eventUri;
  HttpClient httpClient = new HttpClient();

  public Iroha2Api(String url) {
    queryUri = URI.create("http://" + url + "/query");
    instructionUri = URI.create("http://" + url + "/instruction");
    eventUri = URI.create("ws://" + url + "/events");
  }

  private byte[] send(URI uri, HttpMethod method, byte[] data) throws Exception {
    if (!httpClient.isStarted()) {
      httpClient.start();
    }

    ContentResponse response = httpClient
        .newRequest(uri)
        .method(method)
        .body(new BytesRequestContent("text/plain", data))
        .send();

    if (response.getStatus() != HttpStatus.OK_200) {
      throw new RuntimeException(
          "Get status not OK: " + response.getStatus() + " Content: " + response
              .getContentAsString());
    }

    return response.getContent();
  }

  /**
   * Send query request
   *
   * @param request - build and signed request
   * @return query result object
   */
  public QueryResult query(SignedQueryRequest request) throws Exception {
    ByteArrayOutputStream encoded = new ByteArrayOutputStream();
    ScaleCodecWriter codec = new ScaleCodecWriter(encoded);
    codec.write(new SignedQueryRequestWriter(), request);

    byte[] responseContent = send(queryUri, HttpMethod.GET, encoded.toByteArray());

    ScaleCodecReader reader = new ScaleCodecReader(responseContent);
    return reader.read(new QueryResultReader());
  }

  /**
   * Sends instructions to iroha2
   *
   * @param transaction - build and signed transaction
   */
  public byte[] instruction(Transaction transaction) throws Exception {
    ByteArrayOutputStream encoded = new ByteArrayOutputStream();
    ScaleCodecWriter codec = new ScaleCodecWriter(encoded);
    codec.write(new TransactionWriter(), transaction);

    send(instructionUri, HttpMethod.POST, encoded.toByteArray());

    return transaction.getHash();
  }

  /**
   * Sends transaction and get terminal status subscription.
   */
  public Future<TerminalStatus> instructionAsync(Transaction transaction)
      throws Exception {
    // subscribe to events
    byte[] hash = transaction.getHash();
    SubscriptionRequest subscriptionRequest = new SubscriptionRequest(
        new Pipeline(EntityType.Transaction, hash));
    TransactionTerminalStatusWebSocketListener listener = new TransactionTerminalStatusWebSocketListener(
        EntityType.Transaction, hash);
    events(subscriptionRequest, listener);

    ByteArrayOutputStream encoded = new ByteArrayOutputStream();
    ScaleCodecWriter codec = new ScaleCodecWriter(encoded);
    codec.write(new TransactionWriter(), transaction);

    if (!httpClient.isStarted()) {
      httpClient.start();
    }

    Request request = httpClient
        .newRequest(instructionUri)
        .method(HttpMethod.POST)
        .body(new BytesRequestContent("text/plain", encoded.toByteArray()));

    request.send(new FutureResponseListener(request));

    return listener.getResult();
  }

  /**
   * Subscribes to events
   *
   * @param subscriptionRequest - request
   * @param listener            - web socket messages handler
   */
  public void events(SubscriptionRequest subscriptionRequest, Listener listener) {
    WebSocket socket = java.net.http.HttpClient
        .newHttpClient()
        .newWebSocketBuilder()
        .buildAsync(eventUri, listener)
        .join();

    String json = SUBSCRIPTION_REQUEST_WRITER.write(subscriptionRequest);
    socket.sendText(json, true).join();
  }
}
