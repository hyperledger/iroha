package jp.co.soramitsu.iroha2.scale.writer.query;

import io.emeraldpay.polkaj.scale.ScaleCodecWriter;
import io.emeraldpay.polkaj.scale.ScaleWriter;
import java.io.IOException;
import jp.co.soramitsu.iroha2.model.query.SignedQueryRequest;
import jp.co.soramitsu.iroha2.scale.writer.SignatureWriter;
import jp.co.soramitsu.iroha2.scale.writer.query.QueryWriter;

/**
 * SCALE writer for SignedQueryRequest
 */
public class SignedQueryRequestWriter implements ScaleWriter<SignedQueryRequest> {

  private static final SignatureWriter SIGNATURE_WRITER = new SignatureWriter();
  private static final QueryWriter QUERY_WRITER = new QueryWriter();

  @Override
  public void write(ScaleCodecWriter writer, SignedQueryRequest value) throws IOException {
    writer.writeAsList(value.getTimestamp().getBytes());
    writer.write(SIGNATURE_WRITER, value.getSignature());
    writer.write(QUERY_WRITER, value.getQuery());
  }
}
