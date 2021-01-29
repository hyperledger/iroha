package jp.co.soramitsu.iroha2.scale.writer;

import io.emeraldpay.polkaj.scale.ScaleCodecWriter;
import io.emeraldpay.polkaj.scale.ScaleWriter;
import java.io.IOException;
import jp.co.soramitsu.iroha2.model.Query;

public class QueryWriter implements ScaleWriter<Query> {

  private static final jp.co.soramitsu.iroha2.scale.writer.query.QueryWriter QUERY_WRITER =
      new jp.co.soramitsu.iroha2.scale.writer.query.QueryWriter();

  @Override
  public void write(ScaleCodecWriter writer, Query value) throws IOException {
    writer.write(QUERY_WRITER, value.getQuery());
  }

}
