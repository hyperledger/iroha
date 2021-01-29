package jp.co.soramitsu.iroha2.scale.reader;

import io.emeraldpay.polkaj.scale.ScaleCodecReader;
import io.emeraldpay.polkaj.scale.ScaleReader;
import jp.co.soramitsu.iroha2.model.Query;

public class QueryReader implements ScaleReader<Query> {

  private static final jp.co.soramitsu.iroha2.scale.reader.query.QueryReader QUERY_READER =
      new jp.co.soramitsu.iroha2.scale.reader.query.QueryReader();

  @Override
  public Query read(ScaleCodecReader reader) {
    return new Query(reader.read(QUERY_READER));
  }
}
