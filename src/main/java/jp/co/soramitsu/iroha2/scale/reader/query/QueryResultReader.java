package jp.co.soramitsu.iroha2.scale.reader.query;

import io.emeraldpay.polkaj.scale.ScaleCodecReader;
import io.emeraldpay.polkaj.scale.ScaleReader;
import jp.co.soramitsu.iroha2.model.query.QueryResult;
import jp.co.soramitsu.iroha2.scale.reader.ValueReader;

public class QueryResultReader implements ScaleReader<QueryResult> {

  @Override
  public QueryResult read(ScaleCodecReader reader) {
    return new QueryResult(reader.read(new ValueReader()));
  }
}
