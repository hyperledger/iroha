package jp.co.soramitsu.iroha2.model.query;

import jp.co.soramitsu.iroha2.model.Value;
import lombok.Data;
import lombok.NonNull;

@Data
public class QueryResult {

  @NonNull
  private Value value;
}
