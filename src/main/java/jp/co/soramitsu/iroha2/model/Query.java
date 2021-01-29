package jp.co.soramitsu.iroha2.model;

import lombok.Data;
import lombok.NonNull;

@Data
public class Query implements Expression {

  @NonNull
  private jp.co.soramitsu.iroha2.model.query.Query query;

  @Override
  public int getIndex() {
    return 10;
  }
}
