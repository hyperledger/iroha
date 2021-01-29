package jp.co.soramitsu.iroha2.model.query;

import lombok.Data;
import lombok.NonNull;

@Data
public class FindAccountsByName implements Query {

  @NonNull
  private String name;

  @Override
  public int getIndex() {
    return 2;
  }
}
