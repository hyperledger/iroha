package jp.co.soramitsu.iroha2.model.query;

import lombok.Data;
import lombok.NonNull;

@Data
public class FindAssetsByName implements Query {

  @NonNull
  private String name;

  @Override
  public int getIndex() {
    return 7;
  }
}
