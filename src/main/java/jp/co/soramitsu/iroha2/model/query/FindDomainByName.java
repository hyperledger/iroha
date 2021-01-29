package jp.co.soramitsu.iroha2.model.query;

import lombok.Data;
import lombok.NonNull;

@Data
public class FindDomainByName implements Query {

  @NonNull
  private String name;

  @Override
  public int getIndex() {
    return 15;
  }
}
