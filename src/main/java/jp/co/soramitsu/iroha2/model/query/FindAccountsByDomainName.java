package jp.co.soramitsu.iroha2.model.query;

import lombok.Data;
import lombok.NonNull;

@Data
public class FindAccountsByDomainName implements Query {

  @NonNull
  private String domainName;

  @Override
  public int getIndex() {
    return 3;
  }
}
