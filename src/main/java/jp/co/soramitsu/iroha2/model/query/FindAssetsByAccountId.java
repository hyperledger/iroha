package jp.co.soramitsu.iroha2.model.query;

import jp.co.soramitsu.iroha2.model.AccountId;
import lombok.Data;
import lombok.NonNull;

@Data
public class FindAssetsByAccountId implements Query {

  @NonNull
  private AccountId accountId;

  @Override
  public int getIndex() {
    return 8;
  }
}
