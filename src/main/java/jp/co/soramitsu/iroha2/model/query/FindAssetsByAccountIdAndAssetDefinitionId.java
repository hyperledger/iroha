package jp.co.soramitsu.iroha2.model.query;

import jp.co.soramitsu.iroha2.model.AccountId;
import jp.co.soramitsu.iroha2.model.DefinitionId;
import lombok.Data;
import lombok.NonNull;

@Data
public class FindAssetsByAccountIdAndAssetDefinitionId implements Query {

  @NonNull
  private AccountId accountId;
  @NonNull
  private DefinitionId assetDefinitionId;

  @Override
  public int getIndex() {
    return 11;
  }
}
