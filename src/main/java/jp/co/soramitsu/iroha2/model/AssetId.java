package jp.co.soramitsu.iroha2.model;

import lombok.Data;
import lombok.NonNull;

@Data
public class AssetId implements IdBox {

  @NonNull
  private DefinitionId definitionId;
  @NonNull
  private AccountId accountId;

  @Override
  public int getIndex() {
    return 1;
  }
}
