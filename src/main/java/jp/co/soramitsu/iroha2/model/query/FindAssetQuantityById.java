package jp.co.soramitsu.iroha2.model.query;

import jp.co.soramitsu.iroha2.model.AssetId;
import lombok.Data;
import lombok.NonNull;

@Data
public class FindAssetQuantityById implements Query {

  @NonNull
  private AssetId assetId;

  @Override
  public int getIndex() {
    return 13;
  }
}
