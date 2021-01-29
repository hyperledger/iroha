package jp.co.soramitsu.iroha2.model.query;

import jp.co.soramitsu.iroha2.model.AssetId;
import lombok.Data;
import lombok.NonNull;

@Data
public class FindAssetById implements Query {

  @NonNull
  private AssetId id;

  @Override
  public int getIndex() {
    return 6;
  }
}
