package jp.co.soramitsu.iroha2.model;

import lombok.Data;
import lombok.NonNull;

@Data
public class AssetDefinitionId implements IdBox {

  @NonNull
  DefinitionId assetDefinitionId;

  public AssetDefinitionId(String name, String domainName) {
    assetDefinitionId = new DefinitionId(name, domainName);
  }

  public AssetDefinitionId(DefinitionId assetDefinitionId) {
    this.assetDefinitionId = assetDefinitionId;
  }

  @Override
  public int getIndex() {
    return 2;
  }
}
