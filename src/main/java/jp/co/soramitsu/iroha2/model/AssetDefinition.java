package jp.co.soramitsu.iroha2.model;

import lombok.Data;
import lombok.NonNull;

@Data
public class AssetDefinition implements IdentifiableBox {

  @NonNull
  private DefinitionId id;

  @Override
  public int getIndex() {
    return 2;
  }
}
