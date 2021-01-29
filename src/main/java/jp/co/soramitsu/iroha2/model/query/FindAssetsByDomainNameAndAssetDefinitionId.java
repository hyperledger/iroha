package jp.co.soramitsu.iroha2.model.query;

import jp.co.soramitsu.iroha2.model.DefinitionId;
import lombok.Data;
import lombok.NonNull;

@Data
public class FindAssetsByDomainNameAndAssetDefinitionId implements Query {

  @NonNull
  private String domainName;
  @NonNull
  private DefinitionId assetDefinitionId;

  @Override
  public int getIndex() {
    return 12;
  }
}
