package jp.co.soramitsu.iroha2.model;

import java.util.HashMap;
import java.util.Map;
import lombok.Data;
import lombok.NonNull;

@Data
public class Domain implements IdentifiableBox {

  @NonNull
  private String name;
  @NonNull
  private Map<AccountId, Account> accounts = new HashMap<>();
  @NonNull
  private Map<DefinitionId, AssetDefinitionEntry> assetDefinitions = new HashMap<>();


  public Domain(String name) {
    this.name = name;
  }

  public Domain(String name, Map<AccountId, Account> accounts,
      Map<DefinitionId, AssetDefinitionEntry> assetDefinitions) {
    this.name = name;
    this.accounts = accounts;
    this.assetDefinitions = assetDefinitions;
  }

  @Override
  public int getIndex() {
    return 3;
  }
}
