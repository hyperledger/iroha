package jp.co.soramitsu.iroha2.model;

import lombok.Data;
import lombok.NonNull;

@Data
public class AssetDefinitionEntry {

  @NonNull
  private DefinitionId definition;
  @NonNull
  private AccountId registeredBy;
}
