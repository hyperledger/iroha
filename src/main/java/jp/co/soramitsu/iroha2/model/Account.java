package jp.co.soramitsu.iroha2.model;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import lombok.Data;
import lombok.NonNull;

@Data
public class Account implements IdentifiableBox {

  @NonNull
  private AccountId id;
  @NonNull
  private Map<AssetId, Asset> assets;
  @NonNull
  private List<PublicKey> signatories;
  @NonNull
  private List<PermissionRaw> permissions;

  public Account(AccountId id) {
    this.id = id;
    assets = new HashMap<>();
    signatories = new ArrayList<>();
    permissions = new ArrayList<>();
  }

  public Account(AccountId id, Map<AssetId, Asset> assets, List<PublicKey> signatories,
      List<PermissionRaw> permissions) {
    this.id = id;
    this.assets = assets;
    this.signatories = signatories;
    this.permissions = permissions;
  }

  @Override
  public int getIndex() {
    return 0;
  }
}
