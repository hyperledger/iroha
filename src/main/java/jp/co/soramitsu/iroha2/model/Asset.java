package jp.co.soramitsu.iroha2.model;

import java.util.HashMap;
import java.util.Map;
import lombok.Data;
import lombok.NonNull;

@Data
public class Asset implements IdentifiableBox {

  @NonNull
  private AssetId id;
  @NonNull
  private U32 quantity;
  @NonNull
  private U128 bigQuantity;
  @NonNull
  private Map<String, String> store;

  public Asset(AssetId id, U32 quantity, U128 bigQuantity) {
    this.id = id;
    this.quantity = quantity;
    this.bigQuantity = bigQuantity;
    store = new HashMap<>();
  }

  public Asset(AssetId id, U32 quantity, U128 bigQuantity, Map<String, String> store) {
    this.id = id;
    this.quantity = quantity;
    this.bigQuantity = bigQuantity;
    this.store = store;
  }

  @Override
  public int getIndex() {
    return 1;
  }
}
