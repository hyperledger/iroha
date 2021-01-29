package jp.co.soramitsu.iroha2.model;

import lombok.Data;
import lombok.NonNull;

@Data
public class PeerId implements IdBox {

  @NonNull
  private String address;
  @NonNull
  private PublicKey publicKey;

  @Override
  public int getIndex() {
    return 4;
  }
}
