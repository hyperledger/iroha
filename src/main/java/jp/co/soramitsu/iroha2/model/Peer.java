package jp.co.soramitsu.iroha2.model;

import lombok.Data;
import lombok.NonNull;

@Data
public class Peer implements IdentifiableBox {

  @NonNull
  private PeerId peerId;

  @Override
  public int getIndex() {
    return 4;
  }
}
