package jp.co.soramitsu.iroha2.model.query;

import jp.co.soramitsu.iroha2.model.PeerId;
import lombok.Data;
import lombok.NonNull;

@Data
public class FindPeerById implements Query {

  @NonNull
  private PeerId peerId;

  @Override
  public int getIndex() {
    return 17;
  }
}
