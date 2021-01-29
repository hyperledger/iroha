package jp.co.soramitsu.iroha2.scale.reader.query;

import io.emeraldpay.polkaj.scale.ScaleCodecReader;
import io.emeraldpay.polkaj.scale.ScaleReader;
import jp.co.soramitsu.iroha2.model.query.FindPeerById;
import jp.co.soramitsu.iroha2.scale.reader.PeerIdReader;

public class FindPeerByIdReader implements ScaleReader<FindPeerById> {

  private static final PeerIdReader PEER_ID_READER = new PeerIdReader();

  @Override
  public FindPeerById read(ScaleCodecReader reader) {
    return new FindPeerById(reader.read(PEER_ID_READER));
  }
}
