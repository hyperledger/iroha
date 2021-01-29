package jp.co.soramitsu.iroha2.scale.reader.query;

import io.emeraldpay.polkaj.scale.ScaleCodecReader;
import io.emeraldpay.polkaj.scale.ScaleReader;
import jp.co.soramitsu.iroha2.model.query.FindAllPeers;

public class FindAllPeersReader implements ScaleReader<FindAllPeers> {

  @Override
  public FindAllPeers read(ScaleCodecReader scaleCodecReader) {
    return new FindAllPeers();
  }
}
