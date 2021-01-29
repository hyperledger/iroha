package jp.co.soramitsu.iroha2.scale.reader;

import io.emeraldpay.polkaj.scale.ScaleCodecReader;
import io.emeraldpay.polkaj.scale.ScaleReader;
import jp.co.soramitsu.iroha2.model.WorldId;

public class WorldIdReader implements ScaleReader<WorldId> {

  @Override
  public WorldId read(ScaleCodecReader reader) {
    return new WorldId();
  }

}
