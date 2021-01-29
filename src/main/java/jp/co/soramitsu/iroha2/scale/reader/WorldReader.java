package jp.co.soramitsu.iroha2.scale.reader;

import io.emeraldpay.polkaj.scale.ScaleCodecReader;
import io.emeraldpay.polkaj.scale.ScaleReader;
import jp.co.soramitsu.iroha2.model.World;

public class WorldReader implements ScaleReader<World> {

  @Override
  public World read(ScaleCodecReader reader) {
    return new World();
  }

}
