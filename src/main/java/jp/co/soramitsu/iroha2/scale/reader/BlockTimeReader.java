package jp.co.soramitsu.iroha2.scale.reader;

import io.emeraldpay.polkaj.scale.ScaleCodecReader;
import io.emeraldpay.polkaj.scale.ScaleReader;
import jp.co.soramitsu.iroha2.model.BlockTime;

public class BlockTimeReader implements ScaleReader<BlockTime> {

  private static final U128Reader U_128_READER = new U128Reader();

  @Override
  public BlockTime read(ScaleCodecReader reader) {
    return new BlockTime(reader.read(U_128_READER));
  }

}
