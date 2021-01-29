package jp.co.soramitsu.iroha2.scale.writer;

import io.emeraldpay.polkaj.scale.ScaleCodecWriter;
import io.emeraldpay.polkaj.scale.ScaleWriter;
import java.io.IOException;
import jp.co.soramitsu.iroha2.model.BlockTime;

public class BlockTimeWriter implements ScaleWriter<BlockTime> {

  private static final U128Writer U_128_WRITER = new U128Writer();

  @Override
  public void write(ScaleCodecWriter writer, BlockTime value) throws IOException {
    writer.write(U_128_WRITER, value.getValue());
  }
}
