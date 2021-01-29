package jp.co.soramitsu.iroha2.scale.writer;

import io.emeraldpay.polkaj.scale.ScaleCodecWriter;
import io.emeraldpay.polkaj.scale.ScaleWriter;
import java.io.IOException;
import jp.co.soramitsu.iroha2.model.MaximumFaultyPeersAmount;

public class MaximumFaultyPeersAmountWriter implements ScaleWriter<MaximumFaultyPeersAmount> {

  private static final U32Writer U_32_WRITER = new U32Writer();

  @Override
  public void write(ScaleCodecWriter writer, MaximumFaultyPeersAmount value) throws IOException {
    writer.write(U_32_WRITER, value.getValue());
  }
}
