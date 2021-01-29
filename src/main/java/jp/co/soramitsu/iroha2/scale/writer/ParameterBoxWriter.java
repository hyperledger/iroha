package jp.co.soramitsu.iroha2.scale.writer;

import io.emeraldpay.polkaj.scale.ScaleCodecWriter;
import io.emeraldpay.polkaj.scale.ScaleWriter;
import io.emeraldpay.polkaj.scale.writer.UnionWriter;
import java.io.IOException;
import jp.co.soramitsu.iroha2.model.ParameterBox;

public class ParameterBoxWriter implements ScaleWriter<ParameterBox> {

  private static final UnionWriter<ParameterBox> ID_BOX_WRITER = new UnionWriter<>(
      new MaximumFaultyPeersAmountWriter(), // 0 - MaximumFaultyPeersAmountWriter
      new CommitTimeWriter(), // 1 - CommitTime
      new TransactionReceiptTimeWriter(), // 2 - TransactionReceiptTime
      new BlockTimeWriter() // 3 - BlockTime
  );

  @Override
  public void write(ScaleCodecWriter writer, ParameterBox value) throws IOException {
    writer.write(ID_BOX_WRITER, new EnumerationUnionValue<>(value));
  }

}
