package jp.co.soramitsu.iroha2.scale.reader;

import io.emeraldpay.polkaj.scale.ScaleCodecReader;
import io.emeraldpay.polkaj.scale.ScaleReader;
import io.emeraldpay.polkaj.scale.reader.UnionReader;
import jp.co.soramitsu.iroha2.model.IdBox;
import jp.co.soramitsu.iroha2.model.ParameterBox;

public class ParameterBoxReader implements ScaleReader<ParameterBox> {

  private static final UnionReader<ParameterBox> PARAMETER_BOX_READER = new UnionReader<>(
      new MaximumFaultyPeersAmountReader(), // 0 MaximumFaultyPeersAmount
      new CommitTimeReader(), // 1 CommitTime
      new TransactionReceiptTimeReader(), // 2 TransactionReceiptTime
      new BlockTimeReader() // 3 BlockTime
  );

  @Override
  public ParameterBox read(ScaleCodecReader reader) {
    return reader.read(PARAMETER_BOX_READER).getValue();
  }
}
