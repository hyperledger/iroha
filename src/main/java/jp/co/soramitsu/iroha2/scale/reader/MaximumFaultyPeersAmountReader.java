package jp.co.soramitsu.iroha2.scale.reader;

import io.emeraldpay.polkaj.scale.ScaleCodecReader;
import io.emeraldpay.polkaj.scale.ScaleReader;
import jp.co.soramitsu.iroha2.model.MaximumFaultyPeersAmount;

public class MaximumFaultyPeersAmountReader implements ScaleReader<MaximumFaultyPeersAmount> {

  private static final U32Reader U_32_READER = new U32Reader();

  @Override
  public MaximumFaultyPeersAmount read(ScaleCodecReader reader) {
    return new MaximumFaultyPeersAmount(reader.read(U_32_READER));
  }

}
