package jp.co.soramitsu.iroha2.scale.reader;

import io.emeraldpay.polkaj.scale.ScaleCodecReader;
import io.emeraldpay.polkaj.scale.ScaleReader;
import jp.co.soramitsu.iroha2.model.CommitTime;

public class CommitTimeReader implements ScaleReader<CommitTime> {

  private static final U128Reader U_128_READER = new U128Reader();

  @Override
  public CommitTime read(ScaleCodecReader reader) {
    return new CommitTime(reader.read(U_128_READER));
  }

}
