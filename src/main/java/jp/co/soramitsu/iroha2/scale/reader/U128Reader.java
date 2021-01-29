package jp.co.soramitsu.iroha2.scale.reader;

import io.emeraldpay.polkaj.scale.ScaleCodecReader;
import io.emeraldpay.polkaj.scale.ScaleReader;
import jp.co.soramitsu.iroha2.model.U128;

public class U128Reader implements ScaleReader<U128> {

  @Override
  public U128 read(ScaleCodecReader reader) {
    return new U128(reader.readUint128());
  }

}
