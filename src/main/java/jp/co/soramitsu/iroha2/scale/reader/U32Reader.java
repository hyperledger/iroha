package jp.co.soramitsu.iroha2.scale.reader;

import io.emeraldpay.polkaj.scale.ScaleCodecReader;
import io.emeraldpay.polkaj.scale.ScaleReader;
import jp.co.soramitsu.iroha2.model.U32;

public class U32Reader implements ScaleReader<U32> {

  @Override
  public U32 read(ScaleCodecReader reader) {
    return new U32(reader.readUint32());
  }

}
