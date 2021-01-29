package jp.co.soramitsu.iroha2.scale.reader;

import io.emeraldpay.polkaj.scale.ScaleCodecReader;
import io.emeraldpay.polkaj.scale.ScaleReader;
import jp.co.soramitsu.iroha2.model.PermissionRaw;

public class PermissionRawReader implements ScaleReader<PermissionRaw> {

  @Override
  public PermissionRaw read(ScaleCodecReader reader) {
    return new PermissionRaw(reader.readByteArray());
  }
}
