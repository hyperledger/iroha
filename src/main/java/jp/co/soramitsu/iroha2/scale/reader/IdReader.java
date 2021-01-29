package jp.co.soramitsu.iroha2.scale.reader;

import io.emeraldpay.polkaj.scale.ScaleCodecReader;
import io.emeraldpay.polkaj.scale.ScaleReader;
import jp.co.soramitsu.iroha2.model.Id;

public class IdReader implements ScaleReader<Id> {

  private static final IdBoxReader ID_BOX_READER = new IdBoxReader();

  @Override
  public Id read(ScaleCodecReader reader) {
    return new Id(reader.read(ID_BOX_READER));
  }
}
