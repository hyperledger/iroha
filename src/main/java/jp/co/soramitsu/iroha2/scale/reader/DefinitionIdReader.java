package jp.co.soramitsu.iroha2.scale.reader;

import io.emeraldpay.polkaj.scale.ScaleCodecReader;
import io.emeraldpay.polkaj.scale.ScaleReader;
import jp.co.soramitsu.iroha2.model.DefinitionId;

public class DefinitionIdReader implements ScaleReader<DefinitionId> {

  @Override
  public DefinitionId read(ScaleCodecReader reader) {
    return new DefinitionId(reader.readString(), reader.readString());
  }
}
