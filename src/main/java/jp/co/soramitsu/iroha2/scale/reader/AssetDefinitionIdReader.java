package jp.co.soramitsu.iroha2.scale.reader;

import io.emeraldpay.polkaj.scale.ScaleCodecReader;
import io.emeraldpay.polkaj.scale.ScaleReader;
import jp.co.soramitsu.iroha2.model.AssetDefinitionId;

public class AssetDefinitionIdReader implements ScaleReader<AssetDefinitionId> {

  private static final DefinitionIdReader DEFINITION_ID_READER = new DefinitionIdReader();

  @Override
  public AssetDefinitionId read(ScaleCodecReader reader) {
    return new AssetDefinitionId(reader.read(DEFINITION_ID_READER));
  }

}
