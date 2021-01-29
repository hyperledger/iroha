package jp.co.soramitsu.iroha2.scale.reader;

import io.emeraldpay.polkaj.scale.ScaleCodecReader;
import io.emeraldpay.polkaj.scale.ScaleReader;
import jp.co.soramitsu.iroha2.model.AssetDefinition;

public class AssetDefinitionReader implements ScaleReader<AssetDefinition> {

  private static final DefinitionIdReader DEFINITION_ID_READER = new DefinitionIdReader();

  @Override
  public AssetDefinition read(ScaleCodecReader reader) {
    return new AssetDefinition(reader.read(DEFINITION_ID_READER));
  }
}
