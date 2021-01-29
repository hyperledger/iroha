package jp.co.soramitsu.iroha2.scale.reader.query;

import io.emeraldpay.polkaj.scale.ScaleCodecReader;
import io.emeraldpay.polkaj.scale.ScaleReader;
import jp.co.soramitsu.iroha2.model.query.FindAssetsByAssetDefinitionId;
import jp.co.soramitsu.iroha2.scale.reader.DefinitionIdReader;

public class FindAssetsByAssetDefinitionIdReader implements
    ScaleReader<FindAssetsByAssetDefinitionId> {

  private static final DefinitionIdReader DEFINITION_ID_READER = new DefinitionIdReader();

  @Override
  public FindAssetsByAssetDefinitionId read(ScaleCodecReader reader) {
    return new FindAssetsByAssetDefinitionId(reader.read(DEFINITION_ID_READER));
  }
}
