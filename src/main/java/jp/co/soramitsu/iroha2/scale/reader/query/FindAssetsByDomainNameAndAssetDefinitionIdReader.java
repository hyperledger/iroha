package jp.co.soramitsu.iroha2.scale.reader.query;

import io.emeraldpay.polkaj.scale.ScaleCodecReader;
import io.emeraldpay.polkaj.scale.ScaleReader;
import jp.co.soramitsu.iroha2.model.query.FindAssetsByDomainNameAndAssetDefinitionId;
import jp.co.soramitsu.iroha2.scale.reader.DefinitionIdReader;

public class FindAssetsByDomainNameAndAssetDefinitionIdReader implements
    ScaleReader<FindAssetsByDomainNameAndAssetDefinitionId> {

  private static final DefinitionIdReader DEFINITION_ID_READER = new DefinitionIdReader();

  @Override
  public FindAssetsByDomainNameAndAssetDefinitionId read(ScaleCodecReader reader) {
    return new FindAssetsByDomainNameAndAssetDefinitionId(reader.readString(),
        reader.read(DEFINITION_ID_READER));
  }
}
