package jp.co.soramitsu.iroha2.scale.reader.query;

import io.emeraldpay.polkaj.scale.ScaleCodecReader;
import io.emeraldpay.polkaj.scale.ScaleReader;
import jp.co.soramitsu.iroha2.model.query.FindAssetsByAccountIdAndAssetDefinitionId;
import jp.co.soramitsu.iroha2.scale.reader.AccountIdReader;
import jp.co.soramitsu.iroha2.scale.reader.DefinitionIdReader;

public class FindAssetsByAccountIdAndAssetDefinitionIdReader implements
    ScaleReader<FindAssetsByAccountIdAndAssetDefinitionId> {

  private static final AccountIdReader ACCOUNT_ID_READER = new AccountIdReader();
  private static final DefinitionIdReader DEFINITION_ID_READER = new DefinitionIdReader();

  @Override
  public FindAssetsByAccountIdAndAssetDefinitionId read(ScaleCodecReader reader) {
    return new FindAssetsByAccountIdAndAssetDefinitionId(reader.read(ACCOUNT_ID_READER),
        reader.read(DEFINITION_ID_READER));
  }
}
