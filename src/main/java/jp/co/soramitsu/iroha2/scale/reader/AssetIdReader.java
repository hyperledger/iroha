package jp.co.soramitsu.iroha2.scale.reader;

import io.emeraldpay.polkaj.scale.ScaleCodecReader;
import io.emeraldpay.polkaj.scale.ScaleReader;
import jp.co.soramitsu.iroha2.model.AssetId;

public class AssetIdReader implements ScaleReader<AssetId> {

  private static final DefinitionIdReader DEFINITION_ID_READER = new DefinitionIdReader();
  private static final AccountIdReader ACCOUNT_ID_READER = new AccountIdReader();

  @Override
  public AssetId read(ScaleCodecReader reader) {
    return new AssetId(DEFINITION_ID_READER.read(reader), ACCOUNT_ID_READER.read(reader));
  }

}
