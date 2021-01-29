package jp.co.soramitsu.iroha2.scale.reader;

import io.emeraldpay.polkaj.scale.ScaleCodecReader;
import io.emeraldpay.polkaj.scale.ScaleReader;
import jp.co.soramitsu.iroha2.model.AssetDefinition;
import jp.co.soramitsu.iroha2.model.AssetDefinitionEntry;

public class AssetDefinitionEntryReader implements ScaleReader<AssetDefinitionEntry> {

  private static final DefinitionIdReader DEFINITION_ID_READER = new DefinitionIdReader();
  private static final AccountIdReader ACCOUNT_ID_READER = new AccountIdReader();

  @Override
  public AssetDefinitionEntry read(ScaleCodecReader reader) {
    return new AssetDefinitionEntry(reader.read(DEFINITION_ID_READER),
        reader.read(ACCOUNT_ID_READER));
  }
}
