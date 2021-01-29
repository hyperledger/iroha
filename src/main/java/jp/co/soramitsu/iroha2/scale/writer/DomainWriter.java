package jp.co.soramitsu.iroha2.scale.writer;

import io.emeraldpay.polkaj.scale.ScaleCodecWriter;
import io.emeraldpay.polkaj.scale.ScaleWriter;
import java.io.IOException;
import jp.co.soramitsu.iroha2.model.Account;
import jp.co.soramitsu.iroha2.model.AccountId;
import jp.co.soramitsu.iroha2.model.AssetDefinitionEntry;
import jp.co.soramitsu.iroha2.model.DefinitionId;
import jp.co.soramitsu.iroha2.model.Domain;

public class DomainWriter implements ScaleWriter<Domain> {

  private static final MapWriter<AccountId, Account> ACCOUNTS_MAP_WRITER = new MapWriter<>(
      new AccountIdWriter(),
      new AccountWriter());
  private static final MapWriter<DefinitionId, AssetDefinitionEntry> ASSET_DEFINITION_MAP_WRITER = new MapWriter<>(
      new DefinitionIdWriter(),
      new AssetDefinitionEntryWriter());

  @Override
  public void write(ScaleCodecWriter writer, Domain value) throws IOException {
    writer.writeAsList(value.getName().getBytes());
    ACCOUNTS_MAP_WRITER.write(writer, value.getAccounts());
    ASSET_DEFINITION_MAP_WRITER.write(writer, value.getAssetDefinitions());
  }

}
