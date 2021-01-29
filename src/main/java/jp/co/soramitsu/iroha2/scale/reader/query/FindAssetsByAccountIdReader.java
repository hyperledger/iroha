package jp.co.soramitsu.iroha2.scale.reader.query;

import io.emeraldpay.polkaj.scale.ScaleCodecReader;
import io.emeraldpay.polkaj.scale.ScaleReader;
import jp.co.soramitsu.iroha2.model.query.FindAssetsByAccountId;
import jp.co.soramitsu.iroha2.scale.reader.AccountIdReader;

public class FindAssetsByAccountIdReader implements ScaleReader<FindAssetsByAccountId> {

  private static final AccountIdReader ACCOUNT_ID_READER = new AccountIdReader();

  @Override
  public FindAssetsByAccountId read(ScaleCodecReader reader) {
    return new FindAssetsByAccountId(reader.read(ACCOUNT_ID_READER));
  }
}
