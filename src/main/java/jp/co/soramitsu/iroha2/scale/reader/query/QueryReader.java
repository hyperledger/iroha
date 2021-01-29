package jp.co.soramitsu.iroha2.scale.reader.query;

import io.emeraldpay.polkaj.scale.ScaleCodecReader;
import io.emeraldpay.polkaj.scale.ScaleReader;
import io.emeraldpay.polkaj.scale.reader.UnionReader;
import jp.co.soramitsu.iroha2.model.query.Query;

public class QueryReader implements ScaleReader<Query> {

  private static final UnionReader<Query> QUERY_READER = new UnionReader<>(
      new FindAllAccountsReader(), // 0 - FindAllAccounts
      new FindAccountByIdReader(), // 1 - FindAccountById
      new FindAccountsByNameReader(), // 2 - FindAccountsByName
      new FindAccountsByDomainNameReader(), // 3 - FindAccountsByDomainName
      new FindAllAssetsReader(), // 4 - FindAllAssets
      new FindAllAssetsDefinitionsReader(), // 5 - FindAllAssetsDefinitions
      new FindAssetByIdReader(), // 6 - FindAssetById
      new FindAssetsByNameReader(), // 7 - FindAssetByName
      new FindAssetsByAccountIdReader(), // 8 - FindAssetsByAccountId
      new FindAssetsByAssetDefinitionIdReader(), // 9 - FindAssetsByAssetDefinitionId
      new FindAssetsByDomainNameReader(), // 10 - FindAssetsByDomainName
      new FindAssetsByAccountIdAndAssetDefinitionIdReader(),
      // 11 - FindAssetsByAccountIdAndAssetDefinitionId
      new FindAssetsByDomainNameAndAssetDefinitionIdReader(),
      // 12 - FindAssetsByDomainNameAndAssetDefinitionId
      new FindAssetQuantityByIdReader(), // 13 - FindAssetQuantityById
      new FindAllDomainsReader(), // 14 - FindAllDomains
      new FindDomainByNameReader(), // 15 - FindDomainByName
      new FindAllPeersReader(), // 16 - FindAllPeers
      new FindPeerByIdReader(), // 17   FindPeerById
      new FindAllParametersReader() // 18 - FindAllParameters
  );

  @Override
  public Query read(ScaleCodecReader reader) {
    return reader.read(QUERY_READER).getValue();
  }
}
