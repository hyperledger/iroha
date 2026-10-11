// Deterministic workchain-0 addresses of SCCP wallets and consumption
// buckets. Both are plain StateInit addresses (no shard prefix), so an
// off-chain tool computes them from code hash and depth alone.

import "sccp-constants"
import "sccp-storage"

/// StateInit destination of the Jetton wallet of `owner` (zero balance).
fun sccpWalletDeployment(owner: address, minter: address, walletCode: cell): AutoDeployAddress {
    val data: WalletStorage = {
        jettonBalance: 0,
        ownerAddress: owner,
        minterAddress: minter,
    };
    return { workchain: SCCP_WORKCHAIN, stateInit: { code: walletCode, data: data.toCell() } };
}

/// Address of the Jetton wallet of `owner`.
fun sccpWalletAddress(owner: address, minter: address, walletCode: cell): address {
    return sccpWalletDeployment(owner, minter, walletCode).calculateAddress();
}

/// Canonical StateInit destination of bucket `index`: not activated, all 512
/// flags clear. Anyone can deploy it, but only the minter activates it.
fun sccpBucketDeployment(minter: address, index: int, bucketCode: cell): AutoDeployAddress {
    val data: BucketStorage = {
        minterAddress: minter,
        index,
        activated: false,
        bitsHi: 0,
        bitsLo: 0,
    };
    return { workchain: SCCP_WORKCHAIN, stateInit: { code: bucketCode, data: data.toCell() } };
}

/// Address of bucket `index` (nonces `index·512 .. index·512 + 511`).
fun sccpBucketAddress(minter: address, index: int, bucketCode: cell): address {
    return sccpBucketDeployment(minter, index, bucketCode).calculateAddress();
}

/// Account id (the 256-bit hash of an `addr_std`).
@pure
fun address.accountId(self): uint256 {
    val (_, hash) = self.getWorkchainAndHash();
    return hash;
}

/// True iff `a` is `addr_std` in workchain 0 without anycast (bits `100`).
@pure
fun sccpIsBasechainStd(a: address): bool {
    return ((a as slice).preloadUint(3) == 0b100) & (a.getWorkchain() == SCCP_WORKCHAIN);
}
