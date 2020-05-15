package evm

import (
	"strings"

	"vmCaller/iroha"

	"github.com/hyperledger/burrow/execution/native"
	"github.com/hyperledger/burrow/permission"
)

var (
	ServiceContract = native.New().MustContract("ServiceContract",
		`* acmstate.ReaderWriter for bridging EVM state and Iroha state.
			* @dev This interface describes the functions exposed by the native service contracts layer in burrow.
			`,
		native.Function{
			Comment: `
				* @notice Gets asset balance of an Iroha account
				* @param Account Iroha account ID
				* @param Asset asset ID
				* @return Asset balance of the Account
				`,
			PermFlag: permission.Call,
			F:        getAssetBalance,
		},
		native.Function{
			Comment: `
				* @notice Transfers a certain amount of asset from some source account to destination account
				* @param Src source account address
				* @param Dst destination account address
				* @param Asset asset ID
				* @param Amount amount to transfer
				* @return 'true' if successful, 'false' otherwise
				`,
			PermFlag: permission.Call,
			F:        transferAsset,
		},
	)
)

type getAssetBalanceArgs struct {
	Account string
	Asset   string
}

type getAssetBalanceRets struct {
	Result string
}

func getAssetBalance(ctx native.Context, args getAssetBalanceArgs) (getAssetBalanceRets, error) {

	balances, err := iroha.GetAccountAssets(args.Account)
	if err != nil {
		return getAssetBalanceRets{}, err
	}

	value := ""
	for _, v := range balances {
		if v.GetAssetId() == args.Asset {
			value = v.GetBalance()
			break
		}
	}

	ctx.Logger.Trace.Log("function", "getAssetBalance",
		"account", args.Account,
		"asset", args.Asset,
		"value", value)

	return getAssetBalanceRets{Result: value}, nil
}

type transferAssetArgs struct {
	Src    string
	Dst    string
	Asset  string
	Amount string
}

type transferAssetRets struct {
	Result bool
}

func transferAsset(ctx native.Context, args transferAssetArgs) (transferAssetRets, error) {

	err := iroha.TransferAsset(args.Src, args.Dst, args.Asset, args.Amount)
	if err != nil {
		return transferAssetRets{Result: false}, err
	}

	ctx.Logger.Trace.Log("function", "transferAsset",
		"src", args.Src,
		"dst", args.Dst,
		"assetID", args.Asset,
		"amount", args.Amount)

	return transferAssetRets{Result: true}, nil
}

func MustCreateNatives() *native.Natives {
	ns, err := createNatives()
	if err != nil {
		panic(err)
	}
	return ns
}

func createNatives() (*native.Natives, error) {
	ns, err := native.Merge(ServiceContract, native.Permissions, native.Precompiles)
	if err != nil {
		return nil, err
	}
	return ns, nil
}

func IsNative(acc string) bool {
	return strings.ToLower(acc) == "a6abc17819738299b3b2c1ce46d55c74f04e290c"
}
