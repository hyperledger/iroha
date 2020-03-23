package contract

import (
	"strings"

	"vmCaller/api"

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
				* @notice Gets asset balance of the calling account
				* @param AssetID asset ID
				* @return Asset balance of the Account
				`,
			PermFlag: permission.Call,
			F:        getAssetBalance,
		},
		native.Function{
			Comment: `
				* @notice Gets asset balance of an arbitrary account
				* @param Account account address
				* @param AssetID asset ID
				* @return Asset balance of the Account
				`,
			PermFlag: permission.Call,
			F:        getOtherAssetBalance,
		},
		native.Function{
			Comment: `
				* @notice Transfers a certain amount of asset from the calling account to destination account
				* @param Dst destination account address
				* @param AssetID asset ID
				* @param Amount amount to transfer
				* @return 'true' if successful, 'false' otherwise
				`,
			PermFlag: permission.Call,
			F:        transferAsset,
		},
		native.Function{
			Comment: `
				* @notice Transfers a certain amount of asset from some source account to destination account
				* @param Src source account address
				* @param Dst destination account address
				* @param AssetID asset ID
				* @param Amount amount to transfer
				* @return 'true' if successful, 'false' otherwise
				`,
			PermFlag: permission.Call,
			F:        transferOtherAsset,
		},
	)

	trimCutSet = string([]byte{0})
)

type getAssetBalanceArgs struct {
	AssetID string
}

type getAssetBalanceRets struct {
	Result string
}

func getAssetBalance(ctx native.Context, args getAssetBalanceArgs) (getAssetBalanceRets, error) {

	balances, err := api.GetIrohaAccountAssets(api.IrohaAccountID(ctx.Caller))
	if err != nil {
		return getAssetBalanceRets{}, err
	}

	value := ""
	for _, v := range balances {
		if v.GetAssetId() == args.AssetID {
			value = v.GetBalance()
			break
		}
	}

	ctx.Logger.Trace.Log("function", "getAssetBalance",
		"address", ctx.Caller.String(),
		"assetID", args.AssetID,
		"value", value)

	return getAssetBalanceRets{Result: value}, nil
}

type getOtherAssetBalanceArgs struct {
	AccountID string
	AssetID   string
}

type getOtherAssetBalanceRets struct {
	Result string
}

func getOtherAssetBalance(ctx native.Context, args getOtherAssetBalanceArgs) (getOtherAssetBalanceRets, error) {

	balances, err := api.GetIrohaAccountAssets(args.AccountID)
	if err != nil {
		return getOtherAssetBalanceRets{}, err
	}

	value := ""
	for _, v := range balances {
		if v.GetAssetId() == args.AssetID {
			value = v.GetBalance()
			break
		}
	}

	ctx.Logger.Trace.Log("function", "getOtherAssetBalance",
		"address", args.AccountID,
		"assetID", args.AssetID,
		"value", value)

	return getOtherAssetBalanceRets{Result: value}, nil
}

type transferAssetArgs struct {
	Dst     string
	AssetID string
	Amount  string
}

type transferAssetRets struct {
	Result bool
}

func transferAsset(ctx native.Context, args transferAssetArgs) (transferAssetRets, error) {

	err := api.TransferIrohaAsset(api.IrohaAccountID(ctx.Caller), args.Dst, args.AssetID, args.Amount)
	if err != nil {
		return transferAssetRets{Result: false}, err
	}

	ctx.Logger.Trace.Log("function", "transferAsset",
		"src", ctx.Caller.String(),
		"dst", args.Dst,
		"assetID", args.AssetID,
		"amount", args.Amount)

	return transferAssetRets{Result: true}, nil
}

type transferOtherAssetArgs struct {
	Src     string
	Dst     string
	AssetID string
	Amount  string
}

type transferOtherAssetRets struct {
	Result bool
}

func transferOtherAsset(ctx native.Context, args transferOtherAssetArgs) (transferOtherAssetRets, error) {

	err := api.TransferIrohaAsset(args.Src, args.Dst, args.AssetID, args.Amount)
	if err != nil {
		return transferOtherAssetRets{Result: false}, err
	}

	ctx.Logger.Trace.Log("function", "transferOtherAsset",
		"src", args.Src,
		"dst", args.Dst,
		"assetID", args.AssetID,
		"amount", args.Amount)

	return transferOtherAssetRets{Result: true}, nil
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
