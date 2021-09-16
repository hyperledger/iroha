package evm

import (
	"encoding/json"
	"strings"
	"fmt"
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
				* @notice Get transactions of the account
				* @param Account account to be used
				* @return transactions of the account
				`,
			PermFlag: permission.Call,
			F:        getAccountTxn,
		},
		native.Function{
			Comment: `
				* @notice Get transactions of the account
				* @param Account account to be used
				* @param Asset asset id to be used
				* @return transactions of the account
				`,
			PermFlag: permission.Call,
			F:        getAccountAssetTxn,
		},
		native.Function{
			Comment: `
				* @notice Get transactions of the account
				* @param Hash hash of the transaction 
				* @return transactions of the account
				`,
			PermFlag: permission.Call,
			F:        getTransaction,
		},
		/*native.Function{
			Comment: `
				* @notice Grants permission to an account
				* @param Account account to which rights are granted
				* @param Permission permission which is granted to the account
				* @return 'true' if successful, 'false' otherwise
				`,
			PermFlag: permission.Call,
			F:        grantPermission,
		},*/
	)
)


type getTransactionArgs struct {
	Hash string
}

type getTransactionRets struct {
	Result string
}

func getTransaction(ctx native.Context, args getTransactionArgs) (getTransactionRets, error) {
	transaction, err := iroha.GetTransactions(args.Hash)
	if err != nil {
		return getTransactionRets{}, err
	}

	ctx.Logger.Trace.Log("function", "GetAccountTransactions",
		"hash", args.Hash)
	result, err := json.Marshal(transaction)
	return getTransactionRets{Result: string(result)}, nil
}

type getAccountTxnArgs struct {
	Account string
}

type getAccountTxnRets struct {
	Result string
}

func getAccountTxn(ctx native.Context, args getAccountTxnArgs) (getAccountTxnRets, error) {
	transactions, err := iroha.GetAccountTransactions(args.Account)
	if err != nil {
		return getAccountTxnRets{}, err
	}
	fmt.Println("Hello, World!")
	ctx.Logger.Trace.Log("function", "GetAccountTransactions",
		"account", args.Account)
	result, err := json.Marshal(transactions)
	return getAccountTxnRets{Result: string(result)}, nil
}

type getAccountAssetTxnArgs struct {
	Account string
	Asset   string
}

type getAccountAssetTxnRets struct {
	Result string
}

func getAccountAssetTxn(ctx native.Context, args getAccountAssetTxnArgs) (getAccountAssetTxnRets, error) {
	transactions, err := iroha.GetAccountAssetTransactions(args.Account, args.Asset)
	if err != nil {
		return getAccountAssetTxnRets{}, err
	}

	ctx.Logger.Trace.Log("function", "GetAccountAssetTransactions",
		"account", args.Account,
		"asset", args.Asset)

	result, err := json.Marshal(transactions)
	return getAccountAssetTxnRets{Result: string(result)}, nil
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
