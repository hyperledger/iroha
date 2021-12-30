package evm

import (
	"encoding/json"
	"fmt"
	"strings"

	"vmCaller/iroha"
	"vmCaller/iroha_model"
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
				* @param Description description of the transfer
				* @param Asset asset ID
				* @param Amount amount to transfer
				* @return 'true' if successful, 'false' otherwise
				`,
			PermFlag: permission.Call,
			F:        transferAsset,
		},
		native.Function{
			Comment: `
				* @notice Creates a new iroha account
				* @param Name account name
				* @param Domain domain of account
				* @param Key key of account
				* @return 'true' if successful, 'false' otherwise
				`,
			PermFlag: permission.Call,
			F:        createAccount,
		},
		native.Function{
			Comment: `
				* @notice Adds asset to iroha account
				* @param Asset name of asset
				* @param Amount mount of asset to be added
				* @return 'true' if successful, 'false' otherwise
				`,
			PermFlag: permission.Call,
			F:        addAssetQuantity,
		},
		native.Function{
			Comment: `
				* @notice Subtracts asset from iroha account
				* @param Asset name of asset
				* @param Amount amount of asset to be subtracted
				* @return 'true' if successful, 'false' otherwise
				`,
			PermFlag: permission.Call,
			F:        subtractAssetQuantity,
		},
		native.Function{
			Comment: `
				* @notice Sets account detail
				* @param Account account id to be used
				* @param Key key for the added info
				* @param Value value of added info
				* @return 'true' if successful, 'false' otherwise
				`,
			PermFlag: permission.Call,
			F:        setAccountDetail,
		},
		native.Function{
			Comment: `
				* @notice Gets account detail
				* @param Account account id to be used
				* @return details of the account
				`,
			PermFlag: permission.Call,
			F:        getAccountDetail,
		},
		native.Function{
			Comment: `
				* @notice Sets account quorum
				* @param Account account id to be used
				* @param Quorum quorum value to be set
				* @return 'true' if successful, 'false' otherwise
				`,
			PermFlag: permission.Call,
			F:        setAccountQuorum,
		},
		native.Function{
			Comment: `
				* @notice Adds a signatory to the account
				* @param Account account id in which signatory to be added
				* @param Key publicy key to be added as signatory
				* @return 'true' if successful, 'false' otherwise
				`,
			PermFlag: permission.Call,
			F:        addSignatory,
		},
		native.Function{
			Comment: `
				* @notice Adds a signatory to the account
				* @param Account account id in which signatory to be added
				* @param Key publicy key to be added as signatory
				* @return 'true' if successful, 'false' otherwise
				`,
			PermFlag: permission.Call,
			F:        removeSignatory,
		},
		native.Function{
			Comment: `
				* @notice Creates a domain
				* @param Domain name of domain to be created
				* @param Role default role for user created in domain
				* @return 'true' if successful, 'false' otherwise
				`,
			PermFlag: permission.Call,
			F:        createDomain,
		},
		native.Function{
			Comment: `
				* @notice Gets state of the account
				* @param Account account id to be used
				* @return state of the account
				`,
			PermFlag: permission.Call,
			F:        getAccount,
		},
		native.Function{
			Comment: `
				* @notice Creates an asset
				* @param Name name of asset to be created
				* @param Domain domain of the created asset
				* @param Precision precision of created asset
				* @return 'true' if successful, 'false' otherwise
				`,
			PermFlag: permission.Call,
			F:        createAsset,
		},
		native.Function{
			Comment: `
				* @notice Get signatories of the account
				* @param Account account to be used
				* @return signatories of the account
				`,
			PermFlag: permission.Call,
			F:        getSignatories,
		},
		native.Function{
			Comment: `
				* @notice Get Asset's info
				* @param Asset asset id to be used
				* @return details of the asset
				`,
			PermFlag: permission.Call,
			F:        getAssetInfo,
		},
		native.Function{
			Comment: `
				* @notice Updates Account role
				* @param Account name of account to be updated
				* @param Role new role of the account
				* @return 'true' if successful, 'false' otherwise
				`,
			PermFlag: permission.Call,
			F:        appendRole,
		},
		native.Function{
			Comment: `
				* @notice Removes account role
				* @param Account name of account to be updated
				* @param Role role of the account to be removed
				* @return 'true' if successful, 'false' otherwise
				`,
			PermFlag: permission.Call,
			F:        detachRole,
		},
		native.Function{
			Comment: `
				* @notice Adds a new peer
				* @param Address address of the new peer 
				* @param PeerKey key of the new peer
				* @return 'true' if successful, 'false' otherwise
				`,
			PermFlag: permission.Call,
			F:        addPeer,
		},
		native.Function{
			Comment: `
				* @notice Removes a peer
				* @param PeerKey key of the peer to be removed
				* @return 'true' if successful, 'false' otherwise
				`,
			PermFlag: permission.Call,
			F:        removePeer,
		},
		native.Function{
			Comment: `
				* @notice Gets all peers
				* @return details of the peers
				`,
			PermFlag: permission.Call,
			F:        getPeers,
		},
		native.Function{
			Comment: `
				* @notice Gets block 
				* @param Height height of block to be used
				* @return the block at the given height 
				`,
			PermFlag: permission.Call,
			F:        getBlock,
		},
		native.Function{
			Comment: `
				* @notice Gets all roles
				* @return details of the roles
				`,
			PermFlag: permission.Call,
			F:        getRoles,
		},
		native.Function{
			Comment: `
				* @notice Gets permissions of the role
				* @param Role role id to be used
				* @return permissions of the given role
				`,
			PermFlag: permission.Call,
			F:        getRolePermissions,
		},
		native.Function{
			Comment: `
				* @notice Get transactions of the account
				* @param Account account to be used
				* @param TxPaginationMeta`,
			PermFlag: permission.Call,
			F:        getAccountTransactions,
		},
		native.Function{
			Comment: `
				* @notice Get pending transactions of the account
				* @param TxPaginationMeta`,
			PermFlag: permission.Call,
			F:        getPendingTransactions,
		},
		native.Function{
			Comment: `
				* @notice Get account asset transactions of the account
				* @param account Id 
				* @param asset Id
				* @param TxPaginationMeta`,
			PermFlag: permission.Call,
			F:        getAccountAssetTransactions,
		},
		native.Function{
			Comment: `
				* @notice Grant Permission
				* @param account  
				* @param permission`,
			PermFlag: permission.Call,
			F:       grantPermission,
		},
		native.Function{
			Comment: `
				* @notice Revoke Permission
				* @param account  
				* @param permission`,
			PermFlag: permission.Call,
			F:       revokePermission,
		},
		native.Function{
			Comment: `
				* @notice Compare And Set Account Detail
				* @param account  
				* @param key
				* @param value
				* @param old_value
				* @param check_empty`,
			PermFlag: permission.Call,
			F:       compareAndSetAccountDetail,
		},
		native.Function{
			Comment: `
				* @notice Get Transactions
				* @param tx hashes`,
			PermFlag: permission.Call,
			F:       getTransactions,
		},
		native.Function{
			Comment: `
				* @notice Create Role
				* @param role name
				* @param permissions`,
			PermFlag: permission.Call,
			F:       createRole,
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

	value := "0"
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
	Desc   string
	Amount string
}

type transferAssetRets struct {
	Result bool
}

func transferAsset(ctx native.Context, args transferAssetArgs) (transferAssetRets, error) {
	err := iroha.TransferAsset(args.Src, args.Dst, args.Asset, args.Desc, args.Amount)
	if err != nil {
		return transferAssetRets{Result: false}, err
	}

	ctx.Logger.Trace.Log("function", "transferAsset",
		"src", args.Src,
		"dst", args.Dst,
		"assetID", args.Asset,
		"description", args.Desc,
		"amount", args.Amount)

	return transferAssetRets{Result: true}, nil
}

type createAccountArgs struct {
	Name   string
	Domain string
	Key    string
}

type createAccountRets struct {
	Result bool
}

func createAccount(ctx native.Context, args createAccountArgs) (createAccountRets, error) {
	err := iroha.CreateAccount(args.Name, args.Domain, args.Key)
	if err != nil {
		return createAccountRets{Result: false}, err
	}

	ctx.Logger.Trace.Log("function", "createAccount",
		"name", args.Name,
		"domain", args.Domain,
		"key", args.Key)

	return createAccountRets{Result: true}, nil
}

type addAssetQuantityArgs struct {
	Asset  string
	Amount string
}

type addAssetQuantityRets struct {
	Result bool
}

func addAssetQuantity(ctx native.Context, args addAssetQuantityArgs) (addAssetQuantityRets, error) {
	err := iroha.AddAssetQuantity(args.Asset, args.Amount)
	if err != nil {
		return addAssetQuantityRets{Result: false}, err
	}

	ctx.Logger.Trace.Log("function", "addAssetQuantity",
		"asset", args.Asset,
		"amount", args.Amount)

	return addAssetQuantityRets{Result: true}, nil
}

type subtractAssetQuantityArgs struct {
	Asset  string
	Amount string
}

type subtractAssetQuantityRets struct {
	Result bool
}

func subtractAssetQuantity(ctx native.Context, args subtractAssetQuantityArgs) (subtractAssetQuantityRets, error) {
	err := iroha.SubtractAssetQuantity(args.Asset, args.Amount)
	if err != nil {
		return subtractAssetQuantityRets{Result: false}, err
	}

	ctx.Logger.Trace.Log("function", "subtractAssetQuantity",
		"asset", args.Asset,
		"amount", args.Amount)

	return subtractAssetQuantityRets{Result: true}, nil
}

type setAccountDetailArgs struct {
	Account string
	Key     string
	Value   string
}

type setAccountDetailRets struct {
	Result bool
}

func setAccountDetail(ctx native.Context, args setAccountDetailArgs) (setAccountDetailRets, error) {
	err := iroha.SetAccountDetail(args.Account, args.Key, args.Value)
	if err != nil {
		return setAccountDetailRets{Result: false}, err
	}

	ctx.Logger.Trace.Log("function", "setAccountDetail",
		"account", args.Account,
		"key", args.Key,
		"value", args.Value)

	return setAccountDetailRets{Result: true}, nil
}

type getAccountDetailArgs struct {
}

type getAccountDetailRets struct {
	Result string
}

func getAccountDetail(ctx native.Context, args getAccountDetailArgs) (getAccountDetailRets, error) {
	details, err := iroha.GetAccountDetail()
	if err != nil {
		return getAccountDetailRets{}, err
	}

	ctx.Logger.Trace.Log("function", "getAccountDetail")

	return getAccountDetailRets{Result: details}, nil
}

type setAccountQuorumArgs struct {
	Account string
	Quorum  string
}

type setAccountQuorumRets struct {
	Result bool
}

func setAccountQuorum(ctx native.Context, args setAccountQuorumArgs) (setAccountQuorumRets, error) {
	err := iroha.SetAccountQuorum(args.Account, args.Quorum)
	if err != nil {
		return setAccountQuorumRets{Result: false}, err
	}

	ctx.Logger.Trace.Log("function", "setAccountQuorum",
		"account", args.Account,
		"quorum", args.Quorum)

	return setAccountQuorumRets{Result: true}, nil
}

type addSignatoryArgs struct {
	Account string
	Key     string
}

type addSignatoryRets struct {
	Result bool
}

func addSignatory(ctx native.Context, args addSignatoryArgs) (addSignatoryRets, error) {
	err := iroha.AddSignatory(args.Account, args.Key)
	if err != nil {
		return addSignatoryRets{Result: false}, err
	}

	ctx.Logger.Trace.Log("function", "addSignatory",
		"account id", args.Account,
		"public key", args.Key)

	return addSignatoryRets{Result: true}, nil
}

type removeSignatoryArgs struct {
	Account string
	Key     string
}

type removeSignatoryRets struct {
	Result bool
}

func removeSignatory(ctx native.Context, args removeSignatoryArgs) (removeSignatoryRets, error) {
	err := iroha.RemoveSignatory(args.Account, args.Key)
	if err != nil {
		return removeSignatoryRets{Result: false}, err
	}

	ctx.Logger.Trace.Log("function", "removeSignatory",
		"account id", args.Account,
		"public key", args.Key)

	return removeSignatoryRets{Result: true}, nil
}

type createDomainArgs struct {
	Domain string
	Role   string
}

type createDomainRets struct {
	Result bool
}

func createDomain(ctx native.Context, args createDomainArgs) (createDomainRets, error) {
	err := iroha.CreateDomain(args.Domain, args.Role)
	if err != nil {
		return createDomainRets{Result: false}, err
	}

	ctx.Logger.Trace.Log("function", "createDomain",
		"domain name", args.Domain,
		"default role", args.Role)

	return createDomainRets{Result: true}, nil
}

type getAccountArgs struct {
	Account string
}

type getAccountRets struct {
	Result string
}

func getAccount(ctx native.Context, args getAccountArgs) (getAccountRets, error) {
	account, err := iroha.GetAccount(args.Account)
	if err != nil {
		return getAccountRets{}, err
	}
	ctx.Logger.Trace.Log("function", "getAccount",
		"account", args.Account,
		"domain", account.GetDomainId(),
		"quorum", fmt.Sprint(account.GetQuorum()))
	result, err := json.Marshal(account)
	return getAccountRets{Result: string(result)}, nil
}

type createAssetArgs struct {
	Name      string
	Domain    string
	Precision string
}

type createAssetRets struct {
	Result bool
}

func createAsset(ctx native.Context, args createAssetArgs) (createAssetRets, error) {
	err := iroha.CreateAsset(args.Name, args.Domain, args.Precision)
	if err != nil {
		return createAssetRets{Result: false}, err
	}

	ctx.Logger.Trace.Log("function", "createAsset",
		"asset name", args.Name,
		"domain id", args.Domain,
		"precision", args.Precision)

	return createAssetRets{Result: true}, nil
}

type getSignatoriesArgs struct {
	Account string
}

type getSignatoriesRets struct {
	Keys []string
}

func getSignatories(ctx native.Context, args getSignatoriesArgs) (getSignatoriesRets, error) {
	signatory, err := iroha.GetSignatories(args.Account)
	if err != nil {
		return getSignatoriesRets{}, err
	}

	ctx.Logger.Trace.Log("function", "getSignatories",
		"account", args.Account,
		"key", signatory)

	return getSignatoriesRets{Keys: signatory}, nil
}

type getAssetInfoArgs struct {
	Asset string
}

type getAssetInfoRets struct {
	Result string
}

func getAssetInfo(ctx native.Context, args getAssetInfoArgs) (getAssetInfoRets, error) {
	asset, err := iroha.GetAssetInfo(args.Asset)
	if err != nil {
		return getAssetInfoRets{}, err
	}
	ctx.Logger.Trace.Log("function", "getAssetInfo",
		"asset", args.Asset,
		"domain", asset.GetDomainId(),
		"precision", fmt.Sprint(asset.GetPrecision()))
	result, err := json.Marshal(asset)
	return getAssetInfoRets{Result: string(result)}, nil
}

type appendRoleArgs struct {
	Account string
	Role    string
}

type appendRoleRets struct {
	Result bool
}

func appendRole(ctx native.Context, args appendRoleArgs) (appendRoleRets, error) {
	err := iroha.AppendRole(args.Account, args.Role)
	if err != nil {
		return appendRoleRets{Result: false}, err
	}

	ctx.Logger.Trace.Log("function", "appendRole",
		"account name", args.Account,
		"new role", args.Role)

	return appendRoleRets{Result: true}, nil
}

type detachRoleArgs struct {
	Account string
	Role    string
}

type detachRoleRets struct {
	Result bool
}

func detachRole(ctx native.Context, args detachRoleArgs) (detachRoleRets, error) {
	err := iroha.DetachRole(args.Account, args.Role)
	if err != nil {
		return detachRoleRets{Result: false}, err
	}

	ctx.Logger.Trace.Log("function", "detachRole",
		"account name", args.Account,
		"removed role", args.Role)

	return detachRoleRets{Result: true}, nil
}

type addPeerArgs struct {
	Address string
	PeerKey string
}

type addPeerRets struct {
	Result bool
}

func addPeer(ctx native.Context, args addPeerArgs) (addPeerRets, error) {
	err := iroha.AddPeer(args.Address, args.PeerKey)
	if err != nil {
		return addPeerRets{Result: false}, err
	}

	ctx.Logger.Trace.Log("function", "addPeer",
		"peer address", args.Address,
		"peer key", args.PeerKey)

	return addPeerRets{Result: true}, nil
}

type removePeerArgs struct {
	PeerKey string
}

type removePeerRets struct {
	Result bool
}

func removePeer(ctx native.Context, args removePeerArgs) (removePeerRets, error) {
	err := iroha.RemovePeer(args.PeerKey)
	if err != nil {
		return removePeerRets{Result: false}, err
	}

	ctx.Logger.Trace.Log("function", "removePeer",
		"peer key", args.PeerKey)

	return removePeerRets{Result: true}, nil
}

type GrantPermissionArgs struct {
	AccountId string
	Permission string
}

type GrantPermissionRets struct {
	Result bool
}

func grantPermission(ctx native.Context, args GrantPermissionArgs) (GrantPermissionRets, error) {
	err := iroha.GrantPermission(args.AccountId, args.Permission)
	if err != nil {
		return GrantPermissionRets{Result: false}, err
	}

	ctx.Logger.Trace.Log("function", "GrantPermission",
		"account", args.AccountId, "Permission", args.Permission)

	return GrantPermissionRets{Result: true}, nil
}

type RevokePermissionArgs = GrantPermissionArgs
type RevokePermissionRets = GrantPermissionRets 

func revokePermission(ctx native.Context, args RevokePermissionArgs) (RevokePermissionRets, error) {
	err := iroha.RevokePermission(args.AccountId, args.Permission)
	if err != nil {
		return RevokePermissionRets{Result: false}, err
	}

	ctx.Logger.Trace.Log("function", "RevokePermission",
		"account", args.AccountId, "Permission", args.Permission)

	return RevokePermissionRets{Result: true}, nil
}

type compareAndSetAccountDetailArgs struct {
	AccountId string
	Key string
	Value string
	OldValue string
	CheckEmpty string
}

type compareAndSetAccountDetailRets struct {
	Result bool
}

func compareAndSetAccountDetail(ctx native.Context, args compareAndSetAccountDetailArgs) (compareAndSetAccountDetailRets, error) {
	err := iroha.CompareAndSetAccountDetail(args.AccountId, args.Key, args.Value, args.OldValue, args.CheckEmpty)
	if err != nil {
		return compareAndSetAccountDetailRets{Result: false}, err
	}

	ctx.Logger.Trace.Log("function", "CompareAndSetAccountDetail",
		"account", args.AccountId, "key", args.Key, "value", args.Value,
		"old value", args.OldValue, "check empty", args.CheckEmpty)

	return compareAndSetAccountDetailRets{Result: true}, nil
}

type createRoleArgs struct {
	RoleName string
	Permissions string
}

type createRoleRets struct {
	Result bool
}

func createRole(ctx native.Context, args createRoleArgs) (createRoleRets, error) {
	err := iroha.CreateRole(args.RoleName, args.Permissions)
	if err != nil {
		return createRoleRets{Result: false}, err
	}

	ctx.Logger.Trace.Log("function", "CreateRole",
		"Role Name", args.RoleName, "Permissions", args.Permissions)

	return createRoleRets{Result: true}, nil
}

type getPeersArgs struct {
}

type getPeersRets struct {
	Result string
}

func getPeers(ctx native.Context, args getPeersArgs) (getPeersRets, error) {
	peers, err := iroha.GetPeers()
	if err != nil {
		return getPeersRets{}, err
	}
	ctx.Logger.Trace.Log("function", "getPeers")
	result, err := json.Marshal(peers)
	return getPeersRets{Result: string(result)}, nil
}

type getBlockArgs struct {
	Height string
}

type getBlockRets struct {
	Result string
}

func getBlock(ctx native.Context, args getBlockArgs) (getBlockRets, error) {
	block, err := iroha.GetBlock(args.Height)
	if err != nil {
		return getBlockRets{}, err
	}
	ctx.Logger.Trace.Log("function", "getBlock",
		"block height", args.Height)
	result, err := json.Marshal(block)
	return getBlockRets{Result: string(result)}, nil
}

type getRolesArgs struct {
}

type getRolesRets struct {
	Result []string
}

func getRoles(ctx native.Context, args getRolesArgs) (getRolesRets, error) {
	roles, err := iroha.GetRoles()
	if err != nil {
		return getRolesRets{}, err
	}
	ctx.Logger.Trace.Log("function", "getRoles")
	return getRolesRets{Result: roles}, nil
}

type getRolePermissionsArgs struct {
	Role string
}

type getRolePermissionsRets struct {
	Result string
}

func getRolePermissions(ctx native.Context, args getRolePermissionsArgs) (getRolePermissionsRets, error) {
	permissions, err := iroha.GetRolePermissions(args.Role)
	if err != nil {
		return getRolePermissionsRets{}, err
	}
	ctx.Logger.Trace.Log("function", "getRolePermissions",
		"role id", args.Role)
	result, err := json.Marshal(permissions)
	return getRolePermissionsRets{Result: string(result)}, nil
}

type GetAccountTransactionsArgs struct {
	Account string
	PageSize string
	FirstTxHash string
	FirstTxTime string
	LastTxTime string
	FirstTxHeight string
	LastTxHeight string
	Ordering string 
}

type getAccountTransactionsRets struct {
	Result string
}

func getAccountTransactions(ctx native.Context, args GetAccountTransactionsArgs) (getAccountTransactionsRets, error) {
	paginationMetaArg := iroha_model.TxPaginationMeta{ PageSize: &args.PageSize, FirstTxHash: &args.PageSize, Ordering: &args.Ordering,
		FirstTxTime: &args.FirstTxTime, LastTxTime: &args.LastTxTime, FirstTxHeight: &args.FirstTxHeight, LastTxHeight: &args.LastTxHeight}
	transactions, err := iroha.GetAccountTransactions(args.Account, &paginationMetaArg)
	if err != nil {
		return getAccountTransactionsRets{}, err
	}
	ctx.Logger.Trace.Log("function", "GetAccountTransactions",
		"account", args.Account)
	result, err := json.Marshal(transactions)
	return getAccountTransactionsRets{Result: string(result)}, nil
}

type GetPendingTransactionsArgs struct {
	PageSize string
	FirstTxHash string
	FirstTxTime string
	LastTxTime string
	Ordering string 
}

type getPendingTransactionsRets struct {
	Result string
}

func getPendingTransactions(ctx native.Context, args GetPendingTransactionsArgs) (getPendingTransactionsRets, error) {
	paginationMetaArg := iroha_model.TxPaginationMeta{ PageSize: &args.PageSize, FirstTxHash: &args.PageSize, Ordering: &args.Ordering,
		FirstTxTime: &args.FirstTxTime, LastTxTime: &args.LastTxTime}
	transactions, err := iroha.GetPendingTransactions(&paginationMetaArg)
	if err != nil {
		return getPendingTransactionsRets{}, err
	}
	ctx.Logger.Trace.Log("function", "GetPendingTransactions")
	result, err := json.Marshal(transactions)
	return getPendingTransactionsRets{Result: string(result)}, nil
}

type GetAccountAssetTransactionsArgs struct {
	AccountId string
	AssetId string
	PageSize string
	FirstTxHash string
	FirstTxTime string
	LastTxTime string
	FirstTxHeight string
	LastTxHeight string
	Ordering string 
}

type getAccountAssetTransactionsRets struct {
	Result string
}

func getAccountAssetTransactions(ctx native.Context, args GetAccountAssetTransactionsArgs) (getAccountAssetTransactionsRets, error) {
	paginationMetaArg := iroha_model.TxPaginationMeta{ PageSize: &args.PageSize, FirstTxHash: &args.PageSize, Ordering: &args.Ordering,
		FirstTxTime: &args.FirstTxTime, LastTxTime: &args.LastTxTime, FirstTxHeight: &args.FirstTxHeight, LastTxHeight: &args.LastTxHeight}
	transactions, err := iroha.GetAccountAssetTransactions(args.AccountId, args.AssetId, &paginationMetaArg)
	if err != nil {
		return getAccountAssetTransactionsRets{}, err
	}
	ctx.Logger.Trace.Log("function", "GetAccountAssetTransactions", "account", args.AccountId, "asset", args.AssetId)
	result, err := json.Marshal(transactions)
	return getAccountAssetTransactionsRets{Result: string(result)}, nil
}

type GetTransactionsArgs struct {
	Hashes string
}

type getTransactionsRets struct {
	Result string
}

func getTransactions(ctx native.Context, args GetTransactionsArgs) (getTransactionsRets, error) {
	transactions, err := iroha.GetTransactions(args.Hashes)
	if err != nil {
		return getTransactionsRets{}, err
	}
	ctx.Logger.Trace.Log("function", "GetTransactions", "hashes", args.Hashes)
	result, err := json.Marshal(transactions)
	return getTransactionsRets{Result: string(result)}, nil
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
