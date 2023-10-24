package iroha

// #cgo CFLAGS: -I ../../../../irohad
// #cgo linux LDFLAGS: -Wl,-unresolved-symbols=ignore-all
// #cgo darwin LDFLAGS: -Wl,-undefined,dynamic_lookup
// #include "ametsuchi/impl/proto_command_executor.h"
// #include "ametsuchi/impl/proto_specific_query_executor.h"
import "C"
import (
	"fmt"
	"strconv"
	"time"
	"unsafe"
	"github.com/golang/protobuf/proto"
	pb "iroha.protocol"
	"vmCaller/iroha_model"
	"encoding/json"
)

var (
	IrohaCommandExecutor unsafe.Pointer
	IrohaQueryExecutor   unsafe.Pointer
	Caller               string
)

// -----------------------Iroha commands---------------------------------------

/*
	Transfer assets between accounts
*/
func TransferAsset(src, dst, asset, description, amount string) error {
	command := &pb.Command{Command: &pb.Command_TransferAsset{
		TransferAsset: &pb.TransferAsset{
			SrcAccountId:  src,
			DestAccountId: dst,
			AssetId:       asset,
			Description:   description,
			Amount:        amount,
		}}}
	commandResult, err := makeProtobufCmdAndExecute(IrohaCommandExecutor, command)
	return handleErrors(commandResult, err, "TransferAsset")
}

func CreateAccount(name string, domain string, key string) error {
	command := &pb.Command{Command: &pb.Command_CreateAccount{
		CreateAccount: &pb.CreateAccount{
			AccountName: name,
			DomainId:    domain,
			PublicKey:   key,
		}}}
	commandResult, err := makeProtobufCmdAndExecute(IrohaCommandExecutor, command)
	return handleErrors(commandResult, err, "CreateAccount")
}

func AddAssetQuantity(asset string, amount string) error {
	command := &pb.Command{Command: &pb.Command_AddAssetQuantity{
		AddAssetQuantity: &pb.AddAssetQuantity{
			AssetId: asset,
			Amount:  amount,
		}}}
	commandResult, err := makeProtobufCmdAndExecute(IrohaCommandExecutor, command)
	return handleErrors(commandResult, err, "AddAssetQuantity")
}

func SubtractAssetQuantity(asset string, amount string) error {
	command := &pb.Command{Command: &pb.Command_SubtractAssetQuantity{
		SubtractAssetQuantity: &pb.SubtractAssetQuantity{
			AssetId: asset,
			Amount:  amount,
		}}}
	commandResult, err := makeProtobufCmdAndExecute(IrohaCommandExecutor, command)
	return handleErrors(commandResult, err, "SubtractAssetQuantity")
}

func SetAccountDetail(account string, key string, value string) error {
	command := &pb.Command{Command: &pb.Command_SetAccountDetail{
		SetAccountDetail: &pb.SetAccountDetail{
			AccountId: account,
			Key:       key,
			Value:     value,
		}}}
	commandResult, err := makeProtobufCmdAndExecute(IrohaCommandExecutor, command)
	return handleErrors(commandResult, err, "SetAccountDetail")
}

func AddPeer(address string, key string) error {
	command := &pb.Command{Command: &pb.Command_AddPeer{
		AddPeer: &pb.AddPeer{
			Peer: &pb.Peer{
				Address: address,
				PeerKey: key,
			},
		}}}
	commandResult, err := makeProtobufCmdAndExecute(IrohaCommandExecutor, command)
	return handleErrors(commandResult, err, "AddPeer")
}

func RemovePeer(key string) error {
	command := &pb.Command{Command: &pb.Command_RemovePeer{
		RemovePeer: &pb.RemovePeer{
			PublicKey: key,
		}}}
	commandResult, err := makeProtobufCmdAndExecute(IrohaCommandExecutor, command)
	return handleErrors(commandResult, err, "RemovePeer")
}

func SetAccountQuorum(account string, quorum string) error {
	quorum_uint, err := strconv.ParseUint(quorum, 10, 32)
	command := &pb.Command{Command: &pb.Command_SetAccountQuorum{
		SetAccountQuorum: &pb.SetAccountQuorum{
			AccountId: account,
			Quorum:    uint32(quorum_uint),
		}}}
	commandResult, err := makeProtobufCmdAndExecute(IrohaCommandExecutor, command)
	return handleErrors(commandResult, err, "SetAccountQuorum")
}

func AddSignatory(account string, key string) error {
	command := &pb.Command{Command: &pb.Command_AddSignatory{
		AddSignatory: &pb.AddSignatory{
			AccountId: account,
			PublicKey: key,
		}}}
	commandResult, err := makeProtobufCmdAndExecute(IrohaCommandExecutor, command)
	return handleErrors(commandResult, err, "AddSignatory")
}

func RemoveSignatory(account string, key string) error {
	command := &pb.Command{Command: &pb.Command_RemoveSignatory{
		RemoveSignatory: &pb.RemoveSignatory{
			AccountId: account,
			PublicKey: key,
		}}}
	commandResult, err := makeProtobufCmdAndExecute(IrohaCommandExecutor, command)
	return handleErrors(commandResult, err, "RemoveSignatory")
}

func CreateDomain(domain string, role string) error {
	command := &pb.Command{Command: &pb.Command_CreateDomain{
		CreateDomain: &pb.CreateDomain{
			DomainId:    domain,
			DefaultRole: role,
		}}}
	commandResult, err := makeProtobufCmdAndExecute(IrohaCommandExecutor, command)
	return handleErrors(commandResult, err, "CreateDomain")
}

func CreateAsset(name string, domain string, precision string) error {
	precision_uint, err := strconv.ParseUint(precision, 10, 32)
	command := &pb.Command{Command: &pb.Command_CreateAsset{
		CreateAsset: &pb.CreateAsset{
			AssetName: name,
			DomainId:  domain,
			Precision: uint32(precision_uint),
		}}}
	commandResult, err := makeProtobufCmdAndExecute(IrohaCommandExecutor, command)
	return handleErrors(commandResult, err, "CreateAsset")
}

func AppendRole(account string, role string) error {
	command := &pb.Command{Command: &pb.Command_AppendRole{
		AppendRole: &pb.AppendRole{
			AccountId: account,
			RoleName:  role,
		}}}
	commandResult, err := makeProtobufCmdAndExecute(IrohaCommandExecutor, command)
	return handleErrors(commandResult, err, "AppendRole")
}

func DetachRole(account string, role string) error {
	command := &pb.Command{Command: &pb.Command_DetachRole{
		DetachRole: &pb.DetachRole{
			AccountId: account,
			RoleName:  role,
		}}}
	commandResult, err := makeProtobufCmdAndExecute(IrohaCommandExecutor, command)
	return handleErrors(commandResult, err, "DetachRole")
}

func GrantPermission(account string, permission string) error {
	perm := pb.GrantablePermission_value[permission]
	command := &pb.Command{Command: &pb.Command_GrantPermission{
		GrantPermission: &pb.GrantPermission{
			AccountId: account,
			Permission: pb.GrantablePermission(perm),
		}}}
	commandResult, err := makeProtobufCmdAndExecute(IrohaCommandExecutor, command)
	return handleErrors(commandResult, err, "GrantPermission")
}

func RevokePermission(account string, permission string) error {
	perm := pb.GrantablePermission_value[permission]
	command := &pb.Command{Command: &pb.Command_RevokePermission{
		RevokePermission: &pb.RevokePermission{
			AccountId: account,
			Permission: pb.GrantablePermission(perm),
		}}}
	commandResult, err := makeProtobufCmdAndExecute(IrohaCommandExecutor, command)
	return handleErrors(commandResult, err, "RevokePermission")
}

func MakeCompareAndSetAccountDetailArgs(account string, key string, value string, oldValue string, checkEmpty string) (pb.Command, error) {
	cmd1 := &pb.CompareAndSetAccountDetail{
		Key: key,
		Value: value,
		AccountId: account,
	}
	if len(oldValue) != 0 {
		cmd1.OptOldValue = &pb.CompareAndSetAccountDetail_OldValue{oldValue}
	}
	if len(checkEmpty)!=0 {
		val, err := strconv.ParseBool(checkEmpty)
		if err==nil {
			cmd1.CheckEmpty = val
		}else {
			return pb.Command{}, fmt.Errorf("Incorrect value passed to check_empty field")
		}
	}
	cmd := pb.Command{Command:&pb.Command_CompareAndSetAccountDetail{CompareAndSetAccountDetail: cmd1}}
	return cmd, nil
}

func CompareAndSetAccountDetail(account string, key string, value string, oldValue string, checkEmpty string) error {
	command, err := MakeCompareAndSetAccountDetailArgs(account, key, value, oldValue, checkEmpty)
	if err!=nil {
		return handleErrors(nil, err, "		")
	}
	commandResult, err := makeProtobufCmdAndExecute(IrohaCommandExecutor, &command)
	return handleErrors(commandResult, err, "CompareAndSetAccountDetail")
}

func CreateRole(roleName string, permissions string) error {
	var perms_enc []string
	json.Unmarshal([]byte(permissions), &perms_enc)
	var pb_perms = make([]pb.RolePermission, len(perms_enc))
	for i, perm := range perms_enc {
		pb_perms[i] = pb.RolePermission(pb.RolePermission_value[perm])
	}
	command := &pb.Command{Command: &pb.Command_CreateRole{
		CreateRole: &pb.CreateRole{
			RoleName: roleName,
			Permissions:  pb_perms,
		}}}
	commandResult, err := makeProtobufCmdAndExecute(IrohaCommandExecutor, command)
	return handleErrors(commandResult, err, "CreateRole")
}
// -----------------------Iroha queries---------------------------------------

// Queries asset balance of an account
func GetAccountAssets(accountID string) ([]*pb.AccountAsset, error) {
	metaPayload := MakeQueryPayloadMeta()
	query := &pb.Query{Payload: &pb.Query_Payload{
		Meta: &metaPayload,
		Query: &pb.Query_Payload_GetAccountAssets{
			GetAccountAssets: &pb.GetAccountAssets{AccountId: accountID}}}}
	queryResponse, err := makeProtobufQueryAndExecute(IrohaQueryExecutor, query)
	if err != nil {
		return []*pb.AccountAsset{}, err
	}
	switch response := queryResponse.Response.(type) {
	case *pb.QueryResponse_ErrorResponse:
		return []*pb.AccountAsset{}, fmt.Errorf(
			"ErrorResponse in GetIrohaAccountAssets: %d, %v",
			response.ErrorResponse.ErrorCode,
			response.ErrorResponse.Message,
		)
	case *pb.QueryResponse_AccountAssetsResponse:
		accountAssetsResponse := queryResponse.GetAccountAssetsResponse()
		return accountAssetsResponse.AccountAssets, nil
	default:
		return []*pb.AccountAsset{}, fmt.Errorf("Wrong response type in GetIrohaAccountAssets")
	}
}

func GetAccountDetail() (string, error) {
	metaPayload := MakeQueryPayloadMeta()
	query := &pb.Query{Payload: &pb.Query_Payload{
		Meta: &metaPayload,
		Query: &pb.Query_Payload_GetAccountDetail{
			GetAccountDetail: &pb.GetAccountDetail{}}}}
	queryResponse, err := makeProtobufQueryAndExecute(IrohaQueryExecutor, query)
	if err != nil {
		return "Error", err
	}
	switch response := queryResponse.Response.(type) {
	case *pb.QueryResponse_ErrorResponse:
		return "ERROR", fmt.Errorf(
			"ErrorResponse in GetIrohaAccountDetail: %d, %v",
			response.ErrorResponse.ErrorCode,
			response.ErrorResponse.Message,
		)
	case *pb.QueryResponse_AccountDetailResponse:
		accountDetailResponse := queryResponse.GetAccountDetailResponse()
		return accountDetailResponse.Detail, nil
	default:
		return "", fmt.Errorf("Wrong response type in GetIrohaAccountDetail")
	}
}

func GetAccount(accountID string) (*pb.Account, error) {
	metaPayload := MakeQueryPayloadMeta()
	query := &pb.Query{Payload: &pb.Query_Payload{
		Meta: &metaPayload,
		Query: &pb.Query_Payload_GetAccount{
			GetAccount: &pb.GetAccount{AccountId: accountID}}}}
	queryResponse, err := makeProtobufQueryAndExecute(IrohaQueryExecutor, query)
	if err != nil {
		return &pb.Account{}, err
	}
	switch response := queryResponse.Response.(type) {
	case *pb.QueryResponse_ErrorResponse:
		return &pb.Account{}, fmt.Errorf(
			"ErrorResponse in GetIrohaAccount: %d, %v",
			response.ErrorResponse.ErrorCode,
			response.ErrorResponse.Message,
		)
	case *pb.QueryResponse_AccountResponse:
		accountResponse := queryResponse.GetAccountResponse()
		return accountResponse.Account, nil
	default:
		return &pb.Account{}, fmt.Errorf("Wrong response type in GetIrohaAccount")
	}
}

func GetSignatories(accountID string) ([]string, error) {
	metaPayload := MakeQueryPayloadMeta()
	query := &pb.Query{Payload: &pb.Query_Payload{
		Meta: &metaPayload,
		Query: &pb.Query_Payload_GetSignatories{
			GetSignatories: &pb.GetSignatories{AccountId: accountID}}}}
	queryResponse, err := makeProtobufQueryAndExecute(IrohaQueryExecutor, query)
	if err != nil {
		return []string{"Error"}, err
	}
	switch response := queryResponse.Response.(type) {
	case *pb.QueryResponse_ErrorResponse:
		return []string{"ERROR"}, fmt.Errorf(
			"ErrorResponse in GetAccountSignatories: %d, %v",
			response.ErrorResponse.ErrorCode,
			response.ErrorResponse.Message,
		)
	case *pb.QueryResponse_SignatoriesResponse:
		signatoriesResponse := queryResponse.GetSignatoriesResponse()
		return signatoriesResponse.Keys, nil
	default:
		return []string{""}, fmt.Errorf("Wrong response type in GetSignatories")
	}
}

func GetAssetInfo(assetID string) (*pb.Asset, error) {
	metaPayload := MakeQueryPayloadMeta()
	query := &pb.Query{Payload: &pb.Query_Payload{
		Meta: &metaPayload,
		Query: &pb.Query_Payload_GetAssetInfo{
			GetAssetInfo: &pb.GetAssetInfo{AssetId: assetID}}}}
	queryResponse, err := makeProtobufQueryAndExecute(IrohaQueryExecutor, query)
	if err != nil {
		return &pb.Asset{}, err
	}
	switch response := queryResponse.Response.(type) {
	case *pb.QueryResponse_ErrorResponse:
		return &pb.Asset{}, fmt.Errorf(
			"ErrorResponse in GetAssetInfo: %d, %v",
			response.ErrorResponse.ErrorCode,
			response.ErrorResponse.Message,
		)
	case *pb.QueryResponse_AssetResponse:
		assetResponse := queryResponse.GetAssetResponse()
		return assetResponse.Asset, nil
	default:
		return &pb.Asset{}, fmt.Errorf("Wrong response type in GetAssetInfo")
	}
}

func GetPeers() ([]*pb.Peer, error) {
	metaPayload := MakeQueryPayloadMeta()
	query := &pb.Query{Payload: &pb.Query_Payload{
		Meta: &metaPayload,
		Query: &pb.Query_Payload_GetPeers{
			GetPeers: &pb.GetPeers{}}}}
	queryResponse, err := makeProtobufQueryAndExecute(IrohaQueryExecutor, query)
	if err != nil {
		return []*pb.Peer{}, err
	}
	switch response := queryResponse.Response.(type) {
	case *pb.QueryResponse_ErrorResponse:
		return []*pb.Peer{}, fmt.Errorf(
			"ErrorResponse in GetPeers: %d, %v",
			response.ErrorResponse.ErrorCode,
			response.ErrorResponse.Message,
		)
	case *pb.QueryResponse_PeersResponse:
		peersResponse := queryResponse.GetPeersResponse()
		return peersResponse.Peers, nil
	default:
		return []*pb.Peer{}, fmt.Errorf("Wrong response type in GetPeers")
	}
}

func GetBlock(height string) (*pb.Block, error) {
	height_uint, err := strconv.ParseUint(height, 10, 64)
	metaPayload := MakeQueryPayloadMeta()
	query := &pb.Query{Payload: &pb.Query_Payload{
		Meta: &metaPayload,
		Query: &pb.Query_Payload_GetBlock{
			GetBlock: &pb.GetBlock{Height: height_uint}}}}
	queryResponse, err := makeProtobufQueryAndExecute(IrohaQueryExecutor, query)
	if err != nil {
		return &pb.Block{}, err
	}
	switch response := queryResponse.Response.(type) {
	case *pb.QueryResponse_ErrorResponse:
		return &pb.Block{}, fmt.Errorf(
			"ErrorResponse in GetBlock: %d, %v",
			response.ErrorResponse.ErrorCode,
			response.ErrorResponse.Message,
		)
	case *pb.QueryResponse_BlockResponse:
		blockResponse := queryResponse.GetBlockResponse()
		return blockResponse.Block, nil
	default:
		return &pb.Block{}, fmt.Errorf("Wrong response type in GetBlock")
	}
}

func GetRoles() ([]string, error) {
	metaPayload := MakeQueryPayloadMeta()
	query := &pb.Query{Payload: &pb.Query_Payload{
		Meta: &metaPayload,
		Query: &pb.Query_Payload_GetRoles{
			GetRoles: &pb.GetRoles{}}}}
	queryResponse, err := makeProtobufQueryAndExecute(IrohaQueryExecutor, query)
	if err != nil {
		return []string{}, err
	}
	switch response := queryResponse.Response.(type) {
	case *pb.QueryResponse_ErrorResponse:
		return []string{}, fmt.Errorf(
			"ErrorResponse in GetRoles: %d, %v",
			response.ErrorResponse.ErrorCode,
			response.ErrorResponse.Message,
		)
	case *pb.QueryResponse_RolesResponse:
		rolesResponse := queryResponse.GetRolesResponse()
		return rolesResponse.Roles, nil
	default:
		return []string{}, fmt.Errorf("Wrong response type in GetRoles")
	}
}

func GetRolePermissions(role string) ([]pb.RolePermission, error) {
	metaPayload := MakeQueryPayloadMeta()
	query := &pb.Query{Payload: &pb.Query_Payload{
		Meta: &metaPayload,
		Query: &pb.Query_Payload_GetRolePermissions{
			GetRolePermissions: &pb.GetRolePermissions{RoleId: role}}}}
	queryResponse, err := makeProtobufQueryAndExecute(IrohaQueryExecutor, query)
	if err != nil {
		return []pb.RolePermission{}, err
	}
	switch response := queryResponse.Response.(type) {
	case *pb.QueryResponse_ErrorResponse:
		return []pb.RolePermission{}, fmt.Errorf(
			"ErrorResponse in GetRolePermissions: %d, %v",
			response.ErrorResponse.ErrorCode,
			response.ErrorResponse.Message,
		)
	case *pb.QueryResponse_RolePermissionsResponse:
		rolePermissionsResponse := queryResponse.GetRolePermissionsResponse()
		return rolePermissionsResponse.Permissions, nil
	default:
		return []pb.RolePermission{}, fmt.Errorf("Wrong response type in GetRolePermissions")
	}
}


func GetAccountTransactions(accountID string, txPaginationMeta *iroha_model.TxPaginationMeta) ([]*pb.Transaction, error) {
	txPagination, err := iroha_model.MakeTxPaginationMeta(txPaginationMeta)
	if err != nil {
		return []*pb.Transaction{}, err
	}

	metaPayload := MakeQueryPayloadMeta()
	query := &pb.Query{Payload: &pb.Query_Payload{
		Meta: &metaPayload,
		Query: &pb.Query_Payload_GetAccountTransactions{
			GetAccountTransactions: &pb.GetAccountTransactions{AccountId: accountID, PaginationMeta: &txPagination}}}}
	queryResponse, err := makeProtobufQueryAndExecute(IrohaQueryExecutor, query)
	if err != nil {
		return []*pb.Transaction{}, err
	}
	switch response := queryResponse.Response.(type) {
	case *pb.QueryResponse_ErrorResponse:
		return []*pb.Transaction{}, fmt.Errorf(
			"ErrorResponse in GetAccountTransactions: %d, %v",
			response.ErrorResponse.ErrorCode,
			response.ErrorResponse.Message,
		)
	case *pb.QueryResponse_TransactionsPageResponse:
		transactionsPageResponse := queryResponse.GetTransactionsPageResponse()
		return transactionsPageResponse.Transactions, nil
	default:
		return []*pb.Transaction{}, fmt.Errorf("Wrong response type in GetAccountTransactions")
	}
}

func GetPendingTransactions(txPaginationMeta *iroha_model.TxPaginationMeta) ([]*pb.Transaction, error) {
	txPagination, err := iroha_model.MakeTxPaginationMeta(txPaginationMeta)
	if err != nil {
		return []*pb.Transaction{}, err
	}
	metaPayload := MakeQueryPayloadMeta()
	query := &pb.Query{Payload: &pb.Query_Payload{
		Meta: &metaPayload,
		Query: &pb.Query_Payload_GetPendingTransactions{
			GetPendingTransactions: &pb.GetPendingTransactions{PaginationMeta: &txPagination}}}}
	queryResponse, err := makeProtobufQueryAndExecute(IrohaQueryExecutor, query)
	if err != nil {
		return []*pb.Transaction{}, err
	}
	switch response := queryResponse.Response.(type) {
	case *pb.QueryResponse_ErrorResponse:
		return []*pb.Transaction{}, fmt.Errorf(
			"ErrorResponse in GetPendingTransactions: %d, %v",
			response.ErrorResponse.ErrorCode,
			response.ErrorResponse.Message,
		)
	case *pb.QueryResponse_PendingTransactionsPageResponse:
		transactionsPageResponse := queryResponse.GetPendingTransactionsPageResponse()
		return transactionsPageResponse.Transactions, nil
	default:
		return []*pb.Transaction{}, fmt.Errorf("Wrong response type in GetPendingTransactions")
	}
}

func GetAccountAssetTransactions(accountId string, domainId string, txPaginationMeta *iroha_model.TxPaginationMeta) ([]*pb.Transaction, error) {
	txPagination, err := iroha_model.MakeTxPaginationMeta(txPaginationMeta)
	if err != nil {
		return []*pb.Transaction{}, err
	}
	metaPayload := MakeQueryPayloadMeta()
	query := &pb.Query{Payload: &pb.Query_Payload{
		Meta: &metaPayload,
		Query: &pb.Query_Payload_GetAccountAssetTransactions{
			GetAccountAssetTransactions: &pb.GetAccountAssetTransactions{AccountId: accountId, AssetId: domainId, PaginationMeta: &txPagination}}}}
	queryResponse, err := makeProtobufQueryAndExecute(IrohaQueryExecutor, query)
	if err != nil {
		return []*pb.Transaction{}, err
	}
	switch response := queryResponse.Response.(type) {
	case *pb.QueryResponse_ErrorResponse:
		return []*pb.Transaction{}, fmt.Errorf(
			"ErrorResponse in GetAccountAssetTransactions: %d, %v",
			response.ErrorResponse.ErrorCode,
			response.ErrorResponse.Message,
		)
	case *pb.QueryResponse_TransactionsPageResponse:
		transactionsPageResponse := queryResponse.GetTransactionsPageResponse()
		return transactionsPageResponse.Transactions, nil
	default:
		return []*pb.Transaction{}, fmt.Errorf("Wrong response type in GetAccountAssetTransactions")
	}
}

func GetTransactions(hashes string) ([]*pb.Transaction, error) {
	metaPayload := MakeQueryPayloadMeta()
	var hashes_decoded []string
	json.Unmarshal([]byte(hashes), &hashes_decoded)
	query := &pb.Query{Payload: &pb.Query_Payload{
		Meta: &metaPayload,
		Query: &pb.Query_Payload_GetTransactions{
			GetTransactions: &pb.GetTransactions{TxHashes: hashes_decoded}}}}
	queryResponse, err := makeProtobufQueryAndExecute(IrohaQueryExecutor, query)
	if err != nil {
		return []*pb.Transaction{}, err
	}
	switch response := queryResponse.Response.(type) {
	case *pb.QueryResponse_ErrorResponse:
		return []*pb.Transaction{}, fmt.Errorf(
			"ErrorResponse in GetTransactions: %d, %v",
			response.ErrorResponse.ErrorCode,
			response.ErrorResponse.Message,
		)
	case *pb.QueryResponse_TransactionsResponse:
		transactionsResponse := queryResponse.GetTransactionsResponse()
		return transactionsResponse.Transactions, nil
	default:
		return []*pb.Transaction{}, fmt.Errorf("Wrong response type in GetTransactions")
	}
}

// -----------------------Helper functions---------------------------------------

func MakeQueryPayloadMeta() pb.QueryPayloadMeta {
	return pb.QueryPayloadMeta{
			CreatedTime:      uint64(time.Now().UnixNano() / int64(time.Millisecond)),
			CreatorAccountId: Caller,
			QueryCounter:     1}
} 

// Execute Iroha command
func makeProtobufCmdAndExecute(cmdExecutor unsafe.Pointer, command *pb.Command) (res *C.Iroha_CommandError, err error) {
	out, err := proto.Marshal(command)
	if err != nil {
		// magic constant, if not 0 => fail happened
		return &C.Iroha_CommandError{error_code: 100}, err
	}
	cOut := C.CBytes(out)
	commandResult := C.Iroha_ProtoCommandExecutorExecute(cmdExecutor, cOut, C.int(len(out)), C.CString(Caller))
	return &commandResult, nil
}

// Perform Iroha query
func makeProtobufQueryAndExecute(queryExecutor unsafe.Pointer, query *pb.Query) (res *pb.QueryResponse, err error) {
	out, err := proto.Marshal(query)
	if err != nil {
		return nil, err
	}
	cOut := C.CBytes(out)
	queryResult := C.Iroha_ProtoSpecificQueryExecutorExecute(queryExecutor, cOut, C.int(len(out)))
	out = C.GoBytes(queryResult.data, queryResult.size)
	queryResponse := &pb.QueryResponse{}
	err = proto.Unmarshal(out, queryResponse)
	if err != nil {
		return nil, err
	}
	return queryResponse, nil
}

//Performs Error Handling
func handleErrors(result *C.Iroha_CommandError, err error, commandName string) (e error) {
	if err != nil {
		return err
	}
	if result.error_code != 0 {
		error_extra := ""
		error_extra_ptr := result.error_extra.toStringAndRelease()
		if error_extra_ptr != nil {
			error_extra = ": " + *error_extra_ptr
		}
		return fmt.Errorf("Error executing %s command: %s", commandName, error_extra)
	}
	return nil
}
