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
	if err != nil {
		return err
	}
	if commandResult.error_code != 0 {
		error_extra := ""
		error_extra_ptr := commandResult.error_extra.toStringAndRelease()
		if error_extra_ptr != nil {
			error_extra = ": " + *error_extra_ptr
		}
		return fmt.Errorf("Error executing TransferAsset command: %s", error_extra)
	}

	return nil
}

func CreateAccount(name string, domain string, key string) error {
	command := &pb.Command{Command: &pb.Command_CreateAccount{
		CreateAccount: &pb.CreateAccount{
			AccountName: name,
			DomainId:    domain,
			PublicKey:   key,
		}}}
	commandResult, err := makeProtobufCmdAndExecute(IrohaCommandExecutor, command)
	if err != nil {
		return err
	}
	if commandResult.error_code != 0 {
		error_extra := ""
		error_extra_ptr := commandResult.error_extra.toStringAndRelease()
		if error_extra_ptr != nil {
			error_extra = ": " + *error_extra_ptr
		}
		return fmt.Errorf("Error executing CreateAccount command: %s", error_extra)
	}

	return nil
}

func AddAssetQuantity(asset string, amount string) error {
	command := &pb.Command{Command: &pb.Command_AddAssetQuantity{
		AddAssetQuantity: &pb.AddAssetQuantity{
			AssetId: asset,
			Amount:  amount,
		}}}
	commandResult, err := makeProtobufCmdAndExecute(IrohaCommandExecutor, command)
	if err != nil {
		return err
	}
	if commandResult.error_code != 0 {
		error_extra := ""
		error_extra_ptr := commandResult.error_extra.toStringAndRelease()
		if error_extra_ptr != nil {
			error_extra = ": " + *error_extra_ptr
		}
		return fmt.Errorf("Error executing AddAssetQuantity command: %s", error_extra)
	}

	return nil
}

func SubtractAssetQuantity(asset string, amount string) error {
	command := &pb.Command{Command: &pb.Command_SubtractAssetQuantity{
		SubtractAssetQuantity: &pb.SubtractAssetQuantity{
			AssetId: asset,
			Amount:  amount,
		}}}
	commandResult, err := makeProtobufCmdAndExecute(IrohaCommandExecutor, command)
	if err != nil {
		return err
	}
	if commandResult.error_code != 0 {
		error_extra := ""
		error_extra_ptr := commandResult.error_extra.toStringAndRelease()
		if error_extra_ptr != nil {
			error_extra = ": " + *error_extra_ptr
		}
		return fmt.Errorf("Error executing SubtractAssetQuantity command: %s", error_extra)
	}

	return nil
}

func SetAccountDetail(account string, key string, value string) error {
	command := &pb.Command{Command: &pb.Command_SetAccountDetail{
		SetAccountDetail: &pb.SetAccountDetail{
			AccountId: account,
			Key:       key,
			Value:     value,
		}}}
	commandResult, err := makeProtobufCmdAndExecute(IrohaCommandExecutor, command)
	if err != nil {
		return err
	}
	if commandResult.error_code != 0 {
		error_extra := ""
		error_extra_ptr := commandResult.error_extra.toStringAndRelease()
		if error_extra_ptr != nil {
			error_extra = ": " + *error_extra_ptr
		}
		return fmt.Errorf("Error executing SetAccountDetail command: %s", error_extra)
	}

	return nil
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
	if err != nil {
		return err
	}
	if commandResult.error_code != 0 {
		error_extra := ""
		error_extra_ptr := commandResult.error_extra.toStringAndRelease()
		if error_extra_ptr != nil {
			error_extra = ": " + *error_extra_ptr
		}
		return fmt.Errorf("Error executing AddPeer command: %s", error_extra)
	}
	return nil
}

func RemovePeer(key string) error {
	command := &pb.Command{Command: &pb.Command_RemovePeer{
		RemovePeer: &pb.RemovePeer{
			PublicKey: key,
		}}}
	commandResult, err := makeProtobufCmdAndExecute(IrohaCommandExecutor, command)
	if err != nil {
		return err
	}
	if commandResult.error_code != 0 {
		error_extra := ""
		error_extra_ptr := commandResult.error_extra.toStringAndRelease()
		if error_extra_ptr != nil {
			error_extra = ": " + *error_extra_ptr
		}
		return fmt.Errorf("Error executing RemovePeer command: %s", error_extra)
	}
	return nil
}

func SetAccountQuorum(account string, quorum string) error {
	quorum_uint, err := strconv.ParseUint(quorum, 10, 32)
	command := &pb.Command{Command: &pb.Command_SetAccountQuorum{
		SetAccountQuorum: &pb.SetAccountQuorum{
			AccountId: account,
			Quorum:    uint32(quorum_uint),
		}}}
	commandResult, err := makeProtobufCmdAndExecute(IrohaCommandExecutor, command)
	if err != nil {
		return err
	}
	if commandResult.error_code != 0 {
		error_extra := ""
		error_extra_ptr := commandResult.error_extra.toStringAndRelease()
		if error_extra_ptr != nil {
			error_extra = ": " + *error_extra_ptr
		}
		return fmt.Errorf("Error executing SetAccountQuorum command: %s", error_extra)
	}
	return nil
}

func AddSignatory(account string, key string) error {
	command := &pb.Command{Command: &pb.Command_AddSignatory{
		AddSignatory: &pb.AddSignatory{
			AccountId: account,
			PublicKey: key,
		}}}
	commandResult, err := makeProtobufCmdAndExecute(IrohaCommandExecutor, command)
	if err != nil {
		return err
	}
	if commandResult.error_code != 0 {
		error_extra := ""
		error_extra_ptr := commandResult.error_extra.toStringAndRelease()
		if error_extra_ptr != nil {
			error_extra = ": " + *error_extra_ptr
		}
		return fmt.Errorf("Error executing AddSignatory command: %s", error_extra)
	}

	return nil
}

func RemoveSignatory(account string, key string) error {
	command := &pb.Command{Command: &pb.Command_RemoveSignatory{
		RemoveSignatory: &pb.RemoveSignatory{
			AccountId: account,
			PublicKey: key,
		}}}
	commandResult, err := makeProtobufCmdAndExecute(IrohaCommandExecutor, command)
	if err != nil {
		return err
	}
	if commandResult.error_code != 0 {
		error_extra := ""
		error_extra_ptr := commandResult.error_extra.toStringAndRelease()
		if error_extra_ptr != nil {
			error_extra = ": " + *error_extra_ptr
		}
		return fmt.Errorf("Error executing RemoveSignatory command: %s", error_extra)
	}

	return nil
}

func CreateDomain(domain string, role string) error {
	command := &pb.Command{Command: &pb.Command_CreateDomain{
		CreateDomain: &pb.CreateDomain{
			DomainId:    domain,
			DefaultRole: role,
		}}}
	commandResult, err := makeProtobufCmdAndExecute(IrohaCommandExecutor, command)
	if err != nil {
		return err
	}
	if commandResult.error_code != 0 {
		error_extra := ""
		error_extra_ptr := commandResult.error_extra.toStringAndRelease()
		if error_extra_ptr != nil {
			error_extra = ": " + *error_extra_ptr
		}
		return fmt.Errorf("Error executing CreateDomain command: %s", error_extra)
	}

	return nil
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
	if err != nil {
		return err
	}
	if commandResult.error_code != 0 {
		error_extra := ""
		error_extra_ptr := commandResult.error_extra.toStringAndRelease()
		if error_extra_ptr != nil {
			error_extra = ": " + *error_extra_ptr
		}
		return fmt.Errorf("Error executing CreateAsset command: %s", error_extra)
	}

	return nil
}

func AppendRole(account string, role string) error {
	command := &pb.Command{Command: &pb.Command_AppendRole{
		AppendRole: &pb.AppendRole{
			AccountId: account,
			RoleName:  role,
		}}}
	commandResult, err := makeProtobufCmdAndExecute(IrohaCommandExecutor, command)
	if err != nil {
		return err
	}
	if commandResult.error_code != 0 {
		error_extra := ""
		error_extra_ptr := commandResult.error_extra.toStringAndRelease()
		if error_extra_ptr != nil {
			error_extra = ": " + *error_extra_ptr
		}
		return fmt.Errorf("Error executing AppendRole command: %s", error_extra)
	}
	return nil
}

func DetachRole(account string, role string) error {
	command := &pb.Command{Command: &pb.Command_DetachRole{
		DetachRole: &pb.DetachRole{
			AccountId: account,
			RoleName:  role,
		}}}
	commandResult, err := makeProtobufCmdAndExecute(IrohaCommandExecutor, command)
	if err != nil {
		return err
	}
	if commandResult.error_code != 0 {
		error_extra := ""
		error_extra_ptr := commandResult.error_extra.toStringAndRelease()
		if error_extra_ptr != nil {
			error_extra = ": " + *error_extra_ptr
		}
		return fmt.Errorf("Error executing DetachRole command: %s", error_extra)
	}
	return nil
}

// -----------------------Iroha queries---------------------------------------

// Queries asset balance of an account
func GetAccountAssets(accountID string) ([]*pb.AccountAsset, error) {
	query := &pb.Query{Payload: &pb.Query_Payload{
		Meta: &pb.QueryPayloadMeta{
			CreatedTime:      uint64(time.Now().UnixNano() / int64(time.Millisecond)),
			CreatorAccountId: Caller,
			QueryCounter:     1},
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
	query := &pb.Query{Payload: &pb.Query_Payload{
		Meta: &pb.QueryPayloadMeta{
			CreatedTime:      uint64(time.Now().UnixNano() / int64(time.Millisecond)),
			CreatorAccountId: Caller,
			QueryCounter:     1},
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
	query := &pb.Query{Payload: &pb.Query_Payload{
		Meta: &pb.QueryPayloadMeta{
			CreatedTime:      uint64(time.Now().UnixNano() / int64(time.Millisecond)),
			CreatorAccountId: Caller,
			QueryCounter:     1},
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
	query := &pb.Query{Payload: &pb.Query_Payload{
		Meta: &pb.QueryPayloadMeta{
			CreatedTime:      uint64(time.Now().UnixNano() / int64(time.Millisecond)),
			CreatorAccountId: Caller,
			QueryCounter:     1},
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
	query := &pb.Query{Payload: &pb.Query_Payload{
		Meta: &pb.QueryPayloadMeta{
			CreatedTime:      uint64(time.Now().UnixNano() / int64(time.Millisecond)),
			CreatorAccountId: Caller,
			QueryCounter:     1},
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
	query := &pb.Query{Payload: &pb.Query_Payload{
		Meta: &pb.QueryPayloadMeta{
			CreatedTime:      uint64(time.Now().UnixNano() / int64(time.Millisecond)),
			CreatorAccountId: Caller,
			QueryCounter:     1},
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
	query := &pb.Query{Payload: &pb.Query_Payload{
		Meta: &pb.QueryPayloadMeta{
			CreatedTime:      uint64(time.Now().UnixNano() / int64(time.Millisecond)),
			CreatorAccountId: Caller,
			QueryCounter:     1},
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
	query := &pb.Query{Payload: &pb.Query_Payload{
		Meta: &pb.QueryPayloadMeta{
			CreatedTime:      uint64(time.Now().UnixNano() / int64(time.Millisecond)),
			CreatorAccountId: Caller,
			QueryCounter:     1},
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
	query := &pb.Query{Payload: &pb.Query_Payload{
		Meta: &pb.QueryPayloadMeta{
			CreatedTime:      uint64(time.Now().UnixNano() / int64(time.Millisecond)),
			CreatorAccountId: Caller,
			QueryCounter:     1},
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

// -----------------------Helper functions---------------------------------------

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
