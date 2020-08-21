package iroha

// #cgo CFLAGS: -I ../../../../irohad
// #cgo linux LDFLAGS: -Wl,-unresolved-symbols=ignore-all
// #cgo darwin LDFLAGS: -Wl,-undefined,dynamic_lookup
// #include "ametsuchi/impl/proto_command_executor.h"
// #include "ametsuchi/impl/proto_specific_query_executor.h"
import "C"
import (
	"fmt"
	"time"
	"unsafe"

	pb "iroha.protocol"

	"github.com/golang/protobuf/proto"
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
func TransferAsset(src, dst, asset, amount string) error {
	command := &pb.Command{Command: &pb.Command_TransferAsset{
		TransferAsset: &pb.TransferAsset{
			SrcAccountId:  src,
			DestAccountId: dst,
			AssetId:       asset,
			Description:   "EVM asset transfer",
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
