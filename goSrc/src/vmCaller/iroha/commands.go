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

	"github.com/golang/protobuf/proto"
	pb "iroha.protocol"
)

var (
	IrohaCommandExecutor unsafe.Pointer
	IrohaQueryExecutor   unsafe.Pointer
	Caller               string
)


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
func GetTransactions(hash string) ([]*pb.Transaction, error) {
	tx_hash := []string{hash}
	query := &pb.Query{Payload: &pb.Query_Payload{
		Meta: &pb.QueryPayloadMeta{
			CreatedTime:      uint64(time.Now().UnixNano() / int64(time.Millisecond)),
			CreatorAccountId: Caller,
			QueryCounter:     1},
		Query: &pb.Query_Payload_GetTransactions{
			GetTransactions: &pb.GetTransactions{TxHashes: tx_hash}}}}
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

func GetAccountTransactions(accountID string) ([]*pb.Transaction, error) {
	query := &pb.Query{Payload: &pb.Query_Payload{
		Meta: &pb.QueryPayloadMeta{
			CreatedTime:      uint64(time.Now().UnixNano() / int64(time.Millisecond)),
			CreatorAccountId: Caller,
			QueryCounter:     1},
		Query: &pb.Query_Payload_GetAccountTransactions{
			GetAccountTransactions: &pb.GetAccountTransactions{AccountId: accountID}}}}
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

func GetAccountAssetTransactions(accountID string, assetID string) ([]*pb.Transaction, error) {
	query := &pb.Query{Payload: &pb.Query_Payload{
		Meta: &pb.QueryPayloadMeta{
			CreatedTime:      uint64(time.Now().UnixNano() / int64(time.Millisecond)),
			CreatorAccountId: Caller,
			QueryCounter:     1},
		Query: &pb.Query_Payload_GetAccountAssetTransactions{
			GetAccountAssetTransactions: &pb.GetAccountAssetTransactions{AccountId: accountID, AssetId: assetID}}}}
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
		return []*pb.Transaction{}, fmt.Errorf("Wrong response type in GetAccountAssetTransactions")
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
