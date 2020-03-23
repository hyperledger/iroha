package api

// #cgo CFLAGS: -I ../../../../irohad
// #cgo LDFLAGS: -Wl,-unresolved-symbols=ignore-all
// #include "ametsuchi/impl/proto_command_executor.h"
// #include "ametsuchi/impl/proto_specific_query_executor.h"
import "C"
import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unsafe"

	pb "vmCaller/iroha_protocol"

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/burrow/crypto"
)

var (
	IrohaCommandExecutor unsafe.Pointer
	IrohaQueryExecutor   unsafe.Pointer
)

/*
	Following functions are wrappers for Iroha API commands and queries with use of
	CommandExecutor or QueryExecutor accordingly, and protobuf messages from iroha_protocol.
*/

// -----------------------Iroha commands---------------------------------------

// Creates a "mirror" account in Iroha for an EVM account (someEvmAddress[:32] + @evm)
func CreateIrohaEvmAccount(addr crypto.Address) (err error) {
	accountName := irohaCompliantName(addr)

	command := &pb.Command{Command: &pb.Command_CreateAccount{
		CreateAccount: &pb.CreateAccount{AccountName: accountName, DomainId: "evm", PublicKey: fmt.Sprintf("%064s", addr.String())}}}
	commandResult, err := makeProtobufCmdAndExecute(IrohaCommandExecutor, command)
	if err != nil {
		return err
	}

	if commandResult.error_code != 0 {
		return fmt.Errorf("[api.CreateIrohaEvmAccount] error creating Iroha account at address %s", addr.String())
	}

	return nil
}

// Sets key-value pair in storage of the mirrored Iroha account
func SetIrohaAccountDetail(addr crypto.Address, key string, value string) (err error) {
	irohaCompliantAddress := IrohaAccountID(addr)
	// Send SetAccountDetail to Iroha
	command := &pb.Command{Command: &pb.Command_SetAccountDetail{&pb.SetAccountDetail{
		AccountId: irohaCompliantAddress, Key: key, Value: value}}}
	commandResult, err := makeProtobufCmdAndExecute(IrohaCommandExecutor, command)
	if err != nil {
		return err
	}
	fmt.Printf("[setIrohaAccountDetail] set Iroha account detail '%s' for address %s\n%s\n", key, irohaCompliantAddress, commandResult)
	if commandResult.error_code != 0 {
		return fmt.Errorf("[api.SetIrohaAccountDetail] error setting account detail '%s' for %s, value being set is %s",
			key, irohaCompliantAddress, value)
	}

	return nil
}

/*
	Transfer assets between accounts
*/
func TransferIrohaAsset(src, dst, asset, amount string) error {
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
	fmt.Println(commandResult)
	if commandResult.error_code != 0 {
		return fmt.Errorf("[api.TransferIrohaAsset] error transferring asset nominated in %s from %s to %s", asset, src, dst)
	}

	return nil
}

// -----------------------Iroha queries---------------------------------------

// Queries Iroha about the coupled account.
func GetIrohaAccount(addr crypto.Address) (exist bool, err error) {
	irohaCompliantAddress := IrohaAccountID(addr)
	query := &pb.Query{Payload: &pb.Query_Payload{
		Meta: &pb.QueryPayloadMeta{
			CreatedTime:      uint64(time.Now().UnixNano() / int64(time.Millisecond)),
			CreatorAccountId: "evm@evm",
			QueryCounter:     1},
		Query: &pb.Query_Payload_GetAccount{
			GetAccount: &pb.GetAccount{AccountId: irohaCompliantAddress}}}}
	queryResponse, err := makeProtobufQueryAndExecute(IrohaQueryExecutor, query)
	if err != nil {
		return false, err
	}
	switch response := queryResponse.Response.(type) {
	case *pb.QueryResponse_ErrorResponse:
		if response.ErrorResponse.Reason == pb.ErrorResponse_NO_ACCOUNT {
			// No errors, but requested account does not exist
			fmt.Printf("[api.GetIrohaAccount] QueryResponse_ErrorResponse: account %s not found\n", irohaCompliantAddress)
			return false, nil
		}
		return false, fmt.Errorf("[api.GetIrohaAccount] QueryResponse_ErrorResponse: %d, %v", response.ErrorResponse.ErrorCode, response.ErrorResponse.Message)
	case *pb.QueryResponse_AccountResponse:
		fmt.Printf("[api.GetIrohaAccount] QueryResponse_AccountResponse: %s", queryResponse.String())
		return true, nil
	default:
		return false, fmt.Errorf("[api.GetIrohaAccount] wrong queryResponse")
	}
}

// Queries Iroha about the mirrored account detail. Returns account detail
func GetIrohaAccountDetail(addr crypto.Address, key string) (detail string, err error) {
	irohaCompliantAddress := IrohaAccountID(addr)
	query := &pb.Query{Payload: &pb.Query_Payload{
		Meta: &pb.QueryPayloadMeta{
			CreatedTime:      uint64(time.Now().UnixNano() / int64(time.Millisecond)),
			CreatorAccountId: "evm@evm",
			QueryCounter:     1},
		Query: &pb.Query_Payload_GetAccountDetail{
			&pb.GetAccountDetail{
				OptAccountId: &pb.GetAccountDetail_AccountId{AccountId: irohaCompliantAddress},
				OptKey:       &pb.GetAccountDetail_Key{Key: key}}}}}
	queryResponse, err := makeProtobufQueryAndExecute(IrohaQueryExecutor, query)
	if err != nil {
		return "", err
	}
	switch response := queryResponse.Response.(type) {
	case *pb.QueryResponse_ErrorResponse:
		if response.ErrorResponse.Reason == pb.ErrorResponse_NO_ACCOUNT_DETAIL {
			// No errors, but requested account detail does not exist
			fmt.Printf("[api.GetIrohaAccountDetail] QueryResponse_ErrorResponse: no account detail '%s' for account %s\n", key, irohaCompliantAddress)
			return "", nil
		}
		return "", fmt.Errorf("[getIrohaAccountDetail] QueryResponse_ErrorResponse: %d, %v", response.ErrorResponse.ErrorCode, response.ErrorResponse.Message)
	case *pb.QueryResponse_AccountDetailResponse:
		fmt.Printf("[api.GetIrohaAccountDetail] QueryResponse_AccountDetailResponse: %s\n", queryResponse.String())
		accDetailResponse := queryResponse.GetAccountDetailResponse()
		accDetail := accDetailResponse.Detail
		var detailResponse interface{}
		err = json.Unmarshal([]byte(accDetail), &detailResponse)
		if err != nil {
			fmt.Println("[api.GetIrohaAccountDetail] Failed to unmarshal detail response")
			return "", err
		}

		switch response := detailResponse.(type) {
		case map[string]interface{}:
			value, exist := response["evm@evm"]
			if !exist {
				return "", nil
			}
			return value.(map[string]interface{})[key].(string), nil

		default:
			return "", fmt.Errorf("[api.GetIrohaAccountDetail] unexpected response type")
		}

	default:
		return "", fmt.Errorf("[api.GetIrohaAccountDetail] wrong queryResponse")
	}
}

// Queries asset balance of an account
func GetIrohaAccountAssets(accountID string) ([]*pb.AccountAsset, error) {
	query := &pb.Query{Payload: &pb.Query_Payload{
		Meta: &pb.QueryPayloadMeta{
			CreatedTime:      uint64(time.Now().UnixNano() / int64(time.Millisecond)),
			CreatorAccountId: "evm@evm",
			QueryCounter:     1},
		Query: &pb.Query_Payload_GetAccountAssets{
			GetAccountAssets: &pb.GetAccountAssets{AccountId: accountID}}}}
	queryResponse, err := makeProtobufQueryAndExecute(IrohaQueryExecutor, query)
	if err != nil {
		return []*pb.AccountAsset{}, err
	}
	switch response := queryResponse.Response.(type) {
	case *pb.QueryResponse_ErrorResponse:
		if response.ErrorResponse.Reason == pb.ErrorResponse_NO_ACCOUNT {
			// No errors, but requested account does not exist
			fmt.Printf("[api.GetIrohaAccountAssets] QueryResponse_ErrorResponse: account %s not found\n", accountID)
			return []*pb.AccountAsset{}, nil
		}
		return []*pb.AccountAsset{}, fmt.Errorf("[api.GetIrohaAccountAssets] QueryResponse_ErrorResponse: %d, %v", response.ErrorResponse.ErrorCode, response.ErrorResponse.Message)
	case *pb.QueryResponse_AccountAssetsResponse:
		fmt.Printf("[api.GetIrohaAccountAssets] QueryResponse_AccountAssetsResponse: %s\n", queryResponse.String())
		accountAssetsResponse := queryResponse.GetAccountAssetsResponse()
		return accountAssetsResponse.AccountAssets, nil
	default:
		return []*pb.AccountAsset{}, fmt.Errorf("[api.GetIrohaAccountAssets] wrong queryResponse")
	}
}

// -----------------------Helper functions---------------------------------------

// Execute Iroha command
func makeProtobufCmdAndExecute(cmdExecutor unsafe.Pointer, command *pb.Command) (res *C.struct_Iroha_CommandError, err error) {
	fmt.Println(proto.MarshalTextString(command))
	out, err := proto.Marshal(command)
	if err != nil {
		fmt.Println(err)
		// magic constant, if not 0 => fail happened
		return &C.struct_Iroha_CommandError{error_code: 100}, err
	}
	cOut := C.CBytes(out)
	commandResult := C.Iroha_ProtoCommandExecutorExecute(cmdExecutor, cOut, C.int(len(out)), C.CString("evm@evm"))
	return &commandResult, nil
}

// Perform Iroha query
func makeProtobufQueryAndExecute(queryExecutor unsafe.Pointer, query *pb.Query) (res *pb.QueryResponse, err error) {
	fmt.Println(proto.MarshalTextString(query))
	out, err := proto.Marshal(query)
	if err != nil {
		fmt.Println(err)
	}
	cOut := C.CBytes(out)
	queryResult := C.Iroha_ProtoSpecificQueryExecutorExecute(queryExecutor, cOut, C.int(len(out)))
	fmt.Println(queryResult)
	out = C.GoBytes(queryResult.data, queryResult.size)
	queryResponse := &pb.QueryResponse{}
	err = proto.Unmarshal(out, queryResponse)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	return queryResponse, nil
}

func (res *C.struct_Iroha_CommandError) String() string {
	if res.error_extra != nil {
		return fmt.Sprintf("%d, %s", res.error_code, C.GoString(res.error_extra))
	} else {
		return fmt.Sprintf("Iroha_CommandError: code %d", res.error_code)
	}
}

// Helper functions to convert 40 byte long EVM hex-encoded addresses to Iroha compliant account names (32 bytes max)
func irohaCompliantName(addr crypto.Address) string {
	s := strings.ToLower(addr.String())
	if len(s) > 32 {
		s = s[:32]
	}
	return s
}

func IrohaAccountID(addr crypto.Address) string {
	return irohaCompliantName(addr) + "@evm"
}
