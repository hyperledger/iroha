package state

// #cgo CFLAGS: -I ../../../../irohad
// #cgo LDFLAGS: -Wl,-unresolved-symbols=ignore-all
// #include "ametsuchi/impl/proto_command_executor.h"
// #include "ametsuchi/impl/proto_specific_query_executor.h"
import "C"
import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/burrow/acm"
	"github.com/hyperledger/burrow/acm/acmstate"
	"github.com/hyperledger/burrow/binary"
	"github.com/hyperledger/burrow/crypto"
	"time"
	"unsafe"
	pb "vmCaller/iroha_protocol"
)

type IrohaAppState struct {
	commandExecutor unsafe.Pointer
	queryExecutor   unsafe.Pointer
}

// check IrohaAppState implements acmstate.ReaderWriter
var _ acmstate.ReaderWriter = &IrohaAppState{}

func NewIrohaAppState() *IrohaAppState {
	return &IrohaAppState{
		commandExecutor: unsafe.Pointer(nil),
		queryExecutor:   unsafe.Pointer(nil),
	}
}

func (ias *IrohaAppState) GetAccount(addr crypto.Address) (*acm.Account, error) {
	fmt.Println("GetAccount: " + addr.String())
	tiedAccExist, err := ias.getIrohaAccount(addr)
	if err != nil {
		fmt.Println("Error while getting Iroha account")
		return nil, err
	}

	if !tiedAccExist {
		// If Iroha does not have account — create it in Iroha
		err = ias.createIrohaEvmAccount(addr)
		if err != nil {
			fmt.Println("Error while creating Iroha tied account")
			return nil, err
		} else {
			// Return nil, but prepare tied account in Iroha
			err = ias.UpdateAccount(&acm.Account{Address: addr})
			return nil, err
		}

	} else {

		// Get data about account
		accountBytes, err := ias.getIrohaAccountDetail(addr, "EVM_marshalled_account_data")
		if err != nil {
			fmt.Println("Error during GetAccount, addr", addr.String())
		}
		account := &acm.Account{}
		err = account.Unmarshal(accountBytes)
		return account, err
	}
}

// mock
func (ias *IrohaAppState) GetMetadata(metahash acmstate.MetadataHash) (string, error) {
	fmt.Println("GetMetadata: metahash" + metahash.String())
	return "", nil
}

// mock
func (ias *IrohaAppState) SetMetadata(metahash acmstate.MetadataHash, metadata string) error {
	fmt.Println("SetMetadata: metahash" + metahash.String() + " metadata: " + metadata)
	return nil
}

func (ias *IrohaAppState) UpdateAccount(account *acm.Account) error {
	fmt.Println("UpdateAccount: " + account.String())
	if account == nil {
		return fmt.Errorf("UpdateAccount: got nil account")
	}

	marshalledData, err := account.Marshal()
	if err != nil {
		fmt.Println("Error during account marshalling")
		return err
	}

	err = ias.setIrohaAccountDetail(account.Address, "EVM_marshalled_account_data", marshalledData)

	return err
}

func (ias *IrohaAppState) RemoveAccount(address crypto.Address) error {
	fmt.Println("RemoveAccount: " + address.String())
	return nil
}

func (ias *IrohaAppState) GetStorage(addr crypto.Address, key binary.Word256) ([]byte, error) {
	// fmt.Printf("[GetStorage] Retrieving %s accountDetail for %s %x\n", addr.String(), key)
	fmt.Printf("[GetStorage] Retrieving accountDetail for account %s, key: %v, key.String(): %s\n",
		addr.String(), key, key.String())
	return ias.getIrohaAccountDetail(addr, hex.EncodeToString(key.Bytes()))
}

func (ias *IrohaAppState) SetStorage(addr crypto.Address, key binary.Word256, value []byte) error {
	fmt.Printf("[SetStorage]: addr.String(): %s, key (hex): %x, string(key): %s, key.String(): %s, string(value): %s\n",
		addr.String(), key, string(key.Bytes()), key.String(), string(value))
	return ias.setIrohaAccountDetail(addr, hex.EncodeToString(key.Bytes()), value)
}

/*
	Method for retrieving accounts assets balances
	Not part of ReaderWriter interface, hence type assertion required
*/
func (ias *IrohaAppState) GetBalance(addr []byte, asset binary.Word256) ([]byte, error) {
	assetBytes, _ := hex.DecodeString(hex.EncodeToString(asset.UnpadLeft()))
	assetID := string(assetBytes)
	fmt.Printf("[GetBalance] Retrieving balance for account %s, asset.String(): %s\n", string(addr), assetID)
	balances, err := ias.getIrohaAccountAssets(addr)
	if err != nil {
		return []byte{}, err
	}
	for _, v := range balances {
		if v.GetAssetId() == assetID {
			return []byte(v.GetBalance()), nil
		}
	}
	return []byte{}, nil
}

func (ias *IrohaAppState) TransferAsset(src []byte, dst []byte, amount []byte, asset binary.Word256) error {
	assetBytes, _ := hex.DecodeString(hex.EncodeToString(asset.UnpadLeft()))
	assetID := string(assetBytes)
	fmt.Printf("[TransferAsset] Transferring %s asset from %s to %s\n", assetID, string(src), string(dst))
	return ias.transferIrohaAsset(src, dst, amount, assetID)
}

func (ias *IrohaAppState) SetCommandExecutor(ce unsafe.Pointer) {
	ias.commandExecutor = ce
}

func (ias *IrohaAppState) SetQueryExecutor(qe unsafe.Pointer) {
	ias.queryExecutor = qe
}

/*
	Following functions are wrappers for Iroha commands and queries with use of
	commandExecutor or queryExecutor accordingly, and protobuf messages from iroha_protocol.
	In all cases returned error signs about a technical problem, not a logical one.
*/

// Helper function to store the evm account actual "parent" ID in AccountDetails
func (ias *IrohaAppState) SetParentID(addr crypto.Address, key string, value []byte) error {
	return ias.setIrohaAccountDetail(addr, key, value)
}

// Helper function to resolve EVM address into Iroha accountID
func (ias *IrohaAppState) fromEVMAddress(addr crypto.Address) ([]byte, error) {
	return ias.getIrohaAccountDetail(addr, "ParentID")
}

// -----------------------Iroha commands---------------------------------------

// Creates a tied account in Iroha (EVM address + @evm)
func (ias *IrohaAppState) createIrohaEvmAccount(addr crypto.Address) (err error) {
	// Send CreateAccount to Iroha
	command := &pb.Command{Command: &pb.Command_CreateAccount{
		CreateAccount: &pb.CreateAccount{AccountName: addr.String(), DomainId: "evm", PublicKey: fmt.Sprintf("%064s", addr.String())}}}
	commandResult, err := makeProtobufCmdAndExecute(ias.commandExecutor, command)
	if err != nil {
		return err
	}
	fmt.Print("Create Iroha account with address " + addr.String() + " result: ")
	fmt.Println(commandResult)
	if commandResult.error_code != 0 {
		return fmt.Errorf("Error while creating tied account in Iroha at addr " + addr.String())
	}

	return nil
}

// Sets key-value pair in storage of the tied Iroha account
func (ias *IrohaAppState) setIrohaAccountDetail(
	addr crypto.Address, key string, value []byte) (err error) {

	hexValue := hex.EncodeToString(value)
	// Send SetAccountDetail to Iroha
	command := &pb.Command{Command: &pb.Command_SetAccountDetail{&pb.SetAccountDetail{
		AccountId: addr.String() + "@evm", Key: key, Value: hexValue}}}
	commandResult, err := makeProtobufCmdAndExecute(ias.commandExecutor, command)
	if err != nil {
		return err
	}
	fmt.Println("Set Iroha account detail " + key + " with address " + addr.String() + " result:")
	fmt.Println(commandResult)
	if commandResult.error_code != 0 {
		return fmt.Errorf("Error while setting Iroha detail " + key + " at addr " + addr.String() +
			", value " + hexValue)
	}

	return nil
}

// Helper function to perform Iroha commands
func makeProtobufCmdAndExecute(
	cmdExecutor unsafe.Pointer, command *pb.Command) (res *C.struct_Iroha_CommandError, err error) {

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

// -----------------------Iroha queries---------------------------------------

// Queries Iroha about the tied account.
func (ias *IrohaAppState) getIrohaAccount(addr crypto.Address) (exist bool, err error) {
	query := &pb.Query{Payload: &pb.Query_Payload{
		Meta: &pb.QueryPayloadMeta{
			CreatedTime:      uint64(time.Now().UnixNano() / int64(time.Millisecond)),
			CreatorAccountId: "evm@evm",
			QueryCounter:     1},
		Query: &pb.Query_Payload_GetAccount{
			GetAccount: &pb.GetAccount{AccountId: addr.String() + "@evm"}}}}
	queryResponse, err := makeProtobufQueryAndExecute(ias.queryExecutor, query)
	if err != nil {
		return false, err
	}
	fmt.Println(queryResponse)
	switch response := queryResponse.Response.(type) {
	case *pb.QueryResponse_ErrorResponse:
		fmt.Println("QueryResponse_ErrorResponse getIrohaAccount for address " + addr.String())
		if response.ErrorResponse.Reason == pb.ErrorResponse_NO_ACCOUNT {
			// No errors, but requested account does not exist
			return false, nil
		}

		return false, fmt.Errorf("QueryResponse_ErrorResponse: code - %d, message - %v", response.ErrorResponse.ErrorCode, response.ErrorResponse.Message)
	case *pb.QueryResponse_AccountResponse:
		fmt.Println("Query result for address " + addr.String() + ": " + queryResponse.String())
		return true, nil
	default:
		return false, fmt.Errorf("wrong queryResponse for getIrohaAccount")
	}
}

// Queries Iroha about the tied account detail.
// Returns account detail
func (ias *IrohaAppState) getIrohaAccountDetail(addr crypto.Address, key string) (detail []byte, err error) {
	query := &pb.Query{Payload: &pb.Query_Payload{
		Meta: &pb.QueryPayloadMeta{
			CreatedTime:      uint64(time.Now().UnixNano() / int64(time.Millisecond)),
			CreatorAccountId: "evm@evm",
			QueryCounter:     1},
		Query: &pb.Query_Payload_GetAccountDetail{
			&pb.GetAccountDetail{
				OptAccountId: &pb.GetAccountDetail_AccountId{AccountId: addr.String() + "@evm"},
				OptKey:       &pb.GetAccountDetail_Key{Key: key}}}}}
	queryResponse, err := makeProtobufQueryAndExecute(ias.queryExecutor, query)
	if err != nil {
		return []byte{}, err
	}
	fmt.Println(queryResponse)
	switch response := queryResponse.Response.(type) {
	case *pb.QueryResponse_ErrorResponse:
		fmt.Println("QueryResponse_ErrorResponse getIrohaAccountDetail for address " + addr.String() + ", key " + key)
		if response.ErrorResponse.Reason == pb.ErrorResponse_NO_ACCOUNT_DETAIL {
			// No errors, but requested account detail does not exist
			return []byte{}, nil
		}

		return []byte{}, fmt.Errorf("QueryResponse_ErrorResponse: code - %d, message - %v", response.ErrorResponse.ErrorCode, response.ErrorResponse.Message)
	case *pb.QueryResponse_AccountDetailResponse:
		fmt.Println("Query details result for address " + addr.String() + ", key " + key + ": " + queryResponse.String())
		getAccDetail := queryResponse.GetAccountDetailResponse()
		accDetailAsBytes := []byte(getAccDetail.Detail)
		var detailResponse interface{}
		err = json.Unmarshal(accDetailAsBytes, &detailResponse)
		if err != nil {
			fmt.Println("Failed to unmarshal detail response")
			return []byte{}, err
		}

		// Some weird casts to get data from detail response
		// {"evm@evm":{key:value}}, where all data types are strings
		// {} if requested pair (author, detail)
		switch response := detailResponse.(type) {
		case map[string]interface{}:
			value, exist := response["evm@evm"]
			if !exist {
				return []byte{}, nil
			}
			return hex.DecodeString(value.(map[string]interface{})[key].(string))

		default:
			return []byte{}, fmt.Errorf("unexpected get_account_detail response type from Iroha")
		}

	default:
		return []byte{}, fmt.Errorf("wrong queryResponse for getIrohaAccountDetail")
	}
}

// Queries asset balance of an account
func (ias *IrohaAppState) getIrohaAccountAssets(addr []byte) ([]*pb.AccountAsset, error) {
	// accountID, err := ias.fromEVMAddress(addr)
	// fmt.Printf("[IrohaAppState::getIrohaAccountAssets] Parent account ID is: %s\n", accountID)
	// if err != nil {
	// 	return []*pb.AccountAsset{}, err
	// }
	accountID := string(addr)
	query := &pb.Query{Payload: &pb.Query_Payload{
		Meta: &pb.QueryPayloadMeta{
			CreatedTime:      uint64(time.Now().UnixNano() / int64(time.Millisecond)),
			CreatorAccountId: "evm@evm",
			QueryCounter:     1},
		Query: &pb.Query_Payload_GetAccountAssets{
			GetAccountAssets: &pb.GetAccountAssets{AccountId: string(accountID)}}}}
	queryResponse, err := makeProtobufQueryAndExecute(ias.queryExecutor, query)
	if err != nil {
		return []*pb.AccountAsset{}, err
	}
	fmt.Println(queryResponse)
	switch response := queryResponse.Response.(type) {
	case *pb.QueryResponse_ErrorResponse:
		fmt.Println("QueryResponse_ErrorResponse getAccountAssets for address " + string(addr))
		if response.ErrorResponse.Reason == pb.ErrorResponse_NO_ACCOUNT {
			// No errors, but requested account does not exist
			return []*pb.AccountAsset{}, nil
		}
		return []*pb.AccountAsset{}, fmt.Errorf("QueryResponse_ErrorResponse: code - %d, message - %v", response.ErrorResponse.ErrorCode, response.ErrorResponse.Message)
	case *pb.QueryResponse_AccountAssetsResponse:
		fmt.Println("Query result for address " + string(addr) + ": " + queryResponse.String())
		accountAssetsResponse := queryResponse.GetAccountAssetsResponse()
		return accountAssetsResponse.AccountAssets, nil
	default:
		return []*pb.AccountAsset{}, fmt.Errorf("wrong queryResponse for getIrohaAccountAssets")
	}
}

/*
	Method for transferring assets between accounts
	Not part of ReaderWriter interface, hence type assertion required
*/
func (ias *IrohaAppState) transferIrohaAsset(src []byte, dst []byte, amount []byte, asset string) error {
	command := &pb.Command{Command: &pb.Command_TransferAsset{
		TransferAsset: &pb.TransferAsset{
			SrcAccountId:  string(src),
			DestAccountId: string(dst),
			AssetId:       asset,
			Description:   "EVM asset transfer",
			Amount:        string(amount),
		}}}
	commandResult, err := makeProtobufCmdAndExecute(ias.commandExecutor, command)
	if err != nil {
		return err
	}
	fmt.Println(commandResult)
	if commandResult.error_code != 0 {
		return fmt.Errorf("Error occurred when transferring asset nominated in %s from %s to %s\n", asset, string(src), string(dst))
	}

	return nil
}

// Helper function to perform Iroha queries
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
		return fmt.Sprintf("Iroha_CommandError: code - %d, message - %s", res.error_code, C.GoString(res.error_extra))
	} else {
		return fmt.Sprintf("Iroha_CommandError: code %d", res.error_code)
	}
}
