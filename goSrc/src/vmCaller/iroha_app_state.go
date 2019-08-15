package main

// #cgo CFLAGS: -I ../../../irohad
// #cgo LDFLAGS: -Wl,-unresolved-symbols=ignore-all
// #include "ametsuchi/impl/proto_command_executor.h"
// #include "ametsuchi/impl/proto_specific_query_executor.h"
import "C"
import (
	"encoding/hex"
	"fmt"
	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/burrow/acm"
	"github.com/hyperledger/burrow/acm/acmstate"
	"github.com/hyperledger/burrow/binary"
	"github.com/hyperledger/burrow/crypto"
	pb "vmCaller/iroha_protocol"
	"unsafe"
)

// Analogue of the following code, but without metadata:
// https://github.com/hyperledger/burrow/blob/develop/acm/acmstate/memory_state.go

type IrohaAppState struct {
	accounts map[crypto.Address]*acm.Account
	commandExecutor unsafe.Pointer
	queryExecutor   unsafe.Pointer
}

// check IrohaAppState implements acmstate.ReaderWriter
var _ acmstate.ReaderWriter = &IrohaAppState{}

func NewIrohaAppState() *IrohaAppState {
	return &IrohaAppState{
		accounts: make(map[crypto.Address]*acm.Account),
		commandExecutor: unsafe.Pointer(nil),
		queryExecutor  : unsafe.Pointer(nil),
	}
}

func (ias *IrohaAppState) GetAccount(addr crypto.Address) (*acm.Account, error) {
	fmt.Println("GetAccount: " + addr.String())
	if ias.accounts[addr] == nil {
		// If not in cache — request Iroha.
		tiedAccExist, err := ias.getIrohaAccount(addr)
		if err != nil {
			fmt.Println("Error while getting Iroha account")
			return nil, err
		}
		if ! tiedAccExist {
			// If Iroha does not have account — create it in Iroha
			err = ias.createIrohaEvmAccount(addr)
			if err != nil {
				fmt.Println("Error while creating Iroha tied account")
				return nil, err
			}
		}
	}
	return ias.accounts[addr], nil
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
		return fmt.Errorf("UpdateAccount passed nil account in MemoryState")
	}
	ias.accounts[account.GetAddress()] = account
	return nil
}

func (ias *IrohaAppState) RemoveAccount(address crypto.Address) error {
	fmt.Println("RemoveAccount: " + address.String())
	delete(ias.accounts, address)
	return nil
}

func (ias *IrohaAppState) GetStorage(addr crypto.Address, key binary.Word256) ([]byte, error) {
	fmt.Printf("GetStorage: " + addr.String() + " %x\n", key)
	return ias.getIrohaAccountDetail(addr, key)
}

func (ias *IrohaAppState) SetStorage(addr crypto.Address, key binary.Word256, value []byte) error {
	fmt.Printf("SetStorage: " + addr.String() + " %x %x\n", key, value)
	return ias.setIrohaAccountDetail(addr, key, value)
}

/*
	Following functions are wrappers for Iroha commands and queries with use of
	commandExecutor or queryExecutor accordingly, and protobuf messages from iroha_protocol.
	In all cases returned error signs about a technical problem, not a logical one.
*/

// -----------------------Iroha commands---------------------------------------

// Creates a tied account in Iroha (EVM address + @evm)
func (ias *IrohaAppState) createIrohaEvmAccount(addr crypto.Address) (err error) {
	// Send CreateAccount to Iroha
	command := &pb.Command{Command: &pb.Command_CreateAccount{
		CreateAccount: &pb.CreateAccount{AccountName: addr.String() + "@evm", DomainId: "evm"}}}
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
	addr crypto.Address, key binary.Word256, value []byte) (err error) {

	hexKey   := hex.EncodeToString(key.Bytes())
	hexValue := hex.EncodeToString(value)
	// Send SetAccountDetail to Iroha
	command := &pb.Command{Command: &pb.Command_SetAccountDetail{&pb.SetAccountDetail{
		AccountId: addr.String() + "@evm", Key: hexKey, Value: hexValue}}}
	commandResult, err := makeProtobufCmdAndExecute(ias.commandExecutor, command)
	if err != nil {
		return err
	}
	fmt.Println("Set Iroha account detail " + hexKey + " with address " + addr.String() + " result:")
	fmt.Println(commandResult)
	if commandResult.error_code != 0 {
		return fmt.Errorf("Error while setting Iroha detail " + hexKey + " at addr " + addr.String() +
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
	commandResult := C.Iroha_ProtoCommandExecutorExecute(cmdExecutor, cOut, C.int(len(out)))
	return &commandResult, nil
}

// -----------------------Iroha queries---------------------------------------

// Queries Iroha about the tied account.
func (ias *IrohaAppState) getIrohaAccount(addr crypto.Address) (exist bool, err error) {
	query := &pb.Query{Payload: &pb.Query_Payload{Query: &pb.Query_Payload_GetAccount{
		GetAccount: &pb.GetAccount{AccountId: addr.String() + "@evm"}}}}
	queryResponse, err := makeProtobufQueryAndExecute(ias.queryExecutor, query)
	if err != nil {
		return false, err
	}
	switch queryResponse.Response.(type) {
	case *pb.QueryResponse_ErrorResponse:
		fmt.Println("QueryResponse_ErrorResponse getIrohaAccount for address " + addr.String())
		// TODO (IvanTyulyandin):
		// check if "no account" error returned

		// No errors, but requested account does not exist
		return false, nil
	case *pb.QueryResponse_AccountResponse:
		fmt.Println("Query result for address " + addr.String() + ": " + queryResponse.String())
		return true, nil
	default:
		panic("Wrong queryResponce for getIrohaAccount")
	}
}

// Queries Iroha about the tied account detail.
// Returns account detail
func (ias *IrohaAppState) getIrohaAccountDetail(addr crypto.Address, key binary.Word256) (detail []byte, err error) {
	hexKey := hex.EncodeToString(key.Bytes())
	query := &pb.Query{Payload: &pb.Query_Payload{Query: &pb.Query_Payload_GetAccountDetail{
		&pb.GetAccountDetail{
			OptAccountId: &pb.GetAccountDetail_AccountId {AccountId: addr.String() + "@evm"},
			OptKey      : &pb.GetAccountDetail_Key       {Key      : hexKey}}}}}
	queryResponse, err := makeProtobufQueryAndExecute(ias.queryExecutor, query)
	if err != nil {
		return []byte{}, err
	}
	switch queryResponse.Response.(type) {
	case *pb.QueryResponse_ErrorResponse:
		fmt.Println("QueryResponse_ErrorResponse getIrohaAccountDetail for address " + addr.String() + ", key " + hexKey)
		// TODO (IvanTyulyandin):
		// check if "no account detail" error returned

		// No errors, but requested account detail does not exist
		return []byte{}, nil
	case *pb.QueryResponse_AccountDetailResponse:
		fmt.Println("Query details result for address " + addr.String() + ", key " + hexKey + ": " + queryResponse.String())
		getAccDetail := queryResponse.GetAccountDetailResponse()
		return hex.DecodeString(getAccDetail.Detail)
	default:
		panic("Wrong queryResponce for getIrohaAccountDetail")
	}
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
