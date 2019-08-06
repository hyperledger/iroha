package main

// #cgo CFLAGS: -I ../../../irohad
// #cgo LDFLAGS: -Wl,-unresolved-symbols=ignore-all
// #include "ametsuchi/impl/proto_command_executor.h"
// #include "ametsuchi/impl/proto_specific_query_executor.h"
import "C"
import (
	"bytes"
	"fmt"
	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/burrow/acm"
	"github.com/hyperledger/burrow/acm/acmstate"
	"github.com/hyperledger/burrow/binary"
	"github.com/hyperledger/burrow/crypto"
	pb "iroha_protocol"
	"unsafe"
)

// Analogue of the following code, but without metadata:
// https://github.com/hyperledger/burrow/blob/develop/acm/acmstate/memory_state.go

type IrohaAppState struct {
	accounts map[crypto.Address]*acm.Account
	storage  map[crypto.Address]map[binary.Word256][]byte
	commandExecutor unsafe.Pointer
	queryExecutor unsafe.Pointer
}

// check IrohaAppState implements acmstate.ReaderWriter
var _ acmstate.ReaderWriter = &IrohaAppState{}

func NewIrohaAppState() *IrohaAppState {
	return &IrohaAppState{
		accounts: make(map[crypto.Address]*acm.Account),
		storage:  make(map[crypto.Address]map[binary.Word256][]byte),
	}
}

func (ias *IrohaAppState) GetAccount(addr crypto.Address) (*acm.Account, error) {
	fmt.Println("GetAccount: " + addr.String())
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
	storage, ok := ias.storage[addr]
	if !ok {
		return []byte{}, fmt.Errorf("could not find storage for account %s", addr)
	}
	value, ok := storage[key]
	if !ok {
		return []byte{}, fmt.Errorf("could not find key %x for account %s", key, addr)
	}
	return value, nil
}

func (ias *IrohaAppState) SetStorage(addr crypto.Address, key binary.Word256, value []byte) error {
	fmt.Printf("SetStorage: " + addr.String() + " %x %x\n", key, value)
	storage, ok := ias.storage[addr]
	if !ok {
		storage = make(map[binary.Word256][]byte)
		ias.storage[addr] = storage
	}
	storage[key] = value
	return nil
}

func (ias *IrohaAppState) accountsDump() string {
	buf := new(bytes.Buffer)
	fmt.Fprint(buf, "Dumping accounts...", "\n")
	for _, acc := range ias.accounts {
		fmt.Fprint(buf, acc.GetAddress().String(), "\n")
	}
	return buf.String()
}

// Create a tied account into Iroha (EVM address + @evm)
func (ias *IrohaAppState) createIrohaAccount(addr crypto.Address) (err error) {
	// command example
	command := &pb.Command{Command: &pb.Command_CreateAccount{CreateAccount: &pb.CreateAccount{AccountName: addr.String(), DomainId: "evm"}}}
	fmt.Println(proto.MarshalTextString(command))
	out, err := proto.Marshal(command)
	if err != nil {
		fmt.Println(err)
	}
	cOut := C.CBytes(out)
	commandResult := C.Iroha_ProtoCommandExecutorExecute(ias.commandExecutor, cOut, C.int(len(out)))
	fmt.Println("Create Iroha account with address result " + addr.String())
	fmt.Println(commandResult)
	return err
}

// Query Iroha about the tied account
func (ias *IrohaAppState) getIrohaAccount(addr crypto.Address) (account *acm.Account, err error) {
	// query example
	query := &pb.Query{Payload: &pb.Query_Payload{Query: &pb.Query_Payload_GetAccount{GetAccount: &pb.GetAccount{AccountId: addr.String() + "@evm"}}}}
	fmt.Println(proto.MarshalTextString(query))
	out, err := proto.Marshal(query)
	if err != nil {
		fmt.Println(err)
	}
	cOut := C.CBytes(out)
	queryResult := C.Iroha_ProtoSpecificQueryExecutorExecute(ias.queryExecutor, cOut, C.int(len(out)))
	fmt.Println(queryResult)
	out = C.GoBytes(queryResult.data, queryResult.size)
	queryResponse := &pb.QueryResponse{}
	err = proto.Unmarshal(out, queryResponse)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	fmt.Println("Query result for address " + addr.String() + " " + queryResponse.String())

	// not sure if this is the correct initialisation
	return &acm.Account{Address:addr}, nil
}
