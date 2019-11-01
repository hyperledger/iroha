package main

import (
	"bytes"
	"fmt"
	"github.com/hyperledger/burrow/acm"
	"github.com/hyperledger/burrow/acm/acmstate"
	"github.com/hyperledger/burrow/binary"
	"github.com/hyperledger/burrow/crypto"
)

// Analogue of the following code, but without metadata:
// https://github.com/hyperledger/burrow/blob/develop/acm/acmstate/memory_state.go

type IrohaAppState struct {
	accounts map[crypto.Address]*acm.Account
	storage  map[crypto.Address]map[binary.Word256][]byte
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
