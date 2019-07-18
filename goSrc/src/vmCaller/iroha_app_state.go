package main

import (
	"bytes"
	"fmt"
	"github.com/hyperledger/burrow/acm"
	"github.com/hyperledger/burrow/acm/acmstate"
	"github.com/hyperledger/burrow/binary"
	"github.com/hyperledger/burrow/crypto"
)

type IrohaAppState struct {
	accounts map[crypto.Address]*acm.Account
	storage  map[string][]byte
}

// check IrohaAppState implements acmstate.ReaderWriter
var _ acmstate.ReaderWriter = (*IrohaAppState)(nil)

func (ias *IrohaAppState) GetAccount(addr crypto.Address) (*acm.Account, error) {
	fmt.Println("GetAccount: " + addr.String())
	account := ias.accounts[addr]
	return account, nil
}

func (ias *IrohaAppState) UpdateAccount(account *acm.Account) error {
	fmt.Println("UpdateAccount: " + account.String())
	ias.accounts[account.GetAddress()] = account
	return nil
}

func (ias *IrohaAppState) RemoveAccount(address crypto.Address) error {
	fmt.Println("RemoveAccount: " + address.String())
	_, ok := ias.accounts[address]
	if !ok {
		panic(fmt.Sprintf("Invalid account addr: %s", address))
	} else {
		// Remove account
		delete(ias.accounts, address)
	}
	return nil
}

func (ias *IrohaAppState) GetStorage(addr crypto.Address, key binary.Word256) ([]byte, error) {
	fmt.Printf("GetStorage: " + addr.String() + " %x\n", key)
	_, ok := ias.accounts[addr]
	if !ok {
		panic(fmt.Sprintf("Invalid account addr: %s", addr))
	}

	value, ok := ias.storage[addr.String()+key.String()]
	if ok {
		return value, nil
	} else {
		return []byte{}, nil
	}
}

func (ias *IrohaAppState) SetStorage(addr crypto.Address, key binary.Word256, value []byte) error {
	fmt.Printf("SetStorage: " + addr.String() + " %x %x\n", key, value)
	_, ok := ias.accounts[addr]
	if !ok {
		fmt.Println("\n\n", ias.accountsDump())
		panic(fmt.Sprintf("Invalid account addr: %s", addr))
	}

	ias.storage[addr.String()+key.String()] = value
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