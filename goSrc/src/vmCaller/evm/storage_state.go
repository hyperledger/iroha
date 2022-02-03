package evm

import "C"
import (
	"unsafe"

	"vmCaller/iroha"

	"github.com/hyperledger/burrow/acm"
	"github.com/hyperledger/burrow/acm/acmstate"
	"github.com/hyperledger/burrow/binary"
	"github.com/hyperledger/burrow/crypto"
)

type IrohaState struct {
	iroha.IrohaStorage
}

// check that IrohaState implements acmstate.ReaderWriter
var _ acmstate.ReaderWriter = &IrohaState{}

func NewIrohaState(storage unsafe.Pointer) *IrohaState {
	return &IrohaState{
		*iroha.NewIrohaStorage(storage),
	}
}

// mock
func (st *IrohaState) GetMetadata(metahash acmstate.MetadataHash) (string, error) {
	return "", nil
}

// mock
func (st *IrohaState) SetMetadata(metahash acmstate.MetadataHash, metadata string) error {
	return nil
}

// mock
func (st *IrohaState) GetAccountStats() acmstate.AccountStats {
	return acmstate.AccountStats{}
}

// mock
func (st *IrohaState) IterateAccounts(func(*acm.Account) error) error {
	return nil
}

// mock
func (st *IrohaState) IterateStorage(address crypto.Address, consumer func(key binary.Word256, value []byte) error) (err error) {
	return nil
}
