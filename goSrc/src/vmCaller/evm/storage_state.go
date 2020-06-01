package evm

import "C"
import (
	"unsafe"

	"vmCaller/iroha"

	"github.com/hyperledger/burrow/acm/acmstate"
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
