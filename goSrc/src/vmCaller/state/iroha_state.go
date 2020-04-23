package state

// #cgo CFLAGS: -I ../../../../irohad
// #cgo LDFLAGS: -Wl,-unresolved-symbols=ignore-all
// #include <stdlib.h>
// #include "ametsuchi/impl/burrow_storage.h"
import "C"
import (
	"encoding/hex"
	"errors"
	"fmt"
	"unsafe"

	"github.com/hyperledger/burrow/acm"
	"github.com/hyperledger/burrow/acm/acmstate"
	"github.com/hyperledger/burrow/binary"
	"github.com/hyperledger/burrow/crypto"
	berrors "github.com/hyperledger/burrow/execution/errors"
)

type IrohaState struct {
	Storage unsafe.Pointer
}

// check that IrohaState implements acmstate.ReaderWriter
var _ acmstate.ReaderWriter = &IrohaState{}

func NewIrohaState(storage unsafe.Pointer) *IrohaState {
	return &IrohaState{
		Storage: storage,
	}
}

func (st *IrohaState) GetAccount(address crypto.Address) (*acm.Account, error) {
	caddress := C.CString(address.String())
	result := C.Iroha_GetAccount(st.Storage, caddress)
	C.free(unsafe.Pointer(caddress))

	if result.error != nil {
		error := C.GoString(result.error)
		C.free(unsafe.Pointer(result.error))
		return nil, errors.New(error)
	}

	accountBytes, err := hex.DecodeString(C.GoString(result.result))
	C.free(unsafe.Pointer(result.result))
	if err != nil {
		return nil, err
	}

	account := &acm.Account{}
	err = account.Unmarshal(accountBytes)

	return account, err
}

// mock
func (st *IrohaState) GetMetadata(metahash acmstate.MetadataHash) (string, error) {
	fmt.Printf("[GetMetadata] metahash: %s\n", metahash.String())
	return "", nil
}

// mock
func (st *IrohaState) SetMetadata(metahash acmstate.MetadataHash, metadata string) error {
	fmt.Printf("[SetMetadata] metahash: %s, metadata: %s\n", metahash.String(), metadata)
	return nil
}

func (st *IrohaState) UpdateAccount(account *acm.Account) error {
	if account == nil {
		return berrors.Errorf(berrors.Codes.IllegalWrite, "UpdateAccount passed nil account in MemoryState")
	}

	marshalledData, err := account.Marshal()
	if err != nil {
		return err
	}

	caddress := C.CString(account.GetAddress().String())
	caccount := C.CString(hex.EncodeToString(marshalledData))
	result := C.Iroha_UpdateAccount(st.Storage, caddress, caccount)
	C.free(unsafe.Pointer(caddress))
	C.free(unsafe.Pointer(caccount))

	if result.error != nil {
		error := C.GoString(result.error)
		C.free(unsafe.Pointer(result.error))
		return errors.New(error)
	}

	return nil
}

func (st *IrohaState) RemoveAccount(address crypto.Address) error {
	caddress := C.CString(address.String())
	result := C.Iroha_RemoveAccount(st.Storage, caddress)
	C.free(unsafe.Pointer(caddress))

	if result.error != nil {
		error := C.GoString(result.error)
		C.free(unsafe.Pointer(result.error))
		return errors.New(error)
	}

	return nil
}

func (st *IrohaState) GetStorage(address crypto.Address, key binary.Word256) ([]byte, error) {
	caddress := C.CString(address.String())
	ckey := C.CString(hex.EncodeToString(key.Bytes()))
	result := C.Iroha_GetStorage(st.Storage, caddress, ckey)
	C.free(unsafe.Pointer(caddress))
	C.free(unsafe.Pointer(ckey))

	if result.error != nil {
		error := C.GoString(result.error)
		C.free(unsafe.Pointer(result.error))
		return nil, errors.New(error)
	}

	if result.result == nil {
		return nil, nil
	}

	valueHex := C.GoString(result.result)
	C.free(unsafe.Pointer(result.result))

	return hex.DecodeString(valueHex)
}

func (st *IrohaState) SetStorage(address crypto.Address, key binary.Word256, value []byte) error {
	caddress := C.CString(address.String())
	ckey := C.CString(hex.EncodeToString(key.Bytes()))
	cvalue := C.CString(hex.EncodeToString(value))
	result := C.Iroha_SetStorage(st.Storage, caddress, ckey, cvalue)
	C.free(unsafe.Pointer(caddress))
	C.free(unsafe.Pointer(ckey))
	C.free(unsafe.Pointer(cvalue))

	if result.error != nil {
		error := C.GoString(result.error)
		C.free(unsafe.Pointer(result.error))
		return errors.New(error)
	}

	return nil
}
