package iroha

// #cgo CFLAGS: -I ../../../../irohad
// #cgo LDFLAGS: -Wl,-unresolved-symbols=ignore-all
// #include <stdlib.h>
// #include "ametsuchi/impl/burrow_storage.h"
import "C"
import (
	"encoding/hex"
	"unsafe"

	"github.com/hyperledger/burrow/acm"
	"github.com/hyperledger/burrow/binary"
	"github.com/hyperledger/burrow/crypto"
	"github.com/hyperledger/burrow/execution/errors"
)

type IrohaStorage struct {
	storage unsafe.Pointer
}

func NewIrohaStorage(storage unsafe.Pointer) *IrohaStorage {
	return &IrohaStorage{
		storage: storage,
	}
}

func (st *IrohaStorage) GetAccount(address crypto.Address) (*acm.Account, error) {
	cAddress := MakeIrohaCharBuffer(address.String())
	result := C.Iroha_GetAccount(st.storage, *cAddress)
	cAddress.free()

	if result.error != nil {
		err := errors.Errorf(errors.Codes.ExecutionReverted, C.GoString(result.error))
		C.free(unsafe.Pointer(result.error))
		return nil, err
	}

	if result.result == nil {
		return nil, nil
	}

	accountBytes, err := hex.DecodeString(C.GoString(result.result))
	C.free(unsafe.Pointer(result.result))
	if err != nil {
		return nil, err
	}

	account := &acm.Account{}
	err = account.Unmarshal(accountBytes)

	if err == nil {
		// Unmarshalling of account data replaces account.EVMCode == nil with an empty slice []byte{}
		// Hence this workaround to revert that and make native.InitCode work
		if account.EVMCode != nil && len(account.EVMCode) == 0 {
			account.EVMCode = nil
		}
		if account.WASMCode != nil && len(account.WASMCode) == 0 {
			account.WASMCode = nil
		}
	}

	return account, err
}

func (st *IrohaStorage) UpdateAccount(account *acm.Account) error {
	if account == nil {
		return errors.Errorf(errors.Codes.IllegalWrite, "UpdateAccount passed nil account")
	}

	marshalledData, err := account.Marshal()
	if err != nil {
		return err
	}

	cAddress := MakeIrohaCharBuffer(account.GetAddress().String())
	cAccount := MakeIrohaCharBuffer(hex.EncodeToString(marshalledData))
	result := C.Iroha_UpdateAccount(st.storage, *cAddress, *cAccount)
	cAddress.free()
	cAccount.free()

	if result.error != nil {
		err := errors.Errorf(errors.Codes.ExecutionReverted, C.GoString(result.error))
		C.free(unsafe.Pointer(result.error))
		return err
	}

	return nil
}

func (st *IrohaStorage) RemoveAccount(address crypto.Address) error {
	cAddress := MakeIrohaCharBuffer(address.String())
	result := C.Iroha_RemoveAccount(st.storage, *cAddress)
	cAddress.free()

	if result.error != nil {
		err := errors.Errorf(errors.Codes.ExecutionReverted, C.GoString(result.error))
		C.free(unsafe.Pointer(result.error))
		return err
	}

	return nil
}

func (st *IrohaStorage) GetStorage(address crypto.Address, key binary.Word256) ([]byte, error) {
	cAddress := MakeIrohaCharBuffer(address.String())
	cKey := MakeIrohaCharBuffer(hex.EncodeToString(key.Bytes()))
	result := C.Iroha_GetStorage(st.storage, *cAddress, *cKey)
	cAddress.free()
	cKey.free()

	if result.error != nil {
		err := errors.Errorf(errors.Codes.ExecutionReverted, C.GoString(result.error))
		C.free(unsafe.Pointer(result.error))
		return nil, err
	}

	if result.result == nil {
		return nil, nil
	}

	valueHex := C.GoString(result.result)
	C.free(unsafe.Pointer(result.result))

	return hex.DecodeString(valueHex)
}

func (st *IrohaStorage) SetStorage(address crypto.Address, key binary.Word256, value []byte) error {
	cAddress := MakeIrohaCharBuffer(address.String())
	cKey := MakeIrohaCharBuffer(hex.EncodeToString(key.Bytes()))
	cValue := MakeIrohaCharBuffer(hex.EncodeToString(value))
	result := C.Iroha_SetStorage(st.storage, *cAddress, *cKey, *cValue)
	cAddress.free()
	cKey.free()
	cValue.free()

	if result.error != nil {
		err := errors.Errorf(errors.Codes.ExecutionReverted, C.GoString(result.error))
		C.free(unsafe.Pointer(result.error))
		return err
	}

	return nil
}

func (st *IrohaStorage) StoreTxReceipt(address crypto.Address, hex_data []byte, topics []binary.Word256) error {
	cAddress := MakeIrohaCharBuffer(address.String())
	cData := MakeIrohaCharBuffer(hex.EncodeToString(hex_data))
	cTopics := MakeIrohaCharBufferArray(topics)
	result := C.Iroha_StoreTxReceipt(st.storage, *cAddress, *cData, *cTopics.cArray)
	cAddress.free()
	cData.free()
	cTopics.free()

	if result.error != nil {
		err := errors.Errorf(errors.Codes.ExecutionReverted, C.GoString(result.error))
		C.free(unsafe.Pointer(result.error))
		return err
	}

	return nil
}
