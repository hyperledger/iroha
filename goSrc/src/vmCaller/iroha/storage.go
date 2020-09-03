package iroha

// #cgo CFLAGS: -I ../../../../irohad
// #cgo linux LDFLAGS: -Wl,-unresolved-symbols=ignore-all
// #cgo darwin LDFLAGS: -Wl,-undefined,dynamic_lookup
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

func handleIrohaCallResult(result C.Iroha_Result) (*string, error) {
	switch result.which {
	case C.Iroha_Result_Type_Value:
		return result.data.toStringAndRelease(), nil
	case C.Iroha_Result_Type_Error:
		err_str := result.data.toStringAndRelease()
		if err_str != nil {
			return nil, errors.Errorf(errors.Codes.ExecutionReverted, *err_str)
		}
	}
	return nil, errors.Errorf(errors.Codes.ExecutionReverted, "unknown error")
}

func (st *IrohaStorage) GetAccount(address crypto.Address) (*acm.Account, error) {
	cAddress := MakeIrohaCharBuffer(address.String())
	defer cAddress.free()
	accountBytesHex, err := handleIrohaCallResult(C.Iroha_GetAccount(st.storage, *cAddress))

	if err != nil {
		return nil, err
	}

	if accountBytesHex == nil {
		return nil, nil
	}

	accountBytes, err := hex.DecodeString(*accountBytesHex)
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
	defer cAddress.free()
	cAccount := MakeIrohaCharBuffer(hex.EncodeToString(marshalledData))
	defer cAccount.free()
	_, err = handleIrohaCallResult(C.Iroha_UpdateAccount(st.storage, *cAddress, *cAccount))

	if err != nil {
		return err
	}

	return nil
}

func (st *IrohaStorage) RemoveAccount(address crypto.Address) error {
	cAddress := MakeIrohaCharBuffer(address.String())
	defer cAddress.free()
	_, err := handleIrohaCallResult(C.Iroha_RemoveAccount(st.storage, *cAddress))

	if err != nil {
		return err
	}

	return nil
}

func (st *IrohaStorage) GetStorage(address crypto.Address, key binary.Word256) ([]byte, error) {
	cAddress := MakeIrohaCharBuffer(address.String())
	defer cAddress.free()
	cKey := MakeIrohaCharBuffer(hex.EncodeToString(key.Bytes()))
	defer cKey.free()
	valueHex, err := handleIrohaCallResult(C.Iroha_GetStorage(st.storage, *cAddress, *cKey))

	if err != nil {
		return nil, err
	}

	if valueHex == nil {
		return nil, nil
	}

	return hex.DecodeString(*valueHex)
}

func (st *IrohaStorage) SetStorage(address crypto.Address, key binary.Word256, value []byte) error {
	cAddress := MakeIrohaCharBuffer(address.String())
	defer cAddress.free()
	cKey := MakeIrohaCharBuffer(hex.EncodeToString(key.Bytes()))
	defer cKey.free()
	cValue := MakeIrohaCharBuffer(hex.EncodeToString(value))
	defer cValue.free()
	_, err := handleIrohaCallResult(C.Iroha_SetStorage(st.storage, *cAddress, *cKey, *cValue))

	if err != nil {
		return err
	}

	return nil
}

func (st *IrohaStorage) StoreTxReceipt(address crypto.Address, hex_data []byte, topics []binary.Word256) error {
	cAddress := MakeIrohaCharBuffer(address.String())
	defer cAddress.free()
	cData := MakeIrohaCharBuffer(hex.EncodeToString(hex_data))
	defer cData.free()
	cTopics := MakeIrohaCharBufferArray(topics)
	defer cTopics.free()
	_, err := handleIrohaCallResult(C.Iroha_StoreLog(st.storage, *cAddress, *cData, *cTopics.cArray))

	if err != nil {
		return err
	}

	return nil
}
