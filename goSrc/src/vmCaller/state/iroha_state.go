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

func MakeIrohaCharBuffer(data string) *C.struct_Iroha_CharBuffer {
  return &C.struct_Iroha_CharBuffer{
    data: C.CString(data),
    size: C.ulonglong(len(data)),
  }
}

func (buf *C.struct_Iroha_CharBuffer) free() {
  C.free(unsafe.Pointer(buf.data))
}

type Iroha_CharBufferArray_Wrapper struct {
  charBuffers []C.struct_Iroha_CharBuffer
	carray *C.struct_Iroha_CharBufferArray
}

func MakeIrohaCharBufferArray(data []binary.Word256) *Iroha_CharBufferArray_Wrapper {
  array := make([]C.struct_Iroha_CharBuffer, len(data))
  for idx, el := range data {
    array[idx] = *MakeIrohaCharBuffer(hex.EncodeToString(el.Bytes()))
  }
  return &Iroha_CharBufferArray_Wrapper{
    array,
    &C.struct_Iroha_CharBufferArray{
      data: &array[0],
      size: C.ulonglong(len(data)),
    },
  }
}

func (arr *Iroha_CharBufferArray_Wrapper) free() {
  for _, el := range arr.charBuffers {
    C.free(unsafe.Pointer(el.data))
  }
}

func (st *IrohaState) GetAccount(address crypto.Address) (*acm.Account, error) {
	caddress := MakeIrohaCharBuffer(address.String())
	result := C.Iroha_GetAccount(st.Storage, *caddress)
	caddress.free()

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

	caddress := MakeIrohaCharBuffer(account.GetAddress().String())
	caccount := MakeIrohaCharBuffer(hex.EncodeToString(marshalledData))
	result := C.Iroha_UpdateAccount(st.Storage, *caddress, *caccount)
	caddress.free()
	caccount.free()

	if result.error != nil {
		error := C.GoString(result.error)
		C.free(unsafe.Pointer(result.error))
		return errors.New(error)
	}

	return nil
}

func (st *IrohaState) RemoveAccount(address crypto.Address) error {
	caddress := MakeIrohaCharBuffer(address.String())
	result := C.Iroha_RemoveAccount(st.Storage, *caddress)
	caddress.free()

	if result.error != nil {
		error := C.GoString(result.error)
		C.free(unsafe.Pointer(result.error))
		return errors.New(error)
	}

	return nil
}

func (st *IrohaState) GetStorage(address crypto.Address, key binary.Word256) ([]byte, error) {
	caddress := MakeIrohaCharBuffer(address.String())
	ckey := MakeIrohaCharBuffer(hex.EncodeToString(key.Bytes()))
	result := C.Iroha_GetStorage(st.Storage, *caddress, *ckey)
	caddress.free()
	ckey.free()

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
	caddress := MakeIrohaCharBuffer(address.String())
	ckey := MakeIrohaCharBuffer(hex.EncodeToString(key.Bytes()))
	cvalue := MakeIrohaCharBuffer(hex.EncodeToString(value))
	result := C.Iroha_SetStorage(st.Storage, *caddress, *ckey, *cvalue)
	caddress.free()
	ckey.free()
	cvalue.free()

	if result.error != nil {
		error := C.GoString(result.error)
		C.free(unsafe.Pointer(result.error))
		return errors.New(error)
	}

	return nil
}

func (st *IrohaState) StoreTxReceipt(address crypto.Address, hex_data []byte, topics []binary.Word256) error {
	caddress := MakeIrohaCharBuffer(address.String())
	cdata := MakeIrohaCharBuffer(hex.EncodeToString(hex_data))
	ctopics := MakeIrohaCharBufferArray(topics)
	result := C.Iroha_StoreTxReceipt(st.Storage, *caddress, *cdata, *ctopics.carray)
	caddress.free()
	cdata.free()
	ctopics.free()

	if result.error != nil {
		error := C.GoString(result.error)
		C.free(unsafe.Pointer(result.error))
		return errors.New(error)
	}

	return nil
}
