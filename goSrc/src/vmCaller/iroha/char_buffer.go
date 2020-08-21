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

	"github.com/hyperledger/burrow/binary"
)

func MakeIrohaCharBuffer(data string) *C.Iroha_CharBuffer {
	return &C.Iroha_CharBuffer{
		data: C.CString(data),
		size: C.ulonglong(len(data)),
	}
}

func (buf *C.Iroha_CharBuffer) free() {
	C.free(unsafe.Pointer(buf.data))
	buf.data = nil // not really needed but may save some hair on head
}

func (buf *C.Iroha_CharBuffer) toStringAndRelease() *string {
	if buf.data == nil {
		return nil
	}
	defer buf.free()
	result := C.GoStringN(buf.data, C.int(buf.size))
	return &result
}

type Iroha_CharBufferArray_Wrapper struct {
	charBuffers []C.Iroha_CharBuffer
	cArray      *C.Iroha_CharBufferArray
}

func MakeIrohaCharBufferArray(data []binary.Word256) *Iroha_CharBufferArray_Wrapper {
	array := make([]C.Iroha_CharBuffer, len(data))
	for idx, el := range data {
		array[idx] = *MakeIrohaCharBuffer(hex.EncodeToString(el.Bytes()))
	}
	return &Iroha_CharBufferArray_Wrapper{
		array,
		&C.Iroha_CharBufferArray{
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
