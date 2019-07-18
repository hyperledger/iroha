package main

// #cgo CFLAGS: -I ../../../irohad
// #cgo LDFLAGS: -Wl,-unresolved-symbols=ignore-all
// #include "ametsuchi/impl/proto_command_executor.h"
import "C"
import "unsafe"
import (
	"fmt"
	"github.com/go-kit/kit/log"
	"github.com/hyperledger/burrow/acm"
	"github.com/hyperledger/burrow/binary"
	"github.com/hyperledger/burrow/crypto"
	"github.com/hyperledger/burrow/execution/evm"
	"github.com/hyperledger/burrow/logging"
	"github.com/tmthrgd/go-hex"
	"golang.org/x/crypto/ripemd160"
	"os"
	"strconv"
)
// import "github.com/golang/protobuf/proto"
// import pb "iroha_protocol"

func newAppState() *IrohaAppState {
	return &IrohaAppState{
		accounts: make(map[crypto.Address]*acm.Account),
		storage:  make(map[string][]byte),
	}
}

func newParams() evm.Params {
	return evm.Params{
		BlockHeight: 0,
		BlockTime:   0,
		GasLimit:    0,
	}
}

// toEVMaddress converts any string to EVM address
func toEVMaddress(name string) crypto.Address {
	hasher := ripemd160.New()
	hasher.Write([]byte(name))
	return crypto.MustAddressFromBytes(hasher.Sum(nil))
}

func blockHashGetter(height uint64) []byte {
	return binary.LeftPadWord256([]byte(fmt.Sprintf("block_hash_%d", height))).Bytes()
}

func newLogger() *logging.Logger {
	return &logging.Logger{
		Info:   log.NewLogfmtLogger(os.Stdout),
		Trace:  log.NewLogfmtLogger(os.Stdout),
		Output: new(log.SwapLogger),
	}
}

var appState = newAppState()
var logger = newLogger()
var ourVm = evm.NewVM(newParams(), crypto.ZeroAddress, nil, logger)
var evmState = evm.NewState(appState, blockHashGetter)

//export VmCall
func VmCall(code, input, caller, callee *C.char, executor unsafe.Pointer) (*C.char, bool) {
	// command := &pb.Command{Command: &pb.Command_CreateAccount{CreateAccount: &pb.CreateAccount{AccountName: "admin", DomainId: "test"}}}
	// fmt.Println(proto.MarshalTextString(command))
	// out, err := proto.Marshal(command)
	// if err != nil {
	// 	fmt.Println(err)
	// }
	// cOut := C.CBytes(out)
	// result := C.Iroha_ProtoCommandExecutorExecute(executor, cOut, C.int(len(out)))
	// fmt.Println(result)

	// Convert string into EVM address
	account1 := toEVMaddress(C.GoString(caller))

	// if callee is empty -> new contract creation
	goCallee := C.GoString(callee)
	account2 := crypto.Address{}

	if goCallee != "" {
		// take this assignment from
		// https://github.com/hyperledger/sawtooth-seth/blob/master/processor/src/seth_tp/handler/handler.go#L159
		account2 = account1
	}

	var gas uint64 = 1000000
	goByteCode := hex.MustDecodeString(C.GoString(code))
	goInput := hex.MustDecodeString(C.GoString(input))
	output, err := ourVm.Call(evmState, evm.NewNoopEventSink(), account1, account2,
		goByteCode, goInput, 0, &gas)

	if err := evmState.Sync(); err != nil {
		panic("Sync error")
	}
	// Transform output data to a string value.
	// It is a problem to convert []byte, which contains 0 byte inside, to C string.
	// Conversion to C.CString will cut all data after the 0 byte.
	res := ""
	for _, dataAsInt := range output {

		// change base to hex
		tmp := strconv.FormatInt(int64(dataAsInt), 16)

		// save bytecode structure, where hex value f should be 0f, and so on
		if len(tmp) < 2 {
			// len 1 at least after conversion from variable output
			tmp = "0" + tmp
		}
		res += tmp
	}

	if err == nil {
		return C.CString(res), true
	} else {
		fmt.Println(err)
		fmt.Println("NOT NIL")
		return C.CString(res), false
	}
}


func main() {}

