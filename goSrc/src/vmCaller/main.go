package main

// #cgo CFLAGS: -I ../../../irohad
// #cgo LDFLAGS: -Wl,-unresolved-symbols=ignore-all
// #include "ametsuchi/impl/proto_command_executor.h"
// #include "ametsuchi/impl/proto_query_executor.h"
import "C"
import "unsafe"
import (
	"fmt"
	"github.com/hyperledger/burrow/binary"
	"github.com/hyperledger/burrow/crypto"
	"github.com/hyperledger/burrow/execution/evm"
	"github.com/hyperledger/burrow/logging"
	"github.com/tmthrgd/go-hex"
	"golang.org/x/crypto/ripemd160"
	"strconv"
)
// import "github.com/golang/protobuf/proto"
// import pb "iroha_protocol"

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

// Real application state
var appState = NewIrohaAppState()
// EVM instance
var ourVm = evm.NewVM(newParams(), crypto.ZeroAddress, nil, logging.NewNoopLogger())
// EVM cache. Should be synced with real application state
// Sync is performed during VmCall
var evmState = evm.NewState(appState, blockHashGetter)

//export VmCall
func VmCall(code, input, caller, callee *C.char, commandExecutor unsafe.Pointer, queryExecutor unsafe.Pointer) (*C.char, bool) {
	// command example
	// command := &pb.Command{Command: &pb.Command_CreateAccount{CreateAccount: &pb.CreateAccount{AccountName: "admin", DomainId: "test"}}}
	// fmt.Println(proto.MarshalTextString(command))
	// out, err := proto.Marshal(command)
	// if err != nil {
	// 	fmt.Println(err)
	// }
	// cOut := C.CBytes(out)
	// commandResult := C.Iroha_ProtoCommandExecutorExecute(commandExecutor, cOut, C.int(len(out)))
	// fmt.Println(commandResult)

	// query example
	// query := &pb.Query{Payload: &pb.Query_Payload{Query: &pb.Query_Payload_GetAccount{GetAccount: &pb.GetAccount{AccountId: "admin@test"}}}}
	// fmt.Println(proto.MarshalTextString(query))
	// out, err = proto.Marshal(query)
	// if err != nil {
	// 	fmt.Println(err)
	// }
	// cOut = C.CBytes(out)
	// queryResult := C.Iroha_ProtoQueryExecutorExecute(queryExecutor, cOut, C.int(len(out)))
	// fmt.Println(queryResult)
	// out = C.GoBytes(queryResult.data, queryResult.size)
	// queryResponse := &pb.QueryResponse{}
	// err = proto.Unmarshal(out, queryResponse)
	// if err != nil {
	// 	fmt.Println(err)
	// }
	// fmt.Println(queryResponse)

	// Convert strings into EVM addresses
	evmCaller := toEVMaddress(C.GoString(caller))
	evmCallee := toEVMaddress(C.GoString(callee))

	// Check if this accounts exists.
	// If not — create them
	if ! evmState.Exists(evmCaller) {
		evmState.CreateAccount(evmCaller)
	}

	shouldCreateAcc := false
	if ! evmState.Exists(evmCallee) {
		shouldCreateAcc = true
		evmState.CreateAccount(evmCallee)
	}

	var gas uint64 = 1000000
	goByteCode := hex.MustDecodeString(C.GoString(code))
	goInput := hex.MustDecodeString(C.GoString(input))
	output, err := ourVm.Call(evmState, evm.NewNoopEventSink(), evmCaller, evmCallee,
		goByteCode, goInput, 0, &gas)

	if shouldCreateAcc {
		evmState.InitCode(evmCallee, output)
	}

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

