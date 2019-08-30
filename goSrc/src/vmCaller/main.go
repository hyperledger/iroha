package main

import "C"
import (
	"fmt"
	"github.com/hyperledger/burrow/binary"
	"github.com/hyperledger/burrow/crypto"
	"github.com/hyperledger/burrow/execution/evm"
	"github.com/hyperledger/burrow/logging"
	"github.com/tmthrgd/go-hex"
	"golang.org/x/crypto/ripemd160"
	"strconv"
	"unsafe"
)

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

// Create EVM instance
var burrowEVM = evm.NewVM(newParams(), crypto.ZeroAddress, nil, logging.NewNoopLogger())

//export VmCall
func VmCall(code, input, caller, callee *C.char, commandExecutor unsafe.Pointer, queryExecutor unsafe.Pointer) (*C.char, bool) {

	// Update executors
	appState.commandExecutor = commandExecutor
	appState.queryExecutor = queryExecutor

	// The wrapper for EVM state.
	// Contains real application state (here it is the appState) and it's cache.
	// Since Iroha state changes are possible between VmCall invocations,
	// cache should be synced with appState to prevent using of invalid data.
	var evmState = evm.NewState(appState, blockHashGetter)

	// Convert strings into EVM addresses
	evmCaller := toEVMaddress(C.GoString(caller))
	evmCallee := toEVMaddress(C.GoString(callee))

	goByteCode := hex.MustDecodeString(C.GoString(code))
	goInput := hex.MustDecodeString(C.GoString(input))

	// Check if this accounts exists.
	// If not — create them
	if !evmState.Exists(evmCaller) {
		evmState.CreateAccount(evmCaller)
	}

	shouldAddEvmCodeToCallee := false
	if !evmState.Exists(evmCallee) {
		shouldAddEvmCodeToCallee = true
		evmState.CreateAccount(evmCallee)
	} else {
		EvmBytecode, err := appState.getIrohaAccountDetail(evmCallee, "EVM_bytecode")
		if err != nil {
			fmt.Println(err, "No code at callee addr: ", evmCallee.String())
		}
		goByteCode = EvmBytecode
	}

	var gas uint64 = 1000000

	output, err := burrowEVM.Call(evmState, evm.NewNoopEventSink(), evmCaller, evmCallee,
		goByteCode, goInput, 0, &gas)

	if shouldAddEvmCodeToCallee {
		evmState.InitCode(evmCallee, output)
	}

	// If there is no errors after smart contract execution, cache data is written to Iroha.
	if err := evmState.Sync(); err != nil {
		fmt.Println(err, "Sync error")
		return nil, false
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
