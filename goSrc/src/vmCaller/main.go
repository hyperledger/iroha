package main

import "C"
import (
	"fmt"

	"vmCaller/state"

	"github.com/hyperledger/burrow/acm"
	"github.com/hyperledger/burrow/binary"
	"github.com/hyperledger/burrow/crypto"
	"github.com/hyperledger/burrow/execution/evm"
	"github.com/hyperledger/burrow/logging"
	"github.com/hyperledger/burrow/permission"
	"github.com/tmthrgd/go-hex"
	"golang.org/x/crypto/ripemd160"
	"strconv"
	"unsafe"
)

const defaultPermissions permission.PermFlag = permission.Send | permission.Call | permission.CreateContract | permission.CreateAccount

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
var appState = state.NewIrohaAppState()

// Create EVM instance
var burrowEVM = evm.NewVM(newParams(), crypto.ZeroAddress, nil, logging.NewNoopLogger())

//export VmCall
func VmCall(input, caller, callee *C.char, commandExecutor unsafe.Pointer, queryExecutor unsafe.Pointer) (*C.char, bool) {

	// Update executors
	appState.SetCommandExecutor(commandExecutor)
	appState.SetQueryExecutor(queryExecutor)

	// The wrapper for EVM state.
	// Contains real application state (here it is the appState) and it's cache.
	// Since Iroha state changes are possible between VmCall invocations,
	// cache should be synced with appState to prevent using of invalid data.
	var evmState = state.NewState(appState, blockHashGetter)

	// Convert strings into EVM addresses
	evmCaller := toEVMaddress(C.GoString(caller))
	evmCallee := toEVMaddress(C.GoString(callee))

	goInput := hex.MustDecodeString(C.GoString(input))

	// Check if caller account exists
	if !evmState.Exists(evmCaller) {
		evmState.CreateAccount(evmCaller)
		evmState.SetPermission(evmCaller, defaultPermissions, true)
		// TODO: study if storing the original Iroha accountID of the caller is necessary
		// appState.SetParentID(evmCaller, "ParentID", []byte(C.GoString(caller)))
	}

	// Check if callee account exists
	// and prepare to store EVM bytecode

	var gas uint64 = 1000000
	var output acm.Bytecode
	var err error

	if !evmState.Exists(evmCallee) {
		// Then smart contract should be deployed
		fmt.Printf("No EVM account exists for the callee %s. Creating account\n", evmCallee)
		evmState.CreateAccount(evmCallee)
		// Pass goInput as deployment data
		output, err = burrowEVM.Call(evmState, evm.NewNoopEventSink(), evmCaller, evmCallee,
			goInput, []byte{}, 0, &gas)
		if err != nil {
			fmt.Println(err)
			fmt.Println("Error while deploying smart contract at addr ", evmCallee.String(), ", input ", goInput)
			return nil, false
		}
		evmState.InitCode(evmCallee, output)
		evmState.SetPermission(evmCallee, defaultPermissions, true)
	} else {
		var calleeAcc *acm.Account
		calleeAcc, err = appState.GetAccount(evmCallee)
		if err != nil {
			fmt.Println(err, "Error while getting account at callee addr: ", evmCallee.String())
		}
		// Pass goInput as function call
		output, err = burrowEVM.Call(evmState, evm.NewNoopEventSink(), evmCaller, evmCallee,
			calleeAcc.EVMCode, goInput, 0, &gas)
		if err != nil {
			fmt.Println(err)
			fmt.Println("Error while calling smart contract at addr ", evmCallee.String(), ", input ", goInput)
			return nil, false
		}
	}

	// If there is no errors after smart contract execution, cache data is written to Iroha.
	if err = evmState.Sync(); err != nil {
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

	return C.CString(res), true
}

func main() {}
