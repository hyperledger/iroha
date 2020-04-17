package main

import "C"
import (
	"fmt"
	"strconv"
	"unsafe"

	"vmCaller/api"
	"vmCaller/blockchain"
	"vmCaller/contract"
	"vmCaller/state"

	"github.com/hyperledger/burrow/acm"
	"github.com/hyperledger/burrow/execution/engine"
	"github.com/hyperledger/burrow/execution/evm"
	"github.com/hyperledger/burrow/execution/exec"
	"github.com/hyperledger/burrow/execution/native"
	"github.com/hyperledger/burrow/permission"
	"github.com/tmthrgd/go-hex"
)

const defaultPermissions permission.PermFlag = permission.Send | permission.Call | permission.CreateContract | permission.CreateAccount

var (
	// Create EVM instance
	burrowEVM = evm.New(evm.Options{
		DebugOpcodes: true,
		DumpTokens:   true,
		Natives:      contract.MustCreateNatives(),
	})
)

//export VmCall
func VmCall(input, caller, callee *C.char, commandExecutor, queryExecutor, storage unsafe.Pointer) (*C.char, bool) {

	// Update executors
	api.IrohaCommandExecutor = commandExecutor
	api.IrohaQueryExecutor = queryExecutor

	// Iroha world state
	worldState := state.NewIrohaState(storage)

	worldState.UpdateAccount(&acm.Account{
		Address:     acm.GlobalPermissionsAddress,
		Balance:     999999,
		Permissions: permission.DefaultAccountPermissions,
	})

	// Convert strings into EVM addresses
	evmCaller := native.AddressFromName(C.GoString(caller))
	evmCallee := native.AddressFromName(C.GoString(callee))

	goInput := hex.MustDecodeString(C.GoString(input))

	fmt.Printf("[VmCall] caller: %s, callee: %s, len(input): %d\n", C.GoString(caller), C.GoString(callee), len(goInput))

	if contract.IsNative(evmCallee.String()) {
		fmt.Printf("The callee address %s is reserved for a native contract and cannot be called directly", evmCallee)
		return nil, false
	}

	callerAccount, err := worldState.GetAccount(evmCaller)
	if err != nil {
		fmt.Printf("Error getting caller's account at address %s: %s", evmCaller.String(), err.Error())
		return nil, false
	}
	if callerAccount == nil {
		if err := native.CreateAccount(worldState, evmCaller); err != nil {
			fmt.Printf("Error creating caller's account at address %s: %s", evmCaller.String(), err.Error())
			return nil, false
		}
		if err := native.UpdateAccount(worldState,
			evmCaller,
			func(acc *acm.Account) error {
				return acc.Permissions.Base.Set(defaultPermissions, true)
			},
		); err != nil {
			fmt.Println(err, "Error while setting permissions for account at caller addr: ", evmCaller.String())
			return nil, false
		}
	}

	var gas uint64 = 1000000
	var output acm.Bytecode

	calleeAccount, err := worldState.GetAccount(evmCallee)
	if err != nil {
		fmt.Printf("Error getting callee's account at address %s: %s\n", evmCallee.String(), err.Error())
		return nil, false
	}
	if calleeAccount == nil {
		// Callee account doesn't exist therefore a new account with bytecode must be created
		if err := native.CreateAccount(worldState, evmCallee); err != nil {
			fmt.Printf("Error creating callee's account at address %s: %s\n", evmCallee.String(), err.Error())
			return nil, false
		}
		params := engine.CallParams{
			Caller: evmCaller,
			Callee: evmCallee,
			Input:  []byte{},
			Value:  0,
			Gas:    &gas,
		}
		output, err = burrowEVM.Execute(worldState, blockchain.New(), exec.NewNoopEventSink(), params, goInput)
		if err != nil {
			fmt.Printf("Error deploying smart contract at address %s, input %x: %s\n", evmCallee.String(), goInput, err.Error())
			return nil, false
		}

		if err := native.InitCode(worldState, evmCallee, output); err != nil {
			fmt.Printf("Error initializing contract code for the callee account at address %s: %s\n", evmCallee.String(), err.Error())
			return nil, false
		}
		if err := native.UpdateAccount(worldState,
			evmCallee,
			func(acc *acm.Account) error {
				return acc.Permissions.Base.Set(defaultPermissions, true)
			},
		); err != nil {
			fmt.Printf("Error setting permissions for the callee's account at address %s: %s\n", evmCallee.String(), err.Error())
			return nil, false
		}
	} else {
		// Callee's account already exists, therefore treating the input as a contract method ABI + params
		params := engine.CallParams{
			Caller: evmCaller,
			Callee: evmCallee,
			Input:  goInput,
			Value:  0,
			Gas:    &gas,
		}
		output, err = burrowEVM.Execute(worldState, blockchain.New(), exec.NewNoopEventSink(), params, calleeAccount.EVMCode)
		if err != nil {
			fmt.Printf("Error calling a smart contract at address %s with input %x: %s\n", evmCallee.String(), goInput, err.Error())
			return nil, false
		}
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
