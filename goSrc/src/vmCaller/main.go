package main

//typedef const char const_char;
import "C"
import (
	"fmt"
	"unsafe"

	"vmCaller/api"
	"vmCaller/blockchain"
	"vmCaller/contract"
	"vmCaller/state"

	"github.com/hyperledger/burrow/acm"
	"github.com/hyperledger/burrow/crypto"
	"github.com/hyperledger/burrow/execution/engine"
	"github.com/hyperledger/burrow/execution/evm"
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
func VmCall(input, caller, callee, nonce *C.const_char, commandExecutor, queryExecutor, storage unsafe.Pointer) (*C.char, *C.char) {

	// Update executors and Caller
	api.IrohaCommandExecutor = commandExecutor
	api.IrohaQueryExecutor = queryExecutor
	api.Caller = C.GoString(caller)

	// Iroha world state
	worldState := state.NewIrohaState(storage)

	worldState.UpdateAccount(&acm.Account{
		Address:     acm.GlobalPermissionsAddress,
		Balance:     999999,
		Permissions: permission.DefaultAccountPermissions,
	})
	_, err := worldState.GetAccount(acm.GlobalPermissionsAddress)

	// Convert the caller Iroha Account ID to an EVM addresses
	evmCaller := native.AddressFromName(C.GoString(caller))
	callerAccount, err := worldState.GetAccount(evmCaller)
	if err != nil {
		return makeError(fmt.Sprintf("Error getting account at address %s: %s",
			evmCaller.String(), err.Error()))
	}
	if callerAccount == nil {
		if err := native.CreateAccount(worldState, evmCaller); err != nil {
			return makeError(fmt.Sprintf("Error creating account at address %s: %s",
				evmCaller.String(), err.Error()))
		}
		if err := native.UpdateAccount(worldState,
			evmCaller,
			func(acc *acm.Account) error {
				return acc.Permissions.Base.Set(defaultPermissions, true)
			},
		); err != nil {
			return makeError(fmt.Sprintf("Error setting permissions at address %s: %s",
				evmCaller.String(), err.Error()))
		}
	}

	// goInput is either a contract bytecode or an ABI-encoded function - a hex string
	goInput := hex.MustDecodeString(C.GoString(input))

	var gas uint64 = 1000000
	var output acm.Bytecode
	eventSink := NewIrohaEventSink(worldState)

	if callee == nil {
		// A new contract is being deployed
		evmCallee := addressFromNonce(C.GoString(nonce))

		// Check if this address is, indeed, new and available
		calleeAccount, err := worldState.GetAccount(evmCallee)
		if err != nil {
			return makeError(err.Error())
		}
		if calleeAccount != nil {
			return makeError(fmt.Sprintf("Account already exists at address %s", evmCallee.String()))
		}

		if err := native.CreateAccount(worldState, evmCallee); err != nil {
			return makeError(fmt.Sprintf("Error creating account at address %s: %s",
				evmCallee.String(), err.Error()))
		}
		params := engine.CallParams{
			Caller: evmCaller,
			Callee: evmCallee,
			Input:  []byte{},
			Value:  0,
			Gas:    &gas,
		}
		output, err = burrowEVM.Execute(worldState, blockchain.New(), eventSink, params, goInput)
		if err != nil {
			return makeError(fmt.Sprintf("Error deploying smart contract at address %s: %s",
				evmCallee.String(), err.Error()))
		}

		if err := native.InitCode(worldState, evmCallee, output); err != nil {
			return makeError(fmt.Sprintf("Error initializing contract code at address %s: %s",
				evmCallee.String(), err.Error()))
		}
		if err := native.UpdateAccount(worldState,
			evmCallee,
			func(acc *acm.Account) error {
				return acc.Permissions.Base.Set(defaultPermissions, true)
			},
		); err != nil {
			return makeError(fmt.Sprintf("Error setting permissions at address %s: %s",
				evmCallee.String(), err.Error()))
		}

		return C.CString(evmCallee.String()), nil
	}

	// callee is a hex-encoded EVM address
	evmCallee, err := crypto.AddressFromHexString(C.GoString(callee))
	if err != nil {
		return makeError("Invalid callee address")
	}

	if contract.IsNative(evmCallee.String()) {
		return makeError(
			fmt.Sprintf("The callee address %s is reserved for a native contract and cannot be called directly",
				evmCallee.String()))
	}

	calleeAccount, err := worldState.GetAccount(evmCallee)
	if err != nil {
		return makeError(fmt.Sprintf("Error getting account at address %s: %s",
			evmCallee.String(), err.Error()))
	}

	params := engine.CallParams{
		Caller: evmCaller,
		Callee: evmCallee,
		Input:  goInput,
		Value:  0,
		Gas:    &gas,
	}
	output, err = burrowEVM.Execute(worldState, blockchain.New(), eventSink, params, calleeAccount.EVMCode)
	if err != nil {
		return makeError(fmt.Sprintf("Error calling a smart contract at address %s: %s",
			evmCallee.String(), goInput, err.Error()))
	}

	return nil, nil
}

func makeError(msg string) (*C.char, *C.char) {
	return nil, C.CString(msg)
}

func addressFromNonce(nonce string) (address crypto.Address) {
	hash := crypto.Keccak256(hex.MustDecodeString(nonce))
	copy(address[:], hash[len(hash)-crypto.AddressLength:])
	return
}

func main() {}
