package main

//typedef const char const_char;
import "C"
import (
	"fmt"
	"unsafe"

	"vmCaller/blockchain"
	vm "vmCaller/evm"
	"vmCaller/iroha"

	"github.com/hyperledger/burrow/acm"
	"github.com/hyperledger/burrow/acm/acmstate"
	"github.com/hyperledger/burrow/crypto"
	"github.com/hyperledger/burrow/execution/engine"
	"github.com/hyperledger/burrow/execution/evm"
	"github.com/hyperledger/burrow/execution/exec"
	"github.com/hyperledger/burrow/execution/native"
	"github.com/hyperledger/burrow/permission"
	"github.com/tmthrgd/go-hex"
)

var (
	// Create EVM instance
	burrowEVM = evm.New(evm.Options{
		Natives: vm.MustCreateNatives(),
	})
)

type Engine interface {
	Execute(st acmstate.ReaderWriter, blockchain engine.Blockchain, eventSink exec.EventSink,
		params engine.CallParams, code []byte) ([]byte, error)
}

type EngineWrapper struct {
	engine    Engine
	state     acmstate.ReaderWriter
	eventSink exec.EventSink
}

//export VmCall
func VmCall(input, caller, callee, nonce *C.const_char, commandExecutor, queryExecutor, storage unsafe.Pointer) (*C.char, *C.char) {
	// Update global executors and Caller
	iroha.IrohaCommandExecutor = commandExecutor
	iroha.IrohaQueryExecutor = queryExecutor
	iroha.Caller = C.GoString(caller)

	// Iroha world state
	worldState := vm.NewIrohaState(storage)
	if err := worldState.UpdateAccount(&acm.Account{
		Address:     acm.GlobalPermissionsAddress,
		Balance:     999999,
		Permissions: permission.DefaultAccountPermissions,
	}); err != nil {
		return makeError(err.Error())
	}

	// Convert the caller Iroha Account ID to an EVM addresses
	evmCaller := native.AddressFromName(C.GoString(caller))
	callerAccount, err := worldState.GetAccount(evmCaller)
	if err != nil {
		return makeError(fmt.Sprintf("Error getting account at address %s: %s",
			evmCaller.String(), err.Error()))
	}
	if callerAccount == nil {
		if err := worldState.UpdateAccount(&acm.Account{
			Address:     evmCaller,
			Permissions: permission.DefaultAccountPermissions,
		}); err != nil {
			return makeError(fmt.Sprintf("Error creating account at address %s: %s",
				evmCaller.String(), err.Error()))
		}
	}

	// inputBytes is either a contract bytecode or an ABI-encoded function - a hex string
	inputBytes := hex.MustDecodeString(C.GoString(input))

	engine := EngineWrapper{
		engine:    burrowEVM,
		state:     worldState,
		eventSink: vm.NewIrohaEventSink(worldState),
	}

	if callee == nil {
		output, err := engine.NewContract(evmCaller, inputBytes, C.GoString(nonce))
		if err != nil {
			return makeError(err.Error())
		}
		return C.CString(output), nil
	}

	evmCallee, err := crypto.AddressFromHexString(C.GoString(callee))
	if err != nil {
		return makeError("Invalid callee address")
	}

	if vm.IsNative(evmCallee.String()) {
		return makeError(
			fmt.Sprintf("The callee address %s is reserved for a native contract and cannot be called directly",
				evmCallee.String()))
	}

	output, err := engine.Execute(evmCaller, evmCallee, inputBytes)
	if err != nil {
		return makeError(err.Error())
	}
	if output == nil {
		return nil, nil
	}
	return C.CString(hex.EncodeToString(output)), nil
}

func (w *EngineWrapper) NewContract(caller crypto.Address, code []byte, nonce string) (string, error) {
	var output acm.Bytecode
	var gas uint64 = 1000000

	callee := addressFromNonce(nonce)

	// Check if this address is, indeed, new and available
	calleeAccount, err := w.state.GetAccount(callee)
	if err != nil {
		return "", err
	}
	if calleeAccount != nil {
		return "", fmt.Errorf("Account already exists at address %s", callee.String())
	}

	if err := w.state.UpdateAccount(&acm.Account{
		Address:     callee,
		Permissions: permission.DefaultAccountPermissions,
	}); err != nil {
		return "", fmt.Errorf("Error creating account at address %s: %s",
			callee.String(), err.Error())
	}

	params := engine.CallParams{
		Caller: caller,
		Callee: callee,
		Input:  []byte{},
		Value:  0,
		Gas:    &gas,
	}
	output, err = w.engine.Execute(w.state, blockchain.New(), w.eventSink, params, code)
	if err != nil {
		return "", fmt.Errorf("Error deploying smart contract at address %s: %s",
			callee.String(), err.Error())
	}

	if err := native.InitCode(w.state, callee, output); err != nil {
		return "", fmt.Errorf("Error initializing contract code at address %s: %s",
			callee.String(), err.Error())
	}

	return callee.String(), nil
}

func (w *EngineWrapper) Execute(caller, callee crypto.Address, input []byte) ([]byte, error) {
	var gas uint64 = 1000000

	calleeAccount, err := w.state.GetAccount(callee)
	if err != nil {
		return nil, fmt.Errorf("Error getting account at address %s: %s",
			callee.String(), err.Error())
	}
	if calleeAccount == nil {
		return nil, fmt.Errorf("Contract account does not exists at address %s", callee.String())
	}

	params := engine.CallParams{
		Caller: caller,
		Callee: callee,
		Input:  input,
		Value:  0,
		Gas:    &gas,
	}
	output, err := w.engine.Execute(w.state, blockchain.New(), w.eventSink, params, calleeAccount.EVMCode)

	if err != nil {
		return nil, fmt.Errorf("Error calling smart contract at address %s: %s",
			callee.String(), err.Error())
	}

	return output, nil
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
