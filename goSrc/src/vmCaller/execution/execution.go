package execution

import "C"
import (
	"fmt"

	vm "vmCaller/evm"
	"vmCaller/iroha"

	"github.com/hyperledger/burrow/acm"
	"github.com/hyperledger/burrow/acm/acmstate"
	"github.com/hyperledger/burrow/bcm"
	"github.com/hyperledger/burrow/crypto"
	"github.com/hyperledger/burrow/execution/evm"
	"github.com/hyperledger/burrow/execution/exec"
	"github.com/hyperledger/burrow/execution/native"
	"github.com/hyperledger/burrow/logging"
	"github.com/hyperledger/burrow/permission"

	"vmCaller/blockchain"

	"github.com/hyperledger/burrow/execution/engine"
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

// Run a contract's code on an isolated and unpersisted state
// Cannot be used to create new contracts
func CallSim(reader acmstate.Reader, blockchain bcm.BlockchainInfo, fromAddress string, address crypto.Address, data []byte,
	logger *logging.Logger) (*exec.TxExecution, error) {
	worldState := vm.NewIrohaState(iroha.StoragePointer)
	if err := worldState.UpdateAccount(&acm.Account{
		Address:     acm.GlobalPermissionsAddress,
		Balance:     999999,
		Permissions: permission.DefaultAccountPermissions,
	}); err != nil {
		fmt.Println("unable to update account")
	}
	evmCaller := native.AddressFromName(fromAddress)
	// callerAccount, err := worldState.GetAccount(evmCaller)
	// if err != nil {
	// 	fmt.Println("Unable to get account")
	// }

	engine := EngineWrapper{
		engine:    burrowEVM,
		state:     worldState,
		eventSink: vm.NewIrohaEventSink(worldState),
	}
	evmCallee := address
	if vm.IsNative(evmCallee.String()) {
		fmt.Println("address is reserved for native")
	}

	output, err := engine.Execute(evmCaller, evmCallee, data)
	if err != nil {
		return nil, err
	}
	if output == nil {
		return nil, nil
	}
	// create object encapsulating response
	txe := exec.TxExecution{}
	txe.Result = &exec.Result{Return: output}
	return &txe, nil
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
		return nil, fmt.Errorf("Error calling smart contract at address %s: %s %s",
			callee.String(), err.Error(), iroha.IrohaErrorDetails)
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

// Run the given code on an isolated and unpersisted state
// Cannot be used to create new contracts.
func CallCodeSim(reader acmstate.Reader, blockchain bcm.BlockchainInfo, fromAddress string, address crypto.Address, code, data []byte,
	logger *logging.Logger) (*exec.TxExecution, error) {

	// Attach code to target account (overwriting target)
	cache := acmstate.NewCache(reader)
	err := cache.UpdateAccount(&acm.Account{
		Address: address,
		EVMCode: code,
	})

	if err != nil {
		return nil, err
	}
	return CallSim(cache, blockchain, fromAddress, address, data, logger)
}
