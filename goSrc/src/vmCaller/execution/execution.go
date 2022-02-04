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
)

var (
	// Create EVM instance
	burrowEVM = evm.New(evm.Options{
		Natives: vm.MustCreateQueryNatives(),
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
		return nil, fmt.Errorf("Internal error occured while trying to update account")
	}
	evmCaller := native.AddressFromName(fromAddress)
	callerAccount, err := worldState.GetAccount(evmCaller)
	if err != nil {
		return nil,fmt.Errorf("Error while getting iroha account of %s", fromAddress)
	}
	if callerAccount == nil {
		return nil, fmt.Errorf("Sender account must be an existing iroha account")
	}

	engine := EngineWrapper{
		engine:    burrowEVM,
		state:     worldState,
		eventSink: vm.NewIrohaEventSink(worldState),
	}
	evmCallee := address
	if vm.IsNative(evmCallee.String()) {
		return nil, fmt.Errorf("Address is native")
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
		return nil, fmt.Errorf("Error calling smart contract at address %s: %s",
			callee.String(), err.Error())
	}

	return output, nil
}
