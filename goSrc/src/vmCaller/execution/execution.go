package execution

import (
	"fmt"

	vm "vmCaller/evm"
	"vmCaller/iroha"

	"github.com/hyperledger/burrow/acm"
	"github.com/hyperledger/burrow/acm/acmstate"
	"github.com/hyperledger/burrow/bcm"
	"github.com/hyperledger/burrow/crypto"
	"github.com/hyperledger/burrow/execution/exec"
	"github.com/hyperledger/burrow/logging"

	"github.com/hyperledger/burrow/execution/native"
	"github.com/hyperledger/burrow/permission"
)

// Run a contract's code on an isolated and unpersisted state
// Cannot be used to create new contracts
func CallSim(reader acmstate.Reader, blockchain bcm.BlockchainInfo, fromAddress string, address crypto.Address, data []byte,
	logger *logging.Logger) (*exec.TxExecution, error) {
	fmt.Println("executing call sim")
	// worldState :=
	//not working, solve using lines from 209 in call_context.go
	// add logger and events :)
	worldState := vm.NewIrohaState(iroha.StoragePointer)
	fmt.Println("new state created")
	if err := worldState.UpdateAccount(&acm.Account{
		Address:     acm.GlobalPermissionsAddress,
		Balance:     999999,
		Permissions: permission.DefaultAccountPermissions,
	}); err != nil {
		fmt.Println("unable to update account")
	}
	evmCaller := native.AddressFromName(fromAddress)
	callerAccount, err := worldState.GetAccount(evmCaller)
	if err != nil {
		fmt.Println("Unable to get account")
	}
	fmt.Println(callerAccount)
	// exe := contexts.CallContext{
	// 	EVM: evm.New(evm.Options{
	// 		Natives: vm.MustCreateNatives(),
	// 	}),
	// 	RunCall:       true,
	// 	State:         cache,
	// 	MetadataState: acmstate.NewMemoryState(),
	// 	Blockchain:    blockchain,
	// 	Logger:        nil,
	// }
	// fmt.Println("exe created")
	// fmt.Println(address)
	// fmt.Println(data)
	// txe := exec.NewTxExecution(txs.Enclose("dupa", &payload.CallTx{
	// 	Input: &payload.TxInput{
	// 		Address: fromAddress,
	// 	},
	// 	Address:  &address,
	// 	Data:     data,
	// 	GasLimit: 999999,
	// }))
	// fmt.Println("new txe created")
	// // Set height for downstream synchronisation purposes
	// txe.Height = 1
	// fmt.Println("last block height calculated")
	// fmt.Println(txe.Envelope.Tx.Payload)
	// err := exe.Execute(txe, txe.Envelope.Tx.Payload)
	// fmt.Println("executed")
	// if err != nil {
	// 	fmt.Println(err.Error())
	// 	return nil, err
	// }
	return nil, nil

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
