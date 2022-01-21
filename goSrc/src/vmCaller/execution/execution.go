package execution

import (
	"fmt"
	// "vmCaller/iroha"

	"github.com/hyperledger/burrow/acm"
	"github.com/hyperledger/burrow/acm/acmstate"
	"github.com/hyperledger/burrow/bcm"
	"github.com/hyperledger/burrow/crypto"
	"github.com/hyperledger/burrow/execution/exec"
	"github.com/hyperledger/burrow/logging"
)

// Run a contract's code on an isolated and unpersisted state
// Cannot be used to create new contracts
func CallSim(reader acmstate.Reader, blockchain bcm.BlockchainInfo, fromAddress, address crypto.Address, data []byte,
	logger *logging.Logger) (*exec.TxExecution, error) {
	fmt.Println("executing call sim")
	// worldState := vm.NewIrohaState(iroha.StoragePointer)
	// cache := acmstate.NewCache(reader)
	// exe := contexts.CallContext{
	// 	EVM: evm.New(evm.Options{
	// 		Natives: vm.MustCreateNatives(),
	// 	}),
	// 	RunCall:       true,
	// 	State:         cache,
	// 	MetadataState: acmstate.NewMemoryState(),
	// 	Blockchain:    blockchain,
	// 	Logger:        logger,
	// }

	// txe := exec.NewTxExecution(txs.Enclose(blockchain.ChainID(), &payload.CallTx{
	// 	Input: &payload.TxInput{
	// 		Address: fromAddress,
	// 	},
	// 	Address:  &address,
	// 	Data:     data,
	// 	GasLimit: contexts.GasLimit,
	// }))

	// // Set height for downstream synchronisation purposes
	// txe.Height = blockchain.LastBlockHeight()
	// err := exe.Execute(txe, txe.Envelope.Tx.Payload)
	// if err != nil {
	// 	return nil, err
	// }
	// return txe, nil
	return
}

// Run the given code on an isolated and unpersisted state
// Cannot be used to create new contracts.
func CallCodeSim(reader acmstate.Reader, blockchain bcm.BlockchainInfo, fromAddress, address crypto.Address, code, data []byte,
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
