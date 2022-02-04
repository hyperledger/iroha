package web3_service

import (
	"fmt"
	"vmCaller/evm"
	myKernel "vmCaller/iroha_kernel"
	myRpc "vmCaller/rpc"

	"github.com/hyperledger/burrow/acm/acmstate"
	"github.com/hyperledger/burrow/process"
	"github.com/hyperledger/burrow/rpc"
)

var (
	kern myKernel.Kernel
)

func RunServer() {
	// init server
	web3_config := &rpc.ServerConfig{
		Enabled:    true,
		ListenHost: "0.0.0.0",
		ListenPort: "28660",
	}
	new_kern, err := myKernel.NewKernel(".")
	kern = *new_kern
	accounts := evm.IrohaState{}
	var _ acmstate.IterableStatsReader = &accounts
	kern.EthService = myRpc.NewEthService(
		&accounts,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		kern.Logger)
	if err != nil {	
		fmt.Errorf("Error while starting web3 server")
	}
	processes := []process.Launcher{myKernel.Web3Launcher(&kern, web3_config)}
	kern.AddProcesses(processes...)
	kern.Boot()
}

func ShutdownServer() {
	kern.ShutdownAndExit()
}
