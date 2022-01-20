package web3_service

import (
	"fmt"
	"vmCaller/evm"

	"github.com/hyperledger/burrow/acm/acmstate"
	"github.com/hyperledger/burrow/core"
	"github.com/hyperledger/burrow/process"
	"github.com/hyperledger/burrow/rpc"
)

func RunServer() {
	// init server
	web3_config := &rpc.ServerConfig{
		Enabled:    true,
		ListenHost: "127.0.0.1",
		ListenPort: "9001",
	}
	kern, err := core.NewKernel(".")
	accounts := evm.IrohaState{}
	var _ acmstate.IterableStatsReader = &accounts
	kern.EthService = rpc.NewEthService(
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
	processes := []process.Launcher{core.Web3Launcher(kern, web3_config)}
	kern.AddProcesses(processes...)
	kern.Boot()
}
