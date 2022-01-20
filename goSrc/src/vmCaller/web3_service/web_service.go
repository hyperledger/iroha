package web3_service

import (
	"fmt"
	"vmCaller/evm"

	"github.com/hyperledger/burrow/acm/acmstate"
	"github.com/hyperledger/burrow/core"
	"github.com/hyperledger/burrow/process"
	"github.com/hyperledger/burrow/rpc"
	"github.com/hyperledger/burrow/rpc/web3"
)

var (
	kern core.Kernel
)

func RunServer() {
	// init server
	web3_config := &rpc.ServerConfig{
		Enabled:    true,
		ListenHost: "0.0.0.0",
		ListenPort: "28660",
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

func (srv *rpc.EthService) EthCall(req *web3.EthCallParams) (*web3.EthCallResult, error) {
	fmt.Println("executing eth call")
	var to, from crypto.Address
	var err error

	if addr := req.Transaction.To; addr != "" {
		to, err = x.DecodeToAddress(addr)
		if err != nil {
			return nil, err
		}
	}

	if addr := req.Transaction.From; addr != "" {
		from, err = x.DecodeToAddress(addr)
		if err != nil {
			return nil, err
		}
	}
	fmt.Println(from)
	fmt.Println(to)
	data, err := x.DecodeToBytes(req.Transaction.Data)
	if err != nil {
		return nil, err
	}
	fmt.Println(data)
	fmt.Println("resolved data")
	txe, err := execution.CallSim(srv.accounts, srv.blockchain, from, to, data, srv.logger)
	if err != nil {
		fmt.Println("got error from CallSim")
		return nil, err
	} else if txe.Exception != nil {
		fmt.Println("caught exception")
		return nil, txe.Exception.AsError()
	}

	var result string
	if r := txe.GetResult(); r != nil {
		result = x.EncodeBytes(r.GetReturn())
	}

	return &web3.EthCallResult{
		ReturnValue: result,
	}, nil
}
