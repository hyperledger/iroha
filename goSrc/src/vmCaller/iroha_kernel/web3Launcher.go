package iroha_kernel

import (
	"fmt"

	"github.com/hyperledger/burrow/process"
	"github.com/hyperledger/burrow/rpc"
	"github.com/hyperledger/burrow/rpc/lib/server"
	"github.com/hyperledger/burrow/rpc/web3"
)

func Web3Launcher(kern *Kernel, conf *rpc.ServerConfig) process.Launcher {
	return process.Launcher{
		Name:    "Web3ProcessName",
		Enabled: conf.Enabled,
		Launch: func() (process.Process, error) {
			listener, err := process.ListenerFromAddress(fmt.Sprintf("%s:%s", conf.ListenHost, conf.ListenPort))
			if err != nil {
				return nil, err
			}
			err = kern.registerListener("Web3ProcessName", listener)
			if err != nil {
				return nil, err
			}

			srv, err := server.StartHTTPServer(listener, web3.NewServer(kern.EthService), kern.Logger)
			if err != nil {
				return nil, err
			}

			return srv, nil
		},
	}
}
