package main

import (
	"fmt"
	"github.com/hyperledger/burrow/execution/errors"
	"github.com/hyperledger/burrow/execution/evm"
	"github.com/hyperledger/burrow/execution/exec"
)


var _ evm.EventSink = &IrohaEventSink{}

type IrohaEventSink struct {}

func (ies *IrohaEventSink) Call(call *exec.CallEvent, exception *errors.Exception) error {
	fmt.Println("Call")
	return nil
}

func (ies *IrohaEventSink) Log(log *exec.LogEvent) error {
	fmt.Println("Log")
	return nil
}
