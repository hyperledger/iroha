package main

import "C"
import (
	"fmt"

	"vmCaller/state"

	"github.com/hyperledger/burrow/execution/errors"
	"github.com/hyperledger/burrow/execution/exec"
)

var _ exec.EventSink = &IrohaEventSink{}

type IrohaEventSink struct{
  irohaState *state.IrohaState
}

func (ies *IrohaEventSink) Call(call *exec.CallEvent, exception *errors.Exception) error {
	fmt.Println("Call")
	return nil
}

func (ies *IrohaEventSink) Log(log *exec.LogEvent) error {
	fmt.Println("Log")
	return ies.irohaState.StoreTxReceipt(log.Address, log.Data, log.Topics)
}
