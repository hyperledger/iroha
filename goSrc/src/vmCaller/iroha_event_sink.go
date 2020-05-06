package main

import (
	"vmCaller/state"

	"github.com/hyperledger/burrow/execution/errors"
	"github.com/hyperledger/burrow/execution/exec"
)

var _ exec.EventSink = &IrohaEventSink{nil}

type IrohaEventSink struct {
	irohaState *state.IrohaState
}

func NewIrohaEventSink(state *state.IrohaState) *IrohaEventSink {
	return &IrohaEventSink{
		irohaState: state,
	}
}

func (ies *IrohaEventSink) Call(call *exec.CallEvent, exception *errors.Exception) error {
	return nil
}

func (ies *IrohaEventSink) Log(log *exec.LogEvent) error {
	return ies.irohaState.StoreTxReceipt(log.Address, log.Data, log.Topics)
}
