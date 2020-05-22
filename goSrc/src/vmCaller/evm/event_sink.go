package evm

import (
	"github.com/hyperledger/burrow/binary"
	"github.com/hyperledger/burrow/crypto"
	"github.com/hyperledger/burrow/execution/errors"
	"github.com/hyperledger/burrow/execution/exec"
)

var _ exec.EventSink = &IrohaEventSink{nil}

type EventWriter interface {
	StoreTxReceipt(address crypto.Address, hex_data []byte, topics []binary.Word256) error
}

type IrohaEventSink struct {
	irohaState EventWriter
}

func NewIrohaEventSink(state EventWriter) *IrohaEventSink {
	return &IrohaEventSink{
		irohaState: state,
	}
}

func (ies *IrohaEventSink) Call(call *exec.CallEvent, exception *errors.Exception) error {
	return nil
}

func (ies *IrohaEventSink) Log(log *exec.LogEvent) error {
	err := ies.irohaState.StoreTxReceipt(log.Address, log.Data, log.Topics)
	return err
}
