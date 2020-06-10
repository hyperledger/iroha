package evm

import (
	"testing"

	"github.com/hyperledger/burrow/binary"
	"github.com/hyperledger/burrow/crypto"
	"github.com/hyperledger/burrow/execution/exec"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tmthrgd/go-hex"
)

type eventWriterMock struct {
	counter int
	data    map[int][]byte
}

func (e *eventWriterMock) StoreTxReceipt(address crypto.Address, hex_data []byte, topics []binary.Word256) error {

	value := address.Bytes()
	for _, t := range topics {
		value = append(value, t.Bytes()...)
	}
	value = append(value, hex_data...)
	e.data[e.counter] = value
	e.counter++

	return nil
}

func TestLog(t *testing.T) {
	store := eventWriterMock{
		data: map[int][]byte{},
	}
	sink := NewIrohaEventSink(&store)

	addr := crypto.MustAddressFromHexString("0123456789ABCDEF0123456789ABCDEF01234567")
	topics := []binary.Word256{binary.One256}
	hex_data := hex.MustDecodeString("ABCDEF")
	err := sink.Log(&exec.LogEvent{
		Address: addr,
		Data:    hex_data,
		Topics:  topics,
	})
	require.NoError(t, err)
	assert.Equal(
		t,
		store.data[0],
		hex.MustDecodeString("0123456789ABCDEF0123456789ABCDEF012345670000000000000000000000000000000000000000000000000000000000000001ABCDEF"),
	)
}
