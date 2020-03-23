package blockchain

import (
	"encoding/binary"
	"time"

	"github.com/hyperledger/burrow/execution/errors"
)

type Blockchain struct {
	blockHeight uint64
	blockTime   time.Time
}

func New() *Blockchain {
	return &Blockchain{}
}

func (b *Blockchain) LastBlockHeight() uint64 {
	return b.blockHeight
}

func (b *Blockchain) LastBlockTime() time.Time {
	return b.blockTime
}

func (b *Blockchain) BlockHash(height uint64) ([]byte, error) {
	if height > b.blockHeight {
		return nil, errors.Codes.InvalidBlockNumber
	}
	bs := make([]byte, 32)
	binary.BigEndian.PutUint64(bs[24:], height)
	return bs, nil
}
