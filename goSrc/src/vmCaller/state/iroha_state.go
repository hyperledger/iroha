package state

import (
	"encoding/hex"
	"fmt"

	"vmCaller/api"

	"github.com/hyperledger/burrow/acm"
	"github.com/hyperledger/burrow/acm/acmstate"
	"github.com/hyperledger/burrow/binary"
	"github.com/hyperledger/burrow/crypto"
)

type IrohaState struct{}

// check that IrohaState implements acmstate.ReaderWriter
var _ acmstate.ReaderWriter = &IrohaState{}

func NewIrohaState() *IrohaState {
	return &IrohaState{}
}

func (st *IrohaState) GetAccount(addr crypto.Address) (*acm.Account, error) {
	mirrorAccExist, err := api.GetIrohaAccount(addr)
	if err != nil {
		fmt.Printf("[GetAccount] Error getting Iroha account %s\n", addr.String())
		return nil, err
	}

	if !mirrorAccExist {
		// Corresponding account doesn't exist in Iroha
		return nil, nil
	} else {
		// Account exists, fetching its data
		resp, err := api.GetIrohaAccountDetail(addr, "evm_account_data")
		if err != nil {
			return nil, fmt.Errorf("[GetAccount] error getting account details for address %s\n", addr.String())
		}
		accountBytes, err := hex.DecodeString(resp)
		if err != nil {
			return nil, fmt.Errorf("[GetAccount] error decoding hex string %s\n", resp)
		}
		account := &acm.Account{}
		err = account.Unmarshal(accountBytes)

		// Unmarshlling bytecode replaces nil slices with empty ones []byte{}
		// Hence the workaround below to revert this and make native.InitCode work
		if account.EVMCode != nil && len(account.EVMCode) == 0 {
			account.EVMCode = nil
		}
		if account.WASMCode != nil && len(account.WASMCode) == 0 {
			account.WASMCode = nil
		}
		return account, err
	}
}

// mock
func (st *IrohaState) GetMetadata(metahash acmstate.MetadataHash) (string, error) {
	fmt.Printf("[GetMetadata] metahash: %s\n", metahash.String())
	return "", nil
}

// mock
func (st *IrohaState) SetMetadata(metahash acmstate.MetadataHash, metadata string) error {
	fmt.Printf("[SetMetadata] metahash: %s, metadata: %s\n", metahash.String(), metadata)
	return nil
}

func (st *IrohaState) UpdateAccount(account *acm.Account) error {
	if account == nil {
		return fmt.Errorf("[UpdateAccount] account passed is nil")
	}

	exist, err := api.GetIrohaAccount(account.Address)
	if err != nil {
		fmt.Errorf("[UpdateAccount] error getting Iroha account %s", account.String())
		return err
	}
	if !exist {
		// Account doesn't yet exist in Iroha; create it
		err = api.CreateIrohaEvmAccount(account.Address)
		if err != nil {
			fmt.Errorf("[UpdateAccount] error creating Iroha account %s", account.String())
			return err
		}
	}

	marshalledData, err := account.Marshal()
	if err != nil {
		fmt.Printf("[UpdateAccount] Error marshalling account data: %s\n", account.String())
		return err
	}

	err = api.SetIrohaAccountDetail(account.Address, "evm_account_data", hex.EncodeToString(marshalledData))

	return err
}

func (st *IrohaState) RemoveAccount(address crypto.Address) error {
	fmt.Printf("[RemoveAccount] account: %s\n", address.String())
	return nil
}

func (st *IrohaState) GetStorage(addr crypto.Address, key binary.Word256) ([]byte, error) {
	detail, err := api.GetIrohaAccountDetail(addr, hex.EncodeToString(key.Bytes()))
	if err != nil {
		return []byte{}, err
	}
	if detail == "" {
		return nil, nil
	}
	return hex.DecodeString(detail)
}

func (st *IrohaState) SetStorage(addr crypto.Address, key binary.Word256, value []byte) error {
	return api.SetIrohaAccountDetail(addr, hex.EncodeToString(key.Bytes()), hex.EncodeToString(value))
}
