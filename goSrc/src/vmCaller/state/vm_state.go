package state

import (
	"bytes"
	"fmt"

	"github.com/hyperledger/burrow/acm/acmstate"
	"github.com/hyperledger/burrow/binary"
	"github.com/hyperledger/burrow/crypto"
	"github.com/tmthrgd/go-hex"
)

var (
	assetBalanceAddress       crypto.Address
	otherAssetBalanceAddress  crypto.Address
	assetTransferAddress      crypto.Address
	otherAssetTransferAddress crypto.Address
	a0                        binary.Word256
	a1                        binary.Word256
	a2                        binary.Word256
	trimCutSet                string
)

type State struct {
	acmstate.Cache
	backend *IrohaAppState
}

// check State implements acmstate.ReaderWriter
var _ acmstate.ReaderWriter = &State{}

func NewState(st *IrohaAppState) *State {
	return &State{*acmstate.NewCache(st), st}
}

func (st *State) GetStorage(address crypto.Address, key binary.Word256) ([]byte, error) {
	var value []byte
	switch address {
	case assetBalanceAddress:
		fmt.Printf("[vm_state::GetStorage] caller's address %s belongs to AssetBalance contract\n", address.String())
		// Fetching caller's address from "a0" variable
		callerBytes, err := st.Cache.GetStorage(address, a0)
		if err != nil {
			return []byte{}, err
		}
		// Assuming the bytes we have read from cache represent a valid EVM address of type 'address' (or uint160) which is left-padded
		callerAccount, err := crypto.AddressFromBytes(bytes.TrimLeft(callerBytes, trimCutSet))
		if err != nil {
			return []byte{}, err
		}
		value, err = st.backend.GetBalance(irohaAccountID(callerAccount), key)
		if err != nil {
			return []byte{}, err
		}
	case otherAssetBalanceAddress:
		fmt.Printf("[vm_state::GetStorage] caller's address %s belongs to OtherAssetBalance contract\n", address.String())
		// Fetching caller's address from "a0" variable
		otherAccountBytes, err := st.Cache.GetStorage(address, a0)
		if err != nil {
			return []byte{}, err
		}
		// The $accountID parameter type is bytes32 which is right-padded, hence trailing zeros trimming
		otherAccount := string(bytes.TrimRight(otherAccountBytes, trimCutSet))
		value, err = st.backend.GetBalance(otherAccount, key)
		if err != nil {
			return []byte{}, err
		}
	case assetTransferAddress:
		fmt.Printf("[vm_state::GetStorage] caller's address %s belongs to AssetTransfer contract\n", address.String())
		// Fetching caller's address from "a0" variable
		callerBytes, err := st.Cache.GetStorage(address, a0)
		if err != nil {
			return []byte{}, err
		}
		// Assuming the bytes we have read from cache represent a valid EVM address of type 'address' (or uint160) which is left-padded
		srcAccount, err := crypto.AddressFromBytes(bytes.TrimLeft(callerBytes, trimCutSet))
		if err != nil {
			return []byte{}, err
		}

		// Fetching destination address from "a1" variable
		dstBytes, err := st.Cache.GetStorage(address, a1)
		if err != nil {
			return []byte{}, err
		}
		// The $dst parameter type is bytes32 which is right-padded, hence trailing zeros trimming
		dstAccount := string(bytes.TrimRight(dstBytes, trimCutSet))

		// Fetching transfer amount from "a2" variable
		amountBytes, err := st.Cache.GetStorage(address, a2)
		if err != nil {
			return []byte{}, err
		}
		// The $amount parameter type is bytes32 which is right-padded, hence trailing zeros trimming
		amount := string(bytes.TrimRight(amountBytes, trimCutSet))

		err = st.backend.TransferAsset(irohaAccountID(srcAccount), dstAccount, amount, key)
		if err != nil {
			return []byte{}, err
		}
	case otherAssetTransferAddress:
		fmt.Printf("[vm_state::GetStorage] caller's address %s belongs to OtherAssetTransfer contract\n", address.String())
		// Fetching src address from "a0" variable
		srcBytes, err := st.Cache.GetStorage(address, a0)
		if err != nil {
			return []byte{}, err
		}
		// The $src parameter type is bytes32 which is right-padded, hence trailing zeros trimming
		srcAccount := string(bytes.TrimRight(srcBytes, trimCutSet))

		// Fetching destination address from "a1" variable
		dstBytes, err := st.Cache.GetStorage(address, a1)
		if err != nil {
			return []byte{}, err
		}
		// The $dst parameter type is bytes32 which is right-padded, hence trailing zeros trimming
		dstAccount := string(bytes.TrimRight(dstBytes, trimCutSet))

		// Fetching transfer amount from "a2" variable
		amountBytes, err := st.Cache.GetStorage(address, a2)
		if err != nil {
			return []byte{}, err
		}
		// The amount parameter type is bytes32 which is right-padded
		amount := string(bytes.TrimRight(amountBytes, trimCutSet))

		err = st.backend.TransferAsset(srcAccount, dstAccount, amount, key)
		if err != nil {
			return []byte{}, err
		}
	default:
		return st.Cache.GetStorage(address, key)
	}
	return value, nil
}

// package init function
func init() {
	assetBalanceAddress, _ = crypto.AddressFromHexString("200ffd74ede8735cdb03c8327d93244a9040571a")
	otherAssetBalanceAddress, _ = crypto.AddressFromHexString("c1850043a380abc52cd715a99d3e3225cf347ddc")
	assetTransferAddress, _ = crypto.AddressFromHexString("d06d3d6774374e536e39380239fa0e248ae0cb69")
	otherAssetTransferAddress, _ = crypto.AddressFromHexString("67828520a9669a43d57bb391c667cb1b209e6c78")
	a0 = binary.LeftPadWord256(hex.MustDecodeString("833ecd8e2c588c5ea5c03d7418b94f78e901da8b2ab6935e9cb068b5672ab7b1"))
	a1 = binary.LeftPadWord256(hex.MustDecodeString("37d3424576bafb5fd5f9f8e99478f66780477fcd8d71cb2319b37a64a01640db"))
	a2 = binary.LeftPadWord256(hex.MustDecodeString("a2060faa0fc5697bc282c626d908a989dc0d2b79270a5cdc58fbc0ab74c35faf"))
	trimCutSet = string([]byte{0})
}
