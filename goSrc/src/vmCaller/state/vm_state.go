package state

import (
	"bytes"
	"fmt"

	"github.com/hyperledger/burrow/acm"
	"github.com/hyperledger/burrow/acm/acmstate"
	"github.com/hyperledger/burrow/binary"
	"github.com/hyperledger/burrow/crypto"
	"github.com/hyperledger/burrow/crypto/sha3"
	"github.com/hyperledger/burrow/deploy/compile"
	"github.com/hyperledger/burrow/execution/errors"
	"github.com/hyperledger/burrow/execution/evm"
	"github.com/hyperledger/burrow/permission"
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
	// Where we sync
	backend acmstate.ReaderWriter
	// Block chain info
	blockHashGetter func(height uint64) []byte
	// Cache this State wraps
	cache *acmstate.Cache
	// Any error that may have occurred
	error errors.CodedError
	// In order for nested cache to inherit any options
	cacheOptions []acmstate.CacheOption
}

func NewState(st acmstate.ReaderWriter, blockHashGetter func(height uint64) []byte, cacheOptions ...acmstate.CacheOption) *State {
	return &State{
		backend:         st,
		blockHashGetter: blockHashGetter,
		cache:           acmstate.NewCache(st, cacheOptions...),
		cacheOptions:    cacheOptions,
	}
}

func (st *State) NewCache(cacheOptions ...acmstate.CacheOption) evm.Interface {
	return NewState(st.cache, st.blockHashGetter, append(st.cacheOptions, cacheOptions...)...)
}

func (st *State) Sync() errors.CodedError {
	// Do not sync if we have erred
	if st.error != nil {
		return st.error
	}
	err := st.cache.Sync(st.backend)
	if err != nil {
		return errors.AsException(err)
	}
	return nil
}

func (st *State) Error() errors.CodedError {
	if st.error == nil {
		return nil
	}
	return st.error
}

// Errors pushed to state may end up in TxExecutions and therefore the merkle state so it is essential that errors are
// deterministic and independent of the code path taken to execution (e.g. replay takes a different path to that of
// normal consensus reactor so stack traces may differ - as they may across architectures)
func (st *State) PushError(err error) {
	if st.error == nil {
		// Make sure we are not wrapping a known nil value
		ex := errors.AsException(err)
		if ex != nil {
			st.error = ex
		}
	}
}

// Reader

func (st *State) GetStorage(address crypto.Address, key binary.Word256) (value []byte) {
	value = []byte{}
	switch address {
	case assetBalanceAddress:
		fmt.Printf("[vm_state::GetStorage] caller's address %s belongs to AssetBalance contract\n", address.String())
		// Fetching caller's address from "a0" variable
		callerBytes, err := st.cache.GetStorage(address, a0)
		if err != nil {
			st.PushError(err)
			return
		}
		// Assuming the bytes we have read from cache represent a valid EVM address
		callerAccount, err := crypto.AddressFromBytes(bytes.TrimLeft(callerBytes, trimCutSet))
		if err != nil {
			st.PushError(err)
			return
		}
		value, err = st.backend.(*IrohaAppState).GetBalance(irohaAccountID(callerAccount), key)
		if err != nil {
			st.PushError(err)
			return
		}
	case otherAssetBalanceAddress:
		fmt.Printf("[vm_state::GetStorage] caller's address %s belongs to OtherAssetBalance contract\n", address.String())
		// Fetching caller's address from "a0" variable
		otherAccountBytes, err := st.cache.GetStorage(address, a0)
		if err != nil {
			st.PushError(err)
			return
		}
		otherAccount := string(bytes.TrimLeft(otherAccountBytes, trimCutSet))
		value, err = st.backend.(*IrohaAppState).GetBalance(otherAccount, key)
		if err != nil {
			st.PushError(err)
			return
		}
	case assetTransferAddress:
		fmt.Printf("[vm_state::GetStorage] caller's address %s belongs to AssetTransfer contract\n", address.String())
		// Fetching caller's address from "a0" variable
		callerBytes, err := st.cache.GetStorage(address, a0)
		if err != nil {
			st.PushError(err)
			return
		}
		// We assume the bytes we have read from cache represent a valid EVM address
		srcAccount, err := crypto.AddressFromBytes(bytes.TrimLeft(callerBytes, trimCutSet))
		if err != nil {
			st.PushError(err)
			return
		}

		// Fetching caller's address from "a1" variable
		dstBytes, err := st.cache.GetStorage(address, a1)
		if err != nil {
			st.PushError(err)
			return
		}
		dstAccount := string(bytes.TrimLeft(dstBytes, trimCutSet))

		// Fetching transfer amount from "a2" variable
		amountBytes, err := st.cache.GetStorage(address, a2)
		if err != nil {
			st.PushError(err)
			return
		}
		amount := string(bytes.TrimLeft(amountBytes, trimCutSet))

		err = st.backend.(*IrohaAppState).TransferAsset(irohaAccountID(srcAccount), dstAccount, amount, key)
		if err != nil {
			st.PushError(err)
			return
		}
	case otherAssetTransferAddress:
		fmt.Printf("[vm_state::GetStorage] caller's address %s belongs to OtherAssetTransfer contract\n", address.String())
		// Fetching src address from "a0" variable
		srcBytes, err := st.cache.GetStorage(address, a0)
		if err != nil {
			st.PushError(err)
			return
		}
		srcAccount := string(bytes.TrimLeft(srcBytes, trimCutSet))

		// Fetching caller's address from "a1" variable
		dstBytes, err := st.cache.GetStorage(address, a1)
		if err != nil {
			st.PushError(err)
			return
		}
		dstAccount := string(bytes.TrimLeft(dstBytes, trimCutSet))

		// Fetching transfer amount from "a2" variable
		amountBytes, err := st.cache.GetStorage(address, a2)
		if err != nil {
			st.PushError(err)
			return
		}
		amount := string(bytes.TrimLeft(amountBytes, trimCutSet))

		err = st.backend.(*IrohaAppState).TransferAsset(srcAccount, dstAccount, amount, key)
		if err != nil {
			st.PushError(err)
			return
		}
	default:
		var err error
		value, err = st.cache.GetStorage(address, key)
		if err != nil {
			st.PushError(err)
			return
		}
	}
	return
}

func (st *State) GetBalance(address crypto.Address) uint64 {
	acc := st.account(address)
	if acc == nil {
		return 0
	}
	return acc.Balance
}

func (st *State) GetPermissions(address crypto.Address) permission.AccountPermissions {
	acc := st.account(address)
	if acc == nil {
		return permission.AccountPermissions{}
	}
	return acc.Permissions
}

func (st *State) GetEVMCode(address crypto.Address) acm.Bytecode {
	acc := st.account(address)
	if acc == nil {
		return nil
	}
	return acc.EVMCode
}

func (st *State) GetWASMCode(address crypto.Address) acm.Bytecode {
	acc := st.account(address)
	if acc == nil {
		return nil
	}

	return acc.WASMCode
}

func (st *State) GetCodeHash(address crypto.Address) []byte {
	acc := st.account(address)
	if acc == nil || len(acc.CodeHash) == 0 {
		return nil
	}
	return acc.CodeHash
}

func (st *State) Exists(address crypto.Address) bool {
	acc, err := st.cache.GetAccount(address)
	if err != nil {
		st.PushError(err)
		return false
	}
	if acc == nil {
		return false
	}
	return true
}

func (st *State) GetSequence(address crypto.Address) uint64 {
	acc := st.account(address)
	if acc == nil {
		return 0
	}
	return acc.Sequence
}

func (st *State) GetForebear(address crypto.Address) crypto.Address {
	acc := st.account(address)
	if acc == nil && acc.Forebear != nil {
		return *acc.Forebear
	}
	return address
}

// Writer

func (st *State) CreateAccount(address crypto.Address) {
	if st.Exists(address) {
		st.PushError(errors.ErrorCodef(errors.ErrorCodeDuplicateAddress,
			"tried to create an account at an address that already exists: %v", address))
		return
	}
	st.updateAccount(&acm.Account{Address: address})
}

func (st *State) InitCode(address crypto.Address, code []byte) {
	st.initCode(address, nil, code)
}

func (st *State) InitChildCode(address crypto.Address, parent crypto.Address, code []byte) {
	st.initCode(address, &parent, code)

}

func (st *State) initCode(address crypto.Address, parent *crypto.Address, code []byte) {
	acc := st.mustAccount(address)
	if acc == nil {
		st.PushError(errors.ErrorCodef(errors.ErrorCodeInvalidAddress,
			"tried to initialise code for an account that does not exist: %v", address))
		return
	}
	if acc.EVMCode != nil || acc.WASMCode != nil {
		st.PushError(errors.ErrorCodef(errors.ErrorCodeIllegalWrite,
			"tried to initialise code for a contract that already exists: %v", address))
		return
	}

	acc.EVMCode = code

	// keccak256 hash of a contract's code
	hash := sha3.NewKeccak256()
	hash.Write(code)
	codehash := hash.Sum(nil)

	forebear := &address
	metamap := acc.ContractMeta
	if parent != nil {
		// find our ancestor, i.e. the initial contract that was deployed, from which this contract descends
		ancestor := st.mustAccount(*parent)
		if ancestor.Forebear != nil {
			ancestor = st.mustAccount(*ancestor.Forebear)
			forebear = ancestor.Forebear
		} else {
			forebear = parent
		}
		metamap = ancestor.ContractMeta
	}

	// If we have a list of ABIs for this contract, we also know what contract code it is allowed to create
	// For compatibility with older contracts, allow any contract to be created if we have no mappings
	if metamap != nil && len(metamap) > 0 {
		found := codehashPermitted(codehash, metamap)

		// Libraries lie about their deployed bytecode
		if !found {
			deployCodehash := compile.GetDeployCodeHash(code, address)
			found = codehashPermitted(deployCodehash, metamap)
		}

		if !found {
			st.PushError(errors.ErrorCodeInvalidContractCode)
			return
		}
	}

	acc.CodeHash = codehash
	acc.Forebear = forebear

	st.updateAccount(acc)
}

func codehashPermitted(codehash []byte, metamap []*acm.ContractMeta) bool {
	for _, m := range metamap {
		if bytes.Equal(codehash, m.CodeHash) {
			return true
		}
	}

	return false
}

func (st *State) InitWASMCode(address crypto.Address, code []byte) {
	acc := st.mustAccount(address)
	if acc == nil {
		st.PushError(errors.ErrorCodef(errors.ErrorCodeInvalidAddress,
			"tried to initialise code for an account that does not exist: %v", address))
		return
	}
	if acc.EVMCode != nil || acc.WASMCode != nil {
		st.PushError(errors.ErrorCodef(errors.ErrorCodeIllegalWrite,
			"tried to initialise code for a contract that already exists: %v", address))
		return
	}

	acc.WASMCode = code
	// keccak256 hash of a contract's code
	hash := sha3.NewKeccak256()
	hash.Write(code)
	acc.CodeHash = hash.Sum(nil)
	st.updateAccount(acc)
}

func (st *State) UpdateMetaMap(address crypto.Address, mapping []*acm.ContractMeta) {
	acc := st.mustAccount(address)
	if acc == nil {
		st.PushError(errors.ErrorCodef(errors.ErrorCodeInvalidAddress,
			"tried to initialise code for an account that does not exist: %v", address))
		return
	}
	acc.ContractMeta = mapping
	st.updateAccount(acc)
}

func (st *State) SetMetadata(metahash acmstate.MetadataHash, abi string) error {
	return st.cache.SetMetadata(metahash, abi)
}

func (st *State) RemoveAccount(address crypto.Address) {
	if !st.Exists(address) {
		st.PushError(errors.ErrorCodef(errors.ErrorCodeDuplicateAddress,
			"tried to remove an account at an address that does not exist: %v", address))
		return
	}
	st.removeAccount(address)
}

func (st *State) SetStorage(address crypto.Address, key binary.Word256, value []byte) {
	err := st.cache.SetStorage(address, key, value)
	if err != nil {
		st.PushError(err)
	}
}

func (st *State) AddToBalance(address crypto.Address, amount uint64) {
	acc := st.mustAccount(address)
	if acc == nil {
		return
	}
	st.PushError(acc.AddToBalance(amount))
	st.updateAccount(acc)
}

func (st *State) SubtractFromBalance(address crypto.Address, amount uint64) {
	acc := st.mustAccount(address)
	if acc == nil {
		return
	}
	st.PushError(acc.SubtractFromBalance(amount))
	st.updateAccount(acc)
}

func (st *State) SetPermission(address crypto.Address, permFlag permission.PermFlag, value bool) {
	acc := st.mustAccount(address)
	if acc == nil {
		return
	}
	st.PushError(acc.Permissions.Base.Set(permFlag, value))
	st.updateAccount(acc)
}

func (st *State) UnsetPermission(address crypto.Address, permFlag permission.PermFlag) {
	acc := st.mustAccount(address)
	if acc == nil {
		return
	}
	st.PushError(acc.Permissions.Base.Unset(permFlag))
	st.updateAccount(acc)
}

func (st *State) AddRole(address crypto.Address, role string) bool {
	acc := st.mustAccount(address)
	if acc == nil {
		return false
	}
	added := acc.Permissions.AddRole(role)
	st.updateAccount(acc)
	return added
}

func (st *State) RemoveRole(address crypto.Address, role string) bool {
	acc := st.mustAccount(address)
	if acc == nil {
		return false
	}
	removed := acc.Permissions.RemoveRole(role)
	st.updateAccount(acc)
	return removed
}

func (st *State) GetBlockHash(height uint64) (binary.Word256, error) {
	hash := st.blockHashGetter(height)
	if len(hash) == 0 {
		st.PushError(fmt.Errorf("got empty BlockHash from blockHashGetter"))
	}
	return binary.LeftPadWord256(hash), nil
}

// Helpers

func (st *State) account(address crypto.Address) *acm.Account {
	acc, err := st.cache.GetAccount(address)
	if err != nil {
		st.PushError(err)
	}
	return acc
}

func (st *State) mustAccount(address crypto.Address) *acm.Account {
	acc := st.account(address)
	if acc == nil {
		st.PushError(errors.ErrorCodef(errors.ErrorCodeIllegalWrite,
			"attempted to modify non-existent account: %v", address))
	}
	return acc
}

func (st *State) updateAccount(account *acm.Account) {
	err := st.cache.UpdateAccount(account)
	if err != nil {
		st.PushError(err)
	}
}

func (st *State) removeAccount(address crypto.Address) {
	err := st.cache.RemoveAccount(address)
	if err != nil {
		st.PushError(err)
	}
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
