package main

import "C"
import (
	"bytes"
	"errors"
	"fmt"
	"github.com/hyperledger/burrow/execution/evm"

	"github.com/hyperledger/burrow/acm"
	"github.com/hyperledger/burrow/binary"
	. "github.com/hyperledger/burrow/binary"
	"github.com/hyperledger/burrow/crypto"
	"github.com/hyperledger/burrow/logging"
	"github.com/tmthrgd/go-hex"
	"golang.org/x/crypto/ripemd160"
)

type BalanceType = uint64

type IrohaAppState struct {
	accounts map[crypto.Address]*acm.Account
	storage  map[string][]byte
	code     map[crypto.Address]*acm.Bytecode
	balance  map[crypto.Address]BalanceType
}

func (state *IrohaAppState) CreateAccount(addr crypto.Address) (*acm.Account, error) {
	account := new(acm.Account)
	if _, exist := state.accounts[addr]; exist {
		return account, errors.New("account already exists")
	}
	state.accounts[addr] = account
	return account, nil
}

func (state *IrohaAppState) GetAccount(addr crypto.Address) (*acm.Account, error) {
	account, exist := state.accounts[addr]
	if !exist {
		return account, errors.New("account does not exist")
	}
	return account, nil
}

func (state *IrohaAppState) UpdateAccount(account *acm.Account) error {
	state.accounts[account.GetAddress()] = account
	return nil
}

func (state *IrohaAppState) RemoveAccount(address crypto.Address) error {
	_, ok := state.accounts[address]
	if !ok {
		return errors.New("tried to delete non-existing account")
	} else {
		// Remove account
		delete(state.accounts, address)
		delete(state.code, address)
		delete(state.balance, address)
	}
	return nil
}

func (state *IrohaAppState) GetStorage(addr crypto.Address, key Word256) ([]byte, error) {
	_, ok := state.accounts[addr]
	if !ok {
		return []byte{}, errors.New("no such account to get key")
	}

	value, ok := state.storage[addr.String()+key.String()]
	if ok {
		return value, nil
	} else {
		return []byte{}, nil
	}
}

func (state *IrohaAppState) SetStorage(addr crypto.Address, key Word256, value []byte) error {
	_, ok := state.accounts[addr]
	if !ok {
		return errors.New("no such account to set key with word")
	}

	state.storage[addr.String()+key.String()] = value
	return nil
}

func (state *IrohaAppState) Exists(address crypto.Address) bool {
	_, ok := state.accounts[address];
	return ok
}

func (state *IrohaAppState) GetCode(address crypto.Address) acm.Bytecode {
	if code, ok := state.code[address]; ok {
		return *code
	}
	return nil
}

func (state *IrohaAppState) InitCode(address crypto.Address, code []byte) {
	if _, ok := state.accounts[address]; ok {
		_, codeExist := state.code[address]
		if !codeExist {
			newCode := acm.Bytecode(code)
			state.code[address] = &newCode
		} else {
			panic("Code on this address already exit")
		}
	} else {
		panic("No addr for code to init")
	}
}

func (state *IrohaAppState) AddToBalance(address crypto.Address, amount uint64) {
	if _, exist := state.accounts[address]; exist{
		state.balance[address] += amount
	} else {
		panic("Cannot add to account balance")
	}
}

func (state *IrohaAppState) SubtractFromBalance(address crypto.Address, amount uint64) {
	if _, exist := state.accounts[address]; exist{
		state.balance[address] -= amount
	} else {
		panic("Cannot subtract from account balance")
	}
}

func (state *IrohaAppState) accountsDump() string {
	buf := new(bytes.Buffer)
	_,_ = fmt.Fprint(buf, "Dumping accounts...", "\n")
	for _, acc := range state.accounts {
		_, _ = fmt.Fprint(buf, acc.GetAddress().String(), "\n")
	}
	return buf.String()
}

func newAppState() *IrohaAppState {
	state := &IrohaAppState{
		make(map[crypto.Address]*acm.Account),
		make(map[string][]byte),
		make(map[crypto.Address]*acm.Bytecode),
		make(map[crypto.Address]BalanceType),
	}
	// For default permissions
	//fas.accounts[acm.GlobalPermissionsAddress] = &acm.Account{
	//	Permissions: permission.DefaultAccountPermissions,
	//}
	return state
}

func newParams() evm.Params {
	return evm.Params{
		BlockHeight: 0,
		BlockTime:   0,
		GasLimit:    0,
	}
}

func newAddress(name string) crypto.Address {
	hasher := ripemd160.New()
	hasher.Write([]byte(name))
	return crypto.MustAddressFromBytes(hasher.Sum(nil))
}

func blockHashGetter(height uint64) []byte {
	return binary.LeftPadWord256([]byte(fmt.Sprintf("block_hash_%d", height))).Bytes()
}


var logger = logging.NewNoopLogger()
var ourVm = evm.NewVM(newParams(), crypto.ZeroAddress, nil, logger)
var cache = evm.NewState(newAppState(), blockHashGetter)


//export VmCall
func VmCall(code, input, caller, callee *C.char) (*C.char, bool) {

	// Create accounts
	account1 := newAddress(C.GoString(caller))
	account2 := newAddress(C.GoString(callee))

	var gas uint64 = 1000000
	goByteCode := C.GoString(code)
	goInput := []byte(C.GoString(input))
	fmt.Printf("%d\n\n\n%s\n\n\n", len(goByteCode), goByteCode)
	decodedCode := hex.MustDecodeString(goByteCode)
	output, err := ourVm.Call(cache, evm.NewNoopEventSink(), account1, account2,
		decodedCode, goInput, 0, &gas)

	fmt.Println("\n\n\nCODE WAS EXECUTED\n\n\n")
	if err == nil {
		fmt.Println("\n\n\nALL RIGHT\n\n\n")
		return C.CString(string(output)), true
	} else {
		fmt.Println(err)
		fmt.Println("\n\n\nNOT NIL\n\n\n")
		return C.CString(string(output)), false
	}
}


func main() {}

