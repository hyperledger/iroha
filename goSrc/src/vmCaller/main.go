package main

import "C"
import (
	"encoding/binary"
	"fmt"
	"time"

	"vmCaller/state"

	"github.com/hyperledger/burrow/acm"
	"github.com/hyperledger/burrow/crypto"
	"github.com/hyperledger/burrow/execution/engine"
	"github.com/hyperledger/burrow/execution/errors"
	"github.com/hyperledger/burrow/execution/evm"
	"github.com/hyperledger/burrow/execution/exec"
	"github.com/hyperledger/burrow/execution/native"
	"github.com/hyperledger/burrow/permission"
	"github.com/tmthrgd/go-hex"
	"golang.org/x/crypto/ripemd160"
	"strconv"
	"unsafe"
)

const defaultPermissions permission.PermFlag = permission.Send | permission.Call | permission.CreateContract | permission.CreateAccount

type blockchain struct {
	blockHeight uint64
	blockTime   time.Time
}

func (b *blockchain) LastBlockHeight() uint64 {
	return b.blockHeight
}

func (b *blockchain) LastBlockTime() time.Time {
	return b.blockTime
}

func (b *blockchain) BlockHash(height uint64) ([]byte, error) {
	if height > b.blockHeight {
		return nil, errors.Codes.InvalidBlockNumber
	}
	bs := make([]byte, 32)
	binary.BigEndian.PutUint64(bs[24:], height)
	return bs, nil
}

// toEVMaddress converts any string to EVM address
func toEVMaddress(name string) crypto.Address {
	hasher := ripemd160.New()
	hasher.Write([]byte(name))
	return crypto.MustAddressFromBytes(hasher.Sum(nil))
}

// Real application state
var appState = state.NewIrohaAppState()

// Create EVM instance
var burrowEVM = evm.Default()

//export VmCall
func VmCall(input, caller, callee *C.char, commandExecutor unsafe.Pointer, queryExecutor unsafe.Pointer) (*C.char, bool) {

	// Update executors
	appState.SetCommandExecutor(commandExecutor)
	appState.SetQueryExecutor(queryExecutor)

	// The wrapper for EVM state.
	// Contains real application state (here it is the appState) and it's cache.
	// Since Iroha state changes are possible between VmCall invocations,
	// cache should be synced with appState to prevent using of invalid data.
	var evmState = state.NewState(appState)

	// Convert strings into EVM addresses
	evmCaller := toEVMaddress(C.GoString(caller))
	evmCallee := toEVMaddress(C.GoString(callee))

	goInput := hex.MustDecodeString(C.GoString(input))

	// Check if caller account exists
	callerAccount, err := evmState.GetAccount(evmCaller)
	if err != nil {
		fmt.Println(err, "Error while getting account at caller addr: ", evmCaller.String())
		return nil, false
	}
	if callerAccount == nil {
		err := native.CreateAccount(evmState, evmCaller)
		if err != nil {
			fmt.Println(err, "Error while creating account at caller addr: ", evmCaller.String())
			return nil, false
		}
		err = native.UpdateAccount(evmState, evmCaller, func(acc *acm.Account) error {
			return acc.Permissions.Base.Set(defaultPermissions, true)
		})
		if err != nil {
			fmt.Println(err, "Error while setting permissions for account at caller addr: ", evmCaller.String())
			return nil, false
		}
		// TODO: study if storing the original Iroha accountID of the caller is necessary
		// appState.SetParentID(evmCaller, "ParentID", []byte(C.GoString(caller)))
	}

	// Check if callee account exists
	// and prepare to store EVM bytecode

	var gas uint64 = 1000000
	var output acm.Bytecode

	calleeAccount, err := evmState.GetAccount(evmCallee)
	if err != nil {
		fmt.Println(err, "Error while getting account at callee addr: ", evmCallee.String())
		return nil, false
	}
	if calleeAccount == nil {
		// Then smart contract should be deployed
		fmt.Printf("No EVM account exists for the callee %s. Creating account\n", evmCallee)
		err := native.CreateAccount(evmState, evmCallee)
		if err != nil {
			fmt.Println(err, "Error while creating account at callee addr: ", evmCallee.String())
			return nil, false
		}
		// Pass goInput as deployment data
		params := engine.CallParams{
			Caller: evmCaller,
			Callee: evmCallee,
			Input:  []byte{},
			Value:  0,
			Gas:    &gas,
		}
		output, err = burrowEVM.Execute(evmState, new(blockchain), exec.NewNoopEventSink(), params, goInput)
		if err != nil {
			fmt.Println(err)
			fmt.Println("Error while deploying smart contract at addr ", evmCallee.String(), ", input ", goInput)
			return nil, false
		}
		err = native.InitCode(evmState, evmCallee, output)
		if err != nil {
			fmt.Println(err, "Error while initializing code for account at callee addr: ", evmCallee.String())
			return nil, false
		}
		err = native.UpdateAccount(evmState, evmCallee, func(acc *acm.Account) error {
			return acc.Permissions.Base.Set(defaultPermissions, true)
		})
		if err != nil {
			fmt.Println(err, "Error while setting permissions for account at callee addr: ", evmCallee.String())
			return nil, false
		}
	} else {
		// Pass goInput as function call
		params := engine.CallParams{
			Caller: evmCaller,
			Callee: evmCallee,
			Input:  goInput,
			Value:  0,
			Gas:    &gas,
		}
		output, err = burrowEVM.Execute(evmState, new(blockchain), exec.NewNoopEventSink(), params, calleeAccount.EVMCode)
		if err != nil {
			fmt.Println(err)
			fmt.Println("Error while calling smart contract at addr ", evmCallee.String(), ", input ", goInput)
			return nil, false
		}
	}

	// If there is no errors after smart contract execution, cache data is written to Iroha.
	if err = evmState.Sync(appState); err != nil {
		fmt.Println(err, "Sync error")
		return nil, false
	}

	// Transform output data to a string value.
	// It is a problem to convert []byte, which contains 0 byte inside, to C string.
	// Conversion to C.CString will cut all data after the 0 byte.
	res := ""
	for _, dataAsInt := range output {

		// change base to hex
		tmp := strconv.FormatInt(int64(dataAsInt), 16)

		// save bytecode structure, where hex value f should be 0f, and so on
		if len(tmp) < 2 {
			// len 1 at least after conversion from variable output
			tmp = "0" + tmp
		}
		res += tmp
	}

	return C.CString(res), true
}

func main() {}
