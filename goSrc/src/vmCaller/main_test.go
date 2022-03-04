package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/hyperledger/burrow/acm/acmstate"
	"github.com/hyperledger/burrow/crypto"
	"github.com/hyperledger/burrow/execution/engine"
	"github.com/hyperledger/burrow/execution/exec"
	"github.com/stretchr/testify/suite"
	"github.com/tmthrgd/go-hex"
	"io/ioutil"
	"net/http"
	"sync"
	"testing"
)

type engineSuccess struct {
	output []byte
}

func (e *engineSuccess) Execute(st acmstate.ReaderWriter, blockchain engine.Blockchain,
	eventSink exec.EventSink, params engine.CallParams, code []byte) ([]byte, error) {
	return e.output, nil
}

type engineFailure struct {
}

func (e *engineFailure) Execute(st acmstate.ReaderWriter, blockchain engine.Blockchain,
	eventSink exec.EventSink, params engine.CallParams, code []byte) ([]byte, error) {
	return nil, errors.New("Error executing contract")
}

type VmCallerTestSuite struct {
	suite.Suite

	state     acmstate.ReaderWriter
	eventSink exec.EventSink
	engineOk  *EngineWrapper
	engineErr *EngineWrapper
}

func (s *VmCallerTestSuite) SetupSuite() {
	s.state = acmstate.NewMemoryState()
	s.eventSink = exec.NewNoopEventSink()
	s.engineOk = &EngineWrapper{
		engine: &engineSuccess{
			output: []byte("01"),
		},
		state:     s.state,
		eventSink: s.eventSink,
	}
	s.engineErr = &EngineWrapper{
		engine:    &engineFailure{},
		state:     s.state,
		eventSink: s.eventSink,
	}
}

func (s *VmCallerTestSuite) TestStart() {
}

func (s *VmCallerTestSuite) TestStop() {
}

func (s *VmCallerTestSuite) TestCheck() {

	caller := crypto.MustAddressFromHexString("0123456789ABCDEF0123456789ABCDEF01234567")
	code := hex.MustDecodeString("C0DE")
	input := hex.MustDecodeString("0000000000000000000000000000000000000000000000000000000000000001")
	nonce := "414243444546"

	// Test successful contract deployment
	callee, err := s.engineOk.NewContract(caller, code, nonce)
	s.Require().NoError(err)
	s.Require().Equal("D9EB767B19A58B514765B844D0BCF0CD221660AC", callee)

	// Test deployment failure if callee already exists
	_, err = s.engineOk.NewContract(caller, code, nonce)
	s.Require().Error(err)
	s.Require().Equal("Account already exists at address D9EB767B19A58B514765B844D0BCF0CD221660AC", err.Error())

	// Test successful contract execution
	output, err := s.engineOk.Execute(caller, crypto.MustAddressFromHexString(callee), input)
	s.Require().NoError(err)
	s.Require().Equal([]byte("01"), output)

	// Test error during contract execution
	output, err = s.engineErr.Execute(caller, crypto.MustAddressFromHexString(callee), input)
	s.Require().Error(err)
	s.Require().Equal("Error calling smart contract at address D9EB767B19A58B514765B844D0BCF0CD221660AC: Error executing contract", err.Error())
}

func TestVmCallerTestSuite(t *testing.T) {
	suite.Run(t, new(VmCallerTestSuite))
}

func TestCallSim(t *testing.T) {
	address := "http://0.0.0.0:28660"
	data := `{"jsonrpc":"2.0","method":"eth_call","params":[{"from": "admin@test", "to" :"6A26161FAEC585CD038268D656E2E19DA63FCF04", "data": "2c74aaaf00000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000000a61646D696E407465737400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a77747223656E6572677900000000000000000000000000000000000000000000" }, "latest"],"id":1}`
	var wg sync.WaitGroup
	for i := 0; i < 1; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, err := http.NewRequest("POST", address, bytes.NewBuffer([]byte(data)))
			if err != nil {
				fmt.Println(err.Error())
				fmt.Println("creating req failed", err)
				return
			}
			req.Header.Set("Content-Type", "application/json")
			client := http.Client{}
			resp, err := client.Do(req)
			if err != nil {
				return
			}
			var result jsonrpcResult
			body, err := ioutil.ReadAll(resp.Body)
			json.Unmarshal(body, &result)
			if result.Result != "0x00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000043235303000000000000000000000000000000000000000000000000000000000" {
				return
			}
			defer resp.Body.Close()
		}()
	}
	wg.Wait()
}
