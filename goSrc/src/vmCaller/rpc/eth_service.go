package rpc

import (
	myExecution "vmCaller/execution"

	"github.com/hyperledger/burrow/acm/acmstate"
	"github.com/hyperledger/burrow/acm/validator"
	bcm "github.com/hyperledger/burrow/bcm"
	"github.com/hyperledger/burrow/consensus/tendermint"
	"github.com/hyperledger/burrow/crypto"
	x "github.com/hyperledger/burrow/encoding/hex"
	"github.com/hyperledger/burrow/execution"
	"github.com/hyperledger/burrow/execution/exec"
	"github.com/hyperledger/burrow/execution/state"
	"github.com/hyperledger/burrow/keys"
	"github.com/hyperledger/burrow/logging"
	"github.com/hyperledger/burrow/project"
	"github.com/hyperledger/burrow/rpc/web3"
	"github.com/hyperledger/burrow/txs"
	"github.com/hyperledger/burrow/txs/payload"
	tmConfig "github.com/tendermint/tendermint/config"
	"github.com/tendermint/tendermint/types"
)

const (
	chainID      = 1
	maxGasLimit  = 2<<52 - 1
	hexZero      = "0x0"
	hexZeroNonce = "0x0000000000000000"
	pending      = "null"
)

// EthService is a web3 provider
type EthService struct {
	accounts   acmstate.IterableStatsReader
	events     EventsReader
	blockchain bcm.BlockchainInfo
	validators validator.History
	nodeView   *tendermint.NodeView
	trans      *execution.Transactor
	keyClient  keys.KeyClient
	keyStore   *keys.KeyStore
	config     *tmConfig.Config
	logger     *logging.Logger
}

// NewEthService returns our web3 provider
func NewEthService(accounts acmstate.IterableStatsReader,
	events EventsReader, blockchain bcm.BlockchainInfo,
	validators validator.History, nodeView *tendermint.NodeView,
	trans *execution.Transactor, keyStore *keys.KeyStore,
	logger *logging.Logger) *EthService {

	keyClient := keys.NewLocalKeyClient(keyStore, logger)

	return &EthService{
		accounts,
		events,
		blockchain,
		validators,
		nodeView,
		trans,
		keyClient,
		keyStore,
		tmConfig.DefaultConfig(),
		logger,
	}
}

var _ web3.Service = &EthService{}

type EventsReader interface {
	TxsAtHeight(height uint64) ([]*exec.TxExecution, error)
	TxByHash(txHash []byte) (*exec.TxExecution, error)
}

var _ EventsReader = &state.State{}

// Web3ClientVersion returns the version of burrow
func (srv *EthService) Web3ClientVersion() (*web3.Web3ClientVersionResult, error) {
	return &web3.Web3ClientVersionResult{
		ClientVersion: project.FullVersion(),
	}, nil
}

// Web3Sha3 returns Keccak-256 (not the standardized SHA3-256) of the given data
func (srv *EthService) Web3Sha3(req *web3.Web3Sha3Params) (*web3.Web3Sha3Result, error) {
	data, err := x.DecodeToBytes(req.Data)
	if err != nil {
		return nil, err
	}

	return &web3.Web3Sha3Result{
		HashedData: x.EncodeBytes(crypto.Keccak256(data)),
	}, nil
}

// NetListening returns true if the peer is running
func (srv *EthService) NetListening() (*web3.NetListeningResult, error) {
	return &web3.NetListeningResult{
		IsNetListening: srv.nodeView.NodeInfo().GetListenAddress() != "",
	}, nil
}

// NetPeerCount returns the number of connected peers
func (srv *EthService) NetPeerCount() (*web3.NetPeerCountResult, error) {
	return &web3.NetPeerCountResult{
		NumConnectedPeers: x.EncodeNumber(uint64(srv.nodeView.Peers().Size())),
	}, nil
}

// NetVersion returns the hex encoding of the network id,
// this is typically a small int (where 1 == Ethereum mainnet)
func (srv *EthService) NetVersion() (*web3.NetVersionResult, error) {
	return &web3.NetVersionResult{
		ChainID: x.EncodeNumber(uint64(chainID)),
	}, nil
}

func (srv *EthService) EthProtocolVersion() (*web3.EthProtocolVersionResult, error) {
	return nil, web3.ErrNotFound
}

func (srv *EthService) EthChainId() (*web3.EthChainIdResult, error) {
	return nil, web3.ErrNotFound
}

func (srv *EthService) EthBlockNumber() (*web3.EthBlockNumberResult, error) {
	return nil, web3.ErrNotFound
}

// EthCall executes a new message call immediately without creating a transaction
func (srv *EthService) EthCall(req *web3.EthCallParams) (*web3.EthCallResult, error) {
	var to crypto.Address
	var from string
	var err error

	if addr := req.Transaction.To; addr != "" {
		to, err = x.DecodeToAddress(addr)
		if err != nil {
			return nil, err
		}
	}

	if addr := req.Transaction.From; addr != "" {
		from = addr
	}

	data, err := x.DecodeToBytes(req.Transaction.Data)
	if err != nil {
		return nil, err
	}
	txe, err := myExecution.CallSim(srv.accounts, srv.blockchain, from, to, data, srv.logger)
	if err != nil {
		return nil, err
	} else if txe.Exception != nil {
		return nil, txe.Exception.AsError()
	}

	var result string
	if r := txe.GetResult(); r != nil {
		result = x.EncodeBytes(r.GetReturn())
	}

	return &web3.EthCallResult{
		ReturnValue: result,
	}, nil
}

func (srv *EthService) EthGetBalance(req *web3.EthGetBalanceParams) (*web3.EthGetBalanceResult, error) {
	return nil, web3.ErrNotFound
}

func (srv *EthService) EthGetBlockByHash(req *web3.EthGetBlockByHashParams) (*web3.EthGetBlockByHashResult, error) {
	return nil, web3.ErrNotFound
}

func (srv *EthService) EthGetBlockByNumber(req *web3.EthGetBlockByNumberParams) (*web3.EthGetBlockByNumberResult, error) {
	return nil, web3.ErrNotFound
}

func (srv *EthService) EthGetBlockTransactionCountByHash(req *web3.EthGetBlockTransactionCountByHashParams) (*web3.EthGetBlockTransactionCountByHashResult, error) {
	return nil, web3.ErrNotFound
}

func (srv *EthService) EthGetBlockTransactionCountByNumber(req *web3.EthGetBlockTransactionCountByNumberParams) (*web3.EthGetBlockTransactionCountByNumberResult, error) {
	return nil, web3.ErrNotFound
}

func (srv *EthService) EthGetCode(req *web3.EthGetCodeParams) (*web3.EthGetCodeResult, error) {
	return nil, web3.ErrNotFound
}

func (srv *EthService) EthGetStorageAt(req *web3.EthGetStorageAtParams) (*web3.EthGetStorageAtResult, error) {
	return nil, web3.ErrNotFound
}

func (srv *EthService) EthGetTransactionByBlockHashAndIndex(req *web3.EthGetTransactionByBlockHashAndIndexParams) (*web3.EthGetTransactionByBlockHashAndIndexResult, error) {
	return nil, web3.ErrNotFound
}

func (srv *EthService) EthGetTransactionByBlockNumberAndIndex(req *web3.EthGetTransactionByBlockNumberAndIndexParams) (*web3.EthGetTransactionByBlockNumberAndIndexResult, error) {
	return nil, web3.ErrNotFound
}

func (srv *EthService) EthGetTransactionByHash(req *web3.EthGetTransactionByHashParams) (*web3.EthGetTransactionByHashResult, error) {
	return nil, web3.ErrNotFound
}

func (srv *EthService) EthGetTransactionCount(req *web3.EthGetTransactionCountParams) (*web3.EthGetTransactionCountResult, error) {
	return nil, web3.ErrNotFound
}

func getHashAndCallTxFromEnvelope(env *txs.Envelope) ([]byte, *payload.CallTx, error) {
	return nil, nil, web3.ErrNotFound
}

func getHashAndCallTxFromExecution(txe *exec.TxExecution) ([]byte, *payload.CallTx, error) {
	return nil, nil, web3.ErrNotFound
}

func (srv *EthService) EthGetTransactionReceipt(req *web3.EthGetTransactionReceiptParams) (*web3.EthGetTransactionReceiptResult, error) {
	return nil, web3.ErrNotFound
}

func (srv *EthService) EthHashrate() (*web3.EthHashrateResult, error) {
	return nil, web3.ErrNotFound
}

func (srv *EthService) EthMining() (*web3.EthMiningResult, error) {
	return nil, web3.ErrNotFound
}

func (srv *EthService) EthPendingTransactions() (*web3.EthPendingTransactionsResult, error) {
	return nil, web3.ErrNotFound
}

func (srv *EthService) EthEstimateGas(req *web3.EthEstimateGasParams) (*web3.EthEstimateGasResult, error) {
	return &web3.EthEstimateGasResult{
		GasUsed: hexZero,
	}, nil
}

func (srv *EthService) EthGasPrice() (*web3.EthGasPriceResult, error) {
	return &web3.EthGasPriceResult{
		GasPrice: hexZero,
	}, nil
}

type RawTx struct {
	Nonce    uint64 `json:"nonce"`
	GasPrice uint64 `json:"gasPrice"`
	GasLimit uint64 `json:"gasLimit"`
	To       []byte `json:"to"`
	Value    []byte `json:"value"`
	Data     []byte `json:"data"`

	V uint64 `json:"v"`
	R []byte `json:"r"`
	S []byte `json:"s"`
}

func (srv *EthService) EthGetRawTransactionByHash(req *web3.EthGetRawTransactionByHashParams) (*web3.EthGetRawTransactionByHashResult, error) {
	return nil, web3.ErrNotFound
}

func (srv *EthService) EthGetRawTransactionByBlockHashAndIndex(req *web3.EthGetRawTransactionByBlockHashAndIndexParams) (*web3.EthGetRawTransactionByBlockHashAndIndexResult, error) {
	return nil, web3.ErrNotFound
}

func (srv *EthService) EthGetRawTransactionByBlockNumberAndIndex(req *web3.EthGetRawTransactionByBlockNumberAndIndexParams) (*web3.EthGetRawTransactionByBlockNumberAndIndexResult, error) {
	return nil, web3.ErrNotFound
}

func (srv *EthService) EthSendRawTransaction(req *web3.EthSendRawTransactionParams) (*web3.EthSendRawTransactionResult, error) {
	return nil, web3.ErrNotFound
}

func (srv *EthService) EthSyncing() (*web3.EthSyncingResult, error) {
	return nil, web3.ErrNotFound
}

func (srv *EthService) getBlockHeightByHash(hash string) (uint64, error) {
	return 0, web3.ErrNotFound
}

func (srv *EthService) getBlockHeaderAtHeight(height uint64) (*types.Header, error) {
	return srv.blockchain.GetBlockHeader(height)
}

func hexKeccak(data []byte) string {
	return x.EncodeBytes(crypto.Keccak256(data))
}

func hexKeccakAddress(data []byte) string {
	addr := crypto.Keccak256(data)
	return x.EncodeBytes(addr[len(addr)-20:])
}

func (srv *EthService) getBlockInfoAtHeight(height uint64, includeTxs bool) (web3.Block, error) {
	return web3.Block{}, web3.ErrNotFound
}

func getTransaction(block *types.Header, hash []byte, tx *payload.CallTx) web3.Transaction {
	return web3.Transaction{}
}

func (srv *EthService) getHeightByWord(height string) (uint64, bool) {
	switch height {
	case "earliest":
		return 0, true
	case "latest", "pending":
		return srv.blockchain.LastBlockHeight(), true
		// TODO: pending state/transactions
	default:
		return 0, false
	}
}

func getHeightByNumber(height string) (uint64, error) {
	return 0, web3.ErrNotFound
}

func (srv *EthService) getHeightByWordOrNumber(i string) (uint64, error) {
	return 0, web3.ErrNotFound
}

func (srv *EthService) EthSendTransaction(req *web3.EthSendTransactionParams) (*web3.EthSendTransactionResult, error) {
	return nil, web3.ErrNotFound
}

// EthAccounts returns all accounts signable from the local node
func (srv *EthService) EthAccounts() (*web3.EthAccountsResult, error) {
	return nil, web3.ErrNotFound
}

func (srv *EthService) EthSign(req *web3.EthSignParams) (*web3.EthSignResult, error) {
	return nil, web3.ErrNotFound
}

// N / A

func (srv *EthService) EthUninstallFilter(*web3.EthUninstallFilterParams) (*web3.EthUninstallFilterResult, error) {
	return nil, web3.ErrNotFound
}

func (srv *EthService) EthSubmitHashrate(req *web3.EthSubmitHashrateParams) (*web3.EthSubmitHashrateResult, error) {
	return nil, web3.ErrNotFound
}

func (srv *EthService) EthSubmitWork(*web3.EthSubmitWorkParams) (*web3.EthSubmitWorkResult, error) {
	return nil, web3.ErrNotFound
}

func (srv *EthService) EthNewBlockFilter() (*web3.EthNewBlockFilterResult, error) {
	return nil, web3.ErrNotFound
}

func (srv *EthService) EthNewFilter(req *web3.EthNewFilterParams) (*web3.EthNewFilterResult, error) {
	return nil, web3.ErrNotFound
}

func (srv *EthService) EthNewPendingTransactionFilter() (*web3.EthNewPendingTransactionFilterResult, error) {
	return nil, web3.ErrNotFound
}

func (srv *EthService) EthGetUncleByBlockHashAndIndex(req *web3.EthGetUncleByBlockHashAndIndexParams) (*web3.EthGetUncleByBlockHashAndIndexResult, error) {
	return nil, web3.ErrNotFound
}

func (srv *EthService) EthGetUncleByBlockNumberAndIndex(req *web3.EthGetUncleByBlockNumberAndIndexParams) (*web3.EthGetUncleByBlockNumberAndIndexResult, error) {
	return nil, web3.ErrNotFound
}

func (srv *EthService) EthGetUncleCountByBlockHash(req *web3.EthGetUncleCountByBlockHashParams) (*web3.EthGetUncleCountByBlockHashResult, error) {
	return nil, web3.ErrNotFound
}

func (srv *EthService) EthGetUncleCountByBlockNumber(req *web3.EthGetUncleCountByBlockNumberParams) (*web3.EthGetUncleCountByBlockNumberResult, error) {
	return nil, web3.ErrNotFound
}

func (srv *EthService) EthGetProof(req *web3.EthGetProofParams) (*web3.EthGetProofResult, error) {
	return nil, web3.ErrNotFound
}

func (srv *EthService) EthGetWork() (*web3.EthGetWorkResult, error) {
	return nil, web3.ErrNotFound
}

func (srv *EthService) EthGetFilterChanges(req *web3.EthGetFilterChangesParams) (*web3.EthGetFilterChangesResult, error) {
	return nil, web3.ErrNotFound
}

func (srv *EthService) EthGetFilterLogs(req *web3.EthGetFilterLogsParams) (*web3.EthGetFilterLogsResult, error) {
	return nil, web3.ErrNotFound
}

func (srv *EthService) EthCoinbase() (*web3.EthCoinbaseResult, error) {
	return nil, web3.ErrNotFound
}

func (srv *EthService) EthGetLogs(req *web3.EthGetLogsParams) (*web3.EthGetLogsResult, error) {
	return nil, web3.ErrNotFound
}
