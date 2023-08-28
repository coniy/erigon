package commands

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/holiman/uint256"
	"github.com/ledgerwatch/erigon-lib/chain"
	"github.com/ledgerwatch/erigon-lib/common"
	"github.com/ledgerwatch/erigon/accounts/abi"
	"github.com/ledgerwatch/erigon/common/hexutil"
	"github.com/ledgerwatch/erigon/common/math"
	"github.com/ledgerwatch/erigon/consensus/misc"
	"github.com/ledgerwatch/erigon/core"
	"github.com/ledgerwatch/erigon/core/state"
	"github.com/ledgerwatch/erigon/core/types"
	"github.com/ledgerwatch/erigon/core/vm"
	"github.com/ledgerwatch/erigon/core/vm/evmtypes"
	"github.com/ledgerwatch/erigon/crypto"
	"github.com/ledgerwatch/erigon/eth/tracers"
	"github.com/ledgerwatch/erigon/rpc"
	"github.com/ledgerwatch/erigon/searcher"
	"github.com/ledgerwatch/erigon/turbo/adapter/ethapi"
	"github.com/ledgerwatch/erigon/turbo/rpchelper"
	"github.com/ledgerwatch/erigon/turbo/transactions"
	"golang.org/x/crypto/sha3"
	"math/big"
	"time"
)

func (api *APIImpl) SearcherChainData(ctx context.Context, args searcher.ChainDataArgs) (*searcher.ChainDataResult, error) {
	if args.StateBlockNumberOrHash == (rpc.BlockNumberOrHash{}) {
		args.StateBlockNumberOrHash = rpc.BlockNumberOrHashWithNumber(rpc.LatestBlockNumber)
	}

	dbtx, err := api.db.BeginRo(ctx)
	if err != nil {
		return nil, fmt.Errorf("create ro transaction: %v", err)
	}
	defer dbtx.Rollback()

	chainConfig, err := api.chainConfig(dbtx)
	if err != nil {
		return nil, fmt.Errorf("read chain config: %v", err)
	}

	blockNumber, hash, _, err := rpchelper.GetBlockNumber(args.StateBlockNumberOrHash, dbtx, api.filters)
	if err != nil {
		return nil, err
	}

	stateReader, err := rpchelper.CreateStateReader(ctx, dbtx, args.StateBlockNumberOrHash, 0, api.filters, api.stateCache, api.historyV3(dbtx), chainConfig.ChainName)
	if err != nil {
		return nil, fmt.Errorf("create state reader: %v", err)
	}
	ibs := state.New(stateReader)

	parent, err := api._blockReader.Header(context.Background(), dbtx, hash, blockNumber)
	if err != nil {
		return nil, fmt.Errorf("could not fetch header %d(%x): %v", blockNumber, hash, err)
	}
	if parent == nil {
		return nil, fmt.Errorf("block %d(%x) not found", blockNumber, hash)
	}

	res := &searcher.ChainDataResult{
		Header:      parent,
		NextBaseFee: misc.CalcBaseFee(chainConfig, parent),
	}
	if len(args.Accounts) > 0 {
		res.Accounts = make(map[common.Address]*searcher.Account)
	}
	for account, keys := range args.Accounts {
		obj := ibs.GetOrNewStateObject(account)
		res.Accounts[account] = &searcher.Account{
			Balance: obj.Balance().ToBig(),
			Nonce:   obj.Nonce(),
		}
		if len(keys) > 0 {
			res.Accounts[account].State = make(map[common.Hash]common.Hash)
			for _, key := range keys {
				var value uint256.Int
				obj.GetState(&key, &value)
				res.Accounts[account].State[key] = value.Bytes32()
			}
		}
	}
	return res, nil
}

func (api *APIImpl) SearcherCallBundle(ctx context.Context, args searcher.CallBundleArgs) (*searcher.CallBundleResult, error) {
	if len(args.Txs) == 0 {
		return nil, errors.New("missing txs")
	}
	if args.StateBlockNumberOrHash == (rpc.BlockNumberOrHash{}) {
		args.StateBlockNumberOrHash = rpc.BlockNumberOrHashWithNumber(rpc.LatestBlockNumber)
	}
	timeoutMS := int64(5000)
	if args.Timeout != nil {
		timeoutMS = *args.Timeout
	}
	timeout := time.Millisecond * time.Duration(timeoutMS)

	var txs types.Transactions
	for _, encodedTx := range args.Txs {
		tx, err := types.DecodeWrappedTransaction(encodedTx)
		if err != nil {
			return nil, err
		}
		txs = append(txs, tx)
	}

	dbtx, err := api.db.BeginRo(ctx)
	if err != nil {
		return nil, fmt.Errorf("create ro transaction: %v", err)
	}
	defer dbtx.Rollback()

	chainConfig, err := api.chainConfig(dbtx)
	if err != nil {
		return nil, fmt.Errorf("read chain config: %v", err)
	}
	engine := api.engine()

	blockNumber, hash, _, err := rpchelper.GetBlockNumber(args.StateBlockNumberOrHash, dbtx, api.filters)
	if err != nil {
		return nil, err
	}

	stateReader, err := rpchelper.CreateStateReader(ctx, dbtx, args.StateBlockNumberOrHash, 0, api.filters, api.stateCache, api.historyV3(dbtx), chainConfig.ChainName)
	if err != nil {
		return nil, fmt.Errorf("create state reader: %v", err)
	}
	ibs := state.New(stateReader)

	// override state
	if args.StateOverrides != nil {
		err = args.StateOverrides.Apply(ibs)
		if err != nil {
			return nil, fmt.Errorf("override state: %v", err)
		}
	}

	parent, err := api._blockReader.Header(context.Background(), dbtx, hash, blockNumber)
	if err != nil {
		return nil, fmt.Errorf("could not fetch header %d(%x): %v", blockNumber, hash, err)
	}
	if parent == nil {
		return nil, fmt.Errorf("block %d(%x) not found", blockNumber, hash)
	}
	header := &types.Header{
		ParentHash: parent.Hash(),
		Number:     new(big.Int).Set(parent.Number),
		GasLimit:   parent.GasLimit,
		Time:       parent.Time,
		Difficulty: new(big.Int).Set(parent.Difficulty),
		Coinbase:   parent.Coinbase,
		BaseFee:    new(big.Int).Set(parent.BaseFee),
	}
	if chainConfig.IsLondon(parent.Number.Uint64()) {
		header.BaseFee = misc.CalcBaseFee(chainConfig, parent)
	}
	// header overrides
	args.BlockOverrides.Apply(header)

	// Gas pool
	gp := new(core.GasPool).AddGas(math.MaxUint64)

	blockContext := transactions.NewEVMBlockContext(engine, header, args.StateBlockNumberOrHash.RequireCanonical, dbtx, api._blockReader)
	blockHash := parent.Hash()
	rules := chainConfig.Rules(parent.Number.Uint64(), blockContext.Time)

	bundleHash := sha3.NewLegacyKeccak256()
	// Setup context so it may be cancelled when the call
	// has completed or, in case of unmetered gas, setup
	// a context with a timeout
	var cancel context.CancelFunc
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, timeout)
	} else {
		ctx, cancel = context.WithCancel(ctx)
	}
	// Make sure the context is cancelled when the call has completed
	// This makes sure resources are cleaned up
	defer cancel()

	// Feed each of the transactions into the VM ctx
	// And try and estimate the gas used
	ret := &searcher.CallBundleResult{
		CoinbaseDiff:      ibs.GetBalance(header.Coinbase).ToBig(),
		GasFees:           new(big.Int),
		EthSentToCoinbase: new(big.Int),
		StateBlockNumber:  parent.Number.Int64(),
		Txs:               make([]*searcher.BundleTxResult, 0, len(txs)),
	}
	for i, tx := range txs {
		// Check if the context was cancelled (eg. timed-out)
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		ibs.SetTxContext(tx.Hash(), blockHash, i)
		txResult, err := api.applyTransactionWithResult(chainConfig, blockContext, rules, gp, ibs, header, tx, args.EnableCallTracer)
		if err != nil {
			return nil, fmt.Errorf("tx %s error: %w", tx.Hash(), err)
		}
		bundleHash.Write(tx.Hash().Bytes())
		ret.TotalGasUsed += txResult.GasUsed
		ret.GasFees.Add(ret.GasFees, txResult.GasFees)
		ret.Txs = append(ret.Txs, txResult)
	}

	ret.CoinbaseDiff = new(big.Int).Sub(ibs.GetBalance(header.Coinbase).ToBig(), ret.CoinbaseDiff)
	ret.EthSentToCoinbase = new(big.Int).Sub(ret.CoinbaseDiff, ret.GasFees)
	ret.BundleGasPrice = new(big.Int).Div(ret.CoinbaseDiff, big.NewInt(int64(ret.TotalGasUsed)))
	ret.BundleHash = common.BytesToHash(bundleHash.Sum(nil))

	return ret, nil
}

func (api *APIImpl) applyTransactionWithResult(config *chain.Config, blockContext evmtypes.BlockContext, rules *chain.Rules, gp *core.GasPool, ibs *state.IntraBlockState, header *types.Header, tx types.Transaction, enableCallTracer bool) (*searcher.BundleTxResult, error) {
	var tracer tracers.Tracer
	var vmConfig vm.Config
	if enableCallTracer {
		var err error
		tracer, err = tracers.New("callTracer", nil, json.RawMessage(`{"withLog":true}`))
		if err != nil {
			return nil, err
		}
		vmConfig = vm.Config{
			Tracer: tracer,
			Debug:  true,
		}
	}

	singer := types.MakeSigner(config, header.Number.Uint64())
	msg, err := tx.AsMessage(*singer, header.BaseFee, rules)
	if err != nil {
		return nil, err
	}
	// Create a new context to be used in the EVM environment
	evm := vm.NewEVM(blockContext, core.NewEVMTxContext(msg), ibs, config, vmConfig)

	// Apply the transaction to the current state (included in the env).
	coinbaseBalanceBeforeTx := ibs.GetBalance(header.Coinbase)
	result, err := core.ApplyMessage(evm, msg, gp, true, false)
	if err != nil {
		return nil, err
	}

	// Update the state with pending changes
	if err = ibs.FinalizeTx(rules, state.NewNoopWriter()); err != nil {
		return nil, err
	}
	header.GasUsed += result.UsedGas

	// Create a new receipt for the transaction, storing the intermediate root and gas used
	// by the tx.
	receipt := &types.Receipt{Type: tx.Type(), CumulativeGasUsed: header.GasUsed}
	if result.Failed() {
		receipt.Status = types.ReceiptStatusFailed
	} else {
		receipt.Status = types.ReceiptStatusSuccessful
	}
	receipt.TxHash = tx.Hash()
	receipt.GasUsed = result.UsedGas

	// If the transaction created a contract, store the creation address in the receipt.
	if msg.To() == nil {
		receipt.ContractAddress = crypto.CreateAddress(evm.TxContext().Origin, tx.GetNonce())
	}

	// Set the receipt logs and create the bloom filter.
	receipt.Logs = ibs.GetLogs(tx.Hash())
	receipt.Bloom = types.CreateBloom(types.Receipts{receipt})
	receipt.BlockHash = header.Hash()
	receipt.BlockNumber = header.Number
	receipt.TransactionIndex = uint(ibs.TxIndex())

	txResult := &searcher.BundleTxResult{
		TxHash:       tx.Hash(),
		GasUsed:      receipt.GasUsed,
		ReturnData:   result.ReturnData,
		Logs:         receipt.Logs,
		CoinbaseDiff: new(uint256.Int).Sub(ibs.GetBalance(header.Coinbase), coinbaseBalanceBeforeTx).ToBig(),
		CallMsg: &searcher.CallMsg{
			From:       msg.From(),
			To:         msg.To(),
			Gas:        tx.GetGas(),
			GasPrice:   tx.GetFeeCap().ToBig(),
			GasFeeCap:  tx.GetFeeCap().ToBig(),
			GasTipCap:  tx.GetTip().ToBig(),
			Value:      tx.GetValue().ToBig(),
			Nonce:      tx.GetNonce(),
			Data:       tx.GetData(),
			AccessList: tx.GetAccessList(),
		},
	}
	if enableCallTracer {
		traceResult, err := tracer.GetResult()
		if err != nil {
			return nil, fmt.Errorf("tx %s trace error: %w", tx.Hash(), err)
		}
		err = json.Unmarshal(traceResult, &txResult.CallFrame)
		if err != nil {
			return nil, fmt.Errorf("tx %s trace error: %w", tx.Hash(), err)
		}
	}
	var baseFee *uint256.Int
	if header.BaseFee != nil {
		baseFee, _ = uint256.FromBig(header.BaseFee)
	}
	txResult.GasPrice = tx.GetEffectiveGasTip(baseFee).ToBig()
	if err != nil {
		return nil, fmt.Errorf("tx %s error: %w", tx.Hash(), err)
	}
	txResult.GasFees = new(big.Int).Mul(big.NewInt(int64(receipt.GasUsed)), txResult.GasPrice)
	txResult.EthSentToCoinbase = new(big.Int).Sub(txResult.CoinbaseDiff, txResult.GasFees)
	txResult.GasPrice = new(big.Int).Div(txResult.CoinbaseDiff, big.NewInt(int64(receipt.GasUsed)))

	if result.Err != nil {
		txResult.Error = result.Err.Error()
	}
	reason, errUnpack := abi.UnpackRevert(result.Revert())
	if errUnpack == nil {
		txResult.Error = fmt.Sprintf("execution reverted: %v", reason)
	}
	return txResult, err
}

func (api *APIImpl) SearcherCall(ctx context.Context, args searcher.CallArgs) (*searcher.CallResult, error) {
	if len(args.Txs) == 0 {
		return nil, errors.New("missing txs")
	}
	if args.StateBlockNumberOrHash == (rpc.BlockNumberOrHash{}) {
		args.StateBlockNumberOrHash = rpc.BlockNumberOrHashWithNumber(rpc.LatestBlockNumber)
	}
	timeoutMS := int64(5000)
	if args.Timeout != nil {
		timeoutMS = *args.Timeout
	}
	timeout := time.Millisecond * time.Duration(timeoutMS)

	dbtx, err := api.db.BeginRo(ctx)
	if err != nil {
		return nil, fmt.Errorf("create ro transaction: %v", err)
	}
	defer dbtx.Rollback()

	chainConfig, err := api.chainConfig(dbtx)
	if err != nil {
		return nil, fmt.Errorf("read chain config: %v", err)
	}
	engine := api.engine()

	blockNumber, hash, _, err := rpchelper.GetBlockNumber(args.StateBlockNumberOrHash, dbtx, api.filters)
	if err != nil {
		return nil, fmt.Errorf("get block number: %v", err)
	}

	stateReader, err := rpchelper.CreateStateReader(ctx, dbtx, args.StateBlockNumberOrHash, 0, api.filters, api.stateCache, api.historyV3(dbtx), chainConfig.ChainName)
	if err != nil {
		return nil, fmt.Errorf("create state reader: %v", err)
	}
	ibs := state.New(stateReader)

	// override state
	if args.StateOverrides != nil {
		err = args.StateOverrides.Apply(ibs)
		if err != nil {
			return nil, fmt.Errorf("override state: %v", err)
		}
	}

	parent, err := api._blockReader.Header(context.Background(), dbtx, hash, blockNumber)
	if err != nil {
		return nil, fmt.Errorf("could not fetch header %d(%x): %v", blockNumber, hash, err)
	}
	if parent == nil {
		return nil, fmt.Errorf("block %d(%x) not found", blockNumber, hash)
	}
	header := &types.Header{
		ParentHash: parent.Hash(),
		Number:     new(big.Int).Set(parent.Number),
		GasLimit:   parent.GasLimit,
		Time:       parent.Time,
		Difficulty: new(big.Int).Set(parent.Difficulty),
		Coinbase:   parent.Coinbase,
		BaseFee:    new(big.Int).Set(parent.BaseFee),
	}
	// header overrides
	args.BlockOverrides.Apply(header)

	// Gas pool
	gp := new(core.GasPool).AddGas(math.MaxUint64)

	blockContext := transactions.NewEVMBlockContext(engine, header, args.StateBlockNumberOrHash.RequireCanonical, dbtx, api._blockReader)
	blockHash := parent.Hash()
	rules := chainConfig.Rules(parent.Number.Uint64(), blockContext.Time)

	// Setup context so it may be cancelled when the call
	// has completed or, in case of unmetered gas, setup
	// a context with a timeout
	var cancel context.CancelFunc
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, timeout)
	} else {
		ctx, cancel = context.WithCancel(ctx)
	}
	// Make sure the context is cancelled when the call has completed
	// This makes sure resources are cleaned up
	defer cancel()

	// Feed each of the transactions into the VM ctx
	// And try and estimate the gas used
	ret := &searcher.CallResult{
		StateBlockNumber: parent.Number.Int64(),
		Txs:              make([]*searcher.TxResult, 0, len(args.Txs)),
	}
	for i, callMsg := range args.Txs {
		// Check if the context was cancelled (eg. timed-out)
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		// Since it is a txCall we'll just prepare the
		// state with a random hash
		var txHash common.Hash
		rand.Read(txHash[:])

		// New random hash since its a call
		ibs.SetTxContext(txHash, blockHash, i)

		// Convert tx args to msg to apply state transition
		var gasPtr *hexutil.Uint64
		if callMsg.Gas > 0 {
			gasPtr = (*hexutil.Uint64)(&callMsg.Gas)
		}
		txArgs := ethapi.CallArgs{
			From:                 &callMsg.From,
			To:                   callMsg.To,
			Gas:                  gasPtr,
			GasPrice:             (*hexutil.Big)(callMsg.GasPrice),
			MaxFeePerGas:         (*hexutil.Big)(callMsg.GasFeeCap),
			MaxPriorityFeePerGas: (*hexutil.Big)(callMsg.GasTipCap),
			Value:                (*hexutil.Big)(callMsg.Value),
			Data:                 &callMsg.Data,
			AccessList:           &callMsg.AccessList,
		}
		msg, err := txArgs.ToMessage(api.GasCap, blockContext.BaseFee)
		if err != nil {
			return nil, err
		}

		// Create a new EVM environment
		vmConfig := vm.Config{NoBaseFee: true}
		var tracer tracers.Tracer
		if args.EnableCallTracer {
			tracer, err = tracers.New("callTracer", nil, json.RawMessage(`{"withLog":true}`))
			if err != nil {
				return nil, err
			}
			vmConfig.Tracer = tracer
			vmConfig.Debug = true
		}
		evm := vm.NewEVM(blockContext, core.NewEVMTxContext(msg), ibs, chainConfig, vmConfig)

		// Apply state transition
		txResult := new(searcher.TxResult)
		result, err := core.ApplyMessage(evm, msg, gp, true, false)

		// Modifications are committed to the state
		// Only delete empty objects if EIP158/161 (a.k.a Spurious Dragon) is in effect
		_ = ibs.FinalizeTx(rules, state.NewNoopWriter())

		if err != nil {
			txResult.Error = fmt.Sprintf("%s (supplied gas %d)", err.Error(), msg.Gas())
		} else {
			txResult.Logs = ibs.GetLogs(txHash)
			if args.EnableCallTracer {
				traceResult, err := tracer.GetResult()
				if err != nil {
					return nil, err
				}
				err = json.Unmarshal(traceResult, &txResult.CallFrame)
				if err != nil {
					return nil, err
				}
			}

			if result.Err != nil {
				txResult.Error = result.Err.Error()
			}
			reason, errUnpack := abi.UnpackRevert(result.Revert())
			if errUnpack == nil {
				txResult.Error = fmt.Sprintf("execution reverted: %v", reason)
			}
			txResult.GasUsed = result.UsedGas
			txResult.ReturnData = result.ReturnData

			ret.TotalGasUsed += txResult.GasUsed
		}

		ret.Txs = append(ret.Txs, txResult)
	}

	return ret, nil
}
