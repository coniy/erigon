package jsonrpc

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/holiman/uint256"
	"github.com/ledgerwatch/erigon-lib/chain"
	"github.com/ledgerwatch/erigon-lib/common"
	"github.com/ledgerwatch/erigon-lib/common/hexutil"
	"github.com/ledgerwatch/erigon/accounts/abi"
	"github.com/ledgerwatch/erigon/common/math"
	"github.com/ledgerwatch/erigon/consensus/misc"
	"github.com/ledgerwatch/erigon/core"
	"github.com/ledgerwatch/erigon/core/state"
	"github.com/ledgerwatch/erigon/core/types"
	"github.com/ledgerwatch/erigon/core/vm"
	"github.com/ledgerwatch/erigon/core/vm/evmtypes"
	"github.com/ledgerwatch/erigon/crypto"
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
	db := state.New(stateReader)

	// override state
	if args.StateOverrides != nil {
		err = args.StateOverrides.Apply(db)
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
		ParentHash:            parent.Hash(),
		Coinbase:              parent.Coinbase,
		Difficulty:            new(big.Int).Set(parent.Difficulty),
		Number:                new(big.Int).Set(parent.Number),
		GasLimit:              parent.GasLimit,
		Time:                  parent.Time,
		MixDigest:             parent.MixDigest,
		ExcessBlobGas:         parent.ExcessBlobGas,
		ParentBeaconBlockRoot: parent.ParentBeaconBlockRoot,
	}
	if chainConfig.IsLondon(parent.Number.Uint64()) {
		header.BaseFee = misc.CalcBaseFee(chainConfig, parent)
	}
	blockCtx := transactions.NewEVMBlockContext(engine, header, args.StateBlockNumberOrHash.RequireCanonical, dbtx, api._blockReader)

	// block overrides
	args.BlockOverrides.Apply(&blockCtx)

	// Gas pool
	gp := new(core.GasPool).AddGas(math.MaxUint64)

	blockHash := parent.Hash()
	rules := chainConfig.Rules(parent.Number.Uint64(), blockCtx.Time)

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
		db.SetTxContext(txHash, blockHash, i)

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
			Nonce:                (*hexutil.Uint64)(callMsg.Nonce),
			Data:                 &callMsg.Data,
			AccessList:           &callMsg.AccessList,
		}
		msg, err := txArgs.ToMessage(api.GasCap, blockCtx.BaseFee)
		if err != nil {
			return nil, err
		}
		if callMsg.Nonce != nil {
			msg = types.NewMessage(
				msg.From(),
				msg.To(),
				*callMsg.Nonce,
				msg.Value(),
				msg.Gas(),
				msg.GasPrice(),
				msg.FeeCap(),
				msg.Tip(),
				msg.Data(),
				msg.AccessList(),
				true,
				false,
				msg.MaxFeePerBlobGas(),
			)
		}
		msg.SetCheckNonce(callMsg.Nonce != nil)

		// Create a new EVM environment
		vmConfig := vm.Config{
			NoBaseFee: !args.EnableBaseFee,
		}
		var tracer *searcher.Tracer
		if args.EnableCallTracer || callMsg.EnableAccessList {
			cfg := searcher.TracerConfig{
				WithCall:       args.EnableCallTracer,
				WithLog:        args.EnableCallTracer,
				WithAccessList: callMsg.EnableAccessList,
			}
			if cfg.WithAccessList {
				cfg.AccessListExcludes = make(map[common.Address]struct{})
				cfg.AccessListExcludes[msg.From()] = struct{}{}
				if msg.To() != nil {
					cfg.AccessListExcludes[*msg.To()] = struct{}{}
				} else {
					cfg.AccessListExcludes[crypto.CreateAddress(msg.From(), db.GetNonce(msg.From()))] = struct{}{}
				}
				for _, precompile := range vm.ActivePrecompiles(rules) {
					cfg.AccessListExcludes[precompile] = struct{}{}
				}
				cfg.AccessListExcludes[blockCtx.Coinbase] = struct{}{}
			}
			tracer = searcher.NewCombinedTracer(cfg)
			vmConfig.Debug = true
			vmConfig.Tracer = tracer
		}
		evm := vm.NewEVM(blockCtx, core.NewEVMTxContext(msg), db, chainConfig, vmConfig)

		// Apply state transition
		txResult := new(searcher.TxResult)
		result, err := core.ApplyMessage(evm, msg, gp, true, false)

		// Modifications are committed to the state
		// Only delete empty objects if EIP158/161 (a.k.a Spurious Dragon) is in effect
		_ = db.FinalizeTx(rules, state.NewNoopWriter())

		if err != nil {
			txResult.Error = fmt.Sprintf("%s (supplied gas %d)", err.Error(), msg.Gas())
		} else {
			txResult.Logs = db.GetLogs(txHash)
			if args.EnableCallTracer {
				txResult.CallFrame = tracer.CallFrame()
			}
			if callMsg.EnableAccessList {
				txResult.AccessList = tracer.AccessList()
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
	db := state.New(stateReader)

	// override state
	if args.StateOverrides != nil {
		err = args.StateOverrides.Apply(db)
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
		ParentHash:            parent.Hash(),
		Coinbase:              parent.Coinbase,
		Difficulty:            new(big.Int).Set(parent.Difficulty),
		Number:                new(big.Int).Set(parent.Number),
		GasLimit:              parent.GasLimit,
		Time:                  parent.Time,
		MixDigest:             parent.MixDigest,
		ExcessBlobGas:         parent.ExcessBlobGas,
		ParentBeaconBlockRoot: parent.ParentBeaconBlockRoot,
	}
	if chainConfig.IsLondon(parent.Number.Uint64()) {
		header.BaseFee = misc.CalcBaseFee(chainConfig, parent)
	}
	blockCtx := transactions.NewEVMBlockContext(engine, header, args.StateBlockNumberOrHash.RequireCanonical, dbtx, api._blockReader)

	// block overrides
	args.BlockOverrides.Apply(&blockCtx)

	// Gas pool
	gp := new(core.GasPool).AddGas(math.MaxUint64)

	blockHash := parent.Hash()
	rules := chainConfig.Rules(parent.Number.Uint64(), blockCtx.Time)

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
		CoinbaseDiff:      db.GetBalance(blockCtx.Coinbase).ToBig(),
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

		db.SetTxContext(tx.Hash(), blockHash, i)
		txResult, err := api.applyTransactionWithResult(chainConfig, blockCtx, rules, gp, db, tx, args)
		if err != nil {
			return nil, fmt.Errorf("tx %s error: %w", tx.Hash(), err)
		}
		bundleHash.Write(tx.Hash().Bytes())
		ret.TotalGasUsed += txResult.GasUsed
		ret.GasFees.Add(ret.GasFees, txResult.GasFees)
		ret.Txs = append(ret.Txs, txResult)
	}

	ret.CoinbaseDiff = new(big.Int).Sub(db.GetBalance(blockCtx.Coinbase).ToBig(), ret.CoinbaseDiff)
	ret.EthSentToCoinbase = new(big.Int).Sub(ret.CoinbaseDiff, ret.GasFees)
	ret.BundleGasPrice = new(big.Int).Div(ret.CoinbaseDiff, big.NewInt(int64(ret.TotalGasUsed)))
	ret.BundleHash = common.BytesToHash(bundleHash.Sum(nil))

	return ret, nil
}

func (api *APIImpl) applyTransactionWithResult(config *chain.Config, blockCtx evmtypes.BlockContext, rules *chain.Rules, gp *core.GasPool, db *state.IntraBlockState, tx types.Transaction, args searcher.CallBundleArgs) (*searcher.BundleTxResult, error) {
	singer := types.MakeSigner(config, blockCtx.BlockNumber, blockCtx.Time)
	msg, err := tx.AsMessage(*singer, blockCtx.BaseFee.ToBig(), rules)
	if err != nil {
		return nil, err
	}
	var tracer *searcher.Tracer
	var vmConfig vm.Config
	if args.EnableCallTracer || args.EnableAccessList {
		cfg := searcher.TracerConfig{
			WithCall:       args.EnableCallTracer,
			WithLog:        args.EnableCallTracer,
			WithAccessList: args.EnableAccessList,
		}
		if cfg.WithAccessList {
			cfg.AccessListExcludes = make(map[common.Address]struct{})
			cfg.AccessListExcludes[msg.From()] = struct{}{}
			if msg.To() != nil {
				cfg.AccessListExcludes[*msg.To()] = struct{}{}
			} else {
				cfg.AccessListExcludes[crypto.CreateAddress(msg.From(), msg.Nonce())] = struct{}{}
			}
			for _, precompile := range vm.ActivePrecompiles(rules) {
				cfg.AccessListExcludes[precompile] = struct{}{}
			}
			cfg.AccessListExcludes[blockCtx.Coinbase] = struct{}{}
		}
		tracer = searcher.NewCombinedTracer(cfg)
		vmConfig.Debug = true
		vmConfig.Tracer = tracer
	}

	// Create a new context to be used in the EVM environment
	evm := vm.NewEVM(blockCtx, core.NewEVMTxContext(msg), db, config, vmConfig)

	// Apply the transaction to the current state (included in the env).
	coinbaseBalanceBeforeTx := db.GetBalance(blockCtx.Coinbase)
	result, err := core.ApplyMessage(evm, msg, gp, true, false)
	if err != nil {
		return nil, err
	}

	// Update the state with pending changes
	if err = db.FinalizeTx(rules, state.NewNoopWriter()); err != nil {
		return nil, err
	}

	nonce := msg.Nonce()
	txResult := &searcher.BundleTxResult{
		TxHash:       tx.Hash(),
		GasUsed:      result.UsedGas,
		ReturnData:   result.ReturnData,
		Logs:         db.GetLogs(tx.Hash()),
		CoinbaseDiff: new(uint256.Int).Sub(db.GetBalance(blockCtx.Coinbase), coinbaseBalanceBeforeTx).ToBig(),
		CallMsg: &searcher.CallMsg{
			From:       msg.From(),
			To:         msg.To(),
			Gas:        tx.GetGas(),
			GasPrice:   tx.GetFeeCap().ToBig(),
			GasFeeCap:  tx.GetFeeCap().ToBig(),
			GasTipCap:  tx.GetTip().ToBig(),
			Value:      tx.GetValue().ToBig(),
			Nonce:      &nonce,
			Data:       tx.GetData(),
			AccessList: tx.GetAccessList(),
		},
	}
	if args.EnableCallTracer {
		txResult.CallFrame = tracer.CallFrame()
	}
	if args.EnableAccessList {
		txResult.AccessList = tracer.AccessList()
	}
	txResult.GasPrice = tx.GetEffectiveGasTip(blockCtx.BaseFee).ToBig()
	txResult.GasFees = new(big.Int).Mul(big.NewInt(int64(result.UsedGas)), txResult.GasPrice)
	txResult.EthSentToCoinbase = new(big.Int).Sub(txResult.CoinbaseDiff, txResult.GasFees)
	txResult.GasPrice = new(big.Int).Div(txResult.CoinbaseDiff, big.NewInt(int64(result.UsedGas)))

	if result.Err != nil {
		txResult.Error = result.Err.Error()
	}
	reason, errUnpack := abi.UnpackRevert(result.Revert())
	if errUnpack == nil {
		txResult.Error = fmt.Sprintf("execution reverted: %v", reason)
	}
	return txResult, err
}
