// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package core

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"math/rand"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/gopool"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/misc"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/state/snapshot"
	"github.com/ethereum/go-ethereum/core/systemcontracts"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
)

const (
	fullProcessCheck       = 21 // On diff sync mode, will do full process every fullProcessCheck randomly
	recentTime             = 1024 * 3
	recentDiffLayerTimeout = 5
	farDiffLayerTimeout    = 2
)

// StateProcessor is a basic Processor, which takes care of transitioning
// state from one point to another.
//
// StateProcessor implements Processor.
type StateProcessor struct {
	config *params.ChainConfig // Chain configuration options
	bc     *BlockChain         // Canonical block chain
	engine consensus.Engine    // Consensus engine used for block rewards
}

// NewStateProcessor initialises a new StateProcessor.
func NewStateProcessor(config *params.ChainConfig, bc *BlockChain, engine consensus.Engine) *StateProcessor {
	return &StateProcessor{
		config: config,
		bc:     bc,
		engine: engine,
	}
}

type LightStateProcessor struct {
	check int64
	StateProcessor
}

func NewLightStateProcessor(config *params.ChainConfig, bc *BlockChain, engine consensus.Engine) *LightStateProcessor {
	randomGenerator := rand.New(rand.NewSource(int64(time.Now().Nanosecond())))
	check := randomGenerator.Int63n(fullProcessCheck)
	return &LightStateProcessor{
		check:          check,
		StateProcessor: *NewStateProcessor(config, bc, engine),
	}
}

func (p *LightStateProcessor) Process(block *types.Block, statedb *state.StateDB, cfg vm.Config) (*state.StateDB, types.Receipts, []*types.Log, uint64, error) {
	allowLightProcess := true
	if posa, ok := p.engine.(consensus.PoSA); ok {
		allowLightProcess = posa.AllowLightProcess(p.bc, block.Header())
	}
	// random fallback to full process
	if allowLightProcess && block.NumberU64()%fullProcessCheck != uint64(p.check) && len(block.Transactions()) != 0 {
		var pid string
		if peer, ok := block.ReceivedFrom.(PeerIDer); ok {
			pid = peer.ID()
		}
		var diffLayer *types.DiffLayer
		var diffLayerTimeout = recentDiffLayerTimeout
		if time.Now().Unix()-int64(block.Time()) > recentTime {
			diffLayerTimeout = farDiffLayerTimeout
		}
		for tried := 0; tried < diffLayerTimeout; tried++ {
			// wait a bit for the diff layer
			diffLayer = p.bc.GetUnTrustedDiffLayer(block.Hash(), pid)
			if diffLayer != nil {
				break
			}
			time.Sleep(time.Millisecond)
		}
		if diffLayer != nil {
			if err := diffLayer.Receipts.DeriveFields(p.bc.chainConfig, block.Hash(), block.NumberU64(), block.Transactions()); err != nil {
				log.Error("Failed to derive block receipts fields", "hash", block.Hash(), "number", block.NumberU64(), "err", err)
				// fallback to full process
				return p.StateProcessor.Process(block, statedb, cfg)
			}

			receipts, logs, gasUsed, err := p.LightProcess(diffLayer, block, statedb)
			if err == nil {
				log.Info("do light process success at block", "num", block.NumberU64())
				return statedb, receipts, logs, gasUsed, nil
			}
			log.Error("do light process err at block", "num", block.NumberU64(), "err", err)
			p.bc.removeDiffLayers(diffLayer.DiffHash.Load().(common.Hash))
			// prepare new statedb
			statedb.StopPrefetcher()
			parent := p.bc.GetHeader(block.ParentHash(), block.NumberU64()-1)
			statedb, err = state.New(parent.Root, p.bc.stateCache, p.bc.snaps)
			if err != nil {
				return statedb, nil, nil, 0, err
			}
			statedb.SetExpectedStateRoot(block.Root())
			if p.bc.pipeCommit {
				statedb.EnablePipeCommit()
			}
			// Enable prefetching to pull in trie node paths while processing transactions
			statedb.StartPrefetcher("chain")
		}
	}
	// fallback to full process
	return p.StateProcessor.Process(block, statedb, cfg)
}

func (p *LightStateProcessor) LightProcess(diffLayer *types.DiffLayer, block *types.Block, statedb *state.StateDB) (types.Receipts, []*types.Log, uint64, error) {
	statedb.MarkLightProcessed()
	fullDiffCode := make(map[common.Hash][]byte, len(diffLayer.Codes))
	diffTries := make(map[common.Address]state.Trie)
	diffCode := make(map[common.Hash][]byte)

	snapDestructs, snapAccounts, snapStorage, err := statedb.DiffLayerToSnap(diffLayer)
	if err != nil {
		return nil, nil, 0, err
	}

	for _, c := range diffLayer.Codes {
		fullDiffCode[c.Hash] = c.Code
	}
	stateTrie, err := statedb.Trie()
	if err != nil {
		return nil, nil, 0, err
	}
	for des := range snapDestructs {
		stateTrie.TryDelete(des[:])
	}
	threads := gopool.Threads(len(snapAccounts))

	iteAccounts := make([]common.Address, 0, len(snapAccounts))
	for diffAccount := range snapAccounts {
		iteAccounts = append(iteAccounts, diffAccount)
	}

	errChan := make(chan error, threads)
	exitChan := make(chan struct{})
	var snapMux sync.RWMutex
	var stateMux, diffMux sync.Mutex
	for i := 0; i < threads; i++ {
		start := i * len(iteAccounts) / threads
		end := (i + 1) * len(iteAccounts) / threads
		if i+1 == threads {
			end = len(iteAccounts)
		}
		go func(start, end int) {
			for index := start; index < end; index++ {
				select {
				// fast fail
				case <-exitChan:
					return
				default:
				}
				diffAccount := iteAccounts[index]
				snapMux.RLock()
				blob := snapAccounts[diffAccount]
				snapMux.RUnlock()
				addrHash := crypto.Keccak256Hash(diffAccount[:])
				latestAccount, err := snapshot.FullAccount(blob)
				if err != nil {
					errChan <- err
					return
				}

				// fetch previous state
				var previousAccount types.StateAccount
				stateMux.Lock()
				enc, err := stateTrie.TryGet(diffAccount[:])
				stateMux.Unlock()
				if err != nil {
					errChan <- err
					return
				}
				if len(enc) != 0 {
					if err := rlp.DecodeBytes(enc, &previousAccount); err != nil {
						errChan <- err
						return
					}
				}
				if latestAccount.Balance == nil {
					latestAccount.Balance = new(big.Int)
				}
				if previousAccount.Balance == nil {
					previousAccount.Balance = new(big.Int)
				}
				if previousAccount.Root == (common.Hash{}) {
					previousAccount.Root = types.EmptyRootHash
				}
				if len(previousAccount.CodeHash) == 0 {
					previousAccount.CodeHash = types.EmptyCodeHash
				}

				// skip no change account
				if previousAccount.Nonce == latestAccount.Nonce &&
					bytes.Equal(previousAccount.CodeHash, latestAccount.CodeHash) &&
					previousAccount.Balance.Cmp(latestAccount.Balance) == 0 &&
					previousAccount.Root == common.BytesToHash(latestAccount.Root) {
					// It is normal to receive redundant message since the collected message is redundant.
					log.Debug("receive redundant account change in diff layer", "account", diffAccount, "num", block.NumberU64())
					snapMux.Lock()
					delete(snapAccounts, diffAccount)
					delete(snapStorage, diffAccount)
					snapMux.Unlock()
					continue
				}

				// update code
				codeHash := common.BytesToHash(latestAccount.CodeHash)
				if !bytes.Equal(latestAccount.CodeHash, previousAccount.CodeHash) &&
					!bytes.Equal(latestAccount.CodeHash, types.EmptyCodeHash) {
					if code, exist := fullDiffCode[codeHash]; exist {
						if crypto.Keccak256Hash(code) != codeHash {
							errChan <- fmt.Errorf("code and code hash mismatch, account %s", diffAccount.String())
							return
						}
						diffMux.Lock()
						diffCode[codeHash] = code
						diffMux.Unlock()
					} else {
						rawCode := rawdb.ReadCode(p.bc.db, codeHash)
						if len(rawCode) == 0 {
							errChan <- fmt.Errorf("missing code, account %s", diffAccount.String())
							return
						}
					}
				}

				//update storage
				latestRoot := common.BytesToHash(latestAccount.Root)
				if latestRoot != previousAccount.Root {
					accountTrie, err := statedb.Database().OpenStorageTrie(addrHash, previousAccount.Root)
					if err != nil {
						errChan <- err
						return
					}
					snapMux.RLock()
					storageChange, exist := snapStorage[diffAccount]
					snapMux.RUnlock()

					if !exist {
						errChan <- errors.New("missing storage change in difflayer")
						return
					}
					for k, v := range storageChange {
						if len(v) != 0 {
							accountTrie.TryUpdate([]byte(k), v)
						} else {
							accountTrie.TryDelete([]byte(k))
						}
					}

					// check storage root
					accountRootHash := accountTrie.Hash()
					if latestRoot != accountRootHash {
						errChan <- errors.New("account storage root mismatch")
						return
					}
					diffMux.Lock()
					diffTries[diffAccount] = accountTrie
					diffMux.Unlock()
				} else {
					snapMux.Lock()
					delete(snapStorage, diffAccount)
					snapMux.Unlock()
				}

				// can't trust the blob, need encode by our-self.
				latestStateAccount := types.StateAccount{
					Nonce:    latestAccount.Nonce,
					Balance:  latestAccount.Balance,
					Root:     common.BytesToHash(latestAccount.Root),
					CodeHash: latestAccount.CodeHash,
				}
				bz, err := rlp.EncodeToBytes(&latestStateAccount)
				if err != nil {
					errChan <- err
					return
				}
				stateMux.Lock()
				err = stateTrie.TryUpdate(diffAccount[:], bz)
				stateMux.Unlock()
				if err != nil {
					errChan <- err
					return
				}
			}
			errChan <- nil
		}(start, end)
	}

	for i := 0; i < threads; i++ {
		err := <-errChan
		if err != nil {
			close(exitChan)
			return nil, nil, 0, err
		}
	}

	var allLogs []*types.Log
	var gasUsed uint64
	for _, receipt := range diffLayer.Receipts {
		allLogs = append(allLogs, receipt.Logs...)
		gasUsed += receipt.GasUsed
	}

	// Do validate in advance so that we can fall back to full process
	if err := p.bc.validator.ValidateState(block, statedb, diffLayer.Receipts, gasUsed); err != nil {
		log.Error("validate state failed during diff sync", "error", err)
		return nil, nil, 0, err
	}

	// remove redundant storage change
	for account := range snapStorage {
		if _, exist := snapAccounts[account]; !exist {
			log.Warn("receive redundant storage change in diff layer")
			delete(snapStorage, account)
		}
	}

	// remove redundant code
	if len(fullDiffCode) != len(diffLayer.Codes) {
		diffLayer.Codes = make([]types.DiffCode, 0, len(diffCode))
		for hash, code := range diffCode {
			diffLayer.Codes = append(diffLayer.Codes, types.DiffCode{
				Hash: hash,
				Code: code,
			})
		}
	}

	statedb.SetSnapData(snapDestructs, snapAccounts, snapStorage)
	if len(snapAccounts) != len(diffLayer.Accounts) || len(snapStorage) != len(diffLayer.Storages) {
		diffLayer.Destructs, diffLayer.Accounts, diffLayer.Storages = statedb.SnapToDiffLayer()
	}
	statedb.SetDiff(diffLayer, diffTries, diffCode)

	return diffLayer.Receipts, allLogs, gasUsed, nil
}

// Process processes the state changes according to the Ethereum rules by running
// the transaction messages using the statedb and applying any rewards to both
// the processor (coinbase) and any included uncles.
//
// Process returns the receipts and logs accumulated during the process and
// returns the amount of gas that was used in the process. If any of the
// transactions failed to execute due to insufficient gas it will return an error.
func (p *StateProcessor) Process(block *types.Block, statedb *state.StateDB, cfg vm.Config) (*state.StateDB, types.Receipts, []*types.Log, uint64, error) {
	var (
		usedGas     = new(uint64)
		header      = block.Header()
		blockHash   = block.Hash()
		blockNumber = block.Number()
		allLogs     []*types.Log
		gp          = new(GasPool).AddGas(block.GasLimit())
	)

	var receipts = make([]*types.Receipt, 0)
	// Mutate the block and state according to any hard-fork specs
	if p.config.DAOForkSupport && p.config.DAOForkBlock != nil && p.config.DAOForkBlock.Cmp(block.Number()) == 0 {
		misc.ApplyDAOHardFork(statedb)
	}
	// Handle upgrade build-in system contract code
	systemcontracts.UpgradeBuildInSystemContract(p.config, block.Number(), statedb)

	blockContext := NewEVMBlockContext(header, p.bc, nil)
	vmenv := vm.NewEVM(blockContext, vm.TxContext{}, statedb, p.config, cfg)

	txNum := len(block.Transactions())
	// Iterate over and process the individual transactions
	posa, isPoSA := p.engine.(consensus.PoSA)
	commonTxs := make([]*types.Transaction, 0, txNum)

	// initialise bloom processors
	bloomProcessors := NewAsyncReceiptBloomGenerator(txNum)
	statedb.MarkFullProcessed()
	signer := types.MakeSigner(p.config, header.Number)

	// usually do have two tx, one for validator set contract, another for system reward contract.
	systemTxs := make([]*types.Transaction, 0, 2)

	for i, tx := range block.Transactions() {
		if isPoSA {
			if isSystemTx, err := posa.IsSystemTransaction(tx, block.Header()); err != nil {
				bloomProcessors.Close()
				return statedb, nil, nil, 0, err
			} else if isSystemTx {
				systemTxs = append(systemTxs, tx)
				continue
			}
		}

		msg, err := tx.AsMessage(signer, header.BaseFee)
		if err != nil {
			bloomProcessors.Close()
			return statedb, nil, nil, 0, err
		}
		statedb.Prepare(tx.Hash(), i)
		receipt, err := applyTransaction(msg, p.config, p.bc, nil, gp, statedb, blockNumber, blockHash, tx, usedGas, vmenv, bloomProcessors)
		// flash_loan_prove_transaction(msg, p.config, p.bc, nil, gp, statedb, blockNumber, blockHash, tx, usedGas, vmenv, bloomProcessors)
		if err != nil {
			bloomProcessors.Close()
			return statedb, nil, nil, 0, fmt.Errorf("could not apply tx %d [%v]: %w", i, tx.Hash().Hex(), err)
		}
		commonTxs = append(commonTxs, tx)
		receipts = append(receipts, receipt)
	}
	bloomProcessors.Close()

	// Finalize the block, applying any consensus engine specific extras (e.g. block rewards)
	err := p.engine.Finalize(p.bc, header, statedb, &commonTxs, block.Uncles(), &receipts, &systemTxs, usedGas)
	if err != nil {
		return statedb, receipts, allLogs, *usedGas, err
	}
	for _, receipt := range receipts {
		allLogs = append(allLogs, receipt.Logs...)
	}

	return statedb, receipts, allLogs, *usedGas, nil
}



// flash loan archive node testing process
func (p *StateProcessor) Flash_Loan_Process(block *types.Block, statedb *state.StateDB, cfg vm.Config) (*state.StateDB, types.Receipts, []*types.Log, uint64, error) {
	fmt.Println("Processing block number containing flash loan: ", block.Number())
	var (
		usedGas = new(uint64)
		header  = block.Header()
		allLogs []*types.Log
		gp      = new(GasPool).AddGas(block.GasLimit())
	)
	signer := types.MakeSigner(p.bc.chainConfig, block.Number())
	statedb.TryPreload(block, signer)
	var receipts = make([]*types.Receipt, 0)
	// Mutate the block and state according to any hard-fork specs
	if p.config.DAOForkSupport && p.config.DAOForkBlock != nil && p.config.DAOForkBlock.Cmp(block.Number()) == 0 {
		misc.ApplyDAOHardFork(statedb)
	}
	// Handle upgrade build-in system contract code
	systemcontracts.UpgradeBuildInSystemContract(p.config, block.Number(), statedb)

	// blockContext := NewEVMBlockContext(header, p.bc, nil)
	// vmenv := vm.NewEVM(blockContext, vm.TxContext{}, statedb, p.config, cfg)

	txNum := len(block.Transactions())
	// Iterate over and process the individual transactions
	posa, isPoSA := p.engine.(consensus.PoSA)
	commonTxs := make([]*types.Transaction, 0, txNum)

	// initilise bloom processors
	bloomProcessors := NewAsyncReceiptBloomGenerator(txNum)

	// usually do have two tx, one for validator set contract, another for system reward contract.
	systemTxs := make([]*types.Transaction, 0, 2)
	for i, tx := range block.Transactions() {
		if tx.Hash().Hex() == "0xfbe65ad3eed6b28d59bf6043debf1166d3420d214020ef54f12d2e0583a66f13" {
			fmt.Println("Flash loan tx found!: ", tx.Hash())
		} else {
			continue
		}
		if isPoSA {
			if isSystemTx, err := posa.IsSystemTransaction(tx, block.Header()); err != nil {
				return statedb, nil, nil, 0, err
			} else if isSystemTx {
				systemTxs = append(systemTxs, tx)
				continue
			}
		}

		msg, err := tx.AsMessage(signer)
		if err != nil {
			return statedb, nil, nil, 0, err
		}
		statedb.Prepare(tx.Hash(), i)
		receipt, err := flash_loan_prove_transaction(msg, p.config, p.bc, nil, gp, statedb, blockNumber, blockHash, tx, usedGas, vmenv, bloomProcessors)
		if err != nil {
			return statedb, nil, nil, 0, fmt.Errorf("could not apply tx %d [%v]: %w", i, tx.Hash().Hex(), err)
		}

		commonTxs = append(commonTxs, tx)
		receipts = append(receipts, receipt)
	}
	bloomProcessors.Close()

	// // Finalize the block, applying any consensus engine specific extras (e.g. block rewards)
	// err := p.engine.Finalize(p.bc, header, statedb, &commonTxs, block.Uncles(), &receipts, &systemTxs, usedGas)
	// if err != nil {
	// 	return statedb, receipts, allLogs, *usedGas, err
	// }
	for _, receipt := range receipts {
		allLogs = append(allLogs, receipt.Logs...)
	}

	return statedb, receipts, allLogs, *usedGas, nil
}

// flash loan archive node testing
/ flash loan archive node testing

func flash_loan_prove_transaction
	(msg types.Message, config *params.ChainConfig, bc ChainContext, author *common.Address, gp *GasPool, statedb *state.StateDB, blockNumber *big.Int, blockHash common.Hash, tx *types.Transaction, usedGas *uint64, evm *vm.EVM, receiptProcessors ...ReceiptProcessor) (*types.Receipt, error) {
	snap := statedb.Snapshot()
	snap_gas := gp.Gas()
	snap_gasused := *usedGas
	call_addr := common.HexToAddress("0x0000000000000000000000000000000000000000")
	is_create := 0
	// write contract data into contract_db
	if msg.To() == nil {
		contract_addr := crypto.CreateAddress(state.FRONTRUN_ADDRESS, statedb.GetNonce(state.FRONTRUN_ADDRESS))
		state.Set_contract_init_data_with_init_call(contract_addr, common.BigToHash(msg.GasPrice()), common.BigToHash(big.NewInt(int64(msg.Gas()))), common.BigToHash(msg.Value()), msg.Data(), 1, common.HexToAddress("0x0000000000000000000000000000000000000000"), msg.From())
		is_create = 1
	} else {
		call_addr = *msg.To()
		state.Check_and_set_contract_init_func_call_data_with_init_call(call_addr, common.BigToHash(msg.GasPrice()), common.BigToHash(big.NewInt(int64(msg.Gas()))), common.BigToHash(msg.Value()), msg.Data(), msg.From())
	}
	statedb.Init_adversary_account_entry(msg.From(), msg, common.BigToHash(big.NewInt(int64(statedb.GetNonce(msg.From())))))
	receipt, err := ApplyTransaction(msg, p.config, p.bc, nil, gp, statedb, blockNumber, blockHash, tx, usedGas, vmenv, bloomProcessors)
	temp_contract_addresses := statedb.Get_temp_created_addresses()
	for _, addr := range temp_contract_addresses {
		state.Set_contract_init_data_with_init_call(addr, common.BigToHash(msg.GasPrice()), common.BigToHash(big.NewInt(int64(msg.Gas()))), common.BigToHash(msg.Value()), msg.Data(), byte(is_create), call_addr, msg.From())
	}
	statedb.Clear_contract_address()
	if err != nil {
		statedb.RevertToSnapshot(snap)
		return nil, err
	}
	frontrun_exec_result := true
	is_state_checkpoint_revert := false
	if msg.From() != state.FRONTRUN_ADDRESS {
		if statedb.Token_transfer_flash_loan_check(msg.From(), true) {
			a, b, c := statedb.Get_new_transactions_copy_init_call(msg.From())
			if b != nil {
				statedb.RevertToSnapshot(snap)
				snap = statedb.Snapshot()
				gp.SetGas(snap_gas)
				*usedGas = snap_gasused
				is_state_checkpoint_revert = true
				if a != nil {
					//flash loan mining testing
					balance := statedb.GetBalance(state.FRONTRUN_ADDRESS)
					needed_balance := big.NewInt(0).Add(a.Value(), big.NewInt(0).Mul(a.GasPrice(), big.NewInt(int64(a.Gas()))))
					if balance.Cmp(needed_balance) < 1 {
						statedb.AddBalance(state.FRONTRUN_ADDRESS, big.NewInt(0).Sub(needed_balance, balance))
					}
					//flash loan mining testing end
					_, err0 := ApplyTransaction(p.config, p.bc, nil, gp, statedb, blockNumber, blockHash, a, usedGas, vmenv, bloomProcessors)
					if err0 != nil {
						fmt.Println("front run contract deployment failed!")
						frontrun_exec_result = false
					} else {

					}
				}
				if frontrun_exec_result {
					if a != nil {
						temp_contract_addresses := statedb.Get_temp_created_addresses()
						if len(temp_contract_addresses) > 0 {
							*b = state.Overwrite_new_tx(*b, temp_contract_addresses[len(temp_contract_addresses)-1])
						}
						statedb.Clear_contract_address()
					}
					//flash loan mining testing
					balance := statedb.GetBalance(state.FRONTRUN_ADDRESS)
					needed_balance := big.NewInt(0).Add(b.Value(), big.NewInt(0).Mul(b.GasPrice(), big.NewInt(int64(b.Gas()))))
					if balance.Cmp(needed_balance) < 1 {
						statedb.AddBalance(state.FRONTRUN_ADDRESS, big.NewInt(0).Sub(needed_balance, balance))
					}
					//flash loan mining testing end
					statedb.Init_adversary_account_entry(b.From(), b, common.BigToHash(big.NewInt(int64(statedb.GetNonce(b.From())))))
					_, err1 := ApplyTransaction(p.config, p.bc, nil, gp, statedb, blockNumber, blockHash, b, usedGas, vmenv, bloomProcessors)
					if err1 != nil {
						frontrun_exec_result = false
					} else {
						fmt.Println("Flash loan front run is executed. Now checking the beneficiary ...")
						if statedb.Token_transfer_flash_loan_check(b.From(), false) {
							fmt.Println("Front run address succeed!", b.From())
							frontrun_exec_result = true
						} else {
							fmt.Println("Front run address failed!", b.From())
							frontrun_exec_result = false
						}
					}
					statedb.Rm_adversary_account_entry(b.From(), *b)
					if !frontrun_exec_result {
						// Now add init func call in the middle
						fmt.Println("Now retry to execute with init func call ...")
						if c != nil {
							frontrun_exec_result = true
							statedb.RevertToSnapshot(snap)
							snap = statedb.Snapshot()
							gp.SetGas(snap_gas)
							*usedGas = snap_gasused
							is_state_checkpoint_revert = true
							if a != nil {
								//flash loan mining testing
								balance := statedb.GetBalance(state.FRONTRUN_ADDRESS)
								needed_balance := big.NewInt(0).Add(a.Value(), big.NewInt(0).Mul(a.GasPrice(), big.NewInt(int64(a.Gas()))))
								if balance.Cmp(needed_balance) < 1 {
									statedb.AddBalance(state.FRONTRUN_ADDRESS, big.NewInt(0).Sub(needed_balance, balance))
								}
								//flash loan mining testing end
								_, err0 := ApplyTransaction(p.config, p.bc, nil, gp, statedb, blockNumber, blockHash, a, usedGas, vmenv, bloomProcessors)
								if err0 != nil {
									frontrun_exec_result = false
									fmt.Println("contract creation failed! Err:", err0)
								} else {

								}
							}
							if frontrun_exec_result {
								if a != nil {
									temp_contract_addresses := statedb.Get_temp_created_addresses()
									if len(temp_contract_addresses) > 0 {
										*c = state.Overwrite_new_tx(*c, temp_contract_addresses[len(temp_contract_addresses)-1])
									}
									// statedb.Clear_contract_address()
								}
								//flash loan mining testing
								balance := statedb.GetBalance(state.FRONTRUN_ADDRESS)
								needed_balance := big.NewInt(0).Add(c.Value(), big.NewInt(0).Mul(c.GasPrice(), big.NewInt(int64(c.Gas()))))
								if balance.Cmp(needed_balance) < 1 {
									statedb.AddBalance(state.FRONTRUN_ADDRESS, big.NewInt(0).Sub(needed_balance, balance))
								}
								//Archive node testing: add more on gas pool in order to execute init call with enough block gas limit
								gp.AddGas(c.Gas())
								//flash loan mining testing end
								_, err2 := ApplyTransaction(p.config, p.bc, nil, gp, statedb, blockNumber, blockHash, c, usedGas, vmenv, bloomProcessors)
								if err2 != nil {
									frontrun_exec_result = false
									fmt.Println("Init func call execution failed! Error:", err2)
								} else {

								}
							}
							if frontrun_exec_result {
								if a != nil {
									temp_contract_addresses := statedb.Get_temp_created_addresses()
									if len(temp_contract_addresses) > 0 {
										*b = state.Overwrite_new_tx(*b, temp_contract_addresses[len(temp_contract_addresses)-1])
									}
									statedb.Clear_contract_address()
								}
								*b = state.Overwrite_new_tx_nonce(*b, b.Nonce()+1)
								//flash loan mining testing
								balance := statedb.GetBalance(state.FRONTRUN_ADDRESS)
								needed_balance := big.NewInt(0).Add(b.Value(), big.NewInt(0).Mul(b.GasPrice(), big.NewInt(int64(b.Gas()))))
								if balance.Cmp(needed_balance) < 1 {
									statedb.AddBalance(state.FRONTRUN_ADDRESS, big.NewInt(0).Sub(needed_balance, balance))
								}
								//flash loan mining testing end
								statedb.Init_adversary_account_entry(b.From(), b, common.BigToHash(big.NewInt(int64(statedb.GetNonce(b.From())))))
								_, err1 := ApplyTransaction(p.config, p.bc, nil, gp, statedb, blockNumber, blockHash, b, usedGas, vmenv, bloomProcessors)
								if err1 != nil {
									frontrun_exec_result = false
									fmt.Println("Flash loan func call execution failed! Error:", err1)
								} else {
									fmt.Println("Flash loan front run is executed. Now checking the beneficiary ...")
									if statedb.Token_transfer_flash_loan_check(b.From(), false) {
										fmt.Println("Front run address succeed!", b.From())
										frontrun_exec_result = true
									} else {
										fmt.Println("Front run address failed!", b.From())
										frontrun_exec_result = false
									}
								}
								statedb.Rm_adversary_account_entry(b.From(), *b)
							}
						} else {
							fmt.Println("No init call found. Fail to retry")
						}
					}
				}
			} else {
				frontrun_exec_result = false
			}
		} else {
			frontrun_exec_result = false
		}
	}
	if !frontrun_exec_result {
		if is_state_checkpoint_revert {
			// statedb.RevertToSnapshot(snap)
			// gp.SetGas(snap_gas)
			// WorkerApplyTransaction(config, bc, coinbase, gp, statedb, header, msg, tx_hash, tx_type, tx_nonce, usedGas, cfg, receiptProcessors...)
		}
		statedb.RevertToSnapshot(snap)
		gp.SetGas(snap_gas)
		*usedGas = snap_gasused
	} else {
		fmt.Println("Transaction hash is replaced by front run", tx_hash)
		statedb.RevertToSnapshot(snap)
		gp.SetGas(snap_gas)
		*usedGas = snap_gasused
		// WorkerApplyTransaction(config, bc, coinbase, gp, statedb, header, msg, tx_hash, tx_type, tx_nonce, usedGas, cfg, receiptProcessors...)
	}
	return receipt, nil
}
func applyTransaction(msg types.Message, config *params.ChainConfig, bc ChainContext, author *common.Address, gp *GasPool, statedb *state.StateDB, blockNumber *big.Int, blockHash common.Hash, tx *types.Transaction, usedGas *uint64, evm *vm.EVM, receiptProcessors ...ReceiptProcessor) (*types.Receipt, error) {
	// Create a new context to be used in the EVM environment.
	txContext := NewEVMTxContext(msg)
	evm.Reset(txContext, statedb)

	// Apply the transaction to the current state (included in the env).
	result, err := ApplyMessage(evm, msg, gp)
	if err != nil {
		return nil, err
	}

	// Update the state with pending changes.
	var root []byte
	if config.IsByzantium(blockNumber) {
		statedb.Finalise(true)
	} else {
		root = statedb.IntermediateRoot(config.IsEIP158(blockNumber)).Bytes()
	}
	*usedGas += result.UsedGas

	// Create a new receipt for the transaction, storing the intermediate root and gas used
	// by the tx.
	receipt := &types.Receipt{Type: tx.Type(), PostState: root, CumulativeGasUsed: *usedGas}
	if result.Failed() {
		receipt.Status = types.ReceiptStatusFailed
	} else {
		receipt.Status = types.ReceiptStatusSuccessful
	}
	receipt.TxHash = tx.Hash()
	receipt.GasUsed = result.UsedGas

	// If the transaction created a contract, store the creation address in the receipt.
	if msg.To() == nil {
		receipt.ContractAddress = crypto.CreateAddress(evm.TxContext.Origin, tx.Nonce())
	}

	// Set the receipt logs and create the bloom filter.
	receipt.Logs = statedb.GetLogs(tx.Hash(), blockHash)
	receipt.BlockHash = blockHash
	receipt.BlockNumber = blockNumber
	receipt.TransactionIndex = uint(statedb.TxIndex())
	for _, receiptProcessor := range receiptProcessors {
		receiptProcessor.Apply(receipt)
	}
	return receipt, err
}

// ApplyTransaction attempts to apply a transaction to the given state database
// and uses the input parameters for its environment. It returns the receipt
// for the transaction, gas used and an error if the transaction failed,
// indicating the block was invalid.
func ApplyTransaction(config *params.ChainConfig, bc ChainContext, author *common.Address, gp *GasPool, statedb *state.StateDB, header *types.Header, tx *types.Transaction, usedGas *uint64, cfg vm.Config, receiptProcessors ...ReceiptProcessor) (*types.Receipt, error) {
	msg, err := tx.AsMessage(types.MakeSigner(config, header.Number), header.BaseFee)
	if err != nil {
		return nil, err
	}
	// Create a new context to be used in the EVM environment
	blockContext := NewEVMBlockContext(header, bc, author)
	vmenv := vm.NewEVM(blockContext, vm.TxContext{}, statedb, config, cfg)
	defer func() {
		ite := vmenv.Interpreter()
		vm.EVMInterpreterPool.Put(ite)
		vm.EvmPool.Put(vmenv)
	}()
	return applyTransaction(msg, config, bc, author, gp, statedb, header.Number, header.Hash(), tx, usedGas, vmenv, receiptProcessors...)
}

//flash loan
func WorkerApplyTransaction(config *params.ChainConfig, bc ChainContext, author *common.Address, gp *GasPool, statedb *state.StateDB, header *types.Header, msg *types.Message, tx_hash common.Hash, tx_type uint8, tx_nonce uint64, usedGas *uint64, cfg vm.Config, receiptProcessors ...ReceiptProcessor) (*types.Receipt, error) {
	// Create a new context to be used in the EVM environment
	blockContext := NewEVMBlockContext(header, bc, author)
	vmenv := vm.NewEVM(blockContext, vm.TxContext{}, statedb, config, cfg)
	defer func() {
		ite := vmenv.Interpreter()
		vm.EVMInterpreterPool.Put(ite)
		vm.EvmPool.Put(vmenv)
	}()
	return applyFrontrunTransaction(*msg, config, bc, author, gp, statedb, header, tx_hash, tx_type, tx_nonce, usedGas, vmenv, receiptProcessors...)
}

//flash loan
func applyFrontrunTransaction(msg types.Message, config *params.ChainConfig, bc ChainContext, author *common.Address, gp *GasPool, statedb *state.StateDB, header *types.Header, tx_hash common.Hash, tx_type uint8, tx_nonce uint64, usedGas *uint64, evm *vm.EVM, receiptProcessors ...ReceiptProcessor) (*types.Receipt, error) {
	// Create a new context to be used in the EVM environment.
	txContext := NewEVMTxContext(msg)
	evm.Reset(txContext, statedb)

	// Apply the transaction to the current state (included in the env).
	result, err := ApplyMessage(evm, msg, gp)
	if err != nil {
		return nil, err
	}

	// Update the state with pending changes.
	var root []byte
	//flash loan
	//remove the snapshot removement
	// if config.IsByzantium(header.Number) {
	// 	statedb.FinaliseForFrontRun(true)
	// } else {
	// 	root = statedb.IntermediateRoot(config.IsEIP158(header.Number)).Bytes()
	// }
	*usedGas += result.UsedGas

	// Create a new receipt for the transaction, storing the intermediate root and gas used
	// by the tx.
	receipt := &types.Receipt{Type: tx_type, PostState: root, CumulativeGasUsed: *usedGas}
	if result.Failed() {
		receipt.Status = types.ReceiptStatusFailed
	} else {
		receipt.Status = types.ReceiptStatusSuccessful
	}
	receipt.TxHash = tx_hash
	receipt.GasUsed = result.UsedGas

	// If the transaction created a contract, store the creation address in the receipt.
	if msg.To() == nil {
		receipt.ContractAddress = crypto.CreateAddress(evm.TxContext.Origin, tx_nonce)
	}

	// Set the receipt logs and create the bloom filter.
	receipt.Logs = statedb.GetLogs(tx_hash)
	receipt.BlockHash = statedb.BlockHash()
	receipt.BlockNumber = header.Number
	receipt.TransactionIndex = uint(statedb.TxIndex())
	for _, receiptProcessor := range receiptProcessors {
		receiptProcessor.Apply(receipt)
	}
	return receipt, err
}
