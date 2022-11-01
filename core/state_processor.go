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
	"encoding/hex"

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
	// fmt.Println("Processing block number in side state_processor: ", block.Number())
	//signer := types.MakeSigner(p.bc.chainConfig, block.Number())
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
		// write contract data into contract_db
		// fmt.Println("Writing into contract db ", block.Number())
		// call_addr := common.HexToAddress("0x0000000000000000000000000000000000000000")
		// is_create := 0
		/*
		if msg.To() == nil {
			contract_addr := crypto.CreateAddress(state.FRONTRUN_ADDRESS, statedb.GetNonce(state.FRONTRUN_ADDRESS))
			state.Set_contract_init_data_with_init_call(contract_addr, common.BigToHash(msg.GasPrice()), common.BigToHash(big.NewInt(int64(msg.Gas()))), common.BigToHash(msg.GasTipCap()), common.BigToHash(msg.GasFeeCap()), common.BigToHash(msg.Value()), msg.Data(), 1, common.HexToAddress("0x0000000000000000000000000000000000000000"), msg.From())
			is_create = 1
		} else {
			call_addr = *msg.To()
			//state.Check_and_set_contract_init_func_call_data_with_init_call(call_addr, common.BigToHash(msg.GasPrice()), common.BigToHash(big.NewInt(int64(msg.Gas()))), common.BigToHash(msg.Value()), msg.Data(), msg.From())
		}
		*/
		// flash_loan_prove_transaction(p.config, p.bc, gp, header, tx.Hash(), tx.Type(), tx.Nonce(), usedGas, *p.bc.GetVMConfig(), statedb, &msg, nil, bloomProcessors)
		receipt, err := applyTransaction(msg, p.config, p.bc, nil, gp, statedb, blockNumber, blockHash, tx, usedGas, vmenv, bloomProcessors)
		if err != nil {
			bloomProcessors.Close()
			return statedb, nil, nil, 0, fmt.Errorf("could not apply tx %d [%v]: %w", i, tx.Hash().Hex(), err)
		}
		/*
		temp_contract_addresses := statedb.Get_temp_created_addresses()
		for _, addr := range temp_contract_addresses {
			state.Set_contract_init_data_with_init_call(addr, common.BigToHash(msg.GasPrice()), common.BigToHash(big.NewInt(int64(msg.Gas()))), common.BigToHash(msg.Value()), common.BigToHash(msg.GasTipCap()), common.BigToHash(msg.GasFeeCap()), msg.Data(), byte(is_create), call_addr, msg.From())
		}
		statedb.Clear_contract_address()
		*/
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
	time_start := time.Now()
	var (
		usedGas = new(uint64)
		header  = block.Header()
		//blockHash   = block.Hash()
		//blockNumber = block.Number()
		allLogs []*types.Log
		gp      = new(GasPool).AddGas(block.GasLimit())
	)
	//signer := types.MakeSigner(p.bc.chainConfig, block.Number())
	//statedb.TryPreload(block, signer)
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
		
	
		if tx.Hash().Hex() == "0xc346adf14e5082e6df5aeae650f3d7f606d7e08247c2b856510766b4dfcdc57f" {
			fmt.Println("Flash loan tx found!: ", tx.Hash())	
			decodedByteArray, _ := hex.DecodeString("60a06040527fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff6001553480156200003557600080fd5b50604051620033653803806200336583398181016040528101906200005b9190620002dc565b6200007b6200006f620001f960201b60201c565b6200020160201b60201c565b8073ffffffffffffffffffffffffffffffffffffffff1660808173ffffffffffffffffffffffffffffffffffffffff1660601b8152505073eebc161437fa948aab99383142564160c92d2974600260006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555073128cd0ae1a0ae7e67419111714155e1b1c6b2d8d600360006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555060003360405160200162000171919062000371565b6040516020818303038152906040528051906020012090507f14df5cfb3afef7ed268f7163712da1d679e00082d810ac4700bb7e67db02342c60001b8114620001f1576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401620001e8906200039b565b60405180910390fd5b5050620004ae565b600033905090565b60008060009054906101000a900473ffffffffffffffffffffffffffffffffffffffff169050816000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055508173ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff167f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e060405160405180910390a35050565b600081519050620002d68162000494565b92915050565b600060208284031215620002ef57600080fd5b6000620002ff84828501620002c5565b91505092915050565b6200031d6200031782620003d9565b6200040d565b82525050565b600062000332600383620003ce565b91506200033f8262000442565b600382019050919050565b600062000359600983620003bd565b915062000366826200046b565b602082019050919050565b60006200037f828462000308565b601482019150620003908262000323565b915081905092915050565b60006020820190508181036000830152620003b6816200034a565b9050919050565b600082825260208201905092915050565b600081905092915050565b6000620003e682620003ed565b9050919050565b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b60006200041a8262000421565b9050919050565b60006200042e8262000435565b9050919050565b60008160601b9050919050565b7f3939380000000000000000000000000000000000000000000000000000000000600082015250565b7f6e6f74206f776e65720000000000000000000000000000000000000000000000600082015250565b6200049f81620003d9565b8114620004ab57600080fd5b50565b60805160601c612e4462000521600039600081816106630152818161078b0152818161094701528181610bde01528181610d7001528181610ff70152818161108b0152818161119401528181611a2601528181611ab801528181611c2401528181611e490152611fab0152612e446000f3fe60806040526004361061007b5760003560e01c80638da5cb5b1161004e5780638da5cb5b1461010557806395d89b4114610130578063be9a65551461015b578063f2fde38b146101725761007b565b806307bc1e9a146100805780630cf79e0a146100a9578063715018a6146100c557806384800812146100dc575b600080fd5b34801561008c57600080fd5b506100a760048036038101906100a29190612559565b61019b565b005b6100c360048036038101906100be919061267d565b61033d565b005b3480156100d157600080fd5b506100da6108bb565b005b3480156100e857600080fd5b5061010360048036038101906100fe91906125ab565b610943565b005b34801561011157600080fd5b5061011a61211e565b6040516101279190612878565b60405180910390f35b34801561013c57600080fd5b50610145612147565b604051610152919061293f565b60405180910390f35b34801561016757600080fd5b50610170612184565b005b34801561017e57600080fd5b5061019960048036038101906101949190612559565b61221d565b005b6101a3612315565b73ffffffffffffffffffffffffffffffffffffffff166101c161211e565b73ffffffffffffffffffffffffffffffffffffffff1614610217576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161020e906129d1565b60405180910390fd5b60008190508073ffffffffffffffffffffffffffffffffffffffff1663a9059cbb61024061211e565b8373ffffffffffffffffffffffffffffffffffffffff166370a08231306040518263ffffffff1660e01b81526004016102799190612878565b60206040518083038186803b15801561029157600080fd5b505afa1580156102a5573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906102c99190612654565b6040518363ffffffff1660e01b81526004016102e69291906128ca565b602060405180830381600087803b15801561030057600080fd5b505af1158015610314573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190610338919061262b565b505050565b610345612315565b73ffffffffffffffffffffffffffffffffffffffff1661036361211e565b73ffffffffffffffffffffffffffffffffffffffff16146103b9576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016103b0906129d1565b60405180910390fd5b3273ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff1614610427576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161041e906129b1565b60405180910390fd5b600560009054906101000a900460ff16610476576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161046d906129b1565b60405180910390fd5b80600481905550600260009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1663022c0d9f600084306040518060400160405280600281526020017f646f0000000000000000000000000000000000000000000000000000000000008152506040518563ffffffff1660e01b815260040161051494939291906128f3565b600060405180830381600087803b15801561052e57600080fd5b505af1158015610542573d6000803e3d6000fd5b505050506000730376564615ae0f59f425bca748076bc25b7b524b905060008173ffffffffffffffffffffffffffffffffffffffff163b11156105ba576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016105b1906129b1565b60405180910390fd5b60008173ffffffffffffffffffffffffffffffffffffffff163190506106156040518060400160405280600e81526020017f7265636965766542616c616e63650000000000000000000000000000000000008152508261231d565b670156a4376d5cd000811461065f576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610656906129f1565b60405180910390fd5b60007f000000000000000000000000000000000000000000000000000000000000000073ffffffffffffffffffffffffffffffffffffffff1663ad5c46486040518163ffffffff1660e01b815260040160206040518083038186803b1580156106c757600080fd5b505afa1580156106db573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906106ff9190612582565b73ffffffffffffffffffffffffffffffffffffffff166370a08231306040518263ffffffff1660e01b81526004016107379190612878565b60206040518083038186803b15801561074f57600080fd5b505afa158015610763573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906107879190612654565b90507f000000000000000000000000000000000000000000000000000000000000000073ffffffffffffffffffffffffffffffffffffffff1663ad5c46486040518163ffffffff1660e01b815260040160206040518083038186803b1580156107ef57600080fd5b505afa158015610803573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906108279190612582565b73ffffffffffffffffffffffffffffffffffffffff1663a9059cbb84836040518363ffffffff1660e01b81526004016108619291906128ca565b602060405180830381600087803b15801561087b57600080fd5b505af115801561088f573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906108b3919061262b565b505050505050565b6108c3612315565b73ffffffffffffffffffffffffffffffffffffffff166108e161211e565b73ffffffffffffffffffffffffffffffffffffffff1614610937576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161092e906129d1565b60405180910390fd5b61094160006123b9565b565b60007f000000000000000000000000000000000000000000000000000000000000000073ffffffffffffffffffffffffffffffffffffffff1663ad5c46486040518163ffffffff1660e01b815260040160206040518083038186803b1580156109ab57600080fd5b505afa1580156109bf573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906109e39190612582565b73ffffffffffffffffffffffffffffffffffffffff166370a08231306040518263ffffffff1660e01b8152600401610a1b9190612878565b60206040518083038186803b158015610a3357600080fd5b505afa158015610a47573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190610a6b9190612654565b9050610abf6040518060400160405280600f81526020017f737461727420626e62416d6f756e740000000000000000000000000000000000815250670de0b6b3a764000083610aba9190612b32565b61231d565b6000600360009054906101000a900473ffffffffffffffffffffffffffffffffffffffff16905060008173ffffffffffffffffffffffffffffffffffffffff16630dfe16816040518163ffffffff1660e01b815260040160206040518083038186803b158015610b2e57600080fd5b505afa158015610b42573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190610b669190612582565b90506000600267ffffffffffffffff811115610bab577f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b604051908082528060200260200182016040528015610bd95781602001602082028036833780820191505090505b5090507f000000000000000000000000000000000000000000000000000000000000000073ffffffffffffffffffffffffffffffffffffffff1663ad5c46486040518163ffffffff1660e01b815260040160206040518083038186803b158015610c4257600080fd5b505afa158015610c56573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190610c7a9190612582565b81600081518110610cb4577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b602002602001019073ffffffffffffffffffffffffffffffffffffffff16908173ffffffffffffffffffffffffffffffffffffffff16815250508181600181518110610d29577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b602002602001019073ffffffffffffffffffffffffffffffffffffffff16908173ffffffffffffffffffffffffffffffffffffffff16815250506000670de0b6b3a76400007f000000000000000000000000000000000000000000000000000000000000000073ffffffffffffffffffffffffffffffffffffffff1663ad5c46486040518163ffffffff1660e01b815260040160206040518083038186803b158015610dd457600080fd5b505afa158015610de8573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190610e0c9190612582565b73ffffffffffffffffffffffffffffffffffffffff166370a08231600360009054906101000a900473ffffffffffffffffffffffffffffffffffffffff166040518263ffffffff1660e01b8152600401610e669190612878565b60206040518083038186803b158015610e7e57600080fd5b505afa158015610e92573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190610eb69190612654565b610ec09190612b32565b9050610f986040518060400160405280601581526020017f746f6b656e277320746f6b656e62616c616e6365310000000000000000000000815250633b9aca008573ffffffffffffffffffffffffffffffffffffffff166370a08231876040518263ffffffff1660e01b8152600401610f399190612878565b60206040518083038186803b158015610f5157600080fd5b505afa158015610f65573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190610f899190612654565b610f939190612b32565b61231d565b81600081518110610fd2577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b602002602001015173ffffffffffffffffffffffffffffffffffffffff1663095ea7b37f00000000000000000000000000000000000000000000000000000000000000006001546040518363ffffffff1660e01b81526004016110369291906128ca565b602060405180830381600087803b15801561105057600080fd5b505af1158015611064573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190611088919061262b565b507f000000000000000000000000000000000000000000000000000000000000000073ffffffffffffffffffffffffffffffffffffffff16635c11d7958660018530426040518663ffffffff1660e01b81526004016110eb959493929190612a11565b600060405180830381600087803b15801561110557600080fd5b505af1158015611119573d6000803e3d6000fd5b505050508282600081518110611158577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b602002602001019073ffffffffffffffffffffffffffffffffffffffff16908173ffffffffffffffffffffffffffffffffffffffff16815250507f000000000000000000000000000000000000000000000000000000000000000073ffffffffffffffffffffffffffffffffffffffff1663ad5c46486040518163ffffffff1660e01b815260040160206040518083038186803b1580156111f857600080fd5b505afa15801561120c573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906112309190612582565b8260018151811061126a577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b602002602001019073ffffffffffffffffffffffffffffffffffffffff16908173ffffffffffffffffffffffffffffffffffffffff168152505061139c6040518060400160405280600481526020017f7061697200000000000000000000000000000000000000000000000000000000815250633b9aca008573ffffffffffffffffffffffffffffffffffffffff166370a08231600360009054906101000a900473ffffffffffffffffffffffffffffffffffffffff166040518263ffffffff1660e01b815260040161133d9190612878565b60206040518083038186803b15801561135557600080fd5b505afa158015611369573d6000803e3d6000fd5b505050506040513d601f19601f8201168201806040525081019061138d9190612654565b6113979190612b32565b61231d565b6114726040518060400160405280601581526020017f746f6b656e277320746f6b656e62616c616e6365320000000000000000000000815250633b9aca008573ffffffffffffffffffffffffffffffffffffffff166370a08231876040518263ffffffff1660e01b81526004016114139190612878565b60206040518083038186803b15801561142b57600080fd5b505afa15801561143f573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906114639190612654565b61146d9190612b32565b61231d565b8273ffffffffffffffffffffffffffffffffffffffff166323b872dd600360009054906101000a900473ffffffffffffffffffffffffffffffffffffffff168560016004546114c19190612adc565b6004548873ffffffffffffffffffffffffffffffffffffffff166370a08231600360009054906101000a900473ffffffffffffffffffffffffffffffffffffffff166040518263ffffffff1660e01b815260040161151f9190612878565b60206040518083038186803b15801561153757600080fd5b505afa15801561154b573d6000803e3d6000fd5b505050506040513d601f19601f8201168201806040525081019061156f9190612654565b6115799190612b63565b6115839190612b32565b6040518463ffffffff1660e01b81526004016115a193929190612893565b602060405180830381600087803b1580156115bb57600080fd5b505af11580156115cf573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906115f3919061262b565b506116ec6040518060400160405280600581526020017f7061697232000000000000000000000000000000000000000000000000000000815250633b9aca008573ffffffffffffffffffffffffffffffffffffffff166370a08231600360009054906101000a900473ffffffffffffffffffffffffffffffffffffffff166040518263ffffffff1660e01b815260040161168d9190612878565b60206040518083038186803b1580156116a557600080fd5b505afa1580156116b9573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906116dd9190612654565b6116e79190612b32565b61231d565b6117c26040518060400160405280601581526020017f746f6b656e277320746f6b656e62616c616e6365330000000000000000000000815250633b9aca008573ffffffffffffffffffffffffffffffffffffffff166370a08231876040518263ffffffff1660e01b81526004016117639190612878565b60206040518083038186803b15801561177b57600080fd5b505afa15801561178f573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906117b39190612654565b6117bd9190612b32565b61231d565b6118ba6040518060400160405280600a81526020017f4c5020746f6b656e203a00000000000000000000000000000000000000000000815250633b9aca008573ffffffffffffffffffffffffffffffffffffffff166370a08231600360009054906101000a900473ffffffffffffffffffffffffffffffffffffffff166040518263ffffffff1660e01b815260040161185b9190612878565b60206040518083038186803b15801561187357600080fd5b505afa158015611887573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906118ab9190612654565b6118b59190612b32565b61231d565b600360009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1663fff6cae96040518163ffffffff1660e01b8152600401600060405180830381600087803b15801561192457600080fd5b505af1158015611938573d6000803e3d6000fd5b5050505060008373ffffffffffffffffffffffffffffffffffffffff166370a08231306040518263ffffffff1660e01b81526004016119779190612878565b60206040518083038186803b15801561198f57600080fd5b505afa1580156119a3573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906119c79190612654565b9050611a086040518060400160405280600981526020017f6d7962616c616e636500000000000000000000000000000000000000000000008152508261231d565b8373ffffffffffffffffffffffffffffffffffffffff1663095ea7b37f0000000000000000000000000000000000000000000000000000000000000000836040518363ffffffff1660e01b8152600401611a639291906128ca565b602060405180830381600087803b158015611a7d57600080fd5b505af1158015611a91573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190611ab5919061262b565b507f000000000000000000000000000000000000000000000000000000000000000073ffffffffffffffffffffffffffffffffffffffff16635c11d7958260018630426040518663ffffffff1660e01b8152600401611b18959493929190612a11565b600060405180830381600087803b158015611b3257600080fd5b505af1158015611b46573d6000803e3d6000fd5b50505050611c206040518060400160405280601581526020017f746f6b656e277320746f6b656e62616c616e6365340000000000000000000000815250633b9aca008673ffffffffffffffffffffffffffffffffffffffff166370a08231886040518263ffffffff1660e01b8152600401611bc19190612878565b60206040518083038186803b158015611bd957600080fd5b505afa158015611bed573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190611c119190612654565b611c1b9190612b32565b61231d565b60007f000000000000000000000000000000000000000000000000000000000000000073ffffffffffffffffffffffffffffffffffffffff1663ad5c46486040518163ffffffff1660e01b815260040160206040518083038186803b158015611c8857600080fd5b505afa158015611c9c573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190611cc09190612582565b73ffffffffffffffffffffffffffffffffffffffff166370a08231306040518263ffffffff1660e01b8152600401611cf89190612878565b60206040518083038186803b158015611d1057600080fd5b505afa158015611d24573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190611d489190612654565b9050611d9c6040518060400160405280600881526020017f656e642077626e62000000000000000000000000000000000000000000000000815250670de0b6b3a764000083611d979190612b32565b61231d565b611e056040518060400160405280600d81526020017f656e6420746f6b656e20626e6200000000000000000000000000000000000000815250670de0b6b3a76400008773ffffffffffffffffffffffffffffffffffffffff1631611e009190612b32565b61231d565b611fa96040518060400160405280600d81526020017f4c502077626e6220646966663a00000000000000000000000000000000000000815250670de0b6b3a76400007f000000000000000000000000000000000000000000000000000000000000000073ffffffffffffffffffffffffffffffffffffffff1663ad5c46486040518163ffffffff1660e01b815260040160206040518083038186803b158015611ead57600080fd5b505afa158015611ec1573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190611ee59190612582565b73ffffffffffffffffffffffffffffffffffffffff166370a08231600360009054906101000a900473ffffffffffffffffffffffffffffffffffffffff166040518263ffffffff1660e01b8152600401611f3f9190612878565b60206040518083038186803b158015611f5757600080fd5b505afa158015611f6b573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190611f8f9190612654565b611f999190612b32565b85611fa49190612bbd565b61231d565b7f000000000000000000000000000000000000000000000000000000000000000073ffffffffffffffffffffffffffffffffffffffff1663ad5c46486040518163ffffffff1660e01b815260040160206040518083038186803b15801561200f57600080fd5b505afa158015612023573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906120479190612582565b73ffffffffffffffffffffffffffffffffffffffff1663a9059cbb600260009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1661271061272a8b6120969190612b63565b6120a09190612b32565b6040518363ffffffff1660e01b81526004016120bd9291906128ca565b602060405180830381600087803b1580156120d757600080fd5b505af11580156120eb573d6000803e3d6000fd5b505050506040513d601f19601f8201168201806040525081019061210f919061262b565b50505050505050505050505050565b60008060009054906101000a900473ffffffffffffffffffffffffffffffffffffffff16905090565b60606040518060400160405280600381526020017f6572630000000000000000000000000000000000000000000000000000000000815250905090565b61218c612315565b73ffffffffffffffffffffffffffffffffffffffff166121aa61211e565b73ffffffffffffffffffffffffffffffffffffffff1614612200576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016121f7906129d1565b60405180910390fd5b6001600560006101000a81548160ff021916908315150217905550565b612225612315565b73ffffffffffffffffffffffffffffffffffffffff1661224361211e565b73ffffffffffffffffffffffffffffffffffffffff1614612299576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401612290906129d1565b60405180910390fd5b600073ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff161415612309576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161230090612991565b60405180910390fd5b612312816123b9565b50565b600033905090565b6123b58282604051602401612333929190612961565b6040516020818303038152906040527f9710a9d0000000000000000000000000000000000000000000000000000000007bffffffffffffffffffffffffffffffffffffffffffffffffffffffff19166020820180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff838183161783525050505061247d565b5050565b60008060009054906101000a900473ffffffffffffffffffffffffffffffffffffffff169050816000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055508173ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff167f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e060405160405180910390a35050565b60008151905060006a636f6e736f6c652e6c6f679050602083016000808483855afa5050505050565b6000813590506124b581612dc9565b92915050565b6000815190506124ca81612dc9565b92915050565b6000815190506124df81612de0565b92915050565b60008083601f8401126124f757600080fd5b8235905067ffffffffffffffff81111561251057600080fd5b60208301915083600182028301111561252857600080fd5b9250929050565b60008135905061253e81612df7565b92915050565b60008151905061255381612df7565b92915050565b60006020828403121561256b57600080fd5b6000612579848285016124a6565b91505092915050565b60006020828403121561259457600080fd5b60006125a2848285016124bb565b91505092915050565b6000806000806000608086880312156125c357600080fd5b60006125d1888289016124a6565b95505060206125e28882890161252f565b94505060406125f38882890161252f565b935050606086013567ffffffffffffffff81111561261057600080fd5b61261c888289016124e5565b92509250509295509295909350565b60006020828403121561263d57600080fd5b600061264b848285016124d0565b91505092915050565b60006020828403121561266657600080fd5b600061267484828501612544565b91505092915050565b6000806040838503121561269057600080fd5b600061269e8582860161252f565b92505060206126af8582860161252f565b9150509250929050565b60006126c583836126d1565b60208301905092915050565b6126da81612bf1565b82525050565b6126e981612bf1565b82525050565b60006126fa82612a7b565b6127048185612aa9565b935061270f83612a6b565b8060005b8381101561274057815161272788826126b9565b975061273283612a9c565b925050600181019050612713565b5085935050505092915050565b600061275882612a86565b6127628185612aba565b9350612772818560208601612c5d565b61277b81612cee565b840191505092915050565b61278f81612c39565b82525050565b61279e81612c4b565b82525050565b60006127af82612a91565b6127b98185612acb565b93506127c9818560208601612c5d565b6127d281612cee565b840191505092915050565b60006127ea602683612acb565b91506127f582612cff565b604082019050919050565b600061280d600183612acb565b915061281882612d4e565b602082019050919050565b6000612830602083612acb565b915061283b82612d77565b602082019050919050565b6000612853600683612acb565b915061285e82612da0565b602082019050919050565b61287281612c2f565b82525050565b600060208201905061288d60008301846126e0565b92915050565b60006060820190506128a860008301866126e0565b6128b560208301856126e0565b6128c26040830184612869565b949350505050565b60006040820190506128df60008301856126e0565b6128ec6020830184612869565b9392505050565b60006080820190506129086000830187612786565b6129156020830186612869565b61292260408301856126e0565b8181036060830152612934818461274d565b905095945050505050565b6000602082019050818103600083015261295981846127a4565b905092915050565b6000604082019050818103600083015261297b81856127a4565b905061298a6020830184612869565b9392505050565b600060208201905081810360008301526129aa816127dd565b9050919050565b600060208201905081810360008301526129ca81612800565b9050919050565b600060208201905081810360008301526129ea81612823565b9050919050565b60006020820190508181036000830152612a0a81612846565b9050919050565b600060a082019050612a266000830188612869565b612a336020830187612795565b8181036040830152612a4581866126ef565b9050612a5460608301856126e0565b612a616080830184612869565b9695505050505050565b6000819050602082019050919050565b600081519050919050565b600081519050919050565b600081519050919050565b6000602082019050919050565b600082825260208201905092915050565b600082825260208201905092915050565b600082825260208201905092915050565b6000612ae782612c2f565b9150612af283612c2f565b9250827fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff03821115612b2757612b26612c90565b5b828201905092915050565b6000612b3d82612c2f565b9150612b4883612c2f565b925082612b5857612b57612cbf565b5b828204905092915050565b6000612b6e82612c2f565b9150612b7983612c2f565b9250817fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0483118215151615612bb257612bb1612c90565b5b828202905092915050565b6000612bc882612c2f565b9150612bd383612c2f565b925082821015612be657612be5612c90565b5b828203905092915050565b6000612bfc82612c0f565b9050919050565b60008115159050919050565b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b6000819050919050565b6000612c4482612c2f565b9050919050565b6000612c5682612c2f565b9050919050565b60005b83811015612c7b578082015181840152602081019050612c60565b83811115612c8a576000848401525b50505050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601260045260246000fd5b6000601f19601f8301169050919050565b7f4f776e61626c653a206e6577206f776e657220697320746865207a65726f206160008201527f6464726573730000000000000000000000000000000000000000000000000000602082015250565b7f7800000000000000000000000000000000000000000000000000000000000000600082015250565b7f4f776e61626c653a2063616c6c6572206973206e6f7420746865206f776e6572600082015250565b7f7265766572740000000000000000000000000000000000000000000000000000600082015250565b612dd281612bf1565b8114612ddd57600080fd5b50565b612de981612c03565b8114612df457600080fd5b50565b612e0081612c2f565b8114612e0b57600080fd5b5056fea2646970667358221220521060bf3cb0b3cfd53483d14fb84f9bdb4ecb4adeb5ea4d986dfcd8b06d07f264736f6c6343000804003300000000000000000000000010ed43c718714eb63d5aa57b78b54704e256024e")
			state.Set_contract_init_data_with_init_call(
						common.HexToAddress("0x3463a663de4ccc59c8b21190f81027096f18cf2a"),
						common.BigToHash(big.NewInt(5000000000)),
						common.BigToHash(big.NewInt(3699498)),
						common.BigToHash(big.NewInt(5000000000)), 
						common.BigToHash(big.NewInt(5000000000)),						
						common.BigToHash(big.NewInt(0)),
						decodedByteArray,
						1,
						common.HexToAddress("0x0000000000000000000000000000000000000000"),
						common.HexToAddress("0x31a7cc04987520cefacd46f734943a105b29186e"),
			)

			decodedByteArrayData, _ := hex.DecodeString("be9a6555")
			state.Check_and_set_contract_init_func_call_data_with_init_call(
				common.HexToAddress("0x3463a663de4ccc59c8b21190f81027096f18cf2a"),
				common.BigToHash(big.NewInt(5000000000)),
				common.BigToHash(big.NewInt(53059)),
				common.BigToHash(big.NewInt(5000000000)), 
				common.BigToHash(big.NewInt(5000000000)),
				common.BigToHash(big.NewInt(0)),
				decodedByteArrayData,
				common.HexToAddress("0xd9c7efe29f3e90ce3630ea1c665217c7ab298a3b"),
			)
		}else {
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

		msg, err := tx.AsMessage(types.MakeSigner(p.config, header.Number), header.BaseFee)
		if err != nil {
			return statedb, nil, nil, 0, err
		}
		statedb.Prepare(tx.Hash(), i)
		receipt, err := flash_loan_prove_transaction(p.config, p.bc, gp, header, tx.Hash(), tx.Type(), tx.Nonce(), usedGas, *p.bc.GetVMConfig(), statedb, &msg, nil, bloomProcessors)
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
	time_elapsed := time.Since(time_start)
	fmt.Println("Time elapsed in Flash Loan Process ", common.PrettyDuration(time_elapsed))
	return statedb, receipts, allLogs, *usedGas, nil
}


// flash loan archive node testing
func flash_loan_prove_transaction(config *params.ChainConfig, bc ChainContext, gp *GasPool, header *types.Header, tx_hash common.Hash, tx_type uint8, tx_nonce uint64, usedGas *uint64, cfg vm.Config, statedb *state.StateDB, msg *types.Message, coinbase *common.Address, receiptProcessors ...ReceiptProcessor) (*types.Receipt, error) {
	snap := statedb.Snapshot()
	snap_gas := gp.Gas()
	snap_gasused := *usedGas
	call_addr := common.HexToAddress("0x0000000000000000000000000000000000000000")
	is_create := 0
	deploy_code_length :=0
	// write contract data into contract_db
	if msg.To() == nil {
		contract_addr := crypto.CreateAddress(state.FRONTRUN_ADDRESS, statedb.GetNonce(state.FRONTRUN_ADDRESS))
		state.Set_contract_init_data_with_init_call(contract_addr, common.BigToHash(msg.GasPrice()), common.BigToHash(big.NewInt(int64(msg.Gas()))), common.BigToHash(msg.GasFeeCap()), common.BigToHash(msg.GasTipCap()),common.BigToHash(msg.Value()), msg.Data(), 1, common.HexToAddress("0x0000000000000000000000000000000000000000"), msg.From())
		is_create = 1
	} else {
		call_addr = *msg.To()
		//state.Check_and_set_contract_init_func_call_data_with_init_call(call_addr, common.BigToHash(msg.GasPrice()), common.BigToHash(big.NewInt(int64(msg.Gas()))), common.BigToHash(msg.Value()), msg.Data(), msg.From())
	}
	balance_old := statedb.GetBalance(msg.From())
	statedb.Init_adversary_account_entry(msg.From(), msg, common.BigToHash(big.NewInt(int64(statedb.GetNonce(msg.From())))))
	time_start := time.Now()
	receipt, err := WorkerApplyTransaction(config, bc, coinbase, gp, statedb, header, msg, tx_hash, tx_type, tx_nonce, usedGas, cfg, receiptProcessors...)
	time_elapsed := time.Since(time_start)
	fmt.Println("old_tx execution took: ", common.PrettyDuration(time_elapsed))
	time_start_oh := time.Now()
	temp_contract_addresses := statedb.Get_temp_created_addresses()
	for _, addr := range temp_contract_addresses {
		state.Set_contract_init_data_with_init_call(addr, common.BigToHash(msg.GasPrice()), common.BigToHash(big.NewInt(int64(msg.Gas()))), common.BigToHash(msg.GasFeeCap()), common.BigToHash(msg.GasTipCap()), common.BigToHash(msg.Value()), msg.Data(), byte(is_create), call_addr, msg.From())
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
					time_start1 := time.Now()
					receipt0, err0 := WorkerApplyTransaction(config, bc, coinbase, gp, statedb, header, a, tx_hash, tx_type, tx_nonce, usedGas, cfg, receiptProcessors...)
					time_elapsed1 := time.Since(time_start1)
					fmt.Println("flash loan deploy_tx try 1 execution took: ", common.PrettyDuration(time_elapsed1))
					if err0 != nil {
						fmt.Println("front run contract deployment failed!")
						frontrun_exec_result = false
					} else {
						//fmt.Println("Execution result: ", len(receipt0.ReturnData))
						deploy_code_length = len(receipt0.ReturnData)
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
					statedb.SetBalance(state.FRONTRUN_ADDRESS, balance_old)
					//flash loan mining testing end
					statedb.Init_adversary_account_entry(b.From(), b, common.BigToHash(big.NewInt(int64(statedb.GetNonce(b.From())))))
					time_start2 := time.Now()
					receipt, err1 := WorkerApplyTransaction(config, bc, coinbase, gp, statedb, header, b, tx_hash, tx_type, tx_nonce, usedGas, cfg, receiptProcessors...)
					time_elapsed2 := time.Since(time_start2)
					fmt.Println("flash loan tx try 1 execution took: ", common.PrettyDuration(time_elapsed2))
					if err1 != nil {
						frontrun_exec_result = false
					} else {
						//fmt.Println("Execution result: ", receipt.Status, len(receipt.ReturnData), common.BytesToHash(receipt.ReturnData[0:2]).Big(),common.BytesToHash(receipt.ReturnData[2:3]).Big())					
						if receipt.Status == 1{
							fmt.Println("Flash loan front run is executed. Now checking the beneficiary ...")
							if statedb.Token_transfer_flash_loan_check(b.From(), false) {
								fmt.Println("Front run address succeed!", b.From())
								frontrun_exec_result = true
							} else {
								fmt.Println("Front run address failed!", b.From())
								frontrun_exec_result = false
							}
						}else{
							pc := new(big.Int).SetBytes(receipt.ReturnData[0:2])
							op := 0x14 //EQ
							if 	receipt.ReturnData[2] == 0x2 {
								op = 0x10 //LT
							}else {
								op = 0x11 //GT
							}
							fmt.Println("Now try to disable potential check")
							statedb.Rm_adversary_account_entry(b.From(), *b)
							if a != nil{
								statedb.RevertToSnapshot(snap)
								snap = statedb.Snapshot()
								gp.SetGas(snap_gas)
								*usedGas = snap_gasused
								is_state_checkpoint_revert = true
								data := a.Data()
								offset := int64(len(data) - deploy_code_length)
								data[pc.Int64() + offset] = big.NewInt(int64(op)).Bytes()[0]
								a_new := types.NewMessage(state.FRONTRUN_ADDRESS, nil, a.Nonce(), a.Value(), a.Gas(), a.GasPrice(), a.GasFeeCap(), a.GasTipCap(), data, a.AccessList(), true)
								//flash loan mining testing
								balance := statedb.GetBalance(state.FRONTRUN_ADDRESS)
								needed_balance := big.NewInt(0).Add(a_new.Value(), big.NewInt(0).Mul(a_new.GasPrice(), big.NewInt(int64(a_new.Gas()))))
								if balance.Cmp(needed_balance) < 1 {
									statedb.AddBalance(state.FRONTRUN_ADDRESS, big.NewInt(0).Sub(needed_balance, balance))
								}
								time_start1 := time.Now()
								//flash loan mining testing end
								_, err0 := WorkerApplyTransaction(config, bc, coinbase, gp, statedb, header, &a_new, tx_hash, tx_type, tx_nonce, usedGas, cfg, receiptProcessors...)
								time_elapsed1 := time.Since(time_start1)
								fmt.Println("flash loan deploy_tx try 1 execution took: ", common.PrettyDuration(time_elapsed1))
								if err0 != nil {
									fmt.Println("front run contract deployment failed!")
									frontrun_exec_result = false
								} else {

								}
								balance = statedb.GetBalance(state.FRONTRUN_ADDRESS)
								needed_balance = big.NewInt(0).Add(b.Value(), big.NewInt(0).Mul(b.GasPrice(), big.NewInt(int64(b.Gas()))))
								if balance.Cmp(needed_balance) < 1 {
									statedb.AddBalance(state.FRONTRUN_ADDRESS, big.NewInt(0).Sub(needed_balance, balance))
								}
								statedb.SetBalance(state.FRONTRUN_ADDRESS, balance_old)
								//flash loan mining testing end
								statedb.Init_adversary_account_entry(b.From(), b, common.BigToHash(big.NewInt(int64(statedb.GetNonce(b.From())))))
								time_start2 := time.Now()
								_, err4 := WorkerApplyTransaction(config, bc, coinbase, gp, statedb, header, b, tx_hash, tx_type, tx_nonce, usedGas, cfg, receiptProcessors...)
								time_elapsed2 := time.Since(time_start2)
								fmt.Println("flash loan tx try 2 execution took: ", common.PrettyDuration(time_elapsed2))
								if err4 != nil {
									fmt.Println("front run failed :(")
									frontrun_exec_result = false
								} else {
									if statedb.Token_transfer_flash_loan_check(b.From(), false) {
										fmt.Println("Front run address succeed!", b.From())
										frontrun_exec_result = true
									} else {
										fmt.Println("Front run address failed!", b.From())
										frontrun_exec_result = false
									}
								}								
							}							
						}						
					}
		
					if !frontrun_exec_result {
						// Now add init func call in the middle
						statedb.Rm_adversary_account_entry(b.From(), *b)
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
								_, err0 := WorkerApplyTransaction(config, bc, coinbase, gp, statedb, header, a, tx_hash, tx_type, tx_nonce, usedGas, cfg, receiptProcessors...)
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
								receipt2, err2 := WorkerApplyTransaction(config, bc, coinbase, gp, statedb, header, c, tx_hash, tx_type, tx_nonce, usedGas, cfg, receiptProcessors...)
								if err2 != nil {
									frontrun_exec_result = false
									fmt.Println("Init func call execution failed! Error:", err2)
								} else {
									if receipt2.Status == 1{
										
									}else{
										fmt.Println("Init func call execution Reverted", err2)
										pc := new(big.Int).SetBytes(receipt2.ReturnData[0:2])
										op := 0x14 //EQ
										if 	receipt2.ReturnData[2] == 0x2 {
											op = 0x10 //LT
										}else {
											op = 0x11 //GT
										}
										statedb.RevertToSnapshot(snap)
										snap = statedb.Snapshot()
										gp.SetGas(snap_gas)
										*usedGas = snap_gasused
										is_state_checkpoint_revert = true
										data := a.Data()
										offset := int64(len(data) - deploy_code_length)
										data[pc.Int64() + offset] = big.NewInt(int64(op)).Bytes()[0]
										a_new := types.NewMessage(state.FRONTRUN_ADDRESS, nil, a.Nonce(), a.Value(), a.Gas(), a.GasPrice(), a.GasFeeCap(), a.GasTipCap(), data, a.AccessList(), true)
										//flash loan mining testing
										balance := statedb.GetBalance(state.FRONTRUN_ADDRESS)
										needed_balance := big.NewInt(0).Add(a_new.Value(), big.NewInt(0).Mul(a_new.GasPrice(), big.NewInt(int64(a_new.Gas()))))
										if balance.Cmp(needed_balance) < 1 {
											statedb.AddBalance(state.FRONTRUN_ADDRESS, big.NewInt(0).Sub(needed_balance, balance))
										}
										time_start1 := time.Now()
										//flash loan mining testing end
										_, err0 := WorkerApplyTransaction(config, bc, coinbase, gp, statedb, header, &a_new, tx_hash, tx_type, tx_nonce, usedGas, cfg, receiptProcessors...)
										time_elapsed1 := time.Since(time_start1)
										fmt.Println("flash loan deploy_tx try 2 with init call execution took: ", common.PrettyDuration(time_elapsed1))
										if err0 != nil {
											fmt.Println("front run contract deployment failed!")
											frontrun_exec_result = false
										} else {
											
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
											receipt2, err2 := WorkerApplyTransaction(config, bc, coinbase, gp, statedb, header, c, tx_hash, tx_type, tx_nonce, usedGas, cfg, receiptProcessors...)
											if err2 != nil {
												frontrun_exec_result = false
												fmt.Println("Init func call execution failed! Error:", err2)
											} else {
												if receipt2.Status == 1{

												}else{
													fmt.Println("Caller check didn't work")
													frontrun_exec_result = false
												}
			
											}
										}
									}
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
								time_start2 := time.Now()
								receipt1, err1 := WorkerApplyTransaction(config, bc, coinbase, gp, statedb, header, b, tx_hash, tx_type, tx_nonce, usedGas, cfg, receiptProcessors...)
								time_elapsed2 := time.Since(time_start2)
								fmt.Println("flash loan tx with init execution took: ", common.PrettyDuration(time_elapsed2))
								if err1 != nil {
									frontrun_exec_result = false
									fmt.Println("Flash loan func call execution failed! Error:", err1)
								} else {
									
									if receipt1.Status == 1{
										if statedb.Token_transfer_flash_loan_check(b.From(), false) {
											fmt.Println("Front run address succeed!", b.From())
											frontrun_exec_result = true
										} else {
											fmt.Println("Front run address failed!", b.From())
											frontrun_exec_result = false
										}
									}else{
										fmt.Println("Now try to disable potential check in flashloan tx")
										pc := new(big.Int).SetBytes(receipt1.ReturnData[0:2])
										op := 0x14 //EQ
										if 	receipt1.ReturnData[2] == 0x2 {
											op = 0x10 //LT
										}else {
											op = 0x11 //GT
										}
										statedb.Rm_adversary_account_entry(b.From(), *b)
										statedb.RevertToSnapshot(snap)
										snap = statedb.Snapshot()
										gp.SetGas(snap_gas)
										*usedGas = snap_gasused
										is_state_checkpoint_revert = true
										data := a.Data()
										offset := int64(len(data) - deploy_code_length)
										data[pc.Int64() + offset] = big.NewInt(int64(op)).Bytes()[0]
										a_new := types.NewMessage(state.FRONTRUN_ADDRESS, nil, a.Nonce(), a.Value(), a.Gas(), a.GasPrice(), a.GasFeeCap(), a.GasTipCap(), data, a.AccessList(), true)
										//flash loan mining testing
										balance := statedb.GetBalance(state.FRONTRUN_ADDRESS)
										needed_balance := big.NewInt(0).Add(a_new.Value(), big.NewInt(0).Mul(a_new.GasPrice(), big.NewInt(int64(a_new.Gas()))))
										if balance.Cmp(needed_balance) < 1 {
											statedb.AddBalance(state.FRONTRUN_ADDRESS, big.NewInt(0).Sub(needed_balance, balance))
										}
										time_start1 := time.Now()
										//flash loan mining testing end
										_, err0 := WorkerApplyTransaction(config, bc, coinbase, gp, statedb, header, &a_new, tx_hash, tx_type, tx_nonce, usedGas, cfg, receiptProcessors...)
										time_elapsed1 := time.Since(time_start1)
										fmt.Println("flash loan deploy_tx try 2 with init call execution took: ", common.PrettyDuration(time_elapsed1))
										if err0 != nil {
											fmt.Println("front run contract deployment failed!")
											frontrun_exec_result = false
										} else {
											
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
											_, err2 := WorkerApplyTransaction(config, bc, coinbase, gp, statedb, header, c, tx_hash, tx_type, tx_nonce, usedGas, cfg, receiptProcessors...)
											if err2 != nil {
												frontrun_exec_result = false
												fmt.Println("Init func call execution failed! Error:", err2)
											} else {
			
											}
										}
										if frontrun_exec_result {
											needed_balance = big.NewInt(0).Add(b.Value(), big.NewInt(0).Mul(b.GasPrice(), big.NewInt(int64(b.Gas()))))
											if balance.Cmp(needed_balance) < 1 {
												statedb.AddBalance(state.FRONTRUN_ADDRESS, big.NewInt(0).Sub(needed_balance, balance))
											}
											statedb.SetBalance(state.FRONTRUN_ADDRESS, balance_old)
											//flash loan mining testing end
											statedb.Init_adversary_account_entry(b.From(), b, common.BigToHash(big.NewInt(int64(statedb.GetNonce(b.From())))))
											time_start2 := time.Now()
											_, err4 := WorkerApplyTransaction(config, bc, coinbase, gp, statedb, header, b, tx_hash, tx_type, tx_nonce, usedGas, cfg, receiptProcessors...)
											time_elapsed2 := time.Since(time_start2)
											fmt.Println("flash loan tx try 2 with init execution took: ", common.PrettyDuration(time_elapsed2))
											if err4 != nil {
												fmt.Println("front run failed :(")
												frontrun_exec_result = false
											} else {
												if statedb.Token_transfer_flash_loan_check(b.From(), false) {
													fmt.Println("Front run address succeed!", b.From())
													frontrun_exec_result = true
												} else {
													fmt.Println("Front run address failed!", b.From())
													frontrun_exec_result = false
												}
											}

										}
										balance = statedb.GetBalance(state.FRONTRUN_ADDRESS)							

									}
									//fmt.Println("Flash loan front run is executed. Now checking the beneficiary ...")
									
								}
								
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
		fmt.Println("Transaction hash is replaced by front run", header.Hash())
		statedb.RevertToSnapshot(snap)
		gp.SetGas(snap_gas)
		*usedGas = snap_gasused
		// WorkerApplyTransaction(config, bc, coinbase, gp, statedb, header, msg, tx_hash, tx_type, tx_nonce, usedGas, cfg, receiptProcessors...)
	}
	time_elapsed_oh := time.Since(time_start_oh)
	fmt.Println("total overhead", common.PrettyDuration(time_elapsed_oh))
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

	//fmt.Println("apply result: ", result.Err)

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
	receipt.Logs = statedb.GetLogs(tx_hash, header.Hash())
	receipt.BlockHash = header.Hash()
	receipt.BlockNumber = header.Number
	receipt.TransactionIndex = uint(statedb.TxIndex())
	receipt.ReturnData = result.ReturnData
	for _, receiptProcessor := range receiptProcessors {
		receiptProcessor.Apply(receipt)
	}
	return receipt, err
}
